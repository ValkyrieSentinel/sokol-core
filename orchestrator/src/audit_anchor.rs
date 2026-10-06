//! Audit head statements for an external anchor (ADR-0022, opt-in with `--anchor-dir`).
//!
//! The node writes its fsynced audit head as a one-line text statement into a directory, and
//! records that in its own audit log. It does not contact anything: a separate process stamps
//! the files with the official OpenTimestamps client (`scripts/anchor-ots.sh`, `ots stamp`),
//! whose `.ots` proofs, once upgraded, bind each statement to a Bitcoin block. A later rewrite of
//! the log, even by someone controlling every node of the mesh, then contradicts a statement
//! whose existence at that time is attested outside the operator's reach.
use std::io::Write;
use std::path::{Path, PathBuf};

use common::audit_log::CHAIN_LEN;

use crate::audit_witness::Summary;

pub const VERSION: &str = "sokol-audit-head v1";

/// The statement a stamp commits to: exactly this line, with a trailing newline.
pub fn statement(node_id: u64, records: u64, head: &[u8; CHAIN_LEN]) -> String {
    format!(
        "{} node={} records={} head={}\n",
        VERSION,
        node_id,
        records,
        crate::p2p::to_hex(head)
    )
}

/// `head-<node>-<records, 20 digits>.txt`: sorts by records; one statement per head.
pub fn file_name(node_id: u64, records: u64) -> String {
    format!("head-{}-{:020}.txt", node_id, records)
}

/// (node, records, head) of a statement, or None if the text is not exactly one.
pub fn parse(text: &str) -> Option<(u64, u64, [u8; CHAIN_LEN])> {
    let line = text.strip_suffix('\n')?;
    let rest = line.strip_prefix(VERSION)?.strip_prefix(' ')?;
    let mut fields = rest.split(' ');
    let node = fields.next()?.strip_prefix("node=")?.parse().ok()?;
    let records = fields.next()?.strip_prefix("records=")?.parse().ok()?;
    let hex = fields.next()?.strip_prefix("head=")?;
    if fields.next().is_some() || hex.len() != 2 * CHAIN_LEN || line.contains('\n') {
        return None;
    }
    let mut head = [0u8; CHAIN_LEN];
    for (byte, pair) in head.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some((node, records, head))
}

/// Writes the statement durably (temporary file synced, renamed, directory synced) and returns
/// its file name. An existing statement for the same records is kept as it is: a stamp may
/// already cover it, and a statement is never rewritten.
pub fn write_statement(
    dir: &Path,
    node_id: u64,
    records: u64,
    head: &[u8; CHAIN_LEN],
) -> std::io::Result<String> {
    let name = file_name(node_id, records);
    let path = dir.join(&name);
    if path.exists() {
        return Ok(name);
    }
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp", name));
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(statement(node_id, records, head).as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(name)
}

/// How a statement is written; replaceable so tests can delay or fail it.
pub type WriteFn =
    dyn Fn(&Path, u64, u64, &[u8; CHAIN_LEN]) -> std::io::Result<String> + Send + Sync;

/// Statements written, and writes that failed (metrics).
#[derive(Default)]
pub struct AnchorStats {
    pub written: std::sync::atomic::AtomicU64,
    pub failed: std::sync::atomic::AtomicU64,
}

type Job = (
    u64,
    [u8; CHAIN_LEN],
    tokio::task::JoinHandle<std::io::Result<String>>,
);

/// The node's anchor producer (ADR-0022). The blocking write only writes the file: the audit
/// record is made here, by the tick or by shutdown's `finish`, so it can never follow
/// NODE_SHUTDOWN. A head counts as anchored only once its write succeeded; a failed one is
/// tried again on the next due tick.
pub struct Anchorer {
    dir: PathBuf,
    node_id: u64,
    every: std::time::Duration,
    last: Option<std::time::Instant>,
    anchored: Option<u64>,
    job: Option<Job>,
    write: std::sync::Arc<WriteFn>,
    pub stats: std::sync::Arc<AnchorStats>,
}

impl Anchorer {
    pub fn new(dir: PathBuf, node_id: u64, every: std::time::Duration) -> Self {
        Self::with_writer(dir, node_id, every, std::sync::Arc::new(write_statement))
    }

    pub fn with_writer(
        dir: PathBuf,
        node_id: u64,
        every: std::time::Duration,
        write: std::sync::Arc<WriteFn>,
    ) -> Self {
        Self {
            dir,
            node_id,
            every,
            last: None,
            anchored: None,
            job: None,
            write,
            stats: std::sync::Arc::default(),
        }
    }

    fn record(
        &mut self,
        db: &crate::SentinelDb,
        records: u64,
        head: [u8; CHAIN_LEN],
        result: Result<std::io::Result<String>, tokio::task::JoinError>,
    ) {
        use std::sync::atomic::Ordering;
        match result {
            Ok(Ok(file)) => {
                self.anchored = Some(records);
                self.stats.written.fetch_add(1, Ordering::Relaxed);
                db.append(format!(
                    "AUDIT_ANCHOR|Records:{}|Head:{}|File:{}",
                    records,
                    crate::p2p::to_hex(&head),
                    file
                ));
            }
            Ok(Err(e)) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                log::error!(
                    "[Audit] Cannot write the head statement into {}: {}; retried next time",
                    self.dir.display(),
                    e
                );
            }
            Err(e) => {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
                log::error!("[Audit] Head statement writer failed: {}", e);
            }
        }
    }

    /// Every tick: record a finished write, then start the next one if due and the head is not
    /// anchored yet. Never waits for the disk.
    pub async fn tick(
        &mut self,
        durable: Option<(u64, [u8; CHAIN_LEN])>,
        db: &crate::SentinelDb,
        now: std::time::Instant,
    ) {
        if self
            .job
            .as_ref()
            .is_some_and(|(_, _, handle)| handle.is_finished())
        {
            if let Some((records, head, handle)) = self.job.take() {
                let result = handle.await;
                self.record(db, records, head, result);
            }
        }
        if self.job.is_some()
            || self
                .last
                .is_some_and(|at| now.duration_since(at) < self.every)
        {
            return;
        }
        self.last = Some(now);
        let Some((records, head)) = durable else {
            return;
        };
        if self.anchored == Some(records) {
            return;
        }
        let (write, dir, node) = (self.write.clone(), self.dir.clone(), self.node_id);
        let handle = tokio::task::spawn_blocking(move || write(&dir, node, records, &head));
        self.job = Some((records, head, handle));
    }

    /// Shutdown, before NODE_SHUTDOWN: wait up to `wait` for a write in flight and record its
    /// outcome. A write still running then is only logged; it cannot add an audit record later.
    pub async fn finish(&mut self, db: &crate::SentinelDb, wait: std::time::Duration) {
        if let Some((records, head, mut handle)) = self.job.take() {
            match tokio::time::timeout(wait, &mut handle).await {
                Ok(result) => self.record(db, records, head, result),
                Err(_) => log::warn!(
                    "[Audit] Head statement for {} records still being written at shutdown;                      its file may exist without an AUDIT_ANCHOR record",
                    records
                ),
            }
        }
    }
}

/// One statement file found for the node, with whether a stamp (`<file>.ots`) sits next to it.
pub struct Found {
    pub file: PathBuf,
    pub records: u64,
    pub head: [u8; CHAIN_LEN],
    pub stamped: bool,
}

/// Statements in `dir` for `node_id`, oldest first, and how many files could not be read as one.
pub fn statements_for(dir: &Path, node_id: u64) -> Result<(Vec<Found>, usize), String> {
    let mut found = Vec::new();
    let mut malformed = 0;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {}", dir.display(), e))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("head-") && n.ends_with(".txt"))
        })
        .collect();
    entries.sort();
    for file in entries {
        match std::fs::read_to_string(&file)
            .ok()
            .as_deref()
            .and_then(parse)
        {
            Some((node, records, head)) if node == node_id => {
                let mut ots = file.clone().into_os_string();
                ots.push(".ots");
                found.push(Found {
                    stamped: Path::new(&ots).exists(),
                    file,
                    records,
                    head,
                });
            }
            Some(_) => {}
            None => malformed += 1,
        }
    }
    Ok((found, malformed))
}

/// Checks this node's log against its statements; the lines are what `--verify-anchors` prints.
pub fn verify(own_log: &Path, dir: &Path, node_id: u64) -> Result<(Summary, Vec<String>), String> {
    let (found, malformed) = statements_for(dir, node_id)?;
    let claims: Vec<(u64, [u8; CHAIN_LEN])> = found.iter().map(|f| (f.records, f.head)).collect();
    let verdicts = common::audit_log::check_witnesses(own_log, &claims)
        .map_err(|e| format!("own log: {}", e))?;
    let mut summary = Summary::default();
    let mut lines = Vec::new();
    for (f, verdict) in found.iter().zip(verdicts) {
        let what = match verdict {
            common::audit_log::WitnessVerdict::Confirmed => {
                summary.confirmed += 1;
                "confirmed".to_string()
            }
            common::audit_log::WitnessVerdict::Contradicted(found) => {
                summary.contradicted += 1;
                format!(
                    "CONTRADICTED: this log now has head {}",
                    crate::p2p::to_hex(&found)
                )
            }
            common::audit_log::WitnessVerdict::Missing => {
                summary.missing += 1;
                "MISSING: this log has fewer records now".to_string()
            }
            common::audit_log::WitnessVerdict::Pruned => {
                summary.pruned += 1;
                "unknown: in a pruned segment".to_string()
            }
        };
        lines.push(format!(
            "{}: head after {} records {}{}",
            f.file.display(),
            f.records,
            what,
            if f.stamped { "" } else { " (not stamped yet)" }
        ));
    }
    if malformed > 0 {
        lines.push(format!(
            "{} file(s) named like a statement are not one",
            malformed
        ));
        summary.contradicted += malformed;
    }
    Ok((summary, lines))
}

pub fn print_report(own_log: &Path, dir: &Path, node_id: u64) -> i32 {
    match verify(own_log, dir, node_id) {
        Ok((summary, lines)) => {
            for line in &lines {
                println!("{}", line);
            }
            println!(
                "anchored heads for node {}: {} confirmed, {} contradicted, {} missing, {} pruned \
                 (Bitcoin attestation of each .ots: `ots verify <file>.ots`)",
                node_id, summary.confirmed, summary.contradicted, summary.missing, summary.pruned
            );
            summary.exit_code()
        }
        Err(why) => {
            eprintln!("{}", why);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::audit_log::AuditLog;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sokol-anchor-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_log(path: &Path, payloads: &[String]) -> (u64, [u8; CHAIN_LEN]) {
        let _ = std::fs::remove_file(path);
        let mut log = AuditLog::open(path).unwrap();
        for p in payloads {
            log.append(p.as_bytes()).unwrap();
        }
        log.sync().unwrap();
        (log.len(), log.head())
    }

    fn audit_of(path: &str, db: &crate::SentinelDb) -> Vec<String> {
        assert!(db.flush(std::time::Duration::from_secs(2)));
        let mut reader = common::audit_log::AuditReader::open(Path::new(path)).unwrap();
        let mut out = Vec::new();
        while let Some(r) = reader.next_record().unwrap() {
            out.push(String::from_utf8(r.payload).unwrap());
        }
        out
    }

    /// Review of #156 (1): a head was marked anchored before its write, so a failed write was
    /// never retried. Here the first write fails (the directory path is a file); once that is
    /// repaired, the next due tick writes the same head, with no new audit event in between.
    #[tokio::test]
    async fn a_failed_statement_write_is_retried_for_the_same_head() {
        let d = dir("retry");
        let audit = d.join("audit.log").to_string_lossy().into_owned();
        let db = crate::SentinelDb::init(&audit, None).unwrap();
        let anchors = d.join("anchors");
        std::fs::write(&anchors, b"not a directory").unwrap();
        let mut a = Anchorer::new(anchors.clone(), 1, std::time::Duration::from_secs(60));
        let head = Some((3, [7; CHAIN_LEN]));
        let t0 = std::time::Instant::now();
        a.tick(head, &db, t0).await;
        while a.job.as_ref().is_some_and(|j| !j.2.is_finished()) {
            tokio::task::yield_now().await;
        }
        a.tick(head, &db, t0).await; // collects the failure; not due yet
        assert_eq!(a.stats.failed.load(std::sync::atomic::Ordering::Relaxed), 1);
        std::fs::remove_file(&anchors).unwrap();
        a.tick(head, &db, t0 + std::time::Duration::from_secs(61))
            .await;
        a.finish(&db, std::time::Duration::from_secs(2)).await;
        assert_eq!(
            a.stats.written.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the same head was written"
        );
        assert!(anchors.join(file_name(1, 3)).exists());
        assert!(audit_of(&audit, &db)
            .iter()
            .any(|r| r.starts_with("AUDIT_ANCHOR|Records:3|")));
        drop(db);
        std::fs::remove_dir_all(d).unwrap();
    }

    /// Review of #156 (2): the blocking worker appended AUDIT_ANCHOR itself, after shutdown's
    /// NODE_SHUTDOWN. Now `finish` waits for the write in flight and records it first; a write
    /// that outlasts the wait records nothing at all, before or after NODE_SHUTDOWN.
    #[tokio::test]
    async fn a_statement_in_flight_at_shutdown_is_recorded_before_node_shutdown_or_not_at_all() {
        for (delay_ms, wait_ms, recorded) in [(200, 2000, true), (800, 100, false)] {
            let d = dir(&format!("shutdown-{}", recorded));
            let audit = d.join("audit.log").to_string_lossy().into_owned();
            let db = crate::SentinelDb::init(&audit, None).unwrap();
            let slow: std::sync::Arc<WriteFn> =
                std::sync::Arc::new(move |dir: &Path, n, r, h: &[u8; CHAIN_LEN]| {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    write_statement(dir, n, r, h)
                });
            let mut a = Anchorer::with_writer(
                d.join("anchors"),
                1,
                std::time::Duration::from_secs(60),
                slow,
            );
            a.tick(Some((5, [1; CHAIN_LEN])), &db, std::time::Instant::now())
                .await;
            a.finish(&db, std::time::Duration::from_millis(wait_ms))
                .await;
            db.append("NODE_SHUTDOWN".into());
            std::thread::sleep(std::time::Duration::from_millis(delay_ms + 200));
            let records = audit_of(&audit, &db);
            assert_eq!(
                records.last().map(String::as_str),
                Some("NODE_SHUTDOWN"),
                "{:?}",
                records
            );
            assert_eq!(
                records.iter().any(|r| r.starts_with("AUDIT_ANCHOR|")),
                recorded,
                "{:?}",
                records
            );
            drop(db);
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn a_statement_is_one_exact_line_and_parses_back() {
        let head = [0xab; CHAIN_LEN];
        let text = statement(7, 42, &head);
        assert_eq!(
            text,
            format!(
                "sokol-audit-head v1 node=7 records=42 head={}\n",
                "ab".repeat(32)
            )
        );
        assert_eq!(parse(&text), Some((7, 42, head)));
        for bad in [
            text.trim_end().to_string(),
            text.replace("v1", "v2"),
            text.replace("\n", " extra\n"),
            format!("{}{}", text, text),
        ] {
            assert_eq!(parse(&bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn a_statement_is_written_once_and_never_rewritten() {
        let d = dir("once");
        let name = write_statement(&d, 1, 3, &[1; CHAIN_LEN]).unwrap();
        let path = d.join(&name);
        let first = std::fs::read(&path).unwrap();
        // Same records, another head (the log was rewritten): the stamped statement stays.
        assert_eq!(write_statement(&d, 1, 3, &[2; CHAIN_LEN]).unwrap(), name);
        assert_eq!(std::fs::read(&path).unwrap(), first);
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            1,
            "no temporary file is left behind"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    /// ADR-0022 on real files: the statement confirms the log as written and exposes a rewrite
    /// that recomputed the whole chain; another node's statements are ignored; a damaged
    /// statement counts against the check; stamps are reported, not required.
    #[test]
    fn statements_confirm_the_log_and_expose_a_recomputed_rewrite() {
        let d = dir("verify");
        let own = d.join("audit.log");
        let anchors = d.join("anchors");
        let decisions: Vec<String> = (1..=3)
            .map(|i| format!("DYNAMIC_BLOCK_V4|IP:198.51.100.{}", i))
            .collect();
        let (records, head) = write_log(&own, &decisions);
        let name = write_statement(&anchors, 1, records, &head).unwrap();
        write_statement(&anchors, 9, 1, &[0; CHAIN_LEN]).unwrap();
        std::fs::write(anchors.join(format!("{}.ots", name)), b"stamp").unwrap();
        let (summary, lines) = verify(&own, &anchors, 1).unwrap();
        assert_eq!(
            (summary.confirmed, summary.exit_code()),
            (1, 0),
            "{:?}",
            lines
        );
        assert!(!lines[0].contains("not stamped"));

        let mut rewritten = decisions.clone();
        rewritten[0] = "DYNAMIC_BLOCK_V4|IP:203.0.113.1".into();
        write_log(&own, &rewritten);
        let (summary, _) = verify(&own, &anchors, 1).unwrap();
        assert_eq!((summary.contradicted, summary.exit_code()), (1, 1));

        // A fresh log and statement that confirm, plus a damaged statement file: still a failure.
        let fresh = d.join("fresh");
        let (records, head) = write_log(&d.join("fresh.log"), &decisions);
        write_statement(&fresh, 1, records, &head).unwrap();
        assert_eq!(
            verify(&d.join("fresh.log"), &fresh, 1)
                .unwrap()
                .0
                .exit_code(),
            0
        );
        std::fs::write(fresh.join("head-1-00000000000000000099.txt"), "garbage").unwrap();
        let (summary, lines) = verify(&d.join("fresh.log"), &fresh, 1).unwrap();
        assert_eq!(
            summary.exit_code(),
            1,
            "a damaged statement is not ignored: {:?}",
            lines
        );
        assert!(lines.iter().any(|l| l.contains("are not one")));
        std::fs::remove_dir_all(d).unwrap();
    }
}
