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
