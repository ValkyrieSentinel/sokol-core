//! Suricata → Sokol adapter.
//!
//! Follows Suricata's EVE log (`eve.json`), turns alerts into `SIGNAL:` lines on the
//! orchestrator's IPC socket, and lets the orchestrator block the offender on this node and,
//! through the mesh, on every other node. The adapter needs read access to the EVE log and
//! write access to the IPC socket, nothing else.
//!
//! ```text
//! sokol-suricata --eve /var/log/suricata/eve.json --ipc-socket /run/sokol/sokol.sock --max-severity 2
//! ```

// Release builds abort on panic (panic = "abort"), so a panic reachable from input (a peer's
// frame, an IPC line, a trap connection, a file) stops the node. Outside tests, code must not
// be able to panic: no unwrap/expect, no unchecked indexing or slicing, no panic!-family macros.
// A provably safe exception is allowed locally, with its reason.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;

#[path = "../delivery.rs"]
mod delivery;

#[derive(Parser, Debug)]
#[command(about = "Forward Suricata alerts to Sokol-Core as block signals")]
struct Args {
    /// Suricata EVE JSON log to follow. Records above 1 MiB including LF are skipped.
    #[arg(long, default_value = "/var/log/suricata/eve.json")]
    eve: PathBuf,

    /// Orchestrator IPC socket (its --ipc-socket).
    #[arg(long, env = "SOKOL_IPC_SOCKET", default_value = "/run/sokol.sock")]
    ipc_socket: PathBuf,

    /// Forward alerts with this Suricata severity or more serious (1 = highest, 3 = lowest).
    #[arg(long, default_value = "2")]
    max_severity: u64,

    /// Signature IDs never forwarded (repeatable), e.g. noisy rules.
    #[arg(long, value_name = "SID")]
    ignore_sid: Vec<u64>,

    /// Do not forward the same address again within this many seconds.
    #[arg(long, default_value = "60")]
    cooldown_secs: u64,

    /// Upper bound on signals per second sent to the node.
    #[arg(long, default_value = "50")]
    max_signals_per_sec: u32,

    /// Process the existing file content instead of starting at its end.
    #[arg(long)]
    from_start: bool,

    /// Remember where reading got to (the oldest alert the node has not answered yet) in this
    /// file, and resume there after a restart. Recovery reads the current EVE path only;
    /// queued alerts in rotated-away files are not recovered after process loss.
    /// Replays use the same event IDs so the node can recognise duplicates.
    #[arg(long, value_name = "PATH")]
    cursor_file: Option<PathBuf>,

    /// Alerts older than this (by their EVE timestamp) are not forwarded: catching up after a
    /// long outage must not turn an old event into a new block.
    #[arg(long, default_value = "600")]
    max_alert_age_secs: u64,
}

struct Filter {
    max_severity: u64,
    ignore_sid: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq)]
struct Alert {
    /// Hash of the EVE line: a resend after a lost ACK is recognised by the node.
    event: String,
    /// When Suricata saw it (ms since the epoch), if the line says.
    at_ms: Option<i64>,
    src: IpAddr,
    dst: Option<IpAddr>,
    sid: u64,
    signature: String,
}

impl Alert {
    fn signal_line(&self) -> String {
        let dst = self
            .dst
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".into());
        format!(
            "SIGNAL#{}:suricata|{}|{}|sid:{} {}\n",
            self.event, self.src, dst, self.sid, self.signature
        )
    }
}

/// Decides whether one EVE line is an alert to forward.
fn decide(line: &str, filter: &Filter) -> Option<Alert> {
    let event: serde_json::Value = serde_json::from_str(line).ok()?;
    if event.get("event_type")?.as_str()? != "alert" {
        return None;
    }
    let alert = event.get("alert")?;
    let severity = alert.get("severity").and_then(|v| v.as_u64()).unwrap_or(3);
    let sid = alert
        .get("signature_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if severity > filter.max_severity || filter.ignore_sid.contains(&sid) {
        return None;
    }
    let src: IpAddr = event.get("src_ip")?.as_str()?.parse().ok()?;
    let dst = event
        .get("dest_ip")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());
    let signature: String = alert
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
    let at_ms = event
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|t| chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f%z").ok())
        .map(|t| t.timestamp_millis());
    Some(Alert {
        at_ms,
        event: blake3::hash(line.as_bytes())
            .to_hex()
            .chars()
            .take(32)
            .collect(),
        src,
        dst,
        sid,
        signature,
    })
}

/// Suppresses repeats of the same address and caps the overall rate.
struct Gate {
    cooldown: Duration,
    per_sec: u32,
    last_sent: HashMap<IpAddr, Instant>,
    window_start: Option<Instant>,
    in_window: u32,
}

impl Gate {
    fn new(cooldown: Duration, per_sec: u32) -> Self {
        Self {
            cooldown,
            per_sec,
            last_sent: HashMap::new(),
            window_start: None,
            in_window: 0,
        }
    }

    fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        if let Some(last) = self.last_sent.get(&ip) {
            if now.duration_since(*last) < self.cooldown {
                return false;
            }
        }
        let start = *self.window_start.get_or_insert(now);
        if now.duration_since(start) >= Duration::from_secs(1) {
            self.window_start = Some(now);
            self.in_window = 0;
        }
        if self.in_window >= self.per_sec {
            return false;
        }
        self.in_window += 1;
        self.last_sent.insert(ip, now);
        if self.last_sent.len() > 100_000 {
            let cooldown = self.cooldown;
            self.last_sent
                .retain(|_, t| now.duration_since(*t) < cooldown);
        }
        true
    }
}

// Operational quotas, not measured capacity: yield to delivery/checkpointing after either
// budget. Line size includes LF; larger EVE records are deliberately skipped.
const MAX_EVE_LINE_BYTES: usize = 1024 * 1024;
const MAX_POLL_BYTES: usize = 1024 * 1024;
const MAX_POLL_LINES: usize = 256;

/// `tail -F` for one file: survives truncation and rotation (rename + new file).
struct Follower {
    path: PathBuf,
    reader: Option<BufReader<File>>,
    inode: u64,
    position: u64,
    partial: Vec<u8>,
    discarding: bool,
    budget_exhausted: bool,
    /// Where the line being assembled in `partial` starts.
    line_start: u64,
}

/// Where reading got to, saved across restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Cursor {
    inode: u64,
    position: u64,
}

impl Cursor {
    fn load(path: &Path) -> Option<Cursor> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    /// Atomic replace (temporary file, rename).
    fn save(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self).map_err(io::Error::other)?)?;
        std::fs::rename(&tmp, path)
    }
}

impl Follower {
    fn new(path: &Path, from_start: bool) -> Self {
        let mut f = Self {
            path: path.to_path_buf(),
            reader: None,
            inode: 0,
            position: 0,
            partial: Vec::new(),
            discarding: false,
            budget_exhausted: false,
            line_start: 0,
        };
        let _ = f.open(!from_start);
        f
    }

    /// Resumes at a saved cursor: at its position if the file is the same one and not shorter,
    /// from the start if it was rotated or is shorter than the saved position (the remaining
    /// content is unread), otherwise as `new`. Inode/length cannot detect truncation followed
    /// by regrowth beyond the saved position. Says what it did.
    fn resume(path: &Path, cursor: Cursor, from_start: bool) -> (Self, &'static str) {
        let mut f = Self::new(path, from_start);
        let Ok(meta) = std::fs::metadata(path) else {
            return (f, "no file yet");
        };
        if meta.ino() == cursor.inode && meta.len() >= cursor.position {
            if f.open_at(cursor.position).is_ok() {
                return (f, "resumed at the saved position");
            }
        } else if meta.ino() != cursor.inode && f.open(false).is_ok() {
            return (
                f,
                "file rotated while down; reading the new one from its start",
            );
        } else if meta.len() < cursor.position && f.open(false).is_ok() {
            return (f, "file truncated while down; reading it from its start");
        }
        (f, "saved position no longer valid; starting as usual")
    }

    fn open_at(&mut self, position: u64) -> io::Result<()> {
        let file = File::open(&self.path)?;
        let meta = file.metadata()?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(position))?;
        self.position = position;
        self.line_start = position;
        self.inode = meta.ino();
        self.reader = Some(reader);
        self.partial.clear();
        self.discarding = false;
        Ok(())
    }

    /// The cursor just past the last complete line read.
    fn cursor(&self) -> Cursor {
        Cursor {
            inode: self.inode,
            position: self.line_start,
        }
    }

    /// Keep queue offsets tied to their source file. While an older file is pending,
    /// replay the current file from its start after restart rather than transplanting
    /// an unrelated offset. This does not recover old-file entries after process loss;
    /// the outbox is in memory and resume only opens the current path.
    fn checkpoint(&self, oldest: Option<Cursor>) -> Cursor {
        let mut cursor = self.cursor();
        if let Some(oldest) = oldest {
            cursor.position = if oldest.inode == cursor.inode {
                oldest.position
            } else {
                0
            };
        }
        cursor
    }

    fn open(&mut self, at_end: bool) -> io::Result<()> {
        let file = File::open(&self.path)?;
        let meta = file.metadata()?;
        let mut reader = BufReader::new(file);
        self.position = if at_end { meta.len() } else { 0 };
        self.line_start = self.position;
        reader.seek(SeekFrom::Start(self.position))?;
        self.inode = meta.ino();
        self.reader = Some(reader);
        self.partial.clear();
        self.discarding = false;
        Ok(())
    }

    /// One bounded batch of complete lines, each with its starting byte position.
    /// Budgets count consumed bytes and all completed lines (including skipped ones).
    /// BufReader may prefetch; these are work quotas, not a wall-clock deadline.
    fn poll(&mut self) -> io::Result<Vec<(u64, String)>> {
        self.budget_exhausted = false; // errors/EOF must not cause a busy retry loop
        match std::fs::metadata(&self.path) {
            Ok(_) if self.reader.is_none() => self.open(false)?,
            Ok(meta) if meta.ino() != self.inode => {
                // Budgeted polls may leave unread old-file bytes. Drain that descriptor
                // before switching; every returned batch still belongs to one inode.
                let unread = self
                    .reader
                    .as_ref()
                    .map(|reader| reader.get_ref().metadata().map(|m| m.len() > self.position))
                    .transpose()?
                    .unwrap_or(false);
                if !unread {
                    self.open(false)?;
                }
            }
            Ok(meta) if meta.len() < self.position => self.open(false)?,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }
        let Some(reader) = self.reader.as_mut() else {
            return Ok(Vec::new());
        };
        let mut lines = Vec::new();
        let mut remaining = MAX_POLL_BYTES;
        let mut completed = 0;
        while remaining > 0 && completed < MAX_POLL_LINES {
            let bytes = reader.fill_buf()?;
            if bytes.is_empty() {
                break;
            }
            let newline = bytes.iter().take(remaining).position(|byte| *byte == b'\n');
            let count = newline.map_or(bytes.len().min(remaining), |index| index + 1);
            if !self.discarding {
                if count > MAX_EVE_LINE_BYTES - self.partial.len() {
                    self.partial.clear();
                    self.discarding = true;
                    log::warn!(
                        "[sokol-suricata] EVE line at byte {} exceeds {} bytes; skipping to LF",
                        self.line_start,
                        MAX_EVE_LINE_BYTES
                    );
                } else {
                    self.partial.extend(bytes.iter().take(count).copied());
                }
            }
            reader.consume(count);
            self.position += count as u64;
            remaining -= count;
            if newline.is_some() {
                if !self.discarding {
                    match String::from_utf8(std::mem::take(&mut self.partial)) {
                        Ok(line) => lines.push((self.line_start, line)),
                        Err(_) => log::warn!(
                            "[sokol-suricata] invalid UTF-8 EVE line at byte {} skipped",
                            self.line_start
                        ),
                    }
                }
                self.discarding = false;
                self.line_start = self.position;
                completed += 1;
            }
        }
        self.budget_exhausted = remaining == 0 || completed == MAX_POLL_LINES;
        Ok(lines)
    }
}

/// Alerts kept while the node cannot be reached.
const OUTBOX_CAP: usize = 10_000;

/// Sends what is queued; an alert leaves the queue only when the node has answered it.
fn deliver(outbox: &mut delivery::Outbox, socket: &Path) {
    let was_failing = outbox.failing;
    let (done, err) = outbox.flush(64);
    for (line, outcome) in done {
        match outcome {
            delivery::Outcome::Applied
            | delivery::Outcome::Pending
            | delivery::Outcome::Recorded
            | delivery::Outcome::Duplicate => {
                log::info!("[sokol-suricata] {} ({:?})", line, outcome)
            }
            delivery::Outcome::Refused(why) => {
                log::warn!("[sokol-suricata] {}: refused by the node: {}", line, why)
            }
            delivery::Outcome::Rejected(why) => {
                log::error!("[sokol-suricata] {}: rejected by the node: {}", line, why)
            }
        }
    }
    match err {
        Some(e) if !was_failing => log::error!(
            "[sokol-suricata] cannot deliver to {}: {}; {} alerts queued, retrying",
            socket.display(),
            e,
            outbox.pending()
        ),
        None if was_failing && !outbox.failing => {
            log::warn!(
                "[sokol-suricata] node reachable again; queue drained to {}",
                outbox.pending()
            )
        }
        _ => {}
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let filter = Filter {
        max_severity: args.max_severity,
        ignore_sid: args.ignore_sid.clone(),
    };
    let mut gate = Gate::new(
        Duration::from_secs(args.cooldown_secs),
        args.max_signals_per_sec,
    );
    let mut follower = match args.cursor_file.as_deref().and_then(Cursor::load) {
        Some(cursor) => {
            let (f, how) = Follower::resume(&args.eve, cursor, args.from_start);
            log::info!("[sokol-suricata] {} ({:?})", how, cursor);
            f
        }
        None => Follower::new(&args.eve, args.from_start),
    };
    let max_age_ms = (args.max_alert_age_secs as i64).saturating_mul(1000);
    // File identity and offset for each queued alert, oldest first (the outbox is FIFO too).
    // A rotation must not transplant an old-file offset into the new file's saved cursor.
    let mut queued_at: std::collections::VecDeque<Cursor> = std::collections::VecDeque::new();
    let mut saved: Option<Cursor> = None;
    let mut last_save = Instant::now();
    let mut outbox = delivery::Outbox::new(&args.ipc_socket, OUTBOX_CAP);
    log::info!(
        "[sokol-suricata] following {} (severity <= {}), signalling {}",
        args.eve.display(),
        args.max_severity,
        args.ipc_socket.display()
    );

    loop {
        match follower.poll() {
            Ok(lines) => {
                let inode = follower.cursor().inode;
                let now_ms = chrono::Utc::now().timestamp_millis();
                for (start, line) in lines {
                    let Some(alert) = decide(&line, &filter) else {
                        continue;
                    };
                    if alert
                        .at_ms
                        .is_some_and(|at| now_ms.saturating_sub(at) > max_age_ms)
                    {
                        log::debug!("[sokol-suricata] stale alert from {} skipped", alert.src);
                        continue;
                    }
                    if !gate.admit(alert.src, Instant::now()) {
                        continue;
                    }
                    let lost = outbox.lost;
                    if let Err(error) = outbox.push(&alert.signal_line()) {
                        log::warn!("[sokol-suricata] alert rejected before queueing: {}", error);
                        continue; // no queued cursor entry for a rejected alert
                    }
                    queued_at.push_back(Cursor {
                        inode,
                        position: start,
                    });
                    if outbox.lost > lost {
                        queued_at.pop_front();
                        log::error!(
                            "[sokol-suricata] outbox full ({} queued): oldest alert dropped",
                            OUTBOX_CAP
                        );
                    }
                }
            }
            Err(e) => log::error!("[sokol-suricata] reading {}: {}", args.eve.display(), e),
        }
        deliver(&mut outbox, &args.ipc_socket);
        while queued_at.len() > outbox.pending() {
            queued_at.pop_front();
        }
        if let Some(path) = args.cursor_file.as_deref() {
            if last_save.elapsed() >= Duration::from_secs(1) {
                last_save = Instant::now();
                let cursor = follower.checkpoint(queued_at.front().copied());
                if saved != Some(cursor) {
                    match cursor.save(path) {
                        Ok(()) => saved = Some(cursor),
                        Err(e) => log::warn!(
                            "[sokol-suricata] cannot save the cursor to {}: {}",
                            path.display(),
                            e
                        ),
                    }
                }
            }
        }
        // Still deliver/checkpoint between batches, but do not impose 20 batches/s
        // on a backlog. An exact-boundary EOF costs one extra empty poll.
        if !follower.budget_exhausted {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Captured from Suricata 7.0.10 for the test rule used in scripts/xdp-smoke.sh.
    const ALERT: &str = r#"{"timestamp":"2026-09-24T11:48:23.712804+0000","flow_id":2217047500658694,"in_iface":"v0","event_type":"alert","src_ip":"10.7.0.2","src_port":49786,"dest_ip":"10.7.0.1","dest_port":23,"proto":"TCP","pkt_src":"wire/pcap","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"SOKOL TEST telnet probe","category":"Attempted Information Leak","severity":2},"direction":"to_server"}"#;

    fn filter() -> Filter {
        Filter {
            max_severity: 2,
            ignore_sid: vec![],
        }
    }

    #[test]
    fn real_suricata_alert_becomes_a_signal() {
        let alert = decide(ALERT, &filter()).unwrap();
        let (event, rest) = alert
            .signal_line()
            .split_once(':')
            .map(|(v, r)| (v.to_string(), r.to_string()))
            .unwrap();
        assert_eq!(
            rest,
            "suricata|10.7.0.2|10.7.0.1|sid:1000001 SOKOL TEST telnet probe\n"
        );
        assert_eq!(
            event,
            format!("SIGNAL#{}", &blake3::hash(ALERT.as_bytes()).to_hex()[..32])
        );
        let other = ALERT.replace("\"flow_id\":", "\"flow_id\":1");
        assert_ne!(
            decide(&other, &filter()).unwrap().event,
            alert.event,
            "another alert is another event"
        );
    }

    #[test]
    fn filters_by_type_severity_and_sid() {
        let low = ALERT.replace("\"severity\":2", "\"severity\":3");
        assert!(
            decide(&low, &filter()).is_none(),
            "severity 3 is below the threshold"
        );
        let flow = ALERT.replace("\"event_type\":\"alert\"", "\"event_type\":\"flow\"");
        assert!(decide(&flow, &filter()).is_none());
        let ignored = Filter {
            max_severity: 2,
            ignore_sid: vec![1000001],
        };
        assert!(decide(ALERT, &ignored).is_none());
        assert!(decide("not json", &filter()).is_none());
        let bad_ip = ALERT.replace("\"src_ip\":\"10.7.0.2\"", "\"src_ip\":\"evil\"");
        assert!(decide(&bad_ip, &filter()).is_none());
        let newline_sig = ALERT.replace("SOKOL TEST telnet probe", "x\\nDROP_IMMEDIATE:1.1.1.1");
        let line = decide(&newline_sig, &filter()).unwrap().signal_line();
        assert_eq!(
            line.matches('\n').count(),
            1,
            "a signature cannot inject a second IPC line"
        );
    }

    #[test]
    fn gate_suppresses_repeats_and_caps_rate() {
        let t0 = Instant::now();
        let mut gate = Gate::new(Duration::from_secs(60), 3);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(gate.admit(a, t0));
        assert!(!gate.admit(a, t0 + Duration::from_secs(10)), "cooldown");
        assert!(gate.admit(a, t0 + Duration::from_secs(61)), "cooldown over");

        let mut gate = Gate::new(Duration::from_secs(60), 3);
        let admitted = (0..10)
            .filter(|i| gate.admit(format!("198.51.100.{}", i).parse().unwrap(), t0))
            .count();
        assert_eq!(admitted, 3, "at most 3 per second");
        assert!(gate.admit(
            "198.51.100.200".parse().unwrap(),
            t0 + Duration::from_secs(1)
        ));
    }

    fn lines(f: &mut Follower) -> Vec<String> {
        f.poll().unwrap().into_iter().map(|(_, l)| l).collect()
    }

    #[test]
    fn follower_handles_appends_partial_lines_truncation_and_rotation() {
        let dir = std::env::temp_dir().join(format!("sokol-suricata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "old line\n").unwrap();

        let mut f = Follower::new(&path, false);
        assert!(lines(&mut f).is_empty(), "starts at the end by default");

        let mut w = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        w.write_all(b"one\ntw").unwrap();
        assert_eq!(lines(&mut f), vec!["one\n"]);
        w.write_all(b"o\n").unwrap();
        assert_eq!(lines(&mut f), vec!["two\n"], "partial line joined");

        // Rotation: rename away, new file appears.
        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        std::fs::write(&path, "three\n").unwrap();
        assert_eq!(lines(&mut f), vec!["three\n"]);

        // Truncation in place.
        std::fs::write(&path, "").unwrap();
        assert!(lines(&mut f).is_empty());
        std::fs::write(&path, "four\n").unwrap();
        assert_eq!(lines(&mut f), vec!["four\n"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn lines_carry_their_start_and_the_cursor_follows_complete_lines() {
        let dir = std::env::temp_dir().join(format!("sokol-suricata-pos-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "aa\nbbb\ncc").unwrap();
        let mut f = Follower::new(&path, true);
        assert_eq!(
            f.poll().unwrap(),
            vec![(0, "aa\n".to_string()), (3, "bbb\n".to_string())]
        );
        assert_eq!(
            f.cursor().position,
            7,
            "the partial line is not past the cursor"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_restart_resumes_at_the_cursor_or_reads_a_rotated_file_from_its_start() {
        let dir = std::env::temp_dir().join(format!("sokol-suricata-cur-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (path, saved) = (dir.join("eve.json"), dir.join("cursor"));
        std::fs::write(&path, "one\ntwo\n").unwrap();
        let mut f = Follower::new(&path, true);
        let _ = f.poll().unwrap();
        let cursor = Cursor {
            position: 4, // "two" was queued but not yet answered when the adapter stopped
            ..f.cursor()
        };
        cursor.save(&saved).unwrap();
        assert_eq!(Cursor::load(&saved), Some(cursor));

        // Written while the adapter was down.
        let mut w = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        w.write_all(b"three\n").unwrap();
        let (mut f, how) = Follower::resume(&path, cursor, false);
        assert_eq!(how, "resumed at the saved position");
        assert_eq!(
            lines(&mut f),
            vec!["two\n", "three\n"],
            "nothing unanswered is lost"
        );

        // Rotated while down: the new file is read from its start.
        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        std::fs::write(&path, "four\n").unwrap();
        let (mut f, how) = Follower::resume(&path, cursor, false);
        assert!(how.starts_with("file rotated"), "{}", how);
        assert_eq!(lines(&mut f), vec!["four\n"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_restart_reads_a_truncated_file_from_its_start() {
        let dir =
            std::env::temp_dir().join(format!("sokol-suricata-truncated-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "old acknowledged line\n".repeat(100)).unwrap();
        let old = Follower::new(&path, false).cursor();

        // copytruncate keeps the inode. New alerts can arrive before the adapter restarts.
        std::fs::write(&path, format!("{ALERT}\n")).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), old.inode);
        assert!(std::fs::metadata(&path).unwrap().len() < old.position);
        for from_start in [false, true] {
            let (mut follower, how) = Follower::resume(&path, old, from_start);
            assert!(how.starts_with("file truncated"), "{how}");
            let recovered = lines(&mut follower);
            assert_eq!(
                recovered,
                vec![format!("{ALERT}\n")],
                "from_start={from_start}"
            );
            assert!(decide(&recovered[0], &filter()).is_some());
            assert!(
                lines(&mut follower).is_empty(),
                "do not reread on the next poll"
            );
            let next = follower.cursor();
            let (mut resumed, _) = Follower::resume(&path, next, false);
            assert!(
                lines(&mut resumed).is_empty(),
                "the new cursor resumes at the new end"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_pending_old_file_offset_cannot_skip_the_new_file_after_restart() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-rotation-queue-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "already read\nold pending\n").unwrap();
        let mut follower = Follower::new(&path, true);
        let old_lines = follower.poll().unwrap();
        let old = Cursor {
            inode: follower.cursor().inode,
            position: old_lines[1].0,
        };
        assert_eq!(
            follower.checkpoint(Some(old)),
            old,
            "same-file queue position is retained"
        );

        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        let new_content = "new first\nnew second\nnew third\n";
        std::fs::write(&path, new_content).unwrap();
        let new_lines = follower.poll().unwrap();
        assert_ne!(follower.cursor().inode, old.inode);
        assert!(
            new_content.len() as u64 > old.position,
            "old offset would be accepted in the new file"
        );
        let checkpoint = follower.checkpoint(Some(old));
        let saved = dir.join("cursor");
        checkpoint.save(&saved).unwrap();
        let (mut restarted, _) = Follower::resume(&path, Cursor::load(&saved).unwrap(), false);
        assert_eq!(
            lines(&mut restarted).concat(),
            new_content,
            "no prefix of the new file may be skipped"
        );
        assert_eq!(
            checkpoint,
            Cursor {
                inode: follower.cursor().inode,
                position: 0
            }
        );

        // After old-file entries and the first new entry leave the queue, advance within this file.
        let pending_new = Cursor {
            inode: follower.cursor().inode,
            position: new_lines[1].0,
        };
        assert_eq!(follower.checkpoint(Some(pending_new)), pending_new);
        assert_eq!(
            follower.checkpoint(None),
            follower.cursor(),
            "empty queue may checkpoint the read end"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_utf8_does_not_discard_valid_lines_or_shift_the_cursor() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-utf8-invalid-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, b"first\n\xff\nlast\n").unwrap();
        let mut follower = Follower::new(&path, true);
        let batch = follower.poll();
        assert!(
            batch.is_ok(),
            "one malformed line must not discard the batch: {batch:?}"
        );
        assert_eq!(
            batch.unwrap(),
            vec![(0, "first\n".into()), (8, "last\n".into())]
        );
        assert_eq!(follower.cursor().position, 13);
        let (mut resumed, _) = Follower::resume(&path, follower.cursor(), false);
        assert!(lines(&mut resumed).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_partial_utf8_character_waits_for_the_rest_of_the_line() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-utf8-partial-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, b"first\n\xc3").unwrap();
        let mut follower = Follower::new(&path, true);
        let batch = follower.poll();
        assert!(
            batch.is_ok(),
            "an unfinished character is not a malformed line: {batch:?}"
        );
        assert_eq!(batch.unwrap(), vec![(0, "first\n".into())]);
        assert_eq!(follower.cursor().position, 6);
        assert!(lines(&mut follower).is_empty());
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"\xa9\n").unwrap();
        assert_eq!(follower.poll().unwrap(), vec![(6, "é\n".into())]);
        assert_eq!(
            follower.cursor().position,
            9,
            "positions count bytes, not characters"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_poll_yields_after_its_line_budget_without_losing_the_next_line() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-lines-budget-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "x\n".repeat(MAX_POLL_LINES + 1)).unwrap();
        let mut f = Follower::new(&path, true);
        assert_eq!(f.poll().unwrap().len(), MAX_POLL_LINES);
        assert!(f.budget_exhausted);
        assert_eq!(f.cursor().position, (2 * MAX_POLL_LINES) as u64);
        assert_eq!(
            f.poll().unwrap(),
            vec![((2 * MAX_POLL_LINES) as u64, "x\n".into())]
        );
        assert!(!f.budget_exhausted);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_unterminated_oversized_line_has_bounded_work_and_does_not_leak_its_tail() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-bytes-budget-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        let length = 3 * MAX_EVE_LINE_BYTES;
        std::fs::write(&path, vec![b'x'; length]).unwrap();
        let mut f = Follower::new(&path, true);
        while f.position < length as u64 {
            let before = f.position;
            assert!(f.poll().unwrap().is_empty());
            assert!(f.position > before && f.position - before <= MAX_POLL_BYTES as u64);
            assert!(f.partial.len() <= MAX_EVE_LINE_BYTES);
            assert_eq!(
                f.cursor().position,
                0,
                "unfinished record remains replayable"
            );
        }
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"tail\nok\n").unwrap();
        assert_eq!(
            f.poll().unwrap(),
            vec![((length + 5) as u64, "ok\n".into())]
        );
        assert_eq!(f.cursor().position, (length + 8) as u64);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_eve_line_limit_includes_the_newline() {
        let dir =
            std::env::temp_dir().join(format!("sokol-suricata-line-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        let accepted = format!("{}\n", "x".repeat(MAX_EVE_LINE_BYTES - 1));
        let rejected = format!("{}\n", "x".repeat(MAX_EVE_LINE_BYTES));
        std::fs::write(&path, format!("{accepted}{rejected}ok\n")).unwrap();
        let mut f = Follower::new(&path, true);
        let mut observed = Vec::new();
        while f.position < std::fs::metadata(&path).unwrap().len() {
            observed.extend(f.poll().unwrap());
        }
        assert_eq!(
            observed,
            vec![
                (0, accepted),
                ((2 * MAX_EVE_LINE_BYTES + 1) as u64, "ok\n".into())
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rotation_drains_the_old_budgeted_backlog_before_switching_inode() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-drain-budget-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "x\n".repeat(MAX_POLL_LINES + 1)).unwrap();
        let mut f = Follower::new(&path, true);
        assert_eq!(f.poll().unwrap().len(), MAX_POLL_LINES);
        let old_inode = f.cursor().inode;
        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        std::fs::write(&path, "new\n").unwrap();
        assert_eq!(
            f.poll().unwrap(),
            vec![((MAX_POLL_LINES * 2) as u64, "x\n".into())]
        );
        assert_eq!(f.cursor().inode, old_inode);
        assert_eq!(f.poll().unwrap(), vec![(0, "new\n".into())]);
        assert_ne!(f.cursor().inode, old_inode);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_reset_clears_oversized_line_discarding() {
        for rotate in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "sokol-suricata-discard-reset-{}-{rotate}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("eve.json");
            let length = MAX_EVE_LINE_BYTES + 1;
            std::fs::write(&path, vec![b'x'; length]).unwrap();
            let mut f = Follower::new(&path, true);
            while f.position < length as u64 {
                assert!(f.poll().unwrap().is_empty());
            }
            assert!(f.discarding);
            if rotate {
                std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
            }
            std::fs::write(&path, "fresh\n").unwrap();
            assert_eq!(f.poll().unwrap(), vec![(0, "fresh\n".into())]);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn invalid_lines_also_spend_the_poll_line_budget() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-invalid-budget-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        let mut bytes = b"\xff\n".repeat(MAX_POLL_LINES + 1);
        bytes.extend_from_slice(b"ok\n");
        std::fs::write(&path, bytes).unwrap();
        let mut f = Follower::new(&path, true);
        assert!(f.poll().unwrap().is_empty());
        assert_eq!(f.position, (2 * MAX_POLL_LINES) as u64);
        assert_eq!(
            f.poll().unwrap(),
            vec![((2 * (MAX_POLL_LINES + 1)) as u64, "ok\n".into())]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_alert_carries_its_time() {
        let alert = decide(ALERT, &filter()).unwrap();
        assert_eq!(
            alert.at_ms,
            Some(1_790_250_503_712),
            "2026-09-24T11:48:23.712804Z"
        );
    }
}
