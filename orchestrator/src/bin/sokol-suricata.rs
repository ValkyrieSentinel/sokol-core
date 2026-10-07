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
use std::collections::{HashSet, VecDeque};
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

    /// Upper bound on alerts admitted per fixed one-second policy window (not IPC pacing).
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

    /// Forwarding age budget for timestamped alerts, including queueing and retries.
    /// Expiry drops pending forwarding locally, without undoing possibly applied effects.
    /// Missing/unparseable timestamps retain the legacy untimed policy.
    #[arg(long, default_value = "600", value_parser = forwarding_age_secs)]
    max_alert_age_secs: u64,
}

/// Reject an impossible interval before opening the source, loading a cursor or using IPC.
/// This checks the local clock at startup; per-alert checked addition remains necessary.
fn forwarding_age_secs(raw: &str) -> Result<u64, String> {
    let seconds = raw.parse::<u64>().map_err(|error| error.to_string())?;
    Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| "forwarding age exceeds local clock range".to_string())?;
    Ok(seconds)
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

/// Maximum distinct source addresses retained by the adapter cooldown policy.
const COOLDOWN_CAP: usize = 100_000;

/// The first failing policy owns one refusal; this is not a delivery outcome.
enum AdmissionRefusal {
    Cooldown,
    Rate,
    Capacity,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RefusalCounts {
    cooldown: u64,
    rate: u64,
    capacity: u64,
}

impl RefusalCounts {
    fn since(self, reported: Self) -> Self {
        Self {
            cooldown: self.cooldown.saturating_sub(reported.cooldown),
            rate: self.rate.saturating_sub(reported.rate),
            capacity: self.capacity.saturating_sub(reported.capacity),
        }
    }
}

/// Suppresses repeats and bounds policy admission, not delivery or ACK rate.
/// Calls use nondecreasing Instants and one fixed cooldown for this Gate's lifetime.
struct Gate {
    cooldown: Duration,
    per_sec: u32,
    capacity: usize,
    last_sent: HashSet<IpAddr>,
    // One entry per retained address, ordered by successful admission time.
    expires: VecDeque<(IpAddr, Instant)>,
    refusals: RefusalCounts,
    window_start: Option<Instant>,
    in_window: u32,
}

impl Gate {
    fn new(cooldown: Duration, per_sec: u32) -> Self {
        Self::with_capacity(cooldown, per_sec, COOLDOWN_CAP)
    }

    fn with_capacity(cooldown: Duration, per_sec: u32, capacity: usize) -> Self {
        Self {
            cooldown,
            per_sec,
            capacity,
            last_sent: HashSet::new(),
            expires: VecDeque::new(),
            refusals: RefusalCounts::default(),
            window_start: None,
            in_window: 0,
        }
    }

    fn refuse(&mut self, reason: AdmissionRefusal) -> bool {
        let count = match reason {
            AdmissionRefusal::Cooldown => &mut self.refusals.cooldown,
            AdmissionRefusal::Rate => &mut self.refusals.rate,
            AdmissionRefusal::Capacity => &mut self.refusals.capacity,
        };
        *count = count.saturating_add(1);
        false
    }

    fn admit(&mut self, ip: IpAddr, now: Instant) -> bool {
        // Fixed cooldown + monotone time means only a FIFO prefix can expire.
        // Every admitted tuple is removed once; full-hot refusal never scans the set.
        // A single call may still remove the entire bounded queue.
        while self
            .expires
            .front()
            .is_some_and(|(_, at)| now.duration_since(*at) >= self.cooldown)
        {
            if let Some((expired, _)) = self.expires.pop_front() {
                self.last_sent.remove(&expired);
            }
        }
        if self.last_sent.contains(&ip) {
            return self.refuse(AdmissionRefusal::Cooldown);
        }
        let start = *self.window_start.get_or_insert(now);
        if now.duration_since(start) >= Duration::from_secs(1) {
            self.window_start = Some(now);
            self.in_window = 0;
        }
        if self.in_window >= self.per_sec {
            return self.refuse(AdmissionRefusal::Rate);
        }
        if self.last_sent.len() >= self.capacity {
            // Never evict a live cooldown to admit a new address.
            return self.refuse(AdmissionRefusal::Capacity);
        }
        self.in_window += 1;
        self.last_sent.insert(ip);
        self.expires.push_back((ip, now));
        true
    }
}

/// Aggregate monotone refusal counters across batches, including later empty/error polls.
/// Report decisions are at least one second apart; totals saturate, like Gate counters.
/// No per-address storage and no promise that pending diagnostics survive process loss.
#[derive(Default)]
struct AdmissionDiagnostics {
    reported: RefusalCounts,
    last_emit: Option<Instant>,
}

impl AdmissionDiagnostics {
    fn take(&mut self, now: Instant, totals: RefusalCounts) -> Option<RefusalCounts> {
        let counts = totals.since(self.reported);
        if counts == RefusalCounts::default()
            || self
                .last_emit
                .is_some_and(|at| now.duration_since(at) < Duration::from_secs(1))
        {
            return None;
        }
        self.reported = totals;
        self.last_emit = Some(now);
        Some(counts)
    }
}

/// The source's age consumes a local forwarding budget; future timestamps cannot enlarge it.
/// Missing/unparseable timestamps use the existing untimed policy instead (caller-owned).
fn forwarding_deadline(
    at_ms: i64,
    now_ms: i64,
    observed: Instant,
    max_age_secs: u64,
) -> io::Result<Instant> {
    let age_ms = u64::try_from((i128::from(now_ms) - i128::from(at_ms)).max(0))
        .map_err(|_| io::Error::other("alert age exceeds supported range"))?;
    let remaining = Duration::from_secs(max_age_secs)
        .checked_sub(Duration::from_millis(age_ms))
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "stale alert"))?;
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no alert forwarding budget remains",
        ));
    }
    observed.checked_add(remaining).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "alert deadline exceeds local clock range",
        )
    })
}

// Operational quotas, not measured capacity: yield to delivery/checkpointing after either
// budget. Line size includes LF; larger EVE records are deliberately skipped.
const MAX_EVE_LINE_BYTES: usize = 1024 * 1024;
const MAX_POLL_BYTES: usize = 1024 * 1024;
const MAX_POLL_LINES: usize = 256;

/// Completed records survive a later read error in the same bounded scan.
/// File metadata/open errors still return Err from poll before scanning starts.
#[derive(Debug, Default)]
struct ReadBatch {
    lines: Vec<(u64, String)>,
    error: Option<io::Error>,
}

/// `tail -F` for one file: survives truncation and rotation (rename + new file).
struct Follower {
    path: PathBuf,
    reader: Option<BufReader<File>>,
    // Retain a selected restart anchor until a file is successfully opened/positioned.
    pending_resume: Option<Cursor>,
    inode: u64,
    position: u64,
    // A new token on every successful open/reset, including same-inode truncation.
    // Queued positions keep their token alive; pointer identity cannot be reused
    // while one of those positions remains pending. It is never serialized.
    content: std::rc::Rc<()>,
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

/// A pending position belongs to one observed incarnation of the file's contents.
/// Inode alone cannot distinguish positions before and after copytruncate.
struct QueuedCursor {
    cursor: Cursor,
    content: std::rc::Rc<()>,
}

impl Cursor {
    /// `Ok(None)`: no cursor file (a first start). An unreadable or unparseable file is an
    /// error, not a first start: treating it as absent would start at the end of the log and
    /// silently skip what arrived before the crash (review 2026-10-05, detector path).
    fn load(path: &Path) -> Result<Option<Cursor>, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {}", path.display(), e)),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{} is not a cursor: {}", path.display(), e))
    }

    /// Atomic and durable replace, like the node's state file (R26-04): the temporary file is
    /// synced before the rename and the directory after it, so a power loss leaves the old
    /// cursor or the new one, never an empty file.
    fn save(&self, path: &Path) -> io::Result<()> {
        use std::io::Write;
        let tmp = path.with_extension("tmp");
        let mut file = File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(self).map_err(io::Error::other)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

/// Where reading starts: the saved cursor; without one, the end (or the start with
/// `--from-start`); with an unreadable one, the start of the current file. Re-reading is
/// safe: alerts older than the forwarding age budget are skipped, and the node answers a
/// resent event id as a duplicate. Skipping from the end would lose alerts silently.
/// The flag is true when a cursor file existed but could not be used.
fn initial_follower(
    eve: &Path,
    cursor_file: Option<&Path>,
    from_start: bool,
) -> (Follower, String, bool) {
    match cursor_file.map(Cursor::load) {
        Some(Ok(Some(cursor))) => {
            let (f, how) = Follower::resume(eve, cursor);
            (f, format!("{} ({:?})", how, cursor), false)
        }
        Some(Err(why)) => (
            Follower::new(eve, true),
            format!("{}; reading {} from its start", why, eve.display()),
            true,
        ),
        Some(Ok(None)) | None => (
            Follower::new(eve, from_start),
            format!(
                "no saved cursor; reading {} from its {}",
                eve.display(),
                if from_start { "start" } else { "end" }
            ),
            false,
        ),
    }
}

impl Follower {
    fn unopened(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            reader: None,
            pending_resume: None,
            inode: 0,
            position: 0,
            content: std::rc::Rc::new(()),
            partial: Vec::new(),
            discarding: false,
            budget_exhausted: false,
            line_start: 0,
        }
    }

    fn new(path: &Path, from_start: bool) -> Self {
        let mut f = Self::unopened(path);
        let _ = f.open(!from_start);
        f
    }

    /// The saved cursor selects the initial position independently of --from-start.
    /// If opening fails, retain it for later polls and checkpoints. On a successful
    /// open, use the actual descriptor's inode/length to select resume or replay.
    /// Inode/length cannot detect truncation/regrowth between observations.
    fn resume(path: &Path, cursor: Cursor) -> (Self, &'static str) {
        let mut f = Self::unopened(path);
        f.pending_resume = Some(cursor);
        let how = f
            .open_saved(cursor)
            .unwrap_or("waiting for the source to resume");
        (f, how)
    }

    fn open_saved(&mut self, cursor: Cursor) -> io::Result<&'static str> {
        let file = File::open(&self.path)?;
        let meta = file.metadata()?;
        let (position, how) = if meta.ino() != cursor.inode {
            (
                0,
                "file rotated while down; reading the new one from its start",
            )
        } else if meta.len() < cursor.position {
            (0, "file truncated while down; reading it from its start")
        } else {
            (cursor.position, "resumed at the saved position")
        };
        self.install(file, position)?;
        Ok(how)
    }

    /// Commit reader state only after metadata and seek have both succeeded.
    fn install(&mut self, file: File, position: u64) -> io::Result<()> {
        let meta = file.metadata()?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(position))?;
        self.position = position;
        self.line_start = position;
        self.inode = meta.ino();
        self.content = std::rc::Rc::new(());
        self.reader = Some(reader);
        self.pending_resume = None;
        self.partial.clear();
        self.discarding = false;
        Ok(())
    }

    /// The cursor just past the last complete line read.
    fn cursor(&self) -> Cursor {
        if let Some(cursor) = self.pending_resume {
            return cursor;
        }
        Cursor {
            inode: self.inode,
            position: self.line_start,
        }
    }

    fn queued_at(&self, position: u64) -> QueuedCursor {
        QueuedCursor {
            cursor: Cursor {
                position,
                ..self.cursor()
            },
            content: std::rc::Rc::clone(&self.content),
        }
    }

    /// Keep pending offsets tied to the contents from which they were read.
    /// After a detected rotation or truncation, pending old-content work pins
    /// recovery of the current file to its start. This does not retain old bytes
    /// after process loss or detect truncation/regrowth between observations.
    fn checkpoint(&self, oldest: Option<&QueuedCursor>) -> Cursor {
        let mut cursor = self.cursor();
        if let Some(oldest) = oldest {
            cursor.position = if std::rc::Rc::ptr_eq(&oldest.content, &self.content)
                && oldest.cursor.inode == cursor.inode
            {
                oldest.cursor.position
            } else {
                0
            };
        }
        cursor
    }

    fn open(&mut self, at_end: bool) -> io::Result<()> {
        let file = File::open(&self.path)?;
        let position = if at_end { file.metadata()?.len() } else { 0 };
        self.install(file, position)
    }

    /// One bounded batch of complete lines, each with its starting byte position.
    /// Budgets count consumed bytes and all completed lines (including skipped ones).
    /// BufReader may prefetch; these are work quotas, not a wall-clock deadline.
    fn poll(&mut self) -> io::Result<ReadBatch> {
        self.budget_exhausted = false; // errors/EOF must not cause a busy retry loop
        match std::fs::metadata(&self.path) {
            Ok(_) if self.reader.is_none() => {
                if let Some(cursor) = self.pending_resume {
                    let how = self.open_saved(cursor)?;
                    log::info!("[sokol-suricata] {} ({:?})", how, cursor);
                } else {
                    self.open(false)?;
                }
            }
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ReadBatch::default()),
            Err(e) => return Err(e),
        }
        let Some(mut reader) = self.reader.take() else {
            return Ok(ReadBatch::default());
        };
        let result = self.read_batch(&mut reader);
        self.reader = Some(reader);
        Ok(result)
    }

    /// Scan a bounded portion of any buffered input. Production uses the open file;
    /// tests can exercise actual I/O failures without a production failpoint.
    fn read_batch<R: BufRead>(&mut self, reader: &mut R) -> ReadBatch {
        self.budget_exhausted = false;
        let mut error = None;
        let mut lines = Vec::new();
        let mut remaining = MAX_POLL_BYTES;
        let mut completed = 0;
        while remaining > 0 && completed < MAX_POLL_LINES {
            let bytes = match reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(failure) => {
                    error = Some(failure);
                    break; // keep completed lines, partial bytes and the open reader
                }
            };
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
        self.budget_exhausted = error.is_none() && (remaining == 0 || completed == MAX_POLL_LINES);
        ReadBatch { lines, error }
    }
}

/// Alerts kept while the node cannot be reached.
const OUTBOX_CAP: usize = 10_000;

/// Send pending alerts, reporting node answers and counted local freshness losses separately.
fn deliver(outbox: &mut delivery::Outbox, socket: &Path) {
    let was_failing = outbox.failing;
    let expired = outbox.expired;
    let (done, err) = outbox.flush(64);
    let skipped = outbox.expired.saturating_sub(expired);
    if skipped > 0 {
        log::warn!(
            "[sokol-suricata] {} queued alerts expired before forwarding; local policy loss",
            skipped
        );
    }
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
    let mut diagnostics = AdmissionDiagnostics::default();
    let (mut follower, how, damaged) =
        initial_follower(&args.eve, args.cursor_file.as_deref(), args.from_start);
    if damaged {
        log::error!("[sokol-suricata] {}", how);
    } else {
        log::info!("[sokol-suricata] {}", how);
    }
    // File-content identity and offset for each queued alert, oldest first.
    // Neither rotation nor detected copytruncate may transplant an old offset.
    let mut queued_at: std::collections::VecDeque<QueuedCursor> = std::collections::VecDeque::new();
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
            Ok(batch) => {
                if let Some(error) = batch.error {
                    log::error!("[sokol-suricata] reading {}: {}", args.eve.display(), error);
                }
                let observed = Instant::now();
                let now_ms = chrono::Utc::now().timestamp_millis();
                for (start, line) in batch.lines {
                    let Some(alert) = decide(&line, &filter) else {
                        continue;
                    };
                    let deadline = match alert.at_ms {
                        Some(at_ms) => match forwarding_deadline(
                            at_ms,
                            now_ms,
                            observed,
                            args.max_alert_age_secs,
                        ) {
                            Ok(before) => Some(before),
                            Err(error) => {
                                if error.kind() == io::ErrorKind::TimedOut {
                                    log::debug!(
                                        "[sokol-suricata] stale alert from {} skipped",
                                        alert.src
                                    );
                                } else {
                                    log::warn!(
                                        "[sokol-suricata] alert from {} skipped: {}",
                                        alert.src,
                                        error
                                    );
                                }
                                continue;
                            }
                        },
                        None => None,
                    };
                    if !gate.admit(alert.src, Instant::now()) {
                        continue;
                    }
                    let lost = outbox.lost;
                    let line = alert.signal_line();
                    let queued = match deadline {
                        Some(before) => outbox.push_before(&line, before),
                        None => outbox.push(&line),
                    };
                    if let Err(error) = queued {
                        log::warn!("[sokol-suricata] alert rejected before queueing: {}", error);
                        continue; // no queued cursor entry for a rejected alert
                    }
                    queued_at.push_back(follower.queued_at(start));
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
        if let Some(refused) = diagnostics.take(Instant::now(), gate.refusals) {
            if refused.cooldown > 0 {
                log::warn!("[sokol-suricata] {} alerts skipped: source cooldown active (policy admission, not delivery)", refused.cooldown);
            }
            if refused.rate > 0 {
                log::warn!(
                    "[sokol-suricata] {} alerts skipped: policy rate limit reached ({} admissions per fixed one-second window)",
                    refused.rate,
                    args.max_signals_per_sec
                );
            }
            if refused.capacity > 0 {
                log::warn!(
                    "[sokol-suricata] {} alerts skipped: cooldown memory full ({} addresses)",
                    refused.capacity,
                    COOLDOWN_CAP
                );
            }
        }
        deliver(&mut outbox, &args.ipc_socket);
        while queued_at.len() > outbox.pending() {
            queued_at.pop_front();
        }
        if let Some(path) = args.cursor_file.as_deref() {
            if last_save.elapsed() >= Duration::from_secs(1) {
                last_save = Instant::now();
                let cursor = follower.checkpoint(queued_at.front());
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
    fn cli_rejects_unrepresentable_forwarding_age_before_startup() {
        let result = Args::try_parse_from([
            "sokol-suricata",
            "--max-alert-age-secs",
            "18446744073709551615",
        ]);
        assert!(
            result.is_err(),
            "an impossible clock interval must not start the adapter"
        );
    }

    #[test]
    fn cli_forwarding_age_accepts_zero_and_normal_intervals_but_rejects_bad_numbers() {
        for value in ["0", "600", "86400"] {
            let args =
                Args::try_parse_from(["sokol-suricata", "--max-alert-age-secs", value]).unwrap();
            assert_eq!(args.max_alert_age_secs, value.parse::<u64>().unwrap());
        }
        for value in ["-1", "no", "18446744073709551616"] {
            assert!(
                Args::try_parse_from(["sokol-suricata", "--max-alert-age-secs", value]).is_err()
            );
        }
        assert_eq!(
            Args::try_parse_from(["sokol-suricata"])
                .unwrap()
                .max_alert_age_secs,
            600
        );
    }

    fn counts(cooldown: u64, rate: u64, capacity: u64) -> RefusalCounts {
        RefusalCounts {
            cooldown,
            rate,
            capacity,
        }
    }

    #[test]
    fn refusal_diagnostics_preserve_counts_and_space_emissions_across_batches() {
        let t = Instant::now();
        let mut diagnostics = AdmissionDiagnostics::default();
        assert_eq!(diagnostics.take(t, counts(0, 0, 0)), None);
        assert_eq!(diagnostics.take(t, counts(1, 0, 0)), Some(counts(1, 0, 0)));
        for count in 2..=10_001 {
            assert_eq!(
                diagnostics.take(
                    t + Duration::from_nanos(count),
                    counts(count, count * 2, count / 2)
                ),
                None
            );
        }
        let totals = counts(10_001, 20_002, 5_000);
        assert_eq!(
            diagnostics.take(t + Duration::from_millis(999), totals),
            None
        );
        // No new refusals: a later idle/error poll still flushes accumulated counts.
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(1), totals),
            Some(counts(10_000, 20_002, 5_000))
        );
        assert_eq!(diagnostics.take(t + Duration::from_secs(2), totals), None);
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(2), counts(10_001, 20_002, 5_007)),
            Some(counts(0, 0, 7))
        );
        assert_eq!(
            diagnostics.take(
                t + Duration::from_millis(2_999),
                counts(10_004, 20_008, 5_007)
            ),
            None
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(3), counts(10_004, 20_008, 5_007)),
            Some(counts(3, 6, 0))
        );
    }

    #[test]
    fn refusal_diagnostics_do_not_wrap_or_reemit_saturated_totals() {
        let t = Instant::now();
        let mut diagnostics = AdmissionDiagnostics::default();
        let previous = counts(u64::MAX - 2, u64::MAX - 3, u64::MAX - 1);
        let saturated = counts(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(diagnostics.take(t, previous), Some(previous));
        assert_eq!(
            diagnostics.take(t + Duration::from_millis(500), saturated),
            None
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(1), saturated),
            Some(counts(2, 3, 1))
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(2), saturated),
            None
        );
    }

    #[test]
    fn rate_only_diagnostics_wait_for_the_shared_interval_and_preserve_pending_counts() {
        let t = Instant::now();
        let mut diagnostics = AdmissionDiagnostics::default();
        assert_eq!(diagnostics.take(t, counts(0, 4, 0)), Some(counts(0, 4, 0)));
        assert_eq!(
            diagnostics.take(t + Duration::from_millis(999), counts(0, 513, 0)),
            None
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(1), counts(0, 513, 0)),
            Some(counts(0, 509, 0))
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(2), counts(0, 513, 0)),
            None
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(2), counts(2, 513, 0)),
            Some(counts(2, 0, 0))
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_millis(2_999), counts(2, 514, 0)),
            None,
            "other categories cannot bypass the shared report interval"
        );
        assert_eq!(
            diagnostics.take(t + Duration::from_secs(3), counts(2, 514, 0)),
            Some(counts(0, 1, 0))
        );
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
    fn every_gate_refusal_has_one_counted_policy_reason() {
        let t = Instant::now();
        let a = "203.0.113.1".parse().unwrap();
        let b = "203.0.113.2".parse().unwrap();
        let mut gate = Gate::with_capacity(Duration::from_secs(5), 1, 1);
        assert!(gate.admit(a, t));
        assert_eq!(gate.refusals, counts(0, 0, 0), "admission is not refusal");
        assert!(
            !gate.admit(b, t),
            "rate wins when both rate and capacity are full"
        );
        assert_eq!(
            gate.refusals.cooldown + gate.refusals.rate + gate.refusals.capacity,
            1,
            "a policy-refused alert must not disappear from refusal accounting"
        );
        assert_eq!(gate.refusals, counts(0, 1, 0));
        assert!(
            !gate.admit(a, t),
            "cooldown wins even at full rate and capacity"
        );
        assert_eq!(gate.refusals, counts(1, 1, 0));
        assert!(
            !gate.admit(b, t + Duration::from_secs(1)),
            "capacity wins after rate window resets"
        );
        assert_eq!(gate.refusals, counts(1, 1, 1));
        assert_eq!(gate.in_window, 0, "capacity refusal consumes no rate slot");
        assert!(
            gate.admit(b, t + Duration::from_secs(5)),
            "refused b has no cooldown after a expires"
        );
        assert_eq!(gate.refusals, counts(1, 1, 1));
        let mut zero = Gate::with_capacity(Duration::ZERO, 0, 0);
        assert!(!zero.admit(a, t));
        assert!(!zero.admit(a, t + Duration::from_secs(1)));
        assert_eq!(
            zero.refusals,
            counts(0, 2, 0),
            "zero rate wins even at zero capacity"
        );
        assert!(zero.last_sent.is_empty());
        assert!(zero.expires.is_empty());
        assert_eq!(zero.in_window, 0);
    }

    #[test]
    fn gate_refusal_counters_saturate_independently() {
        let t = Instant::now();
        let a = "203.0.113.1".parse().unwrap();
        let b = "203.0.113.2".parse().unwrap();
        let mut gate = Gate::with_capacity(Duration::from_secs(60), 1, 1);
        assert!(gate.admit(a, t));
        gate.refusals = counts(u64::MAX - 1, u64::MAX - 1, u64::MAX - 1);
        for _ in 0..2 {
            assert!(!gate.admit(a, t));
        }
        assert_eq!(gate.refusals, counts(u64::MAX, u64::MAX - 1, u64::MAX - 1));
        for _ in 0..2 {
            assert!(!gate.admit(b, t));
        }
        assert_eq!(gate.refusals, counts(u64::MAX, u64::MAX, u64::MAX - 1));
        for _ in 0..2 {
            assert!(!gate.admit(b, t + Duration::from_secs(1)));
        }
        assert_eq!(gate.refusals, counts(u64::MAX, u64::MAX, u64::MAX));
        assert!(gate.admit(b, t + Duration::from_secs(60)));
        assert_eq!(
            gate.refusals,
            counts(u64::MAX, u64::MAX, u64::MAX),
            "saturation never blocks admission"
        );
    }

    #[test]
    fn gate_suppresses_repeats_and_caps_rate() {
        let t0 = Instant::now();
        let mut gate = Gate::new(Duration::from_secs(60), 3);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(gate.admit(a, t0));
        assert!(!gate.admit(a, t0 + Duration::from_secs(10)), "cooldown");
        assert_eq!(gate.refusals.cooldown, 1, "repeat refusal is observable");
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

    #[test]
    fn gate_cooldown_memory_has_a_hard_bound_without_eviction() {
        let now = Instant::now();
        let mut gate = Gate::new(Duration::from_secs(86_400), u32::MAX);
        for ip in 0..COOLDOWN_CAP as u32 {
            assert!(gate.admit(IpAddr::V4(std::net::Ipv4Addr::from(ip)), now));
        }
        let extra = IpAddr::V4(std::net::Ipv4Addr::from(COOLDOWN_CAP as u32));
        assert!(
            !gate.admit(extra, now),
            "full cooldown memory must refuse a new address"
        );
        assert!(
            gate.last_sent.len() <= COOLDOWN_CAP,
            "memory must not grow beyond its budget"
        );
        assert!(
            !gate.admit(IpAddr::V4(std::net::Ipv4Addr::from(0)), now),
            "capacity must not evict an unexpired cooldown"
        );
    }

    #[test]
    fn gate_capacity_refusal_keeps_live_cooldowns_and_releases_only_expired_slots() {
        let t = Instant::now();
        let a = IpAddr::V4(std::net::Ipv4Addr::from(1));
        let b = IpAddr::V4(std::net::Ipv4Addr::from(2));
        let c = IpAddr::V4(std::net::Ipv4Addr::from(3));
        let mut gate = Gate::with_capacity(Duration::from_secs(5), 2, 2);
        assert!(gate.admit(a, t));
        assert!(gate.admit(b, t + Duration::from_secs(1)));
        assert!(!gate.admit(c, t + Duration::from_secs(2)));
        assert_eq!(gate.refusals.capacity, 1);
        assert_eq!(gate.in_window, 0, "capacity refusal reserves no rate slot");
        assert!(!gate.admit(a, t + Duration::from_secs(4)));
        assert!(!gate.admit(b, t + Duration::from_secs(4)));
        assert!(
            gate.admit(c, t + Duration::from_secs(5)),
            "oldest expired slot is available"
        );
        assert!(
            !gate.admit(b, t + Duration::from_secs(5)),
            "younger cooldown remains"
        );
        assert!(
            gate.admit(a, t + Duration::from_secs(6)),
            "next expired slot is available"
        );
        assert!(
            !gate.admit(c, t + Duration::from_secs(6)),
            "refusals must not renew c early"
        );
        assert_eq!(gate.refusals.capacity, 1);
    }

    #[test]
    fn gate_rate_refusal_does_not_start_cooldown_and_zero_policies_are_defined() {
        let t = Instant::now();
        let a = IpAddr::V4(std::net::Ipv4Addr::from(1));
        let b = IpAddr::V4(std::net::Ipv4Addr::from(2));
        let mut gate = Gate::with_capacity(Duration::from_secs(60), 1, 2);
        assert!(gate.admit(a, t));
        assert!(!gate.admit(b, t));
        assert!(
            gate.admit(b, t + Duration::from_secs(1)),
            "rate refusal did not remember b"
        );

        let mut gate = Gate::with_capacity(Duration::ZERO, 2, 1);
        assert!(gate.admit(a, t));
        assert!(
            gate.admit(a, t),
            "zero cooldown permits another policy admission"
        );
        assert!(!gate.admit(b, t), "zero cooldown still respects rate");
        assert!(gate.admit(b, t + Duration::from_secs(1)));

        let mut gate = Gate::with_capacity(Duration::from_secs(60), 0, 2);
        assert!(!gate.admit(a, t));
        assert!(!gate.admit(a, t + Duration::from_secs(100)));
        assert!(gate.last_sent.is_empty());
        assert!(gate.expires.is_empty());
        let mut gate = Gate::with_capacity(Duration::ZERO, 1, 0);
        assert!(!gate.admit(a, t));
        assert_eq!(gate.in_window, 0);
        assert_eq!(gate.refusals.capacity, 1);
    }

    #[test]
    fn gate_generated_history_preserves_cooldown_and_bounded_unique_memory() {
        let t = Instant::now();
        let cooldown = Duration::from_millis(300);
        let mut gate = Gate::with_capacity(cooldown, 7, 4);
        let mut accepted = std::collections::HashMap::<IpAddr, Instant>::new();
        let mut random = 7u32;
        let mut admissions = 0;
        for step in 0..10_000u64 {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let ip = IpAddr::V4(std::net::Ipv4Addr::from((random >> 16) % 16));
            let now = t + Duration::from_millis(step * 53);
            if gate.admit(ip, now) {
                if let Some(last) = accepted.insert(ip, now) {
                    assert!(
                        now.duration_since(last) >= cooldown,
                        "no early repeat admission"
                    );
                }
                admissions += 1;
            }
            let rejected = u128::from(gate.refusals.cooldown)
                + u128::from(gate.refusals.rate)
                + u128::from(gate.refusals.capacity);
            assert_eq!(
                admissions + rejected,
                u128::from(step) + 1,
                "attempts partition into admissions and exactly one refusal category"
            );
            assert!(gate.last_sent.len() <= 4);
            let queued: HashSet<_> = gate.expires.iter().map(|(ip, _)| *ip).collect();
            assert_eq!(
                queued.len(),
                gate.expires.len(),
                "one expiry tuple per address"
            );
            assert_eq!(
                queued, gate.last_sent,
                "expiry and membership have the same owners"
            );
            for (ip, at) in &gate.expires {
                assert_eq!(
                    accepted.get(ip),
                    Some(at),
                    "timestamp comes from successful admission"
                );
                assert!(now.duration_since(*at) < cooldown);
            }
        }
        assert!(
            admissions > 1_000,
            "history exercises renewal, not just refusals"
        );
        assert!(
            gate.refusals.cooldown > 0,
            "history reaches cooldown refusals"
        );
        assert!(gate.refusals.rate > 0, "history reaches rate refusals");
        assert!(gate.refusals.capacity > 0, "history reaches capacity");
    }

    fn lines(f: &mut Follower) -> Vec<String> {
        f.poll()
            .unwrap()
            .lines
            .into_iter()
            .map(|(_, l)| l)
            .collect()
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

    /// Review 2026-10-05 (detector path): a damaged cursor (here: the empty file a power loss
    /// can leave after a rename without sync) was read as "no cursor" and reading started at
    /// the end of the log, silently skipping what arrived before the crash. It now starts at
    /// the beginning of the current file; a missing cursor still follows --from-start.
    #[test]
    fn a_damaged_cursor_rereads_the_log_instead_of_skipping_it() {
        let dir =
            std::env::temp_dir().join(format!("sokol-suricata-damaged-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let eve = dir.join("eve.json");
        std::fs::write(&eve, "before-the-crash\n").unwrap();
        let cursor = dir.join("cursor.json");
        for damaged in ["", "{\"inode\":", "not json"] {
            std::fs::write(&cursor, damaged).unwrap();
            let (mut f, how, flagged) = initial_follower(&eve, Some(&cursor), false);
            assert!(flagged, "{:?}: {}", damaged, how);
            let batch = f.poll().unwrap();
            assert_eq!(
                batch
                    .lines
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect::<Vec<_>>(),
                vec!["before-the-crash\n"],
                "{:?} must not start at the end",
                damaged
            );
        }
        // Unreadable, not only unparseable (here a directory): an error too, never a first start
        // (review 2026-10-08: treating every read error as "no cursor" went untested).
        std::fs::remove_file(&cursor).unwrap();
        std::fs::create_dir(&cursor).unwrap();
        assert!(Cursor::load(&cursor).is_err());
        let (mut f, how, flagged) = initial_follower(&eve, Some(&cursor), false);
        assert!(flagged, "{}", how);
        assert_eq!(
            f.poll().unwrap().lines.len(),
            1,
            "an unreadable cursor rereads"
        );
        std::fs::remove_dir(&cursor).unwrap();
        let (mut f, _, flagged) = initial_follower(&eve, Some(&cursor), false);
        assert!(!flagged);
        assert!(
            f.poll().unwrap().lines.is_empty(),
            "no cursor, no --from-start: the end"
        );
        // A saved cursor round-trips and leaves no temporary file behind.
        let at = Cursor {
            inode: 7,
            position: 3,
        };
        at.save(&cursor).unwrap();
        assert_eq!(Cursor::load(&cursor), Ok(Some(at)));
        assert!(!cursor.with_extension("tmp").exists());
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
            f.poll().unwrap().lines,
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
        let _ = f.poll().unwrap().lines;
        let cursor = Cursor {
            position: 4, // "two" was queued but not yet answered when the adapter stopped
            ..f.cursor()
        };
        cursor.save(&saved).unwrap();
        assert_eq!(Cursor::load(&saved), Ok(Some(cursor)));

        // Written while the adapter was down.
        let mut w = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        w.write_all(b"three\n").unwrap();
        let (mut f, how) = Follower::resume(&path, cursor);
        assert_eq!(how, "resumed at the saved position");
        assert_eq!(
            lines(&mut f),
            vec!["two\n", "three\n"],
            "nothing unanswered is lost"
        );

        // Rotated while down: the new file is read from its start.
        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        std::fs::write(&path, "four\n").unwrap();
        let (mut f, how) = Follower::resume(&path, cursor);
        assert!(how.starts_with("file rotated"), "{}", how);
        assert_eq!(lines(&mut f), vec!["four\n"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resume_retains_its_anchor_while_the_source_is_missing() {
        let dir =
            std::env::temp_dir().join(format!("sokol-suricata-deferred-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        let parked = dir.join("eve.parked");
        let prefix = "already read\n";
        for mode in ["same", "rotated", "truncated"] {
            std::fs::write(&path, format!("{prefix}pending\n")).unwrap();
            let saved = Cursor {
                inode: std::fs::metadata(&path).unwrap().ino(),
                position: prefix.len() as u64,
            };
            std::fs::rename(&path, &parked).unwrap();
            let (mut follower, _) = Follower::resume(&path, saved);
            assert_eq!(
                follower.cursor(),
                saved,
                "absence is not a new source identity"
            );
            for _ in 0..3 {
                assert!(follower.poll().unwrap().lines.is_empty());
                assert_eq!(follower.checkpoint(None), saved);
            }
            let expected = match mode {
                "same" => {
                    std::fs::rename(&parked, &path).unwrap();
                    "pending\n"
                }
                "rotated" => {
                    std::fs::write(&path, "replacement starts here\n").unwrap();
                    "replacement starts here\n"
                }
                _ => {
                    std::fs::rename(&parked, &path).unwrap();
                    std::fs::write(&path, "new\n").unwrap();
                    "new\n"
                }
            };
            assert_eq!(lines(&mut follower).concat(), expected);
            assert!(lines(&mut follower).is_empty());
            assert_eq!(
                follower.checkpoint(None).position,
                std::fs::metadata(&path).unwrap().len()
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_install_does_not_erase_the_selected_resume_anchor() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-deferred-seek-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("absent.json");
        let anchor = Cursor {
            inode: 17,
            position: 23,
        };
        let (mut follower, _) = Follower::resume(&path, anchor);
        let token = follower.content.clone();
        // A real unseekable descriptor fails after open, without a runtime failpoint.
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(stream));
        assert!(follower.install(file, anchor.position).is_err());
        assert_eq!(follower.cursor(), anchor);
        assert_eq!(follower.pending_resume, Some(anchor));
        assert!(follower.reader.is_none());
        assert!(std::rc::Rc::ptr_eq(&token, &follower.content));
        assert_eq!(follower.position, 0);
        assert_eq!(follower.line_start, 0);
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
        let (mut follower, how) = Follower::resume(&path, old);
        assert!(how.starts_with("file truncated"), "{how}");
        let recovered = lines(&mut follower);
        assert_eq!(recovered, vec![format!("{ALERT}\n")]);
        assert!(decide(&recovered[0], &filter()).is_some());
        assert!(
            lines(&mut follower).is_empty(),
            "do not reread on the next poll"
        );
        let next = follower.cursor();
        let (mut resumed, _) = Follower::resume(&path, next);
        assert!(
            lines(&mut resumed).is_empty(),
            "the new cursor resumes at the new end"
        );
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
        let old_lines = follower.poll().unwrap().lines;
        let old = follower.queued_at(old_lines[1].0);
        assert_eq!(
            follower.checkpoint(Some(&old)),
            old.cursor,
            "same-file queue position is retained"
        );

        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        let new_content = "new first\nnew second\nnew third\n";
        std::fs::write(&path, new_content).unwrap();
        let new_lines = follower.poll().unwrap().lines;
        assert_ne!(follower.cursor().inode, old.cursor.inode);
        assert!(
            new_content.len() as u64 > old.cursor.position,
            "old offset would be accepted in the new file"
        );
        let checkpoint = follower.checkpoint(Some(&old));
        let saved = dir.join("cursor");
        checkpoint.save(&saved).unwrap();
        let (mut restarted, _) = Follower::resume(&path, Cursor::load(&saved).unwrap().unwrap());
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
        let pending_new = follower.queued_at(new_lines[1].0);
        assert_eq!(follower.checkpoint(Some(&pending_new)), pending_new.cursor);
        assert_eq!(
            follower.checkpoint(None),
            follower.cursor(),
            "empty queue may checkpoint the read end"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn detected_truncation_fences_offsets_from_previous_contents() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-truncate-queue-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "already read\nold pending\n").unwrap();
        let mut follower = Follower::new(&path, true);
        let old_lines = follower.poll().unwrap().lines;
        let old = follower.queued_at(old_lines[1].0);
        assert_eq!(follower.checkpoint(Some(&old)), old.cursor);

        // The reader observes shorter contents before they regrow past the old offset.
        std::fs::write(&path, "new first\n").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), old.cursor.inode);
        let first = follower.poll().unwrap().lines;
        assert_eq!(first[0].1, "new first\n");
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"new second\nnew third\n").unwrap();
        let more = follower.poll().unwrap().lines;
        assert!(std::fs::metadata(&path).unwrap().len() > old.cursor.position);
        let checkpoint = follower.checkpoint(Some(&old));
        assert_eq!(
            checkpoint.position, 0,
            "same inode must not transplant an old-content offset"
        );
        let (mut restarted, _) = Follower::resume(&path, checkpoint);
        assert_eq!(
            lines(&mut restarted).concat(),
            "new first\nnew second\nnew third\n"
        );

        // Once only current-content work remains, checkpoint its actual pending position.
        let pending = follower.queued_at(more[0].0);
        assert_eq!(follower.checkpoint(Some(&pending)), pending.cursor);
        assert_eq!(follower.checkpoint(None), follower.cursor());
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct ReadFault {
        bytes: std::io::Cursor<Vec<u8>>,
        fail_at: u64,
        failed: bool,
    }

    impl std::io::Read for ReadFault {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.bytes.position() == self.fail_at && !self.failed {
                self.failed = true;
                return Err(io::Error::other("injected read failure"));
            }
            let limit = if self.failed {
                buf.len()
            } else {
                buf.len()
                    .min((self.fail_at - self.bytes.position()) as usize)
            };
            std::io::Read::read(&mut self.bytes, &mut buf[..limit])
        }
    }

    #[test]
    fn a_read_error_preserves_completed_alerts_and_unfinished_bytes() {
        let dir =
            std::env::temp_dir().join(format!("sokol-suricata-read-error-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        let first = format!("{ALERT}\n");
        let second = format!("{}\n", ALERT.replace("telnet probe", "é probe"));
        let split = second.find('é').unwrap() + 1; // between the two UTF-8 bytes
        let bytes = format!("{first}{second}").into_bytes();
        std::fs::write(&path, &bytes).unwrap();
        let mut follower = Follower::new(&path, true);
        let token = follower.content.clone();
        let fault = ReadFault {
            bytes: std::io::Cursor::new(bytes),
            fail_at: (first.len() + split) as u64,
            failed: false,
        };
        let mut reader = BufReader::with_capacity(7, fault);
        let result = follower.read_batch(&mut reader);
        assert_eq!(
            result.lines.len(),
            1,
            "a later I/O error must not erase a completed alert"
        );
        assert_eq!(result.error.unwrap().to_string(), "injected read failure");
        let batch = result.lines;
        assert_eq!(batch, vec![(0, first.clone())]);
        assert!(decide(&batch[0].1, &filter()).is_some());
        assert!(
            !follower.budget_exhausted,
            "read errors must yield rather than busy-loop"
        );
        assert!(std::rc::Rc::ptr_eq(&token, &follower.content));
        let pending = follower.queued_at(batch[0].0);
        assert_eq!(follower.checkpoint(Some(&pending)).position, 0);
        let resumed = follower.read_batch(&mut reader);
        assert!(resumed.error.is_none());
        let resumed = resumed.lines;
        assert_eq!(resumed, vec![(first.len() as u64, second.clone())]);
        assert!(decide(&resumed[0].1, &filter()).is_some());
        assert_eq!(
            follower.cursor().position,
            (first.len() + second.len()) as u64
        );
        assert!(follower.read_batch(&mut reader).lines.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn read_errors_before_a_complete_line_preserve_the_cursor_and_retry_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-suricata-incomplete-error-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        let line = format!("{}\n", ALERT.replace("telnet probe", "é probe"));
        std::fs::write(&path, &line).unwrap();
        for fail_at in [
            0,
            (line.find('é').unwrap() + 1) as u64,
            (line.len() - 1) as u64,
        ] {
            let mut follower = Follower::new(&path, true);
            let fault = ReadFault {
                bytes: std::io::Cursor::new(line.as_bytes().to_vec()),
                fail_at,
                failed: false,
            };
            let mut reader = BufReader::with_capacity(7, fault);
            let failed = follower.read_batch(&mut reader);
            assert!(failed.error.is_some());
            assert!(failed.lines.is_empty());
            assert_eq!(
                follower.cursor().position,
                0,
                "never checkpoint an unfinished record"
            );
            assert!(!follower.budget_exhausted);
            let retried = follower.read_batch(&mut reader);
            assert!(retried.error.is_none());
            assert_eq!(retried.lines, vec![(0, line.clone())]);
            assert!(decide(&retried.lines[0].1, &filter()).is_some());
            assert_eq!(follower.cursor().position, line.len() as u64);
        }
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
            batch.unwrap().lines,
            vec![(0, "first\n".into()), (8, "last\n".into())]
        );
        assert_eq!(follower.cursor().position, 13);
        let (mut resumed, _) = Follower::resume(&path, follower.cursor());
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
        assert_eq!(batch.unwrap().lines, vec![(0, "first\n".into())]);
        assert_eq!(follower.cursor().position, 6);
        assert!(lines(&mut follower).is_empty());
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"\xa9\n").unwrap();
        assert_eq!(follower.poll().unwrap().lines, vec![(6, "é\n".into())]);
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
        assert_eq!(f.poll().unwrap().lines.len(), MAX_POLL_LINES);
        assert!(f.budget_exhausted);
        assert_eq!(f.cursor().position, (2 * MAX_POLL_LINES) as u64);
        assert_eq!(
            f.poll().unwrap().lines,
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
            assert!(f.poll().unwrap().lines.is_empty());
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
            f.poll().unwrap().lines,
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
            observed.extend(f.poll().unwrap().lines);
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
        assert_eq!(f.poll().unwrap().lines.len(), MAX_POLL_LINES);
        let old_inode = f.cursor().inode;
        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        std::fs::write(&path, "new\n").unwrap();
        assert_eq!(
            f.poll().unwrap().lines,
            vec![((MAX_POLL_LINES * 2) as u64, "x\n".into())]
        );
        assert_eq!(f.cursor().inode, old_inode);
        assert_eq!(f.poll().unwrap().lines, vec![(0, "new\n".into())]);
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
                assert!(f.poll().unwrap().lines.is_empty());
            }
            assert!(f.discarding);
            if rotate {
                std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
            }
            std::fs::write(&path, "fresh\n").unwrap();
            assert_eq!(f.poll().unwrap().lines, vec![(0, "fresh\n".into())]);
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
        assert!(f.poll().unwrap().lines.is_empty());
        assert_eq!(f.position, (2 * MAX_POLL_LINES) as u64);
        assert_eq!(
            f.poll().unwrap().lines,
            vec![((2 * (MAX_POLL_LINES + 1)) as u64, "ok\n".into())]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forwarding_budget_ages_exactly_and_future_timestamps_cannot_enlarge_it() {
        let t = Instant::now();
        assert_eq!(
            forwarding_deadline(0, 1_500, t, 2).unwrap(),
            t + Duration::from_millis(500)
        );
        assert_eq!(
            forwarding_deadline(0, 2_000, t, 2).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            forwarding_deadline(0, 2_001, t, 2).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            forwarding_deadline(9_000, 0, t, 2).unwrap(),
            t + Duration::from_secs(2)
        );
        assert_eq!(
            forwarding_deadline(0, 0, t, 0).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            forwarding_deadline(i64::MIN, i64::MAX, t, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            forwarding_deadline(0, 0, t, u64::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
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
