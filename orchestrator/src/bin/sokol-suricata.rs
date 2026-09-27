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
    /// Suricata EVE JSON log to follow.
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
}

struct Filter {
    max_severity: u64,
    ignore_sid: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq)]
struct Alert {
    /// Hash of the EVE line: a resend after a lost ACK is recognised by the node.
    event: String,
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
    Some(Alert {
        event: blake3::hash(line.as_bytes()).to_hex()[..32].to_string(),
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

/// `tail -F` for one file: survives truncation and rotation (rename + new file).
struct Follower {
    path: PathBuf,
    reader: Option<BufReader<File>>,
    inode: u64,
    position: u64,
    partial: String,
}

impl Follower {
    fn new(path: &Path, from_start: bool) -> Self {
        let mut f = Self {
            path: path.to_path_buf(),
            reader: None,
            inode: 0,
            position: 0,
            partial: String::new(),
        };
        let _ = f.open(!from_start);
        f
    }

    fn open(&mut self, at_end: bool) -> io::Result<()> {
        let file = File::open(&self.path)?;
        let meta = file.metadata()?;
        let mut reader = BufReader::new(file);
        self.position = if at_end { meta.len() } else { 0 };
        reader.seek(SeekFrom::Start(self.position))?;
        self.inode = meta.ino();
        self.reader = Some(reader);
        self.partial.clear();
        Ok(())
    }

    /// Complete lines appended since the last call.
    fn poll(&mut self) -> io::Result<Vec<String>> {
        match std::fs::metadata(&self.path) {
            Ok(meta)
                if self.reader.is_none()
                    || meta.ino() != self.inode
                    || meta.len() < self.position =>
            {
                // First appearance, rotation or truncation: read the new file from its start.
                self.open(false)?;
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }
        let reader = self.reader.as_mut().expect("opened above");
        let mut lines = Vec::new();
        loop {
            let mut chunk = String::new();
            let n = reader.read_line(&mut chunk)?;
            if n == 0 {
                break;
            }
            self.position += n as u64;
            if chunk.ends_with('\n') {
                self.partial.push_str(&chunk);
                lines.push(std::mem::take(&mut self.partial));
            } else {
                // Suricata is mid-write; keep the fragment until the newline arrives.
                self.partial.push_str(&chunk);
            }
        }
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
    let mut follower = Follower::new(&args.eve, args.from_start);
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
                for line in lines {
                    let Some(alert) = decide(&line, &filter) else {
                        continue;
                    };
                    if !gate.admit(alert.src, Instant::now()) {
                        continue;
                    }
                    let lost = outbox.lost;
                    outbox.push(&alert.signal_line());
                    if outbox.lost > lost {
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
        std::thread::sleep(Duration::from_millis(50));
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

    #[test]
    fn follower_handles_appends_partial_lines_truncation_and_rotation() {
        let dir = std::env::temp_dir().join(format!("sokol-suricata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("eve.json");
        std::fs::write(&path, "old line\n").unwrap();

        let mut f = Follower::new(&path, false);
        assert!(f.poll().unwrap().is_empty(), "starts at the end by default");

        let mut w = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        w.write_all(b"one\ntw").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["one\n"]);
        w.write_all(b"o\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["two\n"], "partial line joined");

        // Rotation: rename away, new file appears.
        std::fs::rename(&path, dir.join("eve.json.1")).unwrap();
        std::fs::write(&path, "three\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["three\n"]);

        // Truncation in place.
        std::fs::write(&path, "").unwrap();
        assert!(f.poll().unwrap().is_empty());
        std::fs::write(&path, "four\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["four\n"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
