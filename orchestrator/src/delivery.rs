//! Delivery of detector adapters' signals to the node's IPC socket (review finding F09).
//!
//! A signal leaves the outbox only when the node has answered it: the connection is switched to
//! ACK mode, and the node replies to each line with `OK applied`, `OK pending`, `OK recorded`,
//! `OK duplicate` (an event id it already acted on), `OK refused <why>` or `ERR <why>`. Refusals and errors are final (retrying a protected address
//! or a malformed line would not change the answer). A node that is down, restarting or not
//! answering leaves the signal queued; delivery is retried with a growing pause. The queue is
//! bounded: when it is full the oldest signal is dropped and counted.
//! push_before() additionally drops stale forwarding attempts with a separate expired counter;
//! this is local policy loss, never a node acknowledgement or a retraction.
//! push() rejects malformed framing or oversized wire lines before changing that queue;
//! its Result reports local admission only, never delivery. Callers must handle rejection.
//! Unknown or incomplete replies retain unexpired signals and reconnect with backoff; only a
//! complete recognized acknowledgement is final. ADR-0019 retraction acknowledgements
//! are Recorded outcomes too. This does not establish durable storage.
//! Each answer (including the ACK handshake) is limited to 8192 bytes including newline
//! and ANSWER_TIMEOUT total reading time, not a fresh timeout for every fragment.
//! Oversized/late answers keep the signal queued and trigger the existing reconnect/backoff.
//! Blocking reads check the deadline at 100ms intervals (plus scheduler/kernel delay).
//! This bounds answer reads, not connect/write time or a whole multi-signal flush.
//! push_with_deadline additionally ages a source TTL before each send and switches
//! to a caller-provided retraction on expiry; it never retires an expired event locally.
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Maximum outgoing wire bytes, including the newline appended by exchange().
/// Matches the node's main.rs MAX_IPC_LINE. Check bytes, not Unicode characters.
pub const MAX_SIGNAL_BYTES: usize = 4096;

pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum wire bytes in one acknowledgement, including its terminating newline.
/// The node admits at most 4096-byte IPC requests (main.rs MAX_IPC_LINE); allow
/// room for an echoed invalid field plus the diagnostic prefix in a final ERR.
pub const MAX_ANSWER_BYTES: usize = 8192;
// A fixed short read timeout lets the loop check its total deadline without
// changing socket options after a peer has closed (EINVAL on macOS).
const ANSWER_READ_SLICE: Duration = Duration::from_millis(100);
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// Recorded by the node; its kernel map refused the entry for now and the node retries it.
    Pending,
    Recorded,
    /// The node already acted on this event id (a resend); nothing changed.
    Duplicate,
    /// Final: the node will not act on it (e.g. a protected address).
    Refused(String),
    /// Final: the node could not parse it.
    Rejected(String),
}

impl Outcome {
    fn parse(reply: &str) -> io::Result<Outcome> {
        let reply = reply.trim();
        Ok(match reply {
            "OK applied" => Outcome::Applied,
            "OK pending" => Outcome::Pending,
            "OK recorded"
            | "OK recorded before its signal"
            | "OK nothing held"
            | "OK still held by other reasons"
            | "OK lifted"
            | "OK shortened" => Outcome::Recorded,
            "OK duplicate" => Outcome::Duplicate,
            _ => {
                if let Some(why) = reply
                    .strip_prefix("OK refused ")
                    .filter(|why| !why.trim().is_empty())
                {
                    Outcome::Refused(why.trim().to_string())
                } else if let Some(why) = reply
                    .strip_prefix("ERR ")
                    .filter(|why| !why.trim().is_empty())
                {
                    Outcome::Rejected(why.trim().to_string())
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unrecognized acknowledgement: {:?}", reply),
                    ));
                }
            }
        })
    }
}

struct Conn {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Conn {
    fn open(socket: &Path) -> io::Result<Conn> {
        let stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(ANSWER_READ_SLICE))?;
        stream.set_write_timeout(Some(ANSWER_TIMEOUT))?;
        let mut conn = Conn {
            reader: BufReader::new(stream.try_clone()?),
            stream,
        };
        let hello = conn.exchange("ACK")?;
        if hello.trim() != "OK ack" {
            return Err(io::Error::other(format!(
                "node does not confirm signals (answered '{}'); upgrade the node",
                hello.trim()
            )));
        }
        Ok(conn)
    }

    fn exchange(&mut self, line: &str) -> io::Result<String> {
        self.stream
            .write_all(format!("{}\n", line.trim_end()).as_bytes())?;
        self.stream.flush()?;
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        let mut reply = Vec::new();
        loop {
            if reply.len() == MAX_ANSWER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "answer exceeds byte limit",
                ));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "answer deadline exceeded",
                ));
            }
            let bytes = match self.reader.fill_buf() {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                result => result?,
            };
            // A readable fragment must not renew the total answer deadline.
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "answer deadline exceeded",
                ));
            }
            if bytes.is_empty() {
                break;
            }
            let newline = bytes.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(bytes.len(), |index| index + 1);
            if count > MAX_ANSWER_BYTES - reply.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "answer exceeds byte limit",
                ));
            }
            reply.extend(bytes.iter().take(count).copied());
            self.reader.consume(count);
            if newline.is_some() {
                break;
            }
        }
        let reply = String::from_utf8(reply)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if reply.is_empty() || !reply.ends_with('\n') {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "node closed the connection without answering",
            ));
        }
        Ok(reply)
    }
}

fn validated_line(line: &str) -> io::Result<&str> {
    let payload = line
        .strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line);
    if payload.contains('\n') || payload.contains('\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signal contains a line break",
        ));
    }
    let payload = payload.trim_end(); // preserve the existing wire normalization
    if payload.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signal is empty",
        ));
    }
    if payload.len() >= MAX_SIGNAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signal exceeds IPC limit of 4096 bytes including newline",
        ));
    }
    Ok(payload)
}

/// A source expiry retained alongside the exact queued request. Rendering happens
/// after the ACK handshake, immediately before each attempt, including retries.
struct TimedLine {
    expires: Instant,
    head: String,
    max_seconds: u64,
    tail: String,
    expired: String,
}

impl TimedLine {
    fn render(&self, now: Instant) -> String {
        match self.expires.checked_duration_since(now) {
            Some(left) if !left.is_zero() => {
                let seconds = left
                    .as_secs()
                    .saturating_add(u64::from(left.subsec_nanos() != 0));
                format!(
                    "{};ttl={}:{}",
                    self.head,
                    seconds.min(self.max_seconds),
                    self.tail
                )
            }
            _ => self.expired.clone(),
        }
    }
}

enum Deadline {
    SourceTtl(TimedLine),
    ForwardBefore(Instant),
}

pub struct Outbox {
    socket: PathBuf,
    queue: VecDeque<String>,
    // Exactly one entry per queued line, including ordinary lines without an expiry.
    deadlines: VecDeque<Option<Deadline>>,
    cap: usize,
    conn: Option<Conn>,
    backoff: Duration,
    retry_at: Option<Instant>,
    /// Signals dropped because the queue was full.
    pub lost: u64,
    /// Local forwarding-policy losses; no node reply or undo of an earlier attempt.
    pub expired: u64,
    /// Whether the last attempt failed (for logging an outage once).
    pub failing: bool,
}

impl Outbox {
    pub fn new(socket: &Path, cap: usize) -> Self {
        Self {
            socket: socket.to_path_buf(),
            queue: VecDeque::new(),
            deadlines: VecDeque::new(),
            cap: cap.max(1),
            conn: None,
            backoff: BACKOFF_MIN,
            retry_at: None,
            lost: 0,
            expired: 0,
            failing: false,
        }
    }

    /// Queue one IPC line. An optional final LF or CRLF is accepted; embedded
    /// line breaks, empty payloads and over-limit wire lengths are rejected before
    /// any queue mutation. The caller must report rejection; it is not delivery
    /// or overflow loss. This validates framing, not command meaning or authority.
    pub fn push(&mut self, line: &str) -> io::Result<()> {
        validated_line(line)?;
        if self.queue.len() >= self.cap {
            self.queue.pop_front();
            self.deadlines.pop_front();
            self.lost += 1;
        }
        self.queue.push_back(line.trim_end().to_string());
        self.deadlines.push_back(None);
        Ok(())
    }

    /// Queue a SIGNAL with a source deadline. Its `;ttl=` is recalculated before
    /// each write; at/after expiry send `expired` instead (normally its RETRACT).
    /// Both possible wire frames are validated before any queue mutation. The
    /// caller owns command semantics and the expiry clock; acknowledgement rules,
    /// overflow, and backoff are the same as push(). This is in-memory state.
    #[allow(dead_code)] // Suricata uses push/push_before; source TTL is CrowdSec policy.
    pub fn push_with_deadline(
        &mut self,
        line: &str,
        expires: Instant,
        expired: &str,
    ) -> io::Result<()> {
        let payload = validated_line(line)?;
        let expired = validated_line(expired)?.to_string();
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected SIGNAL#id;ttl=seconds",
            )
        };
        let (head, rest) = payload.split_once(";ttl=").ok_or_else(invalid)?;
        let (ttl, tail) = rest.split_once(':').ok_or_else(invalid)?;
        if !head.starts_with("SIGNAL#") || ttl.parse::<u64>().ok().filter(|n| *n > 0).is_none() {
            return Err(invalid());
        }
        let timing = TimedLine {
            expires,
            head: head.to_string(),
            max_seconds: ttl.parse::<u64>().map_err(|_| invalid())?,
            tail: tail.to_string(),
            expired,
        };
        self.push(line)?;
        if let Some(last) = self.deadlines.back_mut() {
            *last = Some(Deadline::SourceTtl(timing));
        }
        Ok(())
    }

    /// Forward only while the local freshness budget remains. Validate before mutation.
    /// Expiry is a counted local loss, including after a lost ACK; it does not retract
    /// possibly applied effects. Use push_with_deadline for source TTL + retraction.
    #[allow(dead_code)] // CrowdSec uses source TTL, not a forwarding freshness budget.
    pub fn push_before(&mut self, line: &str, before: Instant) -> io::Result<()> {
        self.push(line)?;
        if let Some(last) = self.deadlines.back_mut() {
            *last = Some(Deadline::ForwardBefore(before));
        }
        Ok(())
    }

    fn expire_front(&mut self) -> bool {
        if !matches!(self.deadlines.front(), Some(Some(Deadline::ForwardBefore(at)))
            if Instant::now() >= *at)
        {
            return false;
        }
        self.queue.pop_front();
        self.deadlines.pop_front();
        self.expired = self.expired.saturating_add(1);
        true
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Handles up to `max` queued signals in FIFO order (answers plus freshness losses).
    /// Freshness expiry is checked during backoff and again after opening/handshake.
    /// Stops at transport failure; unexpired obligations retain the existing backoff.
    /// Returns node answers only; local expiry is reported through the expired counter.
    pub fn flush(&mut self, max: usize) -> (Vec<(String, Outcome)>, Option<String>) {
        let mut done = Vec::new();
        // Preserve the ordinary answer bound; each local loss spends one of its slots.
        let mut max = max;
        while done.len() < max {
            if self.expire_front() {
                // The loop condition proves max > 0 here.
                max -= 1;
                continue;
            }
            if self.retry_at.is_some_and(|t| Instant::now() < t) {
                break;
            }
            let Some(line) = self.queue.front().cloned() else {
                break;
            };
            let ready = if self.conn.is_none() {
                Conn::open(&self.socket).map(|conn| self.conn = Some(conn))
            } else {
                Ok(())
            };
            // The ACK handshake may consume the last of the freshness budget.
            if ready.is_ok() && self.expire_front() {
                // A successful handshake followed by policy expiry proves reachability,
                // even though no signal acknowledgement will reset outage state.
                self.failing = false;
                self.backoff = BACKOFF_MIN;
                self.retry_at = None;
                // The loop condition proves max > 0 here.
                max -= 1;
                continue;
            }
            let wire = match self.deadlines.front() {
                Some(Some(Deadline::SourceTtl(timing))) => timing.render(Instant::now()),
                _ => line,
            };
            let reply = ready.and_then(|()| {
                self.conn
                    .as_mut()
                    .ok_or_else(|| io::Error::other("delivery connection unavailable"))?
                    .exchange(&wire)
            });
            match reply.and_then(|text| Outcome::parse(&text)) {
                Ok(outcome) => {
                    self.queue.pop_front();
                    self.deadlines.pop_front();
                    self.failing = false;
                    self.backoff = BACKOFF_MIN;
                    self.retry_at = None;
                    done.push((wire, outcome));
                }
                Err(e) => {
                    // The line may have reached the node; retry later unless its forwarding budget expires.
                    self.conn = None;
                    self.failing = true;
                    self.retry_at = Some(Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                    return (done, Some(e.to_string()));
                }
            }
        }
        (done, None)
    }

    #[cfg(test)]
    fn retry_now(&mut self) {
        self.retry_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn temp_socket(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sokol-delivery-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("ipc.sock")
    }

    /// A node that answers every line with `answer(line)`, after the ACK handshake.
    fn fake_node(
        path: &Path,
        answer: fn(&str) -> Option<&'static str>,
    ) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut w = stream.try_clone().unwrap();
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    let reply = if line == "ACK" {
                        Some("OK ack")
                    } else {
                        answer(&line)
                    };
                    match reply {
                        Some(r) => {
                            let _ = w.write_all(format!("{}\n", r).as_bytes());
                        }
                        None => break,
                    }
                }
            }
        })
    }

    #[test]
    fn forwarding_expiry_is_counted_loss_not_an_ack_and_spends_flush_budget() {
        let path = temp_socket("freshness-budget");
        let mut out = Outbox::new(&path, 4);
        for id in 0..3 {
            out.push_before(
                &format!("SIGNAL#{id}:suricata|203.0.113.7|-|test"),
                Instant::now(),
            )
            .unwrap();
        }
        out.retry_at = Some(Instant::now() + Duration::from_secs(60));
        let (done, error) = out.flush(2);
        assert!(done.is_empty(), "local expiry is not a node answer");
        assert!(
            error.is_none(),
            "expiry needs no connection even during backoff"
        );
        assert_eq!(out.expired, 2);
        assert_eq!(out.lost, 0, "expiry is distinct from overflow");
        assert_eq!(out.pending(), 1, "expiry also respects max work");
        assert_eq!(out.deadlines.len(), 1);
        out.flush(2);
        assert_eq!(out.expired, 3);
        assert_eq!(out.pending(), 0);
        assert!(out.deadlines.is_empty());
    }

    #[test]
    fn invalid_freshness_input_does_not_evict_or_create_a_deadline() {
        let path = temp_socket("freshness-framing");
        let mut out = Outbox::new(&path, 1);
        out.push("SIGNAL:suricata|203.0.113.7|-|test").unwrap();
        assert!(out.push_before("bad\nline", Instant::now()).is_err());
        assert_eq!(out.pending(), 1);
        assert_eq!(out.lost, 0);
        assert!(out.deadlines.front().unwrap().is_none());
    }

    #[test]
    fn lost_ack_then_freshness_expiry_does_not_resend_or_undo_the_signal() {
        let path = temp_socket("freshness-lost-ack");
        let mut out = Outbox::new(&path, 2);
        let line = "SIGNAL#7:suricata|203.0.113.7|-|test";
        out.push_before(line, Instant::now() + Duration::from_secs(60))
            .unwrap();
        let node = fake_node(&path, |line| {
            assert_eq!(line, "SIGNAL#7:suricata|203.0.113.7|-|test");
            None
        });
        let (done, error) = out.flush(1);
        assert!(done.is_empty());
        assert!(error.is_some());
        node.join().unwrap();
        assert_eq!(out.pending(), 1);
        *out.deadlines.front_mut().unwrap() = Some(Deadline::ForwardBefore(Instant::now()));
        let (done, error) = out.flush(1);
        assert!(done.is_empty());
        assert!(
            error.is_none(),
            "expired retry needs no new connection or retraction"
        );
        assert_eq!(out.expired, 1);
        assert_eq!(out.pending(), 0);
        assert!(out.deadlines.is_empty());
    }

    #[test]
    fn timed_wire_ages_rounds_up_and_retracts_at_its_deadline() {
        let now = Instant::now();
        let line = TimedLine {
            expires: now + Duration::from_secs(10),
            head: "SIGNAL#7".into(),
            max_seconds: 10,
            tail: "crowdsec|203.0.113.7|-|test".into(),
            expired: "RETRACT#7:crowdsec|203.0.113.7".into(),
        };
        assert!(line
            .render(now + Duration::from_millis(2500))
            .starts_with("SIGNAL#7;ttl=8:"));
        assert!(line
            .render(now + Duration::from_millis(9999))
            .starts_with("SIGNAL#7;ttl=1:"));
        assert_eq!(line.render(line.expires), line.expired);
        assert_eq!(
            line.render(line.expires + Duration::from_secs(1)),
            line.expired
        );
        assert!(
            line.render(now - Duration::from_secs(1))
                .starts_with("SIGNAL#7;ttl=10:"),
            "even a caller-supplied late deadline cannot enlarge the admitted TTL"
        );
    }

    #[test]
    fn lost_answer_keeps_expiry_and_later_retry_sends_its_retraction() {
        let path = temp_socket("timed-retry");
        let mut out = Outbox::new(&path, 2);
        out.push_with_deadline(
            "SIGNAL#7;ttl=60:crowdsec|203.0.113.7|-|test",
            Instant::now() + Duration::from_secs(60),
            "RETRACT#7:crowdsec|203.0.113.7",
        )
        .unwrap();
        let node = fake_node(&path, |line| {
            assert!(line.starts_with("SIGNAL#7;ttl="));
            None // request observed, answer lost
        });
        let (done, err) = out.flush(1);
        assert!(done.is_empty() && err.is_some());
        node.join().unwrap();
        assert_eq!(out.pending(), 1);
        let Some(Some(Deadline::SourceTtl(timing))) = out.deadlines.front_mut() else {
            panic!("source TTL must be retained after lost answer");
        };
        timing.expires = Instant::now();
        std::fs::remove_file(&path).unwrap();
        let node = fake_node(&path, |line| {
            assert_eq!(line, "RETRACT#7:crowdsec|203.0.113.7");
            Some("OK lifted")
        });
        out.retry_now();
        assert_eq!(
            out.flush(1),
            (
                vec![("RETRACT#7:crowdsec|203.0.113.7".into(), Outcome::Recorded)],
                None
            )
        );
        assert_eq!(out.pending(), 0);
        assert!(out.deadlines.is_empty());
        drop(out);
        node.join().unwrap();
    }

    #[test]
    fn timed_metadata_follows_overflow_and_validation_never_evicts() {
        let path = temp_socket("timed-overflow");
        let mut out = Outbox::new(&path, 1);
        out.push_with_deadline(
            "SIGNAL#7;ttl=1:crowdsec|203.0.113.7|-|test",
            Instant::now(),
            "RETRACT#7:crowdsec|203.0.113.7",
        )
        .unwrap();
        for (line, expiry) in [
            ("SIGNAL#8;ttl=1:crowdsec|203.0.113.8|-|test", "bad\nline"),
            (
                "SIGNAL#8;ttl=0:crowdsec|203.0.113.8|-|test",
                "RETRACT#8:crowdsec|203.0.113.8",
            ),
        ] {
            assert!(out
                .push_with_deadline(line, Instant::now(), expiry)
                .is_err());
            assert_eq!(out.lost, 0);
            assert_eq!(out.pending(), 1);
        }
        out.push("RETRACT#8:crowdsec|203.0.113.8").unwrap();
        assert_eq!(out.lost, 1);
        assert!(out.deadlines.front().unwrap().is_none());
        out.push_with_deadline(
            "SIGNAL#9;ttl=1:crowdsec|203.0.113.9|-|test",
            Instant::now(),
            "RETRACT#9:crowdsec|203.0.113.9",
        )
        .unwrap();
        assert_eq!(out.lost, 2);
        let node = fake_node(&path, |line| {
            assert_eq!(line, "RETRACT#9:crowdsec|203.0.113.9");
            Some("OK nothing held")
        });
        assert_eq!(out.flush(1).0[0].0, "RETRACT#9:crowdsec|203.0.113.9");
        assert!(out.deadlines.is_empty());
        drop(out);
        node.join().unwrap();
    }

    #[test]
    fn a_signal_waits_while_the_node_is_down_and_is_delivered_after() {
        let path = temp_socket("down");
        let mut out = Outbox::new(&path, 16);
        out.push("SIGNAL:test|203.0.113.1|-|x\n").unwrap();
        let (done, err) = out.flush(8);
        assert!(done.is_empty() && err.is_some());
        assert_eq!(out.pending(), 1, "kept for later, not lost");
        let node = fake_node(&path, |_| Some("OK applied"));
        out.retry_now();
        let (done, err) = out.flush(8);
        assert_eq!(err, None);
        assert_eq!(
            done,
            vec![("SIGNAL:test|203.0.113.1|-|x".to_string(), Outcome::Applied)]
        );
        assert_eq!(out.pending(), 0);
        drop(out);
        node.join().unwrap();
    }

    #[test]
    fn refusals_and_errors_are_final() {
        let path = temp_socket("final");
        let node = fake_node(&path, |l| {
            Some(if l.contains("protected") {
                "OK refused source 10.0.0.1 is protected"
            } else {
                "ERR bad line"
            })
        });
        let mut out = Outbox::new(&path, 16);
        out.push("SIGNAL:test|10.0.0.1|-|protected").unwrap();
        out.push("garbage").unwrap();
        let (done, _) = out.flush(8);
        assert_eq!(
            done[0].1,
            Outcome::Refused("source 10.0.0.1 is protected".into())
        );
        assert_eq!(done[1].1, Outcome::Rejected("bad line".into()));
        assert_eq!(out.pending(), 0, "not retried");
        drop(out);
        node.join().unwrap();
    }

    #[test]
    fn a_node_that_does_not_answer_keeps_the_signal() {
        let path = temp_socket("silent");
        let node = fake_node(&path, |_| None); // closes after the handshake
        let mut out = Outbox::new(&path, 16);
        out.push("SIGNAL:test|203.0.113.2|-|x").unwrap();
        let (done, err) = out.flush(8);
        assert!(done.is_empty());
        assert!(err.is_some());
        assert_eq!(out.pending(), 1);
        node.join().unwrap();
    }

    #[test]
    fn a_full_queue_drops_the_oldest_and_counts_it() {
        let mut out = Outbox::new(Path::new("/nonexistent/ipc.sock"), 2);
        out.push("a").unwrap();
        out.push("b").unwrap();
        out.push("c").unwrap();
        assert_eq!(out.pending(), 2);
        assert_eq!(out.lost, 1);
        assert_eq!(out.queue.front().map(String::as_str), Some("b"));
    }

    #[test]
    fn replies_map_to_outcomes() {
        assert_eq!(Outcome::parse("OK applied\n").unwrap(), Outcome::Applied);
        assert_eq!(Outcome::parse("OK pending").unwrap(), Outcome::Pending);
        assert_eq!(Outcome::parse("OK recorded").unwrap(), Outcome::Recorded);
        assert_eq!(Outcome::parse("OK duplicate").unwrap(), Outcome::Duplicate);
        for reply in [
            "OK something else",
            "",
            "ERRatic",
            "OK refusedly",
            "ERR",
            "OK refused",
        ] {
            assert!(
                Outcome::parse(reply).is_err(),
                "{reply:?} must not consume a signal"
            );
        }
    }
    #[test]
    fn unknown_reply_keeps_the_obligation_and_a_later_ack_retires_it() {
        let path = temp_socket("unknown-retry");
        let node = fake_node(&path, |_| Some("OK something else"));
        let mut out = Outbox::new(&path, 2);
        out.push("SIGNAL:test|203.0.113.1|-|x").unwrap();
        let (done, err) = out.flush(1);
        assert!(done.is_empty() && err.is_some());
        assert_eq!((out.pending(), out.lost, out.failing), (1, 0, true));
        node.join().unwrap();
        std::fs::remove_file(&path).unwrap();
        let node = fake_node(&path, |_| Some("OK duplicate"));
        out.retry_now();
        let (done, err) = out.flush(1);
        assert!(err.is_none());
        assert_eq!(done[0].1, Outcome::Duplicate);
        assert_eq!((out.pending(), out.lost, out.failing), (0, 0, false));
        drop(out);
        node.join().unwrap();
    }

    #[test]
    fn an_unterminated_ack_does_not_retire_the_signal() {
        let path = temp_socket("partial");
        let listener = UnixListener::bind(&path).unwrap();
        let node = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"OK ack\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"OK applied").unwrap(); // EOF before the delimiter
        });
        let mut out = Outbox::new(&path, 1);
        out.push("signal").unwrap();
        let (done, err) = out.flush(1);
        assert!(done.is_empty() && err.is_some());
        assert_eq!((out.pending(), out.lost), (1, 0));
        node.join().unwrap();
    }
    #[test]
    fn all_current_retraction_acknowledgements_are_final() {
        for (index, reply) in [
            "OK recorded before its signal",
            "OK nothing held",
            "OK still held by other reasons",
            "OK lifted",
            "OK shortened",
        ]
        .into_iter()
        .enumerate()
        {
            // Exercise the public Outbox path, not only the parser's match arms.
            let path = temp_socket(&format!("retract-{index}"));
            let listener = UnixListener::bind(&path).unwrap();
            let node = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                stream.write_all(b"OK ack\n").unwrap();
                line.clear();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("RETRACT#"));
                writeln!(stream, "{reply}").unwrap();
            });
            let mut out = Outbox::new(&path, 1);
            out.push("RETRACT#7:crowdsec|203.0.113.1").unwrap();
            let (done, err) = out.flush(1);
            assert!(err.is_none(), "{reply}");
            assert_eq!(done[0].1, Outcome::Recorded);
            assert_eq!(out.pending(), 0);
            drop(out);
            node.join().unwrap();
        }
    }
    // Real socket controls: oversized/trickled lines used to be accepted after
    // unbounded read_line accumulation. Keep the final newline significant.
    fn sized_reply_node(path: &Path, size: usize, handshake: bool) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if !handshake {
                stream.write_all(b"OK ack\n").unwrap();
                line.clear();
                reader.read_line(&mut line).unwrap();
            }
            let mut reply = if handshake { "OK ack" } else { "OK applied" }.to_string();
            reply.extend(std::iter::repeat_n(' ', size - reply.len() - 1));
            reply.push('\n');
            let _ = stream.write_all(reply.as_bytes());
            if handshake {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let _ = stream.write_all(b"OK applied\n");
                }
            }
        })
    }

    #[test]
    fn oversized_handshake_and_signal_answers_keep_the_signal_for_retry() {
        for handshake in [true, false] {
            let path = temp_socket(&format!("oversized-{handshake}"));
            let node = sized_reply_node(&path, 8193, handshake);
            let mut out = Outbox::new(&path, 1);
            out.push("signal").unwrap();
            let (done, err) = out.flush(1);
            node.join().unwrap();
            assert!(
                done.is_empty() && err.is_some(),
                "oversized answer was accepted"
            );
            assert_eq!(err.as_deref(), Some("answer exceeds byte limit"));
            assert_eq!((out.pending(), out.lost, out.failing), (1, 0, true));
            assert!(out.conn.is_none() && out.retry_at.is_some());
            std::fs::remove_file(&path).unwrap();
            let node = fake_node(&path, |_| Some("OK duplicate"));
            out.retry_now();
            let (done, err) = out.flush(1);
            assert!(err.is_none());
            assert_eq!(done[0].1, Outcome::Duplicate);
            assert_eq!((out.pending(), out.lost, out.failing), (0, 0, false));
            drop(out);
            node.join().unwrap();
        }
    }

    #[test]
    fn an_answer_exactly_at_the_byte_limit_is_accepted() {
        for handshake in [true, false] {
            let path = temp_socket(&format!("answer-boundary-{handshake}"));
            let node = sized_reply_node(&path, 8192, handshake);
            let mut out = Outbox::new(&path, 1);
            out.push("signal").unwrap();
            let (done, err) = out.flush(1);
            assert!(err.is_none());
            assert_eq!(done[0].1, Outcome::Applied);
            assert_eq!(out.pending(), 0);
            drop(out);
            node.join().unwrap();
        }
    }

    #[test]
    fn continuously_arriving_bytes_do_not_extend_the_answer_deadline() {
        let path = temp_socket("trickle-deadline");
        let listener = UnixListener::bind(&path).unwrap();
        let node = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"OK ack\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"OK applied").unwrap();
            // Each gap is below ANSWER_TIMEOUT; the complete line takes >3s.
            for _ in 0..13 {
                std::thread::sleep(Duration::from_millis(250));
                if stream.write_all(b" ").is_err() {
                    return;
                }
            }
            let _ = stream.write_all(b"\n");
        });
        let mut out = Outbox::new(&path, 1);
        out.push("signal").unwrap();
        let started = Instant::now();
        let (done, err) = out.flush(1);
        let elapsed = started.elapsed();
        node.join().unwrap();
        assert!(
            elapsed < ANSWER_TIMEOUT + Duration::from_secs(1),
            "{elapsed:?}"
        );
        assert!(
            done.is_empty() && err.is_some(),
            "trickled answer was accepted"
        );
        assert_eq!(err.as_deref(), Some("answer deadline exceeded"));
        assert_eq!((out.pending(), out.lost, out.failing), (1, 0, true));
        assert!(out.conn.is_none() && out.retry_at.is_some());
    }
    #[test]
    fn a_fragmented_utf8_answer_within_the_deadline_is_final() {
        let path = temp_socket("fragmented-utf8");
        let listener = UnixListener::bind(&path).unwrap();
        let node = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"OK ack\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            for fragment in [b"OK refu".as_slice(), b"sed \xc3", b"\xa9", b"\n"] {
                stream.write_all(fragment).unwrap();
                // Longer than the read slice, still within the overall answer deadline.
                std::thread::sleep(Duration::from_millis(150));
            }
        });
        let mut out = Outbox::new(&path, 1);
        out.push("signal").unwrap();
        let (done, err) = out.flush(1);
        assert!(err.is_none());
        assert_eq!(done[0].1, Outcome::Refused("é".to_string()));
        assert_eq!((out.pending(), out.lost, out.failing), (0, 0, false));
        drop(out);
        node.join().unwrap();
    }
    #[test]
    fn a_full_unterminated_answer_hits_the_size_limit_before_the_deadline() {
        for size in [8192, 16384] {
            let path = temp_socket(&format!("no-delimiter-{size}"));
            let listener = UnixListener::bind(&path).unwrap();
            let node = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                stream.write_all(b"OK ack\n").unwrap();
                line.clear();
                reader.read_line(&mut line).unwrap();
                let _ = stream.write_all(&vec![b'x'; size]);
                // Stay open: EOF must not be the reason the client stops reading.
                line.clear();
                let _ = reader.read_line(&mut line);
            });
            let mut out = Outbox::new(&path, 1);
            out.push("signal").unwrap();
            let (done, err) = out.flush(1);
            node.join().unwrap();
            assert!(done.is_empty());
            assert_eq!(err.as_deref(), Some("answer exceeds byte limit"));
            assert_eq!((out.pending(), out.lost, out.failing), (1, 0, true));
        }
    }
    #[test]
    fn a_silent_open_peer_hits_the_deadline_in_handshake_and_signal_reads() {
        for handshake in [true, false] {
            let path = temp_socket(&format!("silent-open-{handshake}"));
            let listener = UnixListener::bind(&path).unwrap();
            let node = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                // Also bound the test peer so a broken deadline cannot hang the suite.
                stream
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if !handshake {
                    stream.write_all(b"OK ack\n").unwrap();
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                }
                line.clear();
                let _ = reader.read_line(&mut line); // stay silent until client closes
            });
            let mut out = Outbox::new(&path, 1);
            out.push("signal").unwrap();
            let started = Instant::now();
            let (done, err) = out.flush(1);
            let elapsed = started.elapsed();
            node.join().unwrap();
            assert!(done.is_empty());
            assert_eq!(err.as_deref(), Some("answer deadline exceeded"));
            assert!(
                elapsed < ANSWER_TIMEOUT + Duration::from_secs(1),
                "{elapsed:?}"
            );
            assert_eq!((out.pending(), out.lost, out.failing), (1, 0, true));
            assert!(out.conn.is_none() && out.retry_at.is_some());
        }
    }
    #[test]
    fn an_error_echoing_a_maximum_sized_request_is_still_final() {
        let path = temp_socket("long-node-error");
        let listener = UnixListener::bind(&path).unwrap();
        let reason = format!("invalid signal source '{}'", "x".repeat(4096));
        let expected = reason.clone();
        let node = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            stream.write_all(b"OK ack\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            writeln!(stream, "ERR {reason}").unwrap();
        });
        let mut out = Outbox::new(&path, 1);
        out.push("signal").unwrap();
        let (done, err) = out.flush(1);
        assert!(err.is_none());
        assert_eq!(done[0].1, Outcome::Rejected(expected));
        assert_eq!((out.pending(), out.lost, out.failing), (0, 0, false));
        drop(out);
        node.join().unwrap();
    }
    fn rejected_input_does_not_reach_the_socket(bad: &str, name: &str) {
        use std::io::Read;
        let path = temp_socket(name);
        let listener = UnixListener::bind(&path).unwrap();
        let node = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "ACK\n");
            stream.write_all(b"OK ack\n").unwrap();
            let mut commands = Vec::new();
            loop {
                line.clear();
                let read = (&mut reader).take(4096).read_line(&mut line);
                if !matches!(read, Ok(n) if n > 0) {
                    break;
                }
                if !line.ends_with('\n') && line.len() >= 4096 {
                    break;
                }
                commands.push(line.trim_end().to_string());
                if stream.write_all(b"OK applied\n").is_err() {
                    break;
                }
            }
            commands
        });
        let mut out = Outbox::new(&path, 2);
        let rejected = out.push(bad).unwrap_err();
        assert_eq!(rejected.kind(), io::ErrorKind::InvalidInput);
        out.push("good").unwrap();
        let (done, err) = out.flush(2);
        drop(out);
        let commands = node.join().unwrap();
        assert_eq!(
            commands,
            vec!["good"],
            "invalid input reached the wire or blocked the next signal"
        );
        assert!(err.is_none());
        assert_eq!(done, vec![("good".to_string(), Outcome::Applied)]);
    }

    #[test]
    fn oversized_input_cannot_block_a_following_valid_signal() {
        rejected_input_does_not_reach_the_socket(&"x".repeat(4096), "reject-long-input");
    }

    #[test]
    fn embedded_newline_cannot_send_an_extra_command() {
        rejected_input_does_not_reach_the_socket("first\nextra", "reject-newline-input");
    }

    #[test]
    fn invalid_input_cannot_evict_a_queued_signal() {
        let mut out = Outbox::new(Path::new("/unused"), 1);
        out.push("keep").unwrap();
        assert!(out.push("first\nextra").is_err());
        assert_eq!(out.lost, 0);
        assert_eq!(out.queue.front().map(String::as_str), Some("keep"));
    }
    #[test]
    fn input_framing_accepts_one_terminator_and_rejects_empty_or_multiple_lines() {
        let mut out = Outbox::new(Path::new("/unused"), 4);
        for line in ["a", "b\n", "c\r\n", "d \t\n"] {
            out.push(line).unwrap();
        }
        let original = out.queue.clone();
        assert_eq!(
            original,
            VecDeque::from(["a".into(), "b".into(), "c".into(), "d".into()])
        );
        for line in [
            "", "\n", "\r\n", " \t ", "a\rb", "a\n\n", "a\r", "a\r\nb", "a\nb\n",
        ] {
            assert_eq!(
                out.push(line).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(out.queue, original);
            assert_eq!(out.lost, 0);
        }
    }

    #[test]
    fn input_limit_counts_wire_bytes_including_the_appended_newline() {
        let mut out = Outbox::new(Path::new("/unused"), 2);
        out.push(&"x".repeat(4095)).unwrap();
        out.push(&format!("{}x\r\n", "é".repeat(2047))).unwrap();
        let original = out.queue.clone();
        for line in [&"x".repeat(4096), &"é".repeat(2048)] {
            assert_eq!(
                out.push(line).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(out.queue, original);
            assert_eq!(out.lost, 0);
        }
        assert!(out
            .queue
            .iter()
            .all(|line| line.len() + 1 == MAX_SIGNAL_BYTES));
    }
}
