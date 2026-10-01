//! Delivery of detector adapters' signals to the node's IPC socket (review finding F09).
//!
//! A signal leaves the outbox only when the node has answered it: the connection is switched to
//! ACK mode, and the node replies to each line with `OK applied`, `OK pending`, `OK recorded`,
//! `OK duplicate` (an event id it already acted on), `OK refused <why>` or `ERR <why>`. Refusals and errors are final (retrying a protected address
//! or a malformed line would not change the answer). A node that is down, restarting or not
//! answering leaves the signal queued; delivery is retried with a growing pause. The queue is
//! bounded: when it is full the oldest signal is dropped and counted.
//! Unknown or incomplete reply lines retain the signal and reconnect with backoff; only a
//! complete recognized acknowledgement is final. ADR-0019 retraction acknowledgements
//! are Recorded outcomes too. This does not establish durable storage.
//! Each answer (including the ACK handshake) is limited to 4096 bytes including newline
//! and ANSWER_TIMEOUT total reading time, not a fresh timeout for every fragment.
//! Oversized/late answers keep the signal queued and trigger the existing reconnect/backoff.
//! Blocking reads check the deadline at 100ms intervals (plus scheduler/kernel delay).
//! This bounds answer reads, not connect/write time or a whole multi-signal flush.
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum wire bytes in one acknowledgement, including its terminating newline.
pub const MAX_ANSWER_BYTES: usize = 4096;
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
            reply.extend_from_slice(&bytes[..count]);
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

pub struct Outbox {
    socket: PathBuf,
    queue: VecDeque<String>,
    cap: usize,
    conn: Option<Conn>,
    backoff: Duration,
    retry_at: Option<Instant>,
    /// Signals dropped because the queue was full.
    pub lost: u64,
    /// Whether the last attempt failed (for logging an outage once).
    pub failing: bool,
}

impl Outbox {
    pub fn new(socket: &Path, cap: usize) -> Self {
        Self {
            socket: socket.to_path_buf(),
            queue: VecDeque::new(),
            cap: cap.max(1),
            conn: None,
            backoff: BACKOFF_MIN,
            retry_at: None,
            lost: 0,
            failing: false,
        }
    }

    pub fn push(&mut self, line: &str) {
        if self.queue.len() >= self.cap {
            self.queue.pop_front();
            self.lost += 1;
        }
        self.queue.push_back(line.trim_end().to_string());
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Delivers up to `max` queued signals, in order. Stops at the first transport failure; the
    /// rest (and the failed one) stay queued and are retried after a growing pause. Returns the
    /// node's answer for each signal that left the queue, and the transport error if any.
    pub fn flush(&mut self, max: usize) -> (Vec<(String, Outcome)>, Option<String>) {
        let mut done = Vec::new();
        if self.retry_at.is_some_and(|t| Instant::now() < t) {
            return (done, None);
        }
        while done.len() < max {
            let Some(line) = self.queue.front().cloned() else {
                break;
            };
            let reply = match self.conn.as_mut() {
                Some(conn) => conn.exchange(&line),
                None => Conn::open(&self.socket).and_then(|mut c| {
                    let r = c.exchange(&line);
                    self.conn = Some(c);
                    r
                }),
            };
            match reply.and_then(|text| Outcome::parse(&text)) {
                Ok(outcome) => {
                    self.queue.pop_front();
                    self.failing = false;
                    self.backoff = BACKOFF_MIN;
                    self.retry_at = None;
                    done.push((line, outcome));
                }
                Err(e) => {
                    // The line may or may not have reached the node; it is sent again later.
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
    fn a_signal_waits_while_the_node_is_down_and_is_delivered_after() {
        let path = temp_socket("down");
        let mut out = Outbox::new(&path, 16);
        out.push("SIGNAL:test|203.0.113.1|-|x\n");
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
        out.push("SIGNAL:test|10.0.0.1|-|protected");
        out.push("garbage");
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
        out.push("SIGNAL:test|203.0.113.2|-|x");
        let (done, err) = out.flush(8);
        assert!(done.is_empty());
        assert!(err.is_some());
        assert_eq!(out.pending(), 1);
        node.join().unwrap();
    }

    #[test]
    fn a_full_queue_drops_the_oldest_and_counts_it() {
        let mut out = Outbox::new(Path::new("/nonexistent/ipc.sock"), 2);
        out.push("a");
        out.push("b");
        out.push("c");
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
        out.push("SIGNAL:test|203.0.113.1|-|x");
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
        out.push("signal");
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
            out.push("RETRACT#7:crowdsec|203.0.113.1");
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
            let node = sized_reply_node(&path, 4097, handshake);
            let mut out = Outbox::new(&path, 1);
            out.push("signal");
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
            let node = sized_reply_node(&path, 4096, handshake);
            let mut out = Outbox::new(&path, 1);
            out.push("signal");
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
        out.push("signal");
        let (done, err) = out.flush(1);
        node.join().unwrap();
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
        out.push("signal");
        let (done, err) = out.flush(1);
        assert!(err.is_none());
        assert_eq!(done[0].1, Outcome::Refused("é".to_string()));
        assert_eq!((out.pending(), out.lost, out.failing), (0, 0, false));
        drop(out);
        node.join().unwrap();
    }
    #[test]
    fn a_full_unterminated_answer_hits_the_size_limit_before_the_deadline() {
        for size in [4096, 8192] {
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
            out.push("signal");
            let (done, err) = out.flush(1);
            node.join().unwrap();
            assert!(done.is_empty());
            assert_eq!(err.as_deref(), Some("answer exceeds byte limit"));
            assert_eq!((out.pending(), out.lost, out.failing), (1, 0, true));
        }
    }
}
