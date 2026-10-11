//! FastNetMon → Sokol hook. Set it as FastNetMon's notify script:
//!
//! ```text
//! # /etc/fastnetmon.conf
//! notify_script_path = /usr/local/bin/sokol-fastnetmon-notify
//! ```
//!
//! FastNetMon calls it as `<ip> <incoming|outgoing> <pps> <ban|unban|attack_details>` and writes
//! attack details to stdin for `ban`; the script must read them. The hook forwards
//! `ATTACK:fastnetmon|<ip>|<direction>|<pps>|<action>` to the node's IPC socket
//! (`SOKOL_IPC_SOCKET`, default /run/sokol.sock). The node does not block the reported address —
//! it is the victim, inside the protected network — but reports itself under attack to the mesh.
//!
//! The report goes through `delivery::Outbox` in ACK mode, like the other detector adapters: it
//! is delivered when the node answered it, not when it was written. A node that is down,
//! restarting or silent is retried with the outbox's backoff, but only for `DELIVERY_BUDGET`, so
//! the hook never stalls FastNetMon for long: an attempt starts only inside the budget, and one
//! started just before its end still waits for its answers (`delivery::ANSWER_TIMEOUT` each,
//! the handshake and the report). Exit status: 0 — the node answered that it took the report;
//! `EXIT_NOT_DELIVERED` — no recognized answer within the budget, the report is lost (the hook
//! keeps no state between calls); `EXIT_NOT_ACTED_ON` — the node refused or rejected it, or the
//! arguments did not form a report (final: a retry would not change the answer).

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
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

#[path = "../delivery.rs"]
// One report per call: the hook never asks for the queue length (`Outbox::pending`).
#[allow(dead_code)]
mod delivery;

/// How long the hook keeps trying to deliver one report before it gives up. FastNetMon waits
/// for the script, so this is short; a longer outage loses the report (it says so and exits
/// with `EXIT_NOT_DELIVERED`).
const DELIVERY_BUDGET: Duration = Duration::from_secs(3);
/// How often the hook looks again while the outbox backs off between attempts.
const RETRY_POLL: Duration = Duration::from_millis(100);
/// No recognized answer from the node within `DELIVERY_BUDGET`: the report is lost.
const EXIT_NOT_DELIVERED: i32 = 1;
/// Final: the node refused or rejected the report, or there was no report to send.
const EXIT_NOT_ACTED_ON: i32 = 2;

fn report_line(args: &[String]) -> Result<String, String> {
    let [ip, direction, pps, action] = args else {
        return Err(format!(
            "expected <ip> <direction> <pps> <action>, got {} arguments",
            args.len()
        ));
    };
    let clean = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_control() && *c != '|')
            .take(64)
            .collect()
    };
    Ok(format!(
        "ATTACK:fastnetmon|{}|{}|{}|{}\n",
        clean(ip),
        clean(direction),
        clean(pps),
        clean(action)
    ))
}

/// Delivers `line` in ACK mode, retrying until `budget` has passed. `Ok` is the node's
/// recognized answer; `Err` is the last reason it was not delivered.
fn deliver(socket: &Path, line: &str, budget: Duration) -> Result<delivery::Outcome, String> {
    // One report per call: the outbox never holds more than this line.
    let mut outbox = delivery::Outbox::new(socket, 1);
    outbox
        .push(line)
        .map_err(|e| format!("not sendable: {}", e))?;
    let deadline = Instant::now() + budget;
    let mut last = String::from("no attempt finished");
    loop {
        let (done, error) = outbox.flush(1);
        if let Some((_, outcome)) = done.into_iter().next() {
            return Ok(outcome);
        }
        if let Some(e) = error {
            last = e;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(last);
        }
        std::thread::sleep(RETRY_POLL.min(left));
    }
}

/// Runs the hook for FastNetMon's arguments; returns the exit status.
fn notify(args: &[String]) -> i32 {
    // FastNetMon blocks until the script has consumed the details on stdin.
    let mut details = Vec::new();
    let _ = std::io::stdin().take(1 << 20).read_to_end(&mut details);

    let line = match report_line(args) {
        Ok(line) => line,
        Err(e) => {
            eprintln!("sokol-fastnetmon-notify: {}", e);
            return EXIT_NOT_ACTED_ON;
        }
    };
    let report = line.trim();
    let socket = std::env::var("SOKOL_IPC_SOCKET").unwrap_or_else(|_| "/run/sokol.sock".into());
    match deliver(Path::new(&socket), &line, DELIVERY_BUDGET) {
        Ok(delivery::Outcome::Refused(why)) => {
            eprintln!("sokol-fastnetmon-notify: node refused {}: {}", report, why);
            EXIT_NOT_ACTED_ON
        }
        Ok(delivery::Outcome::Rejected(why)) => {
            eprintln!("sokol-fastnetmon-notify: node rejected {}: {}", report, why);
            EXIT_NOT_ACTED_ON
        }
        Ok(outcome) => {
            eprintln!(
                "sokol-fastnetmon-notify: delivered {} (node answered {:?})",
                report, outcome
            );
            0
        }
        Err(e) => {
            eprintln!(
                "sokol-fastnetmon-notify: NOT delivered {}: no answer from {} within {:?} ({}); the report is lost",
                report, socket, DELIVERY_BUDGET, e
            );
            EXIT_NOT_DELIVERED
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(notify(&args));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::{Command, Output, Stdio};
    use std::sync::mpsc::{channel, Receiver};

    /// Set only in the child that runs the hook; the parent plays the node.
    const CHILD: &str = "SOKOL_FNM_NOTIFY_TEST_CHILD";
    const REPORT: [&str; 4] = ["10.231.0.1", "incoming", "35000", "ban"];
    const LINE: &str = "ATTACK:fastnetmon|10.231.0.1|incoming|35000|ban";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// In the child, runs the hook as FastNetMon would and exits with its status.
    fn run_hook_if_child() {
        if std::env::var_os(CHILD).is_some() {
            std::process::exit(notify(&args(&REPORT)));
        }
    }

    fn temp_socket(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fnm-notify-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let socket = dir.join("node.sock");
        (dir, socket)
    }

    /// A node on `socket`: every line it reads goes to the receiver, and `answer` decides the
    /// reply (`None`: stay silent, keeping the connection open).
    fn node(socket: &Path, answer: fn(&str) -> Option<&'static str>) -> Receiver<String> {
        let listener = UnixListener::bind(socket).unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut w = stream.try_clone().unwrap();
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let reply = answer(&line);
                        // Seen before answered: once the hook has its answer, the line is here.
                        let _ = tx.send(line);
                        if let Some(reply) = reply {
                            let _ = w.write_all(format!("{}\n", reply).as_bytes());
                        }
                    }
                });
            }
        });
        rx
    }

    fn answering(line: &str) -> Option<&'static str> {
        Some(if line == "ACK" {
            "OK ack"
        } else {
            "OK recorded"
        })
    }

    /// Re-runs this test binary with only `test`, as the hook, against `socket`.
    fn hook(test: &str, socket: &Path) -> (Output, Duration) {
        let started = Instant::now();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("SOKOL_IPC_SOCKET", socket)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (output, started.elapsed())
    }

    #[test]
    fn builds_the_attack_line_from_fastnetmon_arguments() {
        assert_eq!(
            report_line(&args(&["10.231.0.1", "incoming", "35000", "ban"])).unwrap(),
            "ATTACK:fastnetmon|10.231.0.1|incoming|35000|ban\n"
        );
        assert!(report_line(&args(&["10.231.0.1", "incoming", "35000"])).is_err());
    }

    #[test]
    fn arguments_cannot_add_fields_or_lines() {
        let line = report_line(&args(&[
            "10.0.0.1|x",
            "incoming\nDROP_IMMEDIATE:1.1.1.1",
            "1",
            "ban",
        ]))
        .unwrap();
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(line.matches('|').count(), 4);
    }

    #[test]
    fn the_first_line_the_node_sees_is_the_ack_handshake() {
        run_hook_if_child();
        let (dir, socket) = temp_socket("handshake");
        let lines = node(&socket, answering);
        hook(
            "tests::the_first_line_the_node_sees_is_the_ack_handshake",
            &socket,
        );
        let seen: Vec<String> = lines.try_iter().collect();
        assert_eq!(
            seen.first().map(String::as_str),
            Some("ACK"),
            "the report must be sent in ACK mode: {:?}",
            seen
        );
        assert_eq!(seen, vec!["ACK".to_string(), LINE.to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_node_that_never_answers_makes_the_hook_fail_within_its_budget_without_claiming_delivery() {
        run_hook_if_child();
        let (dir, socket) = temp_socket("silent");
        let lines = node(&socket, |_| None);
        let (output, took) = hook(
            "tests::a_node_that_never_answers_makes_the_hook_fail_within_its_budget_without_claiming_delivery",
            &socket,
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(EXIT_NOT_DELIVERED),
            "a silent node is not delivery: {}",
            stderr
        );
        assert!(!stderr.contains("notify: delivered"), "{}", stderr);
        assert!(!stderr.contains("notify: sent"), "{}", stderr);
        assert!(stderr.contains("NOT delivered"), "{}", stderr);
        // An attempt starts only inside the budget; one started at its end waits for the
        // handshake and the report answers. One second covers process start-up.
        let bound = DELIVERY_BUDGET + 2 * delivery::ANSWER_TIMEOUT + Duration::from_secs(1);
        assert!(took < bound, "took {:?}, bound {:?}", took, bound);
        assert!(
            lines.try_iter().all(|l| l == "ACK"),
            "nothing goes out before the handshake is answered"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_node_that_records_the_report_makes_the_hook_report_delivery_and_exit_zero() {
        run_hook_if_child();
        let (dir, socket) = temp_socket("recorded");
        let _lines = node(&socket, answering);
        let (output, _) = hook(
            "tests::a_node_that_records_the_report_makes_the_hook_report_delivery_and_exit_zero",
            &socket,
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{}", stderr);
        assert!(
            stderr.contains(&format!("delivered {} (node answered Recorded)", LINE)),
            "{}",
            stderr
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The hook retries until its budget, not once: a node that comes up after the first
    /// attempt failed, still within the budget, gets the report.
    #[test]
    fn a_node_that_comes_up_within_the_budget_still_gets_the_report() {
        run_hook_if_child();
        let (dir, socket) = temp_socket("late");
        let late = socket.clone();
        let starter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            node(&late, answering)
        });
        let (output, _) = hook(
            "tests::a_node_that_comes_up_within_the_budget_still_gets_the_report",
            &socket,
        );
        let _lines = starter.join().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{}", stderr);
        assert!(
            stderr.contains(&format!("delivered {}", LINE)),
            "{}",
            stderr
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_report_the_node_rejects_is_not_called_delivered() {
        run_hook_if_child();
        let (dir, socket) = temp_socket("rejected");
        let _lines = node(&socket, |line| {
            Some(if line == "ACK" {
                "OK ack"
            } else {
                "ERR bad report"
            })
        });
        let (output, _) = hook(
            "tests::a_report_the_node_rejects_is_not_called_delivered",
            &socket,
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(EXIT_NOT_ACTED_ON), "{}", stderr);
        assert!(stderr.contains("node rejected"), "{}", stderr);
        assert!(!stderr.contains("delivered"), "{}", stderr);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
