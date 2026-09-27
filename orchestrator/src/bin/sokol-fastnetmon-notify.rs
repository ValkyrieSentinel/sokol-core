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
//! Exit status is always 0 so a node that is down never stalls FastNetMon.

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
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // FastNetMon blocks until the script has consumed the details on stdin.
    let mut details = Vec::new();
    let _ = std::io::stdin().take(1 << 20).read_to_end(&mut details);

    let line = match report_line(&args) {
        Ok(line) => line,
        Err(e) => {
            eprintln!("sokol-fastnetmon-notify: {}", e);
            return;
        }
    };
    let socket = std::env::var("SOKOL_IPC_SOCKET").unwrap_or_else(|_| "/run/sokol.sock".into());
    let sent = UnixStream::connect(&socket).and_then(|mut s| {
        s.set_write_timeout(Some(Duration::from_secs(2)))?;
        s.write_all(line.as_bytes())
    });
    match sent {
        Ok(()) => eprintln!("sokol-fastnetmon-notify: sent {}", line.trim()),
        Err(e) => eprintln!("sokol-fastnetmon-notify: cannot reach {}: {}", socket, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
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
}
