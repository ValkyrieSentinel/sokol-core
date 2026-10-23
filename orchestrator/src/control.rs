//! Operator control socket (`--control-socket`): one command per line, one reply line each
//! (`OK ...` or `ERR ...`). It is separate from the IPC socket that traps write to, because a
//! trap parses attacker traffic and must not be able to lift bans.
use ipnet::IpNet;

use crate::block_table::parse_target;

#[derive(Debug, PartialEq, Eq)]
pub enum ControlCommand {
    /// Operator ban (address or prefix): permanent until the operator lifts it.
    Ban(IpNet),
    /// Lifts any block of this address or prefix, including operator and `--block` ones.
    Unban(IpNet),
    /// Releases all dynamic (trap, IPC, mesh) blocks; operator and `--block` bans stay.
    FlushDynamic,
    /// Lifts operator bans and detector blocks at once; `--block` stays.
    FlushAll,
    /// Lists the operator bans in force (the dashboard's view is read from the node).
    ListBans,
    /// Re-reads `--peers-file` (key rotation / revocation without a restart).
    ReloadPeers,
    /// Accepts running without state that failed to restore at startup (R27-04).
    AcceptStateLoss,
    /// A command the dashboard knows but this node cannot carry out.
    Unsupported(&'static str),
}

pub const MAX_LINE: u64 = 1024;

/// What one read from a control connection yields.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// A complete line, parsed: run it or answer its error, then read on.
    Line(Result<ControlCommand, String>),
    /// Answer this error once and close the connection.
    Refuse(String),
    /// End of stream, a read error or invalid UTF-8: close without a reply.
    Close,
}

/// Reads one command line of at most `MAX_LINE` bytes. A line that reaches the limit
/// without a newline is refused and the connection closed, as the IPC socket does:
/// reading on would run its remainder as a second command with a second reply, while
/// the protocol is one command and one reply per line. The control socket answers the
/// refusal (the IPC socket only logs it) because its client waits for a reply line.
pub async fn next<R>(reader: &mut R, line: &mut String) -> Next
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    line.clear();
    match reader.take(MAX_LINE).read_line(line).await {
        Ok(0) | Err(_) => Next::Close,
        Ok(_) if !line.ends_with('\n') && line.len() as u64 >= MAX_LINE => {
            Next::Refuse(format!("line over {} bytes; closing connection", MAX_LINE))
        }
        Ok(_) => Next::Line(parse(line)),
    }
}

pub fn parse(line: &str) -> Result<ControlCommand, String> {
    let line = line.trim();
    let (verb, arg) = match line.split_once(':') {
        Some((v, a)) => (v, Some(a.trim())),
        None => (line, None),
    };
    let ip = |arg: Option<&str>| -> Result<IpNet, String> {
        let raw = arg.ok_or_else(|| format!("{} needs an address", verb))?;
        parse_target(raw).ok_or_else(|| format!("'{}' is not an IP address or CIDR prefix", raw))
    };
    match verb {
        "BAN_IP" => ip(arg).map(ControlCommand::Ban),
        "UNBAN_IP" => ip(arg).map(ControlCommand::Unban),
        "FLUSH_BANS" if arg.is_none() => Ok(ControlCommand::FlushDynamic),
        "RELOAD_PEERS" if arg.is_none() => Ok(ControlCommand::ReloadPeers),
        "FLUSH_ALL" if arg.is_none() => Ok(ControlCommand::FlushAll),
        "LIST_BANS" if arg.is_none() => Ok(ControlCommand::ListBans),
        "ACCEPT_STATE_LOSS" if arg.is_none() => Ok(ControlCommand::AcceptStateLoss),
        "XDP_LOAD" | "XDP_UNLOAD" => Ok(ControlCommand::Unsupported(
            "toggling XDP from the dashboard is not supported; stop or start the service",
        )),
        "SET_DEFENSE" => Ok(ControlCommand::Unsupported(
            "defense modes have no enforcement on this node yet",
        )),
        _ => Err(format!("unknown command '{}'", verb)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_dashboard_commands() {
        assert_eq!(
            parse("BAN_IP:203.0.113.5\n"),
            Ok(ControlCommand::Ban(parse_target("203.0.113.5").unwrap()))
        );
        assert_eq!(
            parse("UNBAN_IP: 2001:db8::1"),
            Ok(ControlCommand::Unban(parse_target("2001:db8::1").unwrap()))
        );
        assert_eq!(
            parse("BAN_IP:::ffff:203.0.113.5"),
            Ok(ControlCommand::Ban(parse_target("203.0.113.5").unwrap()))
        );
        assert_eq!(parse("FLUSH_BANS"), Ok(ControlCommand::FlushDynamic));
        assert_eq!(parse("FLUSH_ALL"), Ok(ControlCommand::FlushAll));
        assert_eq!(parse("LIST_BANS\n"), Ok(ControlCommand::ListBans));
        assert!(parse("LIST_BANS:x").is_err());
        assert_eq!(
            parse("BAN_IP:198.51.100.7/24"),
            Ok(ControlCommand::Ban(
                parse_target("198.51.100.0/24").unwrap()
            ))
        );
        assert_eq!(parse("RELOAD_PEERS\n"), Ok(ControlCommand::ReloadPeers));
        assert!(matches!(
            parse("XDP_UNLOAD"),
            Ok(ControlCommand::Unsupported(_))
        ));
        assert!(matches!(
            parse("SET_DEFENSE:MAX_SHIELD"),
            Ok(ControlCommand::Unsupported(_))
        ));
    }

    /// Every outcome of one connection until it closes; bounded, since a reader that
    /// never closed would otherwise loop forever.
    async fn session(input: &[u8]) -> Vec<Next> {
        let mut reader = tokio::io::BufReader::new(input);
        let mut line = String::new();
        let mut outcomes = Vec::new();
        for _ in 0..8 {
            let next = next(&mut reader, &mut line).await;
            let done = !matches!(next, Next::Line(_));
            outcomes.push(next);
            if done {
                break;
            }
        }
        outcomes
    }

    #[tokio::test]
    async fn an_overlong_line_gets_one_error_and_runs_no_command() {
        // The tail after the first MAX_LINE bytes is a valid command on its own.
        let mut input = " ".repeat(1500 - "LIST_BANS\n".len());
        input.push_str("LIST_BANS\n");
        assert_eq!(input.len(), 1500);
        let outcomes = session(input.as_bytes()).await;
        let commands = outcomes
            .iter()
            .filter(|o| matches!(o, Next::Line(Ok(_))))
            .count();
        let errors = outcomes
            .iter()
            .filter(|o| matches!(o, Next::Line(Err(_)) | Next::Refuse(_)))
            .count();
        assert_eq!(
            (commands, errors),
            (0, 1),
            "one overlong line was not one error reply: {outcomes:?}"
        );
        assert!(matches!(outcomes.last(), Some(Next::Refuse(_))));
    }

    #[tokio::test]
    async fn normal_lines_still_run_one_command_each() {
        assert_eq!(
            session(b"LIST_BANS\nBAN_IP:203.0.113.5\n").await,
            vec![
                Next::Line(Ok(ControlCommand::ListBans)),
                Next::Line(Ok(ControlCommand::Ban(
                    parse_target("203.0.113.5").unwrap()
                ))),
                Next::Close,
            ]
        );
        // A line of exactly MAX_LINE bytes, newline included, is still a line.
        let mut exact = " ".repeat(MAX_LINE as usize - "LIST_BANS\n".len());
        exact.push_str("LIST_BANS\n");
        assert_eq!(
            session(exact.as_bytes()).await,
            vec![Next::Line(Ok(ControlCommand::ListBans)), Next::Close]
        );
    }

    #[test]
    fn rejects_anything_else() {
        for bad in [
            "",
            "BAN_IP",
            "BAN_IP:10.0.0.0/33",
            "BAN_IP:example.com",
            "DROP_IMMEDIATE:1.2.3.4",
            "FLUSH_BANS:all",
            "ban_ip:1.2.3.4",
        ] {
            assert!(parse(bad).is_err(), "{:?} should be rejected", bad);
        }
    }
}
