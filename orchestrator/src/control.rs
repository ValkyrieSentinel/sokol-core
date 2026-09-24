//! Operator control socket (`--control-socket`): one command per line, one reply line each
//! (`OK ...` or `ERR ...`). It is separate from the IPC socket that traps write to, because a
//! trap parses attacker traffic and must not be able to lift bans.
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum ControlCommand {
    /// Operator ban: permanent until the operator lifts it.
    Ban(IpAddr),
    /// Lifts any block of this address, including operator and `--block` ones.
    Unban(IpAddr),
    /// Releases all dynamic (trap, IPC, mesh) blocks; operator and `--block` bans stay.
    FlushDynamic,
    /// A command the dashboard knows but this node cannot carry out.
    Unsupported(&'static str),
}

pub const MAX_LINE: u64 = 1024;

pub fn parse(line: &str) -> Result<ControlCommand, String> {
    let line = line.trim();
    let (verb, arg) = match line.split_once(':') {
        Some((v, a)) => (v, Some(a.trim())),
        None => (line, None),
    };
    let ip = |arg: Option<&str>| -> Result<IpAddr, String> {
        let raw = arg.ok_or_else(|| format!("{} needs an address", verb))?;
        raw.parse::<IpAddr>()
            .map(|ip| ip.to_canonical())
            .map_err(|_| {
                format!(
                    "'{}' is not an IP address (prefixes are not supported yet)",
                    raw
                )
            })
    };
    match verb {
        "BAN_IP" => ip(arg).map(ControlCommand::Ban),
        "UNBAN_IP" => ip(arg).map(ControlCommand::Unban),
        "FLUSH_BANS" if arg.is_none() => Ok(ControlCommand::FlushDynamic),
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
            Ok(ControlCommand::Ban("203.0.113.5".parse().unwrap()))
        );
        assert_eq!(
            parse("UNBAN_IP: 2001:db8::1"),
            Ok(ControlCommand::Unban("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parse("BAN_IP:::ffff:203.0.113.5"),
            Ok(ControlCommand::Ban("203.0.113.5".parse().unwrap()))
        );
        assert_eq!(parse("FLUSH_BANS"), Ok(ControlCommand::FlushDynamic));
        assert!(matches!(
            parse("XDP_UNLOAD"),
            Ok(ControlCommand::Unsupported(_))
        ));
        assert!(matches!(
            parse("SET_DEFENSE:MAX_SHIELD"),
            Ok(ControlCommand::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_anything_else() {
        for bad in [
            "",
            "BAN_IP",
            "BAN_IP:10.0.0.0/8",
            "BAN_IP:example.com",
            "DROP_IMMEDIATE:1.2.3.4",
            "FLUSH_BANS:all",
            "ban_ip:1.2.3.4",
        ] {
            assert!(parse(bad).is_err(), "{:?} should be rejected", bad);
        }
    }
}
