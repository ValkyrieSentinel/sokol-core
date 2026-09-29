//! Signals from external detectors (Suricata, CrowdSec, FastNetMon, ...) on the IPC socket:
//!
//! ```text
//! SIGNAL:<source>|<src ip>|<dst ip or ->|<reason>
//! ```
//!
//! The adapter reports both endpoints of the offending packet; the node decides which one is
//! the remote party. Normally that is the source. When the source is this node itself (the
//! alert fired on our own outbound traffic, e.g. a beacon to a malicious host), the destination
//! is blocked instead. Every other protection of the block policy still applies.
//!
//! An adapter that can name the event it reports sends `SIGNAL#<event id>:...` instead. The id
//! (1-64 of `A-Z a-z 0-9 . _ -`) is unique per source; the node acts on a (source, id) once
//! within `EVENT_MEMORY`, so a replay after a lost ACK or an adapter restart gets
//! `OK duplicate` and adds no strike. Lines without an id are always new events.
//!
//! The source may also be a CIDR prefix (e.g. a CrowdSec range decision); a prefix is blocked
//! as given, never swapped for the destination.
//!
//! ADR-0019:
//! - `SIGNAL[#<event id>];ttl=<seconds>:...` carries the source's own duration: the block lasts
//!   that long, within `--block-ttl-max`, instead of this node's escalation.
//! - `RETRACT#<event id>:<source>|<target>` takes the event back. The block ends only when no
//!   other reason holds it (another event of any source, or a line without an id).
use std::net::IpAddr;

use ipnet::IpNet;

use crate::block_policy::{BlockPolicy, LOCAL_ADDRESS};
use crate::block_table::{host, parse_target};

#[derive(Debug, PartialEq, Eq)]
pub struct Signal {
    pub source: String,
    pub src: IpNet,
    pub dst: Option<IpNet>,
    pub reason: String,
}

/// The head of a `SIGNAL` line.
#[derive(Debug, PartialEq, Eq)]
pub struct Verb<'a> {
    pub id: Option<&'a str>,
    /// The source's duration (`;ttl=<seconds>`, 1 s or more).
    pub ttl: Option<std::time::Duration>,
    pub payload: &'a str,
}

/// Splits `SIGNAL[#<event id>][;ttl=<seconds>]:<payload>`. `None` for any other line;
/// `Some(Err)` for a SIGNAL line whose head is malformed.
pub fn split_verb(line: &str) -> Option<Result<Verb<'_>, String>> {
    let rest = line.strip_prefix("SIGNAL")?;
    if !(rest.starts_with(':') || rest.starts_with('#') || rest.starts_with(';')) {
        return None;
    }
    let (head, payload) = rest.split_once(':')?;
    let (id, options) = match head.split_once(';') {
        Some((id, options)) => (id, Some(options)),
        None => (head, None),
    };
    let id = match id.strip_prefix('#') {
        Some(id) => Some(id),
        None if id.is_empty() => None,
        None => return Some(Err(format!("malformed signal head '{}'", head))),
    };
    let ttl = match options {
        None => None,
        Some(o) => match o.strip_prefix("ttl=").and_then(|v| v.parse::<u64>().ok()) {
            Some(secs) if secs > 0 => Some(std::time::Duration::from_secs(secs)),
            _ => {
                return Some(Err(format!(
                    "bad signal option '{}' (ttl=<seconds>, 1 or more)",
                    o
                )))
            }
        },
    };
    Some(Ok(Verb { id, ttl, payload }))
}

/// A detector taking back one of its events.
#[derive(Debug, PartialEq, Eq)]
pub struct Retract {
    pub id: String,
    pub source: String,
    pub target: IpNet,
}

/// Parses `RETRACT#<event id>:<source>|<target>`; `None` for any other line.
pub fn parse_retract(line: &str) -> Option<Result<Retract, String>> {
    let rest = line.strip_prefix("RETRACT")?;
    Some((|| {
        let (id, payload) = rest
            .strip_prefix('#')
            .and_then(|r| r.split_once(':'))
            .ok_or("RETRACT needs an event id: RETRACT#<id>:<source>|<target>")?;
        let id = event_id(id)?.to_string();
        let (source, target) = payload
            .trim()
            .split_once('|')
            .ok_or("RETRACT needs <source>|<target>")?;
        let source = source.trim();
        if source.is_empty()
            || !source
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("invalid signal source '{}'", source));
        }
        let target = parse_target(target.trim())
            .ok_or_else(|| format!("invalid target '{}'", target.trim()))?;
        Ok(Retract {
            id,
            source: source.to_string(),
            target,
        })
    })())
}

/// Checks an event id.
pub fn event_id(id: &str) -> Result<&str, String> {
    if (1..=64).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        Ok(id)
    } else {
        Err(format!("invalid event id '{}'", id))
    }
}

pub fn parse(payload: &str) -> Result<Signal, String> {
    let mut parts = payload.trim().splitn(4, '|');
    let source = parts.next().unwrap_or("").trim();
    let src = parts.next().ok_or("missing source address")?.trim();
    let dst = parts.next().ok_or("missing destination address")?.trim();
    let reason = parts.next().unwrap_or("").trim();

    if source.is_empty()
        || !source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("invalid signal source '{}'", source));
    }
    let src =
        parse_target(src).ok_or_else(|| format!("invalid source address or prefix '{}'", src))?;
    let dst = match dst {
        "-" | "" => None,
        raw => {
            Some(host(raw.parse::<IpAddr>().map_err(|_| {
                format!("invalid destination address '{}'", raw)
            })?))
        }
    };
    // The reason ends up in logs, the audit trail and the dashboard: keep it printable and short.
    let reason: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    Ok(Signal {
        source: source.to_string(),
        src,
        dst,
        reason,
    })
}

/// Picks the address to block, or explains why none may be.
pub fn target(signal: &Signal, policy: &BlockPolicy) -> Result<IpNet, String> {
    if signal.src.prefix_len() != signal.src.max_prefix_len() {
        return policy
            .check_net(signal.src)
            .map(|()| signal.src)
            .map_err(|why| format!("prefix {} is refused ({})", signal.src, why));
    }
    match policy.check(signal.src.addr()) {
        Ok(()) => Ok(signal.src),
        Err(LOCAL_ADDRESS) => {
            let dst = signal
                .dst
                .ok_or("source is this node and no destination was given")?;
            policy
                .check(dst.addr())
                .map(|()| dst)
                .map_err(|why| format!("destination {} is protected ({})", dst, why))
        }
        Err(why) => Err(format!("source {} is protected ({})", signal.src, why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpNet {
        parse_target(s).unwrap()
    }

    fn policy() -> BlockPolicy {
        let mut p = BlockPolicy::builtin();
        p.protect_ip("10.0.0.1".parse().unwrap(), LOCAL_ADDRESS);
        p.protect_ip("10.0.0.254".parse().unwrap(), "default gateway");
        p
    }

    #[test]
    fn splits_the_verb_and_the_event_id() {
        let v = |id, ttl: Option<u64>, payload| {
            Some(Ok(Verb {
                id,
                ttl: ttl.map(std::time::Duration::from_secs),
                payload,
            }))
        };
        assert_eq!(split_verb("SIGNAL:a|b"), v(None, None, "a|b"));
        assert_eq!(
            split_verb("SIGNAL#cs-17:a|b"),
            v(Some("cs-17"), None, "a|b")
        );
        assert_eq!(split_verb("SIGNAL#:a"), v(Some(""), None, "a"));
        assert_eq!(split_verb("SIGNALS:a"), None);
        assert_eq!(split_verb("SIGNAL#17"), None);
        assert_eq!(split_verb("DROP_IMMEDIATE:1.2.3.4"), None);
        // ADR-0019 T2: the source's duration.
        assert_eq!(
            split_verb("SIGNAL#cs-17;ttl=300:a|b"),
            v(Some("cs-17"), Some(300), "a|b")
        );
        assert_eq!(split_verb("SIGNAL;ttl=60:a|b"), v(None, Some(60), "a|b"));
        assert!(matches!(split_verb("SIGNAL#1;ttl=0:a"), Some(Err(_))));
        assert!(matches!(split_verb("SIGNAL#1;ttl=x:a"), Some(Err(_))));
        assert!(matches!(split_verb("SIGNAL#1;prio=1:a"), Some(Err(_))));
        assert!(event_id("crowdsec.17_a-B").is_ok());
        assert!(event_id("").is_err());
        assert!(event_id(&"x".repeat(65)).is_err());
        assert!(event_id("a b").is_err());
        assert!(event_id("a|b").is_err());
    }

    #[test]
    fn parses_retractions() {
        let r = parse_retract("RETRACT#cs-17:crowdsec|203.0.113.9")
            .unwrap()
            .unwrap();
        assert_eq!(r.id, "cs-17");
        assert_eq!(r.source, "crowdsec");
        assert_eq!(r.target, ip("203.0.113.9"));
        assert_eq!(
            parse_retract("RETRACT#1:crowdsec|198.51.100.0/24")
                .unwrap()
                .unwrap()
                .target,
            ip("198.51.100.0/24")
        );
        assert!(parse_retract("RETRACT:crowdsec|203.0.113.9")
            .unwrap()
            .is_err());
        assert!(parse_retract("RETRACT#1:crowd sec|203.0.113.9")
            .unwrap()
            .is_err());
        assert!(parse_retract("RETRACT#1:crowdsec|nope").unwrap().is_err());
        assert!(parse_retract("RETRACT#a b:crowdsec|203.0.113.9")
            .unwrap()
            .is_err());
        assert_eq!(parse_retract("SIGNAL:x"), None);
    }

    #[test]
    fn parses_signals() {
        let s = parse("suricata|203.0.113.5|10.0.0.1|sid:2001219 ET SCAN SSH brute force").unwrap();
        assert_eq!(s.source, "suricata");
        assert_eq!(s.src, ip("203.0.113.5"));
        assert_eq!(s.dst, Some(ip("10.0.0.1")));
        assert_eq!(s.reason, "sid:2001219 ET SCAN SSH brute force");

        let s = parse("crowdsec|::ffff:203.0.113.6|-|ssh-bf").unwrap();
        assert_eq!(s.src, ip("203.0.113.6"));
        assert_eq!(s.dst, None);

        let s = parse("suricata|203.0.113.5|-|a|b|c\u{7}").unwrap();
        assert_eq!(
            s.reason, "a|b|c",
            "reason keeps pipes, drops control characters"
        );
    }

    #[test]
    fn rejects_malformed_signals() {
        for bad in [
            "",
            "suricata",
            "suricata|203.0.113.5",
            "sur icata|203.0.113.5|-|x",
            "suricata|not-an-ip|-|x",
            "suricata|203.0.113.5|nope|x",
            "suricata|10.0.0.0/33|-|x",
            "suricata|203.0.113.5|198.51.100.0/24|x",
        ] {
            assert!(parse(bad).is_err(), "{:?} should be rejected", bad);
        }
    }

    #[test]
    fn blocks_the_remote_endpoint() {
        let p = policy();
        let inbound = parse("suricata|203.0.113.5|10.0.0.1|probe").unwrap();
        assert_eq!(target(&inbound, &p), Ok(ip("203.0.113.5")));

        // Alert on our own outbound traffic: the remote is the destination.
        let outbound = parse("suricata|10.0.0.1|198.51.100.9|beacon").unwrap();
        assert_eq!(target(&outbound, &p), Ok(ip("198.51.100.9")));
    }

    #[test]
    fn prefixes_are_blocked_as_given_under_the_prefix_rules() {
        let p = policy();
        let range = parse("crowdsec|198.51.100.0/24|-|range decision").unwrap();
        assert_eq!(target(&range, &p), Ok(ip("198.51.100.0/24")));
        let covers_node = parse("crowdsec|10.0.0.0/24|198.51.100.9|x").unwrap();
        assert!(
            target(&covers_node, &p).unwrap_err().contains("refused"),
            "never flipped to the destination"
        );
        let too_wide = parse("crowdsec|198.0.0.0/8|-|x").unwrap();
        assert!(target(&too_wide, &p).is_err());
    }

    #[test]
    fn never_flips_onto_a_protected_address() {
        let p = policy();
        // Source protected for a reason other than "this node": refuse, do not try the destination.
        let from_gateway = parse("suricata|10.0.0.254|198.51.100.9|x").unwrap();
        assert!(target(&from_gateway, &p)
            .unwrap_err()
            .contains("default gateway"));
        // Outbound to the gateway: both ends protected.
        let to_gateway = parse("suricata|10.0.0.1|10.0.0.254|x").unwrap();
        assert!(target(&to_gateway, &p).unwrap_err().contains("destination"));
        // Outbound without a destination.
        let no_dst = parse("suricata|10.0.0.1|-|x").unwrap();
        assert!(target(&no_dst, &p).is_err());
        // Loopback on either side.
        assert!(target(&parse("suricata|127.0.0.1|198.51.100.9|x").unwrap(), &p).is_err());
    }
}
