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
use std::net::IpAddr;

use crate::block_policy::{BlockPolicy, LOCAL_ADDRESS};

#[derive(Debug, PartialEq, Eq)]
pub struct Signal {
    pub source: String,
    pub src: IpAddr,
    pub dst: Option<IpAddr>,
    pub reason: String,
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
    let src = src
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid source address '{}'", src))?
        .to_canonical();
    let dst = match dst {
        "-" | "" => None,
        raw => Some(
            raw.parse::<IpAddr>()
                .map_err(|_| format!("invalid destination address '{}'", raw))?
                .to_canonical(),
        ),
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
pub fn target(signal: &Signal, policy: &BlockPolicy) -> Result<IpAddr, String> {
    match policy.check(signal.src) {
        Ok(()) => Ok(signal.src),
        Err(LOCAL_ADDRESS) => {
            let dst = signal
                .dst
                .ok_or("source is this node and no destination was given")?;
            policy
                .check(dst)
                .map(|()| dst)
                .map_err(|why| format!("destination {} is protected ({})", dst, why))
        }
        Err(why) => Err(format!("source {} is protected ({})", signal.src, why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn policy() -> BlockPolicy {
        let mut p = BlockPolicy::builtin();
        p.protect_ip(ip("10.0.0.1"), LOCAL_ADDRESS);
        p.protect_ip(ip("10.0.0.254"), "default gateway");
        p
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
            "suricata|10.0.0.0/8|-|x",
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
