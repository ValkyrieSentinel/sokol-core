//! Attack reports from flow-based detectors (FastNetMon) on the IPC socket:
//!
//! ```text
//! ATTACK:<source>|<victim ip>|<incoming|outgoing>|<pps>|<ban|unban>
//! ```
//!
//! FastNetMon names the *victim* of a volumetric attack — an address of this network, which the
//! node must not block — and the sources of such floods are usually spoofed. So a report does not
//! create a block. It marks the node as under attack in its mesh telemetry until the detector
//! sends `unban` or the report expires, which feeds the cluster status and the storm latch.
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub struct AttackReport {
    pub source: String,
    pub victim: IpAddr,
    pub direction: String,
    pub pps: u64,
    pub active: bool,
}

pub fn parse(payload: &str) -> Result<AttackReport, String> {
    let parts: Vec<&str> = payload.trim().split('|').map(str::trim).collect();
    let [source, victim, direction, pps, action] = parts.as_slice() else {
        return Err("expected <source>|<victim>|<direction>|<pps>|<ban|unban>".into());
    };
    if source.is_empty()
        || !source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("invalid report source '{}'", source));
    }
    let victim = victim
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid victim address '{}'", victim))?
        .to_canonical();
    let direction = match direction.to_ascii_lowercase().as_str() {
        d @ ("incoming" | "outgoing" | "other" | "internal") => d.to_string(),
        other => return Err(format!("invalid direction '{}'", other)),
    };
    let pps = pps.parse::<u64>().unwrap_or(0);
    let active = match action.to_ascii_lowercase().as_str() {
        "ban" | "attack_details" => true,
        "unban" => false,
        other => return Err(format!("invalid action '{}'", other)),
    };
    Ok(AttackReport {
        source: source.to_string(),
        victim,
        direction,
        pps,
        active,
    })
}

/// Reports currently in force, each until its detector clears it or `ttl` passes.
pub struct AttackReports {
    ttl: Duration,
    until: HashMap<(String, IpAddr), Instant>,
}

impl AttackReports {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            until: HashMap::new(),
        }
    }

    pub fn apply(&mut self, report: &AttackReport, now: Instant) {
        let key = (report.source.clone(), report.victim);
        if report.active {
            self.until.insert(key, now + self.ttl);
        } else {
            self.until.remove(&key);
        }
    }

    pub fn active(&mut self, now: Instant) -> usize {
        self.until.retain(|_, until| *until > now);
        self.until.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fastnetmon_reports() {
        let r = parse("fastnetmon|10.231.0.1|incoming|35000|ban").unwrap();
        assert_eq!(r.victim, "10.231.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            (r.direction.as_str(), r.pps, r.active),
            ("incoming", 35000, true)
        );
        assert!(
            !parse("fastnetmon|2001:db8::1|outgoing|0|unban")
                .unwrap()
                .active
        );
        assert!(
            parse("fastnetmon|10.0.0.1|incoming|1|attack_details")
                .unwrap()
                .active
        );
    }

    #[test]
    fn rejects_malformed_reports() {
        for bad in [
            "",
            "fastnetmon|10.0.0.1|incoming|1",
            "fast netmon|10.0.0.1|incoming|1|ban",
            "fastnetmon|nope|incoming|1|ban",
            "fastnetmon|10.0.0.1|sideways|1|ban",
            "fastnetmon|10.0.0.1|incoming|1|explode",
            "fastnetmon|10.0.0.1|incoming|1|ban|extra",
        ] {
            assert!(parse(bad).is_err(), "{:?} should be rejected", bad);
        }
    }

    #[test]
    fn reports_hold_until_cleared_or_expired() {
        let t0 = Instant::now();
        let mut reports = AttackReports::new(Duration::from_secs(600));
        let ban = parse("fastnetmon|10.0.0.1|incoming|35000|ban").unwrap();
        let other = parse("fastnetmon|10.0.0.2|incoming|35000|ban").unwrap();
        reports.apply(&ban, t0);
        reports.apply(&other, t0);
        assert_eq!(reports.active(t0), 2);

        reports.apply(&parse("fastnetmon|10.0.0.1|incoming|0|unban").unwrap(), t0);
        assert_eq!(reports.active(t0), 1, "unban clears only its victim");

        assert_eq!(
            reports.active(t0 + Duration::from_secs(601)),
            0,
            "a lost unban cannot pin the node"
        );
    }
}
