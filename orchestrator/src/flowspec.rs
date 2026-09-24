//! Mirrors the node's blocklist upstream as BGP Flowspec (RFC 8955) "discard source" rules,
//! through a GoBGP daemon the operator runs and peers with the upstream routers.
//!
//! A reconciler compares the active blocks with what was announced on every tick, so an
//! unreachable gobgpd only delays announcements instead of losing them.
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// CLI calls per tick; the rest wait for the next tick.
pub const MAX_OPS_PER_TICK: usize = 64;

pub struct GobgpCli {
    pub bin: PathBuf,
    /// Extra arguments before the command, e.g. `-p 50051` or `-u 10.0.0.5`.
    pub args: Vec<String>,
}

impl GobgpCli {
    fn command_args(&self, announce: bool, ip: IpAddr) -> Vec<String> {
        let (family, prefix) = match ip {
            IpAddr::V4(v4) => ("ipv4-flowspec", format!("{}/32", v4)),
            IpAddr::V6(v6) => ("ipv6-flowspec", format!("{}/128", v6)),
        };
        let mut args = self.args.clone();
        args.extend(
            [
                "global",
                "rib",
                "-a",
                family,
                if announce { "add" } else { "del" },
                "match",
                "source",
                &prefix,
                "then",
                "discard",
            ]
            .map(String::from),
        );
        args
    }

    pub async fn apply(&self, announce: bool, ip: IpAddr) -> Result<(), String> {
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new(&self.bin)
                .args(self.command_args(announce, ip))
                .output(),
        )
        .await
        .map_err(|_| "gobgp did not answer within 5 s".to_string())?
        .map_err(|e| format!("cannot run {}: {}", self.bin.display(), e))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }
}

#[derive(Default)]
pub struct Reconciler {
    announced: HashSet<IpAddr>,
}

impl Reconciler {
    /// What to announce and withdraw so that upstream matches `active`, at most
    /// `MAX_OPS_PER_TICK` operations, withdrawals first (they unblock traffic).
    pub fn plan(&self, active: &HashSet<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
        let mut withdraw: Vec<IpAddr> = self.announced.difference(active).copied().collect();
        let mut announce: Vec<IpAddr> = active.difference(&self.announced).copied().collect();
        withdraw.sort();
        announce.sort();
        withdraw.truncate(MAX_OPS_PER_TICK);
        announce.truncate(MAX_OPS_PER_TICK - withdraw.len());
        (announce, withdraw)
    }

    pub fn announced(&mut self, ip: IpAddr) {
        self.announced.insert(ip);
    }

    pub fn withdrawn(&mut self, ip: IpAddr) {
        self.announced.remove(&ip);
    }

    pub fn announced_count(&self) -> usize {
        self.announced.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> HashSet<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn builds_gobgp_flowspec_commands() {
        let cli = GobgpCli {
            bin: "gobgp".into(),
            args: vec!["-p".into(), "50051".into()],
        };
        assert_eq!(
            cli.command_args(true, "203.0.113.5".parse().unwrap())
                .join(" "),
            "-p 50051 global rib -a ipv4-flowspec add match source 203.0.113.5/32 then discard"
        );
        assert_eq!(
            cli.command_args(false, "2001:db8::5".parse().unwrap())
                .join(" "),
            "-p 50051 global rib -a ipv6-flowspec del match source 2001:db8::5/128 then discard"
        );
    }

    #[test]
    fn plans_the_difference_and_retries_failures() {
        let mut r = Reconciler::default();
        let (announce, withdraw) = r.plan(&ips(&["203.0.113.1", "203.0.113.2"]));
        assert_eq!(announce.len(), 2);
        assert!(withdraw.is_empty());

        // Only the first announcement succeeded: the second is planned again.
        r.announced(announce[0]);
        let (announce, _) = r.plan(&ips(&["203.0.113.1", "203.0.113.2"]));
        assert_eq!(announce, vec!["203.0.113.2".parse::<IpAddr>().unwrap()]);
        r.announced(announce[0]);

        // 203.0.113.1 expired locally: withdraw it.
        let (announce, withdraw) = r.plan(&ips(&["203.0.113.2"]));
        assert!(announce.is_empty());
        assert_eq!(withdraw, vec!["203.0.113.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn caps_work_per_tick_and_withdraws_first() {
        let mut r = Reconciler::default();
        let old: Vec<IpAddr> = (0..10)
            .map(|i| format!("198.51.100.{}", i).parse().unwrap())
            .collect();
        for ip in &old {
            r.announced(*ip);
        }
        let active: HashSet<IpAddr> = (0..200)
            .map(|i| format!("10.1.{}.{}", i / 250, i % 250).parse().unwrap())
            .collect();
        let (announce, withdraw) = r.plan(&active);
        assert_eq!(withdraw.len(), 10);
        assert_eq!(announce.len() + withdraw.len(), MAX_OPS_PER_TICK);
    }
}
