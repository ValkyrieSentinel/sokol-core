//! Mirrors the node's blocklist upstream as BGP Flowspec (RFC 8955) "discard source" rules,
//! through a GoBGP daemon the operator runs and peers with the upstream routers.
//!
//! A reconciler compares the active blocks with what was announced on every tick, so an
//! unreachable gobgpd only delays announcements instead of losing them.
use ipnet::IpNet;
use std::collections::HashSet;
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
    fn command_args(&self, announce: bool, net: IpNet) -> Vec<String> {
        let (family, prefix) = match net {
            IpNet::V4(n) => ("ipv4-flowspec", n.to_string()),
            IpNet::V6(n) => ("ipv6-flowspec", n.to_string()),
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

    pub async fn apply(&self, announce: bool, ip: IpNet) -> Result<(), String> {
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
    announced: HashSet<IpNet>,
}

impl Reconciler {
    /// What to announce and withdraw so that upstream matches `active`, at most
    /// `MAX_OPS_PER_TICK` operations, withdrawals first (they unblock traffic).
    pub fn plan(&self, active: &HashSet<IpNet>) -> (Vec<IpNet>, Vec<IpNet>) {
        let mut withdraw: Vec<IpNet> = self.announced.difference(active).copied().collect();
        let mut announce: Vec<IpNet> = active.difference(&self.announced).copied().collect();
        withdraw.sort();
        announce.sort();
        withdraw.truncate(MAX_OPS_PER_TICK);
        announce.truncate(MAX_OPS_PER_TICK - withdraw.len());
        (announce, withdraw)
    }

    pub fn announced(&mut self, ip: IpNet) {
        self.announced.insert(ip);
    }

    pub fn withdrawn(&mut self, ip: IpNet) {
        self.announced.remove(&ip);
    }

    pub fn announced_count(&self) -> usize {
        self.announced.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> HashSet<IpNet> {
        list.iter()
            .map(|s| crate::block_table::parse_target(s).unwrap())
            .collect()
    }

    fn one(s: &str) -> IpNet {
        crate::block_table::parse_target(s).unwrap()
    }

    #[test]
    fn builds_gobgp_flowspec_commands() {
        let cli = GobgpCli {
            bin: "gobgp".into(),
            args: vec!["-p".into(), "50051".into()],
        };
        assert_eq!(
            cli.command_args(true, one("203.0.113.5")).join(" "),
            "-p 50051 global rib -a ipv4-flowspec add match source 203.0.113.5/32 then discard"
        );
        assert_eq!(
            cli.command_args(false, one("2001:db8::5")).join(" "),
            "-p 50051 global rib -a ipv6-flowspec del match source 2001:db8::5/128 then discard"
        );
    }

    #[test]
    fn prefixes_are_announced_as_prefixes() {
        let cli = GobgpCli {
            bin: "gobgp".into(),
            args: vec![],
        };
        assert_eq!(
            cli.command_args(true, one("198.51.100.0/24")).join(" "),
            "global rib -a ipv4-flowspec add match source 198.51.100.0/24 then discard"
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
        assert_eq!(announce, vec![one("203.0.113.2")]);
        r.announced(announce[0]);

        // 203.0.113.1 expired locally: withdraw it.
        let (announce, withdraw) = r.plan(&ips(&["203.0.113.2"]));
        assert!(announce.is_empty());
        assert_eq!(withdraw, vec![one("203.0.113.1")]);
    }

    #[test]
    fn caps_work_per_tick_and_withdraws_first() {
        let mut r = Reconciler::default();
        let old: Vec<IpNet> = (0..10).map(|i| one(&format!("198.51.100.{}", i))).collect();
        for ip in &old {
            r.announced(*ip);
        }
        let active: HashSet<IpNet> = (0..200)
            .map(|i| one(&format!("10.1.{}.{}", i / 250, i % 250)))
            .collect();
        let (announce, withdraw) = r.plan(&active);
        assert_eq!(withdraw.len(), 10);
        assert_eq!(announce.len() + withdraw.len(), MAX_OPS_PER_TICK);
    }
}
