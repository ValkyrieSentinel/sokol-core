//! Mirrors the node's blocklist upstream as BGP Flowspec (RFC 8955) "discard source" rules,
//! through a GoBGP daemon the operator runs and peers with the upstream routers.
//!
//! The node's rules carry its ownership community. A worker, separate from the main loop,
//! compares the wanted blocks with what gobgpd's RIB actually holds for that community on every
//! round, so a crash of the orchestrator, a restart of gobgpd or an operation whose outcome was
//! unknown (timeout) converges on the next round. Rules without the community (other systems')
//! and rules learned from peers are never touched.
use ipnet::IpNet;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::block_table::show;
use crate::SentinelDb;

/// Rule changes per round; the rest wait for the next round. An operation count, not a time
/// budget: each change is a CLI call of up to CALL_TIMEOUT, after reading two RIB families, so
/// a slow gobgpd can stretch a round to (2 + 64 + 2) × 5 s. The worker runs apart from the main
/// tick (numerical review N06).
pub const MAX_OPS_PER_ROUND: usize = 64;
/// One gobgp call; a call that takes longer is killed, and its outcome is read back next round.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Deadline for the attempt to withdraw the node's rules on shutdown: not a guarantee that any
/// number of rules is withdrawn in it.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

pub struct GobgpCli {
    pub bin: PathBuf,
    /// Extra arguments before the command, e.g. `-p 50051` or `-u 10.0.0.5`.
    pub args: Vec<String>,
    /// Ownership community `asn:value` put on every rule this node announces.
    pub community: (u16, u16),
}

fn family(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => "ipv4-flowspec",
        IpNet::V6(_) => "ipv6-flowspec",
    }
}

impl GobgpCli {
    fn community_str(&self) -> String {
        format!("{}:{}", self.community.0, self.community.1)
    }

    fn community_value(&self) -> u32 {
        ((self.community.0 as u32) << 16) | self.community.1 as u32
    }

    fn command_args(&self, announce: bool, net: IpNet) -> Vec<String> {
        let prefix = net.to_string();
        let community = self.community_str();
        let mut args = self.args.clone();
        args.extend(
            [
                "global",
                "rib",
                "-a",
                family(&net),
                if announce { "add" } else { "del" },
                "match",
                "source",
                &prefix,
                "then",
                "discard",
                "community",
                &community,
            ]
            .map(String::from),
        );
        args
    }

    async fn run(&self, args: Vec<String>) -> Result<Vec<u8>, String> {
        let output = tokio::time::timeout(
            CALL_TIMEOUT,
            tokio::process::Command::new(&self.bin)
                .args(args)
                // A call that times out is killed rather than left to act later.
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| format!("gobgp did not answer within {:?}", CALL_TIMEOUT))?
        .map_err(|e| format!("cannot run {}: {}", self.bin.display(), e))?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    pub async fn apply(&self, announce: bool, net: IpNet) -> Result<(), String> {
        self.run(self.command_args(announce, net)).await.map(|_| ())
    }

    /// This node's rules as gobgpd's RIB holds them now.
    pub async fn observed(&self) -> Result<HashSet<IpNet>, String> {
        let mut own = HashSet::new();
        for fam in ["ipv4-flowspec", "ipv6-flowspec"] {
            let mut args = self.args.clone();
            args.extend(["global", "rib", "-a", fam, "-j"].map(String::from));
            let out = self.run(args).await?;
            own.extend(parse_own_rules(&out, self.community_value())?);
        }
        Ok(own)
    }
}

/// Rules in `gobgp global rib -a <flowspec> -j` output that this node owns: originated locally
/// (no `peer-address`), carrying `community`, and matching exactly one source prefix.
pub fn parse_own_rules(json: &[u8], community: u32) -> Result<HashSet<IpNet>, String> {
    let text = String::from_utf8_lossy(json);
    if text.trim().is_empty() || text.trim() == "null" {
        return Ok(HashSet::new());
    }
    let rib: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| format!("unreadable RIB: {}", e))?;
    let mut own = HashSet::new();
    for paths in rib.values() {
        for path in paths.as_array().into_iter().flatten() {
            let remote = path
                .get("peer-address")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());
            let tagged = path
                .get("attrs")
                .and_then(|a| a.as_array())
                .into_iter()
                .flatten()
                .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(8))
                .filter_map(|a| a.get("communities").and_then(|c| c.as_array()))
                .flatten()
                .any(|c| c.as_u64() == Some(community as u64));
            let components = path
                .get("nlri")
                .and_then(|n| n.get("value"))
                .and_then(|v| v.as_array());
            let source = match components.map(|c| c.as_slice()) {
                Some([only]) if only.get("type").and_then(|t| t.as_u64()) == Some(2) => only
                    .get("value")
                    .and_then(|v| v.get("prefix"))
                    .and_then(|p| p.as_str())
                    .and_then(|p| p.parse::<IpNet>().ok()),
                _ => None,
            };
            if let (false, true, Some(net)) = (remote, tagged, source) {
                own.insert(net);
            }
        }
    }
    Ok(own)
}

/// What to announce and withdraw so that `observed` becomes `wanted`, at most
/// `MAX_OPS_PER_ROUND` operations, withdrawals first (they unblock traffic).
pub fn plan(wanted: &HashSet<IpNet>, observed: &HashSet<IpNet>) -> (Vec<IpNet>, Vec<IpNet>) {
    let mut withdraw: Vec<IpNet> = observed.difference(wanted).copied().collect();
    let mut announce: Vec<IpNet> = wanted.difference(observed).copied().collect();
    withdraw.sort();
    announce.sort();
    withdraw.truncate(MAX_OPS_PER_ROUND);
    announce.truncate(MAX_OPS_PER_ROUND - withdraw.len());
    (announce, withdraw)
}

/// Keeps gobgpd's rules for this node equal to `wanted` until shutdown, then withdraws them.
/// Runs on its own task, so a slow or hung gobgpd never delays expiry, metrics or shutdown of
/// the main loop. `announced` reports the node's rules last observed in the RIB.
pub async fn run_worker(
    cli: GobgpCli,
    mut wanted: watch::Receiver<HashSet<IpNet>>,
    mut shutdown: watch::Receiver<bool>,
    db: Arc<SentinelDb>,
    announced: Arc<AtomicUsize>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut reported_error = false;
    loop {
        tokio::select! {
            _ = shutdown.changed() => if *shutdown.borrow() { break },
            _ = ticker.tick() => {}
        }
        let target = wanted.borrow_and_update().clone();
        match round(&cli, &target, &db).await {
            Ok(count) => {
                announced.store(count, Ordering::Relaxed);
                reported_error = false;
            }
            Err(e) => {
                if !reported_error {
                    log::error!("[Flowspec] {}; retrying every second", e);
                }
                reported_error = true;
            }
        }
    }
    // The node's blocks vanish with it; do not leave its rules behind upstream.
    let empty = HashSet::new();
    let done = tokio::time::timeout(SHUTDOWN_BUDGET, async {
        loop {
            match round(&cli, &empty, &db).await {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(e) => {
                    log::error!("[Flowspec] Withdrawing on shutdown: {}", e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    })
    .await;
    if done != Ok(true) {
        log::error!(
            "[Flowspec] Some of this node's rules may remain upstream after shutdown; they carry community {}",
            cli.community_str()
        );
    }
}

/// One reconciliation round; returns how many of the node's rules the RIB holds afterwards.
async fn round(cli: &GobgpCli, wanted: &HashSet<IpNet>, db: &SentinelDb) -> Result<usize, String> {
    let observed = cli.observed().await?;
    let (announce, withdraw) = plan(wanted, &observed);
    let changed = !announce.is_empty() || !withdraw.is_empty();
    for (is_announce, net) in withdraw
        .into_iter()
        .map(|n| (false, n))
        .chain(announce.into_iter().map(|n| (true, n)))
    {
        match cli.apply(is_announce, net).await {
            Ok(()) => {
                let verb = if is_announce { "announced" } else { "withdrew" };
                log::info!("[Flowspec] {} discard rule for {}", verb, show(&net));
                db.append(format!(
                    "FLOWSPEC_{}|IP:{}",
                    if is_announce { "ANNOUNCE" } else { "WITHDRAW" },
                    show(&net)
                ));
            }
            // Unknown outcome: the next round reads the RIB again.
            Err(e) => return Err(format!("gobgp failed for {}: {}", show(&net), e)),
        }
    }
    // A successful write acknowledges the CLI operation, not the resulting RIB.
    // Keep unknown readback as an error, never replace it with arithmetic guesses.
    if changed {
        Ok(cli.observed().await?.len())
    } else {
        Ok(observed.len())
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

    fn cli(args: &[&str]) -> GobgpCli {
        GobgpCli {
            bin: "gobgp".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            community: (65001, 6666),
        }
    }

    #[test]
    fn builds_gobgp_flowspec_commands_with_the_ownership_community() {
        let c = cli(&["-p", "50051"]);
        assert_eq!(
            c.command_args(true, one("203.0.113.5")).join(" "),
            "-p 50051 global rib -a ipv4-flowspec add match source 203.0.113.5/32 then discard community 65001:6666"
        );
        assert_eq!(
            c.command_args(false, one("2001:db8::5")).join(" "),
            "-p 50051 global rib -a ipv6-flowspec del match source 2001:db8::5/128 then discard community 65001:6666"
        );
        assert_eq!(
            cli(&[]).command_args(true, one("198.51.100.0/24")).join(" "),
            "global rib -a ipv4-flowspec add match source 198.51.100.0/24 then discard community 65001:6666",
            "prefixes are announced as prefixes"
        );
        assert_eq!(c.community_value(), 4259912202);
    }

    /// Captured from gobgpd 4.9.0: one local rule with our community, one local rule without
    /// it (another system's), and one rule with our community learned from a peer.
    const RIB: &str = r#"{"[source: 198.51.100.7/32]":[{"Family":0,"nlri":{"value":[{"type":2,"value":{"prefix":"198.51.100.7/32"}}]},"age":1790270463,"best":true,"attrs":[{"type":1,"value":2},{"type":8,"communities":[4259912202]},{"type":16,"value":[{"type":128,"subtype":6,"as":0,"rate":0}]}],"stale":false,"RemoteID":0,"LocalID":0}],
    "[source: 198.51.100.8/32]":[{"Family":0,"nlri":{"value":[{"type":2,"value":{"prefix":"198.51.100.8/32"}}]},"age":1790270463,"best":true,"attrs":[{"type":1,"value":2},{"type":16,"value":[{"type":128,"subtype":6,"as":0,"rate":0}]}],"stale":false,"RemoteID":0,"LocalID":0}],
    "[source: 203.0.113.9/32]":[{"Family":0,"nlri":{"value":[{"type":2,"value":{"prefix":"203.0.113.9/32"}}]},"age":1790270482,"best":true,"attrs":[{"type":8,"communities":[4259912202]}],"stale":false,"peer-id":"127.0.0.2","peer-address":"127.0.0.2","RemoteID":0,"LocalID":0}],
    "[destination: 10.0.0.1/32][source: 198.51.100.9/32]":[{"Family":0,"nlri":{"value":[{"type":1,"value":{"prefix":"10.0.0.1/32"}},{"type":2,"value":{"prefix":"198.51.100.9/32"}}]},"attrs":[{"type":8,"communities":[4259912202]}],"RemoteID":0,"LocalID":0}]}"#;

    #[test]
    fn only_local_rules_with_our_community_and_a_single_source_are_ours() {
        let own = parse_own_rules(RIB.as_bytes(), 4259912202).unwrap();
        assert_eq!(own, ips(&["198.51.100.7"]));
        assert!(parse_own_rules(RIB.as_bytes(), 1).unwrap().is_empty());
        assert!(parse_own_rules(b"", 1).unwrap().is_empty());
        assert!(parse_own_rules(b"{}", 1).unwrap().is_empty());
        assert!(parse_own_rules(b"not json", 1).is_err());
    }

    #[test]
    fn plans_against_what_the_rib_holds() {
        // F03: after a restart the node remembers nothing; the RIB still has an old rule.
        let (announce, withdraw) = plan(&ips(&["203.0.113.2"]), &ips(&["203.0.113.1"]));
        assert_eq!(announce, vec![one("203.0.113.2")]);
        assert_eq!(
            withdraw,
            vec![one("203.0.113.1")],
            "a stale rule from a previous run is withdrawn"
        );
        // F03: gobgpd lost its RIB; the wanted rules are announced again.
        let (announce, withdraw) = plan(&ips(&["203.0.113.2"]), &HashSet::new());
        assert_eq!(announce, vec![one("203.0.113.2")]);
        assert!(withdraw.is_empty());
    }

    #[test]
    fn caps_work_per_round_and_withdraws_first() {
        let observed: HashSet<IpNet> = (0..10).map(|i| one(&format!("198.51.100.{}", i))).collect();
        let wanted: HashSet<IpNet> = (0..200)
            .map(|i| one(&format!("10.1.{}.{}", i / 250, i % 250)))
            .collect();
        let (announce, withdraw) = plan(&wanted, &observed);
        assert_eq!(withdraw.len(), 10);
        assert_eq!(announce.len() + withdraw.len(), MAX_OPS_PER_ROUND);
    }

    /// F04: a call that times out must not act later (the child is killed with the future).
    #[tokio::test]
    async fn a_timed_out_call_is_killed() {
        let dir = std::env::temp_dir().join(format!("sokol-flowspec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("late");
        let script = dir.join("slow-gobgp");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nsleep 6\ntouch {}\n", marker.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let slow = GobgpCli {
            bin: script,
            args: vec![],
            community: (1, 1),
        };
        assert!(slow.apply(true, one("203.0.113.1")).await.is_err());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!marker.exists(), "the timed-out gobgp call still acted");
    }

    struct RoundFixture {
        dir: PathBuf,
        cli: GobgpCli,
    }

    impl RoundFixture {
        fn new(before: &str, after: &str, fail_after: bool) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "sokol-flowspec-round-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("before.json"), before).unwrap();
            std::fs::write(dir.join("after.json"), after).unwrap();
            let script = dir.join("gobgp");
            // Actual child processes: successful writes may have no effect, and a
            // post-write read may fail even after printing well-formed JSON.
            std::fs::write(
                &script,
                format!(
                    r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
case "$*" in
  *' -j')
    if [ -f applied ] && [ {fail_after} = true ]; then
      cat after.json
      exit 7
    fi
    case "$*" in
      *ipv4-flowspec*)
        if [ -f applied ]; then cat after.json; else cat before.json; fi ;;
      *ipv6-flowspec*) printf '{{}}\n' ;;
      *) exit 8 ;;
    esac ;;
  *' add '*|*' del '*) touch applied ;;
  *) exit 8 ;;
esac
"#
                ),
            )
            .unwrap();
            Self {
                dir,
                cli: GobgpCli {
                    // Reading via sh avoids ETXTBSY when another test's fork
                    // briefly inherits the newly written script's descriptor.
                    bin: "/bin/sh".into(),
                    args: vec![script.to_str().unwrap().to_string()],
                    community: (65001, 6666),
                },
            }
        }

        fn db(&self) -> SentinelDb {
            SentinelDb::init(self.dir.join("audit.log").to_str().unwrap(), None).unwrap()
        }

        fn reads(&self) -> usize {
            std::fs::read_to_string(self.dir.join("calls"))
                .unwrap()
                .lines()
                .filter(|line| line.ends_with(" -j"))
                .count()
        }
    }

    impl Drop for RoundFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn an_accepted_announce_without_a_rib_effect_is_not_counted() {
        let fixture = RoundFixture::new("{}", "{}", false);
        let db = fixture.db();
        let wanted = ips(&["198.51.100.7"]);
        assert_eq!(round(&fixture.cli, &wanted, &db).await.unwrap(), 0);
        assert_eq!(fixture.reads(), 4);
        assert_eq!(
            plan(&wanted, &fixture.cli.observed().await.unwrap()).0,
            vec![one("198.51.100.7")]
        );
    }

    #[tokio::test]
    async fn an_accepted_withdraw_without_a_rib_effect_is_still_counted() {
        let fixture = RoundFixture::new(RIB, RIB, false);
        let db = fixture.db();
        assert_eq!(round(&fixture.cli, &HashSet::new(), &db).await.unwrap(), 1);
        assert_eq!(fixture.reads(), 4);
        assert_eq!(
            plan(&HashSet::new(), &fixture.cli.observed().await.unwrap()).1,
            vec![one("198.51.100.7")]
        );
    }

    #[tokio::test]
    async fn failed_post_write_readback_is_not_an_observed_count() {
        let fixture = RoundFixture::new("{}", RIB, true);
        let db = fixture.db();
        assert!(round(&fixture.cli, &ips(&["198.51.100.7"]), &db)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn malformed_post_write_readback_is_not_an_observed_count() {
        let fixture = RoundFixture::new("{}", "not json", false);
        let db = fixture.db();
        assert!(round(&fixture.cli, &ips(&["198.51.100.7"]), &db)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn successful_changes_return_the_readback_count() {
        for (before, after, wanted, count) in [
            ("{}", RIB, ips(&["198.51.100.7"]), 1),
            (RIB, "{}", HashSet::new(), 0),
        ] {
            let fixture = RoundFixture::new(before, after, false);
            let db = fixture.db();
            assert_eq!(round(&fixture.cli, &wanted, &db).await.unwrap(), count);
            assert_eq!(fixture.reads(), 4);
        }
    }

    #[tokio::test]
    async fn unchanged_round_uses_the_initial_observation_without_extra_reads() {
        let fixture = RoundFixture::new(RIB, "not json", false);
        let db = fixture.db();
        assert_eq!(
            round(&fixture.cli, &ips(&["198.51.100.7"]), &db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(fixture.reads(), 2);
    }
}
