//! Mirrors the node's blocklist upstream as BGP Flowspec (RFC 8955) "discard source" rules,
//! through a GoBGP daemon the operator runs and peers with the upstream routers.
//!
//! The node's rules carry its ownership community. A worker, separate from the main loop,
//! compares the wanted blocks with what gobgpd's RIB actually holds for that community on every
//! round, so a crash of the orchestrator, a restart of gobgpd or an operation whose outcome was
//! unknown (timeout) converges on the next round. Rules without the community (other systems')
//! and rules learned from peers are not selected for removal. Observed foreign local NLRI
//! collisions skip only the affected operations; other writers must serialize changes (the CLI has no CAS).
use ipnet::IpNet;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

/// One completed read of both local RIB families. Age starts before the first CLI
/// read, so a slow or sequential read never appears younger than its oldest part.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Observation {
    count: usize,
    discard_count: usize,
    started: Instant,
}

/// A coherent copy for one scrape; no lock is held during CLI calls or rendering.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ReadbackView {
    pub enabled: bool,
    pub ok: bool,
    pub count: usize,
    pub discard_count: usize,
    pub started: Option<Instant>,
}

#[derive(Default)]
pub struct Readback(Mutex<ReadbackView>);

impl Readback {
    /// Called only for an enabled worker (never for observe mode).
    pub fn enable(&self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).enabled = true;
    }

    pub fn snapshot(&self) -> ReadbackView {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn begin_round(&self) {
        // Revoke before the first await, including shutdown reconciliation.
        self.0.lock().unwrap_or_else(|p| p.into_inner()).ok = false;
    }

    fn completed(&self, observation: Observation) {
        let mut view = self.0.lock().unwrap_or_else(|p| p.into_inner());
        view.count = observation.count;
        view.discard_count = observation.discard_count;
        view.started = Some(observation.started);
        view.ok = true;
    }
}

/// Local paths in the CLI-managed source-only NLRI scope. Ownership and action
/// are separate: a wrong-action owned path still needs cleanup if no longer wanted.
#[derive(Debug, Default)]
pub struct Rib {
    owned: HashSet<IpNet>,
    discard: HashSet<IpNet>,
    foreign_local: HashSet<IpNet>,
}

impl Rib {
    fn extend(&mut self, other: Self) {
        self.owned.extend(other.owned);
        self.discard.extend(other.discard);
        self.foreign_local.extend(other.foreign_local);
    }

    fn observation(&self, started: Instant) -> Observation {
        Observation {
            count: self.owned.len(),
            discard_count: self.discard.len(),
            started,
        }
    }
}

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
    pub async fn observed(&self) -> Result<Rib, String> {
        let mut own = Rib::default();
        for fam in ["ipv4-flowspec", "ipv6-flowspec"] {
            let mut args = self.args.clone();
            args.extend(["global", "rib", "-a", fam, "-j"].map(String::from));
            let out = self.run(args).await?;
            own.extend(parse_rib(&out, self.community_value())?);
        }
        Ok(own)
    }
}

/// Parse the pinned GoBGP JSON. A managed path is local, ID zero, tagged and
/// matches one full source prefix (IPv6 offset zero). Other local paths sharing
/// that exact NLRI are collisions; learned peer paths are not local CLI targets.
pub fn parse_rib(json: &[u8], community: u32) -> Result<Rib, String> {
    // Only an actual JSON object can establish absence. Do not normalize missing
    // stdout/null or silently skip unclassifiable entries into a healthy empty RIB.
    let rib: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(json).map_err(|e| format!("unreadable RIB: {}", e))?;
    let mut own = Rib::default();
    for paths in rib.values() {
        let paths = paths
            .as_array()
            .ok_or("unreadable RIB: paths must be an array")?;
        for path in paths {
            if !path.is_object() {
                return Err("unreadable RIB: path must be an object".into());
            }
            let remote = match path.get("peer-address") {
                None => false,
                Some(value) => !value
                    .as_str()
                    .ok_or("unreadable RIB: peer-address must be a string")?
                    .is_empty(),
            };
            let cli_id = match path.get("LocalID") {
                None => true,
                Some(value) => {
                    value
                        .as_u64()
                        .filter(|id| *id <= u32::MAX as u64)
                        .ok_or("unreadable RIB: LocalID must be uint32")?
                        == 0
                }
            };
            let attrs = path
                .get("attrs")
                .and_then(|a| a.as_array())
                .ok_or("unreadable RIB: attrs must be an array")?;
            let mut tagged = false;
            for attr in attrs {
                let kind = attr
                    .get("type")
                    .and_then(|v| v.as_u64())
                    .filter(|kind| *kind <= u8::MAX as u64)
                    .ok_or("unreadable RIB: attribute type must be uint8")?;
                if kind == 8 {
                    let communities = attr
                        .get("communities")
                        .and_then(|v| v.as_array())
                        .ok_or("unreadable RIB: communities must be an array")?;
                    for value in communities {
                        let value = value
                            .as_u64()
                            .filter(|value| *value <= u32::MAX as u64)
                            .ok_or("unreadable RIB: community must be uint32")?;
                        tagged |= value == u64::from(community);
                    }
                }
            }
            let components = path
                .get("nlri")
                .and_then(|n| n.get("value"))
                .and_then(|v| v.as_array())
                .filter(|v| !v.is_empty())
                .ok_or("unreadable RIB: NLRI components must be a nonempty array")?;
            let mut source = None;
            for component in components {
                let kind = component
                    .get("type")
                    .and_then(|v| v.as_u64())
                    .filter(|kind| *kind <= u8::MAX as u64)
                    .ok_or("unreadable RIB: component type must be uint8")?;
                if kind == 2 {
                    let prefix = component
                        .get("value")
                        .and_then(|v| v.get("prefix"))
                        .and_then(|v| v.as_str())
                        .and_then(|p| p.parse::<IpNet>().ok())
                        .ok_or("unreadable RIB: invalid source prefix")?;
                    let offset = match component.get("offset") {
                        None => 0,
                        Some(value) => value
                            .as_u64()
                            .filter(|offset| *offset <= 128)
                            .ok_or("unreadable RIB: invalid source offset")?,
                    };
                    if components.len() == 1 && offset == 0 {
                        source = Some(prefix);
                    }
                }
            }
            if let (false, Some(net)) = (remote, source) {
                // The CLI uses LocalID=0; it cannot safely select a tagged
                // nonzero-ID path using only this prefix and community.
                if tagged && cli_id {
                    own.owned.insert(net);
                    if has_canonical_discard(path) {
                        own.discard.insert(net);
                    }
                } else {
                    own.foreign_local.insert(net);
                }
            }
        }
    }
    Ok(own)
}

/// GoBGP 4.9.0 emits discard as one traffic-rate extended community (0x8006)
/// with numeric rate zero. Multiple/unknown actions are not canonical discard.
fn has_canonical_discard(path: &serde_json::Value) -> bool {
    let Some(attrs) = path.get("attrs").and_then(|v| v.as_array()) else {
        return false;
    };
    // IPv6-specific redirects use a separate extended-community attribute.
    // A zero traffic-rate action combined with type 25 is not canonical discard.
    if attrs
        .iter()
        .any(|a| a.get("type").and_then(|v| v.as_u64()) == Some(25))
    {
        return false;
    }
    let mut extended = attrs
        .iter()
        .filter(|a| a.get("type").and_then(|v| v.as_u64()) == Some(16));
    let Some(attribute) = extended.next() else {
        return false;
    };
    if extended.next().is_some() {
        return false;
    }
    match attribute
        .get("value")
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
    {
        Some([action]) => {
            action.get("type").and_then(|v| v.as_u64()) == Some(128)
                && action.get("subtype").and_then(|v| v.as_u64()) == Some(6)
                && action
                    .get("as")
                    .and_then(|v| v.as_u64())
                    .is_some_and(|v| v <= u16::MAX as u64)
                && action.get("rate").and_then(|v| v.as_f64()) == Some(0.0)
        }
        _ => false,
    }
}

/// Withdraw owned paths no longer wanted; announce missing or non-discard wanted paths, at most
/// `MAX_OPS_PER_ROUND` operations, withdrawals first (they unblock traffic).
pub fn plan(
    wanted: &HashSet<IpNet>,
    observed: &HashSet<IpNet>,
    discard: &HashSet<IpNet>,
) -> (Vec<IpNet>, Vec<IpNet>) {
    let mut withdraw: Vec<IpNet> = observed.difference(wanted).copied().collect();
    let mut announce: Vec<IpNet> = wanted.difference(discard).copied().collect();
    withdraw.sort();
    announce.sort();
    withdraw.truncate(MAX_OPS_PER_ROUND);
    announce.truncate(MAX_OPS_PER_ROUND - withdraw.len());
    (announce, withdraw)
}

/// Keeps gobgpd's rules for this node equal to `wanted` until shutdown, then withdraws them.
/// Runs on its own task, so a slow or hung gobgpd never delays expiry, metrics or shutdown of
/// the main loop. `readback` retains the last observation and marks pending/failed rounds.
pub async fn run_worker(
    cli: GobgpCli,
    mut wanted: watch::Receiver<HashSet<IpNet>>,
    mut shutdown: watch::Receiver<bool>,
    db: Arc<SentinelDb>,
    readback: Arc<Readback>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut reported_error = false;
    loop {
        tokio::select! {
            _ = shutdown.changed() => if *shutdown.borrow() { break },
            _ = ticker.tick() => {}
        }
        let target = wanted.borrow_and_update().clone();
        match checked_round(&cli, &target, &db, &readback).await {
            Ok(_) => {
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
            match checked_round(&cli, &empty, &db, &readback).await {
                Ok(observation) if observation.count == 0 => return true,
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

/// Same publication path for ordinary and shutdown rounds. Errors and cancelled
/// futures retain the previous count/time, with ok already revoked.
async fn checked_round(
    cli: &GobgpCli,
    wanted: &HashSet<IpNet>,
    db: &SentinelDb,
    readback: &Readback,
) -> Result<Observation, String> {
    readback.begin_round();
    let observation = round(cli, wanted, db).await?;
    readback.completed(observation);
    Ok(observation)
}

/// One reconciliation round; returns the final successful two-family observation.
async fn round(
    cli: &GobgpCli,
    wanted: &HashSet<IpNet>,
    db: &SentinelDb,
) -> Result<Observation, String> {
    let started = Instant::now();
    let observed = cli.observed().await?;
    // CLI writes address NLRI rather than ownership. Exclude known collisions
    // before applying the work quota, so they cannot starve unrelated unblocking.
    let mut collisions: Vec<_> = wanted
        .difference(&observed.discard)
        .chain(observed.owned.difference(wanted))
        .filter(|n| observed.foreign_local.contains(n))
        .copied()
        .collect();
    collisions.sort();
    collisions.dedup();
    let writable_wanted = wanted
        .difference(&observed.foreign_local)
        .copied()
        .collect();
    let writable_owned = observed
        .owned
        .difference(&observed.foreign_local)
        .copied()
        .collect();
    let (announce, withdraw) = plan(&writable_wanted, &writable_owned, &observed.discard);
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
    let observation = if changed {
        let started = Instant::now();
        cli.observed().await?.observation(started)
    } else {
        observed.observation(started)
    };
    if let Some(net) = collisions.first() {
        // Non-colliding work has progressed, but the full round is incomplete.
        // Preserve the last successful counts/time with health already revoked.
        return Err(format!(
            "local FlowSpec path collision for {} ({} skipped); non-colliding operations completed",
            show(net),
            collisions.len()
        ));
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let own = parse_rib(RIB.as_bytes(), 4259912202).unwrap();
        assert_eq!(own.owned, ips(&["198.51.100.7"]));
        assert!(parse_rib(RIB.as_bytes(), 1).unwrap().owned.is_empty());
        assert!(parse_rib(b"", 1).is_err());
        assert!(parse_rib(b"{}", 1).unwrap().owned.is_empty());
        assert!(parse_rib(b" \n{}\n", 1).unwrap().owned.is_empty());
        let mut invalid_utf8 = RIB
            .replace("\"best\":true", "\"best\":true,\"note\":\"marker\"")
            .into_bytes();
        let marker = invalid_utf8
            .windows(6)
            .position(|w| w == b"marker")
            .unwrap();
        invalid_utf8[marker] = 0xff;
        assert!(parse_rib(&invalid_utf8, 4259912202).is_err());
        assert!(parse_rib(b"not json", 1).is_err());
    }

    #[test]
    fn captured_gobgp_actions_separate_ownership_from_discard_for_both_families() {
        let entries: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/gobgp-4.9.0-actions.json"))
                .unwrap();
        for entry in entries.as_array().unwrap() {
            let rib = parse_rib(entry["rib"].to_string().as_bytes(), 4259912202).unwrap();
            match entry["label"].as_str().unwrap() {
                "owned-rate-limit" => {
                    assert_eq!(rib.owned.len(), 1);
                    assert!(rib.discard.is_empty());
                }
                "owned-replaced-by-discard" => {
                    assert_eq!(rib.owned.len(), 1);
                    assert_eq!(rib.discard, rib.owned);
                }
                "foreign-local" => {
                    assert!(rib.owned.is_empty());
                    assert_eq!(rib.foreign_local.len(), 1);
                }
                _ => panic!("unknown captured observation"),
            }
        }
        assert_eq!(entries.as_array().unwrap().len(), 6);
    }

    #[test]
    fn missing_unknown_duplicate_and_nonzero_actions_are_not_discard() {
        let zero = serde_json::json!({"type":128,"subtype":6,"as":0,"rate":0});
        let variants = [
            serde_json::json!([]),
            serde_json::json!([{"type":128,"subtype":6,"as":0,"rate":100}]),
            serde_json::json!([{"type":128,"subtype":6,"as":0,"rate":0.000001}]),
            serde_json::json!([{"type":128,"subtype":6,"as":0,"rate":"0"}]),
            serde_json::json!([{"type":128,"subtype":7,"terminal":true}]),
            serde_json::json!([{"type":128,"subtype":8,"value":"65001:1"}]),
            serde_json::json!([zero, zero]),
            serde_json::json!([zero, {"type":128,"subtype":8,"value":"65001:1"}]),
        ];
        for actions in variants {
            let mut raw: serde_json::Value = serde_json::from_str(RIB).unwrap();
            raw["[source: 198.51.100.7/32]"][0]["attrs"][2]["value"] = actions;
            let rib = parse_rib(raw.to_string().as_bytes(), 4259912202).unwrap();
            assert_eq!(rib.owned, ips(&["198.51.100.7"]));
            assert!(rib.discard.is_empty());
        }
        // IPv6 redirect is carried by a separate type-25 attribute, not type 16.
        // Reject it alongside traffic-rate zero in both family observations.
        let captures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/gobgp-4.9.0-actions.json"))
                .unwrap();
        for entry in captures
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["label"] == "owned-replaced-by-discard")
        {
            let mut raw = entry["rib"].clone();
            let path = &mut raw.as_object_mut().unwrap().values_mut().next().unwrap()[0];
            path["attrs"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "type":25,"value":[{"type":128,"subtype":11,"value":"2001:db8::1:1"}]
                }));
            let rib = parse_rib(raw.to_string().as_bytes(), 4259912202).unwrap();
            assert_eq!(rib.owned.len(), 1);
            assert!(rib.discard.is_empty(), "IPv6-specific action was ignored");
        }
        let mut raw: serde_json::Value = serde_json::from_str(RIB).unwrap();
        let attrs = raw["[source: 198.51.100.7/32]"][0]["attrs"]
            .as_array_mut()
            .unwrap();
        attrs.push(attrs[2].clone());
        assert!(parse_rib(raw.to_string().as_bytes(), 4259912202)
            .unwrap()
            .discard
            .is_empty());
    }

    #[test]
    fn source_offset_and_nonzero_local_id_do_not_grant_cli_ownership() {
        let mut raw: serde_json::Value = serde_json::from_str(RIB).unwrap();
        raw["[source: 198.51.100.7/32]"][0]["nlri"]["value"][0]["offset"] = 16.into();
        let rib = parse_rib(raw.to_string().as_bytes(), 4259912202).unwrap();
        assert!(rib.owned.is_empty());
        assert!(
            !rib.foreign_local.contains(&one("198.51.100.7")),
            "a different NLRI is not a CLI collision"
        );
        raw["[source: 198.51.100.7/32]"][0]["nlri"]["value"][0]["offset"] = 0.into();
        raw["[source: 198.51.100.7/32]"][0]["LocalID"] = 1.into();
        let rib = parse_rib(raw.to_string().as_bytes(), 4259912202).unwrap();
        assert!(rib.owned.is_empty());
        assert!(rib.foreign_local.contains(&one("198.51.100.7")));
    }

    #[test]
    fn plans_against_what_the_rib_holds() {
        // F03: after a restart the node remembers nothing; the RIB still has an old rule.
        let (announce, withdraw) = plan(
            &ips(&["203.0.113.2"]),
            &ips(&["203.0.113.1"]),
            &ips(&["203.0.113.1"]),
        );
        assert_eq!(announce, vec![one("203.0.113.2")]);
        assert_eq!(
            withdraw,
            vec![one("203.0.113.1")],
            "a stale rule from a previous run is withdrawn"
        );
        // F03: gobgpd lost its RIB; the wanted rules are announced again.
        let (announce, withdraw) = plan(&ips(&["203.0.113.2"]), &HashSet::new(), &HashSet::new());
        assert_eq!(announce, vec![one("203.0.113.2")]);
        assert!(withdraw.is_empty());
    }

    #[test]
    fn caps_work_per_round_and_withdraws_first() {
        let observed: HashSet<IpNet> = (0..10).map(|i| one(&format!("198.51.100.{}", i))).collect();
        let wanted: HashSet<IpNet> = (0..200)
            .map(|i| one(&format!("10.1.{}.{}", i / 250, i % 250)))
            .collect();
        let (announce, withdraw) = plan(&wanted, &observed, &observed);
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
    if [ -f pause ]; then
      touch entered
      while [ -f pause ]; do sleep 0.01; done
    fi
    if [ -f fail ]; then cat before.json; exit 7; fi
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
    async fn failed_readback_retains_count_and_age_until_recovery() {
        let fixture = RoundFixture::new(RIB, "{}", false);
        let db = fixture.db();
        let readback = Readback::default();
        assert_eq!(readback.snapshot(), ReadbackView::default());
        readback.enable();
        assert!(!readback.snapshot().ok);
        assert!(readback.snapshot().started.is_none());
        checked_round(&fixture.cli, &ips(&["198.51.100.7"]), &db, &readback)
            .await
            .unwrap();
        let old = readback.snapshot();
        assert!(old.enabled && old.ok);
        assert_eq!(old.count, 1);
        assert_eq!(old.discard_count, 1);
        assert!(old.started.is_some());

        // The actual RIB no longer contains our rule. Even plausible JSON on
        // stdout with a nonzero CLI status cannot count as an observation.
        std::fs::write(fixture.dir.join("before.json"), "{}").unwrap();
        std::fs::write(fixture.dir.join("fail"), "").unwrap();
        assert!(checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
            .await
            .is_err());
        let failed = readback.snapshot();
        assert!(failed.enabled && !failed.ok);
        assert_eq!(failed.count, old.count);
        assert_eq!(failed.discard_count, old.discard_count);
        assert_eq!(failed.started, old.started);

        std::fs::remove_file(fixture.dir.join("fail")).unwrap();
        checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
            .await
            .unwrap();
        let recovered = readback.snapshot();
        assert!(recovered.enabled && recovered.ok);
        assert_eq!(recovered.count, 0);
        assert_eq!(recovered.discard_count, 0);
        assert!(recovered.started.unwrap() > old.started.unwrap());
    }

    #[tokio::test]
    async fn pending_and_cancelled_rounds_revoke_readback_before_waiting() {
        let fixture = RoundFixture::new(RIB, "{}", false);
        let db = fixture.db();
        let readback = Readback::default();
        readback.enable();
        let wanted = ips(&["198.51.100.7"]);
        checked_round(&fixture.cli, &wanted, &db, &readback)
            .await
            .unwrap();
        let old = readback.snapshot();
        std::fs::write(fixture.dir.join("pause"), "").unwrap();
        let mut pending = Box::pin(checked_round(&fixture.cli, &wanted, &db, &readback));
        tokio::select! {
            result = &mut pending => panic!("paused CLI completed: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), async {
                while !fixture.dir.join("entered").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }) => result.unwrap(),
        }
        let during = readback.snapshot();
        assert!(!during.ok);
        assert_eq!(during.count, old.count);
        assert_eq!(during.started, old.started);
        drop(pending);
        assert_eq!(
            readback.snapshot(),
            during,
            "cancellation cannot publish success"
        );
    }

    #[tokio::test]
    async fn observation_age_includes_the_time_spent_reading() {
        let fixture = RoundFixture::new("{}", "{}", false);
        let db = fixture.db();
        let readback = Readback::default();
        readback.enable();
        let wanted = HashSet::new();
        std::fs::write(fixture.dir.join("pause"), "").unwrap();
        let mut pending = Box::pin(checked_round(&fixture.cli, &wanted, &db, &readback));
        tokio::select! {
            result = &mut pending => panic!("paused CLI completed: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), async {
                while !fixture.dir.join("entered").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }) => result.unwrap(),
        }
        let already_reading = Instant::now();
        std::fs::remove_file(fixture.dir.join("pause")).unwrap();
        let observation = pending.await.unwrap();
        assert!(
            observation.started <= already_reading,
            "completion time hides slow reads"
        );
        assert_eq!(readback.snapshot().started, Some(observation.started));
    }

    #[tokio::test]
    async fn scraping_samples_the_worker_without_a_main_tick() {
        let fixture = RoundFixture::new(RIB, "{}", false);
        let db = fixture.db();
        let readback = Readback::default();
        readback.enable();
        let old_main_tick = crate::metrics::Snapshot::default();
        let wanted = ips(&["198.51.100.7"]);
        checked_round(&fixture.cli, &wanted, &db, &readback)
            .await
            .unwrap();
        let good = crate::metrics::render_with_flowspec(&old_main_tick, &readback);
        assert!(good.contains("sokol_flowspec_enabled 1\n"));
        assert!(good.contains("sokol_flowspec_readback_ok 1\n"));
        assert!(good.contains("sokol_flowspec_announced 1\n"));
        std::fs::write(fixture.dir.join("fail"), "").unwrap();
        assert!(checked_round(&fixture.cli, &wanted, &db, &readback)
            .await
            .is_err());
        let failed = crate::metrics::render_with_flowspec(&old_main_tick, &readback);
        assert!(failed.contains("sokol_flowspec_readback_ok 0\n"));
        assert!(failed.contains("sokol_flowspec_announced 1\n"));
        assert!(!failed.contains("sokol_flowspec_readback_age_seconds -1.000\n"));
    }

    struct LiveGobgp {
        fixture: RoundFixture,
        daemon: std::process::Child,
    }

    impl Drop for LiveGobgp {
        fn drop(&mut self) {
            let _ = self.daemon.kill();
            let _ = self.daemon.wait();
        }
    }

    impl LiveGobgp {
        async fn start(bin_dir: &std::path::Path) -> Self {
            let mut fixture = RoundFixture::new("{}", "{}", false);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let config = fixture.dir.join("gobgp.toml");
            std::fs::write(
                &config,
                "[global.config]\n as = 65001\n router-id = \"127.0.0.1\"\n port = -1\n",
            )
            .unwrap();
            let log = std::fs::File::create(fixture.dir.join("daemon.log")).unwrap();
            let daemon = std::process::Command::new(bin_dir.join("gobgpd"))
                .arg("-f")
                .arg(config)
                .arg("--api-hosts")
                .arg(format!("127.0.0.1:{port}"))
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap();
            fixture.cli.bin = bin_dir.join("gobgp");
            fixture.cli.args = vec!["-p".into(), port.to_string()];
            let live = Self { fixture, daemon };
            for _ in 0..50 {
                if live.fixture.cli.observed().await.is_ok() {
                    return live;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!(
                "gobgpd did not become ready: {}",
                std::fs::read_to_string(live.fixture.dir.join("daemon.log")).unwrap()
            );
        }

        async fn put(&self, net: IpNet, action: &str, community: &str) {
            let mut args = self.fixture.cli.args.clone();
            args.extend(
                [
                    "global",
                    "rib",
                    "-a",
                    family(&net),
                    "add",
                    "match",
                    "source",
                ]
                .map(String::from),
            );
            args.push(net.to_string());
            args.push("then".into());
            args.extend(action.split_whitespace().map(String::from));
            args.extend(["community", community].map(String::from));
            self.fixture.cli.run(args).await.unwrap();
        }

        async fn raw(&self, net: IpNet) -> Vec<u8> {
            let mut args = self.fixture.cli.args.clone();
            args.extend(["global", "rib", "-a", family(&net), "-j"].map(String::from));
            self.fixture.cli.run(args).await.unwrap()
        }
    }

    #[tokio::test]
    async fn live_gobgp_round_repairs_actions_and_preserves_foreign_local_paths() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = live.fixture.db();
        let readback = Readback::default();
        readback.enable();
        for net in [one("198.51.100.7"), one("2001:db8::7")] {
            let wanted = HashSet::from([net]);
            live.put(net, "rate-limit 100", "65001:6666").await;
            let initial = live.fixture.cli.observed().await.unwrap();
            assert_eq!(initial.owned, wanted);
            assert!(initial.discard.is_empty());
            checked_round(&live.fixture.cli, &wanted, &db, &readback)
                .await
                .unwrap();
            let fixed = readback.snapshot();
            assert_eq!(fixed.count, 1);
            assert_eq!(fixed.discard_count, 1);
            assert!(fixed.ok);
            assert_eq!(live.fixture.cli.observed().await.unwrap().discard, wanted);

            live.put(net, "discard redirect 2001:db8::1:1", "65001:6666")
                .await;
            let combined = live.fixture.cli.observed().await.unwrap();
            assert_eq!(combined.owned, wanted);
            assert!(
                combined.discard.is_empty(),
                "separate IPv6 redirect counted as discard"
            );
            checked_round(&live.fixture.cli, &wanted, &db, &readback)
                .await
                .unwrap();
            assert_eq!(live.fixture.cli.observed().await.unwrap().discard, wanted);

            live.put(net, "rate-limit 100", "65001:6666").await;
            let removed = checked_round(&live.fixture.cli, &HashSet::new(), &db, &readback)
                .await
                .unwrap();
            assert_eq!(removed.count, 0);
            assert_eq!(removed.discard_count, 0);
            assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());

            live.put(net, "discard", "65001:9999").await;
            let foreign = live.raw(net).await;
            let before = readback.snapshot();
            assert!(checked_round(&live.fixture.cli, &wanted, &db, &readback)
                .await
                .is_err());
            assert_eq!(
                live.raw(net).await,
                foreign,
                "known foreign NLRI must not be replaced"
            );
            // Corrupt only this family's CLI read, leaving the actual daemon's
            // foreign path intact. A missing/unclassifiable read cannot authorize
            // an add that would replace that path, even with a zero CLI exit code.
            let wrapper = live.fixture.dir.join("fault-cli.sh");
            let fault = live.fixture.dir.join("fault.json");
            let writes = live.fixture.dir.join("forwarded-writes");
            std::fs::write(
                &wrapper,
                format!(
                    r#"#!/bin/sh
real="$1"
fault="$2"
writes="$3"
shift 3
case "$*" in
  *' -a {family} -j') cat "$fault"; exit 0 ;;
  *' add '*|*' del '*) touch "$writes" ;;
esac
exec "$real" "$@"
"#,
                    family = family(&net)
                ),
            )
            .unwrap();
            let mut args = vec![
                wrapper.to_str().unwrap().to_string(),
                live.fixture.cli.bin.to_str().unwrap().to_string(),
                fault.to_str().unwrap().to_string(),
                writes.to_str().unwrap().to_string(),
            ];
            args.extend(live.fixture.cli.args.clone());
            let broken_cli = GobgpCli {
                bin: "/bin/sh".into(),
                args,
                community: live.fixture.cli.community,
            };
            for invalid in ["", " \n", "null", "{\"unclassifiable\":null}"] {
                std::fs::write(&fault, invalid).unwrap();
                assert!(checked_round(&broken_cli, &wanted, &db, &readback)
                    .await
                    .is_err());
                assert!(!writes.exists(), "unusable read forwarded a write");
                assert_eq!(
                    live.raw(net).await,
                    foreign,
                    "unusable read replaced the real foreign path"
                );
                let view = readback.snapshot();
                assert!(!view.ok);
                assert_eq!(view.count, before.count);
                assert_eq!(view.discard_count, before.discard_count);
                assert_eq!(view.started, before.started);
            }
            writeln!(std::io::stdout(), "PASS live RIB refusal {}: invalid read preserves foreign path, no writes, prior observation retained", family(&net)).unwrap();
            let refused = readback.snapshot();
            assert!(!refused.ok);
            assert_eq!(refused.count, before.count);
            assert_eq!(refused.discard_count, before.discard_count);
            assert_eq!(refused.started, before.started);
            // A persistent collision must not stall expiry/unblock elsewhere,
            // including the empty wanted set used by shutdown reconciliation.
            let stale = one(if net.addr().is_ipv4() {
                "198.51.100.8"
            } else {
                "2001:db8::8"
            });
            let fresh = one(if net.addr().is_ipv4() {
                "198.51.100.9"
            } else {
                "2001:db8::9"
            });
            live.put(stale, "discard", "65001:6666").await;
            assert!(checked_round(
                &live.fixture.cli,
                &HashSet::from([net, fresh]),
                &db,
                &readback
            )
            .await
            .is_err());
            let progressed = live.fixture.cli.observed().await.unwrap();
            assert!(!progressed.owned.contains(&stale));
            assert!(progressed.discard.contains(&fresh));
            assert!(progressed.foreign_local.contains(&net));
            assert!(!readback.snapshot().ok);
            // Shutdown's ordinary no-collision path must still withdraw fresh.
            checked_round(&live.fixture.cli, &HashSet::new(), &db, &readback)
                .await
                .unwrap();
            assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
            assert!(live
                .fixture
                .cli
                .observed()
                .await
                .unwrap()
                .foreign_local
                .contains(&net));
            // Fixture owner cleanup, not an action of the Sokol reconciliation round.
            live.fixture.cli.apply(false, net).await.unwrap();
            // Direct stdout keeps the positive execution marker visible in CI even
            // when libtest captures successful test output. An unset env is no proof.
            writeln!(std::io::stdout(), "PASS live GoBGP {}: wrong action repaired, unwanted action withdrawn, foreign local path preserved, unrelated rules progress", family(&net)).unwrap();
        }
    }

    #[tokio::test]
    async fn owned_non_discard_action_is_replaced_when_still_wanted() {
        let non_discard = RIB.replace("\"rate\":0", "\"rate\":100");
        let fixture = RoundFixture::new(&non_discard, RIB, false);
        let db = fixture.db();
        let wanted = ips(&["198.51.100.7"]);
        round(&fixture.cli, &wanted, &db).await.unwrap();
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        assert!(
            calls.contains(" add match source 198.51.100.7/32 then discard"),
            "a wanted source with the wrong action was treated as reconciled"
        );
        assert_eq!(fixture.reads(), 4);
    }

    #[tokio::test]
    async fn unwanted_wrong_action_is_withdrawn_and_no_effect_repair_stays_unverified() {
        let non_discard = RIB.replace("\"rate\":0", "\"rate\":100");
        let fixture = RoundFixture::new(&non_discard, "{}", false);
        let db = fixture.db();
        let observation = round(&fixture.cli, &HashSet::new(), &db).await.unwrap();
        assert_eq!(observation.count, 0);
        assert_eq!(observation.discard_count, 0);
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        assert!(calls.contains(" del match source 198.51.100.7/32 then discard"));

        let fixture = RoundFixture::new(&non_discard, &non_discard, false);
        let db = fixture.db();
        let readback = Readback::default();
        readback.enable();
        checked_round(&fixture.cli, &ips(&["198.51.100.7"]), &db, &readback)
            .await
            .unwrap();
        let view = readback.snapshot();
        assert!(view.ok, "successful read is not convergence");
        assert_eq!(view.count, 1);
        assert_eq!(
            view.discard_count, 0,
            "a no-effect CLI success cannot fabricate discard"
        );
        let text =
            crate::metrics::render_with_flowspec(&crate::metrics::Snapshot::default(), &readback);
        assert!(text.contains("sokol_flowspec_discard_rules 0\n"));
        assert!(text.contains("sokol_flowspec_announced 1\n"));
    }

    #[tokio::test]
    async fn collisions_do_not_starve_unrelated_withdrawals_or_announcements() {
        let fixture = RoundFixture::new(RIB, "{}", false);
        let db = fixture.db();
        let readback = Readback::default();
        readback.enable();
        checked_round(&fixture.cli, &ips(&["198.51.100.7"]), &db, &readback)
            .await
            .unwrap();
        let previous = readback.snapshot();
        let mut raw: serde_json::Value = serde_json::from_str(RIB).unwrap();
        let mut wanted = ips(&["203.0.113.7"]);
        // More collisions than the work quota, sorted before the safe announce.
        // They must not spend quota or block the unrelated owned withdrawal.
        for host in 0..=MAX_OPS_PER_ROUND {
            let net = one(&format!("192.0.2.{host}"));
            let mut path = raw["[source: 198.51.100.7/32]"][0].clone();
            path["nlri"]["value"][0]["value"]["prefix"] = net.to_string().into();
            path["attrs"][1]["communities"] = serde_json::json!([4259915535u32]);
            raw[format!("[source: {net}]")] = serde_json::json!([path]);
            wanted.insert(net);
        }
        std::fs::write(fixture.dir.join("before.json"), raw.to_string()).unwrap();
        std::fs::write(fixture.dir.join("calls"), "").unwrap();
        assert!(checked_round(&fixture.cli, &wanted, &db, &readback)
            .await
            .is_err());
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        let writes: Vec<_> = calls
            .lines()
            .filter(|l| l.contains(" add ") || l.contains(" del "))
            .collect();
        assert_eq!(writes.len(), 2, "collision prevented unrelated progress");
        assert!(writes[0].contains(" del match source 198.51.100.7/32 then discard"));
        assert!(writes[1].contains(" add match source 203.0.113.7/32 then discard"));
        assert_eq!(fixture.reads(), 4);
        let failed = readback.snapshot();
        assert!(!failed.ok);
        assert_eq!(failed.count, previous.count);
        assert_eq!(failed.discard_count, previous.discard_count);
        assert_eq!(failed.started, previous.started);

        // Shutdown uses wanted empty. Fence an overlapping nonzero-ID path,
        // while still withdrawing an unrelated owned prefix.
        let mut shutdown: serde_json::Value = serde_json::from_str(RIB).unwrap();
        let owned = shutdown["[source: 198.51.100.7/32]"][0].clone();
        let mut foreign = owned.clone();
        foreign["LocalID"] = 1.into();
        shutdown["[source: 198.51.100.7/32]"] = serde_json::json!([owned, foreign]);
        let mut other = shutdown["[source: 198.51.100.7/32]"][0].clone();
        other["nlri"]["value"][0]["value"]["prefix"] = "203.0.113.7/32".into();
        shutdown["[source: 203.0.113.7/32]"] = serde_json::json!([other]);
        std::fs::remove_file(fixture.dir.join("applied")).unwrap();
        std::fs::write(fixture.dir.join("before.json"), shutdown.to_string()).unwrap();
        std::fs::write(fixture.dir.join("calls"), "").unwrap();
        assert!(checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
            .await
            .is_err());
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        let writes: Vec<_> = calls
            .lines()
            .filter(|l| l.contains(" add ") || l.contains(" del "))
            .collect();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].contains(" del match source 203.0.113.7/32 then discard"));
        assert_eq!(fixture.reads(), 4);
        assert!(!readback.snapshot().ok);
        assert_eq!(readback.snapshot().started, previous.started);
    }

    #[tokio::test]
    async fn empty_output_cannot_publish_zero_before_or_after_writes() {
        for invalid in ["", " \n", "null", "{\"hidden\":null}"] {
            let fixture = RoundFixture::new(RIB, invalid, false);
            let db = fixture.db();
            let readback = Readback::default();
            readback.enable();
            checked_round(&fixture.cli, &ips(&["198.51.100.7"]), &db, &readback)
                .await
                .unwrap();
            let previous = readback.snapshot();
            std::fs::write(fixture.dir.join("before.json"), invalid).unwrap();
            std::fs::write(fixture.dir.join("calls"), "").unwrap();
            assert!(
                checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
                    .await
                    .is_err(),
                "invalid initial read became confirmed absence: {invalid:?}"
            );
            assert!(!fixture.dir.join("applied").exists());
            let failed = readback.snapshot();
            assert!(!failed.ok);
            assert_eq!(failed.count, previous.count);
            assert_eq!(failed.discard_count, previous.discard_count);
            assert_eq!(failed.started, previous.started);
            // A successful write followed by an unusable read must not publish zero either.
            std::fs::write(fixture.dir.join("before.json"), RIB).unwrap();
            assert!(
                checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
                    .await
                    .is_err(),
                "invalid post-write read became confirmed absence"
            );
            assert!(fixture.dir.join("applied").exists());
            let failed = readback.snapshot();
            assert!(!failed.ok);
            assert_eq!(failed.count, previous.count);
            assert_eq!(failed.discard_count, previous.discard_count);
            assert_eq!(failed.started, previous.started);
        }
    }

    #[tokio::test]
    async fn malformed_path_collections_cannot_hide_a_local_collision() {
        for invalid in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!(false),
            serde_json::json!([null]),
            serde_json::json!(["not a path"]),
        ] {
            let raw = serde_json::json!({"[source: 198.51.100.7/32]":invalid});
            let fixture = RoundFixture::new(&raw.to_string(), RIB, false);
            let db = fixture.db();
            assert!(
                round(&fixture.cli, &ips(&["198.51.100.7"]), &db)
                    .await
                    .is_err(),
                "unclassifiable path was skipped"
            );
            assert!(
                !fixture.dir.join("applied").exists(),
                "unknown identity authorized a write"
            );
        }
    }

    #[tokio::test]
    async fn malformed_ownership_fields_cannot_authorize_withdrawal() {
        let variants = [
            ("/peer-address", serde_json::json!(null)),
            ("/peer-address", serde_json::json!(5)),
            ("/LocalID", serde_json::json!("0")),
            ("/attrs", serde_json::json!({})),
            ("/attrs/1/type", serde_json::json!("8")),
            ("/attrs/1/communities", serde_json::json!(null)),
            ("/attrs/1/communities/0", serde_json::json!("65001:6666")),
            ("/nlri/value", serde_json::json!(null)),
            ("/nlri/value/0/type", serde_json::json!("2")),
            ("/nlri/value/0/value/prefix", serde_json::json!("invalid")),
            ("/nlri/value/0/offset", serde_json::json!("0")),
        ];
        for (pointer, value) in variants {
            let mut raw: serde_json::Value = serde_json::from_str(RIB).unwrap();
            let path = &mut raw["[source: 198.51.100.7/32]"][0];
            if pointer == "/peer-address" || pointer.ends_with("/offset") {
                if pointer.ends_with("/offset") {
                    path["nlri"]["value"][0]["offset"] = value;
                } else {
                    path["peer-address"] = value;
                }
            } else {
                *path.pointer_mut(pointer).unwrap() = value;
            }
            let fixture = RoundFixture::new(&raw.to_string(), "{}", false);
            let db = fixture.db();
            assert!(
                round(&fixture.cli, &HashSet::new(), &db).await.is_err(),
                "invalid ownership field accepted: {pointer}"
            );
            assert!(
                !fixture.dir.join("applied").exists(),
                "invalid peer identity authorized withdrawal"
            );
        }
    }

    #[tokio::test]
    async fn foreign_only_collision_performs_no_write() {
        let foreign = RIB.replace("4259912202", "4259915535");
        let fixture = RoundFixture::new(&foreign, RIB, false);
        let db = fixture.db();
        let result = round(&fixture.cli, &ips(&["198.51.100.7"]), &db).await;
        assert!(
            result.is_err(),
            "adding the same NLRI replaces the foreign local path"
        );
        assert!(!fixture.dir.join("applied").exists());
    }

    #[tokio::test]
    async fn an_accepted_announce_without_a_rib_effect_is_not_counted() {
        let fixture = RoundFixture::new("{}", "{}", false);
        let db = fixture.db();
        let wanted = ips(&["198.51.100.7"]);
        assert_eq!(round(&fixture.cli, &wanted, &db).await.unwrap().count, 0);
        assert_eq!(fixture.reads(), 4);
        assert_eq!(
            {
                let rib = fixture.cli.observed().await.unwrap();
                plan(&wanted, &rib.owned, &rib.discard).0
            },
            vec![one("198.51.100.7")]
        );
    }

    #[tokio::test]
    async fn an_accepted_withdraw_without_a_rib_effect_is_still_counted() {
        let fixture = RoundFixture::new(RIB, RIB, false);
        let db = fixture.db();
        assert_eq!(
            round(&fixture.cli, &HashSet::new(), &db)
                .await
                .unwrap()
                .count,
            1
        );
        assert_eq!(fixture.reads(), 4);
        assert_eq!(
            {
                let rib = fixture.cli.observed().await.unwrap();
                plan(&HashSet::new(), &rib.owned, &rib.discard).1
            },
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
            assert_eq!(
                round(&fixture.cli, &wanted, &db).await.unwrap().count,
                count
            );
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
                .unwrap()
                .count,
            1
        );
        assert_eq!(fixture.reads(), 2);
    }
}
