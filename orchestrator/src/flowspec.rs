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
/// a slow gobgpd can stretch an error-free round to (2 + 64 + 2) × 5 s. A live round
/// with pending operations invalidated or failed can add 64 two-family refreshes:
/// (2 + 64 + 2×64 + 2) × 5 s, including fixed-target cleanup failures. The worker
/// runs apart from the main tick and shutdown preempts it (numerical review N06).
pub const MAX_OPS_PER_ROUND: usize = 64;
/// One gobgp call; a call that takes longer is killed. Read both RIB families
/// before continuing its plan or planning a later round; kill is not remote rollback.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Deadline for the attempt to withdraw the node's rules on shutdown: not a guarantee that any
/// number of rules is withdrawn in it.
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);
/// Work renews only after a completed round and this monotonic pause, regardless
/// of CLI success, effect or intent changes. It is not a global call-rate limit.
const ROUND_PAUSE: Duration = Duration::from_secs(1);
const CLEANUP_PAUSE: Duration = Duration::from_millis(500);

/// One completed read of both local RIB families. Age starts before the first CLI
/// read, so a slow or sequential read never appears younger than its oldest part.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Observation {
    count: usize,
    discard_count: usize,
    converged: bool,
    progress: bool,
    started: Instant,
}

/// A coherent copy for one scrape; no lock is held during CLI calls or rendering.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ReadbackView {
    pub enabled: bool,
    pub ok: bool,
    pub count: usize,
    pub discard_count: usize,
    /// The completed round observed owned == discard == its sampled wanted set.
    /// Revoked for pending/failed/cancelled rounds; not proof of latest intent.
    pub converged: bool,
    /// Strict reduction observed between a completed round's reads, for its
    /// sampled target. Not attributed to its commands; None while pending/failed.
    pub progress: Option<bool>,
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
        let mut view = self.0.lock().unwrap_or_else(|p| p.into_inner());
        view.ok = false;
        view.converged = false;
        view.progress = None;
    }

    fn completed(&self, observation: Observation) {
        let mut view = self.0.lock().unwrap_or_else(|p| p.into_inner());
        view.count = observation.count;
        view.discard_count = observation.discard_count;
        view.converged = observation.converged;
        view.progress = Some(observation.progress);
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

    /// Separate obligations: remove unwanted owned paths; establish wanted discard paths.
    fn work(&self, wanted: &HashSet<IpNet>) -> HashSet<(bool, IpNet)> {
        self.owned
            .difference(wanted)
            .map(|n| (false, *n))
            .chain(wanted.difference(&self.discard).map(|n| (true, *n)))
            .collect()
    }

    fn made_progress(&self, wanted: &HashSet<IpNet>, initial: &HashSet<(bool, IpNet)>) -> bool {
        let remaining = self.work(wanted);
        remaining.len() < initial.len() && remaining.is_subset(initial)
    }

    fn observation(&self, wanted: &HashSet<IpNet>, started: Instant) -> Observation {
        Observation {
            count: self.owned.len(),
            discard_count: self.discard.len(),
            converged: &self.owned == wanted && &self.discard == wanted,
            progress: false,
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
            // Known peer paths cannot be targeted by the local CLI. Their
            // remaining metadata must not fence unrelated local reconciliation.
            if remote {
                continue;
            }
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
                    // The pinned GoBGP producer encodes a nil community slice
                    // as null. It establishes no ownership tag.
                    if attr.get("communities").is_some_and(|v| v.is_null()) {
                        continue;
                    }
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
                // CLI writes use identifier zero. Pinned JSON hides actual IDs;
                // cli_id rejects only reported nonzero IDs. Reserve the tag for
                // one writer: a hidden-ID path reusing it is counted as owned.
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
    plan_after(wanted, observed, discard, &PlanCursor::default())
}

/// Worker-local ordering only: never authority, a cached RIB, or proof of effect.
/// Two last-considered prefixes bound memory independently of backlog size.
#[derive(Default)]
struct PlanCursor {
    announce: Option<IpNet>,
    withdraw: Option<IpNet>,
}

impl PlanCursor {
    fn considered(&mut self, announce: bool, net: IpNet) {
        if announce {
            self.announce = Some(net);
        } else {
            self.withdraw = Some(net);
        }
    }
}

fn rotate_after(queue: &mut [IpNet], cursor: Option<IpNet>) {
    queue.sort();
    if let Some(after) = cursor {
        let start = queue.partition_point(|net| *net <= after);
        queue.rotate_left(start);
    }
}

fn plan_after(
    wanted: &HashSet<IpNet>,
    observed: &HashSet<IpNet>,
    discard: &HashSet<IpNet>,
    cursor: &PlanCursor,
) -> (Vec<IpNet>, Vec<IpNet>) {
    let mut withdraw: Vec<IpNet> = observed.difference(wanted).copied().collect();
    let mut announce: Vec<IpNet> = wanted.difference(discard).copied().collect();
    rotate_after(&mut withdraw, cursor.withdraw);
    rotate_after(&mut announce, cursor.announce);
    withdraw.truncate(MAX_OPS_PER_ROUND);
    announce.truncate(MAX_OPS_PER_ROUND - withdraw.len());
    (announce, withdraw)
}

/// Publish only changed prefix sets. Main ticks with identical intent must not
/// cancel a slow read/write on every tick and starve successful observations.
pub fn update_wanted(sender: &watch::Sender<HashSet<IpNet>>, next: HashSet<IpNet>) -> bool {
    sender.send_if_modified(|current| {
        if *current == next {
            false
        } else {
            *current = next;
            true
        }
    })
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
    let mut reported_error = false;
    let mut cursor = PlanCursor::default();
    loop {
        let mut closed = wanted.clone();
        // Stop/closure always preempts normal work, including an already true stop.
        // Useful reads and compatible commands survive intent changes within a round.
        tokio::select! {
            biased;
            _ = stopping(&mut shutdown) => break,
            _ = intent_closed(&mut closed) => break,
            result = live_round_with_cursor(&cli, &mut wanted, &db, &readback, &mut cursor) => {
                match result {
                    Ok(_) => reported_error = false,
                    Err(e) => {
                        if !reported_error {
                            log::error!("[Flowspec] {}; retrying after at least one second", e);
                        }
                        reported_error = true;
                    }
                }
            }
        }
        // A consumed round renews its work allowance only after this fixed pause.
        // Success without effect and supersession spend the same allowance as error.
        // Intent churn neither bypasses nor restarts it; the next round samples afresh.
        tokio::select! {
            biased;
            _ = stopping(&mut shutdown) => break,
            _ = intent_closed(&mut closed) => break,
            _ = tokio::time::sleep(ROUND_PAUSE) => {}
        }
    }

    // The node's blocks vanish with it; do not leave its rules behind upstream.
    let empty = HashSet::new();
    let done = tokio::time::timeout(SHUTDOWN_BUDGET, async {
        loop {
            match checked_round_with_cursor(&cli, &empty, &db, &readback, &mut cursor).await {
                Ok(observation) if observation.count == 0 => return true,
                Ok(_) => {}
                Err(e) => {
                    log::error!("[Flowspec] Withdrawing on shutdown: {}", e);
                }
            }
            // Successful replies with remaining rules also consume cleanup work.
            // This pause stays inside the existing independent ten-second deadline.
            tokio::time::sleep(CLEANUP_PAUSE).await;
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

/// Ignore false shutdown notifications without cancelling useful work. A true
/// value (including one already present) or a closed publisher ends normal work.
async fn stopping(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

async fn intent_closed(wanted: &mut watch::Receiver<HashSet<IpNet>>) {
    while wanted.changed().await.is_ok() {}
}

enum Intent<'a> {
    Fixed(&'a HashSet<IpNet>),
    Live(&'a mut watch::Receiver<HashSet<IpNet>>),
}

impl Intent<'_> {
    fn sample(&mut self) -> HashSet<IpNet> {
        match self {
            Self::Fixed(wanted) => (*wanted).clone(),
            Self::Live(wanted) => wanted.borrow_and_update().clone(),
        }
    }

    fn differs(&self, target: &HashSet<IpNet>) -> bool {
        match self {
            Self::Fixed(_) => false,
            Self::Live(wanted) => *wanted.borrow() != *target,
        }
    }

    fn permits(&self, announce: bool, net: IpNet) -> bool {
        match self {
            Self::Fixed(wanted) => wanted.contains(&net) == announce,
            Self::Live(wanted) => wanted.borrow().contains(&net) == announce,
        }
    }

    /// False means the operation is obsolete, possibly after an unknown effect.
    /// The caller must re-read the RIB before planning any replacement command.
    async fn apply(&mut self, cli: &GobgpCli, announce: bool, net: IpNet) -> Result<bool, String> {
        let Self::Live(wanted) = self else {
            return cli.apply(announce, net).await.map(|_| true);
        };
        if wanted.borrow().contains(&net) != announce {
            return Ok(false);
        }
        let command = cli.apply(announce, net);
        tokio::pin!(command);
        loop {
            tokio::select! {
                biased;
                result = wanted.changed() => {
                    if result.is_err() || wanted.borrow().contains(&net) != announce {
                        return Ok(false);
                    }
                    // An unrelated update must not restart this CLI operation.
                },
                result = &mut command => return result.map(|_| true),
            }
        }
    }
}

struct RoundOutcome {
    observation: Observation,
    retry: bool,
}

/// True requests another round after the worker's work pause, after an obsolete
/// operation or a completed observation whose sampled target has since changed.
#[cfg(test)]
async fn live_round(
    cli: &GobgpCli,
    wanted: &mut watch::Receiver<HashSet<IpNet>>,
    db: &SentinelDb,
    readback: &Readback,
) -> Result<bool, String> {
    live_round_with_cursor(cli, wanted, db, readback, &mut PlanCursor::default()).await
}

async fn live_round_with_cursor(
    cli: &GobgpCli,
    wanted: &mut watch::Receiver<HashSet<IpNet>>,
    db: &SentinelDb,
    readback: &Readback,
    cursor: &mut PlanCursor,
) -> Result<bool, String> {
    readback.begin_round();
    let outcome = reconcile(cli, &mut Intent::Live(wanted), db, cursor).await?;
    readback.completed(outcome.observation);
    Ok(outcome.retry)
}

/// Same publication path for ordinary and shutdown rounds. Errors and cancelled
/// futures retain the previous count/time, with ok already revoked.
#[cfg(test)]
async fn checked_round(
    cli: &GobgpCli,
    wanted: &HashSet<IpNet>,
    db: &SentinelDb,
    readback: &Readback,
) -> Result<Observation, String> {
    checked_round_with_cursor(cli, wanted, db, readback, &mut PlanCursor::default()).await
}

async fn checked_round_with_cursor(
    cli: &GobgpCli,
    wanted: &HashSet<IpNet>,
    db: &SentinelDb,
    readback: &Readback,
    cursor: &mut PlanCursor,
) -> Result<Observation, String> {
    readback.begin_round();
    let observation = reconcile(cli, &mut Intent::Fixed(wanted), db, cursor)
        .await?
        .observation;
    readback.completed(observation);
    Ok(observation)
}

/// One reconciliation round; returns the final successful two-family observation.
#[cfg(test)]
async fn round(
    cli: &GobgpCli,
    wanted: &HashSet<IpNet>,
    db: &SentinelDb,
) -> Result<Observation, String> {
    Ok(reconcile(
        cli,
        &mut Intent::Fixed(wanted),
        db,
        &mut PlanCursor::default(),
    )
    .await?
    .observation)
}

/// Reads survive intent churn; planning samples intent only after both reads.
async fn reconcile(
    cli: &GobgpCli,
    intent: &mut Intent<'_>,
    db: &SentinelDb,
    cursor: &mut PlanCursor,
) -> Result<RoundOutcome, String> {
    let started = Instant::now();
    let mut observed = cli.observed().await?;
    let wanted = intent.sample();
    let initial_work = observed.work(&wanted);
    // CLI writes address NLRI rather than ownership. Exclude known collisions
    // before applying the work quota, so they cannot starve unrelated unblocking.
    let mut collisions: Vec<_> = wanted
        .difference(&observed.discard)
        .chain(observed.owned.difference(&wanted))
        .filter(|n| observed.foreign_local.contains(n))
        .copied()
        .collect();
    let writable_wanted = wanted
        .difference(&observed.foreign_local)
        .copied()
        .collect();
    let writable_owned = observed
        .owned
        .difference(&observed.foreign_local)
        .copied()
        .collect();
    let (announce, withdraw) =
        plan_after(&writable_wanted, &writable_owned, &observed.discard, cursor);
    let changed = !announce.is_empty() || !withdraw.is_empty();
    let mut superseded = false;
    let mut first_failure: Option<String> = None;
    let mut failure_count = 0usize;
    for (is_announce, net) in withdraw
        .into_iter()
        .map(|n| (false, n))
        .chain(announce.into_iter().map(|n| (true, n)))
    {
        // Advance only as each candidate is reached, before any cancellable
        // work. A failed recovery must not skip the rest of an unvisited plan.
        cursor.considered(is_announce, net);
        // An obsolete queued command has not started and has no unknown effect.
        // Keep the finite original queue; a later round plans any replacements.
        if !intent.permits(is_announce, net) {
            superseded = true;
            continue;
        }
        let needed = if is_announce {
            !observed.discard.contains(&net)
        } else {
            observed.owned.contains(&net)
        };
        if !needed {
            continue;
        }
        // After a cancelled call, the refreshed RIB may reveal a new collision
        // or that another queued operation is already satisfied. Do not overwrite it.
        if observed.foreign_local.contains(&net) {
            collisions.push(net);
            continue;
        }
        match intent.apply(cli, is_announce, net).await {
            Ok(false) => {
                superseded = true;
                // Cancellation can follow an accepted write. Before continuing
                // with another NLRI, refresh both families and revalidate it.
                observed = cli.observed().await?;
            }
            Ok(true) => {
                let verb = if is_announce { "announced" } else { "withdrew" };
                log::info!("[Flowspec] {} discard rule for {}", verb, show(&net));
                db.append(format!(
                    "FLOWSPEC_{}|IP:{}",
                    if is_announce { "ANNOUNCE" } else { "WITHDRAW" },
                    show(&net)
                ));
            }
            Err(e) => {
                // An error may follow an accepted RPC. Keep the round incomplete,
                // but refresh before giving another distinct NLRI its turn.
                failure_count += 1;
                first_failure
                    .get_or_insert_with(|| format!("gobgp failed for {}: {}", show(&net), e));
                observed = cli.observed().await?;
            }
        }
    }
    // A successful write acknowledges the CLI operation, not the resulting RIB.
    // Keep unknown readback as an error, never replace it with arithmetic guesses.
    let observation = if changed {
        let started = Instant::now();
        let final_rib = cli.observed().await?;
        let mut observation = final_rib.observation(&wanted, started);
        // Identity/action obligations, not cardinality or successful command count.
        // Reject a smaller mismatch count if it introduced any new obligation.
        observation.progress = final_rib.made_progress(&wanted, &initial_work);
        observation
    } else {
        observed.observation(&wanted, started)
    };
    collisions.sort();
    collisions.dedup();
    if let Some(error) = first_failure {
        // Readable recovery and later CLI successes do not erase a failed call.
        // Publication retains previous counts/time with health revoked.
        return Err(format!(
            "{} ({} command failures, {} collisions skipped); remaining non-colliding operations attempted",
            error, failure_count, collisions.len()
        ));
    }
    if let Some(net) = collisions.first() {
        // Non-colliding work has progressed, but the full round is incomplete.
        // Preserve the last successful counts/time with health already revoked.
        return Err(format!(
            "local FlowSpec path collision for {} ({} skipped); non-colliding operations completed",
            show(net),
            collisions.len()
        ));
    }
    Ok(RoundOutcome {
        observation,
        retry: superseded || intent.differs(&wanted),
    })
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

    async fn eventually(mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        predicate()
    }

    fn copy_cli(cli: &GobgpCli) -> GobgpCli {
        GobgpCli {
            bin: cli.bin.clone(),
            args: cli.args.clone(),
            community: cli.community,
        }
    }

    async fn superseded_read(before: &str, initial: HashSet<IpNet>, latest: HashSet<IpNet>) {
        let fixture = RoundFixture::new(before, before, false);
        std::fs::write(fixture.dir.join("pause"), "").unwrap();
        let readback = Arc::new(Readback::default());
        readback.enable();
        let (wanted_tx, wanted_rx) = watch::channel(initial);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            readback.clone(),
        ));
        assert!(eventually(|| fixture.dir.join("entered").exists()).await);
        wanted_tx.send(latest.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let pending_reads = fixture.reads();
        std::fs::remove_file(fixture.dir.join("pause")).unwrap();
        let recovered = eventually(|| {
            let view = readback.snapshot();
            view.ok && view.converged && view.count == latest.len()
        })
        .await;
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        // The fake writes acknowledge without effect; let shutdown see an empty RIB.
        std::fs::write(fixture.dir.join("before.json"), "{}").unwrap();
        std::fs::write(fixture.dir.join("after.json"), "{}").unwrap();
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(recovered, "latest stable intent did not recover");
        assert!(
            !calls
                .lines()
                .any(|line| line.contains(" add ") || line.contains(" del ")),
            "superseded read led to an obsolete write: {calls}"
        );
        assert_eq!(pending_reads, 1, "intent restarted a useful read");
    }

    #[tokio::test]
    async fn superseded_read_cannot_announce_a_revoked_target() {
        superseded_read("{}", ips(&["198.51.100.7"]), HashSet::new()).await;
    }

    #[tokio::test]
    async fn superseded_read_cannot_withdraw_a_restored_target() {
        superseded_read(RIB, HashSet::new(), ips(&["198.51.100.7"])).await;
    }

    #[tokio::test]
    async fn changing_intent_keeps_the_pending_read_and_samples_latest_before_planning() {
        let fixture = RoundFixture::new("{}", RIB, false);
        std::fs::write(fixture.dir.join("pause"), "").unwrap();
        let (wanted_tx, wanted_rx) = watch::channel(HashSet::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let readback = Arc::new(Readback::default());
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            readback.clone(),
        ));
        assert!(eventually(|| fixture.dir.join("entered").exists()).await);
        for i in 0..12 {
            update_wanted(
                &wanted_tx,
                if i % 2 == 0 {
                    HashSet::new()
                } else {
                    ips(&["198.51.100.7"])
                },
            );
            shutdown_tx.send(false).unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let pending_reads = fixture.reads();
        std::fs::remove_file(fixture.dir.join("pause")).unwrap();
        let completed = eventually(|| {
            let view = readback.snapshot();
            view.converged && view.count == 1
        })
        .await;
        std::fs::write(fixture.dir.join("before.json"), "{}").unwrap();
        std::fs::write(fixture.dir.join("after.json"), "{}").unwrap();
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending_reads, 1,
            "actual intent changes cancelled a useful RIB read"
        );
        assert!(
            completed,
            "latest target was not sampled after the retained read"
        );
    }

    #[tokio::test]
    async fn a_failed_command_does_not_abandon_stable_queued_work() {
        for timeout in [false, true] {
            let fixture = RoundFixture::new(RIB, RIB, false);
            let db = Arc::new(fixture.db());
            let readback = Arc::new(Readback::default());
            readback.enable();
            checked_round(&fixture.cli, &ips(&["198.51.100.7"]), &db, &readback)
                .await
                .unwrap();
            let old = readback.snapshot();
            std::fs::write(fixture.dir.join("calls"), "").unwrap();
            std::fs::write(
                fixture.dir.join("gobgp"),
                r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
case "$*" in
  *' -j') printf '{}\n' ;;
  *' add '*'198.51.100.7/32'*)
    if [ -f timeout ]; then exec sleep 30; fi
    printf 'isolated command failure\n' >&2; exit 7 ;;
  *' add '*'198.51.100.9/32'*) touch stable_done ;;
  *) exit 8 ;;
esac
"#,
            )
            .unwrap();
            if timeout {
                std::fs::write(fixture.dir.join("timeout"), "").unwrap();
            }
            let (wanted_tx, wanted_rx) = watch::channel(ips(&["198.51.100.7", "198.51.100.9"]));
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let worker = tokio::spawn(run_worker(
                copy_cli(&fixture.cli),
                wanted_rx,
                shutdown_rx,
                db,
                readback.clone(),
            ));
            let progressed =
                tokio::time::timeout(Duration::from_secs(if timeout { 8 } else { 2 }), async {
                    while !fixture.dir.join("stable_done").exists() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .is_ok();
            let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
            let failed = readback.snapshot();
            shutdown_tx.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(3), worker)
                .await
                .unwrap()
                .unwrap();
            drop(wanted_tx);
            assert!(
                progressed,
                "one failed prefix abandoned stable queued work: {calls}"
            );
            let writes: Vec<_> = calls.lines().filter(|l| l.contains(" add ")).collect();
            assert!(writes[0].contains("198.51.100.7/32"));
            assert!(
                writes[1].contains("198.51.100.9/32"),
                "failed prefix retried ahead of stable work: {calls}"
            );
            assert!(!failed.ok && !failed.converged);
            assert_eq!(failed.count, old.count);
            assert_eq!(failed.discard_count, old.discard_count);
            assert_eq!(failed.started, old.started);
        }
    }

    #[tokio::test]
    async fn failed_rounds_wait_despite_intent_churn() {
        failed_round_retry(false).await;
    }

    #[tokio::test]
    async fn failed_rounds_wait_despite_overdue_ticks() {
        failed_round_retry(true).await;
    }

    async fn failed_round_retry(overdue: bool) {
        let fixture = RoundFixture::new("{}", "{}", false);
        std::fs::write(fixture.dir.join("hold"), "").unwrap();
        std::fs::write(
            fixture.dir.join("gobgp"),
            r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
if [ -f hold ]; then
  touch entered
  while [ -f hold ]; do sleep 0.01; done
fi
touch failed
exit 7
"#,
        )
        .unwrap();
        let (wanted_tx, wanted_rx) = watch::channel(ips(&["198.51.100.7"]));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            Arc::new(Readback::default()),
        ));
        assert!(eventually(|| fixture.dir.join("entered").exists()).await);
        if overdue {
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
        std::fs::remove_file(fixture.dir.join("hold")).unwrap();
        assert!(eventually(|| fixture.dir.join("failed").exists()).await);
        let completed = Instant::now();
        // Both normal intent churn and false stop notifications must leave
        // the retry deadline alone. Closure/true shutdown is tested live.
        for i in 0..10 {
            wanted_tx
                .send(ips(&[if i % 2 == 0 {
                    "198.51.100.9"
                } else {
                    "198.51.100.7"
                }]))
                .unwrap();
            shutdown_tx.send(false).unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let early = fixture.reads();
        while completed.elapsed() < Duration::from_millis(1600) && fixture.reads() < 2 {
            wanted_tx.send(ips(&["198.51.100.9"])).unwrap();
            shutdown_tx.send(false).unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let retried = fixture.reads() >= 2;
        let elapsed = completed.elapsed();
        shutdown_tx.send(true).unwrap();
        // Cleanup has its own existing bounded retries for this failing CLI.
        worker.abort();
        let _ = worker.await;
        assert_eq!(
            early, 1,
            "failed round retried before its pause: overdue={overdue}"
        );
        assert!(
            retried,
            "intent churn restarted the retry deadline indefinitely"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "retry floor bypassed: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn quota_rotation_serves_announces_after_no_effect_success() {
        quota_worker(false, false, false).await;
    }

    #[tokio::test]
    async fn quota_rotation_serves_withdrawals_after_no_effect_success() {
        quota_worker(true, false, false).await;
    }

    #[tokio::test]
    async fn quota_rotation_serves_announces_after_failed_calls() {
        quota_worker(false, true, false).await;
    }

    #[tokio::test]
    async fn quota_rotation_serves_withdrawals_after_failed_calls() {
        quota_worker(true, true, false).await;
    }

    #[tokio::test]
    async fn quota_rotation_serves_cleanup_within_its_existing_budget() {
        quota_worker(true, true, true).await;
    }

    fn quota_nets(ipv6: bool) -> Vec<IpNet> {
        (0..=MAX_OPS_PER_ROUND)
            .map(|host| {
                one(&if ipv6 {
                    format!("2001:db8:1::{host:x}")
                } else {
                    format!("198.51.100.{host}")
                })
            })
            .collect()
    }

    async fn quota_worker(deleting: bool, failing: bool, cleanup: bool) {
        let nets = quota_nets(false);
        let tail = *nets.last().unwrap();
        let template: serde_json::Value = serde_json::from_str(RIB).unwrap();
        let mut before = serde_json::Map::new();
        if deleting {
            for net in &nets {
                let mut path = template["[source: 198.51.100.7/32]"][0].clone();
                path["nlri"]["value"][0]["value"]["prefix"] = net.to_string().into();
                before.insert(format!("[source: {net}]"), serde_json::json!([path]));
            }
        }
        let mut after = before.clone();
        if deleting {
            after.remove(&format!("[source: {tail}]"));
        } else {
            let mut path = template["[source: 198.51.100.7/32]"][0].clone();
            path["nlri"]["value"][0]["value"]["prefix"] = tail.to_string().into();
            after.insert(format!("[source: {tail}]"), serde_json::json!([path]));
        }
        let fixture = RoundFixture::new(
            &serde_json::Value::Object(before.clone()).to_string(),
            "{}",
            false,
        );
        std::fs::write(
            fixture.dir.join("current.json"),
            serde_json::Value::Object(before).to_string(),
        )
        .unwrap();
        std::fs::write(
            fixture.dir.join("effect.json"),
            serde_json::Value::Object(after).to_string(),
        )
        .unwrap();
        std::fs::write(
            fixture.dir.join("gobgp"),
            format!(
                r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
case "$*" in
  *'ipv4-flowspec -j') cat current.json ;;
  *'ipv6-flowspec -j') printf '{{}}\n' ;;
  *' add '*|*' del '*)
    case "$*" in *' source {tail} '*) cp effect.json current.json; touch served; exit 0 ;; esac
    if [ -f fail ]; then exit 7; fi ;;
  *) exit 8 ;;
esac
"#
            ),
        )
        .unwrap();
        let db = Arc::new(fixture.db());
        let readback = Arc::new(Readback::default());
        readback.enable();
        let initial = if deleting {
            nets.iter().copied().collect()
        } else {
            HashSet::new()
        };
        checked_round(&fixture.cli, &initial, &db, &readback)
            .await
            .unwrap();
        std::fs::write(fixture.dir.join("calls"), "").unwrap();
        if failing {
            std::fs::write(fixture.dir.join("fail"), "").unwrap();
        }
        let target = if deleting {
            HashSet::new()
        } else {
            nets.iter().copied().collect()
        };
        let (_wanted_tx, wanted_rx) = watch::channel(target);
        let (_shutdown_tx, shutdown_rx) = watch::channel(cleanup);
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            db,
            readback.clone(),
        ));
        let served = tokio::time::timeout(Duration::from_secs(6), async {
            while !fixture.dir.join("served").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        if cleanup {
            // The fixture controller clears its stuck RIB after observing service;
            // this is not an assertion that the worker can force failed effects.
            std::fs::write(fixture.dir.join("current.json"), "{}").unwrap();
            tokio::time::timeout(Duration::from_secs(3), worker)
                .await
                .unwrap()
                .unwrap();
            assert!(readback.snapshot().ok && readback.snapshot().converged);
            assert_eq!(readback.snapshot().count, 0);
        } else {
            worker.abort();
            let _ = worker.await;
        }
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        assert!(
            served,
            "quota repeatedly selected the same prefixes: deleting={deleting} failing={failing}"
        );
        let writes: Vec<_> = calls
            .lines()
            .filter(|l| l.contains(" add ") || l.contains(" del "))
            .collect();
        let index = writes
            .iter()
            .position(|l| l.contains(&format!(" source {tail} ")))
            .unwrap();
        assert_eq!(
            index, MAX_OPS_PER_ROUND,
            "tail must be first in the next class plan: {calls}"
        );
        let actual = fixture.cli.observed().await.unwrap();
        assert_eq!(actual.owned.contains(&tail), !deleting);
        assert_eq!(actual.discard.contains(&tail), !deleting);
    }

    #[test]
    fn rotating_plans_preserve_quota_priority_and_wrap_stale_cursors() {
        let nets = quota_nets(false);
        let observed: HashSet<_> = nets.iter().copied().collect();
        let wanted: HashSet<_> = quota_nets(true).into_iter().collect();
        let mut cursor = PlanCursor::default();
        let mut served = HashSet::new();
        for _ in 0..2 {
            let (announce, withdraw) = plan_after(&wanted, &observed, &observed, &cursor);
            assert!(announce.is_empty(), "withdrawals retain strict priority");
            assert_eq!(withdraw.len(), MAX_OPS_PER_ROUND);
            for net in withdraw {
                served.insert(net);
                cursor.considered(false, net);
            }
        }
        assert_eq!(served, observed);
        served.clear();
        for _ in 0..2 {
            let (announce, withdraw) =
                plan_after(&wanted, &HashSet::new(), &HashSet::new(), &cursor);
            assert!(withdraw.is_empty());
            assert_eq!(announce.len(), MAX_OPS_PER_ROUND);
            for net in announce {
                served.insert(net);
                cursor.considered(true, net);
            }
        }
        assert_eq!(served, wanted);
        // When only one announce slot remains, the withdrawal cursor must not
        // repeatedly select the first announce of a different address family.
        let observed: HashSet<_> = nets.iter().copied().take(MAX_OPS_PER_ROUND - 1).collect();
        let wanted: HashSet<_> = quota_nets(true).into_iter().take(2).collect();
        cursor = PlanCursor::default();
        served.clear();
        for _ in 0..2 {
            let (announce, withdraw) = plan_after(&wanted, &observed, &observed, &cursor);
            assert_eq!(withdraw.len(), MAX_OPS_PER_ROUND - 1);
            assert_eq!(announce.len(), 1);
            for net in withdraw {
                cursor.considered(false, net);
            }
            for net in announce {
                served.insert(net);
                cursor.considered(true, net);
            }
        }
        assert_eq!(
            served, wanted,
            "operation classes must have independent cursors"
        );
        // A removed cursor still denotes an ordering boundary, not a required member.
        cursor.withdraw = Some(one("203.0.113.255"));
        let (announce, withdraw) = plan_after(&HashSet::new(), &observed, &HashSet::new(), &cursor);
        assert!(announce.is_empty());
        assert_eq!(withdraw, nets[..MAX_OPS_PER_ROUND - 1]);
        assert_eq!(
            plan(&wanted, &observed, &observed),
            plan_after(&wanted, &observed, &observed, &PlanCursor::default())
        );
    }

    #[tokio::test]
    async fn a_failed_recovery_advances_only_the_considered_prefix() {
        let fixture = RoundFixture::new("{}", "{}", false);
        std::fs::write(
            fixture.dir.join("gobgp"),
            r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
case "$*" in
  *' -j') if [ -f refuse ]; then printf 'null\n'; else printf '{}\n'; fi ;;
  *' add '*) touch refuse; exit 7 ;;
  *) exit 8 ;;
esac
"#,
        )
        .unwrap();
        let db = fixture.db();
        let nets = quota_nets(false);
        let (_wanted_tx, mut wanted_rx) = watch::channel(nets.iter().copied().collect());
        let mut cursor = PlanCursor::default();
        for net in nets.iter().take(3) {
            let _ = std::fs::remove_file(fixture.dir.join("refuse"));
            assert!(live_round_with_cursor(
                &fixture.cli,
                &mut wanted_rx,
                &db,
                &Readback::default(),
                &mut cursor
            )
            .await
            .is_err());
            assert_eq!(
                cursor.announce,
                Some(*net),
                "unvisited queued work skipped after failed recovery"
            );
            // Invalid initial reads authorize no plan and do not move either cursor.
            assert!(live_round_with_cursor(
                &fixture.cli,
                &mut wanted_rx,
                &db,
                &Readback::default(),
                &mut cursor
            )
            .await
            .is_err());
            assert_eq!(cursor.announce, Some(*net));
            assert!(cursor.withdraw.is_none());
        }
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        let writes: Vec<_> = calls.lines().filter(|l| l.contains(" add ")).collect();
        assert_eq!(writes.len(), 3);
        for (call, net) in writes.iter().zip(&nets) {
            assert!(call.contains(&format!(" source {net} ")));
        }
    }

    #[tokio::test]
    async fn round_progress_requires_strict_identity_and_action_improvement() {
        let a = one("198.51.100.7");
        let b = one("198.51.100.9");
        let c = one("198.51.100.10");
        let d = one("198.51.100.11");
        let rib = |owned: &[IpNet], discard: &[IpNet]| {
            let template: serde_json::Value = serde_json::from_str(RIB).unwrap();
            let mut paths = serde_json::Map::new();
            for net in owned {
                let mut path = template["[source: 198.51.100.7/32]"][0].clone();
                path["nlri"]["value"][0]["value"]["prefix"] = net.to_string().into();
                if !discard.contains(net) {
                    path["attrs"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|a| a["type"] != 16);
                }
                paths.insert(format!("[source: {net}]"), serde_json::json!([path]));
            }
            serde_json::Value::Object(paths).to_string()
        };
        for (name, before, after, target, progress, converged) in [
            (
                "no_effect_add",
                rib(&[], &[]),
                rib(&[], &[]),
                HashSet::from([a]),
                false,
                false,
            ),
            (
                "no_effect_delete",
                rib(&[a], &[a]),
                rib(&[a], &[a]),
                HashSet::new(),
                false,
                false,
            ),
            (
                "partial_add",
                rib(&[], &[]),
                rib(&[a], &[a]),
                HashSet::from([a, b]),
                true,
                false,
            ),
            (
                "partial_delete",
                rib(&[a, b], &[a, b]),
                rib(&[a], &[a]),
                HashSet::new(),
                true,
                false,
            ),
            (
                "action_repair",
                rib(&[a], &[]),
                rib(&[a], &[a]),
                HashSet::from([a]),
                true,
                true,
            ),
            (
                "equal_count_swap",
                rib(&[a], &[a]),
                rib(&[b], &[b]),
                HashSet::from([a, b]),
                false,
                false,
            ),
            (
                "smaller_with_new_error",
                rib(&[c], &[c]),
                rib(&[a, d], &[a, d]),
                HashSet::from([a, b]),
                false,
                false,
            ),
            (
                "already_converged",
                rib(&[a], &[a]),
                rib(&[a], &[a]),
                HashSet::from([a]),
                false,
                true,
            ),
        ] {
            let fixture = RoundFixture::new(&before, &after, false);
            let db = fixture.db();
            let readback = Readback::default();
            readback.enable();
            checked_round(&fixture.cli, &target, &db, &readback)
                .await
                .unwrap();
            let view = readback.snapshot();
            assert_eq!(
                view.progress,
                Some(progress),
                "{name}: wrong measured progress"
            );
            assert_eq!(view.converged, converged, "{name}: wrong convergence");
            assert!(crate::metrics::render_with_flowspec(
                &crate::metrics::Snapshot::default(),
                &readback
            )
            .contains(&format!(
                "sokol_flowspec_round_progress {}\n",
                progress as u8
            )));
            // Even a completed improvement cannot remain a verified current observation
            // during pending, failed or cancelled work.
            readback.begin_round();
            assert!(readback.snapshot().progress.is_none());
            assert!(crate::metrics::render_with_flowspec(
                &crate::metrics::Snapshot::default(),
                &readback
            )
            .contains("sokol_flowspec_round_progress -1\n"));
        }
    }

    fn budget_fixture(deleting: bool) -> RoundFixture {
        let fixture = RoundFixture::new("{}", "{}", false);
        std::fs::write(
            fixture.dir.join("current.json"),
            if deleting { RIB } else { "{}" },
        )
        .unwrap();
        std::fs::write(
            fixture.dir.join("gobgp"),
            r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
case "$*" in
  *'ipv4-flowspec -j')
    if [ -f hold ]; then
      touch entered
      while [ -f hold ]; do sleep 0.01; done
    fi
    cat current.json ;;
  *'ipv6-flowspec -j')
    n=0; if [ -f reads ]; then n=$(cat reads); fi
    n=$((n + 1)); printf '%s\n' "$n" > reads
    if [ "$n" = 2 ] && [ -f post_hold ]; then
      touch post_entered
      while [ -f post_hold ]; do sleep 0.01; done
    fi
    printf '{}\n'
    if [ $((n % 2)) = 0 ]; then printf 'done\n' >> rounds; fi ;;
  *' add '*|*' del '*)
    if [ -f effect ]; then
      cp effect.json replacement.json && mv replacement.json current.json
    fi ;;
  *) exit 8 ;;
esac
"#,
        )
        .unwrap();
        fixture
    }

    fn budget_writes(fixture: &RoundFixture) -> usize {
        std::fs::read_to_string(fixture.dir.join("calls"))
            .unwrap()
            .lines()
            .filter(|l| l.contains(" add ") || l.contains(" del "))
            .count()
    }

    #[tokio::test]
    async fn successful_no_effect_rounds_wait_despite_intent_churn() {
        successful_budget(false).await;
    }

    #[tokio::test]
    async fn successful_no_effect_rounds_wait_despite_overdue_ticks() {
        successful_budget(true).await;
    }

    async fn successful_budget(overdue: bool) {
        for deleting in [false, true] {
            let fixture = budget_fixture(deleting);
            if overdue {
                std::fs::write(fixture.dir.join("hold"), "").unwrap();
            }
            let target = if deleting {
                HashSet::new()
            } else {
                ips(&["198.51.100.7"])
            };
            let (wanted_tx, wanted_rx) = watch::channel(target.clone());
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let readback = Arc::new(Readback::default());
            readback.enable();
            let worker = tokio::spawn(run_worker(
                copy_cli(&fixture.cli),
                wanted_rx,
                shutdown_rx,
                Arc::new(fixture.db()),
                readback.clone(),
            ));
            if overdue {
                assert!(eventually(|| fixture.dir.join("entered").exists()).await);
                tokio::time::sleep(Duration::from_millis(1200)).await;
                std::fs::remove_file(fixture.dir.join("hold")).unwrap();
            }
            assert!(eventually(|| readback.snapshot().ok).await);
            assert!(!readback.snapshot().converged);
            let completed = Instant::now();
            // The two sets remain genuinely different even for withdrawals.
            for i in 0..10 {
                wanted_tx
                    .send(if i % 2 == 0 {
                        ips(&["198.51.100.9"])
                    } else {
                        target.clone()
                    })
                    .unwrap();
                shutdown_tx.send(false).unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            let early = budget_writes(&fixture);
            // Restore the deleted prefix, or switch the announced prefix: both
            // final targets differ from what the first round sampled.
            let latest = ips(&[if deleting {
                "198.51.100.7"
            } else {
                "198.51.100.9"
            }]);
            wanted_tx.send(latest.clone()).unwrap();
            let resumed = || {
                if deleting {
                    readback.snapshot().ok && readback.snapshot().converged
                } else {
                    budget_writes(&fixture) >= 2
                }
            };
            while completed.elapsed() < Duration::from_millis(1800) && !resumed() {
                wanted_tx.send(latest.clone()).unwrap();
                shutdown_tx.send(false).unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let retried = resumed();
            let elapsed = completed.elapsed();
            let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
            worker.abort();
            let _ = worker.await;
            assert_eq!(early, 1, "successful no-effect calls bypassed work pause: deleting={deleting}, overdue={overdue}");
            assert!(retried, "intent churn restarted the work pause");
            if deleting {
                assert_eq!(
                    budget_writes(&fixture),
                    1,
                    "restored latest intent was deleted after pause: {calls}"
                );
            } else {
                let writes: Vec<_> = calls.lines().filter(|l| l.contains(" add ")).collect();
                assert!(
                    writes[1].contains("source 198.51.100.9/32"),
                    "post-pause write used stale intent: {calls}"
                );
            }
            assert!(
                elapsed >= Duration::from_millis(900),
                "work pause bypassed: {elapsed:?}"
            );
        }
    }

    #[tokio::test]
    async fn superseded_success_shares_the_work_pause() {
        let fixture = budget_fixture(false);
        std::fs::write(fixture.dir.join("post_hold"), "").unwrap();
        let (wanted_tx, wanted_rx) = watch::channel(ips(&["198.51.100.7"]));
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let readback = Arc::new(Readback::default());
        readback.enable();
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            readback.clone(),
        ));
        assert!(eventually(|| fixture.dir.join("post_entered").exists()).await);
        wanted_tx.send(ips(&["198.51.100.9"])).unwrap();
        std::fs::remove_file(fixture.dir.join("post_hold")).unwrap();
        assert!(eventually(|| readback.snapshot().ok).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let early = budget_writes(&fixture);
        let retried = eventually(|| budget_writes(&fixture) >= 2).await;
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        worker.abort();
        let _ = worker.await;
        assert_eq!(early, 1, "superseded successful round bypassed work pause");
        assert!(
            retried && calls.contains("source 198.51.100.9/32"),
            "latest intent did not recover after pause: {calls}"
        );
    }

    #[tokio::test]
    async fn successful_no_effect_cleanup_waits_and_then_recovers() {
        let fixture = budget_fixture(true);
        let (_wanted_tx, wanted_rx) = watch::channel(HashSet::new());
        let (_shutdown_tx, shutdown_rx) = watch::channel(true);
        let readback = Arc::new(Readback::default());
        readback.enable();
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            readback.clone(),
        ));
        assert!(eventually(|| fixture.dir.join("rounds").exists()).await);
        assert!(!readback.snapshot().converged);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let early = budget_writes(&fixture);
        let retried = eventually(|| budget_writes(&fixture) >= 2).await;
        // Controlled fault removal; this is not guaranteed cleanup under persistent failure.
        std::fs::write(fixture.dir.join("replacement.json"), "{}").unwrap();
        std::fs::rename(
            fixture.dir.join("replacement.json"),
            fixture.dir.join("current.json"),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            early, 1,
            "successful no-effect cleanup spun without its work pause"
        );
        assert!(
            retried && readback.snapshot().converged,
            "cleanup did not recover"
        );
    }

    fn superseding_fixture() -> RoundFixture {
        let fixture = RoundFixture::new("{}", "{}", false);
        let script = fixture.dir.join("gobgp");
        std::fs::write(
            &script,
            r#"#!/bin/sh
cd "$(dirname "$0")" || exit 9
printf '%s\n' "$*" >> calls
case "$*" in
  *' -j')
    if [ -f bad_entered ] && [ ! -f fresh_entered ]; then
      touch fresh_entered
      while [ -f fresh_hold ]; do sleep 0.01; done
    fi
    printf '{}\n' ;;
  *' add '*'198.51.100.7/32'*)
    touch bad_entered
    while [ -f bad_hold ]; do sleep 0.01; done ;;
  *' add '*'198.51.100.9/32'*) touch stable_done ;;
  *) exit 8 ;;
esac
"#,
        )
        .unwrap();
        std::fs::write(fixture.dir.join("bad_hold"), "").unwrap();
        std::fs::write(fixture.dir.join("fresh_hold"), "").unwrap();
        fixture
    }

    #[tokio::test]
    async fn a_superseded_command_does_not_abandon_stable_queued_work() {
        let fixture = superseding_fixture();
        let initial = ips(&["198.51.100.7", "198.51.100.9"]);
        let (wanted_tx, wanted_rx) = watch::channel(initial.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            Arc::new(Readback::default()),
        ));
        assert!(eventually(|| fixture.dir.join("bad_entered").exists()).await);
        update_wanted(&wanted_tx, ips(&["198.51.100.9"]));
        assert!(eventually(|| fixture.dir.join("fresh_entered").exists()).await);
        // Reintroduce the unstable prefix while its recovery read is held. A full
        // restart puts it first again; the remaining queued command must get a turn.
        update_wanted(&wanted_tx, initial);
        std::fs::remove_file(fixture.dir.join("fresh_hold")).unwrap();
        let progressed = eventually(|| fixture.dir.join("stable_done").exists()).await;
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(
            progressed,
            "a flapping first command abandoned stable queued work: {calls}"
        );
        let prefix_calls: Vec<_> = calls
            .lines()
            .filter(|line| line.contains(" add "))
            .collect();
        assert!(
            prefix_calls
                .iter()
                .take_while(|line| !line.contains("198.51.100.9/32"))
                .count()
                == 1,
            "the unstable command was retried before the stable command: {calls}"
        );
    }

    #[tokio::test]
    async fn supersession_requests_replan_even_when_the_sampled_target_is_restored() {
        let fixture = superseding_fixture();
        let initial = ips(&["198.51.100.7", "198.51.100.9"]);
        let (wanted_tx, mut wanted_rx) = watch::channel(initial.clone());
        let cli = copy_cli(&fixture.cli);
        let db = fixture.db();
        let task = tokio::spawn(async move {
            live_round(&cli, &mut wanted_rx, &db, &Readback::default()).await
        });
        assert!(eventually(|| fixture.dir.join("bad_entered").exists()).await);
        update_wanted(&wanted_tx, ips(&["198.51.100.9"]));
        assert!(eventually(|| fixture.dir.join("fresh_entered").exists()).await);
        update_wanted(&wanted_tx, initial);
        std::fs::remove_file(fixture.dir.join("fresh_hold")).unwrap();
        let retry = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(retry, "a superseded prefix must be reconsidered even when latest intent equals the sampled target");
        assert!(fixture.dir.join("stable_done").exists());
    }

    #[tokio::test]
    async fn post_write_observation_keeps_sampled_target_and_requests_replan() {
        let fixture = RoundFixture::new("{}", RIB, false);
        // The write holds only its subsequent read, not the initial observation.
        let script = fixture.dir.join("gobgp");
        let text = std::fs::read_to_string(&script).unwrap();
        std::fs::write(
            &script,
            text.replace("touch applied ;;", "touch applied pause ;;"),
        )
        .unwrap();
        let (wanted_tx, mut wanted_rx) = watch::channel(ips(&["198.51.100.7"]));
        let readback = Arc::new(Readback::default());
        readback.enable();
        let view = readback.clone();
        let cli = copy_cli(&fixture.cli);
        let db = fixture.db();
        let task = tokio::spawn(async move { live_round(&cli, &mut wanted_rx, &db, &view).await });
        assert!(eventually(|| fixture.dir.join("entered").exists()).await);
        wanted_tx.send(HashSet::new()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let reads = fixture.reads();
        std::fs::remove_file(fixture.dir.join("pause")).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            "changed target must request replanning after the work pause"
        );
        let observation = readback.snapshot();
        assert!(
            observation.ok && observation.converged,
            "post-write RIB matches sampled target, though latest intent is empty"
        );
        assert_eq!(observation.count, 1);
        assert_eq!(reads, 3, "post-write read was cancelled by intent change");
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_paused_round_before_obsolete_announcement() {
        let fixture = RoundFixture::new("{}", "{}", false);
        std::fs::write(fixture.dir.join("pause"), "").unwrap();
        let readback = Arc::new(Readback::default());
        readback.enable();
        let (_wanted_tx, wanted_rx) = watch::channel(ips(&["198.51.100.7"]));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            readback.clone(),
        ));
        assert!(eventually(|| fixture.dir.join("entered").exists()).await);
        shutdown_tx.send(true).unwrap();
        let cleanup_started = eventually(|| fixture.reads() >= 2).await;
        std::fs::remove_file(fixture.dir.join("pause")).unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        assert!(
            !calls.contains(" add "),
            "shutdown announced an obsolete target: {calls}"
        );
        assert!(cleanup_started, "shutdown waited for the whole old round");
        assert!(readback.snapshot().ok && readback.snapshot().converged);
    }

    #[tokio::test]
    async fn identical_intent_ticks_do_not_interrupt_a_slow_round() {
        let fixture = RoundFixture::new("{}", RIB, false);
        std::fs::write(fixture.dir.join("pause"), "").unwrap();
        let target = ips(&["198.51.100.7"]);
        let (wanted_tx, wanted_rx) = watch::channel(target.clone());
        let witness = wanted_tx.subscribe();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let readback = Arc::new(Readback::default());
        readback.enable();
        let worker = tokio::spawn(run_worker(
            copy_cli(&fixture.cli),
            wanted_rx,
            shutdown_rx,
            Arc::new(fixture.db()),
            readback.clone(),
        ));
        assert!(eventually(|| fixture.dir.join("entered").exists()).await);
        for _ in 0..64 {
            assert!(!update_wanted(&wanted_tx, target.clone()));
            tokio::task::yield_now().await;
        }
        assert!(!witness.has_changed().unwrap());
        assert_eq!(fixture.reads(), 1);
        std::fs::remove_file(fixture.dir.join("pause")).unwrap();
        let recovered = eventually(|| readback.snapshot().converged).await;
        std::fs::write(fixture.dir.join("before.json"), "{}").unwrap();
        std::fs::write(fixture.dir.join("after.json"), "{}").unwrap();
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(
            recovered,
            "identical publications starved a successful round"
        );
        assert!(update_wanted(&wanted_tx, ips(&["198.51.100.8"])));
        assert!(
            witness.has_changed().unwrap(),
            "same count with other prefix must notify"
        );
    }

    #[tokio::test]
    async fn already_requested_shutdown_and_closed_publishers_start_cleanup() {
        for stop in ["already_shutdown", "intent_closed", "shutdown_closed"] {
            let fixture = RoundFixture::new(RIB, "{}", false);
            let (wanted_tx, wanted_rx) = watch::channel(ips(&["198.51.100.7"]));
            let (shutdown_tx, shutdown_rx) = watch::channel(stop == "already_shutdown");
            let mut wanted_tx = Some(wanted_tx);
            let mut shutdown_tx = Some(shutdown_tx);
            if stop == "intent_closed" {
                drop(wanted_tx.take());
            }
            if stop == "shutdown_closed" {
                drop(shutdown_tx.take());
            }
            let readback = Arc::new(Readback::default());
            readback.enable();
            tokio::time::timeout(
                Duration::from_secs(3),
                run_worker(
                    copy_cli(&fixture.cli),
                    wanted_rx,
                    shutdown_rx,
                    Arc::new(fixture.db()),
                    readback.clone(),
                ),
            )
            .await
            .expect("closed publishers must not spin or keep old intent");
            let view = readback.snapshot();
            assert!(view.ok && view.converged);
            assert_eq!(view.count, 0);
            assert!(std::fs::read_to_string(fixture.dir.join("calls"))
                .unwrap()
                .contains(" del "));
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
        assert!(old.enabled && old.ok && old.converged);
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
        assert!(failed.enabled && !failed.ok && !failed.converged);
        assert!(crate::metrics::render_with_flowspec(
            &crate::metrics::Snapshot::default(),
            &readback
        )
        .contains("sokol_flowspec_round_converged 0\n"));
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
        assert!(
            old.ok && old.converged,
            "revocation requires prior convergence"
        );
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
        assert!(!during.ok && !during.converged);
        assert!(crate::metrics::render_with_flowspec(
            &crate::metrics::Snapshot::default(),
            &readback
        )
        .contains("sokol_flowspec_round_converged 0\n"));
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
    async fn live_gobgp_work_budget_paces_success_and_cleanup_with_truthful_progress() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = Arc::new(live.fixture.db());
        for (net, latest, foreign_net) in [
            (
                one("198.51.100.7"),
                one("198.51.100.9"),
                one("198.51.100.8"),
            ),
            (one("2001:db8::7"), one("2001:db8::9"), one("2001:db8::8")),
        ] {
            live.put(foreign_net, "discard", "65001:9999").await;
            let foreign = live.raw(foreign_net).await;
            for (case, deleting, superseded, stop) in [
                ("add", false, false, "none"),
                ("delete", true, false, "none"),
                ("superseded_add", false, true, "none"),
                ("superseded_delete", true, true, "none"),
                ("shutdown", true, false, "shutdown"),
                ("intent_closed", true, false, "intent"),
                ("shutdown_closed", true, false, "closed"),
                ("cleanup", true, false, "cleanup"),
            ] {
                if deleting {
                    live.fixture.cli.apply(true, net).await.unwrap();
                }
                let before = live.fixture.cli.observed().await.unwrap().owned;
                let readback = Arc::new(Readback::default());
                readback.enable();
                checked_round(&live.fixture.cli, &before, &db, &readback)
                    .await
                    .unwrap();
                let dir = live
                    .fixture
                    .dir
                    .join(format!("budget-{}-{case}", family(&net)));
                std::fs::create_dir(&dir).unwrap();
                for file in ["calls", "no_effect"] {
                    std::fs::write(dir.join(file), "").unwrap();
                }
                if superseded {
                    std::fs::write(dir.join("post_hold"), "").unwrap();
                }
                let wrapper = dir.join("cli.sh");
                std::fs::write(
                    &wrapper,
                    r#"#!/bin/sh
real="$1"; dir="$2"; shift 2
printf '%s\n' "$*" >> "$dir/calls"
case "$*" in
  *' add '*|*' del '*) if [ -f "$dir/no_effect" ]; then exit 0; fi ;;
  *'ipv6-flowspec -j')
    n=0; if [ -f "$dir/reads" ]; then n=$(cat "$dir/reads"); fi
    n=$((n + 1)); printf '%s\n' "$n" > "$dir/reads"
    if [ "$n" = 2 ] && [ -f "$dir/post_hold" ]; then
      touch "$dir/post_entered"
      while [ -f "$dir/post_hold" ]; do sleep 0.01; done
    fi ;;
esac
exec "$real" "$@"
"#,
                )
                .unwrap();
                let mut args = vec![
                    wrapper.to_str().unwrap().into(),
                    live.fixture.cli.bin.to_str().unwrap().into(),
                    dir.to_str().unwrap().into(),
                ];
                args.extend(live.fixture.cli.args.clone());
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args,
                    community: live.fixture.cli.community,
                };
                let target = if deleting {
                    HashSet::new()
                } else {
                    HashSet::from([net])
                };
                let (wanted_tx, wanted_rx) = watch::channel(target.clone());
                let (shutdown_tx, shutdown_rx) = watch::channel(stop == "cleanup");
                let mut wanted_tx = Some(wanted_tx);
                let mut shutdown_tx = Some(shutdown_tx);
                let worker = tokio::spawn(run_worker(
                    cli,
                    wanted_rx,
                    shutdown_rx,
                    db.clone(),
                    readback.clone(),
                ));
                let final_target = if superseded {
                    HashSet::from([latest])
                } else {
                    target.clone()
                };
                if superseded {
                    assert!(eventually(|| dir.join("post_entered").exists()).await);
                    wanted_tx
                        .as_ref()
                        .unwrap()
                        .send(final_target.clone())
                        .unwrap();
                    std::fs::remove_file(dir.join("post_hold")).unwrap();
                }
                let writes = || {
                    std::fs::read_to_string(dir.join("calls"))
                        .unwrap()
                        .lines()
                        .filter(|l| l.contains(" add ") || l.contains(" del "))
                        .count()
                };
                assert!(eventually(|| readback.snapshot().ok && writes() > 0).await);
                let first = readback.snapshot();
                assert!(
                    !first.converged && first.progress == Some(false),
                    "{case}: no-effect calls became progress or convergence"
                );
                assert!(crate::metrics::render_with_flowspec(
                    &crate::metrics::Snapshot::default(),
                    &readback
                )
                .contains("sokol_flowspec_round_progress 0\n"));
                let completed = Instant::now();
                if stop == "none" {
                    // Genuine target churn and false stop notifications cannot buy more work.
                    for i in 0..10 {
                        wanted_tx
                            .as_ref()
                            .unwrap()
                            .send(if i % 2 == 0 {
                                HashSet::from([latest])
                            } else {
                                final_target.clone()
                            })
                            .unwrap();
                        shutdown_tx.as_ref().unwrap().send(false).unwrap();
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    assert_eq!(
                        writes(),
                        1,
                        "{case}: successful round bypassed normal work pause"
                    );
                    while completed.elapsed() < Duration::from_millis(1900) && writes() < 2 {
                        wanted_tx
                            .as_ref()
                            .unwrap()
                            .send(final_target.clone())
                            .unwrap();
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    assert!(
                        writes() >= 2 && completed.elapsed() >= Duration::from_millis(900),
                        "{case}: early or starved retry"
                    );
                    std::fs::remove_file(dir.join("no_effect")).unwrap();
                    assert!(
                        eventually(|| {
                            let v = readback.snapshot();
                            v.ok && v.converged && v.progress == Some(true)
                        })
                        .await,
                        "{case}: effectful recovery not observed"
                    );
                    let actual = live.fixture.cli.observed().await.unwrap();
                    assert_eq!(actual.owned, final_target, "{case}: wrong actual owned set");
                    assert_eq!(
                        actual.discard, final_target,
                        "{case}: wrong actual discard set"
                    );
                    let recovered = readback.snapshot();
                    assert!(recovered.started.unwrap() > first.started.unwrap());
                    shutdown_tx.as_ref().unwrap().send(true).unwrap();
                } else if stop == "cleanup" {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    assert_eq!(writes(), 1, "successful cleanup bypassed its work pause");
                    assert!(eventually(|| writes() >= 2).await);
                    std::fs::remove_file(dir.join("no_effect")).unwrap();
                } else {
                    // Fault removal permits cleanup; interruption must bypass normal work pause.
                    std::fs::remove_file(dir.join("no_effect")).unwrap();
                    match stop {
                        "shutdown" => shutdown_tx.as_ref().unwrap().send(true).unwrap(),
                        "intent" => drop(wanted_tx.take()),
                        "closed" => drop(shutdown_tx.take()),
                        _ => unreachable!(),
                    }
                    let finished = tokio::time::timeout(Duration::from_millis(750), worker).await;
                    assert!(finished.is_ok(), "{case}: cleanup waited for normal pause");
                    finished.unwrap().unwrap();
                    let v = readback.snapshot();
                    assert!(v.ok && v.converged && v.progress == Some(true));
                    assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                    assert_eq!(
                        live.raw(foreign_net).await,
                        foreign,
                        "{case}: foreign path changed"
                    );
                    continue;
                }
                tokio::time::timeout(Duration::from_secs(3), worker)
                    .await
                    .unwrap()
                    .unwrap();
                let v = readback.snapshot();
                assert!(v.ok && v.converged);
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "{case}: foreign path changed"
                );
            }
            writeln!(std::io::stdout(), "PASS live work budget {}: successful no-effect add/delete and supersession paced, measured progress after real recovery, cleanup paced, stop and both closures preempt normal pause, foreign paths preserved", family(&net)).unwrap();
        }
    }

    #[tokio::test]
    async fn live_gobgp_worker_preempts_intent_and_recovers_unknown_writes() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        // Keep one actual audit writer across cases; reopening while its previous
        // detached thread drains could otherwise race appends on the same file.
        let db = Arc::new(live.fixture.db());
        for (net, foreign_net) in [
            (one("198.51.100.7"), one("198.51.100.8")),
            (one("2001:db8::7"), one("2001:db8::8")),
        ] {
            live.put(foreign_net, "discard", "65001:9999").await;
            let foreign = live.raw(foreign_net).await;
            for (case, present, hold_op, stop) in [
                ("revoked_add", false, "read", false),
                ("restored_delete", true, "read", false),
                ("accepted_add", false, "add", false),
                ("accepted_delete", true, "del", false),
                ("shutdown", false, "read", true),
                ("accepted_add_shutdown", false, "add", true),
            ] {
                if present {
                    live.fixture.cli.apply(true, net).await.unwrap();
                }
                let dir = live.fixture.dir.join(format!("{}-{case}", family(&net)));
                std::fs::create_dir(&dir).unwrap();
                let hold = dir.join("hold");
                let entered = dir.join("entered");
                let calls_file = dir.join("calls");
                std::fs::write(&hold, "").unwrap();
                std::fs::write(&calls_file, "").unwrap();
                let wrapper = dir.join("cli.sh");
                std::fs::write(
                    &wrapper,
                    r#"#!/bin/sh
real="$1"; dir="$2"; hold_op="$3"; shift 3
printf '%s\n' "$*" >> "$dir/calls"
op=read
case "$*" in *' add '*) op=add ;; *' del '*) op=del ;; esac
if [ "$op" = "$hold_op" ] && [ -f "$dir/hold" ]; then
  # Write effects occur in real GoBGP before the wrapper withholds its response.
  if [ "$op" != read ]; then "$real" "$@" || exit $?; fi
  touch "$dir/entered"
  while [ -f "$dir/hold" ]; do sleep 0.01; done
  if [ "$op" != read ]; then exit 0; fi
fi
exec "$real" "$@"
"#,
                )
                .unwrap();
                let mut args = vec![
                    wrapper.to_str().unwrap().to_string(),
                    live.fixture.cli.bin.to_str().unwrap().to_string(),
                    dir.to_str().unwrap().to_string(),
                    hold_op.to_string(),
                ];
                args.extend(live.fixture.cli.args.clone());
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args,
                    community: live.fixture.cli.community,
                };
                let before = if present {
                    HashSet::from([net])
                } else {
                    HashSet::new()
                };
                let initial = if present {
                    HashSet::new()
                } else {
                    HashSet::from([net])
                };
                let readback = Arc::new(Readback::default());
                readback.enable();
                checked_round(&live.fixture.cli, &before, &db, &readback)
                    .await
                    .unwrap();
                let old = readback.snapshot();
                assert!(old.ok && old.converged);
                let (wanted_tx, wanted_rx) = watch::channel(initial);
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let worker = tokio::spawn(run_worker(
                    cli,
                    wanted_rx,
                    shutdown_rx,
                    db.clone(),
                    readback.clone(),
                ));
                assert!(eventually(|| entered.exists()).await);
                let pending = readback.snapshot();
                assert!(!pending.ok && !pending.converged);
                assert_eq!(pending.count, old.count);
                assert_eq!(pending.started, old.started);
                // Independently observe the already-committed effect before cancelling its reply.
                if hold_op != "read" {
                    let actual = live.fixture.cli.observed().await.unwrap();
                    let effected = if present {
                        HashSet::new()
                    } else {
                        HashSet::from([net])
                    };
                    assert_eq!(actual.owned, effected);
                    assert_eq!(actual.discard, effected);
                }
                let reads = || {
                    std::fs::read_to_string(&calls_file)
                        .unwrap()
                        .lines()
                        .filter(|line| line.ends_with(" -j"))
                        .count()
                };
                let old_reads = reads();
                if stop {
                    shutdown_tx.send(true).unwrap();
                } else {
                    assert!(update_wanted(&wanted_tx, before.clone()));
                }
                let restarted = if stop || hold_op != "read" {
                    eventually(|| reads() > old_reads).await
                } else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    reads() == old_reads
                };
                std::fs::remove_file(&hold).unwrap();
                let recovered = eventually(|| {
                    let view = readback.snapshot();
                    view.ok && view.converged && view.count == before.len()
                })
                .await;
                let calls = std::fs::read_to_string(&calls_file).unwrap();
                if !stop {
                    shutdown_tx.send(true).unwrap();
                }
                tokio::time::timeout(Duration::from_secs(3), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    restarted && recovered,
                    "{case}: no preemption/recovery: {calls}"
                );
                let writes: Vec<_> = calls
                    .lines()
                    .filter(|line| line.contains(" add ") || line.contains(" del "))
                    .collect();
                if hold_op == "read" {
                    assert!(writes.is_empty(), "obsolete {case} write: {calls}");
                } else {
                    assert_eq!(writes.len(), 2, "unknown write must be reconciled: {calls}");
                    assert!(writes[0].contains(&format!(" {hold_op} ")));
                    let reverse = if hold_op == "add" { "del" } else { "add" };
                    assert!(writes[1].contains(&format!(" {reverse} ")));
                }
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "{case}: foreign RIB changed"
                );
            }
            writeln!(std::io::stdout(), "PASS live intent preemption {}: obsolete add/delete refused, accepted unknown writes reconciled, shutdown starts cleanup, foreign path preserved", family(&net)).unwrap();
        }
    }

    #[tokio::test]
    async fn live_gobgp_worker_retains_useful_reads_and_valid_writes_under_intent_changes() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = Arc::new(live.fixture.db());
        for (net, foreign_net, other) in [
            (
                one("198.51.100.7"),
                one("198.51.100.8"),
                one("198.51.100.9"),
            ),
            (one("2001:db8::7"), one("2001:db8::8"), one("2001:db8::9")),
        ] {
            live.put(foreign_net, "discard", "65001:9999").await;
            let foreign = live.raw(foreign_net).await;
            for (case, hold_op, queued) in [
                ("read", "read", false),
                ("compatible_add", "add", false),
                ("compatible_delete", "del", false),
                ("queued_add_revoked", "add", true),
                ("queued_delete_restored", "del", true),
                ("post_write_read", "post_read", false),
            ] {
                let deleting = hold_op == "del";
                if deleting {
                    live.fixture.cli.apply(true, net).await.unwrap();
                    if queued {
                        live.fixture.cli.apply(true, other).await.unwrap();
                    }
                }
                let initial = if deleting || case == "read" {
                    HashSet::new()
                } else if queued {
                    HashSet::from([net, other])
                } else {
                    HashSet::from([net])
                };
                let latest = if case == "post_write_read" || deleting && !queued {
                    HashSet::new()
                } else if deleting {
                    HashSet::from([other])
                } else {
                    HashSet::from([net])
                };
                let dir = live
                    .fixture
                    .dir
                    .join(format!("progress-{}-{case}", family(&net)));
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("hold"), "").unwrap();
                std::fs::write(dir.join("calls"), "").unwrap();
                let wrapper = dir.join("cli.sh");
                std::fs::write(&wrapper, r#"#!/bin/sh
real="$1"; dir="$2"; hold_op="$3"; shift 3
printf '%s\n' "$*" >> "$dir/calls"
op=read
case "$*" in *' add '*) op=add ;; *' del '*) op=del ;; esac
if { [ "$op" = "$hold_op" ] || { [ "$hold_op" = post_read ] && [ "$op" = read ] && [ -f "$dir/written" ]; }; } && [ -f "$dir/hold" ]; then
  if [ "$op" != read ]; then "$real" "$@" || exit $?; fi
  touch "$dir/entered"
  while [ -f "$dir/hold" ]; do sleep 0.01; done
  touch "$dir/completed"
  if [ "$op" != read ]; then exit 0; fi
fi
if [ "$op" != read ]; then touch "$dir/written"; fi
exec "$real" "$@"
"#).unwrap();
                let mut args = vec![
                    wrapper.to_str().unwrap().into(),
                    live.fixture.cli.bin.to_str().unwrap().into(),
                    dir.to_str().unwrap().into(),
                    hold_op.into(),
                ];
                args.extend(live.fixture.cli.args.clone());
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args,
                    community: live.fixture.cli.community,
                };
                let (wanted_tx, wanted_rx) = watch::channel(initial.clone());
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let readback = Arc::new(Readback::default());
                let worker = tokio::spawn(run_worker(
                    cli,
                    wanted_rx,
                    shutdown_rx,
                    db.clone(),
                    readback.clone(),
                ));
                assert!(eventually(|| dir.join("entered").exists()).await);
                let pending_calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                if hold_op != "read" {
                    let actual = live.fixture.cli.observed().await.unwrap();
                    assert_eq!(actual.owned.contains(&net), !deleting);
                }
                for i in 0..12 {
                    let mut target = initial.clone();
                    if i % 2 == 0 {
                        target.insert(other);
                    } else {
                        target.remove(&other);
                    }
                    update_wanted(&wanted_tx, target);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                update_wanted(&wanted_tx, latest.clone());
                tokio::time::sleep(Duration::from_millis(50)).await;
                let retained_calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                std::fs::remove_file(dir.join("hold")).unwrap();
                let recovered = eventually(|| {
                    let view = readback.snapshot();
                    view.ok && view.converged && view.count == latest.len()
                })
                .await;
                let completed = dir.join("completed").exists();
                let calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                let actual = live.fixture.cli.observed().await.unwrap();
                shutdown_tx.send(true).unwrap();
                tokio::time::timeout(Duration::from_secs(3), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    retained_calls, pending_calls,
                    "{case}: compatible changes restarted useful work"
                );
                assert!(completed && recovered, "{case}: original future did not finish or latest intent did not recover: {calls}");
                assert_eq!(actual.owned, latest);
                assert_eq!(actual.discard, latest);
                let writes: Vec<_> = calls
                    .lines()
                    .filter(|line| line.contains(" add ") || line.contains(" del "))
                    .collect();
                assert_eq!(
                    writes.len(),
                    if case == "post_write_read" { 2 } else { 1 },
                    "{case}: duplicate or obsolete command: {calls}"
                );
                if case == "read" {
                    let first_write = calls
                        .lines()
                        .position(|line| line.contains(" add "))
                        .unwrap();
                    assert_eq!(first_write, 2, "latest target must be planned directly from the retained two-family read: {calls}");
                }
                if queued {
                    assert!(
                        writes.iter().all(|line| !line.contains(&other.to_string())),
                        "{case}: obsolete queued operation: {calls}"
                    );
                }
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "{case}: foreign RIB changed"
                );
            }
            writeln!(std::io::stdout(), "PASS live intent progress {}: initial/post-write reads retained, compatible add/delete retained once, obsolete queued writes refused, latest target recovered, foreign path preserved", family(&net)).unwrap();
        }
    }

    #[tokio::test]
    async fn live_gobgp_quota_rotation_serves_tails_and_revalidates_new_plans() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = live.fixture.db();
        for ipv6 in [false, true] {
            let nets = quota_nets(ipv6);
            let tail = *nets.last().unwrap();
            let foreign_net = one(if ipv6 {
                "2001:db8:ffff::1"
            } else {
                "203.0.113.254"
            });
            live.put(foreign_net, "discard", "65001:9999").await;
            let original_foreign = live.raw(foreign_net).await;
            for (case, deleting, failing, fixed) in [
                ("no_effect_add", false, false, false),
                ("no_effect_delete", true, false, false),
                ("failed_add", false, true, false),
                ("failed_delete", true, true, false),
                ("fixed_failed_delete", true, true, true),
                ("fresh_foreign_tail", false, false, false),
                ("obsolete_tail_add", false, false, false),
                ("obsolete_tail_delete", true, false, false),
            ] {
                if deleting {
                    for net in &nets {
                        live.fixture.cli.apply(true, *net).await.unwrap();
                    }
                }
                let dir = live
                    .fixture
                    .dir
                    .join(format!("quota-{}-{case}", family(&tail)));
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("blocked"), "").unwrap();
                if failing {
                    std::fs::write(dir.join("error"), "").unwrap();
                }
                let script = dir.join("cli.sh");
                std::fs::write(
                    &script,
                    r#"#!/bin/sh
real="$1"; dir="$2"; tail="$3"; shift 3
printf '%s\n' "$*" >> "$dir/calls"
case "$*" in
  *' add '*|*' del '*)
    case "$*" in *" source $tail "*) ;; *)
      if [ -f "$dir/blocked" ]; then
        if [ -f "$dir/error" ]; then exit 7; fi
        exit 0
      fi ;;
    esac ;;
esac
exec "$real" "$@"
"#,
                )
                .unwrap();
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args: [
                        vec![
                            script.to_str().unwrap().into(),
                            live.fixture.cli.bin.to_str().unwrap().into(),
                            dir.to_str().unwrap().into(),
                            tail.to_string(),
                        ],
                        live.fixture.cli.args.clone(),
                    ]
                    .concat(),
                    community: live.fixture.cli.community,
                };
                let before = live.fixture.cli.observed().await.unwrap().owned;
                let readback = Readback::default();
                readback.enable();
                checked_round(&live.fixture.cli, &before, &db, &readback)
                    .await
                    .unwrap();
                let mut target = if deleting {
                    HashSet::new()
                } else {
                    nets.iter().copied().collect()
                };
                let (wanted_tx, mut wanted_rx) = watch::channel(target.clone());
                let mut cursor = PlanCursor::default();
                for round_index in 0..2 {
                    let previous = readback.snapshot();
                    let failed = if fixed {
                        checked_round_with_cursor(&cli, &target, &db, &readback, &mut cursor)
                            .await
                            .is_err()
                    } else {
                        live_round_with_cursor(&cli, &mut wanted_rx, &db, &readback, &mut cursor)
                            .await
                            .is_err()
                    };
                    assert_eq!(
                        failed,
                        failing || (case == "fresh_foreign_tail" && round_index == 1),
                        "{case} round {round_index}"
                    );
                    let view = readback.snapshot();
                    assert!(
                        !view.converged,
                        "partial progress must not certify the whole target"
                    );
                    if failed {
                        assert!(!view.ok);
                        assert_eq!(view.count, previous.count);
                        assert_eq!(view.discard_count, previous.discard_count);
                        assert_eq!(view.started, previous.started);
                    } else {
                        assert!(view.ok);
                    }
                    if round_index == 0 {
                        let calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                        let writes: Vec<_> = calls
                            .lines()
                            .filter(|l| l.contains(" add ") || l.contains(" del "))
                            .collect();
                        assert_eq!(writes.len(), MAX_OPS_PER_ROUND);
                        assert!(!writes
                            .iter()
                            .any(|l| l.contains(&format!(" source {tail} "))));
                        if case == "fresh_foreign_tail" {
                            live.put(tail, "discard", "65001:9999").await;
                        } else if case.starts_with("obsolete_tail") {
                            if deleting {
                                target.insert(tail);
                            } else {
                                target.remove(&tail);
                            }
                            wanted_tx.send(target.clone()).unwrap();
                        }
                    }
                }
                let calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                let writes: Vec<_> = calls
                    .lines()
                    .filter(|l| l.contains(" add ") || l.contains(" del "))
                    .collect();
                assert_eq!(writes.len(), 2 * MAX_OPS_PER_ROUND);
                for round_writes in writes.chunks(MAX_OPS_PER_ROUND) {
                    let unique: HashSet<_> = round_writes.iter().copied().collect();
                    assert_eq!(
                        unique.len(),
                        MAX_OPS_PER_ROUND,
                        "{case}: duplicate command inside a plan"
                    );
                }
                let refused_tail =
                    case == "fresh_foreign_tail" || case.starts_with("obsolete_tail");
                if refused_tail {
                    assert!(
                        !writes
                            .iter()
                            .any(|l| l.contains(&format!(" source {tail} "))),
                        "{case}: rotated plan bypassed current authority"
                    );
                } else {
                    assert!(
                        writes[MAX_OPS_PER_ROUND].contains(&format!(" source {tail} ")),
                        "{case}: tail not first in second plan"
                    );
                    assert_eq!(
                        writes
                            .iter()
                            .filter(|l| l.contains(&format!(" source {tail} ")))
                            .count(),
                        1
                    );
                }
                let actual = live.fixture.cli.observed().await.unwrap();
                let mut expected: HashSet<_> = if deleting {
                    nets.iter().copied().collect()
                } else {
                    HashSet::new()
                };
                if !refused_tail {
                    if deleting {
                        expected.remove(&tail);
                    } else {
                        expected.insert(tail);
                    }
                }
                assert_eq!(actual.owned, expected, "{case}: actual owned effect");
                assert_eq!(actual.discard, expected, "{case}: actual discard effect");
                assert!(actual.foreign_local.contains(&foreign_net));
                let foreign = if case == "fresh_foreign_tail" {
                    assert!(actual.foreign_local.contains(&tail));
                    live.raw(foreign_net).await
                } else {
                    original_foreign.clone()
                };
                // Independent real CLI cleanup: blocked prefixes are fixture faults,
                // not evidence that a bounded worker can always withdraw them.
                for _ in 0..2 {
                    checked_round(&live.fixture.cli, &HashSet::new(), &db, &readback)
                        .await
                        .unwrap();
                }
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "{case}: foreign path changed"
                );
                if case == "fresh_foreign_tail" {
                    // The test's daemon owner removes its injected foreign fixture.
                    live.fixture.cli.apply(false, tail).await.unwrap();
                    assert_eq!(live.raw(foreign_net).await, original_foreign);
                }
            }
            writeln!(std::io::stdout(), "PASS live quota progress {}: 65th add/delete served after no-effect or failed calls, fixed cleanup cursor retained, obsolete and foreign tails refused, truthful readback and foreign paths preserved", family(&tail)).unwrap();
        }
    }

    #[tokio::test]
    async fn live_gobgp_retry_pause_keeps_latest_intent_and_preempts_for_cleanup() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = Arc::new(live.fixture.db());
        for (obsolete, latest, foreign_net) in [
            (
                one("198.51.100.7"),
                one("198.51.100.9"),
                one("198.51.100.8"),
            ),
            (one("2001:db8::7"), one("2001:db8::9"), one("2001:db8::8")),
        ] {
            live.put(foreign_net, "discard", "65001:9999").await;
            let foreign = live.raw(foreign_net).await;
            for case in [
                "timer_and_churn",
                "shutdown",
                "shutdown_closed",
                "intent_closed",
            ] {
                let stopping_case = case != "timer_and_churn";
                if stopping_case {
                    live.fixture.cli.apply(true, latest).await.unwrap();
                }
                let dir = live
                    .fixture
                    .dir
                    .join(format!("retry-{}-{case}", family(&obsolete)));
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("hold"), "").unwrap();
                std::fs::write(dir.join("fail"), "").unwrap();
                let wrapper = dir.join("cli.sh");
                std::fs::write(
                    &wrapper,
                    r#"#!/bin/sh
real="$1"; dir="$2"; shift 2
printf '%s\n' "$*" >> "$dir/calls"
if [ -f "$dir/fail" ]; then
  touch "$dir/entered"
  while [ -f "$dir/hold" ]; do sleep 0.01; done
  touch "$dir/failed"
  printf 'controlled RIB refusal\n' >&2
  exit 7
fi
exec "$real" "$@"
"#,
                )
                .unwrap();
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args: [
                        vec![
                            wrapper.to_str().unwrap().into(),
                            live.fixture.cli.bin.to_str().unwrap().into(),
                            dir.to_str().unwrap().into(),
                        ],
                        live.fixture.cli.args.clone(),
                    ]
                    .concat(),
                    community: live.fixture.cli.community,
                };
                let readback = Arc::new(Readback::default());
                readback.enable();
                let before = live.fixture.cli.observed().await.unwrap().owned;
                checked_round(&live.fixture.cli, &before, &db, &readback)
                    .await
                    .unwrap();
                let old = readback.snapshot();
                let (wanted_tx, wanted_rx) = watch::channel(HashSet::from([obsolete]));
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let worker = tokio::spawn(run_worker(
                    cli,
                    wanted_rx,
                    shutdown_rx,
                    db.clone(),
                    readback.clone(),
                ));
                assert!(eventually(|| dir.join("entered").exists()).await);
                // Accumulate a real overdue periodic tick without timing out a CLI call.
                if !stopping_case {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
                std::fs::remove_file(dir.join("hold")).unwrap();
                assert!(eventually(|| dir.join("failed").exists()).await);
                let completed = Instant::now();
                // Allow ordinary child teardown before sampling pending/failed health.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let failed = readback.snapshot();
                assert!(!failed.ok && !failed.converged);
                assert_eq!(failed.count, old.count);
                assert_eq!(failed.discard_count, old.discard_count);
                assert_eq!(failed.started, old.started);
                std::fs::remove_file(dir.join("fail")).unwrap();
                if !stopping_case {
                    for i in 0..10 {
                        wanted_tx
                            .send(if i % 2 == 0 {
                                HashSet::from([latest])
                            } else {
                                HashSet::new()
                            })
                            .unwrap();
                        shutdown_tx.send(false).unwrap();
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    wanted_tx.send(HashSet::from([latest])).unwrap();
                    let early = std::fs::read_to_string(dir.join("calls")).unwrap();
                    assert_eq!(
                        early.lines().count(),
                        1,
                        "failed round bypassed pause: {early}"
                    );
                    assert!(
                        eventually(|| readback.snapshot().ok && readback.snapshot().converged)
                            .await
                    );
                    assert!(completed.elapsed() >= Duration::from_millis(900));
                    let observed = live.fixture.cli.observed().await.unwrap();
                    assert_eq!(observed.owned, HashSet::from([latest]));
                    assert_eq!(observed.discard, HashSet::from([latest]));
                    let calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                    assert!(
                        !calls
                            .lines()
                            .any(|l| l.contains(" add ") && l.contains(&obsolete.to_string())),
                        "obsolete intent used after pause: {calls}"
                    );
                    shutdown_tx.send(true).unwrap();
                    tokio::time::timeout(Duration::from_secs(3), worker)
                        .await
                        .unwrap()
                        .unwrap();
                } else {
                    let stop_started = Instant::now();
                    match case {
                        "shutdown" => {
                            shutdown_tx.send(true).unwrap();
                        }
                        "shutdown_closed" => drop(shutdown_tx),
                        "intent_closed" => drop(wanted_tx),
                        _ => unreachable!(),
                    }
                    tokio::time::timeout(Duration::from_millis(750), worker)
                        .await
                        .expect("cleanup waited for the normal retry pause")
                        .unwrap();
                    assert!(stop_started.elapsed() < Duration::from_millis(750));
                }
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "foreign path changed in {case}"
                );
            }
            writeln!(std::io::stdout(), "PASS live retry pacing {}: overdue ticks and intent churn wait, latest intent recovered, shutdown and both publisher closures clean up without waiting, foreign path preserved", family(&obsolete)).unwrap();
        }
    }

    #[tokio::test]
    async fn live_gobgp_failed_commands_preserve_safe_queued_work_and_refusals() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = Arc::new(live.fixture.db());
        for (bad, foreign_net, stable, extra) in [
            (
                one("198.51.100.7"),
                one("198.51.100.8"),
                one("198.51.100.9"),
                one("198.51.100.10"),
            ),
            (
                one("2001:db8::7"),
                one("2001:db8::8"),
                one("2001:db8::9"),
                one("2001:db8::10"),
            ),
        ] {
            live.put(foreign_net, "discard", "65001:9999").await;
            for (case, deleting) in [
                ("no_effect_add", false),
                ("no_effect_delete", true),
                ("cleanup_delete", true),
                ("accepted_add", false),
                ("accepted_delete", true),
                ("new_collision", false),
                ("satisfied_queue", false),
                ("unreadable_refresh", false),
                ("malformed_refresh", false),
                ("obsolete_queued_add", false),
                ("obsolete_queued_delete", true),
            ] {
                let mut foreign = live.raw(foreign_net).await;
                if deleting {
                    live.fixture.cli.apply(true, bad).await.unwrap();
                    live.fixture.cli.apply(true, stable).await.unwrap();
                }
                let before = live.fixture.cli.observed().await.unwrap().owned;
                let mut target = if deleting {
                    HashSet::new()
                } else {
                    HashSet::from([bad, stable])
                };
                if case == "new_collision" {
                    target.insert(extra);
                }
                let readback = Arc::new(Readback::default());
                readback.enable();
                checked_round(&live.fixture.cli, &before, &db, &readback)
                    .await
                    .unwrap();
                let old = readback.snapshot();
                let dir = live
                    .fixture
                    .dir
                    .join(format!("failed-{}-{case}", family(&bad)));
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("fresh_hold"), "").unwrap();
                std::fs::write(dir.join("calls"), "").unwrap();
                if case.starts_with("accepted_") {
                    std::fs::write(dir.join("accepted"), "").unwrap();
                }
                let wrapper = dir.join("cli.sh");
                std::fs::write(
                    &wrapper,
                    r#"#!/bin/sh
real="$1"; dir="$2"; bad="$3"; bad_op="$4"; shift 4
printf '%s\n' "$*" >> "$dir/calls"
op=read
case "$*" in *' add '*) op=add ;; *' del '*) op=del ;; esac
case "$*" in *" source $bad "*)
  if [ "$op" = "$bad_op" ]; then
    if [ -f "$dir/accepted" ]; then "$real" "$@" || exit 9; fi
    touch "$dir/failed"
    printf 'isolated command failure\n' >&2
    exit 7
  fi ;;
esac
if [ "$op" = read ] && [ -f "$dir/failed" ] && [ ! -f "$dir/fresh_entered" ]; then
  touch "$dir/fresh_entered"
  while [ -f "$dir/fresh_hold" ]; do sleep 0.01; done
  if [ -f "$dir/read_fail" ]; then printf '{}\n'; exit 7; fi
  if [ -f "$dir/read_malformed" ]; then printf 'null\n'; exit 0; fi
fi
exec "$real" "$@"
"#,
                )
                .unwrap();
                let mut args = vec![
                    wrapper.to_str().unwrap().into(),
                    live.fixture.cli.bin.to_str().unwrap().into(),
                    dir.to_str().unwrap().into(),
                    bad.to_string(),
                    if deleting { "del" } else { "add" }.into(),
                ];
                args.extend(live.fixture.cli.args.clone());
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args,
                    community: live.fixture.cli.community,
                };
                let (wanted_tx, mut wanted_rx) = watch::channel(target.clone());
                let task_db = db.clone();
                let task_readback = readback.clone();
                let task = tokio::spawn(async move {
                    if case == "cleanup_delete" {
                        checked_round(&cli, &HashSet::new(), &task_db, &task_readback)
                            .await
                            .map(|_| false)
                    } else {
                        live_round(&cli, &mut wanted_rx, &task_db, &task_readback).await
                    }
                });
                assert!(
                    eventually(|| dir.join("fresh_entered").exists()).await,
                    "{case}: failed call abandoned the cohort without recovery read"
                );
                if case == "new_collision" {
                    live.put(stable, "discard", "65001:9999").await;
                    foreign = live.raw(foreign_net).await;
                } else if case == "satisfied_queue" {
                    live.fixture.cli.apply(true, stable).await.unwrap();
                } else if case == "unreadable_refresh" {
                    std::fs::write(dir.join("read_fail"), "").unwrap();
                } else if case == "malformed_refresh" {
                    std::fs::write(dir.join("read_malformed"), "").unwrap();
                } else if case == "obsolete_queued_add" {
                    target.remove(&stable);
                    update_wanted(&wanted_tx, target.clone());
                } else if case == "obsolete_queued_delete" {
                    target.insert(stable);
                    update_wanted(&wanted_tx, target.clone());
                }
                std::fs::remove_file(dir.join("fresh_hold")).unwrap();
                let result = tokio::time::timeout(Duration::from_secs(3), task)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    result.is_err(),
                    "{case}: failed command was published as a successful round"
                );
                let view = readback.snapshot();
                assert!(
                    !view.ok && !view.converged,
                    "{case}: failed round published health"
                );
                assert_eq!(
                    view.count, old.count,
                    "{case}: failure changed published count"
                );
                assert_eq!(view.discard_count, old.discard_count);
                assert_eq!(view.started, old.started);
                let calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                let lines: Vec<_> = calls.lines().collect();
                let writes: Vec<_> = lines
                    .iter()
                    .filter(|l| l.contains(" add ") || l.contains(" del "))
                    .collect();
                assert!(writes[0].contains(&format!(" source {bad} ")));
                let refusal = matches!(
                    case,
                    "satisfied_queue"
                        | "unreadable_refresh"
                        | "malformed_refresh"
                        | "obsolete_queued_add"
                        | "obsolete_queued_delete"
                );
                if refusal {
                    assert_eq!(
                        writes.len(),
                        1,
                        "{case}: queued write must be refused: {calls}"
                    );
                } else {
                    let next = if case == "new_collision" {
                        extra
                    } else {
                        stable
                    };
                    assert_eq!(
                        writes.len(),
                        2,
                        "{case}: finite original queue must continue once: {calls}"
                    );
                    assert!(writes[1].contains(&format!(" source {next} ")));
                    let first_index = lines
                        .iter()
                        .position(|l| l.contains(&format!(" source {bad} ")))
                        .unwrap();
                    let next_index = lines
                        .iter()
                        .position(|l| l.contains(&format!(" source {next} ")))
                        .unwrap();
                    let reads: Vec<_> = lines[first_index + 1..next_index]
                        .iter()
                        .filter(|l| l.ends_with(" -j"))
                        .collect();
                    assert_eq!(
                        reads.len(),
                        2,
                        "{case}: queued write lacked a full recovery read: {calls}"
                    );
                    assert!(
                        reads[0].contains("ipv4-flowspec") && reads[1].contains("ipv6-flowspec")
                    );
                }
                let actual = live.fixture.cli.observed().await.unwrap();
                let expected = if deleting {
                    if case == "accepted_delete" {
                        HashSet::new()
                    } else if case == "obsolete_queued_delete" {
                        HashSet::from([bad, stable])
                    } else {
                        HashSet::from([bad])
                    }
                } else if matches!(
                    case,
                    "unreadable_refresh" | "malformed_refresh" | "obsolete_queued_add"
                ) {
                    HashSet::new()
                } else if case == "new_collision" {
                    HashSet::from([extra])
                } else if case == "accepted_add" {
                    HashSet::from([bad, stable])
                } else {
                    HashSet::from([stable])
                };
                assert_eq!(actual.owned, expected, "{case}: wrong actual owned RIB");
                assert_eq!(actual.discard, expected, "{case}: wrong actual discard RIB");
                assert!(actual.foreign_local.contains(&foreign_net));
                if case == "new_collision" {
                    assert!(actual.foreign_local.contains(&stable));
                }
                // A separate successful round on the real CLI can publish recovery.
                // For collisions, recover only the noncolliding subset before cleanup.
                let recovery_target = if case == "new_collision" {
                    HashSet::from([bad, extra])
                } else {
                    target
                };
                checked_round(&live.fixture.cli, &recovery_target, &db, &readback)
                    .await
                    .unwrap();
                assert!(readback.snapshot().ok && readback.snapshot().converged);
                assert_eq!(readback.snapshot().count, recovery_target.len());
                assert!(readback.snapshot().started.unwrap() > old.started.unwrap());
                checked_round(&live.fixture.cli, &HashSet::new(), &db, &readback)
                    .await
                    .unwrap();
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "{case}: cleanup changed foreign paths"
                );
                if case == "new_collision" {
                    let mut args = live.fixture.cli.command_args(false, stable);
                    let last = args.len() - 1;
                    args[last] = "65001:9999".into();
                    live.fixture.cli.run(args).await.unwrap();
                }
            }
            writeln!(std::io::stdout(), "PASS live command failure {}: stable add/delete after failed replies, accepted unknown effects read back, fresh collision/satisfied/obsolete/refusal checks, health retained, recovery and foreign paths verified", family(&bad)).unwrap();
        }
    }

    #[tokio::test]
    async fn live_gobgp_worker_keeps_stable_cohort_after_supersession() {
        use std::io::Write as _;
        let Some(bin_dir) = std::env::var_os("SOKOL_GOBGP_TEST_BIN") else {
            eprintln!("SKIP live GoBGP: SOKOL_GOBGP_TEST_BIN is unset (required in canonical CI)");
            return;
        };
        let live = LiveGobgp::start(std::path::Path::new(&bin_dir)).await;
        let db = Arc::new(live.fixture.db());
        for (bad, foreign_net, stable, extra) in [
            (
                one("198.51.100.7"),
                one("198.51.100.8"),
                one("198.51.100.9"),
                one("198.51.100.10"),
            ),
            (
                one("2001:db8::7"),
                one("2001:db8::8"),
                one("2001:db8::9"),
                one("2001:db8::10"),
            ),
        ] {
            live.put(foreign_net, "discard", "65001:9999").await;
            for (case, bad_add, stable_add) in [
                ("stable_add", true, true),
                ("stable_delete", false, false),
                ("stable_add_after_delete", false, true),
                ("new_collision", true, true),
                ("satisfied_queue", true, true),
                ("unreadable_refresh", true, true),
            ] {
                let mut foreign = live.raw(foreign_net).await;
                if !bad_add {
                    live.fixture.cli.apply(true, bad).await.unwrap();
                }
                if !stable_add {
                    live.fixture.cli.apply(true, stable).await.unwrap();
                }
                let before = live.fixture.cli.observed().await.unwrap().owned;
                let mut initial = HashSet::new();
                if bad_add {
                    initial.insert(bad);
                }
                if stable_add {
                    initial.insert(stable);
                }
                if case == "new_collision" {
                    initial.insert(extra);
                }
                let dir = live
                    .fixture
                    .dir
                    .join(format!("cohort-{}-{case}", family(&bad)));
                std::fs::create_dir(&dir).unwrap();
                for file in ["bad_hold", "fresh_hold", "calls"] {
                    std::fs::write(dir.join(file), "").unwrap();
                }
                let wrapper = dir.join("cli.sh");
                std::fs::write(
                    &wrapper,
                    r#"#!/bin/sh
real="$1"; dir="$2"; bad="$3"; bad_op="$4"; shift 4
printf '%s\n' "$*" >> "$dir/calls"
op=read
case "$*" in *' add '*) op=add ;; *' del '*) op=del ;; esac
case "$*" in *" source $bad "*)
  if [ "$op" = "$bad_op" ] && [ -f "$dir/bad_hold" ]; then
    touch "$dir/bad_entered"
    while [ -f "$dir/bad_hold" ]; do sleep 0.01; done
  fi ;;
esac
if [ "$op" = read ] && [ -f "$dir/bad_entered" ]; then
  if [ ! -f "$dir/fresh_entered" ]; then
    touch "$dir/fresh_entered"
    while [ -f "$dir/fresh_hold" ]; do sleep 0.01; done
  fi
  if [ -f "$dir/read_fail" ]; then printf x >> "$dir/read_failed"; printf '{}\n'; exit 7; fi
fi
exec "$real" "$@"
"#,
                )
                .unwrap();
                let mut args = vec![
                    wrapper.to_str().unwrap().into(),
                    live.fixture.cli.bin.to_str().unwrap().into(),
                    dir.to_str().unwrap().into(),
                    bad.to_string(),
                    if bad_add { "add" } else { "del" }.into(),
                ];
                args.extend(live.fixture.cli.args.clone());
                let cli = GobgpCli {
                    bin: "/bin/sh".into(),
                    args,
                    community: live.fixture.cli.community,
                };
                let readback = Arc::new(Readback::default());
                readback.enable();
                checked_round(&live.fixture.cli, &before, &db, &readback)
                    .await
                    .unwrap();
                let old = readback.snapshot();
                let (wanted_tx, wanted_rx) = watch::channel(initial.clone());
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let worker = tokio::spawn(run_worker(
                    cli,
                    wanted_rx,
                    shutdown_rx,
                    db.clone(),
                    readback.clone(),
                ));
                assert!(eventually(|| dir.join("bad_entered").exists()).await);
                let mut changed = initial.clone();
                if bad_add {
                    changed.remove(&bad);
                } else {
                    changed.insert(bad);
                }
                update_wanted(&wanted_tx, changed);
                assert!(eventually(|| dir.join("fresh_entered").exists()).await);
                // Make the unstable prefix a candidate again while fresh read is held.
                // A complete restart would put it first and abandon the stable queue.
                update_wanted(&wanted_tx, initial);
                if case == "new_collision" {
                    live.put(stable, "discard", "65001:9999").await;
                    foreign = live.raw(foreign_net).await;
                } else if case == "satisfied_queue" {
                    live.fixture.cli.apply(true, stable).await.unwrap();
                } else if case == "unreadable_refresh" {
                    std::fs::write(dir.join("read_fail"), "").unwrap();
                }
                std::fs::remove_file(dir.join("fresh_hold")).unwrap();
                let progressed = if case == "unreadable_refresh" {
                    assert!(
                        eventually(|| std::fs::metadata(dir.join("read_failed"))
                            .map(|m| m.len() >= 2)
                            .unwrap_or(false))
                        .await,
                        "error path did not consume/refuse failed reads"
                    );
                    let pending = readback.snapshot();
                    assert!(!pending.ok && !pending.converged);
                    assert_eq!(pending.count, old.count);
                    assert_eq!(pending.started, old.started);
                    true
                } else {
                    let check_net = if case == "new_collision" {
                        extra
                    } else {
                        stable
                    };
                    let deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        let actual = live.fixture.cli.observed().await.unwrap();
                        if actual.owned.contains(&check_net) == stable_add
                            && actual.discard.contains(&check_net) == stable_add
                        {
                            break true;
                        }
                        if Instant::now() >= deadline {
                            break false;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                };
                // A second held attempt proves the satisfied candidate was consumed
                // and the original round completed, without guessing a processing delay.
                if case == "satisfied_queue" {
                    assert!(
                        eventually(|| std::fs::read_to_string(dir.join("calls"))
                            .unwrap()
                            .lines()
                            .filter(|line| line.contains(&format!(" source {bad} ")))
                            .count()
                            >= 2)
                        .await
                    );
                }
                let calls = std::fs::read_to_string(dir.join("calls")).unwrap();
                let actual = live.fixture.cli.observed().await.unwrap();
                // Real cleanup of the deliberately held prefix prevents this test
                // wrapper from stalling shutdown; ordinary stable cleanup remains worker-owned.
                live.fixture.cli.apply(false, bad).await.unwrap();
                std::fs::remove_file(dir.join("read_fail")).ok();
                shutdown_tx.send(true).unwrap();
                tokio::time::timeout(Duration::from_secs(3), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    progressed,
                    "{case}: superseded first command abandoned stable cohort: {calls}"
                );
                let writes: Vec<_> = calls
                    .lines()
                    .filter(|line| line.contains(" add ") || line.contains(" del "))
                    .collect();
                if matches!(case, "satisfied_queue" | "unreadable_refresh") {
                    assert!(
                        writes
                            .iter()
                            .all(|line| line.contains(&format!(" source {bad} "))),
                        "{case}: queued command must be skipped/refused: {calls}"
                    );
                } else {
                    let target = if case == "new_collision" {
                        extra
                    } else {
                        stable
                    };
                    let index = writes
                        .iter()
                        .position(|line| line.contains(&format!(" source {target} ")))
                        .expect("stable command never reached CLI");
                    assert_eq!(
                        index, 1,
                        "{case}: unstable prefix was retried ahead of stable work: {calls}"
                    );
                    assert!(writes[index].contains(if stable_add { " add " } else { " del " }));
                }
                if case == "new_collision" {
                    assert!(!actual.owned.contains(&stable));
                    assert!(actual.foreign_local.contains(&stable));
                    assert!(
                        writes
                            .iter()
                            .all(|line| !line.contains(&format!(" source {stable} "))),
                        "new collision overwritten: {calls}"
                    );
                }
                assert!(live.fixture.cli.observed().await.unwrap().owned.is_empty());
                assert_eq!(
                    live.raw(foreign_net).await,
                    foreign,
                    "{case}: foreign family RIB changed"
                );
                if case == "new_collision" {
                    let mut args = live.fixture.cli.command_args(false, stable);
                    let last = args.len() - 1;
                    args[last] = "65001:9999".into();
                    live.fixture.cli.run(args).await.unwrap();
                }
            }
            writeln!(std::io::stdout(), "PASS live cohort progress {}: stable add/delete after supersession, fresh collision/satisfied/refusal checks, original queue preserved, foreign paths preserved", family(&bad)).unwrap();
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
            // Keep the real daemon's reads but acknowledge writes without forwarding.
            // Read health must remain separate from observed target equality.
            let wrapper = live.fixture.dir.join("no-effect-cli.sh");
            let attempted = live.fixture.dir.join("no-effect-calls");
            std::fs::write(
                &wrapper,
                r#"#!/bin/sh
real="$1"
calls="$2"
shift 2
case "$*" in
  *' add '*|*' del '*) printf '%s\n' "$*" >> "$calls"; exit 0 ;;
esac
exec "$real" "$@"
"#,
            )
            .unwrap();
            let mut args = vec![
                wrapper.to_str().unwrap().to_string(),
                live.fixture.cli.bin.to_str().unwrap().to_string(),
                attempted.to_str().unwrap().to_string(),
            ];
            args.extend(live.fixture.cli.args.clone());
            let no_effect_cli = GobgpCli {
                bin: "/bin/sh".into(),
                args,
                community: live.fixture.cli.community,
            };
            let replacement = one(if net.addr().is_ipv4() {
                "198.51.100.10"
            } else {
                "2001:db8::10"
            });
            for (target, expected_count) in [
                (HashSet::from([fresh]), 0),
                (HashSet::new(), 1),
                (HashSet::from([replacement]), 1),
            ] {
                if expected_count == 1 {
                    live.fixture.cli.apply(true, fresh).await.unwrap();
                }
                std::fs::write(&attempted, "").unwrap();
                checked_round(&no_effect_cli, &target, &db, &readback)
                    .await
                    .unwrap();
                let calls = std::fs::read_to_string(&attempted).unwrap();
                let expected = if expected_count == 0 {
                    vec![format!(" add match source {} then discard", fresh)]
                } else if target.is_empty() {
                    vec![format!(" del match source {} then discard", fresh)]
                } else {
                    vec![
                        format!(" del match source {} then discard", fresh),
                        format!(" add match source {} then discard", replacement),
                    ]
                };
                assert_eq!(calls.lines().count(), expected.len());
                for operation in expected {
                    assert!(
                        calls.contains(&operation),
                        "no-op CLI did not accept {operation}"
                    );
                }
                let view = readback.snapshot();
                assert!(view.ok);
                assert_eq!(view.count, expected_count);
                assert!(!view.converged);
                let text = crate::metrics::render_with_flowspec(
                    &crate::metrics::Snapshot::default(),
                    &readback,
                );
                assert!(text.contains("sokol_flowspec_readback_ok 1\n"));
                assert!(text.contains("sokol_flowspec_round_converged 0\n"));
                // Restore actual writes: the same sampled target can now converge.
                checked_round(&live.fixture.cli, &target, &db, &readback)
                    .await
                    .unwrap();
                assert!(readback.snapshot().converged);
                checked_round(&live.fixture.cli, &HashSet::new(), &db, &readback)
                    .await
                    .unwrap();
                assert!(readback.snapshot().converged);
                assert_eq!(live.raw(net).await, foreign);
            }
            writeln!(std::io::stdout(), "PASS live convergence {}: read success does not certify no-effect add/delete or equal-count wrong prefixes; recovery converges", family(&net)).unwrap();
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
            ("/attrs/1/communities", serde_json::json!("not an array")),
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

    #[test]
    fn captured_empty_communities_do_not_establish_ownership() {
        let captures: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/gobgp-4.9.0-empty-community.json"
        ))
        .unwrap();
        for capture in captures.as_array().unwrap() {
            let rib =
                parse_rib(capture["stdout"].as_str().unwrap().as_bytes(), 4259912202).unwrap();
            assert!(rib.owned.is_empty());
            assert!(rib.discard.is_empty());
            assert_eq!(
                rib.foreign_local,
                ips(&[capture["prefix"].as_str().unwrap()])
            );
        }
    }

    #[tokio::test]
    async fn empty_community_is_foreign_and_does_not_block_other_withdrawals() {
        // GoBGP's nil uint32 slice marshals as null; an empty standard
        // community is untagged, not corrupt or owned.
        for communities in [serde_json::json!(null), serde_json::json!([])] {
            let mut foreign: serde_json::Value = serde_json::from_str(RIB).unwrap();
            foreign["[source: 198.51.100.7/32]"][0]["attrs"][1]["communities"] = communities;
            let mut combined = foreign.clone();
            let owned: serde_json::Value = serde_json::from_str(RIB).unwrap();
            let mut path = owned["[source: 198.51.100.7/32]"][0].clone();
            path["nlri"]["value"][0]["value"]["prefix"] = serde_json::json!("198.51.100.8/32");
            combined["[source: 198.51.100.8/32]"] = serde_json::json!([path]);
            let parsed = parse_rib(foreign.to_string().as_bytes(), 4259912202).unwrap();
            assert!(parsed.owned.is_empty());
            assert!(parsed
                .foreign_local
                .contains(&"198.51.100.7/32".parse().unwrap()));
            let fixture = RoundFixture::new(&combined.to_string(), &foreign.to_string(), false);
            let db = fixture.db();
            let readback = Readback::default();
            readback.enable();
            checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
                .await
                .unwrap();
            let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
            assert!(calls.contains(" del match source 198.51.100.8/32 "));
            assert!(!calls.contains(" del match source 198.51.100.7/32 "));
            assert!(readback.snapshot().ok);
            assert_eq!(readback.snapshot().count, 0);
        }
    }

    #[tokio::test]
    async fn remote_metadata_does_not_block_local_reconciliation() {
        let mut raw: serde_json::Value = serde_json::from_str(RIB).unwrap();
        // A known peer path is never a local CLI target or collision.
        let remote = &mut raw["[source: 203.0.113.9/32]"][0];
        assert!(remote["peer-address"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        remote["LocalID"] = serde_json::json!("unknown");
        remote["attrs"] = serde_json::json!(null);
        remote["nlri"]["value"] = serde_json::json!(null);
        let fixture = RoundFixture::new(&raw.to_string(), "{}", false);
        let db = fixture.db();
        let readback = Readback::default();
        readback.enable();
        checked_round(&fixture.cli, &HashSet::new(), &db, &readback)
            .await
            .unwrap();
        let calls = std::fs::read_to_string(fixture.dir.join("calls")).unwrap();
        assert!(calls.contains(" del match source 198.51.100.7/32 "));
        assert!(!calls.contains(" del match source 203.0.113.9/32 "));
        assert!(readback.snapshot().ok);
    }

    #[tokio::test]
    async fn completed_reads_do_not_make_no_effect_writes_converged() {
        for (before, after, target, count) in [
            ("{}", "{}", ips(&["198.51.100.7"]), 0),
            (RIB, RIB, HashSet::new(), 1),
            // Same cardinality and canonical action, but the wrong prefix remains.
            (RIB, RIB, ips(&["198.51.100.10"]), 1),
        ] {
            let fixture = RoundFixture::new(before, after, false);
            let db = fixture.db();
            let readback = Readback::default();
            readback.enable();
            checked_round(&fixture.cli, &target, &db, &readback)
                .await
                .unwrap();
            assert!(fixture.dir.join("applied").exists());
            let view = readback.snapshot();
            assert!(view.ok);
            assert_eq!(view.count, count);
            let stale_main = crate::metrics::Snapshot {
                flowspec_round_converged: true,
                ..Default::default()
            };
            let text = crate::metrics::render_with_flowspec(&stale_main, &readback);
            assert!(
                text.contains("sokol_flowspec_round_converged 0\n"),
                "a completed read certified an unachieved target"
            );
        }
    }

    #[tokio::test]
    async fn round_convergence_tracks_prefix_sets_and_canonical_actions() {
        let wrong_action = RIB.replace("\"rate\":0", "\"rate\":100");
        for (before, after, target, expected) in [
            (RIB, RIB, ips(&["198.51.100.7"]), 1),
            (RIB, "{}", HashSet::new(), 1),
            ("{}", RIB, ips(&["198.51.100.7"]), 1),
            ("{}", "{}", HashSet::new(), 1),
            (
                wrong_action.as_str(),
                wrong_action.as_str(),
                ips(&["198.51.100.7"]),
                0,
            ),
            (
                wrong_action.as_str(),
                wrong_action.as_str(),
                HashSet::new(),
                0,
            ),
            (wrong_action.as_str(), RIB, ips(&["198.51.100.7"]), 1),
        ] {
            let fixture = RoundFixture::new(before, after, false);
            let db = fixture.db();
            let readback = Readback::default();
            readback.enable();
            checked_round(&fixture.cli, &target, &db, &readback)
                .await
                .unwrap();
            assert!(readback.snapshot().ok);
            let text = crate::metrics::render_with_flowspec(
                &crate::metrics::Snapshot::default(),
                &readback,
            );
            assert!(text.contains(&format!("sokol_flowspec_round_converged {expected}\n")));
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
