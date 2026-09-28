//! Block decisions (claims) with owners, and the XDP blocklists kept in line with them.
//!
//! Semantics are the proposed ADRs 1-4 (owner rule, retraction by claim id, mesh state as a
//! two-phase set, durable local decisions):
//!
//! - A claim is one immutable decision: issuer node, kind, target, times, reason. Its identity
//!   is the hash of its bytes.
//! - `--block` (Static) is lifted only by the configuration; operator bans (Operator) by the
//!   operator; detector claims (traps, IPC, adapters, peers) expire: the first local one lasts
//!   `base`, each repeat within `STRIKE_MEMORY` doubles it, up to `max`.
//! - Over the mesh only detector claims travel. A claim is retracted mesh-wide only by its
//!   issuer; an operator lift is local and names the claims it lifts, so a peer's copy of a
//!   lifted claim never reinstates it, while a new decision about the address does.
//! - The kernel map follows the effective claims; failed map operations stay pending and are
//!   retried, and only applied entries are counted.
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use aya::maps::lpm_trie::Key;
use aya::maps::{LpmTrie, MapData, MapError, PerCpuArray, PerCpuValues};

/// How long an address's past blocks count towards escalation.
pub const STRIKE_MEMORY: Duration = Duration::from_secs(24 * 3600);

/// How long a detector event id is remembered: a replay within it adds no strike. As long as
/// the strike memory, so a replay can never escalate a block.
pub const EVENT_MEMORY: Duration = STRIKE_MEMORY;
/// Targets whose strikes are remembered at once. Every new source a detector reports adds one,
/// so without a count bound a flood of distinct (spoofed) sources grew the table for as long as
/// STRIKE_MEMORY; the oldest are forgotten first, and a forgotten target restarts at `base`.
pub const MAX_STRIKES: usize = common::BLOCKLIST_CAPACITY as usize;
/// At most this many remembered event ids; the oldest is forgotten first (and counted).
pub const MAX_EVENTS: usize = common::BLOCKLIST_CAPACITY as usize;

/// A single address as a host network (/32 or /128); `::ffff:a.b.c.d` becomes `a.b.c.d/32`.
pub fn host(ip: IpAddr) -> IpNet {
    IpNet::from(ip.to_canonical())
}

/// Network address with host bits cleared; IPv4-mapped IPv6 prefixes become IPv4 ones.
pub fn canonical(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if let Some(v4) = v6.network().to_ipv4_mapped() {
            if v6.prefix_len() >= 96 {
                if let Ok(n) = ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96) {
                    return IpNet::V4(n.trunc());
                }
            }
        }
    }
    net.trunc()
}

/// An address or a CIDR prefix, as accepted from the CLI, the IPC and control sockets and the mesh.
pub fn parse_target(raw: &str) -> Option<IpNet> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(host(ip));
    }
    raw.parse::<IpNet>().ok().map(canonical)
}

/// Addresses print without a prefix length, so logs and audit records stay as before.
pub fn show(net: &IpNet) -> String {
    if net.prefix_len() == net.max_prefix_len() {
        net.addr().to_string()
    } else {
        net.to_string()
    }
}

pub fn family_tag(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => "V4",
        IpNet::V6(_) => "V6",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlPolicy {
    /// Zero disables expiry: detector blocks become permanent.
    pub base: Duration,
    pub max: Duration,
}

/// Who made a block decision; decides who may take it back (ADR-1).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimKind {
    /// `--block`: only the configuration lifts it.
    Static,
    /// Control socket ban: lifted by the operator; never shared.
    Operator,
    /// Trap, IPC, adapters, a peer's detector: expires, and is shared over the mesh.
    Detector,
}

/// One block decision. Immutable; its identity is the hash of its bytes, so a retraction can
/// name exactly the decision it takes back and a later decision about the same address is a
/// different claim.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub issuer: u64,
    pub kind: ClaimKind,
    /// Canonical target as printed by [`show`].
    pub target: String,
    pub issued_ms: u64,
    /// `None`: until lifted.
    pub expires_ms: Option<u64>,
    pub reason: String,
}

/// Hex BLAKE3 of the claim's JSON bytes.
pub type ClaimId = String;

impl Claim {
    pub fn id(&self) -> ClaimId {
        // Integers, strings and a unit enum: serialization cannot fail, and a fallback would
        // give distinct claims one id.
        #[allow(clippy::expect_used, reason = "serializing this struct cannot fail")]
        let bytes = serde_json::to_vec(self).expect("claim serializes");
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// The target, if it is canonical (one claim id per decision, not per spelling).
    pub fn net(&self) -> Option<IpNet> {
        parse_target(&self.target).filter(|net| show(net) == self.target)
    }

    fn live_at(&self, now_ms: u64) -> bool {
        self.expires_ms.is_none_or(|e| e > now_ms)
    }
}

/// Longest reason a claim may carry (bounds the size of every claim, R26-02).
pub const MAX_REASON_BYTES: usize = 512;

fn bounded_reason(reason: &str) -> String {
    if reason.len() <= MAX_REASON_BYTES {
        return reason.to_string();
    }
    let mut end = MAX_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.get(..end).unwrap_or_default().to_string()
}

/// What a kernel entry did while it was in force: its observed effect, for the audit (the
/// node's memory of consequences) and for later review of its own decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub net: IpNet,
    /// Who decided it and why: the earliest claim in force when the entry was applied
    /// (`detector`, `operator`, `static` or `peer <id>`, then the claim's reason).
    pub cause: String,
    /// Packets it dropped; `None` if the counter could not be read.
    pub hits: Option<u64>,
    pub applied_ms: u64,
    pub removed_ms: u64,
}

/// Outcomes kept until collected (one tick normally empties them).
pub const MAX_OUTCOMES: usize = 4096;

/// Pending kernel operations retried per tick (a full map must not cost a syscall per entry per s).
pub const MAX_RETRIES_PER_TICK: usize = 256;

/// A retraction or lift record is kept this long past the moment its claim can no longer
/// count, so a clock stepped back by less than this (NTP, a VM resumed) cannot bring a lifted
/// claim back to life for the length of the step. Twenty times the mesh's clock-skew bound.
pub const FORGET_GRACE: Duration = Duration::from_secs(600);

/// Distinct nodes remembered per retracted id (the issuer plus a few others).
const MAX_RETRACTORS: usize = 4;

/// What one peer may impose on this node (ADR-7). Claims outside it are known and shared but
/// not enforced here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The peer's claims enforced here at once; further ones wait for a free slot.
    pub max_active: usize,
    /// Longest a claim of the peer is enforced here, from when its enforcement starts.
    pub max_ttl: Duration,
    /// Widest prefixes (shortest length) the peer may block here at all.
    pub min_prefix_v4: u8,
    pub min_prefix_v6: u8,
}

impl Envelope {
    pub fn unlimited(max_ttl: Duration) -> Self {
        Self {
            max_active: usize::MAX,
            max_ttl,
            min_prefix_v4: 0,
            min_prefix_v6: 0,
        }
    }

    fn admits(&self, net: &IpNet) -> bool {
        match net {
            IpNet::V4(n) => n.prefix_len() >= self.min_prefix_v4,
            IpNet::V6(n) => n.prefix_len() >= self.min_prefix_v6,
        }
    }
}

/// Prefixes wider than these need claims from `k` distinct nodes before a peer's claim is
/// enforced (this node's own claims count as one). `k <= 1` disables it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quorum {
    pub k: usize,
    pub wide_v4: u8,
    pub wide_v6: u8,
}

impl Quorum {
    pub const OFF: Quorum = Quorum {
        k: 1,
        wide_v4: 0,
        wide_v6: 0,
    };

    fn applies(&self, net: &IpNet) -> bool {
        self.k > 1
            && match net {
                IpNet::V4(n) => n.prefix_len() < self.wide_v4,
                IpNet::V6(n) => n.prefix_len() < self.wide_v6,
            }
    }
}

/// Known claims (and retraction records) beyond this are refused (a flooding peer cannot exhaust memory).
pub const MAX_KNOWN_CLAIMS: usize = 4 * common::BLOCKLIST_CAPACITY as usize;

struct Held {
    claim: Claim,
    net: IpNet,
    /// Local enforcement end: a peer's claim is capped at the local `max`.
    until_ms: Option<u64>,
    /// Passed the local never-block policy.
    allowed: bool,
    /// Holds one of its issuer's enforcement slots (always true for this node's claims).
    in_quota: bool,
    /// Its local end has been handled (so an ended claim is not re-examined every tick).
    ended: bool,
}

#[derive(Default)]
struct Retraction {
    /// Lifted by this node's operator (local only).
    operator: bool,
    /// Nodes that sent a retraction; effective only for the claim's issuer. A set, so another
    /// node's retraction of the same id can never displace the issuer's.
    by_nodes: Vec<u64>,
    /// When the record may be forgotten (the claim cannot be live after it).
    forget_ms: Option<u64>,
}

/// What an operator lift did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lifted {
    /// Claims lifted on this node.
    pub claims: usize,
    /// This node's own detector claims, retracted for the whole mesh.
    pub retracted: Vec<ClaimId>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LiftError {
    NotBlocked,
    /// Only `--block` holds it; the configuration lifts it.
    Static,
}

/// A new local decision, and whether the kernel map took it.
pub struct Added {
    pub claim: Claim,
    pub ttl: Option<Duration>,
    pub applied: Result<(), MapError>,
    /// A new claim (to share); false when the repeat was the running decision (R26-05).
    pub new: bool,
}

/// Result of offering a peer's claim.
#[derive(Debug, PartialEq, Eq)]
pub enum Adoption {
    /// New and now enforced here.
    Enforced,
    /// New; known but not enforced here, and why: "protected", "retracted", "quota",
    /// "envelope", "quorum", "map" (kernel write pending) or "already blocked".
    Held(&'static str),
    Known,
    Refused(&'static str),
}

/// Layout of the state file this build writes and reads. Bumped on any incompatible change;
/// there are no migrations (no release yet): another layout is refused by name at restore.
pub const STATE_SCHEMA: u32 = 1;

fn first_schema() -> u32 {
    1
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            claims: Vec::new(),
            operator_lifts: Vec::new(),
            retracted: Vec::new(),
            peer_ends: Vec::new(),
            events: Vec::new(),
        }
    }
}

/// Durable part of the table (ADR-4): this node's own decisions and lifts.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Persisted {
    /// Layout of this file ([`STATE_SCHEMA`]). A file without it predates the field and has
    /// layout 1.
    #[serde(default = "first_schema")]
    pub schema: u32,
    pub claims: Vec<Claim>,
    pub operator_lifts: Vec<(ClaimId, Option<u64>)>,
    pub retracted: Vec<(ClaimId, Option<u64>)>,
    /// Local ends of peers' claims that were cut short here (R26-07): after a restart the same
    /// claim does not get a new lease. (id, local end, the claim's own expiry)
    #[serde(default)]
    pub peer_ends: Vec<(ClaimId, u64, Option<u64>)>,
    /// Detector events already acted on, oldest first: (hex of the hashed (source, id), seen
    /// at). Saved with the claims they produced, so a replay after a restart is still a
    /// duplicate (R27-05).
    #[serde(default)]
    pub events: Vec<(String, u64)>,
}

/// Block decisions (claims) with owners, and the kernel maps kept in line with them.
///
/// *Desired* state is the set of effective claims: known, not retracted by someone entitled to,
/// allowed by local policy, not past their local end. *Applied* state is what the kernel map
/// holds. They are reconciled per target; a failed map write or delete stays pending and is
/// retried on every tick, so metrics and snapshots never count a block the kernel does not
/// enforce, and a lift that failed is not forgotten.
pub struct BlockTable<B = KernelBlocklist> {
    lists: B,
    policy: TtlPolicy,
    node_id: u64,
    claims: HashMap<ClaimId, Held>,
    retractions: HashMap<ClaimId, Retraction>,
    by_target: HashMap<IpNet, HashSet<ClaimId>>,
    applied: HashSet<IpNet>,
    pending: HashSet<IpNet>,
    /// When each pending target first failed (for the age of the oldest).
    pending_since: HashMap<IpNet, u64>,
    /// When each applied target entered the kernel map, and the decision that put it there.
    applied_at: HashMap<IpNet, u64>,
    applied_cause: HashMap<IpNet, String>,
    /// What removed kernel entries did while they were in force, oldest first (bounded).
    outcomes: std::collections::VecDeque<Outcome>,
    outcomes_dropped: u64,
    /// Targets to retry, oldest first (R26-06): each is retried at most once per tick, and a
    /// target that keeps failing goes to the back, so it cannot starve the others.
    retry: std::collections::VecDeque<IpNet>,
    queued: HashSet<IpNet>,
    strikes: HashMap<IpNet, (u32, u64)>,
    /// (target, last strike) in the order strikes were taken; an entry whose time no longer
    /// matches the map is stale and skipped. Compacted when it holds twice MAX_STRIKES.
    strike_order: std::collections::VecDeque<(IpNet, u64)>,
    strikes_evicted: u64,
    /// Detector events already acted on, keyed by hash of (source, event id), oldest first.
    events: HashMap<[u8; 16], u64>,
    event_order: std::collections::VecDeque<([u8; 16], u64)>,
    events_evicted: u64,
    dirty: bool,
    default_envelope: Envelope,
    envelopes: HashMap<u64, Envelope>,
    quorum: Quorum,
    active_by_issuer: HashMap<u64, usize>,
    waiting: HashMap<u64, std::collections::VecDeque<ClaimId>>,
    /// Local ends of peers' claims cut short here, remembered across restarts (R26-07).
    lease_ends: HashMap<ClaimId, (u64, Option<u64>)>,
    /// Nodes whose claims may count here (the pinned peers). `None` until configured: no
    /// restriction (tests). A peer removed from the peers file loses its claims' effect.
    pinned: Option<HashSet<u64>>,
}

fn ms(d: Duration) -> u64 {
    d.as_millis().min(u64::MAX as u128) as u64
}

impl BlockTable<KernelBlocklist> {
    pub fn new(
        v4: LpmTrie<MapData, [u8; 4], u32>,
        v6: LpmTrie<MapData, [u8; 16], u32>,
        hits: PerCpuArray<MapData, u64>,
        cpus: usize,
        policy: TtlPolicy,
        node_id: u64,
    ) -> Self {
        Self::with_lists(KernelBlocklist::new(v4, v6, hits, cpus), policy, node_id)
    }
}

impl<B: Blocklist> BlockTable<B> {
    pub fn with_lists(lists: B, policy: TtlPolicy, node_id: u64) -> Self {
        Self {
            lists,
            policy,
            node_id,
            claims: HashMap::new(),
            retractions: HashMap::new(),
            by_target: HashMap::new(),
            applied: HashSet::new(),
            pending: HashSet::new(),
            pending_since: HashMap::new(),
            applied_at: HashMap::new(),
            applied_cause: HashMap::new(),
            outcomes: std::collections::VecDeque::new(),
            outcomes_dropped: 0,
            retry: std::collections::VecDeque::new(),
            queued: HashSet::new(),
            strikes: HashMap::new(),
            strike_order: std::collections::VecDeque::new(),
            strikes_evicted: 0,
            events: HashMap::new(),
            event_order: std::collections::VecDeque::new(),
            events_evicted: 0,
            dirty: false,
            default_envelope: Envelope::unlimited(policy.max),
            envelopes: HashMap::new(),
            quorum: Quorum::OFF,
            active_by_issuer: HashMap::new(),
            waiting: HashMap::new(),
            pinned: None,
            lease_ends: HashMap::new(),
        }
    }

    /// Sets the nodes whose claims may count here (R26-01: an unknown or revoked origin's
    /// claims are known but never enforced).
    pub fn set_pinned(&mut self, pinned: HashSet<u64>, now_ms: u64) {
        self.pinned = Some(pinned);
        let nets: Vec<IpNet> = self.by_target.keys().copied().collect();
        self.settle(nets, now_ms);
    }

    fn origin_trusted(&self, issuer: u64) -> bool {
        issuer == self.node_id || self.pinned.as_ref().is_none_or(|p| p.contains(&issuer))
    }

    /// Sets what peers may impose (ADR-7): `default` for every peer, `per_peer` overrides, and
    /// the quorum for wide prefixes. Applies to enforcement from now on; slot counts and local
    /// ends of claims already adopted are kept.
    pub fn configure_peers(
        &mut self,
        default: Envelope,
        per_peer: HashMap<u64, Envelope>,
        quorum: Quorum,
        now_ms: u64,
    ) {
        self.default_envelope = default;
        self.envelopes = per_peer;
        self.quorum = quorum;
        let nets: Vec<IpNet> = self.by_target.keys().copied().collect();
        self.settle(nets, now_ms);
    }

    fn envelope(&self, issuer: u64) -> &Envelope {
        self.envelopes
            .get(&issuer)
            .unwrap_or(&self.default_envelope)
    }

    fn retracted(&self, id: &ClaimId, held: &Held) -> bool {
        self.retractions
            .get(id)
            .is_some_and(|r| r.operator || r.by_nodes.contains(&held.claim.issuer))
    }

    /// Everything but the quorum: this claim alone may count towards enforcing its target.
    fn counts(&self, id: &ClaimId, held: &Held, now_ms: u64) -> bool {
        held.allowed
            && held.in_quota
            && self.origin_trusted(held.claim.issuer)
            && held.until_ms.is_none_or(|u| u > now_ms)
            && !self.retracted(id, held)
            && (held.claim.issuer == self.node_id
                || self.envelope(held.claim.issuer).admits(&held.net))
    }

    /// Distinct nodes with a counting claim on `net` (this node included).
    fn issuers_on(&self, net: &IpNet, now_ms: u64) -> usize {
        let mut issuers = HashSet::new();
        for id in self.by_target.get(net).into_iter().flatten() {
            if let Some(h) = self.claims.get(id) {
                if self.counts(id, h, now_ms) {
                    issuers.insert(h.claim.issuer);
                }
            }
        }
        issuers.len()
    }

    fn effective(&self, id: &ClaimId, held: &Held, now_ms: u64) -> bool {
        self.counts(id, held, now_ms)
            && (held.claim.issuer == self.node_id
                || !self.quorum.applies(&held.net)
                || self.issuers_on(&held.net, now_ms) >= self.quorum.k)
    }

    /// Why a known claim is not enforced here (for the audit); `None` if it is effective.
    fn hold_reason(&self, id: &ClaimId, held: &Held, now_ms: u64) -> Option<&'static str> {
        if !held.allowed {
            Some("protected")
        } else if !self.origin_trusted(held.claim.issuer) {
            Some("revoked")
        } else if self.retracted(id, held) {
            Some("retracted")
        } else if held.claim.issuer != self.node_id
            && !self.envelope(held.claim.issuer).admits(&held.net)
        {
            Some("envelope")
        } else if held.until_ms.is_some_and(|u| u <= now_ms) {
            Some("expired")
        } else if !held.in_quota {
            Some("quota")
        } else if !self.effective(id, held, now_ms) {
            Some("quorum")
        } else {
            None
        }
    }

    fn retractions_full(&self) -> bool {
        self.retractions.len() >= MAX_KNOWN_CLAIMS
    }

    fn release_slot(&mut self, id: &ClaimId) {
        if let Some(h) = self.claims.get_mut(id) {
            if h.in_quota && h.claim.issuer != self.node_id {
                h.in_quota = false;
                if let Some(n) = self.active_by_issuer.get_mut(&h.claim.issuer) {
                    *n = n.saturating_sub(1);
                }
            }
        }
    }

    fn wanted(&self, net: &IpNet, now_ms: u64) -> bool {
        self.by_target.get(net).is_some_and(|ids| {
            ids.iter().any(|id| {
                self.claims
                    .get(id)
                    .is_some_and(|h| self.effective(id, h, now_ms))
            })
        })
    }

    /// Brings the kernel entry for `net` in line with the claims. `Err` leaves it pending.
    fn reconcile(&mut self, net: IpNet, now_ms: u64) -> Result<(), MapError> {
        let want = self.wanted(&net, now_ms);
        let have = self.applied.contains(&net);
        let result = match (want, have) {
            (true, false) => {
                let cause = self.cause(&net, now_ms);
                self.lists.add(net).map(|()| {
                    self.applied.insert(net);
                    self.applied_at.insert(net, now_ms);
                    self.applied_cause.insert(net, cause);
                })
            }
            (false, true) => {
                // Read the entry's effect before it goes (packets arriving in between are lost
                // to the count, not to enforcement).
                let hits = self.lists.hits(net);
                match self.lists.delete(net) {
                    Ok(()) | Err(MapError::KeyNotFound) => {
                        self.applied.remove(&net);
                        let since = self.applied_at.remove(&net).unwrap_or(now_ms);
                        let cause = self.applied_cause.remove(&net).unwrap_or_default();
                        self.record_outcome(Outcome {
                            net,
                            cause,
                            hits,
                            applied_ms: since,
                            removed_ms: now_ms,
                        });
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            _ => Ok(()),
        };
        if result.is_ok() {
            self.pending.remove(&net);
            self.pending_since.remove(&net);
        } else {
            self.pending.insert(net);
            self.pending_since.entry(net).or_insert(now_ms);
            if self.queued.insert(net) {
                self.retry.push_back(net);
            }
        }
        result
    }

    /// Remembers a detector event; false if the same (source, event id) was seen within
    /// EVENT_MEMORY. The caller checks this and adds the claim under one lock, so a replay
    /// after a lost ACK or an adapter restart adds no strike.
    pub fn first_sighting(&mut self, source: &str, event: &str, now_ms: u64) -> bool {
        while let Some(&(key, seen)) = self.event_order.front() {
            if now_ms.saturating_sub(seen) <= ms(EVENT_MEMORY) {
                break;
            }
            self.event_order.pop_front();
            if self.events.get(&key) == Some(&seen) {
                self.events.remove(&key);
            }
        }
        let mut h = blake3::Hasher::new();
        h.update(source.as_bytes());
        h.update(&[0]);
        h.update(event.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&h.finalize().as_bytes()[..16]);
        if self.events.contains_key(&key) {
            return false;
        }
        while self.events.len() >= MAX_EVENTS {
            let Some((old, seen)) = self.event_order.pop_front() else {
                break;
            };
            if self.events.get(&old) == Some(&seen) {
                self.events.remove(&old);
                self.events_evicted += 1;
            }
        }
        self.events.insert(key, now_ms);
        self.event_order.push_back((key, now_ms));
        self.dirty = true;
        true
    }

    /// (remembered event ids, ids forgotten early because the memory was full)
    pub fn event_memory(&self) -> (usize, u64) {
        (self.events.len(), self.events_evicted)
    }

    /// (targets with remembered strikes, targets forgotten early because the memory was full)
    pub fn strike_memory(&self) -> (usize, u64) {
        (self.strikes.len(), self.strikes_evicted)
    }

    /// Records a strike on `net` and returns its count (at least 1). A new target over
    /// MAX_STRIKES makes room by forgetting the least recently struck ones.
    fn strike(&mut self, net: IpNet, now_ms: u64) -> u32 {
        if !self.strikes.contains_key(&net) {
            while self.strikes.len() >= MAX_STRIKES {
                let Some((old, seen)) = self.strike_order.pop_front() else {
                    break;
                };
                if self.strikes.get(&old).map(|&(_, last)| last) == Some(seen) {
                    self.strikes.remove(&old);
                    self.strikes_evicted += 1;
                }
            }
        }
        let entry = self.strikes.entry(net).or_insert((0, now_ms));
        if now_ms.saturating_sub(entry.1) > ms(STRIKE_MEMORY) {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now_ms;
        let count = entry.0;
        self.strike_order.push_back((net, now_ms));
        if self.strike_order.len() > 2 * MAX_STRIKES {
            let strikes = &self.strikes;
            self.strike_order
                .retain(|(n, seen)| strikes.get(n).map(|&(_, last)| last) == Some(*seen));
        }
        count
    }

    /// The earliest claim in force on `net`, as `<who>: <reason>`.
    fn cause(&self, net: &IpNet, now_ms: u64) -> String {
        let first = self
            .by_target
            .get(net)
            .into_iter()
            .flatten()
            .filter_map(|id| {
                self.claims
                    .get(id)
                    .filter(|h| self.effective(id, h, now_ms))
            })
            .min_by_key(|h| (h.claim.issued_ms, h.claim.issuer));
        match first {
            Some(h) => {
                let who = match (h.claim.kind, h.claim.issuer == self.node_id) {
                    (ClaimKind::Static, _) => "static".to_string(),
                    (ClaimKind::Operator, _) => "operator".to_string(),
                    (ClaimKind::Detector, true) => "detector".to_string(),
                    (ClaimKind::Detector, false) => format!("peer {}", h.claim.issuer),
                };
                format!("{}: {}", who, h.claim.reason)
            }
            None => "unknown".to_string(),
        }
    }

    fn record_outcome(&mut self, outcome: Outcome) {
        if self.outcomes.len() >= MAX_OUTCOMES {
            self.outcomes.pop_front();
            self.outcomes_dropped += 1;
        }
        self.outcomes.push_back(outcome);
    }

    /// Outcomes of kernel entries removed since the last call, oldest first, and how many were
    /// dropped because nobody collected them in time.
    pub fn take_outcomes(&mut self) -> (Vec<Outcome>, u64) {
        let dropped = std::mem::take(&mut self.outcomes_dropped);
        (self.outcomes.drain(..).collect(), dropped)
    }

    /// Re-checks every known claim against a changed never-block policy (the host's addresses or
    /// gateways moved). A claim whose target became protected stops counting now (its kernel
    /// entry is removed, a peer's slot freed); one whose target is no longer protected counts
    /// again (a peer's claim queues for a slot). Returns the targets no longer blocked.
    pub fn recheck(&mut self, allowed: impl Fn(IpNet) -> bool, now_ms: u64) -> Vec<IpNet> {
        let mut changed: Vec<(ClaimId, IpNet, bool)> = Vec::new();
        for (id, h) in self.claims.iter_mut() {
            let ok = allowed(h.net);
            if ok != h.allowed {
                h.allowed = ok;
                changed.push((id.clone(), h.net, ok));
            }
        }
        for (id, _, ok) in &changed {
            if *ok {
                let queue = self.claims.get(id).and_then(|h| {
                    let waits = h.claim.issuer != self.node_id
                        && !h.in_quota
                        && h.claim.live_at(now_ms)
                        && !self.retracted(id, h)
                        && self.lease_ends.get(id).is_none_or(|(end, _)| *end > now_ms);
                    waits.then_some(h.claim.issuer)
                });
                if let Some(issuer) = queue {
                    let q = self.waiting.entry(issuer).or_default();
                    if !q.contains(id) {
                        q.push_back(id.clone());
                    }
                }
            } else {
                self.release_slot(id);
            }
        }
        let nets = changed.into_iter().map(|(_, net, _)| net).collect();
        self.settle(nets, now_ms)
    }

    /// Remembers where a peer claim's lease ends if the local cap cuts it short. The end only
    /// ever moves earlier: a lease shortened once (e.g. after a clock step) is not lengthened by
    /// a later restart, so records timed by it (an operator lift) outlive it.
    fn record_lease(&mut self, id: &ClaimId, cap: u64, expires: Option<u64>) {
        if expires.is_some_and(|e| e <= cap) {
            return;
        }
        match self.lease_ends.get_mut(id) {
            Some((end, _)) if *end <= cap => {}
            Some((end, _)) => {
                *end = cap;
                self.dirty = true;
            }
            None => {
                self.lease_ends.insert(id.clone(), (cap, expires));
                self.dirty = true;
            }
        }
    }

    fn insert_held(&mut self, id: ClaimId, held: Held) {
        self.by_target
            .entry(held.net)
            .or_default()
            .insert(id.clone());
        self.claims.insert(id, held);
    }

    /// A decision made on this node. The caller has checked the never-block policy.
    ///
    /// Repeats are coalesced (R26-05): a repeat adds a claim only if it would extend this node's
    /// longest own claim on the target by at least a quarter of its lifetime (so escalation still
    /// doubles the block, and a target at the cap gets a new claim at most every max/4). When a new detector claim does outlast the older ones, they are retracted
    /// mesh-wide, so a target carries a handful of own claims however often it is signalled.
    /// A new claim beyond MAX_KNOWN_CLAIMS is refused.
    pub fn add_local(
        &mut self,
        net: IpNet,
        kind: ClaimKind,
        reason: &str,
        now_ms: u64,
    ) -> Result<Added, &'static str> {
        let net = canonical(net);
        let ttl = match kind {
            ClaimKind::Static | ClaimKind::Operator => None,
            ClaimKind::Detector if self.policy.base.is_zero() => None,
            ClaimKind::Detector => {
                let strikes = self.strike(net, now_ms);
                let factor = 1u32.checked_shl(strikes - 1).unwrap_or(u32::MAX);
                Some(self.policy.base.saturating_mul(factor).min(self.policy.max))
            }
        };
        let new_end = ttl.map(|t| now_ms.saturating_add(ms(t)));
        // This node's own effective claims of the same kind on the target.
        let own: Vec<(ClaimId, Option<u64>)> = self
            .by_target
            .get(&net)
            .into_iter()
            .flatten()
            .filter_map(|id| {
                let h = self.claims.get(id)?;
                (h.claim.issuer == self.node_id
                    && h.claim.kind == kind
                    && self.effective(id, h, now_ms))
                .then(|| (id.clone(), h.claim.expires_ms))
            })
            .collect();
        let longest = own.iter().map(|(_, e)| *e).max_by(|a, b| match (a, b) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, _) => std::cmp::Ordering::Greater,
            (_, None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => x.cmp(y),
        });
        if let Some(longest) = longest {
            let enough = match (longest, new_end, ttl) {
                (None, _, _) => true,
                (Some(_), None, _) => false,
                // A new claim only if it extends the block by at least a quarter of its lifetime.
                (Some(have), Some(want), Some(t)) => want < have.saturating_add(ms(t) / 4),
                (Some(have), Some(want), None) => have >= want,
            };
            let running = own
                .iter()
                .find(|(_, e)| *e == longest)
                .and_then(|(id, _)| self.claims.get(id))
                .map(|h| h.claim.clone());
            if let Some(claim) = running.filter(|_| enough) {
                let applied = self.reconcile(net, now_ms);
                let left = claim
                    .expires_ms
                    .map(|e| Duration::from_millis(e.saturating_sub(now_ms)));
                return Ok(Added {
                    claim,
                    ttl: left,
                    applied,
                    new: false,
                });
            }
        }
        if self.claims.len() >= MAX_KNOWN_CLAIMS {
            return Err("too many known claims");
        }
        let claim = Claim {
            issuer: self.node_id,
            kind,
            target: show(&net),
            issued_ms: now_ms,
            expires_ms: new_end,
            reason: bounded_reason(reason),
        };
        let id = claim.id();
        self.insert_held(
            id,
            Held {
                until_ms: claim.expires_ms,
                claim: claim.clone(),
                net,
                allowed: true,
                in_quota: true,
                ended: false,
            },
        );
        // Older own detector claims the new one outlasts are redundant: take them back.
        if kind == ClaimKind::Detector {
            let outlasted: Vec<ClaimId> = own
                .iter()
                .filter(|(_, e)| match (e, new_end) {
                    (Some(e), Some(n)) => *e <= n,
                    (_, None) => true,
                    (None, Some(_)) => false,
                })
                .map(|(id, _)| id.clone())
                .collect();
            if !outlasted.is_empty() {
                self.retract(self.node_id, &outlasted, now_ms);
            }
        }
        if kind != ClaimKind::Static {
            self.dirty = true;
        }
        let applied = self.reconcile(net, now_ms);
        Ok(Added {
            claim,
            ttl,
            applied,
            new: true,
        })
    }

    /// A claim from a peer (live or in a snapshot). `allowed` is the local never-block verdict.
    pub fn adopt(&mut self, claim: Claim, allowed: bool, now_ms: u64) -> Adoption {
        if claim.kind != ClaimKind::Detector {
            return Adoption::Refused("only detector claims are shared");
        }
        let Some(net) = claim.net() else {
            return Adoption::Refused("target is not canonical");
        };
        if claim.reason.len() > MAX_REASON_BYTES {
            return Adoption::Refused("reason too long");
        }
        if claim.issuer == self.node_id {
            return Adoption::Refused("claims to be issued by this node");
        }
        let id = claim.id();
        if self.claims.contains_key(&id) {
            return Adoption::Known;
        }
        if !claim.live_at(now_ms) {
            return Adoption::Refused("expired");
        }
        if self.claims.len() >= MAX_KNOWN_CLAIMS {
            return Adoption::Refused("too many known claims");
        }
        let envelope = *self.envelope(claim.issuer);
        let cap = now_ms.saturating_add(ms(self.policy.max.min(envelope.max_ttl)));
        // A claim already given a lease here (before a restart) keeps that lease's end: the
        // local cap bounds a claim's total effect, not each lifetime of this process (R26-07).
        let cap = match self.lease_ends.get(&id) {
            Some((end, _)) => cap.min(*end),
            None => cap,
        };
        let until_ms = Some(claim.expires_ms.map_or(cap, |e| e.min(cap)));
        // Only a claim that could count takes a slot or waits for one: not one whose lease ran
        // out (before a restart), one the local policy refuses, or one already retracted (a
        // lifted claim resent by its issuer must not use up the issuer's quota).
        let lease_over = cap <= now_ms;
        let retracted = self
            .retractions
            .get(&id)
            .is_some_and(|r| r.operator || r.by_nodes.contains(&claim.issuer));
        let could_count = !lease_over && allowed && !retracted;
        let issuer = claim.issuer;
        let active = self.active_by_issuer.entry(issuer).or_insert(0);
        let in_quota = could_count && *active < envelope.max_active;
        if in_quota {
            *active += 1;
            // The lease starts with enforcement; a waiting claim records it when it gets a slot.
            self.record_lease(&id, cap, claim.expires_ms);
        } else if could_count {
            self.waiting
                .entry(issuer)
                .or_default()
                .push_back(id.clone());
        }
        self.insert_held(
            id.clone(),
            Held {
                claim,
                net,
                until_ms,
                allowed,
                in_quota,
                ended: lease_over,
            },
        );
        let was = self.applied.contains(&net);
        let result = self.reconcile(net, now_ms);
        let reason = self
            .claims
            .get(&id)
            .and_then(|held| self.hold_reason(&id, held, now_ms));
        match (result, reason) {
            (Ok(()), None) if !was && self.applied.contains(&net) => Adoption::Enforced,
            (Ok(()), None) => Adoption::Held("already blocked"),
            (Err(_), None) => Adoption::Held("map"),
            (_, Some(why)) => Adoption::Held(why),
        }
    }

    /// `issuer` (the authenticated sender) takes back its own claims. Retractions of claims it
    /// did not issue have no effect; retractions of claims not seen yet are kept, so a claim
    /// that arrives after its retraction stays retracted. Returns targets no longer blocked.
    pub fn retract(&mut self, issuer: u64, ids: &[ClaimId], now_ms: u64) -> Vec<IpNet> {
        let mut touched = Vec::new();
        for id in ids {
            let forget_ms = match self.claims.get(id) {
                Some(h) if h.claim.issuer != issuer => continue,
                Some(h) => {
                    touched.push(h.net);
                    h.claim.expires_ms
                }
                None => Some(now_ms.saturating_add(ms(self.policy.max))),
            };
            // R26-03: a new record takes the claim's end (or a bounded wait for an unseen claim);
            // "forever" only where the claim itself never expires. Merging keeps the later end.
            let full = self.retractions_full();
            match self.retractions.entry(id.clone()) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    if full {
                        continue;
                    }
                    v.insert(Retraction {
                        operator: false,
                        by_nodes: vec![issuer],
                        forget_ms,
                    });
                }
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    let r = o.get_mut();
                    if !r.by_nodes.contains(&issuer) && r.by_nodes.len() < MAX_RETRACTORS {
                        r.by_nodes.push(issuer);
                    }
                    r.forget_ms = match (r.forget_ms, forget_ms) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        _ => None,
                    };
                }
            }
            self.release_slot(id);
        }
        self.settle(touched, now_ms)
    }

    fn settle(&mut self, mut touched: Vec<IpNet>, now_ms: u64) -> Vec<IpNet> {
        touched.sort();
        touched.dedup();
        let mut lifted = Vec::new();
        for net in touched {
            let before = self.applied.contains(&net);
            let _ = self.reconcile(net, now_ms);
            if before && !self.applied.contains(&net) {
                lifted.push(net);
            }
        }
        lifted
    }

    fn lift_ids(&mut self, ids: Vec<ClaimId>) -> Lifted {
        let mut out = Lifted::default();
        for id in ids {
            let Some(h) = self.claims.get(&id) else {
                continue;
            };
            if h.claim.kind == ClaimKind::Operator {
                // Local only: no copy exists anywhere else, so it can simply go.
                let net = h.net;
                self.claims.remove(&id);
                if let Some(set) = self.by_target.get_mut(&net) {
                    set.remove(&id);
                    if set.is_empty() {
                        self.by_target.remove(&net);
                    }
                }
                out.claims += 1;
                continue;
            }
            let own_detector =
                h.claim.issuer == self.node_id && h.claim.kind == ClaimKind::Detector;
            // Kept as long as the claim can live anywhere (not just its local lease: a claim
            // that never had one, e.g. one waiting for a slot, would get a fresh lease when it
            // is resent after the record is gone). A claim that never expires keeps it for good.
            let forget_ms = h.claim.expires_ms;
            let r = self.retractions.entry(id.clone()).or_default();
            if !r.operator {
                out.claims += 1;
            }
            r.operator = true;
            r.forget_ms = forget_ms;
            if own_detector {
                if !r.by_nodes.contains(&self.node_id) {
                    r.by_nodes.push(self.node_id);
                }
                out.retracted.push(id);
            } else {
                self.release_slot(&id);
            }
        }
        self.dirty = true;
        out
    }

    /// Operator unban (ADR-1/ADR-2): lifts every claim on `net` except `--block`, here, for as
    /// long as those claims could live anywhere; this node's own detector claims are retracted
    /// mesh-wide. A later, new decision about `net` is a different claim and is not affected.
    pub fn lift(&mut self, net: IpNet, now_ms: u64) -> Result<Lifted, LiftError> {
        let net = canonical(net);
        let ids: Vec<ClaimId> = self
            .by_target
            .get(&net)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        // Lifts every decision about the target known now, enforced or not: a claim waiting
        // for a slot or a quorum must not re-block the target later.
        let mut liftable = Vec::new();
        let (mut has_static, mut blocked) = (false, false);
        for id in ids {
            let Some(h) = self.claims.get(&id) else {
                continue;
            };
            let effective = self.effective(&id, h, now_ms);
            if h.claim.kind == ClaimKind::Static {
                has_static |= effective;
            } else {
                blocked |= effective;
                liftable.push(id);
            }
        }
        if !blocked {
            return Err(if has_static {
                LiftError::Static
            } else {
                LiftError::NotBlocked
            });
        }
        self.strikes.remove(&net);
        let lifted = self.lift_ids(liftable);
        self.settle(vec![net], now_ms);
        Ok(lifted)
    }

    /// Targets of the operator bans in force, sorted.
    pub fn operator_targets(&self, now_ms: u64) -> Vec<IpNet> {
        let mut out: Vec<IpNet> = self
            .claims
            .iter()
            .filter(|(id, h)| h.claim.kind == ClaimKind::Operator && self.effective(id, h, now_ms))
            .map(|(_, h)| h.net)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Lifts operator bans and detector claims at once; `--block` stays.
    pub fn flush_all(&mut self, now_ms: u64) -> (Vec<IpNet>, Lifted) {
        let ids: Vec<ClaimId> = self
            .claims
            .iter()
            .filter(|(_, h)| h.claim.kind != ClaimKind::Static)
            .map(|(id, _)| id.clone())
            .collect();
        let nets: Vec<IpNet> = ids
            .iter()
            .filter_map(|id| self.claims.get(id).map(|h| h.net))
            .collect();
        let lifted = self.lift_ids(ids);
        (self.settle(nets, now_ms), lifted)
    }

    /// Operator flush: lifts every detector claim (any issuer); operator and `--block` stay.
    pub fn flush_detector(&mut self, now_ms: u64) -> (Vec<IpNet>, Lifted) {
        let ids: Vec<ClaimId> = self
            .claims
            .iter()
            .filter(|(_, h)| h.claim.kind == ClaimKind::Detector)
            .map(|(id, _)| id.clone())
            .collect();
        let nets: Vec<IpNet> = ids
            .iter()
            .filter_map(|id| self.claims.get(id).map(|h| h.net))
            .collect();
        let lifted = self.lift_ids(ids);
        (self.settle(nets, now_ms), lifted)
    }

    /// Ends what ran out, forgets what can no longer matter (claims past their global expiry and
    /// their retractions) and retries pending map operations. Returns targets no longer blocked.
    pub fn tick(&mut self, now_ms: u64) -> Vec<IpNet> {
        // Claims whose local end came are handled once, not on every later tick (R26-06).
        let mut touched: Vec<IpNet> = Vec::new();
        for h in self.claims.values_mut() {
            if !h.ended && h.until_ms.is_some_and(|u| u <= now_ms) {
                h.ended = true;
                touched.push(h.net);
            }
        }

        let dead: Vec<ClaimId> = self
            .claims
            .iter()
            .filter(|(_, h)| !h.claim.live_at(now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        // A peer's claim that ended here frees its slot, even while it lives elsewhere.
        let ended: Vec<ClaimId> = self
            .claims
            .iter()
            .filter(|(_, h)| h.in_quota && h.until_ms.is_some_and(|u| u <= now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ended {
            self.release_slot(id);
        }
        for id in dead {
            self.release_slot(&id);
            if let Some(h) = self.claims.remove(&id) {
                if let Some(set) = self.by_target.get_mut(&h.net) {
                    set.remove(&id);
                    if set.is_empty() {
                        self.by_target.remove(&h.net);
                    }
                }
                if h.claim.issuer == self.node_id {
                    self.dirty = true;
                }
            }
        }
        // Waiting claims take freed slots, oldest first.
        let issuers: Vec<u64> = self.waiting.keys().copied().collect();
        for issuer in issuers {
            let max = self.envelope(issuer).max_active;
            loop {
                if self.active_by_issuer.get(&issuer).copied().unwrap_or(0) >= max {
                    break;
                }
                let Some(id) = self.waiting.get_mut(&issuer).and_then(|q| q.pop_front()) else {
                    break;
                };
                // Enforcement starts now, so the local end is counted from now, but never past
                // a lease this claim already had (before a restart, R26-07).
                let cap =
                    now_ms.saturating_add(ms(self.policy.max.min(self.envelope(issuer).max_ttl)));
                let earlier = self.lease_ends.get(&id).map(|(end, _)| *end);
                let cap = earlier.map_or(cap, |end| cap.min(end));
                if cap <= now_ms {
                    continue;
                }
                // A claim retracted or refused by the policy while it waited takes no slot.
                let cannot_count = self
                    .claims
                    .get(&id)
                    .is_some_and(|h| !h.allowed || self.retracted(&id, h));
                if cannot_count {
                    continue;
                }
                if let Some(h) = self.claims.get_mut(&id) {
                    if !h.in_quota && h.claim.live_at(now_ms) {
                        h.in_quota = true;
                        h.until_ms = Some(h.claim.expires_ms.map_or(cap, |e| e.min(cap)));
                        h.ended = false;
                        *self.active_by_issuer.entry(issuer).or_insert(0) += 1;
                        touched.push(h.net);
                        let expires = h.claim.expires_ms;
                        self.record_lease(&id, cap, expires);
                    }
                }
            }
        }
        self.waiting.retain(|_, q| !q.is_empty());
        // A forgotten record must not leave its target's kernel entry stale.
        let claims = &self.claims;
        self.retractions.retain(|id, r| {
            let keep = r
                .forget_ms
                .is_none_or(|f| f.saturating_add(ms(FORGET_GRACE)) > now_ms);
            if !keep {
                if let Some(h) = claims.get(id) {
                    touched.push(h.net);
                }
            }
            keep
        });
        let before = self.lease_ends.len();
        self.lease_ends
            .retain(|_, (_, expires)| expires.is_none_or(|e| e > now_ms));
        if self.lease_ends.len() != before {
            self.dirty = true;
        }
        self.strikes
            .retain(|_, (_, last)| now_ms.saturating_sub(*last) <= ms(STRIKE_MEMORY));
        while let Some(&(net, seen)) = self.strike_order.front() {
            if self.strikes.get(&net).map(|&(_, last)| last) == Some(seen) {
                break;
            }
            self.strike_order.pop_front();
        }
        let mut lifted = self.settle(touched, now_ms);
        // Retries: at most MAX_RETRIES_PER_TICK targets, each once, in queue order.
        let n = self.retry.len().min(MAX_RETRIES_PER_TICK);
        for _ in 0..n {
            let Some(net) = self.retry.pop_front() else {
                break;
            };
            self.queued.remove(&net);
            if self.pending.contains(&net) {
                lifted.extend(self.settle(vec![net], now_ms));
            }
        }
        lifted
    }

    /// Blocks the kernel enforces (for metrics and Flowspec).
    pub fn active(&self) -> usize {
        self.applied.len()
    }

    pub fn active_by_family(&self) -> (usize, usize) {
        self.applied.iter().fold((0, 0), |(v4, v6), n| match n {
            IpNet::V4(_) => (v4 + 1, v6),
            IpNet::V6(_) => (v4, v6 + 1),
        })
    }

    pub fn active_ips(&self) -> HashSet<IpNet> {
        self.applied.clone()
    }

    /// Targets whose kernel entry does not yet match the claims.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// How long the oldest pending map operation has been failing.
    pub fn oldest_pending(&self, now_ms: u64) -> Duration {
        self.pending_since
            .values()
            .min()
            .map_or(Duration::ZERO, |since| {
                Duration::from_millis(now_ms.saturating_sub(*since))
            })
    }

    pub fn is_blocked(&self, net: IpNet) -> bool {
        self.applied.contains(&canonical(net))
    }

    /// What this node sends a peer (R26-01): only its own live detector claims and its own
    /// retractions. A node speaks only for itself; other nodes' claims come from those nodes, so
    /// a relay cannot introduce claims (or quorum votes) in another node's name.
    pub fn snapshot(&self, now_ms: u64) -> (Vec<Claim>, Vec<ClaimId>) {
        let mut claims: Vec<(&ClaimId, &Claim)> = self
            .claims
            .iter()
            .filter(|(id, h)| h.claim.issuer == self.node_id && self.shared(id, h, now_ms))
            .map(|(id, h)| (id, &h.claim))
            .collect();
        claims.sort_by(|a, b| a.0.cmp(b.0));
        let mut retracted: Vec<ClaimId> = self
            .retractions
            .iter()
            .filter(|(_, r)| r.by_nodes.contains(&self.node_id))
            .map(|(id, _)| id.clone())
            .collect();
        retracted.sort();
        (
            claims.into_iter().map(|(_, c)| c.clone()).collect(),
            retracted,
        )
    }

    fn shared(&self, id: &ClaimId, h: &Held, now_ms: u64) -> bool {
        h.claim.kind == ClaimKind::Detector
            && h.claim.live_at(now_ms)
            && !self
                .retractions
                .get(id)
                .is_some_and(|r| r.by_nodes.contains(&h.claim.issuer))
    }

    /// Digest of `issuer`'s live, unretracted detector claims as this node knows them. A node
    /// sends the digest of its own claims; a peer whose view of them differs asks it for a
    /// snapshot.
    pub fn digest_of(&self, issuer: u64, now_ms: u64) -> String {
        let mut ids: Vec<&ClaimId> = self
            .claims
            .iter()
            .filter(|(id, h)| h.claim.issuer == issuer && self.shared(id, h, now_ms))
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        let mut hasher = blake3::Hasher::new();
        for id in ids {
            hasher.update(id.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Digest of this node's own shared claims.
    pub fn digest(&self, now_ms: u64) -> String {
        self.digest_of(self.node_id, now_ms)
    }

    /// Marks the durable part as changed (e.g. after a failed write, to retry it).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Whether the durable part changed since the last [`Self::take_persisted`].
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn take_persisted(&mut self, now_ms: u64) -> Persisted {
        self.dirty = false;
        let mut own: Vec<(&ClaimId, &Claim)> = self
            .claims
            .iter()
            .filter(|(_, h)| {
                h.claim.issuer == self.node_id
                    && h.claim.kind != ClaimKind::Static
                    && h.claim.live_at(now_ms)
            })
            .map(|(id, h)| (id, &h.claim))
            .collect();
        own.sort_by(|a, b| a.0.cmp(b.0));
        let claims: Vec<Claim> = own.into_iter().map(|(_, c)| c.clone()).collect();
        let mut operator_lifts = Vec::new();
        let mut retracted = Vec::new();
        for (id, r) in &self.retractions {
            if r.operator {
                operator_lifts.push((id.clone(), r.forget_ms));
            }
            if r.by_nodes.contains(&self.node_id) {
                retracted.push((id.clone(), r.forget_ms));
            }
        }
        operator_lifts.sort();
        retracted.sort();
        let mut peer_ends: Vec<(ClaimId, u64, Option<u64>)> = self
            .lease_ends
            .iter()
            .filter(|(_, (_, expires))| expires.is_none_or(|e| e > now_ms))
            .map(|(id, (end, expires))| (id.clone(), *end, *expires))
            .collect();
        peer_ends.sort();
        let events = self
            .event_order
            .iter()
            .filter(|(key, seen)| self.events.get(key) == Some(seen))
            .filter(|(_, seen)| now_ms.saturating_sub(*seen) <= ms(EVENT_MEMORY))
            .map(|(key, seen)| (crate::p2p::to_hex(key), *seen))
            .collect();
        Persisted {
            schema: STATE_SCHEMA,
            claims,
            operator_lifts,
            retracted,
            peer_ends,
            events,
        }
    }

    /// Restores this node's decisions after a restart. `allowed` re-checks each target against
    /// the current never-block policy (it may have changed). Returns (restored, refused).
    pub fn restore(
        &mut self,
        state: Persisted,
        allowed: impl Fn(IpNet) -> bool,
        now_ms: u64,
    ) -> (usize, usize) {
        let mut events: Vec<([u8; 16], u64)> = state
            .events
            .iter()
            .filter(|(_, seen)| now_ms.saturating_sub(*seen) <= ms(EVENT_MEMORY))
            .filter_map(|(hex, seen)| {
                let bytes = crate::p2p::from_hex(hex).ok()?;
                Some((<[u8; 16]>::try_from(bytes.as_slice()).ok()?, *seen))
            })
            .collect();
        events.sort_by_key(|(_, seen)| *seen);
        let skip = events.len().saturating_sub(MAX_EVENTS);
        for (key, seen) in events.into_iter().skip(skip) {
            self.events.insert(key, seen);
            self.event_order.push_back((key, seen));
        }
        for (id, end, expires) in state.peer_ends {
            if expires.is_none_or(|e| e > now_ms) && self.lease_ends.len() < MAX_KNOWN_CLAIMS {
                self.lease_ends.insert(id, (end, expires));
            }
        }
        for (id, forget_ms) in state.operator_lifts {
            let r = self.retractions.entry(id).or_default();
            r.operator = true;
            r.forget_ms = forget_ms;
        }
        for (id, forget_ms) in state.retracted {
            let r = self.retractions.entry(id).or_default();
            r.by_nodes.push(self.node_id);
            r.forget_ms = forget_ms;
        }
        let (mut restored, mut refused) = (0, 0);
        let mut nets = Vec::new();
        for claim in state.claims {
            let Some(net) = claim.net() else {
                refused += 1;
                continue;
            };
            if claim.issuer != self.node_id
                || claim.kind == ClaimKind::Static
                || !claim.live_at(now_ms)
            {
                refused += 1;
                continue;
            }
            let ok = allowed(net);
            if !ok {
                refused += 1;
            } else {
                restored += 1;
            }
            let id = claim.id();
            self.insert_held(
                id,
                Held {
                    until_ms: claim.expires_ms,
                    claim,
                    net,
                    allowed: ok,
                    in_quota: true,
                    ended: false,
                },
            );
            nets.push(net);
        }
        self.settle(nets, now_ms);
        (restored, refused)
    }
}

/// Share of a blocklist map in use at which the operator is warned.
pub const WATERMARK: f64 = 0.8;

/// Tracks whether each family is above the watermark, reporting only crossings.
#[derive(Default)]
pub struct Watermark {
    above: [bool; 2],
}

impl Watermark {
    /// Returns a message when a family crosses the watermark in either direction.
    pub fn update(&mut self, (v4, v6): (usize, usize), capacity: usize) -> Vec<String> {
        let mut messages = Vec::new();
        let families = [("IPv4", v4), ("IPv6", v6)];
        for ((name, used), was_above) in families.into_iter().zip(self.above.iter_mut()) {
            let above = used as f64 >= capacity as f64 * WATERMARK;
            if above != *was_above {
                *was_above = above;
                messages.push(if above {
                    format!(
                        "{} blocklist is {}/{} full; new blocks will fail at capacity",
                        name, used, capacity
                    )
                } else {
                    format!(
                        "{} blocklist back below {:.0}% ({}/{})",
                        name,
                        WATERMARK * 100.0,
                        used,
                        capacity
                    )
                });
            }
        }
        messages
    }
}

/// The kernel side of the table: one entry per blocked network.
pub trait Blocklist {
    fn add(&mut self, net: IpNet) -> Result<(), MapError>;
    fn delete(&mut self, net: IpNet) -> Result<(), MapError>;
    /// Packets the entry for `net` has dropped so far (the XDP program counts them in the
    /// entry's value); `None` if it cannot be read.
    fn hits(&self, net: IpNet) -> Option<u64>;
}

/// The XDP program's LPM tries and their per-CPU drop counters. Each entry's value is its
/// counter slot; slots are handed out here and zeroed before reuse.
pub struct KernelBlocklist {
    v4: LpmTrie<MapData, [u8; 4], u32>,
    v6: LpmTrie<MapData, [u8; 16], u32>,
    hits: PerCpuArray<MapData, u64>,
    cpus: usize,
    free_slots: Vec<u32>,
    slot_of: HashMap<IpNet, u32>,
}

impl KernelBlocklist {
    pub fn new(
        v4: LpmTrie<MapData, [u8; 4], u32>,
        v6: LpmTrie<MapData, [u8; 16], u32>,
        hits: PerCpuArray<MapData, u64>,
        cpus: usize,
    ) -> Self {
        Self {
            v4,
            v6,
            hits,
            cpus,
            free_slots: (0..common::BLOCK_HIT_SLOTS).rev().collect(),
            slot_of: HashMap::new(),
        }
    }

    fn zero(&mut self, slot: u32) -> Result<(), MapError> {
        // Only an empty vector is refused, and `cpus` (the kernel's possible CPUs) is never 0.
        let zeros =
            PerCpuValues::try_from(vec![0u64; self.cpus]).map_err(|_| MapError::OutOfBounds {
                index: slot,
                max_entries: common::BLOCK_HIT_SLOTS,
            })?;
        self.hits.set(slot, zeros, 0)
    }
}

impl Blocklist for KernelBlocklist {
    fn add(&mut self, net: IpNet) -> Result<(), MapError> {
        let slot = match self.slot_of.get(&net) {
            Some(slot) => *slot,
            None => self.free_slots.pop().ok_or(MapError::OutOfBounds {
                index: common::BLOCK_HIT_SLOTS,
                max_entries: common::BLOCK_HIT_SLOTS,
            })?,
        };
        let result = self.zero(slot).and_then(|()| match net {
            IpNet::V4(n) => self.v4.insert(
                &Key::new(n.prefix_len() as u32, n.network().octets()),
                slot,
                0,
            ),
            IpNet::V6(n) => self.v6.insert(
                &Key::new(n.prefix_len() as u32, n.network().octets()),
                slot,
                0,
            ),
        });
        match result {
            Ok(()) => {
                self.slot_of.insert(net, slot);
                Ok(())
            }
            Err(e) => {
                if self.slot_of.get(&net) != Some(&slot) {
                    self.free_slots.push(slot);
                }
                Err(e)
            }
        }
    }

    fn delete(&mut self, net: IpNet) -> Result<(), MapError> {
        let result = match net {
            IpNet::V4(n) => self
                .v4
                .remove(&Key::new(n.prefix_len() as u32, n.network().octets())),
            IpNet::V6(n) => self
                .v6
                .remove(&Key::new(n.prefix_len() as u32, n.network().octets())),
        };
        // The slot is free once the entry is gone (a packet in flight may still count into it;
        // it is zeroed before reuse).
        if matches!(result, Ok(()) | Err(MapError::KeyNotFound)) {
            if let Some(slot) = self.slot_of.remove(&net) {
                self.free_slots.push(slot);
            }
        }
        result
    }

    fn hits(&self, net: IpNet) -> Option<u64> {
        let slot = self.slot_of.get(&net)?;
        let per_cpu = self.hits.get(slot, 0).ok()?;
        Some(per_cpu.iter().fold(0u64, |sum, v| sum.saturating_add(*v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const POLICY: TtlPolicy = TtlPolicy {
        base: Duration::from_secs(60),
        max: Duration::from_secs(600),
    };
    const T0: u64 = 1_000_000_000;
    const S: u64 = 1000;

    fn ip(s: &str) -> IpNet {
        parse_target(s).unwrap()
    }

    /// A kernel map stand-in with a fixed capacity and injectable delete failures.
    struct FakeLists {
        nets: HashSet<IpNet>,
        capacity: usize,
        fail_delete: bool,
        deletes: usize,
        /// Packets "dropped" per entry, set by tests.
        hits: HashMap<IpNet, u64>,
    }

    impl Blocklist for FakeLists {
        fn add(&mut self, net: IpNet) -> Result<(), MapError> {
            if !self.nets.contains(&net) && self.nets.len() >= self.capacity {
                return Err(MapError::OutOfBounds {
                    index: self.nets.len() as u32,
                    max_entries: self.capacity as u32,
                });
            }
            self.nets.insert(net);
            Ok(())
        }

        fn delete(&mut self, net: IpNet) -> Result<(), MapError> {
            self.deletes += 1;
            if self.fail_delete {
                return Err(MapError::ElementNotFound);
            }
            if self.nets.remove(&net) {
                Ok(())
            } else {
                Err(MapError::KeyNotFound)
            }
        }

        fn hits(&self, net: IpNet) -> Option<u64> {
            self.nets
                .contains(&net)
                .then(|| self.hits.get(&net).copied().unwrap_or(0))
        }
    }

    fn table(node: u64, capacity: usize) -> BlockTable<FakeLists> {
        BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            POLICY,
            node,
        )
    }

    fn detect(t: &mut BlockTable<FakeLists>, target: &str, now: u64) -> Claim {
        t.add_local(ip(target), ClaimKind::Detector, "test", now)
            .unwrap()
            .claim
    }

    #[test]
    fn a_replayed_event_is_seen_once() {
        let mut t = table(1, 64);
        assert!(t.first_sighting("crowdsec", "17", T0));
        assert!(
            !t.first_sighting("crowdsec", "17", T0 + S),
            "a replay of the same event"
        );
        assert!(
            t.first_sighting("suricata", "17", T0 + S),
            "the same id from another source is another event"
        );
        assert!(t.first_sighting("crowdsec", "18", T0 + S));
        let later = T0 + ms(EVENT_MEMORY) + 2 * S;
        assert!(
            t.first_sighting("crowdsec", "17", later),
            "forgotten after EVENT_MEMORY"
        );
        assert_eq!(t.event_memory(), (1, 0), "expired ids are dropped");
    }

    #[test]
    fn a_replayed_event_is_a_duplicate_after_a_restart() {
        // R27-05 (Codex's probe): event crowdsec/17 blocks until T0+60 s; after a restart at
        // T0+50 s the same event was new again and moved the block's end to T0+110 s.
        let mut a = table(1, 64);
        assert!(a.first_sighting("crowdsec", "17", T0));
        let first = detect(&mut a, "198.51.100.8", T0);
        assert_eq!(first.expires_ms, Some(T0 + 60 * S));
        let saved = serde_json::to_vec(&a.take_persisted(T0 + 50 * S)).unwrap();
        let mut b = table(1, 64);
        b.restore(
            serde_json::from_slice(&saved).unwrap(),
            |_| true,
            T0 + 50 * S,
        );
        assert!(
            !b.first_sighting("crowdsec", "17", T0 + 50 * S),
            "the replayed event was taken as new after the restart"
        );
        assert!(
            b.first_sighting("crowdsec", "18", T0 + 50 * S),
            "a new event still counts"
        );
        // Remembered for EVENT_MEMORY from when it was first seen, restart or not.
        let saved = serde_json::to_vec(&b.take_persisted(T0 + 60 * S)).unwrap();
        let mut c = table(1, 64);
        let late = T0 + ms(EVENT_MEMORY) + S;
        c.restore(serde_json::from_slice(&saved).unwrap(), |_| true, late);
        assert!(
            c.first_sighting("crowdsec", "17", late),
            "forgotten after EVENT_MEMORY"
        );
        assert_eq!(c.event_memory().0, 2, "18 (seen later) is still remembered");
    }

    #[test]
    fn a_new_event_is_saved_even_when_it_adds_no_claim() {
        let mut t = table(1, 64);
        let _ = t.take_persisted(T0);
        assert!(!t.dirty());
        assert!(t.first_sighting("crowdsec", "5", T0));
        assert!(t.dirty(), "a remembered event must reach the state file");
    }

    #[test]
    fn event_memory_is_bounded() {
        let mut t = table(1, 64);
        for i in 0..=MAX_EVENTS {
            assert!(t.first_sighting("x", &i.to_string(), T0));
        }
        assert_eq!(t.event_memory(), (MAX_EVENTS, 1));
        assert!(
            t.first_sighting("x", "0", T0),
            "the oldest id was forgotten to make room"
        );
        assert!(!t.first_sighting("x", &MAX_EVENTS.to_string(), T0));
    }

    #[test]
    fn every_removed_block_leaves_its_outcome() {
        let mut t = table(1, 64);
        let (busy, idle) = (ip("203.0.113.50"), ip("203.0.113.51"));
        detect(&mut t, "203.0.113.50", T0);
        detect(&mut t, "203.0.113.51", T0);
        t.lists.hits.insert(busy, 42);
        // A failed delete leaves no outcome: the entry is still in force.
        t.lists.fail_delete = true;
        t.lift(busy, T0 + 10 * S).unwrap();
        assert!(t.take_outcomes().0.is_empty());
        t.lists.fail_delete = false;
        t.tick(T0 + 11 * S); // the retry succeeds
        let expired_at = T0 + ms(POLICY.base);
        t.tick(expired_at);
        let (outcomes, lost) = t.take_outcomes();
        assert_eq!(lost, 0);
        assert_eq!(
            outcomes,
            vec![
                Outcome {
                    net: busy,
                    cause: "detector: test".into(),
                    hits: Some(42),
                    applied_ms: T0,
                    removed_ms: T0 + 11 * S
                },
                Outcome {
                    net: idle,
                    cause: "detector: test".into(),
                    hits: Some(0),
                    applied_ms: T0,
                    removed_ms: expired_at
                },
            ]
        );
        assert!(t.take_outcomes().0.is_empty(), "collected once");
    }

    #[test]
    fn an_outcome_names_the_decision_that_applied_the_block() {
        let mut t = table(1, 64);
        let net = ip("203.0.113.60");
        let peer = Claim {
            issuer: 2,
            kind: ClaimKind::Detector,
            target: "203.0.113.60".into(),
            issued_ms: T0 - S,
            expires_ms: Some(T0 + 600 * S),
            reason: "suricata: sid:2001219".into(),
        };
        t.adopt(peer, true, T0);
        // A later local decision on the same target does not change who applied it.
        t.add_local(net, ClaimKind::Operator, "ban", T0 + S)
            .unwrap();
        t.lift(net, T0 + 2 * S).unwrap();
        let (outcomes, _) = t.take_outcomes();
        assert_eq!(outcomes[0].cause, "peer 2: suricata: sid:2001219");
    }

    #[test]
    fn uncollected_outcomes_are_bounded_and_counted() {
        let mut t = table(1, MAX_OUTCOMES + 10);
        for i in 0..(MAX_OUTCOMES + 3) as u32 {
            let net = host(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                0x0A00_0000 + i,
            )));
            t.add_local(net, ClaimKind::Operator, "x", T0).unwrap();
            t.lift(net, T0 + S).unwrap();
        }
        let (outcomes, lost) = t.take_outcomes();
        assert_eq!((outcomes.len(), lost), (MAX_OUTCOMES, 3));
    }

    #[test]
    fn a_repeat_merged_into_the_running_claim_is_not_new() {
        let mut t = table(1, 64);
        let a = ip("203.0.113.40");
        assert!(t.add_local(a, ClaimKind::Detector, "x", T0).unwrap().new);
        assert!(
            t.add_local(a, ClaimKind::Detector, "x", T0).unwrap().new,
            "escalation"
        );
        // At the cap, repeats within a quarter of the lifetime are the same decision.
        for _ in 0..8 {
            let _ = t.add_local(a, ClaimKind::Detector, "x", T0);
        }
        let repeat = t.add_local(a, ClaimKind::Detector, "x", T0).unwrap();
        assert!(!repeat.new, "the running claim must not be shared again");
    }

    #[test]
    fn detector_blocks_escalate_and_are_capped() {
        let mut t = table(1, 64);
        let a = ip("203.0.113.1");
        let ttl = |t: &mut BlockTable<FakeLists>, now| {
            t.add_local(a, ClaimKind::Detector, "x", now).unwrap().ttl
        };
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(60)));
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(120)));
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(240)));
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(480)));
        // At the cap a repeat that would not extend the block by a quarter is coalesced: it
        // reports the running block instead of adding a claim.
        for _ in 0..40 {
            assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(480)));
        }
        assert_eq!(
            ttl(&mut t, T0 + 150 * S),
            Some(Duration::from_secs(600)),
            "capped"
        );
        let later = T0 + 150 * S + ms(STRIKE_MEMORY) + S;
        assert_eq!(
            ttl(&mut t, later),
            Some(Duration::from_secs(60)),
            "strikes forgotten"
        );
    }

    /// Every distinct source a detector reports gets a strike. A flood of distinct sources must
    /// not grow that memory past MAX_STRIKES: the oldest are forgotten and counted.
    #[test]
    fn strike_memory_is_bounded_by_count() {
        let v4 = |i: u32| {
            IpNet::from(std::net::IpAddr::from(std::net::Ipv4Addr::from(
                0x0A00_0000 + i,
            )))
        };
        let mut t = table(1, 64);
        let extra = 100;
        for i in 0..(MAX_STRIKES + extra) as u32 {
            let net = v4(i);
            let _ = t.add_local(net, ClaimKind::Detector, "flood", T0 + u64::from(i));
        }
        assert_eq!(t.strike_memory(), (MAX_STRIKES, extra as u64));
        let after = T0 + (MAX_STRIKES + extra) as u64 + S;
        let ttl_of = |t: &mut BlockTable<FakeLists>, net| {
            t.add_local(net, ClaimKind::Detector, "again", after)
                .unwrap()
                .ttl
        };
        // The newest target still has its strike: a repeat now doubles its block.
        let newest = v4((MAX_STRIKES + extra - 1) as u32);
        assert_eq!(ttl_of(&mut t, newest), Some(Duration::from_secs(120)));
        // The oldest was forgotten: it starts over at base.
        let oldest = v4(0);
        assert_eq!(ttl_of(&mut t, oldest), Some(Duration::from_secs(60)));
    }

    #[test]
    fn expiry_unblocks_once_and_a_shorter_repeat_does_not_cut_a_longer_block() {
        let mut t = table(1, 64);
        let a = ip("203.0.113.2");
        detect(&mut t, "203.0.113.2", T0); // 60 s
        detect(&mut t, "203.0.113.2", T0); // 120 s
        assert!(
            t.tick(T0 + 61 * S).is_empty(),
            "the 120 s claim still holds"
        );
        assert!(t.is_blocked(a));
        assert_eq!(t.tick(T0 + 120 * S), vec![a]);
        assert!(t.tick(T0 + 121 * S).is_empty(), "reported once");
        assert_eq!(t.active(), 0);
    }

    #[test]
    fn zero_base_makes_detector_blocks_permanent() {
        let mut t = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 8,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            TtlPolicy {
                base: Duration::ZERO,
                max: Duration::ZERO,
            },
            1,
        );
        let c = t
            .add_local(ip("203.0.113.5"), ClaimKind::Detector, "x", T0)
            .unwrap()
            .claim;
        assert_eq!(c.expires_ms, None);
        assert!(t.tick(T0 + 10_000_000 * S).is_empty());
        assert_eq!(t.active(), 1);
    }

    #[test]
    fn only_the_configuration_lifts_a_static_block() {
        let mut t = table(1, 64);
        let a = ip("198.51.100.1");
        t.add_local(a, ClaimKind::Static, "--block", T0).unwrap();
        assert_eq!(t.lift(a, T0), Err(LiftError::Static));
        detect(&mut t, "198.51.100.1", T0);
        assert_eq!(
            t.lift(a, T0).unwrap().claims,
            1,
            "the detector claim is lifted"
        );
        assert!(t.is_blocked(a), "the static one stays");
        assert_eq!(t.lift(ip("198.51.100.2"), T0), Err(LiftError::NotBlocked));
    }

    #[test]
    fn operator_ban_and_unban() {
        let mut t = table(1, 64);
        let a = ip("198.51.100.3");
        t.add_local(a, ClaimKind::Operator, "operator", T0)
            .unwrap()
            .applied
            .unwrap();
        assert!(
            t.tick(T0 + 10_000_000 * S).is_empty(),
            "operator bans do not expire"
        );
        assert_eq!(
            t.lift(a, T0).unwrap(),
            Lifted {
                claims: 1,
                retracted: vec![]
            }
        );
        assert!(!t.is_blocked(a));
        let (_, lifted) = t.flush_detector(T0);
        assert_eq!(lifted.claims, 0);
    }

    #[test]
    fn a_peer_cannot_retract_another_nodes_claim() {
        // ADR-1: node 2 tries to take back node 1's local detection.
        let mut n1 = table(1, 64);
        let own = detect(&mut n1, "203.0.113.10", T0);
        assert!(n1.retract(2, &[own.id()], T0).is_empty());
        assert!(n1.is_blocked(ip("203.0.113.10")));
        // The issuer may take back its own claim.
        let mut n2 = table(2, 64);
        assert_eq!(n2.adopt(own.clone(), true, T0), Adoption::Enforced);
        assert_eq!(n2.retract(1, &[own.id()], T0), vec![ip("203.0.113.10")]);
        assert!(!n2.is_blocked(ip("203.0.113.10")));
    }

    #[test]
    fn another_nodes_retraction_cannot_displace_the_issuers() {
        // Known claim: node 3 "retracts" node 1's claim after node 1 did.
        let mut n1 = table(1, 64);
        let c = detect(&mut n1, "203.0.113.18", T0);
        let mut n2 = table(2, 64);
        n2.adopt(c.clone(), true, T0);
        n2.retract(1, &[c.id()], T0);
        n2.retract(3, &[c.id()], T0);
        assert!(!n2.is_blocked(ip("203.0.113.18")));
        // Unknown claim: the issuer's retraction arrives first, then node 3's, then the claim.
        let mut n4 = table(4, 64);
        n4.retract(1, &[c.id()], T0);
        n4.retract(3, &[c.id()], T0);
        n4.adopt(c, true, T0);
        assert!(
            !n4.is_blocked(ip("203.0.113.18")),
            "the claim came back to life"
        );
    }

    #[test]
    fn a_retraction_that_arrives_first_still_applies() {
        let mut n1 = table(1, 64);
        let c = detect(&mut n1, "203.0.113.11", T0);
        let mut n2 = table(2, 64);
        n2.retract(1, &[c.id()], T0);
        assert_eq!(n2.adopt(c, true, T0), Adoption::Held("retracted"));
        assert!(!n2.is_blocked(ip("203.0.113.11")));
    }

    #[test]
    fn an_operator_lift_holds_against_every_copy_of_the_lifted_claims() {
        // ADR-2 without a time bound: the lift names claims, so it holds however long a peer's
        // copy lives (the heterogeneous-max refutation), and a new decision is not affected.
        let mut peer = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 64,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            TtlPolicy {
                base: Duration::from_secs(7 * 86_400),
                max: Duration::from_secs(7 * 86_400),
            },
            2,
        );
        let long = detect(&mut peer, "203.0.113.12", T0);
        let mut n1 = table(1, 64);
        let a = ip("203.0.113.12");
        assert_eq!(n1.adopt(long.clone(), true, T0), Adoption::Enforced);
        n1.lift(a, T0 + S).unwrap();
        for day in 0..7 {
            let now = T0 + day * 86_400 * S + 2 * S;
            n1.tick(now);
            assert!(matches!(
                n1.adopt(long.clone(), true, now),
                Adoption::Known | Adoption::Held(_)
            ));
            assert!(!n1.is_blocked(a), "day {}: the lifted claim came back", day);
            // After a restart the peer's copy arrives as new (peer claims are not persisted):
            // only the persisted lift, which names the claim, keeps it out.
            let mut restarted = table(1, 64);
            restarted.restore(n1.take_persisted(now), |_| true, now);
            restarted.adopt(long.clone(), true, now);
            assert!(
                !restarted.is_blocked(a),
                "day {}: back after a restart",
                day
            );
        }
        // A repeat on the peer within a quarter of the block's lifetime is the same decision
        // (coalesced, R26-05), so the lift still holds against it...
        let repeat = detect(&mut peer, "203.0.113.12", T0 + 3 * S);
        assert_eq!(repeat.id(), long.id());
        // ...while a detection that extends the block by a quarter or more is a new claim.
        let later = T0 + 2 * 86_400 * S;
        let fresh = detect(&mut peer, "203.0.113.12", later);
        assert_ne!(fresh.id(), long.id());
        assert_eq!(n1.adopt(fresh, true, later), Adoption::Enforced);
    }

    #[test]
    fn a_peer_claim_is_capped_at_the_local_maximum() {
        let mut peer = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 8,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            TtlPolicy {
                base: Duration::ZERO,
                max: Duration::ZERO,
            },
            2,
        );
        let forever = detect(&mut peer, "203.0.113.13", T0);
        let mut n1 = table(1, 64);
        n1.adopt(forever.clone(), true, T0);
        assert_eq!(n1.tick(T0 + ms(POLICY.max)), vec![ip("203.0.113.13")]);
        assert_eq!(
            n1.adopt(forever, true, T0 + ms(POLICY.max) + S),
            Adoption::Known,
            "not re-imposed"
        );
        assert!(!n1.is_blocked(ip("203.0.113.13")));
    }

    #[test]
    fn a_block_the_map_cannot_take_is_pending_not_counted_and_retried() {
        // F01: desired and applied are kept apart.
        let mut t = table(1, 1);
        detect(&mut t, "198.51.100.20", T0);
        let added = t
            .add_local(ip("198.51.100.21"), ClaimKind::Detector, "x", T0 + 30 * S)
            .unwrap();
        assert!(added.applied.is_err());
        assert_eq!(
            (t.active(), t.pending()),
            (1, 1),
            "only what the kernel enforces is counted"
        );
        assert!(!t.is_blocked(ip("198.51.100.21")));
        t.tick(T0 + 61 * S); // the first block ends, a slot frees, the pending one (to T0+90 s) is retried
        assert!(t.is_blocked(ip("198.51.100.21")));
        assert_eq!(t.pending(), 0);
    }

    #[test]
    fn a_failed_removal_is_not_reported_and_is_retried() {
        // F02: the kernel entry outlives a failed delete; the table keeps trying.
        let mut t = table(1, 8);
        let a = ip("198.51.100.22");
        detect(&mut t, "198.51.100.22", T0);
        t.lists.fail_delete = true;
        assert!(t.tick(T0 + 61 * S).is_empty(), "not reported as unblocked");
        assert!(t.is_blocked(a) && t.lists.nets.contains(&a));
        assert_eq!(t.pending(), 1);
        t.lists.fail_delete = false;
        assert_eq!(t.tick(T0 + 62 * S), vec![a]);
        assert!(!t.lists.nets.contains(&a));
    }

    #[test]
    fn protected_targets_are_known_and_shared_but_not_enforced() {
        let mut n2 = table(2, 8);
        let c = detect(&mut n2, "203.0.113.14", T0);
        let mut n1 = table(1, 8);
        assert_eq!(n1.adopt(c, false, T0), Adoption::Held("protected"));
        assert!(!n1.is_blocked(ip("203.0.113.14")));
        assert_eq!(
            n1.digest_of(2, T0),
            n2.digest(T0),
            "the mesh state converges regardless of policy"
        );
    }

    #[test]
    fn peers_cannot_forge_this_nodes_or_non_detector_claims() {
        let mut n1 = table(1, 8);
        let mut forged = table(1, 8);
        let mine = detect(&mut forged, "203.0.113.15", T0);
        assert!(matches!(n1.adopt(mine, true, T0), Adoption::Refused(_)));
        let mut n2 = table(2, 8);
        let op = n2
            .add_local(ip("203.0.113.16"), ClaimKind::Operator, "x", T0)
            .unwrap()
            .claim;
        assert!(matches!(n1.adopt(op, true, T0), Adoption::Refused(_)));
        let mut odd = detect(&mut n2, "203.0.113.17", T0);
        odd.target = "203.0.113.17/32".into();
        assert!(matches!(n1.adopt(odd, true, T0), Adoption::Refused(_)));
    }

    /// Two nodes exchange snapshots (claims + own retractions), in both directions.
    fn exchange(a: &mut BlockTable<FakeLists>, b: &mut BlockTable<FakeLists>, now: u64) {
        let (ac, ar) = a.snapshot(now);
        let (bc, br) = b.snapshot(now);
        for c in ac {
            b.adopt(c, true, now);
        }
        b.retract(a.node_id, &ar, now);
        for c in bc {
            a.adopt(c, true, now);
        }
        a.retract(b.node_id, &br, now);
    }

    /// Every node's view of every issuer's claims equals that issuer's own digest.
    fn converged(nodes: &[&BlockTable<FakeLists>], now: u64) -> bool {
        nodes.iter().all(|issuer| {
            let own = issuer.digest(now);
            nodes
                .iter()
                .all(|n| n.digest_of(issuer.node_id, now) == own)
        })
    }

    #[test]
    fn one_exchange_with_each_issuer_converges_including_retractions() {
        let (mut n1, mut n2, mut n3) = (table(1, 64), table(2, 64), table(3, 64));
        detect(&mut n1, "203.0.113.30", T0);
        let c2 = detect(&mut n2, "203.0.113.31", T0);
        exchange(&mut n1, &mut n2, T0);
        exchange(&mut n1, &mut n3, T0);
        exchange(&mut n2, &mut n3, T0);
        assert!(converged(&[&n1, &n2, &n3], T0));
        // n2 retracts its claim while n3 is cut off; n3's view of n2 differs until they exchange.
        n2.retract(2, &[c2.id()], T0 + S);
        exchange(&mut n1, &mut n2, T0 + S);
        assert_ne!(n3.digest_of(2, T0 + S), n2.digest(T0 + S));
        exchange(&mut n2, &mut n3, T0 + 2 * S);
        assert!(converged(&[&n1, &n2, &n3], T0 + 2 * S));
        assert!(!n3.is_blocked(ip("203.0.113.31")));
        assert!(n3.is_blocked(ip("203.0.113.30")));
    }

    #[test]
    fn a_snapshot_carries_only_the_nodes_own_claims() {
        // R26-01: n1 knows n2's claim but never passes it on in n2's name.
        let mut n2 = table(2, 64);
        let theirs = detect(&mut n2, "203.0.113.32", T0);
        let mut n1 = table(1, 64);
        n1.adopt(theirs, true, T0);
        let mine = detect(&mut n1, "203.0.113.33", T0);
        let (claims, _) = n1.snapshot(T0);
        assert_eq!(claims, vec![mine]);
    }

    #[test]
    fn a_revoked_origin_stops_counting() {
        let mut n2 = table(2, 64);
        let c = detect(&mut n2, "203.0.113.34", T0);
        let mut n1 = table(1, 64);
        n1.set_pinned([2].into_iter().collect(), T0);
        assert_eq!(n1.adopt(c.clone(), true, T0), Adoption::Enforced);
        n1.set_pinned(HashSet::new(), T0 + S); // node 2 removed from the peers file
        assert!(!n1.is_blocked(ip("203.0.113.34")));
        let mut n3 = table(3, 64);
        n3.set_pinned([2].into_iter().collect(), T0);
        let unknown = detect(&mut table(9, 8), "203.0.113.35", T0);
        assert_eq!(
            n3.adopt(unknown, true, T0),
            Adoption::Held("revoked"),
            "an unknown origin"
        );
    }

    #[test]
    fn a_flush_lifts_all_detector_claims_and_retracts_own_ones() {
        let mut n2 = table(2, 64);
        let theirs = detect(&mut n2, "203.0.113.40", T0);
        let mut n1 = table(1, 64);
        n1.adopt(theirs, true, T0);
        let mine = detect(&mut n1, "203.0.113.41", T0);
        n1.add_local(ip("203.0.113.42"), ClaimKind::Operator, "x", T0)
            .unwrap();
        let (lifted_nets, lifted) = n1.flush_detector(T0);
        assert_eq!(lifted_nets.len(), 2);
        assert_eq!(lifted.retracted, vec![mine.id()]);
        assert!(n1.is_blocked(ip("203.0.113.42")), "operator bans stay");
    }

    #[test]
    fn decisions_and_lifts_survive_a_restart() {
        // ADR-4, and F1 across restarts: a lifted peer claim stays lifted after the restart.
        let mut n2 = table(2, 64);
        let theirs = detect(&mut n2, "203.0.113.50", T0);
        let mut n1 = table(1, 64);
        n1.add_local(ip("203.0.113.51"), ClaimKind::Operator, "op", T0)
            .unwrap();
        detect(&mut n1, "203.0.113.52", T0);
        n1.adopt(theirs.clone(), true, T0);
        n1.lift(ip("203.0.113.50"), T0).unwrap();
        assert!(n1.dirty());
        let saved = n1.take_persisted(T0);
        let bytes = serde_json::to_vec(&saved).unwrap();

        let mut again = table(1, 64);
        let restored: Persisted = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(again.restore(restored, |_| true, T0 + S), (2, 0));
        assert!(again.is_blocked(ip("203.0.113.51")));
        assert!(again.is_blocked(ip("203.0.113.52")));
        assert_eq!(
            again.adopt(theirs, true, T0 + S),
            Adoption::Held("retracted")
        );
        assert!(!again.is_blocked(ip("203.0.113.50")));
        // A target protected since the last run is not re-enforced.
        let mut guarded = table(1, 64);
        let (ok, refused) = guarded.restore(
            serde_json::from_slice(&bytes).unwrap(),
            |n| n != ip("203.0.113.51"),
            T0 + S,
        );
        assert_eq!((ok, refused), (1, 1));
        assert!(!guarded.is_blocked(ip("203.0.113.51")));
    }

    const QUORUM2: Quorum = Quorum {
        k: 2,
        wide_v4: 24,
        wide_v6: 64,
    };

    fn limited(
        node: u64,
        default: Envelope,
        per_peer: &[(u64, Envelope)],
    ) -> BlockTable<FakeLists> {
        let mut t = table(node, 64);
        t.configure_peers(default, per_peer.iter().copied().collect(), QUORUM2, T0);
        t
    }

    #[test]
    fn a_wide_prefix_from_one_peer_waits_for_a_second_node() {
        // ADR-7: a single (possibly compromised) peer cannot cut a /20 off this node.
        let (mut n2, mut n3) = (table(2, 64), table(3, 64));
        let wide = "198.51.96.0/20";
        let c2 = detect(&mut n2, wide, T0);
        let c3 = detect(&mut n3, wide, T0);
        let mut n1 = limited(1, Envelope::unlimited(POLICY.max), &[]);
        assert_eq!(n1.adopt(c2.clone(), true, T0), Adoption::Held("quorum"));
        assert!(!n1.is_blocked(ip(wide)));
        // The same peer repeating itself is still one node.
        let again = detect(&mut n2, wide, T0 + 1);
        assert_eq!(n1.adopt(again, true, T0), Adoption::Held("quorum"));
        assert!(
            !n1.is_blocked(ip(wide)),
            "one peer reached the quorum alone"
        );
        assert_eq!(
            n1.adopt(c3.clone(), true, T0),
            Adoption::Enforced,
            "two nodes agree"
        );
        n1.retract(3, &[c3.id()], T0 + S);
        assert!(!n1.is_blocked(ip(wide)), "back below the quorum");
        // This node's own claim counts as one node.
        let mut n4 = limited(4, Envelope::unlimited(POLICY.max), &[]);
        n4.adopt(c2, true, T0);
        detect(&mut n4, wide, T0);
        assert!(n4.is_blocked(ip(wide)));
        // Narrow targets need no quorum.
        let host = detect(&mut n2, "198.51.100.5", T0);
        assert_eq!(n1.adopt(host, true, T0), Adoption::Enforced);
    }

    #[test]
    fn a_local_wide_block_needs_no_quorum() {
        let mut n1 = limited(1, Envelope::unlimited(POLICY.max), &[]);
        detect(&mut n1, "198.51.96.0/20", T0);
        assert!(n1.is_blocked(ip("198.51.96.0/20")));
    }

    #[test]
    fn a_peers_envelope_bounds_what_it_can_block_here() {
        let mut n2 = table(2, 64);
        let (a, b, c) = (
            detect(&mut n2, "203.0.113.70", T0),
            detect(&mut n2, "203.0.113.71", T0),
            detect(&mut n2, "203.0.113.72", T0),
        );
        let wide = detect(&mut n2, "203.0.113.0/24", T0);
        let tight = Envelope {
            max_active: 2,
            max_ttl: Duration::from_secs(30),
            min_prefix_v4: 32,
            min_prefix_v6: 128,
        };
        let mut n1 = limited(1, Envelope::unlimited(POLICY.max), &[(2, tight)]);
        assert_eq!(n1.adopt(a, true, T0), Adoption::Enforced);
        assert_eq!(n1.adopt(b, true, T0), Adoption::Enforced);
        assert_eq!(
            n1.adopt(c, true, T0),
            Adoption::Held("quota"),
            "third of two slots"
        );
        assert_eq!(n1.adopt(wide, true, T0), Adoption::Held("envelope"));
        // max_ttl: the 60 s claims end here after 30 s, and the waiting claim takes a slot.
        n1.tick(T0 + 31 * S);
        assert!(!n1.is_blocked(ip("203.0.113.70")));
        assert!(
            n1.is_blocked(ip("203.0.113.72")),
            "promoted into the freed slot"
        );
        // Other peers keep the default envelope.
        let mut n3 = table(3, 64);
        assert_eq!(
            n1.adopt(detect(&mut n3, "203.0.113.73", T0), true, T0 + 31 * S),
            Adoption::Enforced
        );
    }

    #[test]
    fn a_retraction_frees_the_issuers_slot() {
        let mut n2 = table(2, 64);
        let (a, b) = (
            detect(&mut n2, "203.0.113.80", T0),
            detect(&mut n2, "203.0.113.81", T0),
        );
        let one = Envelope {
            max_active: 1,
            ..Envelope::unlimited(POLICY.max)
        };
        let mut n1 = limited(1, one, &[]);
        n1.adopt(a.clone(), true, T0);
        assert_eq!(n1.adopt(b, true, T0), Adoption::Held("quota"));
        n1.retract(2, &[a.id()], T0 + S);
        n1.tick(T0 + 2 * S);
        assert!(n1.is_blocked(ip("203.0.113.81")));
    }

    #[test]
    fn envelopes_do_not_change_the_shared_mesh_state() {
        // Held claims are still known and shared: digests converge whatever each node enforces.
        let mut n2 = table(2, 64);
        let wide = detect(&mut n2, "198.51.96.0/20", T0);
        let mut n1 = limited(1, Envelope::unlimited(POLICY.max), &[]);
        n1.adopt(wide, true, T0);
        assert_eq!(n1.digest_of(2, T0), n2.digest(T0));
    }

    #[test]
    fn operator_bans_can_be_listed_and_flushed_with_everything_but_static() {
        let mut t = table(1, 64);
        t.add_local(ip("198.51.100.1"), ClaimKind::Static, "--block", T0)
            .unwrap();
        t.add_local(ip("198.51.100.2"), ClaimKind::Operator, "op", T0)
            .unwrap();
        t.add_local(ip("198.51.100.0/24"), ClaimKind::Operator, "op", T0)
            .unwrap();
        detect(&mut t, "198.51.100.3", T0);
        assert_eq!(
            t.operator_targets(T0),
            vec![ip("198.51.100.0/24"), ip("198.51.100.2")]
        );
        let (lifted, _) = t.flush_all(T0);
        assert_eq!(lifted.len(), 3);
        assert!(t.operator_targets(T0).is_empty());
        assert!(t.is_blocked(ip("198.51.100.1")), "--block stays");
        assert_eq!(t.active(), 1);
    }

    #[test]
    fn retractions_are_forgotten_after_their_horizon() {
        // R26-03: a retraction record ends with its claim (or a bounded wait for an unseen one);
        // only a claim that never expires keeps its tombstone.
        let mut n2 = table(2, 64);
        let finite = detect(&mut n2, "203.0.113.90", T0);
        let mut n1 = table(1, 64);
        n1.adopt(finite.clone(), true, T0);
        n1.retract(2, &[finite.id()], T0);
        n1.retract(2, &["f".repeat(64)], T0); // a claim n1 has never seen
        let mut forever_src = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 8,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            TtlPolicy {
                base: Duration::ZERO,
                max: Duration::ZERO,
            },
            3,
        );
        let forever = detect(&mut forever_src, "203.0.113.91", T0);
        n1.adopt(forever.clone(), true, T0);
        n1.retract(3, &[forever.id()], T0);
        assert_eq!(n1.retractions.len(), 3);
        n1.tick(T0 + ms(POLICY.max) + S);
        assert_eq!(
            n1.retractions.len(),
            3,
            "kept for FORGET_GRACE past the horizon"
        );
        n1.tick(T0 + ms(POLICY.max) + ms(FORGET_GRACE) + S);
        assert_eq!(
            n1.retractions.keys().cloned().collect::<Vec<_>>(),
            vec![forever.id()],
            "finite and unseen tombstones end; the never-expiring claim keeps its own"
        );
    }

    #[test]
    fn a_claims_reason_is_bounded() {
        let mut t = table(1, 8);
        let long = "x".repeat(4 * MAX_REASON_BYTES);
        let c = t
            .add_local(ip("203.0.113.92"), ClaimKind::Detector, &long, T0)
            .unwrap()
            .claim;
        assert_eq!(c.reason.len(), MAX_REASON_BYTES);
        let mut peer_claim = detect(&mut table(2, 8), "203.0.113.93", T0);
        peer_claim.reason = long;
        assert!(matches!(
            t.adopt(peer_claim, true, T0),
            Adoption::Refused(_)
        ));
    }

    #[test]
    fn repeated_detections_of_one_target_keep_a_handful_of_claims() {
        // R26-05: the review stored 262 145 claims for one address; repeats are coalesced now.
        let mut t = table(1, 64);
        for i in 0..20_000u64 {
            t.add_local(ip("203.0.113.95"), ClaimKind::Detector, "x", T0 + i * 10)
                .unwrap();
        }
        assert!(
            t.claims.len() <= 8,
            "{} claims for one target",
            t.claims.len()
        );
        assert!(t.is_blocked(ip("203.0.113.95")));
        // The claims it replaced are taken back, so peers drop them too.
        let (shared, own_retracted) = t.snapshot(T0 + 200_000 * S / 1000);
        assert_eq!(shared.len(), 1);
        assert!(own_retracted.len() + 1 >= t.claims.len());
    }

    #[test]
    fn local_claims_respect_the_known_claims_cap() {
        let mut t = table(1, 64);
        for i in 0..MAX_KNOWN_CLAIMS as u32 {
            let target = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
            t.claims.insert(
                format!("{:064x}", i),
                Held {
                    claim: Claim {
                        issuer: 1,
                        kind: ClaimKind::Detector,
                        target: target.clone(),
                        issued_ms: T0,
                        expires_ms: Some(T0 + 60 * S),
                        reason: String::new(),
                    },
                    net: ip(&target),
                    until_ms: Some(T0 + 60 * S),
                    allowed: true,
                    in_quota: true,
                    ended: false,
                },
            );
        }
        assert_eq!(
            t.add_local(ip("203.0.113.96"), ClaimKind::Detector, "x", T0)
                .err(),
            Some("too many known claims")
        );
    }

    #[test]
    fn a_failing_target_does_not_starve_the_others_and_retries_are_bounded() {
        // R26-06: 300 peer claims end locally while deletes fail; later ticks do bounded work.
        let mut peer = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 1024,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            TtlPolicy {
                base: Duration::ZERO,
                max: Duration::ZERO,
            },
            2,
        );
        let mut n1 = table(1, 1024);
        for i in 0..300u32 {
            let c = detect(&mut peer, &format!("10.9.{}.{}", i / 256, i % 256), T0);
            n1.adopt(c, true, T0);
        }
        n1.lists.fail_delete = true;
        n1.tick(T0 + ms(POLICY.max) + S); // local ends: 300 first attempts, all fail
        assert_eq!(n1.pending(), 300);
        n1.lists.deletes = 0;
        n1.tick(T0 + ms(POLICY.max) + 2 * S);
        assert_eq!(
            n1.lists.deletes, MAX_RETRIES_PER_TICK,
            "retries bounded per tick"
        );
        n1.tick(T0 + ms(POLICY.max) + 3 * S);
        n1.lists.fail_delete = false;
        n1.tick(T0 + ms(POLICY.max) + 4 * S);
        n1.tick(T0 + ms(POLICY.max) + 5 * S);
        assert_eq!(n1.pending(), 0, "every target made progress");
        assert_eq!(n1.active(), 0);
    }

    #[test]
    fn a_capped_peer_claim_gets_no_new_lease_after_a_restart() {
        // R26-07: the review replayed the same never-expiring claim after a restart and it was
        // enforced again for another max. The lease end is kept across restarts.
        let mut peer = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 8,
                fail_delete: false,
                deletes: 0,
                hits: HashMap::new(),
            },
            TtlPolicy {
                base: Duration::ZERO,
                max: Duration::ZERO,
            },
            2,
        );
        let forever = detect(&mut peer, "203.0.113.97", T0);
        let mut n1 = table(1, 64);
        assert_eq!(n1.adopt(forever.clone(), true, T0), Adoption::Enforced);
        let after = T0 + ms(POLICY.max) + S;
        n1.tick(after);
        assert!(!n1.is_blocked(ip("203.0.113.97")));
        let mut restarted = table(1, 64);
        restarted.restore(n1.take_persisted(after), |_| true, after);
        assert_eq!(
            restarted.adopt(forever, true, after),
            Adoption::Held("expired")
        );
        assert!(
            !restarted.is_blocked(ip("203.0.113.97")),
            "a new lease after the restart"
        );
    }

    fn peer_claim(issuer: u64, target: &str, issued: u64) -> Claim {
        Claim {
            issuer,
            kind: ClaimKind::Detector,
            target: target.into(),
            issued_ms: issued,
            expires_ms: None,
            reason: "peer".into(),
        }
    }

    fn one_slot(t: &mut BlockTable<FakeLists>, issuer: u64, now: u64) {
        let mut per_peer = HashMap::new();
        per_peer.insert(
            issuer,
            Envelope {
                max_active: 1,
                ..Envelope::unlimited(POLICY.max)
            },
        );
        t.configure_peers(Envelope::unlimited(POLICY.max), per_peer, Quorum::OFF, now);
    }

    #[test]
    fn a_claim_that_waits_for_a_slot_keeps_its_earlier_lease_end() {
        // R26-07 through the quota queue: a claim leased before a restart that has to wait for
        // a slot afterwards is enforced only until its original lease end.
        let (a, b) = (
            peer_claim(2, "203.0.113.70", T0),
            peer_claim(2, "203.0.113.71", T0),
        );
        let mut n1 = table(1, 64);
        one_slot(&mut n1, 2, T0);
        assert_eq!(n1.adopt(b.clone(), true, T0), Adoption::Enforced);
        let restart = T0 + 400 * S; // b's lease (max 600 s) ends at T0 + 600 s
        let mut restarted = table(1, 64);
        one_slot(&mut restarted, 2, restart);
        restarted.restore(n1.take_persisted(restart), |_| true, restart);
        let a_id = a.id();
        assert_eq!(restarted.adopt(a, true, restart), Adoption::Enforced);
        assert_eq!(restarted.adopt(b, true, restart), Adoption::Held("quota"));
        // a's slot frees at restart + 600 s... too late for b; free it sooner with a retraction.
        restarted.retract(2, &[a_id], restart + 100 * S);
        restarted.tick(restart + 100 * S);
        assert!(
            restarted.is_blocked(ip("203.0.113.71")),
            "b takes the freed slot"
        );
        restarted.tick(T0 + 600 * S);
        assert!(
            !restarted.is_blocked(ip("203.0.113.71")),
            "b is enforced past its original lease end"
        );
    }

    #[test]
    fn lifted_claims_resent_by_their_issuer_take_no_slots() {
        // Found by the machine: after a restart, a peer resending claims the operator had lifted
        // used up its quota with them, so its new claims waited.
        let mut n1 = table(1, 64);
        one_slot(&mut n1, 2, T0);
        let old = peer_claim(2, "203.0.113.73", T0);
        assert_eq!(n1.adopt(old.clone(), true, T0), Adoption::Enforced);
        n1.lift(ip("203.0.113.73"), T0).unwrap();
        let mut restarted = table(1, 64);
        one_slot(&mut restarted, 2, T0 + S);
        restarted.restore(n1.take_persisted(T0 + S), |_| true, T0 + S);
        assert_eq!(
            restarted.adopt(old, true, T0 + S),
            Adoption::Held("retracted")
        );
        assert_eq!(
            restarted.adopt(peer_claim(2, "203.0.113.74", T0 + S), true, T0 + S),
            Adoption::Enforced,
            "the lifted claim holds the peer's only slot"
        );
    }

    #[test]
    fn a_target_that_becomes_protected_is_released_and_its_waiting_claims_stay_out() {
        // Found by the machine: a peer's claim waiting for a slot whose target became protected
        // was still promoted to a slot.
        let mut t = table(1, 64);
        one_slot(&mut t, 2, T0);
        let (a, b) = (
            peer_claim(2, "203.0.113.80", T0),
            peer_claim(2, "203.0.113.81", T0),
        );
        let a_id = a.id();
        assert_eq!(t.adopt(a, true, T0), Adoption::Enforced);
        assert_eq!(t.adopt(b, true, T0), Adoption::Held("quota"));
        let protected = ip("203.0.113.81");
        assert!(t.recheck(|net| net != protected, T0).is_empty());
        t.retract(2, &[a_id], T0 + S); // frees the only slot
        t.tick(T0 + S);
        assert!(
            !t.is_blocked(protected),
            "a protected target was promoted to a slot"
        );
        assert_eq!(t.active_by_issuer.get(&2).copied().unwrap_or(0), 0);
        // Protected while blocked: released at once; unprotected again: enforced again.
        let c = peer_claim(3, "203.0.113.82", T0);
        assert_eq!(t.adopt(c, true, T0 + S), Adoption::Enforced);
        let now_protected = ip("203.0.113.82");
        assert_eq!(
            t.recheck(|net| net != now_protected, T0 + S),
            vec![now_protected]
        );
        assert!(!t.is_blocked(now_protected));
        t.recheck(|_| true, T0 + 2 * S);
        t.tick(T0 + 2 * S);
        assert!(
            t.is_blocked(now_protected),
            "no longer protected: the claim counts again"
        );
    }

    #[test]
    fn an_ended_lease_stays_ended_when_the_clock_steps_back() {
        let mut t = table(1, 64);
        let c = peer_claim(2, "203.0.113.72", T0);
        assert_eq!(t.adopt(c, true, T0), Adoption::Enforced);
        let end = T0 + ms(POLICY.max);
        t.tick(end);
        assert!(!t.is_blocked(ip("203.0.113.72")));
        // The clock steps back a minute and something re-examines every target: the ended lease
        // gave up its slot, so it does not count again.
        t.set_pinned([2].into_iter().collect(), end - 60 * S);
        assert!(
            !t.is_blocked(ip("203.0.113.72")),
            "an ended lease came back after a clock step"
        );
    }

    #[test]
    fn claim_identity_is_its_bytes() {
        let mut t = table(1, 8);
        let a = detect(&mut t, "203.0.113.60", T0);
        let b = detect(&mut t, "203.0.113.60", T0 + 1);
        assert_ne!(a.id(), b.id(), "a later decision is a different claim");
        assert_eq!(a.id(), a.clone().id());
        assert_eq!(a.id().len(), 64);
    }

    #[test]
    fn counts_by_family_and_reports_watermark_crossings_once() {
        let mut t = table(1, 64);
        detect(&mut t, "203.0.113.1", T0);
        t.add_local(ip("203.0.113.2"), ClaimKind::Operator, "x", T0)
            .unwrap();
        detect(&mut t, "2001:db8::1", T0);
        assert_eq!(t.active_by_family(), (2, 1));

        let mut mark = Watermark::default();
        assert!(mark.update((7, 0), 10).is_empty());
        assert_eq!(mark.update((8, 0), 10).len(), 1, "crossing up is reported");
        assert!(
            mark.update((9, 0), 10).is_empty(),
            "staying above is not repeated"
        );
        assert_eq!(
            mark.update((7, 9), 10).len(),
            2,
            "v4 back below, v6 crossing up"
        );
    }

    #[test]
    fn targets_parse_canonically_and_print_like_before() {
        assert_eq!(show(&ip("203.0.113.5")), "203.0.113.5");
        assert_eq!(show(&ip("::ffff:203.0.113.5")), "203.0.113.5");
        assert_eq!(
            show(&ip("198.51.100.77/24")),
            "198.51.100.0/24",
            "host bits cleared"
        );
        assert_eq!(
            show(&ip("::ffff:198.51.100.0/120")),
            "198.51.100.0/24",
            "mapped prefix becomes IPv4"
        );
        assert_eq!(show(&ip("2001:db8::1/48")), "2001:db8::/48");
        assert!(parse_target("10.0.0.0/33").is_none());
        assert!(parse_target("example.com").is_none());
        assert_eq!(family_tag(&ip("2001:db8::/48")), "V6");
    }

    #[test]
    fn prefixes_and_hosts_are_separate_targets() {
        let mut t = table(1, 64);
        detect(&mut t, "198.51.100.0/24", T0);
        t.add_local(ip("198.51.100.9"), ClaimKind::Operator, "x", T0)
            .unwrap();
        assert_eq!(t.active_by_family(), (2, 0));
        assert_eq!(t.tick(T0 + 60 * S), vec![ip("198.51.100.0/24")]);
        assert!(t.is_blocked(ip("198.51.100.9")));
    }

    /// Model-based fuzzing: random sequences of everything that can happen to the table —
    /// local decisions, peers' claims (with odd times, wide prefixes, quota and quorum),
    /// retractions, lifts, flushes, failing map deletes, re-pinning, clock steps in both
    /// directions — checked against invariants after every step.
    mod machine {
        use super::*;
        use proptest::prelude::*;

        const TARGETS: &[&str] = &[
            "203.0.113.1",
            "203.0.113.2",
            "203.0.113.0/24",
            "198.51.0.0/16",
            "2001:db8::1",
            "2001:db8::/48",
            "::ffff:203.0.113.1",
        ];
        const PEERS: &[u64] = &[2, 3, 4];

        #[derive(Clone, Debug)]
        enum Op {
            Local {
                t: usize,
                kind: u8,
            },
            Peer {
                issuer: usize,
                t: usize,
                ttl: Option<u64>,
                back: u64,
                allowed: bool,
                reason: u16,
            },
            Retract {
                issuer: usize,
                pick: usize,
            },
            Lift {
                t: usize,
            },
            FlushAll,
            FlushDetector,
            Tick {
                dt: i64,
            },
            FailDelete(bool),
            Pin {
                mask: u8,
            },
            Restart,
            /// The host's protected set changes (addresses or gateways moved).
            Protect {
                mask: u8,
            },
        }

        fn op() -> impl Strategy<Value = Op> {
            let t = 0..TARGETS.len();
            prop_oneof![
                3 => (t.clone(), 0u8..3).prop_map(|(t, kind)| Op::Local { t, kind }),
                4 => (
                    0..PEERS.len(),
                    t.clone(),
                    prop_oneof![Just(None), (0u64..2_000_000).prop_map(Some), Just(Some(u64::MAX))],
                    prop_oneof![Just(0u64), 0u64..5_000_000, Just(u64::MAX)],
                    prop::bool::weighted(0.9),
                    prop_oneof![Just(0u16), Just(600u16)],
                )
                    .prop_map(|(issuer, t, ttl, back, allowed, reason)| Op::Peer {
                        issuer, t, ttl, back, allowed, reason
                    }),
                2 => (0..PEERS.len() + 1, any::<usize>()).prop_map(|(issuer, pick)| Op::Retract { issuer, pick }),
                2 => t.prop_map(|t| Op::Lift { t }),
                1 => Just(Op::FlushAll),
                1 => Just(Op::FlushDetector),
                4 => prop_oneof![
                    4 => 0i64..700_000,
                    1 => -120_000i64..0,
                    1 => Just(24 * 3600 * 1000i64),
                ]
                .prop_map(|dt| Op::Tick { dt }),
                1 => any::<bool>().prop_map(Op::FailDelete),
                1 => any::<u8>().prop_map(|mask| Op::Pin { mask }),
                1 => Just(Op::Restart),
                1 => any::<u8>().prop_map(|mask| Op::Protect { mask }),
            ]
        }

        fn configure(t: &mut BlockTable<FakeLists>, now: u64) {
            let mut per_peer = HashMap::new();
            per_peer.insert(
                3,
                Envelope {
                    max_active: 2,
                    max_ttl: Duration::from_secs(300),
                    min_prefix_v4: 24,
                    min_prefix_v6: 48,
                },
            );
            t.configure_peers(
                Envelope::unlimited(POLICY.max),
                per_peer,
                Quorum {
                    k: 2,
                    wide_v4: 24,
                    wide_v6: 64,
                },
                now,
            );
        }

        /// Invariants that hold after every step.
        fn check(t: &BlockTable<FakeLists>, now: u64, settled: bool) -> Result<(), TestCaseError> {
            prop_assert_eq!(
                &t.lists.nets,
                &t.applied,
                "applied is exactly what the kernel map holds"
            );
            prop_assert!(
                t.pending.iter().all(|n| t.queued.contains(n)),
                "every pending target is queued for retry"
            );
            prop_assert!(
                t.applied_cause.len() == t.applied.len()
                    && t.applied.iter().all(|n| t.applied_cause.contains_key(n)),
                "the cause is known exactly for applied targets"
            );
            prop_assert!(
                t.applied_at.len() == t.applied.len()
                    && t.applied.iter().all(|n| t.applied_at.contains_key(n)),
                "the applied time is known exactly for applied targets"
            );
            prop_assert!(
                t.pending.len() == t.pending_since.len()
                    && t.pending.iter().all(|n| t.pending_since.contains_key(n)),
                "pending ages follow the pending set"
            );
            for (issuer, n) in &t.active_by_issuer {
                let held = t
                    .claims
                    .values()
                    .filter(|h| h.claim.issuer == *issuer && h.in_quota)
                    .count();
                prop_assert_eq!(*n, held, "slot count of node {}", issuer);
                prop_assert!(
                    *n <= t.envelope(*issuer).max_active,
                    "node {} over its envelope",
                    issuer
                );
            }
            for (id, h) in &t.claims {
                if h.in_quota && h.claim.issuer != 1 {
                    prop_assert!(
                        h.allowed && !t.retracted(id, h),
                        "a claim that cannot count holds one of {}'s slots",
                        h.claim.issuer
                    );
                }
            }
            for (net, ids) in &t.by_target {
                prop_assert!(!ids.is_empty(), "empty target set kept for {}", net);
                for id in ids {
                    let h = t.claims.get(id);
                    prop_assert!(
                        h.is_some_and(|h| h.net == *net),
                        "by_target points to a missing or other claim"
                    );
                }
            }
            prop_assert_eq!(
                t.claims.len(),
                t.by_target.values().map(|s| s.len()).sum::<usize>(),
                "every claim is indexed by its target"
            );
            // ADR-7: a prefix wider than /24 (/64) that only peers claim is enforced only with
            // claims from two distinct nodes that count here.
            for net in t.applied.iter().filter(|n| !t.pending.contains(n)) {
                let wide = match net {
                    IpNet::V4(n) => n.prefix_len() < 24,
                    IpNet::V6(n) => n.prefix_len() < 64,
                };
                let ids = t.by_target.get(net).into_iter().flatten();
                let counting: Vec<&Held> = ids
                    .filter_map(|id| t.claims.get(id).filter(|h| t.counts(id, h, now)))
                    .collect();
                if wide && !counting.iter().any(|h| h.claim.issuer == 1) {
                    let issuers: HashSet<u64> = counting.iter().map(|h| h.claim.issuer).collect();
                    prop_assert!(
                        issuers.len() >= 2,
                        "{} enforced for peers {:?} without quorum",
                        net,
                        issuers
                    );
                }
            }
            if settled {
                let mut nets: HashSet<IpNet> = t.by_target.keys().copied().collect();
                nets.extend(t.applied.iter().copied());
                for net in nets {
                    prop_assert_eq!(
                        t.applied.contains(&net),
                        t.wanted(&net, now),
                        "{} not converged at {}",
                        net,
                        now
                    );
                }
            }
            Ok(())
        }

        fn dump(label: &str, t: &BlockTable<FakeLists>, now: u64) {
            let rel = |x: u64| x as i128 - now as i128;
            eprintln!("--- {} applied {:?}", label, t.applied);
            for (id, h) in &t.claims {
                eprintln!(
                    "  {} {} exp={:?} until={:?} allowed={} quota={} ended={} retr={:?} lease={:?}",
                    h.claim.issuer,
                    h.net,
                    h.claim.expires_ms.map(rel),
                    h.until_ms.map(rel),
                    h.allowed,
                    h.in_quota,
                    h.ended,
                    t.retractions.get(id).map(|r| (
                        r.operator,
                        r.by_nodes.clone(),
                        r.forget_ms.map(rel)
                    )),
                    t.lease_ends.get(id).map(|(e, _)| rel(*e)),
                );
            }
        }

        fn run(ops: Vec<Op>) -> Result<(), TestCaseError> {
            let mut now = T0;
            let mut t = table(1, 1024);
            configure(&mut t, now);
            let mut known: Vec<Claim> = Vec::new();
            // Ghost state: claims the operator lifted, kept outside the table.
            let mut lifted: HashSet<ClaimId> = HashSet::new();
            // Targets the host protects now (Op::Protect); enforcement must never cover them.
            let mut protected: HashSet<IpNet> = HashSet::new();
            let lift_where = |t: &BlockTable<FakeLists>,
                              lifted: &mut HashSet<ClaimId>,
                              f: &dyn Fn(&Held) -> bool| {
                for (id, h) in &t.claims {
                    if h.claim.kind != ClaimKind::Static && f(h) {
                        lifted.insert(id.clone());
                    }
                }
            };
            for op in ops {
                match op {
                    Op::Local { t: i, kind } => {
                        let kind = [ClaimKind::Detector, ClaimKind::Operator, ClaimKind::Static]
                            [kind as usize];
                        // The node refuses protected targets before any claim exists.
                        if protected.contains(&canonical(ip(TARGETS[i]))) {
                            continue;
                        }
                        if let Ok(a) = t.add_local(ip(TARGETS[i]), kind, "fuzz", now) {
                            // A lifted operator ban is deleted, so the same bytes again (same
                            // millisecond) are a new ban.
                            if kind == ClaimKind::Operator {
                                lifted.remove(&a.claim.id());
                            }
                            known.push(a.claim);
                        }
                    }
                    Op::Peer {
                        issuer,
                        t: i,
                        ttl,
                        back,
                        allowed,
                        reason,
                    } => {
                        let issued = now.saturating_sub(back);
                        let claim = Claim {
                            issuer: PEERS[issuer],
                            kind: ClaimKind::Detector,
                            target: show(&canonical(ip(TARGETS[i]))),
                            issued_ms: issued,
                            expires_ms: ttl.map(|d| issued.saturating_add(d)),
                            reason: "r".repeat(reason as usize),
                        };
                        known.push(claim.clone());
                        // As in the node: the verdict depends on the target only.
                        let _ = allowed;
                        let allowed = !protected.contains(&canonical(ip(TARGETS[i])));
                        t.adopt(claim, allowed, now);
                    }
                    Op::Retract { issuer, pick } => {
                        if !known.is_empty() {
                            let c = &known[pick % known.len()];
                            let by = if issuer == PEERS.len() {
                                1
                            } else {
                                PEERS[issuer]
                            };
                            t.retract(by, &[c.id()], now);
                        }
                    }
                    Op::Lift { t: i } => {
                        // Every decision about the target known at the time, enforced or not
                        // (a claim waiting for a slot is lifted too); later ones are new.
                        let net = canonical(ip(TARGETS[i]));
                        let before = t.claims.keys().cloned().collect::<HashSet<_>>();
                        if t.lift(net, now).is_ok() {
                            lift_where(&t, &mut lifted, &|h| {
                                h.net == net && before.contains(&h.claim.id())
                            });
                        }
                    }
                    Op::FlushAll => {
                        lift_where(&t, &mut lifted, &|_| true);
                        t.flush_all(now);
                    }
                    Op::FlushDetector => {
                        lift_where(&t, &mut lifted, &|h| h.claim.kind == ClaimKind::Detector);
                        t.flush_detector(now);
                    }
                    Op::Tick { dt } => {
                        now = now.saturating_add_signed(dt);
                        t.tick(now);
                    }
                    Op::FailDelete(on) => t.lists.fail_delete = on,
                    Op::Protect { mask } => {
                        protected = TARGETS
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| mask & (1 << i) != 0)
                            .map(|(_, t)| canonical(ip(t)))
                            .collect();
                        let p = protected.clone();
                        t.recheck(|net| !p.contains(&net), now);
                    }
                    Op::Pin { mask } => {
                        let pinned = PEERS
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| mask & (1 << i) != 0)
                            .map(|(_, p)| *p)
                            .collect();
                        t.set_pinned(pinned, now);
                    }
                    Op::Restart => {
                        // What a restart keeps: this node's own decisions and lifts.
                        let state = t.take_persisted(now);
                        let bytes = serde_json::to_vec(&state).unwrap();
                        let own_before: HashSet<IpNet> = t
                            .by_target
                            .iter()
                            .filter(|(_, ids)| {
                                ids.iter().any(|id| {
                                    let h = &t.claims[id];
                                    h.claim.issuer == 1
                                        && h.claim.kind != ClaimKind::Static
                                        && t.effective(id, h, now)
                                })
                            })
                            .map(|(net, _)| *net)
                            .collect();
                        let mut fresh = table(1, 1024);
                        fresh.lists.fail_delete = t.lists.fail_delete;
                        configure(&mut fresh, now);
                        let p = protected.clone();
                        fresh.restore(
                            serde_json::from_slice(&bytes).unwrap(),
                            |net| !p.contains(&net),
                            now,
                        );
                        fresh.tick(now);
                        let own_after: HashSet<IpNet> = fresh.applied.clone();
                        prop_assert_eq!(
                            &own_before,
                            &own_after,
                            "a restart keeps exactly this node's effective decisions"
                        );
                        // Then the peers resync: each sends its live claims and its retractions,
                        // in the order they were first sent. The operator's lifts must hold.
                        fresh.set_pinned(
                            t.pinned
                                .clone()
                                .unwrap_or_else(|| PEERS.iter().copied().collect()),
                            now,
                        );
                        let mut sent = HashSet::new();
                        for c in &known {
                            let id = c.id();
                            if c.issuer == 1 || !sent.insert(id.clone()) {
                                continue;
                            }
                            let Some(h) = t.claims.get(&id) else { continue };
                            let by_issuer = t
                                .retractions
                                .get(&id)
                                .is_some_and(|r| r.by_nodes.contains(&c.issuer));
                            if by_issuer {
                                fresh.retract(c.issuer, std::slice::from_ref(&id), now);
                            } else if h.claim.live_at(now) {
                                let allowed = c.net().is_none_or(|n| !protected.contains(&n));
                                fresh.adopt(c.clone(), allowed, now);
                            }
                        }
                        fresh.tick(now);
                        t.tick(now);
                        if std::env::var("SOKOL_FUZZ_DEBUG").is_ok() {
                            dump("before", &t, now);
                            dump("after", &fresh, now);
                        }
                        // Every claim the operator lifted stays without effect.
                        for (id, r) in &t.retractions {
                            if r.operator {
                                if let Some(h) = fresh.claims.get(id) {
                                    prop_assert!(
                                        !fresh.effective(id, h, now),
                                        "operator lift of {}'s claim on {} undone by a resync after restart",
                                        h.claim.issuer, h.net
                                    );
                                }
                            }
                        }
                        t = fresh;
                    }
                }
                check(&t, now, false)?;
                for net in t.applied.iter().filter(|n| !t.pending.contains(n)) {
                    prop_assert!(
                        !protected.contains(net),
                        "{} is protected but enforced",
                        net
                    );
                }
                for id in &lifted {
                    if let Some(h) = t.claims.get(id) {
                        prop_assert!(
                            !t.effective(id, h, now),
                            "{}'s claim on {} counts again after the operator lifted it",
                            h.claim.issuer,
                            h.net
                        );
                    }
                }
            }
            // With deletes working and time moving on, everything converges.
            t.lists.fail_delete = false;
            t.tick(now);
            check(&t, now, true)?;
            Ok(())
        }

        /// Found by the machine: after a restart a peer's claim whose lease had run out waited
        /// for a quota slot and was then given a fresh lease (R26-07 bypass).
        #[test]
        fn a_claim_whose_lease_ran_out_gets_no_new_one_through_the_queue() {
            use Op::*;
            let ops = vec![
                Peer {
                    issuer: 0,
                    t: 1,
                    ttl: Some(u64::MAX),
                    back: 0,
                    allowed: true,
                    reason: 0,
                },
                Peer {
                    issuer: 1,
                    t: 0,
                    ttl: None,
                    back: 0,
                    allowed: false,
                    reason: 0,
                },
                Peer {
                    issuer: 1,
                    t: 0,
                    ttl: Some(1085013),
                    back: 0,
                    allowed: false,
                    reason: 0,
                },
                Tick { dt: 300000 },
                Lift { t: 1 },
                Peer {
                    issuer: 1,
                    t: 1,
                    ttl: None,
                    back: 0,
                    allowed: true,
                    reason: 0,
                },
                Tick { dt: 300000 },
                Restart,
            ];
            if let Err(e) = run(ops) {
                panic!("{}", e);
            }
        }

        /// Found by the machine: after a clock step back and two restarts, an operator lift was
        /// forgotten before the lifted peer claim's (re-lengthened) lease ended.
        #[test]
        fn a_lift_outlives_the_lease_across_clock_steps_and_restarts() {
            use Op::*;
            let ops = vec![
                Peer {
                    issuer: 2,
                    t: 0,
                    ttl: None,
                    back: 0,
                    allowed: true,
                    reason: 0,
                },
                Tick { dt: -27143 },
                Restart,
                Lift { t: 0 },
                Tick { dt: 498025 },
                Restart,
                Tick { dt: 101975 },
            ];
            if let Err(e) = run(ops) {
                panic!("{}", e);
            }
        }

        /// Found by the machine: FLUSH_ALL left a peer's wide-prefix claim that was waiting
        /// for quorum; a second node's claim then enforced it.
        #[test]
        fn a_flush_lifts_claims_that_wait_for_a_quorum() {
            use Op::*;
            let ops = vec![
                Peer {
                    issuer: 0,
                    t: 5,
                    ttl: None,
                    back: 0,
                    allowed: true,
                    reason: 0,
                },
                FlushAll,
                Peer {
                    issuer: 1,
                    t: 5,
                    ttl: None,
                    back: 0,
                    allowed: true,
                    reason: 0,
                },
            ];
            if let Err(e) = run(ops) {
                panic!("{}", e);
            }
        }

        /// Found by the machine: a lifted claim that never had a lease (it waited for a slot)
        /// was forgotten at its would-be lease end and got a fresh lease when resent.
        #[test]
        fn a_lift_of_a_waiting_claim_outlives_restarts() {
            use Op::*;
            let ops = vec![
                Peer {
                    issuer: 1,
                    t: 0,
                    ttl: None,
                    back: 0,
                    allowed: true,
                    reason: 0,
                },
                Peer {
                    issuer: 1,
                    t: 0,
                    ttl: None,
                    back: 1,
                    allowed: true,
                    reason: 0,
                },
                Peer {
                    issuer: 1,
                    t: 6,
                    ttl: None,
                    back: 2,
                    allowed: true,
                    reason: 0,
                },
                FlushAll,
                Tick { dt: 86_400_000 },
                Restart,
            ];
            if let Err(e) = run(ops) {
                panic!("{}", e);
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: std::env::var("SOKOL_FUZZ_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(4096),
                max_shrink_iters: 4096,
                ..ProptestConfig::default()
            })]
            #[test]
            fn the_table_keeps_its_invariants(ops in prop::collection::vec(op(), 1..60)) {
                run(ops)?;
            }
        }
    }
}
