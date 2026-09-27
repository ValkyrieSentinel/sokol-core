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
use aya::maps::{LpmTrie, MapData, MapError};

/// How long an address's past blocks count towards escalation.
pub const STRIKE_MEMORY: Duration = Duration::from_secs(24 * 3600);

/// How long a detector event id is remembered: a replay within it adds no strike. As long as
/// the strike memory, so a replay can never escalate a block.
pub const EVENT_MEMORY: Duration = STRIKE_MEMORY;
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
    reason[..end].to_string()
}

/// Pending kernel operations retried per tick (a full map must not cost a syscall per entry per s).
pub const MAX_RETRIES_PER_TICK: usize = 256;

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

/// Durable part of the table (ADR-4): this node's own decisions and lifts.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Persisted {
    pub claims: Vec<Claim>,
    pub operator_lifts: Vec<(ClaimId, Option<u64>)>,
    pub retracted: Vec<(ClaimId, Option<u64>)>,
    /// Local ends of peers' claims that were cut short here (R26-07): after a restart the same
    /// claim does not get a new lease. (id, local end, the claim's own expiry)
    #[serde(default)]
    pub peer_ends: Vec<(ClaimId, u64, Option<u64>)>,
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
    /// Targets to retry, oldest first (R26-06): each is retried at most once per tick, and a
    /// target that keeps failing goes to the back, so it cannot starve the others.
    retry: std::collections::VecDeque<IpNet>,
    queued: HashSet<IpNet>,
    strikes: HashMap<IpNet, (u32, u64)>,
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
        policy: TtlPolicy,
        node_id: u64,
    ) -> Self {
        Self::with_lists(KernelBlocklist { v4, v6 }, policy, node_id)
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
            retry: std::collections::VecDeque::new(),
            queued: HashSet::new(),
            strikes: HashMap::new(),
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
        } else if !held.in_quota {
            Some("quota")
        } else if held.until_ms.is_some_and(|u| u <= now_ms) {
            Some("expired")
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
            (true, false) => self.lists.add(net).map(|()| {
                self.applied.insert(net);
            }),
            (false, true) => match self.lists.delete(net) {
                Ok(()) | Err(MapError::KeyNotFound) => {
                    self.applied.remove(&net);
                    Ok(())
                }
                Err(e) => Err(e),
            },
            _ => Ok(()),
        };
        if result.is_ok() {
            self.pending.remove(&net);
        } else {
            self.pending.insert(net);
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
        true
    }

    /// (remembered event ids, ids forgotten early because the memory was full)
    pub fn event_memory(&self) -> (usize, u64) {
        (self.events.len(), self.events_evicted)
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
                let entry = self.strikes.entry(net).or_insert((0, now_ms));
                if now_ms.saturating_sub(entry.1) > ms(STRIKE_MEMORY) {
                    entry.0 = 0;
                }
                entry.0 = entry.0.saturating_add(1);
                entry.1 = now_ms;
                let factor = 1u32.checked_shl(entry.0 - 1).unwrap_or(u32::MAX);
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
            if enough {
                let id = own
                    .iter()
                    .find(|(_, e)| *e == longest)
                    .map(|(id, _)| id.clone())
                    .expect("longest is one of them");
                let claim = self.claims[&id].claim.clone();
                let applied = self.reconcile(net, now_ms);
                let left = claim
                    .expires_ms
                    .map(|e| Duration::from_millis(e.saturating_sub(now_ms)));
                return Ok(Added {
                    claim,
                    ttl: left,
                    applied,
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
        if claim.expires_ms.is_none_or(|e| e > cap) && !self.lease_ends.contains_key(&id) {
            self.lease_ends.insert(id.clone(), (cap, claim.expires_ms));
            self.dirty = true;
        }
        let issuer = claim.issuer;
        let active = self.active_by_issuer.entry(issuer).or_insert(0);
        let in_quota = *active < envelope.max_active;
        if in_quota {
            *active += 1;
        } else {
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
                ended: false,
            },
        );
        let was = self.applied.contains(&net);
        let result = self.reconcile(net, now_ms);
        let held = &self.claims[&id];
        match (result, self.hold_reason(&id, held, now_ms)) {
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
                }
                out.claims += 1;
                continue;
            }
            let own_detector =
                h.claim.issuer == self.node_id && h.claim.kind == ClaimKind::Detector;
            let forget_ms = h.claim.expires_ms.or(h.until_ms);
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
        let mut liftable = Vec::new();
        let mut has_static = false;
        for id in ids {
            let h = &self.claims[&id];
            if !self.effective(&id, h, now_ms) {
                continue;
            }
            if h.claim.kind == ClaimKind::Static {
                has_static = true;
            } else {
                liftable.push(id);
            }
        }
        if liftable.is_empty() {
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
            .filter(|(id, h)| h.claim.kind != ClaimKind::Static && self.effective(id, h, now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        let nets: Vec<IpNet> = ids.iter().map(|id| self.claims[id].net).collect();
        let lifted = self.lift_ids(ids);
        (self.settle(nets, now_ms), lifted)
    }

    /// Operator flush: lifts every detector claim (any issuer); operator and `--block` stay.
    pub fn flush_detector(&mut self, now_ms: u64) -> (Vec<IpNet>, Lifted) {
        let ids: Vec<ClaimId> = self
            .claims
            .iter()
            .filter(|(id, h)| h.claim.kind == ClaimKind::Detector && self.effective(id, h, now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        let nets: Vec<IpNet> = ids.iter().map(|id| self.claims[id].net).collect();
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
                // Enforcement starts now, so the local end is counted from now.
                let cap =
                    now_ms.saturating_add(ms(self.policy.max.min(self.envelope(issuer).max_ttl)));
                if let Some(h) = self.claims.get_mut(&id) {
                    if !h.in_quota && h.claim.live_at(now_ms) {
                        h.in_quota = true;
                        h.until_ms = Some(h.claim.expires_ms.map_or(cap, |e| e.min(cap)));
                        h.ended = false;
                        *self.active_by_issuer.entry(issuer).or_insert(0) += 1;
                        touched.push(h.net);
                    }
                }
            }
        }
        self.waiting.retain(|_, q| !q.is_empty());
        self.retractions
            .retain(|_, r| r.forget_ms.is_none_or(|f| f > now_ms));
        let before = self.lease_ends.len();
        self.lease_ends
            .retain(|_, (_, expires)| expires.is_none_or(|e| e > now_ms));
        if self.lease_ends.len() != before {
            self.dirty = true;
        }
        self.strikes
            .retain(|_, (_, last)| now_ms.saturating_sub(*last) <= ms(STRIKE_MEMORY));
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
        Persisted {
            claims,
            operator_lifts,
            retracted,
            peer_ends,
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
        for (i, (name, used)) in [("IPv4", v4), ("IPv6", v6)].into_iter().enumerate() {
            let above = used as f64 >= capacity as f64 * WATERMARK;
            if above != self.above[i] {
                self.above[i] = above;
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
}

/// The XDP program's LPM tries.
pub struct KernelBlocklist {
    v4: LpmTrie<MapData, [u8; 4], u32>,
    v6: LpmTrie<MapData, [u8; 16], u32>,
}

impl Blocklist for KernelBlocklist {
    fn add(&mut self, net: IpNet) -> Result<(), MapError> {
        match net {
            IpNet::V4(n) => self.v4.insert(
                &Key::new(n.prefix_len() as u32, n.network().octets()),
                1u32,
                0,
            ),
            IpNet::V6(n) => self.v6.insert(
                &Key::new(n.prefix_len() as u32, n.network().octets()),
                1u32,
                0,
            ),
        }
    }

    fn delete(&mut self, net: IpNet) -> Result<(), MapError> {
        match net {
            IpNet::V4(n) => self
                .v4
                .remove(&Key::new(n.prefix_len() as u32, n.network().octets())),
            IpNet::V6(n) => self
                .v6
                .remove(&Key::new(n.prefix_len() as u32, n.network().octets())),
        }
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
    }

    fn table(node: u64, capacity: usize) -> BlockTable<FakeLists> {
        BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity,
                fail_delete: false,
                deletes: 0,
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
}
