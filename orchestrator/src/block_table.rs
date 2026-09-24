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

/// Pending kernel operations retried per tick (a full map must not cost a syscall per entry per s).
pub const MAX_RETRIES_PER_TICK: usize = 256;

/// Distinct nodes remembered per retracted id (the issuer plus a few others).
const MAX_RETRACTORS: usize = 4;

/// Known claims (and retraction records) beyond this are refused (a flooding peer cannot exhaust memory).
pub const MAX_KNOWN_CLAIMS: usize = 4 * common::BLOCKLIST_CAPACITY as usize;

struct Held {
    claim: Claim,
    net: IpNet,
    /// Local enforcement end: a peer's claim is capped at the local `max`.
    until_ms: Option<u64>,
    /// Passed the local never-block policy.
    allowed: bool,
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
    /// New; known but not enforced here (retracted, protected, expired, or map error pending).
    Held,
    Known,
    Refused(&'static str),
}

/// Durable part of the table (ADR-4): this node's own decisions and lifts.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Persisted {
    pub claims: Vec<Claim>,
    pub operator_lifts: Vec<(ClaimId, Option<u64>)>,
    pub retracted: Vec<(ClaimId, Option<u64>)>,
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
    strikes: HashMap<IpNet, (u32, u64)>,
    dirty: bool,
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
            strikes: HashMap::new(),
            dirty: false,
        }
    }

    fn retracted(&self, id: &ClaimId, held: &Held) -> bool {
        self.retractions
            .get(id)
            .is_some_and(|r| r.operator || r.by_nodes.contains(&held.claim.issuer))
    }

    fn effective(&self, id: &ClaimId, held: &Held, now_ms: u64) -> bool {
        held.allowed && held.until_ms.is_none_or(|u| u > now_ms) && !self.retracted(id, held)
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
        }
        result
    }

    fn insert_held(&mut self, id: ClaimId, held: Held) {
        self.by_target
            .entry(held.net)
            .or_default()
            .insert(id.clone());
        self.claims.insert(id, held);
    }

    /// A decision made on this node. The caller has checked the never-block policy.
    pub fn add_local(&mut self, net: IpNet, kind: ClaimKind, reason: &str, now_ms: u64) -> Added {
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
        // Each repeat is its own claim, so a shorter repeat cannot cut a longer running block.
        let claim = Claim {
            issuer: self.node_id,
            kind,
            target: show(&net),
            issued_ms: now_ms,
            expires_ms: ttl.map(|t| now_ms.saturating_add(ms(t))),
            reason: reason.to_string(),
        };
        let id = claim.id();
        self.insert_held(
            id,
            Held {
                until_ms: claim.expires_ms,
                claim: claim.clone(),
                net,
                allowed: true,
            },
        );
        if kind != ClaimKind::Static {
            self.dirty = true;
        }
        let applied = self.reconcile(net, now_ms);
        Added {
            claim,
            ttl,
            applied,
        }
    }

    /// A claim from a peer (live or in a snapshot). `allowed` is the local never-block verdict.
    pub fn adopt(&mut self, claim: Claim, allowed: bool, now_ms: u64) -> Adoption {
        if claim.kind != ClaimKind::Detector {
            return Adoption::Refused("only detector claims are shared");
        }
        let Some(net) = claim.net() else {
            return Adoption::Refused("target is not canonical");
        };
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
        let cap = now_ms.saturating_add(ms(self.policy.max));
        let until_ms = Some(claim.expires_ms.map_or(cap, |e| e.min(cap)));
        self.insert_held(
            id.clone(),
            Held {
                claim,
                net,
                until_ms,
                allowed,
            },
        );
        let was = self.applied.contains(&net);
        let result = self.reconcile(net, now_ms);
        match result {
            Ok(()) if !was && self.applied.contains(&net) => Adoption::Enforced,
            _ => Adoption::Held,
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
            if !self.retractions.contains_key(id) && self.retractions.len() >= MAX_KNOWN_CLAIMS {
                continue;
            }
            let r = self.retractions.entry(id.clone()).or_default();
            if !r.by_nodes.contains(&issuer) && r.by_nodes.len() < MAX_RETRACTORS {
                r.by_nodes.push(issuer);
            }
            r.forget_ms = match (r.forget_ms, forget_ms) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
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
        let mut touched: Vec<IpNet> = self
            .claims
            .values()
            .filter(|h| h.until_ms.is_some_and(|u| u <= now_ms))
            .map(|h| h.net)
            .collect();
        touched.extend(self.pending.iter().copied().take(MAX_RETRIES_PER_TICK));

        let dead: Vec<ClaimId> = self
            .claims
            .iter()
            .filter(|(_, h)| !h.claim.live_at(now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        for id in dead {
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
        self.retractions
            .retain(|_, r| r.forget_ms.is_none_or(|f| f > now_ms));
        self.strikes
            .retain(|_, (_, last)| now_ms.saturating_sub(*last) <= ms(STRIKE_MEMORY));
        self.settle(touched, now_ms)
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

    /// The mesh state this node shares: detector claims that are live and not retracted by their
    /// issuer (whatever this node's own operator or policy did with them), and this node's own
    /// retractions.
    pub fn snapshot(&self, now_ms: u64) -> (Vec<Claim>, Vec<ClaimId>) {
        let mut claims: Vec<(&ClaimId, &Claim)> = self
            .claims
            .iter()
            .filter(|(id, h)| self.shared(id, h, now_ms))
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

    /// Digest of the shared claim set; equal digests mean two nodes need not exchange snapshots.
    pub fn digest(&self, now_ms: u64) -> String {
        let mut ids: Vec<&ClaimId> = self
            .claims
            .iter()
            .filter(|(id, h)| self.shared(id, h, now_ms))
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        let mut hasher = blake3::Hasher::new();
        for id in ids {
            hasher.update(id.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
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
        Persisted {
            claims,
            operator_lifts,
            retracted,
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
            },
            POLICY,
            node,
        )
    }

    fn detect(t: &mut BlockTable<FakeLists>, target: &str, now: u64) -> Claim {
        t.add_local(ip(target), ClaimKind::Detector, "test", now)
            .claim
    }

    #[test]
    fn detector_blocks_escalate_and_are_capped() {
        let mut t = table(1, 64);
        let a = ip("203.0.113.1");
        let ttl =
            |t: &mut BlockTable<FakeLists>, now| t.add_local(a, ClaimKind::Detector, "x", now).ttl;
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(60)));
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(120)));
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(240)));
        assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(480)));
        for _ in 0..40 {
            assert_eq!(ttl(&mut t, T0), Some(Duration::from_secs(600)), "capped");
        }
        let later = T0 + ms(STRIKE_MEMORY) + S;
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
            },
            TtlPolicy {
                base: Duration::ZERO,
                max: Duration::ZERO,
            },
            1,
        );
        let c = t
            .add_local(ip("203.0.113.5"), ClaimKind::Detector, "x", T0)
            .claim;
        assert_eq!(c.expires_ms, None);
        assert!(t.tick(T0 + 10_000_000 * S).is_empty());
        assert_eq!(t.active(), 1);
    }

    #[test]
    fn only_the_configuration_lifts_a_static_block() {
        let mut t = table(1, 64);
        let a = ip("198.51.100.1");
        t.add_local(a, ClaimKind::Static, "--block", T0);
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
        assert!(!n4.is_blocked(ip("203.0.113.18")), "the claim came back to life");
    }

    #[test]
    fn a_retraction_that_arrives_first_still_applies() {
        let mut n1 = table(1, 64);
        let c = detect(&mut n1, "203.0.113.11", T0);
        let mut n2 = table(2, 64);
        n2.retract(1, &[c.id()], T0);
        assert_eq!(n2.adopt(c, true, T0), Adoption::Held);
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
                Adoption::Known | Adoption::Held
            ));
            assert!(!n1.is_blocked(a), "day {}: the lifted claim came back", day);
            // After a restart the peer's copy arrives as new (peer claims are not persisted):
            // only the persisted lift, which names the claim, keeps it out.
            let mut restarted = table(1, 64);
            restarted.restore(n1.take_persisted(now), |_| true, now);
            restarted.adopt(long.clone(), true, now);
            assert!(!restarted.is_blocked(a), "day {}: back after a restart", day);
        }
        let fresh = detect(&mut peer, "203.0.113.12", T0 + 3 * S);
        assert_eq!(n1.adopt(fresh, true, T0 + 3 * S), Adoption::Enforced);
    }

    #[test]
    fn a_peer_claim_is_capped_at_the_local_maximum() {
        let mut peer = BlockTable::with_lists(
            FakeLists {
                nets: HashSet::new(),
                capacity: 8,
                fail_delete: false,
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
        let added = t.add_local(ip("198.51.100.21"), ClaimKind::Detector, "x", T0 + 30 * S);
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
        assert_eq!(n1.adopt(c, false, T0), Adoption::Held);
        assert!(!n1.is_blocked(ip("203.0.113.14")));
        assert_eq!(
            n1.digest(T0),
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

    #[test]
    fn one_exchange_converges_including_retractions() {
        let (mut n1, mut n2, mut n3) = (table(1, 64), table(2, 64), table(3, 64));
        detect(&mut n1, "203.0.113.30", T0);
        let c2 = detect(&mut n2, "203.0.113.31", T0);
        exchange(&mut n1, &mut n2, T0);
        exchange(&mut n1, &mut n3, T0);
        // n2 retracts its claim while n3 is cut off; n3 hears of it only through a later exchange.
        n2.retract(2, &[c2.id()], T0 + S);
        exchange(&mut n1, &mut n2, T0 + S);
        assert_ne!(n3.digest(T0 + S), n2.digest(T0 + S));
        exchange(&mut n2, &mut n3, T0 + 2 * S);
        exchange(&mut n1, &mut n3, T0 + 2 * S);
        let d = n1.digest(T0 + 2 * S);
        assert_eq!(n2.digest(T0 + 2 * S), d);
        assert_eq!(n3.digest(T0 + 2 * S), d);
        assert!(!n3.is_blocked(ip("203.0.113.31")));
        assert!(n3.is_blocked(ip("203.0.113.30")));
    }

    #[test]
    fn a_flush_lifts_all_detector_claims_and_retracts_own_ones() {
        let mut n2 = table(2, 64);
        let theirs = detect(&mut n2, "203.0.113.40", T0);
        let mut n1 = table(1, 64);
        n1.adopt(theirs, true, T0);
        let mine = detect(&mut n1, "203.0.113.41", T0);
        n1.add_local(ip("203.0.113.42"), ClaimKind::Operator, "x", T0);
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
        n1.add_local(ip("203.0.113.51"), ClaimKind::Operator, "op", T0);
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
        assert_eq!(again.adopt(theirs, true, T0 + S), Adoption::Held);
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
        t.add_local(ip("203.0.113.2"), ClaimKind::Operator, "x", T0);
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
        t.add_local(ip("198.51.100.9"), ClaimKind::Operator, "x", T0);
        assert_eq!(t.active_by_family(), (2, 0));
        assert_eq!(t.tick(T0 + 60 * S), vec![ip("198.51.100.0/24")]);
        assert!(t.is_blocked(ip("198.51.100.9")));
    }
}
