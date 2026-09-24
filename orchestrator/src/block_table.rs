//! The XDP blocklists plus the lifetimes of their entries.
//!
//! Static blocks (`--block`) are permanent. Dynamic blocks (traps, IPC, mesh) expire: the first
//! block of an address lasts `base`, each repeat within `STRIKE_MEMORY` doubles it, up to `max`.
//! Without expiry every trap hit was a permanent ban, so dynamic addresses of legitimate users
//! stayed blocked forever and the 65 536-entry maps eventually filled up.
//!
//! An operator unban or flush leaves the address *lifted* for `max`: peers may still hold their
//! copy of the block that long, and their catch-up (`BlockSync`) must not quietly reinstate it.
//! A fresh block (a local detection or a peer's live `BlockIp`) overrides the lift.
use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use std::time::{Duration, Instant};

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
pub enum Lifetime {
    Permanent,
    Dynamic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlPolicy {
    /// Zero disables expiry: dynamic blocks become permanent.
    pub base: Duration,
    pub max: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Permanent,
    Until(Instant),
    Expired,
    /// Lifted by the operator; peers' snapshots are not adopted before this instant.
    Lifted(Instant),
}

impl State {
    fn is_active(self) -> bool {
        matches!(self, State::Permanent | State::Until(_))
    }
}

#[derive(Debug)]
struct Entry {
    state: State,
    strikes: u32,
    last_strike: Instant,
}

/// Pure bookkeeping, independent of the kernel maps (and of the clock: callers pass `now`).
#[derive(Debug)]
pub struct ExpiryTracker {
    policy: TtlPolicy,
    entries: HashMap<IpNet, Entry>,
}

impl ExpiryTracker {
    pub fn new(policy: TtlPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
        }
    }

    /// Records a block and returns its lifetime (`None` = permanent).
    pub fn record(&mut self, ip: IpNet, lifetime: Lifetime, now: Instant) -> Option<Duration> {
        let entry = self.entries.entry(ip).or_insert(Entry {
            state: State::Expired,
            strikes: 0,
            last_strike: now,
        });
        if now.duration_since(entry.last_strike) > STRIKE_MEMORY {
            entry.strikes = 0;
        }
        entry.strikes = entry.strikes.saturating_add(1);
        entry.last_strike = now;

        if lifetime == Lifetime::Permanent
            || entry.state == State::Permanent
            || self.policy.base.is_zero()
        {
            entry.state = State::Permanent;
            return None;
        }

        let factor = 1u32.checked_shl(entry.strikes - 1).unwrap_or(u32::MAX);
        let ttl = self.policy.base.saturating_mul(factor).min(self.policy.max);
        let until = now + ttl;
        entry.state = match entry.state {
            State::Until(existing) if existing > until => State::Until(existing),
            _ => State::Until(until),
        };
        Some(ttl)
    }

    /// Adopts a block learned from a peer's snapshot until `now + remaining` (capped at the local
    /// maximum, so a peer cannot impose an endless block). Does not count as a strike. Returns
    /// true if the address was not blocked before.
    pub fn record_until(&mut self, ip: IpNet, remaining: Duration, now: Instant) -> bool {
        let until = now + remaining.min(self.policy.max);
        let entry = self.entries.entry(ip).or_insert(Entry {
            state: State::Expired,
            strikes: 0,
            last_strike: now,
        });
        match entry.state {
            State::Permanent => false,
            State::Lifted(lifted) if lifted > now => false,
            State::Until(existing) => {
                if until > existing {
                    entry.state = State::Until(until);
                }
                false
            }
            State::Expired | State::Lifted(_) => {
                entry.state = State::Until(until);
                true
            }
        }
    }

    /// Whether [`Self::record_until`] would adopt `ip` as a new block.
    pub fn adoptable(&self, ip: &IpNet, now: Instant) -> bool {
        match self.entries.get(ip).map(|e| e.state) {
            None | Some(State::Expired) => true,
            Some(State::Lifted(lifted)) => lifted <= now,
            Some(State::Permanent | State::Until(_)) => false,
        }
    }

    /// Operator unban: ends any block of `ip`, permanent ones included, forgets its strikes, and
    /// refuses peers' copies of it for `max`.
    pub fn lift(&mut self, ip: IpNet, now: Instant) {
        self.entries.insert(
            ip,
            Entry {
                state: State::Lifted(now + self.policy.max),
                strikes: 0,
                last_strike: now,
            },
        );
    }

    /// Running dynamic blocks and their remaining time, for a peer that just (re)connected.
    pub fn dynamic_snapshot(&self, now: Instant) -> Vec<(IpNet, Duration)> {
        let mut out: Vec<(IpNet, Duration)> = self
            .entries
            .iter()
            .filter_map(|(ip, e)| match e.state {
                State::Until(until) if until > now => Some((*ip, until - now)),
                _ => None,
            })
            .collect();
        out.sort();
        out
    }

    pub fn is_permanent(&self, ip: &IpNet) -> bool {
        self.entries
            .get(ip)
            .is_some_and(|e| e.state == State::Permanent)
    }

    /// Forgets a dynamic block and returns true; a permanent block is kept and false returned.
    pub fn release_dynamic(&mut self, ip: &IpNet) -> bool {
        if self.is_permanent(ip) {
            return false;
        }
        self.forget(ip);
        true
    }

    pub fn forget(&mut self, ip: &IpNet) {
        self.entries.remove(ip);
    }

    /// Ends every running dynamic block now (keeping strike history) and lifts it, see
    /// [`Self::lift`]; returns their addresses.
    pub fn take_all_dynamic(&mut self, now: Instant) -> Vec<IpNet> {
        let lifted = State::Lifted(now + self.policy.max);
        let mut released = Vec::new();
        for (ip, entry) in self.entries.iter_mut() {
            if let State::Until(_) = entry.state {
                entry.state = lifted;
                released.push(*ip);
            }
        }
        released
    }

    /// Addresses whose block ran out at `now`. Their strike history is kept for escalation.
    pub fn take_expired(&mut self, now: Instant) -> Vec<IpNet> {
        let mut expired = Vec::new();
        for (ip, entry) in self.entries.iter_mut() {
            if let State::Until(until) = entry.state {
                if until <= now {
                    entry.state = State::Expired;
                    expired.push(*ip);
                }
            }
        }
        self.entries.retain(|_, e| match e.state {
            State::Lifted(lifted) if lifted > now => true,
            State::Expired | State::Lifted(_) => now.duration_since(e.last_strike) <= STRIKE_MEMORY,
            _ => true,
        });
        expired
    }

    pub fn active(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.state.is_active())
            .count()
    }

    pub fn active_ips(&self) -> std::collections::HashSet<IpNet> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state.is_active())
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Active blocks as (IPv4, IPv6) — each family has its own kernel map.
    pub fn active_by_family(&self) -> (usize, usize) {
        let active = self.entries.iter().filter(|(_, e)| e.state.is_active());
        active.fold((0, 0), |(v4, v6), (ip, _)| match ip {
            IpNet::V4(_) => (v4 + 1, v6),
            IpNet::V6(_) => (v4, v6 + 1),
        })
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

pub struct BlockTable<B = KernelBlocklist> {
    lists: B,
    expiry: ExpiryTracker,
}

impl BlockTable<KernelBlocklist> {
    pub fn new(
        v4: LpmTrie<MapData, [u8; 4], u32>,
        v6: LpmTrie<MapData, [u8; 16], u32>,
        policy: TtlPolicy,
    ) -> Self {
        Self::with_lists(KernelBlocklist { v4, v6 }, policy)
    }
}

impl<B: Blocklist> BlockTable<B> {
    pub fn with_lists(lists: B, policy: TtlPolicy) -> Self {
        Self {
            lists,
            expiry: ExpiryTracker::new(policy),
        }
    }

    /// Adds `ip` (as a /32 or /128) to the kernel blocklist. Returns the lifetime applied.
    pub fn insert(
        &mut self,
        ip: IpNet,
        lifetime: Lifetime,
        now: Instant,
    ) -> Result<Option<Duration>, MapError> {
        let net = canonical(ip);
        self.insert_into_map(net)?;
        Ok(self.expiry.record(net, lifetime, now))
    }

    /// Unblocks a dynamic block. Returns `Ok(false)` for a permanent (operator) block, which
    /// only the operator's own configuration may lift.
    pub fn remove_dynamic(&mut self, ip: IpNet) -> Result<bool, MapError> {
        let ip = canonical(ip);
        if !self.expiry.release_dynamic(&ip) {
            return Ok(false);
        }
        self.remove_from_map(ip)?;
        Ok(true)
    }

    /// Lifts any block of `ip`, permanent ones included (operator authority); see
    /// [`ExpiryTracker::lift`].
    pub fn remove(&mut self, ip: IpNet, now: Instant) -> Result<(), MapError> {
        let ip = canonical(ip);
        self.expiry.lift(ip, now);
        self.remove_from_map(ip)
    }

    /// Lifts all dynamic blocks; operator and `--block` bans stay.
    pub fn flush_dynamic(&mut self, now: Instant) -> Vec<IpNet> {
        let released = self.expiry.take_all_dynamic(now);
        for ip in &released {
            if let Err(e) = self.remove_from_map(*ip) {
                log::error!(
                    "[BlockTable] Failed to remove flushed block {}: {:?}",
                    ip,
                    e
                );
            }
        }
        released
    }

    fn insert_into_map(&mut self, net: IpNet) -> Result<(), MapError> {
        self.lists.add(net)
    }

    fn remove_from_map(&mut self, net: IpNet) -> Result<(), MapError> {
        self.lists.delete(net)
    }

    /// Removes blocks whose lifetime ended; returns the addresses that were released.
    pub fn expire(&mut self, now: Instant) -> Vec<IpNet> {
        let expired = self.expiry.take_expired(now);
        for ip in &expired {
            if let Err(e) = self.remove_from_map(*ip) {
                log::error!(
                    "[BlockTable] Failed to remove expired block {}: {:?}",
                    ip,
                    e
                );
            }
        }
        expired
    }

    pub fn active(&self) -> usize {
        self.expiry.active()
    }

    pub fn active_by_family(&self) -> (usize, usize) {
        self.expiry.active_by_family()
    }

    /// Installs a block from a peer's snapshot; see [`ExpiryTracker::record_until`]. The kernel
    /// map is written first: when it is full the address must not be counted (and passed on to
    /// other peers) as blocked while the XDP program lets it through.
    pub fn insert_until(
        &mut self,
        ip: IpNet,
        remaining: Duration,
        now: Instant,
    ) -> Result<bool, MapError> {
        let ip = canonical(ip);
        if self.expiry.adoptable(&ip, now) {
            self.insert_into_map(ip)?;
        }
        Ok(self.expiry.record_until(ip, remaining, now))
    }

    pub fn dynamic_snapshot(&self, now: Instant) -> Vec<(IpNet, Duration)> {
        self.expiry.dynamic_snapshot(now)
    }

    pub fn active_ips(&self) -> std::collections::HashSet<IpNet> {
        self.expiry.active_ips()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: TtlPolicy = TtlPolicy {
        base: Duration::from_secs(60),
        max: Duration::from_secs(600),
    };

    fn ip(s: &str) -> IpNet {
        parse_target(s).unwrap()
    }

    #[test]
    fn dynamic_blocks_expire_and_escalate() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.1");

        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t0),
            Some(Duration::from_secs(60))
        );
        assert!(tracker
            .take_expired(t0 + Duration::from_secs(59))
            .is_empty());
        assert_eq!(tracker.take_expired(t0 + Duration::from_secs(60)), vec![a]);
        assert!(
            tracker
                .take_expired(t0 + Duration::from_secs(61))
                .is_empty(),
            "released once"
        );

        let t1 = t0 + Duration::from_secs(120);
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t1),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t1),
            Some(Duration::from_secs(240))
        );
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t1),
            Some(Duration::from_secs(480))
        );
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t1),
            Some(Duration::from_secs(600)),
            "capped"
        );
        for _ in 0..40 {
            assert_eq!(
                tracker.record(a, Lifetime::Dynamic, t1),
                Some(Duration::from_secs(600))
            );
        }
    }

    #[test]
    fn strikes_are_forgotten_after_the_memory_window() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.2");
        tracker.record(a, Lifetime::Dynamic, t0);
        tracker.record(a, Lifetime::Dynamic, t0);
        let later = t0 + STRIKE_MEMORY + Duration::from_secs(1);
        assert_eq!(tracker.take_expired(later), vec![a]);
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, later),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn a_shorter_new_block_does_not_cut_a_longer_one() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(TtlPolicy {
            base: Duration::from_secs(60),
            max: Duration::from_secs(60),
        });
        let a = ip("203.0.113.3");
        tracker.record(a, Lifetime::Dynamic, t0 + Duration::from_secs(30));
        tracker.record(a, Lifetime::Dynamic, t0);
        assert!(tracker
            .take_expired(t0 + Duration::from_secs(60))
            .is_empty());
        assert_eq!(tracker.take_expired(t0 + Duration::from_secs(90)), vec![a]);
    }

    #[test]
    fn permanent_blocks_never_expire_and_stay_permanent() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.4");
        assert_eq!(tracker.record(a, Lifetime::Permanent, t0), None);
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t0),
            None,
            "a trap hit must not shorten a static block"
        );
        assert!(tracker
            .take_expired(t0 + Duration::from_secs(10_000_000))
            .is_empty());
        assert_eq!(tracker.active(), 1);
    }

    #[test]
    fn only_dynamic_blocks_can_be_released() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let (operator, dynamic) = (ip("203.0.113.7"), ip("203.0.113.8"));
        tracker.record(operator, Lifetime::Permanent, t0);
        tracker.record(dynamic, Lifetime::Dynamic, t0);
        assert!(
            !tracker.release_dynamic(&operator),
            "a mesh unblock must not lift an operator block"
        );
        assert!(tracker.is_permanent(&operator));
        assert!(tracker.release_dynamic(&dynamic));
        assert_eq!(tracker.active(), 1);
    }

    #[test]
    fn flush_releases_only_dynamic_blocks() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let (operator, dynamic) = (ip("203.0.113.9"), ip("203.0.113.10"));
        tracker.record(operator, Lifetime::Permanent, t0);
        tracker.record(dynamic, Lifetime::Dynamic, t0);
        assert_eq!(tracker.take_all_dynamic(t0), vec![dynamic]);
        assert!(tracker.take_all_dynamic(t0).is_empty());
        assert_eq!(tracker.active(), 1);
        assert!(tracker.is_permanent(&operator));
        // Strike history survives a flush: the next block escalates.
        assert_eq!(
            tracker.record(dynamic, Lifetime::Dynamic, t0),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn counts_by_family_and_reports_watermark_crossings_once() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        tracker.record(ip("203.0.113.1"), Lifetime::Dynamic, t0);
        tracker.record(ip("203.0.113.2"), Lifetime::Permanent, t0);
        tracker.record(ip("2001:db8::1"), Lifetime::Dynamic, t0);
        assert_eq!(tracker.active_by_family(), (2, 1));

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
    fn snapshot_and_adoption_of_peer_blocks() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut a = ExpiryTracker::new(POLICY);
        a.record(ip("203.0.113.20"), Lifetime::Dynamic, t0);
        a.record(ip("203.0.113.21"), Lifetime::Permanent, t0);
        let snap = a.dynamic_snapshot(t0 + s(10));
        assert_eq!(
            snap,
            vec![(ip("203.0.113.20"), s(50))],
            "only running dynamic blocks, with time left"
        );

        let mut b = ExpiryTracker::new(POLICY);
        assert!(b.record_until(ip("203.0.113.20"), s(50), t0));
        assert!(
            !b.record_until(ip("203.0.113.20"), s(50), t0),
            "second sync is not new"
        );
        assert_eq!(b.take_expired(t0 + s(50)), vec![ip("203.0.113.20")]);

        // A peer cannot impose a block longer than the local maximum.
        assert!(b.record_until(ip("203.0.113.22"), s(1_000_000), t0));
        assert!(b
            .take_expired(t0 + POLICY.max)
            .contains(&ip("203.0.113.22")));

        // Nor shorten or override a local permanent block.
        b.record(ip("203.0.113.23"), Lifetime::Permanent, t0);
        assert!(!b.record_until(ip("203.0.113.23"), s(1), t0));
        assert!(b.is_permanent(&ip("203.0.113.23")));
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
    fn prefixes_and_hosts_are_tracked_separately() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        tracker.record(ip("198.51.100.0/24"), Lifetime::Dynamic, t0);
        tracker.record(ip("198.51.100.9"), Lifetime::Permanent, t0);
        assert_eq!(tracker.active_by_family(), (2, 0));
        assert_eq!(
            tracker.take_expired(t0 + Duration::from_secs(60)),
            vec![ip("198.51.100.0/24")]
        );
        assert!(tracker.is_permanent(&ip("198.51.100.9")));
    }

    #[test]
    fn zero_base_disables_expiry() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(TtlPolicy {
            base: Duration::ZERO,
            max: Duration::ZERO,
        });
        assert_eq!(
            tracker.record(ip("203.0.113.5"), Lifetime::Dynamic, t0),
            None
        );
        assert!(tracker
            .take_expired(t0 + Duration::from_secs(10_000_000))
            .is_empty());
    }

    #[test]
    fn forget_drops_history() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.6");
        tracker.record(a, Lifetime::Dynamic, t0);
        tracker.record(a, Lifetime::Dynamic, t0);
        tracker.forget(&a);
        assert_eq!(tracker.active(), 0);
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t0),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn an_operator_lift_is_not_undone_by_a_peer_snapshot() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.30");
        tracker.record(a, Lifetime::Dynamic, t0);
        tracker.lift(a, t0 + s(5));
        assert_eq!(tracker.active(), 0);
        assert!(tracker.dynamic_snapshot(t0 + s(5)).is_empty());
        assert!(
            !tracker.record_until(a, s(55), t0 + s(10)),
            "a peer's copy of the block must not reinstate it"
        );
        assert_eq!(tracker.active(), 0);
        assert!(!tracker.adoptable(&a, t0 + s(10)));
        // Peers' copies are capped at `max`, so after that the lift ends.
        assert!(tracker.adoptable(&a, t0 + s(5) + POLICY.max));
        assert!(tracker.record_until(a, s(30), t0 + s(5) + POLICY.max));
        // The lift survives expiry sweeps while it lasts.
        let b = ip("203.0.113.31");
        tracker.lift(b, t0);
        assert!(tracker.take_expired(t0 + s(1)).is_empty());
        assert!(!tracker.record_until(b, s(30), t0 + s(1)));
    }

    #[test]
    fn a_fresh_block_overrides_a_lift_and_starts_from_base() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.32");
        tracker.record(a, Lifetime::Dynamic, t0);
        tracker.record(a, Lifetime::Dynamic, t0);
        tracker.lift(a, t0);
        assert_eq!(
            tracker.record(a, Lifetime::Dynamic, t0),
            Some(Duration::from_secs(60)),
            "an unban forgives past strikes"
        );
        assert_eq!(tracker.active(), 1);
    }

    #[test]
    fn a_flush_lifts_the_released_blocks() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.33");
        tracker.record(a, Lifetime::Dynamic, t0);
        assert_eq!(tracker.take_all_dynamic(t0), vec![a]);
        assert!(!tracker.record_until(a, Duration::from_secs(50), t0));
        assert_eq!(tracker.active(), 0);
    }

    /// A kernel map stand-in with a fixed capacity, like the XDP LPM tries.
    struct FakeLists {
        nets: std::collections::HashSet<IpNet>,
        capacity: usize,
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
            if self.nets.remove(&net) {
                Ok(())
            } else {
                Err(MapError::KeyNotFound)
            }
        }
    }

    fn table(capacity: usize) -> BlockTable<FakeLists> {
        BlockTable::with_lists(
            FakeLists {
                nets: Default::default(),
                capacity,
            },
            POLICY,
        )
    }

    #[test]
    fn a_peer_block_that_does_not_fit_the_map_is_not_counted() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut t = table(1);
        t.insert(ip("198.51.100.1"), Lifetime::Dynamic, t0).unwrap();
        let synced = ip("198.51.100.2");
        assert!(t.insert_until(synced, s(50), t0).is_err());
        assert!(!t.lists.nets.contains(&synced));
        assert_eq!(t.active(), 1, "only what the kernel enforces");
        assert!(
            !t.dynamic_snapshot(t0).iter().any(|(n, _)| *n == synced),
            "not passed on to other peers as blocked"
        );
        // Once there is room, the next sync installs it.
        t.expire(t0 + s(60));
        assert!(t.insert_until(synced, s(50), t0 + s(60)).unwrap());
        assert!(t.lists.nets.contains(&synced));
    }

    #[test]
    fn an_operator_unban_holds_against_a_peer_snapshot() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut t = table(8);
        let a = ip("198.51.100.3");
        t.insert(a, Lifetime::Dynamic, t0).unwrap();
        t.remove(a, t0).unwrap();
        assert!(!t.insert_until(a, s(50), t0 + s(1)).unwrap());
        assert!(!t.lists.nets.contains(&a), "the kernel map stays clear");
        assert_eq!(t.active(), 0);
        // A new detection blocks it again.
        t.insert(a, Lifetime::Dynamic, t0 + s(2)).unwrap();
        assert!(t.lists.nets.contains(&a));
    }
}
