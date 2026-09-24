//! The XDP blocklists plus the lifetimes of their entries.
//!
//! Static blocks (`--block`) are permanent. Dynamic blocks (traps, IPC, mesh) expire: the first
//! block of an address lasts `base`, each repeat within `STRIKE_MEMORY` doubles it, up to `max`.
//! Without expiry every trap hit was a permanent ban, so dynamic addresses of legitimate users
//! stayed blocked forever and the 65 536-entry maps eventually filled up.
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use aya::maps::lpm_trie::Key;
use aya::maps::{LpmTrie, MapData, MapError};

/// How long an address's past blocks count towards escalation.
pub const STRIKE_MEMORY: Duration = Duration::from_secs(24 * 3600);

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
    entries: HashMap<IpAddr, Entry>,
}

impl ExpiryTracker {
    pub fn new(policy: TtlPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
        }
    }

    /// Records a block and returns its lifetime (`None` = permanent).
    pub fn record(&mut self, ip: IpAddr, lifetime: Lifetime, now: Instant) -> Option<Duration> {
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

        if lifetime == Lifetime::Permanent || entry.state == State::Permanent || self.policy.base.is_zero() {
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

    pub fn is_permanent(&self, ip: &IpAddr) -> bool {
        self.entries.get(ip).is_some_and(|e| e.state == State::Permanent)
    }

    /// Forgets a dynamic block and returns true; a permanent block is kept and false returned.
    pub fn release_dynamic(&mut self, ip: &IpAddr) -> bool {
        if self.is_permanent(ip) {
            return false;
        }
        self.forget(ip);
        true
    }

    pub fn forget(&mut self, ip: &IpAddr) {
        self.entries.remove(ip);
    }

    /// Addresses whose block ran out at `now`. Their strike history is kept for escalation.
    pub fn take_expired(&mut self, now: Instant) -> Vec<IpAddr> {
        let mut expired = Vec::new();
        for (ip, entry) in self.entries.iter_mut() {
            if let State::Until(until) = entry.state {
                if until <= now {
                    entry.state = State::Expired;
                    expired.push(*ip);
                }
            }
        }
        self.entries.retain(|_, e| {
            e.state != State::Expired || now.duration_since(e.last_strike) <= STRIKE_MEMORY
        });
        expired
    }

    pub fn active(&self) -> usize {
        self.entries.values().filter(|e| e.state != State::Expired).count()
    }
}

pub struct BlockTable {
    v4: LpmTrie<MapData, [u8; 4], u32>,
    v6: LpmTrie<MapData, [u8; 16], u32>,
    expiry: ExpiryTracker,
}

impl BlockTable {
    pub fn new(
        v4: LpmTrie<MapData, [u8; 4], u32>,
        v6: LpmTrie<MapData, [u8; 16], u32>,
        policy: TtlPolicy,
    ) -> Self {
        Self {
            v4,
            v6,
            expiry: ExpiryTracker::new(policy),
        }
    }

    /// Adds `ip` (as a /32 or /128) to the kernel blocklist. Returns the lifetime applied.
    pub fn insert(&mut self, ip: IpAddr, lifetime: Lifetime, now: Instant) -> Result<Option<Duration>, MapError> {
        match ip.to_canonical() {
            IpAddr::V4(v4) => self.v4.insert(&Key::new(32, v4.octets()), 1u32, 0)?,
            IpAddr::V6(v6) => self.v6.insert(&Key::new(128, v6.octets()), 1u32, 0)?,
        }
        Ok(self.expiry.record(ip.to_canonical(), lifetime, now))
    }

    /// Unblocks a dynamic block. Returns `Ok(false)` for a permanent (operator) block, which
    /// only the operator's own configuration may lift.
    pub fn remove_dynamic(&mut self, ip: IpAddr) -> Result<bool, MapError> {
        let ip = ip.to_canonical();
        if !self.expiry.release_dynamic(&ip) {
            return Ok(false);
        }
        self.remove_from_map(ip)?;
        Ok(true)
    }

    fn remove_from_map(&mut self, ip: IpAddr) -> Result<(), MapError> {
        match ip {
            IpAddr::V4(v4) => self.v4.remove(&Key::new(32, v4.octets())),
            IpAddr::V6(v6) => self.v6.remove(&Key::new(128, v6.octets())),
        }
    }

    /// Removes blocks whose lifetime ended; returns the addresses that were released.
    pub fn expire(&mut self, now: Instant) -> Vec<IpAddr> {
        let expired = self.expiry.take_expired(now);
        for ip in &expired {
            if let Err(e) = self.remove_from_map(*ip) {
                log::error!("[BlockTable] Failed to remove expired block {}: {:?}", ip, e);
            }
        }
        expired
    }

    pub fn active(&self) -> usize {
        self.expiry.active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: TtlPolicy = TtlPolicy {
        base: Duration::from_secs(60),
        max: Duration::from_secs(600),
    };

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dynamic_blocks_expire_and_escalate() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.1");

        assert_eq!(tracker.record(a, Lifetime::Dynamic, t0), Some(Duration::from_secs(60)));
        assert!(tracker.take_expired(t0 + Duration::from_secs(59)).is_empty());
        assert_eq!(tracker.take_expired(t0 + Duration::from_secs(60)), vec![a]);
        assert!(tracker.take_expired(t0 + Duration::from_secs(61)).is_empty(), "released once");

        let t1 = t0 + Duration::from_secs(120);
        assert_eq!(tracker.record(a, Lifetime::Dynamic, t1), Some(Duration::from_secs(120)));
        assert_eq!(tracker.record(a, Lifetime::Dynamic, t1), Some(Duration::from_secs(240)));
        assert_eq!(tracker.record(a, Lifetime::Dynamic, t1), Some(Duration::from_secs(480)));
        assert_eq!(tracker.record(a, Lifetime::Dynamic, t1), Some(Duration::from_secs(600)), "capped");
        for _ in 0..40 {
            assert_eq!(tracker.record(a, Lifetime::Dynamic, t1), Some(Duration::from_secs(600)));
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
        assert_eq!(tracker.record(a, Lifetime::Dynamic, later), Some(Duration::from_secs(60)));
    }

    #[test]
    fn a_shorter_new_block_does_not_cut_a_longer_one() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(TtlPolicy { base: Duration::from_secs(60), max: Duration::from_secs(60) });
        let a = ip("203.0.113.3");
        tracker.record(a, Lifetime::Dynamic, t0 + Duration::from_secs(30));
        tracker.record(a, Lifetime::Dynamic, t0);
        assert!(tracker.take_expired(t0 + Duration::from_secs(60)).is_empty());
        assert_eq!(tracker.take_expired(t0 + Duration::from_secs(90)), vec![a]);
    }

    #[test]
    fn permanent_blocks_never_expire_and_stay_permanent() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let a = ip("203.0.113.4");
        assert_eq!(tracker.record(a, Lifetime::Permanent, t0), None);
        assert_eq!(tracker.record(a, Lifetime::Dynamic, t0), None, "a trap hit must not shorten a static block");
        assert!(tracker.take_expired(t0 + Duration::from_secs(10_000_000)).is_empty());
        assert_eq!(tracker.active(), 1);
    }

    #[test]
    fn only_dynamic_blocks_can_be_released() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(POLICY);
        let (operator, dynamic) = (ip("203.0.113.7"), ip("203.0.113.8"));
        tracker.record(operator, Lifetime::Permanent, t0);
        tracker.record(dynamic, Lifetime::Dynamic, t0);
        assert!(!tracker.release_dynamic(&operator), "a mesh unblock must not lift an operator block");
        assert!(tracker.is_permanent(&operator));
        assert!(tracker.release_dynamic(&dynamic));
        assert_eq!(tracker.active(), 1);
    }

    #[test]
    fn zero_base_disables_expiry() {
        let t0 = Instant::now();
        let mut tracker = ExpiryTracker::new(TtlPolicy { base: Duration::ZERO, max: Duration::ZERO });
        assert_eq!(tracker.record(ip("203.0.113.5"), Lifetime::Dynamic, t0), None);
        assert!(tracker.take_expired(t0 + Duration::from_secs(10_000_000)).is_empty());
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
        assert_eq!(tracker.record(a, Lifetime::Dynamic, t0), Some(Duration::from_secs(60)));
    }
}
