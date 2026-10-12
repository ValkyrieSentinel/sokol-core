//! The mesh's freshness check and replay window (ADR-0010, review 2026-10-05 F4): when an
//! envelope's timestamp is acceptable and how long after its arrival its nonce must be kept.
//! It lives here, apart from the node, so that Kani can prove the two bounds fit
//! (`cargo kani -p common`, docs/VERIFICATION.md); `orchestrator/src/p2p.rs` calls it.
//! Times are wall-clock milliseconds.
//!
//! This is arithmetic only. Refusing a replay also needs the nonce to be still in the node's
//! cache (`p2p::ReplayGuard`): it is dropped once an envelope of the same sender arrives more
//! than REPLAY_WINDOW_MS after it, and on restart. A clock that steps back past the window
//! after such a purge accepts the original again
//! (`a_replay_is_refused_while_its_nonce_is_retained_not_after_a_purge_and_a_step_back`).

/// How far an envelope's timestamp may lie from this node's clock, both ways, inclusive.
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;

/// How long a nonce is remembered after it arrived: a timestamp accepted then is at most
/// MAX_CLOCK_SKEW_MS ahead, so it is stale this long after arrival. Both bounds are inclusive:
/// at exactly this age the frame is still acceptable, so its nonce is still remembered.
pub const REPLAY_WINDOW_MS: u64 = 2 * MAX_CLOCK_SKEW_MS;

/// Whether an envelope stamped `timestamp_ms` is acceptable at `now`.
pub fn fresh(timestamp_ms: u64, now: u64) -> bool {
    timestamp_ms.abs_diff(now) <= MAX_CLOCK_SKEW_MS
}

/// Whether a nonce that arrived at `arrived` must still be remembered at `now`.
pub fn remembered(arrived: u64, now: u64) -> bool {
    arrived.saturating_add(REPLAY_WINDOW_MS) >= now
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounds the proof below covers, at their edges: `cargo test` does not run Kani
    /// harnesses.
    #[test]
    fn a_frame_fresh_at_the_edge_of_the_window_is_still_remembered() {
        let ts = 1_000_000;
        let (first, last) = (ts - MAX_CLOCK_SKEW_MS, ts + MAX_CLOCK_SKEW_MS);
        assert!(fresh(ts, first) && fresh(ts, last) && !fresh(ts, last + 1));
        assert!(
            remembered(first, last),
            "the last moment it is fresh, it is remembered"
        );
        assert!(!remembered(first, last + 1));
        assert!(
            remembered(u64::MAX, 0),
            "an arrival after now (a clock step back) is kept"
        );
        assert!(remembered(u64::MAX - 1, u64::MAX), "saturates");
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The window fits the skew: for any timestamp and any two moments at which it is fresh
    /// (its arrival and a later or earlier one), the window started at the arrival still covers
    /// the other moment, both bounds inclusive. That is what the cache needs to keep a nonce
    /// long enough; it says nothing about what the cache did in between (a purge by a later
    /// arrival, a restart), which this predicate does not model.
    #[kani::proof]
    fn the_replay_window_covers_the_clock_skew_both_ways() {
        let (timestamp, arrived, now): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        kani::assume(fresh(timestamp, arrived) && fresh(timestamp, now));
        assert!(remembered(arrived, now));
    }
}
