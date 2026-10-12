//! The mesh's freshness and replay window (ADR-0010, review 2026-10-05 F4): when an envelope's
//! timestamp is acceptable and how long its nonce must be remembered so that it cannot be
//! accepted twice. It lives here, apart from the node, so that Kani can prove the two bounds
//! fit (`cargo kani -p common`, docs/VERIFICATION.md); `orchestrator/src/p2p.rs` calls it.
//! Times are wall-clock milliseconds.

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

    /// An envelope accepted once (fresh at its arrival) that is fresh again at any later or
    /// earlier moment finds its nonce still remembered then, so it is refused as a replay:
    /// REPLAY_WINDOW_MS is long enough for MAX_CLOCK_SKEW_MS, both bounds inclusive.
    #[kani::proof]
    fn an_envelope_fresh_again_finds_its_nonce_remembered() {
        let (timestamp, arrived, now): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        kani::assume(fresh(timestamp, arrived) && fresh(timestamp, now));
        assert!(remembered(arrived, now));
    }
}
