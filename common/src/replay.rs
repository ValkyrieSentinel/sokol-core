//! The mesh's freshness check and replay window (ADR-0010, review 2026-10-05 F4, review of
//! #26): when an envelope's timestamp is acceptable, how long after its arrival its nonce is
//! kept, and the floor below which a sender's envelopes are refused once their nonces are
//! gone. It lives here, apart from the node, so that Kani can prove it
//! (`cargo kani -p common`, docs/VERIFICATION.md); `orchestrator/src/p2p.rs` calls it.
//! Times are wall-clock milliseconds.
//!
//! A sender's nonce leaves the node's cache (`p2p::ReplayGuard`) REPLAY_WINDOW_MS after it
//! arrived. Its timestamp then raises that sender's floor (`raise`), and an envelope stamped
//! at or below the floor is refused (`admits`). So every envelope accepted in this process is
//! either still in the cache or under the floor, whatever the clock did in between. A new
//! process starts its floors at its start (`fence`), so an envelope stamped before the
//! restart is refused too; one the previous process accepted with a later stamp (its sender's
//! clock ahead) is not, since the fence knows only the start.
//!
//! Cost to honest senders, while this node's clock does not step back: a purge never puts a
//! fresh envelope under the floor (`honest_envelopes_stay_above_the_floor`); the fence can, for
//! a sender whose clock is behind, but only during the first MAX_CLOCK_SKEW_MS after the start
//! (`the_fence_costs_honest_senders_only_the_skew_after_the_start`).

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

/// The timestamps a sender's window refuses outright: those at or below it. `None` refuses
/// nothing.
pub type Floor = Option<u64>;

/// The floor of a window in a process started at `started`: an envelope stamped before the
/// start may have been accepted by the previous process, whose cache is gone.
pub fn fence(started: u64) -> Floor {
    started.checked_sub(1)
}

/// The floor after a nonce stamped `purged` leaves the cache.
pub fn raise(floor: Floor, purged: u64) -> Floor {
    Some(floor.map_or(purged, |f| f.max(purged)))
}

/// Whether an envelope stamped `timestamp_ms` is above the floor.
pub fn admits(timestamp_ms: u64, floor: Floor) -> bool {
    floor.is_none_or(|f| timestamp_ms > f)
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

    /// The floor on concrete values: a purged timestamp and everything below it is refused,
    /// later ones pass; a process started at `t` refuses envelopes stamped before `t`.
    #[test]
    fn the_floor_refuses_purged_timestamps_and_those_before_the_start() {
        assert!(
            admits(0, None) && admits(5, fence(0)),
            "no fence refuses nothing"
        );
        assert!(!admits(99, fence(100)) && admits(100, fence(100)));
        let floor = raise(fence(100), 500);
        assert!(!admits(500, floor) && !admits(120, floor) && admits(501, floor));
        assert_eq!(raise(floor, 300), floor, "the floor never moves down");
        assert!(
            !admits(u64::MAX, raise(None, u64::MAX)),
            "saturates at the top"
        );
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

    /// The policy for one accepted envelope, any start and any clock: after its window was
    /// touched (purging it when due), the envelope is refused at any moment it is fresh. Every
    /// accepted envelope is in the cache or under the floor, and the floor only rises, so this
    /// holds after any number of touches (a later purge raises the floor further).
    #[kani::proof]
    fn an_accepted_envelope_is_refused_again_whatever_the_clock_did() {
        let (started, ts, arrived, touched, again): (u64, u64, u64, u64, u64) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        let mut floor = fence(started);
        // Accepted at `arrived`.
        kani::assume(fresh(ts, arrived) && admits(ts, floor));
        let mut retained = true;
        // The sender's window is next touched at `touched` (any clock: earlier or later than
        // `arrived`), which purges the entry when its window is over.
        if !remembered(arrived, touched) {
            floor = raise(floor, ts);
            retained = false;
        }
        // The same envelope again, at any moment it is fresh: refused by the cache or the floor.
        kani::assume(fresh(ts, again));
        let refused = retained || !admits(ts, floor);
        assert!(refused);
    }

    /// A purge costs honest senders nothing while this node's clock does not step back: an
    /// envelope fresh at a moment no earlier than a purge, and above the floor before it
    /// (the fence included), is above it after. It says nothing about the fence itself.
    #[kani::proof]
    fn honest_envelopes_stay_above_the_floor() {
        let (purged, arrived, purge_at, ts, now, floor): (u64, u64, u64, u64, u64, Floor) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        kani::assume(fresh(purged, arrived) && !remembered(arrived, purge_at));
        kani::assume(purge_at <= now && fresh(ts, now) && admits(ts, floor));
        let above = admits(ts, raise(floor, purged));
        assert!(above);
    }

    /// A restarted process refuses every envelope stamped before its start, and nothing
    /// stamped at or after it.
    #[kani::proof]
    fn a_restart_fences_off_what_came_before() {
        let (started, ts): (u64, u64) = (kani::any(), kani::any());
        let fenced = admits(ts, fence(started)) == (ts >= started);
        assert!(fenced);
    }

    /// The fence's cost to honest senders: from MAX_CLOCK_SKEW_MS after the start on, every
    /// envelope fresh at this node's clock is above it. Before that, an honest sender whose
    /// clock is behind can be refused (`before_window`), as can envelopes in flight across
    /// the restart.
    #[kani::proof]
    fn the_fence_costs_honest_senders_only_the_skew_after_the_start() {
        let (started, ts, now): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        // Wall-clock milliseconds are far below the top of u64.
        let Some(settled) = started.checked_add(MAX_CLOCK_SKEW_MS) else {
            return;
        };
        kani::assume(now >= settled && fresh(ts, now));
        let admitted = admits(ts, fence(started));
        assert!(admitted);
    }
}
