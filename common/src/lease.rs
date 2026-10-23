//! The lease arithmetic of a peer claim (R26-07, ADR-0017, LEASE-C1): where its local lease
//! ends, how its record may move and how long the record (and a lift record) is kept. It lives
//! here, apart from the block table, so that Kani can prove it (`cargo kani -p common`,
//! docs/VERIFICATION.md); `orchestrator/src/block_table.rs` calls it. Every time is in
//! milliseconds on the table's own (monotonic) clock.

/// The local end of a lease that starts at `now`: `max_ttl` later, but never past the end of a
/// lease this claim already had (`earlier`): the local cap bounds a claim's total effect, not
/// each lifetime of the process or each resend.
pub fn cap(now: u64, max_ttl: u64, earlier: Option<u64>) -> u64 {
    let fresh = now.saturating_add(max_ttl);
    earlier.map_or(fresh, |end| fresh.min(end))
}

/// Until when a claim with its own end `end_local` is enforced under a lease ending at `cap`.
pub fn until(end_local: Option<u64>, cap: u64) -> u64 {
    end_local.map_or(cap, |end| end.min(cap))
}

/// A lease record's end after the claim gets a lease ending at `cap`: the end only ever moves
/// earlier, so records timed by it (an operator lift) outlive it.
pub fn recorded_end(old: Option<u64>, cap: u64) -> u64 {
    old.map_or(cap, |end| end.min(cap))
}

/// Whether a lease record, or a lift or retraction record, is still kept at `now`: until
/// `grace` past the end of its claim (`end`; `None` while the claim has no end). A wall-clock
/// step back by less than `grace` makes a resent copy of an ended claim live again for the
/// length of the step; the record is still there, so the copy finds the lease it already had.
pub fn kept(end: Option<u64>, now: u64, grace: u64) -> bool {
    end.is_none_or(|e| e.saturating_add(grace) > now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic the proofs below cover, on concrete values: `cargo test` does not run
    /// Kani harnesses.
    #[test]
    fn a_lease_is_capped_by_its_first_record_and_kept_for_the_grace() {
        assert_eq!(cap(1_000, 600, None), 1_600);
        assert_eq!(
            cap(1_000, 600, Some(1_200)),
            1_200,
            "an earlier lease bounds a new one"
        );
        assert_eq!(cap(1_000, 600, Some(9_000)), 1_600);
        assert_eq!(cap(u64::MAX - 1, 600, None), u64::MAX, "saturates");
        assert_eq!(until(Some(1_100), 1_600), 1_100);
        assert_eq!(until(Some(2_000), 1_600), 1_600);
        assert_eq!(until(None, 1_600), 1_600);
        assert_eq!(recorded_end(Some(1_200), 1_600), 1_200, "never later");
        assert_eq!(recorded_end(Some(1_600), 1_200), 1_200);
        assert_eq!(recorded_end(None, 1_600), 1_600);
        assert!(kept(Some(1_000), 1_599, 600));
        assert!(!kept(Some(1_000), 1_600, 600), "forgotten at end + grace");
        assert!(
            kept(None, u64::MAX, 600),
            "a claim without an end keeps its record"
        );
        assert!(kept(Some(u64::MAX), u64::MAX - 1, 600), "saturates");
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// A claim that already had a lease never gets a longer one, from any later time and
    /// whatever the allowed length: it is enforced at most until that lease's end.
    #[kani::proof]
    fn a_resent_claim_never_outlasts_its_first_lease() {
        let (now, max_ttl, earlier, end_local): (u64, u64, u64, Option<u64>) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let capped = cap(now, max_ttl, Some(earlier));
        assert!(capped <= earlier && until(end_local, capped) <= earlier);
    }

    /// A lease record's end only moves earlier, and is never past the newest cap.
    #[kani::proof]
    fn a_lease_record_only_moves_earlier() {
        let (old, new_cap): (u64, u64) = (kani::any(), kani::any());
        let end = recorded_end(Some(old), new_cap);
        assert!(end <= old && end <= new_cap);
    }

    /// LEASE-C1: after a wall-clock step back by `step` < `grace`, a resent copy of a claim
    /// whose end was `end` on the table's clock is live until `end + step`; for as long as it
    /// is live, its record (and a lift record timed the same way) is still kept, so it finds
    /// its lease and is not renewed. A larger step can outlive the record: the bound is grace.
    #[kani::proof]
    fn within_grace_a_live_resend_finds_its_record() {
        let (end, step, grace, now): (u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(step < grace);
        kani::assume(end.saturating_add(step) > now);
        assert!(kept(Some(end), now, grace));
    }
}
