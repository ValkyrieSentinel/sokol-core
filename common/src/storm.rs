//! The storm latch's arithmetic (ADR-6): which XDP flags a storm adds, and which drops count
//! toward the attack signal. It lives here, apart from the node, so that Kani can prove it
//! (`cargo kani -p common`, docs/VERIFICATION.md); `orchestrator/src/defense.rs` calls it.
use crate::{config_flags, drop_reason, DROP_REASON_SLOTS};

/// Flags added while engaged in strict mode.
pub const STORM_FLAGS: u32 = config_flags::STRICT_PARSE | config_flags::DROP_IPV4_FRAGMENTS;

/// The `CONFIG` value for a state: the operator's `base` flags, plus the storm flags only while
/// engaged in strict mode (`strict`; otherwise a storm is only observed). Disengaging never
/// clears a flag the operator set.
pub const fn flags(base: u32, strict: bool, engaged: bool) -> u32 {
    if strict && engaged {
        base | STORM_FLAGS
    } else {
        base
    }
}

/// Whether drops with `code` happen only because storm mode is engaged: fragment drops while it
/// adds `DROP_IPV4_FRAGMENTS`, strict-parse drops while it adds `STRICT_PARSE`. A storm flag the
/// operator set already is policy, not storm, and its drops count. `MALFORMED_HEADER` is never
/// storm-added: those outer headers are dropped in every mode (strict parsing has its own code).
pub fn storm_added(code: u16, base: u32, strict: bool) -> bool {
    let added = flags(base, strict, true) & !base;
    (code == drop_reason::FRAGMENT_BLOCKED && added & config_flags::DROP_IPV4_FRAGMENTS != 0)
        || (code == drop_reason::STRICT_PARSE_FAILED && added & config_flags::STRICT_PARSE != 0)
}

/// What one reason's counter adds to the attack signal over a telemetry window: its drops in the
/// window (`now - start`, zero for a counter below its start), or nothing for a reason storm
/// mode itself adds.
pub fn counted(code: u16, now: u64, start: u64, base: u32, strict: bool) -> u64 {
    if storm_added(code, base, strict) {
        0
    } else {
        now.saturating_sub(start)
    }
}

/// Drops in a telemetry window (per-reason counters now and at the window's start) that count
/// toward the attack signal: every reason but the ones storm mode itself adds (`counted`).
/// Counting those would let legitimate fragmented or unparsable traffic keep the node under
/// attack, and so the storm that causes the drops, without end.
pub fn attack_drops(
    now: &[u64; DROP_REASON_SLOTS],
    window_start: &[u64; DROP_REASON_SLOTS],
    base: u32,
    strict: bool,
) -> u64 {
    now.iter()
        .zip(window_start)
        .zip(0u16..)
        .map(|((now, start), code)| counted(code, *now, *start, base, strict))
        .fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic the proofs below cover, on concrete values: `cargo test` does not run
    /// Kani harnesses.
    #[test]
    fn storm_drops_are_left_out_and_every_other_reason_counts() {
        let start = [0u64; DROP_REASON_SLOTS];
        let mut now = [0u64; DROP_REASON_SLOTS];
        now[drop_reason::FRAGMENT_BLOCKED as usize] = 7;
        now[drop_reason::STRICT_PARSE_FAILED as usize] = 11;
        now[drop_reason::MALFORMED_HEADER as usize] = 3;
        assert_eq!(
            attack_drops(&now, &start, 0, true),
            3,
            "strict: storm-added left out"
        );
        assert_eq!(
            attack_drops(&now, &start, 0, false),
            21,
            "observe: nothing is storm-added"
        );
        assert_eq!(
            attack_drops(&now, &start, config_flags::DROP_IPV4_FRAGMENTS, true),
            10,
            "fragment drops the operator asked for are policy and count"
        );
        assert_eq!(
            attack_drops(&start, &now, 0, false),
            0,
            "a counter below its start is 0"
        );
        assert_eq!(
            flags(config_flags::OBSERVE_ONLY, true, true),
            config_flags::OBSERVE_ONLY | STORM_FLAGS
        );
        assert_eq!(
            flags(config_flags::OBSERVE_ONLY, true, false),
            config_flags::OBSERVE_ONLY
        );
        assert_eq!(flags(0, false, true), 0, "observe mode adds no flag");
        assert_eq!(
            flags(config_flags::STRICT_PARSE, true, true),
            STORM_FLAGS,
            "a storm flag the operator set stays set while engaged"
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The specification (ADR-6), written apart from `storm_added` so that the proofs do not
    /// assume the implementation they check: a storm in strict mode adds fragment drops unless
    /// the operator set DROP_IPV4_FRAGMENTS, strict-parse drops unless the operator set
    /// STRICT_PARSE, and nothing else.
    fn added_by_the_storm(code: u16, base: u32, strict: bool) -> bool {
        strict
            && ((code == drop_reason::FRAGMENT_BLOCKED
                && base & config_flags::DROP_IPV4_FRAGMENTS == 0)
                || (code == drop_reason::STRICT_PARSE_FAILED
                    && base & config_flags::STRICT_PARSE == 0))
    }

    /// STORM-S1, first half: the drops storm mode itself adds add nothing to the attack
    /// signal, whatever their counters do, so a storm cannot keep itself going on the traffic
    /// it drops. (`attack_drops` is the saturating sum of `counted` over the reasons.)
    #[kani::proof]
    fn storm_added_drops_never_move_the_attack_signal() {
        let (code, now, start, base, strict): (u16, u64, u64, u32, bool) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        kani::assume(added_by_the_storm(code, base, strict));
        assert!(counted(code, now, start, base, strict) == 0);
    }

    /// STORM-S1, second half: every other reason counts in full, in every mode and with any
    /// operator flags, a malformed-header flood among them.
    #[kani::proof]
    fn every_other_drop_reason_counts_in_every_mode() {
        let (code, now, start, base, strict): (u16, u64, u64, u32, bool) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        kani::assume(!added_by_the_storm(code, base, strict));
        assert!(counted(code, now, start, base, strict) == now.saturating_sub(start));
    }

    /// Engaging adds only the storm flags and keeps every flag the operator set; disengaging,
    /// or observe mode, leaves exactly the operator's flags.
    #[kani::proof]
    fn a_storm_adds_only_its_flags_and_keeps_the_operators() {
        let (base, strict, engaged): (u32, bool, bool) = (kani::any(), kani::any(), kani::any());
        let set = flags(base, strict, engaged);
        assert!(set & base == base && set & !base & !STORM_FLAGS == 0);
        assert!(engaged && strict || set == base);
    }
}
