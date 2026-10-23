//! What the node does while a distributed storm is engaged (ADR-6).
//!
//! In `strict` mode the storm latch's Engage switches the XDP program to strict parsing (packets
//! whose headers do not parse are dropped) and drops IPv4 fragments; Disengage restores exactly
//! the flags the operator configured. `observe` only logs, as before.
use aya::maps::{Array, MapData};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum StormMode {
    /// Tighten XDP while the storm lasts.
    Strict,
    /// Log the storm only.
    Observe,
}

/// Flags added while engaged in strict mode.
pub const STORM_FLAGS: u32 = common::storm::STORM_FLAGS;

/// The `CONFIG` value for a state: the operator's `base` flags, plus the storm flags only while
/// engaged in strict mode. Disengaging never clears a flag the operator set
/// (`common::storm::flags`, proved there).
pub fn flags(base: u32, mode: StormMode, engaged: bool) -> u32 {
    common::storm::flags(base, mode == StormMode::Strict, engaged)
}

/// Whether this node's drops in a telemetry window (per-reason counters now and at the window's
/// start, `secs` long) reach `threshold` drops per second, leaving out the reasons storm mode
/// itself adds. Counting those would let legitimate fragmented or unparsable traffic keep the
/// node under attack, and so the storm that causes the drops, without end (ADR-6: the cost is
/// bounded by the storm). Which drops count is `common::storm::attack_drops`, proved there.
pub fn under_attack(
    now: &[u64; common::DROP_REASON_SLOTS],
    window_start: &[u64; common::DROP_REASON_SLOTS],
    secs: f64,
    threshold: u64,
    base: u32,
    mode: StormMode,
) -> bool {
    let drops = common::storm::attack_drops(now, window_start, base, mode == StormMode::Strict);
    (drops as f64 / secs.max(1.0)) as u64 >= threshold
}

/// Where the flags go (the XDP CONFIG map; a stand-in in tests).
pub trait ConfigMap: Send {
    fn write(&mut self, flags: u32) -> Result<(), aya::maps::MapError>;
}

impl ConfigMap for Array<MapData, u32> {
    fn write(&mut self, flags: u32) -> Result<(), aya::maps::MapError> {
        self.set(0, flags, 0)
    }
}

/// Desired and applied mode kept apart (R26-08): a CONFIG write that fails is retried by
/// `reconcile` on every tick until the kernel holds the desired flags, instead of leaving strict
/// flags in force after a storm (or missing them during one) until the next transition.
pub struct Defense<M = Array<MapData, u32>> {
    config: Mutex<M>,
    base: u32,
    mode: StormMode,
    desired: AtomicBool,
    /// Flags last written successfully, or u32::MAX before the first success.
    applied: std::sync::atomic::AtomicU32,
}

impl<M: ConfigMap> Defense<M> {
    pub fn new(config: M, base: u32, mode: StormMode) -> Self {
        Self {
            config: Mutex::new(config),
            base,
            mode,
            desired: AtomicBool::new(false),
            applied: std::sync::atomic::AtomicU32::new(u32::MAX),
        }
    }

    /// Records the latch's state and applies it; returns the flags written.
    pub fn set(&self, engaged: bool) -> Result<u32, aya::maps::MapError> {
        self.desired.store(engaged, Ordering::Relaxed);
        self.reconcile()
    }

    /// Writes the desired flags if the kernel does not hold them yet.
    pub fn reconcile(&self) -> Result<u32, aya::maps::MapError> {
        let value = flags(self.base, self.mode, self.desired.load(Ordering::Relaxed));
        if self.applied.load(Ordering::Relaxed) == value {
            return Ok(value);
        }
        self.config
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .write(value)?;
        self.applied.store(value, Ordering::Relaxed);
        Ok(value)
    }

    /// Whether the kernel does not hold the desired flags yet.
    pub fn pending(&self) -> bool {
        self.applied.load(Ordering::Relaxed)
            != flags(self.base, self.mode, self.desired.load(Ordering::Relaxed))
    }

    pub fn mode(&self) -> StormMode {
        self.mode
    }

    /// The operator's flags, without the storm's.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// Whether storm flags beyond the operator's are in force in the kernel.
    pub fn strict(&self) -> bool {
        let applied = self.applied.load(Ordering::Relaxed);
        applied != u32::MAX && applied & STORM_FLAGS != self.base & STORM_FLAGS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::config_flags::{DROP_IPV4_FRAGMENTS, STRICT_PARSE};

    #[test]
    fn strict_mode_tightens_only_while_engaged() {
        assert_eq!(flags(0, StormMode::Strict, false), 0);
        assert_eq!(
            flags(0, StormMode::Strict, true),
            STRICT_PARSE | DROP_IPV4_FRAGMENTS
        );
        assert_eq!(
            flags(0, StormMode::Observe, true),
            0,
            "observe changes nothing"
        );
    }

    /// Per-reason counters at the end of a window that started at zero.
    fn window(counts: &[(u16, u64)]) -> [u64; common::DROP_REASON_SLOTS] {
        let mut now = [0u64; common::DROP_REASON_SLOTS];
        for &(code, n) in counts {
            now[code as usize] = n;
        }
        now
    }

    const START: [u64; common::DROP_REASON_SLOTS] = [0; common::DROP_REASON_SLOTS];
    /// Every operator base and storm mode a node can run with.
    const BASES: [u32; 2] = [0, DROP_IPV4_FRAGMENTS];
    const MODES: [StormMode; 2] = [StormMode::Strict, StormMode::Observe];

    // In every case below: a 5 s window and a threshold of 1000 drops/s, so 6000 drops of a
    // counted reason are above it.

    #[test]
    fn drops_only_storm_mode_adds_above_the_threshold_are_not_an_attack() {
        use common::drop_reason::{FRAGMENT_BLOCKED, STRICT_PARSE_FAILED};
        let storm_only = window(&[(FRAGMENT_BLOCKED, 6000), (STRICT_PARSE_FAILED, 6000)]);
        for code in [FRAGMENT_BLOCKED, STRICT_PARSE_FAILED] {
            assert!(
                !under_attack(
                    &window(&[(code, 6000)]),
                    &START,
                    5.0,
                    1000,
                    0,
                    StormMode::Strict
                ),
                "reason {} exists only because strict storm mode is on",
                code
            );
        }
        assert!(!under_attack(
            &storm_only,
            &START,
            5.0,
            1000,
            0,
            StormMode::Strict
        ));
        // Observe storm mode adds no drops, so it leaves none out.
        assert!(under_attack(
            &storm_only,
            &START,
            5.0,
            1000,
            0,
            StormMode::Observe
        ));
    }

    #[test]
    fn a_malformed_header_flood_above_the_threshold_is_an_attack_in_every_mode() {
        // Outer headers that never parse are dropped in every mode: storm mode does not add
        // them, so a flood of them stays visible to the attack signal (ADR-6).
        let flood = window(&[(common::drop_reason::MALFORMED_HEADER, 6000)]);
        for base in BASES {
            for mode in MODES {
                assert!(
                    under_attack(&flood, &START, 5.0, 1000, base, mode),
                    "base {:#x}, {:?}",
                    base,
                    mode
                );
            }
        }
    }

    #[test]
    fn attack_drop_reasons_above_the_threshold_count() {
        use common::drop_reason::{FRAGMENT_BLOCKED, INVALID_TCP_FLAGS, SLOW_PATH_LPM_HIT};
        for code in [SLOW_PATH_LPM_HIT, INVALID_TCP_FLAGS] {
            for base in BASES {
                for mode in MODES {
                    assert!(
                        under_attack(&window(&[(code, 6000)]), &START, 5.0, 1000, base, mode),
                        "reason {}, base {:#x}, {:?}",
                        code,
                        base,
                        mode
                    );
                }
            }
        }
        // The operator's own --drop-ipv4-fragments is policy, not storm: its drops count.
        let fragments = window(&[(FRAGMENT_BLOCKED, 6000)]);
        assert!(under_attack(
            &fragments,
            &START,
            5.0,
            1000,
            DROP_IPV4_FRAGMENTS,
            StormMode::Strict
        ));
        // Reasons add up: 3000 + 3000 counted drops in 5 s are 1200/s.
        let split = window(&[(SLOW_PATH_LPM_HIT, 3000), (INVALID_TCP_FLAGS, 3000)]);
        assert!(under_attack(
            &split,
            &START,
            5.0,
            1000,
            0,
            StormMode::Strict
        ));
    }

    #[test]
    fn drops_just_below_the_threshold_are_not_an_attack() {
        use common::drop_reason::{FRAGMENT_BLOCKED, MALFORMED_HEADER, SLOW_PATH_LPM_HIT};
        // 4999 counted drops in 5 s are 999/s; 5000 are 1000/s, at the threshold. The
        // storm-only fragments beside them do not lift them over it.
        let below = window(&[(SLOW_PATH_LPM_HIT, 4999), (FRAGMENT_BLOCKED, 6000)]);
        assert!(!under_attack(
            &below,
            &START,
            5.0,
            1000,
            0,
            StormMode::Strict
        ));
        let at = window(&[(MALFORMED_HEADER, 5000), (FRAGMENT_BLOCKED, 6000)]);
        assert!(under_attack(&at, &START, 5.0, 1000, 0, StormMode::Strict));
        // Only the window counts: the same totals at its start are no drops in it.
        let before = window(&[(SLOW_PATH_LPM_HIT, 6000)]);
        assert!(!under_attack(
            &before,
            &before,
            5.0,
            1000,
            0,
            StormMode::Strict
        ));
    }

    /// A storm flag the operator set is policy, so its strict-parse drops count; observe storm
    /// mode adds no flags, so it leaves nothing out (STORM-S1).
    #[test]
    fn strict_parse_drops_count_when_the_operator_set_the_flag_or_storm_only_observes() {
        let flood = window(&[(common::drop_reason::STRICT_PARSE_FAILED, 6000)]);
        assert!(under_attack(
            &flood,
            &START,
            5.0,
            1000,
            common::config_flags::STRICT_PARSE,
            StormMode::Strict
        ));
        assert!(under_attack(
            &flood,
            &START,
            5.0,
            1000,
            0,
            StormMode::Observe
        ));
    }

    /// The node passes the operator's own flags to the attack signal, not some other value.
    #[test]
    fn a_defense_reports_the_operators_base_flags() {
        for base in [0, DROP_IPV4_FRAGMENTS, common::config_flags::STRICT_PARSE] {
            let d = Defense::new(
                Flaky {
                    fail: false,
                    value: None,
                },
                base,
                StormMode::Strict,
            );
            assert_eq!(d.base(), base);
        }
    }

    struct Flaky {
        fail: bool,
        value: Option<u32>,
    }

    impl ConfigMap for Flaky {
        fn write(&mut self, flags: u32) -> Result<(), aya::maps::MapError> {
            if self.fail {
                return Err(aya::maps::MapError::ElementNotFound);
            }
            self.value = Some(flags);
            Ok(())
        }
    }

    #[test]
    fn a_failed_config_write_is_retried_until_the_kernel_holds_the_desired_mode() {
        // R26-08: the latch transitions once; the kernel must still reach the desired flags.
        let d = Defense::new(
            Flaky {
                fail: false,
                value: None,
            },
            0,
            StormMode::Strict,
        );
        d.set(true).unwrap();
        d.config.lock().unwrap().fail = true;
        assert!(d.set(false).is_err(), "Disengage fails");
        assert!(d.pending());
        assert!(
            d.strict(),
            "the kernel still holds strict flags, and says so"
        );
        d.config.lock().unwrap().fail = false;
        d.reconcile().unwrap(); // the next tick
        assert!(!d.pending());
        assert!(!d.strict());
        assert_eq!(d.config.lock().unwrap().value, Some(0));
    }

    #[test]
    fn disengaging_keeps_the_operators_flags() {
        let base = DROP_IPV4_FRAGMENTS;
        assert_eq!(flags(base, StormMode::Strict, true), base | STRICT_PARSE);
        assert_eq!(
            flags(base, StormMode::Strict, false),
            base,
            "--drop-ipv4-fragments survives the end of a storm"
        );
    }
}
