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
pub const STORM_FLAGS: u32 =
    common::config_flags::STRICT_PARSE | common::config_flags::DROP_IPV4_FRAGMENTS;

/// The `CONFIG` value for a state: the operator's `base` flags, plus the storm flags only while
/// engaged in strict mode. Disengaging never clears a flag the operator set.
pub fn flags(base: u32, mode: StormMode, engaged: bool) -> u32 {
    match (mode, engaged) {
        (StormMode::Strict, true) => base | STORM_FLAGS,
        _ => base,
    }
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
