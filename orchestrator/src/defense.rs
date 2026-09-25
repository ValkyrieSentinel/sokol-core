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

pub struct Defense {
    config: Mutex<Array<MapData, u32>>,
    base: u32,
    mode: StormMode,
    strict: AtomicBool,
}

impl Defense {
    pub fn new(config: Array<MapData, u32>, base: u32, mode: StormMode) -> Self {
        Self {
            config: Mutex::new(config),
            base,
            mode,
            strict: AtomicBool::new(false),
        }
    }

    /// Applies the state to the kernel; returns the flags written.
    pub fn set(&self, engaged: bool) -> Result<u32, aya::maps::MapError> {
        let value = flags(self.base, self.mode, engaged);
        self.config
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set(0, value, 0)?;
        self.strict.store(
            value & STORM_FLAGS != self.base & STORM_FLAGS,
            Ordering::Relaxed,
        );
        Ok(value)
    }

    pub fn mode(&self) -> StormMode {
        self.mode
    }

    /// Whether storm flags beyond the operator's are in force.
    pub fn strict(&self) -> bool {
        self.strict.load(Ordering::Relaxed)
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
