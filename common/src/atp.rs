use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

pub const GLOBAL_MAX_ATP: u64 = 100_000_000;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AtpError {
    DissonanceExhausted,
    ResourceFault,
}

impl fmt::Display for AtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtpError::DissonanceExhausted => {
                write!(f, "DISSONANCE: ATP execution budget exhausted")
            }
            AtpError::ResourceFault => {
                write!(
                    f,
                    "Resource Fault: Local memory ceiling or stack depth breached"
                )
            }
        }
    }
}

impl core::error::Error for AtpError {}

#[derive(Debug)]
pub struct AtpBudgetController {
    consumed: AtomicU64,
    limit: u64,
}

impl AtpBudgetController {
    pub const fn new(limit: u64) -> Self {
        let effective_limit = if limit > GLOBAL_MAX_ATP {
            GLOBAL_MAX_ATP
        } else {
            limit
        };

        Self {
            consumed: AtomicU64::new(0),
            limit: effective_limit,
        }
    }

    #[cfg(target_arch = "bpf")]
    pub fn consume(&self, cost: u64) -> Result<(), AtpError> {
        let current = self.consumed.load(Ordering::Relaxed);
        let next = current.saturating_add(cost);

        if next > self.limit {
            return Err(AtpError::DissonanceExhausted);
        }

        self.consumed.store(next, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn consume(&self, cost: u64) -> Result<(), AtpError> {
        let mut current = self.consumed.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(cost);

            if next > self.limit {
                return Err(AtpError::DissonanceExhausted);
            }

            match self.consumed.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn try_consume(&self, cost: u64) -> bool {
        let mut current = self.consumed.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(cost);
            if next > self.limit {
                return false;
            }

            match self.consumed.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    pub fn replenish(&self, amount: u64) {
        let mut current = self.consumed.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                break;
            }
            let next = current.saturating_sub(amount);
            match self.consumed.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn reset(&self) {
        self.consumed.store(0, Ordering::Release);
    }

    pub fn remaining(&self) -> u64 {
        let current = self.consumed.load(Ordering::Acquire);
        self.limit.saturating_sub(current)
    }

    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Acquire)
    }

    pub fn is_exhausted(&self) -> bool {
        self.remaining() == 0
    }
}
