//! Wall-clock steps, seen by comparing how far the wall clock and the monotonic clock moved
//! between two observations. Expiry and envelope freshness use the wall clock (ADR-0003), so a
//! step moves every block's end and can take the node out of the mesh; this makes it visible.

use std::time::Instant;

/// A disagreement below this is drift or scheduling, not a step.
pub const STEP_THRESHOLD_MS: i64 = 5_000;

#[derive(Default)]
pub struct ClockWatch {
    last: Option<(u64, Instant)>,
    pub steps: u64,
    /// Size of the last step in ms: positive forward, negative backward.
    pub last_step_ms: i64,
}

impl ClockWatch {
    /// Records one observation; returns the step in ms if the wall clock jumped since the
    /// previous one.
    pub fn observe(&mut self, wall_ms: u64, mono: Instant) -> Option<i64> {
        let previous = self.last.replace((wall_ms, mono));
        let (last_wall, last_mono) = previous?;
        let wall = i128::from(wall_ms) - i128::from(last_wall);
        let mono = mono.saturating_duration_since(last_mono).as_millis() as i128;
        let step = i64::try_from(wall - mono).unwrap_or(i64::MAX);
        if step.abs() < STEP_THRESHOLD_MS {
            return None;
        }
        self.steps += 1;
        self.last_step_ms = step;
        Some(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn steps_are_told_from_drift_in_both_directions() {
        let t = Instant::now();
        let mut w = ClockWatch::default();
        assert_eq!(w.observe(1_000_000, t), None, "first observation");
        // Both clocks moved 1 s: nothing.
        assert_eq!(w.observe(1_001_000, t + Duration::from_secs(1)), None);
        // 4.9 s of disagreement is below the threshold.
        assert_eq!(w.observe(1_006_900, t + Duration::from_secs(2)), None);
        // The wall clock jumped an hour forward in one second.
        assert_eq!(
            w.observe(1_006_900 + 3_601_000, t + Duration::from_secs(3)),
            Some(3_600_000)
        );
        // And an hour back.
        assert_eq!(
            w.observe(1_006_900 + 1_000 + 1_000, t + Duration::from_secs(4)),
            Some(-3_600_000)
        );
        assert_eq!((w.steps, w.last_step_ms), (2, -3_600_000));
    }
}
