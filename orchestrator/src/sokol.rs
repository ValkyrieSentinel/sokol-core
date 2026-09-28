#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct FlowRate(pub f64);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct EntropyValue(pub f64);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct RelaxationSec(pub f64);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct PhaseGradient(pub f64);

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FieldVector {
    pub q: FlowRate,
    pub h: EntropyValue,
    pub tau: RelaxationSec,
    pub phi: PhaseGradient,
}

#[derive(Debug, PartialEq)]
pub enum EngineError {
    InvalidFloat,
    ZeroDeltaTime,
}

pub struct SokolEngine {
    /// Units per second (packets/s for the RX counter).
    threshold_per_sec: f64,
}

/// Reports a rate crossing its threshold, not every sample above it.
#[derive(Default)]
pub struct RateAlert {
    above: bool,
}

impl RateAlert {
    /// `Some(true)` when the rate went above, `Some(false)` when it came back, else `None`.
    pub fn update(&mut self, above: bool) -> Option<bool> {
        (above != self.above).then(|| {
            self.above = above;
            above
        })
    }
}

impl SokolEngine {
    pub fn new(threshold_per_sec: f64) -> Self {
        Self { threshold_per_sec }
    }

    /// Whether a cumulative counter moved faster than the threshold between two samples:
    /// `|current - prev| / dt` is a rate (packets/s), compared with a fixed rate threshold.
    /// Not an anomaly model: a steady 600 pps is above a 500 threshold on every sample, with
    /// no spike and no baseline (numerical review N04).
    pub fn rate_above(&self, current: f64, prev: f64, dt: f64) -> Result<bool, EngineError> {
        if dt <= 0.0 || dt.is_nan() || dt.is_infinite() {
            return Err(EngineError::ZeroDeltaTime);
        }
        if current.is_nan() || prev.is_nan() || current.is_infinite() || prev.is_infinite() {
            return Err(EngineError::InvalidFloat);
        }

        let rate = (current - prev) / dt;
        Ok(rate.abs() > self.threshold_per_sec)
    }

    pub fn compute_flow_rate(delta_n: u64, delta_t: f64) -> FlowRate {
        if delta_t <= 0.0 || delta_t.is_nan() || delta_t.is_infinite() {
            return FlowRate(0.0);
        }
        FlowRate(delta_n as f64 / delta_t)
    }

    /// Shannon entropy in bits, `-Σ p log₂ p`, of a probability distribution. The input is not
    /// validated: it must be normalized (`p ≥ 0`, `Σ p = 1`); entries that are not finite and
    /// positive are skipped. Not used by the node (numerical review N04).
    pub fn compute_shannon_entropy(probabilities: &[f64]) -> EntropyValue {
        let h = probabilities
            .iter()
            .filter(|&&p| p > 0.0 && !p.is_nan() && !p.is_infinite())
            .map(|&p| -p * p.log2())
            .sum();
        EntropyValue(h)
    }

    /// Time constant, in **samples**, of a decay that keeps the fraction `alpha` per sample:
    /// `-1 / ln(alpha)`. `alpha` is the retention factor, not an EWMA gain `g` (that retains
    /// `1 - g`); seconds are samples × the sample interval. Not used by the node (N04).
    pub fn compute_relaxation_time(alpha: f64) -> RelaxationSec {
        if alpha <= 0.0 || alpha >= 1.0 || alpha.is_nan() {
            return RelaxationSec(0.0);
        }
        RelaxationSec(-1.0 / alpha.ln())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rate_is_compared_with_the_threshold() {
        let engine = SokolEngine::new(500.0);
        assert_eq!(engine.rate_above(1200.0, 1000.0, 1.0), Ok(false));
        assert_eq!(engine.rate_above(2500.0, 1200.0, 1.0), Ok(true));
        // A steady rate above the threshold is above it on every sample: a rate, not a spike.
        assert_eq!(engine.rate_above(1600.0, 1000.0, 1.0), Ok(true));
        assert_eq!(engine.rate_above(2200.0, 1600.0, 1.0), Ok(true));
        // Per second: 1 200 packets in 3 s is 400/s.
        assert_eq!(engine.rate_above(2200.0, 1000.0, 3.0), Ok(false));
        assert_eq!(
            engine.rate_above(2500.0, 1200.0, 0.0),
            Err(EngineError::ZeroDeltaTime)
        );
        assert_eq!(
            engine.rate_above(2500.0, 1200.0, f64::INFINITY),
            Err(EngineError::ZeroDeltaTime)
        );
        assert_eq!(
            engine.rate_above(f64::NAN, 1200.0, 1.0),
            Err(EngineError::InvalidFloat)
        );
    }

    #[test]
    fn a_rate_alert_reports_crossings_only() {
        let mut alert = RateAlert::default();
        let seen: Vec<Option<bool>> = [false, true, true, true, false, false, true]
            .into_iter()
            .map(|above| alert.update(above))
            .collect();
        assert_eq!(
            seen,
            vec![None, Some(true), None, None, Some(false), None, Some(true)]
        );
    }

    #[test]
    fn test_chronoflux_math() {
        let flow = SokolEngine::compute_flow_rate(10000, 2.0);
        assert_eq!(flow, FlowRate(5000.0));

        let entropy = SokolEngine::compute_shannon_entropy(&[0.5, 0.5, f64::NAN]);
        assert_eq!(entropy, EntropyValue(1.0));

        let tau = SokolEngine::compute_relaxation_time(0.5);
        assert!(tau.0 > 1.44 && tau.0 < 1.45);
    }
}
