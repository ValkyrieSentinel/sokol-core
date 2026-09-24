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
    epsilon: f64,
}

impl SokolEngine {
    pub fn new(epsilon: f64) -> Self {
        Self { epsilon }
    }

    pub fn detect_anomaly(&self, current: f64, prev: f64, dt: f64) -> Result<bool, EngineError> {
        if dt <= 0.0 || dt.is_nan() || dt.is_infinite() {
            return Err(EngineError::ZeroDeltaTime);
        }
        if current.is_nan() || prev.is_nan() || current.is_infinite() || prev.is_infinite() {
            return Err(EngineError::InvalidFloat);
        }

        let derivative = (current - prev) / dt;
        Ok(derivative.abs() > self.epsilon)
    }

    pub fn compute_flow_rate(delta_n: u64, delta_t: f64) -> FlowRate {
        if delta_t <= 0.0 || delta_t.is_nan() || delta_t.is_infinite() {
            return FlowRate(0.0);
        }
        FlowRate(delta_n as f64 / delta_t)
    }

    pub fn compute_shannon_entropy(probabilities: &[f64]) -> EntropyValue {
        let h = probabilities
            .iter()
            .filter(|&&p| p > 0.0 && !p.is_nan() && !p.is_infinite())
            .map(|&p| -p * p.log2())
            .sum();
        EntropyValue(h)
    }

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
    fn test_sokol_temporal_spike() {
        let engine = SokolEngine::new(500.0);

        let normal_prev = 1000.0;
        let normal_curr = 1200.0;
        assert_eq!(
            engine.detect_anomaly(normal_curr, normal_prev, 1.0),
            Ok(false)
        );

        let spike_prev = 1200.0;
        let spike_curr = 2500.0;
        assert_eq!(engine.detect_anomaly(spike_curr, spike_prev, 1.0), Ok(true));

        assert_eq!(
            engine.detect_anomaly(2500.0, 1200.0, 0.0),
            Err(EngineError::ZeroDeltaTime)
        );
        assert_eq!(
            engine.detect_anomaly(2500.0, 1200.0, f64::INFINITY),
            Err(EngineError::ZeroDeltaTime)
        );
        assert_eq!(
            engine.detect_anomaly(f64::NAN, 1200.0, 1.0),
            Err(EngineError::InvalidFloat)
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
