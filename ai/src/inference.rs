use crate::tensor::{Tensor, TensorError};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceError {
    ShapeMismatch,
    BufferTooSmall,
    Tensor(TensorError),
    /// A parameter outside its domain (the reason names which).
    InvalidParameter(&'static str),
}

impl fmt::Display for InferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShapeMismatch => write!(f, "Inference shape mismatch"),
            Self::BufferTooSmall => write!(f, "Export/Import buffer capacity is too small"),
            Self::Tensor(e) => write!(f, "Tensor error: {}", e),
            Self::InvalidParameter(why) => write!(f, "Invalid parameter: {}", why),
        }
    }
}

impl Error for InferenceError {}

impl From<TensorError> for InferenceError {
    fn from(err: TensorError) -> Self {
        InferenceError::Tensor(err)
    }
}

pub struct LinearLayer<const IN: usize, const OUT: usize> {
    pub weights: Tensor<f32, 2>,
    pub bias: Tensor<f32, 1>,
}

impl<const IN: usize, const OUT: usize> LinearLayer<IN, OUT> {
    pub fn new() -> Result<Self, InferenceError> {
        Ok(Self {
            weights: Tensor::new([OUT, IN])?,
            bias: Tensor::new([OUT])?,
        })
    }

    #[inline]
    pub fn forward(
        &self,
        input: &Tensor<f32, 1>,
        output: &mut Tensor<f32, 1>,
    ) -> Result<(), InferenceError> {
        if input.shape()[0] != IN || output.shape()[0] != OUT {
            return Err(InferenceError::ShapeMismatch);
        }

        let w_data = self.weights.data();
        let b_data = self.bias.data();
        let in_data = input.data();
        let out_data = output.data_mut();

        for (i, (out_val, &bias_val)) in out_data.iter_mut().zip(b_data.iter()).enumerate() {
            let row_start = i * IN;
            let weight_row = &w_data[row_start..row_start + IN];

            let mut dot_product = 0.0f32;
            for k in 0..IN {
                dot_product += weight_row[k] * in_data[k];
            }

            *out_val = dot_product + bias_val;
        }
        Ok(())
    }
}

/// Exponentially weighted mean and variance per feature, and a distance of a sample from them.
///
/// `alpha` is the **gain**: the weight of a new sample, so each update keeps `1 - alpha` of the
/// old estimate (the retention). Time enters only through the sample interval `Δt`: the time
/// constant is `-Δt / ln(1 - alpha)` and the half-life `-Δt ln 2 / ln(1 - alpha)`
/// ([`Self::time_constant`], [`Self::half_life`]; [`Self::from_time_constant`] goes the other way).
/// Gain 0.1 at Δt = 1 s is a time constant of about 9.5 s.
///
/// The variance starts at [`Self::INITIAL_VARIANCE`] (in units of the feature, squared) and is an
/// EWMA of the squared innovation against the previous mean, not an unbiased population variance.
/// [`Self::anomaly_score`] is the mean absolute z-score over the features: a distance, not a
/// probability of attack and not a calibrated control-chart statistic.
pub struct EwmaAnomalyDetector<const N: usize> {
    pub mean: Tensor<f32, 1>,
    pub variance: Tensor<f32, 1>,
    /// Gain of a new sample, `0 < alpha <= 1`.
    pub alpha: f32,
    initialized: bool,
}

impl<const N: usize> EwmaAnomalyDetector<N> {
    /// Variance given to every feature by the first sample (units of the feature, squared).
    pub const INITIAL_VARIANCE: f32 = 1.0;
    /// Smallest standard deviation used in the score (units of the feature).
    pub const MIN_STD_DEV: f32 = 1e-6;

    /// `alpha` is the gain of a new sample, in `(0, 1]`; at least one feature.
    pub fn new(alpha: f32) -> Result<Self, InferenceError> {
        if N == 0 {
            return Err(InferenceError::InvalidParameter("no features (N = 0)"));
        }
        if !(alpha > 0.0 && alpha <= 1.0) {
            return Err(InferenceError::InvalidParameter("gain must be in (0, 1]"));
        }
        Ok(Self {
            mean: Tensor::new([N])?,
            variance: Tensor::new([N])?,
            alpha,
            initialized: false,
        })
    }

    /// The gain that gives time constant `tau_secs` at a sample every `dt_secs`:
    /// `1 - exp(-dt / tau)`.
    pub fn from_time_constant(tau_secs: f32, dt_secs: f32) -> Result<Self, InferenceError> {
        if !(tau_secs > 0.0 && dt_secs > 0.0 && tau_secs.is_finite() && dt_secs.is_finite()) {
            return Err(InferenceError::InvalidParameter(
                "time constant and sample interval must be positive and finite",
            ));
        }
        Self::new(1.0 - (-dt_secs / tau_secs).exp())
    }

    /// Time constant in seconds at a sample every `dt_secs`; zero for gain 1 (no memory).
    pub fn time_constant(&self, dt_secs: f32) -> f32 {
        let retention = 1.0 - self.alpha;
        if retention <= 0.0 {
            return 0.0;
        }
        -dt_secs / retention.ln()
    }

    /// Time for the weight of a sample to halve, in seconds at a sample every `dt_secs`.
    pub fn half_life(&self, dt_secs: f32) -> f32 {
        self.time_constant(dt_secs) * core::f32::consts::LN_2
    }

    pub fn update(&mut self, sample: &Tensor<f32, 1>) -> Result<(), InferenceError> {
        if sample.shape()[0] != N {
            return Err(InferenceError::ShapeMismatch);
        }

        let s_data = sample.data();
        let m_data = self.mean.data_mut();
        let v_data = self.variance.data_mut();

        if !self.initialized {
            m_data.copy_from_slice(s_data);
            v_data.fill(Self::INITIAL_VARIANCE);
            self.initialized = true;
            return Ok(());
        }

        let a = self.alpha;
        let inv_a = 1.0 - a;

        for ((m, v), &s) in m_data.iter_mut().zip(v_data.iter_mut()).zip(s_data.iter()) {
            let diff = s - *m;
            *m += a * diff;
            *v = inv_a * *v + a * diff * diff;
        }

        Ok(())
    }

    pub fn anomaly_score(&self, sample: &Tensor<f32, 1>) -> Result<f32, InferenceError> {
        if sample.shape()[0] != N {
            return Err(InferenceError::ShapeMismatch);
        }

        if !self.initialized {
            return Ok(0.0);
        }

        let s_data = sample.data();
        let m_data = self.mean.data();
        let v_data = self.variance.data();

        let total_z_score: f32 = s_data
            .iter()
            .zip(m_data.iter())
            .zip(v_data.iter())
            .map(|((&s, &m), &v)| {
                let std_dev = v.sqrt().max(Self::MIN_STD_DEV);
                (s - m).abs() / std_dev
            })
            .sum();

        Ok(total_z_score / (N as f32))
    }

    pub fn export_state(&self, buffer: &mut [f32]) -> Result<(), InferenceError> {
        if buffer.len() < N * 2 {
            return Err(InferenceError::BufferTooSmall);
        }
        let (m_buf, v_buf) = buffer.split_at_mut(N);
        m_buf.copy_from_slice(self.mean.data());
        v_buf[..N].copy_from_slice(self.variance.data());
        Ok(())
    }

    pub fn import_state(&mut self, buffer: &[f32]) -> Result<(), InferenceError> {
        if buffer.len() < N * 2 {
            return Err(InferenceError::BufferTooSmall);
        }
        let (m_buf, v_buf) = buffer.split_at(N);
        self.mean.data_mut().copy_from_slice(m_buf);
        self.variance.data_mut().copy_from_slice(&v_buf[..N]);
        self.initialized = true;
        Ok(())
    }
}

pub fn relu<const N: usize>(
    input: &Tensor<f32, 1>,
    output: &mut Tensor<f32, 1>,
) -> Result<(), InferenceError> {
    if input.shape()[0] != N || output.shape()[0] != N {
        return Err(InferenceError::ShapeMismatch);
    }
    for (out, &inp) in output.data_mut().iter_mut().zip(input.data().iter()) {
        *out = inp.max(0.0);
    }
    Ok(())
}

pub fn sigmoid<const N: usize>(
    input: &Tensor<f32, 1>,
    output: &mut Tensor<f32, 1>,
) -> Result<(), InferenceError> {
    if input.shape()[0] != N || output.shape()[0] != N {
        return Err(InferenceError::ShapeMismatch);
    }
    for (out, &inp) in output.data_mut().iter_mut().zip(input.data().iter()) {
        *out = 1.0 / (1.0 + (-inp).exp());
    }
    Ok(())
}

pub fn softmax<const N: usize>(
    input: &Tensor<f32, 1>,
    output: &mut Tensor<f32, 1>,
) -> Result<(), InferenceError> {
    if input.shape()[0] != N || output.shape()[0] != N {
        return Err(InferenceError::ShapeMismatch);
    }
    let in_d = input.data();
    let out_d = output.data_mut();

    let max_val = in_d.iter().cloned().fold(f32::NEG_INFINITY, f32::max);

    let sum: f32 = in_d
        .iter()
        .zip(out_d.iter_mut())
        .map(|(&inp, out)| {
            let exp_val = (inp - max_val).exp();
            *out = exp_val;
            exp_val
        })
        .sum();

    if sum > 0.0 {
        let inv_sum = 1.0 / sum;
        for out in out_d.iter_mut() {
            *out *= inv_sum;
        }
    }
    Ok(())
}

pub fn mse_loss<const N: usize>(
    actual: &Tensor<f32, 1>,
    predicted: &Tensor<f32, 1>,
) -> Result<f32, InferenceError> {
    if actual.shape()[0] != N || predicted.shape()[0] != N {
        return Err(InferenceError::ShapeMismatch);
    }
    let sum_sq: f32 = actual
        .data()
        .iter()
        .zip(predicted.data().iter())
        .map(|(&a, &p)| {
            let diff = a - p;
            diff * diff
        })
        .sum();

    Ok(sum_sq / (N as f32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(values: [f32; 2]) -> Tensor<f32, 1> {
        let mut t = Tensor::new([2]).unwrap();
        t.data_mut().copy_from_slice(&values);
        t
    }

    #[test]
    fn the_gain_is_checked() {
        for bad in [0.0, -0.1, 1.5, f32::NAN] {
            assert!(EwmaAnomalyDetector::<2>::new(bad).is_err(), "gain {bad}");
        }
        assert!(EwmaAnomalyDetector::<2>::new(1.0).is_ok());
        assert!(matches!(
            EwmaAnomalyDetector::<0>::new(0.5),
            Err(InferenceError::InvalidParameter(_))
        ));
    }

    /// alpha weighs the new sample: gain 0.1 moves the mean a tenth of the way, 0.9 most of it
    /// (a test at 0.5 cannot tell gain from retention).
    #[test]
    fn alpha_is_the_gain_of_a_new_sample() {
        for (gain, expected) in [(0.1f32, 1.0f32), (0.9, 9.0)] {
            let mut d = EwmaAnomalyDetector::<2>::new(gain).unwrap();
            d.update(&sample([0.0, 0.0])).unwrap();
            d.update(&sample([10.0, 10.0])).unwrap();
            assert!((d.mean.data()[0] - expected).abs() < 1e-5, "gain {gain}");
        }
    }

    /// Gain 0.1 at 1 s is a time constant of about 9.49 s (the review's figure), and the
    /// conversion goes both ways; seconds scale with the sample interval.
    #[test]
    fn time_constant_needs_the_sample_interval() {
        let d = EwmaAnomalyDetector::<2>::new(0.1).unwrap();
        assert!((d.time_constant(1.0) - 9.491).abs() < 1e-3);
        assert!((d.time_constant(5.0) - 5.0 * 9.491).abs() < 5e-3);
        assert!((d.half_life(1.0) - 6.579).abs() < 1e-3);
        let back = EwmaAnomalyDetector::<2>::from_time_constant(9.491, 1.0).unwrap();
        assert!((back.alpha - 0.1).abs() < 1e-4);
        assert!(EwmaAnomalyDetector::<2>::from_time_constant(0.0, 1.0).is_err());
    }

    #[test]
    fn the_score_is_a_distance_in_standard_deviations() {
        let mut d = EwmaAnomalyDetector::<2>::new(0.5).unwrap();
        d.update(&sample([0.0, 0.0])).unwrap();
        // Variance starts at 1: a sample 3 away in both features is 3 standard deviations.
        assert!((d.anomaly_score(&sample([3.0, -3.0])).unwrap() - 3.0).abs() < 1e-6);
        assert_eq!(d.anomaly_score(&sample([0.0, 0.0])).unwrap(), 0.0);
    }
}
