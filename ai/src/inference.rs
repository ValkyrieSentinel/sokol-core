use crate::tensor::{Tensor, TensorError};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceError {
    ShapeMismatch,
    BufferTooSmall,
    Tensor(TensorError),
}

impl fmt::Display for InferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShapeMismatch => write!(f, "Inference shape mismatch"),
            Self::BufferTooSmall => write!(f, "Export/Import buffer capacity is too small"),
            Self::Tensor(e) => write!(f, "Tensor error: {}", e),
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

pub struct EwmaAnomalyDetector<const N: usize> {
    pub mean: Tensor<f32, 1>,
    pub variance: Tensor<f32, 1>,
    pub alpha: f32,
    initialized: bool,
}

impl<const N: usize> EwmaAnomalyDetector<N> {
    pub fn new(alpha: f32) -> Result<Self, InferenceError> {
        Ok(Self {
            mean: Tensor::new([N])?,
            variance: Tensor::new([N])?,
            alpha,
            initialized: false,
        })
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
            v_data.fill(1.0);
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
                let std_dev = v.sqrt().max(1e-6);
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
