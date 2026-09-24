use std::error::Error;
use std::fmt;
use std::ops::{Index, IndexMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorError {
    IndexOutOfBounds,
    ShapeMismatch,
    Overflow,
}

impl fmt::Display for TensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds => write!(f, "Tensor index out of bounds"),
            Self::ShapeMismatch => write!(f, "Data length does not match tensor shape capacity"),
            Self::Overflow => write!(f, "Arithmetic overflow during stride or offset calculation"),
        }
    }
}

impl Error for TensorError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tensor<T, const R: usize> {
    data: Box<[T]>,
    shape: [usize; R],
    strides: [usize; R],
}

pub const fn compute_strides_and_capacity<const R: usize>(
    shape: &[usize; R],
) -> Result<([usize; R], usize), TensorError> {
    let mut strides = [1usize; R];
    let mut total_elements = 1usize;

    let mut i = R;
    while i > 0 {
        i -= 1;
        strides[i] = total_elements;

        match total_elements.checked_mul(shape[i]) {
            Some(val) => total_elements = val,
            None => return Err(TensorError::Overflow),
        }
    }

    Ok((strides, total_elements))
}

impl<T: Default + Clone, const R: usize> Tensor<T, R> {
    pub fn new(shape: [usize; R]) -> Result<Self, TensorError> {
        let (strides, capacity) = compute_strides_and_capacity(&shape)?;
        let data = vec![T::default(); capacity].into_boxed_slice();

        Ok(Self {
            data,
            shape,
            strides,
        })
    }
}

impl<T: Clone, const R: usize> Tensor<T, R> {
    pub fn from_elem(shape: [usize; R], elem: T) -> Result<Self, TensorError> {
        let (strides, capacity) = compute_strides_and_capacity(&shape)?;
        let data = vec![elem; capacity].into_boxed_slice();

        Ok(Self {
            data,
            shape,
            strides,
        })
    }

    pub fn from_vec(shape: [usize; R], data: Vec<T>) -> Result<Self, TensorError> {
        let (strides, capacity) = compute_strides_and_capacity(&shape)?;
        if data.len() != capacity {
            return Err(TensorError::ShapeMismatch);
        }

        Ok(Self {
            data: data.into_boxed_slice(),
            shape,
            strides,
        })
    }

    pub fn from_slice(shape: [usize; R], slice: &[T]) -> Result<Self, TensorError> {
        let (strides, capacity) = compute_strides_and_capacity(&shape)?;
        if slice.len() != capacity {
            return Err(TensorError::ShapeMismatch);
        }

        Ok(Self {
            data: slice.to_vec().into_boxed_slice(),
            shape,
            strides,
        })
    }
}

impl<T, const R: usize> Tensor<T, R> {
    #[inline(always)]
    pub fn shape(&self) -> &[usize; R] {
        &self.shape
    }

    #[inline(always)]
    pub fn strides(&self) -> &[usize; R] {
        &self.strides
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline(always)]
    pub fn data(&self) -> &[T] {
        &self.data
    }

    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [T] {
        &mut self.data
    }

    pub fn into_vec(self) -> Vec<T> {
        self.data.into_vec()
    }

    #[inline]
    pub fn offset_checked(&self, indices: [usize; R]) -> Result<usize, TensorError> {
        let mut offset = 0usize;
        for i in 0..R {
            if indices[i] >= self.shape[i] {
                return Err(TensorError::IndexOutOfBounds);
            }
            let term = indices[i]
                .checked_mul(self.strides[i])
                .ok_or(TensorError::Overflow)?;

            offset = offset.checked_add(term).ok_or(TensorError::Overflow)?;
        }
        Ok(offset)
    }

    #[inline(always)]
    pub fn offset_unchecked(&self, indices: [usize; R]) -> usize {
        let mut offset = 0usize;
        for i in 0..R {
            offset += indices[i] * self.strides[i];
        }
        offset
    }

    pub fn swap_axes(&mut self, axis1: usize, axis2: usize) -> Result<(), TensorError> {
        if axis1 >= R || axis2 >= R {
            return Err(TensorError::IndexOutOfBounds);
        }
        self.shape.swap(axis1, axis2);
        self.strides.swap(axis1, axis2);
        Ok(())
    }

    #[inline]
    pub fn get(&self, indices: [usize; R]) -> Option<&T> {
        match self.offset_checked(indices) {
            Ok(offset) => Some(&self.data[offset]),
            Err(_) => None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self, indices: [usize; R]) -> Option<&mut T> {
        match self.offset_checked(indices) {
            Ok(offset) => Some(&mut self.data[offset]),
            Err(_) => None,
        }
    }

    /// # Safety
    ///
    /// Every index must be below the corresponding dimension of `shape()`; otherwise the
    /// computed offset is out of bounds and the behaviour is undefined.
    #[inline(always)]
    pub unsafe fn get_unchecked(&self, indices: [usize; R]) -> &T {
        let idx = self.offset_unchecked(indices);
        self.data.get_unchecked(idx)
    }

    /// # Safety
    ///
    /// Same contract as [`get_unchecked`](Self::get_unchecked).
    #[inline(always)]
    pub unsafe fn get_unchecked_mut(&mut self, indices: [usize; R]) -> &mut T {
        let idx = self.offset_unchecked(indices);
        self.data.get_unchecked_mut(idx)
    }
}

impl<T, const R: usize> Index<[usize; R]> for Tensor<T, R> {
    type Output = T;

    #[inline(always)]
    fn index(&self, indices: [usize; R]) -> &Self::Output {
        match self.offset_checked(indices) {
            Ok(offset) => &self.data[offset],
            Err(err) => panic!("Tensor index out of bounds: {:?}, error: {}", indices, err),
        }
    }
}

impl<T, const R: usize> IndexMut<[usize; R]> for Tensor<T, R> {
    #[inline(always)]
    fn index_mut(&mut self, indices: [usize; R]) -> &mut Self::Output {
        match self.offset_checked(indices) {
            Ok(offset) => &mut self.data[offset],
            Err(err) => panic!("Tensor index out of bounds: {:?}, error: {}", indices, err),
        }
    }
}
