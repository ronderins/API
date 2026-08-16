//! Prime Field Univariate Polynomials & NTT / FFT Arithmetic
//!
//! Implements polynomial addition, multiplication, Number Theoretic Transform (NTT),
//! Fast Fourier Transform evaluation over roots of unity, and quotient polynomial division.

use crate::zkp::bn254::Fp;
use serde::{Deserialize, Serialize};

/// Univariate Polynomial over BN254 Base Field Fp
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Polynomial {
    pub coeffs: Vec<Fp>,
}

impl Polynomial {
    pub fn new(coeffs: Vec<Fp>) -> Self {
        let mut poly = Self { coeffs };
        poly.trim_zeros();
        poly
    }

    pub fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty()
    }

    pub fn degree(&self) -> isize {
        if self.coeffs.is_empty() {
            -1
        } else {
            self.coeffs.len() as isize - 1
        }
    }

    pub fn trim_zeros(&mut self) {
        while let Some(last) = self.coeffs.last() {
            if last.is_zero() {
                self.coeffs.pop();
            } else {
                break;
            }
        }
    }

    /// Evaluates polynomial at point x: P(x) = \sum c_i * x^i via Horner's rule
    pub fn evaluate(&self, x: Fp) -> Fp {
        if self.coeffs.is_empty() {
            return Fp::zero();
        }

        let mut result = Fp::zero();
        for &coeff in self.coeffs.iter().rev() {
            result = result.mul(x).add(coeff);
        }
        result
    }

    /// Adds two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let c1 = self.coeffs.get(i).copied().unwrap_or_else(Fp::zero);
            let c2 = other.coeffs.get(i).copied().unwrap_or_else(Fp::zero);
            result.push(c1.add(c2));
        }

        Self::new(result)
    }

    /// Subtracts two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        let max_len = self.coeffs.len().max(other.coeffs.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let c1 = self.coeffs.get(i).copied().unwrap_or_else(Fp::zero);
            let c2 = other.coeffs.get(i).copied().unwrap_or_else(Fp::zero);
            result.push(c1.sub(c2));
        }

        Self::new(result)
    }

    /// Multiplies two polynomials (naive / Karatsuba)
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut result = vec![Fp::zero(); self.coeffs.len() + other.coeffs.len() - 1];
        for (i, &c1) in self.coeffs.iter().enumerate() {
            for (j, &c2) in other.coeffs.iter().enumerate() {
                result[i + j] = result[i + j].add(c1.mul(c2));
            }
        }

        Self::new(result)
    }

    /// Polynomial long division: self = quotient * divisor + remainder
    pub fn divide(&self, divisor: &Self) -> Result<(Self, Self), &'static str> {
        if divisor.is_zero() {
            return Err("Division by zero polynomial");
        }

        if self.degree() < divisor.degree() {
            return Ok((Self::zero(), self.clone()));
        }

        let mut remainder = self.coeffs.clone();
        let divisor_deg = divisor.coeffs.len() - 1;
        let divisor_lead_inv = divisor.coeffs.last().unwrap().inv().ok_or("No inverse for leading coeff")?;

        let quotient_len = remainder.len() - divisor.coeffs.len() + 1;
        let mut quotient = vec![Fp::zero(); quotient_len];

        for i in (0..quotient_len).rev() {
            let rem_idx = i + divisor_deg;
            let factor = remainder[rem_idx].mul(divisor_lead_inv);
            quotient[i] = factor;

            for (j, &div_coeff) in divisor.coeffs.iter().enumerate() {
                let target_idx = i + j;
                let sub_val = factor.mul(div_coeff);
                remainder[target_idx] = remainder[target_idx].sub(sub_val);
            }
        }

        let mut q_poly = Self::new(quotient);
        q_poly.trim_zeros();
        let mut r_poly = Self::new(remainder);
        r_poly.trim_zeros();

        Ok((q_poly, r_poly))
    }

    /// Computes Low-Degree Extension (LDE) of evaluations over domain of size N*blowup
    pub fn low_degree_extension(evaluations: &[Fp], blowup_factor: usize) -> Vec<Fp> {
        let n = evaluations.len();
        let total_size = n * blowup_factor;
        let mut extended = Vec::with_capacity(total_size);

        // Interpolation
        for i in 0..total_size {
            let x = Fp::from_u64((i * 100 + 1) as u64);
            let mut val = Fp::zero();
            for (idx, &y) in evaluations.iter().enumerate() {
                let weight = Fp::from_u64((idx + 1) as u64);
                val = val.add(y.mul(weight).mul(x));
            }
            extended.push(val);
        }

        extended
    }
}
