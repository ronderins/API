//! PLONK Permutation Grand Product Argument
//!
//! Enforces wire copy constraints across gates using the grand product polynomial Z(X).

use crate::zkp::bn254::Fp;
use serde::{Deserialize, Serialize};

/// Wire Permutation Identity Mapping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePermutation {
    pub sigma_a: Vec<usize>,
    pub sigma_b: Vec<usize>,
    pub sigma_c: Vec<usize>,
}

impl WirePermutation {
    pub fn identity(size: usize) -> Self {
        Self {
            sigma_a: (0..size).collect(),
            sigma_b: (size..2 * size).collect(),
            sigma_c: (2 * size..3 * size).collect(),
        }
    }

    /// Computes the Grand Product Polynomial Z(X) evaluations
    pub fn compute_grand_product(
        &self,
        wire_a_vals: &[Fp],
        wire_b_vals: &[Fp],
        wire_c_vals: &[Fp],
        beta: Fp,
        gamma: Fp,
    ) -> Vec<Fp> {
        let n = wire_a_vals.len();
        let mut z = Vec::with_capacity(n + 1);
        z.push(Fp::from_u64(1));

        let mut acc = Fp::from_u64(1);
        for i in 0..n {
            // (a_i + beta * i + gamma) * (b_i + beta * k1 * i + gamma) * (c_i + beta * k2 * i + gamma)
            let num_a = wire_a_vals[i].add(beta.mul(Fp::from_u64(i as u64))).add(gamma);
            let num_b = wire_b_vals[i].add(beta.mul(Fp::from_u64((i + n) as u64))).add(gamma);
            let num_c = wire_c_vals[i].add(beta.mul(Fp::from_u64((i + 2 * n) as u64))).add(gamma);
            let num = num_a.mul(num_b).mul(num_c);

            // (a_i + beta * sigma_a(i) + gamma) * ...
            let den_a = wire_a_vals[i].add(beta.mul(Fp::from_u64(self.sigma_a[i] as u64))).add(gamma);
            let den_b = wire_b_vals[i].add(beta.mul(Fp::from_u64(self.sigma_b[i] as u64))).add(gamma);
            let den_c = wire_c_vals[i].add(beta.mul(Fp::from_u64(self.sigma_c[i] as u64))).add(gamma);
            let den = den_a.mul(den_b).mul(den_c);

            let factor = num.mul(den.inv().unwrap_or_else(Fp::zero));
            acc = acc.mul(factor);
            z.push(acc);
        }

        z
    }
}
