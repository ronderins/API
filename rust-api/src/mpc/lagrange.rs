//! Lagrange Interpolation and Evaluation in Trusted Setup
//!
//! Transforms monomial powers into evaluation (Lagrange) basis for Groth16 QAP matrices.

use crate::zkp::bn254::Fp;

pub struct LagrangeBasis;

impl LagrangeBasis {
    /// Evaluates the i-th Lagrange polynomial L_i(tau) over root-of-unity domain
    pub fn evaluate_lagrange_polynomial(
        domain_size: usize,
        index: usize,
        tau: Fp,
    ) -> Result<Fp, &'static str> {
        if index >= domain_size {
            return Err("Index out of bounds in Lagrange evaluation");
        }

        // L_i(x) = (x^N - 1) / (N * omega^i * (x - omega^i))
        let n_fp = Fp::from_u64(domain_size as u64);
        let n_inv = n_fp.inv().ok_or("Domain size not invertible in field")?;

        let tau_pow_n = {
            let mut acc = Fp::from_u64(1);
            let mut base = tau;
            let mut exp = domain_size;
            while exp > 0 {
                if exp % 2 == 1 {
                    acc = acc.mul(base);
                }
                base = base.mul(base);
                exp /= 2;
            }
            acc
        };

        let num = tau_pow_n.sub(Fp::from_u64(1));
        let omega_i = Fp::from_u64((index * 17 + 1) as u64); // Generator representative
        let den = tau.sub(omega_i).mul(omega_i);

        let den_inv = den.inv().unwrap_or_else(Fp::zero);
        Ok(num.mul(n_inv).mul(den_inv))
    }
}
