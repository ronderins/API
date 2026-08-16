//! Custom PLONK Gate Constraints & Selectors
//!
//! Standard Arithmetic Gate: q_L * a + q_R * b + q_O * c + q_M * (a * b) + q_C = 0
//! Custom Range Check Gate and Poseidon Algebraic Sponge Selector Gate.

use crate::zkp::bn254::Fp;
use serde::{Deserialize, Serialize};

/// Selectors configuring the behavior of a PLONK constraint row
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PlonkGateRow {
    pub q_l: Fp,
    pub q_r: Fp,
    pub q_o: Fp,
    pub q_m: Fp,
    pub q_c: Fp,
    pub q_poseidon: Fp,
    pub q_range: Fp,
    pub wire_a: usize,
    pub wire_b: usize,
    pub wire_c: usize,
}

impl PlonkGateRow {
    pub fn new_arithmetic(ql: Fp, qr: Fp, qo: Fp, qm: Fp, qc: Fp, a: usize, b: usize, c: usize) -> Self {
        Self {
            q_l: ql,
            q_r: qr,
            q_o: qo,
            q_m: qm,
            q_c: qc,
            q_poseidon: Fp::zero(),
            q_range: Fp::zero(),
            wire_a: a,
            wire_b: b,
            wire_c: c,
        }
    }

    pub fn new_addition(a: usize, b: usize, c: usize) -> Self {
        Self::new_arithmetic(
            Fp::from_u64(1),
            Fp::from_u64(1),
            Fp::zero().sub(Fp::from_u64(1)),
            Fp::zero(),
            Fp::zero(),
            a,
            b,
            c,
        )
    }

    pub fn new_multiplication(a: usize, b: usize, c: usize) -> Self {
        Self::new_arithmetic(
            Fp::zero(),
            Fp::zero(),
            Fp::zero().sub(Fp::from_u64(1)),
            Fp::from_u64(1),
            Fp::zero(),
            a,
            b,
            c,
        )
    }

    /// Evaluates the gate constraint equation on concrete witness values
    pub fn evaluate(&self, val_a: Fp, val_b: Fp, val_c: Fp) -> Fp {
        let l = self.q_l.mul(val_a);
        let r = self.q_r.mul(val_b);
        let o = self.q_o.mul(val_c);
        let m = self.q_m.mul(val_a.mul(val_b));
        let c = self.q_c;

        l.add(r).add(o).add(m).add(c)
    }
}
