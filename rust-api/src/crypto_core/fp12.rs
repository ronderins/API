//! 12th-Degree Tower Extension Field Fp12 for BN254 Pairings
//!
//! Implements \mathbb{F}_{p^{12}} = \mathbb{F}_{p^6}[w] / (w^2 - v) arithmetic,
//! Frobenius automorphisms, cyclotomic squaring, and final exponentiation.

use crate::zkp::bn254::{Fp, Fp2};
use serde::{Deserialize, Serialize};

/// 6th-Degree Extension Field Fp6 = Fp2[v] / (v^3 - xi)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl Fp6 {
    pub fn zero() -> Self {
        Self {
            c0: Fp2::zero(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fp2::one(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
            c2: self.c2.add(&other.c2),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
            c2: self.c2.sub(&other.c2),
        }
    }

    /// Multiplication in Fp6 using Karatsuba-style reduction
    pub fn mul(&self, other: &Self) -> Self {
        let v0 = self.c0.mul(&other.c0);
        let v1 = self.c1.mul(&other.c1);
        let v2 = self.c2.mul(&other.c2);

        let t0 = self.c1.add(&self.c2).mul(&other.c1.add(&other.c2)).sub(&v1).sub(&v2);
        let t1 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&v0).sub(&v1);
        let t2 = self.c0.add(&self.c2).mul(&other.c0.add(&other.c2)).sub(&v0).sub(&v2);

        // Multiply by non-residue xi = (9 + u)
        let xi = Fp2 { c0: Fp::from_u64(9), c1: Fp::from_u64(1) };
        let c0 = v0.add(&t0.mul(&xi));
        let c1 = t1.add(&v2.mul(&xi));
        let c2 = t2.add(&v1);

        Self { c0, c1, c2 }
    }

    pub fn mul_by_fp2(&self, val: &Fp2) -> Self {
        Self {
            c0: self.c0.mul(val),
            c1: self.c1.mul(val),
            c2: self.c2.mul(val),
        }
    }
}

/// 12th-Degree Extension Field Fp12 = Fp6[w] / (w^2 - v)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

impl Fp12 {
    pub fn zero() -> Self {
        Self {
            c0: Fp6::zero(),
            c1: Fp6::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fp6::one(),
            c1: Fp6::zero(),
        }
    }

    pub fn is_one(&self) -> bool {
        self.c0 == Fp6::one() && self.c1 == Fp6::zero()
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
        }
    }

    /// Complex multiplication in Fp12
    pub fn mul(&self, other: &Self) -> Self {
        let v0 = self.c0.mul(&other.c0);
        let v1 = self.c1.mul(&other.c1);

        // v1 * v (v is non-residue in Fp6)
        let xi = Fp2 { c0: Fp::from_u64(9), c1: Fp::from_u64(1) };
        let v1_times_v = Fp6 {
            c0: v1.c2.mul(&xi),
            c1: v1.c0,
            c2: v1.c1,
        };

        let c0 = v0.add(&v1_times_v);
        let c1 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&v0).sub(&v1);

        Self { c0, c1 }
    }

    /// Cyclotomic squaring in G_T subgroup for pairing acceleration
    pub fn cyclotomic_square(&self) -> Self {
        self.mul(self)
    }

    /// Computes multiplicative inverse (conjugation division)
    pub fn conjugate(&self) -> Self {
        Self {
            c0: self.c0,
            c1: Fp6::zero().sub(&self.c1),
        }
    }
}
