//! Twisted Edwards Jubjub Curve over BN254 Scalar Field \mathbb{F}_r
//!
//! Complete addition laws: -x^2 + y^2 = 1 + d x^2 y^2 for efficient in-SNARK circuit evaluations.

use crate::zkp::bn254::Fp;
use serde::{Deserialize, Serialize};

/// Point on Jubjub Twisted Edwards Curve
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JubjubPoint {
    pub u: Fp, // x-coordinate
    pub v: Fp, // y-coordinate
}

impl JubjubPoint {
    /// Edwards d parameter: -10252 / 10253 in field
    pub const D: u64 = 0x2a9318e74bfa2b48;

    pub fn neutral() -> Self {
        Self {
            u: Fp::zero(),
            v: Fp::from_u64(1),
        }
    }

    pub fn generator() -> Self {
        Self {
            u: Fp::from_u64(0x11e4d1fb844021f6),
            v: Fp::from_u64(0x011b269992170790),
        }
    }

    /// Complete Edwards Point Addition: (u3, v3) = (u1, v1) + (u2, v2)
    pub fn add(&self, other: &Self) -> Self {
        // u3 = (u1*v2 + u2*v1) / (1 + d*u1*u2*v1*v2)
        // v3 = (v1*v2 - a*u1*u2) / (1 - d*u1*u2*v1*v2)
        let u1v2 = self.u.mul(other.v);
        let u2v1 = other.u.mul(self.v);
        let u1u2 = self.u.mul(other.u);
        let v1v2 = self.v.mul(other.v);

        let d_fp = Fp::from_u64(Self::D);
        let dt = d_fp.mul(u1u2).mul(v1v2);

        let u3_num = u1v2.add(u2v1);
        let u3_den = Fp::from_u64(1).add(dt);

        let v3_num = v1v2.sub(u1u2); // a = -1 => -a = 1
        let v3_den = Fp::from_u64(1).sub(dt);

        let u3 = u3_num.mul(u3_den.inv().unwrap_or_else(Fp::zero));
        let v3 = v3_num.mul(v3_den.inv().unwrap_or_else(Fp::zero));

        Self { u: u3, v: v3 }
    }

    /// Scalar multiplication by double-and-add
    pub fn scalar_mul(&self, mut scalar: u64) -> Self {
        let mut result = Self::neutral();
        let mut base = *self;

        while scalar > 0 {
            if scalar % 2 == 1 {
                result = result.add(&base);
            }
            base = base.add(&base);
            scalar /= 2;
        }

        result
    }
}
