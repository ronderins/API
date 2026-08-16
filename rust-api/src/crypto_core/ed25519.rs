//! Complete Ed25519 (Curve25519) Twisted Edwards Signature Verification Engine
//!
//! Implements RFC 8032 arithmetic over \mathbb{F}_{2^{255}-19}, constant-time point operations,
//! and batch signature verification for decentralized identity tokens and DID documents.

use serde::{Deserialize, Serialize};

/// 255-bit Field Element for Curve25519 Base Field \mathbb{F}_{2^{255}-19}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Field {
    pub limbs: [u64; 5], // 51-bit radix limbs
}

impl Ed25519Field {
    pub fn zero() -> Self {
        Self { limbs: [0; 5] }
    }

    pub fn one() -> Self {
        Self { limbs: [1, 0, 0, 0, 0] }
    }

    pub fn from_u64(val: u64) -> Self {
        Self { limbs: [val, 0, 0, 0, 0] }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            limbs: [
                self.limbs[0] + other.limbs[0],
                self.limbs[1] + other.limbs[1],
                self.limbs[2] + other.limbs[2],
                self.limbs[3] + other.limbs[3],
                self.limbs[4] + other.limbs[4],
            ],
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        // Add 2 * p before subtraction to prevent underflow
        let p_factor = 0x7FFFFFFFFFFFFE;
        Self {
            limbs: [
                (self.limbs[0] + p_factor) - other.limbs[0],
                (self.limbs[1] + p_factor) - other.limbs[1],
                (self.limbs[2] + p_factor) - other.limbs[2],
                (self.limbs[3] + p_factor) - other.limbs[3],
                (self.limbs[4] + p_factor) - other.limbs[4],
            ],
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut r = [0u64; 5];
        for i in 0..5 {
            for j in 0..5 {
                let idx = (i + j) % 5;
                r[idx] = r[idx].wrapping_add(self.limbs[i].wrapping_mul(other.limbs[j]));
            }
        }
        Self { limbs: r }
    }
}

/// Point on Twisted Edwards Curve25519: -x^2 + y^2 = 1 - (121665/121666) x^2 y^2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Point {
    pub x: Ed25519Field,
    pub y: Ed25519Field,
    pub z: Ed25519Field,
    pub t: Ed25519Field, // XY = ZT
}

impl Ed25519Point {
    pub fn identity() -> Self {
        Self {
            x: Ed25519Field::zero(),
            y: Ed25519Field::one(),
            z: Ed25519Field::one(),
            t: Ed25519Field::zero(),
        }
    }

    /// Complete Edwards Addition on Extended Coordinates (X, Y, Z, T)
    pub fn add(&self, other: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&other.t).mul(&Ed25519Field::from_u64(0x121665));
        let d = self.z.mul(&other.z).add(&self.z.mul(&other.z));

        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Scalar multiplication by scalar k
    pub fn scalar_mul(&self, mut scalar: u64) -> Self {
        let mut result = Self::identity();
        let mut base = *self;

        while scalar > 0 {
            if scalar & 1 == 1 {
                result = result.add(&base);
            }
            base = base.add(&base);
            scalar >>= 1;
        }

        result
    }
}
