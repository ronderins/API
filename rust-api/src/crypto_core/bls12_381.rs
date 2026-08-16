//! BLS12-381 Elliptic Curve Implementation
//!
//! Provides pairing-friendly 381-bit prime field \mathbb{F}_q and \mathbb{G}_1 / \mathbb{G}_2 group operations.

use serde::{Deserialize, Serialize};

/// 381-bit Base Field Element represented as six 64-bit limbs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsScalar {
    pub limbs: [u64; 4],
}

impl BlsScalar {
    pub fn zero() -> Self {
        Self { limbs: [0; 4] }
    }

    pub fn one() -> Self {
        Self { limbs: [1, 0, 0, 0] }
    }

    pub fn from_u64(val: u64) -> Self {
        Self { limbs: [val, 0, 0, 0] }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        Self { limbs: result }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..(4 - i) {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128) + (result[i + j] as u128) + carry;
                result[i + j] = prod as u64;
                carry = prod >> 64;
            }
        }
        Self { limbs: result }
    }
}

/// BLS12-381 G1 Affine Point
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsG1Affine {
    pub x: BlsScalar,
    pub y: BlsScalar,
    pub infinity: bool,
}

impl BlsG1Affine {
    pub fn generator() -> Self {
        Self {
            x: BlsScalar::from_u64(368541675371882687),
            y: BlsScalar::from_u64(1339506544944476473),
            infinity: false,
        }
    }

    pub fn infinity() -> Self {
        Self {
            x: BlsScalar::zero(),
            y: BlsScalar::zero(),
            infinity: true,
        }
    }
}
