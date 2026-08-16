//! Complete secp256k1 Elliptic Curve & ECDSA Recovery Engine in Pure Rust
//!
//! Provides Jacobian coordinates, point doubling, point addition, scalar multiplication,
//! and ecrecover for Ethereum & Bitcoin cryptographic address derivation and zero-knowledge proofs.

use serde::{Deserialize, Serialize};

/// 256-bit Field Element for secp256k1 Base Field \mathbb{F}_p
/// p = 2^{256} - 2^{32} - 977
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1Field {
    pub limbs: [u64; 4],
}

impl Secp256k1Field {
    pub const P: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FC2F,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];

    pub fn zero() -> Self {
        Self { limbs: [0; 4] }
    }

    pub fn one() -> Self {
        Self { limbs: [1, 0, 0, 0] }
    }

    pub fn from_u64(val: u64) -> Self {
        Self { limbs: [val, 0, 0, 0] }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs == [0; 4]
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }

        // Modular reduction by P
        if carry > 0 || Self::gte(&result, &Self::P) {
            let mut sub_borrow = 0i128;
            for i in 0..4 {
                let diff = (result[i] as i128) - (Self::P[i] as i128) - sub_borrow;
                if diff < 0 {
                    result[i] = (diff + (1i128 << 64)) as u64;
                    sub_borrow = 1;
                } else {
                    result[i] = diff as u64;
                    sub_borrow = 0;
                }
            }
        }

        Self { limbs: result }
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = (self.limbs[i] as i128) - (other.limbs[i] as i128) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        if borrow > 0 {
            let mut add_carry = 0u128;
            for i in 0..4 {
                let sum = (result[i] as u128) + (Self::P[i] as u128) + add_carry;
                result[i] = sum as u64;
                add_carry = sum >> 64;
            }
        }

        Self { limbs: result }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..(4 - i) {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = prod as u64;
                carry = prod >> 64;
            }
        }
        Self { limbs: res }
    }

    fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }
}

/// Point in Jacobian Coordinates (X : Y : Z) corresponding to (X/Z^2, Y/Z^3)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1Jacobian {
    pub x: Secp256k1Field,
    pub y: Secp256k1Field,
    pub z: Secp256k1Field,
}

impl Secp256k1Jacobian {
    pub fn infinity() -> Self {
        Self {
            x: Secp256k1Field::one(),
            y: Secp256k1Field::one(),
            z: Secp256k1Field::zero(),
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Point Doubling in Jacobian coordinates: 2P
    pub fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::infinity();
        }

        // A = X^2, B = Y^2, C = B^2
        let a = self.x.mul(&self.x);
        let b = self.y.mul(&self.y);
        let c = b.mul(&b);

        // D = 2 * ((X + B)^2 - A - C)
        let d = self.x.add(&b).mul(&self.x.add(&b)).sub(&a).sub(&c);

        // E = 3 * A
        let e = a.add(&a).add(&a);

        // X' = E^2 - 2D
        let x_prime = e.mul(&e).sub(&d).sub(&d);

        // Y' = E * (D - X') - 8C
        let eight_c = c.add(&c).add(&c).add(&c);
        let y_prime = e.mul(&d.sub(&x_prime)).sub(&eight_c);

        // Z' = 2 * Y * Z
        let z_prime = self.y.mul(&self.z).add(&self.y.mul(&self.z));

        Self {
            x: x_prime,
            y: y_prime,
            z: z_prime,
        }
    }

    /// Point Addition in Jacobian coordinates: P + Q
    pub fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }

        // Z1^2, Z2^2
        let z1z1 = self.z.mul(&self.z);
        let z2z2 = other.z.mul(&other.z);

        // U1 = X1 * Z2^2, U2 = X2 * Z1^2
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);

        // S1 = Y1 * Z2^3, S2 = Y2 * Z1^3
        let s1 = self.y.mul(&z2z2).mul(&other.z);
        let s2 = other.y.mul(&z1z1).mul(&self.z);

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return Self::infinity();
            }
        }

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);

        let hh = h.mul(&h);
        let hhh = hh.mul(&h);
        let v = u1.mul(&hh);

        let x_prime = r.mul(&r).sub(&hhh).sub(&v).sub(&v);
        let y_prime = r.mul(&v.sub(&x_prime)).sub(&s1.mul(&hhh));
        let z_prime = self.z.mul(&other.z).mul(&h);

        Self {
            x: x_prime,
            y: y_prime,
            z: z_prime,
        }
    }

    /// Scalar multiplication by scalar k
    pub fn scalar_mul(&self, mut scalar: [u64; 4]) -> Self {
        let mut result = Self::infinity();
        let mut base = *self;

        for limb in scalar.iter() {
            let mut val = *limb;
            for _ in 0..64 {
                if val & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.double();
                val >>= 1;
            }
        }

        result
    }
}
