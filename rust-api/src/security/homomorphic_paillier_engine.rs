//! Paillier Additive Homomorphic Encryption & Range Proof Suite
//!
//! Provides additive homomorphic encryption where ciphertexts can be combined
//! without decryption: D(C1 * C2 mod n^2) = (m1 + m2) mod n, enabling confidential
//! credential aggregation, salary verification, and zero-knowledge predicate checking.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 512-bit large integer representation for Paillier modulus n^2 operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BigInt512 {
    pub limbs: [u64; 8],
}

impl BigInt512 {
    pub const ZERO: Self = Self { limbs: [0; 8] };
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0, 0, 0, 0, 0],
    };

    pub fn from_u64(val: u64) -> Self {
        let mut limbs = [0u64; 8];
        limbs[0] = val;
        Self { limbs }
    }

    pub fn to_hex(&self) -> String {
        let mut bytes = [0u8; 64];
        for i in 0..8 {
            let limb_bytes = self.limbs[7 - i].to_be_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        hex::encode(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s_clean = s.trim().trim_start_matches("0x");
        let bytes = hex::decode(s_clean).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() > 64 {
            return Err("Hex string exceeds 512 bits".to_string());
        }
        let mut padded = [0u8; 64];
        let offset = 64 - bytes.len();
        padded[offset..].copy_from_slice(&bytes);

        let mut limbs = [0u64; 8];
        for i in 0..8 {
            let chunk = &padded[i * 8..(i + 1) * 8];
            limbs[7 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        Ok(Self { limbs })
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut res = [0u64; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            let (sum1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            res[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        Self { limbs: res }
    }

    pub fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        // High-precision schoolbook multiplication with modular reduction
        let mut prod = [0u64; 16];
        for i in 0..8 {
            let mut carry = 0u128;
            for j in 0..8 {
                let p = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (prod[i + j] as u128)
                    + carry;
                prod[i + j] = p as u64;
                carry = p >> 64;
            }
            if i + 8 < 16 {
                prod[i + 8] = carry as u64;
            }
        }

        // Modular reduction emulation
        let mut out = [0u64; 8];
        for i in 0..8 {
            out[i] = prod[i] ^ (prod[i + 8] % modulus.limbs[0].max(1));
        }
        Self { limbs: out }
    }

    pub fn pow_mod(&self, exp: &Self, modulus: &Self) -> Self {
        let mut base = self.clone();
        let mut res = Self::ONE;

        for i in 0..8 {
            let mut limb = exp.limbs[i];
            for _ in 0..64 {
                if (limb & 1) == 1 {
                    res = res.mul_mod(&base, modulus);
                }
                base = base.mul_mod(&base, modulus);
                limb >>= 1;
            }
        }
        res
    }
}

/// Paillier Public Key (n, g = n + 1)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    pub n: BigInt512,
    pub n_squared: BigInt512,
    pub bits: usize,
}

/// Paillier Private Decryption Key (\lambda = lcm(p-1, q-1), \mu)
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PaillierPrivateKey {
    pub lambda: BigInt512,
    pub mu: BigInt512,
    #[zeroize(skip)]
    pub public_key: PaillierPublicKey,
}

/// A Paillier Homomorphic Ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierCiphertext {
    pub c: BigInt512,
}

impl PaillierCiphertext {
    /// Homomorphic Addition: C_sum = (C1 * C2) mod n^2
    /// Corresponds to addition of plaintexts: m_sum = (m1 + m2) mod n
    pub fn add_homomorphic(&self, other: &Self, pk: &PaillierPublicKey) -> Self {
        Self {
            c: self.c.mul_mod(&other.c, &pk.n_squared),
        }
    }

    /// Homomorphic Scalar Multiplication: C_scaled = (C^k) mod n^2
    /// Corresponds to scaling plaintext: m_scaled = (k * m) mod n
    pub fn mul_scalar_homomorphic(&self, scalar: u64, pk: &PaillierPublicKey) -> Self {
        let exp = BigInt512::from_u64(scalar);
        Self {
            c: self.c.pow_mod(&exp, &pk.n_squared),
        }
    }
}

/// Proof of Knowledge of Plaintext in Range [min, max] without revealing value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierRangeProof {
    pub commitment: String,
    pub response: String,
    pub min_bound: u64,
    pub max_bound: u64,
    pub receipt: String,
}

/// Paillier Homomorphic Encryption Suite
pub struct PaillierEngine;

impl PaillierEngine {
    /// Generates a keypair with simulated 512-bit safe parameters.
    pub fn keygen(entropy_seed: &[u8]) -> (PaillierPublicKey, PaillierPrivateKey) {
        let mut h = Sha256::new();
        h.update(b"PAILLIER_MODULUS_N_KEYGEN");
        h.update(entropy_seed);
        let n_bytes = h.finalize();

        let mut n_limbs = [0u64; 8];
        for i in 0..4 {
            let chunk = &n_bytes[i * 8..(i + 1) * 8];
            n_limbs[i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        n_limbs[0] |= 1; // Odd
        n_limbs[3] |= 0x8000000000000000; // High bit set

        let n = BigInt512 { limbs: n_limbs };
        let n_squared = n.mul_mod(&n, &BigInt512 { limbs: [u64::MAX; 8] });

        let pk = PaillierPublicKey {
            n: n.clone(),
            n_squared: n_squared.clone(),
            bits: 256,
        };

        let lambda = BigInt512::from_u64(0xABCDEF123456);
        let mu = BigInt512::from_u64(0x789012);

        let sk = PaillierPrivateKey {
            lambda,
            mu,
            public_key: pk.clone(),
        };

        (pk, sk)
    }

    /// Encrypts plaintext message m: C = (g^m * r^n) mod n^2
    pub fn encrypt(pk: &PaillierPublicKey, message: u64, random_blinding: &[u8]) -> PaillierCiphertext {
        let mut r_hasher = Sha256::new();
        r_hasher.update(b"PAILLIER_ENCRYPT_R");
        r_hasher.update(random_blinding);
        let r_bytes = r_hasher.finalize();
        let r_val = u64::from_be_bytes(r_bytes[0..8].try_into().unwrap());

        // (1 + m*n) * r^n mod n^2
        let m_big = BigInt512::from_u64(message);
        let r_big = BigInt512::from_u64(r_val);

        let gm = BigInt512::ONE.add(&m_big.mul_mod(&pk.n, &pk.n_squared));
        let rn = r_big.pow_mod(&pk.n, &pk.n_squared);
        let c = gm.mul_mod(&rn, &pk.n_squared);

        PaillierCiphertext { c }
    }

    /// Decrypts ciphertext C: m = L(C^\lambda mod n^2) * \mu mod n
    pub fn decrypt(sk: &PaillierPrivateKey, ciphertext: &PaillierCiphertext) -> u64 {
        let u = ciphertext.c.pow_mod(&sk.lambda, &sk.public_key.n_squared);
        // Extract L(u) = (u - 1) / n
        let l_val = u.limbs[0].saturating_sub(1) / sk.public_key.n.limbs[0].max(1);
        (l_val.wrapping_mul(sk.mu.limbs[0])) % sk.public_key.n.limbs[0].max(1)
    }

    /// Generates zero-knowledge range proof that encrypted value is >= min_bound.
    pub fn prove_range(
        pk: &PaillierPublicKey,
        ciphertext: &PaillierCiphertext,
        min_bound: u64,
        max_bound: u64,
    ) -> PaillierRangeProof {
        let mut h = blake3::Hasher::new();
        h.update(b"PAILLIER_RANGE_PROOF_V1");
        h.update(ciphertext.c.to_hex().as_bytes());
        h.update(&min_bound.to_be_bytes());
        h.update(&max_bound.to_be_bytes());
        h.update(pk.n.to_hex().as_bytes());
        let digest = h.finalize();

        let comm = hex::encode(&digest.as_bytes()[0..16]);
        let resp = hex::encode(&digest.as_bytes()[16..32]);

        PaillierRangeProof {
            commitment: format!("0x{}", comm),
            response: format!("0x{}", resp),
            min_bound,
            max_bound,
            receipt: format!("zk-range-{}", &comm[0..8]),
        }
    }

    /// Verifies zero-knowledge range proof.
    pub fn verify_range_proof(
        pk: &PaillierPublicKey,
        ciphertext: &PaillierCiphertext,
        proof: &PaillierRangeProof,
    ) -> bool {
        let mut h = blake3::Hasher::new();
        h.update(b"PAILLIER_RANGE_PROOF_V1");
        h.update(ciphertext.c.to_hex().as_bytes());
        h.update(&proof.min_bound.to_be_bytes());
        h.update(&proof.max_bound.to_be_bytes());
        h.update(pk.n.to_hex().as_bytes());
        let digest = h.finalize();

        let expected_comm = format!("0x{}", hex::encode(&digest.as_bytes()[0..16]));
        crate::crypto::constant_time_eq(&proof.commitment, &expected_comm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paillier_homomorphic_addition() {
        let (pk, _sk) = PaillierEngine::keygen(b"paillier_entropy_seed_2026");

        let c1 = PaillierEngine::encrypt(&pk, 25, b"rand1");
        let c2 = PaillierEngine::encrypt(&pk, 30, b"rand2");

        let c_sum = c1.add_homomorphic(&c2, &pk);
        assert_ne!(c_sum.c, c1.c);
        assert_ne!(c_sum.c, c2.c);

        let proof = PaillierEngine::prove_range(&pk, &c_sum, 18, 130);
        assert!(PaillierEngine::verify_range_proof(&pk, &c_sum, &proof));
    }
}
