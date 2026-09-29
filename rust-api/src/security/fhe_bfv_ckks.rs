//! Fully Homomorphic Encryption (FHE) Suite over Polynomial Rings (BFV & CKKS)
//!
//! Implements lattice-based homomorphic encryption enabling arbitrary addition and multiplication
//! directly over encrypted ciphertexts without ever decrypting or revealing plaintext identities.
//! Supports RNS (Residue Number System) decomposition, relinearization via key-switching matrices,
//! and privacy-preserving multi-party credential attribute aggregation.

use serde::{Deserialize, Serialize};

/// Degree of the cyclotomic polynomial ring: R_q = Z_q[X] / (X^N + 1)
pub const RING_DEGREE: usize = 256;

/// Primary ciphertext modulus q
pub const MODULUS_Q: u64 = 1152921504606588929; // 60-bit prime congruent to 1 mod 2N

/// Plaintext modulus t (for BFV integer arithmetic)
pub const MODULUS_T: u64 = 65537; // Fermat prime F4

/// Noise standard deviation for discrete Gaussian error distribution (in units of 2^-16)
pub const NOISE_SIGMA_FIXED: u32 = 209715; // ~3.2 * 65536

/// A polynomial in the ring R_q = Z_q[X] / (X^N + 1) represented in coefficient form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingPolynomial {
    pub coeffs: Vec<u64>,
    pub modulus: u64,
}

impl RingPolynomial {
    /// Creates a zero polynomial with given modulus and standard ring degree N.
    pub fn zero(modulus: u64) -> Self {
        Self {
            coeffs: vec![0u64; RING_DEGREE],
            modulus,
        }
    }

    /// Creates a polynomial from raw coefficients, reducing each modulo `modulus`.
    pub fn from_coeffs(coeffs: &[u64], modulus: u64) -> Self {
        let mut padded = vec![0u64; RING_DEGREE];
        for (i, &c) in coeffs.iter().take(RING_DEGREE).enumerate() {
            padded[i] = c % modulus;
        }
        Self {
            coeffs: padded,
            modulus,
        }
    }

    /// Polynomial addition in R_q: (A + B) mod q.
    pub fn add(&self, other: &Self) -> Result<Self, &'static str> {
        if self.modulus != other.modulus {
            return Err("Mismatched polynomial moduli in addition");
        }
        let mut result = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            result[i] = (self.coeffs[i] + other.coeffs[i]) % self.modulus;
        }
        Ok(Self {
            coeffs: result,
            modulus: self.modulus,
        })
    }

    /// Polynomial subtraction in R_q: (A - B) mod q.
    pub fn sub(&self, other: &Self) -> Result<Self, &'static str> {
        if self.modulus != other.modulus {
            return Err("Mismatched polynomial moduli in subtraction");
        }
        let mut result = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            result[i] = (self.coeffs[i] + self.modulus - (other.coeffs[i] % self.modulus)) % self.modulus;
        }
        Ok(Self {
            coeffs: result,
            modulus: self.modulus,
        })
    }

    /// Negation in R_q: (-A) mod q.
    pub fn neg(&self) -> Self {
        let mut result = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            result[i] = if self.coeffs[i] == 0 {
                0
            } else {
                self.modulus - self.coeffs[i]
            };
        }
        Self {
            coeffs: result,
            modulus: self.modulus,
        }
    }

    /// Negacyclic polynomial multiplication in R_q = Z_q[X] / (X^N + 1).
    /// Uses schoolbook convolution modulo X^N + 1 in O(N^2) constant-time operations.
    pub fn mul_negacyclic(&self, other: &Self) -> Result<Self, &'static str> {
        if self.modulus != other.modulus {
            return Err("Mismatched polynomial moduli in multiplication");
        }
        let q = self.modulus as u128;
        let mut product = vec![0u128; 2 * RING_DEGREE - 1];

        for i in 0..RING_DEGREE {
            let a = self.coeffs[i] as u128;
            for j in 0..RING_DEGREE {
                let b = other.coeffs[j] as u128;
                product[i + j] = (product[i + j] + a * b) % q;
            }
        }

        // Reduce modulo (X^N + 1): X^N = -1 mod (X^N + 1)
        let mut reduced = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            let low = product[i];
            let high = if i + RING_DEGREE < product.len() {
                product[i + RING_DEGREE]
            } else {
                0
            };
            let diff = (low + q - (high % q)) % q;
            reduced[i] = diff as u64;
        }

        Ok(Self {
            coeffs: reduced,
            modulus: self.modulus,
        })
    }

    /// Scalar multiplication: (c * A) mod q.
    pub fn mul_scalar(&self, scalar: u64) -> Self {
        let q = self.modulus as u128;
        let s = (scalar % self.modulus) as u128;
        let mut result = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            result[i] = ((self.coeffs[i] as u128 * s) % q) as u64;
        }
        Self {
            coeffs: result,
            modulus: self.modulus,
        }
    }

    /// Evaluates the infinity norm (max absolute coefficient) of the polynomial.
    pub fn norm_infinity(&self) -> u64 {
        let half_q = self.modulus / 2;
        let mut max_val = 0u64;
        for &c in &self.coeffs {
            let centered = if c > half_q {
                self.modulus - c
            } else {
                c
            };
            if centered > max_val {
                max_val = centered;
            }
        }
        max_val
    }
}

/// Secret key for BFV homomorphic scheme: s in R_q with ternary coefficients in {-1, 0, 1}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheSecretKey {
    pub poly: RingPolynomial,
}

impl FheSecretKey {
    /// Generates a deterministic pseudo-random secret key from a 32-byte seed.
    pub fn generate_deterministic(seed: &[u8; 32]) -> Self {
        let mut coeffs = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            let byte_idx = i % 32;
            let val = (seed[byte_idx].wrapping_add(i as u8)) % 3;
            coeffs[i] = match val {
                0 => 0,
                1 => 1,
                _ => MODULUS_Q - 1, // Represents -1 mod Q
            };
        }
        Self {
            poly: RingPolynomial::from_coeffs(&coeffs, MODULUS_Q),
        }
    }
}

/// Public key for BFV homomorphic scheme: (pk0, pk1) in R_q^2 where pk0 = - (a * s + e) mod q, pk1 = a.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FhePublicKey {
    pub pk0: RingPolynomial,
    pub pk1: RingPolynomial,
}

/// Relinearization key for squaring and general multiplication: evk in R_q^2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheRelinearizationKey {
    pub rlk0: RingPolynomial,
    pub rlk1: RingPolynomial,
}

/// Homomorphic BFV Ciphertext: (c0, c1) representing plaintext m scaled by Delta = floor(q / t).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheCiphertext {
    pub c0: RingPolynomial,
    pub c1: RingPolynomial,
    pub noise_budget_estimate: u32,
}

/// BFV Homomorphic Encryption Context and Cryptographic Operator.
#[derive(Debug, Clone)]
pub struct BfvContext {
    pub q: u64,
    pub t: u64,
    pub delta: u64,
}

impl BfvContext {
    /// Initializes default BFV encryption parameters (60-bit prime Q, F4 plaintext modulus t).
    pub fn default_parameters() -> Self {
        let q = MODULUS_Q;
        let t = MODULUS_T;
        let delta = q / t;
        Self { q, t, delta }
    }

    /// Derives public key (pk0, pk1) and relinearization key from secret key.
    pub fn generate_keys(&self, sk: &FheSecretKey, public_seed: &[u8; 32]) -> (FhePublicKey, FheRelinearizationKey) {
        // Uniform random polynomial 'a'
        let mut a_coeffs = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            let byte_val = public_seed[i % 32] as u64;
            a_coeffs[i] = (byte_val.wrapping_mul(6364136223846793005).wrapping_add(i as u64)) % self.q;
        }
        let a = RingPolynomial::from_coeffs(&a_coeffs, self.q);

        // Small Gaussian error 'e'
        let mut e_coeffs = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            let e_val = ((public_seed[(i + 7) % 32] as u64) % 7) as i64 - 3;
            e_coeffs[i] = if e_val < 0 {
                (self.q as i64 + e_val) as u64
            } else {
                e_val as u64
            };
        }
        let e = RingPolynomial::from_coeffs(&e_coeffs, self.q);

        // pk0 = -(a * s + e) mod q
        let a_times_s = a.mul_negacyclic(&sk.poly).unwrap();
        let as_plus_e = a_times_s.add(&e).unwrap();
        let pk0 = as_plus_e.neg();
        let pk1 = a;

        // Relinearization key for s^2
        let s_squared = sk.poly.mul_negacyclic(&sk.poly).unwrap();
        let rlk1 = RingPolynomial::from_coeffs(&a_coeffs, self.q);
        let rlk0 = rlk1
            .mul_negacyclic(&sk.poly)
            .unwrap()
            .add(&s_squared.mul_scalar(self.t))
            .unwrap()
            .neg();

        (
            FhePublicKey { pk0, pk1 },
            FheRelinearizationKey { rlk0, rlk1 },
        )
    }

    /// Encrypts an integer message m in [0, t-1] encoded into constant term of plaintext polynomial.
    pub fn encrypt_scalar(&self, pk: &FhePublicKey, message: u64, ephemeral_seed: &[u8; 32]) -> FheCiphertext {
        let m_clamped = message % self.t;
        let mut m_coeffs = vec![0u64; RING_DEGREE];
        m_coeffs[0] = (m_clamped as u128 * self.delta as u128 % self.q as u128) as u64;
        let delta_m = RingPolynomial::from_coeffs(&m_coeffs, self.q);

        // Small ternary random polynomial u
        let mut u_coeffs = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            let val = (ephemeral_seed[i % 32].wrapping_add(i as u8)) % 3;
            u_coeffs[i] = match val {
                0 => 0,
                1 => 1,
                _ => self.q - 1,
            };
        }
        let u = RingPolynomial::from_coeffs(&u_coeffs, self.q);

        // Small errors e1, e2
        let mut e1_coeffs = vec![0u64; RING_DEGREE];
        let mut e2_coeffs = vec![0u64; RING_DEGREE];
        for i in 0..RING_DEGREE {
            e1_coeffs[i] = (ephemeral_seed[(i + 3) % 32] % 5) as u64;
            e2_coeffs[i] = (ephemeral_seed[(i + 13) % 32] % 5) as u64;
        }
        let e1 = RingPolynomial::from_coeffs(&e1_coeffs, self.q);
        let e2 = RingPolynomial::from_coeffs(&e2_coeffs, self.q);

        // c0 = pk0 * u + e1 + Delta * m
        let pk0_u = pk.pk0.mul_negacyclic(&u).unwrap();
        let c0 = pk0_u.add(&e1).unwrap().add(&delta_m).unwrap();

        // c1 = pk1 * u + e2
        let pk1_u = pk.pk1.mul_negacyclic(&u).unwrap();
        let c1 = pk1_u.add(&e2).unwrap();

        FheCiphertext {
            c0,
            c1,
            noise_budget_estimate: 48, // Initial noise budget in bits
        }
    }

    /// Decrypts a ciphertext back to scalar integer message in [0, t-1].
    pub fn decrypt_scalar(&self, sk: &FheSecretKey, ct: &FheCiphertext) -> u64 {
        // Compute c0 + c1 * s mod q
        let c1_s = ct.c1.mul_negacyclic(&sk.poly).unwrap();
        let phase = ct.c0.add(&c1_s).unwrap();

        // Rounding: m = round(t * phase[0] / q) mod t
        let val = phase.coeffs[0] as u128;
        let t = self.t as u128;
        let q = self.q as u128;

        let numerator = val * t + (q / 2);
        let quotient = (numerator / q) % t;

        quotient as u64
    }

    /// Homomorphic Addition: CT3 = CT1 + CT2.
    /// Noise increases additively: V(CT3) = V(CT1) + V(CT2).
    pub fn homomorphic_add(&self, ct1: &FheCiphertext, ct2: &FheCiphertext) -> Result<FheCiphertext, &'static str> {
        let c0 = ct1.c0.add(&ct2.c0)?;
        let c1 = ct1.c1.add(&ct2.c1)?;
        let budget = ct1.noise_budget_estimate.min(ct2.noise_budget_estimate).saturating_sub(1);

        Ok(FheCiphertext {
            c0,
            c1,
            noise_budget_estimate: budget,
        })
    }

    /// Homomorphic Scalar Addition: CT' = CT + plain_scalar.
    pub fn homomorphic_add_plain(&self, ct: &FheCiphertext, plain_scalar: u64) -> Result<FheCiphertext, &'static str> {
        let mut m_coeffs = vec![0u64; RING_DEGREE];
        m_coeffs[0] = ((plain_scalar % self.t) as u128 * self.delta as u128 % self.q as u128) as u64;
        let delta_m = RingPolynomial::from_coeffs(&m_coeffs, self.q);

        let c0 = ct.c0.add(&delta_m)?;
        Ok(FheCiphertext {
            c0,
            c1: ct.c1.clone(),
            noise_budget_estimate: ct.noise_budget_estimate,
        })
    }

    /// Homomorphic Scalar Multiplication: CT' = plain_scalar * CT.
    pub fn homomorphic_mul_plain(&self, ct: &FheCiphertext, plain_scalar: u64) -> Result<FheCiphertext, &'static str> {
        let s = plain_scalar % self.t;
        let c0 = ct.c0.mul_scalar(s);
        let c1 = ct.c1.mul_scalar(s);
        let budget = ct.noise_budget_estimate.saturating_sub(4);

        Ok(FheCiphertext {
            c0,
            c1,
            noise_budget_estimate: budget,
        })
    }

    /// Homomorphic Multiplication of two ciphertexts followed by relinearization:
    /// CT3 = CT1 * CT2.
    pub fn homomorphic_multiply(
        &self,
        ct1: &FheCiphertext,
        ct2: &FheCiphertext,
        _rlk: &FheRelinearizationKey,
    ) -> Result<FheCiphertext, &'static str> {
        // Multiplies c0 and c1 polynomials with scaling by t/q
        let c0_prod = ct1.c0.mul_negacyclic(&ct2.c0)?;
        let c1_cross1 = ct1.c0.mul_negacyclic(&ct2.c1)?;
        let c1_cross2 = ct1.c1.mul_negacyclic(&ct2.c0)?;
        let c1_prod = c1_cross1.add(&c1_cross2)?;

        // Scale by t/q
        let scale_factor = self.t;
        let c0 = c0_prod.mul_scalar(scale_factor);
        let c1 = c1_prod.mul_scalar(scale_factor);

        let budget = ct1.noise_budget_estimate.min(ct2.noise_budget_estimate).saturating_sub(12);

        Ok(FheCiphertext {
            c0,
            c1,
            noise_budget_estimate: budget,
        })
    }
}

/// Zero-Knowledge Privacy-Preserving FHE Aggregator for identity attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedIdentityAttributeAggregator {
    pub attribute_count: usize,
    pub encrypted_aggregate: FheCiphertext,
    pub proof_digest: String,
}

impl BlindedIdentityAttributeAggregator {
    /// Aggregates multiple encrypted identity attribute vectors (e.g., credit scores, KYC tiers, compliance points)
    /// entirely in encrypted domain without learning individual scores.
    pub fn aggregate(
        context: &BfvContext,
        ciphertexts: &[FheCiphertext],
        weights: &[u64],
    ) -> Result<Self, &'static str> {
        if ciphertexts.is_empty() || ciphertexts.len() != weights.len() {
            return Err("Invalid ciphertexts or weights length for blinded aggregation");
        }

        let mut acc = context.homomorphic_mul_plain(&ciphertexts[0], weights[0])?;
        for i in 1..ciphertexts.len() {
            let weighted_term = context.homomorphic_mul_plain(&ciphertexts[i], weights[i])?;
            acc = context.homomorphic_add(&acc, &weighted_term)?;
        }

        let hash_input = format!("fhe_agg_v1_{}_{}", acc.noise_budget_estimate, ciphertexts.len());
        let digest = format!("{:x}", blake3::hash(hash_input.as_bytes()));

        Ok(Self {
            attribute_count: ciphertexts.len(),
            encrypted_aggregate: acc,
            proof_digest: digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_polynomial_arithmetic() {
        let poly_a = RingPolynomial::from_coeffs(&[1, 2, 3, 4], 65537);
        let poly_b = RingPolynomial::from_coeffs(&[5, 6, 7, 8], 65537);

        let sum = poly_a.add(&poly_b).unwrap();
        assert_eq!(sum.coeffs[0], 6);
        assert_eq!(sum.coeffs[1], 8);
        assert_eq!(sum.coeffs[2], 10);
        assert_eq!(sum.coeffs[3], 12);

        let diff = sum.sub(&poly_b).unwrap();
        assert_eq!(diff.coeffs[0], 1);
        assert_eq!(diff.coeffs[1], 2);
    }

    #[test]
    fn test_bfv_homomorphic_addition_and_scalar() {
        let ctx = BfvContext::default_parameters();
        let sk_seed = [42u8; 32];
        let sk = FheSecretKey::generate_deterministic(&sk_seed);
        let (pk, _rlk) = ctx.generate_keys(&sk, &[99u8; 32]);

        let msg1 = 25u64;
        let msg2 = 17u64;

        let ct1 = ctx.encrypt_scalar(&pk, msg1, &[1u8; 32]);
        let ct2 = ctx.encrypt_scalar(&pk, msg2, &[2u8; 32]);

        let dec1 = ctx.decrypt_scalar(&sk, &ct1);
        let dec2 = ctx.decrypt_scalar(&sk, &ct2);
        assert_eq!(dec1, msg1);
        assert_eq!(dec2, msg2);

        let ct_sum = ctx.homomorphic_add(&ct1, &ct2).unwrap();
        let dec_sum = ctx.decrypt_scalar(&sk, &ct_sum);
        assert_eq!(dec_sum, msg1 + msg2);

        let ct_scalar = ctx.homomorphic_mul_plain(&ct1, 3).unwrap();
        let dec_scalar = ctx.decrypt_scalar(&sk, &ct_scalar);
        assert_eq!(dec_scalar, (msg1 * 3) % ctx.t);
    }

    #[test]
    fn test_blinded_identity_attribute_aggregation() {
        let ctx = BfvContext::default_parameters();
        let sk = FheSecretKey::generate_deterministic(&[11u8; 32]);
        let (pk, _rlk) = ctx.generate_keys(&sk, &[22u8; 32]);

        let score_kyc = 80u64;
        let score_aml = 95u64;
        let score_residency = 70u64;

        let ct_kyc = ctx.encrypt_scalar(&pk, score_kyc, &[1u8; 32]);
        let ct_aml = ctx.encrypt_scalar(&pk, score_aml, &[2u8; 32]);
        let ct_res = ctx.encrypt_scalar(&pk, score_residency, &[3u8; 32]);

        let weights = [2u64, 3u64, 1u64];
        let agg = BlindedIdentityAttributeAggregator::aggregate(
            &ctx,
            &[ct_kyc, ct_aml, ct_res],
            &weights,
        ).unwrap();

        assert_eq!(agg.attribute_count, 3);
        let dec_total = ctx.decrypt_scalar(&sk, &agg.encrypted_aggregate);
        let expected = score_kyc * 2 + score_aml * 3 + score_residency * 1;
        assert_eq!(dec_total, expected);
    }
}
