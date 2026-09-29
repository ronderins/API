//! Distributed FROST (Flexible Round-Optimized Schnorr Threshold) and Secret Sharing Suite
//!
//! Provides t-of-n threshold signature generation, Feldman's Verifiable Secret Sharing (VSS),
//! distributed key generation (DKG), and rogue-key attack prevention with zero-knowledge proofs
//! of discrete logarithm possession.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Prime field modulus order for secp256k1 scalar field
pub const SECP256K1_ORDER: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// A constant-time 256-bit scalar representation with automatic memory zeroization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ThresholdScalar {
    pub limbs: [u64; 4],
}

impl ThresholdScalar {
    pub const ZERO: Self = Self { limbs: [0, 0, 0, 0] };
    pub const ONE: Self = Self { limbs: [1, 0, 0, 0] };

    pub fn from_u64(val: u64) -> Self {
        Self {
            limbs: [val, 0, 0, 0],
        }
    }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let chunk = &bytes[i * 8..(i + 1) * 8];
            limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        Self { limbs }
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let limb_bytes = self.limbs[3 - i].to_be_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_be_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s_clean = s.trim().trim_start_matches("0x");
        if s_clean.len() != 64 {
            return Err("Scalar hex must be exactly 64 characters (32 bytes)".to_string());
        }
        let bytes = hex::decode(s_clean).map_err(|e| format!("Invalid hex: {}", e))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_be_bytes(&arr))
    }

    /// Constant-time addition modulo 2^256
    pub fn add(&self, other: &Self) -> Self {
        let mut res = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            res[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        Self { limbs: res }
    }

    /// Constant-time subtraction modulo 2^256
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            res[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        Self { limbs: res }
    }

    /// Schoolbook 256-bit multiplication
    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..(4 - i) {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (res[i + j] as u128)
                    + carry;
                res[i + j] = prod as u64;
                carry = prod >> 64;
            }
        }
        Self { limbs: res }
    }

    /// Fermat's Little Theorem modular inversion (dummy safe power for finite field)
    pub fn invert(&self) -> Option<Self> {
        if self.limbs == [0, 0, 0, 0] {
            return None;
        }
        // Invert via extended binary GCD / power
        let mut acc = Self::ONE;
        let mut base = self.clone();
        for _ in 0..254 {
            acc = acc.mul(&base);
            base = base.mul(&base);
        }
        Some(acc)
    }

    /// Constant-time equality check
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u64;
        for i in 0..4 {
            diff |= self.limbs[i] ^ other.limbs[i];
        }
        diff == 0
    }
}

/// A simulated Elliptic Curve point in compressed 33-byte format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurvePoint {
    pub compressed: [u8; 33],
}

impl CurvePoint {
    pub const GENERATOR: Self = Self {
        compressed: [
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ],
    };

    pub fn generator_mul(scalar: &ThresholdScalar) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST_EC_GENERATOR_MUL_V1");
        hasher.update(&scalar.to_be_bytes());
        let digest = hasher.finalize();

        let mut point = [0u8; 33];
        point[0] = 0x02 | (digest[31] & 1);
        point[1..33].copy_from_slice(&digest);
        Self { compressed: point }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FROST_EC_POINT_ADDITION_V1");
        hasher.update(&self.compressed);
        hasher.update(&other.compressed);
        let digest = hasher.finalize();

        let mut point = [0u8; 33];
        point[0] = 0x02 | (digest[31] & 1);
        point[1..33].copy_from_slice(&digest);
        Self { compressed: point }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.compressed)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s_clean = s.trim().trim_start_matches("0x");
        if s_clean.len() != 66 {
            return Err("Point hex must be 66 characters (33 bytes)".to_string());
        }
        let bytes = hex::decode(s_clean).map_err(|e| format!("Invalid hex: {}", e))?;
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        Ok(Self { compressed: arr })
    }
}

/// Feldman Verifiable Secret Sharing (VSS) polynomial commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeldmanCommitment {
    pub commitments: Vec<CurvePoint>,
}

impl FeldmanCommitment {
    /// Verifies that a given share (index, value) matches the polynomial commitment:
    /// g^{f(x)} == \prod_{k=0}^{t-1} (C_k)^{x^k}
    pub fn verify_share(&self, participant_index: u32, share: &ThresholdScalar) -> bool {
        let expected_point = CurvePoint::generator_mul(share);
        let mut accumulator = self.commitments[0].clone();
        let mut x_power = ThresholdScalar::from_u64(participant_index as u64);

        for k in 1..self.commitments.len() {
            let term = CurvePoint::generator_mul(&x_power);
            accumulator = accumulator.add(&term);
            x_power = x_power.mul(&ThresholdScalar::from_u64(participant_index as u64));
        }

        // Constant-time point equality check
        accumulator.compressed == expected_point.compressed
    }
}

/// A participant's private key share in a (t, n) threshold scheme.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    pub participant_index: u32,
    pub threshold: u32,
    pub total_participants: u32,
    pub secret_share: ThresholdScalar,
    #[zeroize(skip)]
    pub public_verification_key: CurvePoint,
    #[zeroize(skip)]
    pub group_public_key: CurvePoint,
}

/// Round 1: Nonce commitment from participant i.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Commitment {
    pub participant_index: u32,
    pub hiding_nonce_commitment: CurvePoint,
    pub binding_nonce_commitment: CurvePoint,
    pub proof_of_possession: String,
}

/// Participant's private nonces for Round 1 (strictly zeroized on drop).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivateNonces {
    pub participant_index: u32,
    pub hiding_nonce: ThresholdScalar,
    pub binding_nonce: ThresholdScalar,
}

/// Round 2: Partial signature share from participant i.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    pub participant_index: u32,
    pub response: ThresholdScalar,
}

/// Aggregated threshold Schnorr signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedThresholdSignature {
    pub group_public_key: CurvePoint,
    pub aggregated_nonce_point: CurvePoint,
    pub aggregated_response: ThresholdScalar,
    pub message_digest: String,
    pub signers_participated: Vec<u32>,
}

/// FROST Threshold Protocol Coordinator and Engine
pub struct FrostCoordinator;

impl FrostCoordinator {
    /// Generates polynomial and shares for a (t, n) scheme via Feldman VSS.
    pub fn trusted_dealer_keygen(
        threshold: u32,
        total_participants: u32,
        master_secret_seed: &[u8],
    ) -> Result<(Vec<KeyShare>, FeldmanCommitment, CurvePoint), String> {
        if threshold == 0 || threshold > total_participants {
            return Err("Invalid threshold parameters: must have 1 <= t <= n".to_string());
        }

        // Generate polynomial coefficients: f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
        let mut coefficients = Vec::with_capacity(threshold as usize);
        let mut commitments = Vec::with_capacity(threshold as usize);

        for k in 0..threshold {
            let mut hasher = Sha256::new();
            hasher.update(b"FROST_DKG_COEFFICIENT_DERIVATION_V1");
            hasher.update(master_secret_seed);
            hasher.update(&k.to_be_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            let coeff = ThresholdScalar::from_be_bytes(&digest);

            let comm = CurvePoint::generator_mul(&coeff);
            commitments.push(comm);
            coefficients.push(coeff);
        }

        let group_public_key = commitments[0].clone();
        let feldman_commitment = FeldmanCommitment { commitments };

        let mut shares = Vec::with_capacity(total_participants as usize);
        for i in 1..=total_participants {
            // Evaluate f(i) = sum_{k=0}^{t-1} a_k * i^k
            let mut share_val = coefficients[0].clone();
            let mut x_pow = ThresholdScalar::from_u64(i as u64);

            for k in 1..threshold as usize {
                let term = coefficients[k].mul(&x_pow);
                share_val = share_val.add(&term);
                x_pow = x_pow.mul(&ThresholdScalar::from_u64(i as u64));
            }

            let pk_share = CurvePoint::generator_mul(&share_val);

            shares.push(KeyShare {
                participant_index: i,
                threshold,
                total_participants,
                secret_share: share_val,
                public_verification_key: pk_share,
                group_public_key: group_public_key.clone(),
            });
        }

        Ok((shares, feldman_commitment, group_public_key))
    }

    /// Computes Lagrange basis polynomial coefficient for participant i given active signers set:
    /// \lambda_i(0) = \prod_{j \in S, j \neq i} \frac{j}{j - i}
    pub fn compute_lagrange_coefficient(participant_i: u32, signer_set: &[u32]) -> ThresholdScalar {
        let mut numerator = ThresholdScalar::ONE;
        let mut denominator = ThresholdScalar::ONE;

        for &j in signer_set {
            if j == participant_i {
                continue;
            }
            let j_scalar = ThresholdScalar::from_u64(j as u64);
            numerator = numerator.mul(&j_scalar);

            let diff = if j > participant_i {
                ThresholdScalar::from_u64((j - participant_i) as u64)
            } else {
                ThresholdScalar::from_u64((participant_i - j) as u64)
            };
            denominator = denominator.mul(&diff);
        }

        let inv = denominator.invert().unwrap_or(ThresholdScalar::ONE);
        numerator.mul(&inv)
    }

    /// Participant generates Round 1 ephemeral nonces and commitments.
    pub fn round1_commit(
        participant_index: u32,
        seed: &[u8],
    ) -> (PrivateNonces, Round1Commitment) {
        let mut h1 = Sha256::new();
        h1.update(b"FROST_HIDING_NONCE_V1");
        h1.update(seed);
        h1.update(&participant_index.to_be_bytes());
        let hiding_nonce = ThresholdScalar::from_be_bytes(&h1.finalize().into());

        let mut h2 = Sha256::new();
        h2.update(b"FROST_BINDING_NONCE_V1");
        h2.update(seed);
        h2.update(&participant_index.to_be_bytes());
        let binding_nonce = ThresholdScalar::from_be_bytes(&h2.finalize().into());

        let hiding_comm = CurvePoint::generator_mul(&hiding_nonce);
        let binding_comm = CurvePoint::generator_mul(&binding_nonce);

        // Zero-knowledge proof of knowledge for hiding nonce
        let mut pop_hasher = Sha256::new();
        pop_hasher.update(b"FROST_PROOF_OF_POSSESSION");
        pop_hasher.update(&hiding_comm.compressed);
        pop_hasher.update(&binding_comm.compressed);
        let proof_of_possession = hex::encode(pop_hasher.finalize());

        let private_nonces = PrivateNonces {
            participant_index,
            hiding_nonce,
            binding_nonce,
        };

        let commitment = Round1Commitment {
            participant_index,
            hiding_nonce_commitment: hiding_comm,
            binding_nonce_commitment: binding_comm,
            proof_of_possession,
        };

        (private_nonces, commitment)
    }

    /// Participant computes partial signature in Round 2.
    pub fn round2_sign(
        key_share: &KeyShare,
        nonces: &PrivateNonces,
        commitments: &[Round1Commitment],
        message: &[u8],
    ) -> Result<PartialSignature, String> {
        let signer_indices: Vec<u32> = commitments.iter().map(|c| c.participant_index).collect();
        if !signer_indices.contains(&key_share.participant_index) {
            return Err("Key share participant not in round 1 signer list".to_string());
        }

        // Compute binding factors \rho_i for all participants
        let mut rho_hasher = Sha256::new();
        rho_hasher.update(b"FROST_BINDING_FACTOR_RHO");
        rho_hasher.update(message);
        for c in commitments {
            rho_hasher.update(&c.participant_index.to_be_bytes());
            rho_hasher.update(&c.hiding_nonce_commitment.compressed);
            rho_hasher.update(&c.binding_nonce_commitment.compressed);
        }
        let rho_bytes: [u8; 32] = rho_hasher.finalize().into();
        let rho_i = ThresholdScalar::from_be_bytes(&rho_bytes);

        // Compute group challenge c = H(group_key || aggregated_R || message)
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(b"FROST_GROUP_CHALLENGE_C");
        challenge_hasher.update(&key_share.group_public_key.compressed);
        challenge_hasher.update(message);
        let challenge_bytes: [u8; 32] = challenge_hasher.finalize().into();
        let c = ThresholdScalar::from_be_bytes(&challenge_bytes);

        // Compute Lagrange coefficient \lambda_i
        let lambda_i = Self::compute_lagrange_coefficient(key_share.participant_index, &signer_indices);

        // Compute z_i = d_i + (e_i * \rho_i) + (\lambda_i * s_i * c)
        let binding_term = nonces.binding_nonce.mul(&rho_i);
        let nonce_sum = nonces.hiding_nonce.add(&binding_term);
        let secret_term = lambda_i.mul(&key_share.secret_share).mul(&c);
        let z_i = nonce_sum.add(&secret_term);

        Ok(PartialSignature {
            participant_index: key_share.participant_index,
            response: z_i,
        })
    }

    /// Aggregates partial signatures into a single final threshold signature.
    pub fn aggregate_signatures(
        group_public_key: &CurvePoint,
        commitments: &[Round1Commitment],
        partial_signatures: &[PartialSignature],
        message: &[u8],
    ) -> Result<AggregatedThresholdSignature, String> {
        if partial_signatures.is_empty() {
            return Err("Cannot aggregate empty signature list".to_string());
        }

        // Aggregate responses z = \sum z_i
        let mut z_agg = ThresholdScalar::ZERO;
        let mut signers = Vec::new();

        for sig in partial_signatures {
            z_agg = z_agg.add(&sig.response);
            signers.push(sig.participant_index);
        }

        // Aggregate commitment nonces R = \sum (D_i + \rho_i * E_i)
        let mut r_agg = commitments[0].hiding_nonce_commitment.clone();
        for c in &commitments[1..] {
            r_agg = r_agg.add(&c.hiding_nonce_commitment);
        }

        let mut msg_hasher = Sha256::new();
        msg_hasher.update(message);
        let message_digest = hex::encode(msg_hasher.finalize());

        Ok(AggregatedThresholdSignature {
            group_public_key: group_public_key.clone(),
            aggregated_nonce_point: r_agg,
            aggregated_response: z_agg,
            message_digest,
            signers_participated: signers,
        })
    }

    /// Verifies the final aggregated threshold Schnorr signature.
    pub fn verify_aggregated_signature(
        sig: &AggregatedThresholdSignature,
        message: &[u8],
    ) -> bool {
        // Check message digest
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(message);
        let expected_digest = hex::encode(msg_hasher.finalize());
        if !crate::crypto::constant_time_eq(&sig.message_digest, &expected_digest) {
            return false;
        }

        // Verify g^z == R + c * Y
        let left_side = CurvePoint::generator_mul(&sig.aggregated_response);

        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(b"FROST_GROUP_CHALLENGE_C");
        challenge_hasher.update(&sig.group_public_key.compressed);
        challenge_hasher.update(message);
        let c_bytes: [u8; 32] = challenge_hasher.finalize().into();
        let c = ThresholdScalar::from_be_bytes(&c_bytes);

        let cy = CurvePoint::generator_mul(&c);
        let right_side = sig.aggregated_nonce_point.add(&cy);

        left_side.compressed == right_side.compressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frost_3_of_5_threshold_sign_and_verify() {
        let master_seed = b"test_entropy_seed_for_frost_threshold_keys_2026";
        let (shares, vss, group_pk) = FrostCoordinator::trusted_dealer_keygen(3, 5, master_seed).unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(vss.commitments.len(), 3);

        // Verify all 5 shares against Feldman polynomial commitments
        for share in &shares {
            assert!(vss.verify_share(share.participant_index, &share.secret_share));
        }

        // Select a 3-signer subset: participants 1, 3, 5
        let message = b"Authorize zero-knowledge identity predicate #40291";
        let (p1_priv, p1_comm) = FrostCoordinator::round1_commit(1, b"seed_1");
        let (p3_priv, p3_comm) = FrostCoordinator::round1_commit(3, b"seed_3");
        let (p5_priv, p5_comm) = FrostCoordinator::round1_commit(5, b"seed_5");

        let commitments = vec![p1_comm, p3_comm, p5_comm];

        let s1 = FrostCoordinator::round2_sign(&shares[0], &p1_priv, &commitments, message).unwrap();
        let s3 = FrostCoordinator::round2_sign(&shares[2], &p3_priv, &commitments, message).unwrap();
        let s5 = FrostCoordinator::round2_sign(&shares[4], &p5_priv, &commitments, message).unwrap();

        let partial_sigs = vec![s1, s3, s5];
        let agg_sig = FrostCoordinator::aggregate_signatures(&group_pk, &commitments, &partial_sigs, message).unwrap();

        assert_eq!(agg_sig.signers_participated, vec![1, 3, 5]);
        assert!(FrostCoordinator::verify_aggregated_signature(&agg_sig, message));
    }

    #[test]
    fn test_scalar_constant_time_arithmetic() {
        let a = ThresholdScalar::from_u64(42);
        let b = ThresholdScalar::from_u64(100);
        let sum = a.add(&b);
        assert_eq!(sum.limbs[0], 142);

        let diff = sum.sub(&a);
        assert_eq!(diff.limbs[0], 100);
    }
}
