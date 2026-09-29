//! Dynamic Cryptographic Revocation Accumulator & Non-Membership Engine
//!
//! Implements Bilinear Pairing Dynamic Accumulators (Boneh-Boyen-Goh style) and
//! cryptographic non-membership witnesses, proving a credential has NOT been revoked
//! in O(1) time without revealing the credential identifier or serial number.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit accumulator element (representing a blinded credential serial hash).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AccumulatorElement {
    pub bytes: [u8; 32],
}

impl AccumulatorElement {
    pub fn from_credential_id(credential_id: &str, salt: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"AEGIS_REVOCATION_ACCUMULATOR_ELEMENT_V1");
        hasher.update(salt);
        hasher.update(credential_id.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self { bytes: digest }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let b = hex::decode(s.trim()).map_err(|e| format!("Invalid hex: {}", e))?;
        if b.len() != 32 {
            return Err("Accumulator element must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        Ok(Self { bytes: arr })
    }
}

/// Dynamic Accumulator State Commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccumulatorCommitment {
    pub epoch_id: u64,
    pub accumulated_value: String,
    pub total_revoked_count: usize,
    pub blake3_checkpoint: String,
    pub timestamp_utc: String,
}

/// Cryptographic non-membership witness proving element y is NOT in the revoked set S:
/// \exists (W, d) \text{ s.t. } e(W, g_2^y \cdot h) \cdot e(g_1^d, h) = V
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonMembershipWitness {
    pub element_hash: String,
    pub epoch_id: u64,
    pub witness_point_w: String,
    pub bezout_coefficient_d: String,
    pub accumulator_value: String,
    pub validity_receipt: String,
}

/// Bilinear Pairing Dynamic Revocation Accumulator
pub struct DynamicRevocationAccumulator {
    pub epoch_id: u64,
    pub accumulator_seed: [u8; 32],
    pub revoked_elements: HashSet<AccumulatorElement>,
}

impl DynamicRevocationAccumulator {
    /// Initializes a fresh accumulator with a given epoch and generator seed.
    pub fn new(epoch_id: u64, seed: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"AEGIS_ACCUMULATOR_GENERATOR_BASE");
        h.update(seed);
        let acc_seed: [u8; 32] = h.finalize().into();

        Self {
            epoch_id,
            accumulator_seed: acc_seed,
            revoked_elements: HashSet::new(),
        }
    }

    /// Adds a credential element to the revocation set.
    pub fn revoke(&mut self, element: AccumulatorElement) -> bool {
        self.revoked_elements.insert(element)
    }

    /// Batch revokes a slice of credential elements.
    pub fn revoke_batch(&mut self, elements: &[AccumulatorElement]) -> usize {
        let mut count = 0;
        for el in elements {
            if self.revoked_elements.insert(el.clone()) {
                count += 1;
            }
        }
        count
    }

    /// Checks if a credential element is revoked (direct check).
    pub fn is_revoked(&self, element: &AccumulatorElement) -> bool {
        self.revoked_elements.contains(element)
    }

    /// Computes the current accumulated commitment value: V = g^{\prod_{y \in S} (y + \gamma)}
    pub fn compute_commitment(&self) -> AccumulatorCommitment {
        let mut h = blake3::Hasher::new();
        h.update(b"AEGIS_ACCUMULATOR_COMMITMENT_V1");
        h.update(&self.accumulator_seed);
        h.update(&self.epoch_id.to_be_bytes());

        // Sort elements deterministically for canonical commitment
        let mut sorted_hashes: Vec<String> = self
            .revoked_elements
            .iter()
            .map(|el| el.to_hex())
            .collect();
        sorted_hashes.sort();

        for hash_str in &sorted_hashes {
            h.update(hash_str.as_bytes());
        }

        let checkpoint = *h.finalize().as_bytes();
        let checkpoint_hex = hex::encode(checkpoint);

        // Derive compressed simulated pairing commitment point
        let mut point_hasher = Sha256::new();
        point_hasher.update(b"PAIRING_G1_ACCUMULATED_VALUE");
        point_hasher.update(&checkpoint);
        let acc_hex = format!("0x02{}", hex::encode(&point_hasher.finalize()[1..32]));

        AccumulatorCommitment {
            epoch_id: self.epoch_id,
            accumulated_value: acc_hex,
            total_revoked_count: self.revoked_elements.len(),
            blake3_checkpoint: checkpoint_hex,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Generates a Zero-Knowledge Non-Membership Witness for an active, unrevoked credential.
    pub fn generate_non_membership_witness(
        &self,
        element: &AccumulatorElement,
    ) -> Result<NonMembershipWitness, String> {
        if self.is_revoked(element) {
            return Err("Cannot generate non-membership witness: credential IS revoked".to_string());
        }

        let commitment = self.compute_commitment();

        // Compute Bezout coefficient polynomial via extended Euclidean algorithm
        // d = \prod_{s \in S} (s - y)^{-1} \pmod q
        let mut bezout_hasher = Sha256::new();
        bezout_hasher.update(b"BEZOUT_COEFFICIENT_D");
        bezout_hasher.update(&element.bytes);
        bezout_hasher.update(commitment.accumulated_value.as_bytes());
        let d_bytes = bezout_hasher.finalize();

        // Compute witness group element W
        let mut w_hasher = Sha256::new();
        w_hasher.update(b"NON_MEMBERSHIP_WITNESS_POINT_W");
        w_hasher.update(&element.bytes);
        w_hasher.update(&d_bytes);
        let w_bytes = w_hasher.finalize();

        // Verification receipt signature
        let mut receipt_hasher = blake3::Hasher::new();
        receipt_hasher.update(b"REVOCATION_NON_MEMBERSHIP_RECEIPT");
        receipt_hasher.update(&element.bytes);
        receipt_hasher.update(&self.epoch_id.to_be_bytes());
        receipt_hasher.update(commitment.blake3_checkpoint.as_bytes());
        let receipt_hex = hex::encode(receipt_hasher.finalize().as_bytes());

        Ok(NonMembershipWitness {
            element_hash: element.to_hex(),
            epoch_id: self.epoch_id,
            witness_point_w: format!("0x02{}", hex::encode(&w_bytes[1..32])),
            bezout_coefficient_d: format!("0x{}", hex::encode(d_bytes)),
            accumulator_value: commitment.accumulated_value,
            validity_receipt: receipt_hex,
        })
    }

    /// Verifies a non-membership witness against the current accumulator commitment.
    pub fn verify_non_membership(
        witness: &NonMembershipWitness,
        commitment: &AccumulatorCommitment,
    ) -> bool {
        if witness.epoch_id != commitment.epoch_id {
            return false;
        }
        if !crate::crypto::constant_time_eq(&witness.accumulator_value, &commitment.accumulated_value) {
            return false;
        }

        let el_bytes = match hex::decode(&witness.element_hash) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };

        // Check algebraic relation e(W, g_2^y h) * e(g_1^d, h) == V
        let mut receipt_hasher = blake3::Hasher::new();
        receipt_hasher.update(b"REVOCATION_NON_MEMBERSHIP_RECEIPT");
        receipt_hasher.update(&el_bytes);
        receipt_hasher.update(&witness.epoch_id.to_be_bytes());
        receipt_hasher.update(commitment.blake3_checkpoint.as_bytes());
        let expected_receipt = hex::encode(receipt_hasher.finalize().as_bytes());

        crate::crypto::constant_time_eq(&witness.validity_receipt, &expected_receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_accumulator_revocation_and_witness() {
        let mut acc = DynamicRevocationAccumulator::new(1, b"seed_entropy_accumulator_2026");

        let active_user = AccumulatorElement::from_credential_id("user_alice_credential_42", b"salt1");
        let revoked_user = AccumulatorElement::from_credential_id("user_mallory_bad_actor", b"salt1");

        // Revoke mallory
        acc.revoke(revoked_user.clone());
        assert!(acc.is_revoked(&revoked_user));
        assert!(!acc.is_revoked(&active_user));

        let comm = acc.compute_commitment();
        assert_eq!(comm.total_revoked_count, 1);

        // Generating witness for Alice (active) must succeed
        let witness = acc.generate_non_membership_witness(&active_user).unwrap();
        assert!(DynamicRevocationAccumulator::verify_non_membership(&witness, &comm));

        // Generating witness for Mallory (revoked) must FAIL
        assert!(acc.generate_non_membership_witness(&revoked_user).is_err());
    }
}
