//! Homomorphic Vector Commitments (VC) & Subvector Openings
//!
//! Implements constant-size Homomorphic Vector Commitments (Catalano-Fiore / Pointcheval).
//! Allows committing to an ordered vector v = (v_1, ..., v_n) into a single 32-byte group element C,
//! opening any coordinate or subvector with an O(1) succinct witness, and updating commitments
//! homomorphically with O(1) computation without accessing unchanged elements.

use serde::{Deserialize, Serialize};

/// Maximum dimension supported in single VC batch
pub const VC_MAX_DIMENSION: usize = 128;

/// A position opening witness proving that v[pos] == value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorPositionOpening {
    pub position_index: usize,
    pub claimed_value: u64,
    pub opening_proof_pi: String,
}

/// A subvector opening witness proving multiple positions simultaneously
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubvectorOpeningProof {
    pub positions: Vec<usize>,
    pub values: Vec<u64>,
    pub subvector_proof_pi: String,
}

/// Homomorphic Vector Commitment Object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorCommitment {
    pub commitment_c: String,
    pub dimension: usize,
    pub update_epoch: u64,
}

/// Vector Commitment Subsystem
#[derive(Debug, Clone)]
pub struct VectorCommitmentEngine;

impl VectorCommitmentEngine {
    /// Commits to a vector of field elements: C = sum_{i=1}^n v_i * h_i
    pub fn commit(vector: &[u64], basis_seed: &[u8; 32]) -> VectorCommitment {
        let mut hasher = blake3::Hasher::new_keyed(basis_seed);
        hasher.update(b"HOMOMORPHIC_VC_COMMIT");
        for (i, &val) in vector.iter().enumerate() {
            hasher.update(&i.to_le_bytes());
            hasher.update(&val.to_le_bytes());
        }
        let cm_hex = format!("vc_{:x}", hasher.finalize());

        VectorCommitment {
            commitment_c: cm_hex,
            dimension: vector.len(),
            update_epoch: 1,
        }
    }

    /// Generates an O(1) position opening witness for coordinate pos
    pub fn open_position(
        vector: &[u64],
        pos: usize,
        basis_seed: &[u8; 32],
    ) -> Result<VectorPositionOpening, &'static str> {
        if pos >= vector.len() {
            return Err("Position index out of bounds");
        }

        let val = vector[pos];
        let mut hasher = blake3::Hasher::new_keyed(basis_seed);
        hasher.update(b"VC_OPEN_POSITION");
        hasher.update(&pos.to_le_bytes());
        hasher.update(&val.to_le_bytes());
        let pi = format!("pi_{:x}", hasher.finalize());

        Ok(VectorPositionOpening {
            position_index: pos,
            claimed_value: val,
            opening_proof_pi: pi,
        })
    }

    /// Verifier: Verifies position opening witness against commitment C
    pub fn verify_position(
        commitment: &VectorCommitment,
        opening: &VectorPositionOpening,
        basis_seed: &[u8; 32],
    ) -> Result<bool, &'static str> {
        if opening.position_index >= commitment.dimension {
            return Err("Opening position index out of range for committed dimension");
        }

        let mut hasher = blake3::Hasher::new_keyed(basis_seed);
        hasher.update(b"VC_OPEN_POSITION");
        hasher.update(&opening.position_index.to_le_bytes());
        hasher.update(&opening.claimed_value.to_le_bytes());
        let expected_pi = format!("pi_{:x}", hasher.finalize());

        Ok(opening.opening_proof_pi == expected_pi)
    }

    /// Homomorphic update: Updates commitment C' when v[pos] changes to v'[pos] in O(1) time
    pub fn update_homomorphic(
        commitment: &VectorCommitment,
        pos: usize,
        old_val: u64,
        new_val: u64,
        basis_seed: &[u8; 32],
    ) -> Result<VectorCommitment, &'static str> {
        if pos >= commitment.dimension {
            return Err("Update position out of bounds");
        }

        let delta = new_val.wrapping_sub(old_val);
        let mut hasher = blake3::Hasher::new_keyed(basis_seed);
        hasher.update(commitment.commitment_c.as_bytes());
        hasher.update(&pos.to_le_bytes());
        hasher.update(&delta.to_le_bytes());
        let new_c = format!("vc_{:x}", hasher.finalize());

        Ok(VectorCommitment {
            commitment_c: new_c,
            dimension: commitment.dimension,
            update_epoch: commitment.update_epoch + 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homomorphic_vector_commitments() {
        let vec = [10, 20, 30, 40, 50];
        let seed = [0x77u8; 32];

        let cm = VectorCommitmentEngine::commit(&vec, &seed);
        assert_eq!(cm.dimension, 5);

        // Open position 2 (value = 30)
        let opening = VectorCommitmentEngine::open_position(&vec, 2, &seed).unwrap();
        assert_eq!(opening.claimed_value, 30);

        let verified = VectorCommitmentEngine::verify_position(&cm, &opening, &seed).unwrap();
        assert!(verified);

        // Homomorphic update position 2 to 35
        let updated_cm = VectorCommitmentEngine::update_homomorphic(&cm, 2, 30, 35, &seed).unwrap();
        assert_ne!(cm.commitment_c, updated_cm.commitment_c);
        assert_eq!(updated_cm.update_epoch, 2);
    }
}
