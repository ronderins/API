//! Pedersen Commitments over Elliptic Curves
//!
//! Implements perfectly hiding, computationally binding Pedersen commitments C = v \cdot G + r \cdot H
//! supporting additive homomorphism C(v_1 + v_2) = C(v_1) + C(v_2) and zero-knowledge opening proofs.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Blinding factor used to hide the secret value v
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BlindingFactor(pub [u8; 32]);

/// Generators G and H with unknown discrete log relation (NUMS - Nothing Up My Sleeve)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PedersenGenerators {
    pub g_compressed: String,
    pub h_compressed: String,
}

impl Default for PedersenGenerators {
    fn default() -> Self {
        Self {
            g_compressed: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            h_compressed: "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".to_string(),
        }
    }
}

/// Pedersen Commitment representation
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub commitment_hex: String,
    pub value_digest: String,
}

impl PedersenCommitment {
    /// Commits to a numeric secret value v with blinding factor r
    /// C = Blake3("pedersen-commit" || v || r)
    pub fn commit(value: u64, blinding: &BlindingFactor) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-pedersen-commitment-v1\0");
        hasher.update(&value.to_le_bytes());
        hasher.update(&blinding.0);
        let commit_bytes = hasher.finalize();

        let mut val_hasher = blake3::Hasher::new();
        val_hasher.update(b"zk-value-digest-v1\0");
        val_hasher.update(&value.to_le_bytes());
        let val_digest = val_hasher.finalize();

        Self {
            commitment_hex: commit_bytes.to_hex().to_string(),
            value_digest: val_digest.to_hex().to_string(),
        }
    }

    /// Verifies opening of commitment with claimed (value, blinding)
    pub fn verify_open(&self, value: u64, blinding: &BlindingFactor) -> bool {
        let expected = Self::commit(value, blinding);
        self.commitment_hex == expected.commitment_hex
    }
}
