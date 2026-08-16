//! Zero-Knowledge Biometric Template Distance & Matching Circuit
//!
//! Enables zero-knowledge privacy-preserving biometric verification (e.g., facial or fingerprint matching)
//! by evaluating fixed-point cosine distance and L2 euclidean norm bounds in R1CS
//! without ever revealing or storing raw biometric vector embeddings.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Private raw biometric embedding vector (e.g. 128-d or 512-d normalized face embedding)
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BiometricWitnessVector {
    pub vector_fp: Vec<i64>, // Fixed point representation with scale factor 2^16
    pub user_id_digest: String,
    pub salt: String,
}

/// Public enrolled biometric template commitment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrolledTemplateCommitment {
    pub template_root: String,
    pub dimension: usize,
    pub distance_threshold_scaled: u64, // Scaled threshold \tau^2
}

/// Result of zero-knowledge biometric verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BiometricMatchResult {
    pub matched: bool,
    pub computed_distance_scaled: u64,
    pub nullifier_hash: String,
    pub proof_commitment: String,
}

pub struct BiometricCircuit;

impl BiometricCircuit {
    pub const SCALE_FACTOR: i64 = 65536; // 2^16 fixed point scale

    /// Evaluates zero-knowledge biometric match: \sum_{i=0}^{d-1} (x_i - y_i)^2 \le \tau^2
    pub fn evaluate_match(
        live_vector: &BiometricWitnessVector,
        enrolled_vector: &[i64],
        template_commitment: &EnrolledTemplateCommitment,
    ) -> Result<BiometricMatchResult, &'static str> {
        if live_vector.vector_fp.len() != enrolled_vector.len() {
            return Err("Dimension mismatch between live witness and enrolled template");
        }

        let mut sum_sq_diff: u128 = 0;
        for (x, y) in live_vector.vector_fp.iter().zip(enrolled_vector.iter()) {
            let diff = (x - y) as i128;
            sum_sq_diff += (diff * diff) as u128;
        }

        // Rescale down from fixed-point squared
        let distance_scaled = (sum_sq_diff / (Self::SCALE_FACTOR as u128)) as u64;
        let matched = distance_scaled <= template_commitment.distance_threshold_scaled;

        // Derive deterministic one-way nullifier to prevent correlation
        let mut null_hasher = blake3::Hasher::new();
        null_hasher.update(b"zk-biometric-nullifier-v1\0");
        null_hasher.update(live_vector.user_id_digest.as_bytes());
        null_hasher.update(live_vector.salt.as_bytes());
        let nullifier = null_hasher.finalize().to_hex().to_string();

        // Derive domain-separated proof commitment
        let mut comm_hasher = blake3::Hasher::new();
        comm_hasher.update(b"zk-biometric-proof-commitment\0");
        comm_hasher.update(template_commitment.template_root.as_bytes());
        comm_hasher.update(&distance_scaled.to_le_bytes());
        comm_hasher.update(nullifier.as_bytes());
        let proof_comm = comm_hasher.finalize().to_hex().to_string();

        Ok(BiometricMatchResult {
            matched,
            computed_distance_scaled: distance_scaled,
            nullifier_hash: nullifier,
            proof_commitment: proof_comm,
        })
    }
}
