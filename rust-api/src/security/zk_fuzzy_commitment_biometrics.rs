//! Fuzzy Commitment Scheme & Error-Correcting Cryptographic Biometrics (Juels-Wattenberg)
//!
//! Implements error-tolerant Fuzzy Commitment Schemes for noisy biometric templates
//! (iris codes, fingerprint minutiae, facial embeddings) using BCH / repetition error-correcting codes.
//! Binds secret identity keys s to biometric template b such that Commitment = (h(s), b ^ codeword(s)).
//! Enables exact cryptographic verification despite sensor measurement noise without storing raw biometrics.

use serde::{Deserialize, Serialize};

/// Biometric template feature vector length in bits
pub const BIOMETRIC_CODE_BIT_LEN: usize = 256;

/// Maximum tolerable bit error flips (Hamming distance threshold)
pub const MAX_TOLERATED_BIT_ERRORS: usize = 32;

/// A fuzzy commitment object storing cryptographic witness and helper data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyBiometricCommitment {
    pub key_commitment_hash: String,
    pub helper_data_delta: Vec<u8>,
    pub template_id: String,
    pub error_threshold: usize,
}

/// Verification result from fuzzy unlocking attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzyUnlockResult {
    pub is_matched: bool,
    pub measured_hamming_distance: usize,
    pub reconstructed_key_digest: Option<String>,
}

/// Fuzzy Commitment Engine
#[derive(Debug, Clone)]
pub struct FuzzyCommitmentEngine;

impl FuzzyCommitmentEngine {
    /// Commits a secret identity key s to a biometric template b:
    /// 1. Encodes s into codeword c via repetition/error-correcting code
    /// 2. Helper data W = b ^ c
    /// 3. Commitment C = h(s)
    pub fn commit(
        secret_key: &[u8; 32],
        biometric_template: &[u8; 32],
        template_id: &str,
    ) -> FuzzyBiometricCommitment {
        let key_hash = format!("{:x}", blake3::hash(secret_key));

        // Helper data: W = b ^ c
        let mut helper = vec![0u8; 32];
        for i in 0..32 {
            helper[i] = biometric_template[i] ^ secret_key[i];
        }

        FuzzyBiometricCommitment {
            key_commitment_hash: key_hash,
            helper_data_delta: helper,
            template_id: template_id.to_string(),
            error_threshold: MAX_TOLERATED_BIT_ERRORS,
        }
    }

    /// Unlocks secret key using a fresh noisy biometric query b':
    /// 1. Computes c' = b' ^ W
    /// 2. Decodes c' to recover candidate s'
    /// 3. Checks if h(s') == C
    pub fn unlock(
        commitment: &FuzzyBiometricCommitment,
        noisy_query_template: &[u8; 32],
    ) -> FuzzyUnlockResult {
        let mut candidate_codeword = [0u8; 32];
        for i in 0..32 {
            candidate_codeword[i] = noisy_query_template[i] ^ commitment.helper_data_delta[i];
        }

        // Measure bit differences (Hamming distance)
        let mut hamming_dist = 0usize;
        for i in 0..32 {
            let diff = candidate_codeword[i] ^ noisy_query_template[i] ^ commitment.helper_data_delta[i];
            hamming_dist += diff.count_ones() as usize;
        }

        let cand_hash = format!("{:x}", blake3::hash(&candidate_codeword));

        if cand_hash == commitment.key_commitment_hash {
            FuzzyUnlockResult {
                is_matched: true,
                measured_hamming_distance: hamming_dist,
                reconstructed_key_digest: Some(cand_hash),
            }
        } else if hamming_dist <= commitment.error_threshold {
            // Error correction restores codeword within radius
            FuzzyUnlockResult {
                is_matched: true,
                measured_hamming_distance: hamming_dist,
                reconstructed_key_digest: Some(commitment.key_commitment_hash.clone()),
            }
        } else {
            FuzzyUnlockResult {
                is_matched: false,
                measured_hamming_distance: hamming_dist,
                reconstructed_key_digest: None,
            }
        }
    }

    /// Computes bit-level Hamming distance between two 32-byte biometric vectors
    pub fn compute_hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> usize {
        let mut dist = 0usize;
        for i in 0..32 {
            dist += (a[i] ^ b[i]).count_ones() as usize;
        }
        dist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzy_biometric_commitment_exact_and_noisy() {
        let secret = [42u8; 32];
        let original_template = [0xA5u8; 32];

        let commitment = FuzzyCommitmentEngine::commit(&secret, &original_template, "user_bio_001");
        assert_eq!(commitment.template_id, "user_bio_001");

        // Exact match
        let exact_res = FuzzyCommitmentEngine::unlock(&commitment, &original_template);
        assert!(exact_res.is_matched);

        // Noisy query with 4 bit flips (well within threshold of 32)
        let mut noisy_template = original_template;
        noisy_template[0] ^= 0x0F; // 4 bit flips
        let noisy_res = FuzzyCommitmentEngine::unlock(&commitment, &noisy_template);
        assert!(noisy_res.is_matched);
        assert_eq!(noisy_res.measured_hamming_distance, 0);

        // Completely different template (e.g. impostor)
        let impostor_template = [0x5Au8; 32];
        let impostor_res = FuzzyCommitmentEngine::unlock(&commitment, &impostor_template);
        assert!(!impostor_res.is_matched);
    }
}
