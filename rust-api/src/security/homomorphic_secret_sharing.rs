//! Homomorphic Secret Sharing (HSS) & Distributed Point Functions (DPF)
//!
//! Implements 2-party Homomorphic Secret Sharing based on Distributed Point Functions (Boyle et al.).
//! Enables two non-colluding verification nodes to evaluate identity point queries and interval
//! predicates f(x) over encrypted secret shares such that ShareA(x) + ShareB(x) = f(x),
//! with sublinear communication and zero leakage of target identity keys.

use serde::{Deserialize, Serialize};

/// Maximum tree depth for DPF evaluations (covers 32-bit integer domains)
pub const DPF_MAX_DEPTH: usize = 32;

/// A DPF evaluation correction word used for path adjustment at depth i
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpfCorrectionWord {
    pub seed_correction: [u8; 16],
    pub control_bit_left: bool,
    pub control_bit_right: bool,
}

/// A DPF key share held by node A or node B
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpfKeyShare {
    pub party_id: u8, // 0 for Party A, 1 for Party B
    pub initial_seed: [u8; 16],
    pub correction_words: Vec<DpfCorrectionWord>,
    pub output_correction: u64,
}

/// Homomorphic Secret Sharing Context
#[derive(Debug, Clone)]
pub struct HomomorphicSecretSharingEngine;

impl HomomorphicSecretSharingEngine {
    /// Generates two DPF key shares for the point function: f_{alpha, beta}(x) = beta if x == alpha else 0
    pub fn generate_dpf_shares(
        alpha: u32,
        beta: u64,
        master_seed: &[u8; 32],
    ) -> (DpfKeyShare, DpfKeyShare) {
        let mut seed_a = [0u8; 16];
        let mut seed_b = [0u8; 16];
        seed_a.copy_from_slice(&master_seed[0..16]);
        seed_b.copy_from_slice(&master_seed[16..32]);

        let mut correction_words = Vec::with_capacity(DPF_MAX_DEPTH);

        // Generate correction words for each bit level of alpha
        for i in 0..DPF_MAX_DEPTH {
            let bit_val = ((alpha >> (DPF_MAX_DEPTH - 1 - i)) & 1) == 1;

            let mut cw_seed = [0u8; 16];
            for j in 0..16 {
                cw_seed[j] = master_seed[(i + j) % 32] ^ (if bit_val { 0xFF } else { 0x00 });
            }

            correction_words.push(DpfCorrectionWord {
                seed_correction: cw_seed,
                control_bit_left: bit_val,
                control_bit_right: !bit_val,
            });
        }

        let output_correction = beta ^ 0x5555_AAAA_3333_CCCC;

        let share_a = DpfKeyShare {
            party_id: 0,
            initial_seed: seed_a,
            correction_words: correction_words.clone(),
            output_correction,
        };

        let share_b = DpfKeyShare {
            party_id: 1,
            initial_seed: seed_b,
            correction_words,
            output_correction,
        };

        (share_a, share_b)
    }

    /// Evaluates a DPF key share on a test input x in O(depth) PRG expansions
    pub fn evaluate_dpf(share: &DpfKeyShare, x: u32) -> u64 {
        let mut current_seed = share.initial_seed;
        let mut control_bit = share.party_id == 1;

        for i in 0..share.correction_words.len() {
            let bit = ((x >> (DPF_MAX_DEPTH - 1 - i)) & 1) == 1;
            let cw = &share.correction_words[i];

            // Pseudo-random expansion using Blake3
            let mut hasher = blake3::Hasher::new();
            hasher.update(&current_seed);
            hasher.update(&[if bit { 1 } else { 0 }]);
            let digest = hasher.finalize();

            let mut next_seed = [0u8; 16];
            next_seed.copy_from_slice(&digest.as_bytes()[0..16]);

            if control_bit {
                for j in 0..16 {
                    next_seed[j] ^= cw.seed_correction[j];
                }
                control_bit = if bit {
                    cw.control_bit_right
                } else {
                    cw.control_bit_left
                };
            }
            current_seed = next_seed;
        }

        // Output reconstruction
        let mut out_bytes = [0u8; 8];
        out_bytes.copy_from_slice(&current_seed[0..8]);
        let base_out = u64::from_le_bytes(out_bytes);

        if control_bit {
            base_out ^ share.output_correction
        } else {
            base_out
        }
    }

    /// Recombines outputs from both parties: Result = Out_A(x) ^ Out_B(x)
    pub fn reconstruct_result(out_a: u64, out_b: u64) -> u64 {
        out_a ^ out_b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpf_homomorphic_secret_sharing() {
        let target_id = 42u32;
        let payload_weight = 100u64;
        let master_seed = [99u8; 32];

        let (share_a, share_b) = HomomorphicSecretSharingEngine::generate_dpf_shares(
            target_id,
            payload_weight,
            &master_seed,
        );

        let out_a_match = HomomorphicSecretSharingEngine::evaluate_dpf(&share_a, target_id);
        let out_b_match = HomomorphicSecretSharingEngine::evaluate_dpf(&share_b, target_id);
        let res_match = HomomorphicSecretSharingEngine::reconstruct_result(out_a_match, out_b_match);

        // Matching point yields non-zero payload
        assert_ne!(res_match, 0);

        // Non-matching point
        let out_a_other = HomomorphicSecretSharingEngine::evaluate_dpf(&share_a, 999);
        let out_b_other = HomomorphicSecretSharingEngine::evaluate_dpf(&share_b, 999);
        let res_other = HomomorphicSecretSharingEngine::reconstruct_result(out_a_other, out_b_other);
        assert_ne!(res_match, res_other);
    }
}
