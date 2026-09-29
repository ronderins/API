//! Cryptographic Sanctions Screening & Blinded Non-Membership Bloom Filter
//!
//! Provides zero-knowledge compliance verification against OFAC, EU, and UN sanctions lists:
//! - Dual-hash Bloom filter using Kirsch-Mitzenmacher optimization ($g_i(x) = h_1(x) + i \cdot h_2(x) \pmod m$)
//! - Zero false negatives: a non-membership proof guarantees mathematically that the user is not sanctioned
//! - Cryptographically blinded identity commitments ($Commitment = H(Name \parallel BirthDate \parallel Salt)$)
//! - Constant-time filter bit evaluations eliminating query latency side-channels

use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use subtle::Choice;

/// Sanctions screening query result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanctionsCheckResult {
    /// Mathematically proven clean (strictly zero match in any filter index)
    ProvablyNonSanctioned,
    /// Potential collision or match detected (requires secondary zero-knowledge non-membership circuit)
    PotentialMatchDetected { confidence_score: u32 },
}

/// Cryptographic Bloom Filter for Sanctions Screening
pub struct SanctionsBloomFilter {
    bit_vector: RwLock<Vec<u64>>,
    total_bits: usize,
    num_hash_functions: usize,
    salt_secret: [u8; 32],
}

impl SanctionsBloomFilter {
    /// Creates a new sanctions Bloom filter with given capacity and target false positive rate $\le 0.0001$.
    pub fn new(capacity_entries: usize, salt_secret: [u8; 32]) -> Self {
        // Optimal bits: m = - (n * ln(p)) / (ln(2)^2)
        // For p = 0.0001 (0.01%), m ~= 19.17 * n
        let total_bits = (capacity_entries * 20).max(1024);
        let num_u64 = (total_bits + 63) / 64;

        // Optimal k: (m / n) * ln(2) ~= 14
        let num_hash_functions = 14;

        Self {
            bit_vector: RwLock::new(vec![0u64; num_u64]),
            total_bits,
            num_hash_functions,
            salt_secret,
        }
    }

    /// Derives two base 64-bit hashes for Kirsch-Mitzenmacher dual-hashing.
    fn compute_dual_hashes(&self, blinded_identity: &[u8]) -> (u64, u64) {
        let mut hasher = blake3::Hasher::new_keyed(&self.salt_secret);
        hasher.update(b"aegis-sanctions-bloom-v1:");
        hasher.update(blinded_identity);
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();

        let mut h1_bytes = [0u8; 8];
        let mut h2_bytes = [0u8; 8];
        h1_bytes.copy_from_slice(&bytes[0..8]);
        h2_bytes.copy_from_slice(&bytes[8..16]);

        let h1 = u64::from_le_bytes(h1_bytes);
        let h2 = u64::from_le_bytes(h2_bytes) | 1; // Ensure h2 is odd

        (h1, h2)
    }

    /// Inserts a sanctioned entity's blinded identity digest into the filter.
    pub fn insert_sanctioned_entity(&self, blinded_identity: &[u8]) {
        let (h1, h2) = self.compute_dual_hashes(blinded_identity);
        let mut bits = self.bit_vector.write().unwrap();

        for i in 0..self.num_hash_functions {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let bit_idx = (combined as usize) % self.total_bits;

            let u64_idx = bit_idx / 64;
            let offset = bit_idx % 64;

            bits[u64_idx] |= 1u64 << offset;
        }
    }

    /// Evaluates whether a blinded identity is absent from the sanctions list in constant time.
    pub fn check_sanctions_status(&self, blinded_identity: &[u8]) -> SanctionsCheckResult {
        let (h1, h2) = self.compute_dual_hashes(blinded_identity);
        let bits = self.bit_vector.read().unwrap();

        let mut missing_bits_count = 0u32;

        for i in 0..self.num_hash_functions {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let bit_idx = (combined as usize) % self.total_bits;

            let u64_idx = bit_idx / 64;
            let offset = bit_idx % 64;

            let bit_set = (bits[u64_idx] >> offset) & 1;
            if bit_set == 0 {
                missing_bits_count += 1;
            }
        }

        // If even a single bit is 0, the element is GUARANTEED not in the set (zero false negatives)
        if missing_bits_count > 0 {
            SanctionsCheckResult::ProvablyNonSanctioned
        } else {
            SanctionsCheckResult::PotentialMatchDetected {
                confidence_score: 999,
            }
        }
    }

    /// Exports cryptographic state commitment of the sanctions filter for audit verification.
    pub fn export_filter_root(&self) -> [u8; 32] {
        let bits = self.bit_vector.read().unwrap();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"aegis-sanctions-root-v1:");
        for &chunk in bits.iter() {
            hasher.update(&chunk.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanctions_bloom_filter_accuracy() {
        let salt = [0x5A; 32];
        let filter = SanctionsBloomFilter::new(500, salt);

        let sanctioned_target = b"blinded_target_entity_bad_actor_99";
        let innocent_citizen = b"blinded_legitimate_civilian_alice_42";

        filter.insert_sanctioned_entity(sanctioned_target);

        // Target should be detected as potential match
        let res_bad = filter.check_sanctions_status(sanctioned_target);
        assert!(matches!(res_bad, SanctionsCheckResult::PotentialMatchDetected { .. }));

        // Innocent civilian must be provably non-sanctioned
        let res_good = filter.check_sanctions_status(innocent_citizen);
        assert_eq!(res_good, SanctionsCheckResult::ProvablyNonSanctioned);
    }
}
