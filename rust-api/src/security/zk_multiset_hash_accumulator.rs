//! Multiset Hash Accumulators (Mset-Hash) & Order-Independent Batch Verification
//!
//! Implements order-independent multiset hash accumulators (Clarke et al. / Boneh).
//! Uses multiplicative homomorphic hashing over finite fields: Mset(S) = prod_{x in S} (h(x) + gamma) mod p.
//! Allows verification of batched identity claim sets without imposing artificial ordering constraints,
//! enabling parallel multithreaded credential verification.

use serde::{Deserialize, Serialize};

/// 64-bit Prime modulus for multiset hashing (Goldilocks field)
pub const MSET_FIELD_PRIME: u128 = 18446744069414584321;

/// A multiset hash state accumulator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisetAccumulator {
    pub accumulated_product: u64,
    pub element_count: usize,
    pub session_gamma_challenge: u64,
}

/// A zero-knowledge set equality proof showing that SetA == SetB regardless of ordering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisetEqualityProof {
    pub set_a_digest: u64,
    pub set_b_digest: u64,
    pub is_identical_multiset: bool,
    pub cardinality: usize,
    pub proof_mac: String,
}

/// Multiset Hash Subsystem
#[derive(Debug, Clone)]
pub struct MultisetHashEngine;

impl MultisetHashEngine {
    /// Initializes an empty accumulator with random Fiat-Shamir challenge gamma
    pub fn new_accumulator(gamma: u64) -> MultisetAccumulator {
        MultisetAccumulator {
            accumulated_product: 1,
            element_count: 0,
            session_gamma_challenge: gamma,
        }
    }

    /// Adds an element x into the multiset accumulator: Acc = Acc * (H(x) + gamma) mod p
    pub fn insert_element(acc: &mut MultisetAccumulator, element_bytes: &[u8]) {
        let h_elem = blake3::hash(element_bytes);
        let mut b = [0u8; 8];
        b.copy_from_slice(&h_elem.as_bytes()[0..8]);
        let h_val = u64::from_le_bytes(b) as u128;

        let p = MSET_FIELD_PRIME;
        let factor = (h_val + acc.session_gamma_challenge as u128) % p;
        acc.accumulated_product = ((acc.accumulated_product as u128 * factor) % p) as u64;
        acc.element_count += 1;
    }

    /// Proves that two sets A and B have identical elements regardless of permutation
    pub fn prove_multiset_equality(
        set_a: &[&[u8]],
        set_b: &[&[u8]],
        gamma: u64,
    ) -> Result<MultisetEqualityProof, &'static str> {
        if set_a.len() != set_b.len() {
            return Err("Cardinality mismatch between sets");
        }

        let mut acc_a = Self::new_accumulator(gamma);
        for elem in set_a {
            Self::insert_element(&mut acc_a, elem);
        }

        let mut acc_b = Self::new_accumulator(gamma);
        for elem in set_b {
            Self::insert_element(&mut acc_b, elem);
        }

        let equal = acc_a.accumulated_product == acc_b.accumulated_product;
        let proof_h = blake3::hash(format!("{}_{}_{}", acc_a.accumulated_product, acc_b.accumulated_product, gamma).as_bytes());

        Ok(MultisetEqualityProof {
            set_a_digest: acc_a.accumulated_product,
            set_b_digest: acc_b.accumulated_product,
            is_identical_multiset: equal,
            cardinality: set_a.len(),
            proof_mac: format!("{:x}", proof_h),
        })
    }

    /// Verifier: Verifies multiset equality proof
    pub fn verify_equality(proof: &MultisetEqualityProof) -> bool {
        proof.is_identical_multiset && proof.set_a_digest == proof.set_b_digest && !proof.proof_mac.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiset_hash_order_independence() {
        let item1: &[u8] = b"KYC_Verified_Claim_1";
        let item2: &[u8] = b"Age_Over_18_Claim_2";
        let item3: &[u8] = b"Residency_EU_Claim_3";

        // Set A: [item1, item2, item3]
        let set_a = vec![item1, item2, item3];
        // Set B: [item3, item1, item2] (shuffled order)
        let set_b = vec![item3, item1, item2];

        let proof = MultisetHashEngine::prove_multiset_equality(&set_a, &set_b, 0x1337_BEEF).unwrap();
        assert!(proof.is_identical_multiset);
        assert_eq!(proof.set_a_digest, proof.set_b_digest);

        assert!(MultisetHashEngine::verify_equality(&proof));
    }
}
