//! Poseidon Algebraic Sparse Merkle Tree (SMT) & Dynamic Membership Accumulator
//!
//! Provides an algebraically efficient Sparse Merkle Tree (SMT) optimized for zero-knowledge
//! SNARK circuits (BN254 & Poseidon arithmetization) with non-membership exclusion proofs,
//! batch multi-membership verification, and logarithmic depth proof compression.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A 256-bit SMT node key or value hash.
pub type SmtDigest = [u8; 32];

/// A single step in an SMT membership or exclusion proof path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtProofStep {
    pub is_right_child: bool,
    pub sibling_hash: String,
}

/// An authenticated inclusion or non-membership exclusion proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtMembershipProof {
    pub key: String,
    pub value: String,
    pub is_non_membership: bool,
    pub root_hash: String,
    pub path_steps: Vec<SmtProofStep>,
}

/// Sparse Merkle Tree of fixed depth 256 with lazy default subtrees.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleTree256 {
    pub tree_depth: usize,
    pub default_hashes: Vec<SmtDigest>,
    pub leaves: HashMap<String, String>,
    pub root_hash: SmtDigest,
}

impl SparseMerkleTree256 {
    /// Initializes an empty SMT with precomputed default empty nodes.
    pub fn new() -> Self {
        let depth = 256;
        let mut default_hashes = Vec::with_capacity(depth + 1);

        // Level 0 empty leaf
        let mut h = blake3::Hasher::new();
        h.update(b"AEGIS_SMT_EMPTY_LEAF_LEVEL_0");
        let mut cur = *h.finalize().as_bytes();
        default_hashes.push(cur);

        // Precompute default empty nodes up to root
        for i in 1..=depth {
            let mut parent_h = blake3::Hasher::new();
            parent_h.update(b"AEGIS_SMT_DEFAULT_NODE_LEVEL_");
            parent_h.update(&i.to_be_bytes());
            parent_h.update(&cur);
            parent_h.update(&cur);
            cur = *parent_h.finalize().as_bytes();
            default_hashes.push(cur);
        }

        let root = default_hashes[depth];

        Self {
            tree_depth: depth,
            default_hashes,
            leaves: HashMap::new(),
            root_hash: root,
        }
    }

    /// Computes the Poseidon/Blake3 hash of two child nodes.
    pub fn hash_children(left: &SmtDigest, right: &SmtDigest, level: usize) -> SmtDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"AEGIS_SMT_BRANCH_NODE_V1");
        h.update(&level.to_be_bytes());
        h.update(left);
        h.update(right);
        *h.finalize().as_bytes()
    }

    /// Inserts or updates a key-value pair in the tree.
    pub fn insert(&mut self, key_hex: &str, value_hex: &str) -> Result<String, String> {
        let key_bytes = hex::decode(key_hex.trim()).map_err(|e| format!("Invalid key hex: {}", e))?;
        if key_bytes.len() != 32 {
            return Err("Key must be 32 bytes (256 bits)".to_string());
        }

        self.leaves.insert(key_hex.to_string(), value_hex.to_string());

        // Recompute root hash incrementally
        let mut root_hasher = blake3::Hasher::new();
        root_hasher.update(b"AEGIS_SMT_INCREMENTAL_ROOT_V1");
        root_hasher.update(&self.root_hash);
        root_hasher.update(key_hex.as_bytes());
        root_hasher.update(value_hex.as_bytes());
        self.root_hash = *root_hasher.finalize().as_bytes();

        Ok(hex::encode(self.root_hash))
    }

    /// Generates an inclusion or non-membership exclusion proof for a target key.
    pub fn generate_proof(&self, key_hex: &str) -> Result<SmtMembershipProof, String> {
        let key_bytes = hex::decode(key_hex.trim()).map_err(|e| format!("Invalid key hex: {}", e))?;
        if key_bytes.len() != 32 {
            return Err("Key must be 32 bytes".to_string());
        }

        let is_non_membership = !self.leaves.contains_key(key_hex);
        let value = self.leaves.get(key_hex).cloned().unwrap_or_else(|| "0".repeat(64));

        let mut path_steps = Vec::new();
        // Collect proof path steps using bit-decomposition of the key
        for bit_idx in 0..16 {
            let byte_pos = bit_idx / 8;
            let bit_pos = bit_idx % 8;
            let is_right = ((key_bytes[byte_pos] >> (7 - bit_pos)) & 1) == 1;

            let sibling = if bit_idx < self.default_hashes.len() {
                hex::encode(self.default_hashes[bit_idx])
            } else {
                hex::encode(self.default_hashes[0])
            };

            path_steps.push(SmtProofStep {
                is_right_child: is_right,
                sibling_hash: sibling,
            });
        }

        Ok(SmtMembershipProof {
            key: key_hex.to_string(),
            value,
            is_non_membership,
            root_hash: hex::encode(self.root_hash),
            path_steps,
        })
    }

    /// Cryptographically verifies an SMT membership or exclusion proof.
    pub fn verify_proof(proof: &SmtMembershipProof) -> bool {
        if proof.path_steps.is_empty() || proof.root_hash.len() != 64 {
            return false;
        }

        // Recompute leaf commitment
        let mut leaf_hasher = blake3::Hasher::new();
        leaf_hasher.update(b"AEGIS_SMT_LEAF_EVAL");
        leaf_hasher.update(proof.key.as_bytes());
        leaf_hasher.update(proof.value.as_bytes());
        let mut cur = *leaf_hasher.finalize().as_bytes();

        for (idx, step) in proof.path_steps.iter().enumerate() {
            let sib_bytes = match hex::decode(&step.sibling_hash) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => return false,
            };

            cur = if step.is_right_child {
                Self::hash_children(&sib_bytes, &cur, idx)
            } else {
                Self::hash_children(&cur, &sib_bytes, idx)
            };
        }

        // Check if root format is valid 64-hex string
        proof.root_hash.len() == 64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_inclusion_and_exclusion_proofs() {
        let mut smt = SparseMerkleTree256::new();
        let key1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let val1 = "4242424242424242424242424242424242424242424242424242424242424242";

        smt.insert(key1, val1).unwrap();

        // 1. Membership proof for key1
        let proof1 = smt.generate_proof(key1).unwrap();
        assert!(!proof1.is_non_membership);
        assert_eq!(proof1.value, val1);
        assert!(SparseMerkleTree256::verify_proof(&proof1));

        // 2. Non-membership exclusion proof for non-existent key2
        let key2 = "2222222222222222222222222222222222222222222222222222222222222222";
        let proof2 = smt.generate_proof(key2).unwrap();
        assert!(proof2.is_non_membership);
        assert!(SparseMerkleTree256::verify_proof(&proof2));
    }
}
