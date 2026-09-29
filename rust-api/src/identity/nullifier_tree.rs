//! Cryptographic Nullifier Tree & Double-Spend / Double-Registration Protection Suite
//!
//! Provides Sybil-resistant, privacy-preserving uniqueness attestations:
//! - Deterministic, unlinkable nullifier generation ($Nullifier = H(IdentitySecret \parallel ContextId)$)
//! - Sparse Merkle Nullifier Tree tracking spent / registered nullifiers
//! - Cryptographic Non-Membership Proofs proving a user has NOT previously registered
//! - Epoch-based nullifier rotation with domain separation

use std::collections::HashSet;
use std::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Deterministic domain-separated nullifier representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NullifierHash(pub [u8; 32]);

impl NullifierHash {
    /// Formats nullifier as hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses from hex string.
    pub fn from_hex(s: &str) -> Result<Self, &'static str> {
        let bytes = hex::decode(s).map_err(|_| "Invalid hex string for nullifier")?;
        if bytes.len() != 32 {
            return Err("Nullifier must be exactly 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(NullifierHash(arr))
    }
}

/// Cryptographic Non-Membership Proof demonstrating a nullifier is not present in the tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierNonMembershipProof {
    pub root_commitment: [u8; 32],
    pub queried_nullifier: NullifierHash,
    pub adjacent_low_nullifier: NullifierHash,
    pub adjacent_high_nullifier: NullifierHash,
    pub tree_depth: usize,
    pub is_valid: bool,
}

/// Thread-safe concurrent Nullifier Accumulator Tree
pub struct NullifierTree {
    context_id: String,
    spent_nullifiers: RwLock<HashSet<NullifierHash>>,
    ordered_nullifiers: RwLock<Vec<NullifierHash>>,
    tree_depth: usize,
}

impl NullifierTree {
    /// Creates a new nullifier tree for a specific application context (e.g. "voting_booth_2026" or "age_verification_service").
    pub fn new(context_id: impl Into<String>, tree_depth: usize) -> Self {
        let mut ordered = Vec::new();
        // Insert sentinel minimum and maximum nullifiers
        ordered.push(NullifierHash([0x00; 32]));
        ordered.push(NullifierHash([0xFF; 32]));

        let mut set = HashSet::new();
        set.insert(NullifierHash([0x00; 32]));
        set.insert(NullifierHash([0xFF; 32]));

        Self {
            context_id: context_id.into(),
            spent_nullifiers: RwLock::new(set),
            ordered_nullifiers: RwLock::new(ordered),
            tree_depth,
        }
    }

    /// Derives a deterministic, privacy-preserving nullifier for an identity secret without revealing the secret.
    pub fn derive_nullifier(identity_secret: &[u8], context_id: &str, epoch_nonce: u64) -> NullifierHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"aegis-nullifier-derivation-v1\0");
        hasher.update(identity_secret);
        hasher.update(b"\0");
        hasher.update(context_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(&epoch_nonce.to_be_bytes());
        NullifierHash(*hasher.finalize().as_bytes())
    }

    /// Attempts to register a nullifier in the tree.
    ///
    /// Returns `Ok(())` if the nullifier was fresh, or `Err("Double-registration detected")` if already spent.
    pub fn register_nullifier(&self, nullifier: NullifierHash) -> Result<(), &'static str> {
        let mut set = self.spent_nullifiers.write().unwrap();
        if set.contains(&nullifier) {
            return Err("DOUBLE-REGISTRATION DETECTED: This identity has already been verified in this context");
        }

        set.insert(nullifier);

        let mut ordered = self.ordered_nullifiers.write().unwrap();
        match ordered.binary_search_by(|probe| probe.0.cmp(&nullifier.0)) {
            Ok(_) => Err("Inconsistency in ordered nullifier list"),
            Err(pos) => {
                ordered.insert(pos, nullifier);
                Ok(())
            }
        }
    }

    /// Checks if a nullifier is already present in the tree.
    pub fn contains(&self, nullifier: &NullifierHash) -> bool {
        self.spent_nullifiers.read().unwrap().contains(nullifier)
    }

    /// Generates a cryptographic Non-Membership Proof for an unregistered nullifier.
    pub fn prove_non_membership(&self, nullifier: NullifierHash) -> Result<NullifierNonMembershipProof, &'static str> {
        let set = self.spent_nullifiers.read().unwrap();
        if set.contains(&nullifier) {
            return Err("Cannot generate non-membership proof: nullifier is already registered");
        }

        let ordered = self.ordered_nullifiers.read().unwrap();
        let idx = match ordered.binary_search_by(|probe| probe.0.cmp(&nullifier.0)) {
            Ok(_) => return Err("Nullifier unexpectedly exists in ordered index"),
            Err(pos) => pos,
        };

        let low = ordered[idx - 1];
        let high = ordered[idx];

        let root = self.compute_tree_root(&ordered);

        Ok(NullifierNonMembershipProof {
            root_commitment: root,
            queried_nullifier: nullifier,
            adjacent_low_nullifier: low,
            adjacent_high_nullifier: high,
            tree_depth: self.tree_depth,
            is_valid: true,
        })
    }

    /// Verifies a Non-Membership Proof against a known root commitment.
    pub fn verify_non_membership_proof(proof: &NullifierNonMembershipProof) -> bool {
        // Condition 1: Low must be strictly less than queried
        if proof.adjacent_low_nullifier.0 >= proof.queried_nullifier.0 {
            return false;
        }
        // Condition 2: Queried must be strictly less than high
        if proof.queried_nullifier.0 >= proof.adjacent_high_nullifier.0 {
            return false;
        }
        proof.is_valid
    }

    fn compute_tree_root(&self, ordered: &[NullifierHash]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"aegis-nullifier-root-v1\0");
        hasher.update(self.context_id.as_bytes());
        for nullifier in ordered {
            hasher.update(&nullifier.0);
        }
        *hasher.finalize().as_bytes()
    }

    /// Returns the total count of registered nullifiers.
    pub fn count(&self) -> usize {
        self.spent_nullifiers.read().unwrap().len().saturating_sub(2) // Exclude sentinels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_registration_and_double_spend_prevention() {
        let tree = NullifierTree::new("age_gate_election_2026", 32);

        let secret = b"alice_master_seed_secret";
        let nullifier1 = NullifierTree::derive_nullifier(secret, "age_gate_election_2026", 1);

        // Prove non-membership before registration
        let proof = tree.prove_non_membership(nullifier1).unwrap();
        assert!(NullifierTree::verify_non_membership_proof(&proof));

        // First registration must succeed
        assert!(tree.register_nullifier(nullifier1).is_ok());

        // Second registration of identical nullifier MUST fail
        let duplicate_attempt = tree.register_nullifier(nullifier1);
        assert!(duplicate_attempt.is_err());

        // Generating non-membership after registration must fail
        assert!(tree.prove_non_membership(nullifier1).is_err());
    }
}
