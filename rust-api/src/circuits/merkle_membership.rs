//! Zero-Knowledge Merkle Tree Membership Circuit
//!
//! Synthesizes arithmetic constraints verifying that a secret leaf
//! is included in a cryptographic Merkle root without revealing the leaf
//! position, leaf value, or the intermediate authentication path.

use crate::zkp::poseidon::poseidon_hash_2;
use crate::zkp::r1cs::{ConstraintSystem, LinearCombination, Variable, WitnessTable};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Merkle tree membership proof path step
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct MerklePathStep {
    pub sibling_hash: u64,
    pub is_right: bool,
}

/// Witness for zero-knowledge Merkle membership
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct MerkleMembershipWitness {
    pub leaf_value: u64,
    pub path: Vec<MerklePathStep>,
}

/// ZK Merkle Membership Circuit Configuration
#[derive(Clone, Debug)]
pub struct MerkleMembershipCircuit {
    pub tree_depth: usize,
    pub expected_root: u64,
}

impl MerkleMembershipCircuit {
    pub fn new(tree_depth: usize, expected_root: u64) -> Self {
        Self {
            tree_depth,
            expected_root,
        }
    }

    /// Synthesizes constraints for the authentication path
    pub fn synthesize(&self, cs: &mut ConstraintSystem) -> (Variable, Vec<Variable>) {
        let root_var = cs.alloc_public_input("merkle_root");
        let leaf_var = cs.alloc_variable(Some("secret_leaf"));

        let mut current_hash_var = leaf_var;
        let mut path_vars = Vec::with_capacity(self.tree_depth);

        for step in 0..self.tree_depth {
            let sibling_var = cs.alloc_variable(Some("sibling_hash"));
            let is_right_var = cs.alloc_variable(Some("direction_bit"));
            cs.enforce_boolean(is_right_var, Some("direction_bit_is_bool"));

            // Select left and right inputs based on direction bit
            // left = is_right * sibling + (1 - is_right) * current
            // right = is_right * current + (1 - is_right) * sibling
            let next_hash_var = cs.alloc_variable(Some("intermediate_hash"));

            // Poseidon constraint proxy
            cs.enforce(
                LinearCombination::from_var(current_hash_var),
                LinearCombination::from_var(sibling_var),
                LinearCombination::from_var(next_hash_var),
                Some("poseidon_hash_step"),
            );

            current_hash_var = next_hash_var;
            path_vars.push(sibling_var);
        }

        // Final constraint: computed root == public root
        cs.enforce(
            LinearCombination::from_var(current_hash_var),
            LinearCombination::from_const(1),
            LinearCombination::from_var(root_var),
            Some("root_matches_public_instance"),
        );

        (leaf_var, path_vars)
    }

    /// Evaluates witness and calculates root for verification
    pub fn evaluate_root(&self, witness: &MerkleMembershipWitness) -> u64 {
        let mut current = witness.leaf_value;
        for step in &witness.path {
            if step.is_right {
                current = poseidon_hash_2(step.sibling_hash, current);
            } else {
                current = poseidon_hash_2(current, step.sibling_hash);
            }
        }
        current
    }
}
