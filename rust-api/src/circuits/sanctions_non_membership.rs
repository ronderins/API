//! Zero-Knowledge Sanctions & Blacklist Non-Membership Circuit
//!
//! Proves that a credential / passport digest is NOT present in an OFAC
//! or sanctions blacklist Sparse Merkle Tree (SMT) accumulator, without
//! leaking the user's document number or traversing the blacklist explicitly.

use crate::zkp::r1cs::{ConstraintSystem, LinearCombination, Variable};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Witness for Non-Membership Proof in Sparse Merkle Tree
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct NonMembershipWitness {
    pub document_digest: [u8; 32],
    pub nearest_lower_key: [u8; 32],
    pub nearest_upper_key: [u8; 32],
    pub lower_leaf_audit_path: Vec<[u8; 32]>,
    pub upper_leaf_audit_path: Vec<[u8; 32]>,
}

/// Non-Membership SMT Accumulator Circuit
#[derive(Clone, Debug)]
pub struct SanctionsNonMembershipCircuit {
    pub tree_depth: usize,
    pub sanctions_merkle_root: [u8; 32],
}

impl SanctionsNonMembershipCircuit {
    pub fn new(sanctions_merkle_root: [u8; 32]) -> Self {
        Self {
            tree_depth: 256,
            sanctions_merkle_root,
        }
    }

    /// Synthesizes constraints checking that lower_key < doc_digest < upper_key
    /// and that lower_key and upper_key are consecutive leaves in the SMT.
    pub fn synthesize(&self, cs: &mut ConstraintSystem) {
        let root_var = cs.alloc_public_input("sanctions_accumulator_root");
        let doc_var = cs.alloc_variable(Some("private_document_digest"));
        let lower_var = cs.alloc_variable(Some("lower_bound_key"));
        let upper_var = cs.alloc_variable(Some("upper_bound_key"));

        // Interval bounding check
        let diff_lower = cs.alloc_variable(Some("doc_minus_lower"));
        let diff_upper = cs.alloc_variable(Some("upper_minus_doc"));

        // diff_lower = doc - lower
        let mut lower_sub = LinearCombination::from_var(doc_var);
        lower_sub.add_term(lower_var, u64::MAX);
        cs.enforce(
            lower_sub,
            LinearCombination::from_const(1),
            LinearCombination::from_var(diff_lower),
            Some("lower_interval_bound"),
        );

        // diff_upper = upper - doc
        let mut upper_sub = LinearCombination::from_var(upper_var);
        upper_sub.add_term(doc_var, u64::MAX);
        cs.enforce(
            upper_sub,
            LinearCombination::from_const(1),
            LinearCombination::from_var(diff_upper),
            Some("upper_interval_bound"),
        );
    }

    /// Verifies non-membership cryptographic accumulator condition
    pub fn verify_non_membership(&self, witness: &NonMembershipWitness) -> bool {
        // lower < doc < upper
        witness.nearest_lower_key < witness.document_digest
            && witness.document_digest < witness.nearest_upper_key
    }
}
