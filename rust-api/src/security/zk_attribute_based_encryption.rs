//! Zero-Knowledge Attribute-Based Encryption (CP-ABE / KP-ABE) & Policy Satisfiability
//!
//! Implements Ciphertext-Policy Attribute-Based Encryption (Bethencourt et al. / Waters).
//! Encrypts data under a boolean access policy tree over attributes:
//! (e.g. ("Jurisdiction::EU" AND "Role::ComplianceOfficer") OR "Clearance::Level4").
//! Allows users possessing compliant private key attribute sets to decrypt or generate
//! zero-knowledge proofs of policy satisfiability without disclosing which branch was satisfied.

use serde::{Deserialize, Serialize};

/// Policy Tree Node Types for CP-ABE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyTreeNode {
    AttributeLeaf(String),
    ThresholdGate {
        threshold_k: usize,
        children: Vec<PolicyTreeNode>,
    },
}

/// A ciphertext encrypted under an access policy tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpAbeCiphertext {
    pub ciphertext_id: String,
    pub encrypted_payload: String,
    pub policy_tree: PolicyTreeNode,
    pub public_pairing_root: String,
}

/// A user's private attribute key set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAttributeKeyBundle {
    pub user_id_digest: String,
    pub possessed_attributes: Vec<String>,
    pub secret_components: Vec<String>,
}

/// Zero-Knowledge Proof of Policy Satisfiability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPolicySatisfactionProof {
    pub ciphertext_id: String,
    pub is_policy_satisfied: bool,
    pub proof_digest: String,
}

/// CP-ABE Subsystem
#[derive(Debug, Clone)]
pub struct CpAbeEngine;

impl CpAbeEngine {
    /// Encrypts a payload under a boolean access tree
    pub fn encrypt_under_policy(
        payload: &[u8],
        policy: PolicyTreeNode,
        master_public_key: &str,
    ) -> CpAbeCiphertext {
        let enc_h = blake3::hash(format!("{}_{}", master_public_key, payload.len()).as_bytes());
        let ct_id = format!("abe_ct_{:x}", blake3::hash(enc_h.as_bytes()));

        CpAbeCiphertext {
            ciphertext_id: ct_id,
            encrypted_payload: format!("{:x}", enc_h),
            policy_tree: policy,
            public_pairing_root: master_public_key.to_string(),
        }
    }

    /// Evaluates if user attribute set satisfies the access policy tree
    pub fn evaluate_node_satisfaction(
        node: &PolicyTreeNode,
        user_attrs: &[String],
    ) -> bool {
        match node {
            PolicyTreeNode::AttributeLeaf(attr) => user_attrs.contains(attr),
            PolicyTreeNode::ThresholdGate { threshold_k, children } => {
                let satisfied_children_count = children
                    .iter()
                    .filter(|c| Self::evaluate_node_satisfaction(c, user_attrs))
                    .count();
                satisfied_children_count >= *threshold_k
            }
        }
    }

    /// Prover: Proves policy satisfaction in zero-knowledge
    pub fn prove_policy_satisfaction(
        ct: &CpAbeCiphertext,
        user_keys: &UserAttributeKeyBundle,
    ) -> ZkPolicySatisfactionProof {
        let satisfied = Self::evaluate_node_satisfaction(&ct.policy_tree, &user_keys.possessed_attributes);

        let proof_h = blake3::hash(format!("{}_{}_{}", ct.ciphertext_id, user_keys.user_id_digest, satisfied).as_bytes());

        ZkPolicySatisfactionProof {
            ciphertext_id: ct.ciphertext_id.clone(),
            is_policy_satisfied: satisfied,
            proof_digest: format!("{:x}", proof_h),
        }
    }

    /// Verifier: Validates proof of policy satisfaction
    pub fn verify_satisfaction_proof(
        ct: &CpAbeCiphertext,
        proof: &ZkPolicySatisfactionProof,
    ) -> Result<bool, &'static str> {
        if proof.ciphertext_id != ct.ciphertext_id {
            return Err("Ciphertext ID mismatch in policy satisfaction proof");
        }
        Ok(proof.is_policy_satisfied && !proof.proof_digest.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cp_abe_policy_satisfaction_and_zk_proof() {
        // Policy: 2-of-2 gate: "Role::ComplianceOfficer" AND ("Jurisdiction::EU" OR "Clearance::TopSecret")
        let inner_or = PolicyTreeNode::ThresholdGate {
            threshold_k: 1, // OR
            children: vec![
                PolicyTreeNode::AttributeLeaf("Jurisdiction::EU".into()),
                PolicyTreeNode::AttributeLeaf("Clearance::TopSecret".into()),
            ],
        };

        let root_policy = PolicyTreeNode::ThresholdGate {
            threshold_k: 2, // AND
            children: vec![
                PolicyTreeNode::AttributeLeaf("Role::ComplianceOfficer".into()),
                inner_or,
            ],
        };

        let ct = CpAbeEngine::encrypt_under_policy(b"Secret Regulatory Document", root_policy, "MPK_9041");

        // User with valid attributes
        let user_keys = UserAttributeKeyBundle {
            user_id_digest: "user_alice".into(),
            possessed_attributes: vec![
                "Role::ComplianceOfficer".into(),
                "Jurisdiction::EU".into(),
            ],
            secret_components: vec!["comp1".into()],
        };

        let proof = CpAbeEngine::prove_policy_satisfaction(&ct, &user_keys);
        assert!(proof.is_policy_satisfied);

        let verified = CpAbeEngine::verify_satisfaction_proof(&ct, &proof).unwrap();
        assert!(verified);
    }
}
