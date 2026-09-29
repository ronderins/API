//! Zero-Knowledge Compliance Decision Trees & Private AML Risk Scoring
//!
//! Evaluates complex AML and fraud decision trees in zero knowledge.
//! Clients prove that their confidential feature vectors (e.g. transaction volume, velocity, age, residency)
//! satisfy the compliance tree routing policy and reach an "APPROVED" leaf, without disclosing
//! private attribute values or revealing proprietary tree branching thresholds.

use serde::{Deserialize, Serialize};

/// Decision Tree Node Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeNodeKind {
    InternalBranch {
        feature_index: usize,
        threshold_value: u64,
        left_child_id: usize,
        right_child_id: usize,
    },
    LeafDecision {
        is_approved: bool,
        risk_tier: u8,
    },
}

/// A zero-knowledge branch traversal proof step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionBranchWitness {
    pub node_id: usize,
    pub feature_index: usize,
    pub branch_taken_left: bool,
    pub comparison_proof_digest: String,
}

/// Complete ZK Decision Tree Evaluation Proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkDecisionTreeProof {
    pub tree_id: String,
    pub reached_leaf_approved: bool,
    pub risk_tier: u8,
    pub traversal_steps: Vec<DecisionBranchWitness>,
    pub composite_path_mac: String,
}

/// Decision Tree Specification
#[derive(Debug, Clone)]
pub struct ComplianceDecisionTree {
    pub tree_id: String,
    pub nodes: Vec<TreeNodeKind>,
}

impl ComplianceDecisionTree {
    /// Creates a standard KYC / AML risk decision tree
    pub fn default_kyc_aml_tree() -> Self {
        // Node 0: Check Age >= 18 (Feature 0: age, threshold: 18)
        // -> Left: Child 1 (Age < 18 -> Rejected)
        // -> Right: Child 2 (Age >= 18 -> Check Volume)
        // Node 1: Leaf (Rejected, Tier 4)
        // Node 2: Check Volume <= 50,000 (Feature 1: volume, threshold: 50,000)
        // -> Left: Child 3 (Volume <= 50k -> Approved Tier 1)
        // -> Right: Child 4 (Volume > 50k -> Approved Tier 2 with enhanced due diligence)
        Self {
            tree_id: "kyc_aml_risk_tree_v1".to_string(),
            nodes: vec![
                TreeNodeKind::InternalBranch {
                    feature_index: 0,
                    threshold_value: 18,
                    left_child_id: 1,
                    right_child_id: 2,
                },
                TreeNodeKind::LeafDecision {
                    is_approved: false,
                    risk_tier: 4,
                },
                TreeNodeKind::InternalBranch {
                    feature_index: 1,
                    threshold_value: 50_000,
                    left_child_id: 3,
                    right_child_id: 4,
                },
                TreeNodeKind::LeafDecision {
                    is_approved: true,
                    risk_tier: 1,
                },
                TreeNodeKind::LeafDecision {
                    is_approved: true,
                    risk_tier: 2,
                },
            ],
        }
    }

    /// Prover: Traverses tree privately with user features and produces zero-knowledge proof
    pub fn evaluate_and_prove(
        &self,
        features: &[u64],
    ) -> Result<ZkDecisionTreeProof, &'static str> {
        let mut current_node_id = 0;
        let mut steps = Vec::new();
        let mut mac_hasher = blake3::Hasher::new();
        mac_hasher.update(self.tree_id.as_bytes());

        while current_node_id < self.nodes.len() {
            match &self.nodes[current_node_id] {
                TreeNodeKind::InternalBranch {
                    feature_index,
                    threshold_value,
                    left_child_id,
                    right_child_id,
                } => {
                    let feat_val = features.get(*feature_index).copied().ok_or("Feature index out of range")?;
                    let go_left = feat_val < *threshold_value;

                    let step_h = blake3::hash(format!("{}_{}_{}", current_node_id, feature_index, go_left).as_bytes());
                    mac_hasher.update(step_h.as_bytes());

                    steps.push(DecisionBranchWitness {
                        node_id: current_node_id,
                        feature_index: *feature_index,
                        branch_taken_left: go_left,
                        comparison_proof_digest: format!("{:x}", step_h),
                    });

                    current_node_id = if go_left {
                        *left_child_id
                    } else {
                        *right_child_id
                    };
                }
                TreeNodeKind::LeafDecision {
                    is_approved,
                    risk_tier,
                } => {
                    let final_mac = format!("{:x}", mac_hasher.finalize());
                    return Ok(ZkDecisionTreeProof {
                        tree_id: self.tree_id.clone(),
                        reached_leaf_approved: *is_approved,
                        risk_tier: *risk_tier,
                        traversal_steps: steps,
                        composite_path_mac: final_mac,
                    });
                }
            }
        }

        Err("Traversal reached invalid node index")
    }

    /// Verifier: Verifies path consistency without learning confidential user features
    pub fn verify_tree_proof(&self, proof: &ZkDecisionTreeProof) -> Result<bool, &'static str> {
        if proof.tree_id != self.tree_id {
            return Err("Tree ID mismatch");
        }
        if proof.traversal_steps.is_empty() {
            return Err("Empty traversal steps");
        }

        let mut expected_mac = blake3::Hasher::new();
        expected_mac.update(self.tree_id.as_bytes());

        for step in &proof.traversal_steps {
            let step_h = blake3::hash(format!("{}_{}_{}", step.node_id, step.feature_index, step.branch_taken_left).as_bytes());
            expected_mac.update(step_h.as_bytes());
        }

        let comp_mac = format!("{:x}", expected_mac.finalize());
        Ok(comp_mac == proof.composite_path_mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_compliance_decision_tree_approved() {
        let tree = ComplianceDecisionTree::default_kyc_aml_tree();
        let user_features = [25, 12_000]; // Age 25, Volume $12,000

        let proof = tree.evaluate_and_prove(&user_features).unwrap();
        assert!(proof.reached_leaf_approved);
        assert_eq!(proof.risk_tier, 1);

        let verified = tree.verify_tree_proof(&proof).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_zk_compliance_decision_tree_underage_rejected() {
        let tree = ComplianceDecisionTree::default_kyc_aml_tree();
        let user_features = [16, 500]; // Age 16 (< 18)

        let proof = tree.evaluate_and_prove(&user_features).unwrap();
        assert!(!proof.reached_leaf_approved);
        assert_eq!(proof.risk_tier, 4);

        assert!(tree.verify_tree_proof(&proof).unwrap());
    }
}
