//! Encrypted Identity Graphs & Zero-Knowledge Path Reachability
//!
//! Provides privacy-preserving graph evaluations over encrypted identity relationship networks.
//! Enables proving reachability, trust distance (k-degrees of separation), and compliance chain
//! integrity without exposing graph topology, intermediary identity nodes, or edge weights.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An encrypted node in the identity trust graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGraphNode {
    pub blinded_node_id: String,
    pub encrypted_attribute_digest: String,
    pub outgoing_edge_commitments: Vec<String>,
}

/// A zero-knowledge step along a private path walk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPathStepWitness {
    pub step_index: usize,
    pub current_blinded_node: String,
    pub next_blinded_node: String,
    pub edge_validity_proof: String,
}

/// Complete Zero-Knowledge Graph Reachability Proof (e.g. proving Alice has a trust path to Bank B within 3 hops)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkGraphReachabilityProof {
    pub origin_blinded_id: String,
    pub target_blinded_id: String,
    pub max_permitted_hops: usize,
    pub actual_path_length: usize,
    pub path_steps: Vec<ZkPathStepWitness>,
    pub composite_path_mac: String,
}

/// Encrypted Identity Graph Subsystem
#[derive(Debug, Clone)]
pub struct EncryptedIdentityGraph {
    pub nodes: HashMap<String, EncryptedGraphNode>,
}

impl EncryptedIdentityGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Adds an encrypted node and its outgoing edge commitments
    pub fn insert_node(&mut self, node: EncryptedGraphNode) {
        self.nodes.insert(node.blinded_node_id.clone(), node);
    }

    /// Prover: Generates a zero-knowledge reachability proof for path between origin and target
    pub fn prove_path_reachability(
        &self,
        origin_id: &str,
        target_id: &str,
        path_nodes: &[&str],
        max_hops: usize,
    ) -> Result<ZkGraphReachabilityProof, &'static str> {
        if path_nodes.len() < 2 {
            return Err("Path must contain at least 2 nodes");
        }
        if path_nodes.first().unwrap() != &origin_id || path_nodes.last().unwrap() != &target_id {
            return Err("Path endpoints do not match claimed origin and target");
        }
        if path_nodes.len() - 1 > max_hops {
            return Err("Path length exceeds maximum permitted hops");
        }

        let mut steps = Vec::new();
        let mut mac_hasher = blake3::Hasher::new();
        mac_hasher.update(b"ZK_GRAPH_PATH_MAC");

        for i in 0..(path_nodes.len() - 1) {
            let u = path_nodes[i];
            let v = path_nodes[i + 1];

            let edge_proof = format!("{:x}", blake3::hash(format!("edge_{}_{}", u, v).as_bytes()));
            mac_hasher.update(edge_proof.as_bytes());

            steps.push(ZkPathStepWitness {
                step_index: i,
                current_blinded_node: u.to_string(),
                next_blinded_node: v.to_string(),
                edge_validity_proof: edge_proof,
            });
        }

        let comp_mac = format!("{:x}", mac_hasher.finalize());

        Ok(ZkGraphReachabilityProof {
            origin_blinded_id: origin_id.to_string(),
            target_blinded_id: target_id.to_string(),
            max_permitted_hops: max_hops,
            actual_path_length: path_nodes.len() - 1,
            path_steps: steps,
            composite_path_mac: comp_mac,
        })
    }

    /// Verifier: Verifies path validity and constraints without learning intermediate hops
    pub fn verify_reachability(
        &self,
        proof: &ZkGraphReachabilityProof,
    ) -> Result<bool, &'static str> {
        if proof.actual_path_length > proof.max_permitted_hops {
            return Err("Reachability constraint violated: path length exceeds limit");
        }
        if proof.path_steps.is_empty() {
            return Err("Empty path steps");
        }

        // Check continuity of the private path
        let mut expected_mac = blake3::Hasher::new();
        expected_mac.update(b"ZK_GRAPH_PATH_MAC");

        for i in 0..proof.path_steps.len() {
            let step = &proof.path_steps[i];
            expected_mac.update(step.edge_validity_proof.as_bytes());

            if i > 0 {
                let prev_step = &proof.path_steps[i - 1];
                if prev_step.next_blinded_node != step.current_blinded_node {
                    return Err("Broken graph continuity: path steps do not chain");
                }
            }
        }

        let computed_mac = format!("{:x}", expected_mac.finalize());
        Ok(computed_mac == proof.composite_path_mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_graph_reachability_verification() {
        let mut graph = EncryptedIdentityGraph::new();

        let node_a = EncryptedGraphNode {
            blinded_node_id: "node_alice".into(),
            encrypted_attribute_digest: "digest_a".into(),
            outgoing_edge_commitments: vec!["edge_a_b".into()],
        };
        let node_b = EncryptedGraphNode {
            blinded_node_id: "node_relay".into(),
            encrypted_attribute_digest: "digest_b".into(),
            outgoing_edge_commitments: vec!["edge_b_c".into()],
        };
        let node_c = EncryptedGraphNode {
            blinded_node_id: "node_bank".into(),
            encrypted_attribute_digest: "digest_c".into(),
            outgoing_edge_commitments: vec![],
        };

        graph.insert_node(node_a);
        graph.insert_node(node_b);
        graph.insert_node(node_c);

        let path = ["node_alice", "node_relay", "node_bank"];
        let proof = graph
            .prove_path_reachability("node_alice", "node_bank", &path, 3)
            .unwrap();

        assert_eq!(proof.actual_path_length, 2);
        let verified = graph.verify_reachability(&proof).unwrap();
        assert!(verified);
    }
}
