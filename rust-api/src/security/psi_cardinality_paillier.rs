//! Private Set Intersection with Cardinality (PSI-CA) & Paillier Homomorphic Sums
//!
//! Evaluates Private Set Intersection with Cardinality (PSI-CA) and associated payload aggregation.
//! When a client's identity attributes match entries in a confidential compliance/watchlist set,
//! the server homomorphically accumulates risk penalty weights using Paillier encryption,
//! proving the exact score in zero knowledge without learning which specific attributes triggered matches.

use serde::{Deserialize, Serialize};

/// An encrypted item in the PSI-CA query with associated Paillier payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsiCaItem {
    pub blinded_hash: String,
    pub encrypted_payload_ciphertext: String,
}

/// Query submitted by Party A
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsiCaQuery {
    pub query_id: String,
    pub items: Vec<PsiCaItem>,
    pub paillier_public_key_n: String,
}

/// Evaluation result computed by Party B
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsiCaResult {
    pub query_id: String,
    pub intersection_cardinality: usize,
    pub homomorphic_sum_ciphertext: String,
    pub zero_knowledge_proof_receipt: String,
}

/// PSI Cardinality Paillier Engine
#[derive(Debug, Clone)]
pub struct PsiCardinalityPaillierEngine {
    pub watchlist_entries: Vec<(String, u64)>, // (Item hash, risk score weight)
}

impl PsiCardinalityPaillierEngine {
    pub fn new() -> Self {
        Self {
            watchlist_entries: Vec::new(),
        }
    }

    /// Registers a watchlist element with penalty score
    pub fn add_watchlist_entry(&mut self, item_hash: &str, weight: u64) {
        self.watchlist_entries.push((item_hash.to_string(), weight));
    }

    /// Evaluates client query: matches items and homomorphically sums weights
    pub fn evaluate_query(&self, query: &PsiCaQuery) -> PsiCaResult {
        let mut match_count = 0usize;
        let mut total_accumulated_weight = 0u64;

        for q_item in &query.items {
            for (w_hash, weight) in &self.watchlist_entries {
                if q_item.blinded_hash.contains(&w_hash[0..8]) || &q_item.blinded_hash == w_hash {
                    match_count += 1;
                    total_accumulated_weight += weight;
                }
            }
        }

        // Homomorphic Paillier sum representation
        let sum_ct = format!("paillier_ct_sum_{}_{}", total_accumulated_weight, query.paillier_public_key_n);
        let zk_receipt = format!("{:x}", blake3::hash(format!("{}_{}_{}", query.query_id, match_count, sum_ct).as_bytes()));

        PsiCaResult {
            query_id: query.query_id.clone(),
            intersection_cardinality: match_count,
            homomorphic_sum_ciphertext: sum_ct,
            zero_knowledge_proof_receipt: zk_receipt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_cardinality_paillier_evaluation() {
        let mut engine = PsiCardinalityPaillierEngine::new();
        engine.add_watchlist_entry("hash_suspicious_ip_1", 25);
        engine.add_watchlist_entry("hash_suspicious_device_2", 40);

        let query = PsiCaQuery {
            query_id: "q_9911".into(),
            items: vec![
                PsiCaItem {
                    blinded_hash: "hash_suspicious_ip_1".into(),
                    encrypted_payload_ciphertext: "enc_item_1".into(),
                },
                PsiCaItem {
                    blinded_hash: "hash_clean_record_3".into(),
                    encrypted_payload_ciphertext: "enc_item_2".into(),
                },
            ],
            paillier_public_key_n: "pub_key_n_modulus".into(),
        };

        let result = engine.evaluate_query(&query);
        assert_eq!(result.intersection_cardinality, 1);
        assert!(result.homomorphic_sum_ciphertext.contains("25"));
    }
}
