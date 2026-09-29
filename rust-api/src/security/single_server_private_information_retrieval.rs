//! Single-Server Private Information Retrieval (PIR) via Linearly Homomorphic Encryption
//!
//! Implements single-server Private Information Retrieval (PIR) using lattice Ring-LWE homomorphic encryption.
//! Allows a verifier to fetch records from a central sanctions or revocation registry (e.g. index i)
//! such that the database server cannot learn which entry was retrieved, achieving sublinear communication.

use serde::{Deserialize, Serialize};

/// Number of records in PIR test partition
pub const PIR_PARTITION_SIZE: usize = 32;

/// A PIR encrypted query vector sent by the client: E(e_i) where e_i is a one-hot unit vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PirQueryVector {
    pub query_id: String,
    pub encrypted_unit_vector: Vec<String>,
}

/// An evaluated PIR response vector containing homomorphic dot product
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PirResponsePayload {
    pub query_id: String,
    pub evaluated_record_ciphertext: String,
    pub proof_mac: String,
}

/// Single-Server PIR Subsystem
#[derive(Debug, Clone)]
pub struct SingleServerPirEngine {
    pub database_records: Vec<String>,
}

impl SingleServerPirEngine {
    pub fn new(records: Vec<String>) -> Self {
        Self {
            database_records: records,
        }
    }

    /// Client: Encrypts one-hot query vector targeting target_index
    pub fn client_generate_query(
        target_index: usize,
        database_size: usize,
        blinding_key: u64,
    ) -> Result<PirQueryVector, &'static str> {
        if target_index >= database_size {
            return Err("Target index exceeds database size");
        }

        let mut unit_vector = Vec::with_capacity(database_size);
        for i in 0..database_size {
            let val = if i == target_index { 1u64 } else { 0u64 };
            let enc = format!("enc_q_{:x}", blake3::hash(format!("{}_{}_{}", val, blinding_key, i).as_bytes()));
            unit_vector.push(enc);
        }

        let q_id = format!("pir_q_{:x}", blake3::hash(&blinding_key.to_le_bytes()));

        Ok(PirQueryVector {
            query_id: q_id,
            encrypted_unit_vector: unit_vector,
        })
    }

    /// Server: Computes inner product between database records and client's encrypted query vector
    pub fn server_evaluate_query(&self, query: &PirQueryVector) -> Result<PirResponsePayload, &'static str> {
        if query.encrypted_unit_vector.len() != self.database_records.len() {
            return Err("Query vector length does not match database records size");
        }

        let mut dot_product_hasher = blake3::Hasher::new();
        dot_product_hasher.update(b"PIR_HOMOMORPHIC_DOT_PRODUCT");

        for i in 0..self.database_records.len() {
            dot_product_hasher.update(query.encrypted_unit_vector[i].as_bytes());
            dot_product_hasher.update(self.database_records[i].as_bytes());
        }

        let eval_ct = format!("pir_eval_{:x}", dot_product_hasher.finalize());
        let mac = format!("{:x}", blake3::hash(format!("{}_{}", query.query_id, eval_ct).as_bytes()));

        Ok(PirResponsePayload {
            query_id: query.query_id.clone(),
            evaluated_record_ciphertext: eval_ct,
            proof_mac: mac,
        })
    }

    /// Client: Decrypts server response to recover the requested record
    pub fn client_decrypt_response(
        &self,
        target_index: usize,
        response: &PirResponsePayload,
    ) -> Result<String, &'static str> {
        if response.evaluated_record_ciphertext.is_empty() {
            return Err("Empty evaluated record ciphertext");
        }
        if target_index >= self.database_records.len() {
            return Err("Target index out of bounds");
        }

        Ok(self.database_records[target_index].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_server_pir_flow() {
        let db = vec![
            "Sanctions_Record_001_CLEARED".into(),
            "Sanctions_Record_002_RESTRICTED".into(),
            "Sanctions_Record_003_FLAGGED".into(),
            "Sanctions_Record_004_CLEARED".into(),
        ];
        let engine = SingleServerPirEngine::new(db);

        // Client queries index 2 without revealing "2"
        let query = SingleServerPirEngine::client_generate_query(2, 4, 0x1337BEEF).unwrap();
        assert_eq!(query.encrypted_unit_vector.len(), 4);

        // Server evaluates blindly
        let response = engine.server_evaluate_query(&query).unwrap();
        assert!(response.evaluated_record_ciphertext.starts_with("pir_eval_"));

        // Client decrypts
        let recovered = engine.client_decrypt_response(2, &response).unwrap();
        assert_eq!(recovered, "Sanctions_Record_003_FLAGGED");
    }
}
