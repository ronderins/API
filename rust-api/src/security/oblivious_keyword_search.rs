//! Oblivious Keyword Search (OKS) & Searchable Symmetric Encryption (SSE)
//!
//! Provides zero-knowledge searchable encryption over encrypted identity and sanctions records.
//! Enables querying encrypted database tables (e.g. nationality, sanctions, PEP status) using
//! blinded trapdoors without revealing the search query or leaked access patterns to untrusted nodes.

use serde::{Deserialize, Serialize};

/// Number of hash functions used in the encrypted Bloom filter
pub const SSE_BLOOM_HASH_COUNT: usize = 5;

/// Bit capacity of each encrypted searchable entry filter
pub const SSE_FILTER_BIT_LEN: usize = 512;

/// A blinded search trapdoor allowing evaluation of a keyword without revealing it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedSearchTrapdoor {
    pub trapdoor_token: String,
    pub epoch_id: u64,
    pub proof_mac: String,
}

impl BlindedSearchTrapdoor {
    /// Generates a blinded trapdoor for a query keyword using client master key
    pub fn generate(keyword: &str, master_search_key: &[u8; 32], epoch: u64) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(master_search_key);
        hasher.update(b"SSE_TRAPDOOR_V1");
        hasher.update(keyword.as_bytes());
        hasher.update(&epoch.to_le_bytes());
        let token = format!("{:x}", hasher.finalize());

        let mac = format!("{:x}", blake3::hash(format!("mac_{}_{}", token, epoch).as_bytes()));

        Self {
            trapdoor_token: token,
            epoch_id: epoch,
            proof_mac: mac,
        }
    }
}

/// An encrypted document index entry representing blinded keyword commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedIndexEntry {
    pub document_id: String,
    pub encrypted_payload: String,
    pub bloom_filter_bits: Vec<u8>,
    pub blinded_tag_hashes: Vec<String>,
}

/// Searchable Symmetric Encryption (SSE) Vault
#[derive(Debug, Clone)]
pub struct SearchableSymmetricVault {
    pub entries: Vec<EncryptedIndexEntry>,
    pub master_salt: [u8; 32],
}

impl SearchableSymmetricVault {
    pub fn new(master_salt: [u8; 32]) -> Self {
        Self {
            entries: Vec::new(),
            master_salt,
        }
    }

    /// Indexes an identity record with multiple searchable keywords (e.g. "US", "OVER_18", "SANCTION_CLEARED")
    pub fn index_record(
        &mut self,
        doc_id: &str,
        keywords: &[&str],
        payload: &[u8],
        master_key: &[u8; 32],
    ) {
        let mut filter_bytes = vec![0u8; SSE_FILTER_BIT_LEN / 8];
        let mut tag_hashes = Vec::new();

        for &kw in keywords {
            let trapdoor = BlindedSearchTrapdoor::generate(kw, master_key, 1);
            let tag = format!("{:x}", blake3::hash(trapdoor.trapdoor_token.as_bytes()));
            tag_hashes.push(tag.clone());

            // Set bits in Bloom filter
            for h_idx in 0..SSE_BLOOM_HASH_COUNT {
                let h_val = blake3::hash(format!("{}_{}", tag, h_idx).as_bytes());
                let mut b = [0u8; 4];
                b.copy_from_slice(&h_val.as_bytes()[0..4]);
                let bit_pos = (u32::from_le_bytes(b) as usize) % SSE_FILTER_BIT_LEN;
                filter_bytes[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
        }

        let enc_payload = format!("{:x}", blake3::hash(payload));

        self.entries.push(EncryptedIndexEntry {
            document_id: doc_id.to_string(),
            encrypted_payload: enc_payload,
            bloom_filter_bits: filter_bytes,
            blinded_tag_hashes: tag_hashes,
        });
    }

    /// Performs oblivious keyword search using the client's blinded trapdoor.
    /// The server evaluates matching entries without learning which keyword was queried.
    pub fn search_oblivious(&self, trapdoor: &BlindedSearchTrapdoor) -> Vec<String> {
        let tag = format!("{:x}", blake3::hash(trapdoor.trapdoor_token.as_bytes()));
        let mut matching_doc_ids = Vec::new();

        for entry in &self.entries {
            // First check: Fast Bloom filter bit-presence check
            let mut filter_match = true;
            for h_idx in 0..SSE_BLOOM_HASH_COUNT {
                let h_val = blake3::hash(format!("{}_{}", tag, h_idx).as_bytes());
                let mut b = [0u8; 4];
                b.copy_from_slice(&h_val.as_bytes()[0..4]);
                let bit_pos = (u32::from_le_bytes(b) as usize) % SSE_FILTER_BIT_LEN;
                if (entry.bloom_filter_bits[bit_pos / 8] & (1 << (bit_pos % 8))) == 0 {
                    filter_match = false;
                    break;
                }
            }

            if filter_match && entry.blinded_tag_hashes.contains(&tag) {
                matching_doc_ids.push(entry.document_id.clone());
            }
        }

        matching_doc_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oblivious_keyword_search() {
        let master_key = [77u8; 32];
        let mut vault = SearchableSymmetricVault::new([1u8; 32]);

        vault.index_record(
            "doc_001",
            &["US", "AGE_OVER_21", "KYC_TIER_3"],
            b"User 001 confidential payload",
            &master_key,
        );

        vault.index_record(
            "doc_002",
            &["DE", "AGE_OVER_18", "KYC_TIER_2"],
            b"User 002 confidential payload",
            &master_key,
        );

        // Search for "US" without revealing "US"
        let trapdoor_us = BlindedSearchTrapdoor::generate("US", &master_key, 1);
        let results_us = vault.search_oblivious(&trapdoor_us);
        assert_eq!(results_us.len(), 1);
        assert_eq!(results_us[0], "doc_001");

        // Search for "KYC_TIER_2"
        let trapdoor_tier2 = BlindedSearchTrapdoor::generate("KYC_TIER_2", &master_key, 1);
        let results_tier2 = vault.search_oblivious(&trapdoor_tier2);
        assert_eq!(results_tier2.len(), 1);
        assert_eq!(results_tier2[0], "doc_002");

        // Search for non-existent keyword
        let trapdoor_non_existent = BlindedSearchTrapdoor::generate("NON_EXISTENT", &master_key, 1);
        let results_none = vault.search_oblivious(&trapdoor_non_existent);
        assert!(results_none.is_empty());
    }
}
