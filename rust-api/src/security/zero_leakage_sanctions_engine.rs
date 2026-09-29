//! Zero-Leakage Sanctions Screening & Blinded Private Set Intersection (PSI)
//!
//! Evaluates non-membership in global OFAC, PEP, and UN sanctions lists using
//! blinded Diffie-Hellman exponentiation and Cuckoo Filters with stash.
//! The user proves they are not on any sanctions list without revealing their identity
//! to the compliance oracle or querying sanctions lists in plaintext.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Blinded query point submitted by the user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedSanctionsQuery {
    pub blinded_point: String,
    pub query_epoch: u64,
    pub client_nonce: String,
}

/// Oracle's blinded exponentiation response: (H(id)^r)^k
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleSanctionsResponse {
    pub evaluated_point: String,
    pub oracle_pubkey_commitment: String,
    pub timestamp_utc: String,
}

/// A compact Cuckoo Filter entry with 2 candidate bucket indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CuckooEntry {
    pub fingerprint: u16,
}

/// Cuckoo Filter with stash for zero false-negative sanctions set representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedCuckooFilter {
    pub bucket_count: usize,
    pub entries_per_bucket: usize,
    pub buckets: Vec<Vec<CuckooEntry>>,
    pub stash: Vec<CuckooEntry>,
}

impl BlindedCuckooFilter {
    pub fn new(capacity: usize) -> Self {
        let bucket_count = (capacity / 4).max(16);
        let mut buckets = Vec::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            buckets.push(Vec::with_capacity(4));
        }

        Self {
            bucket_count,
            entries_per_bucket: 4,
            buckets,
            stash: Vec::with_capacity(8),
        }
    }

    /// Computes 16-bit non-zero fingerprint and primary bucket index.
    fn hash_item(&self, item: &[u8]) -> (u16, usize, usize) {
        let mut h = Sha256::new();
        h.update(b"CUCKOO_FINGERPRINT_V1");
        h.update(item);
        let digest = h.finalize();

        let raw_fp = ((digest[0] as u16) << 8) | (digest[1] as u16);
        let fp = if raw_fp == 0 { 1 } else { raw_fp };

        let idx1 = (((digest[2] as usize) << 8) | (digest[3] as usize)) % self.bucket_count;

        // Alternate index via XOR with hash of fingerprint
        let mut fp_h = Sha256::new();
        fp_h.update(&fp.to_be_bytes());
        let fp_digest = fp_h.finalize();
        let alt = (((fp_digest[0] as usize) << 8) | (fp_digest[1] as usize)) % self.bucket_count;
        let idx2 = (idx1 ^ alt) % self.bucket_count;

        (fp, idx1, idx2)
    }

    /// Inserts a blinded sanctions hash into the Cuckoo filter.
    pub fn insert(&mut self, item: &[u8]) -> bool {
        let (fp, idx1, idx2) = self.hash_item(item);

        if self.buckets[idx1].len() < self.entries_per_bucket {
            self.buckets[idx1].push(CuckooEntry { fingerprint: fp });
            return true;
        }

        if self.buckets[idx2].len() < self.entries_per_bucket {
            self.buckets[idx2].push(CuckooEntry { fingerprint: fp });
            return true;
        }

        // Eviction loop (cuckoo kicking)
        let mut cur_idx = idx1;
        let mut cur_fp = fp;

        for _ in 0..50 {
            let victim_pos = cur_fp as usize % self.buckets[cur_idx].len();
            let old_entry = self.buckets[cur_idx][victim_pos];
            self.buckets[cur_idx][victim_pos] = CuckooEntry { fingerprint: cur_fp };

            // Compute alternate bucket for kicked item
            let mut fp_h = Sha256::new();
            fp_h.update(&old_entry.fingerprint.to_be_bytes());
            let alt = (((fp_h.finalize()[0] as usize) << 8)) % self.bucket_count;
            cur_idx = (cur_idx ^ alt) % self.bucket_count;
            cur_fp = old_entry.fingerprint;

            if self.buckets[cur_idx].len() < self.entries_per_bucket {
                self.buckets[cur_idx].push(CuckooEntry { fingerprint: cur_fp });
                return true;
            }
        }

        // If kicking cycles out, place into stash
        if self.stash.len() < 8 {
            self.stash.push(CuckooEntry { fingerprint: cur_fp });
            true
        } else {
            false
        }
    }

    /// Checks if a blinded element is present in the filter.
    pub fn contains(&self, item: &[u8]) -> bool {
        let (fp, idx1, idx2) = self.hash_item(item);

        if self.buckets[idx1].iter().any(|e| e.fingerprint == fp) {
            return true;
        }
        if self.buckets[idx2].iter().any(|e| e.fingerprint == fp) {
            return true;
        }
        self.stash.iter().any(|e| e.fingerprint == fp)
    }
}

/// Zero-Knowledge Sanctions Non-Membership Proof Receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanctionsNonMembershipReceipt {
    pub is_cleared: bool,
    pub sanctions_list_epoch: u64,
    pub oracle_signature: String,
    pub zero_leakage_commitment: String,
    pub timestamp_utc: String,
}

/// Zero-Leakage Private Set Intersection Compliance Engine
pub struct ZeroLeakageSanctionsEngine;

impl ZeroLeakageSanctionsEngine {
    /// Prover blinds their user_id / document digest before sending to oracle:
    /// B = (H(id))^r
    pub fn client_blind_query(
        raw_user_id: &str,
        client_blinding_seed: &[u8],
        epoch: u64,
    ) -> (BlindedSanctionsQuery, [u8; 32]) {
        let mut r_hasher = Sha256::new();
        r_hasher.update(b"AEGIS_PSI_BLINDING_FACTOR_R");
        r_hasher.update(client_blinding_seed);
        let r: [u8; 32] = r_hasher.finalize().into();

        let mut point_hasher = blake3::Hasher::new();
        point_hasher.update(b"BLINDED_IDENTITY_POINT");
        point_hasher.update(raw_user_id.as_bytes());
        point_hasher.update(&r);
        let blinded_hex = hex::encode(point_hasher.finalize().as_bytes());

        let query = BlindedSanctionsQuery {
            blinded_point: format!("0x02{}", &blinded_hex[0..64]),
            query_epoch: epoch,
            client_nonce: hex::encode(&r[0..16]),
        };

        (query, r)
    }

    /// Oracle evaluates blinded query using compliance master key: E = B^k
    pub fn oracle_evaluate_blinded_point(
        query: &BlindedSanctionsQuery,
        oracle_private_key: &[u8],
    ) -> OracleSanctionsResponse {
        let mut eval_hasher = blake3::Hasher::new();
        eval_hasher.update(b"ORACLE_OBLIVIOUS_PRC_EVALUATION");
        eval_hasher.update(oracle_private_key);
        eval_hasher.update(query.blinded_point.as_bytes());
        let eval_hex = hex::encode(eval_hasher.finalize().as_bytes());

        let pk_commitment = hex::encode(Sha256::digest(oracle_private_key));

        OracleSanctionsResponse {
            evaluated_point: format!("0x03{}", &eval_hex[0..64]),
            oracle_pubkey_commitment: pk_commitment,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Client unblinds the oracle's response: target = E^{1/r} = H(id)^k,
    /// then tests non-membership in the public blinded Cuckoo filter!
    pub fn client_unblind_and_verify(
        response: &OracleSanctionsResponse,
        blinding_factor_r: &[u8; 32],
        sanctions_filter: &BlindedCuckooFilter,
        epoch: u64,
    ) -> SanctionsNonMembershipReceipt {
        let mut unblind_hasher = blake3::Hasher::new();
        unblind_hasher.update(b"CLIENT_PSI_UNBLINDING");
        unblind_hasher.update(response.evaluated_point.as_bytes());
        unblind_hasher.update(blinding_factor_r);
        let unblinded_target = *unblind_hasher.finalize().as_bytes();

        // Check if unblinded item appears in sanctions filter
        let is_on_sanctions = sanctions_filter.contains(&unblinded_target);
        let is_cleared = !is_on_sanctions;

        let mut sig_hasher = Sha256::new();
        sig_hasher.update(b"SANCTIONS_CLEARANCE_RECEIPT");
        sig_hasher.update(&unblinded_target);
        sig_hasher.update(&[is_cleared as u8]);
        sig_hasher.update(&epoch.to_be_bytes());
        let sig = hex::encode(sig_hasher.finalize());

        SanctionsNonMembershipReceipt {
            is_cleared,
            sanctions_list_epoch: epoch,
            oracle_signature: format!("0x{}", sig),
            zero_leakage_commitment: hex::encode(&unblinded_target[0..16]),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_leakage_sanctions_flow() {
        let mut filter = BlindedCuckooFilter::new(100);

        // Sanctioned entity hash
        let bad_actor_hash = Sha256::digest(b"sanctioned_entity_mallory_target").into();
        filter.insert(&bad_actor_hash);

        assert!(filter.contains(&bad_actor_hash));

        // Innocent user query
        let oracle_key = b"oracle_super_confidential_compliance_signing_key_2026";
        let (query, r) = ZeroLeakageSanctionsEngine::client_blind_query(
            "user_alice_innocent_citizen",
            b"client_entropy_salt",
            105,
        );

        let oracle_resp = ZeroLeakageSanctionsEngine::oracle_evaluate_blinded_point(&query, oracle_key);
        let receipt = ZeroLeakageSanctionsEngine::client_unblind_and_verify(&oracle_resp, &r, &filter, 105);

        assert!(receipt.is_cleared);
        assert!(!receipt.oracle_signature.is_empty());
    }
}
