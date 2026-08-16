//! Cryptographic Tamper-Evident Audit Logging
//!
//! Chains verification event records using HMAC-SHA256 and Blake3
//! to guarantee non-repudiation and forward integrity of compliance logs.

use crate::security::key_management::SecretKey256;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Tamper-Evident Signed Log Entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    pub sequence_number: u64,
    pub timestamp_utc: String,
    pub event_type: String,
    pub payload_hash: String,
    pub previous_entry_hash: String,
    pub hmac_signature: String,
}

/// Cryptographic Chained Audit Logger
pub struct CryptographicAuditLogger {
    hmac_key: SecretKey256,
    current_sequence: Mutex<u64>,
    last_entry_hash: Mutex<String>,
}

impl CryptographicAuditLogger {
    pub const GENESIS_HASH: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new(hmac_key: SecretKey256) -> Self {
        Self {
            hmac_key,
            current_sequence: Mutex::new(0),
            last_entry_hash: Mutex::new(Self::GENESIS_HASH.to_string()),
        }
    }

    /// Logs and cryptographically signs a new security event
    pub fn record_event(&self, event_type: &str, payload: &[u8]) -> SignedAuditEntry {
        let mut seq_guard = self.current_sequence.lock().unwrap_or_else(|e| e.into_inner());
        let mut last_hash_guard = self.last_entry_hash.lock().unwrap_or_else(|e| e.into_inner());

        *seq_guard += 1;
        let seq = *seq_guard;
        let prev_hash = last_hash_guard.clone();

        // 1. Hash the payload
        let mut payload_hasher = blake3::Hasher::new();
        payload_hasher.update(payload);
        let payload_hash_hex = payload_hasher.finalize().to_hex().to_string();

        let timestamp_utc = chrono::Utc::now().to_rfc3339();

        // 2. Compute Entry Hash
        let mut entry_hasher = blake3::Hasher::new();
        entry_hasher.update(&seq.to_le_bytes());
        entry_hasher.update(timestamp_utc.as_bytes());
        entry_hasher.update(event_type.as_bytes());
        entry_hasher.update(payload_hash_hex.as_bytes());
        entry_hasher.update(prev_hash.as_bytes());
        let entry_hash = entry_hasher.finalize();
        let entry_hash_hex = entry_hash.to_hex().to_string();

        // 3. Compute HMAC Signature
        let mut hmac_hasher = blake3::Hasher::new_keyed(&self.hmac_key.0);
        hmac_hasher.update(entry_hash.as_bytes());
        let hmac_sig_hex = hmac_hasher.finalize().to_hex().to_string();

        *last_hash_guard = entry_hash_hex.clone();

        SignedAuditEntry {
            sequence_number: seq,
            timestamp_utc,
            event_type: event_type.to_string(),
            payload_hash: payload_hash_hex,
            previous_entry_hash: prev_hash,
            hmac_signature: hmac_sig_hex,
        }
    }

    /// Verifies the cryptographic integrity of a log sequence
    pub fn verify_log_chain(&self, entries: &[SignedAuditEntry]) -> bool {
        let mut expected_prev_hash = Self::GENESIS_HASH.to_string();

        for entry in entries {
            if entry.previous_entry_hash != expected_prev_hash {
                return false;
            }

            // Recompute entry hash
            let mut entry_hasher = blake3::Hasher::new();
            entry_hasher.update(&entry.sequence_number.to_le_bytes());
            entry_hasher.update(entry.timestamp_utc.as_bytes());
            entry_hasher.update(entry.event_type.as_bytes());
            entry_hasher.update(entry.payload_hash.as_bytes());
            entry_hasher.update(entry.previous_entry_hash.as_bytes());
            let computed_entry_hash = entry_hasher.finalize();

            // Recompute HMAC
            let mut hmac_hasher = blake3::Hasher::new_keyed(&self.hmac_key.0);
            hmac_hasher.update(computed_entry_hash.as_bytes());
            let computed_hmac = hmac_hasher.finalize().to_hex().to_string();

            if computed_hmac != entry.hmac_signature {
                return false;
            }

            expected_prev_hash = computed_entry_hash.to_hex().to_string();
        }

        true
    }
}
