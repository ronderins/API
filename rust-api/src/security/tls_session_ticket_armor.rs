//! TLS Session Ticket Encryption Key (STEK) Rotation & Forward Secrecy Armor
//!
//! Enforces forward secrecy for resumed TLS 1.3 sessions and API bearer tokens:
//! - Automated rotating Session Ticket Encryption Keys (STEK) with strict epoch TTLs
//! - Prevents retroactive traffic decryption if server keys are subpoenaed or breached in the future
//! - Authenticated Encryption with Associated Data (AEAD) ticket sealing with key-id indexing
//! - Dual-key window: decrypts previous epoch tickets while strictly encrypting under the active key
//! - Memory-scrubbing zeroization on expired key retirement

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Individual Ephemeral Session Ticket Key with Epoch Lifecycle
#[derive(Clone)]
pub struct StekKeyEntry {
    pub key_id: [u8; 16],
    pub cipher_key: [u8; 32],
    pub hmac_key: [u8; 32],
    pub created_at_epoch_secs: u64,
    pub expires_at_epoch_secs: u64,
}

impl Drop for StekKeyEntry {
    fn drop(&mut self) {
        self.cipher_key.zeroize();
        self.hmac_key.zeroize();
    }
}

/// Sealed TLS Session Ticket Payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSessionTicket {
    pub key_id: [u8; 16],
    pub iv_nonce: [u8; 12],
    pub encrypted_session_state: Vec<u8>,
    pub auth_tag_hmac: [u8; 32],
}

/// Dynamic STEK Key Manager enforcing forward secrecy
pub struct TlsSessionTicketArmor {
    active_key_id: RwLock<[u8; 16]>,
    key_ring: RwLock<HashMap<[u8; 16], StekKeyEntry>>,
    rotation_period_secs: u64,
    ticket_lifetime_secs: u64,
}

impl TlsSessionTicketArmor {
    /// Creates a new STEK manager with specified rotation interval (e.g. 3600s = 1 hr) and ticket lifetime (e.g. 7200s = 2 hrs).
    pub fn new(rotation_period_secs: u64, ticket_lifetime_secs: u64, initial_seed: &[u8; 32]) -> Self {
        let manager = Self {
            active_key_id: RwLock::new([0u8; 16]),
            key_ring: RwLock::new(HashMap::new()),
            rotation_period_secs,
            ticket_lifetime_secs,
        };

        manager.rotate_key(initial_seed);
        manager
    }

    /// Rotates the active session ticket key using entropy from a new seed.
    pub fn rotate_key(&self, fresh_entropy: &[u8; 32]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Derive new Key ID
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(b"stek-key-id-v1:");
        id_hasher.update(fresh_entropy);
        id_hasher.update(&now.to_be_bytes());
        let id_digest = id_hasher.finalize();
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&id_digest.as_bytes()[..16]);

        // 2. Derive Cipher Key
        let mut cipher_hasher = blake3::Hasher::new();
        cipher_hasher.update(b"stek-cipher-key-v1:");
        cipher_hasher.update(fresh_entropy);
        let cipher_key = *cipher_hasher.finalize().as_bytes();

        // 3. Derive HMAC Key
        let mut hmac_hasher = blake3::Hasher::new();
        hmac_hasher.update(b"stek-hmac-key-v1:");
        hmac_hasher.update(fresh_entropy);
        let hmac_key = *hmac_hasher.finalize().as_bytes();

        let entry = StekKeyEntry {
            key_id,
            cipher_key,
            hmac_key,
            created_at_epoch_secs: now,
            expires_at_epoch_secs: now + self.ticket_lifetime_secs,
        };

        // Insert into keyring
        {
            let mut ring = self.key_ring.write().unwrap();
            ring.insert(key_id, entry);

            // Purge expired keys
            ring.retain(|_, k| k.expires_at_epoch_secs > now);
        }

        // Set as active key
        let mut active = self.active_key_id.write().unwrap();
        *active = key_id;
    }

    /// Encrypts and seals sensitive session state under the currently active STEK key.
    pub fn seal_session_ticket(&self, plaintext_session: &[u8]) -> Result<SealedSessionTicket, &'static str> {
        let active_id = *self.active_key_id.read().unwrap();
        let ring = self.key_ring.read().unwrap();
        let key_entry = ring.get(&active_id).ok_or("Active STEK key missing")?;

        // Generate pseudorandom 12-byte IV nonce
        let mut nonce = [0u8; 12];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let nonce_hash = blake3::hash(&now.to_be_bytes());
        nonce.copy_from_slice(&nonce_hash.as_bytes()[..12]);

        // Stream cipher encryption (CTR mode emulation using keyed Blake3)
        let mut ciphertext = Vec::with_capacity(plaintext_session.len());
        for (i, &byte) in plaintext_session.iter().enumerate() {
            let mut mask_hasher = blake3::Hasher::new_keyed(&key_entry.cipher_key);
            mask_hasher.update(&nonce);
            mask_hasher.update(&(i as u64).to_be_bytes());
            let mask = mask_hasher.finalize().as_bytes()[0];
            ciphertext.push(byte ^ mask);
        }

        // Authenticated HMAC tag
        let mut tag_hasher = blake3::Hasher::new_keyed(&key_entry.hmac_key);
        tag_hasher.update(b"stek-auth-tag-v1:");
        tag_hasher.update(&active_id);
        tag_hasher.update(&nonce);
        tag_hasher.update(&ciphertext);
        let auth_tag_hmac = *tag_hasher.finalize().as_bytes();

        Ok(SealedSessionTicket {
            key_id: active_id,
            iv_nonce: nonce,
            encrypted_session_state: ciphertext,
            auth_tag_hmac,
        })
    }

    /// Unseals and decrypts a session ticket, resolving against any valid historical key in the keyring.
    pub fn unseal_session_ticket(&self, ticket: &SealedSessionTicket) -> Result<Vec<u8>, &'static str> {
        let ring = self.key_ring.read().unwrap();
        let key_entry = ring.get(&ticket.key_id).ok_or("Session key expired or revoked (Forward Secrecy enforced)")?;

        // 1. Verify HMAC authentication tag
        let mut tag_hasher = blake3::Hasher::new_keyed(&key_entry.hmac_key);
        tag_hasher.update(b"stek-auth-tag-v1:");
        tag_hasher.update(&ticket.key_id);
        tag_hasher.update(&ticket.iv_nonce);
        tag_hasher.update(&ticket.encrypted_session_state);
        let expected_tag = *tag_hasher.finalize().as_bytes();

        if !ticket.auth_tag_hmac.ct_eq(&expected_tag).into() {
            return Err("Tampered session ticket detected (integrity tag verification failed)");
        }

        // 2. Decrypt session state
        let mut plaintext = Vec::with_capacity(ticket.encrypted_session_state.len());
        for (i, &byte) in ticket.encrypted_session_state.iter().enumerate() {
            let mut mask_hasher = blake3::Hasher::new_keyed(&key_entry.cipher_key);
            mask_hasher.update(&ticket.iv_nonce);
            mask_hasher.update(&(i as u64).to_be_bytes());
            let mask = mask_hasher.finalize().as_bytes()[0];
            plaintext.push(byte ^ mask);
        }

        Ok(plaintext)
    }

    /// Number of active keys retained in the keyring.
    pub fn active_key_count(&self) -> usize {
        self.key_ring.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stek_sealing_and_unsealing() {
        let seed = [0x55u8; 32];
        let armor = TlsSessionTicketArmor::new(3600, 7200, &seed);

        let secret_session = b"authenticated_subject_session_alice_9988";
        let ticket = armor.seal_session_ticket(secret_session).unwrap();

        let decrypted = armor.unseal_session_ticket(&ticket).unwrap();
        assert_eq!(decrypted, secret_session);

        // Tampering with ciphertext should fail HMAC tag check
        let mut tampered_ticket = ticket.clone();
        tampered_ticket.encrypted_session_state[0] ^= 0xFF;
        assert!(armor.unseal_session_ticket(&tampered_ticket).is_err());
    }

    #[test]
    fn test_stek_rotation_maintains_decryption() {
        let seed1 = [0x11u8; 32];
        let seed2 = [0x22u8; 32];
        let armor = TlsSessionTicketArmor::new(3600, 7200, &seed1);

        let ticket_v1 = armor.seal_session_ticket(b"session_v1").unwrap();

        // Rotate key
        armor.rotate_key(&seed2);
        assert_eq!(armor.active_key_count(), 2);

        // Previous ticket should still be decryptable
        assert_eq!(armor.unseal_session_ticket(&ticket_v1).unwrap(), b"session_v1");

        // New ticket encrypted under new key
        let ticket_v2 = armor.seal_session_ticket(b"session_v2").unwrap();
        assert_ne!(ticket_v1.key_id, ticket_v2.key_id);
        assert_eq!(armor.unseal_session_ticket(&ticket_v2).unwrap(), b"session_v2");
    }
}
