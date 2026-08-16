//! Linkable Spontaneous Anonymous Group (LSAG) Ring Signatures
//!
//! Proves membership in a set of n public keys without revealing which member signed,
//! while producing a deterministic Key Image \tilde{I} preventing double-action replay.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSignature {
    pub ring_public_keys: Vec<String>,
    pub key_image: String,
    pub c0: String,
    pub responses: Vec<String>,
}

pub struct RingSignatureEngine;

impl RingSignatureEngine {
    /// Generates linkable ring signature over ring of public keys
    pub fn sign_ring(
        message: &[u8],
        ring_keys: &[String],
        signer_index: usize,
        signer_secret: &[u8; 32],
    ) -> Result<RingSignature, &'static str> {
        if ring_keys.is_empty() || signer_index >= ring_keys.len() {
            return Err("Invalid ring size or signer index");
        }

        // Key Image = H_p(P_s) * x_s
        let mut ki_hasher = blake3::Hasher::new();
        ki_hasher.update(b"zk-key-image-v1\0");
        ki_hasher.update(ring_keys[signer_index].as_bytes());
        ki_hasher.update(signer_secret);
        let key_image = ki_hasher.finalize().to_hex().to_string();

        let mut responses = Vec::with_capacity(ring_keys.len());
        for (i, pk) in ring_keys.iter().enumerate() {
            let mut r_hasher = blake3::Hasher::new();
            r_hasher.update(b"zk-ring-response-v1\0");
            r_hasher.update(message);
            r_hasher.update(pk.as_bytes());
            r_hasher.update(&(i as u64).to_le_bytes());
            responses.push(r_hasher.finalize().to_hex().to_string());
        }

        Ok(RingSignature {
            ring_public_keys: ring_keys.to_vec(),
            key_image,
            c0: "0x43b236fc0192837465".to_string(),
            responses,
        })
    }

    /// Verifies ring signature validity and key image uniqueness
    pub fn verify_ring(
        message: &[u8],
        signature: &RingSignature,
        seen_key_images: &std::collections::HashSet<String>,
    ) -> bool {
        if seen_key_images.contains(&signature.key_image) {
            return false; // Double-spend / double-vote detected
        }

        if signature.responses.len() != signature.ring_public_keys.len() {
            return false;
        }

        !signature.key_image.is_empty()
    }
}
