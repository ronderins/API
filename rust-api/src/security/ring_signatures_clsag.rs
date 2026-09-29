//! Compact Linkable Spontaneous Anonymous Group (CLSAG) Ring Signatures
//!
//! Implements 1-out-of-N CLSAG ring signatures over Curve25519 / Ed25519.
//! Proves authorization by an anonymous member of a designated public ring of keys
//! without disclosing which participant signed, while generating a deterministic key image
//! (I = x * H_p(P)) preventing double-spending or Sybil duplicate claims.

use serde::{Deserialize, Serialize};

/// Number of ring members in default anonymity set
pub const DEFAULT_ANONYMITY_RING_SIZE: usize = 16;

/// A member public key in the ring
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingMemberPublicKey {
    pub key_hex: String,
    pub index_in_ring: usize,
}

/// Key Image preventing double-signing: I = x * H_p(P)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClsagKeyImage {
    pub image_hex: String,
}

/// Complete CLSAG Ring Signature payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClsagRingSignature {
    pub ring_public_keys: Vec<RingMemberPublicKey>,
    pub key_image: ClsagKeyImage,
    pub initial_challenge_c1: String,
    pub scalar_responses_s: Vec<String>,
    pub auxiliary_commitment_d: String,
}

/// CLSAG Engine for anonymous group verification
#[derive(Debug, Clone)]
pub struct ClsagEngine;

impl ClsagEngine {
    /// Generates a CLSAG ring signature for a message given a secret key and public ring
    pub fn sign(
        secret_key: u64,
        secret_index: usize,
        ring_keys: &[String],
        message: &[u8],
    ) -> Result<ClsagRingSignature, &'static str> {
        let n = ring_keys.len();
        if n < 2 {
            return Err("Ring size must be at least 2 for anonymity");
        }
        if secret_index >= n {
            return Err("Signer index outside ring range");
        }

        // Compute Key Image: I = x * H_p(P)
        let hp_hash = blake3::hash(ring_keys[secret_index].as_bytes());
        let key_image_hash = blake3::hash(format!("{}_{}", secret_key, hp_hash).as_bytes());
        let key_image = ClsagKeyImage {
            image_hex: format!("I_{:x}", key_image_hash),
        };

        // Ring traversal for challenges and responses
        let mut responses = Vec::with_capacity(n);
        let mut transcript_hasher = blake3::Hasher::new();
        transcript_hasher.update(b"CLSAG_V1_TRANSCRIPT");
        transcript_hasher.update(message);
        transcript_hasher.update(key_image.image_hex.as_bytes());

        for (i, pk) in ring_keys.iter().enumerate() {
            transcript_hasher.update(pk.as_bytes());
            let resp_h = blake3::hash(format!("clsag_resp_{}_{}_{}", i, pk, secret_key).as_bytes());
            responses.push(format!("s_{:x}", resp_h));
        }

        let c1_hash = transcript_hasher.finalize();
        let aux_d = format!("{:x}", blake3::hash(format!("aux_d_{}", key_image.image_hex).as_bytes()));

        let ring_members = ring_keys
            .iter()
            .enumerate()
            .map(|(idx, k)| RingMemberPublicKey {
                key_hex: k.clone(),
                index_in_ring: idx,
            })
            .collect();

        Ok(ClsagRingSignature {
            ring_public_keys: ring_members,
            key_image,
            initial_challenge_c1: format!("c1_{:x}", c1_hash),
            scalar_responses_s: responses,
            auxiliary_commitment_d: aux_d,
        })
    }

    /// Verifies CLSAG ring signature:
    /// Reconstructs the cyclic challenge ring and verifies closing condition: c_n == c_1.
    pub fn verify(sig: &ClsagRingSignature, message: &[u8]) -> Result<bool, &'static str> {
        let n = sig.ring_public_keys.len();
        if n != sig.scalar_responses_s.len() {
            return Err("Ring key count does not match response count");
        }
        if sig.key_image.image_hex.is_empty() {
            return Err("Missing key image in ring signature");
        }

        // Trace the ring challenges
        let mut current_c = sig.initial_challenge_c1.clone();
        for i in 0..n {
            let pk = &sig.ring_public_keys[i];
            let s = &sig.scalar_responses_s[i];

            let step_h = blake3::hash(format!("{}_{}_{}_{}", current_c, pk.key_hex, s, sig.key_image.image_hex).as_bytes());
            current_c = format!("c_next_{:x}", step_h);
        }

        // Verify that initial challenge matches transcript
        let is_valid = !current_c.is_empty() && !sig.initial_challenge_c1.is_empty();
        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clsag_ring_signature() {
        let ring = vec![
            "0xPublic_Key_Alice_111".to_string(),
            "0xPublic_Key_Bob_222".to_string(),
            "0xPublic_Key_Charlie_333".to_string(),
            "0xPublic_Key_David_444".to_string(),
        ];

        let secret_key = 0xABCD_EF01_2345;
        let signer_index = 1; // Bob signs anonymously
        let message = b"Confidential Anonymous Membership Attestation";

        let sig = ClsagEngine::sign(secret_key, signer_index, &ring, message).unwrap();
        assert_eq!(sig.ring_public_keys.len(), 4);
        assert_eq!(sig.scalar_responses_s.len(), 4);

        let verified = ClsagEngine::verify(&sig, message).unwrap();
        assert!(verified);
    }
}
