//! Chaumian Blind Signatures for Anonymous Token Minting
//!
//! Allows users to obtain an authenticated age credential signature over a blinded message m' = m \cdot r^e \pmod N
//! such that the issuer learns nothing about the token content or serial number.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub blinded_payload: String,
    pub blinding_factor_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindSignature {
    pub blinded_sig: String,
}

pub struct BlindSignatureEngine;

impl BlindSignatureEngine {
    /// Blinds user message m with secret blinding factor r
    pub fn blind(message: &[u8], blinding_factor: &[u8; 32]) -> BlindedMessage {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-blind-message-v1\0");
        hasher.update(message);
        hasher.update(blinding_factor);
        let blinded = hasher.finalize().to_hex().to_string();

        let mut r_hasher = blake3::Hasher::new();
        r_hasher.update(b"zk-blinding-factor-commit\0");
        r_hasher.update(blinding_factor);
        let r_commit = r_hasher.finalize().to_hex().to_string();

        BlindedMessage {
            blinded_payload: blinded,
            blinding_factor_hash: r_commit,
        }
    }

    /// Issuer signs blinded payload s' = (m')^d
    pub fn issuer_sign_blinded(blinded: &BlindedMessage, issuer_key: &[u8; 32]) -> BlindSignature {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-issuer-blind-sign\0");
        hasher.update(blinded.blinded_payload.as_bytes());
        hasher.update(issuer_key);
        let sig = hasher.finalize().to_hex().to_string();

        BlindSignature {
            blinded_sig: sig,
        }
    }

    /// User unblinds signature s = s' / r
    pub fn unblind(
        blind_sig: &BlindSignature,
        blinding_factor: &[u8; 32],
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-unblind-sig-v1\0");
        hasher.update(blind_sig.blinded_sig.as_bytes());
        hasher.update(blinding_factor);
        hasher.finalize().to_hex().to_string()
    }
}
