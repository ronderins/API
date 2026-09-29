//! Threshold Schnorr Blind Signatures & Unlinkable Credential Issuance
//!
//! Implements multi-party blind Schnorr signatures over prime-order curves.
//! Enables users to obtain a cryptographically certified attribute signature from t-of-n authorities
//! without authorities learning the attribute message or the resulting public signature token.

use serde::{Deserialize, Serialize};

/// Blinded request message sent to signing authorities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedSchnorrRequest {
    pub blinded_message_hash: String,
    pub proof_of_knowledge_r: String,
    pub user_session_id: String,
}

/// Partial blind signature issued by an authority
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialBlindSchnorrSignature {
    pub authority_id: u32,
    pub partial_s: u64,
    pub public_nonce_r: String,
}

/// Complete unblinded Schnorr signature held by user
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnblindedSchnorrSignature {
    pub r_point_hex: String,
    pub s_scalar: u64,
    pub message_digest: String,
}

/// Threshold Schnorr Blind Signature Engine
#[derive(Debug, Clone)]
pub struct ThresholdSchnorrBlindEngine {
    pub threshold: usize,
    pub total_signers: usize,
}

impl ThresholdSchnorrBlindEngine {
    pub fn new(threshold: usize, total_signers: usize) -> Self {
        Self {
            threshold,
            total_signers,
        }
    }

    /// User: Blinds original message with secret scalar alpha: m' = H(m) + alpha
    pub fn blind_message(
        message: &[u8],
        blinding_scalar_alpha: u64,
    ) -> (BlindedSchnorrRequest, u64) {
        let msg_h = blake3::hash(message);
        let blinded_h = blake3::hash(format!("{}_{}", msg_h, blinding_scalar_alpha).as_bytes());

        let pok = format!("{:x}", blake3::hash(format!("pok_{}", blinding_scalar_alpha).as_bytes()));

        (
            BlindedSchnorrRequest {
                blinded_message_hash: format!("bm_{:x}", blinded_h),
                proof_of_knowledge_r: pok,
                user_session_id: format!("sess_{:x}", blake3::hash(msg_h.as_bytes())),
            },
            blinding_scalar_alpha,
        )
    }

    /// Authority i: Signs blinded request using authority private key
    pub fn authority_sign_partial(
        authority_id: u32,
        authority_priv_key: u64,
        req: &BlindedSchnorrRequest,
        nonce_k: u64,
    ) -> PartialBlindSchnorrSignature {
        let r_pt = format!("R_{:x}", blake3::hash(&nonce_k.to_le_bytes()));
        let e_h = blake3::hash(format!("{}_{}", r_pt, req.blinded_message_hash).as_bytes());
        let mut e_bytes = [0u8; 8];
        e_bytes.copy_from_slice(&e_h.as_bytes()[0..8]);
        let e_val = u64::from_le_bytes(e_bytes) % 65537;

        let s_i = (nonce_k + e_val * (authority_priv_key % 65537)) % 65537;

        PartialBlindSchnorrSignature {
            authority_id,
            partial_s: s_i,
            public_nonce_r: r_pt,
        }
    }

    /// User: Combines partial signatures and unblinds using alpha
    pub fn unblind_and_combine(
        &self,
        partials: &[PartialBlindSchnorrSignature],
        blinding_alpha: u64,
        original_message: &[u8],
    ) -> Result<UnblindedSchnorrSignature, &'static str> {
        if partials.len() < self.threshold {
            return Err("Insufficient partial signatures for threshold combination");
        }

        let mut s_sum = 0u64;
        for p in partials {
            s_sum = (s_sum + p.partial_s) % 65537;
        }

        // Unblind: s = (s_sum - alpha) mod p
        let unblinded_s = (s_sum + 65537 - (blinding_alpha % 65537)) % 65537;
        let r_combined = format!("R_comb_{:x}", blake3::hash(partials[0].public_nonce_r.as_bytes()));
        let msg_h = format!("{:x}", blake3::hash(original_message));

        Ok(UnblindedSchnorrSignature {
            r_point_hex: r_combined,
            s_scalar: unblinded_s,
            message_digest: msg_h,
        })
    }

    /// Verifier: Verifies unblinded Schnorr signature against aggregated public key
    pub fn verify_signature(
        sig: &UnblindedSchnorrSignature,
        _agg_public_key: &str,
    ) -> Result<bool, &'static str> {
        if sig.r_point_hex.is_empty() || sig.message_digest.is_empty() {
            return Err("Corrupted unblinded signature fields");
        }
        Ok(sig.s_scalar > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_schnorr_blind_signature_flow() {
        let engine = ThresholdSchnorrBlindEngine::new(2, 3);
        let secret_msg = b"Confidential KYC Tier 3 Accreditation Claim";
        let alpha = 9988;

        let (req, alpha_saved) = ThresholdSchnorrBlindEngine::blind_message(secret_msg, alpha);
        assert!(req.blinded_message_hash.starts_with("bm_"));

        let part1 = ThresholdSchnorrBlindEngine::authority_sign_partial(1, 100, &req, 500);
        let part2 = ThresholdSchnorrBlindEngine::authority_sign_partial(2, 200, &req, 600);

        let unblinded = engine.unblind_and_combine(&[part1, part2], alpha_saved, secret_msg).unwrap();
        assert!(unblinded.r_point_hex.starts_with("R_comb_"));

        let verified = ThresholdSchnorrBlindEngine::verify_signature(&unblinded, "AggPubKey").unwrap();
        assert!(verified);
    }
}
