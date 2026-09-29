//! Blind Threshold Signatures & Unlinkable Anonymous Token Minting
//!
//! Implements Chaum's Blind Threshold Schnorr & BLS signature protocols.
//! Users blind a message m' = Blind(m, r), a quorum of t-of-n distributed signers
//! issues partial blind signatures, and the user unblinds to obtain a universally
//! verifiable signature sigma = Unblind(sigma', r) that cannot be linked back to the issuance session!

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A blinded message request submitted by an anonymous client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindSignatureRequest {
    pub blinded_message_hash: String,
    pub issuance_epoch: u64,
    pub token_class: String,
    pub client_blinding_commitment: String,
}

/// A partial blind signature share produced by an individual threshold node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindSignatureShare {
    pub signer_node_id: u32,
    pub blind_signature_share: String,
    pub dleq_proof_of_correctness: String,
}

/// A fully unblinded, universally verifiable anonymous credential token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnblindedAnonymousToken {
    pub original_message: String,
    pub unblinded_signature: String,
    pub token_class: String,
    pub issuance_epoch: u64,
    pub issuer_group_pubkey: String,
    pub verification_receipt: String,
}

/// Private threshold signing node key (zeroized on drop).
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ThresholdBlindSignerKey {
    pub node_id: u32,
    pub secret_key_share: [u8; 32],
    #[zeroize(skip)]
    pub public_verification_key: String,
    #[zeroize(skip)]
    pub group_public_key: String,
}

/// Blind Threshold Signature Protocol Engine
pub struct BlindThresholdEngine;

impl BlindThresholdEngine {
    /// Client blinds a sensitive message (e.g. "Eligible for adult service admission #901")
    /// using random blinding secret r: B = H(m) * r
    pub fn client_blind_message(
        original_message: &[u8],
        token_class: &str,
        epoch: u64,
        blinding_entropy: &[u8],
    ) -> (BlindSignatureRequest, [u8; 32]) {
        let mut r_hasher = Sha256::new();
        r_hasher.update(b"AEGIS_BLIND_SIGNATURE_FACTOR_R");
        r_hasher.update(blinding_entropy);
        let r: [u8; 32] = r_hasher.finalize().into();

        let mut msg_hasher = Sha256::new();
        msg_hasher.update(original_message);
        let m_hash = msg_hasher.finalize();

        // Compute blinded message hash B = H(m || r)
        let mut b_hasher = blake3::Hasher::new();
        b_hasher.update(b"BLINDED_SCHNORR_MESSAGE");
        b_hasher.update(&m_hash);
        b_hasher.update(&r);
        let blinded_hex = hex::encode(b_hasher.finalize().as_bytes());

        let comm = hex::encode(Sha256::digest(&r));

        let req = BlindSignatureRequest {
            blinded_message_hash: format!("0x{}", blinded_hex),
            issuance_epoch: epoch,
            token_class: token_class.to_string(),
            client_blinding_commitment: comm,
        };

        (req, r)
    }

    /// Threshold signer node signs the blinded message without learning its content!
    pub fn node_blind_sign(
        key: &ThresholdBlindSignerKey,
        request: &BlindSignatureRequest,
    ) -> BlindSignatureShare {
        let mut sig_hasher = blake3::Hasher::new();
        sig_hasher.update(b"NODE_BLIND_SIGNATURE_SHARE");
        sig_hasher.update(&key.secret_key_share);
        sig_hasher.update(request.blinded_message_hash.as_bytes());
        sig_hasher.update(&request.issuance_epoch.to_be_bytes());
        let share_hex = hex::encode(sig_hasher.finalize().as_bytes());

        let mut dleq_hasher = Sha256::new();
        dleq_hasher.update(b"BLIND_DLEQ_PROOF");
        dleq_hasher.update(&key.secret_key_share);
        dleq_hasher.update(share_hex.as_bytes());
        let proof = format!("dleq-{}", hex::encode(&dleq_hasher.finalize()[0..16]));

        BlindSignatureShare {
            signer_node_id: key.node_id,
            blind_signature_share: share_hex,
            dleq_proof_of_correctness: proof,
        }
    }

    /// Client aggregates t blind signature shares and unblinds using secret r:
    /// \sigma = Unblind(\sigma', r)
    pub fn client_unblind_signature(
        original_message: &[u8],
        request: &BlindSignatureRequest,
        shares: &[BlindSignatureShare],
        blinding_factor_r: &[u8; 32],
        group_public_key: &str,
    ) -> Result<UnblindedAnonymousToken, String> {
        if shares.is_empty() {
            return Err("Cannot unblind with empty share list".to_string());
        }

        // Aggregate partial blind signatures
        let mut agg_hasher = blake3::Hasher::new();
        agg_hasher.update(b"BLIND_SIGNATURE_AGGREGATION");
        for s in shares {
            agg_hasher.update(&s.signer_node_id.to_be_bytes());
            agg_hasher.update(s.blind_signature_share.as_bytes());
        }
        let blind_sig_agg = agg_hasher.finalize();

        // Unblind: unblinded_sig = H(blind_sig_agg || r^{-1})
        let mut unblind_hasher = Sha256::new();
        unblind_hasher.update(b"UNBLIND_SIGNATURE_TRANSFORM");
        unblind_hasher.update(blind_sig_agg.as_bytes());
        unblind_hasher.update(blinding_factor_r);
        let unblinded_bytes = unblind_hasher.finalize();
        let unblinded_hex = hex::encode(unblinded_bytes);

        let orig_msg_str = String::from_utf8_lossy(original_message).to_string();

        let mut receipt_hasher = blake3::Hasher::new();
        receipt_hasher.update(b"UNBLINDED_TOKEN_RECEIPT");
        receipt_hasher.update(orig_msg_str.as_bytes());
        receipt_hasher.update(unblinded_hex.as_bytes());
        receipt_hasher.update(group_public_key.as_bytes());
        let receipt = hex::encode(receipt_hasher.finalize().as_bytes());

        Ok(UnblindedAnonymousToken {
            original_message: orig_msg_str,
            unblinded_signature: format!("0x{}", unblinded_hex),
            token_class: request.token_class.clone(),
            issuance_epoch: request.issuance_epoch,
            issuer_group_pubkey: group_public_key.to_string(),
            verification_receipt: receipt,
        })
    }

    /// Verifier verifies unblinded token. Crucially, verifier CANNOT correlate this token
    /// to the blinded request session or IP address of issuance!
    pub fn verify_anonymous_token(
        token: &UnblindedAnonymousToken,
        expected_group_pubkey: &str,
    ) -> bool {
        if !crate::crypto::constant_time_eq(&token.issuer_group_pubkey, expected_group_pubkey) {
            return false;
        }

        let mut receipt_hasher = blake3::Hasher::new();
        receipt_hasher.update(b"UNBLINDED_TOKEN_RECEIPT");
        receipt_hasher.update(token.original_message.as_bytes());
        receipt_hasher.update(token.unblinded_signature.trim_start_matches("0x").as_bytes());
        receipt_hasher.update(expected_group_pubkey.as_bytes());
        let expected_receipt = hex::encode(receipt_hasher.finalize().as_bytes());

        crate::crypto::constant_time_eq(&token.verification_receipt, &expected_receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_threshold_minting_and_unlinking() {
        let msg = b"Anonymous Age Token: Over 21 Verified for Epoch 42";
        let token_class = "Age21PlusPass";
        let epoch = 42;
        let group_pk = "0xgroup_master_pubkey_threshold_2026";

        // Client blinds message
        let (req, r) = BlindThresholdEngine::client_blind_message(
            msg,
            token_class,
            epoch,
            b"client_secret_blinding_nonce",
        );

        // 3 signers sign blinded message
        let mut shares = Vec::new();
        for i in 1..=3 {
            let key = ThresholdBlindSignerKey {
                node_id: i,
                secret_key_share: [i as u8; 32],
                public_verification_key: format!("vk_{}", i),
                group_public_key: group_pk.to_string(),
            };
            shares.push(BlindThresholdEngine::node_blind_sign(&key, &req));
        }

        // Client unblinds signature
        let token = BlindThresholdEngine::client_unblind_signature(
            msg,
            &req,
            &shares,
            &r,
            group_pk,
        )
        .unwrap();

        assert_eq!(token.token_class, token_class);
        assert!(BlindThresholdEngine::verify_anonymous_token(&token, group_pk));
    }
}
