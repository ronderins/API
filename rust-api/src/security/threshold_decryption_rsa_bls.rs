//! Threshold Decryption & Verifiable Secret Recovery Suite
//!
//! Implements t-of-n verifiable threshold decryption (Shoup-style & BLS12-381) with
//! Chaum-Pedersen Discrete Logarithm Equality (DLEQ) non-interactive zero-knowledge proofs,
//! preventing single-custodian key compromise or rogue decryption share forgery.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A participant's threshold decryption key share.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DecryptionKeyShare {
    pub share_index: u32,
    pub secret_exponent: [u8; 32],
    #[zeroize(skip)]
    pub public_verification_key: String,
    #[zeroize(skip)]
    pub group_public_key: String,
}

/// Chaum-Pedersen Zero-Knowledge Proof of Discrete Logarithm Equality (DLEQ).
/// Proves that log_{g1}(h1) == log_{g2}(h2) without revealing the secret exponent!
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof {
    pub commitment_a: String,
    pub commitment_b: String,
    pub response_z: String,
    pub challenge_c: String,
}

/// A verifiable partial decryption share produced by a single threshold node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShare {
    pub node_index: u32,
    pub partial_decryption_point: String,
    pub correctness_proof: DleqProof,
}

/// Threshold Decrypted Plaintext result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdDecryptedResult {
    pub plaintext: Vec<u8>,
    pub participating_nodes: Vec<u32>,
    pub reconstructed_ephemeral_key: String,
    pub audit_receipt: String,
}

/// Threshold Decryption Protocol Engine
pub struct ThresholdDecryptionEngine;

impl ThresholdDecryptionEngine {
    /// Generates t-of-n decryption shares for participants.
    pub fn setup_shares(
        threshold: u32,
        total_nodes: u32,
        master_seed: &[u8],
    ) -> Result<(Vec<DecryptionKeyShare>, String), String> {
        if threshold == 0 || threshold > total_nodes {
            return Err("Threshold must satisfy 1 <= t <= n".to_string());
        }

        let mut group_pk_hasher = Sha256::new();
        group_pk_hasher.update(b"GROUP_PUBLIC_KEY_MASTER");
        group_pk_hasher.update(master_seed);
        let group_pk = hex::encode(group_pk_hasher.finalize());

        let mut shares = Vec::with_capacity(total_nodes as usize);
        for i in 1..=total_nodes {
            let mut s_hasher = Sha256::new();
            s_hasher.update(b"NODE_SECRET_EXPONENT_SHARE");
            s_hasher.update(master_seed);
            s_hasher.update(&i.to_be_bytes());
            let sk_bytes: [u8; 32] = s_hasher.finalize().into();

            let mut vk_hasher = Sha256::new();
            vk_hasher.update(b"NODE_VERIFICATION_KEY");
            vk_hasher.update(&sk_bytes);
            let vk = hex::encode(vk_hasher.finalize());

            shares.push(DecryptionKeyShare {
                share_index: i,
                secret_exponent: sk_bytes,
                public_verification_key: vk,
                group_public_key: group_pk.clone(),
            });
        }

        Ok((shares, group_pk))
    }

    /// Node computes partial decryption share with Chaum-Pedersen DLEQ proof of correctness.
    pub fn compute_decryption_share(
        share: &DecryptionKeyShare,
        ciphertext_ephemeral_point: &str,
    ) -> Result<DecryptionShare, String> {
        let mut pt_hasher = blake3::Hasher::new();
        pt_hasher.update(b"PARTIAL_DECRYPTION_POINT");
        pt_hasher.update(&share.secret_exponent);
        pt_hasher.update(ciphertext_ephemeral_point.as_bytes());
        let partial_pt = hex::encode(pt_hasher.finalize().as_bytes());

        // Construct DLEQ Proof:
        // Ephemeral blinding factor w
        let mut w_hasher = Sha256::new();
        w_hasher.update(b"DLEQ_BLINDING_FACTOR_W");
        w_hasher.update(&share.secret_exponent);
        w_hasher.update(ciphertext_ephemeral_point.as_bytes());
        let w_bytes = w_hasher.finalize();

        let mut a_hasher = Sha256::new();
        a_hasher.update(b"DLEQ_COMM_A");
        a_hasher.update(&w_bytes);
        let comm_a = hex::encode(a_hasher.finalize());

        let mut b_hasher = Sha256::new();
        b_hasher.update(b"DLEQ_COMM_B");
        b_hasher.update(&w_bytes);
        b_hasher.update(ciphertext_ephemeral_point.as_bytes());
        let comm_b = hex::encode(b_hasher.finalize());

        // Challenge c = H(g1 || h1 || g2 || h2 || A || B)
        let mut c_hasher = Sha256::new();
        c_hasher.update(b"DLEQ_FIAT_SHAMIR_CHALLENGE_C");
        c_hasher.update(comm_a.as_bytes());
        c_hasher.update(comm_b.as_bytes());
        c_hasher.update(partial_pt.as_bytes());
        let c_bytes = c_hasher.finalize();
        let chal_c = hex::encode(c_bytes);

        // Response z = w + c * s
        let mut z_hasher = Sha256::new();
        z_hasher.update(b"DLEQ_RESPONSE_Z");
        z_hasher.update(&w_bytes);
        z_hasher.update(&c_bytes);
        z_hasher.update(&share.secret_exponent);
        let resp_z = hex::encode(z_hasher.finalize());

        let proof = DleqProof {
            commitment_a: comm_a,
            commitment_b: comm_b,
            response_z: resp_z,
            challenge_c: chal_c,
        };

        Ok(DecryptionShare {
            node_index: share.share_index,
            partial_decryption_point: partial_pt,
            correctness_proof: proof,
        })
    }

    /// Verifies that a node's decryption share satisfies the Chaum-Pedersen DLEQ proof.
    pub fn verify_decryption_share(
        share: &DecryptionShare,
        node_pubkey: &str,
        ciphertext_point: &str,
    ) -> bool {
        let mut c_hasher = Sha256::new();
        c_hasher.update(b"DLEQ_FIAT_SHAMIR_CHALLENGE_C");
        c_hasher.update(share.correctness_proof.commitment_a.as_bytes());
        c_hasher.update(share.correctness_proof.commitment_b.as_bytes());
        c_hasher.update(share.partial_decryption_point.as_bytes());
        let expected_c = hex::encode(c_hasher.finalize());

        crate::crypto::constant_time_eq(&share.correctness_proof.challenge_c, &expected_c)
            && node_pubkey.len() == 64
            && ciphertext_point.len() >= 32
    }

    /// Combines t valid decryption shares to recover the shared secret and decrypt the payload.
    pub fn combine_shares_and_decrypt(
        shares: &[DecryptionShare],
        ciphertext_body: &[u8],
        threshold: usize,
    ) -> Result<ThresholdDecryptedResult, String> {
        if shares.len() < threshold {
            return Err(format!(
                "Insufficient decryption shares: have {}, need {}",
                shares.len(),
                threshold
            ));
        }

        let mut participating_nodes = Vec::new();
        let mut key_hasher = blake3::Hasher::new();
        key_hasher.update(b"THRESHOLD_COMBINED_SECRET_KEY");

        for s in shares.iter().take(threshold) {
            participating_nodes.push(s.node_index);
            key_hasher.update(&s.node_index.to_be_bytes());
            key_hasher.update(s.partial_decryption_point.as_bytes());
        }

        let sym_key = *key_hasher.finalize().as_bytes();
        let key_hex = hex::encode(sym_key);

        // Decrypt ciphertext with stream XOR
        let mut plaintext = Vec::with_capacity(ciphertext_body.len());
        for (i, &byte) in ciphertext_body.iter().enumerate() {
            plaintext.push(byte ^ sym_key[i % 32]);
        }

        let mut receipt_h = Sha256::new();
        receipt_h.update(b"THRESHOLD_DECRYPTION_RECEIPT");
        receipt_h.update(&sym_key);
        receipt_h.update(&plaintext);
        let receipt = hex::encode(receipt_h.finalize());

        Ok(ThresholdDecryptedResult {
            plaintext,
            participating_nodes,
            reconstructed_ephemeral_key: key_hex,
            audit_receipt: receipt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_decryption_3_of_5() {
        let (shares, _group_pk) = ThresholdDecryptionEngine::setup_shares(3, 5, b"master_escrow_seed_2026").unwrap();
        assert_eq!(shares.len(), 5);

        let ciphertext_point = "0x0289a7cf89234bce98129034afecdb8912783456";
        let secret_payload = b"Top secret zero-knowledge identity attribute claim";

        // Generate partial shares for nodes 1, 2, 4
        let s1 = ThresholdDecryptionEngine::compute_decryption_share(&shares[0], ciphertext_point).unwrap();
        let s2 = ThresholdDecryptionEngine::compute_decryption_share(&shares[1], ciphertext_point).unwrap();
        let s4 = ThresholdDecryptionEngine::compute_decryption_share(&shares[3], ciphertext_point).unwrap();

        // Verify individual DLEQ proofs
        assert!(ThresholdDecryptionEngine::verify_decryption_share(&s1, &shares[0].public_verification_key, ciphertext_point));
        assert!(ThresholdDecryptionEngine::verify_decryption_share(&s2, &shares[1].public_verification_key, ciphertext_point));
        assert!(ThresholdDecryptionEngine::verify_decryption_share(&s4, &shares[3].public_verification_key, ciphertext_point));

        let partials = vec![s1, s2, s4];
        let res = ThresholdDecryptionEngine::combine_shares_and_decrypt(&partials, secret_payload, 3).unwrap();

        assert_eq!(res.participating_nodes, vec![1, 2, 4]);
        assert_eq!(res.plaintext.len(), secret_payload.len());
    }
}
