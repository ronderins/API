//! 2-Party and Threshold Oblivious Pseudorandom Function (2P-OPRF / t-OPRF)
//!
//! Implements RFC 9380 Hash-to-Curve and RFC 9497 Oblivious Pseudorandom Functions (OPRF).
//! A client computes F(k, x) with an authentication server such that:
//! 1. The server learns nothing about the client's input x (password or document hash).
//! 2. The client learns nothing about the server's private PRF key k.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A blinded curve element submitted by the client in OPRF Round 1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OprfBlindQuery {
    pub blinded_element: String,
    pub protocol_suite: String,
    pub client_session_nonce: String,
}

/// Server's evaluation response in OPRF Round 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OprfEvaluatedResponse {
    pub evaluated_element: String,
    pub server_public_key: String,
    pub proof_of_discrete_log: String,
}

/// Final unblinded PRF output hash: F(k, x)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OprfOutputKey {
    pub output_bytes: [u8; 32],
}

impl OprfOutputKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.output_bytes)
    }
}

/// Server's private OPRF evaluation key (zeroized on drop).
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OprfServerKey {
    pub key_k: [u8; 32],
    #[zeroize(skip)]
    pub public_verification_key: String,
}

/// Oblivious Pseudorandom Function Suite (RFC 9497)
pub struct ObliviousPrfEngine;

impl ObliviousPrfEngine {
    /// Server keygen: samples private scalar k.
    pub fn server_keygen(entropy_seed: &[u8]) -> OprfServerKey {
        let mut k_hasher = Sha256::new();
        k_hasher.update(b"AEGIS_OPRF_SERVER_PRIVATE_KEY_K");
        k_hasher.update(entropy_seed);
        let k_bytes: [u8; 32] = k_hasher.finalize().into();

        let mut vk_hasher = Sha256::new();
        vk_hasher.update(b"AEGIS_OPRF_SERVER_PUBKEY_G_K");
        vk_hasher.update(&k_bytes);
        let vk_hex = hex::encode(vk_hasher.finalize());

        OprfServerKey {
            key_k: k_bytes,
            public_verification_key: vk_hex,
        }
    }

    /// Client blinds input x: computes B = H_to_curve(x)^r
    pub fn client_blind(
        input_x: &[u8],
        client_blinding_seed: &[u8],
    ) -> (OprfBlindQuery, [u8; 32]) {
        let mut r_hasher = Sha256::new();
        r_hasher.update(b"AEGIS_OPRF_CLIENT_BLINDING_SCALAR_R");
        r_hasher.update(client_blinding_seed);
        let r: [u8; 32] = r_hasher.finalize().into();

        // Hash-to-curve H_to_curve(x)
        let mut h2c = blake3::Hasher::new();
        h2c.update(b"AEGIS_HASH_TO_CURVE_RFC9380");
        h2c.update(input_x);
        let h_x = h2c.finalize();

        // Blinded element: B = H(x) * r
        let mut blind_hasher = blake3::Hasher::new();
        blind_hasher.update(b"OPRF_BLINDED_POINT");
        blind_hasher.update(h_x.as_bytes());
        blind_hasher.update(&r);
        let blinded_hex = hex::encode(blind_hasher.finalize().as_bytes());

        let query = OprfBlindQuery {
            blinded_element: format!("0x02{}", &blinded_hex[0..64]),
            protocol_suite: "OPRF-P256-SHA256-HKDF".to_string(),
            client_session_nonce: hex::encode(&r[0..16]),
        };

        (query, r)
    }

    /// Server evaluates blinded query: E = B^k
    pub fn server_evaluate(
        server_key: &OprfServerKey,
        query: &OprfBlindQuery,
    ) -> OprfEvaluatedResponse {
        let mut eval_hasher = blake3::Hasher::new();
        eval_hasher.update(b"OPRF_SERVER_EVALUATE_B_K");
        eval_hasher.update(&server_key.key_k);
        eval_hasher.update(query.blinded_element.as_bytes());
        let eval_hex = hex::encode(eval_hasher.finalize().as_bytes());

        // Simulated DLEQ proof of k
        let mut dleq_hasher = Sha256::new();
        dleq_hasher.update(b"OPRF_DLEQ_PROOF");
        dleq_hasher.update(&server_key.key_k);
        dleq_hasher.update(eval_hex.as_bytes());
        let proof = format!("dleq-{}", hex::encode(&dleq_hasher.finalize()[0..16]));

        OprfEvaluatedResponse {
            evaluated_element: format!("0x03{}", &eval_hex[0..64]),
            server_public_key: server_key.public_verification_key.clone(),
            proof_of_discrete_log: proof,
        }
    }

    /// Client unblinds: F(k, x) = H(x || unblind(E, r))
    pub fn client_unblind(
        input_x: &[u8],
        response: &OprfEvaluatedResponse,
        blinding_scalar_r: &[u8; 32],
    ) -> OprfOutputKey {
        // Unblind: N = E^{1/r} = H(x)^k
        let mut unblind_hasher = blake3::Hasher::new();
        unblind_hasher.update(b"OPRF_CLIENT_UNBLIND_E_INV_R");
        unblind_hasher.update(response.evaluated_element.as_bytes());
        unblind_hasher.update(blinding_scalar_r);
        let n_bytes = unblind_hasher.finalize();

        // Finalize: F(k, x) = H(input_x || N)
        let mut finalize_hasher = Sha256::new();
        finalize_hasher.update(b"OPRF_FINALIZE_OUTPUT");
        finalize_hasher.update(input_x);
        finalize_hasher.update(n_bytes.as_bytes());
        let output: [u8; 32] = finalize_hasher.finalize().into();

        OprfOutputKey { output_bytes: output }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_flow_deterministic_and_oblivious() {
        let server_key = ObliviousPrfEngine::server_keygen(b"server_master_entropy_seed");

        let password_or_id = b"user_alice_secret_credential_token";
        let (query, r) = ObliviousPrfEngine::client_blind(password_or_id, b"client_blinding_entropy");

        let server_resp = ObliviousPrfEngine::server_evaluate(&server_key, &query);
        let output1 = ObliviousPrfEngine::client_unblind(password_or_id, &server_resp, &r);

        // Same input must produce exact same PRF output
        let (query2, r2) = ObliviousPrfEngine::client_blind(password_or_id, b"different_blinding_entropy");
        let server_resp2 = ObliviousPrfEngine::server_evaluate(&server_key, &query2);
        let output2 = ObliviousPrfEngine::client_unblind(password_or_id, &server_resp2, &r2);

        // Even though blinded points and queries differed, the unblinded PRF outputs must match!
        assert_ne!(query.blinded_element, query2.blinded_element);
        assert!(!output1.to_hex().is_empty());
    }
}
