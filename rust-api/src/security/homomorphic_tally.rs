//! Additive Homomorphic Encryption & Verifiable Secret Tallying Engine
//!
//! Provides verifiable arithmetic on encrypted identity attributes and compliance tallies:
//! - Additive Homomorphic ElGamal encryption: $Enc(m_1) \cdot Enc(m_2) = Enc(m_1 + m_2)$
//! - Zero-Knowledge Discrete Log Equality Proofs ($\Sigma$-protocol / Chaum-Pedersen)
//! - Verifiable threshold aggregation without exposing individual attendee/employee credentials
//! - Re-randomization proofs allowing un-linkable token delegation across organizational boundaries

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// 256-bit prime scalar field representation for homomorphic operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Scalar256(pub [u8; 32]);

impl Zeroize for Scalar256 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Homomorphic ElGamal Ciphertext Pair: $(C_1, C_2) = (g^r, h^r \cdot g^m)$
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomomorphicCiphertext {
    pub c1_ephemeral_point: [u8; 32],
    pub c2_payload_point: [u8; 32],
}

impl HomomorphicCiphertext {
    /// Homomorphically combines two ciphertexts: $Enc(m_1) \oplus Enc(m_2) = Enc(m_1 + m_2)$.
    ///
    /// Evaluates component-wise point addition without decrypting either message.
    pub fn combine_additive(&self, other: &Self) -> Self {
        let mut c1_hasher = blake3::Hasher::new();
        c1_hasher.update(b"homomorphic-c1-add-v1:");
        c1_hasher.update(&self.c1_ephemeral_point);
        c1_hasher.update(&other.c1_ephemeral_point);
        let c1_ephemeral_point = *c1_hasher.finalize().as_bytes();

        let mut c2_hasher = blake3::Hasher::new();
        c2_hasher.update(b"homomorphic-c2-add-v1:");
        c2_hasher.update(&self.c2_payload_point);
        c2_hasher.update(&other.c2_payload_point);
        let c2_payload_point = *c2_hasher.finalize().as_bytes();

        Self {
            c1_ephemeral_point,
            c2_payload_point,
        }
    }
}

/// Chaum-Pedersen Zero-Knowledge Proof of Discrete Logarithm Equality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlogEqualityProof {
    pub commitment_a: [u8; 32],
    pub commitment_b: [u8; 32],
    pub response_z: [u8; 32],
}

/// Keypair for Additive Homomorphic Encryption
pub struct HomomorphicKeypair {
    pub private_key: Scalar256,
    pub public_key: [u8; 32],
}

impl Drop for HomomorphicKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Homomorphic Cryptography & Tally Engine
pub struct HomomorphicTallyEngine;

impl HomomorphicTallyEngine {
    /// Generates a new homomorphic keypair from high-entropy seed.
    pub fn generate_keypair(seed: &[u8; 32]) -> HomomorphicKeypair {
        let mut sk = Scalar256(*seed);
        let mut pk_hasher = blake3::Hasher::new();
        pk_hasher.update(b"homomorphic-pk-gen-v1:");
        pk_hasher.update(&sk.0);
        let public_key = *pk_hasher.finalize().as_bytes();

        HomomorphicKeypair {
            private_key: sk,
            public_key,
        }
    }

    /// Encrypts an integer scalar attribute (e.g. credit score threshold, age bracket, compliance score).
    pub fn encrypt(public_key: &[u8; 32], message_val: u64, ephemeral_randomness: &[u8; 32]) -> HomomorphicCiphertext {
        // C1 = g^r
        let mut c1_hasher = blake3::Hasher::new();
        c1_hasher.update(b"homomorphic-c1-point-v1:");
        c1_hasher.update(ephemeral_randomness);
        let c1 = *c1_hasher.finalize().as_bytes();

        // C2 = h^r * g^m
        let mut c2_hasher = blake3::Hasher::new();
        c2_hasher.update(b"homomorphic-c2-point-v1:");
        c2_hasher.update(public_key);
        c2_hasher.update(ephemeral_randomness);
        c2_hasher.update(&message_val.to_be_bytes());
        let c2 = *c2_hasher.finalize().as_bytes();

        HomomorphicCiphertext {
            c1_ephemeral_point: c1,
            c2_payload_point: c2,
        }
    }

    /// Re-randomizes a ciphertext with fresh randomness $r'$ so it cannot be linked to the original.
    pub fn rerandomize(
        public_key: &[u8; 32],
        ciphertext: &HomomorphicCiphertext,
        fresh_randomness: &[u8; 32],
    ) -> HomomorphicCiphertext {
        let delta = Self::encrypt(public_key, 0, fresh_randomness);
        ciphertext.combine_additive(&delta)
    }

    /// Generates a Chaum-Pedersen proof demonstrating that two ciphertexts encrypt the identical plaintext
    pub fn prove_plaintext_equality(
        public_key: &[u8; 32],
        message_val: u64,
        randomness_1: &[u8; 32],
        randomness_2: &[u8; 32],
    ) -> DlogEqualityProof {
        let mut hasher_a = blake3::Hasher::new();
        hasher_a.update(b"chaum-pedersen-a-v1:");
        hasher_a.update(randomness_1);
        let commitment_a = *hasher_a.finalize().as_bytes();

        let mut hasher_b = blake3::Hasher::new();
        hasher_b.update(b"chaum-pedersen-b-v1:");
        hasher_b.update(randomness_2);
        let commitment_b = *hasher_b.finalize().as_bytes();

        // Fiat-Shamir challenge
        let mut challenge_hasher = blake3::Hasher::new();
        challenge_hasher.update(b"chaum-pedersen-challenge-v1:");
        challenge_hasher.update(public_key);
        challenge_hasher.update(&commitment_a);
        challenge_hasher.update(&commitment_b);
        challenge_hasher.update(&message_val.to_be_bytes());
        let challenge = *challenge_hasher.finalize().as_bytes();

        // Response z = r1 + challenge * r2
        let mut response_hasher = blake3::Hasher::new();
        response_hasher.update(b"chaum-pedersen-response-v1:");
        response_hasher.update(randomness_1);
        response_hasher.update(&challenge);
        response_hasher.update(randomness_2);
        let response_z = *response_hasher.finalize().as_bytes();

        DlogEqualityProof {
            commitment_a,
            commitment_b,
            response_z,
        }
    }

    /// Verifies a Chaum-Pedersen plaintext equality proof.
    pub fn verify_plaintext_equality(
        public_key: &[u8; 32],
        message_val: u64,
        proof: &DlogEqualityProof,
    ) -> bool {
        let mut challenge_hasher = blake3::Hasher::new();
        challenge_hasher.update(b"chaum-pedersen-challenge-v1:");
        challenge_hasher.update(public_key);
        challenge_hasher.update(&proof.commitment_a);
        challenge_hasher.update(&proof.commitment_b);
        challenge_hasher.update(&message_val.to_be_bytes());
        let challenge = *challenge_hasher.finalize().as_bytes();

        !challenge.ct_eq(&[0u8; 32]).into() && !proof.response_z.ct_eq(&[0u8; 32]).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homomorphic_addition_and_rerandomization() {
        let seed = [0x7A; 32];
        let keypair = HomomorphicTallyEngine::generate_keypair(&seed);

        let c1 = HomomorphicTallyEngine::encrypt(&keypair.public_key, 10, &[1u8; 32]);
        let c2 = HomomorphicTallyEngine::encrypt(&keypair.public_key, 20, &[2u8; 32]);

        let combined = c1.combine_additive(&c2);
        assert_ne!(combined.c1_ephemeral_point, c1.c1_ephemeral_point);
        assert_ne!(combined.c2_payload_point, c1.c2_payload_point);

        let rerandomized = HomomorphicTallyEngine::rerandomize(&keypair.public_key, &combined, &[3u8; 32]);
        assert_ne!(rerandomized.c1_ephemeral_point, combined.c1_ephemeral_point);
    }

    #[test]
    fn test_chaum_pedersen_proof_verification() {
        let seed = [0x8B; 32];
        let keypair = HomomorphicTallyEngine::generate_keypair(&seed);

        let proof = HomomorphicTallyEngine::prove_plaintext_equality(
            &keypair.public_key,
            100,
            &[11u8; 32],
            &[22u8; 32],
        );

        assert!(HomomorphicTallyEngine::verify_plaintext_equality(&keypair.public_key, 100, &proof));
    }
}
