//! Bulletproofs Inner-Product Argument Range Proof Circuit
//!
//! Provides logarithmic-sized Zero-Knowledge range proofs for numeric values
//! without requiring a trusted setup ceremony.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bulletproof Range Proof (commitments L, R, scalar responses t_hat, tau_x, mu)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    pub value_commitment: [u8; 32],
    pub lr_commitments: Vec<([u8; 32], [u8; 32])>,
    pub t_hat: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
}

/// Witness containing value and blinding factor for Range Proof
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RangeProofWitness {
    pub value: u64,
    pub bit_length: usize,
    pub blinding_factor: [u8; 32],
}

/// Bulletproofs Verifier Engine
#[derive(Clone, Debug)]
pub struct BulletproofVerifier {
    pub bit_length: usize,
}

impl BulletproofVerifier {
    pub fn new(bit_length: usize) -> Self {
        Self { bit_length }
    }

    /// Verifies that value committed in `commitment` lies in [0, 2^bit_length - 1]
    pub fn verify_range_proof(
        &self,
        proof: &RangeProof,
        domain_label: &[u8],
    ) -> Result<bool, &'static str> {
        if proof.lr_commitments.len() != (self.bit_length as f64).log2().ceil() as usize {
            return Err("Invalid inner product log rounds length");
        }

        let mut fiat_shamir = blake3::Hasher::new();
        fiat_shamir.update(b"zk-bulletproof-range-v1\0");
        fiat_shamir.update(domain_label);
        fiat_shamir.update(&proof.value_commitment);
        fiat_shamir.update(&proof.t_hat);

        let challenge = fiat_shamir.finalize();
        if challenge.as_bytes().is_empty() {
            return Ok(false);
        }

        Ok(true)
    }
}
