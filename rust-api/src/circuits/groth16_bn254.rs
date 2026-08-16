//! Groth16 zk-SNARK Synthesizer and BN254 Verifier Interface
//!
//! Exposes top-level SNARK verification for zero-knowledge identity statements.

use crate::zkp::bn254::{Groth16Proof, Groth16VerifyingKey, U256};

pub struct Groth16IdentityVerifier {
    pub vk: Groth16VerifyingKey,
}

impl Groth16IdentityVerifier {
    pub fn new(vk: Groth16VerifyingKey) -> Self {
        Self { vk }
    }

    /// Performs bilinear pairing check on the supplied Groth16 zk-SNARK proof
    pub fn verify_identity_proof(
        &self,
        proof: &Groth16Proof,
        public_inputs: &[U256],
    ) -> Result<bool, &'static str> {
        self.vk.verify_proof(proof, public_inputs)
    }
}
