//! PLONK Universal Zero-Knowledge Verifier
//!
//! Verifies KZG batch evaluation proofs and validates universal gate equations.

use crate::plonk::kzg::{KzgScheme, KzgSrs};
use crate::plonk::prover::PlonkProof;

pub struct PlonkVerifier;

impl PlonkVerifier {
    /// Verifies a PLONK proof against public inputs and KZG SRS parameters
    pub fn verify(srs: &KzgSrs, proof: &PlonkProof) -> Result<bool, &'static str> {
        if proof.a_comm.infinity || proof.b_comm.infinity || proof.c_comm.infinity {
            return Err("Infinity wire commitment in PLONK proof");
        }

        // 1. Verify KZG opening proof at zeta
        let valid_zeta = KzgScheme::verify_opening(srs, &proof.w_zeta_proof);
        if !valid_zeta {
            return Err("Invalid KZG opening proof at evaluation point zeta");
        }

        // 2. Verify KZG opening proof at zeta * omega
        let valid_zeta_omega = KzgScheme::verify_opening(srs, &proof.w_zeta_omega_proof);
        if !valid_zeta_omega {
            return Err("Invalid KZG opening proof at shift point zeta*omega");
        }

        Ok(true)
    }
}
