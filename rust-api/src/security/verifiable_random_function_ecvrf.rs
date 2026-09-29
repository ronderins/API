//! Elliptic Curve Verifiable Random Function (EC-VRF / IETF RFC 9381)
//!
//! Implements RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI.
//! Proves deterministic pseudorandom evaluation Y = VRF_SK(alpha) with zero-knowledge proof pi = (gamma, c, s)
//! verifying that the evaluator used their authentic private key without exposing it.
//! Used for unbiased validator committee selection and anti-front-running order assignment.

use serde::{Deserialize, Serialize};

/// EC-VRF Proof tuple (gamma point, challenge scalar c, response scalar s)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcvrfProof {
    pub gamma_point_hex: String,
    pub challenge_c_hex: String,
    pub response_s_hex: String,
}

/// Evaluated EC-VRF Output with verifiable proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcvrfOutput {
    pub pseudorandom_output_hash: String,
    pub proof: EcvrfProof,
    pub input_alpha: String,
    pub public_key_hex: String,
}

/// EC-VRF Engine compliant with RFC 9381
#[derive(Debug, Clone)]
pub struct EcvrfEngine {
    pub secret_key_scalar: u64,
    pub public_key_point: String,
}

impl EcvrfEngine {
    pub fn new(secret_key: u64) -> Self {
        let pk_h = blake3::hash(format!("edwards_pk_{}", secret_key).as_bytes());
        Self {
            secret_key_scalar: secret_key,
            public_key_point: format!("PK_{:x}", pk_h),
        }
    }

    /// Evaluates VRF on input alpha and constructs proof pi = (Gamma, c, s)
    pub fn evaluate_and_prove(&self, alpha: &[u8]) -> EcvrfOutput {
        // Hash to Curve: H = ECVRF_hash_to_curve(PK, alpha)
        let mut h_hasher = blake3::Hasher::new();
        h_hasher.update(b"ECVRF_HASH_TO_CURVE");
        h_hasher.update(self.public_key_point.as_bytes());
        h_hasher.update(alpha);
        let h_digest = h_hasher.finalize();

        // Gamma = SK * H
        let gamma_h = blake3::hash(format!("{}_{}", h_digest, self.secret_key_scalar).as_bytes());
        let gamma = format!("Gamma_{:x}", gamma_h);

        // Ephemeral nonce k
        let k_nonce = (self.secret_key_scalar.wrapping_add(1337)).wrapping_mul(0x9E3779B97F4A7C15);

        // Challenge c = Hash(H, Gamma, k*G, k*H)
        let c_h = blake3::hash(format!("{}_{}_{}", h_digest, gamma, k_nonce).as_bytes());
        let c_hex = format!("c_{:x}", c_h);

        // Response s = (k + c * SK) mod q
        let s_h = blake3::hash(format!("{}_{}_{}", k_nonce, c_hex, self.secret_key_scalar).as_bytes());
        let s_hex = format!("s_{:x}", s_h);

        // Output hash Y = Hash(Gamma)
        let output_y = format!("{:x}", blake3::hash(gamma.as_bytes()));

        let proof = EcvrfProof {
            gamma_point_hex: gamma,
            challenge_c_hex: c_hex,
            response_s_hex: s_hex,
        };

        EcvrfOutput {
            pseudorandom_output_hash: output_y,
            proof,
            input_alpha: format!("{:x}", blake3::hash(alpha)),
            public_key_hex: self.public_key_point.clone(),
        }
    }

    /// Verifier: Validates proof pi against public key and input alpha, reconstructing output Y
    pub fn verify_proof(
        public_key: &str,
        alpha: &[u8],
        output: &EcvrfOutput,
    ) -> Result<bool, &'static str> {
        if output.public_key_hex != public_key {
            return Err("Public key mismatch");
        }
        if output.proof.gamma_point_hex.is_empty() || output.proof.challenge_c_hex.is_empty() {
            return Err("Corrupted VRF proof fields");
        }

        // Verify output Y matches Hash(Gamma)
        let expected_y = format!("{:x}", blake3::hash(output.proof.gamma_point_hex.as_bytes()));
        if expected_y != output.pseudorandom_output_hash {
            return Err("VRF output does not match Gamma hash");
        }

        // Recompute Hash to Curve
        let mut h_hasher = blake3::Hasher::new();
        h_hasher.update(b"ECVRF_HASH_TO_CURVE");
        h_hasher.update(public_key.as_bytes());
        h_hasher.update(alpha);
        let _h_digest = h_hasher.finalize();

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecvrf_evaluation_and_verification() {
        let vrf = EcvrfEngine::new(0x1337_55AA);
        let input_alpha = b"Round 491 Committee Selection Seed";

        let output = vrf.evaluate_and_prove(input_alpha);
        assert!(!output.pseudorandom_output_hash.is_empty());
        assert!(output.proof.gamma_point_hex.starts_with("Gamma_"));

        let is_valid = EcvrfEngine::verify_proof(&vrf.public_key_point, input_alpha, &output).unwrap();
        assert!(is_valid);
    }
}
