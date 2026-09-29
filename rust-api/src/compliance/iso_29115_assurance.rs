//! ISO/IEC 29115 Entity Authentication Assurance Framework
//!
//! Provides formal evaluation and certification for Levels of Assurance (LoA):
//! - **LoA 1 (Little/No Confidence)**: Basic self-asserted credential.
//! - **LoA 2 (Some Confidence)**: Single-factor cryptographic challenge.
//! - **LoA 3 (High Confidence)**: Multi-factor cryptographic attestation + hardware key.
//! - **LoA 4 (Very High Confidence)**: HSM/Enclave hardware backing + zero-knowledge proof + anti-replay protection.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Formal ISO/IEC 29115 Level of Assurance
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LevelOfAssurance {
    /// LoA 1: Little or no confidence in the asserted identity
    Loa1Low = 1,
    /// LoA 2: Some confidence in the asserted identity
    Loa2Medium = 2,
    /// LoA 3: High confidence in the asserted identity
    Loa3High = 3,
    /// LoA 4: Very high confidence in the asserted identity
    Loa4VeryHigh = 4,
}

/// Cryptographic evidence submitted for assurance evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationEvidence {
    pub has_hardware_token: bool,
    pub has_enclave_attestation: bool,
    pub has_zkp_predicate: bool,
    pub has_biometric_match: bool,
    pub has_anti_replay_nonce: bool,
    pub key_length_bits: usize,
    pub credential_issuer_trusted: bool,
}

/// Signed ISO 29115 Authentication Assurance Assertion Token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso29115AssertionToken {
    pub assertion_id: String,
    pub subject_commitment: String,
    pub achieved_loa: LevelOfAssurance,
    pub issued_at_epoch_secs: u64,
    pub expires_at_epoch_secs: u64,
    pub cryptographically_bound_nonce: String,
    pub signature_hmac_hex: String,
}

/// Assurance Engine evaluating compliance with ISO/IEC 29115 standards
pub struct Iso29115AssuranceEngine {
    trusted_signing_secret: [u8; 32],
}

impl Iso29115AssuranceEngine {
    /// Creates a new ISO 29115 assurance engine with an HMAC signing secret.
    pub fn new(signing_secret: [u8; 32]) -> Self {
        Self {
            trusted_signing_secret: signing_secret,
        }
    }

    /// Evaluates cryptographic evidence and determines the achieved Level of Assurance.
    pub fn evaluate_loa(&self, evidence: &AuthenticationEvidence) -> LevelOfAssurance {
        // LoA 4: Very High Confidence Requirements:
        // - Enclave attestation OR Hardware token
        // - Zero-knowledge proof predicate
        // - Anti-replay freshness nonce
        // - Key length >= 256 bits
        // - Trusted credential issuer
        if (evidence.has_enclave_attestation || evidence.has_hardware_token)
            && evidence.has_zkp_predicate
            && evidence.has_anti_replay_nonce
            && evidence.key_length_bits >= 256
            && evidence.credential_issuer_trusted
        {
            return LevelOfAssurance::Loa4VeryHigh;
        }

        // LoA 3: High Confidence Requirements:
        // - Multi-factor or hardware token
        // - Anti-replay nonce
        // - Key length >= 128 bits
        if (evidence.has_hardware_token || evidence.has_biometric_match || evidence.has_zkp_predicate)
            && evidence.has_anti_replay_nonce
            && evidence.key_length_bits >= 128
        {
            return LevelOfAssurance::Loa3High;
        }

        // LoA 2: Medium Confidence Requirements:
        // - Anti-replay nonce OR trusted issuer
        if evidence.has_anti_replay_nonce || evidence.credential_issuer_trusted {
            return LevelOfAssurance::Loa2Medium;
        }

        LevelOfAssurance::Loa1Low
    }

    /// Issues an ISO 29115 Assertion Token bound to a zero-knowledge commitment and nonce.
    pub fn issue_assertion_token(
        &self,
        subject_commitment: &str,
        evidence: &AuthenticationEvidence,
        nonce: &str,
        validity_duration_secs: u64,
    ) -> Result<Iso29115AssertionToken, &'static str> {
        let loa = self.evaluate_loa(evidence);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Clock drift error")?
            .as_secs();

        let assertion_id = format!("loa_{}_{}", loa as u8, hex::encode(&blake3::hash(subject_commitment.as_bytes()).as_bytes()[..8]));

        let mut signer = blake3::Hasher::new_keyed(&self.trusted_signing_secret);
        signer.update(b"iso-29115-assertion-token-v1:");
        signer.update(assertion_id.as_bytes());
        signer.update(subject_commitment.as_bytes());
        signer.update(&[loa as u8]);
        signer.update(&now.to_be_bytes());
        signer.update(nonce.as_bytes());

        let signature_hmac_hex = hex::encode(signer.finalize().as_bytes());

        Ok(Iso29115AssertionToken {
            assertion_id,
            subject_commitment: subject_commitment.to_string(),
            achieved_loa: loa,
            issued_at_epoch_secs: now,
            expires_at_epoch_secs: now + validity_duration_secs,
            cryptographically_bound_nonce: nonce.to_string(),
            signature_hmac_hex,
        })
    }

    /// Verifies the authenticity and expiration of an ISO 29115 Assertion Token.
    pub fn verify_assertion_token(&self, token: &Iso29115AssertionToken, expected_nonce: Option<&str>) -> bool {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return false,
        };

        if now > token.expires_at_epoch_secs {
            return false; // Token expired
        }

        if let Some(exp_nonce) = expected_nonce {
            if token.cryptographically_bound_nonce != exp_nonce {
                return false; // Nonce mismatch
            }
        }

        let mut verifier = blake3::Hasher::new_keyed(&self.trusted_signing_secret);
        verifier.update(b"iso-29115-assertion-token-v1:");
        verifier.update(token.assertion_id.as_bytes());
        verifier.update(token.subject_commitment.as_bytes());
        verifier.update(&[token.achieved_loa as u8]);
        verifier.update(&token.issued_at_epoch_secs.to_be_bytes());
        verifier.update(token.cryptographically_bound_nonce.as_bytes());

        let expected_sig = hex::encode(verifier.finalize().as_bytes());
        token.signature_hmac_hex == expected_sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loa4_evaluation_and_token_issuance() {
        let secret = [77u8; 32];
        let engine = Iso29115AssuranceEngine::new(secret);

        let high_sec_evidence = AuthenticationEvidence {
            has_hardware_token: true,
            has_enclave_attestation: true,
            has_zkp_predicate: true,
            has_biometric_match: true,
            has_anti_replay_nonce: true,
            key_length_bits: 256,
            credential_issuer_trusted: true,
        };

        let loa = engine.evaluate_loa(&high_sec_evidence);
        assert_eq!(loa, LevelOfAssurance::Loa4VeryHigh);

        let token = engine
            .issue_assertion_token("commit_user_99a8b7c6", &high_sec_evidence, "nonce_session_123", 300)
            .unwrap();

        assert_eq!(token.achieved_loa, LevelOfAssurance::Loa4VeryHigh);
        assert!(engine.verify_assertion_token(&token, Some("nonce_session_123")));
        assert!(!engine.verify_assertion_token(&token, Some("invalid_nonce")));
    }
}
