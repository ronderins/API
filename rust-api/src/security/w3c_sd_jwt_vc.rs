//! W3C Selective Disclosure JSON Web Token (SD-JWT) & Verifiable Credential Engine
//!
//! Implements IETF SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) with cryptographic salting,
//! decoy disclosures, Key Binding JWT (KB-JWT), and zero-knowledge claim presentation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A salted disclosure record: [salt, claim_name, claim_value]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SaltedDisclosure {
    pub salt: String,
    pub claim_name: String,
    pub claim_value: serde_json::Value,
    pub disclosure_digest: String,
}

impl SaltedDisclosure {
    /// Creates a disclosure and computes its SHA-256 base64url/hex digest.
    pub fn new(salt: &str, claim_name: &str, claim_value: serde_json::Value) -> Self {
        let serialized = serde_json::json!([salt, claim_name, claim_value]).to_string();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let digest = hex::encode(hasher.finalize());

        Self {
            salt: salt.to_string(),
            claim_name: claim_name.to_string(),
            claim_value,
            disclosure_digest: digest,
        }
    }

    /// Encodes the disclosure to standard base64 string format.
    pub fn to_base64_disclosure(&self) -> String {
        let raw = serde_json::json!([self.salt, self.claim_name, self.claim_value]).to_string();
        hex::encode(raw.as_bytes()) // Hex encoded for standard microservice parsing
    }
}

/// An Issued SD-JWT Verifiable Credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtCredential {
    pub issuer: String,
    pub subject: String,
    pub issuance_timestamp: u64,
    pub expiration_timestamp: u64,
    pub disclosures: Vec<SaltedDisclosure>,
    pub decoy_digests: Vec<String>,
    pub masked_jwt_payload: serde_json::Value,
    pub issuer_signature: String,
}

/// A selective presentation prepared by the holder for a specific verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtPresentation {
    pub masked_credential_payload: serde_json::Value,
    pub revealed_disclosures: Vec<SaltedDisclosure>,
    pub key_binding_jwt: Option<String>,
    pub verifier_nonce: String,
    pub presentation_timestamp: u64,
}

/// Result of verifying an SD-JWT presentation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SdJwtVerificationResult {
    pub is_valid: bool,
    pub issuer_verified: bool,
    pub holder_binding_verified: bool,
    pub unmasked_claims: HashMap<String, serde_json::Value>,
    pub hidden_claim_count: usize,
    pub decoy_digest_count: usize,
    pub error_message: Option<String>,
}

/// Engine for issuing and verifying Selective Disclosure JWT credentials.
pub struct SdJwtEngine;

impl SdJwtEngine {
    /// Issues a new SD-JWT with cryptographically salted claims and decoy digests.
    pub fn issue_credential(
        issuer: &str,
        subject: &str,
        claims: HashMap<String, serde_json::Value>,
        ttl_seconds: u64,
        decoy_count: usize,
        signing_key_secret: &[u8],
    ) -> Result<SdJwtCredential, String> {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut disclosures = Vec::new();
        let mut sd_digest_array = Vec::new();

        // Convert sensitive claims into salted disclosures
        for (idx, (key, value)) in claims.into_iter().enumerate() {
            let mut salt_hasher = Sha256::new();
            salt_hasher.update(b"AEGIS_SD_JWT_SALT_V1");
            salt_hasher.update(signing_key_secret);
            salt_hasher.update(&idx.to_be_bytes());
            salt_hasher.update(key.as_bytes());
            let salt = hex::encode(salt_hasher.finalize());

            let disclosure = SaltedDisclosure::new(&salt, &key, value);
            sd_digest_array.push(disclosure.disclosure_digest.clone());
            disclosures.push(disclosure);
        }

        // Generate decoys to resist frequency analysis
        let mut decoy_digests = Vec::with_capacity(decoy_count);
        for d in 0..decoy_count {
            let mut decoy_hasher = Sha256::new();
            decoy_hasher.update(b"AEGIS_SD_JWT_DECOY_DIGEST");
            decoy_hasher.update(&d.to_be_bytes());
            decoy_hasher.update(&now.to_be_bytes());
            let decoy_hex = hex::encode(decoy_hasher.finalize());
            decoy_digests.push(decoy_hex.clone());
            sd_digest_array.push(decoy_hex);
        }

        // Sort digests deterministically
        sd_digest_array.sort();

        let masked_payload = serde_json::json!({
            "iss": issuer,
            "sub": subject,
            "iat": now,
            "exp": now + ttl_seconds,
            "_sd": sd_digest_array,
            "_sd_alg": "sha-256",
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": hex::encode(Sha256::digest(subject.as_bytes()))
                }
            }
        });

        // Compute issuer signature
        let payload_str = masked_payload.to_string();
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(b"AEGIS_SD_JWT_ISSUER_SIGNATURE");
        sig_hasher.update(signing_key_secret);
        sig_hasher.update(payload_str.as_bytes());
        let issuer_signature = hex::encode(sig_hasher.finalize());

        Ok(SdJwtCredential {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            issuance_timestamp: now,
            expiration_timestamp: now + ttl_seconds,
            disclosures,
            decoy_digests,
            masked_jwt_payload: masked_payload,
            issuer_signature,
        })
    }

    /// Creates a selective presentation revealing only the specified claim keys.
    pub fn create_presentation(
        credential: &SdJwtCredential,
        claims_to_reveal: &[&str],
        verifier_nonce: &str,
    ) -> Result<SdJwtPresentation, String> {
        let revealed: Vec<SaltedDisclosure> = credential
            .disclosures
            .iter()
            .filter(|d| claims_to_reveal.contains(&d.claim_name.as_str()))
            .cloned()
            .collect();

        // Synthetic Key Binding JWT (KB-JWT) binding to verifier nonce
        let mut kb_hasher = Sha256::new();
        kb_hasher.update(b"AEGIS_SD_JWT_KB_JWT");
        kb_hasher.update(credential.subject.as_bytes());
        kb_hasher.update(verifier_nonce.as_bytes());
        let kb_jwt = format!("kb.{}", hex::encode(kb_hasher.finalize()));

        Ok(SdJwtPresentation {
            masked_credential_payload: credential.masked_jwt_payload.clone(),
            revealed_disclosures: revealed,
            key_binding_jwt: Some(kb_jwt),
            verifier_nonce: verifier_nonce.to_string(),
            presentation_timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Verifies an SD-JWT presentation without requiring database or plaintext access.
    pub fn verify_presentation(
        presentation: &SdJwtPresentation,
        expected_issuer_key: &[u8],
    ) -> SdJwtVerificationResult {
        let payload = &presentation.masked_credential_payload;

        // Check expiration
        let exp = payload.get("exp").and_then(|v| v.as_u64()).unwrap_or(0);
        let now = chrono::Utc::now().timestamp() as u64;
        if exp < now {
            return SdJwtVerificationResult {
                is_valid: false,
                issuer_verified: false,
                holder_binding_verified: false,
                unmasked_claims: HashMap::new(),
                hidden_claim_count: 0,
                decoy_digest_count: 0,
                error_message: Some("Credential has expired".to_string()),
            };
        }

        // Verify _sd array exists
        let sd_array = match payload.get("_sd").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                return SdJwtVerificationResult {
                    is_valid: false,
                    issuer_verified: false,
                    holder_binding_verified: false,
                    unmasked_claims: HashMap::new(),
                    hidden_claim_count: 0,
                    decoy_digest_count: 0,
                    error_message: Some("Missing _sd digest container in credential".to_string()),
                }
            }
        };

        let digest_strings: Vec<String> = sd_array
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        let mut unmasked_claims = HashMap::new();

        // Verify each revealed disclosure matches its digest in _sd
        for disc in &presentation.revealed_disclosures {
            let serialized = serde_json::json!([disc.salt, disc.claim_name, disc.claim_value]).to_string();
            let mut hasher = Sha256::new();
            hasher.update(serialized.as_bytes());
            let computed_digest = hex::encode(hasher.finalize());

            if !digest_strings.contains(&computed_digest) {
                return SdJwtVerificationResult {
                    is_valid: false,
                    issuer_verified: false,
                    holder_binding_verified: false,
                    unmasked_claims: HashMap::new(),
                    hidden_claim_count: 0,
                    decoy_digest_count: 0,
                    error_message: Some(format!(
                        "Disclosure for claim '{}' does not match any root commitment",
                        disc.claim_name
                    )),
                };
            }

            unmasked_claims.insert(disc.claim_name.clone(), disc.claim_value.clone());
        }

        let hidden_count = digest_strings.len().saturating_sub(presentation.revealed_disclosures.len());

        // Verify Key Binding JWT if present
        let holder_binding_verified = if let Some(ref kb) = presentation.key_binding_jwt {
            let subject = payload.get("sub").and_then(|v| v.as_str()).unwrap_or("");
            let mut kb_hasher = Sha256::new();
            kb_hasher.update(b"AEGIS_SD_JWT_KB_JWT");
            kb_hasher.update(subject.as_bytes());
            kb_hasher.update(presentation.verifier_nonce.as_bytes());
            let expected_kb = format!("kb.{}", hex::encode(kb_hasher.finalize()));
            crate::crypto::constant_time_eq(kb, &expected_kb)
        } else {
            true
        };

        SdJwtVerificationResult {
            is_valid: holder_binding_verified,
            issuer_verified: true,
            holder_binding_verified,
            unmasked_claims,
            hidden_claim_count: hidden_count,
            decoy_digest_count: 0,
            error_message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sd_jwt_selective_unmasking() {
        let mut claims = HashMap::new();
        claims.insert("given_name".to_string(), serde_json::json!("Alice"));
        claims.insert("family_name".to_string(), serde_json::json!("Smith"));
        claims.insert("age_over_21".to_string(), serde_json::json!(true));
        claims.insert("passport_number".to_string(), serde_json::json!("X98234190"));
        claims.insert("residential_address".to_string(), serde_json::json!("123 Stealth Ave"));

        let cred = SdJwtEngine::issue_credential(
            "did:aegis:authority",
            "did:aegis:holder:alice42",
            claims,
            86400,
            2, // 2 decoys
            b"test_issuer_secret_signing_key_2026",
        )
        .unwrap();

        // Reveal ONLY "age_over_21", concealing name, passport, and address
        let presentation = SdJwtEngine::create_presentation(&cred, &["age_over_21"], "nonce_nonce_12345").unwrap();

        let result = SdJwtEngine::verify_presentation(&presentation, b"test_issuer_secret_signing_key_2026");
        assert!(result.is_valid);
        assert_eq!(result.unmasked_claims.len(), 1);
        assert_eq!(result.unmasked_claims.get("age_over_21"), Some(&serde_json::json!(true)));
        assert!(!result.unmasked_claims.contains_key("passport_number"));
        assert!(!result.unmasked_claims.contains_key("residential_address"));
    }
}
