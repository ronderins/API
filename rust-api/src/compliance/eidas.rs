//! eIDAS 2.0 & W3C Verifiable Credentials Selective Disclosure Framework
//!
//! Provides compliance data models and cryptographic proof wrappers
//! adhering to eIDAS High Level of Assurance (LoA) requirements
//! and EU Digital Identity Wallet (EUDIW) selective disclosure specifications.

use serde::{Deserialize, Serialize};

/// W3C Verifiable Credential Header with Zero-Knowledge Proof Envelope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EidasVerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub credential_types: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: EidasCredentialSubject,
    pub proof: ZkCredentialProofEnvelope,
}

/// Disclosed Attribute Claims (Selective Disclosure)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EidasCredentialSubject {
    pub id: String, // Decentralized Identifier (DID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_over_18: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_over_21: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality_iso_3166: Option<String>,
    pub nullifier_hash: String,
}

/// Zero-Knowledge Proof Envelope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkCredentialProofEnvelope {
    #[serde(rename = "type")]
    pub proof_type: String, // "Groth16Bn254Proof2026"
    pub created: String,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String,
}

pub struct EidasVerifier;

impl EidasVerifier {
    /// Validates compliance metadata and proof envelope
    pub fn validate_eidas_envelope(vc: &EidasVerifiableCredential) -> bool {
        if !vc.credential_types.contains(&"VerifiableCredential".to_string()) {
            return false;
        }

        if vc.credential_subject.nullifier_hash.len() != 64 {
            return false;
        }

        !vc.proof.proof_value.is_empty()
    }
}
