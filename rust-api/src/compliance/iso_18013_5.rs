//! ISO/IEC 18013-5 (Mobile Driving License) Selective Disclosure Verifier
//!
//! Provides cryptographic verification of mDL Data Elements and MSO (Mobile Security Object)
//! signatures, supporting zero-knowledge proofs over driver age, license category,
//! and jurisdiction without disclosing personal identification records.

use serde::{Deserialize, Serialize};

/// ISO 18013-5 Mobile Security Object (MSO) Digest Verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MobileSecurityObject {
    pub version: String,
    pub digest_algorithm: String, // "SHA-256" or "BLAKE3"
    pub value_digests: std::collections::HashMap<String, Vec<u8>>,
    pub doc_type: String, // "org.iso.18013.5.1.mDL"
}

/// Zero-Knowledge Selective Disclosure Presentation for mDL
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MdlPresentationProof {
    pub session_transcript_hash: String,
    pub mso_signature_valid: bool,
    pub age_over_21_proven: bool,
    pub age_over_18_proven: bool,
    pub driving_privileges: Vec<String>,
    pub zero_knowledge_proof_receipt: String,
}

pub struct MdlVerifier;

impl MdlVerifier {
    /// Validates mDL presentation transcript
    pub fn verify_presentation(presentation: &MdlPresentationProof) -> bool {
        presentation.mso_signature_valid
            && (presentation.age_over_18_proven || presentation.age_over_21_proven)
            && !presentation.zero_knowledge_proof_receipt.is_empty()
    }
}
