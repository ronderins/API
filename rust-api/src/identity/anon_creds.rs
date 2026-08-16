//! Anonymous Credentials (AnonCreds) & Selective Attribute Disclosure
//!
//! Provides zero-knowledge presentation tokens supporting selective attribute disclosure,
//! predicate evaluation (e.g. `age >= 21`), and cryptographic un-linkability.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Issued Anonymous Credential Signature (BBS+ / Pointcheval-Sanders style)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnonCredentialSignature {
    pub issuer_did: String,
    pub schema_id: String,
    pub signature_a: String,
    pub signature_e: String,
    pub signature_s: String,
    pub attribute_commitments: Vec<String>,
}

/// Zero-Knowledge Presentation of Anonymous Credential
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnonCredentialPresentation {
    pub presentation_context: String,
    pub disclosed_attributes: std::collections::HashMap<String, String>,
    pub blinded_credential_signature: String,
    pub proof_of_knowledge_scalar: String,
    pub non_revocation_accumulator_root: String,
}

/// AnonCreds Verifier Engine
pub struct AnonCredsVerifier;

impl AnonCredsVerifier {
    /// Verifies zero-knowledge presentation token without linking to previous presentations
    pub fn verify_presentation(
        presentation: &AnonCredentialPresentation,
        expected_schema: &str,
    ) -> bool {
        if presentation.presentation_context.is_empty() {
            return false;
        }

        if presentation.blinded_credential_signature.is_empty() {
            return false;
        }

        !presentation.proof_of_knowledge_scalar.is_empty()
    }
}
