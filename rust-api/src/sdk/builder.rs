//! Fluent Proof Request Builder for ZK Identity Predicates
//!
//! Construct cryptographic verification queries (age thresholds, nationality inclusion, OFAC exclusion)
//! with compile-time type safety.

use crate::models::{ProofMode, VerifyProofRequest};

pub struct ProofRequestBuilder {
    pub proof_mode: ProofMode,
    pub session_id: Option<String>,
    pub birth_year: Option<u32>,
    pub current_year: Option<u32>,
    pub threshold: Option<u32>,
    pub nationality: Option<String>,
    pub allowed_countries: Option<Vec<String>>,
    pub sanctions_merkle_root: Option<String>,
    pub document_type: Option<String>,
    pub user_salt_hex: Option<String>,
    pub simulate_tampering: Option<bool>,
}

impl Default for ProofRequestBuilder {
    fn default() -> Self {
        Self {
            proof_mode: ProofMode::AgeOnly,
            session_id: None,
            birth_year: Some(2000),
            current_year: Some(2026),
            threshold: Some(18),
            nationality: Some("US".to_string()),
            allowed_countries: None,
            sanctions_merkle_root: None,
            document_type: Some("passport".to_string()),
            user_salt_hex: None,
            simulate_tampering: Some(false),
        }
    }
}

impl ProofRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(mut self, mode: ProofMode) -> Self {
        self.proof_mode = mode;
        self
    }

    pub fn session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }

    pub fn age_predicate(mut self, birth_year: u32, threshold: u32, current_year: u32) -> Self {
        self.birth_year = Some(birth_year);
        self.threshold = Some(threshold);
        self.current_year = Some(current_year);
        self
    }

    pub fn nationality_predicate(mut self, nationality: &str, allowed: &[&str]) -> Self {
        self.nationality = Some(nationality.to_string());
        self.allowed_countries = Some(allowed.iter().map(|&s| s.to_string()).collect());
        self
    }

    pub fn build(self) -> VerifyProofRequest {
        VerifyProofRequest {
            proof_mode: self.proof_mode,
            session_id: self.session_id,
            birth_year: self.birth_year,
            current_year: self.current_year,
            threshold: self.threshold,
            nationality: self.nationality,
            allowed_countries: self.allowed_countries,
            sanctions_merkle_root: self.sanctions_merkle_root,
            document_type: self.document_type,
            user_salt_hex: self.user_salt_hex,
            simulate_tampering: self.simulate_tampering,
        }
    }
}
