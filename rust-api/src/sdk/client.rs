//! Official ZK-Auth Rust Asynchronous Client SDK
//!
//! Provides high-level asynchronous bindings for creating identity sessions,
//! requesting zero-knowledge proofs, polling validation receipts, and checking nullifier status.

use crate::models::{ProofReceipt, SessionResponse, VerifyProofRequest, VerifyProofResponse};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct ZkAuthClient {
    pub base_url: String,
    pub api_key: Option<String>,
}

impl ZkAuthClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    /// Initializes a one-time cryptographic blind verification QR session
    pub async fn create_session(&self) -> Result<SessionResponse, String> {
        let url = format!("{}/api/v1/session", self.base_url);
        let resp = reqwest::get(&url)
            .await
            .map_err(|e| format!("Failed to create session: {}", e))?;

        resp.json::<SessionResponse>()
            .await
            .map_err(|e| format!("Failed to parse session JSON: {}", e))
    }

    /// Submits a zero-knowledge proof request
    pub async fn verify_identity(
        &self,
        request: &VerifyProofRequest,
    ) -> Result<VerifyProofResponse, String> {
        let url = format!("{}/api/v1/verify", self.base_url);
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|e| format!("Verify request failed: {}", e))?;

        resp.json::<VerifyProofResponse>()
            .await
            .map_err(|e| format!("Failed to parse verification response: {}", e))
    }

    /// Retrieves a tamper-evident audit receipt by proof ID
    pub async fn get_receipt(&self, proof_id: &str) -> Result<ProofReceipt, String> {
        let url = format!("{}/api/v1/proofs/{}", self.base_url, proof_id);
        let resp = reqwest::get(&url)
            .await
            .map_err(|e| format!("Failed to fetch receipt: {}", e))?;

        resp.json::<ProofReceipt>()
            .await
            .map_err(|e| format!("Failed to parse receipt: {}", e))
    }
}
