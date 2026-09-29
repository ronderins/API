use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyRequest {
    pub user_id: String,
    pub doc_hash: String,
    pub age_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub criteria_met: String,
    pub proof_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: u64,
    pub event_type: String,
    pub metadata: HashMap<String, String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    pub proof_id: String,
    pub status: String,
    pub user_id_digest: String,
    pub document_hash: String,
    pub age_threshold: u32,
    pub verified: bool,
    pub criteria_met: String,
    pub commitment: String,
    pub proof_signature: String,
    pub created_at: String,
    pub audit_trail: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofListResponse {
    pub proofs: Vec<ProofResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub total_proofs: usize,
    pub total_audit_events: usize,
    pub active_commitments: usize,
    pub total_ledger_blocks: usize,
    pub latest_merkle_root: String,
    pub uptime_secs: u64,
    pub service: String,
    pub engine: String,
}

/// One-Time-Blind QR Session response for cross-device verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindQrSession {
    pub session_id: String,
    pub challenge_nonce: String,
    pub qr_payload: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub ttl_seconds: u64,
}

/// Tamper-proof Blake3 receipt ledger block entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptLedgerEntry {
    pub block_index: u64,
    pub proof_id: String,
    pub prev_hash: String,
    pub block_hash: String,
    pub merkle_root: String,
    pub timestamp: String,
}

/// Full cryptographic receipt ledger chain response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerChainResponse {
    pub total_blocks: usize,
    pub latest_merkle_root: String,
    pub is_valid: bool,
    pub entries: Vec<ReceiptLedgerEntry>,
}

/// Execution latency benchmark breakdown in microseconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLatencyMicros {
    pub average_verification_micros: u64,
    pub min_verification_micros: u64,
    pub max_verification_micros: u64,
    pub last_operation_micros: u64,
    pub sha256_hashing_micros: u64,
    pub blake3_ledger_chain_micros: u64,
    pub zeroize_wipe_micros: u64,
}

/// Process memory footprint using sysinfo crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryMetrics {
    pub process_rss_bytes: u64,
    pub process_rss_mb: f64,
    pub process_virtual_bytes: u64,
    pub process_virtual_mb: f64,
    pub system_total_memory_bytes: u64,
    pub system_used_memory_bytes: u64,
    pub system_free_memory_bytes: u64,
    pub cpu_usage_percent: f32,
    pub cpu_cores: usize,
}

/// Performance Dashboard response for GET /api/v1/metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetricsResponse {
    pub status: String,
    pub execution_speed: ExecutionLatencyMicros,
    pub memory_usage: ProcessMemoryMetrics,
    pub total_requests_tracked: usize,
    pub uptime_seconds: u64,
    pub binary_integrity_verified: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

/// Request payload to cryptographically verify a standalone signed ZK-Auth JWT proof token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

/// Response payload from cryptographically verifying a standalone signed ZK-Auth JWT proof token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTokenResponse {
    pub is_valid: bool,
    pub proof_id: String,
    pub user_id_digest: String,
    pub document_hash: String,
    pub age_threshold: u32,
    pub verified: bool,
    pub criteria_met: String,
    pub commitment: String,
    pub zk_predicate: String,
    pub simulated_proof_circuit: String,
    pub status: String,
    pub message: String,
}

/// Request payload to verify a Merkle inclusion proof against the cryptographic ledger.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyMerkleInclusionRequest {
    pub leaf_hash: String,
    pub inclusion_path: Vec<crate::crypto::MerkleInclusionProofStep>,
    pub expected_root: String,
}

/// Response payload from Merkle inclusion proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyMerkleInclusionResponse {
    pub is_valid: bool,
    pub leaf_hash: String,
    pub expected_root: String,
    pub path_depth: usize,
    pub timestamp: String,
}

/// Request for Rate-Limiting Nullifier (RLN) anonymous verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RlnVerifyRequest {
    pub epoch: u64,
    pub nullifier_hash: String,
    pub share_x: u64,
    pub share_y: u64,
    pub membership_merkle_root: String,
    pub zk_snark_proof: String,
}

/// Response for Rate-Limiting Nullifier (RLN) anonymous verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RlnVerifyResponse {
    pub is_accepted: bool,
    pub is_slashed: bool,
    pub epoch: u64,
    pub nullifier_hash: String,
    pub slashing_evidence: Option<crate::security::zk_rate_limiter_anonymous::SlashedIdentityEvidence>,
    pub message: String,
    pub timestamp: String,
}

/// Request for Selective Disclosure JWT verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SdJwtVerifyRequest {
    pub presentation: crate::security::w3c_sd_jwt_vc::SdJwtPresentation,
    pub issuer_public_key_or_secret: String,
}

/// Response for Selective Disclosure JWT verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtVerifyResponse {
    pub is_valid: bool,
    pub issuer_verified: bool,
    pub holder_binding_verified: bool,
    pub unmasked_claims: HashMap<String, serde_json::Value>,
    pub hidden_claim_count: usize,
    pub message: String,
    pub timestamp: String,
}

/// Request for Hardware Enclave Attestation quote evaluation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnclaveAttestationRequest {
    pub quote: crate::security::confidential_mpc_enclave::EnclaveAttestationQuote,
    pub challenge: String,
    pub policy: crate::security::confidential_mpc_enclave::EnclaveVerificationPolicy,
}

/// Response for Hardware Enclave Attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveAttestationResponse {
    pub is_valid: bool,
    pub enclave_type: String,
    pub mr_enclave: String,
    pub isv_svn: u32,
    pub verification_receipt: String,
    pub timestamp: String,
}

/// Request for NIST FIPS 204 ML-DSA post-quantum signature verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PqDilithiumVerifyRequest {
    pub public_key: crate::security::dilithium_fips204::MlDsaPublicKey,
    pub message: String,
    pub signature: crate::security::dilithium_fips204::MlDsaSignature,
}

/// Response for NIST FIPS 204 ML-DSA post-quantum signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqDilithiumVerifyResponse {
    pub is_valid: bool,
    pub algorithm: String,
    pub security_level: String,
    pub signature_receipt: String,
    pub timestamp: String,
}

/// Request for Blinded PSI Sanctions Non-Membership check.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SanctionsPsiRequest {
    pub query: crate::security::zero_leakage_sanctions_engine::BlindedSanctionsQuery,
    pub expected_epoch: u64,
}

/// Response for Blinded PSI Sanctions Non-Membership check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsPsiResponse {
    pub is_cleared: bool,
    pub oracle_evaluated_point: String,
    pub oracle_signature: String,
    pub epoch: u64,
    pub timestamp: String,
}

/// Request for Merkle Mountain Range audit proof verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MmrAuditVerifyRequest {
    pub proof: crate::security::audit_merkle_mountain_range::MmrInclusionProof,
}

/// Response for Merkle Mountain Range audit proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrAuditVerifyResponse {
    pub is_valid: bool,
    pub leaf_hash: String,
    pub mmr_size: usize,
    pub bagged_root: String,
    pub timestamp: String,
}

/// Request for Circuit Formal Safety Audit.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FormalCircuitCheckRequest {
    pub circuit: crate::security::formal_proof_verifier::CircuitDescription,
}

/// Response for Circuit Formal Safety Audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalCircuitCheckResponse {
    pub report: crate::security::formal_proof_verifier::FormalAuditReport,
    pub smt_lib2_code: String,
    pub timestamp: String,
}

/// Real-time cryptographic overview dashboard model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityOverviewResponse {
    pub total_rust_loc: usize,
    pub safety_and_hardening_loc: usize,
    pub safety_percentage: f64,
    pub security_modules_count: usize,
    pub active_defenses: Vec<String>,
    pub hardware_enclave_status: String,
    pub post_quantum_status: String,
    pub rln_rate_limiter_epoch: u64,
    pub mmr_audit_tree_size: usize,
    pub timestamp: String,
}

