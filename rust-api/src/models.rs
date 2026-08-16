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
