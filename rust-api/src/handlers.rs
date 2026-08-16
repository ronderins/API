use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use std::collections::HashMap;
use std::env;
use uuid::Uuid;
use crate::error::ApiError;
use crate::models::{
    LedgerChainResponse, PerformanceMetricsResponse, ProofListResponse, StatsResponse,
    VerifyRequest,
};
use crate::store::AppState;
use crate::crypto::constant_time_eq;

fn get_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn check_auth(headers: &HeaderMap, request_id: &str) -> Result<(), ApiError> {
    let key_var = env::var("API_KEY").or_else(|_| env::var("API_KEYS")).unwrap_or_default();
    let configured_keys: Vec<String> = key_var
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // If no keys configured, API operates in open development/public mode
    if configured_keys.is_empty() {
        return Ok(());
    }

    // Extract key from x-api-key header or Authorization: Bearer <token>
    let client_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    let s = s.trim();
                    if s.to_lowercase().starts_with("bearer ") {
                        Some(s[7..].trim().to_string())
                    } else {
                        None
                    }
                })
        })
        .unwrap_or_default();

    if client_key.is_empty() {
        return Err(ApiError::Unauthorized {
            request_id: request_id.to_string(),
        });
    }

    // Constant-time check across all configured authorized keys
    let is_authorized = configured_keys
        .iter()
        .any(|key| constant_time_eq(key, &client_key));

    if !is_authorized {
        return Err(ApiError::Unauthorized {
            request_id: request_id.to_string(),
        });
    }

    Ok(())
}

pub async fn healthz(headers: HeaderMap) -> impl IntoResponse {
    let _request_id = get_request_id(&headers);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "service": "zk-identity-api-rust",
            "engine": "rust-axum"
        })),
    )
}

pub async fn create_verify_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyRequest>,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    let mut violations = HashMap::new();
    let trimmed_user_id = payload.user_id.trim();
    let trimmed_doc_hash = payload.doc_hash.trim().to_lowercase();

    if trimmed_user_id.is_empty() || trimmed_user_id.len() > 256 {
        violations.insert("user_id".to_string(), "must contain between 1 and 256 characters".to_string());
    }

    let hex_chars_valid = trimmed_doc_hash.len() == 64 && trimmed_doc_hash.chars().all(|c| c.is_ascii_hexdigit());
    if !hex_chars_valid {
        violations.insert("doc_hash".to_string(), "must be a 64-character SHA-256 hexadecimal digest".to_string());
    }

    if payload.age_threshold > 130 {
        violations.insert("age_threshold".to_string(), "must be between 0 and 130".to_string());
    }

    if !violations.is_empty() {
        return ApiError::ValidationError {
            message: "The request contains invalid fields.".to_string(),
            request_id,
            details: Some(violations),
        }
        .into_response();
    }

    match state.create_proof(trimmed_user_id, &trimmed_doc_hash, payload.age_threshold).await {
        Ok(res) => (StatusCode::CREATED, Json(res)).into_response(),
        Err(err_msg) => ApiError::VerificationFailed {
            reason: err_msg.to_string(),
            request_id,
        }
        .into_response(),
    }
}

pub async fn get_proof(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    if Uuid::parse_str(&id).is_err() {
        return ApiError::ProofNotFound {
            proof_id: id,
            request_id,
        }
        .into_response();
    }

    match state.get_proof(&id).await {
        Some(proof) => (StatusCode::OK, Json(proof)).into_response(),
        None => ApiError::ProofNotFound {
            proof_id: id,
            request_id,
        }
        .into_response(),
    }
}

pub async fn list_proofs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    let proofs = state.list_proofs(100).await;

    (StatusCode::OK, Json(ProofListResponse { proofs })).into_response()
}

pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    // Generate short-lived UUID token session linked to local memory cache
    let session = state.create_blind_qr_session(300).await;
    (StatusCode::OK, Json(session)).into_response()
}

pub async fn get_ledger(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    let ledger = state.get_receipt_ledger(100).await;
    (StatusCode::OK, Json(ledger)).into_response()
}

pub async fn get_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    let metrics = state.get_metrics().await;
    (StatusCode::OK, Json(metrics)).into_response()
}

pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let (total_proofs, total_audit_events, active_commitments, total_ledger_blocks, latest_merkle_root, uptime_secs) =
        state.get_stats().await;

    (
        StatusCode::OK,
        Json(StatsResponse {
            total_proofs,
            total_audit_events,
            active_commitments,
            total_ledger_blocks,
            latest_merkle_root,
            uptime_secs,
            service: "zk-identity-api-rust".to_string(),
            engine: "rust-axum".to_string(),
        }),
    )
}

/// Cryptographically verifies a standalone signed ZK-Auth JWT proof token without requiring database lookup.
pub async fn verify_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<crate::models::VerifyTokenRequest>,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    let token_trimmed = payload.token.trim();
    if token_trimmed.is_empty() || token_trimmed.len() > 8192 {
        return ApiError::ValidationError {
            message: "Token parameter is invalid or exceeds maximum size limit (8192 chars).".to_string(),
            request_id,
            details: None,
        }
        .into_response();
    }

    match state.verify_signed_token(token_trimmed).await {
        Ok(verified_res) => (StatusCode::OK, Json(verified_res)).into_response(),
        Err(err_msg) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(crate::models::VerifyTokenResponse {
                is_valid: false,
                proof_id: String::new(),
                user_id_digest: String::new(),
                document_hash: String::new(),
                age_threshold: 0,
                verified: false,
                criteria_met: String::new(),
                commitment: String::new(),
                zk_predicate: String::new(),
                simulated_proof_circuit: String::new(),
                status: "invalid".to_string(),
                message: format!("Token verification failed: {}", err_msg),
            }),
        )
            .into_response(),
    }
}

/// Verifies a Merkle inclusion proof against a target Merkle root.
pub async fn verify_merkle_inclusion(
    headers: HeaderMap,
    Json(payload): Json<crate::models::VerifyMerkleInclusionRequest>,
) -> impl IntoResponse {
    let request_id = get_request_id(&headers);

    if let Err(auth_err) = check_auth(&headers, &request_id) {
        return auth_err.into_response();
    }

    let is_valid = crate::crypto::verify_merkle_inclusion_proof(
        payload.leaf_hash.trim(),
        &payload.inclusion_path,
        payload.expected_root.trim(),
    );

    (
        StatusCode::OK,
        Json(crate::models::VerifyMerkleInclusionResponse {
            is_valid,
            leaf_hash: payload.leaf_hash,
            expected_root: payload.expected_root,
            path_depth: payload.inclusion_path.len(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Repository;
    use std::sync::Arc;

    const VALID_DOC_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[tokio::test]
    async fn test_successful_verification_flow() {
        let repo = Arc::new(Repository::new().await);
        let result = repo.create_proof("user_alice_42", VALID_DOC_HASH, 18).await;
        
        assert!(result.is_ok(), "Verification for valid witness must succeed");
        let res = result.unwrap();
        assert!(res.verified);
        assert_eq!(res.criteria_met, "age_over_18");
        assert!(!res.proof_signature.is_empty());
    }

    #[tokio::test]
    async fn test_failed_verification_invalid_doc_hash() {
        let repo = Arc::new(Repository::new().await);
        
        // 1. Too short doc_hash
        let result_short = repo.create_proof("user_alice", "abcdef1234", 18).await;
        assert!(result_short.is_err(), "Short doc_hash must fail verification");
        assert_eq!(
            result_short.unwrap_err(),
            "Invalid document hash: must be a 64-character SHA-256 hexadecimal string"
        );

        // 2. Non-hex characters
        let invalid_hex = "g".repeat(64);
        let result_non_hex = repo.create_proof("user_alice", &invalid_hex, 18).await;
        assert!(result_non_hex.is_err(), "Non-hex characters in doc_hash must fail");
    }

    #[tokio::test]
    async fn test_failed_verification_invalid_age_threshold() {
        let repo = Arc::new(Repository::new().await);
        
        // Age threshold exceeding 130
        let result_out_of_bounds = repo.create_proof("user_alice", VALID_DOC_HASH, 150).await;
        assert!(result_out_of_bounds.is_err(), "Age threshold > 130 must fail");
        assert_eq!(
            result_out_of_bounds.unwrap_err(),
            "Age threshold exceeds maximum allowed value (130)"
        );
    }

    #[tokio::test]
    async fn test_failed_proof_lookup_not_found() {
        let repo = Arc::new(Repository::new().await);
        let nonexistent_uuid = "00000000-0000-0000-0000-000000000999";
        let result = repo.get_proof(nonexistent_uuid).await;
        assert!(result.is_none(), "Nonexistent proof ID must return None");
    }

    #[test]
    fn test_auth_check_rejections_and_successes() {
        // Without API_KEY set
        env::remove_var("API_KEY");
        let headers = HeaderMap::new();
        assert!(check_auth(&headers, "req-1").is_ok());

        // With API_KEY set
        env::set_var("API_KEY", "super-secret-key-123");
        
        // Missing key
        let mut headers_missing = HeaderMap::new();
        let err_missing = check_auth(&headers_missing, "req-2");
        assert!(err_missing.is_err());
        assert_eq!(
            err_missing.unwrap_err(),
            ApiError::Unauthorized {
                request_id: "req-2".to_string()
            }
        );

        // Wrong key
        headers_missing.insert("x-api-key", "wrong-key".parse().unwrap());
        let err_wrong = check_auth(&headers_missing, "req-3");
        assert!(err_wrong.is_err());

        // Correct key
        let mut headers_correct = HeaderMap::new();
        headers_correct.insert("x-api-key", "super-secret-key-123".parse().unwrap());
        assert!(check_auth(&headers_correct, "req-4").is_ok());

        // Bearer token support
        let mut headers_bearer = HeaderMap::new();
        headers_bearer.insert("authorization", "Bearer super-secret-key-123".parse().unwrap());
        assert!(check_auth(&headers_bearer, "req-5").is_ok());

        // Comma-delimited customizable keys (partner-1, partner-2)
        env::set_var("API_KEYS", "partner-alpha-key, partner-beta-key");
        env::remove_var("API_KEY");

        let mut headers_partner = HeaderMap::new();
        headers_partner.insert("x-api-key", "partner-beta-key".parse().unwrap());
        assert!(check_auth(&headers_partner, "req-6").is_ok());

        let mut headers_partner_bearer = HeaderMap::new();
        headers_partner_bearer.insert("authorization", "Bearer partner-alpha-key".parse().unwrap());
        assert!(check_auth(&headers_partner_bearer, "req-7").is_ok());

        env::remove_var("API_KEYS");
    }
}
