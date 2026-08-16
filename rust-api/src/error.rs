use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Algebraic Error Enum representing all domain, validation, security, and runtime failure states.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum ApiError {
    /// Client failed authentication (missing or mismatched API key)
    Unauthorized {
        request_id: String,
    },

    /// Request payload failed syntactic or semantic validation
    ValidationError {
        message: String,
        request_id: String,
        details: Option<HashMap<String, String>>,
    },

    /// Document hash does not meet SHA-256 (64 hex character) specification
    InvalidDocumentHash {
        provided: String,
        reason: String,
        request_id: String,
    },

    /// Age threshold is outside of valid operating domain [0, 130]
    InvalidAgeThreshold {
        threshold: u32,
        request_id: String,
    },

    /// Zero-Knowledge verification circuit evaluation failed
    VerificationFailed {
        reason: String,
        request_id: String,
    },

    /// Requested proof record or commitment does not exist
    ProofNotFound {
        proof_id: String,
        request_id: String,
    },

    /// Cryptographic operation (signing, commitment, constant-time compare) failed
    CryptoError {
        operation: String,
        message: String,
        request_id: String,
    },

    /// In-memory SQLx SQLite database operation failure
    DatabaseError {
        message: String,
        request_id: String,
    },

    /// Unexpected internal server error
    Internal {
        message: String,
        request_id: String,
    },
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized { .. } => write!(f, "A valid API key is required."),
            Self::ValidationError { message, .. } => write!(f, "Validation error: {}", message),
            Self::InvalidDocumentHash { reason, .. } => {
                write!(f, "Invalid document hash format: {}", reason)
            }
            Self::InvalidAgeThreshold { threshold, .. } => {
                write!(f, "Age threshold '{}' is outside valid range (0-130)", threshold)
            }
            Self::VerificationFailed { reason, .. } => {
                write!(f, "Zero-Knowledge verification failed: {}", reason)
            }
            Self::ProofNotFound { proof_id, .. } => {
                write!(f, "The requested proof '{}' does not exist.", proof_id)
            }
            Self::CryptoError { operation, message, .. } => {
                write!(f, "Crypto error during '{}': {}", operation, message)
            }
            Self::DatabaseError { message, .. } => write!(f, "Database error: {}", message),
            Self::Internal { message, .. } => write!(f, "Internal server error: {}", message),
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetailResponse {
    pub code: String,
    pub message: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error: ErrorDetailResponse,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status_code, error_code, message, request_id, details) = match &self {
            Self::Unauthorized { request_id } => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "A valid API key is required.".to_string(),
                request_id.clone(),
                None,
            ),
            Self::ValidationError {
                message,
                request_id,
                details,
            } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                message.clone(),
                request_id.clone(),
                details.clone(),
            ),
            Self::InvalidDocumentHash {
                reason, request_id, ..
            } => {
                let mut d = HashMap::new();
                d.insert("doc_hash".to_string(), reason.clone());
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "VALIDATION_ERROR",
                    "The request contains invalid fields.".to_string(),
                    request_id.clone(),
                    Some(d),
                )
            }
            Self::InvalidAgeThreshold {
                threshold,
                request_id,
            } => {
                let mut d = HashMap::new();
                d.insert(
                    "age_threshold".to_string(),
                    format!("Must be between 0 and 130, received {}", threshold),
                );
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "VALIDATION_ERROR",
                    "The request contains invalid fields.".to_string(),
                    request_id.clone(),
                    Some(d),
                )
            }
            Self::VerificationFailed { reason, request_id } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "PROOF_GENERATION_FAILED",
                reason.clone(),
                request_id.clone(),
                None,
            ),
            Self::ProofNotFound { request_id, .. } => (
                StatusCode::NOT_FOUND,
                "PROOF_NOT_FOUND",
                "The requested proof does not exist.".to_string(),
                request_id.clone(),
                None,
            ),
            Self::CryptoError {
                message,
                request_id,
                ..
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CRYPTO_ERROR",
                message.clone(),
                request_id.clone(),
                None,
            ),
            Self::DatabaseError {
                message,
                request_id,
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                message.clone(),
                request_id.clone(),
                None,
            ),
            Self::Internal {
                message,
                request_id,
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                message.clone(),
                request_id.clone(),
                None,
            ),
        };

        let envelope = ErrorEnvelope {
            error: ErrorDetailResponse {
                code: error_code.to_string(),
                message,
                request_id: request_id.clone(),
                details,
            },
        };

        let mut res = (status_code, Json(envelope)).into_response();
        if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
            res.headers_mut().insert("x-request-id", val);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_enum_status_codes_and_payloads() {
        let err_unauth = ApiError::Unauthorized {
            request_id: "req-1".to_string(),
        };
        assert_eq!(err_unauth.to_string(), "A valid API key is required.");

        let mut details = HashMap::new();
        details.insert("user_id".to_string(), "cannot be empty".to_string());
        let err_val = ApiError::ValidationError {
            message: "Validation failed".to_string(),
            request_id: "req-2".to_string(),
            details: Some(details),
        };

        let json_val = serde_json::to_string(&err_val).expect("Serialization succeeds");
        assert!(json_val.contains("user_id"));

        let err_not_found = ApiError::ProofNotFound {
            proof_id: "fake-id".to_string(),
            request_id: "req-3".to_string(),
        };
        assert!(err_not_found.to_string().contains("fake-id"));
    }

    #[test]
    fn test_error_enum_equality_and_matching() {
        let err1 = ApiError::InvalidAgeThreshold {
            threshold: 150,
            request_id: "test-req".to_string(),
        };
        let err2 = ApiError::InvalidAgeThreshold {
            threshold: 150,
            request_id: "test-req".to_string(),
        };
        assert_eq!(err1, err2);
    }
}
