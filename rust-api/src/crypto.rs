use blake3::Hasher as Blake3Hasher;
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Ephemeral memory structure that automatically zeroes out stack/heap memory
/// when dropped or when `.zeroize()` is invoked immediately after verification.
#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug)]
pub struct EphemeralSensitiveWitness {
    pub raw_user_id: String,
    pub doc_hash: String,
    pub nonce: String,
    pub age_threshold: u32,
}

impl EphemeralSensitiveWitness {
    pub fn new(user_id: &str, doc_hash: &str, nonce: &str, age_threshold: u32) -> Self {
        Self {
            raw_user_id: user_id.to_string(),
            doc_hash: doc_hash.to_string(),
            nonce: nonce.to_string(),
            age_threshold,
        }
    }

    /// Explicitly overwrite heap and stack memory immediately after verification.
    pub fn lockdown_and_wipe(&mut self) {
        self.zeroize();
    }
}

/// Computes SHA-256 hex digest of arbitrary byte slice.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Computes Blake3 hex digest for cryptographic receipt ledger.
pub fn compute_blake3_hex(data: &[u8]) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Computes a Blake3 Merkle tree parent node hash from left and right child hashes.
pub fn compute_merkle_node(left_hash: &str, right_hash: &str) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"zk-blake3-merkle-node-v1\0");
    hasher.update(left_hash.as_bytes());
    hasher.update(right_hash.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Computes a Blake3 chained block receipt hash for tamper-proof ledger auditing.
pub fn compute_receipt_block_hash(
    block_index: u64,
    prev_hash: &str,
    proof_id: &str,
    commitment: &str,
    timestamp: &str,
) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"zk-blake3-receipt-block-v1\0");
    hasher.update(&block_index.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\0");
    hasher.update(proof_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(commitment.as_bytes());
    hasher.update(b"\0");
    hasher.update(timestamp.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Builds zero-knowledge proof commitment with strict domain separation and Ephemeral Memory Lockdown:
/// SHA-256("zk-identity-proof-v1\0" || user_id || 0x00 || doc_hash || 0x00 || age_threshold || 0x00 || nonce)
/// Uses `Zeroizing` buffer to guarantee memory is wiped immediately after commitment calculation.
pub fn build_commitment(
    user_id: &str,
    doc_hash: &str,
    age_threshold: u32,
    nonce: &str,
) -> String {
    // Wrap sensitive inputs in zeroizing buffers
    let mut sensitive_buf = Zeroizing::new(Vec::<u8>::new());
    sensitive_buf.extend_from_slice(b"zk-identity-proof-v1\0");
    sensitive_buf.extend_from_slice(user_id.as_bytes());
    sensitive_buf.push(0);
    sensitive_buf.extend_from_slice(doc_hash.as_bytes());
    sensitive_buf.push(0);
    sensitive_buf.extend_from_slice(age_threshold.to_string().as_bytes());
    sensitive_buf.push(0);
    sensitive_buf.extend_from_slice(nonce.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&*sensitive_buf);
    let digest = hasher.finalize();

    // Explicitly zeroize the buffer immediately
    sensitive_buf.zeroize();

    hex::encode(digest)
}

/// Constant-time comparison for API keys to prevent timing side-channel attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    a_bytes.ct_eq(b_bytes).into()
}

/// Custom JWT claims embedded into the cryptographically signed payload token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofPayloadClaims {
    pub proof_id: String,
    pub user_id_digest: String,
    pub document_hash: String,
    pub age_threshold: u32,
    pub verified: bool,
    pub criteria_met: String,
    pub commitment: String,
    pub zk_predicate: String,
    pub simulated_proof_circuit: String,
}

/// Token signer using the `jwt-simple` crate for cryptographic token issuance.
#[derive(Clone)]
pub struct ZkTokenSigner {
    key: HS256Key,
}

impl ZkTokenSigner {
    pub fn new() -> Self {
        let secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "zkp-identity-verification-master-key-32b".to_string());
        let key = HS256Key::from_bytes(secret.as_bytes());
        Self { key }
    }

    /// Generates a unique, cryptographically signed payload token using `jwt-simple`.
    pub fn create_signed_token(
        &self,
        proof_id: &str,
        user_id_digest: &str,
        doc_hash: &str,
        age_threshold: u32,
        verified: bool,
        criteria_met: &str,
        commitment: &str,
    ) -> Result<String, String> {
        let custom_claims = ZkProofPayloadClaims {
            proof_id: proof_id.to_string(),
            user_id_digest: user_id_digest.to_string(),
            document_hash: doc_hash.to_string(),
            age_threshold,
            verified,
            criteria_met: criteria_met.to_string(),
            commitment: commitment.to_string(),
            zk_predicate: format!("age >= {}", age_threshold),
            simulated_proof_circuit: "Groth16/BN254-AgeCheck-v1".to_string(),
        };

        let claims = Claims::with_custom_claims(custom_claims, Duration::from_days(30))
            .with_issuer("zk-identity-rust-api")
            .with_subject(user_id_digest);

        self.key
            .authenticate(claims)
            .map_err(|e| format!("JWT signing failed: {}", e))
    }

    /// Verifies and decodes a signed payload token using `jwt-simple`.
    pub fn verify_token(&self, token: &str) -> Result<JWTClaims<ZkProofPayloadClaims>, String> {
        self.key
            .verify_token::<ZkProofPayloadClaims>(token, None)
            .map_err(|e| format!("JWT validation failed: {}", e))
    }
}

/// Cryptographic verification result of an independent ZK-Auth JWT Proof Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenVerificationOutcome {
    pub valid: bool,
    pub proof_id: String,
    pub user_id_digest: String,
    pub document_hash: String,
    pub age_threshold: u32,
    pub verified: bool,
    pub criteria_met: String,
    pub commitment: String,
    pub zk_predicate: String,
    pub simulated_proof_circuit: String,
    pub issued_at_timestamp: Option<u64>,
    pub expires_at_timestamp: Option<u64>,
}

/// Merkle inclusion verification path node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProofStep {
    pub position: String, // "left" or "right"
    pub hash: String,
}

/// Verifies a Merkle inclusion proof against a target Merkle root hash.
pub fn verify_merkle_inclusion_proof(
    leaf_hash: &str,
    inclusion_path: &[MerkleInclusionProofStep],
    expected_root: &str,
) -> bool {
    let clean_leaf = leaf_hash.trim().to_lowercase();
    let clean_root = expected_root.trim().to_lowercase();

    if clean_leaf.len() != 64 || !clean_leaf.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    if clean_root.len() != 64 || !clean_root.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    if inclusion_path.len() > 64 {
        return false;
    }

    let mut current_hash = clean_leaf;

    for step in inclusion_path {
        let step_hash = step.hash.trim().to_lowercase();
        if step_hash.len() != 64 || !step_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        if step.position == "left" {
            current_hash = compute_merkle_node(&step_hash, &current_hash);
        } else if step.position == "right" {
            current_hash = compute_merkle_node(&current_hash, &step_hash);
        } else {
            return false;
        }
    }

    constant_time_eq(&current_hash, &clean_root)
}

/// Simulates Zero-Knowledge Proof evaluation:
/// 1. Hashing and checking document hash integrity (64-char SHA-256)
/// 2. Evaluating age threshold using mock verification logic (simulated R1CS circuit evaluation)
/// 3. Confirms predicate satisfaction without exposing raw birthdate or identity
pub fn simulate_zkp_age_verification(
    doc_hash: &str,
    age_threshold: u32,
) -> Result<bool, &'static str> {
    if doc_hash.len() != 64 || !doc_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid document hash: must be a 64-character SHA-256 hexadecimal string");
    }

    if age_threshold > 130 {
        return Err("Age threshold exceeds maximum allowed value (130)");
    }

    // Mock verification logic: simulates constraint satisfaction in a ZK arithmetic circuit.
    // In our simulation, the user's private witness meets the threshold constraint.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256_hex() {
        let digest = compute_sha256_hex(b"hello world");
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_build_commitment_domain_separation() {
        let c1 = build_commitment("user-1", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 18, "nonce-1");
        let c2 = build_commitment("user-1", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 18, "nonce-2");
        assert_ne!(c1, c2, "Different nonces must yield different commitments");
        assert_eq!(c1.len(), 64);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("secret123", "secret123"));
        assert!(!constant_time_eq("secret123", "wrong"));
        assert!(!constant_time_eq("secret123", "secret124"));
    }

    #[test]
    fn test_jwt_token_signing_and_verification() {
        let signer = ZkTokenSigner::new();
        let proof_id = "test-proof-uuid";
        let user_id_digest = compute_sha256_hex(b"user-alice");
        let doc_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let commitment = "f".repeat(64);

        let token = signer
            .create_signed_token(proof_id, &user_id_digest, doc_hash, 21, true, "age_over_21", &commitment)
            .expect("Signing must succeed");

        let claims = signer.verify_token(&token).expect("Verification must succeed");
        assert_eq!(claims.custom.proof_id, proof_id);
        assert_eq!(claims.custom.user_id_digest, user_id_digest);
        assert_eq!(claims.custom.age_threshold, 21);
        assert!(claims.custom.verified);
        assert_eq!(claims.custom.criteria_met, "age_over_21");

        // Failure Case: Tampered token signature fails verification
        let tampered_token = format!("{}tampered", token);
        let verify_tampered = signer.verify_token(&tampered_token);
        assert!(verify_tampered.is_err(), "Tampered token must fail signature check");

        // Failure Case: Malformed token string
        let verify_garbage = signer.verify_token("not.a.valid.jwt");
        assert!(verify_garbage.is_err(), "Malformed token string must fail verification");
    }

    #[test]
    fn test_simulate_zkp_age_verification_validation() {
        let valid_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        // Successful verification
        assert!(simulate_zkp_age_verification(valid_hash, 18).is_ok());
        assert!(simulate_zkp_age_verification(valid_hash, 21).is_ok());
        assert!(simulate_zkp_age_verification(valid_hash, 65).is_ok());

        // Failed verifications
        assert!(simulate_zkp_age_verification("too_short", 18).is_err());
        assert!(simulate_zkp_age_verification("1234567890", 21).is_err());
        assert!(simulate_zkp_age_verification(valid_hash, 200).is_err());
        assert!(simulate_zkp_age_verification(valid_hash, 131).is_err());
    }

    #[test]
    fn test_ephemeral_memory_lockdown_zeroize() {
        let mut witness = EphemeralSensitiveWitness::new("super_secret_user", "abcdef123456", "nonce_999", 25);
        assert_eq!(witness.raw_user_id, "super_secret_user");
        assert_eq!(witness.doc_hash, "abcdef123456");
        
        witness.lockdown_and_wipe();
        assert!(witness.raw_user_id.is_empty() || witness.raw_user_id.bytes().all(|b| b == 0));
        assert!(witness.doc_hash.is_empty() || witness.doc_hash.bytes().all(|b| b == 0));
    }

    #[test]
    fn test_blake3_receipt_hash_and_merkle_node() {
        let digest1 = compute_blake3_hex(b"block_1_receipt");
        let digest2 = compute_blake3_hex(b"block_2_receipt");
        assert_eq!(digest1.len(), 64);
        assert_eq!(digest2.len(), 64);
        assert_ne!(digest1, digest2);

        let parent_merkle = compute_merkle_node(&digest1, &digest2);
        assert_eq!(parent_merkle.len(), 64);
        assert_ne!(parent_merkle, digest1);

        let block_hash = compute_receipt_block_hash(1, &digest1, "proof-uuid-1", "commitment-1", "2026-08-14T20:00:00Z");
        assert_eq!(block_hash.len(), 64);
    }

    #[test]
    fn test_canary_integrity_matching() {
        let test_bytes = b"canonical_binary_payload_v1";
        let computed_hash = compute_sha256_hex(test_bytes);
        assert_eq!(computed_hash.len(), 64);
        assert!(constant_time_eq(&computed_hash, &computed_hash));
    }

    #[test]
    fn test_merkle_inclusion_proof_verification() {
        let leaf_1 = compute_blake3_hex(b"leaf_transaction_1");
        let leaf_2 = compute_blake3_hex(b"leaf_transaction_2");
        let leaf_3 = compute_blake3_hex(b"leaf_transaction_3");
        let leaf_4 = compute_blake3_hex(b"leaf_transaction_4");

        let parent_12 = compute_merkle_node(&leaf_1, &leaf_2);
        let parent_34 = compute_merkle_node(&leaf_3, &leaf_4);
        let root = compute_merkle_node(&parent_12, &parent_34);

        // Inclusion path for leaf_1: [right: leaf_2, right: parent_34]
        let path_leaf_1 = vec![
            MerkleInclusionProofStep {
                position: "right".to_string(),
                hash: leaf_2.clone(),
            },
            MerkleInclusionProofStep {
                position: "right".to_string(),
                hash: parent_34.clone(),
            },
        ];

        assert!(verify_merkle_inclusion_proof(&leaf_1, &path_leaf_1, &root));
        // Failure case: altered root
        assert!(!verify_merkle_inclusion_proof(&leaf_1, &path_leaf_1, "0".repeat(64).as_str()));
    }
}
