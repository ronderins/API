# AegisZK: Rust Zero-Knowledge Security Microservice

A high-performance, memory-safe Zero-Knowledge verification service implemented in Rust using Axum, Tokio, and Blake3 for cryptographic identity and predicate evaluation.

- **Author**: [Rony M. (@ronderins)](https://github.com/ronderins)
- **Repository**: [https://github.com/ronderins/S4](https://github.com/ronderins/S4)
- **License**: MIT
- **Data Privacy Specification**: Strict zero personally identifiable information (PII) architecture.

---

## What Does "ZK" Mean?

**ZK** stands for **Zero-Knowledge** (Zero-Knowledge Proofs):
- **Prove Truth Without Data**: Enables a prover to mathematically prove a condition is true (such as age eligibility or credential validity) without revealing underlying private attributes or exact birthdates.
- **Zero Storage (Zero PII)**: Verification happens without the server ever receiving, parsing, or retaining personal identity documents.
- **Unlinkability**: Proofs incorporate domain-separated nonces and blinding to prevent cross-service tracking.

---

## Cryptographic Operations and Attestation Generation

1. **Document Hashing**: Validates the 64-character SHA-256 hexadecimal digest representing the client-side identity credential.
2. **Predicate Evaluation**: Evaluates constraints against private witness data without exposing raw attributes or exact birthdates (`predicate = age >= threshold`).
3. **Cryptographically Signed Attestation (`jwt-simple`)**: Emits an HMAC-SHA256 authenticated JWT containing the anonymized `user_id_digest`, `doc_hash`, `age_threshold`, `age_verified`, and `commitment`.

---

## Response Structure

Requests to `POST /api/v1/verify` return a structured response adhering to the following schema:

```json
{
  "verified": true,
  "criteria_met": "age_over_18",
  "proof_signature": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## Persistence Layer and Privacy Guarantees (SQLx + SQLite In-Memory)

- **SQLx Connection Pool**: Verification events and cryptographic audit entries are managed via an asynchronous in-memory SQLite connection pool (`sqlite://:memory:?cache=shared`).
- **Zero-PII Invariants**:
  - No personal names, display aliases, or plaintext records are accepted by the storage subsystem.
  - Exact birthdates and ages are strictly excluded from relational tables.
  - Identifiers are hashed using SHA-256 with domain separation (`user_id_digest = SHA-256(raw_id)`) prior to persistence.
- **Persisted Schema Fields**:
  - `verification_timestamp` (ISO-8601 string)
  - `criteria_met` (Boolean / integer representing constraint satisfaction)
  - `proof_signature` (HMAC-SHA256 authenticated token)
  - `commitment` (Domain-separated SHA-256 commitment)
  - `document_hash` (Cryptographic digest of the presented document)
  - `user_id_digest` (Non-reversible SHA-256 hash)
  - `age_threshold` (Configured minimum age threshold)

---

## Algebraic Error Representation (`ApiError`)

All error conditions are formalized as an algebraic enum (`ApiError`) in `src/error.rs`:

```rust
pub enum ApiError {
    Unauthorized { request_id: String },
    ValidationError { message: String, request_id: String, details: Option<HashMap<String, String>> },
    InvalidDocumentHash { provided: String, reason: String, request_id: String },
    InvalidAgeThreshold { threshold: u32, request_id: String },
    VerificationFailed { reason: String, request_id: String },
    ProofNotFound { proof_id: String, request_id: String },
    CryptoError { operation: String, message: String, request_id: String },
    DatabaseError { message: String, request_id: String },
    Internal { message: String, request_id: String },
}
```

This enum implements `axum::response::IntoResponse`, returning precise HTTP status codes (401, 404, 422, 500) and standardized error payloads.

---

## Unit and Integration Test Suite

The test suite covers:
- **Valid Predicate Evaluations**: Correct constraint resolution across standard age tiers (18, 21, 65).
- **Feldman Verifiable Secret Sharing (VSS)**: Polynomial coefficient generation, share verification, and threshold reconstruction.
- **Nova / IVC Recursive Folding**: Step folding verification and multi-predicate accumulator compaction.
- **Biometric Template Matching**: Fixed-point distance evaluation and privacy-preserving match checks.
- **Post-Quantum Hybrid Signatures**: NIST FIPS 204 (ML-DSA) state commitments bound with classical elliptic curves.
- **W3C VC 2.0 & SD-JWT**: Credential schema validation and predicate evaluation.
- **WebGPU Shader & Compute Pipelines**: Hardware acceleration benchmarks and WGSL shader verification.
- **Validation Failures**:
  - Truncated or malformed document hash lengths.
  - Non-hexadecimal characters in hash representations.
  - Out-of-bounds age thresholds (>130).
  - Empty or oversized user identifiers.
  - Unknown proof lookups (`PROOF_NOT_FOUND`).
  - Missing or invalid API key authorization (`UNAUTHORIZED`).
  - Tampered JWT token signatures.
- **Security Invariants**: Constant-time equality checks and zero-PII data assertion.

Execute tests via:
```bash
cargo test
```

---

## Containerized Deployment

A multi-stage `Dockerfile` is provided for containerized environments:

```bash
docker build -t zk-identity-api-rust ./rust-api
docker run -p 8080:8080 zk-identity-api-rust
```

---

## Compilation and Execution

```bash
cd rust-api
cargo run --release
```

The Axum service listens on `http://0.0.0.0:8080`.

---

## Environment Variables and Configuration

**No external API keys or secrets are required** to run this microservice. All parameters are optional and have default values:

| Variable | Required | Description | Default |
| :--- | :--- | :--- | :--- |
| `HOST` | Optional | Network interface IP to bind the HTTP server to | `127.0.0.1` |
| `PORT` | Optional | Port to listen on | `8080` |
| `RUST_LOG` | Optional | Tracing level (`debug`, `info`, `warn`, `error`) | `info` |
| `DATABASE_URL` | Optional | SQLite connection string for the Merkle ledger | `sqlite:zk_identity.db` |
| `API_KEY` | Optional | Pre-shared key for endpoint authorization | None (Open Access) |
| `CANARY_ENFORCE` | Optional | Enforce binary SHA-256 integrity validation | `false` |

---

## Security Architecture

1. **Deterministic Memory Zeroization (`zeroize`)**:
   - Employs `Zeroize`, `ZeroizeOnDrop`, and `Zeroizing` wrappers around sensitive inputs (witness values, document digests, secret keys).
   - Enforces immediate overwriting of heap and stack buffers upon completion of cryptographic operations.

2. **Single-Use Challenge Nonces (`GET /api/v1/session`)**:
   - Generates ephemeral UUID session tokens with five-minute expiration times.
   - Handled in an in-memory thread-safe cache (`tokio::sync::RwLock`) with automatic expiration cleanup.

3. **Append-Only Merkle Receipt Ledger (Blake3)**:
   - Maintains a tamper-evident Blake3 cryptographic hash chain in SQLite.
   - Computes cumulative Merkle root digests across sequential verification blocks for independent validation.

4. **Telemetry and Performance Metrics (`GET /api/v1/metrics`)**:
   - Tracks microsecond execution latencies across hashing, circuit evaluation, and memory clearing.
   - Gathers process memory (RSS) and CPU utilization metrics via `sysinfo`.

5. **Binary Integrity Verification**:
   - Checks the executing binary's SHA-256 digest against the canonical release hash upon startup.

6. **Side-Channel Resistant Authorization**:
   - Pre-shared API keys evaluated in constant time to prevent timing attacks.
   - Accepts both `X-API-Key` and `Authorization: Bearer` header conventions.

---

## Endpoint Index

- `GET /healthz` - Health, liveness, and readiness check
- `GET /api/v1/session` - Generate single-use challenge token (5-minute TTL)
- `POST /api/v1/verify` - Ephemeral memory-locked zero-knowledge verification
- `POST /api/v1/verify-token` - Cryptographically verify standalone JWT proof token
- `POST /api/v1/verify-merkle` - Validate Merkle inclusion path against target root
- `GET /api/v1/proofs/{id}` - Lookup proof record, signed token, and audit trail
- `GET /api/v1/proofs` - List stored verification proofs
- `GET /api/v1/ledger` - Retrieve tamper-evident Blake3 Merkle block ledger
- `GET /api/v1/metrics` - Microsecond execution latency and system memory metrics
- `GET /api/v1/stats` - Aggregated metrics and current Merkle root digest
