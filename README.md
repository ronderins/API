# Aegis: Cryptographic Identity & Predicate Verification Engine

Aegis is a high-assurance cryptographic attestation engine that couples a native Rust microservice with a developer-focused verification workbench built on Next.js. The architecture enables verifiable predicate evaluations (such as age threshold validations, credential authenticity proofs, and Merkle inclusion checks) without persisting, transmitting, or exposing raw personally identifiable information (PII).

- **Author**: [Rony M. (@ronderins)](https://github.com/ronderins)
- **Repository**: [https://github.com/ronderins/S4](https://github.com/ronderins/S4)
- **License**: MIT
- **Data Privacy Specification**: Zero personally identifiable information (PII) is stored, indexed, or retained.
- **Infrastructure Requirements**: 100% Self-hosted and fully autonomous. No third-party SaaS dependencies or external API keys are required.
- **Deployment Targets**: Optimized for Vercel, Docker, Bare Metal, and Cloudflare Pages.

---

## Core Security & Verification Principles

- **Mathematical Proof Without Data Disclosure**: The prover demonstrates that a statement is mathematically true (e.g. *"Subject meets specified age and credential parameters"*) without revealing underlying identity data (such as exact date of birth, legal name, or document identifiers).
- **Strict Ephemeral State & Zero Storage**: The verification layer validates cryptographic commitments and blinding nonces without writing personal attributes to persistent disk or relational tables.
- **Unlinkable Blinding Nonces**: Cryptographic blinding ensures verifiers cannot correlate attestations or track identity activity across separate services or verification sessions.

---

## Technical Capabilities & Subsystems

1. **Deterministic Ephemeral Memory Deallocation (`zeroize`)**: Strictly enforces heap and stack scrubbing to overwrite witness attributes, blinding nonces, and document digests immediately following constraint evaluation.
2. **Recursive Proof Folding & Aggregation (Nova/IVC)**: Compresses multi-predicate identity pipelines (age verification, AML compliance tiers, and sanctions non-membership) into a constant-sized verification accumulator.
3. **Verifiable Secret Sharing & Threshold Decryption (Feldman VSS)**: Provides m-of-n decentralized oracle consensus and threshold signing without a single point of failure.
4. **Biometric Template Matching Constraints**: Evaluates fixed-point distance constraints (L2 Euclidean / Cosine distance) on facial and fingerprint embeddings without storing raw biometric vectors.
5. **Post-Quantum Hybrid Signatures (NIST FIPS 204 ML-DSA)**: Binds lattice state commitments with classical elliptic curves (BN254/Ed25519) to ensure long-term forward secrecy against quantum adversaries.
6. **W3C Verifiable Credentials 2.0 & SD-JWT Engine**: Supports selective disclosure and predicate unmasking compliant with international identity wallet specifications.
7. **Single-Use Challenge Nonces (`GET /api/v1/session`)**: Issues cryptographically secure challenge nonces with a 5-minute time-to-live (TTL) to prevent replay and cross-device spoofing.
8. **Cryptographic Receipt Ledger (Blake3 Merkle Chain)**: Maintains an append-only, tamper-evident hash chain in SQLite providing instant inclusion proof capabilities (`POST /api/v1/verify-merkle`).
9. **Microsecond Telemetry & Memory Instrumentation (`GET /api/v1/metrics`)**: Direct OS-level execution monitoring and memory consumption telemetry via the native `sysinfo` interface.

---

## Verification Interface & Developer Workbench

Cryptographic identity protocols involve mathematical primitives that are difficult to inspect through raw terminal commands alone. While the primary Rust microservice (`/rust-api/`) compiles into an ultra-lean binary (~15MB) for high-throughput production environments, the Next.js frontend acts as an interactive security workbench.

Security engineers, auditors, and evaluators can directly inspect:
- Client-side SHA-256 and Blake3 document digest calculation before network transmission.
- Witness generation and constraint satisfaction timing in microseconds.
- Merkle root progression, block receipts, and inclusion path verification.
- Ephemeral memory sanitization telemetry (`zeroize` validation).
- Multi-language API request generators across cURL, TypeScript, Rust, and Python.

---

## Production Deployment

### 1. Deploying to Vercel (Zero-Config)
This repository is optimized for one-click native Vercel deployment:
1. Connect your repository to [Vercel](https://vercel.com).
2. Framework Preset: **Next.js** (automatically detected).
3. Node.js Version: **20.x** or **22.x**.
4. (Optional) Configure environment variables such as `API_KEY` to enforce pre-shared header authentication.
5. Click **Deploy**.

### 2. Docker & Containerized Deployment
```bash
# Build and launch both Rust Axum and Next.js services
docker compose up --build -d
```

### 3. Local Development
```bash
# Install dependencies
npm install

# Start Next.js development server on port 3000
npm run dev

# (Optional) Launch native Rust backend on port 8080
cd rust-api && cargo run --release
```

---

## Configuration & Environment Variables

| Variable | Required | Description | Default / Fallback |
| :--- | :--- | :--- | :--- |
| `RUST_API_URL` | **Optional** | URL of the standalone Rust Axum service. If unset or offline, Next.js automatically executes with its built-in engine. | `http://localhost:8080` |
| `API_KEY` | **Optional** | Pre-shared key to enforce authenticated API requests (`X-API-Key`). | `None` (Open Mode) |
| `API_KEYS` | **Optional** | Comma-separated list of authorized pre-shared API keys. | `None` |
| `PORT` | **Optional** | HTTP port for the web server. | `3000` |
| `CANARY_ENFORCE` | **Optional** | Enforce binary SHA-256 release integrity verification (`true`/`false`). | `false` |
| `CANARY_CANONICAL_SHA256` | **Optional** | Expected canonical SHA-256 digest of the compiled Rust binary. | `None` |

---

## API Specification

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/healthz` | System health, liveness, and readiness check |
| `POST` | `/api/v1/verify` | Evaluates predicate constraints and issues signed verification tokens |
| `POST` | `/api/v1/verify-token` | Verifies and validates cryptographic JWT proof tokens |
| `POST` | `/api/v1/verify-merkle` | Validates Merkle inclusion paths against the ledger root |
| `GET` | `/api/v1/session` | Generates short-lived session challenge nonces |
| `GET` | `/api/v1/ledger` | Retrieves the append-only Blake3 Merkle block ledger |
| `GET` | `/api/v1/metrics` | Returns microsecond execution latency and system memory statistics |
| `GET` | `/api/v1/proofs` | Lists historical proof commitments |
| `GET` | `/api/v1/proofs/{id}` | Retrieves a specific proof record and its verification audit trail |
| `GET` | `/api/v1/stats` | Aggregated engine metrics and active Merkle root digests |

---

## Continuous Integration & Automated Tests

The repository includes a comprehensive GitHub Actions workflow (`.github/workflows/ci.yml`) that validates every commit:
- **Rust Toolchain**: Executes `cargo fmt --check`, `cargo clippy -- -D warnings`, and the cryptographic test suite (`cargo test`).
- **Frontend Validation**: Performs TypeScript type checking, linting, and Next.js production compilation.
- **Container Verification**: Verifies container build definitions for all microservices.
