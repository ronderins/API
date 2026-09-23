# Aegis

Privacy-preserving identity and predicate verification engine. Verify age and credential eligibility over HTTP without receiving, processing, or storing personal identifiable information (PII).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org/)
[![Rust 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

---

## Overview

Traditional identity verification systems require users to upload clear, unredacted scans of their passports, driver's licenses, or national ID cards to central cloud servers. This approach creates high-risk honeypots of sensitive customer data, exposes platforms to catastrophic data breach liabilities under regulations like GDPR and CCPA, and causes high user friction.

Aegis solves this by decoupling **eligibility verification** from **data collection**:

1. **Client-Side Hashing**: The user's device computes a cryptographic hash of the identity document locally via WebCrypto. Raw documents and images never touch the network.
2. **Predicate Verification**: The backend verifies mathematical constraints (e.g., `Age >= 21`) against the document commitment without learning the birthdate or identity details.
3. **Signed Proof Tokens & Receipts**: Aegis issues a tamper-evident, signed JWT proof token and records an immutable leaf in an append-only Blake3 Merkle tree for independent auditability.
4. **Zero Data Retention**: Stack and heap buffers are zeroized upon evaluation. No names, birthdates, social security numbers, or scans are ever persisted to disk.

---

## How It Works

```text
[ User Device ] 
       │
       │ 1. Hash document locally (SHA-256)
       ▼
[ Client Application ]
       │
       │ 2. Fetch single-use nonce: GET /api/v1/session
       │ 3. Submit predicate check: POST /api/v1/verify
       ▼
[ Aegis Engine ]
       │
       ├── Evaluate predicate: (CurrentYear - BirthYear >= Threshold)
       ├── Zeroize witness memory buffers
       ├── Commit leaf to append-only Merkle ledger
       └── Issue signed JWT proof token
       │
       ▼
[ Verified Response ] ──> HTTP 200 { verified: true, proof_token, merkle_root }
```

---

## Quickstart & Integration

### 1. Acquire Anti-Replay Nonce
Fetch a single-use ephemeral challenge nonce (300-second TTL) to protect against replay attacks:

```bash
curl -s http://localhost:3000/api/v1/session
```

Response:
```json
{
  "session_nonce": "9e12bf4a-7c3d-4e8f-9a1b-0d2e3f4a5b6c",
  "expires_in": 300
}
```

### 2. Verify Predicate
Submit the client-side document digest and the required threshold:

```bash
curl -X POST http://localhost:3000/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "customer-alice-492",
    "doc_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "age_threshold": 21
  }'
```

Response:
```json
{
  "proof_id": "prf_8f3c4e2b1a0d9e8f",
  "criteria_met": "age_over_21",
  "commitment": "b2f6d7e9a1b8c3d4dc0af8e9f0b1c2d3a4b5c6d7e8f90a1b2c3d4e5f60718293",
  "proof_signature": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "merkle_root": "0x4a7d3b8f1c2e5a9b0d6f8e7a1c3b5d7f9e2a4b6c8d0e1f3a5b7c9d1e3f5a7b9c",
  "timestamp": 1774313545
}
```

### 3. Verify Existing Proof Token
Validate a previously minted proof token without contacting database storage:

```bash
curl -X POST http://localhost:3000/api/v1/verify-token \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

---

## Code Examples

### TypeScript / Node.js
```typescript
import { createHash } from "crypto";

interface VerifyResponse {
  proof_id: string;
  criteria_met: string;
  commitment: string;
  proof_signature: string;
  merkle_root?: string;
}

export async function verifyAgeEligibility(
  documentBuffer: Buffer,
  pseudonymousUserId: string,
  requiredAge = 21
): Promise<VerifyResponse> {
  const AEGIS_URL = process.env.AEGIS_URL || "http://localhost:3000";

  // 1. Hash document locally on device (raw bytes never transmitted)
  const docHash = createHash("sha256").update(documentBuffer).digest("hex");

  // 2. Dispatch verification request
  const response = await fetch(`${AEGIS_URL}/api/v1/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_id: pseudonymousUserId,
      doc_hash: docHash,
      age_threshold: requiredAge,
    }),
  });

  if (!response.ok) {
    throw new Error(`Verification failed with status ${response.status}`);
  }

  return (await response.json()) as VerifyResponse;
}
```

### Python 3
```python
import hashlib
import requests

AEGIS_URL = "http://localhost:3000"

# 1. Compute document digest locally
raw_doc_bytes = b"passport_scan_data"
doc_hash = hashlib.sha256(raw_doc_bytes).hexdigest()

# 2. Submit verification request
res = requests.post(f"{AEGIS_URL}/api/v1/verify", json={
    "user_id": "customer-bob-883",
    "doc_hash": doc_hash,
    "age_threshold": 21
})

data = res.json()
print("Criteria met:", data.get("criteria_met"))
print("Proof commitment:", data.get("commitment"))
```

### Rust
```rust
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let res = client
        .post("http://localhost:3000/api/v1/verify")
        .header("Content-Type", "application/json")
        .json(&json!({
            "user_id": "customer-clara-210",
            "doc_hash": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
            "age_threshold": 21
        }))
        .send()
        .await?;

    println!("Status: {}", res.status());
    println!("Response: {}", res.text().await?);
    Ok(())
}
```

---

## API Reference

All endpoints return JSON and use standard HTTP status codes.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/healthz` | System health check and engine liveness status |
| `GET` | `/api/v1/session` | Generates a single-use replay challenge nonce (300s TTL) |
| `POST` | `/api/v1/verify` | Evaluates predicate constraints and issues signed verification tokens |
| `POST` | `/api/v1/verify-token` | Validates signed cryptographic JWT tokens and checks expiration |
| `POST` | `/api/v1/verify-merkle` | Validates Merkle inclusion paths against the published ledger root |
| `GET` | `/api/v1/ledger` | Returns append-only Merkle block ledger receipts |
| `GET` | `/api/v1/proofs` | Lists historical proof commitments and timestamps (Zero PII) |
| `GET` | `/api/v1/proofs/{id}` | Retrieves a specific proof record and its verification receipt |
| `GET` | `/api/v1/metrics` | Microsecond execution latency and memory usage |
| `GET` | `/api/v1/stats` | Real-time counts of proofs minted and audit log entries |

---

## Architecture

Aegis is organized into four distinct operational layers:

1. **Client Edge**: Hashing of identity documents happens on user hardware using WebCrypto or native libraries.
2. **API Gateway**: Provides anti-replay nonces, enforces schema validation, and handles constant-time token evaluation.
3. **Core Verification Engine**: Evaluates predicate arithmetic, securely wipes witness memory via zeroization, and calculates domain-separated commitments.
4. **Cryptographic Ledger**: Records commitments into an append-only Blake3 Merkle tree, enabling non-repudiable audit trails with logarithmic inclusion verification.

---

## Security Invariants

* **Zero PII Footprint**: Neither document photos, names, nor dates of birth are ever written to disk or logged.
* **Memory Zeroization**: Stack and heap buffers containing intermediate witness variables implement `ZeroizeOnDrop` to prevent forensic memory dumps.
* **Anti-Replay Mechanism**: Nonces are tied to single verification requests and expire after 300 seconds.
* **Constant-Time Comparison**: Cryptographic tokens and hashes are validated using constant-time byte comparisons to protect against timing side-channel attacks.
* **Merkle Receipts**: Attestations can be audited against the append-only Merkle tree root without disclosing any personal data.

---

## Local Setup

### Option 1: Next.js Full Stack (Default)
Runs Next.js App Router with the built-in cryptographic engine on port 3000:

```bash
npm install
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000).

### Option 2: Docker Compose (Next.js + Rust Axum Engine)
Runs the native Rust engine on port 8080 with Next.js running on port 3000:

```bash
docker compose up --build
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
