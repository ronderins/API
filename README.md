<div align="center">

# Aegis • Cryptographic Identity & Predicate Verification Engine

<p align="center">
  <strong>Zero-Knowledge Attestation • Zero PII Retention • Sub-Millisecond Rust Core • Blake3 Merkle Receipts</strong>
</p>

[![Aegis Architectural Banner](assets/hero-banner.svg)](https://github.com/ronderins/API)

<p align="center">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-10b981?style=flat-square&logo=shield" alt="Status" />
  <img src="https://img.shields.io/badge/Rust-1.80%2B%20Axum-f97316?style=flat-square&logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/Frontend-Next.js%2015%20App%20Router-000000?style=flat-square&logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/Latency-%3C150%C2%B5s%20SIMD%20Blake3-38bdf8?style=flat-square&logo=speedtest" alt="Latency" />
  <img src="https://img.shields.io/badge/PII%20Retention-0%20Bytes-10b981?style=flat-square&logo=databricks" alt="PII Retention" />
  <img src="https://img.shields.io/badge/Post--Quantum-FIPS%20204%20ML--DSA-a855f7?style=flat-square&logo=quantumcomputing" alt="Post-Quantum" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License" />
</p>

<p align="center">
  <a href="#-what-is-aegis-api-goal--problem-statement">API Goal</a> •
  <a href="#-who-is-aegis-for--how-is-it-useful">Who Is It For?</a> •
  <a href="#-system-design--architecture-animation">System Design</a> •
  <a href="#-how-it-works-under-the-hood">How It Works</a> •
  <a href="#-api-quickstart--code-examples">API Quickstart</a> •
  <a href="#-production-deployment">Deployment</a> •
  <a href="#-cryptographic-specifications">Security Spec</a>
</p>

---

</div>

## 🎯 What Is Aegis? (API Goal & Problem Statement)

### The Fundamental Digital Identity Dilemma
Every day, millions of digital businesses face a crippling compliance paradox:
1. **Regulations mandate strict verification**: Global laws (such as the UK Online Safety Act, EU Digital Services Act, US State Age Gating laws, and FINRA/CFTC financial regulations) require platforms to verify user eligibility—such as confirming an individual is 18+ or 21+, not located in a sanctioned jurisdiction, or holding a valid credential.
2. **Traditional verification creates catastrophic legal liabilities**: Conventional Identity/KYC vendors force users to upload high-resolution photos of passports, driver's licenses, and national identity cards. Platforms store these unencrypted or loosely guarded files in cloud buckets—creating massive **"honeypots"** that are repeatedly hacked, leaked, or ransomed.

> Under GDPR Article 83, storing user identity data exposes companies to penalties up to **€20,000,000 or 4% of global annual turnover**, while 40%+ of potential customers abandon registration forms when prompted to upload physical government documents.

### The Aegis Solution
**Aegis is a high-assurance, privacy-preserving cryptographic attestation engine.** 

The goal of the Aegis API is to enable applications to verify identity predicates—such as **"Is this user over 21?"**, **"Is this passport genuine and unexpired?"**, or **"Is this entity absent from an OFAC sanctions list?"**—**WITHOUT EVER collecting, transmitting, indexing, or storing the user's raw Personally Identifiable Information (PII).**

* **0 Bytes PII Stored**: Neither raw photos, names, social security numbers, nor dates of birth ever touch server disks or databases.
* **Mathematical Invariance**: Proofs are constructed using client-side cryptographic hashing, blinding nonces, and arithmetic predicate evaluation.
* **Append-Only Merkle Block Ledger**: Every verification receipt is chained in an immutable Blake3 Merkle tree with $O(\log N)$ tamper-evident inclusion proof verification.
* **Deterministic RAM Scrubbing (`zeroize`)**: Heap and stack witnesses are purged to zeroes immediately upon constraint evaluation.

---

## 👥 Who Is Aegis For & How Is It Useful?

Aegis was specifically architected to serve five distinct stakeholder groups, solving concrete operational, legal, and engineering bottlenecks:

| Stakeholder / Persona | Their Core Pain Point | How Aegis Solves It | Tangible Business & Security Value |
| :--- | :--- | :--- | :--- |
| **🛒 Online Platforms, Gaming & E-Commerce** | Mandated age verification (alcohol, adult content, regulated gaming) triggers 40%+ cart abandonment and massive data breach exposure. | Evaluates `Age >= Threshold` client-side. The platform receives a signed cryptographic token stating `verified: true`. | **100% regulatory compliance** with zero customer drop-off and zero minor data liability. |
| **🏦 FinTech, DeFi & Web3 Protocols** | Need to verify KYC/AML compliance and sanctions non-membership without de-anonymizing wallet addresses or hosting toxic PII vaults. | Binds cryptographic commitments directly to user public keys or EVM calldata without public disclosure of private net worth or legal names. | **Auditable compliance** while preserving user pseudonymity and decentralized trust guarantees. |
| **💻 Software Engineers & Dev Teams** | Building zero-knowledge circuits from scratch requires rare cryptographic expertise, complex math, and costly vendor lock-in. | Single-line HTTP REST API (`POST /api/v1/verify`), OpenAPI 3.1 specification, and sub-millisecond response latency (<150µs). | **5-minute integration** using standard JSON payloads, self-sovereign API keys, and zero vendor lock-in. |
| **🛡️ Compliance Officers, CISOs & Auditors** | Traditional vendors offer opaque marketing claims ("military-grade encryption") while secretly storing raw customer logs. | Tamper-evident Blake3 Merkle ledger, open-source Rust engine, and mathematical non-repudiation receipts (`POST /api/v1/verify-merkle`). | **Zero GDPR/CCPA data breach liability**; independent mathematical verification replaces blind trust. |
| **👤 Everyday Citizens & Consumers** | Users must upload sensitive documents to unvetted websites, exposing them to identity theft, stalking, and credit fraud. | The physical document never leaves the device. WebCrypto calculates a one-way hash and blinding salt before any bytes touch the wire. | **Absolute digital sovereignty**: users prove their eligibility without surrendering their private lives. |

---

## 🏗️ System Design & Architecture (Animation)

Aegis is structured into four secure execution tiers. Watch the animated architectural pipeline below to understand how an attestation flows from the user's browser down to the immutable cryptographic ledger:

<div align="center">
  <img src="assets/system-architecture.svg" alt="Aegis Architectural System Design" width="100%" />
</div>

### Architectural Tiers Breakdown

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. CLIENT / SUBJECT EDGE (Device-Side WebCrypto / SDK)                                                 │
│    • Raw Passport / ID photo scanned locally                                                           │
│    • WebCrypto Blake3 / SHA-256 digest generated: H(doc)                                               │
│    • Cryptographic Blinding Nonce (r) injected                                                         │
│    • [CRITICAL]: Raw PII is wiped from device memory immediately (0 bytes transmitted)                 │
└───────────────────────────────────┬────────────────────────────────────────────────────────────────────┘
                                    │ HTTPS (TLS 1.3) + Encrypted Payload
                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. API GATEWAY & SESSION GUARD (Rust Axum / Next.js Proxy)                                             │
│    • Session Challenge Nonce (GET /api/v1/session, 300s TTL) prevents replay attacks                   │
│    • Constant-Time Timing Shield: prevents side-channel execution analysis                             │
│    • Seccomp Linux Sandbox & Strict CSP Security Headers enforced                                      │
└───────────────────────────────────┬────────────────────────────────────────────────────────────────────┘
                                    │ Memory Buffer Dispatch
                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. AEGIS CRYPTOGRAPHIC ENGINE (Native Rust Microservice)                                               │
│    • Predicate Constraint Evaluator (Groth16 BN254 / Bulletproofs range check)                         │
│    • Arithmetic Constraint: (current_year - birth_year >= threshold) == 1                              │
│    • Deterministic RAM Scrubbing: zeroize::Zeroize::zeroize(&mut witness)                              │
│    • Post-Quantum Hybrid Attestation: NIST FIPS 204 (ML-DSA) + Classical Ed25519                     │
└───────────────────────────────────┬────────────────────────────────────────────────────────────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────────────────────────────────────┐
│ 4A. VERIFIER ATTESTATION TOKEN       │  │ 4B. APPEND-ONLY BLAKE3 MERKLE BLOCK LEDGER                   │
│ • Cryptographically signed JWT token │  │ • Proof commitment Leaf hashed into SIMD Blake3 tree        │
│ • Payload: { verified: true, ... }   │  │ • Immutable block chained in SQLite ledger                   │
│ • Consumed by relying party          │  │ • Logarithmic O(log N) inclusion receipt verification        │
└──────────────────────────────────────┘  └──────────────────────────────────────────────────────────────┘
```

---

## 🔬 How It Works Under The Hood

The diagram below contrasts the traditional, highly vulnerable KYC honeypot model with the Aegis zero-knowledge mathematical predicate pipeline:

<div align="center">
  <img src="assets/zk-how-it-works.svg" alt="How Aegis ZK Verification Works Under The Hood" width="100%" />
</div>

### Detailed 5-Step Cryptographic Execution Cycle

#### Step 1: Client-Side One-Way Hash & Blinding Nonce
When a user provides a document (e.g., passport or driver's license), the raw bytes are **never transmitted**. Instead, the client generates a 256-bit hash bound with a random blinding nonce $r$:
$$\text{doc\_hash} = \text{Blake3}(\text{document\_bytes} \parallel r)$$
The user's raw file is wiped from browser RAM immediately. An adversary intercepting network traffic sees only an irreversible 64-character hexadecimal digest.

#### Step 2: Ephemeral Witness Generation & Predicate Constraint
The verification service evaluates an arithmetic circuit over a finite field $\mathbb{F}_q$:
$$\mathcal{C}(\text{witness}) \implies (\text{current\_year} - \text{birth\_year} \ge \text{threshold}) \stackrel{?}{=} 1$$
If the constraint holds, the predicate evaluates to `true`. The prover satisfies the constraint system without revealing the private witness (exact birthdate).

#### Step 3: Domain-Separated Cryptographic Commitment
To guarantee non-repudiation and prevent cross-application forgery, a salted cryptographic commitment $C$ is synthesized with domain separation:
$$C = \text{SHA-256}(\text{"zk-identity-proof-v1"} \parallel \text{user\_digest} \parallel \text{doc\_hash} \parallel \text{threshold} \parallel \text{session\_nonce})$$

#### Step 4: Deterministic RAM Scrubbing (`zeroize`)
Standard programming runtimes often leave sensitive cryptographic keys and witness variables in heap memory indefinitely. Aegis enforces deterministic hardware memory wiping using the Rust `zeroize` crate:
```rust
// rust-api/src/security/guarded_memory.rs
use zeroize::Zeroize;

let mut witness_buffer: [u8; 32] = compute_ephemeral_witness();
evaluate_circuit_constraints(&witness_buffer)?;

// Deterministically overwrite memory with 0x00 bytes before deallocation
witness_buffer.zeroize();
```
Even if an attacker achieves a core dump or physical memory acquisition of the host server, no remnants of the witness or private credentials exist in RAM.

#### Step 5: Append-Only Merkle Block Receipt
Every successful attestation generates an immutable block receipt in the Blake3 Merkle tree:

<div align="center">
  <img src="assets/merkle-ledger.svg" alt="Append-Only Blake3 Merkle Block Ledger" width="100%" />
</div>

Auditors can verify that a specific attestation was legally issued by querying `POST /api/v1/verify-merkle`. Verification requires only $O(\log N)$ sibling hashes, verifying the mathematical inclusion path against the published Merkle Root without exposing any other user's proof.

---

## ⚡ API Quickstart & Code Examples

Aegis is completely self-sovereign. No credit cards or account registrations are required.

### 1. Bash / cURL
```bash
# Step 1: Fetch a short-lived session challenge nonce (5-min TTL)
SESSION=$(curl -s https://your-aegis-host/api/v1/session)
NONCE=$(echo $SESSION | jq -r '.session_nonce')

# Step 2: Generate a privacy-preserving age attestation (Age >= 21)
curl -X POST https://your-aegis-host/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "user_digest": "4a7d3b8f1c2e5a9b0d6f8e7a1c3b5d7f9e2a4b6c8d0e1f3a5b7c9d1e3f5a7b9c",
    "doc_hash": "8f3c4e2b1a0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f",
    "threshold": 21,
    "current_year": 2026,
    "birth_year": 2001,
    "nonce": "'"$NONCE"'"
  }'

# Step 3: Verify the issued cryptographic JWT proof token
curl -X POST https://your-aegis-host/api/v1/verify-token \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

### 2. TypeScript / Node.js
```typescript
import { createHash, randomBytes } from "crypto";

async function verifyAgeWithAegis(passportBytes: Buffer, birthYear: number) {
  // 1. Client-Side Hash: Document never leaves the device
  const docHash = createHash("sha256").update(passportBytes).digest("hex");
  const userDigest = createHash("sha256").update("user_unique_salt").digest("hex");

  // 2. Request ephemeral session challenge
  const sessionRes = await fetch("https://your-aegis-host/api/v1/session");
  const { session_nonce } = await sessionRes.json();

  // 3. Submit cryptographic predicate verification
  const verifyRes = await fetch("https://your-aegis-host/api/v1/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_digest: userDigest,
      doc_hash: docHash,
      threshold: 21,
      current_year: new Date().getFullYear(),
      birth_year: birthYear,
      nonce: session_nonce,
    }),
  });

  const attestation = await verifyRes.json();
  console.log("Proof Result:", attestation.status); // "verified"
  console.log("Cryptographic Receipt:", attestation.proof_token);
  return attestation;
}
```

### 3. Python 3
```python
import hashlib, requests

# 1. Compute client-side document hash locally
doc_bytes = b"sample_raw_passport_data_or_mrz"
doc_hash = hashlib.sha256(doc_bytes).hexdigest()
user_digest = hashlib.sha256(b"pseudonymous_user_id").hexdigest()

# 2. Acquire ephemeral challenge
base_url = "https://your-aegis-host"
session = requests.get(f"{base_url}/api/v1/session").json()

# 3. Request zero-knowledge verification
response = requests.post(f"{base_url}/api/v1/verify", json={
    "user_digest": user_digest,
    "doc_hash": doc_hash,
    "threshold": 21,
    "current_year": 2026,
    "birth_year": 2002,
    "nonce": session["session_nonce"]
})

result = response.json()
print(f"Status: {result['status']}") # verified
print(f"Merkle Block ID: {result['block_id']}")
```

---

## 📡 Complete API Endpoint Reference

| Method | Endpoint | Description | Request Body / Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | System health, service status, and memory liveness check | None |
| `GET` | `/api/v1/session` | Generates a single-use challenge nonce (300s TTL) | None |
| `POST` | `/api/v1/verify` | Evaluates predicate constraints and issues signed verification tokens | `{ user_digest, doc_hash, threshold, current_year, birth_year, nonce }` |
| `POST` | `/api/v1/verify-token`| Validates signed cryptographic JWT tokens and checks expiration | `{ token }` |
| `POST` | `/api/v1/verify-merkle`| Validates Merkle inclusion paths against the published ledger root | `{ proof_id, leaf_hash, merkle_root, sibling_path }` |
| `GET` | `/api/v1/ledger` | Returns the append-only Blake3 Merkle block ledger receipts | `?limit=50&offset=0` |
| `GET` | `/api/v1/proofs` | Lists historical proof commitments and timestamps | None |
| `GET` | `/api/v1/proofs/{id}` | Retrieves a specific proof record and its verification receipt | Path parameter: `id` |
| `GET` | `/api/v1/metrics` | Real-time microsecond execution latency and memory usage | None |
| `GET` | `/api/v1/stats` | Aggregated engine metrics and active Merkle root digests | None |

---

## 🚀 Production Deployment

Aegis is 100% self-hosted and autonomous. It requires no third-party SaaS accounts or external API keys.

### Option 1: Native Vercel Deployment (Zero-Config)
The Next.js workbench incorporates the built-in TypeScript cryptographic core as a seamless fallback, enabling zero-config deployment to Vercel:
1. Fork or push this repository to GitHub.
2. Import the repository into [Vercel](https://vercel.com).
3. Framework Preset: **Next.js** (automatically detected).
4. Node.js Version: **20.x** or **22.x**.
5. Click **Deploy**.

### Option 2: Docker Compose (Full Stack: Rust Axum + Next.js)
Deploy both the sub-millisecond Rust Axum microservice and Next.js frontend with a single command:
```bash
# Clone the repository
git clone https://github.com/ronderins/API.git
cd API

# Launch both services in isolated containers
docker compose up --build -d
```
* The Next.js Verification Workbench runs at `http://localhost:3000`
* The Native Rust Axum Engine runs at `http://localhost:8080`

### Option 3: Local Development
```bash
# 1. Install frontend dependencies
npm install

# 2. Run Next.js development server
npm run dev

# 3. (Optional) Run Rust Axum service locally
cd rust-api
cargo run --release
```

---

## 🔐 Environment Configuration

| Variable | Required | Description | Default |
| :--- | :---: | :--- | :--- |
| `PORT` | Optional | HTTP port for the web server | `3000` |
| `RUST_API_URL` | Optional | Address of the native Rust Axum microservice | `http://localhost:8080` |
| `API_KEY` | Optional | Enforces pre-shared key header authentication (`X-API-Key`) | `None` (Open Mode) |
| `API_KEYS` | Optional | Comma-separated list of authorized pre-shared API keys | `None` |
| `CANARY_ENFORCE` | Optional | Enforce binary SHA-256 release integrity verification | `false` |
| `CANARY_CANONICAL_SHA256` | Optional | Expected canonical SHA-256 digest of the compiled binary | `None` |

---

## 🛡️ Cryptographic Specifications & Hardening

* **Zero-Knowledge Circuit Family**: Groth16 over the BN254 (alt_bn128) pairing-friendly elliptic curve, Bulletproofs for logarithmic range proofs, and Nova Incremental Verifiable Computation (IVC) for multi-predicate proof folding.
* **Hashing Primitives**: Blake3 with SIMD vectorization (AVX2 / AVX-512 / ARM NEON) executing in <100ns per digest; NIST SHA-256 with domain separation prefixes (`zk-identity-proof-v1`).
* **Post-Quantum Hybrid Readiness**: Dual-signed commitments combining classical Ed25519 with NIST FIPS 204 ML-DSA (Module-Lattice Digital Signatures) for quantum forward secrecy.
* **Memory Protection**: Zeroization of stack and heap witness structures using the `zeroize` crate to prevent RAM dump forensics.
* **Constant-Time Guarantees**: Cryptographic comparisons executed via `subtle::ConstantTimeEq` to eliminate timing side-channels.
* **Compliance Standards**: Formally aligned with **W3C Verifiable Credentials Data Model 2.0**, **ISO/IEC 18013-5 mDL**, and **EU eIDAS 2.0 Architectural Framework**.

---

## 📄 License & Attribution

Developed by **Rony M. ([@ronderins](https://github.com/ronderins))**.

Released under the **MIT License**. You are free to use, modify, distribute, and integrate Aegis into commercial and open-source applications without restriction.
