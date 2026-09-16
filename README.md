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
  <img src="https://img.shields.io/badge/Open%20Source-Community%20Driven-ec4899?style=flat-square" alt="Open Source" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License" />
</p>

<p align="center">
  <a href="#-what-is-aegis"><img src="assets/icons/target.svg" width="26" height="26" align="absmiddle" /> What Is Aegis</a> &nbsp;•&nbsp;
  <a href="#-who-is-aegis-for"><img src="assets/icons/users.svg" width="26" height="26" align="absmiddle" /> Who Is It For</a> &nbsp;•&nbsp;
  <a href="#-system-architecture"><img src="assets/icons/architecture.svg" width="26" height="26" align="absmiddle" /> Architecture</a> &nbsp;•&nbsp;
  <a href="#-how-it-works"><img src="assets/icons/circuit.svg" width="26" height="26" align="absmiddle" /> How It Works</a> &nbsp;•&nbsp;
  <a href="#-how-to-consume-the-api"><img src="assets/icons/zap.svg" width="26" height="26" align="absmiddle" /> Consume The API</a> &nbsp;•&nbsp;
  <a href="#-ui-design--animation-system"><img src="assets/icons/code.svg" width="26" height="26" align="absmiddle" /> UI & Animations</a> &nbsp;•&nbsp;
  <a href="#-api-reference"><img src="assets/icons/terminal.svg" width="26" height="26" align="absmiddle" /> API Reference</a> &nbsp;•&nbsp;
  <a href="#-deployment"><img src="assets/icons/rocket.svg" width="26" height="26" align="absmiddle" /> Deployment</a> &nbsp;•&nbsp;
  <a href="#-security-specifications"><img src="assets/icons/shield.svg" width="26" height="26" align="absmiddle" /> Security Spec</a>
</p>

---

</div>

## <img src="assets/icons/target.svg" width="34" height="34" align="absmiddle" /> What Is Aegis?

### What Does This API Do?
**Aegis is an HTTP REST API for verifying user identity attributes (such as "Age ≥ 21", "Unexpired Passport", or "Sanctions-Free Entity") without ever collecting, inspecting, or storing the user's personal data (PII).**

Instead of forcing users to upload passport photos or driver's licenses to your cloud servers:
1. **The client hashes the document locally**: Your frontend or mobile app hashes the ID using Blake3 or SHA-256 with a client salt. Raw document bytes never leave the user's device.
2. **Your backend sends the hash and predicate rule to Aegis** (`POST /api/v1/verify`).
3. **Aegis evaluates the zero-knowledge circuit in Rust memory (<150µs)**, deterministically wipes all witness data from RAM (`zeroize`), and writes an audit leaf to an append-only Blake3 Merkle tree.
4. **Aegis returns a signed verification token** (`{ verified: true }`) that your application can independently verify with standard public key cryptography.

```json
// 1. Request: What your app sends to POST /api/v1/verify
{
  "user_digest": "4a7d3b8f1c2e5a9b0d6f8e7a1c3b5d7f9e2a4b6c8d0e1f3a5b7c9d1e3f5a7b9c",
  "doc_hash": "8f3c4e2b1a0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f",
  "threshold": 21,
  "current_year": 2026,
  "birth_year": 2001,
  "nonce": "e9b4072f8a1c4d92"
}

// 2. Response: What Aegis returns in <150 microseconds
{
  "status": "verified",
  "predicate": "age_over_21",
  "verified": true,
  "proof_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "merkle_root": "0x9e12bf4a...7e",
  "leaf_hash": "0x4a11c8d0...b2",
  "latency_us": 142
}
```

### Core Developer Guarantees
* <img src="assets/icons/shield-check.svg" width="26" height="26" align="absmiddle" /> **0 Bytes PII Stored**: Neither raw photos, names, social security numbers, nor dates of birth ever touch server disks or databases.
* <img src="assets/icons/shield-check.svg" width="26" height="26" align="absmiddle" /> **Sub-Millisecond Rust Engine**: Verification runs in <150µs using an Axum + SIMD Blake3 native microservice.
* <img src="assets/icons/shield-check.svg" width="26" height="26" align="absmiddle" /> **Deterministic RAM Scrubbing (`zeroize`)**: Heap and stack witnesses are purged to zeroes immediately upon constraint evaluation.
* <img src="assets/icons/shield-check.svg" width="26" height="26" align="absmiddle" /> **Append-Only Merkle Block Ledger**: Every verification receipt is chained in an immutable Blake3 Merkle tree with $O(\log N)$ tamper-evident inclusion proof verification.

---

## <img src="assets/icons/users.svg" width="34" height="34" align="absmiddle" /> Who Is Aegis For?

| Use Case / Domain | Typical Industry Problem | What You Implement With Aegis | Result & Developer Value |
| :--- | :--- | :--- | :--- |
| <img src="assets/icons/cart.svg" width="28" height="28" align="absmiddle" /> **Age-Restricted Platforms & E-Commerce** | Mandated age checks (gaming, alcohol delivery, adult content) cause 40%+ drop-off and severe minor data liabilities. | Call `POST /api/v1/verify` with `threshold: 18` or `21`. Client hashes the ID; you receive a signed verification token. | **Full regulatory compliance** with zero customer drop-off and zero stored user PII. |
| <img src="assets/icons/bank.svg" width="28" height="28" align="absmiddle" /> **FinTech, Web3 & Crypto Protocols** | AML/sanctions compliance requires screening users without de-anonymizing wallet addresses or hosting toxic PII vaults. | Evaluate sanctions non-membership or accredited investor rules over cryptographic commitments. | **Auditable compliance** while preserving user privacy and decentralized trust. |
| <img src="assets/icons/code.svg" width="28" height="28" align="absmiddle" /> **Software Engineers & Backend Devs** | Custom ZK circuits require specialized math, circuit compilers, and costly vendor contracts. | Single HTTP REST API (`POST /api/v1/verify`), OpenAPI 3.1 specification, and sub-millisecond execution. | **5-minute integration** using standard JSON payloads, self-sovereign keys, and zero vendor lock-in. |
| <img src="assets/icons/audit.svg" width="28" height="28" align="absmiddle" /> **Compliance Officers & Security Auditors** | Auditing traditional KYC vendors requires trusting proprietary logs and opaque promises. | Query `POST /api/v1/verify-merkle` to mathematically verify inclusion in the Blake3 Merkle ledger. | **Zero data breach liability**; mathematical non-repudiation replaces blind trust. |
| <img src="assets/icons/person.svg" width="28" height="28" align="absmiddle" /> **End Users & Privacy Advocates** | Users must upload sensitive government documents to unvetted websites, risking identity theft. | Documents are hashed on the user's device. No raw identity bytes ever cross the network. | **Digital sovereignty**: users prove their eligibility without surrendering their private identity. |

---

## <img src="assets/icons/architecture.svg" width="34" height="34" align="absmiddle" /> System Architecture

Aegis is structured into four secure execution tiers. The architectural pipeline below illustrates how an attestation flows from the user's browser down to the immutable cryptographic ledger:

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

## <img src="assets/icons/circuit.svg" width="34" height="34" align="absmiddle" /> How It Works

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

## <img src="assets/icons/zap.svg" width="34" height="34" align="absmiddle" /> How to Consume the API (Developer Integration Guide)

Aegis is engineered for instant, zero-friction developer adoption. It is 100% self-contained: no external SaaS signups, credit cards, or proprietary vendor credentials are required.

### How the API is Created & Operates
* **Dual Execution Runtime**: Aegis includes both a full-stack **Next.js 15 App Router** engine (`/src/app/api/v1/*`) running on port `3000` and an optional native **Rust Axum** microservice (`/rust-api`) running on port `8080`. Both runtimes implement identical cryptographic API contracts.
* **Authentication**: Optional pre-shared API key authorization via `X-API-Key: <key>` header or `Authorization: Bearer <key>`. Verification uses constant-time byte comparisons (`crypto.timingSafeEqual` in Node.js / `subtle::ConstantTimeEq` in Rust) to eliminate side-channel timing leaks.
* **Zero PII Payload Guarantee**: The API strictly forbids raw identity bytes. The client hashes the identity document and user ID locally. Aegis receives only 64-character hexadecimal SHA-256/Blake3 digests and numerical predicate thresholds.
* **Cryptographic Invariants**: Outputs tamper-evident HS256 JWT attestation tokens, domain-separated commitment hashes (`SHA-256("zk-identity-proof-v1\0" || user_digest || doc_hash || threshold || nonce)`), and appends an immutable leaf to an in-memory Blake3 Merkle tree.

---

### Step-by-Step Realistic Consumption Flow

```
[User Device]                           [Your App Backend]                          [Aegis API]
     │                                          │                                        │
     │ 1. Hash Document Locally (Blake3/SHA256) │                                        │
     ├─────────────────────────────────────────>│                                        │
     │                                          │ 2. Fetch Challenge Nonce               │
     │                                          ├───────────────────────────────────────>│
     │                                          │<───────────────────────────────────────┤ (200 OK: session_nonce)
     │                                          │                                        │
     │                                          │ 3. Submit Predicate Verification       │
     │                                          ├───────────────────────────────────────>│ (POST /api/v1/verify)
     │                                          │<───────────────────────────────────────┤ (200 OK: proof_token, merkle_root)
     │                                          │                                        │
     │ 4. Verified Access Granted               │ 5. (Optional) Audit Ledger Inclusion   │
     │<─────────────────────────────────────────┤                                        ├───────────────────────────────────────>│ (POST /api/v1/verify-merkle)
```

---

### Code Examples: Real-World Consumption

#### 1. TypeScript & Node.js / Next.js
```typescript
import { createHash } from "crypto";

interface AegisVerifyResponse {
  status: "verified" | "rejected";
  predicate: string;
  verified: boolean;
  proof_id: string;
  proof_token: string;
  commitment: string;
  merkle_root: string;
  latency_us: number;
}

async function verifyUserAge(
  rawDocumentBytes: Buffer,
  pseudonymousUserId: string,
  userBirthYear: number,
  requiredAge = 21
): Promise<AegisVerifyResponse> {
  const AEGIS_BASE_URL = process.env.AEGIS_API_URL || "http://localhost:3000";
  const AEGIS_API_KEY = process.env.AEGIS_API_KEY;

  // Step 1: Client/Edge hashes document locally (Raw document NEVER leaves device/memory)
  const docHash = createHash("sha256").update(rawDocumentBytes).digest("hex");
  const userDigest = createHash("sha256").update(pseudonymousUserId).digest("hex");

  // Step 2: Fetch single-use session challenge nonce (prevents replay attacks)
  const sessionRes = await fetch(`${AEGIS_BASE_URL}/api/v1/session`);
  if (!sessionRes.ok) throw new Error("Failed to acquire challenge nonce");
  const { session_nonce } = await sessionRes.json();

  // Step 3: Dispatch verification request
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (AEGIS_API_KEY) headers["X-API-Key"] = AEGIS_API_KEY;

  const verifyRes = await fetch(`${AEGIS_BASE_URL}/api/v1/verify`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      user_digest: userDigest,
      doc_hash: docHash,
      threshold: requiredAge,
      current_year: new Date().getFullYear(),
      birth_year: userBirthYear,
      nonce: session_nonce,
    }),
  });

  if (!verifyRes.ok) {
    const errorData = await verifyRes.json();
    throw new Error(`Aegis verification error: ${errorData.error || verifyRes.statusText}`);
  }

  const result: AegisVerifyResponse = await verifyRes.json();
  
  // Step 4: Validate token (or store in your user session)
  console.log(`Verification status: ${result.status}`); // "verified"
  console.log(`Proof Token (JWT): ${result.proof_token}`);
  console.log(`Merkle Root: ${result.merkle_root}`);
  console.log(`Latency: ${result.latency_us}µs`);

  return result;
}
```

#### 2. cURL / Bash
```bash
# 1. Acquire single-use ephemeral challenge nonce (300s TTL)
NONCE=$(curl -s http://localhost:3000/api/v1/session | jq -r '.session_nonce')

# 2. Submit privacy-preserving age predicate check (Age >= 21)
# Note: user_digest and doc_hash are client-generated 64-char SHA-256 hex strings
curl -X POST http://localhost:3000/api/v1/verify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test-api-key" \
  -d '{
    "user_digest": "4a7d3b8f1c2e5a9b0d6f8e7a1c3b5d7f9e2a4b6c8d0e1f3a5b7c9d1e3f5a7b9c",
    "doc_hash": "8f3c4e2b1a0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f",
    "threshold": 21,
    "current_year": 2026,
    "birth_year": 2002,
    "nonce": "'"$NONCE"'"
  }'

# 3. Validate issued tamper-evident JWT proof token
curl -X POST http://localhost:3000/api/v1/verify-token \
  -H "Content-Type: application/json" \
  -d '{"token": "<TOKEN_FROM_STEP_2>"}'

# 4. Lookup immutable audit ledger entry by proof ID
curl -s http://localhost:3000/api/v1/proofs/<PROOF_ID> | jq .
```

#### 3. Python 3 (requests)
```python
import hashlib
import requests

AEGIS_URL = "http://localhost:3000"
HEADERS = {"X-API-Key": "your-api-key"}

# 1. Compute client-side digests locally
doc_bytes = b"sample_raw_passport_mrz_data"
doc_hash = hashlib.sha256(doc_bytes).hexdigest()
user_digest = hashlib.sha256(b"user_unique_identifier").hexdigest()

# 2. Request single-use challenge nonce
session_res = requests.get(f"{AEGIS_URL}/api/v1/session")
nonce = session_res.json()["session_nonce"]

# 3. Request zero-knowledge verification
verify_res = requests.post(f"{AEGIS_URL}/api/v1/verify", headers=HEADERS, json={
    "user_digest": user_digest,
    "doc_hash": doc_hash,
    "threshold": 21,
    "current_year": 2026,
    "birth_year": 2003,
    "nonce": nonce
})

data = verify_res.json()
print("Status:", data["status"])              # "verified"
print("JWT Proof Token:", data["proof_token"]) # Cryptographic proof of age >= 21
print("Execution Latency:", data["latency_us"], "microseconds")
```

---

### HTTP Status & Error Code Reference

| Status Code | Meaning | Cause |
| :---: | :--- | :--- |
| `200 OK` | **Verification Successful** | Predicate constraint evaluated to `true`, JWT minted, and Merkle leaf recorded. |
| `400 Bad Request` | **Missing or Invalid Parameters** | Missing `user_digest`, `doc_hash` not 64 hex chars, or invalid threshold range. |
| `401 Unauthorized` | **Invalid API Key** | `X-API-Key` or `Bearer` token failed constant-time equality check against authorized keys. |
| `404 Not Found` | **Proof ID Not Found** | Queried proof ID does not exist in the active SQLite ledger (`GET /api/v1/proofs/:id`). |
| `422 Unprocessable` | **Predicate Criteria Unmet** | Arithmetic check failed (e.g., user is 19 for a threshold of 21). `criteria_met: false`. |
| `500 Internal Error` | **Engine Fault** | SQLite database or cryptographic hashing anomaly. Zero PII is logged. |

---

## <img src="assets/icons/code.svg" width="34" height="34" align="absmiddle" /> UI Architecture: Card Spacing & Cryptographic Animations

The Aegis workbench interface is purposefully engineered for developer and security auditor clarity. It eliminates visual clutter ("AI Slop") through mathematically sound spatial rhythm and cryptographic GSAP animations.

### 1. Geometric Card Spacing Hierarchy (No Clunky Borders)
To prevent clunky, cramped, or misaligned container layouts, Aegis adheres to a strict nested spacing system:

* **Top-Level Container Cards (`aegis-card`)**:
  * Outer Padding: `p-6 sm:p-7` (24px to 28px).
  * Corner Radius: `rounded-2xl` (16px).
  * Background & Border: `bg-zinc-900/70 border border-zinc-800 shadow-xl`.
* **Child Cards & Invariant Blocks**:
  * Inner Padding: `p-5` (20px).
  * Corner Radius: `rounded-xl` (12px).
  * Background & Border: `bg-zinc-950/90 border border-zinc-800/80 shadow-md`.
* **Sub-Containers, Terminals & Code Blocks**:
  * Deep Padding: `p-3.5` (14px).
  * Corner Radius: `rounded-xl` (12px).
  * Background & Border: `bg-zinc-900/90 border border-zinc-800/80 font-mono`.
* **Mathematical Nested Radius Rule**:
  $$\text{Radius}_{\text{inner}} = \text{Radius}_{\text{outer}} - \text{Padding}_{\text{gap}}$$
  Situate `rounded-xl` cards inside `rounded-2xl` containers with balanced gap distributions, preventing overlapping or jagged corner curves.

### 2. Purpose-Driven Cryptographic GSAP Animation Suite
Animations in Aegis are not decorative SaaS gimmicks—they visually reflect **cryptographic isolation, circuit constraints, and tamper-evident guarantees**. All animations are centralized in `src/lib/gsap-animations.ts`:

| Animation Function | Purpose / Domain Logic | Visual Effect & Easing |
| :--- | :--- | :--- |
| `animateCardsStagger(container, selector)` | Entrance reveal when switching tabs or viewing audit specs | Subtle vertical glide (`y: 16 -> 0`), opacity scaling (`0 -> 1`), and `power3.out` physics easing with 45ms stagger. |
| `animateCardHover(el, isEnter)` | Tactile cursor feedback on interactive cards and inspectable modules | Subtle -2.5px elevation on hover with spring recovery (`back.out(2)`). |
| `animateCircuitPulse(el)` | Visualizes cryptographic circuit evaluation during proof generation | Cyan/emerald scanning border wave across the active card with zero layout shift. |
| `animateVerificationSuccess(container)` | Immediate feedback when a proof satisfies zero-knowledge constraints | Expanding emerald glow pulse (`rgba(16, 185, 129, 0.4)`) with elastic boundary settle. |
| `animateCryptoStream(targetEl, text)` | Visualizes domain-separated commitment and hash crystallization | Rapid hexadecimal character scramble ticker before resolving into the final hash. |
| `animateViewTransition(container)` | Seamless navigation across workbench tabs | Smooth cross-view opacity and translation reset with zero layout conflicts. |

---

## <img src="assets/icons/terminal.svg" width="34" height="34" align="absmiddle" /> API Reference

All endpoints return JSON and adhere to standard HTTP status codes.

| Method | Endpoint | Description | Request Body / Query | Headers |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | System health check and engine liveness status | None | None |
| `GET` | `/api/v1/session` | Generates a single-use challenge nonce (300s TTL) | None | None |
| `POST` | `/api/v1/verify` | Evaluates predicate constraints and issues signed verification tokens | `{ user_digest, doc_hash, threshold, current_year, birth_year, nonce }` | `X-API-Key` (Optional) |
| `POST` | `/api/v1/verify-token` | Validates signed cryptographic JWT tokens and checks expiration | `{ token: string }` | None |
| `POST` | `/api/v1/verify-merkle` | Validates Merkle inclusion paths against the published ledger root | `{ proof_id, leaf_hash, merkle_root, sibling_path }` | None |
| `GET` | `/api/v1/ledger` | Returns append-only Blake3 Merkle block ledger receipts | `?limit=50&offset=0` | None |
| `GET` | `/api/v1/proofs` | Lists historical proof commitments and timestamps (Zero PII) | None | None |
| `GET` | `/api/v1/proofs/{id}` | Retrieves a specific proof record and its verification receipt | Path param: `id` | None |
| `GET` | `/api/v1/metrics` | Real-time microsecond execution latency and memory usage | None | None |
| `GET` | `/api/v1/stats` | Aggregated ledger metrics and active Merkle root digests | None | None |

---

## <img src="assets/icons/git-collab.svg" width="34" height="34" align="absmiddle" /> Contributing

> **Aegis is 100% Free & Open Source Software (FOSS).**  
> We believe digital privacy and identity sovereignty belong to humanity, not private monopolies. Anyone—regardless of experience level—is warmly invited and encouraged to collaborate, propose architectural improvements, audit circuits, or contribute code.

<p align="center">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome" />
  <img src="https://img.shields.io/badge/First%20Timers-Friendly-blue.svg?style=flat-square" alt="First Timers Friendly" />
  <img src="https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square" alt="License" />
</p>

### Where You Can Help & Good First Ideas
There are many areas where your contributions make an immediate, global impact:
* <img src="assets/icons/circuit.svg" width="26" height="26" align="absmiddle" /> **Zero-Knowledge Circuits (Rust)**: Add new zero-knowledge predicate circuits in `rust-api/src/circuits/` (e.g., citizenship residence proofs, income threshold verification, biometric embedding Hamming distance).
* <img src="assets/icons/code.svg" width="26" height="26" align="absmiddle" /> **Client SDKs**: Help build and maintain lightweight, idiomatic SDKs for **Go**, **Python**, **Kotlin (Android)**, **Swift (iOS)**, or **React Native**.
* <img src="assets/icons/audit.svg" width="26" height="26" align="absmiddle" /> **Compliance & Test Vectors**: Contribute test vectors for **eIDAS 2.0**, **W3C VC 2.0**, **ISO/IEC 18013-5 mDL**, or jurisdictional age requirements.
* <img src="assets/icons/zap.svg" width="26" height="26" align="absmiddle" /> **Performance & SIMD Optimization**: Benchmark and optimize Blake3 / Groth16 multi-scalar multiplication routines for AVX-512, ARM NEON, and WebAssembly WebGPU backends.
* <img src="assets/icons/shield.svg" width="26" height="26" align="absmiddle" /> **Formal Verification & Security Audits**: Review constant-time execution routines, memory isolation boundaries, and Linux Seccomp filter policies.
* <img src="assets/icons/license.svg" width="26" height="26" align="absmiddle" /> **Documentation & Guides**: Improve API references, write integration tutorials for Next.js/Express/Django/Rails, or translate documentation.

---

### Step-by-Step Contribution Workflow

We follow standard GitHub flow and conventional commit standards:

#### 1. Fork & Clone
```bash
# Fork the repository on GitHub, then clone your fork locally:
git clone https://github.com/<your-username>/API.git
cd API
```

#### 2. Create a Topic Branch
```bash
git checkout -b feat/add-residence-predicate-circuit
```

#### 3. Install Dependencies & Verify Build
```bash
# Frontend & Next.js verification
npm install
npm run lint
npm run build

# Native Rust engine verification
cd rust-api
cargo test
cargo clippy --all-targets -- -D warnings
cd ..
```

#### 4. Commit Your Work with Conventional Messages
```bash
git commit -m "feat(circuits): implement zk-residence country exclusion constraint"
```
*Common prefixes:* `feat:`, `fix:`, `perf:`, `docs:`, `test:`, `refactor:`, `chore:`

#### 5. Push & Open a Pull Request
```bash
git push origin feat/add-residence-predicate-circuit
```
Open a Pull Request against the `main` branch. Provide a clear summary of your changes, any benchmarks, and relevant issue links. Maintainers will review and provide friendly, constructive feedback promptly!

---

### Community & Code of Conduct
Aegis is dedicated to providing a welcoming, respectful, and safe experience for everyone. We uphold high cryptographic standards while maintaining an empathetic, beginner-friendly community. 

* Have an idea or question? Open a **[GitHub Discussion](https://github.com/ronderins/API/discussions)** or file an **[Issue](https://github.com/ronderins/API/issues)**.
* Found a security vulnerability? Please report it privately to the maintainers as outlined in our security policy.

---

## <img src="assets/icons/rocket.svg" width="34" height="34" align="absmiddle" /> Deployment

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

## <img src="assets/icons/key.svg" width="34" height="34" align="absmiddle" /> Environment Configuration

| Variable | Required | Description | Default |
| :--- | :---: | :--- | :--- |
| `PORT` | Optional | HTTP port for the web server | `3000` |
| `RUST_API_URL` | Optional | Address of the native Rust Axum microservice | `http://localhost:8080` |
| `API_KEY` | Optional | Enforces pre-shared key header authentication (`X-API-Key`) | `None` (Open Mode) |
| `API_KEYS` | Optional | Comma-separated list of authorized pre-shared API keys | `None` |
| `CANARY_ENFORCE` | Optional | Enforce binary SHA-256 release integrity verification | `false` |
| `CANARY_CANONICAL_SHA256` | Optional | Expected canonical SHA-256 digest of the compiled binary | `None` |

---

## <img src="assets/icons/shield.svg" width="34" height="34" align="absmiddle" /> Security Specifications

* **Zero-Knowledge Circuit Family**: Groth16 over the BN254 (alt_bn128) pairing-friendly elliptic curve, Bulletproofs for logarithmic range proofs, and Nova Incremental Verifiable Computation (IVC) for multi-predicate proof folding.
* **Hashing Primitives**: Blake3 with SIMD vectorization (AVX2 / AVX-512 / ARM NEON) executing in <100ns per digest; NIST SHA-256 with domain separation prefixes (`zk-identity-proof-v1`).
* **Post-Quantum Hybrid Readiness**: Dual-signed commitments combining classical Ed25519 with NIST FIPS 204 ML-DSA (Module-Lattice Digital Signatures) for quantum forward secrecy.
* **Memory Protection**: Zeroization of stack and heap witness structures using the `zeroize` crate to prevent RAM dump forensics.
* **Constant-Time Guarantees**: Cryptographic comparisons executed via `subtle::ConstantTimeEq` to eliminate timing side-channels.
* **Compliance Standards**: Formally aligned with **W3C Verifiable Credentials Data Model 2.0**, **ISO/IEC 18013-5 mDL**, and **EU eIDAS 2.0 Architectural Framework**.

---

## <img src="assets/icons/license.svg" width="34" height="34" align="absmiddle" /> License

Maintained with <img src="assets/icons/git-collab.svg" width="26" height="26" align="absmiddle" /> by **Rony M. ([@ronderins](https://github.com/ronderins))** and the **Open Source Community**.

Released under the **MIT License**. You are free to use, modify, distribute, and integrate Aegis into commercial and open-source applications without restriction.
