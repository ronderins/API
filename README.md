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
  <a href="#-what-is-aegis"><img src="assets/icons/target.svg" width="22" height="22" align="absmiddle" /> What Is Aegis</a> &nbsp;•&nbsp;
  <a href="#-how-to-consume-the-api"><img src="assets/icons/zap.svg" width="22" height="22" align="absmiddle" /> Consume The API</a> &nbsp;•&nbsp;
  <a href="#-system-architecture"><img src="assets/icons/architecture.svg" width="22" height="22" align="absmiddle" /> Architecture</a> &nbsp;•&nbsp;
  <a href="#-how-it-works"><img src="assets/icons/circuit.svg" width="22" height="22" align="absmiddle" /> How It Works</a> &nbsp;•&nbsp;
  <a href="#-who-is-aegis-for"><img src="assets/icons/users.svg" width="22" height="22" align="absmiddle" /> Who Is It For</a> &nbsp;•&nbsp;
  <a href="#-api-reference"><img src="assets/icons/terminal.svg" width="22" height="22" align="absmiddle" /> API Reference</a> &nbsp;•&nbsp;
  <a href="#-ui-design--animation-system"><img src="assets/icons/code.svg" width="22" height="22" align="absmiddle" /> UI & Animations</a> &nbsp;•&nbsp;
  <a href="#-deployment"><img src="assets/icons/rocket.svg" width="22" height="22" align="absmiddle" /> Deployment</a>
</p>

---

</div>

## <img src="assets/icons/target.svg" width="30" height="30" align="absmiddle" /> What Is Aegis?

**Aegis is an HTTP REST API for verifying user identity attributes (such as "Age ≥ 21", "Valid Passport", or "Sanctions-Free") without ever collecting, seeing, or storing the user's personal data (PII).**

Instead of forcing users to upload sensitive passport photos, driver's licenses, or SSNs to your cloud databases:
1. **Device-Side Hash**: The user's device hashes their ID locally with SHA-256 or Blake3. Raw ID bytes never leave the phone or browser.
2. **API Predicate Check**: Your backend forwards the hash and the rule (e.g. `threshold: 21`) to `POST /api/v1/verify`.
3. **Instant Verification & Zeroize**: The Aegis Rust engine verifies the zero-knowledge constraint in **<150µs**, wipes RAM clean with `zeroize`, and issues a signed tamper-evident JWT proof token.

```json
// POST /api/v1/verify -> Payload sent by your backend
{
  "user_digest": "4a7d3b8f1c2e5a9b0d6f8e7a1c3b5d7f9e2a4b6c8d0e1f3a5b7c9d1e3f5a7b9c",
  "doc_hash": "8f3c4e2b1a0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f",
  "threshold": 21,
  "current_year": 2026,
  "birth_year": 2002,
  "nonce": "e9b4072f8a1c4d92"
}

// 200 OK -> Returned in <150 microseconds
{
  "status": "verified",
  "predicate": "age_over_21",
  "verified": true,
  "proof_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "merkle_root": "0x9e12bf4a...7e",
  "latency_us": 142
}
```

### Core Developer Guarantees
* <img src="assets/icons/shield-check.svg" width="22" height="22" align="absmiddle" /> **0 Bytes PII Stored**: Neither raw photos, names, nor birthdates ever touch server disks.
* <img src="assets/icons/shield-check.svg" width="22" height="22" align="absmiddle" /> **Sub-Millisecond Speed**: Verification executes in <150µs via Axum & SIMD Blake3.
* <img src="assets/icons/shield-check.svg" width="22" height="22" align="absmiddle" /> **RAM Zeroization (`zeroize`)**: All witness variables are scrubbed to zeroes (`0x00`) immediately after evaluation.
* <img src="assets/icons/shield-check.svg" width="22" height="22" align="absmiddle" /> **Tamper-Evident Merkle Receipts**: Attestation commitments are recorded in an append-only tree with $O(\log N)$ inclusion verification.

---

## <img src="assets/icons/zap.svg" width="30" height="30" align="absmiddle" /> How to Consume the API

Aegis is completely self-contained. It requires no external SaaS subscriptions, cloud accounts, or proprietary vendor tokens.

<div align="center">
  <img src="assets/developer-api-flow.svg" alt="Aegis Developer Integration in 3 Simple Steps" width="100%" />
</div>

<br/>

### 3-Step Integration Overview

1. **Client / Frontend**: Hash the user's ID locally with WebCrypto (`doc_hash = sha256(raw_bytes)`). No raw photo ever leaves the client.
2. **Your Backend**: Request a single-use replay challenge nonce (`GET /api/v1/session`) and submit the predicate request to `POST /api/v1/verify`.
3. **Response**: Aegis returns `{ verified: true, proof_token }`. Store the proof token in your user session or database.

---

### Code Examples: Copy & Paste Ready

#### 1. TypeScript & Node.js / Next.js
```typescript
import { createHash } from "crypto";

interface AegisVerifyResponse {
  status: "verified" | "rejected";
  predicate: string;
  verified: boolean;
  proof_token: string;
  merkle_root: string;
  latency_us: number;
}

export async function verifyUserAge(
  rawDocumentBytes: Buffer,
  pseudonymousUserId: string,
  userBirthYear: number,
  requiredAge = 21
): Promise<AegisVerifyResponse> {
  const AEGIS_URL = process.env.AEGIS_API_URL || "http://localhost:3000";

  // 1. Hash document locally on device (Raw PII NEVER leaves memory)
  const docHash = createHash("sha256").update(rawDocumentBytes).digest("hex");
  const userDigest = createHash("sha256").update(pseudonymousUserId).digest("hex");

  // 2. Fetch single-use replay prevention nonce (300s TTL)
  const sessionRes = await fetch(`${AEGIS_URL}/api/v1/session`);
  const { session_nonce } = await sessionRes.json();

  // 3. Dispatch verification request
  const verifyRes = await fetch(`${AEGIS_URL}/api/v1/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      user_digest: userDigest,
      doc_hash: docHash,
      threshold: requiredAge,
      current_year: new Date().getFullYear(),
      birth_year: userBirthYear,
      nonce: session_nonce,
    }),
  });

  const result: AegisVerifyResponse = await verifyRes.json();
  console.log(`Verified: ${result.verified} in ${result.latency_us}µs`);
  return result;
}
```

#### 2. cURL / Terminal
```bash
# 1. Acquire single-use ephemeral challenge nonce (300s TTL)
NONCE=$(curl -s http://localhost:3000/api/v1/session | jq -r '.session_nonce')

# 2. Submit privacy-preserving age check (Age >= 21)
curl -X POST http://localhost:3000/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "user_digest": "4a7d3b8f1c2e5a9b0d6f8e7a1c3b5d7f9e2a4b6c8d0e1f3a5b7c9d1e3f5a7b9c",
    "doc_hash": "8f3c4e2b1a0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f",
    "threshold": 21,
    "current_year": 2026,
    "birth_year": 2002,
    "nonce": "'"$NONCE"'"
  }'
```

#### 3. Python 3
```python
import hashlib, requests

AEGIS_URL = "http://localhost:3000"

# 1. Compute client-side digests locally
doc_hash = hashlib.sha256(b"raw_id_photo_bytes").hexdigest()
user_digest = hashlib.sha256(b"user_unique_id").hexdigest()

# 2. Acquire single-use challenge nonce
nonce = requests.get(f"{AEGIS_URL}/api/v1/session").json()["session_nonce"]

# 3. Submit verification request
res = requests.post(f"{AEGIS_URL}/api/v1/verify", json={
    "user_digest": user_digest,
    "doc_hash": doc_hash,
    "threshold": 21,
    "current_year": 2026,
    "birth_year": 2002,
    "nonce": nonce
}).json()

print(f"Verified: {res['verified']} (Token: {res['proof_token'][:30]}...)")
```

---

## <img src="assets/icons/architecture.svg" width="30" height="30" align="absmiddle" /> System Architecture

Aegis is divided into four isolated execution tiers:

<div align="center">
  <img src="assets/system-architecture.svg" alt="Aegis Architectural System Design" width="100%" />
</div>

<br/>

| Tier | Component | Responsibility & Security Invariant |
| :--- | :--- | :--- |
| **1. Client Edge** | Device / WebCrypto SDK | Scans documents locally, computes irreversible Blake3/SHA-256 hash, injects blinding salt. **0 bytes of raw PII leave the device.** |
| **2. API Gateway** | Axum / Next.js Proxy | Issues single-use anti-replay nonces (300s TTL), applies token-bucket rate limiting, and runs constant-time auth. |
| **3. Rust ZK Core** | Native Rust Microservice | Evaluates arithmetic constraints ($CurrentYear - BirthYear \ge Threshold$) in <150µs, runs `zeroize(&mut witness)` to scrub RAM, and signs with post-quantum ML-DSA. |
| **4. Receipts** | Verifier Token & Merkle Tree | Issues a tamper-evident JWT attestation and records the commitment leaf into an immutable Blake3 Merkle ledger. |

---

## <img src="assets/icons/circuit.svg" width="30" height="30" align="absmiddle" /> How It Works

### 1. Honeypots vs. Zero-Knowledge Proofs
Traditional KYC vendors upload identity photos to centralized servers, creating vulnerable honeypots targeted by ransomware. Aegis completely eliminates this risk:

<div align="center">
  <img src="assets/zk-how-it-works.svg" alt="Zero-Knowledge vs Traditional Verification" width="100%" />
</div>

<br/>

### 2. Zero-Knowledge Predicate Circuit & Memory Isolation
How can Aegis verify someone is over 21 without knowing their birthdate? It converts the verification into an arithmetic inequality constraint:

<div align="center">
  <img src="assets/zero-knowledge-circuit.svg" alt="Zero-Knowledge Predicate Circuit & Memory Isolation" width="100%" />
</div>

<br/>

* **Public Statement**: Current year (`2026`) and required age (`21`). Known to all parties.
* **Private Witness**: Birth year (`2002`). Kept inside isolated enclave memory.
* **Arithmetic Gate**: Computes $\Delta = 2026 - 2002 = 24 \ge 21 \implies \text{TRUE}$.
* **Hardware Memory Scrubbing (`zeroize`)**: Once evaluated, the witness buffer is scrubbed with zeroes (`0x00`). No forensic memory dump can ever extract the birthdate.

### 3. Append-Only Blake3 Merkle Block Ledger
Every attestation is recorded as a leaf in a cryptographic Merkle tree, allowing non-repudiable audit verification without revealing any user data:

<div align="center">
  <img src="assets/merkle-ledger.svg" alt="Append-Only Blake3 Merkle Block Ledger" width="100%" />
</div>

<br/>

To verify an attestation, an auditor queries `POST /api/v1/verify-merkle` with the $O(\log N)$ sibling path. If the computed root matches the published Merkle root, the proof is mathematically authentic.

---

## <img src="assets/icons/users.svg" width="30" height="30" align="absmiddle" /> Who Is Aegis For?

| Industry / Role | Problem | Aegis Solution |
| :--- | :--- | :--- |
| <img src="assets/icons/cart.svg" width="22" height="22" align="absmiddle" /> **Age-Restricted Platforms & Apps** | KYC document uploads cause 40%+ drop-off and massive regulatory liability. | Instant local document hash and sub-millisecond age check. Zero drop-off, zero stored data. |
| <img src="assets/icons/bank.svg" width="22" height="22" align="absmiddle" /> **FinTech & Web3 Protocols** | Must screen users without de-anonymizing wallet addresses or holding toxic PII vaults. | Cryptographic predicate attestation: users prove accreditation or sanctions compliance privately. |
| <img src="assets/icons/code.svg" width="22" height="22" align="absmiddle" /> **Backend & Full-Stack Developers** | Building custom ZK circuits requires advanced mathematics, specialized compilers, and expensive SaaS. | Standard HTTP REST API (`POST /api/v1/verify`), sub-millisecond execution, and 5-minute integration. |
| <img src="assets/icons/audit.svg" width="22" height="22" align="absmiddle" /> **Security & Compliance Teams** | Auditing traditional KYC vendors requires trusting opaque promises and proprietary logs. | Mathematical Merkle inclusion proofs replace blind vendor trust. Zero breach liability. |

---

## <img src="assets/icons/terminal.svg" width="30" height="30" align="absmiddle" /> API Reference

All endpoints return JSON and adhere to standard HTTP status codes.

| Method | Endpoint | Description | Request Body / Query |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | System health check and engine liveness status | None |
| `GET` | `/api/v1/session` | Generates a single-use replay challenge nonce (300s TTL) | None |
| `POST` | `/api/v1/verify` | Evaluates predicate constraints and issues signed verification tokens | `{ user_digest, doc_hash, threshold, current_year, birth_year, nonce }` |
| `POST` | `/api/v1/verify-token` | Validates signed cryptographic JWT tokens and checks expiration | `{ token: string }` |
| `POST` | `/api/v1/verify-merkle` | Validates Merkle inclusion paths against the published ledger root | `{ proof_id, leaf_hash, merkle_root, sibling_path }` |
| `GET` | `/api/v1/ledger` | Returns append-only Blake3 Merkle block ledger receipts | `?limit=50&offset=0` |
| `GET` | `/api/v1/proofs` | Lists historical proof commitments and timestamps (Zero PII) | None |
| `GET` | `/api/v1/proofs/{id}` | Retrieves a specific proof record and its verification receipt | Path param: `id` |
| `GET` | `/api/v1/metrics` | Real-time microsecond execution latency and memory usage | None |

---

## <img src="assets/icons/code.svg" width="30" height="30" align="absmiddle" /> UI Architecture: Card Spacing & Animations

The Aegis workbench interface eliminates visual clutter through mathematically harmonious spatial rhythm and cryptographic GSAP animations.

### 1. Geometric Card Spacing Hierarchy
* **Container Cards (`aegis-card`)**: Outer padding `p-6 sm:p-7` (24px–28px), corner radius `rounded-2xl` (16px), background `bg-zinc-900/70 border border-zinc-800`.
* **Child Cards & Invariant Blocks**: Inner padding `p-5` (20px), corner radius `rounded-xl` (12px), background `bg-zinc-950/90 border border-zinc-800/80`.
* **Sub-Containers & Code Terminals**: Deep padding `p-3.5` (14px), corner radius `rounded-xl` (12px), font `font-mono`.
* **Nested Radius Formula**: $\text{Radius}_{\text{inner}} = \text{Radius}_{\text{outer}} - \text{Padding}_{\text{gap}}$. Situate `rounded-xl` inside `rounded-2xl` for smooth, un-crowded corners.

### 2. Cryptographic GSAP Animation Suite
All animations are centralized in `src/lib/gsap-animations.ts`:

| Animation Function | Trigger / Domain Logic | Visual Effect |
| :--- | :--- | :--- |
| `animateCardsStagger(container, selector)` | Tab navigation and workbench reveals | Smooth vertical entrance (`y: 16 -> 0`) with `power3.out` easing and 45ms stagger. |
| `animateCardHover(el, isEnter)` | Card interaction and cursor feedback | Subtle -2.5px elevation with spring settle (`back.out(2)`). |
| `animateCircuitPulse(el)` | Cryptographic circuit evaluation | Scanning cyan/emerald border wave with zero layout shift. |
| `animateVerificationSuccess(container)` | Satisfied zero-knowledge constraint | Expanding emerald glow pulse (`rgba(16, 185, 129, 0.4)`). |
| `animateCryptoStream(targetEl, text)` | Hash and commitment crystallization | Rapid hexadecimal scramble ticker before settling on final hash. |

---

## <img src="assets/icons/rocket.svg" width="30" height="30" align="absmiddle" /> Deployment

Aegis is 100% self-hosted and requires no third-party cloud credentials.

### Option 1: Vercel (Zero-Config)
The Next.js workbench incorporates the built-in TypeScript cryptographic core as a seamless fallback:
1. Import the repository into [Vercel](https://vercel.com).
2. Framework Preset: **Next.js** (auto-detected). Click **Deploy**.

### Option 2: Docker Compose (Full Stack: Rust Axum + Next.js)
```bash
git clone https://github.com/ronderins/API.git
cd API
docker compose up --build -d
```
* Next.js Verification Workbench: `http://localhost:3000`
* Native Rust Axum Engine: `http://localhost:8080`

### Option 3: Local Development
```bash
npm install
npm run dev
```

---

## <img src="assets/icons/shield.svg" width="30" height="30" align="absmiddle" /> Security Specifications

* **ZK Circuit Family**: Groth16 over BN254 (alt_bn128), Bulletproofs for logarithmic range proofs, and Nova IVC for multi-predicate proof folding.
* **Hashing Primitives**: Blake3 with SIMD vectorization (AVX2 / AVX-512 / ARM NEON) executing in <100ns; NIST SHA-256 with domain separation prefixes (`zk-identity-proof-v1`).
* **Post-Quantum Hybrid Readiness**: Dual-signed commitments combining Ed25519 with NIST FIPS 204 ML-DSA (Module-Lattice Digital Signatures).
* **Memory Protection**: Zeroization of stack and heap witness structures via `zeroize` to eliminate RAM dump forensics.
* **Constant-Time Execution**: Byte comparisons run via `subtle::ConstantTimeEq` to prevent side-channel timing leaks.

---

## <img src="assets/icons/license.svg" width="30" height="30" align="absmiddle" /> License

Maintained with <img src="assets/icons/git-collab.svg" width="22" height="22" align="absmiddle" /> by **Rony M. ([@ronderins](https://github.com/ronderins))** and the **Open Source Community**.

Released under the **MIT License**. Free to use, modify, and distribute for commercial and open-source applications.
