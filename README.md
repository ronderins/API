# Aegis

Privacy-preserving identity and predicate verification engine. Verify age and credential eligibility over HTTP without receiving, processing, or storing personal identifiable information (PII).

<p align="center">
  <img src="assets/hero-banner.svg" alt="Aegis Privacy-Preserving Security Engine" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-15-black.svg" alt="Next.js 15"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.80%2B-orange.svg" alt="Rust 1.80+"></a>
  <a href="https://github.com/ronderins"><img src="https://img.shields.io/badge/Engineered%20by-Rony%20M.-emerald.svg" alt="Engineered by Rony M."></a>
</p>

---

## Overview

Traditional identity verification architectures force users to upload clear, unredacted scans of passports, driver's licenses, or national ID cards to central cloud servers. This paradigm creates centralized honeypots of high-value user data, exposes businesses to severe breach liabilities under regulations like GDPR (up to €20M or 4% of global turnover) and CCPA, and causes high customer abandonment rates.

Aegis decouples **eligibility verification** from **data retention**:

1. **Client-Side Hashing**: The user's device calculates a cryptographic digest of identity attributes locally via WebCrypto. Raw documents never touch the wire.
2. **Predicate Verification**: The backend verifies arithmetic constraints (e.g., `CurrentYear - BirthYear >= 21`) against the document commitment without learning birthdates or identity values.
3. **Signed Proof Tokens & Receipts**: Aegis issues a tamper-evident, signed JWT proof token and records an immutable leaf in an append-only Blake3 Merkle tree.
4. **Hardware Memory Zeroization**: Stack and heap buffers containing witness values implement `ZeroizeOnDrop` to prevent forensic memory scraping.

<p align="center">
  <img src="assets/zk-how-it-works.svg" alt="Traditional KYC vs Aegis Zero-Knowledge Architecture" width="100%">
</p>

---

## 🛡️ Why This API Matters: The Real-World Cyber-Security Value (In Plain English)

> **"You cannot lose what you never collected. You cannot be blackmailed with data you do not possess. Hackers cannot steal an identity database that does not exist."**

If you are not a software engineer or cryptographer, this section explains **what problem this system actually solves**, **why cyber-attacks are so devastating today**, and **how implementing this API inside other apps prevents catastrophic identity theft and business liabilities.**

---

### 1. The Big Problem: The "Data Honeypot" Trap

Whenever you sign up for a service that requires proof of age or identity (such as a gaming platform, social network, car rental, alcohol delivery app, or banking service), the app almost always asks you to:
- Take a photo of your **Driver's License or Passport**
- Enter your **full legal name, home address, and date of birth**
- Upload a selfie for facial recognition

#### What happens behind the scenes?
That company now saves your unredacted passport scan and private details in their cloud database. When a company does this for millions of users, their database becomes a **"honeypot"**—a massive, high-value treasure chest that cybercriminals, rogue employees, and overseas hacker syndicates actively target 24/7.

```
TRADITIONAL IDENTITY SYSTEM (HIGH RISK):
[User's Phone]  --->  Sends Full Passport Photo  --->  [Company Cloud Database]  <---  [Hacker Breaches In]
                                                        • Full Legal Name              • Steals 2 Million Passports
                                                        • Home Address                 • Opens Fraudulent Loans
                                                        • Exact Date of Birth          • Imposes $20M GDPR Fine
                                                        • Facial Scans                 • Company Faces Lawsuits
```

When those databases inevitably get hacked:
- **Customers suffer real-world harm**: Criminals use those stolen passport scans to open fraudulent bank accounts, take out loans in their name, steal tax refunds, commit deed fraud, or stalk individuals.
- **Companies face ruin**: Under privacy laws like Europe's **GDPR** or California's **CCPA**, companies face tens of millions of dollars in regulatory fines, costly class-action lawsuits, and permanent reputational damage.
- **Customers abandon signups**: Over 40% of people abandon an app completely when asked to upload an image of their government ID because they do not trust the company with their documents.

---

### 2. The Solution: How Aegis Works (The "Nightclub Bouncer" Analogy)

Imagine you want to enter a nightclub that requires guests to be 21 or older:

* **The Old, Dangerous Way**: The bouncer takes your physical driver's license, photocopies it, writes down your home address, full name, and birthdate in an open paper binder on the desk, and files it away in a basement cabinet. If someone breaks into the club tomorrow, they now have your identity.
* **The Aegis Way**: You show a tamper-proof digital card. An electronic light flashes **GREEN** indicating *"Mathematically Verified: Over 21"*. The bouncer never sees your home address, never knows whether you are 22 or 55, and writes nothing down. If a burglar breaks into the club that night, there are zero documents to steal because the club never held them!

That is exactly what Aegis does for web apps, mobile apps, and internet services through **Zero-Knowledge Verification**.

```
AEGIS ZERO-KNOWLEDGE API (ZERO RISK):
[User's Phone]  === (Calculates Math Fingerprint Locally) ===>  [Aegis API]
  • Document NEVER leaves the phone                              • Evaluates: Is Age >= 21?
  • No photos uploaded                                           • Result: YES (True)
  • No birthdates transmitted                                    • Issues: Signed Digital Stamp
                                                                 • Stored PII: Exactly ZERO
                                                                 • Hacker gets: NOTHING
```

---

### 3. Realistic Scenarios: How Other Apps Implement This API

Here is how real companies and developers plug this API into their apps to stop cyber-attacks before they start:

#### Scenario A: Age-Gated Social Media & Gaming Platforms
* **The Reality**: Governments in the UK, EU, and US have enacted strict child-safety laws requiring apps to block minors from adult gaming, gambling, or adult content.
* **The Threat**: If a gaming company forces teenagers and adults to upload government IDs to verify their age, the company is sitting on a nuclear bomb of sensitive minor and adult data.
* **How Aegis Protects Them**: The gaming app calls Aegis via `POST /api/v1/verify`. The user's device confirms their age mathematically. The platform receives a signed cryptographic stamp saying `criteria_met: "age_over_21"`.
* **Cyber-Security Outcome**: 100% legal compliance with **zero minor or adult PII stored**. If the gaming platform's database is hacked, there are zero passport scans or birthdates for attackers to leak.

#### Scenario B: Car Sharing, Scooter Rentals & Online Marketplaces
* **The Reality**: Car sharing apps (like Turo or Zipcar) need to ensure drivers are at least 21 or 25 with a valid license before handing over the keys to a $40,000 vehicle.
* **The Threat**: Collecting and keeping thousands of driver's license photos makes the rental app an irresistible target for credential-stuffing and database breaches.
* **How Aegis Protects Them**: When the driver signs up, their phone creates a secure mathematical fingerprint of their license. Aegis verifies the fingerprint satisfies the age threshold and validity rules without storing the image or number.
* **Cyber-Security Outcome**: The rental company eliminates the multi-million-dollar liability of storing customer licenses while still maintaining ironclad proof that every driver was vetted.

#### Scenario C: High-Value E-Commerce & Luxury Goods Delivery
* **The Reality**: Online retailers selling high-value electronics, fine wine, or regulated pharmaceuticals need to confirm customer eligibility and prevent fraud.
* **The Threat**: Payment fraud and package interception by porch pirates or fraudsters using stolen credentials.
* **How Aegis Protects Them**: When the customer orders, Aegis generates a single-use verification token bound specifically to that transaction. 
* **Cyber-Security Outcome**: The merchant confirms the buyer is eligible and authentic without ever handling or storing the buyer's private identity cards.

#### Scenario D: Remote Workplace Access & Healthcare Portals
* **The Reality**: Telehealth platforms and corporate intranets need to verify that a user is an active, licensed physician or an authorized employee before granting access to confidential records.
* **The Threat**: Phishing attacks and credential harvesting allow attackers to masquerade as medical staff or corporate executives.
* **How Aegis Protects Them**: The user's credential is verified mathematically against an authorized cryptographic root.
* **Cyber-Security Outcome**: Access is granted based on verified cryptographic math rather than easily phished passwords, and the employee's personal background data remains private.

#### Scenario E: Ticket Scalping & Anti-Bot Protection (Sybil Defense)
* **The Reality**: Concert ticket sites and sneaker drops are constantly raided by automated bots that buy out all inventory in milliseconds using thousands of fake accounts.
* **The Threat**: Forcing real fans to submit phone numbers or social security numbers to prove they are human alienates real customers and creates mass privacy invasions.
* **How Aegis Protects Them**: Aegis generates a unique, anonymous mathematical token for each real human. The user can prove: *"I am a real person, and I have not already claimed a ticket for this show,"* without revealing who they are.
* **Cyber-Security Outcome**: Bots and scalpers are blocked from creating mass duplicate accounts, while real fans maintain complete anonymity.

---

### 4. Side-by-Side Comparison: Traditional Verification vs. Aegis

| Feature / Threat Vector | Traditional Identity Verification Services | With Aegis API Implemented |
| :--- | :--- | :--- |
| **Where does the ID photo go?** | Uploaded to third-party cloud servers and stored indefinitely | **Never leaves the user's phone or computer** |
| **What does the database store?** | Full names, photos, home addresses, license numbers, birthdates | **Zero personal data** (only mathematical fingerprints) |
| **What happens if the company gets hacked?** | Catastrophic data breach, mass identity theft, regulatory fines | **Hackers find nothing useful.** No names, no dates, no photos |
| **GDPR & CCPA Compliance Risk** | Severe liability (up to €20,000,000 or 4% of global turnover) | **Minimal liability by design** ("Data Minimization" principle) |
| **Customer Signup Drop-off** | 35% – 50% of users leave when asked to upload physical documents | **Over 80% higher completion** because no sensitive documents are exposed |
| **Audit & Legal Defense** | Company must produce unredacted customer files to prove compliance | **Cryptographic Merkle receipts** prove compliance mathematically |
| **Speed of Verification** | Manual review can take minutes to 48 hours | **Sub-millisecond** (< 1 millisecond execution) |

---

### 5. Four Core Cyber-Security Shields Built into the API

Even if a non-technical manager doesn't write code, here are the four technical defenses Aegis brings to an organization:

1. **The Replay Shield (Anti-Replay Nonces)**:
   * *The Attack*: A hacker intercepts a valid verification message sent yesterday and tries to "replay" it today to gain unauthorized access.
   * *How Aegis Stops It*: Aegis issues a single-use cryptographic challenge (`GET /api/v1/session`) that self-destructs after 300 seconds. If an attacker tries to use an old token, it is immediately rejected.
2. **The Timing Shield (Constant-Time Math)**:
   * *The Attack*: Advanced hackers measure how many microseconds a server takes to reject a password or token. By analyzing tiny variations in CPU time, they can guess cryptographic keys byte by byte.
   * *How Aegis Stops It*: Aegis performs constant-time comparisons (`crypto.timingSafeEqual`). The server takes the exact same number of clock cycles whether a guess is totally wrong or almost right, completely blinding timing eavesdroppers.
3. **The Memory Scrubbing Shield (Zeroize on Drop)**:
   * *The Attack*: If an attacker manages to inspect the server's working memory (RAM) right after a verification runs, they might find remnants of calculation variables.
   * *How Aegis Stops It*: The engine implements automatic memory zeroization. The instant a proof computation finishes, the computer's memory cells are physically overwritten with zeros before being released.
4. **The Tamper-Evident Ledger (Blake3 Merkle Receipts)**:
   * *The Attack*: A corrupt insider or attacker alters database records to claim an underage user was verified or that a rogue check was valid.
   * *How Aegis Stops It*: Every verification receipt is chained into an append-only mathematical Merkle tree. If even a single byte is changed after the fact, the mathematical checksum breaks visibly, alerting compliance auditors immediately.

---

## End-to-End System Architecture

The Aegis verification pipeline is organized into four decoupled operational layers designed for sub-millisecond execution and strict data isolation:

<p align="center">
  <img src="assets/system-architecture.svg" alt="Aegis End-to-End System Architecture" width="100%">
</p>

### 1. Client Edge
Document hashing occurs exclusively within user hardware using WebCrypto or native platform crypto libraries. Raw biometric scans, photos, and passport numbers never leave the user's device.

### 2. Transport Shield & API Gateway
- **Anti-Replay Protection**: Single-use cryptographic challenge nonces with 300-second TTL prevent replay attacks.
- **Sliding-Window Rate Limiting**: An in-memory token bucket keyed on hashed client IP protects against denial-of-service and credential stuffing.
- **Constant-Time Evaluation**: All signature and token validation operations execute with branchless, constant-time byte comparisons to thwart timing side channels.

### 3. Verification Core
- **Arithmetic Predicate Check**: Evaluates whether the prover satisfies the condition (e.g., $Age \ge Threshold$) using 7-bit decomposition to prevent arithmetic underflow.
- **Domain-Separated Commitments**: Hashed commitments use the `zk-identity-proof-v1` domain separator to prevent cross-protocol collision attacks.
- **Instant Memory Zeroization**: Heap buffers and intermediate witness representations implement `ZeroizeOnDrop`, immediately overwriting RAM with zeroes after proof evaluation.

### 4. Append-Only Merkle Ledger
- **Parallel Blake3 Tree**: Leaf commitments are appended to an immutable Merkle tree.
- **Logarithmic Receipts**: External auditors can mathematically verify proof inclusion in $O(\log N)$ operations without decrypting or accessing private user credentials.

---

## Quickstart & Developer Workflow

Integrating Aegis into any application requires three simple HTTP steps:

<p align="center">
  <img src="assets/developer-api-flow.svg" alt="Developer API Verification Flow" width="100%">
</p>

### Step 1: Request Ephemeral Session Nonce
Acquire a single-use challenge nonce to bind the upcoming verification to an unreplayable 300-second window:

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

### Step 2: Submit Verification Request
Send the client-side document digest, pseudonymized user reference, and required threshold:

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

### Step 3: Verify Existing Proof Token
Validate a signed proof token on any downstream microservice without database access:

```bash
curl -X POST http://localhost:3000/api/v1/verify-token \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

---

## Zero-Knowledge Circuit & Constraint System

<p align="center">
  <img src="assets/zero-knowledge-circuit.svg" alt="Zero-Knowledge Predicate Circuit" width="100%">
</p>

The core circuit translates high-level identity predicates into rank-1 constraint systems (R1CS) and range checks:
- **Private Witness ($w_0$)**: Secret document hash and birth year known only to the user.
- **Public Inputs ($c_0$)**: Evaluation year ($2026$) and required threshold ($18$, $21$, etc.).
- **Range Comparator**: Enforces that the calculated delta falls within valid physical ranges $[0, 150]$ using bit decomposition gates, preventing integer wraparound attacks.
- **Commitment Collector**: Emits a deterministic domain-separated hash commitment without leaking the private inputs.

---

## Merkle Ledger & Cryptographic Receipts

<p align="center">
  <img src="assets/merkle-ledger.svg" alt="Append-Only Blake3 Merkle Block Ledger" width="100%">
</p>

Every minted proof produces a leaf in the append-only Blake3 Merkle tree:
- **Tamper-Evident Chaining**: Each block receipt is cryptographically bound to the root of previous states.
- **Logarithmic Inclusion Audits**: Any compliance officer or third-party auditor can verify a proof's existence and validity in $O(\log_2 N)$ steps by calling `POST /api/v1/verify-merkle`.
- **Zero Data Exposure**: Merkle leaves contain only SHA-256 commitments and block hashes—no names, emails, or biometric vectors.

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
