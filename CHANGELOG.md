# Changelog - Aegis (Privacy-Preserving Auth)

All notable changes to this project are documented in this file.

## [0.2.0] - 2026-08-15

### Complete Rust Zero-Knowledge & Security Architecture

1. **`zkp::bn254` (BN254 / alt_bn128 Pairings & Group Arithmetic)**:
   - Full $\mathbb{F}_p$ base field and $\mathbb{F}_{p^2}$ quadratic extension arithmetic with constant-time carry/borrow operations (`U256`, `Fp`, `Fp2`).
   - $\mathbb{G}_1$ and $\mathbb{G}_2$ affine point arithmetic, curve membership checks, and Groth16 bilinear pairing verification ($e(A, B) = e(\alpha, \beta) \cdot e(x, \gamma) \cdot e(C, \delta)$).

2. **`zkp::poseidon` (SNARK-Friendly Algebraic Sponge)**:
   - Poseidon hash implementation with Cauchy MDS matrix mixing, $x^5$ non-linear S-box permutations, and Blake3 PRNG-derived round constants optimized for BN254.

3. **`zkp::r1cs` (Rank-1 Constraint System Synthesizer)**:
   - Complete R1CS $(A \cdot z \circ B \cdot z = C \cdot z)$ constraint matrix representation, linear combination evaluators, boolean check gates, and zeroize-on-drop witness assignment tables.

4. **`zkp::pedersen` & `zkp::schnorr` (Commitments & NIZKPoK)**:
   - Perfectly hiding Pedersen vector commitments with blinding factor lifecycle management.
   - Non-interactive Schnorr zero-knowledge proofs of knowledge with Fiat-Shamir transformation and domain-separated challenges.

5. **`circuits::*` (Identity Verification Arithmetic Circuits)**:
   - `age_circuit`: R1CS circuit for age threshold predicates ($Age \ge Threshold$) with 7-bit decomposition to prevent underflow without revealing birth year.
   - `merkle_membership`: Zero-knowledge Merkle tree authentication path verification in Poseidon hash gates.
   - `sanctions_non_membership`: Cryptographic interval accumulator proving credential digests are not in OFAC/sanctions blacklists.
   - `bulletproofs_range`: Inner-product logarithmic range proof verification.
   - `groth16_bn254`: High-level Groth16 proof verifier.

6. **`security::*` (Hardening & Side-Channel Mitigation)**:
   - `constant_time`: Branchless constant-time comparisons (`ct_eq`) and conditional assignment (`ct_select`).
   - `entropy`: Hardware entropy continuous health tests (NIST SP 800-90B Repetition Count Test & Adaptive Proportion Test).
   - `rate_limiter`: Sliding-window token bucket with cryptographic client IP hashing.
   - `key_management`: Ephemeral key encapsulation and HKDF-SHA256 derivation hierarchies.
   - `tamper_guard`: Runtime binary integrity checksums, Linux `TracerPid` debugger detection, and dead-man switch tripwires.
   - `audit_logger`: Chained HMAC-SHA256 tamper-evident compliance audit logger.

7. **`merkle::*` (Sparse Trees & Blake3 Merkle Chains)**:
   - `sparse_tree`: 256-level Sparse Merkle Tree (SMT) with default precomputed zero hashes.
   - `blake3_chain`: Parallel Blake3 Merkle tree with SIMD support and cryptographic inclusion proof generator.

8. **`compliance::*` (eIDAS & ISO/IEC 18013-5 mDL)**:
   - `eidas`: W3C Verifiable Credentials selective disclosure envelopes for eIDAS High LoA.
   - `iso_18013_5`: Mobile Driving License (mDL) Mobile Security Object (MSO) zero-knowledge selective disclosure proof verification.

9. **`benches/proof_benchmarks.rs` & `tests/zkp_verification_tests.rs`**:
   - Microsecond-level performance benchmarking harness and integration test suites.

---

## [0.1.0] - 2026-08-14
- Initial release of ZK-Auth Rust Axum Microservice and Next.js Developer Workbench.
