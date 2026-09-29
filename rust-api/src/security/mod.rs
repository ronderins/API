//! Security, Hardening, and Cryptographic Protection Suite
//!
//! Comprehensive microarchitectural, hardware-enforced, and zero-knowledge security suite.
//!
//! Submodules:
//! - `audit_logger`: Tamper-evident HMAC chained cryptographic audit log.
//! - `audit_merkle_mountain_range`: Append-only MMR for logarithmic inclusion and consistency proofs.
//! - `biometric_liveness_vault`: Homomorphic 128-d cancelable BioHash and honey encryption vault.
//! - `circuit_tamper_proofing`: Runtime AST and R1CS arithmetic constraint sanity checks.
//! - `confidential_mpc_enclave`: AMD SEV-SNP & Intel SGX quote validation and sealed storage.
//! - `confidential_state_machine`: Verifiable credential state machine with zero-knowledge transition proofs.
//! - `constant_time`: Side-channel immune comparison and branchless operations.
//! - `differential_privacy`: Laplace and Gaussian perturbation with privacy budget accounting.
//! - `dilithium_fips204`: NIST FIPS 204 (ML-DSA) lattice-based post-quantum signature engine.
//! - `distributed_nullifier_graph`: Double-spend prevention DAG with epoch ratcheting.
//! - `enclave_attestation`: Remote hardware enclave evidence validation.
//! - `entropy`: Hardware entropy evaluation and NIST SP 800-90B health checks.
//! - `ephemeral_entropy_beacon`: Continuous NIST SP 800-90B RCT/APT health testing with HMAC-DRBG.
//! - `fault_injection_armor`: Dual-rail redundant execution neutralizing clock/laser glitches.
//! - `formal_proof_verifier`: Under-constrained wire detection and SMT-LIB2 circuit verification.
//! - `formal_verification`: Invariance verification for arithmetic gate systems.
//! - `guarded_memory`: Kernel `mlock`, `MADV_DONTDUMP`, guard pages, and RAII zeroization.
//! - `hardware_canary`: Ptrace anti-debugging, hardware canary integrity, and CPU fault traps.
//! - `hardware_security_token_fido2`: FIDO2/WebAuthn CTAP2 authenticator parsing and replay protection.
//! - `homomorphic_tally`: Additive ElGamal homomorphic tallying and zero-knowledge shuffle proofs.
//! - `hsm_isolation`: Hardware Security Module token isolation and PKCS#11 abstractions.
//! - `key_management`: Ephemeral key exchange and HKDF-SHA256 derivation hierarchies.
//! - `mtls_pki_validator`: Mutual TLS X.509 PKI certificate chain and intermediate pinning.
//! - `oblivious_transfer`: Chou-Orlandi 1-of-2 OT and Yao's Garbled Circuits predicate evaluator.
//! - `post_quantum`: NIST Kyber-768 / X25519 hybrid post-quantum key encapsulation.
//! - `quantum_kyber_pke`: Ring-LWE polynomial arithmetic with NTT acceleration.
//! - `rate_limiter`: Distributed sliding window rate limiter with cryptographic client hashing.
//! - `rate_limiter_distributed`: Generic Cell Rate Algorithm (GCRA) token bucket rate limiter.
//! - `replay_guard`: Bloom-indexed spent nullifier ledger and epoch freshness verification.
//! - `safe_memory_allocator`: Page-boundary memory canaries with volatile multi-pass zeroization.
//! - `sanctions_bloom_filter`: Blinded counting Bloom filter for OFAC non-membership checks.
//! - `seccomp_sandbox`: Linux Seccomp-BPF strict syscall filtering and process isolation.
//! - `side_channel_defenses`: Oblivious table lookups and branchless arithmetic selects.
//! - `side_channel_spectre_shield`: Speculative execution barriers and cache-line isolation.
//! - `strict_headers`: Zero-trust HTTP security headers (HSTS 2-yr, CSP strict, COOP/CORP).
//! - `tamper_guard`: Runtime binary integrity, ptrace checks, and dead-man tripwires.
//! - `threshold_mpc_signing`: Distributed FROST t-of-n Schnorr threshold signing and Feldman VSS.
//! - `timing_shield`: Cache-line eviction, constant-jitter blinding, and branchless selects.
//! - `tls_session_ticket_armor`: Hardware-isolated Session Ticket Encryption Key (STEK) armor.
//! - `w3c_sd_jwt_vc`: W3C Selective Disclosure JWT (SD-JWT) salted claim engine.
//! - `zero_knowledge_audit_trail`: Forward-secure append-only Merkle receipt audit blocks.
//! - `zero_knowledge_revocation`: Dynamic bilinear pairing accumulator with non-membership proofs.
//! - `zero_leakage_sanctions_engine`: Private Set Intersection (PSI) and Cuckoo Filter non-membership.
//! - `zk_dos_shield`: Proof-of-Work dynamic difficulty shield against algorithmic CPU exhaustion.
//! - `zk_rate_limiter_anonymous`: Rate-Limiting Nullifier (RLN) Shamir double-spend slashing.
//! - `zk_rollup_batcher`: Recursive ZK-Rollup proof compressor and state transition engine.

pub mod audit_logger;
pub mod audit_merkle_mountain_range;
pub mod biometric_liveness_vault;
pub mod blind_threshold_signatures;
pub mod circuit_tamper_proofing;
pub mod confidential_mpc_enclave;
pub mod confidential_state_machine;
pub mod constant_time;
pub mod differential_privacy;
pub mod dilithium_fips204;
pub mod distributed_nullifier_graph;
pub mod enclave_attestation;
pub mod entropy;
pub mod ephemeral_entropy_beacon;
pub mod fault_injection_armor;
pub mod formal_proof_verifier;
pub mod formal_r1cs_optimizer;
pub mod formal_verification;
pub mod guarded_memory;
pub mod hardware_canary;
pub mod hardware_security_token_fido2;
pub mod homomorphic_paillier_engine;
pub mod homomorphic_tally;
pub mod honey_encryption_vault;
pub mod hsm_isolation;
pub mod key_management;
pub mod mtls_pki_validator;
pub mod oblivious_transfer;
pub mod plonk_upookup_tables;
pub mod post_quantum;
pub mod quantum_kyber_pke;
pub mod rate_limiter;
pub mod rate_limiter_distributed;
pub mod replay_guard;
pub mod safe_memory_allocator;
pub mod sanctions_bloom_filter;
pub mod seccomp_sandbox;
pub mod side_channel_defenses;
pub mod side_channel_spectre_shield;
pub mod strict_headers;
pub mod tamper_guard;
pub mod threshold_decryption_rsa_bls;
pub mod threshold_key_derivation_hkdf;
pub mod threshold_mpc_signing;
pub mod threshold_oblivious_prf;
pub mod timing_shield;
pub mod tls_session_ticket_armor;
pub mod w3c_sd_jwt_vc;
pub mod wasm_enclave_sandbox;
pub mod zero_knowledge_audit_trail;
pub mod zero_knowledge_revocation;
pub mod zero_leakage_sanctions_engine;
pub mod zk_anonymous_credential_issuer;
pub mod zk_attestation_pki_bridge;
pub mod zk_confidential_credit_score;
pub mod zk_dos_shield;
pub mod zk_membership_merkle_accumulator;
pub mod zk_rate_limiter_anonymous;
pub mod zk_rollup_batcher;
pub mod zk_sanctions_fuzzy_trie;
pub mod zk_verifiable_shuffle;

pub use audit_logger::{CryptographicAuditLogger, SignedAuditEntry};
pub use audit_merkle_mountain_range::{MerkleMountainRange, MmrInclusionProof, MmrNode};
pub use biometric_liveness_vault::{BiometricEmbedding128, BiometricMatchReceipt, BiometricVault, BiometricVaultRecord};
pub use blind_threshold_signatures::{BlindSignatureRequest, BlindSignatureShare, BlindThresholdEngine, ThresholdBlindSignerKey, UnblindedAnonymousToken};
pub use circuit_tamper_proofing::{CircuitSafetyAuditReport, CircuitSafetyVerifier, CircuitSafetyViolation};
pub use confidential_mpc_enclave::{ConfidentialEnclaveEngine, EnclaveAttestationQuote, EnclaveMeasurement, EnclaveType, EnclaveVerificationPolicy, SealedEnclavePayload};
pub use confidential_state_machine::{ConfidentialStateMachine, CredentialLifecycleState, CredentialStateRecord, StateTransitionProof};
pub use constant_time::ct_eq;
pub use differential_privacy::{DifferentialPrivacyEngine, DpParameters, PrivacyBudgetState};
pub use dilithium_fips204::{DilithiumPoly, MlDsaEngine, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use distributed_nullifier_graph::{DistributedNullifierGraph, NullifierGraphNode, NullifierSyncCheckpoint, VerificationEpoch};
pub use enclave_attestation::{EnclaveAttestationEvidence, EnclaveTcbStatus, HardwareEnclaveVerifier};
pub use entropy::{EntropyEvaluator, EntropyHealthStatus};
pub use ephemeral_entropy_beacon::{ContinuousHealthTester, EntropyFailureReason, HardenedHmacDrbg};
pub use fault_injection_armor::{FaultInjectionArmor, HardenedBoolean, RedundantAuditProof};
pub use formal_proof_verifier::{CircuitDescription, CircuitVulnerabilityKind, FormalAuditReport, FormalCircuitVerifier, FormalConstraintRow};
pub use formal_r1cs_optimizer::{OptimizationCertificate, R1csFormalOptimizer, R1csGate, R1csTerm};
pub use formal_verification::{FormalVerificationReport, FormalVerifier, VerifiedTheorem};
pub use guarded_memory::{GuardedBuffer, MemoryProtectionConfig};
pub use hardware_canary::{CanaryHealthStatus, HardwareCanaryGuard};
pub use hardware_security_token_fido2::{Fido2Policy, Fido2VerificationResult, HardwareSecurityTokenEngine, ParsedAuthenticatorData, WebAuthnAssertion};
pub use homomorphic_paillier_engine::{BigInt512, PaillierCiphertext, PaillierEngine, PaillierPrivateKey, PaillierPublicKey, PaillierRangeProof};
pub use homomorphic_tally::{DlogEqualityProof, HomomorphicCiphertext, HomomorphicKeypair, HomomorphicTallyEngine, Scalar256};
pub use honey_encryption_vault::{HoneyCiphertext, HoneyEncryptionVault, IdentityDte, VaultIdentityRecord};
pub use hsm_isolation::{HardwareSecurityModule, HsmSlotStatus, HsmUserPin};
pub use key_management::{KeyDerivation, KeyPair, SecretKey256};
pub use mtls_pki_validator::{MtlsSecurityContext, ParsedX509Certificate, PkiTrustStore, PkiValidationError};
pub use oblivious_transfer::{GarbledCircuit, ObliviousTransferEngine, OtBlock, OtReceiverQuery, OtSenderResponse, OtSenderSetup};
pub use plonk_upookup_tables::{LookupTable, MultiplicityVector, PlookupEngine, PlookupProof, WitnessQueryColumn};
pub use post_quantum::{HybridCiphertext, HybridPublicKey, HybridSecretKey, PostQuantumHybridEngine};
pub use quantum_kyber_pke::{MlKem768Engine, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, RingPolynomial};
pub use rate_limiter::{RateLimitPolicy, RateLimiter};
pub use rate_limiter_distributed::{GcraRateLimiter, RateLimitTier};
pub use replay_guard::{ReplayGuard, ReplayGuardConfig};
pub use safe_memory_allocator::{MemoryProtectionPolicy, SafeMemoryBuffer, SecureCell};
pub use sanctions_bloom_filter::{SanctionsBloomFilter, SanctionsCheckResult};
pub use seccomp_sandbox::{SeccompPolicy, SeccompSandbox, SeccompStatusReport};
pub use side_channel_defenses::{ObliviousTable, SafeScalar32, SideChannelShield};
pub use side_channel_spectre_shield::{CacheAlignedSecret, ObliviousSboxTable, SpectreShield};
pub use strict_headers::StrictSecurityHeaders;
pub use tamper_guard::{TamperCheckReport, TamperGuard};
pub use threshold_decryption_rsa_bls::{DecryptionKeyShare, DecryptionShare, DleqProof, ThresholdDecryptedResult, ThresholdDecryptionEngine};
pub use threshold_key_derivation_hkdf::{DerivationStepShare, DerivedSubkey, DhkdfNodeShare, DistributedHkdfEngine};
pub use threshold_mpc_signing::{AggregatedThresholdSignature, FeldmanCommitment, FrostCoordinator, KeyShare, PartialSignature, Round1Commitment, ThresholdScalar};
pub use threshold_oblivious_prf::{ObliviousPrfEngine, OprfBlindQuery, OprfEvaluatedResponse, OprfOutputKey, OprfServerKey};
pub use timing_shield::TimingShield;
pub use tls_session_ticket_armor::{SealedSessionTicket, StekKeyEntry, TlsSessionTicketArmor};
pub use w3c_sd_jwt_vc::{SaltedDisclosure, SdJwtCredential, SdJwtEngine, SdJwtPresentation, SdJwtVerificationResult};
pub use wasm_enclave_sandbox::{WasmEnclaveSandbox, WasmExecutionReceipt, WasmLinearMemory, WasmOpcode, WasmSandboxError, WasmStateSnapshot};
pub use zero_knowledge_audit_trail::{AuditLogBlock, AuditVerificationReceipt, ForwardSecureAuditTrail};
pub use zero_knowledge_revocation::{AccumulatorCommitment, AccumulatorElement, DynamicRevocationAccumulator, NonMembershipWitness as RevocationNonMembershipWitness};
pub use zero_leakage_sanctions_engine::{BlindedCuckooFilter, BlindedSanctionsQuery, OracleSanctionsResponse, SanctionsNonMembershipReceipt, ZeroLeakageSanctionsEngine};
pub use zk_anonymous_credential_issuer::{BbsPlusEngine, BbsPlusProofOfKnowledge, BbsPlusPublicKey, BbsPlusSecretKey, BbsPlusSignature};
pub use zk_attestation_pki_bridge::{DistinguishedNameAttribute, ParsedZkX509Certificate, ZkPkiAttestationReceipt, ZkPkiBridgeEngine};
pub use zk_confidential_credit_score::{ConfidentialCreditEngine, ConfidentialCreditReceipt, ConfidentialFinancialWitness, FinancialCommitmentBundle, SolvencyPolicy};
pub use zk_dos_shield::{PowChallenge, PowSolution, ZkDosShield};
pub use zk_membership_merkle_accumulator::{SmtMembershipProof, SmtProofStep, SparseMerkleTree256};
pub use zk_rate_limiter_anonymous::{RlnIdentitySecret, RlnManager, RlnProofShare, SlashedIdentityEvidence};
pub use zk_rollup_batcher::{RollupBatchReceipt, RollupBlockHeader, RollupStateDiff, RollupVerificationTx, ZkRollupBatcher};
pub use zk_sanctions_fuzzy_trie::{FuzzyMatchReceipt, FuzzyNameMatchingEngine, FuzzyTrieNode};
pub use zk_verifiable_shuffle::{ShuffleCiphertext, VerifiableShuffleEngine, VerifiableShuffleProof};
