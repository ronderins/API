//! Security, Hardening, and Cryptographic Protection Suite
//!
//! Submodules:
//! - `constant_time`: Side-channel immune comparison and branchless operations.
//! - `entropy`: Hardware entropy evaluation and NIST SP 800-90B health checks.
//! - `rate_limiter`: Distributed sliding window rate limiter with cryptographic client hashing.
//! - `key_management`: Ephemeral key exchange and HKDF-SHA256 derivation hierarchies.
//! - `tamper_guard`: Runtime binary integrity, ptrace checks, and dead-man tripwires.
//! - `audit_logger`: Tamper-evident HMAC chained cryptographic audit log.
//! - `guarded_memory`: Kernel `mlock`, `MADV_DONTDUMP`, guard pages, and RAII zeroization.
//! - `seccomp_sandbox`: Linux Seccomp-BPF strict syscall filtering and process isolation.
//! - `timing_shield`: Cache-line eviction, constant-jitter blinding, and branchless selects.
//! - `replay_guard`: Bloom-indexed spent nullifier ledger and epoch freshness verification.
//! - `strict_headers`: Zero-trust HTTP security headers (HSTS 2-yr, CSP strict, COOP/CORP).

pub mod audit_logger;
pub mod circuit_tamper_proofing;
pub mod confidential_state_machine;
pub mod constant_time;
pub mod differential_privacy;
pub mod enclave_attestation;
pub mod entropy;
pub mod ephemeral_entropy_beacon;
pub mod fault_injection_armor;
pub mod formal_verification;
pub mod guarded_memory;
pub mod hardware_canary;
pub mod homomorphic_tally;
pub mod hsm_isolation;
pub mod key_management;
pub mod mtls_pki_validator;
pub mod post_quantum;
pub mod quantum_kyber_pke;
pub mod rate_limiter;
pub mod rate_limiter_distributed;
pub mod replay_guard;
pub mod safe_memory_allocator;
pub mod sanctions_bloom_filter;
pub mod seccomp_sandbox;
pub mod side_channel_defenses;
pub mod strict_headers;
pub mod tamper_guard;
pub mod timing_shield;
pub mod tls_session_ticket_armor;
pub mod zero_knowledge_audit_trail;
pub mod zk_dos_shield;

pub use audit_logger::{CryptographicAuditLogger, SignedAuditEntry};
pub use circuit_tamper_proofing::{CircuitSafetyAuditReport, CircuitSafetyVerifier, CircuitSafetyViolation};
pub use confidential_state_machine::{ConfidentialStateMachine, CredentialLifecycleState, CredentialStateRecord, StateTransitionProof};
pub use constant_time::ct_eq;
pub use differential_privacy::{DifferentialPrivacyEngine, DpParameters, PrivacyBudgetState};
pub use enclave_attestation::{EnclaveAttestationEvidence, EnclaveTcbStatus, HardwareEnclaveVerifier};
pub use entropy::{EntropyEvaluator, EntropyHealthStatus};
pub use ephemeral_entropy_beacon::{ContinuousHealthTester, EntropyFailureReason, HardenedHmacDrbg};
pub use fault_injection_armor::{FaultInjectionArmor, HardenedBoolean, RedundantAuditProof};
pub use formal_verification::{FormalVerificationReport, FormalVerifier, VerifiedTheorem};
pub use guarded_memory::{GuardedBuffer, MemoryProtectionConfig};
pub use hardware_canary::{CanaryHealthStatus, HardwareCanaryGuard};
pub use homomorphic_tally::{DlogEqualityProof, HomomorphicCiphertext, HomomorphicKeypair, HomomorphicTallyEngine, Scalar256};
pub use hsm_isolation::{HardwareSecurityModule, HsmSlotStatus, HsmUserPin};
pub use key_management::{KeyDerivation, KeyPair, SecretKey256};
pub use mtls_pki_validator::{MtlsSecurityContext, ParsedX509Certificate, PkiTrustStore, PkiValidationError};
pub use post_quantum::{HybridCiphertext, HybridPublicKey, HybridSecretKey, PostQuantumHybridEngine};
pub use quantum_kyber_pke::{MlKem768Engine, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, RingPolynomial};
pub use rate_limiter::{RateLimitPolicy, RateLimiter};
pub use rate_limiter_distributed::{GcraRateLimiter, RateLimitTier};
pub use replay_guard::{ReplayGuard, ReplayGuardConfig};
pub use safe_memory_allocator::{MemoryProtectionPolicy, SafeMemoryBuffer, SecureCell};
pub use sanctions_bloom_filter::{SanctionsBloomFilter, SanctionsCheckResult};
pub use seccomp_sandbox::{SeccompPolicy, SeccompSandbox, SeccompStatusReport};
pub use side_channel_defenses::{ObliviousTable, SafeScalar32, SideChannelShield};
pub use strict_headers::StrictSecurityHeaders;
pub use tamper_guard::{TamperCheckReport, TamperGuard};
pub use timing_shield::TimingShield;
pub use tls_session_ticket_armor::{SealedSessionTicket, StekKeyEntry, TlsSessionTicketArmor};
pub use zero_knowledge_audit_trail::{AuditLogBlock, AuditVerificationReceipt, ForwardSecureAuditTrail};
pub use zk_dos_shield::{PowChallenge, PowSolution, ZkDosShield};
