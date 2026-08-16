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
pub mod constant_time;
pub mod entropy;
pub mod guarded_memory;
pub mod key_management;
pub mod rate_limiter;
pub mod replay_guard;
pub mod seccomp_sandbox;
pub mod strict_headers;
pub mod tamper_guard;
pub mod timing_shield;

pub use audit_logger::{CryptographicAuditLogger, SignedAuditEntry};
pub use constant_time::ct_eq;
pub use entropy::{EntropyEvaluator, EntropyHealthStatus};
pub use guarded_memory::{GuardedBuffer, MemoryProtectionConfig};
pub use key_management::{KeyDerivation, KeyPair, SecretKey256};
pub use rate_limiter::{RateLimitPolicy, RateLimiter};
pub use replay_guard::{ReplayGuard, ReplayGuardConfig};
pub use seccomp_sandbox::{SeccompPolicy, SeccompSandbox, SeccompStatusReport};
pub use strict_headers::StrictSecurityHeaders;
pub use tamper_guard::{TamperCheckReport, TamperGuard};
pub use timing_shield::TimingShield;
