//! Security, Hardening, and Cryptographic Protection Suite
//!
//! Submodules:
//! - `constant_time`: Side-channel immune comparison and branchless operations.
//! - `entropy`: Hardware entropy evaluation and NIST SP 800-90B health checks.
//! - `rate_limiter`: Distributed sliding window rate limiter with cryptographic client hashing.
//! - `key_management`: Ephemeral key exchange and HKDF-SHA256 derivation hierarchies.
//! - `tamper_guard`: Runtime binary integrity, ptrace checks, and dead-man tripwires.
//! - `audit_logger`: Tamper-evident HMAC chained cryptographic audit log.

pub mod audit_logger;
pub mod constant_time;
pub mod entropy;
pub mod key_management;
pub mod rate_limiter;
pub mod tamper_guard;
