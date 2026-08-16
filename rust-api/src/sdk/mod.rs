//! Official ZK-Auth Rust Client SDK Suite
//!
//! Submodules:
//! - `client`: Async HTTP/REST client for ZK verification microservice.
//! - `builder`: Type-safe fluent builder for identity predicates.
//! - `offline_verifier`: Standalone air-gapped cryptographic receipt evaluator.

pub mod builder;
pub mod client;
pub mod offline_verifier;

pub use builder::ProofRequestBuilder;
pub use client::ZkAuthClient;
pub use offline_verifier::OfflineVerifier;
