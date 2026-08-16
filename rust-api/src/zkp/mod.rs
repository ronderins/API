//! Zero-Knowledge Proofs and Cryptographic Foundations
//!
//! Submodules:
//! - `bn254`: Field and curve arithmetic over BN254 / alt_bn128 for pairing checks.
//! - `poseidon`: SNARK-friendly algebraic hash function.
//! - `r1cs`: Rank-1 Constraint System synthesizer and verifier.
//! - `pedersen`: Vector commitments and blinding factor management.
//! - `schnorr`: Non-interactive zero-knowledge proofs of knowledge (NIZKPoK).

pub mod bn254;
pub mod pedersen;
pub mod poseidon;
pub mod r1cs;
pub mod schnorr;
