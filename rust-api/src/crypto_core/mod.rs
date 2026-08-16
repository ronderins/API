//! High-Performance Elliptic Curves, Towers, and Pairing Kernels
//!
//! Submodules:
//! - `fp12`: 12th-degree tower extension field arithmetic.
//! - `optimal_ate`: Miller loop and final exponentiation bilinear pairings.
//! - `bls12_381`: BLS12-381 pairing-friendly curve arithmetic.
//! - `jubjub`: Twisted Edwards Jubjub embedded curve for inside-SNARK operations.
//! - `pasta`: Pallas/Vesta recursive cycles of curves.
//! - `vss_threshold`: Feldman Verifiable Secret Sharing & threshold decryption.
//! - `pq_hybrid`: Post-quantum hybrid signatures (ML-DSA / Dilithium).

pub mod bls12_381;
pub mod bn254_constants;
pub mod ed25519;
pub mod fp12;
pub mod jubjub;
pub mod optimal_ate;
pub mod pasta;
pub mod pq_hybrid;
pub mod secp256k1;
pub mod vss_threshold;

pub use bls12_381::{BlsG1Affine, BlsScalar};
pub use bn254_constants::Bn254Constants;
pub use ed25519::{Ed25519Field, Ed25519Point};
pub use fp12::{Fp12, Fp6};
pub use jubjub::JubjubPoint;
pub use optimal_ate::OptimalAtePairing;
pub use pasta::PastaPoint;
pub use pq_hybrid::{PqHybridEngine, PqHybridPublicKey, PqHybridSignature};
pub use secp256k1::{Secp256k1Field, Secp256k1Jacobian};
pub use vss_threshold::{FeldmanVssEngine, SecretShare, VssCommitment};
