//! PLONK Universal SNARK Proof System Suite
//!
//! Submodules:
//! - `gates`: Custom arithmetic, range-check, and Poseidon hash gates.
//! - `permutation`: Wire copy permutation grand product argument.
//! - `kzg`: Kate-Zaverucha-Goldberg polynomial commitment scheme.
//! - `prover`: 4-round interactive Oracle proof synthesizer.
//! - `verifier`: Fast constant-time pairing verifier.

pub mod gates;
pub mod kzg;
pub mod permutation;
pub mod prover;
pub mod verifier;

pub use gates::PlonkGateRow;
pub use kzg::{KzgOpeningProof, KzgScheme, KzgSrs};
pub use permutation::WirePermutation;
pub use prover::{PlonkProof, PlonkProver};
pub use verifier::PlonkVerifier;
