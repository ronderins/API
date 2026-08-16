//! Zero-Knowledge Arithmetic Circuits and Predicates
//!
//! Submodules:
//! - `age_circuit`: R1CS circuit for age predicates without birth year leakage.
//! - `merkle_membership`: Poseidon membership circuit for private identity registries.
//! - `sanctions_non_membership`: Cryptographic accumulator for OFAC / blacklist non-membership.
//! - `bulletproofs_range`: Inner product range proof verifier.
//! - `groth16_bn254`: Groth16 zk-SNARK verifier interface.
//! - `recursive_folding`: Nova/IVC multi-predicate proof folding accumulator.
//! - `biometric_embedding`: Private zero-knowledge biometric template matching circuit.

pub mod age_circuit;
pub mod biometric_embedding;
pub mod bulletproofs_range;
pub mod gadgets;
pub mod groth16_bn254;
pub mod merkle_membership;
pub mod recursive_folding;
pub mod sanctions_non_membership;

pub use biometric_embedding::{BiometricCircuit, BiometricMatchResult, BiometricWitnessVector, EnrolledTemplateCommitment};
pub use recursive_folding::{FoldedProofReceipt, RecursiveFoldingScheme, RelaxedR1csInstance, RelaxedR1csWitness};
