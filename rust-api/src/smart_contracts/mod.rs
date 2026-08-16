//! Smart Contracts & On-Chain Zero-Knowledge Verification Suite
//!
//! Submodules:
//! - `solidity_generator`: Production Solidity Groth16 / BN254 verifier contract generator.
//! - `calldata`: EVM ABI encoding and proof calldata serializer.

pub mod calldata;
pub mod solidity_generator;

pub use calldata::{EvmCalldataEncoder, EvmCalldataPayload};
pub use solidity_generator::SolidityVerifierGenerator;
