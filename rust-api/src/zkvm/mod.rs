//! Zero-Knowledge Virtual Machine (zkVM) Architecture Suite
//!
//! Submodules:
//! - `opcodes`: 64-bit zkVM instruction set architecture and operand decoding.
//! - `state_machine`: Execution trace generator and virtual register machine.
//! - `polynomial`: Prime field univariate polynomial arithmetic, NTT, and quotient division.
//! - `fri`: Fast Reed-Solomon Interactive Oracle Proofs of Proximity (FRI).
//! - `air`: Algebraic Intermediate Representation constraints for computational integrity.
//! - `verifier`: End-to-end zkVM STARK certificate verifier.

pub mod air;
pub mod fri;
pub mod opcodes;
pub mod polynomial;
pub mod safe_execution_sandbox;
pub mod state_machine;
pub mod verifier;

pub use air::IdentityAir;
pub use fri::{FriCommitLayer, FriProof, FriQueryProof, FriVerifier};
pub use opcodes::{Instruction, Opcode, Register};
pub use polynomial::Polynomial;
pub use safe_execution_sandbox::{SafeZkVmSandbox, SandboxConfig, SandboxExecutionReceipt, SandboxViolation};
pub use state_machine::{ExecutionTrace, TraceRow, ZkVirtualMachine};
pub use verifier::{ZkCertificateVerifier, ZkExecutionCertificate};
