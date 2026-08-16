//! AegisZK: Cryptographic Zero-Knowledge Identity & Security Verification Engine
//!
//! A high-assurance, constant-time Rust library and microservice for privacy-preserving
//! identity verification, Groth16/BN254 pairing checks, Poseidon algebraic hashing,
//! Sparse Merkle Tree accumulators, and ephemeral memory lockdown.

pub mod circuits;
pub mod cli;
pub mod compliance;
pub mod crypto;
pub mod crypto_core;
pub mod handlers;
pub mod hsm;
pub mod identity;
pub mod merkle;
pub mod models;
pub mod mpc;
pub mod plonk;
pub mod privacy_engine;
pub mod sdk;
pub mod security;
pub mod smart_contracts;
pub mod store;
pub mod wasm;
pub mod zkp;
pub mod zkvm;

pub use circuits::age_circuit::{AgeCircuitConfig, AgeVerificationCircuit, AgeWitness};
pub use circuits::biometric_embedding::{BiometricCircuit, BiometricMatchResult, BiometricWitnessVector, EnrolledTemplateCommitment};
pub use circuits::groth16_bn254::Groth16IdentityVerifier;
pub use circuits::merkle_membership::{MerkleMembershipCircuit, MerkleMembershipWitness};
pub use circuits::recursive_folding::{FoldedProofReceipt, RecursiveFoldingScheme, RelaxedR1csInstance, RelaxedR1csWitness};
pub use circuits::sanctions_non_membership::{NonMembershipWitness, SanctionsNonMembershipCircuit};
pub use cli::{CliParser, TerminalRenderer, ZkCliCommand};
pub use crypto::{EphemeralSensitiveWitness, Nullifier, ZkCommitment, ZkProofEngine};
pub use crypto_core::{BlsG1Affine, BlsScalar, FeldmanVssEngine, Fp12, Fp6, JubjubPoint, OptimalAtePairing, PastaPoint, PqHybridEngine, PqHybridPublicKey, PqHybridSignature, SecretShare, VssCommitment};
pub use hsm::{EnclaveAttestationVerifier, HsmCryptoToken};
pub use identity::{AnonCredsVerifier, DidResolver, RevocationAccumulator, W3cVcEngine, W3cVerifiableCredential};
pub use merkle::blake3_chain::{Blake3MerkleTree, MerkleInclusionProof};
pub use merkle::sparse_tree::SparseMerkleTree;
pub use mpc::{CeremonyTranscript, MpcCoordinator};
pub use plonk::{KzgOpeningProof, KzgScheme, KzgSrs, PlonkGateRow, PlonkProof, PlonkProver, PlonkVerifier, WirePermutation};
pub use privacy_engine::{BlindSignature, BlindSignatureEngine, BlindedMessage, DifferentialPrivacyEngine, DifferentiallyPrivateStat, RingSignature, RingSignatureEngine};
pub use sdk::{OfflineVerifier, ProofRequestBuilder, ZkAuthClient};
pub use security::audit_logger::{CryptographicAuditLogger, SignedAuditEntry};
pub use security::constant_time::ct_eq;
pub use security::differential_privacy::{DifferentialPrivacyEngine as SecurityDpEngine, DpParameters, PrivacyBudgetState};
pub use security::enclave_attestation::{EnclaveAttestationEvidence, EnclaveTcbStatus, HardwareEnclaveVerifier};
pub use security::entropy::{EntropyEvaluator, EntropyHealthStatus};
pub use security::formal_verification::{FormalVerificationReport, FormalVerifier, VerifiedTheorem};
pub use security::guarded_memory::{GuardedBuffer, MemoryProtectionConfig};
pub use security::hsm_isolation::{HardwareSecurityModule, HsmSlotStatus, HsmUserPin};
pub use security::key_management::{KeyDerivation, KeyPair, SecretKey256};
pub use security::post_quantum::{HybridCiphertext, HybridPublicKey, HybridSecretKey, PostQuantumHybridEngine};
pub use security::rate_limiter::{RateLimitPolicy, RateLimiter};
pub use security::replay_guard::{ReplayGuard, ReplayGuardConfig};
pub use security::seccomp_sandbox::{SeccompPolicy, SeccompSandbox, SeccompStatusReport};
pub use security::strict_headers::StrictSecurityHeaders;
pub use security::tamper_guard::{TamperCheckReport, TamperGuard};
pub use security::timing_shield::TimingShield;
pub use smart_contracts::{EvmCalldataEncoder, SolidityVerifierGenerator};
pub use store::Repository;
pub use wasm::{BrowserProverEngine, GpuAccelerationBenchmark, WasmProverRequest, WasmProverResponse, WebGpuProver};
pub use zkp::bn254::{Fp, G1Affine, G2Affine, Groth16Proof, Groth16VerifyingKey, U256};
pub use zkp::pedersen::{BlindingFactor, PedersenCommitment, PedersenGenerators};
pub use zkp::poseidon::{poseidon_hash_2, poseidon_hash_bytes, PoseidonParams};
pub use zkp::r1cs::{ConstraintSystem, LinearCombination, Variable, WitnessTable};
pub use zkp::schnorr::{prove_knowledge, verify_knowledge, SchnorrProof, SchnorrPublicKey, SchnorrSecret};
pub use zkvm::{ExecutionTrace, FriProof, FriVerifier, IdentityAir, Instruction, Opcode, Register, TraceRow, ZkCertificateVerifier, ZkExecutionCertificate, ZkVirtualMachine};
