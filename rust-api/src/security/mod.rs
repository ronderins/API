//! Security, Hardening, and Cryptographic Protection Suite
//!
//! Comprehensive microarchitectural, hardware-enforced, and zero-knowledge security suite.
//!
//! Submodules:
//! - `audit_logger`: Tamper-evident HMAC chained cryptographic audit log.
//! - `audit_merkle_mountain_range`: Append-only MMR for logarithmic inclusion and consistency proofs.
//! - `biometric_liveness_vault`: Homomorphic 128-d cancelable BioHash and honey encryption vault.
//! - `circuit_tamper_proofing`: Runtime AST and R1CS arithmetic constraint sanity checks.
//! - `confidential_mpc_enclave`: AMD SEV-SNP & Intel SGX quote validation and sealed storage.
//! - `confidential_state_machine`: Verifiable credential state machine with zero-knowledge transition proofs.
//! - `constant_time`: Side-channel immune comparison and branchless operations.
//! - `differential_privacy`: Laplace and Gaussian perturbation with privacy budget accounting.
//! - `dilithium_fips204`: NIST FIPS 204 (ML-DSA) lattice-based post-quantum signature engine.
//! - `distributed_nullifier_graph`: Double-spend prevention DAG with epoch ratcheting.
//! - `enclave_attestation`: Remote hardware enclave evidence validation.
//! - `entropy`: Hardware entropy evaluation and NIST SP 800-90B health checks.
//! - `ephemeral_entropy_beacon`: Continuous NIST SP 800-90B RCT/APT health testing with HMAC-DRBG.
//! - `fault_injection_armor`: Dual-rail redundant execution neutralizing clock/laser glitches.
//! - `formal_proof_verifier`: Under-constrained wire detection and SMT-LIB2 circuit verification.
//! - `formal_verification`: Invariance verification for arithmetic gate systems.
//! - `guarded_memory`: Kernel `mlock`, `MADV_DONTDUMP`, guard pages, and RAII zeroization.
//! - `hardware_canary`: Ptrace anti-debugging, hardware canary integrity, and CPU fault traps.
//! - `hardware_security_token_fido2`: FIDO2/WebAuthn CTAP2 authenticator parsing and replay protection.
//! - `homomorphic_tally`: Additive ElGamal homomorphic tallying and zero-knowledge shuffle proofs.
//! - `hsm_isolation`: Hardware Security Module token isolation and PKCS#11 abstractions.
//! - `key_management`: Ephemeral key exchange and HKDF-SHA256 derivation hierarchies.
//! - `mtls_pki_validator`: Mutual TLS X.509 PKI certificate chain and intermediate pinning.
//! - `oblivious_transfer`: Chou-Orlandi 1-of-2 OT and Yao's Garbled Circuits predicate evaluator.
//! - `post_quantum`: NIST Kyber-768 / X25519 hybrid post-quantum key encapsulation.
//! - `quantum_kyber_pke`: Ring-LWE polynomial arithmetic with NTT acceleration.
//! - `rate_limiter`: Distributed sliding window rate limiter with cryptographic client hashing.
//! - `rate_limiter_distributed`: Generic Cell Rate Algorithm (GCRA) token bucket rate limiter.
//! - `replay_guard`: Bloom-indexed spent nullifier ledger and epoch freshness verification.
//! - `safe_memory_allocator`: Page-boundary memory canaries with volatile multi-pass zeroization.
//! - `sanctions_bloom_filter`: Blinded counting Bloom filter for OFAC non-membership checks.
//! - `seccomp_sandbox`: Linux Seccomp-BPF strict syscall filtering and process isolation.
//! - `side_channel_defenses`: Oblivious table lookups and branchless arithmetic selects.
//! - `side_channel_spectre_shield`: Speculative execution barriers and cache-line isolation.
//! - `strict_headers`: Zero-trust HTTP security headers (HSTS 2-yr, CSP strict, COOP/CORP).
//! - `tamper_guard`: Runtime binary integrity, ptrace checks, and dead-man tripwires.
//! - `threshold_mpc_signing`: Distributed FROST t-of-n Schnorr threshold signing and Feldman VSS.
//! - `timing_shield`: Cache-line eviction, constant-jitter blinding, and branchless selects.
//! - `tls_session_ticket_armor`: Hardware-isolated Session Ticket Encryption Key (STEK) armor.
//! - `w3c_sd_jwt_vc`: W3C Selective Disclosure JWT (SD-JWT) salted claim engine.
//! - `zero_knowledge_audit_trail`: Forward-secure append-only Merkle receipt audit blocks.
//! - `zero_knowledge_revocation`: Dynamic bilinear pairing accumulator with non-membership proofs.
//! - `zero_leakage_sanctions_engine`: Private Set Intersection (PSI) and Cuckoo Filter non-membership.
//! - `zk_dos_shield`: Proof-of-Work dynamic difficulty shield against algorithmic CPU exhaustion.
//! - `zk_rate_limiter_anonymous`: Rate-Limiting Nullifier (RLN) Shamir double-spend slashing.
//! - `zk_rollup_batcher`: Recursive ZK-Rollup proof compressor and state transition engine.

pub mod audit_logger;
pub mod audit_merkle_mountain_range;
pub mod biometric_liveness_vault;
pub mod blind_threshold_signatures;
pub mod circuit_tamper_proofing;
pub mod confidential_mpc_enclave;
pub mod confidential_state_machine;
pub mod constant_time;
pub mod differential_privacy;
pub mod dilithium_fips204;
pub mod distributed_nullifier_graph;
pub mod enclave_attestation;
pub mod entropy;
pub mod ephemeral_entropy_beacon;
pub mod fault_injection_armor;
pub mod formal_proof_verifier;
pub mod formal_r1cs_optimizer;
pub mod formal_verification;
pub mod guarded_memory;
pub mod hardware_canary;
pub mod hardware_security_token_fido2;
pub mod homomorphic_paillier_engine;
pub mod homomorphic_tally;
pub mod honey_encryption_vault;
pub mod hsm_isolation;
pub mod key_management;
pub mod mtls_pki_validator;
pub mod oblivious_transfer;
pub mod plonk_upookup_tables;
pub mod post_quantum;
pub mod quantum_kyber_pke;
pub mod rate_limiter;
pub mod rate_limiter_distributed;
pub mod replay_guard;
pub mod safe_memory_allocator;
pub mod sanctions_bloom_filter;
pub mod seccomp_sandbox;
pub mod side_channel_defenses;
pub mod side_channel_spectre_shield;
pub mod strict_headers;
pub mod tamper_guard;
pub mod threshold_decryption_rsa_bls;
pub mod threshold_key_derivation_hkdf;
pub mod threshold_mpc_signing;
pub mod threshold_oblivious_prf;
pub mod timing_shield;
pub mod tls_session_ticket_armor;
pub mod w3c_sd_jwt_vc;
pub mod wasm_enclave_sandbox;
pub mod zero_knowledge_audit_trail;
pub mod zero_knowledge_revocation;
pub mod zero_leakage_sanctions_engine;
pub mod zk_anonymous_credential_issuer;
pub mod zk_attestation_pki_bridge;
pub mod zk_confidential_credit_score;
pub mod zk_dos_shield;
pub mod zk_membership_merkle_accumulator;
pub mod zk_rate_limiter_anonymous;
pub mod zk_rollup_batcher;
pub mod zk_sanctions_fuzzy_trie;
pub mod zk_verifiable_shuffle;

// Advanced Ultra-Hardened Security Modules
pub mod fhe_bfv_ckks;
pub mod zkvm_jit_armor;
pub mod threshold_bls_aggregation;
pub mod verifiable_delay_function;
pub mod stark_fri_engine;
pub mod oblivious_keyword_search;
pub mod falcon_fips206;
pub mod w3c_did_vp_engine;
pub mod bulletproofs_plus_range;
pub mod pkcs11_session_armor;
pub mod homomorphic_secret_sharing;
pub mod confidential_query_guard;
pub mod dynamic_vector_accumulator;
pub mod zk_cross_chain_relayer;
pub mod ring_signatures_clsag;
pub mod oprf_blind_tokens;
pub mod zk_kyc_compliance_matrix;
pub mod kernel_memory_armor;
pub mod zk_plonk_hypercube;
pub mod threshold_oblivious_transfer_psi;
pub mod zk_plonk_fri_composer;
pub mod blind_zk_threshold_credentials;
pub mod zk_confidential_state_channels;
pub mod zk_fuzzy_commitment_biometrics;
pub mod zk_adaptive_threat_response;
pub mod asynchronous_vss_dkg;
pub mod encrypted_identity_graph;
pub mod plonkish_custom_gate_matrix;
pub mod verifiable_random_function_ecvrf;
pub mod sphincs_plus_fips205;
pub mod psi_cardinality_paillier;
pub mod zk_fair_lottery_shuffle;
pub mod enclave_key_sealing;
pub mod homomorphic_inner_product_argument;
pub mod zk_graph_sanitization;
pub mod zk_verifiable_shuffle_prover;
pub mod threshold_key_recovery_engine;
pub mod differential_privacy_advanced;
pub mod homomorphic_vector_commitments;
pub mod musig2_schnorr_threshold;
pub mod enclave_protected_channel;
pub mod path_oram_memory_engine;
pub mod plonkish_logup_multi_table;
pub mod single_server_private_information_retrieval;
pub mod zk_compliance_decision_tree;
pub mod smt_circuit_solver_bridge;
pub mod threshold_schnorr_blind_sig;
pub mod zk_attribute_based_encryption;
pub mod blake3_incremental_streaming_tree;
pub mod zk_multiset_hash_accumulator;
pub mod dice_hardware_identity_pki;
pub mod zk_batch_shuffle_verifier;
pub mod confidential_calldata_evm;
pub mod proactive_secret_sharing;
pub mod verifiable_credential_federation;
pub mod pq_session_key_exchange;
pub mod zk_confidential_ot_extension;
pub mod hardware_tee_keystore;
pub mod zk_plonk_hyperplonk_prover;
pub mod zk_confidential_multi_hop_settlement;
pub mod zk_groth16_recursive_verifier;
pub mod formal_invariant_arithmetic_fuzzer;

pub use audit_logger::{CryptographicAuditLogger, SignedAuditEntry};
pub use audit_merkle_mountain_range::{MerkleMountainRange, MmrInclusionProof, MmrNode};
pub use biometric_liveness_vault::{BiometricEmbedding128, BiometricMatchReceipt, BiometricVault, BiometricVaultRecord};
pub use blind_threshold_signatures::{BlindSignatureRequest, BlindSignatureShare, BlindThresholdEngine, ThresholdBlindSignerKey, UnblindedAnonymousToken};
pub use circuit_tamper_proofing::{CircuitSafetyAuditReport, CircuitSafetyVerifier, CircuitSafetyViolation};
pub use confidential_mpc_enclave::{ConfidentialEnclaveEngine, EnclaveAttestationQuote, EnclaveMeasurement, EnclaveType, EnclaveVerificationPolicy, SealedEnclavePayload};
pub use confidential_state_machine::{ConfidentialStateMachine, CredentialLifecycleState, CredentialStateRecord, StateTransitionProof};
pub use constant_time::ct_eq;
pub use differential_privacy::{DifferentialPrivacyEngine, DpParameters, PrivacyBudgetState};
pub use dilithium_fips204::{DilithiumPoly, MlDsaEngine, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use distributed_nullifier_graph::{DistributedNullifierGraph, NullifierGraphNode, NullifierSyncCheckpoint, VerificationEpoch};
pub use enclave_attestation::{EnclaveAttestationEvidence, EnclaveTcbStatus, HardwareEnclaveVerifier};
pub use entropy::{EntropyEvaluator, EntropyHealthStatus};
pub use ephemeral_entropy_beacon::{ContinuousHealthTester, EntropyFailureReason, HardenedHmacDrbg};
pub use fault_injection_armor::{FaultInjectionArmor, HardenedBoolean, RedundantAuditProof};
pub use formal_proof_verifier::{CircuitDescription, CircuitVulnerabilityKind, FormalAuditReport, FormalCircuitVerifier, FormalConstraintRow};
pub use formal_r1cs_optimizer::{OptimizationCertificate, R1csFormalOptimizer, R1csGate, R1csTerm};
pub use formal_verification::{FormalVerificationReport, FormalVerifier, VerifiedTheorem};
pub use guarded_memory::{GuardedBuffer, MemoryProtectionConfig};
pub use hardware_canary::{CanaryHealthStatus, HardwareCanaryGuard};
pub use hardware_security_token_fido2::{Fido2Policy, Fido2VerificationResult, HardwareSecurityTokenEngine, ParsedAuthenticatorData, WebAuthnAssertion};
pub use homomorphic_paillier_engine::{BigInt512, PaillierCiphertext, PaillierEngine, PaillierPrivateKey, PaillierPublicKey, PaillierRangeProof};
pub use homomorphic_tally::{DlogEqualityProof, HomomorphicCiphertext, HomomorphicKeypair, HomomorphicTallyEngine, Scalar256};
pub use honey_encryption_vault::{HoneyCiphertext, HoneyEncryptionVault, IdentityDte, VaultIdentityRecord};
pub use hsm_isolation::{HardwareSecurityModule, HsmSlotStatus, HsmUserPin};
pub use key_management::{KeyDerivation, KeyPair, SecretKey256};
pub use mtls_pki_validator::{MtlsSecurityContext, ParsedX509Certificate, PkiTrustStore, PkiValidationError};
pub use oblivious_transfer::{GarbledCircuit, ObliviousTransferEngine, OtBlock, OtReceiverQuery, OtSenderResponse, OtSenderSetup};
pub use plonk_upookup_tables::{LookupTable, MultiplicityVector, PlookupEngine, PlookupProof, WitnessQueryColumn};
pub use post_quantum::{HybridCiphertext, HybridPublicKey, HybridSecretKey, PostQuantumHybridEngine};
pub use quantum_kyber_pke::{MlKem768Engine, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, RingPolynomial};
pub use rate_limiter::{RateLimitPolicy, RateLimiter};
pub use rate_limiter_distributed::{GcraRateLimiter, RateLimitTier};
pub use replay_guard::{ReplayGuard, ReplayGuardConfig};
pub use safe_memory_allocator::{MemoryProtectionPolicy, SafeMemoryBuffer, SecureCell};
pub use sanctions_bloom_filter::{SanctionsBloomFilter, SanctionsCheckResult};
pub use seccomp_sandbox::{SeccompPolicy, SeccompSandbox, SeccompStatusReport};
pub use side_channel_defenses::{ObliviousTable, SafeScalar32, SideChannelShield};
pub use side_channel_spectre_shield::{CacheAlignedSecret, ObliviousSboxTable, SpectreShield};
pub use strict_headers::StrictSecurityHeaders;
pub use tamper_guard::{TamperCheckReport, TamperGuard};
pub use threshold_decryption_rsa_bls::{DecryptionKeyShare, DecryptionShare, DleqProof, ThresholdDecryptedResult, ThresholdDecryptionEngine};
pub use threshold_key_derivation_hkdf::{DerivationStepShare, DerivedSubkey, DhkdfNodeShare, DistributedHkdfEngine};
pub use threshold_mpc_signing::{AggregatedThresholdSignature, FeldmanCommitment, FrostCoordinator, KeyShare, PartialSignature, Round1Commitment, ThresholdScalar};
pub use threshold_oblivious_prf::{ObliviousPrfEngine, OprfBlindQuery, OprfEvaluatedResponse, OprfOutputKey, OprfServerKey};
pub use timing_shield::TimingShield;
pub use tls_session_ticket_armor::{SealedSessionTicket, StekKeyEntry, TlsSessionTicketArmor};
pub use w3c_sd_jwt_vc::{SaltedDisclosure, SdJwtCredential, SdJwtEngine, SdJwtPresentation, SdJwtVerificationResult};
pub use wasm_enclave_sandbox::{WasmEnclaveSandbox, WasmExecutionReceipt, WasmLinearMemory, WasmOpcode, WasmSandboxError, WasmStateSnapshot};
pub use zero_knowledge_audit_trail::{AuditLogBlock, AuditVerificationReceipt, ForwardSecureAuditTrail};
pub use zero_knowledge_revocation::{AccumulatorCommitment, AccumulatorElement, DynamicRevocationAccumulator, NonMembershipWitness as RevocationNonMembershipWitness};
pub use zero_leakage_sanctions_engine::{BlindedCuckooFilter, BlindedSanctionsQuery, OracleSanctionsResponse, SanctionsNonMembershipReceipt, ZeroLeakageSanctionsEngine};
pub use zk_anonymous_credential_issuer::{BbsPlusEngine, BbsPlusProofOfKnowledge, BbsPlusPublicKey, BbsPlusSecretKey, BbsPlusSignature};
pub use zk_attestation_pki_bridge::{DistinguishedNameAttribute, ParsedZkX509Certificate, ZkPkiAttestationReceipt, ZkPkiBridgeEngine};
pub use zk_confidential_credit_score::{ConfidentialCreditEngine, ConfidentialCreditReceipt, ConfidentialFinancialWitness, FinancialCommitmentBundle, SolvencyPolicy};
pub use zk_dos_shield::{PowChallenge, PowSolution, ZkDosShield};
pub use zk_membership_merkle_accumulator::{SmtMembershipProof, SmtProofStep, SparseMerkleTree256};
pub use zk_rate_limiter_anonymous::{RlnIdentitySecret, RlnManager, RlnProofShare, SlashedIdentityEvidence};
pub use zk_rollup_batcher::{RollupBatchReceipt, RollupBlockHeader, RollupStateDiff, RollupVerificationTx, ZkRollupBatcher};
pub use zk_sanctions_fuzzy_trie::{FuzzyMatchReceipt, FuzzyNameMatchingEngine, FuzzyTrieNode};
pub use zk_verifiable_shuffle::{ShuffleCiphertext, VerifiableShuffleEngine, VerifiableShuffleProof};

// Ultra-Hardened Tier 2 Security Exports
pub use fhe_bfv_ckks::{BfvContext, BlindedIdentityAttributeAggregator, FheCiphertext, FhePublicKey, FheRelinearizationKey, FheSecretKey};
pub use zkvm_jit_armor::{ControlFlowIntegrityTable, HardenedZkvmSandbox, ZkOpcode, ZkvmExecutionTrace, ZkvmTraceVerifier};
pub use threshold_bls_aggregation::{AggregatedBlsSignature, BlsG1Point, BlsG2Point, BlsScalar, BlsSignatureShare, BlsThresholdAggregator, ProofOfPossession};
pub use verifiable_delay_function::{TimedCredentialEscrow, VdfConfig, VdfProof, WesolowskiVdf};
pub use stark_fri_engine::{FriCommitmentLayer, GoldilocksField, StarkFriEngine, StarkFriProof};
pub use oblivious_keyword_search::{BlindedSearchTrapdoor, EncryptedIndexEntry, SearchableSymmetricVault};
pub use falcon_fips206::{FalconEngine, FalconPolynomial, FalconPublicKey, FalconSecretKey, FalconSignature};
pub use w3c_did_vp_engine::{DidDocument, PresentationProof, VerifiableCredentialItem, VerifiablePresentation, W3cDidEngine};
pub use bulletproofs_plus_range::{AggregateRangeProof, BulletproofsPlusEngine, BulletproofsPlusProof, PedersenCommitment};
pub use pkcs11_session_armor::{HsmKeyClass, HsmSlotState, Pkcs11SessionArmor};
pub use homomorphic_secret_sharing::{DpfCorrectionWord, DpfKeyShare, HomomorphicSecretSharingEngine};
pub use confidential_query_guard::{ConfidentialQueryGuard, SafeParameterizedQuery, SafeSqlToken};
pub use dynamic_vector_accumulator::{DynamicAccumulatorState, DynamicNonMembershipWitness, DynamicVectorAccumulator};
pub use zk_cross_chain_relayer::{EvmBlockHeaderCommitment, MptNodeType, MptProofStep, ZkCrossChainIdentityReceipt, ZkCrossChainRelayer};
pub use ring_signatures_clsag::{ClsagEngine, ClsagKeyImage, ClsagRingSignature, RingMemberPublicKey};
pub use oprf_blind_tokens::{BlindedTokenRequest, EvaluatedTokenResponse, OprfBlindTokenEngine, UnblindedRedemptionToken};
pub use zk_kyc_compliance_matrix::{CompliancePolicyRule, ConfidentialComplianceWitness, JurisdictionCode, ZkComplianceReceipt, ZkKycComplianceMatrix};
pub use kernel_memory_armor::{AslrEntropyReport, GuardedMemoryAllocation, KernelMemoryArmor, PageProtectionStatus};
pub use zk_plonk_hypercube::{HypercubeSumcheckEngine, MultilinearExtension, SumcheckProof, SumcheckRoundMessage};
pub use threshold_oblivious_transfer_psi::{BlindedPsiElement, PsiPolynomialCommitment, PsiQueryRequest, PsiQueryResponse, ThresholdPsiEngine};
pub use zk_plonk_fri_composer::{PlonkFriComposer, PlonkFriCompositeProof, PlonkGateConstraint};
pub use blind_zk_threshold_credentials::{AnonymousMasterCredential, AnonymousPresentationProof, AuthoritySignatureShare, BlindThresholdCredentialsEngine, BlindedCredentialIssuanceRequest};
pub use zk_confidential_state_channels::{ChannelDisputeProof, ChannelState, ChannelStateUpdate, ConfidentialStateChannel};
pub use zk_fuzzy_commitment_biometrics::{FuzzyBiometricCommitment, FuzzyCommitmentEngine, FuzzyUnlockResult};
pub use zk_adaptive_threat_response::{AdaptiveThreatConfig, AdaptiveThreatEngine, SecurityAnomalyEvent, ThreatSeverityLevel};

// Ultra-Hardened Tier 3 Security Exports
pub use asynchronous_vss_dkg::{AsynchronousVssEngine, AvssEchoVote, AvssFieldElement, AvssReadyCertificate, AvssSendProposal, BivariatePolynomial};
pub use encrypted_identity_graph::{EncryptedGraphNode, EncryptedIdentityGraph, ZkGraphReachabilityProof, ZkPathStepWitness};
pub use plonkish_custom_gate_matrix::{CustomGateExpression, PlonkishCell, PlonkishMatrix};
pub use verifiable_random_function_ecvrf::{EcvrfEngine, EcvrfOutput, EcvrfProof};
pub use sphincs_plus_fips205::{ForsSignature, SphincsEngine, SphincsPublicKey, SphincsSecretKey, SphincsSignature, WotsLeaf};
pub use psi_cardinality_paillier::{PsiCaItem, PsiCaQuery, PsiCaResult, PsiCardinalityPaillierEngine};
pub use zk_fair_lottery_shuffle::{FairLotteryShuffleEngine, NeffShuffleProof, ShuffleElGamalCiphertext};
pub use enclave_key_sealing::{EnclaveKeySealingEngine, EnclaveSealingPolicy, SealedHardwarePayload};
pub use homomorphic_inner_product_argument::{HomomorphicIpaEngine, IpaFoldingStep, IpaProof};
pub use zk_graph_sanitization::{GraphSanitizationEngine, GraphSanitizationPolicy, GraphSanitizationReceipt, SanitizedGraphEdge};
pub use zk_verifiable_shuffle_prover::{ElGamalPair, PermutationMatrixCommitment, VerifiableShuffleArgument, VerifiableShuffleProver};
pub use threshold_key_recovery_engine::{GuardianKeyShare, KeyRecoveryResult, ThresholdKeyRecoveryEngine};
pub use differential_privacy_advanced::{AdvancedDpEngine, DpMechanismKind, DpQueryRecord, PrivacyBudgetLedger};
pub use homomorphic_vector_commitments::{SubvectorOpeningProof, VectorCommitment, VectorCommitmentEngine, VectorPositionOpening};
pub use musig2_schnorr_threshold::{AggregatedMusig2PublicKey, Musig2Engine, Musig2FinalSignature, Musig2PartialSignature, Musig2PublicNonce, Musig2SecretNonce};
pub use enclave_protected_channel::{EnclaveProtectedChannel, EnclaveSecureSession, NoiseHandshakeMessage, NoiseHandshakeState};
pub use path_oram_memory_engine::{OramBlock, OramBucket, PathOramEngine};
pub use plonkish_logup_multi_table::{LogupEngine, LogupFractionalTerm, LogupProof, LogupTable};
pub use single_server_private_information_retrieval::{PirQueryVector, PirResponsePayload, SingleServerPirEngine};
pub use zk_compliance_decision_tree::{ComplianceDecisionTree, DecisionBranchWitness, TreeNodeKind, ZkDecisionTreeProof};

// Ultra-Hardened Tier 4 Security Exports
pub use smt_circuit_solver_bridge::{SmtCircuitBridge, SmtLinearTerm, SmtR1csConstraint, SmtVerificationReport, SmtWireVar};
pub use threshold_schnorr_blind_sig::{BlindedSchnorrRequest, PartialBlindSchnorrSignature, ThresholdSchnorrBlindEngine, UnblindedSchnorrSignature};
pub use zk_attribute_based_encryption::{CpAbeCiphertext, CpAbeEngine, PolicyTreeNode, UserAttributeKeyBundle, ZkPolicySatisfactionProof};
pub use blake3_incremental_streaming_tree::{Blake3StreamingTree, StreamingInclusionProof, StreamingTreeNode};
pub use zk_multiset_hash_accumulator::{MSET_FIELD_PRIME, MultisetAccumulator, MultisetEqualityProof, MultisetHashEngine};
pub use dice_hardware_identity_pki::{DiceCertificateLayer, DiceHardwareChain, DiceHardwareEngine};

// Ultra-Hardened Tier 5 Security Exports
pub use zk_batch_shuffle_verifier::{BatchShuffleOpening, BatchShuffleVerifier};
pub use confidential_calldata_evm::{EvmCalldataEncoder, Groth16EvmCalldata};
pub use proactive_secret_sharing::{ProactiveRenewedShare, ProactiveSecretSharingEngine, PssSubshareUpdate};
pub use verifiable_credential_federation::{CredentialFederationEngine, FederatedBridgeProof, FederatedTrustAnchor};
pub use pq_session_key_exchange::{HybridClientInitiation, HybridServerResponse, PqSessionContext, PqSessionKeyExchangeEngine};

// Ultra-Hardened Tier 6 Security Exports
pub use zk_confidential_ot_extension::{BaseOtKeyPair, EvaluatedExtendedOtBatch, OtExtensionColumnMessage, OtExtensionEngine};
pub use hardware_tee_keystore::{HardwareTeeKeystore, HardwareTeeType, TeeAttestationReport, TeeKeySlot};
pub use zk_plonk_hyperplonk_prover::{HyperplonkProof, HyperplonkProverEngine, MultilinearSelectorCommitments};





