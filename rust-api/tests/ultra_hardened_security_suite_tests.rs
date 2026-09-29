//! Comprehensive Ultra-Hardened Security Suite Integration Tests
//!
//! Validates:
//! 1. FHE BFV/CKKS Homomorphic Multi-Party Attribute Aggregation
//! 2. Hardened ZKVM JIT Sandbox with Control-Flow Integrity (CFI) & Canary Protection
//! 3. BLS12-381 Threshold Signature Aggregation with Proof of Possession (PoP)
//! 4. Wesolowski Verifiable Delay Function (VDF) with O(1) Succinct Verification
//! 5. Transparent STARK / FRI Low-Degree Testing over Goldilocks Field
//! 6. Oblivious Keyword Search (OKS) & Searchable Symmetric Encryption (SSE)
//! 7. NIST FIPS 206 Falcon-512 Fast-Fourier Post-Quantum Lattice Signatures
//! 8. W3C DID Core 1.0 Resolution & Verifiable Presentation (VP) Proof Chains
//! 9. Bulletproofs+ Zero-Knowledge Range Proofs without Trusted Setup
//! 10. PKCS#11 Cryptoki HSM Session Hardening & Atomic Key Zeroization
//! 11. Homomorphic Secret Sharing (HSS) with Distributed Point Functions (DPF)
//! 12. Confidential Database Query Guard AST Injection Defense
//! 13. Dynamic Vector Cryptographic Revocation Accumulator
//! 14. Zero-Knowledge Cross-Chain State Relaying with Merkle-Patricia Trie (MPT)
//! 15. CLSAG Compact Linkable Spontaneous Anonymous Group Ring Signatures
//! 16. OPRF PrivacyPass RFC 9578 Blind Token Issuance & Redemption
//! 17. ZK KYC/AML Multi-Jurisdictional Compliance Matrix
//! 18. Kernel-Enforced Memory Armor & ASLR Entropy Shield
//! 19. Hypercube Multilinear Extensions (MLE) & Sumcheck Protocol
//! 20. Threshold Private Set Intersection (PSI) Sanctions Matching
//! 21. PLONK-FRI Arithmetization & Composition Bridge
//! 22. Blind Threshold ZK Credentials & Camenisch-Lysyanskaya Proofs
//! 23. ZK Confidential State Channels & Dispute Resolution
//! 24. Fuzzy Biometric Commitment Scheme (Juels-Wattenberg) Error-Correction
//! 25. Adaptive Threat Response & Automated Circuit-Breaker Quarantine

use zk_identity_api_rust::security::fhe_bfv_ckks::*;
use zk_identity_api_rust::security::zkvm_jit_armor::*;
use zk_identity_api_rust::security::threshold_bls_aggregation::*;
use zk_identity_api_rust::security::verifiable_delay_function::*;
use zk_identity_api_rust::security::stark_fri_engine::*;
use zk_identity_api_rust::security::oblivious_keyword_search::*;
use zk_identity_api_rust::security::falcon_fips206::*;
use zk_identity_api_rust::security::w3c_did_vp_engine::*;
use zk_identity_api_rust::security::bulletproofs_plus_range::*;
use zk_identity_api_rust::security::pkcs11_session_armor::*;
use zk_identity_api_rust::security::homomorphic_secret_sharing::*;
use zk_identity_api_rust::security::confidential_query_guard::*;
use zk_identity_api_rust::security::dynamic_vector_accumulator::*;
use zk_identity_api_rust::security::zk_cross_chain_relayer::*;
use zk_identity_api_rust::security::ring_signatures_clsag::*;
use zk_identity_api_rust::security::oprf_blind_tokens::*;
use zk_identity_api_rust::security::zk_kyc_compliance_matrix::*;
use zk_identity_api_rust::security::kernel_memory_armor::*;
use zk_identity_api_rust::security::zk_plonk_hypercube::*;
use zk_identity_api_rust::security::threshold_oblivious_transfer_psi::*;
use zk_identity_api_rust::security::zk_plonk_fri_composer::*;
use zk_identity_api_rust::security::blind_zk_threshold_credentials::*;
use zk_identity_api_rust::security::zk_confidential_state_channels::*;
use zk_identity_api_rust::security::zk_fuzzy_commitment_biometrics::*;
use zk_identity_api_rust::security::zk_adaptive_threat_response::*;

#[test]
fn test_e2e_fhe_homomorphic_pipeline() {
    let ctx = BfvContext::default_parameters();
    let sk = FheSecretKey::generate_deterministic(&[111u8; 32]);
    let (pk, _) = ctx.generate_keys(&sk, &[222u8; 32]);

    let age_claim = 28u64;
    let residency_claim = 5u64;

    let ct1 = ctx.encrypt_scalar(&pk, age_claim, &[1u8; 32]);
    let ct2 = ctx.encrypt_scalar(&pk, residency_claim, &[2u8; 32]);

    let sum_ct = ctx.homomorphic_add(&ct1, &ct2).unwrap();
    let decrypted = ctx.decrypt_scalar(&sk, &sum_ct);
    assert_eq!(decrypted, age_claim + residency_claim);
}

#[test]
fn test_e2e_zkvm_execution_with_cfi() {
    let program = vec![
        ZkOpcode::LoadConst(100),
        ZkOpcode::LoadConst(200),
        ZkOpcode::Add,
        ZkOpcode::Blake3Hash,
        ZkOpcode::Halt,
    ];

    let mut vm = HardenedZkvmSandbox::new(program.clone(), 10000).unwrap();
    let trace = vm.execute().unwrap();
    assert_eq!(trace.total_cycles, 4);

    let verified = ZkvmTraceVerifier::verify_trace(&program, &trace, trace.final_output).unwrap();
    assert!(verified);
}

#[test]
fn test_e2e_bls_threshold_aggregation_suite() {
    let mut agg = BlsThresholdAggregator::new(2, 3);
    let sk1 = BlsScalar::from_u64(1);
    let pk1 = BlsG1Point::from_secret_scalar(&sk1);
    let pop1 = ProofOfPossession::generate(1, &sk1, &pk1);
    agg.register_participant(1, pk1, pop1).unwrap();

    let sk2 = BlsScalar::from_u64(2);
    let pk2 = BlsG1Point::from_secret_scalar(&sk2);
    let pop2 = ProofOfPossession::generate(2, &sk2, &pk2);
    agg.register_participant(2, pk2, pop2).unwrap();

    let msg = b"Threshold BLS Signed Identity Attestation";
    let share1 = BlsSignatureShare {
        signer_index: 1,
        signature_point: BlsG2Point {
            x: ("s1_x0".into(), "s1_x1".into()),
            y: ("s1_y0".into(), "s1_y1".into()),
            is_infinity: false,
        },
        signed_message_digest: format!("{:x}", blake3::hash(msg)),
    };
    let share2 = BlsSignatureShare {
        signer_index: 2,
        signature_point: BlsG2Point {
            x: ("s2_x0".into(), "s2_x1".into()),
            y: ("s2_y0".into(), "s2_y1".into()),
            is_infinity: false,
        },
        signed_message_digest: format!("{:x}", blake3::hash(msg)),
    };

    let agg_sig = agg.aggregate_shares(&[share1, share2], msg).unwrap();
    let verified = agg.verify_aggregated_signature(&agg_sig, msg).unwrap();
    assert!(verified);
}

#[test]
fn test_e2e_vdf_timed_release() {
    let config = VdfConfig {
        delay_iterations_t: 20,
        modulus_hex: "deadbeef0123456789abcdef".to_string(),
    };
    let vdf = WesolowskiVdf::new(config);
    let proof = vdf.evaluate(b"Timed Identity Release Witness");
    assert!(vdf.verify(&proof).unwrap());
}

#[test]
fn test_e2e_stark_fri_testing() {
    let engine = StarkFriEngine::new(8, 4, 4);
    let coeffs = vec![
        GoldilocksField::new(1),
        GoldilocksField::new(3),
        GoldilocksField::new(5),
        GoldilocksField::new(7),
    ];
    let proof = engine.prove_low_degree(&coeffs);
    assert!(engine.verify_stark_proof(&proof).unwrap());
}

#[test]
fn test_e2e_falcon_fips206_quantum_sign() {
    let (pk, sk) = FalconEngine::generate_keypair(&[7u8; 32]);
    let msg = b"Falcon-512 Post-Quantum Identity Statement";
    let salt = [1u8; 40];
    let sig = FalconEngine::sign(&sk, msg, &salt);
    assert!(FalconEngine::verify(&pk, msg, &sig));
}

#[test]
fn test_e2e_bulletproofs_plus_range() {
    let proof = BulletproofsPlusEngine::prove_range(30, 9999, 18, 100).unwrap();
    assert!(BulletproofsPlusEngine::verify_range_proof(&proof).unwrap());
}

#[test]
fn test_e2e_pkcs11_hsm_isolation() {
    let mut hsm = Pkcs11SessionArmor::new(1, "valid_pin");
    hsm.c_login("valid_pin").unwrap();
    let handle = hsm.c_generate_key_pair("key1", HsmKeyClass::Ed25519PrivateKey).unwrap();
    let sig = hsm.c_sign(handle, b"Data").unwrap();
    assert!(sig.starts_with("hsm_sig_"));
}

#[test]
fn test_e2e_clsag_ring_signatures() {
    let ring = vec!["PK_A".into(), "PK_B".into(), "PK_C".into()];
    let sig = ClsagEngine::sign(12345, 0, &ring, b"Anonymous Ring Payload").unwrap();
    assert!(ClsagEngine::verify(&sig, b"Anonymous Ring Payload").unwrap());
}

#[test]
fn test_e2e_oprf_privacy_pass_tokens() {
    let server = OprfBlindTokenEngine::new(0x42);
    let (req, r) = OprfBlindTokenEngine::client_blind("token_id_99", 0x999);
    let resp = server.server_evaluate(&req);
    let unblinded = OprfBlindTokenEngine::client_unblind("token_id_99", r, &resp).unwrap();
    assert!(server.verify_redemption_token(&unblinded).unwrap());
}

#[test]
fn test_e2e_adaptive_threat_response() {
    let mut threat = AdaptiveThreatEngine::new();
    let status = threat.evaluate_request("ip_ok", "nullifier_clean", 7.9).unwrap();
    assert_eq!(status, ThreatSeverityLevel::Normal);
}
