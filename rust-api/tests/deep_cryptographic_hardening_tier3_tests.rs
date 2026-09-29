//! Deep Cryptographic Hardening & Advanced Security Suite Integration Tests (Tier 3)
//!
//! Validates:
//! 1. Asynchronous Verifiable Secret Sharing (AVSS) Bivariate Consistency
//! 2. Encrypted Identity Graph Path Reachability & Hop Constraints
//! 3. PlonKish Custom Gate Matrix & 16-bit Range Synthesizer
//! 4. EC-VRF IETF RFC 9381 Evaluation & Proof Verification
//! 5. NIST FIPS 205 (SLH-DSA / SPHINCS+) Stateless Post-Quantum Signatures
//! 6. PSI-CA with Paillier Homomorphic Sums on Risk Penalty Vectors
//! 7. Neff Verifiable Shuffle Argument & Permutation Invariance
//! 8. Hardware-Enforced Enclave Key Sealing (MRENCLAVE / MRSIGNER)
//! 9. Homomorphic Vector Inner-Product Arguments (IPA) Logarithmic Verification
//! 10. ZK Graph Sanitization & Differential Privacy Degree Distribution Bounds

use zk_identity_api_rust::security::asynchronous_vss_dkg::*;
use zk_identity_api_rust::security::encrypted_identity_graph::*;
use zk_identity_api_rust::security::plonkish_custom_gate_matrix::*;
use zk_identity_api_rust::security::verifiable_random_function_ecvrf::*;
use zk_identity_api_rust::security::sphincs_plus_fips205::*;
use zk_identity_api_rust::security::psi_cardinality_paillier::*;
use zk_identity_api_rust::security::zk_fair_lottery_shuffle::*;
use zk_identity_api_rust::security::enclave_key_sealing::*;
use zk_identity_api_rust::security::homomorphic_inner_product_argument::*;
use zk_identity_api_rust::security::zk_graph_sanitization::*;

#[test]
fn test_tier3_avss_bivariate_cross_verification() {
    let engine = AsynchronousVssEngine::new(7); // t = 2 (7 nodes)
    let seed = [0x99u8; 32];
    let secret = 4242;

    let proposals = engine.dealer_disperse("avss_cohort_alpha", 0, secret, &seed);
    assert_eq!(proposals.len(), 7);

    // Cross-point equality: F(3, 5) == F(5, 3)
    let pt_3_5 = engine.verify_cross_point(&proposals[2], 5);
    let pt_5_3 = engine.verify_cross_point(&proposals[4], 3);
    assert_eq!(pt_3_5.value, pt_5_3.value);
}

#[test]
fn test_tier3_encrypted_identity_graph_path_validation() {
    let mut graph = EncryptedIdentityGraph::new();

    let node1 = EncryptedGraphNode {
        blinded_node_id: "user_alice_cred".into(),
        encrypted_attribute_digest: "digest_1".into(),
        outgoing_edge_commitments: vec!["edge_1_2".into()],
    };
    let node2 = EncryptedGraphNode {
        blinded_node_id: "trust_intermediary_auditor".into(),
        encrypted_attribute_digest: "digest_2".into(),
        outgoing_edge_commitments: vec!["edge_2_3".into()],
    };
    let node3 = EncryptedGraphNode {
        blinded_node_id: "regulator_fincen".into(),
        encrypted_attribute_digest: "digest_3".into(),
        outgoing_edge_commitments: vec![],
    };

    graph.insert_node(node1);
    graph.insert_node(node2);
    graph.insert_node(node3);

    let path = ["user_alice_cred", "trust_intermediary_auditor", "regulator_fincen"];
    let proof = graph
        .prove_path_reachability("user_alice_cred", "regulator_fincen", &path, 2)
        .unwrap();

    assert_eq!(proof.actual_path_length, 2);
    assert!(graph.verify_reachability(&proof).unwrap());
}

#[test]
fn test_tier3_plonkish_matrix_synthesis() {
    let mut matrix = PlonkishMatrix::new(8);
    matrix.add_range_check_16(0);
    matrix.add_poseidon_sbox_gate(1);

    for row in 0..8 {
        matrix.assign_advice(0, row, (row as u64) * 1000).unwrap();
        matrix.assign_advice(1, row, (row as u64) + 1).unwrap();
    }

    assert!(matrix.verify_custom_gates().unwrap());
}

#[test]
fn test_tier3_ecvrf_unbiased_randomness() {
    let engine = EcvrfEngine::new(0xDEAD_CAFE_BEEF);
    let input = b"Audit Session Validator Epoch 904";

    let output = engine.evaluate_and_prove(input);
    assert!(!output.pseudorandom_output_hash.is_empty());

    let is_valid = EcvrfEngine::verify_proof(&engine.public_key_point, input, &output).unwrap();
    assert!(is_valid);
}

#[test]
fn test_tier3_sphincs_fips205_signature_verification() {
    let (pk, sk) = SphincsEngine::generate_keypair(&[0x42u8; 32]);
    let message = b"Confidential Sovereign Digital Identity Credential #88992";

    let sig = SphincsEngine::sign(&sk, message);
    assert_eq!(sig.hypertree_auth_nodes.len(), SPHINCS_D);

    let valid = SphincsEngine::verify(&pk, message, &sig);
    assert!(valid);
}

#[test]
fn test_tier3_psi_cardinality_paillier_homomorphic_sum() {
    let mut engine = PsiCardinalityPaillierEngine::new();
    engine.add_watchlist_entry("sanction_record_11", 50);
    engine.add_watchlist_entry("sanction_record_22", 75);

    let query = PsiCaQuery {
        query_id: "psi_ca_test_01".into(),
        items: vec![
            PsiCaItem {
                blinded_hash: "sanction_record_11".into(),
                encrypted_payload_ciphertext: "enc_cred_1".into(),
            },
            PsiCaItem {
                blinded_hash: "sanction_record_22".into(),
                encrypted_payload_ciphertext: "enc_cred_2".into(),
            },
            PsiCaItem {
                blinded_hash: "unmatched_clean_client_33".into(),
                encrypted_payload_ciphertext: "enc_cred_3".into(),
            },
        ],
        paillier_public_key_n: "test_n_modulus".into(),
    };

    let res = engine.evaluate_query(&query);
    assert_eq!(res.intersection_cardinality, 2);
    assert!(res.homomorphic_sum_ciphertext.contains("125")); // 50 + 75 = 125
}

#[test]
fn test_tier3_neff_verifiable_shuffle() {
    let ciphertexts = vec![
        ShuffleElGamalCiphertext { c1_hex: "c1_1".into(), c2_hex: "c2_1".into() },
        ShuffleElGamalCiphertext { c1_hex: "c1_2".into(), c2_hex: "c2_2".into() },
        ShuffleElGamalCiphertext { c1_hex: "c1_3".into(), c2_hex: "c2_3".into() },
        ShuffleElGamalCiphertext { c1_hex: "c1_4".into(), c2_hex: "c2_4".into() },
    ];

    let perm = vec![3, 1, 0, 2];
    let r = vec![7, 14, 21, 28];

    let proof = FairLotteryShuffleEngine::shuffle_and_prove(&ciphertexts, &perm, &r).unwrap();
    assert_eq!(proof.batch_size, 4);

    let ok = FairLotteryShuffleEngine::verify_shuffle(&proof).unwrap();
    assert!(ok);
}

#[test]
fn test_tier3_enclave_key_sealing_policies() {
    let engine = EnclaveKeySealingEngine::new(
        "measurement_build_abc",
        "signer_intel_corp_xyz",
        4,
        &[0x12u8; 32],
    );

    let raw_secret = b"Enclave Private Master Key 0xCAFEBABE";
    let nonce = [0x99u8; 16];

    let sealed_measurement = engine.seal_data(
        raw_secret,
        EnclaveSealingPolicy::ExactEnclaveMeasurement,
        &nonce,
    );
    assert!(engine.unseal_data(&sealed_measurement).unwrap());

    let sealed_signer = engine.seal_data(
        raw_secret,
        EnclaveSealingPolicy::EnclaveSignerAuthority,
        &nonce,
    );
    assert!(engine.unseal_data(&sealed_signer).unwrap());
}

#[test]
fn test_tier3_homomorphic_inner_product_argument() {
    let a = [2, 4, 6, 8, 10, 12, 14, 16];
    let b = [1, 1, 1, 1, 1, 1, 1, 1];

    let proof = HomomorphicIpaEngine::prove_inner_product(&a, &b).unwrap();
    assert_eq!(proof.folding_steps.len(), 3);
    assert_eq!(proof.inner_product_claim_c, 72); // sum(2..16) = 72

    assert!(HomomorphicIpaEngine::verify_inner_product(&proof).unwrap());
}

#[test]
fn test_tier3_graph_sanitization_k_anonymity() {
    let policy = GraphSanitizationPolicy {
        min_k_anonymity_degree: 2,
        max_epsilon_budget: 0.8,
        delta_failure_probability: 1e-7,
        laplacian_spectral_bound: 0.4,
    };
    let engine = GraphSanitizationEngine::new(policy);

    let edges = vec![
        SanitizedGraphEdge { source_masked: "N1".into(), target_masked: "N2".into(), noisy_weight: 5 },
        SanitizedGraphEdge { source_masked: "N2".into(), target_masked: "N3".into(), noisy_weight: 5 },
        SanitizedGraphEdge { source_masked: "N3".into(), target_masked: "N4".into(), noisy_weight: 5 },
        SanitizedGraphEdge { source_masked: "N4".into(), target_masked: "N1".into(), noisy_weight: 5 },
    ];

    let cert = engine.evaluate_and_certify("cert_graph_test", &edges, 4).unwrap();
    assert_eq!(cert.evaluated_k_anonymity, 2);
    assert!(cert.spectral_gap_valid);
}
