//! Comprehensive End-to-End Cryptographic Hardening Tests (Tier 5)
//!
//! Validates:
//! 1. Verifiable Secret Shuffling with ElGamal & Multi-Exponentiation Proofs
//! 2. Threshold Key Recovery & Shamir-Feldman VSS Reconstruction
//! 3. Advanced Differential Privacy Moments Accountant & Renyi DP
//! 4. Homomorphic Vector Commitments & Subvector Coordinate Openings
//! 5. BIP-327 MuSig2 2-Round Multi-Signatures
//! 6. Enclave Protected Channel (Noise_XX) & Hardware Attestation
//! 7. Path-ORAM (Oblivious RAM) Memory Shield & Tree Re-encryption
//! 8. LogUp Multi-Table Fractional Derivatives Lookup Argument
//! 9. Single-Server Private Information Retrieval (PIR)
//! 10. ZK Compliance Decision Tree & AML Risk Traversal

use zk_identity_api_rust::security::zk_verifiable_shuffle_prover::*;
use zk_identity_api_rust::security::threshold_key_recovery_engine::*;
use zk_identity_api_rust::security::differential_privacy_advanced::*;
use zk_identity_api_rust::security::homomorphic_vector_commitments::*;
use zk_identity_api_rust::security::musig2_schnorr_threshold::*;
use zk_identity_api_rust::security::enclave_protected_channel::*;
use zk_identity_api_rust::security::path_oram_memory_engine::*;
use zk_identity_api_rust::security::plonkish_logup_multi_table::*;
use zk_identity_api_rust::security::single_server_private_information_retrieval::*;
use zk_identity_api_rust::security::zk_compliance_decision_tree::*;

#[test]
fn test_tier5_verifiable_shuffle_argument() {
    let list = vec![
        ElGamalPair { c1_point: "pt1_c1".into(), c2_point: "pt1_c2".into() },
        ElGamalPair { c1_point: "pt2_c1".into(), c2_point: "pt2_c2".into() },
        ElGamalPair { c1_point: "pt3_c1".into(), c2_point: "pt3_c2".into() },
    ];
    let perm = vec![2, 0, 1];
    let r = vec![501, 502, 503];

    let proof = VerifiableShuffleProver::prove_shuffle(&list, &perm, &r).unwrap();
    assert!(VerifiableShuffleProver::verify_shuffle(&proof).unwrap());
}

#[test]
fn test_tier5_threshold_key_recovery() {
    let engine = ThresholdKeyRecoveryEngine::new(2, 3);
    // P(X) = 999 + 5*X mod 65537
    // P(1) = 1004, P(2) = 1009
    let shares = vec![
        GuardianKeyShare {
            guardian_index: 1,
            share_scalar_y: 1004,
            share_commitment_v: "".into(),
            guardian_identity_did: "did:key:g1".into(),
        },
        GuardianKeyShare {
            guardian_index: 2,
            share_scalar_y: 1009,
            share_commitment_v: "".into(),
            guardian_identity_did: "did:key:g2".into(),
        },
    ];

    let res = engine.reconstruct_secret(&shares).unwrap();
    assert!(res.is_successful);
    let expected = format!("{:x}", blake3::hash(&999u64.to_le_bytes()));
    assert_eq!(res.reconstructed_secret_digest.unwrap(), expected);
}

#[test]
fn test_tier5_advanced_dp_moments_accountant() {
    let mut dp = AdvancedDpEngine::new(10.0, 1e-5);
    for i in 0..5 {
        let val = dp.execute_private_query(&format!("q_{}", i), 50.0, 1.0, 3.0, 0.1).unwrap();
        assert!((val - 50.0).abs() < 5.0);
    }
    let ledger = dp.get_budget_ledger();
    assert_eq!(ledger.total_queries_served, 5);
    assert!(!ledger.is_budget_depleted);
}

#[test]
fn test_tier5_homomorphic_vector_commitments() {
    let v = [100, 200, 300, 400];
    let seed = [0x55; 32];
    let cm = VectorCommitmentEngine::commit(&v, &seed);
    let op = VectorCommitmentEngine::open_position(&v, 3, &seed).unwrap();
    assert_eq!(op.claimed_value, 400);
    assert!(VectorCommitmentEngine::verify_position(&cm, &op, &seed).unwrap());
}

#[test]
fn test_tier5_musig2_threshold() {
    let pks = vec!["PK_1".into(), "PK_2".into()];
    let agg = Musig2Engine::aggregate_public_keys(&pks).unwrap();
    let msg = b"BIP-327 Integration Claim";
    let (s1, p1) = Musig2Engine::generate_nonces(0, &[0x33; 32]);
    let (s2, p2) = Musig2Engine::generate_nonces(1, &[0x44; 32]);
    let part1 = Musig2Engine::sign_partial(0, 10, &s1, &agg, msg);
    let part2 = Musig2Engine::sign_partial(1, 20, &s2, &agg, msg);
    let final_sig = Musig2Engine::aggregate_partial_signatures(&[part1, part2], &agg).unwrap();
    assert!(Musig2Engine::verify_signature(&final_sig, msg).unwrap());
}

#[test]
fn test_tier5_enclave_protected_channel() {
    let mut client = EnclaveProtectedChannel::new(1, "");
    let mut enclave = EnclaveProtectedChannel::new(2, "INTEL_SGX_DCAP_QUOTE_OK");
    let m1 = client.send_handshake_1(11);
    let m2 = enclave.respond_handshake_2(&m1, 22).unwrap();
    let sess = client.finalize_handshake_3(&m2).unwrap();
    assert!(sess.peer_hardware_attested);
}

#[test]
fn test_tier5_path_oram_memory() {
    let mut oram = PathOramEngine::new([0x88; 32]);
    let data = b"Confidential Payload 99".to_vec();
    oram.access(10, Some(data.clone()), 2).unwrap();
    let read = oram.access(10, None, 5).unwrap().unwrap();
    assert_eq!(read, data);
}

#[test]
fn test_tier5_logup_multi_table() {
    let mut engine = LogupEngine::new();
    engine.register_table(1, vec![1, 2, 3, 5, 8, 13]);
    let proof = engine.prove_lookups(1, &[1, 2, 3, 3, 8], 998877).unwrap();
    assert!(LogupEngine::verify_logup(&proof).unwrap());
}

#[test]
fn test_tier5_single_server_pir() {
    let records = vec!["PEP_01".into(), "SANCTION_02".into(), "CLEARED_03".into()];
    let pir = SingleServerPirEngine::new(records);
    let q = SingleServerPirEngine::client_generate_query(1, 3, 0x55).unwrap();
    let resp = pir.server_evaluate_query(&q).unwrap();
    let rec = pir.client_decrypt_response(1, &resp).unwrap();
    assert_eq!(rec, "SANCTION_02");
}

#[test]
fn test_tier5_zk_decision_tree() {
    let tree = ComplianceDecisionTree::default_kyc_aml_tree();
    let proof = tree.evaluate_and_prove(&[30, 25_000]).unwrap();
    assert!(proof.reached_leaf_approved);
    assert!(tree.verify_tree_proof(&proof).unwrap());
}
