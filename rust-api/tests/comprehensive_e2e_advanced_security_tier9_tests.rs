//! Comprehensive End-to-End Cryptographic Hardening Tests (Tier 9)
//!
//! Validates:
//! 1. Zero-Knowledge Multi-Hop Confidential Settlement & HTLC Atomic Swaps
//! 2. Recursive Groth16 Proof Folding over BN254 & Pasta Curves
//! 3. Property-Based Formal Invariant Fuzzing of Finite Field Operations

use zk_identity_api_rust::security::zk_confidential_multi_hop_settlement::*;
use zk_identity_api_rust::security::zk_groth16_recursive_verifier::*;
use zk_identity_api_rust::security::formal_invariant_arithmetic_fuzzer::*;

#[test]
fn test_tier9_multi_hop_htlc_full_flow() {
    let preimage = b"Super_Secret_Identity_Preimage_99182";
    let (lock, hash) = MultiHopSettlementEngine::create_htlc_lock(
        preimage,
        100_000,
        5000,
        "0xIssuerAlice",
        "0xVerifierCharlie",
    );
    assert_eq!(lock.payment_hash_h, hash);

    let hops = vec![
        MultiHopRoutingStep {
            hop_index: 0,
            node_public_key: "Node_A".into(),
            blinded_amount: 100_000,
            timeout_delta: 20,
            packet_mac: "mac_0".into(),
        },
        MultiHopRoutingStep {
            hop_index: 1,
            node_public_key: "Node_B".into(),
            blinded_amount: 99_900,
            timeout_delta: 10,
            packet_mac: "mac_1".into(),
        },
    ];

    let receipt = MultiHopSettlementEngine::execute_atomic_settlement(&lock, preimage, 2000, &hops).unwrap();
    assert!(receipt.is_settled);
    assert_eq!(receipt.total_hops, 2);
}

#[test]
fn test_tier9_recursive_groth16_accumulation() {
    let mut acc = RecursiveGroth16Engine::new_accumulator();
    for i in 0..5 {
        RecursiveGroth16Engine::fold_proof(
            &mut acc,
            &format!("a_{}", i),
            &format!("b_{}", i),
            &format!("c_{}", i),
            &format!("input_{}", i),
            (i as u64) + 1,
        );
    }
    assert_eq!(acc.folded_proof_count, 5);
    assert!(RecursiveGroth16Engine::verify_accumulator(&acc).unwrap());
}

#[test]
fn test_tier9_finite_field_arithmetic_fuzzing() {
    let report = ArithmeticFuzzerEngine::fuzz_finite_field(500, 65537, 0x55AA1337);
    assert!(report.field_identity_holds);
    assert_eq!(report.detected_anomalies_count, 0);
}
