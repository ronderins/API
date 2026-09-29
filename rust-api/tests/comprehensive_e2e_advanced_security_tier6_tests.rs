//! Comprehensive End-to-End Cryptographic Hardening Tests (Tier 6)
//!
//! Validates:
//! 1. Formal SMT Circuit Solver Bridge & Soundness Proof Emittance
//! 2. Threshold Schnorr Blind Signatures & Unlinkable Credential Issuance
//! 3. Zero-Knowledge CP-ABE Attribute-Based Encryption Policy Trees
//! 4. Blake3 Incremental Streaming Merkle Tree & Peak Merging
//! 5. Multiset Hash Accumulators & Order-Independent Equality
//! 6. TCG DICE Hardware Identity Certificate Chains

use zk_identity_api_rust::security::smt_circuit_solver_bridge::*;
use zk_identity_api_rust::security::threshold_schnorr_blind_sig::*;
use zk_identity_api_rust::security::zk_attribute_based_encryption::*;
use zk_identity_api_rust::security::blake3_incremental_streaming_tree::*;
use zk_identity_api_rust::security::zk_multiset_hash_accumulator::*;
use zk_identity_api_rust::security::dice_hardware_identity_pki::*;

#[test]
fn test_tier6_smt_circuit_verification() {
    let mut bridge = SmtCircuitBridge::new(5, vec![0, 4]);
    // w1 * w2 = w3
    bridge.add_constraint(vec![(1, 1)], vec![(2, 1)], vec![(3, 1)]);
    // w3 + w0 = w4 -> (w3 + w0) * 1 = w4
    bridge.add_constraint(vec![(3, 1), (0, 1)], vec![(0, 0)], vec![(4, 1)]);

    let report = bridge.verify_circuit_soundness();
    assert!(report.is_sound_and_complete);
    assert!(report.smt_lib2_script.contains("(check-sat)"));
}

#[test]
fn test_tier6_threshold_schnorr_blind_signature() {
    let engine = ThresholdSchnorrBlindEngine::new(2, 3);
    let msg = b"Confidential KYC Credential Claim";
    let (req, alpha) = ThresholdSchnorrBlindEngine::blind_message(msg, 0x1234);

    let p1 = ThresholdSchnorrBlindEngine::authority_sign_partial(1, 10, &req, 100);
    let p2 = ThresholdSchnorrBlindEngine::authority_sign_partial(2, 20, &req, 200);

    let unblinded = engine.unblind_and_combine(&[p1, p2], alpha, msg).unwrap();
    assert!(ThresholdSchnorrBlindEngine::verify_signature(&unblinded, "Pub").unwrap());
}

#[test]
fn test_tier6_cp_abe_policy_satisfiability() {
    let policy = PolicyTreeNode::ThresholdGate {
        threshold_k: 1, // OR
        children: vec![
            PolicyTreeNode::AttributeLeaf("Role::Admin".into()),
            PolicyTreeNode::AttributeLeaf("Role::Auditor".into()),
        ],
    };

    let ct = CpAbeEngine::encrypt_under_policy(b"Sensitive Secret", policy, "MasterPK");
    let user_keys = UserAttributeKeyBundle {
        user_id_digest: "alice_id".into(),
        possessed_attributes: vec!["Role::Auditor".into()],
        secret_components: vec![],
    };

    let proof = CpAbeEngine::prove_policy_satisfaction(&ct, &user_keys);
    assert!(proof.is_policy_satisfied);
    assert!(CpAbeEngine::verify_satisfaction_proof(&ct, &proof).unwrap());
}

#[test]
fn test_tier6_blake3_streaming_tree() {
    let mut tree = Blake3StreamingTree::new();
    for i in 0..8 {
        tree.append_chunk(format!("Chunk Data #{}", i).as_bytes());
    }
    assert_eq!(tree.total_chunks_appended, 8);
    let root = tree.get_current_root();
    assert!(!root.is_empty());

    let proof = tree.generate_inclusion_proof(3, b"Chunk Data #3");
    assert!(Blake3StreamingTree::verify_inclusion(&proof).unwrap());
}

#[test]
fn test_tier6_multiset_hash_equality() {
    let a: Vec<&[u8]> = vec![b"Claim A", b"Claim B", b"Claim C"];
    let b: Vec<&[u8]> = vec![b"Claim C", b"Claim A", b"Claim B"];

    let proof = MultisetHashEngine::prove_multiset_equality(&a, &b, 0x9999).unwrap();
    assert!(MultisetHashEngine::verify_equality(&proof));
}

#[test]
fn test_tier6_dice_hardware_pki_chain() {
    let engine = DiceHardwareEngine::new("HSM_Silicon_Model_X");
    let uds = [0x77; 32];
    let stages = [[0x10; 32], [0x20; 32]];

    let chain = engine.build_attested_chain(&uds, &stages);
    assert_eq!(chain.layers.len(), 2);
    assert!(DiceHardwareEngine::verify_chain(&chain).unwrap());
}
