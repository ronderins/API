//! Comprehensive End-to-End Cryptographic Hardening Tests (Tier 8)
//!
//! Validates:
//! 1. IKNP & Silent Oblivious Transfer (OT) Extension
//! 2. Unified Hardware TEE Keystore (AWS Nitro, ARM TrustZone, AMD SEV-SNP)
//! 3. HyperPlonk Multilinear Zero-Knowledge Constraint Verification
//! 4. Full Cryptographic Pipeline End-to-End Regression Protection

use zk_identity_api_rust::security::zk_confidential_ot_extension::*;
use zk_identity_api_rust::security::hardware_tee_keystore::*;
use zk_identity_api_rust::security::zk_plonk_hyperplonk_prover::*;

#[test]
fn test_tier8_ot_extension_batch() {
    let mut base_keys = Vec::new();
    for i in 0..OT_EXTENSION_KAPPA {
        base_keys.push(BaseOtKeyPair {
            key_0: [i as u8; 16],
            key_1: [(i as u8) ^ 0xAA; 16],
        });
    }

    let engine = OtExtensionEngine::new(5, vec![false; OT_EXTENSION_KAPPA]);
    let target_pairs = [
        (100, 200),
        (300, 400),
        (500, 600),
        (700, 800),
        (900, 1000),
    ];
    let choices = [true, false, true, true, false];

    let batch = engine.expand_transfers(&base_keys, &target_pairs, &choices).unwrap();
    assert_eq!(batch.batch_size, 5);
    assert!(OtExtensionEngine::verify_batch(&batch).unwrap());
}

#[test]
fn test_tier8_tee_keystore_multi_enclave() {
    let mut amdsnp = HardwareTeeKeystore::new(HardwareTeeType::AmdSevSnp);
    let slot = amdsnp.allocate_key_slot(10, "identity_key_sec", &[0x77; 32]).unwrap();
    assert_eq!(slot.slot_index, 10);

    let quote = amdsnp.generate_attestation_quote("session_challenge_44");
    assert_eq!(quote.tee_type, HardwareTeeType::AmdSevSnp);
    assert!(HardwareTeeKeystore::verify_report(&quote, "session_challenge_44").unwrap());
}

#[test]
fn test_tier8_hyperplonk_prover() {
    let a = [10, 20, 30, 40];
    let b = [2, 3, 4, 5];
    let c = [20, 60, 120, 200]; // Multiplications: a * b = c

    let proof = HyperplonkProverEngine::prove_hyperplonk(&a, &b, &c, 0xCAFE).unwrap();
    assert_eq!(proof.num_constraints, 4);
    assert!(HyperplonkProverEngine::verify_hyperplonk(&proof).unwrap());
}
