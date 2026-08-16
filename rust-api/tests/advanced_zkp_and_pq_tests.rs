//! Advanced Cryptographic, Recursive Folding, Biometric, and Post-Quantum Tests

use zk_identity_microservice::circuits::biometric_embedding::{BiometricCircuit, BiometricWitnessVector, EnrolledTemplateCommitment};
use zk_identity_microservice::circuits::recursive_folding::{RecursiveFoldingScheme, RelaxedR1csInstance};
use zk_identity_microservice::crypto_core::pq_hybrid::PqHybridEngine;
use zk_identity_microservice::crypto_core::vss_threshold::FeldmanVssEngine;
use zk_identity_microservice::identity::w3c_vc::{W3cVerifiableCredential, W3cVcEngine};
use zk_identity_microservice::wasm::webgpu_prover::WebGpuProver;
use std::collections::HashMap;

#[test]
fn test_feldman_vss_split_and_reconstruction() {
    let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let (commitment, shares) = FeldmanVssEngine::split_secret(secret, 3, 5).expect("VSS split failed");

    assert_eq!(commitment.threshold, 3);
    assert_eq!(commitment.total_shares, 5);
    assert_eq!(shares.len(), 5);

    // Verify all individual shares
    for share in &shares {
        assert!(FeldmanVssEngine::verify_share(share, &commitment));
    }

    // Reconstruct with exactly threshold shares
    let reconstructed = FeldmanVssEngine::reconstruct_secret(&shares[0..3], 3).expect("Reconstruction failed");
    assert!(!reconstructed.is_empty());
}

#[test]
fn test_recursive_folding_scheme() {
    let acc = RelaxedR1csInstance {
        commitment_w: "3a8f9c1b2e5d7a4f6c8b0e2d4a6f8b0e2d4a6f8b0e2d4a6f8b0e2d4a6f8b0e2d".to_string(),
        commitment_e: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        scalar_u: "0x1".to_string(),
        public_inputs_x: vec!["18".to_string(), "2026".to_string()],
    };

    let new_inst = RelaxedR1csInstance {
        commitment_w: "7c1b4e9f0a2d5e8b3c6f9a1d4e7b0c3f6a9d2e5b8c1f4a7d0e3b6f9a2c5e8b1d".to_string(),
        commitment_e: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        scalar_u: "0x1".to_string(),
        public_inputs_x: vec!["21".to_string(), "2026".to_string()],
    };

    let receipt = RecursiveFoldingScheme::fold_step(&acc, &new_inst, 1);
    assert!(receipt.is_valid);
    assert_eq!(receipt.folding_step, 2);
    assert!(RecursiveFoldingScheme::verify_folded_accumulator(&receipt));
}

#[test]
fn test_biometric_embedding_circuit() {
    // 8-dimensional test vector in 2^16 fixed point
    let scale = BiometricCircuit::SCALE_FACTOR;
    let live_vec = BiometricWitnessVector {
        vector_fp: vec![scale, 2 * scale, scale / 2, scale, scale, scale, scale, scale],
        user_id_digest: "usr-alice-digest".to_string(),
        salt: "salt-bio-123".to_string(),
    };

    let enrolled_vec = vec![scale, 2 * scale, scale / 2, scale + 100, scale, scale, scale, scale];
    let commitment = EnrolledTemplateCommitment {
        template_root: "0x98f7e6d5c4b3a201...".to_string(),
        dimension: 8,
        distance_threshold_scaled: 50000,
    };

    let result = BiometricCircuit::evaluate_match(&live_vec, &enrolled_vec, &commitment)
        .expect("Biometric circuit failed");

    assert!(result.matched);
    assert!(!result.nullifier_hash.is_empty());
}

#[test]
fn test_w3c_vc_engine() {
    let mut subject = HashMap::new();
    subject.insert("id".to_string(), serde_json::json!("did:zk:123456789abcdef"));
    subject.insert("age_over_21".to_string(), serde_json::json!(true));
    subject.insert("birth_year".to_string(), serde_json::json!(2000));

    let vc = W3cVerifiableCredential {
        context: vec!["https://www.w3.org/ns/credentials/v2".to_string()],
        id: "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_string(),
        vc_type: vec!["VerifiableCredential".to_string(), "AgeAttestationCredential".to_string()],
        issuer: "did:web:auth.zk-id.internal".to_string(),
        valid_from: "2026-01-01T00:00:00Z".to_string(),
        valid_until: Some("2028-01-01T00:00:00Z".to_string()),
        credential_subject: subject,
        proof: None,
    };

    let is_valid = W3cVcEngine::evaluate_age_predicate(&vc, 21).expect("Predicate evaluation failed");
    assert!(is_valid);
}

#[test]
fn test_post_quantum_hybrid_signatures() {
    let doc_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let classical_secret = b"classical-ed25519-secret-seed-1234";
    let pq_seed = b"nist-mldsa-65-quantum-seed-5678";

    let (pk, sig) = PqHybridEngine::sign_hybrid_identity(doc_hash, classical_secret, pq_seed)
        .expect("Signing hybrid identity failed");

    assert!(PqHybridEngine::verify_hybrid_identity(doc_hash, &pk, &sig));
}

#[test]
fn test_webgpu_prover_shaders_and_benchmarks() {
    let shader = WebGpuProver::get_bn254_msm_wgsl_shader();
    assert!(shader.contains("msm_bucket_accumulate"));

    let bench = WebGpuProver::benchmark_estimated_speedup(65536);
    assert!(bench.speedup_factor > 5.0);
}
