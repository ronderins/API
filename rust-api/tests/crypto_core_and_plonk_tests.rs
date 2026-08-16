//! Advanced Cryptography Core, PLONK, and Privacy Engine Tests

use zk_identity_microservice::crypto_core::fp12::{Fp12, Fp6};
use zk_identity_microservice::crypto_core::jubjub::JubjubPoint;
use zk_identity_microservice::crypto_core::optimal_ate::OptimalAtePairing;
use zk_identity_microservice::plonk::gates::PlonkGateRow;
use zk_identity_microservice::plonk::kzg::{KzgScheme, KzgSrs};
use zk_identity_microservice::plonk::prover::PlonkProver;
use zk_identity_microservice::plonk::verifier::PlonkVerifier;
use zk_identity_microservice::privacy_engine::blind_signatures::BlindSignatureEngine;
use zk_identity_microservice::privacy_engine::laplace::DifferentialPrivacyEngine;
use zk_identity_microservice::privacy_engine::ring_signatures::RingSignatureEngine;
use zk_identity_microservice::zkp::bn254::{Fp, G1Affine, G2Affine};

#[test]
fn test_fp12_arithmetic_and_squaring() {
    let a = Fp12::one();
    let b = Fp12::one();
    let c = a.mul(&b);
    assert_eq!(c, Fp12::one());
    assert_eq!(c.cyclotomic_square(), Fp12::one());
}

#[test]
fn test_jubjub_curve_addition_and_scalar_mul() {
    let g = JubjubPoint::generator();
    let double_g = g.add(&g);
    let scalar_2_g = g.scalar_mul(2);
    assert_eq!(double_g.u, scalar_2_g.u);
    assert_eq!(double_g.v, scalar_2_g.v);
}

#[test]
fn test_optimal_ate_pairing_multi_check() {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    assert!(OptimalAtePairing::multi_pairing_check(&[(&p, &q)]));
}

#[test]
fn test_plonk_prover_and_verifier_pipeline() {
    let srs = KzgSrs {
        g1_powers: vec![G1Affine::generator(); 16],
        g2_tau: G2Affine::generator(),
    };

    let gates = vec![
        PlonkGateRow::new_addition(0, 1, 2),       // x0 + x1 = x2  (3 + 5 = 8)
        PlonkGateRow::new_multiplication(2, 3, 4), // x2 * x3 = x4  (8 * 2 = 16)
    ];

    let witness = vec![
        Fp::from_u64(3),
        Fp::from_u64(5),
        Fp::from_u64(8),
        Fp::from_u64(2),
        Fp::from_u64(16),
    ];

    let public_inputs = vec![Fp::from_u64(16)];

    let proof = PlonkProver::prove(&srs, &gates, &witness, &public_inputs).expect("PLONK proving");
    assert!(PlonkVerifier::verify(&srs, &proof).expect("PLONK verification"));
}

#[test]
fn test_differential_privacy_laplace() {
    let stat = DifferentialPrivacyEngine::privatize_count(100, 1.0);
    assert_eq!(stat.raw_count, 100);
    assert!(stat.noisy_count > 0.0);
    assert_eq!(stat.epsilon, 1.0);
}

#[test]
fn test_chaumian_blind_signatures() {
    let message = b"user-age-over-21-credential-token-001";
    let blinding_factor = [0x42u8; 32];
    let issuer_secret = [0x99u8; 32];

    let blinded = BlindSignatureEngine::blind(message, &blinding_factor);
    let blind_sig = BlindSignatureEngine::issuer_sign_blinded(&blinded, &issuer_secret);
    let unblinded = BlindSignatureEngine::unblind(&blind_sig, &blinding_factor);

    assert_eq!(unblinded.len(), 64);
}

#[test]
fn test_ring_signature_anonymity_and_linkability() {
    let msg = b"anonymous-compliance-statement-vote-yes";
    let ring = vec![
        "pk_alice_0123456789".to_string(),
        "pk_bob_9876543210".to_string(),
        "pk_charlie_55555".to_string(),
    ];
    let signer_idx = 1; // Bob
    let bob_secret = [0x33u8; 32];

    let sig = RingSignatureEngine::sign_ring(msg, &ring, signer_idx, &bob_secret).expect("Ring signature");
    assert_eq!(sig.ring_public_keys.len(), 3);
    assert_eq!(sig.responses.len(), 3);

    let mut seen_nullifiers = std::collections::HashSet::new();
    assert!(RingSignatureEngine::verify_ring(msg, &sig, &seen_nullifiers));

    // Mark key image as seen
    seen_nullifiers.insert(sig.key_image.clone());
    // Second attempt should fail (linkable double-spend prevention)
    assert!(!RingSignatureEngine::verify_ring(msg, &sig, &seen_nullifiers));
}
