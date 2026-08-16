//! Multi-Party Computation and Hardware Security Module Tests

use zk_identity_microservice::hsm::enclave::{EnclaveAttestationQuote, EnclaveAttestationVerifier};
use zk_identity_microservice::hsm::pkcs11::HsmCryptoToken;
use zk_identity_microservice::mpc::ceremony::{MpcContribution, MpcCoordinator};
use zk_identity_microservice::mpc::lagrange::LagrangeBasis;
use zk_identity_microservice::mpc::transcript::CeremonyTranscript;
use zk_identity_microservice::zkp::bn254::Fp;

#[test]
fn test_mpc_ceremony_contribution_chain() {
    let mut coordinator = MpcCoordinator::new(1024);

    let mut hasher1 = blake3::Hasher::new();
    hasher1.update(b"zk-mpc-contribution-v1\0");
    hasher1.update(&1u32.to_le_bytes());
    hasher1.update(b"contributor-alice");
    hasher1.update(MpcCoordinator::GENESIS_MPC_HASH.as_bytes());
    hasher1.update(b"g1_power_1");
    let hash1 = hasher1.finalize().to_hex().to_string();

    let c1 = MpcContribution {
        contributor_id: "contributor-alice".to_string(),
        sequence_number: 1,
        tau_g1_powers: vec!["g1_power_1".to_string()],
        tau_g2_powers: vec!["g2_power_1".to_string()],
        public_key_signature: "sig_alice".to_string(),
        previous_hash: MpcCoordinator::GENESIS_MPC_HASH.to_string(),
        contribution_hash: hash1.clone(),
    };

    assert!(coordinator.accept_contribution(&c1).is_ok());
    assert_eq!(coordinator.current_sequence, 1);
    assert_eq!(coordinator.last_hash, hash1);
}

#[test]
fn test_hsm_session_and_blind_signing() {
    let session = HsmCryptoToken::open_session("ZK_IDENTITY_FIPS140_HSM", b"pin_987654").expect("HSM session open");
    assert!(session.is_authenticated);

    let doc_digest = [0x5au8; 32];
    let signature = HsmCryptoToken::sign_identity_receipt(&session, &doc_digest);
    assert_eq!(signature.len(), 64);
}

#[test]
fn test_enclave_attestation_verification() {
    let verifier = EnclaveAttestationVerifier::new("DEV_SIMULATION_MODE");
    let quote = EnclaveAttestationQuote {
        enclave_id: "nitro-enclave-us-west-2-001".to_string(),
        pcr0_enclave_image_hash: "a3f5c9e2b1".to_string(),
        pcr1_kernel_hash: "kernel_hash".to_string(),
        pcr2_application_hash: "app_hash".to_string(),
        user_data_nonce: "challenge_nonce_xyz123".to_string(),
        signature: "hardware_root_sig".to_string(),
        timestamp_epoch_ms: 1786770000000,
    };

    assert!(verifier.verify_quote(&quote, "challenge_nonce_xyz123").expect("Enclave verification"));
}

#[test]
fn test_lagrange_basis_evaluation() {
    let tau = Fp::from_u64(10);
    let l0 = LagrangeBasis::evaluate_lagrange_polynomial(8, 0, tau).expect("Lagrange L0");
    assert!(!l0.is_zero());
}
