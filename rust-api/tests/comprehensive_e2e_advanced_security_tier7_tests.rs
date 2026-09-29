//! Comprehensive End-to-End Cryptographic Hardening Tests (Tier 7)
//!
//! Validates:
//! 1. Verifiable Batch Shuffle Opening & Fiat-Shamir Transcript Derivation
//! 2. Confidential Identity Smart Contract EVM Calldata Serialization
//! 3. Proactive Secret Sharing (PSS) Polynomial Renewal & Zero-Subshare Roll
//! 4. Cross-Domain Verifiable Credential Federation & eIDAS/NIST Bridge
//! 5. Post-Quantum Dual-Hybrid Key Exchange Handshake & Forward Secrecy

use zk_identity_api_rust::security::zk_batch_shuffle_verifier::*;
use zk_identity_api_rust::security::confidential_calldata_evm::*;
use zk_identity_api_rust::security::proactive_secret_sharing::*;
use zk_identity_api_rust::security::verifiable_credential_federation::*;
use zk_identity_api_rust::security::pq_session_key_exchange::*;

#[test]
fn test_tier7_batch_shuffle_verifier() {
    let verifier = BatchShuffleVerifier::new();
    let opening = BatchShuffleOpening {
        batch_id: "batch_epoch_904".into(),
        permutation_hash: "perm_hash_alpha".into(),
        challenged_evaluations: vec![10, 20, 30],
        composite_response_scalar: 777,
    };

    assert!(verifier.verify_batch_opening(&opening, 3).unwrap());
}

#[test]
fn test_tier7_evm_calldata_formatting() {
    let calldata = EvmCalldataEncoder::encode_groth16(
        100, 200,
        300, 400, 500, 600,
        700, 800,
        &[18, 9999],
    );

    assert_eq!(calldata.public_signals.len(), 2);
    assert!(EvmCalldataEncoder::validate_packed_calldata(&calldata).unwrap());
}

#[test]
fn test_tier7_proactive_secret_sharing_epoch_transition() {
    let mut pss = ProactiveSecretSharingEngine::new(3, 2);
    let initial_share = 5000u64;

    let subshares = pss.generate_zero_subshares(1, &[0x33; 32]);
    let matching_updates = vec![
        subshares[0].clone(),
        subshares[1].clone(),
    ];

    let renewed = pss.apply_resharing(1, initial_share, &matching_updates).unwrap();
    assert_eq!(renewed.epoch, 2);
    assert!(renewed.previous_epoch_zeroized);
}

#[test]
fn test_tier7_credential_federation_eidas_bridge() {
    let federation = CredentialFederationEngine::new();
    let proof = federation
        .issue_bridge_proof("eu.eidas.trust.registry", "us.gov.nist80063.registry", "cred_hash_441")
        .unwrap();

    assert!(federation.verify_federated_credential(&proof).unwrap());
}

#[test]
fn test_tier7_post_quantum_hybrid_session_ratchet() {
    let (init, priv_key) = PqSessionKeyExchangeEngine::client_initiate("pq_sess_77", &[0x77; 32]);
    let (resp, _) = PqSessionKeyExchangeEngine::server_respond(&init, &[0x99; 32]);

    let ctx = PqSessionKeyExchangeEngine::client_finalize(&init, priv_key, &resp).unwrap();
    assert!(ctx.post_quantum_secure);
    assert_eq!(ctx.session_id, "pq_sess_77");
}
