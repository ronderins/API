//! Identity, Smart Contract Generator, and WASM Browser Prover Tests

use zk_identity_microservice::identity::anon_creds::{AnonCredentialPresentation, AnonCredsVerifier};
use zk_identity_microservice::identity::did::DidResolver;
use zk_identity_microservice::identity::revocation::RevocationAccumulator;
use zk_identity_microservice::smart_contracts::calldata::EvmCalldataEncoder;
use zk_identity_microservice::smart_contracts::solidity_generator::SolidityVerifierGenerator;
use zk_identity_microservice::wasm::browser_prover::{BrowserProverEngine, WasmProverRequest};

#[test]
fn test_did_resolution() {
    let did = "did:zk:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let doc = DidResolver::resolve(did).expect("DID resolution");
    assert_eq!(doc.id, did);
    assert_eq!(doc.verification_method.len(), 1);
}

#[test]
fn test_revocation_accumulator_updates_and_witnesses() {
    let mut reg = RevocationAccumulator::new("kyc-passport-registry-eu");
    let nullifier = [0x77u8; 32];

    assert!(!reg.is_revoked(&nullifier));
    assert!(reg.generate_non_revocation_witness(&nullifier).is_ok());

    reg.revoke(nullifier);
    assert!(reg.is_revoked(&nullifier));
    assert!(reg.generate_non_revocation_witness(&nullifier).is_err());
}

#[test]
fn test_solidity_verifier_generator() {
    let code = SolidityVerifierGenerator::generate_verifier_contract("ZKIdentityVerifier");
    assert!(code.contains("contract ZKIdentityVerifier"));
    assert!(code.contains("ecPairing"));
    assert!(code.contains("verifyProof"));
}

#[test]
fn test_evm_calldata_encoder() {
    let a = [0x11u8; 64];
    let b = [0x22u8; 128];
    let c = [0x33u8; 64];
    let inputs = vec![18, 2026, 0x1234, 0x5678];

    let calldata = EvmCalldataEncoder::encode_proof(&a, &b, &c, &inputs);
    assert!(calldata.function_signature.starts_with("verifyProof"));
    assert!(calldata.raw_calldata_hex.starts_with("0x43b236fc"));
}

#[test]
fn test_wasm_browser_prover_synthesis() {
    let req = WasmProverRequest {
        birth_year: 1998,
        current_year: 2026,
        threshold: 21,
        user_salt_hex: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a".to_string(),
    };

    let res = BrowserProverEngine::synthesize_proof_in_wasm(&req).expect("WASM proof synthesis");
    assert!(res.is_valid);
    assert_eq!(res.nullifier_hash.len(), 64);
    assert!(res.constraint_count >= 9);
}
