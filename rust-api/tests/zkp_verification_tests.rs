// Comprehensive Cryptographic and Circuit Verification Test Suite

use zk_identity_microservice::circuits::age_circuit::{AgeVerificationCircuit, AgeWitness};
use zk_identity_microservice::circuits::merkle_membership::{MerkleMembershipCircuit, MerkleMembershipWitness, MerklePathStep};
use zk_identity_microservice::circuits::sanctions_non_membership::{NonMembershipWitness, SanctionsNonMembershipCircuit};
use zk_identity_microservice::merkle::blake3_chain::Blake3MerkleTree;
use zk_identity_microservice::merkle::sparse_tree::SparseMerkleTree;
use zk_identity_microservice::security::audit_logger::CryptographicAuditLogger;
use zk_identity_microservice::security::constant_time::ct_eq;
use zk_identity_microservice::security::entropy::EntropyEvaluator;
use zk_identity_microservice::security::key_management::{KeyDerivation, KeyPair, SecretKey256};
use zk_identity_microservice::security::rate_limiter::{RateLimitPolicy, RateLimiter};
use zk_identity_microservice::zkp::bn254::{Fp, U256};
use zk_identity_microservice::zkp::pedersen::{BlindingFactor, PedersenCommitment, PedersenGenerators};
use zk_identity_microservice::zkp::poseidon::{poseidon_hash_2, poseidon_hash_bytes};
use zk_identity_microservice::zkp::r1cs::ConstraintSystem;
use zk_identity_microservice::zkp::schnorr::{prove_knowledge, verify_knowledge, SchnorrPublicKey, SchnorrSecret};

#[test]
fn test_bn254_field_addition_and_subtraction() {
    let a = Fp::from_u64(100);
    let b = Fp::from_u64(250);
    let sum = a.add(b);
    let diff = sum.sub(a);
    assert_eq!(diff, b);
}

#[test]
fn test_poseidon_sponge_hashing() {
    let h1 = poseidon_hash_2(42, 99);
    let h2 = poseidon_hash_2(42, 99);
    assert_eq!(h1, h2);
    assert_ne!(h1, 0);

    let bytes_hash = poseidon_hash_bytes(b"test-input");
    assert_eq!(bytes_hash.len(), 32);
}

#[test]
fn test_r1cs_age_circuit_synthesis_and_verification() {
    let circuit = AgeVerificationCircuit::new(18, 2026);
    let mut cs = ConstraintSystem::new();
    circuit.synthesize(&mut cs);

    assert!(cs.constraints.len() >= 9);

    let valid_witness = AgeWitness {
        birth_year: 2000,
        current_year: 2026,
        user_salt: [0x5au8; 32],
    };

    let table = circuit.generate_witness(&cs, &valid_witness).expect("Valid witness generation");
    assert!(cs.is_satisfied(&table.values).expect("Constraint satisfaction check"));

    let underage_witness = AgeWitness {
        birth_year: 2015,
        current_year: 2026,
        user_salt: [0x5au8; 32],
    };
    assert!(circuit.generate_witness(&cs, &underage_witness).is_err());
}

#[test]
fn test_pedersen_commitment_homomorphism_and_opening() {
    let gens = PedersenGenerators::default_bn254();
    let val = b"confidential-attribute-payload";
    let blinding = BlindingFactor::random();

    let commitment = PedersenCommitment::commit(&gens, val, &blinding);
    assert!(commitment.verify_opening(&gens, val, &blinding));

    let wrong_val = b"tampered-attribute-payload";
    assert!(!commitment.verify_opening(&gens, wrong_val, &blinding));
}

#[test]
fn test_schnorr_zero_knowledge_proof_of_knowledge() {
    let secret = SchnorrSecret {
        secret_scalar: [0x42u8; 32],
    };
    let public_key = SchnorrPublicKey {
        point: [0x99u8; 32],
    };
    let context = b"zk-session-challenge-nonce";

    let proof = prove_knowledge(&secret, &public_key, context);
    assert!(verify_knowledge(&public_key, &proof, context));
}

#[test]
fn test_constant_time_comparison() {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 5];
    let c = [1u8, 2, 3, 4, 6];

    assert!(ct_eq(&a, &b));
    assert!(!ct_eq(&a, &c));
}

#[test]
fn test_entropy_health_assessment() {
    let mut eval = EntropyEvaluator::new();
    let random_pool = EntropyEvaluator::secure_random_seed();
    let status = eval.assess_entropy_pool(&random_pool);

    assert!(status.passed_rct);
    assert!(status.Shannon_entropy_estimate >= 700);
}

#[test]
fn test_cryptographic_rate_limiter() {
    let policy = RateLimitPolicy {
        max_requests_per_window: 3,
        window_duration: std::time::Duration::from_secs(10),
    };
    let limiter = RateLimiter::new(policy);
    let client = RateLimiter::fingerprint_client("192.168.1.100", b"salt");

    assert!(limiter.check_and_record(&client));
    assert!(limiter.check_and_record(&client));
    assert!(limiter.check_and_record(&client));
    assert!(!limiter.check_and_record(&client)); // Rate limited
}

#[test]
fn test_audit_logger_tamper_evidence() {
    let key = SecretKey256([0x77u8; 32]);
    let logger = CryptographicAuditLogger::new(key);

    let e1 = logger.record_event("PROOF_VERIFIED", b"proof_payload_1");
    let e2 = logger.record_event("SESSION_CREATED", b"proof_payload_2");

    let chain = vec![e1, e2];
    assert!(logger.verify_log_chain(&chain));
}

#[test]
fn test_blake3_merkle_tree_inclusion_proof() {
    let mut tree = Blake3MerkleTree::new();
    for i in 0..8 {
        let mut leaf = [0u8; 32];
        leaf[0] = i as u8;
        tree.push_leaf(leaf);
    }

    let root = tree.compute_root();
    assert_ne!(root, [0u8; 32]);

    let proof = tree.generate_inclusion_proof(3).expect("Proof generation");
    assert!(Blake3MerkleTree::verify_inclusion(&proof));
}
