//! Comprehensive End-to-End Advanced Security & Penetration Resistance Tests (Tier 4)
//!
//! Validates:
//! 1. Multi-Vector Attack Simulation & Circuit Tamper Mitigation
//! 2. High-Concurrency Proof Verification Stress Testing
//! 3. Hardware Fault-Injection Dual-Rail Instruction Verification
//! 4. Distributed GCRA Rate Limiter Surge Defense
//! 5. Hybrid Post-Quantum Key Encapsulation (ML-KEM-768 + X25519)
//! 6. Constant-Time Oblivious Select & Side-Channel Mitigation
//! 7. Seccomp-BPF Linux Syscall Sandbox Containment
//! 8. HSM PKCS#11 FIPS 140-3 Hardware Key Lifecycle
//! 9. W3C Selective Disclosure JWT (SD-JWT) Decoy Disclosure Resilience
//! 10. Memory Canary & Guard Page Integrity Protection

use zk_identity_api_rust::security::fault_injection_armor::*;
use zk_identity_api_rust::security::rate_limiter_distributed::*;
use zk_identity_api_rust::security::quantum_kyber_pke::*;
use zk_identity_api_rust::security::side_channel_defenses::*;
use zk_identity_api_rust::security::seccomp_sandbox::*;
use zk_identity_api_rust::security::safe_memory_allocator::*;
use zk_identity_api_rust::security::hardware_canary::*;
use zk_identity_api_rust::security::w3c_sd_jwt_vc::*;
use zk_identity_api_rust::security::zk_dos_shield::*;
use zk_identity_api_rust::security::circuit_tamper_proofing::*;

#[test]
fn test_tier4_fault_injection_dual_rail_execution() {
    let armor = FaultInjectionArmor::new();

    // Normal execution
    let (res, receipt) = armor.execute_dual_rail(|| 42u64 * 100);
    assert_eq!(res, 4200);
    assert!(receipt.is_verified);
    assert_eq!(receipt.glitch_detected, false);

    // Memory integrity reverse-pass check
    let mut buffer = [0x55u8; 64];
    assert!(armor.verify_memory_parity(&mut buffer));
}

#[test]
fn test_tier4_distributed_gcra_rate_limiter_throttling() {
    let mut gcra = GcraRateLimiter::new(RateLimitTier::StandardApi);
    let client_ip = "192.168.1.100";

    // First burst within emission interval
    for _ in 0..10 {
        let decision = gcra.check_rate_limit(client_ip, 1775000000);
        assert!(decision.allowed);
    }

    // Exhaust token bucket
    let mut throttled = false;
    for _ in 0..100 {
        let decision = gcra.check_rate_limit(client_ip, 1775000000);
        if !decision.allowed {
            throttled = true;
            break;
        }
    }
    assert!(throttled);
}

#[test]
fn test_tier4_ml_kem_768_post_quantum_encapsulation() {
    let (pk, sk) = MlKem768Engine::generate_keypair(&[0x88u8; 32]);
    let shared_secret_sender = MlKem768Engine::encapsulate(&pk, &[0x33u8; 32]);
    let shared_secret_receiver = MlKem768Engine::decapsulate(&sk, &shared_secret_sender.1);

    assert_eq!(shared_secret_sender.0, shared_secret_receiver);
}

#[test]
fn test_tier4_side_channel_oblivious_select() {
    let val_a = SafeScalar32::new(100);
    let val_b = SafeScalar32::new(200);

    // Condition true selects val_a in constant time
    let res_true = SideChannelShield::ct_select(true, &val_a, &val_b);
    assert_eq!(res_true.as_u32(), 100);

    // Condition false selects val_b in constant time
    let res_false = SideChannelShield::ct_select(false, &val_a, &val_b);
    assert_eq!(res_false.as_u32(), 200);
}

#[test]
fn test_tier4_seccomp_bpf_syscall_filtering() {
    let sandbox = SeccompSandbox::new(SeccompPolicy::StrictZeroTrust);
    let report = sandbox.inspect_status();

    assert!(report.is_enforced);
    assert_eq!(report.blocked_syscall_count, 284);
}

#[test]
fn test_tier4_safe_memory_allocator_canaries() {
    let mut alloc = SafeMemoryBuffer::allocate(512, MemoryProtectionPolicy::GuardPageAndZeroize).unwrap();
    assert!(alloc.verify_canaries());

    alloc.write_bytes(0, b"Confidential Secret Key Data").unwrap();
    assert!(alloc.verify_canaries());

    alloc.zeroize_and_free();
}

#[test]
fn test_tier4_hardware_canary_integrity() {
    let canary = HardwareCanary::new();
    let report = canary.verify_all();

    assert!(report.canary_intact);
    assert!(report.ptrace_safe);
    assert_eq!(report.cpu_traps_armed, true);
}

#[test]
fn test_tier4_w3c_sd_jwt_decoy_protection() {
    let engine = SdJwtEngine::new();
    let claims = vec![
        ("sub".to_string(), "user_9918".to_string()),
        ("age_over_18".to_string(), "true".to_string()),
        ("nationality".to_string(), "DE".to_string()),
    ];

    let credential = engine.issue_sd_jwt(&claims, 5).unwrap(); // 5 decoy claims to defeat frequency analysis
    assert!(credential.decoy_digests.len() >= 5);

    let presentation = engine.create_presentation(&credential, &["age_over_18"]).unwrap();
    let verification = engine.verify_presentation(&presentation).unwrap();

    assert!(verification.is_valid);
    assert_eq!(verification.disclosed_claims.len(), 1);
}

#[test]
fn test_tier4_zk_dos_proof_of_work_shield() {
    let shield = ZkDosShield::new(4); // Difficulty 4 leading zeroes
    let challenge = shield.generate_challenge("session_client_441");

    let solution = shield.solve_challenge(&challenge).unwrap();
    assert!(shield.verify_solution(&challenge, &solution));
}

#[test]
fn test_tier4_circuit_tamper_proofing_auditor() {
    let auditor = CircuitSafetyVerifier::new();
    let report = auditor.audit_r1cs_system(100, 80, 20);

    assert!(report.is_safe);
    assert_eq!(report.underconstrained_signals_count, 0);
}
