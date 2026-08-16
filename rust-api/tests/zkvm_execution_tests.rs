//! Zero-Knowledge Virtual Machine & Polynomial Integration Tests

use zk_identity_microservice::zkp::bn254::Fp;
use zk_identity_microservice::zkvm::air::IdentityAir;
use zk_identity_microservice::zkvm::fri::{FriCommitLayer, FriProof, FriQueryProof, FriVerifier};
use zk_identity_microservice::zkvm::opcodes::{Instruction, Opcode, Register};
use zk_identity_microservice::zkvm::polynomial::Polynomial;
use zk_identity_microservice::zkvm::state_machine::{TraceRow, ZkVirtualMachine};
use zk_identity_microservice::zkvm::verifier::{ZkCertificateVerifier, ZkExecutionCertificate};

#[test]
fn test_zkvm_arithmetic_execution() {
    let program = vec![
        Instruction::new(Opcode::LoadImm, Register::R1, Register::R0, Register::R0, 42),
        Instruction::new(Opcode::LoadImm, Register::R2, Register::R0, Register::R0, 58),
        Instruction::new(Opcode::Add, Register::R0, Register::R1, Register::R2, 0),
        Instruction::new(Opcode::Halt, Register::R0, Register::R0, Register::R0, 0),
    ];

    let mut vm = ZkVirtualMachine::new(program);
    let trace = vm.run_with_trace().expect("zkVM execution");

    assert_eq!(trace.final_registers[0], 100);
    assert_eq!(trace.total_cycles, 4);
    assert_ne!(trace.trace_root, [0u8; 32]);
}

#[test]
fn test_zkvm_poseidon_sponge_opcode() {
    let program = vec![
        Instruction::new(Opcode::LoadImm, Register::R1, Register::R0, Register::R0, 1337),
        Instruction::new(Opcode::LoadImm, Register::R2, Register::R0, Register::R0, 2026),
        Instruction::new(Opcode::PoseidonSponge, Register::R0, Register::R1, Register::R2, 0),
        Instruction::new(Opcode::Halt, Register::R0, Register::R0, Register::R0, 0),
    ];

    let mut vm = ZkVirtualMachine::new(program);
    let trace = vm.run_with_trace().expect("zkVM Poseidon execution");

    assert_ne!(trace.final_registers[0], 0);
}

#[test]
fn test_zkvm_age_predicate_program() {
    // Proves age >= 21: (2026 - birth_year) >= 21
    let program = vec![
        Instruction::new(Opcode::LoadImm, Register::R1, Register::R0, Register::R0, 2026), // Current Year
        Instruction::new(Opcode::LoadImm, Register::R2, Register::R0, Register::R0, 2000), // Birth Year (Private input)
        Instruction::new(Opcode::Sub, Register::R3, Register::R1, Register::R2, 0),       // Age = 26
        Instruction::new(Opcode::LoadImm, Register::R4, Register::R0, Register::R0, 21),   // Threshold
        Instruction::new(Opcode::JmpGt, Register::R0, Register::R3, Register::R4, 6),     // if age > 21 goto 6
        Instruction::new(Opcode::LoadImm, Register::R0, Register::R0, Register::R0, 0),   // Failure: 0
        Instruction::new(Opcode::Halt, Register::R0, Register::R0, Register::R0, 0),
        Instruction::new(Opcode::LoadImm, Register::R0, Register::R0, Register::R0, 1),   // Success: 1
        Instruction::new(Opcode::Halt, Register::R0, Register::R0, Register::R0, 0),
    ];

    let mut vm = ZkVirtualMachine::new(program);
    let trace = vm.run_with_trace().expect("zkVM Age check");

    assert_eq!(trace.final_registers[0], 1); // Success
}

#[test]
fn test_polynomial_arithmetic_and_division() {
    // P(x) = x^2 + 2x + 1 = (x + 1)(x + 1)
    let p1 = Polynomial::new(vec![Fp::from_u64(1), Fp::from_u64(1)]);
    let p2 = Polynomial::new(vec![Fp::from_u64(1), Fp::from_u64(1)]);
    let prod = p1.mul(&p2);

    assert_eq!(prod.degree(), 2);
    assert_eq!(prod.evaluate(Fp::from_u64(2)), Fp::from_u64(9)); // (2+1)^2 = 9

    let (q, r) = prod.divide(&p1).expect("Polynomial division");
    assert_eq!(q.degree(), 1);
    assert!(r.is_zero());
}

#[test]
fn test_fri_protocol_verification() {
    let verifier = FriVerifier::new(8, 16);
    let proof = FriProof {
        commit_layers: vec![
            FriCommitLayer {
                root: "trace_lde_root_hex_0123".to_string(),
                evaluations_len: 128,
            },
            FriCommitLayer {
                root: "layer_1_root_hex_4567".to_string(),
                evaluations_len: 64,
            },
        ],
        final_polynomial_coeffs: vec!["42".to_string()],
        queries: vec![FriQueryProof {
            position: 12,
            folded_evaluations: vec!["val1".to_string(), "val2".to_string()],
            auth_paths: vec![vec!["p1".to_string()], vec!["p2".to_string()]],
        }],
        blowup_factor: 8,
    };

    assert!(verifier.verify(&proof, "trace_lde_root_hex_0123").expect("FRI verification"));
}
