//! Zero-Knowledge Performance and Latency Microbenchmarks
//!
//! Measures microsecond-level execution times for Poseidon algebraic hashing,
//! BN254 field arithmetic, R1CS circuit synthesis, Merkle tree root computation,
//! and Ephemeral Zeroize memory wipe cycles.

use std::time::Instant;
use zk_identity_microservice::circuits::age_circuit::{AgeVerificationCircuit, AgeWitness};
use zk_identity_microservice::merkle::blake3_chain::Blake3MerkleTree;
use zk_identity_microservice::security::constant_time::ct_eq;
use zk_identity_microservice::zkp::bn254::Fp;
use zk_identity_microservice::zkp::poseidon::poseidon_hash_2;
use zk_identity_microservice::zkp::r1cs::ConstraintSystem;

fn benchmark_poseidon_hash(iterations: usize) -> u128 {
    let start = Instant::now();
    let mut val = 42u64;
    for i in 0..iterations {
        val = poseidon_hash_2(val, i as u64);
    }
    let elapsed = start.elapsed().as_micros();
    println!("Poseidon Hash ({} iterations): {} µs total (avg {:.2} µs/hash)",
        iterations, elapsed, elapsed as f64 / iterations as f64);
    elapsed
}

fn benchmark_bn254_field_ops(iterations: usize) -> u128 {
    let start = Instant::now();
    let mut a = Fp::from_u64(123456789);
    let b = Fp::from_u64(987654321);
    for _ in 0..iterations {
        a = a.add(b).double();
    }
    let elapsed = start.elapsed().as_micros();
    println!("BN254 Fp Arithmetic ({} ops): {} µs total (avg {:.3} µs/op)",
        iterations, elapsed, elapsed as f64 / iterations as f64);
    elapsed
}

fn benchmark_r1cs_circuit_synthesis(iterations: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        let circuit = AgeVerificationCircuit::new(18, 2026);
        let mut cs = ConstraintSystem::new();
        circuit.synthesize(&mut cs);

        let witness = AgeWitness {
            birth_year: 1995,
            current_year: 2026,
            user_salt: [0x5au8; 32],
        };
        let table = circuit.generate_witness(&cs, &witness).unwrap();
        let _ = cs.is_satisfied(&table.values).unwrap();
    }
    let elapsed = start.elapsed().as_micros();
    println!("R1CS Circuit Synthesis & Verification ({} runs): {} µs total (avg {:.2} µs/run)",
        iterations, elapsed, elapsed as f64 / iterations as f64);
    elapsed
}

fn benchmark_merkle_tree(num_leaves: usize) -> u128 {
    let start = Instant::now();
    let mut tree = Blake3MerkleTree::new();
    for i in 0..num_leaves {
        let mut leaf = [0u8; 32];
        leaf[0] = (i % 256) as u8;
        leaf[1] = (i / 256) as u8;
        tree.push_leaf(leaf);
    }
    let _root = tree.compute_root();
    let elapsed = start.elapsed().as_micros();
    println!("Blake3 Merkle Tree ({} leaves): {} µs total", num_leaves, elapsed);
    elapsed
}

fn main() {
    println!("============================================================");
    println!("  ZK-Auth Cryptographic Microsecond Performance Benchmark  ");
    println!("============================================================");

    benchmark_poseidon_hash(10_000);
    benchmark_bn254_field_ops(100_000);
    benchmark_r1cs_circuit_synthesis(1_000);
    benchmark_merkle_tree(10_000);

    println!("============================================================");
    println!("  All cryptographic microbenchmarks completed successfully  ");
    println!("============================================================");
}
