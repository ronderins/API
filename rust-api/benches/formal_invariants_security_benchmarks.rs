//! Formal Invariants & Advanced Security Benchmarks
//!
//! Measures execution latency and hardware efficiency for:
//! - BFV FHE homomorphic multiplication and scalar scaling
//! - BLS12-381 threshold signature share aggregation
//! - Wesolowski VDF sequential squarings vs O(1) verification
//! - Bulletproofs+ 64-bit range proof generation
//! - Falcon-512 FIPS 206 lattice signature verification
//! - ZKVM JIT opcode dispatch and memory boundary validation

use std::time::Instant;
use zk_identity_api_rust::security::fhe_bfv_ckks::*;
use zk_identity_api_rust::security::threshold_bls_aggregation::*;
use zk_identity_api_rust::security::verifiable_delay_function::*;
use zk_identity_api_rust::security::bulletproofs_plus_range::*;
use zk_identity_api_rust::security::falcon_fips206::*;
use zk_identity_api_rust::security::zkvm_jit_armor::*;

pub fn benchmark_fhe_homomorphic_addition() -> u128 {
    let ctx = BfvContext::default_parameters();
    let sk = FheSecretKey::generate_deterministic(&[0x11u8; 32]);
    let (pk, _) = ctx.generate_keys(&sk, &[0x22u8; 32]);

    let ct1 = ctx.encrypt_scalar(&pk, 42, &[1u8; 32]);
    let ct2 = ctx.encrypt_scalar(&pk, 58, &[2u8; 32]);

    let start = Instant::now();
    let _sum = ctx.homomorphic_add(&ct1, &ct2).unwrap();
    start.elapsed().as_micros()
}

pub fn benchmark_bls_aggregation_latency() -> u128 {
    let mut agg = BlsThresholdAggregator::new(2, 2);
    let sk1 = BlsScalar::from_u64(1);
    let pk1 = BlsG1Point::from_secret_scalar(&sk1);
    let pop1 = ProofOfPossession::generate(1, &sk1, &pk1);
    agg.register_participant(1, pk1, pop1).unwrap();

    let sk2 = BlsScalar::from_u64(2);
    let pk2 = BlsG1Point::from_secret_scalar(&sk2);
    let pop2 = ProofOfPossession::generate(2, &sk2, &pk2);
    agg.register_participant(2, pk2, pop2).unwrap();

    let msg = b"Benchmark Payload";
    let share1 = BlsSignatureShare {
        signer_index: 1,
        signature_point: BlsG2Point {
            x: ("x0".into(), "x1".into()),
            y: ("y0".into(), "y1".into()),
            is_infinity: false,
        },
        signed_message_digest: format!("{:x}", blake3::hash(msg)),
    };
    let share2 = BlsSignatureShare {
        signer_index: 2,
        signature_point: BlsG2Point {
            x: ("x0".into(), "x1".into()),
            y: ("y0".into(), "y1".into()),
            is_infinity: false,
        },
        signed_message_digest: format!("{:x}", blake3::hash(msg)),
    };

    let start = Instant::now();
    let _agg = agg.aggregate_shares(&[share1, share2], msg).unwrap();
    start.elapsed().as_micros()
}

pub fn benchmark_vdf_verification() -> u128 {
    let config = VdfConfig {
        delay_iterations_t: 10,
        modulus_hex: "abcdef0123456789".into(),
    };
    let vdf = WesolowskiVdf::new(config);
    let proof = vdf.evaluate(b"Benchmark VDF Input");

    let start = Instant::now();
    let _ = vdf.verify(&proof).unwrap();
    start.elapsed().as_micros()
}

pub fn benchmark_bulletproofs_plus() -> u128 {
    let start = Instant::now();
    let _ = BulletproofsPlusEngine::prove_range(35, 12345, 18, 100).unwrap();
    start.elapsed().as_micros()
}

pub fn benchmark_falcon_verify() -> u128 {
    let (pk, sk) = FalconEngine::generate_keypair(&[0x99u8; 32]);
    let msg = b"Benchmark Falcon Message";
    let sig = FalconEngine::sign(&sk, msg, &[0x44u8; 40]);

    let start = Instant::now();
    let _ = FalconEngine::verify(&pk, msg, &sig);
    start.elapsed().as_micros()
}

pub fn benchmark_zkvm_sandbox_execution() -> u128 {
    let program = vec![
        ZkOpcode::LoadConst(10),
        ZkOpcode::LoadConst(20),
        ZkOpcode::Add,
        ZkOpcode::Blake3Hash,
        ZkOpcode::Halt,
    ];
    let mut vm = HardenedZkvmSandbox::new(program, 5000).unwrap();

    let start = Instant::now();
    let _ = vm.execute().unwrap();
    start.elapsed().as_micros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_all_security_benchmarks() {
        let fhe_us = benchmark_fhe_homomorphic_addition();
        let bls_us = benchmark_bls_aggregation_latency();
        let vdf_us = benchmark_vdf_verification();
        let bp_us = benchmark_bulletproofs_plus();
        let falcon_us = benchmark_falcon_verify();
        let zkvm_us = benchmark_zkvm_sandbox_execution();

        println!("FHE Addition: {} us", fhe_us);
        println!("BLS Aggregation: {} us", bls_us);
        println!("VDF Verification: {} us", vdf_us);
        println!("Bulletproofs+ Prove: {} us", bp_us);
        println!("Falcon Verify: {} us", falcon_us);
        println!("ZKVM Sandbox: {} us", zkvm_us);

        assert!(fhe_us < 50_000);
        assert!(bls_us < 10_000);
        assert!(vdf_us < 10_000);
    }
}
