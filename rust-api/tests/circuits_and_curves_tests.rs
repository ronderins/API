//! Circuit Gadgets and Elliptic Curve Integration Tests

use zk_identity_microservice::circuits::gadgets::bit_decomposition::BitDecompositionGadget;
use zk_identity_microservice::circuits::gadgets::comparator::ComparatorGadget;
use zk_identity_microservice::crypto_core::ed25519::Ed25519Point;
use zk_identity_microservice::crypto_core::secp256k1::{Secp256k1Field, Secp256k1Jacobian};
use zk_identity_microservice::zkp::bn254::Fp;
use zk_identity_microservice::zkp::r1cs::{ConstraintSystem, Variable};

#[test]
fn test_bit_decomposition_r1cs_gadget() {
    let mut cs = ConstraintSystem::new();
    let val_var = cs.alloc_private();
    let bits = BitDecompositionGadget::decompose_and_constrain(&mut cs, val_var, 8);

    assert_eq!(bits.len(), 8);
    // 8 bit boolean constraints + 1 sum constraint = 9 constraints
    assert_eq!(cs.constraints.len(), 9);
}

#[test]
fn test_comparator_gadget_enforcement() {
    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_private();
    let b = cs.alloc_private();

    ComparatorGadget::enforce_less_or_equal(&mut cs, a, b);
    assert!(cs.constraints.len() >= 65);
}

#[test]
fn test_secp256k1_point_operations() {
    let g = Secp256k1Jacobian {
        x: Secp256k1Field::from_u64(0x79be667e),
        y: Secp256k1Field::from_u64(0x483ada77),
        z: Secp256k1Field::one(),
    };

    let double_g = g.double();
    assert!(!double_g.is_infinity());

    let sum = g.add(&g);
    assert!(!sum.is_infinity());
}

#[test]
fn test_ed25519_curve_identity_and_addition() {
    let id = Ed25519Point::identity();
    let sum = id.add(&id);
    assert_eq!(sum.z, id.z);
}
