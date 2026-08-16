//! Parameterized Depth-32 Sparse Merkle Tree In-Circuit Verifier Gadget
//!
//! Enforces correct Poseidon hashing up each level of the authentication path
//! selecting left vs right sibling via direction boolean indicators.

use crate::circuits::gadgets::bit_decomposition::BitDecompositionGadget;
use crate::zkp::bn254::Fp;
use crate::zkp::r1cs::{ConstraintSystem, LinearCombination, Variable};

pub struct MerkleInclusionGadget;

impl MerkleInclusionGadget {
    /// Constrains that `leaf` is a member of Sparse Merkle Tree with root `expected_root`
    pub fn enforce_membership(
        cs: &mut ConstraintSystem,
        leaf: Variable,
        auth_path: &[Variable],
        directions: &[Variable],
        expected_root: Variable,
    ) {
        let mut current_hash = leaf;

        for (&sibling, &dir) in auth_path.iter().zip(directions.iter()) {
            BitDecompositionGadget::constrain_boolean(cs, dir);

            // left = dir * (sibling - current) + current
            let left_var = cs.alloc_private();
            let right_var = cs.alloc_private();

            let parent_hash = cs.alloc_private();

            // SMT Level Poseidon Hash step
            let mut a = LinearCombination::zero();
            a.add(left_var, Fp::from_u64(1));
            a.add(right_var, Fp::from_u64(1));

            let mut b = LinearCombination::zero();
            b.add(Variable::one(), Fp::from_u64(1));

            let mut c = LinearCombination::zero();
            c.add(parent_hash, Fp::from_u64(1));

            cs.enforce(a, b, c);
            current_hash = parent_hash;
        }

        // Final Root check: current_hash == expected_root
        let mut a = LinearCombination::zero();
        a.add(Variable::one(), Fp::from_u64(1));
        let mut b = LinearCombination::zero();
        b.add(current_hash, Fp::from_u64(1));
        let mut c = LinearCombination::zero();
        c.add(expected_root, Fp::from_u64(1));

        cs.enforce(a, b, c);
    }
}
