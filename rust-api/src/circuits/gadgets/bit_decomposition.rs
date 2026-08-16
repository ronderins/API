//! Bit Decomposition & Boolean Constraining Gadgets
//!
//! Enforces that an arithmetic wire x decomposes into N binary bits b_0, b_1, ..., b_{N-1}
//! such that \sum b_i 2^i = x and \forall i, b_i (1 - b_i) = 0.

use crate::zkp::bn254::Fp;
use crate::zkp::r1cs::{ConstraintSystem, LinearCombination, Variable};

pub struct BitDecompositionGadget;

impl BitDecompositionGadget {
    /// Constrains variable `val` to be boolean (0 or 1): val * (1 - val) = 0
    pub fn constrain_boolean(cs: &mut ConstraintSystem, var: Variable) {
        let mut a = LinearCombination::zero();
        a.add(var, Fp::from_u64(1));

        let mut b = LinearCombination::zero();
        b.add(Variable::one(), Fp::from_u64(1));
        b.add(var, Fp::zero().sub(Fp::from_u64(1)));

        let c = LinearCombination::zero();
        cs.enforce(a, b, c);
    }

    /// Decomposes `val` into `num_bits` binary variables and enforces sum equality
    pub fn decompose_and_constrain(
        cs: &mut ConstraintSystem,
        val: Variable,
        num_bits: usize,
    ) -> Vec<Variable> {
        let mut bits = Vec::with_capacity(num_bits);
        let mut bit_sum = LinearCombination::zero();

        for i in 0..num_bits {
            let bit_var = cs.alloc_private();
            Self::constrain_boolean(cs, bit_var);

            let power_of_two = Fp::from_u64(1u64 << (i.min(62)));
            bit_sum.add(bit_var, power_of_two);
            bits.push(bit_var);
        }

        // Enforce sum == val
        let mut a = LinearCombination::zero();
        a.add(Variable::one(), Fp::from_u64(1));
        let b = bit_sum;
        let mut c = LinearCombination::zero();
        c.add(val, Fp::from_u64(1));

        cs.enforce(a, b, c);

        bits
    }
}
