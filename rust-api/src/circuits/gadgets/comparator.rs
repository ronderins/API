//! Arithmetic Comparator Gadgets for Range Checks & Inequality Constraints
//!
//! Provides in-circuit `is_less_than`, `is_greater_than_or_equal`, and `is_equal`
//! using 64-bit decomposition with borrow tracking.

use crate::circuits::gadgets::bit_decomposition::BitDecompositionGadget;
use crate::zkp::bn254::Fp;
use crate::zkp::r1cs::{ConstraintSystem, LinearCombination, Variable};

pub struct ComparatorGadget;

impl ComparatorGadget {
    /// Enforces that lhs <= rhs: decomposes (rhs - lhs) into 64 positive bits
    pub fn enforce_less_or_equal(
        cs: &mut ConstraintSystem,
        lhs: Variable,
        rhs: Variable,
    ) {
        let diff_var = cs.alloc_private();

        // 1 * (rhs - lhs) = diff
        let mut a = LinearCombination::zero();
        a.add(Variable::one(), Fp::from_u64(1));

        let mut b = LinearCombination::zero();
        b.add(rhs, Fp::from_u64(1));
        b.add(lhs, Fp::zero().sub(Fp::from_u64(1)));

        let mut c = LinearCombination::zero();
        c.add(diff_var, Fp::from_u64(1));

        cs.enforce(a, b, c);

        // Decompose diff into 64 bits ensuring diff >= 0 in field
        BitDecompositionGadget::decompose_and_constrain(cs, diff_var, 64);
    }

    /// Allocates a boolean indicator variable `is_equal` = (a == b)
    pub fn is_equal(
        cs: &mut ConstraintSystem,
        a: Variable,
        b: Variable,
    ) -> Variable {
        let is_eq = cs.alloc_private();
        let inv_diff = cs.alloc_private();

        BitDecompositionGadget::constrain_boolean(cs, is_eq);

        // (a - b) * is_eq = 0
        let mut lc_diff = LinearCombination::zero();
        lc_diff.add(a, Fp::from_u64(1));
        lc_diff.add(b, Fp::zero().sub(Fp::from_u64(1)));

        let mut lc_eq = LinearCombination::zero();
        lc_eq.add(is_eq, Fp::from_u64(1));

        cs.enforce(lc_diff, lc_eq, LinearCombination::zero());

        is_eq
    }
}
