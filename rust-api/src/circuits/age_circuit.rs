//! Zero-Knowledge Age Verification Circuit
//!
//! Implements arithmetic constraints verifying that a user satisfies
//! an age threshold (e.g. Age >= 18 or Age >= 21) without revealing
//! their birth year, exact age, or identification details.

use crate::zkp::r1cs::{ConstraintSystem, LinearCombination, Variable, WitnessTable};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Private Witness containing the confidential age information
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct AgeWitness {
    pub birth_year: u32,
    pub current_year: u32,
    pub user_salt: [u8; 32],
}

impl AgeWitness {
    pub fn compute_age(&self) -> u32 {
        if self.current_year >= self.birth_year {
            self.current_year - self.birth_year
        } else {
            0
        }
    }
}

/// Public parameters for the Age Verification predicate
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeCircuitConfig {
    pub age_threshold: u32,
    pub current_year: u32,
}

/// Synthesizes the Age Verification R1CS circuit
pub struct AgeVerificationCircuit {
    pub config: AgeCircuitConfig,
}

impl AgeVerificationCircuit {
    pub fn new(threshold: u32, current_year: u32) -> Self {
        Self {
            config: AgeCircuitConfig {
                age_threshold: threshold,
                current_year,
            },
        }
    }

    /// Compiles the circuit into an R1CS constraint system
    pub fn synthesize(&self, cs: &mut ConstraintSystem) -> (Variable, Vec<Variable>) {
        // 1. Allocate Public Inputs
        let threshold_var = cs.alloc_public_input("age_threshold");
        let current_year_var = cs.alloc_public_input("current_year");

        // 2. Allocate Private Witness Variables
        let birth_year_var = cs.alloc_variable(Some("birth_year"));
        let calculated_age_var = cs.alloc_variable(Some("calculated_age"));
        let diff_var = cs.alloc_variable(Some("age_minus_threshold"));

        // Constraint 1: birth_year + calculated_age = current_year
        let mut age_sum = LinearCombination::from_var(birth_year_var);
        age_sum.add_term(calculated_age_var, 1);
        cs.enforce(
            age_sum,
            LinearCombination::from_const(1),
            LinearCombination::from_var(current_year_var),
            Some("age_definition: birth_year + age = current_year"),
        );

        // Constraint 2: calculated_age - threshold = diff
        let mut age_diff = LinearCombination::from_var(calculated_age_var);
        age_diff.add_term(threshold_var, u64::MAX); // -threshold
        cs.enforce(
            age_diff,
            LinearCombination::from_const(1),
            LinearCombination::from_var(diff_var),
            Some("difference: age - threshold = diff"),
        );

        // Constraint 3: Bit-decomposition of `diff` (7 bits for range [0, 127])
        // Guarantees diff >= 0 without arithmetic underflow
        let mut bit_vars = Vec::with_capacity(7);
        let mut bit_sum = LinearCombination::zero();

        for i in 0..7 {
            let bit_v = cs.alloc_variable(Some("diff_bit"));
            cs.enforce_boolean(bit_v, Some("bit_is_boolean"));
            bit_sum.add_term(bit_v, 1 << i);
            bit_vars.push(bit_v);
        }

        // Constraint 4: sum(2^i * bit_i) = diff
        cs.enforce(
            bit_sum,
            LinearCombination::from_const(1),
            LinearCombination::from_var(diff_var),
            Some("range_proof: bit_decomposition == diff"),
        );

        (diff_var, bit_vars)
    }

    /// Generates a valid witness assignment if the witness satisfies the predicate
    pub fn generate_witness(
        &self,
        cs: &ConstraintSystem,
        witness: &AgeWitness,
    ) -> Result<WitnessTable, &'static str> {
        let age = witness.compute_age();
        if age < self.config.age_threshold {
            return Err("Witness does not satisfy age threshold (predicate failed)");
        }

        let diff = (age - self.config.age_threshold) as u64;
        if diff >= 128 {
            return Err("Age difference out of supported 7-bit range");
        }

        let mut table = WitnessTable::new(cs.num_variables);

        // Public inputs
        table.set(Variable(1), self.config.age_threshold as u64);
        table.set(Variable(2), self.config.current_year as u64);

        // Witness
        table.set(Variable(3), witness.birth_year as u64);
        table.set(Variable(4), age as u64);
        table.set(Variable(5), diff);

        // Bits
        for i in 0..7 {
            let bit_val = (diff >> i) & 1;
            table.set(Variable(6 + i), bit_val);
        }

        Ok(table)
    }
}
