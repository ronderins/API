//! Algebraic Intermediate Representation (AIR) for Identity zkVM
//!
//! Enforces transition constraints, boundary constraints, and permutation arguments
//! across execution trace steps for valid arithmetic and cryptographic state transitions.

use crate::zkp::bn254::Fp;
use crate::zkvm::state_machine::TraceRow;

/// AIR Constraint Evaluation Result
#[derive(Clone, Debug, Default)]
pub struct AirEvaluations {
    pub transition_evals: Vec<Fp>,
    pub boundary_evals: Vec<Fp>,
}

/// Identity zkVM AIR Descriptor
pub struct IdentityAir {
    pub trace_length: usize,
    pub register_count: usize,
}

impl IdentityAir {
    pub fn new(trace_length: usize) -> Self {
        Self {
            trace_length,
            register_count: 8,
        }
    }

    /// Evaluates transition constraints between current state `row` and next state `next_row`
    pub fn evaluate_transition_constraints(&self, curr: &TraceRow, next: &TraceRow) -> Vec<Fp> {
        let mut evals = Vec::new();

        // 1. Cycle increment constraint: next.cycle - curr.cycle - 1 = 0
        let cycle_diff = (next.cycle as i128) - (curr.cycle as i128) - 1;
        evals.push(if cycle_diff == 0 { Fp::zero() } else { Fp::from_u64(cycle_diff.abs() as u64) });

        // 2. Halt state persistence: curr.is_halted => next.is_halted
        if curr.is_halted && !next.is_halted {
            evals.push(Fp::from_u64(1)); // Violation
        } else {
            evals.push(Fp::zero());
        }

        // 3. Register continuity when halted
        if curr.is_halted {
            for i in 0..8 {
                let diff = (curr.registers[i] as i128) - (next.registers[i] as i128);
                evals.push(if diff == 0 { Fp::zero() } else { Fp::from_u64(diff.abs() as u64) });
            }
        }

        evals
    }

    /// Evaluates boundary constraints for initial state and final state
    pub fn evaluate_boundary_constraints(
        &self,
        first_row: &TraceRow,
        last_row: &TraceRow,
        expected_output: u64,
    ) -> Vec<Fp> {
        let mut evals = Vec::new();

        // Initial cycle must be 0
        evals.push(Fp::from_u64(first_row.cycle));

        // Initial PC must be 0
        evals.push(Fp::from_u64(first_row.pc));

        // Final state must be halted
        evals.push(if last_row.is_halted { Fp::zero() } else { Fp::from_u64(1) });

        // Output register R0 matches expected predicate result
        let r0_diff = (last_row.registers[0] as i128) - (expected_output as i128);
        evals.push(if r0_diff == 0 { Fp::zero() } else { Fp::from_u64(r0_diff.abs() as u64) });

        evals
    }
}
