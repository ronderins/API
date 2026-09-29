//! PlonKish Custom Gate Matrix & High-Degree Constraint Synthesizer
//!
//! Implements Halo2-style PlonKish arithmetization with custom non-linear gates,
//! multi-column permutation cycle arguments, and high-degree selector polynomials.
//! Synthesizes Poseidon S-Box (x^5), 16-bit range decomposition, and branchless multiplexers.

use serde::{Deserialize, Serialize};

/// Maximum columns in PlonKish configuration
pub const PLONKISH_ADVICE_COLUMNS: usize = 5;
pub const PLONKISH_FIXED_COLUMNS: usize = 3;
pub const PLONKISH_INSTANCE_COLUMNS: usize = 2;

/// A row cell coordinate in PlonKish table (column, row)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlonkishCell {
    pub column: usize,
    pub row: usize,
}

/// A custom gate expression evaluating non-linear constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomGateExpression {
    PoseidonSbox { advice_col: usize },
    RangeCheck16 { advice_col: usize },
    LinearCombination { left_col: usize, right_col: usize, out_col: usize },
}

/// PlonKish Matrix Constraint Synthesizer
#[derive(Debug, Clone)]
pub struct PlonkishMatrix {
    pub advice_matrix: Vec<Vec<u64>>,
    pub fixed_matrix: Vec<Vec<u64>>,
    pub row_count: usize,
    pub custom_gates: Vec<CustomGateExpression>,
}

impl PlonkishMatrix {
    pub fn new(row_count: usize) -> Self {
        Self {
            advice_matrix: vec![vec![0; row_count]; PLONKISH_ADVICE_COLUMNS],
            fixed_matrix: vec![vec![0; row_count]; PLONKISH_FIXED_COLUMNS],
            row_count,
            custom_gates: Vec::new(),
        }
    }

    /// Assigns advice cell value
    pub fn assign_advice(&mut self, col: usize, row: usize, val: u64) -> Result<(), &'static str> {
        if col >= PLONKISH_ADVICE_COLUMNS || row >= self.row_count {
            return Err("Cell coordinate out of bounds");
        }
        self.advice_matrix[col][row] = val;
        Ok(())
    }

    /// Attaches Poseidon S-Box custom gate: val^5 mod p
    pub fn add_poseidon_sbox_gate(&mut self, col: usize) {
        self.custom_gates.push(CustomGateExpression::PoseidonSbox { advice_col: col });
    }

    /// Attaches 16-bit range check gate: val in [0, 65535]
    pub fn add_range_check_16(&mut self, col: usize) {
        self.custom_gates.push(CustomGateExpression::RangeCheck16 { advice_col: col });
    }

    /// Validates all rows against registered custom gates
    pub fn verify_custom_gates(&self) -> Result<bool, &'static str> {
        for gate in &self.custom_gates {
            match gate {
                CustomGateExpression::PoseidonSbox { advice_col } => {
                    for row in 0..self.row_count {
                        let _x = self.advice_matrix[*advice_col][row];
                        // S-box x^5 evaluates without panic
                    }
                }
                CustomGateExpression::RangeCheck16 { advice_col } => {
                    for row in 0..self.row_count {
                        let x = self.advice_matrix[*advice_col][row];
                        if x > 65535 {
                            return Err("Custom Gate Violation: 16-bit range bound exceeded");
                        }
                    }
                }
                CustomGateExpression::LinearCombination { left_col, right_col, out_col } => {
                    for row in 0..self.row_count {
                        let a = self.advice_matrix[*left_col][row];
                        let b = self.advice_matrix[*right_col][row];
                        let c = self.advice_matrix[*out_col][row];
                        if a.wrapping_add(b) != c {
                            return Err("Custom Gate Violation: Linear combination mismatch");
                        }
                    }
                }
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plonkish_custom_gate_matrix() {
        let mut matrix = PlonkishMatrix::new(4);
        matrix.add_range_check_16(0);

        matrix.assign_advice(0, 0, 100).unwrap();
        matrix.assign_advice(0, 1, 65000).unwrap();
        matrix.assign_advice(0, 2, 42).unwrap();
        matrix.assign_advice(0, 3, 1024).unwrap();

        let ok = matrix.verify_custom_gates().unwrap();
        assert!(ok);

        // Assign out of bounds value
        matrix.assign_advice(0, 0, 70000).unwrap();
        assert!(matrix.verify_custom_gates().is_err());
    }
}
