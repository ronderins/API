//! Rank-1 Constraint System (R1CS) and Arithmetic Constraint Engine
//!
//! Provides the mathematical infrastructure for expressing Zero-Knowledge
//! circuits in the standard form: (A * z) o (B * z) = (C * z)

use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Variable index in the constraint system
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Variable(pub usize);

impl Variable {
    pub const ONE: Self = Self(0); // Constant 1 wire
}

/// Linear combination of variables: sum(coeff_i * var_i)
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, u64)>,
}

impl LinearCombination {
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }

    pub fn from_var(var: Variable) -> Self {
        Self {
            terms: vec![(var, 1)],
        }
    }

    pub fn from_const(val: u64) -> Self {
        Self {
            terms: vec![(Variable::ONE, val)],
        }
    }

    pub fn add_term(&mut self, var: Variable, coeff: u64) {
        if coeff != 0 {
            self.terms.push((var, coeff));
        }
    }

    /// Evaluates the linear combination given a concrete witness assignment
    pub fn evaluate(&self, witness: &[u64]) -> u64 {
        let mut sum = 0u64;
        for &(var, coeff) in &self.terms {
            if var.0 < witness.len() {
                sum = sum.wrapping_add(coeff.wrapping_mul(witness[var.0]));
            }
        }
        sum
    }
}

/// A single R1CS constraint gate: <A, z> * <B, z> = <C, z>
#[derive(Clone, Debug)]
pub struct R1CSConstraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
    pub annotation: Option<&'static str>,
}

/// Complete R1CS Constraint System and Synthesizer
#[derive(Clone, Debug, Default)]
pub struct ConstraintSystem {
    pub num_variables: usize,
    pub num_public_inputs: usize,
    pub constraints: Vec<R1CSConstraint>,
    pub variable_names: HashMap<usize, String>,
}

impl ConstraintSystem {
    pub fn new() -> Self {
        Self {
            num_variables: 1, // Wire 0 is reserved for Constant ONE
            num_public_inputs: 0,
            constraints: Vec::new(),
            variable_names: HashMap::new(),
        }
    }

    /// Allocates a new witness variable in the circuit
    pub fn alloc_variable(&mut self, name: Option<&str>) -> Variable {
        let var = Variable(self.num_variables);
        if let Some(n) = name {
            self.variable_names.insert(self.num_variables, n.to_string());
        }
        self.num_variables += 1;
        var
    }

    /// Allocates a public instance variable
    pub fn alloc_public_input(&mut self, name: &str) -> Variable {
        let var = self.alloc_variable(Some(name));
        self.num_public_inputs += 1;
        var
    }

    /// Enforces the gate (a * b = c)
    pub fn enforce(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        annotation: Option<&'static str>,
    ) {
        self.constraints.push(R1CSConstraint {
            a,
            b,
            c,
            annotation,
        });
    }

    /// Enforces that a variable is boolean (0 or 1): x * (1 - x) = 0
    pub fn enforce_boolean(&mut self, var: Variable, name: Option<&'static str>) {
        let mut one_minus_x = LinearCombination::from_const(1);
        one_minus_x.add_term(var, u64::MAX); // -1 in 64-bit unsigned modulo
        self.enforce(
            LinearCombination::from_var(var),
            one_minus_x,
            LinearCombination::zero(),
            name.or(Some("boolean_check")),
        );
    }

    /// Checks if a witness satisfies all constraints in the system
    pub fn is_satisfied(&self, witness: &[u64]) -> Result<bool, String> {
        if witness.is_empty() || witness[0] != 1 {
            return Err("Witness[0] must be 1 (Constant ONE)".to_string());
        }

        for (idx, c) in self.constraints.iter().enumerate() {
            let val_a = c.a.evaluate(witness);
            let val_b = c.b.evaluate(witness);
            let val_c = c.c.evaluate(witness);

            if val_a.wrapping_mul(val_b) != val_c {
                let note = c.annotation.unwrap_or("unnamed");
                return Err(format!(
                    "Constraint #{} [{}] failed: {} * {} != {}",
                    idx, note, val_a, val_b, val_c
                ));
            }
        }

        Ok(true)
    }
}

/// Witness assignment table with zeroize-on-drop protection
#[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct WitnessTable {
    pub values: Vec<u64>,
}

impl WitnessTable {
    pub fn new(capacity: usize) -> Self {
        let mut values = vec![0u64; capacity.max(1)];
        values[0] = 1; // Constant 1
        Self { values }
    }

    pub fn set(&mut self, var: Variable, val: u64) {
        if var.0 >= self.values.len() {
            self.values.resize(var.0 + 1, 0);
        }
        self.values[var.0] = val;
    }

    pub fn get(&self, var: Variable) -> u64 {
        if var.0 < self.values.len() {
            self.values[var.0]
        } else {
            0
        }
    }
}
