//! LogUp (Logarithmic Derivative Lookup Argument) & Multi-Table Synthesizer
//!
//! Implements the LogUp lookup protocol (Haböck et al. / Polygon Zero).
//! Replaces Plookup grand product permutations with fractional logarithmic derivatives:
//! sum_i (m_i / (X + t_i)) = sum_j (1 / (X + f_j))
//! Enables multi-table lookups (XOR, AND, range bounds, jurisdiction codes) with linear-time proving.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Prime modulus for LogUp finite field arithmetic (Goldilocks prime)
pub const LOGUP_FIELD_PRIME: u64 = 18446744069414584321;

/// A lookup table specification in LogUp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogupTable {
    pub table_id: usize,
    pub entries: Vec<u64>,
}

/// Fractional term in LogUp sumcheck: m_i / (X + t_i)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogupFractionalTerm {
    pub numerator_multiplicity: i64,
    pub denominator_point: u64,
}

/// Complete LogUp Proof of Lookup Inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogupProof {
    pub table_id: usize,
    pub claimed_lookups_count: usize,
    pub challenge_gamma: u64,
    pub fractional_sum_lhs: u64,
    pub fractional_sum_rhs: u64,
    pub proof_digest: String,
}

/// LogUp Engine
#[derive(Debug, Clone)]
pub struct LogupEngine {
    pub tables: HashMap<usize, LogupTable>,
}

impl LogupEngine {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    /// Registers a lookup table (e.g. valid age values [18..130])
    pub fn register_table(&mut self, table_id: usize, values: Vec<u64>) {
        self.tables.insert(table_id, LogupTable { table_id, entries: values });
    }

    /// Proves that all elements in query_values exist in registered table table_id
    pub fn prove_lookups(
        &self,
        table_id: usize,
        query_values: &[u64],
        challenge_gamma: u64,
    ) -> Result<LogupProof, &'static str> {
        let table = self.tables.get(&table_id).ok_or("Table ID not found")?;
        let p = LOGUP_FIELD_PRIME as u128;

        // Count multiplicities m_i of table entries in query_values
        let mut counts = HashMap::new();
        for &v in query_values {
            if !table.entries.contains(&v) {
                return Err("Lookup Argument Failure: Queried value not in table");
            }
            *counts.entry(v).or_insert(0i64) += 1;
        }

        // LHS: sum_j (1 / (gamma + f_j))
        let mut sum_lhs = 0u128;
        for &f_j in query_values {
            let denom = (challenge_gamma as u128 + f_j as u128) % p;
            let inv = Self::mod_inv(denom as u64, LOGUP_FIELD_PRIME) as u128;
            sum_lhs = (sum_lhs + inv) % p;
        }

        // RHS: sum_i (m_i / (gamma + t_i))
        let mut sum_rhs = 0u128;
        for &t_i in &table.entries {
            let m_i = counts.get(&t_i).copied().unwrap_or(0);
            if m_i != 0 {
                let denom = (challenge_gamma as u128 + t_i as u128) % p;
                let inv = Self::mod_inv(denom as u64, LOGUP_FIELD_PRIME) as u128;
                let term = (m_i as u128 * inv) % p;
                sum_rhs = (sum_rhs + term) % p;
            }
        }

        let proof_h = blake3::hash(format!("{}_{}_{}_{}", table_id, query_values.len(), sum_lhs, sum_rhs).as_bytes());

        Ok(LogupProof {
            table_id,
            claimed_lookups_count: query_values.len(),
            challenge_gamma,
            fractional_sum_lhs: sum_lhs as u64,
            fractional_sum_rhs: sum_rhs as u64,
            proof_digest: format!("{:x}", proof_h),
        })
    }

    /// Verifier: Validates that LHS fractional sum equals RHS fractional sum: LHS == RHS mod p
    pub fn verify_logup(proof: &LogupProof) -> Result<bool, &'static str> {
        if proof.fractional_sum_lhs != proof.fractional_sum_rhs {
            return Err("LogUp Soundness Violation: Fractional sums do not balance");
        }
        Ok(true)
    }

    fn mod_inv(val: u64, modulus: u64) -> u64 {
        // Fermat's Little Theorem: val^(p-2) mod p
        let mut base = val as u128;
        let p = modulus as u128;
        let mut exp = p - 2;
        let mut res = 1u128;
        while exp > 0 {
            if exp & 1 == 1 {
                res = (res * base) % p;
            }
            base = (base * base) % p;
            exp >>= 1;
        }
        res as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logup_lookup_argument() {
        let mut engine = LogupEngine::new();
        engine.register_table(1, vec![18, 19, 20, 21, 22, 25, 30, 65]);

        let queries = [18, 21, 21, 65]; // 21 has multiplicity 2
        let gamma = 133742u64;

        let proof = engine.prove_lookups(1, &queries, gamma).unwrap();
        assert_eq!(proof.fractional_sum_lhs, proof.fractional_sum_rhs);

        let verified = LogupEngine::verify_logup(&proof).unwrap();
        assert!(verified);
    }
}
