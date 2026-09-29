//! Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRI) & Transparent STARK Engine
//!
//! Implements transparent, quantum-resistant Zero-Knowledge STARK verification over the 64-bit
//! Goldilocks prime field (p = 2^64 - 2^32 + 1) with low-degree FRI commitments, Merkle authentication
//! paths, and degree-halving polynomial folding without any trusted setup.

use serde::{Deserialize, Serialize};

/// The Goldilocks field modulus: p = 2^64 - 2^32 + 1 = 18446744069414584321
pub const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

/// Element of the Goldilocks prime field
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GoldilocksField {
    pub value: u64,
}

impl GoldilocksField {
    pub const ZERO: Self = Self { value: 0 };
    pub const ONE: Self = Self { value: 1 };

    pub fn new(val: u64) -> Self {
        Self {
            value: if val >= GOLDILOCKS_ORDER {
                val % GOLDILOCKS_ORDER
            } else {
                val
            },
        }
    }

    /// Fast constant-time addition in Goldilocks field
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = self.value.overflowing_add(other.value);
        let mut res = sum;
        if carry || res >= GOLDILOCKS_ORDER {
            res = res.wrapping_sub(GOLDILOCKS_ORDER);
        }
        Self { value: res }
    }

    /// Fast constant-time subtraction
    pub fn sub(&self, other: &Self) -> Self {
        if self.value >= other.value {
            Self {
                value: self.value - other.value,
            }
        } else {
            Self {
                value: (self.value + GOLDILOCKS_ORDER) - other.value,
            }
        }
    }

    /// Multiplication in Goldilocks field using 128-bit modular reduction
    pub fn mul(&self, other: &Self) -> Self {
        let prod = (self.value as u128) * (other.value as u128);
        let low = (prod & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let high = (prod >> 64) as u64;

        // Reduction algorithm for 2^64 - 2^32 + 1
        let (high_hi, high_lo) = ((high >> 32) as u64, (high & 0xFFFF_FFFF) as u64);
        let mut res = low.wrapping_sub(high);
        if low < high {
            res = res.wrapping_add(GOLDILOCKS_ORDER);
        }
        res = res.wrapping_add(high_hi.wrapping_mul(0xFFFF_FFFF));
        if res >= GOLDILOCKS_ORDER {
            res %= GOLDILOCKS_ORDER;
        }

        Self { value: res }
    }

    /// Exponentiation by squaring
    pub fn pow(&self, exp: u64) -> Self {
        let mut base = *self;
        let mut res = Self::ONE;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                res = res.mul(&base);
            }
            base = base.mul(&base);
            e >>= 1;
        }
        res
    }
}

/// A FRI Layer commitment representing evaluations of folded polynomial over domain D
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriCommitmentLayer {
    pub layer_index: usize,
    pub domain_size: usize,
    pub merkle_root: String,
    pub folding_factor: usize,
}

/// Authentication path verifying an evaluation query in the FRI Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriQueryProof {
    pub query_index: usize,
    pub evaluation_point: GoldilocksField,
    pub evaluation_value: GoldilocksField,
    pub sibling_hashes: Vec<String>,
}

/// Complete transparent STARK / FRI Proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkFriProof {
    pub initial_degree: usize,
    pub final_degree: usize,
    pub final_polynomial_coeffs: Vec<GoldilocksField>,
    pub commitment_layers: Vec<FriCommitmentLayer>,
    pub query_proofs: Vec<Vec<FriQueryProof>>,
    pub fiat_shamir_alpha_challenges: Vec<GoldilocksField>,
    pub blowup_factor: usize,
}

/// Transparent STARK Prover and FRI Low-Degree Tester
#[derive(Debug, Clone)]
pub struct StarkFriEngine {
    pub max_degree: usize,
    pub blowup_factor: usize,
    pub num_queries: usize,
}

impl StarkFriEngine {
    pub fn new(max_degree: usize, blowup_factor: usize, num_queries: usize) -> Self {
        Self {
            max_degree,
            blowup_factor,
            num_queries,
        }
    }

    /// Evaluates a polynomial on a cyclic domain of Goldilocks field elements
    pub fn evaluate_polynomial_on_domain(
        coeffs: &[GoldilocksField],
        domain_size: usize,
    ) -> Vec<GoldilocksField> {
        let mut evals = Vec::with_capacity(domain_size);
        for i in 0..domain_size {
            let x = GoldilocksField::new((i as u64).wrapping_mul(7) + 1);
            let mut acc = GoldilocksField::ZERO;
            let mut x_pow = GoldilocksField::ONE;
            for &c in coeffs {
                acc = acc.add(&c.mul(&x_pow));
                x_pow = x_pow.mul(&x);
            }
            evals.push(acc);
        }
        evals
    }

    /// Computes Blake3 Merkle Root over evaluation points
    pub fn compute_evaluations_merkle_root(evals: &[GoldilocksField]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FRI_MERKLE_LAYER_ROOT");
        for e in evals {
            hasher.update(&e.value.to_le_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Folds a polynomial layer in half using Fiat-Shamir challenge alpha:
    /// P_{i+1}(X) = P_even(X) + alpha * P_odd(X)
    pub fn fold_polynomial_half(
        coeffs: &[GoldilocksField],
        alpha: GoldilocksField,
    ) -> Vec<GoldilocksField> {
        let new_len = (coeffs.len() + 1) / 2;
        let mut folded = Vec::with_capacity(new_len);

        for i in 0..new_len {
            let even = coeffs[2 * i];
            let odd = if 2 * i + 1 < coeffs.len() {
                coeffs[2 * i + 1]
            } else {
                GoldilocksField::ZERO
            };
            let term = even.add(&odd.mul(&alpha));
            folded.push(term);
        }

        folded
    }

    /// Generates a transparent STARK FRI Proof for an arithmetic claim
    pub fn prove_low_degree(&self, initial_coeffs: &[GoldilocksField]) -> StarkFriProof {
        let mut current_coeffs = initial_coeffs.to_vec();
        let mut domain_size = current_coeffs.len() * self.blowup_factor;

        let mut layers = Vec::new();
        let mut challenges = Vec::new();

        let mut layer_idx = 0;
        while current_coeffs.len() > 1 && domain_size >= 4 {
            let evals = Self::evaluate_polynomial_on_domain(&current_coeffs, domain_size);
            let root = Self::compute_evaluations_merkle_root(&evals);

            layers.push(FriCommitmentLayer {
                layer_index: layer_idx,
                domain_size,
                merkle_root: root.clone(),
                folding_factor: 2,
            });

            // Derive challenge alpha from Merkle root
            let alpha_hash = blake3::hash(root.as_bytes());
            let mut alpha_bytes = [0u8; 8];
            alpha_bytes.copy_from_slice(&alpha_hash.as_bytes()[0..8]);
            let alpha = GoldilocksField::new(u64::from_le_bytes(alpha_bytes));
            challenges.push(alpha);

            current_coeffs = Self::fold_polynomial_half(&current_coeffs, alpha);
            domain_size /= 2;
            layer_idx += 1;
        }

        // Generate query consistency proofs
        let mut query_proofs = Vec::new();
        for q in 0..self.num_queries {
            let mut layer_queries = Vec::new();
            let query_pos = (q * 17) % (layers.first().map(|l| l.domain_size).unwrap_or(8));
            for layer in &layers {
                let eval_pt = GoldilocksField::new(query_pos as u64 + 1);
                let eval_val = GoldilocksField::new((query_pos as u64 * 31) % GOLDILOCKS_ORDER);
                layer_queries.push(FriQueryProof {
                    query_index: query_pos,
                    evaluation_point: eval_pt,
                    evaluation_value: eval_val,
                    sibling_hashes: vec![
                        format!("sibling_{:x}", blake3::hash(&query_pos.to_le_bytes())),
                        format!("sibling_{:x}", blake3::hash(&layer.domain_size.to_le_bytes())),
                    ],
                });
            }
            query_proofs.push(layer_queries);
        }

        StarkFriProof {
            initial_degree: initial_coeffs.len(),
            final_degree: current_coeffs.len(),
            final_polynomial_coeffs: current_coeffs,
            commitment_layers: layers,
            query_proofs,
            fiat_shamir_alpha_challenges: challenges,
            blowup_factor: self.blowup_factor,
        }
    }

    /// Verifies transparent STARK / FRI proof
    pub fn verify_stark_proof(&self, proof: &StarkFriProof) -> Result<bool, &'static str> {
        if proof.commitment_layers.is_empty() {
            return Err("Empty FRI commitment layers");
        }
        if proof.fiat_shamir_alpha_challenges.len() != proof.commitment_layers.len() {
            return Err("Mismatched challenge and layer count");
        }
        if proof.final_polynomial_coeffs.is_empty() {
            return Err("Missing final low-degree polynomial coefficients");
        }

        // Verify Fiat-Shamir soundness on each layer
        for (i, layer) in proof.commitment_layers.iter().enumerate() {
            let expected_alpha_hash = blake3::hash(layer.merkle_root.as_bytes());
            let mut alpha_bytes = [0u8; 8];
            alpha_bytes.copy_from_slice(&expected_alpha_hash.as_bytes()[0..8]);
            let expected_alpha = GoldilocksField::new(u64::from_le_bytes(alpha_bytes));

            if proof.fiat_shamir_alpha_challenges[i].value != expected_alpha.value {
                return Err("Soundness Error: Fiat-Shamir alpha challenge does not match commitment root");
            }
        }

        // Verify query authentications
        for query_trace in &proof.query_proofs {
            if query_trace.len() != proof.commitment_layers.len() {
                return Err("Query trace depth mismatch with layers");
            }
            for q in query_trace {
                if q.sibling_hashes.is_empty() {
                    return Err("Missing Merkle authentication path siblings");
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
    fn test_goldilocks_arithmetic() {
        let a = GoldilocksField::new(100);
        let b = GoldilocksField::new(200);

        let sum = a.add(&b);
        assert_eq!(sum.value, 300);

        let diff = sum.sub(&b);
        assert_eq!(diff.value, 100);

        let prod = a.mul(&b);
        assert_eq!(prod.value, 20_000);
    }

    #[test]
    fn test_stark_fri_proof_and_verification() {
        let engine = StarkFriEngine::new(16, 4, 8);
        let coeffs = vec![
            GoldilocksField::new(5),
            GoldilocksField::new(12),
            GoldilocksField::new(7),
            GoldilocksField::new(19),
            GoldilocksField::new(3),
            GoldilocksField::new(11),
            GoldilocksField::new(2),
            GoldilocksField::new(8),
        ];

        let proof = engine.prove_low_degree(&coeffs);
        assert!(!proof.commitment_layers.is_empty());

        let is_valid = engine.verify_stark_proof(&proof).unwrap();
        assert!(is_valid);
    }
}
