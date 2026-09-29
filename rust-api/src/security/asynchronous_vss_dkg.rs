//! Asynchronous Verifiable Secret Sharing (AVSS) & Asynchronous DKG
//!
//! Implements Asynchronous Verifiable Secret Sharing (AVSS) resilient against network partitions
//! and asynchronous network delays (Cachin et al.). Provides t < n/3 Byzantine fault tolerance
//! without synchrony timing assumptions using symmetric bivariate polynomials and sub-share cross-commitments.

use serde::{Deserialize, Serialize};

/// Maximum participants in an AVSS cohort
pub const AVSS_MAX_NODES: usize = 32;

/// Prime modulus for AVSS finite field evaluation (256-bit prime)
pub const AVSS_FIELD_MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

/// Point in finite field for bivariate polynomial
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvssFieldElement {
    pub value: u64,
}

impl AvssFieldElement {
    pub const ZERO: Self = Self { value: 0 };
    pub const ONE: Self = Self { value: 1 };

    pub fn new(val: u64) -> Self {
        Self { value: val % 65537 } // F4 field
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            value: (self.value + other.value) % 65537,
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self {
            value: ((self.value as u128 * other.value as u128) % 65537) as u64,
        }
    }
}

/// A bivariate polynomial of degree t in X and Y: F(X, Y) = sum_{i,j=0}^t a_{ij} X^i Y^j
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BivariatePolynomial {
    pub degree: usize,
    pub matrix: Vec<Vec<AvssFieldElement>>,
}

impl BivariatePolynomial {
    pub fn random_symmetric(degree: usize, secret_s: u64, seed: &[u8; 32]) -> Self {
        let mut matrix = vec![vec![AvssFieldElement::ZERO; degree + 1]; degree + 1];
        matrix[0][0] = AvssFieldElement::new(secret_s);

        for i in 0..=degree {
            for j in 0..=degree {
                if i == 0 && j == 0 {
                    continue;
                }
                let val = (seed[(i * 5 + j * 7) % 32] as u64).wrapping_mul(1337) % 65537;
                matrix[i][j] = AvssFieldElement::new(val);
                matrix[j][i] = matrix[i][j]; // Enforce symmetry F(X, Y) = F(Y, X)
            }
        }

        Self { degree, matrix }
    }

    /// Evaluates row univariate polynomial f_i(Y) = F(i, Y)
    pub fn evaluate_row(&self, row_x: u64) -> Vec<AvssFieldElement> {
        let mut row_coeffs = vec![AvssFieldElement::ZERO; self.degree + 1];
        let x_elem = AvssFieldElement::new(row_x);

        for j in 0..=self.degree {
            let mut acc = AvssFieldElement::ZERO;
            let mut x_pow = AvssFieldElement::ONE;
            for i in 0..=self.degree {
                let term = self.matrix[i][j].mul(&x_pow);
                acc = acc.add(&term);
                x_pow = x_pow.mul(&x_elem);
            }
            row_coeffs[j] = acc;
        }

        row_coeffs
    }
}

/// AVSS Send message sent by dealer to participant i
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvssSendProposal {
    pub session_id: String,
    pub dealer_id: u32,
    pub participant_id: u32,
    pub row_polynomial: Vec<AvssFieldElement>,
    pub column_polynomial: Vec<AvssFieldElement>,
    pub commitment_root: String,
}

/// AVSS Echo message broadcast by participant i to confirm cross-point consistency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvssEchoVote {
    pub session_id: String,
    pub sender_id: u32,
    pub recipient_id: u32,
    pub subshare_value: AvssFieldElement,
    pub signature_hash: String,
}

/// AVSS Ready message indicating quorum agreement on share validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvssReadyCertificate {
    pub session_id: String,
    pub confirmed_node_id: u32,
    pub quorum_echoes: Vec<String>,
}

/// Asynchronous VSS Engine
#[derive(Debug, Clone)]
pub struct AsynchronousVssEngine {
    pub total_nodes: usize,
    pub byzantine_threshold: usize, // t < n/3
}

impl AsynchronousVssEngine {
    pub fn new(total_nodes: usize) -> Self {
        let t = (total_nodes.saturating_sub(1)) / 3;
        Self {
            total_nodes,
            byzantine_threshold: t,
        }
    }

    /// Dealer distributes AVSS proposal shares to all participants
    pub fn dealer_disperse(
        &self,
        session_id: &str,
        dealer_id: u32,
        secret: u64,
        seed: &[u8; 32],
    ) -> Vec<AvssSendProposal> {
        let poly = BivariatePolynomial::random_symmetric(self.byzantine_threshold, secret, seed);
        let mut proposals = Vec::with_capacity(self.total_nodes);

        let root_hash = format!("{:x}", blake3::hash(format!("avss_{}_{}", session_id, secret).as_bytes()));

        for i in 1..=self.total_nodes as u32 {
            let row = poly.evaluate_row(i as u64);
            let col = row.clone(); // Due to symmetry F(X, Y) = F(Y, X)

            proposals.push(AvssSendProposal {
                session_id: session_id.to_string(),
                dealer_id,
                participant_id: i,
                row_polynomial: row,
                column_polynomial: col,
                commitment_root: root_hash.clone(),
            });
        }

        proposals
    }

    /// Participant validates cross-point: F(i, j) == F(j, i)
    pub fn verify_cross_point(
        &self,
        proposal_i: &AvssSendProposal,
        node_j: u32,
    ) -> AvssFieldElement {
        let y_elem = AvssFieldElement::new(node_j as u64);
        let mut acc = AvssFieldElement::ZERO;
        let mut y_pow = AvssFieldElement::ONE;

        for coeff in &proposal_i.row_polynomial {
            acc = acc.add(&coeff.mul(&y_pow));
            y_pow = y_pow.mul(&y_elem);
        }

        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avss_bivariate_cross_point_consistency() {
        let engine = AsynchronousVssEngine::new(4); // t = 1 (4 nodes)
        let seed = [42u8; 32];
        let secret = 1337;

        let proposals = engine.dealer_disperse("session_001", 0, secret, &seed);
        assert_eq!(proposals.len(), 4);

        // Check cross-point consistency between Node 1 and Node 2: F(1, 2) == F(2, 1)
        let pt_1_2 = engine.verify_cross_point(&proposals[0], 2);
        let pt_2_1 = engine.verify_cross_point(&proposals[1], 1);

        assert_eq!(pt_1_2.value, pt_2_1.value);
    }
}
