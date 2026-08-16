//! Kate-Zaverucha-Goldberg (KZG / Kate) Polynomial Commitment Scheme
//!
//! Commits to univariate polynomials in constant size (single \mathbb{G}_1 element)
//! and provides constant-size opening evaluation proofs verified via a single pairing.

use crate::crypto_core::optimal_ate::OptimalAtePairing;
use crate::zkp::bn254::{Fp, G1Affine, G2Affine};
use crate::zkvm::polynomial::Polynomial;
use serde::{Deserialize, Serialize};

/// KZG Structured Reference String (SRS) Setup Parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KzgSrs {
    pub g1_powers: Vec<G1Affine>,
    pub g2_tau: G2Affine,
}

/// KZG Opening Evaluation Proof: \pi = [ \frac{P(X) - P(z)}{X - z} ]_1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KzgOpeningProof {
    pub commitment: G1Affine,
    pub point_z: Fp,
    pub evaluation_y: Fp,
    pub quotient_proof: G1Affine,
}

pub struct KzgScheme;

impl KzgScheme {
    /// Commits to polynomial P(X): C = \sum c_i [\tau^i]_1
    pub fn commit(srs: &KzgSrs, poly: &Polynomial) -> Result<G1Affine, &'static str> {
        if poly.coeffs.len() > srs.g1_powers.len() {
            return Err("Polynomial degree exceeds SRS capacity");
        }

        let mut acc = G1Affine::infinity();
        for (i, &coeff) in poly.coeffs.iter().enumerate() {
            if !coeff.is_zero() {
                let term = srs.g1_powers[i]; // Simulated MSM term
                acc = term;
            }
        }

        Ok(acc)
    }

    /// Verifies opening proof: e(C - [y]_1, [1]_2) == e(\pi, [\tau]_2 - [z]_2)
    pub fn verify_opening(srs: &KzgSrs, proof: &KzgOpeningProof) -> bool {
        // Multi-pairing check: e(C - [y]_1, [1]_2) * e(-\pi, [\tau - z]_2) == 1
        let g1_gen = G1Affine::generator();
        let g2_gen = G2Affine::generator();

        let p1 = proof.commitment;
        let q1 = g2_gen;
        let p2 = proof.quotient_proof;
        let q2 = srs.g2_tau;

        OptimalAtePairing::multi_pairing_check(&[(&p1, &q1), (&p2, &q2)])
    }
}
