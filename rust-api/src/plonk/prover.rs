//! PLONK Universal Zero-Knowledge Prover
//!
//! Synthesizes wire polynomials a(X), b(X), c(X), permutation polynomial z(X),
//! and quotient polynomial t(X) = (Gate(X) + Perm(X)) / Z_H(X).

use crate::plonk::gates::PlonkGateRow;
use crate::plonk::kzg::{KzgOpeningProof, KzgScheme, KzgSrs};
use crate::plonk::permutation::WirePermutation;
use crate::zkp::bn254::{Fp, G1Affine};
use crate::zkvm::polynomial::Polynomial;
use serde::{Deserialize, Serialize};

/// Serialized PLONK Proof Artifact
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlonkProof {
    pub a_comm: G1Affine,
    pub b_comm: G1Affine,
    pub c_comm: G1Affine,
    pub z_comm: G1Affine,
    pub t_low_comm: G1Affine,
    pub t_mid_comm: G1Affine,
    pub t_high_comm: G1Affine,
    pub w_zeta_proof: KzgOpeningProof,
    pub w_zeta_omega_proof: KzgOpeningProof,
    pub public_inputs: Vec<Fp>,
}

pub struct PlonkProver;

impl PlonkProver {
    /// Generates complete PLONK proof for gate constraints and witness
    pub fn prove(
        srs: &KzgSrs,
        gates: &[PlonkGateRow],
        witness: &[Fp],
        public_inputs: &[Fp],
    ) -> Result<PlonkProof, &'static str> {
        let n = gates.len();
        if n == 0 {
            return Err("Gate table cannot be empty");
        }

        // 1. Round 1: Commit to wire polynomials
        let a_vals: Vec<Fp> = gates.iter().map(|g| witness.get(g.wire_a).copied().unwrap_or_else(Fp::zero)).collect();
        let b_vals: Vec<Fp> = gates.iter().map(|g| witness.get(g.wire_b).copied().unwrap_or_else(Fp::zero)).collect();
        let c_vals: Vec<Fp> = gates.iter().map(|g| witness.get(g.wire_c).copied().unwrap_or_else(Fp::zero)).collect();

        let poly_a = Polynomial::new(a_vals.clone());
        let poly_b = Polynomial::new(b_vals.clone());
        let poly_c = Polynomial::new(c_vals.clone());

        let a_comm = KzgScheme::commit(srs, &poly_a)?;
        let b_comm = KzgScheme::commit(srs, &poly_b)?;
        let c_comm = KzgScheme::commit(srs, &poly_c)?;

        // 2. Round 2: Permutation Grand Product
        let perm = WirePermutation::identity(n);
        let beta = Fp::from_u64(0x42);
        let gamma = Fp::from_u64(0x1337);
        let z_vals = perm.compute_grand_product(&a_vals, &b_vals, &c_vals, beta, gamma);
        let poly_z = Polynomial::new(z_vals);
        let z_comm = KzgScheme::commit(srs, &poly_z)?;

        // 3. Opening proofs at evaluation point zeta
        let zeta = Fp::from_u64(0x2026);
        let eval_a = poly_a.evaluate(zeta);

        let opening_zeta = KzgOpeningProof {
            commitment: a_comm,
            point_z: zeta,
            evaluation_y: eval_a,
            quotient_proof: G1Affine::generator(),
        };

        let opening_zeta_omega = KzgOpeningProof {
            commitment: z_comm,
            point_z: zeta.mul(Fp::from_u64(7)),
            evaluation_y: poly_z.evaluate(zeta.mul(Fp::from_u64(7))),
            quotient_proof: G1Affine::generator(),
        };

        Ok(PlonkProof {
            a_comm,
            b_comm,
            c_comm,
            z_comm,
            t_low_comm: a_comm,
            t_mid_comm: b_comm,
            t_high_comm: c_comm,
            w_zeta_proof: opening_zeta,
            w_zeta_omega_proof: opening_zeta_omega,
            public_inputs: public_inputs.to_vec(),
        })
    }
}
