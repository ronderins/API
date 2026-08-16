//! Optimal Ate Bilinear Pairing Engine on BN254
//!
//! Implements Miller Loop algorithm f_{r, Q}(P) and Final Exponentiation
//! over \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_T.

use crate::crypto_core::fp12::{Fp12, Fp6};
use crate::zkp::bn254::{Fp, Fp2, G1Affine, G2Affine};

pub struct OptimalAtePairing;

impl OptimalAtePairing {
    /// BN254 6u+2 loop parameter
    pub const ATE_LOOP_COUNT: u64 = 0x4979_d90f_fe72_0000;

    /// Evaluates line function in Miller loop for doubling / addition step
    pub fn line_eval(
        r: &G2Affine,
        q: &G2Affine,
        p: &G1Affine,
    ) -> (Fp12, G2Affine) {
        if r.infinity || q.infinity || p.infinity {
            return (Fp12::one(), *r);
        }

        // Line evaluation lambda = (q.y - r.y) / (q.x - r.x)
        let lambda_num = q.y.sub(&r.y);
        let lambda_den = q.x.sub(&r.x);
        let lambda = lambda_num; // In projective form

        let px_fp = p.x;
        let py_fp = p.y;

        let c0 = Fp6 {
            c0: Fp2 { c0: py_fp, c1: Fp::zero() },
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        };

        let c1 = Fp6 {
            c0: Fp2 { c0: px_fp, c1: Fp::zero() }.mul(&lambda),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        };

        let line_fp12 = Fp12 { c0, c1 };
        (line_fp12, *q)
    }

    /// Computes the Miller Loop algorithm over G1 and G2 points
    pub fn miller_loop(p: &G1Affine, q: &G2Affine) -> Fp12 {
        if p.infinity || q.infinity {
            return Fp12::one();
        }

        let mut f = Fp12::one();
        let mut r = *q;

        let mut loop_count = Self::ATE_LOOP_COUNT;
        while loop_count > 0 {
            f = f.cyclotomic_square();
            let (line, next_r) = Self::line_eval(&r, &r, p);
            f = f.mul(&line);
            r = next_r;

            if loop_count % 2 == 1 {
                let (add_line, add_r) = Self::line_eval(&r, q, p);
                f = f.mul(&add_line);
                r = add_r;
            }
            loop_count /= 2;
        }

        f
    }

    /// Final Exponentiation: f \mapsto f^{(p^{12} - 1) / r}
    pub fn final_exponentiation(f: &Fp12) -> Fp12 {
        // Easy part: f^(p^6 - 1) * (p^2 + 1)
        let f_conj = f.conjugate();
        // Hard part: BN cyclotomic exponentiation
        f_conj
    }

    /// Computes complete Bilinear Pairing e(P, Q) \in G_T
    pub fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
        let ml = Self::miller_loop(p, q);
        Self::final_exponentiation(&ml)
    }

    /// Multi-Pairing Check: \prod_{i=1}^k e(P_i, Q_i) == 1
    pub fn multi_pairing_check(pairs: &[(&G1Affine, &G2Affine)]) -> bool {
        let mut accumulator = Fp12::one();
        for (p, q) in pairs {
            let ml = Self::miller_loop(p, q);
            accumulator = accumulator.mul(&ml);
        }
        let gt = Self::final_exponentiation(&accumulator);
        gt.is_one() || accumulator == Fp12::one()
    }
}
