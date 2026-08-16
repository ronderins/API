//! Precomputed BN254 Elliptic Curve Constants & Endomorphism Parameters
//!
//! Gallant-Lambert-Vanstone (GLV) and Frobenius endomorphisms for accelerating
//! scalar multiplication [k]P = [k_1]P + [k_2]\lambda P.

use crate::zkp::bn254::Fp;

pub struct Bn254Constants;

impl Bn254Constants {
    /// Curve Equation parameter b = 3 in y^2 = x^3 + 3
    pub const CURVE_B: u64 = 3;

    /// Cube root of unity \beta \in \mathbb{F}_p for GLV endomorphism \psi(x, y) = (\beta x, y)
    pub const GLV_BETA: [u64; 4] = [
        0x79344c824fcdf6e7,
        0x5ee76b55f9c2f67b,
        0x67b6daf004617f13,
        0x2acda73273e3a39b,
    ];

    /// Frobenius constant \gamma_{1, 1} = \xi^{(p-1)/6}
    pub const FROBENIUS_GAMMA_11: [u64; 4] = [
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ];

    /// Windowed NAF Precomputed Multiples Table for G1 Generator
    pub const G1_PRECOMPUTED_TABLE_SIZE: usize = 256;
}
