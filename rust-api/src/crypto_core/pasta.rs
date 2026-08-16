//! Pallas and Vesta (Pasta) 2-Cycle Curves for Recursive ZK Proving
//!
//! Pallas: y^2 = x^3 + 5 over F_q, order F_p
//! Vesta:  y^2 = x^3 + 5 over F_p, order F_q

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PastaPoint {
    pub x: u64,
    pub y: u64,
    pub is_infinity: bool,
}

impl PastaPoint {
    pub fn pallas_generator() -> Self {
        Self {
            x: 1,
            y: 0x1b74b5a30a12937c,
            is_infinity: false,
        }
    }

    pub fn vesta_generator() -> Self {
        Self {
            x: 1,
            y: 0x37a5b3a4a1a44e5d,
            is_infinity: false,
        }
    }
}
