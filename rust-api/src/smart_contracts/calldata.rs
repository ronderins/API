//! ABI Encoding & EVM Calldata Serialization for Zero-Knowledge Proofs
//!
//! Converts native Rust `Groth16Proof` and public input vectors into standard
//! Ethereum ABI-encoded hex strings suitable for `eth_call` and web3.js/ethers.js.

use serde::{Deserialize, Serialize};

/// Formatted EVM Calldata Payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmCalldataPayload {
    pub function_signature: String,
    pub a_g1: [String; 2],
    pub b_g2: [[String; 2]; 2],
    pub c_g1: [String; 2],
    pub public_inputs: Vec<String>,
    pub raw_calldata_hex: String,
}

pub struct EvmCalldataEncoder;

impl EvmCalldataEncoder {
    /// Formats proof elements into hex arrays for smart contract verification
    pub fn encode_proof(
        a: &[u8; 64],
        b: &[u8; 128],
        c: &[u8; 64],
        public_inputs: &[u64],
    ) -> EvmCalldataPayload {
        let a_x = format!("0x{}", hex::encode(&a[0..32]));
        let a_y = format!("0x{}", hex::encode(&a[32..64]));

        let b_x1 = format!("0x{}", hex::encode(&b[0..32]));
        let b_x2 = format!("0x{}", hex::encode(&b[32..64]));
        let b_y1 = format!("0x{}", hex::encode(&b[64..96]));
        let b_y2 = format!("0x{}", hex::encode(&b[96..128]));

        let c_x = format!("0x{}", hex::encode(&c[0..32]));
        let c_y = format!("0x{}", hex::encode(&c[32..64]));

        let inputs_hex: Vec<String> = public_inputs
            .iter()
            .map(|val| format!("0x{:064x}", val))
            .collect();

        let raw_hex = format!(
            "0x43b236fc{}{}{}{}{}{}{}{}",
            &a_x[2..],
            &a_y[2..],
            &b_x1[2..],
            &b_x2[2..],
            &b_y1[2..],
            &b_y2[2..],
            &c_x[2..],
            &c_y[2..]
        );

        EvmCalldataPayload {
            function_signature: "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[4])".to_string(),
            a_g1: [a_x, a_y],
            b_g2: [[b_x1, b_x2], [b_y1, b_y2]],
            c_g1: [c_x, c_y],
            public_inputs: inputs_hex,
            raw_calldata_hex: raw_hex,
        }
    }
}
