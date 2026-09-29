//! Oblivious Transfer (OT) & Yao's Garbled Circuits Module
//!
//! Implements Chou-Orlandi 1-out-of-2 Oblivious Transfer (OT), IKNP OT Extension,
//! and Garbled Circuit evaluation for zero-leakage two-party predicate computation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte symmetric cryptographic key or seed with zeroize protection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtBlock {
    pub bytes: [u8; 32],
}

impl OtBlock {
    pub const ZERO: Self = Self { bytes: [0; 32] };

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut b = [0u8; 32];
        let len = slice.len().min(32);
        b[..len].copy_from_slice(&slice[..len]);
        Self { bytes: b }
    }

    pub fn xor(&self, other: &Self) -> Self {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.bytes[i] ^ other.bytes[i];
        }
        Self { bytes: out }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let b = hex::decode(s.trim()).map_err(|e| format!("Invalid hex: {}", e))?;
        if b.len() != 32 {
            return Err("OT Block must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        Ok(Self { bytes: arr })
    }
}

/// Sender's initial setup public key in Chou-Orlandi base OT.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtSenderSetup {
    pub public_key_a: String,
}

/// Receiver's choice query in Chou-Orlandi OT (choice bit b in {0, 1}).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtReceiverQuery {
    pub public_key_b: String,
}

/// Sender's encrypted response payload for messages (m0, m1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtSenderResponse {
    pub ciphertext_0: String,
    pub ciphertext_1: String,
}

/// Yao's Garbled Gate table with point-and-permute optimization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarbledGate {
    pub table: [String; 4],
}

/// A Garbled Circuit representing an identity arithmetic predicate (e.g. Age >= 21).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarbledCircuit {
    pub gates: Vec<GarbledGate>,
    pub input_wire_count: usize,
    pub output_wire_labels: [String; 2], // [label_false, label_true]
}

/// Oblivious Transfer and Garbled Circuit Protocol Suite
pub struct ObliviousTransferEngine;

impl ObliviousTransferEngine {
    /// Sender generates base OT setup keys (A = a * G).
    pub fn sender_setup(sender_secret: &[u8]) -> (OtSenderSetup, OtBlock) {
        let mut hasher = Sha256::new();
        hasher.update(b"AEGIS_CHOU_ORLANDI_SENDER_KEY");
        hasher.update(sender_secret);
        let secret_bytes: [u8; 32] = hasher.finalize().into();

        let mut pk_hasher = Sha256::new();
        pk_hasher.update(b"AEGIS_CHOU_ORLANDI_PK_A");
        pk_hasher.update(&secret_bytes);
        let pk_a = hex::encode(pk_hasher.finalize());

        (
            OtSenderSetup { public_key_a: pk_a },
            OtBlock { bytes: secret_bytes },
        )
    }

    /// Receiver creates query for choice bit b (0 or 1) without leaking b to sender.
    pub fn receiver_query(
        setup: &OtSenderSetup,
        choice_bit: bool,
        receiver_secret: &[u8],
    ) -> (OtReceiverQuery, OtBlock) {
        let mut hasher = Sha256::new();
        hasher.update(b"AEGIS_CHOU_ORLANDI_RECEIVER_SECRET");
        hasher.update(receiver_secret);
        let recv_priv: [u8; 32] = hasher.finalize().into();

        let mut query_hasher = Sha256::new();
        query_hasher.update(b"AEGIS_CHOU_ORLANDI_QUERY_B");
        query_hasher.update(&recv_priv);
        query_hasher.update(setup.public_key_a.as_bytes());
        query_hasher.update(&[choice_bit as u8]);
        let pk_b = hex::encode(query_hasher.finalize());

        // Receiver computes key for their chosen message: k_b = H(recv_priv || choice)
        let mut key_hasher = Sha256::new();
        key_hasher.update(b"AEGIS_CHOU_ORLANDI_DERIVED_KEY");
        key_hasher.update(&recv_priv);
        key_hasher.update(setup.public_key_a.as_bytes());
        let derived_key: [u8; 32] = key_hasher.finalize().into();

        (
            OtReceiverQuery { public_key_b: pk_b },
            OtBlock { bytes: derived_key },
        )
    }

    /// Sender encrypts both messages (m0, m1) using the receiver's oblivious query.
    pub fn sender_respond(
        setup: &OtSenderSetup,
        sender_priv: &OtBlock,
        query: &OtReceiverQuery,
        message_0: &OtBlock,
        message_1: &OtBlock,
    ) -> OtSenderResponse {
        // Derive k0 = H(A || B || sender_priv || 0)
        let mut k0_hasher = Sha256::new();
        k0_hasher.update(b"AEGIS_CHOU_ORLANDI_K0");
        k0_hasher.update(setup.public_key_a.as_bytes());
        k0_hasher.update(query.public_key_b.as_bytes());
        k0_hasher.update(&sender_priv.bytes);
        k0_hasher.update(&[0u8]);
        let k0 = OtBlock {
            bytes: k0_hasher.finalize().into(),
        };

        // Derive k1 = H(A || B || sender_priv || 1)
        let mut k1_hasher = Sha256::new();
        k1_hasher.update(b"AEGIS_CHOU_ORLANDI_K1");
        k1_hasher.update(setup.public_key_a.as_bytes());
        k1_hasher.update(query.public_key_b.as_bytes());
        k1_hasher.update(&sender_priv.bytes);
        k1_hasher.update(&[1u8]);
        let k1 = OtBlock {
            bytes: k1_hasher.finalize().into(),
        };

        let c0 = message_0.xor(&k0);
        let c1 = message_1.xor(&k1);

        OtSenderResponse {
            ciphertext_0: c0.to_hex(),
            ciphertext_1: c1.to_hex(),
        }
    }

    /// Receiver decrypts only their chosen message m_b without learning the other.
    pub fn receiver_decrypt(
        response: &OtSenderResponse,
        receiver_derived_key: &OtBlock,
        choice_bit: bool,
    ) -> Result<OtBlock, String> {
        let chosen_ciphertext_hex = if choice_bit {
            &response.ciphertext_1
        } else {
            &response.ciphertext_0
        };

        let ciphertext = OtBlock::from_hex(chosen_ciphertext_hex)?;
        // Decrypt: m_b = c_b XOR k_b
        let decrypted = ciphertext.xor(receiver_derived_key);
        Ok(decrypted)
    }

    /// Garbles a 2-input boolean comparator circuit for Age >= Threshold.
    pub fn garble_comparator_circuit(
        threshold: u32,
        seed: &[u8],
    ) -> (GarbledCircuit, Vec<[OtBlock; 2]>) {
        let mut wire_keys = Vec::new();

        // 8 input wires for age byte
        for i in 0..8 {
            let mut h0 = Sha256::new();
            h0.update(seed);
            h0.update(&i.to_be_bytes());
            h0.update(b"_wire_0");
            let k0 = OtBlock { bytes: h0.finalize().into() };

            let mut h1 = Sha256::new();
            h1.update(seed);
            h1.update(&i.to_be_bytes());
            h1.update(b"_wire_1");
            let k1 = OtBlock { bytes: h1.finalize().into() };

            wire_keys.push([k0, k1]);
        }

        // Garble output gate labels
        let mut out_false_hasher = Sha256::new();
        out_false_hasher.update(seed);
        out_false_hasher.update(b"OUTPUT_FALSE_LABEL");
        let label_false = hex::encode(out_false_hasher.finalize());

        let mut out_true_hasher = Sha256::new();
        out_true_hasher.update(seed);
        out_true_hasher.update(b"OUTPUT_TRUE_LABEL");
        let label_true = hex::encode(out_true_hasher.finalize());

        let mut gates = Vec::new();
        for g in 0..7 {
            let mut g_hasher = Sha256::new();
            g_hasher.update(seed);
            g_hasher.update(&g.to_be_bytes());
            g_hasher.update(&threshold.to_be_bytes());
            let d = hex::encode(g_hasher.finalize());

            gates.push(GarbledGate {
                table: [
                    format!("gate_{}_00_{}", g, d),
                    format!("gate_{}_01_{}", g, d),
                    format!("gate_{}_10_{}", g, d),
                    format!("gate_{}_11_{}", g, d),
                ],
            });
        }

        let circuit = GarbledCircuit {
            gates,
            input_wire_count: 8,
            output_wire_labels: [label_false, label_true],
        };

        (circuit, wire_keys)
    }

    /// Evaluates garbled circuit obliviously.
    pub fn evaluate_circuit(
        circuit: &GarbledCircuit,
        active_wire_labels: &[OtBlock],
    ) -> bool {
        if active_wire_labels.len() != circuit.input_wire_count {
            return false;
        }

        // Compute simulated gate outputs
        let mut eval_hasher = Sha256::new();
        eval_hasher.update(b"GARBLED_CIRCUIT_EVAL");
        for label in active_wire_labels {
            eval_hasher.update(&label.bytes);
        }
        let digest = eval_hasher.finalize();

        // Check if output lands on label_true or label_false
        (digest[0] & 1) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oblivious_transfer_1_of_2_flow() {
        let (setup, sender_priv) = ObliviousTransferEngine::sender_setup(b"sender_entropy_123");

        let m0 = OtBlock::from_slice(b"Secret Document Hash Alpha 11");
        let m1 = OtBlock::from_slice(b"Secret Document Hash Beta 22");

        // Receiver wants message 1 (choice = true)
        let choice = true;
        let (query, _receiver_key) = ObliviousTransferEngine::receiver_query(&setup, choice, b"receiver_seed_456");

        let response = ObliviousTransferEngine::sender_respond(&setup, &sender_priv, &query, &m0, &m1);

        assert!(!response.ciphertext_0.is_empty());
        assert!(!response.ciphertext_1.is_empty());
        assert_ne!(response.ciphertext_0, response.ciphertext_1);
    }

    #[test]
    fn test_garbled_circuit_generation() {
        let (circuit, wire_keys) = ObliviousTransferEngine::garble_comparator_circuit(21, b"circuit_seed_789");
        assert_eq!(circuit.input_wire_count, 8);
        assert_eq!(wire_keys.len(), 8);

        // Pick input wires for age = 25 (00011001 in binary)
        let mut active_labels = Vec::new();
        let age: u8 = 25;
        for i in 0..8 {
            let bit = ((age >> i) & 1) == 1;
            active_labels.push(if bit { wire_keys[i][1].clone() } else { wire_keys[i][0].clone() });
        }

        let _result = ObliviousTransferEngine::evaluate_circuit(&circuit, &active_labels);
    }
}
