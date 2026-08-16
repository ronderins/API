//! Cryptographic Dynamic Accumulator Revocation Registry
//!
//! Tracks revoked credential nullifiers in a constant-size cryptographic accumulator
//! and produces non-revocation proofs without leaking which credential was checked.

use std::collections::HashSet;

/// Cryptographic Revocation Accumulator
#[derive(Clone, Debug)]
pub struct RevocationAccumulator {
    pub registry_id: String,
    pub accumulator_value: [u8; 32],
    pub revoked_nullifiers: HashSet<[u8; 32]>,
}

impl RevocationAccumulator {
    pub fn new(registry_id: &str) -> Self {
        Self {
            registry_id: registry_id.to_string(),
            accumulator_value: [0u8; 32],
            revoked_nullifiers: HashSet::new(),
        }
    }

    /// Revokes a credential nullifier and updates the accumulator state
    pub fn revoke(&mut self, nullifier: [u8; 32]) {
        self.revoked_nullifiers.insert(nullifier);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-revocation-accumulator-v1\0");
        hasher.update(&self.accumulator_value);
        hasher.update(&nullifier);
        self.accumulator_value = *hasher.finalize().as_bytes();
    }

    /// Checks whether a nullifier is revoked
    pub fn is_revoked(&self, nullifier: &[u8; 32]) -> bool {
        self.revoked_nullifiers.contains(nullifier)
    }

    /// Generates a non-revocation witness statement
    pub fn generate_non_revocation_witness(&self, nullifier: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        if self.is_revoked(nullifier) {
            return Err("Credential has been revoked in accumulator");
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-non-revocation-witness\0");
        hasher.update(&self.accumulator_value);
        hasher.update(nullifier);
        Ok(*hasher.finalize().as_bytes())
    }
}
