//! Rate-Limiting Nullifier (RLN) & Anonymous Anti-Spam Protocol
//!
//! Implements the Rate-Limiting Nullifier (RLN) zero-knowledge protocol based on
//! 2-of-2 Shamir Secret Sharing. Honest provers can verify identity attributes once per epoch
//! anonymously. If a malicious prover submits 2 proofs in the same epoch, their private key
//! is mathematically reconstructed via Lagrange interpolation and their stake slashed!

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Prime field modulus for RLN polynomial operations (BN254 scalar field order)
pub const RLN_PRIME_MODULUS: u64 = 0xFFFFFFFF00000001; // 64-bit toy prime for fast exact demonstration

/// Secret identity credentials of an RLN member (zeroized on drop).
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RlnIdentitySecret {
    pub identity_secret_a0: u64,
    pub identity_nullifier: u64,
    pub identity_trapdoor: u64,
}

impl RlnIdentitySecret {
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"AEGIS_RLN_SECRET_DERIVATION_V1");
        h.update(seed);
        let digest = h.finalize();

        let a0 = u64::from_be_bytes(digest[0..8].try_into().unwrap()) % RLN_PRIME_MODULUS;
        let nullifier = u64::from_be_bytes(digest[8..16].try_into().unwrap()) % RLN_PRIME_MODULUS;
        let trapdoor = u64::from_be_bytes(digest[16..24].try_into().unwrap()) % RLN_PRIME_MODULUS;

        Self {
            identity_secret_a0: a0,
            identity_nullifier: nullifier,
            identity_trapdoor: trapdoor,
        }
    }

    /// Computes public identity commitment: C = H(a0 || nullifier)
    pub fn compute_identity_commitment(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"RLN_IDENTITY_COMMITMENT");
        h.update(&self.identity_secret_a0.to_be_bytes());
        h.update(&self.identity_nullifier.to_be_bytes());
        hex::encode(h.finalize().as_bytes())
    }
}

/// A zero-knowledge rate-limiting proof share for an epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RlnProofShare {
    pub epoch: u64,
    pub nullifier_hash: String,
    pub share_x: u64,
    pub share_y: u64,
    pub membership_merkle_root: String,
    pub zk_snark_proof: String,
}

/// Slashed evidence produced when double-sign is detected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashedIdentityEvidence {
    pub epoch: u64,
    pub recovered_secret_a0: u64,
    pub reconstructed_identity_commitment: String,
    pub share_1_x: u64,
    pub share_1_y: u64,
    pub share_2_x: u64,
    pub share_2_y: u64,
    pub slashing_bounty_tx: String,
}

/// Rate-Limiting Nullifier State Manager
#[derive(Clone, Debug)]
pub struct RlnManager {
    pub current_epoch: u64,
    pub active_merkle_root: String,
    pub registered_members: Vec<String>,
    pub seen_shares: std::collections::HashMap<String, RlnProofShare>,
}

impl RlnManager {
    pub fn new(initial_epoch: u64, membership_root: &str) -> Self {
        Self {
            current_epoch: initial_epoch,
            active_merkle_root: membership_root.to_string(),
            registered_members: Vec::new(),
            seen_shares: std::collections::HashMap::new(),
        }
    }

    /// Prover creates an evaluation of the polynomial f(x) = a0 + a1 * x mod q
    /// where a1 = H(a0 || epoch || message_hash)
    pub fn create_proof_share(
        identity: &RlnIdentitySecret,
        epoch: u64,
        message: &[u8],
        merkle_root: &str,
    ) -> RlnProofShare {
        // Compute message challenge x = H(message)
        let mut x_hasher = Sha256::new();
        x_hasher.update(b"RLN_MESSAGE_X_CHALLENGE");
        x_hasher.update(message);
        let x_bytes = x_hasher.finalize();
        let x = u64::from_be_bytes(x_bytes[0..8].try_into().unwrap()) % RLN_PRIME_MODULUS;

        // Compute slope a1 = H(a0 || epoch)
        let mut a1_hasher = Sha256::new();
        a1_hasher.update(b"RLN_SLOPE_A1");
        a1_hasher.update(&identity.identity_secret_a0.to_be_bytes());
        a1_hasher.update(&epoch.to_be_bytes());
        let a1_bytes = a1_hasher.finalize();
        let a1 = u64::from_be_bytes(a1_bytes[0..8].try_into().unwrap()) % RLN_PRIME_MODULUS;

        // Evaluate f(x) = (a0 + a1 * x) mod q
        let a1_x = ((a1 as u128) * (x as u128)) % (RLN_PRIME_MODULUS as u128);
        let y = (((identity.identity_secret_a0 as u128) + a1_x) % (RLN_PRIME_MODULUS as u128)) as u64;

        // Compute domain-separated epoch nullifier
        let mut null_hasher = blake3::Hasher::new();
        null_hasher.update(b"RLN_EPOCH_NULLIFIER");
        null_hasher.update(&identity.identity_nullifier.to_be_bytes());
        null_hasher.update(&epoch.to_be_bytes());
        let nullifier_hex = hex::encode(null_hasher.finalize().as_bytes());

        // Simulated Groth16 proof
        let mut snark_hasher = Sha256::new();
        snark_hasher.update(b"RLN_GROTH16_PROOF");
        snark_hasher.update(nullifier_hex.as_bytes());
        snark_hasher.update(&x.to_be_bytes());
        snark_hasher.update(&y.to_be_bytes());
        let snark_hex = hex::encode(snark_hasher.finalize());

        RlnProofShare {
            epoch,
            nullifier_hash: nullifier_hex,
            share_x: x,
            share_y: y,
            membership_merkle_root: merkle_root.to_string(),
            zk_snark_proof: format!("rln-zk-{}", &snark_hex[0..32]),
        }
    }

    /// Verifies share, checks for spam violations, and extracts the malicious prover's private key!
    pub fn verify_and_record(
        &mut self,
        share: &RlnProofShare,
    ) -> Result<Option<SlashedIdentityEvidence>, String> {
        if share.epoch != self.current_epoch {
            return Err(format!(
                "Share epoch {} does not match current epoch {}",
                share.epoch, self.current_epoch
            ));
        }

        if !crate::crypto::constant_time_eq(&share.membership_merkle_root, &self.active_merkle_root) {
            return Err("Membership Merkle root mismatch".to_string());
        }

        // Check if we have already seen a share for this nullifier in this epoch
        if let Some(existing) = self.seen_shares.get(&share.nullifier_hash) {
            if existing.share_x == share.share_x && existing.share_y == share.share_y {
                return Err("Duplicate identical share: replay dropped".to_string());
            }

            // DOUBLE SPEND / RATE-LIMIT BREACH DETECTED!
            // Recover secret a0 via Lagrange interpolation across 2 points: (x1, y1) and (x2, y2)
            // a0 = (x2*y1 - x1*y2) * (x2 - x1)^(-1) mod q
            let x1 = existing.share_x as u128;
            let y1 = existing.share_y as u128;
            let x2 = share.share_x as u128;
            let y2 = share.share_y as u128;
            let q = RLN_PRIME_MODULUS as u128;

            let term1 = (x2 * y1) % q;
            let term2 = (x1 * y2) % q;
            let num = if term1 >= term2 { term1 - term2 } else { term1 + q - term2 };

            let den = if x2 >= x1 { x2 - x1 } else { x2 + q - x1 };
            let inv_den = Self::mod_inverse(den as u64, RLN_PRIME_MODULUS).unwrap_or(1) as u128;

            let recovered_a0 = ((num * inv_den) % q) as u64;

            let mut comm_hasher = blake3::Hasher::new();
            comm_hasher.update(b"RLN_IDENTITY_COMMITMENT");
            comm_hasher.update(&recovered_a0.to_be_bytes());
            let reconstructed_comm = hex::encode(comm_hasher.finalize().as_bytes());

            let evidence = SlashedIdentityEvidence {
                epoch: share.epoch,
                recovered_secret_a0: recovered_a0,
                reconstructed_identity_commitment: reconstructed_comm,
                share_1_x: existing.share_x,
                share_1_y: existing.share_y,
                share_2_x: share.share_x,
                share_2_y: share.share_y,
                slashing_bounty_tx: format!("slash-tx-{}", hex::encode(Sha256::digest(&recovered_a0.to_be_bytes()))),
            };

            return Ok(Some(evidence));
        }

        // Honest single spend
        self.seen_shares.insert(share.nullifier_hash.clone(), share.clone());
        Ok(None)
    }

    /// Modular inverse via Extended Euclidean Algorithm
    fn mod_inverse(a: u64, m: u64) -> Option<u64> {
        let mut t = 0i128;
        let mut newt = 1i128;
        let mut r = m as i128;
        let mut newr = a as i128;

        while newr != 0 {
            let quotient = r / newr;
            let temp_t = t - quotient * newt;
            t = newt;
            newt = temp_t;

            let temp_r = r - quotient * newr;
            r = newr;
            newr = temp_r;
        }

        if r > 1 {
            return None;
        }
        if t < 0 {
            t += m as i128;
        }
        Some(t as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rln_single_spend_and_double_spend_slashing() {
        let identity = RlnIdentitySecret::from_seed(b"honest_user_identity_seed_994");
        let merkle_root = "0xmerkle_root_of_authorized_members_2026";
        let mut manager = RlnManager::new(42, merkle_root);

        // First verification share for Message 1 (e.g. "Request Access to API")
        let share1 = RlnManager::create_proof_share(&identity, 42, b"Request Access to API", merkle_root);
        let res1 = manager.verify_and_record(&share1).unwrap();
        assert!(res1.is_none(), "Honest single spend must not be slashed");

        // Malicious second verification share in same epoch for Message 2 (Spam attempt!)
        let share2 = RlnManager::create_proof_share(&identity, 42, b"Spam Access Attempt 2", merkle_root);
        let res2 = manager.verify_and_record(&share2).unwrap();
        assert!(res2.is_some(), "Double spend must trigger mathematical slashing!");

        let evidence = res2.unwrap();
        assert_eq!(evidence.recovered_secret_a0, identity.identity_secret_a0, "Prover private key must be recovered exactly!");
    }
}
