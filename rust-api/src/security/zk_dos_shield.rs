//! Adaptive Zero-Knowledge DoS Defense & Computational Client-Puzzle Shield
//!
//! Protects intensive zero-knowledge verification routines (Groth16 pairings, MSM) against DoS:
//! - Adaptive difficulty client puzzles (dynamic Proof-of-Work challenge titration)
//! - Stateless cryptographic challenge generation with HMAC-bound timestamps
//! - Sub-millisecond verification of client solution on server side ($O(1)$ hash check)
//! - Exponential difficulty escalation during traffic spikes, queue backpressure, or suspected attacks
//! - Fully automated machine-to-machine defense without user-facing CAPTCHAs

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Client Proof-of-Work Challenge Ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge_id: String,
    pub epoch_timestamp_secs: u64,
    pub difficulty_leading_zero_bits: u32,
    pub random_salt: [u8; 16],
    pub server_hmac: [u8; 32],
}

/// Client Solution Payload submitted alongside expensive verification requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowSolution {
    pub challenge_id: String,
    pub nonce_solution: u64,
}

/// Dynamic Load Monitor and DoS Protection Engine
pub struct ZkDosShield {
    hmac_secret: [u8; 32],
    base_difficulty: u32,
    current_backpressure_difficulty: AtomicU32,
    max_challenge_age_secs: u64,
}

impl ZkDosShield {
    /// Creates a new DoS shield with base difficulty (e.g. 12 bits leading zeros = ~4,096 hashes, ~1ms client CPU).
    pub fn new(hmac_secret: [u8; 32], base_difficulty: u32, max_challenge_age_secs: u64) -> Self {
        Self {
            hmac_secret,
            base_difficulty,
            current_backpressure_difficulty: AtomicU32::new(base_difficulty),
            max_challenge_age_secs,
        }
    }

    /// Dynamically scales puzzle difficulty based on server CPU load or proof queue backlog.
    pub fn update_load_factor(&self, active_queue_depth: usize, max_capacity: usize) {
        let load_ratio = (active_queue_depth as f64) / (max_capacity.max(1) as f64);

        let target_diff = if load_ratio > 0.85 {
            // Critical overload: require 20 bits (~1,000,000 hashes, ~200ms CPU for client)
            self.base_difficulty + 8
        } else if load_ratio > 0.60 {
            // High load: require 16 bits (~65,536 hashes, ~15ms CPU)
            self.base_difficulty + 4
        } else if load_ratio > 0.30 {
            // Moderate load
            self.base_difficulty + 2
        } else {
            // Normal baseline load
            self.base_difficulty
        };

        self.current_backpressure_difficulty.store(target_diff, Ordering::Relaxed);
    }

    /// Issues a stateless, time-bound PoW challenge for an incoming client session.
    pub fn generate_challenge(&self, client_session_id: &str) -> PowChallenge {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let difficulty = self.current_backpressure_difficulty.load(Ordering::Relaxed);

        // Derive deterministic pseudo-random salt for this session
        let mut salt_hasher = blake3::Hasher::new_keyed(&self.hmac_secret);
        salt_hasher.update(b"aegis-pow-salt-v1:");
        salt_hasher.update(client_session_id.as_bytes());
        salt_hasher.update(&now.to_be_bytes());
        let full_hash = *salt_hasher.finalize().as_bytes();
        let mut random_salt = [0u8; 16];
        random_salt.copy_from_slice(&full_hash[..16]);

        let challenge_id = format!("pow_{}_{}", difficulty, hex::encode(&full_hash[16..24]));

        // Sign challenge parameters to ensure stateless tamper protection
        let mut signer = blake3::Hasher::new_keyed(&self.hmac_secret);
        signer.update(b"aegis-pow-sig-v1:");
        signer.update(challenge_id.as_bytes());
        signer.update(&now.to_be_bytes());
        signer.update(&difficulty.to_be_bytes());
        signer.update(&random_salt);
        let server_hmac = *signer.finalize().as_bytes();

        PowChallenge {
            challenge_id,
            epoch_timestamp_secs: now,
            difficulty_leading_zero_bits: difficulty,
            random_salt,
            server_hmac,
        }
    }

    /// Verifies that a client's solution satisfies the required difficulty threshold.
    pub fn verify_solution(&self, challenge: &PowChallenge, solution: &PowSolution) -> Result<(), &'static str> {
        if challenge.challenge_id != solution.challenge_id {
            return Err("Challenge ID mismatch");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check age expiration
        if now.saturating_sub(challenge.epoch_timestamp_secs) > self.max_challenge_age_secs {
            return Err("PoW challenge expired");
        }

        // Verify server HMAC on challenge
        let mut signer = blake3::Hasher::new_keyed(&self.hmac_secret);
        signer.update(b"aegis-pow-sig-v1:");
        signer.update(challenge.challenge_id.as_bytes());
        signer.update(&challenge.epoch_timestamp_secs.to_be_bytes());
        signer.update(&challenge.difficulty_leading_zero_bits.to_be_bytes());
        signer.update(&challenge.random_salt);
        let expected_hmac = *signer.finalize().as_bytes();

        if !challenge.server_hmac.ct_eq(&expected_hmac).into() {
            return Err("Tampered challenge token detected");
        }

        // Verify solution hash meets leading zero bits requirement
        let mut solution_hasher = blake3::Hasher::new();
        solution_hasher.update(b"aegis-pow-solve-v1:");
        solution_hasher.update(challenge.challenge_id.as_bytes());
        solution_hasher.update(&challenge.random_salt);
        solution_hasher.update(&solution.nonce_solution.to_be_bytes());
        let digest = *solution_hasher.finalize().as_bytes();

        let leading_zeros = Self::count_leading_zero_bits(&digest);
        if leading_zeros < challenge.difficulty_leading_zero_bits {
            return Err("Insufficient computational work demonstrated");
        }

        Ok(())
    }

    /// Helper function to solve a challenge on the client or test runner side.
    pub fn solve_challenge_for_test(challenge: &PowChallenge) -> PowSolution {
        let mut nonce = 0u64;
        loop {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"aegis-pow-solve-v1:");
            hasher.update(challenge.challenge_id.as_bytes());
            hasher.update(&challenge.random_salt);
            hasher.update(&nonce.to_be_bytes());
            let digest = *hasher.finalize().as_bytes();

            if Self::count_leading_zero_bits(&digest) >= challenge.difficulty_leading_zero_bits {
                return PowSolution {
                    challenge_id: challenge.challenge_id.clone(),
                    nonce_solution: nonce,
                };
            }
            nonce += 1;
        }
    }

    fn count_leading_zero_bits(bytes: &[u8; 32]) -> u32 {
        let mut zeros = 0;
        for &byte in bytes {
            let lz = byte.leading_zeros();
            zeros += lz;
            if lz != 8 {
                break;
            }
        }
        zeros
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_dos_shield_challenge_and_solve() {
        let shield = ZkDosShield::new([0x77; 32], 8, 300); // 8 bits for instant test run
        let challenge = shield.generate_challenge("session_ip_192_168_1_1");

        assert_eq!(challenge.difficulty_leading_zero_bits, 8);

        let solution = ZkDosShield::solve_challenge_for_test(&challenge);
        assert!(shield.verify_solution(&challenge, &solution).is_ok());

        // Tampered nonce should fail
        let bad_solution = PowSolution {
            challenge_id: challenge.challenge_id.clone(),
            nonce_solution: solution.nonce_solution.wrapping_add(1),
        };
        assert!(shield.verify_solution(&challenge, &bad_solution).is_err());
    }
}
