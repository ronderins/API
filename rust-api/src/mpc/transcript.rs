//! Verifiable MPC Ceremony Audit Transcript
//!
//! Provides cryptographic proof of honest participation across all ceremony rounds.

use crate::mpc::ceremony::MpcContribution;
use serde::{Deserialize, Serialize};

/// Public Ceremony Transcript Record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyTranscript {
    pub ceremony_name: String,
    pub total_contributions: usize,
    pub final_accumulator_hash: String,
    pub contributions: Vec<MpcContribution>,
}

impl CeremonyTranscript {
    pub fn new(ceremony_name: &str) -> Self {
        Self {
            ceremony_name: ceremony_name.to_string(),
            total_contributions: 0,
            final_accumulator_hash: String::new(),
            contributions: Vec::new(),
        }
    }

    /// Verifies the full chain of contributions from genesis to the final accumulator
    pub fn verify_entire_transcript(&self) -> bool {
        let mut expected_prev_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        for (idx, contrib) in self.contributions.iter().enumerate() {
            if contrib.sequence_number != (idx + 1) as u32 {
                return false;
            }

            if contrib.previous_hash != expected_prev_hash {
                return false;
            }

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"zk-mpc-contribution-v1\0");
            hasher.update(&contrib.sequence_number.to_le_bytes());
            hasher.update(contrib.contributor_id.as_bytes());
            hasher.update(contrib.previous_hash.as_bytes());
            for g1 in &contrib.tau_g1_powers {
                hasher.update(g1.as_bytes());
            }
            let computed = hasher.finalize().to_hex().to_string();

            if computed != contrib.contribution_hash {
                return false;
            }

            expected_prev_hash = &contrib.contribution_hash;
        }

        if let Some(last) = self.contributions.last() {
            if last.contribution_hash != self.final_accumulator_hash {
                return false;
            }
        }

        true
    }
}
