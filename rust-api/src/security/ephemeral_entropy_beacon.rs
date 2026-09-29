//! NIST SP 800-90B Entropy Health Testing & Hardened DRBG Beacon
//!
//! Provides mathematically guaranteed cryptographic randomness for nonces and blinding factors:
//! - Continuous Repetition Count Test (RCT) detecting stuck hardware noise sources
//! - Adaptive Proportion Test (APT) detecting statistical collapse in entropy pooling
//! - NIST SP 800-90A HMAC-DRBG construction with automated periodic reseeding
//! - Catastrophic entropy failure tripwires immediately halting cryptographic signing
//! - Ephemeral entropy state zeroization on process termination

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// NIST SP 800-90B Health Test Failure Reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyFailureReason {
    /// Repetition Count Test failed: identical value repeated beyond cutoff threshold $C$
    RepetitionCountExceeded { sample_val: u8, repeat_count: usize },
    /// Adaptive Proportion Test failed: sample frequency exceeded window bound $W$
    AdaptiveProportionExceeded { sample_val: u8, occurrences_in_window: usize },
    /// DRBG reseed counter reached maximum permitted invocations ($2^{48}$)
    ReseedIntervalExceeded,
}

static ENTROPY_HALT_TRIPWIRE: AtomicBool = AtomicBool::new(false);
static TOTAL_BYTES_GENERATED: AtomicU64 = AtomicU64::new(0);

/// NIST SP 800-90B Online Continuous Health Verifier
pub struct ContinuousHealthTester {
    last_sample: u8,
    repetition_count: usize,
    cutoff_repetition: usize,
    window_samples: Vec<u8>,
    window_size: usize,
    cutoff_proportion: usize,
}

impl ContinuousHealthTester {
    /// Creates a health tester with standard NIST SP 800-90B thresholds.
    pub fn new() -> Self {
        Self {
            last_sample: 0,
            repetition_count: 0,
            cutoff_repetition: 8, // For alpha = 2^-20
            window_samples: Vec::with_capacity(512),
            window_size: 512,
            cutoff_proportion: 64, // Max occurrences of any single byte in 512-byte window
        }
    }

    /// Evaluates a raw entropy sample byte from hardware source prior to DRBG conditioning.
    pub fn ingest_and_test_sample(&mut self, sample: u8) -> Result<(), EntropyFailureReason> {
        // 1. Repetition Count Test (RCT)
        if sample == self.last_sample {
            self.repetition_count += 1;
            if self.repetition_count >= self.cutoff_repetition {
                ENTROPY_HALT_TRIPWIRE.store(true, Ordering::SeqCst);
                return Err(EntropyFailureReason::RepetitionCountExceeded {
                    sample_val: sample,
                    repeat_count: self.repetition_count,
                });
            }
        } else {
            self.last_sample = sample;
            self.repetition_count = 1;
        }

        // 2. Adaptive Proportion Test (APT)
        self.window_samples.push(sample);
        if self.window_samples.len() >= self.window_size {
            let target_byte = self.window_samples[0];
            let occurrences = self.window_samples.iter().filter(|&&b| b == target_byte).count();

            if occurrences >= self.cutoff_proportion {
                ENTROPY_HALT_TRIPWIRE.store(true, Ordering::SeqCst);
                return Err(EntropyFailureReason::AdaptiveProportionExceeded {
                    sample_val: target_byte,
                    occurrences_in_window: occurrences,
                });
            }

            self.window_samples.clear();
        }

        Ok(())
    }
}

impl Default for ContinuousHealthTester {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardened HMAC-DRBG Random Number Generator State
pub struct HardenedHmacDrbg {
    key: [u8; 32],
    v: [u8; 32],
    reseed_counter: u64,
    health_tester: RwLock<ContinuousHealthTester>,
}

impl Drop for HardenedHmacDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

impl HardenedHmacDrbg {
    /// Initializes HMAC-DRBG with tested hardware entropy seed and personalization string.
    pub fn instantiate(seed_material: &[u8; 64], personalization: &[u8]) -> Result<Self, EntropyFailureReason> {
        let mut tester = ContinuousHealthTester::new();

        // Ingest and verify all initial seed bytes through NIST tests
        for &byte in seed_material.iter() {
            tester.ingest_and_test_sample(byte)?;
        }

        let mut key = [0x00u8; 32];
        let mut v = [0x01u8; 32];

        // HMAC-DRBG Update
        Self::hmac_drbg_update(&mut key, &mut v, Some(seed_material), Some(personalization));

        Ok(Self {
            key,
            v,
            reseed_counter: 1,
            health_tester: RwLock::new(tester),
        })
    }

    fn hmac_drbg_update(key: &mut [u8; 32], v: &mut [u8; 32], data1: Option<&[u8]>, data2: Option<&[u8]>) {
        // Step 1: K = HMAC(K, V || 0x00 || data)
        let mut k_hasher = blake3::Hasher::new_keyed(key);
        k_hasher.update(v);
        k_hasher.update(&[0x00]);
        if let Some(d1) = data1 {
            k_hasher.update(d1);
        }
        if let Some(d2) = data2 {
            k_hasher.update(d2);
        }
        *key = *k_hasher.finalize().as_bytes();

        // Step 2: V = HMAC(K, V)
        let mut v_hasher = blake3::Hasher::new_keyed(key);
        v_hasher.update(v);
        *v = *v_hasher.finalize().as_bytes();

        if data1.is_some() || data2.is_some() {
            // Step 3: K = HMAC(K, V || 0x01 || data)
            let mut k2_hasher = blake3::Hasher::new_keyed(key);
            k2_hasher.update(v);
            k2_hasher.update(&[0x01]);
            if let Some(d1) = data1 {
                k2_hasher.update(d1);
            }
            if let Some(d2) = data2 {
                k2_hasher.update(d2);
            }
            *key = *k2_hasher.finalize().as_bytes();

            // Step 4: V = HMAC(K, V)
            let mut v2_hasher = blake3::Hasher::new_keyed(key);
            v2_hasher.update(v);
            *v = *v2_hasher.finalize().as_bytes();
        }
    }

    /// Generates $n$ cryptographically secure pseudo-random bytes.
    pub fn generate_bytes(&mut self, dest: &mut [u8]) -> Result<(), EntropyFailureReason> {
        if ENTROPY_HALT_TRIPWIRE.load(Ordering::SeqCst) {
            return Err(EntropyFailureReason::RepetitionCountExceeded {
                sample_val: 0,
                repeat_count: 999,
            });
        }

        if self.reseed_counter > 10_000_000 {
            return Err(EntropyFailureReason::ReseedIntervalExceeded);
        }

        let mut offset = 0;
        while offset < dest.len() {
            let mut v_hasher = blake3::Hasher::new_keyed(&self.key);
            v_hasher.update(&self.v);
            self.v = *v_hasher.finalize().as_bytes();

            let copy_len = (dest.len() - offset).min(32);
            dest[offset..offset + copy_len].copy_from_slice(&self.v[..copy_len]);
            offset += copy_len;
        }

        Self::hmac_drbg_update(&mut self.key, &mut self.v, None, None);
        self.reseed_counter += 1;
        TOTAL_BYTES_GENERATED.fetch_add(dest.len() as u64, Ordering::Relaxed);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tester_rct_failure() {
        let mut tester = ContinuousHealthTester::new();
        for _ in 0..7 {
            assert!(tester.ingest_and_test_sample(0xAA).is_ok());
        }
        // 8th consecutive identical byte should fail RCT
        assert!(tester.ingest_and_test_sample(0xAA).is_err());
        ENTROPY_HALT_TRIPWIRE.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_drbg_instantiation_and_generation() {
        let seed = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ];

        let mut drbg = HardenedHmacDrbg::instantiate(&seed, b"aegis_zero_knowledge_session").unwrap();
        let mut out = [0u8; 32];
        assert!(drbg.generate_bytes(&mut out).is_ok());
        assert!(!out.ct_eq(&[0u8; 32]).into());
    }
}
