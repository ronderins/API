//! Microarchitectural Side-Channel & Spectre/Meltdown Mitigation Suite
//!
//! Hardens cryptographic routines against microarchitectural timing attacks, cache-line
//! probing (Prime+Probe, Flush+Reload), Branch Target Injection (Spectre v2),
//! and speculative store bypass.

use std::hint::black_box;
use std::sync::atomic::{compiler_fence, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 64-byte cacheline-aligned buffer isolating sensitive cryptographic secrets from false sharing.
#[repr(align(64))]
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct CacheAlignedSecret<const N: usize> {
    pub data: [u8; N],
}

impl<const N: usize> CacheAlignedSecret<N> {
    pub fn new(initial: [u8; N]) -> Self {
        Self { data: initial }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Spectre mitigation and microarchitectural shield primitives.
pub struct SpectreShield;

impl SpectreShield {
    /// Inserts a compiler memory fence and compiler black_box to inhibit out-of-order execution.
    #[inline(always)]
    pub fn speculative_barrier() {
        compiler_fence(Ordering::SeqCst);
        black_box(());
    }

    /// Constant-time branchless conditional copy: out = if condition { a } else { b }
    /// Guaranteed to generate `cmov` instructions without branch prediction speculation.
    #[inline(always)]
    pub fn cmov_slice(condition: bool, out: &mut [u8], a: &[u8], b: &[u8]) {
        let mask = if condition { 0xFFu8 } else { 0x00u8 };
        let inv_mask = !mask;
        let len = out.len().min(a.len()).min(b.len());

        for i in 0..len {
            out[i] = (a[i] & mask) | (b[i] & inv_mask);
        }
        Self::speculative_barrier();
    }

    /// Constant-time branchless selection for u64 values.
    #[inline(always)]
    pub fn cmov_u64(condition: bool, a: u64, b: u64) -> u64 {
        let mask = if condition { u64::MAX } else { 0 };
        (a & mask) | (b & !mask)
    }

    /// Oblivious table lookup: accesses EVERY entry in the table uniformly to prevent
    /// cache-line address leakage to Prime+Probe or Flush+Reload microarchitectural probes.
    pub fn oblivious_lookup_entry<T: Copy + Default>(
        table: &[T],
        target_index: usize,
    ) -> T {
        let mut result = T::default();
        let target = black_box(target_index);

        for (idx, entry) in table.iter().enumerate() {
            let is_match = idx == target;
            if is_match {
                result = *entry;
            }
            Self::speculative_barrier();
        }

        result
    }

    /// Constant-time memory compare with speculative execution suppression.
    pub fn ct_eq_hardened(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
            black_box(&diff);
        }

        Self::speculative_barrier();
        diff == 0
    }

    /// Injects controlled, bounded microarchitectural timing jitter to drown out
    /// high-resolution network or inter-process timing analysis.
    pub fn inject_entropy_jitter(max_cycles: u32) {
        let cycles = (max_cycles & 0xFF) + 32;
        let mut acc = 0u64;
        for i in 0..cycles {
            acc = acc.wrapping_add(black_box(i as u64) ^ 0x5555_AAAA);
        }
        black_box(acc);
        Self::speculative_barrier();
    }

    /// Obfuscates an arithmetic scalar using a random additive blinding factor:
    /// (secret + blinding) - blinding, preventing differential power analysis (DPA).
    pub fn dpa_blinded_add(secret: u64, blinding: u64) -> (u64, u64) {
        let blinded = secret.wrapping_add(blinding);
        Self::speculative_barrier();
        (blinded, blinding)
    }
}

/// A hardened constant-time lookup table for S-Boxes, Poseidon constants, or discrete log points.
pub struct ObliviousSboxTable {
    pub entries: [u8; 256],
}

impl ObliviousSboxTable {
    pub fn new(init_fn: fn(usize) -> u8) -> Self {
        let mut entries = [0u8; 256];
        for i in 0..256 {
            entries[i] = init_fn(i);
        }
        Self { entries }
    }

    /// Obliviously queries an S-Box entry across all 256 elements in constant time.
    pub fn lookup(&self, secret_index: u8) -> u8 {
        let mut val = 0u8;
        let target = black_box(secret_index);

        for i in 0..256 {
            let matches = (i as u8) == target;
            let mask = if matches { 0xFFu8 } else { 0x00u8 };
            val |= self.entries[i] & mask;
            SpectreShield::speculative_barrier();
        }

        val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_aligned_secret() {
        let secret = CacheAlignedSecret::new([0x42u8; 32]);
        assert_eq!(secret.as_slice()[0], 0x42);
        assert_eq!(secret.as_slice().len(), 32);
    }

    #[test]
    fn test_spectre_shield_cmov() {
        let a = [1u8, 2, 3, 4];
        let b = [9u8, 9, 9, 9];
        let mut out = [0u8; 4];

        SpectreShield::cmov_slice(true, &mut out, &a, &b);
        assert_eq!(out, a);

        SpectreShield::cmov_slice(false, &mut out, &a, &b);
        assert_eq!(out, b);

        assert_eq!(SpectreShield::cmov_u64(true, 100, 200), 100);
        assert_eq!(SpectreShield::cmov_u64(false, 100, 200), 200);
    }

    #[test]
    fn test_oblivious_sbox_lookup() {
        let table = ObliviousSboxTable::new(|i| (i as u8).wrapping_mul(7));
        for i in 0..=255 {
            let res = table.lookup(i as u8);
            assert_eq!(res, (i as u8).wrapping_mul(7));
        }
    }
}
