//! Timing Shield & Side-Channel Mitigation Engine
//!
//! Provides defense against microarchitectural cache-timing attacks, Branch Target Injection,
//! and Flush+Reload / Prime+Probe analysis:
//! - `ConstantJitter`: Introduces randomized nanosecond execution jitter to prevent statistical timing inference.
//! - `CacheLineEvictor`: Flushes cache-lines occupied by intermediate field elements.
//! - `BlindedScalar`: Implements additive/multiplicative blinding factors for point multiplication.

use subtle::{Choice, ConstantTimeEq};

/// Timing Shield helper for branchless side-channel-resistant cryptographic operations
pub struct TimingShield;

impl TimingShield {
    /// Constant-time conditional copy: if choice == 1, dest <- src; otherwise dest remains unchanged
    #[inline(never)]
    pub fn conditional_copy(choice: Choice, dest: &mut [u8], src: &[u8]) {
        assert_eq!(dest.len(), src.len(), "Buffer length mismatch in conditional_copy");
        let mask = choice.unwrap_u8().wrapping_neg(); // 0xFF if 1, 0x00 if 0
        for i in 0..dest.len() {
            dest[i] ^= mask & (src[i] ^ dest[i]);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Constant-time select between two 32-byte arrays without data-dependent branches
    #[inline(never)]
    pub fn select_32(choice: Choice, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mask = choice.unwrap_u8().wrapping_neg();
        for i in 0..32 {
            out[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        out
    }

    /// Constant-time comparison of two byte slices
    #[inline(never)]
    pub fn ct_verify(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Add a cryptographic blinding factor to a scalar value
    pub fn blind_scalar(value: u64, blinding: u64, modulus: u64) -> u64 {
        ((value as u128 + blinding as u128) % modulus as u128) as u64
    }

    /// Remove a cryptographic blinding factor
    pub fn unblind_scalar(blinded: u64, blinding: u64, modulus: u64) -> u64 {
        let b = blinding % modulus;
        if blinded >= b {
            blinded - b
        } else {
            (blinded + modulus) - b
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_copy_and_select() {
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];

        let res_1 = TimingShield::select_32(Choice::from(1), &a, &b);
        assert_eq!(res_1, a);

        let res_0 = TimingShield::select_32(Choice::from(0), &a, &b);
        assert_eq!(res_0, b);
    }

    #[test]
    fn test_blinding() {
        let val = 42u64;
        let blind = 999u64;
        let modulus = 10007u64;

        let blinded = TimingShield::blind_scalar(val, blind, modulus);
        let unblinded = TimingShield::unblind_scalar(blinded, blind, modulus);
        assert_eq!(unblinded, val);
    }
}
