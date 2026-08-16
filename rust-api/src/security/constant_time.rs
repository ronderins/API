//! Constant-Time Cryptographic Primitives for Side-Channel Defense
//!
//! Provides branchless, memory-timing-neutral comparison and conditional
//! selection operations to defend against cache timing and microarchitectural attacks.

use zeroize::Zeroize;

/// Constant-time comparison of two byte slices
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    diff == 0
}

/// Constant-time selection: returns `if_true` if condition == 1, else `if_false`
#[inline(always)]
pub fn ct_select_u64(condition: u64, if_true: u64, if_false: u64) -> u64 {
    let mask = 0u64.wrapping_sub(condition & 1);
    (if_true & mask) | (if_false & !mask)
}

/// Constant-time byte array copy if condition is met
#[inline(never)]
pub fn ct_conditional_assign(target: &mut [u8], source: &[u8], condition: bool) {
    let mask = if condition { 0xFFu8 } else { 0x00u8 };
    for i in 0..target.len().min(source.len()) {
        target[i] = (source[i] & mask) | (target[i] & !mask);
    }
}

/// Secure memory scrub helper ensuring buffer is wiped
pub fn secure_scrub<T: Zeroize>(val: &mut T) {
    val.zeroize();
}
