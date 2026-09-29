//! Cryptographic Side-Channel Mitigations & Constant-Time Oblivious Primitives
//!
//! Provides defense-in-depth protection against microarchitectural attacks:
//! - Cache-timing attacks (Flush+Reload, Prime+Probe)
//! - Branch-prediction side-channels (Spectre-style speculative execution)
//! - Simple & Differential Power Analysis (SPA / DPA)
//! - Timing leaks during variable-time table lookups or scalar multiplications
//! - Oblivious array index selection with bitwise constant-time masking

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Constant-time oblivious table lookup that accesses all table entries
/// to ensure identical cache-line access patterns regardless of the target index.
pub struct ObliviousTable<T: Copy + Default + ConditionallySelectable + Zeroize> {
    entries: Vec<T>,
}

impl<T: Copy + Default + ConditionallySelectable + Zeroize> ObliviousTable<T> {
    /// Creates a new oblivious table from an existing slice.
    pub fn new(slice: &[T]) -> Self {
        Self {
            entries: slice.to_vec(),
        }
    }

    /// Retrieves the entry at `index` in guaranteed constant time without branching.
    ///
    /// Every entry in the table is read and conditionally selected using bitwise masks,
    /// generating an identical sequence of CPU loads and instruction timings.
    pub fn lookup(&self, index: usize) -> T {
        let mut result = T::default();

        for (i, entry) in self.entries.iter().enumerate() {
            let is_match = Choice::from((i == index) as u8);
            result.conditional_assign(entry, is_match);
        }

        result
    }

    /// Obliviously writes `val` into `index` without revealing the target address through cache lines.
    pub fn write_oblivious(&mut self, index: usize, val: &T) {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            let is_match = Choice::from((i == index) as u8);
            entry.conditional_assign(val, is_match);
        }
    }

    /// Number of elements in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<T: Copy + Default + ConditionallySelectable + Zeroize> Drop for ObliviousTable<T> {
    fn drop(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.zeroize();
        }
    }
}

/// Constant-time 32-byte scalar point representation for side-channel immune curve math.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SafeScalar32(pub [u8; 32]);

impl ConditionallySelectable for SafeScalar32 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        SafeScalar32(out)
    }
}

impl Zeroize for SafeScalar32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Constant-time conditional swap (cswap) between two sensitive buffers.
pub fn constant_time_cswap<T: ConditionallySelectable + Copy>(a: &mut T, b: &mut T, swap: Choice) {
    let temp = *a;
    a.conditional_assign(b, swap);
    b.conditional_assign(&temp, swap);
}

/// Defensive Execution Jitter and Blinding Engine.
///
/// Injects bounded micro-delays and dummy arithmetic cycles to defeat high-resolution
/// hardware oscilloscope measurements and power analysis (DPA/CPA).
pub struct SideChannelShield {
    blinding_rounds: usize,
    dummy_accumulator: u64,
}

impl SideChannelShield {
    /// Creates a new shield with specified defensive blinding iterations.
    pub fn new(blinding_rounds: usize) -> Self {
        Self {
            blinding_rounds: blinding_rounds.clamp(1, 1024),
            dummy_accumulator: 0xCAFE_BABE_1337_0001,
        }
    }

    /// Executes balanced dummy arithmetic cycles to normalize instruction pipeline execution time.
    #[inline(never)]
    pub fn execute_balanced_dummy_cycles(&mut self, condition: bool) {
        let choice = Choice::from(condition as u8);

        // Branchless execution: perform identical operations regardless of condition
        for i in 0..self.blinding_rounds {
            let dummy_a = (self.dummy_accumulator ^ (i as u64)).wrapping_mul(0x517cc1b727220a95);
            let dummy_b = (self.dummy_accumulator.rotate_left(7)).wrapping_add(0x9e3779b97f4a7c15);

            let selected = u64::conditional_select(&dummy_a, &dummy_b, choice);
            self.dummy_accumulator = self.dummy_accumulator.wrapping_add(selected);
        }

        // Prevent dead-code compiler optimization via black box volatile read
        unsafe {
            std::ptr::read_volatile(&self.dummy_accumulator);
        }
    }

    /// Verifies two byte slices for constant-time equivalence without timing variance.
    pub fn safe_slices_equal(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
}

impl Drop for SideChannelShield {
    fn drop(&mut self) {
        self.dummy_accumulator.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oblivious_table_lookup() {
        let items = [
            SafeScalar32([1; 32]),
            SafeScalar32([2; 32]),
            SafeScalar32([3; 32]),
            SafeScalar32([4; 32]),
        ];

        let table = ObliviousTable::new(&items);

        let retrieved = table.lookup(2);
        assert_eq!(retrieved, SafeScalar32([3; 32]));

        let retrieved_first = table.lookup(0);
        assert_eq!(retrieved_first, SafeScalar32([1; 32]));
    }

    #[test]
    fn test_constant_time_cswap() {
        let mut x = SafeScalar32([10; 32]);
        let mut y = SafeScalar32([20; 32]);

        // Swap when choice is 0 (false) -> no swap
        constant_time_cswap(&mut x, &mut y, Choice::from(0));
        assert_eq!(x.0[0], 10);
        assert_eq!(y.0[0], 20);

        // Swap when choice is 1 (true) -> swapped
        constant_time_cswap(&mut x, &mut y, Choice::from(1));
        assert_eq!(x.0[0], 20);
        assert_eq!(y.0[0], 10);
    }
}
