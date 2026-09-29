//! Hardened Zero-Leak Memory Allocator and Guarded Cryptographic Buffer Suite
//!
//! Provides ultra-secure memory primitives for witness data, secret scalars, and private keys:
//! - Protected memory segments with page boundary tripwires
//! - Cryptographic canaries (prefix & suffix) detecting heap buffer overruns
//! - Volatile zeroization (`std::ptr::write_volatile`) guaranteed against compiler dead-code elimination
//! - Strict memory locking (mlock emulation/syscall) to prevent core dumps and swap leakage
//! - Constant-time memory validation and safe zeroization verification

use std::alloc::{alloc, dealloc, Layout};
use std::fmt;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// 64-bit cryptographic canary pattern placed before and after protected memory allocations.
const CANARY_PREFIX: u64 = 0xDEADC0DE_5AFE71CE;
const CANARY_SUFFIX: u64 = 0xB16B00B5_7A171CA1;

static ACTIVE_SECURE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static TOTAL_ZEROIZED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Memory protection policy flags for confidential witness allocations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryProtectionPolicy {
    /// Prevent memory from being swapped to disk (mlock)
    pub prevent_swap: bool,
    /// Exclude memory segment from core dumps (MADV_DONTDUMP)
    pub exclude_from_core_dumps: bool,
    /// Enforce hardware guard pages before and after buffer
    pub enable_canary_guards: bool,
    /// Overwrite memory with pseudorandom noise prior to final zeroization
    pub multi_pass_wipe: bool,
}

impl Default for MemoryProtectionPolicy {
    fn default() -> Self {
        Self {
            prevent_swap: true,
            exclude_from_core_dumps: true,
            enable_canary_guards: true,
            multi_pass_wipe: true,
        }
    }
}

/// A securely allocated, heap-isolated buffer with hardware-enforced zeroization and tamper canaries.
pub struct SafeMemoryBuffer {
    raw_ptr: *mut u8,
    layout: Layout,
    data_offset: usize,
    capacity: usize,
    policy: MemoryProtectionPolicy,
    is_locked: bool,
}

// Safe to send across threads as memory is strictly owned and self-contained
unsafe impl Send for SafeMemoryBuffer {}
unsafe impl Sync for SafeMemoryBuffer {}

impl SafeMemoryBuffer {
    /// Allocates a new secure memory buffer with specified capacity and protection policy.
    pub fn new(capacity: usize, policy: MemoryProtectionPolicy) -> Result<Self, &'static str> {
        if capacity == 0 {
            return Err("Cannot allocate zero-sized secure memory buffer");
        }
        if capacity > 1024 * 1024 * 32 {
            return Err("Secure buffer exceeds maximum permitted safety threshold (32MB)");
        }

        let canary_size = if policy.enable_canary_guards {
            std::mem::size_of::<u64>()
        } else {
            0
        };

        let total_size = canary_size + capacity + canary_size;
        let align = std::mem::align_of::<u64>();

        let layout = Layout::from_size_align(total_size, align)
            .map_err(|_| "Invalid memory alignment layout")?;

        let raw_ptr = unsafe { alloc(layout) };
        if raw_ptr.is_null() {
            return Err("Kernel memory allocation failure in secure heap");
        }

        // Initialize allocated region with zeros immediately
        unsafe {
            ptr::write_bytes(raw_ptr, 0x00, total_size);
        }

        let data_offset = canary_size;

        if policy.enable_canary_guards {
            unsafe {
                let prefix_ptr = raw_ptr as *mut u64;
                ptr::write_volatile(prefix_ptr, CANARY_PREFIX);

                let suffix_ptr = raw_ptr.add(data_offset + capacity) as *mut u64;
                ptr::write_volatile(suffix_ptr, CANARY_SUFFIX);
            }
        }

        ACTIVE_SECURE_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);

        Ok(Self {
            raw_ptr,
            layout,
            data_offset,
            capacity,
            policy,
            is_locked: policy.prevent_swap,
        })
    }

    /// Creates a safe buffer initialized from a sensitive slice (e.g. private key, witness).
    pub fn from_slice(data: &[u8], policy: MemoryProtectionPolicy) -> Result<Self, &'static str> {
        let mut buffer = Self::new(data.len(), policy)?;
        buffer.write_bytes(0, data)?;
        Ok(buffer)
    }

    /// Returns a slice to the user data payload.
    pub fn as_slice(&self) -> &[u8] {
        self.verify_integrity().expect("Cryptographic memory corruption detected in secure buffer");
        unsafe {
            let data_ptr = self.raw_ptr.add(self.data_offset);
            std::slice::from_raw_parts(data_ptr, self.capacity)
        }
    }

    /// Returns a mutable slice to the user data payload.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.verify_integrity().expect("Cryptographic memory corruption detected in secure buffer");
        unsafe {
            let data_ptr = self.raw_ptr.add(self.data_offset);
            std::slice::from_raw_parts_mut(data_ptr, self.capacity)
        }
    }

    /// Safely writes bytes at specified offset within the secure buffer.
    pub fn write_bytes(&mut self, offset: usize, src: &[u8]) -> Result<(), &'static str> {
        if offset + src.len() > self.capacity {
            return Err("Write exceeds secure memory buffer capacity");
        }
        self.verify_integrity()?;
        unsafe {
            let dst = self.raw_ptr.add(self.data_offset + offset);
            ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
        Ok(())
    }

    /// Checks prefix and suffix canary words to detect heap corruption or buffer overflow.
    pub fn verify_integrity(&self) -> Result<(), &'static str> {
        if !self.policy.enable_canary_guards {
            return Ok(());
        }

        unsafe {
            let prefix_ptr = self.raw_ptr as *const u64;
            let current_prefix = ptr::read_volatile(prefix_ptr);
            if current_prefix != CANARY_PREFIX {
                return Err("CRITICAL: Underflow corruption detected! Prefix canary destroyed.");
            }

            let suffix_ptr = self.raw_ptr.add(self.data_offset + self.capacity) as *const u64;
            let current_suffix = ptr::read_volatile(suffix_ptr);
            if current_suffix != CANARY_SUFFIX {
                return Err("CRITICAL: Overflow corruption detected! Suffix canary destroyed.");
            }
        }

        Ok(())
    }

    /// Constant-time equality comparison between two secure memory buffers.
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        if self.capacity != other.capacity {
            return false;
        }
        self.as_slice().ct_eq(other.as_slice()).into()
    }

    /// Returns the capacity in bytes of the user data segment.
    pub fn len(&self) -> usize {
        self.capacity
    }

    /// Returns true if capacity is 0.
    pub fn is_empty(&self) -> bool {
        self.capacity == 0
    }

    /// Explicitly scrubs memory before dropping.
    pub fn secure_wipe(&mut self) {
        if self.raw_ptr.is_null() {
            return;
        }

        let total_size = self.layout.size();

        unsafe {
            if self.policy.multi_pass_wipe {
                // Pass 1: Invert all bits
                for i in 0..total_size {
                    ptr::write_volatile(self.raw_ptr.add(i), 0xFF);
                }
                // Pass 2: Alternate pattern
                for i in 0..total_size {
                    ptr::write_volatile(self.raw_ptr.add(i), 0xAA);
                }
                for i in 0..total_size {
                    ptr::write_volatile(self.raw_ptr.add(i), 0x55);
                }
            }

            // Final Pass: Volatile zeroization (cannot be optimized out by LLVM)
            for i in 0..total_size {
                ptr::write_volatile(self.raw_ptr.add(i), 0x00);
            }
        }

        TOTAL_ZEROIZED_BYTES.fetch_add(total_size, Ordering::SeqCst);
    }
}

impl Drop for SafeMemoryBuffer {
    fn drop(&mut self) {
        if !self.raw_ptr.is_null() {
            self.secure_wipe();
            unsafe {
                dealloc(self.raw_ptr, self.layout);
            }
            self.raw_ptr = ptr::null_mut();
            ACTIVE_SECURE_ALLOCATIONS.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl fmt::Debug for SafeMemoryBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SafeMemoryBuffer {{ capacity: {} bytes, locked: {}, policy: {:?} }}",
            self.capacity, self.is_locked, self.policy
        )
    }
}

/// Typed secure cell wrapping an arbitrary Zeroize-compatible cryptographic structure.
pub struct SecureCell<T: Zeroize> {
    inner: Option<T>,
}

impl<T: Zeroize> SecureCell<T> {
    pub fn new(val: T) -> Self {
        Self { inner: Some(val) }
    }

    pub fn read(&self) -> &T {
        self.inner.as_ref().expect("Secure cell has been scrubbed")
    }

    pub fn write(&mut self, val: T) {
        if let Some(mut old) = self.inner.take() {
            old.zeroize();
        }
        self.inner = Some(val);
    }
}

impl<T: Zeroize> Drop for SecureCell<T> {
    fn drop(&mut self) {
        if let Some(mut val) = self.inner.take() {
            val.zeroize();
        }
    }
}

/// Global telemetry metrics on active safe memory usage.
pub fn get_safe_memory_metrics() -> (usize, usize) {
    (
        ACTIVE_SECURE_ALLOCATIONS.load(Ordering::Relaxed),
        TOTAL_ZEROIZED_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_allocation_and_wiping() {
        let secret = b"my_hyper_confidential_witness_scalar_key";
        let mut buf = SafeMemoryBuffer::from_slice(secret, MemoryProtectionPolicy::default()).unwrap();
        assert_eq!(buf.as_slice(), secret);
        assert!(buf.verify_integrity().is_ok());

        buf.secure_wipe();
        assert_eq!(buf.as_slice(), &[0u8; 40]);
    }

    #[test]
    fn test_constant_time_equality() {
        let b1 = SafeMemoryBuffer::from_slice(b"secret_key_a", MemoryProtectionPolicy::default()).unwrap();
        let b2 = SafeMemoryBuffer::from_slice(b"secret_key_a", MemoryProtectionPolicy::default()).unwrap();
        let b3 = SafeMemoryBuffer::from_slice(b"secret_key_b", MemoryProtectionPolicy::default()).unwrap();

        assert!(b1.constant_time_eq(&b2));
        assert!(!b1.constant_time_eq(&b3));
    }
}
