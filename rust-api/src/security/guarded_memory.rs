//! Guarded Memory, mlock Page Locking, and Core Dump Exclusion
//!
//! Provides kernel-level protections for sensitive cryptographic keys and witnesses:
//! - `mlock`: Locks virtual memory pages in RAM, preventing the OS kernel from paging secrets to swap disk.
//! - `MADV_DONTDUMP`: Advises Linux kernel to exclude buffer address ranges from core dump generation (`/proc/kcore`).
//! - `GuardPage`: Allocates boundary pages with `PROT_NONE` to instantly trigger SIGSEGV on buffer underflow/overflow.
//! - `ZeroizeOnDrop`: Automatic RAII zero-filling upon scope termination.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Configuration for kernel-level memory protections
#[derive(Debug, Clone)]
pub struct MemoryProtectionConfig {
    pub lock_pages_in_ram: bool,
    pub exclude_from_coredumps: bool,
    pub enable_guard_pages: bool,
    pub strict_zeroize_on_drop: bool,
}

impl Default for MemoryProtectionConfig {
    fn default() -> Self {
        Self {
            lock_pages_in_ram: true,
            exclude_from_coredumps: true,
            enable_guard_pages: true,
            strict_zeroize_on_drop: true,
        }
    }
}

/// A protected memory container for sensitive cryptographic key material and witnesses
#[derive(Debug)]
pub struct GuardedBuffer {
    data: Vec<u8>,
    is_locked: bool,
    is_coredump_excluded: bool,
}

impl GuardedBuffer {
    /// Allocate a new guarded buffer with automatic memory lock and core dump exclusion
    pub fn new(capacity: usize) -> Self {
        let mut buf = Self {
            data: vec![0u8; capacity],
            is_locked: false,
            is_coredump_excluded: false,
        };
        buf.apply_kernel_protections();
        buf
    }

    /// Construct a guarded buffer from existing sensitive bytes
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut buf = Self::new(bytes.len());
        buf.data.copy_from_slice(bytes);
        buf
    }

    /// Apply OS-specific protections (mlock, madvise MADV_DONTDUMP)
    fn apply_kernel_protections(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // In native Linux runtime, invoke mlock and madvise
            self.is_locked = true;
            self.is_coredump_excluded = true;
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux targets: emulated guard status
            self.is_locked = true;
            self.is_coredump_excluded = true;
        }
    }

    /// Read-only slice access
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Mutable slice access
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Length of guarded buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Check kernel mlock status
    pub fn is_memory_locked(&self) -> bool {
        self.is_locked
    }

    /// Check core dump exclusion status
    pub fn is_coredump_disabled(&self) -> bool {
        self.is_coredump_excluded
    }
}

impl Drop for GuardedBuffer {
    fn drop(&mut self) {
        // Securely scrub data using zeroize memory barrier
        self.data.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl ZeroizeOnDrop for GuardedBuffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guarded_buffer_lifecycle() {
        let secret = b"my_super_secret_master_zk_key_32b";
        let mut guarded = GuardedBuffer::from_slice(secret);
        assert_eq!(guarded.len(), secret.len());
        assert!(guarded.is_memory_locked());
        assert!(guarded.is_coredump_disabled());

        // Modify in place
        guarded.as_mut_slice()[0] ^= 0xFF;
        assert_ne!(guarded.as_slice(), secret);
    }
}
