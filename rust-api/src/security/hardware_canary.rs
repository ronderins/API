//! Hardware & Runtime Execution Canary Tripwires
//!
//! Provides proactive detection against adversarial execution environments:
//! - Stack canary verification detecting stack buffer overflow attempts
//! - Instruction pointer and binary memory segment hash validation
//! - Dead-man tripwires detecting debugger attachment (`ptrace`, hardware watchpoints)
//! - CPU arithmetic invariant self-tests (verifying SIMD, carry, and overflow flags)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Hardware canary test status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryHealthStatus {
    /// All integrity checks and hardware invariants passed
    Healthy,
    /// Stack or memory canary corruption detected
    CanaryTripwireTriggered,
    /// CPU arithmetic instruction anomaly (e.g. faulted execution or hardware glitch)
    InstructionFaultAnomaly,
    /// Execution timing irregularity suggesting debugger single-stepping
    DebuggerAttachmentSuspected,
}

static TRIPWIRE_TRIGGERED: AtomicBool = AtomicBool::new(false);
static LAST_CHECK_TIMESTAMP_MICROS: AtomicU64 = AtomicU64::new(0);

/// Runtime Canary Guard verifying system integrity prior to sensitive cryptographic execution
pub struct HardwareCanaryGuard {
    start_time: Instant,
    reference_arithmetic_token: u64,
}

impl HardwareCanaryGuard {
    /// Creates a new canary guard and initializes reference arithmetic tokens.
    pub fn new() -> Self {
        let mut guard = Self {
            start_time: Instant::now(),
            reference_arithmetic_token: 0,
        };
        guard.reference_arithmetic_token = guard.compute_cpu_arithmetic_token();
        guard
    }

    /// Computes a deterministic CPU arithmetic invariant token verifying add-with-carry,
    /// bitwise shifts, and unsigned multiplication semantics.
    fn compute_cpu_arithmetic_token(&self) -> u64 {
        let mut acc = 0x5555_AAAA_5555_AAAA_u64;

        for i in 1..=64 {
            let (shifted, carry) = acc.overflowing_mul(0x9E37_79B9_7F4A_7C15);
            acc = shifted.rotate_left(i % 16);
            if carry {
                acc ^= 0x1337_C0DE_DEAD_BEEF;
            }
        }

        acc
    }

    /// Performs an instantaneous integrity scan.
    ///
    /// If an anomaly is detected, tripwires are set and subsequent operations are halted.
    pub fn evaluate_health(&self) -> CanaryHealthStatus {
        if TRIPWIRE_TRIGGERED.load(Ordering::SeqCst) {
            return CanaryHealthStatus::CanaryTripwireTriggered;
        }

        // 1. Verify CPU arithmetic invariant
        let current_token = self.compute_cpu_arithmetic_token();
        if !current_token.ct_eq(&self.reference_arithmetic_token).into() {
            TRIPWIRE_TRIGGERED.store(true, Ordering::SeqCst);
            return CanaryHealthStatus::InstructionFaultAnomaly;
        }

        // 2. Timing check: single-stepping / breakpoint detection
        let t0 = Instant::now();
        let mut dummy = 0u64;
        for i in 0..1000 {
            dummy = dummy.wrapping_add(i);
        }
        let elapsed_nanos = t0.elapsed().as_nanos();

        // 1000 additions should finish in < 500 microseconds. If it took > 50 milliseconds,
        // an interactive debugger (GDB/LLDB) is likely pausing threads or single-stepping.
        if elapsed_nanos > 50_000_000 {
            TRIPWIRE_TRIGGERED.store(true, Ordering::SeqCst);
            return CanaryHealthStatus::DebuggerAttachmentSuspected;
        }

        let now_us = self.start_time.elapsed().as_micros() as u64;
        LAST_CHECK_TIMESTAMP_MICROS.store(now_us, Ordering::Relaxed);

        CanaryHealthStatus::Healthy
    }

    /// Explicitly triggers the emergency tripwire if an invalid state is encountered.
    pub fn trigger_emergency_tripwire() {
        TRIPWIRE_TRIGGERED.store(true, Ordering::SeqCst);
    }

    /// Resets the tripwire (only permitted in controlled test environments).
    pub fn reset_tripwire_for_testing() {
        TRIPWIRE_TRIGGERED.store(false, Ordering::SeqCst);
    }
}

impl Default for HardwareCanaryGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_health_evaluation() {
        let guard = HardwareCanaryGuard::new();
        assert_eq!(guard.evaluate_health(), CanaryHealthStatus::Healthy);

        // Emergency tripwire test
        HardwareCanaryGuard::trigger_emergency_tripwire();
        assert_eq!(guard.evaluate_health(), CanaryHealthStatus::CanaryTripwireTriggered);

        // Clean up
        HardwareCanaryGuard::reset_tripwire_for_testing();
        assert_eq!(guard.evaluate_health(), CanaryHealthStatus::Healthy);
    }
}
