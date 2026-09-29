//! Generic Cell Rate Algorithm (GCRA) and Privacy-Preserving Rate Limiting Engine
//!
//! Provides ultra-high-throughput, lock-minimized rate limiting:
//! - Implements standard GCRA (Leaky Bucket dual) with microsecond precision
//! - Hashes client IP addresses using salted Blake3 with a rotating daily secret
//! - Enforces strict tiered limits (Public Verification, Proof Generation, Admin Queries)
//! - Protects against zero-knowledge proof generation CPU exhaustion / DoS attacks

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Rate limit tier configuration
#[derive(Debug, Clone, Copy)]
pub struct RateLimitTier {
    /// Emission interval between requests in microseconds ($T$)
    pub emission_interval_us: u64,
    /// Maximum burst tolerance in microseconds ($\tau$)
    pub burst_tolerance_us: u64,
}

impl RateLimitTier {
    /// Creates a rate limit tier allowing `max_requests_per_sec` with burst allowance `burst_size`.
    pub fn new(max_requests_per_sec: u64, burst_size: u64) -> Self {
        let emission_interval_us = 1_000_000 / max_requests_per_sec.max(1);
        let burst_tolerance_us = emission_interval_us * burst_size;
        Self {
            emission_interval_us,
            burst_tolerance_us,
        }
    }

    /// Default tier for computationally expensive zero-knowledge proof generation (e.g. 5 req/s, burst 10)
    pub fn proof_generation_tier() -> Self {
        Self::new(5, 10)
    }

    /// Default tier for cheap proof verification checks (e.g. 100 req/s, burst 200)
    pub fn verification_tier() -> Self {
        Self::new(100, 200)
    }
}

/// Cell entry tracking the Theoretical Arrival Time (TAT) for a client key
struct RateLimitCell {
    /// Theoretical Arrival Time in microseconds since engine start
    tat_us: AtomicU64,
}

/// High-performance, concurrent GCRA Rate Limiter
pub struct GcraRateLimiter {
    start_time: Instant,
    salt: [u8; 32],
    cells: RwLock<HashMap<[u8; 32], RateLimitCell>>,
    tier: RateLimitTier,
}

impl GcraRateLimiter {
    /// Creates a new GCRA rate limiter with random salt and specified tier policy.
    pub fn new(tier: RateLimitTier, salt: [u8; 32]) -> Self {
        Self {
            start_time: Instant::now(),
            salt,
            cells: RwLock::new(HashMap::new()),
            tier,
        }
    }

    /// Hashes a raw client IP string into an irreversible 32-byte identifier using salted Blake3.
    pub fn hash_client_ip(&self, ip_str: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.salt);
        hasher.update(b"aegis-rate-limit-client-v1:");
        hasher.update(ip_str.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Evaluates GCRA compliance for a client identified by `client_hash`.
    ///
    /// Returns `Ok(())` if allowed, or `Err(retry_after_us)` if rate-limited.
    pub fn check_and_record(&self, client_hash: [u8; 32]) -> Result<(), u64> {
        let now_us = self.start_time.elapsed().as_micros() as u64;
        let t = self.tier.emission_interval_us;
        let tau = self.tier.burst_tolerance_us;

        // Fast path: cell already exists
        {
            let map = self.cells.read().unwrap();
            if let Some(cell) = map.get(&client_hash) {
                return Self::evaluate_cell(cell, now_us, t, tau);
            }
        }

        // Slow path: register new cell
        let mut map = self.cells.write().unwrap();
        let cell = map.entry(client_hash).or_insert_with(|| RateLimitCell {
            tat_us: AtomicU64::new(now_us),
        });

        Self::evaluate_cell(cell, now_us, t, tau)
    }

    fn evaluate_cell(cell: &RateLimitCell, now_us: u64, t: u64, tau: u64) -> Result<(), u64> {
        loop {
            let tat = cell.tat_us.load(Ordering::Acquire);
            let new_tat = tat.max(now_us);

            if new_tat > now_us + tau {
                let retry_after_us = new_tat - (now_us + tau);
                return Err(retry_after_us);
            }

            let next_tat = new_tat + t;
            if cell.tat_us.compare_exchange_weak(tat, next_tat, Ordering::Release, Ordering::Relaxed).is_ok() {
                return Ok(());
            }
        }
    }

    /// Periodically cleans up stale client cells older than `max_idle_duration`.
    pub fn evict_stale_cells(&self, max_idle: Duration) {
        let now_us = self.start_time.elapsed().as_micros() as u64;
        let cutoff_us = now_us.saturating_sub(max_idle.as_micros() as u64);

        let mut map = self.cells.write().unwrap();
        map.retain(|_, cell| {
            cell.tat_us.load(Ordering::Relaxed) > cutoff_us
        });
    }

    /// Returns the number of currently tracked client cells.
    pub fn active_client_count(&self) -> usize {
        self.cells.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcra_rate_limiting_enforcement() {
        let salt = [42u8; 32];
        let tier = RateLimitTier::new(10, 2); // 10 req/s, burst = 2
        let limiter = GcraRateLimiter::new(tier, salt);

        let client = limiter.hash_client_ip("192.168.1.55");

        // First 3 requests should succeed (due to burst tolerance)
        assert!(limiter.check_and_record(client).is_ok());
        assert!(limiter.check_and_record(client).is_ok());
        assert!(limiter.check_and_record(client).is_ok());

        // 4th immediate request should be rate-limited
        let err = limiter.check_and_record(client);
        assert!(err.is_err());
        assert!(err.unwrap_err() > 0);
    }
}
