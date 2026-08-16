//! Cryptographic Sliding Window Rate Limiter
//!
//! Enforces distributed token bucket rate limiting on proof generation
//! and verification endpoints to mitigate denial-of-service (DoS) and
//! side-channel probing attempts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for Rate Limiting Rules
#[derive(Clone, Copy, Debug)]
pub struct RateLimitPolicy {
    pub max_requests_per_window: usize,
    pub window_duration: Duration,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_requests_per_window: 60,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Client access log record in sliding window
#[derive(Clone, Debug)]
struct ClientWindowRecord {
    timestamps: Vec<Instant>,
}

/// Thread-Safe Cryptographic Rate Limiter
pub struct RateLimiter {
    policy: RateLimitPolicy,
    clients: Mutex<HashMap<[u8; 32], ClientWindowRecord>>,
}

impl RateLimiter {
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Computes cryptographic client fingerprint to avoid storing raw IP addresses
    pub fn fingerprint_client(ip_or_token: &str, salt: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zk-rate-limit-client-id\0");
        hasher.update(salt);
        hasher.update(ip_or_token.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Checks if client request is permitted under policy
    pub fn check_and_record(&self, client_hash: &[u8; 32]) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.policy.window_duration).unwrap_or(now);

        let mut map = match self.clients.lock() {
            Ok(guard) => guard,
            Err(_) => return true, // Fail-open gracefully on lock poison
        };

        let record = map.entry(*client_hash).or_insert_with(|| ClientWindowRecord {
            timestamps: Vec::with_capacity(self.policy.max_requests_per_window),
        });

        // Prune expired timestamps
        record.timestamps.retain(|&ts| ts > cutoff);

        if record.timestamps.len() >= self.policy.max_requests_per_window {
            false
        } else {
            record.timestamps.push(now);
            true
        }
    }

    /// Periodic garbage collection of inactive clients
    pub fn prune_stale_entries(&self) {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.policy.window_duration * 2).unwrap_or(now);

        if let Ok(mut map) = self.clients.lock() {
            map.retain(|_, record| record.timestamps.iter().any(|&ts| ts > cutoff));
        }
    }
}
