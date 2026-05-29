// SPDX-License-Identifier: MIT
//
//! Replay-protection cache for JWT `jti` claims.
//!
//! Tracks seen `jti` values within their `exp` window. Used on both
//! sides of a token-exchange flow: inbound subject-token replay defense
//! AND outbound issued-token replay defense (token-exchange response
//! is one-shot when the OP holds an actor_token).
//!
//! # Semantics (RFC 9068 §4 + RFC 7519 §4.1.7)
//!
//! - **Retention.** An entry's expiry equals `max(token_exp,
//!   now + RETENTION_FLOOR_SECS)`. Long-exp tokens are kept until
//!   their actual expiry (real replay defense); short-exp tokens are
//!   kept past expiry by the floor to close the post-exp-boundary
//!   replay window where an attacker re-presents a freshly-expired
//!   token to a clock-skewed RP.
//! - **Capacity.** Bounded at `DEFAULT_CAPACITY = 100_000`. On
//!   insert-at-capacity, the entry that would expire SOONEST is
//!   evicted — minimizes the replay-defense lost per evicted entry.
//! - **Parallel correctness.** `Mutex<HashMap>` serializes all
//!   check+mark operations. Under K parallel callers presenting the
//!   same `jti`, exactly one acquires the lock first, inserts, and
//!   succeeds; the remaining K-1 observe the entry and fail with
//!   `OidcError::TokenReplay`.
//!
//! See `crates/nucleus-oidc-provider/THREAT_MODEL.md` T03 (replay
//! across audiences) for the security context.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::OidcError;

/// Tracks seen `jti` values to reject replayed tokens.
///
/// Entries are dropped once expired; the live set only ever holds the
/// unexpired tokens of the issuer's validity window.
pub struct JtiCache {
    used: Mutex<HashMap<String, u64>>,
    capacity: usize,
}

/// Default per-process cache capacity. Bounds memory growth under
/// hostile replay-with-distinct-jtis attacks per `THREAT_MODEL.md` T07.
pub const DEFAULT_CAPACITY: usize = 100_000;

/// Retention floor in seconds — entries are kept until at least
/// `now + RETENTION_FLOOR_SECS` even if their token's `exp` is sooner.
/// Closes the post-expiry boundary where a token can briefly be
/// replayed against an RP whose clock is skewed slightly behind.
pub const RETENTION_FLOOR_SECS: u64 = 60;

impl JtiCache {
    /// Empty cache with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Empty cache with an explicit capacity ceiling.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            used: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Record `jti` as seen. Returns [`OidcError::TokenReplay`] if it
    /// was already present and not yet expired.
    ///
    /// Each call also evicts expired entries (lazy sweep). If the cache
    /// is at capacity and the incoming entry would push it over, the
    /// OLDEST-expiring entry is evicted to make room — a hostile
    /// attacker can blow recent entries out of the cache by flooding
    /// distinct jtis, but only at the cost of losing replay defense on
    /// THEIR OWN entries. Legitimate tokens within their exp window
    /// remain safe.
    pub fn check_and_mark(&self, jti: &str, exp: u64) -> Result<(), OidcError> {
        // (#55 LOW-5) Fail-loud on a clock that's before unix epoch
        // rather than silently treating `now = 0`. With `now = 0`,
        // EVERY entry would store `retention_until = max(exp, FLOOR)`
        // → cache state degenerates and the eviction policy no longer
        // protects honest entries. Better to surface the bad clock.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| OidcError::JwtValidation("system clock before unix epoch".into()))?;
        let retention_until = exp.max(now.saturating_add(RETENTION_FLOOR_SECS));
        let mut used = self
            .used
            .lock()
            .map_err(|_| OidcError::TokenReplay("jti cache poisoned".to_string()))?;
        used.retain(|_, expiry| *expiry > now);
        if used.contains_key(jti) {
            return Err(OidcError::TokenReplay(jti.to_string()));
        }
        if used.len() >= self.capacity {
            // Evict the entry that would expire soonest.
            if let Some(oldest_kid) = used
                .iter()
                .min_by_key(|(_, &exp)| exp)
                .map(|(k, _)| k.clone())
            {
                used.remove(&oldest_kid);
            }
        }
        used.insert(jti.to_string(), retention_until);
        Ok(())
    }

    /// Current cache size — for observability + tests.
    pub fn len(&self) -> usize {
        self.used.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_exp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600
    }

    #[test]
    fn accepts_first_use_rejects_replay() {
        let cache = JtiCache::new();
        let exp = future_exp();
        cache.check_and_mark("jti-1", exp).unwrap();
        let err = cache
            .check_and_mark("jti-1", exp)
            .expect_err("replay must be rejected");
        assert_eq!(err, OidcError::TokenReplay("jti-1".to_string()));
    }

    #[test]
    fn distinct_jtis_both_accepted() {
        let cache = JtiCache::new();
        let exp = future_exp();
        cache.check_and_mark("jti-a", exp).unwrap();
        cache.check_and_mark("jti-b", exp).unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn expired_entry_is_evicted_on_next_check() {
        let cache = JtiCache::new();
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1;
        // First call has past exp — accepted, immediately stale.
        cache.check_and_mark("jti-stale", past).unwrap();
        // Next call sweeps it out before insert; the same jti is accepted again.
        cache.check_and_mark("jti-stale", past + 1).unwrap_or(());
    }

    /// Parallel K=100 stress test — single-lock serialization under
    /// hostile thread-level contention. Exactly one admit, K-1 rejects.
    #[test]
    fn parallel_presentations_of_same_jti_admit_exactly_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        const K: usize = 100;
        let cache = Arc::new(JtiCache::new());
        let exp = future_exp();
        let admitted = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(K);
        for _ in 0..K {
            let cache = Arc::clone(&cache);
            let admitted = Arc::clone(&admitted);
            let rejected = Arc::clone(&rejected);
            handles.push(std::thread::spawn(move || {
                match cache.check_and_mark("contested", exp) {
                    Ok(()) => {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(OidcError::TokenReplay(_)) => {
                        rejected.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("unexpected error: {e:?}"),
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(admitted.load(Ordering::SeqCst), 1);
        assert_eq!(rejected.load(Ordering::SeqCst), K - 1);
    }

    /// Retention floor keeps short-exp entries past their token-exp
    /// (clock-skewed RP scenario).
    #[test]
    fn retention_floor_keeps_short_exp_entry() {
        let cache = JtiCache::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stale_exp = now.saturating_sub(1);
        cache.check_and_mark("stale", stale_exp).unwrap();
        let err = cache.check_and_mark("stale", stale_exp).unwrap_err();
        assert_eq!(err, OidcError::TokenReplay("stale".to_string()));
    }

    #[test]
    fn capacity_evicts_soonest_expiring_entry() {
        let cache = JtiCache::with_capacity(2);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cache.check_and_mark("short", now + 60).unwrap();
        cache.check_and_mark("medium", now + 600).unwrap();
        assert_eq!(cache.len(), 2);
        // Adding a third at capacity evicts the soonest-expiring entry
        // (`short`), leaving {medium, long}.
        cache.check_and_mark("long", now + 6000).unwrap();
        assert_eq!(cache.len(), 2);
        // Replay defense still works for the two retained entries.
        let err = cache.check_and_mark("medium", now + 600).unwrap_err();
        assert_eq!(err, OidcError::TokenReplay("medium".to_string()));
        let err = cache.check_and_mark("long", now + 6000).unwrap_err();
        assert_eq!(err, OidcError::TokenReplay("long".to_string()));
        // The evicted `short` is no longer protected — re-insertion
        // succeeds (this is the documented capacity-pressure tradeoff).
        cache.check_and_mark("short", now + 60).unwrap();
    }
}
