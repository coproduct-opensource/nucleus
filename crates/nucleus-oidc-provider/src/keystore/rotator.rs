//! `KeyRotator` — background sweep + optional periodic rotation.
//!
//! The actual rotation primitive (atomic active-key swap, grace-window
//! retention for the rotated-out key, `revoke()` for immediate removal)
//! lives in the [`JwtKeyStore`](super::JwtKeyStore) trait — implemented
//! by [`InMemoryKeyStore`](super::InMemoryKeyStore) and
//! [`FileKeyStore`](super::FileKeyStore) in #33. This module adds the
//! **scheduling layer**:
//!
//! - A configurable-interval sweep of expired grace entries (memory
//!   hygiene; lookups already filter at read-time).
//! - Optional periodic rotation on a schedule (e.g. every 12h).
//! - Graceful shutdown via `tokio_util::sync::CancellationToken`.
//!
//! Industry context (Auth0, Okta, Curity, Zalando): rotation cadences
//! span hours-to-days; grace windows are sized to ≥ max-token-lifetime.
//! Our default 1h grace window matches our 1h token-lifetime cap; the
//! rotation cadence is operator policy and defaults to "manual only".

use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use super::JwtKeyStore;

/// Default sweep cadence: every 60s. Fast enough that expired entries
/// don't linger long; slow enough that the lock isn't pinging hot.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Background scheduler that drives sweep + optional rotation on a
/// shared key store.
pub struct KeyRotator {
    store: Arc<dyn JwtKeyStore>,
    sweep_interval: Duration,
    rotation_interval: Option<Duration>,
    cancel: CancellationToken,
}

impl KeyRotator {
    /// Construct a rotator with default sweep cadence (60s) and no
    /// automatic rotation (manual-only).
    pub fn new(store: Arc<dyn JwtKeyStore>) -> Self {
        Self {
            store,
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
            rotation_interval: None,
            cancel: CancellationToken::new(),
        }
    }

    /// Override sweep cadence. Useful for tests with short intervals.
    pub fn with_sweep_interval(mut self, interval: Duration) -> Self {
        self.sweep_interval = interval;
        self
    }

    /// Enable automatic rotation at the given cadence. Sensible
    /// production values are 12h-7d depending on operator policy.
    pub fn with_rotation_interval(mut self, interval: Duration) -> Self {
        self.rotation_interval = Some(interval);
        self
    }

    /// Return a clone of the cancellation token. The caller drives
    /// shutdown by calling `.cancel()` on this token; `run()` returns
    /// promptly when that happens.
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Drive the rotate + sweep loop until the cancellation token fires.
    ///
    /// Takes ownership so the rotator can't be re-run after shutdown
    /// (the `CancellationToken` is one-shot).
    pub async fn run(self) {
        let mut sweep_tick = tokio::time::interval(self.sweep_interval);
        sweep_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Discard the immediate first tick so the loop actually waits.
        sweep_tick.tick().await;

        if let Some(rotation_interval) = self.rotation_interval {
            let mut rotate_tick = tokio::time::interval(rotation_interval);
            rotate_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            rotate_tick.tick().await;

            loop {
                tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    _ = sweep_tick.tick() => self.do_sweep(),
                    _ = rotate_tick.tick() => self.do_rotate(),
                }
            }
        } else {
            loop {
                tokio::select! {
                    _ = self.cancel.cancelled() => return,
                    _ = sweep_tick.tick() => self.do_sweep(),
                }
            }
        }
    }

    fn do_sweep(&self) {
        match self.store.sweep_expired() {
            Ok(0) => {}
            Ok(n) => tracing::debug!(removed = n, "key-store sweep"),
            Err(e) => tracing::warn!(error = %e, "key-store sweep failed"),
        }
    }

    fn do_rotate(&self) {
        match self.store.rotate() {
            Ok(outcome) => tracing::info!(
                new_kid = %outcome.new_kid,
                old_kid = ?outcome.old_kid,
                "key-store rotated"
            ),
            Err(e) => tracing::warn!(error = %e, "key-store rotate failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;
    use ed25519_dalek::Verifier as _;
    use std::time::SystemTime;

    fn fresh_store_with_grace(grace: Duration) -> Arc<dyn JwtKeyStore> {
        Arc::new(InMemoryKeyStore::with_grace_window(grace))
    }

    #[tokio::test]
    async fn run_returns_promptly_on_cancel_without_rotation() {
        let store = fresh_store_with_grace(Duration::from_secs(60));
        let rotator = KeyRotator::new(store).with_sweep_interval(Duration::from_millis(50));
        let cancel = rotator.cancellation();

        let handle = tokio::spawn(rotator.run());
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run() must return within 2s of cancel");
        result.unwrap();
    }

    #[tokio::test]
    async fn sweep_removes_expired_grace_entries() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::with_grace_window(
            Duration::from_millis(50),
        ));

        // Rotate twice to populate the grace set.
        store.rotate().unwrap();
        store.rotate().unwrap();
        assert_eq!(store.all_verify_keys().unwrap().len(), 3);

        // Wait past the grace window.
        tokio::time::sleep(Duration::from_millis(120)).await;

        // Read-side already filters; verify so.
        assert_eq!(store.all_verify_keys().unwrap().len(), 1);

        // sweep_expired collapses the underlying storage too.
        let removed = store.sweep_expired().unwrap();
        assert_eq!(removed, 2, "expected 2 expired entries swept");

        // Subsequent sweep finds nothing.
        let removed = store.sweep_expired().unwrap();
        assert_eq!(removed, 0);
    }

    /// Acceptance criterion (e) — token signed pre-rotation must FAIL
    /// verification after the grace window expires.
    #[tokio::test]
    async fn token_signed_pre_rotation_fails_after_grace_expires() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::with_grace_window(
            Duration::from_millis(50),
        ));
        let bytes = b"signed-before-rotation";
        let signed = store.sign(bytes).unwrap();
        let pre_kid = signed.kid.clone();

        store.rotate().unwrap();
        // During grace: verifying with the old kid works.
        store.verify_key(&pre_kid).expect("old kid still in grace");

        // Pass grace.
        tokio::time::sleep(Duration::from_millis(120)).await;

        // After grace: old kid lookup fails.
        let err = store.verify_key(&pre_kid).unwrap_err();
        assert!(
            matches!(err, super::super::KeyStoreError::UnknownKid(_)),
            "expected UnknownKid after grace expires, got {err:?}"
        );
    }

    /// Acceptance criterion (f) — parallel `rotate()` calls serialize
    /// cleanly: no panic, no data corruption, every issued signature
    /// is verifiable by SOMETHING in the verify-set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_rotate_calls_serialize() {
        let store: Arc<dyn JwtKeyStore> =
            Arc::new(InMemoryKeyStore::with_grace_window(Duration::from_secs(60)));

        // Spawn 8 tasks each calling rotate() 10x. Total: 80 rotations.
        let mut handles = vec![];
        for _ in 0..8 {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    s.rotate().unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // After 80 rotations with 60s grace, verify-set holds the active
        // key plus up to ~80 old keys (all within grace).
        let keys = store.all_verify_keys().unwrap();
        assert!(
            !keys.is_empty() && keys.len() <= 81,
            "verify-set has {} keys (expected 1..=81)",
            keys.len()
        );

        // The active key must still be sign-and-verify usable.
        let signed = store.sign(b"after-the-rotations").unwrap();
        let vk = store.verify_key(&signed.kid).unwrap();
        let sig_arr: [u8; 64] = signed.signature.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verifying_key
            .verify(b"after-the-rotations", &sig)
            .expect("post-storm signature must verify");
    }

    /// Run-with-rotation actually triggers a rotation tick.
    #[tokio::test]
    async fn run_with_rotation_interval_rotates_at_least_once() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let initial_kid = store.active_kid().unwrap();

        let rotator = KeyRotator::new(Arc::clone(&store))
            .with_sweep_interval(Duration::from_millis(50))
            .with_rotation_interval(Duration::from_millis(80));
        let cancel = rotator.cancellation();

        let handle = tokio::spawn(rotator.run());
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let final_kid = store.active_kid().unwrap();
        assert_ne!(
            initial_kid, final_kid,
            "rotator with 80ms cadence must have rotated in 200ms window"
        );
    }

    #[test]
    fn cancellation_token_clone_propagates() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let rotator = KeyRotator::new(store);
        let c1 = rotator.cancellation();
        let c2 = rotator.cancellation();
        assert!(!c1.is_cancelled());
        c1.cancel();
        assert!(c2.is_cancelled(), "clone must share cancellation state");
    }

    /// Sanity: sweep_expired is a no-op when nothing has expired.
    #[test]
    fn sweep_with_no_expired_returns_zero() {
        let store: Arc<dyn JwtKeyStore> =
            Arc::new(InMemoryKeyStore::with_grace_window(Duration::from_secs(60)));
        store.rotate().unwrap();
        let now = SystemTime::now();
        let removed = store.sweep_expired().unwrap();
        assert_eq!(removed, 0);
        // Grace entries still present.
        let keys = store.all_verify_keys().unwrap();
        assert_eq!(keys.len(), 2);
        // Sanity: clock still moves forward.
        assert!(SystemTime::now() >= now);
    }
}
