//! In-memory `JwtKeyStore` implementation.
//!
//! Production-suitable for ephemeral / single-process deployments where
//! key loss on restart is acceptable (e.g., short-lived demo OPs,
//! integration tests). For durable storage use [`super::FileKeyStore`].
//!
//! # Threat-model coverage
//!
//! - GA-1 (ephemeral keys): documented limitation; this is the
//!   ephemeral store *by design*.
//! - GA-2 (RFC 7638 KID): KID derivation uses [`super::rfc7638_kid`].
//! - GA-3 (rotation): `rotate()` is implemented with grace window.
//! - GA-8 (zeroize): `SigningKey` zeroizes on drop (ed25519-dalek
//!   default + explicit `zeroize` feature in Cargo.toml).
//! - GA-13 (no key accessor): the `signing_key` field is private
//!   and never exposed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signer, SigningKey};

use super::{rfc7638_kid, JwtKeyStore, KeyStoreError, RotateOutcome, SignedBytes, VerifyKey};

/// Default rotation grace window. Tokens signed pre-rotation verify
/// for this long after the rotation event. Matches the value
/// recommended in `THREAT_MODEL.md` (T13).
pub const DEFAULT_GRACE_WINDOW: Duration = Duration::from_secs(3600);

/// In-memory key store. Generates a fresh Ed25519 keypair on
/// construction; thereafter every `rotate()` extends the verify-set
/// for the configured grace window.
pub struct InMemoryKeyStore {
    inner: Mutex<Inner>,
    grace_window: Duration,
}

struct Inner {
    /// The currently-active signing key. Its private bytes are wiped
    /// on `Drop` via ed25519-dalek's `ZeroizeOnDrop`.
    active_signing: SigningKey,
    /// Cached verifying key + KID for the active. Updated on rotate.
    active_kid: String,
    active_not_before: SystemTime,
    /// Verify-only entries from previous active keys. KID → entry.
    /// Each entry has a `not_after` that bounds its grace window.
    previous: HashMap<String, Arc<VerifyKey>>,
}

impl InMemoryKeyStore {
    /// Create a new store with a freshly-generated active key and the
    /// default 1h grace window.
    pub fn new() -> Self {
        Self::with_grace_window(DEFAULT_GRACE_WINDOW)
    }

    /// Create with an explicit grace window. Used by tests that
    /// need short windows to exercise expiry without sleeping.
    pub fn with_grace_window(grace_window: Duration) -> Self {
        let signing = SigningKey::generate(&mut rand::rng());
        let kid = rfc7638_kid(&signing.verifying_key());
        Self {
            inner: Mutex::new(Inner {
                active_signing: signing,
                active_kid: kid,
                active_not_before: SystemTime::now(),
                previous: HashMap::new(),
            }),
            grace_window,
        }
    }

    fn active_verify_key(inner: &Inner) -> Arc<VerifyKey> {
        Arc::new(VerifyKey {
            kid: inner.active_kid.clone(),
            verifying_key: inner.active_signing.verifying_key(),
            not_before: inner.active_not_before,
            // Active keys are open-ended; the JWKS endpoint serves
            // them until they rotate. `not_after` is set to far-future.
            not_after: SystemTime::now() + Duration::from_secs(365 * 24 * 3600),
        })
    }

    fn sweep_expired(inner: &mut Inner) {
        let now = SystemTime::now();
        inner.previous.retain(|_, vk| vk.not_after > now);
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtKeyStore for InMemoryKeyStore {
    fn sign(&self, bytes: &[u8]) -> Result<SignedBytes, KeyStoreError> {
        let inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        let sig = inner.active_signing.sign(bytes);
        Ok(SignedBytes {
            kid: inner.active_kid.clone(),
            alg: "EdDSA",
            signature: sig.to_bytes().to_vec(),
        })
    }

    fn active_kid(&self) -> Result<String, KeyStoreError> {
        let inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        Ok(inner.active_kid.clone())
    }

    fn verify_key(&self, kid: &str) -> Result<Arc<VerifyKey>, KeyStoreError> {
        let inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        if kid == inner.active_kid {
            return Ok(Self::active_verify_key(&inner));
        }
        let entry = inner
            .previous
            .get(kid)
            .ok_or_else(|| KeyStoreError::UnknownKid(kid.to_string()))?;
        if entry.not_after <= SystemTime::now() {
            return Err(KeyStoreError::UnknownKid(kid.to_string()));
        }
        Ok(Arc::clone(entry))
    }

    fn all_verify_keys(&self) -> Result<Vec<Arc<VerifyKey>>, KeyStoreError> {
        let inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        let now = SystemTime::now();
        let mut out = Vec::with_capacity(1 + inner.previous.len());
        out.push(Self::active_verify_key(&inner));
        for vk in inner.previous.values() {
            if vk.not_after > now {
                out.push(Arc::clone(vk));
            }
        }
        Ok(out)
    }

    fn rotate(&self) -> Result<RotateOutcome, KeyStoreError> {
        let mut inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        let now = SystemTime::now();

        // Capture old verifying key + KID for the verify-set.
        let old_kid = inner.active_kid.clone();
        let old_verify = VerifyKey {
            kid: old_kid.clone(),
            verifying_key: inner.active_signing.verifying_key(),
            not_before: inner.active_not_before,
            not_after: now + self.grace_window,
        };
        inner.previous.insert(old_kid.clone(), Arc::new(old_verify));

        // Generate new active. Old SigningKey is replaced and dropped
        // here; ed25519-dalek's ZeroizeOnDrop wipes it.
        let new_signing = SigningKey::generate(&mut rand::rng());
        let new_kid = rfc7638_kid(&new_signing.verifying_key());
        inner.active_signing = new_signing;
        inner.active_kid = new_kid.clone();
        inner.active_not_before = now;

        Self::sweep_expired(&mut inner);

        // (#55 LOW-3) Cap grace-window entries — evict soonest-expiring
        // when over the limit. Defends against operator misconfiguration
        // (rotation cadence < grace window) growing the verify-set
        // without bound.
        while inner.previous.len() > super::file::MAX_PREVIOUS_ENTRIES {
            if let Some(soonest_kid) = inner
                .previous
                .iter()
                .min_by_key(|(_, vk)| vk.not_after)
                .map(|(k, _)| k.clone())
            {
                inner.previous.remove(&soonest_kid);
            } else {
                break;
            }
        }

        Ok(RotateOutcome {
            new_kid,
            old_kid: Some(old_kid),
        })
    }

    fn revoke(&self, kid: &str) -> Result<(), KeyStoreError> {
        let mut inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        if kid == inner.active_kid {
            return Err(KeyStoreError::CannotRevokeActive);
        }
        inner
            .previous
            .remove(kid)
            .ok_or_else(|| KeyStoreError::UnknownKid(kid.to_string()))?;
        Ok(())
    }

    fn sweep_expired(&self) -> Result<usize, KeyStoreError> {
        let mut inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        let before = inner.previous.len();
        Self::sweep_expired(&mut inner);
        Ok(before - inner.previous.len())
    }

    fn supports_rotation(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    #[test]
    fn fresh_store_has_one_active_key() {
        let store = InMemoryKeyStore::new();
        let keys = store.all_verify_keys().unwrap();
        assert_eq!(keys.len(), 1);
        let active = store.active_kid().unwrap();
        assert_eq!(keys[0].kid, active);
    }

    #[test]
    fn sign_returns_kid_alg_and_verifiable_signature() {
        let store = InMemoryKeyStore::new();
        let bytes = b"canonical payload";
        let signed = store.sign(bytes).unwrap();
        assert_eq!(signed.alg, "EdDSA");
        assert_eq!(signed.signature.len(), 64);

        let vk = store.verify_key(&signed.kid).unwrap();
        let sig_bytes: [u8; 64] = signed.signature.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verifying_key
            .verify(bytes, &sig)
            .expect("signature must verify against active key");
    }

    #[test]
    fn rotate_extends_verify_set_for_grace_window() {
        let store = InMemoryKeyStore::with_grace_window(Duration::from_secs(60));
        let original_kid = store.active_kid().unwrap();
        let outcome = store.rotate().unwrap();
        assert_eq!(outcome.old_kid.as_deref(), Some(original_kid.as_str()));
        assert_ne!(outcome.new_kid, original_kid);

        // Both KIDs are now in the verify-set.
        let keys = store.all_verify_keys().unwrap();
        assert_eq!(keys.len(), 2);
        let kids: Vec<_> = keys.iter().map(|k| k.kid.as_str()).collect();
        assert!(kids.contains(&original_kid.as_str()));
        assert!(kids.contains(&outcome.new_kid.as_str()));

        // Active KID is the new one.
        assert_eq!(store.active_kid().unwrap(), outcome.new_kid);
    }

    #[test]
    fn token_signed_pre_rotation_verifies_during_grace() {
        let store = InMemoryKeyStore::with_grace_window(Duration::from_secs(60));
        let bytes = b"pre-rotation payload";
        let signed = store.sign(bytes).unwrap();
        let pre_kid = signed.kid.clone();

        store.rotate().unwrap();

        // Verify with the old (now-rotated-out) key — still in verify-set.
        let vk = store.verify_key(&pre_kid).unwrap();
        let sig_bytes: [u8; 64] = signed.signature.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verifying_key
            .verify(bytes, &sig)
            .expect("pre-rotation signature must verify during grace");
    }

    #[test]
    fn revoke_removes_from_verify_set() {
        let store = InMemoryKeyStore::with_grace_window(Duration::from_secs(60));
        let original_kid = store.active_kid().unwrap();
        store.rotate().unwrap();

        // Before revoke: in verify-set.
        store.verify_key(&original_kid).unwrap();
        store.revoke(&original_kid).unwrap();
        // After revoke: gone.
        let err = store.verify_key(&original_kid).unwrap_err();
        assert!(matches!(err, KeyStoreError::UnknownKid(_)));
    }

    #[test]
    fn revoke_active_kid_is_rejected() {
        let store = InMemoryKeyStore::new();
        let active = store.active_kid().unwrap();
        let err = store.revoke(&active).unwrap_err();
        assert!(matches!(err, KeyStoreError::CannotRevokeActive));
    }

    #[test]
    fn unknown_kid_lookup_errors() {
        let store = InMemoryKeyStore::new();
        let err = store.verify_key("not-a-real-kid").unwrap_err();
        assert!(matches!(err, KeyStoreError::UnknownKid(_)));
    }

    #[test]
    fn many_rotations_bound_verify_set_to_two_during_short_grace() {
        let store = InMemoryKeyStore::with_grace_window(Duration::from_millis(1));
        for _ in 0..5 {
            store.rotate().unwrap();
            // Give the grace window a moment to expire.
            std::thread::sleep(Duration::from_millis(5));
        }
        // After enough wait, only the active key remains (no live grace entries).
        let keys = store.all_verify_keys().unwrap();
        assert_eq!(
            keys.len(),
            1,
            "expired grace entries must be swept; got {} keys",
            keys.len()
        );
    }
}
