//! File-backed `JwtKeyStore` — encrypted-at-rest with the `age` v1 format.
//!
//! The on-disk format is opaque to the operator: an age-encrypted blob
//! whose plaintext is a JSON-serialized [`PersistedState`]. The
//! operator supplies a passphrase via [`FileKeyStore::open_with_passphrase`].
//!
//! # Production caveat (v1)
//!
//! The passphrase is the only thing protecting the on-disk key. For
//! real production, an operator should:
//! - Source the passphrase from a real secret store (KMS, Vault).
//! - Rotate the passphrase periodically (re-encryption is supported
//!   via `rotate_passphrase()` — left for a follow-up PR).
//! - Run the OP inside a hardened container with a read-only root
//!   filesystem and an explicit data volume for the keystore file.
//!
//! A KMS-backed [`super::JwtKeyStore`] impl is the eventual production
//! goal; this file backend is the v1 "bring-your-own-passphrase" tier.
//!
//! See `crates/nucleus-oidc-provider/THREAT_MODEL.md` T01 (key
//! compromise) and `docs/local-issuer-prod-readiness-gap.md` GA-1 / GA-9.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::memory::DEFAULT_GRACE_WINDOW;
use super::{rfc7638_kid, JwtKeyStore, KeyStoreError, RotateOutcome, SignedBytes, VerifyKey};

/// File-backed, encrypted-at-rest key store.
/// (#55 LOW-3) Hard cap on the verify-set's grace-window entries. With
/// rotation cadence < grace window the `previous` map grows linearly
/// with rotation count; cap at 32 entries and evict the soonest-expiring
/// when over. Operator misconfiguration (rotation every 1m, grace 1h)
/// otherwise grows unbounded.
pub(crate) const MAX_PREVIOUS_ENTRIES: usize = 32;

pub struct FileKeyStore {
    /// Path to the age-encrypted blob.
    path: PathBuf,
    /// Operator passphrase. Wrapped in `Zeroizing` so it scrubs on Drop.
    passphrase: Mutex<Zeroizing>,
    inner: Mutex<Inner>,
    /// (#55 MED-3) Serializes concurrent rotate() calls so two
    /// rotations can't race to disk. Held during the full
    /// generate+persist+swap sequence. Sign() does NOT take this
    /// lock, so signing latency is not affected by rotation.
    rotate_lock: Mutex<()>,
    grace_window: Duration,
}

struct Inner {
    active_signing: SigningKey,
    active_kid: String,
    active_not_before: SystemTime,
    previous: HashMap<String, Arc<VerifyKey>>,
}

/// Persisted form. `deny_unknown_fields` so a typo in a future migration
/// fails loud, not silent (audit MED-3 discipline).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    schema_version: u32,
    active: PersistedActive,
    previous: Vec<PersistedVerify>,
    grace_window_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedActive {
    kid: String,
    signing_key_bytes: [u8; 32],
    not_before_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedVerify {
    kid: String,
    verifying_key_bytes: [u8; 32],
    not_before_unix: u64,
    not_after_unix: u64,
}

/// String wrapper that zeroizes on Drop. Used for the operator passphrase
/// to keep its lifetime bounded in memory.
struct Zeroizing(String);

impl Drop for Zeroizing {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl FileKeyStore {
    /// Open an existing keystore file. If the file does not exist,
    /// creates a fresh keystore at the given path with one active key
    /// and writes it through. The passphrase is used both ways.
    ///
    /// The grace window defaults to 1h; use
    /// [`Self::open_with_grace_window`] for test-friendly short windows.
    pub fn open_with_passphrase(
        path: impl AsRef<Path>,
        passphrase: String,
    ) -> Result<Self, KeyStoreError> {
        Self::open_with_grace_window(path, passphrase, DEFAULT_GRACE_WINDOW)
    }

    /// Open with explicit grace window. Tests want short windows so
    /// they can exercise expiry without sleeping.
    pub fn open_with_grace_window(
        path: impl AsRef<Path>,
        passphrase: String,
        grace_window: Duration,
    ) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        let zeroizing_passphrase = Zeroizing(passphrase);

        let inner = if path.exists() {
            Self::decrypt_and_load(&path, &zeroizing_passphrase.0)?
        } else {
            // First-time bootstrap: generate fresh active, persist.
            let signing = SigningKey::generate(&mut rand::rng());
            let kid = rfc7638_kid(&signing.verifying_key());
            let inner = Inner {
                active_signing: signing,
                active_kid: kid,
                active_not_before: SystemTime::now(),
                previous: HashMap::new(),
            };
            Self::encrypt_and_write(&path, &zeroizing_passphrase.0, &inner, grace_window)?;
            inner
        };

        Ok(Self {
            path,
            passphrase: Mutex::new(zeroizing_passphrase),
            inner: Mutex::new(inner),
            rotate_lock: Mutex::new(()),
            grace_window,
        })
    }

    fn decrypt_and_load(path: &Path, passphrase: &str) -> Result<Inner, KeyStoreError> {
        let encrypted =
            fs::read(path).map_err(|e| KeyStoreError::Backend(format!("read {path:?}: {e}")))?;
        let decryptor = age::Decryptor::new(encrypted.as_slice())
            .map_err(|e| KeyStoreError::Backend(format!("age decryptor: {e}")))?;
        let identity =
            age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase.to_string()));
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| KeyStoreError::Backend(format!("age decrypt: {e}")))?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| KeyStoreError::Backend(format!("age read: {e}")))?;

        let persisted: PersistedState = serde_json::from_slice(&plaintext)
            .map_err(|e| KeyStoreError::Backend(format!("json parse: {e}")))?;
        if persisted.schema_version != 1 {
            return Err(KeyStoreError::Backend(format!(
                "unsupported schema_version {} (expected 1)",
                persisted.schema_version
            )));
        }

        let active_signing = SigningKey::from_bytes(&persisted.active.signing_key_bytes);
        let active_kid = persisted.active.kid;
        let active_not_before = UNIX_EPOCH + Duration::from_secs(persisted.active.not_before_unix);

        let mut previous = HashMap::new();
        for p in persisted.previous {
            let vk = VerifyingKey::from_bytes(&p.verifying_key_bytes)
                .map_err(|e| KeyStoreError::Backend(format!("vk parse: {e}")))?;
            let entry = Arc::new(VerifyKey {
                kid: p.kid.clone(),
                verifying_key: vk,
                not_before: UNIX_EPOCH + Duration::from_secs(p.not_before_unix),
                not_after: UNIX_EPOCH + Duration::from_secs(p.not_after_unix),
            });
            previous.insert(p.kid, entry);
        }

        Ok(Inner {
            active_signing,
            active_kid,
            active_not_before,
            previous,
        })
    }

    fn encrypt_and_write(
        path: &Path,
        passphrase: &str,
        inner: &Inner,
        grace_window: Duration,
    ) -> Result<(), KeyStoreError> {
        let persisted = PersistedState {
            schema_version: 1,
            active: PersistedActive {
                kid: inner.active_kid.clone(),
                signing_key_bytes: inner.active_signing.to_bytes(),
                not_before_unix: inner
                    .active_not_before
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
            previous: inner
                .previous
                .values()
                .map(|vk| PersistedVerify {
                    kid: vk.kid.clone(),
                    verifying_key_bytes: vk.verifying_key.to_bytes(),
                    not_before_unix: vk
                        .not_before
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    not_after_unix: vk
                        .not_after
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                })
                .collect(),
            grace_window_secs: grace_window.as_secs(),
        };

        let plaintext = serde_json::to_vec(&persisted)
            .map_err(|e| KeyStoreError::Backend(format!("json encode: {e}")))?;

        let recipient =
            age::scrypt::Recipient::new(age::secrecy::SecretString::from(passphrase.to_string()));
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| KeyStoreError::Backend(format!("age encryptor: {e}")))?;

        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| KeyStoreError::Backend(format!("age wrap: {e}")))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| KeyStoreError::Backend(format!("age write: {e}")))?;
        writer
            .finish()
            .map_err(|e| KeyStoreError::Backend(format!("age finish: {e}")))?;

        // Atomic write: .tmp + fsync + rename.
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| KeyStoreError::Backend(format!("create {tmp:?}: {e}")))?;
            f.write_all(&encrypted)
                .map_err(|e| KeyStoreError::Backend(format!("write {tmp:?}: {e}")))?;
            f.sync_all()
                .map_err(|e| KeyStoreError::Backend(format!("fsync {tmp:?}: {e}")))?;
        }
        fs::rename(&tmp, path)
            .map_err(|e| KeyStoreError::Backend(format!("rename {tmp:?} -> {path:?}: {e}")))?;
        // (#55 MED-4) Parent-directory fsync after rename so the
        // rename itself survives a crash. On ext4/data=writeback (or
        // any filesystem that delays directory-entry writes), the
        // file's contents are durable but the new path may not be.
        // Without this, a crash mid-rotation can lose the rotated
        // key — weakening T01's rotation-bounds-blast-radius claim.
        if let Some(parent) = path.parent() {
            // Opening a directory for fsync is a Unix idiom; on Windows
            // this is a no-op-or-error, so we ignore failure there.
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn active_verify_key(inner: &Inner) -> Arc<VerifyKey> {
        Arc::new(VerifyKey {
            kid: inner.active_kid.clone(),
            verifying_key: inner.active_signing.verifying_key(),
            not_before: inner.active_not_before,
            not_after: SystemTime::now() + Duration::from_secs(365 * 24 * 3600),
        })
    }

    fn sweep_expired(inner: &mut Inner) {
        let now = SystemTime::now();
        inner.previous.retain(|_, vk| vk.not_after > now);
    }

    fn persist(&self, inner: &Inner) -> Result<(), KeyStoreError> {
        let pass = self
            .passphrase
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?;
        Self::encrypt_and_write(&self.path, &pass.0, inner, self.grace_window)
    }
}

impl JwtKeyStore for FileKeyStore {
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
        // (#55 MED-3) Serialize concurrent rotations on a dedicated
        // mutex so sign() is never blocked by rotate's disk I/O.
        let _rotate_guard = self
            .rotate_lock
            .lock()
            .map_err(|_| KeyStoreError::Poisoned)?;

        let now = SystemTime::now();
        let new_signing = SigningKey::generate(&mut rand::rng());
        let new_kid = rfc7638_kid(&new_signing.verifying_key());

        // Briefly take the inner lock to snapshot current state — no
        // disk I/O happens under this lock.
        let (old_kid, old_verifying, old_not_before, mut next_previous) = {
            let inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
            (
                inner.active_kid.clone(),
                inner.active_signing.verifying_key(),
                inner.active_not_before,
                inner.previous.clone(),
            )
        };

        // Mutate the snapshot OUTSIDE the lock.
        let old_verify = Arc::new(VerifyKey {
            kid: old_kid.clone(),
            verifying_key: old_verifying,
            not_before: old_not_before,
            not_after: now + self.grace_window,
        });
        next_previous.insert(old_kid.clone(), old_verify);
        // Sweep expired.
        next_previous.retain(|_, vk| vk.not_after > now);
        // (#55 LOW-3) Cap grace-window entries — evict soonest-expiring
        // when over MAX_PREVIOUS_ENTRIES.
        while next_previous.len() > MAX_PREVIOUS_ENTRIES {
            if let Some(soonest_kid) = next_previous
                .iter()
                .min_by_key(|(_, vk)| vk.not_after)
                .map(|(k, _)| k.clone())
            {
                next_previous.remove(&soonest_kid);
            } else {
                break;
            }
        }

        // Build a temp Inner to persist — uses a duplicate SigningKey
        // derived from the same bytes so the original `new_signing`
        // can move into the in-memory swap below.
        let signing_bytes = new_signing.to_bytes();
        let persist_inner = Inner {
            active_signing: SigningKey::from_bytes(&signing_bytes),
            active_kid: new_kid.clone(),
            active_not_before: now,
            previous: next_previous.clone(),
        };

        // Disk I/O OUTSIDE the inner lock — encrypt+fsync can take
        // hundreds of ms (age scrypt KDF + fsync) without stalling
        // concurrent sign() calls.
        {
            let pass = self
                .passphrase
                .lock()
                .map_err(|_| KeyStoreError::Poisoned)?;
            Self::encrypt_and_write(&self.path, &pass.0, &persist_inner, self.grace_window)?;
        }

        // Atomic in-memory swap (brief inner lock).
        {
            let mut inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
            inner.active_signing = new_signing;
            inner.active_kid = new_kid.clone();
            inner.active_not_before = now;
            inner.previous = next_previous;
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
        self.persist(&inner)?;
        Ok(())
    }

    fn sweep_expired(&self) -> Result<usize, KeyStoreError> {
        let mut inner = self.inner.lock().map_err(|_| KeyStoreError::Poisoned)?;
        let before = inner.previous.len();
        Self::sweep_expired(&mut inner);
        let removed = before - inner.previous.len();
        if removed > 0 {
            self.persist(&inner)?;
        }
        Ok(removed)
    }

    fn supports_rotation(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn bootstrap_creates_persistent_file_on_first_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.age");
        let store =
            FileKeyStore::open_with_passphrase(&path, "test-passphrase".to_string()).unwrap();
        assert!(path.exists());
        let kid = store.active_kid().unwrap();
        assert!(!kid.is_empty());
    }

    #[test]
    fn reopen_recovers_active_kid_across_process_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.age");
        let pass = "the-passphrase".to_string();

        let kid_a = {
            let s = FileKeyStore::open_with_passphrase(&path, pass.clone()).unwrap();
            s.active_kid().unwrap()
        };

        // Drop the store. Re-open with the same passphrase.
        let kid_b = {
            let s = FileKeyStore::open_with_passphrase(&path, pass).unwrap();
            s.active_kid().unwrap()
        };

        assert_eq!(kid_a, kid_b, "reopen must recover the same active KID");
    }

    #[test]
    fn wrong_passphrase_fails_decrypt() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.age");
        let pass = "correct".to_string();
        let _ = FileKeyStore::open_with_passphrase(&path, pass).unwrap();

        let result = FileKeyStore::open_with_passphrase(&path, "wrong".to_string());
        let err = match result {
            Ok(_) => panic!("wrong passphrase must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, KeyStoreError::Backend(_)));
    }

    #[test]
    fn rotate_persists_grace_window_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.age");
        let pass = "the-passphrase".to_string();
        let store =
            FileKeyStore::open_with_grace_window(&path, pass.clone(), Duration::from_secs(60))
                .unwrap();

        let original_kid = store.active_kid().unwrap();
        let outcome = store.rotate().unwrap();
        drop(store);

        // Reopen: previous KID is in verify-set; new KID is active.
        let store2 = FileKeyStore::open_with_passphrase(&path, pass).unwrap();
        let active = store2.active_kid().unwrap();
        assert_eq!(active, outcome.new_kid);
        // Old KID still resolvable.
        store2.verify_key(&original_kid).expect(
            "rotated-out KID must persist in verify-set across restart during grace window",
        );
    }

    #[test]
    fn revoke_persists_removal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.age");
        let pass = "p".to_string();
        let store =
            FileKeyStore::open_with_grace_window(&path, pass.clone(), Duration::from_secs(60))
                .unwrap();

        let original_kid = store.active_kid().unwrap();
        store.rotate().unwrap();
        store.revoke(&original_kid).unwrap();
        drop(store);

        let store2 = FileKeyStore::open_with_passphrase(&path, pass).unwrap();
        let err = store2.verify_key(&original_kid).unwrap_err();
        assert!(matches!(err, KeyStoreError::UnknownKid(_)));
    }
}
