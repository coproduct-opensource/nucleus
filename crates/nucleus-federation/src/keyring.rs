// SPDX-License-Identifier: MIT
//
//! The federation issuer's key on disk: load it, publish it, rotate it.
//!
//! A node signs every outbound assertion with ONE P-256 key, and a provider
//! trusts that key only because it appears in the issuer's JWKS — fetched by
//! discovery, fetched from a URL, or pasted in by hand. So the key is not only
//! a secret to keep; it is a published fact, and changing it is a protocol
//! with the providers, not a file operation. This module is that protocol,
//! kept in one place so the node (which signs) and the operator's CLI (which
//! publishes and rotates) cannot disagree about which files mean what.
//!
//! # The files (under the node's state directory)
//!
//! | file | meaning | published | signs |
//! |---|---|---|---|
//! | [`CURRENT_KEY_FILE`] | the key the node signs with | yes | yes |
//! | [`NEXT_KEY_FILE`] | staged: published, not yet used | yes | **never** |
//! | [`PREV_KEY_FILE`] | promoted away: still published until its last assertion expired | yes | no |
//! | [`ROTATION_RECORD_FILE`] | when `next` was staged and `prev` was promoted, keyed by `kid` | — | — |
//!
//! Every file is written by [`write_atomic`](KeyDir) — a `0400` temporary in
//! the same directory, fsynced, then renamed over the target — so a reader
//! sees the old file or the new one, never a torn one. Every key file is read
//! only after the checks in [`KeyDir`]: a regular file (not a symlink), no
//! group or other permission bits, owned by the key directory's owner.
//!
//! # The state machine
//!
//! ```text
//!            stage                 promote                    retire
//!   {C}  ─────────────►  {C, N}  ───────────►  {C'=N, P=C}  ──────────►  {C'}
//!         JWKS: +N          ≥ overlap after       JWKS: unchanged     ≥ retire window
//!                           stage                                     after promote
//!                                                                     JWKS: −P
//! ```
//!
//! * **Stage** generates `next`. From here the JWKS carries both keys; the
//!   node still signs with `current` and cannot do otherwise — nothing in this
//!   module hands out `next` as a signer.
//! * **Promote** is refused until `next` has been published for
//!   [`RotationPolicy::promote_overlap`]: the providers' JWKS cache lifetime
//!   (a provider that fetched the JWKS just BEFORE the stage keeps that copy
//!   this long) plus the maximum assertion lifetime (the profile's stated
//!   margin, §1). Then `current` is copied to `prev` and `next` is renamed
//!   over `current`. The published SET does not change at promote — the
//!   same two keys, relabelled — which is why the overlap is paid at stage.
//! * **Retire** is refused until [`RotationPolicy::retire_after`] has passed
//!   since the promote: the longest assertion the old key could have signed,
//!   plus the clock skew a provider may tolerate on its `exp`. Then `prev` is
//!   removed and leaves the JWKS.
//!
//! One rotation at a time: promote is refused while a `prev` is still
//! published, so the JWKS never needs more than three keys and a retire never
//! removes a key that a second, overlapping rotation still depends on.
//!
//! # Why the timestamps are keyed by `kid`
//!
//! The overlap check is the whole safety argument, so the record that feeds
//! it must describe the files actually present. A stamp counts only for the
//! key whose `kid` it names; a `next` or `prev` file with no matching stamp —
//! a crash between the key write and the record write, or a file someone put
//! there by hand — is stamped NOW, which restarts its clock rather than
//! assuming it has been published all along. Every failure of the record
//! makes a rotation slower, never earlier.
//!
//! # How the running node picks up a promoted key
//!
//! Without a restart. [`KeyDirSigner`] re-checks the `current` file's
//! identity (device, inode, size, mtime) on every assertion and reloads when
//! it changed; promote is a `rename`, so the inode always changes. A reload
//! that fails its checks FAILS the assertion rather than falling back to the
//! key the operator replaced — see [`crate::CurrentSigner`].

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::assertion::{
    AssertionSigner, CurrentSigner, EcdsaP256Signer, MAX_TTL, PublicJwk, SIGNING_ALG, SignError,
    is_valid_issuer, jwks,
};

/// The key the node signs with. The name P3 shipped, unchanged, so a node
/// that already has a key keeps its `kid`.
pub const CURRENT_KEY_FILE: &str = "jwt_svid_p256_signing_key.der";
/// A staged key: published, never used to sign until promoted.
pub const NEXT_KEY_FILE: &str = "jwt_svid_p256_signing_key.next.der";
/// The key promoted away from, published until its last assertion expired.
pub const PREV_KEY_FILE: &str = "jwt_svid_p256_signing_key.prev.der";
/// When `next` was staged and `prev` promoted, keyed by `kid`.
pub const ROTATION_RECORD_FILE: &str = "jwt_svid_p256_rotation.json";
/// Held for the length of one stage/promote/retire.
const LOCK_FILE: &str = "jwt_svid_p256_rotation.lock";

/// How long a provider is assumed to cache the issuer's JWKS, unless the
/// operator says otherwise. Fifteen minutes is a common default for OIDC
/// relying parties; a provider that caches longer needs the flag raised.
pub const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(900);

/// The most clock skew a provider may tolerate on `exp` — the profile's upper
/// bound (§2.2 item 14: at least 30 s, SHOULD NOT exceed 300 s).
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Where the discovery document lives, relative to the issuer.
pub const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

/// Where the JWKS lives, relative to the issuer. Beside the discovery
/// document, so a static host serves one `.well-known/` directory and the
/// operator publishes both files with one copy.
pub const JWKS_PATH: &str = ".well-known/jwks.json";

/// Why a key operation was refused. Messages name files and `kid`s — public
/// facts — and never carry key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    /// A filesystem operation failed.
    #[error("{}: {what}", path.display())]
    Io { path: PathBuf, what: String },
    /// A key or record file carries group or other permission bits.
    #[error(
        "{} has mode {mode:o}; a signing key must be readable by its owner only (0400)",
        path.display()
    )]
    Permissions { path: PathBuf, mode: u32 },
    /// The key directory is writable by someone other than its owner, who
    /// could then rename a key of their choosing into place.
    #[error(
        "{} has mode {mode:o}; the key directory must not be writable by group or others",
        path.display()
    )]
    DirPermissions { path: PathBuf, mode: u32 },
    /// A key file, or a file this process just created, is owned by someone
    /// other than the key directory's owner.
    #[error(
        "{} is owned by uid {found}, not by the key directory's owner (uid {expected}); \
         run this as the node's user, or the node will not be able to read the key",
        path.display()
    )]
    Owner {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    /// The path is a symlink or not a regular file.
    #[error("{} is not a regular file", path.display())]
    NotAFile { path: PathBuf },
    /// The file is not a P-256 PKCS#8 key.
    #[error("{} is not a P-256 PKCS#8 key", path.display())]
    Key { path: PathBuf },
    /// There is no current key.
    #[error("no current key at {}", path.display())]
    NoCurrent { path: PathBuf },
    /// Promote with nothing staged.
    #[error("no key is staged; run `rotate --stage` first")]
    NotStaged,
    /// Promote while the previous rotation's key is still published.
    #[error(
        "the previous key {kid} is still published; retire it before promoting again \
         (one rotation at a time)"
    )]
    PrevStillPublished { kid: String },
    /// Retire with nothing to retire.
    #[error("there is no previous key to retire")]
    NothingToRetire,
    /// The overlap (promote) or retire window has not passed.
    #[error(
        "too early to {what}: allowed at unix time {allowed_at}, {} s from now",
        allowed_at.saturating_sub(*now)
    )]
    TooEarly {
        what: &'static str,
        allowed_at: u64,
        now: u64,
    },
    /// The rotation record could not be parsed.
    #[error("rotation record {} is unreadable: {what}", path.display())]
    Record { path: PathBuf, what: String },
    /// Another rotation holds the lock, or a crashed one left it.
    #[error(
        "{} exists: another rotation is running, or one crashed — remove it if none is running",
        path.display()
    )]
    Locked { path: PathBuf },
    /// The issuer is not an `https` URL with a host.
    #[error("issuer must be an https URL with a host, got {0:?}")]
    Issuer(String),
    /// The configured maximum assertion lifetime is outside `1..=MAX_TTL`.
    #[error("the maximum assertion lifetime must be between 1 and {} seconds", MAX_TTL.as_secs())]
    Policy,
    /// Key generation failed.
    #[error("key generation failed")]
    Generate,
}

/// The waiting periods a rotation observes. See the module docs for why each
/// term is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    jwks_cache_ttl: Duration,
    max_assertion_ttl: Duration,
}

impl Default for RotationPolicy {
    /// 15 min cache + 60 min assertions: promote after 75 min, retire after
    /// 65 min.
    fn default() -> Self {
        Self {
            jwks_cache_ttl: DEFAULT_JWKS_CACHE_TTL,
            max_assertion_ttl: MAX_TTL,
        }
    }
}

impl RotationPolicy {
    /// A policy for providers that cache the JWKS for `jwks_cache_ttl` and a
    /// node whose longest assertion lives `max_assertion_ttl`.
    ///
    /// # Errors
    /// `max_assertion_ttl` is zero or above [`MAX_TTL`]. Lowering it below the
    /// registry's largest `assertion_ttl_secs` would shorten the retire window
    /// under a live assertion; the CLI checks that against the registry when
    /// it is given one.
    pub fn new(
        jwks_cache_ttl: Duration,
        max_assertion_ttl: Duration,
    ) -> Result<Self, KeyringError> {
        if max_assertion_ttl.is_zero() || max_assertion_ttl > MAX_TTL {
            return Err(KeyringError::Policy);
        }
        Ok(Self {
            jwks_cache_ttl,
            max_assertion_ttl,
        })
    }

    /// How long `next` must have been published before it may sign:
    /// JWKS cache lifetime + maximum assertion lifetime.
    pub fn promote_overlap(&self) -> Duration {
        self.jwks_cache_ttl + self.max_assertion_ttl
    }

    /// How long after a promote the old key must stay published: the longest
    /// assertion it could have signed just before the swap, plus the skew a
    /// provider may allow on that assertion's `exp`.
    pub fn retire_after(&self) -> Duration {
        self.max_assertion_ttl + MAX_CLOCK_SKEW
    }
}

/// A `kid` and the unix time something happened to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    kid: String,
    at: u64,
}

/// [`ROTATION_RECORD_FILE`]'s contents.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationRecord {
    /// When the key now in `next` was staged.
    #[serde(default)]
    next_staged: Option<Stamp>,
    /// When the key now in `prev` stopped being `current`.
    #[serde(default)]
    prev_promoted: Option<Stamp>,
}

impl RotationRecord {
    /// The record as it must be for the files present: a stamp survives only
    /// for the `kid` it names, and a file with no stamp is stamped `now`
    /// (its clock restarts — slower, never earlier). A `next` or `prev` that
    /// is the current key (an interrupted promote's copy) is not a separate
    /// key and gets no stamp.
    fn reconciled(&self, current: &str, next: Option<&str>, prev: Option<&str>, now: u64) -> Self {
        let keep = |file: Option<&str>, stamp: &Option<Stamp>| {
            let kid = file.filter(|k| *k != current)?;
            Some(match stamp {
                Some(s) if s.kid == kid => s.clone(),
                _ => Stamp {
                    kid: kid.to_string(),
                    at: now,
                },
            })
        };
        Self {
            next_staged: keep(next, &self.next_staged),
            prev_promoted: keep(prev, &self.prev_promoted),
        }
    }
}

/// A staged key and when it was staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub jwk: PublicJwk,
    pub staged_at: u64,
}

/// A retained previous key and when it was promoted away from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retained {
    pub jwk: PublicJwk,
    pub promoted_at: u64,
}

/// What is on disk, as the providers should see it. Public halves only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyState {
    /// The key the node signs with.
    pub current: PublicJwk,
    /// A staged key, if any.
    pub next: Option<Staged>,
    /// A previous key still published, if any.
    pub prev: Option<Retained>,
}

impl KeyState {
    /// Every key the JWKS must carry: current, then next, then prev.
    pub fn published(&self) -> Vec<PublicJwk> {
        let mut keys = vec![self.current.clone()];
        keys.extend(self.next.as_ref().map(|s| s.jwk.clone()));
        keys.extend(self.prev.as_ref().map(|r| r.jwk.clone()));
        keys
    }

    /// The JWKS document for [`KeyState::published`].
    pub fn jwks(&self) -> serde_json::Value {
        jwks(&self.published())
    }

    /// When a promote becomes allowed, if a key is staged.
    pub fn promote_allowed_at(&self, policy: &RotationPolicy) -> Option<u64> {
        self.next.as_ref().map(|s| {
            s.staged_at
                .saturating_add(policy.promote_overlap().as_secs())
        })
    }

    /// When a retire becomes allowed, if a previous key is published.
    pub fn retire_allowed_at(&self, policy: &RotationPolicy) -> Option<u64> {
        self.prev.as_ref().map(|r| {
            r.promoted_at
                .saturating_add(policy.retire_after().as_secs())
        })
    }
}

/// The published key set before and after a rotation step — what an operator
/// with an INLINE registration must re-register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub before: Vec<PublicJwk>,
    pub after: KeyState,
}

impl Transition {
    /// `kid`s published after the step and not before.
    pub fn added(&self) -> Vec<String> {
        let before: Vec<&str> = self.before.iter().map(|k| k.kid.as_str()).collect();
        self.after
            .published()
            .into_iter()
            .filter(|k| !before.contains(&k.kid.as_str()))
            .map(|k| k.kid)
            .collect()
    }

    /// `kid`s published before the step and not after.
    pub fn removed(&self) -> Vec<String> {
        let after: Vec<String> = self.after.published().into_iter().map(|k| k.kid).collect();
        self.before
            .iter()
            .filter(|k| !after.contains(&k.kid))
            .map(|k| k.kid.clone())
            .collect()
    }
}

/// The directory holding the issuer's key files (the node's state directory).
#[derive(Debug, Clone)]
pub struct KeyDir {
    dir: PathBuf,
}

/// Removes the rotation lock when a step ends, however it ends.
struct Lock(PathBuf);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl KeyDir {
    /// The key files under `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn io(path: &Path, e: &std::io::Error) -> KeyringError {
        KeyringError::Io {
            path: path.to_path_buf(),
            what: e.to_string(),
        }
    }

    /// The uid every key file must carry: the key directory's owner. Not the
    /// caller's uid — an operator reading as root may inspect a node's keys,
    /// but the node (the directory's owner) must be able to read every key it
    /// will ever be asked to sign with.
    #[cfg(unix)]
    fn owner_uid(&self) -> Result<u32, KeyringError> {
        use std::os::unix::fs::MetadataExt as _;
        fs::metadata(&self.dir)
            .map(|m| m.uid())
            .map_err(|e| Self::io(&self.dir, &e))
    }

    /// Refuse a directory someone other than its owner may write to.
    fn check_dir(&self) -> Result<(), KeyringError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&self.dir)
                .map_err(|e| Self::io(&self.dir, &e))?
                .permissions()
                .mode();
            if mode & 0o022 != 0 {
                return Err(KeyringError::DirPermissions {
                    path: self.dir.clone(),
                    mode: mode & 0o7777,
                });
            }
        }
        Ok(())
    }

    /// Open `name` read-only after checking it: a regular file (a symlink is
    /// refused, and the opened file must be the one checked), no group/other
    /// bits, owned by the directory's owner. `None` if absent.
    fn open_checked(&self, name: &str) -> Result<Option<(File, fs::Metadata)>, KeyringError> {
        let path = self.path(name);
        let link = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Self::io(&path, &e)),
        };
        if !link.file_type().is_file() {
            return Err(KeyringError::NotAFile { path });
        }
        let file = File::open(&path).map_err(|e| Self::io(&path, &e))?;
        let meta = file.metadata().map_err(|e| Self::io(&path, &e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            // Swapped for something else between the lstat and the open.
            if (meta.dev(), meta.ino()) != (link.dev(), link.ino()) {
                return Err(KeyringError::NotAFile { path });
            }
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(KeyringError::Permissions {
                    path,
                    mode: mode & 0o7777,
                });
            }
            let expected = self.owner_uid()?;
            if meta.uid() != expected {
                return Err(KeyringError::Owner {
                    path,
                    found: meta.uid(),
                    expected,
                });
            }
        }
        Ok(Some((file, meta)))
    }

    /// The checked bytes of `name`, wiped on drop.
    fn read_checked(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        let Some((mut file, _)) = self.open_checked(name)? else {
            return Ok(None);
        };
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes)
            .map_err(|e| Self::io(&self.path(name), &e))?;
        Ok(Some(bytes))
    }

    /// The key in `name`, checked and parsed.
    fn load(&self, name: &str) -> Result<Option<EcdsaP256Signer>, KeyringError> {
        let Some(bytes) = self.read_checked(name)? else {
            return Ok(None);
        };
        EcdsaP256Signer::from_pkcs8(&bytes)
            .map(Some)
            .map_err(|_| KeyringError::Key {
                path: self.path(name),
            })
    }

    /// The current key, if there is one. For the node's start-up, which
    /// creates one when this is `None`.
    ///
    /// # Errors
    /// The file exists but fails its checks, or is not a P-256 key
    /// ([`KeyringError::Key`] — the one the node may choose to replace).
    pub fn load_current(&self) -> Result<Option<EcdsaP256Signer>, KeyringError> {
        self.load(CURRENT_KEY_FILE)
    }

    /// Generate a key and write it as the current key, atomically, `0400`.
    /// For a node with no key yet (or an unparseable one). Rotation never
    /// calls this: it only ever renames a PUBLISHED key into place.
    pub fn create_current(&self) -> Result<EcdsaP256Signer, KeyringError> {
        let der = EcdsaP256Signer::generate_pkcs8().map_err(|_| KeyringError::Generate)?;
        let signer = EcdsaP256Signer::from_pkcs8(&der).map_err(|_| KeyringError::Generate)?;
        self.write_atomic(CURRENT_KEY_FILE, &der)?;
        Ok(signer)
    }

    /// Write `bytes` to `name`: a `0400` temporary beside it, fsynced, owner
    /// checked, renamed over the target, directory fsynced.
    ///
    /// The temporary is created with mode `0400` in the `open` itself, so the
    /// key is never, even briefly, readable by anyone else. The owner check
    /// is on the file this process just made: if that is not the directory's
    /// owner (an operator running the CLI as root on a node running as a
    /// service user), the node could not read the key it will be asked to
    /// sign with, so the write is abandoned before the rename.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), KeyringError> {
        let target = self.path(name);
        let tmp = self.path(&format!(".{name}.tmp-{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o400);
        }
        let written = (|| {
            let mut file = opts.open(&tmp).map_err(|e| Self::io(&tmp, &e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
                // The umask can only have removed bits; set it exactly.
                file.set_permissions(fs::Permissions::from_mode(0o400))
                    .map_err(|e| Self::io(&tmp, &e))?;
                let found = file.metadata().map_err(|e| Self::io(&tmp, &e))?.uid();
                let expected = self.owner_uid()?;
                if found != expected {
                    return Err(KeyringError::Owner {
                        path: target.clone(),
                        found,
                        expected,
                    });
                }
            }
            file.write_all(bytes).map_err(|e| Self::io(&tmp, &e))?;
            file.sync_all().map_err(|e| Self::io(&tmp, &e))
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp, &target) {
            let _ = fs::remove_file(&tmp);
            return Err(Self::io(&target, &e));
        }
        self.sync_dir();
        Ok(())
    }

    /// Make a rename durable. Best effort: not every platform can fsync a
    /// directory, and the rename itself is already atomic.
    fn sync_dir(&self) {
        #[cfg(unix)]
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
    }

    fn read_record(&self) -> Result<RotationRecord, KeyringError> {
        let path = self.path(ROTATION_RECORD_FILE);
        let Some(bytes) = self.read_checked(ROTATION_RECORD_FILE)? else {
            return Ok(RotationRecord::default());
        };
        serde_json::from_slice(&bytes).map_err(|e| KeyringError::Record {
            path,
            what: e.to_string(),
        })
    }

    fn write_record(&self, record: &RotationRecord) -> Result<(), KeyringError> {
        let bytes = serde_json::to_vec_pretty(record).map_err(|e| KeyringError::Record {
            path: self.path(ROTATION_RECORD_FILE),
            what: e.to_string(),
        })?;
        self.write_atomic(ROTATION_RECORD_FILE, &bytes)
    }

    /// Load every key and the reconciled record.
    fn snapshot(
        &self,
        now: u64,
    ) -> Result<
        (
            EcdsaP256Signer,
            Option<EcdsaP256Signer>,
            Option<EcdsaP256Signer>,
            RotationRecord,
            bool,
        ),
        KeyringError,
    > {
        let current = self
            .load(CURRENT_KEY_FILE)?
            .ok_or_else(|| KeyringError::NoCurrent {
                path: self.path(CURRENT_KEY_FILE),
            })?;
        let next = self.load(NEXT_KEY_FILE)?;
        let prev = self.load(PREV_KEY_FILE)?;
        let stored = self.read_record()?;
        let record = stored.reconciled(
            current.kid(),
            next.as_ref().map(|k| k.kid()),
            prev.as_ref().map(|k| k.kid()),
            now,
        );
        let changed = record != stored;
        Ok((current, next, prev, record, changed))
    }

    fn state_of(
        current: &EcdsaP256Signer,
        next: Option<&EcdsaP256Signer>,
        prev: Option<&EcdsaP256Signer>,
        record: &RotationRecord,
    ) -> KeyState {
        // The reconciled record has a stamp exactly for each distinct next/prev.
        let pair = |key: Option<&EcdsaP256Signer>, stamp: &Option<Stamp>| {
            let key = key?;
            let stamp = stamp.as_ref().filter(|s| s.kid == key.kid())?;
            Some((key.public_jwk(), stamp.at))
        };
        KeyState {
            current: current.public_jwk(),
            next: pair(next, &record.next_staged).map(|(jwk, staged_at)| Staged { jwk, staged_at }),
            prev: pair(prev, &record.prev_promoted)
                .map(|(jwk, promoted_at)| Retained { jwk, promoted_at }),
        }
    }

    /// What is published now. Read-only: a file with no stamp is shown as
    /// stamped `now` (what the next rotation step would record) but nothing
    /// is written.
    pub fn state(&self, now: u64) -> Result<KeyState, KeyringError> {
        let (current, next, prev, record, _) = self.snapshot(now)?;
        Ok(Self::state_of(
            &current,
            next.as_ref(),
            prev.as_ref(),
            &record,
        ))
    }

    /// Take the lock, check the directory, load and reconcile, and persist the
    /// reconciled record if it changed.
    fn begin(
        &self,
        now: u64,
    ) -> Result<
        (
            Lock,
            EcdsaP256Signer,
            Option<EcdsaP256Signer>,
            Option<EcdsaP256Signer>,
            RotationRecord,
        ),
        KeyringError,
    > {
        self.check_dir()?;
        let lock_path = self.path(LOCK_FILE);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&lock_path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(KeyringError::Locked { path: lock_path });
            }
            Err(e) => return Err(Self::io(&lock_path, &e)),
        }
        let lock = Lock(lock_path);
        let (current, next, prev, record, changed) = self.snapshot(now)?;
        if changed {
            self.write_record(&record)?;
        }
        Ok((lock, current, next, prev, record))
    }

    /// Stage a next key if none is staged. Idempotent: with a key already
    /// staged, nothing changes and its original stamp stands.
    pub fn stage(&self, now: u64) -> Result<Transition, KeyringError> {
        let (_lock, current, next, prev, mut record) = self.begin(now)?;
        let before = Self::state_of(&current, next.as_ref(), prev.as_ref(), &record).published();
        let next = match next.filter(|n| n.kid() != current.kid()) {
            Some(n) => n,
            None => {
                let der = EcdsaP256Signer::generate_pkcs8().map_err(|_| KeyringError::Generate)?;
                let staged =
                    EcdsaP256Signer::from_pkcs8(&der).map_err(|_| KeyringError::Generate)?;
                self.write_atomic(NEXT_KEY_FILE, &der)?;
                record.next_staged = Some(Stamp {
                    kid: staged.kid().to_string(),
                    at: now,
                });
                self.write_record(&record)?;
                staged
            }
        };
        Ok(Transition {
            before,
            after: Self::state_of(&current, Some(&next), prev.as_ref(), &record),
        })
    }

    /// Promote the staged key to current, keeping the old one as `prev`.
    ///
    /// # Errors
    /// Nothing staged; a previous key still published; or `now` is before
    /// the staged key's stamp plus [`RotationPolicy::promote_overlap`].
    ///
    /// # Order, and what a crash at each point leaves
    ///
    /// 1. `prev` := a copy of `current`. A crash here leaves `prev` equal to
    ///    `current` — no new key published, none removed; a rerun proceeds.
    /// 2. rename `next` over `current`. The swap: the node signs with the new
    ///    key from its next assertion. A crash here leaves the record saying
    ///    the key is staged while it is current; reconciliation stamps `prev`
    ///    at the rerun's `now`, which only delays the retire.
    /// 3. record: `prev` promoted at `now`, nothing staged.
    pub fn promote(&self, now: u64, policy: &RotationPolicy) -> Result<Transition, KeyringError> {
        let (_lock, current, next, prev, mut record) = self.begin(now)?;
        let before = Self::state_of(&current, next.as_ref(), prev.as_ref(), &record).published();
        if let Some(p) = prev.as_ref().filter(|p| p.kid() != current.kid()) {
            return Err(KeyringError::PrevStillPublished {
                kid: p.kid().to_string(),
            });
        }
        let Some(next) = next.filter(|n| n.kid() != current.kid()) else {
            return Err(KeyringError::NotStaged);
        };
        let staged_at = record
            .next_staged
            .as_ref()
            .filter(|s| s.kid == next.kid())
            .map_or(now, |s| s.at);
        let allowed_at = staged_at.saturating_add(policy.promote_overlap().as_secs());
        if now < allowed_at {
            return Err(KeyringError::TooEarly {
                what: "promote",
                allowed_at,
                now,
            });
        }
        let current_der =
            self.read_checked(CURRENT_KEY_FILE)?
                .ok_or_else(|| KeyringError::NoCurrent {
                    path: self.path(CURRENT_KEY_FILE),
                })?;
        self.write_atomic(PREV_KEY_FILE, &current_der)?;
        let next_path = self.path(NEXT_KEY_FILE);
        fs::rename(&next_path, self.path(CURRENT_KEY_FILE))
            .map_err(|e| Self::io(&next_path, &e))?;
        self.sync_dir();
        record.next_staged = None;
        record.prev_promoted = Some(Stamp {
            kid: current.kid().to_string(),
            at: now,
        });
        self.write_record(&record)?;
        Ok(Transition {
            before,
            after: Self::state_of(&next, None, Some(&current), &record),
        })
    }

    /// Remove the previous key from the published set.
    ///
    /// # Errors
    /// No previous key, or `now` is before its promote stamp plus
    /// [`RotationPolicy::retire_after`].
    pub fn retire(&self, now: u64, policy: &RotationPolicy) -> Result<Transition, KeyringError> {
        let (_lock, current, next, prev, mut record) = self.begin(now)?;
        let before = Self::state_of(&current, next.as_ref(), prev.as_ref(), &record).published();
        let Some(prev) = prev else {
            return Err(KeyringError::NothingToRetire);
        };
        // A prev equal to current is an interrupted promote's copy: not a
        // published key of its own, so removing it needs no wait.
        if prev.kid() != current.kid() {
            let promoted_at = record
                .prev_promoted
                .as_ref()
                .filter(|s| s.kid == prev.kid())
                .map_or(now, |s| s.at);
            let allowed_at = promoted_at.saturating_add(policy.retire_after().as_secs());
            if now < allowed_at {
                return Err(KeyringError::TooEarly {
                    what: "retire",
                    allowed_at,
                    now,
                });
            }
        }
        let prev_path = self.path(PREV_KEY_FILE);
        fs::remove_file(&prev_path).map_err(|e| Self::io(&prev_path, &e))?;
        self.sync_dir();
        record.prev_promoted = None;
        self.write_record(&record)?;
        Ok(Transition {
            before,
            after: Self::state_of(&current, next.as_ref(), None, &record),
        })
    }
}

/// The discovery document's `jwks_uri` for `issuer`: [`JWKS_PATH`] under it.
pub fn jwks_uri(issuer: &str) -> String {
    format!("{}/{JWKS_PATH}", issuer.trim_end_matches('/'))
}

/// The OIDC discovery document for this issuer (served at
/// `<issuer>/.well-known/openid-configuration`).
///
/// `issuer` is written back byte-for-byte: providers compare it to the
/// assertion's `iss` exactly (profile §2.2), so this must be the same string
/// the node was started with as `--federation-issuer`.
///
/// # Errors
/// `issuer` is not an https URL with a host — the rule
/// [`is_valid_issuer`] applies to the assertions themselves.
pub fn discovery_document(issuer: &str) -> Result<serde_json::Value, KeyringError> {
    if !is_valid_issuer(issuer) {
        return Err(KeyringError::Issuer(issuer.to_string()));
    }
    Ok(serde_json::json!({
        "issuer": issuer,
        "jwks_uri": jwks_uri(issuer),
        "id_token_signing_alg_values_supported": [SIGNING_ALG],
        // Required members of an OpenID Provider Metadata document. This
        // issuer signs assertions, not ID tokens; the values describe the
        // tokens' shape (public `sub`) for providers that validate the
        // document strictly.
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "claims_supported": [
            "iss", "sub", "aud", "iat", "exp", "jti",
            "nucleus_tenant", "nucleus_upstream", "nucleus_root", "nucleus_chain"
        ],
    }))
}

/// A file's identity, to tell whether it was replaced since it was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_ns: i128,
}

impl FileStamp {
    fn of(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Self {
                dev: meta.dev(),
                ino: meta.ino(),
                len: meta.len(),
                mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            }
        }
        #[cfg(not(unix))]
        {
            let mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos() as i128);
            Self {
                dev: 0,
                ino: 0,
                len: meta.len(),
                mtime_ns,
            }
        }
    }
}

struct Loaded {
    stamp: FileStamp,
    signer: Arc<EcdsaP256Signer>,
}

/// The node's signer: whatever key is in [`CURRENT_KEY_FILE`] right now.
///
/// Reads nothing but the current file — `next` is never a signer before it
/// is promoted, because no code path here opens it. Each call re-checks the
/// file (permissions, owner, identity) and reloads it when it was replaced,
/// so a promote takes effect at the node's next assertion with no restart.
pub struct KeyDirSigner {
    keys: KeyDir,
    loaded: Mutex<Loaded>,
}

impl std::fmt::Debug for KeyDirSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyDirSigner")
            .field("dir", &self.keys.dir)
            .finish_non_exhaustive()
    }
}

impl KeyDirSigner {
    /// A signer over `keys`' current key, loaded now so a node with no usable
    /// key fails at start-up rather than at its first assertion.
    pub fn open(keys: KeyDir) -> Result<Self, KeyringError> {
        let (signer, stamp) = Self::load_current(&keys)?;
        Ok(Self {
            keys,
            loaded: Mutex::new(Loaded {
                stamp,
                signer: Arc::new(signer),
            }),
        })
    }

    fn load_current(keys: &KeyDir) -> Result<(EcdsaP256Signer, FileStamp), KeyringError> {
        let path = keys.path(CURRENT_KEY_FILE);
        let (mut file, meta) = keys
            .open_checked(CURRENT_KEY_FILE)?
            .ok_or(KeyringError::NoCurrent { path: path.clone() })?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes)
            .map_err(|e| KeyDir::io(&path, &e))?;
        let signer = EcdsaP256Signer::from_pkcs8(&bytes).map_err(|_| KeyringError::Key { path })?;
        Ok((signer, FileStamp::of(&meta)))
    }

    /// The signer for the next assertion.
    ///
    /// # Errors
    /// The current file is gone, or was replaced by one that fails its checks.
    /// Never the previously loaded key instead: the operator replaced it.
    pub fn signer(&self) -> Result<Arc<EcdsaP256Signer>, KeyringError> {
        let path = self.keys.path(CURRENT_KEY_FILE);
        let (_, meta) = self
            .keys
            .open_checked(CURRENT_KEY_FILE)?
            .ok_or(KeyringError::NoCurrent { path })?;
        let stamp = FileStamp::of(&meta);
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        if loaded.stamp != stamp {
            // Loaded from a fresh open, and stamped from THAT open: if the
            // file changes again in between, the stamp differs next call and
            // it reloads again, rather than caching a key under a stale stamp.
            let (signer, stamp) = Self::load_current(&self.keys)?;
            *loaded = Loaded {
                stamp,
                signer: Arc::new(signer),
            };
        }
        Ok(Arc::clone(&loaded.signer))
    }
}

impl CurrentSigner for KeyDirSigner {
    fn current(self: Arc<Self>) -> Result<Arc<dyn AssertionSigner>, SignError> {
        self.signer()
            .map(|s| s as Arc<dyn AssertionSigner>)
            .map_err(|_| SignError::Key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_790_000_000;

    fn policy() -> RotationPolicy {
        RotationPolicy::default()
    }

    fn fresh() -> (tempfile::TempDir, KeyDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = KeyDir::new(dir.path());
        keys.create_current().expect("creates");
        (dir, keys)
    }

    fn kids(keys: &[PublicJwk]) -> Vec<String> {
        keys.iter().map(|k| k.kid.clone()).collect()
    }

    #[test]
    fn the_default_overlap_is_cache_plus_max_assertion_lifetime() {
        let p = policy();
        assert_eq!(p.promote_overlap(), Duration::from_secs(75 * 60));
        assert_eq!(p.retire_after(), Duration::from_secs(65 * 60));
        assert!(RotationPolicy::new(DEFAULT_JWKS_CACHE_TTL, Duration::ZERO).is_err());
        assert!(
            RotationPolicy::new(DEFAULT_JWKS_CACHE_TTL, MAX_TTL + Duration::from_secs(1)).is_err()
        );
    }

    #[test]
    fn the_discovery_document_names_the_issuer_byte_for_byte() {
        for iss in [
            "https://federation.nodes.example.invalid",
            "https://federation.nodes.example.invalid/tenant-a",
            "https://federation.nodes.example.invalid/",
        ] {
            let doc = discovery_document(iss).expect("valid issuer");
            assert_eq!(doc["issuer"].as_str(), Some(iss));
            let uri = doc["jwks_uri"].as_str().unwrap();
            assert!(uri.starts_with(iss.trim_end_matches('/')), "{uri}");
            assert!(uri.ends_with("/.well-known/jwks.json"), "{uri}");
            assert!(!uri.contains("//.well-known"), "{uri}");
            assert_eq!(
                doc["id_token_signing_alg_values_supported"],
                serde_json::json!([SIGNING_ALG])
            );
        }
        assert!(discovery_document("http://federation.nodes.example.invalid").is_err());
        assert!(discovery_document("https://").is_err());
    }

    /// The JWKS kid is the RFC 7638 thumbprint, recomputed here from the
    /// published x/y independently of the signer.
    #[test]
    fn the_published_kid_is_the_rfc7638_thumbprint() {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        let (_d, keys) = fresh();
        keys.stage(T0).unwrap();
        let state = keys.state(T0).unwrap();
        let published = state.published();
        assert_eq!(published.len(), 2, "current and next are both published");
        for k in &published {
            let canonical = format!(
                r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
                k.crv, k.kty, k.x, k.y
            );
            let thumb = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(canonical.as_bytes()));
            assert_eq!(k.kid, thumb);
        }
    }

    #[test]
    fn stage_publishes_next_without_ever_signing_with_it() {
        let (_d, keys) = fresh();
        let signer = Arc::new(KeyDirSigner::open(keys.clone()).unwrap());
        let before = Arc::clone(&signer).current().unwrap().kid().to_string();

        let t = keys.stage(T0).unwrap();
        let next = t.after.next.clone().expect("staged");
        assert_eq!(t.added(), vec![next.jwk.kid.clone()]);
        assert!(t.removed().is_empty());
        assert_eq!(next.staged_at, T0);
        assert_eq!(
            kids(&t.after.published()),
            vec![before.clone(), next.jwk.kid.clone()]
        );

        // Still the current key, however long we wait without promoting.
        assert_eq!(Arc::clone(&signer).current().unwrap().kid(), before);

        // Staging again changes nothing and keeps the original stamp.
        let again = keys.stage(T0 + 999).unwrap();
        assert!(again.added().is_empty() && again.removed().is_empty());
        assert_eq!(again.after.next.unwrap().staged_at, T0);
    }

    /// The overlap check is the rotation's safety argument. Perturbation: make
    /// `promote` skip the `now < allowed_at` refusal and this goes red.
    #[test]
    fn promote_is_refused_before_the_overlap_and_allowed_after() {
        let (_d, keys) = fresh();
        let signer = Arc::new(KeyDirSigner::open(keys.clone()).unwrap());
        let old = Arc::clone(&signer).current().unwrap().kid().to_string();
        assert!(matches!(
            keys.promote(T0, &policy()),
            Err(KeyringError::NotStaged)
        ));

        let staged = keys.stage(T0).unwrap().after.next.unwrap().jwk.kid;
        let overlap = policy().promote_overlap().as_secs();
        match keys.promote(T0 + overlap - 1, &policy()) {
            Err(KeyringError::TooEarly { allowed_at, .. }) => assert_eq!(allowed_at, T0 + overlap),
            other => panic!("promote one second early was not refused: {other:?}"),
        }
        // Refused, and nothing moved: the node still signs with the old key.
        assert_eq!(Arc::clone(&signer).current().unwrap().kid(), old);
        assert!(keys.dir().join(NEXT_KEY_FILE).exists());
        assert!(!keys.dir().join(PREV_KEY_FILE).exists());

        let t = keys
            .promote(T0 + overlap, &policy())
            .expect("allowed at the overlap");
        // The published set is unchanged at promote: nothing to re-register.
        assert!(t.added().is_empty() && t.removed().is_empty());
        assert_eq!(t.after.current.kid, staged);
        assert_eq!(t.after.prev.as_ref().unwrap().jwk.kid, old);
        assert!(t.after.next.is_none());

        // The RUNNING signer — no restart, same object — now signs with the
        // promoted key.
        assert_eq!(Arc::clone(&signer).current().unwrap().kid(), staged);
        // And a signature from it verifies under the promoted public key.
        let s = Arc::clone(&signer).current().unwrap();
        assert_eq!(s.public_jwk(), t.after.current);
    }

    #[test]
    fn prev_is_retained_until_retire_and_retire_waits_out_its_window() {
        let (_d, keys) = fresh();
        let old = keys.state(T0).unwrap().current.kid;
        keys.stage(T0).unwrap();
        let at = T0 + policy().promote_overlap().as_secs();
        keys.promote(at, &policy()).unwrap();

        // A second rotation cannot start promoting while prev is published.
        keys.stage(at).unwrap();
        assert!(matches!(
            keys.promote(at + 10 * 3600, &policy()),
            Err(KeyringError::PrevStillPublished { .. })
        ));

        let window = policy().retire_after().as_secs();
        assert!(matches!(
            keys.retire(at + window - 1, &policy()),
            Err(KeyringError::TooEarly { what: "retire", .. })
        ));
        assert!(kids(&keys.state(at).unwrap().published()).contains(&old));

        let t = keys
            .retire(at + window, &policy())
            .expect("allowed after the window");
        assert_eq!(t.removed(), vec![old.clone()]);
        assert!(t.added().is_empty());
        assert!(!keys.dir().join(PREV_KEY_FILE).exists());
        assert!(matches!(
            keys.retire(at + window, &policy()),
            Err(KeyringError::NothingToRetire)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn every_file_rotation_writes_is_owner_read_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, keys) = fresh();
        keys.stage(T0).unwrap();
        keys.promote(T0 + policy().promote_overlap().as_secs(), &policy())
            .unwrap();
        for name in [CURRENT_KEY_FILE, PREV_KEY_FILE, ROTATION_RECORD_FILE] {
            let mode = fs::metadata(keys.dir().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o400, "{name} has mode {mode:o}");
        }
        keys.stage(T0 + 10 * 3600).unwrap();
        let mode = fs::metadata(keys.dir().join(NEXT_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);
        // No temporary or lock is left behind.
        let stray: Vec<_> = fs::read_dir(keys.dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.') || n.ends_with(".lock"))
            .collect();
        assert!(stray.is_empty(), "left behind: {stray:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_key_readable_by_others_is_refused_everywhere() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, keys) = fresh();
        let signer = Arc::new(KeyDirSigner::open(keys.clone()).unwrap());
        let path = keys.dir().join(CURRENT_KEY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        assert!(matches!(
            keys.state(T0),
            Err(KeyringError::Permissions { .. })
        ));
        assert!(matches!(
            keys.stage(T0),
            Err(KeyringError::Permissions { .. })
        ));
        assert!(KeyDirSigner::open(keys.clone()).is_err());
        // The running signer fails closed rather than keep signing.
        assert!(Arc::clone(&signer).current().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_key_is_refused() {
        let (d, keys) = fresh();
        let path = keys.dir().join(CURRENT_KEY_FILE);
        let real = d.path().join("elsewhere.der");
        fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(matches!(
            keys.load_current(),
            Err(KeyringError::NotAFile { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_writable_key_directory_refuses_rotation() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, keys) = fresh();
        fs::set_permissions(keys.dir(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            keys.stage(T0),
            Err(KeyringError::DirPermissions { .. })
        ));
    }

    /// A crash between writing `next` and writing the record leaves a staged
    /// key with no stamp. The next step stamps it NOW: its overlap restarts,
    /// it is never treated as published since some earlier time.
    #[test]
    fn an_unstamped_next_key_restarts_its_overlap() {
        let (_d, keys) = fresh();
        keys.stage(T0).unwrap();
        fs::remove_file(keys.dir().join(ROTATION_RECORD_FILE)).unwrap();
        let later = T0 + 10 * 3600;
        match keys.promote(later, &policy()) {
            Err(KeyringError::TooEarly { allowed_at, .. }) => {
                assert_eq!(allowed_at, later + policy().promote_overlap().as_secs())
            }
            other => panic!("an unstamped key was promoted: {other:?}"),
        }
    }

    /// A record stamp for a different key than the file holds does not count.
    #[test]
    fn a_stamp_counts_only_for_the_kid_it_names() {
        let rec = RotationRecord {
            next_staged: Some(Stamp {
                kid: "other".into(),
                at: 1,
            }),
            prev_promoted: None,
        };
        let r = rec.reconciled("cur", Some("nxt"), None, 500);
        assert_eq!(
            r.next_staged,
            Some(Stamp {
                kid: "nxt".into(),
                at: 500
            })
        );
        // A next that IS the current key (an interrupted promote) is not staged.
        let r = rec.reconciled("cur", Some("cur"), Some("cur"), 500);
        assert_eq!(r, RotationRecord::default());
    }

    #[test]
    fn a_held_lock_refuses_a_second_rotation() {
        let (_d, keys) = fresh();
        fs::write(keys.dir().join(LOCK_FILE), b"").unwrap();
        assert!(matches!(keys.stage(T0), Err(KeyringError::Locked { .. })));
    }
}
