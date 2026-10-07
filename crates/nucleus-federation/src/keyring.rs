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
//! Those are a FILE-custody directory. A TPM-custody directory
//! ([`crate::custody`], ADR 0012) holds [`TPM_CURRENT_KEY_FILE`],
//! [`TPM_NEXT_KEY_FILE`] and [`TPM_PREV_KEY_FILE`] in the same three roles:
//! each the TPM's wrapping of a key that never leaves it, usable only in the
//! boot state it was created in. A directory holds one layout or the other,
//! never both ([`KeyringError::MixedCustody`]); rotation (stage, promote,
//! retire) is the same state machine over either.
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
//! Without a restart. [`KeyDirSigner`] reads and validates the `current`
//! file on every assertion, retaining one fixed signer for that assertion.
//! A failed read or validation FAILS the assertion rather than falling back
//! to the key the operator replaced — see [`crate::CurrentSigner`].

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use nucleus_node_evidence::tpm_key::WrappedKey;

use crate::assertion::{
    AssertionSigner, CurrentSigner, EcdsaP256Signer, MAX_TTL, PublicJwk, SIGNING_ALG, SignError,
    is_valid_issuer, jwks,
};
use crate::custody::{self, CustodyKind, KeyCustody};

/// The key the node signs with. The name P3 shipped, unchanged, so a node
/// that already has a key keeps its `kid`.
pub const CURRENT_KEY_FILE: &str = "jwt_svid_p256_signing_key.der";
/// A staged key: published, never used to sign until promoted.
pub const NEXT_KEY_FILE: &str = "jwt_svid_p256_signing_key.next.der";
/// The key promoted away from, published until its last assertion expired.
pub const PREV_KEY_FILE: &str = "jwt_svid_p256_signing_key.prev.der";
/// A TPM-custody directory's current key: the TPM's wrapping of it.
pub const TPM_CURRENT_KEY_FILE: &str = "jwt_svid_p256_tpm_key.json";
/// A TPM-custody directory's staged key.
pub const TPM_NEXT_KEY_FILE: &str = "jwt_svid_p256_tpm_key.next.json";
/// A TPM-custody directory's previous key.
pub const TPM_PREV_KEY_FILE: &str = "jwt_svid_p256_tpm_key.prev.json";

/// The three files of one custody layout.
#[derive(Debug, Clone, Copy)]
struct Layout {
    kind: CustodyKind,
    current: &'static str,
    next: &'static str,
    prev: &'static str,
}

const FILE_LAYOUT: Layout = Layout {
    kind: CustodyKind::File,
    current: CURRENT_KEY_FILE,
    next: NEXT_KEY_FILE,
    prev: PREV_KEY_FILE,
};

const TPM_LAYOUT: Layout = Layout {
    kind: CustodyKind::Tpm,
    current: TPM_CURRENT_KEY_FILE,
    next: TPM_NEXT_KEY_FILE,
    prev: TPM_PREV_KEY_FILE,
};

fn layout_of(kind: CustodyKind) -> Layout {
    match kind {
        CustodyKind::File => FILE_LAYOUT,
        CustodyKind::Tpm => TPM_LAYOUT,
    }
}

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
    /// The TPM refused, or could not be reached.
    #[error("TPM: {what}")]
    Tpm { what: String },
    /// The directory holds keys of one custody and the caller asked for the
    /// other.
    #[error(
        "{} holds {on_disk} federation keys but this node is configured for {configured} \
         custody. A file key on a node with a TPM needs {}; moving to TPM custody is a new \
         key that upstreams must be told about (ADR 0012)",
        dir.display(), crate::custody::FILE_CUSTODY_WAIVER_FLAG
    )]
    CustodyMismatch {
        dir: PathBuf,
        on_disk: CustodyKind,
        configured: CustodyKind,
    },
    /// The directory holds both file and TPM key files.
    #[error(
        "{} holds both file and TPM-resident federation key files; remove one set",
        dir.display()
    )]
    MixedCustody { dir: PathBuf },
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
        // Saturating: an overflowing sum can only lengthen the wait, which is
        // the safe direction for a window that exists to be waited out.
        self.jwks_cache_ttl.saturating_add(self.max_assertion_ttl)
    }

    /// How long after a promote the old key must stay published: the longest
    /// assertion it could have signed just before the swap, plus the skew a
    /// provider may allow on that assertion's `exp`.
    pub fn retire_after(&self) -> Duration {
        self.max_assertion_ttl.saturating_add(MAX_CLOCK_SKEW)
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

/// A key as one of the directory's files holds it.
pub enum StoredKey {
    /// A PKCS#8 key, loaded.
    File(EcdsaP256Signer),
    /// A TPM-wrapped key and its public JWK.
    Tpm(WrappedKey, PublicJwk),
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(k) => f.debug_tuple("File").field(k).finish(),
            Self::Tpm(_, jwk) => f.debug_tuple("Tpm").field(&jwk.kid).finish(),
        }
    }
}

impl StoredKey {
    /// The key's `kid`.
    pub fn kid(&self) -> &str {
        match self {
            Self::File(k) => k.kid(),
            Self::Tpm(_, jwk) => &jwk.kid,
        }
    }

    /// The public JWK.
    pub fn public_jwk(&self) -> PublicJwk {
        match self {
            Self::File(k) => k.public_jwk(),
            Self::Tpm(_, jwk) => jwk.clone(),
        }
    }
}

/// How a published key is held, for the custody statement a node publishes.
pub enum Held {
    /// TPM-resident: the wrapped key, for the AK to certify.
    Tpm(WrappedKey),
    /// A file.
    File,
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

/// Every key and the reconciled record, as one step reads them.
struct Snapshot {
    layout: Layout,
    current: StoredKey,
    next: Option<StoredKey>,
    prev: Option<StoredKey>,
    record: RotationRecord,
    /// Whether reconciliation changed the stored record.
    changed: bool,
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
        self.check_dir()?;
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

    /// Which layout the directory holds, if any key file is present.
    ///
    /// # Errors
    /// Both layouts are present ([`KeyringError::MixedCustody`]), or a path
    /// cannot be examined.
    pub fn custody_on_disk(&self) -> Result<Option<CustodyKind>, KeyringError> {
        let present = |l: Layout| -> Result<bool, KeyringError> {
            for name in [l.current, l.next, l.prev] {
                let path = self.path(name);
                match fs::symlink_metadata(&path) {
                    Ok(_) => return Ok(true),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(Self::io(&path, &e)),
                }
            }
            Ok(false)
        };
        match (present(FILE_LAYOUT)?, present(TPM_LAYOUT)?) {
            (true, true) => Err(KeyringError::MixedCustody {
                dir: self.dir.clone(),
            }),
            (true, false) => Ok(Some(CustodyKind::File)),
            (false, true) => Ok(Some(CustodyKind::Tpm)),
            (false, false) => Ok(None),
        }
    }

    /// The layout on disk; a directory with no key is reported as having no
    /// current key.
    fn layout(&self) -> Result<Layout, KeyringError> {
        self.custody_on_disk()?
            .map(layout_of)
            .ok_or_else(|| KeyringError::NoCurrent {
                path: self.dir.clone(),
            })
    }

    /// The key in `name` of `layout`, checked and parsed.
    fn load(&self, layout: Layout, name: &str) -> Result<Option<StoredKey>, KeyringError> {
        let Some(bytes) = self.read_checked(name)? else {
            return Ok(None);
        };
        let bad = || KeyringError::Key {
            path: self.path(name),
        };
        match layout.kind {
            CustodyKind::File => EcdsaP256Signer::from_pkcs8(&bytes)
                .map(|k| Some(StoredKey::File(k)))
                .map_err(|_| bad()),
            CustodyKind::Tpm => custody::decode(&bytes)
                .map(|k| {
                    let jwk = custody::jwk_of(&k);
                    Some(StoredKey::Tpm(k, jwk))
                })
                .map_err(|_| bad()),
        }
    }

    /// The current key, if there is one, in whichever layout the directory
    /// holds. For the node's start-up, which creates one when this is `None`.
    ///
    /// # Errors
    /// The file exists but fails its checks, or does not parse
    /// ([`KeyringError::Key`] — the one the node may choose to replace), or
    /// the directory mixes layouts.
    pub fn load_current(&self) -> Result<Option<StoredKey>, KeyringError> {
        match self.custody_on_disk()? {
            None => Ok(None),
            Some(kind) => {
                let layout = layout_of(kind);
                self.load(layout, layout.current)
            }
        }
    }

    /// A fresh key in `custody`, as file bytes and as loaded.
    fn generate(&self, custody: &KeyCustody) -> Result<(Vec<u8>, StoredKey), KeyringError> {
        match custody {
            KeyCustody::File(_) => {
                let der = EcdsaP256Signer::generate_pkcs8().map_err(|_| KeyringError::Generate)?;
                let k = EcdsaP256Signer::from_pkcs8(&der).map_err(|_| KeyringError::Generate)?;
                Ok((der.to_vec(), StoredKey::File(k)))
            }
            KeyCustody::Tpm(tpm) => {
                let k = tpm.create().map_err(|what| KeyringError::Tpm { what })?;
                let bytes = custody::encode(&k).map_err(|what| KeyringError::Tpm { what })?;
                let jwk = custody::jwk_of(&k);
                Ok((bytes, StoredKey::Tpm(k, jwk)))
            }
        }
    }

    /// Refuse `custody` on a directory that holds the other layout.
    fn check_custody(
        &self,
        on_disk: CustodyKind,
        custody: &KeyCustody,
    ) -> Result<(), KeyringError> {
        if on_disk == custody.kind() {
            Ok(())
        } else {
            Err(KeyringError::CustodyMismatch {
                dir: self.dir.clone(),
                on_disk,
                configured: custody.kind(),
            })
        }
    }

    /// Generate a key in `custody` and write it as the current key,
    /// atomically, `0400`. For a node with no key yet, an unparseable one,
    /// or (TPM custody) one bound to another boot state. Rotation never calls
    /// this: it only ever renames a PUBLISHED key into place.
    ///
    /// # Errors
    /// The directory holds the other custody's keys; generation or the write
    /// failed.
    pub fn create_current(&self, custody: &KeyCustody) -> Result<PublicJwk, KeyringError> {
        if let Some(kind) = self.custody_on_disk()? {
            self.check_custody(kind, custody)?;
        }
        let (bytes, key) = self.generate(custody)?;
        let wiped = Zeroizing::new(bytes);
        self.write_atomic(layout_of(custody.kind()).current, &wiped)?;
        Ok(key.public_jwk())
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
        self.check_dir()?;
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
    fn snapshot(&self, now: u64) -> Result<Snapshot, KeyringError> {
        let layout = self.layout()?;
        let current =
            self.load(layout, layout.current)?
                .ok_or_else(|| KeyringError::NoCurrent {
                    path: self.path(layout.current),
                })?;
        let next = self.load(layout, layout.next)?;
        let prev = self.load(layout, layout.prev)?;
        let stored = self.read_record()?;
        let record = stored.reconciled(
            current.kid(),
            next.as_ref().map(|k| k.kid()),
            prev.as_ref().map(|k| k.kid()),
            now,
        );
        let changed = record != stored;
        Ok(Snapshot {
            layout,
            current,
            next,
            prev,
            record,
            changed,
        })
    }

    fn state_of(
        current: &StoredKey,
        next: Option<&StoredKey>,
        prev: Option<&StoredKey>,
        record: &RotationRecord,
    ) -> KeyState {
        // The reconciled record has a stamp exactly for each distinct next/prev.
        let pair = |key: Option<&StoredKey>, stamp: &Option<Stamp>| {
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
        let Snapshot {
            layout: _,
            current,
            next,
            prev,
            record,
            changed: _,
        } = self.snapshot(now)?;
        Ok(Self::state_of(
            &current,
            next.as_ref(),
            prev.as_ref(),
            &record,
        ))
    }

    /// Every published key with how it is held: the input to the custody
    /// statements a node publishes beside its JWKS (ADR 0012). In
    /// [`KeyState::published`] order.
    pub fn published_custody(&self, now: u64) -> Result<Vec<(PublicJwk, Held)>, KeyringError> {
        let Snapshot {
            layout: _,
            current,
            next,
            prev,
            record,
            changed: _,
        } = self.snapshot(now)?;
        let published: Vec<String> =
            Self::state_of(&current, next.as_ref(), prev.as_ref(), &record)
                .published()
                .into_iter()
                .map(|k| k.kid)
                .collect();
        let mut out = Vec::new();
        for key in [Some(current), next, prev].into_iter().flatten() {
            if !published.contains(&key.kid().to_string())
                || out
                    .iter()
                    .any(|(j, _): &(PublicJwk, Held)| j.kid == key.kid())
            {
                continue;
            }
            let jwk = key.public_jwk();
            out.push(match key {
                StoredKey::File(_) => (jwk, Held::File),
                StoredKey::Tpm(k, _) => (jwk, Held::Tpm(k)),
            });
        }
        Ok(out)
    }

    /// Take the lock, check the directory, load and reconcile, and persist the
    /// reconciled record if it changed.
    fn begin(&self, now: u64) -> Result<(Lock, Snapshot), KeyringError> {
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
        let snap = self.snapshot(now)?;
        if snap.changed {
            self.write_record(&snap.record)?;
        }
        Ok((lock, snap))
    }

    /// Stage a next key, generated in `custody`, if none is staged.
    /// Idempotent: with a key already staged, nothing changes and its
    /// original stamp stands.
    ///
    /// # Errors
    /// `custody` is not the directory's ([`KeyringError::CustodyMismatch`]):
    /// a TPM-custody directory stages only TPM keys, so rotation never
    /// brings a file key into it.
    pub fn stage(&self, now: u64, custody: &KeyCustody) -> Result<Transition, KeyringError> {
        let (
            _lock,
            Snapshot {
                layout,
                current,
                next,
                prev,
                mut record,
                changed: _,
            },
        ) = self.begin(now)?;
        self.check_custody(layout.kind, custody)?;
        let before = Self::state_of(&current, next.as_ref(), prev.as_ref(), &record).published();
        let next = match next.filter(|n| n.kid() != current.kid()) {
            Some(n) => n,
            None => {
                let (bytes, staged) = self.generate(custody)?;
                let wiped = Zeroizing::new(bytes);
                self.write_atomic(layout.next, &wiped)?;
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
        let (
            _lock,
            Snapshot {
                layout,
                current,
                next,
                prev,
                mut record,
                changed: _,
            },
        ) = self.begin(now)?;
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
            self.read_checked(layout.current)?
                .ok_or_else(|| KeyringError::NoCurrent {
                    path: self.path(layout.current),
                })?;
        self.write_atomic(layout.prev, &current_der)?;
        let next_path = self.path(layout.next);
        fs::rename(&next_path, self.path(layout.current)).map_err(|e| Self::io(&next_path, &e))?;
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
        let (
            _lock,
            Snapshot {
                layout,
                current,
                next,
                prev,
                mut record,
                changed: _,
            },
        ) = self.begin(now)?;
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
        let prev_path = self.path(layout.prev);
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

/// The node's signer: whatever key is in [`CURRENT_KEY_FILE`] right now.
///
/// Reads nothing but the current file — `next` is never a signer before it
/// is promoted, because no code path here opens it. Each call re-checks the
/// file (permissions and owner) and parses its bytes for this assertion. A
/// stat tuple cannot prove that key bytes are unchanged (ADR 0007 C-1); an
/// in-place replacement with a restored timestamp must never reuse an old key.
pub struct KeyDirSigner {
    keys: KeyDir,
    custody: KeyCustody,
}

impl std::fmt::Debug for KeyDirSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyDirSigner")
            .field("dir", &self.keys.dir)
            .field("custody", &self.custody.kind())
            .finish_non_exhaustive()
    }
}

impl KeyDirSigner {
    /// A signer over `keys`' current key in `custody`, loaded now so a node
    /// with no usable key fails at start-up rather than at its first
    /// assertion.
    ///
    /// # Errors
    /// No current key, a key that fails its checks, or a directory whose
    /// custody is not `custody` — a file key is never signed with on a node
    /// configured for TPM custody, nor a TPM key on one that is not.
    pub fn open(keys: KeyDir, custody: KeyCustody) -> Result<Self, KeyringError> {
        let source = Self { keys, custody };
        source.signer()?;
        Ok(source)
    }

    /// The signer for the next assertion, loaded from one checked file.
    ///
    /// # Errors
    /// The current file is gone, or its permissions, ownership or bytes fail
    /// validation, or its custody is not the configured one. Never fall back
    /// to a previously loaded key.
    pub fn signer(&self) -> Result<Arc<dyn AssertionSigner>, KeyringError> {
        let current = self
            .keys
            .load_current()?
            .ok_or_else(|| KeyringError::NoCurrent {
                path: self.keys.dir.clone(),
            })?;
        match (current, &self.custody) {
            (StoredKey::File(k), KeyCustody::File(_)) => Ok(Arc::new(k)),
            (StoredKey::Tpm(k, _), KeyCustody::Tpm(tpm)) => Ok(Arc::new(tpm.signer(k))),
            (StoredKey::File(_), KeyCustody::Tpm(_)) => Err(KeyringError::CustodyMismatch {
                dir: self.keys.dir.clone(),
                on_disk: CustodyKind::File,
                configured: CustodyKind::Tpm,
            }),
            (StoredKey::Tpm(..), KeyCustody::File(_)) => Err(KeyringError::CustodyMismatch {
                dir: self.keys.dir.clone(),
                on_disk: CustodyKind::Tpm,
                configured: CustodyKind::File,
            }),
        }
    }
}

impl CurrentSigner for KeyDirSigner {
    fn current(self: Arc<Self>) -> Result<Arc<dyn AssertionSigner>, SignError> {
        self.signer().map_err(|_| SignError::Key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::FileCustody;

    const FILE: KeyCustody = KeyCustody::File(FileCustody::NoTpmConfigured);

    const T0: u64 = 1_790_000_000;

    fn policy() -> RotationPolicy {
        RotationPolicy::default()
    }

    fn fresh() -> (tempfile::TempDir, KeyDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = KeyDir::new(dir.path());
        keys.create_current(&FILE).expect("creates");
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
        for malformed in [
            "https://?query",
            "https://#fragment",
            "https:// bad host",
            "https://issuer.example.invalid?query",
            "https://issuer.example.invalid#fragment",
            "https://user:password@issuer.example.invalid",
        ] {
            assert!(discovery_document(malformed).is_err(), "{malformed}");
        }
    }

    /// The JWKS kid is the RFC 7638 thumbprint, recomputed here from the
    /// published x/y independently of the signer.
    #[test]
    fn the_published_kid_is_the_rfc7638_thumbprint() {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        let (_d, keys) = fresh();
        keys.stage(T0, &FILE).unwrap();
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
        let signer = Arc::new(KeyDirSigner::open(keys.clone(), FILE).unwrap());
        let before = Arc::clone(&signer).current().unwrap().kid().to_string();

        let t = keys.stage(T0, &FILE).unwrap();
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
        let again = keys.stage(T0 + 999, &FILE).unwrap();
        assert!(again.added().is_empty() && again.removed().is_empty());
        assert_eq!(again.after.next.unwrap().staged_at, T0);
    }

    /// The overlap check is the rotation's safety argument. Perturbation: make
    /// `promote` skip the `now < allowed_at` refusal and this goes red.
    #[test]
    fn promote_is_refused_before_the_overlap_and_allowed_after() {
        let (_d, keys) = fresh();
        let signer = Arc::new(KeyDirSigner::open(keys.clone(), FILE).unwrap());
        let old = Arc::clone(&signer).current().unwrap().kid().to_string();
        assert!(matches!(
            keys.promote(T0, &policy()),
            Err(KeyringError::NotStaged)
        ));

        let staged = keys.stage(T0, &FILE).unwrap().after.next.unwrap().jwk.kid;
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
        keys.stage(T0, &FILE).unwrap();
        let at = T0 + policy().promote_overlap().as_secs();
        keys.promote(at, &policy()).unwrap();

        // A second rotation cannot start promoting while prev is published.
        keys.stage(at, &FILE).unwrap();
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
        keys.stage(T0, &FILE).unwrap();
        keys.promote(T0 + policy().promote_overlap().as_secs(), &policy())
            .unwrap();
        for name in [CURRENT_KEY_FILE, PREV_KEY_FILE, ROTATION_RECORD_FILE] {
            let mode = fs::metadata(keys.dir().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o400, "{name} has mode {mode:o}");
        }
        keys.stage(T0 + 10 * 3600, &FILE).unwrap();
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
    fn changing_key_bytes_without_changing_the_cache_stamp_cannot_reuse_a_signer() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let (_d, keys) = fresh();
        let signer = KeyDirSigner::open(keys.clone(), FILE).unwrap();
        let path = keys.dir().join(CURRENT_KEY_FILE);
        let before = fs::metadata(&path).unwrap();
        let original = signer.signer().unwrap();
        let replacement = EcdsaP256Signer::generate_pkcs8().unwrap();
        let expected = EcdsaP256Signer::from_pkcs8(&replacement).unwrap();
        assert_eq!(replacement.len() as u64, before.len());
        let overwrite = |bytes: &[u8]| {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.set_times(fs::FileTimes::new().set_modified(before.modified().unwrap()))
                .unwrap();
            file.set_permissions(fs::Permissions::from_mode(0o400))
                .unwrap();
            let after = file.metadata().unwrap();
            assert_eq!(
                (
                    before.dev(),
                    before.ino(),
                    before.len(),
                    before.modified().unwrap()
                ),
                (
                    after.dev(),
                    after.ino(),
                    after.len(),
                    after.modified().unwrap()
                )
            );
        };
        overwrite(&replacement);
        assert_ne!(original.kid(), expected.kid());
        assert_eq!(signer.signer().unwrap().kid(), expected.kid());
        // An assertion already holding its signer remains internally consistent.
        assert_ne!(original.kid(), expected.kid());
        overwrite(&vec![0; replacement.len()]);
        assert!(matches!(signer.signer(), Err(KeyringError::Key { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn a_key_readable_by_others_is_refused_everywhere() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, keys) = fresh();
        let signer = Arc::new(KeyDirSigner::open(keys.clone(), FILE).unwrap());
        let path = keys.dir().join(CURRENT_KEY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        assert!(matches!(
            keys.state(T0),
            Err(KeyringError::Permissions { .. })
        ));
        assert!(matches!(
            keys.stage(T0, &FILE),
            Err(KeyringError::Permissions { .. })
        ));
        assert!(KeyDirSigner::open(keys.clone(), FILE).is_err());
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
        let signer = KeyDirSigner::open(keys.clone(), FILE).unwrap();
        fs::set_permissions(keys.dir(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            keys.stage(T0, &FILE),
            Err(KeyringError::DirPermissions { .. })
        ));
        assert!(matches!(
            keys.load_current(),
            Err(KeyringError::DirPermissions { .. })
        ));
        assert!(matches!(
            signer.signer(),
            Err(KeyringError::DirPermissions { .. })
        ));
        assert!(matches!(
            keys.create_current(&FILE),
            Err(KeyringError::DirPermissions { .. })
        ));
    }

    /// A crash between writing `next` and writing the record leaves a staged
    /// key with no stamp. The next step stamps it NOW: its overlap restarts,
    /// it is never treated as published since some earlier time.
    #[test]
    fn an_unstamped_next_key_restarts_its_overlap() {
        let (_d, keys) = fresh();
        keys.stage(T0, &FILE).unwrap();
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
        assert!(matches!(
            keys.stage(T0, &FILE),
            Err(KeyringError::Locked { .. })
        ));
    }

    fn unreachable_tpm(dir: &Path) -> KeyCustody {
        KeyCustody::Tpm(crate::custody::TpmCustody::new(
            crate::custody::TpmEndpoint::Device(dir.join("no-such-tpm")),
        ))
    }

    /// A file directory never takes a TPM key and a TPM-custody node never
    /// signs with a file key: custody is refused across, never converted
    /// (ADR 0012). Each refusal happens before any TPM is touched.
    #[test]
    fn custody_is_never_crossed() {
        let (dir, keys) = fresh();
        let tpm = unreachable_tpm(dir.path());
        assert_eq!(keys.custody_on_disk().unwrap(), Some(CustodyKind::File));
        assert!(matches!(
            keys.stage(T0, &tpm),
            Err(KeyringError::CustodyMismatch {
                on_disk: CustodyKind::File,
                configured: CustodyKind::Tpm,
                ..
            })
        ));
        assert!(matches!(
            keys.create_current(&tpm),
            Err(KeyringError::CustodyMismatch { .. })
        ));
        let err = KeyDirSigner::open(keys.clone(), tpm).unwrap_err();
        assert!(
            err.to_string()
                .contains(crate::custody::FILE_CUSTODY_WAIVER_FLAG),
            "{err}"
        );
        // The waiver's custody signs with it.
        KeyDirSigner::open(keys.clone(), KeyCustody::File(FileCustody::Waived)).unwrap();
    }

    #[test]
    fn a_directory_holding_both_layouts_is_refused() {
        let (_d, keys) = fresh();
        fs::write(keys.dir().join(TPM_NEXT_KEY_FILE), b"{}").unwrap();
        assert!(matches!(
            keys.custody_on_disk(),
            Err(KeyringError::MixedCustody { .. })
        ));
        assert!(matches!(
            keys.state(T0),
            Err(KeyringError::MixedCustody { .. })
        ));
        assert!(matches!(
            KeyDirSigner::open(keys.clone(), FILE),
            Err(KeyringError::MixedCustody { .. })
        ));
    }

    #[test]
    fn an_unreachable_tpm_creates_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyDir::new(dir.path());
        assert!(matches!(
            keys.create_current(&unreachable_tpm(dir.path())),
            Err(KeyringError::Tpm { .. })
        ));
        assert_eq!(keys.custody_on_disk().unwrap(), None);
    }

    #[test]
    fn a_file_directory_publishes_file_custody() {
        let (_d, keys) = fresh();
        keys.stage(T0, &FILE).unwrap();
        let held = keys.published_custody(T0).unwrap();
        assert_eq!(held.len(), 2);
        assert!(held.iter().all(|(_, h)| matches!(h, Held::File)));
        let kids: Vec<String> = held.into_iter().map(|(j, _)| j.kid).collect();
        assert_eq!(kids, self::kids(&keys.state(T0).unwrap().published()));
    }
}
