//! `KeyringKeyStore` — an ES256 key store over `nucleus-federation`'s keyring.
//!
//! # Why this store exists
//!
//! The in-process stores sign EdDSA. Relying parties that take an outside OIDC
//! issuer — cloud workload-identity federation, and verifiers built to the
//! SPIFFE JWT-SVID profile — accept RS256 or ES256 and never EdDSA, so an OP
//! whose tokens must reach them signs ES256. This store does that without a
//! second P-256 implementation: the key, its files and its rotation are
//! `nucleus_federation::keyring`'s, and signing goes through that crate's
//! `AssertionSigner`, whose only signing method returns a fixed 64-byte
//! `r || s`. A TPM- or KMS-held key is another implementation of that trait,
//! not a change here.
//!
//! # Rotation is the keyring's protocol, not `rotate()`
//!
//! The in-process stores rotate by signing with a new key at once and keeping
//! the old one verifiable for a grace window. A relying party that cached the
//! JWKS just before that rotation sees a `kid` it does not have. The keyring
//! instead STAGES the next key (published, never signing), PROMOTES it only
//! after the relying parties' JWKS cache lifetime plus the longest token has
//! passed, and RETIRES the old key only after its last token expired. That is
//! the protocol an outside relying party needs, so this store does not offer
//! the other one: `rotate()` and `revoke()` answer
//! [`KeyStoreError::OperatorRotated`], and the operator runs
//! `nucleus-oidc-provider keys {stage,promote,retire}` against the same
//! directory. The running OP reads the directory on every sign and every JWKS
//! request, so a promoted key is used — and a staged one published — without
//! a restart.
//!
//! # Custody
//!
//! Chosen by the caller as a `KeyCustody`. On a host with no TPM it is
//! `File(NoTpmConfigured)`: a `0400` PKCS#8 file, owned by the directory's
//! owner, in the OP's state directory. That is a key anyone holding the disk
//! can use, and the deployment docs say so rather than calling it sealed.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nucleus_federation::keyring::{KeyDir, KeyDirSigner, RotationPolicy};
use nucleus_federation::{CurrentSigner as _, KeyCustody};

use super::{
    JwtKeyStore, KeyStoreError, PublicKey, RotateOutcome, SignedBytes, SigningAlg, VerifyKey,
};

/// How long the published (public) key set is reused before the directory is
/// read again. `/jwks.json` and `/healthz` are unauthenticated, and reading
/// the set loads and parses every key file, so without this a request flood
/// is a flood of disk reads and key parses. Five seconds is far inside the
/// keyring's 75-minute stage-to-promote overlap, so a staged key still
/// reaches relying parties long before it signs. Signing never uses this: it
/// reads the current key every time (ADR 0007 C-1).
const PUBLISHED_TTL: Duration = Duration::from_secs(5);

/// An ES256 key store over a keyring directory.
pub struct KeyringKeyStore {
    keys: KeyDir,
    signer: Arc<KeyDirSigner>,
    policy: RotationPolicy,
    published: Mutex<Option<(Instant, Vec<Arc<VerifyKey>>)>>,
}

impl std::fmt::Debug for KeyringKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringKeyStore")
            .field("dir", &self.keys.dir())
            .finish_non_exhaustive()
    }
}

/// The keyring's errors name files and `kid`s — public facts — and never key
/// material, so carrying their text is safe.
fn backend(e: impl std::fmt::Display) -> KeyStoreError {
    KeyStoreError::Backend(e.to_string())
}

fn now_unix() -> Result<u64, KeyStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| KeyStoreError::Backend("clock before unix epoch".into()))
}

/// Create `dir` owner-only (`0700`) if it does not exist. Its owner is the
/// owner every key file must carry, so it is created by the OP itself — on a
/// fresh volume mounted for the OP's user, that user. An existing directory is
/// left as it is: the keyring checks the files, and re-moding a directory
/// someone else set up is not this store's decision.
fn create_private_dir(dir: &std::path::Path) -> Result<(), KeyStoreError> {
    if dir.exists() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| KeyStoreError::Backend(format!("creating {}: {e}", dir.display())))
}

impl KeyringKeyStore {
    /// Open the keyring in `dir`, creating its first key in `custody` if the
    /// directory has none. A directory whose key fails its checks (mode,
    /// owner, parse) or holds the other custody's layout is an error: the OP
    /// refuses to start rather than replace a key relying parties trust.
    pub fn open_or_create(
        dir: impl Into<std::path::PathBuf>,
        custody: KeyCustody,
        policy: RotationPolicy,
    ) -> Result<Self, KeyStoreError> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        let keys = KeyDir::new(&dir);
        if keys.load_current().map_err(backend)?.is_none() {
            let jwk = keys.create_current(&custody).map_err(backend)?;
            tracing::info!(kid = %jwk.kid, dir = %dir.display(), "keyring: created the first signing key");
        }
        let signer = Arc::new(KeyDirSigner::open(KeyDir::new(&dir), custody).map_err(backend)?);
        Ok(Self {
            keys,
            signer,
            policy,
            published: Mutex::new(None),
        })
    }

    fn published(&self) -> Result<Vec<Arc<VerifyKey>>, KeyStoreError> {
        let mut cache = self.published.lock().map_err(|_| KeyStoreError::Poisoned)?;
        if let Some((at, keys)) = cache.as_ref()
            && at.elapsed() < PUBLISHED_TTL
        {
            return Ok(keys.clone());
        }
        let keys = self.read_published()?;
        *cache = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    fn read_published(&self) -> Result<Vec<Arc<VerifyKey>>, KeyStoreError> {
        let now = now_unix()?;
        let state = self.keys.state(now).map_err(backend)?;
        let read_at = UNIX_EPOCH + Duration::from_secs(now);
        // Leaving the JWKS takes a promote and then the retire window, so a
        // current or staged key is published at least that long from now; a
        // previous key at least until its retire becomes allowed.
        let floor = read_at + self.policy.retire_after();
        let mut out = Vec::with_capacity(3);
        let mut push = |jwk: nucleus_federation::PublicJwk, not_after: SystemTime| {
            out.push(Arc::new(VerifyKey {
                kid: jwk.kid.clone(),
                public: PublicKey::P256(jwk),
                not_before: UNIX_EPOCH,
                not_after,
            }));
        };
        let retire_at = state.retire_allowed_at(&self.policy);
        push(state.current, floor);
        if let Some(next) = state.next {
            push(next.jwk, floor);
        }
        if let (Some(prev), Some(at)) = (state.prev, retire_at) {
            push(prev.jwk, UNIX_EPOCH + Duration::from_secs(at));
        }
        Ok(out)
    }
}

impl JwtKeyStore for KeyringKeyStore {
    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn sign(&self, bytes: &[u8]) -> Result<SignedBytes, KeyStoreError> {
        // One fixed signer per signature, so the `kid` and the signature come
        // from the same key even if the operator promotes between the calls.
        let signer = Arc::clone(&self.signer).current().map_err(backend)?;
        let signature = signer.sign_es256(bytes).map_err(backend)?;
        Ok(SignedBytes {
            kid: signer.kid().to_string(),
            alg: SigningAlg::Es256,
            signature: signature.0.to_vec(),
        })
    }

    fn active_kid(&self) -> Result<String, KeyStoreError> {
        let signer = Arc::clone(&self.signer).current().map_err(backend)?;
        Ok(signer.kid().to_string())
    }

    fn verify_key(&self, kid: &str) -> Result<Arc<VerifyKey>, KeyStoreError> {
        self.published()?
            .into_iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| KeyStoreError::UnknownKid(kid.to_string()))
    }

    fn all_verify_keys(&self) -> Result<Vec<Arc<VerifyKey>>, KeyStoreError> {
        self.published()
    }

    fn rotate(&self) -> Result<RotateOutcome, KeyStoreError> {
        Err(KeyStoreError::OperatorRotated)
    }

    fn revoke(&self, _kid: &str) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::OperatorRotated)
    }

    fn sweep_expired(&self) -> Result<usize, KeyStoreError> {
        // Nothing held in memory to sweep; retire removes a key's file.
        Ok(0)
    }

    fn supports_rotation(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_federation::FileCustody;

    const FILE: KeyCustody = KeyCustody::File(FileCustody::NoTpmConfigured);

    fn store() -> (tempfile::TempDir, KeyringKeyStore) {
        let dir = tempfile::tempdir().unwrap();
        let s =
            KeyringKeyStore::open_or_create(dir.path(), FILE, RotationPolicy::default()).unwrap();
        (dir, s)
    }

    #[test]
    fn a_missing_directory_is_created_owner_only() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("keys");
        KeyringKeyStore::open_or_create(&dir, FILE, RotationPolicy::default()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn creates_one_key_and_reopens_to_the_same_kid() {
        let (dir, s) = store();
        let kid = s.active_kid().unwrap();
        assert_eq!(s.all_verify_keys().unwrap().len(), 1);
        let again =
            KeyringKeyStore::open_or_create(dir.path(), FILE, RotationPolicy::default()).unwrap();
        assert_eq!(
            again.active_kid().unwrap(),
            kid,
            "a restart must keep the key"
        );
    }

    #[test]
    fn signs_es256_with_the_published_key() {
        let (_dir, s) = store();
        let msg = b"header.payload";
        let signed = s.sign(msg).unwrap();
        assert_eq!(signed.alg, SigningAlg::Es256);
        assert_eq!(signed.signature.len(), 64, "JOSE r||s");
        let vk = s.verify_key(&signed.kid).unwrap();
        let PublicKey::P256(jwk) = &vk.public else {
            panic!("an ES256 store publishes P-256 keys");
        };
        assert_eq!((jwk.kty, jwk.crv), ("EC", "P-256"));
        let point = p256_point(jwk);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(msg, &signed.signature)
            .expect("the signature verifies under the published JWK");
    }

    #[test]
    fn a_staged_key_is_published_but_never_signs() {
        let (dir, s) = store();
        let before = s.active_kid().unwrap();
        KeyDir::new(dir.path())
            .stage(now_unix().unwrap(), &FILE)
            .unwrap();
        let kids: Vec<String> = s
            .all_verify_keys()
            .unwrap()
            .iter()
            .map(|k| k.kid.clone())
            .collect();
        assert_eq!(kids.len(), 2, "current and staged are both published");
        assert_eq!(s.sign(b"x").unwrap().kid, before, "staged never signs");
    }

    #[test]
    fn rotate_and_revoke_point_at_the_keyring_protocol() {
        let (_dir, s) = store();
        assert!(matches!(s.rotate(), Err(KeyStoreError::OperatorRotated)));
        assert!(matches!(s.revoke("k"), Err(KeyStoreError::OperatorRotated)));
    }

    pub(crate) fn p256_point(jwk: &nucleus_federation::PublicJwk) -> Vec<u8> {
        use base64::Engine as _;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut point = vec![0x04];
        point.extend(b.decode(&jwk.x).unwrap());
        point.extend(b.decode(&jwk.y).unwrap());
        point
    }
}
