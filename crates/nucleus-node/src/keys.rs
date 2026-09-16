//! The node's role-separated signing keys.
//!
//! Four persisted Ed25519 identities, each a DISTINCT trust role, and the
//! shared load-or-create machinery behind them:
//!
//! | key | role |
//! |---|---|
//! | executor | the executor's receipt identity (`register_executor_pubkey`) |
//! | task issuer | signs live-path session capability tokens at pod spawn |
//! | approval | signs `/v1/approve`, verified in-guest by the tool proxy |
//! | certificate root | the anchor every pod's `LatticeCertificate` chains to |
//!
//! # Why this is its own module (#2512)
//!
//! These lived in `trust_gate.rs`, a module whose stated subject was
//! "verifies agent attestations against the Coproduct Trust API and records
//! the resulting reputation". That file's own header had to carry a sentence
//! disclaiming the arrangement — "It also owns the node's role-separated
//! signing keys … which are unrelated to reputation" — which is a comment doing
//! a module boundary's job.
//!
//! The cost was concrete, not aesthetic: `pod_authority.rs` reaches into the
//! reputation module for `load_or_create_cert_root_signing_key`, the #2474
//! certificate root. So the file holding the node's most authority-bearing key
//! could not be deleted, and deleting the reputation code it was named for
//! required moving this first. Separation is what makes the removal possible.
//!
//! # What these keys are NOT
//!
//! None of them is a reputation input, and none decides what a pod may do. The
//! certificate-root key signs the certificate whose CONTENT decides authority;
//! it is the anchor, not the decision. Nothing here reads or writes a
//! `PodSpec`'s policy — `pod_authority::PodAuthority::admit` does that, once,
//! from the caller's certificate.

use std::path::Path;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use tracing::{debug, info, warn};

/// Filename (under `state_dir`) holding the persisted executor signing key.
const EXECUTOR_KEY_FILE: &str = "executor_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **task-issuer** signing
/// key — the root that signs live-path session capability tokens. DISTINCT from
/// [`EXECUTOR_KEY_FILE`] so the two trust roles never share a key.
const TASK_ISSUER_KEY_FILE: &str = "task_issuer_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **approval** signing
/// key — the key whose signatures the guest tool-proxy accepts on
/// `/v1/approve`, verified against the PUBLIC half delivered as
/// `nucleus.approval_pubkeys`. DISTINCT from the other two role keys: the
/// approval authority must not double as the executor's receipt identity or
/// the task-token root.
const APPROVAL_SIGNING_KEY_FILE: &str = "approval_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **certificate-root**
/// signing key — the trust anchor every pod's `LatticeCertificate` chains
/// to (`pod_authority`). DISTINCT from the three role keys above: the
/// authority that says what a pod MAY do must not double as the executor's
/// receipt identity, the task-token root, or the approval authority.
const CERT_ROOT_KEY_FILE: &str = "cert_root_signing_key.der";

/// Generate a fresh Ed25519 signing key from the OS CSPRNG.
///
/// Samples 32 raw bytes via `rand_core 0.6`'s `fill_bytes` and feeds
/// `SigningKey::from_bytes` — equivalent to `SigningKey::generate(&mut rng)` but
/// avoids the cross-version `CryptoRng`/`rand_core` trait-identity mismatch that
/// breaks `generate` when multiple rand_core majors coexist (dalek 3 tracks a
/// newer rand_core than the 0.6 we depend on). Mirrors the pattern in
/// `nucleus-verifier-service::signing::VerifierSigner::random`.
pub(crate) fn generate_signing_key() -> SigningKey {
    use rand_core::RngCore as _;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

/// Load the per-executor Ed25519 signing key from `state_dir`, creating and
/// persisting a fresh one on first run.
///
/// Without persistence, every node restart mints a brand-new identity, which
/// silently invalidates any prior `register_executor_pubkey` enrollment — the
/// threat-model claim that registration survives an HMAC compromise is only
/// true if the executor's signing key is stable across restarts (#1630).
///
/// The key is stored as PKCS#8 DER (same encoding as
/// [`nucleus_lineage::LocalIssuer`]) with `0o400` permissions on Unix. A
/// missing file is created; a present-but-unreadable file is logged and
/// replaced rather than crashing the node (fail-open on *availability*, not on
/// identity — a corrupt key was never a valid enrollment anyway).
pub fn load_or_create_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(state_dir, EXECUTOR_KEY_FILE, "executor signing key")
}

/// Load the dedicated **task-issuer** Ed25519 signing key from `state_dir`,
/// creating and persisting a fresh one on first run.
///
/// Uses the identical persistence discipline as
/// [`load_or_create_signing_key`] (PKCS#8 DER, `0o400`, fail-open on
/// availability) but a DISTINCT file ([`TASK_ISSUER_KEY_FILE`]). This is the
/// root that signs live-path session capability tokens; keeping it separate
/// from the executor key enforces role separation — a compromise or rotation
/// of one identity does not implicate the other, and the executor key (which
/// is also the executor's receipt identity) never doubles as a token root.
pub fn load_or_create_task_issuer_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(state_dir, TASK_ISSUER_KEY_FILE, "task issuer signing key")
}

/// Load the dedicated **approval** Ed25519 signing key from `state_dir`,
/// creating and persisting a fresh one on first run.
///
/// Same persistence discipline as the other role keys, and persistence
/// matters MORE here: a running pod verifies approvals against the public key
/// it booted with, so a node that minted a fresh key on every restart could
/// no longer approve anything for pods launched before the restart.
pub fn load_or_create_approval_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(state_dir, APPROVAL_SIGNING_KEY_FILE, "approval signing key")
}

/// Load the dedicated **certificate-root** Ed25519 signing key from
/// `state_dir`, creating and persisting a fresh one on first run.
///
/// Persistence is load-bearing: every running pod's certificate chains to
/// this key, and a pod's sub-pod requests are verified against it, so a node
/// that minted a fresh root on every restart would orphan every chain it had
/// issued.
pub fn load_or_create_cert_root_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(
        state_dir,
        CERT_ROOT_KEY_FILE,
        "certificate root signing key",
    )
}

/// Shared implementation for the persisted per-node Ed25519 keys. `filename` is
/// the basename under `state_dir`; `label` is used only in log lines.
fn load_or_create_key_file(state_dir: &Path, filename: &str, label: &str) -> SigningKey {
    let path = state_dir.join(filename);

    if path.exists() {
        match std::fs::read(&path) {
            Ok(bytes) => match SigningKey::from_pkcs8_der(&bytes) {
                Ok(key) => {
                    debug!(path = %path.display(), "loaded persisted {label}");
                    return key;
                }
                Err(e) => warn!(
                    path = %path.display(),
                    error = %e,
                    "{label} file is unreadable; regenerating"
                ),
            },
            Err(e) => warn!(
                path = %path.display(),
                error = %e,
                "failed to read {label} file; regenerating"
            ),
        }
    }

    let key = generate_signing_key();
    match key.to_pkcs8_der() {
        Ok(der) => {
            if let Err(e) = write_key_file(&path, der.as_bytes()) {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist {label}; identity will not survive restart"
                );
            } else {
                info!(path = %path.display(), "generated and persisted new {label}");
            }
        }
        Err(e) => warn!(error = %e, "failed to PKCS#8-encode {label}; not persisting"),
    }
    key
}

/// Write `bytes` to `path`, restricting permissions to owner-read-only (`0o400`)
/// on Unix so the private key is not world/group readable.
fn write_key_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Executor signing-key persistence (#1630) ──────────────────────────

    #[test]
    fn test_signing_key_persists_across_calls() {
        // The core property: a "restart" (a second load from the same
        // state_dir) must yield the SAME executor identity.
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_signing_key(dir.path());
        let k2 = load_or_create_signing_key(dir.path());
        assert_eq!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes(),
            "executor signing key must be stable across restarts"
        );
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
    }

    /// Role separation: the task-issuer key must be a DIFFERENT key from the
    /// executor key in the same state_dir (distinct files), yet each must be
    /// stable across restarts. Reusing the executor key as the token root would
    /// conflate the executor identity with the capability-token issuer.
    #[test]
    fn test_task_issuer_key_is_distinct_from_executor_and_persists() {
        let dir = tempfile::tempdir().unwrap();

        let exec = load_or_create_signing_key(dir.path());
        let issuer = load_or_create_task_issuer_signing_key(dir.path());
        assert_ne!(
            exec.verifying_key().as_bytes(),
            issuer.verifying_key().as_bytes(),
            "task-issuer key must not equal the executor key (role separation)"
        );

        // Distinct files on disk.
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
        assert!(dir.path().join(TASK_ISSUER_KEY_FILE).exists());

        // Stable across a "restart" (second load from the same dir).
        let issuer2 = load_or_create_task_issuer_signing_key(dir.path());
        assert_eq!(
            issuer.verifying_key().as_bytes(),
            issuer2.verifying_key().as_bytes(),
            "task-issuer key must be stable across restarts"
        );
    }

    /// `from_env` provisions BOTH keys and they are role-separated.
    #[test]
    fn test_signing_key_distinct_per_state_dir() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ka = load_or_create_signing_key(a.path());
        let kb = load_or_create_signing_key(b.path());
        assert_ne!(
            ka.verifying_key().as_bytes(),
            kb.verifying_key().as_bytes(),
            "separate state dirs must have independent identities"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_persisted_key_is_owner_read_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        load_or_create_signing_key(dir.path());
        let mode = std::fs::metadata(dir.path().join(EXECUTOR_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400, "private key must be mode 0400");
    }

    #[test]
    fn test_corrupt_key_file_regenerates_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(EXECUTOR_KEY_FILE), b"not valid pkcs8 der").unwrap();
        // Must not panic; must produce a usable, persisted key.
        let k = load_or_create_signing_key(dir.path());
        let reloaded = load_or_create_signing_key(dir.path());
        assert_eq!(
            k.verifying_key().as_bytes(),
            reloaded.verifying_key().as_bytes(),
            "after regeneration the new key must itself persist"
        );
    }
}
