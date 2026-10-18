//! An operator client identity the node mints for itself at start-up
//! (Program C, C2): `--operator-identity-dir`.
//!
//! A local node's operator needs an mTLS client certificate to call the
//! node's API at all (the HTTP and gRPC listeners are mTLS-only). The
//! live-path gates used to get one by reading `<state-dir>/ca/ca-key.pem`
//! directly and signing a certificate with it: an operator path that is
//! "read the node's CA key". The node now mints the operator's certificate
//! itself, for exactly the identity `--root-minter-spiffe-id` names, into a
//! directory only its own uid can enter, and nothing outside the node needs
//! the CA key again.
//!
//! The directory must not be inside the state directory (its contents are the
//! operator's, not the node's) and, if it exists, must be the node's own with
//! no group or other bits. Writes `cert.pem`, `key.pem` (0600) and
//! `trust-bundle.pem`, the same names `nucleus node --tls-cert --tls-key
//! --trust-bundle` takes.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ApiError;

/// `--operator-identity-dir`.
#[derive(clap::Args, Debug, Clone, Default)]
pub(crate) struct OperatorIdentityArgs {
    /// Mint a client certificate for `--root-minter-spiffe-id` at start-up,
    /// into this directory (created 0700; `cert.pem`, `key.pem`,
    /// `trust-bundle.pem`). Outside `--state-dir`. Valid for the node's
    /// certificate TTL. For a local operator or a live gate; never read the
    /// node's CA key instead.
    #[arg(
        long = "operator-identity-dir",
        env = "NUCLEUS_NODE_OPERATOR_IDENTITY_DIR"
    )]
    pub(crate) dir: Option<PathBuf>,
}

/// Mint and write the operator identity, when asked.
///
/// # Errors
/// Asked without `--root-minter-spiffe-id`, a directory inside the state
/// directory or reachable by another uid, or a failed mint or write.
pub(crate) async fn write(
    args: &crate::Args,
    manager: &crate::identity::IdentityManager,
) -> Result<(), ApiError> {
    let Some(dir) = args.operator_identity.dir.as_deref() else {
        return Ok(());
    };
    let (operator, state_dir) = (
        args.authority.root_minter_spiffe_id.as_deref(),
        args.state_dir.as_path(),
    );
    let refuse = |why: String| ApiError::Driver(format!("--operator-identity-dir: {why}"));
    let operator = operator.ok_or_else(|| {
        refuse("requires --root-minter-spiffe-id, the identity it is minted for".into())
    })?;
    let identity = nucleus_identity::Identity::from_spiffe_uri(operator)
        .map_err(|e| refuse(format!("{operator}: {e}")))?;
    prepare_dir(dir, state_dir).map_err(refuse)?;
    let csr = nucleus_identity::CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .map_err(|e| refuse(e.to_string()))?;
    let cert = manager
        .ca()
        .sign_csr(
            csr.csr(),
            csr.private_key(),
            &identity,
            manager.cert_ttl().max(Duration::from_secs(60)),
        )
        .await
        .map_err(|e| refuse(e.to_string()))?;
    let bundle: String = manager
        .trust_bundle()
        .roots()
        .iter()
        .map(|root| root.to_pem())
        .collect();
    let key = dir.join("key.pem");
    write_private(&key, cert.private_key_pem().as_bytes()).map_err(refuse)?;
    std::fs::write(dir.join("cert.pem"), cert.chain_pem())?;
    std::fs::write(dir.join("trust-bundle.pem"), bundle)?;
    tracing::info!(dir = %dir.display(), %operator, "operator client identity written");
    Ok(())
}

/// Create `dir` 0700, or accept it if it is this uid's own with no group or
/// other bits; refuse it inside `state_dir`.
fn prepare_dir(dir: &Path, state_dir: &Path) -> Result<(), String> {
    let absolute = |p: &Path| std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display()));
    let abs_dir = resolve_directory(&absolute(dir)?)?;
    let state = state_dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", state_dir.display()))?;
    if abs_dir.starts_with(&state) {
        return Err(format!(
            "{} is inside the state directory; the operator's identity is not the node's",
            dir.display()
        ));
    }
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .recursive(true)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))
        }
        Ok(meta)
            if meta.is_dir()
                && meta.uid() == nucleus::runtime_uid()
                && meta.permissions().mode() & 0o077 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(format!(
            "{} exists and is not a directory only this uid can enter",
            dir.display()
        )),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// Resolve existing ancestors even when the requested directory does not exist yet.
/// Otherwise a symlink to the state directory hides a new child from the containment check.
fn resolve_directory(path: &Path) -> Result<PathBuf, String> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                for component in missing.into_iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| format!("{}: {e}", path.display()))?;
                missing.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| format!("{}: {e}", path.display()))?;
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
}

/// Write `bytes` to `path` created 0600 (replacing a previous file).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let failed = |e: std::io::Error| format!("{}: {e}", path.display());
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(failed(e)),
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operator's directory is never the node's: inside the state
    /// directory, or an existing directory another uid can enter, is refused;
    /// a fresh one is made 0700.
    #[test]
    fn the_operator_directory_is_private_and_outside_the_state_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let state = root.path().join("state");
        std::fs::create_dir(&state).expect("state");
        assert!(prepare_dir(&state.join("operator"), &state).is_err());
        assert!(prepare_dir(&state, &state).is_err());

        let alias = root.path().join("state-alias");
        std::os::unix::fs::symlink(&state, &alias).expect("state symlink");
        assert!(prepare_dir(&alias.join("new/operator"), &state).is_err());
        assert!(
            !state.join("new").exists(),
            "refuse before creating anything"
        );

        let fresh = root.path().join("operator");
        prepare_dir(&fresh, &state).expect("fresh");
        let mode = std::fs::metadata(&fresh)
            .expect("made")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);

        let shared = root.path().join("shared");
        std::fs::create_dir(&shared).expect("shared");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).expect("0755");
        assert!(prepare_dir(&shared, &state).is_err());
    }

    #[test]
    fn the_key_is_written_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("key.pem");
        write_private(&key, b"k").expect("first");
        write_private(&key, b"k2").expect("replaced");
        let meta = std::fs::metadata(&key).expect("written");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&key).expect("read"), b"k2");
    }
}
