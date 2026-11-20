//! Loads this pod's SVID identity for the two clients that call
//! nucleus-node over mTLS: `node_client` (pod-management HTTP) and
//! `lockdown_client` (lockdown gRPC).
//!
//! Extracted out of `main.rs` (Move B) rather than left inline, matching
//! this codebase's house pattern for shrinking `main.rs` in place whenever a
//! self-contained piece grows past a few lines (`auth.rs`, `http_serve.rs`,
//! `grpc_tls.rs` all started the same way).

use std::io::{IsTerminal as _, Read as _};
use std::path::PathBuf;

use nucleus_identity::pod_files::KEY_ON_STDIN_MAX;

/// The pod's private key, delivered on stdin by the launcher (#3471,
/// `nucleus_identity::pod_files::PodKey::into_pipe`) and held only in this
/// process's memory. Not `Clone`; its `Debug` is redacted.
pub(crate) struct DeliveredKey(String);

impl std::fmt::Debug for DeliveredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveredKey(<redacted>)")
    }
}

impl DeliveredKey {
    /// Read the key from `input` to its end: the launcher wrote it whole and
    /// closed the pipe. Refused when nothing arrives, when more than
    /// [`KEY_ON_STDIN_MAX`] arrives, or when it is not text.
    pub(crate) fn read_from(input: impl std::io::Read) -> Result<Self, String> {
        let mut pem = String::new();
        input
            .take(KEY_ON_STDIN_MAX + 1)
            .read_to_string(&mut pem)
            .map_err(|e| format!("reading the pod key from stdin: {e}"))?;
        if u64::try_from(pem.len()).unwrap_or(u64::MAX) > KEY_ON_STDIN_MAX {
            return Err(format!(
                "more than {KEY_ON_STDIN_MAX} bytes arrived on stdin, which is not a pod key"
            ));
        }
        if pem.trim().is_empty() {
            return Err(
                "the launcher said it delivered the pod key on stdin, and none arrived".into(),
            );
        }
        Ok(Self(pem))
    }

    /// The key this process's launcher delivered, read once, now: before
    /// anything is spawned (a child inherits stdin) and after the runtime
    /// sealed itself (`nucleus::seal_runtime`). `None` when the launcher
    /// delivered none. A terminal is refused: an operator who set the flag by
    /// hand gets a reason, not a process waiting on the keyboard.
    pub(crate) fn from_stdin(delivered: bool) -> Result<Option<Self>, String> {
        if !delivered {
            return Ok(None);
        }
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err(
                "--identity-key-on-stdin is set and stdin is a terminal; a launcher delivers \
                 the pod key on a pipe"
                    .into(),
            );
        }
        Self::read_from(stdin.lock()).map(Some)
    }
}

/// Where the pod's private key comes from.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KeySource<'a> {
    /// A file the proxy reads (`--identity-key`): the guest layout's, where
    /// every child is another uid.
    File(&'a PathBuf),
    /// Delivered on stdin at startup (`--identity-key-on-stdin`).
    Delivered(&'a DeliveredKey),
}

/// Cert, key, and trust bundle as separate PEM strings — the shape both
/// `WorkloadCertificate::from_pem` (`lockdown_client`'s gRPC identity) and
/// `TrustBundle::from_pem` want. `node_client`'s reqwest-based HTTP client
/// wants cert and key concatenated instead; its call site does that
/// concatenation itself rather than this module baking in one client's
/// convention.
#[derive(Debug)]
pub(crate) struct NodeIdentityPem {
    pub(crate) cert_pem: String,
    pub(crate) key_pem: String,
    pub(crate) bundle_pem: String,
}

/// Load this pod's SVID identity and the node's trust bundle.
///
/// Both `node_client` and `lockdown_client` need the same pair, so this is
/// loaded once by their shared caller and passed to each rather than
/// re-read per client.
///
/// Returns `None` (rather than erroring) when neither an identity cert path
/// nor a trust bundle path is available — matching `sandbox_proof`'s
/// existing `--identity-cert`-falls-back-to-`--tls-cert` fallback — so a
/// deployment that hasn't wired identity yet gets a clear "disabled" state
/// instead of a hard failure at a call site that may not even be enabled
/// (`--enable-pod-mgmt` / `--node-grpc-url` gate whether these clients are
/// built at all).
pub(crate) fn load(
    identity_cert: Option<&PathBuf>,
    tls_cert: Option<&PathBuf>,
    identity_key: Option<KeySource<'_>>,
    identity_trust_bundle: Option<&PathBuf>,
    trust_bundle: Option<&PathBuf>,
) -> Option<Result<NodeIdentityPem, String>> {
    let cert_path = identity_cert.or(tls_cert)?.clone();
    let key = identity_key?;
    let bundle_path = identity_trust_bundle.or(trust_bundle)?.clone();

    Some((|| {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| format!("failed to read {}: {e}", cert_path.display()))?;
        let key_pem = match key {
            KeySource::File(path) => std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?,
            KeySource::Delivered(DeliveredKey(pem)) => pem.clone(),
        };
        let bundle_pem = std::fs::read_to_string(&bundle_path)
            .map_err(|e| format!("failed to read {}: {e}", bundle_path.display()))?;

        Ok(NodeIdentityPem {
            cert_pem,
            key_pem,
            bundle_pem,
        })
    })())
}

/// `load`, but fail closed: logs and exits when identity is unset or
/// unreadable, instead of handing each of `node_client` and
/// `lockdown_client`'s call sites their own copy of that boilerplate.
/// `flag_hint` names the CLI flag that gated building this client, for the
/// "you enabled X but didn't give it an identity" message.
pub(crate) fn require(
    identity_cert: Option<&PathBuf>,
    tls_cert: Option<&PathBuf>,
    identity_key: Option<KeySource<'_>>,
    identity_trust_bundle: Option<&PathBuf>,
    trust_bundle: Option<&PathBuf>,
    flag_hint: &str,
) -> NodeIdentityPem {
    match load(
        identity_cert,
        tls_cert,
        identity_key,
        identity_trust_bundle,
        trust_bundle,
    ) {
        Some(Ok(identity)) => identity,
        Some(Err(e)) => {
            tracing::error!("failed to load node identity for {flag_hint}: {e}");
            std::process::exit(1);
        }
        None => {
            tracing::error!(
                "{flag_hint} requires an SVID identity (--identity-cert/--tls-cert, \
                 --identity-key or --identity-key-on-stdin, and \
                 --identity-trust-bundle/--trust-bundle) to \
                 authenticate to nucleus-node over mTLS"
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_when_no_cert_path_is_available() {
        assert!(
            load(
                None,
                None,
                Some(KeySource::File(&PathBuf::from("k"))),
                Some(&PathBuf::from("b")),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn none_when_no_key_path_is_available() {
        assert!(
            load(
                Some(&PathBuf::from("c")),
                None,
                None,
                Some(&PathBuf::from("b")),
                None
            )
            .is_none()
        );
    }

    #[test]
    fn none_when_no_bundle_path_is_available() {
        assert!(
            load(
                Some(&PathBuf::from("c")),
                None,
                Some(KeySource::File(&PathBuf::from("k"))),
                None,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn identity_cert_falls_back_to_tls_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let bundle_path = dir.path().join("bundle.pem");
        std::fs::write(&cert_path, "CERT").unwrap();
        std::fs::write(&key_path, "KEY").unwrap();
        std::fs::write(&bundle_path, "BUNDLE").unwrap();

        let result = load(
            None,
            Some(&cert_path),
            Some(KeySource::File(&key_path)),
            Some(&bundle_path),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.cert_pem, "CERT");
        assert_eq!(result.key_pem, "KEY");
        assert_eq!(result.bundle_pem, "BUNDLE");
    }

    #[test]
    fn identity_trust_bundle_falls_back_to_trust_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let bundle_path = dir.path().join("bundle.pem");
        std::fs::write(&cert_path, "CERT").unwrap();
        std::fs::write(&key_path, "KEY").unwrap();
        std::fs::write(&bundle_path, "BUNDLE").unwrap();

        let result = load(
            Some(&cert_path),
            None,
            Some(KeySource::File(&key_path)),
            None,
            Some(&bundle_path),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.bundle_pem, "BUNDLE");
    }

    #[test]
    fn a_missing_file_reports_its_path_in_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.pem");
        let key_path = dir.path().join("key.pem");
        let bundle_path = dir.path().join("bundle.pem");
        std::fs::write(&key_path, "KEY").unwrap();
        std::fs::write(&bundle_path, "BUNDLE").unwrap();

        let err = load(
            Some(&missing),
            None,
            Some(KeySource::File(&key_path)),
            Some(&bundle_path),
            None,
        )
        .unwrap()
        .unwrap_err();
        assert!(
            err.contains("does-not-exist.pem"),
            "error should name the missing path, got: {err}"
        );
    }

    /// #3471: a delivered key is used as the key, with no key file at all,
    /// and is never printed.
    #[test]
    fn a_delivered_key_is_the_key_and_no_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let bundle_path = dir.path().join("bundle.pem");
        std::fs::write(&cert_path, "CERT").unwrap();
        std::fs::write(&bundle_path, "BUNDLE").unwrap();
        let key = DeliveredKey::read_from(&b"-----BEGIN PRIVATE KEY-----\nK\n"[..]).unwrap();
        assert_eq!(format!("{key:?}"), "DeliveredKey(<redacted>)");
        let result = load(
            Some(&cert_path),
            None,
            Some(KeySource::Delivered(&key)),
            Some(&bundle_path),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.key_pem, "-----BEGIN PRIVATE KEY-----\nK\n");
        assert_eq!(result.cert_pem, "CERT");
    }

    /// #3471: nothing on stdin, or more than a key, is refused by name.
    #[test]
    fn an_empty_or_oversized_delivery_is_refused() {
        let empty = DeliveredKey::read_from(&b"  \n"[..]).unwrap_err();
        assert!(empty.contains("none arrived"), "{empty}");
        let huge = vec![b'k'; usize::try_from(KEY_ON_STDIN_MAX).unwrap() + 1];
        let refused = DeliveredKey::read_from(&huge[..]).unwrap_err();
        assert!(refused.contains("not a pod key"), "{refused}");
        assert!(DeliveredKey::from_stdin(false).unwrap().is_none());
    }
}
