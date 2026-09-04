//! Loads this pod's SVID identity for the two clients that call
//! nucleus-node over mTLS: `node_client` (pod-management HTTP) and
//! `lockdown_client` (lockdown gRPC).
//!
//! Extracted out of `main.rs` (Move B) rather than left inline, matching
//! this codebase's house pattern for shrinking `main.rs` in place whenever a
//! self-contained piece grows past a few lines (`auth.rs`, `http_serve.rs`,
//! `grpc_tls.rs` all started the same way).

use std::path::PathBuf;

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
    identity_key: Option<&PathBuf>,
    identity_trust_bundle: Option<&PathBuf>,
    trust_bundle: Option<&PathBuf>,
) -> Option<Result<NodeIdentityPem, String>> {
    let cert_path = identity_cert.or(tls_cert)?.clone();
    let key_path = identity_key?.clone();
    let bundle_path = identity_trust_bundle.or(trust_bundle)?.clone();

    Some((|| {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| format!("failed to read {}: {e}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| format!("failed to read {}: {e}", key_path.display()))?;
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
    identity_key: Option<&PathBuf>,
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
                 --identity-key, and --identity-trust-bundle/--trust-bundle) to \
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
                Some(&PathBuf::from("k")),
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
                Some(&PathBuf::from("k")),
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
            Some(&key_path),
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
            Some(&key_path),
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
            Some(&key_path),
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
}
