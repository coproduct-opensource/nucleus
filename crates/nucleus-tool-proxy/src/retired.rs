//! What #2446 step 3 deleted, refused by name.
//!
//! The shared-secret (HMAC) auth tier and the tier-3 sandbox token were both
//! keyed by `--auth-secret` (`NUCLEUS_TOOL_PROXY_AUTH_SECRET`). Step 2 left the
//! tier no authority; step 3 deleted it, the token and the key. A launcher
//! that still passes the key is configured for a proxy that no longer exists,
//! so it is refused at startup, naming the flag and what replaced it, rather
//! than started with a credential that does nothing (ADR 0007 B: a removed
//! input is not a silently accepted one).
//!
//! The same deletion leaves plain TCP without mTLS with no way to authenticate
//! anything but an approval: every other route would answer
//! [`crate::auth::AuthError::UnprovenTransport`]. Starting such a proxy used to
//! need the secret, and was refused without one; it is refused now for the
//! reason that is actually true.

/// Refuse a shared secret handed to this process.
///
/// An empty value is not a secret and is not refused: a host-verified launcher
/// was allowed to leave the variable empty, and an empty key keyed nothing.
pub fn refuse_auth_secret(value: Option<&str>) -> Result<(), String> {
    match value.map(str::trim) {
        None | Some("") => Ok(()),
        Some(_) => Err(
            "--auth-secret (NUCLEUS_TOOL_PROXY_AUTH_SECRET) is retired (#2446 step 3): the \
             shared-secret tier and the orchestrator sandbox token it keyed are deleted. \
             Remove it. The proxy is reached over its peer-verified Unix socket \
             (--listen-unix), vsock, or mTLS, and proves its sandbox with an identity \
             certificate (NUCLEUS_IDENTITY_CERT, e.g. nucleus_identity::pod_files)"
                .to_string(),
        ),
    }
}

/// Refuse to serve on a transport that can authenticate no caller.
///
/// `host_verified` is a vsock or peer-verified Unix binding; `mtls` is a TCP
/// listener that verifies client certificates. Either one can name a caller.
pub fn require_proven_transport(host_verified: bool, mtls: bool) -> Result<(), String> {
    match (host_verified, mtls) {
        (true, _) | (false, true) => Ok(()),
        (false, false) => Err(
            "no transport that can authenticate a caller: plain TCP without --mtls proves \
             nothing, and the shared-secret tier that took its requests is deleted (#2446 \
             step 3). Serve on --listen-unix (a peer-verified Unix socket), vsock, or TCP \
             with --mtls"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A launcher that still passes the secret is refused, and the refusal
    /// names the flag, the issue and what to use instead.
    #[test]
    fn a_shared_secret_is_refused_by_name() {
        let why = refuse_auth_secret(Some("deadbeef")).expect_err("a secret is retired");
        for needle in [
            "--auth-secret",
            "NUCLEUS_TOOL_PROXY_AUTH_SECRET",
            "#2446",
            "--listen-unix",
            "NUCLEUS_IDENTITY_CERT",
        ] {
            assert!(why.contains(needle), "missing {needle:?} in {why}");
        }
        assert!(refuse_auth_secret(None).is_ok());
        assert!(refuse_auth_secret(Some("")).is_ok());
        assert!(refuse_auth_secret(Some("  ")).is_ok());
    }

    /// Exhaustive: only the transport that names no caller is refused.
    #[test]
    fn only_a_transport_that_proves_nothing_is_refused() {
        assert!(require_proven_transport(true, false).is_ok());
        assert!(require_proven_transport(true, true).is_ok());
        assert!(require_proven_transport(false, true).is_ok());
        let why = require_proven_transport(false, false).expect_err("plain TCP");
        for needle in ["--mtls", "--listen-unix", "#2446"] {
            assert!(why.contains(needle), "missing {needle:?} in {why}");
        }
    }
}
