//! What #2446 step 3 and the 2026-11-21 approval-HMAC deletion took away,
//! refused by name.
//!
//! The legacy approval HMAC key, `--approval-secret`
//! (`NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`), is refused the same way
//! ([`refuse_approval_secret`]); approver public keys are now the only
//! approval authority ([`require_approval_pubkeys`]).
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

/// Refuse the approval HMAC key handed to this process.
///
/// `--approval-secret` (`NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`) keyed the legacy
/// approval tier, deleted 2026-11-21 (zero static secrets, item 1). The
/// tool-proxy recomputed that MAC, so it could sign the approvals it checked,
/// and the key reached the workload through the world-readable guest command
/// line. A launcher still passing it is configured for a tier that no longer
/// exists, so it is refused by name rather than started with a key that
/// verifies nothing. As with [`refuse_auth_secret`], an empty value keyed
/// nothing and is not refused; a proxy with no `--approval-pubkeys` is
/// refused separately ([`require_approval_pubkeys`]).
pub fn refuse_approval_secret(value: Option<&str>) -> Result<(), String> {
    match value.map(str::trim) {
        None | Some("") => Ok(()),
        Some(_) => Err(
            "--approval-secret (NUCLEUS_TOOL_PROXY_APPROVAL_SECRET) is retired: the shared-key \
             approval tier it keyed is deleted, because the proxy that checks such a key can \
             also sign with it, and so could the workload that read it from the guest command \
             line. Remove it. Approvals are an approver's Ed25519 signature, checked against \
             the PUBLIC keys in --approval-pubkeys (NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS; \
             nucleus.approval_pubkeys on a guest's command line)"
                .to_string(),
        ),
    }
}

/// Refuse to start with no approval authority.
///
/// With the HMAC tier deleted, approver public keys are the only way into
/// `/v1/approve`. A proxy without them has an approval endpoint nobody can
/// authenticate to, which is a provisioning error, and startup is where it
/// should stop. `raw` is `--approval-pubkeys` as given; its keys are parsed
/// (and a malformed one refused) by `auth::ApprovalVerifier::from_hex_list`.
pub fn require_approval_pubkeys(raw: Option<&str>) -> Result<&str, String> {
    match raw.map(str::trim) {
        Some(keys) if !keys.is_empty() => Ok(keys),
        None | Some(_) => Err(
            "no approval authority is provisioned: set --approval-pubkeys \
             (NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS) to the approvers' Ed25519 public keys. The \
             shared-key alternative (NUCLEUS_TOOL_PROXY_APPROVAL_SECRET) is retired"
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

    /// The approval HMAC key is refused by name, naming what replaced it. Red
    /// before 2026-11-21: `--approval-secret` keyed a live approval tier.
    #[test]
    fn the_approval_secret_is_refused_by_name() {
        let why = refuse_approval_secret(Some("deadbeef")).expect_err("the key is retired");
        for needle in [
            "--approval-secret",
            "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
            "retired",
            "--approval-pubkeys",
            "nucleus.approval_pubkeys",
        ] {
            assert!(why.contains(needle), "missing {needle:?} in {why}");
        }
        assert!(
            !why.contains("deadbeef"),
            "the refusal never echoes the key"
        );
        assert!(refuse_approval_secret(None).is_ok());
        assert!(refuse_approval_secret(Some("")).is_ok());
        assert!(refuse_approval_secret(Some("  ")).is_ok());
    }

    /// Approver keys are the only approval authority, so their absence is a
    /// startup refusal that names them and the retired alternative.
    #[test]
    fn a_proxy_without_approver_keys_is_refused() {
        for raw in [None, Some(""), Some("  ")] {
            let why = require_approval_pubkeys(raw).expect_err("no approval authority");
            for needle in [
                "--approval-pubkeys",
                "NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS",
                "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
            ] {
                assert!(why.contains(needle), "{raw:?}: missing {needle:?} in {why}");
            }
        }
        assert_eq!(require_approval_pubkeys(Some(" ab,cd ")), Ok("ab,cd"));
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
