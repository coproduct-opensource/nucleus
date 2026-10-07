//! How the local driver reaches its pods' tool-proxies (#2446 step 2).
//!
//! The local driver used to bind each proxy on loopback TCP and provision it
//! `NUCLEUS_TOOL_PROXY_AUTH_SECRET` and `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`,
//! and its `SignedProxy` HMAC'd every request. That is the shared-secret tier,
//! whose authority ceiling is now zero (the tool-proxy admits only
//! `/v1/health` on it). So a local pod is provisioned like a container pod on
//! the default transport:
//!
//! - the proxy listens on a peer-verified Unix socket in the pod directory
//!   (`--listen-unix`), and the node reaches it there;
//! - approvals are Ed25519, signed by the node's approval key and verified
//!   against its PUBLIC half (`NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS`);
//! - the sandbox proof is the pod's node-issued SVID (tier 2), not an HMAC'd
//!   sandbox token;
//! - no shared secret is provisioned at all.
//!
//! The node runs as the proxy's own uid on this driver, in the same pid
//! namespace, so the proxy admits it by uid and names it a pod peer
//! (`AuthTier::PodPeer`). That tier carries the pod's policy, exactly what the
//! shared secret used to carry, and binds no delegation identity.
//!
//! # A tool-proxy too old for the socket
//!
//! The local driver runs the node's own `--tool-proxy-path`, normally the same
//! build. One older than [`GuestCapability::HostVerifiedProxySocket`] does not
//! know `--listen-unix` and exits; one that announces a TCP address instead is
//! not the proxy this node provisioned. Both fail the create by name
//! ([`target`], [`exited`]). Neither falls back to a shared secret.

use std::path::{Path, PathBuf};

use nucleus_spec::tier2_artifacts::{FirstShipped, GuestCapability};

use crate::signed_proxy::ProxyTarget;
use crate::{ApiError, NodeState};

/// The socket's name in the pod directory. Short, because a Unix socket path
/// is limited to ~104 bytes on macOS and the pod directory is not.
pub(crate) const SOCKET_FILE: &str = "proxy.sock";

/// The capability this transport depends on.
const SOCKET_CAPABILITY: GuestCapability = GuestCapability::HostVerifiedProxySocket;

/// Where the proxy of the pod in `pod_dir` listens.
pub(crate) fn socket(pod_dir: &Path) -> std::io::Result<PathBuf> {
    std::path::absolute(pod_dir.join(SOCKET_FILE))
}

/// The environment the proxy is provisioned with for this transport: the
/// node's approval PUBLIC key, and nothing secret.
pub(crate) fn proxy_env(state: &NodeState) -> [(&'static str, String); 1] {
    [(
        "NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS",
        hex::encode(state.approval_signer.verifying_key().to_bytes()),
    )]
}

/// Where the node's `SignedProxy` forwards, given what the proxy announced.
/// The announcement is a readiness signal; the target is the socket the node
/// provisioned, never an address parsed out of it.
pub(crate) fn target(socket: &Path, announced: &str) -> Result<ProxyTarget, ApiError> {
    if announced.starts_with("unix://") {
        Ok(ProxyTarget::Unix(socket.to_path_buf()))
    } else {
        Err(ApiError::Driver(format!(
            "the local tool-proxy announced {announced:?}, not the peer-verified socket this node \
             provisioned at {}. {}",
            socket.display(),
            too_old()
        )))
    }
}

/// The error for a proxy that exited before announcing anything.
pub(crate) fn exited(status: std::process::ExitStatus, log: &Path) -> ApiError {
    ApiError::Driver(format!(
        "the local tool-proxy exited ({status}) before announcing its socket; its log is {}. {}",
        log.display(),
        too_old()
    ))
}

fn too_old() -> String {
    let when = match SOCKET_CAPABILITY.first_shipped() {
        FirstShipped::Release(v) => format!("first released in v{v}"),
        FirstShipped::NotYet => "in no published release yet".to_string(),
    };
    format!(
        "A tool-proxy older than {SOCKET_CAPABILITY:?} ({when}) cannot serve it; point \
         --tool-proxy-path at this node's own build. The shared-secret transport is not a \
         fallback: it admits only /v1/health (#2446)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2446 step 2: what the local driver provisions holds no shared secret.
    /// Red before: the driver set NUCLEUS_TOOL_PROXY_AUTH_SECRET and
    /// NUCLEUS_TOOL_PROXY_APPROVAL_SECRET on every local pod's proxy.
    #[test]
    fn a_local_pod_is_provisioned_no_shared_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::pod_api::handler_tests::state(&dir);
        let env = proxy_env(&state);
        for (key, _) in &env {
            assert!(!key.contains("SECRET"), "{key} is a shared secret");
        }
        assert_eq!(
            env[0].1,
            hex::encode(state.approval_signer.verifying_key().to_bytes()),
            "approvals verify against the node's public key"
        );
    }

    #[test]
    fn a_tcp_announcement_is_refused_by_name() {
        let socket = Path::new("/var/lib/nucleus/pods/p/proxy.sock");
        let err = target(socket, "127.0.0.1:4242").unwrap_err().to_string();
        assert!(err.contains("HostVerifiedProxySocket"), "{err}");
        assert!(err.contains("/v1/health"), "{err}");
        assert_eq!(
            target(socket, "unix:///var/lib/nucleus/pods/p/proxy.sock").unwrap(),
            ProxyTarget::Unix(socket.to_path_buf())
        );
    }
}
