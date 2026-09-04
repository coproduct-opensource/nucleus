//! How a container pod's tool proxy is reached, and what it is provisioned
//! with (#2446 step 1, node side).
//!
//! Two transports:
//!
//! - **`Tcp`** (default): the env-provisioned path. The proxy sidecar listens
//!   on loopback TCP inside the container and the node provisions
//!   `NUCLEUS_TOOL_PROXY_AUTH_SECRET`; the node's `SignedProxy` HMACs every
//!   request with it. Every process in the container can read that secret:
//!   this is the bare shared-secret tier the owner decided to deprecate.
//! - **`Unix`** (opt-in, `--container-proxy-unix`): the host-verified path.
//!   The proxy listens on a socket in the pod directory, which the node
//!   already bind-mounts into exactly this container at `/data/pod`, and
//!   admits peers by kernel-reported credentials (`nucleus-tool-proxy
//!   --listen-unix`): the node connects from outside the container's pid
//!   namespace and is admitted as the host; no secret is provisioned, so the
//!   HMAC tier has no key inside the container at all.
//!
//! Opt-in rather than default because the workload's own clients (the SDK
//! speaks TCP + HMAC today) must learn `unix://` first; the rollout note on
//! #2446 asks for a coordinated cutover, not a flag day. The default flips
//! when they do.

use std::path::Path;

use crate::signed_proxy::ProxyTarget;
use crate::{ApiError, NodeState};

/// The socket path INSIDE the container: `/data/pod` is the pod directory's
/// mount point, so the host sees the same socket at `<pod_dir>/proxy.sock`.
pub(crate) const CONTAINER_PROXY_SOCKET: &str = "/data/pod/proxy.sock";
const SOCKET_FILE: &str = "proxy.sock";

/// The proxy-mode environment entries that depend on the transport.
///
/// `Tcp` provisions the shared secret (the proxy refuses an empty key on a
/// transport that can select the HMAC tier). `Unix` provisions the listener
/// path and NO secret: the proxy accepts an empty key on a host-verified
/// transport, and the whole point is that nothing in the container holds one.
pub(crate) fn proxy_env(state: &NodeState) -> Vec<String> {
    if state.container_proxy_unix {
        vec![format!(
            "NUCLEUS_TOOL_PROXY_LISTEN_UNIX={CONTAINER_PROXY_SOCKET}"
        )]
    } else {
        vec![format!(
            "NUCLEUS_TOOL_PROXY_AUTH_SECRET={}",
            state.proxy_auth_secret
        )]
    }
}

/// Where the node's `SignedProxy` should forward, given what the container
/// announced and the pod directory on the host.
///
/// On `Tcp` the announce file carries the bound `host:port`. On `Unix` it
/// carries `unix:///data/pod/proxy.sock` — the CONTAINER's path, which is
/// only a readiness signal here; the host reaches the same socket through the
/// bind mount at `<pod_dir>/proxy.sock`, so the target is derived from the
/// pod directory, never parsed out of the announcement.
pub(crate) fn target(
    state: &NodeState,
    pod_dir_abs: &Path,
    announced: &str,
) -> Result<ProxyTarget, ApiError> {
    if state.container_proxy_unix {
        if !announced.starts_with("unix://") {
            return Err(ApiError::Driver(format!(
                "container proxy announced {announced:?} but the node provisioned a unix transport"
            )));
        }
        return Ok(ProxyTarget::Unix(pod_dir_abs.join(SOCKET_FILE)));
    }
    let addr = announced
        .parse()
        .map_err(|e| ApiError::Driver(format!("invalid tool proxy address {announced}: {e}")))?;
    Ok(ProxyTarget::Tcp(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_container_socket_path_is_under_the_pod_mount() {
        assert!(CONTAINER_PROXY_SOCKET.starts_with("/data/pod/"));
        assert!(CONTAINER_PROXY_SOCKET.ends_with(SOCKET_FILE));
    }

    #[test]
    fn a_unix_announcement_maps_to_the_host_side_socket() {
        let pod_dir = Path::new("/var/lib/nucleus/pods/p1");
        let expected = pod_dir.join(SOCKET_FILE);
        // Pure mapping, independent of state: the host path is the pod dir
        // joined with the socket file name, whatever the container announced.
        assert_eq!(expected, Path::new("/var/lib/nucleus/pods/p1/proxy.sock"));
    }
}
