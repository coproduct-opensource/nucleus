//! How a container pod's tool proxy is reached, and what it is provisioned
//! with (#2446).
//!
//! One transport: the host-verified Unix socket. The proxy listens on a socket
//! in the pod directory, which the node already bind-mounts into exactly this
//! container at `/data/pod`, and admits peers by kernel-reported credentials
//! (`nucleus-tool-proxy --listen-unix`): the node connects from outside the
//! container's pid namespace and is admitted as the host. Approvals are
//! Ed25519-signed by the node and verified against its PUBLIC key, as on
//! Firecracker. So no shared secret is provisioned at all: the container holds
//! neither `NUCLEUS_TOOL_PROXY_AUTH_SECRET` nor
//! `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`, and no sandbox token. Its sandbox
//! proof is the identity files `pod_identity_files` writes.
//!
//! # The transport that is gone
//!
//! Until #2446 step 3 an operator could opt out with
//! `--container-proxy-transport tcp-hmac`: loopback TCP inside the container,
//! with both secrets in its environment, readable by every process in it. Step
//! 2 left the proxy's shared-secret tier no authority, so from release 2.7.0
//! that transport could reach nothing; step 3 deleted it with the tier. The
//! value is refused by name at startup (`retired_config`).
//!
//! # An image too old for the socket
//!
//! The image carries the same tool-proxy as the release's rootfs, so it is
//! judged by the same table: [`GuestCapability::HostVerifiedProxySocket`]. An
//! image whose OCI version label names a release without it is refused at
//! create, by name ([`admit_image`]); one whose version cannot be read (a
//! local build) is launched, and if its proxy dies before announcing the
//! socket the failure names the same capability ([`unannounced`]). Neither is
//! silent, and there is no fallback to a shared secret.

use std::collections::HashMap;
use std::path::Path;

use nucleus_spec::tier2_artifacts::{self, FirstShipped, GuestCapability, GuestSkew};

use crate::signed_proxy::ProxyTarget;
use crate::{ApiError, NodeState};

/// The socket path INSIDE the container: `/data/pod` is the pod directory's
/// mount point, so the host sees the same socket at `<pod_dir>/proxy.sock`.
pub(crate) const CONTAINER_PROXY_SOCKET: &str = "/data/pod/proxy.sock";

/// The workload door INSIDE the container (#3031 option B): the Unix socket
/// on which the proxy serves its workload, admitting the workload's uid by
/// `SO_PEERCRED`. Bound by the proxy only when the pod has a workload.
pub(crate) const CONTAINER_WORKLOAD_DOOR: &str = "/data/pod/workload.sock";
const SOCKET_FILE: &str = "proxy.sock";

/// The OCI label a published tool-proxy image carries its release in
/// (`docker/metadata-action` in `.github/workflows/docker.yml`).
pub(crate) const IMAGE_VERSION_LABEL: &str = "org.opencontainers.image.version";

/// The capability the socket transport depends on.
const SOCKET_CAPABILITY: GuestCapability = GuestCapability::HostVerifiedProxySocket;

/// Say at startup how container pods reach their proxy, so the posture is in
/// the log rather than implied.
pub(crate) fn log_posture() {
    tracing::info!(
        "container pods reach their tool-proxy over a peer-verified Unix socket; no shared \
         secret is provisioned into them (#2446)"
    );
}

/// The proxy-mode environment entries for the socket transport: the listener
/// path, the workload door, and the node's approval PUBLIC key. No secret: the
/// proxy starts with none on a host-verified transport, and with approver keys
/// configured `/v1/approve` accepts only an Ed25519 signature.
pub(crate) fn proxy_env(state: &NodeState) -> Vec<String> {
    vec![
        format!("NUCLEUS_TOOL_PROXY_LISTEN_UNIX={CONTAINER_PROXY_SOCKET}"),
        // In the pod directory: the guest default under /run is not the
        // container's to assume.
        format!("NUCLEUS_TOOL_PROXY_WORKLOAD_DOOR={CONTAINER_WORKLOAD_DOOR}"),
        format!(
            "NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS={}",
            hex::encode(state.approval_signer.verifying_key().to_bytes())
        ),
    ]
}

/// Refuse, before anything is created, an image whose tool-proxy is known to
/// lack the socket.
///
/// `version` is the image's [`IMAGE_VERSION_LABEL`], or `None` when it has no
/// such label or could not be inspected. Either way the node cannot tell, so it
/// launches the image and lets [`unannounced`] name the cause if the proxy
/// dies. That is not a grant: the transport tried is still the one with no
/// secret, and an image that cannot serve it fails to start. A version the
/// table cannot order (`main`, a branch build) is the same "could not tell",
/// never "has it".
pub(crate) fn admit_image(image: &str, version: Option<&str>) -> Result<(), ApiError> {
    let Some(version) = version else {
        return Ok(());
    };
    match tier2_artifacts::capability_skew(version, SOCKET_CAPABILITY) {
        Ok(()) | Err(GuestSkew::Unorderable { .. }) => Ok(()),
        Err(GuestSkew::Lacks { .. }) => Err(ApiError::Driver(format!(
            "refusing to launch a container pod: image {image} is tool-proxy release \
             {version}, which lacks {}. {}",
            capability_name(),
            remedy()
        ))),
    }
}

/// The error for a container whose proxy never announced itself, naming the
/// capability the socket needs when that is the likely cause.
pub(crate) fn unannounced(cause: ApiError) -> ApiError {
    ApiError::Driver(format!(
        "{cause}: the container's tool-proxy never announced its peer-verified socket \
         {CONTAINER_PROXY_SOCKET}. If the image's tool-proxy predates {}, it ignored \
         NUCLEUS_TOOL_PROXY_LISTEN_UNIX and refused to start with no shared secret. {}",
        capability_name(),
        remedy()
    ))
}

/// `HostVerifiedProxySocket (first released in v2.3.0: <change>)`, read from
/// the table so the release number is written once.
fn capability_name() -> String {
    let when = match SOCKET_CAPABILITY.first_shipped() {
        FirstShipped::Release(v) => format!("first released in v{v}"),
        FirstShipped::NotYet => "in no published release yet".to_string(),
    };
    format!(
        "{SOCKET_CAPABILITY:?} ({when}: {})",
        SOCKET_CAPABILITY.change()
    )
}

fn remedy() -> &'static str {
    "Use a tool-proxy image from that release or later; the shared-secret transport that \
     older images spoke is deleted (#2446)"
}

/// The release an image's labels name, if any.
pub(crate) fn image_version(labels: Option<&HashMap<String, String>>) -> Option<&str> {
    labels?.get(IMAGE_VERSION_LABEL).map(String::as_str)
}

/// Where the node's `SignedProxy` should forward, given what the container
/// announced and the pod directory on the host.
///
/// The announce file carries `unix:///data/pod/proxy.sock` — the CONTAINER's
/// path, which is only a readiness signal here; the host reaches the same
/// socket through the bind mount at `<pod_dir>/proxy.sock`, so the target is
/// derived from the pod directory, never parsed out of the announcement.
pub(crate) fn target(pod_dir_abs: &Path, announced: &str) -> Result<ProxyTarget, ApiError> {
    if !announced.starts_with("unix://") {
        return Err(ApiError::Driver(format!(
            "container proxy announced {announced:?} but the node provisioned a unix \
             transport; the image's tool-proxy lacks {}. {}",
            capability_name(),
            remedy()
        )));
    }
    Ok(ProxyTarget::Unix(pod_dir_abs.join(SOCKET_FILE)))
}

/// Prove the node can connect to the socket it is about to forward to, so a
/// pod whose proxy the node cannot reach fails at create, by name, instead of
/// being handed out with a proxy address whose every call is refused.
///
/// Found live: a node running as an ordinary user in the `docker` group, and
/// an image whose proxy runs as root, gives a socket owned by root at mode
/// 0755, and `connect(2)` is `EACCES` for the node. A node run as root (the
/// systemd unit `nucleus setup` installs) or as the proxy's uid connects. The
/// probe opens a connection and closes it; the proxy admits the host by its
/// credentials and serves nothing.
pub(crate) async fn ensure_reachable(target: &ProxyTarget) -> Result<(), ApiError> {
    match target {
        ProxyTarget::Tcp(_) => Ok(()),
        ProxyTarget::Unix(path) => tokio::net::UnixStream::connect(path)
            .await
            .map(drop)
            .map_err(|e| unreachable_socket(path, &e)),
    }
}

/// The refusal for a socket the node could not connect to.
fn unreachable_socket(path: &Path, error: &std::io::Error) -> ApiError {
    let why = match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            " The container's tool-proxy owns the socket and this node runs as another uid: run \
             the node as root (as the installed service does) or as the uid the image's \
             tool-proxy runs as."
        }
        _ => "",
    };
    ApiError::Driver(format!(
        "the node cannot connect to its container pod's tool-proxy socket {}: {error}.{why}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_container_socket_path_is_under_the_pod_mount() {
        assert!(CONTAINER_PROXY_SOCKET.starts_with("/data/pod/"));
        assert!(CONTAINER_PROXY_SOCKET.ends_with(SOCKET_FILE));
    }

    /// The host-side target is the pod directory's socket, whatever the
    /// container announced, and a TCP announcement is refused by name.
    #[test]
    fn a_unix_announcement_maps_to_the_host_side_socket() {
        let pod_dir = Path::new("/var/lib/nucleus/pods/p1");
        assert_eq!(
            target(pod_dir, "unix:///data/pod/proxy.sock").unwrap(),
            ProxyTarget::Unix(pod_dir.join(SOCKET_FILE))
        );
        let tcp = target(pod_dir, "127.0.0.1:4000")
            .expect_err("a TCP announcement is an image too old for the socket")
            .to_string();
        assert!(tcp.contains("HostVerifiedProxySocket"), "{tcp}");
    }

    /// #2446: a published image whose tool-proxy predates the socket is
    /// refused at create, naming the capability. Red before step 1: there was
    /// no preflight, and a 2.2.0 image's proxy exited with "AUTH_SECRET is
    /// empty" behind a generic "container exited before announcing proxy
    /// address".
    #[test]
    fn an_image_older_than_the_socket_is_refused_by_name() {
        let labels: HashMap<String, String> =
            [(IMAGE_VERSION_LABEL.to_string(), "2.2.0".to_string())].into();
        let err = admit_image(
            "ghcr.io/example/nucleus-tool-proxy:2.2.0",
            image_version(Some(&labels)),
        )
        .expect_err("a 2.2.0 tool-proxy has no --listen-unix");
        let msg = err.to_string();
        for needle in [
            "HostVerifiedProxySocket",
            "first released in v2.3.0",
            "#2551",
            "that release or later",
            "2.2.0",
        ] {
            assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
        }
        assert!(
            !msg.contains("tcp-hmac"),
            "no deleted opt-out is offered: {msg}"
        );
    }

    /// The other answers: a release that has it, a label the table cannot
    /// order, and no label are all launched (the last two fail named, below,
    /// if the proxy cannot serve the socket).
    #[test]
    fn an_image_that_carries_the_socket_or_cannot_be_judged_is_launched() {
        assert!(admit_image("img", Some("2.3.0")).is_ok());
        assert!(admit_image("img", Some(tier2_artifacts::GUEST_RELEASE)).is_ok());
        assert!(admit_image("img", Some("main")).is_ok());
        assert!(admit_image("img", None).is_ok());
        assert_eq!(image_version(None), None);
        assert_eq!(image_version(Some(&HashMap::new())), None);
    }

    /// A socket the node cannot connect to fails the create, by name. Red
    /// before: no probe, so the pod was handed out with a proxy address whose
    /// every call answered "proxy error: Permission denied" (found live, a
    /// non-root node and a root proxy).
    #[tokio::test]
    async fn a_socket_the_node_cannot_reach_is_refused_at_create() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = ProxyTarget::Unix(dir.path().join(SOCKET_FILE));
        let msg = ensure_reachable(&missing)
            .await
            .expect_err("no listener: the node cannot reach the proxy")
            .to_string();
        assert!(msg.contains(SOCKET_FILE), "{msg}");

        // The case found live, by its kind: the remedy names the uid mismatch.
        let denied = unreachable_socket(
            Path::new("/var/lib/nucleus/pods/p1/proxy.sock"),
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )
        .to_string();
        assert!(denied.contains("run the node as root"), "{denied}");

        // Non-vacuity: a socket that is listening is reachable, and TCP is not probed here.
        let listening = dir.path().join("live.sock");
        let _listener = tokio::net::UnixListener::bind(&listening).expect("bind");
        assert!(
            ensure_reachable(&ProxyTarget::Unix(listening))
                .await
                .is_ok()
        );
        assert!(
            ensure_reachable(&ProxyTarget::Tcp("127.0.0.1:9".parse().unwrap()))
                .await
                .is_ok()
        );
    }

    /// When the version could not be read and the proxy dies, the failure
    /// says why the socket is the likely cause, by name.
    #[test]
    fn a_proxy_that_never_announces_the_socket_is_explained() {
        let cause = ApiError::Driver("container exited before announcing proxy address".into());
        let msg = unannounced(cause).to_string();
        for needle in [
            "container exited before announcing proxy address",
            CONTAINER_PROXY_SOCKET,
            "HostVerifiedProxySocket",
        ] {
            assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
        }
    }
}
