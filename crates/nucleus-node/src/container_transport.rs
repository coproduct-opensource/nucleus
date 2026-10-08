//! How a container pod's tool proxy is reached, and what it is provisioned
//! with (#2446 step 1).
//!
//! Two transports, chosen by the operator with `--container-proxy-transport`:
//!
//! - **`Unix`** (the default): the host-verified path. The proxy listens on a
//!   socket in the pod directory, which the node already bind-mounts into
//!   exactly this container at `/data/pod`, and admits peers by kernel-reported
//!   credentials (`nucleus-tool-proxy --listen-unix`): the node connects from
//!   outside the container's pid namespace and is admitted as the host.
//!   Approvals are Ed25519-signed by the node and verified against its PUBLIC
//!   key, as on Firecracker. So no shared secret is provisioned at all: the
//!   container holds neither `NUCLEUS_TOOL_PROXY_AUTH_SECRET` nor
//!   `NUCLEUS_TOOL_PROXY_APPROVAL_SECRET`.
//! - **`TcpHmac`** (opt-out): the env-provisioned legacy path. The proxy
//!   listens on loopback TCP inside the container and the node provisions both
//!   secrets; the node's `SignedProxy` HMACs every request. Every process in
//!   the container can read them: this is the bare shared-secret tier the
//!   owner decided to deprecate, kept only for tool-proxy images that predate
//!   the socket.
//!
//! The default flipped once the workload stopped needing a secret to reach
//! its proxy: it is given its own door (`CONTAINER_WORKLOAD_DOOR`, #3122) on
//! both transports, and every client of it speaks `unix://` (`nucleus-mcp`,
//! `nucleus-egress-http`, and `nucleus-sdk`'s `ProxyClient`).
//!
//! # An image too old for the default
//!
//! The image carries the same tool-proxy as the release's rootfs, so it is
//! judged by the same table: [`GuestCapability::HostVerifiedProxySocket`]. An
//! image whose OCI version label names a release without it is refused at
//! create, by name ([`admit_image`]); one whose version cannot be read (a
//! local build) is launched, and if its proxy dies before announcing the
//! socket the failure names the same capability ([`unannounced`]). Neither is
//! silent, and neither falls back to the shared secret on its own: the
//! operator opts in to that with `--container-proxy-transport tcp-hmac`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use nucleus_spec::tier2_artifacts::{self, FirstShipped, GuestCapability, GuestSkew};

use crate::signed_proxy::{ApprovalSigning, ProxyTarget};
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

/// The capability the default transport depends on.
const SOCKET_CAPABILITY: GuestCapability = GuestCapability::HostVerifiedProxySocket;

/// How the node reaches every container pod's tool-proxy. Chosen by the
/// operator, never by a spec.
///
/// Two named variants rather than a `bool` (ADR 0007 A-7), matched
/// exhaustively (E-2), and no `Default` impl (B-1): the CLI default is spelled
/// out on the flag, and it is the one with no shared secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ContainerProxyTransport {
    /// The peer-verified Unix socket in the pod directory. No shared secret
    /// reaches the container. The default.
    Unix,
    /// Loopback TCP inside the container, authenticated by a shared secret the
    /// node provisions into the container's environment. For tool-proxy
    /// images that predate [`GuestCapability::HostVerifiedProxySocket`].
    TcpHmac,
}

impl ContainerProxyTransport {
    /// Whether the proxy is reached over the host-verified socket, which is
    /// also when it is handed its identity files (the HMAC sandbox token is
    /// unverifiable there: the proxy holds no key).
    pub(crate) fn is_host_verified(self) -> bool {
        match self {
            Self::Unix => true,
            Self::TcpHmac => false,
        }
    }

    /// Say at startup when this node provisions shared secrets into its
    /// containers, so the weakened posture is in the log rather than implied.
    pub(crate) fn log_posture(self) {
        match self {
            Self::Unix => tracing::info!(
                "container pods reach their tool-proxy over a peer-verified Unix socket; \
                 no shared secret is provisioned into them (#2446)"
            ),
            Self::TcpHmac => tracing::warn!(
                "--container-proxy-transport tcp-hmac: every container pod is provisioned \
                 NUCLEUS_TOOL_PROXY_AUTH_SECRET and NUCLEUS_TOOL_PROXY_APPROVAL_SECRET, which \
                 every process in it can read (the deprecated shared-secret tier, #2446)"
            ),
        }
    }
}

/// The proxy-mode environment entries that depend on the transport.
///
/// `TcpHmac` provisions both shared secrets (the proxy refuses an empty key on
/// a transport that can select the HMAC tier). `Unix` provisions the listener
/// path and the node's approval PUBLIC key, and no secret: the proxy accepts an
/// empty key on a host-verified transport, and with approver keys configured
/// `/v1/approve` accepts only an Ed25519 signature.
pub(crate) fn proxy_env(state: &NodeState) -> Vec<String> {
    // The workload door goes in the pod directory on both transports: the
    // guest default under /run is not the container's to assume.
    let door = format!("NUCLEUS_TOOL_PROXY_WORKLOAD_DOOR={CONTAINER_WORKLOAD_DOOR}");
    match state.container_proxy {
        ContainerProxyTransport::Unix => vec![
            format!("NUCLEUS_TOOL_PROXY_LISTEN_UNIX={CONTAINER_PROXY_SOCKET}"),
            door,
            format!(
                "NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS={}",
                hex::encode(state.approval_signer.verifying_key().to_bytes())
            ),
        ],
        ContainerProxyTransport::TcpHmac => vec![
            format!("NUCLEUS_TOOL_PROXY_AUTH_SECRET={}", state.proxy_auth_secret),
            door,
            format!(
                "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET={}",
                state.proxy_approval_secret
            ),
        ],
    }
}

/// How the node's `SignedProxy` signs `/v1/approve` for this transport: the
/// same choice [`proxy_env`] provisioned the container to verify.
pub(crate) fn approval_signing(state: &NodeState) -> ApprovalSigning {
    match state.container_proxy {
        ContainerProxyTransport::Unix => {
            ApprovalSigning::Ed25519(Arc::clone(&state.approval_signer))
        }
        ContainerProxyTransport::TcpHmac => {
            ApprovalSigning::Hmac(Arc::new(state.proxy_approval_secret.as_bytes().to_vec()))
        }
    }
}

/// Refuse, before anything is created, an image whose tool-proxy is known to
/// lack the socket this node's transport depends on.
///
/// `version` is the image's [`IMAGE_VERSION_LABEL`], or `None` when it has no
/// such label or could not be inspected. Either way the node cannot tell, so it
/// launches the image and lets [`unannounced`] name the cause if the proxy
/// dies. That is not a grant: the transport tried is still the one with no
/// secret, and an image that cannot serve it fails to start rather than
/// falling back. A version the table cannot order (`main`, a branch build) is
/// the same "could not tell", never "has it".
pub(crate) fn admit_image(
    transport: ContainerProxyTransport,
    image: &str,
    version: Option<&str>,
) -> Result<(), ApiError> {
    match transport {
        // The opt-out speaks only the shared-secret tier, which a release with
        // `SharedSecretTierRetired` answers on `/v1/health` alone (#2446 step 2).
        // Such an image is refused here, by name; one the table cannot order is
        // launched, and its proxy names the same refusal on the first call.
        ContainerProxyTransport::TcpHmac => match version
            .map(|v| tier2_artifacts::capability_skew(v, GuestCapability::SharedSecretTierRetired))
        {
            Some(Ok(())) => Err(ApiError::Driver(format!(
                "refusing to launch a container pod: image {image} is tool-proxy release {}, \
                 whose shared-secret tier carries no authority (SharedSecretTierRetired, #2446), \
                 and --container-proxy-transport tcp-hmac speaks nothing else. Use the default \
                 transport, --container-proxy-transport unix",
                version.unwrap_or_default()
            ))),
            Some(Err(_)) | None => Ok(()),
        },
        ContainerProxyTransport::Unix => {
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
    }
}

/// The error for a container whose proxy never announced itself, naming the
/// capability the default transport needs when that is the likely cause.
pub(crate) fn unannounced(transport: ContainerProxyTransport, cause: ApiError) -> ApiError {
    match transport {
        ContainerProxyTransport::TcpHmac => cause,
        ContainerProxyTransport::Unix => ApiError::Driver(format!(
            "{cause}: the container's tool-proxy never announced its peer-verified socket \
             {CONTAINER_PROXY_SOCKET}. If the image's tool-proxy predates {}, it ignored \
             NUCLEUS_TOOL_PROXY_LISTEN_UNIX and refused to start with no shared secret. {}",
            capability_name(),
            remedy()
        )),
    }
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
    "Use a tool-proxy image from that release or later, or opt this node back into the \
     deprecated shared-secret transport with --container-proxy-transport tcp-hmac \
     (NUCLEUS_CONTAINER_PROXY_TRANSPORT)"
}

/// The release an image's labels name, if any.
pub(crate) fn image_version(labels: Option<&HashMap<String, String>>) -> Option<&str> {
    labels?.get(IMAGE_VERSION_LABEL).map(String::as_str)
}

/// Where the node's `SignedProxy` should forward, given what the container
/// announced and the pod directory on the host.
///
/// On `TcpHmac` the announce file carries the bound `host:port`. On `Unix` it
/// carries `unix:///data/pod/proxy.sock` — the CONTAINER's path, which is
/// only a readiness signal here; the host reaches the same socket through the
/// bind mount at `<pod_dir>/proxy.sock`, so the target is derived from the
/// pod directory, never parsed out of the announcement.
pub(crate) fn target(
    state: &NodeState,
    pod_dir_abs: &Path,
    announced: &str,
) -> Result<ProxyTarget, ApiError> {
    match state.container_proxy {
        ContainerProxyTransport::Unix => {
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
        ContainerProxyTransport::TcpHmac => {
            let addr = announced.parse().map_err(|e| {
                ApiError::Driver(format!("invalid tool proxy address {announced}: {e}"))
            })?;
            Ok(ProxyTarget::Tcp(addr))
        }
    }
}

/// Prove the node can connect to the socket it is about to forward to, so a
/// pod whose proxy the node cannot reach fails at create, by name, instead of
/// being handed out with a proxy address whose every call is refused.
///
/// Found live on the default transport: a node running as an ordinary user
/// in the `docker` group, and an image whose proxy runs as root, gives a
/// socket owned by root at mode 0755, and `connect(2)` is `EACCES` for the
/// node. A node run as root (the systemd unit `nucleus setup` installs) or as
/// the proxy's uid connects. The probe opens a connection and closes it; the
/// proxy admits the host by its credentials and serves nothing.
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
        "the node cannot connect to its container pod's tool-proxy socket {}: {error}.{why} Or \
         opt this node back into the deprecated shared-secret transport with \
         --container-proxy-transport tcp-hmac (NUCLEUS_CONTAINER_PROXY_TRANSPORT)",
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

    #[test]
    fn a_unix_announcement_maps_to_the_host_side_socket() {
        let pod_dir = Path::new("/var/lib/nucleus/pods/p1");
        let expected = pod_dir.join(SOCKET_FILE);
        // Pure mapping, independent of state: the host path is the pod dir
        // joined with the socket file name, whatever the container announced.
        assert_eq!(expected, Path::new("/var/lib/nucleus/pods/p1/proxy.sock"));
    }

    /// #2446: a published image whose tool-proxy predates the socket is
    /// refused at create, naming the capability and the opt-out. Red before
    /// this change: there was no preflight, and a 2.2.0 image's proxy exited
    /// with "AUTH_SECRET is empty" behind a generic "container exited before
    /// announcing proxy address".
    #[test]
    fn an_image_older_than_the_socket_is_refused_by_name() {
        let labels: HashMap<String, String> =
            [(IMAGE_VERSION_LABEL.to_string(), "2.2.0".to_string())].into();
        let err = admit_image(
            ContainerProxyTransport::Unix,
            "ghcr.io/example/nucleus-tool-proxy:2.2.0",
            image_version(Some(&labels)),
        )
        .expect_err("a 2.2.0 tool-proxy has no --listen-unix");
        let msg = err.to_string();
        for needle in [
            "HostVerifiedProxySocket",
            "first released in v2.3.0",
            "#2551",
            "--container-proxy-transport tcp-hmac",
            "2.2.0",
        ] {
            assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
        }
    }

    /// The other answers: a release that has it, a label the table cannot
    /// order, and no label are all launched (the last two fail named, below,
    /// if the proxy cannot serve the socket); the legacy transport demands
    /// nothing of the image.
    #[test]
    fn an_image_that_carries_the_socket_or_cannot_be_judged_is_launched() {
        let unix = ContainerProxyTransport::Unix;
        assert!(admit_image(unix, "img", Some("2.3.0")).is_ok());
        assert!(admit_image(unix, "img", Some(tier2_artifacts::GUEST_RELEASE)).is_ok());
        assert!(admit_image(unix, "img", Some("main")).is_ok());
        assert!(admit_image(unix, "img", None).is_ok());
        assert!(admit_image(ContainerProxyTransport::TcpHmac, "img", Some("2.2.0")).is_ok());
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
        assert!(
            msg.contains("--container-proxy-transport tcp-hmac"),
            "{msg}"
        );

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
    /// says why the default transport is the likely cause, by name.
    #[test]
    fn a_proxy_that_never_announces_the_socket_is_explained() {
        let cause = || ApiError::Driver("container exited before announcing proxy address".into());
        let msg = unannounced(ContainerProxyTransport::Unix, cause()).to_string();
        for needle in [
            "container exited before announcing proxy address",
            CONTAINER_PROXY_SOCKET,
            "HostVerifiedProxySocket",
            "--container-proxy-transport tcp-hmac",
        ] {
            assert!(msg.contains(needle), "missing {needle:?} in: {msg}");
        }
        let legacy = unannounced(ContainerProxyTransport::TcpHmac, cause()).to_string();
        assert!(!legacy.contains("HostVerifiedProxySocket"), "{legacy}");
    }

    /// #2446 step 2 keeps the opt-out working for every image that can still
    /// serve it: `tcp-hmac` admits a release before `SharedSecretTierRetired`
    /// (2.6.0, 2.2.0) and an image the table cannot order, exactly as before.
    /// The pinned release is the first to carry the retirement (2.7.0), so its
    /// image, and an RC of it, is refused by the arm above, by name.
    #[test]
    fn tcp_hmac_admits_every_image_that_serves_it_and_refuses_the_retired_tier() {
        for version in [Some("2.6.0"), Some("2.2.0"), Some("main"), None] {
            assert!(
                admit_image(ContainerProxyTransport::TcpHmac, "img", version).is_ok(),
                "{version:?}"
            );
        }
        assert_eq!(
            GuestCapability::SharedSecretTierRetired.first_shipped(),
            FirstShipped::Release(tier2_artifacts::GUEST_RELEASE)
        );
        for version in [tier2_artifacts::GUEST_RELEASE, "2.7.0-rc.1"] {
            let err = admit_image(ContainerProxyTransport::TcpHmac, "img", Some(version))
                .expect_err(version)
                .to_string();
            for needle in ["SharedSecretTierRetired", "#2446", version] {
                assert!(err.contains(needle), "missing {needle:?} in: {err}");
            }
        }
    }
}
