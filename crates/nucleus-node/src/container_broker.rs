//! The host performs a container pod's credentialed calls (CB4A Model A, #2906).
//!
//! # What this closes
//!
//! The container driver used to copy `credentials.env` verbatim into the
//! container's environment, where `docker inspect`, `/proc/<pid>/environ` and
//! every child the agent spawned could read it, and into the `pod.yaml` the
//! container mounts. A Firecracker pod never held its credentials: its proxy
//! asks the host to make the call, and the host decides, fetches or mints the
//! credential, performs the call and streams the reply back.
//!
//! A container pod now takes the same path. The node binds the pod's broker on
//! a Unix socket in the pod directory it already bind-mounts into exactly that
//! container (`/data/pod/broker/`), through the same `start_broker_for_pod` the
//! vsock path uses: the same identity binding, policy, admitted upstreams,
//! credential store and decider (ADR 0007 G-1). The container's tool-proxy is
//! told the socket's path and the pod's broker capability, and nothing else;
//! the credential stays in the node's environment or is minted per exchange
//! (ADR 0010). A spec that still carries `credentials.env` is refused at create
//! by name ([`refuse_spec_credentials`]), never silently dropped (A-2, B-2).
//!
//! # Who may connect
//!
//! Only the container's init process, which is the node's tool-proxy (the node
//! makes it the entrypoint and creates the container with `init: false`). The
//! node learns its host pid from the runtime after start and arms the
//! listener's peer rule with it (`broker_transport::peer`); every other process
//! in the container, the workload included, is refused by the kernel's peer
//! credentials before a frame is read. The broker capability on every frame is
//! a second, independent check, as on Firecracker. The socket's directory is
//! `0700` and the node's: the tool-proxy reaches it as root in the container or
//! as the node's own uid, the two configurations in which the proxy can write
//! the pod directory at all.
//!
//! # What this does not close
//!
//! The container is not a Firecracker-equivalent boundary. Its egress is the
//! runtime's network (a container cannot take a structured network policy, so
//! a workload can still reach the internet directly, without a credential);
//! its identity is an unmeasured one (ADR 0016 D5); it shares the host kernel.
//! What is closed is the credential's exposure to the container.

use std::path::{Path, PathBuf};

use nucleus_spec::PodSpec;
use nucleus_spec::tier2_artifacts::{self, FirstShipped, GuestCapability, GuestSkew};
use uuid::Uuid;

use crate::broker_transport::BrokerListener;
use crate::broker_transport::peer::ArmContainerInit;
use crate::spec_posture::PostureRefused;
use crate::{ApiError, NodeState};

/// The broker's directory INSIDE the container: under the pod directory's
/// mount point, so the host sees the same socket under `<pod_dir>/broker/`.
pub(crate) const CONTAINER_BROKER_DIR: &str = "/data/pod/broker";
/// The directory's name in the pod directory.
const BROKER_DIR: &str = "broker";
/// The base the inventory's port is appended to (`guest_socket::listener_path`).
const SOCKET_BASE: &str = "broker";

/// The one `credentials.env` name a container spec may carry: the unmediated
/// node's task runner (`container_mediation::launch`), a command and not a
/// credential.
pub(crate) const TASK_RUNNER: &str = "NUCLEUS_TASK_CMD";

/// The capability a container pod's credentialed egress needs of its image.
const CAPABILITY: GuestCapability = GuestCapability::ContainerBrokerSocket;

/// Where the node binds a container pod's broker, before the inventory's port
/// is appended.
pub(crate) fn host_socket_base(pod_dir: &Path) -> PathBuf {
    pod_dir.join(BROKER_DIR).join(SOCKET_BASE)
}

/// The same socket, as the container's tool-proxy names it. Derived from the
/// same base and the same `listener_path` the host binds with, so the two
/// cannot disagree about the port suffix.
pub(crate) fn container_socket_path() -> PathBuf {
    crate::guest_socket::listener_path(
        &Path::new(CONTAINER_BROKER_DIR).join(SOCKET_BASE),
        nucleus_ifc_kernel::VsockListener::CredentialBroker,
    )
}

/// Evidence that a container pod's spec carries no credential value for the
/// driver to deliver. Its constructor is private (ADR 0007 C-1): the only way
/// to hold one is [`refuse_spec_credentials`] admitting the spec.
pub(crate) struct NoSpecCredentials(());

impl NoSpecCredentials {
    /// What the broker's rollout is checked against: holding one is the fact.
    pub(crate) fn witnessed(&self) -> bool {
        true
    }
}

/// The one decider for what a container pod's `credentials.env` may carry:
/// nothing but [`TASK_RUNNER`].
///
/// `spec_posture::admit` calls it at create, so the author learns before
/// anything runs; the spawn path calls it again for the witness the broker's
/// rollout is checked against.
///
/// # Errors
/// [`PostureRefused::ContainerCredentials`], naming every refused key.
pub(crate) fn refuse_spec_credentials(spec: &PodSpec) -> Result<NoSpecCredentials, PostureRefused> {
    let keys: Vec<&str> = spec
        .spec
        .credentials
        .iter()
        .flat_map(|c| c.env.keys())
        .map(String::as_str)
        .filter(|key| *key != TASK_RUNNER)
        .collect();
    if keys.is_empty() {
        Ok(NoSpecCredentials(()))
    } else {
        Err(PostureRefused::ContainerCredentials {
            keys: keys.join(", "),
        })
    }
}

/// Refuse, before anything is created, a pod with credentialed egress on an
/// image whose tool-proxy is known to lack the container broker socket.
///
/// `version` is the image's OCI version label. One the table cannot order, or
/// none, is "cannot tell" (A-1): the pod is launched, and an older proxy that
/// cannot use the socket refuses at startup by name
/// (`egress::reject_egress_without_a_broker`). A pod with no credentialed
/// egress never needs the socket, so it is not judged for it.
///
/// # Errors
/// The image's release lacks [`GuestCapability::ContainerBrokerSocket`].
pub(crate) fn admit_image(
    image: &str,
    version: Option<&str>,
    spec: &PodSpec,
) -> Result<(), ApiError> {
    if spec.spec.credentialed_egress.is_empty() {
        return Ok(());
    }
    let Some(version) = version else {
        return Ok(());
    };
    match tier2_artifacts::capability_skew(version, CAPABILITY) {
        Ok(()) | Err(GuestSkew::Unorderable { .. }) => Ok(()),
        Err(GuestSkew::Lacks { .. }) => {
            let when = match CAPABILITY.first_shipped() {
                FirstShipped::Release(v) => format!("first released in v{v}"),
                FirstShipped::NotYet => "in no published release yet".to_string(),
            };
            Err(ApiError::Driver(format!(
                "refusing to launch a container pod with credentialed_egress: image {image} is \
                 tool-proxy release {version}, which lacks {CAPABILITY:?} ({when}: {}). Use a \
                 tool-proxy image built from a tree that has it",
                CAPABILITY.change()
            )))
        }
    }
}

/// A container pod's broker, bound and serving, waiting to learn which process
/// is the container's init.
#[must_use = "a prepared broker that is never armed admits nobody"]
pub(crate) struct Prepared {
    listener: BrokerListener,
    arm: ArmContainerInit,
    env: Vec<String>,
}

impl Prepared {
    /// What the container's tool-proxy is told: the pod's broker capability and
    /// the socket's path inside the container. Never a credential.
    pub(crate) fn env(&self) -> &[String] {
        &self.env
    }

    /// Admit the container's init, by the host pid the runtime reported, and
    /// hand the listener to the pod that owns it.
    ///
    /// # Errors
    /// The arming window closed first: the broker would admit nobody.
    pub(crate) fn arm(self, pid: u32) -> Result<BrokerListener, ApiError> {
        self.arm.arm(pid).map_err(|refused| {
            ApiError::Driver(format!(
                "container pod's credential broker was not armed: {refused}"
            ))
        })?;
        Ok(self.listener)
    }
}

/// Bind and serve a container pod's broker, or `None` when the pod has nothing
/// to reach.
///
/// Served only for a mediated pod that was admitted an upstream: an unmediated
/// container has no proxy to ask, and a pod with no upstream has nothing it
/// could ask for, so neither gets a socket in its pod directory. A pod that
/// does have upstreams and cannot be served is refused here, by name, rather
/// than launched to fail on its first call.
///
/// # Errors
/// The spec carries a credential value; the node has no identity to bind the
/// listener to; the broker could not be started.
pub(crate) async fn prepare(
    state: &NodeState,
    spec: &PodSpec,
    pod_dir: &Path,
    id: Uuid,
) -> Result<Option<Prepared>, ApiError> {
    let never_delivered = refuse_spec_credentials(spec)?;
    if !state.container_mediation.runs_tool_proxy() || spec.spec.credentialed_egress.is_empty() {
        return Ok(None);
    }
    let identity = state
        .identity_manager
        .as_ref()
        .map(|manager| manager.pod_identity(id))
        .ok_or_else(|| {
            ApiError::Driver(format!(
                "pod {id} declares credentialed_egress, which the host performs over the pod's \
                 broker, and this node has no identity manager to bind that broker to"
            ))
        })?;
    let (serve, verify) = crate::broker_launch::BrokerCapability::mint(id);
    let (arm, init) = crate::broker_transport::peer::container_init(
        std::time::Instant::now() + crate::broker_transport::peer::ARM_WINDOW,
    );
    let listener = crate::broker_launch::start_broker_for_pod(crate::broker_launch::BrokerInputs {
        state,
        spec,
        route: crate::broker_launch::BrokerRoute::PodDir {
            pod_dir,
            init,
            never_delivered: &never_delivered,
        },
        registered: Some(&identity),
        id,
        capability: verify,
        egress: crate::egress_meter::EgressMeter::for_pod(
            spec,
            pod_dir.to_path_buf(),
            id,
            state.authority.egress_record_signer(),
        ),
    })
    .await?
    .ok_or_else(|| {
        ApiError::Driver(format!(
            "pod {id} declares credentialed_egress and its broker was not started (see the \
             node's log): a container pod has no other path to an upstream"
        ))
    })?;
    let env = vec![
        format!(
            "NUCLEUS_TOOL_PROXY_BROKER_SECRET={}",
            serve.into_served(id)?
        ),
        format!(
            "NUCLEUS_TOOL_PROXY_BROKER_SOCKET={}",
            container_socket_path().display()
        ),
    ];
    Ok(Some(Prepared { listener, arm, env }))
}

/// Arm a prepared broker with the container's init, as the runtime reports it
/// after start.
///
/// # Errors
/// The runtime could not be asked, or reported no pid: the broker would admit
/// nobody, and the pod could reach none of its upstreams.
pub(crate) async fn arm(
    prepared: Option<Prepared>,
    docker: &bollard::Docker,
    container_id: &str,
) -> Result<Option<BrokerListener>, ApiError> {
    let Some(prepared) = prepared else {
        return Ok(None);
    };
    let inspected = docker
        .inspect_container(
            container_id,
            None::<bollard::query_parameters::InspectContainerOptions>,
        )
        .await
        .map_err(|e| ApiError::Driver(format!("inspect container {container_id}: {e}")))?;
    let pid = inspected
        .state
        .and_then(|state| state.pid)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(|| {
            ApiError::Driver(format!(
                "the container runtime reported no init pid for {container_id}, so its credential \
                 broker could admit no peer"
            ))
        })?;
    prepared.arm(pid).map(Some)
}

#[cfg(test)]
#[path = "container_broker_tests.rs"]
mod tests;
