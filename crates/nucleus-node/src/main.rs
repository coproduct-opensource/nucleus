use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Extension, State};
use axum::response::Response as AxumResponse;
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use clap::Parser;
use driver::DriverKind;
use nucleus_client::drand::{DrandConfig, DrandFailMode};
#[cfg(target_os = "linux")]
use nucleus_spec::NetworkSpec;
use nucleus_spec::PodSpec;
use nucleus_spec::dlc_admission::DlcProvisioning;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
#[cfg(any(feature = "local-driver", target_os = "linux"))]
use tokio::process::Command;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response as GrpcResponse, Status};
use tracing::{error, info};
use uuid::Uuid;

mod api_error;
mod art12_collector;
mod audit_sink;
mod auth;
mod clearing_receipt_collector;
mod firecracker_api;
mod firecracker_config;
mod grpc_tls;
mod guest_diagnosis;
mod http_serve;
mod identity;
mod image_identity;
mod jail_placement;
mod keys;
mod lockdown;
mod mediation_receipt_collector;
mod node_capacity;
mod pod_api;
mod pod_authority;
mod pod_boot_identity;
mod pod_caller_identity;
mod pod_receipt;
mod pod_resources;
mod pod_view;
mod production_confinement;
mod rootfs_source;
mod sealed_rootfs;
mod spec_posture;
mod spend_receipt_collector;
mod workload_api_protocol;
mod workload_api_vsock;
mod workload_artifacts;
mod workload_result;
use api_error::ApiError;
use container_mediation::container_driver_reject_unsupported_network_policy;
#[cfg(feature = "local-driver")]
mod bare_tier_opt_in;
mod boot_trace;
#[cfg(feature = "local-driver")]
use bare_tier_opt_in::{local_driver_opt_in, unsandboxed_proxy_flag};
// Reached only from the Firecracker launch path, which is `cfg(target_os = "linux")`.
// On any other host every item here is genuinely dead, and CI builds release
// binaries with `RUSTFLAGS=-D warnings`, so the warning is an error that fails the
// macOS release job. Same pattern as `boot_trace`/`cgroup`.
mod broker;
mod broker_launch;
mod broker_perform;
mod broker_rollout;
mod broker_stream;
mod broker_transport;
mod cgroup;
mod container_mediation;
mod container_transport;
mod cred_split;
mod driver;
#[cfg(test)]
mod effect_footprint;
mod egress_meter;
mod envelope_frame;
mod federated_credential;
mod federation_ingress;
mod guest_socket;
mod host_decide;
mod host_paths;
mod lifecycle;
mod net;
mod posture;
mod session_mint;
mod signed_proxy;
mod snapshot;
mod snapshot_restore;
mod snapshot_store;
mod snapshot_vmm;
#[cfg(test)]
mod spiffe_walk;
mod trust_gate;
mod upstreams;
mod vsock_bridge;

#[cfg(target_os = "linux")]
use nucleus_microvm_host::probe as host_requirements;
pub use nucleus_proto::nucleus_node as proto;

use proto::node_service_server::{NodeService, NodeServiceServer};

#[derive(Parser, Debug)]
#[command(name = "nucleus-node", mut_args = |a| a.hide_env_values(true))]
#[command(about = "Node daemon (kubelet analogue) for nucleus pods")]
struct Args {
    /// Listen address for the node HTTP API.
    #[arg(long, env = "NUCLEUS_NODE_LISTEN", default_value = "127.0.0.1:8080")]
    listen: String,
    /// Optional listen address for the gRPC API.
    #[arg(long, env = "NUCLEUS_NODE_GRPC_LISTEN")]
    grpc_listen: Option<String>,
    /// State directory for pod metadata/logs.
    #[arg(long, env = "NUCLEUS_NODE_STATE_DIR", default_value = "./nucleus-node")]
    state_dir: PathBuf,
    #[command(flatten)]
    authority: pod_authority::AuthorityArgs,
    #[command(flatten)]
    host_paths: host_paths::HostPathArgs,
    #[command(flatten)]
    audit_sinks: audit_sink::AuditSinkArgs,
    #[command(flatten)]
    pod_ceilings: pod_resources::PodCeilingArgs,
    #[command(flatten)]
    node_capacity: node_capacity::CapacityArgs,
    /// Driver backend.
    #[arg(
        long,
        env = "NUCLEUS_NODE_DRIVER",
        value_enum,
        default_value = "firecracker"
    )]
    driver: DriverKind,
    /// Allow the local driver (no VM isolation).
    #[cfg(feature = "local-driver")]
    #[arg(long, env = "NUCLEUS_ALLOW_LOCAL_DRIVER", default_value_t = false)]
    allow_local_driver: bool,
    /// Path to the nucleus-tool-proxy binary (local driver).
    #[cfg(feature = "local-driver")]
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_PATH",
        default_value = "nucleus-tool-proxy"
    )]
    tool_proxy_path: PathBuf,
    /// Path to firecracker binary (firecracker driver).
    #[arg(long, env = "NUCLEUS_FIRECRACKER_PATH", default_value = "firecracker")]
    firecracker_path: PathBuf,
    /// Build the microVM over Firecracker's API socket instead of a config file.
    ///
    /// Off by default: this is the path a snapshot needs (a config file boots on parse, leaving
    /// no moment to pause), and it is opt-in until it has run on real hardware as long as the
    /// config-file path has.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_API_BOOT", default_value_t = false)]
    firecracker_api_boot: bool,
    /// Run Firecracker inside a new network namespace (Linux only).
    #[arg(long, env = "NUCLEUS_FIRECRACKER_NETNS", default_value_t = true)]
    firecracker_netns: bool,
    /// Fail closed if netns iptables drift from the baseline.
    #[arg(
        long,
        env = "NUCLEUS_FIRECRACKER_NETNS_DRIFT_CHECK",
        default_value_t = true
    )]
    firecracker_netns_drift_check: bool,
    /// Interval (seconds) for netns iptables drift checks.
    #[arg(
        long,
        env = "NUCLEUS_FIRECRACKER_NETNS_DRIFT_INTERVAL_SECS",
        default_value_t = 10
    )]
    firecracker_netns_drift_interval_secs: u64,
    /// Max concurrent Firecracker pods (0 = unlimited).
    #[arg(long, env = "NUCLEUS_FIRECRACKER_MAX_PODS", default_value_t = 15)]
    firecracker_max_pods: usize,

    /// Require verified-active seccomp on launched Firecracker VMs (most-paranoid #3).
    ///
    /// Fail-closed default (`true`): if the launched VMM's seccomp filter cannot
    /// be confirmed active, the pod launch is aborted rather than proceeding
    /// unconfined. Set to `false` ONLY in environments where `/proc/<pid>/status`
    /// is legitimately unreadable and the risk is accepted (logs an UNSAFE warning).
    #[arg(
        long,
        env = "NUCLEUS_FIRECRACKER_SECCOMP_VERIFY",
        default_value_t = true
    )]
    firecracker_seccomp_verify: bool,

    /// Launch Firecracker through the jailer (chroot + pivot_root + dropped
    /// privileges + cgroups established BEFORE exec).
    ///
    /// DEFAULT ON, because the alternative it replaces has a real hole: spawning
    /// Firecracker directly with `--config-file` boots the VM immediately and
    /// `apply_cgroup` then runs against the resulting pid, so the guest executes
    /// for a window before its cpu/memory limits exist. The jailer cannot be late
    /// — it writes the cgroup and drops privileges before `exec()`.
    ///
    /// Production builds reject false. With the development-only local-driver
    /// feature, set false to fall back to the direct-spawn path. That is an OPERATIONAL
    /// off-switch for an environment where the jailer is unavailable or the jail
    /// cannot be co-located with the images (see `--jailer-chroot-base`), not a
    /// recommendation: turning it off reopens the pre-exec cgroup window.
    #[arg(long, env = "NUCLEUS_FIRECRACKER_JAILER", default_value_t = true, action = clap::ArgAction::Set, value_parser = production_confinement::parse_jailer_enabled)]
    firecracker_jailer: bool,
    /// Path to the Firecracker `jailer` binary.
    #[arg(long, env = "NUCLEUS_JAILER_PATH", default_value = "jailer")]
    jailer_path: PathBuf,
    /// Base directory under which the jailer builds `<base>/<exec>/<id>/root`.
    ///
    /// MUST be on the same filesystem as any WRITABLE drive in the pod image.
    /// Writable resources are hard-linked into the jail so the guest's writes land
    /// at the caller's path exactly as they do on the non-jailed path; a
    /// cross-filesystem jail makes that impossible and fails the launch rather
    /// than silently copying and discarding those writes.
    #[arg(
        long,
        env = "NUCLEUS_JAILER_CHROOT_BASE",
        default_value = "/srv/jailer"
    )]
    jailer_chroot_base: PathBuf,
    /// Unprivileged uid the jailed VMM drops to. `nucleus-hostctl seed` reads the same variable,
    /// so a disk it seeds is handed to this uid.
    #[arg(long, env = nucleus_microvm_host::jail_user::UID_ENV, default_value = "123")]
    jailer_uid: production_confinement::NonRootUid,
    /// Unprivileged gid the jailed VMM drops to.
    #[arg(long, env = nucleus_microvm_host::jail_user::GID_ENV, default_value_t = 100)]
    jailer_gid: u32,
    /// Seal each pinned read-only rootfs once per node life and boot every pod from a reflink
    /// clone of it, instead of reading the whole file before each boot (`sealed_rootfs.rs`).
    /// Needs reflink on the jailer chroot base's filesystem; without it pods are read as before.
    #[arg(long, env = "NUCLEUS_SEAL_PINNED_ROOTFS")]
    seal_pinned_rootfs: bool,

    // Container driver configuration
    /// Container image every container pod runs, and in mediated mode the image whose
    /// `nucleus-tool-proxy` mediates it. Node-owned: a spec cannot choose it (#3133).
    #[arg(
        long,
        env = "NUCLEUS_CONTAINER_IMAGE",
        default_value = "nucleus-tool-proxy:latest"
    )]
    container_image: String,
    /// Whether container pods run under the tool-proxy. `unmediated` runs the image's entrypoint
    /// with no reference monitor; it is an operator opt-in, never a spec choice (#3133).
    #[arg(
        long,
        env = "NUCLEUS_CONTAINER_MEDIATION",
        value_enum,
        default_value = "tool-proxy"
    )]
    container_mediation: container_mediation::ContainerMediation,
    /// Network mode for containers ("none", "bridge", or a custom network name).
    #[arg(long, env = "NUCLEUS_CONTAINER_NETWORK", default_value = "none")]
    container_network: String,
    /// Reach container pods' proxies over a peer-verified Unix socket, no shared secret (#2446). Opt-in.
    #[arg(long, env = "NUCLEUS_CONTAINER_PROXY_UNIX", default_value_t = false)]
    container_proxy_unix: bool,
    /// Max concurrent container pods (0 = unlimited).
    #[arg(long, env = "NUCLEUS_CONTAINER_MAX_PODS", default_value_t = 10)]
    container_max_pods: usize,

    /// Shared secret for signing tool-proxy requests from the host.
    #[arg(long, env = "NUCLEUS_NODE_PROXY_AUTH_SECRET")]
    proxy_auth_secret: String,
    /// Secret for signing approval requests (separate from tool auth).
    #[arg(long, env = "NUCLEUS_NODE_PROXY_APPROVAL_SECRET")]
    proxy_approval_secret: String,
    /// Default actor to use when signing proxy requests.
    #[arg(long, env = "NUCLEUS_NODE_PROXY_ACTOR", default_value = "nucleus-node")]
    proxy_actor: String,
    /// Trusted proof-carrying postures: `<posture>@<hexdigest>` entries a trusted
    /// builder has proven, comma/space/newline separated. A pod carrying a
    /// `dlc_posture` label is admitted only when its claimed artifact digest
    /// matches the rootfs the node measures AND `(posture, digest)` appears here.
    /// Empty (the default) trusts nothing, so every posture claim is refused
    /// fail-closed; pods carrying no claim are unaffected. See `posture.rs`.
    #[arg(long, env = "NUCLEUS_NODE_TRUSTED_POSTURES", default_value = "")]
    trusted_postures: String,
    /// SPIFFE trust domain for workload identity.
    #[arg(
        long,
        env = "NUCLEUS_IDENTITY_TRUST_DOMAIN",
        default_value = "nucleus.local"
    )]
    identity_trust_domain: String,
    /// Certificate TTL in seconds (default: 1 hour).
    #[arg(long, env = "NUCLEUS_IDENTITY_CERT_TTL_SECS", default_value_t = 3600)]
    identity_cert_ttl_secs: u64,
    /// Unix socket path for the Workload API server.
    #[arg(long, env = "NUCLEUS_IDENTITY_WORKLOAD_API_SOCKET")]
    identity_workload_api_socket: Option<PathBuf>,
    /// Vsock port for guest-to-host Workload API connections.
    #[arg(
        long,
        env = "NUCLEUS_IDENTITY_WORKLOAD_API_VSOCK_PORT",
        default_value_t = 15012
    )]
    identity_workload_api_vsock_port: u32,
    /// Serve the per-pod credential broker socket.
    ///
    /// Off by default; listen mode preserves legacy credential delivery.
    #[arg(long, env = "NUCLEUS_NODE_BROKER_LISTEN", default_value_t = false)]
    broker_listen: bool,
    /// Withhold spec credentials; requires Firecracker and compatible guest-init.
    #[arg(long, env = "NUCLEUS_NODE_BROKER_ENFORCING", default_value_t = false)]
    broker_enforcing: bool,
    /// Vsock port the guest uses to reach the credential broker.
    #[arg(long, env = "NUCLEUS_NODE_BROKER_VSOCK_PORT", default_value_t = 15013)]
    broker_vsock_port: u32,
    /// Largest request body one streamed credentialed-egress call may upload
    /// (#2696 P4). Every byte is also charged to the pod's egress ceiling.
    #[arg(
        long,
        env = "NUCLEUS_NODE_EGRESS_STREAM_MAX_REQUEST_BYTES",
        default_value_t = broker_stream::DEFAULT_MAX_STREAM_REQUEST_BYTES
    )]
    egress_stream_max_request_bytes: u64,
    /// Largest reply one streamed credentialed-egress call may relay back to
    /// the guest. A longer reply is cut and the guest told why.
    #[arg(
        long,
        env = "NUCLEUS_NODE_EGRESS_STREAM_MAX_RESPONSE_BYTES",
        default_value_t = broker_stream::DEFAULT_MAX_STREAM_RESPONSE_BYTES
    )]
    egress_stream_max_response_bytes: u64,
    /// Enable drand anchoring for approval signatures.
    #[arg(long, env = "NUCLEUS_NODE_DRAND_ENABLED", default_value_t = true)]
    drand_enabled: bool,
    /// Drand API endpoint URL.
    #[arg(
        long,
        env = "NUCLEUS_NODE_DRAND_URL",
        default_value = "https://api.drand.sh/public/latest"
    )]
    drand_url: String,
    /// Number of previous drand rounds to accept (tolerance for network latency).
    #[arg(long, env = "NUCLEUS_NODE_DRAND_TOLERANCE", default_value_t = 1)]
    drand_tolerance: u64,
    /// Drand failure mode: strict (reject) or cached (use stale for up to 60s).
    #[arg(long, env = "NUCLEUS_NODE_DRAND_FAIL_MODE", default_value = "strict")]
    drand_fail_mode: String,

    // gRPC TLS/mTLS configuration
    /// Path to server certificate PEM file for gRPC TLS.
    #[arg(long, env = "NUCLEUS_NODE_GRPC_TLS_CERT")]
    grpc_tls_cert: Option<PathBuf>,
    /// Path to server private key PEM file for gRPC TLS.
    #[arg(long, env = "NUCLEUS_NODE_GRPC_TLS_KEY")]
    grpc_tls_key: Option<PathBuf>,
    /// Path to CA certificate PEM for client verification (enables mTLS).
    /// When set, clients must present valid certificates signed by this CA.
    #[arg(long, env = "NUCLEUS_NODE_GRPC_TLS_CA")]
    grpc_tls_ca: Option<PathBuf>,
}

#[derive(Clone)]
struct NodeState {
    pods: pod_api::PodRegistry,
    state_dir: PathBuf,
    host_roots: host_paths::Roots,
    /// The most memory, vCPUs and huge pages one pod may ask for (#3130).
    pod_ceilings: pod_resources::PodCeilings,
    node_capacity: node_capacity::Capacity,
    driver: DriverKind,
    #[cfg(feature = "local-driver")]
    tool_proxy_path: PathBuf,
    /// Whether this node's local driver deliberately runs its tool-proxies
    /// on the bare host tier, decided once at startup by
    /// [`local_driver_opt_in`]. It is what puts `--unsandboxed` on a proxy's
    /// command line, so the flag traces to the operator's
    /// `--driver local --allow-local-driver` and to nothing else.
    #[cfg(feature = "local-driver")]
    local_driver_opt_in: nucleus::UnsandboxedOptIn,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_pool: Option<Arc<Semaphore>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_api_boot: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_netns: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_netns_drift_check: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_netns_drift_interval: Duration,
    /// Fail-closed seccomp verification on Firecracker launch (most-paranoid #3).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_seccomp_verify: bool,
    /// Launch via the jailer so cgroups/chroot/privilege-drop precede exec.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_jailer: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    jailer_path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    jailer_chroot_base: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    jailer_uid: production_confinement::NonRootUid,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    jailer_gid: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    sealed_rootfs: Option<Arc<sealed_rootfs::SealedRootfs>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    network_allocator: Arc<net::NetworkAllocator>,
    /// Node HTTP listen address (for orchestrator pod management back-references).
    #[cfg(feature = "local-driver")]
    listen_addr: String,
    proxy_auth_secret: String,
    /// Node-only secret for deriving per-pod caller-identity tokens.
    ///
    /// Fresh per process, never persisted, never shared with a pod — which is
    /// the whole point: a pod able to derive tokens could claim to be any other
    /// pod. See `pod_caller_identity`.
    caller_secret: std::sync::Arc<[u8; 32]>,
    proxy_approval_secret: String,
    /// Ed25519 key whose signatures Firecracker guests accept on
    /// `/v1/approve`. The PRIVATE half never leaves the node; guests get the
    /// public half as `nucleus.approval_pubkeys`. Persisted in `state_dir` so
    /// pods launched before a node restart can still be approved.
    // Reached only from the Firecracker spawn path, which is `cfg(target_os = "linux")`.
    // On other hosts it is genuinely dead, and CI builds release binaries with
    // `RUSTFLAGS=-D warnings` (setup-rust-toolchain's default), so the warning is an
    // error that fails the macOS release job. Same pattern as `boot_trace`/`cgroup`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    approval_signer: std::sync::Arc<ed25519_dalek::SigningKey>,
    proxy_actor: Option<String>,
    /// Operator-configured registry of proof-carrying postures a trusted builder
    /// has proven. Consulted fail-closed at pod admission (`posture.rs`).
    trusted_postures: posture::PostureRegistry,
    /// The operator's audit sinks (`--audit-sinks`): the only destinations a pod's audit log is
    /// written to with the node's credentials (#3131). Read at admission (`spec_posture::admit`).
    audit_sinks: Arc<audit_sink::AuditSinks>,
    /// Mints each pod's uploader a credential limited to its resolved sink (#3160). `None`: every
    /// audit sink is refused at create, by name; the node's own key is never the fallback.
    audit_minter: Option<Arc<dyn audit_sink::credentials::ScopedCredentialMinter>>,
    /// Drand configuration for anchoring approval signatures.
    drand_config: Option<DrandConfig>,
    /// Identity manager for SPIFFE certificates (experimental, not yet wired to Firecracker).
    #[allow(dead_code)]
    identity_manager: Option<identity::IdentityManager>,
    /// Vsock port for guest-to-host Workload API connections.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    identity_vsock_port: u32,
    /// Whether pods should be served a credential broker socket.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    broker_listen: bool,
    /// Whether the broker should also withhold credentials from the guest spec.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    broker_enforcing: bool,
    /// Vsock port the guest uses to reach the credential broker.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    broker_vsock_port: u32,
    /// Per-call bounds on a streamed credentialed-egress call.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    egress_stream_limits: broker_stream::StreamLimits,
    /// Authorization policy for SPIFFE-based access control.
    authz_policy: auth::AuthorizationPolicy,
    // Container driver state
    /// The image every container pod runs (`--container-image`).
    container_image: String,
    /// Whether container pods run under the tool-proxy (`--container-mediation`).
    container_mediation: container_mediation::ContainerMediation,
    /// Default network mode for containers.
    container_network: String,
    container_proxy_unix: bool,
    /// Semaphore limiting concurrent container pods.
    container_pool: Option<Arc<Semaphore>>,
    /// Docker client (initialized at startup when container driver is active).
    docker: Option<Arc<bollard::Docker>>,
    /// Execution-receipt reporting config: the trust API base URL, the
    /// executor identity and the role-separated keys that sign receipts.
    /// Nothing here scopes a sandbox — the reputation lookup that once did was
    /// deleted in #2512.
    trust_gate: trust_gate::TrustGateConfig,
    /// Per-pod certificate authority: proof of caller authority at
    /// pod-create, budget conserved across spawn (pod_authority.rs).
    authority: Arc<pod_authority::PodAuthority>,
    /// Epochs for the pods' shadow decision channels (#2702, P8): one counter
    /// for the whole node, so no two channels' ledgers share an epoch.
    #[cfg(target_os = "linux")]
    decision_epochs: Arc<host_decide::EpochSource>,
    /// HTTP client for trust API calls.
    http_client: reqwest::Client,
    /// Broadcast channel for streaming lockdown commands to connected tool-proxies.
    lockdown_tx: tokio::sync::broadcast::Sender<proto::LockdownCommand>,
    /// The lockdowns in force (`lockdown::Active`).
    lockdowns: Arc<std::sync::Mutex<lockdown::Active>>,
}

#[derive(Debug)]
struct PodHandle {
    id: Uuid,
    spec: PodSpec,
    created_at: u64,
    log_path: PathBuf,
    proxy_addr: Mutex<Option<String>>,
    driver_state: DriverState,
    /// Parent pod ID for orchestrator-spawned sub-pods.
    /// When set, this pod is cancelled if the parent exits.
    parent_pod_id: Option<Uuid>,
    /// The verified proof-carrying posture stamp (`<posture>:verified`), set when
    /// the pod carried a `dlc_posture` claim that passed admission. `None` when
    /// the pod carried no claim. Surfaced in `PodInfo` so an operator can see the
    /// claim was checked, not merely present. See `posture.rs`.
    posture_stamp: Option<String>,
    /// Root identity of the certificate this node issued the pod, recorded at
    /// creation and never re-derived: its trust domain is the pod's tenant
    /// (ADR 0001; `auth::CallerScope::Tenant`). `None` only for fixtures.
    owner: Option<String>,
    capacity: Mutex<Option<node_capacity::Reservation>>,
}

/// Whether a teardown has to stop the pod's process, or it already exited.
///
/// Cancel and exit cleanup used to be two copies of each driver's teardown, and they
/// drifted: a local pod that exited on its own kept its signed proxy running, and a
/// cancelled container lost its exit state. Now each driver has ONE teardown, and
/// this is the only thing that differs between the two paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Kill,
    AlreadyExited,
}

#[derive(Debug)]
enum DriverState {
    #[cfg(feature = "local-driver")]
    Local(Box<LocalPod>),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Firecracker(Box<FirecrackerPod>),
    Container(Box<ContainerPod>),
}

#[cfg(feature = "local-driver")]
#[derive(Debug)]
struct LocalPod {
    child: Mutex<tokio::process::Child>,
    signed_proxy: Mutex<Option<signed_proxy::SignedProxy>>,
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct FirecrackerPod {
    direct_cgroup: Mutex<Option<cgroup::Placement>>,
    /// The host-owned pod dir: where teardown preserves the exit report and where
    /// the node's record of the pod's mediation key lives (`pod_receipt`).
    pod_dir: PathBuf,
    child: Arc<Mutex<tokio::process::Child>>,
    bridge: Mutex<Option<vsock_bridge::VsockBridge>>,
    signed_proxy: Mutex<Option<signed_proxy::SignedProxy>>,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    net_plan: Mutex<Option<net::NetPlan>>,
    netns: Mutex<Option<String>>,
    dns_proxy: Mutex<Option<net::DnsProxyState>>,
    drift_monitor: Mutex<Option<JoinHandle<()>>>,
    drift_stop: Arc<AtomicBool>,
    /// Reference to network allocator for releasing indices on cleanup
    network_allocator: Arc<net::NetworkAllocator>,
    /// SPIFFE identity for this pod (if identity management is enabled)
    #[allow(dead_code)]
    identity: Option<nucleus_identity::Identity>,
    /// Reference to identity manager for cleanup
    identity_manager: Option<identity::IdentityManager>,
    /// The key this pod was REGISTERED under, carried rather than re-derived.
    ///
    /// Teardown used to call `unregister_pod(&identity.to_spiffe_uri())` while
    /// registration used `register_pod(id.to_string(), ..)`. Those are different
    /// strings, so `HashMap::remove` never matched and no pod was EVER removed
    /// from the identity registry. Two derivations of one key is the bug; there
    /// is now one value, produced once and carried to the removal.
    identity_registry_key: Option<String>,
    /// Workload API vsock bridge for this pod
    workload_api_bridge: Mutex<Option<workload_api_vsock::WorkloadApiVsockBridge>>,
    /// The credential broker listening for this pod, when the rollout serves one.
    ///
    /// Owned rather than spawned-and-forgotten: the socket path is derived from
    /// the pod's vsock path, so a listener outliving its pod would still be bound
    /// to the dead pod's identity when a later pod reused that path.
    broker: Mutex<Option<broker_transport::BrokerListener>>,
    /// The shadow decision service for this pod (#2702, P8), owned for the same
    /// reason the broker is: its socket path is derived from the pod's vsock path.
    decide: Mutex<Option<host_decide::DecideListener>>,
    /// The jail this pod runs in, when launched via the jailer. Held so teardown
    /// can remove it — a jail left behind leaks disk and, because writable drives
    /// are hard-linked in, keeps a reference to the caller's image alive.
    jail: Mutex<Option<firecracker_config::JailLayout>>,
    /// What a base snapshot of this pod would have to name — see `snapshot_store::SnapshotInputs`.
    snapshot: Option<snapshot_store::SnapshotInputs>,
}

/// Container-based pod execution via Docker API (Colima, Docker Desktop, Podman).
///
/// The image and whether the tool-proxy mediates the pod are node configuration
/// (`--container-image`, `--container-mediation`); see `container_mediation` (#3133).
#[derive(Debug)]
struct ContainerPod {
    container_id: String,
    docker: bollard::Docker,
    /// Only present when the node mediates its container pods.
    signed_proxy: Mutex<Option<signed_proxy::SignedProxy>>,
    /// Semaphore permit for concurrency limiting.
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    /// Cached exit state — set before container removal so status() works after cleanup.
    cached_exit: Mutex<Option<PodState>>,
}

pub(crate) use pod_view::{CreatePodRequest, CreatePodResponse, PodInfo, PodState};

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    // Install the ring crypto provider for rustls (must be done before any TLS operations)
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| ApiError::Driver("failed to install rustls crypto provider".to_string()))?;

    let _tracing_guard = boot_trace::init_tracing().map_err(ApiError::Driver)?;

    let args = Args::parse();
    broker_rollout::require_supported_driver(args.broker_enforcing, &args.driver)?;
    tokio::fs::create_dir_all(&args.state_dir).await?;
    #[cfg(feature = "local-driver")]
    if matches!(args.driver, DriverKind::Local) && !args.allow_local_driver {
        return Err(ApiError::Driver(
            "local driver disabled; pass --allow-local-driver to run without VM isolation"
                .to_string(),
        ));
    }
    if args.proxy_auth_secret.trim().is_empty() {
        return Err(ApiError::Driver(
            "proxy auth secret is required (set NUCLEUS_NODE_PROXY_AUTH_SECRET)".to_string(),
        ));
    }
    if args.proxy_approval_secret.trim().is_empty() {
        return Err(ApiError::Driver(
            "proxy approval secret required (set NUCLEUS_NODE_PROXY_APPROVAL_SECRET)".to_string(),
        ));
    }

    // Initialize identity manager. Unconditional (Move B) — HTTP and gRPC
    // both require mTLS now, so an identity manager is not optional
    // infrastructure any more; it's what the node presents ITS OWN identity
    // with. `--identity-workload-api-socket` used to gate this construction,
    // but the socket it names was never opened either way (#2197) — the flag
    // is accepted for compatibility and kept for documentation purposes, not
    // consulted here any more.
    let identity_manager = {
        let cert_ttl = Duration::from_secs(args.identity_cert_ttl_secs);
        // `new_with_persistent_ca`, not `new`: the node is long-lived, and
        // `new` mints a fresh in-memory root on every call. A node that used
        // `new` here would silently invalidate every SVID it had issued on
        // its own next restart — the CA root is the trust anchor mTLS peers
        // verify against, so its identity changing is not cosmetic. See
        // `SelfSignedCa::load_or_create` for the persistence contract.
        let manager = identity::IdentityManager::new_with_persistent_ca(
            &args.identity_trust_domain,
            cert_ttl,
            &args.state_dir.join("ca"),
        )
        .map_err(|e| ApiError::Driver(format!("failed to create identity manager: {e}")))?
        .with_mediation_binding_dir(args.state_dir.join("pods"));

        // Repopulate the registry from the pods already on disk. Without this a
        // node restart orphaned every running pod from its own identity (#1641):
        // the registry is in-memory and nothing refilled it, so a live pod could
        // no longer resolve the SVID it had been issued.
        //
        // Derived from `state_dir/pods/*/pod.yaml` rather than from a journal, so
        // it cannot disagree with the directory that already says which pods
        // exist. See `rebuild_registry_from_disk`.
        let restored = manager.rebuild_registry_from_disk(&args.state_dir).await;
        if restored > 0 {
            info!(
                "restored {restored} pod identities from {}",
                args.state_dir.display()
            );
        }

        // Refresh still runs: it maintains the certs the vsock bridge serves.
        manager.start_refresh_loop();

        info!(
            "identity manager initialized with trust domain '{}'",
            args.identity_trust_domain
        );
        Some(manager)
    };

    // Build drand config if enabled
    let drand_config = if args.drand_enabled {
        let fail_mode = match args.drand_fail_mode.to_lowercase().as_str() {
            "cached" => DrandFailMode::Cached,
            _ => DrandFailMode::Strict, // "degraded" is no longer supported
        };
        Some(DrandConfig {
            enabled: true,
            api_url: args.drand_url.clone(),
            round_tolerance: args.drand_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: None, // Use defaults from drand module
            public_key: None, // Use defaults from drand module
        })
    } else {
        None
    };

    // Initialize Docker client if container driver is selected
    let docker = if matches!(args.driver, DriverKind::Container) {
        let docker = bollard::Docker::connect_with_local_defaults()
            .map_err(|e| ApiError::Driver(format!("failed to connect to Docker: {e}")))?;
        match docker.version().await {
            Ok(v) => {
                info!(
                    api_version = ?v.api_version,
                    "Docker client connected (container driver)"
                );
            }
            Err(e) => {
                return Err(ApiError::Driver(format!(
                    "Docker not reachable (is Colima running?): {e}"
                )));
            }
        }
        if !args.container_mediation.runs_tool_proxy() {
            tracing::warn!(
                "--container-mediation=unmediated: container pods run with NO reference monitor"
            );
        }
        Some(Arc::new(docker))
    } else {
        None
    };

    let container_pool =
        if matches!(args.driver, DriverKind::Container) && args.container_max_pods > 0 {
            Some(Arc::new(Semaphore::new(args.container_max_pods)))
        } else {
            None
        };

    let authority = pod_authority::PodAuthority::from_args(&args).map_err(ApiError::Driver)?;

    // A zero bound is refused at start-up, not discovered as a refusal of
    // every streamed call later (ADR 0007 B).
    let egress_stream_limits = broker_stream::StreamLimits::new(
        args.egress_stream_max_request_bytes,
        args.egress_stream_max_response_bytes,
    )
    .map_err(ApiError::Driver)?;

    let state = NodeState {
        pods: Arc::new(Mutex::new(HashMap::new())),
        state_dir: args.state_dir.clone(),
        host_roots: args.host_paths.ensure(&args.state_dir)?,
        pod_ceilings: args.pod_ceilings.ceilings(),
        node_capacity: args.node_capacity.build()?,
        driver: args.driver.clone(),
        #[cfg(feature = "local-driver")]
        tool_proxy_path: args.tool_proxy_path.clone(),
        #[cfg(feature = "local-driver")]
        local_driver_opt_in: local_driver_opt_in(&args.driver, args.allow_local_driver),
        firecracker_path: args.firecracker_path.clone(),
        firecracker_pool: build_firecracker_pool(&args),
        firecracker_api_boot: args.firecracker_api_boot,
        firecracker_netns: args.firecracker_netns,
        firecracker_netns_drift_check: args.firecracker_netns_drift_check,
        firecracker_netns_drift_interval: Duration::from_secs(
            args.firecracker_netns_drift_interval_secs,
        ),
        firecracker_seccomp_verify: args.firecracker_seccomp_verify,
        firecracker_jailer: args.firecracker_jailer,
        jailer_path: args.jailer_path.clone(),
        jailer_chroot_base: args.jailer_chroot_base.clone(),
        jailer_uid: args.jailer_uid,
        jailer_gid: args.jailer_gid,
        sealed_rootfs: sealed_rootfs::from_flags(
            args.seal_pinned_rootfs && args.firecracker_jailer,
            &args.jailer_chroot_base,
        ),
        network_allocator: Arc::new(net::NetworkAllocator::new()),
        #[cfg(feature = "local-driver")]
        listen_addr: args.listen.clone(),
        proxy_auth_secret: args.proxy_auth_secret.clone(),
        // A NODE-ONLY secret, fresh per process and never persisted or shared.
        //
        // Not `auth_secret`: every proxy holds that one, so deriving caller
        // tokens from it would let any pod compute any other pod's token — the
        // mechanism would authenticate nothing. Not configured, either: there is
        // no operator burden and nothing to leak at rest, and a node restart
        // simply invalidates tokens for pods that cannot outlive the node.
        caller_secret: {
            use rand_core::RngCore;
            let mut k = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut k);
            std::sync::Arc::new(k)
        },
        proxy_approval_secret: args.proxy_approval_secret.clone(),
        approval_signer: std::sync::Arc::new(keys::load_or_create_approval_signing_key(
            &args.state_dir,
        )),
        proxy_actor: Some(args.proxy_actor.clone()).filter(|actor| !actor.trim().is_empty()),
        trusted_postures: posture::PostureRegistry::from_operator_str(&args.trusted_postures),
        audit_sinks: Arc::new(args.audit_sinks.load().map_err(ApiError::Driver)?),
        // No minter ships in this crate: a scoped credential is a provider's protocol, and an
        // embedding that runs audit sinks supplies one. Until then a spec that names a sink is
        // refused at create rather than given the node's own key.
        audit_minter: None,
        drand_config,
        identity_manager,
        identity_vsock_port: args.identity_workload_api_vsock_port,
        broker_listen: args.broker_listen,
        broker_enforcing: args.broker_enforcing,
        broker_vsock_port: args.broker_vsock_port,
        egress_stream_limits,
        authz_policy: auth::AuthorizationPolicy::new(&args.identity_trust_domain)
            .with_operator_identity(authority.root_minter())
            .with_federated_trust_domains(authority.caller_bindings().trust_domains()),
        container_image: args.container_image.clone(),
        container_mediation: args.container_mediation,
        container_network: args.container_network.clone(),
        container_proxy_unix: args.container_proxy_unix,
        container_pool,
        docker,
        trust_gate: trust_gate::TrustGateConfig::from_env(&args.state_dir),
        authority: Arc::new(authority),
        #[cfg(target_os = "linux")]
        decision_epochs: Arc::new(host_decide::EpochSource::seeded()),
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default(),
        lockdown_tx: tokio::sync::broadcast::channel::<proto::LockdownCommand>(16).0,
        lockdowns: Arc::default(),
    };

    // Release what the previous life of this node acquired, BEFORE serving anything: a pod
    // launched first would own a jail this then deletes. Why startup and not a timer is the
    // argument on `reclaim_orphaned_jails` itself.
    #[cfg(target_os = "linux")]
    if args.firecracker_jailer {
        let n = firecracker_config::reclaim_orphaned_jails(
            &args.jailer_chroot_base,
            &args.firecracker_path,
        )
        .len();
        if n > 0 {
            info!(count = n, "reclaimed jail(s) stranded by a previous node");
        }
    }

    // Refuse, by name, an installed artifact the jailed VMM cannot read or could rewrite, rather
    // than chowning it at the first pod: it is hard-linked into every jail (#3152).
    #[cfg(target_os = "linux")]
    if args.firecracker_jailer && matches!(&args.driver, DriverKind::Firecracker) {
        let who = jail_placement::JailUser {
            uid: args.jailer_uid.get(),
            gid: args.jailer_gid,
        };
        let checked =
            jail_placement::check_installed_artifacts(&args.host_paths.artifacts_root, who)
                .map_err(|refusal| ApiError::Driver(refusal.to_string()))?;
        info!(
            checked,
            "installed artifacts: readable and not writable by the jail user"
        );
    }

    // Pods that outlived a restart get their certificates + holder keys back.
    let restored_authority = state.authority.restore_from_disk().await;
    info!("restored certificate authority for {restored_authority} pod(s)");

    // Enroll this executor's Ed25519 public key with the trust-service, once,
    // before serving. Every receipt POST is signed with the matching private
    // key (`X-Nucleus-Executor-Sig`) but ships no inline pubkey, so the
    // trust-service can only verify those signatures if it learned the key from
    // this enrollment first. A no-op when the trust gate is disabled.
    trust_gate::register_executor_pubkey(&state.trust_gate, &state.http_client).await;
    // Routes authenticated by the node mTLS middleware
    let authenticated_routes = Router::new()
        .route("/v1/pods", post(create_pod).get(pod_api::list_pods))
        .route("/v1/pods/{id}/logs", get(pod_api::pod_logs))
        .route("/v1/pods/{id}/cancel", post(pod_api::cancel_pod))
        .route("/v1/pods/{id}/snapshot", post(pod_api::snapshot_pod))
        .route("/v1/pods/{id}/receipt", get(pod_api::get_receipt))
        .merge(workload_result::routes())
        .merge(pod_api::effect_approvals::routes())
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Routes that don't require auth. The federation exchange is NOT here: it
    // is served on its own server-auth-only listener (`federation_ingress`).
    let public_routes = Router::new()
        .route(
            "/v1/art12/{session_id}",
            post(art12_collector::art12_append),
        )
        .route("/v1/health", get(health))
        .with_state(state.clone());

    let app = public_routes.merge(authenticated_routes);

    if let Some(grpc_listen) = args.grpc_listen.clone() {
        // Load TLS config if certificate paths are provided
        let tls_config = match (&args.grpc_tls_cert, &args.grpc_tls_key) {
            (Some(cert_path), Some(key_path)) => {
                match grpc_tls::GrpcTlsConfig::from_paths(
                    cert_path,
                    key_path,
                    args.grpc_tls_ca.as_deref(),
                )
                .await
                {
                    Ok(config) => {
                        let mode = if config.mtls_enabled() { "mTLS" } else { "TLS" };
                        info!("gRPC {} enabled", mode);
                        config
                    }
                    Err(e) => {
                        return Err(ApiError::Driver(format!("gRPC TLS config failed: {e}")));
                    }
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ApiError::Driver(
                    "both --grpc-tls-cert and --grpc-tls-key must be provided for TLS".to_string(),
                ));
            }
            // No explicit cert/key files: self-issue from the node's own
            // identity — the mandatory default now that HMAC has no
            // fallback (Move B). `identity_manager` is always constructed
            // (see above), so this cannot fail for lack of one; the
            // `--grpc-tls-self-issued` flag that used to gate this is // hmac-allow: historical, flag removed by Move B
            // accepted for compatibility but has no effect any more — this
            // path is not optional.
            (None, None) => {
                let manager = state
                    .identity_manager
                    .as_ref()
                    .expect("identity_manager is unconditionally constructed above (Move B)");
                grpc_tls::GrpcTlsConfig::from_node_identity(manager)
                    .await
                    .map_err(|e| {
                        ApiError::Driver(format!("gRPC self-issued TLS config failed: {e}"))
                    })?
            }
        };

        let grpc_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_grpc(grpc_state, grpc_listen, tls_config).await {
                error!("grpc server error: {err}");
            }
        });
    }

    start_pod_reaper(state.clone());

    federation_ingress::spawn(&state, &args.authority.ingress).await?;
    http_serve::serve(&state, &args.listen, app).await?;

    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn create_pod(
    State(state): State<NodeState>,
    Extension(caller): Extension<auth::CallerScope>,
    Extension(auth_ctx): Extension<auth::AuthContext>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Json<CreatePodResponse>, ApiError> {
    let spec = match serde_yaml::from_slice::<PodSpec>(&body) {
        Ok(spec) => spec,
        Err(_) => {
            let request: CreatePodRequest =
                serde_yaml::from_slice(&body).map_err(|e| ApiError::InvalidSpec(e.to_string()))?;
            if let Some(spec) = request.spec {
                spec
            } else if let Some(yaml) = request.yaml {
                serde_yaml::from_str(&yaml).map_err(|e| ApiError::InvalidSpec(e.to_string()))?
            } else {
                return Err(ApiError::InvalidSpec("missing spec".to_string()));
            }
        }
    };

    // WHO the parent is, established by the node rather than declared by the
    // caller: the per-pod caller token, or the caller's own pod SVID.
    // `x-nucleus-parent-pod-id` is unauthenticated, so lineage built on it is
    // forgeable in both directions -- see `pod_api::resolve_parent_pod_id`.
    let named = headers.get(PARENT_HEADER).and_then(|v| v.to_str().ok());
    let admission =
        pod_authority::Admission::from_http(&state.authz_policy, caller.pod(), &auth_ctx, &headers);
    let parent_pod_id = pod_api::parent_for_create(&state, &caller, named).await?;

    let raw = String::from_utf8_lossy(&body).to_string();
    let (id, proxy_addr) =
        create_pod_internal(&state, spec, parent_pod_id, Some(raw), admission).await?;

    Ok(Json(CreatePodResponse { id, proxy_addr }))
}

const MAX_AUTH_BODY_BYTES: usize = 10 * 1024 * 1024;

async fn auth_middleware(
    State(state): State<NodeState>,
    request: axum::http::Request<Body>,
    next: middleware::Next,
) -> Result<AxumResponse, ApiError> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_AUTH_BODY_BYTES)
        .await
        .map_err(|e| ApiError::Body(e.to_string()))?;
    let context = auth::resolve_http_auth(&state, &parts)?;

    // WHICH POD is calling: its caller token, else its own pod SVID. Unscoped
    // only for an identity the policy grants node-wide reach, never by default
    // (`AuthorizationPolicy::caller_scope`, which gRPC resolves through too).
    let caller = auth::resolve_http_caller(&state, &context, &parts.headers)?;

    let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(context);
    req.extensions_mut().insert(caller);
    Ok(next.run(req).await)
}

/// The unauthenticated parent header; read only by `pod_api::parent_for_create`.
const PARENT_HEADER: &str = "x-nucleus-parent-pod-id";

#[tracing::instrument(skip_all, fields(boot.stage = "pod.create", pod_id = tracing::field::Empty, chain_depth = tracing::field::Empty))]
async fn create_pod_internal(
    state: &NodeState,
    mut spec: PodSpec,
    parent_pod_id: Option<Uuid>,
    raw_yaml: Option<String>,
    admission: pod_authority::Admission,
) -> Result<(Uuid, Option<String>), ApiError> {
    production_confinement::admit_seccomp(spec.spec.seccomp.as_ref())
        .map_err(|e| ApiError::InvalidSpec(e.to_owned()))?;
    rootfs_source::admit(&spec)?; // OCI needs an image store; boot_args are allowlisted (#3124)
    host_paths::admit(&mut spec, &state.driver, &state.host_roots)?;
    // Posture fields a spec may not weaken (#3120), and where its audit log goes (#3131). A sink
    // this node cannot mint a scoped credential for is refused here, by name (#3160).
    let audit_mint = audit_sink::credentials::admit(
        spec_posture::admit(&spec, &state.audit_sinks, &state.pod_ceilings)?,
        state.audit_minter.as_ref(),
    )?;
    let id = Uuid::new_v4();
    tracing::Span::current().record("pod_id", tracing::field::display(id));
    let created_at = now_unix();

    // ── Backend clamp. The reputation lookup that used to run here was
    // deleted in #2512: it wrote labels and authorised nothing, and what a pod
    // MAY do comes from the certificate below. ───────────────────────────────
    driver::clamp_isolation_to_backend(&state.driver, &mut spec)?;
    admission.stamp_ci_principal(&state.authz_policy, &mut spec)?;

    let pod_dir = lifecycle::pod_dir(&state.state_dir, id);
    tokio::fs::create_dir_all(&pod_dir).await?;

    // ── Posture Gate: proof-carrying admission (fail-closed) ──────────
    // If the pod carries a `dlc_posture` claim, admit it only when the claimed
    // artifact digest matches the rootfs the node measures ITSELF and a trusted
    // builder has proven that posture for that artifact. No claim is inert. The
    // measured digest is unforgeable by the pod, so this is a reached obligation
    // (AssuranceCoverage.lean's reached-vs-unreached distinction), not a carried
    // assertion trusted on the pod's word. See posture.rs / `admit_posture`.
    let posture_stamp: Option<String> =
        posture::admit_posture(&spec, id, &state.trusted_postures).await?;

    // ── Authority Gate: proof of caller authority, budget conserved ──
    // The caller's certificate decides what this pod may do; the spec's policy
    // is a REQUEST, meet-clamped and never trusted alone. See pod_authority.rs.
    lockdown::admits(state, admission.caller_pod).await?;
    let issued = state.authority.admit(&admission, &spec, id).await?;
    tracing::Span::current().record("chain_depth", issued.chain_depth);
    // The issued lattice AND the admitted credentialed upstreams replace what
    // the spec requested, in one call so neither can be applied without the other.
    // The pod's owner is the issued root identity (ADR 0001: its tenant).
    let owner = issued.root_identity.clone();
    let reservation = issued.apply_to(&mut spec);

    // The uploader's credential, minted only now that the caller's authority is admitted: one
    // limited to this pod's resolved bucket and prefix, for the pod's lifetime (#3160).
    let capacity = state.node_capacity.reserve(&spec)?;
    let audit = match audit_mint {
        None => None,
        Some(mint) => {
            let ttl = audit_sink::credentials::credential_ttl(spec.spec.timeout_seconds);
            match mint.mint(ttl).await {
                Ok(grant) => Some(grant),
                Err(refused) => {
                    reservation.release().await;
                    return Err(refused.into());
                }
            }
        }
    };

    let spawned = match state.driver {
        #[cfg(feature = "local-driver")]
        DriverKind::Local => spawn_local_pod(state, &pod_dir, &spec, id, audit.as_ref()).await,
        DriverKind::Firecracker => {
            spawn_firecracker_pod(state, &pod_dir, &spec, id, audit.as_ref()).await
        }
        DriverKind::Container => {
            let raw = raw_yaml.as_deref();
            spawn_container_pod(state, &pod_dir, &spec, id, raw, audit.as_ref()).await
        }
        DriverKind::AppleVz => driver::spawn_vz_pod(state, &pod_dir, &spec, id).await,
    };
    let (driver_state, proxy_addr, log_path) = match spawned {
        Ok(s) => s,
        Err(e) => {
            // Nothing ran, so nothing was spent: the reservation goes back whole.
            reservation.release().await;
            return Err(e);
        }
    };
    boot_trace::log_guest_console_timeline(&log_path).await;

    // Write lifecycle audit event so even direct-task pods have an audit trail.
    lifecycle::write_lifecycle_audit(
        &pod_dir,
        "pod_started",
        &id.to_string(),
        &format!("driver={:?}", state.driver),
    )
    .await;

    let handle = Arc::new(PodHandle {
        id,
        spec,
        created_at,
        log_path,
        proxy_addr: Mutex::new(proxy_addr.clone()),
        driver_state,
        parent_pod_id,
        posture_stamp,
        owner: Some(owner),
        capacity: Mutex::new(Some(capacity)),
    });

    state.pods.lock().await.insert(id, handle);
    reservation.commit(); // registered: the reaper releases it from here (a drop before, #3032)
    Ok((id, proxy_addr))
}

#[cfg(feature = "local-driver")]
impl LocalPod {
    async fn status(&self) -> PodState {
        let mut child = self.child.lock().await;
        match child.try_wait() {
            Ok(Some(status)) => PodState::Exited {
                code: status.code(),
            },
            Ok(None) => PodState::Running,
            Err(err) => PodState::Error {
                message: err.to_string(),
            },
        }
    }

    async fn teardown(&self, stop: Stop) -> Result<(), ApiError> {
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        if stop == Stop::Kill {
            self.child.lock().await.kill().await.map_err(ApiError::Io)?;
        }
        Ok(())
    }
}

impl FirecrackerPod {
    async fn status(&self) -> PodState {
        let mut child = self.child.lock().await;
        match child.try_wait() {
            Ok(Some(status)) => PodState::Exited {
                code: status.code(),
            },
            Ok(None) => PodState::Running,
            Err(err) => PodState::Error {
                message: err.to_string(),
            },
        }
    }

    async fn teardown(&self, stop: Stop) -> Result<(), ApiError> {
        // Identity first: the workload API bridge drains before the identity is
        // released, so nothing is served for an identity that is gone.
        self.cleanup_identity().await;
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        if let Some(mut dns_proxy) = self.dns_proxy.lock().await.take() {
            let _ = dns_proxy.child.kill().await;
        }
        self.drift_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.drift_monitor.lock().await.take() {
            handle.abort();
        }
        self.permit.lock().await.take();
        if let Some(bridge) = self.bridge.lock().await.take() {
            bridge.shutdown().await;
        }
        if let Some(plan) = self.net_plan.lock().await.take() {
            self.network_allocator.release(plan.index);
            let _ = net::cleanup_network(&plan).await;
        } else if let Some(name) = self.netns.lock().await.take() {
            let _ = net::cleanup_netns(&name).await;
        }
        if stop == Stop::Kill {
            self.child.lock().await.kill().await.map_err(ApiError::Io)?;
        }
        let mut placement = self.direct_cgroup.lock().await;
        if let Some(group) = placement.as_mut() {
            group.cleanup().await?;
        }
        placement.take();
        // After the kill, never before: pulling files out from under a live VMM is
        // its own failure mode.
        if let Some(layout) = self.jail.lock().await.take() {
            pod_receipt::preserve_exit_report(&layout, &self.pod_dir);
            firecracker_config::cleanup_jail(&layout);
        }
        Ok(())
    }
}

impl ContainerPod {
    async fn status(&self) -> PodState {
        // Return cached state if container was already cleaned up.
        if let Some(ref cached) = *self.cached_exit.lock().await {
            return cached.clone();
        }
        use bollard::query_parameters::InspectContainerOptions;
        match self
            .docker
            .inspect_container(&self.container_id, None::<InspectContainerOptions>)
            .await
        {
            Ok(info) => {
                let state = info.state.as_ref();
                let running = state.and_then(|s| s.running).unwrap_or(false);
                if running {
                    PodState::Running
                } else {
                    let exit_state = PodState::Exited {
                        code: state.and_then(|s| s.exit_code).map(|c| c as i32),
                    };
                    // Cache the terminal state so it survives container removal.
                    *self.cached_exit.lock().await = Some(exit_state.clone());
                    exit_state
                }
            }
            Err(e) => PodState::Error {
                message: e.to_string(),
            },
        }
    }

    async fn teardown(&self, stop: Stop) -> Result<(), ApiError> {
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        if stop == Stop::Kill {
            let _ = self
                .docker
                .stop_container(
                    &self.container_id,
                    Some(bollard::query_parameters::StopContainerOptions {
                        t: Some(5),
                        signal: Some("SIGTERM".to_string()),
                    }),
                )
                .await;
        }
        // Cache the exit state BEFORE removal, on both paths: once the container is
        // gone `status()` cannot inspect it and would report an error. Cancel used to
        // skip this, so a cancelled pod read as `Error` and the reaper audited its
        // exit as "No such container".
        if self.cached_exit.lock().await.is_none() {
            let _ = self.status().await;
        }
        let _ = self
            .docker
            .remove_container(
                &self.container_id,
                Some(bollard::query_parameters::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        self.permit.lock().await.take();
        Ok(())
    }
}

/// The local tool-proxy's audit uploader environment (#3131, #3160).
///
/// The tool-proxy inherits the node's environment (`Command` does not `env_clear`), so every name
/// the uploader's credential chain reads is removed first, pod with a sink or not: the node's own
/// key reaches no pod by inheritance. Then, for a pod with a sink, the destination admission
/// resolved and the credential minted for exactly that destination.
#[cfg(feature = "local-driver")]
fn provision_local_audit_env(
    command: &mut Command,
    audit: Option<&audit_sink::credentials::AuditGrant>,
) {
    for key in audit_sink::credentials::UPLOADER_CREDENTIAL_ENV {
        command.env_remove(key);
    }
    if let Some(grant) = audit {
        command.envs(grant.proxy_env());
    }
}

#[cfg(feature = "local-driver")]
async fn spawn_local_pod(
    state: &NodeState,
    pod_dir: &Path,
    spec: &PodSpec,
    id: Uuid,
    audit: Option<&audit_sink::credentials::AuditGrant>,
) -> Result<(DriverState, Option<String>, PathBuf), ApiError> {
    let spec_path = pod_dir.join("pod.yaml");
    let log_path = pod_dir.join("pod.log");
    let announce_path = pod_dir.join("proxy.addr");

    let spec_yaml = serde_yaml::to_string(spec).map_err(ApiError::Serde)?;
    // Compute spec hash before writing (write consumes the string).
    let spec_yaml_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(spec_yaml.as_bytes()))
    };
    tokio::fs::write(&spec_path, spec_yaml).await?;

    if spec.spec.network.is_some() {
        return Err(ApiError::Driver(
            "network policy requires firecracker driver".to_string(),
        ));
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1 does not apply: a byte stream (the child's stdout), not a record log"
    )]
    let log_stdout = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1 does not apply: a byte stream (the child's stderr), not a record log"
    )]
    let log_stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let mut command = Command::new(&state.tool_proxy_path);
    command
        .args(unsandboxed_proxy_flag(state.local_driver_opt_in))
        .arg("--spec")
        .arg(&spec_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--announce-path")
        .arg(&announce_path)
        // The workload door, in the pod's own directory: the guest default
        // (`guest_layout::WORKLOAD_DOOR`, under /run) is not writable by a
        // host-side proxy. Bound only when the pod has a workload.
        .arg("--workload-door")
        .arg(std::path::absolute(pod_dir.join("workload.sock"))?);
    command.env(
        "NUCLEUS_TOOL_PROXY_AUTH_SECRET",
        state.proxy_auth_secret.as_str(),
    );
    command.env(
        "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
        state.proxy_approval_secret.as_str(),
    );
    let audit_path = pod_dir.join("audit.log");
    command.env(
        "NUCLEUS_TOOL_PROXY_AUDIT_LOG",
        audit_path.to_string_lossy().as_ref(),
    );

    art12_collector::provision_pod_env(&mut command, pod_dir, &state.listen_addr, &id.to_string());

    provision_local_audit_env(&mut command, audit);

    // Inject sandbox proof token so tool-proxy can verify it's in a managed sandbox.
    let sandbox_token = nucleus_client::generate_sandbox_token(
        state.proxy_auth_secret.as_bytes(),
        &id.to_string(),
        &spec_yaml_hash,
    );
    command.env("NUCLEUS_SANDBOX_TOKEN", &sandbox_token);

    // Live-path: mint + inject the session capability token scoped to exactly
    // the pod policy's granted operations. The tool-proxy verifies it once at
    // startup (fail-closed). Injected on the same host-controlled env channel as
    // the secrets above; the token itself is a scoped capability + PUBLIC issuer
    // key (not a secret). Names match the tool-proxy verify half exactly.
    if let Some(minted) = pod_authority::mint_task_token_for_spec(state, spec, id).await {
        command.env("NUCLEUS_TASK_TOKEN", &minted.token_json);
        command.env("NUCLEUS_TASK_TOKEN_NONCE", &minted.nonce_hex);
        command.env("NUCLEUS_TASK_TOKEN_ISSUER", &minted.issuer_hex);
    }
    // The pod's certificate of authority + the pinned anchor (pod_authority).
    for (key, value) in state.authority.boot_env(id).await {
        command.env(key, value);
    }

    // DLC-D verified admission: pod-scoped provisioning via PodSpec labels,
    // forwarded verbatim as the NUCLEUS_DLC_* env the tool-proxy reads. The
    // label->env mapping is `nucleus_spec::dlc_admission`'s, the same one the
    // container driver and the Firecracker workload API use. Node-global env
    // still inherits (Command does not env_clear); labels let a single pod —
    // e.g. `nucleus verify --tier2`'s — run under admission without touching
    // host config. Values are NOT validated here: the proxy's parser owns that
    // and fails CLOSED (partial/garbage config provisions deny-all).
    if let Some(dlc) = DlcProvisioning::from_labels(&spec.metadata.labels) {
        command.envs(dlc.env());
    }

    // Detect orchestrator pod: inject pod management env vars
    let enable_pod_mgmt = spec
        .metadata
        .labels
        .get("enable_pod_mgmt")
        .map(|v| v == "true")
        .unwrap_or(false);
    if enable_pod_mgmt {
        command.env("NUCLEUS_TOOL_PROXY_ENABLE_POD_MGMT", "true");
        // Point orchestrator's tool-proxy at this node's HTTP API. `https://`
        // since Move B: the node's HTTP listener is mTLS-only, unconditionally
        // (http_serve.rs) — there is no plaintext fallback any more.
        let node_url = format!("https://{}", state.listen_addr);
        command.env("NUCLEUS_TOOL_PROXY_NODE_URL", &node_url);
        // Mint this orchestrator pod its own SVID so its tool-proxy can
        // authenticate back to the node over mTLS (`node_identity::require`
        // in nucleus-tool-proxy). `NUCLEUS_TOOL_PROXY_NODE_AUTH_SECRET` was
        // the pre-Move-B mechanism (a shared secret the tool-proxy no longer
        // reads); this is the SVID-file replacement, env-parity with what
        // guest-init already does for the real Firecracker path over vsock.
        // Node-assigned `ns/pods/sa/<uuid>`: the shape `AuthorizationPolicy`'s
        // pod class authorizes for pod management and nothing else. What the
        // pod may CREATE is decided by its certificate, not by this prefix.
        let manager = state
            .identity_manager
            .as_ref()
            .expect("identity_manager is unconditionally constructed above (Move B)");
        let orchestrator_identity = manager.pod_identity(id);
        let orchestrator_cert = manager
            .fetch_certificate(&orchestrator_identity)
            .await
            .map_err(|e| {
                ApiError::Driver(format!(
                    "failed to mint orchestrator pod {id}'s SVID for pod management: {e}"
                ))
            })?;
        let identity_dir = pod_dir.join("identity");
        tokio::fs::create_dir_all(&identity_dir).await?;
        let identity_cert_path = identity_dir.join("cert.pem");
        let identity_key_path = identity_dir.join("key.pem");
        let identity_bundle_path = identity_dir.join("trust-bundle.pem");
        tokio::fs::write(&identity_cert_path, orchestrator_cert.chain_pem()).await?;
        tokio::fs::write(&identity_key_path, orchestrator_cert.private_key_pem()).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&identity_key_path, std::fs::Permissions::from_mode(0o600))
                .await?;
        }
        let bundle_pem = manager
            .trust_bundle()
            .roots()
            .iter()
            .map(|r| r.to_pem().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(&identity_bundle_path, bundle_pem).await?;
        command.env("NUCLEUS_IDENTITY_CERT", &identity_cert_path);
        command.env("NUCLEUS_IDENTITY_KEY", &identity_key_path);
        command.env("NUCLEUS_IDENTITY_TRUST_BUNDLE", &identity_bundle_path);
        // Caller identity → tool-proxy scopes the management API (env-parity with guest-init).
        command.env("NUCLEUS_POD_ID", id.to_string());
        command.env(
            "NUCLEUS_POD_CALLER_TOKEN",
            pod_caller_identity::derive_token(state.caller_secret.as_ref(), id),
        );
        info!("enabled pod management for orchestrator pod {}", id);
    }

    let mut child = command
        .stdout(log_stdout)
        .stderr(log_stderr)
        .spawn()
        .map_err(|e| ApiError::Driver(format!("failed to spawn tool proxy: {e}")))?;

    let mut proxy_addr = wait_for_announce(&announce_path, &mut child).await;
    let mut signed_proxy = None;
    if let Some(addr) = proxy_addr.as_ref() {
        let target_addr: SocketAddr = addr
            .parse()
            .map_err(|e| ApiError::Driver(format!("invalid tool proxy address {addr}: {e}")))?;
        let proxy = signed_proxy::SignedProxy::start_with_drand(
            target_addr,
            Arc::new(state.proxy_auth_secret.as_bytes().to_vec()),
            // Env-provisioned pod: it verifies approvals with the shared secret.
            Some(signed_proxy::ApprovalSigning::Hmac(Arc::new(
                state.proxy_approval_secret.as_bytes().to_vec(),
            ))),
            state.proxy_actor.clone(),
            state.drand_config.clone(),
        )
        .await
        .map_err(|e| ApiError::Driver(format!("signed proxy failed: {e}")))?;
        proxy_addr = Some(format!("http://{}", proxy.listen_addr()));
        signed_proxy = Some(proxy);
    }

    let handle = LocalPod {
        child: Mutex::new(child),
        signed_proxy: Mutex::new(signed_proxy),
    };

    info!("spawned local pod {}", id);
    Ok((DriverState::Local(Box::new(handle)), proxy_addr, log_path))
}

/// The environment a container pod is started with.
///
/// Split out of [`spawn_container_pod`] so what reaches the container's
/// tool-proxy can be read by a test without a Docker daemon: every other half
/// of that function needs one.
async fn container_env(
    state: &NodeState,
    spec: &PodSpec,
    id: Uuid,
    mediation: container_mediation::ContainerMediation,
    sandbox_token: &str,
    spec_yaml: &str,
    audit: Option<&audit_sink::credentials::AuditGrant>,
) -> Vec<String> {
    let mut env: Vec<String> = vec![format!("NUCLEUS_SANDBOX_TOKEN={sandbox_token}")];
    let proxy_mode = mediation.runs_tool_proxy();

    if proxy_mode {
        env.extend(container_transport::proxy_env(state));
        env.push(format!(
            "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET={}",
            state.proxy_approval_secret
        ));
        env.push("NUCLEUS_TOOL_PROXY_AUDIT_LOG=/data/pod/audit.log".to_string());
        art12_collector::provision_container_env(&mut env);

        // The audit sink admission resolved against the operator's `--audit-sinks` (#3131), and
        // the credential minted for exactly that destination (#3160). A container inherits
        // nothing from the node, so this is the only credential its uploader holds.
        if let Some(grant) = audit {
            for (key, value) in grant.proxy_env() {
                env.push(format!("{key}={value}"));
            }
        }

        // Live-path session capability token (see spawn_local_pod). Injected in
        // proxy mode — the only container mode that runs the tool-proxy sidecar.
        if let Some(minted) = pod_authority::mint_task_token_for_spec(state, spec, id).await {
            env.push(format!("NUCLEUS_TASK_TOKEN={}", minted.token_json));
            env.push(format!("NUCLEUS_TASK_TOKEN_NONCE={}", minted.nonce_hex));
            env.push(format!("NUCLEUS_TASK_TOKEN_ISSUER={}", minted.issuer_hex));
        }
        for (key, value) in state.authority.boot_env(id).await {
            env.push(format!("{key}={value}"));
        }
        // DLC-D verified admission from the PodSpec labels, through the same
        // declaration the local driver and the Firecracker workload API use.
        // This driver used to have no copy of the mapping at all, so a
        // container pod's dlc_* labels were accepted, listed by `nucleus node
        // pods`, and never reached the tool-proxy that enforces them (#2903).
        if let Some(dlc) = DlcProvisioning::from_labels(&spec.metadata.labels) {
            env.extend(dlc.env().map(|(key, value)| format!("{key}={value}")));
        }
    }

    // Pass credentials from PodSpec (if any)
    if let Some(ref creds) = spec.spec.credentials {
        for (key, val) in &creds.env {
            env.push(format!("{key}={val}"));
        }
    }

    // In direct mode, extract the task from the raw YAML (task is not in the typed
    // PodSpec struct — it's a free-form field that the tool-proxy/agent reads from YAML).
    if !proxy_mode
        && let Ok(raw) = serde_yaml::from_str::<serde_json::Value>(spec_yaml)
        && let Some(task) = raw
            .get("spec")
            .and_then(|s| s.get("task"))
            .and_then(|t| t.as_str())
    {
        env.push(format!("NUCLEUS_TASK={task}"));
    }
    env
}

async fn spawn_container_pod(
    state: &NodeState,
    pod_dir: &Path,
    spec: &PodSpec,
    id: Uuid,
    raw_yaml: Option<&str>,
    audit: Option<&audit_sink::credentials::AuditGrant>,
) -> Result<(DriverState, Option<String>, PathBuf), ApiError> {
    // Fail-closed: reject a network egress policy the container driver cannot
    // enforce (parity with spawn_local_pod / firecracker reject_unsupported_policy)
    // — checked before acquiring the docker client so it rejects even without docker.
    container_driver_reject_unsupported_network_policy(spec)?;

    let docker = state
        .docker
        .as_ref()
        .ok_or_else(|| ApiError::Driver("Docker client not initialized".into()))?;

    // Acquire semaphore permit
    let permit = match &state.container_pool {
        Some(pool) => Some(
            pool.clone()
                .acquire_owned()
                .await
                .map_err(|_| ApiError::Driver("container pool closed".into()))?,
        ),
        None => None,
    };

    let spec_path = pod_dir.join("pod.yaml");
    let log_path = pod_dir.join("pod.log");
    let announce_path = pod_dir.join("proxy.addr");
    let audit_path = pod_dir.join("audit.log");

    // Prefer raw YAML (preserves free-form fields like `task:` that aren't in PodInner).
    // Fall back to re-serialized typed spec if raw isn't available.
    let spec_yaml = match raw_yaml {
        Some(raw) => raw.to_string(),
        None => serde_yaml::to_string(spec).map_err(ApiError::Serde)?,
    };
    let spec_yaml_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(spec_yaml.as_bytes()))
    };
    tokio::fs::write(&spec_path, &spec_yaml).await?;

    let sandbox_token = nucleus_client::generate_sandbox_token(
        state.proxy_auth_secret.as_bytes(),
        &id.to_string(),
        &spec_yaml_hash,
    );

    // Mediation and image are the node's (#3133); `spec_posture::admit` refused a spec naming them.
    let mediation = state.container_mediation;
    let proxy_mode = mediation.runs_tool_proxy();
    let env = container_env(
        state,
        spec,
        id,
        mediation,
        &sandbox_token,
        &spec_yaml,
        audit,
    )
    .await;
    let launch = container_mediation::launch(mediation, &state.container_image, &env);
    let image = launch.image.clone();

    let pod_dir_abs = pod_dir
        .canonicalize()
        .unwrap_or_else(|_| pod_dir.to_path_buf());

    // Bind mounts: pod_dir → /data/pod, work_dir → /workspace. `host_paths::admit`
    // resolved work_dir to a directory strictly inside --workspace-root.
    let binds = vec![
        format!("{}:/data/pod:rw", pod_dir_abs.display()),
        format!("{}:/workspace:rw", spec.spec.work_dir.display()),
    ];

    // Network mode: the node's, or `none` if the pod asks for it; any other label is refused.
    let network_mode = spec_posture::container_network(
        spec.metadata
            .labels
            .get("nucleus.io/network")
            .map(String::as_str),
        &state.container_network,
    )?;

    let size = pod_resources::PodSize::of(spec);
    let container_memory = i64::try_from(size.memory_bytes()).unwrap_or(i64::MAX);
    let host_config = bollard::models::HostConfig {
        network_mode: Some(network_mode),
        binds: Some(binds),
        // Always the admitted size (#3130); an absent spec field is the node's default, never
        // unlimited. Swap equal to memory means none beyond it.
        memory: Some(container_memory),
        memory_swap: Some(container_memory),
        nano_cpus: Some(i64::from(size.vcpus()) * 1_000_000_000),
        pids_limit: Some(pod_resources::CONTAINER_PIDS_MAX),
        ..Default::default()
    };

    let config = bollard::models::ContainerCreateBody {
        image: Some(launch.image),
        entrypoint: launch.entrypoint,
        cmd: launch.cmd,
        env: Some(env),
        host_config: Some(host_config),
        working_dir: Some("/workspace".to_string()),
        ..Default::default()
    };

    let container = docker
        .create_container(
            None::<bollard::query_parameters::CreateContainerOptions>,
            config,
        )
        .await
        .map_err(|e| ApiError::Driver(format!("create container: {e}")))?;

    let container_id = container.id.clone();
    docker
        .start_container(
            &container_id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await
        .map_err(|e| ApiError::Driver(format!("start container {container_id}: {e}")))?;

    // Stream container logs to pod.log in background
    {
        let docker = docker.as_ref().clone();
        let cid = container_id.clone();
        let log_path = log_path.clone();
        tokio::spawn(async move {
            use bollard::query_parameters::LogsOptions;
            use tokio_stream::StreamExt;
            let opts = LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            };
            let mut stream = docker.logs(&cid, Some(opts));
            #[expect(
                clippy::disallowed_methods,
                reason = "ADR 0007 G-1 does not apply: a byte stream (the container's log stream), not a record log"
            )]
            let mut file = match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    error!("failed to open log file {}: {e}", log_path.display());
                    return;
                }
            };
            while let Some(Ok(output)) = stream.next().await {
                let bytes = output.into_bytes();
                if file.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
    }

    // In proxy mode: wait for announce file and wrap with SignedProxy
    let mut proxy_addr = None;
    let mut signed_proxy_opt = None;

    if proxy_mode {
        proxy_addr =
            wait_for_container_announce(&announce_path, docker.as_ref(), &container_id).await;

        if let Some(ref addr) = proxy_addr {
            let target = container_transport::target(state, &pod_dir_abs, addr)?;
            let proxy = signed_proxy::SignedProxy::start_with_drand(
                target,
                Arc::new(state.proxy_auth_secret.as_bytes().to_vec()),
                // Env-provisioned container: shared-secret approvals.
                Some(signed_proxy::ApprovalSigning::Hmac(Arc::new(
                    state.proxy_approval_secret.as_bytes().to_vec(),
                ))),
                state.proxy_actor.clone(),
                state.drand_config.clone(),
            )
            .await
            .map_err(|e| ApiError::Driver(format!("signed proxy failed: {e}")))?;
            proxy_addr = Some(format!("http://{}", proxy.listen_addr()));
            signed_proxy_opt = Some(proxy);
        }
    }

    // Touch audit log so it exists even in direct mode (for inspection)
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1 does not apply: creates the file so it exists; writes nothing"
    )]
    let _ = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .await;

    let handle = ContainerPod {
        container_id,
        docker: docker.as_ref().clone(),
        signed_proxy: Mutex::new(signed_proxy_opt),
        permit: Mutex::new(permit),
        cached_exit: Mutex::new(None),
    };

    info!(pod_id = %id, %image, ?mediation, "spawned container pod");
    Ok((
        DriverState::Container(Box::new(handle)),
        proxy_addr,
        log_path,
    ))
}

/// Wait for the announce file inside a container pod (analogous to `wait_for_announce`
/// for the local driver, but checks container status instead of process status).
async fn wait_for_container_announce(
    announce_path: &Path,
    docker: &bollard::Docker,
    container_id: &str,
) -> Option<String> {
    use bollard::query_parameters::InspectContainerOptions;

    let wait_result = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(addr) = tokio::fs::read_to_string(announce_path).await {
                let trimmed = addr.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }

            // Check if container exited early
            match docker
                .inspect_container(container_id, None::<InspectContainerOptions>)
                .await
            {
                Ok(info) => {
                    let running = info.state.as_ref().and_then(|s| s.running).unwrap_or(false);
                    if !running {
                        error!("container exited before announcing proxy address");
                        return None;
                    }
                }
                Err(e) => {
                    error!("container inspect error: {e}");
                    return None;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    wait_result.unwrap_or_default()
}

/// Ask the VMM its version and judge it against the floor.
///
/// A binary that will not run, or that prints nothing recognisable, yields a
/// refusal rather than a pass — the whole point is that the failure mode is
/// "no microVM", never "microVM on an unknown build".
///
/// Deliberately NOT `#[cfg(target_os = "linux")]` even though its only caller
/// is: nothing in here is platform-specific, and gating it would mean the code
/// is never compiled or tested on a macOS dev host. `vmm_preflight_refuses_*`
/// exercise it here.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[tracing::instrument(skip_all, fields(boot.stage = "vmm.preflight"))]
async fn vmm_preflight(firecracker_path: &Path) -> nucleus_spec::vmm_version::VmmVerdict {
    use nucleus_spec::vmm_version::{VmmVerdict, judge};

    // Fully qualified: the `Command` import is feature/platform-gated, and this
    // function deliberately is not.
    match tokio::process::Command::new(firecracker_path)
        .arg("--version")
        .output()
        .await
    {
        Ok(out) => {
            // Firecracker has printed its banner on stdout across releases, but
            // judge both streams rather than depend on which.
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            judge(&text)
        }
        Err(e) => VmmVerdict::Unparseable {
            raw: format!("{} could not be executed: {e}", firecracker_path.display()),
        },
    }
}

async fn spawn_firecracker_pod(
    state: &NodeState,
    pod_dir: &Path,
    spec: &PodSpec,
    id: Uuid,
    audit: Option<&audit_sink::credentials::AuditGrant>,
) -> Result<(DriverState, Option<String>, PathBuf), ApiError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, pod_dir, spec, id, audit);
        let why = "firecracker requires Linux; run nucleus-node inside Colima on macOS";
        Err(ApiError::Driver(why.to_string()))
    }

    #[cfg(target_os = "linux")]
    {
        // Everything the host must provide, checked BEFORE anything is built.
        //
        // This used to be a bare /dev/kvm check. Two other hard requirements were
        // discovered only by failing at the moment they were used:
        // /dev/vhost-vsock was checked nowhere in the node, so its absence
        // surfaced ~3s later as `vsock socket not found` naming a socket path
        // rather than a kernel module; and CAP_NET_ADMIN was never checked, so
        // networking failed partway through setup_network with a namespace, a
        // veth pair and a bridge already created.
        //
        // See `host_requirements` for the table and why the decision is split
        // from the observation.
        host_requirements::preflight(spec.spec.network.is_some()).map_err(ApiError::Driver)?;
        // The node's limits for this pod, merged with what the spec may lower (#3130). Admitted
        // at create by the same function, so an error here is a node fault, not a spec one.
        let node_cgroup = pod_resources::node_cgroup(spec, pod_resources::CgroupVersion::detect())
            .map_err(|e| ApiError::InvalidSpec(e.to_string()))?;

        // REFUSE A VMM WITH A KNOWN GUEST ESCAPE.
        //
        // Nucleus's isolation claim is delegated to Firecracker and the jailer,
        // so a VMM carrying an escape-class advisory is a hole in the boundary
        // even when every line of nucleus is correct. `doctor` reports this, but
        // `doctor` is advisory and nobody has to run it — the launch path is the
        // only place a refusal actually binds. Fail closed: an unreadable
        // version is refused, not assumed safe.
        let verdict = vmm_preflight(&state.firecracker_path).await;
        if !verdict.is_acceptable() {
            return Err(ApiError::Driver(format!(
                "refusing to launch a microVM: {verdict}"
            )));
        }
        if state.proxy_approval_secret.trim().is_empty() {
            return Err(ApiError::Driver(
                "proxy approval secret is required to enforce signed approvals".to_string(),
            ));
        }

        let permit = match state.firecracker_pool.as_ref() {
            Some(pool) => Some(
                pool.clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| ApiError::Driver("firecracker pool closed".to_string()))?,
            ),
            None => None,
        };

        // Resolved once: every consumer below takes a rootfs that is a host file by construction.
        let image = rootfs_source::HostImage::of_spec(spec)?;
        let vsock_spec = spec
            .spec
            .vsock
            .as_ref()
            .ok_or_else(|| ApiError::Driver("missing spec.vsock".to_string()))?;

        let mut net_plan: Option<net::NetPlan> = None;
        let mut netns_name: Option<String> = None;
        let mut dns_proxy: Option<net::DnsProxyState> = None;

        // Decide the network isolation plan up front (pure + property-tested in
        // net.rs: `netns_plan_never_omits_netns_or_default_deny`). The imperative
        // path below performs the side effects in the order the security model
        // requires — default-deny is applied BEFORE any workload process runs.
        let netns_plan =
            net::NetnsPlan::decide(state.firecracker_netns, spec.spec.network.as_ref());
        if netns_plan.reject_unsupported_policy {
            return Err(ApiError::Driver(
                "network policy requires --firecracker-netns=true".to_string(),
            ));
        }
        // Declared OUT here on purpose. The namespace is made inside the block
        // below but must survive until this function succeeds, so a guard scoped
        // to that block would reap a live pod's namespace the moment the block
        // ended — worse than the leak it exists to prevent.
        let mut netns_guard: Option<net::NetnsGuard> = None;
        if netns_plan.create_netns {
            let name = net::netns_name(id);
            net::create_netns(&name).await?;
            // Armed from here to the single success return. Every `?` and early
            // `return` between the two now reaps, including ones added later by
            // someone who never read this comment.
            netns_guard = Some(net::NetnsGuard::new(&name));

            // Apply default-deny iptables policy BEFORE any process spawns.
            // This closes the race window where a process could exfiltrate
            // data before the full policy is applied. `apply_default_deny` is
            // guaranteed true whenever `create_netns` is (see NetnsPlan).
            if netns_plan.apply_default_deny {
                if let Err(err) = net::apply_default_deny(&name).await {
                    let _ = net::cleanup_netns(&name).await;
                    return Err(err);
                }
            }
            netns_name = Some(name.clone());

            if netns_plan.allocate_net_plan {
                let network = spec
                    .spec
                    .network
                    .as_ref()
                    .expect("allocate_net_plan implies a network policy is present");
                if let Err(err) = net::validate_policy(network) {
                    let _ = net::cleanup_netns(&name).await;
                    return Err(err);
                }
                let mut plan = match state.network_allocator.allocate(id, name.clone()) {
                    Ok(plan) => plan,
                    Err(err) => {
                        let _ = net::cleanup_netns(&name).await;
                        return Err(err);
                    }
                };
                if let Err(err) = net::setup_network(&plan).await {
                    state.network_allocator.release(plan.index);
                    let _ = net::cleanup_network(&plan).await;
                    return Err(err);
                }
                if let Err(err) = net::write_policy_files(pod_dir, Some(network)).await {
                    state.network_allocator.release(plan.index);
                    let _ = net::cleanup_network(&plan).await;
                    return Err(err);
                }
                match net::start_dns_proxy(&mut plan, network, pod_dir).await {
                    Ok(proxy) => {
                        dns_proxy = proxy;
                    }
                    Err(err) => {
                        state.network_allocator.release(plan.index);
                        let _ = net::cleanup_network(&plan).await;
                        return Err(err);
                    }
                }
                net_plan = Some(plan);
            }
        }

        // THE JAILER CUTOVER. When enabled (the default) Firecracker is launched
        // by the jailer, which establishes the cgroup, chroots into a fresh mount
        // namespace and drops privileges BEFORE `exec()`. The direct-spawn path
        // below cannot do that: `--config-file` boots the VM immediately and
        // `apply_cgroup` runs afterwards, so the guest executes for a window
        // before its limits exist.
        //
        // Everything downstream that names a path has to move with it. A jailed
        // Firecracker resolves paths AFTER chroot, so a host path does not merely
        // point somewhere wrong — it points nowhere.
        // ONE binding for the jail id, shared by the layout below and the jailer's
        // `--id` argument. If those two ever disagreed the jailer would chroot into
        // a directory nothing had been placed in, and every path would resolve to
        // nothing after the chroot.
        let jail_id = id.to_string();
        let jail_layout = if state.firecracker_jailer {
            Some(firecracker_config::JailLayout::new(
                &state.jailer_chroot_base,
                &state.firecracker_path,
                &jail_id,
            ))
        } else {
            None
        };

        let log_path = pod_dir.join("firecracker.log");
        let config_path = pod_dir.join("firecracker.json");
        // Firecracker CREATES the vsock socket at its configured `uds_path`, which
        // under the jailer is inside the jail. The host must connect where the
        // socket actually appears, so this is the jail path when jailed — getting
        // it wrong hangs `wait_for_vsock_socket` on a file nothing will ever make.
        let vsock_path = match jail_layout {
            Some(ref jail) => jail.host_path(firecracker_config::in_jail::VSOCK),
            None => pod_dir.join("vsock.sock"),
        };

        // IDENTITY IS GATED ON EGRESS CONFINEMENT.
        //
        // A SPIFFE SVID bounds how LONG a credential is useful (short-lived,
        // rotated). What bounds WHERE it can be presented is the egress policy.
        // A pod allowed to reach the open internet holds a credential
        // presentable to any endpoint, including an attacker's — the temporal
        // bound survives and the spatial one is simply absent.
        //
        // So the two are offered as a trade rather than a prohibition: keep the
        // broad allowlist and boot WITHOUT a workload API, or narrow it to named
        // hosts and get an identity. The pod still runs either way; refusing the
        // launch would make this a ban instead of a choice.
        let identity_grant = net::decide_identity_grant(spec.spec.network.as_ref());
        if let net::IdentityGrant::Denied { .. } = &identity_grant {
            tracing::warn!(pod = %id, "{identity_grant}");
        }
        let workload_api_port = net::workload_api_port_for(
            state.identity_manager.is_some(),
            &identity_grant,
            state.identity_vsock_port,
        );
        // #2789: give the pod a writable `/work`. Decided before the config that
        // declares the drive, so a disk that cannot be made means no drive
        // rather than a dead boot.
        let (effective_image, scratch_is_node_provisioned) = firecracker_config::scratch_for_pod(
            &image,
            jail_layout.as_ref(),
            state.jailer_uid.get(),
            state.jailer_gid,
        );
        let image = &effective_image;
        // Live-path: mint the session capability token. It is served to the
        // guest over the workload API (`FETCH_TASK_TOKEN`, per-pod socket) — no
        // longer written to the kernel cmdline — so `from_spec` does not take
        // it; only `PodMaterial` below does.
        let task_token = pod_authority::mint_task_token_for_spec(state, spec, id).await;
        let pod_certificate = state.authority.boot_certificate(id).await;
        let config = firecracker_config::FirecrackerConfig::from_spec(
            spec,
            &log_path,
            &vsock_path,
            image,
            net_plan.as_ref(),
            // The PUBLIC half only — the signing half stays in this process.
            &hex::encode(state.approval_signer.verifying_key().to_bytes()),
            workload_api_port,
            audit.map(audit_sink::credentials::AuditGrant::target),
            jail_layout.as_ref(),
        )
        .requiring_host_spec(state.broker_enforcing);
        let config_json = match serde_json::to_vec_pretty(&config) {
            Ok(data) => data,
            Err(err) => {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(ApiError::Driver(format!("config serialize failed: {err}")));
            }
        };
        // The host copy at `config_path` stays for operators to inspect; the
        // authoritative one the VMM reads is the copy `prepare_jail` puts inside.
        let jail_config_json = config_json.clone();
        if let Err(err) = tokio::fs::write(&config_path, config_json).await {
            cleanup_net_resources(
                &state.network_allocator,
                &mut net_plan,
                &mut netns_name,
                &mut dns_proxy,
                jail_layout.as_ref(),
            )
            .await;
            return Err(ApiError::Driver(format!("config write failed: {err}")));
        }

        // Build the jail's contents. The jailer creates the chroot dir itself and
        // tolerates one that already exists, but it does NOT bring resources in —
        // the kernel, rootfs, scratch and seccomp filter are ours to place, and the
        // config has to be written where the jailed VMM will read it.
        if let Some(ref jail) = jail_layout {
            if let Err(err) = firecracker_config::prepare_jail(
                jail,
                image,
                spec,
                &jail_config_json,
                state.jailer_uid.get(),
                state.jailer_gid,
                scratch_is_node_provisioned,
            ) {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(ApiError::Driver(format!("jail preparation failed: {err}")));
            }
        }

        // Hold the artifacts to what the spec pinned, AFTER placement: in the jail these are the
        // inodes that will boot (hard links, or a clone of a sealed copy for the rootfs).
        // A pinned read-only rootfs is swapped for a clone of the node's sealed copy, measured
        // once per node life (`sealed_rootfs.rs`); `None` leaves it to `verify` to read.
        let sealed = match (&state.sealed_rootfs, &jail_layout, &image.rootfs_digest) {
            (Some(store), Some(jail), Some(pin)) if image.read_only => {
                let dest = jail.host_path(firecracker_config::in_jail::ROOTFS);
                let owner = (state.jailer_uid.get(), state.jailer_gid);
                store.place(image.rootfs_path(), pin, &dest, owner).await
            }
            _ => None,
        };
        let measured = match image_identity::verify(image, jail_layout.as_ref(), sealed).await {
            Ok(measured) => measured,
            Err(err) => {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(ApiError::Driver(err));
            }
        };

        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 G-1 does not apply: a byte stream (the VMM's console), not a record log"
        )]
        let log_stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|err| ApiError::Driver(format!("failed to open firecracker log: {err}")))?;
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 G-1 does not apply: a byte stream (the VMM's console), not a record log"
        )]
        let log_stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|err| ApiError::Driver(format!("failed to open firecracker log: {err}")))?;

        let netns_path = netns_name
            .as_ref()
            .map(|name| format!("/var/run/netns/{name}"));
        let mut command = if let Some(ref jail) = jail_layout {
            if state.firecracker_netns && netns_path.is_none() {
                firecracker_config::cleanup_jail(jail);
                return Err(ApiError::Driver(
                    "network namespace name missing".to_string(),
                ));
            }
            // `--netns` replaces the `ip netns exec` wrapper: the jailer joins the
            // namespace itself, pre-exec, so there is no intermediate `ip` process.
            // The cgroup goes in the same argv and is likewise applied before exec,
            // which is what closes the window `apply_cgroup` left open.
            let firecracker_path = state.firecracker_path.to_string_lossy();
            let chroot_base = state.jailer_chroot_base.to_string_lossy();
            let plan = firecracker_config::JailerPlan {
                firecracker_path: &firecracker_path,
                pod_id: &jail_id,
                chroot_base: &chroot_base,
                uid: state.jailer_uid,
                gid: state.jailer_gid,
                netns: netns_path.as_deref(),
                cgroup: &node_cgroup,
                config_file_in_jail: (!state.firecracker_api_boot)
                    .then_some(firecracker_config::in_jail::CONFIG),
            };
            let mut cmd = Command::new(&state.jailer_path);
            // `jailer_args` already terminates with `--` and Firecracker's own
            // `--config-file`, so anything appended after this lands in the VMM's
            // argv rather than the jailer's.
            cmd.args(firecracker_config::jailer_args(&plan));
            cmd
        } else if state.firecracker_netns {
            let Some(ref name) = netns_name else {
                return Err(ApiError::Driver(
                    "network namespace name missing".to_string(),
                ));
            };
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", name, "--"]);
            cmd.arg(&state.firecracker_path);
            if !state.firecracker_api_boot {
                cmd.arg("--config-file").arg(&config_path);
            }
            // Per-pod, for the same reason as the plain branch below. A netns
            // isolates the network, not the filesystem, so the default API
            // socket path is still shared with every other pod on the host.
            cmd.arg("--api-sock")
                .arg(pod_dir.join("firecracker.socket"));
            cmd
        } else {
            let mut cmd = Command::new(&state.firecracker_path);
            if !state.firecracker_api_boot {
                cmd.arg("--config-file").arg(&config_path);
            }
            // WITHOUT THIS, ONE POD AT A TIME. Firecracker defaults its API
            // socket to the global `/run/firecracker.socket`, so a second
            // concurrent launch fails to bind it and exits immediately.
            //
            // The jailed path never hit this because the jailer chroots each
            // pod, which is why it went unnoticed: the default configuration is
            // fine and the unjailed one silently serialises.
            //
            // The failure is also badly misleading. Firecracker exits before
            // creating its vsock socket, so the node reports "vsock socket not
            // found"; and if the node gets far enough to check seccomp it reads
            // the mode of a process that has already died and reports
            // "seccomp mode 0 (expected 2 = filter)" — a fail-closed security
            // check stating a true fact about the wrong process. Both were
            // observed and both cost real time before the cause was understood.
            cmd.arg("--api-sock")
                .arg(pod_dir.join("firecracker.socket"));
            cmd
        };
        firecracker_config::apply_seccomp_flags(&mut command, spec, jail_layout.is_some())?;
        let (broker_serve, broker_verify) = broker_launch::BrokerCapability::mint(id);
        let prepared_pod = match async {
            let identity = pod_boot_identity::prepare(pod_boot_identity::Inputs {
                measured,
                state,
                pod_dir,
                spec,
                image,
                id,
                grant: &identity_grant,
                vsock_path: &vsock_path,
                jail_owner: jail_layout
                    .as_ref()
                    .map(|_| (state.jailer_uid.get(), state.jailer_gid)),
                task_token: task_token.clone(),
                pod_certificate: pod_certificate.clone(),
                broker_serve,
                // Served once over FETCH_AUDIT_CREDENTIALS: the credential minted for this pod's
                // resolved sink, never the node's own (#3160).
                audit_creds: audit.map(audit_sink::credentials::AuditGrant::served_credentials),
            })
            .await?;
            identity
                .with_broker(
                    state,
                    spec,
                    &vsock_path,
                    id,
                    broker_verify,
                    jail_layout
                        .as_ref()
                        .map(|_| (state.jailer_uid.get(), state.jailer_gid)),
                )
                .await
        }
        .await
        {
            Ok(ready) => ready,
            Err(err) => {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(err);
            }
        };
        command.stdout(log_stdout).stderr(log_stderr);
        let mut child = match prepared_pod.spawn(&mut command) {
            Ok(child) => child,
            Err(err) => {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(ApiError::Driver(format!(
                    "failed to spawn firecracker: {err}"
                )));
            }
        };
        let pid = child.id();

        // API mode builds the machine before anything reads the sandbox, because Firecracker
        // installs its seccomp filter when the vCPUs start, NOT at exec.
        //
        // MEASURED, and it contradicts the obvious design. The appeal of the API socket was
        // supposed to be verify-then-boot: a VMM idling in its API loop with its filter already
        // on, checked while still stopped. It does not work — a Firecracker left idle for five
        // seconds after exec still reports `seccomp mode 0`, and the launch aborts fail-closed
        // on a sandbox that was about to be correct. So the check stays downstream of the boot
        // here exactly as it is for a config file, and the ordering win the API was expected to
        // buy is simply not available.
        if state.firecracker_api_boot {
            let jail = jail_layout.as_ref();
            let sock = firecracker_api::api_socket_path(jail, pod_dir);
            let base = snapshot_restore::base_for(state, &config, spec, &verdict, jail);
            let booted = snapshot_restore::bring_up(&sock, &config, base.as_ref(), jail).await;
            if let Err(reason) = booted {
                let _ = child.kill().await;
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(ApiError::Driver(format!("api boot failed: {reason}")));
            }
        }

        // Verify seccomp is active on the Firecracker process (unless explicitly disabled).
        // Seccomp mode 2 = SECCOMP_MODE_FILTER (BPF filter active).
        //
        // FAIL-CLOSED (most-paranoid #3): when `firecracker_seccomp_verify` is set
        // (the default), a process whose seccomp filter cannot be confirmed active
        // is killed and the launch is aborted rather than left running unconfined.
        // The previous behavior only logged a warning and continued (fail-open).
        if !matches!(spec.spec.seccomp, Some(nucleus_spec::SeccompSpec::Disabled)) {
            // Bounded poll, not a single read: the filter is installed by
            // Firecracker after `exec`, and under the jailer this pid is the jailer
            // for the whole chroot/privilege-drop sequence before that. A snapshot
            // taken here would see mode 0 and abort a launch that was about to be
            // correctly confined. Still fail-closed — the deadline decides, not the
            // absence of an answer.
            let verified = match pid {
                Some(fc_pid) => match firecracker_config::verify_seccomp_active_within(
                    fc_pid,
                    std::time::Duration::from_secs(5),
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(
                            pid = fc_pid,
                            "seccomp filter verified active on firecracker process"
                        );
                        Ok(())
                    }
                    Err(e) => Err(format!("seccomp verification failed for pid {fc_pid}: {e}")),
                },
                None => Err("firecracker pid unavailable; cannot verify seccomp".to_string()),
            };
            if let Err(reason) = verified {
                if state.firecracker_seccomp_verify {
                    let _ = child.kill().await;
                    cleanup_net_resources(
                        &state.network_allocator,
                        &mut net_plan,
                        &mut netns_name,
                        &mut dns_proxy,
                        jail_layout.as_ref(),
                    )
                    .await;
                    return Err(ApiError::Driver(format!(
                        "{reason} — aborting launch (fail-closed). Set \
                         NUCLEUS_FIRECRACKER_SECCOMP_VERIFY=false only if this environment \
                         legitimately cannot read /proc and the risk is accepted."
                    )));
                }
                tracing::warn!(
                    %reason,
                    "seccomp verification failed but firecracker_seccomp_verify=false; continuing (UNSAFE)"
                );
            }
        }

        let mut netns_baseline: Option<String> = None;
        let mut netns_pid: Option<u32> = None;

        if state.firecracker_netns {
            let default_policy = NetworkSpec::nothing_listed();
            let policy = spec.spec.network.as_ref().unwrap_or(&default_policy);
            let pid = match pid {
                Some(pid) => pid,
                None => {
                    let _ = child.kill().await;
                    cleanup_net_resources(
                        &state.network_allocator,
                        &mut net_plan,
                        &mut netns_name,
                        &mut dns_proxy,
                        jail_layout.as_ref(),
                    )
                    .await;
                    return Err(ApiError::Driver(
                        "firecracker process id unavailable for network policy".to_string(),
                    ));
                }
            };
            netns_pid = Some(pid);
            let dns_entries = dns_proxy.as_ref().map(|proxy| proxy.entries.as_slice());
            let dns_server = dns_proxy
                .as_ref()
                .and_then(|_| net_plan.as_ref().map(|plan| plan.gateway_ip));
            if let Err(err) = net::apply_host_policy(pid, policy, dns_entries, dns_server).await {
                let _ = child.kill().await;
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                    jail_layout.as_ref(),
                )
                .await;
                return Err(err);
            }
            if state.firecracker_netns_drift_check {
                match net::snapshot_iptables(pid).await {
                    Ok(snapshot) => {
                        let baseline_path = pod_dir.join("net.iptables.baseline");
                        if let Err(err) =
                            tokio::fs::write(&baseline_path, snapshot.as_bytes()).await
                        {
                            let _ = child.kill().await;
                            cleanup_net_resources(
                                &state.network_allocator,
                                &mut net_plan,
                                &mut netns_name,
                                &mut dns_proxy,
                                jail_layout.as_ref(),
                            )
                            .await;
                            return Err(ApiError::Driver(format!(
                                "failed to write iptables baseline: {err}"
                            )));
                        }
                        netns_baseline = Some(snapshot);
                    }
                    Err(err) => {
                        let _ = child.kill().await;
                        cleanup_net_resources(
                            &state.network_allocator,
                            &mut net_plan,
                            &mut netns_name,
                            &mut dns_proxy,
                            jail_layout.as_ref(),
                        )
                        .await;
                        return Err(err);
                    }
                }
            }
        }

        // CGROUPS. Under the jailer these are already applied — it wrote every
        // `--cgroup file=value` and put its own pid in the cgroup BEFORE `exec()`,
        // so the limits existed before the VMM did. Re-applying here would be
        // harmless but misleading: it would keep alive the impression that the
        // post-spawn path is what enforces limits, when the whole point of the
        // cutover is that it no longer has to.
        //
        // On the direct-spawn path it remains the only mechanism, and it remains
        // late — the guest runs briefly before its limits exist. That is the window
        // the jailer closes, and the reason `--firecracker-jailer` defaults on.
        let mut direct_cgroup = None;
        if jail_layout.is_none() {
            // Always placed (#3130): in the spec's directory if it names one, else the node's.
            let dir = spec
                .spec
                .cgroup
                .as_ref()
                .map_or_else(|| cgroup::node_dir(&jail_id), |c| c.path.clone());
            let placed = match pid {
                Some(pid) => cgroup::apply_cgroup(pid, &dir, &node_cgroup).await,
                None => Err(ApiError::Driver(
                    "firecracker process id unavailable for cgroup placement".to_string(),
                )),
            };
            match placed {
                Ok(placement) => direct_cgroup = Some(placement),
                Err(err) => {
                    let _ = child.kill().await;
                    cleanup_net_resources(
                        &state.network_allocator,
                        &mut net_plan,
                        &mut netns_name,
                        &mut dns_proxy,
                        jail_layout.as_ref(),
                    )
                    .await;
                    return Err(err);
                }
            }
        }

        if let Err(err) = wait_for_vsock_socket(&vsock_path).await {
            let _ = child.kill().await;
            cleanup_net_resources(
                &state.network_allocator,
                &mut net_plan,
                &mut netns_name,
                &mut dns_proxy,
                jail_layout.as_ref(),
            )
            .await;
            return Err(err);
        }
        let bridge = vsock_bridge::VsockBridge::start(vsock_path.clone(), vsock_spec.port)
            .await
            .map_err(|e| ApiError::Driver(format!("vsock bridge failed: {e}")))?;

        let mut proxy_addr = format!("http://{}", bridge.listen_addr());
        let proxy = signed_proxy::SignedProxy::start_with_drand(
            bridge.listen_addr(),
            Arc::new(state.proxy_auth_secret.as_bytes().to_vec()),
            // Firecracker pod: it verifies approvals against the node's PUBLIC
            // key (nucleus.approval_pubkeys), so approvals are Ed25519-signed
            // and no approval secret exists in the guest.
            Some(signed_proxy::ApprovalSigning::Ed25519(Arc::clone(
                &state.approval_signer,
            ))),
            state.proxy_actor.clone(),
            state.drand_config.clone(),
        )
        .await
        .map_err(|e| ApiError::Driver(format!("signed proxy failed: {e}")))?;
        proxy_addr = format!("http://{}", proxy.listen_addr());
        let health_addr = proxy.listen_addr();
        let signed_proxy = Some(proxy);

        if let Err(err) = prepared_pod
            .gate(health_addr, pod_dir, spec, id, &mut child)
            .await
        {
            if let Some(proxy) = signed_proxy {
                proxy.shutdown().await;
            }
            bridge.shutdown().await;
            let _ = child.kill().await;
            cleanup_net_resources(
                &state.network_allocator,
                &mut net_plan,
                &mut netns_name,
                &mut dns_proxy,
                jail_layout.as_ref(),
            )
            .await;
            return Err(err);
        }

        let child = Arc::new(Mutex::new(child));
        let drift_stop = Arc::new(AtomicBool::new(false));
        let drift_monitor = if state.firecracker_netns_drift_check {
            if let (Some(pid), Some(baseline)) = (netns_pid, netns_baseline) {
                let pod_dir = pod_dir.to_path_buf();
                let child = Arc::clone(&child);
                let stop = Arc::clone(&drift_stop);
                let interval = state.firecracker_netns_drift_interval;
                Some(tokio::spawn(async move {
                    let current_path = pod_dir.join("net.iptables.current");
                    let mut ticker = tokio::time::interval(interval);
                    loop {
                        ticker.tick().await;
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        match net::snapshot_iptables(pid).await {
                            Ok(snapshot) => {
                                if snapshot != baseline {
                                    let _ =
                                        tokio::fs::write(&current_path, snapshot.as_bytes()).await;
                                    let mut child = child.lock().await;
                                    let _ = child.kill().await;
                                    error!("iptables drift detected; pod netns {} terminated", pid);
                                    break;
                                }
                            }
                            Err(err) => {
                                let _ = tokio::fs::write(&current_path, format!("{err}")).await;
                                let mut child = child.lock().await;
                                let _ = child.kill().await;
                                error!(
                                    "iptables drift check failed; pod netns {} terminated: {err}",
                                    pid
                                );
                                break;
                            }
                        }
                    }
                }))
            } else {
                None
            }
        } else {
            None
        };

        let decide = host_decide::start_for_pod(
            state,
            id,
            &vsock_path,
            pod_dir,
            jail_layout
                .as_ref()
                .map(|_| (state.jailer_uid.get(), state.jailer_gid)),
        )
        .await;

        let (identity_parts, broker) = prepared_pod.into_parts();
        let pod_boot_identity::IdentityParts {
            identity: pod_identity,
            manager: identity_manager,
            registry_key: identity_registry_key,
            bridge: workload_api_bridge,
        } = identity_parts;

        let handle = FirecrackerPod {
            direct_cgroup: Mutex::new(direct_cgroup),
            pod_dir: pod_dir.to_path_buf(),
            jail: Mutex::new(jail_layout.clone()),
            child,
            bridge: Mutex::new(Some(bridge)),
            signed_proxy: Mutex::new(signed_proxy),
            permit: Mutex::new(permit),
            net_plan: Mutex::new(net_plan),
            netns: Mutex::new(netns_name),
            dns_proxy: Mutex::new(dns_proxy),
            drift_monitor: Mutex::new(drift_monitor),
            drift_stop,
            network_allocator: state.network_allocator.clone(),
            identity: pod_identity,
            identity_registry_key: identity_registry_key.clone(),
            identity_manager,
            workload_api_bridge: Mutex::new(workload_api_bridge),
            broker: Mutex::new(broker),
            decide: Mutex::new(decide),
            snapshot: verdict.found().map(|v| config.snapshot_inputs(v)),
        };

        info!("spawned firecracker pod {}", id);

        // The pod owns its namespace from here; the reaper tears it down when
        // the pod exits. This is the ONLY path that reaches this line, so it is
        // the only place the guard should stand down.
        if let Some(guard) = netns_guard.take() {
            guard.disarm();
        }

        Ok((
            DriverState::Firecracker(Box::new(handle)),
            Some(proxy_addr),
            log_path,
        ))
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn cleanup_net_resources(
    allocator: &net::NetworkAllocator,
    net_plan: &mut Option<net::NetPlan>,
    netns_name: &mut Option<String>,
    dns_proxy: &mut Option<net::DnsProxyState>,
    // The jail is torn down here rather than at each abort site ON PURPOSE. Every
    // post-spawn failure path already funnels through this function, so threading
    // the jail through it means a new abort path cannot forget to remove the jail:
    // it will not compile without saying what to do about it.
    jail: Option<&firecracker_config::JailLayout>,
) {
    if let Some(mut proxy) = dns_proxy.take() {
        let _ = proxy.child.kill().await;
    }
    if let Some(plan) = net_plan.take() {
        // Release the index back to the pool for reuse
        allocator.release(plan.index);
        let _ = net::cleanup_network(&plan).await;
    } else if let Some(name) = netns_name.take() {
        let _ = net::cleanup_netns(&name).await;
    }
    // Last, and after the VMM has been killed by the caller: removing files out
    // from under a live Firecracker is its own kind of bad.
    if let Some(layout) = jail {
        firecracker_config::cleanup_jail(layout);
    }
}

#[cfg(feature = "local-driver")]
async fn wait_for_announce(
    announce_path: &Path,
    child: &mut tokio::process::Child,
) -> Option<String> {
    let wait_result = timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(addr) = tokio::fs::read_to_string(announce_path).await {
                let trimmed = addr.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    error!("tool proxy exited early: {:?}", status);
                    return None;
                }
                Ok(None) => {}
                Err(err) => {
                    error!("tool proxy wait error: {err}");
                    return None;
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    wait_result.unwrap_or_default()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_firecracker_pool(args: &Args) -> Option<Arc<Semaphore>> {
    if !matches!(&args.driver, DriverKind::Firecracker) || args.firecracker_max_pods == 0 {
        return None;
    }
    Some(Arc::new(Semaphore::new(args.firecracker_max_pods)))
}

fn start_pod_reaper(state: NodeState) {
    tokio::spawn(async move {
        let mut reaped = std::collections::HashSet::new();
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            reap_once(&state, &mut reaped).await;
        }
    });
}

/// One pass of the pod reaper.
///
/// `reaped` is the reaper's own record of the pods it has already handled, and the
/// one thing that decides it. Exited pods stay in the registry (their status, logs
/// and receipts are still served), so without it every pass redid the exit: another
/// `pod_exited` lifecycle audit entry every 10 s — six for one exit on a live node —
/// and another identity release, which warned that the registry keys had drifted
/// apart because the first release had already removed them. The cascade is NOT
/// gated on it: a running child of any exited parent is cancelled on every pass, so
/// a cascade that failed is retried.
async fn reap_once(state: &NodeState, reaped: &mut std::collections::HashSet<Uuid>) {
    let pods: Vec<Arc<PodHandle>> = {
        let guard = state.pods.lock().await;
        guard.values().cloned().collect()
    };
    // Forget pods no longer registered, so the set is bounded by the registry.
    reaped.retain(|id| pods.iter().any(|p| p.id == *id));

    if pods.is_empty() {
        return;
    }

    // Collect IDs of exited/errored pods for cascading cancel
    let mut exited_ids = Vec::new();

    for pod in &pods {
        let pod_state = pod.status().await;
        if matches!(pod_state, PodState::Exited { .. } | PodState::Error { .. }) {
            exited_ids.push(pod.id);
            if !reaped.insert(pod.id) {
                continue;
            }
            // Write lifecycle audit for pod exit
            let detail = match &pod_state {
                PodState::Exited { code } => format!("exit_code={}", code.unwrap_or(-1)),
                PodState::Error { message } => format!("error={message}"),
                _ => "unknown".to_string(),
            };
            let pod_dir = pod.log_path.parent().unwrap_or(Path::new("."));
            lifecycle::write_lifecycle_audit(pod_dir, "pod_exited", &pod.id.to_string(), &detail)
                .await;

            pod.cleanup_after_exit().await;
            let guest_spend =
                clearing_receipt_collector::guest_reported_spend(pod_dir, &pod.id.to_string());
            tracing::debug!(pod = %pod.id, ?guest_spend, "guest-reported spend; no budget credit");
            state.authority.release_child(pod.id).await;
        }
    }

    // Cascade cancel: kill children of exited parent pods
    if !exited_ids.is_empty() {
        for pod in &pods {
            if let Some(parent_id) = pod.parent_pod_id
                && exited_ids.contains(&parent_id)
            {
                let child_state = pod.status().await;
                if matches!(child_state, PodState::Running) {
                    info!(
                        "cascading cancel: killing child pod {} (parent {} exited)",
                        pod.id, parent_id
                    );
                    if let Err(e) = pod.cancel().await {
                        error!("failed to cascade cancel pod {}: {}", pod.id, e);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "vsock.wait"))]
async fn wait_for_vsock_socket(path: &Path) -> Result<(), ApiError> {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if tokio::fs::metadata(path).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ApiError::Driver(format!(
        "vsock socket not found at {}",
        path.display()
    )))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// How long to wait for the guest's tool-proxy to answer.
///
/// # Why this is not five seconds any more
///
/// Five was chosen when the guest could prove itself with material already on
/// its kernel command line: boot, read the cmdline, serve. The guest now fetches
/// its SVID **and** its session token from the host over vsock before it serves
/// anything, so its readiness includes two host round-trips that did not exist
/// when the budget was set.
///
/// Measured on real hardware: with the budget at five seconds the node started
/// the workload API bridge and tore it down 5.08s later, having never seen the
/// guest — the guest was still starting, and the log showed it had successfully
/// fetched both artifacts. The launch failed with "proxy health check timed out"
/// for a pod that was working.
///
/// Tunable because the right value depends on the image: a heavier rootfs boots
/// slower, and an operator who knows theirs should not have to patch the node.
///
/// # This is necessary but NOT sufficient, and saying so matters
///
/// Raising it to thirty did not make the launch succeed. The guest reaches a
/// healthy state — the pod log shows it fetching its SVID and its session token
/// and then serving, with no error — and the check still times out, so something
/// in the HOST chain (signed proxy to vsock bridge to guest) is not completing.
/// That is a separate defect and is not yet isolated.
///
/// The budget change stands on its own: five seconds predates the guest doing
/// host round-trips during startup, and would be wrong even once the host chain
/// is fixed. It is not a workaround for that defect and should not be read as
/// one.
pub(crate) use nucleus_spec::boot_budget::PROXY_HEALTH_TIMEOUT_SECS_DEFAULT;

async fn serve_grpc(
    state: NodeState,
    listen: String,
    tls_config: grpc_tls::GrpcTlsConfig,
) -> Result<(), ApiError> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| ApiError::Driver(format!("invalid grpc listen addr: {e}")))?;
    // Every caller building `tls_config` from `--grpc-tls-cert`/`--grpc-tls-key`
    // must also pass `--grpc-tls-ca` (enforced at the call site building this
    // value) or the self-issued default (always mTLS, see
    // `GrpcTlsConfig::from_node_identity`) — so this is always true in
    // practice. Asserted rather than assumed: HMAC has no fallback any more
    // (Move B), so a caller lacking a client cert would otherwise be
    // silently unauthenticatable instead of loudly refused at startup.
    let mtls_enabled = tls_config.mtls_enabled();
    if !mtls_enabled {
        return Err(ApiError::Driver(
            "gRPC TLS is configured without a client CA (--grpc-tls-ca) — with no HMAC \
             fallback, no caller could ever authenticate. Pass --grpc-tls-ca, or omit \
             --grpc-tls-cert/--grpc-tls-key to use the self-issued mTLS default."
                .to_string(),
        ));
    }

    let service =
        NodeServiceServer::with_interceptor(GrpcService { state }, move |mut req: Request<()>| {
            let auth_ctx = auth::authenticate_grpc_request(&req)
                .map_err(|e| Status::unauthenticated(e.to_string()))?;

            // Store the auth context in request extensions for use in handlers
            req.extensions_mut().insert(auth_ctx);

            Ok(req)
        });

    let server_tls_config = tls_config.build_server_tls_config();
    let mut server = tonic::transport::Server::builder()
        .tls_config(server_tls_config)
        .map_err(|e| ApiError::Driver(format!("gRPC TLS setup failed: {e}")))?;

    info!("nucleus-node grpc listening on {} (mTLS)", addr);

    server
        .add_service(service)
        .serve(addr)
        .await
        .map_err(|e| ApiError::Driver(format!("grpc serve failed: {e}")))?;
    Ok(())
}

#[derive(Clone)]
struct GrpcService {
    state: NodeState,
}

#[tonic::async_trait]
impl NodeService for GrpcService {
    async fn create_pod(
        &self,
        request: Request<proto::CreatePodRequest>,
    ) -> Result<GrpcResponse<proto::CreatePodResponse>, Status> {
        // Check authorization
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::CreatePod,
        )?;

        // WHO is calling: the SPIFFE peer the interceptor verified. A pod's own
        // SVID identifies it as a pod; the unauthenticated parent header is
        // consulted only for callers that are not pods (same rule as HTTP).
        let auth_ctx = auth::get_auth_context(&request)
            .cloned()
            .ok_or_else(|| Status::unauthenticated("no authenticated peer"))?;
        let admission =
            pod_authority::Admission::from_grpc(&self.state.authz_policy, &auth_ctx, &request);
        // The resolver HTTP uses, on the peer `admission` read: no token here.
        let policy = &self.state.authz_policy;
        let scope = policy
            .caller_scope(None, &auth_ctx.spiffe_id)
            .map_err(|e| Status::permission_denied(e.to_string()))?;
        let named = request
            .metadata()
            .get(PARENT_HEADER)
            .and_then(|v| v.to_str().ok());
        let parent_pod_id = pod_api::parent_for_create(&self.state, &scope, named)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        let yaml = request.into_inner().yaml;
        if yaml.trim().is_empty() {
            return Err(Status::invalid_argument("missing pod spec yaml"));
        }

        let spec: PodSpec = serde_yaml::from_str(&yaml)
            .map_err(|e| Status::invalid_argument(format!("invalid yaml: {e}")))?;
        let (id, proxy_addr) = create_pod_internal(
            &self.state,
            spec,
            parent_pod_id,
            Some(yaml.clone()),
            admission,
        )
        .await
        .map_err(|e| match e {
            ApiError::Authority(_) | ApiError::Authorization(_) => {
                Status::permission_denied(e.to_string())
            }
            other => Status::internal(other.to_string()),
        })?;

        Ok(GrpcResponse::new(proto::CreatePodResponse {
            id: id.to_string(),
            proxy_addr: proxy_addr.unwrap_or_default(),
        }))
    }

    async fn list_pods(
        &self,
        request: Request<proto::Empty>,
    ) -> Result<GrpcResponse<proto::ListPodsResponse>, Status> {
        // Check authorization
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::ListPods,
        )?;

        // Scoped to the calling pod exactly as the HTTP listing is (#2475).
        let caller = pod_api::grpc_caller(&self.state, request.metadata(), request.extensions())?;
        let infos = pod_api::collect_pod_infos(&self.state, &caller).await;
        let pods = infos.into_iter().map(pod_info_to_grpc).collect();
        Ok(GrpcResponse::new(proto::ListPodsResponse { pods }))
    }

    async fn pod_logs(
        &self,
        request: Request<proto::PodId>,
    ) -> Result<GrpcResponse<proto::PodLogsResponse>, Status> {
        // Check authorization
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::StreamLogs,
        )?;

        let (md, ext, req) = request.into_parts();
        let pod = pod_api::grpc_scoped_pod(&self.state, &md, &ext, &req.id).await?;
        let logs = tokio::fs::read_to_string(&pod.log_path)
            .await
            .unwrap_or_default();
        Ok(GrpcResponse::new(proto::PodLogsResponse { logs }))
    }

    async fn cancel_pod(
        &self,
        request: Request<proto::PodId>,
    ) -> Result<GrpcResponse<proto::CancelPodResponse>, Status> {
        // Check authorization
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::CancelPod,
        )?;

        let (md, ext, req) = request.into_parts();
        let pod = pod_api::grpc_scoped_pod(&self.state, &md, &ext, &req.id).await?;
        pod.cancel()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(GrpcResponse::new(proto::CancelPodResponse {
            status: "cancelled".to_string(),
        }))
    }

    async fn get_pod(
        &self,
        request: Request<proto::GetPodRequest>,
    ) -> Result<GrpcResponse<proto::GetPodResponse>, Status> {
        // Check authorization
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::GetPod,
        )?;

        let (md, ext, req) = request.into_parts();
        let handle = pod_api::grpc_scoped_pod(&self.state, &md, &ext, &req.pod_id).await?;
        let info = handle.info().await;
        Ok(GrpcResponse::new(proto::GetPodResponse {
            pod: Some(pod_info_to_grpc(info)),
        }))
    }

    type StreamPodLogsStream = ReceiverStream<Result<proto::LogEntry, Status>>;

    async fn stream_pod_logs(
        &self,
        request: Request<proto::StreamLogsRequest>,
    ) -> Result<GrpcResponse<Self::StreamPodLogsStream>, Status> {
        // Check authorization
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::StreamLogs,
        )?;

        let (md, ext, req) = request.into_parts();
        let pod = pod_api::grpc_scoped_pod(&self.state, &md, &ext, &req.pod_id).await?;

        let log_path = pod.log_path.clone();
        let follow = req.follow;
        let offset_bytes = req.offset_bytes;

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        // Spawn task to stream logs
        tokio::spawn(async move {
            if let Err(e) = stream_logs_to_channel(log_path, offset_bytes, follow, tx).await {
                error!("log streaming error: {e}");
            }
        });

        Ok(GrpcResponse::new(ReceiverStream::new(rx)))
    }

    type WatchPodStateStream = ReceiverStream<Result<proto::PodStateChange, Status>>;

    async fn watch_pod_state(
        &self,
        request: Request<proto::WatchPodRequest>,
    ) -> Result<GrpcResponse<Self::WatchPodStateStream>, Status> {
        // Check authorization (watching state is similar to getting pod info)
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::GetPod,
        )?;

        let (md, ext, req) = request.into_parts();
        let pod = pod_api::grpc_scoped_pod(&self.state, &md, &ext, &req.pod_id).await?;
        let id = pod.id;

        let include_initial = req.include_initial;
        let pod_id_str = id.to_string();

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Spawn task to watch pod state
        tokio::spawn(async move {
            if let Err(e) = watch_pod_state_to_channel(pod, pod_id_str, include_initial, tx).await {
                error!("pod state watching error: {e}");
            }
        });

        Ok(GrpcResponse::new(ReceiverStream::new(rx)))
    }

    async fn get_receipt(
        &self,
        request: Request<proto::GetReceiptRequest>,
    ) -> Result<GrpcResponse<proto::GetReceiptResponse>, Status> {
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::GetReceipt,
        )?;

        let (md, ext, req) = request.into_parts();
        let pod_id_str = req.pod_id;
        let handle = pod_api::grpc_scoped_pod(&self.state, &md, &ext, &pod_id_str).await?;

        let built = pod_receipt::build(&handle, &self.state.authority)
            .await
            .map_err(|e| match e {
                pod_receipt::ReceiptError::NotExited => Status::failed_precondition(e.to_string()),
                pod_receipt::ReceiptError::NoExitReport(_) => Status::not_found(e.to_string()),
                pod_receipt::ReceiptError::Malformed(_) => Status::internal(e.to_string()),
            })?;
        // The outward-facing report stays on this transport only; see `pod_receipt`'s module docs
        // for why the HTTP route deliberately does not inherit it.
        pod_receipt::report_to_trust_gate(&self.state, &built);
        let r = built.receipt;

        Ok(GrpcResponse::new(proto::GetReceiptResponse {
            receipt: Some(r.into()),
        }))
    }

    async fn lockdown(
        &self,
        request: Request<proto::LockdownRequest>,
    ) -> Result<GrpcResponse<proto::LockdownResponse>, Status> {
        // Issuing and lifting are both operator actions: see `auth::Operation::Lockdown`.
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::Lockdown,
        )?;

        let (operator, req) = lockdown::attributed(request)?;
        Ok(GrpcResponse::new(
            lockdown::issue(&self.state, operator, req).await,
        ))
    }

    type WatchLockdownStream = ReceiverStream<Result<proto::LockdownCommand, Status>>;

    async fn watch_lockdown(
        &self,
        request: Request<tonic::Streaming<proto::LockdownAck>>,
    ) -> Result<GrpcResponse<Self::WatchLockdownStream>, Status> {
        auth::authorize_grpc_operation(
            &request,
            &self.state.authz_policy,
            auth::Operation::CancelPod,
        )?;

        // WHICH pod is watching, resolved as every other handler resolves it (a
        // pod peer is its own pod); anything unresolved still receives, fail-open.
        let watcher = pod_api::grpc_caller(&self.state, request.metadata(), request.extensions())
            .ok()
            .and_then(|scope| scope.pod());

        let mut ack_stream = request.into_inner();
        // `rx` is moved into the forwarder (which owns the `recv` loop and takes
        // `mut` internally), so it needs no `mut` here.
        let rx = self.state.lockdown_tx.subscribe();

        let (tx, grpc_rx) = tokio::sync::mpsc::channel(16);

        lockdown::spawn_filtered_forwarder(self.state.clone(), rx, tx, watcher);

        // ACK consumer: log acknowledgements from the tool-proxy
        tokio::spawn(async move {
            while let Ok(Some(ack)) = ack_stream.message().await {
                tracing::info!(
                    proxy_id = %ack.proxy_id,
                    applied = ack.applied,
                    ack_ts = ack.timestamp_unix,
                    "lockdown ACK received"
                );
            }
        });

        Ok(GrpcResponse::new(ReceiverStream::new(grpc_rx)))
    }
}

/// K8s-style label selector matching: "key=value,key2=value2".
/// All pairs must match (AND semantics). Empty selector matches all.
fn matches_label_selector(labels: &BTreeMap<String, String>, selector: &str) -> bool {
    if selector.is_empty() {
        return true;
    }
    selector.split(',').all(|pair| {
        let mut parts = pair.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(value)) => labels.get(key.trim()) == Some(&value.trim().to_string()),
            _ => false,
        }
    })
}

/// Stream log file contents to a channel
async fn stream_logs_to_channel(
    log_path: PathBuf,
    offset_bytes: u64,
    follow: bool,
    tx: tokio::sync::mpsc::Sender<Result<proto::LogEntry, Status>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file = tokio::fs::File::open(&log_path).await?;
    let mut reader = BufReader::new(file);

    // Seek to offset if specified
    if offset_bytes > 0 {
        reader.seek(std::io::SeekFrom::Start(offset_bytes)).await?;
    }

    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            if follow {
                // No more data, wait and try again
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            } else {
                // EOF and not following
                break;
            }
        }

        // Parse log level from line if it looks like structured log
        let level = if line.contains("\"level\":\"error\"") || line.contains("[ERROR]") {
            "error"
        } else if line.contains("\"level\":\"warn\"") || line.contains("[WARN]") {
            "warn"
        } else if line.contains("\"level\":\"debug\"") || line.contains("[DEBUG]") {
            "debug"
        } else {
            "info"
        };

        let entry = proto::LogEntry {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            line: line.trim_end().to_string(),
            level: level.to_string(),
        };

        if tx.send(Ok(entry)).await.is_err() {
            // Receiver dropped
            break;
        }
    }

    Ok(())
}

/// Watch pod state changes and send to channel
async fn watch_pod_state_to_channel(
    pod: Arc<PodHandle>,
    pod_id: String,
    include_initial: bool,
    tx: tokio::sync::mpsc::Sender<Result<proto::PodStateChange, Status>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut last_state = pod.status().await;

    // Send initial state if requested
    if include_initial {
        let (state_str, exit_code, error) = pod_state_to_strings(&last_state);
        let change = proto::PodStateChange {
            pod_id: pod_id.clone(),
            previous_state: String::new(),
            new_state: state_str,
            timestamp_unix: now_unix(),
            exit_code,
            error,
        };
        if tx.send(Ok(change)).await.is_err() {
            return Ok(());
        }
    }

    // Poll for state changes
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let current_state = pod.status().await;
        let state_changed = !states_equal(&last_state, &current_state);

        if state_changed {
            let (prev_str, _, _) = pod_state_to_strings(&last_state);
            let (new_str, exit_code, error) = pod_state_to_strings(&current_state);

            let change = proto::PodStateChange {
                pod_id: pod_id.clone(),
                previous_state: prev_str,
                new_state: new_str.clone(),
                timestamp_unix: now_unix(),
                exit_code,
                error,
            };

            if tx.send(Ok(change)).await.is_err() {
                // Receiver dropped
                break;
            }

            // If pod has exited or errored, stop watching
            if matches!(
                current_state,
                PodState::Exited { .. } | PodState::Error { .. }
            ) {
                break;
            }

            last_state = current_state;
        }
    }

    Ok(())
}

fn pod_state_to_strings(state: &PodState) -> (String, i32, String) {
    match state {
        PodState::Running => ("running".to_string(), 0, String::new()),
        PodState::Exited { code } => ("exited".to_string(), code.unwrap_or(-1), String::new()),
        PodState::Error { message } => ("error".to_string(), -1, message.clone()),
    }
}

fn states_equal(a: &PodState, b: &PodState) -> bool {
    match (a, b) {
        (PodState::Running, PodState::Running) => true,
        (PodState::Exited { code: a }, PodState::Exited { code: b }) => a == b,
        (PodState::Error { message: a }, PodState::Error { message: b }) => a == b,
        _ => false,
    }
}

fn pod_info_to_grpc(info: PodInfo) -> proto::PodInfo {
    let (state, exit_code, error) = match info.state {
        PodState::Running => ("running".to_string(), 0, String::new()),
        PodState::Exited { code } => ("exited".to_string(), code.unwrap_or(-1), String::new()),
        PodState::Error { message } => ("error".to_string(), -1, message),
    };

    proto::PodInfo {
        id: info.id.to_string(),
        name: info.name.unwrap_or_default(),
        created_at_unix: info.created_at_unix,
        state,
        exit_code,
        error,
        proxy_addr: info.proxy_addr.unwrap_or_default(),
        labels: info.labels.into_iter().collect(),
    }
}

// Firecracker VM configuration lives in firecracker_config.rs

#[cfg(test)]
#[path = "tests_main.rs"]
mod tests;
