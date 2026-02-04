use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use clap::{Parser, ValueEnum};
use nucleus_client::drand::{DrandConfig, DrandFailMode};
#[cfg(target_os = "linux")]
use nucleus_spec::NetworkSpec;
use nucleus_spec::PodSpec;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response as GrpcResponse, Status};
use tracing::{error, info};
use uuid::Uuid;

mod auth;
mod identity;
mod workload_api_vsock;
use auth::{AuthConfig, AuthError};
mod cgroup;
mod net;
mod signed_proxy;
mod vsock_bridge;

pub mod proto {
    tonic::include_proto!("nucleus.node.v1");
}

use proto::node_service_server::{NodeService, NodeServiceServer};

#[derive(Parser, Debug)]
#[command(name = "nucleus-node")]
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
    /// Driver backend.
    #[arg(
        long,
        env = "NUCLEUS_NODE_DRIVER",
        value_enum,
        default_value = "firecracker"
    )]
    driver: DriverKind,
    /// Allow the local driver (no VM isolation).
    #[arg(long, env = "NUCLEUS_ALLOW_LOCAL_DRIVER", default_value_t = false)]
    allow_local_driver: bool,
    /// Path to the nucleus-tool-proxy binary (local driver).
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_PATH",
        default_value = "nucleus-tool-proxy"
    )]
    tool_proxy_path: PathBuf,
    /// Path to firecracker binary (firecracker driver).
    #[arg(long, env = "NUCLEUS_FIRECRACKER_PATH", default_value = "firecracker")]
    firecracker_path: PathBuf,
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
    /// Shared secret for HMAC request signing.
    #[arg(long, env = "NUCLEUS_NODE_AUTH_SECRET")]
    auth_secret: String,
    /// Maximum allowed clock skew (seconds) for signed requests.
    #[arg(long, env = "NUCLEUS_NODE_AUTH_MAX_SKEW_SECS", default_value_t = 60)]
    auth_max_skew_secs: u64,
    /// Shared secret for signing tool-proxy requests from the host.
    #[arg(long, env = "NUCLEUS_NODE_PROXY_AUTH_SECRET")]
    proxy_auth_secret: String,
    /// Secret for signing approval requests (separate from tool auth).
    #[arg(long, env = "NUCLEUS_NODE_PROXY_APPROVAL_SECRET")]
    proxy_approval_secret: String,
    /// Default actor to use when signing proxy requests.
    #[arg(long, env = "NUCLEUS_NODE_PROXY_ACTOR", default_value = "nucleus-node")]
    proxy_actor: String,
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
}

#[derive(Clone, Debug, ValueEnum)]
enum DriverKind {
    Local,
    Firecracker,
}

#[derive(Clone)]
struct NodeState {
    pods: Arc<Mutex<HashMap<Uuid, Arc<PodHandle>>>>,
    state_dir: PathBuf,
    driver: DriverKind,
    tool_proxy_path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_pool: Option<Arc<Semaphore>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_netns: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_netns_drift_check: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    firecracker_netns_drift_interval: Duration,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    network_allocator: Arc<net::NetworkAllocator>,
    auth: AuthConfig,
    proxy_auth_secret: String,
    proxy_approval_secret: String,
    proxy_actor: Option<String>,
    /// Drand configuration for anchoring approval signatures.
    drand_config: Option<DrandConfig>,
    /// Identity manager for SPIFFE certificates (experimental, not yet wired to Firecracker).
    #[allow(dead_code)]
    identity_manager: Option<identity::IdentityManager>,
    /// Vsock port for guest-to-host Workload API connections.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    identity_vsock_port: u32,
}

#[derive(Debug)]
struct PodHandle {
    id: Uuid,
    spec: PodSpec,
    created_at: u64,
    log_path: PathBuf,
    proxy_addr: Mutex<Option<String>>,
    driver_state: DriverState,
}

#[derive(Debug)]
enum DriverState {
    Local(Box<LocalPod>),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Firecracker(Box<FirecrackerPod>),
}

#[derive(Debug)]
struct LocalPod {
    child: Mutex<tokio::process::Child>,
    signed_proxy: Mutex<Option<signed_proxy::SignedProxy>>,
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct FirecrackerPod {
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
    /// Workload API vsock bridge for this pod
    workload_api_bridge: Mutex<Option<workload_api_vsock::WorkloadApiVsockBridge>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum PodState {
    Running,
    Exited { code: Option<i32> },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize)]
struct PodInfo {
    id: Uuid,
    name: Option<String>,
    created_at_unix: u64,
    state: PodState,
    proxy_addr: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreatePodResponse {
    id: Uuid,
    proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreatePodRequest {
    #[serde(default)]
    spec: Option<PodSpec>,
    #[serde(default)]
    yaml: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("invalid spec: {0}")]
    InvalidSpec(String),
    #[error("pod not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("driver error: {0}")]
    Driver(String),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("request body error: {0}")]
    Body(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> AxumResponse {
        let status = match self {
            ApiError::InvalidSpec(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Serde(_) => StatusCode::BAD_REQUEST,
            ApiError::Driver(_) => StatusCode::BAD_REQUEST,
            ApiError::Auth(_) => StatusCode::UNAUTHORIZED,
            ApiError::Body(_) => StatusCode::BAD_REQUEST,
        };
        let body = Json(ErrorBody {
            error: self.to_string(),
        });
        (status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
    tokio::fs::create_dir_all(&args.state_dir).await?;
    if matches!(args.driver, DriverKind::Local) && !args.allow_local_driver {
        return Err(ApiError::Driver(
            "local driver disabled; pass --allow-local-driver to run without VM isolation"
                .to_string(),
        ));
    }
    if args.auth_secret.trim().is_empty() {
        return Err(ApiError::Driver(
            "node auth secret is required (set NUCLEUS_NODE_AUTH_SECRET)".to_string(),
        ));
    }
    if args.proxy_auth_secret.trim().is_empty() {
        return Err(ApiError::Driver(
            "proxy auth secret is required (set NUCLEUS_NODE_PROXY_AUTH_SECRET)".to_string(),
        ));
    }
    if args.proxy_approval_secret.trim().is_empty() {
        return Err(ApiError::Driver(
            "proxy approval secret is required (set NUCLEUS_NODE_PROXY_APPROVAL_SECRET)"
                .to_string(),
        ));
    }

    // Initialize identity manager (optional, enabled if socket path is specified)
    let identity_manager = if let Some(ref socket_path) = args.identity_workload_api_socket {
        let cert_ttl = Duration::from_secs(args.identity_cert_ttl_secs);
        let manager = identity::IdentityManager::new(&args.identity_trust_domain, cert_ttl)
            .map_err(|e| ApiError::Driver(format!("failed to create identity manager: {e}")))?;

        // Start the Workload API server
        manager
            .start_workload_api_server(socket_path)
            .await
            .map_err(|e| ApiError::Driver(format!("failed to start workload API: {e}")))?;

        // Start certificate refresh loop
        manager.start_refresh_loop();

        info!(
            "identity manager initialized with trust domain '{}', workload API at {}",
            args.identity_trust_domain,
            socket_path.display()
        );
        Some(manager)
    } else {
        None
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

    let state = NodeState {
        pods: Arc::new(Mutex::new(HashMap::new())),
        state_dir: args.state_dir.clone(),
        driver: args.driver.clone(),
        tool_proxy_path: args.tool_proxy_path.clone(),
        firecracker_path: args.firecracker_path.clone(),
        firecracker_pool: build_firecracker_pool(&args),
        firecracker_netns: args.firecracker_netns,
        firecracker_netns_drift_check: args.firecracker_netns_drift_check,
        firecracker_netns_drift_interval: Duration::from_secs(
            args.firecracker_netns_drift_interval_secs,
        ),
        network_allocator: Arc::new(net::NetworkAllocator::new()),
        auth: AuthConfig::new(
            args.auth_secret.as_bytes(),
            Duration::from_secs(args.auth_max_skew_secs),
        ),
        proxy_auth_secret: args.proxy_auth_secret.clone(),
        proxy_approval_secret: args.proxy_approval_secret.clone(),
        proxy_actor: Some(args.proxy_actor.clone()).filter(|actor| !actor.trim().is_empty()),
        drand_config,
        identity_manager,
        identity_vsock_port: args.identity_workload_api_vsock_port,
    };

    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/pods", post(create_pod).get(list_pods))
        .route("/v1/pods/{id}/logs", get(pod_logs))
        .route("/v1/pods/{id}/cancel", post(cancel_pod))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    if let Some(grpc_listen) = args.grpc_listen.clone() {
        let grpc_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_grpc(grpc_state, grpc_listen).await {
                error!("grpc server error: {err}");
            }
        });
    }

    start_pod_reaper(state.clone());

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!("nucleus-node listening on {}", args.listen);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn create_pod(
    State(state): State<NodeState>,
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

    let (id, proxy_addr) = create_pod_internal(&state, spec).await?;

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
    let context = auth::verify_http(&parts.headers, &bytes, &state.auth)?;
    let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(context);
    Ok(next.run(req).await)
}

async fn create_pod_internal(
    state: &NodeState,
    spec: PodSpec,
) -> Result<(Uuid, Option<String>), ApiError> {
    let id = Uuid::new_v4();
    let created_at = now_unix();
    let pod_dir = state.state_dir.join("pods").join(id.to_string());
    tokio::fs::create_dir_all(&pod_dir).await?;

    let (driver_state, proxy_addr, log_path) = match state.driver {
        DriverKind::Local => spawn_local_pod(state, &pod_dir, &spec, id).await?,
        DriverKind::Firecracker => spawn_firecracker_pod(state, &pod_dir, &spec, id).await?,
    };

    let handle = Arc::new(PodHandle {
        id,
        spec,
        created_at,
        log_path,
        proxy_addr: Mutex::new(proxy_addr.clone()),
        driver_state,
    });

    state.pods.lock().await.insert(id, handle);

    Ok((id, proxy_addr))
}

async fn list_pods(State(state): State<NodeState>) -> Result<Json<Vec<PodInfo>>, ApiError> {
    let infos = collect_pod_infos(&state).await;
    Ok(Json(infos))
}

async fn collect_pod_infos(state: &NodeState) -> Vec<PodInfo> {
    let pods: Vec<Arc<PodHandle>> = {
        let guard = state.pods.lock().await;
        guard.values().cloned().collect()
    };

    let mut infos = Vec::with_capacity(pods.len());
    for pod in pods {
        infos.push(pod.info().await);
    }

    infos
}

async fn pod_logs(
    State(state): State<NodeState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<String, ApiError> {
    let pod = get_pod(&state, id).await?;
    let logs = tokio::fs::read_to_string(&pod.log_path)
        .await
        .unwrap_or_default();
    Ok(logs)
}

async fn cancel_pod(
    State(state): State<NodeState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pod = get_pod(&state, id).await?;
    pod.cancel().await?;
    Ok(Json(serde_json::json!({"status": "cancelled"})))
}

async fn get_pod(state: &NodeState, id: Uuid) -> Result<Arc<PodHandle>, ApiError> {
    let guard = state.pods.lock().await;
    guard.get(&id).cloned().ok_or(ApiError::NotFound)
}

impl PodHandle {
    async fn info(&self) -> PodInfo {
        let state = self.status().await;
        let proxy_addr = self.proxy_addr.lock().await.clone();
        PodInfo {
            id: self.id,
            name: self.spec.metadata.name.clone(),
            created_at_unix: self.created_at,
            state,
            proxy_addr,
        }
    }

    async fn status(&self) -> PodState {
        match &self.driver_state {
            DriverState::Local(local) => local.status().await,
            DriverState::Firecracker(firecracker) => firecracker.status().await,
        }
    }

    async fn cancel(&self) -> Result<(), ApiError> {
        match &self.driver_state {
            DriverState::Local(local) => local.cancel().await,
            DriverState::Firecracker(firecracker) => firecracker.cancel().await,
        }
    }

    async fn cleanup_after_exit(&self) {
        match &self.driver_state {
            DriverState::Local(local) => local.cleanup().await,
            DriverState::Firecracker(firecracker) => firecracker.cleanup().await,
        }
    }
}

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

    async fn cancel(&self) -> Result<(), ApiError> {
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        let mut child = self.child.lock().await;
        child.kill().await.map_err(ApiError::Io)?;
        Ok(())
    }

    async fn cleanup(&self) {
        // Nothing to clean up for local pods beyond process exit.
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

    async fn cancel(&self) -> Result<(), ApiError> {
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
        let mut child = self.child.lock().await;
        child.kill().await.map_err(ApiError::Io)?;
        Ok(())
    }

    async fn cleanup(&self) {
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
    }

    /// Cleans up identity resources (unregister from VM registry, forget certificate).
    async fn cleanup_identity(&self) {
        // Shut down workload API bridge
        if let Some(bridge) = self.workload_api_bridge.lock().await.take() {
            bridge.shutdown().await;
        }

        if let (Some(ref identity), Some(ref manager)) = (&self.identity, &self.identity_manager) {
            manager.unregister_pod(&identity.to_spiffe_uri()).await;
            manager.forget_certificate(identity).await;
        }
    }
}

async fn spawn_local_pod(
    state: &NodeState,
    pod_dir: &Path,
    spec: &PodSpec,
    id: Uuid,
) -> Result<(DriverState, Option<String>, PathBuf), ApiError> {
    let spec_path = pod_dir.join("pod.yaml");
    let log_path = pod_dir.join("pod.log");
    let announce_path = pod_dir.join("proxy.addr");

    let spec_yaml = serde_yaml::to_string(spec).map_err(ApiError::Serde)?;
    tokio::fs::write(&spec_path, spec_yaml).await?;

    if spec.spec.network.is_some() {
        return Err(ApiError::Driver(
            "network policy requires firecracker driver".to_string(),
        ));
    }

    let log_stdout = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let mut command = Command::new(&state.tool_proxy_path);
    command
        .arg("--spec")
        .arg(&spec_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--announce-path")
        .arg(&announce_path);
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
            Some(Arc::new(state.proxy_approval_secret.as_bytes().to_vec())),
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

async fn spawn_firecracker_pod(
    state: &NodeState,
    pod_dir: &Path,
    spec: &PodSpec,
    id: Uuid,
) -> Result<(DriverState, Option<String>, PathBuf), ApiError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, pod_dir, spec, id);
        Err(ApiError::Driver(
            "firecracker requires Linux; run nucleus-node inside Colima on macOS".to_string(),
        ))
    }

    #[cfg(target_os = "linux")]
    {
        if !Path::new("/dev/kvm").exists() {
            return Err(ApiError::Driver(
                "firecracker requires /dev/kvm (KVM not available)".to_string(),
            ));
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

        let image = spec
            .spec
            .image
            .as_ref()
            .ok_or_else(|| ApiError::Driver("missing spec.image".to_string()))?;
        let vsock_spec = spec
            .spec
            .vsock
            .as_ref()
            .ok_or_else(|| ApiError::Driver("missing spec.vsock".to_string()))?;

        let mut net_plan: Option<net::NetPlan> = None;
        let mut netns_name: Option<String> = None;
        let mut dns_proxy: Option<net::DnsProxyState> = None;

        if state.firecracker_netns {
            let name = net::netns_name(id);
            net::create_netns(&name).await?;

            // Apply default-deny iptables policy BEFORE any process spawns.
            // This closes the race window where a process could exfiltrate
            // data before the full policy is applied.
            if let Err(err) = net::apply_default_deny(&name).await {
                let _ = net::cleanup_netns(&name).await;
                return Err(err);
            }
            netns_name = Some(name.clone());

            if let Some(network) = spec.spec.network.as_ref() {
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
        } else if spec.spec.network.is_some() {
            return Err(ApiError::Driver(
                "network policy requires --firecracker-netns=true".to_string(),
            ));
        }

        let log_path = pod_dir.join("firecracker.log");
        let config_path = pod_dir.join("firecracker.json");
        let vsock_path = pod_dir.join("vsock.sock");

        let workload_api_port = state
            .identity_manager
            .as_ref()
            .map(|_| state.identity_vsock_port);
        let config = FirecrackerConfig::from_spec(
            spec,
            &log_path,
            &vsock_path,
            image,
            net_plan.as_ref(),
            &state.proxy_auth_secret,
            &state.proxy_approval_secret,
            workload_api_port,
        );
        let config_json = match serde_json::to_vec_pretty(&config) {
            Ok(data) => data,
            Err(err) => {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                )
                .await;
                return Err(ApiError::Driver(format!("config serialize failed: {err}")));
            }
        };
        if let Err(err) = tokio::fs::write(&config_path, config_json).await {
            cleanup_net_resources(
                &state.network_allocator,
                &mut net_plan,
                &mut netns_name,
                &mut dns_proxy,
            )
            .await;
            return Err(ApiError::Driver(format!("config write failed: {err}")));
        }

        let log_stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|err| ApiError::Driver(format!("failed to open firecracker log: {err}")))?;
        let log_stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|err| ApiError::Driver(format!("failed to open firecracker log: {err}")))?;

        let mut command = if state.firecracker_netns {
            let Some(ref name) = netns_name else {
                return Err(ApiError::Driver(
                    "network namespace name missing".to_string(),
                ));
            };
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", name, "--"]);
            cmd.arg(&state.firecracker_path);
            cmd
        } else {
            Command::new(&state.firecracker_path)
        };
        command.arg("--config-file").arg(&config_path);
        apply_seccomp_flags(&mut command, spec)?;
        let mut child = match command.stdout(log_stdout).stderr(log_stderr).spawn() {
            Ok(child) => child,
            Err(err) => {
                cleanup_net_resources(
                    &state.network_allocator,
                    &mut net_plan,
                    &mut netns_name,
                    &mut dns_proxy,
                )
                .await;
                return Err(ApiError::Driver(format!(
                    "failed to spawn firecracker: {err}"
                )));
            }
        };
        let pid = child.id();
        let mut netns_baseline: Option<String> = None;
        let mut netns_pid: Option<u32> = None;

        if state.firecracker_netns {
            let default_policy = NetworkSpec {
                allow: Vec::new(),
                deny: Vec::new(),
                dns_allow: Vec::new(),
            };
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
                        )
                        .await;
                        return Err(err);
                    }
                }
            }
        }

        if let Some(ref cgroup_spec) = spec.spec.cgroup {
            if let Some(pid) = pid {
                cgroup::apply_cgroup(pid, cgroup_spec).await?;
            } else {
                return Err(ApiError::Driver(
                    "firecracker process id unavailable for cgroup placement".to_string(),
                ));
            }
        }

        if let Err(err) = wait_for_vsock_socket(&vsock_path).await {
            let _ = child.kill().await;
            cleanup_net_resources(
                &state.network_allocator,
                &mut net_plan,
                &mut netns_name,
                &mut dns_proxy,
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
            Some(Arc::new(state.proxy_approval_secret.as_bytes().to_vec())),
            state.proxy_actor.clone(),
            state.drand_config.clone(),
        )
        .await
        .map_err(|e| ApiError::Driver(format!("signed proxy failed: {e}")))?;
        proxy_addr = format!("http://{}", proxy.listen_addr());
        let health_addr = proxy.listen_addr();
        let signed_proxy = Some(proxy);

        if let Err(err) = wait_for_proxy_health(health_addr).await {
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

        // Create and register SPIFFE identity if identity management is enabled
        let (pod_identity, identity_manager, workload_api_bridge) =
            if let Some(ref manager) = state.identity_manager {
                // Use pod name or labels for namespace/service_account context
                // Since Metadata doesn't have namespace, we default to "default"
                let namespace = "default";
                let service_account = spec.metadata.name.as_deref().unwrap_or("");
                let identity = manager.identity_for_pod(id, namespace, service_account);

                // Register the pod identity
                manager.register_pod(id.to_string(), identity.clone()).await;

                // Compute launch attestation for this pod
                // This captures integrity measurements of kernel, rootfs, and config
                let pod_id_str = id.to_string();
                let config_bytes = serde_json::to_vec(spec).unwrap_or_default();
                match manager
                    .compute_attestation(
                        &pod_id_str,
                        &image.kernel_path,
                        &image.rootfs_path,
                        &config_bytes,
                    )
                    .await
                {
                    Ok(attestation) => {
                        info!(
                            "computed launch attestation for pod {}: {}",
                            id,
                            attestation.to_hex_summary()
                        );
                        // Fetch attested certificate (includes attestation in X.509 extension)
                        if let Err(e) = manager
                            .fetch_attested_certificate(&identity, &pod_id_str)
                            .await
                        {
                            tracing::warn!(
                                "failed to fetch attested certificate for pod {}: {}",
                                id,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                        "failed to compute attestation for pod {}, using standard certificate: {}",
                        id,
                        e
                    );
                        // Fall back to standard certificate without attestation
                        if let Err(e) = manager.prefetch_certificate(&identity).await {
                            tracing::warn!("failed to prefetch certificate for pod {}: {}", id, e);
                        }
                    }
                }

                // Start workload API vsock bridge for this pod
                // Uses Firecracker's naming convention: {vsock_uds_path}_{port}
                // Guest connects to CID 2 (host) on the workload API port via AF_VSOCK
                let bridge = match workload_api_vsock::WorkloadApiVsockBridge::start(
                    &vsock_path,
                    state.identity_vsock_port,
                    id,
                    manager.clone(),
                )
                .await
                {
                    Ok(b) => {
                        info!(
                            "started workload API vsock bridge at {} for pod {}",
                            b.socket_path().display(),
                            id
                        );
                        Some(b)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "failed to start workload API vsock bridge for pod {}: {}",
                            id,
                            e
                        );
                        None
                    }
                };

                info!(
                    "registered identity {} for pod {}",
                    identity.to_spiffe_uri(),
                    id
                );

                (Some(identity), Some(manager.clone()), bridge)
            } else {
                (None, None, None)
            };

        let handle = FirecrackerPod {
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
            identity_manager,
            workload_api_bridge: Mutex::new(workload_api_bridge),
        };

        info!("spawned firecracker pod {}", id);

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
}

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
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let pods: Vec<Arc<PodHandle>> = {
                let guard = state.pods.lock().await;
                guard.values().cloned().collect()
            };

            if pods.is_empty() {
                continue;
            }

            for pod in pods {
                let state = pod.status().await;
                if matches!(state, PodState::Exited { .. } | PodState::Error { .. }) {
                    pod.cleanup_after_exit().await;
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
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
async fn wait_for_proxy_health(addr: SocketAddr) -> Result<(), ApiError> {
    let start = std::time::Instant::now();
    let host = addr.ip();
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
            let request = format!(
                "GET /v1/health HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
            );
            if stream.write_all(request.as_bytes()).await.is_err() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).await.is_err() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let response = String::from_utf8_lossy(&buf);
            if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
                return Ok(());
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(ApiError::Driver("proxy health check timed out".to_string()))
}

async fn serve_grpc(state: NodeState, listen: String) -> Result<(), ApiError> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| ApiError::Driver(format!("invalid grpc listen addr: {e}")))?;
    let auth = state.auth.clone();
    let service =
        NodeServiceServer::with_interceptor(GrpcService { state }, move |req: Request<()>| {
            let method = req
                .metadata()
                .get("x-nucleus-method")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| Status::unauthenticated("missing x-nucleus-method"))?;
            auth::verify_grpc(req.metadata(), method, &auth)
                .map_err(|e| Status::unauthenticated(e.to_string()))?;
            Ok(req)
        });
    info!("nucleus-node grpc listening on {}", addr);
    tonic::transport::Server::builder()
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
        let yaml = request.into_inner().yaml;
        if yaml.trim().is_empty() {
            return Err(Status::invalid_argument("missing pod spec yaml"));
        }

        let spec: PodSpec = serde_yaml::from_str(&yaml)
            .map_err(|e| Status::invalid_argument(format!("invalid yaml: {e}")))?;
        let (id, proxy_addr) = create_pod_internal(&self.state, spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(GrpcResponse::new(proto::CreatePodResponse {
            id: id.to_string(),
            proxy_addr: proxy_addr.unwrap_or_default(),
        }))
    }

    async fn list_pods(
        &self,
        _request: Request<proto::Empty>,
    ) -> Result<GrpcResponse<proto::ListPodsResponse>, Status> {
        let infos = collect_pod_infos(&self.state).await;
        let pods = infos.into_iter().map(pod_info_to_grpc).collect();
        Ok(GrpcResponse::new(proto::ListPodsResponse { pods }))
    }

    async fn pod_logs(
        &self,
        request: Request<proto::PodId>,
    ) -> Result<GrpcResponse<proto::PodLogsResponse>, Status> {
        let id = Uuid::parse_str(&request.into_inner().id)
            .map_err(|_| Status::invalid_argument("invalid pod id"))?;
        let pod = get_pod(&self.state, id)
            .await
            .map_err(|_| Status::not_found("pod not found"))?;
        let logs = tokio::fs::read_to_string(&pod.log_path)
            .await
            .unwrap_or_default();
        Ok(GrpcResponse::new(proto::PodLogsResponse { logs }))
    }

    async fn cancel_pod(
        &self,
        request: Request<proto::PodId>,
    ) -> Result<GrpcResponse<proto::CancelPodResponse>, Status> {
        let id = Uuid::parse_str(&request.into_inner().id)
            .map_err(|_| Status::invalid_argument("invalid pod id"))?;
        let pod = get_pod(&self.state, id)
            .await
            .map_err(|_| Status::not_found("pod not found"))?;
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
        let id = Uuid::parse_str(&request.into_inner().pod_id)
            .map_err(|_| Status::invalid_argument("invalid pod id"))?;
        let handle = get_pod(&self.state, id)
            .await
            .map_err(|_| Status::not_found("pod not found"))?;
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
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.pod_id)
            .map_err(|_| Status::invalid_argument("invalid pod id"))?;
        let pod = get_pod(&self.state, id)
            .await
            .map_err(|_| Status::not_found("pod not found"))?;

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
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.pod_id)
            .map_err(|_| Status::invalid_argument("invalid pod id"))?;
        let pod = get_pod(&self.state, id)
            .await
            .map_err(|_| Status::not_found("pod not found"))?;

        let include_initial = req.include_initial;
        let pod_id_str = id.to_string();

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Spawn task to watch pod state
        tokio::spawn(async move {
            if let Err(e) =
                watch_pod_state_to_channel(pod, pod_id_str, include_initial, tx).await
            {
                error!("pod state watching error: {e}");
            }
        });

        Ok(GrpcResponse::new(ReceiverStream::new(rx)))
    }
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
            if matches!(current_state, PodState::Exited { .. } | PodState::Error { .. }) {
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
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct FirecrackerConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSource,
    drives: Vec<DriveConfig>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    #[serde(rename = "network-interfaces", skip_serializing_if = "Vec::is_empty")]
    network_interfaces: Vec<NetworkInterface>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vsock: Option<VsockConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logger: Option<LoggerConfig>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct BootSource {
    kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_args: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct DriveConfig {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct MachineConfig {
    vcpu_count: i64,
    mem_size_mib: i64,
    smt: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct NetworkInterface {
    iface_id: String,
    host_dev_name: String,
    guest_mac: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct LoggerConfig {
    log_path: String,
    level: String,
    show_level: bool,
    show_log_origin: bool,
}

#[cfg(target_os = "linux")]
impl FirecrackerConfig {
    #[allow(clippy::too_many_arguments)]
    fn from_spec(
        spec: &PodSpec,
        log_path: &Path,
        vsock_path: &Path,
        image: &nucleus_spec::ImageSpec,
        net_plan: Option<&net::NetPlan>,
        auth_secret: &str,
        approval_secret: &str,
        workload_api_port: Option<u32>,
    ) -> Self {
        let vcpu_count = spec
            .spec
            .resources
            .as_ref()
            .and_then(|r| r.cpu_cores)
            .unwrap_or(1) as i64;
        let mem_size_mib = spec
            .spec
            .resources
            .as_ref()
            .and_then(|r| r.memory_mib)
            .unwrap_or(512) as i64;

        let default_args = "console=ttyS0 reboot=k panic=1 pci=off init=/init".to_string();
        let mut boot_args = match image.boot_args.clone() {
            Some(args) => {
                if args.contains("init=") {
                    Some(args)
                } else {
                    Some(format!("{args} init=/init"))
                }
            }
            None => Some(default_args),
        };

        if let Some(plan) = net_plan {
            let extra = plan.kernel_arg();
            boot_args = match boot_args.take() {
                Some(args) if args.contains("nucleus.net=") => Some(args),
                Some(args) => Some(format!("{args} {extra}")),
                None => Some(extra),
            };
        }

        boot_args = match boot_args.take() {
            Some(args) if args.contains("ipv6.disable=") => Some(args),
            Some(args) => Some(format!("{args} ipv6.disable=1")),
            None => Some("ipv6.disable=1".to_string()),
        };

        // Inject secrets via kernel command line (read by nucleus-guest-init)
        // This is more secure than baking secrets into the rootfs image
        boot_args = match boot_args.take() {
            Some(args) => Some(format!(
                "{args} nucleus.auth_secret={auth_secret} nucleus.approval_secret={approval_secret}"
            )),
            None => Some(format!(
                "nucleus.auth_secret={auth_secret} nucleus.approval_secret={approval_secret}"
            )),
        };

        // Inject workload API port if identity management is enabled
        if let Some(port) = workload_api_port {
            boot_args = match boot_args.take() {
                Some(args) => Some(format!("{args} nucleus.workload_api_port={port}")),
                None => Some(format!("nucleus.workload_api_port={port}")),
            };
        }

        let vsock = spec.spec.vsock.as_ref().map(|vsock| VsockConfig {
            guest_cid: vsock.guest_cid,
            uds_path: vsock_path.display().to_string(),
        });

        let network_interfaces = match net_plan {
            Some(plan) => vec![NetworkInterface {
                iface_id: "eth0".to_string(),
                host_dev_name: plan.tap_name.clone(),
                guest_mac: plan.guest_mac.clone(),
            }],
            None => Vec::new(),
        };

        Self {
            boot_source: BootSource {
                kernel_image_path: image.kernel_path.display().to_string(),
                boot_args,
            },
            drives: build_drive_config(image),
            machine_config: MachineConfig {
                vcpu_count,
                mem_size_mib,
                smt: false,
            },
            network_interfaces,
            vsock,
            logger: Some(LoggerConfig {
                log_path: log_path.display().to_string(),
                level: "Info".to_string(),
                show_level: true,
                show_log_origin: false,
            }),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct VsockConfig {
    guest_cid: u32,
    uds_path: String,
}

#[cfg(target_os = "linux")]
fn build_drive_config(image: &nucleus_spec::ImageSpec) -> Vec<DriveConfig> {
    let mut drives = vec![DriveConfig {
        drive_id: "rootfs".to_string(),
        path_on_host: image.rootfs_path.display().to_string(),
        is_root_device: true,
        is_read_only: image.read_only,
    }];

    if let Some(ref scratch) = image.scratch_path {
        drives.push(DriveConfig {
            drive_id: "scratch".to_string(),
            path_on_host: scratch.display().to_string(),
            is_root_device: false,
            is_read_only: false,
        });
    }

    drives
}

#[cfg(target_os = "linux")]
fn apply_seccomp_flags(command: &mut Command, spec: &PodSpec) -> Result<(), ApiError> {
    if let Some(ref seccomp) = spec.spec.seccomp {
        match seccomp {
            nucleus_spec::SeccompSpec::Default => {}
            nucleus_spec::SeccompSpec::Disabled => {
                command.arg("--no-seccomp");
            }
            nucleus_spec::SeccompSpec::Custom { filter_path } => {
                command.arg("--seccomp-filter").arg(filter_path);
            }
        }
    }
    Ok(())
}
