use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use clap::{Parser, ValueEnum};
use nucleus_spec::PodSpec;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tonic::{Request, Response as GrpcResponse, Status};
use tracing::{error, info};
use uuid::Uuid;

mod auth;
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
    #[arg(long, env = "NUCLEUS_NODE_DRIVER", value_enum, default_value = "local")]
    driver: DriverKind,
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
    /// Shared secret for HMAC request signing.
    #[arg(long, env = "NUCLEUS_NODE_AUTH_SECRET")]
    auth_secret: Option<String>,
    /// Maximum allowed clock skew (seconds) for signed requests.
    #[arg(long, env = "NUCLEUS_NODE_AUTH_MAX_SKEW_SECS", default_value_t = 60)]
    auth_max_skew_secs: u64,
    /// Shared secret for signing tool-proxy requests from the host (optional).
    #[arg(long, env = "NUCLEUS_NODE_PROXY_AUTH_SECRET")]
    proxy_auth_secret: Option<String>,
    /// Default actor to use when signing proxy requests.
    #[arg(long, env = "NUCLEUS_NODE_PROXY_ACTOR", default_value = "nucleus-node")]
    proxy_actor: String,
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
    auth: Option<AuthConfig>,
    proxy_auth_secret: Option<String>,
    proxy_actor: Option<String>,
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
    Local(LocalPod),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Firecracker(FirecrackerPod),
}

#[derive(Debug)]
struct LocalPod {
    child: Mutex<tokio::process::Child>,
    signed_proxy: Mutex<Option<signed_proxy::SignedProxy>>,
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct FirecrackerPod {
    child: Mutex<tokio::process::Child>,
    bridge: Mutex<Option<vsock_bridge::VsockBridge>>,
    signed_proxy: Mutex<Option<signed_proxy::SignedProxy>>,
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

    let state = NodeState {
        pods: Arc::new(Mutex::new(HashMap::new())),
        state_dir: args.state_dir.clone(),
        driver: args.driver.clone(),
        tool_proxy_path: args.tool_proxy_path.clone(),
        firecracker_path: args.firecracker_path.clone(),
        auth: args.auth_secret.as_ref().map(|secret| {
            AuthConfig::new(
                secret.as_bytes(),
                Duration::from_secs(args.auth_max_skew_secs),
            )
        }),
        proxy_auth_secret: args.proxy_auth_secret.clone(),
        proxy_actor: Some(args.proxy_actor.clone()).filter(|actor| !actor.trim().is_empty()),
    };

    if state.auth.is_none() {
        info!("nucleus-node auth disabled (set NUCLEUS_NODE_AUTH_SECRET to enable)");
    }

    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/pods", post(create_pod).get(list_pods))
        .route("/v1/pods/:id/logs", get(pod_logs))
        .route("/v1/pods/:id/cancel", post(cancel_pod))
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
    if let Some(auth) = state.auth.as_ref() {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, MAX_AUTH_BODY_BYTES)
            .await
            .map_err(|e| ApiError::Body(e.to_string()))?;
        let context = auth::verify_http(&parts.headers, &bytes, auth)?;
        let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
        req.extensions_mut().insert(context);
        Ok(next.run(req).await)
    } else {
        Ok(next.run(request).await)
    }
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
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        if let Some(bridge) = self.bridge.lock().await.take() {
            bridge.shutdown().await;
        }
        let mut child = self.child.lock().await;
        child.kill().await.map_err(ApiError::Io)?;
        Ok(())
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

    if let Some(network) = spec.spec.network.as_ref() {
        net::apply_network_policy(pod_dir, Some(network)).await?;
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
    if let Some(secret) = state.proxy_auth_secret.as_ref() {
        command.env("NUCLEUS_TOOL_PROXY_AUTH_SECRET", secret);
    }
    let mut child = command
        .stdout(log_stdout)
        .stderr(log_stderr)
        .spawn()
        .map_err(|e| ApiError::Driver(format!("failed to spawn tool proxy: {e}")))?;

    let mut proxy_addr = wait_for_announce(&announce_path, &mut child).await;
    let mut signed_proxy = None;
    if let (Some(secret), Some(addr)) = (state.proxy_auth_secret.as_ref(), proxy_addr.as_ref()) {
        let target_addr: SocketAddr = addr
            .parse()
            .map_err(|e| ApiError::Driver(format!("invalid tool proxy address {addr}: {e}")))?;
        let proxy = signed_proxy::SignedProxy::start(
            target_addr,
            Arc::new(secret.as_bytes().to_vec()),
            state.proxy_actor.clone(),
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
    Ok((DriverState::Local(handle), proxy_addr, log_path))
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

        net::apply_network_policy(pod_dir, spec.spec.network.as_ref()).await?;

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

        let log_path = pod_dir.join("firecracker.log");
        let config_path = pod_dir.join("firecracker.json");
        let vsock_path = pod_dir.join("vsock.sock");

        let config = FirecrackerConfig::from_spec(spec, &log_path, &vsock_path, image);
        let config_json = serde_json::to_vec_pretty(&config)
            .map_err(|e| ApiError::Driver(format!("config serialize failed: {e}")))?;
        tokio::fs::write(&config_path, config_json).await?;

        let log_stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let log_stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        let mut command = Command::new(&state.firecracker_path);
        command.arg("--config-file").arg(&config_path);
        apply_seccomp_flags(&mut command, spec)?;
        let child = command
            .stdout(log_stdout)
            .stderr(log_stderr)
            .spawn()
            .map_err(|e| ApiError::Driver(format!("failed to spawn firecracker: {e}")))?;

        if let Some(ref cgroup_spec) = spec.spec.cgroup {
            if let Some(pid) = child.id() {
                cgroup::apply_cgroup(pid, cgroup_spec).await?;
            } else {
                return Err(ApiError::Driver(
                    "firecracker process id unavailable for cgroup placement".to_string(),
                ));
            }
        }

        wait_for_vsock_socket(&vsock_path).await?;
        let bridge = vsock_bridge::VsockBridge::start(vsock_path.clone(), vsock_spec.port)
            .await
            .map_err(|e| ApiError::Driver(format!("vsock bridge failed: {e}")))?;

        let mut proxy_addr = format!("http://{}", bridge.listen_addr());
        let mut signed_proxy = None;
        let health_addr = if let Some(secret) = state.proxy_auth_secret.as_ref() {
            let proxy = signed_proxy::SignedProxy::start(
                bridge.listen_addr(),
                Arc::new(secret.as_bytes().to_vec()),
                state.proxy_actor.clone(),
            )
            .await
            .map_err(|e| ApiError::Driver(format!("signed proxy failed: {e}")))?;
            proxy_addr = format!("http://{}", proxy.listen_addr());
            let addr = proxy.listen_addr();
            signed_proxy = Some(proxy);
            addr
        } else {
            bridge.listen_addr()
        };

        if let Err(err) = wait_for_proxy_health(health_addr).await {
            if let Some(proxy) = signed_proxy {
                proxy.shutdown().await;
            }
            bridge.shutdown().await;
            let mut child = child;
            let _ = child.kill().await;
            return Err(err);
        }

        let handle = FirecrackerPod {
            child: Mutex::new(child),
            bridge: Mutex::new(Some(bridge)),
            signed_proxy: Mutex::new(signed_proxy),
        };

        info!("spawned firecracker pod {}", id);

        Ok((DriverState::Firecracker(handle), Some(proxy_addr), log_path))
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
            if let Some(ref auth) = auth {
                let method = req
                    .metadata()
                    .get("x-nucleus-method")
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| Status::unauthenticated("missing x-nucleus-method"))?;
                auth::verify_grpc(req.metadata(), method, auth)
                    .map_err(|e| Status::unauthenticated(e.to_string()))?;
            }
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
struct LoggerConfig {
    log_path: String,
    level: String,
    show_level: bool,
    show_log_origin: bool,
}

#[cfg(target_os = "linux")]
impl FirecrackerConfig {
    fn from_spec(
        spec: &PodSpec,
        log_path: &Path,
        vsock_path: &Path,
        image: &nucleus_spec::ImageSpec,
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
        let boot_args = match image.boot_args.clone() {
            Some(args) => {
                if args.contains("init=") {
                    Some(args)
                } else {
                    Some(format!("{args} init=/init"))
                }
            }
            None => Some(default_args),
        };

        let vsock = spec.spec.vsock.as_ref().map(|vsock| VsockConfig {
            guest_cid: vsock.guest_cid,
            uds_path: vsock_path.display().to_string(),
        });

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
