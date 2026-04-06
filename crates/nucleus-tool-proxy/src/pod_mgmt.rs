#![allow(clippy::disallowed_types)] // #1216 exempt: vsock endpoint setup (infrastructure)
                                    // =============================================================================
                                    // Pod Management Handlers (orchestrator mode)
                                    // =============================================================================
                                    //
                                    // Extracted from main.rs to reduce file size. These handlers allow the
                                    // tool-proxy to orchestrate sub-pods via nucleus-node.

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::warn;

use nucleus::portcullis::{CapabilityLevel, Operation};
use nucleus::{BudgetModel, NucleusError};
use nucleus_spec::{BudgetModelSpec, PodSpec};
use portcullis::verdict_sink::{VerdictContext, VerdictOutcome};

use crate::node_client;
use crate::{actor_from_auth, ApiError, AppState, PodRuntime};

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct CreateSubPodRequest {
    /// PodSpec YAML for the sub-pod.
    pub spec_yaml: String,
    /// Reason for creating the sub-pod (audit trail).
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateSubPodResponse {
    pub pod_id: String,
    pub proxy_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PodIdRequest {
    pub pod_id: String,
}

// ---------------------------------------------------------------------------
// Capability check
// ---------------------------------------------------------------------------

/// Check that manage_pods capability is at least LowRisk.
fn check_manage_pods(state: &AppState) -> Result<(), ApiError> {
    let policy = state.runtime.policy();
    let level = policy.capabilities.manage_pods;
    if level == CapabilityLevel::Never {
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "manage_pods".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub(crate) async fn create_sub_pod(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<crate::auth::AuthContext>>,
    Json(req): Json<CreateSubPodRequest>,
) -> Result<Json<CreateSubPodResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // 1. Check manage_pods capability
    check_manage_pods(&state)?;

    // 2. Parse requested PodSpec
    let mut spec: PodSpec = serde_yaml::from_str(&req.spec_yaml)
        .map_err(|e| ApiError::Spec(format!("invalid sub-pod spec: {e}")))?;

    // 3. Resolve requested policy → PermissionLattice
    let requested = spec
        .spec
        .resolve_policy()
        .map_err(|e| ApiError::Spec(format!("invalid sub-pod policy: {e}")))?;

    // 4. Enforce delegation ceiling via delegate_to()
    if let Some(ceiling) = state.delegation_ceiling.as_ref() {
        let delegated = ceiling
            .delegate_to(&requested, &req.reason)
            .map_err(|e| ApiError::Spec(format!("delegation failed: {e}")))?;

        // Replace policy with delegated (never exceeds parent)
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(delegated),
        };
    }

    // 5. Inject credentials from orchestrator's env (transparent to agent)
    let mut creds = spec.spec.credentials.take().unwrap_or_default();
    for (key, val) in &state.orchestrator_credentials {
        if !creds.env.contains_key(key) {
            creds.env.insert(key.clone(), val.clone());
        }
    }
    if !creds.is_empty() {
        spec.spec.credentials = Some(creds);
    }

    // 6. Forward to nucleus-node
    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let spec_yaml = serde_yaml::to_string(&spec)
        .map_err(|e| ApiError::Spec(format!("failed to serialize sub-pod spec: {e}")))?;

    let result = node
        .create_pod(&spec_yaml)
        .await
        .map_err(|e| ApiError::Spec(format!("node create_pod failed: {e}")))?;

    // 7. Record verdict
    if let Err(e) = sink.record(VerdictContext {
        operation: Operation::ManagePods,
        subject: format!("sub-pod {} (reason: {})", result.id, req.reason),
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }

    Ok(Json(CreateSubPodResponse {
        pod_id: result.id.to_string(),
        proxy_addr: result.proxy_addr,
    }))
}

pub(crate) async fn list_sub_pods(
    State(state): State<AppState>,
    _headers: HeaderMap,
) -> Result<Json<Vec<node_client::PodInfo>>, ApiError> {
    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pods = node
        .list_pods()
        .await
        .map_err(|e| ApiError::Spec(format!("node list_pods failed: {e}")))?;

    Ok(Json(pods))
}

pub(crate) async fn get_pod_status(
    State(state): State<AppState>,
    Json(req): Json<PodIdRequest>,
) -> Result<Json<Vec<node_client::PodInfo>>, ApiError> {
    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pods = node
        .list_pods()
        .await
        .map_err(|e| ApiError::Spec(format!("node list_pods failed: {e}")))?;

    let filtered: Vec<_> = pods
        .into_iter()
        .filter(|p| p.id.to_string() == req.pod_id)
        .collect();

    Ok(Json(filtered))
}

pub(crate) async fn get_pod_logs(
    State(state): State<AppState>,
    Json(req): Json<PodIdRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pod_id: uuid::Uuid = req
        .pod_id
        .parse()
        .map_err(|e| ApiError::Spec(format!("invalid pod_id: {e}")))?;

    let logs = node
        .pod_logs(pod_id)
        .await
        .map_err(|e| ApiError::Spec(format!("node pod_logs failed: {e}")))?;

    Ok(Json(
        serde_json::json!({ "pod_id": req.pod_id, "logs": logs }),
    ))
}

pub(crate) async fn cancel_sub_pod(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<crate::auth::AuthContext>>,
    Json(req): Json<PodIdRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sink = &state.verdict_sink;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    check_manage_pods(&state)?;

    let node = state
        .node_client
        .as_ref()
        .ok_or_else(|| ApiError::Spec("pod management not enabled".to_string()))?;

    let pod_id: uuid::Uuid = req
        .pod_id
        .parse()
        .map_err(|e| ApiError::Spec(format!("invalid pod_id: {e}")))?;

    node.cancel_pod(pod_id)
        .await
        .map_err(|e| ApiError::Spec(format!("node cancel_pod failed: {e}")))?;

    if let Err(e) = sink.record(VerdictContext {
        operation: Operation::ManagePods,
        subject: format!("sub-pod {}", req.pod_id),
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }

    Ok(Json(
        serde_json::json!({ "status": "cancelled", "pod_id": req.pod_id }),
    ))
}

// ---------------------------------------------------------------------------
// Runtime / Budget helpers
// ---------------------------------------------------------------------------

pub(crate) fn build_runtime(spec: &PodSpec) -> Result<PodRuntime, ApiError> {
    let policy = spec
        .spec
        .resolve_policy()
        .map_err(|e| ApiError::Spec(e.to_string()))?;
    let timeout = std::time::Duration::from_secs(spec.spec.timeout_seconds);
    let mut runtime_spec = nucleus::PodSpec::new(policy, spec.spec.work_dir.clone(), timeout);
    if let Some(model) = spec.spec.budget_model.as_ref() {
        runtime_spec.budget_model = map_budget_model(model);
    }

    PodRuntime::new(runtime_spec).map_err(ApiError::Nucleus)
}

fn map_budget_model(model: &BudgetModelSpec) -> BudgetModel {
    BudgetModel {
        base_cost_usd: model.base_cost_usd,
        cost_per_second_usd: model.cost_per_second_usd,
    }
}

// ---------------------------------------------------------------------------
// Vsock support
// ---------------------------------------------------------------------------

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct VsockConfig {
    pub cid: u32,
    pub port: u32,
}

#[cfg(target_os = "linux")]
pub(crate) fn resolve_vsock(
    args: &crate::Args,
    spec: &PodSpec,
) -> Result<Option<VsockConfig>, ApiError> {
    let port = match args
        .vsock_port
        .or_else(|| spec.spec.vsock.as_ref().map(|v| v.port))
    {
        Some(port) => port,
        None => {
            if args.vsock_cid.is_some() {
                return Err(ApiError::Spec("vsock_cid requires vsock_port".to_string()));
            }
            return Ok(None);
        }
    };
    let cid = args
        .vsock_cid
        .or_else(|| spec.spec.vsock.as_ref().map(|v| v.guest_cid))
        .unwrap_or(tokio_vsock::VMADDR_CID_ANY);

    Ok(Some(VsockConfig { cid, port }))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve_vsock(
    args: &crate::Args,
    spec: &PodSpec,
) -> Result<Option<VsockConfig>, ApiError> {
    if args.vsock_port.is_some() || spec.spec.vsock.is_some() {
        Err(ApiError::Spec(
            "vsock requires Linux (run inside the Firecracker VM)".to_string(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn serve_vsock(
    app: Router,
    vsock: VsockConfig,
    announce_path: Option<PathBuf>,
) -> Result<(), ApiError> {
    let addr = tokio_vsock::VsockAddr::new(vsock.cid, vsock.port);
    let listener = tokio_vsock::VsockListener::bind(addr)?;
    let local = listener.local_addr()?;
    if let Some(path) = announce_path {
        tokio::fs::write(path, format!("vsock://{}:{}", local.cid(), local.port())).await?;
    }
    info!(
        "nucleus-tool-proxy listening on vsock {}:{}",
        local.cid(),
        local.port()
    );
    let listener = VsockAxumListener { inner: listener };
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn serve_vsock(
    _app: Router,
    _vsock: VsockConfig,
    _announce_path: Option<PathBuf>,
) -> Result<(), ApiError> {
    Err(ApiError::Spec(
        "vsock requires Linux (run inside the Firecracker VM)".to_string(),
    ))
}

#[cfg(target_os = "linux")]
struct VsockAxumListener {
    inner: tokio_vsock::VsockListener,
}

#[cfg(target_os = "linux")]
impl axum::serve::Listener for VsockAxumListener {
    type Io = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => return (stream, addr),
                Err(err) => {
                    tracing::error!("vsock accept error: {err}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
