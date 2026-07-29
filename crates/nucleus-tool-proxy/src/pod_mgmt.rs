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

use nucleus::portcullis::{CapabilityLevel, FlowTracker, NodeKind, Operation};
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

/// Information-flow egress gate for sub-pod spawning (audit C-1 / #1207).
///
/// `create_sub_pod` spawns a child compartment and injects orchestrator
/// credentials into it. A fresh child `FlowTracker` starts clean, so if the
/// parent session has ingested adversarial/web content (integrity-tainted), is
/// poisoned (an observation was dropped), or carries confidentiality above what
/// the spawn may emit, then allowing the spawn would *launder* the parent's
/// accumulated taint across the sub-pod boundary — the confused-deputy
/// subagent-spawn vector. `ManagePods` is an `OutboundAction`
/// (see `Kernel::node_kind_for`), so we consult the SAME egress gate the kernel
/// uses on its in-process path (`portcullis::kernel::ifc`), failing CLOSED here.
/// This makes non-interference hold across the sub-pod boundary, not only within
/// the single-process kernel path.
///
/// Kept as a small private helper so its logic is unit-tested directly and so the
/// call from `create_sub_pod` cannot be silently dropped (an unused private fn
/// fails the warnings-denied build).
fn sub_pod_ifc_gate(flow: &FlowTracker) -> Result<(), ApiError> {
    if flow.is_poisoned() {
        return Err(ApiError::IfcDenied(
            "session poisoned: an information-flow observation was dropped; \
             refusing to spawn a credential-injected sub-pod (fail-closed)"
                .to_string(),
        ));
    }
    if let Some(detail) = portcullis::exposure_core::ifc_egress_denial(
        flow,
        Operation::ManagePods,
        NodeKind::OutboundAction,
    ) {
        return Err(ApiError::IfcDenied(detail));
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

    // 1b. IFC egress gate (audit C-1 / #1207): a parent session that has ingested
    //     adversarial/web content — or is poisoned, or over its confidentiality
    //     ceiling — may NOT spawn a credential-injected sub-pod. Fail closed HERE,
    //     before credential injection (step 5) and any node call (step 6): a fresh
    //     child FlowTracker starts clean and would otherwise launder the parent's
    //     accumulated taint across the sub-pod boundary (confused-deputy spawn).
    {
        let flow = state.flow_tracker.lock().await;
        sub_pod_ifc_gate(&flow)?;
    }

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
    let mut runtime_spec = nucleus::PodSpec::new(policy, spec.spec.work_dir.clone(), timeout)
        // Containment posture (most-paranoid #2). We declare the *honest* minimum:
        // `Unsandboxed`. The proxy only starts inside a verified managed sandbox
        // (it exits 78 without a `SandboxProof`), but a SPIFFE-tier proof does not
        // by itself prove a microVM boundary — so we do NOT over-claim `MicroVM`.
        // Consequence (fail-closed, by design): a policy that sets
        // `minimum_isolation = microvm()` will REFUSE to execute here until real
        // VM attestation (the SandboxProof DICE/Tier-1 launch measurement) is
        // threaded in to upgrade this to `ContainmentMode::MicroVM`.
        // TODO(most-paranoid #2 follow-up): derive containment from the verified
        // SandboxProof tier (Attested/DICE => MicroVM) instead of this constant.
        .with_containment(nucleus::ContainmentMode::Unsandboxed);
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

/// `VMADDR_CID_HOST` — the well-known vsock context id of the host.
///
/// The kernel sets the peer CID on an accepted AF_VSOCK connection; a process
/// cannot choose its own. That makes "the peer is the host" a fact the guest
/// kernel enforces, rather than something a caller asserts.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub const VMADDR_CID_HOST: u32 = 2;

/// `VMADDR_CID_LOCAL` — vsock loopback. An in-guest process connecting to a
/// listener in its own VM arrives with this CID (or the VM's own CID), which is
/// precisely how the agent could otherwise reach the proxy's control plane.
#[cfg_attr(not(test), allow(dead_code))]
pub const VMADDR_CID_LOCAL: u32 = 1;

/// Whether an accepted vsock peer is the host.
///
/// # Why this is the whole point
///
/// The proxy serves its control plane over AF_VSOCK, and `accept()` previously
/// returned every peer. But a guest process can reach a listener in its own VM
/// — over loopback (`VMADDR_CID_LOCAL`) or the VM's own CID — so the agent
/// could open the proxy's control plane and issue tool calls as if it were the
/// host. `nucleus.auth_secret` exists to stop exactly that: the host HMACs its
/// requests so the proxy can tell them from the agent's.
///
/// That defence cannot work, because the key travels on the kernel command line
/// (`crates/nucleus-guest-init/src/main.rs` reads it from `/proc/cmdline`) and
/// every guest process can read it. It draws a trust boundary inside one trust
/// domain.
///
/// Checking the peer CID replaces a secret the agent can read with a property
/// the guest kernel enforces and no guest process can forge. It is strictly
/// stronger, and it is what lets the secret leave the command line.
#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub fn peer_is_host(peer_cid: u32) -> bool {
    peer_cid == VMADDR_CID_HOST
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
                Ok((stream, addr)) => {
                    // FAIL CLOSED ON PEER IDENTITY. Only the host may drive the
                    // proxy's control plane. A guest process reaching this
                    // listener over loopback is the agent trying to issue tool
                    // calls as the host — dropped here by a fact the kernel
                    // enforces, not by a secret the agent can read.
                    if !peer_is_host(addr.cid()) {
                        tracing::warn!(
                            peer_cid = addr.cid(),
                            "rejecting vsock control-plane connection from a non-host peer"
                        );
                        drop(stream);
                        continue;
                    }
                    return (stream, addr);
                }
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

#[cfg(test)]
mod ifc_gate_tests {
    //! Regression guard for audit finding C-1 / #1207: a tainted or poisoned
    //! parent session must not be able to spawn a credential-injected sub-pod.
    //! These test the security decision directly; the handler wiring is guarded
    //! by `sub_pod_ifc_gate` being a private fn called only from `create_sub_pod`
    //! (dropping the call makes it dead code → warnings-denied build fails).
    use super::sub_pod_ifc_gate;
    use crate::ApiError;
    use nucleus::portcullis::{FlowTracker, NodeKind};

    #[test]
    fn tainted_parent_is_denied_sub_pod() {
        let mut tainted = FlowTracker::new();
        tainted
            .observe(NodeKind::WebContent)
            .expect("observe web content");
        assert!(tainted.is_tainted());
        assert!(
            matches!(sub_pod_ifc_gate(&tainted), Err(ApiError::IfcDenied(_))),
            "a web-tainted parent must be denied sub-pod spawn (audit C-1)"
        );
    }

    #[test]
    fn poisoned_parent_is_denied_sub_pod() {
        let mut poisoned = FlowTracker::new();
        poisoned.poison();
        assert!(poisoned.is_poisoned());
        assert!(
            matches!(sub_pod_ifc_gate(&poisoned), Err(ApiError::IfcDenied(_))),
            "a poisoned parent must be denied sub-pod spawn (fail-closed)"
        );
    }

    #[test]
    fn clean_parent_passes_the_gate() {
        let clean = FlowTracker::new();
        assert!(
            sub_pod_ifc_gate(&clean).is_ok(),
            "a clean parent must pass the IFC gate (no over-denial)"
        );
    }
}

#[cfg(test)]
mod vsock_peer_tests {
    use super::{peer_is_host, VMADDR_CID_HOST, VMADDR_CID_LOCAL};

    /// The host, and only the host, may drive the control plane.
    #[test]
    fn only_the_host_cid_is_accepted() {
        assert!(peer_is_host(VMADDR_CID_HOST));
        for other in [0u32, VMADDR_CID_LOCAL, 3, 4, 42, u32::MAX] {
            assert!(
                !peer_is_host(other),
                "CID {other} must not be treated as the host"
            );
        }
    }

    /// THE ATTACK THIS CLOSES. An in-guest process — the agent — reaching the
    /// proxy's vsock listener arrives over loopback or the VM's own CID, never
    /// as CID 2. Before the check it was indistinguishable from the host and
    /// only `nucleus.auth_secret` stood in the way, a key the agent can read
    /// from /proc/cmdline.
    #[test]
    fn an_in_guest_peer_cannot_pose_as_the_host() {
        assert!(
            !peer_is_host(VMADDR_CID_LOCAL),
            "vsock loopback is not the host"
        );
        // A VM's own CID is >= 3; the first few are the realistic guest values.
        for guest_cid in 3u32..=8 {
            assert!(
                !peer_is_host(guest_cid),
                "guest CID {guest_cid} is not the host"
            );
        }
    }

    /// The hypervisor CID is not the host either — nothing but 2 passes.
    #[test]
    fn the_hypervisor_cid_is_not_the_host() {
        assert!(!peer_is_host(0));
    }
}

#[cfg(test)]
mod vsock_accept_wiring {
    /// The enforcement lives inside `#[cfg(target_os = "linux")]`, so no unit
    /// test on a dev Mac can observe it being deleted — the predicate tests
    /// above would stay green while the listener accepted every peer again.
    ///
    /// This reads the source and asserts the accept path still consults
    /// `peer_is_host`. Structural, not semantic: it proves the call is present,
    /// not that it is correct. The predicate tests cover correctness; this
    /// covers the wiring that the platform hides.
    #[test]
    fn the_accept_path_still_checks_the_peer_cid() {
        let src = include_str!("pod_mgmt.rs");
        let accept = src
            .split("async fn accept(&mut self)")
            .nth(1)
            .expect("VsockAxumListener::accept must exist");
        let body = &accept[..accept.find("\n    fn local_addr").unwrap_or(accept.len())];
        assert!(
            body.contains("peer_is_host"),
            "the vsock accept path no longer checks the peer CID — any guest \
             process could reach the proxy control plane as if it were the host"
        );
        assert!(
            body.contains("continue"),
            "a rejected peer must be dropped and the loop continued, not returned"
        );
    }
}
