//! Bounded binary reads for host artifact collection. The same kernel decision,
//! discharge and sandbox checks as text reads apply; no ambient file open lives
//! on this route. An approval requirement is a refusal, never auto-approved.

use axum::body::Body;
use axum::response::Response;
use axum::{Json, extract::State};
use nucleus_ifc_kernel::discharge::PreflightResult;
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::{ApiError, AppState, NodeKind, Operation, VerdictContext, VerdictOutcome};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    path: String,
    max_bytes: usize,
}

pub(crate) async fn read(
    State(state): State<AppState>,
    auth: Option<axum::Extension<crate::auth::AuthContext>>,
    certified: Option<axum::Extension<crate::pod_cert::CertifiedPermissions>>,
    Json(request): Json<Request>,
) -> Result<Response, ApiError> {
    if request.max_bytes > nucleus_spec::workload_result::MAX_ARTIFACT_BYTES {
        return Err(ApiError::Spec(
            "artifact limit exceeds runtime ceiling".into(),
        ));
    }
    crate::validation::validate_path(&request.path).map_err(ApiError::Validation)?;
    let auth = auth.map(|value| value.0);
    let decision =
        crate::http_kernel_decide(&state, Operation::ReadFiles, &request.path, auth.as_ref())
            .await?;
    let authority = {
        let scope = state.session_task_token.verified_scope();
        let ceiling = state.ceiling(Operation::ReadFiles, certified.as_ref());
        let graph = state.flow_graph.lock().await;
        match crate::run_gate::preflight_read_fs(scope, ceiling, &request.path, &graph) {
            PreflightResult::Allowed(bundle) => {
                portcullis_effects::authority::Authority::new(bundle)
            }
            PreflightResult::Denied { reason, .. }
            | PreflightResult::RequiresApproval { reason } => {
                return Err(ApiError::IfcDenied(format!(
                    "artifact discharge denied: {reason}"
                )));
            }
        }
    };
    let runtime = state.runtime.clone();
    let path = request.path.clone();
    let result = tokio::task::spawn_blocking(move || {
        runtime
            .sandbox()
            .read_bounded(path, request.max_bytes, decision, authority)
    })
    .await
    .map_err(|e| ApiError::Spec(format!("artifact read task: {e}")))?;
    let outcome = match &result {
        Ok(_) => VerdictOutcome::Allow,
        Err(error) => VerdictOutcome::Error {
            error: error.to_string(),
        },
    };
    state
        .verdict_sink
        .record(VerdictContext {
            operation: Operation::ReadFiles,
            subject: request.path,
            outcome,
            actor: crate::actor_from_auth(auth.as_ref()),
            policy_rule: None,
            extensions: BTreeMap::new(),
        })
        .map_err(|e| ApiError::Spec(format!("artifact audit: {e}")))?;
    let bytes = result?;
    // Build outputs are untrusted data even though the runtime collected them.
    crate::ingest::http_observe_flow(&state, NodeKind::ToolResponse, &bytes).await;
    Response::builder()
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Spec(e.to_string()))
}
