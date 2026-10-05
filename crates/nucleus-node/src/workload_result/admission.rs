//! Admission inventory comes from the host's effective spec, without contacting
//! a guest or reading an execution receipt. Never export workload env or secrets.
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use nucleus_spec::workload_admission::WorkloadAdmission;
use uuid::Uuid;

use crate::{ApiError, NodeState, pod_api};

pub(super) async fn get(
    State(state): State<NodeState>,
    Extension(caller): Extension<crate::auth::CallerScope>,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkloadAdmission>, ApiError> {
    let pod = pod_api::get_pod_for_caller(&state, id, &caller).await?;
    let spec = &pod.spec;
    let workload = spec
        .spec
        .workload
        .as_ref()
        .ok_or_else(|| ApiError::InvalidSpec("pod has no configured workload".into()))?;
    let label = |name: &str| spec.metadata.labels.get(name).cloned().unwrap_or_default();
    Ok(Json(WorkloadAdmission {
        pod_id: id.to_string(),
        created_at_unix: pod.created_at,
        source_commit: label("build.source.commit"),
        source_tree: label("build.source.tree"),
        gate: label("build.gate"),
        program_digest: nucleus_spec::identity::program_digest(spec)
            .map_err(|e| ApiError::InvalidSpec(format!("host program identity: {e}")))?,
        architecture: std::env::consts::ARCH.into(),
        artifacts: workload.artifacts.clone(),
        session_id: id.to_string(),
        issuer_kid: state.trust_gate.executor_id.clone(),
        verifying_key: state
            .trust_gate
            .executor_signing_key
            .verifying_key()
            .to_bytes(),
    }))
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn admission_is_available_without_a_supervisor_or_receipt() {
        assert!(matches!(
            crate::auth::operation_for_route(
                &axum::http::Method::GET,
                "/v1/pods/example/workload-admission"
            ),
            Some(crate::auth::Operation::GetReceipt)
        ));
        let dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&dir);
        let id = crate::pod_api::handler_tests::register(&state, None).await;
        let expected = {
            let mut pods = state.pods.lock().await;
            let pod = std::sync::Arc::get_mut(pods.get_mut(&id).unwrap()).unwrap();
            pod.proxy_addr = tokio::sync::Mutex::new(None);
            pod.spec.spec.workload = Some(
                serde_json::from_value(serde_json::json!({
                    "command": "/bin/true", "artifacts": {"tests": "tests.json"},
                    "env": {"PRIVATE_INPUT": "not-for-export"}
                }))
                .unwrap(),
            );
            // Match the admitted representation, which replaces the profile.
            pod.spec.spec.policy = nucleus_spec::PolicySpec::Inline {
                lattice: Box::new(portcullis::PermissionLattice::codegen()),
            };
            nucleus_spec::identity::program_digest(&pod.spec).unwrap()
        };
        let app = super::super::routes()
            .layer(Extension(crate::auth::CallerScope::NodeWide))
            .with_state(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/pods/{id}/workload-admission"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let admission: WorkloadAdmission = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(admission.program_digest, expected);
        assert_eq!(admission.artifacts["tests"], "tests.json");
        assert_eq!(
            admission.verifying_key,
            state
                .trust_gate
                .executor_signing_key
                .verifying_key()
                .to_bytes()
        );
        assert!(!String::from_utf8_lossy(&bytes).contains("not-for-export"));
        state
            .pods
            .lock()
            .await
            .get(&id)
            .unwrap()
            .cancel()
            .await
            .unwrap();
    }
}
