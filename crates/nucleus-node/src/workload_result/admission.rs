//! Admission inventory comes from the host's effective spec, without contacting
//! a guest or reading an execution receipt. Never export workload env or secrets.
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use nucleus_spec::workload_admission::WorkloadAdmission;
use uuid::Uuid;

use crate::{ApiError, DriverState, NodeState, pod_api};

/// The workload door the pod's proxy binds, by where that proxy runs. The
/// launcher of each driver names the same path: the local driver passes
/// [`crate::lifecycle::local_workload_door`], the container driver
/// `CONTAINER_WORKLOAD_DOOR`, and a microVM guest's proxy binds its default,
/// `guest_layout::WORKLOAD_DOOR`, which the node does not override.
fn workload_door(
    state: &NodeState,
    pod: &crate::PodHandle,
    id: Uuid,
) -> Result<std::path::PathBuf, ApiError> {
    Ok(match &pod.driver_state {
        #[cfg(feature = "local-driver")]
        DriverState::Local(_) => {
            crate::lifecycle::local_workload_door(&crate::lifecycle::pod_dir(&state.state_dir, id))
                .map_err(|e| ApiError::Driver(format!("workload door path: {e}")))?
        }
        DriverState::Container(_) => crate::container_transport::CONTAINER_WORKLOAD_DOOR.into(),
        DriverState::Firecracker(_) => nucleus_spec::guest_layout::WORKLOAD_DOOR.into(),
    })
}

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
    // What the runtime injects into the workload's environment, from the same
    // function the launcher calls, so a verifier derives these inputs from this
    // record rather than restating them (#3219).
    let door = nucleus_client::endpoint::ProxyEndpoint::unix(&workload_door(&state, &pod, id)?);
    let runtime_environment_inputs = nucleus_spec::workload_egress::injected_env(
        &spec.spec.credentialed_egress,
        &door.to_string(),
    );
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
        runtime_environment_inputs,
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
            // One declared upstream: the runtime injects its URL (#3219).
            pod.spec.spec.credentialed_egress = vec![nucleus_spec::CredentialedEgressSpec {
                name: "model-api".into(),
                upstream: "https://model.invalid/".into(),
                credential_env: "LLM_API_TOKEN".into(),
                header: "authorization".into(),
                value_prefix: "Bearer ".into(),
                effects: nucleus_spec::EffectTable::unclassified(),
            }];
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
        // The injected egress URL names the door the local launcher passes,
        // and nothing about the credential crosses.
        let door =
            crate::lifecycle::local_workload_door(&crate::lifecycle::pod_dir(&state.state_dir, id))
                .unwrap();
        assert_eq!(
            admission.runtime_environment_inputs,
            std::collections::BTreeMap::from([(
                "NUCLEUS_EGRESS_MODEL_API_URL".to_string(),
                format!("unix://{}/v1/egress/model-api", door.display()),
            )])
        );
        assert!(!String::from_utf8_lossy(&bytes).contains("LLM_API_TOKEN"));
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
