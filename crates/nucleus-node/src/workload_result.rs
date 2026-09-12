//! Fetch the supervising proxy's read-only observation through the node-owned
//! proxy bridge. Pod lineage is checked before revealing or contacting it.
//! This response does not itself assert a sandbox tier or carry a signature.

use axum::Json;
use axum::extract::{Extension, Path, State};
use nucleus_ci_verdict::execution::{Backend, ExecutionClaim, ExecutionSchema};
use nucleus_receipt::{Receipt, Session};
use nucleus_spec::workload_result::WorkloadResult;
use nucleus_spec::workload_result::{ProgramBinding, WorkloadIsolation};
use uuid::Uuid;

use crate::{ApiError, DriverState, NodeState, pod_api};

pub(crate) async fn get(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkloadResult>, ApiError> {
    let pod = pod_api::get_pod_for_caller(&state, id, caller).await?;
    let address =
        pod.proxy_addr.lock().await.clone().ok_or_else(|| {
            ApiError::Driver("workload supervisor is not reachable yet".to_string())
        })?;
    fetch(&state.http_client, &address).await.map(Json)
}

/// Sign only the protected supervisor's completed observation, using the
/// existing host-only executor key. Local/container evidence remains labeled
/// as such and the public microVM verifier refuses it.
pub(crate) async fn receipt(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Receipt>, ApiError> {
    let pod = pod_api::get_pod_for_caller(&state, id, caller).await?;
    let backend = match &pod.driver_state {
        #[cfg(feature = "local-driver")]
        DriverState::Local(_) => Backend::Local,
        DriverState::Container(_) => Backend::Container,
        DriverState::Firecracker(_) => Backend::Firecracker,
    };
    let address = pod
        .proxy_addr
        .lock()
        .await
        .clone()
        .ok_or_else(|| ApiError::Driver("workload supervisor is not reachable yet".into()))?;
    let observed = fetch(&state.http_client, &address).await?;
    let claim = completed_claim(&pod.spec, id, backend, observed)?;
    let projection = claim
        .to_projection()
        .map_err(|e| ApiError::Driver(format!("encoding execution claim: {e}")))?;
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Driver(format!("execution receipt clock: {e}")))?;
    let issued_at_micros = u64::try_from(issued.as_micros())
        .map_err(|e| ApiError::Driver(format!("execution receipt clock overflow: {e}")))?;
    Ok(Json(Receipt::sign(
        Session {
            session_id: id.to_string(),
            issuer_kid: state.trust_gate.executor_id.clone(),
            issued_at_micros,
            parent_chain: Vec::new(),
        },
        vec![projection],
        &state.trust_gate.executor_signing_key,
    )))
}

fn completed_claim(
    spec: &nucleus_spec::PodSpec,
    id: Uuid,
    backend: Backend,
    observed: WorkloadResult,
) -> Result<ExecutionClaim, ApiError> {
    if backend == Backend::Firecracker {
        require_image_pins(spec)?;
    }
    let WorkloadResult::Exited {
        exit_code,
        stdout_sha256,
        stderr_sha256,
        launch_hash,
        environment,
        program,
        isolation,
    } = observed
    else {
        return Err(ApiError::Driver(
            "workload has no complete execution observation".into(),
        ));
    };
    let ProgramBinding::Bound { digest } = program else {
        return Err(ApiError::Driver(
            "workload has no declared program identity".into(),
        ));
    };
    let expected = nucleus_spec::identity::program_digest(spec)
        .map_err(|e| ApiError::Driver(format!("host program identity: {e}")))?;
    if digest != expected {
        return Err(ApiError::Driver(
            "supervisor program identity differs from host spec".into(),
        ));
    }
    Ok(ExecutionClaim {
        schema: ExecutionSchema::V1,
        pod_id: id.to_string(),
        program_digest: expected,
        architecture: std::env::consts::ARCH.into(),
        backend,
        uid_isolated: isolation == WorkloadIsolation::UidIsolated,
        exit_code,
        stdout_sha256,
        stderr_sha256,
        launch_hash,
        environment_inputs_sha256: environment.inputs_sha256,
        environment_complete_sha256: environment.complete_sha256,
    })
}

/// The Firecracker spawn path checks present pins against placed bytes. Do not
/// turn its backwards-compatible allowance for absent pins into signed identity.
fn require_image_pins(spec: &nucleus_spec::PodSpec) -> Result<(), ApiError> {
    let Some(image) = &spec.spec.image else {
        return Err(ApiError::Driver(
            "execution receipt requires an explicitly pinned image".into(),
        ));
    };
    let nucleus_spec::ImageSpec {
        kernel_path: _,
        rootfs_path: _,
        boot_args: _,
        kernel_digest,
        rootfs_digest,
        data_path,
        data_digest,
        scratch_path,
        scratch_digest,
        read_only,
    } = image;
    if !read_only
        || kernel_digest.is_none()
        || rootfs_digest.is_none()
        || data_path.is_some() != data_digest.is_some()
        || scratch_path.is_some() != scratch_digest.is_some()
    {
        return Err(ApiError::Driver(
            "execution receipt requires read-only rootfs and complete image pins".into(),
        ));
    }
    Ok(())
}

async fn fetch(client: &reqwest::Client, address: &str) -> Result<WorkloadResult, ApiError> {
    let mut response = client
        .get(format!(
            "{}/v1/workload/result",
            address.trim_end_matches('/')
        ))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| ApiError::Driver(format!("reading workload supervisor: {e}")))?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ApiError::Driver(format!("reading workload result body: {e}")))?
    {
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(ApiError::Driver("workload result exceeds 16 KiB".into()));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| ApiError::Driver(format!("malformed workload supervisor result: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    fn spec() -> nucleus_spec::PodSpec {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "nucleus/v1", "kind": "Pod",
            "metadata": {"name": "observation-test"},
            "spec": {"work_dir": "/work"}
        }))
        .unwrap()
    }

    fn observed(spec: &nucleus_spec::PodSpec) -> WorkloadResult {
        WorkloadResult::Exited {
            exit_code: Some(23),
            stdout_sha256: "a".repeat(64),
            stderr_sha256: "b".repeat(64),
            launch_hash: "c".repeat(64),
            environment: nucleus_spec::workload_result::EnvironmentIdentity::of(&Default::default()),
            program: ProgramBinding::Bound {
                digest: nucleus_spec::identity::program_digest(spec).unwrap(),
            },
            isolation: WorkloadIsolation::Unconfined,
        }
    }

    #[test]
    fn signing_preparation_preserves_actual_exit_and_backend() {
        let spec = spec();
        let claim = completed_claim(&spec, Uuid::nil(), Backend::Local, observed(&spec)).unwrap();
        assert_eq!(claim.exit_code, Some(23));
        assert_eq!(claim.backend, Backend::Local);
        assert!(!claim.uid_isolated);
    }

    #[test]
    fn incomplete_or_wrong_program_observations_cannot_be_signed() {
        let spec = spec();
        for result in [
            WorkloadResult::NotConfigured,
            WorkloadResult::Running,
            WorkloadResult::Unavailable {
                reason: "lost pipe".into(),
            },
        ] {
            assert!(completed_claim(&spec, Uuid::nil(), Backend::Local, result).is_err());
        }
        let mut observation = observed(&spec);
        if let WorkloadResult::Exited { program, .. } = &mut observation {
            *program = ProgramBinding::Bound {
                digest: "another program".into(),
            };
        }
        assert!(completed_claim(&spec, Uuid::nil(), Backend::Local, observation).is_err());
    }

    #[test]
    fn microvm_receipts_require_explicit_complete_boot_pins() {
        let mut spec = spec();
        assert!(require_image_pins(&spec).is_err());
        let digest = format!("sha-256:{}", "a".repeat(64));
        spec.spec.image = Some(
            serde_json::from_value(serde_json::json!({
                "kernel_path": "/kernel", "rootfs_path": "/rootfs",
                "kernel_digest": digest, "rootfs_digest": digest,
                "read_only": true
            }))
            .unwrap(),
        );
        assert!(require_image_pins(&spec).is_ok());
        let image = spec.spec.image.as_mut().unwrap();
        image.data_path = Some("/source.ext4".into());
        assert!(require_image_pins(&spec).is_err());
        let image = spec.spec.image.as_mut().unwrap();
        image.data_digest = image.rootfs_digest.clone();
        assert!(require_image_pins(&spec).is_ok());
        spec.spec.image.as_mut().unwrap().read_only = false;
        assert!(require_image_pins(&spec).is_err());
    }

    #[tokio::test]
    async fn an_unavailable_supervisor_is_an_error_not_a_pass() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/v1/workload/result",
            get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = fetch(&reqwest::Client::new(), &format!("http://{address}")).await;
        task.abort();
        assert!(result.is_err());
    }
}
