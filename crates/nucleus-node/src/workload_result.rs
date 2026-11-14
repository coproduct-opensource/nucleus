//! Fetch the supervising proxy's read-only observation through the node-owned
//! proxy bridge. Pod lineage is checked before revealing or contacting it.
//! This response does not itself assert a sandbox tier or carry a signature.

use axum::Json;
use axum::extract::{Extension, Path, State};
use nucleus_ci_verdict::execution::{Backend, ExecutionClaim, ExecutionSchema, SandboxTier};
use nucleus_receipt::{Receipt, Session};
use nucleus_spec::workload_result::WorkloadResult;
use nucleus_spec::workload_result::{ProgramBinding, WorkloadIsolation};
use uuid::Uuid;

use crate::{ApiError, DriverState, NodeState, pod_api};

mod admission;
mod logs;

pub(crate) fn routes() -> axum::Router<NodeState> {
    use axum::routing::get;
    axum::Router::new()
        .route("/v1/pods/{id}/workload-admission", get(admission::get))
        .route("/v1/pods/{id}/workload-result", get(self::get))
        .route("/v1/pods/{id}/workload-logs/stdout", get(logs::stdout))
        .route("/v1/pods/{id}/workload-logs/stderr", get(logs::stderr))
        .route(
            "/v1/pods/{id}/execution-receipt",
            get(receipt).post(crate::workload_artifacts::collect),
        )
}

pub(crate) async fn get(
    State(state): State<NodeState>,
    Extension(caller): Extension<crate::auth::CallerScope>,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkloadResult>, ApiError> {
    let pod = pod_api::get_pod_for_caller(&state, id, &caller).await?;
    let address =
        pod.proxy_addr.lock().await.clone().ok_or_else(|| {
            ApiError::SupervisorUnavailable("proxy address is not ready".to_string())
        })?;
    let proof = observation_proof(
        &pod,
        &address,
        "/v1/workload/result",
        state.request_proofs.is_some(),
    )
    .await?;
    fetch(&state.http_client, &address, proof.as_deref())
        .await
        .map(Json)
}

/// Sign only the protected supervisor's completed observation, using the
/// existing host-only executor key. Local/container evidence remains labeled
/// as such and the public microVM verifier refuses it.
pub(crate) async fn receipt(
    State(state): State<NodeState>,
    Extension(caller): Extension<crate::auth::CallerScope>,
    Path(id): Path<Uuid>,
) -> Result<Json<Receipt>, ApiError> {
    let (claim, _) = observe_claim(&state, &caller, id).await?;
    sign_claim(&state, id, claim).map(Json)
}

pub(crate) async fn observe_claim(
    state: &NodeState,
    caller: &crate::auth::CallerScope,
    id: Uuid,
) -> Result<(ExecutionClaim, String), ApiError> {
    let pod = pod_api::get_pod_for_caller(state, id, caller).await?;
    let backend = backend_of(&pod.driver_state);
    let address = pod
        .proxy_addr
        .lock()
        .await
        .clone()
        .ok_or_else(|| ApiError::SupervisorUnavailable("proxy address is not ready".into()))?;
    let proof = observation_proof(
        &pod,
        &address,
        "/v1/workload/result",
        state.request_proofs.is_some(),
    )
    .await?;
    let observed = fetch(&state.http_client, &address, proof.as_deref()).await?;
    let claim = completed_claim(
        &pod.spec,
        id,
        backend,
        observed,
        state.node_platform.platform(),
        // The same value that chose the key `sign_claim` signs with.
        state.trust_gate.tier.claim_tier(),
    )?;
    Ok((claim, address))
}

/// The backend a pod runs on, from the driver the host spawned it with: never from a label.
pub(crate) fn backend_of(driver: &DriverState) -> Backend {
    match driver {
        #[cfg(feature = "local-driver")]
        DriverState::Local(_) => Backend::Local,
        DriverState::Container(_) => Backend::Container,
        DriverState::Firecracker(_) => Backend::Firecracker,
    }
}

pub(crate) fn sign_claim(
    state: &NodeState,
    id: Uuid,
    claim: ExecutionClaim,
) -> Result<Receipt, ApiError> {
    // The key decides the mark (Program C, C0): a claim is signed only under
    // the signing domain it declares, so the insecure key never signs a claim
    // without the insecure tier, nor the executor key a claim with it.
    if claim.sandbox_tier != state.trust_gate.tier.claim_tier() {
        return Err(ApiError::Driver(format!(
            "execution claim declares {:?}, but this node signs as {:?}",
            claim.sandbox_tier, state.trust_gate.tier
        )));
    }
    let projection = claim
        .to_projection()
        .map_err(|e| ApiError::Driver(format!("encoding execution claim: {e}")))?;
    let issued = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Driver(format!("execution receipt clock: {e}")))?;
    let issued_at_micros = u64::try_from(issued.as_micros())
        .map_err(|e| ApiError::Driver(format!("execution receipt clock overflow: {e}")))?;
    Ok(Receipt::sign(
        Session {
            session_id: id.to_string(),
            issuer_kid: state.trust_gate.executor_id.clone(),
            issued_at_micros,
            parent_chain: Vec::new(),
        },
        vec![projection],
        &state.trust_gate.executor_signing_key,
    ))
}

fn completed_claim(
    spec: &nucleus_spec::PodSpec,
    id: Uuid,
    backend: Backend,
    observed: WorkloadResult,
    node_platform: nucleus_ci_verdict::execution::NodePlatform,
    sandbox_tier: SandboxTier,
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
        namespace,
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
    let workload = spec.spec.workload.as_ref().ok_or_else(|| {
        ApiError::Driver("execution observation has no configured workload".into())
    })?;
    // The same decider the create-time admission used, for this backend: a
    // spec this runtime cannot enforce is never signed, and the supervisor's
    // record of what the hook did must be exactly what the spec was admitted
    // for (#3528).
    let expected_namespace = workload
        .namespace
        .admit(
            workload.uid,
            crate::spec_posture::namespace_enforcement(Some(backend)),
        )
        .map_err(|e| ApiError::Driver(e.to_string()))?
        .setup();
    if namespace != expected_namespace {
        return Err(ApiError::Driver(
            "supervisor namespace setup differs from admitted spec".into(),
        ));
    }
    let expected = nucleus_spec::identity::program_digest(spec)
        .map_err(|e| ApiError::Driver(format!("host program identity: {e}")))?;
    if digest != expected {
        return Err(ApiError::Driver(
            "supervisor program identity differs from host spec".into(),
        ));
    }
    let source_commit = spec
        .metadata
        .labels
        .get("build.source.commit")
        .cloned()
        .unwrap_or_default();
    let source_tree = spec
        .metadata
        .labels
        .get("build.source.tree")
        .cloned()
        .unwrap_or_default();
    let gate = spec
        .metadata
        .labels
        .get("build.gate")
        .cloned()
        .unwrap_or_default();
    Ok(ExecutionClaim {
        schema: ExecutionSchema::V2,
        pod_id: id.to_string(),
        source_commit,
        source_tree,
        gate,
        program_digest: expected,
        architecture: std::env::consts::ARCH.into(),
        backend,
        uid_isolated: isolation == WorkloadIsolation::UidIsolated,
        namespace,
        exit_code,
        stdout_sha256,
        stderr_sha256,
        launch_hash,
        environment_inputs_sha256: environment.inputs_sha256,
        environment_complete_sha256: environment.complete_sha256,
        artifacts: Default::default(),
        node_platform,
        sandbox_tier,
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
        rootfs: _,
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

async fn observation_proof(
    pod: &crate::PodHandle,
    address: &str,
    path: &str,
    required: bool,
) -> Result<Option<String>, ApiError> {
    let holder = match &pod.driver_state {
        #[cfg(feature = "local-driver")]
        DriverState::Local(driver) => &driver.signed_proxy,
        DriverState::Container(driver) => &driver.signed_proxy,
        DriverState::Firecracker(driver) => &driver.signed_proxy,
    };
    let endpoint = holder
        .lock()
        .await
        .as_ref()
        .map(|proxy| proxy.observation_endpoint());
    let proof = match endpoint {
        Some(endpoint) => endpoint
            .proof(address, path)
            .map_err(|e| ApiError::Driver(format!("supervisor observation proof: {e}")))?,
        None => None,
    };
    if required && proof.is_none() {
        return Err(ApiError::Driver(
            "supervisor observation authority unavailable".into(),
        ));
    }
    Ok(proof)
}

async fn fetch(
    client: &reqwest::Client,
    address: &str,
    proof: Option<&str>,
) -> Result<WorkloadResult, ApiError> {
    let request = client
        .get(format!(
            "{}/v1/workload/result",
            address.trim_end_matches('/')
        ))
        .timeout(std::time::Duration::from_secs(10));
    let request = match proof {
        Some(proof) => request.header("dpop", proof),
        None => request,
    };
    let mut response = request
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| supervisor_error("reading workload supervisor", e))?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| supervisor_error("reading workload result body", e))?
    {
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(ApiError::Driver("workload result exceeds 16 KiB".into()));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| ApiError::Driver(format!("malformed workload supervisor result: {e}")))
}

fn supervisor_error(context: &str, error: reqwest::Error) -> ApiError {
    if let Some(status) = error.status() {
        let message = format!("{context}: {error}");
        if status.is_server_error() {
            ApiError::SupervisorUnavailable(message)
        } else {
            ApiError::Driver(message)
        }
    } else {
        let reason = if error.is_timeout() {
            "timed out"
        } else if error.is_connect() {
            "connection failed"
        } else {
            "transport failed"
        };
        ApiError::SupervisorUnavailable(format!("{context}: {reason}: {error}"))
    }
}

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    fn spec() -> nucleus_spec::PodSpec {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "nucleus/v1", "kind": "Pod",
            "metadata": {"name": "observation-test"},
            "spec": {"policy":{"type":"profile","name":"default"},"work_dir": "/work",
                     "workload": {"command":"/usr/bin/true"}}
        }))
        .unwrap()
    }

    fn observed(spec: &nucleus_spec::PodSpec) -> WorkloadResult {
        observed_namespace(spec, nucleus_spec::NamespaceSetup::Runtime {})
    }

    fn observed_namespace(
        spec: &nucleus_spec::PodSpec,
        namespace: nucleus_spec::NamespaceSetup,
    ) -> WorkloadResult {
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
            namespace,
        }
    }

    fn unattested() -> nucleus_ci_verdict::execution::NodePlatform {
        nucleus_ci_verdict::execution::NodePlatform::Unattested {
            reason: "test node".into(),
        }
    }

    #[test]
    fn the_node_signs_runtime_placement_and_nothing_else() {
        use nucleus_spec::{NamespaceSetup, WorkloadNamespace};
        let claim_for = |spec: &nucleus_spec::PodSpec, observed: NamespaceSetup| {
            completed_claim(
                spec,
                Uuid::nil(),
                Backend::Local,
                observed_namespace(spec, observed),
                unattested(),
                SandboxTier::Driver,
            )
        };
        let runtime = spec();
        let claim = claim_for(&runtime, NamespaceSetup::Runtime {}).unwrap();
        assert_eq!(claim.schema, ExecutionSchema::V2);
        assert_eq!(claim.namespace, NamespaceSetup::Runtime {});
        let private = NamespaceSetup::PrivateUserNetwork {
            outer_uid: 65534,
            inner_uid: 1000,
            loopback: true,
        };
        // A supervisor reporting anything but the admitted runtime placement
        // is not signed.
        for wrong in [
            private,
            NamespaceSetup::PrivateNetwork {},
            NamespaceSetup::Unrecorded {},
        ] {
            assert!(claim_for(&runtime, wrong).is_err(), "{wrong:?}");
        }
        // A spec this runtime cannot enforce is not signed, even when the
        // observation agrees with it.
        let mut requested = spec();
        requested.spec.workload.as_mut().unwrap().namespace =
            WorkloadNamespace::PrivateUserNetwork {
                inner_uid: 1000,
                loopback: true,
            };
        for observed in [private, NamespaceSetup::Runtime {}] {
            assert!(claim_for(&requested, observed).is_err(), "{observed:?}");
        }
    }

    /// #3528: on the backend that makes it, a private placement is signed,
    /// and only when the supervisor's hook record is exactly the admitted
    /// mapping: the outer uid the spec states, the inner uid and the loopback
    /// state it asked for. A record that differs in any one of them, or says
    /// `runtime`, is not signed; neither is a spec whose outer uid is left to
    /// a default.
    #[test]
    fn the_node_signs_a_private_placement_only_as_the_hook_recorded_it() {
        use nucleus_spec::{NamespaceSetup, WorkloadNamespace};
        let mut pinned = spec();
        let digest = format!("sha-256:{}", "a".repeat(64));
        pinned.spec.image = Some(
            serde_json::from_value(serde_json::json!({
                "kernel_path": "/kernel", "rootfs_path": "/rootfs",
                "kernel_digest": digest, "rootfs_digest": digest, "read_only": true
            }))
            .unwrap(),
        );
        let workload = pinned.spec.workload.as_mut().unwrap();
        workload.uid = Some(65534);
        workload.namespace = WorkloadNamespace::PrivateUserNetwork {
            inner_uid: 1001,
            loopback: false,
        };
        let claim_for = |spec: &nucleus_spec::PodSpec, observed: NamespaceSetup| {
            completed_claim(
                spec,
                Uuid::nil(),
                Backend::Firecracker,
                observed_namespace(spec, observed),
                unattested(),
                SandboxTier::Driver,
            )
        };
        let admitted = NamespaceSetup::PrivateUserNetwork {
            outer_uid: 65534,
            inner_uid: 1001,
            loopback: false,
        };
        let claim = claim_for(&pinned, admitted).expect("the hook record matches");
        assert_eq!(claim.schema, ExecutionSchema::V2);
        assert_eq!(claim.namespace, admitted);
        for wrong in [
            NamespaceSetup::PrivateUserNetwork {
                outer_uid: 4242,
                inner_uid: 1001,
                loopback: false,
            },
            NamespaceSetup::PrivateUserNetwork {
                outer_uid: 65534,
                inner_uid: 0,
                loopback: false,
            },
            NamespaceSetup::PrivateUserNetwork {
                outer_uid: 65534,
                inner_uid: 1001,
                loopback: true,
            },
            NamespaceSetup::Runtime {},
            NamespaceSetup::Unrecorded {},
        ] {
            assert!(claim_for(&pinned, wrong).is_err(), "{wrong:?}");
        }
        pinned.spec.workload.as_mut().unwrap().uid = None;
        assert!(
            claim_for(&pinned, admitted).is_err(),
            "an outer uid left to a default is not a mapping anyone can check"
        );
    }

    #[test]
    fn signing_preparation_preserves_actual_exit_and_backend() {
        let spec = spec();
        let claim = completed_claim(
            &spec,
            Uuid::nil(),
            Backend::Local,
            observed(&spec),
            unattested(),
            SandboxTier::Driver,
        )
        .unwrap();
        assert_eq!(claim.exit_code, Some(23));
        assert_eq!(claim.backend, Backend::Local);
        assert_eq!(
            claim.node_platform,
            unattested(),
            "the node's platform is recorded as given"
        );
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
            assert!(
                completed_claim(
                    &spec,
                    Uuid::nil(),
                    Backend::Local,
                    result,
                    unattested(),
                    SandboxTier::Driver
                )
                .is_err()
            );
        }
        let mut observation = observed(&spec);
        if let WorkloadResult::Exited { program, .. } = &mut observation {
            *program = ProgramBinding::Bound {
                digest: "another program".into(),
            };
        }
        assert!(
            completed_claim(
                &spec,
                Uuid::nil(),
                Backend::Local,
                observation,
                unattested(),
                SandboxTier::Driver
            )
            .is_err()
        );
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
        let result = fetch(&reqwest::Client::new(), &format!("http://{address}"), None).await;
        task.abort();
        assert!(result.is_err());
    }
}
