//! gRPC implementation of `JobService` for the control-plane-server.
//!
//! Iter-1 surface mirrors the REST endpoints exposed under `/v1/jobs`:
//!
//! | gRPC                      | REST equivalent              |
//! |---------------------------|------------------------------|
//! | `JobService.Submit`       | `POST /v1/jobs`              |
//! | `JobService.Get`          | `GET  /v1/jobs/{id}`         |
//!
//! Iter-2 will add `StreamEvents` (matching SSE) and `Cancel`
//! (matching `POST /v1/jobs/{id}/cancel`) so internal callers can
//! avoid running both an HTTP and a gRPC client.
//!
//! # Auth posture (#2442)
//!
//! The gRPC surface is authenticated exactly like REST: every call carries
//! `authorization: Bearer <JWT-SVID>`, verified by the interceptor
//! [`intercepted`] installs against the SAME [`crate::auth::SpiffeAuthConfig`]
//! the REST extractor uses (one trust JWKS, one audience, one subject
//! prefix). The verified principal is placed in the request extensions;
//! `Submit` records it as the job's owner and `Get` refuses (NOT_FOUND, no
//! existence oracle) a job it does not own.
//!
//! It used to run open — "a private listener only same-org machines reach"
//! — with the boundary asserted in this comment rather than enforced, and
//! `Get` returned any job's bundle to anyone who could connect. Network
//! topology is not authentication. `main.rs` now refuses to bind the gRPC
//! listener without auth in a production build and binds loopback by default.

use nucleus_control_plane::{AgentDriverRef, Destination, InputRef, JobId, JobSpec, JobState};
use nucleus_proto::control_plane::{
    JobIdMessage, JobStatus, JobStatusCode, JobSubmission, SubmittedJob,
    job_service_server::{JobService, JobServiceServer},
};
use tonic::service::interceptor::InterceptedService;
use tonic::{Request, Response, Status};

use crate::auth::{AuthenticatedPrincipal, principal_from_grpc};
use crate::state::AppState;

/// gRPC service impl. Holds an `AppState` so handlers see the same
/// job registry, runner registry, and event broker as the REST
/// handlers.
pub struct GrpcJobService {
    state: AppState,
}

impl GrpcJobService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

/// The service wrapped in the JWT-SVID interceptor — the ONLY way `main.rs`
/// mounts it, so an unauthenticated gRPC surface is not constructible there.
pub fn intercepted(
    state: AppState,
) -> InterceptedService<
    JobServiceServer<GrpcJobService>,
    impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone,
> {
    let config = state.spiffe_auth.clone();
    JobServiceServer::with_interceptor(GrpcJobService::new(state), move |mut req: Request<()>| {
        let principal = principal_from_grpc(&req, config.as_deref())?;
        req.extensions_mut().insert(principal);
        Ok(req)
    })
}

/// The principal the interceptor verified for this call. Absent only if the
/// service was mounted without [`intercepted`], which is a programming error
/// reported as UNAUTHENTICATED rather than admitted.
fn principal_of<T>(request: &Request<T>) -> Result<AuthenticatedPrincipal, Status> {
    request
        .extensions()
        .get::<AuthenticatedPrincipal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("no verified principal on this call"))
}

/// Map a proto `JobSubmission` to the internal `JobSpec`. Iter-1
/// only supports `InputRef::Inline` + `Destination::InResponse`;
/// any other request shape returns `INVALID_ARGUMENT`.
fn to_job_spec(req: JobSubmission) -> Result<JobSpec, Status> {
    let driver = req
        .agent_driver
        .ok_or_else(|| Status::invalid_argument("agent_driver is required"))?;
    let inline = req
        .inline_input
        .ok_or_else(|| Status::invalid_argument("inline_input is required (iter-1)"))?;
    let content: serde_json::Value = serde_json::from_str(&inline.content_json)
        .map_err(|e| Status::invalid_argument(format!("inline_input.content_json: {e}")))?;
    let config: serde_json::Value = if driver.config_json.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&driver.config_json)
            .map_err(|e| Status::invalid_argument(format!("agent_driver.config_json: {e}")))?
    };
    Ok(JobSpec {
        input_ref: InputRef::Inline { content },
        task: req.task,
        destination: if req.destination_in_response {
            Destination::InResponse
        } else {
            return Err(Status::invalid_argument(
                "iter-1 gRPC only supports destination_in_response=true",
            ));
        },
        policy_profile: req.policy_profile,
        agent_driver: AgentDriverRef {
            name: driver.name,
            version: if driver.version.is_empty() {
                None
            } else {
                Some(driver.version)
            },
            config,
        },
    })
}

/// Map an internal `JobState` to a proto `JobStatus`.
fn to_job_status(job_id: &JobId, state: JobState) -> JobStatus {
    match state {
        JobState::Queued { .. } => JobStatus {
            job_id: job_id.to_string(),
            status: JobStatusCode::StatusQueued as i32,
            bundle_json: String::new(),
            failure_reason: String::new(),
        },
        JobState::Running { .. } => JobStatus {
            job_id: job_id.to_string(),
            status: JobStatusCode::StatusRunning as i32,
            bundle_json: String::new(),
            failure_reason: String::new(),
        },
        JobState::Completed { outcome, .. } => JobStatus {
            job_id: job_id.to_string(),
            status: JobStatusCode::StatusCompleted as i32,
            bundle_json: serde_json::to_string(&outcome.bundle).unwrap_or_default(),
            failure_reason: String::new(),
        },
        JobState::Failed { reason, .. } => JobStatus {
            job_id: job_id.to_string(),
            status: JobStatusCode::StatusFailed as i32,
            bundle_json: String::new(),
            failure_reason: reason,
        },
    }
}

#[tonic::async_trait]
impl JobService for GrpcJobService {
    async fn submit(
        &self,
        request: Request<JobSubmission>,
    ) -> Result<Response<SubmittedJob>, Status> {
        let principal = principal_of(&request)?;
        let req = request.into_inner();
        let spec = to_job_spec(req)?;

        // Driver lookup: same as the REST handler — fast-fail on
        // unknown driver names before doing any state I/O.
        if self.state.runners.get(&spec.agent_driver.name).is_none() {
            return Err(Status::failed_precondition(format!(
                "unknown agent driver: {}",
                spec.agent_driver.name
            )));
        }

        // Initial registry insert. Mirrors the synchronous portion of
        // the REST submit_job — the full job-execution wiring (spawning
        // the runner + emitting lineage edges) is iter-2 once we can
        // share an `execute_job_async` helper between REST + gRPC.
        let initial = JobState::Queued {
            submitted_at: chrono::Utc::now(),
            // The owner of record: the interceptor-verified caller, carried
            // forward unchanged through every later transition (#2433).
            owner: principal.sub().to_string(),
        };
        let id = self
            .state
            .jobs
            .insert(initial)
            .map_err(|e| Status::internal(format!("registry insert: {e}")))?;

        tracing::info!(
            job_id = %id,
            driver = %spec.agent_driver.name,
            owner = %principal.sub(),
            "gRPC JobService.Submit accepted job"
        );

        Ok(Response::new(SubmittedJob {
            job_id: id.to_string(),
        }))
    }

    async fn get(&self, request: Request<JobIdMessage>) -> Result<Response<JobStatus>, Status> {
        let principal = principal_of(&request)?;
        let id = JobId::from_raw(request.into_inner().job_id);
        let state = self
            .state
            .jobs
            .get(&id)
            .map_err(|_| Status::not_found(format!("job {id} not found")))?;
        // Same rule as REST (#2441): another owner's job is NOT FOUND, not
        // PERMISSION_DENIED — a denial would confirm the id exists.
        if !principal.owns(state.owner()) {
            tracing::warn!(
                caller = %principal.sub(),
                owner = %state.owner(),
                job_id = %id,
                "gRPC Get from a non-owner refused as not-found"
            );
            return Err(Status::not_found(format!("job {id} not found")));
        }
        Ok(Response::new(to_job_status(&id, state)))
    }
}
