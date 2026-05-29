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
//! # Auth posture
//!
//! Internal services connect over Fly.io 6PN, which is WireGuard-
//! encrypted in transit. SPIFFE JWT-SVID authentication on the gRPC
//! surface is iter-2 (uses the same `verify_jwt_svid` helper as the
//! REST extractor); iter-1 runs the gRPC surface open since deploys
//! ship it on a private listener that only same-org Fly machines
//! reach. Production callers MUST set `--spiffe-trust-jwks-path`
//! before exposing the gRPC port outside the 6PN.

use nucleus_control_plane::{AgentDriverRef, Destination, InputRef, JobId, JobSpec, JobState};
use nucleus_proto::control_plane::{
    job_service_server::JobService, JobIdMessage, JobStatus, JobStatusCode, JobSubmission,
    SubmittedJob,
};
use tonic::{Request, Response, Status};

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
        };
        let id = self
            .state
            .jobs
            .insert(initial)
            .map_err(|e| Status::internal(format!("registry insert: {e}")))?;

        tracing::info!(
            job_id = %id,
            driver = %spec.agent_driver.name,
            "gRPC JobService.Submit accepted job"
        );

        Ok(Response::new(SubmittedJob {
            job_id: id.to_string(),
        }))
    }

    async fn get(&self, request: Request<JobIdMessage>) -> Result<Response<JobStatus>, Status> {
        let id = JobId::from_raw(request.into_inner().job_id);
        let state = self
            .state
            .jobs
            .get(&id)
            .map_err(|_| Status::not_found(format!("job {id} not found")))?;
        Ok(Response::new(to_job_status(&id, state)))
    }
}
