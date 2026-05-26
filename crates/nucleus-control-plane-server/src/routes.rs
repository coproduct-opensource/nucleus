//! Route handlers. Each handler returns `Result<T, ApiError>` so
//! [`ApiError::into_response`] handles the error wire format uniformly.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use nucleus_control_plane::{execute_job, JobId, JobOutcome, JobSpec, JobState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::state::AppState;

/// Response body for a successful `POST /v1/jobs`. Mirrors
/// async-job-API consensus: stable status URL + initial state.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobSubmissionResponse {
    pub job_id: JobId,
    pub status_url: String,
    pub state: JobState,
}

/// `GET /healthz` — liveness only. Doesn't check downstream signers
/// because the demo issuer is in-process; production deployments will
/// extend this with a Workload API ping.
pub async fn healthz() -> &'static str {
    "ok"
}

/// `POST /v1/jobs` — submit a [`JobSpec`].
///
/// Honors `Idempotency-Key` (request header): a repeat submission with
/// the same key returns the existing job (200 + Location), no
/// re-execution. Without a key, every POST starts a new job (202 +
/// Location).
///
/// Returns `202 Accepted` for the new-job path because we kick off the
/// runner asynchronously via `tokio::spawn`. The MockJobRunner is
/// synchronous and fast in practice — clients should still poll the
/// status URL rather than assuming immediate completion.
pub async fn submit_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(spec): Json<JobSpec>,
) -> Result<impl IntoResponse, ApiError> {
    // Look up the driver up front so we fail fast on unknown drivers
    // rather than after queueing the job.
    if state.runners.get(&spec.agent_driver.name).is_none() {
        return Err(ApiError::UnknownDriver(spec.agent_driver.name.clone()));
    }

    // Idempotency: collapse `Idempotency-Key` + body hash → JobId.
    // We hash the body so a key reused with a *different* spec is
    // treated as a fresh submission (the industry pattern; reusing a
    // key with a different body is almost always a client bug).
    let idem_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| {
            let mut h = Sha256::new();
            h.update(k.as_bytes());
            h.update(b"\0");
            h.update(serde_json::to_vec(&spec).unwrap_or_default());
            format!("{k}:{}", hex::encode(h.finalize()))
        });

    if let Some(ref key) = idem_key {
        if let Some(existing) = state
            .jobs
            .find_by_idempotency_key(key)
            .map_err(|e| ApiError::Internal(e.to_string()))?
        {
            let current = state
                .jobs
                .get(&existing)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            let response = JobSubmissionResponse {
                job_id: existing.clone(),
                status_url: format!("/v1/jobs/{}", existing),
                state: current,
            };
            let location = response.status_url.clone();
            return Ok((
                StatusCode::OK, // repeat submission → 200, not 202
                [(header::LOCATION, location)],
                Json(response),
            )
                .into_response());
        }
    }

    let now = Utc::now();
    let job_id = state
        .jobs
        .insert(JobState::Queued { submitted_at: now })
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if let Some(key) = idem_key {
        state
            .jobs
            .record_idempotency(key, job_id.clone())
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }

    spawn_job(state.clone(), job_id.clone(), spec);

    let response = JobSubmissionResponse {
        job_id: job_id.clone(),
        status_url: format!("/v1/jobs/{}", job_id),
        state: JobState::Queued { submitted_at: now },
    };
    let location = response.status_url.clone();
    Ok((
        StatusCode::ACCEPTED,
        [(header::LOCATION, location)],
        Json(response),
    )
        .into_response())
}

fn spawn_job(state: AppState, job_id: JobId, spec: JobSpec) {
    tokio::spawn(async move {
        // Move the actual execution onto a blocking thread — `execute_job`
        // (and the underlying lineage signer) is CPU-bound and uses
        // synchronous IO on the sink path. Keeping it off the tokio
        // worker thread avoids starving other handlers.
        let result = tokio::task::spawn_blocking({
            let state = state.clone();
            let job_id = job_id.clone();
            let spec = spec.clone();
            move || run_job_blocking(&state, &job_id, &spec)
        })
        .await;

        let new_state = match result {
            Ok(Ok(outcome)) => JobState::Completed {
                started_at: outcome.started_at,
                completed_at: Utc::now(),
                outcome: outcome.outcome,
            },
            Ok(Err(e)) => JobState::Failed {
                started_at: None,
                failed_at: Utc::now(),
                reason: e.to_string(),
            },
            Err(join_err) => JobState::Failed {
                started_at: None,
                failed_at: Utc::now(),
                reason: format!("runner task panicked or was cancelled: {join_err}"),
            },
        };

        if let Err(e) = state.jobs.update(&job_id, new_state) {
            tracing::error!(
                target: "nucleus_control_plane_server",
                "failed to persist final job state for {job_id}: {e}"
            );
        }
    });
}

/// Carrier for what `run_job_blocking` returns on success — we need to
/// reconstruct the `started_at` timestamp for the final `Completed`
/// state.
struct RunOutcome {
    started_at: chrono::DateTime<chrono::Utc>,
    outcome: JobOutcome,
}

fn run_job_blocking(
    state: &AppState,
    job_id: &JobId,
    spec: &JobSpec,
) -> Result<RunOutcome, String> {
    let started_at = Utc::now();
    let session_root = state.new_session_pod();

    // Mark as Running so polling clients see progress.
    state
        .jobs
        .update(
            job_id,
            JobState::Running {
                started_at,
                session_root: session_root.to_string(),
            },
        )
        .map_err(|e| e.to_string())?;

    let runner = state
        .runners
        .get(&spec.agent_driver.name)
        .ok_or_else(|| format!("unknown agent driver: {}", spec.agent_driver.name))?;

    let jwks: nucleus_lineage::Jwks =
        serde_json::from_value(state.issuer.publish_jwks()).map_err(|e| e.to_string())?;

    let bundle = execute_job(
        spec,
        &session_root,
        runner,
        state.sink.as_ref(),
        state.issuer.as_ref(),
        jwks,
        Vec::new(),
    )
    .map_err(|e| e.to_string())?;

    Ok(RunOutcome {
        started_at,
        outcome: JobOutcome {
            bundle,
            // v1 only supports InResponse delivery; the bundle ride the
            // status response. HttpPost / LocalPath are deferred.
            delivered: matches!(
                spec.destination,
                nucleus_control_plane::Destination::InResponse
            ),
        },
    })
}

/// `GET /v1/jobs/{id}` — current state snapshot.
pub async fn get_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobState>, ApiError> {
    let id = JobId::from_raw(job_id);
    let state = state.jobs.get(&id).map_err(|_| ApiError::NotFound)?;
    Ok(Json(state))
}

/// `GET /v1/jobs/{id}/bundle` — the verified provenance bundle.
///
/// Returns 200 with the bundle body when the job is `Completed`,
/// 409 with the current state otherwise, 404 if unknown.
pub async fn get_bundle(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<nucleus_envelope::Bundle>, ApiError> {
    let id = JobId::from_raw(job_id);
    let job_state = state.jobs.get(&id).map_err(|_| ApiError::NotFound)?;
    match job_state {
        JobState::Completed { outcome, .. } => Ok(Json(outcome.bundle)),
        JobState::Queued { .. } => Err(ApiError::Conflict { state: "queued" }),
        JobState::Running { .. } => Err(ApiError::Conflict { state: "running" }),
        JobState::Failed { .. } => Err(ApiError::Conflict { state: "failed" }),
    }
}
