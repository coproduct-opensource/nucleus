//! Route handlers. Each handler returns `Result<T, ApiError>` so
//! [`ApiError::into_response`] handles the error wire format uniformly.

use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use chrono::Utc;
use futures_util::Stream;
use nucleus_control_plane::{execute_job, JobId, JobOutcome, JobSpec, JobState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::events::JobEvent;
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
    _: crate::auth::RequireSpiffeAuth,
    headers: HeaderMap,
    Json(spec): Json<JobSpec>,
) -> Result<impl IntoResponse, ApiError> {
    // Look up the driver up front so we fail fast on unknown drivers
    // rather than after queueing the job.
    if state.runners.get(&spec.agent_driver.name).is_none() {
        return Err(ApiError::UnknownDriver(spec.agent_driver.name.clone()));
    }

    // Reject input-ref variants that need an allow-list before we let
    // them onto a network-reachable surface. The MockJobRunner already
    // refuses Url, but other drivers might happily fetch it (SSRF) or
    // read arbitrary local paths (e.g. /etc/shadow). Until per-driver
    // capabilities exist, the API layer rejects both. A deployment
    // that needs them can build a custom server with its own router.
    match &spec.input_ref {
        nucleus_control_plane::InputRef::Inline { .. } => {}
        nucleus_control_plane::InputRef::Url { .. } => {
            return Err(ApiError::BadRequest(
                "InputRef::Url is not permitted on the public control-plane (SSRF surface); \
                 use InputRef::Inline or run a driver-specific server"
                    .into(),
            ));
        }
        nucleus_control_plane::InputRef::LocalPath { .. } => {
            return Err(ApiError::BadRequest(
                "InputRef::LocalPath is not permitted on the public control-plane (arbitrary \
                 file-read surface); inline the content via InputRef::Inline"
                    .into(),
            ));
        }
    }

    // Compute the idempotency hash up front. Serialization failure on
    // a fully-typed `JobSpec` is essentially unreachable (`serde_json`
    // on this Serialize impl only fails on I/O, which doesn't apply),
    // but if it does fail we propagate as Internal rather than silently
    // collapsing every "failed" submission onto the empty-hash bucket.
    let idem_key = match headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        Some(k) => {
            let spec_bytes = serde_json::to_vec(&spec)
                .map_err(|e| ApiError::Internal(format!("idempotency hash: {e}")))?;
            let mut h = Sha256::new();
            h.update(k.as_bytes());
            h.update(b"\0");
            h.update(&spec_bytes);
            Some(format!("{k}:{}", hex::encode(h.finalize())))
        }
        None => None,
    };

    let now = Utc::now();
    let queued = JobState::Queued { submitted_at: now };

    let (job_id, freshly_inserted) = match idem_key {
        Some(key) => state
            .jobs
            .insert_with_idempotency(key, queued.clone())
            .map_err(|e| ApiError::Internal(e.to_string()))?,
        None => {
            let id = state
                .jobs
                .insert(queued.clone())
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            (id, true)
        }
    };

    if !freshly_inserted {
        // Repeat submission with the same Idempotency-Key + body — no
        // re-execution. Return the existing job's state with 200.
        let current = state
            .jobs
            .get(&job_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let response = JobSubmissionResponse {
            job_id: job_id.clone(),
            status_url: format!("/v1/jobs/{}", job_id),
            state: current,
        };
        let location = response.status_url.clone();
        return Ok((
            StatusCode::OK,
            [(header::LOCATION, location)],
            Json(response),
        )
            .into_response());
    }

    // **MED-6 (audit) fix.** Acquire a job-slot permit BEFORE
    // publishing the queued event or spawning. If the server is at
    // capacity, surface 503 at_capacity so the caller can retry
    // later. Held by the spawned task and released when the terminal
    // state is published. Without this, an attacker generating
    // distinct Idempotency-Key values per request could queue
    // unbounded blocking tasks.
    let permit = match state.job_slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return Err(ApiError::AtCapacity {
                in_flight: crate::state::MAX_INFLIGHT_JOBS - state.job_slots.available_permits(),
                max: crate::state::MAX_INFLIGHT_JOBS,
            });
        }
    };

    // Publish the initial queued event so a subscriber attaching right
    // away catches the lifecycle from the start.
    state.events.publish(
        &job_id,
        JobEvent::StateChanged {
            state: queued.clone(),
        },
    );

    spawn_job(state.clone(), job_id.clone(), spec, permit);

    let response = JobSubmissionResponse {
        job_id: job_id.clone(),
        status_url: format!("/v1/jobs/{}", job_id),
        state: queued,
    };
    let location = response.status_url.clone();
    Ok((
        StatusCode::ACCEPTED,
        [(header::LOCATION, location)],
        Json(response),
    )
        .into_response())
}

fn spawn_job(
    state: AppState,
    job_id: JobId,
    spec: JobSpec,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    tokio::spawn(async move {
        // **MED-6**: hold the job-slot permit for the lifetime of
        // this task. Dropped when the function returns (after
        // publishing the terminal event), which is when the slot
        // becomes available for a new submission.
        let _permit = permit;
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
                outcome: Box::new(outcome.outcome),
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

        // If the registry write fails, the SSE stream MUST NOT advertise
        // a state the registry doesn't hold. Convert the failure into a
        // Failed terminal so subscribers see a coherent (state, polling)
        // pair instead of a divergent one.
        let published_state = match state.jobs.update(&job_id, new_state.clone()) {
            Ok(()) => new_state,
            Err(e) => {
                tracing::error!(
                    target: "nucleus_control_plane_server",
                    "failed to persist final job state for {job_id}: {e}"
                );
                let synthesized = JobState::Failed {
                    started_at: None,
                    failed_at: Utc::now(),
                    reason: format!("registry update failed: {e}"),
                };
                // Best-effort retry — same registry, but now writing a
                // Failed state. If that also fails, the SSE Closing
                // event documents the divergence.
                let _ = state.jobs.update(&job_id, synthesized.clone());
                synthesized
            }
        };
        state.events.publish(
            &job_id,
            JobEvent::StateChanged {
                state: published_state,
            },
        );
        state.events.publish(
            &job_id,
            JobEvent::Closing {
                reason: "terminal_state",
            },
        );
        state.events.close(&job_id);
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
    let running = JobState::Running {
        started_at,
        session_root: session_root.to_string(),
    };
    state
        .jobs
        .update(job_id, running.clone())
        .map_err(|e| e.to_string())?;
    state
        .events
        .publish(job_id, JobEvent::StateChanged { state: running });

    let runner = state
        .runners
        .get(&spec.agent_driver.name)
        .ok_or_else(|| format!("unknown agent driver: {}", spec.agent_driver.name))?;

    let jwks: nucleus_lineage::Jwks =
        serde_json::from_value(state.issuer.publish_jwks()).map_err(|e| e.to_string())?;

    // The issuer that signs edges is also the binding signer — a v2.2
    // PayloadBinding's `keyid` looks up into the same JWKS as edge
    // signatures, so re-using the key keeps the trust topology flat.
    let issuer_ref: &dyn nucleus_lineage::EdgeSigner = state.issuer.as_ref();
    let bundle = execute_job(
        spec,
        &session_root,
        runner,
        state.sink.as_ref(),
        issuer_ref,
        jwks,
        Vec::new(),
        state.merkle_prover.as_deref(),
        Some(issuer_ref),
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
    _: crate::auth::RequireSpiffeAuth,
    Path(job_id): Path<String>,
) -> Result<Json<JobState>, ApiError> {
    let id = JobId::from_raw(job_id);
    let state = state.jobs.get(&id).map_err(|_| ApiError::NotFound)?;
    Ok(Json(state))
}

/// `POST /v1/jobs/{id}/cancel` — request cancellation.
///
/// Idempotent:
/// - If the job is `Queued` or `Running`, the registry is updated to
///   `Failed { reason = "cancelled" }` and a `job_state_changed`
///   event is published to the SSE broker. The endpoint returns 200
///   with the new state.
/// - If the job is already `Completed` or `Failed`, the current state
///   is returned unchanged with 200. Repeated cancel calls are safe.
/// - If the job is unknown, 404.
///
/// **Iter-1 of #78** does NOT terminate in-flight agent execution —
/// the MockJobRunner is synchronous and the surface for cooperative
/// cancellation through JobRunner is iter-2 (will plumb a
/// CancellationToken through the runner trait). When the registry
/// later observes the runner emitting a terminal Completed state,
/// the cancellation transition takes precedence (the cancel was
/// requested first; the runner's response is recorded in lineage
/// but doesn't unwind the cancel decision).
pub async fn cancel_job(
    State(state): State<AppState>,
    _: crate::auth::RequireSpiffeAuth,
    Path(job_id): Path<String>,
) -> Result<Json<JobState>, ApiError> {
    let id = JobId::from_raw(job_id);
    let current = state.jobs.get(&id).map_err(|_| ApiError::NotFound)?;
    let next = match &current {
        JobState::Queued { .. } | JobState::Running { .. } => {
            let new_state = JobState::Failed {
                started_at: match &current {
                    JobState::Running { started_at, .. } => Some(*started_at),
                    _ => None,
                },
                failed_at: chrono::Utc::now(),
                reason: "cancelled by client request".to_string(),
            };
            state
                .jobs
                .update(&id, new_state.clone())
                .map_err(|_| ApiError::NotFound)?;
            state.events.publish(
                &id,
                crate::events::JobEvent::StateChanged {
                    state: new_state.clone(),
                },
            );
            tracing::info!(job_id = %id, "job cancelled by client");
            new_state
        }
        JobState::Completed { .. } | JobState::Failed { .. } => {
            // Idempotent: terminal state already; return unchanged.
            current.clone()
        }
    };
    Ok(Json(next))
}

/// `GET /v1/jobs/{id}/events/stream` — Server-Sent Events stream of
/// lifecycle transitions for the job.
///
/// Flow:
/// 1. Validate the job exists (404 if not).
/// 2. Emit the current state as the first `state_changed` event so a
///    late subscriber catches up. If the current state is terminal,
///    also emit `closing` and end the stream — no further events
///    will ever fire for this job.
/// 3. Otherwise, subscribe to the broker and forward future events.
///    Keep-alive comments every 15s to prevent intermediary timeouts.
///
/// Lagged receivers (broker channel backlog overflow) are handled by
/// re-emitting the current state from the registry and continuing.
/// Events deliberately don't carry monotonic IDs in v1 — `Last-Event-ID`
/// resumption is a v2 surface that needs a persistent event log.
pub async fn stream_job_events(
    State(state): State<AppState>,
    _: crate::auth::RequireSpiffeAuth,
    Path(job_id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let id = JobId::from_raw(job_id);
    let current = state.jobs.get(&id).map_err(|_| ApiError::NotFound)?;
    let stream = build_event_stream(state, id, current);
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn build_event_stream(
    state: AppState,
    job_id: JobId,
    current: JobState,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        // 1) Emit the current state as the first event (catch-up).
        let initial = JobEvent::StateChanged { state: current.clone() };
        yield Ok(event_for(&initial));

        // If the job is already terminal, close immediately.
        if matches!(current, JobState::Completed { .. } | JobState::Failed { .. }) {
            yield Ok(event_for(&JobEvent::Closing { reason: "already_terminal" }));
            return;
        }

        // 2) Subscribe to live events. If the broker has no channel
        //    (job completed between the registry read and subscribe),
        //    bail with a closing event.
        let mut rx = match state.events.subscribe(&job_id) {
            Some(rx) => rx,
            None => {
                yield Ok(event_for(&JobEvent::Closing { reason: "no_active_stream" }));
                return;
            }
        };

        // 3) Forward events.
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match rx.recv().await {
                Ok(evt) => {
                    let is_closing = matches!(evt, JobEvent::Closing { .. });
                    yield Ok(event_for(&evt));
                    if is_closing {
                        return;
                    }
                }
                Err(RecvError::Closed) => {
                    yield Ok(event_for(&JobEvent::Closing { reason: "broker_closed" }));
                    return;
                }
                Err(RecvError::Lagged(_skipped)) => {
                    // Re-fetch state and emit a state_changed so the client
                    // catches up. Skipped events are typically intermediate
                    // states; the registry holds the most recent.
                    if let Ok(latest) = state.jobs.get(&job_id) {
                        yield Ok(event_for(&JobEvent::StateChanged { state: latest.clone() }));
                        if matches!(latest, JobState::Completed { .. } | JobState::Failed { .. }) {
                            yield Ok(event_for(&JobEvent::Closing { reason: "terminal_after_lag" }));
                            return;
                        }
                    } else {
                        return;
                    }
                }
            }
        }
    }
}

fn event_for(evt: &JobEvent) -> Event {
    let data = serde_json::to_string(evt).unwrap_or_else(|_| "{}".to_string());
    Event::default().event(evt.name()).data(data)
}

/// `GET /v1/jobs/{id}/bundle` — the verified provenance bundle.
///
/// Returns 200 with the bundle body when the job is `Completed`,
/// 409 with the current state otherwise, 404 if unknown.
pub async fn get_bundle(
    State(state): State<AppState>,
    _: crate::auth::RequireSpiffeAuth,
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
