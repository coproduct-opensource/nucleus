//! End-to-end tests that drive the axum app via `tower::ServiceExt::oneshot`
//! — no TCP socket, no real bind. The MockJobRunner runs synchronously
//! so polling typically lands a `Completed` state on the very next call.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use nucleus_control_plane::{
    AgentDriverRef, Destination, InputRef, JobSpec, JobState, MockJobRunner,
};
use nucleus_control_plane_server::{
    build_app, registry::RunnerRegistry, state::build_demo_state, AppState,
};
use nucleus_envelope::{verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::{InMemorySink, Jwks};
use serde_json::Value;
use tower::ServiceExt;

fn sample_spec() -> JobSpec {
    JobSpec {
        input_ref: InputRef::Inline {
            content: serde_json::json!({"raw": "hello"}),
        },
        task: "summarize".to_string(),
        destination: Destination::InResponse,
        policy_profile: "report-extraction".to_string(),
        agent_driver: AgentDriverRef {
            name: "mock".to_string(),
            version: None,
            config: serde_json::json!({}),
        },
    }
}

fn fresh_state() -> AppState {
    let runners = RunnerRegistry::new().register("mock", Box::new(MockJobRunner));
    let sink = Arc::new(InMemorySink::new());
    build_demo_state(
        runners,
        sink,
        "test.nucleus.local",
        "agents",
        "control-plane",
    )
    .expect("demo state should build")
}

async fn read_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body should be JSON")
}

async fn poll_until_completed(app: axum::Router, job_id: &str, max_attempts: usize) -> Value {
    for attempt in 0..max_attempts {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/v1/jobs/{job_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp.into_body()).await;
        let state = body.get("state").and_then(|s| s.as_str()).unwrap_or("");
        if state == "completed" {
            return body;
        }
        if state == "failed" {
            panic!("job failed on attempt {attempt}: {body}");
        }
        // Brief sleep to actually surrender runtime time to the
        // spawned blocking task. `yield_now` alone is not sufficient
        // when the worker is single-threaded and the blocking task
        // is awaiting on a thread-pool result.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("job {job_id} did not reach completed state within {max_attempts} polls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_returns_ok() {
    let app = build_app(fresh_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_then_poll_then_fetch_bundle() {
    let state = fresh_state();
    let app = build_app(state.clone());

    // 1) Submit.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    let submission = read_json(resp.into_body()).await;
    let job_id = submission["job_id"].as_str().unwrap().to_string();
    assert_eq!(location, format!("/v1/jobs/{job_id}"));

    // 2) Poll until Completed.
    let final_state = poll_until_completed(app.clone(), &job_id, 100).await;
    assert_eq!(final_state["state"], "completed");

    // 3) Fetch bundle.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/jobs/{job_id}/bundle"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bundle: Bundle = serde_json::from_value(read_json(resp.into_body()).await).unwrap();
    assert_eq!(bundle.envelope.edges.len(), 5);

    // And it verifies against the server's actual issuer JWKS.
    let jwks: Jwks = serde_json::from_value(state.issuer.publish_jwks()).unwrap();
    let report = verify_bundle(&bundle, &TrustAnchor::from_jwks(jwks))
        .expect("bundle from API must verify against the issuer JWKS");
    assert_eq!(report.edge_count, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_driver_returns_422() {
    let app = build_app(fresh_state());
    let mut spec = sample_spec();
    spec.agent_driver.name = "does-not-exist".to_string();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&spec).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["error"], "unknown_driver");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_job_returns_404() {
    let app = build_app(fresh_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/jobs/job-nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bundle_on_in_progress_job_returns_409() {
    // We can't reliably observe a "running" state because the mock is
    // synchronous, but we CAN poke directly at the registry to install
    // a queued/running state and check the route response.
    let state = fresh_state();
    let id = state
        .jobs
        .insert(JobState::Queued {
            submitted_at: chrono::Utc::now(),
        })
        .unwrap();
    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/jobs/{id}/bundle"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["error"], "conflict");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotency_key_collapses_duplicate_submissions() {
    let state = fresh_state();
    let app = build_app(state);
    let payload = serde_json::to_vec(&sample_spec()).unwrap();

    // First submission — 202.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "client-key-42")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::ACCEPTED);
    let body1 = read_json(resp1.into_body()).await;
    let first_id = body1["job_id"].as_str().unwrap().to_string();

    // Second submission, same key + body — 200, same job_id.
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "client-key-42")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = read_json(resp2.into_body()).await;
    assert_eq!(body2["job_id"], first_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_streams_lifecycle_to_completion() {
    use futures_util::StreamExt;

    let state = fresh_state();
    let app = build_app(state);

    // Submit a job and grab its id.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let job_id = read_json(resp.into_body()).await["job_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Connect to the SSE stream.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/jobs/{job_id}/events/stream"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );

    // Drain the stream, parsing event lines until we see a `closing` event
    // or we exceed a soft cap. We expect at minimum a final
    // state=completed and then a closing event.
    let mut body_stream = resp.into_body().into_data_stream();
    let mut buf = Vec::new();
    let mut saw_completed = false;
    let mut saw_closing = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let chunk =
            tokio::time::timeout(std::time::Duration::from_millis(200), body_stream.next()).await;
        let next = match chunk {
            Ok(Some(Ok(bytes))) => bytes,
            Ok(Some(Err(e))) => panic!("body error: {e}"),
            Ok(None) => break,
            Err(_) => continue, // timeout — wait for more
        };
        buf.extend_from_slice(&next);
        let s = String::from_utf8_lossy(&buf).into_owned();
        if s.contains("\"state\":\"completed\"") {
            saw_completed = true;
        }
        if s.contains("event: closing") {
            saw_closing = true;
            break;
        }
    }
    assert!(
        saw_completed,
        "expected a completed state_changed event; got:\n{}",
        String::from_utf8_lossy(&buf)
    );
    assert!(
        saw_closing,
        "expected a closing event; got:\n{}",
        String::from_utf8_lossy(&buf)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_for_unknown_job_returns_404() {
    let app = build_app(fresh_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/jobs/job-nonexistent/events/stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_late_subscriber_to_completed_job_gets_catchup_and_closes() {
    use futures_util::StreamExt;
    use nucleus_control_plane::JobOutcome;

    // Hand-craft a registry state where the job is already completed,
    // then subscribe to SSE — the handler must emit the terminal state
    // + a closing event and end the stream without hanging.
    let state = fresh_state();
    let sink = nucleus_lineage::InMemorySink::new();
    let issuer = nucleus_lineage::LocalIssuer::random().unwrap();
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();

    // Build a real completed bundle so the state shape is honest.
    let bundle = nucleus_control_plane::execute_job(
        &sample_spec(),
        &nucleus_lineage::CallSpiffeId::pod("late.nucleus.local", "agents", "sub").unwrap(),
        &MockJobRunner,
        &sink,
        &issuer,
        jwks,
        Vec::new(),
    )
    .unwrap();

    let now = chrono::Utc::now();
    let id = state
        .jobs
        .insert(JobState::Completed {
            started_at: now,
            completed_at: now,
            outcome: JobOutcome {
                bundle,
                delivered: true,
            },
        })
        .unwrap();

    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/jobs/{id}/events/stream"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body_stream = resp.into_body().into_data_stream();
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(100), body_stream.next()).await
        {
            Ok(Some(Ok(bytes))) => buf.extend_from_slice(&bytes),
            Ok(_) => break, // stream ended
            Err(_) => continue,
        }
    }
    let s = String::from_utf8_lossy(&buf);
    assert!(
        s.contains("\"state\":\"completed\"") && s.contains("event: closing"),
        "late subscriber must get terminal state + closing; got:\n{s}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idempotency_key_with_different_body_creates_new_job() {
    let state = fresh_state();
    let app = build_app(state);

    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "same-key")
                .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let id1 = read_json(resp1.into_body()).await["job_id"]
        .as_str()
        .unwrap()
        .to_string();

    let mut different = sample_spec();
    different.task = "different task".to_string();
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "same-key")
                .body(Body::from(serde_json::to_vec(&different).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::ACCEPTED,
        "different body must NOT reuse the prior job"
    );
    let id2 = read_json(resp2.into_body()).await["job_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(id1, id2);
}
