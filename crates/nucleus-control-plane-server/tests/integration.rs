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
