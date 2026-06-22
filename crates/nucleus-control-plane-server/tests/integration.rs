//! End-to-end tests that drive the axum app via `tower::ServiceExt::oneshot`
//! — no TCP socket, no real bind. The MockJobRunner runs synchronously
//! so polling typically lands a `Completed` state on the very next call.
//!
//! Requires `--features insecure-dev` (MockJobRunner + the random LocalIssuer
//! via `build_demo_state`). Production builds (default features) refuse the mock
//! runner and the demo issuer (most-paranoid #6); without the feature this file
//! compiles to an empty test binary.
#![cfg(feature = "insecure-dev")]

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
        None,
        None,
    )
    .unwrap();

    let now = chrono::Utc::now();
    let id = state
        .jobs
        .insert(JobState::Completed {
            started_at: now,
            completed_at: now,
            outcome: Box::new(JobOutcome {
                bundle,
                delivered: true,
            }),
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

/// CRIT-1 regression. Concurrent jobs MUST produce independently
/// verifiable bundles. Earlier code shared one SPIFFE pod URI across
/// every job, which made `extract_session_subgraph` (URI-prefix filter
/// on a shared sink) sweep up every concurrent job's edges. The
/// resulting bundles failed chain verification because `prev_hash`
/// values were signed against per-job emission order, not the
/// interleaved global order.
///
/// Fix: `AppState::new_session_pod` mints a per-session unique SA
/// segment (`<sa>-<uuid>`). This test runs N jobs in parallel and
/// asserts every bundle verifies, plus that no two bundles share
/// any edges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_jobs_produce_independently_verifying_bundles() {
    use std::collections::HashSet;

    let state = fresh_state();
    let app = build_app(state.clone());
    let jwks: Jwks = serde_json::from_value(state.issuer.publish_jwks()).unwrap();

    const N: usize = 8;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let app = app.clone();
        let spec = JobSpec {
            input_ref: InputRef::Inline {
                content: serde_json::json!({"i": i}),
            },
            task: format!("task-{i}"),
            ..sample_spec()
        };
        handles.push(tokio::spawn(async move {
            let resp = app
                .clone()
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
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            let body = read_json(resp.into_body()).await;
            body["job_id"].as_str().unwrap().to_string()
        }));
    }
    let job_ids: Vec<String> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .map(|j| j.unwrap())
        .collect();

    // Wait for all jobs to complete, then fetch every bundle.
    for id in &job_ids {
        let _ = poll_until_completed(app.clone(), id, 200).await;
    }

    let mut bundles = Vec::with_capacity(N);
    for id in &job_ids {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/v1/jobs/{id}/bundle"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "bundle fetch for {id}");
        let bundle: Bundle = serde_json::from_value(read_json(resp.into_body()).await).unwrap();
        bundles.push(bundle);
    }

    // Every bundle independently verifies against the shared trust JWKS.
    let trusted = TrustAnchor::from_jwks(jwks);
    for (i, bundle) in bundles.iter().enumerate() {
        verify_bundle(bundle, &trusted)
            .unwrap_or_else(|e| panic!("bundle {i} for job {} failed verify: {e}", job_ids[i]));
        assert_eq!(bundle.envelope.edges.len(), 5);
    }

    // No two bundles share any edge child. (If session roots were
    // shared, every bundle would contain every other bundle's edges.)
    let mut all_children: HashSet<String> = HashSet::new();
    for bundle in &bundles {
        for edge in &bundle.envelope.edges {
            assert!(
                all_children.insert(edge.child.to_string()),
                "edge child {} appeared in more than one bundle — sessions are leaking",
                edge.child
            );
        }
    }
}

/// v2.2 regression: every bundle the control-plane server produces
/// must carry a PayloadBinding signed by the same key that signs edges.
/// Pinning here ensures a future refactor that drops `Some(issuer)` from
/// `execute_job` in routes.rs is caught.
///
/// Beefed up per audit HIGH-1/HIGH-2: pin the kid identity (so a
/// future side-channel binding key gets caught) AND demonstrate that
/// payload tampering breaks verification through the API surface
/// (the v1→v2.2 gap-closure claim, demonstrated end-to-end, not just
/// at the library boundary).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_bundles_carry_payload_binding() {
    let state = fresh_state();
    let app = build_app(state.clone());
    let jwks: Jwks = serde_json::from_value(state.issuer.publish_jwks()).unwrap();
    let issuer_kid = nucleus_lineage::EdgeSigner::kid(state.issuer.as_ref()).to_string();

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
    let _ = poll_until_completed(app.clone(), &job_id, 100).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/jobs/{job_id}/bundle"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bundle: Bundle = serde_json::from_value(read_json(resp.into_body()).await).unwrap();

    let binding = bundle
        .binding
        .as_ref()
        .expect("server bundles MUST carry a v2.2 PayloadBinding");

    // HIGH-1: the binding's keyid MUST equal the edge issuer's kid,
    // so JWKS lookup at the verifier resolves to the same key.
    // Without this, a future refactor introducing a side-channel
    // binding key (and forgetting to embed its JWK) would still pass
    // the require_payload_binding test as long as the OOB jwks
    // contained the side-channel key.
    assert_eq!(
        binding.keyid, issuer_kid,
        "binding.keyid must match the edge issuer's kid"
    );

    // HIGH-1: if a Merkle anchor is present, the binding's
    // merkle_root_hex must equal the anchor's sth.root_hash_hex
    // byte-for-byte. Pins the v2.2+v2 combined path.
    if let Some(anchor) = &bundle.envelope.merkle_anchor {
        assert_eq!(
            binding.merkle_root_hex.as_deref(),
            Some(anchor.sth.root_hash_hex.as_str()),
            "binding merkle_root_hex must equal envelope.merkle_anchor.sth.root_hash_hex"
        );
    }

    let trust = TrustAnchor::from_jwks(jwks.clone()).require_payload_binding();
    let report = verify_bundle(&bundle, &trust)
        .expect("server bundle must verify with require_payload_binding");
    assert!(report.payload_binding_verified);

    // HIGH-2: demonstrate the v1→v2.2 gap closure end-to-end.
    // Mutate the payload and re-verify with require_payload_binding;
    // verification MUST fail. This was the documented v1 limitation
    // that v2.2 closes.
    let mut tampered = bundle.clone();
    tampered.payload = serde_json::json!({"task": "TAMPERED"});
    let err = verify_bundle(&tampered, &trust)
        .expect_err("payload tamper must fail when require_payload_binding is set");
    assert!(
        matches!(
            err,
            nucleus_envelope::VerifyBundleError::BadPayloadBinding { .. }
        ),
        "expected BadPayloadBinding, got {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_inputref_url_at_api_boundary() {
    let app = build_app(fresh_state());
    let mut spec = sample_spec();
    spec.input_ref = InputRef::Url {
        url: "https://example.com/data".to_string(),
    };
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp.into_body()).await;
    assert!(
        body["message"].as_str().unwrap().contains("SSRF"),
        "expected SSRF-flagged rejection, got: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_inputref_localpath_at_api_boundary() {
    let app = build_app(fresh_state());
    let mut spec = sample_spec();
    spec.input_ref = InputRef::LocalPath {
        path: std::path::PathBuf::from("/etc/passwd"),
    };
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

// ─────────────────────────────────────────────────────────────────
// SPIFFE auth (#79)
// ─────────────────────────────────────────────────────────────────

mod spiffe_auth {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
    use ed25519_dalek::{Signer as _, SigningKey, SECRET_KEY_LENGTH};
    use nucleus_control_plane_server::SpiffeAuthConfig;
    use nucleus_oidc_core::{Jwk, Jwks as OidcJwks};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Signer {
        signing_key: SigningKey,
        kid: String,
    }

    impl Signer {
        fn new() -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&[31u8; SECRET_KEY_LENGTH]),
                kid: "test-kid".to_string(),
            }
        }
        fn jwks(&self) -> OidcJwks {
            let vk = self.signing_key.verifying_key();
            OidcJwks {
                keys: vec![Jwk {
                    kty: "OKP".to_string(),
                    kid: self.kid.clone(),
                    alg: Some("EdDSA".to_string()),
                    use_: Some("sig".to_string()),
                    crv: Some("Ed25519".to_string()),
                    x: Some(B64URL.encode(vk.to_bytes())),
                    y: None,
                    n: None,
                    e: None,
                }],
            }
        }
        fn mint(&self, sub: &str, aud: &str) -> String {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let header_json = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, self.kid);
            let payload = serde_json::json!({"sub": sub, "aud": aud, "exp": now + 600, "iat": now});
            let h = B64URL.encode(header_json.as_bytes());
            let p = B64URL.encode(payload.to_string().as_bytes());
            let signed_input = format!("{h}.{p}");
            let sig = self.signing_key.sign(signed_input.as_bytes());
            format!("{h}.{p}.{}", B64URL.encode(sig.to_bytes()))
        }
    }

    fn auth_enabled_state(signer: &Signer) -> AppState {
        let rr = RunnerRegistry::new().register("mock", Box::new(MockJobRunner));
        let sink: Arc<dyn nucleus_lineage::LineageSink> = Arc::new(InMemorySink::new());
        let mut s = build_demo_state(rr, sink, "test.nucleus.local", "agents", "subject")
            .expect("build_demo_state");
        s.spiffe_auth = Some(Arc::new(SpiffeAuthConfig::new(
            signer.jwks(),
            "https://control.test/api",
            "spiffe://test.nucleus.local/ns/agents/sa/",
        )));
        s
    }

    #[tokio::test]
    async fn submit_without_token_returns_401_when_auth_enabled() {
        let signer = Signer::new();
        let state = auth_enabled_state(&signer);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/jobs")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn submit_with_malformed_bearer_returns_401() {
        let signer = Signer::new();
        let state = auth_enabled_state(&signer);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/jobs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer not.a.jwt")
            .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn submit_with_wrong_audience_returns_403() {
        let signer = Signer::new();
        let state = auth_enabled_state(&signer);
        let token = signer.mint(
            "spiffe://test.nucleus.local/ns/agents/sa/coder",
            "https://OTHER.test/api",
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/jobs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn submit_with_wrong_subject_prefix_returns_403() {
        let signer = Signer::new();
        let state = auth_enabled_state(&signer);
        let token = signer.mint(
            "spiffe://test.nucleus.local/ns/OTHER/sa/coder",
            "https://control.test/api",
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/jobs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn submit_with_valid_jwt_svid_returns_202() {
        let signer = Signer::new();
        let state = auth_enabled_state(&signer);
        let token = signer.mint(
            "spiffe://test.nucleus.local/ns/agents/sa/coder",
            "https://control.test/api",
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/jobs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(&sample_spec()).unwrap()))
            .unwrap();
        let resp = build_app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn healthz_works_even_with_auth_enabled() {
        let signer = Signer::new();
        let state = auth_enabled_state(&signer);
        let resp = build_app(state)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
