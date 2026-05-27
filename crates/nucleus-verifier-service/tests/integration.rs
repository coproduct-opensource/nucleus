//! End-to-end: produce a real signed bundle via nucleus-control-plane,
//! POST it to the verifier service via in-process tower::oneshot, and
//! confirm the trust-anchor and self-check paths produce the documented
//! responses.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use nucleus_control_plane::{
    execute_job, AgentDriverRef, Destination, InputRef, JobSpec, MockJobRunner,
};
use nucleus_envelope::Bundle;
use nucleus_lineage::{CallSpiffeId, InMemorySink, Jwks, LocalIssuer};
use nucleus_verifier_service::build_app;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Build a real, signed bundle so the verifier sees genuine input.
fn build_signed_bundle() -> (Bundle, Jwks, LocalIssuer) {
    let issuer = LocalIssuer::random().unwrap();
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let sink = InMemorySink::new();
    let runner = MockJobRunner;
    let session_root = CallSpiffeId::pod("test.nucleus.local", "agents", "subject").unwrap();
    let spec = JobSpec {
        input_ref: InputRef::Inline {
            content: json!({"x": "y"}),
        },
        task: "summarize".to_string(),
        destination: Destination::InResponse,
        policy_profile: "report-extraction".to_string(),
        agent_driver: AgentDriverRef {
            name: "mock".to_string(),
            version: None,
            config: json!({}),
        },
    };
    let bundle = execute_job(
        &spec,
        &session_root,
        &runner,
        &sink,
        &issuer,
        jwks.clone(),
        Vec::new(),
        None,
        None,
    )
    .unwrap();
    (bundle, jwks, issuer)
}

async fn read_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("JSON")
}

#[tokio::test]
async fn healthz_returns_ok() {
    let resp = build_app()
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

#[tokio::test]
async fn root_describes_the_service() {
    let resp = build_app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.contains("POST /v1/verify"), "got: {s}");
}

#[tokio::test]
async fn verify_with_trust_jwks_returns_out_of_band_mode() {
    let (bundle, jwks, _issuer) = build_signed_bundle();
    let req_body = json!({
        "bundle": bundle,
        "trust_jwks": jwks,
    });
    let resp = build_app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["trust_mode"], "out_of_band");
    assert_eq!(body["report"]["edge_count"], 5);
    assert_eq!(body["report"]["trust_domain"], "test.nucleus.local");
    assert!(body["report"]["head_edge_hash_hex"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn verify_without_jwks_runs_self_check_with_clear_warning() {
    let (bundle, _jwks, _issuer) = build_signed_bundle();
    let req_body = json!({"bundle": bundle});
    let resp = build_app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["trust_mode"], "self_check_only");
}

#[tokio::test]
async fn verify_with_wrong_jwks_returns_422() {
    // Produce a bundle signed by issuer A; verify against an unrelated
    // issuer B's JWKS. This is exactly the CRIT-1 attacker-JWKS path.
    let (bundle, _jwks_a, _issuer_a) = build_signed_bundle();
    let issuer_b = LocalIssuer::random().unwrap();
    let jwks_b: Jwks = serde_json::from_value(issuer_b.publish_jwks()).unwrap();

    let req_body = json!({
        "bundle": bundle,
        "trust_jwks": jwks_b,
    });
    let resp = build_app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "verification_failed");
}

/// **HIGH-1 (#1648 / audit) fix.** Verify the cap on
/// `trusted_witnesses_hex` fires at the route layer with 400, BEFORE
/// any per-entry hex parse — closing the DoS amplifier of forcing the
/// verifier to do 64 × N Ed25519 verifies per request.
#[tokio::test]
async fn verify_rejects_oversized_trusted_witnesses_hex() {
    let (bundle, jwks, _issuer) = build_signed_bundle();
    // 33 entries exceeds MAX_TRUSTED_WITNESSES_PER_REQUEST = 32.
    let too_many: Vec<String> = (0..33)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            hex::encode(bytes)
        })
        .collect();
    let resp = build_app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "bundle": bundle,
                        "trust_jwks": jwks,
                        "trusted_witnesses_hex": too_many,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "bad_request");
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("33 entries") && msg.contains("max 32"),
        "expected cap-rejection message; got {msg:?}",
    );
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let resp = build_app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    // axum's Json extractor returns 422 for "could not be decoded" / 400 for "missing".
    // We just assert it's a 4xx and not 500.
    assert!(
        resp.status().is_client_error(),
        "expected 4xx, got {}",
        resp.status()
    );
}
