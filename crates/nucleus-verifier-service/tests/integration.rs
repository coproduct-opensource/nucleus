//! End-to-end: produce a real signed bundle via nucleus-control-plane,
//! POST it to the verifier service via in-process tower::oneshot, and
//! confirm the trust-anchor and self-check paths produce the documented
//! responses.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use base64::Engine as _;
use http_body_util::BodyExt;
use nucleus_control_plane::{
    execute_job, AgentDriverRef, Destination, InputRef, JobSpec, MockJobRunner,
};
use nucleus_envelope::Bundle;
use nucleus_lineage::{CallSpiffeId, InMemorySink, Jwks, LocalIssuer};
use nucleus_verifier_service::{app::AppState, build_app};
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
    let resp = build_app(AppState::default())
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
    let resp = build_app(AppState::default())
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
    let resp = build_app(AppState::default())
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
    let resp = build_app(AppState::default())
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
    let resp = build_app(AppState::default())
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
    let resp = build_app(AppState::default())
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
    let resp = build_app(AppState::default())
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

// ─────────────────────────────────────────────────────────────────
// Hash-lookup endpoint (#68) + AppState wiring (#93)
// ─────────────────────────────────────────────────────────────────

async fn fresh_db_state() -> AppState {
    let pool = nucleus_verifier_service::connect_and_migrate("sqlite::memory:")
        .await
        .expect("in-memory db");
    AppState {
        db: Some(pool),
        signer: None,
        metrics: None,
        merkle: None,
        witness: None,
    }
}

#[tokio::test]
async fn lookup_returns_503_when_persistence_disabled() {
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/bundles/{}/verify", "a".repeat(64)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "persistence_disabled");
}

#[tokio::test]
async fn lookup_returns_400_for_malformed_hash() {
    let state = fresh_db_state().await;
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/v1/bundles/notahex/verify")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn lookup_returns_404_for_unknown_hash() {
    let state = fresh_db_state().await;
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri(format!("/v1/bundles/{}/verify", "f".repeat(64)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn verify_then_lookup_returns_stored_report() {
    let state = fresh_db_state().await;
    let app = build_app(state);

    // 1) POST /v1/verify with a real signed bundle.
    let (bundle, jwks, _issuer) = build_signed_bundle();
    let bundle_hash_hex = hex::encode(nucleus_envelope::canonical_bundle_hash(&bundle));
    let verify_req = json!({"bundle": bundle, "trust_jwks": jwks});
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&verify_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2) GET /v1/bundles/{hash}/verify returns the stored report.
    let lookup = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/bundles/{bundle_hash_hex}/verify"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lookup.status(), StatusCode::OK);
    let body = read_json(lookup.into_body()).await;
    assert_eq!(body["envelope_hash"], bundle_hash_hex);
    assert_eq!(body["ok"], true);
    assert!(body["submitted_at"].as_i64().unwrap() > 0);
    assert_eq!(body["report"]["trust_domain"], "test.nucleus.local");
    assert_eq!(body["report"]["edge_count"], 5);
}

#[tokio::test]
async fn verify_failure_records_with_error_kind() {
    let state = fresh_db_state().await;
    let app = build_app(state);

    // Bundle signed by issuer A; verified against unrelated issuer B's JWKS.
    let (bundle, _jwks_a, _issuer_a) = build_signed_bundle();
    let bundle_hash_hex = hex::encode(nucleus_envelope::canonical_bundle_hash(&bundle));
    let issuer_b = LocalIssuer::random().unwrap();
    let jwks_b: Jwks = serde_json::from_value(issuer_b.publish_jwks()).unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"bundle": bundle, "trust_jwks": jwks_b})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The failure persisted with an error_kind discriminant.
    let lookup = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/bundles/{bundle_hash_hex}/verify"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lookup.status(), StatusCode::OK);
    let body = read_json(lookup.into_body()).await;
    assert_eq!(body["ok"], false);
    assert!(
        body["error_kind"].as_str().is_some(),
        "failure must record an error_kind discriminant; got {body}"
    );
    // report must be omitted on failure
    assert!(body.get("report").is_none() || body["report"].is_null());
}

// ─────────────────────────────────────────────────────────────────
// Transparency log endpoints (#69 iter-1)
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn log_size_returns_zero_on_fresh_db() {
    let state = fresh_db_state().await;
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/v1/log/size")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["tree_size"], 0);
}

#[tokio::test]
async fn log_size_returns_503_without_db() {
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .uri("/v1/log/size")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn log_sth_returns_genesis_on_empty_log() {
    let state = fresh_db_state().await;
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["tree_size"], 0);
    assert_eq!(body["root_hash_hex"], "0".repeat(64));
    assert_eq!(body["signed"], false);
}

#[tokio::test]
async fn successful_verify_advances_log_tip() {
    let state = fresh_db_state().await;
    let app = build_app(state);

    // Tip before any verify is genesis (all-zeros).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = read_json(resp.into_body()).await;
    let tip_before = body["root_hash_hex"].as_str().unwrap().to_string();
    assert_eq!(tip_before, "0".repeat(64));

    // POST /v1/verify with a real signed bundle.
    let (bundle, jwks, _issuer) = build_signed_bundle();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"bundle": bundle, "trust_jwks": jwks})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Tip after verify advances + tree_size becomes 1.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["tree_size"], 1);
    let tip_after = body["root_hash_hex"].as_str().unwrap().to_string();
    assert_ne!(
        tip_after, tip_before,
        "tip must advance after a successful verify"
    );
    assert_eq!(tip_after.len(), 64, "tip must be 64-char hex SHA-256");
}

#[tokio::test]
async fn failed_verify_does_not_advance_log() {
    let state = fresh_db_state().await;
    let app = build_app(state);

    // Bundle signed by A; verified against B's JWKS → 422.
    let (bundle, _jwks_a, _issuer_a) = build_signed_bundle();
    let issuer_b = LocalIssuer::random().unwrap();
    let jwks_b: Jwks = serde_json::from_value(issuer_b.publish_jwks()).unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"bundle": bundle, "trust_jwks": jwks_b})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Log tip MUST still be genesis — failed verifications must not
    // be admitted to the public transparency log (would pollute
    // chain with garbage entries).
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["tree_size"], 0);
    assert_eq!(body["root_hash_hex"], "0".repeat(64));
}

// ─────────────────────────────────────────────────────────────────
// Signed STH + /.well-known/jwks.json (#94 iter-2 + #71 partial)
// ─────────────────────────────────────────────────────────────────

use nucleus_verifier_service::VerifierSigner;
use std::sync::Arc;

async fn signed_state() -> AppState {
    let pool = nucleus_verifier_service::connect_and_migrate("sqlite::memory:")
        .await
        .unwrap();
    AppState {
        db: Some(pool),
        signer: Some(Arc::new(VerifierSigner::random())),
        metrics: None,
        merkle: None,
        witness: None,
    }
}

#[tokio::test]
async fn well_known_jwks_returns_published_key() {
    let state = signed_state().await;
    let expected_kid = state.signer.as_ref().unwrap().kid().to_string();
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["alg"], "EdDSA");
    assert_eq!(keys[0]["kid"], expected_kid);
}

#[tokio::test]
async fn well_known_jwks_returns_empty_keys_without_signer() {
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["keys"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn signed_sth_includes_signature_and_kid() {
    let state = signed_state().await;
    let expected_kid = state.signer.as_ref().unwrap().kid().to_string();
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["signed"], true);
    assert_eq!(body["kid"], expected_kid);
    let sig_b64 = body["signature_b64"].as_str().unwrap();
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .unwrap();
    assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");
}

#[tokio::test]
async fn signed_sth_signature_verifies_against_published_jwks() {
    // End-to-end: fetch JWKS, fetch STH, reconstruct canonical bytes,
    // verify signature. This is exactly the path a client SDK runs.
    let state = signed_state().await;
    let app = build_app(state.clone());

    // Append one entry so the chain head is non-trivial.
    let (bundle, jwks, _issuer) = build_signed_bundle();
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"bundle": bundle, "trust_jwks": jwks})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Fetch STH.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = read_json(resp.into_body()).await;
    let tree_size = body["tree_size"].as_i64().unwrap();
    let timestamp_ms = body["timestamp_ms"].as_i64().unwrap();
    let root_hash_hex = body["root_hash_hex"].as_str().unwrap();
    let sig_b64 = body["signature_b64"].as_str().unwrap();

    // Fetch JWKS.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks_body = read_json(resp.into_body()).await;
    let x_b64url = jwks_body["keys"][0]["x"].as_str().unwrap();

    // Reconstruct verifying key + canonical bytes.
    let vk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64url)
        .unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(vk_bytes.as_slice()).unwrap(),
    )
    .unwrap();

    let root_bytes: [u8; 32] = hex::decode(root_hash_hex)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    let canonical =
        nucleus_verifier_service::canonical_sth_bytes(tree_size, timestamp_ms, &root_bytes);

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .unwrap();
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    ed25519_dalek::Verifier::verify(&vk, &canonical, &signature)
        .expect("end-to-end: signed STH must verify against published JWKS");
}

#[tokio::test]
async fn unsigned_sth_path_still_works_without_signer() {
    // Persistence enabled but no signer: STH endpoint returns the
    // chain head with signed=false.
    let pool = nucleus_verifier_service::connect_and_migrate("sqlite::memory:")
        .await
        .unwrap();
    let state = AppState {
        db: Some(pool),
        signer: None,
        metrics: None,
        merkle: None,
        witness: None,
    };
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/v1/log/sth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["signed"], false);
    assert!(body.get("signature_b64").is_none() || body["signature_b64"].is_null());
    assert!(body.get("kid").is_none() || body["kid"].is_null());
}

#[tokio::test]
async fn well_known_configuration_describes_service_correctly() {
    // Service description must reflect both modes (signer present/absent
    // and db present/absent). This test exercises the signer+db case.
    let state = signed_state().await;
    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/.well-known/nucleus-verifier-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["service"], "nucleus-verifier");
    assert!(body["service_version"].is_string());
    assert!(body["envelope_schema_version_supported"].is_array());
    assert!(
        body["envelope_schema_version_supported"][0]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(body["jwks_uri"], "/.well-known/jwks.json");
    assert_eq!(body["endpoints"]["verify"], "/v1/verify");
    assert_eq!(
        body["endpoints"]["bundle_lookup"],
        "/v1/bundles/{hash}/verify"
    );
    assert_eq!(body["endpoints"]["log_size"], "/v1/log/size");
    assert_eq!(body["endpoints"]["log_sth"], "/v1/log/sth");
    assert_eq!(body["sth"]["signed"], true);
    assert_eq!(body["sth"]["signing_algorithm"], "EdDSA");
    assert!(body["sth"]["domain_separator"]
        .as_str()
        .unwrap()
        .starts_with("nucleus-verifier-sth/"));
    assert_eq!(body["persistence"]["enabled"], true);
    assert_eq!(body["persistence"]["bundle_lookup_supported"], true);
    assert_eq!(body["persistence"]["transparency_log_supported"], true);
    assert_eq!(body["limits"]["max_bundle_bytes"], 2 * 1024 * 1024);
}

#[tokio::test]
async fn well_known_configuration_reflects_stateless_mode() {
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .uri("/.well-known/nucleus-verifier-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body["sth"]["signed"], false);
    assert_eq!(body["persistence"]["enabled"], false);
    assert_eq!(body["persistence"]["bundle_lookup_supported"], false);
    assert_eq!(body["persistence"]["transparency_log_supported"], false);
}
