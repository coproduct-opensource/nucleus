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
        agent_card: None,
        credit_store: None,
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
        agent_card: None,
        credit_store: None,
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
        agent_card: None,
        credit_store: None,
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
async fn well_known_agent_card_returns_404_without_card() {
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn well_known_agent_card_verifies_against_matching_key() {
    use nucleus_agent_card::{
        sign_card, verify_card, AgentCapabilities, AgentCard, AgentInterface, JsonWebKey,
        NucleusClaims, A2A_PROTOCOL_VERSION,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use std::sync::Arc;

    // Out-of-band card-signing key (resolved by the caller separately).
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let der = pkcs8.as_ref().to_vec();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
    let pk = kp.public_key().as_ref();
    let resolved_key = JsonWebKey::ec_p256(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk[1..33]),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk[33..65]),
    );

    // The bundle issuer whose JWKS the card advertises.
    let issuer = LocalIssuer::random().unwrap();
    let advertised: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();

    let card = AgentCard {
        name: "Nucleus Verifier".to_string(),
        description: "verifier-service integration test card".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://verifier.test.nucleus.local/a2a/v1".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
            tenant: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "1.0.0".to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities::default(),
        security_schemes: serde_json::Map::new(),
        security_requirements: vec![],
        default_input_modes: vec!["application/json".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    }
    .with_nucleus_claims(&NucleusClaims {
        spiffe_id: "spiffe://test.nucleus.local/ns/verifier/sa/svc".to_string(),
        did: "did:web:verifier.test.nucleus.local".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: advertised,
        runtime_guarantees: None,
    })
    .unwrap();
    let signed = sign_card(card, &der, "verifier-card-key-1").unwrap();

    let state = AppState {
        agent_card: Some(Arc::new(signed)),
        ..AppState::default()
    };

    let resp = build_app(state)
        .oneshot(
            Request::builder()
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The returned card MUST verify against the matching resolved key.
    let body = read_json(resp.into_body()).await;
    let returned: AgentCard = serde_json::from_value(body).unwrap();
    let verified = verify_card(&returned, &resolved_key)
        .expect("served agent card must verify against the matching out-of-band key");
    assert_eq!(verified.claims.did, "did:web:verifier.test.nucleus.local");
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

// ─────────────────────────────────────────────────────────────────
// Durable credit ledger: POST /v1/credit/{agent_id}/accrue + GET standing
// ─────────────────────────────────────────────────────────────────

/// A genuinely-honest settlement receipt, built with the SAME proven kernels
/// recompute checks against (so a Match is real, not asserted).
fn honest_settlement_receipt(
    price_micro: u64,
    delivered_bps: u64,
) -> nucleus_recompute::ClearingReceipt {
    use nucleus_econ_kernels::{classify, refund, seller_gross};
    nucleus_recompute::ClearingReceipt::Settlement(nucleus_recompute::SettlementClaim {
        price_micro,
        delivered_bps,
        verdict: classify(delivered_bps),
        seller_gross: seller_gross(price_micro, delivered_bps),
        refund: refund(price_micro, delivered_bps),
    })
}

/// An `AppState` whose credit ledger is a fresh store opened at `path`.
/// Returned by value; `.oneshot()` consumes the router so the store handle drops
/// before the next call reopens the same path (redb is single-handle).
fn credit_state(path: &std::path::Path) -> AppState {
    let store =
        nucleus_creditworthiness::store::CreditLedgerStore::open(path).expect("open credit ledger");
    AppState {
        credit_store: Some(Arc::new(store)),
        ..AppState::default()
    }
}

/// A shared-store `AppState`: clone it per oneshot to drive the SAME ledger
/// across multiple in-process requests (POST then GET against one handle).
fn shared_credit_state(path: &std::path::Path) -> AppState {
    let store = Arc::new(
        nucleus_creditworthiness::store::CreditLedgerStore::open(path).expect("open credit ledger"),
    );
    AppState {
        credit_store: Some(store),
        ..AppState::default()
    }
}

// ── Authenticated-accrue test kit (detached Ed25519 over the body bytes) ──

/// Deterministic Ed25519 signing key from a one-byte seed (tests only).
fn test_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// The canonical ledger identity for a key: lowercase hex of its verifying key —
/// what the authenticated handler derives and uses as the URL `{agent_id}`.
fn key_id(sk: &ed25519_dalek::SigningKey) -> String {
    hex::encode(sk.verifying_key().to_bytes())
}

/// Detached-sign the EXACT `bytes` with `sk`; return `(pubkey_hex, sig_b64)`.
fn sign_bytes(sk: &ed25519_dalek::SigningKey, bytes: &[u8]) -> (String, String) {
    use ed25519_dalek::Signer;
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sk.sign(bytes).to_bytes());
    (pubkey_hex, sig_b64)
}

/// Build a `POST /v1/credit/{path_id}/accrue` carrying `body_bytes` verbatim and
/// (optionally) the two detached-Ed25519 auth headers. `None` omits a header
/// (to exercise the missing-header 401 path); the body bytes are sent exactly so
/// a signature over them stays valid (no re-serialization).
fn accrue_with_headers(
    path_id: &str,
    body_bytes: Vec<u8>,
    pubkey_hex: Option<&str>,
    sig_b64: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/credit/{path_id}/accrue"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(pk) = pubkey_hex {
        b = b.header(nucleus_verifier_service::auth::PUBKEY_HEADER, pk);
    }
    if let Some(sig) = sig_b64 {
        b = b.header(nucleus_verifier_service::auth::SIGNATURE_HEADER, sig);
    }
    b.body(Body::from(body_bytes)).unwrap()
}

/// Happy-path signed accrue: serialize `body`, sign those exact bytes with `sk`,
/// and POST to `/v1/credit/{path_id}/accrue` with both auth headers. `path_id`
/// is separate from the signer so a test can drive the confused-deputy case;
/// pass `&key_id(sk)` for the authentic path.
fn signed_accrue_request(
    sk: &ed25519_dalek::SigningKey,
    path_id: &str,
    body: &serde_json::Value,
) -> Request<Body> {
    let bytes = serde_json::to_vec(body).unwrap();
    let (pk, sig) = sign_bytes(sk, &bytes);
    accrue_with_headers(path_id, bytes, Some(&pk), Some(&sig))
}

/// GET the (public) standing for `id`.
fn standing_request(id: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/v1/credit/{id}?max_defection_gain_micro=1000000"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn credit_accrue_then_standing_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");

    // Instance #1: accrue honest receipts under the signer's own identity.
    let sk = test_key(1);
    let id = key_id(&sk);
    let receipts = vec![
        honest_settlement_receipt(400_000, 10_000),
        honest_settlement_receipt(300_000, 10_000),
    ];
    let body = json!({ "receipts": receipts, "max_defection_gain_micro": 1_000_000 });
    let resp = build_app(credit_state(&path))
        .oneshot(signed_accrue_request(&sk, &id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["reputation_micro"], 700_000);
    assert_eq!(j["event_count"], 2);
    assert_eq!(j["required_bond_micro"], 300_000);
    assert_eq!(j["appended"], 2);
    assert_eq!(j["head_hash_hex"].as_str().unwrap().len(), 64);
    // Instance #1's router (and its store handle) is dropped at this `;`.

    // Instance #2: a DIFFERENT store opened at the SAME path — the persisted
    // standing comes back, proving the reopen survives (end-to-end durability).
    // The GET is PUBLIC: no signature, queried by the same hex id.
    let resp = build_app(credit_state(&path))
        .oneshot(standing_request(&id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["reputation_micro"], 700_000);
    assert_eq!(j["event_count"], 2);
    assert_eq!(j["required_bond_micro"], 300_000);
    assert_eq!(j["max_defection_gain_micro"], 1_000_000);
}

#[tokio::test]
async fn credit_endpoints_503_when_disabled_but_stateless_still_works() {
    // accrue → 503 persistence_disabled. The persistence check precedes auth, so
    // a disabled deployment still reports 503 (not 401) — and an unsigned probe
    // here proves the ordering.
    let body = json!({ "receipts": [], "max_defection_gain_micro": 1_000_000 });
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/credit/agent-a/accrue")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["error"], "persistence_disabled");

    // standing → 503 persistence_disabled
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .uri("/v1/credit/agent-a?max_defection_gain_micro=1000000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["error"], "persistence_disabled");

    // The stateless POST /v1/credit is UNCHANGED — the required non-breaking
    // default (no --credit-db => the only credit endpoint with behavior). It is
    // recompute-only and stays unauthenticated (no standing is minted).
    let receipts = vec![honest_settlement_receipt(500_000, 10_000)];
    let body = json!({ "receipts": receipts, "max_defection_gain_micro": 1_000_000 });
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/credit")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["reputation_micro"], 500_000);
    assert_eq!(j["required_bond_micro"], 500_000);
}

#[tokio::test]
async fn credit_accrue_replay_idempotent_under_auth() {
    // Replaying the signer's OWN valid envelope verbatim is a harmless no-op:
    // per-identity receipt_hash dedup ⇒ appended==0, standing + head unchanged.
    // This carries the prior idempotence guarantee onto the signed path.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(1);
    let id = key_id(&sk);
    let receipts = vec![honest_settlement_receipt(400_000, 10_000)];
    let body = json!({ "receipts": receipts, "max_defection_gain_micro": 1_000_000 });
    // Sign ONCE; the captured (bytes, pk, sig) is replayed verbatim below.
    let bytes = serde_json::to_vec(&body).unwrap();
    let (pk, sig) = sign_bytes(&sk, &bytes);

    // First accrual: 1 new entry.
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some(&pk),
            Some(&sig),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j1 = read_json(resp.into_body()).await;
    assert_eq!(j1["appended"], 1);
    assert_eq!(j1["reputation_micro"], 400_000);
    let head1 = j1["head_hash_hex"].as_str().unwrap().to_string();

    // Replay the EXACT same signed envelope: deduped → 0 appended, stable.
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some(&pk),
            Some(&sig),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j2 = read_json(resp.into_body()).await;
    assert_eq!(j2["appended"], 0);
    assert_eq!(j2["reputation_micro"], 400_000);
    assert_eq!(j2["event_count"], 1);
    assert_eq!(j2["head_hash_hex"].as_str().unwrap(), head1);
}

#[tokio::test]
async fn credit_standing_is_isolated_per_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    // Accrue under identity A only (signed by A).
    let sk_a = test_key(1);
    let id_a = key_id(&sk_a);
    let receipts = vec![honest_settlement_receipt(600_000, 10_000)];
    let body = json!({ "receipts": receipts, "max_defection_gain_micro": 1_000_000 });
    let resp = build_app(state.clone())
        .oneshot(signed_accrue_request(&sk_a, &id_a, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A different identity B never accrued: zero standing → full bond. A's
    // accrual did not leak across identities.
    let id_b = key_id(&test_key(2));
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id_b))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["reputation_micro"], 0);
    assert_eq!(j["event_count"], 0);
    assert_eq!(j["required_bond_micro"], 1_000_000);
}

#[tokio::test]
async fn credit_accrue_caught_defection_burns_standing_through_the_api() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    // One honest 1M settlement and one tampered settlement (seller_gross + 1)
    // that recompute catches as a defection — the recompute IS the fraud proof.
    // The agent signs its OWN history; recompute is the judge, so a caught
    // defection still burns the (authenticated) standing.
    let sk = test_key(1);
    let id = key_id(&sk);
    let mut tampered = honest_settlement_receipt(1_000_000, 10_000);
    if let nucleus_recompute::ClearingReceipt::Settlement(ref mut c) = tampered {
        c.seller_gross += 1;
    }
    let receipts = vec![honest_settlement_receipt(1_000_000, 10_000), tampered];
    let body = json!({ "receipts": receipts, "max_defection_gain_micro": 2_000_000 });
    let resp = build_app(state)
        .oneshot(signed_accrue_request(&sk, &id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    // 1,000,000 honest credit − 1,000,000 caught-defection debit = 0 standing;
    // both receipts minted an event.
    assert_eq!(j["reputation_micro"], 0);
    assert_eq!(j["event_count"], 2);
    assert_eq!(j["appended"], 2);
}

// ── Authenticated-identity binding: the gap this change closes ──

#[tokio::test]
async fn credit_accrue_unsigned_is_401_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(1);
    let id = key_id(&sk);
    let receipts = vec![honest_settlement_receipt(400_000, 10_000)];
    let body = json!({ "receipts": receipts, "max_defection_gain_micro": 1_000_000 });
    let bytes = serde_json::to_vec(&body).unwrap();

    // No signature headers at all → 401.
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(&id, bytes.clone(), None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["error"], "unauthorized");

    // Pubkey present but signature missing → still 401.
    let (pk, _sig) = sign_bytes(&sk, &bytes);
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(&id, bytes.clone(), Some(&pk), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Nothing was written: standing for the id is still empty.
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["event_count"], 0);
    assert_eq!(j["reputation_micro"], 0);
}

#[tokio::test]
async fn credit_accrue_bad_signature_is_401() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(1);
    let id = key_id(&sk);
    let body = json!({ "receipts": [honest_settlement_receipt(400_000, 10_000)], "max_defection_gain_micro": 1_000_000 });
    let bytes = serde_json::to_vec(&body).unwrap();
    let pk = hex::encode(sk.verifying_key().to_bytes());

    // Valid pubkey, garbage 64-byte signature → 401.
    let garbage = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some(&pk),
            Some(&garbage),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Truncated (non-64-byte) signature → 401.
    let truncated = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some(&pk),
            Some(&truncated),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Still nothing written.
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id))
        .await
        .unwrap();
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["event_count"], 0);
}

#[tokio::test]
async fn credit_accrue_tampered_body_is_401() {
    // The core integrity property: a signature over body A does not authorize
    // body B. Sign one body, submit a DIFFERENT one under the same pubkey.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(1);
    let id = key_id(&sk);
    let body_a = json!({ "receipts": [honest_settlement_receipt(400_000, 10_000)], "max_defection_gain_micro": 1_000_000 });
    let body_b = json!({ "receipts": [honest_settlement_receipt(999_000, 10_000)], "max_defection_gain_micro": 1_000_000 });
    let bytes_a = serde_json::to_vec(&body_a).unwrap();
    let bytes_b = serde_json::to_vec(&body_b).unwrap();
    let (pk, sig_over_a) = sign_bytes(&sk, &bytes_a);

    // Send body B with a signature computed over body A → verify fails → 401.
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes_b,
            Some(&pk),
            Some(&sig_over_a),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Nothing written.
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id))
        .await
        .unwrap();
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["event_count"], 0);
}

#[tokio::test]
async fn credit_accrue_confused_deputy_path_mismatch_is_403() {
    // Authenticated as K, but the path names a DIFFERENT identity → 403, and
    // nothing is written under EITHER id.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(1);
    let id = key_id(&sk);
    let other_id = key_id(&test_key(2));
    let body = json!({ "receipts": [honest_settlement_receipt(400_000, 10_000)], "max_defection_gain_micro": 1_000_000 });

    // Valid signature by K, but POST to the OTHER id's path → 403.
    let resp = build_app(state.clone())
        .oneshot(signed_accrue_request(&sk, &other_id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["error"], "forbidden");

    // Neither the signer's id nor the targeted id got any entry.
    for q in [&id, &other_id] {
        let resp = build_app(state.clone())
            .oneshot(standing_request(q))
            .await
            .unwrap();
        let j = read_json(resp.into_body()).await;
        assert_eq!(j["event_count"], 0, "no write under {q}");
    }
}

#[tokio::test]
async fn credit_accrue_cross_identity_double_claim_is_prevented() {
    // The Sybil/double-claim case, now PREVENTED at the API: capture identity
    // A's fully-valid signed accrue and try to replay it under a DIFFERENT id.
    // It cannot inflate B's standing — re-pointing requires re-signing (the
    // attacker lacks B's key) and the path/id mismatch 403s.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk_a = test_key(1);
    let id_a = key_id(&sk_a);
    let body = json!({ "receipts": [honest_settlement_receipt(400_000, 10_000)], "max_defection_gain_micro": 1_000_000 });
    let bytes = serde_json::to_vec(&body).unwrap();
    let (pk_a, sig_a) = sign_bytes(&sk_a, &bytes);

    // A's authentic accrual succeeds and builds A's standing.
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id_a,
            bytes.clone(),
            Some(&pk_a),
            Some(&sig_a),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Replay A's captured envelope verbatim under B's id → 403 (path != derived
    // id A). The same receipt cannot be claimed a second time under B.
    let id_b = key_id(&test_key(2));
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id_b,
            bytes.clone(),
            Some(&pk_a),
            Some(&sig_a),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // B's standing is untouched; A's is intact.
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id_b))
        .await
        .unwrap();
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["event_count"], 0);
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id_a))
        .await
        .unwrap();
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["reputation_micro"], 400_000);
}

#[tokio::test]
async fn credit_accrue_invalid_pubkey_is_401() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(1);
    let id = key_id(&sk);
    let body = json!({ "receipts": [honest_settlement_receipt(400_000, 10_000)], "max_defection_gain_micro": 1_000_000 });
    let bytes = serde_json::to_vec(&body).unwrap();
    let (_, sig) = sign_bytes(&sk, &bytes);

    // Non-hex pubkey → 401.
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some("nothex!!"),
            Some(&sig),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Valid hex but wrong length (31 bytes) → 401.
    let short = hex::encode([0u8; 31]);
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some(&short),
            Some(&sig),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Syntactically 32 bytes but NOT a valid Ed25519 point → 401. ~half of all
    // 32-byte encodings fail decompression; find one deterministically.
    let mut n: u8 = 1;
    let bad_point = loop {
        let candidate = [n; 32];
        if ed25519_dalek::VerifyingKey::from_bytes(&candidate).is_err() {
            break candidate;
        }
        n = n
            .checked_add(1)
            .expect("an invalid Ed25519 point must exist");
    };
    let bad_hex = hex::encode(bad_point);
    let resp = build_app(state.clone())
        .oneshot(accrue_with_headers(
            &id,
            bytes.clone(),
            Some(&bad_hex),
            Some(&sig),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credit_standing_read_requires_no_signature() {
    // Standing is a public, recomputable read: GET works with NO auth header and
    // returns the post-accrual value.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");
    let state = shared_credit_state(&path);

    let sk = test_key(3);
    let id = key_id(&sk);
    let body = json!({ "receipts": [honest_settlement_receipt(500_000, 10_000)], "max_defection_gain_micro": 1_000_000 });
    let resp = build_app(state.clone())
        .oneshot(signed_accrue_request(&sk, &id, &body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET with no signature header → 200, value matches the accrual.
    let resp = build_app(state.clone())
        .oneshot(standing_request(&id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = read_json(resp.into_body()).await;
    assert_eq!(j["reputation_micro"], 500_000);
    assert_eq!(j["event_count"], 1);
}

#[tokio::test]
async fn credit_authenticated_standing_matches_stateless_post() {
    // Parity under auth: the durable standing minted through the SIGNED accrue
    // path equals the stateless POST /v1/credit value for the same receipts —
    // re-asserting the proven commutative-monoid fold through the gated API.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credit.redb");

    let receipts = vec![
        honest_settlement_receipt(400_000, 10_000),
        honest_settlement_receipt(300_000, 10_000),
    ];
    let max = 1_000_000u64;

    // Stateless recompute (no auth, no store).
    let resp = build_app(AppState::default())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/credit")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({ "receipts": receipts, "max_defection_gain_micro": max }),
                    )
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let stateless = read_json(resp.into_body()).await;

    // Authenticated durable accrue.
    let sk = test_key(7);
    let id = key_id(&sk);
    let resp = build_app(credit_state(&path))
        .oneshot(signed_accrue_request(
            &sk,
            &id,
            &json!({ "receipts": receipts, "max_defection_gain_micro": max }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let durable = read_json(resp.into_body()).await;

    assert_eq!(durable["reputation_micro"], stateless["reputation_micro"]);
    assert_eq!(
        durable["required_bond_micro"],
        stateless["required_bond_micro"]
    );
}
