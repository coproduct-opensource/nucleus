//! Integration test for the HTTP `WitnessClient`. Spins up a wiremock
//! server that runs an [`InProcessWitness`] internally and POSTs an
//! STH from a real producer through `HttpWitnessClient`, asserting the
//! returned cosignature verifies cryptographically.
//!
//! Requires `--features http,dev`.

#![cfg(all(feature = "http", feature = "insecure-local-issuer"))]

use std::time::Duration;

use nucleus_lineage::{
    canonical_sth_bytes, Cosignature, Ed25519Witness, HttpWitnessClient, InProcessWitness,
    SignedTreeHead, TreeWitness, WitnessClient,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

/// A wiremock responder that internally runs an `InProcessWitness` —
/// receives the STH bytes (via the request body), parses, cosigns,
/// returns the real `Cosignature`. This is "as production-realistic as
/// possible without a real witness binary."
struct WitnessHandler {
    witness: InProcessWitness,
}

impl Respond for WitnessHandler {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let sth: SignedTreeHead = match serde_json::from_slice(&req.body) {
            Ok(s) => s,
            Err(e) => {
                return ResponseTemplate::new(400).set_body_string(format!("bad STH: {e}"));
            }
        };
        match self.witness.cosign(&sth) {
            Ok(cosig) => ResponseTemplate::new(200).set_body_json(cosig),
            Err(e) => ResponseTemplate::new(500).set_body_string(format!("cosign: {e}")),
        }
    }
}

#[tokio::test]
async fn http_witness_cosigns_a_real_sth() {
    let mock = MockServer::start().await;
    let witness = InProcessWitness::from_seed([77u8; 32]);
    let witness_pub = witness.verifying_key_bytes();
    let witness_kid = witness.kid().to_string();
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .and(header("content-type", "application/json"))
        .respond_with(WitnessHandler { witness })
        .mount(&mock)
        .await;

    // Produce an STH from a real producer (separate seed).
    let producer = Ed25519Witness::from_seed([11u8; 32]);
    let sth = producer.sign_sth(7, &[0xAB; 32]).unwrap();

    // wiremock runs in the same tokio runtime; the blocking reqwest
    // client must run on a spawn_blocking thread so it doesn't deadlock
    // the runtime by blocking on its own server.
    let base = mock.uri();
    let sth_clone = sth.clone();
    let cosig: Cosignature = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base).unwrap();
        client.cosign(&sth_clone).unwrap()
    })
    .await
    .unwrap();

    assert_eq!(cosig.witness_kid, witness_kid);
    assert_eq!(cosig.signature.len(), 64);

    // The returned cosignature must cryptographically verify over the
    // original STH's canonical bytes against the witness's pubkey —
    // i.e., the HTTP layer didn't corrupt anything.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let canonical = canonical_sth_bytes(
        sth.tree_size,
        sth.timestamp_ms,
        &hex::decode(&sth.root_hash_hex).unwrap().try_into().unwrap(),
    );
    let vk = VerifyingKey::from_bytes(&witness_pub).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&cosig.signature);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&canonical, &sig)
        .expect("HTTP-returned cosig must verify against the witness pubkey");
}

#[tokio::test]
async fn http_witness_surfaces_non_200_as_backend_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .respond_with(ResponseTemplate::new(503).set_body_string("witness overloaded"))
        .mount(&mock)
        .await;

    let producer = Ed25519Witness::from_seed([22u8; 32]);
    let sth = producer.sign_sth(1, &[0u8; 32]).unwrap();

    let base = mock.uri();
    let sth_clone = sth.clone();
    let result = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base).unwrap();
        client.cosign(&sth_clone)
    })
    .await
    .unwrap();

    let err = result.expect_err("503 must surface as WitnessError::Backend");
    let msg = err.to_string();
    assert!(msg.contains("503"), "expected 503 in error, got: {msg}");
    assert!(
        msg.contains("witness overloaded"),
        "error must include server body, got: {msg}"
    );
}

#[tokio::test]
async fn http_witness_pinned_kid_rejects_mismatched_response() {
    let mock = MockServer::start().await;
    // Server has a witness with kid X; client is pinned to expect Y.
    let real_witness = InProcessWitness::from_seed([33u8; 32]);
    let unexpected_kid = "totally-not-the-real-kid".to_string();
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .respond_with(WitnessHandler {
            witness: real_witness,
        })
        .mount(&mock)
        .await;

    let producer = Ed25519Witness::from_seed([44u8; 32]);
    let sth = producer.sign_sth(2, &[1u8; 32]).unwrap();

    let base = mock.uri();
    let sth_clone = sth.clone();
    let expected_kid = unexpected_kid.clone();
    let result = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base)
            .unwrap()
            .with_expected_kid(expected_kid);
        client.cosign(&sth_clone)
    })
    .await
    .unwrap();

    let err = result.expect_err("kid mismatch must reject");
    assert!(err.to_string().contains("expected"), "got: {err}");
}

/// **CRIT-1 from audit on slice C.** A hostile witness returning a
/// gigantic response body must be rejected before the producer
/// allocates that memory. Cap is enforced via Content-Length and
/// post-read length check.
#[tokio::test]
async fn http_witness_rejects_oversized_response_body() {
    let mock = MockServer::start().await;
    // 1 MiB body — well past the 8 KiB cap.
    let big = serde_json::to_string(&serde_json::json!({
        "witness_kid": "x",
        "signature": "AA",
        "timestamp_ms": 1,
        "junk": "X".repeat(1024 * 1024),
    }))
    .unwrap();
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(big.into_bytes(), "application/json"))
        .mount(&mock)
        .await;

    let producer = Ed25519Witness::from_seed([66u8; 32]);
    let sth = producer.sign_sth(1, &[0u8; 32]).unwrap();
    let base = mock.uri();
    let sth_clone = sth.clone();
    let err = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base).unwrap();
        client.cosign(&sth_clone)
    })
    .await
    .unwrap()
    .expect_err("oversized body must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("Content-Length") || msg.contains("byte body"),
        "expected size-cap error, got: {msg}"
    );
}

/// **MED-5 from audit.** A witness returning 200 OK with an empty `{}`
/// body must produce a clean error path, not a panic or a silent
/// "zero cosignature." Pins the serde behavior — required fields on
/// Cosignature catch this.
#[tokio::test]
async fn http_witness_rejects_empty_cosignature_body() {
    let mock = MockServer::start().await;
    // `set_body_raw` sets BOTH body and Content-Type in one shot,
    // overriding the default text/plain that set_body_string would
    // pick. We need the Content-Type to pass so the deserialize
    // step is what fails on `{}`.
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"{}".to_vec(), "application/json"))
        .mount(&mock)
        .await;

    let producer = Ed25519Witness::from_seed([77u8; 32]);
    let sth = producer.sign_sth(1, &[0u8; 32]).unwrap();
    let base = mock.uri();
    let sth_clone = sth.clone();
    let err = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base).unwrap();
        client.cosign(&sth_clone)
    })
    .await
    .unwrap()
    .expect_err("empty body must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("malformed Cosignature JSON"),
        "expected serde error, got: {msg}"
    );
}

/// **MED-6 from audit.** A witness returning HTML with a body that
/// happens to parse as JSON must be rejected at the Content-Type
/// check.
#[tokio::test]
async fn http_witness_rejects_non_json_content_type() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"witness_kid":"x","signature":"AA","timestamp_ms":1}"#)
                .insert_header("content-type", "text/html"),
        )
        .mount(&mock)
        .await;

    let producer = Ed25519Witness::from_seed([88u8; 32]);
    let sth = producer.sign_sth(1, &[0u8; 32]).unwrap();
    let base = mock.uri();
    let sth_clone = sth.clone();
    let err = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base).unwrap();
        client.cosign(&sth_clone)
    })
    .await
    .unwrap()
    .expect_err("non-JSON Content-Type must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("non-JSON Content-Type"),
        "expected content-type error, got: {msg}"
    );
}

#[tokio::test]
async fn http_witness_timeout_surfaces_as_backend_error() {
    let mock = MockServer::start().await;
    // 10s delay vs 500ms client timeout → timeout fires.
    Mock::given(method("POST"))
        .and(path("/v2.1/cosign"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&mock)
        .await;

    let producer = Ed25519Witness::from_seed([55u8; 32]);
    let sth = producer.sign_sth(1, &[0u8; 32]).unwrap();

    let base = mock.uri();
    let sth_clone = sth.clone();
    let result = tokio::task::spawn_blocking(move || {
        let client = HttpWitnessClient::new(base)
            .unwrap()
            .with_timeout(Duration::from_millis(500))
            .unwrap();
        client.cosign(&sth_clone)
    })
    .await
    .unwrap();

    // reqwest's timeout error string varies across versions — the
    // important property is that the client surfaces a clean
    // WitnessError::Backend (not a panic) so the bundle builder can
    // route the failure. Don't over-assert the wording.
    let err = result.expect_err("timeout must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("/v2.1/cosign") && msg.contains("witness backend failure"),
        "expected backend POST error, got: {msg}"
    );
}
