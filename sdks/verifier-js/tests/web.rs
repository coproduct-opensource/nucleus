//! wasm-bindgen-test suite — runs in a node or browser wasm runtime.
//!
//! Invoke with `wasm-pack test --node` (default; runs in Node.js
//! with the wasm test runner) or `wasm-pack test --chrome --headless`
//! for browser-targeted coverage. The bridging logic between
//! verifyBundle's JSON-in / JsValue-out boundary is the surface
//! these tests pin.

use nucleus_verifier_wasm::{
    sdk_version, supported_envelope_schema_version, verify_bundle_js, verify_receipt_js,
};
use wasm_bindgen_test::*;

// Default: tests run in Node.js (the wasm-bindgen-test default
// target). To opt into browser execution, uncomment the line below
// and invoke `wasm-pack test --chrome --headless`.
// wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn sdk_version_returns_non_empty_string() {
    let v = sdk_version();
    assert!(
        !v.is_empty(),
        "sdk_version must return a populated version string"
    );
}

#[wasm_bindgen_test]
fn supported_envelope_schema_version_is_at_least_1() {
    assert!(supported_envelope_schema_version() >= 1);
}

#[wasm_bindgen_test]
fn verify_bundle_rejects_malformed_bundle_json() {
    let result = verify_bundle_js("not valid json", "{}");
    assert!(
        result.is_err(),
        "malformed bundle JSON must surface as JsError"
    );
}

#[wasm_bindgen_test]
fn verify_bundle_rejects_malformed_trust_anchor_json() {
    let valid_bundle = r#"{"payload":{},"envelope":{"session_root":"spiffe://t/ns/a/sa/b","edges":[],"jwks":{"keys":[]},"meta":{"schema_version":1,"created_at":"2026-05-29T00:00:00Z"}}}"#;
    let result = verify_bundle_js(valid_bundle, "definitely not json");
    assert!(
        result.is_err(),
        "malformed trust anchor JSON must surface as JsError"
    );
}

// ── verifyReceipt: the colimit receipt envelope across the wasm boundary ─────

fn signed_receipt_and_key() -> (nucleus_receipt::Receipt, [u8; 32]) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let session = nucleus_receipt::Session {
        session_id: "spiffe://test/agent-x".into(),
        issuer_kid: "test-kid".into(),
        issued_at_micros: 1_717_000_000_000_000,
        parent_chain: vec![],
    };
    let projections = vec![nucleus_receipt::Projection::Identity(serde_json::json!({
        "sub": "spiffe://test/agent-x"
    }))];
    let receipt = nucleus_receipt::Receipt::sign(session, projections, &sk);
    (receipt, sk.verifying_key().to_bytes())
}

fn outcome_of(verdict: wasm_bindgen::JsValue) -> String {
    let v: serde_json::Value =
        serde_wasm_bindgen::from_value(verdict).expect("verdict deserializes");
    v["outcome"].as_str().expect("outcome is a string").into()
}

#[wasm_bindgen_test]
fn verify_receipt_round_trips_a_freshly_signed_receipt() {
    let (receipt, vk) = signed_receipt_and_key();
    let json = serde_json::to_string(&receipt).unwrap();
    let verdict = verify_receipt_js(&json, &vk).expect("well-formed input");
    assert_eq!(outcome_of(verdict), "verified");
}

#[wasm_bindgen_test]
fn verify_receipt_reports_tamper_as_root_hash_mismatch() {
    let (mut receipt, vk) = signed_receipt_and_key();
    receipt.session.session_id = "spiffe://attacker/imposter".into();
    let json = serde_json::to_string(&receipt).unwrap();
    let verdict = verify_receipt_js(&json, &vk).expect("well-formed input");
    assert_eq!(outcome_of(verdict), "root_hash_mismatch");
}

#[wasm_bindgen_test]
fn verify_receipt_reports_wrong_key_as_signature_mismatch() {
    let (receipt, _vk) = signed_receipt_and_key();
    let wrong_vk = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32])
        .verifying_key()
        .to_bytes();
    let json = serde_json::to_string(&receipt).unwrap();
    let verdict = verify_receipt_js(&json, &wrong_vk).expect("well-formed input");
    assert_eq!(outcome_of(verdict), "signature_mismatch");
}

#[wasm_bindgen_test]
fn verify_receipt_rejects_malformed_json() {
    let (_receipt, vk) = signed_receipt_and_key();
    assert!(
        verify_receipt_js("not valid json", &vk).is_err(),
        "malformed receipt JSON must surface as JsError"
    );
}

#[wasm_bindgen_test]
fn verify_receipt_rejects_wrong_key_length() {
    let (receipt, _vk) = signed_receipt_and_key();
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(
        verify_receipt_js(&json, &[0u8; 31]).is_err(),
        "a 31-byte key must surface as JsError"
    );
}

#[wasm_bindgen_test]
fn verify_bundle_rejects_empty_envelope_under_strict_anchor() {
    // Empty envelope + strict anchor (no allow_empty) → verification
    // failure. We check that the SDK propagates the typed rejection.
    let empty_bundle = r#"{
        "payload": {},
        "envelope": {
            "session_root": "spiffe://prod.example.com/ns/agents/sa/x",
            "edges": [],
            "jwks": {"keys": []},
            "meta": {"schema_version": 1, "created_at": "2026-05-29T00:00:00Z"}
        }
    }"#;
    let anchor = r#"{}"#; // self_check_only mode, allow_empty=false
    let result = verify_bundle_js(empty_bundle, anchor);
    assert!(
        result.is_err(),
        "empty envelope must be rejected under strict anchor"
    );
}
