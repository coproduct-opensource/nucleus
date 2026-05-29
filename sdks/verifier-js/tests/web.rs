//! wasm-bindgen-test suite — runs in a node or browser wasm runtime.
//!
//! Invoke with `wasm-pack test --node` (default; runs in Node.js
//! with the wasm test runner) or `wasm-pack test --chrome --headless`
//! for browser-targeted coverage. The bridging logic between
//! verifyBundle's JSON-in / JsValue-out boundary is the surface
//! these tests pin.

use nucleus_verifier_wasm::{sdk_version, supported_envelope_schema_version, verify_bundle_js};
use wasm_bindgen_test::*;

// Default: tests run in Node.js (the wasm-bindgen-test default
// target). To opt into browser execution, uncomment the line below
// and invoke `wasm-pack test --chrome --headless`.
// wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn sdk_version_returns_non_empty_string() {
    let v = sdk_version();
    assert!(!v.is_empty(), "sdk_version must return a populated version string");
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
