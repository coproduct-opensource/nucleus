//! wasm-bindgen-test suite — runs in a node or browser wasm runtime.
//!
//! Invoke with `wasm-pack test --node` (default; runs in Node.js
//! with the wasm test runner) or `wasm-pack test --chrome --headless`
//! for browser-targeted coverage. The bridging logic between
//! verifyBundle's JSON-in / JsValue-out boundary is the surface
//! these tests pin.

use nucleus_verifier_wasm::{
    sdk_version, supported_envelope_schema_version, verify_agent_card_js, verify_bundle_js,
    verify_receipt_js,
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

// ── verifyAgentCard: the signed identity document across the wasm boundary ───
// Signing is native-only (the `sign` feature never enters wasm builds), so the
// wasm boundary tests pin the input-error and rejected-verdict paths; the full
// sign→verify round-trip is pinned by the native tests in src/lib.rs.

/// A structurally well-formed signed A2A v1.0 AgentCard whose signature
/// is garbage.
fn garbage_signed_card_json() -> String {
    let mut card = nucleus_agent_card::AgentCard {
        name: "Coder Agent".to_string(),
        description: "wasm boundary tests".to_string(),
        supported_interfaces: vec![nucleus_agent_card::AgentInterface {
            url: "https://coder.prod.example.com/a2a/v1".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            tenant: None,
            protocol_version: nucleus_agent_card::A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "1.0.0".to_string(),
        documentation_url: None,
        capabilities: nucleus_agent_card::AgentCapabilities::default(),
        security_schemes: Default::default(),
        security_requirements: vec![],
        default_input_modes: vec!["application/json".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    }
    .with_nucleus_claims(&nucleus_agent_card::NucleusClaims {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
        did: "did:web:coder.prod.example.com".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: nucleus_lineage::Jwks { keys: vec![] },
        runtime_guarantees: None,
    })
    .unwrap();
    card.signatures = vec![nucleus_agent_card::AgentCardSignature {
        protected: "eyJhbGciOiJFUzI1NiJ9".to_string(),
        signature: "bm90LWEtcmVhbC1zaWc".to_string(),
        header: None,
    }];
    serde_json::to_string(&card).unwrap()
}

/// A syntactically valid P-256 JWK (RFC 7515 A.3 test vector point).
const RESOLVED_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

#[wasm_bindgen_test]
fn verify_agent_card_reports_bad_signature_as_rejected_verdict() {
    let verdict =
        verify_agent_card_js(&garbage_signed_card_json(), RESOLVED_JWK).expect("well-formed input");
    assert_eq!(outcome_of(verdict), "rejected");
}

#[wasm_bindgen_test]
fn verify_agent_card_rejects_malformed_card_json() {
    assert!(
        verify_agent_card_js("not valid json", RESOLVED_JWK).is_err(),
        "malformed signed-card JSON must surface as JsError"
    );
}

#[wasm_bindgen_test]
fn verify_agent_card_rejects_malformed_jwk_json() {
    assert!(
        verify_agent_card_js(&garbage_signed_card_json(), "{}").is_err(),
        "malformed resolved-JWK JSON must surface as JsError"
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
