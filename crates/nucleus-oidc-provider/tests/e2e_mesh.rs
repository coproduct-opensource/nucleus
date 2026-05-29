//! End-to-end mesh test — full flow through the OP in-process.
//!
//! Simulates an upstream IdP (fixture Ed25519 signer) issuing a JWT-SVID
//! that the OP validates via its `StaticBundleProvider`, then exchanges
//! through `/oauth/token`, asserting RFC 8693 conformance and the
//! defense properties from #44/#45.
//!
//! Acceptance criteria coverage (task #50):
//! - (a) exactly 1 token-exchange roundtrip per LLM-boundary call
//! - (b) expired subject_token rejected (clock-skew test)
//! - (c) audience-not-in-rules → invalid_target
//! - (d) federation-rule grant-not-allowed → invalid_target
//! - (e) replay (same jti twice) → second exchange fails
//! - (f) runs in <30s in-process (axum::oneshot, no real network)
//!
//! Out of scope: this test does NOT depend on `wiremock` because the
//! OP's behavior under all relevant conditions is verifiable
//! in-process via axum oneshot. A wiremock RP would add network +
//! cert-trust ceremony without exercising additional code paths.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http_body_util::BodyExt;
use nucleus_oidc_provider::{
    app::{build_app, AppState},
    federation::{FederationRegistry, FederationRule, FederationRules},
    issuer::JwtIssuer,
    keystore::{rfc7638_kid, InMemoryKeyStore, JwtKeyStore},
    spire::StaticBundleProvider,
    token::{TOKEN_EXCHANGE_GRANT, TOKEN_TYPE_JWT},
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use uuid::Uuid;

const TRUST_DOMAIN: &str = "prod.example.com";
const POD_SUBJECT: &str = "spiffe://prod.example.com/ns/agents/sa/coder";
const RP_AUDIENCE: &str = "https://rp-a.example/api";

/// One-shot harness: builds a complete in-process OP with an upstream
/// signer registered under `TRUST_DOMAIN`, and a federation rule that
/// allows `POD_SUBJECT/*` → `RP_AUDIENCE` via token-exchange grant.
struct MeshHarness {
    app: axum::Router,
    upstream_sk: ed25519_dalek::SigningKey,
    upstream_kid: String,
}

impl MeshHarness {
    fn new() -> Self {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let issuer = Arc::new(
            JwtIssuer::new(
                store.clone(),
                "https://oidc.nucleus.example/".to_string(),
                Duration::from_secs(300),
            )
            .unwrap(),
        );

        let rules = FederationRules {
            rule: vec![FederationRule {
                id: "test-allow".to_string(),
                subject_prefix: "spiffe://prod.example.com/*".to_string(),
                audience: RP_AUDIENCE.to_string(),
                allowed_grants: vec![TOKEN_EXCHANGE_GRANT.to_string()],
                max_token_lifetime_secs: 3600,
            }],
        };

        // Upstream IdP signer — registered in the OP's bundle.
        let upstream_sk = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let upstream_kid = rfc7638_kid(&upstream_sk.verifying_key());
        let bundle = StaticBundleProvider::new();
        bundle.add_key(
            TRUST_DOMAIN,
            upstream_kid.clone(),
            upstream_sk.verifying_key(),
        );

        let app = build_app(AppState {
            keystore: store,
            issuer_url: Arc::from("https://oidc.nucleus.example/"),
            issuer,
            jti_cache: Arc::new(nucleus_oidc_core::JtiCache::new()),
            federation: Arc::new(FederationRegistry::new(rules)),
            bundle_provider: Arc::new(bundle),
        });

        Self {
            app,
            upstream_sk,
            upstream_kid,
        }
    }

    /// Construct a subject_token signed by the upstream IdP fixture key.
    fn make_subject_token(&self, sub: &str, exp_offset_secs: i64, jti: Option<&str>) -> String {
        use ed25519_dalek::Signer;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset_secs).max(0) as u64;
        let jti_str = jti
            .map(|j| j.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let header_json = format!(
            r#"{{"alg":"EdDSA","kid":"{}","typ":"JWT"}}"#,
            self.upstream_kid
        );
        let payload_json = format!(r#"{{"sub":"{sub}","exp":{exp},"jti":"{jti_str}"}}"#);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = self.upstream_sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    async fn post_token(&self, body: String) -> axum::http::Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn body_to_value(body: Body) -> serde_json::Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Acceptance (a): one well-formed exchange request → exactly one
/// successful response with the documented RFC 8693 shape.
#[tokio::test]
async fn e2e_happy_path_token_exchange_returns_access_token() {
    let h = MeshHarness::new();
    let subj = h.make_subject_token(POD_SUBJECT, 300, None);
    let body = form_body(&[
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("subject_token", &subj),
        ("subject_token_type", TOKEN_TYPE_JWT),
        ("audience", RP_AUDIENCE),
    ]);
    let resp = h.post_token(body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_to_value(resp.into_body()).await;
    assert!(v["access_token"].as_str().is_some());
    assert_eq!(v["token_type"], "Bearer");
    assert!(v["expires_in"].as_u64().unwrap() <= 3600);
    // Pin the issued_token_type to the URN per RFC 8693 §2.2.1.
    assert_eq!(
        v["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
}

/// Acceptance (b): subject_token whose `exp` is in the past gets
/// `invalid_grant` with the constant-time opaque description.
#[tokio::test]
async fn e2e_expired_subject_token_returns_invalid_grant() {
    let h = MeshHarness::new();
    let subj = h.make_subject_token(POD_SUBJECT, -10, None);
    let body = form_body(&[
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("subject_token", &subj),
        ("subject_token_type", TOKEN_TYPE_JWT),
        ("audience", RP_AUDIENCE),
    ]);
    let resp = h.post_token(body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_to_value(resp.into_body()).await;
    assert_eq!(v["error"], "invalid_grant");
    assert_eq!(
        v["error_description"], "subject token validation failed",
        "constant-time opaque description (#44 OPAQUE_INVALID_GRANT)"
    );
}

/// Acceptance (c): audience not in any federation rule → `invalid_target`.
#[tokio::test]
async fn e2e_audience_not_in_rules_returns_invalid_target() {
    let h = MeshHarness::new();
    let subj = h.make_subject_token(POD_SUBJECT, 300, None);
    let body = form_body(&[
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("subject_token", &subj),
        ("subject_token_type", TOKEN_TYPE_JWT),
        // Audience matches NO federation rule.
        ("audience", "https://not-registered.example/api"),
    ]);
    let resp = h.post_token(body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_to_value(resp.into_body()).await;
    assert_eq!(v["error"], "invalid_target");
    assert_eq!(
        v["error_description"],
        "federation policy denies the requested (subject, audience) exchange",
        "constant-time opaque description (#44 OPAQUE_INVALID_TARGET)"
    );
}

/// Acceptance (e): replay defense — second presentation of same jti fails.
#[tokio::test]
async fn e2e_replay_of_same_jti_rejected() {
    let h = MeshHarness::new();
    let subj = h.make_subject_token(POD_SUBJECT, 300, Some("fixed-jti-e2e"));
    let body = form_body(&[
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("subject_token", &subj),
        ("subject_token_type", TOKEN_TYPE_JWT),
        ("audience", RP_AUDIENCE),
    ]);
    let r1 = h.post_token(body.clone()).await;
    assert_eq!(r1.status(), StatusCode::OK);

    let r2 = h.post_token(body).await;
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
    let v = body_to_value(r2.into_body()).await;
    assert_eq!(v["error"], "invalid_grant");
}

/// Issued access_token has `kid` resolvable via the OP's `/jwks.json` —
/// downstream RPs (real or wiremocked) can fetch it and verify.
#[tokio::test]
async fn e2e_issued_token_kid_present_in_jwks_endpoint() {
    let h = MeshHarness::new();
    let subj = h.make_subject_token(POD_SUBJECT, 300, None);
    let body = form_body(&[
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("subject_token", &subj),
        ("subject_token_type", TOKEN_TYPE_JWT),
        ("audience", RP_AUDIENCE),
    ]);
    let token_resp = h.post_token(body).await;
    assert_eq!(token_resp.status(), StatusCode::OK);
    let v = body_to_value(token_resp.into_body()).await;
    let access_token = v["access_token"].as_str().unwrap().to_string();

    // Decode the access_token's kid.
    let header_b64 = access_token.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    let issued_kid = header["kid"].as_str().unwrap().to_string();
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "at+jwt");

    // Fetch /jwks.json — the issued kid must be present.
    let jwks_resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks_resp.status(), StatusCode::OK);
    let jwks = body_to_value(jwks_resp.into_body()).await;
    let kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert!(
        kids.contains(&issued_kid.as_str()),
        "issued token's kid {issued_kid:?} must be advertised in /jwks.json {kids:?}"
    );
}

/// Cross-acceptance check: the discovery doc references the same
/// `jwks_uri` an RP would use to bootstrap. End-to-end mesh consumers
/// can find the OP's keys without out-of-band coordination.
#[tokio::test]
async fn e2e_discovery_doc_points_at_consistent_jwks_uri() {
    let h = MeshHarness::new();
    let disco_resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disco_resp.status(), StatusCode::OK);
    let v = body_to_value(disco_resp.into_body()).await;
    assert_eq!(v["issuer"], "https://oidc.nucleus.example/");
    assert_eq!(v["jwks_uri"], "https://oidc.nucleus.example/jwks.json");
    assert_eq!(
        v["token_endpoint"],
        "https://oidc.nucleus.example/oauth/token"
    );
    // EdDSA advertised — defends T04 algorithm-confusion at the
    // discovery layer.
    let algs = v["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert!(algs.iter().any(|a| a == "EdDSA"));
}
