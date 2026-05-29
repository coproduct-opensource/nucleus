//! `GET /.well-known/openid-configuration` — RFC 8414 discovery.
//!
//! Wire shape: RFC 8414 OAuth 2.0 Authorization Server Metadata, served
//! at the canonical OIDC Discovery 1.0 path. The body uses OAuth-metadata
//! fields exclusively because this OP is a **workload-identity OP**:
//! we issue access tokens via RFC 8693 token exchange, not user-facing
//! authorization-code or implicit flows.
//!
//! Per RFC 8414 §2: `authorization_endpoint` is "REQUIRED unless no
//! grant types are supported that use the authorization endpoint." We
//! support only token-exchange, so the field is correctly omitted and
//! `response_types_supported` is the empty array. RPs that strictly
//! require OIDC Discovery 1.0 semantics will fail to parse this doc,
//! which is the right outcome — they aren't our intended consumers.
//!
//! Cache discipline mirrors `/jwks.json` (#35): `Cache-Control` +
//! ETag derived from the doc bytes, `If-None-Match` → 304.

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::app::AppState;
use crate::error::OidcApiError;

/// Wire form of the discovery doc.
///
/// `#[serde(skip_serializing_if)]` keeps the wire shape minimal; fields
/// we don't support are absent rather than null.
#[derive(Debug, Serialize)]
struct DiscoveryDoc {
    /// The OP's issuer URL. MUST be HTTPS per RFC 8414 §2.
    issuer: String,
    /// JWKS endpoint URL.
    jwks_uri: String,
    /// Token endpoint URL (RFC 8693 token exchange).
    token_endpoint: String,
    /// Response types supported. Empty because this OP serves no
    /// browser-redirect grants. Per RFC 8414 §2, omitting
    /// `authorization_endpoint` is permitted when this is empty.
    response_types_supported: Vec<&'static str>,
    /// Grant types this OP accepts at `token_endpoint`.
    grant_types_supported: Vec<&'static str>,
    /// Token-endpoint authentication mechanism for the **client** half
    /// of the exchange. For a workload-identity OP this is `private_key_jwt`
    /// (the client/workload presents a JWT-SVID as `client_assertion`).
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Signing algorithms the OP advertises for the `id_token_signing_alg`
    /// field. We don't issue id_tokens, but advertising EdDSA pins the
    /// algorithm at the discovery layer — RPs that read this to pick
    /// a verifying alg get the right answer.
    id_token_signing_alg_values_supported: Vec<&'static str>,
    /// Subject-identifier types. RFC 8414 / OIDC Discovery: "public"
    /// is the universal value for non-pseudonymous identifiers, which
    /// our SPIFFE-derived `sub` is.
    subject_types_supported: Vec<&'static str>,
    /// Scope values the OP can include in issued tokens.
    scopes_supported: Vec<&'static str>,
    /// Free-text reference to operator-facing docs.
    service_documentation: &'static str,
    /// Workload Identifier Federation extension flag (informational).
    /// Advertised so consumers know this OP accepts SPIFFE/WIMSE SVIDs
    /// as `subject_token` per `draft-klrc-aiagent-auth-00` (AIMS).
    #[serde(rename = "urn:nucleus:workload_identity_supported")]
    workload_identity_supported: bool,
}

fn build_doc(issuer_url: &str) -> DiscoveryDoc {
    let base = issuer_url.trim_end_matches('/');
    DiscoveryDoc {
        issuer: issuer_url.to_string(),
        jwks_uri: format!("{base}/jwks.json"),
        token_endpoint: format!("{base}/oauth/token"),
        response_types_supported: vec![],
        grant_types_supported: vec!["urn:ietf:params:oauth:grant-type:token-exchange"],
        token_endpoint_auth_methods_supported: vec!["private_key_jwt"],
        id_token_signing_alg_values_supported: vec!["EdDSA"],
        subject_types_supported: vec!["public"],
        scopes_supported: vec![],
        service_documentation: "https://github.com/coproduct-opensource/nucleus", // vendor-allow: project repo
        workload_identity_supported: true,
    }
}

fn etag_for(json: &[u8]) -> String {
    let digest = Sha256::digest(json);
    let b64 = URL_SAFE_NO_PAD.encode(digest);
    format!("\"{b64}\"")
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, OidcApiError> {
    let doc = build_doc(&state.issuer_url);
    let json = serde_json::to_vec(&doc)
        .map_err(|e| OidcApiError::Internal(format!("discovery serialize: {e}")))?;
    let etag = etag_for(&json);

    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(s) = if_none_match.to_str() {
            if s == etag {
                let mut response = StatusCode::NOT_MODIFIED.into_response();
                let h = response.headers_mut();
                h.insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300, must-revalidate"),
                );
                if let Ok(v) = HeaderValue::from_str(&etag) {
                    h.insert(header::ETAG, v);
                }
                return Ok(response);
            }
        }
    }

    let mut response = (StatusCode::OK, json).into_response();
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, must-revalidate"),
    );
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag)
            .map_err(|e| OidcApiError::Internal(format!("etag header: {e}")))?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{InMemoryKeyStore, JwtKeyStore};
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app(issuer_url: &str) -> axum::Router {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let jwt_issuer = Arc::new(
            crate::issuer::JwtIssuer::new(
                store.clone(),
                issuer_url.to_string(),
                std::time::Duration::from_secs(300),
            )
            .unwrap(),
        );
        crate::app::build_app(AppState {
            keystore: store,
            issuer_url: Arc::from(issuer_url),
            issuer: jwt_issuer,
            jti_cache: Arc::new(nucleus_oidc_core::JtiCache::new()),
            federation: Arc::new(crate::federation::FederationRegistry::empty()),
            bundle_provider: Arc::new(crate::spire::StaticBundleProvider::new()),
        })
    }

    async fn get_discovery(app: axum::Router) -> Response<Body> {
        app.oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn body_to_value(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn returns_200_with_application_json_body() {
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn doc_contains_required_rfc_8414_fields() {
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        let body = body_to_value(resp.into_body()).await;
        assert_eq!(body["issuer"], "https://oidc.nucleus.example/");
        assert_eq!(body["jwks_uri"], "https://oidc.nucleus.example/jwks.json");
        assert_eq!(
            body["token_endpoint"],
            "https://oidc.nucleus.example/oauth/token"
        );
        // response_types_supported is required by RFC 8414 — must be present
        // even when empty, signaling no auth-endpoint grant types.
        assert!(body["response_types_supported"].is_array());
        assert_eq!(
            body["response_types_supported"].as_array().unwrap().len(),
            0
        );
        assert_eq!(body["subject_types_supported"][0], "public");
    }

    #[tokio::test]
    async fn doc_advertises_eddsa_signing_alg() {
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        let body = body_to_value(resp.into_body()).await;
        let algs = body["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap();
        assert!(algs.iter().any(|v| v == "EdDSA"));
        // Negative: no `none`, no HS*, no RS* leaking through.
        for alg in algs {
            let s = alg.as_str().unwrap();
            assert_ne!(s, "none");
            assert!(!s.starts_with("HS"));
            assert!(!s.starts_with("RS"));
        }
    }

    #[tokio::test]
    async fn doc_advertises_token_exchange_grant() {
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        let body = body_to_value(resp.into_body()).await;
        let grants = body["grant_types_supported"].as_array().unwrap();
        assert!(grants
            .iter()
            .any(|v| v == "urn:ietf:params:oauth:grant-type:token-exchange"));
    }

    #[tokio::test]
    async fn doc_advertises_private_key_jwt_client_auth() {
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        let body = body_to_value(resp.into_body()).await;
        let methods = body["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap();
        assert!(methods.iter().any(|v| v == "private_key_jwt"));
    }

    #[tokio::test]
    async fn doc_omits_authorization_endpoint() {
        // RFC 8414 §2 permits omitting this when no auth-code/implicit
        // grants are supported. Pinning the omission so a future
        // refactor that adds it triggers a deliberate review.
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        let body = body_to_value(resp.into_body()).await;
        assert!(body.get("authorization_endpoint").is_none());
    }

    #[tokio::test]
    async fn cache_control_and_etag_present() {
        let resp = get_discovery(app("https://oidc.nucleus.example/")).await;
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=300, must-revalidate")
        );
        let etag = resp.headers().get(header::ETAG).expect("etag present");
        let s = etag.to_str().unwrap();
        assert!(s.starts_with('"') && s.ends_with('"'));
    }

    #[tokio::test]
    async fn etag_stable_for_same_issuer() {
        let app1 = app("https://oidc.nucleus.example/");
        let app2 = app("https://oidc.nucleus.example/");
        let r1 = get_discovery(app1).await;
        let r2 = get_discovery(app2).await;
        assert_eq!(
            r1.headers().get(header::ETAG).unwrap(),
            r2.headers().get(header::ETAG).unwrap()
        );
    }

    #[tokio::test]
    async fn etag_differs_for_different_issuer() {
        let r1 = get_discovery(app("https://oidc.nucleus.example/")).await;
        let r2 = get_discovery(app("https://other.example/")).await;
        assert_ne!(
            r1.headers().get(header::ETAG).unwrap(),
            r2.headers().get(header::ETAG).unwrap()
        );
    }

    #[tokio::test]
    async fn if_none_match_returns_304() {
        let app = app("https://oidc.nucleus.example/");
        let r1 = get_discovery(app.clone()).await;
        let etag = r1
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/.well-known/openid-configuration")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert!(resp.headers().get(header::ETAG).is_some());
        assert!(resp.headers().get(header::CACHE_CONTROL).is_some());
    }

    #[tokio::test]
    async fn trailing_slash_normalization_in_jwks_uri() {
        // Issuer with trailing slash should not double-slash the
        // jwks_uri derivation.
        let r1 = get_discovery(app("https://oidc.nucleus.example/")).await;
        let v1 = body_to_value(r1.into_body()).await;
        let r2 = get_discovery(app("https://oidc.nucleus.example")).await;
        let v2 = body_to_value(r2.into_body()).await;
        assert_eq!(v1["jwks_uri"], "https://oidc.nucleus.example/jwks.json");
        assert_eq!(v2["jwks_uri"], "https://oidc.nucleus.example/jwks.json");
    }

    #[test]
    fn workload_identity_extension_uses_urn_namespace() {
        // RFC 7519 §4.3 collision-resistant naming for the extension.
        let json = serde_json::to_string(&build_doc("https://oidc.nucleus.example/")).unwrap();
        assert!(json.contains("urn:nucleus:workload_identity_supported"));
        assert!(!json.contains("\"workload_identity_supported\""));
    }
}
