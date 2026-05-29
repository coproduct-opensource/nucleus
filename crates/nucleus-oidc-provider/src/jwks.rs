//! `GET /jwks.json` — RFC 7517 verify-set publication.
//!
//! Conformance:
//! - Body shape per RFC 7517 §5; OKP key entries per RFC 8037 §2.
//! - `Content-Type: application/jwk-set+json` per RFC 7517 §8.5.1.
//! - `Cache-Control: public, max-age=300, must-revalidate` matches
//!   the 5-minute polling cadence major IdPs (Auth0, Confluent Cloud)
//!   use as the practical floor.
//! - `ETag` derives from the sorted KID list — changes only when the
//!   verify-set changes (rotate / revoke / grace expiry).
//! - Conditional GET: `If-None-Match` matching the current ETag
//!   returns 304 with the Cache-Control + ETag headers echoed, per
//!   RFC 9111 §4.3.4.
//!
//! See `THREAT_MODEL.md` T02 (JWKS poisoning) — HTTPS + the operator
//! runbook's pinning guidance are the in-deployment mitigations; here
//! we focus on serving the right bytes.

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
use crate::keystore::VerifyKey;

/// One key in a JWK Set per RFC 7517 + RFC 8037.
#[derive(Debug, Serialize)]
struct JwkEntry {
    kty: &'static str,
    crv: &'static str,
    kid: String,
    x: String,
    alg: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
}

#[derive(Debug, Serialize)]
struct JwkSet {
    keys: Vec<JwkEntry>,
}

fn verify_key_to_jwk(vk: &VerifyKey) -> JwkEntry {
    let x = URL_SAFE_NO_PAD.encode(vk.verifying_key.as_bytes());
    JwkEntry {
        kty: "OKP",
        crv: "Ed25519",
        kid: vk.kid.clone(),
        x,
        alg: "EdDSA",
        use_: "sig",
    }
}

/// ETag for the current verify-set. Stable across calls with no
/// rotation; changes when any KID is added, removed, or expires.
///
/// We sort KIDs lexicographically so the hash is independent of the
/// keystore's internal order (HashMap iteration is non-deterministic).
fn compute_etag(keys: &[std::sync::Arc<VerifyKey>]) -> String {
    let mut kids: Vec<&str> = keys.iter().map(|k| k.kid.as_str()).collect();
    kids.sort();
    let mut hasher = Sha256::new();
    for kid in kids {
        hasher.update(kid.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let b64 = URL_SAFE_NO_PAD.encode(digest);
    // ETag values are quoted per RFC 9110 §8.8.3.
    format!("\"{b64}\"")
}

/// `GET /jwks.json` handler.
pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, OidcApiError> {
    let keys = state
        .keystore
        .all_verify_keys()
        .map_err(|e| OidcApiError::Internal(format!("keystore: {e}")))?;
    let etag = compute_etag(&keys);

    // Conditional GET — same etag → 304 with required header echo.
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH) {
        if let Ok(s) = if_none_match.to_str() {
            // Per RFC 9110 §13.1.2, If-None-Match may be `*` or a comma-
            // separated list of etags. We do exact-match against a
            // single etag and ignore the wildcard / multi-tag forms in
            // v1 — neither is required for JWKS polling and both add
            // surface for misuse.
            if s == etag {
                return Ok(not_modified(&etag));
            }
        }
    }

    let body = JwkSet {
        keys: keys.iter().map(|k| verify_key_to_jwk(k)).collect(),
    };
    let json = serde_json::to_vec(&body)
        .map_err(|e| OidcApiError::Internal(format!("jwks serialize: {e}")))?;

    let mut response = (StatusCode::OK, json).into_response();
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/jwk-set+json"),
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

fn not_modified(etag: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    let h = response.headers_mut();
    // RFC 9110 §15.4.5: 304 MUST echo Cache-Control + ETag.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, must-revalidate"),
    );
    if let Ok(v) = HeaderValue::from_str(etag) {
        h.insert(header::ETAG, v);
    }
    response
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

    fn app_with_store(store: Arc<dyn JwtKeyStore>) -> axum::Router {
        let issuer_url = "https://oidc.nucleus.example/".to_string();
        let issuer = std::sync::Arc::new(
            crate::issuer::JwtIssuer::new(
                store.clone(),
                issuer_url.clone(),
                std::time::Duration::from_secs(300),
            )
            .unwrap(),
        );
        crate::app::build_app(AppState {
            keystore: store,
            issuer_url: Arc::from(issuer_url.as_str()),
            issuer,
            jti_cache: std::sync::Arc::new(nucleus_oidc_core::JtiCache::new()),
            federation: std::sync::Arc::new(crate::federation::FederationRegistry::empty()),
            bundle_provider: std::sync::Arc::new(crate::spire::StaticBundleProvider::new()),
        })
    }

    async fn get_jwks(app: axum::Router) -> Response<Body> {
        app.oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/jwks.json")
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
    async fn returns_200_with_jwk_set_json_body() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let resp = get_jwks(app_with_store(store.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/jwk-set+json")
        );
        let body = body_to_value(resp.into_body()).await;
        let keys = body["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        let entry = &keys[0];
        assert_eq!(entry["kty"], "OKP");
        assert_eq!(entry["crv"], "Ed25519");
        assert_eq!(entry["alg"], "EdDSA");
        assert_eq!(entry["use"], "sig");
        assert_eq!(entry["kid"], store.active_kid().unwrap());
        // x is base64url-no-pad of the 32-byte public key — 43 chars.
        assert_eq!(entry["x"].as_str().unwrap().len(), 43);
    }

    #[tokio::test]
    async fn cache_control_header_is_5min_with_must_revalidate() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let resp = get_jwks(app_with_store(store)).await;
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=300, must-revalidate")
        );
    }

    #[tokio::test]
    async fn etag_header_present_and_stable_across_calls() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let app = app_with_store(store);

        let r1 = get_jwks(app.clone()).await;
        let etag_1 = r1
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("etag present");
        assert!(etag_1.starts_with('"') && etag_1.ends_with('"'));

        let r2 = get_jwks(app).await;
        let etag_2 = r2
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("etag present");
        assert_eq!(etag_1, etag_2, "etag stable when verify-set unchanged");
    }

    #[tokio::test]
    async fn etag_changes_after_rotation() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let app = app_with_store(store.clone());

        let r1 = get_jwks(app.clone()).await;
        let etag_1 = r1
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        store.rotate().unwrap();

        let r2 = get_jwks(app).await;
        let etag_2 = r2
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        assert_ne!(etag_1, etag_2, "etag changes after rotation");
    }

    #[tokio::test]
    async fn if_none_match_with_current_etag_returns_304() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let app = app_with_store(store);

        let r1 = get_jwks(app.clone()).await;
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
                    .uri("/jwks.json")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        // Per RFC 9110 §15.4.5, 304 echoes ETag + Cache-Control.
        assert_eq!(
            resp.headers()
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok()),
            Some(etag.as_str())
        );
        assert!(resp.headers().get(header::CACHE_CONTROL).is_some());
    }

    #[tokio::test]
    async fn if_none_match_with_stale_etag_returns_200() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let app = app_with_store(store);

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/jwks.json")
                    .header(header::IF_NONE_MATCH, "\"stale-etag\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Acceptance property: every kid in /jwks.json round-trips through
    /// `JwtKeyStore::verify_key`. After rotation, BOTH the new and old
    /// kids appear in the response and both look up cleanly.
    #[tokio::test]
    async fn every_emitted_kid_resolves_through_verify_key() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let app = app_with_store(store.clone());

        store.rotate().unwrap();
        store.rotate().unwrap();
        // Two old kids in grace + one active = 3 entries.

        let resp = get_jwks(app).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_value(resp.into_body()).await;
        let kids: Vec<String> = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kid"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kids.len(), 3, "got kids: {kids:?}");

        for kid in &kids {
            store.verify_key(kid).unwrap_or_else(|_| {
                panic!("kid {kid:?} from /jwks.json must resolve via verify_key")
            });
        }
    }

    /// Negative test: a revoked kid is absent from /jwks.json on the
    /// next call (no eventual-consistency window — the JWKS reads
    /// directly from the store).
    #[tokio::test]
    async fn revoked_kid_absent_from_subsequent_response() {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let app = app_with_store(store.clone());

        let original_kid = store.active_kid().unwrap();
        store.rotate().unwrap();

        // Before revoke: 2 keys in JWKS.
        let r1 = get_jwks(app.clone()).await;
        let v1 = body_to_value(r1.into_body()).await;
        assert_eq!(v1["keys"].as_array().unwrap().len(), 2);

        store.revoke(&original_kid).unwrap();

        // After revoke: 1 key, and the original kid is gone.
        let r2 = get_jwks(app).await;
        let v2 = body_to_value(r2.into_body()).await;
        let keys = v2["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let remaining_kid = keys[0]["kid"].as_str().unwrap();
        assert_ne!(remaining_kid, original_kid);
    }
}
