//! `POST /oauth/token` — RFC 8693 token exchange.
//!
//! Single supported grant: `urn:ietf:params:oauth:grant-type:token-exchange`.
//! The caller presents a `subject_token` (a JWT-SVID) plus an `audience`;
//! the OP validates the subject_token, consults the federation registry
//! (#41, currently allow-all stub), records the jti for replay defense,
//! and mints a fresh audience-bound access token via [`JwtIssuer`].
//!
//! # Validation pipeline
//!
//! 1. Parse `application/x-www-form-urlencoded` body.
//! 2. Enforce `grant_type` and `subject_token_type`.
//! 3. Peek at the subject_token's `iss`, `sub`, `exp`, `jti` claims —
//!    **signature verification against SPIRE bundle is task #45**. Until
//!    then we accept any well-formed JWT-SVID; this is documented as a
//!    pre-prod limitation.
//! 4. Federation rule check (allow-all stub until #41 lands).
//! 5. Reject replay via [`JtiCache`].
//! 6. Mint response via [`JwtIssuer::mint`] with `act` claim attesting
//!    the original SVID subject per RFC 8693 §4.1.
//!
//! Error responses follow RFC 6749 §5.2 + RFC 8693 §2.2.2 shapes
//! (`{error, error_description}`).

use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nucleus_lineage::CallSpiffeId;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::app::AppState;
use crate::error::OidcApiError;
use crate::issuer::{DelegatedActor, MintRequest};

/// RFC 8693 grant-type URI for token exchange.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 token-type URI for JWTs (covers JWT-SVIDs).
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 8693 token-type URI for issued access tokens.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 §2.1 request fields. Optional fields are `Option<String>`;
/// missing required fields surface as `InvalidRequest` per RFC 8693
/// §2.2.2.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub actor_token: Option<String>,
    #[serde(default)]
    pub actor_token_type: Option<String>,
}

/// RFC 8693 §2.2.1 successful-response body.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: &'static str,
    pub token_type: &'static str,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Hard cap on accepted subject_token lifetime. The OP enforces this
/// regardless of the upstream IdP's `exp` to defend the JtiCache
/// against pollution attacks (#55 HIGH-1).
pub const MAX_SUBJECT_TTL_SECS: u64 = 3600;

/// `aud` claim shape — RFC 7519 §4.1.3 permits either a string or
/// array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    Single(String),
    Multi(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, target: &str) -> bool {
        match self {
            AudienceClaim::Single(s) => s == target,
            AudienceClaim::Multi(v) => v.iter().any(|a| a == target),
        }
    }
}

/// Subset of JWT-SVID claims we read from the subject_token.
/// `iat`/`iss` are accepted-but-not-validated — we keep the field
/// declarations so `deny_unknown_fields` doesn't reject realistic
/// SPIFFE JWT-SVIDs that carry them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SubjectClaims {
    sub: String,
    #[serde(default)]
    aud: Option<AudienceClaim>,
    #[serde(default)]
    exp: Option<u64>,
    /// RFC 7519 §4.1.5 not-before (#55 HIGH-2).
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    jti: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    Form(req): Form<TokenExchangeRequest>,
) -> Result<Response, OidcApiError> {
    // 1. Grant + subject_token_type discipline.
    if req.grant_type != TOKEN_EXCHANGE_GRANT {
        return Err(OidcApiError::UnsupportedGrantType(format!(
            "grant_type must be {TOKEN_EXCHANGE_GRANT:?}, got {:?}",
            req.grant_type
        )));
    }
    if req.subject_token_type != TOKEN_TYPE_JWT {
        return Err(OidcApiError::InvalidRequest(format!(
            "subject_token_type must be {TOKEN_TYPE_JWT:?}, got {:?}",
            req.subject_token_type
        )));
    }
    if let Some(ref t) = req.requested_token_type {
        if t != TOKEN_TYPE_ACCESS_TOKEN {
            return Err(OidcApiError::InvalidRequest(format!(
                "requested_token_type must be {TOKEN_TYPE_ACCESS_TOKEN:?}, got {t:?}"
            )));
        }
    }

    // 2. Audience selection — RFC 8693 §2.1 says either `audience` or
    //    `resource` carries the target identifier. We require one of
    //    them for federation-rule lookup.
    let audience = req
        .audience
        .clone()
        .or_else(|| req.resource.clone())
        .ok_or_else(|| {
            OidcApiError::InvalidRequest("missing `audience` or `resource`".to_string())
        })?;
    if audience.trim().is_empty() {
        return Err(OidcApiError::InvalidRequest(
            "audience must be non-empty".to_string(),
        ));
    }

    // 3. Decode + verify the subject_token signature against the
    //    SPIRE trust bundle (#45). The decode step happens first to
    //    extract `kid` + `iss` + `sub`; we then dispatch the verifying
    //    key lookup through `state.bundle_provider`.
    let (header_b64, payload_b64, sig_b64) = split_jwt(&req.subject_token).map_err(|m| {
        tracing::warn!(detail = %m, "subject_token malformed");
        OidcApiError::InvalidGrant(m)
    })?;

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .map_err(|e| OidcApiError::InvalidGrant(format!("header b64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OidcApiError::InvalidGrant(format!("header json: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcApiError::InvalidGrant("subject_token missing alg".into()))?;
    if alg != "EdDSA" {
        // Algorithm-pin per THREAT_MODEL T04 — we only accept EdDSA
        // subject_tokens. Other algs are documented as v2 work.
        tracing::warn!(alg = %alg, "subject_token unsupported alg");
        return Err(OidcApiError::InvalidGrant(format!(
            "subject_token alg {alg:?} unsupported"
        )));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcApiError::InvalidGrant("subject_token missing kid".into()))?;

    let claims = decode_jwt_payload(&req.subject_token)
        .map_err(|m| OidcApiError::InvalidGrant(format!("subject_token claim decode: {m}")))?;

    let sub_spiffe = CallSpiffeId::parse(claims.sub.clone()).map_err(|e| {
        OidcApiError::InvalidGrant(format!("subject_token sub is not a SPIFFE ID: {e}"))
    })?;

    // Extract trust-domain (authority) from `spiffe://<trust-domain>/...`
    let sub_str = sub_spiffe.as_str();
    let trust_domain = sub_str
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/').map(|(td, _)| td))
        .ok_or_else(|| {
            OidcApiError::InvalidGrant("subject_token sub missing trust-domain".into())
        })?;

    let vk = state
        .bundle_provider
        .verify_key(trust_domain, kid)
        .ok_or_else(|| {
            tracing::warn!(trust_domain = %trust_domain, kid = %kid, "subject_token kid unknown");
            OidcApiError::InvalidGrant(format!(
                "subject_token kid {kid:?} not in trust bundle for {trust_domain:?}"
            ))
        })?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|e| OidcApiError::InvalidGrant(format!("sig b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        OidcApiError::InvalidGrant("subject_token sig wrong length (Ed25519 = 64 bytes)".into())
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|e| {
            tracing::warn!(error = %e, "subject_token signature verify failed");
            OidcApiError::InvalidGrant("subject_token signature verify failed".into())
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OidcApiError::Internal("clock before unix epoch".into()))?
        .as_secs();

    // (#55 HIGH-3) RFC 8693 §1 confused-deputy defense: subject_token
    // `aud` MUST include the OP's own issuer URL. If absent or empty,
    // accept (downstream SPIRE Agent SVIDs sometimes omit `aud`);
    // if present, require the OP to be in the list.
    if let Some(aud_claim) = &claims.aud {
        if !aud_claim.contains(state.issuer_url.as_ref()) {
            tracing::warn!(?aud_claim, op_issuer = %state.issuer_url, "subject_token aud mismatch");
            return Err(OidcApiError::InvalidGrant(
                "subject_token aud does not include OP issuer".into(),
            ));
        }
    }

    // (#55 HIGH-2) RFC 7519 §4.1.5 nbf check with 60s clock-skew leeway
    // (THREAT_MODEL T06).
    if let Some(nbf) = claims.nbf {
        if nbf > now.saturating_add(60) {
            tracing::warn!(nbf, now, "subject_token not yet valid");
            return Err(OidcApiError::InvalidGrant(
                "subject_token not yet valid (nbf in the future)".into(),
            ));
        }
    }

    let sub_exp = claims.exp.ok_or_else(|| {
        OidcApiError::InvalidGrant("subject_token missing `exp` claim".to_string())
    })?;
    if sub_exp <= now {
        return Err(OidcApiError::InvalidGrant(format!(
            "subject_token already expired ({sub_exp} <= {now})"
        )));
    }

    // 4. Replay defense — every subject_token presentation must be
    //    fresh within its exp window. Subject tokens without `jti`
    //    cannot be replay-protected; reject conservatively.
    let jti = claims.jti.clone().ok_or_else(|| {
        OidcApiError::InvalidGrant("subject_token missing `jti` claim".to_string())
    })?;
    // (#55 HIGH-1) Clamp the JTI retention bound to defend the cache
    // against an upstream IdP that mints `exp = u64::MAX` tokens.
    // Without this clamp a hostile-bundle key can pollute the cache
    // permanently, evicting legitimate short-lived entries via the
    // soonest-expiring eviction policy.
    let jti_retention_bound = sub_exp.min(now.saturating_add(MAX_SUBJECT_TTL_SECS));
    state
        .jti_cache
        .check_and_mark(&jti, jti_retention_bound)
        .map_err(|_| {
            OidcApiError::InvalidGrant(format!("subject_token jti {jti:?} already presented"))
        })?;

    // 5. Federation rule lookup (#41).
    let decision = state
        .federation
        .evaluate(sub_spiffe.as_str(), &audience, TOKEN_EXCHANGE_GRANT);
    let rule_max_lifetime = match decision {
        crate::federation::Decision::Allow {
            matched_rule_id,
            max_lifetime,
        } => {
            tracing::info!(
                sub = %sub_spiffe,
                audience = %audience,
                matched_rule = %matched_rule_id,
                "federation: ALLOW"
            );
            max_lifetime
        }
        crate::federation::Decision::Deny(reason) => {
            tracing::warn!(
                sub = %sub_spiffe,
                audience = %audience,
                ?reason,
                "federation: DENY"
            );
            return Err(OidcApiError::InvalidTarget(format!(
                "federation policy denies (sub, audience) — {reason:?}"
            )));
        }
    };

    // 6. Mint response token. `act` claim attests the upstream actor
    //    per RFC 8693 §4.1.
    let mint_lifetime = bounded_lifetime(sub_exp, now).min(rule_max_lifetime);
    let client_id = sub_spiffe.to_string();
    let act = Some(DelegatedActor {
        sub: client_id.clone(),
        act: None,
    });
    let issuer = state.issuer.clone();
    let token = issuer
        .mint(MintRequest {
            subject: sub_spiffe,
            audience: audience.clone(),
            client_id,
            scope: req.scope.clone(),
            act,
            kind: Some("token_exchange".to_string()),
        })
        .map_err(|e| OidcApiError::Internal(format!("mint: {e}")))?;

    let body = TokenExchangeResponse {
        access_token: token,
        issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: mint_lifetime.as_secs(),
        scope: req.scope,
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// Clamp the mint lifetime so the response token never outlives the
/// subject_token's exp. Both bounds: ≤ subject_exp - now AND ≤ 1h.
fn bounded_lifetime(subject_exp: u64, now: u64) -> Duration {
    let remaining = subject_exp.saturating_sub(now);
    let bounded = remaining.min(3600);
    Duration::from_secs(bounded.max(1))
}

fn decode_jwt_payload(jwt: &str) -> Result<SubjectClaims, String> {
    let mut parts = jwt.splitn(3, '.');
    let _header = parts
        .next()
        .ok_or_else(|| "jwt missing header".to_string())?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| "jwt missing payload".to_string())?;
    let _sig = parts
        .next()
        .ok_or_else(|| "jwt missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("jwt has more than 3 parts".to_string());
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("base64url decode: {e}"))?;
    let claims: SubjectClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload json: {e}"))?;
    Ok(claims)
}

/// Split a compact JWS into its three base64url segments without
/// decoding them. Returns owned `String`s so the caller can pass them
/// to both decode (per-segment) and `format!` (signing-input
/// reconstruction).
fn split_jwt(jwt: &str) -> Result<(String, String, String), String> {
    let mut parts = jwt.splitn(3, '.');
    let header = parts
        .next()
        .ok_or_else(|| "jwt missing header".to_string())?;
    let payload = parts
        .next()
        .ok_or_else(|| "jwt missing payload".to_string())?;
    let sig = parts
        .next()
        .ok_or_else(|| "jwt missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("jwt has more than 3 parts".to_string());
    }
    Ok((header.to_string(), payload.to_string(), sig.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::JwtIssuer;
    use crate::keystore::{InMemoryKeyStore, JwtKeyStore};
    use axum::body::Body;
    use axum::http::{header, Method, Request};
    use http_body_util::BodyExt;
    use nucleus_oidc_core::JtiCache;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Test-fixture upstream signer: same Ed25519 keypair used by
    /// `make_subject_jwt` to sign tokens AND by the bundle provider
    /// to verify them. The `kid` is the RFC 7638 thumbprint.
    fn fixture_signer() -> (ed25519_dalek::SigningKey, String) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let kid = crate::keystore::rfc7638_kid(&sk.verifying_key());
        (sk, kid)
    }

    fn app() -> axum::Router {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let issuer = Arc::new(
            JwtIssuer::new(
                store.clone(),
                "https://oidc.nucleus.example/".to_string(),
                Duration::from_secs(300),
            )
            .unwrap(),
        );
        let rules = crate::federation::FederationRules {
            rule: vec![crate::federation::FederationRule {
                id: "test-allow".to_string(),
                subject_prefix: "spiffe://prod.example.com/*".to_string(),
                audience: "https://rp-a.example/api".to_string(),
                allowed_grants: vec![TOKEN_EXCHANGE_GRANT.to_string()],
                max_token_lifetime_secs: 3600,
            }],
        };
        let federation = Arc::new(crate::federation::FederationRegistry::new(rules));

        // Register the fixture signer's public key under
        // (trust_domain=prod.example.com, kid=<rfc7638-thumbprint>).
        let (sk, kid) = fixture_signer();
        let bundle = crate::spire::StaticBundleProvider::new();
        bundle.add_key("prod.example.com", kid, sk.verifying_key());

        crate::app::build_app(crate::app::AppState {
            keystore: store,
            issuer_url: Arc::from("https://oidc.nucleus.example/"),
            issuer,
            jti_cache: Arc::new(JtiCache::new()),
            federation,
            bundle_provider: Arc::new(bundle),
        })
    }

    fn make_subject_jwt(sub: &str, exp_offset_secs: i64, jti: Option<&str>) -> String {
        let (sk, kid) = fixture_signer();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset_secs).max(0) as u64;
        let jti_str = jti
            .map(|j| j.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"JWT"}}"#);
        let payload_json = format!(r#"{{"sub":"{sub}","exp":{exp},"jti":"{jti_str}"}}"#);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        use ed25519_dalek::Signer;
        let sig = sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Subject_token signed by a key NOT in the bundle. Used by the
    /// signature-verification negative tests.
    fn make_subject_jwt_with_unknown_key(sub: &str) -> String {
        let unknown_sk = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
        let unknown_kid = crate::keystore::rfc7638_kid(&unknown_sk.verifying_key());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + 300) as u64;
        let jti = Uuid::new_v4().to_string();
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{unknown_kid}","typ":"JWT"}}"#);
        let payload_json = format!(r#"{{"sub":"{sub}","exp":{exp},"jti":"{jti}"}}"#);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        use ed25519_dalek::Signer;
        let sig = unknown_sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
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

    async fn post_token(app: axum::Router, body: String) -> Response<Body> {
        app.oneshot(
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

    async fn body_to_value(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn happy_path_returns_access_token() {
        let sub = "spiffe://prod.example.com/ns/agents/sa/coder";
        let subject = make_subject_jwt(sub, 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_value(resp.into_body()).await;
        assert!(v["access_token"].as_str().unwrap().contains('.'));
        assert_eq!(v["issued_token_type"], TOKEN_TYPE_ACCESS_TOKEN);
        assert_eq!(v["token_type"], "Bearer");
        assert!(v["expires_in"].as_u64().unwrap() > 0);
        assert!(v["expires_in"].as_u64().unwrap() <= 300);
    }

    /// M-3 strong-binding regression for the OIDC subject_token trust root
    /// (site: subject_token signature check, the `vk.verify_strict(...)`
    /// call). The Ed25519 identity/neutral key (`[1, 0, ..., 0]`) with the
    /// identity-triple signature (R = identity encoding, s = 0) satisfies
    /// the COFACTORED verification equation for EVERY message, so non-strict
    /// `verify()` ACCEPTS it. The crafted subject_token below is otherwise
    /// fully valid (valid SPIFFE `sub`, fresh `exp`/`jti`, matching
    /// `audience`) and the identity key is registered in the trust bundle,
    /// so under non-strict `verify()` the exchange SUCCEEDS (200) and mints
    /// an access token bound to a FORGED identity. `verify_strict()` rejects
    /// the small-order key → 400 invalid_grant. If the site reverts to
    /// `vk.verify(...)`, assertion (ii) sees 200 OK and fails.
    #[tokio::test]
    async fn small_order_key_is_rejected_by_verify_strict() {
        use ed25519_dalek::VerifyingKey;

        // (i) No regression: an honest token still succeeds.
        let honest = make_subject_jwt("spiffe://prod.example.com/ns/agents/sa/coder", 300, None);
        let honest_body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &honest),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        assert_eq!(
            post_token(app(), honest_body).await.status(),
            StatusCode::OK
        );

        // Build an app whose trust bundle contains the small-order identity
        // key under the trust domain the federation rule allows.
        let mut id = [0u8; 32];
        id[0] = 1; // identity/neutral point encoding — a small-order key
        let identity_vk =
            VerifyingKey::from_bytes(&id).expect("identity point is a valid Ed25519 encoding");
        let identity_kid = crate::keystore::rfc7638_kid(&identity_vk);

        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let issuer = Arc::new(
            JwtIssuer::new(
                store.clone(),
                "https://oidc.nucleus.example/".to_string(),
                Duration::from_secs(300),
            )
            .unwrap(),
        );
        let rules = crate::federation::FederationRules {
            rule: vec![crate::federation::FederationRule {
                id: "test-allow".to_string(),
                subject_prefix: "spiffe://prod.example.com/*".to_string(),
                audience: "https://rp-a.example/api".to_string(),
                allowed_grants: vec![TOKEN_EXCHANGE_GRANT.to_string()],
                max_token_lifetime_secs: 3600,
            }],
        };
        let federation = Arc::new(crate::federation::FederationRegistry::new(rules));
        let bundle = crate::spire::StaticBundleProvider::new();
        bundle.add_key("prod.example.com", identity_kid.clone(), identity_vk);
        let forged_app = crate::app::build_app(crate::app::AppState {
            keystore: store,
            issuer_url: Arc::from("https://oidc.nucleus.example/"),
            issuer,
            jti_cache: Arc::new(JtiCache::new()),
            federation,
            bundle_provider: Arc::new(bundle),
        });

        // (ii) Strong binding: a subject_token that is fully valid EXCEPT
        //      that it carries the identity-triple signature under the
        //      registered small-order identity key.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + 300) as u64;
        let jti = Uuid::new_v4().to_string();
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{identity_kid}","typ":"JWT"}}"#);
        let payload_json = format!(
            r#"{{"sub":"spiffe://prod.example.com/ns/agents/sa/coder","exp":{exp},"jti":"{jti}"}}"#
        );
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&id); // R = identity, s = 0
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
        let forged = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let forged_body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &forged),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(forged_app, forged_body).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "identity-triple subject_token must be REFUSED by verify_strict; a \
             revert to non-strict verify() would mint an access token for a \
             forged identity"
        );
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn wrong_grant_type_returns_unsupported_grant_type() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", "authorization_code"),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn wrong_subject_token_type_returns_invalid_request() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", "urn:not:a:real:type"),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_request");
    }

    #[tokio::test]
    async fn missing_audience_and_resource_returns_invalid_request() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_request");
    }

    #[tokio::test]
    async fn malformed_subject_token_returns_invalid_grant() {
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", "not-a-jwt"),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn non_spiffe_subject_returns_invalid_grant() {
        let subject = make_subject_jwt("just-a-string", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn expired_subject_token_returns_invalid_grant() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", -10, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn replay_of_same_jti_rejected() {
        let app = app();
        let subject = make_subject_jwt(
            "spiffe://prod.example.com/ns/x/sa/y",
            300,
            Some("fixed-jti-1"),
        );
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let r1 = post_token(app.clone(), body.clone()).await;
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = post_token(app, body).await;
        assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(r2.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
        // Per #44 constant-time hardening, the inner replay-specific
        // detail is wire-opaque; assert the canonical description.
        assert_eq!(v["error_description"], crate::error::OPAQUE_INVALID_GRANT);
    }

    #[tokio::test]
    async fn resource_field_accepted_as_audience_alias() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("resource", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn issued_token_lifetime_bounded_by_subject_exp() {
        // Subject expires in 60s — issued token's expires_in must be ≤ 60s.
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 60, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_value(resp.into_body()).await;
        assert!(v["expires_in"].as_u64().unwrap() <= 60);
    }

    #[tokio::test]
    async fn unknown_kid_returns_invalid_grant() {
        let subject = make_subject_jwt_with_unknown_key("spiffe://prod.example.com/ns/x/sa/y");
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn tampered_signature_returns_invalid_grant() {
        // Build a valid token then corrupt the last 4 chars of the
        // signature segment — must fail signature verify.
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let parts: Vec<&str> = subject.splitn(3, '.').collect();
        let tampered_sig = format!("{}AAAA", &parts[2][..parts[2].len().saturating_sub(4)]);
        let tampered = format!("{}.{}.{tampered_sig}", parts[0], parts[1]);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &tampered),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn unsupported_alg_returns_invalid_grant() {
        // Forge a JWT with `alg=HS256` — must be rejected per T04
        // algorithm-pin discipline, regardless of signature validity.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now + 300;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"x","typ":"JWT"}"#); // alg-pin-allow: negative test asserting HS256 is rejected
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"sub":"spiffe://prod.example.com/ns/x/sa/y","exp":{exp},"jti":"j"}}"#)
                .as_bytes(),
        );
        let sig = URL_SAFE_NO_PAD.encode(b"fake-hmac-output");
        let token = format!("{header}.{payload}.{sig}");
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &token),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn scope_round_trips_to_response() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
            ("scope", "read:bundles write:bundles"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["scope"], "read:bundles write:bundles");
    }
}
