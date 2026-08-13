//! Generic OAuth JWT-bearer token exchange (RFC 7523), behind the
//! `token-exchange` feature so the base identity crate stays network-free.
//!
//! This is the keyless-auth primitive: a workload presents an OIDC JWT (a GitHub
//! Actions token, or a SPIFFE JWT-SVID) and exchanges it for a short-lived Bearer
//! access token, with no static API key. It is the mechanism behind vendor
//! Workload Identity Federation (e.g. Anthropic's Claude API WIF is exactly an
//! RFC 7523 `jwt-bearer` grant), but this client is **vendor-neutral**: the token
//! endpoint, audience, and grant type are all inputs — there is no vendor host or
//! token literal in this module.
//!
//! # Fail-closed
//!
//! The exchange returns a usable token ONLY on an unambiguous success: a 2xx
//! response whose body carries an `access_token` and a `token_type` of `Bearer`.
//! A non-2xx status, a missing `access_token`, or any other `token_type` is an
//! `Err` — never a token. A relying party can therefore treat a returned
//! [`ExchangedToken`] as "the IdP federated this workload", nothing weaker.

use reqwest::Client;

/// Percent-encode one `application/x-www-form-urlencoded` value (RFC 3986
/// unreserved set stays literal; everything else becomes `%XX`).
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The RFC 7523 grant type most IdPs (and vendor WIF) accept.
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// A short-lived Bearer token minted by the exchange.
#[derive(Debug, Clone)]
pub struct ExchangedToken {
    /// The `access_token`, to be sent as `Authorization: Bearer <token>`.
    pub bearer: String,
    /// Seconds until expiry, as reported by the endpoint (0 if unstated).
    pub expires_in: u64,
}

/// Why an exchange did not yield a usable Bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeError {
    /// The HTTP request itself failed (connect/TLS/timeout).
    Http(String),
    /// The endpoint returned a non-2xx status (with a truncated body).
    Status(u16, String),
    /// The 2xx body was not the expected JSON.
    Body(String),
    /// A required field was absent from the success body.
    Missing(&'static str),
    /// The `token_type` was present but not `Bearer` — refuse it.
    NotBearer(String),
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "token exchange HTTP error: {e}"),
            Self::Status(c, b) => write!(f, "token exchange returned status {c}: {b}"),
            Self::Body(e) => write!(f, "token exchange body was not valid JSON: {e}"),
            Self::Missing(field) => write!(f, "token exchange success body missing `{field}`"),
            Self::NotBearer(t) => write!(f, "token exchange returned token_type {t:?}, not Bearer"),
        }
    }
}

impl std::error::Error for ExchangeError {}

/// Exchange an OIDC JWT for a short-lived Bearer token via an RFC 7523
/// `jwt-bearer` grant. `endpoint`, `audience`, and `grant` are inputs so this is
/// vendor-neutral (pass [`GRANT_JWT_BEARER`] for the standard grant).
///
/// Fail-closed: only a 2xx body with `access_token` and `token_type == "Bearer"`
/// yields `Ok`.
pub async fn exchange_jwt_bearer(
    http: &Client,
    endpoint: &str,
    subject_jwt: &str,
    audience: &str,
    grant: &str,
) -> Result<ExchangedToken, ExchangeError> {
    // application/x-www-form-urlencoded, RFC 3986 percent-encoding, no extra deps.
    let body = format!(
        "grant_type={}&assertion={}&audience={}",
        form_encode(grant),
        form_encode(subject_jwt),
        form_encode(audience),
    );
    let resp = http
        .post(endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| ExchangeError::Http(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| ExchangeError::Http(e.to_string()))?;

    if !status.is_success() {
        let mut body = text;
        body.truncate(200);
        return Err(ExchangeError::Status(status.as_u16(), body));
    }

    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ExchangeError::Body(e.to_string()))?;

    // Refuse anything that is not explicitly a Bearer token — a relying party must
    // not carry a token whose type the IdP did not affirm as Bearer.
    match v.get("token_type").and_then(serde_json::Value::as_str) {
        Some(t) if t.eq_ignore_ascii_case("bearer") => {}
        Some(other) => return Err(ExchangeError::NotBearer(other.to_string())),
        None => return Err(ExchangeError::Missing("token_type")),
    }

    let bearer = v
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or(ExchangeError::Missing("access_token"))?
        .to_string();
    let expires_in = v
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    Ok(ExchangedToken { bearer, expires_in })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client() -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Client::new()
    }

    /// Success — a well-formed exchange returns the Bearer the endpoint minted.
    /// The mock ONLY matches when the request body carries the `jwt-bearer`
    /// grant_type AND the assertion JWT, so a green here proves the client
    /// actually SENT the exchange (assert-on-received), not merely returned Ok.
    #[tokio::test]
    async fn exchanges_a_jwt_for_the_endpoints_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("grant_type=urn"))
            .and(body_string_contains("jwt-bearer"))
            .and(body_string_contains("assertion=the.subject.jwt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "sk-oat-minted-by-endpoint",
                "token_type": "Bearer",
                "expires_in": 900
            })))
            .mount(&server)
            .await;

        let tok = exchange_jwt_bearer(
            &client(),
            &format!("{}/oauth/token", server.uri()),
            "the.subject.jwt",
            "https://rp.example/api",
            GRANT_JWT_BEARER,
        )
        .await
        .expect("a well-formed exchange yields a token");

        // The returned Bearer is the MINTED token, never the subject JWT — a
        // client that forwarded the raw assertion instead would fail here.
        assert_eq!(tok.bearer, "sk-oat-minted-by-endpoint");
        assert_ne!(tok.bearer, "the.subject.jwt");
        assert_eq!(tok.expires_in, 900);
    }

    /// FAIL-CLOSED — a non-2xx status yields no token.
    #[tokio::test]
    async fn a_rejected_exchange_is_an_error_not_a_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("federation rule did not match"),
            )
            .mount(&server)
            .await;

        let err = exchange_jwt_bearer(
            &client(),
            &format!("{}/oauth/token", server.uri()),
            "j",
            "a",
            GRANT_JWT_BEARER,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ExchangeError::Status(403, _)), "{err}");
    }

    /// FAIL-CLOSED — a 2xx body with no `access_token` yields no token.
    #[tokio::test]
    async fn a_success_body_without_access_token_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token_type": "Bearer", "expires_in": 900
            })))
            .mount(&server)
            .await;

        let err = exchange_jwt_bearer(
            &client(),
            &format!("{}/oauth/token", server.uri()),
            "j",
            "a",
            GRANT_JWT_BEARER,
        )
        .await
        .unwrap_err();
        assert_eq!(err, ExchangeError::Missing("access_token"));
    }

    /// FAIL-CLOSED — a token the endpoint does not call `Bearer` is refused, even
    /// with an `access_token` present. A client that accepted any token_type
    /// would go green here — this is the mutation-red guard.
    #[tokio::test]
    async fn a_non_bearer_token_type_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "opaque", "token_type": "mac", "expires_in": 900
            })))
            .mount(&server)
            .await;

        let err = exchange_jwt_bearer(
            &client(),
            &format!("{}/oauth/token", server.uri()),
            "j",
            "a",
            GRANT_JWT_BEARER,
        )
        .await
        .unwrap_err();
        assert_eq!(err, ExchangeError::NotBearer("mac".to_string()));
    }
}
