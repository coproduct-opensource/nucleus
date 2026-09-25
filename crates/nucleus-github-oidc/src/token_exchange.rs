//! Generic OAuth JWT-bearer token exchange (RFC 7523), behind the
//! `token-exchange` feature so the base identity crate stays network-free.
//!
//! This is the keyless-auth primitive: a workload presents an OIDC JWT (a GitHub
//! Actions token, or a SPIFFE JWT-SVID) and exchanges it for a short-lived Bearer
//! access token, with no static API key. The client is vendor-neutral: the token
//! endpoint, audience, and grant type are all inputs.
//!
//! # A forwarder now
//!
//! The client lives in `nucleus-federation` ([`nucleus_federation::exchange`]);
//! this module keeps the old entry point's signature and forwards to it. The
//! types changed, deliberately, because the old ones were the flaws:
//!
//! - [`ExchangedToken`] no longer derives `Debug` over the bearer. Read it with
//!   `expose()`; `{:?}` prints `[redacted]`.
//! - [`ExchangeError`] no longer carries up to 200 bytes of the endpoint's
//!   body, which could echo the scopes asked for (ADR 0004). A refusal is a
//!   status code and nothing else.
//! - `expires_in()` is an `Option`; an endpoint that does not state a lifetime
//!   no longer reads as "expires in 0 seconds".
//!
//! # Fail-closed
//!
//! The exchange returns a usable token ONLY on an unambiguous success: a 2xx
//! response whose body carries an `access_token` and a `token_type` of `Bearer`.
//! Anything else is an `Err` — never a token.

use nucleus_federation::{CompactJwt, Encoding, Grant, TokenRequest};
use reqwest::Client;

pub use nucleus_federation::token_client::{GRANT_JWT_BEARER, GRANT_TOKEN_EXCHANGE};
pub use nucleus_federation::{ExchangeError, ExchangedToken};

/// Exchange an OIDC JWT for a short-lived Bearer token. `grant` selects the
/// wire form: [`GRANT_JWT_BEARER`] sends RFC 7523 `assertion`,
/// [`GRANT_TOKEN_EXCHANGE`] sends RFC 8693 `subject_token`; any other value is
/// refused before any I/O. The body is form-encoded and always carries
/// `audience`, as it always has.
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
    let grant = match grant {
        GRANT_JWT_BEARER => Grant::JwtBearer7523,
        GRANT_TOKEN_EXCHANGE => Grant::TokenExchange8693,
        _ => return Err(ExchangeError::InvalidRequest),
    };
    let endpoint = reqwest::Url::parse(endpoint).map_err(|_| ExchangeError::InvalidRequest)?;
    let req = TokenRequest::new(
        endpoint,
        grant,
        Encoding::Form,
        CompactJwt::new(subject_jwt),
    )?
    .with_audience(audience);
    nucleus_federation::exchange(http, &req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client() -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        nucleus_federation::default_client().unwrap()
    }

    /// Success — the forwarder sends the same form body the old client did
    /// (grant, assertion, audience) and returns the endpoint's minted token.
    /// The mock matches the EXACT body, so a green proves what was sent.
    #[tokio::test]
    async fn exchanges_a_jwt_for_the_endpoints_bearer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
                 &assertion=the.subject.jwt\
                 &audience=https%3A%2F%2Frp.example%2Fapi",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-by-endpoint",
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

        // The returned Bearer is the MINTED token, never the subject JWT.
        assert_eq!(tok.expose(), "minted-by-endpoint");
        assert_eq!(tok.expires_in(), Some(900));
        assert!(!format!("{tok:?}").contains("minted-by-endpoint"));
    }

    /// FAIL-CLOSED — a non-2xx status yields no token, and none of its body.
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
        assert_eq!(err, ExchangeError::Refused { status: 403 });
        assert!(!err.to_string().contains("rule"));
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
        assert_eq!(err, ExchangeError::Malformed);
    }

    /// FAIL-CLOSED — a token the endpoint does not call `Bearer` is refused, even
    /// with an `access_token` present.
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
        assert_eq!(err, ExchangeError::Malformed);
    }

    /// An unknown grant string is refused before anything is sent.
    #[tokio::test]
    async fn an_unknown_grant_is_refused_locally() {
        let err = exchange_jwt_bearer(
            &client(),
            "https://token.example/oauth/token",
            "j",
            "a",
            "urn:example:not-a-grant",
        )
        .await
        .unwrap_err();
        assert_eq!(err, ExchangeError::InvalidRequest);
    }
}
