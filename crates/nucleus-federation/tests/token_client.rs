//! The token client against a mock endpoint. Every success test matches the
//! EXACT body the endpoint received, so a green proves what went on the wire,
//! not merely that the client returned `Ok`.

use std::collections::BTreeMap;

use nucleus_federation::token_client::{GRANT_JWT_BEARER, GRANT_TOKEN_EXCHANGE, TOKEN_TYPE_JWT};
use nucleus_federation::{
    CompactJwt, Encoding, ExchangeError, Grant, TokenRequest, default_client, exchange,
};
use reqwest::Url;
use serde_json::json;
use wiremock::matchers::{body_json, body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ASSERTION: &str = "eyJhbGciOi.eyJzdWIiOi.c2ln";
const MINTED: &str = "minted-access-token-value";

fn client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    default_client().unwrap()
}

fn params() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("rule_id".to_string(), "example-rule".to_string()),
        ("org id".to_string(), "example org/1".to_string()),
    ])
}

fn request(server: &MockServer, grant: Grant, enc: Encoding) -> TokenRequest {
    TokenRequest::new(
        Url::parse(&format!("{}/oauth/token", server.uri())).unwrap(),
        grant,
        enc,
        CompactJwt::new(ASSERTION),
    )
    .unwrap()
    .with_audience("https://upstream.example/api")
    .with_scope("read write")
    .with_params(params())
    .unwrap()
}

fn ok_body() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": MINTED, "token_type": "Bearer", "expires_in": 900,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
    }))
}

async fn expect_exact_form(grant: Grant, want: &str) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string(want))
        .respond_with(ok_body())
        .expect(1)
        .mount(&server)
        .await;
    let tok = exchange(&client(), &request(&server, grant, Encoding::Form))
        .await
        .expect("exact form body matched");
    assert_eq!(tok.expose(), MINTED);
    assert_eq!(tok.expires_in(), Some(900));
}

async fn expect_exact_json(grant: Grant, want: serde_json::Value) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(header("content-type", "application/json"))
        .and(body_json(want))
        .respond_with(ok_body())
        .expect(1)
        .mount(&server)
        .await;
    let tok = exchange(&client(), &request(&server, grant, Encoding::Json))
        .await
        .expect("exact json body matched");
    assert_eq!(tok.expose(), MINTED);
}

#[tokio::test]
async fn rfc8693_form_sends_subject_token_and_its_type() {
    expect_exact_form(
        Grant::TokenExchange8693,
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
         &subject_token=eyJhbGciOi.eyJzdWIiOi.c2ln\
         &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
         &audience=https%3A%2F%2Fupstream.example%2Fapi\
         &scope=read%20write\
         &org%20id=example%20org%2F1\
         &rule_id=example-rule",
    )
    .await;
}

#[tokio::test]
async fn rfc7523_form_sends_assertion_and_no_subject_token_type() {
    expect_exact_form(
        Grant::JwtBearer7523,
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer\
         &assertion=eyJhbGciOi.eyJzdWIiOi.c2ln\
         &audience=https%3A%2F%2Fupstream.example%2Fapi\
         &scope=read%20write\
         &org%20id=example%20org%2F1\
         &rule_id=example-rule",
    )
    .await;
}

#[tokio::test]
async fn rfc8693_json_sends_the_same_fields_as_an_object() {
    expect_exact_json(
        Grant::TokenExchange8693,
        json!({
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": ASSERTION,
            "subject_token_type": TOKEN_TYPE_JWT,
            "audience": "https://upstream.example/api",
            "scope": "read write",
            "rule_id": "example-rule",
            "org id": "example org/1",
        }),
    )
    .await;
}

#[tokio::test]
async fn rfc7523_json_sends_assertion() {
    expect_exact_json(
        Grant::JwtBearer7523,
        json!({
            "grant_type": GRANT_JWT_BEARER,
            "assertion": ASSERTION,
            "audience": "https://upstream.example/api",
            "scope": "read write",
            "rule_id": "example-rule",
            "org id": "example org/1",
        }),
    )
    .await;
}

#[tokio::test]
async fn audience_and_scope_are_omitted_when_unset() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_json(
            json!({ "grant_type": GRANT_JWT_BEARER, "assertion": ASSERTION }),
        ))
        .respond_with(ok_body())
        .expect(1)
        .mount(&server)
        .await;
    let req = TokenRequest::new(
        Url::parse(&format!("{}/t", server.uri())).unwrap(),
        Grant::JwtBearer7523,
        Encoding::Json,
        CompactJwt::new(ASSERTION),
    )
    .unwrap();
    exchange(&client(), &req).await.expect("minimal body");
}

#[test]
fn a_param_named_like_a_standard_field_is_refused() {
    for k in [
        "grant_type",
        "subject_token",
        "assertion",
        "audience",
        "scope",
        "subject_token_type",
    ] {
        let r = TokenRequest::new(
            Url::parse("https://token.example/t").unwrap(),
            Grant::TokenExchange8693,
            Encoding::Form,
            CompactJwt::new(ASSERTION),
        )
        .unwrap()
        .with_params(BTreeMap::from([(k.to_string(), "smuggled".to_string())]));
        assert_eq!(r.unwrap_err(), ExchangeError::InvalidRequest, "{k}");
    }
}

/// A refusal carries the status and nothing the endpoint said — the body here
/// echoes the scopes, which is exactly what must not travel back.
#[tokio::test]
async fn a_non_2xx_is_refused_with_its_status_and_without_its_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string("scope read write not permitted for rule"),
        )
        .mount(&server)
        .await;
    let err = exchange(
        &client(),
        &request(&server, Grant::TokenExchange8693, Encoding::Form),
    )
    .await
    .unwrap_err();
    assert_eq!(err, ExchangeError::Refused { status: 403 });
    for rendered in [format!("{err:?}"), err.to_string()] {
        assert!(!rendered.contains("scope"), "{rendered}");
        assert!(!rendered.contains("not permitted"), "{rendered}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/elsewhere", server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(path("/elsewhere"))
        .respond_with(ok_body())
        .expect(0)
        .mount(&server)
        .await;
    let err = exchange(
        &client(),
        &request(&server, Grant::JwtBearer7523, Encoding::Form),
    )
    .await
    .unwrap_err();
    assert_eq!(err, ExchangeError::Refused { status: 307 });
}

async fn exchange_with_body(
    body: serde_json::Value,
) -> Result<nucleus_federation::ExchangedToken, ExchangeError> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    exchange(
        &client(),
        &request(&server, Grant::JwtBearer7523, Encoding::Form),
    )
    .await
}

#[tokio::test]
async fn a_token_type_other_than_bearer_is_refused() {
    let err =
        exchange_with_body(json!({"access_token": MINTED, "token_type": "mac", "expires_in": 60}))
            .await
            .unwrap_err();
    assert_eq!(err, ExchangeError::Malformed);
    let err = exchange_with_body(json!({"access_token": MINTED, "expires_in": 60}))
        .await
        .unwrap_err();
    assert_eq!(err, ExchangeError::Malformed);
}

#[tokio::test]
async fn bearer_is_matched_case_insensitively() {
    let tok = exchange_with_body(
        json!({"access_token": MINTED, "token_type": "bearer", "expires_in": 60}),
    )
    .await
    .unwrap();
    assert_eq!(tok.expires_in(), Some(60));
}

#[tokio::test]
async fn a_missing_access_token_is_refused() {
    let err = exchange_with_body(json!({"token_type": "Bearer"}))
        .await
        .unwrap_err();
    assert_eq!(err, ExchangeError::Malformed);
    let err = exchange_with_body(json!({"access_token": "", "token_type": "Bearer"}))
        .await
        .unwrap_err();
    assert_eq!(err, ExchangeError::Malformed);
}

/// Absent is "not stated", not zero. The old client turned this into 0.
#[tokio::test]
async fn a_missing_expires_in_is_none_not_zero() {
    let tok = exchange_with_body(json!({"access_token": MINTED, "token_type": "Bearer"}))
        .await
        .unwrap();
    assert_eq!(tok.expires_in(), None);
}

#[tokio::test]
async fn an_expires_in_that_is_not_an_integer_is_refused() {
    let err = exchange_with_body(
        json!({"access_token": MINTED, "token_type": "Bearer", "expires_in": "900"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err, ExchangeError::Malformed);
    let err = exchange_with_body(
        json!({"access_token": MINTED, "token_type": "Bearer", "expires_in": -1}),
    )
    .await
    .unwrap_err();
    assert_eq!(err, ExchangeError::Malformed);
}

#[tokio::test]
async fn debug_of_an_exchanged_token_never_contains_the_token() {
    let tok = exchange_with_body(
        json!({"access_token": MINTED, "token_type": "Bearer", "expires_in": 5}),
    )
    .await
    .unwrap();
    let dbg = format!("{tok:?}");
    assert!(!dbg.contains(MINTED), "{dbg}");
    assert!(dbg.contains("[redacted]"), "{dbg}");
    let alt = format!("{tok:#?}");
    assert!(!alt.contains(MINTED), "{alt}");
}

#[tokio::test]
async fn an_unreachable_endpoint_is_a_transport_error() {
    // Bind then drop a plain listener so the port is (very likely) closed.
    // Not a MockServer: wiremock pools those, so a dropped one still answers.
    let uri = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let req = TokenRequest::new(
        Url::parse(&format!("{uri}/t")).unwrap(),
        Grant::JwtBearer7523,
        Encoding::Form,
        CompactJwt::new(ASSERTION),
    )
    .unwrap();
    assert_eq!(
        exchange(&client(), &req).await.unwrap_err(),
        ExchangeError::Transport
    );
}
