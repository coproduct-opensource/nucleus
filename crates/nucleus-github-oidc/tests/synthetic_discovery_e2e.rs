//! SYNTHETIC end-to-end test for the keyless-OIDC prototype.
//!
//! ⚠️  SYNTHETIC TOKEN, NOT A LIVE GITHUB TOKEN. ⚠️
//!
//! Everything here is locally minted with the checked-in workspace test RSA
//! key (`crates/nucleus-fly-oidc/testdata/jwt_test_priv.pem`) under
//! `kid = test-kid`. There is NO connection to GitHub, no live network, and
//! these tokens can NEVER verify against GitHub's real JWKS. The point is to
//! drive the *real* validation code path — `DiscoveryKeyResolver` doing OIDC
//! discovery, fetching a JWKS, building a `DecodingKey`, RS256-verifying,
//! claim-checking, replay-checking, and deriving the SPIFFE id — end to end,
//! against a localhost mock issuer instead of GitHub.
//!
//! The live, genuine end-to-end proof (a real GitHub token + GitHub's real
//! JWKS) can only run inside a CI job with `permissions: id-token: write`;
//! see `.github/workflows/oidc-keyless-prototype.yml`. That result is
//! PENDING CI and is NOT asserted here.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use nucleus_github_oidc::{GitHubOidcConfig, GitHubOidcValidator, OidcError};
use nucleus_oidc_core::DiscoveryKeyResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// SYNTHETIC test private key — the shared workspace test key, NOT a GitHub
/// signing key. The matching public key's `n`/`e` live in
/// `testdata/synthetic_jwks.json`.
const TEST_PRIV: &str = include_str!("../../nucleus-fly-oidc/testdata/jwt_test_priv.pem");
/// The SYNTHETIC JWKS served by the localhost mock issuer below. Clearly
/// labelled as not-a-live-GitHub-JWKS in its own `_comment` field.
const SYNTHETIC_JWKS: &str = include_str!("../testdata/synthetic_jwks.json");
const TEST_KID: &str = "test-kid";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Mint a GitHub-Actions-SHAPED, SYNTHETIC RS256 token with the test key.
/// Shape mirrors a real GitHub OIDC token's claims, but it is locally signed.
/// The `iss` is the localhost mock issuer (known only after the OS assigns a
/// port), so the caller passes it in.
fn mint_with_issuer(
    issuer: &str,
    repo: &str,
    owner: &str,
    git_ref: &str,
    aud: &str,
    jti: &str,
) -> String {
    let n = now();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": format!("repo:{repo}:ref:{git_ref}"),
        "aud": aud,
        "exp": n + 600,
        "iat": n - 30,
        "nbf": n - 30,
        "jti": jti,
        "repository": repo,
        "repository_owner": owner,
        "ref": git_ref,
        "actor": "octocat",
        "event_name": "push",
        "job_workflow_ref": format!("{repo}/.github/workflows/oidc.yml@{git_ref}"),
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV.as_bytes()).expect("synthetic test key parses");
    encode(&header, &claims, &key).expect("synthetic token encodes")
}

/// Spawn a minimal localhost HTTP server that mimics GitHub's OIDC surface:
/// `/.well-known/openid-configuration` -> a discovery doc whose `jwks_uri`
/// points at `/.well-known/jwks` (GitHub's non-standard path, no `.json`),
/// which serves the SYNTHETIC JWKS. Returns the issuer base URL.
///
/// This is a hand-rolled HTTP/1.1 responder (no extra web-framework dep) so
/// the dev-dependency surface stays small. It serves exactly two routes.
async fn spawn_synthetic_oidc_issuer() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind localhost");
    let addr = listener.local_addr().expect("local addr");
    let issuer = format!("http://{addr}");
    let discovery = serde_json::json!({
        "issuer": issuer,
        // GitHub serves jwks at /.well-known/jwks (NOT /jwks.json); mirror it.
        "jwks_uri": format!("{issuer}/.well-known/jwks"),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })
    .to_string();

    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let discovery = discovery.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let body: &str = if path.starts_with("/.well-known/openid-configuration") {
                    &discovery
                } else if path.starts_with("/.well-known/jwks") {
                    SYNTHETIC_JWKS
                } else {
                    "{}"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });

    issuer
}

/// The workspace `reqwest` is built with `rustls-no-provider`, so any process
/// using `DiscoveryKeyResolver` MUST install a crypto provider exactly once
/// before constructing a reqwest client. Tests share one install.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
async fn synthetic_token_validates_through_real_discovery_path() {
    // ⚠️ SYNTHETIC TOKEN, NOT A LIVE GITHUB TOKEN ⚠️
    install_crypto_provider();
    let issuer = spawn_synthetic_oidc_issuer().await;

    let token = mint_with_issuer(
        &issuer,
        "coproduct-opensource/nucleus-agent-starter",
        "coproduct-opensource",
        "refs/heads/main",
        "nucleus.io",
        "synthetic-jti-valid",
    );

    // REAL validator + REAL DiscoveryKeyResolver: discovery -> jwks fetch ->
    // JWK -> DecodingKey -> RS256 verify -> claim checks -> replay -> SPIFFE.
    let validator = GitHubOidcValidator::new(
        GitHubOidcConfig::new("nucleus.io")
            .with_issuer(&issuer)
            .allow_org("coproduct-opensource"),
        DiscoveryKeyResolver::new(),
    );

    let identity = validator
        .validate(&token)
        .await
        .expect("synthetic token validates through the real discovery path");

    assert_eq!(
        identity.spiffe_id.as_str(),
        "spiffe://nucleus.io/ns/github/sa/coproduct-opensource/nucleus-agent-starter/refs/refs-heads-main"
    );
    assert_eq!(identity.claims.actor, "octocat");
    assert_eq!(
        identity.claims.repository,
        "coproduct-opensource/nucleus-agent-starter"
    );
}

#[tokio::test]
async fn synthetic_replayed_token_is_rejected_through_real_path() {
    // ⚠️ SYNTHETIC TOKEN, NOT A LIVE GITHUB TOKEN ⚠️
    install_crypto_provider();
    let issuer = spawn_synthetic_oidc_issuer().await;

    let token = mint_with_issuer(
        &issuer,
        "coproduct-opensource/nucleus-agent-starter",
        "coproduct-opensource",
        "refs/heads/main",
        "nucleus.io",
        "synthetic-jti-replay",
    );

    let validator = GitHubOidcValidator::new(
        GitHubOidcConfig::new("nucleus.io")
            .with_issuer(&issuer)
            .allow_org("coproduct-opensource"),
        DiscoveryKeyResolver::new(),
    );

    // First presentation succeeds...
    validator.validate(&token).await.expect("first use ok");
    // ...replaying the same jti within its window is rejected.
    assert!(matches!(
        validator.validate(&token).await,
        Err(OidcError::TokenReplay(_))
    ));
}
