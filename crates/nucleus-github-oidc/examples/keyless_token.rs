//! Exchange an OIDC JWT (a GitHub Actions token, or a SPIFFE JWT-SVID) for a
//! short-lived Bearer via the generic RFC 7523 client — the keyless entrypoint
//! the nightly red-team lane uses to authenticate a live-LLM adversary WITHOUT a
//! static API key.
//!
//! Reads the subject JWT, the token endpoint, and the audience from the
//! environment; prints ONLY the Bearer to stdout (so a caller can capture it) and
//! diagnostics to stderr. Fail-closed: a rejected or malformed exchange exits
//! non-zero and prints no token.
//!
//! ```bash
//! LLM_OIDC_JWT=<oidc-jwt> LLM_OAUTH_TOKEN_URL=<endpoint> LLM_OAUTH_AUDIENCE=<aud> \
//!   cargo run -p nucleus-github-oidc --features token-exchange --example keyless_token
//! ```

use nucleus_github_oidc::token_exchange::{exchange_jwt_bearer, GRANT_JWT_BEARER};

#[tokio::main]
async fn main() {
    // Workspace reqwest is rustls-no-provider; install a provider before building
    // a Client (never exercised against a mock, required at Client-build time).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let jwt = require_env("LLM_OIDC_JWT");
    let endpoint = require_env("LLM_OAUTH_TOKEN_URL");
    let audience = require_env("LLM_OAUTH_AUDIENCE");
    let grant = std::env::var("LLM_OAUTH_GRANT").unwrap_or_else(|_| GRANT_JWT_BEARER.to_string());

    let client = reqwest::Client::new();
    match exchange_jwt_bearer(&client, &endpoint, &jwt, &audience, &grant).await {
        Ok(token) => {
            eprintln!(
                "keyless: exchanged an OIDC JWT for a Bearer (expires in {}s)",
                token.expires_in
            );
            // stdout carries ONLY the token, so `TOKEN=$(... example ...)` works.
            println!("{}", token.bearer);
        }
        Err(err) => {
            // Fail-closed: no token on stdout, non-zero exit.
            eprintln!("keyless: exchange FAILED (no token minted): {err}");
            std::process::exit(1);
        }
    }
}

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("keyless: {key} is required");
        std::process::exit(2);
    })
}
