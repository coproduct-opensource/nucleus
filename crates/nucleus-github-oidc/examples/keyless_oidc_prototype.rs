//! Keyless GitHub Actions OIDC prototype — the HONEST end-to-end spike.
//!
//! This binary is the Rust half of part (3) of the spike: it runs *inside* a
//! GitHub Actions job that has `permissions: id-token: write`, requests a REAL
//! OIDC token from GitHub, and feeds it to the REAL [`GitHubOidcValidator`]
//! against GitHub's REAL JWKS. There is no synthetic key here — this is the
//! genuine proof that the validator accepts a live `token.actions.githubusercontent.com`
//! token.
//!
//! It CANNOT run outside CI: a live token only exists when the runner exposes
//! `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. Run
//! locally and it exits non-zero with a clear "not in CI" message. The
//! end-to-end result is therefore PENDING CI until the workflow actually runs.
//!
//! This is an example (not a default workspace target), so the default
//! `cargo build`/`cargo test` stays green without the network deps; build it
//! explicitly with `cargo run -p nucleus-github-oidc --example keyless_oidc_prototype`.
//!
//! Token request mechanics mirror `@actions/core` `getIDToken(audience)`
//! (`actions/toolkit` `packages/core/src/oidc-utils.ts`):
//!   GET `${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=<urlencoded aud>`
//!   Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}
//!   -> JSON `{ "value": "<jwt>" }`

use nucleus_github_oidc::{DiscoveryKeyResolver, GitHubOidcConfig, GitHubOidcValidator};

/// The audience this prototype asks GitHub to stamp into `aud`. The workflow
/// must request the SAME audience (`core.getIDToken("nucleus.io")` or the
/// `&audience=nucleus.io` query param) or validation fails on `aud`.
const NUCLEUS_AUDIENCE: &str = "nucleus.io";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Workspace reqwest is built with `rustls-no-provider`, so a crypto
    // provider MUST be installed before any TLS client is constructed or the
    // process panics at Client-build time. Workspace convention is ring.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Read the runner-injected request endpoint + bearer. These exist ONLY
    //    in a job with `id-token: write`.
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
        "ACTIONS_ID_TOKEN_REQUEST_URL is unset — this prototype only runs inside a \
         GitHub Actions job with `permissions: id-token: write`. A live GitHub OIDC \
         token cannot be minted anywhere else. (PENDING CI)"
    })?;
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .map_err(|_| "ACTIONS_ID_TOKEN_REQUEST_TOKEN is unset — not in a CI job (PENDING CI)")?;

    // 2. Request the token exactly the way the toolkit does.
    let token = request_id_token(&request_url, &request_token, NUCLEUS_AUDIENCE).await?;
    println!("requested a live GitHub OIDC token ({} bytes)", token.len());

    // 3. Validate against GitHub's REAL JWKS via the production discovery
    //    resolver. Issuer + alg (RS256) + aud default from GitHubOidcConfig.
    let validator = GitHubOidcValidator::new(
        GitHubOidcConfig::new(NUCLEUS_AUDIENCE).allow_org(
            std::env::var("GITHUB_REPOSITORY_OWNER")
                .unwrap_or_else(|_| "coproduct-opensource".into()),
        ),
        DiscoveryKeyResolver::new(),
    );

    let identity = validator.validate(&token).await?;

    println!("LIVE GitHub OIDC token VERIFIED against real JWKS");
    println!("  repository       = {}", identity.claims.repository);
    println!("  repository_owner = {}", identity.claims.repository_owner);
    println!("  ref              = {}", identity.claims.git_ref);
    println!("  actor            = {}", identity.claims.actor);
    println!("  sub              = {}", identity.claims.sub);
    println!("  derived SPIFFE id = {}", identity.spiffe_id.as_str());
    Ok(())
}

/// The `@actions/core` `getIDToken(audience)` request, reimplemented in Rust.
async fn request_id_token(
    request_url: &str,
    request_token: &str,
    audience: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encoded_aud = urlencoding(audience);
    let url = format!("{request_url}&audience={encoded_aud}");

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        value: String,
    }

    let resp: TokenResponse = reqwest::Client::new()
        .get(&url)
        .bearer_auth(request_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp.value)
}

/// Minimal application/x-www-form-urlencoded encoder for the audience param —
/// avoids pulling a dep just for one query value.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
