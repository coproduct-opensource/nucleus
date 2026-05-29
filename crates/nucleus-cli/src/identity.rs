//! `nucleus identity` — JWT-SVID inspection + OP token-exchange affordances.
//!
//! Subcommands:
//! - `inspect <token>` — decode header + claims of a JWT (offline,
//!   no signature verification).
//! - `mint --audience <url> --out <file>` — request a JWT-SVID from
//!   the local SPIRE Agent. **Stub in v1** — depends on the
//!   `nucleus-oidc-provider::spire::WorkloadApiBundleProvider`
//!   integration deferred to v2.
//! - `present --token <file> --op-url <url> --audience <rp>` — POST
//!   the subject_token to the OP's `/oauth/token` endpoint and emit
//!   the exchanged access-token. **Stub in v1** — exercises the OP
//!   via integration test in #50.
//! - `verify --token <file> --jwks <url-or-file>` — verify a JWT's
//!   signature against a JWKS. **Stub in v1** — verification primitive
//!   lives in `nucleus-oidc-core::Jwk::public_key()`; CLI wire-up is
//!   straightforward but deferred to keep this iteration tight.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct IdentityArgs {
    #[command(subcommand)]
    command: IdentityCommand,
}

#[derive(Subcommand, Debug)]
enum IdentityCommand {
    /// Decode and display a JWT's header + claims (offline; no signature check).
    Inspect(InspectArgs),
    /// Request a JWT-SVID from the local SPIRE Agent (stub in v1).
    Mint(MintArgs),
    /// Exchange a subject_token with the OP for an audience-bound access token (stub in v1).
    Present(PresentArgs),
    /// Verify a JWT's signature against a JWKS (stub in v1).
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to a JWT file, OR the literal token string (auto-detected).
    pub token: String,
    /// Emit raw JSON instead of pretty-printed.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct MintArgs {
    /// Audience URL the issued SVID will be bound to.
    #[arg(long)]
    pub audience: String,
    /// Output path for the minted token.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Debug)]
pub struct PresentArgs {
    /// Path to the JWT-SVID subject_token.
    #[arg(long)]
    pub token: PathBuf,
    /// HTTPS issuer URL of the target OP.
    #[arg(long)]
    pub op_url: String,
    /// Audience for the exchanged access token.
    #[arg(long)]
    pub audience: String,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to the JWT to verify.
    #[arg(long)]
    pub token: PathBuf,
    /// JWKS source — either an HTTPS URL or a local file path.
    #[arg(long)]
    pub jwks: String,
}

pub fn execute(args: IdentityArgs) -> Result<()> {
    match args.command {
        IdentityCommand::Inspect(a) => inspect(a),
        IdentityCommand::Mint(_) => Err(anyhow!(
            "`nucleus identity mint` is not implemented in v1. Track follow-up: \
             integration depends on nucleus-oidc-provider::spire::WorkloadApiBundleProvider \
             (currently fail-closed stub). Use a SPIRE Agent's `spire-agent api fetch jwt` \
             in the meantime."
        )),
        IdentityCommand::Present(_) => Err(anyhow!(
            "`nucleus identity present` is not implemented in v1. The exchange wire shape is \
             RFC 8693 (token-exchange grant). Use curl in the meantime: \
             `curl -X POST <op-url>/oauth/token \\\n  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \\\n  -d 'subject_token=<jwt>' \\\n  -d 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \\\n  -d 'audience=<rp>'`"
        )),
        IdentityCommand::Verify(_) => Err(anyhow!(
            "`nucleus identity verify` is not implemented in v1. \
             The primitive (Jwk::public_key + Ed25519 verify) is available in \
             nucleus-oidc-core; CLI wire-up is straightforward and tracked as a follow-up."
        )),
    }
}

fn inspect(args: InspectArgs) -> Result<()> {
    let token = read_token(&args.token)?;
    let parts: Vec<&str> = token.trim().splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "expected JWT with 3 dot-separated segments; got {}",
            parts.len()
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .with_context(|| "decoding header base64url")?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).with_context(|| "parsing header JSON")?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .with_context(|| "decoding payload base64url")?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).with_context(|| "parsing payload JSON")?;

    let signature_len_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map(|v| v.len())
        .unwrap_or(0);

    let report = serde_json::json!({
        "header": header,
        "claims": payload,
        "signature_length_bytes": signature_len_bytes,
        "algorithm_hint": match signature_len_bytes {
            64 => "EdDSA (Ed25519) signature length",
            32 => "HS256 / SHA-256 MAC length",
            256 => "RS2048 signature length",
            384 => "RS3072 signature length",
            512 => "RS4096 signature length",
            _ => "unknown",
        },
    });

    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}

/// Accept either a path to a file OR the literal token string. If the
/// input contains exactly two `.` separators (JWT shape), treat it as
/// the token; otherwise treat it as a file path.
fn read_token(arg: &str) -> Result<String> {
    if arg.matches('.').count() == 2 && !arg.contains('/') {
        Ok(arg.to_string())
    } else {
        std::fs::read_to_string(arg).with_context(|| format!("reading token file {arg:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt() -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"at+jwt","kid":"k1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            br#"{"iss":"https://oidc.nucleus.example/","sub":"spiffe://prod.example.com/ns/agents/sa/coder","aud":"https://rp/api","iat":1,"exp":3600}"#,
        );
        let sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn inspect_accepts_literal_jwt_token() {
        let token = make_jwt();
        let args = InspectArgs { token, json: true };
        inspect(args).unwrap();
    }

    #[test]
    fn inspect_rejects_non_jwt_input() {
        let args = InspectArgs {
            token: "not-a-jwt-and-not-a-file".to_string(),
            json: true,
        };
        let err = inspect(args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("expected JWT") || msg.contains("reading token file"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn read_token_routes_jwt_string_to_literal_path() {
        let token = make_jwt();
        let result = read_token(&token).unwrap();
        assert_eq!(result, token);
    }

    #[test]
    fn mint_present_verify_return_v1_stub_errors() {
        // Stub message asserts: each command returns a clear "not implemented"
        // error with operator guidance — closes the user-feedback loop.
        let mint = execute(IdentityArgs {
            command: IdentityCommand::Mint(MintArgs {
                audience: "x".into(),
                out: PathBuf::from("/tmp/out"),
            }),
        });
        assert!(mint.unwrap_err().to_string().contains("not implemented"));

        let present = execute(IdentityArgs {
            command: IdentityCommand::Present(PresentArgs {
                token: PathBuf::from("/tmp/t"),
                op_url: "x".into(),
                audience: "y".into(),
            }),
        });
        assert!(present.unwrap_err().to_string().contains("not implemented"));

        let verify = execute(IdentityArgs {
            command: IdentityCommand::Verify(VerifyArgs {
                token: PathBuf::from("/tmp/t"),
                jwks: "x".into(),
            }),
        });
        assert!(verify.unwrap_err().to_string().contains("not implemented"));
    }
}
