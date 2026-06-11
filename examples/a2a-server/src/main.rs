//! Run the demo server:
//!
//! ```bash
//! cd examples/a2a-server && cargo run
//! ```
//!
//! It prints a ready-made `X-Agent-Card` header value for a demo caller, so
//! you can exercise the gate with curl:
//!
//! ```bash
//! curl -s http://localhost:3000/.well-known/agent-card.json | jq .securitySchemes
//! curl -si http://localhost:3000/jsonrpc -H "content-type: application/json" \
//!   -H "A2A-Version: 1.0" \
//!   -H "X-Agent-Card: <printed value>" \
//!   -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","messageId":"m1","parts":[{"text":"Agents need receipts. Trust needs proofs."}]}}}'
//! # → X-Nucleus-Receipt header (base64url bundle) AND the same bundle in
//! #   result.task.metadata["https://coproduct.one/a2a/ext/receipt/v1"];
//! #   omit A2A-Version to see the §3.6 -32009 VersionNotSupportedError
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_a2a_server_example::{build_app, ServerIdentity};
use nucleus_agent_card::{
    sign_card, AgentCapabilities, AgentCard, AgentInterface, JsonWebKey, NucleusClaims,
    A2A_PROTOCOL_VERSION,
};
use nucleus_lineage::{Jwks, LocalIssuer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = "http://localhost:3000";
    let identity = ServerIdentity::generate_demo(base)?;
    let receipt_jwks = serde_json::to_string(&identity.receipt_jwks)?;

    // A demo CALLER identity so the gate can be exercised immediately. In
    // production the operator resolves real caller keys out-of-band.
    let (caller_card_header, caller_verify_jwk) = demo_caller()?;

    println!("Summarizer Agent (nucleus-guarded) on {base}");
    println!("  card:      {base}/.well-known/agent-card.json");
    println!("  JSON-RPC:  {base}/jsonrpc   (requires X-Agent-Card + A2A-Version: 1.0)");
    println!("  REST:      {base}/rest      (requires X-Agent-Card + A2A-Version: 1.0)");
    println!();
    println!("receipts verify offline against this JWKS:");
    println!("  {receipt_jwks}");
    println!();
    println!("demo caller X-Agent-Card value:");
    println!("  {caller_card_header}");

    let app = build_app(identity, caller_verify_jwk);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// A throwaway caller: fresh P-256 key, signed v1.0 card with nucleus
/// claims. Returns (header value, public JWK the server trusts).
fn demo_caller() -> anyhow::Result<(String, JsonWebKey)> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|e| anyhow::anyhow!("generate caller key: {e}"))?;
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|e| anyhow::anyhow!("load caller key: {e}"))?;
    let pk = kp.public_key().as_ref();
    let jwk = JsonWebKey::ec_p256(
        URL_SAFE_NO_PAD.encode(&pk[1..33]),
        URL_SAFE_NO_PAD.encode(&pk[33..65]),
    );

    let trust_jwks: Jwks = serde_json::from_value(LocalIssuer::random()?.publish_jwks())?;
    let card = AgentCard {
        name: "Demo Caller".to_string(),
        description: "Throwaway caller identity for exercising the gate.".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://caller.example.com/a2a/v1".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            tenant: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "0.0.1".to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities::default(),
        security_schemes: serde_json::Map::new(),
        security_requirements: vec![],
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["text/plain".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    }
    .with_nucleus_claims(&NucleusClaims {
        spiffe_id: "spiffe://caller.example.com/ns/agents/sa/demo".to_string(),
        did: "did:web:caller.example.com".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks,
        runtime_guarantees: None,
    })?;
    let signed = sign_card(card, pkcs8.as_ref(), "demo-caller-key-1")?;
    Ok((serde_json::to_string(&signed)?, jwk))
}
