//! End-to-end QuickStart: verify a buyer agent, serve a paid request, and
//! issue a receipt the buyer can independently verify.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p nucleus-verify-commerce --example quickstart
//! ```
//!
//! This example uses the TEST-ONLY `insecure-local-issuer` signer (a dev-dep) to
//! keep it self-contained. A production seller injects a real `EdgeSigner`
//! (e.g. SPIFFE-Workload-API-backed) and publishes the matching JWKS
//! out-of-band; the buyer resolves the seller's JWKS the same way.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_agent_card::{sign_card, AgentCard, JsonWebKey};
use nucleus_envelope::{Bundle, TrustAnchor};
use nucleus_lineage::{CallSpiffeId, Jwks, LocalIssuer};
use nucleus_verify_commerce::{
    serve_verified, verify_receipt_bundle, AgentCardVerifier, CallerClaims, CommerceRequest,
    EnvelopeReceiptIssuer, PaymentProof,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Buyer side: a signed Agent Card asserts the buyer's identity ──────────
    // The buyer holds a P-256 key; the seller resolves the matching public key
    // out-of-band (here we just hand it over).
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("generate P-256 key");
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("load P-256 key");
    let pk = kp.public_key().as_ref();
    let buyer_pub_jwk = JsonWebKey::ec_p256(
        URL_SAFE_NO_PAD.encode(&pk[1..33]),
        URL_SAFE_NO_PAD.encode(&pk[33..65]),
    );

    let buyer_trust_jwks: Jwks = serde_json::from_value(LocalIssuer::random()?.publish_jwks())?;
    let buyer_card = AgentCard {
        spiffe_id: "spiffe://buyer.example.com/ns/agents/sa/shopper".to_string(),
        did: "did:web:shopper.buyer.example.com".to_string(),
        security_schemes: serde_json::json!({}),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: buyer_trust_jwks,
        runtime_guarantees: None,
    };
    let signed_card = sign_card(buyer_card, pkcs8.as_ref())?;

    // ── Seller side: signing identity + published JWKS (production: real signer)
    let seller_signer = LocalIssuer::random()?;
    let seller_jwks: Jwks = serde_json::from_value(seller_signer.publish_jwks())?;
    let seller_root = CallSpiffeId::pod("seller.example.com", "agents", "commerce")?;

    let verifier = AgentCardVerifier::new(buyer_pub_jwk);
    let issuer = EnvelopeReceiptIssuer::new(seller_root, &seller_signer, seller_jwks.clone());

    // ── The incoming paid request (transport mapped into CommerceRequest) ─────
    let request = CommerceRequest::new(
        "/v1/summarize",
        CallerClaims {
            agent_id: "did:web:shopper.buyer.example.com".to_string(),
            credential: serde_json::to_string(&signed_card)?,
        },
        PaymentProof {
            scheme: "x402".to_string(),
            reference: "0xpay_demo_123".to_string(),
        },
    );

    // ── verify → serve → receipt ──────────────────────────────────────────────
    let runtime = tokio_rt();
    let (body, receipt) = runtime.block_on(serve_verified(
        &request,
        &verifier,
        &issuer,
        |caller, req| {
            let who = caller.spiffe_id.clone();
            let what = req.resource.clone();
            async move { Ok(format!("[summary of {what} for verified caller {who}]").into_bytes()) }
        },
    ))?;

    println!("Served {} bytes to a verified caller.", body.len());
    println!("Receipt:");
    println!("  resource          = {}", receipt.resource);
    println!("  caller_spiffe_id  = {}", receipt.caller_spiffe_id);
    println!("  payment_reference = {}", receipt.payment_reference);
    println!("  body_sha256       = {}", receipt.body_sha256);

    // ── Buyer (or anyone) independently verifies the receipt ──────────────────
    let bundle: Bundle = serde_json::from_value(receipt.bundle.clone().expect("envelope receipt"))?;
    let verified = verify_receipt_bundle(&bundle, &TrustAnchor::from_jwks(seller_jwks))?;
    println!(
        "\nIndependently verified against the seller's JWKS:\n  {} paid {} for {} (body {})",
        verified.caller_spiffe_id,
        verified.payment_reference,
        verified.resource,
        verified.body_sha256
    );

    Ok(())
}

/// Minimal current-thread Tokio runtime for the example.
fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
}
