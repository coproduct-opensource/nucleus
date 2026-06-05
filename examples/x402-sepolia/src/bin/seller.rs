//! x402 seller on **Base Sepolia (testnet)** with the nucleus IFC gate +
//! receipt on the paid route.
//!
//! Testnet only. Reads config from env; no keys are stored here:
//! - `SELLER_ADDRESS`   — Base Sepolia address that receives the USDC (required)
//! - `FACILITATOR_URL`  — x402 facilitator (default: https://facilitator.x402.rs)
//! - `PRICE_USDC`       — price per call (default: 0.01)
//! - `BIND`             — listen address (default: 0.0.0.0:4021)
//!
//! `GET /paid` is x402-protected. After payment, the handler runs the nucleus
//! model-level IFC decision over the call's declared data-flow and returns the
//! result alongside the (allow) verdict — so a paid call is *also* gated on an
//! information-flow check. See `crates/nucleus-verify-commerce`.

use std::str::FromStr;

use alloy_primitives::Address;
use axum::{routing::get, Json, Router};
use x402_axum::X402Middleware;
// `KnownNetworkEip155` is the trait that provides `USDC::base_sepolia()`.
use x402_chain_eip155::{KnownNetworkEip155, V1Eip155Exact};
use x402_types::networks::USDC;

use nucleus_verify_commerce::{body_sha256_hex, DeclaredInput, FlowDeclaration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seller = std::env::var("SELLER_ADDRESS")
        .map_err(|_| anyhow::anyhow!("set SELLER_ADDRESS (your Base Sepolia receiving address)"))?;
    let seller: Address = Address::from_str(seller.trim())?;
    let facilitator =
        std::env::var("FACILITATOR_URL").unwrap_or_else(|_| "https://facilitator.x402.rs".into());
    let price = std::env::var("PRICE_USDC").unwrap_or_else(|_| "0.01".into());
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:4021".into());

    let x402 = X402Middleware::new(&facilitator);
    let price_tag =
        V1Eip155Exact::price_tag(seller, USDC::base_sepolia().parse(price.as_str())?);

    let app: Router = Router::new().route(
        "/paid",
        get(paid_handler).layer(x402.with_price_tag(price_tag)),
    );

    println!("x402 seller on Base Sepolia (TESTNET)");
    println!("  receive USDC → {seller}");
    println!("  facilitator   = {facilitator}");
    println!("  price         = {price} USDC  on  GET /paid");
    println!("  listening     = http://{bind}/paid");
    println!("  (the paid route is also IFC-gated by nucleus-verify-commerce)");

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// The paid work. x402 has already verified payment by the time we get here;
/// we then run the nucleus IFC gate over the call's declared data-flow and
/// fold the verdict into the response.
async fn paid_handler() -> Json<serde_json::Value> {
    // Declared data-flow for this paid call: a trusted prompt + a local DB row,
    // served to the authenticated buyer. (A real deployment derives this from
    // the request; an untrusted-content input here would DENY before serving.)
    let verdict = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow])
        .decide();

    let body = b"{\"summary\":\"<paid result>\"}";
    Json(serde_json::json!({
        "result": "paid result delivered",
        "body_sha256": body_sha256_hex(body),
        "ifc_verdict": verdict,
    }))
}
