//! x402 seller on **Base Sepolia (testnet)** with the nucleus IFC gate in
//! front of the x402 payment layer.
//!
//! Testnet only. Reads config from env; no keys are stored here:
//! - `SELLER_ADDRESS`   — Base Sepolia address that receives the USDC (required)
//! - `FACILITATOR_URL`  — x402 facilitator (default: https://facilitator.x402.rs)
//! - `PRICE_USDC`       — price per call (default: 0.01)
//! - `BIND`             — listen address (default: 0.0.0.0:4021)
//!
//! Two paid routes share one price and one IFC pre-gate, differing only in the
//! data-flow they declare:
//!
//! - `GET /paid`         declares a **safe** flow (trusted prompt + local DB
//!   row). The gate ALLOWS → x402 collects payment → the handler serves the
//!   result + the (allow) verdict.
//! - `GET /paid-unsafe`  declares an **unsafe** flow (trusted prompt +
//!   adversarial **web content** — the indirect prompt-injection vector reaching
//!   an outbound action). The gate DENIES → it returns `403` **before** the
//!   x402 layer runs, so the buyer is **never charged**.
//!
//! That ordering is the point: the gate refuses dangerous flows *before money
//! moves*. The decision is model-level over the **declared** inputs (a real
//! deployment derives the declaration from the request); see
//! `crates/nucleus-verify-commerce`.

use std::str::FromStr;

use alloy_primitives::Address;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Extension, Json, Router};
use x402_axum::X402Middleware;
// `KnownNetworkEip155` is the trait that provides `USDC::base_sepolia()`.
use x402_chain_eip155::{KnownNetworkEip155, V1Eip155Exact};
use x402_types::networks::USDC;

use nucleus_verify_commerce::{body_sha256_hex, DeclaredInput, FlowDeclaration, IfcVerdict};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seller = std::env::var("SELLER_ADDRESS")
        .map_err(|_| anyhow::anyhow!("set SELLER_ADDRESS (your Base Sepolia receiving address)"))?;
    let seller: Address = Address::from_str(seller.trim())?;
    let facilitator =
        std::env::var("FACILITATOR_URL").unwrap_or_else(|_| "https://facilitator.x402.rs".into());
    let price = std::env::var("PRICE_USDC").unwrap_or_else(|_| "0.01".into());
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:4021".into());

    // Same price + recipient on both routes; a fresh `X402Middleware` /
    // `price_tag` per route since the layer consumes them.
    let make_paywall = || -> anyhow::Result<_> {
        let tag = V1Eip155Exact::price_tag(seller, USDC::base_sepolia().parse(price.as_str())?);
        Ok(X402Middleware::new(&facilitator).with_price_tag(tag))
    };

    // Safe flow: trusted prompt + internal DB row → ALLOW.
    let safe_decl = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]);
    let safe_route = Router::new()
        .route("/paid", get(paid_handler).layer(make_paywall()?))
        .layer(from_fn_with_state(safe_decl, ifc_pregate));

    // Unsafe flow: trusted prompt + adversarial web content reaching an
    // outbound action (the lethal trifecta) → DENY before payment.
    let unsafe_decl = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]);
    let unsafe_route = Router::new()
        .route("/paid-unsafe", get(paid_handler).layer(make_paywall()?))
        .layer(from_fn_with_state(unsafe_decl, ifc_pregate));

    let app: Router = safe_route.merge(unsafe_route);

    println!("x402 seller on Base Sepolia (TESTNET)");
    println!("  receive USDC → {seller}");
    println!("  facilitator   = {facilitator}");
    println!("  price         = {price} USDC");
    println!("  GET /paid         safe flow   → IFC ALLOW → pay → result");
    println!("  GET /paid-unsafe  unsafe flow → IFC DENY  → 403 (NOT charged)");
    println!("  listening     = http://{bind}");

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// The nucleus IFC pre-gate. Runs **before** the x402 payment layer: it makes
/// the model-level information-flow decision over this route's declared inputs
/// and, on a deny, short-circuits with `403` so the payment layer never runs and
/// the buyer is never charged. On an allow it stashes the verdict for the
/// handler to fold into its response.
async fn ifc_pregate(
    State(decl): State<FlowDeclaration>,
    mut req: Request,
    next: Next,
) -> Response {
    let verdict = decl.decide();
    if !verdict.is_allow() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "ifc_denied",
                "detail": "the declared data-flow for this call would exfiltrate; \
                           refused by the nucleus IFC gate BEFORE payment — you were not charged",
                "ifc_verdict": verdict,
            })),
        )
            .into_response();
    }
    req.extensions_mut().insert(verdict);
    next.run(req).await
}

/// The paid work. By the time we get here the IFC gate has ALLOWED (and stashed
/// the verdict) and x402 has verified payment. We echo the result + the verdict
/// the gate made the call under.
async fn paid_handler(Extension(verdict): Extension<IfcVerdict>) -> Json<serde_json::Value> {
    let body = b"{\"summary\":\"<paid result>\"}";
    Json(serde_json::json!({
        "result": "paid result delivered",
        "body_sha256": body_sha256_hex(body),
        "ifc_verdict": verdict,
    }))
}
