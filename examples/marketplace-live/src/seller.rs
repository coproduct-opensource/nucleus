//! The local x402 seller route the [`crate::X402Facilitator`] pays — the same
//! pattern as `examples/x402-sepolia` (x402 paywall + nucleus IFC pre-gate),
//! exposed as a `Router` so the binary can merge it with the dashboard API on one
//! port. The IFC gate runs BEFORE the x402 payment layer, so an unsafe declared
//! flow is refused with `403` and never charged.

use alloy_primitives::Address;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Extension, Json, Router};
use x402_axum::X402Middleware;
use x402_chain_eip155::{KnownNetworkEip155, V1Eip155Exact};
use x402_types::networks::USDC;

use nucleus_verify_commerce::{body_sha256_hex, DeclaredInput, FlowDeclaration, IfcVerdict};

/// Build the x402 seller router: `GET /paid`, priced in Base Sepolia USDC, paid
/// to `seller`, gated by the nucleus IFC pre-gate (safe flow → ALLOW).
pub fn seller_router(
    seller: Address,
    facilitator_url: &str,
    price_usdc: &str,
) -> anyhow::Result<Router> {
    let tag = V1Eip155Exact::price_tag(seller, USDC::base_sepolia().parse(price_usdc)?);
    let paywall = X402Middleware::new(facilitator_url).with_price_tag(tag);
    let safe_decl = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]);
    Ok(Router::new()
        .route("/paid", get(paid_handler).layer(paywall))
        .layer(from_fn_with_state(safe_decl, ifc_pregate)))
}

/// The IFC pre-gate — runs before the x402 payment layer; deny ⇒ `403`, no charge.
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
                "ifc_verdict": verdict,
            })),
        )
            .into_response();
    }
    req.extensions_mut().insert(verdict);
    next.run(req).await
}

/// The paid work (x402 has verified payment; the IFC gate allowed + stashed the
/// verdict). Echoes the result + verdict.
async fn paid_handler(Extension(verdict): Extension<IfcVerdict>) -> Json<serde_json::Value> {
    let body = b"{\"summary\":\"<paid result>\"}";
    Json(serde_json::json!({
        "result": "paid result delivered",
        "body_sha256": body_sha256_hex(body),
        "ifc_verdict": verdict,
    }))
}
