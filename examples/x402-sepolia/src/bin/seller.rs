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
async fn paid_handler(
    Extension(verdict): Extension<IfcVerdict>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let body = b"{\"summary\":\"<paid result>\"}";

    // The rail-side transaction reference, taken from the x402 payment the
    // middleware just accepted. If the header is missing or unparseable we say
    // so rather than inventing a reference — an attestation naming a
    // transaction that does not exist would be worse than no attestation.
    let tx_ref = headers
        .get("x-payment")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| nucleus_verify_commerce::x402::parse_payment_header(h).ok())
        .map(|p| p.reference)
        .unwrap_or_else(|| "<no x-payment header>".to_string());

    let payout_bundle = build_payout(&tx_ref);

    Json(serde_json::json!({
        "result": "paid result delivered",
        "body_sha256": body_sha256_hex(body),
        "ifc_verdict": verdict,
        "payout": payout_bundle,
    }))
}

/// Build the recompute-verifiable payout for one paid call, plus the settlement
/// attestation that says it was paid.
///
/// The buyer does not have to trust any of this: `verify_payout` re-derives the
/// split from the proven kernels, and `verify_settlement_set` checks every payee
/// was discharged exactly once. A seller that quietly reweighted the split, or
/// paid two of three payees, is caught client-side.
///
/// The split below is a DEMO constant. A real deployment reads it from the offer
/// the buyer accepted — that is slice S3, and pretending otherwise here would
/// make the example claim more than it does.
fn build_payout(tx_ref: &str) -> serde_json::Value {
    use nucleus_econ_kernels::commons::CommonsShare;
    use nucleus_recompute::payout::{issue_payout, Attribution};
    use nucleus_recompute::settlement_attestation::{
        issue_settlement_attestation, verify_settlement_set,
    };
    use nucleus_recompute::{issue_settlement, verify_receipt};

    // Price in micro-USD. The demo price is 0.01 USDC; delivery is full, so the
    // whole price is distributable.
    let price_micro: u64 = std::env::var("PRICE_USDC")
        .ok()
        .and_then(|p| p.parse::<f64>().ok())
        .map(|usd| (usd * 1_000_000.0) as u64)
        .unwrap_or(10_000);

    let clearing = issue_settlement(price_micro, 10_000);
    let shares = vec![
        CommonsShare {
            destination: "seller".into(),
            bps: 7_000,
        },
        CommonsShare {
            destination: "runtime".into(),
            bps: 2_500,
        },
        CommonsShare {
            destination: "commons".into(),
            bps: 500,
        },
    ];
    let attribution = Attribution {
        workload_spiffe_id: "spiffe://nucleus.local/example/x402-seller".into(),
        assurance: 0, // demo: no attestation backend wired, and it says so
        offer_hash_hex: String::new(),
        disclosure_hash_hex: String::new(),
    };

    let Ok(payout) = issue_payout(clearing.clone(), shares, attribution) else {
        return serde_json::json!({ "error": "payout could not be issued" });
    };

    let attestations: Vec<_> = payout
        .allocations
        .iter()
        .filter_map(|a| issue_settlement_attestation(&payout, &a.destination, "x402-evm", tx_ref))
        .collect();

    // Self-check before serving: never hand a buyer a receipt this seller has
    // not itself verified.
    let clearing_ok = verify_receipt(&clearing).is_match();
    let set = verify_settlement_set(&attestations, &payout);

    serde_json::json!({
        "payout": payout,
        "settlements": attestations,
        "self_check": {
            "clearing_recomputes": clearing_ok,
            "settlement_set": format!("{set:?}"),
        },
        "how_to_verify": "POST {receipt, verifying_key_hex} to /v1/payout/verify, \
                          or run verifySignedPayout() in the browser — neither trusts this seller",
    })
}
