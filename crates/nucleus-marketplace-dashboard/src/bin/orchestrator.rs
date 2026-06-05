//! The live marketplace orchestrator binary — **SIMULATED settlement**.
//!
//! This binary runs the agent fleet against the deterministic
//! [`FakeFacilitator`]: every settlement is simulated (tagged
//! `BalanceSource::Simulated`, with a `0xsimulated…` reference) — NO real funds
//! move. It exists to drive the live SSE feed for frontend development and a
//! safe, repeatable demo.
//!
//! The REAL Base Sepolia (testnet) settlement path lives in a separate workspace
//! under `examples/` (keystore-backed signer over `x402-reqwest`), so the heavy
//! alloy/x402 tree never enters this crate or the main CI.
//!
//! Run: `BIND=127.0.0.1:4040 cargo run -p nucleus-marketplace-dashboard --bin marketplace-orchestrator`

use std::sync::Arc;

use nucleus_marketplace_dashboard::{
    http, AgentLoop, FakeFacilitator, Hub, MicroUsd, Orchestrator, SystemClock,
};
use nucleus_verify_commerce::{DeclaredInput, FlowDeclaration};
use tokio_util::sync::CancellationToken;

/// A small, readable fleet: four agents whose declared flows are SAFE (the gate
/// ALLOWS) plus one "compromised" agent whose flow pulls in adversarial web
/// content (the gate DENIES) on a slower cadence — the periodic red accent.
fn default_fleet() -> Vec<AgentLoop> {
    let usdc = |x: i64| MicroUsd(x);
    vec![
        AgentLoop::new(
            "summarizer-agent",
            "/v1/summarize",
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]),
            usdc(10_000),
            1_700,
        ),
        AgentLoop::new(
            "pricing-agent",
            "/v1/price-quote",
            FlowDeclaration::new([DeclaredInput::DatabaseRow]),
            usdc(20_000),
            2_300,
        ),
        AgentLoop::new(
            "qa-agent",
            "/v1/answer",
            FlowDeclaration::new([DeclaredInput::UserPrompt]),
            usdc(5_000),
            1_300,
        ),
        AgentLoop::new(
            "research-agent",
            "/v1/research",
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]),
            usdc(15_000),
            1_900,
        ),
        // Compromised: a paid call whose ancestry includes adversarial web
        // content reaching an outbound action — the lethal trifecta. DENIED.
        AgentLoop::new(
            "compromised-agent",
            "/v1/exfiltrate",
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]),
            usdc(10_000),
            5_000,
        ),
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("┌────────────────────────────────────────────────────────────────┐");
    eprintln!("│  nucleus marketplace dashboard — SIMULATED SETTLEMENT           │");
    eprintln!("│  No real funds move. Balances are tagged `simulated`.           │");
    eprintln!("│  Real Base Sepolia settlement lives in examples/ (separate WS). │");
    eprintln!("└────────────────────────────────────────────────────────────────┘");

    let hub = Hub::new(Arc::new(SystemClock), 1_024, 500);
    let facilitator = Arc::new(FakeFacilitator::always_confirm(MicroUsd(20_000_000)));
    let orchestrator = Arc::new(Orchestrator::new(
        Arc::clone(&hub),
        facilitator,
        default_fleet(),
    ));

    let cancel = CancellationToken::new();
    let run_handle = tokio::spawn({
        let orch = Arc::clone(&orchestrator);
        let cancel = cancel.clone();
        async move { orch.run(cancel).await }
    });

    let app = http::router(Arc::clone(&hub));
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:4040".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("marketplace dashboard (SIMULATED) → http://{bind}");
    println!("  GET /api/events    (SSE live feed)");
    println!("  GET /api/snapshot  (cold-start state)");
    println!("  GET /api/receipt/{{settlement_id}}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancel.cancel();
        })
        .await?;

    run_handle.abort();
    Ok(())
}
