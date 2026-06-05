//! `marketplace-live` — the nucleus marketplace dashboard with **REAL Base
//! Sepolia (testnet) settlement**. Small testnet funds move.
//!
//! One process serves the x402 seller route (`/paid`, IFC-pre-gated) + the
//! dashboard SSE API (`/api/*`) on one port, and drives the orchestrator whose
//! `X402Facilitator` pays that local route for real — each confirmed settlement
//! is a real Base Sepolia tx shown live with its on-chain hash.
//!
//! Secrets never touch argv: the signing key is in an encrypted keystore and its
//! password is resolved from the macOS Keychain / a no-echo prompt / a file /
//! env (in that order). See `crate::signer`.
//!
//! Run: `just marketplace-live --testnet` (requires a funded testnet keystore).

use std::sync::Arc;

use alloy_primitives::{address, Address};
use anyhow::{anyhow, Context};
use clap::Parser;
use tokio_util::sync::CancellationToken;

use marketplace_live::erc8004::IDENTITY_REGISTRY_BASE_SEPOLIA;
use marketplace_live::{seller_router, signer, AlloyAnchor, Anchorer, X402Facilitator};
use nucleus_marketplace_dashboard::{
    http, AgentId, AgentLoop, Facilitator, Hub, MarketEvent, MicroUsd, Orchestrator, SystemClock,
};
use nucleus_verify_commerce::{DeclaredInput, FlowDeclaration};

/// USDC on Base Sepolia (testnet). 6 decimals.
const USDC_BASE_SEPOLIA: Address = address!("036CbD53842c5426634e7929541eC2318f3dCF7e");
/// Refuse to start below this balance (0.01 USDC) so a drained wallet fails loud.
const BALANCE_FLOOR_MICROS: i64 = 10_000;

#[derive(Parser, Debug)]
#[command(about = "nucleus marketplace dashboard — REAL Base Sepolia testnet settlement")]
struct Args {
    /// Required acknowledgement that this spends real testnet funds.
    #[arg(long)]
    testnet: bool,
    /// Encrypted keystore path (foundry format). Password resolved securely.
    #[arg(long, default_value = "~/.foundry/keystores/nucleus-x402")]
    keystore: String,
    /// Base Sepolia JSON-RPC endpoint.
    #[arg(long, default_value = "https://sepolia.base.org")]
    rpc: String,
    /// Seller receiving address (payTo). Funds move here from the keystore wallet.
    #[arg(long, env = "SELLER_ADDRESS")]
    seller_address: String,
    /// x402 facilitator that settles on-chain.
    #[arg(long, default_value = "https://facilitator.x402.rs")]
    facilitator_url: String,
    /// Bind address for the seller route + dashboard API.
    #[arg(long, default_value = "127.0.0.1:4040")]
    bind: String,
    /// Price per call (USDC). Drives both the seller paywall and the agent fleet,
    /// so the dashboard amount equals the real settled amount.
    #[arg(long, default_value = "0.001")]
    price: String,
    /// Hard cap on confirmed settlements; the run stops after this many so the
    /// faucet wallet can't be drained.
    #[arg(long, default_value_t = 20)]
    max_settlements: u64,
    /// ERC-8004 ValidationRegistry address (self-deployed on Base Sepolia). When
    /// set, enables on-chain anchoring: agents are registered on the canonical
    /// Identity Registry and each verified receipt is anchored on the Validation
    /// Registry. These writes are GASFUL — the wallet also needs Base Sepolia ETH.
    #[arg(long)]
    validation_registry: Option<String>,
    /// Base URI for agent registration files (the on-chain agentURI per agent).
    #[arg(long, default_value = "https://marketplace.local/agents")]
    agent_uri_base: String,
}

fn expand_tilde(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) => format!("{home}/{rest}"),
            Err(_) => path.to_string(),
        },
        None => path.to_string(),
    }
}

fn price_to_micros(p: &str) -> anyhow::Result<i64> {
    let usd: f64 = p.parse().with_context(|| format!("parsing price `{p}`"))?;
    Ok((usd * 1_000_000.0).round() as i64)
}

/// A conservative real-settlement fleet: two SAFE agents on slow cadences (each
/// confirmed settlement is a real tx) + one compromised agent that the IFC gate
/// denies before any spend.
fn conservative_fleet(price: MicroUsd) -> Vec<AgentLoop> {
    vec![
        AgentLoop::new(
            "summarizer-agent",
            "/v1/summarize",
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]),
            price,
            15_000,
        ),
        AgentLoop::new(
            "research-agent",
            "/v1/research",
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]),
            price,
            23_000,
        ),
        AgentLoop::new(
            "compromised-agent",
            "/v1/exfiltrate",
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]),
            price,
            19_000,
        ),
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    eprintln!("┌────────────────────────────────────────────────────────────────┐");
    eprintln!("│  nucleus marketplace — REAL Base Sepolia TESTNET settlement     │");
    eprintln!("│  Small testnet funds WILL move. Never point this at mainnet.    │");
    eprintln!("└────────────────────────────────────────────────────────────────┘");
    if !args.testnet {
        eprintln!("refusing to run without --testnet (explicit acknowledgement that funds move).");
        std::process::exit(2);
    }

    let seller_addr: Address = args
        .seller_address
        .trim()
        .parse()
        .context("parsing --seller-address")?;
    let price_micros = price_to_micros(&args.price)?;
    let price = MicroUsd(price_micros);

    // Load the signer securely (password never on argv).
    eprintln!("loading keystore {} …", args.keystore);
    let signer = signer::load_keystore_signer(expand_tilde(&args.keystore))?;
    let payer = signer.address();
    // Same key signs x402 (gasless) and ERC-8004 writes (gasful); clone for the anchorer.
    let anchor_signer = signer.clone();

    let seller_base = format!("http://{}", args.bind);
    let facilitator = Arc::new(X402Facilitator::new(
        signer,
        &args.rpc,
        seller_base,
        USDC_BASE_SEPOLIA,
        payer,
    )?);

    // Pre-flight: show real money before anything settles; refuse if too low.
    let balance = facilitator
        .balance_of(&AgentId::from("payer"))
        .await
        .ok_or_else(|| anyhow!("could not read USDC balance from {}", args.rpc))?;
    eprintln!("payer wallet : {payer}");
    eprintln!(
        "USDC balance : {:.6} USDC  (floor {:.6})",
        balance.micros() as f64 / 1e6,
        BALANCE_FLOOR_MICROS as f64 / 1e6
    );
    if balance.micros() < BALANCE_FLOOR_MICROS {
        return Err(anyhow!(
            "balance below floor — fund {payer} with Base Sepolia bUSDC \
             (https://faucet.circle.com, select Base Sepolia) then retry"
        ));
    }
    eprintln!("seller payTo : {seller_addr}");
    eprintln!(
        "price/call   : {} USDC   max settlements: {}",
        args.price, args.max_settlements
    );

    // One port serves the x402 seller route + the dashboard API.
    let hub = Hub::new(Arc::new(SystemClock), 1_024, 500);
    let app = seller_router(seller_addr, &args.facilitator_url, &args.price)?
        .merge(http::router(Arc::clone(&hub)));
    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    println!("marketplace-live (REAL testnet) → http://{}", args.bind);
    println!("  dashboard API : http://{}/api/events", args.bind);

    let cancel = CancellationToken::new();
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move { cancel.cancelled().await })
                .await;
        }
    });

    // Drain cap: stop once the confirmed-settlement budget is spent.
    let cap_watch = tokio::spawn({
        let facilitator = Arc::clone(&facilitator);
        let cancel = cancel.clone();
        let max = args.max_settlements;
        async move {
            loop {
                if facilitator.confirmed_count() >= max {
                    eprintln!("reached --max-settlements ({max}); stopping.");
                    cancel.cancel();
                    break;
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                }
            }
        }
    });

    let fleet = conservative_fleet(price);

    // ERC-8004 anchoring (opt-in via --validation-registry). Registers each agent
    // on the canonical Identity Registry, then anchors each verified receipt on
    // the Validation Registry. GASFUL — needs Base Sepolia ETH.
    if let Some(vr) = &args.validation_registry {
        let validation: Address = vr.trim().parse().context("parsing --validation-registry")?;
        let anchorer = Arc::new(AlloyAnchor::new(
            anchor_signer,
            &args.rpc,
            IDENTITY_REGISTRY_BASE_SEPOLIA,
            validation,
        )?);
        eprintln!("ERC-8004 anchoring ENABLED");
        eprintln!("  Identity   : {IDENTITY_REGISTRY_BASE_SEPOLIA}");
        eprintln!("  Validation : {validation}");
        let mut ids = std::collections::HashMap::new();
        for a in &fleet {
            let uri = format!(
                "{}/{}",
                args.agent_uri_base.trim_end_matches('/'),
                a.agent.as_str()
            );
            let id = anchorer
                .register_agent(&uri)
                .await
                .with_context(|| format!("ERC-8004 register for {}", a.agent.as_str()))?;
            eprintln!("  registered {} → agentId {id}", a.agent.as_str());
            ids.insert(a.agent.as_str().to_string(), id);
        }
        let ids = Arc::new(ids);
        let base = format!("http://{}", args.bind);
        tokio::spawn({
            let hub = Arc::clone(&hub);
            let anchorer = Arc::clone(&anchorer);
            let ids = Arc::clone(&ids);
            let cancel = cancel.clone();
            async move {
                let mut rx = hub.subscribe();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        ev = rx.recv() => match ev {
                            Ok(MarketEvent::ReceiptVerified { for_settlement_id, agent, verified, .. }) if verified => {
                                let Some(&agent_id) = ids.get(agent.as_str()) else { continue };
                                let Some(receipt) = hub.receipt(for_settlement_id) else { continue };
                                let json = serde_json::to_string(&receipt).unwrap_or_default();
                                let uri = format!("{base}/api/receipt/{for_settlement_id}");
                                match anchorer.anchor(agent_id, &uri, &json, true).await {
                                    Ok(out) => {
                                        hub.emit(MarketEvent::ReceiptAnchored {
                                            id: 0,
                                            ts_unix_ms: 0,
                                            agent,
                                            for_settlement_id,
                                            agent_id,
                                            request_hash: out.request_hash,
                                            validation_tx: out.validation_tx,
                                            response: out.response,
                                        });
                                    }
                                    Err(e) => eprintln!("anchor failed (settlement {for_settlement_id}): {e:#}"),
                                }
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            Err(_) => {} // lagged — recover on the next event
                        }
                    }
                }
            }
        });
    } else {
        eprintln!("ERC-8004 anchoring disabled (no --validation-registry)");
    }

    let orchestrator = Arc::new(Orchestrator::new(Arc::clone(&hub), facilitator, fleet));
    let run = tokio::spawn({
        let orch = Arc::clone(&orchestrator);
        let cancel = cancel.clone();
        async move { orch.run(cancel).await }
    });

    // Ctrl-C → graceful shutdown.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { eprintln!("\nshutting down…"); cancel.cancel(); }
        _ = cancel.cancelled() => {}
    }

    let _ = tokio::join!(run, cap_watch, server);
    Ok(())
}
