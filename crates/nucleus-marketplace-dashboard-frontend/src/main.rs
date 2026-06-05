//! Leptos CSR activity-feed for the nucleus verified-agent marketplace.
//!
//! Subscribes to the orchestrator's `/api/events` SSE stream (reconnect handled
//! by `leptos-use`), folds each event through the SAME `MarketState::apply`
//! reducer the backend uses (shared verbatim), and renders a live feed + KPI
//! strip + per-agent panel. The deny is the visual peak (red flash). Money
//! numbers always carry their source badge — simulated can never look real.

use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_use::core::ConnectionReadyState;
use leptos_use::{
    use_event_source_with_options, ReconnectLimit, UseEventSourceOptions, UseEventSourceReturn,
};

use nucleus_marketplace_dashboard::{
    AgentSummary, BalanceSource, ClearingMethod, Lane, MarketEvent, MarketState,
};

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

/// Format micro-USD as a USDC string.
fn usdc(micros: i64) -> String {
    format!("{:.4}", micros as f64 / 1_000_000.0)
}

fn lane_class(l: Lane) -> &'static str {
    match l {
        Lane::Commerce => "lane lane-commerce",
        Lane::Security => "lane lane-security",
        Lane::Trust => "lane lane-trust",
        Lane::Proof => "lane lane-proof",
    }
}

fn source_label(s: &BalanceSource) -> &'static str {
    match s {
        BalanceSource::Simulated => "simulated",
        BalanceSource::OnChainTestnet => "testnet",
    }
}

fn short(s: &str) -> String {
    if s.len() <= 14 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..8], &s[s.len() - 4..])
    }
}

/// (chip label, chip class, detail) for one event.
fn describe(ev: &MarketEvent) -> (String, &'static str, String) {
    match ev {
        MarketEvent::AgentRegistered {
            resource,
            declared_inputs,
            ..
        } => (
            "registered".into(),
            "chip chip-trust",
            format!("{resource}  ·  [{}]", declared_inputs.join(", ")),
        ),
        MarketEvent::CallStarted {
            resource, attempt, ..
        } => (
            "call".into(),
            "chip chip-commerce",
            format!("{resource}  #{attempt}"),
        ),
        MarketEvent::IfcAllow { .. } => (
            "ALLOW".into(),
            "chip chip-ok",
            "in-bounds flow — payment may proceed".into(),
        ),
        MarketEvent::IfcDeny {
            reason,
            declared_inputs,
            ..
        } => (
            "DENY".into(),
            "chip chip-error",
            format!("{reason}  ·  [{}]", declared_inputs.join(", ")),
        ),
        MarketEvent::Settlement {
            amount,
            cleared_method,
            externality,
            outcome,
            source,
            ..
        } => {
            let st = match outcome {
                nucleus_marketplace_dashboard::SettlementOutcome::Confirmed { tx_hash } => {
                    format!("confirmed {}", short(tx_hash))
                }
                nucleus_marketplace_dashboard::SettlementOutcome::Timeout => "timeout".into(),
                nucleus_marketplace_dashboard::SettlementOutcome::Orphaned => "orphaned".into(),
            };
            let method = match cleared_method {
                ClearingMethod::FixedPrice => "fixed".to_string(),
                ClearingMethod::Pigouvian => format!("pigou +{}", usdc(externality.micros())),
                ClearingMethod::Vcg => format!("vcg +{}", usdc(externality.micros())),
            };
            (
                format!("settle {}", usdc(amount.micros())),
                "chip chip-commerce",
                format!("{st}  ·  {}  ·  {method}", source_label(source)),
            )
        }
        MarketEvent::ReceiptVerified {
            verified,
            body_sha256,
            ..
        } => (
            if *verified {
                "receipt ✓"
            } else {
                "receipt ✗"
            }
            .into(),
            "chip chip-proof",
            format!("sha256 {}", &body_sha256[..body_sha256.len().min(16)]),
        ),
        MarketEvent::BalanceUpdate {
            balance, source, ..
        } => (
            "balance".into(),
            "chip chip-commerce",
            format!(
                "{} USDC  ·  {}",
                usdc(balance.micros()),
                source_label(source)
            ),
        ),
    }
}

#[component]
fn App() -> impl IntoView {
    // Client-side state, folded by the SAME reducer the backend uses.
    let state = RwSignal::new(MarketState::with_cap(300));

    // Cold start: hydrate from the snapshot, then apply the live stream on top.
    spawn_local(async move {
        if let Ok(resp) = gloo_net::http::Request::get("/api/snapshot").send().await {
            if let Ok(snap) = resp.json::<MarketState>().await {
                state.set(snap);
            }
        }
    });

    let UseEventSourceReturn {
        message,
        ready_state,
        ..
    } = use_event_source_with_options::<MarketEvent, JsonSerdeCodec>(
        "/api/events",
        UseEventSourceOptions::default()
            .reconnect_limit(ReconnectLimit::Infinite)
            .reconnect_interval(2_000),
    );

    // Dedup against the snapshot/replay overlap: only apply strictly-newer ids.
    Effect::new(move |_| {
        if let Some(msg) = message.get() {
            let ev = msg.data;
            state.update(|s| {
                if ev.id() > s.last_id {
                    s.apply(&ev);
                }
            });
        }
    });

    let conn = move || match ready_state.get() {
        ConnectionReadyState::Open => ("● live", "chip chip-ok"),
        ConnectionReadyState::Connecting => ("● connecting", "chip chip-warn"),
        ConnectionReadyState::Closing => ("● closing", "chip chip-warn"),
        ConnectionReadyState::Closed => ("● offline", "chip chip-error"),
    };

    // Newest-first feed.
    let recent = move || {
        let mut v: Vec<MarketEvent> = state.get().recent.iter().cloned().collect();
        v.reverse();
        v
    };
    let agents = move || state.get().agents.into_iter().collect::<Vec<_>>();

    view! {
        <div class="app">
            <header class="topbar">
                <h1>"nucleus " <span class="accent">"verified marketplace"</span></h1>
                <div class="conn">
                    {move || { let (l, c) = conn(); view! { <span class=c>{l}</span> } }}
                </div>
            </header>

            <div class="sim-banner">
                "SIMULATED settlement (testnet model). Balances are tagged "
                <code>"simulated"</code>" — no real funds move. Real Base Sepolia settlement runs from the example workspace."
            </div>

            <section class="kpis">
                <div class="kpi kpi-ok">
                    <div class="kpi-val">{move || state.get().allow_count}</div>
                    <div class="kpi-label">"IFC allowed"</div>
                </div>
                <div class="kpi kpi-deny">
                    <div class="kpi-val">{move || state.get().deny_count}</div>
                    <div class="kpi-label">"IFC denied (before payment)"</div>
                </div>
                <div class="kpi kpi-proof">
                    <div class="kpi-val">{move || state.get().receipts_verified}</div>
                    <div class="kpi-label">"receipts verified"</div>
                </div>
                <div class="kpi kpi-commerce">
                    <div class="kpi-val">{move || usdc(state.get().simulated_settled_micros)}</div>
                    <div class="kpi-label">"settled (sim USDC)"</div>
                </div>
            </section>

            <div class="cols">
                <section class="feed">
                    <h2>"activity"</h2>
                    <ul>
                        <For
                            each=recent
                            key=|e| e.id()
                            children=move |e: MarketEvent| {
                                let (label, chip, detail) = describe(&e);
                                let lane = lane_class(e.lane());
                                let row = if e.is_peak() { "row peak" } else { "row" };
                                let agent = e.agent().as_str().to_string();
                                view! {
                                    <li class=row>
                                        <span class=lane></span>
                                        <span class=chip>{label}</span>
                                        <span class="agent">{agent}</span>
                                        <span class="detail">{detail}</span>
                                    </li>
                                }
                            }
                        />
                    </ul>
                </section>

                <section class="agents">
                    <h2>"agents"</h2>
                    <ul>
                        <For
                            each=agents
                            key=|(id, _)| id.clone()
                            children=move |(id, sum): (String, AgentSummary)| {
                                let bal = sum
                                    .balance
                                    .map(|b| usdc(b.micros()))
                                    .unwrap_or_else(|| "—".into());
                                let src = sum.balance_source.as_ref().map(source_label).unwrap_or("");
                                let src_cls = match sum.balance_source {
                                    Some(BalanceSource::OnChainTestnet) => "src testnet",
                                    _ => "src",
                                };
                                view! {
                                    <li>
                                        <span class="agent">{id}</span>
                                        <span class="bal">
                                            {bal} " USDC" <span class=src_cls>{src}</span>
                                        </span>
                                        <span class="counts">
                                            {sum.allows} " ✓ / " {sum.denies} " ✕"
                                        </span>
                                    </li>
                                }
                            }
                        />
                    </ul>
                </section>
            </div>
        </div>
    }
}
