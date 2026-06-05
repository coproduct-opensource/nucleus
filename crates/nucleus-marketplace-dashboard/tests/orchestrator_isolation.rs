//! The load-bearing milestone: the orchestrator + event model proven IN
//! ISOLATION — deterministic, no network, no alloy (FakeFacilitator + FixedClock).

use std::sync::Arc;

use nucleus_marketplace_dashboard::{
    FakeFacilitator, FixedClock, Hub, MarketEvent, MicroUsd, Orchestrator, SettlementOutcome,
};
use nucleus_verify_commerce::{DeclaredInput, FlowDeclaration};

fn agent(
    id: &str,
    inputs: impl IntoIterator<Item = DeclaredInput>,
) -> nucleus_marketplace_dashboard::AgentLoop {
    nucleus_marketplace_dashboard::AgentLoop::new(
        id,
        "/v1/summarize",
        FlowDeclaration::new(inputs),
        MicroUsd(10_000),
        1000,
    )
}

/// Variant tags of the events in the hub's snapshot, in order.
fn tags(hub: &Hub) -> Vec<&'static str> {
    hub.snapshot()
        .recent
        .iter()
        .map(|e| match e {
            MarketEvent::AgentRegistered { .. } => "agent_registered",
            MarketEvent::CallStarted { .. } => "call_started",
            MarketEvent::IfcAllow { .. } => "ifc_allow",
            MarketEvent::IfcDeny { .. } => "ifc_deny",
            MarketEvent::Settlement { .. } => "settlement",
            MarketEvent::ReceiptVerified { .. } => "receipt_verified",
            MarketEvent::BalanceUpdate { .. } => "balance_update",
            MarketEvent::ReceiptAnchored { .. } => "receipt_anchored",
        })
        .collect()
}

#[tokio::test]
async fn allow_path_emits_full_sequence() {
    let hub = Hub::new(Arc::new(FixedClock::new(1000)), 64, 64);
    let fac = Arc::new(FakeFacilitator::always_confirm(MicroUsd(20_000_000)));
    let orch = Orchestrator::new(
        Arc::clone(&hub),
        Arc::clone(&fac),
        // safe flow: trusted prompt + internal DB row → ALLOW
        vec![agent(
            "agent-a",
            [DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow],
        )],
    );

    orch.step_once(0, 1).await;

    assert_eq!(
        tags(&hub),
        vec![
            "call_started",
            "ifc_allow",
            "settlement",
            "receipt_verified",
            "balance_update",
        ]
    );
    let snap = hub.snapshot();
    assert_eq!(snap.allow_count, 1);
    assert_eq!(snap.deny_count, 0);
    assert_eq!(snap.receipts_verified, 1);
    assert_eq!(snap.simulated_settled_micros, 10_000);
    assert_eq!(snap.onchain_settled_micros, 0); // honesty: nothing on-chain
    assert_eq!(fac.settle_calls(), 1);
    assert_eq!(
        snap.agents["agent-a"].balance,
        Some(MicroUsd(20_000_000 - 10_000))
    );
}

#[tokio::test]
async fn deny_path_stops_before_settlement() {
    let hub = Hub::new(Arc::new(FixedClock::new(1000)), 64, 64);
    let fac = Arc::new(FakeFacilitator::always_confirm(MicroUsd(20_000_000)));
    let orch = Orchestrator::new(
        Arc::clone(&hub),
        Arc::clone(&fac),
        // unsafe flow: trusted prompt + adversarial web content → DENY
        vec![agent(
            "agent-x",
            [DeclaredInput::UserPrompt, DeclaredInput::WebContent],
        )],
    );

    orch.step_once(0, 1).await;

    // The seller.rs ordering guarantee, proven in isolation: nothing after IfcDeny.
    assert_eq!(tags(&hub), vec!["call_started", "ifc_deny"]);
    assert_eq!(
        fac.settle_calls(),
        0,
        "settlement must NEVER be attempted on a denied flow"
    );
    let snap = hub.snapshot();
    assert_eq!(snap.deny_count, 1);
    assert_eq!(snap.simulated_settled_micros, 0);
}

#[tokio::test]
async fn timeout_path_yields_no_receipt_and_no_resettle() {
    let hub = Hub::new(Arc::new(FixedClock::new(1000)), 64, 64);
    let fac = Arc::new(FakeFacilitator::scripted(
        MicroUsd(20_000_000),
        [SettlementOutcome::Timeout],
        SettlementOutcome::Timeout,
    ));
    let orch = Orchestrator::new(
        Arc::clone(&hub),
        Arc::clone(&fac),
        vec![agent("agent-a", [DeclaredInput::UserPrompt])],
    );

    orch.step_once(0, 1).await;

    // Allowed, settlement attempted once, timed out → no receipt, no balance,
    // and crucially the iteration does NOT re-settle (double-spend trap avoided).
    assert_eq!(tags(&hub), vec!["call_started", "ifc_allow", "settlement"]);
    assert_eq!(fac.settle_calls(), 1);
    let snap = hub.snapshot();
    assert_eq!(snap.receipts_verified, 0);
    assert_eq!(snap.simulated_settled_micros, 0);
}

#[tokio::test]
async fn whole_core_is_reproducible_with_no_network() {
    // Two identical runs (FixedClock + scripted FakeFacilitator) produce
    // byte-identical event JSON — the entire core is deterministic.
    async fn run() -> String {
        let hub = Hub::new(Arc::new(FixedClock::new(42)), 128, 128);
        let fac = Arc::new(FakeFacilitator::scripted(
            MicroUsd(20_000_000),
            [
                SettlementOutcome::Confirmed {
                    tx_hash: String::new(),
                },
                SettlementOutcome::Confirmed {
                    tx_hash: String::new(),
                },
            ],
            SettlementOutcome::Confirmed {
                tx_hash: String::new(),
            },
        ));
        let orch = Orchestrator::new(
            Arc::clone(&hub),
            fac,
            vec![
                agent("a", [DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]),
                agent("b", [DeclaredInput::UserPrompt, DeclaredInput::WebContent]),
            ],
        );
        orch.register_all();
        orch.step_once(0, 1).await;
        orch.step_once(1, 1).await;
        serde_json::to_string(&hub.snapshot().recent).unwrap()
    }

    assert_eq!(run().await, run().await);
}
