//! The orchestrator: runs N [`AgentLoop`]s, each one iteration emitting the
//! marketplace event sequence into the [`Hub`]. Generic over [`Facilitator`] so
//! tests drive it with [`crate::FakeFacilitator`] — no network, no alloy.
//!
//! The per-iteration ordering mirrors
//! [`nucleus_verify_commerce::serve_verified_ifc`] exactly: the IFC gate runs
//! before settlement, and a DENY stops the iteration — settlement is never
//! attempted. That guarantee is asserted in `tests/orchestrator_isolation.rs`
//! via the facilitator's `settle_calls()` probe.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::agent::AgentLoop;
use crate::event::{MarketEvent, SettlementOutcome, VerifyMethod};
use crate::facilitator::{Facilitator, SettleRequest};
use crate::hub::Hub;
use nucleus_verify_commerce::{
    body_sha256_hex, CallerClaims, CommerceRequest, PaymentProof, ReceiptContext, ReceiptIssuer,
    VerifiedCaller,
};

/// CAIP-2 chain id for Base Sepolia (testnet).
pub const BASE_SEPOLIA_CAIP2: &str = "eip155:84532";

/// Drives the marketplace.
pub struct Orchestrator<F: Facilitator> {
    hub: Arc<Hub>,
    facilitator: Arc<F>,
    agents: Vec<AgentLoop>,
    chain: String,
}

impl<F: Facilitator + 'static> Orchestrator<F> {
    /// Build an orchestrator over a hub, a facilitator, and an agent fleet.
    pub fn new(hub: Arc<Hub>, facilitator: Arc<F>, agents: Vec<AgentLoop>) -> Self {
        Self {
            hub,
            facilitator,
            agents,
            chain: BASE_SEPOLIA_CAIP2.to_string(),
        }
    }

    /// The agent fleet.
    pub fn agents(&self) -> &[AgentLoop] {
        &self.agents
    }

    /// Emit an `AgentRegistered` for every agent (call once at startup).
    pub fn register_all(&self) {
        for a in &self.agents {
            self.hub.emit(MarketEvent::AgentRegistered {
                id: 0,
                ts_unix_ms: 0,
                agent: a.agent.clone(),
                resource: a.resource.clone(),
                declared_inputs: a.declared_inputs(),
                price: a.price,
            });
        }
    }

    /// Run exactly one iteration for `agents[idx]` synchronously, emitting the
    /// full event sequence. The deterministic test entry point.
    ///
    /// Sequence on ALLOW: `CallStarted → IfcAllow → Settlement → [Confirmed ⇒
    /// ReceiptVerified → BalanceUpdate]`. On DENY: `CallStarted → IfcDeny` and
    /// nothing else (settlement is never attempted).
    pub async fn step_once(&self, idx: usize, attempt: u64) {
        let a = &self.agents[idx];

        self.hub.emit(MarketEvent::CallStarted {
            id: 0,
            ts_unix_ms: 0,
            agent: a.agent.clone(),
            resource: a.resource.clone(),
            attempt,
        });

        // IFC gate — strictly before settlement.
        let verdict = a.flow.decide();
        if !verdict.is_allow() {
            self.hub.emit(MarketEvent::IfcDeny {
                id: 0,
                ts_unix_ms: 0,
                agent: a.agent.clone(),
                reason: verdict.reason.clone(),
                declared_inputs: verdict.declared_inputs.clone(),
                canonical: verdict.canonical(),
            });
            return; // deny ⇒ no settlement, no handler, no receipt
        }

        self.hub.emit(MarketEvent::IfcAllow {
            id: 0,
            ts_unix_ms: 0,
            agent: a.agent.clone(),
            declared_inputs: verdict.declared_inputs.clone(),
            canonical: verdict.canonical(),
        });

        let payment_reference = format!("{}-{}", a.agent.as_str(), attempt);
        let outcome = self
            .facilitator
            .settle(&SettleRequest {
                agent: a.agent.clone(),
                amount: a.price,
                resource: a.resource.clone(),
                payment_reference: payment_reference.clone(),
            })
            .await;
        let source = self.facilitator.source();

        let settlement_id = self.hub.emit(MarketEvent::Settlement {
            id: 0,
            ts_unix_ms: 0,
            agent: a.agent.clone(),
            amount: a.price,
            chain: self.chain.clone(),
            outcome: outcome.clone(),
            source,
        });

        // Only a confirmed settlement yields a receipt + balance update.
        let SettlementOutcome::Confirmed { tx_hash } = &outcome else {
            return;
        };

        // Issue the receipt through the REAL verify-commerce issuer, binding the
        // delivered bytes + the IFC verdict. (The simulated path uses the
        // hash-binding issuer; the real settlement path swaps in the signed
        // EnvelopeReceiptIssuer + verify_receipt_bundle.)
        let caller = VerifiedCaller {
            spiffe_id: format!("spiffe://marketplace.local/agent/{}", a.agent.as_str()),
        };
        let request = CommerceRequest::new(
            a.resource.clone(),
            CallerClaims {
                agent_id: a.agent.0.clone(),
                credential: "simulated".into(),
            },
            PaymentProof {
                scheme: "x402".into(),
                reference: payment_reference.clone(),
            },
        );
        let body =
            format!("{{\"resource\":\"{}\",\"tx\":\"{}\"}}", a.resource, tx_hash).into_bytes();

        let issuer = nucleus_verify_commerce::HashingReceiptIssuer;
        let (receipt, verified) = match issuer.issue(&ReceiptContext {
            caller: &caller,
            request: &request,
            body: &body,
            ifc_verdict: Some(&verdict),
        }) {
            // HashRebind verification: re-derive the content binding and compare.
            Ok(r) => {
                let ok = r.body_sha256 == body_sha256_hex(&body);
                (Some(r), ok)
            }
            Err(_) => (None, false),
        };

        let body_sha256 = receipt
            .as_ref()
            .map(|r| r.body_sha256.clone())
            .unwrap_or_default();
        if let Some(r) = receipt {
            self.hub.store_receipt(settlement_id, r);
        }
        self.hub.emit(MarketEvent::ReceiptVerified {
            id: 0,
            ts_unix_ms: 0,
            agent: a.agent.clone(),
            resource: a.resource.clone(),
            payment_reference,
            body_sha256,
            for_settlement_id: settlement_id,
            method: VerifyMethod::HashRebind,
            verified,
        });

        if let Some(balance) = self.facilitator.balance_of(&a.agent).await {
            self.hub.emit(MarketEvent::BalanceUpdate {
                id: 0,
                ts_unix_ms: 0,
                agent: a.agent.clone(),
                balance,
                source,
            });
        }
    }

    /// Run all agent loops until `cancel` fires. Each loop paces off its
    /// `interval_ms`. Consumes `self` (wrapped in `Arc`) so loops can share it.
    pub async fn run(self: Arc<Self>, cancel: CancellationToken) {
        self.register_all();
        let mut set = tokio::task::JoinSet::new();
        for idx in 0..self.agents.len() {
            let this = Arc::clone(&self);
            let cancel = cancel.clone();
            let interval = self.agents[idx].interval_ms.max(1);
            set.spawn(async move {
                let mut attempt: u64 = 0;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(interval)) => {
                            attempt += 1;
                            this.step_once(idx, attempt).await;
                        }
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
    }
}
