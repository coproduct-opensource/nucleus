//! The settlement seam. The orchestrator is generic over [`Facilitator`], so the
//! entire core tests against [`FakeFacilitator`] with NO network and NO alloy.
//!
//! The real Base Sepolia implementation (`X402Facilitator`, driving
//! `x402-reqwest` against the testnet with a keystore-backed signer) lives in a
//! SEPARATE workspace (`examples/`), exactly like `examples/x402-sepolia`, so the
//! heavy alloy/x402 dependency tree never enters this crate or the main CI.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::event::{AgentId, BalanceSource, MicroUsd, SettlementOutcome};

/// One settlement request handed to a [`Facilitator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleRequest {
    /// The paying agent.
    pub agent: AgentId,
    /// Amount to settle.
    pub amount: MicroUsd,
    /// The resource being paid for.
    pub resource: String,
    /// The payment reference the call is bound to.
    pub payment_reference: String,
}

/// Settles a paid call. Implementations decide whether settlement is real
/// (on-chain testnet) or simulated, reported via [`Facilitator::source`].
#[async_trait]
pub trait Facilitator: Send + Sync {
    /// Attempt to settle; resolves to a terminal [`SettlementOutcome`].
    async fn settle(&self, req: &SettleRequest) -> SettlementOutcome;

    /// The current balance of `agent`, if known. The orchestrator emits this as a
    /// [`crate::event::MarketEvent::BalanceUpdate`] tagged with [`Self::source`].
    async fn balance_of(&self, agent: &AgentId) -> Option<MicroUsd>;

    /// Provenance of every number this facilitator produces. A
    /// [`BalanceSource::Simulated`] facilitator can never report real money.
    fn source(&self) -> BalanceSource;
}

/// A deterministic, network-free facilitator for tests and the live SIMULATED
/// demo binary. Outcomes can be scripted; balances are tracked as simple
/// arithmetic. Every number it reports is [`BalanceSource::Simulated`].
pub struct FakeFacilitator {
    scripted: Mutex<VecDeque<SettlementOutcome>>,
    default_outcome: SettlementOutcome,
    initial_balance: i64,
    balances: Mutex<std::collections::BTreeMap<AgentId, i64>>,
    calls: AtomicU64,
}

impl FakeFacilitator {
    /// Always confirm, starting every agent at `initial_balance`.
    pub fn always_confirm(initial_balance: MicroUsd) -> Self {
        Self {
            scripted: Mutex::new(VecDeque::new()),
            default_outcome: SettlementOutcome::Confirmed {
                tx_hash: String::new(), // filled per-call with a clearly-synthetic ref
            },
            initial_balance: initial_balance.micros(),
            balances: Mutex::new(std::collections::BTreeMap::new()),
            calls: AtomicU64::new(0),
        }
    }

    /// Return the scripted outcomes in order; once exhausted, fall back to
    /// `default_outcome`.
    pub fn scripted(
        initial_balance: MicroUsd,
        outcomes: impl IntoIterator<Item = SettlementOutcome>,
        default_outcome: SettlementOutcome,
    ) -> Self {
        Self {
            scripted: Mutex::new(outcomes.into_iter().collect()),
            default_outcome,
            initial_balance: initial_balance.micros(),
            balances: Mutex::new(std::collections::BTreeMap::new()),
            calls: AtomicU64::new(0),
        }
    }

    /// How many times [`Facilitator::settle`] has been invoked — the test probe
    /// that proves the deny path NEVER reaches settlement.
    pub fn settle_calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// A clearly-synthetic, deterministic "tx hash" so a simulated settlement can
    /// never be mistaken for an on-chain one.
    fn simulated_ref(call_index: u64) -> String {
        format!("0xsimulated{call_index:056x}")
    }
}

#[async_trait]
impl Facilitator for FakeFacilitator {
    async fn settle(&self, req: &SettleRequest) -> SettlementOutcome {
        let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
        let outcome = {
            let mut q = self.scripted.lock().unwrap();
            q.pop_front()
                .unwrap_or_else(|| self.default_outcome.clone())
        };
        // Materialise a synthetic confirmed ref + debit the simulated balance.
        let outcome = match outcome {
            SettlementOutcome::Confirmed { tx_hash } => {
                let tx_hash = if tx_hash.is_empty() {
                    Self::simulated_ref(call_index)
                } else {
                    tx_hash
                };
                let mut bals = self.balances.lock().unwrap();
                let bal = bals
                    .entry(req.agent.clone())
                    .or_insert(self.initial_balance);
                *bal -= req.amount.micros();
                SettlementOutcome::Confirmed { tx_hash }
            }
            other => other, // Timeout / Orphaned do not move the balance
        };
        outcome
    }

    async fn balance_of(&self, agent: &AgentId) -> Option<MicroUsd> {
        let bals = self.balances.lock().unwrap();
        Some(MicroUsd(
            bals.get(agent).copied().unwrap_or(self.initial_balance),
        ))
    }

    fn source(&self) -> BalanceSource {
        BalanceSource::Simulated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(agent: &str, amount: i64) -> SettleRequest {
        SettleRequest {
            agent: AgentId::from(agent),
            amount: MicroUsd(amount),
            resource: "/v1/x".into(),
            payment_reference: "ref-1".into(),
        }
    }

    #[tokio::test]
    async fn always_confirm_debits_and_is_simulated() {
        let f = FakeFacilitator::always_confirm(MicroUsd(20_000_000));
        assert_eq!(f.source(), BalanceSource::Simulated);
        let out = f.settle(&req("a", 10_000)).await;
        assert!(out.is_confirmed());
        if let SettlementOutcome::Confirmed { tx_hash } = out {
            assert!(tx_hash.starts_with("0xsimulated"));
        }
        assert_eq!(
            f.balance_of(&AgentId::from("a")).await,
            Some(MicroUsd(19_990_000))
        );
        assert_eq!(f.settle_calls(), 1);
    }

    #[tokio::test]
    async fn scripted_outcomes_return_in_order_then_default() {
        let f = FakeFacilitator::scripted(
            MicroUsd(1_000_000),
            [
                SettlementOutcome::Confirmed {
                    tx_hash: String::new(),
                },
                SettlementOutcome::Timeout,
                SettlementOutcome::Orphaned,
            ],
            SettlementOutcome::Timeout,
        );
        assert!(f.settle(&req("a", 1)).await.is_confirmed());
        assert_eq!(f.settle(&req("a", 1)).await, SettlementOutcome::Timeout);
        assert_eq!(f.settle(&req("a", 1)).await, SettlementOutcome::Orphaned);
        // exhausted → default
        assert_eq!(f.settle(&req("a", 1)).await, SettlementOutcome::Timeout);
        assert_eq!(f.settle_calls(), 4);
        // Timeout/Orphaned never debited: only the single confirm did.
        assert_eq!(
            f.balance_of(&AgentId::from("a")).await,
            Some(MicroUsd(999_999))
        );
    }
}
