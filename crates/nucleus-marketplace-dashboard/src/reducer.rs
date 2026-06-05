//! The pure reducer: `MarketState` + [`MarketState::apply`]. State is exactly
//! `fold(apply, default, events)`, so a fresh SSE client's `/api/snapshot` and
//! the live feed can never diverge — they are the same function over the same
//! events. No tokio, no network: a plain synchronous fold tested with
//! hand-injected event vectors.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::event::{AgentId, BalanceSource, MarketEvent, MicroUsd};

/// Default cap on the recent-event ring carried in a snapshot.
pub const DEFAULT_RECENT_CAP: usize = 200;

/// Per-agent rollup.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentSummary {
    /// The resource this agent buys.
    pub resource: String,
    /// Declared IFC input tokens (coverage audit surface).
    pub declared_inputs: Vec<String>,
    /// Price per call (micro-USD).
    pub price: MicroUsd,
    /// IFC allows / denies seen for this agent.
    pub allows: u64,
    /// IFC denies seen for this agent.
    pub denies: u64,
    /// Confirmed settlements for this agent.
    pub settlements: u64,
    /// Latest known balance, if any.
    pub balance: Option<MicroUsd>,
    /// Provenance of `balance` (so the UI badges Simulated vs OnChainTestnet).
    pub balance_source: Option<BalanceSource>,
    /// ERC-8004 `agentId` (Identity Registry tokenId), once registered on-chain.
    pub agent_id: Option<u64>,
    /// Receipts anchored on-chain (ERC-8004 Validation Registry) for this agent.
    pub anchored: u64,
    /// Latest on-chain validation score (0–100; 100 = in-bounds).
    pub last_validation: Option<u8>,
}

/// The reduced marketplace state — the ground truth a cold client receives.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MarketState {
    /// Per-agent rollups, keyed by agent id.
    pub agents: BTreeMap<String, AgentSummary>,
    /// Total IFC allows across the marketplace.
    pub allow_count: u64,
    /// Total IFC denies across the marketplace.
    pub deny_count: u64,
    /// Total receipts that verified.
    pub receipts_verified: u64,
    /// Total receipts anchored on-chain (ERC-8004 Validation Registry).
    pub receipts_anchored: u64,
    /// Cumulative micro-USD settled via the SIMULATED facilitator.
    pub simulated_settled_micros: i64,
    /// Cumulative micro-USD settled on-chain (Base Sepolia testnet) — only ever
    /// incremented by a `Confirmed` settlement tagged `OnChainTestnet`.
    pub onchain_settled_micros: i64,
    /// Cumulative Pigouvian (externality) micro-USD across confirmed settlements.
    /// `0` while pricing is `FixedPrice`; grows once a Pigouvian/VCG mechanism
    /// is wired in (see [`crate::clearing`]).
    pub externality_micros: i64,
    /// Highest event id applied (the snapshot's `Last-Event-ID`).
    pub last_id: u64,
    /// Bounded recent-event ring (newest last).
    pub recent: VecDeque<MarketEvent>,
    /// Cap for `recent`.
    pub recent_cap: usize,
}

impl MarketState {
    /// A fresh state with a given recent-ring cap.
    pub fn with_cap(recent_cap: usize) -> Self {
        Self {
            recent_cap,
            ..Default::default()
        }
    }

    fn agent_mut(&mut self, id: &AgentId) -> &mut AgentSummary {
        self.agents.entry(id.0.clone()).or_default()
    }

    /// Fold one event into the state. Pure and total.
    pub fn apply(&mut self, ev: &MarketEvent) {
        self.last_id = self.last_id.max(ev.id());

        match ev {
            MarketEvent::AgentRegistered {
                agent,
                resource,
                declared_inputs,
                price,
                ..
            } => {
                let a = self.agent_mut(agent);
                a.resource = resource.clone();
                a.declared_inputs = declared_inputs.clone();
                a.price = *price;
            }
            MarketEvent::CallStarted { .. } => {}
            MarketEvent::IfcAllow { agent, .. } => {
                self.allow_count += 1;
                self.agent_mut(agent).allows += 1;
            }
            MarketEvent::IfcDeny { agent, .. } => {
                self.deny_count += 1;
                self.agent_mut(agent).denies += 1;
            }
            MarketEvent::Settlement {
                agent,
                amount,
                externality,
                outcome,
                source,
                ..
            } => {
                if outcome.is_confirmed() {
                    self.agent_mut(agent).settlements += 1;
                    self.externality_micros += externality.micros();
                    match source {
                        BalanceSource::Simulated => {
                            self.simulated_settled_micros += amount.micros()
                        }
                        BalanceSource::OnChainTestnet => {
                            self.onchain_settled_micros += amount.micros()
                        }
                    }
                }
            }
            MarketEvent::ReceiptVerified { verified, .. } => {
                if *verified {
                    self.receipts_verified += 1;
                }
            }
            MarketEvent::BalanceUpdate {
                agent,
                balance,
                source,
                ..
            } => {
                let a = self.agent_mut(agent);
                a.balance = Some(*balance);
                a.balance_source = Some(*source);
            }
            MarketEvent::ReceiptAnchored {
                agent,
                agent_id,
                response,
                ..
            } => {
                self.receipts_anchored += 1;
                let a = self.agent_mut(agent);
                a.agent_id = Some(*agent_id);
                a.anchored += 1;
                a.last_validation = Some(*response);
            }
        }

        self.recent.push_back(ev.clone());
        let cap = if self.recent_cap == 0 {
            DEFAULT_RECENT_CAP
        } else {
            self.recent_cap
        };
        while self.recent.len() > cap {
            self.recent.pop_front();
        }
    }

    /// Fold a whole sequence — the canonical way to build state from events.
    pub fn fold(events: &[MarketEvent], recent_cap: usize) -> Self {
        let mut s = MarketState::with_cap(recent_cap);
        for ev in events {
            s.apply(ev);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SettlementOutcome, VerifyMethod};

    fn ev_seq() -> Vec<MarketEvent> {
        let a = AgentId::from("agent-a");
        vec![
            MarketEvent::AgentRegistered {
                id: 1,
                ts_unix_ms: 10,
                agent: a.clone(),
                resource: "/v1/summarize".into(),
                declared_inputs: vec!["user_prompt".into(), "database_row".into()],
                price: MicroUsd(10_000),
            },
            MarketEvent::CallStarted {
                id: 2,
                ts_unix_ms: 11,
                agent: a.clone(),
                resource: "/v1/summarize".into(),
                attempt: 1,
            },
            MarketEvent::IfcAllow {
                id: 3,
                ts_unix_ms: 12,
                agent: a.clone(),
                declared_inputs: vec!["database_row".into(), "user_prompt".into()],
                canonical: "allow\0database_row,user_prompt".into(),
            },
            MarketEvent::Settlement {
                id: 4,
                ts_unix_ms: 13,
                agent: a.clone(),
                amount: MicroUsd(10_000),
                cleared_method: crate::event::ClearingMethod::FixedPrice,
                externality: MicroUsd(0),
                chain: "eip155:84532".into(),
                outcome: SettlementOutcome::Confirmed {
                    tx_hash: "0xsimulated0".into(),
                },
                source: BalanceSource::Simulated,
            },
            MarketEvent::ReceiptVerified {
                id: 5,
                ts_unix_ms: 14,
                agent: a.clone(),
                resource: "/v1/summarize".into(),
                payment_reference: "ref-1".into(),
                body_sha256: "deadbeef".into(),
                for_settlement_id: 4,
                method: VerifyMethod::HashRebind,
                verified: true,
            },
            MarketEvent::BalanceUpdate {
                id: 6,
                ts_unix_ms: 15,
                agent: a,
                balance: MicroUsd(19_990_000),
                source: BalanceSource::Simulated,
            },
        ]
    }

    #[test]
    fn reducer_counts_and_balances() {
        let s = MarketState::fold(&ev_seq(), 200);
        assert_eq!(s.allow_count, 1);
        assert_eq!(s.deny_count, 0);
        assert_eq!(s.receipts_verified, 1);
        assert_eq!(s.simulated_settled_micros, 10_000);
        assert_eq!(s.onchain_settled_micros, 0); // honesty: nothing on-chain
        assert_eq!(s.last_id, 6);
        let a = &s.agents["agent-a"];
        assert_eq!(a.allows, 1);
        assert_eq!(a.settlements, 1);
        assert_eq!(a.balance, Some(MicroUsd(19_990_000)));
        assert_eq!(a.balance_source, Some(BalanceSource::Simulated));
    }

    #[test]
    fn snapshot_equals_replay_of_all_events() {
        // Folding the same events from scratch twice yields identical state —
        // the property that makes /api/snapshot == live feed.
        let events = ev_seq();
        let a = MarketState::fold(&events, 200);
        let mut b = MarketState::with_cap(200);
        for e in &events {
            b.apply(e);
        }
        assert_eq!(a, b);
    }

    #[test]
    fn honesty_invariant_onchain_requires_onchain_settlement() {
        // A reducer fed only Simulated settlements must NEVER show on-chain money.
        let s = MarketState::fold(&ev_seq(), 200);
        assert_eq!(s.onchain_settled_micros, 0);
        assert!(s
            .agents
            .values()
            .all(|a| a.balance_source != Some(BalanceSource::OnChainTestnet)));
    }

    #[test]
    fn recent_ring_is_bounded() {
        let a = AgentId::from("a");
        let mut s = MarketState::with_cap(3);
        for i in 0..10 {
            s.apply(&MarketEvent::CallStarted {
                id: i,
                ts_unix_ms: i as i64,
                agent: a.clone(),
                resource: "/x".into(),
                attempt: i,
            });
        }
        assert_eq!(s.recent.len(), 3);
        assert_eq!(s.recent.front().unwrap().id(), 7);
        assert_eq!(s.recent.back().unwrap().id(), 9);
        assert_eq!(s.last_id, 9);
    }
}
