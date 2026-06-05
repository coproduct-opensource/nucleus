//! THE wire contract. `serde` internally-tagged so the same enum (de)serializes
//! identically in the axum backend and a wasm32 frontend — this module has ONLY
//! serde as a dependency, so it compiles to wasm unchanged.
//!
//! # Honesty
//!
//! [`MarketEvent::Settlement`] and [`MarketEvent::BalanceUpdate`] carry a
//! [`BalanceSource`]. A number derived from the deterministic, network-free
//! [`crate::FakeFacilitator`] is tagged [`BalanceSource::Simulated`]; a number
//! derived from a confirmed Base Sepolia (testnet) transaction is tagged
//! [`BalanceSource::OnChainTestnet`]. There is no code path that produces an
//! `OnChainTestnet` number without a real confirmed tx — the reducer asserts
//! this invariant in tests. The UI must surface the source as a visible badge so
//! a simulated balance can never masquerade as real money.

use serde::{Deserialize, Serialize};

/// Integer micro-USD (`1 USDC = 1_000_000`). Newtype to avoid float money and
/// unit confusion (per the Paragon audit note on `MicroUsd`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MicroUsd(pub i64);

impl MicroUsd {
    /// USDC from whole + 6-decimal fractional micro units.
    pub const fn from_micros(m: i64) -> Self {
        MicroUsd(m)
    }
    /// The raw micro-USD value.
    pub const fn micros(self) -> i64 {
        self.0
    }
}

/// A marketplace participant identifier (an agent's stable handle).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for AgentId {
    fn from(s: &str) -> Self {
        AgentId(s.to_string())
    }
}

/// The colour lanes the UI groups events by (always paired with a text label —
/// never colour alone, for accessibility).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// Commerce: calls, settlements, balances.
    Commerce,
    /// Security: the IFC allow/deny decisions.
    Security,
    /// Trust: identity / registration.
    Trust,
    /// Proof: receipts + verification.
    Proof,
}

/// Provenance of a money number — keeps the UI honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceSource {
    /// Derived from a confirmed on-chain Base Sepolia (testnet) settlement.
    OnChainTestnet,
    /// Derived from the deterministic [`crate::FakeFacilitator`] — NOT real money.
    Simulated,
}

/// How a settlement attempt resolved (mirrors the x402 timeout state machine;
/// the real failure mode is a facilitator timeout, not a nonce collision).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SettlementOutcome {
    /// Settled; carries the (real or clearly-synthetic-simulated) tx reference.
    Confirmed {
        /// On-chain tx hash, or a `0xsimulated…` reference in the simulated path.
        tx_hash: String,
    },
    /// Facilitator timed out; the tx may still confirm later — UI shows "unresolved".
    Timeout,
    /// Polled past the deadline without on-chain confirmation.
    Orphaned,
}

impl SettlementOutcome {
    /// `true` only for [`SettlementOutcome::Confirmed`].
    pub fn is_confirmed(&self) -> bool {
        matches!(self, SettlementOutcome::Confirmed { .. })
    }
}

/// The mechanism that priced a settled call. Carried on the wire so the UI never
/// implies price discovery that isn't actually running.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingMethod {
    /// Static base price; no externality, no discovery (today's default).
    #[default]
    FixedPrice,
    /// Base price + an internalised externality surcharge (Pigouvian) — future.
    Pigouvian,
    /// Truthful clearing of a contended resource (Vickrey–Clarke–Groves) — future.
    Vcg,
}

/// One marketplace event. `id` (monotonic seq) and `ts_unix_ms` are stamped by
/// the [`crate::Hub`] on emit via the injected [`crate::Clock`], so producers
/// construct events with `0` placeholders and never set wall-clock time directly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MarketEvent {
    /// An agent joined the fleet (carries its declared IFC flow surface).
    AgentRegistered {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        resource: String,
        /// The `DeclaredInput` tokens this agent's calls expose (coverage audit).
        declared_inputs: Vec<String>,
        price: MicroUsd,
    },
    /// An agent began one paid-call attempt.
    CallStarted {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        resource: String,
        attempt: u64,
    },
    /// The model-level IFC gate ALLOWED the call (payment + handler may run).
    IfcAllow {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        /// Sorted + deduped declared inputs the verdict was made over.
        declared_inputs: Vec<String>,
        /// Verdict canonical string (`allow\0inputs`) for independent re-derivation.
        canonical: String,
    },
    /// The IFC gate DENIED — the demo's peak; no payment, no handler.
    IfcDeny {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        reason: String,
        declared_inputs: Vec<String>,
        canonical: String,
    },
    /// A settlement attempt resolved (real testnet tx OR simulated).
    Settlement {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        /// The cleared price actually settled (= base price under `FixedPrice`).
        amount: MicroUsd,
        /// The mechanism that priced this call. `serde(default)` keeps the wire
        /// backward-compatible as new mechanisms land.
        #[serde(default)]
        cleared_method: ClearingMethod,
        /// The Pigouvian (externality) component of `amount`; `0` under fixed
        /// pricing. `serde(default)` for backward compatibility.
        #[serde(default)]
        externality: MicroUsd,
        /// CAIP-2 chain id; Base Sepolia is `eip155:84532` — testnet only.
        chain: String,
        outcome: SettlementOutcome,
        /// `OnChainTestnet` vs `Simulated` — never faked.
        source: BalanceSource,
    },
    /// A receipt for a settled call was issued AND checked.
    ReceiptVerified {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        resource: String,
        payment_reference: String,
        body_sha256: String,
        /// Seq of the [`MarketEvent::Settlement`] this receipt binds (UI join key).
        for_settlement_id: u64,
        /// What kind of check produced `verified` (hash re-derivation vs signed bundle).
        method: VerifyMethod,
        /// True iff the check accepted the receipt.
        verified: bool,
    },
    /// A running balance changed (always tagged with its source).
    BalanceUpdate {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        balance: MicroUsd,
        source: BalanceSource,
    },
    /// A receipt was anchored on-chain via the ERC-8004 Validation Registry
    /// (Base Sepolia testnet) — the in-bounds decision is now checkable from
    /// chain reads. Emitted by the real-settlement path (see
    /// `examples/marketplace-live`); never present in the simulated feed.
    ReceiptAnchored {
        id: u64,
        ts_unix_ms: i64,
        agent: AgentId,
        /// Seq of the [`MarketEvent::Settlement`] this anchor binds (UI join key).
        for_settlement_id: u64,
        /// The ERC-8004 `agentId` (Identity Registry tokenId).
        agent_id: u64,
        /// `keccak256(receipt)` committed on-chain (hex `0x…`).
        request_hash: String,
        /// The `validationResponse` tx hash (hex `0x…`; link to Basescan).
        validation_tx: String,
        /// The 0–100 validation score posted (100 = in-bounds).
        response: u8,
    },
}

/// How a [`MarketEvent::ReceiptVerified`] was checked — so the UI never
/// overclaims a hash re-derivation as a signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMethod {
    /// Re-derived the receipt's content binding (body SHA-256) and compared.
    /// Used in the simulated core (the `HashingReceiptIssuer` has no signature).
    HashRebind,
    /// Verified a full signed `nucleus-envelope` provenance bundle
    /// (`verify_receipt_bundle`). Used on the real settlement path.
    SignedBundle,
}

impl MarketEvent {
    /// Monotonic seq id (the SSE `Event` id / `Last-Event-ID` join key).
    pub fn id(&self) -> u64 {
        match self {
            MarketEvent::AgentRegistered { id, .. }
            | MarketEvent::CallStarted { id, .. }
            | MarketEvent::IfcAllow { id, .. }
            | MarketEvent::IfcDeny { id, .. }
            | MarketEvent::Settlement { id, .. }
            | MarketEvent::ReceiptVerified { id, .. }
            | MarketEvent::BalanceUpdate { id, .. }
            | MarketEvent::ReceiptAnchored { id, .. } => *id,
        }
    }

    /// The agent this event concerns.
    pub fn agent(&self) -> &AgentId {
        match self {
            MarketEvent::AgentRegistered { agent, .. }
            | MarketEvent::CallStarted { agent, .. }
            | MarketEvent::IfcAllow { agent, .. }
            | MarketEvent::IfcDeny { agent, .. }
            | MarketEvent::Settlement { agent, .. }
            | MarketEvent::ReceiptVerified { agent, .. }
            | MarketEvent::BalanceUpdate { agent, .. }
            | MarketEvent::ReceiptAnchored { agent, .. } => agent,
        }
    }

    /// UI lane (drives colour + icon; always paired with a label, never colour-only).
    pub fn lane(&self) -> Lane {
        match self {
            MarketEvent::AgentRegistered { .. } => Lane::Trust,
            MarketEvent::CallStarted { .. }
            | MarketEvent::Settlement { .. }
            | MarketEvent::BalanceUpdate { .. } => Lane::Commerce,
            MarketEvent::IfcAllow { .. } | MarketEvent::IfcDeny { .. } => Lane::Security,
            MarketEvent::ReceiptVerified { .. } | MarketEvent::ReceiptAnchored { .. } => {
                Lane::Proof
            }
        }
    }

    /// The deny is the demo's peak; the UI flashes + pins it.
    pub fn is_peak(&self) -> bool {
        matches!(self, MarketEvent::IfcDeny { .. })
    }

    /// Set the monotonic `id` and wall-clock `ts_unix_ms`. Called once by the
    /// [`crate::Hub`] on emit; producers leave these `0`.
    pub fn stamp(&mut self, new_id: u64, ts: i64) {
        match self {
            MarketEvent::AgentRegistered { id, ts_unix_ms, .. }
            | MarketEvent::CallStarted { id, ts_unix_ms, .. }
            | MarketEvent::IfcAllow { id, ts_unix_ms, .. }
            | MarketEvent::IfcDeny { id, ts_unix_ms, .. }
            | MarketEvent::Settlement { id, ts_unix_ms, .. }
            | MarketEvent::ReceiptVerified { id, ts_unix_ms, .. }
            | MarketEvent::BalanceUpdate { id, ts_unix_ms, .. }
            | MarketEvent::ReceiptAnchored { id, ts_unix_ms, .. } => {
                *id = new_id;
                *ts_unix_ms = ts;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(variant: &str) -> MarketEvent {
        let agent = AgentId::from("agent-a");
        match variant {
            "registered" => MarketEvent::AgentRegistered {
                id: 0,
                ts_unix_ms: 0,
                agent,
                resource: "/v1/summarize".into(),
                declared_inputs: vec!["user_prompt".into()],
                price: MicroUsd(10_000),
            },
            "deny" => MarketEvent::IfcDeny {
                id: 0,
                ts_unix_ms: 0,
                agent,
                reason: "AdversarialAncestry".into(),
                declared_inputs: vec!["user_prompt".into(), "web_content".into()],
                canonical: "deny\0user_prompt,web_content".into(),
            },
            _ => unreachable!(),
        }
    }

    #[test]
    fn stamp_sets_id_and_ts() {
        let mut ev = sample("registered");
        assert_eq!(ev.id(), 0);
        ev.stamp(42, 1_700_000_000_000);
        assert_eq!(ev.id(), 42);
        if let MarketEvent::AgentRegistered { ts_unix_ms, .. } = ev {
            assert_eq!(ts_unix_ms, 1_700_000_000_000);
        } else {
            panic!("variant changed");
        }
    }

    #[test]
    fn lanes_and_peak() {
        assert_eq!(sample("registered").lane(), Lane::Trust);
        assert_eq!(sample("deny").lane(), Lane::Security);
        assert!(sample("deny").is_peak());
        assert!(!sample("registered").is_peak());
    }

    #[test]
    fn wire_tags_are_snake_case_and_stable() {
        // Lock the wire contract the frontend depends on.
        let v = serde_json::to_value(sample("deny")).unwrap();
        assert_eq!(v["type"], "ifc_deny");
        assert_eq!(v["agent"], "agent-a");
        assert_eq!(v["declared_inputs"][1], "web_content");

        let settled = MarketEvent::Settlement {
            id: 1,
            ts_unix_ms: 2,
            agent: AgentId::from("a"),
            amount: MicroUsd(10_000),
            cleared_method: ClearingMethod::FixedPrice,
            externality: MicroUsd(0),
            chain: "eip155:84532".into(),
            outcome: SettlementOutcome::Confirmed {
                tx_hash: "0xabc".into(),
            },
            source: BalanceSource::Simulated,
        };
        let s = serde_json::to_value(&settled).unwrap();
        assert_eq!(s["type"], "settlement");
        assert_eq!(s["outcome"]["state"], "confirmed");
        assert_eq!(s["source"], "simulated");
        assert_eq!(s["cleared_method"], "fixed_price");

        // Backward-compat: an old Settlement JSON without the clearing fields
        // still deserializes (serde defaults), proving the wire stays stable.
        let legacy = serde_json::json!({
            "type": "settlement", "id": 1, "ts_unix_ms": 2, "agent": "a",
            "amount": 10_000, "chain": "eip155:84532",
            "outcome": {"state": "confirmed", "tx_hash": "0xabc"}, "source": "simulated"
        });
        let back: MarketEvent = serde_json::from_value(legacy).unwrap();
        assert_eq!(back, settled);

        // Round-trip every variant shape we just built.
        for ev in [sample("registered"), sample("deny"), settled] {
            let json = serde_json::to_string(&ev).unwrap();
            let back: MarketEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(ev, back);
        }
    }
}
