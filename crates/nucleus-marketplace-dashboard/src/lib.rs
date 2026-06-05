//! Real-time **verified-agent-marketplace** dashboard.
//!
//! An axum SSE orchestrator that runs N agent loops making paid calls through
//! the nucleus IFC gate ([`nucleus_verify_commerce`]), emitting
//! allow/deny/settlement/receipt events to a broadcast [`Hub`]. A Leptos
//! frontend renders the live feed and verifies receipts in-browser.
//!
//! # Design: a network-free, deterministic core
//!
//! The decision/event/state core is exercised with **no network, no real
//! clock, and no alloy**:
//!
//! - [`Clock`] (with [`FixedClock`]) makes timestamps deterministic.
//! - [`Facilitator`] (with [`FakeFacilitator`]) abstracts settlement; the real
//!   Base Sepolia (testnet) implementation lives in a **separate workspace**
//!   under `examples/`, so the heavy x402/alloy tree never enters this crate or
//!   the main CI.
//! - The IFC decision is [`nucleus_verify_commerce::FlowDeclaration::decide`] — a
//!   pure function with its own tests.
//! - [`MarketState::apply`] is a pure synchronous fold; state is exactly
//!   `fold(apply, default, events)`, so `/api/snapshot` and the live feed can
//!   never diverge.
//! - [`Orchestrator::step_once`] runs one agent iteration synchronously for
//!   deterministic assertions.
//!
//! # Honesty
//!
//! Testnet only. The IFC verdict is **model-level over declared inputs**
//! (coverage-limited, per-call). Simulated money is tagged
//! [`event::BalanceSource::Simulated`] and can never appear as on-chain money —
//! see [`event`].

#![forbid(unsafe_code)]

pub mod agent;
pub mod clock;
pub mod event;
pub mod facilitator;
pub mod hub;
pub mod orchestrator;
pub mod reducer;

#[cfg(feature = "server")]
pub mod http;

pub use agent::AgentLoop;
pub use clock::{Clock, FixedClock, SystemClock};
pub use event::{
    AgentId, BalanceSource, Lane, MarketEvent, MicroUsd, SettlementOutcome, VerifyMethod,
};
pub use facilitator::{Facilitator, FakeFacilitator, SettleRequest};
pub use hub::Hub;
pub use orchestrator::{Orchestrator, BASE_SEPOLIA_CAIP2};
pub use reducer::{AgentSummary, MarketState, DEFAULT_RECENT_CAP};
