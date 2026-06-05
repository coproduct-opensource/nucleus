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

// Always compiled — the serde-only wire contract + pure reducer. These are
// wasm-safe (serde only), so a wasm frontend can depend on this crate with
// `default-features = false` and share the `MarketEvent` type verbatim.
pub mod event;
pub mod reducer;

// The async orchestrator core — needs tokio + the IFC gate (`runtime` feature).
#[cfg(feature = "runtime")]
pub mod agent;
#[cfg(feature = "runtime")]
pub mod clock;
#[cfg(feature = "runtime")]
pub mod facilitator;
#[cfg(feature = "runtime")]
pub mod hub;
#[cfg(feature = "runtime")]
pub mod orchestrator;

// The thin axum SSE edge.
#[cfg(feature = "server")]
pub mod http;

pub use event::{
    AgentId, BalanceSource, Lane, MarketEvent, MicroUsd, SettlementOutcome, VerifyMethod,
};
pub use reducer::{AgentSummary, MarketState, DEFAULT_RECENT_CAP};

#[cfg(feature = "runtime")]
pub use agent::AgentLoop;
#[cfg(feature = "runtime")]
pub use clock::{Clock, FixedClock, SystemClock};
#[cfg(feature = "runtime")]
pub use facilitator::{Facilitator, FakeFacilitator, SettleRequest};
#[cfg(feature = "runtime")]
pub use hub::Hub;
#[cfg(feature = "runtime")]
pub use orchestrator::{Orchestrator, BASE_SEPOLIA_CAIP2};
