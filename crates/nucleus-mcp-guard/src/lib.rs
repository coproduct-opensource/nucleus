//! # Trifecta Gate — `nucleus-mcp-guard`
//!
//! An **observe-only MCP proxy** that shows what an AI agent *can* exfiltrate.
//!
//! It sits transparently between an agent and its MCP server, taint-tracks the
//! dataflow of a session, and flags every moment the agent holds the **lethal
//! trifecta** — private data + exposure to untrusted content + an outbound
//! channel — at which point a prompt-injection can leak the private data out.
//!
//! The detection is not heuristic hand-waving: the actual decision is the proven
//! model-level IFC gate in [`nucleus_ifc`] (`FlowDeclaration::decide`). This crate
//! only adapts MCP tool traffic into that gate's inputs ([`classify`]) and
//! accumulates session taint ([`session`]).
//!
//! ## Two ways in
//! - [`proxy::run_stdio_proxy`] — wrap a live stdio MCP server (zero agent changes).
//! - [`analyze_session`] — replay a recorded list of tool names offline (great for
//!   CI and for producing the report artifact without a live server).
//!
//! ## Tiers (the product)
//! - **Free (this crate):** observe + report. Manufactures the "my agent CAN
//!   exfiltrate" artifact.
//! - **Enforcement (paid):** the same gate, but block on a denied verdict in the
//!   proxy, with signed, recomputable audit receipts.

pub mod classify;
pub mod proxy;
pub mod report;
pub mod session;

pub use classify::{Classifier, ClassifierConfig, Rule, ToolRole};
pub use report::{analyze_session, SessionReport};
pub use session::{Finding, SessionMonitor, ToolEvent};
