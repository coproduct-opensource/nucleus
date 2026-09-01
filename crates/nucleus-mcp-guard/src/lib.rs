//! # Trifecta Gate — `nucleus-mcp-guard`
//!
//! An **MCP proxy** that shows — or stops — what an AI agent can exfiltrate.
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
//! ## The discovery channel
//!
//! The proxy also vets `tools/list`, which is where **tool poisoning** and
//! **rug-pulls** live and which nothing in this crate previously looked at. MCP
//! carries instructions and data in one channel, so a tool description has as
//! much influence over the agent as the system prompt does. Schemas are pinned
//! on first sight ([`proxy::GuardConfig::pin_file`] to persist across sessions)
//! and re-checked on every later listing; metadata that is not vouched for is
//! recorded as adversarial ingest, so a subsequent egress call is denied by the
//! same proven gate that handles web content.
//!
//! ## Two modes
//! - [`proxy::Mode::Observe`] (default) — report and forward anyway, so wrapping
//!   a server never starts refusing traffic by surprise.
//! - [`proxy::Mode::Enforce`] — answer the agent with a JSON-RPC error and never
//!   forward the call.
//!
//! Both ship here. Enforcement being merely *described* while the code only
//! `eprintln!`d is precisely the kind of control that reads as protection and
//! is not.

pub mod classify;
pub mod proxy;
pub mod report;
pub mod session;

pub use classify::{Classifier, ClassifierConfig, Rule, ToolRole};
pub use report::{analyze_session, SessionReport};
pub use session::{Finding, SessionMonitor, ToolEvent};
