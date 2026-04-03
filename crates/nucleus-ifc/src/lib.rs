//! # nucleus-ifc — Information Flow Control for AI Agents
//!
//! The only IFC library shipping in production. Track how data flows
//! through your agent, detect taint from untrusted sources, and block
//! unsafe actions at the data level — not just the capability level.
//!
//! ## Quick Start
//!
//! ```rust
//! use nucleus_ifc::{FlowTracker, NodeKind};
//!
//! let mut tracker = FlowTracker::new();
//!
//! // Agent fetches web content (adversarial integrity)
//! let web = tracker.observe(NodeKind::WebContent).unwrap();
//!
//! // Model reads the web content
//! let plan = tracker.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();
//!
//! // Is it safe to write a file based on this data?
//! let check = tracker.check_safety(&[plan], true);
//! assert!(check.is_denied()); // Adversarial ancestry blocks writes
//! ```
//!
//! ## Why IFC?
//!
//! Every prompt injection defense on the market uses heuristic pattern
//! matching. Nucleus uses Denning's lattice model (1976) — mathematically
//! proven information flow control with formal verification (62 Kani proofs,
//! 165 Lean 4 theorems).
//!
//! The flow graph tracks WHERE data came from, not just WHAT the model
//! wants to do. Web content carries `Adversarial` integrity. User prompts
//! carry `Directive` authority. The labels propagate through the causal
//! DAG via lattice join — taint cannot be laundered.

// Re-export the public API from portcullis-core.
pub use portcullis_core::flow::NodeKind;
pub use portcullis_core::ifc_api::{FlowError, FlowTracker, SafetyCheck};
pub use portcullis_core::{AuthorityLevel, DerivationClass, IFCLabel, IntegLevel};
