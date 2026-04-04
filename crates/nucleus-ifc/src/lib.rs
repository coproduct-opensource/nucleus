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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic flow tracking ───────────────────────────────────────────────────

    #[test]
    fn web_content_taints_downstream_writes() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let plan = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();
        let check = t.check_safety(&[plan], true);
        assert!(
            check.is_denied(),
            "adversarial web content must block writes"
        );
    }

    #[test]
    fn clean_user_prompt_allows_write() {
        let mut t = FlowTracker::new();
        let user = t.observe(NodeKind::UserPrompt).unwrap();
        let plan = t
            .observe_with_parents(NodeKind::ModelPlan, &[user])
            .unwrap();
        let check = t.check_safety(&[plan], true);
        assert!(check.is_safe(), "trusted user prompt should allow write");
    }

    #[test]
    fn file_read_allows_write() {
        let mut t = FlowTracker::new();
        let file = t.observe(NodeKind::FileRead).unwrap();
        let plan = t
            .observe_with_parents(NodeKind::ModelPlan, &[file])
            .unwrap();
        assert!(t.check_safety(&[plan], true).is_safe());
    }

    #[test]
    fn adversarial_ancestry_propagates_through_chain() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let mid = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();
        let out = t.observe_with_parents(NodeKind::ModelPlan, &[mid]).unwrap();
        // Two hops later — taint cannot be laundered
        assert!(t.check_safety(&[out], true).is_denied());
    }

    // ── Taint state ───────────────────────────────────────────────────────────

    #[test]
    fn is_tainted_after_web_content() {
        let mut t = FlowTracker::new();
        assert!(!t.is_tainted());
        t.observe(NodeKind::WebContent).unwrap();
        assert!(t.is_tainted());
    }

    #[test]
    fn clean_tracker_is_not_tainted() {
        let t = FlowTracker::new();
        assert!(!t.is_tainted());
    }

    #[test]
    fn fresh_tracker_has_no_ai_derived() {
        let t = FlowTracker::new();
        assert!(!t.has_ai_derived());
    }

    #[test]
    fn model_plan_marks_ai_derived() {
        let mut t = FlowTracker::new();
        let user = t.observe(NodeKind::UserPrompt).unwrap();
        t.observe_with_parents(NodeKind::ModelPlan, &[user])
            .unwrap();
        assert!(t.has_ai_derived());
    }

    // ── Label inspection ─────────────────────────────────────────────────────

    #[test]
    fn web_content_label_is_adversarial() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let label = t.label(web).unwrap();
        assert_eq!(label.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn user_prompt_label_is_trusted() {
        let mut t = FlowTracker::new();
        let user = t.observe(NodeKind::UserPrompt).unwrap();
        let label = t.label(user).unwrap();
        assert_eq!(label.integrity, IntegLevel::Trusted);
    }

    #[test]
    fn deterministic_bind_excluded_from_ai_derived() {
        let mut t = FlowTracker::new();
        t.observe_with_parents(NodeKind::DeterministicBind, &[])
            .unwrap();
        // DeterministicBind is not model-driven
        assert!(!t.has_ai_derived());
    }

    // ── Compartment isolation ─────────────────────────────────────────────────

    #[test]
    fn new_tracker_isolates_from_tainted_tracker() {
        let mut research = FlowTracker::new();
        research.observe(NodeKind::WebContent).unwrap();
        assert!(research.is_tainted());

        let draft = FlowTracker::new();
        assert!(!draft.is_tainted(), "fresh tracker must start clean");
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn label_for_unknown_node_returns_none() {
        let t = FlowTracker::new();
        // Node ID 999 was never observed
        assert!(t.label(999).is_none());
    }

    #[test]
    fn check_safety_empty_nodes_is_safe() {
        let t = FlowTracker::new();
        // No nodes → no adversarial ancestry
        assert!(t.check_safety(&[], true).is_safe());
    }
}
