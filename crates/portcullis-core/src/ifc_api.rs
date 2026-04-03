//! FlowTracker — standalone IFC API facade (#1038).
//!
//! A simple, ergonomic entry point for adding information flow control
//! to any AI agent. Wraps the flow graph internals behind a clean API.
//!
//! ```rust,ignore
//! use portcullis_core::ifc_api::{FlowTracker, NodeKind};
//!
//! let mut tracker = FlowTracker::new();
//! let web = tracker.observe(NodeKind::WebContent)?;
//! let plan = tracker.observe_with_parents(NodeKind::ModelPlan, &[web])?;
//!
//! // Web content + model plan → write attempt: is it safe?
//! let label = tracker.label(plan);
//! assert_eq!(label.integrity, portcullis_core::IntegLevel::Adversarial);
//! ```

use crate::flow::{NodeKind, intrinsic_label};
use crate::{AuthorityLevel, DerivationClass, IFCLabel, IntegLevel};

/// A lightweight IFC flow tracker for AI agent data provenance.
///
/// Tracks how data flows through an agent session: which tools produce
/// data, what labels that data carries, and whether actions based on
/// that data are safe.
pub struct FlowTracker {
    /// Node storage: (kind, label, parents).
    nodes: Vec<(NodeKind, IFCLabel, Vec<u64>)>,
    next_id: u64,
}

/// Error from flow tracking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// A referenced parent node does not exist.
    ParentNotFound(u64),
    /// Too many parents (max 8).
    TooManyParents(usize),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentNotFound(id) => write!(f, "parent node {id} not found"),
            Self::TooManyParents(n) => write!(f, "too many parents: {n} (max 8)"),
        }
    }
}

impl std::error::Error for FlowError {}

/// Result of checking whether an action is safe given its data ancestry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum SafetyCheck {
    /// The action's data ancestry is clean — no adversarial taint,
    /// authority level is sufficient.
    Safe,
    /// The action would use data with adversarial integrity.
    AdversarialAncestry {
        /// The node that introduced the adversarial taint.
        tainted_node: u64,
    },
    /// The action would use data with insufficient authority.
    InsufficientAuthority {
        /// The authority level of the data.
        actual: AuthorityLevel,
        /// The minimum authority required.
        required: AuthorityLevel,
    },
}

impl SafetyCheck {
    /// Returns `true` if the check passed (action is safe).
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe)
    }

    /// Returns `true` if the check failed (action should be denied).
    pub fn is_denied(&self) -> bool {
        !self.is_safe()
    }
}

impl FlowTracker {
    /// Create a new empty flow tracker.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            next_id: 1, // 0 reserved as sentinel
        }
    }

    /// Observe a new data source entering the session (no parents).
    ///
    /// Returns the node ID for use as a parent in subsequent observations.
    pub fn observe(&mut self, kind: NodeKind) -> Result<u64, FlowError> {
        self.observe_with_parents(kind, &[])
    }

    /// Observe a new node with explicit causal parents.
    ///
    /// The node's label is computed by joining parent labels with the
    /// intrinsic label for this node kind (Denning's lattice join).
    pub fn observe_with_parents(
        &mut self,
        kind: NodeKind,
        parents: &[u64],
    ) -> Result<u64, FlowError> {
        if parents.len() > 8 {
            return Err(FlowError::TooManyParents(parents.len()));
        }
        for &pid in parents {
            if pid == 0 || pid > self.next_id {
                return Err(FlowError::ParentNotFound(pid));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute label: intrinsic join with parent labels.
        let mut label = intrinsic_label(kind, now);
        for &pid in parents {
            if let Some((_, parent_label, _)) = self.nodes.get((pid - 1) as usize) {
                label = label.join(*parent_label);
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        self.nodes.push((kind, label, parents.to_vec()));
        Ok(id)
    }

    /// Get the IFC label for a node.
    pub fn label(&self, node_id: u64) -> Option<&IFCLabel> {
        self.nodes.get((node_id - 1) as usize).map(|(_, l, _)| l)
    }

    /// Check whether an action with the given ancestry is safe.
    ///
    /// An action is unsafe if any ancestor has:
    /// - `Adversarial` integrity (prompt injection risk)
    /// - `NoAuthority` while the action requires authority
    pub fn check_safety(&self, parents: &[u64], requires_authority: bool) -> SafetyCheck {
        for &pid in parents {
            if let Some((_, label, _)) = self.nodes.get((pid - 1) as usize) {
                if label.integrity == IntegLevel::Adversarial {
                    return SafetyCheck::AdversarialAncestry { tainted_node: pid };
                }
                if requires_authority && label.authority == AuthorityLevel::NoAuthority {
                    return SafetyCheck::InsufficientAuthority {
                        actual: label.authority,
                        required: AuthorityLevel::Informational,
                    };
                }
            }
        }
        SafetyCheck::Safe
    }

    /// Number of tracked nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Check if any node in the tracker has adversarial integrity.
    pub fn is_tainted(&self) -> bool {
        self.nodes
            .iter()
            .any(|(_, l, _)| l.integrity == IntegLevel::Adversarial)
    }

    /// Check if any node has AI-derived derivation.
    pub fn has_ai_derived(&self) -> bool {
        self.nodes
            .iter()
            .any(|(_, l, _)| l.derivation == DerivationClass::AIDerived)
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_observe() {
        let mut t = FlowTracker::new();
        let id = t.observe(NodeKind::FileRead).unwrap();
        assert_eq!(id, 1);
        assert_eq!(t.node_count(), 1);
    }

    #[test]
    fn web_content_is_adversarial() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let label = t.label(web).unwrap();
        assert_eq!(label.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn taint_propagates_through_model() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let plan = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();
        let label = t.label(plan).unwrap();
        assert_eq!(
            label.integrity,
            IntegLevel::Adversarial,
            "model plan inherits adversarial from web content"
        );
    }

    #[test]
    fn safety_check_blocks_adversarial() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let plan = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();

        let check = t.check_safety(&[plan], true);
        assert!(check.is_denied());
        assert!(matches!(check, SafetyCheck::AdversarialAncestry { .. }));
    }

    #[test]
    fn clean_ancestry_is_safe() {
        let mut t = FlowTracker::new();
        let user = t.observe(NodeKind::UserPrompt).unwrap();
        let file = t.observe(NodeKind::FileRead).unwrap();
        let plan = t
            .observe_with_parents(NodeKind::ModelPlan, &[user, file])
            .unwrap();

        let check = t.check_safety(&[plan], true);
        assert!(check.is_safe());
    }

    #[test]
    fn is_tainted_detects_web() {
        let mut t = FlowTracker::new();
        assert!(!t.is_tainted());
        t.observe(NodeKind::WebContent).unwrap();
        assert!(t.is_tainted());
    }

    #[test]
    fn parent_not_found_error() {
        let mut t = FlowTracker::new();
        let err = t
            .observe_with_parents(NodeKind::ModelPlan, &[999])
            .unwrap_err();
        assert!(matches!(err, FlowError::ParentNotFound(999)));
    }
}
