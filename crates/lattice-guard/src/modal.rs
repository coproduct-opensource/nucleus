//! Modal operators for necessity (□) and possibility (◇) in permissions.
//!
//! Modal logic distinguishes between:
//! - **Necessity (□)**: What MUST be true / what is guaranteed
//! - **Possibility (◇)**: What MAY be true / what is achievable
//!
//! # Connection to Topology (S4 Axioms)
//!
//! In the S4 modal logic system:
//! - □ corresponds to the **interior operator** (what's definitely inside)
//! - ◇ corresponds to the **closure operator** (what's in the boundary)
//!
//! The key axioms:
//! - `□A → A` (necessity implies actuality)
//! - `□A → □□A` (positive introspection)
//! - `A → ◇A` (actuality implies possibility)
//!
//! # Security Applications
//!
//! - **Necessity**: Permissions that can be exercised without approval
//! - **Possibility**: Permissions that could be achieved through escalation
//! - **Gap**: The difference represents what requires human intervention
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::modal::{ModalPermissions, ModalContext};
//! use lattice_guard::PermissionLattice;
//!
//! let perms = PermissionLattice::fix_issue();
//!
//! // Compute what's guaranteed vs what's possible
//! let necessary = perms.necessity();
//! let possible = perms.possibility(&PermissionLattice::permissive());
//!
//! // Create a modal context for reasoning
//! let context = ModalContext::new(perms);
//! if context.requires_escalation() {
//!     println!("Some operations require approval");
//! }
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityLevel, Operation};
use crate::escalation::SpiffeTraceChain;
use crate::frame::Lattice;
use crate::PermissionLattice;

/// Modal operators on permission lattices.
///
/// These operators distinguish between what is **necessarily** true
/// (guaranteed, can act without approval) and what is **possibly** true
/// (achievable, perhaps through escalation).
pub trait ModalPermissions: Lattice {
    /// Necessity operator (□): the "interior" of permissions.
    ///
    /// Returns the permissions that can be exercised without any approval.
    /// This removes capabilities that have corresponding obligations.
    ///
    /// # Properties
    ///
    /// - `□A ≤ A` (necessity implies actuality)
    /// - `□(□A) = □A` (idempotent)
    /// - `□(A ∧ B) = □A ∧ □B` (distributes over meet)
    fn necessity(&self) -> Self;

    /// Possibility operator (◇): the "closure" of permissions.
    ///
    /// Returns the permissions that could potentially be achieved,
    /// given an escalation ceiling (maximum permissions an approver could grant).
    ///
    /// # Properties
    ///
    /// - `A ≤ ◇A` (actuality implies possibility)
    /// - `◇(◇A) = ◇A` (idempotent)
    /// - `◇(A ∨ B) = ◇A ∨ ◇B` (distributes over join)
    fn possibility(&self, ceiling: &Self) -> Self;

    /// Check if escalation is required to achieve target permissions.
    fn requires_escalation_to(&self, target: &Self) -> bool {
        !self.necessity().leq(target)
    }
}

impl ModalPermissions for PermissionLattice {
    fn necessity(&self) -> Self {
        // The necessity is what we can do WITHOUT approval.
        // Operations that require approval are set to Never.
        let mut result = self.clone();

        for op in &self.obligations.approvals {
            match op {
                Operation::ReadFiles => result.capabilities.read_files = CapabilityLevel::Never,
                Operation::WriteFiles => result.capabilities.write_files = CapabilityLevel::Never,
                Operation::EditFiles => result.capabilities.edit_files = CapabilityLevel::Never,
                Operation::RunBash => result.capabilities.run_bash = CapabilityLevel::Never,
                Operation::GlobSearch => result.capabilities.glob_search = CapabilityLevel::Never,
                Operation::GrepSearch => result.capabilities.grep_search = CapabilityLevel::Never,
                Operation::WebSearch => result.capabilities.web_search = CapabilityLevel::Never,
                Operation::WebFetch => result.capabilities.web_fetch = CapabilityLevel::Never,
                Operation::GitCommit => result.capabilities.git_commit = CapabilityLevel::Never,
                Operation::GitPush => result.capabilities.git_push = CapabilityLevel::Never,
                Operation::CreatePr => result.capabilities.create_pr = CapabilityLevel::Never,
                Operation::ManagePods => result.capabilities.manage_pods = CapabilityLevel::Never,
            }
        }

        result
    }

    fn possibility(&self, ceiling: &Self) -> Self {
        // The possibility is the join with the escalation ceiling.
        // This represents what we COULD achieve if escalation is granted.
        self.join(ceiling)
    }
}

/// A modal context tracking both necessity and possibility.
///
/// This provides a complete picture of an agent's permission state:
/// - What can be done right now (necessity)
/// - What could be done with escalation (possibility)
/// - What requires human approval (the gap)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ModalContext {
    /// The base permission lattice
    pub base: PermissionLattice,
    /// What is necessarily available (no approval needed)
    pub necessary: PermissionLattice,
    /// What is possibly achievable (with escalation)
    pub possible: PermissionLattice,
    /// The escalation ceiling (maximum achievable)
    pub ceiling: PermissionLattice,
}

impl ModalContext {
    /// Create a new modal context with default ceiling.
    pub fn new(base: PermissionLattice) -> Self {
        let necessary = base.necessity();
        let ceiling = PermissionLattice::permissive();
        let possible = base.possibility(&ceiling);

        Self {
            base,
            necessary,
            possible,
            ceiling,
        }
    }

    /// Create a modal context with a specific escalation ceiling.
    pub fn with_ceiling(base: PermissionLattice, ceiling: PermissionLattice) -> Self {
        let necessary = base.necessity();
        let possible = base.possibility(&ceiling);

        Self {
            base,
            necessary,
            possible,
            ceiling,
        }
    }

    /// Create a modal context from a SPIFFE trace chain.
    ///
    /// The chain's ceiling becomes the escalation ceiling.
    pub fn from_trace_chain(
        chain: &SpiffeTraceChain,
        escalation_ceiling: &PermissionLattice,
    ) -> Self {
        let base = chain.ceiling().unwrap_or_default();
        let necessary = base.necessity();
        let possible = base.possibility(escalation_ceiling);

        Self {
            base,
            necessary,
            possible,
            ceiling: escalation_ceiling.clone(),
        }
    }

    /// Check if escalation is required for any operation.
    pub fn requires_escalation(&self) -> bool {
        !self.base.obligations.approvals.is_empty()
    }

    /// Get the operations that require escalation.
    pub fn escalation_required_for(&self) -> Vec<Operation> {
        self.base.obligations.approvals.iter().copied().collect()
    }

    /// Check if a specific operation requires escalation.
    pub fn operation_requires_escalation(&self, op: Operation) -> bool {
        self.base.obligations.requires(op)
    }

    /// Compute the "gap" between necessity and base.
    ///
    /// The gap represents capabilities that exist in the base but
    /// require approval to exercise.
    pub fn approval_gap(&self) -> Vec<Operation> {
        self.escalation_required_for()
    }

    /// Check if the context is "tight" (no gap between necessity and base).
    ///
    /// A tight context means all capabilities can be exercised without approval.
    pub fn is_tight(&self) -> bool {
        self.base.obligations.approvals.is_empty()
    }

    /// Check if a target permission is achievable (within possibility).
    pub fn is_achievable(&self, target: &PermissionLattice) -> bool {
        target.leq(&self.possible)
    }

    /// Check if a target permission is guaranteed (within necessity).
    pub fn is_guaranteed(&self, target: &PermissionLattice) -> bool {
        target.leq(&self.necessary)
    }
}

/// Modal operators for specific capability dimensions.
///
/// This provides fine-grained modal reasoning about individual capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapabilityModal {
    /// The operation in question
    pub operation: Operation,
    /// The current capability level
    pub level: CapabilityLevel,
    /// Whether this operation requires approval
    pub requires_approval: bool,
}

impl CapabilityModal {
    /// Create a new capability modal from a permission lattice and operation.
    pub fn from_perms(perms: &PermissionLattice, operation: Operation) -> Self {
        let level = match operation {
            Operation::ReadFiles => perms.capabilities.read_files,
            Operation::WriteFiles => perms.capabilities.write_files,
            Operation::EditFiles => perms.capabilities.edit_files,
            Operation::RunBash => perms.capabilities.run_bash,
            Operation::GlobSearch => perms.capabilities.glob_search,
            Operation::GrepSearch => perms.capabilities.grep_search,
            Operation::WebSearch => perms.capabilities.web_search,
            Operation::WebFetch => perms.capabilities.web_fetch,
            Operation::GitCommit => perms.capabilities.git_commit,
            Operation::GitPush => perms.capabilities.git_push,
            Operation::CreatePr => perms.capabilities.create_pr,
            Operation::ManagePods => perms.capabilities.manage_pods,
        };

        let requires_approval = perms.obligations.requires(operation);

        Self {
            operation,
            level,
            requires_approval,
        }
    }

    /// The necessary level (what's guaranteed without approval).
    pub fn necessary_level(&self) -> CapabilityLevel {
        if self.requires_approval {
            CapabilityLevel::Never
        } else {
            self.level
        }
    }

    /// The possible level (what could be achieved).
    pub fn possible_level(&self, ceiling: CapabilityLevel) -> CapabilityLevel {
        std::cmp::max(self.level, ceiling)
    }

    /// Check if this capability can be exercised now.
    pub fn can_exercise(&self) -> bool {
        self.level > CapabilityLevel::Never && !self.requires_approval
    }

    /// Check if this capability could be exercised with approval.
    pub fn can_exercise_with_approval(&self) -> bool {
        self.level > CapabilityLevel::Never
    }
}

/// Compute all capability modals for a permission lattice.
pub fn all_capability_modals(perms: &PermissionLattice) -> Vec<CapabilityModal> {
    vec![
        CapabilityModal::from_perms(perms, Operation::ReadFiles),
        CapabilityModal::from_perms(perms, Operation::WriteFiles),
        CapabilityModal::from_perms(perms, Operation::EditFiles),
        CapabilityModal::from_perms(perms, Operation::RunBash),
        CapabilityModal::from_perms(perms, Operation::GlobSearch),
        CapabilityModal::from_perms(perms, Operation::GrepSearch),
        CapabilityModal::from_perms(perms, Operation::WebSearch),
        CapabilityModal::from_perms(perms, Operation::WebFetch),
        CapabilityModal::from_perms(perms, Operation::GitCommit),
        CapabilityModal::from_perms(perms, Operation::GitPush),
        CapabilityModal::from_perms(perms, Operation::CreatePr),
        CapabilityModal::from_perms(perms, Operation::ManagePods),
    ]
}

/// A single step in an escalation path.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationStep {
    /// The operation to approve.
    pub operation: Operation,
    /// The capability level gained.
    pub from_level: CapabilityLevel,
    /// The capability level after approval.
    pub to_level: CapabilityLevel,
    /// Estimated cost of this step (from WeakeningCostConfig).
    pub cost: rust_decimal::Decimal,
    /// Whether this step completes the trifecta.
    pub completes_trifecta: bool,
}

/// An ordered escalation path from current to target permissions.
///
/// Steps are ranked by cost (cheapest first), allowing agents to request
/// the most affordable approvals first. Steps that complete the trifecta
/// are always ranked last regardless of base cost, since they require
/// the most scrutiny.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationPath {
    /// Ordered steps (cheapest non-trifecta first, trifecta-completing last).
    pub steps: Vec<EscalationStep>,
    /// Total cost of all steps.
    pub total_cost: rust_decimal::Decimal,
    /// Whether the full path completes the trifecta.
    pub completes_trifecta: bool,
}

impl EscalationPath {
    /// Whether the path is empty (no escalation needed).
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Number of approval steps required.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

impl ModalContext {
    /// Compute the cheapest escalation path from current to target permissions.
    ///
    /// Uses the `WeakeningCostConfig` to price each approval step, then orders
    /// them so:
    /// 1. Non-trifecta steps sorted by ascending cost
    /// 2. Trifecta-completing steps last (highest scrutiny)
    ///
    /// Returns `None` if the target is not achievable (exceeds ceiling).
    pub fn escalation_path(
        &self,
        target: &PermissionLattice,
        cost_config: &crate::weakening::WeakeningCostConfig,
    ) -> Option<EscalationPath> {
        use crate::capability::IncompatibilityConstraint;

        // Target capabilities must be achievable (within possibility's capabilities)
        if !target.capabilities.leq(&self.possible.capabilities) {
            return None;
        }

        let constraint = IncompatibilityConstraint::enforcing();
        let mut steps = Vec::new();

        // Check each capability dimension
        let cap_checks: &[(Operation, CapabilityLevel, CapabilityLevel)] = &[
            (
                Operation::ReadFiles,
                self.necessary.capabilities.read_files,
                target.capabilities.read_files,
            ),
            (
                Operation::WriteFiles,
                self.necessary.capabilities.write_files,
                target.capabilities.write_files,
            ),
            (
                Operation::EditFiles,
                self.necessary.capabilities.edit_files,
                target.capabilities.edit_files,
            ),
            (
                Operation::RunBash,
                self.necessary.capabilities.run_bash,
                target.capabilities.run_bash,
            ),
            (
                Operation::WebSearch,
                self.necessary.capabilities.web_search,
                target.capabilities.web_search,
            ),
            (
                Operation::WebFetch,
                self.necessary.capabilities.web_fetch,
                target.capabilities.web_fetch,
            ),
            (
                Operation::GitPush,
                self.necessary.capabilities.git_push,
                target.capabilities.git_push,
            ),
            (
                Operation::CreatePr,
                self.necessary.capabilities.create_pr,
                target.capabilities.create_pr,
            ),
        ];

        // Build a running capability to track trifecta impact
        let running_caps = self.necessary.capabilities.clone();

        for &(op, from_level, to_level) in cap_checks {
            if to_level > from_level {
                let cost = cost_config.capability_cost(from_level, to_level);

                // Check if granting this step would complete the trifecta
                let mut test_caps = running_caps.clone();
                match op {
                    Operation::ReadFiles => test_caps.read_files = to_level,
                    Operation::WriteFiles => test_caps.write_files = to_level,
                    Operation::EditFiles => test_caps.edit_files = to_level,
                    Operation::RunBash => test_caps.run_bash = to_level,
                    Operation::WebSearch => test_caps.web_search = to_level,
                    Operation::WebFetch => test_caps.web_fetch = to_level,
                    Operation::GitPush => test_caps.git_push = to_level,
                    Operation::CreatePr => test_caps.create_pr = to_level,
                    _ => {}
                }
                let completes = constraint.is_trifecta_complete(&test_caps)
                    && !constraint.is_trifecta_complete(&running_caps);

                steps.push(EscalationStep {
                    operation: op,
                    from_level,
                    to_level,
                    cost: cost.total(),
                    completes_trifecta: completes,
                });
            }
        }

        // Sort: non-trifecta by cost ascending, trifecta-completing last
        steps.sort_by(|a, b| match (a.completes_trifecta, b.completes_trifecta) {
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
            _ => a.cost.cmp(&b.cost),
        });

        let total_cost = steps.iter().map(|s| s.cost).sum();
        let completes_trifecta = steps.iter().any(|s| s.completes_trifecta);

        Some(EscalationPath {
            steps,
            total_cost,
            completes_trifecta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_necessity_removes_gated_capabilities() {
        let perms = PermissionLattice::fix_issue();

        // fix_issue has obligations for several operations
        let necessary = perms.necessity();

        // Operations with obligations should be Never in necessity
        for op in &perms.obligations.approvals {
            match op {
                Operation::GitPush => {
                    assert_eq!(necessary.capabilities.git_push, CapabilityLevel::Never);
                }
                Operation::CreatePr => {
                    assert_eq!(necessary.capabilities.create_pr, CapabilityLevel::Never);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_necessity_is_deflationary() {
        let perms = PermissionLattice::default();
        let necessary = perms.necessity();

        // □A ≤ A
        assert!(necessary.leq(&perms));
    }

    #[test]
    fn test_necessity_is_idempotent() {
        let perms = PermissionLattice::fix_issue();

        let once = perms.necessity();
        let twice = once.necessity();

        // □(□A) = □A
        assert_eq!(once.capabilities, twice.capabilities);
    }

    #[test]
    fn test_possibility_is_inflationary() {
        let perms = PermissionLattice::restrictive();
        let ceiling = PermissionLattice::permissive();

        let possible = perms.possibility(&ceiling);

        // A ≤ ◇A in terms of capabilities
        assert!(perms.capabilities.leq(&possible.capabilities));
    }

    #[test]
    fn test_possibility_bounded_by_ceiling() {
        let perms = PermissionLattice::restrictive();
        let ceiling = PermissionLattice::codegen();

        let possible = perms.possibility(&ceiling);

        // Possibility should not exceed the ceiling
        // (join with ceiling means at most ceiling's capabilities)
        assert!(possible.capabilities.web_fetch <= ceiling.capabilities.web_fetch);
    }

    #[test]
    fn test_modal_context_creation() {
        let perms = PermissionLattice::fix_issue();
        let context = ModalContext::new(perms.clone());

        // Necessary ≤ Base ≤ Possible
        assert!(context.necessary.leq(&context.base));
        assert!(context.base.leq(&context.possible));
    }

    #[test]
    fn test_modal_context_escalation_detection() {
        let perms = PermissionLattice::fix_issue();
        let context = ModalContext::new(perms);

        // fix_issue has obligations, so requires escalation
        assert!(context.requires_escalation());
        assert!(!context.is_tight());
    }

    #[test]
    fn test_modal_context_tight_when_no_obligations() {
        let perms = PermissionLattice::read_only();
        let context = ModalContext::new(perms);

        // read_only has no obligations
        assert!(context.is_tight());
    }

    #[test]
    fn test_capability_modal() {
        let perms = PermissionLattice::fix_issue();

        let git_push = CapabilityModal::from_perms(&perms, Operation::GitPush);

        // git_push should be gated in fix_issue due to trifecta
        if perms.is_trifecta_vulnerable() {
            assert!(git_push.requires_approval);
            assert!(!git_push.can_exercise());
            assert!(git_push.can_exercise_with_approval());
        }
    }

    #[test]
    fn test_achievability() {
        let perms = PermissionLattice::restrictive();
        let ceiling = PermissionLattice::codegen();
        let context = ModalContext::with_ceiling(perms, ceiling.clone());

        // Codegen should be achievable
        assert!(context.is_achievable(&ceiling));

        // Something beyond ceiling should not be achievable
        let beyond = PermissionLattice::permissive();
        assert!(!context.is_achievable(&beyond));
    }

    #[test]
    fn test_guaranteed() {
        let perms = PermissionLattice::read_only();
        let context = ModalContext::new(perms.clone());

        // read_only has no obligations, so base should be guaranteed
        assert!(context.is_guaranteed(&perms));
    }

    #[test]
    fn test_escalation_path_no_escalation_needed() {
        let perms = PermissionLattice::read_only();
        let context = ModalContext::new(perms.clone());
        let config = crate::weakening::WeakeningCostConfig::default();

        let path = context.escalation_path(&perms, &config).unwrap();
        assert!(path.is_empty());
    }

    #[test]
    fn test_escalation_path_with_capability_elevation() {
        use rust_decimal::Decimal;

        let perms = PermissionLattice::restrictive();
        let ceiling = PermissionLattice::permissive();
        let context = ModalContext::with_ceiling(perms, ceiling);
        let config = crate::weakening::WeakeningCostConfig::default();

        let mut target = PermissionLattice::restrictive();
        target.capabilities.write_files = CapabilityLevel::LowRisk;
        target.capabilities.web_fetch = CapabilityLevel::LowRisk;

        let path = context.escalation_path(&target, &config).unwrap();
        assert!(!path.is_empty());
        assert!(path.total_cost > Decimal::ZERO);

        // Steps should be ordered by cost (cheapest first)
        for window in path.steps.windows(2) {
            if !window[0].completes_trifecta && !window[1].completes_trifecta {
                assert!(window[0].cost <= window[1].cost);
            }
        }
    }

    #[test]
    fn test_escalation_path_trifecta_completing_last() {
        let perms = PermissionLattice::restrictive();
        let ceiling = PermissionLattice::permissive();
        let context = ModalContext::with_ceiling(perms, ceiling);
        let config = crate::weakening::WeakeningCostConfig::default();

        // Target with full trifecta: private data + untrusted content + exfil
        let mut target = PermissionLattice::restrictive();
        target.capabilities.read_files = CapabilityLevel::Always; // already Always in restrictive
        target.capabilities.web_fetch = CapabilityLevel::LowRisk;
        target.capabilities.git_push = CapabilityLevel::LowRisk;

        let path = context.escalation_path(&target, &config).unwrap();

        // If there are trifecta-completing steps, they should be last
        if path.completes_trifecta {
            let last_non_trifecta = path.steps.iter().rposition(|s| !s.completes_trifecta);
            let first_trifecta = path.steps.iter().position(|s| s.completes_trifecta);
            if let (Some(last_nt), Some(first_t)) = (last_non_trifecta, first_trifecta) {
                assert!(
                    last_nt < first_t,
                    "Trifecta-completing steps should come after non-trifecta steps"
                );
            }
        }
    }

    #[test]
    fn test_escalation_path_unachievable_returns_none() {
        let perms = PermissionLattice::restrictive();
        let ceiling = PermissionLattice::read_only(); // Limited ceiling
        let context = ModalContext::with_ceiling(perms, ceiling);
        let config = crate::weakening::WeakeningCostConfig::default();

        // Target exceeds ceiling
        let target = PermissionLattice::permissive();
        assert!(context.escalation_path(&target, &config).is_none());
    }

    #[test]
    fn test_all_capability_modals() {
        let perms = PermissionLattice::default();
        let modals = all_capability_modals(&perms);

        // Should have one modal per operation
        assert_eq!(modals.len(), 12);

        // Each modal should match the corresponding capability
        for modal in &modals {
            let expected_level = match modal.operation {
                Operation::ReadFiles => perms.capabilities.read_files,
                Operation::WriteFiles => perms.capabilities.write_files,
                Operation::EditFiles => perms.capabilities.edit_files,
                Operation::RunBash => perms.capabilities.run_bash,
                Operation::GlobSearch => perms.capabilities.glob_search,
                Operation::GrepSearch => perms.capabilities.grep_search,
                Operation::WebSearch => perms.capabilities.web_search,
                Operation::WebFetch => perms.capabilities.web_fetch,
                Operation::GitCommit => perms.capabilities.git_commit,
                Operation::GitPush => perms.capabilities.git_push,
                Operation::CreatePr => perms.capabilities.create_pr,
                Operation::ManagePods => perms.capabilities.manage_pods,
            };
            assert_eq!(modal.level, expected_level);
        }
    }
}
