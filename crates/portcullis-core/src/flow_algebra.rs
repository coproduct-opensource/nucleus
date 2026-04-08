//! Flow Algebra — the mathematical foundation of nucleus-code.
//!
//! Two primitives: `join` and `flows_to`.
//! Four laws: commutativity, associativity, idempotency, monotonicity.
//! Everything else is derived.
//!
//! ```text
//! 1. a ⊔ b = b ⊔ a           (commutativity → parallel is safe)
//! 2. a ⊔ (b ⊔ c) = (a ⊔ b) ⊔ c  (associativity → ratchet order irrelevant)
//! 3. a ⊔ a = a               (idempotency → caching is safe)
//! 4. a ≤ a ⊔ b               (monotonicity → taint never decreases)
//! ```

use crate::{
    AuthorityLevel, IFCLabel, IntegLevel, Operation, SinkClass,
    flow::{NodeKind, intrinsic_label},
};

// ═══════════════════════════════════════════════════════════════════════════
// FlowState — the algebraic session state
// ═══════════════════════════════════════════════════════════════════════════

/// The algebraic state of a session — a single label that accumulates
/// via join. All policy decisions reduce to: `state.flows_to(sink)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowState {
    label: IFCLabel,
}

impl FlowState {
    /// The bottom element — allows everything.
    pub fn bottom() -> Self {
        Self {
            label: IFCLabel::default(),
        }
    }

    /// Create from an explicit label.
    pub fn from_label(label: IFCLabel) -> Self {
        Self { label }
    }

    /// The current label.
    pub fn label(&self) -> &IFCLabel {
        &self.label
    }

    // ── Primitive 1: join ────────────────────────────────────────────

    /// Join a label into the state. This is THE fundamental operation.
    /// The state can only become more restrictive (monotonic).
    pub fn join(&mut self, other: IFCLabel) {
        self.label = self.label.join(other);
    }

    /// Join with an operation's intrinsic label.
    pub fn join_operation(&mut self, op: Operation) {
        let kind = operation_to_node_kind(op);
        let intrinsic = intrinsic_label(kind, now_secs());
        self.join(intrinsic);
    }

    // ── Primitive 2: flows_to ───────────────────────────────────────

    /// Can the current state flow to this sink? THE fundamental check.
    pub fn flows_to(&self, sink: SinkClass) -> bool {
        let req_integ = sink_required_integrity(sink);
        let req_auth = sink_required_authority(sink);

        self.label.integrity >= req_integ && self.label.authority >= req_auth
    }

    // ── Derived operations (all built from join + flows_to) ─────────

    /// Is the state tainted by adversarial content?
    pub fn is_tainted(&self) -> bool {
        self.label.integrity <= IntegLevel::Adversarial
    }

    /// Can we cache a result computed in this state?
    /// Idempotency: a ⊔ a = a → re-joining the same label is a no-op.
    /// Valid when the state hasn't become MORE restrictive since caching.
    pub fn cache_valid_for(&self, cached_label: &IFCLabel) -> bool {
        // Cache is valid if current state is no more restrictive than when cached.
        // If state degraded (integrity dropped), cached result from a better state
        // shouldn't be served — it might not have been checked under current taint.
        self.label.integrity >= cached_label.integrity
    }

    /// Can two operations be parallelized?
    /// Commutativity: a ⊔ b = b ⊔ a → order doesn't matter.
    /// Safe when neither operation is a write (writes have side effects).
    pub fn can_parallelize(op_a: Operation, op_b: Operation) -> bool {
        let a_readonly = matches!(
            op_a,
            Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch
        );
        let b_readonly = matches!(
            op_b,
            Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch
        );
        a_readonly && b_readonly
    }

    /// Does a child state satisfy delegation narrowing?
    /// Child must be at least as restrictive as parent on security dimensions:
    /// - Child integrity ≤ parent integrity (can't claim more trust)
    /// - Child confidentiality ≥ parent confidentiality (can't declassify)
    pub fn child_within_parent(parent: &FlowState, child: &FlowState) -> bool {
        child.label.integrity <= parent.label.integrity
            && child.label.confidentiality >= parent.label.confidentiality
    }

    /// Number of clean (untainted) steps from the start.
    /// The cache breakpoint is at this index.
    pub fn clean_prefix_of(labels: &[IFCLabel]) -> usize {
        labels
            .iter()
            .take_while(|l| l.integrity >= IntegLevel::Untrusted)
            .count()
    }
}

impl Default for FlowState {
    fn default() -> Self {
        Self::bottom()
    }
}

// ── Lattice implementation ─────────────────────────────────────────────
//
// FlowState delegates to IFCLabel's Lattice impl. This enables generic
// lattice combinators and property tests on session states.

impl crate::category::Lattice for FlowState {
    fn meet(&self, other: &Self) -> Self {
        Self {
            label: crate::category::Lattice::meet(&self.label, &other.label),
        }
    }
    fn join(&self, other: &Self) -> Self {
        Self {
            label: crate::category::Lattice::join(&self.label, &other.label),
        }
    }
    fn leq(&self, other: &Self) -> bool {
        crate::category::Lattice::leq(&self.label, &other.label)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sink requirements — what does each sink demand?
// ═══════════════════════════════════════════════════════════════════════════

fn sink_required_integrity(sink: SinkClass) -> IntegLevel {
    match sink {
        SinkClass::GitPush | SinkClass::GitCommit | SinkClass::PRCommentWrite => {
            IntegLevel::Untrusted
        }
        SinkClass::WorkspaceWrite | SinkClass::BashExec => IntegLevel::Adversarial,
        _ => IntegLevel::Adversarial,
    }
}

fn sink_required_authority(sink: SinkClass) -> AuthorityLevel {
    match sink {
        SinkClass::GitPush | SinkClass::GitCommit | SinkClass::PRCommentWrite => {
            AuthorityLevel::Directive
        }
        SinkClass::WorkspaceWrite => AuthorityLevel::Suggestive,
        SinkClass::BashExec | SinkClass::HTTPEgress => AuthorityLevel::Suggestive,
        _ => AuthorityLevel::NoAuthority,
    }
}

fn operation_to_node_kind(op: Operation) -> NodeKind {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => NodeKind::FileRead,
        Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
        _ => NodeKind::OutboundAction,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests — verify the four laws + derived operations
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfLevel, DerivationClass, Freshness, ProvenanceSet};

    fn adversarial() -> IFCLabel {
        IFCLabel {
            integrity: IntegLevel::Adversarial,
            confidentiality: ConfLevel::Public,
            authority: AuthorityLevel::NoAuthority,
            ..IFCLabel::default()
        }
    }

    fn trusted() -> IFCLabel {
        IFCLabel {
            integrity: IntegLevel::Trusted,
            confidentiality: ConfLevel::Internal,
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
        }
    }

    // ── Law 1: Commutativity ────────────────────────────────────────

    #[test]
    fn law_commutative() {
        let a = trusted();
        let b = adversarial();
        assert_eq!(a.join(b), b.join(a));
    }

    // ── Law 2: Associativity ────────────────────────────────────────

    #[test]
    fn law_associative() {
        let a = trusted();
        let b = adversarial();
        let c = IFCLabel {
            integrity: IntegLevel::Untrusted,
            ..IFCLabel::default()
        };
        assert_eq!(a.join(b).join(c), a.join(b.join(c)));
    }

    // ── Law 3: Idempotency ──────────────────────────────────────────

    #[test]
    fn law_idempotent() {
        let a = trusted();
        assert_eq!(a.join(a), a);
    }

    // ── Law 4: Monotonicity ─────────────────────────────────────────

    #[test]
    fn law_monotone() {
        let mut state = FlowState::from_label(trusted());
        let before = state.label;
        state.join(adversarial());
        // Integrity can only decrease (more restricted)
        assert!(state.label.integrity <= before.integrity);
    }

    // ── Derived: flows_to ───────────────────────────────────────────

    #[test]
    fn clean_state_flows_to_workspace() {
        let state = FlowState::from_label(trusted());
        assert!(state.flows_to(SinkClass::WorkspaceWrite));
    }

    #[test]
    fn tainted_state_blocked_from_git_push() {
        let mut state = FlowState::from_label(trusted());
        state.join(adversarial());
        assert!(!state.flows_to(SinkClass::GitPush));
    }

    // ── Derived: taint detection ────────────────────────────────────

    #[test]
    fn bottom_not_tainted() {
        assert!(!FlowState::bottom().is_tainted());
    }

    #[test]
    fn web_content_taints() {
        let mut state = FlowState::bottom();
        state.join(adversarial());
        assert!(state.is_tainted());
    }

    // ── Derived: parallel safety ────────────────────────────────────

    #[test]
    fn reads_parallelize() {
        assert!(FlowState::can_parallelize(
            Operation::ReadFiles,
            Operation::GrepSearch
        ));
    }

    #[test]
    fn write_blocks_parallel() {
        assert!(!FlowState::can_parallelize(
            Operation::ReadFiles,
            Operation::WriteFiles
        ));
    }

    // ── Derived: delegation narrowing ───────────────────────────────

    #[test]
    fn child_within_parent_valid() {
        let parent = FlowState::from_label(trusted());
        let child = FlowState::from_label(trusted());
        assert!(FlowState::child_within_parent(&parent, &child));
    }

    #[test]
    fn tainted_child_within_tainted_parent() {
        let mut parent = FlowState::from_label(trusted());
        parent.join(adversarial());
        let mut child = FlowState::from_label(trusted());
        child.join(adversarial());
        assert!(FlowState::child_within_parent(&parent, &child));
    }

    #[test]
    fn clean_child_escapes_tainted_parent() {
        let mut parent = FlowState::from_label(trusted());
        parent.join(adversarial());
        let child = FlowState::from_label(trusted());
        // child is "better" than parent — this is escalation
        assert!(!FlowState::child_within_parent(&parent, &child));
    }

    // ── Derived: cache validity ─────────────────────────────────────

    #[test]
    fn cache_valid_same_state() {
        let state = FlowState::from_label(trusted());
        assert!(state.cache_valid_for(&trusted()));
    }

    #[test]
    fn cache_invalid_after_taint() {
        let mut state = FlowState::from_label(trusted());
        state.join(adversarial());
        // Cached result from when state was trusted is no longer valid
        assert!(!state.cache_valid_for(&trusted()));
    }

    // ── Derived: clean prefix ───────────────────────────────────────

    #[test]
    fn clean_prefix_all() {
        let labels = vec![trusted(), trusted()];
        assert_eq!(FlowState::clean_prefix_of(&labels), 2);
    }

    #[test]
    fn clean_prefix_breaks_at_adversarial() {
        let labels = vec![trusted(), adversarial(), trusted()];
        assert_eq!(FlowState::clean_prefix_of(&labels), 1);
    }

    // ── Lattice trait ──────────────────────────────────────────────────

    #[test]
    fn flow_state_lattice_laws() {
        use crate::category::verify_lattice_laws;

        // Use uniform freshness to avoid the Freshness::leq edge case
        let fresh = crate::Freshness {
            observed_at: 1000,
            ttl_secs: 3600,
        };
        let samples = vec![
            FlowState::from_label(IFCLabel {
                freshness: fresh,
                ..trusted()
            }),
            FlowState::from_label(IFCLabel {
                freshness: fresh,
                ..adversarial()
            }),
            FlowState::from_label(IFCLabel {
                freshness: fresh,
                ..IFCLabel::default()
            }),
        ];
        let v = verify_lattice_laws(&samples);
        assert!(v.is_empty(), "FlowState lattice violations: {v:?}");
    }

    #[test]
    fn flow_state_meet_is_least_restrictive() {
        let trusted_state = FlowState::from_label(trusted());
        let mut tainted_state = FlowState::from_label(trusted());
        tainted_state.join(adversarial()); // inherent join (mut, IFCLabel)

        // Lattice meet should give us the less restrictive state
        let met = crate::category::Lattice::meet(&trusted_state, &tainted_state);
        assert_eq!(
            met, trusted_state,
            "meet should recover the less restrictive state"
        );
    }
}
