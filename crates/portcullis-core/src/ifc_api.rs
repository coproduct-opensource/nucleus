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
use crate::{AuthorityLevel, ConfLevel, DerivationClass, IFCLabel, IntegLevel};

/// A lightweight IFC flow tracker for AI agent data provenance.
///
/// Tracks how data flows through an agent session: which tools produce
/// data, what labels that data carries, and whether actions based on
/// that data are safe.
///
/// ## Monotonic session ratchet (#1207)
///
/// The tracker maintains a `session_taint_ceiling: DerivationClass` that
/// is the join of every node's derivation class ever observed in this session.
/// Because `DerivationClass::join` is monotone, this value can only increase —
/// it is a durable session-level record that the agent has been exposed to
/// AI-derived or external content, regardless of which specific node triggered
/// the exposure.
///
/// This closes the "laundering" gap: a node with clean causal ancestry still
/// produces a session-level flag when checked via
/// [`check_action_safety_with_ceiling`] if the session has previously observed
/// `OpaqueExternal` content through *any* path.
pub struct FlowTracker {
    /// Node storage: (kind, label, parents).
    nodes: Vec<(NodeKind, IFCLabel, Vec<u64>)>,
    next_id: u64,
    /// Monotonically non-decreasing session-level taint ceiling.
    ///
    /// Equal to the join of every node's `derivation` class registered in
    /// this session. Can only increase via [`observe_with_parents`].
    /// Only decreasable via the explicit [`reset_session_ceiling`] escape hatch,
    /// which must only be called after verified human authorization.
    session_taint_ceiling: DerivationClass,
    /// Monotonically non-decreasing session-level confidentiality ceiling (#1208).
    ///
    /// Equal to `max(node.confidentiality)` over every node registered in this
    /// session. Because `ConfLevel` ordering is `Public < Internal < Secret`,
    /// this value can only increase. Once the session has observed `Secret` data,
    /// the ceiling stays at `Secret` — any output sink with `max_conf < Secret`
    /// triggers a [`SafetyCheck::ConfidentialityViolation`].
    session_conf_ceiling: ConfLevel,
}

/// Error from flow tracking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// A referenced parent node does not exist.
    ParentNotFound(u64),
    /// Too many parents (max 8).
    TooManyParents(usize),
    /// Node ID space exhausted — cannot allocate more node IDs (#1226, #1235).
    IdSpaceExhausted,
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentNotFound(id) => write!(f, "parent node {id} not found"),
            Self::TooManyParents(n) => write!(f, "too many parents: {n} (max 8)"),
            Self::IdSpaceExhausted => write!(f, "node ID space exhausted (u64 overflow)"),
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
    /// A referenced parent node ID does not exist in the tracker.
    ///
    /// Returned by [`FlowTracker::check_safety`] when a caller supplies a
    /// node ID that is not tracked. The check fails closed (#1180) — an
    /// unknown node could be the result of a bug that skipped taint tracking,
    /// so we treat it as unsafe rather than allowing it silently.
    UnknownNode {
        /// The node ID that was not found.
        node_id: u64,
    },
    /// The session's taint ceiling exceeds the caller's required threshold.
    ///
    /// Returned by [`FlowTracker::check_action_safety_with_ceiling`] when the
    /// session has previously observed content at or above `threshold` — even
    /// if the specific node being checked has clean causal ancestry.
    ///
    /// This is the monotonic ratchet check (#1207): once the session ceiling
    /// reaches a given level, it cannot drop back below it without an explicit
    /// human-authorized [`FlowTracker::reset_session_ceiling`] call.
    SessionCeilingExceeded {
        /// The current session taint ceiling.
        ceiling: DerivationClass,
        /// The threshold the caller required the ceiling to remain below.
        threshold: DerivationClass,
    },
    /// The data's confidentiality level exceeds the sink's maximum allowed
    /// confidentiality (#1208).
    ///
    /// Returned by [`FlowTracker::check_confidentiality_flow`] and
    /// [`FlowTracker::check_exfiltration_safety`] when the node's
    /// (or session's) confidentiality is higher than what the sink permits.
    ///
    /// This is the **downflow containment** dual to integrity's upflow taint:
    /// `Secret` data must not flow to a `Public` sink.
    ConfidentialityViolation {
        /// The actual confidentiality level of the data.
        data_conf: ConfLevel,
        /// The maximum confidentiality the sink allows.
        sink_max_conf: ConfLevel,
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
            session_taint_ceiling: DerivationClass::Deterministic, // bottom
            session_conf_ceiling: ConfLevel::Public, // bottom
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
            if pid == 0 || pid >= self.next_id {
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
            if let Some((_, parent_label, _)) = self.node_entry(pid) {
                label = label.join(*parent_label);
            }
        }

        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(FlowError::IdSpaceExhausted)?;
        // Raise the session taint ceiling: join is monotone so this never decreases.
        self.session_taint_ceiling = self.session_taint_ceiling.join(label.derivation);
        // Raise the session confidentiality ceiling (#1208): max is monotone.
        if label.confidentiality > self.session_conf_ceiling {
            self.session_conf_ceiling = label.confidentiality;
        }
        self.nodes.push((kind, label, parents.to_vec()));
        Ok(id)
    }

    /// Get the IFC label for a node.
    ///
    /// Returns `None` for unknown or sentinel (0) IDs without panicking (#1203).
    pub fn label(&self, node_id: u64) -> Option<&IFCLabel> {
        self.node_entry(node_id).map(|(_, l, _)| l)
    }

    /// Internal helper: look up a node entry by ID, guarding the sentinel.
    ///
    /// Node IDs are 1-based; ID 0 is reserved as a sentinel and must not be
    /// used in arithmetic without first checking for zero (#1203).
    fn node_entry(&self, node_id: u64) -> Option<&(NodeKind, IFCLabel, Vec<u64>)> {
        // Use try_from to avoid silent truncation on 32-bit targets (#1212).
        let idx = usize::try_from(node_id.checked_sub(1)?).ok()?;
        self.nodes.get(idx)
    }

    /// Check whether performing an action based on a specific node is safe.
    ///
    /// This is the **recommended API**. It checks the node's already-joined
    /// label, which correctly reflects all transitive ancestry. Since
    /// `observe_with_parents()` joins parent labels at observation time,
    /// checking the node's own label is sufficient.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let web = tracker.observe(NodeKind::WebContent)?;
    /// let plan = tracker.observe_with_parents(NodeKind::ModelPlan, &[web])?;
    /// // plan's label already includes web's taint via join
    /// assert!(tracker.check_action_safety(plan, true).is_denied());
    /// ```
    pub fn check_action_safety(&self, node_id: u64, requires_authority: bool) -> SafetyCheck {
        let Some((_, label, _)) = self.node_entry(node_id) else {
            // Unknown or sentinel node — fail-closed (#1198, #1203).
            return SafetyCheck::UnknownNode { node_id };
        };
        if label.integrity == IntegLevel::Adversarial {
            return SafetyCheck::AdversarialAncestry {
                tainted_node: node_id,
            };
        }
        if requires_authority && label.authority == AuthorityLevel::NoAuthority {
            return SafetyCheck::InsufficientAuthority {
                actual: label.authority,
                required: AuthorityLevel::Informational,
            };
        }
        SafetyCheck::Safe
    }

    /// Check whether an action with the given ancestry is safe.
    ///
    /// **Prefer [`check_action_safety`] instead** — it takes a single node ID
    /// whose label already reflects all transitive ancestry via join.
    ///
    /// This method checks each provided parent individually. If you pass the
    /// wrong nodes (e.g., only trusted parents, omitting a tainted one), the
    /// check will incorrectly return `Safe`.
    ///
    /// An action is unsafe if any of the provided nodes has:
    /// - `Adversarial` integrity (prompt injection risk)
    /// - `NoAuthority` while the action requires authority
    ///
    /// **Fails closed on unknown node IDs** (#1180): if any `pid` is not
    /// found in the tracker, `SafetyCheck::UnknownNode` is returned. An
    /// unknown ID may indicate a bug where taint tracking was skipped for
    /// the ancestor — treating it as safe would silently bypass the IFC check.
    pub fn check_safety(&self, parents: &[u64], requires_authority: bool) -> SafetyCheck {
        for &pid in parents {
            match self.node_entry(pid) {
                None => {
                    // Fail closed: unknown or sentinel IDs are unsafe (#1180, #1203).
                    return SafetyCheck::UnknownNode { node_id: pid };
                }
                Some((_, label, _)) => {
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
        }
        SafetyCheck::Safe
    }

    /// Check whether an action is safe given its node ancestry *and* the
    /// session-level taint ceiling (#1207).
    ///
    /// This is a stricter version of [`check_action_safety`]: in addition to
    /// checking the node's own label, it checks whether the session has ever
    /// been exposed to content at or above `ceiling_threshold`. If so, it
    /// returns [`SafetyCheck::SessionCeilingExceeded`] even if the specific
    /// node's causal ancestry is clean.
    ///
    /// # When to use this vs `check_action_safety`
    ///
    /// - Use `check_action_safety` for per-action checks against a node's
    ///   own taint ancestry.
    /// - Use `check_action_safety_with_ceiling` for **privileged writes or
    ///   external communication** where session-level exposure history matters,
    ///   not just the specific node's ancestry.
    ///
    /// # Example
    ///
    /// ```rust
    /// use portcullis_core::ifc_api::{FlowTracker, SafetyCheck};
    /// use portcullis_core::{DerivationClass};
    /// use portcullis_core::flow::NodeKind;
    ///
    /// let mut t = FlowTracker::new();
    /// // Session observes web content (OpaqueExternal)
    /// let _web = t.observe(NodeKind::WebContent).unwrap();
    /// // Later, a clean file read is observed
    /// let clean = t.observe(NodeKind::FileRead).unwrap();
    ///
    /// // Per-node check: clean node passes
    /// assert!(t.check_action_safety(clean, false).is_safe());
    ///
    /// // Session-ceiling check: session saw OpaqueExternal, so privileged
    /// // actions are flagged even for the clean node
    /// let result = t.check_action_safety_with_ceiling(clean, false, DerivationClass::AIDerived);
    /// assert!(matches!(result, SafetyCheck::SessionCeilingExceeded { .. }));
    /// ```
    pub fn check_action_safety_with_ceiling(
        &self,
        node_id: u64,
        requires_authority: bool,
        ceiling_threshold: DerivationClass,
    ) -> SafetyCheck {
        // First: node-level check (existing semantics, fail-closed on unknown).
        let node_check = self.check_action_safety(node_id, requires_authority);
        if node_check.is_denied() {
            return node_check;
        }
        // Second: session ceiling check — has the session been exposed at or
        // above the threshold? `a.leq(b)` iff `a ⊔ b = b`, i.e., b ≥ a.
        if ceiling_threshold.leq(self.session_taint_ceiling) {
            return SafetyCheck::SessionCeilingExceeded {
                ceiling: self.session_taint_ceiling,
                threshold: ceiling_threshold,
            };
        }
        SafetyCheck::Safe
    }

    /// The current session taint ceiling.
    ///
    /// Equal to the join of every node's `derivation` class registered since
    /// the tracker was created (or last reset). Monotonically non-decreasing.
    ///
    /// Use this for Portcullis Audit session summaries and for determining
    /// whether the session has ever been exposed to AI-derived or external
    /// content without walking the full flow graph.
    pub fn session_taint_ceiling(&self) -> DerivationClass {
        self.session_taint_ceiling
    }

    /// Returns `true` if the session has observed content above `Deterministic`.
    ///
    /// Equivalent to `session_taint_ceiling() != DerivationClass::Deterministic`.
    pub fn is_session_tainted(&self) -> bool {
        self.session_taint_ceiling != DerivationClass::Deterministic
    }

    /// The current session confidentiality ceiling (#1208).
    ///
    /// Equal to the maximum `ConfLevel` of any node registered since the
    /// tracker was created. Monotonically non-decreasing (`Public → Internal
    /// → Secret`).
    ///
    /// Once the session has observed `Secret` data, no sink with
    /// `max_conf < Secret` should be used without an explicit declassification.
    pub fn session_conf_ceiling(&self) -> ConfLevel {
        self.session_conf_ceiling
    }

    /// Returns `true` if the session has observed data above `Public`
    /// confidentiality.
    pub fn has_confidential_data(&self) -> bool {
        self.session_conf_ceiling > ConfLevel::Public
    }

    /// Check whether writing a node's data to a sink respects confidentiality
    /// downflow containment (#1208).
    ///
    /// The **downflow rule**: data with `ConfLevel = C` may only flow to sinks
    /// with `max_allowed_conf ≥ C`. Writing `Secret` data to a `Public` sink
    /// is a confidentiality violation.
    ///
    /// This checks the **specific node's** label. For session-wide enforcement,
    /// use [`check_exfiltration_safety`] which also checks the session ceiling.
    ///
    /// # Example
    ///
    /// ```rust
    /// use portcullis_core::ifc_api::FlowTracker;
    /// use portcullis_core::ConfLevel;
    /// use portcullis_core::flow::NodeKind;
    ///
    /// let mut t = FlowTracker::new();
    /// let secret = t.observe(NodeKind::EnvVar).unwrap();
    ///
    /// // Secret data → Secret sink: OK
    /// assert!(t.check_confidentiality_flow(secret, ConfLevel::Secret).is_safe());
    /// // Secret data → Public sink: violation
    /// assert!(t.check_confidentiality_flow(secret, ConfLevel::Public).is_denied());
    /// ```
    pub fn check_confidentiality_flow(
        &self,
        node_id: u64,
        sink_max_conf: ConfLevel,
    ) -> SafetyCheck {
        let Some((_, label, _)) = self.node_entry(node_id) else {
            return SafetyCheck::UnknownNode { node_id };
        };
        if label.confidentiality > sink_max_conf {
            return SafetyCheck::ConfidentialityViolation {
                data_conf: label.confidentiality,
                sink_max_conf,
            };
        }
        SafetyCheck::Safe
    }

    /// Full exfiltration safety check: integrity upflow + confidentiality
    /// downflow + authority + session ceilings (#1208).
    ///
    /// This is the **recommended API for write actions**. It combines:
    /// 1. Integrity upflow: no adversarial ancestry (existing `check_action_safety`)
    /// 2. Authority gate: data must have sufficient authority (existing)
    /// 3. Confidentiality downflow: node's `conf ≤ sink_max_conf` (#1208)
    /// 4. Session taint ceiling check (if `ceiling_threshold` provided)
    /// 5. Session conf ceiling check: session's max conf ≤ sink_max_conf
    ///
    /// The session-level conf ceiling check enforces that if the session has
    /// *ever* observed `Secret` data, writing to a `Public` sink is blocked
    /// even if the specific node is `Public`. This prevents laundering attacks
    /// where secret data is round-tripped through a clean node.
    pub fn check_exfiltration_safety(
        &self,
        node_id: u64,
        requires_authority: bool,
        sink_max_conf: ConfLevel,
    ) -> SafetyCheck {
        // 1. Integrity + authority (existing semantics).
        let integrity_check = self.check_action_safety(node_id, requires_authority);
        if integrity_check.is_denied() {
            return integrity_check;
        }

        // 2. Node-level confidentiality downflow.
        let conf_check = self.check_confidentiality_flow(node_id, sink_max_conf);
        if conf_check.is_denied() {
            return conf_check;
        }

        // 3. Session confidentiality ceiling: has the session ever seen data
        //    more confidential than the sink allows?
        if self.session_conf_ceiling > sink_max_conf {
            return SafetyCheck::ConfidentialityViolation {
                data_conf: self.session_conf_ceiling,
                sink_max_conf,
            };
        }

        SafetyCheck::Safe
    }

    /// Reset the session taint ceiling to the given value.
    ///
    /// # Security warning
    ///
    /// This is an **explicit escape hatch** — it is the only way to lower the
    /// session ceiling. It MUST only be called after verified human authorization
    /// (e.g., a `MemoryAuthority::MayResolve` gate or equivalent). Calling this
    /// in automated agent code without human oversight violates the monotonicity
    /// invariant and removes the "no silent cleansing" guarantee.
    ///
    /// In a future version this will require an explicit `SessionCleanse` token
    /// minted only by the human-authorization layer (#1207).
    pub fn reset_session_ceiling(&mut self, new_ceiling: DerivationClass) {
        self.session_taint_ceiling = new_ceiling;
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

    // ── check_action_safety tests (#1099) ──────────────────────────

    #[test]
    fn action_safety_detects_taint_transitively() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let plan = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();
        // plan's label includes web's adversarial taint via join
        assert!(t.check_action_safety(plan, false).is_denied());
    }

    #[test]
    fn action_safety_clean_node_passes() {
        let mut t = FlowTracker::new();
        let file = t.observe(NodeKind::FileRead).unwrap();
        assert!(t.check_action_safety(file, false).is_safe());
    }

    #[test]
    fn action_safety_unknown_node_denied() {
        let t = FlowTracker::new();
        // Node 999 doesn't exist — fail-closed with UnknownNode, not AdversarialAncestry (#1198).
        let result = t.check_action_safety(999, false);
        assert!(result.is_denied());
        assert!(
            matches!(result, SafetyCheck::UnknownNode { node_id: 999 }),
            "expected UnknownNode(999), got {result:?}"
        );
    }

    #[test]
    fn action_safety_vs_check_safety_equivalence() {
        // When used correctly, both APIs produce the same result
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let plan = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();

        let old_api = t.check_safety(&[plan], false);
        let new_api = t.check_action_safety(plan, false);
        assert_eq!(old_api.is_denied(), new_api.is_denied());
    }

    #[test]
    fn action_safety_prevents_footgun() {
        // The footgun: check_safety with wrong parents gives false Safe
        let mut t = FlowTracker::new();
        let trusted = t.observe(NodeKind::FileRead).unwrap();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let plan = t
            .observe_with_parents(NodeKind::ModelPlan, &[trusted, web])
            .unwrap();

        // FOOTGUN: passing only trusted parent to old API → false Safe
        assert!(t.check_safety(&[trusted], false).is_safe());
        // CORRECT: new API checks plan's own label → correctly denied
        assert!(t.check_action_safety(plan, false).is_denied());
    }

    #[test]
    fn check_safety_fails_closed_on_unknown_node() {
        // #1180: unknown node IDs must not silently pass — fail closed.
        let t = FlowTracker::new();
        let result = t.check_safety(&[999], false);
        assert!(result.is_denied());
        assert!(matches!(result, SafetyCheck::UnknownNode { node_id: 999 }));
    }

    #[test]
    fn check_safety_unknown_node_in_mixed_list() {
        // If the unknown node comes after a safe known node, still fails closed.
        let mut t = FlowTracker::new();
        let file = t.observe(NodeKind::FileRead).unwrap();
        let result = t.check_safety(&[file, 9999], false);
        assert!(result.is_denied());
        assert!(matches!(result, SafetyCheck::UnknownNode { node_id: 9999 }));
    }

    // ── Off-by-one fix: next_id is not yet assigned (#1186) ──────────────

    #[test]
    fn observe_rejects_next_id_as_parent() {
        // next_id is the ID that will be assigned to the *next* node — it
        // does not exist yet. Before the fix, `pid > next_id` let it through;
        // after the fix, `pid >= next_id` correctly rejects it.
        let mut t = FlowTracker::new();
        // next_id == 1 before any observe
        let err = t
            .observe_with_parents(NodeKind::ModelPlan, &[1])
            .unwrap_err();
        assert!(matches!(err, FlowError::ParentNotFound(1)));
    }

    #[test]
    fn observe_accepts_valid_prior_node_as_parent() {
        let mut t = FlowTracker::new();
        let file = t.observe(NodeKind::FileRead).unwrap(); // id == 1, next_id now == 2
        // id 1 is valid; next_id (2) is not yet assigned
        let plan = t.observe_with_parents(NodeKind::ModelPlan, &[file]);
        assert!(plan.is_ok());
    }

    // ── Sentinel ID 0 guard (#1203) ──────────────────────────────────────

    #[test]
    fn label_sentinel_id_zero_returns_none_not_panic() {
        // Before #1203, (0u64 - 1) panicked in debug via underflow.
        let t = FlowTracker::new();
        assert!(t.label(0).is_none());
    }

    #[test]
    fn check_action_safety_sentinel_zero_returns_unknown_node() {
        let t = FlowTracker::new();
        let result = t.check_action_safety(0, false);
        assert!(matches!(result, SafetyCheck::UnknownNode { node_id: 0 }));
    }

    #[test]
    fn check_safety_sentinel_zero_fails_closed() {
        let t = FlowTracker::new();
        let result = t.check_safety(&[0], false);
        assert!(result.is_denied());
        assert!(matches!(result, SafetyCheck::UnknownNode { node_id: 0 }));
    }

    // ── Monotonic session ratchet (#1207) ────────────────────────────────

    #[test]
    fn new_tracker_has_deterministic_ceiling() {
        let t = FlowTracker::new();
        assert_eq!(t.session_taint_ceiling(), DerivationClass::Deterministic);
        assert!(!t.is_session_tainted());
    }

    #[test]
    fn ceiling_raised_by_web_content_observation() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::WebContent).unwrap();
        // WebContent is OpaqueExternal — ceiling should now be OpaqueExternal
        assert_eq!(t.session_taint_ceiling(), DerivationClass::OpaqueExternal);
        assert!(t.is_session_tainted());
    }

    #[test]
    fn ceiling_raised_by_model_plan_observation() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::ModelPlan).unwrap();
        // ModelPlan is AIDerived — ceiling should be at least AIDerived
        assert!(t.is_session_tainted());
        assert!(DerivationClass::AIDerived.leq(t.session_taint_ceiling()));
    }

    #[test]
    fn ceiling_is_monotone_across_observations() {
        let mut t = FlowTracker::new();
        let _f = t.observe(NodeKind::FileRead).unwrap(); // Deterministic
        assert_eq!(t.session_taint_ceiling(), DerivationClass::Deterministic);

        let _m = t.observe(NodeKind::ModelPlan).unwrap(); // AIDerived
        let mid = t.session_taint_ceiling();
        assert!(DerivationClass::Deterministic.leq(mid));

        let _w = t.observe(NodeKind::WebContent).unwrap(); // OpaqueExternal
        let top = t.session_taint_ceiling();
        // Ceiling can only go up
        assert!(mid.leq(top));
        assert_eq!(top, DerivationClass::OpaqueExternal);
    }

    #[test]
    fn ceiling_never_decreases_on_clean_observation_after_taint() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::WebContent).unwrap(); // OpaqueExternal
        let ceiling_before = t.session_taint_ceiling();

        // Observing clean file reads must not lower the ceiling
        t.observe(NodeKind::FileRead).unwrap();
        t.observe(NodeKind::FileRead).unwrap();
        assert_eq!(t.session_taint_ceiling(), ceiling_before);
    }

    #[test]
    fn check_action_safety_with_ceiling_blocks_on_session_exposure() {
        let mut t = FlowTracker::new();
        // Session observes web content — ceiling becomes OpaqueExternal
        let _web = t.observe(NodeKind::WebContent).unwrap();
        // Later, a clean file read is observed
        let clean_file = t.observe(NodeKind::FileRead).unwrap();

        // Per-node check: the file read's own label is clean
        assert!(t.check_action_safety(clean_file, false).is_safe());

        // Session-ceiling check: session saw OpaqueExternal — privileged
        // actions are blocked even for the clean node
        let result =
            t.check_action_safety_with_ceiling(clean_file, false, DerivationClass::AIDerived);
        assert!(
            matches!(result, SafetyCheck::SessionCeilingExceeded { .. }),
            "expected SessionCeilingExceeded, got {result:?}"
        );
    }

    #[test]
    fn check_action_safety_with_ceiling_passes_when_below_threshold() {
        let mut t = FlowTracker::new();
        let _m = t.observe(NodeKind::ModelPlan).unwrap(); // AIDerived ceiling
        let clean = t.observe(NodeKind::FileRead).unwrap();

        // Threshold is OpaqueExternal — ceiling is only AIDerived, so passes
        let result =
            t.check_action_safety_with_ceiling(clean, false, DerivationClass::OpaqueExternal);
        assert!(result.is_safe(), "should pass: ceiling below threshold");
    }

    #[test]
    fn check_action_safety_with_ceiling_node_denial_takes_priority() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap();
        let tainted = t.observe_with_parents(NodeKind::ModelPlan, &[web]).unwrap();

        // Node is adversarially tainted — AdversarialAncestry should be returned
        // before reaching the ceiling check
        let result = t.check_action_safety_with_ceiling(tainted, false, DerivationClass::AIDerived);
        assert!(
            matches!(result, SafetyCheck::AdversarialAncestry { .. }),
            "node-level denial should take priority over ceiling check"
        );
    }

    #[test]
    fn check_action_safety_with_ceiling_unknown_node_fails_closed() {
        let t = FlowTracker::new();
        let result = t.check_action_safety_with_ceiling(999, false, DerivationClass::AIDerived);
        assert!(matches!(result, SafetyCheck::UnknownNode { node_id: 999 }));
    }

    #[test]
    fn ceiling_deterministic_session_passes_all_thresholds() {
        let mut t = FlowTracker::new();
        let f = t.observe(NodeKind::FileRead).unwrap();
        assert_eq!(t.session_taint_ceiling(), DerivationClass::Deterministic);

        // All thresholds above Deterministic should pass (ceiling is at bottom)
        for threshold in [
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ] {
            let result = t.check_action_safety_with_ceiling(f, false, threshold);
            assert!(
                result.is_safe(),
                "deterministic session should pass threshold {threshold:?}"
            );
        }
    }

    #[test]
    fn reset_session_ceiling_lowers_ceiling() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::WebContent).unwrap();
        assert_eq!(t.session_taint_ceiling(), DerivationClass::OpaqueExternal);

        // Explicit reset (requires human authorization in production)
        t.reset_session_ceiling(DerivationClass::Deterministic);
        assert_eq!(t.session_taint_ceiling(), DerivationClass::Deterministic);
        assert!(!t.is_session_tainted());
    }

    #[test]
    fn session_tainted_status_reflects_ceiling() {
        let mut t = FlowTracker::new();
        assert!(!t.is_session_tainted());

        t.observe(NodeKind::ModelPlan).unwrap();
        assert!(t.is_session_tainted());

        t.reset_session_ceiling(DerivationClass::Deterministic);
        assert!(!t.is_session_tainted());
    }

    // ── Confidentiality downflow containment tests (#1208) ──────────

    #[test]
    fn conf_ceiling_starts_at_public() {
        let t = FlowTracker::new();
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Public);
        assert!(!t.has_confidential_data());
    }

    #[test]
    fn conf_ceiling_raised_by_secret_node() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::EnvVar).unwrap(); // Secret
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Secret);
        assert!(t.has_confidential_data());
    }

    #[test]
    fn conf_ceiling_raised_by_internal_node() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::FileRead).unwrap(); // Internal
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Internal);
        assert!(t.has_confidential_data());
    }

    #[test]
    fn conf_ceiling_monotonically_increases() {
        let mut t = FlowTracker::new();
        t.observe(NodeKind::WebContent).unwrap(); // Public
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Public);

        t.observe(NodeKind::FileRead).unwrap(); // Internal
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Internal);

        t.observe(NodeKind::WebContent).unwrap(); // Public — doesn't lower
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Internal);

        t.observe(NodeKind::EnvVar).unwrap(); // Secret — raises
        assert_eq!(t.session_conf_ceiling(), ConfLevel::Secret);
    }

    #[test]
    fn conf_propagates_through_join() {
        let mut t = FlowTracker::new();
        let secret = t.observe(NodeKind::EnvVar).unwrap();
        let public = t.observe(NodeKind::WebContent).unwrap();
        // Joining secret + public → secret (max)
        let combined = t
            .observe_with_parents(NodeKind::ModelPlan, &[secret, public])
            .unwrap();
        let label = t.label(combined).unwrap();
        assert_eq!(label.confidentiality, ConfLevel::Secret);
    }

    #[test]
    fn check_confidentiality_flow_secret_to_secret_ok() {
        let mut t = FlowTracker::new();
        let env = t.observe(NodeKind::EnvVar).unwrap(); // Secret
        assert!(
            t.check_confidentiality_flow(env, ConfLevel::Secret)
                .is_safe()
        );
    }

    #[test]
    fn check_confidentiality_flow_secret_to_public_denied() {
        let mut t = FlowTracker::new();
        let env = t.observe(NodeKind::EnvVar).unwrap(); // Secret
        let check = t.check_confidentiality_flow(env, ConfLevel::Public);
        assert!(check.is_denied());
        assert!(
            matches!(check, SafetyCheck::ConfidentialityViolation { data_conf, sink_max_conf }
                if data_conf == ConfLevel::Secret && sink_max_conf == ConfLevel::Public)
        );
    }

    #[test]
    fn check_confidentiality_flow_secret_to_internal_denied() {
        let mut t = FlowTracker::new();
        let env = t.observe(NodeKind::EnvVar).unwrap(); // Secret
        assert!(
            t.check_confidentiality_flow(env, ConfLevel::Internal)
                .is_denied()
        );
    }

    #[test]
    fn check_confidentiality_flow_internal_to_secret_ok() {
        let mut t = FlowTracker::new();
        let file = t.observe(NodeKind::FileRead).unwrap(); // Internal
        assert!(
            t.check_confidentiality_flow(file, ConfLevel::Secret)
                .is_safe()
        );
    }

    #[test]
    fn check_confidentiality_flow_public_to_public_ok() {
        let mut t = FlowTracker::new();
        let web = t.observe(NodeKind::WebContent).unwrap(); // Public
        assert!(
            t.check_confidentiality_flow(web, ConfLevel::Public)
                .is_safe()
        );
    }

    #[test]
    fn check_confidentiality_flow_unknown_node_fails_closed() {
        let t = FlowTracker::new();
        let check = t.check_confidentiality_flow(999, ConfLevel::Secret);
        assert!(matches!(check, SafetyCheck::UnknownNode { node_id: 999 }));
    }

    // ── Exfiltration safety (combined) tests (#1208) ────────────────

    #[test]
    fn exfiltration_safety_clean_session_to_internal_sink() {
        // UserPrompt is Internal conf — writing to Internal sink is OK.
        let mut t = FlowTracker::new();
        let user = t.observe(NodeKind::UserPrompt).unwrap();
        assert!(
            t.check_exfiltration_safety(user, false, ConfLevel::Internal)
                .is_safe()
        );
    }

    #[test]
    fn exfiltration_safety_secret_node_to_public_sink_denied() {
        let mut t = FlowTracker::new();
        let env = t.observe(NodeKind::EnvVar).unwrap(); // Secret
        let check = t.check_exfiltration_safety(env, false, ConfLevel::Public);
        assert!(check.is_denied());
        assert!(matches!(
            check,
            SafetyCheck::ConfidentialityViolation { .. }
        ));
    }

    #[test]
    fn exfiltration_safety_session_ceiling_blocks_clean_node() {
        // Session has seen Secret data. FileRead is Internal, but the
        // session ceiling (Secret) blocks writing to an Internal sink.
        let mut t = FlowTracker::new();
        let _env = t.observe(NodeKind::EnvVar).unwrap(); // Secret — raises ceiling
        let file = t.observe(NodeKind::FileRead).unwrap(); // Internal, Trusted

        // The file node itself is Internal, but session ceiling is Secret
        let check = t.check_exfiltration_safety(file, false, ConfLevel::Internal);
        assert!(check.is_denied());
        assert!(matches!(
            check,
            SafetyCheck::ConfidentialityViolation {
                data_conf: ConfLevel::Secret,
                sink_max_conf: ConfLevel::Internal,
            }
        ));
    }

    #[test]
    fn exfiltration_safety_session_ceiling_ok_for_secret_sink() {
        // Session has seen Secret but we're writing to a Secret sink — OK.
        let mut t = FlowTracker::new();
        let _env = t.observe(NodeKind::EnvVar).unwrap();
        let file = t.observe(NodeKind::FileRead).unwrap(); // Internal, Trusted
        assert!(
            t.check_exfiltration_safety(file, false, ConfLevel::Secret)
                .is_safe()
        );
    }

    #[test]
    fn exfiltration_safety_integrity_failure_takes_precedence() {
        // Both integrity (adversarial) and confidentiality (secret) violations
        // present — integrity check fires first.
        let mut t = FlowTracker::new();
        let env = t.observe(NodeKind::EnvVar).unwrap(); // Secret + Trusted
        let web = t.observe(NodeKind::WebContent).unwrap(); // Public + Adversarial
        let combined = t
            .observe_with_parents(NodeKind::OutboundAction, &[env, web])
            .unwrap();
        // combined: Secret conf (max), Adversarial integrity (min)
        let check = t.check_exfiltration_safety(combined, false, ConfLevel::Public);
        // Integrity fires first
        assert!(matches!(check, SafetyCheck::AdversarialAncestry { .. }));
    }

    #[test]
    fn exfiltration_safety_authority_check_respected() {
        // Secret node has NoAuthority + Trusted integrity → authority check fires.
        let mut t = FlowTracker::new();
        let secret = t.observe(NodeKind::Secret).unwrap(); // NoAuthority, Secret, Trusted
        let check = t.check_exfiltration_safety(secret, true, ConfLevel::Secret);
        assert!(matches!(check, SafetyCheck::InsufficientAuthority { .. }));
    }

    // ── FlowTracker next_id overflow tests (#1226, #1235) ───────────────

    #[test]
    fn next_id_overflow_returns_error_not_wrap() {
        // #1226/#1235: next_id at u64::MAX should fail, not wrap to 0.
        let mut t = FlowTracker::new();
        // Force next_id to u64::MAX (just before overflow)
        t.next_id = u64::MAX;
        let result = t.observe(NodeKind::FileRead);
        assert!(
            matches!(result, Err(FlowError::IdSpaceExhausted)),
            "expected IdSpaceExhausted, got: {result:?}"
        );
    }

    #[test]
    fn next_id_near_max_still_works() {
        // ID u64::MAX - 1 is the last valid allocation.
        let mut t = FlowTracker::new();
        t.next_id = u64::MAX - 1;
        // This should succeed — assigns ID = u64::MAX - 1, increments to u64::MAX
        let result = t.observe(NodeKind::FileRead);
        assert!(result.is_ok());
        // Next allocation would overflow — should fail
        let result2 = t.observe(NodeKind::FileRead);
        assert!(matches!(result2, Err(FlowError::IdSpaceExhausted)));
    }
}
