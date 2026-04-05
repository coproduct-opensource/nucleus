//! Policy pipeline combinators — composable decision chains (#1148).
//!
//! Replace monolithic decision functions with composable policy checks.
//! Each check is independently testable, Kani-provable, and composes
//! via algebraic combinators (FirstMatch, AllOf, AnyOf, Not).
//!
//! ## Example
//!
//! ```rust,ignore
//! use portcullis_core::combinators::*;
//!
//! let pipeline = first_match(vec![
//!     Box::new(DenyIfBudgetExhausted),
//!     Box::new(DenyIfAdversarialAncestry),
//!     Box::new(AllowIfCapabilitySufficient),
//! ]);
//! let result = pipeline.check(&request);
//! ```

/// Result of a single policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Definitive allow — this check approves the operation.
    Allow,
    /// Definitive deny with reason.
    Deny(String),
    /// Requires human approval before proceeding.
    RequiresApproval(String),
    /// This check has no opinion — pass to the next check in the pipeline.
    Abstain,
}

impl CheckResult {
    /// Whether this result is definitive (not Abstain).
    pub fn is_decided(&self) -> bool {
        !matches!(self, Self::Abstain)
    }

    /// Whether this result allows the operation.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this result denies the operation.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny(_))
    }
}

/// A composable policy check.
///
/// Implement this trait for each independent policy concern (delegation,
/// IFC flow, budget, egress, etc.). Checks compose via combinators.
pub trait PolicyCheck: Send + Sync {
    /// Evaluate this check against a request context.
    fn check(&self, req: &PolicyRequest) -> CheckResult;

    /// Human-readable name for diagnostics.
    fn name(&self) -> &str;
}

/// Request context passed to policy checks.
///
/// Contains the operation being requested and relevant context
/// for making a decision.
#[derive(Debug, Clone)]
pub struct PolicyRequest {
    /// The operation being requested (e.g., "read_files", "web_fetch").
    pub operation: String,
    /// The capability level required for this operation.
    pub required_level: crate::CapabilityLevel,
    /// Additional context as key-value pairs.
    pub context: std::collections::BTreeMap<String, String>,
    /// Optional task witness for task-alignment checks.
    ///
    /// Attach via [`PolicyRequest::with_task_witness`]. Policy checks that
    /// implement task-scope enforcement (e.g., [`crate::task_shield::TaskScopePolicy`])
    /// read this field to constrain operations to the declared task scope.
    pub task_witness: Option<std::sync::Arc<crate::task_shield::TaskWitness>>,
}

impl PolicyRequest {
    /// Create a new request for an operation.
    pub fn new(operation: &str, level: crate::CapabilityLevel) -> Self {
        Self {
            operation: operation.to_string(),
            required_level: level,
            context: std::collections::BTreeMap::new(),
            task_witness: None,
        }
    }

    /// Add a context value.
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }

    /// Attach a [`TaskWitness`] to this request for task-alignment enforcement.
    ///
    /// [`crate::task_shield::TaskScopePolicy`] checks use this to gate operations
    /// against the declared task scope.
    pub fn with_task_witness(
        mut self,
        witness: std::sync::Arc<crate::task_shield::TaskWitness>,
    ) -> Self {
        self.task_witness = Some(witness);
        self
    }

    /// Borrow the attached task witness, if any.
    pub fn task_witness(&self) -> Option<&crate::task_shield::TaskWitness> {
        self.task_witness.as_deref()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Combinators
// ═══════════════════════════════════════════════════════════════════════════

/// First-match: try each check in order, return the first decisive result.
/// If all abstain, returns Abstain.
pub struct FirstMatch {
    checks: Vec<Box<dyn PolicyCheck>>,
}

impl FirstMatch {
    pub fn new(checks: Vec<Box<dyn PolicyCheck>>) -> Self {
        Self { checks }
    }
}

impl PolicyCheck for FirstMatch {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        for c in &self.checks {
            let result = c.check(req);
            if result.is_decided() {
                return result;
            }
        }
        CheckResult::Abstain
    }

    fn name(&self) -> &str {
        "FirstMatch"
    }
}

/// All-of: all checks must allow. If any denies, deny.
///
/// `Abstain` is treated as the identity element (no opinion) — checks that
/// abstain are skipped and do not affect the result. If **all** checks abstain,
/// the combinator returns `Abstain`. This mirrors the lattice identity: a check
/// with no opinion should not change the outcome of the conjunction (#1197).
///
/// This is the meet-combinator on the truth ordering.
pub struct AllOf {
    checks: Vec<Box<dyn PolicyCheck>>,
}

impl AllOf {
    pub fn new(checks: Vec<Box<dyn PolicyCheck>>) -> Self {
        Self { checks }
    }
}

impl PolicyCheck for AllOf {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        let mut saw_approval = false;
        let mut saw_decisive = false;
        for c in &self.checks {
            match c.check(req) {
                CheckResult::Deny(reason) => return CheckResult::Deny(reason),
                CheckResult::RequiresApproval(_) => {
                    saw_approval = true;
                    saw_decisive = true;
                }
                CheckResult::Allow => {
                    saw_decisive = true;
                }
                // Abstain = identity: this check has no opinion; skip it.
                CheckResult::Abstain => {}
            }
        }
        if !saw_decisive {
            return CheckResult::Abstain;
        }
        if saw_approval {
            CheckResult::RequiresApproval("multiple checks require approval".into())
        } else {
            CheckResult::Allow
        }
    }

    fn name(&self) -> &str {
        "AllOf"
    }
}

/// Any-of: if any check allows, allow. Only deny if all deny.
///
/// `Allow` is the join-absorber (top of the truth order for disjunction) and
/// may short-circuit. `RequiresApproval` is accumulated across all checks and
/// only returned if no check returned `Allow` — this preserves commutativity:
/// `AnyOf([A, B])` and `AnyOf([B, A])` produce the same result regardless of
/// order (#1222). Mirrors the accumulation pattern in `AllOf`.
///
/// This is the join-combinator on the truth ordering.
pub struct AnyOf {
    checks: Vec<Box<dyn PolicyCheck>>,
}

impl AnyOf {
    pub fn new(checks: Vec<Box<dyn PolicyCheck>>) -> Self {
        Self { checks }
    }
}

impl PolicyCheck for AnyOf {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        let mut saw_approval = false;
        let mut last_deny = None;
        for c in &self.checks {
            match c.check(req) {
                // Allow is the join absorber — short-circuit is safe and order-independent.
                CheckResult::Allow => return CheckResult::Allow,
                // Accumulate rather than short-circuit: a later Allow must win (#1222).
                CheckResult::RequiresApproval(_) => {
                    saw_approval = true;
                }
                CheckResult::Deny(reason) => last_deny = Some(reason),
                CheckResult::Abstain => {}
            }
        }
        if saw_approval {
            CheckResult::RequiresApproval("any-of escalation".into())
        } else {
            match last_deny {
                Some(reason) => CheckResult::Deny(reason),
                None => CheckResult::Abstain,
            }
        }
    }

    fn name(&self) -> &str {
        "AnyOf"
    }
}

/// Not: flip Allow <-> Deny, leave RequiresApproval and Abstain unchanged.
pub struct Not<T: PolicyCheck> {
    inner: T,
}

impl<T: PolicyCheck> Not<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: PolicyCheck + Send + Sync> PolicyCheck for Not<T> {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        match self.inner.check(req) {
            CheckResult::Allow => CheckResult::Deny("negated: inner allowed".into()),
            CheckResult::Deny(_) => CheckResult::Allow,
            other => other,
        }
    }

    fn name(&self) -> &str {
        "Not"
    }
}

/// Convenience: create a FirstMatch pipeline.
pub fn first_match(checks: Vec<Box<dyn PolicyCheck>>) -> FirstMatch {
    FirstMatch::new(checks)
}

/// Convenience: create an AllOf combinator.
pub fn all_of(checks: Vec<Box<dyn PolicyCheck>>) -> AllOf {
    AllOf::new(checks)
}

/// Convenience: create an AnyOf combinator.
pub fn any_of(checks: Vec<Box<dyn PolicyCheck>>) -> AnyOf {
    AnyOf::new(checks)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysAllow;
    impl PolicyCheck for AlwaysAllow {
        fn check(&self, _: &PolicyRequest) -> CheckResult {
            CheckResult::Allow
        }
        fn name(&self) -> &str {
            "AlwaysAllow"
        }
    }

    struct AlwaysDeny;
    impl PolicyCheck for AlwaysDeny {
        fn check(&self, _: &PolicyRequest) -> CheckResult {
            CheckResult::Deny("denied".into())
        }
        fn name(&self) -> &str {
            "AlwaysDeny"
        }
    }

    struct AlwaysAbstain;
    impl PolicyCheck for AlwaysAbstain {
        fn check(&self, _: &PolicyRequest) -> CheckResult {
            CheckResult::Abstain
        }
        fn name(&self) -> &str {
            "AlwaysAbstain"
        }
    }

    fn req() -> PolicyRequest {
        PolicyRequest::new("test_op", crate::CapabilityLevel::LowRisk)
    }

    #[test]
    fn first_match_returns_first_decisive() {
        let pipeline = first_match(vec![
            Box::new(AlwaysAbstain),
            Box::new(AlwaysDeny),
            Box::new(AlwaysAllow),
        ]);
        assert!(pipeline.check(&req()).is_deny());
    }

    #[test]
    fn first_match_all_abstain() {
        let pipeline = first_match(vec![Box::new(AlwaysAbstain), Box::new(AlwaysAbstain)]);
        assert_eq!(pipeline.check(&req()), CheckResult::Abstain);
    }

    #[test]
    fn all_of_requires_all_allow() {
        let combo = all_of(vec![Box::new(AlwaysAllow), Box::new(AlwaysAllow)]);
        assert!(combo.check(&req()).is_allow());
    }

    #[test]
    fn all_of_one_deny_denies() {
        let combo = all_of(vec![Box::new(AlwaysAllow), Box::new(AlwaysDeny)]);
        assert!(combo.check(&req()).is_deny());
    }

    // ── AllOf Abstain identity semantics (#1197) ─────────────────────────

    #[test]
    fn all_of_abstain_is_identity_not_absorber() {
        // Abstaining check should be skipped; the Allow still wins.
        let combo = all_of(vec![Box::new(AlwaysAbstain), Box::new(AlwaysAllow)]);
        assert!(
            combo.check(&req()).is_allow(),
            "Abstain must not absorb Allow"
        );
    }

    #[test]
    fn all_of_abstain_does_not_hide_deny() {
        // Deny must still win even when another check abstains.
        let combo = all_of(vec![Box::new(AlwaysAbstain), Box::new(AlwaysDeny)]);
        assert!(
            combo.check(&req()).is_deny(),
            "Deny must not be hidden by Abstain"
        );
    }

    #[test]
    fn all_of_abstain_before_deny_does_not_short_circuit() {
        // The critical regression: Abstain before Deny must not short-circuit.
        // Old bug: AllOf returned Abstain immediately on first Abstain, hiding Deny.
        let combo = all_of(vec![
            Box::new(AlwaysAbstain),
            Box::new(AlwaysAbstain),
            Box::new(AlwaysDeny),
        ]);
        assert!(combo.check(&req()).is_deny());
    }

    #[test]
    fn all_of_all_abstain_returns_abstain() {
        // When every check abstains, AllOf itself should abstain.
        let combo = all_of(vec![Box::new(AlwaysAbstain), Box::new(AlwaysAbstain)]);
        assert_eq!(combo.check(&req()), CheckResult::Abstain);
    }

    struct AlwaysRequireApproval;
    impl PolicyCheck for AlwaysRequireApproval {
        fn check(&self, _: &PolicyRequest) -> CheckResult {
            CheckResult::RequiresApproval("approval needed".into())
        }
        fn name(&self) -> &str {
            "AlwaysRequireApproval"
        }
    }

    #[test]
    fn any_of_one_allow_allows() {
        let combo = any_of(vec![Box::new(AlwaysDeny), Box::new(AlwaysAllow)]);
        assert!(combo.check(&req()).is_allow());
    }

    #[test]
    fn any_of_all_deny() {
        let combo = any_of(vec![Box::new(AlwaysDeny), Box::new(AlwaysDeny)]);
        assert!(combo.check(&req()).is_deny());
    }

    // ── AnyOf commutativity (#1222) ──────────────────────────────────────────

    #[test]
    fn any_of_allow_beats_requires_approval_regardless_of_order() {
        // AnyOf([RequiresApproval, Allow]) must equal AnyOf([Allow, RequiresApproval]).
        // Before the fix, the first ordering returned RequiresApproval due to short-circuit.
        let ab = any_of(vec![Box::new(AlwaysRequireApproval), Box::new(AlwaysAllow)]);
        assert!(
            ab.check(&req()).is_allow(),
            "Allow must beat RequiresApproval even when RequiresApproval comes first"
        );

        let ba = any_of(vec![Box::new(AlwaysAllow), Box::new(AlwaysRequireApproval)]);
        assert!(ba.check(&req()).is_allow());
    }

    #[test]
    fn any_of_requires_approval_beats_deny() {
        // RequiresApproval > Deny in truth order for AnyOf.
        let combo = any_of(vec![Box::new(AlwaysRequireApproval), Box::new(AlwaysDeny)]);
        assert!(
            matches!(combo.check(&req()), CheckResult::RequiresApproval(_)),
            "RequiresApproval must beat Deny in AnyOf"
        );

        // Commutative: same result in reverse order.
        let combo2 = any_of(vec![Box::new(AlwaysDeny), Box::new(AlwaysRequireApproval)]);
        assert!(matches!(
            combo2.check(&req()),
            CheckResult::RequiresApproval(_)
        ));
    }

    #[test]
    fn any_of_all_abstain_returns_abstain() {
        let combo = any_of(vec![Box::new(AlwaysAbstain), Box::new(AlwaysAbstain)]);
        assert_eq!(combo.check(&req()), CheckResult::Abstain);
    }

    #[test]
    fn any_of_requires_approval_with_abstain_returns_approval() {
        let combo = any_of(vec![
            Box::new(AlwaysAbstain),
            Box::new(AlwaysRequireApproval),
        ]);
        assert!(matches!(
            combo.check(&req()),
            CheckResult::RequiresApproval(_)
        ));
    }

    #[test]
    fn not_flips_allow_deny() {
        let n = Not::new(AlwaysAllow);
        assert!(n.check(&req()).is_deny());

        let n = Not::new(AlwaysDeny);
        assert!(n.check(&req()).is_allow());
    }

    #[test]
    fn not_preserves_abstain() {
        let n = Not::new(AlwaysAbstain);
        assert_eq!(n.check(&req()), CheckResult::Abstain);
    }

    #[test]
    fn nested_combinators() {
        // AllOf(AnyOf(deny, allow), Not(deny)) = AllOf(allow, allow) = allow
        let inner_any: Box<dyn PolicyCheck> =
            Box::new(any_of(vec![Box::new(AlwaysDeny), Box::new(AlwaysAllow)]));
        let inner_not: Box<dyn PolicyCheck> = Box::new(Not::new(AlwaysDeny));
        let combo = all_of(vec![inner_any, inner_not]);
        assert!(combo.check(&req()).is_allow());
    }

    #[test]
    fn request_context() {
        let r = PolicyRequest::new("web_fetch", crate::CapabilityLevel::LowRisk)
            .with_context("url", "https://example.com")
            .with_context("session_id", "sess_1");
        assert_eq!(r.context.get("url").unwrap(), "https://example.com");
    }
}
