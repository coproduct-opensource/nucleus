//! Built-in policy checks — compose-ready implementations for common patterns.
//!
//! Each check implements [`PolicyCheck`] and composes with `all_of`/`any_of`/`first_match`.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use portcullis_core::combinators::*;
//! use portcullis_core::builtin_checks::*;
//!
//! let policy = all_of(vec![
//!     Box::new(ReadOnly),
//!     Box::new(RequireApprovalFor::new(["git_push", "create_pr"])),
//! ]);
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::CapabilityLevel;
use crate::combinators::{CheckResult, PolicyCheck, PolicyRequest};

// ── Capability checks ──────────────────────────────────────────────────────────

/// Allow reads, deny writes and execution.
///
/// Denies any operation whose required level exceeds `LowRisk` on the
/// truth ordering, treating `Always` as write/exec territory.
///
/// # Example
/// ```rust,ignore
/// let policy = all_of(vec![Box::new(ReadOnly)]);
/// assert!(policy.check(&req("read_files")).is_allow());
/// assert!(policy.check(&req("run_bash")).is_deny());
/// ```
pub struct ReadOnly;

impl PolicyCheck for ReadOnly {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        // Operations that mutate state or execute code require Always-level capability.
        // LowRisk covers read/search; Always covers write/exec/network.
        if req.required_level == CapabilityLevel::Always {
            CheckResult::Deny(format!(
                "read-only policy: {} requires write/exec capability",
                req.operation
            ))
        } else {
            CheckResult::Allow
        }
    }

    fn name(&self) -> &str {
        "ReadOnly"
    }
}

/// Require at least a minimum capability level for any operation.
///
/// Abstains when the operation meets the requirement, denies when it doesn't.
pub struct RequireMinCapability {
    pub minimum: CapabilityLevel,
}

impl RequireMinCapability {
    pub fn new(minimum: CapabilityLevel) -> Self {
        Self { minimum }
    }
}

impl PolicyCheck for RequireMinCapability {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if req.required_level >= self.minimum {
            CheckResult::Abstain
        } else {
            CheckResult::Deny(format!(
                "{}: requires {:?} capability, only {:?} available",
                req.operation, self.minimum, req.required_level
            ))
        }
    }

    fn name(&self) -> &str {
        "RequireMinCapability"
    }
}

/// Deny any operation at `Never` capability level (i.e., disabled operations).
pub struct DenyDisabled;

impl PolicyCheck for DenyDisabled {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if req.required_level == CapabilityLevel::Never {
            CheckResult::Deny(format!(
                "{}: capability is disabled (Never level)",
                req.operation
            ))
        } else {
            CheckResult::Abstain
        }
    }

    fn name(&self) -> &str {
        "DenyDisabled"
    }
}

// ── Approval gates ─────────────────────────────────────────────────────────────

/// Require human approval for a specific set of operations.
///
/// # Example
/// ```rust,ignore
/// RequireApprovalFor::new(["git_push", "create_pr", "manage_pods"])
/// ```
pub struct RequireApprovalFor {
    operations: BTreeSet<String>,
}

impl RequireApprovalFor {
    pub fn new<I, S>(ops: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            operations: ops.into_iter().map(Into::into).collect(),
        }
    }
}

impl PolicyCheck for RequireApprovalFor {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if self.operations.contains(&req.operation) {
            CheckResult::RequiresApproval(format!("{}: requires human approval", req.operation))
        } else {
            CheckResult::Abstain
        }
    }

    fn name(&self) -> &str {
        "RequireApprovalFor"
    }
}

/// Deny a specific set of operations entirely.
pub struct DenyOperations {
    operations: BTreeSet<String>,
    reason: String,
}

impl DenyOperations {
    pub fn new<I, S>(ops: I, reason: impl Into<String>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            operations: ops.into_iter().map(Into::into).collect(),
            reason: reason.into(),
        }
    }
}

impl PolicyCheck for DenyOperations {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if self.operations.contains(&req.operation) {
            CheckResult::Deny(format!("{}: {}", req.operation, self.reason))
        } else {
            CheckResult::Abstain
        }
    }

    fn name(&self) -> &str {
        "DenyOperations"
    }
}

// ── Context-based checks ───────────────────────────────────────────────────────

/// Deny if the request context contains a key matching a given value.
///
/// # Example
/// ```rust,ignore
/// // Deny web_fetch during code_review mode
/// DenyWhenContextMatches::new("mode", "code_review", ["web_fetch"])
/// ```
pub struct DenyWhenContextMatches {
    key: String,
    value: String,
    restricted_ops: BTreeSet<String>,
}

impl DenyWhenContextMatches {
    pub fn new<I, S>(key: impl Into<String>, value: impl Into<String>, ops: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            key: key.into(),
            value: value.into(),
            restricted_ops: ops.into_iter().map(Into::into).collect(),
        }
    }
}

impl PolicyCheck for DenyWhenContextMatches {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        let matches_op =
            self.restricted_ops.is_empty() || self.restricted_ops.contains(&req.operation);
        if matches_op
            && let Some(v) = req.context.get(&self.key)
            && v == &self.value
        {
            return CheckResult::Deny(format!(
                "{}: denied when {}={}",
                req.operation, self.key, self.value
            ));
        }
        CheckResult::Abstain
    }

    fn name(&self) -> &str {
        "DenyWhenContextMatches"
    }
}

/// Deny if a specific context key is present with an adversarial taint marker.
///
/// Checks for `taint=adversarial` in the request context, which is set by
/// IFC tracking when data flows from untrusted sources.
pub struct DenyAdversarialTaint;

impl PolicyCheck for DenyAdversarialTaint {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if req.context.get("taint").map(|s| s.as_str()) == Some("adversarial") {
            CheckResult::Deny(format!(
                "{}: denied — adversarial taint detected in request context",
                req.operation
            ))
        } else {
            CheckResult::Abstain
        }
    }

    fn name(&self) -> &str {
        "DenyAdversarialTaint"
    }
}

/// Deny if the request comes from an untrusted source compartment.
///
/// Checks `source_trust=untrusted` in the request context.
pub struct RequireTrustedSource;

impl PolicyCheck for RequireTrustedSource {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        match req.context.get("source_trust").map(|s| s.as_str()) {
            Some("trusted") => CheckResult::Abstain,
            Some("untrusted") => CheckResult::Deny(format!(
                "{}: denied — operation originates from untrusted source",
                req.operation
            )),
            // Fail-closed: absent or unrecognized source_trust key is denied (#1211).
            // An attacker who omits the key must not get a free pass through AllOf.
            None | Some(_) => CheckResult::Deny(format!(
                "{}: denied — source_trust context key absent or unrecognized value",
                req.operation
            )),
        }
    }

    fn name(&self) -> &str {
        "RequireTrustedSource"
    }
}

// ── Budget gate ────────────────────────────────────────────────────────────────

/// Deny operations once a cumulative budget (in micro-USD) is exhausted.
///
/// Budget is tracked atomically — safe for concurrent policy evaluation.
/// The budget is shared across all clones of this check.
///
/// ## Atomic reservation (eliminates TOCTOU window, #1179 / #1196)
///
/// When the caller passes `cost_micro_usd` in the [`PolicyRequest`] context,
/// `check()` atomically reserves that amount using a compare-and-swap loop.
/// This eliminates both the TOCTOU window and the wrapping-arithmetic race that
/// affects fetch_add + rollback under high concurrency.
///
/// ```rust,ignore
/// let req = PolicyRequest::new("web_fetch", CapabilityLevel::LowRisk)
///     .with_context("cost_micro_usd", "1500");
/// // check() will atomically reserve 1500 µUSD — no separate record_cost() needed.
/// ```
///
/// When `cost_micro_usd` is not in context, `check()` falls back to a snapshot
/// read (with `Acquire` ordering, so cross-thread writes are visible) and the
/// caller is responsible for calling `record_cost()` separately.
///
/// # Example
/// ```rust,ignore
/// let gate = BudgetGate::new(1_000_000); // $1.00 limit
/// gate.record_cost(500_000);             // $0.50 spent
/// assert!(gate.check(&req("any_op")).is_abstain());
/// gate.record_cost(600_000);             // now $1.10 total
/// assert!(gate.check(&req("any_op")).is_deny());
/// ```
pub struct BudgetGate {
    max_micro_usd: u64,
    spent_micro_usd: Arc<AtomicU64>,
}

impl BudgetGate {
    /// Create a new budget gate with the given limit in micro-USD (1 USD = 1_000_000).
    pub fn new(max_micro_usd: u64) -> Self {
        Self {
            max_micro_usd,
            spent_micro_usd: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record additional cost in micro-USD.
    ///
    /// Uses a CAS loop with saturating addition so the counter can never wrap
    /// past `u64::MAX` and silently reopen the budget (#1210).
    pub fn record_cost(&self, micro_usd: u64) {
        let mut current = self.spent_micro_usd.load(Ordering::Acquire);
        loop {
            let new_val = current.saturating_add(micro_usd);
            match self.spent_micro_usd.compare_exchange_weak(
                current,
                new_val,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Current total spend in micro-USD.
    ///
    /// Uses `Acquire` ordering so this read sees all preceding `record_cost` writes.
    pub fn spent(&self) -> u64 {
        self.spent_micro_usd.load(Ordering::Acquire)
    }

    /// Remaining budget in micro-USD.
    pub fn remaining(&self) -> u64 {
        self.max_micro_usd.saturating_sub(self.spent())
    }

    /// Atomically try to reserve `cost` µUSD, returning `true` if successful.
    ///
    /// Uses a compare-and-swap loop to avoid the wrapping-arithmetic race in
    /// fetch_add + rollback: under concurrent pressure, a wrapping fetch_add
    /// could temporarily expose a small counter value to a racing thread before
    /// the rollback fires, allowing the racing thread to bypass the limit (#1196).
    pub fn try_reserve(&self, cost: u64) -> bool {
        let mut current = self.spent_micro_usd.load(Ordering::Acquire);
        loop {
            let new = match current.checked_add(cost) {
                Some(n) if n <= self.max_micro_usd => n,
                _ => return false,
            };
            match self.spent_micro_usd.compare_exchange_weak(
                current,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
}

impl Clone for BudgetGate {
    fn clone(&self) -> Self {
        Self {
            max_micro_usd: self.max_micro_usd,
            spent_micro_usd: Arc::clone(&self.spent_micro_usd),
        }
    }
}

impl PolicyCheck for BudgetGate {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        // If caller provides expected cost, use atomic reservation to eliminate TOCTOU.
        if let Some(cost) = req
            .context
            .get("cost_micro_usd")
            .and_then(|s| s.parse::<u64>().ok())
        {
            if !self.try_reserve(cost) {
                return CheckResult::Deny(format!(
                    "{}: budget exhausted — cannot reserve {} µUSD ({}/{} µUSD used)",
                    req.operation,
                    cost,
                    self.spent(),
                    self.max_micro_usd
                ));
            }
            return CheckResult::Abstain;
        }

        // Fallback: snapshot read (Acquire ensures cross-thread visibility).
        // Caller must call record_cost() separately — a TOCTOU window remains
        // but cross-thread write visibility is now correct.
        if self.spent() >= self.max_micro_usd {
            CheckResult::Deny(format!(
                "{}: budget exhausted ({}/{} µUSD)",
                req.operation,
                self.spent(),
                self.max_micro_usd
            ))
        } else {
            CheckResult::Abstain
        }
    }

    fn name(&self) -> &str {
        "BudgetGate"
    }
}

// ── Rate limiter ───────────────────────────────────────────────────────────────

/// Deny operations once a counter limit is exceeded within a session.
///
/// This is a simple counter-based rate limiter (not time-windowed).
///
/// ## Atomic slot reservation (eliminates TOCTOU window, #1179 / #1196)
///
/// `check()` atomically reserves a call slot via a compare-and-swap loop.
/// This eliminates both the TOCTOU window and the wrapping-arithmetic race that
/// affects fetch_add + rollback under high concurrency.
///
/// `record_call()` is kept for backward compatibility but is a no-op when the
/// caller uses `check()` — slots are consumed by `check()` itself.
///
/// For time-windowed rate limiting, integrate with an external clock.
pub struct RateLimit {
    max_calls: u64,
    call_count: Arc<AtomicU64>,
}

impl RateLimit {
    pub fn new(max_calls: u64) -> Self {
        Self {
            max_calls,
            call_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// No-op: kept for API backward compatibility.
    ///
    /// `check()` now atomically consumes a call slot, so separate `record_call()`
    /// is no longer needed and would double-count. Callers that previously did
    /// `check()` + `record_call()` should remove the `record_call()` call.
    #[deprecated(
        since = "1.0.0",
        note = "check() now atomically reserves a slot; calling record_call() separately double-counts"
    )]
    pub fn record_call(&self) {
        // Intentional no-op: slot reservation moved into check() (#1179).
    }

    /// Current consumed call count.
    ///
    /// Uses `Acquire` ordering so cross-thread writes are visible.
    pub fn count(&self) -> u64 {
        self.call_count.load(Ordering::Acquire)
    }
}

impl Clone for RateLimit {
    fn clone(&self) -> Self {
        Self {
            max_calls: self.max_calls,
            call_count: Arc::clone(&self.call_count),
        }
    }
}

impl PolicyCheck for RateLimit {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        // CAS loop: atomically reserve one call slot without the wrapping-arithmetic
        // race that fetch_add + rollback has under high concurrency (#1196).
        let mut current = self.call_count.load(Ordering::Acquire);
        loop {
            if current >= self.max_calls {
                return CheckResult::Deny(format!(
                    "{}: rate limit exceeded ({}/{} calls)",
                    req.operation, current, self.max_calls
                ));
            }
            match self.call_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return CheckResult::Abstain,
                Err(actual) => current = actual,
            }
        }
    }

    fn name(&self) -> &str {
        "RateLimit"
    }
}

// ── Common composition helpers ─────────────────────────────────────────────────

/// Pre-built check: deny web_fetch and web_search during code review mode.
///
/// Checks `mode=code_review` in request context.
pub fn no_web_during_code_review() -> DenyWhenContextMatches {
    DenyWhenContextMatches::new("mode", "code_review", ["web_fetch", "web_search"])
}

/// Pre-built check: require approval for destructive git operations.
pub fn approval_for_git_push() -> RequireApprovalFor {
    RequireApprovalFor::new(["git_push", "create_pr"])
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combinators::{all_of, any_of, first_match};

    fn req(op: &str) -> PolicyRequest {
        PolicyRequest::new(op, CapabilityLevel::LowRisk)
    }

    fn req_always(op: &str) -> PolicyRequest {
        PolicyRequest::new(op, CapabilityLevel::Always)
    }

    fn req_never(op: &str) -> PolicyRequest {
        PolicyRequest::new(op, CapabilityLevel::Never)
    }

    // ── ReadOnly ────────────────────────────────────────────────────────────

    #[test]
    fn read_only_allows_low_risk() {
        assert!(ReadOnly.check(&req("read_files")).is_allow());
    }

    #[test]
    fn read_only_denies_always() {
        assert!(ReadOnly.check(&req_always("run_bash")).is_deny());
    }

    #[test]
    fn read_only_allows_never_level() {
        // Never-level means the operation is disabled but we don't double-deny here
        let r = ReadOnly.check(&req_never("run_bash"));
        assert!(r.is_allow() || matches!(r, CheckResult::Abstain));
    }

    // ── RequireMinCapability ─────────────────────────────────────────────────

    #[test]
    fn require_min_cap_abstains_when_sufficient() {
        let check = RequireMinCapability::new(CapabilityLevel::LowRisk);
        assert_eq!(check.check(&req_always("op")), CheckResult::Abstain);
    }

    #[test]
    fn require_min_cap_denies_when_insufficient() {
        let check = RequireMinCapability::new(CapabilityLevel::Always);
        assert!(check.check(&req("op")).is_deny());
    }

    // ── DenyDisabled ─────────────────────────────────────────────────────────

    #[test]
    fn deny_disabled_denies_never() {
        assert!(DenyDisabled.check(&req_never("run_bash")).is_deny());
    }

    #[test]
    fn deny_disabled_abstains_otherwise() {
        assert_eq!(DenyDisabled.check(&req("read_files")), CheckResult::Abstain);
    }

    // ── RequireApprovalFor ───────────────────────────────────────────────────

    #[test]
    fn approval_for_listed_ops() {
        let check = RequireApprovalFor::new(["git_push", "create_pr"]);
        assert!(matches!(
            check.check(&req("git_push")),
            CheckResult::RequiresApproval(_)
        ));
        assert!(matches!(
            check.check(&req("create_pr")),
            CheckResult::RequiresApproval(_)
        ));
        assert_eq!(check.check(&req("read_files")), CheckResult::Abstain);
    }

    // ── DenyOperations ───────────────────────────────────────────────────────

    #[test]
    fn deny_operations_set() {
        let check = DenyOperations::new(["run_bash"], "bash not allowed in this profile");
        assert!(check.check(&req("run_bash")).is_deny());
        assert_eq!(check.check(&req("read_files")), CheckResult::Abstain);
    }

    // ── DenyWhenContextMatches ───────────────────────────────────────────────

    #[test]
    fn deny_web_during_review() {
        let check = no_web_during_code_review();
        let r = PolicyRequest::new("web_fetch", CapabilityLevel::LowRisk)
            .with_context("mode", "code_review");
        assert!(check.check(&r).is_deny());
    }

    #[test]
    fn allow_web_outside_review() {
        let check = no_web_during_code_review();
        let r = PolicyRequest::new("web_fetch", CapabilityLevel::LowRisk)
            .with_context("mode", "general");
        assert_eq!(check.check(&r), CheckResult::Abstain);
    }

    // ── DenyAdversarialTaint ─────────────────────────────────────────────────

    #[test]
    fn adversarial_taint_denies() {
        let r = req("read_files").with_context("taint", "adversarial");
        assert!(DenyAdversarialTaint.check(&r).is_deny());
    }

    #[test]
    fn no_taint_abstains() {
        assert_eq!(
            DenyAdversarialTaint.check(&req("read_files")),
            CheckResult::Abstain
        );
    }

    // ── RequireTrustedSource ─────────────────────────────────────────────────

    #[test]
    fn untrusted_source_denies() {
        let r = req("web_fetch").with_context("source_trust", "untrusted");
        assert!(RequireTrustedSource.check(&r).is_deny());
    }

    #[test]
    fn trusted_source_abstains() {
        let r = req("web_fetch").with_context("source_trust", "trusted");
        assert_eq!(RequireTrustedSource.check(&r), CheckResult::Abstain);
    }

    // ── BudgetGate ───────────────────────────────────────────────────────────

    #[test]
    fn budget_gate_allows_under_limit() {
        let gate = BudgetGate::new(1_000_000);
        gate.record_cost(500_000);
        assert_eq!(gate.check(&req("any_op")), CheckResult::Abstain);
    }

    #[test]
    fn budget_gate_denies_at_limit() {
        let gate = BudgetGate::new(1_000_000);
        gate.record_cost(1_000_000);
        assert!(gate.check(&req("any_op")).is_deny());
    }

    #[test]
    fn budget_gate_shared_across_clones() {
        let gate = BudgetGate::new(500_000);
        let gate2 = gate.clone();
        gate2.record_cost(500_000);
        assert!(gate.check(&req("op")).is_deny());
    }

    #[test]
    fn budget_gate_remaining() {
        let gate = BudgetGate::new(1_000_000);
        gate.record_cost(300_000);
        assert_eq!(gate.remaining(), 700_000);
    }

    #[test]
    fn budget_gate_atomic_reservation_via_context() {
        // Passing cost_micro_usd in context uses atomic try_reserve (#1179).
        let gate = BudgetGate::new(1_000_000);
        let req_with_cost = PolicyRequest::new("web_fetch", CapabilityLevel::LowRisk)
            .with_context("cost_micro_usd", "400000");
        assert_eq!(gate.check(&req_with_cost), CheckResult::Abstain);
        assert_eq!(gate.spent(), 400_000);
        // Second request that would exceed budget is denied and rolled back.
        let req2 = PolicyRequest::new("web_fetch", CapabilityLevel::LowRisk)
            .with_context("cost_micro_usd", "700000");
        assert!(gate.check(&req2).is_deny());
        // Spent should still be 400_000 (rollback succeeded).
        assert_eq!(gate.spent(), 400_000);
    }

    #[test]
    fn budget_gate_try_reserve_rollback() {
        let gate = BudgetGate::new(100);
        assert!(gate.try_reserve(80));
        assert!(!gate.try_reserve(30)); // 80+30=110 > 100 → deny + rollback
        assert_eq!(gate.spent(), 80); // only 80 committed
    }

    // ── RateLimit ────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_allows_under_max() {
        // check() atomically reserves slots (#1179).
        let rl = RateLimit::new(3);
        assert_eq!(rl.check(&req("op")), CheckResult::Abstain); // slot 1
        assert_eq!(rl.check(&req("op")), CheckResult::Abstain); // slot 2
        assert_eq!(rl.check(&req("op")), CheckResult::Abstain); // slot 3 (last)
    }

    #[test]
    fn rate_limit_denies_at_max() {
        let rl = RateLimit::new(2);
        assert_eq!(rl.check(&req("op")), CheckResult::Abstain); // slot 1
        assert_eq!(rl.check(&req("op")), CheckResult::Abstain); // slot 2
        assert!(rl.check(&req("op")).is_deny()); // over limit
    }

    #[test]
    fn rate_limit_count_reflects_consumed_slots() {
        let rl = RateLimit::new(5);
        rl.check(&req("op"));
        rl.check(&req("op"));
        assert_eq!(rl.count(), 2);
    }

    #[test]
    fn rate_limit_rollback_on_deny_keeps_count_stable() {
        let rl = RateLimit::new(1);
        assert_eq!(rl.check(&req("op")), CheckResult::Abstain); // 1 consumed
        assert!(rl.check(&req("op")).is_deny()); // over limit, rolled back
        assert_eq!(rl.count(), 1); // still 1, not 2
    }

    // ── Composition ──────────────────────────────────────────────────────────

    #[test]
    fn compose_read_only_with_approval_gate() {
        let policy = all_of(vec![
            Box::new(ReadOnly),
            Box::new(RequireApprovalFor::new(["git_push"])),
        ]);

        // Low-risk read: ReadOnly allows, RequireApprovalFor abstains (no opinion).
        // AllOf treats Abstain as identity, so the Allow from ReadOnly wins (#1197).
        assert_eq!(policy.check(&req("read_files")), CheckResult::Allow);

        // Always-level write: deny (ReadOnly short-circuits before RequireApprovalFor)
        assert!(policy.check(&req_always("run_bash")).is_deny());

        // Listed op at LowRisk: ReadOnly allows, then RequireApprovalFor fires
        assert!(matches!(
            policy.check(&req("git_push")),
            CheckResult::RequiresApproval(_)
        ));
    }

    #[test]
    fn compose_budget_and_taint() {
        let budget = BudgetGate::new(1_000_000);
        budget.record_cost(1_000_000); // exhausted

        let policy = first_match(vec![Box::new(DenyAdversarialTaint), Box::new(budget)]);

        // Budget exhausted
        assert!(policy.check(&req("op")).is_deny());

        // Adversarial taint caught first
        let tainted = req("op").with_context("taint", "adversarial");
        assert!(policy.check(&tainted).is_deny());
    }

    #[test]
    fn any_of_trusted_sources() {
        let policy = any_of(vec![
            Box::new(RequireTrustedSource),
            Box::new(DenyAdversarialTaint),
        ]);

        // Absent source_trust key: fail-closed → deny (#1211).
        // An attacker who omits the key must not pass through any_of/all_of.
        assert!(policy.check(&req("op")).is_deny());

        // Explicit untrusted source: also denies.
        let r = req("op").with_context("source_trust", "untrusted");
        assert!(policy.check(&r).is_deny());

        // Explicit trusted source: abstains (passes through to next check).
        let r = req("op").with_context("source_trust", "trusted");
        assert_eq!(policy.check(&r), CheckResult::Abstain);
    }
}
