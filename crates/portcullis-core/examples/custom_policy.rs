//! Custom policy combinator demo — add a policy check in 10 lines.
//!
//! Run with: `cargo run -p portcullis-core --example custom_policy`
//!
//! Shows the progressive DX levels:
//! - Level 0: Implement PolicyCheck (one trait, one method)
//! - Level 1: Compose with combinators (all_of, any_of, first_match)
//! - Level 2: Use Verdict bilattice for contradiction detection

use portcullis_core::CapabilityLevel;
use portcullis_core::bilattice::Verdict;
use portcullis_core::combinators::*;

// ═══════════════════════════════════════════════════════════════════════════
// Level 0: Implement a custom policy check (10 lines)
// ═══════════════════════════════════════════════════════════════════════════

/// A simple rate limiter — deny if too many requests.
struct RateLimit {
    max: u32,
    current: std::sync::atomic::AtomicU32,
}

impl RateLimit {
    fn new(max: u32) -> Self {
        Self {
            max,
            current: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl PolicyCheck for RateLimit {
    fn check(&self, _req: &PolicyRequest) -> CheckResult {
        let count = self
            .current
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if count > self.max {
            CheckResult::Deny(format!("rate limited: {count}/{}", self.max))
        } else {
            CheckResult::Allow
        }
    }
    fn name(&self) -> &str {
        "RateLimit"
    }
}

/// Deny web access during code review.
struct NoWebInReview;

impl PolicyCheck for NoWebInReview {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if req.context.get("mode") == Some(&"code_review".to_string())
            && (req.operation == "web_fetch" || req.operation == "web_search")
        {
            CheckResult::Deny("no web access during code review".into())
        } else {
            CheckResult::Abstain // no opinion on non-web ops
        }
    }
    fn name(&self) -> &str {
        "NoWebInReview"
    }
}

/// Require approval for git push.
struct RequireApprovalForPush;

impl PolicyCheck for RequireApprovalForPush {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        if req.operation == "git_push" {
            CheckResult::RequiresApproval("git push requires human approval".into())
        } else {
            CheckResult::Abstain
        }
    }
    fn name(&self) -> &str {
        "RequireApprovalForPush"
    }
}

fn main() {
    println!("=== Policy Combinator Demo ===\n");

    // ── Level 1: Compose checks ────────────────────────────────────

    let policy = first_match(vec![
        // Rate limit applies first (deny fast if exceeded)
        Box::new(RateLimit::new(3)),
        // Then check mode-specific rules
        Box::new(NoWebInReview),
        // Then check approval requirements
        Box::new(RequireApprovalForPush),
    ]);

    // Simulate some requests
    let requests = [
        PolicyRequest::new("read_file", CapabilityLevel::LowRisk),
        PolicyRequest::new("web_fetch", CapabilityLevel::LowRisk)
            .with_context("mode", "code_review"),
        PolicyRequest::new("git_push", CapabilityLevel::LowRisk),
        PolicyRequest::new("read_file", CapabilityLevel::LowRisk),
        PolicyRequest::new("read_file", CapabilityLevel::LowRisk), // 5th request, rate limited
    ];

    for (i, req) in requests.iter().enumerate() {
        let result = policy.check(req);
        println!("  Request {}: {} -> {:?}", i + 1, req.operation, result);
    }

    // ── Level 2: Bilattice contradiction detection ─────────────────

    println!("\n=== Bilattice Contradiction Detection ===\n");

    // Two policy sources disagree about web_fetch:
    let delegation_says = Verdict::Allow; // delegation grants the capability
    let ifc_says = Verdict::Deny; // but IFC detects adversarial taint

    // info_join detects the contradiction
    let combined = delegation_says.info_join(ifc_says);
    println!("  Delegation says: {delegation_says}");
    println!("  IFC says:        {ifc_says}");
    println!("  Combined:        {combined}");
    println!("  Is conflict?     {}", combined.is_conflict());

    // truth_meet is more conservative — just picks the restriction
    let conservative = delegation_says.truth_meet(ifc_says);
    println!("\n  Conservative (truth_meet): {conservative}");
    println!("  → bilattice tells you WHY: conflict vs simple deny");

    // De Morgan: negate(a AND b) = (NOT a) OR (NOT b)
    let a = Verdict::Allow;
    let b = Verdict::Deny;
    let lhs = a.truth_meet(b).negate();
    let rhs = a.negate().truth_join(b.negate());
    println!(
        "\n  De Morgan duality holds: ¬(A∧D) = {lhs}, ¬A∨¬D = {rhs}, equal = {}",
        lhs == rhs
    );

    println!("\n=== Summary ===");
    println!("  Level 0: Implement PolicyCheck (one trait)");
    println!("  Level 1: Compose with first_match/all_of/any_of");
    println!("  Level 2: Use Verdict bilattice for rich diagnostics");
    println!("  Level 3: Lean proofs verify your policy algebra (see FORMAL_METHODS.md)");
}
