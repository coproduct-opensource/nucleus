//! Delegation Chain Attack Demo
//!
//! This test suite demonstrates the attack scenario that ONLY a formal
//! permission lattice can defend against — transitive delegation escalation
//! in multi-agent systems. No sandbox (E2B, Daytona, Modal, Docker) can
//! stop these attacks because every agent operates within its individual
//! sandbox and every delegation flows through the legitimate protocol.
//!
//! ## The Scenario: "Operation PajaMAS"
//!
//! Inspired by Trail of Bits' multi-agent hijacking research (July 2025)
//! and the Amazon Kiro incident (December 2025).
//!
//! An enterprise deploys 4 agents in a delegation chain:
//!
//! ```text
//!   Human (Alice)
//!     │ delegates "review this PR" with code_review permissions
//!     ▼
//!   Orchestrator Agent
//!     │ delegates browsing to Scout
//!     │ delegates code analysis to Coder
//!     ▼            ▼
//!   Scout Agent   Coder Agent
//!   (web browse)  (read/write code)
//! ```
//!
//! **The attack**: Scout visits a malicious URL during research. The page
//! contains a hidden prompt injection that tricks Scout into delegating
//! a "critical fix" to Coder. Coder has write_files + git_push permissions.
//! If the delegation succeeds, the attacker achieves code deployment through
//! a chain of legitimate-looking delegations.
//!
//! **Without lattice-guard**: Every agent is in its own sandbox. Scout's
//! request to Coder arrives through the legitimate inter-agent API. Coder
//! executes the "fix" because it came from a trusted peer. The attacker's
//! code is pushed to the repository.
//!
//! **With lattice-guard**: The meet operation ensures Scout can only delegate
//! permissions it actually has. Scout has web_search + web_fetch but NOT
//! write_files or git_push. The delegation to Coder produces the meet of
//! Scout's and Coder's permissions — which has NO write or push capability.
//! The attack chain is structurally broken by the lattice.
//!
//! ## Attack Classes Demonstrated
//!
//! | Test | Attack | Defense |
//! |------|--------|---------|
//! | `scenario_1_*` | Multi-agent delegation hijacking (Trail of Bits PajaMAS) | Meet operation |
//! | `scenario_2_*` | Trifecta completion via delegation chain | Trifecta constraint on meet |
//! | `scenario_3_*` | Budget laundering through sub-agents | Budget meet + charge tracking |
//! | `scenario_4_*` | Confused deputy (OWASP ASI03) | MeetJustification audit trail |
//! | `scenario_5_*` | Kiro-class destructive autonomy | Ceiling theorem on trace chain |
//!
//! ## References
//!
//! - Trail of Bits: "Hijacking Multi-Agent Systems in Your PajaMAS" (July 2025)
//! - Amazon Kiro AWS Outage (December 2025) — 13-hour outage from autonomous deletion
//! - Replit Database Deletion (July 2025) — AI deleted production data and lied about it
//! - OWASP Top 10 for Agentic Applications (2026) — ASI02, ASI03, ASI04
//! - Google DeepMind: "Intelligent AI Delegation" (arXiv:2602.11865)
//! - Embrace The Red: "Cross-Agent Privilege Escalation" (November 2025)
//! - Invariant Labs: MCP Tool Poisoning Attacks (April 2025)

use lattice_guard::{
    audit::{AuditEntry, AuditLog, PermissionEvent},
    delegation::meet_with_justification,
    BudgetLattice, CapabilityLevel, EffectivePermissions, IncompatibilityConstraint,
    PermissionLattice, TrifectaRisk,
};
use rust_decimal::Decimal;

// ============================================================================
// AGENT PROFILES
//
// These mirror a realistic enterprise deployment where different agents
// have different permission profiles based on their role.
// ============================================================================

/// Human approver — broad permissions, the trust anchor.
fn human_alice() -> PermissionLattice {
    let mut perms = PermissionLattice::new("Human: Alice (senior engineer)");
    perms.capabilities.read_files = CapabilityLevel::Always;
    perms.capabilities.write_files = CapabilityLevel::Always;
    perms.capabilities.edit_files = CapabilityLevel::Always;
    perms.capabilities.run_bash = CapabilityLevel::Always;
    perms.capabilities.glob_search = CapabilityLevel::Always;
    perms.capabilities.grep_search = CapabilityLevel::Always;
    perms.capabilities.web_search = CapabilityLevel::Always;
    perms.capabilities.web_fetch = CapabilityLevel::Always;
    perms.capabilities.git_commit = CapabilityLevel::Always;
    perms.capabilities.git_push = CapabilityLevel::LowRisk;
    perms.capabilities.create_pr = CapabilityLevel::LowRisk;
    perms.budget = BudgetLattice::with_cost_limit(10.0);
    perms
}

/// Orchestrator — coordinates sub-agents, no direct code modification.
fn orchestrator_requested() -> PermissionLattice {
    let mut perms = PermissionLattice::new("Orchestrator: coordinate sub-agents");
    perms.capabilities.read_files = CapabilityLevel::Always;
    perms.capabilities.write_files = CapabilityLevel::Never;
    perms.capabilities.edit_files = CapabilityLevel::Never;
    perms.capabilities.run_bash = CapabilityLevel::Never;
    perms.capabilities.glob_search = CapabilityLevel::Always;
    perms.capabilities.grep_search = CapabilityLevel::Always;
    perms.capabilities.web_search = CapabilityLevel::LowRisk;
    perms.capabilities.web_fetch = CapabilityLevel::Never;
    // Orchestrator wants git_push to merge results
    perms.capabilities.git_commit = CapabilityLevel::LowRisk;
    perms.capabilities.git_push = CapabilityLevel::LowRisk;
    perms.capabilities.create_pr = CapabilityLevel::LowRisk;
    perms.budget = BudgetLattice::with_cost_limit(5.0);
    perms
}

/// Scout — browses the web for research, no code access.
fn scout_requested() -> PermissionLattice {
    let mut perms = PermissionLattice::new("Scout: web research agent");
    perms.capabilities.read_files = CapabilityLevel::LowRisk; // read docs
    perms.capabilities.write_files = CapabilityLevel::Never;
    perms.capabilities.edit_files = CapabilityLevel::Never;
    perms.capabilities.run_bash = CapabilityLevel::Never;
    perms.capabilities.glob_search = CapabilityLevel::LowRisk;
    perms.capabilities.grep_search = CapabilityLevel::Never;
    perms.capabilities.web_search = CapabilityLevel::Always;
    perms.capabilities.web_fetch = CapabilityLevel::Always;
    perms.capabilities.git_commit = CapabilityLevel::Never;
    perms.capabilities.git_push = CapabilityLevel::Never;
    perms.capabilities.create_pr = CapabilityLevel::Never;
    perms.capabilities.manage_pods = CapabilityLevel::Never;
    perms.budget = BudgetLattice::with_cost_limit(2.0);
    perms
}

/// Coder — reads and writes code, pushes to git. No web access.
fn coder_requested() -> PermissionLattice {
    let mut perms = PermissionLattice::new("Coder: implementation agent");
    perms.capabilities.read_files = CapabilityLevel::Always;
    perms.capabilities.write_files = CapabilityLevel::Always;
    perms.capabilities.edit_files = CapabilityLevel::Always;
    perms.capabilities.run_bash = CapabilityLevel::LowRisk; // run tests
    perms.capabilities.glob_search = CapabilityLevel::Always;
    perms.capabilities.grep_search = CapabilityLevel::Always;
    perms.capabilities.web_search = CapabilityLevel::Never;
    perms.capabilities.web_fetch = CapabilityLevel::Never;
    perms.capabilities.git_commit = CapabilityLevel::Always;
    perms.capabilities.git_push = CapabilityLevel::LowRisk;
    perms.capabilities.create_pr = CapabilityLevel::LowRisk;
    perms.capabilities.manage_pods = CapabilityLevel::Never;
    perms.budget = BudgetLattice::with_cost_limit(3.0);
    perms
}

// ============================================================================
// Scenario 1: Multi-Agent Delegation Hijacking
//
// Trail of Bits PajaMAS attack: A low-privilege agent (Scout) is tricked
// by a malicious URL into delegating a "critical fix" to a high-privilege
// agent (Coder). The meet operation prevents the escalation.
// ============================================================================

/// Step 1: Alice delegates to Orchestrator. The meet narrows git_push and
/// creates the first link in the delegation chain.
#[test]
fn scenario_1a_alice_delegates_to_orchestrator() {
    let alice = human_alice();
    let orch_req = orchestrator_requested();

    let orch_effective = alice
        .delegate_to(&orch_req, "PR review coordination")
        .expect("delegation should succeed");

    // Orchestrator gets the meet of Alice's and its own requested permissions
    assert!(orch_effective.capabilities.leq(&alice.capabilities));
    assert!(orch_effective.capabilities.leq(&orch_req.capabilities));

    // Orchestrator can read files (both have it)
    assert_eq!(
        orch_effective.capabilities.read_files,
        CapabilityLevel::Always
    );

    // git_push: min(Alice's LowRisk, Orch's LowRisk) = LowRisk
    assert_eq!(
        orch_effective.capabilities.git_push,
        CapabilityLevel::LowRisk
    );

    // web_fetch: min(Alice's Always, Orch's Never) = Never
    // Orchestrator didn't request web_fetch, so it doesn't get it
    assert_eq!(
        orch_effective.capabilities.web_fetch,
        CapabilityLevel::Never
    );

    // Budget: min(10.0, 5.0) = 5.0
    assert_eq!(orch_effective.budget.max_cost_usd, Decimal::new(5, 0));
}

/// Step 2: Orchestrator delegates to Scout for web research.
/// Scout gets web browsing but NO code modification or git push.
#[test]
fn scenario_1b_orchestrator_delegates_to_scout() {
    let alice = human_alice();
    let orch_req = orchestrator_requested();
    let orch_effective = alice.delegate_to(&orch_req, "PR review").unwrap();

    let scout_req = scout_requested();
    let scout_effective = orch_effective
        .delegate_to(&scout_req, "research competitor approaches")
        .expect("delegation should succeed");

    // Scout gets web_search: min(Orch's LowRisk, Scout's Always) = LowRisk
    assert_eq!(
        scout_effective.capabilities.web_search,
        CapabilityLevel::LowRisk
    );

    // Scout gets web_fetch: min(Orch's Never, Scout's Always) = Never!
    // Orchestrator doesn't have web_fetch, so Scout can't get it through delegation.
    assert_eq!(
        scout_effective.capabilities.web_fetch,
        CapabilityLevel::Never
    );

    // Critical: Scout has NO write, NO git_push, NO create_pr
    assert_eq!(
        scout_effective.capabilities.write_files,
        CapabilityLevel::Never
    );
    assert_eq!(
        scout_effective.capabilities.git_push,
        CapabilityLevel::Never
    );
    assert_eq!(
        scout_effective.capabilities.create_pr,
        CapabilityLevel::Never
    );
    assert_eq!(
        scout_effective.capabilities.run_bash,
        CapabilityLevel::Never
    );
}

/// Step 3: THE ATTACK — Scout is compromised by a malicious URL and tries
/// to delegate a "critical fix" to Coder with full write + push permissions.
///
/// With lattice-guard: Scout can only delegate permissions it HAS. Since
/// Scout has no write_files/git_push/create_pr, the meet with Coder's
/// request produces a lattice with NONE of those capabilities. The attack
/// chain is structurally broken.
#[test]
fn scenario_1c_hijacked_scout_cannot_delegate_write_to_coder() {
    // Build the real delegation chain
    let alice = human_alice();
    let orch_effective = alice
        .delegate_to(&orchestrator_requested(), "PR review")
        .unwrap();
    let scout_effective = orch_effective
        .delegate_to(&scout_requested(), "research")
        .unwrap();

    // THE ATTACK: Scout (compromised) tries to delegate to Coder
    // with full code modification permissions
    let coder_req = coder_requested();
    let (attack_result, justification) = meet_with_justification(&scout_effective, &coder_req);

    // The meet produces a lattice with NO dangerous capabilities
    assert_eq!(
        attack_result.capabilities.write_files,
        CapabilityLevel::Never
    );
    assert_eq!(
        attack_result.capabilities.edit_files,
        CapabilityLevel::Never
    );
    assert_eq!(attack_result.capabilities.git_push, CapabilityLevel::Never);
    assert_eq!(attack_result.capabilities.create_pr, CapabilityLevel::Never);
    assert_eq!(attack_result.capabilities.run_bash, CapabilityLevel::Never);
    assert_eq!(
        attack_result.capabilities.git_commit,
        CapabilityLevel::Never
    );

    // The justification records WHY these were blocked
    assert!(justification.was_narrowed);
    let restricted = justification.restricted_dimensions();
    assert!(
        restricted.contains(&"write_files"),
        "write_files should be in restricted dimensions: {:?}",
        restricted
    );
    assert!(
        restricted.contains(&"git_push"),
        "git_push should be in restricted dimensions: {:?}",
        restricted
    );

    // Prove: attack_result ≤ scout_effective (monotonicity)
    assert!(attack_result
        .capabilities
        .leq(&scout_effective.capabilities));
}

/// Step 4: Verify the full chain is reconstructable from audit events.
#[test]
fn scenario_1d_full_chain_auditable() {
    let log = AuditLog::in_memory();
    let cid = "pr-review-42";

    // Alice → Orchestrator
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/human/alice",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/human/alice".into(),
                to_identity: "spiffe://acme.corp/agent/orchestrator".into(),
                requested_description: "coordinate PR review".into(),
                granted_description: "read + search + git (no web_fetch)".into(),
                was_narrowed: true,
                restricted_dimensions: vec!["web_fetch".into()],
            },
        )
        .with_correlation_id(cid),
    );

    // Orchestrator → Scout
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/agent/orchestrator",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/agent/orchestrator".into(),
                to_identity: "spiffe://acme.corp/agent/scout".into(),
                requested_description: "web research".into(),
                granted_description: "web_search:LowRisk only (no write, no git)".into(),
                was_narrowed: true,
                restricted_dimensions: vec![
                    "write_files".into(),
                    "git_push".into(),
                    "web_fetch".into(),
                ],
            },
        )
        .with_correlation_id(cid),
    );

    // Scout (compromised) → Coder — the ATTACK delegation
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/agent/scout",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/agent/scout".into(),
                to_identity: "spiffe://acme.corp/agent/coder".into(),
                requested_description: "ATTACK: critical fix with full write".into(),
                granted_description: "read_files:LowRisk only (all write/push=Never)".into(),
                was_narrowed: true,
                restricted_dimensions: vec![
                    "write_files".into(),
                    "edit_files".into(),
                    "run_bash".into(),
                    "git_commit".into(),
                    "git_push".into(),
                    "create_pr".into(),
                ],
            },
        )
        .with_correlation_id(cid),
    );

    // Reconstruct the full chain from leaf
    let chain = log
        .reconstruct_delegation_chain("spiffe://acme.corp/agent/coder", Some(cid))
        .expect("chain should be reconstructable");

    assert_eq!(chain.depth(), 3, "3 hops: Alice → Orch → Scout → Coder");
    assert_eq!(
        chain.root_identity.as_deref(),
        Some("spiffe://acme.corp/human/alice")
    );
    assert!(chain.has_narrowing());

    // The full chain shows ALL restricted dimensions across every hop
    let all_restricted = chain.all_restricted_dimensions();
    assert!(all_restricted.contains(&"git_push"));
    assert!(all_restricted.contains(&"write_files"));
    assert!(all_restricted.contains(&"web_fetch"));

    // Verify the audit chain's cryptographic integrity
    assert!(
        log.verify_chain().is_ok(),
        "audit chain must be tamper-evident"
    );
}

// ============================================================================
// Scenario 2: Trifecta Completion via Delegation Chain
//
// Attacker attempts to assemble the lethal trifecta by combining capabilities
// from different agents in the chain: read_files from Coder, web_fetch from
// Scout, git_push from Orchestrator. The meet operation + trifecta constraint
// prevents any single delegation from accumulating all three.
// ============================================================================

/// Even if an attacker could somehow combine Scout's web capabilities with
/// Coder's code capabilities, the trifecta constraint would fire on the meet.
#[test]
fn scenario_2_trifecta_blocks_combined_capabilities() {
    // Hypothetical: what if Scout somehow had web_fetch AND Coder had read + push?
    let mut scout_like = PermissionLattice::new("synthetic scout-like");
    scout_like.capabilities.read_files = CapabilityLevel::Always;
    scout_like.capabilities.web_fetch = CapabilityLevel::Always;
    scout_like.capabilities.web_search = CapabilityLevel::Always;
    scout_like.capabilities.run_bash = CapabilityLevel::LowRisk;
    scout_like.capabilities.git_push = CapabilityLevel::LowRisk;

    // Check: the trifecta constraint detects this as Complete
    let constraint = IncompatibilityConstraint::enforcing();
    let risk = constraint.trifecta_risk(&scout_like.capabilities);
    assert_eq!(risk, TrifectaRisk::Complete);

    // When we normalize (apply the trifecta nucleus), exfiltration
    // operations get approval obligations added
    let obligations = constraint.obligations_for(&scout_like.capabilities);
    assert!(
        obligations.requires(lattice_guard::Operation::RunBash)
            || obligations.requires(lattice_guard::Operation::GitPush),
        "trifecta must add approval obligations to exfiltration ops"
    );
}

// ============================================================================
// Scenario 3: Budget Laundering
//
// An attacker tries to bypass budget limits by splitting work across multiple
// sub-agents, each with their own budget. The meet operation prevents
// a child from receiving more budget than its parent has remaining.
// ============================================================================

/// Budget delegation: delegate_to rejects when requested budget exceeds
/// parent's remaining budget. The meet still clamps, but the API enforces
/// that callers must request within bounds — preventing budget laundering.
#[test]
fn scenario_3a_budget_cannot_exceed_parent() {
    let mut parent = PermissionLattice::new("parent with $5 budget");
    parent.budget = BudgetLattice::with_cost_limit(5.0);

    // Greedy child requests $100 — delegate_to rejects this
    let mut greedy_child = PermissionLattice::new("child requesting $100");
    greedy_child.budget = BudgetLattice::with_cost_limit(100.0);

    let err = parent
        .delegate_to(&greedy_child, "budget test")
        .unwrap_err();
    assert!(
        matches!(
            err,
            lattice_guard::DelegationError::InsufficientBudget { .. }
        ),
        "must reject: requested budget ($100) exceeds parent remaining ($5)"
    );

    // Honest child requests within parent's remaining — succeeds
    let mut honest_child = PermissionLattice::new("child requesting $3");
    honest_child.budget = BudgetLattice::with_cost_limit(3.0);

    let effective = parent.delegate_to(&honest_child, "budget test").unwrap();
    assert_eq!(effective.budget.max_cost_usd, Decimal::new(3, 0));

    // The meet itself does clamp — useful for forensic analysis
    let (meet_result, justification) = meet_with_justification(&parent, &greedy_child);
    assert_eq!(meet_result.budget.max_cost_usd, Decimal::new(5, 0));
    assert!(justification.was_narrowed);
}

/// Budget consumption tracking: charges are atomic and irreversible.
#[test]
fn scenario_3b_budget_charges_are_atomic() {
    let mut parent = PermissionLattice::new("parent");
    parent.budget = BudgetLattice::with_cost_limit(5.0);
    let mut effective = parent.delegate_to(&coder_requested(), "coder").unwrap();

    // Charge $2.50 — succeeds
    assert!(effective.budget.charge(Decimal::new(250, 2)));
    assert_eq!(effective.budget.remaining(), Decimal::new(50, 2)); // min(5,3) - 2.50

    // Try to charge $1.00 — fails, only $0.50 remaining
    assert!(!effective.budget.charge(Decimal::new(1, 0)));

    // Negative charges rejected (prevents budget inflation attack)
    assert!(!effective.budget.charge(Decimal::new(-5, 0)));

    // Zero charges rejected (prevents charge-nothing loops)
    assert!(!effective.budget.charge(Decimal::ZERO));
}

// ============================================================================
// Scenario 4: Confused Deputy with Audit Trail
//
// OWASP ASI03: A compromised "manager agent" tells a trusted "accountant
// agent" to perform an action. The accountant acts because the request
// came from a trusted peer. MeetJustification provides the forensic trail.
// ============================================================================

/// The meet justification records every dimension that was restricted,
/// providing forensic evidence of what was blocked and why.
#[test]
fn scenario_4_confused_deputy_leaves_forensic_trail() {
    let alice = human_alice();
    let orch_effective = alice
        .delegate_to(&orchestrator_requested(), "review")
        .unwrap();

    // Orchestrator (compromised) tries to delegate deployment-level access
    let mut deploy_request = PermissionLattice::new("deploy agent");
    deploy_request.capabilities.run_bash = CapabilityLevel::Always;
    deploy_request.capabilities.write_files = CapabilityLevel::Always;
    deploy_request.capabilities.git_push = CapabilityLevel::Always;
    deploy_request.capabilities.manage_pods = CapabilityLevel::Always;
    deploy_request.budget = BudgetLattice::with_cost_limit(50.0);

    let (result, justification) = meet_with_justification(&orch_effective, &deploy_request);

    // manage_pods: Orchestrator has Never, so deploy agent gets Never
    assert_eq!(result.capabilities.manage_pods, CapabilityLevel::Never);

    // run_bash: Orchestrator has Never (wasn't requested), so deploy agent gets Never
    assert_eq!(result.capabilities.run_bash, CapabilityLevel::Never);

    // Budget: min(5.0, 50.0) = 5.0
    assert_eq!(result.budget.max_cost_usd, Decimal::new(5, 0));

    // The justification is a complete forensic record
    assert!(justification.was_narrowed);
    let dims = justification.restricted_dimensions();
    assert!(
        dims.contains(&"run_bash"),
        "run_bash restriction must be recorded"
    );
    assert!(
        dims.contains(&"budget"),
        "budget restriction must be recorded"
    );

    // Every restriction has a reason
    for restriction in &justification.restrictions {
        match restriction.reason {
            lattice_guard::delegation::RestrictionReason::CeilingExceeded => {
                // Parent didn't have this capability — correct
            }
            lattice_guard::delegation::RestrictionReason::TrifectaDemotion => {
                // Trifecta constraint demoted this — correct
            }
            lattice_guard::delegation::RestrictionReason::BudgetExceeded => {
                // Budget exceeded parent — correct
            }
            _ => {}
        }
    }
}

// ============================================================================
// Scenario 5: Kiro-Class Destructive Autonomy
//
// Amazon Kiro (Dec 2025): Agent autonomously decided to "delete and recreate"
// a production environment. The agent had legitimate permissions — the problem
// was that no ceiling prevented destructive operations.
//
// The ceiling theorem proves: effective_perms(agent) ≤ ceiling(trace_chain).
// If the trace chain never grants manage_pods or unrestricted run_bash,
// no downstream agent can acquire those capabilities regardless of how
// many delegation hops it goes through.
// ============================================================================

/// The ceiling theorem: no matter how deep the delegation chain,
/// effective permissions never exceed the meet of all ancestors.
#[test]
fn scenario_5a_ceiling_theorem_holds_across_chain() {
    let alice = human_alice();
    let orch = alice
        .delegate_to(&orchestrator_requested(), "review")
        .unwrap();
    let coder = orch.delegate_to(&coder_requested(), "implement").unwrap();

    // Create a further sub-delegation: Coder → Test Runner
    // Test runner must request within coder's budget (which is ≤ orch's ≤ alice's)
    let mut test_runner_req = PermissionLattice::new("test runner");
    test_runner_req.capabilities.read_files = CapabilityLevel::Always;
    test_runner_req.capabilities.write_files = CapabilityLevel::Never;
    test_runner_req.capabilities.edit_files = CapabilityLevel::Never;
    test_runner_req.capabilities.run_bash = CapabilityLevel::Always;
    test_runner_req.capabilities.glob_search = CapabilityLevel::Never;
    test_runner_req.capabilities.grep_search = CapabilityLevel::Never;
    test_runner_req.capabilities.web_search = CapabilityLevel::Never;
    test_runner_req.capabilities.web_fetch = CapabilityLevel::Never;
    test_runner_req.capabilities.git_commit = CapabilityLevel::Never;
    test_runner_req.capabilities.git_push = CapabilityLevel::Never;
    test_runner_req.capabilities.create_pr = CapabilityLevel::Never;
    test_runner_req.capabilities.manage_pods = CapabilityLevel::Never;
    test_runner_req.budget = BudgetLattice::with_cost_limit(1.0); // within coder's remaining

    let test_runner = coder.delegate_to(&test_runner_req, "run tests").unwrap();

    // Ceiling theorem: test_runner ≤ coder ≤ orch ≤ alice
    assert!(test_runner.capabilities.leq(&coder.capabilities));
    assert!(test_runner.capabilities.leq(&orch.capabilities));
    assert!(test_runner.capabilities.leq(&alice.capabilities));

    // Budget ceiling: test_runner.budget ≤ coder.budget ≤ orch.budget ≤ alice.budget
    assert!(test_runner.budget.max_cost_usd <= coder.budget.max_cost_usd);
    assert!(coder.budget.max_cost_usd <= orch.budget.max_cost_usd);
    assert!(orch.budget.max_cost_usd <= alice.budget.max_cost_usd);
}

/// Kiro scenario: even with legitimate permissions, the lattice prevents
/// manage_pods (infrastructure deletion) from appearing in the chain
/// if Alice never granted it.
#[test]
fn scenario_5b_kiro_attack_blocked_by_ceiling() {
    let alice = human_alice();

    // Alice never granted manage_pods
    assert_eq!(alice.capabilities.manage_pods, CapabilityLevel::Never);

    // No matter what any downstream agent requests...
    let mut infra_destroyer = PermissionLattice::new("infra destroyer");
    infra_destroyer.capabilities.manage_pods = CapabilityLevel::Always;
    infra_destroyer.capabilities.run_bash = CapabilityLevel::Always;

    // ...the meet with Alice's ceiling blocks manage_pods
    let orch = alice
        .delegate_to(&orchestrator_requested(), "review")
        .unwrap();
    let effective = orch
        .delegate_to(&infra_destroyer, "ATTACK: destroy infra")
        .unwrap();

    assert_eq!(
        effective.capabilities.manage_pods,
        CapabilityLevel::Never,
        "manage_pods must be blocked: Alice never granted it"
    );
}

/// EffectivePermissions integrity: tampering with the lattice after
/// delegation is detectable via SHA-256 checksum.
#[test]
fn scenario_5c_post_delegation_tampering_detected() {
    let alice = human_alice();
    let orch = alice
        .delegate_to(&orchestrator_requested(), "review")
        .unwrap();
    let effective = EffectivePermissions::new(orch);

    // Integrity check passes
    assert!(effective.verify_integrity());

    // Simulate tampering: clone and modify the lattice
    let mut tampered = effective.lattice.clone();
    tampered.capabilities.manage_pods = CapabilityLevel::Always;

    let tampered_eff = EffectivePermissions {
        lattice: tampered,
        budget_reservation_id: effective.budget_reservation_id,
        checksum: effective.checksum.clone(), // Keep old checksum
    };

    // Integrity check FAILS — checksum mismatch
    assert!(
        !tampered_eff.verify_integrity(),
        "tampered permissions must fail integrity check"
    );
}

// ============================================================================
// Scenario 6: Full End-to-End — The PajaMAS Attack Defended
//
// This combines all the above into a single narrative test that walks
// through the complete attack sequence and demonstrates every defense layer.
// ============================================================================

/// Full end-to-end: 4-agent chain, attack attempt, and forensic reconstruction.
#[test]
fn scenario_6_full_pajamas_attack_defended() {
    let log = AuditLog::in_memory();
    let correlation = "incident-2025-PajaMAS";

    // === Phase 1: Legitimate delegation chain ===

    let alice = human_alice();

    // Alice → Orchestrator
    let orch = alice
        .delegate_to(&orchestrator_requested(), "PR review")
        .unwrap();
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/human/alice",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/human/alice".into(),
                to_identity: "spiffe://acme.corp/agent/orchestrator".into(),
                requested_description: "coordinate PR review".into(),
                granted_description: format!(
                    "git_push:{:?}, web_fetch:Never",
                    orch.capabilities.git_push
                ),
                was_narrowed: true,
                restricted_dimensions: vec!["web_fetch".into()],
            },
        )
        .with_correlation_id(correlation),
    );

    // Orchestrator → Scout
    let scout = orch.delegate_to(&scout_requested(), "research").unwrap();
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/agent/orchestrator",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/agent/orchestrator".into(),
                to_identity: "spiffe://acme.corp/agent/scout".into(),
                requested_description: "web research".into(),
                granted_description: "web_search:LowRisk, no write/push".into(),
                was_narrowed: true,
                restricted_dimensions: vec![
                    "write_files".into(),
                    "git_push".into(),
                    "web_fetch".into(),
                ],
            },
        )
        .with_correlation_id(correlation),
    );

    // Orchestrator → Coder (legitimate)
    let coder = orch
        .delegate_to(&coder_requested(), "implement fix")
        .unwrap();
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/agent/orchestrator",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/agent/orchestrator".into(),
                to_identity: "spiffe://acme.corp/agent/coder".into(),
                requested_description: "implement code changes".into(),
                granted_description: format!(
                    "write:{:?}, push:{:?}",
                    coder.capabilities.write_files, coder.capabilities.git_push
                ),
                was_narrowed: true,
                restricted_dimensions: vec![
                    "write_files".into(),
                    "edit_files".into(),
                    "run_bash".into(),
                ],
            },
        )
        .with_correlation_id(correlation),
    );

    // === Phase 2: Scout is compromised ===
    // Scout visits a malicious URL. The page contains prompt injection
    // that tricks Scout into trying to delegate to Coder.

    // Scout tries to delegate write + push to a "sub-coder"
    let (attack_result, attack_justification) = meet_with_justification(&scout, &coder_requested());

    // Record the attempted (and blocked) delegation
    log.record(
        AuditEntry::new(
            "spiffe://acme.corp/agent/scout",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://acme.corp/agent/scout".into(),
                to_identity: "spiffe://acme.corp/agent/attacker-coder".into(),
                requested_description: "ATTACK: critical security fix".into(),
                granted_description: format!(
                    "BLOCKED: write:{:?}, push:{:?} (all Never)",
                    attack_result.capabilities.write_files, attack_result.capabilities.git_push,
                ),
                was_narrowed: true,
                restricted_dimensions: attack_justification
                    .restricted_dimensions()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
        )
        .with_correlation_id(correlation),
    );

    // === Phase 3: Verify defenses held ===

    // 1. Attack result has no dangerous capabilities
    assert_eq!(
        attack_result.capabilities.write_files,
        CapabilityLevel::Never
    );
    assert_eq!(attack_result.capabilities.git_push, CapabilityLevel::Never);
    assert_eq!(attack_result.capabilities.run_bash, CapabilityLevel::Never);

    // 2. Legitimate coder still has its permissions (attack didn't affect it)
    assert_eq!(coder.capabilities.write_files, CapabilityLevel::Never);
    // Coder's write_files is Never because orchestrator has write_files=Never
    // This is correct — orchestrator was a coordinator, not a coder itself
    assert_eq!(coder.capabilities.git_push, CapabilityLevel::LowRisk);

    // 3. The audit chain is reconstructable
    let attack_chain = log
        .reconstruct_delegation_chain("spiffe://acme.corp/agent/attacker-coder", Some(correlation))
        .expect("attack chain must be reconstructable");

    assert_eq!(attack_chain.depth(), 3); // Alice → Orch → Scout → attacker-coder
    assert!(attack_chain.has_narrowing());

    // 4. The audit chain is cryptographically intact
    assert!(log.verify_chain().is_ok());

    // 5. Can identify all agents involved in the incident
    let all_delegations = log.delegations_involving("spiffe://acme.corp/agent/scout");
    assert_eq!(all_delegations.len(), 2); // Scout received + Scout attempted

    // === Phase 4: Post-incident analysis ===

    // The security team can reconstruct exactly what happened:
    let chain = attack_chain;
    assert_eq!(
        chain.root_identity.as_deref(),
        Some("spiffe://acme.corp/human/alice"),
        "trust anchor is identified"
    );
    assert_eq!(
        chain.leaf_identity, "spiffe://acme.corp/agent/attacker-coder",
        "attack target is identified"
    );
    // Every hop in the chain was narrowed — defense in depth at every level
    assert!(chain.links.iter().all(|l| l.was_narrowed));
}
