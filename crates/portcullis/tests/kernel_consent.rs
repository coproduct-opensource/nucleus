#![allow(deprecated)]
//! Two-phase consent in `Kernel::decide` (#3443).
//!
//! An approval is consumed only if the whole decision is `Allow`. Every
//! refusal leaves it unspent. One consent requirement spends one approval, no
//! matter how many gates ask the same question. A static-obligation approval
//! does not discharge the dynamic exposure gate, which needs its own.
//!
//! These are HISTORY tests: they grant, attempt something that is refused, and
//! then check that the grant still buys exactly what it was granted for. A
//! test that only looked at one decision could not see an approval being spent
//! by a refusal. This mirrors `refusal_preserves_the_authority` in
//! `MediationScopeExtracted.lean`.

use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{
    CapabilityLattice, CapabilityLevel, CommandLattice, Operation, PermissionLattice,
};
use portcullis_core::policy_rules::{
    AdmissibilityRule, LabelPredicate, PolicyRuleSet, RuleVerdict,
};
use portcullis_core::SinkClass;

fn all_always() -> CapabilityLattice {
    CapabilityLattice {
        read_files: CapabilityLevel::Always,
        write_files: CapabilityLevel::Always,
        edit_files: CapabilityLevel::Always,
        run_bash: CapabilityLevel::Always,
        glob_search: CapabilityLevel::Always,
        grep_search: CapabilityLevel::Always,
        web_search: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::Always,
        git_commit: CapabilityLevel::Always,
        git_push: CapabilityLevel::Always,
        create_pr: CapabilityLevel::Always,
        manage_pods: CapabilityLevel::Always,
        spawn_agent: CapabilityLevel::Always,
        extensions: std::collections::BTreeMap::new(),
    }
}

/// Every capability `Always`, the program `forbidden` blocked, and exactly the
/// obligations named. Nothing else can hold or refuse.
fn lattice(obligated: &[Operation]) -> PermissionLattice {
    let mut commands = CommandLattice::permissive();
    commands.block("forbidden");
    let mut perms = PermissionLattice::builder()
        .description("consent-test")
        .capabilities_with(all_always(), portcullis::ConsentMode::Autonomous)
        .commands(commands)
        .build()
        .expect("consent is declared");
    perms.declare_all(portcullis::ConsentMode::Autonomous);
    for op in obligated {
        perms.declare(*op, portcullis::ConsentMode::RequiresApproval);
    }
    perms
}

/// A policy rule that holds `sink` for approval and allows every other sink.
fn hold_sink(sink: SinkClass) -> PolicyRuleSet {
    let mut rules = PolicyRuleSet::new();
    rules.push(AdmissibilityRule {
        name: "held for a person".to_string(),
        source_predicate: LabelPredicate::any(),
        artifact_predicate: LabelPredicate::any(),
        sink_class: sink,
        verdict: RuleVerdict::RequiresApproval,
    });
    rules
}

/// Build the exposure an exfil op would complete: private data, then
/// untrusted content.
fn expose(kernel: &mut Kernel) {
    let (r, _) = kernel.decide(Operation::ReadFiles, "docs/design.md");
    assert!(r.verdict.is_allowed(), "precondition: read allowed");
    let (f, _) = kernel.decide(Operation::WebFetch, "https://untrusted.example/x");
    assert!(f.verdict.is_allowed(), "precondition: fetch allowed");
}

/// Grant A (a policy-rule approval for `RunBash`). Attempt a command the
/// command lattice refuses (step 5, after the policy rule at step 3d). The
/// refusal must not spend A: the next allowed command succeeds exactly once.
#[test]
fn a_refusal_at_the_command_step_leaves_the_approval_unspent() {
    let mut kernel = Kernel::new(lattice(&[]));
    kernel.set_policy_rules(hold_sink(SinkClass::BashExec));
    kernel.grant_approval(Operation::RunBash, 1);

    let (refused, token) = kernel.decide(Operation::RunBash, "forbidden --now");
    assert!(
        matches!(
            refused.verdict,
            Verdict::Deny(DenyReason::CommandBlocked { .. })
        ),
        "precondition: the command step refuses, got {:?}",
        refused.verdict
    );
    assert!(token.is_none());

    let (first, token) = kernel.decide(Operation::RunBash, "ls -la");
    assert!(
        first.verdict.is_allowed(),
        "the approval granted for RunBash was spent by a refusal: {:?}",
        first.verdict
    );
    assert!(token.is_some());

    let (second, _) = kernel.decide(Operation::RunBash, "ls -la");
    assert_eq!(
        second.verdict,
        Verdict::RequiresApproval,
        "one approval buys exactly one operation"
    );
}

/// The same history with the refusal at the path step (step 4).
#[test]
fn a_refusal_at_the_path_step_leaves_the_approval_unspent() {
    let mut perms = lattice(&[]);
    perms.paths = portcullis::PathLattice::block_sensitive();
    let mut kernel = Kernel::new(perms);
    kernel.set_policy_rules(hold_sink(SinkClass::WorkspaceWrite));
    kernel.grant_approval(Operation::WriteFiles, 1);

    let (refused, _) = kernel.decide(Operation::WriteFiles, ".env");
    assert!(
        matches!(
            refused.verdict,
            Verdict::Deny(DenyReason::PathBlocked { .. })
        ),
        "precondition: the path step refuses, got {:?}",
        refused.verdict
    );

    let (first, _) = kernel.decide(Operation::WriteFiles, "notes.txt");
    assert!(
        first.verdict.is_allowed(),
        "the approval granted for WriteFiles was spent by a refusal: {:?}",
        first.verdict
    );
    let (second, _) = kernel.decide(Operation::WriteFiles, "notes.txt");
    assert_eq!(second.verdict, Verdict::RequiresApproval);
}

/// An operation that a policy rule AND a lattice obligation both hold is one
/// consent requirement asked twice. One approval satisfies it, and it spends
/// exactly one.
#[test]
fn one_consent_asked_twice_spends_one_approval() {
    let mut kernel = Kernel::new(lattice(&[Operation::RunBash]));
    kernel.set_policy_rules(hold_sink(SinkClass::BashExec));
    kernel.grant_approval(Operation::RunBash, 1);

    let (d, token) = kernel.decide(Operation::RunBash, "ls -la");
    assert!(
        d.verdict.is_allowed(),
        "one approval must satisfy both the policy rule and the obligation: {:?}",
        d.verdict
    );
    assert!(token.is_some());

    let (again, _) = kernel.decide(Operation::RunBash, "ls -la");
    assert_eq!(
        again.verdict,
        Verdict::RequiresApproval,
        "and it spent exactly one"
    );
}

/// A static-obligation approval does not clear an exfil the exposure gate
/// holds. Before #3443 step 7 returned `Allow` as soon as it found the static
/// approval, and the gate never ran.
#[test]
fn a_static_approval_does_not_clear_an_uninhabitable_exfil() {
    let mut kernel = Kernel::capability_only(lattice(&[Operation::GitPush]));
    expose(&mut kernel);
    kernel.grant_approval(Operation::GitPush, 1);

    let (held, token) = kernel.decide(Operation::GitPush, "origin/main");
    assert_eq!(
        held.verdict,
        Verdict::RequiresApproval,
        "the exposure gate must hold the push even though its static obligation is approved"
    );
    assert!(held.exposure_transition.dynamic_gate_applied);
    assert!(token.is_none());
    assert!(
        !kernel.exposure().is_uninhabitable(),
        "a held push contributes no exposure"
    );

    // The held decision spent nothing: one more approval (the gate's own)
    // makes two, which is what the push needs.
    kernel.grant_approval(Operation::GitPush, 1);
    let (allowed, token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        allowed.verdict.is_allowed(),
        "static approval + exposure approval must allow: {:?}",
        allowed.verdict
    );
    assert!(token.is_some());
    assert!(allowed.exposure_transition.dynamic_gate_applied);

    // Both were spent, and nothing else.
    let (after, _) = kernel.decide(Operation::GitPush, "origin/main");
    assert_eq!(after.verdict, Verdict::RequiresApproval);
}

/// A policy-rule approval found at step 3d, then a hold at the exposure gate:
/// the hold spends nothing.
#[test]
fn an_exposure_hold_after_a_policy_approval_spends_nothing() {
    let mut kernel = Kernel::capability_only(lattice(&[]));
    let mut rules = hold_sink(SinkClass::GitPush);
    for sink in [SinkClass::SecretRead, SinkClass::HTTPEgress] {
        rules.push(AdmissibilityRule {
            name: format!("allow {sink:?}"),
            source_predicate: LabelPredicate::any(),
            artifact_predicate: LabelPredicate::any(),
            sink_class: sink,
            verdict: RuleVerdict::Allow,
        });
    }
    kernel.set_policy_rules(rules);
    expose(&mut kernel);
    kernel.grant_approval(Operation::GitPush, 1);

    let (held, _) = kernel.decide(Operation::GitPush, "origin/main");
    assert_eq!(held.verdict, Verdict::RequiresApproval);
    assert!(held.exposure_transition.dynamic_gate_applied);

    kernel.grant_approval(Operation::GitPush, 1);
    let (allowed, _) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        allowed.verdict.is_allowed(),
        "the policy approval must have survived the hold: {:?}",
        allowed.verdict
    );
}

/// Non-vacuity: with no obligation and no exposure, a grant is never touched,
/// and an approval-free op is allowed without one.
#[test]
fn an_op_nobody_holds_spends_nothing() {
    let mut kernel = Kernel::capability_only(lattice(&[]));
    kernel.grant_approval(Operation::GitPush, 1);
    let (d, _) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(d.verdict.is_allowed());
    assert!(!d.exposure_transition.dynamic_gate_applied);

    // The grant is still there: an exposure hold now finds it.
    expose(&mut kernel);
    let (allowed, _) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        allowed.verdict.is_allowed(),
        "an op nobody held must not have spent the grant: {:?}",
        allowed.verdict
    );
    assert!(allowed.exposure_transition.dynamic_gate_applied);
}
