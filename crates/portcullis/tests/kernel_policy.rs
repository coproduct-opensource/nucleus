#![allow(deprecated)]
//! PolicyRuleSet integration tests (#657) — extracted from kernel.rs.
//!
//! These tests verify that the kernel enforces policy rules: allow, deny,
//! requires-approval verdicts, default-deny when no rule matches, and
//! passthrough when no policy rules are configured.

use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{
    CapabilityLattice, CapabilityLevel, CommandLattice, Operation, PermissionLattice,
};
use portcullis_core::policy_rules::{
    AdmissibilityRule, LabelPredicate, PolicyRuleSet, RuleVerdict,
};
use portcullis_core::{IntegLevel, SinkClass};

/// Helper: build a kernel with the given policy rules and all capabilities.
fn kernel_with_policy(rules: PolicyRuleSet) -> Kernel {
    // All capabilities set to Always — policy is the only gate.
    let all_caps = CapabilityLattice {
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
    };
    let mut perms = PermissionLattice::builder()
        .description("policy-test: all caps, policy is the gate")
        .capabilities(all_caps)
        .commands(CommandLattice::permissive())
        .build();
    // Clear obligations so the uninhabitable state doesn't interfere.
    perms.obligations.approvals.clear();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();
    kernel.set_policy_rules(rules);
    kernel
}

#[test]
fn policy_allows_trusted_write() {
    let mut rules = PolicyRuleSet::new();
    rules.push(AdmissibilityRule {
        name: "trusted workspace writes allowed".to_string(),
        source_predicate: LabelPredicate {
            min_integrity: Some(IntegLevel::Trusted),
            ..LabelPredicate::any()
        },
        artifact_predicate: LabelPredicate::any(),
        sink_class: SinkClass::WorkspaceWrite,
        verdict: RuleVerdict::Allow,
    });

    let mut kernel = kernel_with_policy(rules);

    // WriteFiles to a workspace path → classified as WorkspaceWrite
    let (d, token) = kernel.decide(Operation::WriteFiles, "src/main.rs");
    assert!(
        matches!(d.verdict, Verdict::Allow),
        "trusted write should be allowed, got: {:?}",
        d.verdict
    );
    assert!(token.is_some());
}

#[test]
fn policy_denies_by_rule() {
    let mut rules = PolicyRuleSet::new();
    rules.push(AdmissibilityRule {
        name: "no git push ever".to_string(),
        source_predicate: LabelPredicate::any(),
        artifact_predicate: LabelPredicate::any(),
        sink_class: SinkClass::GitPush,
        verdict: RuleVerdict::Deny,
    });

    let mut kernel = kernel_with_policy(rules);

    // GitPush → denied by policy even though capabilities allow it
    let (d, token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        matches!(d.verdict, Verdict::Deny(DenyReason::PolicyDenied { .. })),
        "git push should be denied by policy rule, got: {:?}",
        d.verdict
    );
    assert!(token.is_none());

    // Verify the deny reason contains the rule name
    if let Verdict::Deny(DenyReason::PolicyDenied {
        rule_name,
        sink_class,
    }) = &d.verdict
    {
        assert_eq!(rule_name, "no git push ever");
        assert!(sink_class.contains("GitPush"));
    }
}

#[test]
fn policy_requires_approval() {
    let mut rules = PolicyRuleSet::new();
    rules.push(AdmissibilityRule {
        name: "bash needs approval".to_string(),
        source_predicate: LabelPredicate::any(),
        artifact_predicate: LabelPredicate::any(),
        sink_class: SinkClass::BashExec,
        verdict: RuleVerdict::RequiresApproval,
    });

    let mut kernel = kernel_with_policy(rules);

    // RunBash → requires approval by policy
    let (d, token) = kernel.decide(Operation::RunBash, "ls -la");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "bash should require approval, got: {:?}",
        d.verdict
    );
    assert!(token.is_none());

    // Grant approval and try again
    kernel.grant_approval(Operation::RunBash, 1);
    let (d, token) = kernel.decide(Operation::RunBash, "ls -la");
    assert!(
        matches!(d.verdict, Verdict::Allow),
        "bash should be allowed after approval, got: {:?}",
        d.verdict
    );
    assert!(token.is_some());
}

#[test]
fn policy_default_deny_when_no_rule_matches() {
    let mut rules = PolicyRuleSet::new();
    // Only allow WorkspaceWrite — everything else default-denied
    rules.push(AdmissibilityRule {
        name: "allow writes only".to_string(),
        source_predicate: LabelPredicate::any(),
        artifact_predicate: LabelPredicate::any(),
        sink_class: SinkClass::WorkspaceWrite,
        verdict: RuleVerdict::Allow,
    });

    let mut kernel = kernel_with_policy(rules);

    // Write is allowed
    let (d, _) = kernel.decide(Operation::WriteFiles, "src/lib.rs");
    assert!(matches!(d.verdict, Verdict::Allow));

    // GitPush has no matching rule → default deny
    let (d, token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        matches!(d.verdict, Verdict::Deny(DenyReason::PolicyDenied { .. })),
        "unmatched operation should be default-denied, got: {:?}",
        d.verdict
    );
    assert!(token.is_none());

    // Verify it's a default deny (empty rule name)
    if let Verdict::Deny(DenyReason::PolicyDenied { rule_name, .. }) = &d.verdict {
        assert_eq!(rule_name, "(default deny)");
    }
}

#[test]
fn no_policy_rules_means_no_filtering() {
    // Kernel without policy rules — all operations pass through
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    // Don't call set_policy_rules

    let (d, token) = kernel.decide(Operation::WriteFiles, "src/main.rs");
    assert!(matches!(d.verdict, Verdict::Allow));
    assert!(token.is_some());
}
