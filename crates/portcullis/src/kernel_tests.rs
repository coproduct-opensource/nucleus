use super::*;
use crate::{CapabilityLevel, PermissionLattice};

#[test]
fn test_basic_allow() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed());
    assert_eq!(d.sequence, 0);
}

#[test]
fn test_capability_deny() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // safe_pr_fixer has git_push=Never
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(d.verdict.is_denied());
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::InsufficientCapability)
    ));
}

#[test]
fn test_trace_is_append_only() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    kernel.decide(Operation::ReadFiles, "/a");
    kernel.decide(Operation::ReadFiles, "/b");
    kernel.decide(Operation::GitPush, "/c");

    assert_eq!(kernel.trace().len(), 3);
    assert_eq!(kernel.trace()[0].sequence, 0);
    assert_eq!(kernel.trace()[1].sequence, 1);
    assert_eq!(kernel.trace()[2].sequence, 2);

    // Sequences are monotonically increasing
    for i in 1..kernel.trace().len() {
        assert!(kernel.trace()[i].sequence > kernel.trace()[i - 1].sequence);
    }
}

#[test]
fn test_monotone_attenuation() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);

    // Start with permissive
    assert_eq!(
        kernel.effective().capabilities.git_push,
        CapabilityLevel::Always
    );

    // Attenuate with restrictive ceiling
    let ceiling = PermissionLattice::read_only();
    let result = kernel.attenuate(&ceiling);
    assert!(result.is_ok());

    // Git push should now be Never
    assert_eq!(
        kernel.effective().capabilities.git_push,
        CapabilityLevel::Never
    );

    // Further attenuation should also work (idempotent at bottom)
    let result = kernel.attenuate(&ceiling);
    assert!(result.is_ok());
}

#[test]
fn test_budget_tracking() {
    let perms = PermissionLattice::safe_pr_fixer(); // $5 budget
    let mut kernel = Kernel::new(perms);

    // Charge $2
    let remaining = kernel.charge(Decimal::new(200, 2)).unwrap();
    assert_eq!(remaining, Decimal::new(300, 2));

    // Charge another $2
    let remaining = kernel.charge(Decimal::new(200, 2)).unwrap();
    assert_eq!(remaining, Decimal::new(100, 2));

    // Try to charge $2 more (exceeds remaining $1)
    let result = kernel.charge(Decimal::new(200, 2));
    assert!(result.is_err());
}

#[test]
fn test_budget_exhaustion_denies() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Exhaust budget
    let _ = kernel.charge(Decimal::new(500, 2));

    // Now decide should deny
    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::BudgetExhausted { .. })
    ));
}

#[test]
fn test_approval_grant_and_consume() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // run_bash requires approval in safe_pr_fixer (uninhabitable_state mitigation)
    let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "should require approval, got {:?}",
        d.verdict
    );

    // Grant 2 approvals
    kernel.grant_approval(Operation::RunBash, 2);

    // First use: approved
    let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
    assert!(d.verdict.is_allowed());

    // Second use: approved
    let (d, _token) = kernel.decide(Operation::RunBash, "cargo build");
    assert!(d.verdict.is_allowed());

    // Third use: no more approvals
    let (d, _token) = kernel.decide(Operation::RunBash, "cargo check");
    assert!(matches!(d.verdict, Verdict::RequiresApproval));
}

#[test]
fn test_path_blocked() {
    let perms = PermissionLattice::safe_pr_fixer(); // blocks sensitive paths
    let mut kernel = Kernel::new(perms);

    // .ssh is blocked by path lattice
    let (d, _token) = kernel.decide(Operation::ReadFiles, "/home/user/.ssh/id_rsa");
    assert!(
        d.verdict.is_denied(),
        "should deny .ssh access, got {:?}",
        d.verdict
    );
}

#[test]
fn test_session_id_stable() {
    let perms = PermissionLattice::default();
    let kernel = Kernel::new(perms);

    let id1 = kernel.session_id();
    let id2 = kernel.session_id();
    assert_eq!(id1, id2);
}

#[test]
fn test_initial_hash_preserved() {
    let perms = PermissionLattice::safe_pr_fixer();
    let expected_hash = perms.checksum();
    let kernel = Kernel::new(perms);

    assert_eq!(kernel.initial_hash(), expected_hash);
}

#[test]
fn test_decision_count() {
    let perms = PermissionLattice::default();
    let mut kernel = Kernel::new(perms);

    assert_eq!(kernel.decision_count(), 0);
    kernel.decide(Operation::ReadFiles, "/a");
    assert_eq!(kernel.decision_count(), 1);
    kernel.decide(Operation::ReadFiles, "/b");
    assert_eq!(kernel.decision_count(), 2);
}

#[test]
fn test_zero_charge_is_noop() {
    let perms = PermissionLattice::default();
    let mut kernel = Kernel::new(perms);

    let remaining = kernel.remaining_usd();
    let result = kernel.charge(Decimal::ZERO);
    assert!(result.is_ok());
    assert_eq!(kernel.remaining_usd(), remaining);
}

#[test]
fn test_negative_charge_is_noop() {
    let perms = PermissionLattice::default();
    let mut kernel = Kernel::new(perms);

    let remaining = kernel.remaining_usd();
    let result = kernel.charge(Decimal::new(-100, 2));
    assert!(result.is_ok());
    assert_eq!(kernel.remaining_usd(), remaining);
}

#[test]
fn test_complete_mediation_coverage() {
    // Every Operation variant must produce a decision (not panic)
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);

    let operations = [
        Operation::ReadFiles,
        Operation::WriteFiles,
        Operation::EditFiles,
        Operation::RunBash,
        Operation::GlobSearch,
        Operation::GrepSearch,
        Operation::WebSearch,
        Operation::WebFetch,
        Operation::GitCommit,
        Operation::GitPush,
        Operation::CreatePr,
        Operation::ManagePods,
    ];

    for op in operations {
        let (d, _token) = kernel.decide(op, "test-subject");
        // Should not panic; verdict should be one of the three variants
        assert!(
            matches!(
                d.verdict,
                Verdict::Allow | Verdict::RequiresApproval | Verdict::Deny(_)
            ),
            "Operation {:?} should produce a definitive verdict, got {:?}",
            op,
            d.verdict
        );
    }

    assert_eq!(kernel.decision_count(), 12);
}

#[test]
fn test_pre_post_permission_hashes_stable() {
    let perms = PermissionLattice::default();
    let mut kernel = Kernel::new(perms);

    let (d1, _token) = kernel.decide(Operation::ReadFiles, "/a");
    let (d2, _token) = kernel.decide(Operation::ReadFiles, "/b");

    // Without attenuation, hashes should be stable
    assert_eq!(d1.pre_permissions_hash, d1.post_permissions_hash);
    assert_eq!(d1.post_permissions_hash, d2.pre_permissions_hash);
}

#[test]
fn test_doc_editor_kernel_session() {
    // doc-editor: read all, write docs, no network, no bash, no push
    use crate::capability::CapabilityLattice;
    let perms = PermissionLattice::builder()
        .description("doc-editor-like")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            edit_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .build();

    let mut kernel = Kernel::new(perms);

    // Can read
    assert!(kernel
        .decide(Operation::ReadFiles, "/workspace/README.md")
        .0
        .verdict
        .is_allowed());

    // Can write
    let (d, _token) = kernel.decide(Operation::WriteFiles, "/workspace/docs/guide.md");
    assert!(
        d.verdict.is_allowed() || matches!(d.verdict, Verdict::RequiresApproval),
        "write should be allowed or require approval"
    );

    // Cannot run bash
    assert!(kernel
        .decide(Operation::RunBash, "make docs")
        .0
        .verdict
        .is_denied());

    // Cannot push
    assert!(kernel
        .decide(Operation::GitPush, "origin/main")
        .0
        .verdict
        .is_denied());

    // Cannot fetch web
    assert!(kernel
        .decide(Operation::WebFetch, "https://example.com")
        .0
        .verdict
        .is_denied());
}

#[test]
fn test_monotone_sequence_property() {
    // After attenuation, previously-allowed operations may become denied
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);

    // Initially allowed
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    // permissive has uninhabitable_state so push requires approval, but capability is present
    assert!(!matches!(
        d.verdict,
        Verdict::Deny(DenyReason::InsufficientCapability)
    ));

    // Attenuate to read-only
    let ceiling = PermissionLattice::read_only();
    kernel.attenuate(&ceiling).unwrap();

    // Now denied
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::InsufficientCapability)
    ));
}

// ── Exposure plumbing tests ──────────────────────────────────────────

#[test]
fn test_exposure_starts_empty() {
    let perms = PermissionLattice::default();
    let kernel = Kernel::new(perms);

    assert_eq!(kernel.exposure().count(), 0);
    assert!(!kernel.exposure().is_uninhabitable());
}

#[test]
fn test_exposure_accumulates_on_allow() {
    // Use a profile that allows reads and web_fetch without uninhabitable_state obligations
    use crate::capability::CapabilityLattice;
    let perms = PermissionLattice::builder()
        .description("read-and-fetch")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .build();

    let mut kernel = Kernel::new(perms);

    // ReadFiles → PrivateDatan exposure
    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed());
    assert!(kernel.exposure().contains(ExposureLabel::PrivateData));
    assert_eq!(kernel.exposure().count(), 1);
    assert_eq!(d.exposure_transition.pre_count, 0);
    assert_eq!(d.exposure_transition.post_count, 1);
    assert_eq!(
        d.exposure_transition.contributed_label,
        Some(ExposureLabel::PrivateData)
    );

    // WebFetch → UntrustedContent exposure
    let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());
    assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));
    assert_eq!(kernel.exposure().count(), 2);
    assert_eq!(d.exposure_transition.pre_count, 1);
    assert_eq!(d.exposure_transition.post_count, 2);
}

#[test]
fn test_exposure_does_not_accumulate_on_deny() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // git_push=Never → denied, no exposure recorded
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(d.verdict.is_denied());
    assert_eq!(kernel.exposure().count(), 0);
    assert_eq!(d.exposure_transition.post_count, 0);
}

#[test]
fn test_exposure_monotone_never_decreases() {
    use crate::capability::CapabilityLattice;
    let perms = PermissionLattice::builder()
        .description("all-read")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .build();

    let mut kernel = Kernel::new(perms);

    // Build up exposure
    kernel.decide(Operation::ReadFiles, "/a");
    kernel.decide(Operation::WebFetch, "https://b.com");

    // Neutral operation (WriteFiles) should not reduce exposure
    kernel.decide(Operation::WriteFiles, "/c");
    assert_eq!(kernel.exposure().count(), 2);

    // Denied operation should not reduce exposure
    kernel.decide(Operation::RunBash, "echo hi");
    assert_eq!(kernel.exposure().count(), 2);
}

#[test]
fn test_dynamic_exposure_gate_blocks_exfil() {
    // Build a profile that allows ALL operations (no static obligations).
    // No uninhabitable_state obligations in the lattice because we construct one
    // without running normalize().
    use crate::capability::CapabilityLattice;
    let mut perms = PermissionLattice::builder()
        .description("everything-allowed")
        .capabilities(CapabilityLattice {
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
        })
        .build();

    // Clear any obligations the builder might have added
    perms.obligations.approvals.clear();

    // Use capability_only() to isolate the exposure gating subsystem
    // from flow control (which would deny earlier via FlowViolation).
    let mut kernel = Kernel::capability_only(perms);

    // Step 1: Read private data → exposure PrivateData
    let (d, _token) = kernel.decide(Operation::ReadFiles, "/etc/passwd");
    assert!(d.verdict.is_allowed());

    // Step 2: Fetch untrusted content → exposure UntrustedContent
    let (d, _token) = kernel.decide(Operation::WebFetch, "https://evil.com/payload");
    assert!(d.verdict.is_allowed());

    // Step 3: Try to push → uninhabitable_state would complete → dynamic gate!
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "dynamic exposure gate should block exfil, got {:?}",
        d.verdict
    );
    assert!(d.exposure_transition.dynamic_gate_applied);

    // Exposure should NOT have advanced (operation was gated, not allowed)
    assert!(!kernel.exposure().is_uninhabitable());
    assert_eq!(kernel.exposure().count(), 2);
}

#[test]
fn test_dynamic_exposure_gate_with_pre_approval() {
    use crate::capability::CapabilityLattice;
    let mut perms = PermissionLattice::builder()
        .description("everything-allowed")
        .capabilities(CapabilityLattice {
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
        })
        .build();

    perms.obligations.approvals.clear();

    // Use capability_only() to isolate the exposure gating subsystem.
    let mut kernel = Kernel::capability_only(perms);

    // Pre-grant approval for the exfil operation
    kernel.grant_approval(Operation::GitPush, 1);

    // Accumulate exposure
    kernel.decide(Operation::ReadFiles, "/etc/passwd");
    kernel.decide(Operation::WebFetch, "https://evil.com/payload");

    // Push with pre-approval should be allowed through the dynamic gate
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        d.verdict.is_allowed(),
        "pre-approved exfil should pass dynamic gate, got {:?}",
        d.verdict
    );
    assert!(d.exposure_transition.dynamic_gate_applied);
    assert!(d.exposure_transition.state_uninhabitable);
    assert!(kernel.exposure().is_uninhabitable());
}

#[test]
fn test_dynamic_exposure_gate_does_not_affect_non_exfil() {
    use crate::capability::CapabilityLattice;
    let mut perms = PermissionLattice::builder()
        .description("everything-allowed")
        .capabilities(CapabilityLattice {
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
        })
        .build();

    perms.obligations.approvals.clear();

    // Use capability_only() to isolate the exposure gating subsystem.
    let mut kernel = Kernel::capability_only(perms);

    // Accumulate two legs
    kernel.decide(Operation::ReadFiles, "/etc/passwd");
    kernel.decide(Operation::WebFetch, "https://evil.com");

    // Neutral ops should still be allowed even with high exposure
    let (d, _token) = kernel.decide(Operation::WriteFiles, "/workspace/out.txt");
    assert!(d.verdict.is_allowed());
    assert!(!d.exposure_transition.dynamic_gate_applied);

    // git_commit is not an exfil op — should be allowed
    let (d, _token) = kernel.decide(Operation::GitCommit, "fix: stuff");
    assert!(d.verdict.is_allowed());
    assert!(!d.exposure_transition.dynamic_gate_applied);
}

#[test]
fn test_exposure_transition_in_decision_trace() {
    use crate::capability::CapabilityLattice;
    let perms = PermissionLattice::builder()
        .description("read-only")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .build();

    let mut kernel = Kernel::new(perms);

    kernel.decide(Operation::ReadFiles, "/a");
    kernel.decide(Operation::ReadFiles, "/b");
    kernel.decide(Operation::WriteFiles, "/c"); // denied

    let trace = kernel.trace();

    // First read: exposure 0→1
    assert_eq!(trace[0].exposure_transition.pre_count, 0);
    assert_eq!(trace[0].exposure_transition.post_count, 1);
    assert_eq!(
        trace[0].exposure_transition.contributed_label,
        Some(ExposureLabel::PrivateData)
    );

    // Second read: exposure stays at 1 (already has PrivateData)
    assert_eq!(trace[1].exposure_transition.pre_count, 1);
    assert_eq!(trace[1].exposure_transition.post_count, 1);

    // Denied write: exposure stays at 1 (denied ops don't contribute)
    assert_eq!(trace[2].exposure_transition.pre_count, 1);
    assert_eq!(trace[2].exposure_transition.post_count, 1);
}

#[test]
fn test_runbash_dynamic_gate_omnibus() {
    // RunBash is special: it projects both PrivateData + ExfilVector.
    // If we've already ingested untrusted content, RunBash should
    // be dynamically gated because it's an exfil vector that would
    // complete the uninhabitable_state (it projects PrivateData too).
    use crate::capability::CapabilityLattice;
    use crate::CommandLattice;
    let mut perms = PermissionLattice::builder()
        .description("bash-and-web")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .commands(CommandLattice::permissive())
        .build();

    perms.obligations.approvals.clear();

    // Use capability_only() to isolate the exposure gating subsystem.
    let mut kernel = Kernel::capability_only(perms);

    // Fetch untrusted content
    kernel.decide(Operation::WebFetch, "https://evil.com/payload");
    assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));

    // RunBash with a permitted command — uninhabitable_state would complete via omnibus
    let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "RunBash omnibus projection should trigger dynamic gate, got {:?}",
        d.verdict
    );
    assert!(d.exposure_transition.dynamic_gate_applied);
}

// ── Isolation tests ─────────────────────────────────────────────

#[test]
fn test_isolation_minimum_met() {
    // Policy requires namespaced, runtime is MicroVM — should pass
    let perms =
        PermissionLattice::safe_pr_fixer().with_minimum_isolation(IsolationLattice::sandboxed());
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(
        d.verdict.is_allowed(),
        "MicroVM satisfies sandboxed minimum"
    );
}

#[test]
fn test_isolation_minimum_not_met() {
    // Policy requires MicroVM, runtime is localhost — should deny everything
    let perms =
        PermissionLattice::safe_pr_fixer().with_minimum_isolation(IsolationLattice::microvm());
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::localhost());

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(
        matches!(
            d.verdict,
            Verdict::Deny(DenyReason::IsolationInsufficient { .. })
        ),
        "localhost does not satisfy MicroVM minimum, got {:?}",
        d.verdict
    );
}

#[test]
fn test_isolation_minimum_exact_match() {
    // Policy requires sandboxed, runtime is exactly sandboxed — should pass
    let perms =
        PermissionLattice::safe_pr_fixer().with_minimum_isolation(IsolationLattice::sandboxed());
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::sandboxed());

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed(), "exact match satisfies minimum");
}

#[test]
fn test_isolation_minimum_partial_fail() {
    use crate::isolation::{FileIsolation, NetworkIsolation, ProcessIsolation};

    // Policy requires MicroVM + Filtered network
    let min = IsolationLattice::new(
        ProcessIsolation::MicroVM,
        FileIsolation::Sandboxed,
        NetworkIsolation::Filtered,
    );
    let perms = PermissionLattice::safe_pr_fixer().with_minimum_isolation(min);

    // Runtime has MicroVM process but Host network — partial failure
    let runtime = IsolationLattice::new(
        ProcessIsolation::MicroVM,
        FileIsolation::Sandboxed,
        NetworkIsolation::Host,
    );
    let mut kernel = Kernel::with_isolation(perms, runtime);

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(
        matches!(
            d.verdict,
            Verdict::Deny(DenyReason::IsolationInsufficient { .. })
        ),
        "Host network doesn't satisfy Filtered minimum"
    );
}

#[test]
fn test_isolation_no_minimum_always_passes() {
    // Policy has no minimum_isolation — any runtime works
    let perms = PermissionLattice::safe_pr_fixer();
    assert!(perms.minimum_isolation.is_none());
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::localhost());

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(
        d.verdict.is_allowed(),
        "no minimum → always passes isolation check"
    );
}

#[test]
fn test_airgapped_denies_network_ops() {
    // Even with web_fetch=Always, airgapped network denies it
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

    let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(
        matches!(d.verdict, Verdict::Deny(DenyReason::IsolationGated { .. })),
        "airgapped network must deny web_fetch even if capability allows it, got {:?}",
        d.verdict
    );
}

#[test]
fn test_airgapped_denies_web_search() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

    let (d, _token) = kernel.decide(Operation::WebSearch, "rust async");
    assert!(
        matches!(d.verdict, Verdict::Deny(DenyReason::IsolationGated { .. })),
        "airgapped network must deny web_search, got {:?}",
        d.verdict
    );
}

#[test]
fn test_airgapped_allows_non_network_ops() {
    // Airgapped still allows file operations and local commands
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed(), "airgapped should allow file reads");

    let (d, _token) = kernel.decide(Operation::GlobSearch, "**/*.rs");
    assert!(d.verdict.is_allowed(), "airgapped should allow glob search");
}

#[test]
fn test_filtered_network_allows_web_ops() {
    // Filtered network (not airgapped) should allow web operations
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm_with_network());

    let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(
        d.verdict.is_allowed(),
        "filtered network should allow web_fetch, got {:?}",
        d.verdict
    );
}

#[test]
fn test_isolation_minimum_meet_takes_stronger() {
    // When two policies are combined via meet, the minimum_isolation
    // should be the join (stronger) of both
    let a = PermissionLattice::permissive().with_minimum_isolation(IsolationLattice::sandboxed());
    let b = PermissionLattice::permissive().with_minimum_isolation(IsolationLattice::microvm());

    let result = a.meet(&b);
    assert!(
        result.minimum_isolation.is_some(),
        "meet should preserve minimum_isolation"
    );
    let min = result.minimum_isolation.unwrap();
    // MicroVM is stronger than sandboxed on all dimensions
    assert!(min.at_least(&IsolationLattice::microvm()));
}

#[test]
fn test_kernel_isolation_accessor() {
    let perms = PermissionLattice::safe_pr_fixer();
    let iso = IsolationLattice::microvm();
    let kernel = Kernel::with_isolation(perms, iso);

    assert_eq!(kernel.isolation(), &IsolationLattice::microvm());
}

// ── Certificate integration tests ───────────────────────────────

#[test]
fn test_from_certificate_creates_kernel() {
    use crate::certificate::{verify_certificate, LatticeCertificate};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let root_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + chrono::Duration::hours(8);

    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/human/alice".into(),
        not_after,
        &root_key,
        &rng,
    );

    let (cert, _) = cert
        .delegate(
            &PermissionLattice::restrictive(),
            "spiffe://test/agent/coder".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    let fingerprint = cert.fingerprint();
    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    let mut kernel = Kernel::from_certificate(verified, fingerprint);

    // Provenance is set
    let prov = kernel.provenance().unwrap();
    assert_eq!(prov.root_identity, "spiffe://test/human/alice");
    assert_eq!(prov.leaf_identity, "spiffe://test/agent/coder");
    assert_eq!(prov.chain_depth, 1);
    assert_eq!(prov.certificate_fingerprint, fingerprint);

    // Kernel makes decisions using the certificate's effective permissions
    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed());
}

#[test]
fn test_from_certificate_enforces_restrictions() {
    use crate::certificate::{verify_certificate, LatticeCertificate};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let root_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + chrono::Duration::hours(8);

    // Mint with permissive root
    let (cert, holder_key) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/root".into(),
        not_after,
        &root_key,
        &rng,
    );

    // Delegate to read_only
    let (cert, _) = cert
        .delegate(
            &PermissionLattice::read_only(),
            "spiffe://test/reader".into(),
            not_after,
            &holder_key,
            &rng,
        )
        .unwrap();

    let fingerprint = cert.fingerprint();
    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    let mut kernel = Kernel::from_certificate(verified, fingerprint);

    // Reading is allowed
    assert!(kernel
        .decide(Operation::ReadFiles, "/workspace/main.rs")
        .0
        .verdict
        .is_allowed());

    // Writing is denied (read_only profile)
    assert!(kernel
        .decide(Operation::GitPush, "origin/main")
        .0
        .verdict
        .is_denied());
}

#[test]
fn test_kernel_without_certificate_has_no_provenance() {
    let kernel = Kernel::new(PermissionLattice::default());
    assert!(kernel.provenance().is_none());
}

#[test]
fn test_from_certificate_attenuate_preserves_provenance() {
    use crate::certificate::{verify_certificate, LatticeCertificate};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let root_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let root_pub = root_key.public_key().as_ref().to_vec();
    let not_after = Utc::now() + chrono::Duration::hours(8);

    let (cert, _) = LatticeCertificate::mint(
        PermissionLattice::permissive(),
        "spiffe://test/root".into(),
        not_after,
        &root_key,
        &rng,
    );

    let fingerprint = cert.fingerprint();
    let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
    let mut kernel = Kernel::from_certificate(verified, fingerprint);

    // Attenuate the kernel
    kernel.attenuate(&PermissionLattice::read_only()).unwrap();

    // Provenance is preserved after attenuation
    let prov = kernel.provenance().unwrap();
    assert_eq!(prov.root_identity, "spiffe://test/root");
    assert_eq!(prov.certificate_fingerprint, fingerprint);
}

// ── Flow control integration tests ───────────────────────────────

#[test]
fn flow_enabled_by_default() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    // Flow graph is always on. Flat decide() no longer gates — use
    // decide_with_parents() for flow enforcement via the causal DAG.
    //
    // Observe web content (this is the data source, not an action).
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Write depending on web content is blocked by DAG flow check
    let (d2, _) = kernel.decide_with_parents(Operation::WriteFiles, "/tmp/test.txt", &[web]);
    assert!(
        matches!(d2.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
        "Flow control should enforce via DAG, got {:?}",
        d2.verdict
    );
}

#[test]
fn capability_only_skips_flow_control() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::capability_only(perms);
    // Without flow control, web + write should work fine
    let (d1, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(matches!(d1.verdict, Verdict::Allow));
    let (d2, _) = kernel.decide(Operation::WriteFiles, "/tmp/test.txt");
    assert!(matches!(d2.verdict, Verdict::Allow));
}

#[test]
fn flow_web_then_write_blocked() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // Observe web content — this is the data source node
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    // WriteFiles depending on web content is blocked by DAG flow check
    let (d2, _) = kernel.decide_with_parents(Operation::WriteFiles, "/tmp/test.txt", &[web]);
    assert!(
        matches!(d2.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
        "Expected FlowViolation, got {:?}",
        d2.verdict
    );
}

#[test]
fn flow_web_then_read_allowed() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // WebFetch taints session
    let (d1, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(matches!(d1.verdict, Verdict::Allow));

    // ReadFiles still allowed — only requires Informational authority
    let (d2, _) = kernel.decide(Operation::ReadFiles, "/tmp/test.txt");
    assert!(matches!(d2.verdict, Verdict::Allow));
}

#[test]
fn flow_pure_user_actions_allowed() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // Pure user-directed actions (no web taint) should pass flow checks.
    // Some ops may require approval from legacy checks — that's fine,
    // we just verify they're not denied by FlowViolation.
    let (d1, _) = kernel.decide(Operation::ReadFiles, "/src/main.rs");
    assert!(matches!(d1.verdict, Verdict::Allow));
    let (d2, _) = kernel.decide(Operation::WriteFiles, "/tmp/out.txt");
    assert!(matches!(d2.verdict, Verdict::Allow));
    let (d3, _) = kernel.decide(Operation::GitCommit, "fix: typo");
    assert!(matches!(d3.verdict, Verdict::Allow));
    // CreatePr may require approval via legacy static check — that's OK.
    // What matters is it's NOT a FlowViolation.
    let (d4, _) = kernel.decide(Operation::CreatePr, "fix typo");
    assert!(
        !matches!(d4.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
        "CreatePr should not be a flow violation: {:?}",
        d4.verdict
    );
}

#[test]
fn flow_check_runs_before_approvals() {
    let mut perms = PermissionLattice::permissive();
    // Force GitPush to require approval
    perms.capabilities.git_push = CapabilityLevel::LowRisk;
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // Pre-grant approval for GitPush
    kernel.grant_approval(Operation::GitPush, 1);

    // Observe web content (data source)
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    // GitPush depending on web node should be DENIED by DAG flow check
    // even with pre-granted approval
    let (d2, _) = kernel.decide_with_parents(Operation::GitPush, "origin main", &[web]);
    assert!(
        matches!(d2.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
        "Flow check must run before approval path! Got {:?}",
        d2.verdict
    );
}

// --- Causal DAG integration tests (step 6 of bright-knitting-mitten) ---

#[test]
fn dag_independent_branches_no_overtaint() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Task A: web content (adversarial)
    let web_id = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Task B: local file (trusted) — NO dependency on web
    let file_id = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[])
        .unwrap();

    // Task B write depends ONLY on file — ALLOWED
    let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/out.txt", &[file_id]);
    assert!(
        d.verdict.is_allowed(),
        "File-only write should be allowed, got {:?}",
        d.verdict
    );
    assert!(d.flow_node_id.is_some());

    // Task A write depends on web — DENIED
    let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/web.txt", &[web_id]);
    assert!(
        d.verdict.is_denied(),
        "Web-tainted write should be denied, got {:?}",
        d.verdict
    );
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::FlowViolation { .. })
    ));
}

#[test]
fn dag_transitive_taint_propagation() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Model plan derived from web content
    let plan = kernel
        .observe(portcullis_core::flow::NodeKind::ModelPlan, &[web])
        .unwrap();

    // Write depending on plan (transitively depends on web) — DENIED
    let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/derived.txt", &[plan]);
    assert!(
        d.verdict.is_denied(),
        "Transitive web taint should propagate, got {:?}",
        d.verdict
    );
}

#[test]
fn dag_clean_chain_allowed() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    let file = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[user])
        .unwrap();
    let plan = kernel
        .observe(portcullis_core::flow::NodeKind::ModelPlan, &[file])
        .unwrap();

    // Write depending on clean chain: user → file → plan — ALLOWED
    let (d, token) = kernel.decide_with_parents(Operation::WriteFiles, "/clean.txt", &[plan]);
    assert!(d.verdict.is_allowed());
    assert!(token.is_some());
    assert!(d.flow_node_id.is_some());
}

#[test]
fn dag_denied_action_produces_receipt() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    let (d, _) = kernel.decide_with_parents(Operation::CreatePr, "my-pr", &[web]);
    assert!(d.verdict.is_denied());
    match &d.verdict {
        Verdict::Deny(DenyReason::FlowViolation { receipt, .. }) => {
            assert!(
                receipt.is_some(),
                "Denied DAG action should include receipt"
            );
            assert!(
                receipt.as_ref().unwrap().contains("BLOCKED"),
                "Receipt should contain BLOCKED"
            );
        }
        other => panic!("Expected FlowViolation, got {:?}", other),
    }
}

#[test]
fn dag_always_on_even_capability_only() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);
    // capability_only() still has a flow graph — decide_with_parents uses the DAG

    let (d, _) = kernel.decide_with_parents(Operation::ReadFiles, "/workspace/main.rs", &[]);
    assert!(d.verdict.is_allowed());
    assert!(
        d.flow_node_id.is_some(),
        "DAG always on → should have flow_node_id"
    );
}

#[test]
fn dag_capability_check_still_applies() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();

    // DAG says allow (clean parents), but capability lattice says never for GitPush
    let (d, _) = kernel.decide_with_parents(Operation::GitPush, "origin/main", &[user]);
    assert!(
        d.verdict.is_denied(),
        "Capability check should still apply even when DAG allows, got {:?}",
        d.verdict
    );
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::InsufficientCapability)
    ));
}

#[test]
fn dag_bypasses_flat_flow_label() {
    // Issue #365: when both flow systems are enabled, the DAG should
    // supersede the flat label — not double-deny.
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control(); // flat label

    // Read web content — taints the flat session label
    let _web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Also taint the flat label via a regular decide()
    let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());

    // Now use the DAG with clean parents — should be allowed
    // even though the flat label is tainted
    let file = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[])
        .unwrap();
    let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/clean.txt", &[file]);
    assert!(
        d.verdict.is_allowed(),
        "DAG clean parents should override flat taint, got {:?}",
        d.verdict
    );
}

#[test]
fn dag_observe_works_on_capability_only() {
    // #753: flow graph is always present, even on capability_only kernels
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);
    let result = kernel.observe(portcullis_core::flow::NodeKind::FileRead, &[]);
    assert!(
        result.is_ok(),
        "observe() should succeed — DAG is always on"
    );
}

#[test]
fn dag_declassification_allows_validated_tool() {
    use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
    use portcullis_core::IntegLevel;

    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Add declassification rule: search API output gets Adversarial → Untrusted
    kernel.add_declassification_rule(DeclassificationRule {
        action: DeclassifyAction::RaiseIntegrity {
            from: IntegLevel::Adversarial,
            to: IntegLevel::Untrusted,
        },
        justification: "Search API returns curated content",
    });

    // Observe web content — normally Adversarial/NoAuthority
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    // Without declassification, web content → write would be DENIED
    // (NoAuthority cannot steer privileged actions).
    // But the rule raised integrity from Adversarial → Untrusted.
    // Authority is still NoAuthority, so writes are still denied by
    // the authority check. This verifies declassification fires but
    // doesn't grant more than it should.
    let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/out.txt", &[web]);
    assert!(
        d.verdict.is_denied(),
        "Authority is still NoAuthority — write should be denied even with raised integrity"
    );
}

#[test]
fn dag_declassification_authority_upgrade() {
    use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
    use portcullis_core::AuthorityLevel;

    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Raise authority: Informational → Suggestive (for curated tool output)
    // ToolResponse starts at Informational authority
    kernel.add_declassification_rule(DeclassificationRule {
        action: DeclassifyAction::RaiseAuthority {
            from: AuthorityLevel::Informational,
            to: AuthorityLevel::Suggestive,
        },
        justification: "Tool output from validated API",
    });

    // Also raise integrity so both checks pass
    kernel.add_declassification_rule(DeclassificationRule {
        action: DeclassifyAction::RaiseIntegrity {
            from: portcullis_core::IntegLevel::Adversarial,
            to: portcullis_core::IntegLevel::Untrusted,
        },
        justification: "Validated API output",
    });

    let tool = kernel
        .observe(portcullis_core::flow::NodeKind::ToolResponse, &[])
        .unwrap();

    // ToolResponse starts with Untrusted/Informational.
    // Declassification raises authority to Suggestive.
    // Write requires Suggestive authority — should now be allowed.
    let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/out.txt", &[tool]);
    assert!(
        d.verdict.is_allowed(),
        "Declassified tool response should allow write, got {:?}",
        d.verdict
    );
}

// ── Egress policy integration tests → tests/kernel_egress.rs (#825) ──

// ── #654: Causal decide — flow graph supersedes flat label in decide() ──

#[test]
fn causal_decide_flat_decide_skips_flow_gate_when_graph_enabled() {
    // #654: When the flow graph is enabled, flat decide() should NOT
    // use the session-level flow_label as a gate. The over-tainting
    // problem is solved by the DAG — callers use decide_with_parents()
    // for flow-checked decisions.
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // WebFetch taints the flat session label
    let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());

    // Without #654, this would be DENIED by the flat flow_label gate.
    // With #654, decide() skips the flat gate when the graph is active.
    let (d, _) = kernel.decide(Operation::WriteFiles, "/tmp/clean.txt");
    assert!(
        d.verdict.is_allowed(),
        "With flow graph enabled, flat decide() should NOT gate on session label. Got {:?}",
        d.verdict
    );
}

#[test]
fn dag_always_on_flat_decide_does_not_gate() {
    // #753: flow graph is always present — flat decide() never gates
    // on the session label. Use decide_with_parents() for flow enforcement.
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());

    // With flow graph always on, flat decide() skips the label gate
    let (d, _) = kernel.decide(Operation::WriteFiles, "/tmp/test.txt");
    assert!(
        d.verdict.is_allowed(),
        "With flow graph always on, flat decide() should not gate on session label. Got {:?}",
        d.verdict
    );
}

#[test]
fn causal_decide_flat_label_still_updated_for_audit() {
    // #654: Even when the graph is active and decide() skips the gate,
    // the flat flow_label is still updated for audit/reporting.
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // Fetch web content
    let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());

    // The flat label should be tainted (for audit) even though
    // it didn't gate the operation.
    // Verify by disabling the flow graph and checking that the
    // flat label would now gate.
    // We can't disable the graph, but we can verify the label
    // is tainted by checking the exposure transition covers web fetch.
    assert_eq!(
        d.exposure_transition.contributed_label,
        Some(ExposureLabel::UntrustedContent)
    );
}

#[test]
fn causal_decide_key_test_adversarial_read_clean_write_allowed() {
    // Issue #654 acceptance criteria:
    // "adversarial read + independent clean write → clean write ALLOWED"
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Adversarial content observed
    let _web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    // Independent clean file read
    let file = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[])
        .unwrap();

    // Clean write depending only on the file — ALLOWED
    let (d, token) = kernel.decide_with_parents(Operation::WriteFiles, "/clean.txt", &[file]);
    assert!(
        d.verdict.is_allowed(),
        "#654 key test: independent clean write must be ALLOWED. Got {:?}",
        d.verdict
    );
    assert!(token.is_some());
}

#[test]
fn causal_decide_key_test_write_depending_on_adversarial_denied() {
    // Issue #654 acceptance criteria:
    // "write that depends on adversarial content → still DENIED"
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Adversarial content observed
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    // Write depending on adversarial content — DENIED
    let (d, token) = kernel.decide_with_parents(Operation::WriteFiles, "/tainted.txt", &[web]);
    assert!(
        d.verdict.is_denied(),
        "#654 key test: write depending on adversarial content must be DENIED. Got {:?}",
        d.verdict
    );
    assert!(token.is_none());
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::FlowViolation { .. })
    ));
}

#[test]
fn causal_decide_exposure_still_tracked_for_audit() {
    // #654: ExposureTracker is still updated for audit/reporting.
    use crate::capability::CapabilityLattice;
    let mut perms = PermissionLattice::builder()
        .description("everything-allowed")
        .capabilities(CapabilityLattice {
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
        })
        .build();
    perms.obligations.approvals.clear();

    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control();

    // Read private data
    let (d, _) = kernel.decide(Operation::ReadFiles, "/etc/passwd");
    assert!(d.verdict.is_allowed());
    assert!(kernel.exposure().contains(ExposureLabel::PrivateData));

    // Fetch untrusted content
    let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());
    assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));

    // Exposure is tracked for audit even though flow graph is active
    assert_eq!(kernel.exposure().count(), 2);
}

// ── PolicyRuleSet integration tests → tests/kernel_policy.rs (#657) ──

// ── Receipt chain integration tests → tests/kernel_receipt.rs (#825) ──

// ── Enterprise allowlist enforcement (#734) ─────────────────────

#[test]
fn enterprise_blocks_denied_sink() {
    use portcullis_core::enterprise::EnterpriseAllowlist;
    use portcullis_core::SinkClass;

    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);

    // Enterprise policy denies git_commit sink
    kernel.set_enterprise(EnterpriseAllowlist {
        denied_sinks: vec![SinkClass::GitCommit],
        ..Default::default()
    });

    let (d, token) = kernel.decide(Operation::GitCommit, "fix: something");
    assert!(d.verdict.is_denied(), "enterprise should block git_commit");
    assert!(token.is_none());
    match &d.verdict {
        Verdict::Deny(DenyReason::EnterpriseBlocked { detail }) => {
            assert!(
                detail.contains("GitCommit"),
                "detail should mention the sink class: {detail}"
            );
        }
        other => panic!("expected EnterpriseBlocked, got {other:?}"),
    }
}

#[test]
fn enterprise_allows_permitted_sink() {
    use portcullis_core::enterprise::EnterpriseAllowlist;
    use portcullis_core::SinkClass;

    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);

    // Enterprise policy allows only workspace_write and git_commit
    kernel.set_enterprise(EnterpriseAllowlist {
        allowed_sinks: Some(vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit]),
        ..Default::default()
    });

    // git_commit is in the allowlist — should pass
    let (d, token) = kernel.decide(Operation::GitCommit, "fix: allowed");
    assert!(d.verdict.is_allowed(), "enterprise should allow git_commit");
    assert!(token.is_some());
}

#[test]
fn no_enterprise_is_passthrough() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);

    // No enterprise policy set — git_commit should be allowed by capabilities
    let (d, token) = kernel.decide(Operation::GitCommit, "fix: no enterprise");
    assert!(
        d.verdict.is_allowed(),
        "without enterprise policy, capabilities alone decide"
    );
    assert!(token.is_some());
}

// ── Kernel token verification tests → tests/kernel_token.rs (#825) ──

// ── Delegation enforcement tests → tests/kernel_delegation.rs ──

// ── Sink scope enforcement tests → tests/kernel_sink_scope.rs (#825) ──

// ═══════════════════════════════════════════════════════════════════
// extract_host unit tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_extract_host() {
    assert_eq!(
        extract_host("https://api.example.com/path"),
        "api.example.com"
    );
    assert_eq!(extract_host("http://host:8080/path"), "host");
    assert_eq!(extract_host("api.example.com"), "api.example.com");
    assert_eq!(extract_host("https://host.com"), "host.com");
}
