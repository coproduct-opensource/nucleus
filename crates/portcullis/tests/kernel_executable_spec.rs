#![allow(deprecated)]
//! Executable Specification for the Kernel Decision Engine
//!
//! This module defines the kernel's intended behavior as a **reference model**
//! and then uses proptest to verify the production kernel matches it on all
//! random inputs.
//!
//! # What This Proves
//!
//! If these tests pass:
//! 1. **Monotone permissions**: effective permissions never increase during a session
//! 2. **Monotone exposure**: accumulated exposure never decreases during a session
//! 3. **Complete mediation**: every Operation produces a verdict (no panics, no gaps)
//! 4. **Dynamic exposure gate soundness**: if uninhabitable_state would complete AND op is exfil,
//!    the kernel requires approval (unless pre-approved)
//! 5. **Exposure accumulation correctness**: only allowed ops contribute exposure
//! 6. **Budget monotonicity**: consumed_usd never decreases
//! 7. **Trace integrity**: trace length == decision_count, sequences are monotone
//!
//! # Relation to Kani proofs
//!
//! The Kani proofs in `kani.rs` verify algebraic properties of the *lattice types*
//! (ExposureSet, PermissionLattice, etc.) via bounded model checking. This file
//! verifies the *kernel engine* — the stateful orchestrator that uses those types.
//! Together they provide end-to-end verification from lattice algebra to runtime
//! enforcement.

use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{
    CapabilityLattice, CapabilityLevel, CommandLattice, ExposureLabel, ExposureSet, Obligations,
    Operation, PermissionLattice,
};
use proptest::prelude::*;
use rust_decimal::Decimal;

// ============================================================================
// Reference Model — the executable spec
// ============================================================================

/// Classify an operation into its exposure label (reference implementation).
fn spec_classify(op: Operation) -> Option<ExposureLabel> {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            Some(ExposureLabel::PrivateData)
        }
        Operation::WebFetch | Operation::WebSearch => Some(ExposureLabel::UntrustedContent),
        Operation::RunBash | Operation::GitPush | Operation::CreatePr | Operation::SpawnAgent => {
            Some(ExposureLabel::ExfilVector)
        }
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::GitCommit
        | Operation::ManagePods => None,
    }
}

/// Is this operation an exfiltration vector?
fn spec_is_exfil(op: Operation) -> bool {
    matches!(
        op,
        Operation::RunBash | Operation::GitPush | Operation::CreatePr | Operation::SpawnAgent
    )
}

/// Project exposure after an operation (reference implementation).
fn spec_project_exposure(current: &ExposureSet, op: Operation) -> ExposureSet {
    if op == Operation::RunBash {
        current
            .union(&ExposureSet::singleton(ExposureLabel::PrivateData))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector))
    } else if let Some(label) = spec_classify(op) {
        current.union(&ExposureSet::singleton(label))
    } else {
        current.clone()
    }
}

/// Record exposure from an allowed operation (reference implementation).
fn spec_apply_record(current: &ExposureSet, op: Operation) -> ExposureSet {
    if let Some(label) = spec_classify(op) {
        current.union(&ExposureSet::singleton(label))
    } else {
        current.clone()
    }
}

// ============================================================================
// Proptest Strategies
// ============================================================================

fn arb_capability_level() -> impl Strategy<Value = CapabilityLevel> {
    prop_oneof![
        Just(CapabilityLevel::Never),
        Just(CapabilityLevel::LowRisk),
        Just(CapabilityLevel::Always),
    ]
}

fn arb_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::ReadFiles),
        Just(Operation::WriteFiles),
        Just(Operation::EditFiles),
        Just(Operation::RunBash),
        Just(Operation::GlobSearch),
        Just(Operation::GrepSearch),
        Just(Operation::WebSearch),
        Just(Operation::WebFetch),
        Just(Operation::GitCommit),
        Just(Operation::GitPush),
        Just(Operation::CreatePr),
        Just(Operation::ManagePods),
        Just(Operation::SpawnAgent),
    ]
}

fn arb_capability_lattice() -> impl Strategy<Value = CapabilityLattice> {
    (
        (
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
            arb_capability_level(),
        ),
        arb_capability_level(),
    )
        .prop_map(|((rf, wf, ef, rb, gs, grs, ws, wfe, gc, gp, cp, mp), sa)| {
            CapabilityLattice {
                read_files: rf,
                write_files: wf,
                edit_files: ef,
                run_bash: rb,
                glob_search: gs,
                grep_search: grs,
                web_search: ws,
                web_fetch: wfe,
                git_commit: gc,
                git_push: gp,
                create_pr: cp,
                manage_pods: mp,
                spawn_agent: sa,
                extensions: std::collections::BTreeMap::new(),
            }
        })
}

/// Generate a sequence of operations (3..12 operations per session).
fn arb_operation_sequence() -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(arb_operation(), 3..12)
}

// ============================================================================
// Property: Monotone permissions under attenuation
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_attenuation_monotone(
        caps_initial in arb_capability_lattice(),
        caps_ceiling in arb_capability_lattice(),
    ) {
        let initial = PermissionLattice::builder()
            .description("initial")
            .capabilities(caps_initial)
            .build();
        let ceiling = PermissionLattice::builder()
            .description("ceiling")
            .capabilities(caps_ceiling)
            .build();

        let mut kernel = Kernel::new(initial);
        let pre_effective = kernel.effective().clone();

        let result = kernel.attenuate(&ceiling);
        prop_assert!(result.is_ok(), "attenuate should never fail");

        // Post-attenuation effective ≤ pre-attenuation effective
        prop_assert!(
            kernel.effective().leq(&pre_effective),
            "attenuate violated monotonicity: effective increased"
        );
    }
}

// ============================================================================
// Property: Monotone exposure through operation sequences
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_exposure_monotone_through_session(
        caps in arb_capability_lattice(),
        ops in arb_operation_sequence(),
    ) {
        let mut perms = PermissionLattice::builder()
            .description("exposure-test")
            .capabilities(caps)
            .commands(CommandLattice::permissive())
            .build();
        perms.obligations = Obligations::default();

        let mut kernel = Kernel::new(perms);

        let mut prev_exposure_count = kernel.exposure().count();

        for op in ops {
            let (d, _token) = kernel.decide(op, "test-subject");

            // Exposure count must never decrease
            let new_count = kernel.exposure().count();
            prop_assert!(
                new_count >= prev_exposure_count,
                "exposure decreased from {} to {} after {:?} (verdict: {:?})",
                prev_exposure_count,
                new_count,
                op,
                d.verdict,
            );

            // ExposureTransition must be consistent
            prop_assert_eq!(
                d.exposure_transition.pre_count, prev_exposure_count,
                "pre_count mismatch in decision {}",
                d.sequence,
            );
            prop_assert_eq!(
                d.exposure_transition.post_count, new_count,
                "post_count mismatch in decision {}",
                d.sequence,
            );

            prev_exposure_count = new_count;
        }
    }
}

// ============================================================================
// Property: Complete mediation — every op produces a verdict, never panics
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_complete_mediation(
        caps in arb_capability_lattice(),
        ops in arb_operation_sequence(),
    ) {
        let perms = PermissionLattice::builder()
            .description("mediation-test")
            .capabilities(caps)
            .commands(CommandLattice::permissive())
            .build();

        let mut kernel = Kernel::new(perms);

        for (i, op) in ops.iter().enumerate() {
            let (d, _token) = kernel.decide(*op, "test-subject");

            // Must produce a definitive verdict
            prop_assert!(
                matches!(d.verdict, Verdict::Allow | Verdict::RequiresApproval | Verdict::Deny(_)),
                "decision {} for {:?} produced unexpected verdict: {:?}",
                i, op, d.verdict,
            );

            // Sequence must match
            prop_assert_eq!(d.sequence, i as u64);
        }

        // Trace length matches decision count
        prop_assert_eq!(kernel.trace().len(), ops.len());
        prop_assert_eq!(kernel.decision_count(), ops.len() as u64);
    }
}

// ============================================================================
// Property: Dynamic exposure gate soundness
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_dynamic_exposure_gate_soundness(
        caps in arb_capability_lattice(),
        ops in arb_operation_sequence(),
    ) {
        let mut perms = PermissionLattice::builder()
            .description("exposure-gate-test")
            .capabilities(caps)
            .commands(CommandLattice::permissive())
            .build();
        // Clear static obligations to isolate dynamic gating
        perms.obligations = Obligations::default();

        let mut kernel = Kernel::new(perms);

        // Track our own reference exposure accumulator
        let mut ref_exposure = ExposureSet::empty();

        for op in ops {
            let pre_uninhabitable = ref_exposure.is_uninhabitable();
            let projected = spec_project_exposure(&ref_exposure, op);
            let would_complete = !pre_uninhabitable && projected.is_uninhabitable();

            let (d, _token) = kernel.decide(op, "test-subject");

            // If dynamic gate should fire: uninhabitable_state would newly complete AND op is exfil
            if would_complete && spec_is_exfil(op) {
                // The kernel must either:
                // - RequiresApproval (dynamic gate fired)
                // - Deny (something else blocked it first — capability, path, etc.)
                prop_assert!(
                    matches!(d.verdict, Verdict::RequiresApproval | Verdict::Deny(_)),
                    "dynamic gate should have fired for {:?} but got {:?}",
                    op, d.verdict,
                );
            }

            // Update reference exposure (only if operation was allowed)
            if d.verdict.is_allowed() {
                ref_exposure = spec_apply_record(&ref_exposure, op);
            }
        }
    }
}

// ============================================================================
// Property: Exposure only advances on allowed operations
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_exposure_only_on_allow(
        caps in arb_capability_lattice(),
        ops in arb_operation_sequence(),
    ) {
        let mut perms = PermissionLattice::builder()
            .description("exposure-allow-test")
            .capabilities(caps)
            .commands(CommandLattice::permissive())
            .build();
        perms.obligations = Obligations::default();

        let mut kernel = Kernel::new(perms);

        for op in ops {
            let pre_count = kernel.exposure().count();
            let (d, _token) = kernel.decide(op, "test-subject");
            let post_count = kernel.exposure().count();

            if d.verdict.is_denied() || matches!(d.verdict, Verdict::RequiresApproval) {
                // Denied/gated operations must NOT advance exposure
                prop_assert_eq!(
                    pre_count, post_count,
                    "exposure advanced on denied/gated op {:?}: {} -> {}",
                    op, pre_count, post_count,
                );
            }
        }
    }
}

// ============================================================================
// Property: Budget monotonicity
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_budget_monotone(
        charges in prop::collection::vec(0u32..100, 1..10),
    ) {
        let perms = PermissionLattice::safe_pr_fixer(); // $5 budget
        let mut kernel = Kernel::new(perms);

        let mut prev_remaining = kernel.remaining_usd();

        for charge_cents in charges {
            let amount = Decimal::new(charge_cents as i64, 2);
            match kernel.charge(amount) {
                Ok(remaining) => {
                    // Remaining must not increase
                    prop_assert!(
                        remaining <= prev_remaining,
                        "remaining increased from {} to {} after charging {}",
                        prev_remaining, remaining, amount,
                    );
                    prev_remaining = remaining;
                }
                Err(DenyReason::BudgetExhausted { .. }) => {
                    // Budget exhaustion is valid — remaining should still be non-negative
                    prop_assert!(
                        kernel.remaining_usd() >= Decimal::ZERO,
                        "remaining went negative: {}",
                        kernel.remaining_usd(),
                    );
                }
                Err(other) => {
                    prop_assert!(false, "unexpected deny reason: {:?}", other);
                }
            }
        }
    }
}

// ============================================================================
// Property: Trace integrity — sequences are monotonically increasing
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_trace_sequence_monotone(
        caps in arb_capability_lattice(),
        ops in arb_operation_sequence(),
    ) {
        let perms = PermissionLattice::builder()
            .description("trace-test")
            .capabilities(caps)
            .commands(CommandLattice::permissive())
            .build();

        let mut kernel = Kernel::new(perms);

        for op in &ops {
            kernel.decide(*op, "test-subject");
        }

        let trace = kernel.trace();

        // Verify monotone sequence
        for i in 1..trace.len() {
            prop_assert!(
                trace[i].sequence > trace[i - 1].sequence,
                "sequence not monotone at index {}: {} vs {}",
                i, trace[i].sequence, trace[i - 1].sequence,
            );
        }

        // Verify permission hash chain
        for i in 1..trace.len() {
            prop_assert_eq!(
                &trace[i].pre_permissions_hash,
                &trace[i - 1].post_permissions_hash,
                "permission hash chain broken at index {}",
                i,
            );
        }
    }
}

// ============================================================================
// Property: Exposure transition contributed_label matches spec_classify
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_exposure_transition_label_matches_spec(
        caps in arb_capability_lattice(),
        ops in arb_operation_sequence(),
    ) {
        let perms = PermissionLattice::builder()
            .description("label-test")
            .capabilities(caps)
            .commands(CommandLattice::permissive())
            .build();

        let mut kernel = Kernel::new(perms);

        for op in ops {
            let (d, _token) = kernel.decide(op, "test-subject");
            let expected_label = spec_classify(op);
            prop_assert_eq!(
                d.exposure_transition.contributed_label, expected_label,
                "contributed_label mismatch for {:?}",
                op,
            );
        }
    }
}

// ============================================================================
// Concrete scenario specs: attack chain simulations
// ============================================================================

/// Spec: the Clinejection attack (WebFetch → RunBash) must be blocked.
///
/// This is the executable spec version of Kani proof A8.
#[test]
fn spec_clinejection_blocked() {
    let mut perms = PermissionLattice::builder()
        .description("clinejection-test")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Always,
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
        .commands(CommandLattice::permissive())
        .build();
    perms.obligations = Obligations::default();

    // Use capability_only() to isolate exposure gating from flow control.
    // (With Kernel::new(), flow control blocks this attack even earlier
    // via FlowViolation — this test specifically validates exposure gating.)
    let mut kernel = Kernel::capability_only(perms);

    // Step 1: WebFetch injects untrusted content
    let (d, _token) = kernel.decide(Operation::WebFetch, "https://attacker.com/payload.js");
    assert!(d.verdict.is_allowed());
    assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));

    // Step 2: RunBash (npm install with preinstall hook) → dynamic gate
    let (d, _token) = kernel.decide(Operation::RunBash, "npm install");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "Clinejection: RunBash after WebFetch MUST be gated, got {:?}",
        d.verdict,
    );
    assert!(d.exposure_transition.dynamic_gate_applied);
}

/// Spec: the Toxic Agent Flow (ReadFiles → WebFetch → GitPush) must be blocked.
///
/// Attacker injects payload via web content → agent reads private data → pushes.
#[test]
fn spec_toxic_agent_flow_blocked() {
    let mut perms = PermissionLattice::builder()
        .description("toxic-flow-test")
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
            git_push: CapabilityLevel::Always,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .commands(CommandLattice::permissive())
        .build();
    perms.obligations = Obligations::default();

    // Use capability_only() to isolate exposure gating from flow control.
    let mut kernel = Kernel::capability_only(perms);

    // Step 1: Read private data
    let (d, _token) = kernel.decide(Operation::ReadFiles, "/etc/passwd");
    assert!(d.verdict.is_allowed());

    // Step 2: Fetch untrusted content (attacker's payload)
    let (d, _token) = kernel.decide(Operation::WebFetch, "https://evil.com/instructions");
    assert!(d.verdict.is_allowed());

    // Step 3: GitPush → uninhabitable_state completes → dynamic gate
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "Toxic Agent Flow: GitPush after ReadFiles+WebFetch MUST be gated, got {:?}",
        d.verdict,
    );
    assert!(d.exposure_transition.dynamic_gate_applied);
}

/// Spec: pre-approved operations bypass the dynamic gate exactly N times.
#[test]
fn spec_pre_approval_consumed_exactly() {
    let mut perms = PermissionLattice::builder()
        .description("approval-test")
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
            git_push: CapabilityLevel::Always,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .commands(CommandLattice::permissive())
        .build();
    perms.obligations = Obligations::default();

    // Use capability_only() to isolate exposure gating from flow control.
    let mut kernel = Kernel::capability_only(perms);

    // Pre-grant exactly 2 GitPush approvals
    kernel.grant_approval(Operation::GitPush, 2);

    // Build up exposure
    kernel.decide(Operation::ReadFiles, "/etc/passwd");
    kernel.decide(Operation::WebFetch, "https://evil.com");

    // First push: approved (consumes 1 approval)
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/feat-1");
    assert!(d.verdict.is_allowed(), "1st push should be pre-approved");

    // Second push: approved (consumes last approval)
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/feat-2");
    assert!(d.verdict.is_allowed(), "2nd push should be pre-approved");

    // Third push: no approvals left → RequiresApproval
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/feat-3");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "3rd push should require approval (exhausted), got {:?}",
        d.verdict,
    );
}

/// Spec: neutral operations don't trigger dynamic gate even at high exposure.
#[test]
fn spec_neutral_ops_unaffected_by_exposure() {
    let mut perms = PermissionLattice::builder()
        .description("neutral-test")
        .capabilities(CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Always,
            spawn_agent: CapabilityLevel::Never,
            extensions: std::collections::BTreeMap::new(),
        })
        .commands(CommandLattice::permissive())
        .build();
    perms.obligations = Obligations::default();

    // Use capability_only() to isolate exposure gating from flow control.
    let mut kernel = Kernel::capability_only(perms);

    // Build up 2 exposure legs
    kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    kernel.decide(Operation::WebFetch, "https://docs.example.com");
    assert_eq!(kernel.exposure().count(), 2);

    // Neutral operations should be allowed regardless of exposure
    let neutral_ops = [
        Operation::WriteFiles,
        Operation::EditFiles,
        Operation::GitCommit,
        Operation::ManagePods,
    ];
    for op in neutral_ops {
        let (d, _token) = kernel.decide(op, "test-subject");
        assert!(
            d.verdict.is_allowed(),
            "neutral op {:?} should be allowed at exposure count 2, got {:?}",
            op,
            d.verdict,
        );
        assert!(
            !d.exposure_transition.dynamic_gate_applied,
            "neutral op {:?} should not trigger dynamic gate",
            op,
        );
    }
}

/// Adversarial gap #10: Deny is never followed by Allow for the same
/// operation in the same session (without intervening approval grant).
///
/// The kernel's monotonicity invariant means: if an operation is denied
/// due to InsufficientCapability (level=Never), no subsequent call with
/// the same operation can return Allow — because permissions only tighten.
#[test]
fn prop_deny_never_followed_by_allow_same_op() {
    // Use a profile where some ops are denied
    let perms = PermissionLattice::read_only();
    let mut kernel = Kernel::new(perms);

    // Collect denied operations
    let mut denied_ops: Vec<Operation> = Vec::new();
    for &op in &Operation::ALL {
        let (d, _token) = kernel.decide(op, "test-subject");
        if matches!(d.verdict, Verdict::Deny(DenyReason::InsufficientCapability)) {
            denied_ops.push(op);
        }
    }

    // Verify: calling the same denied ops again still denies them
    assert!(!denied_ops.is_empty(), "read_only should deny some ops");
    for &op in &denied_ops {
        let (d, _token) = kernel.decide(op, "test-subject-retry");
        assert!(
            matches!(d.verdict, Verdict::Deny(DenyReason::InsufficientCapability)),
            "op {:?} was denied, then allowed on retry — monotonicity violated",
            op,
        );
    }

    // Verify with a permissive profile that attenuating never widens
    let permissive = PermissionLattice::permissive();
    let mut kernel2 = Kernel::new(permissive);

    // Allow everything first
    for &op in &Operation::ALL {
        let (d, _token) = kernel2.decide(op, "allowed");
        // Some ops may require approval, but none should be InsufficientCapability
        assert!(
            !matches!(d.verdict, Verdict::Deny(DenyReason::InsufficientCapability)),
            "permissive profile should not deny {:?} for capability",
            op,
        );
    }

    // Attenuate to restrictive
    let _ = kernel2.attenuate(&PermissionLattice::restrictive());

    // Now the same ops that were allowed should be denied
    let (d, _token) = kernel2.decide(Operation::RunBash, "after-attenuate");
    assert!(
        matches!(d.verdict, Verdict::Deny(DenyReason::InsufficientCapability)),
        "RunBash should be denied after attenuating to restrictive",
    );
}
