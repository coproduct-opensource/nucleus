//! Constitutional Kernel Demo — Two Amendments
//!
//! This is the demo from spec section 23:
//!
//! 1. Agent proposes a scheduler improvement patch. Constitutional kernel
//!    admits it — lineage shows parent → child with witness bundle, all
//!    invariants preserved.
//!
//! 2. Agent proposes a patch that sneaks in a new outbound network domain.
//!    Constitutional kernel rejects it — rejection reason shows
//!    `CapabilityNonEscalation: +evil.com`.
//!
//! Run with: `cargo test -p ck-kernel --test demo_two_amendments -- --nocapture`

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use ck_kernel::{CandidateAmendment, Kernel};
use ck_types::manifest::*;
use ck_types::witness::*;
use ck_types::{AdmissionDecision, ArtifactDigest, PatchClass};

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/// The constitution: what the governed controller is allowed to do.
fn genesis_policy() -> PolicyManifest {
    PolicyManifest {
        version: 1,
        capabilities: CapabilitySet {
            filesystem_read: ["/workspace/repo".into()].into(),
            filesystem_write: ["/workspace/repo".into(), "/workspace/artifacts".into()].into(),
            network_allow: ["api.github.com".into(), "crates.io".into()].into(),
            tools_allow: [
                "builder".into(),
                "tester".into(),
                "kani".into(),
                "replay".into(),
            ]
            .into(),
            secret_classes: BTreeSet::new(),
            max_parallel_tasks: 4,
        },
        io_surface: IoSurface {
            outbound_domains: ["api.github.com".into(), "crates.io".into()].into(),
            local_file_roots: ["/workspace".into()].into(),
            env_vars_readable: ["HOME".into(), "PATH".into()].into(),
            tool_namespaces: BTreeSet::new(),
            repo_write_targets: ["coproduct/nucleus".into()].into(),
        },
        budget_bounds: BudgetBounds {
            max_tokens: 200_000,
            max_wall_ms: 1_800_000,
            max_cpu_ms: 1_200_000,
            max_memory_bytes: 4_000_000_000,
            max_network_calls: 200,
            max_files_touched: 50,
            max_dollar_spend_millicents: 500_000,
            max_patch_attempts: 3,
        },
        proof_requirements: ProofRequirements {
            config_patch: ["build_pass".into(), "tests_pass".into()].into(),
            controller_patch: [
                "build_pass".into(),
                "tests_pass".into(),
                "kani_pass".into(),
                "replay_pass".into(),
            ]
            .into(),
            evaluator_patch: [
                "build_pass".into(),
                "tests_pass".into(),
                "replay_pass".into(),
            ]
            .into(),
        },
        amendment_rules: AmendmentRules {
            may_modify: [
                "controller_code".into(),
                "controller_config".into(),
                "evaluator_code".into(),
            ]
            .into(),
            may_not_modify: [
                "kernel_checker".into(),
                "constitution_manifest".into(),
                "signature_roots".into(),
            ]
            .into(),
            require_monotone_capabilities: true,
            require_monotone_io: true,
            require_monotone_proofreq: true,
            constitutional_human_signatures: 2,
        },
    }
}

fn make_witness(
    parent: &ArtifactDigest,
    candidate: &ArtifactDigest,
    patch_class: PatchClass,
    policy_before: &PolicyManifest,
    policy_after: &PolicyManifest,
    kani: Option<bool>,
) -> ck_types::WitnessBundle {
    ck_types::WitnessBundle {
        bundle_version: 1,
        parent_digest: parent.clone(),
        candidate_digest: candidate.clone(),
        patch_digest: ArtifactDigest::from_bytes(b"demo-patch"),
        patch_class,
        timestamp_utc: Utc::now(),
        toolchain: ToolchainInfo {
            container_digest: Some("sha256:abc123...pinned".into()),
            rustc_version: "1.85.0-nightly".into(),
            kani_version: Some("0.50.0".into()),
            kernel_version: "0.1.0".into(),
        },
        policy_before: policy_before.clone(),
        policy_after: policy_after.clone(),
        reports: VerificationReports {
            build: Some(ReportSummary {
                passed: true,
                summary: "cargo build --release: 0 errors, 0 warnings".into(),
                artifact_digest: Some(ArtifactDigest::from_bytes(b"binary-digest")),
            }),
            tests: Some(ReportSummary {
                passed: true,
                summary: "cargo test: 847 passed, 0 failed, 6 ignored".into(),
                artifact_digest: None,
            }),
            kani: kani.map(|p| ReportSummary {
                passed: p,
                summary: if p {
                    "6 proofs verified, 0 failures".into()
                } else {
                    "VERIFICATION FAILED: budget_no_underflow".into()
                },
                artifact_digest: None,
            }),
            policy_diff: None,
            replay: None,
            adversarial: None,
            termination: None,
            artifact_digests: BTreeMap::new(),
        },
        signatures: vec![BundleSignature {
            signer: "kernel-ci".into(),
            algorithm: "ed25519".into(),
            signature: "demo-signature-would-be-real-in-production".into(),
            role: None,
        }],
        source_tree_digest: None,
        build_container_digest: None,
    }
}

fn print_lineage(kernel: &Kernel) {
    eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║              CONSTITUTIONAL AMENDMENT LINEAGE               ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    for record in kernel.lineage() {
        let short_parent = &record.parent_digest.hex()[..12];
        let short_child = &record.candidate_digest.hex()[..12];
        let short_witness = &record.witness_digest.hex()[..12];
        eprintln!(
            "║ seq={:<3} {:?} {:<8} parent={}.. child={}.. ║",
            record.sequence,
            if record.admitted { "✓" } else { "✗" },
            format!("{:?}", record.patch_class),
            short_parent,
            short_child,
        );
        eprintln!(
            "║         witness={}..  {}  ║",
            short_witness,
            record.timestamp_utc.format("%Y-%m-%dT%H:%M:%SZ"),
        );
    }
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
}

// ═══════════════════════════════════════════════════════════════════════════
// DEMO
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn demo_valid_amendment_admitted() {
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  DEMO 1: Valid scheduler improvement — ADMITTED");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let policy = genesis_policy();
    let genesis = ArtifactDigest::from_bytes(b"controller-v1.0");
    let mut kernel = Kernel::new(genesis.clone());

    eprintln!("\n  Genesis: {}", genesis);
    eprintln!("  Policy digest: {}", policy.digest());
    eprintln!(
        "  Capabilities: {} network domains, {} tools",
        policy.capabilities.network_allow.len(),
        policy.capabilities.tools_allow.len(),
    );
    eprintln!(
        "  Budget: {} max tokens, ${}",
        policy.budget_bounds.max_tokens,
        policy.budget_bounds.max_dollar_spend_millicents as f64 / 100_000.0,
    );

    // Agent proposes: tighter retry backoff, same policy
    let candidate = ArtifactDigest::from_bytes(b"controller-v1.1-tighter-retry");
    let witness = make_witness(
        &genesis,
        &candidate,
        PatchClass::Controller,
        &policy,
        &policy,    // SAME POLICY — no escalation
        Some(true), // Kani passes
    );

    eprintln!("\n  Candidate: {}", candidate);
    eprintln!("  Patch class: Controller");
    eprintln!("  Policy diff: NONE (capabilities, I/O, budget, proof-req all identical)");
    eprintln!("  Build: PASS");
    eprintln!("  Tests: PASS (847 passed)");
    eprintln!("  Kani:  PASS (6 proofs verified)");

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Controller,
        witness,
    });

    match &decision {
        AdmissionDecision::Accepted {
            lineage_digest,
            witness_digest,
        } => {
            eprintln!("\n  ┌─────────────────────────────────────────────┐");
            eprintln!("  │  DECISION: ✓ ADMITTED                       │");
            eprintln!("  │  Lineage digest: {}..  │", &lineage_digest.hex()[..12]);
            eprintln!("  │  Witness digest: {}..  │", &witness_digest.hex()[..12]);
            eprintln!("  └─────────────────────────────────────────────┘");
        }
        other => panic!("Expected Accepted, got: {:?}", other),
    }

    print_lineage(&kernel);
    assert!(matches!(decision, AdmissionDecision::Accepted { .. }));
    assert_eq!(kernel.lineage_length(), 2);
}

#[test]
fn demo_malicious_amendment_rejected() {
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  DEMO 2: Malicious capability escalation — REJECTED");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let policy = genesis_policy();
    let genesis = ArtifactDigest::from_bytes(b"controller-v1.0");
    let mut kernel = Kernel::new(genesis.clone());

    // Agent proposes: same scheduler change BUT sneaks in a new network domain
    let mut escalated_policy = policy.clone();
    escalated_policy
        .capabilities
        .network_allow
        .insert("exfiltrate.evil.com".into());
    // Also tries to weaken proof requirements (drop kani)
    escalated_policy
        .proof_requirements
        .controller_patch
        .remove("kani_pass");

    let candidate = ArtifactDigest::from_bytes(b"controller-v1.1-with-backdoor");
    let witness = make_witness(
        &genesis,
        &candidate,
        PatchClass::Controller,
        &policy,
        &escalated_policy, // ESCALATED — new domain + weakened checks
        Some(true),
    );

    eprintln!("\n  Genesis: {}", genesis);
    eprintln!("  Candidate: {}", candidate);
    eprintln!("  Patch class: Controller");
    eprintln!("  Policy diff:");
    eprintln!("    network_allow: +exfiltrate.evil.com  ← ESCALATION");
    eprintln!("    controller_patch proof_requirements: -kani_pass  ← GOVERNANCE WEAKENING");
    eprintln!("  Build: PASS");
    eprintln!("  Tests: PASS");
    eprintln!("  Kani:  PASS");

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate,
        patch_class: PatchClass::Controller,
        witness,
    });

    match &decision {
        AdmissionDecision::Rejected { reasons } => {
            eprintln!("\n  ┌─────────────────────────────────────────────┐");
            eprintln!("  │  DECISION: ✗ REJECTED                       │");
            eprintln!("  │                                              │");
            for reason in reasons {
                eprintln!("  │  [{:?}]", reason.invariant);
                eprintln!("  │    {}", reason.message);
                eprintln!("  │                                              │");
            }
            eprintln!("  └─────────────────────────────────────────────┘");
        }
        other => panic!("Expected Rejected, got: {:?}", other),
    }

    print_lineage(&kernel);
    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert_eq!(kernel.lineage_length(), 1); // only genesis
}

#[test]
fn demo_full_lineage_sequence() {
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  DEMO 3: Full lineage — 3 valid, 1 rejected, 1 more valid");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let policy = genesis_policy();
    let genesis = ArtifactDigest::from_bytes(b"controller-v1.0");
    let mut kernel = Kernel::new(genesis.clone());

    // v1.1: tighter retry config (Config class, no Kani needed)
    let v1_1 = ArtifactDigest::from_bytes(b"v1.1-retry-config");
    let w = make_witness(&genesis, &v1_1, PatchClass::Config, &policy, &policy, None);
    let d = kernel.admit(CandidateAmendment {
        parent_digest: genesis.clone(),
        candidate_digest: v1_1.clone(),
        patch_class: PatchClass::Config,
        witness: w,
    });
    eprintln!("  v1.1 (Config — retry tuning):  {:?}", decision_tag(&d));

    // v1.2: scheduler refactor (Controller class, Kani required + provided)
    let v1_2 = ArtifactDigest::from_bytes(b"v1.2-scheduler-refactor");
    let w = make_witness(
        &v1_1,
        &v1_2,
        PatchClass::Controller,
        &policy,
        &policy,
        Some(true),
    );
    let d = kernel.admit(CandidateAmendment {
        parent_digest: v1_1.clone(),
        candidate_digest: v1_2.clone(),
        patch_class: PatchClass::Controller,
        witness: w,
    });
    eprintln!("  v1.2 (Controller — scheduler): {:?}", decision_tag(&d));

    // v1.3-BAD: tries to add a network domain (REJECTED)
    let mut bad_policy = policy.clone();
    bad_policy
        .capabilities
        .network_allow
        .insert("stealth.io".into());
    let v1_3_bad = ArtifactDigest::from_bytes(b"v1.3-bad-escalation");
    let w = make_witness(
        &v1_2,
        &v1_3_bad,
        PatchClass::Config,
        &policy,
        &bad_policy,
        None,
    );
    let d = kernel.admit(CandidateAmendment {
        parent_digest: v1_2.clone(),
        candidate_digest: v1_3_bad.clone(),
        patch_class: PatchClass::Config,
        witness: w,
    });
    eprintln!("  v1.3 (Config — escalation):    {:?}", decision_tag(&d));

    // v1.3: legitimate config patch after the failed attempt
    let v1_3 = ArtifactDigest::from_bytes(b"v1.3-legitimate-config");
    let w = make_witness(&v1_2, &v1_3, PatchClass::Config, &policy, &policy, None);
    let d = kernel.admit(CandidateAmendment {
        parent_digest: v1_2.clone(),
        candidate_digest: v1_3.clone(),
        patch_class: PatchClass::Config,
        witness: w,
    });
    eprintln!("  v1.3 (Config — legitimate):    {:?}", decision_tag(&d));

    // v1.4: tighter budget (child budget < parent budget = OK)
    let mut tighter_policy = policy.clone();
    tighter_policy.budget_bounds.max_tokens = 100_000;
    tighter_policy.budget_bounds.max_dollar_spend_millicents = 250_000;
    let v1_4 = ArtifactDigest::from_bytes(b"v1.4-tighter-budget");
    let w = make_witness(
        &v1_3,
        &v1_4,
        PatchClass::Config,
        &policy,
        &tighter_policy,
        None,
    );
    let d = kernel.admit(CandidateAmendment {
        parent_digest: v1_3.clone(),
        candidate_digest: v1_4.clone(),
        patch_class: PatchClass::Config,
        witness: w,
    });
    eprintln!("  v1.4 (Config — tighter budget): {:?}", decision_tag(&d));

    print_lineage(&kernel);

    assert_eq!(kernel.lineage_length(), 5); // genesis + 4 admitted (1 rejected)
    assert!(!kernel.is_admitted(&v1_3_bad)); // bad one not in lineage
    assert!(kernel.is_admitted(&v1_4)); // good one is
}

fn decision_tag(d: &AdmissionDecision) -> &'static str {
    match d {
        AdmissionDecision::Accepted { .. } => "ADMITTED",
        AdmissionDecision::Rejected { .. } => "REJECTED",
        AdmissionDecision::Quarantined { .. } => "QUARANTINED",
        AdmissionDecision::Expired => "EXPIRED",
    }
}
