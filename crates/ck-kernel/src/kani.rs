//! Kani BMC harnesses for constitutional kernel invariants.
//!
//! These proofs verify that the kernel's admission algorithm enforces
//! the constitutional contract using SYMBOLIC inputs via kani::any(),
//! not just concrete test cases.
//!
//! Approach: BTreeSet<String> is too complex for direct symbolic analysis.
//! We use a bounded symbolic model with kani::any::<bool>() to decide
//! set membership over a fixed universe of elements, and kani::any::<u64>()
//! for numeric fields. This covers ALL combinations within the bound.
//!
//! Proved invariants:
//! 1. Capability widening on ordinary path is impossible (symbolic)
//! 2. Governance weakening on ordinary path is impossible (symbolic)
//! 3. Rejected amendments never appear in the lineage
//! 4. Budget escalation on ordinary path is impossible (symbolic)
//! 5. Constitutional self-merge is always rejected
//! 6. Valid amendment with identical policy always admitted
//! 7a-7e. I/O surface widening on ordinary path is impossible (one proof per axis)

#![cfg(kani)]

use std::collections::BTreeSet;

use crate::{CandidateAmendment, Kernel};
use ck_types::manifest::*;
use ck_types::witness::*;
use ck_types::{AdmissionDecision, ArtifactDigest, PatchClass};

// ═══════════════════════════════════════════════════════════════════════════
// SYMBOLIC HELPERS — bounded model over a small universe
// ═══════════════════════════════════════════════════════════════════════════

/// Fixed universe of possible set elements for bounded symbolic analysis.
// Universes kept at 2 elements to keep BTreeSet<String> CBMC state tractable.
// 2 elements → 4 subsets per set; the proof covers ∀ subsets, so the
// invariant is verified exhaustively within this bound.
const DOMAIN_UNIVERSE: &[&str] = &["a.com", "b.com"];
const PATH_UNIVERSE: &[&str] = &["/workspace", "/tmp"];
const TOOL_UNIVERSE: &[&str] = &["builder", "tester"];
const PROOF_UNIVERSE: &[&str] = &["build_pass", "tests_pass"];
const ENV_UNIVERSE: &[&str] = &["HOME", "PATH"];
const REPO_UNIVERSE: &[&str] = &["org/repo1", "org/repo2"];

/// Build a symbolic BTreeSet by choosing membership for each element.
fn symbolic_set(universe: &[&str]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for &elem in universe {
        if kani::any::<bool>() {
            set.insert(elem.to_string());
        }
    }
    set
}

/// Build a symbolic BudgetBounds where each field is independently symbolic.
/// Fields are bounded to [0, 1000] to keep the SAT search tractable —
/// the proof verifies escalation detection, not full u64 range.
fn symbolic_budget() -> BudgetBounds {
    let b = BudgetBounds {
        max_tokens: kani::any(),
        max_wall_ms: kani::any(),
        max_cpu_ms: kani::any(),
        max_memory_bytes: kani::any(),
        max_network_calls: kani::any(),
        max_files_touched: kani::any(),
        max_dollar_spend_millicents: kani::any(),
        max_patch_attempts: kani::any(),
    };
    kani::assume(b.max_tokens <= 1000);
    kani::assume(b.max_wall_ms <= 1000);
    kani::assume(b.max_cpu_ms <= 1000);
    kani::assume(b.max_memory_bytes <= 1000);
    kani::assume(b.max_network_calls <= 1000);
    kani::assume(b.max_files_touched <= 1000);
    kani::assume(b.max_dollar_spend_millicents <= 1000);
    kani::assume(b.max_patch_attempts <= 1000);
    b
}

/// Build a parent policy with fixed (non-empty) sets.
fn parent_policy() -> PolicyManifest {
    PolicyManifest {
        version: 1,
        capabilities: CapabilitySet {
            filesystem_read: ["/workspace".into()].into(),
            filesystem_write: ["/workspace".into()].into(),
            network_allow: ["a.com".into()].into(),
            tools_allow: ["builder".into()].into(),
            secret_classes: BTreeSet::new(),
            max_parallel_tasks: 2,
        },
        io_surface: IoSurface {
            outbound_domains: ["a.com".into()].into(),
            local_file_roots: ["/workspace".into()].into(),
            env_vars_readable: BTreeSet::new(),
            tool_namespaces: BTreeSet::new(),
            repo_write_targets: BTreeSet::new(),
        },
        budget_bounds: BudgetBounds {
            max_tokens: 100,
            max_wall_ms: 100,
            max_cpu_ms: 100,
            max_memory_bytes: 100,
            max_network_calls: 10,
            max_files_touched: 10,
            max_dollar_spend_millicents: 100,
            max_patch_attempts: 3,
        },
        proof_requirements: ProofRequirements {
            config_patch: ["build_pass".into()].into(),
            controller_patch: ["build_pass".into(), "kani_pass".into()].into(),
            evaluator_patch: ["build_pass".into()].into(),
        },
        amendment_rules: AmendmentRules {
            may_modify: ["code".into()].into(),
            may_not_modify: ["kernel".into()].into(),
            require_monotone_capabilities: true,
            require_monotone_io: true,
            require_monotone_proofreq: true,
            constitutional_human_signatures: 2,
        },
    }
}

fn make_witness_for_proof(
    parent: &ArtifactDigest,
    candidate: &ArtifactDigest,
    patch_class: PatchClass,
    policy_before: &PolicyManifest,
    policy_after: &PolicyManifest,
    include_kani: bool,
) -> ck_types::WitnessBundle {
    use chrono::Utc;
    use std::collections::BTreeMap;

    ck_types::WitnessBundle {
        bundle_version: 1,
        parent_digest: parent.clone(),
        candidate_digest: candidate.clone(),
        patch_digest: ArtifactDigest::from_hex("abcd"),
        patch_class,
        timestamp_utc: Utc::now(),
        toolchain: ToolchainInfo {
            container_digest: None,
            rustc_version: "1.85.0".into(),
            kani_version: None,
            kernel_version: "0.1.0".into(),
        },
        policy_before: policy_before.clone(),
        policy_after: policy_after.clone(),
        reports: VerificationReports {
            build: Some(ReportSummary {
                passed: true,
                summary: "ok".into(),
                artifact_digest: None,
            }),
            tests: Some(ReportSummary {
                passed: true,
                summary: "ok".into(),
                artifact_digest: None,
            }),
            kani: if include_kani {
                Some(ReportSummary {
                    passed: true,
                    summary: "ok".into(),
                    artifact_digest: None,
                })
            } else {
                None
            },
            policy_diff: None,
            replay: None,
            adversarial: None,
            termination: None,
            sandbox: None,
            artifact_digests: BTreeMap::new(),
        },
        signatures: vec![BundleSignature {
            signer: "ci".into(),
            algorithm: "ed25519".into(),
            signature: "sig".into(),
            role: None,
        }],
        source_tree_digest: None,
        build_container_digest: None,
        manifest_digest_before: None,
        manifest_digest_after: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 1: Capability widening is ALWAYS rejected (symbolic network_allow)
// ═══════════════════════════════════════════════════════════════════════════

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_capability_escalation_always_rejected() {
    let pp = parent_policy();
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    // Child has a SYMBOLIC network_allow set drawn from DOMAIN_UNIVERSE
    let mut child = pp.clone();
    child.capabilities.network_allow = symbolic_set(DOMAIN_UNIVERSE);

    // Assume the child is a STRICT superset (has something parent doesn't)
    let parent_net = &pp.capabilities.network_allow;
    let child_net = &child.capabilities.network_allow;
    kani::assume(!child_net.is_subset(parent_net));

    let candidate = ArtifactDigest::from_hex("candidate");
    let witness =
        make_witness_for_proof(&genesis, &candidate, PatchClass::Config, &pp, &child, false);

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Config,
        witness,
    });

    // THEOREM: ANY capability escalation is rejected
    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert!(!kernel.is_admitted(&candidate));
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 2: Governance weakening is ALWAYS rejected (symbolic proof_reqs)
// ═══════════════════════════════════════════════════════════════════════════

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_governance_weakening_always_rejected() {
    let pp = parent_policy();
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    // Child has SYMBOLIC proof requirements (subset of PROOF_UNIVERSE)
    let mut child = pp.clone();
    child.proof_requirements.controller_patch = symbolic_set(PROOF_UNIVERSE);

    // Assume child WEAKENS requirements (child is strict subset of parent)
    let parent_reqs = &pp.proof_requirements.controller_patch;
    let child_reqs = &child.proof_requirements.controller_patch;
    kani::assume(!parent_reqs.is_subset(child_reqs)); // parent has something child dropped

    let candidate = ArtifactDigest::from_hex("candidate");
    let witness =
        make_witness_for_proof(&genesis, &candidate, PatchClass::Config, &pp, &child, false);

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Config,
        witness,
    });

    // THEOREM: ANY governance weakening is rejected
    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert!(!kernel.is_admitted(&candidate));
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 3: Rejected amendments NEVER appear in lineage
// ═══════════════════════════════════════════════════════════════════════════

#[kani::proof]
#[kani::solver(cadical)]
fn proof_rejected_never_in_lineage() {
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    // Unknown parent — guaranteed rejection
    let fake_parent = ArtifactDigest::from_hex("fake");
    let candidate = ArtifactDigest::from_hex("candidate");
    let policy = parent_policy();
    let witness = make_witness_for_proof(
        &fake_parent,
        &candidate,
        PatchClass::Config,
        &policy,
        &policy,
        false,
    );

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: fake_parent,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Config,
        witness,
    });

    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert!(!kernel.is_admitted(&candidate));
    assert_eq!(kernel.lineage_length(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 4: Budget escalation is ALWAYS rejected (fully symbolic bounds)
// ═══════════════════════════════════════════════════════════════════════════

#[kani::proof]
#[kani::solver(cadical)]
fn proof_budget_escalation_always_rejected() {
    let pp = parent_policy();
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    // Child has FULLY SYMBOLIC budget bounds
    let mut child = pp.clone();
    child.budget_bounds = symbolic_budget();

    // Assume at least one budget field EXCEEDS the parent
    kani::assume(
        child.budget_bounds.max_tokens > pp.budget_bounds.max_tokens
            || child.budget_bounds.max_wall_ms > pp.budget_bounds.max_wall_ms
            || child.budget_bounds.max_cpu_ms > pp.budget_bounds.max_cpu_ms
            || child.budget_bounds.max_memory_bytes > pp.budget_bounds.max_memory_bytes
            || child.budget_bounds.max_network_calls > pp.budget_bounds.max_network_calls
            || child.budget_bounds.max_files_touched > pp.budget_bounds.max_files_touched
            || child.budget_bounds.max_dollar_spend_millicents
                > pp.budget_bounds.max_dollar_spend_millicents
            || child.budget_bounds.max_patch_attempts > pp.budget_bounds.max_patch_attempts,
    );

    let candidate = ArtifactDigest::from_hex("candidate");
    let witness =
        make_witness_for_proof(&genesis, &candidate, PatchClass::Config, &pp, &child, false);

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Config,
        witness,
    });

    // THEOREM: ANY budget escalation is rejected
    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert!(!kernel.is_admitted(&candidate));
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 5: Constitutional self-merge is ALWAYS rejected
// ═══════════════════════════════════════════════════════════════════════════

#[kani::proof]
#[kani::solver(cadical)]
fn proof_constitutional_self_merge_impossible() {
    let policy = parent_policy();
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    let candidate = ArtifactDigest::from_hex("candidate");
    let witness = make_witness_for_proof(
        &genesis,
        &candidate,
        PatchClass::Constitutional,
        &policy,
        &policy,
        false,
    );

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Constitutional,
        witness,
    });

    // THEOREM: constitutional patches are NEVER self-merged
    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert!(!kernel.is_admitted(&candidate));
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 6: Config patch with identical policy is ALWAYS admitted
// ═══════════════════════════════════════════════════════════════════════════

#[kani::proof]
#[kani::solver(cadical)]
fn proof_identical_policy_config_patch_admitted() {
    let policy = parent_policy();
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    let candidate = ArtifactDigest::from_hex("candidate");
    let witness = make_witness_for_proof(
        &genesis,
        &candidate,
        PatchClass::Config,
        &policy,
        &policy, // identical
        false,
    );

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Config,
        witness,
    });

    // THEOREM: identical policy config patch is ALWAYS admitted
    assert!(matches!(decision, AdmissionDecision::Accepted { .. }));
    assert!(kernel.is_admitted(&candidate));
    assert_eq!(kernel.lineage_length(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF 7a-7e: I/O surface widening is ALWAYS rejected (one axis per proof)
//
// Split into per-axis proofs for tractable verification time.
// Each proof symbolizes one IoSurface field while keeping others identical
// to parent, then assumes the symbolic set is a strict superset.
// Together they cover all 5 axes of IoSurface.
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: prove that widening a single IoSurface axis is always rejected.
fn prove_io_axis_rejection(
    mutate: fn(&mut ck_types::manifest::IoSurface),
    is_widened: fn(&ck_types::manifest::IoSurface, &ck_types::manifest::IoSurface) -> bool,
) {
    let pp = parent_policy();
    let genesis = ArtifactDigest::from_hex("genesis");
    let mut kernel = Kernel::new(genesis.clone());

    let mut child = pp.clone();
    mutate(&mut child.io_surface);
    kani::assume(is_widened(&child.io_surface, &pp.io_surface));

    let candidate = ArtifactDigest::from_hex("candidate");
    let witness =
        make_witness_for_proof(&genesis, &candidate, PatchClass::Config, &pp, &child, false);

    let decision = kernel.admit(CandidateAmendment {
        parent_digest: genesis,
        candidate_digest: candidate.clone(),
        patch_class: PatchClass::Config,
        witness,
    });

    assert!(matches!(decision, AdmissionDecision::Rejected { .. }));
    assert!(!kernel.is_admitted(&candidate));
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_io_outbound_domains_widening_rejected() {
    prove_io_axis_rejection(
        |io| io.outbound_domains = symbolic_set(DOMAIN_UNIVERSE),
        |child, parent| !child.outbound_domains.is_subset(&parent.outbound_domains),
    );
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_io_local_file_roots_widening_rejected() {
    prove_io_axis_rejection(
        |io| io.local_file_roots = symbolic_set(PATH_UNIVERSE),
        |child, parent| !child.local_file_roots.is_subset(&parent.local_file_roots),
    );
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_io_env_vars_widening_rejected() {
    prove_io_axis_rejection(
        |io| io.env_vars_readable = symbolic_set(ENV_UNIVERSE),
        |child, parent| !child.env_vars_readable.is_subset(&parent.env_vars_readable),
    );
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_io_tool_namespaces_widening_rejected() {
    prove_io_axis_rejection(
        |io| io.tool_namespaces = symbolic_set(TOOL_UNIVERSE),
        |child, parent| !child.tool_namespaces.is_subset(&parent.tool_namespaces),
    );
}

#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(3)]
fn proof_io_repo_write_targets_widening_rejected() {
    prove_io_axis_rejection(
        |io| io.repo_write_targets = symbolic_set(REPO_UNIVERSE),
        |child, parent| {
            !child
                .repo_write_targets
                .is_subset(&parent.repo_write_targets)
        },
    );
}
