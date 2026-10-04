//! The probe table, and the accounting rows beside it: what is probed, what is not and why,
//! and what falsifies itself elsewhere.
//!
//! Order is the shell script's, so the run reads the same: the xtask families first, then the
//! shell gates.

use super::perturb::{self as p, GenFn, PerturbFn};

/// How a gate is invoked, and therefore how its CI wiring is checked.
pub enum Family {
    /// `bash scripts/<gate> <flags>`; `flags` must be how CI invokes it.
    Script {
        gate: &'static str,
        flags: &'static str,
    },
    /// `cargo run -q -p xtask -- <sub>`, which CI must invoke bare.
    Xtask { sub: &'static str },
    /// A gate CI invokes BOTH bare and with a flag, probed on the flagged form too.
    XtaskFlagged {
        sub: &'static str,
        flags: &'static str,
    },
    /// A gate CI invokes with a flag this harness cannot supply, probed bare on the conjuncts
    /// that do not need it. Pays for the difference with two assertions: the clean bare run is
    /// GREEN, and the perturbed bare run reds WITH `marker` in its output -- exit status alone
    /// cannot tell "the conjunct under test fired" from "the gate fell over on the way there".
    XtaskPartial {
        sub: &'static str,
        ci_flags: &'static str,
        marker: &'static str,
    },
    /// A gate CI invokes with flags naming files the JOB generates and the tree does not carry.
    /// CI's flags are asserted verbatim; the probe's may differ ONLY in the generated paths.
    XtaskGenerated {
        sub: &'static str,
        ci_flags: &'static str,
        generated: &'static [Generated],
    },
}

/// One generated input: the name CI uses, a temp-file name for the probe's copy, and the
/// function that writes it.
pub struct Generated {
    pub ci_name: &'static str,
    /// `(prefix, extension)` of the probe's temporary file. It must sit OUTSIDE the repository:
    /// a file left in the tree trips the dirty-tree guard on the next run.
    pub temp: (&'static str, &'static str),
    pub gen_name: &'static str,
    pub write: GenFn,
    /// The generator must produce a NON-EMPTY file; a changed-files list may legitimately be
    /// empty and only has to exist.
    pub must_be_nonempty: bool,
}

pub struct Perturbation {
    pub name: &'static str,
    pub apply: PerturbFn,
}

pub struct Probe {
    pub family: Family,
    pub target: &'static str,
    pub desc: &'static str,
    pub perturb: Perturbation,
}

macro_rules! pert {
    ($f:ident) => {
        Perturbation {
            name: stringify!($f),
            apply: p::$f,
        }
    };
}

const fn script(gate: &'static str, flags: &'static str) -> Family {
    Family::Script { gate, flags }
}

const fn xtask(sub: &'static str) -> Family {
    Family::Xtask { sub }
}

const POLICY: &[Generated] = &[
    Generated {
        ci_name: "before.toml",
        temp: ("policy-base", ".toml"),
        gen_name: "gen_policy_base",
        write: p::gen_policy_base,
        must_be_nonempty: true,
    },
    Generated {
        ci_name: "changed.txt",
        temp: ("policy-changed", ".txt"),
        gen_name: "gen_policy_changed",
        write: p::gen_policy_changed,
        must_be_nonempty: false,
    },
];

pub fn probes() -> Vec<Probe> {
    vec![
        // ECON BOUNDARY (#2514): the perturbation is the defect itself, one decision function
        // reaching for the market.
        Probe {
            family: xtask("econ-boundary"),
            target: "crates/nucleus-tool-proxy/src/run_gate.rs",
            desc: "a capability decision reaching into the economic layer",
            perturb: pert!(perturb_econ_boundary_reach),
        },
        // ADR 0007 C-4; `f7f9719b` is the defect this generalises.
        Probe {
            family: xtask("convergence"),
            target: "crates/nucleus-tool-proxy/src/run_gate.rs",
            desc: "one more affine type taken by reference",
            perturb: pert!(perturb_convergence_linearity),
        },
        Probe {
            family: xtask("bound"),
            target: "crates/nucleus-tool-proxy/src/run_gate.rs",
            desc: "one more witness accepted and dropped",
            perturb: pert!(perturb_bound_dropped_witness),
        },
        // A floor with slack under it has already stopped gating (ADR 0007 I-1). Deliberately
        // NOT a dropped witness: that reds through `bound`'s INERT_TOTAL cross-check, an error
        // rather than the scorecard's own decision procedure.
        Probe {
            family: xtask("scorecard"),
            target: "crates/nucleus-tool-proxy/src/run_gate.rs",
            desc: "a family's pin gone slack under it",
            perturb: pert!(perturb_scorecard_slack),
        },
        Probe {
            family: xtask("scorecard"),
            target: "crates/nucleus-tool-proxy/src/pod_mgmt.rs",
            desc: "a law the tree declares and nothing discharges",
            perturb: pert!(perturb_scorecard_undischarged_law),
        },
        Probe {
            family: xtask("scorecard"),
            target: "crates/nucleus-pca/src/lib.rs",
            desc: "a crate's totality declaration losing one of its seven lints",
            perturb: pert!(perturb_scorecard_partial_totality),
        },
        // `life` is pinned at a MEASURED zero; the slack check turns the first discharge into a
        // red demanding the pin be raised.
        Probe {
            family: xtask("scorecard"),
            target: "crates/nucleus-node/src/broker_launch.rs",
            desc: "the first affine right to gain a validity interval",
            perturb: pert!(perturb_scorecard_first_expiry),
        },
        Probe {
            family: xtask("scorecard"),
            target: "crates/nucleus-tool-proxy/src/art12.rs",
            desc: "a waiver that expires downgraded to one that never does",
            perturb: pert!(perturb_scorecard_forever_waiver),
        },
        Probe {
            family: xtask("assurance-required"),
            target: "ci/assurance-required-ratchet.txt",
            desc: "a claim whose falsifier the merge queue does not gate on, past the pin",
            perturb: pert!(perturb_assurance_required_pin),
        },
        Probe {
            family: xtask("pin-parity"),
            target: "ci/lean/lean-toolchain",
            desc: "two first-party Lean versions in one tree",
            perturb: pert!(perturb_lean_toolchain_split),
        },
        // Exit 2 ("could not look") is red and is the right red: a pin nobody can resolve is
        // not a pin.
        Probe {
            family: xtask("self-pin"),
            target: ".github/workflows/scan.yml",
            desc: "a self-pin naming a commit that does not exist",
            perturb: pert!(perturb_self_pin_sha),
        },
        Probe {
            family: xtask("allowlist-gates"),
            target: "ci/allowlist-gates.txt",
            desc: "an allowlist grown past its pinned size",
            perturb: pert!(perturb_allowlist_pin),
        },
        // `--parity` is the mode that checks the Rust harness implements every gate its shell
        // scripts announce. A mode nothing probes is a gate that cannot fail.
        Probe {
            family: Family::XtaskFlagged {
                sub: "allowlist-gates",
                flags: "--parity",
            },
            target: "scripts/check-ingest-hashed.sh",
            desc: "a shell gate the Rust harness never ported",
            perturb: pert!(perturb_unported_shell_gate),
        },
        Probe {
            family: xtask("fly-pools"),
            target: "ci/fly-runner/manager.toml",
            desc: "the committed POOLS default the manager refuses",
            perturb: pert!(perturb_fly_pool_volumes),
        },
        Probe {
            family: xtask("pipefail"),
            target: ".github/workflows/a2a-tck.yml",
            desc: "a pipeline added to a block with no pipefail",
            perturb: pert!(perturb_pipefail_new_unguarded_pipe),
        },
        // gatehouse-pin, probed on the two conjuncts that need no gatehouse checkout. It was
        // UNCOVERED as "takes --gatehouse <path>", which is true of its THIRD conjunct only.
        Probe {
            family: Family::XtaskPartial {
                sub: "gatehouse-pin",
                ci_flags: "--gatehouse gatehouse",
                marker: "the pins name different gatehouses",
            },
            target: ".github/workflows/gatehouse-shadow.yml",
            desc: "two workflows building gatehouse at different commits",
            perturb: pert!(perturb_gatehouse_ref_skew),
        },
        Probe {
            family: Family::XtaskPartial {
                sub: "gatehouse-pin",
                ci_flags: "--gatehouse gatehouse",
                marker: "a step runs a gatehouse no pin names",
            },
            target: ".github/workflows/gatehouse-shadow.yml",
            desc: "a step falling back to the action's downloaded default",
            perturb: pert!(perturb_gatehouse_bin_dir_dropped),
        },
        // Retargeted when the harness left scripts/: the shell planted this in its own text,
        // which is now a one-line shim with no `mktemp` to rewrite. Any shell file the gate
        // scans is the same subject.
        Probe {
            family: xtask("portability"),
            target: "scripts/check-ci-spec-golden.sh",
            desc: "a BSD-only shell construct reintroduced",
            perturb: pert!(perturb_portability_bsd_only),
        },
        Probe {
            family: xtask("action-inputs"),
            target: ".github/workflows/gatehouse-shadow.yml",
            desc: "a `with:` key the action does not declare",
            perturb: pert!(perturb_action_inputs_undeclared_key),
        },
        Probe {
            family: xtask("workspace-members"),
            target: "Cargo.toml",
            desc: "a crate dropped from the workspace members list",
            perturb: pert!(perturb_workspace_member_dropped),
        },
        Probe {
            family: xtask("command-grammar"),
            target: "docs/design/command-bands.toml",
            desc: "a leaf command whose authority band the table no longer declares",
            perturb: pert!(perturb_command_band_dropped),
        },
        Probe {
            family: Family::XtaskFlagged {
                sub: "scoreboard-ratchet",
                flags: "--baseline scripts/exemplar-baseline.json",
            },
            target: "scripts/exemplar-baseline.json",
            desc: "a baseline claiming a score the tree does not have",
            perturb: pert!(perturb_exemplar_baseline),
        },
        // An unroutable job looks exactly like a busy pool: "waiting" is the normal state.
        Probe {
            family: xtask("fly-pools"),
            target: ".github/workflows/audit.yml",
            desc: "a job routed at a runner variable nobody declared",
            perturb: pert!(perturb_runs_on_undeclared_var),
        },
        Probe {
            family: xtask("push-auth"),
            target: ".github/workflows/clippy-ratchet.yml",
            desc: "a CI push relying on the checkout's ambient credential",
            perturb: pert!(perturb_push_auth_strip),
        },
        Probe {
            family: xtask("coverage-floor"),
            target: ".github/workflows/coverage-matrix.yml",
            desc: "a coverage floor lowered without moving its pin",
            perturb: pert!(perturb_coverage_floor),
        },
        Probe {
            family: xtask("gate-budget"),
            target: ".github/workflows/gatehouse-shadow.yml",
            desc: "a gate timeout its job kills before the runner can report",
            perturb: pert!(perturb_gate_budget_timeout),
        },
        // `GateMode::Preflight` builds the kernel `with_skip_for_testing()`, so an amendment is
        // just a second manifest; one entry added to `network_allow` is refused as
        // CapabilityNonEscalation.
        Probe {
            family: Family::XtaskGenerated {
                sub: "policy-gate",
                ci_flags: "--base before.toml --candidate PolicyManifest.toml --changed-files changed.txt",
                generated: POLICY,
            },
            target: "PolicyManifest.toml",
            desc: "an amendment the constitutional kernel must refuse",
            perturb: pert!(perturb_policy_escalation),
        },
        Probe {
            family: script("check-line-ratchet.sh", "--strict"),
            target: "crates/portcullis/src/kernel.rs",
            desc: "400 lines past the ceiling",
            perturb: pert!(perturb_line_ratchet),
        },
        Probe {
            family: script("check-gate-defs-match-plan.sh", ""),
            target: ".gatehouse/gates/fmt.json",
            desc: "a gate definition that declares no tools",
            perturb: pert!(perturb_gate_def_tools_dropped),
        },
        Probe {
            family: script("check-dep-ceiling.sh", ""),
            target: "scripts/check-dep-ceiling.sh",
            desc: "a ceiling above the count it caps",
            perturb: pert!(perturb_dep_ceiling_raise),
        },
        Probe {
            family: script("check-wasm-closure.sh", ""),
            target: "scripts/check-wasm-closure.sh",
            desc: "a crate forbidden that is in the closure",
            perturb: pert!(perturb_wasm_closure_forbid_present),
        },
        Probe {
            family: script("check-law-mechanisms.sh", ""),
            target: "crates/portcullis/src/lattice.rs",
            desc: "a declared-dead mechanism gains a production call site",
            perturb: pert!(perturb_law_mechanism_wired),
        },
        Probe {
            family: script("check-law-mechanisms.sh", ""),
            target: "crates/portcullis/src/budget.rs",
            desc: "one allowance past the crate's dead-code ceiling",
            perturb: pert!(perturb_dead_code_ratchet),
        },
        Probe {
            family: script("check-inert-authority.sh", ""),
            target: "crates/portcullis/src/lattice.rs",
            desc: "a new witness accepted and dropped",
            perturb: pert!(perturb_inert_authority_added),
        },
        Probe {
            family: script("check-inert-authority.sh", ""),
            target: "crates/nucleus-cli/src/grant.rs",
            desc: "a declared site fixed, its row left behind",
            perturb: pert!(perturb_inert_authority_paid),
        },
        Probe {
            family: script("check-mediation.sh", ""),
            target: "crates/nucleus-tool-proxy/src/egress.rs",
            desc: "a raw Command::new on the agent path",
            perturb: pert!(perturb_mediation),
        },
        Probe {
            family: script("check-sealed-home.sh", ""),
            target: "crates/portcullis-effects/src/lib.rs",
            desc: "an un-allowlisted spawn in the sealed home",
            perturb: pert!(perturb_sealed_home),
        },
        Probe {
            family: script("check-verify-strict.sh", ""),
            target: "crates/nucleus-identity/src/lib.rs",
            desc: "a non-strict dalek .verify()",
            perturb: pert!(perturb_verify_strict),
        },
        Probe {
            family: script("check-verify-strict.sh", ""),
            target: "crates/ck-types/src/witness.rs",
            desc: "a cofactored ring ED25519 verify",
            perturb: pert!(perturb_ring_ed25519),
        },
        Probe {
            family: script("check-failclosed-verifiers.sh", ""),
            target: "crates/nucleus-identity/src/lib.rs",
            desc: "a verifier returning Ok where it cannot check",
            perturb: pert!(perturb_failclosed),
        },
        Probe {
            family: script("check-ingest-hashed.sh", ""),
            target: "crates/nucleus-tool-proxy/src/egress.rs",
            desc: "an unwitnessed .observe() ingest",
            perturb: pert!(perturb_ingest_hashed),
        },
        Probe {
            family: script("check-sandbox-trusted-base.sh", ""),
            target: "sandbox-trusted-base.txt",
            desc: "a pinned_by naming a nonexistent test",
            perturb: pert!(perturb_trusted_base),
        },
        Probe {
            family: script("check-test-helpers-not-in-production.sh", ""),
            target: "crates/nucleus-tool-proxy/Cargo.toml",
            desc: "test-helpers enabled on a non-dev edge",
            perturb: pert!(perturb_test_helpers_in_prod),
        },
        Probe {
            family: script("check-lean-libs-built.sh", ""),
            target: "crates/portcullis-core/lean/lakefile.lean",
            desc: "a lean_lib nothing builds",
            perturb: pert!(perturb_lean_lib_unbuilt),
        },
        Probe {
            family: script("check-lean-libs-built.sh", ""),
            target: ".github/workflows/ifc-lean.yml",
            desc: "a default_target package no workflow bare-builds",
            perturb: pert!(perturb_default_target_unbuilt),
        },
        Probe {
            family: script("check-kani-proof-count.sh", "--strict"),
            target: "crates/portcullis/src/kani.rs",
            desc: "a deleted Kani harness",
            perturb: pert!(perturb_kani_harness_deleted),
        },
        Probe {
            family: script("check-task-compiler-offline.sh", ""),
            target: "crates/nucleus-task-compiler/Cargo.toml",
            desc: "a network crate in the task compiler",
            perturb: pert!(perturb_compiler_online),
        },
        Probe {
            family: script("check-declassify-sink-scope-enforced.sh", ""),
            target: "crates/portcullis/src/flow_graph.rs",
            desc: "the applied sink mask widened to admit every sink",
            perturb: pert!(perturb_declassify_unscope),
        },
        Probe {
            family: script("check-declassify-governor-keys-sealed.sh", ""),
            target: "crates/nucleus-tool-proxy/src/declassify.rs",
            desc: "a set_trusted_keys caller outside kernel construction",
            perturb: pert!(perturb_governor_keys_unsealed),
        },
        // The EXACT defect the North Star ledger gate was built for, quoted verbatim.
        Probe {
            family: script("check-north-star-ledger.sh", ""),
            target: "docs/north-star.md",
            desc: "the original overclaiming declassification status row restored",
            perturb: pert!(perturb_ledger_restore_false_row),
        },
        Probe {
            family: script("check-c1-inbound-fences.sh", ""),
            target: "crates/nucleus-tool-proxy/src/workload.rs",
            desc: "the reserved-namespace fence D neutered",
            perturb: pert!(perturb_c1_inbound_fence),
        },
        Probe {
            family: script("check-declassify-value-bound.sh", ""),
            target: "crates/portcullis/src/flow_graph.rs",
            desc: "value_binding_ok neutered to accept a substituted value",
            perturb: pert!(perturb_declassify_value_unbind),
        },
        Probe {
            family: script("check-extracted-callsites.sh", ""),
            target: "crates/nucleus-tool-proxy/src/workload.rs",
            desc: "the live ident_may_deliver call site removed",
            perturb: pert!(perturb_extracted_callsite),
        },
        Probe {
            family: script("check-no-hmac-auth.sh", ""),
            target: "crates/nucleus-node/src/auth.rs",
            desc: "a retired NUCLEUS_NODE_AUTH_SECRET reference reintroduced",
            perturb: pert!(perturb_no_hmac_auth),
        },
        // CI-1 (crates/ci-spec): one probe per founding-defect class.
        Probe {
            family: script("check-ci-spec.sh", ""),
            target: ".github/workflows/kani-nightly-noop.yml",
            desc: "a noop twin missing one of the real twin's paths",
            perturb: pert!(perturb_twin_paths_ignore),
        },
        Probe {
            family: script("check-ci-spec.sh", ""),
            target: ".github/workflows/zizmor.yml",
            desc: "cancel-in-progress true under merge_group",
            perturb: pert!(perturb_cancel_in_progress),
        },
        Probe {
            family: script("check-ci-spec-bite.sh", ""),
            target: "ci/lean/CiSpecBite.lean",
            desc: "a structure declared in the bite",
            perturb: pert!(perturb_bite_semantics),
        },
        Probe {
            family: script("check-ci-spec-golden.sh", ""),
            target: "ci/lean/CiSpec/Golden.lean",
            desc: "a hand-edited golden vector",
            perturb: pert!(perturb_golden_lean),
        },
        Probe {
            family: script("check-ci-assurance-ledger.sh", ""),
            target: "docs/assurance/ci-assurance.md",
            desc: "a NOT-YET row promoted to PROVED with no evidence or pin change",
            perturb: pert!(perturb_ci_assurance_overclaim),
        },
        Probe {
            family: script("check-kani-divergence.sh", ""),
            target: "crates/portcullis/src/capability.rs",
            desc: "an unlisted cfg(not(kani)) fork",
            perturb: pert!(perturb_kani_divergence_unlisted),
        },
    ]
}

/// Uncovered, LISTED rather than omitted. The count is a ratchet that may only shrink: a
/// meta-gate that silently covered half the gates would be the exact vacuity it exists to find.
/// The history of every paid-down row (10 -> 2 in September 2026, each one an exemption whose
/// stated obstacle named the gate's SUBJECT and not its DETECTION) is in the git log of
/// `scripts/check-gates-can-fail.sh`.
pub const UNCOVERED: &[&str] = &[
    "xtask prepush                 a local aggregator CI never runs (only scripts/prepush.sh calls it, so no workflow invocation exists to probe); each gate it wraps is decided in CI on its own -- scoreboard-ratchet and scorecard probed, line-ratchet via check-line-ratchet.sh, cargo audit in audit.yml -- and its fold is unit-tested in crates/xtask/src/prepush.rs. Remove when the domain is derived from CI-reachable sources only",
    "xtask ci-spec                 reads live branch protection; a perturbation needs the GitHub API, not a file",
    "xtask line-ratchet            probed through scripts/check-line-ratchet.sh, which is the same decision procedure",
];

// 2026-10-04: preserve main's #3165 local-prepush exemption during the Rust port.
// The domain still includes local scripts; no additional CI gate is exempted.
pub const UNCOVERED_CEILING: usize = 3;

/// Gates that PROVE they can fail, on a toolchain this job does not have, in their OWN workflow
/// job. Not "uncovered": each has a live falsifier that fails CI if the gate stops detecting its
/// subject. Listed so the accounting stays honest -- a gate that is neither probed, nor
/// uncovered, nor here is UNACCOUNTED -- and so each falsifier's location is on the record.
pub const SELF_FALSIFIED: &[&str] = &[
    "check-mediation-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)",
    "check-observed-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)",
    "check-rest-pattern-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)",
    "check-preimage-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)",
    "check-egress-probe.sh        States 2+3 in the 'egress-probe-falsifier' job (quickstart-boot.yml)",
    "check-adversary-probe.sh     BREACH+INCONCLUSIVE states in the 'adversary-probe-falsifier' job (adversary-probe.yml)",
    "check-clippy-ratchet.sh     ceiling-below-actual in the 'ratchet-falsifier' job (clippy-ratchet.yml)",
    "check-mutants-report.sh     --self-test in the 'mutants' job (coverage-matrix.yml)",
];

/// Subcommands whose ONLY route into CI is a script, with the script named. A row is a claim
/// that is CHECKED: the named script must actually invoke the named subcommand.
pub const SHIM_COVERED: &[&str] = &[
    "inert-authority scripts/check-inert-authority.sh",
    "law-mechanisms  scripts/check-law-mechanisms.sh",
    "kani-coverage   scripts/check-kani-proof-count.sh",
    // A READER for `check-lean-libs-built.sh`, which decides on what it reads and is probed
    // twice; its old exemption named a different program's needs.
    "lean-action-builds scripts/check-lean-libs-built.sh",
];

/// The shell gates the table probes. `xtask ci-spec local-coverage` credits a decider through
/// the gauntlet's `--baseline-only` call only for a gate named here -- one decider for the fact
/// "this gate is in the probe table", read from the table rather than from a copy of it.
pub fn probed_shell_gates() -> std::collections::BTreeSet<&'static str> {
    probes()
        .iter()
        .filter_map(|p| match p.family {
            Family::Script { gate, .. } => Some(gate),
            _ => None,
        })
        .collect()
}
