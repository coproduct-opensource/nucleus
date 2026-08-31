// Model ↔ production parity for the Constitutional Kernel monotonicity gate.
// Bridges the PRODUCTION `ck_policy::check_monotonicity` to the Mathlib-free Lean
// model it is pinned to (`crates/ck-policy/lean/Ck/Policy.lean`, namespace
// `Ck.Policy`), by transcribing the Lean verdict predicate `passed` into a Rust
// mirror and asserting it AGREES with `check_monotonicity(...).passed` over
// randomized `PolicyManifest` pairs — plus one fixed adversarial vector (the
// `meta_gap` counterexample).
//
// ── Proof ↔ production pin (grep me) ─────────────────────────────────────────
//
// Lean source: `crates/ck-policy/lean/Ck/Policy.lean`
// (namespace `Ck.Policy`, Lean 4 v4.30.0-rc2, Mathlib-free, 0 `sorry`,
//  no native-decide; built + sorry-banned by `.github/workflows/ck-policy-lean.yml`).
//
//   MODEL DEFS (the Rust mirror below transcribes these EXACTLY):
//     • `escalatesB child parent`   — some element of `child` not in `parent`.
//     • `dropsB     child parent`   — some element of `parent` not in `child`.
//     • `budgetWithin c p`          — pointwise `≤` over the 8 budget fields.
//     • `capViolated/ioViolated/proofReqViolated` — each gated on the PARENT flag;
//       `budgetViolated` ALWAYS checked.
//     • `passed p c`                — `!cap && !io && !budget && !proofreq` violated,
//       the image of `check_monotonicity(parent=p, child=c).passed`.
//
//   THEOREMS (each pinned here; proofs live in the Lean file):
//     • `T1_gate_sound`                — conditional monotonicity-gate soundness.
//     • `meta_gap`                     — the anti-coup HOLE (constructive
//       counterexample). The fixed adversarial case below is its Rust image.
//     • `strengthened_gate_closes_it`  — the constructive fix (`checkPlus`) carries
//       the flag forward across a 2-step chain where the plain gate fails.
//
// **The parity claim** asserted below: the Rust mirror is a TRANSCRIPTION of the
// Lean MODEL's verdict (`passed`), asserted EQUAL to the PRODUCTION
// `check_monotonicity(...).passed` over randomized manifests. The mirror is NOT
// the production function — it is a hand-written copy of the Lean defs. The
// proptest NARROWS the model↔Rust gap PROBABILISTICALLY; it does NOT close it and
// is NOT a formal extraction.
//
// ── EXTRACTION-GAP CAVEAT (grep me) ──────────────────────────────────────────
// The theorems are proved about the Lean MODEL. This parity proptest binds them to
// the SHIPPED Rust only PROBABILISTICALLY (random sampling, finite cases) plus the
// fixed adversarial vector. A formal Aeneas-style extraction of
// `check_monotonicity` would be required to close the model↔Rust gap DEDUCTIVELY.
// Until then, treat the theorems as statements about the model, parity-checked —
// not extracted — into Rust.

use std::collections::BTreeSet;

use ck_policy::check_monotonicity;
use ck_types::manifest::{
    AmendmentRules, BudgetBounds, CapabilitySet, IoSurface, PolicyManifest, ProofRequirements,
};
use proptest::prelude::*;

// ── The Lean model, transcribed to Rust (the spec-pinned mirror) ─────────────

/// Mirror of Lean `escalatesB child parent`: some element of `child` is NOT in
/// `parent`. (`escalations_over(parent)` would be non-empty.)
fn lean_escalates(child: &BTreeSet<String>, parent: &BTreeSet<String>) -> bool {
    child.iter().any(|x| !parent.contains(x))
}

/// Mirror of Lean `dropsB child parent`: some element of `parent` is NOT in
/// `child`. (`dropped_requirements(parent)` would be non-empty.)
fn lean_drops(child: &BTreeSet<String>, parent: &BTreeSet<String>) -> bool {
    parent.iter().any(|x| !child.contains(x))
}

/// Mirror of Lean `budgetWithin c p`: pointwise `≤` over the eight budget fields.
fn lean_budget_within(c: &BudgetBounds, p: &BudgetBounds) -> bool {
    c.max_tokens <= p.max_tokens
        && c.max_wall_ms <= p.max_wall_ms
        && c.max_cpu_ms <= p.max_cpu_ms
        && c.max_memory_bytes <= p.max_memory_bytes
        && c.max_network_calls <= p.max_network_calls
        && c.max_files_touched <= p.max_files_touched
        && c.max_dollar_spend_millicents <= p.max_dollar_spend_millicents
        && c.max_patch_attempts <= p.max_patch_attempts
}

/// Mirror of Lean `capViolated`: gated on the PARENT capability flag. The model
/// collapses every capability axis into one `Names` carrier; the production
/// `escalations_over` inspects six axes — we OR the per-axis escalation predicate
/// over exactly those six, which is the faithful boolean image (any axis
/// escalates ⇒ the verdict is "violated").
fn lean_cap_violated(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    if !p.amendment_rules.require_monotone_capabilities {
        return false;
    }
    lean_escalates(
        &c.capabilities.filesystem_read,
        &p.capabilities.filesystem_read,
    ) || lean_escalates(
        &c.capabilities.filesystem_write,
        &p.capabilities.filesystem_write,
    ) || lean_escalates(&c.capabilities.network_allow, &p.capabilities.network_allow)
        || lean_escalates(&c.capabilities.tools_allow, &p.capabilities.tools_allow)
        || lean_escalates(
            &c.capabilities.secret_classes,
            &p.capabilities.secret_classes,
        )
        || c.capabilities.max_parallel_tasks > p.capabilities.max_parallel_tasks
}

/// Mirror of Lean `ioViolated`: gated on the PARENT io flag, ORed over the five
/// io-surface axes.
fn lean_io_violated(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    if !p.amendment_rules.require_monotone_io {
        return false;
    }
    lean_escalates(
        &c.io_surface.outbound_domains,
        &p.io_surface.outbound_domains,
    ) || lean_escalates(
        &c.io_surface.local_file_roots,
        &p.io_surface.local_file_roots,
    ) || lean_escalates(
        &c.io_surface.env_vars_readable,
        &p.io_surface.env_vars_readable,
    ) || lean_escalates(&c.io_surface.tool_namespaces, &p.io_surface.tool_namespaces)
        || lean_escalates(
            &c.io_surface.repo_write_targets,
            &p.io_surface.repo_write_targets,
        )
}

/// Mirror of Lean `budgetViolated`: ALWAYS checked (no gating flag).
fn lean_budget_violated(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    !lean_budget_within(&c.budget_bounds, &p.budget_bounds)
}

/// Mirror of Lean `proofReqViolated`: gated on the PARENT proofreq flag, ORed over
/// the three patch classes.
fn lean_proof_req_violated(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    if !p.amendment_rules.require_monotone_proofreq {
        return false;
    }
    lean_drops(
        &c.proof_requirements.config_patch,
        &p.proof_requirements.config_patch,
    ) || lean_drops(
        &c.proof_requirements.controller_patch,
        &p.proof_requirements.controller_patch,
    ) || lean_drops(
        &c.proof_requirements.evaluator_patch,
        &p.proof_requirements.evaluator_patch,
    )
}

/// Mirror of Lean `rulesNonWeakening c p`: the child's governance flags are
/// pointwise `≥` the parent's — you may ENABLE a flag but never DISABLE one
/// (`parent_flag -> child_flag` on each axis) — AND the numeric signature
/// threshold may rise but never fall (`Rules.sigs`, `p.sigs ≤ c.sigs`).
/// Checked UNCONDITIONALLY.
fn lean_rules_non_weakening(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    let pr = &p.amendment_rules;
    let cr = &c.amendment_rules;
    (!pr.require_monotone_capabilities || cr.require_monotone_capabilities)
        && (!pr.require_monotone_io || cr.require_monotone_io)
        && (!pr.require_monotone_proofreq || cr.require_monotone_proofreq)
        && (pr.constitutional_human_signatures <= cr.constitutional_human_signatures)
}

/// Mirror of the STRENGTHENED Lean `passed p c` (== the proven `checkPlus`):
/// the conjunction of the four "not violated" verdicts AND the UNCONDITIONAL
/// `rulesNonWeakening` conjunct. This is the image of the SHIPPED
/// `check_monotonicity(parent=p, child=c).passed` after the T1/T4 fix.
fn lean_passed(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    !lean_cap_violated(p, c)
        && !lean_io_violated(p, c)
        && !lean_budget_violated(p, c)
        && !lean_proof_req_violated(p, c)
        && lean_rules_non_weakening(p, c)
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn budget(vals: [u64; 8]) -> BudgetBounds {
    BudgetBounds {
        max_tokens: vals[0],
        max_wall_ms: vals[1],
        max_cpu_ms: vals[2],
        max_memory_bytes: vals[3],
        max_network_calls: vals[4],
        max_files_touched: vals[5],
        max_dollar_spend_millicents: vals[6],
        max_patch_attempts: vals[7] as u32,
    }
}

fn set_of(items: &[&str], keep: &[bool]) -> BTreeSet<String> {
    items
        .iter()
        .zip(keep.iter().chain(std::iter::repeat(&true)))
        .filter(|(_, k)| **k)
        .map(|(s, _)| (*s).to_string())
        .collect()
}

/// A `PolicyManifest` parameterized by the knobs the gate actually reads.
/// Slice the `i`-th axis's membership mask out of a flat mask. Short inputs are
/// tolerated (missing entries read as `false`) so fixtures can pass `&[]`.
fn axis(flat: &[bool], i: usize, width: usize) -> &[bool] {
    let start = (i * width).min(flat.len());
    let end = (start + width).min(flat.len());
    &flat[start..end]
}

#[allow(clippy::too_many_arguments)]
fn manifest(
    caps_keep: &[bool],
    io_keep: &[bool],
    proof_keep: &[bool],
    budget_vals: [u64; 8],
    parallel: u32,
    flag_cap: bool,
    flag_io: bool,
    flag_proof: bool,
    sigs: u32,
) -> PolicyManifest {
    let cap_pool = ["/a", "/b", "/c", "net1", "tool1", "secretA"];
    let io_pool = ["dom1", "root1", "ENV1", "ns1", "owner/repo"];
    let proof_pool = ["build_pass", "tests_pass", "kani_pass", "replay_pass"];
    PolicyManifest {
        version: 1,
        // INDEPENDENT mask per axis. Previously every axis in a group shared one
        // mask, so all five capability sets — and all five io sets — were EQUAL in
        // all 2048 cases. A gate that read `filesystem_read` where it meant
        // `network_allow` passed every case, because the two were never different.
        // Chunking one longer mask gives each axis its own membership.
        capabilities: CapabilitySet {
            filesystem_read: set_of(&cap_pool, axis(caps_keep, 0, cap_pool.len())),
            filesystem_write: set_of(&cap_pool, axis(caps_keep, 1, cap_pool.len())),
            network_allow: set_of(&cap_pool, axis(caps_keep, 2, cap_pool.len())),
            tools_allow: set_of(&cap_pool, axis(caps_keep, 3, cap_pool.len())),
            secret_classes: set_of(&cap_pool, axis(caps_keep, 4, cap_pool.len())),
            max_parallel_tasks: parallel,
        },
        io_surface: IoSurface {
            outbound_domains: set_of(&io_pool, axis(io_keep, 0, io_pool.len())),
            local_file_roots: set_of(&io_pool, axis(io_keep, 1, io_pool.len())),
            env_vars_readable: set_of(&io_pool, axis(io_keep, 2, io_pool.len())),
            tool_namespaces: set_of(&io_pool, axis(io_keep, 3, io_pool.len())),
            repo_write_targets: set_of(&io_pool, axis(io_keep, 4, io_pool.len())),
        },
        budget_bounds: budget(budget_vals),
        proof_requirements: ProofRequirements {
            config_patch: set_of(&proof_pool, axis(proof_keep, 0, proof_pool.len())),
            controller_patch: set_of(&proof_pool, axis(proof_keep, 1, proof_pool.len())),
            evaluator_patch: set_of(&proof_pool, axis(proof_keep, 2, proof_pool.len())),
        },
        amendment_rules: AmendmentRules {
            may_modify: BTreeSet::new(),
            may_not_modify: BTreeSet::new(),
            require_monotone_capabilities: flag_cap,
            require_monotone_io: flag_io,
            require_monotone_proofreq: flag_proof,
            constitutional_human_signatures: sigs,
        },
    }
}

// ── The parity proptest ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// PRODUCTION `check_monotonicity(parent, child).passed` AGREES with the Rust
    /// transcription of the Lean model verdict `passed`, over randomized manifest
    /// pairs spanning all axes + all flag combinations.
    #[test]
    fn production_passed_agrees_with_lean_model(
        pc in proptest::collection::vec(any::<bool>(), 6 * 5),
        cc in proptest::collection::vec(any::<bool>(), 6 * 5),
        pio in proptest::collection::vec(any::<bool>(), 5 * 5),
        cio in proptest::collection::vec(any::<bool>(), 5 * 5),
        ppr in proptest::collection::vec(any::<bool>(), 4 * 3),
        cpr in proptest::collection::vec(any::<bool>(), 4 * 3),
        pbud in proptest::array::uniform8(0u64..8),
        cbud in proptest::array::uniform8(0u64..8),
        ppar in 0u32..8,
        cpar in 0u32..8,
        flag_cap in any::<bool>(),
        flag_io in any::<bool>(),
        flag_proof in any::<bool>(),
        cflag_cap in any::<bool>(),
        cflag_io in any::<bool>(),
        cflag_proof in any::<bool>(),
        psigs in 0u32..4,
        csigs in 0u32..4,
    ) {
        // The parent's flags gate cap/io/proofreq; the child's flags now MATTER
        // too — the SHIPPED gate checks `rulesNonWeakening` UNCONDITIONALLY, so
        // we vary the child's flags in BOTH directions to exercise the anti-coup
        // check (disabling a parent-enabled flag must now be rejected).
        let parent = manifest(&pc, &pio, &ppr, pbud, ppar, flag_cap, flag_io, flag_proof, psigs);
        let child = manifest(&cc, &cio, &cpr, cbud, cpar, cflag_cap, cflag_io, cflag_proof, csigs);

        let prod = check_monotonicity(&parent, &child).passed;
        let model = lean_passed(&parent, &child);
        prop_assert_eq!(
            prod, model,
            "model↔production divergence: prod={}, model={}\nparent={:?}\nchild={:?}",
            prod, model, parent, child
        );
    }
}

// ── Fixed adversarial case: the `meta_gap` coup is now CLOSED ─────────────────

/// The Rust image of the Lean `meta_gap` / `weak_gate_admits_coup` witness
/// (`fullParent` / `disarmingChild`): a child IDENTICAL on every escalation
/// projection the gate reads, that silently turns OFF the parent's
/// `require_monotone_capabilities` flag — the disarming step of the two-step
/// coup. The OLD (parent-flag-only) gate ADMITTED this. The SHIPPED gate now
/// checks `rulesNonWeakening` UNCONDITIONALLY, so the disarming step is REJECTED
/// at step ONE — the coup never gets a second move. This is the Rust image of
/// the Lean `new_gate_rejects_coup` theorem.
#[test]
fn meta_gap_coup_is_now_rejected() {
    let zero = [0u64; 8];
    // fullParent: every monotone flag ON, empty projections.
    let parent = manifest(&[], &[], &[], zero, 0, true, true, true, 2);
    // disarmingChild: identical projections, but capability flag OFF.
    let mut child = parent.clone();
    child.amendment_rules.require_monotone_capabilities = false;

    // The child DID weaken the amendment rules (the precondition of the coup).
    assert!(
        parent.amendment_rules.require_monotone_capabilities
            && !child.amendment_rules.require_monotone_capabilities,
        "meta_gap: the child disabled a required-monotone flag"
    );

    // THE FIX: the SHIPPED production gate now REJECTS the disarming step.
    let prod = check_monotonicity(&parent, &child);
    assert!(
        !prod.passed,
        "meta_gap CLOSED: shipped gate must REJECT the disarming amendment, got passed=true: {:?}",
        prod.diff
    );
    assert!(
        prod.diff
            .violated_invariants
            .contains(&ck_types::ConstitutionalInvariant::AmendmentRulesMonotonicity),
        "meta_gap: rejection must cite AmendmentRulesMonotonicity: {:?}",
        prod.diff.violated_invariants
    );

    // The strengthened model AGREES the step is rejected (parity, both directions).
    assert!(
        !lean_passed(&parent, &child),
        "meta_gap: strengthened model must agree the disarming step is rejected"
    );

    // Because step ONE is now rejected, the coup's intended SECOND step (a
    // grandchild escalating capabilities freely under the relaxed flag) is never
    // reachable on the ordinary path — the child never enters the lineage.
}

/// Rust image of the Lean `new_gate_rejects_signature_lowering` /
/// `raising_signatures_is_admitted` theorems.
///
/// The NUMERIC half of the anti-coup check. Every boolean flag is untouched, so
/// a gate that enumerates only the three booleans sees nothing wrong — the child
/// merely lowers the human-signature threshold, disarming the review that would
/// police the NEXT constitutional amendment.
#[test]
fn signature_lowering_is_rejected_and_raising_is_not() {
    let zero = [0u64; 8];
    let parent = manifest(&[], &[], &[], zero, 0, true, true, true, 2);

    // Lowering: rejected, citing AmendmentRulesMonotonicity.
    let mut lowered = parent.clone();
    lowered.amendment_rules.constitutional_human_signatures = 0;
    assert_eq!(
        lowered.amendment_rules.require_monotone_capabilities,
        parent.amendment_rules.require_monotone_capabilities,
        "the numeric coup must leave every boolean flag untouched"
    );
    let prod = check_monotonicity(&parent, &lowered);
    assert!(
        !prod.passed,
        "lowering the signature threshold must be rejected: {:?}",
        prod.diff
    );
    assert!(
        prod.diff
            .violated_invariants
            .contains(&ck_types::ConstitutionalInvariant::AmendmentRulesMonotonicity),
        "must cite AmendmentRulesMonotonicity: {:?}",
        prod.diff.violated_invariants
    );

    // The model agrees — this is the parity claim, not just the production one.
    assert_eq!(prod.passed, lean_passed(&parent, &lowered));

    // Raising: admitted. The axis is monotone upward, not frozen.
    let mut raised = parent.clone();
    raised.amendment_rules.constitutional_human_signatures = 7;
    let prod_up = check_monotonicity(&parent, &raised);
    assert!(
        prod_up.passed,
        "raising the threshold must be admitted: {:?}",
        prod_up.diff
    );
    assert_eq!(prod_up.passed, lean_passed(&parent, &raised));
}
