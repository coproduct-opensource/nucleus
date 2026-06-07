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

/// Mirror of Lean `passed p c`: the conjunction of the four "not violated"
/// verdicts. The image of `check_monotonicity(parent=p, child=c).passed`.
fn lean_passed(p: &PolicyManifest, c: &PolicyManifest) -> bool {
    !lean_cap_violated(p, c)
        && !lean_io_violated(p, c)
        && !lean_budget_violated(p, c)
        && !lean_proof_req_violated(p, c)
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
) -> PolicyManifest {
    let cap_pool = ["/a", "/b", "/c", "net1", "tool1", "secretA"];
    let io_pool = ["dom1", "root1", "ENV1", "ns1", "owner/repo"];
    let proof_pool = ["build_pass", "tests_pass", "kani_pass", "replay_pass"];
    PolicyManifest {
        version: 1,
        capabilities: CapabilitySet {
            filesystem_read: set_of(&cap_pool, caps_keep),
            filesystem_write: set_of(&cap_pool, caps_keep),
            network_allow: set_of(&cap_pool, caps_keep),
            tools_allow: set_of(&cap_pool, caps_keep),
            secret_classes: set_of(&cap_pool, caps_keep),
            max_parallel_tasks: parallel,
        },
        io_surface: IoSurface {
            outbound_domains: set_of(&io_pool, io_keep),
            local_file_roots: set_of(&io_pool, io_keep),
            env_vars_readable: set_of(&io_pool, io_keep),
            tool_namespaces: set_of(&io_pool, io_keep),
            repo_write_targets: set_of(&io_pool, io_keep),
        },
        budget_bounds: budget(budget_vals),
        proof_requirements: ProofRequirements {
            config_patch: set_of(&proof_pool, proof_keep),
            controller_patch: set_of(&proof_pool, proof_keep),
            evaluator_patch: set_of(&proof_pool, proof_keep),
        },
        amendment_rules: AmendmentRules {
            may_modify: BTreeSet::new(),
            may_not_modify: BTreeSet::new(),
            require_monotone_capabilities: flag_cap,
            require_monotone_io: flag_io,
            require_monotone_proofreq: flag_proof,
            constitutional_human_signatures: 2,
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
        pc in proptest::collection::vec(any::<bool>(), 6),
        cc in proptest::collection::vec(any::<bool>(), 6),
        pio in proptest::collection::vec(any::<bool>(), 5),
        cio in proptest::collection::vec(any::<bool>(), 5),
        ppr in proptest::collection::vec(any::<bool>(), 4),
        cpr in proptest::collection::vec(any::<bool>(), 4),
        pbud in proptest::array::uniform8(0u64..8),
        cbud in proptest::array::uniform8(0u64..8),
        ppar in 0u32..8,
        cpar in 0u32..8,
        flag_cap in any::<bool>(),
        flag_io in any::<bool>(),
        flag_proof in any::<bool>(),
    ) {
        // Flags are read off the PARENT only; the child's flags are irrelevant to
        // the plain gate (THIS is the meta-gap), so we hold them arbitrary-but-true.
        let parent = manifest(&pc, &pio, &ppr, pbud, ppar, flag_cap, flag_io, flag_proof);
        let child = manifest(&cc, &cio, &cpr, cbud, cpar, true, true, true);

        let prod = check_monotonicity(&parent, &child).passed;
        let model = lean_passed(&parent, &child);
        prop_assert_eq!(
            prod, model,
            "model↔production divergence: prod={}, model={}\nparent={:?}\nchild={:?}",
            prod, model, parent, child
        );
    }
}

// ── Fixed adversarial case: the `meta_gap` counterexample ─────────────────────

/// The Rust image of the Lean `meta_gap` witness (`fullParent` / `disarmingChild`):
/// a child IDENTICAL on every projection the gate reads (so `check_monotonicity`
/// PASSES) that silently turns OFF the parent's `require_monotone_capabilities`
/// flag — disarming the NEXT amendment. This is the T4 anti-self-weakening crux:
/// the plain gate never inspects the child's amendment rules.
#[test]
fn meta_gap_passing_amendment_disarms_future_enforcement() {
    let zero = [0u64; 8];
    // fullParent: every monotone flag ON, empty projections.
    let parent = manifest(&[], &[], &[], zero, 0, true, true, true);
    // disarmingChild: identical projections, but capability flag OFF.
    let mut child = parent.clone();
    child.amendment_rules.require_monotone_capabilities = false;

    // The plain production gate PASSES this amendment (model agrees).
    let prod = check_monotonicity(&parent, &child);
    assert!(
        prod.passed,
        "meta_gap: plain gate should admit the disarming amendment: {:?}",
        prod.diff
    );
    assert!(
        lean_passed(&parent, &child),
        "meta_gap: model should agree it passes"
    );

    // Yet the child has WEAKENED the amendment rules (turned a required-monotone
    // flag off) — exactly what `check_monotonicity` fails to forbid (Lean
    // `weakensRules`). The strengthened gate (`checkPlus`, see Ck/Policy.lean)
    // would REJECT this step; that is the constructive fix the proof recommends.
    assert!(
        parent.amendment_rules.require_monotone_capabilities
            && !child.amendment_rules.require_monotone_capabilities,
        "meta_gap: the child disabled a required-monotone flag"
    );

    // The coup's SECOND step: under the now-relaxed child flag, a grandchild
    // escalates capabilities freely and STILL passes the plain gate.
    let mut grandchild = child.clone();
    grandchild
        .capabilities
        .network_allow
        .insert("evil.com".into());
    let step2 = check_monotonicity(&child, &grandchild);
    assert!(
        step2.passed,
        "meta_gap: two-step coup — grandchild escalates freely after disarming"
    );
}
