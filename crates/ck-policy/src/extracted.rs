//! Aeneas-extractable CORE of the Constitutional Kernel monotonicity gate.
//!
//! # Why this module exists (the tier-1 bridge)
//!
//! The production gate `crate::check_monotonicity` decides whether an ordinary
//! amendment from `parent` to `child` preserves constitutional order. That
//! function is written against `ck_types::PolicyManifest`, whose fields are
//! `BTreeSet<String>` collections — constructs the **Aeneas Lean backend cannot
//! translate** (no `BTreeSet`, no `String`, no generics, no `HashMap`). So the
//! literal `check_monotonicity` is *not* extractable, and we never claim it is.
//!
//! Instead, this module is a **self-contained, monomorphized mirror** of the
//! gate's *decision*, authored entirely inside the Rust subset Charon + Aeneas
//! can translate (integers, `bool`, fixed-size arrays, slices, simple loops —
//! NO `BTreeSet`, NO `String`, NO generics, NO trait objects, NO `HashMap`, and
//! crucially NO dependency on `ck_types`, so Charon does not drag the
//! non-translatable `PolicyManifest` type graph into the extraction).
//!
//! ## The three honesty tiers (DO NOT CONFLATE)
//!
//! * **DEDUCTIVE (tier-1, the new bridge).** Charon extracts the functions below
//!   to LLBC; Aeneas translates that LLBC to Lean (`lean-aeneas/generated/`).
//!   Lean theorems are then proved *about the extracted model*. This is a formal
//!   model→Lean translation — not a hand transcription.
//! * **STATISTICAL (tier-4, sampled).** The extracted CORE is bound to the
//!   PRODUCTION `check_monotonicity` by parity proptests
//!   (`tests/extracted_core_parity.rs`), which sample agreement over randomized
//!   manifests. A proptest is NOT a proof; it narrows the gap probabilistically.
//!
//! The honest end-to-end claim is therefore: *a self-contained, monomorphized
//! core that faithfully mirrors the gate's verdict was extracted by Charon+Aeneas
//! and proven in Lean; that core is bound to the production `check_monotonicity`
//! by a parity proptest.* It is NOT "the literal `check_monotonicity` was
//! verified," and "verified Rust != verified binary" (the TCB still trusts
//! Charon, Aeneas, the Lean kernel, and rustc).
//!
//! # Subset discipline
//!
//! Each authority axis (capabilities / io surface / proof requirements) is a set
//! of strings in production; here we represent it as a slice of **interned u32
//! ids** (`&[u32]`). Set membership / subset / "dropped" become pure integer
//! scans. This is a *faithful structural mirror*: the production gate's verdict
//! is a function of exactly these set/order relations, reproduced here over the
//! integer encoding. The parity proptest interns the production string sets into
//! the same id space and asserts the verdicts agree.

#![allow(clippy::needless_range_loop)]

// ── Set primitives over interned u32 ids ─────────────────────────────────────

/// `true` iff every element of `child` also occurs in `parent` — i.e. `child` is
/// a subset of `parent`. This is the boolean image of
/// `CapabilitySet::escalations_over(parent).is_empty()` /
/// `IoSurface::escalations_over(parent).is_empty()` on one axis: no element of
/// the child lies outside the parent (no escalation).
pub fn subset_u32(child: &[u32], parent: &[u32]) -> bool {
    let mut i = 0;
    while i < child.len() {
        let x = child[i];
        let mut found = false;
        let mut j = 0;
        while j < parent.len() {
            if parent[j] == x {
                found = true;
            }
            j += 1;
        }
        if !found {
            return false;
        }
        i += 1;
    }
    true
}

/// `true` iff some element of `parent` is missing from `child` — i.e. a required
/// element was DROPPED. The boolean image of
/// `ProofRequirements::dropped_requirements(parent).is_empty() == false`. Note
/// `dropped(child, parent)` is exactly `!subset_u32(parent, child)`.
pub fn dropped_u32(child: &[u32], parent: &[u32]) -> bool {
    let mut i = 0;
    while i < parent.len() {
        let x = parent[i];
        let mut found = false;
        let mut j = 0;
        while j < child.len() {
            if child[j] == x {
                found = true;
            }
            j += 1;
        }
        if !found {
            return true;
        }
        i += 1;
    }
    false
}

// ── Budget: pointwise ≤ over the 8 bounds ────────────────────────────────────

/// `true` iff every one of the eight child budget bounds is `<=` the parent's —
/// the boolean image of `BudgetBounds::is_within`. The eight slots mirror, in
/// order: max_tokens, max_wall_ms, max_cpu_ms, max_memory_bytes,
/// max_network_calls, max_files_touched, max_dollar_spend_millicents,
/// max_patch_attempts. ALWAYS checked by the gate (no gating flag).
pub fn budget_within(child: &[u64; 8], parent: &[u64; 8]) -> bool {
    let mut i = 0;
    let mut ok = true;
    while i < 8 {
        if child[i] > parent[i] {
            ok = false;
        }
        i += 1;
    }
    ok
}

// ── Amendment-rules non-weakening (the anti-coup / anti-self-weakening fix) ───

/// `true` iff the child does NOT disable any governance flag the parent enabled.
/// The three axes are `[require_monotone_capabilities, require_monotone_io,
/// require_monotone_proofreq]`. On each axis the constraint is
/// `parent_flag -> child_flag`: you may ENABLE a flag the parent did not require,
/// but never DISABLE one it did. Boolean image of
/// `AmendmentRules::weakened_flags_over(parent).is_empty()`.
///
/// This is checked UNCONDITIONALLY by the gate — it is never itself gated on any
/// flag, because a gated anti-coup check could be disarmed one level up.
pub fn rules_non_weakening(parent: [bool; 3], child: [bool; 3]) -> bool {
    let cap_ok = !parent[0] || child[0];
    let io_ok = !parent[1] || child[1];
    let proofreq_ok = !parent[2] || child[2];
    cap_ok && io_ok && proofreq_ok
}

// ── Per-axis "violated" verdicts (cap/io/proofreq gated on the PARENT flag) ───

/// Capability axis violated? Gated on the PARENT capability flag, exactly as the
/// production gate consults `escalations_over` only when
/// `parent.amendment_rules.require_monotone_capabilities`. Violated iff the flag
/// is on AND the child is NOT a subset of the parent on this axis.
pub fn cap_violated(parent_flag: bool, child: &[u32], parent: &[u32]) -> bool {
    if parent_flag {
        !subset_u32(child, parent)
    } else {
        false
    }
}

/// I/O axis violated? Gated on the PARENT io flag.
pub fn io_violated(parent_flag: bool, child: &[u32], parent: &[u32]) -> bool {
    if parent_flag {
        !subset_u32(child, parent)
    } else {
        false
    }
}

/// Proof-requirement axis violated? Gated on the PARENT proofreq flag. Violated
/// iff the flag is on AND the child DROPPED a requirement the parent had.
pub fn proofreq_violated(parent_flag: bool, child: &[u32], parent: &[u32]) -> bool {
    if parent_flag {
        dropped_u32(child, parent)
    } else {
        false
    }
}

/// Budget axis violated? ALWAYS checked (no gating flag in the production gate).
pub fn budget_violated(child: &[u64; 8], parent: &[u64; 8]) -> bool {
    !budget_within(child, parent)
}

// ── The top-level verdict: faithful mirror of check_monotonicity().passed ─────

/// `passed_core` mirrors `check_monotonicity(parent, child).passed`.
///
/// The verdict is "passed" iff:
///   * the capability axis is not violated (gated on `parent_flags[0]`), AND
///   * the io axis is not violated (gated on `parent_flags[1]`), AND
///   * the budget is within bounds (ALWAYS checked), AND
///   * no proof requirement was dropped (gated on `parent_flags[2]`), AND
///   * the amendment rules are not weakened (`rules_non_weakening`, checked
///     UNCONDITIONALLY — the anti-coup fix).
///
/// Arguments are the monomorphized projections the gate reads:
///   * `parent_flags` / `child_flags`: `[cap, io, proofreq]` governance flags.
///   * `*_caps` / `*_io` / `*_proof`: interned-id sets for each authority axis.
///   * `*_budget`: the 8 budget bounds.
///
/// `parent_flags` gates cap/io/proofreq; `child_flags` feeds the unconditional
/// `rules_non_weakening` check. This composition is the structural image of the
/// production `diff.is_clean()`.
#[allow(clippy::too_many_arguments)]
pub fn passed_core(
    parent_flags: [bool; 3],
    child_flags: [bool; 3],
    parent_caps: &[u32],
    child_caps: &[u32],
    parent_io: &[u32],
    child_io: &[u32],
    parent_proof: &[u32],
    child_proof: &[u32],
    parent_budget: &[u64; 8],
    child_budget: &[u64; 8],
) -> bool {
    let cap_ok = !cap_violated(parent_flags[0], child_caps, parent_caps);
    let io_ok = !io_violated(parent_flags[1], child_io, parent_io);
    let budget_ok = !budget_violated(child_budget, parent_budget);
    let proof_ok = !proofreq_violated(parent_flags[2], child_proof, parent_proof);
    let rules_ok = rules_non_weakening(parent_flags, child_flags);
    cap_ok && io_ok && budget_ok && proof_ok && rules_ok
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for the extracted core
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const Z: [u64; 8] = [0; 8];
    const ALL_ON: [bool; 3] = [true, true, true];

    #[test]
    fn subset_basics() {
        assert!(subset_u32(&[], &[]));
        assert!(subset_u32(&[], &[1, 2, 3]));
        assert!(subset_u32(&[2], &[1, 2, 3]));
        assert!(subset_u32(&[1, 3], &[1, 2, 3]));
        assert!(subset_u32(&[1, 1, 2], &[1, 2])); // duplicates in child OK
        assert!(!subset_u32(&[9], &[1, 2, 3]));
        assert!(!subset_u32(&[1, 9], &[1, 2, 3]));
        assert!(!subset_u32(&[1], &[])); // nonempty child, empty parent
    }

    #[test]
    fn dropped_is_negation_of_reversed_subset() {
        // dropped(child, parent) == !subset(parent, child)
        let cases: &[(&[u32], &[u32])] = &[
            (&[], &[]),
            (&[1, 2], &[1, 2]),
            (&[1], &[1, 2]), // parent has 2, child dropped it
            (&[1, 2, 3], &[1]),
            (&[5], &[6]),
        ];
        for (child, parent) in cases {
            assert_eq!(dropped_u32(child, parent), !subset_u32(parent, child));
        }
    }

    #[test]
    fn dropped_basics() {
        assert!(!dropped_u32(&[1, 2, 3], &[1, 2])); // child has all of parent
        assert!(!dropped_u32(&[1, 2], &[1, 2]));
        assert!(dropped_u32(&[1], &[1, 2])); // parent's 2 dropped
        assert!(dropped_u32(&[], &[1])); // empty child drops everything
        assert!(!dropped_u32(&[1], &[])); // nothing required, nothing dropped
    }

    #[test]
    fn budget_pointwise() {
        assert!(budget_within(&Z, &Z));
        assert!(budget_within(
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[1, 2, 3, 4, 5, 6, 7, 8]
        ));
        assert!(budget_within(
            &[0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 2, 3, 4, 5, 6, 7, 8]
        ));
        // any single field exceeding fails
        for i in 0..8 {
            let mut child = [0u64; 8];
            let parent = [5u64; 8];
            child[i] = 6;
            assert!(!budget_within(&child, &parent), "field {i}");
        }
    }

    #[test]
    fn non_weakening_truth_table() {
        // parent_flag -> child_flag on each axis.
        for &p in &[false, true] {
            for &c in &[false, true] {
                let ok = rules_non_weakening([p, false, false], [c, false, false]);
                // non-weakening iff NOT(parent ON and child OFF), i.e. parent -> child.
                assert_eq!(ok, !p || c);
            }
        }
        // enabling a flag the parent didn't require is fine
        assert!(rules_non_weakening([false, false, false], ALL_ON));
        // disabling any required flag is a weakening
        assert!(!rules_non_weakening(ALL_ON, [false, true, true]));
        assert!(!rules_non_weakening(ALL_ON, [true, false, true]));
        assert!(!rules_non_weakening(ALL_ON, [true, true, false]));
        assert!(rules_non_weakening(ALL_ON, ALL_ON));
    }

    #[test]
    fn passed_core_identical_passes() {
        // Identical manifest passes (reflexivity).
        assert!(passed_core(
            ALL_ON,
            ALL_ON,
            &[1, 2],
            &[1, 2],
            &[3],
            &[3],
            &[4, 5],
            &[4, 5],
            &[10; 8],
            &[10; 8],
        ));
    }

    #[test]
    fn passed_core_tighter_child_passes() {
        // Fewer caps, fewer io, MORE proof reqs, tighter budget — all stricter.
        assert!(passed_core(
            ALL_ON,
            ALL_ON,
            &[1, 2, 3], // parent caps
            &[1],       // child caps (subset)
            &[7, 8],
            &[7],    // child io subset
            &[4],    // parent proof
            &[4, 5], // child proof (superset = stricter, nothing dropped)
            &[10; 8],
            &[5; 8], // tighter budget
        ));
    }

    #[test]
    fn passed_core_cap_escalation_rejected() {
        assert!(!passed_core(
            ALL_ON,
            ALL_ON,
            &[1, 2],
            &[1, 2, 9], // child adds cap 9 → escalation
            &[],
            &[],
            &[],
            &[],
            &Z,
            &Z,
        ));
    }

    #[test]
    fn passed_core_cap_escalation_allowed_when_flag_off() {
        // Parent has cap flag OFF → escalation tolerated on that axis.
        assert!(passed_core(
            [false, true, true],
            [false, true, true],
            &[1, 2],
            &[1, 2, 9], // escalation, but cap flag off
            &[],
            &[],
            &[],
            &[],
            &Z,
            &Z,
        ));
    }

    #[test]
    fn passed_core_budget_always_checked() {
        // Even with ALL flags off, budget overrun is rejected.
        let mut child_b = [0u64; 8];
        child_b[6] = 1; // exceed dollar spend
        assert!(!passed_core(
            [false, false, false],
            [false, false, false],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &Z,
            &child_b,
        ));
    }

    #[test]
    fn passed_core_proofreq_drop_rejected() {
        assert!(!passed_core(
            ALL_ON,
            ALL_ON,
            &[],
            &[],
            &[],
            &[],
            &[1, 2],
            &[1], // child dropped proof req 2
            &Z,
            &Z,
        ));
    }

    #[test]
    fn passed_core_io_widening_rejected() {
        assert!(!passed_core(
            ALL_ON,
            ALL_ON,
            &[],
            &[],
            &[1],
            &[1, 2], // io widened
            &[],
            &[],
            &Z,
            &Z,
        ));
    }

    #[test]
    fn passed_core_disarming_amendment_rejected() {
        // THE COUP: child identical on every projection but turns OFF the parent's
        // capability monotonicity flag. UNCONDITIONAL rules_non_weakening rejects it.
        assert!(!passed_core(
            ALL_ON,
            [false, true, true], // child disarms cap flag
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &Z,
            &Z,
        ));
    }

    #[test]
    fn passed_core_disarming_unconditional() {
        // Even when the parent already has cap flag OFF, disarming a DIFFERENT
        // enabled flag (io) is still caught — the check is unconditional.
        assert!(!passed_core(
            [false, true, true],
            [false, false, true], // child disarms io
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &Z,
            &Z,
        ));
    }

    #[test]
    fn passed_core_enabling_flag_passes() {
        // Enabling a flag the parent didn't require is a strengthening → passes.
        assert!(passed_core(
            [false, false, false],
            ALL_ON,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &Z,
            &Z,
        ));
    }
}
