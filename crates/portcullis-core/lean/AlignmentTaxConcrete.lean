import AlignmentTaxBridge

/-! # Concrete alignment-tax non-vacuity

Direct demonstration that the alignment-tax framework is **not
vacuous** on a concrete example. The abstract bridge theorem
`alignmentTaxH1_eq_operational` is conditional on a single open
structural lemma (`gaussRankBool_append_le`, see the foundation
audit in `AlignmentTaxBridge.lean`). This file sidesteps that
open problem by using `native_decide` on fully-concrete instances.

## What this proves (unconditionally)

* `alignmentTaxH1 diamondSite [1, 2, 3] = 2` — rank H¹ evaluates to
  a known non-zero value on the diamond IFC poset (this is already
  in `ComparisonTheorem.lean`; re-stated here as a smoke test
  anchor).

* `RealisesH1 diamondSite [1, 2, 3] (fullDeclassList ...)` — an
  explicit realising set exists. Provable because on a fixed
  concrete input, `gaussRankBool` is just a fuel-bounded algorithm
  that `native_decide` can run to completion.

## Why this addresses the steelman

Objection: "The cohomological alignment cost might be empirically
vacuous — real IFC posets might always have rank H¹ = 0."

Answer: the diamond poset has rank H¹ = 2, exhibited concretely.
The structural theorems may be conditional on the open lemma, but
the *instance* is real.

## What this does NOT prove

* A tight realiser of size 2 (would require knowing the specific
  C¹ indices of diamondSite and picking edges for each H¹ generator).
* The abstract equality `alignmentTaxH1 = operationalAlignmentTaxH1`
  — still needs `gaussRankBool_append_le`.
-/

open PortcullisCore.AlignmentTaxBridge
open SemanticIFCDecidable
open AlexandrovSite
open PresheafCech
open BridgeTheorem

namespace PortcullisCore.AlignmentTaxConcrete

/-- **Non-vacuity smoke test #1**: rank H¹ of the diamond IFC poset
    is exactly 2. Already proved in `ComparisonTheorem.lean` via
    `native_decide`; restated here as the anchor of the concrete
    arc. -/
theorem diamond_rank_is_two :
    alignmentTaxH1 diamondSite [1, 2, 3] = 2 :=
  diamond_alignmentTaxH1

/-- **Non-vacuity smoke test #2**: the diamond site has a strictly
    positive alignment tax. Direct consequence of the above. -/
theorem diamond_rank_pos :
    0 < alignmentTaxH1 diamondSite [1, 2, 3] := by
  rw [diamond_rank_is_two]
  decide

/-- **Non-vacuity smoke test #3**: the directInject site has zero
    alignment tax, showing `alignmentTaxH1` distinguishes
    structurally-different IFC posets. -/
theorem directInject_rank_is_zero :
    alignmentTaxH1 directInjectSite [1, 2] = 0 :=
  directInject_alignmentTaxH1

/-- **Separation theorem (concrete)**: the alignment-tax invariant
    strictly separates the diamond and directInject sites.

    This is a fully-concrete refutation of the "everything is vacuous"
    objection: at least two IFC posets have distinct, computable
    alignment-tax values (2 ≠ 0), demonstrating the invariant has
    genuine discriminative power. -/
theorem diamond_directInject_separation :
    alignmentTaxH1 diamondSite [1, 2, 3] ≠
      alignmentTaxH1 directInjectSite [1, 2] := by
  rw [diamond_rank_is_two, directInject_rank_is_zero]
  decide

/-- **Tight concrete realiser for diamondSite** (zero abstract sorry).

    A specific 2-element list of declassification edges that satisfies
    `RealisesH1` on the diamond IFC poset. Combined with the proved
    `diamond_rank_is_two`, this exhibits a fully-concrete instance
    where the **upper-bound side of the alignment-tax conjecture
    holds unconditionally**:

      `operationalAlignmentTaxH1 diamondSite [1,2,3] ≤ 2 = alignmentTaxH1`.

    The witness is `[⟨1, 2, 0⟩, ⟨1, 2, 3⟩]` — two declassification
    edges between observation indices 1 and 2 on propositions 0 and 3
    respectively. Empirically derived by enumerating rank-bumping
    edges and finding the first pair whose combined declass-rows
    increase rank by 2 (from 14 to 16, hitting the `|C¹| - rank δ¹ = 16`
    threshold).

    Verified by `native_decide` on the concrete `RealisesH1`
    Boolean predicate. -/
theorem diamond_concrete_realiser :
    ∃ L : List DeclassEdge,
      L.length = 2 ∧ RealisesH1 diamondSite [1, 2, 3] L := by
  refine ⟨[⟨1, 2, 0⟩, ⟨1, 2, 3⟩], rfl, ?_⟩
  unfold RealisesH1
  native_decide

/-- **Concrete upper bound on operational tax** (modulo definability).

    Given a tight realiser exists, `operationalAlignmentTaxH1` is
    bounded above by 2 on the diamond instance — *if* the
    `operationalAlignmentTaxH1` definition's existence-witness sorry
    in `AlignmentTaxBridge.lean` is closed.

    Stated separately to make the dependency explicit: the *witness*
    side of the tax theorem is concrete; only the `Nat.find`
    well-definedness still chains back to the foundation sorry. -/
theorem diamond_operational_tax_le_two_corollary :
    (∃ L : List DeclassEdge,
      L.length ≤ 2 ∧ RealisesH1 diamondSite [1, 2, 3] L) := by
  obtain ⟨L, hL_len, hL_real⟩ := diamond_concrete_realiser
  exact ⟨L, by omega, hL_real⟩

/- **Arc status (honest)**: this file now contains a concrete
   realiser proof — the FIRST instance where the upper-bound side
   of the alignment-tax conjecture is verified WITHOUT depending on
   the abstract `gaussRankBool_append_le` sorry.

   The lower-bound side (no L of length < 2 realises) still requires
   the abstract `realising_set_size_ge_h1` lemma, which uses the
   open structural sorry. So the FULL equality
   `operationalAlignmentTaxH1 diamondSite [1,2,3] = 2` is still
   conditional on closing the foundation. But the concrete witness
   is real. -/

end PortcullisCore.AlignmentTaxConcrete
