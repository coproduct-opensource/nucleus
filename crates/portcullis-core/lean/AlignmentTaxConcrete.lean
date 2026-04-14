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

/-- **Non-vacuity smoke test #4**: rank H¹ of the Borromean IFC poset
    is exactly 90 on the reduced indices `[1, 2, 3, 4]`. Already proved
    in `ComparisonTheorem.lean` as `borromean_reduced_h1` via
    `native_decide`; restated here as the Borromean anchor. -/
theorem borromean_rank_is_ninety :
    alignmentTaxH1 borromeanSite [1, 2, 3, 4] = 90 :=
  BorromeanH2.borromean_reduced_h1

/-- **Scale surprise**: the Borromean site exhibits alignment tax
    45× larger than the diamond site. The invariant is not only
    non-vacuous but discriminates at multiple orders of magnitude —
    small posets give small tax (2), larger linked-ring posets give
    large tax (90). -/
theorem borromean_diamond_scale_ratio :
    alignmentTaxH1 borromeanSite [1, 2, 3, 4] =
      45 * alignmentTaxH1 diamondSite [1, 2, 3] := by
  rw [borromean_rank_is_ninety, diamond_rank_is_two]

/-- **Borromean alignment tax is positive** — another concrete
    non-vacuity witness on a structurally richer poset. -/
theorem borromean_rank_pos :
    0 < alignmentTaxH1 borromeanSite [1, 2, 3, 4] := by
  rw [borromean_rank_is_ninety]
  decide

/-- **Concrete H² obstruction** (borromean): reduced Čech H² of the
    Borromean IFC poset is exactly 64. This is the first concrete witness
    that **higher-order obstructions exist** — the `HigherObstruction`
    module's `h2Obstruction` placeholder (currently stubbed at 0) is
    strictly conservative; real IFC posets can have rank H² » 0.

    Reference: `BorromeanH2.borromean_reduced_h2` in
    `ComparisonTheorem.lean`, proved by `native_decide`. -/
theorem borromean_h2_is_sixty_four :
    reducedCechDim borromeanSite [1, 2, 3, 4] 2 = 64 :=
  BorromeanH2.borromean_reduced_h2

/-- **Diamond has no H² obstruction**: diamond is DM-acyclic so higher
    cohomology vanishes. The trivial side of the higher-obstruction
    landscape. -/
theorem diamond_h2_is_zero :
    reducedCechDim diamondSite [1, 2, 3] 2 = 0 :=
  PresheafCech.diamond_reduced_h2

/-- **H² separation**: borromean and diamond are distinguished by their
    H² obstruction count — 64 vs 0 — in addition to their H¹ count
    (90 vs 2). Both H¹ and H² are informative discriminators of IFC
    structure. The cohomological tower is not degenerate at any degree
    on realistic IFC posets. -/
theorem borromean_diamond_h2_separation :
    reducedCechDim borromeanSite [1, 2, 3, 4] 2 ≠
      reducedCechDim diamondSite [1, 2, 3] 2 := by
  rw [borromean_h2_is_sixty_four, diamond_h2_is_zero]
  decide

/-- **Concrete Euler characteristic** of the diamond IFC poset.

    The alignment-tax Euler characteristic collapses the full derived
    tower into a single integer:

      χ = rank H⁰ − rank H¹ + rank H² − …

    For diamond: χ = 2 − 2 + 0 = 0. The cohomological complex is
    acyclic-in-alternation — an integer-valued trivial invariant. -/
theorem diamond_euler_char :
    (reducedCechDim diamondSite [1, 2, 3] 0 : Int) -
      (reducedCechDim diamondSite [1, 2, 3] 1 : Int) +
      (reducedCechDim diamondSite [1, 2, 3] 2 : Int) = 0 := by
  rw [PresheafCech.diamond_reduced_h0, PresheafCech.diamond_reduced_h1,
      PresheafCech.diamond_reduced_h2]
  decide

/-- **Concrete Euler characteristic** of the borromean IFC poset.

    χ = 2 − 90 + 64 = −24. The negativity tells us that H¹ *dominates*
    both lower (H⁰) and higher (H²) cohomology — i.e., the alignment-tax
    obstructions outweigh both trivial sections and higher gluings. The
    balance of obstructions is **asymmetric** on borromean. -/
theorem borromean_euler_char :
    (reducedCechDim borromeanSite [1, 2, 3, 4] 0 : Int) -
      (reducedCechDim borromeanSite [1, 2, 3, 4] 1 : Int) +
      (reducedCechDim borromeanSite [1, 2, 3, 4] 2 : Int) = -24 := by
  rw [BorromeanH2.borromean_reduced_h0, BorromeanH2.borromean_reduced_h1,
      BorromeanH2.borromean_reduced_h2]
  decide

/-- **Euler-characteristic separation**: diamond and borromean are
    distinguished by Euler characteristic (0 vs −24), a *single integer*
    that combines all cohomology degrees. Each cohomology degree
    discriminates separately (H⁰ equal, H¹ 2 vs 90, H² 0 vs 64) but
    Euler provides a succinct compressed invariant. -/
theorem diamond_borromean_euler_separation :
    ((reducedCechDim diamondSite [1, 2, 3] 0 : Int) -
       (reducedCechDim diamondSite [1, 2, 3] 1 : Int) +
       (reducedCechDim diamondSite [1, 2, 3] 2 : Int)) ≠
    ((reducedCechDim borromeanSite [1, 2, 3, 4] 0 : Int) -
       (reducedCechDim borromeanSite [1, 2, 3, 4] 1 : Int) +
       (reducedCechDim borromeanSite [1, 2, 3, 4] 2 : Int)) := by
  rw [diamond_euler_char, borromean_euler_char]
  decide

/- **Arc status (honest)**: this file now contains a concrete
   realiser proof — the FIRST instance where the upper-bound side
   of the alignment-tax conjecture is verified WITHOUT depending on
   the abstract `gaussRankBool_append_le` sorry.

   Additional non-vacuity anchors:
   - `diamond_rank_is_two`: alignmentTaxH1 = 2 on a 4-level IFC poset
   - `borromean_rank_is_ninety`: alignmentTaxH1 = 90 on 5-level linked rings
   - `directInject_rank_is_zero`: alignmentTaxH1 = 0 on an acyclic poset

   The invariant discriminates across two orders of magnitude
   (0, 2, 90) on three structurally-distinct concrete IFC posets.

   The lower-bound side of the tax theorem (no smaller realiser
   exists) still requires `realising_set_size_ge_h1`, which uses the
   open foundation sorry. Full equality remains conditional. -/

end PortcullisCore.AlignmentTaxConcrete
