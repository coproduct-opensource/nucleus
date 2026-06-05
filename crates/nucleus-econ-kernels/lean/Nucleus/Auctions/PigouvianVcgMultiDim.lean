/-
  Nucleus / Auctions / Pigouvian-VCG Multi-Dimension

  **STATUS: PROVED.** Multi-dimension extension of
  `PigouvianVcg.effectivePigou`. The single-dim primitive already
  has parity with `pigouvian_re_weight` (U4 256-case proptest);
  this file closes the gap to `effective_minus_pigou_micro` — the
  function the kernel's `run_vcg_with_externalities` actually calls.

  # The Lean spec

  The kernel sums Pigouvian contributions across the K = 7 resource
  dimensions, splitting them into TAX (negative externality) and
  SUBSIDY (positive externality) buckets. The result is:

      result = bid - Σ tax_i + Σ subsidy_i        (saturating)

  where each `contrib_i = rate_i * ext_i / scale`.

  We model this in Lean via two lists of `(rate, ext)` pairs (one
  for taxes, one for subsidies), folded into running sums, then
  combined with the raw bid via Nat-saturating subtraction +
  unbounded addition. The Rust mirror in `pigou_aeneas.rs` adds the
  u128 → u64 saturation that the µUSD lattice requires.

  # E4.3 progression

  This is step 1: Lean spec. Step 2 lands the Rust mirror in
  `crates/nucleus-econ-kernels/src/extracted/pigou_aeneas.rs`. Step
  3 adds a multi-dim parity proptest binding kernel ↔ extracted ↔
  Lean. Together these close the audit's C4 "verified-spec,
  unverified-impl" gap at the multi-dim layer, in addition to the
  sequential-welfare bound already pinned by F6.1.
-/

namespace Nucleus.Auctions.PigouvianVcgMultiDim

/-- Sum of `r * e / scale` over a list of `(rate, ext)` pairs.
    Pure structural recursion; no Mathlib. -/
def sumContribs : List (Nat × Nat) → Nat → Nat
  | [], _ => 0
  | (r, e) :: rest, scale => r * e / scale + sumContribs rest scale

/-- Multi-dimension Pigouvian re-weighting.

    `taxes` = list of (rate, ext_units) pairs for *negative-externality*
    dimensions (gpu_seconds, co2_grams, …); their contribs are
    *subtracted* from the bid.

    `subsidies` = list of (rate, ext_units) pairs for *positive-
    externality* dimensions (knowledge_spillover, …); their contribs
    are *added* back.

    Returns the saturating-Nat re-weighted bid.

    Mirrors the Rust kernel `effective_minus_pigou_micro` shape
    bit-for-bit (modulo the u128 → u64 saturation that lives in the
    Rust mirror only). -/
def effectivePigouMultiDim
    (b scale : Nat)
    (taxes subsidies : List (Nat × Nat)) : Nat :=
  let taxTotal := sumContribs taxes scale
  let subTotal := sumContribs subsidies scale
  (b - taxTotal) + subTotal

/-- **U1 multi-dim — bounded above by `b + Σ subsidies`.**

    The multi-dim adjusted bid never exceeds the raw bid plus the
    full subsidy stack. Composes with the single-dim
    `pigouvian_welfare_optimal_on_lattice` to give the multi-dim
    welfare bound the kernel actually preserves.

    Proof: `Nat.sub_le` saturating-subtraction lemma + monotone
    addition. -/
theorem effectivePigouMultiDim_bounded_above
    (b scale : Nat) (taxes subsidies : List (Nat × Nat)) :
    effectivePigouMultiDim b scale taxes subsidies
      ≤ b + sumContribs subsidies scale := by
  unfold effectivePigouMultiDim
  have h_sub : b - sumContribs taxes scale ≤ b := Nat.sub_le _ _
  exact Nat.add_le_add_right h_sub _

/-- **U1 multi-dim corollary** — empty tax + empty subsidy reduces
    to the raw bid (the back-compat property).

    Witnesses the pre-Pigouvian regression test: a bidder with no
    externality claims pays no tax, gets no subsidy, sees their bid
    flow through unchanged. -/
theorem effectivePigouMultiDim_empty_is_identity
    (b scale : Nat) :
    effectivePigouMultiDim b scale [] [] = b := by
  unfold effectivePigouMultiDim sumContribs
  simp

/-- **U1 multi-dim corollary** — single-dim tax case agrees with
    the single-dim primitive `PigouvianVcg.effectivePigou` (modulo
    the b + 0 = b absorption).

    Pins the multi-dim spec as a strict generalization of the
    single-dim spec already extracted in `pigou_aeneas.rs`. -/
theorem effectivePigouMultiDim_single_tax_matches_singledim
    (b rate ext scale : Nat) :
    effectivePigouMultiDim b scale [(rate, ext)] []
      = b - rate * ext / scale := by
  show (b - (rate * ext / scale + sumContribs [] scale))
        + sumContribs [] scale
        = b - rate * ext / scale
  unfold sumContribs
  simp

/-- **U1 multi-dim corollary** — zero scale gives Nat-div = 0
    semantics on every contrib, so the result equals `b`. Witnesses
    the same back-compat as the single-dim `zero_scale_is_identity`
    would (we don't have that one explicitly, but the Nat-div
    semantics propagate via `Nat.div_zero`).

    Note: `scale = 0` isn't a production state (the kernel pins
    scale to 1_000_000), but the Lean spec must define the function
    for all Nat inputs. -/
theorem effectivePigouMultiDim_zero_scale_is_identity
    (b : Nat) (taxes subsidies : List (Nat × Nat)) :
    effectivePigouMultiDim b 0 taxes subsidies
      = b + sumContribs subsidies 0 := by
  -- sumContribs taxes 0 = 0 (each r*e/0 = 0 in Nat)
  have h_tax_zero : sumContribs taxes 0 = 0 := by
    induction taxes with
    | nil => unfold sumContribs; rfl
    | cons p rest ih =>
      cases p with
      | mk r e =>
        unfold sumContribs
        simp [Nat.div_zero, ih]
  show (b - sumContribs taxes 0) + sumContribs subsidies 0
        = b + sumContribs subsidies 0
  rw [h_tax_zero, Nat.sub_zero]

end Nucleus.Auctions.PigouvianVcgMultiDim
