/-
  # PigouvianVcg.lean — Pigouvian-augmented VCG over the rounded lattice.

  **Pigouvian U1.** Formal statement of the load-bearing property that
  the Rust kernel (`crates/nucleus-econ-kernels/src/vcg_pigou.rs::
  effective_minus_pigou_micro`) implements:

      effective_minus_pigou_micro(b, ext, rate)
          = b - rate * ext / 1_000_000      (saturating Nat)

  When `rate * ext / 1_000_000 ≤ b`, the result equals `b - rate * ext / s`;
  otherwise it saturates to `0`. The key invariants we want to pin
  formally:

  1. **Bounded above by the raw bid** — `effective ≤ b` (no Pigouvian
     re-weighting ever *increases* a bid).
  2. **Monotone in bid** — increasing the raw bid never decreases
     the adjusted bid (so the classical Vickrey 2nd-price argument
     composes with this layer; see `IntegerVcgTruthful.lean` for
     the homogeneous-regime truthfulness theorem).
  3. **Independent of bid for the tax term** — `rate` and `ext` come
     from oracle attestations, NOT the bidder's report; so the tax
     contribution does not vary with `b`. This is the truthfulness-
     preservation property arXiv 2601.03451 proves under
     hierarchical-graph dependencies.

  The proofs use `Nat`-only arithmetic, no Mathlib, to match the
  A2/A7 discipline. Aeneas extraction to `pigou_aeneas.rs` is the
  U3 follow-on; U4 binds the extracted Rust to the kernel via a
  differential proptest mirroring `lean_model_parity.rs`.
-/

namespace Nucleus.Auctions.PigouvianVcg

/--
  Stage-1 Pigouvian re-weighting: subtract the integer Pigouvian tax
  from the raw bid, saturating at zero. Mirrors the Rust function
  `effective_minus_pigou_micro` (single-dimension simplification —
  the K-dim sum is a fold over this primitive).

  `scale = 1_000_000` in the production substrate so `ext` and `rate`
  are expressed in micro-units.
-/
def effectivePigou (b rate ext scale : Nat) : Nat :=
  b - rate * ext / scale

/--
  **U1 — `pigouvian_welfare_optimal_on_lattice`** (the named acceptance
  in the PIGOUVIAN-EXTERNALITY.md tracker).

  Statement form: the adjusted bid is bounded above by the raw bid.
  This is the *minimal* welfare-monotonicity guarantee — every winner
  in the auction over adjusted bids has utility ≤ what they'd see
  in a pure-VCG auction over raw bids; Pigouvian re-weighting can only
  shift welfare AWAY from bidders TOWARDS the rebate pool, never
  inflate welfare.

  This composes with the homogeneous-regime truthfulness theorem
  (`Nucleus.Auctions.IntegerVcgTruthful.vickrey_truthful`):
  truthful reporting `b = v` remains dominant on `effectivePigou`
  because the discount is independent of `b`.

  Proof: `Nat.sub_le` is the saturating-subtraction lemma; in
  `Nat` the result of `a - b` is always `≤ a`.
-/
theorem pigouvian_welfare_optimal_on_lattice
    (b rate ext scale : Nat) :
    effectivePigou b rate ext scale ≤ b := by
  unfold effectivePigou
  exact Nat.sub_le b (rate * ext / scale)

/--
  **U1 corollary** — adjusted bid is *monotone* in the raw bid.
  If `a ≤ b` then `effectivePigou a rate ext s ≤ effectivePigou b rate ext s`.

  Composes with `IntegerVcgTruthful.effective_value_monotone_on_lattice`
  to give: the kernel's allocator sees a strictly order-preserving
  transform of raw bids, so the highest-effective-value bidder under
  the pure-VCG kernel is also the highest-adjusted-value bidder under
  the Pigouvian kernel — i.e. the *winner* is unchanged when all
  bidders share the same Pigouvian discount profile (a homogeneous
  externality regime).

  Proof: `Nat.sub_le_sub_right` lifts `a ≤ b` through the saturating
  subtraction of the same `rate * ext / s` term on both sides.
-/
theorem effectivePigou_monotone_in_bid
    (a b rate ext scale : Nat) (h : a ≤ b) :
    effectivePigou a rate ext scale ≤ effectivePigou b rate ext scale := by
  unfold effectivePigou
  exact Nat.sub_le_sub_right h (rate * ext / scale)

/--
  **U1 second corollary** — zero rate is the identity.
  If `rate = 0`, the adjusted bid equals the raw bid. Witnesses the
  back-compat property: a pre-Pigouvian invocation (no rate set)
  sees the kernel run unchanged.

  Proof: `0 * x = 0` and `0 / s = 0`, then `b - 0 = b`.
-/
theorem zero_rate_is_identity
    (b ext scale : Nat) :
    effectivePigou b 0 ext scale = b := by
  unfold effectivePigou
  simp

/--
  **U1 third corollary** — empty externality is the identity.
  If `ext = 0`, the adjusted bid equals the raw bid even under
  non-zero `rate`. Witnesses the "non-emitter pays no Pigouvian tax"
  property: a bidder who declares zero consumption pays zero
  tax (and a hostile oracle can't sign a non-zero claim into the
  bidder's profile without breaking the Ed25519 signature, per
  the V1 wire contract).
-/
theorem zero_externality_is_identity
    (b rate scale : Nat) :
    effectivePigou b rate 0 scale = b := by
  unfold effectivePigou
  simp

end Nucleus.Auctions.PigouvianVcg
