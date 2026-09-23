/-
  Nucleus / Auctions / Threshold truthfulness

  **STATUS: PROVED.** The single structural fact underneath every
  truthfulness result in this directory, and the two extensions the
  runtime needs: multi-unit rounds, and reputation entering a clearing
  without touching the payment rule.

  # The observation

  `IntegerVcgTruthful.vickrey_truthful` and
  `VcgPigouTruthful.pigou_vickrey_truthful` are the same four-case
  split over the same shape:

      utility v b = if b ≥ SOMETHING then v - SOMETHING else 0

  where SOMETHING does not mention `b`. Neither proof uses any
  property of `maxBid others` beyond that. So the content of both is
  one theorem about a **bid-independent threshold**, and the auction
  results are instances of it.

  That is not a tidying exercise. Two mechanisms this runtime wants
  are exactly two more instances, and stating the general fact is what
  makes them theorems rather than analogies:

  * **Multi-unit rounds** (`k` identical slots, unit demand). A bidder
    wins a slot iff its bid clears the `k`-th highest of the *other*
    bids, and pays exactly that. The threshold is a function of `k`
    and `others` — not of `b` — so truthfulness follows by
    instantiation, and `slot_threshold_one_is_max` shows the
    single-slot case is the classical result unchanged.

  * **Reputation-weighted clearing.** `docs/rfcs/reputation-weighted-clearing.md`
    states the design rule — standing enters bond and admission, never
    the bid and never the payment rule — and then says plainly that
    the claim those channels preserve truthfulness is *"an analogy to
    the existing proof until it has its own Lean theorem"*. This file
    discharges that obligation: a bond is a bid-independent offset
    (`bonded_truthful`) and admission is a bid-independent predicate
    (`admitted_truthful`).

  # Scope honesty

  - Unit demand. A bidder wants at most one slot. Multi-unit demand
    (a bidder valuing a second slot) is a different mechanism and is
    NOT covered — VCG over a combinatorial domain is
    `VcgRevenueNonMonotone`'s territory, with its non-monotone
    revenue witness.
  - The thresholds here are *defined* to be bid-independent, the same
    way `VcgPigouTruthful` defines `τ` to be. What earns that in the
    Rust kernel is the same discipline: the k-th highest of the others
    is computed from the other bids, and standing is read from a
    ledger the bidder cannot write mid-round. `bid_dependent_threshold_breaks_it`
    pins the boundary as a falsifier, mirroring the bid-dependent-tax
    witness in `VcgPigouTruthful`.
  - Ties go to the bidder (`≥` is inclusive), as elsewhere in this
    directory. At a tie the price equals the valuation, so both
    branches give the same Nat utility and the tie-break rule cannot
    move the inequality.
-/

import Nucleus.Auctions.IntegerVcgTruthful

namespace Nucleus.Auctions.ThresholdTruthful

open Nucleus.Auctions.IntegerVcgTruthful

/-- Utility facing an arbitrary price threshold `t`.

    Win iff the bid clears `t`; pay `t`; saturating `Nat` subtraction
    floors an unprofitable win at `0`, which is what lets the integer
    µUSD lattice carry the real-valued argument. -/
def utilityAt (v b t : Nat) : Nat :=
  if b ≥ t then v - t else 0

/-- **Threshold truthfulness.** Against any price threshold that does
    not depend on the bid, truthful reporting weakly dominates every
    deviation.

    The four cases are the ones `vickrey_truthful` splits on, with
    `maxBid others` replaced by `t`:

    1. Both win at `t`. Equal.
    2. Deviator wins, truthful loses (`b ≥ t > v`): the deviator's
       `v - t` saturates to `0`, and the truthful arm is `0`.
    3. Deviator loses, truthful wins: `0 ≤ v - t`.
    4. Both lose. Equal. -/
theorem threshold_truthful (v b t : Nat) :
    utilityAt v b t ≤ utilityAt v v t := by
  unfold utilityAt
  by_cases hd : b ≥ t
  · by_cases ht : v ≥ t
    · simp [hd, ht]
    · simp [hd, ht]
      have hlt : v < t := Nat.lt_of_not_le ht
      omega
  · by_cases ht : v ≥ t
    · simp [hd, ht]
    · simp [hd, ht]

/-- The classical single-good result is this theorem at
    `t = maxBid others`. Stated so the generalization is checkable as
    a strict one rather than asserted to be. -/
theorem vickrey_is_a_threshold (v b : Nat) (others : List Nat) :
    utilityAt v b (maxBid others) = utility v b others := by
  unfold utilityAt utility
  by_cases h : b ≥ maxBid others
  · simp [h]
  · simp [h]

/-! ## Multi-unit rounds -/

/-- Drop one occurrence of the maximum. Structural recursion, no
    Mathlib: walk the list, and drop the first element equal to the
    maximum of the whole list. -/
def dropOne (m : Nat) : List Nat → List Nat
  | [] => []
  | x :: rest => if x = m then rest else x :: dropOne m rest

/-- Drop the `k` highest bids. `dropTop 0 l = l`. -/
def dropTop : Nat → List Nat → List Nat
  | 0, l => l
  | (k + 1), l => dropTop k (dropOne (maxBid l) l)

/-- The price a bidder faces when `units` identical slots are sold to
    unit-demand bidders: the `units`-th highest of the OTHER bids.

    `units = 0` is not a round — nothing is allocated — and the value
    at `0` is never consulted by the theorems below, which are all
    stated at `units + 1`. -/
def slotThreshold : Nat → List Nat → Nat
  | 0, _ => 0
  | (k + 1), l => maxBid (dropTop k l)

/-- One slot is the classical auction: the threshold is the highest
    other bid, unchanged. -/
theorem slot_threshold_one_is_max (others : List Nat) :
    slotThreshold 1 others = maxBid others := by
  unfold slotThreshold dropTop
  rfl

/-- **Multi-unit truthfulness.** With `k + 1` identical slots and unit
    demand, truthful reporting weakly dominates every deviation.

    The threshold takes `k` and `others` and never `b`, so this is
    `threshold_truthful` at that threshold. What the runtime must
    preserve is exactly that argument list: a slot count or an
    opponent set that moved with the bidder's own report would put the
    mechanism outside this theorem. -/
theorem multi_unit_truthful (v b k : Nat) (others : List Nat) :
    utilityAt v b (slotThreshold (k + 1) others)
      ≤ utilityAt v v (slotThreshold (k + 1) others) :=
  threshold_truthful v b (slotThreshold (k + 1) others)

/-- At one slot, multi-unit truthfulness IS `vickrey_truthful` — the
    generalization does not quietly change the single-slot mechanism. -/
theorem multi_unit_at_one_slot_is_vickrey (v b : Nat) (others : List Nat) :
    utilityAt v b (slotThreshold 1 others) = utility v b others := by
  rw [slot_threshold_one_is_max]
  exact vickrey_is_a_threshold v b others

/-! ## Reputation, entering where it cannot distort the report -/

/-- Utility with a bid-independent participation cost `c` — the
    anti-grief bond a winner posts. Standing reduces `c`; it does not
    touch the threshold. -/
def utilityBonded (v b t c : Nat) : Nat :=
  utilityAt v b t - c

/-- **A bond preserves truthfulness.** For any bid-independent cost
    `c`, truthful reporting still weakly dominates.

    This is the first channel of `reputation-weighted-clearing.md`:
    standing buys a cheaper bond, and the bid is untouched, so the
    dominance argument is undisturbed. Subtracting the same `c` from
    both arms cannot reverse an inequality under saturating `Nat`
    subtraction. -/
theorem bonded_truthful (v b t c : Nat) :
    utilityBonded v b t c ≤ utilityBonded v v t c := by
  unfold utilityBonded
  have h := threshold_truthful v b t
  omega

/-- Utility when admission is decided before bids are read. `adm` is a
    `Bool` computed from identity and standing — never from `b`. -/
def utilityAdmitted (v b t : Nat) (adm : Bool) : Nat :=
  if adm then utilityAt v b t else 0

/-- **Admission preserves truthfulness.** A participation predicate
    evaluated on identity and standing, before any bid is read, cannot
    distort bidding among the admitted.

    This is the second channel of `reputation-weighted-clearing.md`.
    The hypothesis that makes it true is visible in the statement:
    `adm` is one value shared by both arms, so it cannot depend on
    which bid was submitted. -/
theorem admitted_truthful (v b t : Nat) (adm : Bool) :
    utilityAdmitted v b t adm ≤ utilityAdmitted v v t adm := by
  unfold utilityAdmitted
  cases adm with
  | false => simp
  | true => simpa using threshold_truthful v b t

/-- **Both channels together.** Standing may set the bond AND gate
    admission in the same clearing without disturbing the result — the
    composition, not just each in isolation, because a mechanism is
    what ships. -/
theorem bonded_and_admitted_truthful (v b t c : Nat) (adm : Bool) :
    (if adm then utilityBonded v b t c else 0)
      ≤ (if adm then utilityBonded v v t c else 0) := by
  cases adm with
  | false => simp
  | true => simpa using bonded_truthful v b t c

/-! ## The boundary, as a falsifier -/

/-- **Bid-independence is load-bearing, and here is what breaks.**

    A threshold that moves with the report — the shape a
    standing-weighted PRICE would have, since a bidder's standing is
    attached to the bidder — makes deviation strictly profitable. The
    witness: valuation `100`, a price equal to the bidder's own report.
    Reporting `100` yields `100 - 100 = 0`; reporting `40` yields
    `100 - 40 = 60`.

    This is why `reputation-weighted-clearing.md` forbids scaling the
    bid or the payment, and why the two channels above are stated over
    a `c` and an `adm` that the bid cannot reach. Mirrors
    `VcgPigouTruthful`'s bid-dependent-tax witness. -/
example :
    let v : Nat := 100
    let t_bid_dep (x : Nat) : Nat := x
    utilityAt v v (t_bid_dep v) < utilityAt v 40 (t_bid_dep 40) := by
  decide

end Nucleus.Auctions.ThresholdTruthful
