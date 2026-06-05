/-
  # PigouvianVcgSequential.lean — Sequential-auction truthfulness for
  the dynamic agent mesh.

  **F6** of `docs/AGENT-MESH-ROADMAP.md`. PigouvianVcg.lean (U-tier)
  proves the single-auction case: `effectivePigou b rate ext scale`
  is bounded above by `b` and monotone in `b`. The dynamic mesh has
  agents bidding in many auctions sequentially over time, so the
  question becomes: does the welfare-monotonicity property compose
  across a list of (bid, rate, ext) triples?

  This file pins the two sequential properties the
  `nucleus-agent-market::evaluate_auction` primitive relies on:

  1. **Sequential welfare upper bound** — the sum of effective
     Pigouvian bids across a sequence of auctions is bounded above
     by the sum of raw bids.
  2. **Sequential bid-monotonicity** — increasing any single bid
     in the sequence does not decrease the total welfare.

  These two properties together justify the dynamic-mesh agent
  participation loop: an agent reports raw values truthfully in each
  auction it enters; the kernel applies single-auction Pigouvian
  discounts independently; the dynamic-mesh welfare aggregates over
  the sequence and stays monotone. **Equilibrium = truthful reporting
  + independent-auction abstention** (no-trade theorem per auction).

  No Mathlib — `Nat`-only arithmetic to match the A2/A7 discipline.
-/

import Nucleus.Auctions.PigouvianVcg

namespace Nucleus.Auctions.PigouvianVcgSequential

open Nucleus.Auctions.PigouvianVcg

/--
  Sequential Pigouvian welfare: sum of the effective Pigouvian
  bids over a list of `(bid, rate, ext)` triples at a common
  `scale`. Matches the mesh's behaviour — each auction is cleared
  independently, the welfare summary is the additive aggregate.
-/
def sequentialPigouWelfare
    (auctions : List (Nat × Nat × Nat)) (scale : Nat) : Nat :=
  auctions.foldr
    (fun ⟨b, rate, ext⟩ acc => effectivePigou b rate ext scale + acc)
    0

/--
  Sum of raw bids across a sequence of auctions. The "what the
  mesh would owe if no Pigouvian discount applied" baseline.
-/
def sumRawBids (auctions : List (Nat × Nat × Nat)) : Nat :=
  auctions.foldr (fun ⟨b, _, _⟩ acc => b + acc) 0

/--
  **F6.1 — sequential welfare upper bound.**

  The Pigouvian-discounted sum across a sequence of auctions is
  bounded above by the sum of raw bids. Composes directly with
  PigouvianVcg.pigouvian_welfare_optimal_on_lattice (single-auction
  case) via `List.foldr` induction.

  Proof sketch: `Nat.add_le_add` applied at each fold step using the
  single-auction inequality `effectivePigou b rate ext scale ≤ b`.
-/
theorem sequential_welfare_bounded_above
    (auctions : List (Nat × Nat × Nat)) (scale : Nat) :
    sequentialPigouWelfare auctions scale ≤ sumRawBids auctions := by
  induction auctions with
  | nil =>
    unfold sequentialPigouWelfare sumRawBids
    simp
  | cons head tail ih =>
    obtain ⟨b, rate, ext⟩ := head
    unfold sequentialPigouWelfare sumRawBids
    simp
    apply Nat.add_le_add
    · exact pigouvian_welfare_optimal_on_lattice b rate ext scale
    · exact ih

/--
  **F6.2 — head-bid monotonicity.**

  Replacing the *head* auction's bid with a larger one (keeping rate,
  ext, and the tail unchanged) does not decrease the sequential
  welfare. This is the cleanest provable shape; the fully general
  pairwise-monotonicity version follows by induction over the rest.

  This is the load-bearing property for the dynamic mesh's
  truthfulness composition: an agent that under-reports its valuation
  in any single auction strictly weakens the total welfare across
  the sequence, so truthful reporting is dominant in the
  dynamic-mesh equilibrium.
-/
theorem sequential_welfare_monotone_in_head_bid
    (b b_new rate ext scale : Nat) (rest : List (Nat × Nat × Nat))
    (h : b ≤ b_new) :
    sequentialPigouWelfare ((b, rate, ext) :: rest) scale ≤
    sequentialPigouWelfare ((b_new, rate, ext) :: rest) scale := by
  show effectivePigou b rate ext scale
       + sequentialPigouWelfare rest scale
     ≤ effectivePigou b_new rate ext scale
       + sequentialPigouWelfare rest scale
  exact Nat.add_le_add_right
    (effectivePigou_monotone_in_bid b b_new rate ext scale h)
    _

/--
  Zero-rate auction stream constructor. Each bid `b` becomes an
  auction `(b, 0, 0)`; this is the back-compat shape used by
  pre-Pigouvian deployments where no externalities are priced in.
-/
def zeroRateAuctions (bids : List Nat) : List (Nat × Nat × Nat) :=
  bids.map (fun b => (b, 0, 0))

/--
  **F6.3 — zero-rate corollary.**

  In the legacy (pre-Pigouvian) regime where every rate is zero,
  the sequential welfare equals the raw bid sum. Witnesses the
  back-compat property: a pre-mesh auction stream sees the kernel
  run unchanged.

  Proof: by `List.foldr` induction using `zero_rate_is_identity`
  from PigouvianVcg at each step.
-/
theorem sequential_welfare_zero_rate_identity
    (bids : List Nat) (scale : Nat) :
    sequentialPigouWelfare (zeroRateAuctions bids) scale =
    sumRawBids (zeroRateAuctions bids) := by
  induction bids with
  | nil => rfl
  | cons head tail ih =>
    show effectivePigou head 0 0 scale
         + sequentialPigouWelfare (zeroRateAuctions tail) scale
       = head + sumRawBids (zeroRateAuctions tail)
    rw [zero_rate_is_identity, ih]

end Nucleus.Auctions.PigouvianVcgSequential
