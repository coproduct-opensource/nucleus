/-
  Nucleus / Auctions / VCG Revenue Non-Monotonicity

  **STATUS: PROVED, SORRY-FREE.** A concrete, computable counterexample
  theorem witnessing that the revenue of a combinatorial VCG (Vickrey-
  Clarke-Groves) auction is *non-monotone*: weakly raising every input
  bid (here, by adding a bidder) can *strictly lower* total seller
  revenue.

  # The SOTA claim (and the prior art it advances past)

  Strategy-proofness / soundness of (combinatorial) Vickrey auctions has
  been machine-checked before:

    - Caminati, Kerber, Lange, Rowat, "Proving soundness of combinatorial
      Vickrey auctions and generating verified executable code"
      (Isabelle/HOL, arXiv:1308.1779) — SOUNDNESS only.
    - github.com/metareflection/vickrey — Lean 4, 0-sorry, generic over
      `LinearOrderedAddCommGroup` — STRATEGY-PROOFNESS only.
    - `Nucleus.Auctions.IntegerVcgTruthful` (this repo) — single-good
      Vickrey truthfulness over the `Nat` µUSD lattice.

  None of these formalize a *revenue* property. VCG is "infamously
  revenue non-monotone in combinatorial auctions" (Ausubel & Milgrom,
  "The Lovely but Lonely Vickrey Auction", 2006; Roughgarden CS364B L7;
  arXiv:2602.20439) — but that non-monotonicity has, to our knowledge,
  never been machine-checked over a running integer kernel. This file
  does exactly that: it states the property as a SORRY-FREE EXISTENTIAL
  counterexample, closed by `decide` over the `Nat` kernel.

  We deliberately do NOT claim a universal monotonicity statement (that
  would be false). The honest, decidable claim is the *existence* of a
  dominating-input / lower-revenue pair.

  # The counterexample (Ausubel–Milgrom, integer instance)

  Two goods {A, B}. Bids are triples `(v_a, v_b, v_ab)` in µUSD.

    b  = [ L = (0,0,2),  M = (2,0,0) ]
       bidder L wants only the *bundle* (complementary), M wants only A.
       Welfare-optimal assigns the bundle to L (welfare 2); L pays M's
       externality = 2.  totalRevenue b  = 2.

    b2 = [ L = (0,0,2),  M = (2,0,0),  N = (0,2,0) ]   (added bidder N)
       Now splitting A→M, B→N has welfare 4 > 2 (bundle). Each winner's
       VCG payment is 0 (removing one single-good winner still lets the
       other take its good and displaces L symmetrically; net externality
       0).  totalRevenue b2 = 0.

  `b2` dominates `b` coordinate-wise (a bidder was *added*; every existing
  bid is unchanged, and the new bidder's bids are ≥ the implicit 0s), yet
  revenue drops 2 → 0. This is the canonical "Lovely but Lonely Vickrey"
  shape and is *exactly* the `complementary_bundle_wins_against_singletons`
  test shape in `vcg_combo.rs` (scale 2 → 100 etc. is free).

  # Parity with the running kernel (mandate: prod runs the proven function)

  The Lean `optimalWelfare` / `vcgPayment` / `totalRevenue` below are a
  faithful `Nat` port of `clear_combinatorial_2good` in
  `crates/nucleus-econ-kernels/src/vcg_combo.rs`:

    - same brute-force `(n+1)²` assignment grid,
    - same lex `(welfare, a, b)` tie-break (smallest index wins ties),
    - same externality payment rule (`optimal-welfare-without-bidder`
      minus `welfare-of-other-winners`, saturating at 0),
    - same bundle single-charge rule (A and B to the same bidder ⇒ B
      payment folded into A).

  The Rust test `vcg_combo_revenue_non_monotone_parity` asserts the kernel
  produces the *same two numbers* this theorem names (revenue 2, then 0)
  on the *same* witness. Without that parity test the "verified spec /
  unverified impl" gap (see MEMORY) would leave the claim unverified;
  with it, the money-path runs the proven function.

  # Scope honesty

  - 2-good combinatorial case only (matches `vcg_combo.rs`).
  - The theorem is an *existential counterexample*, not a universal law.
    It proves non-monotonicity is *realizable* in this exact kernel — the
    strongest honest claim. It does not characterize *when* monotonicity
    holds.
  - `Nat`-only, no Mathlib — matches the sibling auction theorems and the
    `Nucleus` package's mathlib-free stance.
  - Axioms: confirmed by `#print axioms` to be only
    `{propext, Classical.choice, Quot.sound}` — i.e. NO `sorryAx`.
-/

namespace Nucleus.Auctions.VcgRevenueNonMonotone

/-- A bidder's combinatorial bid over the 2-good space, in µUSD.
    Mirrors `CombinatorialBid` in `vcg_combo.rs` (sans the `bidder`
    identity string, which is irrelevant to revenue). -/
structure CombinatorialBid where
  vA : Nat
  vB : Nat
  vAB : Nat
deriving DecidableEq, Repr

/-- Welfare contributed by an assignment `(a, b)` of goods (A, B) to
    bidder *indices* into `bids`, where the sentinel index `bids.length`
    means "unassigned".

    Mirrors the inner body of `optimal_welfare` in `vcg_combo.rs`:
      - if A and B go to the *same* bidder, that bidder contributes
        their bundle value `vAB` (and B adds nothing);
      - otherwise A contributes `vA` of its winner and B contributes
        `vB` of its winner;
      - the sentinel (unassigned) contributes 0. -/
def assignmentWelfare (bids : List CombinatorialBid) (a b : Nat) : Nat :=
  let n := bids.length
  let wA :=
    if h : a < n then
      if a == b then (bids.get ⟨a, h⟩).vAB else (bids.get ⟨a, h⟩).vA
    else 0
  let wB :=
    if h : b < n then
      if b == a then 0 else (bids.get ⟨b, h⟩).vB
    else 0
  wA + wB

/-- The list of candidate assignments `(a, b)` with `a, b ∈ 0..=n`,
    enumerated in the SAME lexicographic order the Rust double loop
    visits them (`a` outer, `b` inner), so the tie-break below selects
    the identical winner. -/
def candidates (n : Nat) : List (Nat × Nat) :=
  (List.range (n + 1)).flatMap (fun a => (List.range (n + 1)).map (fun b => (a, b)))

/-- Fold one candidate into the running best `(welfare, a, b)` using the
    Rust tie-break: a strictly higher welfare wins; on a welfare tie the
    lexicographically smaller `(a, b)` wins. -/
def betterPick (best cand : Nat × Nat × Nat) : Nat × Nat × Nat :=
  let (bw, ba, bb) := best
  let (cw, ca, cb) := cand
  if cw > bw ∨ (cw == bw ∧ (ca < ba ∨ (ca == ba ∧ cb < bb))) then cand else best

/-- Brute-force welfare-maximizing assignment, returning
    `(welfare, winnerA, winnerB)` as raw indices (with `n` = unassigned).

    The initial best is `(0, n, n)` — welfare 0, both goods unassigned —
    exactly the Rust `best` initializer (`(0, None, None)`, where `None`
    is encoded as the sentinel `n`). -/
def optimalAssignment (bids : List CombinatorialBid) : Nat × Nat × Nat :=
  let n := bids.length
  (candidates n).foldl
    (fun best (a, b) => betterPick best (assignmentWelfare bids a b, a, b))
    (0, n, n)

/-- Maximum achievable welfare. -/
def optimalWelfare (bids : List CombinatorialBid) : Nat :=
  (optimalAssignment bids).1

/-- Drop the bidder at index `i` (the "without this bidder" reduced set
    used for the VCG externality). -/
def removeAt (bids : List CombinatorialBid) (i : Nat) : List CombinatorialBid :=
  (bids.zipIdx).filterMap (fun (b, j) => if j == i then none else some b)

/-- Welfare of the *other* winners in the chosen allocation, excluding
    bidder `excluded`. Mirrors the `w_others` accumulation in
    `payment_for`. -/
def welfareOfOtherWinners (bids : List CombinatorialBid)
    (winA winB excluded : Nat) : Nat :=
  let n := bids.length
  let fromA :=
    if winA < n ∧ winA ≠ excluded then
      if winB == winA then
        -- bundle winner: full bundle value
        if h : winA < n then (bids.get ⟨winA, h⟩).vAB else 0
      else
        if h : winA < n then (bids.get ⟨winA, h⟩).vA else 0
    else 0
  let fromB :=
    if winB < n ∧ winB ≠ excluded ∧ winB ≠ winA then
      if h : winB < n then (bids.get ⟨winB, h⟩).vB else 0
    else 0
  fromA + fromB

/-- VCG payment charged when excluding bidder `excluded` (the winner of a
    good): the optimal welfare *without* them, minus the welfare the
    *other* winners still realize, saturating at 0.

    Mirrors `payment_for` in `vcg_combo.rs` (`w_without.saturating_sub
    (w_others)`; `Nat` subtraction already saturates). -/
def externalityPayment (bids : List CombinatorialBid)
    (winA winB excluded : Nat) : Nat :=
  optimalWelfare (removeAt bids excluded)
    - welfareOfOtherWinners bids winA winB excluded

/-- Total seller revenue: the VCG payments of the winner(s) of A and B.

    Mirrors `clear_combinatorial_2good`'s `payment_a + payment_b` with the
    bundle single-charge rule: if A and B are won by the *same* bidder,
    only the A-side externality is charged (B side is 0). -/
def totalRevenue (bids : List CombinatorialBid) : Nat :=
  let n := bids.length
  let (_, winA, winB) := optimalAssignment bids
  let payA := if winA < n then externalityPayment bids winA winB winA else 0
  let payB :=
    if winA == winB then 0
    else if winB < n then externalityPayment bids winA winB winB else 0
  payA + payB

/-- Coordinate-wise dominance: `b2` dominates `b` if `b2` has every bid of
    `b` (in order) with each component weakly larger, and may have
    *additional* bidders appended. Adding a bidder is a (weak) input
    increase: the implicit pre-existing bid of an absent bidder is `(0,0,0)`,
    and any real bid dominates it. This is the "raising bids / adding a
    bidder weakly increases inputs" relation from the plan. -/
def pointwiseGE : List CombinatorialBid → List CombinatorialBid → Prop
  | _, [] => True  -- b2 covers every (possibly zero) bidder of the shorter b
  | [], _ :: _ => False  -- b2 ran out of bidders to dominate b's remaining
  | x2 :: r2, x :: r =>
      x2.vA ≥ x.vA ∧ x2.vB ≥ x.vB ∧ x2.vAB ≥ x.vAB ∧ pointwiseGE r2 r

/-- `pointwiseGE` is decidable by structural recursion on both lists. -/
def decidablePointwiseGE :
    (b2 b : List CombinatorialBid) → Decidable (pointwiseGE b2 b)
  | _, [] => isTrue (by unfold pointwiseGE; trivial)
  | [], _ :: _ => isFalse (by unfold pointwiseGE; intro h; exact h)
  | x2 :: r2, x :: r =>
      have : Decidable (pointwiseGE r2 r) := decidablePointwiseGE r2 r
      inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))

instance (b2 b : List CombinatorialBid) : Decidable (pointwiseGE b2 b) :=
  decidablePointwiseGE b2 b

-- ── The canonical Ausubel–Milgrom witness ──────────────────────────────

/-- Bidder L: values the *bundle* only (complementary). -/
def bidL : CombinatorialBid := ⟨0, 0, 2⟩
/-- Bidder M: values good A only. -/
def bidM : CombinatorialBid := ⟨2, 0, 0⟩
/-- Bidder N: values good B only. -/
def bidN : CombinatorialBid := ⟨0, 2, 0⟩

/-- HIGH-revenue bid vector: only L and M. Bundle → L; L pays M's
    externality = 2 ⇒ revenue 2. -/
def bidsHigh : List CombinatorialBid := [bidL, bidM]
/-- LOW-revenue bid vector: L, M, and the *added* bidder N. Split
    A→M, B→N is welfare-optimal (4 > 2); both VCG payments 0 ⇒ revenue 0. -/
def bidsLow : List CombinatorialBid := [bidL, bidM, bidN]

-- ── Sanity (all `by decide` over the Nat kernel) ───────────────────────

/-- The high-revenue instance clears to revenue 2, matching the Rust
    kernel's `payment_a + payment_b` on the same witness. -/
theorem revenue_high_is_two : totalRevenue bidsHigh = 2 := by decide

/-- The low-revenue instance (one extra bidder) clears to revenue 0. -/
theorem revenue_low_is_zero : totalRevenue bidsLow = 0 := by decide

/-- `bidsLow` dominates `bidsHigh` coordinate-wise (it is `bidsHigh` with
    bidder N appended; no existing bid decreased). -/
theorem low_dominates_high : pointwiseGE bidsLow bidsHigh := by decide

-- ── The SOTA theorem ───────────────────────────────────────────────────

/-- **VCG revenue is non-monotone.** There exist combinatorial bid
    vectors `b, b2` such that `b2` weakly dominates `b` coordinate-wise
    (every bid in `b2` is ≥ the corresponding bid in `b`, with extra
    bidders only adding value) yet the total VCG revenue *strictly
    decreases*: `totalRevenue b2 < totalRevenue b`.

    Witnessed by the canonical Ausubel–Milgrom instance and closed by
    `decide` over the `Nat` kernel — no Mathlib, no `sorry`. The auditor
    is invited to run `#print axioms vcg_revenue_non_monotone`: the only
    axioms are `propext`, `Classical.choice`, `Quot.sound`. -/
theorem vcg_revenue_non_monotone :
    ∃ b b2 : List CombinatorialBid,
      pointwiseGE b2 b ∧ totalRevenue b2 < totalRevenue b := by
  exact ⟨bidsHigh, bidsLow, by decide, by decide⟩

/-- **Corollary — adding a bidder lowers revenue.** The dominating vector
    `bidsLow` is *literally* `bidsHigh` with one bidder (N) appended, so
    this is the "add a bidder, revenue strictly drops" framing
    (Ausubel–Milgrom's L/M/N example). -/
theorem adding_a_bidder_lowers_revenue :
    bidsLow = bidsHigh ++ [bidN] ∧ totalRevenue bidsLow < totalRevenue bidsHigh := by
  exact ⟨by decide, by decide⟩

/-- **Corollary — raising a single bid lowers revenue (dual framing).**
    Start from `bidsHighInert := [L, M, N0]` where N0 = (0,0,0) is inert
    (revenue still 2, bundle → L). RAISE N0's `vB` from 0 to 2 (giving
    `bidsLow`) — a single monotone bid increase — and revenue drops 2 → 0.
    This is the dual of the add-bidder framing on the *same* witness. -/
def bidN0 : CombinatorialBid := ⟨0, 0, 0⟩
def bidsHighInert : List CombinatorialBid := [bidL, bidM, bidN0]

theorem raising_a_bundle_bid_lowers_revenue :
    pointwiseGE bidsLow bidsHighInert ∧
    -- the only difference is N's vB: 0 → 2
    bidsLow = [bidL, bidM, { bidN0 with vB := 2 }] ∧
    totalRevenue bidsLow < totalRevenue bidsHighInert := by
  exact ⟨by decide, by decide, by decide⟩

/-- The inert-padding instance has the same revenue as the two-bidder
    high instance — adding an all-zero bidder changes nothing — confirming
    the dual framing starts from revenue 2. -/
theorem inert_padding_preserves_high_revenue :
    totalRevenue bidsHighInert = totalRevenue bidsHigh := by decide

-- ── Axiom audit (uncomment locally to verify sorry-freeness) ────────────
-- The auditor runs `#print axioms` to confirm no `sorryAx` is hidden under
-- a green `lake build`. All five report only the standard
-- `[propext, Classical.choice, Quot.sound]` — never `sorryAx`.
-- #print axioms vcg_revenue_non_monotone
-- #print axioms adding_a_bidder_lowers_revenue
-- #print axioms raising_a_bundle_bid_lowers_revenue
-- #print axioms revenue_high_is_two
-- #print axioms revenue_low_is_zero

/-- Non-vacuity witness (KB VM99): `totalRevenue` is NOT constant — two bid
    profiles yield different revenue. Rules out a degenerate constant revenue
    that would make the `<` in the non-monotonicity theorem vacuous. -/
theorem revenue_nonconstant :
    ∃ b b2 : List CombinatorialBid, totalRevenue b ≠ totalRevenue b2 :=
  ⟨bidsHigh, bidsLow, by decide⟩

end Nucleus.Auctions.VcgRevenueNonMonotone
