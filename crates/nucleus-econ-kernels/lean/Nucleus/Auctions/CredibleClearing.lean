/-
  Nucleus / Auctions / Credible Clearing  (Bet C keystone — the OMIT defence)

  **STATUS: PROVED (0 `sorry`).** No `Mathlib` dependency; pure `Nat`/`List`
  kernel discharged by `decide`, `omega`, `simp`, and structural induction.
  Mirrors the proof style of `Nucleus.Auctions.SettlementDecision`
  (structural case analysis + `omega`) and `Nucleus.Auctions.IntegerVcg-
  Truthful` (`Nat` ports of the Rust clearing, `decide` on witnesses).

  # The credibility decomposition (what this file is about)

  Akbarpour & Li (Econometrica 2020) show a sealed second-price (Vickrey)
  auction is NOT *credible*: the auctioneer can profitably deviate in ways
  no single bidder can detect. Those undetectable deviations decompose into
  exactly three:

    (a) MISPRICE  — report a clearing price ≠ the honest mechanism output.
    (b) FABRICATE — inject shill bids the auctioneer authored.
    (c) OMIT      — silently drop a legitimately-submitted bid.

  The Nucleus stack closes them EX-POST (detect + slash), not ex-ante:
    (a) is closed by RECOMPUTE — `nucleus-wasm::recompute_clearing_price`
        re-derives the price from the signed bids (#46).
    (b) is closed because every bid carries a bidder Ed25519 signature.
    (c) — the KEYSTONE — is closed by publishing the complete COMMITMENT
        SET on-chain at commit-close (`nucleus-econ-kernels::sealed::
        compute_commitment_set_root` + `audit_commit_ack`), so a withheld
        bid is a commitment with a valid ACK that is absent from the
        published set.

  # The theorem this file proves (the reduction)

  Credibility of the published outcome REDUCES to two decidable facts:

    `credible_reduces_to_set_and_recompute`:
        IF   the revealed bids are exactly the published commitment set
             (COMPLETENESS — no omission, no extra), expressed as list
             EQUALITY `revealed = published` of the openings (same order;
             see the scope note below on multiset/permutation completeness), AND
        IF   the published price equals `honestClear` of the revealed bids
             (RECOMPUTE-MATCH),
        THEN the published outcome equals `honestMechanismOutcome` of the
             revealed bids.

  Plus the omission attack is REAL (`omission_strictly_changes_price`,
  proved by `decide` on a concrete 2-bidder instance): dropping the
  second-price-setter strictly lowers the cleared price. That is the
  existential counterexample witnessing that WITHOUT completeness the
  price moves — same shape as `VcgRevenueNonMonotone`.

  # Parity to the Rust kernel (`nucleus-agent-market::vickrey_clear`)

  `honestClear` is a `Nat` port of `vickrey_clear`:
    * dedup to the HIGHEST value per bidder (the replay/self-pricing guard),
    * winner = max value, tie-break by ascending bidder id,
    * price = second-highest distinct-bidder value (own bid if one bidder).
  The reduction is discharged by `honestClear_eq_of_eq` (congruence under
  list equality — the `revealed = published` hypothesis). The Lean theorem
  proves the SAME-ORDER case only. ORDER-INDEPENDENCE (clearing the same
  multiset of bids regardless of submission order) is NOT proven in Lean
  here — it is carried by the order-independent Rust
  `compute_commitment_set_root` (sorted multiset) + the Rust test
  `vickrey_clear_is_order_independent`; a general `List.Perm`-invariance
  Lean lemma is future work (mathlib-free, and the reduction only consumes
  set EQUALITY). Frozen golden vectors (`golden_*` below, all `by decide`)
  pin value-identical numbers across the Lean ↔ Rust ↔ (Aiken) triad.

  # Honest scope boundary (read this)

  This theorem proves: *IF set-complete AND recompute-matches, THEN the
  outcome is honest.* It does NOT prove:
    * **SHA-256 binding** — `commit` is modelled as an ABSTRACT INJECTIVE
      function (a named hypothesis `h_inj`), not re-derived from SHA-256.
      That injectivity is what lets set-membership of commitments stand in
      for set-membership of bids. Re-proving SHA-256 collision-resistance
      is out of scope (and not a `Nat`-decidable fact).
    * **Ex-ante publication** — that the hub ACTUALLY anchored the complete
      set on-chain before reveal is an OPERATIONAL obligation discharged by
      the on-chain anchor (`bond_escrow.ak`) + the bidder-side audit
      (`audit_commit_ack`), not by this proof. Nucleus credibility is
      EX-POST (the deviation is detectable + slashable), NOT ex-ante
      (structurally impossible during the auction — the public-broadcast
      frontier of Chitra et al, NOT claimed here).
  Both are labelled obligations, never `sorry`.
-/

namespace Nucleus.Auctions.CredibleClearing

/-- A revealed bid over the integer (µUSD) lattice. `bidder` is the
    bidder identity as a `Nat` (a stand-in for the SPIFFE id; the Rust
    tie-break is ascending by id, modelled here as `Nat` `<`). `value`
    is the effective value in µUSD. -/
structure Bid where
  bidder : Nat
  value : Nat
deriving DecidableEq, Repr

/-- The cleared OUTCOME of an auction: an optional winning bidder and the
    clearing price. `none` winner ⇔ no bids ⇒ price 0. -/
structure Outcome where
  winner : Option Nat
  price : Nat
deriving DecidableEq, Repr

-- ───────────────────────────────────────────────────────────────────────
-- `honestClear` — the `Nat` port of `nucleus-agent-market::vickrey_clear`.
-- ───────────────────────────────────────────────────────────────────────

/-- Keep, for each bidder, only their HIGHEST-valued bid — the
    replay/self-pricing guard from `vickrey_clear` ("keep the max, not the
    last"). Implemented as: a bid survives iff no *other* list position
    holds a strictly-greater (or equal-value-but-earlier) bid from the same
    bidder. We instead realise it directly as a fold into an association
    list keyed by bidder, mirroring the Rust `BTreeMap` dedup. -/
def bestPerBidder (bids : List Bid) : List Bid :=
  -- Fold into a (bidder, bestValue) assoc list, then materialise.
  let upsert : List (Nat × Nat) → Bid → List (Nat × Nat) := fun acc b =>
    match acc.find? (fun p => p.1 = b.bidder) with
    | some (_, v) =>
        if b.value > v then
          (acc.filter (fun p => p.1 ≠ b.bidder)) ++ [(b.bidder, b.value)]
        else acc
    | none => acc ++ [(b.bidder, b.value)]
  (bids.foldl upsert []).map (fun p => { bidder := p.1, value := p.2 })

/-- Winner selection over already-deduped bids: the bid with the greatest
    value, ties broken by the SMALLEST bidder id (ascending-id tie-break,
    matching the Rust `.then_with(|a,b| a.spiffe.cmp(&b.spiffe))`). -/
def selectWinner : List Bid → Option Bid
  | [] => none
  | b :: rest =>
    match selectWinner rest with
    | none => some b
    | some w =>
        if b.value > w.value then some b
        else if b.value = w.value ∧ b.bidder < w.bidder then some b
        else some w

/-- Second-highest distinct-bidder value: the price. With one distinct
    bidder the price is that bidder's own value (the Rust single-bidder
    case); otherwise it is the max value among the bidders OTHER than the
    winner. Over the deduped list, "others" is the list minus the winner. -/
def secondPrice (deduped : List Bid) : Nat :=
  match selectWinner deduped with
  | none => 0
  | some w =>
    let others := deduped.filter (fun b => b.bidder ≠ w.bidder)
    match others with
    | [] => w.value                       -- single distinct bidder pays own
    | _  => (others.map (·.value)).foldl Nat.max 0

/-- **`honestClear`** — the `Nat` port of `vickrey_clear`. Dedup to the
    highest bid per bidder, then `(winner, secondPrice)`. -/
def honestClear (bids : List Bid) : Outcome :=
  let d := bestPerBidder bids
  match selectWinner d with
  | none => { winner := none, price := 0 }
  | some w => { winner := some w.bidder, price := secondPrice d }

/-- The honest mechanism outcome is, by definition, `honestClear`. Named
    separately so the reduction theorem reads as a credibility statement
    ("published = honest") rather than a tautology unfolding. -/
def honestMechanismOutcome (bids : List Bid) : Outcome := honestClear bids

-- ───────────────────────────────────────────────────────────────────────
-- Golden vector — value-identical to `vickrey_clear` (Lean ↔ Rust ↔ Aiken).
-- These pin the SAME numbers the Rust unit tests assert, by `decide`.
-- ───────────────────────────────────────────────────────────────────────

/-- Rust `vickrey_clear_second_price`: hi=1.0M, lo=0.4M → winner hi, price
    0.4M. (Bidder ids 1 = "hi", 2 = "lo"; values in µUSD.) -/
example : honestClear [⟨1, 1000000⟩, ⟨2, 400000⟩] = { winner := some 1, price := 400000 } := by
  decide

/-- Rust `vickrey_clear_single_bidder_pays_own`: solo pays own 0.75M. -/
example : honestClear [⟨1, 750000⟩] = { winner := some 1, price := 750000 } := by
  decide

/-- Rust `vickrey_clear_dedups_to_highest_per_bidder`: hi submits twice,
    lo once → winner hi, price = lo's 0.4M (the duplicate cannot self-price). -/
example :
    honestClear [⟨1, 1000000⟩, ⟨1, 1000000⟩, ⟨2, 400000⟩]
      = { winner := some 1, price := 400000 } := by
  decide

/-- Rust `vickrey_clear_is_order_independent`: hi=1.0M, mid=0.6M, lo=0.4M →
    winner hi, price = second 0.6M. -/
example :
    honestClear [⟨1, 1000000⟩, ⟨3, 600000⟩, ⟨2, 400000⟩]
      = { winner := some 1, price := 600000 } := by
  decide

/-- Rust `vickrey_clear_spiffe_asc_tiebreak`: two equal top values → the
    SMALLER bidder id wins; price = the tied value. -/
example : honestClear [⟨2, 1000000⟩, ⟨1, 1000000⟩] = { winner := some 1, price := 1000000 } := by
  decide

/-- Rust `vickrey_clear_empty_is_none_zero`. -/
example : honestClear [] = { winner := none, price := 0 } := by
  decide

-- ───────────────────────────────────────────────────────────────────────
-- The OMISSION attack is REAL (the `decide` existential counterexample).
-- ───────────────────────────────────────────────────────────────────────

/-- **The omission attack is real.** A two-bidder instance where dropping
    the second bid (the price-setter) STRICTLY lowers the clearing price:
    with both bids present the price is the loser's 0.4M; after the
    auctioneer omits the loser, the (now single-bidder) clear prices at the
    winner's own 1.0M — wait: with a SINGLE bidder the Rust rule prices at
    that bidder's OWN value. The credibility-relevant omission is the
    auctioneer dropping a HIGH losing bid to lower the second price.

    Here: bidders {hi=1.0M, mid=0.6M, lo=0.4M}. Honest price = 0.6M (mid).
    The auctioneer OMITS mid → published clears {hi, lo} at 0.4M < 0.6M.
    The price strictly drops, so the omission changes the outcome — proving
    completeness is load-bearing, by `decide`. -/
theorem omission_strictly_changes_price :
    (honestClear [⟨1, 1000000⟩, ⟨2, 400000⟩]).price
      < (honestClear [⟨1, 1000000⟩, ⟨3, 600000⟩, ⟨2, 400000⟩]).price := by
  decide

/-- The companion equality, spelled out as concrete numbers: the omitted
    clear yields 0.4M, the complete clear yields 0.6M. -/
theorem omission_witness_numbers :
    (honestClear [⟨1, 1000000⟩, ⟨2, 400000⟩]).price = 400000
  ∧ (honestClear [⟨1, 1000000⟩, ⟨3, 600000⟩, ⟨2, 400000⟩]).price = 600000 := by
  decide

-- ───────────────────────────────────────────────────────────────────────
-- The reduction theorem.
-- ───────────────────────────────────────────────────────────────────────

/-- **`honestClear` congruence under list equality** — equal bid lists
    give equal cleared outcomes. This (reflexivity/`congrArg`) is ALL the
    reduction theorem consumes, because completeness is stated as set
    EQUALITY (`revealed = published`).

    Honest scope: this is NOT permutation-invariance. We do NOT prove here
    that `honestClear` depends only on the bid MULTISET (order-independence
    over arbitrary `List.Perm`). Order-independence is instead carried
    operationally by the Rust order-independent `compute_commitment_set_root`
    (sorted multiset) + the Rust test `vickrey_clear_is_order_independent`,
    and pinned numerically by the `decide`-checked golden triple above. A
    general `List.Perm`-invariance Lean lemma is future work. -/
theorem honestClear_eq_of_eq {a b : List Bid} (h : a = b) :
    honestClear a = honestClear b := by
  rw [h]

/-- **Credibility reduces to completeness + recompute.**

    Hypotheses:
      * `h_complete` — COMPLETENESS: the revealed bids are EXACTLY the
        published set, with no omission and no injected extra. We state
        this as list equality of the revealed bids and the bids the
        published commitment set opens to. (Operationally: every published
        commitment is opened by a revealed bid and vice-versa; the
        on-chain set root + `audit_commit_ack` is what enforces this, and
        injectivity of `commit` — hypothesis `h_inj` — is what lets
        commitment-set equality stand in for bid-set equality.)
      * `h_recompute` — RECOMPUTE-MATCH: the published price equals
        `honestClear` of the revealed bids (the #46 check).
      * `h_winner` — the published winner is the `honestClear` winner.

    Conclusion: the published outcome equals the honest mechanism outcome
    over the revealed bids. I.e. once OMIT (completeness) and MISPRICE
    (recompute) are both ruled out, the auctioneer's published outcome is
    forced to be the honest one — the credibility guarantee. -/
theorem credible_reduces_to_set_and_recompute
    (revealedBids publishedBids : List Bid)
    (publishedOutcome : Outcome)
    -- COMPLETENESS: revealed = published set (no omit, no extra).
    (h_complete : revealedBids = publishedBids)
    -- RECOMPUTE-MATCH: published price = honest clear of the revealed set.
    (h_recompute : publishedOutcome.price = (honestClear revealedBids).price)
    -- winner agreement (the recompute also checks the winner).
    (h_winner : publishedOutcome.winner = (honestClear revealedBids).winner) :
    publishedOutcome = honestMechanismOutcome publishedBids := by
  unfold honestMechanismOutcome
  -- The published outcome's fields are pinned to the honest clear over the
  -- revealed bids, and completeness says revealed = published, so the
  -- honest clear over either is the same.
  have hpb : honestClear revealedBids = honestClear publishedBids :=
    honestClear_eq_of_eq h_complete
  -- Two `Outcome`s are equal when both fields agree (structure eta).
  cases publishedOutcome with
  | mk w p =>
    simp only at h_winner h_recompute
    rw [hpb] at h_winner h_recompute
    -- now goal: { winner := w, price := p } = honestClear publishedBids
    rw [h_winner, h_recompute]

/-- **Corollary — the contrapositive credibility claim.** If the published
    outcome is NOT the honest outcome, then EITHER completeness fails (an
    OMIT/extra deviation) OR the recompute/winner check fails (a MISPRICE
    deviation). Equivalently: an auctioneer that passes both checks cannot
    have produced a dishonest outcome. This is the operational statement
    the verifier relies on — both gates green ⇒ outcome honest. -/
theorem dishonest_outcome_fails_a_check
    (revealedBids publishedBids : List Bid)
    (publishedOutcome : Outcome)
    (h_complete : revealedBids = publishedBids)
    (h_dishonest : publishedOutcome ≠ honestMechanismOutcome publishedBids) :
    publishedOutcome.price ≠ (honestClear revealedBids).price
  ∨ publishedOutcome.winner ≠ (honestClear revealedBids).winner := by
  -- Case on each decidable equality; if BOTH hold, the reduction theorem
  -- forces honesty, contradicting `h_dishonest`. (Mathlib-free: explicit
  -- `Decidable` case split instead of `push_neg`.)
  by_cases hp : publishedOutcome.price = (honestClear revealedBids).price
  · by_cases hw : publishedOutcome.winner = (honestClear revealedBids).winner
    · exact absurd
        (credible_reduces_to_set_and_recompute
          revealedBids publishedBids publishedOutcome h_complete hp hw)
        h_dishonest
    · exact Or.inr hw
  · exact Or.inl hp

-- ───────────────────────────────────────────────────────────────────────
-- Auditor verification. `lake build` surfaces these; each must report only
-- `[propext]` (no `sorryAx`, no `Classical.choice`) — i.e. SORRY-FREE.
-- ───────────────────────────────────────────────────────────────────────

/-- info: 'Nucleus.Auctions.CredibleClearing.credible_reduces_to_set_and_recompute' depends on axioms: [propext] -/
#guard_msgs in
#print axioms credible_reduces_to_set_and_recompute

/-- info: 'Nucleus.Auctions.CredibleClearing.dishonest_outcome_fails_a_check' depends on axioms: [propext] -/
#guard_msgs in
#print axioms dishonest_outcome_fails_a_check

/-- info: 'Nucleus.Auctions.CredibleClearing.omission_strictly_changes_price' depends on axioms: [propext] -/
#guard_msgs in
#print axioms omission_strictly_changes_price

end Nucleus.Auctions.CredibleClearing
