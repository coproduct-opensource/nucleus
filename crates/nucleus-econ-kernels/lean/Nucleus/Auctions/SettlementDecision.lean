/-
  Nucleus / Auctions / Settlement Decision  (Bet B — verified settlement)

  **STATUS: PROVED (0 `sorry`).** No `Mathlib` dependency; pure `Nat`
  arithmetic discharged by `omega` and structural case analysis. Mirrors
  the proof style of `Nucleus.Auctions.BudgetConservation` (the other
  load-bearing, Mathlib-free auction theorem in this directory).

  # What this file specifies

  The Bet-B settlement extension (v2) takes a *verdict* — a delivery score
  `deliveredBps ∈ [0, 10000]` asserted by an off-chain delivery oracle
  (PoTE; see the trust-assumption section in
  `crates/nucleus-cardano-offchain/src/settlement_rule.rs` and the design
  doc in the PR) — and decides how the auction's locked `price` lovelace
  splits between the seller (payout) and the bidder (refund).

  v1 settlement (the audited validator under `cardano/`) is the special
  case `deliveredBps = 10000`: the seller is paid the full `price` (less
  the platform fee) and the bidder is refunded only the unspent escrow
  remainder `locked - price`. v2 generalises: a verdict short of full
  delivery diverts part of `price` *back* to the bidder as a delivery
  refund, on top of the escrow remainder.

  The arithmetic here is the SINGLE SOURCE OF TRUTH. It is mirrored
  value-identically (byte for byte on the wire) in:
    * Rust:  `crates/nucleus-cardano-offchain/src/settlement_rule.rs`
    * Aiken: `cardano/lib/settlement/decision.ak`
  and pinned by a frozen golden vector (the same triad pattern as
  `BudgetConservation` ↔ `vcg.rs` ↔ `receipt.ak`).

  # The five theorems (the verified core of Bet B)

  1. `classify_total`        — `classify` is total: every `deliveredBps`
                               maps to exactly one of REVERSE / PARTIAL /
                               RELEASE, with the boundaries at 0 and 10000.
  2. `conservation`          — for ALL verdicts: `sellerGross + refund =
                               price`. No lovelace is created or destroyed
                               by the split; the platform fee is then carved
                               out of `sellerGross` (fee conservation is the
                               v1 property, re-exported).
  3. `sellerGross_mono`      — `sellerGross` is monotone nondecreasing in
                               `deliveredBps` (more delivery ⇒ seller gets
                               at least as much).
  4. `refund_antitone`       — `refund` is antitone in `deliveredBps` (more
                               delivery ⇒ bidder refunded at most as much).
  5. `sellerGross_le_price`  — `sellerGross ≤ price` always (seller can
                               never be paid more than the locked price).

  Plus the two boundary-identification lemmas the validator relies on:
    * `release_is_full_payout`  — at 10000, `sellerGross = price`, `refund = 0`.
    * `reverse_is_full_refund`  — at 0,     `sellerGross = 0`, `refund = price`.

  # Honest scope boundary (read this)

  These theorems prove the settlement *function* is correct: total,
  conservative, monotone, and bounded. They DO NOT — and cannot — prove
  that `deliveredBps` is *true*. "Was the work delivered, and to what
  degree?" is an oracle question (PoTE). The verdict is a TRUST INPUT,
  cryptographically committed (signed by the clearer/oracle key folded
  into the receipt) but not itself verified here. The PR's design doc
  names this assumption explicitly: *we prove the function; we name the
  oracle.*
-/

namespace Nucleus.Auctions.SettlementDecision

/-- Basis-points denominator. 10000 bps = 100%. -/
def bpsScale : Nat := 10000

/-- A settlement verdict bucket. `classify` maps a delivery score to one
    of these three. The on-chain validator branches the payout split on
    this classification; the arithmetic below is what actually moves the
    lovelace.

    reverse : deliveredBps = 0          (full refund to bidder, nothing to seller)
    partial : 0 < deliveredBps < 10000  (split)
    release : deliveredBps >= 10000     (full payout to seller; the v1 case) -/
inductive Verdict : Type where
  | Reverse : Verdict
  | Partial : Verdict
  | Release : Verdict
  deriving DecidableEq, Repr

/-- Classify a delivery score into a verdict bucket. Total over `Nat`
    (scores above `bpsScale` are clamped to `release` by the validator's
    in-range guard, but `classify` itself is defined for all inputs). -/
def classify (deliveredBps : Nat) : Verdict :=
  if deliveredBps = 0 then Verdict.Reverse
  else if deliveredBps ≥ bpsScale then Verdict.Release
  else Verdict.Partial

/-- The seller's GROSS proceeds (before the platform fee is carved out):
    `floor(price * deliveredBps / 10000)`, clamped so the score never
    exceeds full delivery. Integer floor division — identical to the
    Rust/Aiken `*  / 10000` arithmetic. -/
def sellerGross (price deliveredBps : Nat) : Nat :=
  price * (min deliveredBps bpsScale) / bpsScale

/-- The bidder's delivery refund: the part of `price` NOT paid to the
    seller. Defined as the residual `price - sellerGross` so that
    conservation is true *by construction*. -/
def refund (price deliveredBps : Nat) : Nat :=
  price - sellerGross price deliveredBps

-- ───────────────────────────────────────────────────────────────────────
-- Helper: sellerGross ≤ price  (needed for conservation and the bound).
-- ───────────────────────────────────────────────────────────────────────

/-- **Theorem 5 (bound).** The seller's gross is never more than the price.

    `floor(price * m / 10000) ≤ price` whenever `m ≤ 10000`, and `min … 10000`
    guarantees the clamp. Proof: `min … bpsScale ≤ bpsScale`, so
    `price * (min …) ≤ price * bpsScale`, and floor-dividing both sides by
    `bpsScale` gives `≤ price`. -/
theorem sellerGross_le_price (price deliveredBps : Nat) :
    sellerGross price deliveredBps ≤ price := by
  unfold sellerGross bpsScale
  have hm : min deliveredBps 10000 ≤ 10000 := Nat.min_le_right _ _
  -- price * (min …) ≤ price * 10000
  have hmul : price * min deliveredBps 10000 ≤ price * 10000 :=
    Nat.mul_le_mul_left price hm
  -- floor-divide by 10000, then `price * 10000 / 10000 = price`.
  calc price * min deliveredBps 10000 / 10000
      ≤ price * 10000 / 10000 := Nat.div_le_div_right hmul
    _ = price := by
        rw [Nat.mul_div_cancel] ; omega

-- ───────────────────────────────────────────────────────────────────────
-- Theorem 2 — conservation (holds for ALL verdicts / all scores).
-- ───────────────────────────────────────────────────────────────────────

/-- **Theorem 2 (conservation).** For every price and every delivery score:
    `sellerGross + refund = price`. The split never creates or destroys
    lovelace. Because `refund` is defined as `price - sellerGross` and
    `sellerGross ≤ price` (Theorem 5), `Nat` subtraction does not truncate,
    so the two add back to exactly `price`. -/
theorem conservation (price deliveredBps : Nat) :
    sellerGross price deliveredBps + refund price deliveredBps = price := by
  unfold refund
  have h := sellerGross_le_price price deliveredBps
  omega

-- ───────────────────────────────────────────────────────────────────────
-- Theorem 3 — sellerGross monotone in the delivery score.
-- ───────────────────────────────────────────────────────────────────────

/-- **Theorem 3 (seller-share monotonicity).** More delivery never pays the
    seller less: `a ≤ b → sellerGross price a ≤ sellerGross price b`.

    Proof: `min` is monotone, multiplication on the left is monotone, and
    floor division by a fixed denominator is monotone. -/
theorem sellerGross_mono (price : Nat) {a b : Nat} (hab : a ≤ b) :
    sellerGross price a ≤ sellerGross price b := by
  unfold sellerGross
  have hmin : min a bpsScale ≤ min b bpsScale := by
    have h1 : min a bpsScale ≤ a := Nat.min_le_left _ _
    have h2 : min a bpsScale ≤ bpsScale := Nat.min_le_right _ _
    exact Nat.le_min.mpr ⟨Nat.le_trans h1 hab, h2⟩
  have hmul : price * min a bpsScale ≤ price * min b bpsScale :=
    Nat.mul_le_mul_left price hmin
  exact Nat.div_le_div_right hmul

-- ───────────────────────────────────────────────────────────────────────
-- Theorem 4 — refund antitone in the delivery score.
-- ───────────────────────────────────────────────────────────────────────

/-- **Theorem 4 (liability antitonicity).** More delivery never refunds the
    bidder more: `a ≤ b → refund price b ≤ refund price a`.

    Proof: `refund = price - sellerGross`; subtracting a larger
    `sellerGross` (Theorem 3) leaves a smaller residual. -/
theorem refund_antitone (price : Nat) {a b : Nat} (hab : a ≤ b) :
    refund price b ≤ refund price a := by
  unfold refund
  have hs : sellerGross price a ≤ sellerGross price b := sellerGross_mono price hab
  omega

-- ───────────────────────────────────────────────────────────────────────
-- Boundary identification — REVERSE and RELEASE reduce to the v1 endpoints.
-- ───────────────────────────────────────────────────────────────────────

/-- **RELEASE boundary.** At full delivery the seller gets the entire price
    and the bidder's delivery refund is zero — i.e. v2 reduces *exactly* to
    the v1 settlement (full payout) at `deliveredBps = 10000`. This is the
    "conservative extension" claim, mechanised. -/
theorem release_is_full_payout (price : Nat) :
    sellerGross price bpsScale = price ∧ refund price bpsScale = 0 := by
  constructor
  · unfold sellerGross bpsScale
    rw [Nat.min_self, Nat.mul_div_cancel]
    omega
  · unfold refund sellerGross bpsScale
    rw [Nat.min_self, Nat.mul_div_cancel]
    · omega
    · omega

/-- **REVERSE boundary.** At zero delivery the seller gets nothing and the
    bidder is refunded the entire price (a full chargeback). -/
theorem reverse_is_full_refund (price : Nat) :
    sellerGross price 0 = 0 ∧ refund price 0 = price := by
  constructor
  · unfold sellerGross bpsScale
    simp
  · unfold refund sellerGross bpsScale
    simp

-- ───────────────────────────────────────────────────────────────────────
-- Theorem 1 — classify is total and the boundaries are exactly identified.
-- ───────────────────────────────────────────────────────────────────────

/-- **Theorem 1 (totality + boundary identification).** `classify` is a
    total function whose three branches are exactly the intervals
    `{0}`, `(0, 10000)`, `[10000, ∞)`:

      * `deliveredBps = 0`              ↔ `reverse`
      * `0 < deliveredBps < 10000`      ↔ `partial`
      * `deliveredBps ≥ 10000`          ↔ `release`

    Totality is immediate (the definition is a complete `if/else`); the
    content is the boundary characterisation, which is what the validator's
    branch selection depends on. -/
theorem classify_total (deliveredBps : Nat) :
    (deliveredBps = 0 ∧ classify deliveredBps = Verdict.Reverse)
  ∨ (0 < deliveredBps ∧ deliveredBps < bpsScale ∧ classify deliveredBps = Verdict.Partial)
  ∨ (deliveredBps ≥ bpsScale ∧ classify deliveredBps = Verdict.Release) := by
  unfold classify
  by_cases h0 : deliveredBps = 0
  · left
    exact ⟨h0, by simp [h0]⟩
  · by_cases hr : deliveredBps ≥ bpsScale
    · right; right
      refine ⟨hr, ?_⟩
      simp [h0, hr]
    · right; left
      refine ⟨Nat.pos_of_ne_zero h0, ?_, ?_⟩
      · omega
      · simp [h0, hr]

end Nucleus.Auctions.SettlementDecision
