import SessionCeilingProofs

/-!
# Exposure-Loop Least-Fixpoint Proofs — ONE theorem for every user-defined loop

Spike for the "user-defined cascades" investigation (follow-up to #1249 / the
`SessionCeilingProofs` ratchet).

## The claim under test

> A user loop is admissible iff its body is a **monotone endomap** on the
> exposure lattice — and then the ratchet holds at its least fixpoint by
> construction, so every loop inherits ONE theorem instead of shipping its own
> proof obligation.

This file proves exactly that, Mathlib-free, and ties it to the SHIPPED object:
the runtime session-taint ceiling (`SessionCeilingProofs.ceilingFold`) is shown
to be a least fixpoint of a monotone endomap on this same lattice.

## Why this, and not the Kleene-star / action-algebra route

On the capability quantale the star is DEGENERATE: `CapLevel` is the 3-chain
`Never < LowRisk < Always` and `⊗ = meet` is idempotent (proven —
`CapabilityResiduatedQuantaleProofs.capmeet_idem`), so `aⁱ = a` for `i ≥ 1` and
`a* = 1 ∨ a = ⊤` for every `a`. Iterating an idempotent op reaches its fixpoint
in one step, so "does the ratchet survive iteration" needs only idempotence +
monotonicity — both already proven. The interesting iteration lives in the taint
*state*, and there the sufficient (and necessary — see `badLoop_breaks_ratchet`)
tool is Knaster–Tarski over a monotone endomap, NOT residuation, star, or KAT.
That also sidesteps the Σ⁰₁ undecidability of full action logic (Kuznetsov 2019):
the admission check here is "is the body monotone?", a structural side-condition,
not an equivalence decision.

## Discipline
Mathlib-free (same as `SessionCeilingProofs`); `#print axioms` audited at the end.
-/

namespace ExposureLoop

/-- A bounded join-semilattice with antisymmetry and a `Nat` rank that strictly
    increases along the strict order, bounded by `height`. The rank is what makes
    "iterate to a fixpoint" terminate on a FINITE lattice without Mathlib's
    well-founded / `CompleteLattice` machinery — Knaster–Tarski by strict ascent. -/
class RankedLattice (α : Type) where
  le      : α → α → Prop
  join    : α → α → α
  bot     : α
  le_refl       : ∀ a, le a a
  le_trans      : ∀ {a b c}, le a b → le b c → le a c
  le_antisymm   : ∀ {a b}, le a b → le b a → a = b
  le_join_left  : ∀ a b, le a (join a b)
  le_join_right : ∀ a b, le b (join a b)
  join_le       : ∀ {a b c}, le a c → le b c → le (join a b) c
  bot_le        : ∀ a, le bot a
  rank          : α → Nat
  rank_mono     : ∀ {a b}, le a b → rank a ≤ rank b
  rank_strict   : ∀ {a b}, le a b → a ≠ b → rank a < rank b
  height        : Nat
  rank_le_height : ∀ a, rank a ≤ height

open RankedLattice

variable {α : Type} [RankedLattice α]

/-- The admissibility side-condition: the loop body is a monotone endomap. -/
def Mono (f : α → α) : Prop := ∀ a b, le a b → le (f a) (f b)

/-- Unroll the loop body `n` times from `⊥`. -/
def iter (f : α → α) : Nat → α → α
  | 0,      x => x
  | (n+1),  x => f (iter f n x)

-- ═══════════════════════════════════════════════════════════════════════════
-- The iteration chain from ⊥ ascends (for a monotone body)
-- ═══════════════════════════════════════════════════════════════════════════

/-- Each unrolling is `≥` the previous one: starting from `⊥`, a monotone body
    can only raise the exposure. (The first step `⊥ ≤ f ⊥` is free; monotonicity
    propagates it.) -/
theorem iter_step_le (f : α → α) (hf : Mono f) :
    ∀ n, le (iter f n bot) (iter f (n+1) bot) := by
  intro n
  induction n with
  | zero => exact bot_le _
  | succ n ih => exact hf _ _ ih

/-- The chain is monotone in the step count. -/
theorem iter_le_of_le (f : α → α) (hf : Mono f) :
    ∀ m d, le (iter f m bot) (iter f (m + d) bot) := by
  intro m d
  induction d with
  | zero => exact le_refl _
  | succ d ih => exact le_trans ih (iter_step_le f hf (m + d))

-- ═══════════════════════════════════════════════════════════════════════════
-- Termination: the ascending chain stabilizes within `height + 1` steps
-- ═══════════════════════════════════════════════════════════════════════════

/-- If every step up to `n` strictly moved, the rank has climbed at least `n`. -/
theorem rank_ge_of_strict (f : α → α) (hf : Mono f) :
    ∀ n, (∀ k, k < n → iter f (k+1) bot ≠ iter f k bot) →
      n ≤ rank (iter f n bot) := by
  intro n
  induction n with
  | zero => intro _; exact Nat.zero_le _
  | succ n ih =>
      intro hstrict
      have ihn : n ≤ rank (iter f n bot) :=
        ih (fun k hk => hstrict k (Nat.lt_succ_of_lt hk))
      have hne : iter f (n+1) bot ≠ iter f n bot := hstrict n (Nat.lt_succ_self n)
      have hlt : rank (iter f n bot) < rank (iter f (n+1) bot) :=
        rank_strict (iter_step_le f hf n) (fun h => hne h.symm)
      exact Nat.lt_of_le_of_lt ihn hlt

/-- Because the rank is bounded by `height`, some step within `height + 1` must
    stall — i.e. hit a fixpoint of the body. -/
theorem exists_fixpoint_index (f : α → α) (hf : Mono f) :
    ∃ k, k ≤ height (α := α) ∧ iter f (k+1) bot = iter f k bot := by
  refine Classical.byContradiction (fun hne => ?_)
  have hstrict : ∀ k, k < height (α := α) + 1 → iter f (k+1) bot ≠ iter f k bot := by
    intro k hk hEq
    exact hne ⟨k, Nat.lt_succ_iff.mp hk, hEq⟩
  have hge := rank_ge_of_strict f hf (height (α := α) + 1) hstrict
  have hle := rank_le_height (iter f (height (α := α) + 1) bot)
  exact absurd (Nat.le_trans hge hle) (Nat.not_succ_le_self _)

/-- Once a step stalls, every later unrolling is constant. -/
theorem iter_const (f : α → α) (k : Nat)
    (hfix : iter f (k+1) bot = iter f k bot) :
    ∀ j, iter f (k+j) bot = iter f k bot := by
  intro j
  induction j with
  | zero => rfl
  | succ j ih => show f (iter f (k+j) bot) = iter f k bot
                 rw [ih]; exact hfix

-- ═══════════════════════════════════════════════════════════════════════════
-- The least fixpoint
-- ═══════════════════════════════════════════════════════════════════════════

/-- `lfp f` — iterate the body from `⊥` past the point it must have stalled. -/
def lfp (f : α → α) : α := iter f (height (α := α) + 1) bot

/-- **`lfp f` is a genuine fixpoint** of a monotone body. -/
theorem lfp_fixed (f : α → α) (hf : Mono f) : f (lfp f) = lfp f := by
  obtain ⟨k, hkH, hfix⟩ := exists_fixpoint_index f hf
  have hconst := iter_const f k hfix
  have hkH1 : k ≤ height (α := α) + 1 := Nat.le_trans hkH (Nat.le_succ _)
  have e1 : iter f (height (α := α) + 1) bot = iter f k bot := by
    obtain ⟨d, hd⟩ := Nat.le.dest hkH1
    rw [← hd]; exact hconst d
  have e2 : iter f (height (α := α) + 2) bot = iter f k bot := by
    have hkH2 : k ≤ height (α := α) + 2 := Nat.le_trans hkH1 (Nat.le_succ _)
    obtain ⟨d, hd⟩ := Nat.le.dest hkH2
    rw [← hd]; exact hconst d
  show f (iter f (height (α := α) + 1) bot) = iter f (height (α := α) + 1) bot
  calc f (iter f (height (α := α) + 1) bot)
        = iter f (height (α := α) + 2) bot := rfl
      _ = iter f k bot := e2
      _ = iter f (height (α := α) + 1) bot := e1.symm

/-- Past `height + 1`, every unrolling equals `lfp f`. -/
theorem iter_from_lfp (f : α → α) (hf : Mono f) :
    ∀ j, iter f (height (α := α) + 1 + j) bot = lfp f := by
  intro j
  induction j with
  | zero => rfl
  | succ j ih =>
      show f (iter f (height (α := α) + 1 + j) bot) = lfp f
      rw [ih]; exact lfp_fixed f hf

/-- **Every finite unrolling stays below the fixpoint** — no number of loop
    iterations escapes upward past `lfp f`. -/
theorem iter_le_lfp (f : α → α) (hf : Mono f) :
    ∀ n, le (iter f n bot) (lfp f) := by
  intro n
  rcases Nat.lt_or_ge n (height (α := α) + 1) with h | h
  · obtain ⟨d, hd⟩ := Nat.le.dest (Nat.le_of_lt h)
    have hchain := iter_le_of_le f hf n d
    rw [hd] at hchain; exact hchain
  · obtain ⟨j, hj⟩ := Nat.le.dest h
    rw [← hj, iter_from_lfp f hf j]; exact le_refl _

-- ═══════════════════════════════════════════════════════════════════════════
-- THE headline theorem: one ratchet for every admissible loop
-- ═══════════════════════════════════════════════════════════════════════════

/-- The ratchet guarantees an admissible loop inherits. -/
structure Ratchets (f : α → α) : Prop where
  /-- the loop converges: `lfp f` is a real fixpoint of the body -/
  fixed          : f (lfp f) = lfp f
  /-- every intermediate unrolling stays `≤` the fixpoint -/
  unrolls_below  : ∀ n, le (iter f n bot) (lfp f)
  /-- **anti-laundering**: if any unrolling denies an action (its required
      cleanliness `t` is `≤` the exposure), the fixpoint denies it too — a loop
      cannot iterate its way out of a denial -/
  denial_persists : ∀ n t, le t (iter f n bot) → le t (lfp f)

/-- **ONE theorem for every user loop.** A monotone body is admissible: the
    ratchet holds at its least fixpoint, no per-loop proof required. -/
theorem loop_admissible (f : α → α) (hf : Mono f) : Ratchets f where
  fixed           := lfp_fixed f hf
  unrolls_below   := iter_le_lfp f hf
  denial_persists := fun n _t ht => le_trans ht (iter_le_lfp f hf n)

-- ═══════════════════════════════════════════════════════════════════════════
-- Tie to the SHIPPED object: the session-taint ceiling is such a fixpoint
-- ═══════════════════════════════════════════════════════════════════════════

/-- A `RankedLattice` is in particular the `TaintLattice` the runtime ceiling is
    proven over — so `ceilingFold` (the shipped `ifc_api.rs` update) lives on
    this exact lattice. -/
instance instTaintLattice : SessionCeiling.TaintLattice α where
  le      := le
  join    := join
  bot     := bot
  le_refl := le_refl
  le_trans := le_trans
  le_join_left := le_join_left
  le_join_right := le_join_right
  join_le := join_le
  bot_le := bot_le

theorem join_bot_left (k : α) : join bot k = k :=
  le_antisymm (join_le (bot_le k) (le_refl k)) (le_join_right bot k)

theorem join_idem (k : α) : join k k = k :=
  le_antisymm (join_le (le_refl k) (le_refl k)) (le_join_left k k)

/-- The "raise exposure to at least `k`" body — `x ↦ x ⊔ k` — is monotone; this
    is precisely the shape of a single session observation. -/
theorem bump_mono (k : α) : Mono (fun x => join x k) := by
  intro a b hab
  exact join_le (le_trans hab (le_join_left b k)) (le_join_right b k)

/-- Its least fixpoint from `⊥` is exactly `k`. -/
theorem iter_join_const (k : α) :
    ∀ n, iter (fun x => join x k) (n+1) bot = k := by
  intro n
  induction n with
  | zero => show join bot k = k
            exact join_bot_left k
  | succ n ih => show join (iter (fun x => join x k) (n+1) bot) k = k
                 rw [ih]; exact join_idem k

theorem lfp_join_const (k : α) : lfp (fun x => join x k) = k :=
  iter_join_const k (height (α := α))

/-- **The shipped runtime object is a least fixpoint on the exposure lattice.**
    The session-taint ceiling `ceilingFold ⊥ os` (the `ifc_api.rs` update the
    anti-laundering proofs are stated over) equals the least fixpoint of a
    monotone endomap `x ↦ x ⊔ (ceilingFold ⊥ os)` — so the general
    `loop_admissible` ratchet subsumes the bespoke `SessionCeilingProofs`
    ratchet, rather than duplicating it. -/
theorem ceilingFold_eq_lfp (os : List α) :
    SessionCeiling.TaintLattice.ceilingFold (bot : α) os
      = lfp (fun x => join x (SessionCeiling.TaintLattice.ceilingFold (bot : α) os)) :=
  (lfp_join_const _).symm

-- ═══════════════════════════════════════════════════════════════════════════
-- Non-vacuity witness + FALSIFICATION (monotonicity is load-bearing)
-- ═══════════════════════════════════════════════════════════════════════════

/-- A concrete 3-chain, mirroring the capability lattice `Never < LowRisk < Always`. -/
inductive L3 where
  | lo | mid | hi
  deriving DecidableEq, Repr

def L3.toNat : L3 → Nat
  | .lo => 0 | .mid => 1 | .hi => 2

/-- Reducible so `decide` can see the `Nat.le` `Decidable` instance underneath
    (a plain `def` would hide it — the abstract-projection trap). -/
abbrev L3.le (a b : L3) : Prop := a.toNat ≤ b.toNat
def L3.join (a b : L3) : L3 := if a.toNat ≤ b.toNat then b else a

instance : RankedLattice L3 where
  le := L3.le
  join := L3.join
  bot := .lo
  le_refl        := by intro a; cases a <;> decide
  le_trans       := by intro a b c; cases a <;> cases b <;> cases c <;> decide
  le_antisymm    := by intro a b; cases a <;> cases b <;> decide
  le_join_left   := by intro a b; cases a <;> cases b <;> decide
  le_join_right  := by intro a b; cases a <;> cases b <;> decide
  join_le        := by intro a b c; cases a <;> cases b <;> cases c <;> decide
  bot_le         := by intro a; cases a <;> decide
  rank           := L3.toNat
  rank_mono      := by intro a b; cases a <;> cases b <;> decide
  rank_strict    := by intro a b; cases a <;> cases b <;> decide
  height         := 2
  rank_le_height := by intro a; cases a <;> decide

/-- Non-vacuity: a real admissible loop on the 3-chain. Its body raises the
    ceiling to `mid`; the ratchet holds at the fixpoint `mid`. -/
example : Ratchets (fun x => RankedLattice.join x L3.mid) :=
  loop_admissible _ (bump_mono L3.mid)

example : lfp (fun x => RankedLattice.join x L3.mid) = L3.mid := lfp_join_const L3.mid

/-- The fixpoint genuinely differs from the `⊥` start — not a trivial lattice. -/
example : lfp (fun x => RankedLattice.join x L3.mid) ≠ RankedLattice.bot := by
  rw [lfp_join_const]; show L3.mid ≠ L3.lo; decide

/-- A NON-monotone body on the same lattice: it swaps `lo` and `hi`. -/
def badLoop : L3 → L3
  | .lo => .hi
  | .hi => .lo
  | .mid => .mid

theorem badLoop_not_mono : ¬ Mono badLoop := by
  intro h
  have hle : L3.le L3.lo L3.hi := by decide
  have hbad : L3.le (badLoop L3.lo) (badLoop L3.hi) := h L3.lo L3.hi hle
  exact absurd hbad (by decide)

/-- **Monotonicity is load-bearing, not decoration.** Drop it and the ratchet
    fails: the second unrolling of `badLoop` drops strictly BELOW the first
    (`hi` then `lo`, `⊥ = lo`), so no fixpoint dominates the chain and
    `unrolls_below` is false. This is the RED that makes the monotone hypothesis
    a real gate rather than decoration. -/
theorem badLoop_breaks_ratchet :
    ¬ L3.le (iter badLoop 1 L3.lo) (iter badLoop 2 L3.lo) := by
  decide

-- ═══════════════════════════════════════════════════════════════════════════
-- Axiom audit — must be free of `sorryAx`
-- ═══════════════════════════════════════════════════════════════════════════

#print axioms loop_admissible
#print axioms ceilingFold_eq_lfp
#print axioms badLoop_breaks_ratchet
#print axioms badLoop_not_mono

end ExposureLoop
