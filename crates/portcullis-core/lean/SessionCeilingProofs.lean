/-!
# Session Taint Ceiling — Anti-Laundering Proofs  (PROVED — 0 proof-holes, 0 extra axioms)

Models the runtime session taint ceiling (`nucleus-ifc-kernel/src/ifc_api.rs`):
the ceiling starts at ⊥ (`Deterministic`, :266); each observation RAISES it by
`join` (:360/:458); an action is DENIED when `threshold ≤ ceiling`
(`check_action_safety_with_ceiling`, :624); the ceiling is lowered ONLY via a
token-gated `reset_session_ceiling` (:780 — the type-enforced ratchet).

Proves the #1207 anti-laundering guarantee / FORMAL_METHODS "What we DON'T verify
#7" (compartment transitions): no sequence of observations — nor a fresh
compartment/node — can launder away accumulated taint; only an authorized reset
can lower the ceiling. Mathlib-free; same discipline as `UnwindingNoninterference`.
-/

namespace SessionCeiling

/-- A bounded join-semilattice — the `DerivationClass` taint lattice abstracted
    (`join` = "most tainted wins"; ⊥ = `Deterministic`). -/
class TaintLattice (α : Type) where
  le      : α → α → Prop
  join    : α → α → α
  bot     : α
  le_refl       : ∀ a, le a a
  le_trans      : ∀ {a b c}, le a b → le b c → le a c
  le_join_left  : ∀ a b, le a (join a b)
  le_join_right : ∀ a b, le b (join a b)
  join_le       : ∀ {a b c}, le a c → le b c → le (join a b) c
  bot_le        : ∀ a, le bot a

namespace TaintLattice
variable {α : Type} [TaintLattice α]

/-- The session ceiling after folding observed derivation classes into an initial
    ceiling — `foldl join`, exactly the ifc_api.rs update. -/
def ceilingFold (c0 : α) : List α → α
  | []      => c0
  | o :: os => ceilingFold (join c0 o) os

/-- **(A) Monotone ratchet** — each observation only RAISES the ceiling; it never
    drops below its start. This is "taint never silently decreases" (no reset). -/
theorem le_ceilingFold_init (c0 : α) (os : List α) : le c0 (ceilingFold c0 os) := by
  induction os generalizing c0 with
  | nil => exact le_refl c0
  | cons o os ih => exact le_trans (le_join_left c0 o) (ih (join c0 o))

/-- **(B) No observation is laundered** — every observed class flows into the
    final ceiling, regardless of position in the sequence. -/
theorem obs_le_ceilingFold (c0 : α) (os : List α) :
    ∀ o, o ∈ os → le o (ceilingFold c0 os) := by
  induction os generalizing c0 with
  | nil => intro o h; cases h
  | cons x xs ih =>
      intro o h
      cases h with
      | head => exact le_trans (le_join_right c0 x) (le_ceilingFold_init (join c0 x) xs)
      | tail _ hmem => exact ih (join c0 x) o hmem

/-- Folding appends: `ceilingFold c0 (os ++ extra) = ceilingFold (ceilingFold c0 os) extra`. -/
theorem ceilingFold_append (c0 : α) (os extra : List α) :
    ceilingFold c0 (os ++ extra) = ceilingFold (ceilingFold c0 os) extra := by
  induction os generalizing c0 with
  | nil => rfl
  | cons o os ih => exact ih (join c0 o)

/-- Appending further observations only RAISES the ceiling. -/
theorem le_ceilingFold_append (c0 : α) (os extra : List α) :
    le (ceilingFold c0 os) (ceilingFold c0 (os ++ extra)) := by
  rw [ceilingFold_append]; exact le_ceilingFold_init _ _

/-- The session-ceiling gate (`check_action_safety_with_ceiling`): an action with
    required-cleanliness `threshold` is DENIED when `le threshold ceiling`. -/
def denied (threshold ceiling : α) : Prop := le threshold ceiling

/-- **(C) ANTI-LAUNDERING.** If ANY observation in the session is at least as
    tainted as the action's threshold, the action is DENIED after the whole
    session — independent of observation order. No sequence launders it away. -/
theorem tainted_obs_denies (c0 : α) (os : List α) (threshold o : α)
    (hmem : o ∈ os) (htaint : le threshold o) :
    denied threshold (ceilingFold c0 os) :=
  le_trans htaint (obs_le_ceilingFold c0 os o hmem)

/-- **(D) COMPARTMENT TRANSITION CANNOT LAUNDER.** The gate reads the SESSION
    ceiling, not the per-node/compartment label, and further observations only
    raise it — so a denied action stays denied across a compartment transition
    (modeled as appending fresh nodes/observations). A fresh compartment cannot
    re-enable a denied action. -/
theorem denied_persists (c0 : α) (os extra : List α) (threshold : α)
    (hden : denied threshold (ceilingFold c0 os)) :
    denied threshold (ceilingFold c0 (os ++ extra)) :=
  le_trans hden (le_ceilingFold_append c0 os extra)

/-- **(E) Lowering requires a reset.** Without a reset, the ceiling stays ≥ its
    start; so a session starting clean (⊥) that becomes denied can be re-cleaned
    ONLY by an explicit `reset_session_ceiling` (the token-gated ratchet), never
    by observation. -/
theorem no_launder_without_reset (c0 : α) (os : List α) : le c0 (ceilingFold c0 os) :=
  le_ceilingFold_init c0 os

/-- A ceiling folded from an initial value bounded by `b` over observations all
    bounded by `b` stays bounded by `b` (join is the LEAST upper bound). -/
theorem ceilingFold_le_of_bound (b : α) : ∀ (c0 : α) (os : List α),
    le c0 b → (∀ o ∈ os, le o b) → le (ceilingFold c0 os) b
  | c0, [], hc0, _ => hc0
  | c0, o :: os, hc0, hos => by
      apply ceilingFold_le_of_bound b (join c0 o) os
      · exact join_le hc0 (hos o (List.Mem.head os))
      · intro x hx; exact hos x (List.Mem.tail o hx)

/-- **(F) The reset is a real release valve.** Modeling `reset_session_ceiling`
    as returning the ceiling to ⊥: if every observation AFTER the reset is clean
    (≤ a bound `b` that does not already deny the action), then the action
    requiring `threshold` is NO LONGER denied. This is the positive complement to
    (E) — the token-gated reset genuinely re-enables actions, it is not a no-op. -/
theorem reset_re_enables (threshold b : α) (os : List α)
    (hbound : ∀ o ∈ os, le o b) (hopen : ¬ le threshold b) :
    ¬ denied threshold (ceilingFold bot os) := by
  intro hden
  exact hopen (le_trans hden (ceilingFold_le_of_bound b bot os (bot_le b) hbound))

end TaintLattice

/-- Non-vacuity witness: ℕ with `≤` and `max`-by-if, ⊥ = 0. Mathlib-free, so the
    theorems above are not vacuously about an empty class. -/
instance : TaintLattice Nat where
  le := Nat.le
  join a b := if a ≤ b then b else a
  bot := 0
  le_refl := Nat.le_refl
  le_trans := Nat.le_trans
  le_join_left a b := by
    by_cases h : a ≤ b
    · rw [if_pos h]; exact h
    · rw [if_neg h]; exact Nat.le_refl a
  le_join_right a b := by
    by_cases h : a ≤ b
    · rw [if_pos h]; exact Nat.le_refl b
    · rw [if_neg h]; exact Nat.le_of_lt (Nat.lt_of_not_le h)
  join_le := by
    intro a b c ha hb
    by_cases h : a ≤ b
    · rw [if_pos h]; exact hb
    · rw [if_neg h]; exact ha
  bot_le := Nat.zero_le

open TaintLattice in
/-- Concrete anti-laundering: a session that observed taint level `5` denies any
    action requiring cleanliness `≤ 3`, and a later clean observation (`0`, a fresh
    compartment) does NOT lift the denial. Distinct values — a genuine implication.
    (`TaintLattice.le` is an abstract projection so `decide` cannot see its
    `Decidable`; the `(3:Nat) ≤ 5` proof is defeq to `le 3 5` for the Nat instance.) -/
example : denied (3 : Nat) (ceilingFold 0 ([1, 5, 2] ++ [0])) :=
  tainted_obs_denies 0 ([1, 5, 2] ++ [0]) 3 5 (by decide) (by decide : (3 : Nat) ≤ 5)

#print axioms TaintLattice.tainted_obs_denies
#print axioms TaintLattice.denied_persists
#print axioms TaintLattice.no_launder_without_reset
#print axioms TaintLattice.reset_re_enables
#print axioms TaintLattice.obs_le_ceilingFold
#print axioms TaintLattice.le_ceilingFold_init

end SessionCeiling
