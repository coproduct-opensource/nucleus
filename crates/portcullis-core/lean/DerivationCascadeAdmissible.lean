import ExposureLoopFixpointProofs

/-!
# User-authored cascades over the derivation lattice inherit the ratchet

Makes `ExposureLoop.loop_admissible` **load-bearing on a user object**: a
user-authored cascade — a `Vec<CascadeStep>` (the Rust surface, Brick B) whose
every step is a monotone endomap on the derivation lattice — inherits the
anti-laundering ratchet at its least fixpoint, with NO per-cascade proof.

## The lattice is the real one (a diamond, not a chain)

`Deriv` below is a faithful model of the production `DerivationClass`
(nucleus-ifc-kernel/src/ifc_lattice.rs:212): the diamond
`Deterministic(⊥) < {AIDerived, HumanPromoted} < Mixed < OpaqueExternal(⊤)`,
with `AIDerived` and `HumanPromoted` INCOMPARABLE (`is_diamond`). `join` here
transcribes `DerivationClass::join` (ifc_lattice.rs:248) arm-for-arm; it is the
same pure mirror `DerivationNoninterferenceExtracted.joinP` uses over the
Aeneas-extracted `djoin` (bridged there by `djoin_ok`).

**ANCHOR obligation (Brick B):** the pure `Deriv.join`/`Deriv.le` here are bound
to production `crate::DerivationClass::{join, leq}` by the exhaustive N×N parity
test in the Rust cascade module — the same discipline that bound the newtype to
the lattice in #2299 (`every_tag_binds_to_its_named_lattice_level`). Without that
parity test this model is unanchored; with it, the ratchet proven here governs
the shipped lattice.

## Why `loop_admissible` and not the existing join-fold theorem

`DerivationNoninterferenceExtracted.derivation_sink_never_admitted` already proves
the ratchet for a fold of *joins* (observations). The step vocabulary here also
includes `sealAbove` — a monotone CLOSURE that is NOT a join with a constant — so
the general `loop_admissible` (any monotone endomap) is what licenses it. That is
the extension point a user cascade needs: new monotone step kinds inherit the
ratchet without re-proving it.

Mathlib-free; `#print axioms` audited at the end.
-/

namespace DerivationCascade

open ExposureLoop

/-- Faithful model of production `DerivationClass` (ifc_lattice.rs:212). -/
inductive Deriv where
  | Deterministic | AIDerived | HumanPromoted | Mixed | OpaqueExternal
  deriving DecidableEq, Repr

/-- LUB — transcribes `DerivationClass::join` (ifc_lattice.rs:248): `Deterministic`
    is identity, `OpaqueExternal` absorbs, distinct non-⊥/⊤ pairs → `Mixed`. -/
def Deriv.join : Deriv → Deriv → Deriv
  | .Deterministic, x => x
  | x, .Deterministic => x
  | .OpaqueExternal, _ => .OpaqueExternal
  | _, .OpaqueExternal => .OpaqueExternal
  | .AIDerived, .AIDerived => .AIDerived
  | .HumanPromoted, .HumanPromoted => .HumanPromoted
  | .Mixed, .Mixed => .Mixed
  | _, _ => .Mixed

/-- The join-induced order (`DerivationClass::leq`, ifc_lattice.rs:293). Reducible
    so `decide` sees the underlying `DecidableEq`. -/
abbrev Deriv.le (a b : Deriv) : Prop := Deriv.join a b = b

/-- Longest-chain height from ⊥ — the strict-ascent rank that makes Knaster–Tarski
    terminate on the finite lattice (the incomparable pair shares rank 1). -/
def Deriv.rank : Deriv → Nat
  | .Deterministic => 0
  | .AIDerived => 1
  | .HumanPromoted => 1
  | .Mixed => 2
  | .OpaqueExternal => 3

/-- The real derivation diamond is a `RankedLattice`, so `loop_admissible` fires
    at it. Every field is a finite fact discharged by `decide` over the 5 elements. -/
instance : RankedLattice Deriv where
  le := Deriv.le
  join := Deriv.join
  bot := .Deterministic
  le_refl := by intro a; cases a <;> decide
  le_trans := by intro a b c; cases a <;> cases b <;> cases c <;> decide
  le_antisymm := by intro a b; cases a <;> cases b <;> decide
  le_join_left := by intro a b; cases a <;> cases b <;> decide
  le_join_right := by intro a b; cases a <;> cases b <;> decide
  join_le := by intro a b c; cases a <;> cases b <;> cases c <;> decide
  bot_le := by intro a; cases a <;> decide
  rank := Deriv.rank
  rank_mono := by intro a b; cases a <;> cases b <;> decide
  rank_strict := by intro a b; cases a <;> cases b <;> decide
  height := 3
  rank_le_height := by intro a; cases a <;> decide

/-- Bridge the abstract `RankedLattice.le` projection to the concrete decidable
    `Deriv.le`, so `decide` can discharge monotonicity goals stated via `Mono`
    (which is phrased over `RankedLattice.le`). -/
instance (a b : Deriv) : Decidable (RankedLattice.le a b) :=
  inferInstanceAs (Decidable (Deriv.le a b))

/-- **`loop_admissible` at the real derivation diamond.** Any monotone endomap on
    the shipped derivation lattice inherits the ratchet. -/
theorem cascade_admissible (f : Deriv → Deriv) (hf : Mono f) : Ratchets f :=
  loop_admissible f hf

-- ── The user step vocabulary — each a monotone endomap ──────────────────────

/-- RAISE — observe/join the ceiling up to at least `c` (the observation step). -/
def raiseTo (c : Deriv) : Deriv → Deriv := fun x => Deriv.join x c

theorem raiseTo_mono (c : Deriv) : Mono (raiseTo c) := by
  intro a b; cases c <;> cases a <;> cases b <;> decide

/-- SEAL — a monotone tripwire: once exposure reaches `t`, seal to fully-opaque
    (`OpaqueExternal`); otherwise pass through. This is a monotone CLOSURE, not a
    join with a constant — the step `loop_admissible` licenses that a join-fold
    theorem cannot. -/
def sealAbove (t : Deriv) : Deriv → Deriv :=
  fun x => if Deriv.le t x then .OpaqueExternal else x

theorem sealAbove_mono (t : Deriv) : Mono (sealAbove t) := by
  intro a b; cases t <;> cases a <;> cases b <;> decide

-- ── A cascade is a list of steps; monotonicity composes ─────────────────────

theorem id_mono : Mono (id : Deriv → Deriv) := fun _ _ h => h

theorem comp_mono {f g : Deriv → Deriv} (hf : Mono f) (hg : Mono g) : Mono (f ∘ g) :=
  fun _ _ h => hf _ _ (hg _ _ h)

/-- Run a user cascade: compose its steps left-to-right from the identity. -/
def runCascade (steps : List (Deriv → Deriv)) : Deriv → Deriv :=
  steps.foldl (fun acc f => f ∘ acc) id

theorem foldl_comp_mono :
    ∀ (steps : List (Deriv → Deriv)) (acc : Deriv → Deriv),
      Mono acc → (∀ f ∈ steps, Mono f) →
      Mono (steps.foldl (fun acc f => f ∘ acc) acc) := by
  intro steps
  induction steps with
  | nil => intro acc hacc _; exact hacc
  | cons f rest ih =>
      intro acc hacc hall
      exact ih (f ∘ acc)
        (comp_mono (hall f (List.mem_cons.mpr (Or.inl rfl))) hacc)
        (fun g hg => hall g (List.mem_cons.mpr (Or.inr hg)))

theorem runCascade_mono (steps : List (Deriv → Deriv)) (h : ∀ f ∈ steps, Mono f) :
    Mono (runCascade steps) :=
  foldl_comp_mono steps id id_mono h

/-- **THE binding theorem for the Rust cascade surface.** A user-authored cascade
    whose every step is monotone inherits the ratchet — fixed point, unrollings
    stay below it, and denial persists (no ordering launders taint). One theorem,
    every cascade, no per-cascade proof. -/
theorem user_cascade_ratchets (steps : List (Deriv → Deriv)) (h : ∀ f ∈ steps, Mono f) :
    Ratchets (runCascade steps) :=
  cascade_admissible _ (runCascade_mono steps h)

-- ── Non-vacuity on the genuine diamond ──────────────────────────────────────

/-- Genuine DIAMOND, not a chain: the two mid elements are incomparable, so the
    ratchet is not secretly a total-order argument. -/
theorem is_diamond :
    ¬ Deriv.le .AIDerived .HumanPromoted ∧ ¬ Deriv.le .HumanPromoted .AIDerived := by
  decide

/-- The fixpoint of "raise to AIDerived" is `AIDerived` (≠ ⊥) — distinct values. -/
example : lfp (raiseTo Deriv.AIDerived) = Deriv.AIDerived := by
  unfold raiseTo; exact lfp_join_const Deriv.AIDerived

/-- A concrete user cascade — raise to AIDerived, then seal above Mixed — ratchets
    with no bespoke proof. Uses BOTH step kinds; `sealAbove` is the monotone step
    that only `loop_admissible` covers. This is the "no silent cleansing" guarantee
    inherited by a user-authored object. -/
example : Ratchets (runCascade [raiseTo Deriv.AIDerived, sealAbove Deriv.Mixed]) :=
  user_cascade_ratchets _ (by
    intro f hf
    rcases List.mem_cons.mp hf with rfl | hf
    · exact raiseTo_mono _
    rcases List.mem_cons.mp hf with rfl | hf
    · exact sealAbove_mono _
    nomatch hf)

-- ── Axiom audit ─────────────────────────────────────────────────────────────

#print axioms cascade_admissible
#print axioms user_cascade_ratchets
#print axioms is_diamond

end DerivationCascade
