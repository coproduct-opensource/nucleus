import GkatQuotientProofs

/-!
# The period law

`star_bijection` makes an `InitCover` a covering map of graphs.  Covering maps of graphs have
a classical numerical invariant: the **period** of a strongly connected component, the gcd of
its cycle lengths.  A covering sends a cycle of length `n` to a closed walk of length `n`, so
the period downstairs divides every cycle length upstairs — `period(tgt) | period(src)`.

This file proves it, and it is the first genuinely group-theoretic constraint in the
development: covers of a circle correspond to subgroups `nℤ ≤ ℤ`, and this is the statement
that a cover cannot shorten the cycle it sits over.

## Why closed walks rather than cycles

The gcd of all *closed walk* lengths at a state equals the gcd of all *cycle* lengths, so
nothing is lost, and everything stays inside core Lean: no `Finset`, no gcd over an infinite
set, no strongly-connected-component theory.  A "period" here is any `d` dividing every
closed walk length, which is exactly the usable form — the greatest such `d` is the period,
but no proof below needs it to be greatest.

## What it does and does not give

It bounds how *big* a cover must be.  It can never forbid one, because the cyclic cover
multiplies the period by any `k` (`cyclicCover`, and `cyclicCover4` for degree 4), so
divisibility can always be arranged by enlarging the candidate.  An impossibility obstruction
has to live in the halt labelling, which the period does not see.

Where it does bite is as a **filter**: `no_cover_of_period` rules out a cover outright from a
divisibility mismatch, without exhibiting any map.  The search uses exactly this, and it is
cheaper than the cover test it replaces.
-/

namespace GkatPeriod

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatQuotient

variable {A T : Type}
variable {S Q : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut Q A T}

/-! ## Walks -/

/-- A run of a fixed guarded string from one state to another.  The list is the walk, so its
    length is the walk's length; a *closed* walk is one whose endpoints coincide. -/
inductive Walk {S X : Type} (aut : GAut S A T) (W : T → X → Bool) :
    S → X → List (A × X) → S → Prop where
  | nil (s : S) (x : X) : Walk aut W s x [] s
  | cons {s : S} {x : X} {q : A} {x' : X} {w : List (A × X)} {s' t : S} :
      autStep W aut s x = some (q, s') → Walk aut W s' x' w t →
      Walk aut W s x ((q, x') :: w) t

/-! ## A cover is a graph morphism on `toGAut` -/

/-- The cover commutes with stepping, at the pseudostate and at core states alike.  This is
    `initStep_eq` and `coreStep_eq` restated one level up, where the state type is
    `Option S` and the induced map is `Option.map`. -/
theorem cover_step (φ : InitCover src tgt) {X : Type} (W : T → X → Bool) (x : X)
    (u : Option S) :
    (autStep W src.toGAut u x).map (fun o => (o.1, o.2.map φ.map))
      = autStep W tgt.toGAut (u.map φ.map) x := by
  cases u with
  | none =>
      show (autStep W src.toGAut none x).map (fun o => (o.1, o.2.map φ.map))
        = autStep W tgt.toGAut none x
      rw [autStep_init, autStep_init, ← φ.initStep_eq X W x]
      cases firstMatch W x src.initTrans <;> rfl
  | some s =>
      show (autStep W src.toGAut (some s) x).map (fun o => (o.1, o.2.map φ.map))
        = autStep W tgt.toGAut (some (φ.map s)) x
      rw [autStep_core, autStep_core, ← φ.coreStep_eq s X W x]
      cases firstMatch W x (src.core.trans s) <;> rfl

/-- **A cover maps walks to walks of the same length.**  Induction on the walk, with
    `cover_step` at each step.  The length is literally preserved because the guarded string
    is carried along unchanged. -/
theorem cover_walk (φ : InitCover src tgt) {X : Type} {W : T → X → Bool}
    {u v : Option S} {x : X} {w : List (A × X)}
    (h : Walk src.toGAut W u x w v) :
    Walk tgt.toGAut W (u.map φ.map) x w (v.map φ.map) := by
  induction h with
  | nil s x => exact Walk.nil _ _
  | @cons u x q x' w u' v hstep _ ih =>
      refine Walk.cons ?_ ih
      have hc := cover_step φ W x u
      rw [hstep] at hc
      simpa using hc.symm

/-! ## The law -/

/-- `d` is *a* period at `s`: it divides the length of every closed walk there.  The period
    proper is the greatest such `d`, but nothing below needs it to be greatest — which is
    what keeps this free of gcd-over-an-infinite-set machinery. -/
def PeriodOf {S : Type} (aut : InitializedGAut S A T) (s : Option S) (d : Nat) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X) (w : List (A × X)),
    Walk aut.toGAut W s x w s → d ∣ w.length

/-- **The period law.**  Every period below `φ.map s` is a period above `s`: a closed walk
    upstairs pushes down to a closed walk of the *same* length, so its length is divisible by
    whatever divides the lengths downstairs.

    Read as gcds this is `period(tgt) | period(src)` — a cover cannot shorten the cycle it
    sits over. -/
theorem period_divides (φ : InitCover src tgt) (s : Option S) {d : Nat}
    (hd : PeriodOf tgt (s.map φ.map) d) : PeriodOf src s d :=
  fun X W x w h => hd X W x w (cover_walk φ h)

/-- **The obstruction, and the search filter.**  If every state of the target has period
    divisible by `d`, but some closed walk of the source has a length `d` does not divide,
    then no cover exists at all — established without exhibiting or refuting any map. -/
theorem no_cover_of_period (d : Nat) (s : Option S)
    (htgt : ∀ q : Option Q, PeriodOf tgt q d) (hsrc : ¬ PeriodOf src s d) :
    ¬ Nonempty (InitCover src tgt) :=
  fun ⟨φ⟩ => hsrc (period_divides φ s (htgt (s.map φ.map)))

/-! ## Non-vacuity -/

/-- Everything has period 1, so the statement is satisfiable. -/
theorem periodOf_one {S : Type} (aut : InitializedGAut S A T) (s : Option S) :
    PeriodOf aut s 1 :=
  fun _ _ _ _ _ => Nat.one_dvd _

/-- Periods compose along covers, since covers do. -/
theorem period_divides_comp {R : Type} {mid : InitializedGAut R A T}
    (φ : InitCover src mid) (ψ : InitCover mid tgt) (s : Option S) {d : Nat}
    (hd : PeriodOf tgt ((s.map φ.map).map ψ.map) d) : PeriodOf src s d :=
  period_divides φ s (period_divides ψ (s.map φ.map) hd)

#print axioms cover_step
#print axioms cover_walk
#print axioms period_divides
#print axioms no_cover_of_period

end GkatPeriod
