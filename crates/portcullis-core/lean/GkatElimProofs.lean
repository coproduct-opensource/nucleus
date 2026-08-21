import GkatThreeLoopProofs

/-! # General state elimination: expression-labeled automata

    The vehicle for the FiniteAxiomsCompleteBA generalization.  `GAut`
    arms carry single actions; Gaussian elimination substitutes CLOSED
    EXPRESSIONS through same-rank cycles, so the intermediate objects
    are automata whose arms carry arbitrary productive expressions.
    The terminal form is `WNAutE` (self-loop + descending exits), whose
    solution `wnSolE` is already certified; this file grounds the
    intermediate form and its roles interface. -/

namespace GkatElim

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatTrim
open GkatThreeLoop

variable {A T : Type}

/-- An expression-labeled automaton: `GAut` with expression arm
    bodies.  The carrier of Gaussian elimination. -/
structure ELabAut (S A T : Type) where
  states : List S
  hlt : S → BExp T
  trans : S → List (BExp T × Exp A T × S)

/-- The dispatch fold with expression bodies. -/
def foldTLE {S : Type} (sol : S → Exp A T) (h : BExp T)
    (L : List (BExp T × Exp A T × S)) : Exp A T :=
  L.foldr (fun t acc => Exp.ite t.1 (.seq t.2.1 (sol t.2.2)) acc)
    (.test h)

/-- The equation of a state. -/
def eqRHSEL {S : Type} (aut : ELabAut S A T) (sol : S → Exp A T)
    (s : S) : Exp A T :=
  foldTLE sol (aut.hlt s) (aut.trans s)

/-- Roles for expression-labeled automata, mirroring `StateRole`. -/
inductive ERole {S : Type} (aut : ELabAut S A T) (sol : S → Exp A T)
    (s : S) : Prop where
  | fold (h : sol s = eqRHSEL aut sol s)
  | equivFold (h : EquivBA (sol s) (eqRHSEL aut sol s))
  | salomaaE (G : BExp T) (BODY rest : Exp A T)
      (hsol : sol s = .seq (.wh G BODY) rest)
      (hrhs : EquivBA (eqRHSEL aut sol s)
        (.ite G (.seq BODY (sol s)) rest))

/-- The embedding of a flat automaton. -/
def embedG {S : Type} (aut : GAut S A T) : ELabAut S A T where
  states := aut.states
  hlt := aut.hlt
  trans := fun s => (aut.trans s).map (fun e => (e.1, .act e.2.1, e.2.2))

/-- The embedded dispatch is the flat dispatch. -/
theorem foldTLE_embed {S : Type} (sol : S → Exp A T) (h : BExp T)
    (L : List (BExp T × A × S)) :
    foldTLE sol h (L.map (fun e => (e.1, .act e.2.1, e.2.2)))
      = foldTL sol h L := by
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol hd.2.2))
          (foldTLE sol h (rest.map (fun e => (e.1, .act e.2.1, e.2.2))))
        = Exp.ite hd.1 (.seq (.act hd.2.1) (sol hd.2.2))
          (foldTL sol h rest)
      rw [ih]

/-- Embedded equations are flat equations. -/
theorem eqRHSEL_embed {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (s : S) :
    eqRHSEL (embedG aut) sol s = eqRHS aut sol s := by
  show foldTLE sol (aut.hlt s)
      ((aut.trans s).map (fun e => (e.1, .act e.2.1, e.2.2)))
    = eqRHS aut sol s
  rw [foldTLE_embed, eqRHS_foldTL]

/-- **ROLES TRANSFER**: roles of the embedded automaton are flat
    roles — the general elimination concludes at `GAut` level. -/
theorem stateRole_of_eRole {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (s : S)
    (h : ERole (embedG aut) sol s) : StateRole aut sol s := by
  cases h with
  | fold h =>
      refine StateRole.fold ?_
      rw [h, eqRHSEL_embed]
  | equivFold h =>
      refine StateRole.equivFold ?_
      rw [eqRHSEL_embed] at h
      exact h
  | salomaaE G BODY rest hsol hrhs =>
      refine StateRole.salomaaE G BODY rest hsol ?_
      rw [eqRHSEL_embed] at hrhs
      exact hrhs

#print axioms foldTLE_embed
#print axioms eqRHSEL_embed
#print axioms stateRole_of_eRole

/-! ## The substitution homomorphism

    Gaussian elimination substitutes closed forms for call markers.
    Provable equivalence is closed under action substitution, provided
    every substituted image is strictly productive (semantically) — the
    `w3`/`w3_ba` side conditions transport through `baTest` and a
    `bval`-level computation of `E` under substitution. -/

/-- Action substitution: replace each action by an expression; guards
    untouched. -/
def substA {A' : Type} (σ : A → Exp A' T) : Exp A T → Exp A' T
  | .act a => σ a
  | .test b => .test b
  | .seq e f => .seq (substA σ e) (substA σ f)
  | .ite b e f => .ite b (substA σ e) (substA σ f)
  | .wh b e => .wh b (substA σ e)

/-- `E` under substitution: with productive images, the empty-word
    guard is semantically unchanged. -/
theorem bval_E_substA {A' : Type} {σ : A → Exp A' T}
    (hσ : ∀ (a : A) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (σ a)) x = false) :
    ∀ (e : Exp A T) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (substA σ e)) x = bval W (E e) x := by
  intro e
  induction e with
  | act a =>
      intro X W x
      show bval W (E (σ a)) x = false
      exact hσ a X W x
  | test b => intro X W x; rfl
  | seq e f ihe ihf =>
      intro X W x
      show (bval W (E (substA σ e)) x && bval W (E (substA σ f)) x)
        = (bval W (E e) x && bval W (E f) x)
      rw [ihe X W x, ihf X W x]
  | ite b e f ihe ihf =>
      intro X W x
      show ((bval W b x && bval W (E (substA σ e)) x)
          || (!(bval W b x) && bval W (E (substA σ f)) x))
        = ((bval W b x && bval W (E e) x)
          || (!(bval W b x) && bval W (E f) x))
      rw [ihe X W x, ihf X W x]
  | wh b e ih => intro X W x; rfl

/-- Base provable equivalence maps into `EquivBA` under productive
    substitution (the `w3` side condition re-derives via `baTest`). -/
theorem equiv_substA {A' : Type} {σ : A → Exp A' T}
    (hσ : ∀ (a : A) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (σ a)) x = false)
    {e f : Exp A T} (h : Equiv e f) :
    EquivBA (substA σ e) (substA σ f) := by
  induction h with
  | refl e => exact EquivBA.base (Equiv.refl _)
  | symm _ ih => exact EquivBA.symm ih
  | trans _ _ ih₁ ih₂ => exact EquivBA.trans ih₁ ih₂
  | seq_c _ _ ih₁ ih₂ => exact EquivBA.seq_c ih₁ ih₂
  | ite_c _ _ ih₁ ih₂ => exact EquivBA.ite_c ih₁ ih₂
  | wh_c _ ih => exact EquivBA.wh_c ih
  | u1 b e => exact EquivBA.base (Equiv.u1 b _)
  | u2 b e f => exact EquivBA.base (Equiv.u2 b _ _)
  | u3 b c e f g => exact EquivBA.base (Equiv.u3 b c _ _ _)
  | u4 b e f => exact EquivBA.base (Equiv.u4 b _ _)
  | u5 b e f g => exact EquivBA.base (Equiv.u5 b _ _ _)
  | s1 e f g => exact EquivBA.base (Equiv.s1 _ _ _)
  | s2 e => exact EquivBA.base (Equiv.s2 _)
  | s3 e => exact EquivBA.base (Equiv.s3 _)
  | s4 e => exact EquivBA.base (Equiv.s4 _)
  | s5 e => exact EquivBA.base (Equiv.s5 _)
  | w1 b e => exact EquivBA.base (Equiv.w1 b _)
  | w2 b c e => exact EquivBA.base (Equiv.w2 b c _)
  | w3 hE hg ihE ihg =>
      refine EquivBA.w3_ba ?_ ihg
      refine EquivBA.trans
        (EquivBA.baTest (fun X W x => bval_E_substA hσ _ X W x)) ?_
      exact ihE

/-- **THE SUBSTITUTION HOMOMORPHISM**: `EquivBA` is closed under
    productive action substitution. -/
theorem equivBA_substA {A' : Type} {σ : A → Exp A' T}
    (hσ : ∀ (a : A) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (σ a)) x = false)
    {e f : Exp A T} (h : EquivBA e f) :
    EquivBA (substA σ e) (substA σ f) := by
  induction h with
  | base h => exact equiv_substA hσ h
  | symm _ ih => exact EquivBA.symm ih
  | trans _ _ ih₁ ih₂ => exact EquivBA.trans ih₁ ih₂
  | seq_c _ _ ih₁ ih₂ => exact EquivBA.seq_c ih₁ ih₂
  | ite_c _ _ ih₁ ih₂ => exact EquivBA.ite_c ih₁ ih₂
  | wh_c _ ih => exact EquivBA.wh_c ih
  | baTest h => exact EquivBA.baTest h
  | ite_guard h => exact EquivBA.ite_guard h
  | wh_guard h => exact EquivBA.wh_guard h
  | s6 b c => exact EquivBA.s6 b c
  | w3_ba hE hg ihE ihg =>
      refine EquivBA.w3_ba ?_ ihg
      refine EquivBA.trans
        (EquivBA.baTest (fun X W x => bval_E_substA hσ _ X W x)) ?_
      exact ihE

#print axioms bval_E_substA
#print axioms equiv_substA
#print axioms equivBA_substA

end GkatElim
