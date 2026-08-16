import GkatCompletenessImpliesUAProofs

/-!
# The counter-model interface

`no_completeness_of_cycle_ambiguity` says a productive guarded cycle with two
provably-distinct solutions refutes finite-axiom completeness.  That theorem is not
usable as stated: its hypothesis is `¬ EquivBA (g i) (g' i)`, and the only way to
establish a *negative* fact about a derivability relation is to exhibit an invariant that
all the rules preserve — a model.

This file supplies that interface.  A `GkatModel` is an algebra with one field per finite
axiom; `GkatModel.sound` proves every `EquivBA`-derivation is preserved; and
`no_completeness_of_model_separation` composes the two, so refuting completeness reduces
to filling in a structure and pointing at two elements.

## What a separating model must look like

The obligations are not arbitrary, and two of them are already known to conflict with the
obvious candidates:

* the model must validate `w3` — uniqueness of **one-state** productive guarded fixpoints;
* it must *fail* uniqueness for a **two-state** productive cycle.

Any model built from guarded languages validates uniqueness at *every* arity
(`GkatHardFrontier.indexed_cycle_semantic_unique`), so no language-based model can
separate.  A separating model must therefore carry information that is not a function of
the language — which is exactly what finite-axiom incompleteness would mean.  The
interface makes that requirement explicit rather than leaving it as commentary.

Axioms: `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatModel

open GkatSyntax GkatGS GkatFaithful GkatKleene
open GkatCompletenessImpliesUA

variable {A T : Type}

/-- Semantic Boolean equality of guards, over the free Boolean algebra on `T`. -/
def GuardEq (b c : BExp T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = bval W c x

/-- An algebra with one field per finite GKAT axiom, over a Boolean algebra of tests.
    Productivity is carried as an abstract predicate; the coherence condition tying it to
    the syntactic halting test `E` is a hypothesis of `sound`, since it must mention the
    interpretation. -/
structure Model (A T : Type) where
  Carrier : Type
  act : A → Carrier
  test : BExp T → Carrier
  seq : Carrier → Carrier → Carrier
  ite : BExp T → Carrier → Carrier → Carrier
  wh : BExp T → Carrier → Carrier
  Productive : Carrier → Prop
  -- Boolean-algebra layer
  test_congr : ∀ {b c : BExp T}, GuardEq b c → test b = test c
  ite_guard : ∀ {b c : BExp T} (x y : Carrier), GuardEq b c → ite b x y = ite c x y
  wh_guard : ∀ {b c : BExp T} (x : Carrier), GuardEq b c → wh b x = wh c x
  s6 : ∀ b c : BExp T, seq (test b) (test c) = test (.and b c)
  -- guarded union
  u1 : ∀ (b : BExp T) (x : Carrier), ite b x x = x
  u2 : ∀ (b : BExp T) (x y : Carrier), ite b x y = ite (.not b) y x
  u3 : ∀ (b c : BExp T) (x y z : Carrier),
    ite c (ite b x y) z = ite (.and b c) x (ite c y z)
  u4 : ∀ (b : BExp T) (x y : Carrier), ite b x y = ite b (seq (test b) x) y
  u5 : ∀ (b : BExp T) (x y z : Carrier),
    ite b (seq x z) (seq y z) = seq (ite b x y) z
  -- sequencing
  s1 : ∀ x y z : Carrier, seq (seq x y) z = seq x (seq y z)
  s2 : ∀ x : Carrier, seq (test .zero) x = test .zero
  s3 : ∀ x : Carrier, seq x (test .zero) = test .zero
  s4 : ∀ x : Carrier, seq (test .one) x = x
  s5 : ∀ x : Carrier, seq x (test .one) = x
  -- iteration
  w1 : ∀ (b : BExp T) (x : Carrier), wh b x = ite b (seq x (wh b x)) (test .one)
  w2 : ∀ (b c : BExp T) (x : Carrier),
    wh b (ite c x (test .one)) = wh b (seq (test c) x)
  w3 : ∀ {b : BExp T} {x y z : Carrier},
    Productive x → z = ite b (seq x z) y → z = seq (wh b x) y

/-- Interpretation of the syntax in a model. -/
def Model.interp (Mo : Model A T) : Exp A T → Mo.Carrier
  | .act a => Mo.act a
  | .test b => Mo.test b
  | .seq e f => Mo.seq (Mo.interp e) (Mo.interp f)
  | .ite b e f => Mo.ite b (Mo.interp e) (Mo.interp f)
  | .wh b e => Mo.wh b (Mo.interp e)

/-- The productivity side condition of `W3`, read off the guarded-string model.  A
    derivation of `E e ≡ 0` really does force `E e` to be Boolean-false everywhere, so
    the abstract `Productive` predicate only ever has to cover genuinely productive
    bodies. -/
theorem E_false_of_equiv {e : Exp A T}
    (h : Equiv (.test (E e) : Exp A T) (.test .zero)) :
    ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e) x = false := by
  intro X W x
  cases hv : bval W (E e) x with
  | false => rfl
  | true =>
      have hzero := (sound W h (x, [])).mp ⟨hv, rfl⟩
      exact absurd hzero.1 (by simp [bval])

theorem E_false_of_equivBA {e : Exp A T}
    (h : EquivBA (.test (E e) : Exp A T) (.test .zero)) :
    ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e) x = false := by
  intro X W x
  cases hv : bval W (E e) x with
  | false => rfl
  | true =>
      have hzero := (sound_BA W h (x, [])).mp ⟨hv, rfl⟩
      exact absurd hzero.1 (by simp [bval])

/-- The productivity coherence a model must satisfy for `sound` to apply. -/
def Model.ProductiveCoherent (Mo : Model A T) : Prop :=
  ∀ e : Exp A T,
    (∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e) x = false) →
    Mo.Productive (Mo.interp e)

/-- **Soundness for the loop-free-plus-`W` core.** -/
theorem Model.sound_Equiv (Mo : Model A T) (hcoh : Mo.ProductiveCoherent)
    {e f : Exp A T} (h : Equiv e f) : Mo.interp e = Mo.interp f := by
  induction h with
  | refl _ => rfl
  | symm _ ih => exact ih.symm
  | trans _ _ ih₁ ih₂ => exact ih₁.trans ih₂
  | seq_c _ _ ih₁ ih₂ => show Mo.seq _ _ = Mo.seq _ _; rw [ih₁, ih₂]
  | ite_c _ _ ih₁ ih₂ => show Mo.ite _ _ _ = Mo.ite _ _ _; rw [ih₁, ih₂]
  | wh_c _ ih => show Mo.wh _ _ = Mo.wh _ _; rw [ih]
  | u1 b e => exact Mo.u1 b (Mo.interp e)
  | u2 b e f => exact Mo.u2 b (Mo.interp e) (Mo.interp f)
  | u3 b c e f g => exact Mo.u3 b c (Mo.interp e) (Mo.interp f) (Mo.interp g)
  | u4 b e f => exact Mo.u4 b (Mo.interp e) (Mo.interp f)
  | u5 b e f g => exact Mo.u5 b (Mo.interp e) (Mo.interp f) (Mo.interp g)
  | s1 e f g => exact Mo.s1 (Mo.interp e) (Mo.interp f) (Mo.interp g)
  | s2 e => exact Mo.s2 (Mo.interp e)
  | s3 e => exact Mo.s3 (Mo.interp e)
  | s4 e => exact Mo.s4 (Mo.interp e)
  | s5 e => exact Mo.s5 (Mo.interp e)
  | w1 b e => exact Mo.w1 b (Mo.interp e)
  | w2 b c e => exact Mo.w2 b c (Mo.interp e)
  | @w3 b e f g hprod _ _ ihstep =>
      exact Mo.w3 (hcoh e (E_false_of_equiv hprod)) ihstep

/-- **Soundness for the full Boolean-aware theory.**  Every `EquivBA`-derivation is
    preserved by every model, so a model that separates two expressions witnesses their
    non-derivability. -/
theorem Model.sound (Mo : Model A T) (hcoh : Mo.ProductiveCoherent)
    {e f : Exp A T} (h : EquivBA e f) : Mo.interp e = Mo.interp f := by
  induction h with
  | base hb => exact Mo.sound_Equiv hcoh hb
  | symm _ ih => exact ih.symm
  | trans _ _ ih₁ ih₂ => exact ih₁.trans ih₂
  | seq_c _ _ ih₁ ih₂ => show Mo.seq _ _ = Mo.seq _ _; rw [ih₁, ih₂]
  | ite_c _ _ ih₁ ih₂ => show Mo.ite _ _ _ = Mo.ite _ _ _; rw [ih₁, ih₂]
  | wh_c _ ih => show Mo.wh _ _ = Mo.wh _ _; rw [ih]
  | baTest hguard => exact Mo.test_congr (fun X W x => hguard X W x)
  | ite_guard hguard => exact Mo.ite_guard _ _ (fun X W x => hguard X W x)
  | wh_guard hguard => exact Mo.wh_guard _ (fun X W x => hguard X W x)
  | s6 b c => exact Mo.s6 b c
  | @w3_ba b e f g hprod _ _ ihstep =>
      exact Mo.w3 (hcoh e (E_false_of_equivBA hprod)) ihstep

/-- Separation in a model is non-derivability. -/
theorem Model.not_equivBA_of_separates (Mo : Model A T)
    (hcoh : Mo.ProductiveCoherent) {e f : Exp A T}
    (hsep : Mo.interp e ≠ Mo.interp f) : ¬ EquivBA e f :=
  fun h => hsep (Mo.sound hcoh h)

/-! ## The refutation interface -/

/-- **What a negative resolution has to produce.**  A model, its productivity coherence,
    two solutions of one productive guarded cycle, and a single point where the model
    tells them apart.  Everything else is discharged here.

    Note the two obligations pull against each other: `Model.w3` demands uniqueness of
    one-state productive fixpoints, while `hsep` demands *non*-uniqueness for this cycle.
    A model built from guarded languages cannot do both. -/
theorem no_completeness_of_model_separation
    (Mo : Model A T) (hcoh : Mo.ProductiveCoherent)
    {I : Type} (next : I → I) (b : I → BExp T) (e f : I → Exp A T)
    (hprod : ∀ i, EquivBA (.test (E (e i)) : Exp A T) (.test .zero))
    (g g' : I → Exp A T)
    (hg : ∀ i, EquivBA (g i) (.ite (b i) (.seq (e i) (g (next i))) (f i)))
    (hg' : ∀ i, EquivBA (g' i) (.ite (b i) (.seq (e i) (g' (next i))) (f i)))
    {i : I} (hsep : Mo.interp (g i) ≠ Mo.interp (g' i)) :
    ¬ FiniteAxiomsCompleteBA A T :=
  no_completeness_of_cycle_ambiguity next b e f hprod g g' hg hg'
    (Mo.not_equivBA_of_separates hcoh hsep)

/-! ## The interface is inhabited

    The one-point model satisfies every obligation, which shows the axiom fields are not
    contradictory.  It separates nothing, of course — a separating instance is precisely
    the open problem. -/

/-- The trivial model. -/
def trivialModel (A T : Type) : Model A T where
  Carrier := Unit
  act _ := ()
  test _ := ()
  seq _ _ := ()
  ite _ _ _ := ()
  wh _ _ := ()
  Productive _ := True
  test_congr _ := rfl
  ite_guard _ _ _ := rfl
  wh_guard _ _ := rfl
  s6 _ _ := rfl
  u1 _ _ := rfl
  u2 _ _ _ := rfl
  u3 _ _ _ _ _ := rfl
  u4 _ _ _ := rfl
  u5 _ _ _ _ := rfl
  s1 _ _ _ := rfl
  s2 _ := rfl
  s3 _ := rfl
  s4 _ := rfl
  s5 _ := rfl
  w1 _ _ := rfl
  w2 _ _ _ := rfl
  w3 _ _ := rfl

theorem trivialModel_coherent : (trivialModel A T).ProductiveCoherent :=
  fun _ _ => True.intro

/-- Sanity: the trivial model does collapse everything, so the interface cannot be
    satisfied vacuously by pointing at it. -/
theorem trivialModel_separates_nothing (e f : Exp A T) :
    (trivialModel A T).interp e = (trivialModel A T).interp f := rfl

#print axioms Model.sound_Equiv
#print axioms Model.sound
#print axioms Model.not_equivBA_of_separates
#print axioms no_completeness_of_model_separation
#print axioms trivialModel_coherent

end GkatModel
