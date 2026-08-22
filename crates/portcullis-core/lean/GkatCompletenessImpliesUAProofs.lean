import GkatCompletenessReductionProofs
import GkatHardFrontierProofs

/-!
# Completeness *entails* UA, so "completeness with UA eliminated" is not a softer target

It is tempting to read "prove completeness without UA" as a weaker goal than "derive UA",
on the grounds that a completeness proof might route around uniqueness.  It cannot.

`completeness_implies_cycle_uniqueness` derives the **full indexed uniqueness axiom** —
for an arbitrary index type, not just two states — from `FiniteAxiomsCompleteBA` alone.
The argument is short because the semantic half is already available: a productive guarded
cycle has a unique *language* solution (`GkatHardFrontier.indexed_cycle_semantic_unique`,
by well-founded induction on string length), so any two equational solutions are
language-equivalent, and completeness converts that into a derivation.

Consequently:

* proving completeness in the finite theory **is** proving UA in the finite theory;
* refuting UA (a model validating U/S/W where UAₙ fails) refutes completeness.

There is no third option in which completeness holds and uniqueness is bypassed.  This is
what makes the residue identified in `GkatDecidedPullbackProofs` load-bearing rather than
cosmetic, and it is why the remaining work is a genuine open problem rather than an
engineering gap.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatCompletenessImpliesUA

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatHardFrontier
open GkatNullLanguage

variable {A T : Type}

/-! ## An equational cycle solution is a semantic one -/

/-- Productivity, transported from the syntactic side condition of `W3` to the semantic
    side condition of the string induction. -/
theorem den_productive_of_E_zero {e : Exp A T}
    (hprod : EquivBA (.test (E e) : Exp A T) (.test .zero))
    {X : Type} (W : T → X → Bool) (a : X) : ¬ den W e (a, []) := by
  intro hden
  have hE : bval W (E e) a = true := (den_empty_E W e a).mp hden
  have hzero := (sound_BA W hprod (a, [])).mp ⟨hE, rfl⟩
  exact Bool.noConfusion hzero.1

/-- A family of expressions satisfying the guarded cycle equations denotes a family of
    languages satisfying the semantic cycle. -/
theorem cycleSolves_of_equations {I : Type} {next : I → I}
    {b : I → BExp T} {e f g : I → Exp A T}
    (hg : ∀ i, EquivBA (g i) (.ite (b i) (.seq (e i) (g (next i))) (f i)))
    {X : Type} (W : T → X → Bool) :
    CycleSolves W next b e f (fun i => den W (g i)) := by
  intro i gs
  refine Iff.trans (sound_BA W (hg i) gs) ?_
  simp only [den_ite, den_seq, CycleStep]

/-! ## The uniqueness axiom, derived from completeness -/

/-- **Completeness implies UA, at every arity.**  Two equational solutions of the same
    productive guarded cycle are provably equal, given only finite-axiom completeness.

    The index type `I` is arbitrary: this is not merely `UA₂`, it is the whole scheme. -/
theorem completeness_implies_cycle_uniqueness
    (hcomplete : FiniteAxiomsCompleteBA A T)
    {I : Type} (next : I → I) (b : I → BExp T) (e f : I → Exp A T)
    (hprod : ∀ i, EquivBA (.test (E (e i)) : Exp A T) (.test .zero))
    (g g' : I → Exp A T)
    (hg : ∀ i, EquivBA (g i) (.ite (b i) (.seq (e i) (g (next i))) (f i)))
    (hg' : ∀ i, EquivBA (g' i) (.ite (b i) (.seq (e i) (g' (next i))) (f i))) :
    ∀ i, EquivBA (g i) (g' i) := by
  intro i
  refine hcomplete _ _ ?_
  intro X W gs
  exact indexed_cycle_semantic_unique W next b e f
    (fun j a => den_productive_of_E_zero (hprod j) W a)
    (cycleSolves_of_equations hg W) (cycleSolves_of_equations hg' W) i gs

/-- The crossed two-state instance, spelled out: `UA₂` itself follows from completeness.
    Compare `GkatUAIndep.ua2_of_pullback`, which needs an extra guard-pullback witness —
    completeness needs none, because it already implies the whole scheme. -/
theorem completeness_implies_ua2
    (hcomplete : FiniteAxiomsCompleteBA A T)
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hprod0 : EquivBA (.test (E e0) : Exp A T) (.test .zero))
    (hprod1 : EquivBA (.test (E e1) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') f1)) :
    EquivBA g0 g0' := by
  refine completeness_implies_cycle_uniqueness hcomplete
    (I := Bool) not (fun i => bif i then b0 else b1)
    (fun i => bif i then e0 else e1) (fun i => bif i then f0 else f1)
    (fun i => by cases i <;> simpa using ‹_›)
    (fun i => bif i then g0 else g1) (fun i => bif i then g0' else g1')
    (fun i => by cases i <;> simpa using ‹_›)
    (fun i => by cases i <;> simpa using ‹_›) true

/-- **The contrapositive, which is the actionable form.**  Any model validating the finite
    axioms in which some productive guarded cycle has two provably-distinct solutions
    refutes finite-axiom completeness.  This is the shape a negative resolution must
    take. -/
theorem no_completeness_of_cycle_ambiguity
    {I : Type} (next : I → I) (b : I → BExp T) (e f : I → Exp A T)
    (hprod : ∀ i, EquivBA (.test (E (e i)) : Exp A T) (.test .zero))
    (g g' : I → Exp A T)
    (hg : ∀ i, EquivBA (g i) (.ite (b i) (.seq (e i) (g (next i))) (f i)))
    (hg' : ∀ i, EquivBA (g' i) (.ite (b i) (.seq (e i) (g' (next i))) (f i)))
    {i : I} (hne : ¬ EquivBA (g i) (g' i)) :
    ¬ FiniteAxiomsCompleteBA A T :=
  fun hcomplete =>
    hne (completeness_implies_cycle_uniqueness hcomplete next b e f hprod g g' hg hg' i)

#print axioms den_productive_of_E_zero
#print axioms cycleSolves_of_equations
#print axioms completeness_implies_cycle_uniqueness
#print axioms completeness_implies_ua2
#print axioms no_completeness_of_cycle_ambiguity

end GkatCompletenessImpliesUA
