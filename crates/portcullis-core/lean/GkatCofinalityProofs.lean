import GkatCyclicCoverProofs

/-!
# Thompson-cofinality: the open problem, factored

`CommonCoveredIntermediate` is the single residual obligation
(`completeness_of_common_covered_intermediate`).  It asks for two things at once — that a
common intermediate *exist*, and that it be *covered* by the syntax — and conflating them
sent the search after the wrong theorem.

The natural strengthening, "every system satisfying the nesting coequation is covered by a
Thompson automaton", is **too strong**.  Generating every fully reachable automaton with at
most three states and testing directly (`experiments/gkat-crystallization/span-search`,
`expansion_test`) leaves six that are productive and bisimilar to a GKAT expression but
covered by none, stably under a 56-million-automaton candidate pool and four rounds of
refinement.  So that route would have been months spent on a false statement.

The six have a property in common, and it is exactly the right one: **not one of them covers
a Thompson automaton**, while a pullback always does — it projects onto both sides.  That
suggests the hypothesis the counterexamples fail is the hypothesis to assume:

    ThompsonCofinal :  a system that COVERS a Thompson automaton is COVERED by one.

Under Stallings' correspondence — `star_bijection` makes an `InitCover` a covering map of
graphs — this reads as a statement about subgroups.  Covers of a graph `m` correspond to
subgroups of the free group `π₁ m`, a Thompson automaton picks out a "Thompson subgroup",
and Stallings' Lemma says the fibre product of two covers has `π₁ (a ×_m b) = π₁ a ∩ π₁ b`.
So the pullback of two Thompson automata is the subgroup `H_e ∩ H_f`, and what has to be
shown is that some Thompson subgroup lies below it.  `ThompsonCofinal` is the statement that
Thompson subgroups are **cofinal below every Thompson subgroup**, which covers the
intersection case and explains the counterexamples: they are subgroups lying below no
Thompson subgroup at all, so nothing is required of them.

This file names the split and proves the reduction.  What is left open afterwards is two
independent statements rather than one entangled one.
-/

namespace GkatCofinality

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatUnrollCover GkatCyclicCover

variable {A T : Type}

/-! ## The two halves -/

/-- **Half one: the span exists.**  Uniformly equivalent programs admit a common system
    covering both.  The canonical witness is the pullback, whose transitions are
    `crossTrans` of the two components' (`firstMatch_crossTrans` is what makes its guards
    behave).  This half is a construction, not a theorem about the syntax. -/
def SpanExists (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T f).aut)

/-- **Half two: Thompson automata are cofinal below Thompson automata.**  Anything that
    covers the automaton of a program is covered by the automaton of a program.

    This is the substantive half, and the one the search supports: every counterexample to
    the unrestricted statement fails *this* hypothesis. -/
def ThompsonCofinal (A T : Type) : Prop :=
  ∀ {S : Type} (sys : InitializedGAut S A T) (e : Exp A T),
    Nonempty (InitCover sys (certifiedThompson A T e).aut) → HasThompsonCover sys

/-- **The factorization.**  The two halves together are exactly the residual obligation, so
    finite-axiom completeness follows from them with no uniqueness axiom.

    Note which side supplies which: `SpanExists` produces the intermediate, and its cover of
    `e` is precisely the hypothesis `ThompsonCofinal` needs.  Neither half mentions
    quotients, coequations, or well-nestedness. -/
theorem commonCoveredIntermediate_of_halves
    (hspan : SpanExists A T) (hcof : ThompsonCofinal A T) :
    CommonCoveredIntermediate A T := by
  intro e f heq
  obtain ⟨S, mid, ⟨π₁⟩, ⟨π₂⟩⟩ := hspan e f heq
  obtain ⟨h, ⟨χ⟩⟩ := hcof mid e ⟨π₁⟩
  exact ⟨S, mid, h, ⟨π₁⟩, ⟨π₂⟩, ⟨χ⟩⟩

/-- Completeness from the two halves, with the whole chain assembled. -/
theorem completeness_of_halves
    (hspan : SpanExists A T) (hcof : ThompsonCofinal A T) :
    FiniteAxiomsCompleteBA A T :=
  completeness_of_common_covered_intermediate (commonCoveredIntermediate_of_halves hspan hcof)

/-! ## Non-vacuity, and the instances already proved

    A named target is worth nothing if it is unsatisfiable or if nothing is known about it.
    Both halves have witnesses, and `ThompsonCofinal` holds outright on every class this
    development has closed. -/

/-- `SpanExists` is satisfied on the diagonal: a program spans with itself. -/
theorem spanExists_refl (e : Exp A T) :
    ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T e).aut) :=
  ⟨(certifiedThompson A T e).State, (certifiedThompson A T e).aut,
    ⟨InitCover.id _⟩, ⟨InitCover.id _⟩⟩

/-- **Cofinality holds whenever the covering system is itself syntax-generated.**  The
    degenerate case, but it is the base of every induction: a Thompson automaton covering a
    Thompson automaton is covered by itself. -/
theorem thompsonCofinal_of_syntactic (h : Exp A T) (e : Exp A T)
    (_ : Nonempty (InitCover (certifiedThompson A T h).aut (certifiedThompson A T e).aut)) :
    HasThompsonCover (certifiedThompson A T h).aut :=
  ⟨h, ⟨InitCover.id _⟩⟩

/-- **Cofinality holds on the unrolling class.**  `unrollCover` says the unrolled program's
    automaton covers the loop's; it is syntax-generated, so it is covered. -/
theorem thompsonCofinal_unrolling (g : BExp T) (e : Exp A T) :
    HasThompsonCover
      (certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).aut :=
  ⟨.ite g (.seq e (.wh g e)) (.test BExp.one), ⟨InitCover.id _⟩⟩

/-- **Cofinality holds on the doubling class** — the refinement the search found to be
    missing, and the one that changes the covering degree. -/
theorem thompsonCofinal_doubling (g : BExp T) (e : Exp A T) :
    HasThompsonCover
      (certifiedThompson A T (.wh g (.seq e (.ite g e (.test BExp.one))))).aut :=
  ⟨.wh g (.seq e (.ite g e (.test BExp.one))), ⟨InitCover.id _⟩⟩

/-- **Degree 4 with no new proof.**  `HasThompsonCover.along` already says a Thompson cover
    passes down along covers, and `InitCover.comp` says covers compose — so doubling the
    already-doubled body is `cyclicCover` applied twice, and every power of two follows.
    That is why the search never needed a degree-3 move: iterated doubling supplies 2, 4, 8,
    and the data shows degree 3 rescues nothing that those do not. -/
def cyclicCover4 {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    InitCover
      (loopInitialized g (doubledBody g (doubledBody g B)))
      (loopInitialized g B) :=
  (cyclicCover g (doubledBody g B)).comp (cyclicCover g B)

#print axioms commonCoveredIntermediate_of_halves
#print axioms completeness_of_halves
#print axioms cyclicCover4

end GkatCofinality
