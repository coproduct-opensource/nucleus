import GkatCrystallizationProofs

/-!
# Bricks 1–2 of the crystallization construction: the syntactic layering

Grabmayer and Fokkink's uniqueness argument runs on charts carrying a **layering**: a
grading under which loops are never *mutually* nested, so state elimination can proceed
one layer at a time using only a one-state fixpoint rule.  Crystallization is then the
procedure that repairs a bisimulation collapse back into that class.

To transpose it, the layering has to exist here first.  For Thompson automata it comes
from the syntax rather than being searched for: a state is an occurrence of an action, and
its grade is the number of `while`s enclosing that occurrence.  `thompsonRank` computes
exactly that, by the same structural recursion as `certifiedThompson`.

Both clauses of LLEE are established here, and neither is a guess — each is read off the
Thompson constructors:

* **loops are never mutually nested** — the component-closure theorems, graded by
  `thompsonRank`: a syntactic component is entered at one place and never re-entered from
  outside, so components can be ordered;
* **no successful termination mid-loop** — the exit-guardedness theorems: control leaves a
  component only under that component's own halt test, which is literally the guard the
  constructors write (`left.core.hlt s ∧ _` for sequencing,
  `body.core.hlt s ∧ guard ∧ _` for loop back edges).

What remains is brick 3, the crystallization procedure itself; see the file footer.

Axioms: `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatLayering

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson

variable {A T : Type}

/-! ## The syntactic layering -/

/-- Loop-nesting rank of a Thompson state: the number of `while`s enclosing the action
    occurrence that the state represents. -/
def thompsonRank (A T : Type) : (program : Exp A T) →
    (certifiedThompson A T program).State → Nat
  | .test _ => fun s => nomatch s
  | .act _ => fun _ => 0
  | .ite _ p q => fun s => match s with
      | .inl i => thompsonRank A T p i
      | .inr i => thompsonRank A T q i
  | .seq p q => fun s => match s with
      | .inl i => thompsonRank A T p i
      | .inr i => thompsonRank A T q i
  | .wh _ p => fun s => thompsonRank A T p s + 1

@[simp] theorem thompsonRank_act (a : A) (s : (certifiedThompson A T (.act a)).State) :
    thompsonRank A T (.act a) s = 0 := rfl

@[simp] theorem thompsonRank_wh (g : BExp T) (p : Exp A T)
    (s : (certifiedThompson A T p).State) :
    thompsonRank A T (.wh g p) s = thompsonRank A T p s + 1 := rfl

@[simp] theorem thompsonRank_ite_inl (g : BExp T) (p q : Exp A T)
    (i : (certifiedThompson A T p).State) :
    thompsonRank A T (.ite g p q) (Sum.inl i) = thompsonRank A T p i := rfl

@[simp] theorem thompsonRank_ite_inr (g : BExp T) (p q : Exp A T)
    (i : (certifiedThompson A T q).State) :
    thompsonRank A T (.ite g p q) (Sum.inr i) = thompsonRank A T q i := rfl

@[simp] theorem thompsonRank_seq_inl (p q : Exp A T)
    (i : (certifiedThompson A T p).State) :
    thompsonRank A T (.seq p q) (Sum.inl i) = thompsonRank A T p i := rfl

@[simp] theorem thompsonRank_seq_inr (p q : Exp A T)
    (i : (certifiedThompson A T q).State) :
    thompsonRank A T (.seq p q) (Sum.inr i) = thompsonRank A T q i := rfl

/-- Every state inside a loop is graded strictly above the loop's ambient level.  This is
    the "descending into a loop is a descent" half of a layering, in its simplest form. -/
theorem thompsonRank_wh_pos (g : BExp T) (p : Exp A T)
    (s : (certifiedThompson A T (.wh g p)).State) :
    0 < thompsonRank A T (.wh g p) s :=
  Nat.succ_pos _

/-! ## Component closure

    The formal content of "loops are never mutually nested": a program's components are
    entered at one place and never re-entered from outside, so they can be ordered. -/

/-- In a sequential composition, the right component never returns to the left.  Control
    passes forward exactly once. -/
theorem seq_inr_closed (p q : Exp A T)
    (s : (certifiedThompson A T q).State)
    (tr : BExp T × A × (certifiedThompson A T (.seq p q)).State)
    (htr : tr ∈ (certifiedThompson A T (.seq p q)).aut.core.trans (Sum.inr s)) :
    ∃ u, tr.2.2 = Sum.inr u := by
  have hred : (certifiedThompson A T (.seq p q)).aut.core.trans (Sum.inr s) =
      ((certifiedThompson A T q).aut.core.trans s).map
        (fun t => (t.1, t.2.1, Sum.inr t.2.2)) := rfl
  rw [hred] at htr
  obtain ⟨orig, _, rfl⟩ := List.mem_map.mp htr
  exact ⟨orig.2.2, rfl⟩

/-- In a conditional, the two branches never communicate: the left component is closed. -/
theorem ite_inl_closed (g : BExp T) (p q : Exp A T)
    (s : (certifiedThompson A T p).State)
    (tr : BExp T × A × (certifiedThompson A T (.ite g p q)).State)
    (htr : tr ∈ (certifiedThompson A T (.ite g p q)).aut.core.trans (Sum.inl s)) :
    ∃ u, tr.2.2 = Sum.inl u := by
  have hred : (certifiedThompson A T (.ite g p q)).aut.core.trans (Sum.inl s) =
      ((certifiedThompson A T p).aut.core.trans s).map
        (fun t => (t.1, t.2.1, Sum.inl t.2.2)) := rfl
  rw [hred] at htr
  obtain ⟨orig, _, rfl⟩ := List.mem_map.mp htr
  exact ⟨orig.2.2, rfl⟩

/-- …and so is the right. -/
theorem ite_inr_closed (g : BExp T) (p q : Exp A T)
    (s : (certifiedThompson A T q).State)
    (tr : BExp T × A × (certifiedThompson A T (.ite g p q)).State)
    (htr : tr ∈ (certifiedThompson A T (.ite g p q)).aut.core.trans (Sum.inr s)) :
    ∃ u, tr.2.2 = Sum.inr u := by
  have hred : (certifiedThompson A T (.ite g p q)).aut.core.trans (Sum.inr s) =
      ((certifiedThompson A T q).aut.core.trans s).map
        (fun t => (t.1, t.2.1, Sum.inr t.2.2)) := rfl
  rw [hred] at htr
  obtain ⟨orig, _, rfl⟩ := List.mem_map.mp htr
  exact ⟨orig.2.2, rfl⟩

/-- Consequently the rank is constant along the right component of a sequence: control
    inside `q` stays inside `q`, at `q`'s own grading. -/
theorem seq_inr_rank_stable (p q : Exp A T)
    (s : (certifiedThompson A T q).State)
    (tr : BExp T × A × (certifiedThompson A T (.seq p q)).State)
    (htr : tr ∈ (certifiedThompson A T (.seq p q)).aut.core.trans (Sum.inr s)) :
    ∃ u, tr.2.2 = Sum.inr u ∧
      thompsonRank A T (.seq p q) tr.2.2 = thompsonRank A T q u := by
  obtain ⟨u, hu⟩ := seq_inr_closed p q s tr htr
  exact ⟨u, hu, by rw [hu]; rfl⟩

/-! ## Brick 2: exit-guardedness, read off the constructions

    LLEE's second clause is "no successful termination can occur mid-loop".  Its GKAT form
    does not have to be invented — it is visible in the two constructions that create
    cross-component edges, and it is the same condition in both:

    **control leaves a component only under that component's own halt test.**

    In `seqInitialized`, the edges from a left state into the right component carry guard
    `left.core.hlt s ∧ _`.  In `loopInitialized`, the back edges carry
    `body.core.hlt s ∧ guard ∧ _`.  Neither is a design choice; both are literally the
    guards the constructors write down. -/

/-- Leaving the left component of a sequence happens only under the left component's halt
    test.  Control does not escape a component until that component has finished. -/
theorem seqInitialized_exit_guarded {S₁ S₂ : Type}
    (left : InitializedGAut S₁ A T) (right : InitializedGAut S₂ A T)
    (s : S₁) (tr : BExp T × A × Sum S₁ S₂)
    (htr : tr ∈ (seqInitialized left right).core.trans (Sum.inl s))
    (u : S₂) (hu : tr.2.2 = Sum.inr u) :
    ∃ g', tr.1 = BExp.and (left.core.hlt s) g' := by
  simp only [seqInitialized, seqGSystem, List.mem_append, List.mem_map] at htr
  rcases htr with ⟨orig, _, rfl⟩ | ⟨orig, _, rfl⟩
  · exact absurd hu (by simp)
  · exact ⟨orig.1, rfl⟩

/-- A guard of the shape `c ∧ _` implies `c`. -/
private theorem and_left_implies (c g : BExp T) :
    GuardImplies (BExp.and c g) c := by
  intro X W x hx
  change (bval W c x && bval W g x) = true at hx
  cases hh : bval W c x with
  | true => rfl
  | false => rw [hh] at hx; exact absurd hx (by simp)

/-- The usable form: an exit guard implies the component has halted. -/
theorem seqInitialized_exit_implies_halt {S₁ S₂ : Type}
    (left : InitializedGAut S₁ A T) (right : InitializedGAut S₂ A T)
    (s : S₁) (tr : BExp T × A × Sum S₁ S₂)
    (htr : tr ∈ (seqInitialized left right).core.trans (Sum.inl s))
    (u : S₂) (hu : tr.2.2 = Sum.inr u) :
    GuardImplies tr.1 (left.core.hlt s) := by
  obtain ⟨g', hg'⟩ := seqInitialized_exit_guarded left right s tr htr u hu
  rw [hg']
  exact and_left_implies _ _

/-- Re-entering a loop happens only under the body's halt test *and* the loop guard: the
    back edge fires exactly when the body has finished an iteration and the loop continues.
    This is the "no successful termination mid-loop" clause. -/
theorem loopInitialized_back_guarded {S : Type} (guard : BExp T)
    (body : InitializedGAut S A T) (s : S) (tr : BExp T × A × S)
    (htr : tr ∈ (loopInitialized guard body).core.trans s)
    (hnew : tr ∉ body.core.trans s) :
    ∃ g', tr.1 = BExp.and (body.core.hlt s) (BExp.and guard g') := by
  simp only [loopInitialized, List.mem_append, List.mem_map] at htr
  rcases htr with hold | ⟨orig, _, rfl⟩
  · exact absurd hold hnew
  · exact ⟨orig.1, rfl⟩

/-- The usable form for loops: a back edge implies the body has halted. -/
theorem loopInitialized_back_implies_halt {S : Type} (guard : BExp T)
    (body : InitializedGAut S A T) (s : S) (tr : BExp T × A × S)
    (htr : tr ∈ (loopInitialized guard body).core.trans s)
    (hnew : tr ∉ body.core.trans s) :
    GuardImplies tr.1 (body.core.hlt s) := by
  obtain ⟨g', hg'⟩ := loopInitialized_back_guarded guard body s tr htr hnew
  rw [hg']
  exact and_left_implies _ _

/-- …and that the loop guard still holds, so the loop really is continuing rather than
    exiting.  Together with `loopInitialized_back_implies_halt` this pins the back edge to
    exactly the loop-head position. -/
theorem loopInitialized_back_implies_guard {S : Type} (guard : BExp T)
    (body : InitializedGAut S A T) (s : S) (tr : BExp T × A × S)
    (htr : tr ∈ (loopInitialized guard body).core.trans s)
    (hnew : tr ∉ body.core.trans s) :
    GuardImplies tr.1 guard := by
  obtain ⟨g', hg'⟩ := loopInitialized_back_guarded guard body s tr htr hnew
  intro X W x hx
  rw [hg'] at hx
  change (bval W (body.core.hlt s) x &&
    (bval W guard x && bval W g' x)) = true at hx
  cases hg : bval W guard x with
  | true => rfl
  | false =>
      rw [hg] at hx
      cases bval W (body.core.hlt s) x <;> exact absurd hx (by simp)

/-- The loop's own halt test is the body's halt test conjoined with loop exit, so a state
    inside a loop can terminate only where the loop itself terminates. -/
theorem loopInitialized_hlt {S : Type} (guard : BExp T)
    (body : InitializedGAut S A T) (s : S) :
    (loopInitialized guard body).core.hlt s
      = BExp.and (body.core.hlt s) (BExp.not guard) := rfl

/-! ## What brick 2 gives, and what brick 3 needs

    Both clauses of LLEE now have a GKAT form, and both are theorems rather than
    hypotheses:

    * **loops are never mutually nested** — `seq_inr_closed`, `ite_inl_closed`,
      `ite_inr_closed`, graded by `thompsonRank`;
    * **no successful termination mid-loop** — `loopInitialized_hlt` together with
      `loopInitialized_back_implies_halt` and `loopInitialized_back_implies_guard`: a state
      inside a loop halts only where the loop exits, and re-enters only where the body has
      halted and the guard still holds.

    Brick 3 is the crystallization procedure itself: given a bisimulation between two
    Thompson automata, produce a *third program* whose automaton covers both, preserving
    this layering.  `GkatCrystallization.equivBA_of_cover` is the interface it has to hit.

    ### Where brick 3 concentrates its difficulty

    Synthesis from a layered automaton would need the layering stated for an *arbitrary*
    automaton, not just for the Thompson constructors — the collapse is not Thompson, which
    is the whole reason a repair is needed.  Attempting that abstraction turns up a
    specific obstacle, worth recording:

    **the loop head is a pseudostate, not a state.**  In `loopInitialized` the back edges
    from `s` do not target one re-entry state; they target the whole of
    `body.initTrans`, with `body`'s initial guards.  The single-entry structure that makes
    layer-by-layer elimination work therefore lives in the *initial dynamics* of an
    `InitializedGAut`, which a bisimulation collapse does not preserve — collapse works on
    states, and the loop head is not among them.

    So the abstraction cannot simply be "a `GAut` plus a rank": it has to retain the
    pseudostate structure, which is precisely what `InitializedGAut` provides and precisely
    what collapsing destroys.  That is the same difficulty Grabmayer's crystallization
    resolves for process graphs with empty-step transitions, and it is why the repair is
    the substance of that proof rather than a corollary of it. -/

#print axioms thompsonRank_wh_pos
#print axioms seq_inr_closed
#print axioms ite_inl_closed
#print axioms ite_inr_closed
#print axioms seq_inr_rank_stable
#print axioms seqInitialized_exit_implies_halt
#print axioms loopInitialized_back_implies_halt
#print axioms loopInitialized_back_implies_guard
#print axioms loopInitialized_hlt

end GkatLayering
