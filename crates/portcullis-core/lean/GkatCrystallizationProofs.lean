import GkatModelProofs

/-!
# The positive route, reduced to one statement: a common *syntax-generated* collapse

The blueprint here is Grabmayer and Fokkink's proof that Milner's system is complete for
regular expressions modulo bisimilarity, and its 1-free predecessor, which the skip-free
GKAT completeness result already rides on.  Two of its ingredients transfer directly, and
the third names the gap.

1. **Layering gives uniqueness.**  Charts satisfying the *layered loop existence and
   elimination* (LLEE) property admit unique solutions — loops are never mutually nested,
   so elimination proceeds layer by layer with only a one-state fixpoint rule.  The GKAT
   counterpart is already here: `certifiedThompson_solution_unique`, whose proof is
   exactly a syntax-layered induction closing with `W3`.

2. **The obstruction is the same obstruction.**  LLEE is *not closed under bisimulation
   collapse*.  That is precisely why `ThompsonInternalCompleteBA` resists every direct
   attack: the collapse of a Thompson automaton is no longer a Thompson automaton, so its
   equations are no longer known to be solvable.

3. **Their fix is crystallization** — do not fully collapse; perform a layering-preserving
   *near*-collapse, landing back inside the well-behaved class.

Transposed to GKAT, (3) says the common quotient should itself be **syntax-generated** —
the Thompson automaton of a third program.  For such a target the solution is free: it is
the target's own canonical labelling.  So the residual solvability obligation, which is
what made the behavioural quotient circular, disappears entirely.

The collapse is asked for as a *behavioural* quotient (`UniformBehavioralGAutQuotient`),
not a strict `GAutHom`: guard partitions are allowed to differ syntactically, which they
must, since two equivalent programs need not test the same guards in the same order.

Axioms: `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatCrystallization

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson

variable {A T : Type}

/-- **A common syntax-generated collapse.**  Any two uniformly language-equivalent
    programs admit a behavioural quotient of their combined automata onto the Thompson
    automaton of a single third program, identifying the two starts.

    This is the GKAT form of a crystallized common chart: the target is not merely some
    automaton, it is the automaton *of an expression*, which is what keeps its equation
    system solvable inside the finite theory. -/
def CommonSyntacticCollapse (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (h : Exp A T)
      (π : UniformBehavioralGAutQuotient
        (sumGAut (certifiedThompson A T e).aut.toGAut
          (certifiedThompson A T f).aut.toGAut)
        (certifiedThompson A T h).aut.toGAut),
      π.mapState (.inl none) = π.mapState (.inr none)

/-- **The positive route, in one step.**  A common syntax-generated collapse yields full
    finite-axiom completeness.

    No uniqueness axiom appears anywhere: the covering program's own canonical labelling
    solves the target system (`certifiedThompson_toGAut_solves`), the quotient pulls that
    solution back to both source automata, and Thompson start-canonicity — itself UA-free
    — identifies each pullback with its source program. -/
theorem completeness_of_common_syntactic_collapse
    (hcollapse : CommonSyntacticCollapse A T) : FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨h, π, hstart⟩ := hcollapse e f heq
  exact certifiedThompson_uniform_solved_quotient π
    (initializedStandard h (certifiedThompson A T h).standard)
    (certifiedThompson_toGAut_solves h) hstart

/-! ## Why the target is strictly easier than a behavioural quotient

    For an arbitrary behavioural quotient, `UniformBehavioralGAutQuotient.solves_of_descends`
    needs the source labels to *descend* along the quotient — which is completeness again.
    For a syntax-generated target nothing is needed: the labelling exists outright. -/

theorem syntactic_target_is_solvable (h : Exp A T) :
    SolvesBA (certifiedThompson A T h).aut.toGAut
      (initializedStandard h (certifiedThompson A T h).standard) :=
  certifiedThompson_toGAut_solves h

/-! ## Non-vacuity

    The target must not be unsatisfiable, or the reduction says nothing.  The codiagonal
    exhibits a genuine instance: a program's automaton, doubled, collapses onto itself. -/

/-- The codiagonal quotient of a doubled automaton. -/
def codiagonal {S : Type} (aut : GAut S A T) :
    UniformBehavioralGAutQuotient (sumGAut aut aut) aut where
  mapState := Sum.elim id id
  maps_states := by
    intro s hs
    cases s with
    | inl u =>
        change Sum.inl u ∈ aut.states.map Sum.inl ++ aut.states.map Sum.inr at hs
        simpa using hs
    | inr u =>
        change Sum.inr u ∈ aut.states.map Sum.inl ++ aut.states.map Sum.inr at hs
        simpa using hs
  onto_states := by
    intro q hq
    refine ⟨Sum.inl q, ?_, rfl⟩
    change Sum.inl q ∈ aut.states.map Sum.inl ++ aut.states.map Sum.inr
    simpa using hq
  bisim_graph := by
    intro X W s q hrel
    cases s with
    | inl u =>
        cases hrel
        refine ⟨fun _ => rfl, ?_, ?_⟩
        · intro a action target hstep
          rw [autStep_sumGAut_inl] at hstep
          cases hbase : autStep W aut u a with
          | none => rw [hbase] at hstep; exact absurd hstep (by simp)
          | some output =>
              rw [hbase] at hstep
              simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hstep
              obtain ⟨rfl, rfl⟩ := hstep
              exact ⟨output.2, hbase, rfl⟩
        · intro a action target hstep
          have hstep' : autStep W aut u a = some (action, target) := hstep
          exact ⟨Sum.inl target, by rw [autStep_sumGAut_inl, hstep']; rfl, rfl⟩
    | inr u =>
        cases hrel
        refine ⟨fun _ => rfl, ?_, ?_⟩
        · intro a action target hstep
          rw [autStep_sumGAut_inr] at hstep
          cases hbase : autStep W aut u a with
          | none => rw [hbase] at hstep; exact absurd hstep (by simp)
          | some output =>
              rw [hbase] at hstep
              simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hstep
              obtain ⟨rfl, rfl⟩ := hstep
              exact ⟨output.2, hbase, rfl⟩
        · intro a action target hstep
          have hstep' : autStep W aut u a = some (action, target) := hstep
          exact ⟨Sum.inr target, by rw [autStep_sumGAut_inr, hstep']; rfl, rfl⟩

/-- The reflexive instance: a program always collapses onto itself, with the two starts
    identified.  So `CommonSyntacticCollapse` is satisfiable, and the reduction is not
    vacuous — what is open is whether the collapse exists for *distinct* programs. -/
theorem commonSyntacticCollapse_refl (e : Exp A T) :
    ∃ (h : Exp A T)
      (π : UniformBehavioralGAutQuotient
        (sumGAut (certifiedThompson A T e).aut.toGAut
          (certifiedThompson A T e).aut.toGAut)
        (certifiedThompson A T h).aut.toGAut),
      π.mapState (.inl none) = π.mapState (.inr none) :=
  ⟨e, codiagonal _, rfl⟩

/-! ## First brick: pairs where crystallization is unnecessary

    If one program's automaton already covers the other's — a behavioural quotient in one
    direction, matching starts — then no repair is needed: the covering automaton *is* the
    common syntax-generated target.  For that class, completeness holds outright.

    This is the base of the crystallization induction: the cases it does not have to
    repair. -/

/-- Extend a one-sided cover to a quotient of the combined automaton. -/
def sumCover {S₁ S₂ : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    (φ : UniformBehavioralGAutQuotient aut₂ aut₁) :
    UniformBehavioralGAutQuotient (sumGAut aut₁ aut₂) aut₁ where
  mapState := Sum.elim id φ.mapState
  maps_states := by
    intro s hs
    cases s with
    | inl u =>
        change Sum.inl u ∈ aut₁.states.map Sum.inl ++ aut₂.states.map Sum.inr at hs
        simpa using hs
    | inr v =>
        change Sum.inr v ∈ aut₁.states.map Sum.inl ++ aut₂.states.map Sum.inr at hs
        refine φ.maps_states v ?_
        simpa using hs
  onto_states := by
    intro q hq
    refine ⟨Sum.inl q, ?_, rfl⟩
    change Sum.inl q ∈ aut₁.states.map Sum.inl ++ aut₂.states.map Sum.inr
    simpa using hq
  bisim_graph := by
    intro X W s q hrel
    cases s with
    | inl u =>
        cases hrel
        refine ⟨fun _ => rfl, ?_, ?_⟩
        · intro a action target hstep
          rw [autStep_sumGAut_inl] at hstep
          cases hbase : autStep W aut₁ u a with
          | none => rw [hbase] at hstep; exact absurd hstep (by simp)
          | some output =>
              rw [hbase] at hstep
              simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hstep
              obtain ⟨rfl, rfl⟩ := hstep
              exact ⟨output.2, hbase, rfl⟩
        · intro a action target hstep
          have hstep' : autStep W aut₁ u a = some (action, target) := hstep
          exact ⟨Sum.inl target, by rw [autStep_sumGAut_inl, hstep']; rfl, rfl⟩
    | inr v =>
        cases hrel
        obtain ⟨hhlt, hfwd, hbwd⟩ := φ.bisim_graph X W v (φ.mapState v) rfl
        refine ⟨hhlt, ?_, ?_⟩
        · intro a action target hstep
          rw [autStep_sumGAut_inr] at hstep
          cases hbase : autStep W aut₂ v a with
          | none => rw [hbase] at hstep; exact absurd hstep (by simp)
          | some output =>
              rw [hbase] at hstep
              simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hstep
              obtain ⟨rfl, rfl⟩ := hstep
              obtain ⟨target₁, hstep₁, hrel₁⟩ := hfwd a output.1 output.2 hbase
              exact ⟨target₁, hstep₁, hrel₁⟩
        · intro a action target hstep
          obtain ⟨source₂, hstep₂, hrel₂⟩ := hbwd a action target hstep
          refine ⟨Sum.inr source₂, ?_, hrel₂⟩
          rw [autStep_sumGAut_inr, hstep₂]
          rfl

/-- **Completeness, unconditionally, for covered pairs.**  If the Thompson automaton of
    `f` covers that of `e` behaviourally and the starts correspond, then `⊢ e = f`.

    No uniqueness axiom, no completeness hypothesis, and no crystallization: the cover
    already provides a syntax-generated common target, so the solution is `e`'s own
    canonical labelling.  This is the class the crystallization construction never has to
    repair. -/
theorem equivBA_of_cover {e f : Exp A T}
    (φ : UniformBehavioralGAutQuotient
      (certifiedThompson A T f).aut.toGAut (certifiedThompson A T e).aut.toGAut)
    (hstart : φ.mapState none = none) :
    EquivBA e f :=
  certifiedThompson_uniform_solved_quotient (sumCover φ)
    (initializedStandard e (certifiedThompson A T e).standard)
    (certifiedThompson_toGAut_solves e) hstart.symm

/-- Consequently a cover always supplies a common syntax-generated collapse. -/
theorem commonSyntacticCollapse_of_cover {e f : Exp A T}
    (φ : UniformBehavioralGAutQuotient
      (certifiedThompson A T f).aut.toGAut (certifiedThompson A T e).aut.toGAut)
    (hstart : φ.mapState none = none) :
    ∃ (h : Exp A T)
      (π : UniformBehavioralGAutQuotient
        (sumGAut (certifiedThompson A T e).aut.toGAut
          (certifiedThompson A T f).aut.toGAut)
        (certifiedThompson A T h).aut.toGAut),
      π.mapState (.inl none) = π.mapState (.inr none) :=
  ⟨e, sumCover φ, hstart.symm⟩

/-! ## Reversing the arrows: a common syntactic **refinement**

    `CommonSyntacticCollapse` is a *cospan*: both automata quotient onto one syntactic
    target.  That target is badly over-determined.  Thompson automata are deterministic,
    so a functional bisimulation that identifies the two starts is forced to identify
    `δ_e w` with `δ_f w` for every trace `w`, and to be step-closed; the reachable part of
    the target is therefore not a matter of design at all — it is the *joint trace
    quotient*, pinned up to further collapse.  When that pinned automaton is not itself
    syntax-generated, no `h` can exist.

    That happens.  Take (over one primitive test `b`, one action `p`)

      e = p ; while b do p          f = (if b then 1 else p) ; while b do p

    Both automata are fully reachable with three states, the two programs are uniformly
    language-equivalent, and their joint trace quotient has two states: a start that steps
    `p` at *every* atom, and a loop state halting on `¬b`.  It is already
    bisimulation-collapsed, so any target must be isomorphic to it on the nose — one core
    state, i.e. one action occurrence in `h`.  But a self-looping single core state can
    only arise as the body state of a `while g do _` with `g ≡ b`, and *every* transition
    entering a loop body from outside carries that loop's guard conjoined
    (`loopInitialized.initTrans` is `.and guard _`, and `seq`/`ite`/`wh` only conjoin
    further).  So no Thompson start can step into it at a `¬b` atom.  No such `h` exists,
    and `CommonSyntacticCollapse` is false as stated.

    It is *only* the collapse that fails: `⊢ e = f` is derivable, and completeness is
    untouched — the cospan was sufficient, never necessary.

    All of that is a **theorem**: `GkatCollapseRefutation.not_commonSyntacticCollapse`
    proves `¬ CommonSyntacticCollapse Unit Unit`, with the pair's provable equality
    (`fProg_equivBA_eProg`) alongside it so the two claims cannot drift apart.  The loop
    guard does its work in `no_selfloop_at_halting_entry`, a five-case induction on the
    Thompson constructors.

    It is corroborated independently in `experiments/gkat-crystallization/`, which mirrors
    this file's Thompson construction executably: closing the combinators to a fixpoint
    enumerates *every* one-action Thompson automaton over two tests (4,767 of them,
    saturating after four rounds) and the required target is not among them.

    The repair is to reverse the arrows.  A **span** — one program whose automaton covers
    *both* — needs no new machinery whatsoever: `equivBA_of_cover` is already the whole
    proof, applied twice.  And it asks Thompson automata to do the thing they are good at
    (duplicate along a guard split) rather than the thing they resist (collapse).  For the
    pair above the span exists immediately: `h = if b then e else f`. -/

/-- **A common syntax-generated refinement.**  Any two uniformly language-equivalent
    programs are both covered by the Thompson automaton of a single third program, with
    starts corresponding. -/
def CommonSyntacticRefinement (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (h : Exp A T)
      (φ : UniformBehavioralGAutQuotient
        (certifiedThompson A T h).aut.toGAut (certifiedThompson A T e).aut.toGAut)
      (ψ : UniformBehavioralGAutQuotient
        (certifiedThompson A T h).aut.toGAut (certifiedThompson A T f).aut.toGAut),
      φ.mapState none = none ∧ ψ.mapState none = none

/-- **The positive route, span form.**  A common syntax-generated refinement yields full
    finite-axiom completeness — by two applications of `equivBA_of_cover` and transitivity.

    No uniqueness axiom and no crystallization: each leg is already a covered pair. -/
theorem completeness_of_common_syntactic_refinement
    (hspan : CommonSyntacticRefinement A T) : FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨h, φ, ψ, hφ, hψ⟩ := hspan e f heq
  exact EquivBA.trans (equivBA_of_cover φ hφ)
    (EquivBA.symm (equivBA_of_cover ψ hψ))

/-- The identity cover, so the span target is non-vacuous. -/
def idQuotient {S : Type} (aut : GAut S A T) :
    UniformBehavioralGAutQuotient aut aut where
  mapState := id
  maps_states := fun _ hs => hs
  onto_states := fun q hq => ⟨q, hq, rfl⟩
  bisim_graph := by
    intro X W s q hrel
    cases hrel
    exact ⟨fun _ => rfl,
      fun _ _ target hstep => ⟨target, hstep, rfl⟩,
      fun _ _ target hstep => ⟨target, hstep, rfl⟩⟩

/-- A program is its own common refinement, so `CommonSyntacticRefinement` is satisfiable;
    what is open is whether the span exists for *distinct* programs. -/
theorem commonSyntacticRefinement_refl (e : Exp A T) :
    ∃ (h : Exp A T)
      (φ : UniformBehavioralGAutQuotient
        (certifiedThompson A T h).aut.toGAut (certifiedThompson A T e).aut.toGAut)
      (ψ : UniformBehavioralGAutQuotient
        (certifiedThompson A T h).aut.toGAut (certifiedThompson A T e).aut.toGAut),
      φ.mapState none = none ∧ ψ.mapState none = none :=
  ⟨e, idQuotient _, idQuotient _, rfl, rfl⟩

/-- A cover is a span with a degenerate leg, so the span target subsumes the first
    brick: everything `equivBA_of_cover` already settles is settled by it too. -/
theorem commonSyntacticRefinement_of_cover {e f : Exp A T}
    (φ : UniformBehavioralGAutQuotient
      (certifiedThompson A T f).aut.toGAut (certifiedThompson A T e).aut.toGAut)
    (hstart : φ.mapState none = none) :
    ∃ (h : Exp A T)
      (φ' : UniformBehavioralGAutQuotient
        (certifiedThompson A T h).aut.toGAut (certifiedThompson A T e).aut.toGAut)
      (ψ : UniformBehavioralGAutQuotient
        (certifiedThompson A T h).aut.toGAut (certifiedThompson A T f).aut.toGAut),
      φ'.mapState none = none ∧ ψ.mapState none = none :=
  ⟨f, φ, idQuotient _, hstart, rfl⟩

#print axioms completeness_of_common_syntactic_collapse
#print axioms syntactic_target_is_solvable
#print axioms completeness_of_common_syntactic_refinement
#print axioms idQuotient
#print axioms commonSyntacticRefinement_refl
#print axioms commonSyntacticRefinement_of_cover
#print axioms codiagonal
#print axioms commonSyntacticCollapse_refl
#print axioms sumCover
#print axioms equivBA_of_cover
#print axioms commonSyntacticCollapse_of_cover

end GkatCrystallization
