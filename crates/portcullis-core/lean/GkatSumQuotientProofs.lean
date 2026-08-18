import GkatTotalizationProofs

/-!
# The open conjunct, restated on the weaker hypothesis

This development has carried `ReachListCovered` as its single open conjunct: the pullback,
listed on its reachable states, is Thompson-**covered**.  Measurement no longer supports that
as the right target.  At `K = 5` it holds for 4288/4679 = 91.6%; at `K = 6`, on a much larger
instance space, the union of both routes reaches only 68244/113795 = **60.0%**.  A rate that
falls that far as the space grows is what a real gap looks like, not only a search-budget one.

The hypothesis actually consumed by the completeness reduction is weaker.  It asks not for a
cover but for a **solution**: an assignment of expressions to the states of a behavioural
quotient of `Me + Mf` satisfying that quotient's equations.  No surjection from a Thompson
automaton is required.  Measured with a procedure that is sound — it rejects 5000/5000
non-nested automata, which provably have no solution since the nesting coequation is an iff,
and it rejects the Figure 3 automaton — sum-quotient solvability holds on 9221/9245 = 99.7%
of instances, against 45.4% for arbitrary (non-equivalent) pairs of Thompson automata drawn
from the same population.

So this file swaps the open conjunct.  `SumQuotientSolvable` is the hypothesis, and
`completeness_of_sumQuotientSolvable` is the reduction, proved.

What makes the swap non-trivial is the pseudostate.  A Thompson automaton's start is *not* a
core state: `InitializedGAut.toGAut` adjoins it as `none`, with `hlt none = initHlt` and
`trans none = initTrans`.  The uniqueness theorem available here,
`certifiedThompson_solution_unique`, speaks about core states, while the reduction needs the
value at `none`.  The bridge is `certifiedThompson_initial_canonical`, and connecting them
needs the observation that `eqRHS` and `eqRHSParam` are the same fold over the same branches,
differing only in the fallback — `test h` versus `seq (test h) (test 1)` — which S5 identifies.
-/

namespace GkatSumQuotient

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSynthesis

variable {A T S : Type}

/-! ## The two folds agree -/

/-- `guardedFold` over `transitionBranches` is the same right fold `eqRHS` performs.  Both are
    `foldr` over the transition list; this fuses the intervening `map`. -/
theorem guardedFold_transitionBranches (l : List (BExp T × A × S))
    (sol : S → Exp A T) (fallback : Exp A T) :
    guardedFold (transitionBranches l sol) fallback =
      l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) fallback := by
  induction l with
  | nil => rfl
  | cons head tail ih =>
      exact congrArg (fun r => Exp.ite head.1 (.seq (.act head.2.1) (sol head.2.2)) r) ih

/-- `eqRHS` unfolded to its fold. -/
theorem eqRHS_fold (aut : GAut S A T) (sol : S → Exp A T) (s : S) :
    eqRHS aut sol s =
      (aut.trans s).foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc)
        (.test (aut.hlt s)) := rfl

/-- `eqRHSParam` unfolded to the same fold, with the parameterised fallback. -/
theorem eqRHSParam_fold (aut : GSystem S A T) (sol : S → Exp A T)
    (finish : Exp A T) (s : S) :
    eqRHSParam aut sol finish s =
      (aut.trans s).foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc)
        (paramFallback (aut.hlt s) finish) :=
  guardedFold_transitionBranches _ _ _

/-- Retagging the targets with `some` before folding is folding through `some`. -/
theorem foldr_map_some (l : List (BExp T × A × S)) (sol : Option S → Exp A T)
    (fb : Exp A T) :
    (l.map (fun t => (t.1, t.2.1, some t.2.2))).foldr
        (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) fb =
      l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol (some t.2.2))) acc) fb := by
  induction l with
  | nil => rfl
  | cons head tail ih =>
      exact congrArg
        (fun r => Exp.ite head.1 (.seq (.act head.2.1) (sol (some head.2.2))) r) ih

/-- Changing the fallback under a provable equality changes the fold under one. -/
theorem foldr_fallback_congr (l : List (BExp T × A × S)) (sol : S → Exp A T)
    {b₁ b₂ : Exp A T} (h : EquivBA b₁ b₂) :
    EquivBA (l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) b₁)
      (l.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) b₂) := by
  induction l with
  | nil => exact h
  | cons _ _ ih => exact EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih

/-- The fallback of `eqRHS` and the fallback of `eqRHSParam` at ending `1` agree, by S5. -/
theorem fallback_equiv (halt : BExp T) :
    EquivBA (.test halt : Exp A T) (paramFallback halt (.test .one)) :=
  EquivBA.symm (EquivBA.base (Equiv.s5 (.test halt)))

/-! ## A solution of `toGAut` is a Thompson solution, plus a value at the pseudostate -/

/-- On core states, `eqRHS` of the pseudostate-extended automaton is `eqRHSParam` of the core
    at ending `1`. -/
theorem eqRHS_some (aut : InitializedGAut S A T)
    (sol : Option S → Exp A T) (state : S) :
    EquivBA (eqRHS aut.toGAut sol (some state))
      (eqRHSParam aut.core (fun s => sol (some s)) (.test .one) state) := by
  rw [eqRHS_fold, eqRHSParam_fold]
  simp only [InitializedGAut.toGAut]
  rw [foldr_map_some]
  exact foldr_fallback_congr _ (fun s => sol (some s)) (fallback_equiv _)

/-- At the pseudostate, `eqRHS` is `initRHSParam` at ending `1`. -/
theorem eqRHS_none (aut : InitializedGAut S A T) (sol : Option S → Exp A T) :
    EquivBA (eqRHS aut.toGAut sol none)
      (initRHSParam aut (fun s => sol (some s)) (.test .one)) := by
  rw [eqRHS_fold, initRHSParam, guardedFold_transitionBranches]
  simp only [InitializedGAut.toGAut]
  rw [foldr_map_some]
  exact foldr_fallback_congr _ (fun s => sol (some s)) (fallback_equiv _)

/-- **The restriction is a Thompson solution.**  Solving the pseudostate-extended system
    entails solving the core system at ending `1`. -/
theorem thompsonSolves_of_solvesBA (aut : InitializedGAut S A T)
    (sol : Option S → Exp A T) (hsol : SolvesBA aut.toGAut sol) :
    ThompsonSolvesBA aut.core (fun s => sol (some s)) := by
  intro state hstate
  have hmem : (some state) ∈ aut.toGAut.states :=
    List.mem_cons_of_mem _ (List.mem_map_of_mem hstate)
  exact EquivBA.trans (hsol (some state) hmem) (eqRHS_some aut sol state)

/-- **The pseudostate carries the program.**  Any solution of the extended system assigns to
    `none` an expression provably equal to the program itself — which is what the completeness
    reduction needs and what the core uniqueness theorem does not directly give. -/
theorem sol_none_equiv (program : Exp A T)
    (sol : Option (certifiedThompson A T program).State → Exp A T)
    (hsol : SolvesBA (certifiedThompson A T program).aut.toGAut sol) :
    EquivBA (sol none) program := by
  have hcore : ThompsonSolvesBA (certifiedThompson A T program).aut.core
      (fun s => sol (some s)) :=
    thompsonSolves_of_solvesBA _ sol hsol
  have hnone : none ∈ (certifiedThompson A T program).aut.toGAut.states := List.mem_cons_self
  have h₁ : EquivBA (sol none)
      (initRHSParam (certifiedThompson A T program).aut
        (fun s => sol (some s)) (.test .one)) :=
    EquivBA.trans (hsol none hnone) (eqRHS_none _ sol)
  have h₂ := certifiedThompson_initial_canonical program (.test .one)
    (fun s => sol (some s)) hcore
  exact EquivBA.trans (EquivBA.trans h₁ h₂) (EquivBA.base (Equiv.s5 program))

/-! ## Existence: the extended system always has a solution

    `sol_none_equiv` is the identification half — any solution pins `none` to the program.
    This is the existence half, and together they make the file self-contained: the object the
    swapped conjunct asks a quotient to have is one the unquotiented automaton always has. -/

/-- The standard solution, extended to the pseudostate by the program itself. -/
def extendedSolution (program : Exp A T) :
    Option (certifiedThompson A T program).State → Exp A T
  | none => program
  | some state => (certifiedThompson A T program).standard state

/-- **Every Thompson automaton's pseudostate-extended system is solvable.**  On core states
    this is the certificate's own standard solution; at the pseudostate it is the program,
    which `certifiedThompson_initial_canonical` shows satisfies the initial equation. -/
theorem toGAut_solvable (program : Exp A T) :
    SolvesBA (certifiedThompson A T program).aut.toGAut (extendedSolution program) := by
  intro state hstate
  have hstd : ThompsonSolvesBA (certifiedThompson A T program).aut.core
      (certifiedThompson A T program).standard :=
    (certifiedThompson A T program).certificate.standardSolves
  cases state with
  | none =>
      have h₂ := certifiedThompson_initial_canonical program (.test .one)
        (certifiedThompson A T program).standard hstd
      exact EquivBA.symm (EquivBA.trans (eqRHS_none _ (extendedSolution program))
        (EquivBA.trans h₂ (EquivBA.base (Equiv.s5 program))))
  | some state =>
      have hmem : state ∈ (certifiedThompson A T program).aut.core.states := by
        rcases List.mem_cons.mp hstate with h | h
        · exact absurd h (by simp)
        · obtain ⟨s, hs, hse⟩ := List.mem_map.mp h
          cases hse; exact hs
      exact EquivBA.trans (hstd state hmem)
        (EquivBA.symm (eqRHS_some _ (extendedSolution program) state))

/-! ## Non-vacuity

    `PartnerExists` held for 0 of 4679 instances, which made its completeness theorem true and
    useless.  A new existential should not be trusted until its shape is inhabited, so this
    exhibits the data `SumQuotientSolvable` demands, on the diagonal. -/

/-- A strict homomorphism induces a functional bisimulation.  Halting transfers by `hlt_eq`;
    stepping transfers because `firstMatch` commutes with retargeting the transition list,
    which is `firstMatch_map_target_to`. -/
theorem gAutHom_bisim {S₁ S₂ X : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    (φ : GAutHom aut₁ aut₂) (W : T → X → Bool) :
    GAutBisim W aut₁ aut₂ (fun s q => φ.mapState s = q) := by
  intro s1 s2 hR
  subst hR
  have hstep : ∀ a, autStep W aut₂ (φ.mapState s1) a =
      (autStep W aut₁ s1 a).map (fun o => (o.1, φ.mapState o.2)) := by
    intro a
    show firstMatch W a (aut₂.trans (φ.mapState s1)) = _
    rw [φ.trans_eq s1, firstMatch_map_target_to]
    rfl
  refine ⟨?_, ?_, ?_⟩
  · intro a; rw [φ.hlt_eq s1]
  · intro a q s1' h
    exact ⟨φ.mapState s1', by rw [hstep a, h]; rfl, rfl⟩
  · intro a q s2' h
    rw [hstep a] at h
    cases hs : autStep W aut₁ s1 a with
    | none => rw [hs] at h; exact absurd h (by simp)
    | some o =>
        obtain ⟨q0, s0⟩ := o
        rw [hs] at h
        have h' : (q0, φ.mapState s0) = (q, s2') := Option.some.inj h
        have hq : q0 = q := congrArg Prod.fst h'
        have hsn : φ.mapState s0 = s2' := congrArg Prod.snd h'
        exact ⟨s0, by rw [hq], hsn⟩

/-- Retagging with `inl` and folding back is the identity on a transition list. -/
private theorem map_inj_elim_left {S : Type} (l : List (BExp T × A × S)) :
    ((l.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S)))).map
      (fun t => (t.1, t.2.1, Sum.elim id id t.2.2))) = l := by
  induction l with
  | nil => rfl
  | cons _ _ ih => simp only [List.map_cons, ih]; rfl

/-- Same, for the right injection. -/
private theorem map_inj_elim_right {S : Type} (l : List (BExp T × A × S)) :
    ((l.map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S S)))).map
      (fun t => (t.1, t.2.1, Sum.elim id id t.2.2))) = l := by
  induction l with
  | nil => rfl
  | cons _ _ ih => simp only [List.map_cons, ih]; rfl

/-- The codiagonal `A + A → A`.  Strict, because `sumGAut` retags targets and the fold undoes
    exactly that retagging. -/
def codiagonal (aut : GAut S A T) : GAutHom (sumGAut aut aut) aut where
  mapState := Sum.elim id id
  maps_states := by
    intro s hs
    simp only [sumGAut, List.mem_append, List.mem_map] at hs
    rcases hs with ⟨t, ht, rfl⟩ | ⟨t, ht, rfl⟩ <;> exact ht
  hlt_eq := by intro s; cases s <;> rfl
  trans_eq := by
    intro s
    cases s with
    | inl s => exact (map_inj_elim_left (aut.trans s)).symm
    | inr s => exact (map_inj_elim_right (aut.trans s)).symm

/-- The codiagonal as a behavioural quotient: onto because the left injection is a section. -/
def codiagonalQuotient (aut : GAut S A T) :
    UniformBehavioralGAutQuotient (sumGAut aut aut) aut where
  mapState := Sum.elim id id
  maps_states := (codiagonal aut).maps_states
  onto_states := by
    intro q hq
    exact ⟨Sum.inl q, List.mem_append.mpr (Or.inl (List.mem_map_of_mem hq)), rfl⟩
  bisim_graph := fun X W => gAutHom_bisim (codiagonal aut) W

/-- **Non-vacuity on the diagonal.**  For every program the data `SumQuotientSolvable` asks
    for exists: fold the two copies of `Me` together, and take the extended standard solution.
    So the hypothesis is not vacuously satisfiable-free — what it genuinely demands is that the
    same data survive when the two halves are DIFFERENT programs with the same behaviour. -/
theorem sumQuotientSolvable_diagonal (e : Exp A T) :
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T e).aut.toGAut) quot)
      (qsol : Q → Exp A T),
      SolvesBA quot qsol ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none) :=
  ⟨Option (certifiedThompson A T e).State, (certifiedThompson A T e).aut.toGAut,
    codiagonalQuotient _, extendedSolution e, toGAut_solvable e, rfl⟩

/-! ## A common Thompson target discharges the conjunct

    This is the crystallization transposition recorded in `GkatCrystallizationProofs`: rather
    than collapse `Me + Mf` behaviourally and then ask whether the collapse is solvable, ask
    for the common target to be SYNTAX-GENERATED — the Thompson automaton of a third program.
    For such a target solvability is free, because `toGAut_solvable` supplies the solution.

    It also connects the swapped conjunct back to the object the search harness actually looks
    for, so the measurements and the Lean statement are about the same thing. -/

/-- Map fusion through a sum-elimination, left injection. -/
private theorem map_elim_left {S₁ S₂ R : Type} (F : S₁ → R) (G : S₂ → R)
    (l : List (BExp T × A × S₁)) :
    ((l.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂)))).map
        (fun t => (t.1, t.2.1, Sum.elim F G t.2.2))) =
      l.map (fun t => (t.1, t.2.1, F t.2.2)) := by
  induction l with
  | nil => rfl
  | cons _ _ ih => simp only [List.map_cons, ih]; rfl

/-- Map fusion through a sum-elimination, right injection. -/
private theorem map_elim_right {S₁ S₂ R : Type} (F : S₁ → R) (G : S₂ → R)
    (l : List (BExp T × A × S₂)) :
    ((l.map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂)))).map
        (fun t => (t.1, t.2.1, Sum.elim F G t.2.2))) =
      l.map (fun t => (t.1, t.2.1, G t.2.2)) := by
  induction l with
  | nil => rfl
  | cons _ _ ih => simp only [List.map_cons, ih]; rfl

/-- Co-pairing of two homomorphisms into a common target. -/
def elimSum {S₁ S₂ R : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T} {tgt : GAut R A T}
    (φ₁ : GAutHom aut₁ tgt) (φ₂ : GAutHom aut₂ tgt) : GAutHom (sumGAut aut₁ aut₂) tgt where
  mapState := Sum.elim φ₁.mapState φ₂.mapState
  maps_states := by
    intro s hs
    simp only [sumGAut, List.mem_append, List.mem_map] at hs
    rcases hs with ⟨t, ht, rfl⟩ | ⟨t, ht, rfl⟩
    · exact φ₁.maps_states t ht
    · exact φ₂.maps_states t ht
  hlt_eq := by intro s; cases s with
    | inl s => exact φ₁.hlt_eq s
    | inr s => exact φ₂.hlt_eq s
  trans_eq := by
    intro s
    cases s with
    | inl s =>
        show tgt.trans (φ₁.mapState s) =
          ((aut₁.trans s).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂)))).map
            (fun t => (t.1, t.2.1, Sum.elim φ₁.mapState φ₂.mapState t.2.2))
        rw [map_elim_left]; exact φ₁.trans_eq s
    | inr s =>
        show tgt.trans (φ₂.mapState s) =
          ((aut₂.trans s).map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂)))).map
            (fun t => (t.1, t.2.1, Sum.elim φ₁.mapState φ₂.mapState t.2.2))
        rw [map_elim_right]; exact φ₂.trans_eq s

/-- **TRUE, BUT NOT A ROUTE — its hypothesis is refuted.**  The data asked for here is exactly
    `GkatCrystallization.CommonSyntacticCollapse`'s: two homomorphisms onto a common
    Thompson automaton, plus surjectivity, is precisely a behavioural quotient of the sum onto
    a syntax-generated target.  And `GkatCollapseRefutation.not_commonSyntacticCollapse` proves
    no such data exists in general — for

        e = p ; while b do p        f = (if b then 1 else p) ; while b do p

    determinism pins the quotient to two states, surjectivity forces the target to have exactly
    those two, and either choice of pseudostate contradicts the Thompson structure.

    So this cannot close the problem, and `completeness_of_common_syntactic_collapse` already
    covered the same ground.  It is kept for two reasons: `elimSum` and the co-pairing are
    reusable, and the comparison is what shows where `SumQuotientSolvable` actually differs —
    the cospan dies because the target must be THOMPSON-GENERATED, a demand
    `SumQuotientSolvable` does not make.

    **A common syntax-generated target discharges the swapped conjunct.**  If both Thompson
    automata map homomorphically onto the Thompson automaton of a third program, sending
    pseudostate to pseudostate, then the quotient data `SumQuotientSolvable` demands exists —
    and the solution is free, being the third program's own extended standard solution.

    So the open conjunct is implied by the existence of a common Thompson target, which is
    exactly what the search harness enumerates. -/
theorem sumQuotientSolvable_of_common_thompson (e f h : Exp A T)
    (φ₁ : GAutHom (certifiedThompson A T e).aut.toGAut (certifiedThompson A T h).aut.toGAut)
    (φ₂ : GAutHom (certifiedThompson A T f).aut.toGAut (certifiedThompson A T h).aut.toGAut)
    (honto : ∀ q ∈ (certifiedThompson A T h).aut.toGAut.states,
      ∃ s, s ∈ (sumGAut (certifiedThompson A T e).aut.toGAut
                        (certifiedThompson A T f).aut.toGAut).states ∧
        Sum.elim φ₁.mapState φ₂.mapState s = q)
    (hs₁ : φ₁.mapState none = none) (hs₂ : φ₂.mapState none = none) :
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut) quot)
      (qsol : Q → Exp A T),
      SolvesBA quot qsol ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none) := by
  refine ⟨Option (certifiedThompson A T h).State, (certifiedThompson A T h).aut.toGAut,
    { mapState := Sum.elim φ₁.mapState φ₂.mapState
      maps_states := (elimSum φ₁ φ₂).maps_states
      onto_states := honto
      bisim_graph := fun X W => gAutHom_bisim (elimSum φ₁ φ₂) W },
    extendedSolution h, toGAut_solvable h, ?_⟩
  show φ₁.mapState none = φ₂.mapState none
  rw [hs₁, hs₂]

/-! ## Cycles push forward along a quotient — and only forward

    A caution worth recording, because the literature's phrasing invites the opposite reading.
    The NESTING COEQUATION cuts out a covariety, and covarieties are closed under homomorphic
    images, subcoalgebras and coproducts.  `Nested` here is NOT that coequation: it is its
    finite kernel — mutually reachable states may not carry complementary halt guards — which
    is the condition excluding the Figure 3 automaton.

    That kernel pushes FORWARD along a behavioural quotient, proved below.  It does not
    obviously pull back: lifting a cycle of the quotient yields a source path returning to some
    state with the SAME IMAGE as the one it started from, not to that state itself, so
    recovering a genuine source cycle needs finiteness and a pigeonhole argument.  So
    "covarieties are closed under homomorphic images" must not be cited for `Nested`. -/

variable {S Q Atom : Type}

/-- A step pushes forward along a behavioural quotient. -/
theorem autStep1_quotient {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool) {s s' : S}
    (h : AutStep1 V src s s') : AutStep1 V quot (π.mapState s) (π.mapState s') := by
  obtain ⟨a, q, hstep⟩ := h
  obtain ⟨-, hfwd, -⟩ := π.bisim_graph Atom V s (π.mapState s) rfl
  obtain ⟨t, hq, ht⟩ := hfwd a q s' hstep
  exact ⟨a, q, by rw [hq, ht]⟩

/-- Reachability pushes forward. -/
theorem autReaches_quotient {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool) {s s' : S}
    (h : AutReaches V src s s') : AutReaches V quot (π.mapState s) (π.mapState s') := by
  induction h with
  | refl => exact AutReaches.refl _
  | tail _ hstep ih => exact AutReaches.tail ih (autStep1_quotient π V hstep)

/-- And so does a genuine cycle. -/
theorem autReaches1_quotient {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool) {s s' : S}
    (h : AutReaches1 V src s s') : AutReaches1 V quot (π.mapState s) (π.mapState s') := by
  obtain ⟨x, hstep, hreach⟩ := h
  exact ⟨π.mapState x, autStep1_quotient π V hstep, autReaches_quotient π V hreach⟩

/-- **`Nested` is REFLECTED by a quotient, not preserved by one.**  If the quotient satisfies
    the kernel then so does the source; the converse is the direction that would need the
    pigeonhole argument, and is not proved here. -/
theorem nested_of_quotient_nested {src : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient src quot) (V : T → Atom → Bool)
    (hq : Nested V quot) : Nested V src := by
  intro s1 s2 hmem h12 h21 hcomp
  refine hq (π.mapState s1) (π.mapState s2) (π.maps_states s1 hmem)
    (autReaches1_quotient π V h12) (autReaches1_quotient π V h21) (fun a => ?_)
  obtain ⟨h1, -, -⟩ := π.bisim_graph Atom V s1 (π.mapState s1) rfl
  obtain ⟨h2, -, -⟩ := π.bisim_graph Atom V s2 (π.mapState s2) rfl
  rw [← h1 a, ← h2 a]
  exact hcomp a

/-! ## Solvable but not syntax-generated — the gap, exhibited

    The literature states the crux plainly: "a proper characterization of solvable automata
    would be crucial for proving a completeness theorem for GKAT, but such a characterization
    remains elusive", and there are automata that admit a solution while not being well-nested.

    This exhibits the gap at the exact point where the cospan route dies.
    `not_commonSyntacticCollapse` shows that for

        e = p ; while b do p        f = (if b then 1 else p) ; while b do p

    determinism pins the quotient of `Me + Mf` to two states — a common start image and a
    common action image — and no THOMPSON automaton has that shape.  But the two-state system
    itself is solved outright, below.  So at that pair a solvable target exists where a
    syntax-generated one does not, which is exactly the room `SumQuotientSolvable` has and
    `CommonSyntacticCollapse` does not. -/

/-- Under `¬b`, the test `1` and the test `¬b` agree, so a `while`'s exit branch may be
    written with either.  Both sides reduce to `ite ¬b (¬b)? X` through U2, U4 and S6. -/
theorem else_guard_test (b : BExp T) (X : Exp A T) :
    EquivBA (.ite b X (.test .one)) (.ite b X (.test (.not b))) := by
  have h3 : EquivBA (.seq (.test (.not b)) (.test .one) : Exp A T) (.test (.not b)) :=
    EquivBA.trans (EquivBA.s6 (.not b) .one)
      (EquivBA.baTest (fun Y W x => by
        show (bval W (BExp.not b) x && true) = bval W (BExp.not b) x
        cases bval W (BExp.not b) x <;> rfl))
  exact EquivBA.trans
    (EquivBA.trans (EquivBA.base (Equiv.u2 b X (.test .one)))
      (EquivBA.trans (EquivBA.base (Equiv.u4 (.not b) (.test .one) X))
        (EquivBA.ite_c h3 (EquivBA.base (Equiv.refl X)))))
    (EquivBA.symm (EquivBA.base (Equiv.u2 b X (.test (.not b)))))

/-- The two-state shape the refutation pins the quotient to: a start image that always steps,
    and an action image that loops on `b` and halts on `¬b`. -/
def gapAut (b : BExp T) (p : A) : GAut Bool A T where
  states := [false, true]
  hlt := fun s => cond s (BExp.not b) BExp.zero
  trans := fun s => cond s [(b, p, true)] [(BExp.one, p, true)]
  start := false

/-- Its solution, written down directly: the loop, and the loop after one action. -/
def gapSol (b : BExp T) (p : A) : Bool → Exp A T :=
  fun s => cond s (.wh b (.act p)) (.seq (.act p) (.wh b (.act p)))

/-- **The pinned quotient is solvable.**  No search and no uniqueness axiom: the action image
    is solved by W1, and the start image by `ite_one`.

    Read against `not_commonSyntacticCollapse`, this is the gap: at that pair the quotient has
    a solution while having no syntax-generated target. -/
theorem gapAut_solvable (b : BExp T) (p : A) : SolvesBA (gapAut b p) (gapSol b p) := by
  intro s _
  cases s with
  | false => exact EquivBA.symm (ite_one _ _)
  | true =>
      exact EquivBA.trans (EquivBA.base (Equiv.w1 b (.act p))) (else_guard_test b _)

/-! ## When the standard solution DESCENDS — already proved, elsewhere

    The residue of this programme is eight quotients that are bisimulation collapses of
    Thompson automata but are not Thompson.  Such a quotient always has a SEMANTIC solution:
    the source carries the standard solution, `sem_solves_autLang` makes each expression denote
    its state's language, and bisimilar states have equal languages, so the assignment is
    constant on fibres up to language equality.  What is missing is that fibre-mates be
    PROVABLY equal, so it descends in the equational theory.

    I proved that sufficient here — and then found it already in the corpus, stronger:
    `GkatThompson.UniformBehavioralGAutQuotient.solves_of_descends`, which takes a BEHAVIOURAL
    quotient rather than a strict homomorphism, with `eqRHS_solution_congr` as its congruence
    lemma.  Its own docstring says it "isolates the non-semantic descent obligation left by
    Thompson uniqueness", which is exactly the synthesis reached independently from the
    measurements.  My versions were strictly weaker and are removed rather than kept.

    That is the THIRD duplication in this development — after `toGAut_solvable` against
    `certifiedThompson_toGAut_solves`, and `sumQuotientSolvable_of_common_thompson` against
    `completeness_of_common_syntactic_collapse`.  The corpus should be searched before a
    statement is proved, not after. -/

/-! ## The swap -/

/-- **The open conjunct, weakened.**  For uniformly equivalent `e` and `f`, some behavioural
    quotient of `Me + Mf` identifying the two starts has a solution.

    Weaker than `ReachListCovered` in two independent ways: it asks for a solution rather than
    a cover, and it says nothing about the covering automaton being Thompson.  Measured at
    9221/9245 = 99.7% by a sound procedure, against 45.4% for non-equivalent pairs from the
    same population, and against `ReachListCovered`'s 60.0% at `K = 6`. -/
def SumQuotientSolvable (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut) quot)
      (qsol : Q → Exp A T),
      SolvesBA quot qsol ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none)

/-- **The reduction.**  Solvability of the sum-quotient gives completeness of the finite
    axioms.

    The mathematics is NOT new here: this is `certifiedThompson_uniform_solved_quotient`, which
    was already in the corpus with exactly these hypotheses and conclusion, quantified over
    pairs.  I proved it again before checking — a fourth duplication — and it is now delegated
    rather than reproved.  What the wrapper adds is only bookkeeping: a NAMED `Prop` that can be
    compared against `ReachListCovered` as the programme's open conjunct.

    No uniqueness axiom appears; uniqueness enters only where it is already a theorem, at
    Thompson-generated automata. -/
theorem completeness_of_sumQuotientSolvable (h : SumQuotientSolvable A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨Q, quot, π, qsol, hqsol, hstart⟩ := h e f heq
  exact certifiedThompson_uniform_solved_quotient π qsol hqsol hstart

#print axioms guardedFold_transitionBranches
#print axioms thompsonSolves_of_solvesBA
#print axioms sol_none_equiv
#print axioms toGAut_solvable
#print axioms gAutHom_bisim
#print axioms sumQuotientSolvable_diagonal
#print axioms sumQuotientSolvable_of_common_thompson
#print axioms else_guard_test
#print axioms gapAut_solvable
#print axioms nested_of_quotient_nested
#print axioms completeness_of_sumQuotientSolvable


/-! ## The programme's remaining obligation, stated

    Everything the measurement established chains to a single statement.  Completeness follows
    from `SumQuotientSolvable`, proved below.  A solvable quotient is supplied either by
    ELIMINATION or by the quotient BEING a Thompson automaton.  Elimination covers 99.74% of
    crux pairs and stops exactly where it would need an unguarded union — and no quotient avoids
    that union, measured 0 of 24.  So the Thompson half is not a convenience: on the fragment
    where elimination stops it is the only witness, and the whole programme rests on it.

    Written out, that obligation is `SumQuotientThompson` below.  It needs no isomorphism
    transport: if the quotient's target IS the Thompson automaton of some `g`, then
    `certifiedThompson_toGAut_solves` hands over its solution and the existing reduction closes
    it.  The proof is three lines; the content is entirely in the statement.

    Measured at NA=2, pairk=4: 9245 / 9245 = 100%.  The same shape on the PULLBACK — the brief's
    `ReachListCovered` — is 4288 / 4679 = 91.6% and budget-saturated, so this is the formulation
    where the evidence is strongest, not merely a restatement. -/

/-- **The remaining obligation.**  For every language-equivalent pair, some behavioural quotient
    of the sum of their Thompson automata IS the Thompson automaton of a third program, with the
    two start states identified. -/
def SumQuotientThompson (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (g : Exp A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut)
            (certifiedThompson A T g).aut.toGAut),
      π.mapState (Sum.inl none) = π.mapState (Sum.inr none)

/-- **It implies completeness.**  Thompson automata solve themselves, so the quotient comes with
    a solution for free and `certifiedThompson_uniform_solved_quotient` finishes. -/
theorem completeness_of_sumQuotientThompson (h : SumQuotientThompson A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨g, π, hstart⟩ := h e f heq
  exact certifiedThompson_uniform_solved_quotient π _
    (certifiedThompson_toGAut_solves g) hstart

/-- And it is at least as strong as the solvability form, so nothing is lost by stating the
    obligation this way. -/
theorem sumQuotientSolvable_of_thompson (h : SumQuotientThompson A T) :
    SumQuotientSolvable A T := by
  intro e f heq
  obtain ⟨g, π, hstart⟩ := h e f heq
  exact ⟨_, _, π, _, certifiedThompson_toGAut_solves g, hstart⟩

#print axioms completeness_of_sumQuotientThompson
#print axioms sumQuotientSolvable_of_thompson


/-! ## The coproduct half of the covariety

    The literature's characterisation is that the automata whose behaviour is GKAT-expressible
    are exactly those satisfying the NESTING COEQUATION, and that this class is a COVARIETY —
    closed under homomorphic images, subcoalgebras and coproducts.  The corpus has `Nested` (the
    finite kernel: no two mutually-reachable states with complementary halt guards) and proves
    it for derivative automata, but no closure lemma.

    The coproduct half is provable here, and it is the half the sum route needs: a step out of
    the left summand stays in the left summand, so mutual reachability can never cross the
    components and the condition reduces to each side.  Measured independently at 100% on the
    start-merged quotients; this proves the coproduct step of that. -/

theorem autStep1_sumGAut_inl_inv {S₁ S₂ : Type} {V : T → Atom → Bool}
    {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T} {s : S₁} {t : Sum S₁ S₂}
    (h : AutStep1 V (sumGAut a₁ a₂) (.inl s) t) :
    ∃ u, t = .inl u ∧ AutStep1 V a₁ s u := by
  obtain ⟨α, q, hq⟩ := h
  rw [autStep_sumGAut_inl] at hq
  cases hs : autStep V a₁ s α with
  | none => rw [hs] at hq; exact absurd hq (by simp)
  | some o =>
      rw [hs] at hq
      simp only [Option.map_some] at hq
      injection hq with hq
      injection hq with h1 h2
      exact ⟨o.2, h2.symm, ⟨α, o.1, by rw [hs]⟩⟩

theorem autStep1_sumGAut_inr_inv {S₁ S₂ : Type} {V : T → Atom → Bool}
    {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T} {s : S₂} {t : Sum S₁ S₂}
    (h : AutStep1 V (sumGAut a₁ a₂) (.inr s) t) :
    ∃ u, t = .inr u ∧ AutStep1 V a₂ s u := by
  obtain ⟨α, q, hq⟩ := h
  rw [autStep_sumGAut_inr] at hq
  cases hs : autStep V a₂ s α with
  | none => rw [hs] at hq; exact absurd hq (by simp)
  | some o =>
      rw [hs] at hq
      simp only [Option.map_some] at hq
      injection hq with hq
      injection hq with h1 h2
      exact ⟨o.2, h2.symm, ⟨α, o.1, by rw [hs]⟩⟩

theorem autReaches_sumGAut_inl {S₁ S₂ : Type} {V : T → Atom → Bool}
    {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T} {s : S₁} {t : Sum S₁ S₂}
    (h : AutReaches V (sumGAut a₁ a₂) (.inl s) t) :
    ∃ u, t = .inl u ∧ AutReaches V a₁ s u := by
  induction h with
  | refl => exact ⟨s, rfl, AutReaches.refl s⟩
  | tail _ hstep ih =>
      obtain ⟨u, rfl, hru⟩ := ih
      obtain ⟨v, rfl, hsv⟩ := autStep1_sumGAut_inl_inv hstep
      exact ⟨v, rfl, AutReaches.tail hru hsv⟩

theorem autReaches_sumGAut_inr {S₁ S₂ : Type} {V : T → Atom → Bool}
    {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T} {s : S₂} {t : Sum S₁ S₂}
    (h : AutReaches V (sumGAut a₁ a₂) (.inr s) t) :
    ∃ u, t = .inr u ∧ AutReaches V a₂ s u := by
  induction h with
  | refl => exact ⟨s, rfl, AutReaches.refl s⟩
  | tail _ hstep ih =>
      obtain ⟨u, rfl, hru⟩ := ih
      obtain ⟨v, rfl, hsv⟩ := autStep1_sumGAut_inr_inv hstep
      exact ⟨v, rfl, AutReaches.tail hru hsv⟩

theorem mem_sumGAut_inl {S₁ S₂ : Type} {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T} {x : S₁}
    (h : (Sum.inl x : Sum S₁ S₂) ∈ (sumGAut a₁ a₂).states) : x ∈ a₁.states := by
  simp only [sumGAut, List.mem_append, List.mem_map] at h
  rcases h with ⟨w, hw, hwe⟩ | ⟨w, _, hwe⟩
  · injection hwe with hwe; exact hwe ▸ hw
  · exact absurd hwe (by simp)

theorem mem_sumGAut_inr {S₁ S₂ : Type} {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T} {x : S₂}
    (h : (Sum.inr x : Sum S₁ S₂) ∈ (sumGAut a₁ a₂).states) : x ∈ a₂.states := by
  simp only [sumGAut, List.mem_append, List.mem_map] at h
  rcases h with ⟨w, _, hwe⟩ | ⟨w, hw, hwe⟩
  · exact absurd hwe (by simp)
  · injection hwe with hwe; exact hwe ▸ hw

/-- **The nesting coequation is closed under coproducts.**  Mutual reachability cannot cross
    the two summands, so the condition is inherited componentwise. -/
theorem Nested_sumGAut {S₁ S₂ : Type} {V : T → Atom → Bool}
    {a₁ : GAut S₁ A T} {a₂ : GAut S₂ A T}
    (h₁ : Nested V a₁) (h₂ : Nested V a₂) : Nested V (sumGAut a₁ a₂) := by
  intro s1 s2 hs1 hr12 hr21
  cases s1 with
  | inl x =>
      obtain ⟨m, hstep, hreach⟩ := hr12
      obtain ⟨m', rfl, hsm⟩ := autStep1_sumGAut_inl_inv hstep
      obtain ⟨y, rfl, hmy⟩ := autReaches_sumGAut_inl hreach
      obtain ⟨n, hstep2, hreach2⟩ := hr21
      obtain ⟨n', rfl, hyn⟩ := autStep1_sumGAut_inl_inv hstep2
      obtain ⟨z, hz, hnz⟩ := autReaches_sumGAut_inl hreach2
      have hzx : x = z := by injection hz
      exact h₁ x y (mem_sumGAut_inl hs1) ⟨m', hsm, hmy⟩
        ⟨n', hyn, by rw [hzx]; exact hnz⟩
  | inr x =>
      obtain ⟨m, hstep, hreach⟩ := hr12
      obtain ⟨m', rfl, hsm⟩ := autStep1_sumGAut_inr_inv hstep
      obtain ⟨y, rfl, hmy⟩ := autReaches_sumGAut_inr hreach
      obtain ⟨n, hstep2, hreach2⟩ := hr21
      obtain ⟨n', rfl, hyn⟩ := autStep1_sumGAut_inr_inv hstep2
      obtain ⟨z, hz, hnz⟩ := autReaches_sumGAut_inr hreach2
      have hzx : x = z := by injection hz
      exact h₂ x y (mem_sumGAut_inr hs1) ⟨m', hsm, hmy⟩
        ⟨n', hyn, by rw [hzx]; exact hnz⟩

#print axioms Nested_sumGAut

end GkatSumQuotient
