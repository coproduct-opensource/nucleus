import GkatNormalProofs

/-!
# Totality is compositional, and stuckness has exactly two sources

The previous file established that totality — every state, at every atom, either halts or
steps — is what the development actually needs, and that the sink needed to repair it is
expressible: `while 1 do e` is null for every body, provably `0`, and total.

This file finds out how much repair is needed, by asking which constructors break totality.
The answer is sharp, and it is not what six iterations of pruning work suggested.

## The four preservation lemmas

  * `totalParts_action` — an action is total.
  * `totalParts_testOne` — `1?` is total.
  * `totalParts_seq`, `totalParts_ite` — `;` and `+_b` preserve totality **unconditionally**.
  * `totalParts_loop` — `while b do e` preserves it under one side condition: wherever the
    guard holds, the body's pseudostate must *step*.

So totality is compositional except at two places, and both are places GKAT's own axioms
already point at:

  * **the test subalgebra.**  `b?` is stuck at every `¬b` atom — it neither halts nor steps.
    `test_zero_not_total` is the witness.
  * **the loop side condition.**  `while b do 1?` is stuck at every `b` atom: the body halts
    immediately, so the loop can neither exit nor make progress.  `wh_test_not_total` is the
    witness — and it is worth putting beside `GkatNormal.wh_one_total`, which is the *same
    guard* with an action for a body, and total.  The guard is not what breaks it; a body that
    can do nothing is.

That second condition is not an invention of this file.  It is the side condition `W3`
already carries: `w3_ba` requires `EquivBA (.test (E e)) (.test .zero)` — the body cannot halt
immediately — before the fixpoint rule may be applied.  So the two sources of partiality in
GKAT's automata are exactly the two places its axiomatisation already treats specially.

## Both sources are repaired: `settledReachable`

`Settled` names the syntactic class the lemmas add up to, and `total_of_settled` proves every
`Settled` program has a total automaton.  Both sources are then discharged, and
`settledReachable` puts them together: **every program is provably equal to a settled one**,
hence to one whose automaton is total (`total_form`).

  * **The test.**  `b?` is provably equal to `if b then 1? else (while 1 do a)` — the sink,
    used for what it was built for.
  * **The loop.**  `while g do e ≡ while g do (if ¬E(e) then e else diverge)`
    (`loop_settles`), whose body has `E = 0` *for every* `e`, so it steps under every guard
    and the side condition is discharged outright rather than assumed.

The loop derivation rests on one algebraic fact, `halt_restriction`: **a program restricted to
the atoms where it can halt immediately is `skip`** — `E(e)? · e ≡ E(e)?`, proved by induction
on `e` from the finite axioms, `[propext]` only.  Determinism is why it is true: a
deterministic automaton that halts cannot also step, so on that region the empty word is all
it accepts.  Through `U1` and `U4` it gives the decomposition `e ≡ e +_{¬E e} 1`, which is
precisely the step the literature identifies as what a productive normal form needs, and then
`W2` — "non-productive loop iterations do not contribute" — does the rest.

One step there is not in the literature and is the reason this reaches totality rather than
mere productivity.  `W2`'s own normal form `(¬E e)? · e` *is* productive — its `E` is `0` —
but its automaton is **stuck** at immediate-halt atoms, not total.  Replacing the dead arm by
the sink keeps `E = 0` and makes it step instead.  Productive is not the same as total, and
the difference is exactly a `0` where a divergence belongs.

The whole thing needs `A` inhabited, and that is the honest boundary: with no actions there is
no divergent program to route stuck configurations into, and the partiality is irreparable.

Note what changed.  Pruning had to remove states — dead regions, unreachable branches — and
was defeated three times because the constructors destroy the induction hypothesis.
Totalising *adds* transitions, and the induction hypothesis survives every constructor.

## What the file now proves end to end

`completeness_of_canonicallySettled` derives `FiniteAxiomsCompleteBA` from **two** hypotheses:
`CanonicallySettled` and `PullbackCovered`.  Everything between them is discharged:

  * **normalisation to a total form** — `settledReachable`, proved;
  * **the behavioural target** — `commonTarget_of_pad`, proved, with no reachability, no
    productivity and no non-nullity hypothesis, and with the basepoint supplied
    unconditionally by the sink the padding attaches;
  * **the structural side conditions** — `haltStepDisjoint_thompson` and
    `thompson_states_complete`, proved rather than assumed;
  * **dead-canonicity is inherited by the padding** — `deadCanonical_ite`,
    `deadCanonical_div`, proved.

`CanonicallySettled` is itself two thirds proved: `settledReachable` gives its first two
conjuncts, and only `DeadCanonical` is open.

The identification that makes the sink legitimate is the one the literature calls the
**early-termination property** — programs that fail immediately are equated with programs
that fail eventually.  `wh_one_provably_zero` is exactly that, derived here rather than
postulated, and it is what lets a stuck configuration be replaced by a divergent one without
leaving the equational theory.
-/

namespace GkatTotalization

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCommonTarget GkatNormal GkatAtomTransfer

variable {A T : Type}
variable {S S₁ S₂ : Type}

/-! ## Totality, componentwise

    `Total` is stated on `toGAut`, whose carrier is `Option S`.  The constructions are stated
    on the components, so this is the same property in the form they expose. -/

/-- The pseudostate and every core state halt or step, at every atom. -/
structure TotalParts (aut : InitializedGAut S A T) : Prop where
  init : ∀ (X : Type) (W : T → X → Bool) (x : X),
    bval W aut.initHlt x = true ∨ (firstMatch W x aut.initTrans).isSome = true
  core : ∀ (X : Type) (W : T → X → Bool) (x : X) (u : S),
    bval W (aut.core.hlt u) x = true ∨ (firstMatch W x (aut.core.trans u)).isSome = true

theorem total_of_parts {aut : InitializedGAut S A T} (h : TotalParts aut) : Total aut := by
  intro X W x s
  cases s with
  | none =>
      rcases h.init X W x with hh | hs
      · exact Or.inl hh
      · refine Or.inr ?_
        show (firstMatch W x (aut.initTrans.map
          (fun t => (t.1, t.2.1, (some t.2.2 : Option S))))).isSome = true
        rw [firstMatch_map_target_to (F := fun u : S => (some u : Option S))]
        cases hf : firstMatch W x aut.initTrans with
        | none => rw [hf] at hs; exact hs
        | some o => rfl
  | some u =>
      rcases h.core X W x u with hh | hs
      · exact Or.inl hh
      · refine Or.inr ?_
        show (firstMatch W x ((aut.core.trans u).map
          (fun t => (t.1, t.2.1, (some t.2.2 : Option S))))).isSome = true
        rw [firstMatch_map_target_to (F := fun v : S => (some v : Option S))]
        cases hf : firstMatch W x (aut.core.trans u) with
        | none => rw [hf] at hs; exact hs
        | some o => rfl

theorem parts_of_total {aut : InitializedGAut S A T} (h : Total aut) : TotalParts aut where
  init := fun X W x => by
    rcases h X W x none with hh | hs
    · exact Or.inl hh
    · refine Or.inr ?_
      have hmap : (firstMatch W x (aut.initTrans.map
          (fun t => (t.1, t.2.1, (some t.2.2 : Option S))))).isSome = true := hs
      rw [firstMatch_map_target_to (F := fun u : S => (some u : Option S))] at hmap
      cases hf : firstMatch W x aut.initTrans with
      | none => rw [hf] at hmap; exact hmap
      | some o => rfl
  core := fun X W x u => by
    rcases h X W x (some u) with hh | hs
    · exact Or.inl hh
    · refine Or.inr ?_
      have hmap : (firstMatch W x ((aut.core.trans u).map
          (fun t => (t.1, t.2.1, (some t.2.2 : Option S))))).isSome = true := hs
      rw [firstMatch_map_target_to (F := fun v : S => (some v : Option S))] at hmap
      cases hf : firstMatch W x (aut.core.trans u) with
      | none => rw [hf] at hmap; exact hmap
      | some o => rfl

/-! ## Stepping, by membership

    Every preservation proof below has the same shape: to show a state steps, exhibit one
    transition in its list whose guard fires.  Computing `firstMatch` through the appends and
    guard-conjunctions the constructions build is unnecessary — `firstMatch` returns *some*
    match whenever any guard fires, and which one is irrelevant to totality. -/

/-- A match means some listed guard fires. -/
private theorem fires_of_isSome {X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) (h : (firstMatch W x L).isSome = true) :
    ∃ t ∈ L, bval W t.1 x = true := by
  induction L with
  | nil => exact absurd h (by simp [firstMatch])
  | cons hd tl ih =>
      by_cases hg : bval W hd.1 x = true
      · exact ⟨hd, List.mem_cons_self, hg⟩
      · have hskip : firstMatch W x (hd :: tl) = firstMatch W x tl := by
          obtain ⟨q, act, v⟩ := hd
          simp only [firstMatch]
          exact if_neg hg
        rw [hskip] at h
        obtain ⟨t, ht, hft⟩ := ih h
        exact ⟨t, List.mem_cons_of_mem _ ht, hft⟩

/-- …and conversely, a firing guard anywhere in the list means a match. -/
private theorem isSome_of_mem_fires {X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) {t : BExp T × A × S} (hm : t ∈ L)
    (hg : bval W t.1 x = true) : (firstMatch W x L).isSome = true := by
  obtain ⟨o, ho⟩ := firstMatch_isSome_of_mem_fires W x L hm hg
  rw [ho]
  rfl

/-! ## The leaves -/

/-- **An action is total.**  Its pseudostate steps unconditionally, its core state halts
    unconditionally. -/
theorem totalParts_action (a : A) : TotalParts (thompsonAction (T := T) a) where
  init := fun _ _ _ => Or.inr rfl
  core := fun _ _ _ _ => Or.inl rfl

/-- **`1?` is total.**  It halts everywhere, and has no core states. -/
theorem totalParts_testOne : TotalParts (thompsonTest (A := A) (BExp.one : BExp T)) where
  init := fun _ _ _ => Or.inl rfl
  core := fun _ _ _ u => nomatch u

/-! ## The compositional cases -/

/-- **Guarded choice preserves totality, unconditionally.**  At any atom exactly one branch
    guard fires, and that branch's own behaviour is inherited verbatim. -/
theorem totalParts_ite (g : BExp T) {L : InitializedGAut S₁ A T} {R : InitializedGAut S₂ A T}
    (hl : TotalParts L) (hr : TotalParts R) : TotalParts (iteInitialized g L R) where
  init := fun X W x => by
    cases hg : bval W g x
    · rcases hr.init X W x with hh | hs
      · refine Or.inl ?_
        show (bval W g x && bval W L.initHlt x || (!bval W g x) && bval W R.initHlt x) = true
        simp [hg, hh]
      · refine Or.inr ?_
        obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
        refine isSome_of_mem_fires W x _
          (List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨t, ht, rfl⟩))) ?_
        show ((!bval W g x) && bval W t.1 x) = true
        simp [hg, hft]
    · rcases hl.init X W x with hh | hs
      · refine Or.inl ?_
        show (bval W g x && bval W L.initHlt x || (!bval W g x) && bval W R.initHlt x) = true
        simp [hg, hh]
      · refine Or.inr ?_
        obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
        refine isSome_of_mem_fires W x _
          (List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨t, ht, rfl⟩))) ?_
        show (bval W g x && bval W t.1 x) = true
        simp [hg, hft]
  core := fun X W x u => by
    cases u with
    | inl v =>
        rcases hl.core X W x v with hh | hs
        · exact Or.inl hh
        · refine Or.inr ?_
          obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
          exact isSome_of_mem_fires W x _ (List.mem_map.mpr ⟨t, ht, rfl⟩) hft
    | inr v =>
        rcases hr.core X W x v with hh | hs
        · exact Or.inl hh
        · refine Or.inr ?_
          obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
          exact isSome_of_mem_fires W x _ (List.mem_map.mpr ⟨t, ht, rfl⟩) hft

/-- **Sequential composition preserves totality, unconditionally.**  If the left component
    steps, so does the composite; if it halts, control passes to the right component's
    pseudostate, which halts or steps by its own totality. -/
theorem totalParts_seq {L : InitializedGAut S₁ A T} {R : InitializedGAut S₂ A T}
    (hl : TotalParts L) (hr : TotalParts R) : TotalParts (seqInitialized L R) where
  init := fun X W x => by
    rcases hl.init X W x with hh | hs
    · rcases hr.init X W x with hh2 | hs2
      · refine Or.inl ?_
        show (bval W L.initHlt x && bval W R.initHlt x) = true
        simp [hh, hh2]
      · refine Or.inr ?_
        obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs2
        refine isSome_of_mem_fires W x _
          (List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨t, ht, rfl⟩))) ?_
        show (bval W L.initHlt x && bval W t.1 x) = true
        simp [hh, hft]
    · refine Or.inr ?_
      obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
      exact isSome_of_mem_fires W x _
        (List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨t, ht, rfl⟩))) hft
  core := fun X W x u => by
    cases u with
    | inl v =>
        rcases hl.core X W x v with hh | hs
        · rcases hr.init X W x with hh2 | hs2
          · refine Or.inl ?_
            show (bval W (L.core.hlt v) x && bval W R.initHlt x) = true
            simp [hh, hh2]
          · refine Or.inr ?_
            obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs2
            refine isSome_of_mem_fires W x _
              (List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨t, ht, rfl⟩))) ?_
            show (bval W (L.core.hlt v) x && bval W t.1 x) = true
            simp [hh, hft]
        · refine Or.inr ?_
          obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
          exact isSome_of_mem_fires W x _
            (List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨t, ht, rfl⟩))) hft
    | inr v =>
        rcases hr.core X W x v with hh | hs
        · exact Or.inl hh
        · refine Or.inr ?_
          obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
          exact isSome_of_mem_fires W x _ (List.mem_map.mpr ⟨t, ht, rfl⟩) hft

/-- The loop side condition: wherever the guard holds, the body's *pseudostate* steps.

    This is `W3`'s side condition seen on the automaton.  `w3_ba` demands
    `EquivBA (.test (E e)) (.test .zero)` — the body cannot halt immediately — before the
    fixpoint rule may be used, and that is exactly what fails when the body's pseudostate
    halts at a guard atom: the loop makes no progress and cannot exit. -/
def BodySteps (B : InitializedGAut S A T) (g : BExp T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X), bval W g x = true →
    (firstMatch W x B.initTrans).isSome = true

/-- **A loop preserves totality exactly when its body steps under the guard.**

    At a `¬g` atom the loop halts, by construction.  At a `g` atom the pseudostate takes the
    guarded entry block, which fires by `BodySteps`; and a core state either steps inside the
    body or, having halted there, takes the back edge — which is guarded by the body halt
    conjoined with `g`, so it fires for the same reason. -/
theorem totalParts_loop (g : BExp T) {B : InitializedGAut S A T} (hb : TotalParts B)
    (hstep : BodySteps B g) : TotalParts (loopInitialized g B) where
  init := fun X W x => by
    cases hg : bval W g x
    · refine Or.inl ?_
      show (!bval W g x) = true
      simp [hg]
    · refine Or.inr ?_
      obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ (hstep X W x hg)
      refine isSome_of_mem_fires W x _ (List.mem_map.mpr ⟨t, ht, rfl⟩) ?_
      show (bval W g x && bval W t.1 x) = true
      simp [hg, hft]
  core := fun X W x u => by
    rcases hb.core X W x u with hh | hs
    · cases hg : bval W g x
      · refine Or.inl ?_
        show (bval W (B.core.hlt u) x && !bval W g x) = true
        simp [hh, hg]
      · refine Or.inr ?_
        obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ (hstep X W x hg)
        refine isSome_of_mem_fires W x _
          (List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨t, ht, rfl⟩))) ?_
        show (bval W (B.core.hlt u) x && (bval W g x && bval W t.1 x)) = true
        simp [hh, hg, hft]
    · refine Or.inr ?_
      obtain ⟨t, ht, hft⟩ := fires_of_isSome W x _ hs
      exact isSome_of_mem_fires W x _ (List.mem_append.mpr (Or.inl ht)) hft

/-! ## The syntactic class -/

/-- The class the five lemmas add up to: every embedded test is `1`, and every loop body
    steps wherever its guard holds.  Nothing else is restricted. -/
inductive Settled : Exp A T → Prop where
  | act (a : A) : Settled (.act a)
  | one : Settled (.test BExp.one)
  | seq {e f : Exp A T} : Settled e → Settled f → Settled (.seq e f)
  | ite (g : BExp T) {e f : Exp A T} : Settled e → Settled f → Settled (.ite g e f)
  | wh (g : BExp T) {e : Exp A T} : Settled e →
      BodySteps (certifiedThompson A T e).aut g → Settled (.wh g e)

theorem totalParts_of_settled {e : Exp A T} (h : Settled e) :
    TotalParts (certifiedThompson A T e).aut := by
  induction h with
  | act a => exact totalParts_action a
  | one => exact totalParts_testOne
  | seq _ _ ih₁ ih₂ => exact totalParts_seq ih₁ ih₂
  | ite g _ _ ih₁ ih₂ => exact totalParts_ite g ih₁ ih₂
  | wh g _ hp ih => exact totalParts_loop g ih hp

/-- **Every settled program has a total automaton.** -/
theorem total_of_settled {e : Exp A T} (h : Settled e) :
    Total (certifiedThompson A T e).aut :=
  total_of_parts (totalParts_of_settled h)

/-! ## The first source, discharged

    `b?` is stuck at every `¬b` atom, and the repair is the sink.  Note that it needs an
    action: a language with no actions has no divergent program to route into, and there the
    partiality is irreparable. -/

/-- The sink, as a program: `while 1 do a`, null for every `a` and total. -/
def div (a : A) : Exp A T := .wh BExp.one (.act a)

theorem settled_div (a : A) : Settled (div a : Exp A T) :=
  Settled.wh BExp.one (Settled.act a) (fun _ _ _ _ => rfl)

/-- The totalised test: `if b then 1? else (while 1 do a)`. -/
def totalTest (a : A) (b : BExp T) : Exp A T := .ite b (.test BExp.one) (div a)

theorem settled_totalTest (a : A) (b : BExp T) : Settled (totalTest a b : Exp A T) :=
  Settled.ite b Settled.one (settled_div a)

/-- **A test is provably equal to a settled program.**  `test_eq_ite_one_zero` splits `b?`
    into `if b then 1? else 0`, and `wh_one_provably_zero` replaces the `0` by the sink. -/
theorem totalTest_equiv (a : A) (b : BExp T) :
    EquivBA (.test b : Exp A T) (totalTest a b) :=
  EquivBA.trans (test_eq_ite_one_zero b)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
      (EquivBA.symm (GkatNormal.wh_one_provably_zero (.act a))))

theorem totalTest_total (a : A) (b : BExp T) :
    Total (certifiedThompson A T (totalTest a b)).aut :=
  total_of_settled (settled_totalTest a b)

/-! ## The two witnesses

    Both are minimal, and together they show the two sources are genuinely different: the
    same guard `1` is total with an action for a body and stuck with a test. -/

/-- **The test subalgebra is the first source.**  `0?` neither halts nor steps. -/
theorem test_zero_not_total :
    ¬ Total (certifiedThompson Unit Unit (.test (BExp.zero))).aut := by
  intro h
  rcases h Unit (fun _ _ => true) () none with hh | hs
  · have hfalse : (false : Bool) = true := hh
    exact Bool.noConfusion hfalse
  · have hfalse : (false : Bool) = true := hs
    exact Bool.noConfusion hfalse

/-- **The loop side condition is the second source.**  `while 1 do 1?` neither halts (the
    guard never fails) nor steps (the body's pseudostate has no transitions).

    Compare `GkatNormal.wh_one_total`: `while 1 do a` — the same guard — *is* total.  So the
    guard is not what breaks it.  A body that can do nothing is. -/
theorem wh_test_not_total :
    ¬ Total (certifiedThompson Unit Unit (.wh BExp.one (.test BExp.one))).aut := by
  intro h
  rcases h Unit (fun _ _ => true) () none with hh | hs
  · have hfalse : (false : Bool) = true := hh
    exact Bool.noConfusion hfalse
  · have hfalse : (false : Bool) = true := hs
    exact Bool.noConfusion hfalse

/-! ## The halt guard is `E`

    The pseudostate's halt guard is the syntactic `E(e)` — the very Boolean expression `W3`'s
    side condition is about.  Structural, and it is what lets `BodySteps` be checked by
    computing on syntax rather than by inspecting an automaton. -/

theorem initHlt_eq_E (e : Exp A T) : (certifiedThompson A T e).aut.initHlt = E e := by
  induction e with
  | act p => rfl
  | test b => rfl
  | seq f h ihf ihh =>
      show BExp.and (certifiedThompson A T f).aut.initHlt
        (certifiedThompson A T h).aut.initHlt = BExp.and (E f) (E h)
      rw [ihf, ihh]
  | ite c f h ihf ihh =>
      show BExp.or (BExp.and c (certifiedThompson A T f).aut.initHlt)
          (BExp.and (BExp.not c) (certifiedThompson A T h).aut.initHlt)
        = BExp.or (BExp.and c (E f)) (BExp.and (BExp.not c) (E h))
      rw [ihf, ihh]
  | wh c f _ => rfl

/-! ## Restriction to the immediate-halt region

    The one algebraic fact the loop case needs: **a program restricted to the atoms where it
    can halt immediately is `skip`**.  Determinism is why — at such an atom the program halts,
    and a deterministic automaton that halts cannot also step, so the empty word is all it
    accepts.

    Stated with an arbitrary antecedent guard `b ≤ E(e)` rather than `E(e)` itself, because
    that is what makes the induction go through: the `seq` case needs it at `b`, and the `ite`
    case at `b ∧ c` and `b ∧ ¬c`. -/

theorem test_restrict (e : Exp A T) : ∀ (b : BExp T), GuardImplies b (E e) →
    EquivBA (.seq (.test b) e : Exp A T) (.test b) := by
  induction e with
  | act p =>
      intro b hle
      have hunsat : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = false := by
        intro X W x
        cases hb : bval W b x with
        | false => rfl
        | true =>
            have hc : (false : Bool) = true := hle X W x hb
            exact Bool.noConfusion hc
      exact EquivBA.trans (GkatGuardedAlgebra.test_unsat_seq (.act p) hunsat)
        (EquivBA.baTest (fun X W x => (hunsat X W x).symm))
  | test c =>
      intro b hle
      exact EquivBA.trans (EquivBA.s6 b c)
        (EquivBA.baTest (GkatGuardedAlgebra.band_of_implies hle))
  | seq f h ihf ihh =>
      intro b hle
      have hf : GuardImplies b (E f) := fun X W x hb =>
        ((Bool.and_eq_true _ _).mp (hle X W x hb)).1
      have hh : GuardImplies b (E h) := fun X W x hb =>
        ((Bool.and_eq_true _ _).mp (hle X W x hb)).2
      exact EquivBA.trans (EquivBA.symm (GkatGuardedAlgebra.seq_assoc (.test b) f h))
        (EquivBA.trans
          (EquivBA.seq_c (ihf b hf) (EquivBA.base (Equiv.refl h)))
          (ihh b hh))
  | ite c f h ihf ihh =>
      intro b hle
      have hf : GuardImplies (BExp.and b c) (E f) := by
        intro X W x hbc
        have hb : bval W b x = true := ((Bool.and_eq_true _ _).mp hbc).1
        have hc : bval W c x = true := ((Bool.and_eq_true _ _).mp hbc).2
        have hor : (bval W c x && bval W (E f) x ||
            (!bval W c x) && bval W (E h) x) = true := hle X W x hb
        rw [hc] at hor
        simpa using hor
      have hh : GuardImplies (BExp.and (BExp.not (BExp.and b c)) b) (E h) := by
        intro X W x hbc
        have hnbc : (!(bval W b x && bval W c x)) = true := ((Bool.and_eq_true _ _).mp hbc).1
        have hb : bval W b x = true := ((Bool.and_eq_true _ _).mp hbc).2
        have hor : (bval W c x && bval W (E f) x ||
            (!bval W c x) && bval W (E h) x) = true := hle X W x hb
        rw [hb] at hnbc
        have hc : bval W c x = false := by
          cases hcv : bval W c x with
          | false => rfl
          | true => rw [hcv] at hnbc; exact Bool.noConfusion hnbc
        rw [hc] at hor
        simpa using hor
      refine EquivBA.trans (GkatGuardedAlgebra.test_seq_ite b c f h) ?_
      refine EquivBA.trans (EquivBA.base (Equiv.u4 (.and b c) f (.seq (.test b) h))) ?_
      refine EquivBA.trans
        (EquivBA.ite_c (ihf (.and b c) hf) (EquivBA.base (Equiv.refl (.seq (.test b) h)))) ?_
      refine EquivBA.trans
        (GkatGuardedAlgebra.ite_restrict_else (.and b c) (.test (.and b c))
          (.seq (.test b) h)) ?_
      refine EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl (.test (.and b c))))
          (GkatGuardedAlgebra.test_seq_merge (.not (.and b c)) b h)) ?_
      refine EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl (.test (.and b c))))
          (ihh (.and (.not (.and b c)) b) hh)) ?_
      refine EquivBA.trans
        (ite_tests_ba (.and b c) (.and b c) (.and (.not (.and b c)) b)) ?_
      refine EquivBA.baTest ?_
      intro X W x
      show ((bval W b x && bval W c x) && (bval W b x && bval W c x) ||
        (!(bval W b x && bval W c x)) &&
          ((!(bval W b x && bval W c x)) && bval W b x)) = bval W b x
      cases bval W b x <;> cases bval W c x <;> rfl
  | wh c f _ =>
      intro b hle
      have hunsat : ∀ (X : Type) (W : T → X → Bool) (x : X),
          bval W (BExp.and b c) x = bval W (BExp.zero : BExp T) x := by
        intro X W x
        show (bval W b x && bval W c x) = false
        cases hb : bval W b x with
        | false => rfl
        | true =>
            have hnc : (!bval W c x) = true := hle X W x hb
            cases hc : bval W c x with
            | false => rfl
            | true => rw [hc] at hnc; exact Bool.noConfusion hnc
      refine EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl (.test b))) (EquivBA.base (Equiv.w1 c f))) ?_
      refine EquivBA.trans
        (GkatGuardedAlgebra.test_seq_ite b c (.seq f (.wh c f)) (.test .one)) ?_
      refine EquivBA.trans (EquivBA.ite_guard hunsat) ?_
      refine EquivBA.trans (EquivBA.base (ite_zero (.seq f (.wh c f)) (.seq (.test b) (.test .one)))) ?_
      exact GkatGuardedAlgebra.seq_one (.test b)

/-- **A program is `skip` on the atoms where it halts immediately.** -/
theorem halt_restriction (e : Exp A T) :
    EquivBA (.seq (.test (E e)) e : Exp A T) (.test (E e)) :=
  test_restrict e (E e) (fun _ _ _ h => h)

/-- **The decomposition.**  `e ≡ e +_{¬E e} 1` — every program splits into its
    immediate-halt region, where it is `skip`, and the rest, where it must act.

    This is the step the literature identifies as the one a productive normal form needs, and
    it is exactly `halt_restriction` seen through `U1` and `U4`. -/
theorem decomposes (e : Exp A T) :
    EquivBA (e : Exp A T) (.ite (.not (E e)) e (.test BExp.one)) := by
  have hu1 : EquivBA (e : Exp A T) (.ite (E e) e e) :=
    EquivBA.symm (EquivBA.base (Equiv.u1 (E e) e))
  have hthen : EquivBA (.ite (E e) (.test BExp.one) e : Exp A T) (.ite (E e) e e) :=
    EquivBA.trans (EquivBA.base (Equiv.u4 (E e) (.test .one) e))
      (EquivBA.trans
        (EquivBA.ite_c (GkatGuardedAlgebra.seq_one (.test (E e)))
          (EquivBA.base (Equiv.refl e)))
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.symm (halt_restriction e))
            (EquivBA.base (Equiv.refl e)))
          (EquivBA.symm (EquivBA.base (Equiv.u4 (E e) e e)))))
  exact EquivBA.trans (EquivBA.trans hu1 (EquivBA.symm hthen))
    (EquivBA.base (Equiv.u2 (E e) (.test .one) e))

/-! ## The loop case, closed -/

/-- The settled loop body: `if ¬E(e) then e else diverge`.  Its own `E` is `0` *for every*
    `e` — the immediate-halt region has been replaced by divergence rather than pruned, which
    is why the result steps everywhere instead of merely failing to halt. -/
def settledBody (e : Exp A T) (a : A) : Exp A T := .ite (.not (E e)) e (div a)

theorem settled_settledBody (a : A) {e : Exp A T} (h : Settled e) :
    Settled (settledBody e a) :=
  Settled.ite _ h (settled_div a)

/-- The settled body never halts immediately, whatever `e` was. -/
theorem settledBody_never_halts (e : Exp A T) (a : A) {X : Type} (W : T → X → Bool) (x : X) :
    bval W (certifiedThompson A T (settledBody e a)).aut.initHlt x = false := by
  rw [initHlt_eq_E]
  show ((!bval W (E e) x) && bval W (E e) x ||
    (!(!bval W (E e) x)) && (!bval W (BExp.one : BExp T) x)) = false
  cases bval W (E e) x <;> rfl

/-- …so it steps under *every* guard, and the loop side condition is discharged outright. -/
theorem bodySteps_settledBody (g : BExp T) {e : Exp A T} (a : A) (hs : Settled e) :
    BodySteps (certifiedThompson A T (settledBody e a)).aut g := by
  intro X W x _
  rcases (totalParts_of_settled (settled_settledBody a hs)).init X W x with hh | hstep
  · rw [settledBody_never_halts e a W x] at hh
    exact Bool.noConfusion hh
  · exact hstep

/-- **The loop rewrite is provable.**  `while g do e ≡ while g do (if ¬E(e) then e else 0)`.

    The derivation is four steps and uses `W2` for exactly what `W2` is for — "non-productive
    loop iterations do not contribute":

      `while g do e`
        ≡ `while g do (e +_{¬E e} 1)`      decomposition
        ≡ `while g do ((¬E e)? ; e)`       W2
        ≡ `while g do (e +_{¬E e} 0)`      an assertion is a guarded choice with a dead arm
        ≡ `while g do (e +_{¬E e} div)`    the sink is provably `0`

    The last step is the one that matters.  `W2`'s own normal form `(¬E e)?·e` is *productive*
    — its `E` is `0` — but its automaton is **stuck** at immediate-halt atoms, not total.
    Replacing the dead arm by the sink keeps `E = 0` and makes it step instead. -/
theorem loop_settles (g : BExp T) (e : Exp A T) (a : A) :
    EquivBA (.wh g e : Exp A T) (.wh g (settledBody e a)) :=
  EquivBA.trans (EquivBA.wh_c (decomposes e))
    (EquivBA.trans (EquivBA.base (Equiv.w2 g (.not (E e)) e))
      (EquivBA.trans
        (EquivBA.wh_c (EquivBA.symm (GkatGuardedAlgebra.ite_zero_else (.not (E e)) e)))
        (EquivBA.wh_c (EquivBA.ite_c (EquivBA.base (Equiv.refl e))
          (EquivBA.symm (GkatNormal.wh_one_provably_zero (.act a)))))))

/-! ## What remains -/

/-- **The remaining obligation.**  Every program is provably equal to a settled one.

    The `test` case is `totalTest_equiv`; `seq` and `ite` are immediate from the induction
    hypotheses, since neither constructor imposes a condition.  The open case is `wh`: a loop
    whose body can halt immediately has to be rewritten so that it cannot, and that is the
    single statement the totalisation route now rests on. -/
def SettledReachable (A T : Type) : Prop :=
  ∀ e : Exp A T, ∃ h : Exp A T, EquivBA e h ∧ Settled h

/-- If it holds, every program is provably equal to one with a total automaton — which is the
    hypothesis `step_agree_of_total` needs, and the reason the route was taken. -/
theorem total_form_of_settledReachable (hs : SettledReachable A T) (e : Exp A T) :
    ∃ h : Exp A T, EquivBA e h ∧ Total (certifiedThompson A T h).aut := by
  obtain ⟨h, heq, hset⟩ := hs e
  exact ⟨h, heq, total_of_settled hset⟩

/-- **Every program is provably equal to a settled one** — hence to one whose automaton is
    total.  The induction is now routine: `test` uses the sink, `seq` and `ite` impose no
    condition at all, and `wh` uses `loop_settles`.

    Needs an action, and that is the honest boundary of the result: with `A` empty there is no
    divergent program to route stuck configurations into, and the partiality is irreparable. -/
theorem settledReachable (a : A) : SettledReachable A T := by
  intro e
  induction e with
  | act p => exact ⟨.act p, EquivBA.base (Equiv.refl _), Settled.act p⟩
  | test b => exact ⟨totalTest a b, totalTest_equiv a b, settled_totalTest a b⟩
  | seq f h ihf ihh =>
      obtain ⟨f', hf, sf⟩ := ihf
      obtain ⟨h', hh, sh⟩ := ihh
      exact ⟨.seq f' h', EquivBA.seq_c hf hh, Settled.seq sf sh⟩
  | ite c f h ihf ihh =>
      obtain ⟨f', hf, sf⟩ := ihf
      obtain ⟨h', hh, sh⟩ := ihh
      exact ⟨.ite c f' h', EquivBA.ite_c hf hh, Settled.ite c sf sh⟩
  | wh c f ihf =>
      obtain ⟨f', hf, sf⟩ := ihf
      exact ⟨.wh c (settledBody f' a),
        EquivBA.trans (EquivBA.wh_c hf) (loop_settles c f' a),
        Settled.wh c (settled_settledBody a sf) (bodySteps_settledBody c a sf)⟩

/-- **Totalisation, done.**  Every program is provably equal to one whose automaton is total
    — the hypothesis `step_agree_of_total` needs, now discharged rather than assumed. -/
theorem total_form (a : A) (e : Exp A T) :
    ∃ h : Exp A T, EquivBA e h ∧ Total (certifiedThompson A T h).aut :=
  total_form_of_settledReachable (settledReachable a) e

/-! ## Where productivity is actually consumed

    With `settledReachable` proved, the natural move is to swap `Total` for `Productive`
    everywhere and delete `Normalizable` from the chain.  That works for one of the two uses
    and not the other, and the difference is worth pinning down rather than glossing.

    `crossEquiv_step` — language-equivalent states take the *same action* to
    language-equivalent targets — consumes productivity in exactly one line: it needs a word
    accepted from the state just stepped into, so that it can push that word through the
    language equivalence and read off the other side's action.  The lemma below is that proof
    with the hypothesis narrowed to what it uses: liveness at the single stepped-to state,
    under the single interpretation in play.  `crossEquiv_step` is now a corollary.

    Totality cannot supply that.  `step_agree_of_total` proves the other side *steps*, which
    is strictly weaker than stepping with the same action: if both targets are dead, both
    languages are empty, the two states are language-equivalent, and nothing constrains the
    two actions to agree.  And dead states cannot be normalised away, because the sink is one
    — `div a`'s core state accepts nothing, and the sink is what totalisation runs on.

    So the residue is sharp, and it is not "totality is too weak".  It is that dead states
    must be made *canonical* — every one of them the same sink, stepping with the same
    action — rather than merely present.  `DeadCanonical` names that. -/

/-- **The bridge, isolated.**  If the two sides step along the *same* action, their targets
    are language-equivalent — with no liveness hypothesis anywhere.  Everything productivity
    was ever needed for is the *action*; once that agrees, the rest is the sum-interpretation
    transfer and nothing else. -/
theorem crossEquiv_targets {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {s : Option S₁} {t : Option S₂} (h : CrossEquiv a b s t)
    {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁} {t' : Option S₂}
    (hs : autStep W a.toGAut s x = some (q, s'))
    (ht : autStep W b.toGAut t x = some (q, t')) :
    CrossEquiv a b s' t' := by
  intro Y V gs
  obtain ⟨y, v⟩ := gs
  let W'' : T → Sum X Y → Bool := fun c => Sum.elim (W c) (V c)
  have hl : ∀ (c : T) (z : X), W'' c (Sum.inl z) = W c z := fun _ _ => rfl
  have hr : ∀ (c : T) (z : Y), W'' c (Sum.inr z) = V c z := fun _ _ => rfl
  have pushA : ∀ u : Option S₁,
      autRun W'' a.toGAut u (Sum.inr y) (mapAtoms Sum.inr v) ↔ autRun V a.toGAut u y v :=
    fun u => autRun_transfer hr a.toGAut u y v
  have pushB : ∀ u : Option S₂,
      autRun W'' b.toGAut u (Sum.inr y) (mapAtoms Sum.inr v) ↔ autRun V b.toGAut u y v :=
    fun u => autRun_transfer hr b.toGAut u y v
  have step_l : autStep W'' a.toGAut s (Sum.inl x) = some (q, s') := by
    rw [show autStep W'' a.toGAut s (Sum.inl x) = autStep W a.toGAut s x from
      firstMatch_transfer hl (a.toGAut.trans s) x]
    exact hs
  have step_r : autStep W'' b.toGAut t (Sum.inl x) = some (q, t') := by
    rw [show autStep W'' b.toGAut t (Sum.inl x) = autStep W b.toGAut t x from
      firstMatch_transfer hl (b.toGAut.trans t) x]
    exact ht
  have bridge := h (Sum X Y) W'' (Sum.inl x, (q, Sum.inr y) :: mapAtoms Sum.inr v)
  change (∃ u, autStep W'' a.toGAut s (Sum.inl x) = some (q, u) ∧
      autRun W'' a.toGAut u (Sum.inr y) (mapAtoms Sum.inr v)) ↔
    (∃ u, autStep W'' b.toGAut t (Sum.inl x) = some (q, u) ∧
      autRun W'' b.toGAut u (Sum.inr y) (mapAtoms Sum.inr v)) at bridge
  constructor
  · intro hrun
    obtain ⟨u, hu, hru⟩ := bridge.mp ⟨s', step_l, (pushA s').mpr hrun⟩
    rw [step_r] at hu
    have huv : u = t' := congrArg Prod.snd (Option.some.inj hu.symm)
    exact (pushB t').mp (huv ▸ hru)
  · intro hrun
    obtain ⟨u, hu, hru⟩ := bridge.mpr ⟨t', step_r, (pushB t').mpr hrun⟩
    rw [step_l] at hu
    have huv : u = s' := congrArg Prod.snd (Option.some.inj hu.symm)
    exact (pushA s').mp (huv ▸ hru)

/-- **`crossEquiv_step`, with the hypothesis narrowed to what the proof uses.**  Only the
    state just stepped into must accept something, and only under the interpretation at
    hand — not every state under every interpretation. -/
theorem crossEquiv_step_at {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {s : Option S₁} {t : Option S₂} (h : CrossEquiv a b s t)
    {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁}
    (hs : autStep W a.toGAut s x = some (q, s'))
    (hlive : ∃ (x' : X) (w : List (A × X)), autRun W a.toGAut s' x' w) :
    ∃ t', autStep W b.toGAut t x = some (q, t') ∧ CrossEquiv a b s' t' := by
  obtain ⟨x', w, hw⟩ := hlive
  obtain ⟨t', ht, _⟩ := (h X W (x, (q, x') :: w)).mp ⟨s', hs, hw⟩
  exact ⟨t', ht, crossEquiv_targets h W x hs ht⟩

/-- The original is the corollary: global productivity is pointwise liveness, everywhere. -/
theorem crossEquiv_step_of_productive {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (hprod : Productive a) {s : Option S₁} {t : Option S₂}
    (h : CrossEquiv a b s t) {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁}
    (hs : autStep W a.toGAut s x = some (q, s')) :
    ∃ t', autStep W b.toGAut t x = some (q, t') ∧ CrossEquiv a b s' t' :=
  crossEquiv_step_at h W x hs (hprod X W x s')

/-- **The residue, named.**  Every step into a state that accepts nothing carries the same
    fixed action.  This is what totality cannot supply and what the counterexample needs:
    two dead targets are language-equivalent whatever actions reach them, so agreement has to
    be imposed by making the dead part canonical.

    It is satisfiable in principle — the sink `div a₀` steps with `a₀` into itself — so the
    remaining normalisation is "route every dead region into *the* sink", not "remove dead
    regions", which is the move `Normalizable` tried and `wh_simple_not_productive` refuted. -/
def DeadCanonical {S : Type} (a₀ : A) (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X) (s : Option S) (q : A) (s' : Option S),
    autStep W aut.toGAut s x = some (q, s') →
    (∀ (x' : X) (w : List (A × X)), ¬ autRun W aut.toGAut s' x' w) → q = a₀

/-- **The payoff: `Total` + `DeadCanonical` restores the bisimulation step.**

    This is what productivity was standing in for, and it now holds without it.  The proof
    splits on whether the state just stepped into accepts anything under the interpretation
    at hand:

      * **live** — `crossEquiv_step_at` applies verbatim;
      * **dead** — `step_agree_of_total` says the other side steps, and its target must be
        dead too (a word accepted there would transfer back and revive `s'`), so
        `DeadCanonical` forces *both* actions to be `a₀` and the two agree.

    Note where each hypothesis is spent.  Totality gives the other side a *step*;
    dead-canonicity gives that step the right *action*; and `crossEquiv_targets` — which needs
    neither — carries the language equivalence to the targets.  Together they replace
    `Productive` in the one place it was ever used. -/
theorem crossEquiv_step_of_canonical {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (a₀ : A)
    (hd : HaltStepDisjoint a) (htb : Total b)
    (hca : DeadCanonical a₀ a) (hcb : DeadCanonical a₀ b)
    {s : Option S₁} {t : Option S₂} (h : CrossEquiv a b s t)
    {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁}
    (hs : autStep W a.toGAut s x = some (q, s')) :
    ∃ t', autStep W b.toGAut t x = some (q, t') ∧ CrossEquiv a b s' t' := by
  by_cases hlive : ∃ (x' : X) (w : List (A × X)), autRun W a.toGAut s' x' w
  · exact crossEquiv_step_at h W x hs hlive
  · -- `s'` is dead under `W`
    have hdead : ∀ (x' : X) (w : List (A × X)), ¬ autRun W a.toGAut s' x' w := by
      intro x' w hw
      exact hlive ⟨x', w, hw⟩
    have hqa : q = a₀ := hca X W x s q s' hs hdead
    have hsome := step_agree_of_total hd htb h W x hs
    cases hb : autStep W b.toGAut t x with
    | none => rw [hb] at hsome; exact Bool.noConfusion hsome
    | some p =>
        obtain ⟨q₂, t'⟩ := p
        -- the other side's target is dead too, or a word there would revive `s'`
        have hdead' : ∀ (y : X) (v : List (A × X)), ¬ autRun W b.toGAut t' y v := by
          intro y v hv
          have hbrun : autRun W b.toGAut t x ((q₂, y) :: v) := ⟨t', hb, hv⟩
          obtain ⟨s'', hs2, hrun2⟩ := (h X W (x, (q₂, y) :: v)).mpr hbrun
          have hpair : (q, s') = (q₂, s'') := Option.some.inj (hs.symm.trans hs2)
          have htgt : s'' = s' := (congrArg (fun z : A × Option S₁ => z.2) hpair).symm
          exact hdead y v (htgt ▸ hrun2)
        have hqb : q₂ = a₀ := hcb X W x t q₂ t' hb hdead'
        have hqq : q₂ = q := hqb.trans hqa.symm
        have hbq : autStep W b.toGAut t x = some (q, t') := by rw [hb, hqq]
        exact ⟨t', by rw [hqq], crossEquiv_targets h W x hs hbq⟩

/-- **`DeadCanonical` is a strict weakening of productivity.**  A productive automaton has no
    dead states at all, so it satisfies the condition vacuously — for every `a₀` at once.  So
    `crossEquiv_step_of_canonical` genuinely subsumes `crossEquiv_step_of_productive` rather
    than trading one hypothesis for an incomparable one. -/
theorem deadCanonical_of_productive (a₀ : A) {aut : InitializedGAut S A T}
    (h : Productive aut) : DeadCanonical a₀ aut := by
  intro X W x s _ s' _ hdead
  obtain ⟨x', w, hw⟩ := h X W x s'
  exact absurd hw (hdead x' w)

/-- The sink's own core state accepts nothing — so dead states are not an artefact to be
    eliminated, they are what totalisation *introduces*.  Non-vacuity for `DeadCanonical`
    being about canonicity rather than absence. -/
theorem sink_state_dead (a₀ : A) {X : Type} (W : T → X → Bool) (x' : X)
    (w : List (A × X)) :
    ¬ autRun W (certifiedThompson A T (div a₀)).aut.toGAut (some ()) x' w := by
  induction w generalizing x' with
  | nil => intro h; exact Bool.noConfusion (show (false : Bool) = true from h)
  | cons hd tl ih =>
      rintro ⟨u, hu, hru⟩
      have hu' : ((a₀, some ()) : A × Option Unit) = (hd.1, u) := by
        have hstep : autStep W (certifiedThompson A T (div a₀)).aut.toGAut (some ()) x'
            = some (a₀, some ()) := rfl
        rw [hstep] at hu
        exact Option.some.inj hu
      have htgt : u = some () := (congrArg (fun z : A × Option Unit => z.2) hu').symm
      exact ih hd.2 (htgt ▸ hru)

/-! ## Completeness, with normalisation discharged -/

/-- **REFUTED — see `not_totalCommonTarget`.**  The behavioural-target hypothesis, restated
    for *total* automata.  Totality is not enough: two total, language-equivalent programs can
    step into dead states along *different* actions, and a cover preserves actions pointwise,
    so no common target exists.  Kept because the refutation is what pins `DeadCanonical` down
    as necessary rather than convenient. -/
def TotalCommonTarget (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    Total (certifiedThompson A T e).aut → Total (certifiedThompson A T f).aut →
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T e).aut m)
      (ψ : InitCover (certifiedThompson A T f).aut m),
      Nonempty (GkatPullback.Base φ ψ)

/-- **VACUOUS — `not_totalCommonTarget` refutes the hypothesis.**  Kept for the record: the
    implication is valid, and the shape is right; it is `TotalCommonTarget` that is false.
    `completeness_of_canonical` is the repaired version.

    **Completeness from two statements instead of three.**

    `completeness_of_normalized` needed `Normalizable`, `NormalCommonTarget` and
    `PullbackCovered`.  `Normalizable` is false — `wh_simple_not_productive` — and it is now
    gone: `settledReachable` replaces it and is *proved*, so the normalisation step is
    discharged rather than assumed.

    The null case-split disappears too.  `Normalizable` had to exclude null programs, since
    `0` is not productive; totalisation has no such exclusion — `0` settles to the sink, which
    is total — so the argument runs uniformly over every pair. -/
theorem completeness_of_total (a : A)
    (hct : TotalCommonTarget A T) (hpc : PullbackCovered A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨e', hee', hse⟩ := settledReachable a e
  obtain ⟨f', hff', hsf⟩ := settledReachable a f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans
      (sound_BA (V := W) hff' gs)
  obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := hct e' f' heq' (total_of_settled hse) (total_of_settled hsf)
  obtain ⟨h, ⟨χ⟩⟩ := hpc e' f' Q m φ ψ base
  exact EquivBA.trans hee'
    (EquivBA.trans
      (equivBA_of_common_refinement χ (GkatPullback.pullbackFst φ ψ base)
        (GkatPullback.pullbackSnd φ ψ base))
      (EquivBA.symm hff'))

#print axioms crossEquiv_targets
#print axioms crossEquiv_step_at
#print axioms crossEquiv_step_of_canonical
#print axioms deadCanonical_of_productive
#print axioms sink_state_dead
#print axioms completeness_of_total
#print axioms initHlt_eq_E
#print axioms halt_restriction
#print axioms decomposes
#print axioms loop_settles
#print axioms settledReachable
#print axioms total_form
#print axioms total_of_parts
#print axioms parts_of_total
#print axioms totalParts_ite
#print axioms totalParts_seq
#print axioms totalParts_loop
#print axioms total_of_settled
#print axioms totalTest_equiv
#print axioms totalTest_total
#print axioms test_zero_not_total
#print axioms wh_test_not_total

/-! ## Totality is not enough — and the reason is the actions, not the steps

    The previous section argued that `Total` cannot replace `Productive` in
    `crossEquiv_step`, because two dead targets are language-equivalent whatever actions reach
    them.  That was an argument about a proof.  This is the statement itself, refuted.

        p  =  if c then (a ; diverge) else 1?
        q  =  if c then (b ; diverge) else 1?

    Both are settled, hence total.  Both are provably `if c then 0 else 1?`, since `e · 0 ≡ 0`
    is `S3` and the sink is provably `0` — so they are uniformly language-equivalent.  And at
    a `c` atom `p` steps along `a` while `q` steps along `b`.

    A cover preserves the action pointwise (`initStep_eq` carries `o.1` through untouched), so
    a common target would have to step along `a` and along `b` at the same atom.  There is
    none.

    This is the acceptance condition doing the damage.  For a deterministic Mealy machine
    bisimulation *does* coincide with language equivalence — but a Mealy machine has no
    accepting states and therefore no dead ones.  GKAT's automata halt, so a state can accept
    nothing at all, and every route into such a state is behaviourally invisible while
    remaining structurally visible to a cover.

    So `DeadCanonical` is not a convenience.  Some condition making the dead part canonical is
    *necessary*, and productivity was standing in for it all along. -/

private abbrev cG : BExp Unit := .prim ()

/-- `if c then (a ; diverge) else 1?`, with `a = false`. -/
private abbrev deadP : Exp Bool Unit := .ite cG (.seq (.act false) (div false)) (.test .one)

/-- The same program with a different action into the dead region. -/
private abbrev deadQ : Exp Bool Unit := .ite cG (.seq (.act true) (div false)) (.test .one)

private abbrev wAll : Unit → Unit → Bool := fun _ _ => true

/-- Anything followed by the sink is provably `0` — `S3`, once the sink is `0`. -/
private theorem seq_div_zero (p : Bool) :
    EquivBA (.seq (.act p) (div false) : Exp Bool Unit) (.test .zero) :=
  EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (GkatNormal.wh_one_provably_zero (.act false)))
    (EquivBA.base (Equiv.s3 (.act p)))

theorem deadP_equiv_deadQ : EquivBA (deadP) (deadQ) :=
  EquivBA.trans (EquivBA.ite_c (seq_div_zero false) (EquivBA.base (Equiv.refl _)))
    (EquivBA.symm (EquivBA.ite_c (seq_div_zero true) (EquivBA.base (Equiv.refl _))))

theorem deadP_lang_deadQ : UniformLanguageEquivalent deadP deadQ :=
  fun _ W gs => sound_BA (V := W) deadP_equiv_deadQ gs

theorem deadP_settled : Settled deadP :=
  Settled.ite _ (Settled.seq (Settled.act false) (settled_div false)) Settled.one

theorem deadQ_settled : Settled deadQ :=
  Settled.ite _ (Settled.seq (Settled.act true) (settled_div false)) Settled.one

/-- **No system covers both.**  At a `c` atom the two pseudostates step along different
    actions, and `initStep_eq` carries the action through unchanged. -/
theorem no_common_cover {Q : Type} {m : InitializedGAut Q Bool Unit}
    (φ : InitCover (certifiedThompson Bool Unit deadP).aut m)
    (ψ : InitCover (certifiedThompson Bool Unit deadQ).aut m) : False := by
  have hp := φ.initStep_eq Unit wAll ()
  have hq := ψ.initStep_eq Unit wAll ()
  rw [← hq] at hp
  have hbool : (false : Bool) = true :=
    congrArg (fun o : Option (Bool × Q) => (o.map (fun z : Bool × Q => z.1)).getD true) hp
  exact Bool.noConfusion hbool

/-- **`TotalCommonTarget` is false.**  Totality does not recover the behavioural target;
    something must make the dead part canonical. -/
theorem not_totalCommonTarget : ¬ TotalCommonTarget Bool Unit := by
  intro h
  obtain ⟨_, _, φ, ψ, _⟩ := h deadP deadQ deadP_lang_deadQ
    (total_of_settled deadP_settled) (total_of_settled deadQ_settled)
  exact no_common_cover φ ψ

#print axioms deadP_equiv_deadQ
#print axioms no_common_cover
#print axioms not_totalCommonTarget

/-! ## The span, without productivity

    `StepAgree` is the property the span construction actually consumes; `GkatQuotient` now
    takes it directly rather than `Productive`.  Two things supply it — `stepAgree_of_productive`
    and, here, totality with a canonical dead part — and only the second is achievable.

    What is left in `Matched` after the swap is `Reachable` and target-listing.  Listing is
    free for Thompson automata; reachability is not, and it is the other half of *trimming*:
    an automaton is trim when every state is both **accessible** (reachable from the start) and
    **co-accessible** (some accepting run leaves it).  `Reachable` is the accessible half.
    `DeadCanonical` is what stands in for the co-accessible half — GKAT cannot delete its dead
    states, since it must stay total, so it makes them all the same sink instead. -/

theorem stepAgree_of_canonical {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (a₀ : A)
    (hd : HaltStepDisjoint a) (htb : Total b)
    (hca : DeadCanonical a₀ a) (hcb : DeadCanonical a₀ b) : StepAgree a b := by
  intro s t h X W x q s' hs
  exact crossEquiv_step_of_canonical a₀ hd htb hca hcb h W x hs

/-- Everything `Matched` needs, with productivity replaced throughout. -/
noncomputable def matched_of_canonical {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (a₀ : A)
    (hda : HaltStepDisjoint a) (hdb : HaltStepDisjoint b)
    (hta : Total a) (htb : Total b)
    (hca : DeadCanonical a₀ a) (hcb : DeadCanonical a₀ b)
    (ra : Reachable a) (rb : Reachable b)
    (la : GAutTargetsListed a.toGAut) (lb : GAutTargetsListed b.toGAut)
    (hinit : CrossEquiv a b none none) : GkatQuotient.Matched a b :=
  GkatQuotient.matched_of_reachable
    (stepAgree_of_canonical a₀ hda htb hca hcb)
    (stepAgree_of_canonical a₀ hdb hta hcb hca)
    (stepAgree_of_canonical a₀ hdb htb hcb hcb) ra rb la lb hinit

/-- **The behavioural target exists for total, dead-canonical, reachable automata.**  This is
    `NormalCommonTarget`'s construction with `Productive` — which is unachievable — replaced by
    two conditions, one of which is now proved achievable. -/
theorem span_of_canonical {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (a₀ : A)
    (hda : HaltStepDisjoint a) (hdb : HaltStepDisjoint b)
    (hta : Total a) (htb : Total b)
    (hca : DeadCanonical a₀ a) (hcb : DeadCanonical a₀ b)
    (ra : Reachable a) (rb : Reachable b)
    (la : GAutTargetsListed a.toGAut) (lb : GAutTargetsListed b.toGAut)
    (hinit : CrossEquiv a b none none) :
    Nonempty (InitCover a (GkatQuotient.target b)) ∧
      Nonempty (InitCover b (GkatQuotient.target b)) :=
  GkatQuotient.span_of_matched
    (matched_of_canonical a₀ hda hdb hta htb hca hcb ra rb la lb hinit)

#print axioms stepAgree_of_canonical
#print axioms span_of_canonical

/-! ## Structural facts the chain needs

    Two things that were being carried as hypotheses and are simply true. -/

/-- Every state of a Thompson automaton is listed. -/
theorem thompson_states_complete (p : Exp A T) :
    ∀ s : (certifiedThompson A T p).State, s ∈ (certifiedThompson A T p).aut.core.states := by
  induction p with
  | test b => intro s; exact nomatch s
  | act q => intro s; cases s; exact List.Mem.head _
  | seq e f ihe ihf =>
      intro s
      show s ∈ (certifiedThompson A T e).aut.core.states.map Sum.inl ++
        (certifiedThompson A T f).aut.core.states.map Sum.inr
      cases s with
      | inl u => exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨u, ihe u, rfl⟩))
      | inr v => exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨v, ihf v, rfl⟩))
  | ite g e f ihe ihf =>
      intro s
      show s ∈ (certifiedThompson A T e).aut.core.states.map Sum.inl ++
        (certifiedThompson A T f).aut.core.states.map Sum.inr
      cases s with
      | inl u => exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨u, ihe u, rfl⟩))
      | inr v => exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨v, ihf v, rfl⟩))
  | wh g e ihe => intro s; exact ihe s

/-- **Halting excludes stepping, at every state.**  `UniformWF` gives it at listed states, and
    every state is listed. -/
theorem haltStepDisjoint_thompson (p : Exp A T) :
    HaltStepDisjoint (certifiedThompson A T p).aut := by
  intro X W x s hh
  refine (certifiedThompson_uniformWF p X W).1 s ?_ x hh
  show s ∈ none :: (certifiedThompson A T p).aut.core.states.map some
  cases s with
  | none => exact List.Mem.head _
  | some u =>
      exact List.Mem.tail _ (List.mem_map.mpr ⟨u, thompson_states_complete p u, rfl⟩)

/-! ## Dead-canonicity is inherited by guarded choice

    The padding needs the padded programs to be dead-canonical, and they are as soon as their
    branches are.  `ite` only relabels: core states keep their own dynamics under `inl`/`inr`,
    and the entry transitions keep their branch's actions.  So a dead state of the composite is
    a dead state of a branch, entered along the branch's own action. -/

private theorem fmSomeF {S R X : Type} (W : T → X → Bool) (x : X) (F : S → R)
    (Lst : List (BExp T × A × S)) :
    firstMatch W x ((Lst.map (fun t => (t.1, t.2.1, F t.2.2))).map
        (fun t => (t.1, t.2.1, some t.2.2)))
      = (firstMatch W x Lst).map (fun o => (o.1, some (F o.2))) := by
  induction Lst with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨q, act, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      cases hq : bval W q x
      · simpa [hq] using ih
      · simp [hq]

private theorem fmIte {S R X : Type} (W : T → X → Bool) (x : X) (P : BExp T) (F : S → R)
    (Lst : List (BExp T × A × S)) :
    firstMatch W x ((Lst.map (fun t => (BExp.and P t.1, t.2.1, F t.2.2))).map
        (fun t => (t.1, t.2.1, some t.2.2)))
      = if bval W P x then (firstMatch W x Lst).map (fun o => (o.1, some (F o.2))) else none := by
  induction Lst with
  | nil => cases hP : bval W P x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, act, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P q) x = (bval W P x && bval W q x) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hq : bval W q x <;> simp

private theorem map_some_inv {R Q : Type} {o : Option (A × R)} {F : R → Q} {q : A} {t : Q}
    (h : o.map (fun z => (z.1, F z.2)) = some (q, t)) : ∃ w, o = some (q, w) ∧ t = F w := by
  cases o with
  | none => exact absurd h (by simp)
  | some z =>
      obtain ⟨q', w⟩ := z
      simp only [Option.map_some] at h
      have hp : ((q', F w) : A × Q) = (q, t) := Option.some.inj h
      exact ⟨w, congrArg (fun c : A => some (c, w)) (congrArg (fun z : A × Q => z.1) hp),
        (congrArg (fun z : A × Q => z.2) hp).symm⟩

variable {S₁ S₂ : Type}

private theorem step_ite_inl (g : BExp T) (L : InitializedGAut S₁ A T)
    (R : InitializedGAut S₂ A T) (u : S₁) {X : Type} (W : T → X → Bool) (x : X) :
    autStep W (iteInitialized g L R).toGAut (some (Sum.inl u)) x
      = (firstMatch W x (L.core.trans u)).map (fun o => (o.1, some (Sum.inl o.2))) :=
  fmSomeF W x (fun v : S₁ => (Sum.inl v : Sum S₁ S₂)) (L.core.trans u)

private theorem step_ite_inr (g : BExp T) (L : InitializedGAut S₁ A T)
    (R : InitializedGAut S₂ A T) (v : S₂) {X : Type} (W : T → X → Bool) (x : X) :
    autStep W (iteInitialized g L R).toGAut (some (Sum.inr v)) x
      = (firstMatch W x (R.core.trans v)).map (fun o => (o.1, some (Sum.inr o.2))) :=
  fmSomeF W x (fun w : S₂ => (Sum.inr w : Sum S₁ S₂)) (R.core.trans v)

theorem autStep_ite_none (g : BExp T) (L : InitializedGAut S₁ A T)
    (R : InitializedGAut S₂ A T) {X : Type} (W : T → X → Bool) (x : X) :
    autStep W (iteInitialized g L R).toGAut none x
      = if bval W g x
        then (firstMatch W x L.initTrans).map (fun o => (o.1, some (Sum.inl o.2)))
        else (firstMatch W x R.initTrans).map (fun o => (o.1, some (Sum.inr o.2))) := by
  show firstMatch W x
      ((L.initTrans.map (fun t => (BExp.and g t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂))) ++
        R.initTrans.map (fun t =>
          (BExp.and (BExp.not g) t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂)))).map
        (fun t => (t.1, t.2.1, some t.2.2))) = _
  rw [List.map_append]
  have hl := fmIte (A := A) W x g (fun v : S₁ => (Sum.inl v : Sum S₁ S₂)) L.initTrans
  have hr := fmIte (A := A) W x (BExp.not g) (fun w : S₂ => (Sum.inr w : Sum S₁ S₂)) R.initTrans
  have hnot : bval W (BExp.not g) x = !bval W g x := rfl
  cases hg : bval W g x
  · rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg]; simp), hr, hnot, hg]
    simp
  · cases hf : firstMatch W x L.initTrans with
    | some o =>
        rw [firstMatch_append_some (x := (o.1, some (Sum.inl o.2)))
          _ _ _ _ (by rw [hl, hg, hf]; simp)]
        simp [hg]
    | none =>
        rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg, hf]; simp), hr, hnot, hg]
        simp

theorem autRun_ite_inl (g : BExp T) (L : InitializedGAut S₁ A T) (R : InitializedGAut S₂ A T)
    {X : Type} (W : T → X → Bool) :
    ∀ (w : List (A × X)) (u : S₁) (x : X),
      autRun W (iteInitialized g L R).toGAut (some (Sum.inl u)) x w
        ↔ autRun W L.toGAut (some u) x w := by
  intro w
  induction w with
  | nil => intro u x; exact Iff.rfl
  | cons hd tl ih =>
      intro u x
      constructor
      · rintro ⟨v, hv, hrun⟩
        rw [step_ite_inl] at hv
        obtain ⟨o, ho, hveq⟩ :=
          map_some_inv (F := fun w : S₁ => (some (Sum.inl w) : Option (Sum S₁ S₂))) hv
        refine ⟨some o, by rw [GkatQuotient.autStep_core, ho]; rfl, ?_⟩
        rw [hveq] at hrun
        exact (ih o hd.2).mp hrun
      · rintro ⟨v, hv, hrun⟩
        rw [GkatQuotient.autStep_core] at hv
        obtain ⟨o, ho, hveq⟩ := map_some_inv (F := fun w : S₁ => (some w : Option S₁)) hv
        refine ⟨some (Sum.inl o), by rw [step_ite_inl, ho]; rfl, ?_⟩
        rw [hveq] at hrun
        exact (ih o hd.2).mpr hrun

theorem autRun_ite_inr (g : BExp T) (L : InitializedGAut S₁ A T) (R : InitializedGAut S₂ A T)
    {X : Type} (W : T → X → Bool) :
    ∀ (w : List (A × X)) (v : S₂) (x : X),
      autRun W (iteInitialized g L R).toGAut (some (Sum.inr v)) x w
        ↔ autRun W R.toGAut (some v) x w := by
  intro w
  induction w with
  | nil => intro v x; exact Iff.rfl
  | cons hd tl ih =>
      intro v x
      constructor
      · rintro ⟨u, hu, hrun⟩
        rw [step_ite_inr] at hu
        obtain ⟨o, ho, hueq⟩ :=
          map_some_inv (F := fun w : S₂ => (some (Sum.inr w) : Option (Sum S₁ S₂))) hu
        refine ⟨some o, by rw [GkatQuotient.autStep_core, ho]; rfl, ?_⟩
        rw [hueq] at hrun
        exact (ih o hd.2).mp hrun
      · rintro ⟨u, hu, hrun⟩
        rw [GkatQuotient.autStep_core] at hu
        obtain ⟨o, ho, hueq⟩ := map_some_inv (F := fun w : S₂ => (some w : Option S₂)) hu
        refine ⟨some (Sum.inr o), by rw [step_ite_inr, ho]; rfl, ?_⟩
        rw [hueq] at hrun
        exact (ih o hd.2).mpr hrun

/-- **Guarded choice inherits dead-canonicity.** -/
theorem deadCanonical_ite (a₀ : A) (g : BExp T) {L : InitializedGAut S₁ A T}
    {R : InitializedGAut S₂ A T} (hL : DeadCanonical a₀ L) (hR : DeadCanonical a₀ R) :
    DeadCanonical a₀ (iteInitialized g L R) := by
  intro X W x s q s' hstep hdead
  cases s with
  | none =>
      cases hg : bval W g x
      · rw [autStep_ite_none, hg] at hstep
        simp only [Bool.false_eq_true, if_false] at hstep
        obtain ⟨o, ho, hs'⟩ :=
          map_some_inv (F := fun w : S₂ => (some (Sum.inr w) : Option (Sum S₁ S₂))) hstep
        refine hR X W x none q (some o) (by rw [GkatQuotient.autStep_init, ho]; rfl) ?_
        intro y v hv
        apply hdead y v
        rw [hs']
        exact (autRun_ite_inr g L R W v o y).mpr hv
      · rw [autStep_ite_none, hg] at hstep
        simp only [if_true] at hstep
        obtain ⟨o, ho, hs'⟩ :=
          map_some_inv (F := fun w : S₁ => (some (Sum.inl w) : Option (Sum S₁ S₂))) hstep
        refine hL X W x none q (some o) (by rw [GkatQuotient.autStep_init, ho]; rfl) ?_
        intro y v hv
        apply hdead y v
        rw [hs']
        exact (autRun_ite_inl g L R W v o y).mpr hv
  | some sv =>
      cases sv with
      | inl u =>
          rw [step_ite_inl] at hstep
          obtain ⟨o, ho, hs'⟩ :=
            map_some_inv (F := fun w : S₁ => (some (Sum.inl w) : Option (Sum S₁ S₂))) hstep
          refine hL X W x (some u) q (some o) (by rw [GkatQuotient.autStep_core, ho]; rfl) ?_
          intro y v hv
          apply hdead y v
          rw [hs']
          exact (autRun_ite_inl g L R W v o y).mpr hv
      | inr u =>
          rw [step_ite_inr] at hstep
          obtain ⟨o, ho, hs'⟩ :=
            map_some_inv (F := fun w : S₂ => (some (Sum.inr w) : Option (Sum S₁ S₂))) hstep
          refine hR X W x (some u) q (some o) (by rw [GkatQuotient.autStep_core, ho]; rfl) ?_
          intro y v hv
          apply hdead y v
          rw [hs']
          exact (autRun_ite_inr g L R W v o y).mpr hv

/-- The sink is dead-canonical for its own action, trivially: every transition it has carries
    `a₀`. -/
theorem deadCanonical_div (a₀ : A) :
    DeadCanonical a₀ (certifiedThompson A T (div a₀)).aut := by
  intro X W x s q s' hstep _
  cases s with
  | none =>
      have h : autStep W (certifiedThompson A T (div a₀)).aut.toGAut none x
        = some (a₀, some ()) := rfl
      rw [h] at hstep
      exact congrArg (fun z : A × Option Unit => z.1) (Option.some.inj hstep.symm)
  | some u =>
      cases u
      have h : autStep W (certifiedThompson A T (div a₀)).aut.toGAut (some ()) x
        = some (a₀, some ()) := rfl
      rw [h] at hstep
      exact congrArg (fun z : A × Option Unit => z.1) (Option.some.inj hstep.symm)

#print axioms thompson_states_complete
#print axioms haltStepDisjoint_thompson
#print axioms deadCanonical_ite
#print axioms deadCanonical_div

/-! ## Padding: the behavioural target without reachability

    `Reachable` was never wanted for itself.  It was a way to *produce*, for every state of
    one automaton, a same-language state of the other — and to know the partners exhaust the
    other side, which is what makes the far leg of the span onto.  `Matched` now takes that
    matching as data, so any other way of producing it will do.

    Here is one, and it costs nothing.  For programs `e` and `f`, put

        padOne  e f  =  if 1 then e else f            ≡ e   (U-axioms)
        padZero e f  =  if 0 then e else f            ≡ f   (U-axioms)

    `ite` builds its core as the disjoint sum of the two branches' cores and touches only the
    pseudostate, so **the two padded programs have literally the same core** — same state
    type, same halt guards, same transitions.  Only the entry differs, which is exactly what
    makes one behave as `e` and the other as `f`.

    So the partner map is the identity, `partner_equiv` is `Iff.rfl`, and `cover` is
    immediate.  The `f`-side automaton carries a dead copy of `e`'s states and vice versa —
    unreachable, and no longer a problem, because the construction never asked for
    reachability, only for the two state-language sets to coincide.  Padding makes them
    coincide by construction.

    This is what the *accessible* half of trimming was standing in for, and it turns out not
    to need trimming at all: rather than deleting the states that spoil the match, add the
    ones that complete it. -/

/-- The right-hand padding: `f` with the sink attached.  The sink is there only to guarantee
    the padded core has at least one state, which is what the pullback's basepoint needs. -/
def padBody (f : Exp A T) (a₀ : A) : Exp A T := .ite BExp.one f (div a₀)

/-- `if 1 then e else (f + sink)` — provably `e`. -/
def padOne (e f : Exp A T) (a₀ : A) : Exp A T := .ite BExp.one e (padBody f a₀)

/-- `if 0 then e else (f + sink)` — provably `f`, and with the *same* core as `padOne`. -/
def padZero (e f : Exp A T) (a₀ : A) : Exp A T := .ite BExp.zero e (padBody f a₀)

theorem padBody_equiv (f : Exp A T) (a₀ : A) : EquivBA f (padBody f a₀) :=
  EquivBA.symm (ite_one f (div a₀))

theorem padOne_equiv (e f : Exp A T) (a₀ : A) : EquivBA e (padOne e f a₀) :=
  EquivBA.symm (ite_one e (padBody f a₀))

theorem padZero_equiv (e f : Exp A T) (a₀ : A) : EquivBA f (padZero e f a₀) :=
  EquivBA.trans (padBody_equiv f a₀)
    (EquivBA.symm (EquivBA.base (ite_zero e (padBody f a₀))))

theorem settled_padBody {f : Exp A T} (hf : Settled f) (a₀ : A) : Settled (padBody f a₀) :=
  Settled.ite _ hf (settled_div a₀)

theorem settled_padOne {e f : Exp A T} (he : Settled e) (hf : Settled f) (a₀ : A) :
    Settled (padOne e f a₀) := Settled.ite _ he (settled_padBody hf a₀)

theorem settled_padZero {e f : Exp A T} (he : Settled e) (hf : Settled f) (a₀ : A) :
    Settled (padZero e f a₀) := Settled.ite _ he (settled_padBody hf a₀)

theorem deadCanonical_padBody (a₀ : A) {f : Exp A T}
    (hf : DeadCanonical a₀ (certifiedThompson A T f).aut) :
    DeadCanonical a₀ (certifiedThompson A T (padBody f a₀)).aut :=
  deadCanonical_ite a₀ BExp.one hf (deadCanonical_div a₀)

theorem deadCanonical_padOne (a₀ : A) {e f : Exp A T}
    (he : DeadCanonical a₀ (certifiedThompson A T e).aut)
    (hf : DeadCanonical a₀ (certifiedThompson A T f).aut) :
    DeadCanonical a₀ (certifiedThompson A T (padOne e f a₀)).aut :=
  deadCanonical_ite a₀ BExp.one he (deadCanonical_padBody a₀ hf)

theorem deadCanonical_padZero (a₀ : A) {e f : Exp A T}
    (he : DeadCanonical a₀ (certifiedThompson A T e).aut)
    (hf : DeadCanonical a₀ (certifiedThompson A T f).aut) :
    DeadCanonical a₀ (certifiedThompson A T (padZero e f a₀)).aut :=
  deadCanonical_ite a₀ BExp.zero he (deadCanonical_padBody a₀ hf)

/-- **The two padded programs have the same core.**  `iteInitialized` puts the guard on the
    entry transitions only, so the internal dynamics are identical — which is the whole
    trick. -/
theorem pad_core_eq (e f : Exp A T) (a₀ : A) :
    (certifiedThompson A T (padZero e f a₀)).aut.core
      = (certifiedThompson A T (padOne e f a₀)).aut.core := rfl

/-- **Runs from a core state never see the pseudostate.**  So two automata that agree on
    their cores have the same language at every core state, however their entries differ.
    This is what makes the padding work: `ite` changes only the entry. -/
theorem autRun_core_congr {S : Type} {A0 A1 : InitializedGAut S A T}
    (hhlt : ∀ u : S, A0.core.hlt u = A1.core.hlt u)
    (htr : ∀ u : S, A0.core.trans u = A1.core.trans u)
    {X : Type} (W : T → X → Bool) :
    ∀ (w : List (A × X)) (u : S) (x : X),
      autRun W A0.toGAut (some u) x w ↔ autRun W A1.toGAut (some u) x w := by
  intro w
  induction w with
  | nil =>
      intro u x
      show bval W (A0.core.hlt u) x = true ↔ bval W (A1.core.hlt u) x = true
      rw [hhlt]
  | cons hd tl ih =>
      intro u x
      have hstep : autStep W A0.toGAut (some u) x = autStep W A1.toGAut (some u) x := by
        show firstMatch W x ((A0.core.trans u).map (fun t => (t.1, t.2.1, some t.2.2)))
          = firstMatch W x ((A1.core.trans u).map (fun t => (t.1, t.2.1, some t.2.2)))
        rw [htr]
      constructor
      · rintro ⟨v, hv, hrun⟩
        obtain ⟨v', rfl⟩ := GkatQuotient.step_target_some A0 W (some u) x hv
        exact ⟨some v', hstep.symm.trans hv, (ih v' hd.2).mp hrun⟩
      · rintro ⟨v, hv, hrun⟩
        obtain ⟨v', rfl⟩ := GkatQuotient.step_target_some A1 W (some u) x hv
        exact ⟨some v', hstep.trans hv, (ih v' hd.2).mpr hrun⟩

/-- Hence every core state is its own partner. -/
theorem pad_partner (e f : Exp A T) (a₀ : A)
    (s : (certifiedThompson A T (padZero e f a₀)).State) :
    CrossEquiv (certifiedThompson A T (padZero e f a₀)).aut
      (certifiedThompson A T (padOne e f a₀)).aut (some s) (some s) := by
  intro X W gs
  obtain ⟨y, v⟩ := gs
  exact autRun_core_congr (A0 := (certifiedThompson A T (padZero e f a₀)).aut)
    (A1 := (certifiedThompson A T (padOne e f a₀)).aut) (fun _ => rfl) (fun _ => rfl) W v s y

/-- The pseudostates match exactly when the two programs do. -/
theorem pad_init (e f : Exp A T) (a₀ : A) (h : UniformLanguageEquivalent e f) :
    CrossEquiv (certifiedThompson A T (padZero e f a₀)).aut
      (certifiedThompson A T (padOne e f a₀)).aut none none := by
  intro X W gs
  have h0 := congrFun (certifiedThompson_start_language (padZero e f a₀) X W) gs
  have h1 := congrFun (certifiedThompson_start_language (padOne e f a₀) X W) gs
  rw [h0, h1]
  exact (sound_BA (V := W) (padZero_equiv e f a₀) gs).symm.trans
    ((h X W gs).symm.trans (sound_BA (V := W) (padOne_equiv e f a₀) gs))

/-- **`Matched` with no reachability anywhere.** -/
def matched_of_pad (a₀ : A) (e f : Exp A T) (hlang : UniformLanguageEquivalent e f)
    (ht0 : Total (certifiedThompson A T (padZero e f a₀)).aut)
    (ht1 : Total (certifiedThompson A T (padOne e f a₀)).aut)
    (hc0 : DeadCanonical a₀ (certifiedThompson A T (padZero e f a₀)).aut)
    (hc1 : DeadCanonical a₀ (certifiedThompson A T (padOne e f a₀)).aut) :
    GkatQuotient.Matched (certifiedThompson A T (padZero e f a₀)).aut
      (certifiedThompson A T (padOne e f a₀)).aut where
  stepab := stepAgree_of_canonical a₀ (haltStepDisjoint_thompson _) ht1 hc0 hc1
  stepba := stepAgree_of_canonical a₀ (haltStepDisjoint_thompson _) ht0 hc1 hc0
  stepbb := stepAgree_of_canonical a₀ (haltStepDisjoint_thompson _) ht1 hc1 hc1
  init := pad_init e f a₀ hlang
  partner := id
  partner_equiv := pad_partner e f a₀
  partner_mem := fun _ hs => hs
  cover := fun t ht => ⟨t, ht, pad_partner e f a₀ t⟩

/-- **The common target, in the exact shape `CanonicalCommonTarget` asks for** — with no
    reachability hypothesis anywhere.  The basepoint is the sink state the padding attaches,
    so it is available unconditionally. -/
theorem commonTarget_of_pad (a₀ : A) (e f : Exp A T) (hlang : UniformLanguageEquivalent e f)
    (ht0 : Total (certifiedThompson A T (padZero e f a₀)).aut)
    (ht1 : Total (certifiedThompson A T (padOne e f a₀)).aut)
    (hc0 : DeadCanonical a₀ (certifiedThompson A T (padZero e f a₀)).aut)
    (hc1 : DeadCanonical a₀ (certifiedThompson A T (padOne e f a₀)).aut) :
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
      (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m),
      Nonempty (GkatPullback.Base φ ψ) := by
  obtain ⟨⟨φ⟩, ⟨ψ⟩⟩ :=
    GkatQuotient.span_of_matched (matched_of_pad a₀ e f hlang ht0 ht1 hc0 hc1)
  exact ⟨_, _, φ, ψ,
    GkatPullback.Base.ofMem φ ψ
      (thompson_states_complete (padZero e f a₀) (Sum.inr (Sum.inr ())))⟩

#print axioms commonTarget_of_pad
#print axioms pad_partner
#print axioms pad_init

/-! ## The repaired chain

    `DeadCanonical` blocks the counterexample exactly: with `a₀ = false`, `deadP` is canonical
    and `deadQ` is not, so the pair can never both satisfy it.  What it costs is a second
    normalisation obligation — every program provably equal to one that is settled *and* has a
    canonical dead part — which replaces `Normalizable`'s "remove dead regions" by "route them
    all into the one sink". -/

/-- The common-target hypothesis, for automata that are total **and** dead-canonical. -/
def CanonicalCommonTarget (A T : Type) (a₀ : A) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    Total (certifiedThompson A T e).aut → Total (certifiedThompson A T f).aut →
    DeadCanonical a₀ (certifiedThompson A T e).aut →
    DeadCanonical a₀ (certifiedThompson A T f).aut →
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T e).aut m)
      (ψ : InitCover (certifiedThompson A T f).aut m),
      Nonempty (GkatPullback.Base φ ψ)

/-- The normalisation it needs.  `settledReachable` gives the first two conjuncts already; the
    third is the open half, and it is the one `sinkify`-style "every null subterm becomes the
    sink" construction is for. -/
def CanonicallySettled (A T : Type) (a₀ : A) : Prop :=
  ∀ e : Exp A T, ∃ e' : Exp A T,
    EquivBA e e' ∧ Settled e' ∧ DeadCanonical a₀ (certifiedThompson A T e').aut

/-- **Completeness, repaired.**  Same shape as `completeness_of_total`, with the dead part
    made canonical on both sides — which is the least that can be added, since the pair
    `deadP`/`deadQ` shows the hypothesis is false without it. -/
theorem completeness_of_canonical (a₀ : A) (hcs : CanonicallySettled A T a₀)
    (hct : CanonicalCommonTarget A T a₀) (hpc : PullbackCovered A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨e', hee', hse, hce⟩ := hcs e
  obtain ⟨f', hff', hsf, hcf⟩ := hcs f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans
      (sound_BA (V := W) hff' gs)
  obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := hct e' f' heq'
    (total_of_settled hse) (total_of_settled hsf) hce hcf
  obtain ⟨h, ⟨χ⟩⟩ := hpc e' f' Q m φ ψ base
  exact EquivBA.trans hee'
    (EquivBA.trans
      (equivBA_of_common_refinement χ (GkatPullback.pullbackFst φ ψ base)
        (GkatPullback.pullbackSnd φ ψ base))
      (EquivBA.symm hff'))

#print axioms completeness_of_canonical

/-- **Completeness from `CanonicallySettled` and `PullbackCovered`.**

    Two hypotheses.  Normalisation is one of them and is two thirds proved
    (`settledReachable` gives the first two conjuncts); the common target is no longer a
    hypothesis at all, and neither is reachability, productivity or non-nullity. -/
theorem completeness_of_canonicallySettled (a₀ : A) (hcs : CanonicallySettled A T a₀)
    (hpc : PullbackCovered A T) : FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨e', hee', hse, hce⟩ := hcs e
  obtain ⟨f', hff', hsf, hcf⟩ := hcs f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans
      (sound_BA (V := W) hff' gs)
  obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := commonTarget_of_pad a₀ e' f' heq'
    (total_of_settled (settled_padZero hse hsf a₀))
    (total_of_settled (settled_padOne hse hsf a₀))
    (deadCanonical_padZero a₀ hce hcf) (deadCanonical_padOne a₀ hce hcf)
  obtain ⟨h, ⟨χ⟩⟩ := hpc (padZero e' f' a₀) (padOne e' f' a₀) Q m φ ψ base
  have hmid : EquivBA (padZero e' f' a₀) (padOne e' f' a₀) :=
    equivBA_of_common_refinement χ (GkatPullback.pullbackFst φ ψ base)
      (GkatPullback.pullbackSnd φ ψ base)
  exact EquivBA.trans hee'
    (EquivBA.trans (padOne_equiv e' f' a₀)
      (EquivBA.trans hmid.symm
        (EquivBA.trans (padZero_equiv e' f' a₀).symm hff'.symm)))

#print axioms completeness_of_canonicallySettled

end GkatTotalization
