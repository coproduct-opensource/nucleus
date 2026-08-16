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

## `Settled`, and what is left

`Settled` names the syntactic class the lemmas add up to, and `total_of_settled` proves every
`Settled` program has a total automaton.  `totalTest` then discharges the first source
outright: `b?` is provably equal to `if b then 1? else (while 1 do a)`, which is `Settled`.
That uses the sink, and it needs `A` inhabited — a language with no actions at all has no
divergent program to route into, and there stuckness is irreparable.

What is left is `SettledReachable`: every program is provably equal to a `Settled` one.  The
`test` case is done here; the loop case is the remaining obligation, and it is now a single
identified statement rather than a search for the right normal form.

Note what changed.  Pruning had to remove states — dead regions, unreachable branches — and
was defeated three times because the constructors destroy the induction hypothesis.
Totalising *adds* transitions, and the four lemmas above show the induction hypothesis
survives every constructor but one.
-/

namespace GkatTotalization

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCommonTarget GkatNormal

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

end GkatTotalization
