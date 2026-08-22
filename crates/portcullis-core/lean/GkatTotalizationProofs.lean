import GkatNormalProofs
import GkatLoopExitProofs

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

`CanonicallySettled` is discharged too, by `canonicallySettled_holds`.  Both normalisations
are proved — `settledReachable_loopProductive` for settling, `nrm` / `nrm_equiv` /
`settled_nrm` / `live_nrm` for exact dead-code elimination — and so is the bridge between
them, in three steps:

  * **homogeneity** (`actionLabelled_thompson`) — the construction is a position automaton, so
    every transition into a state carries that state's own action.  `DeadCanonical` therefore
    stops being about transitions: it says every dead state is an occurrence of `a₀`.
  * **residuality** (`standard_null_of_dead`) — each state's language is the denotation of its
    state expression, so "dead" becomes "this residual accepts nothing", in syntax.
  * **the match** (`deadStates_of_live`) — at every position, the residual is exactly the
    continuation `Live` was checking.  So a dead occurrence contradicts liveness, except at
    the sink, which is exempt and labelled `a₀`.

So `completeness_of_pullbackCovered` derives `FiniteAxiomsCompleteBA` from one hypothesis
**alone** — and not even the general one.  Uniqueness, productivity, reachability,
non-nullity, the common target and dead-canonicity are all theorems now.

What remains is `PaddedPullbackCovered`, which is `PullbackCovered` restricted to the pair the
proof actually forms: two *padded* programs, which share a core, over the behavioural quotient
of one of them.  There both legs of the span are the **same** map `rep`
(`pad_span_maps_agree`), and two states have the same representative exactly when they have
the same language (`rep_eq_iff_langEquiv`) — so the object that has to be covered is the
**kernel pair** of the behavioural quotient: the language-equivalence relation itself,
presented as an automaton.  That is a far more specific thing than a fibre product of two
unrelated covers, and it is where the remaining work is.

The identification that makes the sink legitimate is the one the literature calls the
**early-termination property** — programs that fail immediately are equated with programs
that fail eventually.  `wh_one_provably_zero` is exactly that, derived here rather than
postulated, and it is what lets a stuck configuration be replaced by a divergent one without
leaving the equational theory.
-/

namespace GkatTotalization

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCommonTarget GkatNormal GkatAtomTransfer GkatPeriod GkatLoopExit

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
    (∀ (Y : Type) (V : T → Y → Bool) (y : Y) (w : List (A × Y)),
      ¬ autRun V aut.toGAut s' y w) → q = a₀

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
  by_cases hlive : ∃ (Y : Type) (V : T → Y → Bool) (y : Y) (w : List (A × Y)),
      autRun V a.toGAut s' y w
  · obtain ⟨Y, V, y, w, hw⟩ := hlive
    let W'' : T → Sum X Y → Bool := fun c => Sum.elim (W c) (V c)
    have hl : ∀ (c : T) (z : X), W'' c (Sum.inl z) = W c z := fun _ _ => rfl
    have hr : ∀ (c : T) (z : Y), W'' c (Sum.inr z) = V c z := fun _ _ => rfl
    have hsL : autStep W'' a.toGAut s (Sum.inl x) = some (q, s') := by
      rw [show autStep W'' a.toGAut s (Sum.inl x) = autStep W a.toGAut s x from
        firstMatch_transfer hl (a.toGAut.trans s) x]
      exact hs
    obtain ⟨t', ht, hce⟩ := crossEquiv_step_at h W'' (Sum.inl x) hsL
      ⟨Sum.inr y, mapAtoms Sum.inr w, (autRun_transfer hr a.toGAut s' y w).mpr hw⟩
    refine ⟨t', ?_, hce⟩
    rw [← show autStep W'' b.toGAut t (Sum.inl x) = autStep W b.toGAut t x from
      firstMatch_transfer hl (b.toGAut.trans t) x]
    exact ht
  · have hdead : ∀ (Y : Type) (V : T → Y → Bool) (y : Y) (w : List (A × Y)),
        ¬ autRun V a.toGAut s' y w := by
      intro Y V y w hw
      exact hlive ⟨Y, V, y, w, hw⟩
    have hqa : q = a₀ := hca X W x s q s' hs hdead
    have hsome := step_agree_of_total hd htb h W x hs
    cases hb : autStep W b.toGAut t x with
    | none => rw [hb] at hsome; exact Bool.noConfusion hsome
    | some p =>
        obtain ⟨q₂, t'⟩ := p
        have hdead' : ∀ (Y : Type) (V : T → Y → Bool) (y : Y) (w : List (A × Y)),
            ¬ autRun V b.toGAut t' y w := by
          intro Y V y w hw
          let W'' : T → Sum X Y → Bool := fun c => Sum.elim (W c) (V c)
          have hl : ∀ (c : T) (z : X), W'' c (Sum.inl z) = W c z := fun _ _ => rfl
          have hr : ∀ (c : T) (z : Y), W'' c (Sum.inr z) = V c z := fun _ _ => rfl
          have hbL : autStep W'' b.toGAut t (Sum.inl x) = some (q₂, t') := by
            rw [show autStep W'' b.toGAut t (Sum.inl x) = autStep W b.toGAut t x from
              firstMatch_transfer hl (b.toGAut.trans t) x]
            exact hb
          have hbrun : autRun W'' b.toGAut t (Sum.inl x)
              ((q₂, Sum.inr y) :: mapAtoms Sum.inr w) :=
            ⟨t', hbL, (autRun_transfer hr b.toGAut t' y w).mpr hw⟩
          obtain ⟨s'', hs2, hrun2⟩ :=
            (h (Sum X Y) W'' (Sum.inl x, (q₂, Sum.inr y) :: mapAtoms Sum.inr w)).mpr hbrun
          have haL : autStep W'' a.toGAut s (Sum.inl x) = some (q, s') := by
            rw [show autStep W'' a.toGAut s (Sum.inl x) = autStep W a.toGAut s x from
              firstMatch_transfer hl (a.toGAut.trans s) x]
            exact hs
          have hpair : (q, s') = (q₂, s'') := Option.some.inj (haL.symm.trans hs2)
          have htgt : s'' = s' := (congrArg (fun z : A × Option S₁ => z.2) hpair).symm
          exact hdead (Sum X Y) W'' (Sum.inr y) (mapAtoms Sum.inr w) (htgt ▸ hrun2)
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
  exact absurd hw (hdead X W x' w)

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
        intro Y V y v hv
        apply hdead Y V y v
        rw [hs']
        exact (autRun_ite_inr g L R V v o y).mpr hv
      · rw [autStep_ite_none, hg] at hstep
        simp only [if_true] at hstep
        obtain ⟨o, ho, hs'⟩ :=
          map_some_inv (F := fun w : S₁ => (some (Sum.inl w) : Option (Sum S₁ S₂))) hstep
        refine hL X W x none q (some o) (by rw [GkatQuotient.autStep_init, ho]; rfl) ?_
        intro Y V y v hv
        apply hdead Y V y v
        rw [hs']
        exact (autRun_ite_inl g L R V v o y).mpr hv
  | some sv =>
      cases sv with
      | inl u =>
          rw [step_ite_inl] at hstep
          obtain ⟨o, ho, hs'⟩ :=
            map_some_inv (F := fun w : S₁ => (some (Sum.inl w) : Option (Sum S₁ S₂))) hstep
          refine hL X W x (some u) q (some o) (by rw [GkatQuotient.autStep_core, ho]; rfl) ?_
          intro Y V y v hv
          apply hdead Y V y v
          rw [hs']
          exact (autRun_ite_inl g L R V v o y).mpr hv
      | inr u =>
          rw [step_ite_inr] at hstep
          obtain ⟨o, ho, hs'⟩ :=
            map_some_inv (F := fun w : S₂ => (some (Sum.inr w) : Option (Sum S₁ S₂))) hstep
          refine hR X W x (some u) q (some o) (by rw [GkatQuotient.autStep_core, ho]; rfl) ?_
          intro Y V y v hv
          apply hdead Y V y v
          rw [hs']
          exact (autRun_ite_inr g L R V v o y).mpr hv

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

/-- **The pullback the chain actually forms.**  `PullbackCovered` quantifies over arbitrary
    pairs of programs and an arbitrary common quotient.  The completeness proof never uses
    that generality: it applies the hypothesis exactly once, to the two *padded* forms, which
    share a core, over the behavioural quotient of one of them.

    That is a much more specific object.  In the padded construction both legs of the span are
    the **same** map, `rep` (`pad_span_maps_agree`), so the fibre product is the *kernel pair*
    of the behavioural quotient — the language-equivalence relation itself, presented as an
    automaton — rather than a fibre product of two unrelated covers.

    `paddedPullbackCovered_of_pullbackCovered` records that this is a genuine weakening. -/
def PaddedPullbackCovered (A T : Type) (a₀ : A) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ),
    HasThompsonCover (GkatPullback.pullback φ ψ base)

theorem paddedPullbackCovered_of_pullbackCovered (a₀ : A) (h : PullbackCovered A T) :
    PaddedPullbackCovered A T a₀ :=
  fun e f Q m φ ψ base => h _ _ Q m φ ψ base

/-- **The fibre is exactly language-equivalence.**  Two states have the same representative
    precisely when they have the same language, so the kernel pair of `rep` *is* the
    language-equivalence relation presented as a set of pairs. -/
theorem rep_eq_iff_langEquiv {S : Type} (b : InitializedGAut S A T) (u v : S) :
    GkatQuotient.rep b u = GkatQuotient.rep b v ↔ LangEquiv b (some u) (some v) := by
  constructor
  · intro h
    have h1 := GkatQuotient.rep_equiv b u
    have h2 := (GkatQuotient.rep_equiv b v).symm
    rw [← h] at h2
    exact h1.trans h2
  · intro h
    exact GkatQuotient.rep_eq_of_equiv h

/-- **Both legs of the padded span are the same map.**  `partner` is the identity, so
    `matchCover`'s map is `rep ∘ id = rep`, which is `targetCover`'s map on the nose. -/
theorem pad_span_maps_agree (a₀ : A) (e f : Exp A T) (hlang : UniformLanguageEquivalent e f)
    (ht0 : Total (certifiedThompson A T (padZero e f a₀)).aut)
    (ht1 : Total (certifiedThompson A T (padOne e f a₀)).aut)
    (hc0 : DeadCanonical a₀ (certifiedThompson A T (padZero e f a₀)).aut)
    (hc1 : DeadCanonical a₀ (certifiedThompson A T (padOne e f a₀)).aut) :
    (GkatQuotient.matchCover (matched_of_pad a₀ e f hlang ht0 ht1 hc0 hc1)).map
      = (GkatQuotient.targetCover
          (matched_of_pad a₀ e f hlang ht0 ht1 hc0 hc1).stepbb).map := rfl

/-- **Completeness from `CanonicallySettled` and `PullbackCovered`.**

    Two hypotheses.  Normalisation is one of them and is two thirds proved
    (`settledReachable` gives the first two conjuncts); the common target is no longer a
    hypothesis at all, and neither is reachability, productivity or non-nullity. -/
theorem completeness_of_canonicallySettled (a₀ : A) (hcs : CanonicallySettled A T a₀)
    (hpc : PaddedPullbackCovered A T a₀) : FiniteAxiomsCompleteBA A T := by
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
  obtain ⟨h, ⟨χ⟩⟩ := hpc e' f' Q m φ ψ base
  have hmid : EquivBA (padZero e' f' a₀) (padOne e' f' a₀) :=
    equivBA_of_common_refinement χ (GkatPullback.pullbackFst φ ψ base)
      (GkatPullback.pullbackSnd φ ψ base)
  exact EquivBA.trans hee'
    (EquivBA.trans (padOne_equiv e' f' a₀)
      (EquivBA.trans hmid.symm
        (EquivBA.trans (padZero_equiv e' f' a₀).symm hff'.symm)))


/-! ## Dead-code elimination, with the continuation as a parameter

    `DeadCanonical` is the last piece, and the obstacle is that **liveness is a backward
    property**: whether a state is dead depends on what its continuation does, not on the
    subterm it sits in.  `(a +_d (b ; ¬c?)) ; c?` is live, has no null subterm, and yet the
    state after `b` is dead — so "replace every null subterm by the sink" cannot work, and two
    turns of this development were spent discovering that.

    The fix is to stop looking for a backward analysis and carry the future along instead.
    `nrm a₀ e K` normalises `e` knowing that its continuation is `K`, and every recursive call
    knows its own continuation exactly:

        seq e f    →  `e`'s continuation is `f ; K`
        ite g e f  →  both branches keep `K`          (this is `U5`, done semantically)
        wh g e     →  the body's continuation is `(while g do e) ; K`

    So the only test needed is at an action: if `p ; K` accepts nothing, the occurrence of `p`
    is dead in this context and is replaced by the sink.  No rewriting to a distributed normal
    form is required — passing the continuation *is* the distribution.

    The recursion is structural in the program, with the continuation varying freely, so it
    terminates for the same reason the syntax is well-founded. -/

open Classical in
/-- Exact dead-code elimination: an action whose continuation accepts nothing becomes the
    sink. -/
noncomputable def nrm (a₀ : A) : Exp A T → Exp A T → Exp A T
  | .act p, K => if UniformExpLempty (.seq (.act p) K) then div a₀ else .act p
  | .test b, _ => .test b
  | .seq e f, K => .seq (nrm a₀ e (.seq f K)) (nrm a₀ f K)
  | .ite g e f, K => .ite g (nrm a₀ e K) (nrm a₀ f K)
  | .wh g e, K => .wh g (nrm a₀ e (.seq (.wh g e) K))

/-- **Normalisation preserves the immediate-halt guard.**  The sink and an action both have
    `E = 0`, and every other case is a congruence — so `W3`'s side condition survives, which
    is what the loop case of the equivalence needs. -/
theorem E_nrm (a₀ : A) : ∀ (e K : Exp A T) (X : Type) (W : T → X → Bool) (x : X),
    bval W (E (nrm a₀ e K)) x = bval W (E e) x := by
  intro e
  induction e with
  | act p =>
      intro K X W x
      by_cases h : UniformExpLempty (.seq (.act p) K : Exp A T) <;>
        simp only [nrm, h, if_true, if_false] <;> rfl
  | test b => intro K X W x; rfl
  | seq e f ihe ihf =>
      intro K X W x
      show (bval W (E (nrm a₀ e (.seq f K))) x && bval W (E (nrm a₀ f K)) x)
        = (bval W (E e) x && bval W (E f) x)
      rw [ihe (.seq f K) X W x, ihf K X W x]
  | ite g e f ihe ihf =>
      intro K X W x
      show (bval W g x && bval W (E (nrm a₀ e K)) x ||
          (!bval W g x) && bval W (E (nrm a₀ f K)) x)
        = (bval W g x && bval W (E e) x || (!bval W g x) && bval W (E f) x)
      rw [ihe K X W x, ihf K X W x]
  | wh g e _ => intro K X W x; rfl

/-- Every loop body has `E ≡ 0` — `W3`'s side condition, as a property of the program.  The
    settled forms satisfy it: `settledBody` never halts immediately, by construction. -/
inductive LoopProductive : Exp A T → Prop where
  | act (p : A) : LoopProductive (.act p)
  | test (b : BExp T) : LoopProductive (.test b)
  | seq {e f : Exp A T} : LoopProductive e → LoopProductive f → LoopProductive (.seq e f)
  | ite (g : BExp T) {e f : Exp A T} :
      LoopProductive e → LoopProductive f → LoopProductive (.ite g e f)
  | wh (g : BExp T) {e : Exp A T} : LoopProductive e →
      (∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e) x = false) →
      LoopProductive (.wh g e)

/-- The sink is a loop, and its body is a single action — so it is loop-productive. -/
theorem loopProductive_div (a₀ : A) : LoopProductive (div a₀ : Exp A T) :=
  LoopProductive.wh BExp.one (LoopProductive.act a₀) (fun _ _ _ => rfl)

/-- **Normalisation is provable, in context.**  The replacement is not equivalent to what it
    replaces — an action is not the sink — but `e ; K` and `(nrm a₀ e K) ; K` are, which is
    exactly the statement dead-code elimination should have.

    Four of the five cases are congruence and associativity.  The loop case is `W3`: the
    original `(while g do e) ; K` already solves the equation for the *new* body, because the
    induction hypothesis at continuation `(while g do e) ; K` says precisely that the two
    bodies agree when followed by it. -/
theorem nrm_equiv (a₀ : A) : ∀ (e : Exp A T), LoopProductive e → ∀ (K : Exp A T),
    EquivBA (.seq e K) (.seq (nrm a₀ e K) K) := by
  intro e
  induction e with
  | act p =>
      intro _ K
      by_cases h : UniformExpLempty (.seq (.act p) K : Exp A T)
      · simp only [nrm, h, if_true]
        refine EquivBA.trans (GkatNullLanguage.nullLanguage_complete _ h) (EquivBA.symm ?_)
        exact EquivBA.trans
          (EquivBA.seq_c (GkatNormal.wh_one_provably_zero (.act a₀))
            (EquivBA.base (Equiv.refl K)))
          (EquivBA.base (Equiv.s2 K))
      · simp only [nrm, h, if_false]
        exact EquivBA.base (Equiv.refl _)
  | test b => intro _ K; exact EquivBA.base (Equiv.refl _)
  | seq e f ihe ihf =>
      intro hlp K
      cases hlp with
      | seq hle hlf =>
          show EquivBA (.seq (.seq e f) K)
            (.seq (.seq (nrm a₀ e (.seq f K)) (nrm a₀ f K)) K)
          refine EquivBA.trans (EquivBA.base (Equiv.s1 e f K)) ?_
          refine EquivBA.trans (ihe hle (.seq f K)) ?_
          refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (ihf hlf K)) ?_
          exact EquivBA.symm (EquivBA.base (Equiv.s1 _ _ K))
  | ite g e f ihe ihf =>
      intro hlp K
      cases hlp with
      | ite _ hle hlf =>
          show EquivBA (.seq (.ite g e f) K)
            (.seq (.ite g (nrm a₀ e K) (nrm a₀ f K)) K)
          refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 g e f K))) ?_
          refine EquivBA.trans (EquivBA.ite_c (ihe hle K) (ihf hlf K)) ?_
          exact EquivBA.base (Equiv.u5 g _ _ K)
  | wh g e ihe =>
      intro hlp K
      cases hlp with
      | wh _ hle hE =>
          show EquivBA (.seq (.wh g e) K) (.seq (.wh g (nrm a₀ e (.seq (.wh g e) K))) K)
          refine EquivBA.w3_ba ?_ ?_
          · exact EquivBA.baTest (fun X W x => (E_nrm a₀ e (.seq (.wh g e) K) X W x).trans
              (hE X W x))
          · refine EquivBA.trans (EquivBA.base (salomaa_solution_exists g e K)) ?_
            exact EquivBA.ite_c (ihe hle (.seq (.wh g e) K)) (EquivBA.base (Equiv.refl K))

/-- **Dead code elimination for a whole program.**  `1` is the trivial continuation. -/
theorem nrm_top_equiv (a₀ : A) (e : Exp A T) (hlp : LoopProductive e) :
    EquivBA e (nrm a₀ e (.test BExp.one)) :=
  EquivBA.trans (EquivBA.symm (GkatGuardedAlgebra.seq_one e))
    (EquivBA.trans (nrm_equiv a₀ e hlp (.test BExp.one))
      (GkatGuardedAlgebra.seq_one _))

/-! ## The two normalisations compose -/

/-- A settled body with `E ≡ 0` steps under every guard — the general form of
    `bodySteps_settledBody`. -/
theorem bodySteps_of_E_zero {e : Exp A T} (hs : Settled e)
    (hE : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e) x = false) (g : BExp T) :
    BodySteps (certifiedThompson A T e).aut g := by
  intro X W x _
  rcases (totalParts_of_settled hs).init X W x with hh | hstep
  · rw [initHlt_eq_E, hE X W x] at hh
    exact Bool.noConfusion hh
  · exact hstep

theorem loopProductive_nrm (a₀ : A) : ∀ (e : Exp A T), LoopProductive e → ∀ K : Exp A T,
    LoopProductive (nrm a₀ e K) := by
  intro e
  induction e with
  | act p =>
      intro _ K
      by_cases h : UniformExpLempty (.seq (.act p) K : Exp A T)
      · simp only [nrm, h, if_true]; exact loopProductive_div a₀
      · simp only [nrm, h, if_false]; exact LoopProductive.act p
  | test b => intro _ K; exact LoopProductive.test b
  | seq e f ihe ihf =>
      intro hlp K
      cases hlp with
      | seq hle hlf => exact LoopProductive.seq (ihe hle _) (ihf hlf K)
  | ite g e f ihe ihf =>
      intro hlp K
      cases hlp with
      | ite _ hle hlf => exact LoopProductive.ite g (ihe hle K) (ihf hlf K)
  | wh g e ihe =>
      intro hlp K
      cases hlp with
      | wh _ hle hE =>
          exact LoopProductive.wh g (ihe hle _)
            (fun X W x => (E_nrm a₀ e _ X W x).trans (hE X W x))

theorem settled_nrm (a₀ : A) : ∀ (e : Exp A T), Settled e → LoopProductive e →
    ∀ K : Exp A T, Settled (nrm a₀ e K) := by
  intro e
  induction e with
  | act p =>
      intro _ _ K
      by_cases h : UniformExpLempty (.seq (.act p) K : Exp A T)
      · simp only [nrm, h, if_true]; exact settled_div a₀
      · simp only [nrm, h, if_false]; exact Settled.act p
  | test b =>
      intro hs _ K
      cases hs with
      | one => exact Settled.one
  | seq e f ihe ihf =>
      intro hs hlp K
      cases hs with
      | seq hse hsf =>
          cases hlp with
          | seq hle hlf => exact Settled.seq (ihe hse hle _) (ihf hsf hlf K)
  | ite g e f ihe ihf =>
      intro hs hlp K
      cases hs with
      | ite _ hse hsf =>
          cases hlp with
          | ite _ hle hlf => exact Settled.ite g (ihe hse hle K) (ihf hsf hlf K)
  | wh g e ihe =>
      intro hs hlp K
      cases hs with
      | wh _ hse _ =>
          cases hlp with
          | wh _ hle hE =>
              refine Settled.wh g (ihe hse hle _) ?_
              exact bodySteps_of_E_zero (ihe hse hle _)
                (fun X W x => (E_nrm a₀ e _ X W x).trans (hE X W x)) g

/-- The settled loop bodies never halt immediately, so the settling normalisation already
    delivers `W3`'s side condition. -/
theorem loopProductive_settledBody (a : A) (e : Exp A T) :
    ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E (settledBody e a)) x = false := by
  intro X W x
  rw [← initHlt_eq_E]
  exact settledBody_never_halts e a W x

/-- **Settling delivers loop-productivity too.**  Same induction as `settledReachable`, with
    the extra conjunct carried through. -/
theorem settledReachable_loopProductive (a : A) (e : Exp A T) :
    ∃ h : Exp A T, EquivBA e h ∧ Settled h ∧ LoopProductive h := by
  induction e with
  | act p => exact ⟨.act p, EquivBA.base (Equiv.refl _), Settled.act p, LoopProductive.act p⟩
  | test b =>
      exact ⟨totalTest a b, totalTest_equiv a b, settled_totalTest a b,
        LoopProductive.ite b (LoopProductive.test _) (loopProductive_div a)⟩
  | seq f h ihf ihh =>
      obtain ⟨f', hf, sf, lf⟩ := ihf
      obtain ⟨h', hh, sh, lh⟩ := ihh
      exact ⟨.seq f' h', EquivBA.seq_c hf hh, Settled.seq sf sh, LoopProductive.seq lf lh⟩
  | ite c f h ihf ihh =>
      obtain ⟨f', hf, sf, lf⟩ := ihf
      obtain ⟨h', hh, sh, lh⟩ := ihh
      exact ⟨.ite c f' h', EquivBA.ite_c hf hh, Settled.ite c sf sh,
        LoopProductive.ite c lf lh⟩
  | wh c f ihf =>
      obtain ⟨f', hf, sf, lf⟩ := ihf
      exact ⟨.wh c (settledBody f' a),
        EquivBA.trans (EquivBA.wh_c hf) (loop_settles c f' a),
        Settled.wh c (settled_settledBody a sf) (bodySteps_settledBody c a sf),
        LoopProductive.wh c (LoopProductive.ite _ lf (loopProductive_div a))
          (loopProductive_settledBody a f')⟩

/-- **Both normalisations, composed.**  Every program is provably equal to one that is
    settled — hence total — and has had its dead code eliminated exactly.

    What is left for `CanonicallySettled` is the soundness of the elimination: that the
    normalised program's automaton really has no dead state but the sink's, so it is
    `DeadCanonical`.  That is a statement about states rather than about syntax, and it is
    the only thing between this and the completeness theorem. -/
theorem settled_and_dce (a₀ : A) (e : Exp A T) :
    ∃ h : Exp A T, EquivBA e h ∧ Settled h ∧ LoopProductive h ∧
      h = nrm a₀ (Classical.choose (settledReachable_loopProductive a₀ e)) (.test BExp.one) := by
  obtain ⟨h, hh, hs, hl⟩ := settledReachable_loopProductive a₀ e
  refine ⟨nrm a₀ (Classical.choose (settledReachable_loopProductive a₀ e)) (.test BExp.one),
    ?_, ?_, ?_, rfl⟩
  · obtain ⟨hh', hs', hl'⟩ := Classical.choose_spec (settledReachable_loopProductive a₀ e)
    exact EquivBA.trans hh' (nrm_top_equiv a₀ _ hl')
  · obtain ⟨_, hs', hl'⟩ := Classical.choose_spec (settledReachable_loopProductive a₀ e)
    exact settled_nrm a₀ _ hs' hl' _
  · obtain ⟨_, _, hl'⟩ := Classical.choose_spec (settledReachable_loopProductive a₀ e)
    exact loopProductive_nrm a₀ _ hl' _

/-! ## What the elimination guarantees, syntactically

    `nrm` leaves no dead action occurrence behind.  Stating that needs the same device the
    construction did — a continuation parameter — because "this occurrence is dead" is not a
    property of the occurrence alone.

    `Live a₀ e K` says: read `e` in continuation `K`, and every action occurrence in it has a
    continuation that accepts something.  The one exception is the sink itself, which is dead
    by design and canonical by construction — every transition into `div a₀` carries `a₀`,
    since that is the only entry transition it has. -/

/-- Nullity of `X ; K` depends on `K` only through its language. -/
theorem null_seq_congr {X K K' : Exp A T} (h : EquivBA K K') :
    UniformExpLempty (.seq X K) → UniformExpLempty (.seq X K') := by
  intro hnull Y W gs
  intro hden
  exact hnull Y W gs
    ((sound_BA (V := W) (EquivBA.seq_c (EquivBA.base (Equiv.refl X)) h) gs).mpr hden)

/-- Every action occurrence has a live continuation; the sink is the only exception. -/
inductive Live (a₀ : A) : Exp A T → Exp A T → Prop where
  | act (p : A) (K : Exp A T) :
      ¬ UniformExpLempty (.seq (.act p) K) → Live a₀ (.act p) K
  | sink (K : Exp A T) : Live a₀ (div a₀) K
  | test (b : BExp T) (K : Exp A T) : Live a₀ (.test b) K
  | seq {e f K : Exp A T} :
      Live a₀ e (.seq f K) → Live a₀ f K → Live a₀ (.seq e f) K
  | ite (g : BExp T) {e f K : Exp A T} :
      Live a₀ e K → Live a₀ f K → Live a₀ (.ite g e f) K
  | wh (g : BExp T) {e K : Exp A T} :
      Live a₀ e (.seq (.wh g e) K) → Live a₀ (.wh g e) K

/-- Liveness only sees the continuation's language, so equivalent continuations agree. -/
theorem live_congr (a₀ : A) {e K : Exp A T} (h : Live a₀ e K) :
    ∀ {K' : Exp A T}, EquivBA K K' → Live a₀ e K' := by
  induction h with
  | act p K hn => exact fun hk => Live.act p _ (fun hnull => hn (null_seq_congr hk.symm hnull))
  | sink K => exact fun _ => Live.sink _
  | test b K => exact fun _ => Live.test b _
  | seq _ _ ihe ihf =>
      exact fun hk => Live.seq (ihe (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hk)) (ihf hk)
  | ite g _ _ ihe ihf => exact fun hk => Live.ite g (ihe hk) (ihf hk)
  | wh g _ ihe =>
      exact fun hk =>
        Live.wh g (ihe (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hk))

/-- **The elimination is exhaustive.**  Every action left standing has a live continuation —
    which is what "no dead code remains" means, stated without reference to the automaton. -/
theorem live_nrm (a₀ : A) : ∀ (e : Exp A T), LoopProductive e → ∀ K : Exp A T,
    Live a₀ (nrm a₀ e K) K := by
  intro e
  induction e with
  | act p =>
      intro _ K
      by_cases h : UniformExpLempty (.seq (.act p) K : Exp A T)
      · simp only [nrm, h, if_true]; exact Live.sink K
      · simp only [nrm, h, if_false]; exact Live.act p K h
  | test b => intro _ K; exact Live.test b K
  | seq e f ihe ihf =>
      intro hlp K
      cases hlp with
      | seq hle hlf =>
          refine Live.seq ?_ (ihf hlf K)
          exact live_congr a₀ (ihe hle (.seq f K)) (nrm_equiv a₀ f hlf K)
  | ite g e f ihe ihf =>
      intro hlp K
      cases hlp with
      | ite _ hle hlf => exact Live.ite g (ihe hle K) (ihf hlf K)
  | wh g e ihe =>
      intro hlp K
      cases hlp with
      | wh _ hle hE =>
          refine Live.wh g ?_
          exact live_congr a₀ (ihe hle (.seq (.wh g e) K))
            (nrm_equiv a₀ (.wh g e) (LoopProductive.wh g hle hE) K)

/-! ## Homogeneity: every transition into a state carries that state's own action

    The remaining obligation is about *steps*, and it does not need to be.  GKAT's Thompson
    construction is a position automaton — its states are the action occurrences of the
    program — and position automata are **homogeneous**: any two transitions entering the same
    state carry the same label, namely the letter at that position.  Glushkov's construction
    has this property classically; the GKAT variant inherits it, because every constructor
    relabels targets without ever touching the action component.

    Once that is proved, `DeadCanonical` stops being a statement about steps.  A transition
    into a state carries that state's action, so

        every transition into a dead state carries `a₀`
          ⟺  every dead state is an occurrence of `a₀`

    and the last obligation becomes a question about *which states are dead*, with the
    transitions eliminated entirely. -/

/-- The action at each position — the occurrence a state stands for. -/
def actionOf : (p : Exp A T) → (certifiedThompson A T p).State → A
  | .act q, _ => q
  | .test _, s => nomatch s
  | .seq e f, s => Sum.elim (actionOf e) (actionOf f) s
  | .ite _ e f, s => Sum.elim (actionOf e) (actionOf f) s
  | .wh _ e, s => actionOf e s

/-- Homogeneity: every listed transition's action is the label of its target. -/
def ActionLabelled {S : Type} (aut : InitializedGAut S A T) (lbl : S → A) : Prop :=
  (∀ t ∈ aut.initTrans, t.2.1 = lbl t.2.2) ∧
  (∀ (u : S), ∀ t ∈ aut.core.trans u, t.2.1 = lbl t.2.2)

/-- **The Thompson construction is homogeneous.**  Every constructor relabels targets and
    conjoins guards; none of them rewrites an action. -/
theorem actionLabelled_thompson (p : Exp A T) :
    ActionLabelled (certifiedThompson A T p).aut (actionOf p) := by
  induction p with
  | act q =>
      constructor
      · intro t ht
        rcases List.mem_singleton.mp ht with rfl
        rfl
      · intro _ t ht
        have hnil : t ∈ ([] : List (BExp T × A × Unit)) := ht
        exact nomatch hnil
  | test b =>
      constructor
      · intro t ht
        have hnil : t ∈ ([] : List (BExp T × A × Empty)) := ht
        exact nomatch hnil
      · intro u
        exact nomatch u
  | seq e f ihe ihf =>
      constructor
      · intro t ht
        rcases List.mem_append.mp ht with h | h
        · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihe.1 t' ht'
        · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihf.1 t' ht'
      · intro u t ht
        cases u with
        | inl v =>
            rcases List.mem_append.mp ht with h | h
            · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihe.2 v t' ht'
            · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihf.1 t' ht'
        | inr v =>
            obtain ⟨t', ht', rfl⟩ := List.mem_map.mp ht; exact ihf.2 v t' ht'
  | ite g e f ihe ihf =>
      constructor
      · intro t ht
        rcases List.mem_append.mp ht with h | h
        · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihe.1 t' ht'
        · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihf.1 t' ht'
      · intro u t ht
        cases u with
        | inl v => obtain ⟨t', ht', rfl⟩ := List.mem_map.mp ht; exact ihe.2 v t' ht'
        | inr v => obtain ⟨t', ht', rfl⟩ := List.mem_map.mp ht; exact ihf.2 v t' ht'
  | wh g e ihe =>
      constructor
      · intro t ht
        obtain ⟨t', ht', rfl⟩ := List.mem_map.mp ht; exact ihe.1 t' ht'
      · intro u t ht
        rcases List.mem_append.mp ht with h | h
        · exact ihe.2 u t h
        · obtain ⟨t', ht', rfl⟩ := List.mem_map.mp h; exact ihe.1 t' ht'

private theorem mem_of_firstMatch {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) {o : A × S} (h : firstMatch W x L = some o) :
    ∃ t ∈ L, t.2 = o := by
  induction L with
  | nil => exact absurd h (by simp [firstMatch])
  | cons hd tl ih =>
      obtain ⟨g, q, v⟩ := hd
      simp only [firstMatch] at h
      by_cases hg : bval W g x
      · rw [if_pos hg] at h
        exact ⟨(g, q, v), List.mem_cons_self, Option.some.inj h⟩
      · rw [if_neg hg] at h
        obtain ⟨t, ht, he⟩ := ih h
        exact ⟨t, List.mem_cons_of_mem _ ht, he⟩

/-- **`DeadCanonical` reduces to a statement about states.**  With homogeneity, requiring
    every transition into a dead state to carry `a₀` is the same as requiring every dead state
    to be an occurrence of `a₀`. -/
theorem deadCanonical_of_deadStates (p : Exp A T) (a₀ : A)
    (h : ∀ u : (certifiedThompson A T p).State,
      (∀ (Y : Type) (V : T → Y → Bool) (y : Y) (w : List (A × Y)),
        ¬ autRun V (certifiedThompson A T p).aut.toGAut (some u) y w) →
      actionOf p u = a₀) :
    DeadCanonical a₀ (certifiedThompson A T p).aut := by
  intro X W x s q s' hstep hdead
  obtain ⟨u, rfl⟩ := GkatQuotient.step_target_some (certifiedThompson A T p).aut W s x hstep
  have hlbl := actionLabelled_thompson p
  have hmem : ∃ t ∈ (certifiedThompson A T p).aut.toGAut.trans s, t.2 = (q, some u) :=
    mem_of_firstMatch W x _ hstep
  obtain ⟨t, ht, hteq⟩ := hmem
  refine Eq.trans ?_ (h u hdead)
  cases s with
  | none =>
      obtain ⟨t', ht', rfl⟩ := List.mem_map.mp ht
      have h1 : t'.2.1 = q := congrArg (fun z : A × Option _ => z.1) hteq
      have h2 : some t'.2.2 = some u := congrArg (fun z : A × Option _ => z.2) hteq
      rw [← h1, hlbl.1 t' ht', Option.some.inj h2]
  | some v =>
      obtain ⟨t', ht', rfl⟩ := List.mem_map.mp ht
      have h1 : t'.2.1 = q := congrArg (fun z : A × Option _ => z.1) hteq
      have h2 : some t'.2.2 = some u := congrArg (fun z : A × Option _ => z.2) hteq
      rw [← h1, hlbl.2 v t' ht', Option.some.inj h2]

#print axioms actionLabelled_thompson
#print axioms deadCanonical_of_deadStates

/-- **The last bridge.**  Syntactic liveness gives automaton-level dead-canonicity: if every
    action occurrence in `h` has a live continuation, then the only dead states of `h ; K`'s
    automaton belong to sinks, and every transition into a sink carries `a₀` because that is
    the sink's only entry action.

    This is the one statement between `live_nrm` and `CanonicallySettled`, and it is the only
    remaining step that has to reason about states rather than syntax.

    Note the shape: it is about `h ; K`, not `h`, because that is what the induction will need
    — the automaton of `h ; K` is `seqInitialized` of the two, so an occurrence inside `h`
    sees exactly the continuation `Live` was tracking.

    Note also *which* deadness it uses.  `DeadCanonical` asks the target to accept nothing
    under **every** interpretation, and that is forced: `nrm` tests `UniformExpLempty`, which
    is uniform, so a pointwise-dead-here-but-live-elsewhere state would be beyond its reach.
    `crossEquiv_step_of_canonical` was rebuilt to work with the uniform version, using the
    sum-interpretation transfer to move a witness found under one interpretation into the one
    at hand. -/
def LiveImpliesCanonical (A T : Type) (a₀ : A) : Prop :=
  ∀ h : Exp A T, Live a₀ h (.test BExp.one) →
    DeadCanonical a₀ (certifiedThompson A T h).aut

/-- **`CanonicallySettled` reduces to that bridge.**  Both normalisations are proved; only the
    soundness of the elimination is left. -/
theorem canonicallySettled_of_bridge (a₀ : A) (hb : LiveImpliesCanonical A T a₀) :
    CanonicallySettled A T a₀ := by
  intro e
  obtain ⟨h, hh, hs, hl⟩ := settledReachable_loopProductive a₀ e
  refine ⟨nrm a₀ h (.test BExp.one), EquivBA.trans hh (nrm_top_equiv a₀ h hl),
    settled_nrm a₀ h hs hl _, ?_⟩
  exact hb _ (live_nrm a₀ h hl (.test BExp.one))

/-- **Completeness from the bridge and `PullbackCovered`.** -/
theorem completeness_of_bridge (a₀ : A) (hb : LiveImpliesCanonical A T a₀)
    (hpc : PaddedPullbackCovered A T a₀) : FiniteAxiomsCompleteBA A T :=
  completeness_of_canonicallySettled a₀ (canonicallySettled_of_bridge a₀ hb) hpc

/-- Non-vacuity for the bridge: it holds at the sink, which is the one program that is
    deliberately dead.  `deadCanonical_div` is the automaton half, `Live.sink` the syntactic
    one, so the two sides of the statement do meet somewhere. -/
theorem bridge_holds_at_sink (a₀ : A) (K : Exp A T) :
    Live a₀ (div a₀ : Exp A T) K ∧
      DeadCanonical a₀ (certifiedThompson A T (div a₀)).aut :=
  ⟨Live.sink _, deadCanonical_div a₀⟩

#print axioms bridge_holds_at_sink
/-! ## The residual, and the obligation discharged

    The Thompson automaton is **residual**: each state's language is the denotation of its
    state expression, which `certifiedThompson_state_language` already proves.  So "state `u`
    is dead" is "`standard u` accepts nothing", and the question moves from automata to syntax
    for good.

    The residuals have exactly the shapes the construction suggests —

        act    standard _        = 1
        seq    standard (inl v)  = (left standard v) ; rightProgram
               standard (inr w)  = right standard w
        ite    standard (inl v)  = left standard v          (and symmetrically)
        wh     standard v        = (body standard v) ; (while g do body)

    — and each one is precisely the continuation `Live` was tracking at that position.  That
    correspondence is what closes the argument: an occurrence is dead exactly when the
    continuation `Live` checked was null, and `Live` guarantees it was not, unless the
    occurrence is a sink. -/

theorem null_congr {e f : Exp A T} (h : EquivBA e f) (hn : UniformExpLempty e) :
    UniformExpLempty f := by
  intro X W gs hden
  exact hn X W gs ((sound_BA (V := W) h gs).mpr hden)

/-- A dead state has a null state expression — the automaton side, used once and then never
    again. -/
theorem standard_null_of_dead (p : Exp A T) (u : (certifiedThompson A T p).State)
    (hdead : ∀ (Y : Type) (V : T → Y → Bool) (y : Y) (w : List (A × Y)),
      ¬ autRun V (certifiedThompson A T p).aut.toGAut (some u) y w) :
    UniformExpLempty ((certifiedThompson A T p).standard u) := by
  intro Y V gs hden
  have hmem : (some u) ∈ (certifiedThompson A T p).aut.toGAut.states := by
    show (some u) ∈ none :: (certifiedThompson A T p).aut.core.states.map some
    exact List.Mem.tail _ (List.mem_map.mpr ⟨u, thompson_states_complete p u, rfl⟩)
  have hfun := congrFun (certifiedThompson_state_language p (some u) hmem Y V) gs
  exact hdead Y V gs.1 gs.2 (Eq.mpr hfun hden)

/-- If the continuation accepts nothing, neither does an action followed by it. -/
private theorem null_act_seq (p : A) {K : Exp A T}
    (h : UniformExpLempty (.seq (.test BExp.one) K : Exp A T)) :
    UniformExpLempty (.seq (.act p) K : Exp A T) := by
  have hK : UniformExpLempty K := null_congr (GkatGuardedAlgebra.one_seq K) h
  refine null_congr ?_ h
  refine EquivBA.trans (GkatGuardedAlgebra.one_seq K) ?_
  refine EquivBA.trans (GkatNullLanguage.nullLanguage_complete K hK) ?_
  exact EquivBA.symm
    (EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl (.act p)))
        (GkatNullLanguage.nullLanguage_complete K hK))
      (EquivBA.base (Equiv.s3 (.act p))))

/-- **Every dead occurrence is a sink.**  Induction on the `Live` derivation: at each
    position the residual is the continuation `Live` was checking, so a dead occurrence
    contradicts liveness — except at the sink, which is exempt and labelled `a₀`. -/
theorem deadStates_of_live (a₀ : A) {h K : Exp A T} (hl : Live a₀ h K) :
    ∀ u : (certifiedThompson A T h).State,
      UniformExpLempty (.seq ((certifiedThompson A T h).standard u) K) →
      actionOf h u = a₀ := by
  induction hl with
  | act p K hn =>
      intro u hnull
      exact absurd (null_act_seq p hnull) hn
  | sink K => intro u _; cases u; rfl
  | test b K => intro u _; exact nomatch u
  | @seq e f K _ _ ihe ihf =>
      intro u hnull
      cases u with
      | inl v =>
          refine ihe v (null_congr ?_ hnull)
          exact EquivBA.base (Equiv.s1 ((certifiedThompson A T e).standard v) f K)
      | inr w => exact ihf w hnull
  | ite g _ _ ihe ihf =>
      intro u hnull
      cases u with
      | inl v => exact ihe v hnull
      | inr w => exact ihf w hnull
  | @wh g e K _ ihe =>
      intro u hnull
      refine ihe u (null_congr ?_ hnull)
      exact EquivBA.base
        (Equiv.s1 ((certifiedThompson A T e).standard u) (.wh g e) K)

/-- **`LiveImpliesCanonical`, discharged.** -/
theorem liveImpliesCanonical_holds (a₀ : A) : LiveImpliesCanonical A T a₀ := by
  intro h hl
  refine deadCanonical_of_deadStates _ a₀ ?_
  intro u hdead
  refine deadStates_of_live a₀ hl u (null_congr ?_ (standard_null_of_dead h u hdead))
  exact EquivBA.symm (GkatGuardedAlgebra.seq_one _)

/-! ## Can the known obstruction refute what is left?

    Exactly one statement remains, so the next question is not "how do we prove it" but
    "can it be broken".  GKAT has one known inexpressibility obstruction — the nesting
    coequation `Nested`, which excludes the Figure 3 automaton — and it has never been pointed
    at the pullback.

    It cannot break it, and the reason is structural.  `Nested` is **reflected along covers**:
    a cover preserves halt guards pointwise and carries steps to steps, so a mutually-reachable
    pair with complementary halt guards in the source would produce one in the target.  The
    pullback *covers* the padded Thompson automaton (`pullbackFst`), so if that automaton is
    nested then so is the pullback — and no Figure-3 configuration can appear there to refute
    `PaddedPullbackCovered`.

    This is a negative result about refutations, and it is worth having: it says the one
    weapon available for showing something is not GKAT-expressible does not apply here, so
    effort belongs on proving the statement rather than breaking it. -/

theorem autStep1_cover {S S' : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut S' A T}
    {X : Type} (W : T → X → Bool) (φ : InitCover src tgt)
    {u v : Option S} (h : AutStep1 W src.toGAut u v) :
    AutStep1 W tgt.toGAut (u.map φ.map) (v.map φ.map) := by
  obtain ⟨x, q, hs⟩ := h
  refine ⟨x, q, ?_⟩
  rw [← cover_step φ W x u, hs]
  rfl

theorem autReaches_cover {S S' : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut S' A T}
    {X : Type} (W : T → X → Bool) (φ : InitCover src tgt)
    {u v : Option S} (h : AutReaches W src.toGAut u v) :
    AutReaches W tgt.toGAut (u.map φ.map) (v.map φ.map) := by
  induction h with
  | refl => exact AutReaches.refl _
  | tail _ hstep ih => exact AutReaches.tail ih (autStep1_cover W φ hstep)

theorem autReaches1_cover {S S' : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut S' A T}
    {X : Type} (W : T → X → Bool) (φ : InitCover src tgt)
    {u v : Option S} (h : AutReaches1 W src.toGAut u v) :
    AutReaches1 W tgt.toGAut (u.map φ.map) (v.map φ.map) := by
  obtain ⟨x, h1, h2⟩ := h
  exact ⟨x.map φ.map, autStep1_cover W φ h1, autReaches_cover W φ h2⟩

/-- **The nesting coequation is reflected along covers.**  If what a system covers is nested,
    so is the system. -/
theorem nested_of_cover {S S' : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut S' A T}
    {X : Type} (W : T → X → Bool) (φ : InitCover src tgt)
    (h : Nested W tgt.toGAut) : Nested W src.toGAut := by
  intro s1 s2 hs1 h12 h21 hcomp
  refine h (s1.map φ.map) (s2.map φ.map) ?_
    (autReaches1_cover W φ h12) (autReaches1_cover W φ h21) ?_
  · cases s1 with
    | none => exact List.Mem.head _
    | some u =>
        have hu : u ∈ src.core.states := by
          rcases List.mem_cons.mp hs1 with hc | hc
          · exact absurd hc (by simp)
          · obtain ⟨y, hy, hye⟩ := List.mem_map.mp hc
            exact (Option.some.inj hye) ▸ hy
        exact List.Mem.tail _ (List.mem_map.mpr ⟨φ.map u, φ.maps u hu, rfl⟩)
  · intro a
    rw [← cover_halt φ s1 W a, ← cover_halt φ s2 W a]
    exact hcomp a

/-- **The Figure-3 obstruction cannot refute what is left.**  Every pullback the completeness
    chain forms covers a Thompson automaton, so it inherits the nesting coequation from it.

    The hypothesis is the automaton analogue of `GkatKleene.Nested_derivAut`, which is already
    proved for the derivative automaton; it is a transport, not a new conjecture. -/
theorem pullback_nested {X : Type} (W : T → X → Bool) (a₀ : A) (e f : Exp A T)
    (hN : ∀ p : Exp A T, Nested W (certifiedThompson A T p).aut.toGAut)
    {Q : Type} {m : InitializedGAut Q A T}
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ) :
    Nested W (GkatPullback.pullback φ ψ base).toGAut :=
  nested_of_cover W (GkatPullback.pullbackFst φ ψ base) (hN (padZero e f a₀))

#print axioms nested_of_cover
#print axioms pullback_nested

/-! ## Un-sharing: the construction the measurement found

    The search settled the last statement empirically, and it did it by finding the *shape* of
    the cover rather than by searching harder.  Every padded kernel pair that no forward
    refinement could cover is covered by **un-sharing**: a state reachable from two different
    branches of the entry is given a private copy in each, and the copies are mapped back.
    One level of that covers 2181 of 2181 uncovered cases, so no repeated unfolding is needed —
    which matters, because the full tree unfolding is infinite on cyclic automata and would not
    become a construction at all.

    Here it is as a construction.  A cover may duplicate, so what a system needs is not one
    program covering all of it at once but *two lists of states* whose union is everything,
    each covered separately.  `relist` changes only which states an automaton lists, leaving
    its dynamics alone; `splitCover` folds two relistings back together.

    This is `dupCover` with the two copies allowed to list different states.  `dupCover` is the
    case `l₁ = l₂ = all`; the gain is that a shorter list is easier to cover, so a system no
    program covers whole can still be covered branch by branch. -/

/-- The same automaton, listing a different set of states.  Dynamics untouched. -/
def relist {S : Type} (P : InitializedGAut S A T) (l : List S) : InitializedGAut S A T where
  core := { states := l, hlt := P.core.hlt, trans := P.core.trans }
  initHlt := P.initHlt
  initTrans := P.initTrans

private theorem fmGuardFold {S X : Type} (W : T → X → Bool) (x : X) (P : BExp T)
    (F : S → Sum S S) (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P t.1, t.2.1, F t.2.2))) =
      if bval W P x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, act, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P q) x = (bval W P x && bval W q x) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hq : bval W q x <;> simp

private def foldSum {S : Type} : Sum S S → S
  | Sum.inl s => s
  | Sum.inr s => s

/-- **Un-sharing is a cover.**  Split `P`'s states into two lists that between them cover
    everything, guard the two copies apart, and the fold is a cover of `P`. -/
def splitCover (g : BExp T) {S : Type} (P : InitializedGAut S A T) (l₁ l₂ : List S)
    (h₁ : ∀ s ∈ l₁, s ∈ P.core.states) (h₂ : ∀ s ∈ l₂, s ∈ P.core.states)
    (hcov : ∀ q ∈ P.core.states, q ∈ l₁ ∨ q ∈ l₂) :
    InitCover (iteInitialized g (relist P l₁) (relist P l₂)) P where
  map := foldSum
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and g P.initHlt) (BExp.and (BExp.not g) P.initHlt)) x
      = bval W P.initHlt x
    cases hg : bval W g x <;> simp [bval, hg]
  coreHlt_eq := fun s _ _ _ => by
    cases s with
    | inl _ => rfl
    | inr _ => rfl
  initStep_eq := fun X W x => by
    show (firstMatch W x
        (P.initTrans.map (fun t => (BExp.and g t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))) ++
         P.initTrans.map (fun t =>
           (BExp.and (BExp.not g) t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
        (fun o => (o.1, foldSum o.2))
      = firstMatch W x P.initTrans
    have hl := fmGuardFold (A := A) W x g (fun s : S => (Sum.inl s : Sum S S)) P.initTrans
    have hr := fmGuardFold (A := A) W x (BExp.not g)
      (fun s : S => (Sum.inr s : Sum S S)) P.initTrans
    have hnot : bval W (BExp.not g) x = !bval W g x := rfl
    cases hg : bval W g x
    · rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg]; simp), hr, hnot, hg]
      cases firstMatch W x P.initTrans <;> simp [foldSum]
    · cases he : firstMatch W x P.initTrans with
      | some o =>
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum S S)))
            _ _ _ _ (by rw [hl, hg, he]; simp)]
          simp [foldSum]
      | none =>
          rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg, he]; simp), hr, hnot, hg]
          simp
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        show (firstMatch W x
            ((P.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))))).map
            (fun o => (o.1, foldSum o.2))
          = firstMatch W x (P.core.trans u)
        rw [firstMatch_map_target_to (F := fun s : S => (Sum.inl s : Sum S S))]
        cases firstMatch W x (P.core.trans u) <;> simp [foldSum]
    | inr u =>
        show (firstMatch W x
            ((P.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
            (fun o => (o.1, foldSum o.2))
          = firstMatch W x (P.core.trans u)
        rw [firstMatch_map_target_to (F := fun s : S => (Sum.inr s : Sum S S))]
        cases firstMatch W x (P.core.trans u) <;> simp [foldSum]
  maps := by
    intro s hs
    have hs' : s ∈ l₁.map (Sum.inl : S → Sum S S) ++ l₂.map (Sum.inr : S → Sum S S) := hs
    rcases List.mem_append.mp hs' with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact h₁ u hu
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact h₂ u hu
  onto := by
    intro q hq
    rcases hcov q hq with h | h
    · exact ⟨Sum.inl q, List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨q, h, rfl⟩)), rfl⟩
    · exact ⟨Sum.inr q, List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨q, h, rfl⟩)), rfl⟩

/-- **Un-sharing reduces coverability to the branches.**  If each list is covered when listed
    alone, the whole system is covered — by `if g then <first> else <second>`.

    This is the construction the sweep found, stated once and for all: a system no single
    program covers can still be covered branch by branch, because a cover is allowed to
    duplicate. -/
theorem hasThompsonCover_of_split (g : BExp T) {S : Type} (P : InitializedGAut S A T)
    (l₁ l₂ : List S)
    (h₁ : ∀ s ∈ l₁, s ∈ P.core.states) (h₂ : ∀ s ∈ l₂, s ∈ P.core.states)
    (hcov : ∀ q ∈ P.core.states, q ∈ l₁ ∨ q ∈ l₂)
    (hc₁ : HasThompsonCover (relist P l₁)) (hc₂ : HasThompsonCover (relist P l₂)) :
    HasThompsonCover P := by
  obtain ⟨h1, ⟨χ1⟩⟩ := hc₁
  obtain ⟨h2, ⟨χ2⟩⟩ := hc₂
  exact ⟨.ite g h1 h2,
    ⟨(InitCover.ite g χ1 χ2).comp (splitCover g P l₁ l₂ h₁ h₂ hcov)⟩⟩

/-! ### `restrict` — the operation the measurement actually uses

    `relist` was the wrong primitive.  The un-shared parts the search builds carry a
    **restricted entry**: the copy for a guard region has no entry transition outside it.
    `relist` keeps the whole pseudostate, so a cover of `relist P l₁` still has to answer for
    `P`'s entry at the *other* atoms, and `maps` then drags that entry target into `l₁` — which
    a branch list does not contain.  That is why the branch lists could never instantiate
    `hasThompsonCover_of_split`, and why the 2181/2181 result was not evidence for it.

    `restrict P l g` fixes it: same core, state list `l`, entry conjoined with `g`.  Then
    `ite g (restrict P l₁ g) (restrict P l₂ ¬g)` reproduces `P`'s entry — the double guard
    `g ∧ (g ∧ t)` collapses — and *is* the automaton the search builds. -/

/-- The same automaton with a restricted state list **and** a restricted entry. -/
def restrict {S : Type} (P : InitializedGAut S A T) (l : List S) (g : BExp T) :
    InitializedGAut S A T where
  core := { states := l, hlt := P.core.hlt, trans := P.core.trans }
  initHlt := .and g P.initHlt
  initTrans := P.initTrans.map (fun t => (BExp.and g t.1, t.2))

private theorem fmTwice {S X : Type} (W : T → X → Bool) (x : X) (P : BExp T)
    (F : S → Sum S S) (L : List (BExp T × A × S)) :
    firstMatch W x ((L.map (fun t => (BExp.and P t.1, t.2))).map
        (fun t => (BExp.and P t.1, t.2.1, F t.2.2)))
      = if bval W P x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, act, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and P q)) x
        = (bval W P x && (bval W P x && bval W q x)) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hq : bval W q x <;> simp

/-- **The restricted split is a cover.**  No side conditions on the lists at all: the two
    restricted copies list `l₁` and `l₂`, and together they are exactly `l₁ ++ l₂`. -/
def restrictSplitCover (g : BExp T) {S : Type} (P : InitializedGAut S A T) (l₁ l₂ : List S) :
    InitCover (iteInitialized g (restrict P l₁ g) (restrict P l₂ (.not g)))
      (relist P (l₁ ++ l₂)) where
  map := foldSum
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and g (BExp.and g P.initHlt))
      (BExp.and (BExp.not g) (BExp.and (BExp.not g) P.initHlt))) x = bval W P.initHlt x
    cases hg : bval W g x <;> simp [bval, hg]
  coreHlt_eq := fun s _ _ _ => by
    cases s with
    | inl _ => rfl
    | inr _ => rfl
  initStep_eq := fun X W x => by
    show (firstMatch W x
        ((P.initTrans.map (fun t => (BExp.and g t.1, t.2))).map
            (fun t => (BExp.and g t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))) ++
         (P.initTrans.map (fun t => (BExp.and (BExp.not g) t.1, t.2))).map
            (fun t => (BExp.and (BExp.not g) t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
        (fun o => (o.1, foldSum o.2))
      = firstMatch W x P.initTrans
    have hl := fmTwice (A := A) W x g (fun s : S => (Sum.inl s : Sum S S)) P.initTrans
    have hr := fmTwice (A := A) W x (BExp.not g)
      (fun s : S => (Sum.inr s : Sum S S)) P.initTrans
    have hnot : bval W (BExp.not g) x = !bval W g x := rfl
    cases hg : bval W g x
    · rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg]; simp), hr, hnot, hg]
      cases firstMatch W x P.initTrans <;> simp [foldSum]
    · cases he : firstMatch W x P.initTrans with
      | some o =>
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum S S)))
            _ _ _ _ (by rw [hl, hg, he]; simp)]
          simp [foldSum]
      | none =>
          rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg, he]; simp), hr, hnot, hg]
          simp
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        show (firstMatch W x
            ((P.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))))).map
            (fun o => (o.1, foldSum o.2))
          = firstMatch W x (P.core.trans u)
        rw [firstMatch_map_target_to (F := fun s : S => (Sum.inl s : Sum S S))]
        cases firstMatch W x (P.core.trans u) <;> simp [foldSum]
    | inr u =>
        show (firstMatch W x
            ((P.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
            (fun o => (o.1, foldSum o.2))
          = firstMatch W x (P.core.trans u)
        rw [firstMatch_map_target_to (F := fun s : S => (Sum.inr s : Sum S S))]
        cases firstMatch W x (P.core.trans u) <;> simp [foldSum]
  maps := by
    intro s hs
    have hs' : s ∈ l₁.map (Sum.inl : S → Sum S S) ++ l₂.map (Sum.inr : S → Sum S S) := hs
    rcases List.mem_append.mp hs' with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inl hu)
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inr hu)
  onto := by
    intro q hq
    rcases List.mem_append.mp hq with h | h
    · exact ⟨Sum.inl q, List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨q, h, rfl⟩)), rfl⟩
    · exact ⟨Sum.inr q, List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨q, h, rfl⟩)), rfl⟩

/-- **Un-sharing, correctly modelled.**  If each restricted branch is coverable, so is the
    relisting on their union — by `if g then <first> else <second>`. -/
theorem hasThompsonCover_of_restrictSplit (g : BExp T) {S : Type} (P : InitializedGAut S A T)
    (l₁ l₂ : List S)
    (h₁ : HasThompsonCover (restrict P l₁ g))
    (h₂ : HasThompsonCover (restrict P l₂ (.not g))) :
    HasThompsonCover (relist P (l₁ ++ l₂)) := by
  obtain ⟨e₁, ⟨χ₁⟩⟩ := h₁
  obtain ⟨e₂, ⟨χ₂⟩⟩ := h₂
  exact ⟨.ite g e₁ e₂, ⟨(InitCover.ite g χ₁ χ₂).comp (restrictSplitCover g P l₁ l₂)⟩⟩

#print axioms restrictSplitCover
#print axioms hasThompsonCover_of_restrictSplit

/-- **Un-sharing at arbitrary arity.**  A pseudostate's guarded transition list can have any
    number of branches, so the split has to be `n`-ary, not binary.  Any finite family of state
    lists that between them cover the system will do, and the guard is irrelevant — both copies
    of a `splitCover` carry the *same* dynamics, so nothing depends on which atoms the guard
    selects.  That is what makes the induction go through with a single fixed guard. -/
theorem hasThompsonCover_of_splitN {S : Type} (g : BExp T) :
    ∀ (ls : List (List S)) (P : InitializedGAut S A T), ls ≠ [] →
      (∀ l ∈ ls, ∀ s ∈ l, s ∈ P.core.states) →
      (∀ q ∈ P.core.states, ∃ l ∈ ls, q ∈ l) →
      (∀ l ∈ ls, HasThompsonCover (relist P l)) →
      HasThompsonCover P := by
  intro ls
  induction ls with
  | nil => intro _ hne; exact absurd rfl hne
  | cons l rest ih =>
      intro P _ hsub hcov hall
      cases rest with
      | nil =>
          refine hasThompsonCover_of_split g P l l
            (hsub l (List.Mem.head _)) (hsub l (List.Mem.head _)) ?_
            (hall l (List.Mem.head _)) (hall l (List.Mem.head _))
          intro q hq
          obtain ⟨l', hl', hq'⟩ := hcov q hq
          rcases List.mem_cons.mp hl' with rfl | hc
          · exact Or.inl hq'
          · exact absurd hc (by simp)
      | cons l' rest' =>
          have hflat : ∀ s ∈ (l' :: rest').flatten, s ∈ P.core.states := by
            intro s hs
            obtain ⟨t, ht, hst⟩ := List.mem_flatten.mp hs
            exact hsub t (List.Mem.tail _ ht) s hst
          have hrest : HasThompsonCover (relist P ((l' :: rest').flatten)) := by
            refine ih (relist P ((l' :: rest').flatten)) (by simp) ?_ ?_ ?_
            · intro t ht s hs
              exact List.mem_flatten.mpr ⟨t, ht, hs⟩
            · intro q hq
              obtain ⟨t, ht, hqt⟩ := List.mem_flatten.mp hq
              exact ⟨t, ht, hqt⟩
            · intro t ht
              exact hall t (List.Mem.tail _ ht)
          refine hasThompsonCover_of_split g P l ((l' :: rest').flatten)
            (hsub l (List.Mem.head _)) hflat ?_ (hall l (List.Mem.head _)) hrest
          intro q hq
          obtain ⟨t, ht, hqt⟩ := hcov q hq
          rcases List.mem_cons.mp ht with rfl | hc
          · exact Or.inl hqt
          · exact Or.inr (List.mem_flatten.mpr ⟨t, hc, hqt⟩)

/-- `dupCover` is the degenerate case: both copies list everything. -/
theorem relist_self {S : Type} (P : InitializedGAut S A T) : relist P P.core.states = P := rfl

/-- **The last statement, in the shape the measurement verified.**  Instead of asking for one
    program covering the whole pullback, ask for a guard and two lists of its states that
    between them cover everything, each coverable on its own.

    That is exactly what the sweep checked: the branch reachable sets of the entry, one level,
    2181 of 2181 uncovered padded kernel pairs.  Stating it this way means the remaining
    obligation and the evidence for it are the same statement, rather than the evidence being
    for a construction and the obligation being about something else. -/
def BranchesCovered (A T : Type) (a₀ : A) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ),
    ∃ ls : List (List (GkatPullback.Fib φ ψ)), ls ≠ [] ∧
      (∀ l ∈ ls, ∀ s ∈ l, s ∈ (GkatPullback.pullback φ ψ base).core.states) ∧
      (∀ q ∈ (GkatPullback.pullback φ ψ base).core.states, ∃ l ∈ ls, q ∈ l) ∧
      (∀ l ∈ ls, HasThompsonCover (relist (GkatPullback.pullback φ ψ base) l))

theorem paddedPullbackCovered_of_branchesCovered (a₀ : A) (hb : BranchesCovered A T a₀) :
    PaddedPullbackCovered A T a₀ := by
  intro e f Q m φ ψ base
  obtain ⟨ls, hne, hsub, hcov, hall⟩ := hb e f Q m φ ψ base
  exact hasThompsonCover_of_splitN BExp.one ls _ hne hsub hcov hall

#print axioms relist_self
#print axioms paddedPullbackCovered_of_branchesCovered
#print axioms hasThompsonCover_of_splitN
#print axioms splitCover
#print axioms hasThompsonCover_of_split

/-! ## The measured object and the stated object are not the same

    Worth recording before any more evidence is collected against the wrong target.

    `GkatPullback.pullback` lists **every matched pair**: its `core.states` is
    `a.core.states.flatMap (fun u => b.core.states.map (pairUp base u ·))`, so it is the whole
    product with unmatched pairs collapsed onto the basepoint.  The search harness builds its
    pullback by breadth-first exploration from the entry, and `canon` renumbers by a
    breadth-first walk and drops what it never reaches — so the harness measured the
    **reachable** pullback.

    `onto` in `InitCover` is with respect to the *listed* states, so covering the stated object
    is strictly harder than covering the measured one.  The 4679/4679 result is evidence for
    the reachable pullback, not for `PaddedPullbackCovered` as written.

    The full listing is not gratuitous: it is how both projections are onto without assuming
    reachability, which is exactly what padding was introduced to avoid.  But with padding it
    is far more than needed.  Both legs of the padded span are the *same* map
    (`pad_span_maps_agree`), so every **diagonal** pair is matched — and the diagonal alone
    already projects onto every state of both sides.  So the listing can shrink from `|S|²` to
    `|S|` without giving up `onto`, which is the direction that would make the stated object
    and the measured one meet. -/

/-- With padding, every diagonal pair is matched — both legs of the span are `rep`. -/
theorem pad_diag_matched (a₀ : A) (e f : Exp A T) (hlang : UniformLanguageEquivalent e f)
    (ht0 : Total (certifiedThompson A T (padZero e f a₀)).aut)
    (ht1 : Total (certifiedThompson A T (padOne e f a₀)).aut)
    (hc0 : DeadCanonical a₀ (certifiedThompson A T (padZero e f a₀)).aut)
    (hc1 : DeadCanonical a₀ (certifiedThompson A T (padOne e f a₀)).aut)
    (u : (certifiedThompson A T (padZero e f a₀)).State) :
    (GkatQuotient.matchCover (matched_of_pad a₀ e f hlang ht0 ht1 hc0 hc1)).map u
      = (GkatQuotient.targetCover
          (matched_of_pad a₀ e f hlang ht0 ht1 hc0 hc1).stepbb).map u :=
  congrFun (pad_span_maps_agree a₀ e f hlang ht0 ht1 hc0 hc1) u

/-- **The diagonal alone is onto both projections.**  So a listing containing just the
    diagonal keeps `pullbackFst` and `pullbackSnd` surjective, and the object to cover shrinks
    from the whole matched product to something the size of one side. -/
theorem diag_onto {S Q : Type} {a b : InitializedGAut S A T} {m : InitializedGAut Q A T}
    (φ : InitCover a m) (ψ : InitCover b m) (base : GkatPullback.Base φ ψ)
    (hmaps : φ.map = ψ.map) (hstates : a.core.states = b.core.states) :
    ∀ q ∈ a.core.states,
      ∃ p ∈ (a.core.states.map (fun u => GkatPullback.pairUp base u u)),
        (p : GkatPullback.Fib φ ψ).val.1 = q := by
  intro q hq
  refine ⟨GkatPullback.pairUp base q q, List.mem_map.mpr ⟨q, hq, rfl⟩, ?_⟩
  exact GkatPullback.pairUp_fst base (by rw [hmaps])

/-! ### The diagonal-listed pullback

    Listing only the diagonal keeps both projections onto, so the object the chain has to
    cover shrinks from the whole matched product to the size of one side.  Nothing else about
    the pullback changes — `relist` rewrites the state list and leaves the dynamics alone — so
    every cover condition except `maps` and `onto` is reused verbatim from `pullbackFst` and
    `pullbackSnd`. -/

/-- The diagonal of the pullback, as a state list.  It is what makes the projections onto;
    it is *not* enough on its own to be listed, because the pullback's entry target is
    off-diagonal — the two padded entries land in different summands — and `maps` would then
    force a covering automaton's entry state outside the list.  So the listing has to contain
    the diagonal, not equal it. -/
noncomputable def diagList {S Q : Type} {a b : InitializedGAut S A T} {m : InitializedGAut Q A T}
    (φ : InitCover a m) (ψ : InitCover b m) (base : GkatPullback.Base φ ψ) :
    List (GkatPullback.Fib φ ψ) :=
  a.core.states.map (fun u => GkatPullback.pairUp base u u)

/-- The pullback listed on `l` instead of the whole matched product. -/
noncomputable def pullbackOn {S₁ S₂ Q : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {m : InitializedGAut Q A T}
    (φ : InitCover a m) (ψ : InitCover b m)
    (base : GkatPullback.Base φ ψ) (l : List (GkatPullback.Fib φ ψ)) :
    InitializedGAut (GkatPullback.Fib φ ψ) A T :=
  relist (GkatPullback.pullback φ ψ base) l

/-- **The left projection survives any listing that contains the diagonal and stays inside
    the full one.** -/
noncomputable def pullbackOnFst {S Q : Type} {a b : InitializedGAut S A T}
    {m : InitializedGAut Q A T} (φ : InitCover a m) (ψ : InitCover b m)
    (base : GkatPullback.Base φ ψ) (l : List (GkatPullback.Fib φ ψ))
    (hmaps : φ.map = ψ.map)
    (hsub : ∀ s ∈ l, s ∈ (GkatPullback.pullback φ ψ base).core.states)
    (hdiag : ∀ u ∈ a.core.states, GkatPullback.pairUp base u u ∈ l) :
    InitCover (pullbackOn φ ψ base l) a where
  map := fun p => p.val.1
  initHlt_eq := (GkatPullback.pullbackFst φ ψ base).initHlt_eq
  coreHlt_eq := (GkatPullback.pullbackFst φ ψ base).coreHlt_eq
  initStep_eq := (GkatPullback.pullbackFst φ ψ base).initStep_eq
  coreStep_eq := (GkatPullback.pullbackFst φ ψ base).coreStep_eq
  maps := fun s hs => (GkatPullback.pullbackFst φ ψ base).maps s (hsub s hs)
  onto := by
    intro q hq
    exact ⟨GkatPullback.pairUp base q q, hdiag q hq,
      GkatPullback.pairUp_fst base (by rw [hmaps])⟩

/-- **And so does the right projection**, given the two sides list the same states — which
    padding guarantees, since the padded pair shares a core. -/
noncomputable def pullbackOnSnd {S Q : Type} {a b : InitializedGAut S A T}
    {m : InitializedGAut Q A T} (φ : InitCover a m) (ψ : InitCover b m)
    (base : GkatPullback.Base φ ψ) (l : List (GkatPullback.Fib φ ψ))
    (hmaps : φ.map = ψ.map) (hstates : a.core.states = b.core.states)
    (hsub : ∀ s ∈ l, s ∈ (GkatPullback.pullback φ ψ base).core.states)
    (hdiag : ∀ u ∈ a.core.states, GkatPullback.pairUp base u u ∈ l) :
    InitCover (pullbackOn φ ψ base l) b where
  map := fun p => p.val.2
  initHlt_eq := (GkatPullback.pullbackSnd φ ψ base).initHlt_eq
  coreHlt_eq := (GkatPullback.pullbackSnd φ ψ base).coreHlt_eq
  initStep_eq := (GkatPullback.pullbackSnd φ ψ base).initStep_eq
  coreStep_eq := (GkatPullback.pullbackSnd φ ψ base).coreStep_eq
  maps := fun s hs => (GkatPullback.pullbackSnd φ ψ base).maps s (hsub s hs)
  onto := by
    intro q hq
    exact ⟨GkatPullback.pairUp base q q, hdiag q (hstates ▸ hq),
      GkatPullback.pairUp_snd base (by rw [hmaps])⟩

/-! ### The partner function

    The direct route.  A cover of the pullback by one side is exactly a **partner function**:
    a map `σ` sending each state of the left component to a state of the right that it is
    matched with, and that commutes with the dynamics.  Then `u ↦ (u, σ u)` is a cover, the
    listing is the graph of `σ`, and — since the left component *is* a Thompson automaton —
    the pullback is Thompson-covered outright.

    This is where the sharing problem lives, and it is now visible as one hypothesis rather
    than spread through a search.  `σ` is forced along every run: the entry pins `σ` at the
    first target, and `hcore` propagates it.  It is well defined exactly when no state is
    reached carrying two different partners — and un-sharing is what repairs that by
    duplicating the state so each copy can carry its own partner. -/

/-- The graph of a partner function, as a state list. -/
noncomputable def graphList {S₁ S₂ Q : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {m : InitializedGAut Q A T}
    (φ : InitCover a m) (ψ : InitCover b m) (base : GkatPullback.Base φ ψ) (σ : S₁ → S₂) :
    List (GkatPullback.Fib φ ψ) :=
  a.core.states.map (fun u => GkatPullback.pairUp base u (σ u))

/-- **A partner function is a cover.**  The left component covers the pullback listed on the
    graph of `σ`. -/
noncomputable def graphCover {S₁ S₂ Q : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} {m : InitializedGAut Q A T}
    (φ : InitCover a m) (ψ : InitCover b m) (base : GkatPullback.Base φ ψ) (σ : S₁ → S₂)
    (hmatch : ∀ u, φ.map u = ψ.map (σ u))
    (hinit : ∀ (X : Type) (W : T → X → Bool) (x : X) (o : A × S₁),
      firstMatch W x a.initTrans = some o →
      firstMatch W x b.initTrans = some (o.1, σ o.2))
    (hcore : ∀ (X : Type) (W : T → X → Bool) (x : X) (u : S₁) (o : A × S₁),
      firstMatch W x (a.core.trans u) = some o →
      firstMatch W x (b.core.trans (σ u)) = some (o.1, σ o.2)) :
    InitCover a (pullbackOn φ ψ base (graphList φ ψ base σ)) where
  map := fun u => GkatPullback.pairUp base u (σ u)
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun u _ W x => by
    show bval W (a.core.hlt u) x
      = bval W (a.core.hlt (GkatPullback.pairUp base u (σ u)).val.1) x
    rw [GkatPullback.pairUp_fst base (hmatch u)]
  initStep_eq := fun X W x => by
    show (firstMatch W x a.initTrans).map
        (fun o => (o.1, GkatPullback.pairUp base o.2 (σ o.2)))
      = firstMatch W x
          ((GkatSynthesis.crossTrans a.initTrans b.initTrans).map
            (fun t => (t.1, t.2.1, GkatPullback.pairUp base t.2.2.1 t.2.2.2)))
    rw [firstMatch_map_target_to
        (F := fun q : S₁ × S₂ => GkatPullback.pairUp base q.1 q.2),
      GkatSynthesis.firstMatch_crossTrans]
    cases h₁ : firstMatch W x a.initTrans with
    | none => rfl
    | some o₁ => rw [hinit X W x o₁ h₁]; rfl
  coreStep_eq := fun u X W x => by
    show (firstMatch W x (a.core.trans u)).map
        (fun o => (o.1, GkatPullback.pairUp base o.2 (σ o.2)))
      = firstMatch W x
          ((GkatSynthesis.crossTrans (a.core.trans (GkatPullback.pairUp base u (σ u)).val.1)
            (b.core.trans (GkatPullback.pairUp base u (σ u)).val.2)).map
            (fun t => (t.1, t.2.1, GkatPullback.pairUp base t.2.2.1 t.2.2.2)))
    rw [GkatPullback.pairUp_fst base (hmatch u), GkatPullback.pairUp_snd base (hmatch u),
      firstMatch_map_target_to
        (F := fun q : S₁ × S₂ => GkatPullback.pairUp base q.1 q.2),
      GkatSynthesis.firstMatch_crossTrans]
    cases h₁ : firstMatch W x (a.core.trans u) with
    | none => rfl
    | some o₁ => rw [hcore X W x u o₁ h₁]; rfl
  maps := fun u hu => List.mem_map.mpr ⟨u, hu, rfl⟩
  onto := by
    intro q hq
    obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hq
    exact ⟨u, hu, rfl⟩

/-- **Graph and diagonal at once.**  `graphCover` alone lists only `σ`'s graph, and then the
    *right* projection's `onto` would need `σ` surjective.  Duplicating the source fixes it:
    `ite 1 a a` is still a Thompson automaton, the left copy carries the graph of `σ`, and the
    right copy carries the diagonal.

    The diagonal copy commutes for free because the padded pair **shares its core** — the
    identity is a partner function on core states.  And the guard `1` makes the right copy
    unreachable from the entry, so nothing forces its map to agree with `σ`. -/
noncomputable def graphDiagCover {S Q : Type} {a b : InitializedGAut S A T}
    {m : InitializedGAut Q A T} (φ : InitCover a m) (ψ : InitCover b m)
    (base : GkatPullback.Base φ ψ) (σ : S → S)
    (hshare : ∀ u, b.core.trans u = a.core.trans u)
    (hdiag : ∀ u, φ.map u = ψ.map u)
    (hmatch : ∀ u, φ.map u = ψ.map (σ u))
    (hinit : ∀ (X : Type) (W : T → X → Bool) (x : X) (o : A × S),
      firstMatch W x a.initTrans = some o →
      firstMatch W x b.initTrans = some (o.1, σ o.2))
    (hcore : ∀ (X : Type) (W : T → X → Bool) (x : X) (u : S) (o : A × S),
      firstMatch W x (a.core.trans u) = some o →
      firstMatch W x (b.core.trans (σ u)) = some (o.1, σ o.2)) :
    InitCover (iteInitialized BExp.one a a)
      (pullbackOn φ ψ base (graphList φ ψ base σ ++ diagList φ ψ base)) where
  map := Sum.elim (fun u => GkatPullback.pairUp base u (σ u))
    (fun u => GkatPullback.pairUp base u u)
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and BExp.one a.initHlt)
      (BExp.and (BExp.not BExp.one) a.initHlt)) x = bval W a.initHlt x
    simp [bval]
  coreHlt_eq := fun s _ W x => by
    cases s with
    | inl u =>
        show bval W (a.core.hlt u) x
          = bval W (a.core.hlt (GkatPullback.pairUp base u (σ u)).val.1) x
        rw [GkatPullback.pairUp_fst base (hmatch u)]
    | inr u =>
        show bval W (a.core.hlt u) x
          = bval W (a.core.hlt (GkatPullback.pairUp base u u).val.1) x
        rw [GkatPullback.pairUp_fst base (hdiag u)]
  initStep_eq := fun X W x => by
    show (firstMatch W x
        (a.initTrans.map (fun t => (BExp.and BExp.one t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))) ++
         a.initTrans.map (fun t =>
           (BExp.and (BExp.not BExp.one) t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
        (fun o => (o.1, Sum.elim (fun u => GkatPullback.pairUp base u (σ u))
          (fun u => GkatPullback.pairUp base u u) o.2))
      = firstMatch W x
          ((GkatSynthesis.crossTrans a.initTrans b.initTrans).map
            (fun t => (t.1, t.2.1, GkatPullback.pairUp base t.2.2.1 t.2.2.2)))
    rw [firstMatch_map_target_to
        (F := fun q : S × S => GkatPullback.pairUp base q.1 q.2),
      GkatSynthesis.firstMatch_crossTrans]
    have hl := fmGuardFold (A := A) W x BExp.one (fun s : S => (Sum.inl s : Sum S S))
      a.initTrans
    have hr := fmGuardFold (A := A) W x (BExp.not BExp.one)
      (fun s : S => (Sum.inr s : Sum S S)) a.initTrans
    cases h₁ : firstMatch W x a.initTrans with
    | none =>
        rw [firstMatch_append_none _ _ _ _ (by rw [hl, h₁]; simp [bval]), hr]
        simp [bval]
    | some o =>
        rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum S S)))
          _ _ _ _ (by rw [hl, h₁]; simp [bval])]
        rw [hinit X W x o h₁]
        rfl
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        show (firstMatch W x
            ((a.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))))).map
            (fun o => (o.1, Sum.elim (fun v => GkatPullback.pairUp base v (σ v))
              (fun v => GkatPullback.pairUp base v v) o.2))
          = firstMatch W x
              ((GkatSynthesis.crossTrans
                (a.core.trans (GkatPullback.pairUp base u (σ u)).val.1)
                (b.core.trans (GkatPullback.pairUp base u (σ u)).val.2)).map
                (fun t => (t.1, t.2.1, GkatPullback.pairUp base t.2.2.1 t.2.2.2)))
        rw [GkatPullback.pairUp_fst base (hmatch u), GkatPullback.pairUp_snd base (hmatch u),
          firstMatch_map_target_to (F := fun v : S => (Sum.inl v : Sum S S)),
          firstMatch_map_target_to
            (F := fun q : S × S => GkatPullback.pairUp base q.1 q.2),
          GkatSynthesis.firstMatch_crossTrans]
        cases h₁ : firstMatch W x (a.core.trans u) with
        | none => rfl
        | some o => rw [hcore X W x u o h₁]; rfl
    | inr u =>
        show (firstMatch W x
            ((a.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
            (fun o => (o.1, Sum.elim (fun v => GkatPullback.pairUp base v (σ v))
              (fun v => GkatPullback.pairUp base v v) o.2))
          = firstMatch W x
              ((GkatSynthesis.crossTrans
                (a.core.trans (GkatPullback.pairUp base u u).val.1)
                (b.core.trans (GkatPullback.pairUp base u u).val.2)).map
                (fun t => (t.1, t.2.1, GkatPullback.pairUp base t.2.2.1 t.2.2.2)))
        rw [GkatPullback.pairUp_fst base (hdiag u), GkatPullback.pairUp_snd base (hdiag u),
          hshare u,
          firstMatch_map_target_to (F := fun v : S => (Sum.inr v : Sum S S)),
          firstMatch_map_target_to
            (F := fun q : S × S => GkatPullback.pairUp base q.1 q.2),
          GkatSynthesis.firstMatch_crossTrans]
        cases h₁ : firstMatch W x (a.core.trans u) with
        | none => rfl
        | some o => rfl
  maps := by
    intro s hs
    have hs' : s ∈ a.core.states.map (Sum.inl : S → Sum S S) ++
        a.core.states.map (Sum.inr : S → Sum S S) := hs
    rcases List.mem_append.mp hs' with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨u, hu, rfl⟩))
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩))
  onto := by
    intro q hq
    rcases List.mem_append.mp hq with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact ⟨Sum.inl u,
        List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨u, hu, rfl⟩)), rfl⟩
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact ⟨Sum.inr u,
        List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩)), rfl⟩

/-- **The pullback is Thompson-covered as soon as a partner function exists**, because the
    left component of the padded span is itself a Thompson automaton. -/
theorem hasThompsonCover_of_partner {S₂ Q : Type} (a₀ : A) (e f : Exp A T)
    {b : InitializedGAut S₂ A T} {m : InitializedGAut Q A T}
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m) (ψ : InitCover b m)
    (base : GkatPullback.Base φ ψ)
    (σ : (certifiedThompson A T (padZero e f a₀)).State → S₂)
    (hmatch : ∀ u, φ.map u = ψ.map (σ u))
    (hinit : ∀ (X : Type) (W : T → X → Bool) (x : X)
      (o : A × (certifiedThompson A T (padZero e f a₀)).State),
      firstMatch W x (certifiedThompson A T (padZero e f a₀)).aut.initTrans = some o →
      firstMatch W x b.initTrans = some (o.1, σ o.2))
    (hcore : ∀ (X : Type) (W : T → X → Bool) (x : X)
      (u : (certifiedThompson A T (padZero e f a₀)).State)
      (o : A × (certifiedThompson A T (padZero e f a₀)).State),
      firstMatch W x ((certifiedThompson A T (padZero e f a₀)).aut.core.trans u) = some o →
      firstMatch W x (b.core.trans (σ u)) = some (o.1, σ o.2)) :
    HasThompsonCover (pullbackOn φ ψ base (graphList φ ψ base σ)) :=
  ⟨padZero e f a₀, ⟨graphCover φ ψ base σ hmatch hinit hcore⟩⟩

#print axioms graphCover
#print axioms graphDiagCover
#print axioms hasThompsonCover_of_partner

#print axioms pullbackOnFst
#print axioms pullbackOnSnd

#print axioms pad_diag_matched
#print axioms diag_onto

/-! ## Completeness from one statement -/

/-- Every state of the sink is an `a₀` occurrence. -/
theorem actionOf_div (a₀ : A) (u : (certifiedThompson A T (div a₀)).State) :
    actionOf (div a₀ : Exp A T) u = a₀ := by
  cases u; rfl

/-- **`CanonicallySettled`, discharged.** -/
theorem canonicallySettled_holds (a₀ : A) : CanonicallySettled A T a₀ :=
  canonicallySettled_of_bridge a₀ (liveImpliesCanonical_holds a₀)

/-- **Completeness follows from `PullbackCovered` alone.**

    Every other hypothesis the chain ever carried — uniqueness, productivity, reachability,
    non-nullity, a common target, dead-canonicity — is now a theorem. -/
theorem completeness_of_pullbackCovered (a₀ : A) (hpc : PaddedPullbackCovered A T a₀) :
    FiniteAxiomsCompleteBA A T :=
  completeness_of_canonicallySettled a₀ (canonicallySettled_holds a₀) hpc

#print axioms actionOf_div
#print axioms deadStates_of_live
#print axioms liveImpliesCanonical_holds
#print axioms canonicallySettled_holds
#print axioms rep_eq_iff_langEquiv
#print axioms pad_span_maps_agree
/-- **The last statement, about the diagonal-listed pullback.**  Same shape as
    `PaddedPullbackCovered`, but the object to cover is the size of one side rather than of the
    whole matched product — and it is the object the search harness actually measures, since
    that builds its pullback by exploring from the entry. -/
def PaddedDiagPullbackCovered (A T : Type) (a₀ : A) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ), φ.map = ψ.map →
    ∃ l : List (GkatPullback.Fib φ ψ),
      (∀ s ∈ l, s ∈ (GkatPullback.pullback φ ψ base).core.states) ∧
      (∀ u ∈ (certifiedThompson A T (padZero e f a₀)).aut.core.states,
        GkatPullback.pairUp base u u ∈ l) ∧
      HasThompsonCover (pullbackOn φ ψ base l)

/-- **Completeness from the diagonal-listed pullback.**  The padded span satisfies the
    map-equality hypothesis by `pad_span_maps_agree`, and shares a core, so both projections
    are covers by `pullbackDiagFst` / `pullbackDiagSnd`. -/
theorem completeness_of_diagPullback (a₀ : A) (hcs : CanonicallySettled A T a₀)
    (hpc : PaddedDiagPullbackCovered A T a₀) : FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨e', hee', hse, hce⟩ := hcs e
  obtain ⟨f', hff', hsf, hcf⟩ := hcs f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA (V := W) hee' gs).symm.trans (heq X W gs)).trans
      (sound_BA (V := W) hff' gs)
  have ht0 := total_of_settled (settled_padZero hse hsf a₀)
  have ht1 := total_of_settled (settled_padOne hse hsf a₀)
  have hc0 := deadCanonical_padZero a₀ hce hcf
  have hc1 := deadCanonical_padOne a₀ hce hcf
  have hmaps := pad_span_maps_agree a₀ e' f' heq' ht0 ht1 hc0 hc1
  obtain ⟨base⟩ :=
    GkatPullback.Base.ofMem
      (GkatQuotient.matchCover (matched_of_pad a₀ e' f' heq' ht0 ht1 hc0 hc1))
      (GkatQuotient.targetCover (matched_of_pad a₀ e' f' heq' ht0 ht1 hc0 hc1).stepbb)
      (thompson_states_complete (padZero e' f' a₀) (Sum.inr (Sum.inr ())))
  obtain ⟨l, hsub, hdiag, ⟨h, ⟨χ⟩⟩⟩ := hpc e' f' _ _ _ _ base hmaps
  have hmid : EquivBA (padZero e' f' a₀) (padOne e' f' a₀) :=
    equivBA_of_common_refinement χ
      (pullbackOnFst _ _ base l hmaps hsub hdiag)
      (pullbackOnSnd _ _ base l hmaps rfl hsub hdiag)
  exact EquivBA.trans hee'
    (EquivBA.trans (padOne_equiv e' f' a₀)
      (EquivBA.trans hmid.symm
        (EquivBA.trans (padZero_equiv e' f' a₀).symm hff'.symm)))

/-- **Completeness from one statement about the diagonal-listed pullback alone.** -/
theorem completeness_of_diagPullbackCovered (a₀ : A)
    (hpc : PaddedDiagPullbackCovered A T a₀) : FiniteAxiomsCompleteBA A T :=
  completeness_of_diagPullback a₀ (canonicallySettled_holds a₀) hpc

#print axioms completeness_of_diagPullback
/-- **REFUTED BY MEASUREMENT — kept for the record, not to be built on.**  A partner function
    for the padded span essentially never exists: measured over all 4679 total-instance padded
    kernel pairs at two atoms, the forced pairing is single-valued in **0** of them, in either
    component.  Restricting to one entry branch at a time — which is what un-sharing does —
    lifts it only to 623 of 4679.

    The reason is visible in the statement.  `hinit` quantifies over *every* interpretation and
    atom, so two atoms whose entry lands on the same state of the left component but different
    states of the right already make `σ` multi-valued, before any run begins.

    So `completeness_of_partner` below is a true implication with an unsatisfiable hypothesis.
    It is kept because the shape is the informative part: a cover of the pullback *by one side*
    is exactly a partner function, so the measurement says no such cover exists, and the
    covering automaton has to be built from the pullback rather than from either component. -/
def PartnerExists (A T : Type) (a₀ : A) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m),
    φ.map = ψ.map →
    ∃ σ : (certifiedThompson A T (padZero e f a₀)).State →
          (certifiedThompson A T (padOne e f a₀)).State,
      (∀ u ∈ (certifiedThompson A T (padZero e f a₀)).aut.core.states,
        σ u ∈ (certifiedThompson A T (padOne e f a₀)).aut.core.states) ∧
      (∀ u, φ.map u = ψ.map (σ u)) ∧
      (∀ (X : Type) (W : T → X → Bool) (x : X)
        (o : A × (certifiedThompson A T (padZero e f a₀)).State),
        firstMatch W x (certifiedThompson A T (padZero e f a₀)).aut.initTrans = some o →
        firstMatch W x (certifiedThompson A T (padOne e f a₀)).aut.initTrans
          = some (o.1, σ o.2)) ∧
      (∀ (X : Type) (W : T → X → Bool) (x : X)
        (u : (certifiedThompson A T (padZero e f a₀)).State)
        (o : A × (certifiedThompson A T (padZero e f a₀)).State),
        firstMatch W x ((certifiedThompson A T (padZero e f a₀)).aut.core.trans u) = some o →
        firstMatch W x ((certifiedThompson A T (padOne e f a₀)).aut.core.trans (σ u))
          = some (o.1, σ o.2))

/-- **A partner function discharges the last statement.**  The covering program is
    `if 1 then padZero else padZero` — the padded left component, duplicated once so the
    second copy can carry the diagonal. -/
theorem paddedDiagPullbackCovered_of_partner (a₀ : A) (hp : PartnerExists A T a₀) :
    PaddedDiagPullbackCovered A T a₀ := by
  intro e f Q m φ ψ base hmaps
  obtain ⟨σ, hσ, hmatch, hinit, hcore⟩ := hp e f Q m φ ψ hmaps
  refine ⟨List.append (graphList φ ψ base σ) (diagList φ ψ base), ?_, ?_, ?_⟩
  · intro s hs
    rcases List.mem_append.mp hs with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_flatMap.mpr ⟨u, hu, List.mem_map.mpr ⟨σ u, hσ u hu, rfl⟩⟩
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_flatMap.mpr ⟨u, hu, List.mem_map.mpr ⟨u, hu, rfl⟩⟩
  · intro u hu
    exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩))
  · exact ⟨.ite BExp.one (padZero e f a₀) (padZero e f a₀),
      ⟨graphDiagCover φ ψ base σ (fun _ => rfl) (fun u => congrFun hmaps u)
        hmatch hinit hcore⟩⟩

/-- **Completeness from the existence of a partner function** — vacuous, see above. -/
theorem completeness_of_partner (a₀ : A) (hp : PartnerExists A T a₀) :
    FiniteAxiomsCompleteBA A T :=
  completeness_of_diagPullbackCovered a₀ (paddedDiagPullbackCovered_of_partner a₀ hp)

/-- Eliminate the empty summand — the state type of `0? ; h` is `Empty ⊕ h.State`. -/
private def emptyElim {S R : Type} (g : S → R) : Sum Empty S → R
  | Sum.inl z => nomatch z
  | Sum.inr u => g u

/-- A guard that never fires kills every transition it guards. -/
private theorem fmDeadGuard {S R X : Type} (W : T → X → Bool) (x : X) (G : BExp T)
    (hG : bval W G x = false) (L : List (BExp T × A × S)) (F : S → R) :
    firstMatch W x (L.map (fun t => (BExp.and G t.1, t.2.1, F t.2.2))) = none := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨q, act, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hq : bval W (BExp.and G q) x = false := by
        show (bval W G x && bval W q x) = false
        rw [hG]
        rfl
      rw [if_neg (by rw [hq]; simp)]
      exact ih

/-- **The diagonal piece is a theorem, not a hypothesis.**  Its guard is `¬1`, so its entry
    never fires, and `0? ; padOne` covers it: the leading `0?` kills the entry and contributes
    no states, while `padOne`'s states map onto the diagonal by `u ↦ (u, u)` — which typechecks
    only because the padded pair shares its core. -/
noncomputable def diagPieceCover (a₀ : A) (e f : Exp A T) {Q : Type}
    {m : InitializedGAut Q A T}
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ) (hmaps : φ.map = ψ.map) :
    InitCover (certifiedThompson A T (.seq (.test BExp.zero) (padOne e f a₀))).aut
      (restrict (GkatPullback.pullback φ ψ base) (diagList φ ψ base) (.not BExp.one)) where
  map := emptyElim (fun u => GkatPullback.pairUp base u u)
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun s _ W x => by
    cases s with
    | inl z => exact nomatch z
    | inr u =>
        show bval W ((certifiedThompson A T (padOne e f a₀)).aut.core.hlt u) x
          = bval W ((certifiedThompson A T (padOne e f a₀)).aut.core.hlt
              (GkatPullback.pairUp base u u).val.1) x
        rw [GkatPullback.pairUp_fst base (congrFun hmaps u)]
  initStep_eq := fun X W x => by
    have hz : bval W (BExp.zero : BExp T) x = false := rfl
    have hn : bval W (BExp.not BExp.one : BExp T) x = false := rfl
    show (firstMatch W x
        (([] : List (BExp T × A × Sum Empty (certifiedThompson A T (padOne e f a₀)).State)) ++
         (certifiedThompson A T (padOne e f a₀)).aut.initTrans.map
           (fun t => (BExp.and BExp.zero t.1, t.2.1,
             (Sum.inr t.2.2 : Sum Empty (certifiedThompson A T (padOne e f a₀)).State))))).map
        (fun o => (o.1, emptyElim (fun u => GkatPullback.pairUp base u u) o.2))
      = firstMatch W x
          ((GkatPullback.pullback φ ψ base).initTrans.map
            (fun t => (BExp.and (BExp.not BExp.one) t.1, t.2.1, t.2.2)))
    rw [List.nil_append,
      fmDeadGuard W x BExp.zero hz (certifiedThompson A T (padOne e f a₀)).aut.initTrans
        (fun v => (Sum.inr v : Sum Empty (certifiedThompson A T (padOne e f a₀)).State)),
      fmDeadGuard W x (BExp.not BExp.one) hn (GkatPullback.pullback φ ψ base).initTrans
        (fun v : GkatPullback.Fib φ ψ => v)]
    rfl
  coreStep_eq := fun s X W x => by
    cases s with
    | inl z => exact nomatch z
    | inr u =>
        show (firstMatch W x
            (((certifiedThompson A T (padOne e f a₀)).aut.core.trans u).map
              (fun t => (t.1, t.2.1,
                (Sum.inr t.2.2 : Sum Empty
                  (certifiedThompson A T (padOne e f a₀)).State))))).map
            (fun o => (o.1, emptyElim (fun v => GkatPullback.pairUp base v v) o.2))
          = firstMatch W x
              ((GkatSynthesis.crossTrans
                ((certifiedThompson A T (padOne e f a₀)).aut.core.trans
                  (GkatPullback.pairUp base u u).val.1)
                ((certifiedThompson A T (padOne e f a₀)).aut.core.trans
                  (GkatPullback.pairUp base u u).val.2)).map
                (fun t => (t.1, t.2.1, GkatPullback.pairUp base t.2.2.1 t.2.2.2)))
        rw [GkatPullback.pairUp_fst base (congrFun hmaps u),
          GkatPullback.pairUp_snd base (congrFun hmaps u),
          firstMatch_map_target_to
            (F := fun v : (certifiedThompson A T (padOne e f a₀)).State =>
              (Sum.inr v : Sum Empty (certifiedThompson A T (padOne e f a₀)).State)),
          firstMatch_map_target_to
            (F := fun q : (certifiedThompson A T (padOne e f a₀)).State ×
              (certifiedThompson A T (padOne e f a₀)).State =>
              GkatPullback.pairUp base q.1 q.2),
          GkatSynthesis.firstMatch_crossTrans]
        cases firstMatch W x ((certifiedThompson A T (padOne e f a₀)).aut.core.trans u) <;> rfl
  maps := by
    intro s hs
    rcases List.mem_append.mp hs with h | h
    · obtain ⟨z, _, _⟩ := List.mem_map.mp h
      exact nomatch z
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_map.mpr ⟨u, hu, rfl⟩
  onto := by
    intro q hq
    obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hq
    exact ⟨Sum.inr u,
      List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩)), rfl⟩

theorem hasThompsonCover_diagPiece (a₀ : A) (e f : Exp A T) {Q : Type}
    {m : InitializedGAut Q A T}
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ) (hmaps : φ.map = ψ.map) :
    HasThompsonCover
      (restrict (GkatPullback.pullback φ ψ base) (diagList φ ψ base) (.not BExp.one)) :=
  ⟨.seq (.test BExp.zero) (padOne e f a₀), ⟨diagPieceCover a₀ e f φ ψ base hmaps⟩⟩

#print axioms diagPieceCover
#print axioms hasThompsonCover_diagPiece

/-! ### The measured construction, as a hypothesis it can actually satisfy

    Two pieces, and they are exactly the two the search builds.

      * `l₁`, `l₂` — the two entry branches, each with its entry restricted to its own guard.
        This is exactly what the search builds, and what it covered 2181 times out of 2181.
    The diagonal the projections also need is **not** a hypothesis: `hasThompsonCover_diagPiece`
    proves it.  So what is left to assume is exactly what the search measured, and nothing
    more.

    The two branch pieces are combined first, under the guard `1`, and the diagonal is attached
    on the outside — so the diagonal's copy is entered on no atom at all, which is what makes
    its dead entry harmless. -/
def RestrictedBranchesCovered (A T : Type) (a₀ : A) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ), φ.map = ψ.map →
    ∃ (g : BExp T) (l₁ l₂ : List (GkatPullback.Fib φ ψ)),
      (∀ s ∈ List.append (List.append l₁ l₂) (diagList φ ψ base),
        s ∈ (GkatPullback.pullback φ ψ base).core.states) ∧
      HasThompsonCover
        (restrict (restrict (GkatPullback.pullback φ ψ base) (List.append l₁ l₂) BExp.one)
          l₁ g) ∧
      HasThompsonCover
        (restrict (restrict (GkatPullback.pullback φ ψ base) (List.append l₁ l₂) BExp.one)
          l₂ (.not g))

theorem paddedDiagPullbackCovered_of_restrictedBranches (a₀ : A)
    (hr : RestrictedBranchesCovered A T a₀) : PaddedDiagPullbackCovered A T a₀ := by
  intro e f Q m φ ψ base hmaps
  obtain ⟨g, l₁, l₂, hsub, h₁, h₂⟩ := hr e f Q m φ ψ base hmaps
  have h₃ := hasThompsonCover_diagPiece a₀ e f φ ψ base hmaps
  refine ⟨List.append (List.append l₁ l₂) (diagList φ ψ base), hsub, ?_, ?_⟩
  · intro u hu
    exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩))
  · have hmid := hasThompsonCover_of_restrictSplit g
      (restrict (GkatPullback.pullback φ ψ base) (List.append l₁ l₂) BExp.one) l₁ l₂ h₁ h₂
    exact hasThompsonCover_of_restrictSplit BExp.one (GkatPullback.pullback φ ψ base)
      (List.append l₁ l₂) (diagList φ ψ base) hmid h₃

/-- **Completeness from the measured construction.** -/
theorem completeness_of_restrictedBranches (a₀ : A)
    (hr : RestrictedBranchesCovered A T a₀) : FiniteAxiomsCompleteBA A T :=
  completeness_of_diagPullbackCovered a₀
    (paddedDiagPullbackCovered_of_restrictedBranches a₀ hr)

/-! ### One conjunct, and it is the thing the search measures

    With the diagonal piece proved, the branch split is no longer needed to state the
    obligation.  Take `l₂ := diagList` and `g := 1` in `hasThompsonCover_of_restrictSplit`:
    the second piece is the diagonal, which is a theorem, and `restrict P l 1` is just `P`
    listed on `l` with its entry intact — `g ∧ t` fires exactly when `t` does.

    So the whole programme reduces to: **the pullback, listed on its reachable states, is
    Thompson-covered.**  That is precisely what the harness computes, since its pullback is
    built by exploring from the entry — and it is what un-sharing covered 2181 times out of
    2181, and what refinement covers directly in 196 of 200 sampled cases. -/
def ReachListCovered (A T : Type) (a₀ : A) : Prop :=
  ∀ (e f : Exp A T) (Q : Type) (m : InitializedGAut Q A T)
    (φ : InitCover (certifiedThompson A T (padZero e f a₀)).aut m)
    (ψ : InitCover (certifiedThompson A T (padOne e f a₀)).aut m)
    (base : GkatPullback.Base φ ψ), φ.map = ψ.map →
    ∃ l : List (GkatPullback.Fib φ ψ),
      (∀ s ∈ l, s ∈ (GkatPullback.pullback φ ψ base).core.states) ∧
      HasThompsonCover (restrict (GkatPullback.pullback φ ψ base) l BExp.one)

theorem paddedDiagPullbackCovered_of_reachList (a₀ : A) (hr : ReachListCovered A T a₀) :
    PaddedDiagPullbackCovered A T a₀ := by
  intro e f Q m φ ψ base hmaps
  obtain ⟨l, hsub, hcov⟩ := hr e f Q m φ ψ base hmaps
  refine ⟨List.append l (diagList φ ψ base), ?_, ?_, ?_⟩
  · intro s hs
    rcases List.mem_append.mp hs with h | h
    · exact hsub s h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_flatMap.mpr ⟨u, hu, List.mem_map.mpr ⟨u, hu, rfl⟩⟩
  · intro u hu
    exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩))
  · exact hasThompsonCover_of_restrictSplit BExp.one (GkatPullback.pullback φ ψ base)
      l (diagList φ ψ base) hcov (hasThompsonCover_diagPiece a₀ e f φ ψ base hmaps)

/-- **Completeness from one condition on the reachable listing.** -/
theorem completeness_of_reachList (a₀ : A) (hr : ReachListCovered A T a₀) :
    FiniteAxiomsCompleteBA A T :=
  completeness_of_diagPullbackCovered a₀ (paddedDiagPullbackCovered_of_reachList a₀ hr)

#print axioms paddedDiagPullbackCovered_of_reachList
#print axioms completeness_of_reachList

#print axioms paddedDiagPullbackCovered_of_restrictedBranches
#print axioms completeness_of_restrictedBranches

#print axioms completeness_of_diagPullbackCovered
#print axioms paddedDiagPullbackCovered_of_partner
#print axioms completeness_of_partner

#print axioms completeness_of_pullbackCovered

#print axioms live_nrm
#print axioms canonicallySettled_of_bridge
#print axioms completeness_of_bridge

#print axioms settled_nrm
#print axioms settledReachable_loopProductive
#print axioms settled_and_dce
#print axioms E_nrm
#print axioms nrm_equiv
#print axioms nrm_top_equiv

#print axioms completeness_of_canonicallySettled

end GkatTotalization
