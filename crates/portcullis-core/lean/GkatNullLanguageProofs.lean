import GkatNullSemanticsProofs

/-!
# Null-language completeness for GKAT from the finite axioms

This file proves, with **no uniqueness axiom beyond `W3` (the n = 1 instance already in
the finite system)** and no completeness hypothesis:

    UniformExpLempty e  →  EquivBA e 0                      (`nullLanguage_complete`)

"A GKAT program with no guarded strings is provably `0`."

## Why this is the interesting fragment

GKAT has no `+`, so it cannot case-split on the state *after* a program: from
`⊢ u·¬z = 0` one cannot conclude `⊢ u = u·z`, which is what a Kleene-algebra proof
would do at every sequential composition.  The whole difficulty of the theorem is
recovering that right-hand case split.

The answer is that GKAT recovers it **only along syntax-generated control flow**, and
recovers it *without* any global uniqueness principle.  That is the content of

    Post e : ∀ b z p q,  ULempty (b·e·¬z)  →  ⊢ b·e·(p +_z q) = b·e·p

— *postcondition elimination*.  `Post` is proved by structural induction on `e`: the
sequential case inserts a Boolean case split at the junction point (`insert_test`, from
`U1`+`U4` alone) and discharges it with `Post` of the prefix; the loop case turns the
split into a **loop invariant** and closes it with `W3`.  Nothing anywhere quantifies
over solutions of an arbitrary equation system.

`Zero` (a dead assertion is provably `0`) then follows by a second structural induction
that threads the continuation, so no case split is ever needed at a `seq`.

## What this closes in this development

`dead_thompson_label_eq_zero_of_complete` previously assumed `FiniteAxiomsCompleteBA` —
i.e. it assumed the very theorem the development is trying to prove.  It is replaced
here by `dead_thompson_label_eq_zero`, which assumes nothing.  Every dead branch of a
Thompson automaton can therefore be rewritten to `0` inside the finite theory.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatNullLanguage

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson
open GkatGuardedAlgebra GkatAtomTransfer GkatNullSemantics

variable {A T : Type}

/-! ## The two induction targets -/

/-- **Postcondition elimination.**  If `e` started under `b` can never land outside `z`,
    then a `z`-test on its continuation is redundant. -/
def Post (e : Exp A T) : Prop :=
  ∀ (b z : BExp T) (p q : Exp A T),
    UniformExpLempty (.seq (.test b) (.seq e (.test (.not z)))) →
    EquivBA (.seq (.test b) (.seq e (.ite z p q))) (.seq (.test b) (.seq e p))

/-- **Null elimination.**  Every uniformly empty assertion of `e` is provably `0`. -/
def Zero (e : Exp A T) : Prop :=
  ∀ b : BExp T, UniformExpLempty (.seq (.test b) e) →
    EquivBA (.seq (.test b) e) (.test .zero)

/-- The continuation-threaded form of `Zero`, which is what actually inducts. -/
def ZeroThrough (e : Exp A T) : Prop :=
  ∀ f : Exp A T, Zero f → Zero (.seq e f)

/-- Tests are trivially null-eliminable: an unsatisfiable conjunction is `0` by Boolean
    congruence. -/
theorem zero_test (c : BExp T) : Zero (.test c : Exp A T) := by
  intro b hempty
  have hunsat : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b c) x = false := by
    intro X W x
    cases hv : bval W (.and b c) x with
    | false => rfl
    | true =>
        exfalso
        have hb : bval W b x = true := by
          change (bval W b x && bval W c x) = true at hv
          cases hb' : bval W b x with
          | true => rfl
          | false => rw [hb'] at hv; exact absurd hv (by simp)
        have hc : bval W c x = true := by
          change (bval W b x && bval W c x) = true at hv
          cases hc' : bval W c x with
          | true => rfl
          | false => rw [hc'] at hv; exact absurd hv (by simp)
        exact hempty X W (x, []) ⟨[], [], rfl, ⟨hb, rfl⟩, ⟨hc, rfl⟩⟩
  exact EquivBA.trans (EquivBA.s6 b c) (EquivBA.baTest hunsat)

/-- `1` is null-eliminable, which seeds the continuation-threaded induction. -/
theorem zero_one : Zero (.test .one : Exp A T) := zero_test .one

/-! ## Normal form of a guarded choice under an assertion -/

/-- Splitting an asserted conditional into its two asserted arms.  Both arms carry the
    full region that selects them, so each may be rewritten independently. -/
theorem ite_seq_normal (b c : BExp T) (e₁ e₂ x : Exp A T) :
    EquivBA (.seq (.test b) (.seq (.ite c e₁ e₂) x))
      (.ite (.and b c) (.seq (.test (.and b c)) (.seq e₁ x))
        (.seq (.test (.and b (.not c))) (.seq e₂ x))) := by
  have hguard : ∀ (X : Type) (W : T → X → Bool) (v : X),
      bval W (.and (.not (.and b c)) b) v = bval W (.and b (.not c)) v := by
    intro X W v
    simp only [bval]
    cases bval W b v <;> cases bval W c v <;> rfl
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (ite_seq_right c e₁ e₂ x)) ?_
  refine EquivBA.trans (test_seq_ite b c (.seq e₁ x) (.seq e₂ x)) ?_
  refine EquivBA.trans
    (EquivBA.base (Equiv.u4 (.and b c) (.seq e₁ x) (.seq (.test b) (.seq e₂ x)))) ?_
  refine EquivBA.trans
    (ite_restrict_else (.and b c) (.seq (.test (.and b c)) (.seq e₁ x))
      (.seq (.test b) (.seq e₂ x))) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ?_
  exact EquivBA.trans (test_seq_merge (.not (.and b c)) b (.seq e₂ x))
    (test_seq_guard_congr (.seq e₂ x) hguard)

/-! ## The loop normal form

    A loop that is dead under `b` is provably equal to a loop whose body is the
    *productive* Thompson derivative restricted to the dead region, followed by the exit
    region.  The only fixpoint principle used is `W3` — the `n = 1` uniqueness instance
    that the finite axiom system already contains. -/

/-- The abstract `W3` step.  All Thompson-specific data (`h`, `D`) enters only through
    the four hypotheses, so this lemma is a statement about *any* decomposition of a loop
    body into an immediate-termination test and a productive residual. -/
theorem loop_w3_step {Z g h : BExp T} {p D : Exp A T} (hpost : Post p)
    (hstepinv : UniformExpLempty
      (.seq (.test (.and Z g)) (.seq p (.test (.not Z)))))
    (hdecomp : EquivBA p (.ite h (.test .one) D))
    (hDrestrict : EquivBA (.seq (.test (.not h)) D : Exp A T) D)
    (hDprod : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E D) x = false)
    (F : Exp A T) :
    EquivBA (.seq (.test Z) (.seq (.wh g D) F))
      (.seq (.wh (.and Z g) (.seq (.test (.and (.and Z g) (.not h))) D))
        (.seq (.test (.and Z (.not g))) F)) := by
  -- the restricted body is productive
  have hprodBody : EquivBA
      (.test (E (.seq (.test (.and (.and Z g) (.not h))) D)) : Exp A T)
      (.test .zero) := by
    apply EquivBA.baTest
    intro X W x
    change (bval W (.and (.and Z g) (.not h)) x && bval W (E D) x) = false
    rw [hDprod X W x]
    cases bval W (.and (.and Z g) (.not h)) x <;> rfl
  -- the restricted body is `p` with immediate termination excluded
  have hGh : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.and (.and Z g) (.not h)) h) x = false := by
    intro X W x
    simp only [bval]
    cases bval W Z x <;> cases bval W g x <;> cases bval W h x <;> rfl
  have hbodySeq : ∀ x : Exp A T,
      EquivBA (.seq (.seq (.test (.and (.and Z g) (.not h))) D) x)
        (.seq (.test (.and (.and Z g) (.not h))) (.seq p x)) := by
    intro x
    refine EquivBA.symm ?_
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.seq_c hdecomp (EquivBA.base (Equiv.refl x)))) ?_
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (ite_seq_right h (.test .one) D x)) ?_
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.ite_c (one_seq x) (EquivBA.base (Equiv.refl _)))) ?_
    refine EquivBA.trans
      (test_seq_ite (.and (.and Z g) (.not h)) h x (.seq D x)) ?_
    refine EquivBA.trans
      (ite_of_unsat x
        (.seq (.test (.and (.and Z g) (.not h))) (.seq D x)) hGh) ?_
    exact seq_assoc' (.test (.and (.and Z g) (.not h))) D x
  -- postcondition elimination transfers from `p` to the restricted body
  have hGimp : GuardImplies (.and (.and Z g) (.not h)) (.and Z g) := by
    intro X W x hx
    change ((bval W Z x && bval W g x) && (! bval W h x)) = true at hx
    cases hzg : (bval W Z x && bval W g x) with
    | true => exact hzg
    | false => rw [hzg] at hx; exact absurd hx (by simp)
  have hpostBody : ∀ u v : Exp A T,
      EquivBA (.seq (.seq (.test (.and (.and Z g) (.not h))) D) (.ite Z u v))
        (.seq (.seq (.test (.and (.and Z g) (.not h))) D) u) := by
    intro u v
    exact EquivBA.trans (hbodySeq _)
      (EquivBA.trans
        (hpost (.and (.and Z g) (.not h)) Z u v
          (ULempty_of_guard_implies hGimp hstepinv))
        (EquivBA.symm (hbodySeq u)))
  -- one unrolling, with the invariant reinserted at the loop head
  have helse : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.not (.and Z g)) Z) x = bval W (.and Z (.not g)) x := by
    intro X W x
    simp only [bval]
    cases bval W Z x <;> cases bval W g x <;> rfl
  have hunroll : EquivBA (.seq (.test Z) (.seq (.wh g D) F))
      (.ite (.and Z g)
        (.seq (.seq (.test (.and (.and Z g) (.not h))) D)
          (.seq (.test Z) (.seq (.wh g D) F)))
        (.seq (.test (.and Z (.not g))) F)) := by
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.seq_c (EquivBA.base (Equiv.w1 g D))
          (EquivBA.base (Equiv.refl F)))) ?_
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (ite_seq_right g (.seq D (.wh g D)) (.test .one) F)) ?_
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.ite_c (seq_assoc D (.wh g D) F) (one_seq F))) ?_
    refine EquivBA.trans
      (test_seq_ite Z g (.seq D (.seq (.wh g D) F)) F) ?_
    refine EquivBA.trans
      (EquivBA.base (Equiv.u4 (.and Z g) (.seq D (.seq (.wh g D) F))
        (.seq (.test Z) F))) ?_
    refine EquivBA.trans
      (ite_restrict_else (.and Z g)
        (.seq (.test (.and Z g)) (.seq D (.seq (.wh g D) F)))
        (.seq (.test Z) F)) ?_
    refine EquivBA.ite_c ?_ ?_
    · refine EquivBA.trans
        (seq_assoc' (.test (.and Z g)) D (.seq (.wh g D) F)) ?_
      refine EquivBA.trans
        (EquivBA.seq_c
          (EquivBA.trans
            (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
              (EquivBA.symm hDrestrict))
            (test_seq_merge (.and Z g) (.not h) D))
          (EquivBA.base (Equiv.refl _))) ?_
      refine EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (insert_test Z (.seq (.wh g D) F))) ?_
      exact hpostBody (.seq (.test Z) (.seq (.wh g D) F)) (.seq (.wh g D) F)
    · exact EquivBA.trans (test_seq_merge (.not (.and Z g)) Z F)
        (test_seq_guard_congr F helse)
  exact EquivBA.w3_ba hprodBody hunroll

/-- The dead loop, in normal form.  `Z` is the finite Boolean region on which the loop
    with its continuation is uniformly empty; the loop provably cannot leave it. -/
theorem loop_normal_form {b g : BExp T} {p k : Exp A T} (hpost : Post p)
    (hdead : UniformExpLempty (.seq (.test b) (.seq (.wh g p) k))) :
    ∃ (Z : BExp T) (body : Exp A T),
      GuardImplies b Z ∧
      UniformExpLempty (.seq (.test (.and Z (.not g))) k) ∧
      ∀ F : Exp A T,
        EquivBA (.seq (.test b) (.seq (.wh g p) F))
          (.seq (.test b)
            (.seq (.wh (.and Z g) body)
              (.seq (.test (.and Z (.not g))) F))) := by
  classical
  have hbZ : GuardImplies b (deadTestOver (splitGuards b (.seq (.wh g p) k))
      (.seq (.wh g p) k)) :=
    deadTestOver_greatest (mem_splitGuards_head b (.seq (.wh g p) k)) hdead
  have hZdead : UniformExpLempty
      (.seq (.test (deadTestOver (splitGuards b (.seq (.wh g p) k))
        (.seq (.wh g p) k))) (.seq (.wh g p) k)) :=
    deadTestOver_dead _ _
  have hexit := ULempty_loop_exit (g := g) (p := p) (k := k) hZdead
  have hstepinv := ULempty_loop_step (g := g) (p := p) (k := k)
    (splitGuards b (.seq (.wh g p) k)) (mem_splitGuards_prim b (.seq (.wh g p) k))
  have hWD : EquivBA (.wh g p : Exp A T)
      (.wh g (guardedFold (transitionBranches (certifiedThompson A T p).aut.initTrans
        (certifiedThompson A T p).standard) (.test .zero))) :=
    initialized_productiveLoop g (certifiedThompson A T p).aut
      (certifiedThompson A T p).standard p
      (certifiedThompson A T p).certificate.parametric
      (certifiedThompson A T p).certificate.standardSolves
      (certifiedThompson A T p).certificate.initDisjoint
  have hdecomp : EquivBA p
      (.ite (certifiedThompson A T p).aut.initHlt (.test .one)
        (guardedFold (transitionBranches (certifiedThompson A T p).aut.initTrans
          (certifiedThompson A T p).standard) (.test .zero))) :=
    initial_program_decomposition (certifiedThompson A T p).aut
      (certifiedThompson A T p).standard p
      (certifiedThompson A T p).certificate.parametric
      (certifiedThompson A T p).certificate.standardSolves
      (certifiedThompson A T p).certificate.initDisjoint
  have himp : ∀ branch ∈ transitionBranches (certifiedThompson A T p).aut.initTrans
      (certifiedThompson A T p).standard,
      GuardImplies branch.1 (.not (certifiedThompson A T p).aut.initHlt) := by
    intro branch hmem X W x hguard
    have hd := (certifiedThompson A T p).certificate.initDisjoint branch hmem X W x
    change (bval W branch.1 x &&
      bval W (certifiedThompson A T p).aut.initHlt x) = false at hd
    change (! bval W (certifiedThompson A T p).aut.initHlt x) = true
    rw [hguard] at hd
    cases hhalt : bval W (certifiedThompson A T p).aut.initHlt x with
    | false => rfl
    | true => rw [hhalt] at hd; exact Bool.noConfusion hd
  have hDrestrict := test_seq_guardedFold_of_implies
    (.not (certifiedThompson A T p).aut.initHlt)
    (transitionBranches (certifiedThompson A T p).aut.initTrans
      (certifiedThompson A T p).standard) himp
  have hDprod := transitionActionFold_productive
    (certifiedThompson A T p).aut.initTrans (certifiedThompson A T p).standard
  refine ⟨deadTestOver (splitGuards b (.seq (.wh g p) k)) (.seq (.wh g p) k),
    .seq (.test (.and (.and (deadTestOver (splitGuards b (.seq (.wh g p) k))
        (.seq (.wh g p) k)) g)
      (.not (certifiedThompson A T p).aut.initHlt)))
      (guardedFold (transitionBranches (certifiedThompson A T p).aut.initTrans
        (certifiedThompson A T p).standard) (.test .zero)),
    hbZ, hexit, ?_⟩
  intro F
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.seq_c hWD (EquivBA.base (Equiv.refl F)))) ?_
  refine EquivBA.trans
    (test_seq_guard_congr _
      (fun X W x => (band_of_implies hbZ X W x).symm)) ?_
  refine EquivBA.trans (EquivBA.symm (test_seq_merge b _ _)) ?_
  exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (loop_w3_step hpost hstepinv hdecomp hDrestrict hDprod F)

/-! ## Postcondition elimination, by structural induction -/

/-- The sequential step of `Post`: insert a Boolean case split at the junction point and
    discharge it with postcondition elimination for the prefix.  `insert_test` is `U1`
    plus `U4`; nothing else is used. -/
theorem post_seq_step {b d : BExp T} {e₁ e₂ : Exp A T} (h₁ : Post e₁)
    (hkill : UniformExpLempty (.seq (.test b) (.seq e₁ (.test (.not d)))))
    (x : Exp A T) :
    EquivBA (.seq (.test b) (.seq e₁ (.seq e₂ x)))
      (.seq (.test b) (.seq e₁ (.seq (.test d) (.seq e₂ x)))) := by
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (insert_test d (.seq e₂ x)))) ?_
  exact h₁ b d (.seq (.test d) (.seq e₂ x)) (.seq e₂ x) hkill

theorem post_all (e : Exp A T) : Post e := by
  induction e with
  | act a =>
      intro b z p q hempty
      rcases Classical.em (∃ (X : Type) (W : T → X → Bool) (x : X),
          bval W b x = true) with hsat | hunsat
      · obtain ⟨X, W, x, hx⟩ := hsat
        have htaut := GuardImplies_act_post hx hempty
        exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (ite_taut p q (fun X W x => htaut X W x)))
      · have hfalse : ∀ (X : Type) (W : T → X → Bool) (x : X),
            bval W b x = false := by
          intro X W x
          cases hv : bval W b x with
          | false => rfl
          | true => exact absurd ⟨X, W, x, hv⟩ hunsat
        exact EquivBA.trans (test_unsat_seq _ hfalse)
          (EquivBA.symm (test_unsat_seq _ hfalse))
  | test c =>
      intro b z p q hempty
      have himp : GuardImplies (.and b c) z := by
        intro X W x hx
        have hb : bval W b x = true := by
          change (bval W b x && bval W c x) = true at hx
          cases hb' : bval W b x with
          | true => rfl
          | false => rw [hb'] at hx; exact absurd hx (by simp)
        have hc : bval W c x = true := by
          change (bval W b x && bval W c x) = true at hx
          cases hc' : bval W c x with
          | true => rfl
          | false => rw [hc'] at hx; exact absurd hx (by simp)
        cases hz : bval W z x with
        | true => rfl
        | false =>
            refine (hempty X W (x, []) ⟨[], [], rfl, ⟨hb, rfl⟩, ?_⟩).elim
            refine ⟨[], [], rfl, ⟨hc, rfl⟩, ?_, rfl⟩
            change (! bval W z x) = true
            rw [hz]
            rfl
      exact EquivBA.trans (test_seq_merge b c (.ite z p q))
        (EquivBA.trans (test_seq_ite_of_implies p q himp)
          (EquivBA.symm (test_seq_merge b c p)))
  | seq e₁ e₂ ih₁ ih₂ =>
      intro b z p q hempty
      have hassoc : ∀ x : Exp A T,
          EquivBA (.seq (.test b) (.seq (.seq e₁ e₂) x))
            (.seq (.test b) (.seq e₁ (.seq e₂ x))) :=
        fun x => EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (seq_assoc e₁ e₂ x)
      have hkill := ULempty_prefix_outside_dead
        (splitGuards b (.seq e₂ (.test (.not z))))
        (mem_splitGuards_prim b (.seq e₂ (.test (.not z))))
        (ULempty_congr (hassoc (.test (.not z))) hempty)
      have hinner := deadTestOver_dead
        (splitGuards b (.seq e₂ (.test (.not z)))) (.seq e₂ (.test (.not z)))
      refine EquivBA.trans (hassoc (.ite z p q)) ?_
      refine EquivBA.trans (post_seq_step ih₁ hkill (.ite z p q)) ?_
      refine EquivBA.trans ?_ (EquivBA.symm (hassoc p))
      refine EquivBA.trans ?_ (EquivBA.symm (post_seq_step ih₁ hkill p))
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (ih₂ _ z p q hinner))
  | ite c e₁ e₂ ih₁ ih₂ =>
      intro b z p q hempty
      have hthen := ULempty_ite_then hempty
      have helse := ULempty_ite_else hempty
      refine EquivBA.trans (ite_seq_normal b c e₁ e₂ (.ite z p q)) ?_
      refine EquivBA.trans ?_ (EquivBA.symm (ite_seq_normal b c e₁ e₂ p))
      exact EquivBA.ite_c (ih₁ _ z p q hthen) (ih₂ _ z p q helse)
  | wh g p ih =>
      intro b z u v hempty
      obtain ⟨Z, body, hbZ, hexit, hnormal⟩ :=
        loop_normal_form (k := .test (.not z)) ih hempty
      have himp : GuardImplies (.and Z (.not g)) z := by
        intro X W x hx
        cases hz : bval W z x with
        | true => rfl
        | false =>
            refine (hexit X W (x, []) ⟨[], [], rfl, ⟨hx, rfl⟩, ?_, rfl⟩).elim
            change (! bval W z x) = true
            rw [hz]
            rfl
      refine EquivBA.trans (hnormal (.ite z u v)) ?_
      refine EquivBA.trans ?_ (EquivBA.symm (hnormal u))
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (test_seq_ite_of_implies u v himp))

/-! ## Null elimination, by structural induction with a threaded continuation -/

theorem zeroThrough_all (e : Exp A T) : ZeroThrough e := by
  induction e with
  | act a =>
      intro f hf b hempty
      rcases Classical.em (∃ (X : Type) (W : T → X → Bool) (x : X),
          bval W b x = true) with hsat | hunsat
      · obtain ⟨X, W, x, hx⟩ := hsat
        have hfempty : UniformExpLempty f := ULempty_act_continuation hx hempty
        have hfzero : EquivBA f (.test .zero) := by
          refine EquivBA.trans (EquivBA.symm (one_seq f)) ?_
          refine hf .one ?_
          intro Y W' gs hden
          exact hfempty Y W' gs ((den_test_seq_iff W' .one f gs.1 gs.2).mp hden).2
        refine EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hfzero)) ?_
        refine EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (seq_zero_right (.act a))) ?_
        exact seq_zero_right (.test b)
      · have hfalse : ∀ (X : Type) (W : T → X → Bool) (x : X),
            bval W b x = false := by
          intro X W x
          cases hv : bval W b x with
          | false => rfl
          | true => exact absurd ⟨X, W, x, hv⟩ hunsat
        exact test_unsat_seq _ hfalse
  | test c =>
      intro f hf b hempty
      exact EquivBA.trans (test_seq_merge b c f)
        (hf (.and b c) (ULempty_test_head hempty))
  | seq e₁ e₂ ih₁ ih₂ =>
      intro f hf b hempty
      have hassoc : EquivBA (.seq (.test b) (.seq (.seq e₁ e₂) f))
          (.seq (.test b) (.seq e₁ (.seq e₂ f))) :=
        EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (seq_assoc e₁ e₂ f)
      exact EquivBA.trans hassoc
        (ih₁ (.seq e₂ f) (ih₂ f hf) b (ULempty_congr hassoc hempty))
  | ite c e₁ e₂ ih₁ ih₂ =>
      intro f hf b hempty
      refine EquivBA.trans (ite_seq_normal b c e₁ e₂ f) ?_
      refine EquivBA.trans
        (EquivBA.ite_c (ih₁ f hf _ (ULempty_ite_then hempty))
          (ih₂ f hf _ (ULempty_ite_else hempty))) ?_
      exact EquivBA.base (Equiv.u1 (.and b c) (.test .zero))
  | wh g p ih =>
      intro f hf b hempty
      obtain ⟨Z, body, hbZ, hexit, hnormal⟩ :=
        loop_normal_form (k := f) (post_all p) hempty
      refine EquivBA.trans (hnormal f) ?_
      refine EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (hf _ hexit))) ?_
      refine EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (seq_zero_right (.wh (.and Z g) body))) ?_
      exact seq_zero_right (.test b)

/-! ## The theorem -/

/-- Every expression is null-eliminable. -/
theorem zero_all (e : Exp A T) : Zero e := by
  intro b hempty
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.symm (seq_one e))) ?_
  exact zeroThrough_all e (.test .one) zero_one b
    (ULempty_congr
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.symm (seq_one e)))
      hempty)

/-- **Null-language completeness for GKAT from the finite axioms.**  A program with no
    guarded strings is provably `0`.  `W3` (the `n = 1` uniqueness instance already in
    the finite system) is the only fixpoint principle used; the global uniqueness axiom
    `UA` is not used, and neither is any completeness hypothesis. -/
theorem nullLanguage_complete (e : Exp A T) (hempty : UniformExpLempty e) :
    EquivBA e (.test .zero) := by
  refine EquivBA.trans (EquivBA.symm (one_seq e)) ?_
  exact zero_all e .one
    (ULempty_congr (EquivBA.symm (one_seq e)) hempty)

/-- Restated against the language-equivalence interface used by the completeness file. -/
theorem uniformLanguageEquivalent_zero_implies_zero (e : Exp A T)
    (h : UniformLanguageEquivalent e (.test .zero)) :
    EquivBA e (.test .zero) :=
  nullLanguage_complete e ((uniformExpLempty_iff_zero e).mpr h)

/-! ## What this discharges in the Thompson development -/

/-- **The dead-branch obligation, unconditionally.**  Compare
    `dead_thompson_label_eq_zero_of_complete`, which had to assume
    `FiniteAxiomsCompleteBA` — i.e. the theorem under construction.  Here nothing is
    assumed: a uniformly dead state of a certified Thompson automaton has canonical
    label provably `0`. -/
theorem dead_thompson_label_eq_zero
    (program : Exp A T)
    (state : Option (certifiedThompson A T program).State)
    (hstate : state ∈ (certifiedThompson A T program).aut.toGAut.states)
    (hdead : UniformAutLempty
      (certifiedThompson A T program).aut.toGAut state) :
    EquivBA (initializedStandard program
      (certifiedThompson A T program).standard state) (.test .zero) :=
  nullLanguage_complete _
    ((certifiedThompson_state_empty_iff program state hstate).mp hdead)

/-- The same statement for a uniformly dead *program*: every effectively unreachable or
    non-terminating Thompson region can be deleted inside the finite theory. -/
theorem dead_region_eliminable {e : Exp A T} (b : BExp T)
    (hdead : UniformExpLempty (.seq (.test b) e)) :
    EquivBA (.seq (.test b) e) (.test .zero) :=
  zero_all e b hdead

/-! ## Non-vacuity

    The theorem is only interesting if `UniformExpLempty` has witnesses that are not
    already syntactically `0`, and if `EquivBA` is not total.  The latter is
    `GkatFaithful.left_distrib_not_ba_theorem`; the former is exhibited here. -/

/-- An always-guarded loop has no guarded string at all: every `InLoop` derivation must
    bottom out in an `exit`, which `1` forbids. -/
theorem inLoop_one_empty {X : Type} (W : T → X → Bool)
    (dene : GS A X → Prop) (gs : GS A X) : ¬ InLoop W .one dene gs := by
  intro hloop
  induction hloop with
  | exit a hexit => exact Bool.noConfusion hexit
  | step _ _ _ _ _ _ ih => exact ih

theorem while_true_uniformly_empty (p : Exp A T) :
    UniformExpLempty (.wh .one p) :=
  fun X W gs hden => inLoop_one_empty W (den W p) gs hden

theorem ULempty_seq_right {e f : Exp A T} (hf : UniformExpLempty f) :
    UniformExpLempty (.seq e f) := by
  intro X W gs hden
  obtain ⟨l₁, l₂, _, _, hf'⟩ := hden
  exact hf X W (lastAtom gs.1 l₁, l₂) hf'

/-- A concrete non-reflexive instance: an action followed by a divergent loop is
    provably `0`.  The two sides are syntactically distinct, so this is not an instance
    of reflexivity. -/
theorem act_then_diverge_eq_zero (a : A) (p : Exp A T) :
    EquivBA (.seq (.act a) (.wh .one p)) (.test .zero) :=
  nullLanguage_complete _ (ULempty_seq_right (while_true_uniformly_empty p))

example :
    (Exp.seq (.act ()) (.wh .one (.act ())) : Exp Unit Unit) ≠ (.test .zero) := by
  decide

/-- A dead *test* region is likewise eliminable, even under an arbitrary program. -/
theorem contradictory_prefix_eq_zero (b : BExp T) (e : Exp A T) :
    EquivBA (.seq (.test (.and b (.not b))) e) (.test .zero) := by
  refine dead_region_eliminable (.and b (.not b)) ?_
  intro X W gs hden
  obtain ⟨a, l⟩ := gs
  obtain ⟨hb, _⟩ := (den_test_seq_iff W _ e a l).mp hden
  change (bval W b a && (! bval W b a)) = true at hb
  have hcontra : (bval W b a && (! bval W b a)) = false := by
    cases bval W b a <;> rfl
  rw [hcontra] at hb
  exact Bool.noConfusion hb

#print axioms ite_seq_normal
#print axioms loop_normal_form
#print axioms post_all
#print axioms zeroThrough_all
#print axioms nullLanguage_complete
#print axioms dead_thompson_label_eq_zero
#print axioms act_then_diverge_eq_zero
#print axioms contradictory_prefix_eq_zero

end GkatNullLanguage
