import GkatPlanExistenceProofs
import GkatNormalizationProofs

/-! # The automaton-level trim — the mountain bypass

    The plan-existence programme needed `LiveSteps` of the Thompson sum, and the
    syntactic route (normalize the PROGRAM until its Thompson automaton is
    silent-free) is a mountain: a compositional liveness invariant over the whole
    Thompson construction.  This file takes the bypass: trim the AUTOMATON.

    `trimAut` drops every transition whose target has empty generic language,
    conjoining each surviving guard with the negation of the dead guards dropped
    before it — so `firstMatch` priority is preserved exactly.  Consequences:

    * per-state languages are UNCHANGED at every carrier and valuation
      (`autLang_trimAut`) — dead arms only ever consumed a letter and rejected;
    * the trimmed automaton is trimmed in the `LiveSteps` sense BY CONSTRUCTION
      (`liveSteps_trimAut`) — every firing step lands on a live state.

    With this, the canonical-quotient start merge needs NO hypothesis at all:
    quotient `trimAut` of the sum instead of the sum.  What the swap costs is one
    new obligation, discharged in the equation-transfer section of the programme:
    solutions of the trimmed system provably solve the original system (`s3`
    kills the dead arms). -/

namespace GkatTrim

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization

variable {S A T : Type}

open Classical in
/-- Trim a transition list: drop dead-target entries, conjoining each kept guard
    with the negation of the dead guards accumulated so far (`D`), so that the
    first-match priority structure is preserved exactly. -/
noncomputable def trimList (aut : GAut S A T) :
    List (BExp T × A × S) → BExp T → List (BExp T × A × S)
  | [], _ => []
  | (g, a, t) :: rest, D =>
      if Live aut t then (.and g (.not D), a, t) :: trimList aut rest D
      else trimList aut rest (.or D g)

/-- The trimmed automaton: same states, same halts, trimmed transitions. -/
noncomputable def trimAut (aut : GAut S A T) : GAut S A T where
  states := aut.states
  hlt := aut.hlt
  trans := fun s => trimList aut (aut.trans s) .zero
  start := aut.start

open Classical in
private theorem trimList_cons (aut : GAut S A T) (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) (D : BExp T) :
    trimList aut ((g, a, t) :: rest) D
      = if Live aut t then (.and g (.not D), a, t) :: trimList aut rest D
        else trimList aut rest (.or D g) := rfl

private theorem fm_cons {Atom : Type} (V : T → Atom → Bool) (x : Atom)
    (g : BExp T) (a : A) (t : S) (rest : List (BExp T × A × S)) :
    firstMatch V x ((g, a, t) :: rest)
      = if bval V g x = true then some (a, t) else firstMatch V x rest := rfl

open Classical in
/-- Once inside the accumulated dead guard, the trimmed list never fires. -/
theorem firstMatch_trimList_none {Atom : Type} (V : T → Atom → Bool)
    (aut : GAut S A T) (L : List (BExp T × A × S)) (D : BExp T) (x : Atom)
    (hD : bval V D x = true) :
    firstMatch V x (trimList aut L D) = none := by
  induction L generalizing D with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      by_cases hl : Live aut t
      · rw [trimList_cons, if_pos hl, fm_cons]
        have hb : ¬ (bval V (.and g (.not D)) x = true) := by
          intro h
          have h' : (bval V g x && !bval V D x) = true := h
          rw [hD] at h'
          cases hg : bval V g x <;> rw [hg] at h' <;> exact Bool.noConfusion h'
        rw [if_neg hb]
        exact ih D hD
      · rw [trimList_cons, if_neg hl]
        refine ih (.or D g) ?_
        show (bval V D x || bval V g x) = true
        rw [hD]; rfl

open Classical in
/-- Outside the accumulated dead guard, the trimmed list fires exactly like the
    original — except that dead-target hits become rejections. -/
theorem firstMatch_trimList {Atom : Type} (V : T → Atom → Bool)
    (aut : GAut S A T) (L : List (BExp T × A × S)) (D : BExp T) (x : Atom)
    (hD : bval V D x = false) :
    firstMatch V x (trimList aut L D)
      = (firstMatch V x L).bind
          (fun y => if Live aut y.2 then some y else none) := by
  induction L generalizing D with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      by_cases hl : Live aut t
      · rw [trimList_cons, if_pos hl, fm_cons, fm_cons]
        by_cases hg : bval V g x = true
        · have hb : bval V (.and g (.not D)) x = true := by
            show (bval V g x && !bval V D x) = true
            rw [hg, hD]; rfl
          rw [if_pos hg, if_pos hb]
          show some (a, t) = if Live aut t then some (a, t) else none
          rw [if_pos hl]
        · have hb : ¬ (bval V (.and g (.not D)) x = true) := by
            intro h
            have h' : (bval V g x && !bval V D x) = true := h
            cases hgv : bval V g x with
            | true => exact hg hgv
            | false => rw [hgv] at h'; exact Bool.noConfusion h'
          rw [if_neg hg, if_neg hb]
          exact ih D hD
      · rw [trimList_cons, if_neg hl, fm_cons]
        by_cases hg : bval V g x = true
        · rw [if_pos hg]
          show firstMatch V x (trimList aut rest (.or D g))
            = if Live aut t then some (a, t) else none
          rw [if_neg hl]
          exact firstMatch_trimList_none V aut rest (.or D g) x (by
            show (bval V D x || bval V g x) = true
            rw [hg]
            cases bval V D x <;> rfl)
        · rw [if_neg hg]
          refine ih (.or D g) ?_
          show (bval V D x || bval V g x) = false
          rw [hD]
          cases hgv : bval V g x with
          | true => exact absurd hgv hg
          | false => rfl

open Classical in
/-- One-step behaviour of the trim: original steps, with dead hits rejected. -/
theorem autStep_trimAut {Atom : Type} (V : T → Atom → Bool) (aut : GAut S A T)
    (s : S) (x : Atom) :
    autStep V (trimAut aut) s x
      = (autStep V aut s x).bind
          (fun y => if Live aut y.2 then some y else none) :=
  firstMatch_trimList V aut (aut.trans s) .zero x rfl

open Classical in
theorem bind_live_some {aut : GAut S A T} {o : Option (A × S)} {q : A}
    {s' : S}
    (h : (o.bind fun y => if Live aut y.2 then some y else none)
      = some (q, s')) :
    o = some (q, s') ∧ Live aut s' := by
  cases o with
  | none => exact nomatch h
  | some y =>
      obtain ⟨q0, t0⟩ := y
      have h2 : (if Live aut t0 then some (q0, t0) else none) = some (q, s') := h
      by_cases hl : Live aut t0
      · rw [if_pos hl] at h2
        have hp : (q0, t0) = (q, s') := Option.some.inj h2
        have hq : q0 = q := congrArg Prod.fst hp
        have ht : t0 = s' := congrArg Prod.snd hp
        subst hq; subst ht
        exact ⟨rfl, hl⟩
      · rw [if_neg hl] at h2
        exact nomatch h2

open Classical in
theorem bind_live_of {aut : GAut S A T} {o : Option (A × S)} {q : A}
    {s' : S} (h : o = some (q, s')) (hl : Live aut s') :
    (o.bind fun y => if Live aut y.2 then some y else none) = some (q, s') := by
  subst h
  show (if Live aut s' then some (q, s') else none) = some (q, s')
  rw [if_pos hl]

/-- **Language preservation**: accepted runs never pass through dead states, so
    trimming changes no state's language — at ANY carrier and valuation. -/
theorem autRun_trimAut {Atom : Type} (V : T → Atom → Bool) (aut : GAut S A T) :
    ∀ (l : List (A × Atom)) (s : S) (x : Atom),
      autRun V (trimAut aut) s x l ↔ autRun V aut s x l := by
  intro l
  induction l with
  | nil => intro s x; exact Iff.rfl
  | cons p w ih =>
      intro s x
      obtain ⟨q, x'⟩ := p
      constructor
      · intro hr
        have hr' : ∃ s', autStep V (trimAut aut) s x = some (q, s')
            ∧ autRun V (trimAut aut) s' x' w := hr
        obtain ⟨s', hstep, hrun⟩ := hr'
        rw [autStep_trimAut] at hstep
        obtain ⟨ha, -⟩ := bind_live_some hstep
        exact ⟨s', ha, (ih s' x').mp hrun⟩
      · intro hr
        have hr' : ∃ s', autStep V aut s x = some (q, s')
            ∧ autRun V aut s' x' w := hr
        obtain ⟨s', ha, hrun⟩ := hr'
        have hlive : Live aut s' :=
          ⟨_, _, (autRun_gen aut V w s' x').mp hrun⟩
        exact ⟨s', by rw [autStep_trimAut]; exact bind_live_of ha hlive,
          (ih s' x').mpr hrun⟩

theorem autLang_trimAut {Atom : Type} (V : T → Atom → Bool) (aut : GAut S A T)
    (s : S) : autLang V (trimAut aut) s = autLang V aut s := by
  funext gs
  obtain ⟨x, l⟩ := gs
  exact propext (autRun_trimAut V aut l s x)

/-- Liveness transfers back into the trim. -/
theorem live_trimAut {aut : GAut S A T} {s : S} (h : Live aut s) :
    Live (trimAut aut) s := by
  obtain ⟨β, l, hr⟩ := h
  exact ⟨β, l, (autRun_trimAut (genW T) aut l s β).mpr hr⟩

/-- **The trim is trimmed**: every firing step of `trimAut` lands live. -/
theorem liveSteps_trimAut (aut : GAut S A T) : LiveSteps (trimAut aut) := by
  intro s α q s' hs
  rw [autStep_trimAut] at hs
  obtain ⟨-, hl⟩ := bind_live_some hs
  exact live_trimAut hl

#print axioms autLang_trimAut
#print axioms liveSteps_trimAut

/-! ## Equation transfer: trimmed solutions solve the original system

    A solution of the trimmed equations provably solves the untrimmed ones:
    dead arms die by `s3` (their targets' solutions are provably `0`, because a
    dead state's trimmed equation is an empty-guard fold over an empty halt),
    and the guard bookkeeping is under-guard `ite` algebra. -/

/-- The Salomaa fold, list-parametric (definitionally `eqRHS`). -/
private def foldT (sol : S → Exp A T) (h : BExp T)
    (L : List (BExp T × A × S)) : Exp A T :=
  L.foldr (fun t acc => .ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc) (.test h)

theorem firstMatch_none_all {Atom : Type} (V : T → Atom → Bool) {x : Atom}
    {L : List (BExp T × A × S)} (h : firstMatch V x L = none) :
    ∀ e ∈ L, bval V e.1 x = false := by
  induction L with
  | nil => intro e he; exact nomatch he
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [fm_cons] at h
      by_cases hg : bval V g x = true
      · rw [if_pos hg] at h; exact nomatch h
      · rw [if_neg hg] at h
        intro e he
        rcases List.mem_cons.mp he with heq | hmem
        · rw [heq]
          cases hgv : bval V g x with
          | true => exact absurd hgv hg
          | false => rfl
        · exact ih h e hmem

theorem firstMatch_some_of_mem {Atom : Type} (V : T → Atom → Bool) {x : Atom}
    {L : List (BExp T × A × S)} {e : BExp T × A × S} (he : e ∈ L)
    (hb : bval V e.1 x = true) : ∃ y, firstMatch V x L = some y := by
  induction L with
  | nil => exact nomatch he
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [fm_cons]
      by_cases hg : bval V g x = true
      · exact ⟨(a, t), by rw [if_pos hg]⟩
      · rw [if_neg hg]
        rcases List.mem_cons.mp he with heq | hmem
        · exact absurd (by rw [heq] at hb; exact hb) hg
        · exact ih hmem

/-- A fold whose guards and halt are all empty is provably `0?`. -/
theorem fold_all_dead {sol : S → Exp A T} {h : BExp T}
    {L : List (BExp T × A × S)}
    (hg : ∀ e ∈ L, GuardEmpty e.1) (hh : GuardEmpty h) :
    EquivBA (foldT sol h L) (.test .zero) := by
  induction L with
  | nil => exact guard_zero_test hh
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      show EquivBA
        (.ite g (.seq (.act a) (sol t)) (foldT sol h rest)) (.test .zero)
      refine EquivBA.trans (GkatDeadExitElim.ite_zero_guard _ _
        (fun X W x => hg (g, a, t) (by simp) X W x)) ?_
      exact ih (fun e he => hg e (by simp [he]))

/-- **Dead states have provably-zero solutions** in the trimmed system: their
    trimmed equations are empty-guard folds over an empty halt. -/
theorem trim_dead_sol {aut : GAut S A T} {sol : S → Exp A T}
    (hsol : SolvesBA (trimAut aut) sol) {t : S} (ht : t ∈ aut.states)
    (hd : ¬ Live aut t) : EquivBA (sol t) (.test .zero) := by
  refine EquivBA.trans (hsol t ht) ?_
  refine fold_all_dead ?_ ?_
  · intro e he X W x
    show bval W e.1 x = false
    rw [bval_gen W x e.1]
    cases hb : bval (genW T) e.1 (fun u => W u x) with
    | false => rfl
    | true =>
        exfalso
        obtain ⟨y, hy⟩ := firstMatch_some_of_mem (genW T) he hb
        obtain ⟨q, u⟩ := y
        have hy' : autStep (genW T) (trimAut aut) t (fun u => W u x)
            = some (q, u) := hy
        rw [autStep_trimAut] at hy'
        obtain ⟨ha, hlu⟩ := bind_live_some hy'
        obtain ⟨β, l, hr⟩ := hlu
        exact hd ⟨_, (q, β) :: l, u, ha, hr⟩
  · intro X W x
    show bval W (aut.hlt t) x = false
    rw [bval_gen W x (aut.hlt t)]
    cases hh : bval (genW T) (aut.hlt t) (fun u => W u x) with
    | false => rfl
    | true => exact absurd ⟨_, [], hh⟩ hd

/-- Introduce a provably-dead arm: `X ≡ ite c 0? X` when `X` rejects under `c`. -/
theorem dead_arm_insert {c : BExp T} {X : Exp A T}
    (hc : EquivBA (.seq (.test c) X) (.seq (.test c) (.test .zero))) :
    EquivBA X (.ite c (.test .zero) X) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u1 c X)))
    (ite_congr_under_guard hc)

/-- Inside the else guard of `ite (¬D∧g)`, the `(¬D)?` assertion tightens to
    `(¬(D∨g))?`. -/
theorem else_tighten_or (D g : BExp T) (X : Exp A T) : EquivBA
    (.seq (.test (.not (.and (.not D) g))) (.seq (.test (.not D)) X))
    (.seq (.test (.not (.or D g))) X) := by
  refine EquivBA.trans
    (seq_assoc' (.test (.not (.and (.not D) g))) (.test (.not D)) X) ?_
  refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl X))
  refine EquivBA.trans (EquivBA.s6 _ _) ?_
  refine EquivBA.baTest ?_
  intro Y W x
  show (!(!bval W D x && bval W g x) && !bval W D x)
    = (!(bval W D x || bval W g x))
  cases bval W D x <;> cases bval W g x <;> rfl

/-- A redundant stronger assertion absorbs into a stronger prefix. -/
theorem test_absorb_left {h c : BExp T} (himp : GuardImplies h c) (X : Exp A T) :
    EquivBA (.seq (.test h) (.seq (.test c) X)) (.seq (.test h) X) := by
  refine EquivBA.trans (seq_assoc' (.test h) (.test c) X) ?_
  refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl X))
  refine EquivBA.trans (EquivBA.s6 h c) ?_
  refine EquivBA.baTest ?_
  intro Y W x
  show (bval W h x && bval W c x) = bval W h x
  cases hh : bval W h x with
  | true => rw [himp Y W x hh]; rfl
  | false => rfl

open Classical in
/-- Under a guard inside the accumulated dead set, a trimmed fold with an
    excluded halt is provably `0?`. -/
theorem trim_fold_dead (aut : GAut S A T) {sol : S → Exp A T} {hltG h : BExp T}
    (L : List (BExp T × A × S)) :
    ∀ D' : BExp T, GuardImplies h D' → GuardEmpty (.and h hltG) →
    EquivBA (.seq (.test h) (foldT sol hltG (trimList aut L D')))
            (.seq (.test h) (.test .zero)) := by
  induction L with
  | nil =>
      intro D' _ hempty
      refine EquivBA.trans (EquivBA.s6 h hltG) ?_
      refine EquivBA.trans (guard_zero_test hempty) ?_
      refine EquivBA.symm ?_
      refine EquivBA.trans (EquivBA.s6 h .zero) ?_
      exact EquivBA.baTest (fun X W x => by
        show (bval W h x && false) = false
        cases bval W h x <;> rfl)
  | cons hd rest ih =>
      intro D' himp hempty
      obtain ⟨g, a, t⟩ := hd
      by_cases hl : Live aut t
      · rw [trimList_cons, if_pos hl]
        show EquivBA (.seq (.test h)
          (.ite (.and g (.not D')) (.seq (.act a) (sol t))
            (foldT sol hltG (trimList aut rest D')))) _
        refine EquivBA.trans (test_seq_ite h (.and g (.not D')) _ _) ?_
        refine EquivBA.trans (GkatDeadExitElim.ite_zero_guard _ _
          (fun X W x => by
            show (bval W h x && (bval W g x && !bval W D' x)) = false
            cases hh : bval W h x with
            | false => rfl
            | true => rw [himp X W x hh]; cases bval W g x <;> rfl)) ?_
        exact ih D' himp hempty
      · rw [trimList_cons, if_neg hl]
        exact ih (.or D' g) (fun X W x hh => by
          show (bval W D' x || bval W g x) = true
          rw [himp X W x hh]; rfl) hempty

open Classical in
/-- **THE EQUATION-TRANSFER FOLD LEMMA**: outside the accumulated dead guard,
    the original fold is provably the trimmed fold — dead arms die by `s3`. -/
theorem trim_fold_equiv (aut : GAut S A T) {sol : S → Exp A T} {hltG : BExp T}
    (L : List (BExp T × A × S)) :
    ∀ D : BExp T,
    (∀ e ∈ L, ¬ Live aut e.2.2 → EquivBA (sol e.2.2) (.test .zero)) →
    (∀ e ∈ L, GuardEmpty (.and hltG e.1)) →
    EquivBA (.seq (.test (.not D)) (foldT sol hltG L))
            (.seq (.test (.not D)) (foldT sol hltG (trimList aut L D))) := by
  induction L with
  | nil => intro D _ _; exact EquivBA.base (Equiv.refl _)
  | cons hd rest ih =>
      intro D hdead hexcl
      obtain ⟨g, a, t⟩ := hd
      have hdead' : ∀ e ∈ rest, ¬ Live aut e.2.2 →
          EquivBA (sol e.2.2) (.test .zero) :=
        fun e he => hdead e (by simp [he])
      have hexcl' : ∀ e ∈ rest, GuardEmpty (.and hltG e.1) :=
        fun e he => hexcl e (by simp [he])
      by_cases hl : Live aut t
      · rw [trimList_cons, if_pos hl]
        show EquivBA (.seq (.test (.not D))
            (.ite g (.seq (.act a) (sol t)) (foldT sol hltG rest)))
          (.seq (.test (.not D))
            (.ite (.and g (.not D)) (.seq (.act a) (sol t))
              (foldT sol hltG (trimList aut rest D))))
        refine EquivBA.trans (test_seq_ite (.not D) g _ _) ?_
        refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
          (ih D hdead' hexcl')) ?_
        refine EquivBA.trans (EquivBA.ite_guard (b := .and (.not D) g)
          (c := .and (.not D) (.and g (.not D))) (fun X W x => by
          show (!bval W D x && bval W g x)
            = (!bval W D x && (bval W g x && !bval W D x))
          cases bval W D x <;> cases bval W g x <;> rfl)) ?_
        exact EquivBA.symm (test_seq_ite (.not D) (.and g (.not D)) _ _)
      · rw [trimList_cons, if_neg hl]
        show EquivBA (.seq (.test (.not D))
            (.ite g (.seq (.act a) (sol t)) (foldT sol hltG rest)))
          (.seq (.test (.not D)) (foldT sol hltG (trimList aut rest (.or D g))))
        have harm : EquivBA (.seq (.act a) (sol t)) (.test .zero) := by
          refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (hdead (g, a, t) (by simp) hl)) ?_
          exact EquivBA.base (Equiv.s3 (.act a))
        refine EquivBA.trans (test_seq_ite (.not D) g _ _) ?_
        refine EquivBA.trans (EquivBA.ite_c harm (EquivBA.base (Equiv.refl _))) ?_
        refine EquivBA.trans (ite_congr_under_else
          (EquivBA.trans (else_tighten_or D g (foldT sol hltG rest))
            (EquivBA.trans (ih (.or D g) hdead' hexcl')
              (EquivBA.symm (else_tighten_or D g
                (foldT sol hltG (trimList aut rest (.or D g)))))))) ?_
        refine EquivBA.symm (dead_arm_insert ?_)
        refine EquivBA.trans (test_absorb_left (fun X W x hh => by
          show (!bval W D x) = true
          have hh' : (!bval W D x && bval W g x) = true := hh
          cases hD : bval W D x with
          | false => rfl
          | true => rw [hD] at hh'; exact Bool.noConfusion hh') _) ?_
        exact trim_fold_dead aut rest (.or D g)
          (fun X W x hh => by
            show (bval W D x || bval W g x) = true
            have hh' : (!bval W D x && bval W g x) = true := hh
            cases hD : bval W D x with
            | true => rfl
            | false =>
                rw [hD] at hh'
                cases hg : bval W g x with
                | true => rfl
                | false => rw [hg] at hh'; exact Bool.noConfusion hh')
          (fun X W x => by
            show ((!bval W D x && bval W g x) && bval W hltG x) = false
            have hex' : (bval W hltG x && bval W g x) = false :=
              hexcl (g, a, t) (by simp) X W x
            cases hg : bval W g x with
            | false => cases bval W D x <;> rfl
            | true =>
                rw [hg] at hex'
                cases hh : bval W hltG x with
                | false => cases bval W D x <;> rfl
                | true => rw [hh] at hex'; exact Bool.noConfusion hex')

/-- Strip a tautological `(¬0)?` prefix. -/
theorem not_zero_strip (X : Exp A T) :
    EquivBA (.seq (.test (.not .zero)) X) X := by
  refine EquivBA.trans (test_seq_guard_congr (b := .not .zero) (c := .one) X
    (fun Y W x => by
      show (!false) = true
      rfl)) ?_
  exact EquivBA.base (Equiv.s4 X)

open Classical in
/-- **UNTRIMMING SOLUTIONS**: a solution of the trimmed system provably solves
    the original system, given listed-target closure and halt/step exclusion at
    the generic valuation. -/
theorem solvesBA_untrim (aut : GAut S A T) {sol : S → Exp A T}
    (hclosed : ∀ s ∈ aut.states, ∀ e ∈ aut.trans s, e.2.2 ∈ aut.states)
    (hwf1 : ∀ s ∈ aut.states, ∀ α : T → Bool,
      bval (genW T) (aut.hlt s) α = true →
        autStep (genW T) aut s α = none)
    (hsol : SolvesBA (trimAut aut) sol) : SolvesBA aut sol := by
  intro s hs
  refine EquivBA.trans (hsol s hs) ?_
  refine EquivBA.symm ?_
  have hdead : ∀ e ∈ aut.trans s, ¬ Live aut e.2.2 →
      EquivBA (sol e.2.2) (.test .zero) :=
    fun e he hnl => trim_dead_sol hsol (hclosed s hs e he) hnl
  have hexcl : ∀ e ∈ aut.trans s, GuardEmpty (.and (aut.hlt s) e.1) := by
    intro e he X W x
    show (bval W (aut.hlt s) x && bval W e.1 x) = false
    rw [bval_gen W x (aut.hlt s), bval_gen W x e.1]
    cases hh : bval (genW T) (aut.hlt s) (fun u => W u x) with
    | false => rfl
    | true =>
        rw [firstMatch_none_all (genW T) (hwf1 s hs _ hh) e he]
        rfl
  refine EquivBA.trans (EquivBA.symm (not_zero_strip _)) ?_
  refine EquivBA.trans (trim_fold_equiv aut (aut.trans s) .zero hdead hexcl) ?_
  exact not_zero_strip _

#print axioms solvesBA_untrim

/-! ## The rewired summit

    Quotient the TRIMMED sum: the start merge is then unconditional (the trim
    satisfies `LiveSteps` by construction, so S1a's language equality upgrades
    to bisimilarity), the canonical quotient always exists, its solutions
    descend to the trim, `solvesBA_untrim` carries them to the raw sum, the
    coproduct embeddings restrict them to the components, and Thompson
    uniqueness reads off the programs.  ONE hypothesis remains: role existence
    for the canonical quotient of the trimmed sum. -/

theorem firstMatch_none_of_all {Atom : Type} (V : T → Atom → Bool) {x : Atom}
    {L : List (BExp T × A × S)} (h : ∀ e ∈ L, bval V e.1 x = false) :
    firstMatch V x L = none := by
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      have hf : bval V g x = false := h (g, a, t) (by simp)
      have hg : ¬ (bval V g x = true) := by
        intro hgt
        rw [hf] at hgt
        exact Bool.noConfusion hgt
      rw [fm_cons, if_neg hg]
      exact ih (fun e he => h e (by simp [he]))

theorem toGAut_closed {S' : Type} (aut : InitializedGAut S' A T)
    (hinit : InitTargetsListed aut) (hcore : CoreTargetsListed aut) :
    ∀ s ∈ aut.toGAut.states, ∀ e ∈ aut.toGAut.trans s,
      e.2.2 ∈ aut.toGAut.states := by
  intro s hs e he
  cases s with
  | none =>
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      exact List.mem_cons_of_mem _
        (List.mem_map.mpr ⟨t0.2.2, hinit t0 ht0, rfl⟩)
  | some u =>
      have hu : u ∈ aut.core.states := by
        rcases List.mem_cons.mp hs with h1 | h2
        · exact nomatch h1
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h2
          exact (Option.some.inj hvu) ▸ hv
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      exact List.mem_cons_of_mem _
        (List.mem_map.mpr ⟨t0.2.2, hcore u hu t0 ht0, rfl⟩)

theorem toGAut_excl {S' : Type} (aut : InitializedGAut S' A T)
    (standard : S' → Exp A T)
    (hinit : InitHaltDisjointBA aut standard) (hcore : CoreHaltDisjoint aut) :
    ∀ s ∈ aut.toGAut.states, ∀ e ∈ aut.toGAut.trans s,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        (bval W (aut.toGAut.hlt s) x && bval W e.1 x) = false := by
  intro s hs e he X W x
  cases s with
  | none =>
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      have hb : (bval W t0.1 x && bval W aut.initHlt x) = false :=
        hinit (t0.1, .seq (.act t0.2.1) (standard t0.2.2))
          (List.mem_map.mpr ⟨t0, ht0, rfl⟩) X W x
      show (bval W aut.initHlt x && bval W t0.1 x) = false
      cases h1 : bval W t0.1 x with
      | false => cases bval W aut.initHlt x <;> rfl
      | true =>
          rw [h1] at hb
          cases h2 : bval W aut.initHlt x with
          | false => rfl
          | true => rw [h2] at hb; exact Bool.noConfusion hb
  | some u =>
      have hu : u ∈ aut.core.states := by
        rcases List.mem_cons.mp hs with h1 | h2
        · exact nomatch h1
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h2
          exact (Option.some.inj hvu) ▸ hv
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      have hb : (bval W t0.1 x && bval W (aut.core.hlt u) x) = false :=
        hcore u hu t0 ht0 X W x
      show (bval W (aut.core.hlt u) x && bval W t0.1 x) = false
      cases h1 : bval W t0.1 x with
      | false => cases bval W (aut.core.hlt u) x <;> rfl
      | true =>
          rw [h1] at hb
          cases h2 : bval W (aut.core.hlt u) x with
          | false => rfl
          | true => rw [h2] at hb; exact Bool.noConfusion hb

theorem sumGAut_closed {S₁ S₂ : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    (h₁ : ∀ s ∈ aut₁.states, ∀ e ∈ aut₁.trans s, e.2.2 ∈ aut₁.states)
    (h₂ : ∀ s ∈ aut₂.states, ∀ e ∈ aut₂.trans s, e.2.2 ∈ aut₂.states) :
    ∀ s ∈ (sumGAut aut₁ aut₂).states, ∀ e ∈ (sumGAut aut₁ aut₂).trans s,
      e.2.2 ∈ (sumGAut aut₁ aut₂).states := by
  intro s hs e he
  cases s with
  | inl u =>
      have hu : u ∈ aut₁.states := by
        rcases List.mem_append.mp hs with h1 | h2
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h1
          exact (Sum.inl.inj hvu) ▸ hv
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h2
          exact nomatch hvu
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      exact List.mem_append.mpr
        (Or.inl (List.mem_map.mpr ⟨t0.2.2, h₁ u hu t0 ht0, rfl⟩))
  | inr u =>
      have hu : u ∈ aut₂.states := by
        rcases List.mem_append.mp hs with h1 | h2
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h1
          exact nomatch hvu
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h2
          exact (Sum.inr.inj hvu) ▸ hv
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      exact List.mem_append.mpr
        (Or.inr (List.mem_map.mpr ⟨t0.2.2, h₂ u hu t0 ht0, rfl⟩))

theorem sumGAut_excl {S₁ S₂ : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    (h₁ : ∀ s ∈ aut₁.states, ∀ e ∈ aut₁.trans s,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        (bval W (aut₁.hlt s) x && bval W e.1 x) = false)
    (h₂ : ∀ s ∈ aut₂.states, ∀ e ∈ aut₂.trans s,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        (bval W (aut₂.hlt s) x && bval W e.1 x) = false) :
    ∀ s ∈ (sumGAut aut₁ aut₂).states, ∀ e ∈ (sumGAut aut₁ aut₂).trans s,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        (bval W ((sumGAut aut₁ aut₂).hlt s) x && bval W e.1 x) = false := by
  intro s hs e he X W x
  cases s with
  | inl u =>
      have hu : u ∈ aut₁.states := by
        rcases List.mem_append.mp hs with h1 | h2
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h1
          exact (Sum.inl.inj hvu) ▸ hv
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h2
          exact nomatch hvu
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      exact h₁ u hu t0 ht0 X W x
  | inr u =>
      have hu : u ∈ aut₂.states := by
        rcases List.mem_append.mp hs with h1 | h2
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h1
          exact nomatch hvu
        · obtain ⟨v, hv, hvu⟩ := List.mem_map.mp h2
          exact (Sum.inr.inj hvu) ▸ hv
      obtain ⟨t0, ht0, rfl⟩ := List.mem_map.mp he
      exact h₂ u hu t0 ht0 X W x

/-- The Thompson sum of a program pair. -/
def SUMof (A T : Type) (e f : Exp A T) :
    GAut ((Option (certifiedThompson A T e).State)
      ⊕ (Option (certifiedThompson A T f).State)) A T :=
  sumGAut (certifiedThompson A T e).aut.toGAut
          (certifiedThompson A T f).aut.toGAut

/-- **THE REMAINING HYPOTHESIS**: the canonical quotient of the TRIMMED
    Thompson sum of every uniformly-equivalent pair is role-covered.  This is
    the exact object the harness measures (it trims and canonizes before
    everything), and the quotient and start merge are now theorems — only the
    roles are open. -/
def RoleCovered (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ qsol : ((Option (certifiedThompson A T e).State)
        ⊕ (Option (certifiedThompson A T f).State)) → Exp A T,
      ∀ s ∈ (bisimQuotAut (trimAut (SUMof A T e f))).states,
        StateRole (bisimQuotAut (trimAut (SUMof A T e f))) qsol s

open GkatSumQuotient in
/-- **The per-pair core of the rewired summit**: any provable solution of the
    canonical quotient of the trimmed Thompson sum yields the pair's provable
    equivalence. -/
theorem equivBA_of_quot_solvesBA {A T : Type} (e f : Exp A T)
    (heq : UniformLanguageEquivalent e f)
    {qsol : ((Option (certifiedThompson A T e).State)
        ⊕ (Option (certifiedThompson A T f).State)) → Exp A T}
    (hq : SolvesBA (bisimQuotAut (trimAut (SUMof A T e f))) qsol) :
    EquivBA e f := by
  have htrim : SolvesBA (trimAut (SUMof A T e f))
      (fun s => qsol (bisimRep (trimAut (SUMof A T e f)) s)) :=
    (canonicalQuotient (trimAut (SUMof A T e f))).lift_solvesBA hq
  have hsum : SolvesBA (SUMof A T e f)
      (fun s => qsol (bisimRep (trimAut (SUMof A T e f)) s)) := by
    refine solvesBA_untrim _ ?_ ?_ htrim
    · exact sumGAut_closed
        (toGAut_closed _ (certifiedThompson A T e).certificate.initTargets
          (certifiedThompson A T e).structural.targets)
        (toGAut_closed _ (certifiedThompson A T f).certificate.initTargets
          (certifiedThompson A T f).structural.targets)
    · intro s hs α hh
      refine firstMatch_none_of_all (genW T) ?_
      intro en hen
      have hx := sumGAut_excl
          (toGAut_excl _ _ (certifiedThompson A T e).certificate.initDisjoint
            (certifiedThompson A T e).structural.disjoint)
          (toGAut_excl _ _ (certifiedThompson A T f).certificate.initDisjoint
            (certifiedThompson A T f).structural.disjoint)
          s hs en hen _ (genW T) α
      have hx' : (bval (genW T) ((SUMof A T e f).hlt s) α
          && bval (genW T) en.1 α) = false := hx
      rw [hh] at hx'
      exact hx' 
  have hsole : SolvesBA (certifiedThompson A T e).aut.toGAut
      (fun s => qsol (bisimRep (trimAut (SUMof A T e f)) (Sum.inl s))) :=
    (GAutHom.inl _ _).lift_solvesBA hsum
  have hsolf : SolvesBA (certifiedThompson A T f).aut.toGAut
      (fun s => qsol (bisimRep (trimAut (SUMof A T e f)) (Sum.inr s))) :=
    (GAutHom.inr _ _).lift_solvesBA hsum
  have he' := sol_none_equiv e _ hsole
  have hf' := sol_none_equiv f _ hsolf
  have hstarteq : UniformStateEquiv (trimAut (SUMof A T e f))
      (Sum.inl none) (Sum.inr none) := by
    intro X W
    rw [autLang_trimAut, autLang_trimAut]
    exact sum_starts_language_equal e f heq W
  have hmerge : bisimRep (trimAut (SUMof A T e f)) (Sum.inl none)
      = bisimRep (trimAut (SUMof A T e f)) (Sum.inr none) :=
    bisimRep_coherent _ (genBisimilar_of_uniformStateEquiv
      (liveSteps_trimAut _) hstarteq)
  refine EquivBA.trans (EquivBA.symm he') ?_
  rw [hmerge]
  exact hf'

open GkatSumQuotient in
/-- **THE REWIRED CONDITIONAL SUMMIT**: role existence for canonical quotients
    of trimmed Thompson sums implies UA-free completeness of GKAT over the free
    Boolean algebra. -/
theorem completeness_of_roleCovered {A T : Type} (h : RoleCovered A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨qsol, hroles⟩ := h e f heq
  exact equivBA_of_quot_solvesBA e f heq (decomp_solves _ _ hroles)

#print axioms completeness_of_roleCovered

end GkatTrim
