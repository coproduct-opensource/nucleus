import GkatPlanExistenceProofs

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
open GkatDecomp GkatPlanExistence

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
private theorem bind_live_some {aut : GAut S A T} {o : Option (A × S)} {q : A}
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
private theorem bind_live_of {aut : GAut S A T} {o : Option (A × S)} {q : A}
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

end GkatTrim
