import GkatSynthesisProofs

/-!
# The positive fork, closed for the unrolling class

The residual target `CommonCoveredIntermediate` is the open problem in general
(`ua2_of_solvable_intermediate`).  It is not open everywhere.  This file closes it for the
class the whole investigation started from: **W1-unrolling pairs**,

    while g do B        vs        if g then (B ; while g do B) else 1

for an arbitrary body — arbitrary *system*, in fact, not just an arbitrary program.

The content is one lemma, and it is the move any attack on the general problem needs.
Covering is obtained by making the expression's automaton **finer**; unrolling is the
canonical way to refine it; and `unrollCover` proves that the unrolled automaton covers the
loop's, for every body.  That the two are *bisimilar* is easy and useless — what is proved
here is that one is a quotient of the other, which is the strength the fork requires.

Why this class and not another: the original plan proposed exactly this pair as its
falsification experiment.  It could not falsify the cospan (the unrolled automaton covers
the loop, so the pair sits inside the already-settled class), and that was the first finding
of the session.  The same fact, pushed the other way, closes the *positive* fork here.
-/

namespace GkatUnrollCover

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis

variable {A T : Type}

/-! ## `firstMatch` under guard refinement -/

private theorem firstMatch_none_forall {S X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) (h : firstMatch W x L = none) :
    ∀ t ∈ L, bval W t.1 x = false := by
  induction L with
  | nil => intro t ht; exact absurd ht (by simp)
  | cons hd tl ih =>
      obtain ⟨g, q, s⟩ := hd
      simp only [firstMatch] at h
      by_cases hg : bval W g x
      · rw [if_pos hg] at h; exact absurd h (by simp)
      · rw [if_neg hg] at h
        intro t ht
        rcases List.mem_cons.mp ht with rfl | htl
        · exact Bool.eq_false_iff.mpr hg
        · exact ih h t htl

/-- If a list does not fire, no guard-refinement of it fires either. -/
private theorem firstMatch_none_of_refine {S R X : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S)) (f : BExp T × A × S → BExp T × A × R)
    (href : ∀ t ∈ L, bval W t.1 x = false → bval W (f t).1 x = false)
    (h : firstMatch W x L = none) : firstMatch W x (L.map f) = none := by
  have hall := firstMatch_none_forall W x L h
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      simp only [List.map_cons, firstMatch]
      have hhd : bval W (f hd).1 x = false :=
        href hd (List.Mem.head _) (hall hd (List.Mem.head _))
      rw [if_neg (by rw [hhd]; simp)]
      exact ih (fun t ht => href t (List.Mem.tail _ ht))
        (by
          simp only [firstMatch] at h
          by_cases hg : bval W hd.1 x
          · rw [if_pos (by obtain ⟨g, q, s⟩ := hd; exact hg)] at h
            exact absurd h (by simp)
          · rw [if_neg (by obtain ⟨g, q, s⟩ := hd; exact hg)] at h; exact h)
        (fun t ht => hall t (List.Mem.tail _ ht))

private theorem fm_guard_to {S R X : Type} (W : T → X → Bool) (x : X) (P : BExp T)
    (F : S → R) (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P t.1, t.2.1, F t.2.2))) =
      if bval W P x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P q) x = (bval W P x && bval W q x) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hq : bval W q x <;> simp [hP, hq]

private theorem fm_guard2 {S X : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
    (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P (BExp.and Q t.1), t.2))) =
      if bval W P x then (if bval W Q x then firstMatch W x L else none) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> cases hQ : bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and Q q)) x
          = (bval W P x && (bval W Q x && bval W q x)) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hq : bval W q x <;>
        simp [hP, hQ, hq]

/-! ## The unrolling cover

    `unrollCover` is stated for an arbitrary initialized system, so it applies to any body
    at all, not only to bodies that are Thompson automata. -/

private def unrollMap {S : Type} : Sum (Sum S S) Empty → S
  | Sum.inl (Sum.inl u) => u
  | Sum.inl (Sum.inr u) => u
  | Sum.inr z => nomatch z

/-- **Unrolling refines.**  The automaton of `if g then (B ; while g do B) else 1` covers
    the automaton of `while g do B`: the prefix copy of the body and the in-loop copy both
    fold onto the loop's single copy, and the guards match block for block.

    This is the canonical refinement move — the one that turns "bisimilar to an expression"
    into "covered by an expression" — proved for an arbitrary body. -/
def unrollCover {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    InitCover
      (iteInitialized g (seqInitialized B (loopInitialized g B))
        (thompsonTest (A := A) BExp.one))
      (loopInitialized g B) where
  map := unrollMap
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and g (BExp.and B.initHlt (BExp.not g)))
      (BExp.and (BExp.not g) BExp.one)) x = bval W (BExp.not g) x
    cases hg : bval W g x <;> simp [bval, hg]
  coreHlt_eq := fun s _ _ _ => by
    cases s with
    | inl u => cases u with | inl _ => rfl | inr _ => rfl
    | inr z => exact nomatch z
  initStep_eq := fun X W x => by
    show (firstMatch W x
        (((B.initTrans.map (fun t : BExp T × A × S => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))) ++
           (B.initTrans.map (fun t : BExp T × A × S => (BExp.and g t.1, t.2))).map
             (fun t : BExp T × A × S =>
               (BExp.and B.initHlt t.1, t.2.1, (Sum.inr t.2.2 : Sum S S)))).map
          (fun t : BExp T × A × Sum S S =>
            (BExp.and g t.1, t.2.1, (Sum.inl t.2.2 : Sum (Sum S S) Empty)))) ++
         ([] : List (BExp T × A × Sum (Sum S S) Empty)))).map
        (fun o => (o.1, unrollMap o.2))
      = firstMatch W x (B.initTrans.map (fun t : BExp T × A × S => (BExp.and g t.1, t.2)))
    rw [List.append_nil, fm_guard_to, firstMatch_map_guard]
    cases hg : bval W g x
    · simp
    · simp only [if_pos rfl]
      cases hb : firstMatch W x B.initTrans with
      | some o =>
          have hP : firstMatch W x
              (B.initTrans.map (fun t : BExp T × A × S =>
                (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))))
              = some (o.1, Sum.inl o.2) := by
            rw [firstMatch_map_target_to, hb]; rfl
          rw [firstMatch_append_some _ _ _ _ hP]
          rfl
      | none =>
          have hP : firstMatch W x
              (B.initTrans.map (fun t : BExp T × A × S =>
                (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S)))) = none := by
            rw [firstMatch_map_target_to, hb]; rfl
          have hQ : firstMatch W x
              ((B.initTrans.map (fun t : BExp T × A × S => (BExp.and g t.1, t.2))).map
                (fun t : BExp T × A × S =>
                  (BExp.and B.initHlt t.1, t.2.1, (Sum.inr t.2.2 : Sum S S)))) = none := by
            rw [fm_guard_to, firstMatch_map_guard, hb]
            cases bval W B.initHlt x <;> cases bval W g x <;> rfl
          rw [firstMatch_append_none _ _ _ _ hP, hQ]
          rfl
  coreStep_eq := fun s _ W x => by
    cases s with
    | inl u =>
        cases u with
        | inl v =>
            show (firstMatch W x
                (((B.core.trans v).map (fun t : BExp T × A × S =>
                    (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))) ++
                  (B.initTrans.map (fun t : BExp T × A × S => (BExp.and g t.1, t.2))).map
                    (fun t : BExp T × A × S =>
                      (BExp.and (B.core.hlt v) t.1, t.2.1, (Sum.inr t.2.2 : Sum S S)))).map
                 (fun t : BExp T × A × Sum S S =>
                   (t.1, t.2.1, (Sum.inl t.2.2 : Sum (Sum S S) Empty))))).map
                (fun o => (o.1, unrollMap o.2))
              = firstMatch W x (B.core.trans v ++
                  B.initTrans.map (fun t : BExp T × A × S =>
                    (BExp.and (B.core.hlt v) (BExp.and g t.1), t.2)))
            rw [firstMatch_map_target_to]
            cases hb : firstMatch W x (B.core.trans v) with
            | some o =>
                have hP : firstMatch W x
                    ((B.core.trans v).map (fun t : BExp T × A × S =>
                      (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S)))) = some (o.1, Sum.inl o.2) := by
                  rw [firstMatch_map_target_to, hb]; rfl
                rw [firstMatch_append_some _ _ _ _ hP, firstMatch_append_some _ _ _ _ hb]
                rfl
            | none =>
                have hP : firstMatch W x
                    ((B.core.trans v).map (fun t : BExp T × A × S =>
                      (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S)))) = none := by
                  rw [firstMatch_map_target_to, hb]; rfl
                rw [firstMatch_append_none _ _ _ _ hP, firstMatch_append_none _ _ _ _ hb,
                  fm_guard_to, firstMatch_map_guard, fm_guard2]
                cases bval W (B.core.hlt v) x <;> cases bval W g x <;>
                  cases firstMatch W x B.initTrans <;> rfl
        | inr v =>
            show (firstMatch W x
                ((B.core.trans v ++ B.initTrans.map (fun t : BExp T × A × S =>
                    (BExp.and (B.core.hlt v) (BExp.and g t.1), t.2))).map
                  (fun t : BExp T × A × S =>
                    (t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))) |>.map
                  (fun t : BExp T × A × Sum S S =>
                    (t.1, t.2.1, (Sum.inl t.2.2 : Sum (Sum S S) Empty))))).map
                (fun o => (o.1, unrollMap o.2))
              = firstMatch W x (B.core.trans v ++
                  B.initTrans.map (fun t : BExp T × A × S =>
                    (BExp.and (B.core.hlt v) (BExp.and g t.1), t.2)))
            rw [firstMatch_map_target_to, firstMatch_map_target_to]
            cases firstMatch W x (B.core.trans v ++
                B.initTrans.map (fun t : BExp T × A × S =>
                  (BExp.and (B.core.hlt v) (BExp.and g t.1), t.2))) <;> rfl
    | inr z => exact nomatch z
  maps := by
    intro s hs
    cases s with
    | inl u =>
        cases u with
        | inl v =>
            have : v ∈ B.core.states := by
              change Sum.inl (Sum.inl v) ∈
                (B.core.states.map Sum.inl ++ B.core.states.map Sum.inr).map Sum.inl ++
                  ([] : List (Sum (Sum S S) Empty)) at hs
              rw [List.append_nil] at hs
              obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hs
              cases hwe
              rcases List.mem_append.mp hw with h | h
              · obtain ⟨y, hy, hye⟩ := List.mem_map.mp h; cases hye; exact hy
              · obtain ⟨y, _, hye⟩ := List.mem_map.mp h; exact absurd hye (by simp)
            exact this
        | inr v =>
            have : v ∈ B.core.states := by
              change Sum.inl (Sum.inr v) ∈
                (B.core.states.map Sum.inl ++ B.core.states.map Sum.inr).map Sum.inl ++
                  ([] : List (Sum (Sum S S) Empty)) at hs
              rw [List.append_nil] at hs
              obtain ⟨w, hw, hwe⟩ := List.mem_map.mp hs
              cases hwe
              rcases List.mem_append.mp hw with h | h
              · obtain ⟨y, _, hye⟩ := List.mem_map.mp h; exact absurd hye (by simp)
              · obtain ⟨y, hy, hye⟩ := List.mem_map.mp h; cases hye; exact hy
            exact this
    | inr z => exact nomatch z
  onto := by
    intro q hq
    refine ⟨Sum.inl (Sum.inl q), ?_, rfl⟩
    change Sum.inl (Sum.inl q) ∈
      (B.core.states.map Sum.inl ++ B.core.states.map Sum.inr).map Sum.inl ++
        ([] : List (Sum (Sum S S) Empty))
    rw [List.append_nil]
    exact List.mem_map.mpr ⟨Sum.inl q, List.mem_append.mpr (Or.inl
      (List.mem_map.mpr ⟨q, hq, rfl⟩)), rfl⟩

/-! ## The fork, closed for the unrolling class -/

/-- **`CommonCoveredIntermediate`, discharged for every W1-unrolling pair.**  For arbitrary
    guard and body, `while g do e` and its unrolling admit a common intermediate that is
    solvable by the syntax: the unrolled program's own automaton, which covers the loop's by
    `unrollCover` and is solvable because it is syntax-generated.

    Unlike `fork_closed_for_covered_pairs`, this class is not hypothesis-bound — it holds for
    every `g` and `e`, so it is an infinite class of pairs on which the residual target is
    settled outright. -/
theorem fork_closed_for_unrolling (g : BExp T) (e : Exp A T) :
    ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid (certifiedThompson A T (.wh g e)).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T
        (.ite g (.seq e (.wh g e)) (.test BExp.one))).aut) ∧
      HasThompsonCover mid :=
  ⟨(certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).State,
    (certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).aut,
    ⟨unrollCover g (certifiedThompson A T e).aut⟩,
    ⟨InitCover.id _⟩,
    ⟨.ite g (.seq e (.wh g e)) (.test BExp.one), ⟨InitCover.id _⟩⟩⟩

/-- Non-vacuity: the closure re-derives W1 itself, through the fork's own reduction rather
    than from the axiom. -/
theorem w1_via_the_fork (g : BExp T) (e : Exp A T) :
    EquivBA (.wh g e : Exp A T) (.ite g (.seq e (.wh g e)) (.test BExp.one)) :=
  equivBA_of_common_refinement
    (InitCover.id (certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).aut)
    (unrollCover g (certifiedThompson A T e).aut)
    (InitCover.id _)

#print axioms unrollCover
#print axioms fork_closed_for_unrolling
#print axioms w1_via_the_fork

/-! ## The bisimilarity→cover upgrade, delivering internal completeness

    `GkatCompletenessReduction.completeness_iff_thompson_internal` shows full completeness is
    *equivalent* to `ThompsonInternalCompleteBA`: two listed states of **one** program's
    Thompson automaton with the same language carry provably equal canonical labels.  So the
    whole open problem is about telling apart positions inside a single program.

    A cover delivers exactly that, wherever it reaches.  This is what the upgrade buys: a
    cover is not merely a bisimulation, it identifies positions — and identified positions
    have provably equal labels, with no uniqueness axiom. -/

/-- **Covers force internal label equality.**  If a cover onto another program's automaton
    identifies two listed positions of `h`'s automaton, their canonical labels are provably
    equal — an instance of `ThompsonInternalCompleteBA`, from the finite axioms alone.

    The mechanism: the target's canonical labelling is a solution, the quotient lifts it to a
    solution of `h`'s system, Thompson uniqueness makes that solution provably the canonical
    one pointwise, and the lifted solution is *literally the same expression* at the two
    identified positions. -/
theorem labels_agree_of_cover {e h : Exp A T}
    (φ : InitCover (certifiedThompson A T h).aut (certifiedThompson A T e).aut)
    (u v : Option (certifiedThompson A T h).State)
    (hu : u ∈ (certifiedThompson A T h).aut.toGAut.states)
    (hv : v ∈ (certifiedThompson A T h).aut.toGAut.states)
    (heq : φ.toQuotient.mapState u = φ.toQuotient.mapState v) :
    EquivBA (initializedStandard h (certifiedThompson A T h).standard u)
      (initializedStandard h (certifiedThompson A T h).standard v) := by
  have hsol := φ.toQuotient.lift_solvesBA (certifiedThompson_toGAut_solves e)
  have hu' := (certifiedThompson A T h).certificate.toGAut_state_canonical
    (certifiedThompson A T h).aut (certifiedThompson A T h).standard h _ hsol u hu
  have hv' := (certifiedThompson A T h).certificate.toGAut_state_canonical
    (certifiedThompson A T h).aut (certifiedThompson A T h).standard h _ hsol v hv
  have hsame : initializedStandard e (certifiedThompson A T e).standard
      (φ.toQuotient.mapState u)
      = initializedStandard e (certifiedThompson A T e).standard
        (φ.toQuotient.mapState v) := by rw [heq]
  exact EquivBA.trans (EquivBA.symm hu') (by rw [hsame] at hu' ⊢; exact hv')

/-- **The unrolling instance.**  In the automaton of `if g then (e ; while g do e) else 1`,
    the prefix copy and the in-loop copy of any body position carry provably equal canonical
    labels — the two positions that behave alike, told apart and then proved equal, for
    arbitrary guard and body. -/
theorem unroll_labels_agree (g : BExp T) (e : Exp A T)
    (u : (certifiedThompson A T e).State)
    (hu : u ∈ (certifiedThompson A T e).aut.core.states) :
    EquivBA
      (initializedStandard (.ite g (.seq e (.wh g e)) (.test BExp.one))
        (certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).standard
        (some (Sum.inl (Sum.inl u))))
      (initializedStandard (.ite g (.seq e (.wh g e)) (.test BExp.one))
        (certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).standard
        (some (Sum.inl (Sum.inr u)))) := by
  have hcore : ∀ w : Sum (certifiedThompson A T e).State (certifiedThompson A T e).State,
      w ∈ ((certifiedThompson A T e).aut.core.states.map Sum.inl ++
           (certifiedThompson A T e).aut.core.states.map Sum.inr) →
      (some (Sum.inl w) :
        Option (certifiedThompson A T (.ite g (.seq e (.wh g e)) (.test BExp.one))).State)
        ∈ (certifiedThompson A T
            (.ite g (.seq e (.wh g e)) (.test BExp.one))).aut.toGAut.states := by
    intro w hw
    refine List.Mem.tail _ (List.mem_map.mpr ⟨Sum.inl w, ?_, rfl⟩)
    change Sum.inl w ∈
      ((certifiedThompson A T e).aut.core.states.map Sum.inl ++
       (certifiedThompson A T e).aut.core.states.map Sum.inr).map Sum.inl ++
      ([] : List (Sum (Sum (certifiedThompson A T e).State
        (certifiedThompson A T e).State) Empty))
    rw [List.append_nil]
    exact List.mem_map.mpr ⟨w, hw, rfl⟩
  exact labels_agree_of_cover (e := .wh g e)
    (h := .ite g (.seq e (.wh g e)) (.test BExp.one))
    (unrollCover g (certifiedThompson A T e).aut)
    _ _ (hcore (Sum.inl u) (List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨u, hu, rfl⟩))))
    (hcore (Sum.inr u) (List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨u, hu, rfl⟩)))) rfl

#print axioms labels_agree_of_cover
#print axioms unroll_labels_agree

/-! ## The target, reduced to completeness on canonical labels

    `ThompsonInternalCompleteBA` compares two *states* by their guarded languages.  But a
    Thompson state's language is exactly the denotation of its canonical label
    (`certifiedThompson_state_language`), so the comparison is really between two
    *expressions* — and the whole open problem is completeness restricted to the expressions
    that arise as canonical labels of Thompson positions.

    That is a sharp restriction.  Canonical labels are not arbitrary programs: they are the
    syntactic suffixes the constructors write down — `standard u` in an `ite` branch,
    `standard u ; R` in the left of a sequence, `standard u ; while g do e` inside a loop. -/

/-- A Thompson state's language equality *is* language equivalence of its canonical label. -/
theorem langEq_iff_labels (program : Exp A T)
    (s t : Option (certifiedThompson A T program).State)
    (hs : s ∈ (certifiedThompson A T program).aut.toGAut.states)
    (ht : t ∈ (certifiedThompson A T program).aut.toGAut.states) :
    UniformAutLangEq (certifiedThompson A T program).aut.toGAut
        (certifiedThompson A T program).aut.toGAut s t
      ↔ UniformLanguageEquivalent
          (initializedStandard program (certifiedThompson A T program).standard s)
          (initializedStandard program (certifiedThompson A T program).standard t) := by
  constructor
  · intro h X W gs
    have hs' := congrFun (certifiedThompson_state_language program s hs X W) gs
    have ht' := congrFun (certifiedThompson_state_language program t ht X W) gs
    rw [← hs', ← ht']
    exact h X W gs
  · intro h X W gs
    have hs' := congrFun (certifiedThompson_state_language program s hs X W) gs
    have ht' := congrFun (certifiedThompson_state_language program t ht X W) gs
    rw [hs', ht']
    exact h X W gs

/-- **The residual target, in its most restricted form.**  Completeness need only hold
    between expressions that arise as canonical labels of positions in one program's own
    Thompson automaton. -/
def LabelCompleteBA (A T : Type) : Prop :=
  ∀ (program : Exp A T) (s t : Option (certifiedThompson A T program).State),
    s ∈ (certifiedThompson A T program).aut.toGAut.states →
    t ∈ (certifiedThompson A T program).aut.toGAut.states →
    UniformLanguageEquivalent
        (initializedStandard program (certifiedThompson A T program).standard s)
        (initializedStandard program (certifiedThompson A T program).standard t) →
    EquivBA (initializedStandard program (certifiedThompson A T program).standard s)
      (initializedStandard program (certifiedThompson A T program).standard t)

/-- Label-completeness gives the internal form, hence — with
    `completeness_iff_thompson_internal` — full finite-axiom completeness. -/
theorem thompson_internal_of_label_complete (h : LabelCompleteBA A T) :
    GkatCompletenessReduction.ThompsonInternalCompleteBA A T := by
  intro program s t hs ht hlang
  exact h program s t hs ht ((langEq_iff_labels program s t hs ht).mp hlang)

/-- And conversely, so the restriction loses nothing: the open problem *is* completeness on
    canonical labels, no more and no less. -/
theorem label_complete_of_thompson_internal
    (h : GkatCompletenessReduction.ThompsonInternalCompleteBA A T) : LabelCompleteBA A T := by
  intro program s t hs ht hlang
  exact h program s t hs ht ((langEq_iff_labels program s t hs ht).mpr hlang)

#print axioms langEq_iff_labels
#print axioms thompson_internal_of_label_complete
#print axioms label_complete_of_thompson_internal

/-! ## The label formulas, machine-checked

    Each constructor either carries a position's label through unchanged, or wraps it in a
    context.  All five are definitional; stating them makes the shape of `LabelCompleteBA`
    explicit. -/

theorem label_ite_inl (g : BExp T) (p q : Exp A T) (u : (certifiedThompson A T p).State) :
    initializedStandard (.ite g p q)
        (certifiedThompson A T (.ite g p q)).standard (some (Sum.inl u))
      = initializedStandard p (certifiedThompson A T p).standard (some u) := rfl

theorem label_ite_inr (g : BExp T) (p q : Exp A T) (v : (certifiedThompson A T q).State) :
    initializedStandard (.ite g p q)
        (certifiedThompson A T (.ite g p q)).standard (some (Sum.inr v))
      = initializedStandard q (certifiedThompson A T q).standard (some v) := rfl

theorem label_seq_inr (p q : Exp A T) (v : (certifiedThompson A T q).State) :
    initializedStandard (.seq p q)
        (certifiedThompson A T (.seq p q)).standard (some (Sum.inr v))
      = initializedStandard q (certifiedThompson A T q).standard (some v) := rfl

/-- The left of a sequence wraps its labels in a context. -/
theorem label_seq_inl (p q : Exp A T) (u : (certifiedThompson A T p).State) :
    initializedStandard (.seq p q)
        (certifiedThompson A T (.seq p q)).standard (some (Sum.inl u))
      = .seq (initializedStandard p (certifiedThompson A T p).standard (some u)) q := rfl

/-- So does a loop body. -/
theorem label_wh (g : BExp T) (p : Exp A T) (u : (certifiedThompson A T p).State) :
    initializedStandard (.wh g p)
        (certifiedThompson A T (.wh g p)).standard (some u)
      = .seq (initializedStandard p (certifiedThompson A T p).standard (some u))
          (.wh g p) := rfl

/-! ### What the reduction does and does not buy

    It is tempting to read the label formulas as saying the open problem is confined to the
    two *context* cases, `seq`-left and loop-body, since the others carry labels through
    untouched.  That reading is wrong, and the repository's own proof of
    `complete_of_thompson_internal` shows why: it embeds an arbitrary pair `e`, `f` as the
    two branch positions of `1 ? (a·e) : (a·f)`, whose labels are exactly `e` and `f`.

    So *cross-branch* pairs inside a single `ite` already carry the full strength of the
    problem — the label restriction is not a weakening of the expressions involved.  What it
    does remove is arbitrary *systems*: quotients, products and minimizations never appear,
    and uniqueness is needed only for syntax-generated automata, where it is a theorem
    (`certifiedThompson_solution_unique`).  Existence is the whole of what is left, which is
    the same conclusion Pham's thesis reaches from the other side. -/

#print axioms label_seq_inl
#print axioms label_wh

/-! ## A mechanism that is not "pull the guard back"

    Every technique that closes a slice of the existence problem works the same way: it makes
    the branch decidable *before* the prefix runs, so prefix and guard commute.  On the
    undecided residue that is impossible by construction — `undecided_residue_branches` shows
    the prefix demonstrably reaches both sides of the guard — so no amount of cleverness about
    witnesses will reach it.

    There is a different move available, and it is the one the classical theory uses.  For
    regular expressions the position (Glushkov) automaton and the c-continuation automaton sit
    *above* the canonical ones in the quotient order: the follow automaton is a quotient of the
    position automaton, the equation automaton a quotient of the c-continuation automaton.  One
    does not commute anything — one starts from a syntax-generated automaton that is already
    fine enough and folds it down.

    Transposed here: do not solve the system, **refine the expression until its automaton is
    fine enough to fold onto the system**.  `unrollCover` is one such refinement step, and the
    lemmas below say a refinement made anywhere inside a program refines the whole program.  So
    unrollings compose into a chain of ever-finer covers, and the open question changes shape:
    it becomes *how far must one unroll*, a termination question with classical analogues
    (star height, loop complexity, the Caron–Ziadi inversion of Glushkov), rather than *which
    guard witnesses the crossing*, which the residue result has already closed off. -/

/-- Unrolling a loop inside the left of a sequence refines the whole sequence. -/
def unroll_in_seq_left {S Q : Type} (g : BExp T) (B : InitializedGAut S A T)
    (R : InitializedGAut Q A T) :
    InitCover
      (seqInitialized (iteInitialized g (seqInitialized B (loopInitialized g B))
        (thompsonTest (A := A) BExp.one)) R)
      (seqInitialized (loopInitialized g B) R) :=
  InitCover.seq (unrollCover g B) (InitCover.id R)

/-- …inside the right of a sequence. -/
def unroll_in_seq_right {S Q : Type} (g : BExp T) (B : InitializedGAut S A T)
    (L : InitializedGAut Q A T) :
    InitCover
      (seqInitialized L (iteInitialized g (seqInitialized B (loopInitialized g B))
        (thompsonTest (A := A) BExp.one)))
      (seqInitialized L (loopInitialized g B)) :=
  InitCover.seq (InitCover.id L) (unrollCover g B)

/-- …inside a branch of a conditional. -/
def unroll_in_ite_left {S Q : Type} (guard g : BExp T) (B : InitializedGAut S A T)
    (R : InitializedGAut Q A T) :
    InitCover
      (iteInitialized guard (iteInitialized g (seqInitialized B (loopInitialized g B))
        (thompsonTest (A := A) BExp.one)) R)
      (iteInitialized guard (loopInitialized g B) R) :=
  InitCover.ite guard (unrollCover g B) (InitCover.id R)

/-- …and inside the body of an enclosing loop.  With `InitCover.comp`, these chain: any
    sequence of unrollings, at any depths, yields a single cover onto the original. -/
def unroll_in_loop {S : Type} (outer g : BExp T) (B : InitializedGAut S A T) :
    InitCover
      (loopInitialized outer (iteInitialized g (seqInitialized B (loopInitialized g B))
        (thompsonTest (A := A) BExp.one)))
      (loopInitialized outer (loopInitialized g B)) :=
  InitCover.loop outer (unrollCover g B)

#print axioms unroll_in_seq_left
#print axioms unroll_in_loop

end GkatUnrollCover
