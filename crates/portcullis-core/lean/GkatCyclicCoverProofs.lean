import GkatUnrollCoverProofs

/-!
# The cyclic cover: repeating the loop body refines the loop

`unrollCover` refines a loop by peeling one iteration off the **front** — it lengthens the
lasso's tail and leaves the cycle alone.  This file proves the complementary move, the one
that changes the cycle itself:

    while g do B        vs        while g do (B ; if g then B else 1)

Read through Stallings' dictionary — `star_bijection` says an `InitCover` is bijective on
stars, i.e. a *covering map of graphs* — a Thompson automaton's cycle length is the number
of action occurrences in its loop body, and that is the covering degree.  Repeating the body
doubles it.  This is the degree-2 cyclic cover of the loop.

Why the move is needed.  Searching the closure of the Thompson combinators shows that
unrolling and guard-split duplication both *saturate*: however often they are iterated they
rescue only 12 of the 20 uncoverable pullbacks at `K = 5`, and 34 of 54 at `K = 4`.  Neither
changes the covering degree — unrolling lengthens the tail, duplication widens — so neither
can produce a candidate whose cycle the pullback's cycle divides.  Adding this move closes
both enumerations outright, and degree 2 is enough: degree 3 never rescues anything that
iterated doubling does not.

What is proved here is the *semantic* half, and for an arbitrary body — an arbitrary
initialized system, not merely a Thompson one.  Whether

    x^(b) ≡ (x · (x +_b 1))^(b)

is *derivable* from the finite axioms is a separate and open question: unrolling both sides
reduces it to identifying two solutions of the same guarded system, which is exactly the
step the uniqueness axiom supplies.  Nothing below depends on that question.
-/

namespace GkatCyclicCover

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis

variable {A T : Type}

/-! ## `firstMatch` under guard refinement with a change of target

    The three shapes the doubled automaton actually produces.  `firstMatch_map_guard` and
    `firstMatch_map_target_to` cover a guard and a target separately; these cover the
    combinations, and `firstMatch_map_guard_target` in `GkatKleeneProofs` is not enough
    because it forces the target type to stay fixed. -/

private theorem fmGuardTo {S R X : Type} (W : T → X → Bool) (x : X) (P : BExp T)
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
      cases hP : bval W P x <;> cases hq : bval W q x <;> simp

private theorem fmGuard2To {S R X : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
    (F : S → R) (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P (BExp.and Q t.1), t.2.1, F t.2.2))) =
      if bval W P x then
        (if bval W Q x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none)
      else none := by
  induction L with
  | nil => cases hP : bval W P x <;> cases hQ : bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨q, a, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and Q q)) x
          = (bval W P x && (bval W Q x && bval W q x)) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hq : bval W q x <;> simp

private theorem fmGuard2 {S X : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
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
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hq : bval W q x <;> simp

/-! ## The doubled body -/

/-- Both copies of the body fold onto the loop's single copy. -/
private def cycMap {S : Type} : Sum S (Sum S Empty) → S
  | Sum.inl u => u
  | Sum.inr (Sum.inl u) => u
  | Sum.inr (Sum.inr z) => nomatch z

/-- `B ; if g then B else 1` — the body run once, then run again exactly when the loop
    would have re-entered it.

    Public because the *statement* of `cyclicCover` mentions it, and because composing
    `cyclicCover` with itself at `doubledBody g B` gives degree 4 for free. -/
def doubledBody {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    InitializedGAut (Sum S (Sum S Empty)) A T :=
  seqInitialized B (iteInitialized g B (thompsonTest (A := A) BExp.one))

private theorem doubledBody_initTrans {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    (doubledBody g B).initTrans =
      B.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S (Sum S Empty)))) ++
      B.initTrans.map (fun t =>
        (BExp.and B.initHlt (BExp.and g t.1), t.2.1,
          (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty)))) := by
  simp [doubledBody, seqInitialized, iteInitialized, thompsonTest, List.map_map, Function.comp]

private theorem doubledBody_coreHlt_inl {S : Type} (g : BExp T) (B : InitializedGAut S A T)
    (u : S) :
    (doubledBody g B).core.hlt (Sum.inl u) =
      BExp.and (B.core.hlt u)
        (BExp.or (BExp.and g B.initHlt) (BExp.and (BExp.not g) BExp.one)) := rfl

private theorem doubledBody_coreHlt_inr {S : Type} (g : BExp T) (B : InitializedGAut S A T)
    (u : S) :
    (doubledBody g B).core.hlt (Sum.inr (Sum.inl u)) = B.core.hlt u := rfl

private theorem doubledBody_coreTrans_inl {S : Type} (g : BExp T) (B : InitializedGAut S A T)
    (u : S) :
    (doubledBody g B).core.trans (Sum.inl u) =
      (B.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S (Sum S Empty)))) ++
      B.initTrans.map (fun t =>
        (BExp.and (B.core.hlt u) (BExp.and g t.1), t.2.1,
          (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty)))) := by
  simp [doubledBody, seqInitialized, seqGSystem, iteInitialized, thompsonTest,
    List.map_map, Function.comp]

private theorem doubledBody_coreTrans_inr {S : Type} (g : BExp T) (B : InitializedGAut S A T)
    (u : S) :
    (doubledBody g B).core.trans (Sum.inr (Sum.inl u)) =
      (B.core.trans u).map (fun t =>
        (t.1, t.2.1, (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty)))) := by
  simp [doubledBody, seqInitialized, seqGSystem, iteInitialized, thompsonTest, sumGSystem,
    List.map_map, Function.comp]

private theorem doubledBody_states {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    (doubledBody g B).core.states =
      B.core.states.map (Sum.inl : S → Sum S (Sum S Empty)) ++
      B.core.states.map (fun u => (Sum.inr (Sum.inl u) : Sum S (Sum S Empty))) := by
  simp [doubledBody, seqInitialized, seqGSystem, iteInitialized, thompsonTest, sumGSystem,
    List.map_map, Function.comp]

/-! ## The pseudostate steps agree

    The whole proof turns on this: the doubled body's initial pseudostate makes exactly the
    move the body's does.  The prefix copy fires first, and when it does not fire nothing in
    the second copy can, because every guard there refines a guard of `B.initTrans`. -/

private theorem doubledBody_initStep {S X : Type} (g : BExp T) (B : InitializedGAut S A T)
    (W : T → X → Bool) (x : X) :
    (firstMatch W x (doubledBody g B).initTrans).map (fun o => (o.1, cycMap o.2))
      = firstMatch W x B.initTrans := by
  rw [doubledBody_initTrans]
  cases hb : firstMatch W x B.initTrans with
  | some o =>
      have hP : firstMatch W x
          (B.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S (Sum S Empty)))))
          = some (o.1, Sum.inl o.2) := by
        rw [firstMatch_map_target_to, hb]; rfl
      rw [firstMatch_append_some _ _ _ _ hP]; rfl
  | none =>
      have hP : firstMatch W x
          (B.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S (Sum S Empty)))))
          = none := by
        rw [firstMatch_map_target_to, hb]; rfl
      have hQ : firstMatch W x
          (B.initTrans.map (fun t =>
            (BExp.and B.initHlt (BExp.and g t.1), t.2.1,
              (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty))))) = none := by
        rw [fmGuard2To (F := fun v : S => (Sum.inr (Sum.inl v) : Sum S (Sum S Empty))), hb]
        cases bval W B.initHlt x <;> cases bval W g x <;> rfl
      rw [firstMatch_append_none _ _ _ _ hP, hQ]; rfl

/-- The `none` half of `doubledBody_initStep`, in the form the core-step proof needs. -/
private theorem doubledBody_initStep_none {S X : Type} (g : BExp T) (B : InitializedGAut S A T)
    (W : T → X → Bool) (x : X) (h : firstMatch W x B.initTrans = none) :
    firstMatch W x (doubledBody g B).initTrans = none := by
  have hA := doubledBody_initStep g B W x
  rw [h] at hA
  cases hC : firstMatch W x (doubledBody g B).initTrans with
  | none => rfl
  | some o => rw [hC] at hA; exact absurd hA (by simp)

/-! ## The cyclic cover -/

/-- **Repeating the loop body refines the loop.**  The automaton of
    `while g do (B ; if g then B else 1)` covers the automaton of `while g do B`: the two
    copies of the body fold onto the loop's single copy, and the guards match block for
    block.

    Unlike `unrollCover`, this move changes the length of the cycle, which under
    `star_bijection` is the degree of the covering.  It is the refinement the search found
    to be missing, and it is proved here for an arbitrary body. -/
def cyclicCover {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    InitCover (loopInitialized g (doubledBody g B)) (loopInitialized g B) where
  map := cycMap
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun s _ W x => by
    cases s with
    | inl u =>
        show bval W (BExp.and ((doubledBody g B).core.hlt (Sum.inl u)) (BExp.not g)) x
          = bval W (BExp.and (B.core.hlt u) (BExp.not g)) x
        rw [doubledBody_coreHlt_inl]
        cases hg : bval W g x <;> simp [bval, hg]
    | inr v =>
        cases v with
        | inl u => rfl
        | inr z => exact nomatch z
  initStep_eq := fun X W x => by
    show (firstMatch W x
        ((doubledBody g B).initTrans.map (fun t => (BExp.and g t.1, t.2)))).map
        (fun o => (o.1, cycMap o.2))
      = firstMatch W x (B.initTrans.map (fun t => (BExp.and g t.1, t.2)))
    rw [firstMatch_map_guard, firstMatch_map_guard]
    cases hg : bval W g x
    · simp
    · simpa using doubledBody_initStep g B W x
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        show (firstMatch W x
            ((doubledBody g B).core.trans (Sum.inl u) ++
              (doubledBody g B).initTrans.map (fun t =>
                (BExp.and ((doubledBody g B).core.hlt (Sum.inl u)) (BExp.and g t.1), t.2)))).map
            (fun o => (o.1, cycMap o.2))
          = firstMatch W x (B.core.trans u ++
              B.initTrans.map (fun t =>
                (BExp.and (B.core.hlt u) (BExp.and g t.1), t.2)))
        rw [doubledBody_coreTrans_inl, doubledBody_coreHlt_inl, List.append_assoc]
        cases hc : firstMatch W x (B.core.trans u) with
        | some o =>
            have hP : firstMatch W x
                ((B.core.trans u).map (fun t =>
                  (t.1, t.2.1, (Sum.inl t.2.2 : Sum S (Sum S Empty)))))
                = some (o.1, Sum.inl o.2) := by
              rw [firstMatch_map_target_to, hc]; rfl
            rw [firstMatch_append_some _ _ _ _ hP, firstMatch_append_some _ _ _ _ hc]
            rfl
        | none =>
            have hP : firstMatch W x
                ((B.core.trans u).map (fun t =>
                  (t.1, t.2.1, (Sum.inl t.2.2 : Sum S (Sum S Empty)))))
                = none := by
              rw [firstMatch_map_target_to, hc]; rfl
            rw [firstMatch_append_none _ _ _ _ hP, firstMatch_append_none _ _ _ _ hc]
            have hand : ∀ P Q : BExp T,
                bval W (BExp.and P Q) x = (bval W P x && bval W Q x) := fun _ _ => rfl
            have hP2 := fmGuard2To (A := A) W x (B.core.hlt u) g
              (fun v : S => (Sum.inr (Sum.inl v) : Sum S (Sum S Empty))) B.initTrans
            have hP3 := fmGuard2 (A := A) W x
              (BExp.and (B.core.hlt u)
                (BExp.or (BExp.and g B.initHlt) (BExp.and (BExp.not g) BExp.one)))
              g (doubledBody g B).initTrans
            have hQ2 := fmGuard2 (A := A) W x (B.core.hlt u) g B.initTrans
            -- the second body copy fires exactly when the loop's own re-entry would
            have hP2some : ∀ o, firstMatch W x B.initTrans = some o →
                bval W (B.core.hlt u) x = true → bval W g x = true →
                firstMatch W x (B.initTrans.map (fun t =>
                  (BExp.and (B.core.hlt u) (BExp.and g t.1), t.2.1,
                    (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty)))))
                  = some (o.1, Sum.inr (Sum.inl o.2)) := by
              intro o ho hh' hg'
              rw [hP2, ho, hh', hg']; simp
            have hP2none : bval W (B.core.hlt u) x = false ∨ bval W g x = false ∨
                firstMatch W x B.initTrans = none →
                firstMatch W x (B.initTrans.map (fun t =>
                  (BExp.and (B.core.hlt u) (BExp.and g t.1), t.2.1,
                    (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty))))) = none := by
              intro h
              rw [hP2]
              rcases h with h | h | h <;> simp [h]
            -- the loop's own re-entry block never fires when the copy has not: its guard
            -- refines the copy's by the extra conjunct `(doubledBody g B).initHlt`
            have hP3none : bval W (B.core.hlt u) x = false ∨ bval W g x = false ∨
                firstMatch W x B.initTrans = none →
                firstMatch W x ((doubledBody g B).initTrans.map (fun t =>
                  (BExp.and (BExp.and (B.core.hlt u)
                    (BExp.or (BExp.and g B.initHlt) (BExp.and (BExp.not g) BExp.one)))
                    (BExp.and g t.1), t.2))) = none := by
              intro h
              rw [hP3]
              rcases h with h | h | h
              · simp [hand, h]
              · simp [h]
              · rw [doubledBody_initStep_none g B W x h]; simp
            cases hh : bval W (B.core.hlt u) x
            · rw [firstMatch_append_none _ _ _ _ (hP2none (Or.inl hh)),
                hP3none (Or.inl hh)]
              simp [hQ2, hh]
            · cases hg : bval W g x
              · rw [firstMatch_append_none _ _ _ _ (hP2none (Or.inr (Or.inl hg))),
                  hP3none (Or.inr (Or.inl hg))]
                simp [hQ2, hg]
              · cases hb : firstMatch W x B.initTrans with
                | some o =>
                    rw [firstMatch_append_some _ _ _ _ (hP2some o hb hh hg)]
                    simp [hQ2, hh, hg, hb, cycMap]
                | none =>
                    rw [firstMatch_append_none _ _ _ _ (hP2none (Or.inr (Or.inr hb))),
                      hP3none (Or.inr (Or.inr hb))]
                    simp [hQ2, hb]
    | inr v =>
        cases v with
        | inl u =>
            show (firstMatch W x
                ((doubledBody g B).core.trans (Sum.inr (Sum.inl u)) ++
                  (doubledBody g B).initTrans.map (fun t =>
                    (BExp.and ((doubledBody g B).core.hlt (Sum.inr (Sum.inl u)))
                      (BExp.and g t.1), t.2)))).map
                (fun o => (o.1, cycMap o.2))
              = firstMatch W x (B.core.trans u ++
                  B.initTrans.map (fun t =>
                    (BExp.and (B.core.hlt u) (BExp.and g t.1), t.2)))
            rw [doubledBody_coreTrans_inr, doubledBody_coreHlt_inr]
            cases hc : firstMatch W x (B.core.trans u) with
            | some o =>
                have hP : firstMatch W x
                    ((B.core.trans u).map (fun t =>
                      (t.1, t.2.1, (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty)))))
                    = some (o.1, Sum.inr (Sum.inl o.2)) := by
                  rw [firstMatch_map_target_to
                    (F := fun v : S => (Sum.inr (Sum.inl v) : Sum S (Sum S Empty))), hc]
                  rfl
                rw [firstMatch_append_some _ _ _ _ hP, firstMatch_append_some _ _ _ _ hc]
                rfl
            | none =>
                have hP : firstMatch W x
                    ((B.core.trans u).map (fun t =>
                      (t.1, t.2.1, (Sum.inr (Sum.inl t.2.2) : Sum S (Sum S Empty)))))
                    = none := by
                  rw [firstMatch_map_target_to
                    (F := fun v : S => (Sum.inr (Sum.inl v) : Sum S (Sum S Empty))), hc]
                  rfl
                rw [firstMatch_append_none _ _ _ _ hP, firstMatch_append_none _ _ _ _ hc,
                  fmGuard2, fmGuard2]
                cases hh : bval W (B.core.hlt u) x
                · simp
                · cases hg : bval W g x
                  · simp
                  · simpa using doubledBody_initStep g B W x
        | inr z => exact nomatch z
  maps := by
    intro s hs
    show cycMap s ∈ B.core.states
    have hs : s ∈ (doubledBody g B).core.states := hs
    rw [doubledBody_states] at hs
    cases s with
    | inl u =>
        rcases List.mem_append.mp hs with h | h
        · obtain ⟨y, hy, hye⟩ := List.mem_map.mp h; cases hye; exact hy
        · obtain ⟨y, _, hye⟩ := List.mem_map.mp h; exact absurd hye (by simp)
    | inr v =>
        cases v with
        | inl u =>
            rcases List.mem_append.mp hs with h | h
            · obtain ⟨y, _, hye⟩ := List.mem_map.mp h; exact absurd hye (by simp)
            · obtain ⟨y, hy, hye⟩ := List.mem_map.mp h
              have : y = u := by injection hye with h1; injection h1
              exact this ▸ hy
        | inr z => exact nomatch z
  onto := by
    intro q hq
    refine ⟨Sum.inl q, ?_, rfl⟩
    show (Sum.inl q : Sum S (Sum S Empty)) ∈ (doubledBody g B).core.states
    rw [doubledBody_states]
    exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨q, hq, rfl⟩))

/-! ## The fork, closed for the doubling class -/

/-- **`CommonCoveredIntermediate`, discharged for every loop/doubledBody-loop pair.**  The
    doubledBody program's own automaton covers the loop's by `cyclicCover`, and is solvable
    because it is syntax-generated.  Like `fork_closed_for_unrolling` this is not
    hypothesis-bound: it holds for every guard and body. -/
theorem fork_closed_for_doubling (g : BExp T) (e : Exp A T) :
    ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid (certifiedThompson A T (.wh g e)).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T
        (.wh g (.seq e (.ite g e (.test BExp.one))))).aut) ∧
      HasThompsonCover mid :=
  ⟨(certifiedThompson A T (.wh g (.seq e (.ite g e (.test BExp.one))))).State,
    (certifiedThompson A T (.wh g (.seq e (.ite g e (.test BExp.one))))).aut,
    ⟨cyclicCover g (certifiedThompson A T e).aut⟩,
    ⟨InitCover.id _⟩,
    ⟨.wh g (.seq e (.ite g e (.test BExp.one))), ⟨InitCover.id _⟩⟩⟩

/-- **Loop doubling is a theorem of the finite axioms.**

        while g do e  ≡  while g do (e ; if g then e else 1)

    for arbitrary guard and body, with **no uniqueness axiom**.

    This settles the question the search raised.  Attempting the identity by hand from W1
    stalls: unrolling both sides reduces it to identifying two solutions of one guarded
    system, which is what UA does.  The cover route avoids that step entirely — the doubledBody
    automaton *covers* the loop's, so the loop's canonical labelling lifts to a solution of
    the doubled system, and Thompson uniqueness (a theorem about syntax-generated automata,
    not an axiom) makes that lifted solution provably canonical pointwise.

    So the refinement move the search found to be missing is sound *and* derivable, and
    using it to build common refinements is not circular. -/
theorem loop_doubling_provable (g : BExp T) (e : Exp A T) :
    EquivBA (.wh g e : Exp A T) (.wh g (.seq e (.ite g e (.test BExp.one)))) :=
  equivBA_of_common_refinement
    (InitCover.id (certifiedThompson A T (.wh g (.seq e (.ite g e (.test BExp.one))))).aut)
    (cyclicCover g (certifiedThompson A T e).aut)
    (InitCover.id _)

#print axioms cyclicCover
#print axioms fork_closed_for_doubling
#print axioms loop_doubling_provable

end GkatCyclicCover
