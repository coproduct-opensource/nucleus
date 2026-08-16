import GkatCyclicKProofs

/-!
# Guard-split duplication refines

The search uses three refinement moves, and all three are now covers in Lean:

  * **W1-unrolling** — `unrollCover`, lengthens the lasso's tail;
  * **degree-`k` cyclic covering** — `cyclicCoverK`, multiplies the cycle length;
  * **guard-split duplication** — here, widens the automaton.

    e   ⇒   if g then e else e

Axiomatically this move is free: `e +_g e ≡ e` is U1, plain idempotence.  What was missing
is the *cover*, and the cover is the thing the synthesis needs — `equivBA_of_cover` runs on
covers, not on equalities, and `labels_agree_of_cover` is why the difference matters.

The map folds the two copies together.  What makes it a cover rather than merely a
bisimulation is the pseudostate: `iteInitialized` guards the left copy's entries by `g` and
the right copy's by `¬g`, so at any atom exactly one block fires and the fold sends it to the
same place the undivided automaton would go.

Stated for an arbitrary system, so it applies to any body and not only to Thompson automata.
-/

namespace GkatDupCover

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis

variable {A T : Type}
variable {S : Type}

private theorem fmGuardTo {R X : Type} (W : T → X → Bool) (x : X) (P : BExp T)
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

/-- Both copies fold onto the original. -/
private def dupMap : Sum S S → S
  | Sum.inl s => s
  | Sum.inr s => s

/-- **Guard-split duplication refines.**  `if g then E else E` covers `E`, for any system. -/
def dupCover (g : BExp T) (E : InitializedGAut S A T) :
    InitCover (iteInitialized g E E) E where
  map := dupMap
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and g E.initHlt) (BExp.and (BExp.not g) E.initHlt)) x
      = bval W E.initHlt x
    cases hg : bval W g x <;> simp [bval, hg]
  coreHlt_eq := fun s _ _ _ => by
    cases s with
    | inl _ => rfl
    | inr _ => rfl
  initStep_eq := fun X W x => by
    show (firstMatch W x
        (E.initTrans.map (fun t => (BExp.and g t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))) ++
         E.initTrans.map (fun t =>
           (BExp.and (BExp.not g) t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
        (fun o => (o.1, dupMap o.2))
      = firstMatch W x E.initTrans
    have hl := fmGuardTo (A := A) W x g (fun s : S => (Sum.inl s : Sum S S)) E.initTrans
    have hr := fmGuardTo (A := A) W x (BExp.not g)
      (fun s : S => (Sum.inr s : Sum S S)) E.initTrans
    have hnot : bval W (BExp.not g) x = !bval W g x := rfl
    cases hg : bval W g x
    · rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg]; simp), hr, hnot, hg]
      cases firstMatch W x E.initTrans <;> simp [dupMap]
    · cases he : firstMatch W x E.initTrans with
      | some o =>
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum S S)))
            _ _ _ _ (by rw [hl, hg, he]; simp)]
          simp [dupMap]
      | none =>
          rw [firstMatch_append_none _ _ _ _ (by rw [hl, hg, he]; simp), hr, hnot, hg]
          simp
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        show (firstMatch W x
            ((E.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S S))))).map
            (fun o => (o.1, dupMap o.2))
          = firstMatch W x (E.core.trans u)
        rw [firstMatch_map_target_to (F := fun s : S => (Sum.inl s : Sum S S))]
        cases firstMatch W x (E.core.trans u) <;> simp [dupMap]
    | inr u =>
        show (firstMatch W x
            ((E.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S S))))).map
            (fun o => (o.1, dupMap o.2))
          = firstMatch W x (E.core.trans u)
        rw [firstMatch_map_target_to (F := fun s : S => (Sum.inr s : Sum S S))]
        cases firstMatch W x (E.core.trans u) <;> simp [dupMap]
  maps := by
    intro s hs
    show dupMap s ∈ E.core.states
    have hs' : s ∈ E.core.states.map (Sum.inl : S → Sum S S) ++
        E.core.states.map (Sum.inr : S → Sum S S) := hs
    rcases List.mem_append.mp hs' with h | h <;>
      · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
        exact hu
  onto := by
    intro q hq
    refine ⟨Sum.inl q, ?_, rfl⟩
    show (Sum.inl q : Sum S S) ∈ E.core.states.map (Sum.inl : S → Sum S S) ++
      E.core.states.map (Sum.inr : S → Sum S S)
    exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨q, hq, rfl⟩))

/-- **The move, as an equality of programs.**  Recovered through the cover rather than from
    U1 — which is the non-vacuity check the other two moves also get. -/
theorem dup_provable (g : BExp T) (e : Exp A T) :
    EquivBA (e : Exp A T) (.ite g e e) :=
  equivBA_of_common_refinement
    (InitCover.id (certifiedThompson A T (.ite g e e)).aut)
    (dupCover g (certifiedThompson A T e).aut)
    (InitCover.id _)

#print axioms dupCover
#print axioms dup_provable

end GkatDupCover
