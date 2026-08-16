import GkatRefinesProofs
import GkatQuotientProofs

/-!
# Normal form: non-vacuity, and exactly which constructor breaks which half

`Normalizable` is the last unstarted link in the chain.  Before attempting it, two things
have to be established, and the previous commit is why: `Productive` and `Reachable` had only
ever appeared as *hypotheses*, so nothing had ever been required to satisfy them, and both
turned out to be wrong when something finally had to.

So this file does the check first.  `act_normal` exhibits a program in normal form, which is
the non-vacuity the definitions never had.  Then the two failure lemmas map the obstruction
precisely: normality is *not* preserved by the constructors, and the two halves break in
different places.

## What breaks where

  * `seq` breaks **productivity**.  `a ; 0` has a core state — the one for `a` — from which
    nothing is ever accepted, at any atom.  Sequencing a live program with a dead one makes
    the live part dead.
  * `ite` breaks **reachability**.  `if 1 then p else q` never enters `q`, so every state of
    `q` is unreachable, however well-behaved `q` is on its own.

Both are exactly the two prunings a normalization procedure has to perform — dead regions to
`0`, unreachable branches away under `ite_of_taut` / `ite_of_unsat` — which is why the
construction cannot be a straightforward structural induction: the induction hypothesis is
destroyed by the very constructors it has to traverse.
-/

namespace GkatNormal

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCommonTarget

variable {A T : Type}

/-! ## Non-vacuity -/

/-- **A single action is in normal form.**  Its one core state halts at every atom, so
    nothing is dead; and it is entered from the pseudostate, so nothing is unreachable.

    Small, but it is the first thing in the development that *satisfies* `Normal` rather than
    assuming it. -/
theorem act_normal (a : A) : Normal (certifiedThompson A T (.act a)).aut := by
  constructor
  · intro X W x s
    cases s with
    | none =>
        refine ⟨x, [(a, x)], ?_⟩
        refine ⟨some (), ?_, ?_⟩
        · show firstMatch W x
            ([(BExp.one, a, ())].map (fun t => (t.1, t.2.1, some t.2.2))) = some (a, some ())
          rfl
        · show bval W BExp.one x = true
          rfl
    | some u =>
        refine ⟨x, [], ?_⟩
        show bval W ((certifiedThompson A T (.act a)).aut.core.hlt u) x = true
        cases u
        rfl
  · intro s
    cases s
    refine Reaches.step (W := fun _ (_ : Unit) => true) (x := ()) (q := a) Reaches.start ?_
    show firstMatch (fun _ (_ : Unit) => true) ()
      ([(BExp.one, a, ())].map (fun t => (t.1, t.2.1, some t.2.2))) = some (a, some ())
    rfl

/-! ## Where the constructors break it -/

/-- **`seq` destroys productivity.**  The core state of `a` in `a ; 0` accepts nothing at any
    atom: it halts only where `0` does, which is nowhere, and its only transition leads into
    `0`, which has no states at all.

    So productivity is not preserved by sequencing, and a normalization procedure must prune
    the dead region rather than recurse past it. -/
theorem seq_dead_not_productive (a : A) :
    ¬ Productive (certifiedThompson Unit Unit
        (.seq (.act ()) (.test .zero))).aut := by
  intro h
  obtain ⟨x, w, hw⟩ := h Unit (fun _ _ => true) () (some (Sum.inl ()))
  cases w with
  | nil =>
      -- the state halts only where `0` does, which is nowhere
      have hb : bval (fun _ (_ : Unit) => true) (BExp.and BExp.one BExp.zero) x = true := hw
      exact absurd hb (by simp [bval])
  | cons hd tl =>
      -- and it has no transitions at all: `0` contributes no entry edges
      obtain ⟨s', hstep, _⟩ := hw
      have hn : autStep (fun _ (_ : Unit) => true)
          (certifiedThompson Unit Unit ((Exp.act ()).seq (Exp.test BExp.zero))).aut.toGAut
          (some (Sum.inl ())) x = none := rfl
      rw [hn] at hstep
      exact absurd hstep (by simp)

/-- Under a tautologous guard, nothing ever leaves the first branch. -/
private theorem ite_taut_inv {u : Option (Sum Unit Unit)}
    (h : Reaches (certifiedThompson Unit Unit (.ite .one (.act ()) (.act ()))).aut u) :
    u = none ∨ u = some (Sum.inl ()) := by
  induction h with
  | start => exact Or.inl rfl
  | @step p q X W x c _ hstep ih =>
      rcases ih with rfl | rfl
      · right
        have hfix : autStep W
            (certifiedThompson Unit Unit (.ite .one (.act ()) (.act ()))).aut.toGAut none x
            = some ((), some (Sum.inl ())) := rfl
        have heq := Option.some.inj (hstep.symm.trans hfix)
        exact congrArg (fun z : Unit × Option (Sum Unit Unit) => z.2) heq
      · have hn : autStep W
            (certifiedThompson Unit Unit (.ite .one (.act ()) (.act ()))).aut.toGAut
            (some (Sum.inl ())) x = none := rfl
        exact absurd (hn.symm.trans hstep) (by simp)

/-- **`ite` destroys reachability.**  Under a tautologous guard the second branch is never
    entered, so its states are unreachable however well-behaved that branch is on its own.

    Together with `seq_dead_not_productive` this is why normalization cannot be a plain
    structural induction: each half of `Normal` is destroyed by a different constructor, so
    the induction hypothesis does not survive the traversal.  The two prunings — dead regions
    to `0`, unreachable branches away under `ite_of_taut` — are exactly the repairs. -/
theorem ite_taut_not_reachable :
    ¬ Reachable (certifiedThompson Unit Unit (.ite .one (.act ()) (.act ()))).aut := by
  intro h
  rcases ite_taut_inv (h (Sum.inr ())) with hc | hc
  · exact absurd hc (by simp)
  · -- `(certifiedThompson _).State` does not unfold at reducible transparency, so `simp`
    -- cannot see the `Sum` structure; discriminate with an explicit function instead
    have hd : (true = false) :=
      congrArg (fun o : Option (Sum Unit Unit) =>
        match o with | some (Sum.inr _) => true | _ => false) hc
    exact absurd hd (by simp)

/-! ## What `ite` *does* preserve

    The obstruction lemmas say normality is not an invariant of the recursion.  But the two
    halves fail for different and locatable reasons, and pinning down what survives is what a
    normalization procedure gets to rely on.

    For `ite`, productivity fails only at the **pseudostate** — the core states inherit their
    halt guards and transitions unchanged, so a dead state in the composite was already dead
    in its branch.  And pseudostate productivity is exactly non-nullity, which `Normalizable`
    assumes anyway.  So `ite` preserves productivity *given* the hypothesis already in hand. -/

/-- A run inside the left branch lifts to a run of the conditional. -/
private theorem run_inl {S₁ S₂ X : Type} (g : BExp T) (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (W : T → X → Bool) :
    ∀ (u : S₁) (x : X) (w : List (A × X)),
      autRun W P.toGAut (some u) x w →
      autRun W (iteInitialized g P Q).toGAut (some (Sum.inl u)) x w := by
  intro u x w
  induction w generalizing u x with
  | nil => exact fun h => h
  | cons hd tl ih =>
      obtain ⟨q, x'⟩ := hd
      rintro ⟨s', hstep, hrun⟩
      obtain ⟨v, rfl⟩ := GkatQuotient.step_target_some P W (some u) x hstep
      refine ⟨some (Sum.inl v), ?_, ih v x' hrun⟩
      rw [GkatQuotient.autStep_core] at hstep ⊢
      show (firstMatch W x ((iteInitialized g P Q).core.trans (Sum.inl u))).map
        (fun o => (o.1, some o.2)) = some (q, some (Sum.inl v))
      show (firstMatch W x ((P.core.trans u).map
          (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂))))).map
        (fun o => (o.1, some o.2)) = some (q, some (Sum.inl v))
      rw [firstMatch_map_target_to (F := fun v : S₁ => (Sum.inl v : Sum S₁ S₂))]
      cases hf : firstMatch W x (P.core.trans u) with
      | none => rw [hf] at hstep; exact absurd hstep (by simp)
      | some o =>
          rw [hf] at hstep
          have := Option.some.inj hstep
          simp only [Option.map_some]
          have h1 : o.1 = q := congrArg (fun z : A × Option S₁ => z.1) this
          have h2 : (some o.2 : Option S₁) = some v :=
            congrArg (fun z : A × Option S₁ => z.2) this
          rw [h1, Option.some.inj h2]

/-- A run inside the right branch lifts likewise. -/
private theorem run_inr {S₁ S₂ X : Type} (g : BExp T) (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (W : T → X → Bool) :
    ∀ (u : S₂) (x : X) (w : List (A × X)),
      autRun W Q.toGAut (some u) x w →
      autRun W (iteInitialized g P Q).toGAut (some (Sum.inr u)) x w := by
  intro u x w
  induction w generalizing u x with
  | nil => exact fun h => h
  | cons hd tl ih =>
      obtain ⟨q, x'⟩ := hd
      rintro ⟨s', hstep, hrun⟩
      obtain ⟨v, rfl⟩ := GkatQuotient.step_target_some Q W (some u) x hstep
      refine ⟨some (Sum.inr v), ?_, ih v x' hrun⟩
      rw [GkatQuotient.autStep_core] at hstep ⊢
      show (firstMatch W x ((Q.core.trans u).map
          (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂))))).map
        (fun o => (o.1, some o.2)) = some (q, some (Sum.inr v))
      rw [firstMatch_map_target_to (F := fun v : S₂ => (Sum.inr v : Sum S₁ S₂))]
      cases hf : firstMatch W x (Q.core.trans u) with
      | none => rw [hf] at hstep; exact absurd hstep (by simp)
      | some o =>
          rw [hf] at hstep
          have := Option.some.inj hstep
          simp only [Option.map_some]
          have h1 : o.1 = q := congrArg (fun z : A × Option S₂ => z.1) this
          have h2 : (some o.2 : Option S₂) = some v :=
            congrArg (fun z : A × Option S₂ => z.2) this
          rw [h1, Option.some.inj h2]

/-- **`ite` preserves productivity, given non-nullity.**  Every dead state of `if g then P
    else Q` is a dead state of `P` or of `Q`; the pseudostate is the only new one, and its
    productivity is precisely the non-nullity hypothesis `Normalizable` already carries.

    Contrast `ite_taut_not_reachable`: the *other* half genuinely fails, and no hypothesis of
    this kind repairs it — the branch is unreachable however live it is. -/
theorem productive_ite {S₁ S₂ : Type} (g : BExp T)
    (P : InitializedGAut S₁ A T) (Q : InitializedGAut S₂ A T)
    (hp : Productive P) (hq : Productive Q)
    (hinit : ∀ (X : Type) (W : T → X → Bool) (_ : X),
      ∃ (x' : X) (w : List (A × X)),
        autRun W (iteInitialized g P Q).toGAut none x' w) :
    Productive (iteInitialized g P Q) := by
  intro X W x s
  cases s with
  | none => exact hinit X W x
  | some v =>
      cases v with
      | inl u =>
          obtain ⟨x', w, hw⟩ := hp X W x (some u)
          exact ⟨x', w, run_inl g P Q W u x' w hw⟩
      | inr u =>
          obtain ⟨x', w, hw⟩ := hq X W x (some u)
          exact ⟨x', w, run_inr g P Q W u x' w hw⟩

#print axioms productive_ite
#print axioms act_normal
#print axioms seq_dead_not_productive
#print axioms ite_taut_not_reachable

end GkatNormal
