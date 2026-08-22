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

/-! ## `seq` and `wh`

    Completing the classification.  `seq` is half as good as `ite`: its *right* component
    inherits everything, but its left component's halt guard is conjoined with `Q.initHlt`
    and it gains exit edges, so left states can newly die.  `wh` is worse than both — no
    state inherits, because every body state's halt is weakened by `¬g`, and unlike `ite` the
    damage is *not* repaired by non-nullity. -/

/-- The right component of a sequence inherits its runs unchanged. -/
private theorem run_seq_inr {S₁ S₂ X : Type} (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (W : T → X → Bool) :
    ∀ (u : S₂) (x : X) (w : List (A × X)),
      autRun W Q.toGAut (some u) x w →
      autRun W (seqInitialized P Q).toGAut (some (Sum.inr u)) x w := by
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

/-- **A sequence's right component keeps its productivity.**  Only the left component and the
    pseudostate can newly die, which is what `seq_dead_not_productive` exhibits. -/
theorem productive_seq_right {S₁ S₂ : Type} (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (hq : Productive Q) {X : Type} (W : T → X → Bool)
    (x : X) (u : S₂) :
    ∃ (x' : X) (w : List (A × X)),
      autRun W (seqInitialized P Q).toGAut (some (Sum.inr u)) x' w := by
  obtain ⟨x', w, hw⟩ := hq X W x (some u)
  exact ⟨x', w, run_seq_inr P Q W u x' w hw⟩

/-- **`wh` is strictly worse than `ite`: non-nullity does not repair it.**

    `while b do (a ; 0)` is non-null — it halts at every `¬b` atom straight from the
    pseudostate — yet its body state is dead.  Its halt guard is `(1 ∧ 0) ∧ ¬b`, which is
    never satisfied, and its only transition is the back edge, guarded by the same `1 ∧ 0`.

    So for `ite`, productivity was repairable by a hypothesis already in hand
    (`productive_ite`); for `wh` there is no such hypothesis.  The dead region has to be
    pruned before the loop is built, not after. -/
theorem wh_dead_body_not_productive :
    ¬ Productive (certifiedThompson Unit Unit
        (.wh (.prim ()) (.seq (.act ()) (.test .zero)))).aut := by
  intro h
  obtain ⟨x, w, hw⟩ := h Unit (fun _ _ => true) () (some (Sum.inl ()))
  cases w with
  | nil =>
      have hb : bval (fun _ (_ : Unit) => true)
          (BExp.and (BExp.and BExp.one BExp.zero) (BExp.not (BExp.prim ()))) x = true := hw
      exact absurd hb (by simp [bval])
  | cons hd tl =>
      obtain ⟨s', hstep, _⟩ := hw
      have hn : autStep (fun _ (_ : Unit) => true)
          (certifiedThompson Unit Unit
            (.wh (.prim ()) (.seq (.act ()) (.test .zero)))).aut.toGAut
          (some (Sum.inl ())) x = none := rfl
      exact absurd (hn.symm.trans hstep) (by simp)

/-! ## The duality

    `Reachable` is a **forward** analysis and `Productive` a **backward** one — reachability
    asks what the pseudostate can get to, productivity what can still get to a halt.  The
    classification above should therefore mirror itself across `seq`, and it does:

      productivity (backward) — the **right** component inherits, the left can die;
      reachability  (forward) — the **left** component inherits, the right can become
                                unreachable when `P` never halts.

    That is why the two prunings sit at different points in the recursion, which was an
    empirical observation two steps ago and is now the expected consequence of the direction
    each analysis runs in. -/

private theorem seq_initTrans {S₁ S₂ : Type} (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) :
    (seqInitialized P Q).initTrans =
      P.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂))) ++
      Q.initTrans.map (fun t =>
        (BExp.and P.initHlt t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂))) := rfl

private theorem seq_coreTrans_inl {S₁ S₂ : Type} (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (s : S₁) :
    (seqInitialized P Q).core.trans (Sum.inl s) =
      (P.core.trans s).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂))) ++
      Q.initTrans.map (fun t =>
        (BExp.and (P.core.hlt s) t.1, t.2.1, (Sum.inr t.2.2 : Sum S₁ S₂))) := rfl

/-- A step of the left component lifts to a step of the sequence.  The left block of the
    transition list comes first, so whenever `P` fires the sequence follows it. -/
private theorem step_seq_inl {S₁ S₂ X : Type} (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (W : T → X → Bool) (x : X) {p q : Option S₁} {c : A}
    (h : autStep W P.toGAut p x = some (c, q)) :
    autStep W (seqInitialized P Q).toGAut (p.map Sum.inl) x = some (c, q.map Sum.inl) := by
  cases p with
  | none =>
      rw [GkatQuotient.autStep_init] at h
      cases hf : firstMatch W x P.initTrans with
      | none => rw [hf] at h; exact absurd h (by simp)
      | some o =>
          rw [hf] at h
          simp only [Option.map_some] at h
          have hpair := Option.some.inj h
          have hc : o.1 = c := congrArg (fun z : A × Option S₁ => z.1) hpair
          have hq : (some o.2 : Option S₁) = q := congrArg (fun z : A × Option S₁ => z.2) hpair
          show autStep W (seqInitialized P Q).toGAut none x = some (c, q.map Sum.inl)
          rw [GkatQuotient.autStep_init, seq_initTrans]
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum S₁ S₂))) _ _ _ _
            (by rw [firstMatch_map_target_to
              (F := fun v : S₁ => (Sum.inl v : Sum S₁ S₂)), hf]; rfl)]
          rw [← hq, ← hc]; rfl
  | some s =>
      rw [GkatQuotient.autStep_core] at h
      cases hf : firstMatch W x (P.core.trans s) with
      | none => rw [hf] at h; exact absurd h (by simp)
      | some o =>
          rw [hf] at h
          simp only [Option.map_some] at h
          have hpair := Option.some.inj h
          have hc : o.1 = c := congrArg (fun z : A × Option S₁ => z.1) hpair
          have hq : (some o.2 : Option S₁) = q := congrArg (fun z : A × Option S₁ => z.2) hpair
          show autStep W (seqInitialized P Q).toGAut (some (Sum.inl s)) x
            = some (c, q.map Sum.inl)
          rw [GkatQuotient.autStep_core, seq_coreTrans_inl]
          rw [firstMatch_append_some (x := (o.1, (Sum.inl o.2 : Sum S₁ S₂))) _ _ _ _
            (by rw [firstMatch_map_target_to
              (F := fun v : S₁ => (Sum.inl v : Sum S₁ S₂)), hf]; rfl)]
          rw [← hq, ← hc]; rfl

/-- **A sequence's left component keeps its reachability** — the dual of
    `productive_seq_right`.  Forward analysis flows left to right, so the leftmost component
    is the one nothing upstream can disturb. -/
theorem reaches_seq_inl {S₁ S₂ : Type} (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) {u : Option S₁} (h : Reaches P u) :
    Reaches (seqInitialized P Q) (u.map Sum.inl) := by
  induction h with
  | start => exact Reaches.start
  | @step p q X W x c _ hstep ih => exact Reaches.step ih (step_seq_inl P Q W x hstep)

/-! ## Guards live only at entries

    The Thompson construction here is the guarded form of a Glushkov position automaton: one
    core state per action occurrence, a single pseudostate playing Glushkov's `q₀`, and the
    guards attached to the *entry* edges — `initTrans` is the guarded `First` set.

    That pins down where reachability can be obstructed, and it is only three places:

      `ite` guards the **entry** to each branch (`g`, `¬g`);
      `seq` guards the **junction** into the right component (by the left's halt);
      `wh`  guards the **back edge** (by `g`).

    Nowhere else does a constructor add a guard — a component's own core transitions are
    carried across untouched.  The two lemmas below are that fact for `ite` and `wh`; the
    `seq` case is the first block of `step_seq_inl` above. -/

/-- A core step of a branch lifts to the conditional unchanged — `ite` guards only the
    entry. -/
theorem step_ite_inl {S₁ S₂ X : Type} (g : BExp T) (P : InitializedGAut S₁ A T)
    (Q : InitializedGAut S₂ A T) (W : T → X → Bool) (x : X) {s : S₁} {c : A} {q : Option S₁}
    (h : autStep W P.toGAut (some s) x = some (c, q)) :
    autStep W (iteInitialized g P Q).toGAut (some (Sum.inl s)) x = some (c, q.map Sum.inl) := by
  rw [GkatQuotient.autStep_core] at h
  cases hf : firstMatch W x (P.core.trans s) with
  | none => rw [hf] at h; exact absurd h (by simp)
  | some o =>
      rw [hf] at h
      simp only [Option.map_some] at h
      have hpair := Option.some.inj h
      have hc : o.1 = c := congrArg (fun z : A × Option S₁ => z.1) hpair
      have hq : (some o.2 : Option S₁) = q := congrArg (fun z : A × Option S₁ => z.2) hpair
      show autStep W (iteInitialized g P Q).toGAut (some (Sum.inl s)) x
        = some (c, q.map Sum.inl)
      rw [GkatQuotient.autStep_core]
      show (firstMatch W x ((P.core.trans s).map
          (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Sum S₁ S₂))))).map
        (fun o => (o.1, some o.2)) = some (c, q.map Sum.inl)
      rw [firstMatch_map_target_to (F := fun v : S₁ => (Sum.inl v : Sum S₁ S₂)), hf,
        ← hq, ← hc]
      rfl

/-- A core step of the body lifts to the loop unchanged — `wh` guards only the back edge.
    Here the state type is preserved, so the step is literally the same one. -/
theorem step_wh_body {S : Type} {X : Type} (g : BExp T) (B : InitializedGAut S A T)
    (W : T → X → Bool) (x : X) {s : S} {c : A} {q : Option S}
    (h : autStep W B.toGAut (some s) x = some (c, q)) :
    autStep W (loopInitialized g B).toGAut (some s) x = some (c, q) := by
  rw [GkatQuotient.autStep_core] at h ⊢
  show (firstMatch W x (B.core.trans s ++
      B.initTrans.map (fun t =>
        (BExp.and (B.core.hlt s) (BExp.and g t.1), t.2)))).map
    (fun o => (o.1, some o.2)) = some (c, q)
  cases hf : firstMatch W x (B.core.trans s) with
  | none => rw [hf] at h; exact absurd h (by simp)
  | some o => rw [firstMatch_append_some _ _ _ _ hf, ← hf]; exact h

/-! ## `Normalizable` is false a third time, and structurally

    `while p do a` is an ordinary program — non-null, no dead subterm, nothing to prune — and
    it is **not productive**.  Under the all-true interpretation the guard never fails, so the
    loop never exits, its body state loops forever and accepts nothing.

    That is not a definitional slip like the previous two.  `Productive` quantifies over
    *every* interpretation, and no amount of rewriting the program can make a loop terminate
    under an interpretation that keeps its guard true.  So `Normalizable` cannot hold, and the
    fault is in requiring productivity uniformly.

    What `crossEquiv_step` actually needs is productivity at the *one* interpretation where
    the step occurs.  Relativising it there is the repair, and it is a restructuring of
    `Matched` and `NormalCommonTarget` rather than a lemma — `Reaches` uses a different
    interpretation at every step, so the hypothesis has to be threaded rather than assumed
    once. -/

/-- **The witness.**  No pruning repairs this: the program is already in any reasonable normal
    form, and the deadness is created by the interpretation, not by the syntax. -/
theorem wh_simple_not_productive :
    ¬ Productive (certifiedThompson Unit Unit (.wh (.prim ()) (.act ()))).aut := by
  intro h
  obtain ⟨x, w, hw⟩ := h Unit (fun _ _ => true) () (some ())
  induction w generalizing x with
  | nil =>
      have hb : bval (fun _ (_ : Unit) => true)
          (BExp.and BExp.one (BExp.not (BExp.prim ()))) x = true := hw
      exact absurd hb (by simp [bval])
  | cons hd tl ih =>
      obtain ⟨s', hstep, hrun⟩ := hw
      have hfix : autStep (fun _ (_ : Unit) => true)
          (certifiedThompson Unit Unit (.wh (.prim ()) (.act ()))).aut.toGAut (some ()) x
          = some ((), some ()) := rfl
      have hpair := Option.some.inj (hfix.symm.trans hstep)
      have hs : s' = some () :=
        (congrArg (fun z : Unit × Option Unit => z.2) hpair).symm
      exact ih hd.2 (hs ▸ hrun)

/-! ## What productivity was standing in for

    Classically, bisimilarity coincides with language equivalence for deterministic automata
    **with a complete transition function**.  GKAT automata are deterministic but *partial* —
    a state may neither halt nor step at an atom — and that partiality is precisely where the
    `0` versus `a ; 0` counterexample lives.  So the condition the development wants is
    totality, not productivity.

    The lemma below is that classical fact in the form the step argument needs, and it makes
    the roles explicit: `a`'s halts and steps are disjoint (automatic for a Thompson
    automaton, `CoreStructural.disjoint`), `b` is total, and the two agree on halting — then
    they agree on stepping, with no productivity anywhere.

    This does not by itself rescue `Normalizable`.  `b?` is not total either: at a `¬b` atom
    its pseudostate neither halts nor steps.  What it does is separate two things that
    `Productive` had conflated — the *structural* requirement (disjointness, free) from the
    *semantic* one (totality) — and show the semantic half is the classical condition rather
    than an invention of mine. -/

/-- No state both halts and steps at the same atom.  Automatic for Thompson automata. -/
def HaltStepDisjoint {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X) (s : Option S),
    bval W (aut.toGAut.hlt s) x = true → autStep W aut.toGAut s x = none

/-- Every state, at every atom, either halts or steps — the transition function is complete. -/
def Total {S : Type} (aut : InitializedGAut S A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X) (s : Option S),
    bval W (aut.toGAut.hlt s) x = true ∨ (autStep W aut.toGAut s x).isSome = true

/-- **Totality replaces productivity.**  If `b` is total and the two agree on halting, then
    `a` stepping forces `b` to step — which is all `crossEquiv_step` ever wanted.  The proof
    is the classical one: `b` must halt or step; if it halts then so does `a`, and `a`'s
    halts are disjoint from its steps, contradicting the step we started from. -/
theorem step_agree_of_total {S₁ S₂ : Type} {a : InitializedGAut S₁ A T}
    {b : InitializedGAut S₂ A T} (hd : HaltStepDisjoint a) (htb : Total b)
    {s : Option S₁} {t : Option S₂} (h : CrossEquiv a b s t)
    {X : Type} (W : T → X → Bool) (x : X) {q : A} {s' : Option S₁}
    (hs : autStep W a.toGAut s x = some (q, s')) :
    (autStep W b.toGAut t x).isSome = true := by
  rcases htb X W x t with hh | hstep
  · have ha : bval W (a.toGAut.hlt s) x = true := (crossEquiv_hlt h X W x).trans hh
    have hnone := hd X W x s ha
    rw [hs] at hnone
    exact absurd hnone (by simp)
  · exact hstep

/-! ## The sink exists

    Totalising a partial automaton means adding a sink and routing every undefined transition
    into it; the construction preserves the language, which is why it is the standard repair.
    In GKAT the sink cannot be a state one merely adds — it has to be *expressible*, and it
    has to be provably `0`, or routing into it would not preserve provable equality.

    `while 1 do e` is that sink, for **any** body.  `InLoop` is an inductive whose only base
    case is `exit`, which demands the guard be false; with guard `1` that case is unavailable,
    so no derivation exists at all and the language is empty.  `nullLanguage_complete` then
    makes it provably `0`.

    And its automaton is total: nothing ever halts (every halt guard carries `¬1`), and every
    state steps (the back edge is guarded by `1`).  So a stuck configuration can be replaced
    by a divergent one, provably, and the result is total exactly where the original was
    stuck. -/

/-- A loop with a tautologous guard has no derivations: the only base case demands the guard
    be false. -/
theorem inLoop_one_empty {X : Type} {W : T → X → Bool} {P : GS A X → Prop} {gs : GS A X}
    (h : InLoop W BExp.one P gs) : False := by
  induction h with
  | exit a hb => exact absurd hb (by simp [bval])
  | step a l1 rest hb hbody hrec ih => exact ih

/-- **`while 1 do e` is null, for every body.** -/
theorem wh_one_empty (e : Exp A T) : UniformExpLempty (.wh BExp.one e) :=
  fun _ _ _ h => inLoop_one_empty h

/-- **…and provably `0`.**  So routing a stuck configuration into it preserves provable
    equality, which is what makes it usable as a sink rather than merely a semantic one. -/
theorem wh_one_provably_zero (e : Exp A T) :
    EquivBA (.wh BExp.one e : Exp A T) (.test .zero) :=
  GkatNullLanguage.nullLanguage_complete _ (wh_one_empty e)

/-- **…and total.**  Nothing halts, since every halt guard carries `¬1`; and everything
    steps, since the back edge is guarded by `1`. -/
theorem wh_one_total (a : A) :
    Total (certifiedThompson A T (.wh BExp.one (.act a))).aut := by
  intro X W x s
  right
  cases s with
  | none => rfl
  | some u => cases u; rfl

#print axioms wh_one_empty
#print axioms wh_one_provably_zero
#print axioms wh_one_total
#print axioms step_agree_of_total
#print axioms wh_simple_not_productive
#print axioms step_ite_inl
#print axioms step_wh_body
#print axioms reaches_seq_inl
#print axioms productive_seq_right
#print axioms wh_dead_body_not_productive
#print axioms productive_ite
#print axioms act_normal
#print axioms seq_dead_not_productive
#print axioms ite_taut_not_reachable

end GkatNormal
