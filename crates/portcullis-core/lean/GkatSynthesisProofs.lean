import GkatSpanWitnessProofs

/-!
# Phase C, the engine: covers compose along the Thompson constructors

Synthesis has to turn a *system* into an *expression* whose Thompson automaton covers it.
The recursion that does this needs one thing to be true at every step: that assembling
covered pieces yields a covered assembly.  This file proves exactly that, for all three
constructors, over arbitrary initialized systems rather than only Thompson ones.

    seqInitialized  preserves covers
    iteInitialized  preserves covers
    loopInitialized preserves covers

`InitCover` is the pseudostate-preserving cover these need.  The plain
`UniformBehavioralGAutQuotient` is not enough on its own: a cover that merged the initial
pseudostate into a core state could not be pushed through `seq`, whose exit edges are
guarded by the *core* halt of the left component while its initial edges are guarded by the
*initial* halt.  Keeping the two apart is what makes the induction go through, and it is the
same distinction the collapse refutation turns on.

With these, synthesis *is* a structural recursion.  `synth_loop`, `synth_ite` and
`synth_seq` are its three steps, stated in the form the recursion uses — the expression
grows by the same constructor that grows the system — and `InitCover.id` supplies the
leaves.  `InitCover.toQuotient` then feeds the result to `equivBA_of_cover`, which is Phase
C's stated done-when: `equivBA_of_synth`.

Two things are deliberately *not* here.

There is no `synth : System → Exp` taking an arbitrary system, because an arbitrary system
carries no presentation to recurse on; supplying one is the caller's obligation and is
exactly what a decomposition theorem would provide.

And there is no proof that the systems needing synthesis — pullbacks, in the span
formulation — always admit such a presentation.  The B′ search found the pullback is often
but *not always* itself Thompson-shaped (20 of 269 decidable cases were not), so a general
synthesis must sometimes unfold the pullback first, and nothing here bounds that unfolding.
That gap is the honest boundary of Phase C as it now stands.

Axioms: `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatSynthesis

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization

variable {A T : Type}

/-! ## Two `firstMatch` lemmas the constructors need

    The repository already has append, guard-conjunction and target-remapping in isolation;
    the loop needs a doubly-conjoined guard and the sequence needs conjunction and
    remapping at once, across carriers. -/

private theorem firstMatch_guard2 {X S : Type} (W : T → X → Bool) (x : X) (P Q : BExp T)
    (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P (BExp.and Q t.1), t.2))) =
      if bval W P x then (if bval W Q x then firstMatch W x L else none) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> cases hQ : bval W Q x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P (BExp.and Q g)) x
          = (bval W P x && (bval W Q x && bval W g x)) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hQ : bval W Q x <;> cases hg : bval W g x <;>
        simp [hP, hQ, hg]

private theorem firstMatch_guard_to {X S R : Type} (W : T → X → Bool) (x : X) (P : BExp T)
    (F : S → R) (L : List (BExp T × A × S)) :
    firstMatch W x (L.map (fun t => (BExp.and P t.1, t.2.1, F t.2.2))) =
      if bval W P x then (firstMatch W x L).map (fun o => (o.1, F o.2)) else none := by
  induction L with
  | nil => cases hP : bval W P x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and P g) x = (bval W P x && bval W g x) := rfl
      rw [hand, ih]
      cases hP : bval W P x <;> cases hg : bval W g x <;> simp [hP, hg]

/-! ## Pseudostate-preserving covers -/

/-- A cover of initialized systems: a map of core states that respects halts and steps, is
    surjective on listed states, and keeps the initial pseudostate initial. -/
structure InitCover {S Q : Type} (src : InitializedGAut S A T)
    (tgt : InitializedGAut Q A T) where
  map : S → Q
  initHlt_eq : ∀ (X : Type) (W : T → X → Bool) (x : X),
    bval W src.initHlt x = bval W tgt.initHlt x
  coreHlt_eq : ∀ (s : S) (X : Type) (W : T → X → Bool) (x : X),
    bval W (src.core.hlt s) x = bval W (tgt.core.hlt (map s)) x
  initStep_eq : ∀ (X : Type) (W : T → X → Bool) (x : X),
    (firstMatch W x src.initTrans).map (fun o => (o.1, map o.2))
      = firstMatch W x tgt.initTrans
  coreStep_eq : ∀ (s : S) (X : Type) (W : T → X → Bool) (x : X),
    (firstMatch W x (src.core.trans s)).map (fun o => (o.1, map o.2))
      = firstMatch W x (tgt.core.trans (map s))
  maps : ∀ s ∈ src.core.states, map s ∈ tgt.core.states
  onto : ∀ q ∈ tgt.core.states, ∃ s, s ∈ src.core.states ∧ map s = q

private theorem option_map_id_pair {R : Type} (y : Option (A × R)) :
    y.map (fun o => (o.1, _root_.id o.2)) = y := by
  cases y <;> rfl

/-- Every system covers itself. -/
def InitCover.id {S : Type} (aut : InitializedGAut S A T) : InitCover aut aut where
  map := _root_.id
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun _ _ _ _ => rfl
  initStep_eq := fun _ _ _ => option_map_id_pair _
  coreStep_eq := fun _ _ _ _ => option_map_id_pair _
  maps := fun _ hs => hs
  onto := fun q hq => ⟨q, hq, rfl⟩

/-! ## The three constructor steps -/

/-- **Loops preserve covers.**  This is the step Phase C's innermost layer needs: a covered
    body inside a `while` yields a covered loop.  The initial transitions are gated by the
    loop guard on both sides and the back edges by the body halt conjoined with it, so both
    reduce to the body's own agreement. -/
def InitCover.loop {S Q : Type} (guard : BExp T) {src : InitializedGAut S A T}
    {tgt : InitializedGAut Q A T} (φ : InitCover src tgt) :
    InitCover (loopInitialized guard src) (loopInitialized guard tgt) where
  map := φ.map
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun s X W x => by
    change (bval W (src.core.hlt s) x && !bval W guard x)
      = (bval W (tgt.core.hlt (φ.map s)) x && !bval W guard x)
    rw [φ.coreHlt_eq s X W x]
  initStep_eq := fun X W x => by
    change (firstMatch W x (src.initTrans.map (fun t => (BExp.and guard t.1, t.2)))).map _
      = firstMatch W x (tgt.initTrans.map (fun t => (BExp.and guard t.1, t.2)))
    rw [firstMatch_map_guard, firstMatch_map_guard]
    cases hg : bval W guard x
    · simp
    · simpa using φ.initStep_eq X W x
  coreStep_eq := fun s X W x => by
    change (firstMatch W x (src.core.trans s ++
        src.initTrans.map (fun t => (BExp.and (src.core.hlt s) (BExp.and guard t.1), t.2)))).map _
      = firstMatch W x (tgt.core.trans (φ.map s) ++
        tgt.initTrans.map (fun t =>
          (BExp.and (tgt.core.hlt (φ.map s)) (BExp.and guard t.1), t.2)))
    cases hsrc : firstMatch W x (src.core.trans s) with
    | some o =>
        have htgt : firstMatch W x (tgt.core.trans (φ.map s)) = some (o.1, φ.map o.2) := by
          rw [← φ.coreStep_eq s X W x, hsrc]; rfl
        rw [firstMatch_append_some _ _ _ _ hsrc, firstMatch_append_some _ _ _ _ htgt]
        rfl
    | none =>
        have htgt : firstMatch W x (tgt.core.trans (φ.map s)) = none := by
          rw [← φ.coreStep_eq s X W x, hsrc]; rfl
        rw [firstMatch_append_none _ _ _ _ hsrc, firstMatch_append_none _ _ _ _ htgt,
          firstMatch_guard2, firstMatch_guard2, φ.coreHlt_eq s X W x]
        cases hh : bval W (tgt.core.hlt (φ.map s)) x <;> cases hg : bval W guard x <;>
          simp [φ.initStep_eq X W x]
  maps := φ.maps
  onto := φ.onto

/-- **Conditionals preserve covers.**  The two branches never communicate, so each side's
    agreement transfers untouched; only the initial dynamics are partitioned. -/
def InitCover.ite {S₁ S₂ Q₁ Q₂ : Type} (guard : BExp T)
    {src₁ : InitializedGAut S₁ A T} {tgt₁ : InitializedGAut Q₁ A T}
    {src₂ : InitializedGAut S₂ A T} {tgt₂ : InitializedGAut Q₂ A T}
    (φ : InitCover src₁ tgt₁) (ψ : InitCover src₂ tgt₂) :
    InitCover (iteInitialized guard src₁ src₂) (iteInitialized guard tgt₁ tgt₂) where
  map := Sum.map φ.map ψ.map
  initHlt_eq := fun X W x => by
    change ((bval W guard x && bval W src₁.initHlt x) ||
        ((!bval W guard x) && bval W src₂.initHlt x))
      = ((bval W guard x && bval W tgt₁.initHlt x) ||
        ((!bval W guard x) && bval W tgt₂.initHlt x))
    rw [φ.initHlt_eq X W x, ψ.initHlt_eq X W x]
  coreHlt_eq := fun s X W x => by
    cases s with
    | inl u => exact φ.coreHlt_eq u X W x
    | inr v => exact ψ.coreHlt_eq v X W x
  initStep_eq := fun X W x => by
    change (firstMatch W x
        (src₁.initTrans.map (fun t => (BExp.and guard t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂))) ++
         src₂.initTrans.map (fun t =>
           (BExp.and (BExp.not guard) t.1, t.2.1, Sum.inr t.2.2)))).map _
      = firstMatch W x
        (tgt₁.initTrans.map (fun t => (BExp.and guard t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂))) ++
         tgt₂.initTrans.map (fun t =>
           (BExp.and (BExp.not guard) t.1, t.2.1, Sum.inr t.2.2)))
    cases hg : bval W guard x
    · have h1 : firstMatch W x
          (src₁.initTrans.map (fun t => (BExp.and guard t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂)))) = none := by
        rw [firstMatch_guard_to, hg]; rfl
      have h2 : firstMatch W x
          (tgt₁.initTrans.map (fun t => (BExp.and guard t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂)))) = none := by
        rw [firstMatch_guard_to, hg]; rfl
      rw [firstMatch_append_none _ _ _ _ h1, firstMatch_append_none _ _ _ _ h2,
        firstMatch_guard_to, firstMatch_guard_to]
      have hn : bval W (BExp.not guard) x = true := by
        change (!bval W guard x) = true; rw [hg]; rfl
      rw [hn]
      simp only [if_true, Option.map_map]
      rw [← ψ.initStep_eq X W x]
      cases firstMatch W x src₂.initTrans <;> rfl
    · have h1 : firstMatch W x
          (src₁.initTrans.map (fun t => (BExp.and guard t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂))))
          = (firstMatch W x src₁.initTrans).map (fun o => (o.1, (Sum.inl o.2 : S₁ ⊕ S₂))) := by
        rw [firstMatch_guard_to, hg]; rfl
      have h2 : firstMatch W x
          (tgt₁.initTrans.map (fun t => (BExp.and guard t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂))))
          = (firstMatch W x tgt₁.initTrans).map (fun o => (o.1, (Sum.inl o.2 : Q₁ ⊕ Q₂))) := by
        rw [firstMatch_guard_to, hg]; rfl
      cases hs : firstMatch W x src₁.initTrans with
      | some o =>
          have ht : firstMatch W x tgt₁.initTrans = some (o.1, φ.map o.2) := by
            rw [← φ.initStep_eq X W x, hs]; rfl
          rw [firstMatch_append_some _ _ _ _ (by rw [h1, hs]; rfl),
            firstMatch_append_some _ _ _ _ (by rw [h2, ht]; rfl)]
          rfl
      | none =>
          have ht : firstMatch W x tgt₁.initTrans = none := by
            rw [← φ.initStep_eq X W x, hs]; rfl
          rw [firstMatch_append_none _ _ _ _ (by rw [h1, hs]; rfl),
            firstMatch_append_none _ _ _ _ (by rw [h2, ht]; rfl),
            firstMatch_guard_to, firstMatch_guard_to]
          have hn : bval W (BExp.not guard) x = false := by
            change (!bval W guard x) = false; rw [hg]; rfl
          rw [hn]
          rfl
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        change (firstMatch W x
            ((src₁.core.trans u).map (fun t => (t.1, t.2.1, Sum.inl t.2.2)))).map _
          = firstMatch W x ((tgt₁.core.trans (φ.map u)).map (fun t => (t.1, t.2.1, Sum.inl t.2.2)))
        rw [firstMatch_map_target_to, firstMatch_map_target_to, ← φ.coreStep_eq u X W x]
        cases firstMatch W x (src₁.core.trans u) <;> rfl
    | inr v =>
        change (firstMatch W x
            ((src₂.core.trans v).map (fun t => (t.1, t.2.1, Sum.inr t.2.2)))).map _
          = firstMatch W x ((tgt₂.core.trans (ψ.map v)).map (fun t => (t.1, t.2.1, Sum.inr t.2.2)))
        rw [firstMatch_map_target_to, firstMatch_map_target_to, ← ψ.coreStep_eq v X W x]
        cases firstMatch W x (src₂.core.trans v) <;> rfl
  maps := by
    intro s hs
    change s ∈ src₁.core.states.map Sum.inl ++ src₂.core.states.map Sum.inr at hs
    change Sum.map φ.map ψ.map s ∈ tgt₁.core.states.map Sum.inl ++ tgt₂.core.states.map Sum.inr
    rcases List.mem_append.mp hs with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨φ.map u, φ.maps u hu, rfl⟩))
    · obtain ⟨v, hv, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨ψ.map v, ψ.maps v hv, rfl⟩))
  onto := by
    intro q hq
    change q ∈ tgt₁.core.states.map Sum.inl ++ tgt₂.core.states.map Sum.inr at hq
    rcases List.mem_append.mp hq with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      obtain ⟨s, hs, rfl⟩ := φ.onto u hu
      exact ⟨Sum.inl s, List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨s, hs, rfl⟩)), rfl⟩
    · obtain ⟨v, hv, rfl⟩ := List.mem_map.mp h
      obtain ⟨s, hs, rfl⟩ := ψ.onto v hv
      exact ⟨Sum.inr s, List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨s, hs, rfl⟩)), rfl⟩

/-- **Sequences preserve covers.**  The exit edges out of the left component are guarded by
    its *core* halt and the initial edges by its *initial* halt; a cover that respects both
    separately — which is what `InitCover` demands — pushes through. -/
def InitCover.seq {S₁ S₂ Q₁ Q₂ : Type}
    {src₁ : InitializedGAut S₁ A T} {tgt₁ : InitializedGAut Q₁ A T}
    {src₂ : InitializedGAut S₂ A T} {tgt₂ : InitializedGAut Q₂ A T}
    (φ : InitCover src₁ tgt₁) (ψ : InitCover src₂ tgt₂) :
    InitCover (seqInitialized src₁ src₂) (seqInitialized tgt₁ tgt₂) where
  map := Sum.map φ.map ψ.map
  initHlt_eq := fun X W x => by
    change (bval W src₁.initHlt x && bval W src₂.initHlt x)
      = (bval W tgt₁.initHlt x && bval W tgt₂.initHlt x)
    rw [φ.initHlt_eq X W x, ψ.initHlt_eq X W x]
  coreHlt_eq := fun s X W x => by
    cases s with
    | inl u =>
        change (bval W (src₁.core.hlt u) x && bval W src₂.initHlt x)
          = (bval W (tgt₁.core.hlt (φ.map u)) x && bval W tgt₂.initHlt x)
        rw [φ.coreHlt_eq u X W x, ψ.initHlt_eq X W x]
    | inr v => exact ψ.coreHlt_eq v X W x
  initStep_eq := fun X W x => by
    change (firstMatch W x
        (src₁.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂))) ++
         src₂.initTrans.map (fun t =>
           (BExp.and src₁.initHlt t.1, t.2.1, (Sum.inr t.2.2 : S₁ ⊕ S₂))))).map _
      = firstMatch W x
        (tgt₁.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂))) ++
         tgt₂.initTrans.map (fun t =>
           (BExp.and tgt₁.initHlt t.1, t.2.1, (Sum.inr t.2.2 : Q₁ ⊕ Q₂))))
    cases hs : firstMatch W x src₁.initTrans with
    | some o =>
        have ht : firstMatch W x tgt₁.initTrans = some (o.1, φ.map o.2) := by
          rw [← φ.initStep_eq X W x, hs]; rfl
        have h1 : firstMatch W x
            (src₁.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂))))
            = some (o.1, (Sum.inl o.2 : S₁ ⊕ S₂)) := by
          rw [firstMatch_map_target_to, hs]; rfl
        have h2 : firstMatch W x
            (tgt₁.initTrans.map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂))))
            = some (o.1, (Sum.inl (φ.map o.2) : Q₁ ⊕ Q₂)) := by
          rw [firstMatch_map_target_to, ht]; rfl
        rw [firstMatch_append_some _ _ _ _ h1, firstMatch_append_some _ _ _ _ h2]
        rfl
    | none =>
        have ht : firstMatch W x tgt₁.initTrans = none := by
          rw [← φ.initStep_eq X W x, hs]; rfl
        rw [firstMatch_append_none _ _ _ _ (by rw [firstMatch_map_target_to, hs]; rfl),
          firstMatch_append_none _ _ _ _ (by rw [firstMatch_map_target_to, ht]; rfl),
          firstMatch_guard_to, firstMatch_guard_to, φ.initHlt_eq X W x]
        cases hh : bval W tgt₁.initHlt x
        · simp
        · rw [← ψ.initStep_eq X W x]
          cases firstMatch W x src₂.initTrans <;> simp
  coreStep_eq := fun s X W x => by
    cases s with
    | inl u =>
        change (firstMatch W x
            ((src₁.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂))) ++
             src₂.initTrans.map (fun t =>
               (BExp.and (src₁.core.hlt u) t.1, t.2.1, (Sum.inr t.2.2 : S₁ ⊕ S₂))))).map _
          = firstMatch W x
            ((tgt₁.core.trans (φ.map u)).map (fun t =>
                (t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂))) ++
             tgt₂.initTrans.map (fun t =>
               (BExp.and (tgt₁.core.hlt (φ.map u)) t.1, t.2.1, (Sum.inr t.2.2 : Q₁ ⊕ Q₂))))
        cases hs : firstMatch W x (src₁.core.trans u) with
        | some o =>
            have ht : firstMatch W x (tgt₁.core.trans (φ.map u)) = some (o.1, φ.map o.2) := by
              rw [← φ.coreStep_eq u X W x, hs]; rfl
            have h1 : firstMatch W x
                ((src₁.core.trans u).map (fun t => (t.1, t.2.1, (Sum.inl t.2.2 : S₁ ⊕ S₂))))
                = some (o.1, (Sum.inl o.2 : S₁ ⊕ S₂)) := by
              rw [firstMatch_map_target_to, hs]; rfl
            have h2 : firstMatch W x
                ((tgt₁.core.trans (φ.map u)).map (fun t =>
                  (t.1, t.2.1, (Sum.inl t.2.2 : Q₁ ⊕ Q₂))))
                = some (o.1, (Sum.inl (φ.map o.2) : Q₁ ⊕ Q₂)) := by
              rw [firstMatch_map_target_to, ht]; rfl
            rw [firstMatch_append_some _ _ _ _ h1, firstMatch_append_some _ _ _ _ h2]
            rfl
        | none =>
            have ht : firstMatch W x (tgt₁.core.trans (φ.map u)) = none := by
              rw [← φ.coreStep_eq u X W x, hs]; rfl
            rw [firstMatch_append_none _ _ _ _ (by rw [firstMatch_map_target_to, hs]; rfl),
              firstMatch_append_none _ _ _ _ (by rw [firstMatch_map_target_to, ht]; rfl),
              firstMatch_guard_to, firstMatch_guard_to, φ.coreHlt_eq u X W x]
            cases hh : bval W (tgt₁.core.hlt (φ.map u)) x
            · simp
            · rw [← ψ.initStep_eq X W x]
              cases firstMatch W x src₂.initTrans <;> simp
    | inr v =>
        change (firstMatch W x
            ((src₂.core.trans v).map (fun t => (t.1, t.2.1, (Sum.inr t.2.2 : S₁ ⊕ S₂))))).map _
          = firstMatch W x
            ((tgt₂.core.trans (ψ.map v)).map (fun t =>
              (t.1, t.2.1, (Sum.inr t.2.2 : Q₁ ⊕ Q₂))))
        rw [firstMatch_map_target_to, firstMatch_map_target_to, ← ψ.coreStep_eq v X W x]
        cases firstMatch W x (src₂.core.trans v) <;> rfl
  maps := by
    intro s hs
    change s ∈ src₁.core.states.map Sum.inl ++ src₂.core.states.map Sum.inr at hs
    change Sum.map φ.map ψ.map s ∈ tgt₁.core.states.map Sum.inl ++ tgt₂.core.states.map Sum.inr
    rcases List.mem_append.mp hs with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨φ.map u, φ.maps u hu, rfl⟩))
    · obtain ⟨v, hv, rfl⟩ := List.mem_map.mp h
      exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨ψ.map v, ψ.maps v hv, rfl⟩))
  onto := by
    intro q hq
    change q ∈ tgt₁.core.states.map Sum.inl ++ tgt₂.core.states.map Sum.inr at hq
    rcases List.mem_append.mp hq with h | h
    · obtain ⟨u, hu, rfl⟩ := List.mem_map.mp h
      obtain ⟨s, hs, rfl⟩ := φ.onto u hu
      exact ⟨Sum.inl s, List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨s, hs, rfl⟩)), rfl⟩
    · obtain ⟨v, hv, rfl⟩ := List.mem_map.mp h
      obtain ⟨s, hs, rfl⟩ := ψ.onto v hv
      exact ⟨Sum.inr s, List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨s, hs, rfl⟩)), rfl⟩

/-! ## Bridge to the cover interface

    `equivBA_of_cover` consumes a `UniformBehavioralGAutQuotient`; an `InitCover` yields one,
    with the pseudostate sent to the pseudostate. -/

private theorem toGAut_step_eq {S : Type} (aut : InitializedGAut S A T) {X : Type}
    (W : T → X → Bool) (u : S) (x : X) :
    autStep W aut.toGAut (some u) x
      = (firstMatch W x (aut.core.trans u)).map (fun o => (o.1, some o.2)) :=
  firstMatch_map_target_to W x some (aut.core.trans u)

private theorem toGAut_init_step_eq {S : Type} (aut : InitializedGAut S A T) {X : Type}
    (W : T → X → Bool) (x : X) :
    autStep W aut.toGAut none x
      = (firstMatch W x aut.initTrans).map (fun o => (o.1, some o.2)) :=
  firstMatch_map_target_to W x some aut.initTrans

private theorem bisim_of_map_step {S Q X : Type} {A₁ : GAut S A T} {A₂ : GAut Q A T}
    (W : T → X → Bool) (m : S → Q)
    (hhlt : ∀ s x, bval W (A₁.hlt s) x = bval W (A₂.hlt (m s)) x)
    (hstep : ∀ s x, (autStep W A₁ s x).map (fun o => (o.1, m o.2)) = autStep W A₂ (m s) x) :
    GAutBisim W A₁ A₂ (fun s q => m s = q) := by
  intro s q hrel
  cases hrel
  refine ⟨fun x => hhlt s x, ?_, ?_⟩
  · intro x a u hu
    refine ⟨m u, ?_, rfl⟩
    rw [← hstep s x, hu]
    rfl
  · intro x a v hv
    have h := hstep s x
    rw [hv] at h
    cases hu : autStep W A₁ s x with
    | none => rw [hu] at h; exact absurd h (by simp)
    | some o =>
        rw [hu] at h
        simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨h1, h2⟩ := h
        subst h1
        exact ⟨o.2, rfl, h2⟩

/-- An `InitCover` is a start-preserving behavioural quotient. -/
def InitCover.toQuotient {S Q : Type} {src : InitializedGAut S A T}
    {tgt : InitializedGAut Q A T} (φ : InitCover src tgt) :
    UniformBehavioralGAutQuotient src.toGAut tgt.toGAut where
  mapState := Option.map φ.map
  maps_states := by
    intro s hs
    cases s with
    | none => exact List.Mem.head _
    | some u =>
        have hu : u ∈ src.core.states := by
          rcases List.mem_cons.mp hs with h | h
          · exact absurd h (by simp)
          · obtain ⟨w, hw, hwe⟩ := List.mem_map.mp h
            cases hwe; exact hw
        exact List.Mem.tail _ (List.mem_map.mpr ⟨φ.map u, φ.maps u hu, rfl⟩)
  onto_states := by
    intro q hq
    cases q with
    | none => exact ⟨none, List.Mem.head _, rfl⟩
    | some v =>
        have hv : v ∈ tgt.core.states := by
          rcases List.mem_cons.mp hq with h | h
          · exact absurd h (by simp)
          · obtain ⟨w, hw, hwe⟩ := List.mem_map.mp h
            cases hwe; exact hw
        obtain ⟨u, hu, rfl⟩ := φ.onto v hv
        exact ⟨some u, List.Mem.tail _ (List.mem_map.mpr ⟨u, hu, rfl⟩), rfl⟩
  bisim_graph := by
    intro X W
    refine bisim_of_map_step W (Option.map φ.map) ?_ ?_
    · intro s x
      cases s with
      | none => exact φ.initHlt_eq X W x
      | some u => exact φ.coreHlt_eq u X W x
    · intro s x
      cases s with
      | none =>
          show (autStep W src.toGAut none x).map _ = autStep W tgt.toGAut none x
          rw [toGAut_init_step_eq, toGAut_init_step_eq, ← φ.initStep_eq X W x]
          cases firstMatch W x src.initTrans <;> rfl
      | some u =>
          show (autStep W src.toGAut (some u) x).map _
            = autStep W tgt.toGAut (some (φ.map u)) x
          rw [toGAut_step_eq, toGAut_step_eq, ← φ.coreStep_eq u X W x]
          cases firstMatch W x (src.core.trans u) <;> rfl

/-! ## Phase C: synthesis is a structural recursion

    Each step grows the expression by the same constructor that grows the system, so a
    system assembled from covered pieces is covered by the assembled expression.  These are
    the recursion's three cases; `InitCover.id` supplies the leaves. -/

def synth_loop {S : Type} (guard : BExp T) {sys : InitializedGAut S A T} {e : Exp A T}
    (φ : InitCover (certifiedThompson A T e).aut sys) :
    InitCover (certifiedThompson A T (.wh guard e)).aut (loopInitialized guard sys) :=
  InitCover.loop guard φ

def synth_ite {S₁ S₂ : Type} (guard : BExp T)
    {sys₁ : InitializedGAut S₁ A T} {sys₂ : InitializedGAut S₂ A T} {e f : Exp A T}
    (φ : InitCover (certifiedThompson A T e).aut sys₁)
    (ψ : InitCover (certifiedThompson A T f).aut sys₂) :
    InitCover (certifiedThompson A T (.ite guard e f)).aut (iteInitialized guard sys₁ sys₂) :=
  InitCover.ite guard φ ψ

def synth_seq {S₁ S₂ : Type}
    {sys₁ : InitializedGAut S₁ A T} {sys₂ : InitializedGAut S₂ A T} {e f : Exp A T}
    (φ : InitCover (certifiedThompson A T e).aut sys₁)
    (ψ : InitCover (certifiedThompson A T f).aut sys₂) :
    InitCover (certifiedThompson A T (.seq e f)).aut (seqInitialized sys₁ sys₂) :=
  InitCover.seq φ ψ

/-- **Phase C's done-when.**  A synthesised expression whose Thompson automaton covers the
    Thompson automaton of another expression yields provable equality — `equivBA_of_cover`
    applies to the output of the recursion above. -/
theorem equivBA_of_synth {e h : Exp A T}
    (φ : InitCover (certifiedThompson A T h).aut (certifiedThompson A T e).aut) :
    EquivBA e h :=
  equivBA_of_cover φ.toQuotient rfl

#print axioms InitCover.loop
#print axioms InitCover.ite
#print axioms InitCover.seq
#print axioms InitCover.toQuotient
#print axioms equivBA_of_synth

/-! ## Covers compose, so an intermediate system is usable

    A span does not have to be exhibited directly against both sides.  It suffices to find
    one Thompson automaton covering a *single* intermediate system that itself covers both —
    which is the shape the pullback has. -/

/-- Covers are transitive. -/
def InitCover.comp {S Q R : Type} {a : InitializedGAut S A T} {b : InitializedGAut Q A T}
    {c : InitializedGAut R A T} (φ : InitCover a b) (ψ : InitCover b c) : InitCover a c where
  map := fun s => ψ.map (φ.map s)
  initHlt_eq := fun X W x => (φ.initHlt_eq X W x).trans (ψ.initHlt_eq X W x)
  coreHlt_eq := fun s X W x =>
    (φ.coreHlt_eq s X W x).trans (ψ.coreHlt_eq (φ.map s) X W x)
  initStep_eq := fun X W x => by
    rw [← ψ.initStep_eq X W x, ← φ.initStep_eq X W x]
    cases firstMatch W x a.initTrans <;> rfl
  coreStep_eq := fun s X W x => by
    rw [← ψ.coreStep_eq (φ.map s) X W x, ← φ.coreStep_eq s X W x]
    cases firstMatch W x (a.core.trans s) <;> rfl
  maps := fun s hs => ψ.maps (φ.map s) (φ.maps s hs)
  onto := by
    intro q hq
    obtain ⟨v, hv, rfl⟩ := ψ.onto q hq
    obtain ⟨u, hu, rfl⟩ := φ.onto v hv
    exact ⟨u, hu, rfl⟩

/-- **The span, through an intermediate.**  One Thompson automaton covering a system that
    covers both sides settles the pair.  This is what reduces `CommonSyntacticRefinement`
    to a statement about a single canonical object rather than an existential over covers of
    both sides at once. -/
theorem equivBA_of_common_refinement {S : Type} {e f h : Exp A T}
    {mid : InitializedGAut S A T}
    (χ : InitCover (certifiedThompson A T h).aut mid)
    (π₁ : InitCover mid (certifiedThompson A T e).aut)
    (π₂ : InitCover mid (certifiedThompson A T f).aut) :
    EquivBA e f :=
  EquivBA.trans (equivBA_of_synth (χ.comp π₁))
    (EquivBA.symm (equivBA_of_synth (χ.comp π₂)))

#print axioms InitCover.comp
#print axioms equivBA_of_common_refinement

/-! ## The product of two guarded transition lists

    The canonical intermediate system for a span is the pullback, whose transitions are the
    lexicographic product of the two components'.  The lemma below is what makes that
    construction behave: `firstMatch` over the product selects exactly the pair of the two
    components' own selections.

    Why lexicographic order is the right one: `firstMatch` picks the *first* satisfied
    guard, so the product's first satisfied entry is the least `i` with `g₁ᵢ` true (paired
    with some satisfiable `g₂`), then within that block the least `j` with `g₂ⱼ` true — that
    is, exactly `(i*, j*)`.  Every other entry is unreachable by ordering rather than by
    guard, which is why a product state can never fire a transition its components would
    not. -/

/-- The lexicographic product of two guarded transition lists. -/
def crossTrans {S₁ S₂ : Type} (L₁ : List (BExp T × A × S₁)) (L₂ : List (BExp T × A × S₂)) :
    List (BExp T × A × (S₁ × S₂)) :=
  L₁.flatMap (fun t₁ => L₂.map (fun t₂ => (BExp.and t₁.1 t₂.1, t₁.2.1, (t₁.2.2, t₂.2.2))))

private theorem firstMatch_cross_block {S₁ S₂ X : Type} (W : T → X → Bool) (x : X)
    (g : BExp T) (a : A) (u : S₁) (L₂ : List (BExp T × A × S₂)) :
    firstMatch W x (L₂.map (fun t₂ => (BExp.and g t₂.1, a, (u, t₂.2.2))))
      = if bval W g x then (firstMatch W x L₂).map (fun o => (a, (u, o.2))) else none := by
  induction L₂ with
  | nil => cases hg : bval W g x <;> simp [firstMatch]
  | cons hd tl ih =>
      obtain ⟨g₂, a₂, v⟩ := hd
      simp only [List.map_cons, firstMatch]
      have hand : bval W (BExp.and g g₂) x = (bval W g x && bval W g₂ x) := rfl
      rw [hand, ih]
      cases hg : bval W g x <;> cases hg₂ : bval W g₂ x <;> simp [hg, hg₂]

/-- **The product selects the pair of selections.**  Both components must fire; if either
    does not, the product does not. -/
theorem firstMatch_crossTrans {S₁ S₂ X : Type} (W : T → X → Bool) (x : X)
    (L₁ : List (BExp T × A × S₁)) (L₂ : List (BExp T × A × S₂)) :
    firstMatch W x (crossTrans L₁ L₂)
      = match firstMatch W x L₁, firstMatch W x L₂ with
        | some o₁, some o₂ => some (o₁.1, (o₁.2, o₂.2))
        | _, _ => none := by
  induction L₁ with
  | nil => cases firstMatch W x L₂ <;> rfl
  | cons hd tl ih =>
      obtain ⟨g, a, u⟩ := hd
      have hsplit : crossTrans ((g, a, u) :: tl) L₂
          = (L₂.map (fun t₂ => (BExp.and g t₂.1, a, (u, t₂.2.2)))) ++ crossTrans tl L₂ := rfl
      rw [hsplit]
      cases hg : bval W g x with
      | false =>
          have hblock : firstMatch W x
              (L₂.map (fun t₂ => (BExp.and g t₂.1, a, (u, t₂.2.2)))) = none := by
            rw [firstMatch_cross_block, hg]; rfl
          rw [firstMatch_append_none _ _ _ _ hblock, ih]
          have : firstMatch W x ((g, a, u) :: tl) = firstMatch W x tl := by
            simp only [firstMatch, hg]; rfl
          rw [this]
      | true =>
          have hfirst : firstMatch W x ((g, a, u) :: tl) = some (a, u) := by
            simp only [firstMatch, hg]; rfl
          rw [hfirst]
          cases h₂ : firstMatch W x L₂ with
          | none =>
              have hblock : firstMatch W x
                  (L₂.map (fun t₂ => (BExp.and g t₂.1, a, (u, t₂.2.2)))) = none := by
                rw [firstMatch_cross_block, hg, h₂]; rfl
              rw [firstMatch_append_none _ _ _ _ hblock, ih, h₂]
              cases firstMatch W x tl <;> rfl
          | some o₂ =>
              have hblock : firstMatch W x
                  (L₂.map (fun t₂ => (BExp.and g t₂.1, a, (u, t₂.2.2))))
                  = some (a, (u, o₂.2)) := by
                rw [firstMatch_cross_block, hg, h₂]; rfl
              rw [firstMatch_append_some _ _ _ _ hblock]

#print axioms firstMatch_crossTrans

/-! ## What remains, named

    Everything above composes.  Assembling it, finite-axiom completeness now reduces to a
    single existence statement about one intermediate object per pair — no quotient has to
    be pinned, no collapse invented, and both legs of the span come from the same system. -/

/-- **The residual target.**  For every uniformly equivalent pair, a system covering both
    sides which is itself covered by the Thompson automaton of some program.

    This is what `CommonSyntacticRefinement` becomes once covers are known to compose: the
    two legs of the span need not be found separately, only a single common intermediate
    and one Thompson cover of it.  The canonical candidate is the pullback, whose
    transitions are `crossTrans` of the two components'. -/
def CommonCoveredIntermediate (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (S : Type) (mid : InitializedGAut S A T) (h : Exp A T),
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T f).aut) ∧
      Nonempty (InitCover (certifiedThompson A T h).aut mid)

/-- **The reduction, assembled.**  A common covered intermediate yields full finite-axiom
    completeness, using only the composition results above and `equivBA_of_cover`.

    No uniqueness axiom, no crystallization, and — unlike the refuted cospan — nothing that
    forces the intermediate to be a *quotient*, which is precisely what could not be built. -/
theorem completeness_of_common_covered_intermediate
    (hmid : CommonCoveredIntermediate A T) : FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨S, mid, h, ⟨π₁⟩, ⟨π₂⟩, ⟨χ⟩⟩ := hmid e f heq
  exact equivBA_of_common_refinement χ π₁ π₂

/-- Non-vacuity: an expression is its own covered intermediate, so the target is
    satisfiable.  What is open is the case of *distinct* programs. -/
theorem commonCoveredIntermediate_refl (e : Exp A T) :
    ∃ (S : Type) (mid : InitializedGAut S A T) (h : Exp A T),
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover (certifiedThompson A T h).aut mid) :=
  ⟨(certifiedThompson A T e).State, (certifiedThompson A T e).aut, e,
    ⟨InitCover.id _⟩, ⟨InitCover.id _⟩, ⟨InitCover.id _⟩⟩

#print axioms completeness_of_common_covered_intermediate
#print axioms commonCoveredIntermediate_refl

/-! ## The positive fork, as a closure property

    Grabmayer and Fokkink's structural condition LEE ("loop existence and elimination")
    says a chart can have its loop sub-charts peeled off one at a time until no infinite
    path remains, and their theorem is that such charts have *provable solutions* — the
    solution being an expression, not an isomorphism.  That is the cover direction, and it
    is what the constructor lemmas above already provide, read in reverse: peeling a loop is
    `loopInitialized` run backwards, and `InitCover.loop` is what puts the cover back.

    So the GKAT form of "LEE charts are solvable" is not a new construction but a closure
    property of a single predicate. -/

/-- A system solvable by the syntax: some program's Thompson automaton covers it. -/
def HasThompsonCover {S : Type} (sys : InitializedGAut S A T) : Prop :=
  ∃ h : Exp A T, Nonempty (InitCover (certifiedThompson A T h).aut sys)

theorem hasThompsonCover_act (a : A) :
    HasThompsonCover (thompsonAction a : InitializedGAut Unit A T) :=
  ⟨.act a, ⟨InitCover.id _⟩⟩

theorem hasThompsonCover_test (b : BExp T) :
    HasThompsonCover (thompsonTest b : InitializedGAut Empty A T) :=
  ⟨.test b, ⟨InitCover.id _⟩⟩

theorem hasThompsonCover_seq {S₁ S₂ : Type} {s₁ : InitializedGAut S₁ A T}
    {s₂ : InitializedGAut S₂ A T}
    (h₁ : HasThompsonCover s₁) (h₂ : HasThompsonCover s₂) :
    HasThompsonCover (seqInitialized s₁ s₂) := by
  obtain ⟨e, ⟨φ⟩⟩ := h₁
  obtain ⟨f, ⟨ψ⟩⟩ := h₂
  exact ⟨.seq e f, ⟨InitCover.seq φ ψ⟩⟩

theorem hasThompsonCover_ite {S₁ S₂ : Type} (guard : BExp T) {s₁ : InitializedGAut S₁ A T}
    {s₂ : InitializedGAut S₂ A T}
    (h₁ : HasThompsonCover s₁) (h₂ : HasThompsonCover s₂) :
    HasThompsonCover (iteInitialized guard s₁ s₂) := by
  obtain ⟨e, ⟨φ⟩⟩ := h₁
  obtain ⟨f, ⟨ψ⟩⟩ := h₂
  exact ⟨.ite guard e f, ⟨InitCover.ite guard φ ψ⟩⟩

/-- **Loop elimination, reversed.**  Peeling a loop is what LEE does; this puts the cover
    back on afterwards, which is the step that makes the peeling into a solution. -/
theorem hasThompsonCover_loop {S : Type} (guard : BExp T) {sys : InitializedGAut S A T}
    (h : HasThompsonCover sys) : HasThompsonCover (loopInitialized guard sys) := by
  obtain ⟨e, ⟨φ⟩⟩ := h
  exact ⟨.wh guard e, ⟨InitCover.loop guard φ⟩⟩

/-- Solvability transports along covers: anything a solvable system covers is solvable. -/
theorem HasThompsonCover.along {S Q : Type} {src : InitializedGAut S A T}
    {tgt : InitializedGAut Q A T} (φ : InitCover src tgt) (h : HasThompsonCover src) :
    HasThompsonCover tgt := by
  obtain ⟨e, ⟨χ⟩⟩ := h
  exact ⟨e, ⟨χ.comp φ⟩⟩

/-- **The positive fork, stated exactly.**  Completeness follows if every uniformly
    equivalent pair admits a common intermediate that is solvable by the syntax.

    Everything except the existence of that intermediate is now proved: solvability is
    closed under all three constructors and under covering, so any intermediate assembled
    by peeling — the GKAT reading of LEE — qualifies automatically. -/
theorem completeness_of_solvable_intermediate
    (hmid : ∀ e f : Exp A T, UniformLanguageEquivalent e f →
      ∃ (S : Type) (mid : InitializedGAut S A T),
        Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
        Nonempty (InitCover mid (certifiedThompson A T f).aut) ∧
        HasThompsonCover mid) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨S, mid, ⟨π₁⟩, ⟨π₂⟩, hsolv⟩ := hmid e f heq
  obtain ⟨h, ⟨χ⟩⟩ := hsolv
  exact equivBA_of_common_refinement χ π₁ π₂

#print axioms hasThompsonCover_loop
#print axioms HasThompsonCover.along
#print axioms completeness_of_solvable_intermediate

/-! ## How hard the residual target is, exactly

    It is tempting to read `completeness_of_solvable_intermediate` as leaving a
    formalization task — import the right theorem about which automata are expressible and
    be done.  It does not.  Composing it with the repository's own
    `completeness_implies_ua2` shows the residual target **entails the uniqueness axiom**,
    so closing it would settle what has been open since Smolka et al. -/

/-- **Closing the positive fork solves the open problem.**  A common solvable intermediate
    for every equivalent pair yields `UA₂` — and, through
    `completeness_implies_cycle_uniqueness`, the whole scheme.

    So the remaining gap cannot be closed by importing a known characterization of the
    expressible automata: if it could, UA would already be known derivable.  Whatever
    separates "the intermediate is the behaviour of some expression" from "some
    expression's automaton *covers* the intermediate" is where the difficulty lives. -/
theorem ua2_of_solvable_intermediate
    (hmid : ∀ e f : Exp A T, UniformLanguageEquivalent e f →
      ∃ (S : Type) (mid : InitializedGAut S A T),
        Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
        Nonempty (InitCover mid (certifiedThompson A T f).aut) ∧
        HasThompsonCover mid)
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hprod0 : EquivBA (.test (E e0) : Exp A T) (.test .zero))
    (hprod1 : EquivBA (.test (E e1) : Exp A T) (.test .zero))
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) f1))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') f1)) :
    EquivBA g0 g0' :=
  GkatCompletenessImpliesUA.completeness_implies_ua2
    (completeness_of_solvable_intermediate hmid) hprod0 hprod1 h0 h1 h0' h1'

#print axioms ua2_of_solvable_intermediate

/-! ## Localising the difficulty

    The coequation of Schmid–Kappé–Kozen–Silva cuts out exactly the automata that are
    *behaviours* of GKAT expressions, and `Nested` (in `GkatKleeneProofs`) is its automaton
    kernel — every expression's automaton satisfies it.  So "is this system the behaviour of
    an expression?" is a settled question with a known answer.

    That is strictly weaker than what the fork needs.  A cover is a *functional* bisimulation
    that is onto: it exhibits the system as a quotient of the expression's own automaton, not
    merely as something bisimilar to it.  The implication below goes one way only, and by
    `ua2_of_solvable_intermediate` the converse cannot be free — it is where the uniqueness
    axiom lives. -/

/-- Solvability gives a start-preserving behavioural quotient — the direction that is free.
    The converse, from "bisimilar to some expression's automaton" back to "covered by one",
    is what `ua2_of_solvable_intermediate` shows cannot be free. -/
theorem quotient_of_hasThompsonCover {S : Type} {sys : InitializedGAut S A T}
    (h : HasThompsonCover sys) :
    ∃ h' : Exp A T, ∃ π : UniformBehavioralGAutQuotient
      (certifiedThompson A T h').aut.toGAut sys.toGAut, π.mapState none = none := by
  obtain ⟨h', ⟨φ⟩⟩ := h
  exact ⟨h', φ.toQuotient, rfl⟩

#print axioms quotient_of_hasThompsonCover

/-- **The fork, closed for the covered class.**  When one side's Thompson automaton already
    covers the other's, that automaton *is* the common solvable intermediate — it covers the
    other side by hypothesis, itself by identity, and is solvable because it is
    syntax-generated.  No open problem is involved. -/
theorem fork_closed_for_covered_pairs {e f : Exp A T}
    (φ : InitCover (certifiedThompson A T f).aut (certifiedThompson A T e).aut) :
    ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid (certifiedThompson A T e).aut) ∧
      Nonempty (InitCover mid (certifiedThompson A T f).aut) ∧
      HasThompsonCover mid :=
  ⟨(certifiedThompson A T f).State, (certifiedThompson A T f).aut,
    ⟨φ⟩, ⟨InitCover.id _⟩, ⟨f, ⟨InitCover.id _⟩⟩⟩

#print axioms fork_closed_for_covered_pairs

/-! ## What an `InitCover` is, in the standard vocabulary

    A map of graphs is an **immersion** when it is injective on the star of each vertex, and
    a **covering** when it is bijective there (Stallings).  Because GKAT automata are
    deterministic, a state's outgoing edges are indexed by atoms on both sides, and
    `coreStep_eq` matches them in both directions at once.  So an `InitCover` is bijective on
    stars: it is not an analogy to a covering map, it is one.

    That places this development inside a standard dictionary — coverings of a graph
    correspond to subgroups of its (free) fundamental group, finite covers to finite-index
    subgroups, and the fibre product of two covers decomposes by double cosets, with
    components of length `lcm` of the degrees over a circle.  The last fact is visible in the
    search: a period-2 lasso against a period-3 cycle yields a six-state pullback.

    It also says which refinements can help.  A Thompson automaton's cycle length is the
    number of action occurrences in its loop body, and to cover a cycle of length `L` a
    candidate needs a cycle length that `L` divides.  W1-unrolling lengthens the *tail* and
    leaves the cycle alone; guard-split duplication widens the automaton and leaves the cycle
    alone.  Neither changes the invariant that matters. -/

/-- **A cover is bijective on stars.**  At every state and every atom, source and target step
    together — the covering condition, as opposed to an immersion's one-sided injectivity. -/
theorem star_bijection {S Q : Type} {src : InitializedGAut S A T} {tgt : InitializedGAut Q A T}
    (φ : InitCover src tgt) (s : S) (X : Type) (W : T → X → Bool) (x : X) :
    (firstMatch W x (src.core.trans s)).isSome
      = (firstMatch W x (tgt.core.trans (φ.map s))).isSome := by
  rw [← φ.coreStep_eq s X W x]
  cases firstMatch W x (src.core.trans s) <;> rfl

/-- The same at the pseudostate. -/
theorem star_bijection_init {S Q : Type} {src : InitializedGAut S A T}
    {tgt : InitializedGAut Q A T} (φ : InitCover src tgt)
    (X : Type) (W : T → X → Bool) (x : X) :
    (firstMatch W x src.initTrans).isSome = (firstMatch W x tgt.initTrans).isSome := by
  rw [← φ.initStep_eq X W x]
  cases firstMatch W x src.initTrans <;> rfl

#print axioms star_bijection
#print axioms star_bijection_init

end GkatSynthesis
