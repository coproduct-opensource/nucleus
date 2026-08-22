import GkatCollapseRefutationProofs

/-!
# The repair survives the pair that killed the cospan

`GkatCollapseRefutationProofs` refutes `CommonSyntacticCollapse` with the pair

    e = p ; while b do p        f = (if b then 1 else p) ; while b do p

and `GkatCrystallizationProofs` offers `CommonSyntacticRefinement` in its place — a *span*
(one program covering both) rather than a cospan (both collapsing onto one program).  A
replacement target earns nothing if the counterexample kills it too, so this file
discharges exactly that: for the refuting pair the span exists, witnessed by

    h = if b then e else f

Both legs are built here as `UniformBehavioralGAutQuotient`s and checked, so
`equivBA_of_cover` applies twice and the pair is covered by the new target.

Why the span survives where the cospan died: a cospan must *collapse*, and the collapse was
pinned to an automaton Thompson's loop-entry discipline cannot build.  A span may *refine*,
and refining is what a guard split does — `h` simply keeps both programs' automata and
selects between them on `b`, which is an operation the syntax has.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatSpanWitness

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatCollapseRefutation

/-- The witness: `h = if b then e else f`. -/
def hProg : Exp Act Tst := .ite bT eProg fProg

private abbrev HAut := (certifiedThompson Act Tst hProg).aut.toGAut
private abbrev EAut := (certifiedThompson Act Tst eProg).aut.toGAut
private abbrev FAut := (certifiedThompson Act Tst fProg).aut.toGAut

/-! ## The five states of `h`, and the three of each side

    `h`'s core states are `e`'s two action occurrences followed by `f`'s two. -/

private abbrev hE1 : Option (certifiedThompson Act Tst hProg).State := some (Sum.inl (Sum.inl ()))
private abbrev hE2 : Option (certifiedThompson Act Tst hProg).State := some (Sum.inl (Sum.inr ()))
private abbrev hF1 : Option (certifiedThompson Act Tst hProg).State :=
  some (Sum.inr (Sum.inl (Sum.inr ())))
private abbrev hF2 : Option (certifiedThompson Act Tst hProg).State := some (Sum.inr (Sum.inr ()))

private abbrev eE1 : Option (certifiedThompson Act Tst eProg).State := some (Sum.inl ())
private abbrev eE2 : Option (certifiedThompson Act Tst eProg).State := some (Sum.inr ())

private abbrev fF1 : Option (certifiedThompson Act Tst fProg).State :=
  some (Sum.inl (Sum.inr ()))
private abbrev fF2 : Option (certifiedThompson Act Tst fProg).State := some (Sum.inr ())

/-! ## Step computations

    Every transition list below is pinned by unfolding alone (`rfl`); only the guards then
    need evaluating, and each has the same shape `_ ∧ (b ∧ _)`. -/

private theorem h_step_start {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W HAut none a = if W () a then some ((), hE1) else some ((), hF1) := by
  show firstMatch W a (HAut.trans none) = _
  rw [show HAut.trans none =
    [ (BExp.and bT BExp.one, (), hE1)
    , (BExp.and bT (BExp.and BExp.zero (BExp.and bT BExp.one)), (), hE2)
    , (BExp.and (BExp.not bT) (BExp.and (BExp.not bT) BExp.one), (), hF1)
    , (BExp.and (BExp.not bT)
        (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
          (BExp.and bT BExp.one)), (), hF2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem h_step_e1 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W HAut hE1 a = if W () a then some ((), hE2) else none := by
  show firstMatch W a (HAut.trans hE1) = _
  rw [show HAut.trans hE1 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), hE2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem h_step_e2 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W HAut hE2 a = if W () a then some ((), hE2) else none := by
  show firstMatch W a (HAut.trans hE2) = _
  rw [show HAut.trans hE2 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), hE2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem h_step_f1 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W HAut hF1 a = if W () a then some ((), hF2) else none := by
  show firstMatch W a (HAut.trans hF1) = _
  rw [show HAut.trans hF1 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), hF2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem h_step_f2 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W HAut hF2 a = if W () a then some ((), hF2) else none := by
  show firstMatch W a (HAut.trans hF2) = _
  rw [show HAut.trans hF2 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), hF2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem e_step_start {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W EAut none a = some ((), eE1) := by
  show firstMatch W a (EAut.trans none) = _
  rw [show EAut.trans none =
    [ (BExp.one, (), eE1)
    , (BExp.and BExp.zero (BExp.and bT BExp.one), (), eE2) ] from rfl]
  simp [firstMatch, bval] <;> rfl

private theorem e_step_e1 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W EAut eE1 a = if W () a then some ((), eE2) else none := by
  show firstMatch W a (EAut.trans eE1) = _
  rw [show EAut.trans eE1 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), eE2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem e_step_e2 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W EAut eE2 a = if W () a then some ((), eE2) else none := by
  show firstMatch W a (EAut.trans eE2) = _
  rw [show EAut.trans eE2 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), eE2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem f_step_start {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W FAut none a = if W () a then some ((), fF2) else some ((), fF1) := by
  show firstMatch W a (FAut.trans none) = _
  rw [show FAut.trans none =
    [ (BExp.and (BExp.not bT) BExp.one, (), fF1)
    , (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
        (BExp.and bT BExp.one), (), fF2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem f_step_f1 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W FAut fF1 a = if W () a then some ((), fF2) else none := by
  show firstMatch W a (FAut.trans fF1) = _
  rw [show FAut.trans fF1 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), fF2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem f_step_f2 {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W FAut fF2 a = if W () a then some ((), fF2) else none := by
  show firstMatch W a (FAut.trans fF2) = _
  rw [show FAut.trans fF2 =
    [ (BExp.and BExp.one (BExp.and bT BExp.one), (), fF2) ] from rfl]
  cases hb : W () a <;> simp [firstMatch, bval, bT, hb] <;> rfl

/-! ## Halt guards

    Every action state on both sides halts exactly off the loop guard, and every start
    never halts. -/

private theorem h_hlt_start {X : Type} (W : Tst → X → Bool) (a : X) :
    bval W (HAut.hlt none) a = false := by
  show bval W (BExp.or (BExp.and bT (BExp.and BExp.zero (BExp.not bT)))
    (BExp.and (BExp.not bT)
      (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
        (BExp.not bT)))) a = false
  cases hb : W () a <;> simp [bval, bT, hb]

private theorem e_hlt_start {X : Type} (W : Tst → X → Bool) (a : X) :
    bval W (EAut.hlt none) a = false := by
  show bval W (BExp.and BExp.zero (BExp.not bT)) a = false
  simp [bval]

private theorem f_hlt_start {X : Type} (W : Tst → X → Bool) (a : X) :
    bval W (FAut.hlt none) a = false := by
  show bval W (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
    (BExp.not bT)) a = false
  cases hb : W () a <;> simp [bval, bT, hb]

private theorem act_hlt {X : Type} (W : Tst → X → Bool) (a : X) :
    bval W (BExp.and BExp.one (BExp.not bT)) a = !W () a := by
  simp [bval, bT]

/-! ## Two generic bisimulation steps

    Every state pair below is one of two shapes: a start, which steps at both atoms, or an
    action state, which steps on `b` and halts off it. -/

private theorem bisim_branch {X S₁ S₂ : Type} {A₁ : GAut S₁ Act Tst} {A₂ : GAut S₂ Act Tst}
    (W : Tst → X → Bool) (m : S₁ → S₂) {s : S₁} {t : S₂} {sT sF : S₁} {tT tF : S₂}
    (hhlt : ∀ a, bval W (A₁.hlt s) a = bval W (A₂.hlt t) a)
    (h1t : ∀ a, W () a = true → autStep W A₁ s a = some ((), sT))
    (h1f : ∀ a, W () a = false → autStep W A₁ s a = some ((), sF))
    (h2t : ∀ a, W () a = true → autStep W A₂ t a = some ((), tT))
    (h2f : ∀ a, W () a = false → autStep W A₂ t a = some ((), tF))
    (hmT : m sT = tT) (hmF : m sF = tF) :
    (∀ a, bval W (A₁.hlt s) a = bval W (A₂.hlt t) a) ∧
    (∀ (a : X) (q : Act) (u : S₁), autStep W A₁ s a = some (q, u) →
      ∃ v, autStep W A₂ t a = some (q, v) ∧ m u = v) ∧
    (∀ (a : X) (q : Act) (v : S₂), autStep W A₂ t a = some (q, v) →
      ∃ u, autStep W A₁ s a = some (q, u) ∧ m u = v) := by
  refine ⟨hhlt, ?_, ?_⟩
  · intro a q u hu
    cases hb : W () a with
    | true =>
        rw [h1t a hb] at hu
        cases hu
        exact ⟨tT, h2t a hb, hmT⟩
    | false =>
        rw [h1f a hb] at hu
        cases hu
        exact ⟨tF, h2f a hb, hmF⟩
  · intro a q v hv
    cases hb : W () a with
    | true =>
        rw [h2t a hb] at hv
        cases hv
        exact ⟨sT, h1t a hb, hmT⟩
    | false =>
        rw [h2f a hb] at hv
        cases hv
        exact ⟨sF, h1f a hb, hmF⟩

private theorem bisim_guarded {X S₁ S₂ : Type} {A₁ : GAut S₁ Act Tst} {A₂ : GAut S₂ Act Tst}
    (W : Tst → X → Bool) (m : S₁ → S₂) {s : S₁} {t : S₂} {sT : S₁} {tT : S₂}
    (hhlt : ∀ a, bval W (A₁.hlt s) a = bval W (A₂.hlt t) a)
    (h1t : ∀ a, W () a = true → autStep W A₁ s a = some ((), sT))
    (h1f : ∀ a, W () a = false → autStep W A₁ s a = none)
    (h2t : ∀ a, W () a = true → autStep W A₂ t a = some ((), tT))
    (h2f : ∀ a, W () a = false → autStep W A₂ t a = none)
    (hmT : m sT = tT) :
    (∀ a, bval W (A₁.hlt s) a = bval W (A₂.hlt t) a) ∧
    (∀ (a : X) (q : Act) (u : S₁), autStep W A₁ s a = some (q, u) →
      ∃ v, autStep W A₂ t a = some (q, v) ∧ m u = v) ∧
    (∀ (a : X) (q : Act) (v : S₂), autStep W A₂ t a = some (q, v) →
      ∃ u, autStep W A₁ s a = some (q, u) ∧ m u = v) := by
  refine ⟨hhlt, ?_, ?_⟩
  · intro a q u hu
    cases hb : W () a with
    | true => rw [h1t a hb] at hu; cases hu; exact ⟨tT, h2t a hb, hmT⟩
    | false => rw [h1f a hb] at hu; exact absurd hu (by simp)
  · intro a q v hv
    cases hb : W () a with
    | true => rw [h2t a hb] at hv; cases hv; exact ⟨sT, h1t a hb, hmT⟩
    | false => rw [h2f a hb] at hv; exact absurd hv (by simp)

/-! ## Case forms of the step lemmas -/

private theorem hs_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W HAut none a = some ((), hE1) := by rw [h_step_start, hb]; rfl
private theorem hs_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W HAut none a = some ((), hF1) := by rw [h_step_start, hb]; rfl
private theorem he1_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W HAut hE1 a = some ((), hE2) := by rw [h_step_e1, hb]; rfl
private theorem he1_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W HAut hE1 a = none := by rw [h_step_e1, hb]; rfl
private theorem he2_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W HAut hE2 a = some ((), hE2) := by rw [h_step_e2, hb]; rfl
private theorem he2_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W HAut hE2 a = none := by rw [h_step_e2, hb]; rfl
private theorem hf1_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W HAut hF1 a = some ((), hF2) := by rw [h_step_f1, hb]; rfl
private theorem hf1_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W HAut hF1 a = none := by rw [h_step_f1, hb]; rfl
private theorem hf2_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W HAut hF2 a = some ((), hF2) := by rw [h_step_f2, hb]; rfl
private theorem hf2_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W HAut hF2 a = none := by rw [h_step_f2, hb]; rfl

private theorem es_any {X : Type} (W : Tst → X → Bool) (a : X) :
    autStep W EAut none a = some ((), eE1) := e_step_start W a
private theorem ee1_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W EAut eE1 a = some ((), eE2) := by rw [e_step_e1, hb]; rfl
private theorem ee1_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W EAut eE1 a = none := by rw [e_step_e1, hb]; rfl
private theorem ee2_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W EAut eE2 a = some ((), eE2) := by rw [e_step_e2, hb]; rfl
private theorem ee2_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W EAut eE2 a = none := by rw [e_step_e2, hb]; rfl

private theorem fs_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W FAut none a = some ((), fF2) := by rw [f_step_start, hb]; rfl
private theorem fs_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W FAut none a = some ((), fF1) := by rw [f_step_start, hb]; rfl
private theorem ff1_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W FAut fF1 a = some ((), fF2) := by rw [f_step_f1, hb]; rfl
private theorem ff1_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W FAut fF1 a = none := by rw [f_step_f1, hb]; rfl
private theorem ff2_t {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = true) :
    autStep W FAut fF2 a = some ((), fF2) := by rw [f_step_f2, hb]; rfl
private theorem ff2_f {X : Type} (W : Tst → X → Bool) (a : X) (hb : W () a = false) :
    autStep W FAut fF2 a = none := by rw [f_step_f2, hb]; rfl

/-! ## The two cover legs

    `h`'s `e`-copy maps onto `e` identically; its `f`-copy folds onto `e`'s two states the
    way the shared trace demands.  Onto `f` the roles swap. -/

/-- `thompson h → thompson e`. -/
def phiMap : Option (certifiedThompson Act Tst hProg).State →
    Option (certifiedThompson Act Tst eProg).State
  | none => none
  | some (Sum.inl u) => some u
  | some (Sum.inr (Sum.inl (Sum.inl z))) => nomatch z
  | some (Sum.inr (Sum.inl (Sum.inr _))) => eE1
  | some (Sum.inr (Sum.inr _)) => eE2

/-- `thompson h → thompson f`. -/
def psiMap : Option (certifiedThompson Act Tst hProg).State →
    Option (certifiedThompson Act Tst fProg).State
  | none => none
  | some (Sum.inl _) => fF2
  | some (Sum.inr (Sum.inl (Sum.inl z))) => nomatch z
  | some (Sum.inr (Sum.inl (Sum.inr _))) => fF1
  | some (Sum.inr (Sum.inr _)) => fF2

/-- The first leg of the span. -/
def phi : UniformBehavioralGAutQuotient HAut EAut where
  mapState := phiMap
  maps_states := by
    intro s _
    cases s with
    | none => exact List.Mem.head _
    | some v =>
        cases v with
        | inl u =>
            cases u with
            | inl _ => exact List.Mem.tail _ (List.Mem.head _)
            | inr _ => exact List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))
        | inr w =>
            cases w with
            | inl y =>
                cases y with
                | inl z => exact nomatch z
                | inr _ => exact List.Mem.tail _ (List.Mem.head _)
            | inr _ => exact List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))
  onto_states := by
    intro q _
    cases q with
    | none => exact ⟨none, List.Mem.head _, rfl⟩
    | some u =>
        cases u with
        | inl _ => exact ⟨hE1, List.Mem.tail _ (List.Mem.head _), rfl⟩
        | inr _ =>
            exact ⟨hE2, List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)), rfl⟩
  bisim_graph := by
    intro X W s q hrel
    cases hrel
    cases s with
    | none =>
        exact bisim_branch W phiMap
          (fun a => (h_hlt_start W a).trans (e_hlt_start W a).symm)
          (hs_t W) (hs_f W) (fun a _ => es_any W a) (fun a _ => es_any W a) rfl rfl
    | some v =>
        cases v with
        | inl u =>
            cases u with
            | inl _ =>
                exact bisim_guarded W phiMap (fun _ => rfl)
                  (he1_t W) (he1_f W) (ee1_t W) (ee1_f W) rfl
            | inr _ =>
                exact bisim_guarded W phiMap (fun _ => rfl)
                  (he2_t W) (he2_f W) (ee2_t W) (ee2_f W) rfl
        | inr w =>
            cases w with
            | inl y =>
                cases y with
                | inl z => exact nomatch z
                | inr _ =>
                    exact bisim_guarded W phiMap (fun _ => rfl)
                      (hf1_t W) (hf1_f W) (ee1_t W) (ee1_f W) rfl
            | inr _ =>
                exact bisim_guarded W phiMap (fun _ => rfl)
                  (hf2_t W) (hf2_f W) (ee2_t W) (ee2_f W) rfl

/-- The second leg of the span. -/
def psi : UniformBehavioralGAutQuotient HAut FAut where
  mapState := psiMap
  maps_states := by
    intro s _
    cases s with
    | none => exact List.Mem.head _
    | some v =>
        cases v with
        | inl _ => exact List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))
        | inr w =>
            cases w with
            | inl y =>
                cases y with
                | inl z => exact nomatch z
                | inr _ => exact List.Mem.tail _ (List.Mem.head _)
            | inr _ => exact List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))
  onto_states := by
    intro q _
    cases q with
    | none => exact ⟨none, List.Mem.head _, rfl⟩
    | some u =>
        cases u with
        | inl y =>
            cases y with
            | inl z => exact nomatch z
            | inr _ =>
                exact ⟨hF1, List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _
                  (List.Mem.head _))), rfl⟩
        | inr _ => exact ⟨hE1, List.Mem.tail _ (List.Mem.head _), rfl⟩
  bisim_graph := by
    intro X W s q hrel
    cases hrel
    cases s with
    | none =>
        exact bisim_branch W psiMap
          (fun a => (h_hlt_start W a).trans (f_hlt_start W a).symm)
          (hs_t W) (hs_f W) (fs_t W) (fs_f W) rfl rfl
    | some v =>
        cases v with
        | inl u =>
            cases u with
            | inl _ =>
                exact bisim_guarded W psiMap (fun _ => rfl)
                  (he1_t W) (he1_f W) (ff2_t W) (ff2_f W) rfl
            | inr _ =>
                exact bisim_guarded W psiMap (fun _ => rfl)
                  (he2_t W) (he2_f W) (ff2_t W) (ff2_f W) rfl
        | inr w =>
            cases w with
            | inl y =>
                cases y with
                | inl z => exact nomatch z
                | inr _ =>
                    exact bisim_guarded W psiMap (fun _ => rfl)
                      (hf1_t W) (hf1_f W) (ff1_t W) (ff1_f W) rfl
            | inr _ =>
                exact bisim_guarded W psiMap (fun _ => rfl)
                  (hf2_t W) (hf2_f W) (ff2_t W) (ff2_f W) rfl

/-! ## The span exists for the refuting pair -/

/-- **The repair survives.**  The pair that refutes `CommonSyntacticCollapse` satisfies the
    span condition: `h = if b then e else f` covers both sides, starts corresponding. -/
theorem span_for_the_refuting_pair :
    ∃ (h : Exp Act Tst)
      (φ : UniformBehavioralGAutQuotient
        (certifiedThompson Act Tst h).aut.toGAut
        (certifiedThompson Act Tst eProg).aut.toGAut)
      (ψ : UniformBehavioralGAutQuotient
        (certifiedThompson Act Tst h).aut.toGAut
        (certifiedThompson Act Tst fProg).aut.toGAut),
      φ.mapState none = none ∧ ψ.mapState none = none :=
  ⟨hProg, phi, psi, rfl, rfl⟩

/-- Non-vacuity: the two legs really are usable covers — running them through
    `equivBA_of_cover` re-derives the pair's provable equality, independently of the
    syntactic derivation in `fProg_equivBA_eProg`. -/
theorem equivBA_of_the_span : EquivBA eProg fProg :=
  EquivBA.trans (equivBA_of_cover phi rfl) (EquivBA.symm (equivBA_of_cover psi rfl))

#print axioms phi
#print axioms psi
#print axioms span_for_the_refuting_pair
#print axioms equivBA_of_the_span

end GkatSpanWitness
