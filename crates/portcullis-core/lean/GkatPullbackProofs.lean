import GkatCofinalityProofs

/-!
# The pullback, constructed

`GkatCofinality` splits the residual obligation into `SpanExists` (a construction) and
`ThompsonCofinal` (a theorem).  This file discharges the construction: the **fibre product**
of two covers of a common system, with both projections proved to be covers.

Under Stallings' correspondence this is the standard object — `star_bijection` makes an
`InitCover` a covering map of graphs, and the fibre product of two covers is the graph whose
fundamental group is the intersection of theirs.  Here it is built directly.

## The one delicate point

`InitCover`'s coherence conditions are quantified over **every** state, so the carrier has to
be the matched pairs

    Fib φ ψ  =  { (s, t) // φ.map s = ψ.map t }

and not the full product: off the diagonal the two components disagree about halting, and
about whether they step at all.  But `crossTrans` — the lexicographic product of two
transition lists, whose `firstMatch` behaviour is already known — produces *unmatched* target
pairs among its entries.  They are excluded from selection by list **ordering**, not by any
guard being false, so there is no syntactic way to drop them.

The way through is to push every target through a total function `pairUp`, which returns the
genuine matched element where it can and a fixed basepoint elsewhere.  The basepoint is never
observed: `firstMatch_crossTrans` says the product selects exactly the pair of the two
components' own selections, and `matched_core` / `matched_init` below show *that* pair is
always matched — because both components project to the same step of the common target.  So
the junk branch is unreachable in every statement that mentions it, and `InitCover` never has
to be weakened.
-/

namespace GkatPullback

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCofinality

variable {A T : Type}

variable {S₁ S₂ Q : Type} {a : InitializedGAut S₁ A T} {b : InitializedGAut S₂ A T}
  {m : InitializedGAut Q A T}

/-! ## The carrier -/

/-- Matched pairs: the fibre product's states. -/
abbrev Fib (φ : InitCover a m) (ψ : InitCover b m) : Type :=
  { p : S₁ × S₂ // φ.map p.1 = ψ.map p.2 }

/-- A listed matched pair, used only as the value of `pairUp` off the diagonal.  It exists
    whenever `a` has any listed state (`Base.ofMem`), and nothing below observes it. -/
structure Base (φ : InitCover a m) (ψ : InitCover b m) where
  pt : Fib φ ψ
  fst_mem : pt.val.1 ∈ a.core.states
  snd_mem : pt.val.2 ∈ b.core.states

/-- A basepoint exists as soon as `a` lists a state: its image is listed in `m`, and `ψ`
    is onto, so some state of `b` matches it. -/
theorem Base.ofMem (φ : InitCover a m) (ψ : InitCover b m) {u : S₁} (hu : u ∈ a.core.states) :
    Nonempty (Base φ ψ) := by
  obtain ⟨v, hv, hvq⟩ := ψ.onto (φ.map u) (φ.maps u hu)
  exact ⟨⟨⟨(u, v), hvq.symm⟩, hu, hv⟩⟩

/-- Total pairing: the matched element where the pair matches, the basepoint otherwise. -/
noncomputable def pairUp {φ : InitCover a m} {ψ : InitCover b m} (base : Base φ ψ)
    (u : S₁) (v : S₂) : Fib φ ψ :=
  letI := Classical.propDecidable (φ.map u = ψ.map v)
  if h : φ.map u = ψ.map v then ⟨(u, v), h⟩ else base.pt

theorem pairUp_matched {φ : InitCover a m} {ψ : InitCover b m} (base : Base φ ψ)
    {u : S₁} {v : S₂} (h : φ.map u = ψ.map v) :
    pairUp base u v = ⟨(u, v), h⟩ := by
  letI := Classical.propDecidable (φ.map u = ψ.map v)
  simp only [pairUp, dif_pos h]

theorem pairUp_fst {φ : InitCover a m} {ψ : InitCover b m} (base : Base φ ψ)
    {u : S₁} {v : S₂} (h : φ.map u = ψ.map v) : (pairUp base u v).val.1 = u := by
  rw [pairUp_matched base h]

theorem pairUp_snd {φ : InitCover a m} {ψ : InitCover b m} (base : Base φ ψ)
    {u : S₁} {v : S₂} (h : φ.map u = ψ.map v) : (pairUp base u v).val.2 = v := by
  rw [pairUp_matched base h]

/-! ## The selected pair is always matched

    This is what makes the junk branch unobservable.  At a matched source, both components
    project onto the *same* step of `m`, so their selected targets have the same image. -/

theorem matched_init (φ : InitCover a m) (ψ : InitCover b m) {X : Type}
    (W : T → X → Bool) (x : X) {o₁ : A × S₁} {o₂ : A × S₂}
    (h₁ : firstMatch W x a.initTrans = some o₁)
    (h₂ : firstMatch W x b.initTrans = some o₂) :
    φ.map o₁.2 = ψ.map o₂.2 := by
  have e₁ := φ.initStep_eq X W x
  have e₂ := ψ.initStep_eq X W x
  rw [h₁] at e₁
  rw [h₂] at e₂
  simp only [Option.map_some] at e₁ e₂
  have : (some (o₁.1, φ.map o₁.2) : Option (A × Q)) = some (o₂.1, ψ.map o₂.2) := by
    rw [e₁, ← e₂]
  exact congrArg Prod.snd (Option.some.inj this)

theorem matched_core (φ : InitCover a m) (ψ : InitCover b m) {X : Type}
    (W : T → X → Bool) (x : X) (p : Fib φ ψ) {o₁ : A × S₁} {o₂ : A × S₂}
    (h₁ : firstMatch W x (a.core.trans p.val.1) = some o₁)
    (h₂ : firstMatch W x (b.core.trans p.val.2) = some o₂) :
    φ.map o₁.2 = ψ.map o₂.2 := by
  have e₁ := φ.coreStep_eq p.val.1 X W x
  have e₂ := ψ.coreStep_eq p.val.2 X W x
  rw [h₁] at e₁
  rw [h₂] at e₂
  simp only [Option.map_some] at e₁ e₂
  have : (some (o₁.1, φ.map o₁.2) : Option (A × Q)) = some (o₂.1, ψ.map o₂.2) := by
    rw [e₁, p.property, ← e₂]
  exact congrArg Prod.snd (Option.some.inj this)

/-- The two components fire together at the pseudostate. -/
theorem init_fires_together (φ : InitCover a m) (ψ : InitCover b m) {X : Type}
    (W : T → X → Bool) (x : X) :
    (firstMatch W x a.initTrans).isSome = (firstMatch W x b.initTrans).isSome := by
  rw [star_bijection_init φ X W x, star_bijection_init ψ X W x]

/-- The two components fire together at every matched pair. -/
theorem core_fires_together (φ : InitCover a m) (ψ : InitCover b m) {X : Type}
    (W : T → X → Bool) (x : X) (p : Fib φ ψ) :
    (firstMatch W x (a.core.trans p.val.1)).isSome
      = (firstMatch W x (b.core.trans p.val.2)).isSome := by
  rw [star_bijection φ p.val.1 X W x, star_bijection ψ p.val.2 X W x, p.property]

/-! ## The fibre product -/

/-- **The pullback.**  Halting and the pseudostate's guard are read off the left component;
    the right component agrees at every matched pair, which is what makes the *other*
    projection a cover too.  Transitions are `crossTrans`, with targets totalized. -/
noncomputable def pullback (φ : InitCover a m) (ψ : InitCover b m) (base : Base φ ψ) :
    InitializedGAut (Fib φ ψ) A T where
  core := {
    states := a.core.states.flatMap
      (fun u => b.core.states.map (fun v => pairUp base u v))
    hlt := fun p => a.core.hlt p.val.1
    trans := fun p =>
      (crossTrans (a.core.trans p.val.1) (b.core.trans p.val.2)).map
        (fun t => (t.1, t.2.1, pairUp base t.2.2.1 t.2.2.2))
  }
  initHlt := a.initHlt
  initTrans :=
    (crossTrans a.initTrans b.initTrans).map
      (fun t => (t.1, t.2.1, pairUp base t.2.2.1 t.2.2.2))

/-- Every listed state of the pullback is `pairUp` of a listed pair. -/
private theorem mem_states {φ : InitCover a m} {ψ : InitCover b m} (base : Base φ ψ)
    {p : Fib φ ψ} (hp : p ∈ (pullback φ ψ base).core.states) :
    ∃ u v, u ∈ a.core.states ∧ v ∈ b.core.states ∧ p = pairUp base u v := by
  obtain ⟨u, hu, hp⟩ := List.mem_flatMap.mp hp
  obtain ⟨v, hv, hp⟩ := List.mem_map.mp hp
  exact ⟨u, v, hu, hv, hp.symm⟩

/-! ## Both projections are covers -/

/-- **The left projection.** -/
noncomputable def pullbackFst (φ : InitCover a m) (ψ : InitCover b m) (base : Base φ ψ) :
    InitCover (pullback φ ψ base) a where
  map := fun p => p.val.1
  initHlt_eq := fun _ _ _ => rfl
  coreHlt_eq := fun _ _ _ _ => rfl
  initStep_eq := fun X W x => by
    show (firstMatch W x
        ((crossTrans a.initTrans b.initTrans).map
          (fun t => (t.1, t.2.1, pairUp base t.2.2.1 t.2.2.2)))).map
        (fun o => (o.1, o.2.val.1))
      = firstMatch W x a.initTrans
    rw [firstMatch_map_target_to (F := fun q : S₁ × S₂ => pairUp base q.1 q.2),
      firstMatch_crossTrans]
    have hfire := init_fires_together φ ψ W x
    cases h₁ : firstMatch W x a.initTrans with
    | none => cases h₂ : firstMatch W x b.initTrans <;> rfl
    | some o₁ =>
        cases h₂ : firstMatch W x b.initTrans with
        | none => rw [h₁, h₂] at hfire; exact absurd hfire (by simp)
        | some o₂ =>
            simp only [Option.map_some]
            rw [pairUp_fst base (matched_init φ ψ W x h₁ h₂)]
  coreStep_eq := fun p X W x => by
    show (firstMatch W x
        ((crossTrans (a.core.trans p.val.1) (b.core.trans p.val.2)).map
          (fun t => (t.1, t.2.1, pairUp base t.2.2.1 t.2.2.2)))).map
        (fun o => (o.1, o.2.val.1))
      = firstMatch W x (a.core.trans p.val.1)
    rw [firstMatch_map_target_to (F := fun q : S₁ × S₂ => pairUp base q.1 q.2),
      firstMatch_crossTrans]
    have hfire := core_fires_together φ ψ W x p
    cases h₁ : firstMatch W x (a.core.trans p.val.1) with
    | none => cases h₂ : firstMatch W x (b.core.trans p.val.2) <;> rfl
    | some o₁ =>
        cases h₂ : firstMatch W x (b.core.trans p.val.2) with
        | none => rw [h₁, h₂] at hfire; exact absurd hfire (by simp)
        | some o₂ =>
            simp only [Option.map_some]
            rw [pairUp_fst base (matched_core φ ψ W x p h₁ h₂)]
  maps := by
    intro p hp
    obtain ⟨u, v, hu, hv, rfl⟩ := mem_states base hp
    letI := Classical.propDecidable (φ.map u = ψ.map v)
    by_cases h : φ.map u = ψ.map v
    · rw [pairUp_fst base h]; exact hu
    · rw [show pairUp base u v = base.pt by simp only [pairUp, dif_neg h]]
      exact base.fst_mem
  onto := by
    intro q hq
    obtain ⟨v, hv, hvq⟩ := ψ.onto (φ.map q) (φ.maps q hq)
    refine ⟨pairUp base q v, ?_, pairUp_fst base hvq.symm⟩
    exact List.mem_flatMap.mpr ⟨q, hq, List.mem_map.mpr ⟨v, hv, rfl⟩⟩

/-- **The right projection.**  The halting guards are read off the left component, so this
    direction is where the matching proof does visible work. -/
noncomputable def pullbackSnd (φ : InitCover a m) (ψ : InitCover b m) (base : Base φ ψ) :
    InitCover (pullback φ ψ base) b where
  map := fun p => p.val.2
  initHlt_eq := fun X W x => (φ.initHlt_eq X W x).trans (ψ.initHlt_eq X W x).symm
  coreHlt_eq := fun p X W x => by
    refine (φ.coreHlt_eq p.val.1 X W x).trans ?_
    rw [p.property]
    exact (ψ.coreHlt_eq p.val.2 X W x).symm
  initStep_eq := fun X W x => by
    show (firstMatch W x
        ((crossTrans a.initTrans b.initTrans).map
          (fun t => (t.1, t.2.1, pairUp base t.2.2.1 t.2.2.2)))).map
        (fun o => (o.1, o.2.val.2))
      = firstMatch W x b.initTrans
    rw [firstMatch_map_target_to (F := fun q : S₁ × S₂ => pairUp base q.1 q.2),
      firstMatch_crossTrans]
    have hfire := init_fires_together φ ψ W x
    cases h₁ : firstMatch W x a.initTrans with
    | none =>
        cases h₂ : firstMatch W x b.initTrans with
        | none => rfl
        | some o₂ => rw [h₁, h₂] at hfire; exact absurd hfire (by simp)
    | some o₁ =>
        cases h₂ : firstMatch W x b.initTrans with
        | none => rw [h₁, h₂] at hfire; exact absurd hfire (by simp)
        | some o₂ =>
            simp only [Option.map_some]
            rw [pairUp_snd base (matched_init φ ψ W x h₁ h₂)]
            have hact : o₁.1 = o₂.1 := by
              have e₁ := φ.initStep_eq X W x
              have e₂ := ψ.initStep_eq X W x
              rw [h₁] at e₁
              rw [h₂] at e₂
              simp only [Option.map_some] at e₁ e₂
              have : (some (o₁.1, φ.map o₁.2) : Option (A × Q)) = some (o₂.1, ψ.map o₂.2) := by
                rw [e₁, ← e₂]
              exact congrArg Prod.fst (Option.some.inj this)
            rw [hact]
  coreStep_eq := fun p X W x => by
    show (firstMatch W x
        ((crossTrans (a.core.trans p.val.1) (b.core.trans p.val.2)).map
          (fun t => (t.1, t.2.1, pairUp base t.2.2.1 t.2.2.2)))).map
        (fun o => (o.1, o.2.val.2))
      = firstMatch W x (b.core.trans p.val.2)
    rw [firstMatch_map_target_to (F := fun q : S₁ × S₂ => pairUp base q.1 q.2),
      firstMatch_crossTrans]
    have hfire := core_fires_together φ ψ W x p
    cases h₁ : firstMatch W x (a.core.trans p.val.1) with
    | none =>
        cases h₂ : firstMatch W x (b.core.trans p.val.2) with
        | none => rfl
        | some o₂ => rw [h₁, h₂] at hfire; exact absurd hfire (by simp)
    | some o₁ =>
        cases h₂ : firstMatch W x (b.core.trans p.val.2) with
        | none => rw [h₁, h₂] at hfire; exact absurd hfire (by simp)
        | some o₂ =>
            simp only [Option.map_some]
            rw [pairUp_snd base (matched_core φ ψ W x p h₁ h₂)]
            have hact : o₁.1 = o₂.1 := by
              have e₁ := φ.coreStep_eq p.val.1 X W x
              have e₂ := ψ.coreStep_eq p.val.2 X W x
              rw [h₁] at e₁
              rw [h₂] at e₂
              simp only [Option.map_some] at e₁ e₂
              have : (some (o₁.1, φ.map o₁.2) : Option (A × Q)) = some (o₂.1, ψ.map o₂.2) := by
                rw [e₁, p.property, ← e₂]
              exact congrArg Prod.fst (Option.some.inj this)
            rw [hact]
  maps := by
    intro p hp
    obtain ⟨u, v, hu, hv, rfl⟩ := mem_states base hp
    letI := Classical.propDecidable (φ.map u = ψ.map v)
    by_cases h : φ.map u = ψ.map v
    · rw [pairUp_snd base h]; exact hv
    · rw [show pairUp base u v = base.pt by simp only [pairUp, dif_neg h]]
      exact base.snd_mem
  onto := by
    intro q hq
    obtain ⟨u, hu, huq⟩ := φ.onto (ψ.map q) (ψ.maps q hq)
    refine ⟨pairUp base u q, ?_, pairUp_snd base huq⟩
    exact List.mem_flatMap.mpr ⟨u, hu, List.mem_map.mpr ⟨q, hq, rfl⟩⟩

/-! ## The span, delivered -/

/-- **Two covers of a common system span.**  This is `SpanExists`' content, discharged for
    an arbitrary common target: the fibre product covers both sides. -/
theorem span_of_common_target (φ : InitCover a m) (ψ : InitCover b m) (base : Base φ ψ) :
    ∃ (S : Type) (mid : InitializedGAut S A T),
      Nonempty (InitCover mid a) ∧ Nonempty (InitCover mid b) :=
  ⟨Fib φ ψ, pullback φ ψ base, ⟨pullbackFst φ ψ base⟩, ⟨pullbackSnd φ ψ base⟩⟩

/-- **What `SpanExists` still needs.**  A system both Thompson automata cover, together with
    a matched basepoint — and `Base.ofMem` supplies the basepoint from any listed state of
    the left automaton, so the real content is the common target.

    That target is the joint behavioural quotient: two uniformly equivalent programs have the
    same minimised behaviour, and each automaton covers it.  Constructing it is the residue
    of the constructive half; the fibre product above is the part that was delicate. -/
def CommonTarget (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    ∃ (Q : Type) (m : InitializedGAut Q A T)
      (φ : InitCover (certifiedThompson A T e).aut m)
      (ψ : InitCover (certifiedThompson A T f).aut m),
      Nonempty (Base φ ψ)

/-- **The constructive half, reduced.**  A common target yields the span, via the fibre
    product.  So `SpanExists` is no longer an open construction — it is exactly
    `CommonTarget`, which is a statement about behavioural minimisation and mentions neither
    covers-of-covers nor the syntax. -/
theorem spanExists_of_commonTarget (hct : CommonTarget A T) : SpanExists A T := by
  intro e f heq
  obtain ⟨Q, m, φ, ψ, ⟨base⟩⟩ := hct e f heq
  exact ⟨Fib φ ψ, pullback φ ψ base, ⟨pullbackFst φ ψ base⟩, ⟨pullbackSnd φ ψ base⟩⟩

/-- **Completeness, from the two remaining statements.**  `CommonTarget` is a minimisation
    fact; `ThompsonCofinal` is the substantive theorem the search supports.  Everything
    between them is now machine-checked, with no uniqueness axiom anywhere. -/
theorem completeness_of_target_and_cofinality
    (hct : CommonTarget A T) (hcof : ThompsonCofinal A T) :
    FiniteAxiomsCompleteBA A T :=
  completeness_of_halves (spanExists_of_commonTarget hct) hcof

#print axioms pullbackFst
#print axioms pullbackSnd
#print axioms span_of_common_target
#print axioms spanExists_of_commonTarget
#print axioms completeness_of_target_and_cofinality

end GkatPullback
