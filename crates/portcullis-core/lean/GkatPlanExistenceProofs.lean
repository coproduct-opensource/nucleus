import GkatDecompProofs

/-! # Toward plan existence: the attack on `DecompCovered`

    `completeness_of_decompCovered` reduced the open problem to one hypothesis.  This
    file opens the attack.  The strategy decomposes `DecompCovered` into:

    * **S1 — the canonical quotient**: for uniformly equivalent `e, f`, the
      start-merging behavioural quotient of the Thompson sum exists.
      - S1a (below, PROVED): the sum's two start states are language-equal at every
        carrier and valuation — the semantic germ of the merge.
      - S1b (open): the quotient construction itself — the sum modulo state language
        equivalence, as a `UniformBehavioralGAutQuotient`.  Technical care: language
        equality gives halt-guard agreement pointwise and derivative-language
        agreement, but step-matching in `GAutBisim` needs the automaton normalized
        (dead-continuation transitions trimmed), the Lean incarnation of the
        harness's trim/canon discipline.
    * **S2 — role existence (the mathematical core, open)**: the canonical quotient's
      states admit `StateRole` witnesses.  Evidence: 100% measured on three exhaustive
      spaces and the sampled frontier; the walk-planner is the constructive skeleton;
      the guarded Caron–Ziadi orbit analogy names the invariants.
    * **S3 — assembly**: from constructive S2, the `qsol` assignment and witnesses
      (definitional given S2's form).

    S1a is proved here; S1b and S2 are the open work, in that order. -/

namespace GkatPlanExistence

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp

variable {A T : Type}

/-- **S1a.  The starts are language-equal.**  Uniform language equivalence of the
    programs transfers along the Thompson start-language theorem and the coproduct
    embeddings: at every carrier and valuation, the sum's two start states accept the
    same guarded strings. -/
theorem sum_starts_language_equal (e f : Exp A T)
    (heq : UniformLanguageEquivalent e f)
    {X : Type} (W : T → X → Bool) :
    autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                       (certifiedThompson A T f).aut.toGAut) (Sum.inl none)
      = autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                           (certifiedThompson A T f).aut.toGAut) (Sum.inr none) := by
  have hl : autLang W (certifiedThompson A T e).aut.toGAut none
      = autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                           (certifiedThompson A T f).aut.toGAut) (Sum.inl none) :=
    autLang_eq_of_gautBisim
      (gAutHom_bisim (GAutHom.inl (certifiedThompson A T e).aut.toGAut
        (certifiedThompson A T f).aut.toGAut) W) rfl
  have hr : autLang W (certifiedThompson A T f).aut.toGAut none
      = autLang W (sumGAut (certifiedThompson A T e).aut.toGAut
                           (certifiedThompson A T f).aut.toGAut) (Sum.inr none) :=
    autLang_eq_of_gautBisim
      (gAutHom_bisim (GAutHom.inr (certifiedThompson A T e).aut.toGAut
        (certifiedThompson A T f).aut.toGAut) W) rfl
  rw [← hl, ← hr, certifiedThompson_start_language, certifiedThompson_start_language]
  funext gs
  exact propext (heq X W gs)

#print axioms sum_starts_language_equal

/-! ## S1b, stage A: the generic valuation and naturality

    Per-valuation step matching from language equality FAILS naively (a continuation
    can be dead at one valuation and live at another).  The rescue: every guard
    evaluation at any `(W, x)` factors through the GENERIC atom `fun t => W t x` of
    the generic valuation `W₀ : T → (T → Bool) → Bool, W₀ t α = α t`.  Consequently
    language equality at `W₀` controls behaviour at every valuation, and the
    quotient's bisimulation obligations reduce to the generic carrier. -/

/-- The generic valuation: atoms are the truth assignments themselves. -/
def genW (T : Type) : T → (T → Bool) → Bool := fun t α => α t

/-- Guard evaluation factors through the generic atom. -/
theorem bval_gen {X : Type} (W : T → X → Bool) (x : X) (g : BExp T) :
    bval W g x = bval (genW T) g (fun t => W t x) := by
  induction g with
  | zero => rfl
  | one => rfl
  | prim t => rfl
  | not b ih => show (! bval W b x) = _; rw [ih]; rfl
  | and b c ihb ihc => show (bval W b x && bval W c x) = _; rw [ihb, ihc]; rfl
  | or b c ihb ihc => show (bval W b x || bval W c x) = _; rw [ihb, ihc]; rfl

theorem firstMatch_gen {X S' : Type} (W : T → X → Bool) (x : X)
    (L : List (BExp T × A × S')) :
    firstMatch W x L = firstMatch (genW T) (fun t => W t x) L := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      show (if bval W g x then _ else _) = (if bval (genW T) g _ then _ else _)
      rw [bval_gen W x g]
      by_cases hg : bval (genW T) g (fun t => W t x)
      · rw [if_pos hg, if_pos hg]
      · rw [if_neg hg, if_neg hg]; exact ih

/-- Step evaluation factors through the generic atom. -/
theorem autStep_gen {X S' : Type} (aut : GAut S' A T) (W : T → X → Bool) (x : X)
    (s : S') :
    autStep W aut s x = autStep (genW T) aut s (fun t => W t x) :=
  firstMatch_gen W x (aut.trans s)

/-- Runs factor through the generic valuation: a `(W, x)`-run is exactly a generic run
    of the pointwise-translated string. -/
theorem autRun_gen {X S' : Type} (aut : GAut S' A T) (W : T → X → Bool)
    (l : List (A × X)) (s : S') (x : X) :
    autRun W aut s x l
      ↔ autRun (genW T) aut s (fun t => W t x)
          (l.map (fun p => (p.1, fun t => W t p.2))) := by
  induction l generalizing s x with
  | nil =>
      show (bval W (aut.hlt s) x = true) ↔ (bval (genW T) (aut.hlt s) _ = true)
      rw [bval_gen W x (aut.hlt s)]
  | cons p w ih =>
      obtain ⟨q, x'⟩ := p
      show (∃ s', autStep W aut s x = some (q, s') ∧ autRun W aut s' x' w) ↔ _
      rw [autStep_gen aut W x s]
      exact ⟨fun ⟨s', h1, h2⟩ => ⟨s', h1, (ih s' x').mp h2⟩,
             fun ⟨s', h1, h2⟩ => ⟨s', h1, (ih s' x').mpr h2⟩⟩

/-- Uniform state-language equivalence (the quotient relation of S1b). -/
def UniformStateEquiv (aut : GAut S A T) (s t : S) : Prop :=
  ∀ (X : Type) (W : T → X → Bool), autLang W aut s = autLang W aut t

/-- Language equality at the GENERIC valuation already gives uniform equivalence. -/
theorem uniformStateEquiv_of_gen {aut : GAut S A T} {s t : S}
    (h : autLang (genW T) aut s = autLang (genW T) aut t) :
    UniformStateEquiv aut s t := by
  intro X W
  funext gs
  obtain ⟨x, l⟩ := gs
  show autRun W aut s x l = autRun W aut t x l
  apply propext
  rw [autRun_gen aut W l s x, autRun_gen aut W l t x]
  exact iff_of_eq
    (congrFun h ((fun t => W t x),
      l.map (fun p : A × X => (p.1, fun t => W t p.2))))

/-- Halt guards agree across uniformly equivalent states (length-zero strings). -/
theorem hlt_of_uniformStateEquiv {aut : GAut S A T} {s t : S}
    (h : UniformStateEquiv aut s t) {X : Type} (W : T → X → Bool) (x : X) :
    bval W (aut.hlt s) x = bval W (aut.hlt t) x := by
  have hP : (bval W (aut.hlt s) x = true) ↔ (bval W (aut.hlt t) x = true) :=
    iff_of_eq (congrFun (h X W) (x, ([] : List (A × X))))
  cases hbs : bval W (aut.hlt s) x <;> cases hbt : bval W (aut.hlt t) x
  · rfl
  · have hc := hP.mpr hbt
    rw [hbs] at hc
    exact Bool.noConfusion hc
  · have hc := hP.mp hbs
    rw [hbt] at hc
    exact Bool.noConfusion hc
  · rfl

theorem UniformStateEquiv.refl (aut : GAut S A T) (s : S) :
    UniformStateEquiv aut s s := fun _ _ => rfl

theorem UniformStateEquiv.symm {aut : GAut S A T} {s t : S}
    (h : UniformStateEquiv aut s t) : UniformStateEquiv aut t s :=
  fun X W => (h X W).symm

theorem UniformStateEquiv.trans {aut : GAut S A T} {s t u : S}
    (h1 : UniformStateEquiv aut s t) (h2 : UniformStateEquiv aut t u) :
    UniformStateEquiv aut s u :=
  fun X W => (h1 X W).trans (h2 X W)

/-! ## S1b, stage A': step matching under liveness

    The counterexample to naive step matching is a SILENT transition: a step to a
    state with empty language, invisible to language equality.  Liveness of step
    targets (the trim/normalization invariant) is exactly the hypothesis that
    excludes it — and then language equality matches steps on the nose. -/

/-- A state is live when its generic language is nonempty. -/
def Live (aut : GAut S A T) (s : S) : Prop :=
  ∃ (α : T → Bool) (l : List (A × (T → Bool))), autRun (genW T) aut s α l

/-- Trimmedness: every generic step lands on a live state (no silent transitions). -/
def LiveSteps (aut : GAut S A T) : Prop :=
  ∀ s (α : T → Bool) (q : A) (s' : S),
    autStep (genW T) aut s α = some (q, s') → Live aut s'

/-- **Step matching.**  On a trimmed automaton, uniformly equivalent states match
    generic steps exactly: same action letter, uniformly equivalent targets. -/
theorem step_match {aut : GAut S A T} (hl : LiveSteps aut) {s t : S}
    (h : UniformStateEquiv aut s t) {α : T → Bool} {q : A} {s' : S}
    (hs : autStep (genW T) aut s α = some (q, s')) :
    ∃ t', autStep (genW T) aut t α = some (q, t') ∧ UniformStateEquiv aut s' t' := by
  obtain ⟨β, l, hrun⟩ := hl s α q s' hs
  have hmem : autRun (genW T) aut s α ((q, β) :: l) := ⟨s', hs, hrun⟩
  have hmem' : ∃ t', autStep (genW T) aut t α = some (q, t')
      ∧ autRun (genW T) aut t' β l :=
    (iff_of_eq (congrFun (h _ (genW T)) (α, (q, β) :: l))).mp hmem
  obtain ⟨t', ht, _⟩ := hmem'
  refine ⟨t', ht, uniformStateEquiv_of_gen ?_⟩
  funext gs
  obtain ⟨γ, w⟩ := gs
  show autRun (genW T) aut s' γ w = autRun (genW T) aut t' γ w
  apply propext
  constructor
  · intro hw
    have hsrun : autRun (genW T) aut s α ((q, γ) :: w) := ⟨s', hs, hw⟩
    have htrun : ∃ t'', autStep (genW T) aut t α = some (q, t'')
        ∧ autRun (genW T) aut t'' γ w :=
      (iff_of_eq (congrFun (h _ (genW T)) (α, (q, γ) :: w))).mp hsrun
    obtain ⟨t'', ht'', hw'⟩ := htrun
    have hpair : (q, t') = (q, t'') := Option.some.inj (ht.symm.trans ht'')
    have hts : t' = t'' := congrArg Prod.snd hpair
    rw [hts]
    exact hw'
  · intro hw
    have htrun : autRun (genW T) aut t α ((q, γ) :: w) := ⟨t', ht, hw⟩
    have hsrun : ∃ s'', autStep (genW T) aut s α = some (q, s'')
        ∧ autRun (genW T) aut s'' γ w :=
      (iff_of_eq (congrFun (h _ (genW T)) (α, (q, γ) :: w))).mpr htrun
    obtain ⟨s'', hs'', hw'⟩ := hsrun
    have hpair : (q, s') = (q, s'') := Option.some.inj (hs.symm.trans hs'')
    have hss : s' = s'' := congrArg Prod.snd hpair
    rw [hss]
    exact hw'

/-- **The stage-A capstone.**  On a trimmed automaton, uniform state equivalence is a
    bisimulation at EVERY carrier and valuation — precisely the `bisim_graph` shape
    a `UniformBehavioralGAutQuotient` demands, before quotient bookkeeping. -/
theorem uniformStateEquiv_bisim {aut : GAut S A T} (hl : LiveSteps aut)
    (X : Type) (W : T → X → Bool) :
    GAutBisim W aut aut (UniformStateEquiv aut) := by
  intro s t h
  refine ⟨fun x => hlt_of_uniformStateEquiv h W x, ?_, ?_⟩
  · intro x q s' hs
    rw [autStep_gen] at hs
    obtain ⟨t', ht, h'⟩ := step_match hl h hs
    exact ⟨t', by rw [autStep_gen]; exact ht, h'⟩
  · intro x q t' ht
    rw [autStep_gen] at ht
    obtain ⟨s', hs, h'⟩ := step_match hl h.symm ht
    exact ⟨s', by rw [autStep_gen]; exact hs, h'.symm⟩

#print axioms uniformStateEquiv_bisim

end GkatPlanExistence
