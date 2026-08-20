import GkatDecompProofs

/-! # Toward plan existence: the attack on `DecompCovered`

    `completeness_of_decompCovered` reduced the open problem to one hypothesis.  This
    file opens the attack.  The strategy decomposes `DecompCovered` into:

    * **S1 — the canonical quotient**: for uniformly equivalent `e, f`, the
      start-merging behavioural quotient of the Thompson sum exists.
      - S1a (below, PROVED): the sum's two start states are language-equal at every
        carrier and valuation — the semantic germ of the merge.
      - S1b (below, PROVED modulo trimmedness): the quotient construction.  The
        right quotient relation is GENERIC BISIMILARITY, not language equality —
        language equality cannot present a bisim quotient in the presence of silent
        transitions.  Everything factors through the generic valuation (stage A);
        every automaton has a canonical bisimilarity quotient with no side
        conditions (stage B, `canonicalQuotient`); and on a TRIMMED sum
        (`LiveSteps`) language equality upgrades to bisimilarity, merging the
        starts via S1a (stage C, `canonical_quotient_merges_starts`).
    * **S0 — the trim hypothesis (open, engineering-mathematics)**: `LiveSteps` for
      the Thompson sum — silent-freeness of Thompson automata of normalized
      programs, plus the dead-code-elimination bridge inside `EquivBA` for
      arbitrary programs.
    * **S2 — role existence (the mathematical core, open)**: the canonical quotient's
      states admit `StateRole` witnesses.  Evidence: 100% measured on three exhaustive
      spaces and the sampled frontier; the walk-planner is the constructive skeleton;
      the guarded Caron–Ziadi orbit analogy names the invariants.
    * **S3 — assembly**: from constructive S2, the `qsol` assignment and witnesses
      (definitional given S2's form).

    S1 is done modulo S0; S0 and S2 are the open work. -/

namespace GkatPlanExistence

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp

variable {S A T : Type}

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

/-! ## S1b, stage B: the canonical quotient — by GENERIC BISIMILARITY

    Design correction, recorded: the quotient relation is generic bisimilarity, not
    language equality.  Language equality is too coarse for a bisim-presented
    quotient in the presence of silent transitions (two dead states with different
    silent letters are language-equal, but no deterministic quotient state can match
    both steps).  Bisimilarity quotients need NO trimming; trimmedness (`LiveSteps`)
    enters exactly once — at the start merge, where the stage-A capstone upgrades
    the starts' language equality (S1a) to bisimilarity. -/

/-- Generic bisimilarity: related by some bisimulation at the generic valuation. -/
def GenBisimilar (aut : GAut S A T) (s t : S) : Prop :=
  ∃ R : S → S → Prop, GAutBisim (genW T) aut aut R ∧ R s t

/-- Equality is a bisimulation. -/
theorem gAutBisim_eq {Atom : Type} (V : T → Atom → Bool) (aut : GAut S A T) :
    GAutBisim V aut aut (fun s t => s = t) := by
  intro s t h
  subst h
  exact ⟨fun _ => rfl,
    fun _ q s' hs => ⟨s', hs, rfl⟩,
    fun _ q s' hs => ⟨s', hs, rfl⟩⟩

/-- The flip of a bisimulation is a bisimulation. -/
theorem gAutBisim_flip {Atom : Type} {V : T → Atom → Bool} {aut : GAut S A T}
    {R : S → S → Prop} (h : GAutBisim V aut aut R) :
    GAutBisim V aut aut (fun s t => R t s) := by
  intro s t hts
  obtain ⟨h1, h2, h3⟩ := h t s hts
  exact ⟨fun a => (h1 a).symm,
    fun a q s' hs => h3 a q s' hs,
    fun a q t' ht => h2 a q t' ht⟩

/-- The composition of bisimulations is a bisimulation. -/
theorem gAutBisim_comp {Atom : Type} {V : T → Atom → Bool} {aut : GAut S A T}
    {R1 R2 : S → S → Prop}
    (h1 : GAutBisim V aut aut R1) (h2 : GAutBisim V aut aut R2) :
    GAutBisim V aut aut (fun s u => ∃ t, R1 s t ∧ R2 t u) := by
  intro s u hsu
  obtain ⟨t, hst, htu⟩ := hsu
  obtain ⟨a1, b1, c1⟩ := h1 s t hst
  obtain ⟨a2, b2, c2⟩ := h2 t u htu
  refine ⟨fun a => (a1 a).trans (a2 a), ?_, ?_⟩
  · intro a q s' hs
    obtain ⟨t', ht, hR1⟩ := b1 a q s' hs
    obtain ⟨u', hu, hR2⟩ := b2 a q t' ht
    exact ⟨u', hu, t', hR1, hR2⟩
  · intro a q u' hu
    obtain ⟨t', ht, hR2⟩ := c2 a q u' hu
    obtain ⟨s', hs, hR1⟩ := c1 a q t' ht
    exact ⟨s', hs, t', hR1, hR2⟩

theorem GenBisimilar.refl (aut : GAut S A T) (s : S) : GenBisimilar aut s s :=
  ⟨fun s t => s = t, gAutBisim_eq (genW T) aut, rfl⟩

theorem GenBisimilar.symm {aut : GAut S A T} {s t : S}
    (h : GenBisimilar aut s t) : GenBisimilar aut t s := by
  obtain ⟨R, hR, hst⟩ := h
  exact ⟨fun a b => R b a, gAutBisim_flip hR, hst⟩

theorem GenBisimilar.trans {aut : GAut S A T} {s t u : S}
    (h1 : GenBisimilar aut s t) (h2 : GenBisimilar aut t u) :
    GenBisimilar aut s u := by
  obtain ⟨R1, hR1, hst⟩ := h1
  obtain ⟨R2, hR2, htu⟩ := h2
  exact ⟨fun a c => ∃ b, R1 a b ∧ R2 b c, gAutBisim_comp hR1 hR2, t, hst, htu⟩

/-- Bisimilarity itself (the union of all bisimulations) is a bisimulation. -/
theorem genBisimilar_bisim (aut : GAut S A T) :
    GAutBisim (genW T) aut aut (GenBisimilar aut) := by
  intro s t h
  obtain ⟨R, hR, hst⟩ := h
  obtain ⟨h1, h2, h3⟩ := hR s t hst
  refine ⟨h1, ?_, ?_⟩
  · intro a q s' hs
    obtain ⟨t', ht, hR'⟩ := h2 a q s' hs
    exact ⟨t', ht, R, hR, hR'⟩
  · intro a q t' ht
    obtain ⟨s', hs, hR'⟩ := h3 a q t' ht
    exact ⟨s', hs, R, hR, hR'⟩

/-- Naturality of bisimulations: a bisimulation at the generic valuation is a
    bisimulation at EVERY carrier and valuation. -/
theorem gAutBisim_of_generic {S1 S2 : Type} {aut1 : GAut S1 A T}
    {aut2 : GAut S2 A T} {R : S1 → S2 → Prop}
    (h : GAutBisim (genW T) aut1 aut2 R) (X : Type) (W : T → X → Bool) :
    GAutBisim W aut1 aut2 R := by
  intro s t hst
  obtain ⟨h1, h2, h3⟩ := h s t hst
  refine ⟨?_, ?_, ?_⟩
  · intro x
    rw [bval_gen W x (aut1.hlt s), bval_gen W x (aut2.hlt t)]
    exact h1 (fun u => W u x)
  · intro x q s' hs
    rw [autStep_gen] at hs
    obtain ⟨t', ht, hR⟩ := h2 _ q s' hs
    exact ⟨t', by rw [autStep_gen]; exact ht, hR⟩
  · intro x q t' ht
    rw [autStep_gen] at ht
    obtain ⟨s', hs, hR⟩ := h3 _ q t' ht
    exact ⟨s', by rw [autStep_gen]; exact hs, hR⟩

/-- The stage-A capstone, restated: on a trimmed automaton, language equality IS
    bisimilarity. -/
theorem genBisimilar_of_uniformStateEquiv {aut : GAut S A T} (hl : LiveSteps aut)
    {s t : S} (h : UniformStateEquiv aut s t) : GenBisimilar aut s t :=
  ⟨UniformStateEquiv aut, uniformStateEquiv_bisim hl (T → Bool) (genW T), h⟩

/-! ### Representatives by choice — no quotient types needed

    A representative function coherent across a class is all the quotient
    construction needs.  `Classical.choose` on the inhabited class predicate gives
    it: coherence is propositional equality of the class predicates (funext +
    propext), and proof irrelevance does the rest. -/

private theorem choose_congr {α : Type} {p q : α → Prop} (hpq : p = q)
    (h1 : ∃ x, p x) (h2 : ∃ x, q x) :
    Classical.choose h1 = Classical.choose h2 := by
  subst hpq; rfl

/-- A representative of each bisimilarity class. -/
noncomputable def bisimRep (aut : GAut S A T) (s : S) : S :=
  Classical.choose (⟨s, GenBisimilar.refl aut s⟩ : ∃ t, GenBisimilar aut s t)

theorem bisimRep_bisim (aut : GAut S A T) (s : S) :
    GenBisimilar aut s (bisimRep aut s) :=
  Classical.choose_spec _

theorem bisimRep_coherent (aut : GAut S A T) {s t : S}
    (h : GenBisimilar aut s t) : bisimRep aut s = bisimRep aut t :=
  choose_congr
    (funext fun _u => propext ⟨fun h1 => h.symm.trans h1, fun h1 => h.trans h1⟩) _ _

/-! ### The quotient automaton -/

/-- `firstMatch` commutes with retargeting the transition list. -/
theorem firstMatch_retarget {Atom S' : Type} (V : T → Atom → Bool) (a : Atom)
    (f : S' → S') (L : List (BExp T × A × S')) :
    firstMatch V a (L.map (fun e => (e.1, e.2.1, f e.2.2)))
      = (firstMatch V a L).map (fun y => (y.1, f y.2)) := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      show (if bval V g a then some (q, f s') else _)
        = (if bval V g a then some (q, s') else _).map _
      by_cases hg : bval V g a
      · rw [if_pos hg, if_pos hg]; rfl
      · rw [if_neg hg, if_neg hg]; exact ih

/-- The canonical quotient automaton: representative states, retargeted
    transitions.  The carrier stays `S`; the quotient lives in the `states` list. -/
noncomputable def bisimQuotAut (aut : GAut S A T) : GAut S A T where
  states := aut.states.map (bisimRep aut)
  hlt := aut.hlt
  trans := fun s => (aut.trans s).map (fun e => (e.1, e.2.1, bisimRep aut e.2.2))
  start := bisimRep aut aut.start

theorem bisimQuotAut_step {Atom : Type} (aut : GAut S A T) (V : T → Atom → Bool)
    (r : S) (a : Atom) :
    autStep V (bisimQuotAut aut) r a
      = (autStep V aut r a).map (fun y => (y.1, bisimRep aut y.2)) :=
  firstMatch_retarget V a (bisimRep aut) (aut.trans r)

/-- The representative graph is a bisimulation at the generic valuation. -/
theorem bisimQuot_bisim_gen (aut : GAut S A T) :
    GAutBisim (genW T) aut (bisimQuotAut aut)
      (fun s q => bisimRep aut s = q) := by
  intro s q hq
  subst hq
  obtain ⟨h1, h2, h3⟩ := genBisimilar_bisim aut s (bisimRep aut s)
    (bisimRep_bisim aut s)
  refine ⟨h1, ?_, ?_⟩
  · intro a q0 s' hs
    obtain ⟨t', ht, hb⟩ := h2 a q0 s' hs
    refine ⟨bisimRep aut t', ?_, bisimRep_coherent aut hb⟩
    rw [bisimQuotAut_step, ht]
    rfl
  · intro a q0 u hu
    rw [bisimQuotAut_step] at hu
    cases hstep : autStep (genW T) aut (bisimRep aut s) a with
    | none =>
        rw [hstep] at hu
        exact nomatch hu
    | some y =>
        obtain ⟨q1, t'⟩ := y
        rw [hstep] at hu
        have hp : (q1, bisimRep aut t') = (q0, u) := Option.some.inj hu
        obtain ⟨s', hs, hb⟩ := h3 a q1 t' hstep
        have hq1 : q1 = q0 := congrArg Prod.fst hp
        have hu' : bisimRep aut t' = u := congrArg Prod.snd hp
        subst hq1
        subst hu'
        exact ⟨s', hs, bisimRep_coherent aut hb⟩

/-- **THE CANONICAL QUOTIENT** (S1b, stage B done): every automaton has a
    behavioural quotient by generic bisimilarity, uniform over all carriers and
    valuations. -/
noncomputable def canonicalQuotient (aut : GAut S A T) :
    UniformBehavioralGAutQuotient aut (bisimQuotAut aut) where
  mapState := bisimRep aut
  maps_states := fun s hs => List.mem_map.mpr ⟨s, hs, rfl⟩
  onto_states := fun _q hq => List.mem_map.mp hq
  bisim_graph := fun X W =>
    gAutBisim_of_generic (bisimQuot_bisim_gen aut) X W

/-! ### Stage C: the start merge -/

open GkatSumQuotient in
/-- **S1b assembled**: for uniformly equivalent programs whose Thompson sum is
    trimmed (`LiveSteps` — no silent transitions), the canonical quotient exists
    and MERGES THE STARTS.  This discharges the quotient half of `DecompCovered`;
    what remains there is role existence (S2) and the trim hypothesis (S0). -/
theorem canonical_quotient_merges_starts (e f : Exp A T)
    (heq : UniformLanguageEquivalent e f)
    (hl : LiveSteps (sumGAut (certifiedThompson A T e).aut.toGAut
                             (certifiedThompson A T f).aut.toGAut)) :
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut) quot),
      π.mapState (Sum.inl none) = π.mapState (Sum.inr none) := by
  refine ⟨_, bisimQuotAut _, canonicalQuotient _, ?_⟩
  apply bisimRep_coherent
  apply genBisimilar_of_uniformStateEquiv hl
  intro X W
  exact sum_starts_language_equal e f heq W

#print axioms canonical_quotient_merges_starts

/-! ## The refutation: `DecompCovered` as stated is FALSE

    The quotient in `DecompCovered` is bisim-presented, and merged starts force the
    two starts bisimilar (compose the graph bisimulation with its converse).  But
    language equality does not imply bisimilarity in the presence of silent
    transitions: `a·0` and `0` are language-equal (both empty), yet Thompson(`a·0`)'s
    start steps at every atom while Thompson(`0`)'s start is stuck, so NO behavioural
    quotient of their sum can merge the starts.  The corrected reduction
    (`DecompCoveredTrim` below) adds the trim hypothesis; the normalization bridge
    (S0) restores full completeness from it. -/

section Refutation

private def eDead : Exp Unit Unit := .seq (.act ()) (.test .zero)
private def fDead : Exp Unit Unit := .test .zero

private theorem eDead_empty {X : Type} (W : Unit → X → Bool) (gs : GS Unit X) :
    ¬ den W eDead gs := by
  intro h
  obtain ⟨l1, l2, _, _, hf⟩ := h
  exact Bool.noConfusion hf.1

private theorem fDead_empty {X : Type} (W : Unit → X → Bool) (gs : GS Unit X) :
    ¬ den W fDead gs := fun h => Bool.noConfusion h.1

/-- **The hypothesis of the conditional summit, refuted.**  `DecompCovered Unit Unit`
    is false: the pair `(a·0, 0)` is uniformly language-equivalent but its Thompson
    sum admits no start-merging behavioural quotient. -/
theorem decompCovered_false : ¬ DecompCovered Unit Unit := by
  intro h
  obtain ⟨Q, quot, π, qsol, _, hstart⟩ := h eDead fDead
    (fun X W gs => ⟨fun he => absurd he (eDead_empty W gs),
                    fun hf => absurd hf (fDead_empty W gs)⟩)
  have hstepL : autStep (fun (_ : Unit) (_ : Unit) => true)
      (sumGAut (certifiedThompson Unit Unit eDead).aut.toGAut
               (certifiedThompson Unit Unit fDead).aut.toGAut)
      (Sum.inl none) ()
      = some ((), Sum.inl (some (Sum.inl ()))) := rfl
  have hstepR : autStep (fun (_ : Unit) (_ : Unit) => true)
      (sumGAut (certifiedThompson Unit Unit eDead).aut.toGAut
               (certifiedThompson Unit Unit fDead).aut.toGAut)
      (Sum.inr none) ()
      = none := rfl
  have hbisim := π.bisim_graph Unit (fun _ _ => true)
  obtain ⟨q', hq, _⟩ :=
    (hbisim (Sum.inl none) (π.mapState (Sum.inl none)) rfl).2.1 () ()
      (Sum.inl (some (Sum.inl ()))) hstepL
  obtain ⟨s', hs, _⟩ :=
    (hbisim (Sum.inr none) (π.mapState (Sum.inl none)) hstart.symm).2.2 () () q' hq
  rw [hstepR] at hs
  exact nomatch hs

end Refutation

/-! ## The corrected reduction: trim as a hypothesis, normalization as the bridge -/

open GkatSumQuotient in
/-- **The corrected plan-existence hypothesis**: `DecompCovered`, restricted to
    pairs whose Thompson sum is trimmed.  This is the version all the measured
    evidence actually supports (the harness trims/canonizes before everything). -/
def DecompCoveredTrim (A T : Type) : Prop :=
  ∀ e f : Exp A T, UniformLanguageEquivalent e f →
    LiveSteps (sumGAut (certifiedThompson A T e).aut.toGAut
                       (certifiedThompson A T f).aut.toGAut) →
    ∃ (Q : Type) (quot : GAut Q A T)
      (π : UniformBehavioralGAutQuotient
            (sumGAut (certifiedThompson A T e).aut.toGAut
                     (certifiedThompson A T f).aut.toGAut) quot)
      (qsol : Q → Exp A T),
      (∀ s ∈ quot.states, StateRole quot qsol s) ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none)

/-- **S0, named**: every program is provably equivalent, in the finite axioms, to
    one whose Thompson automaton is trimmed (no silent transitions). -/
def NormalizationBridge (A T : Type) : Prop :=
  ∀ e : Exp A T, ∃ e' : Exp A T, EquivBA e e' ∧
    LiveSteps (certifiedThompson A T e').aut.toGAut

/-- Liveness transfers into the left summand. -/
theorem live_sum_inl {S₁ S₂ : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    {s : S₁} (h : Live aut₁ s) : Live (sumGAut aut₁ aut₂) (Sum.inl s) := by
  have hlang : autLang (genW T) aut₁ s
      = autLang (genW T) (sumGAut aut₁ aut₂) (Sum.inl s) :=
    autLang_eq_of_gautBisim (gAutHom_bisim (GAutHom.inl aut₁ aut₂) (genW T)) rfl
  obtain ⟨α, l, hr⟩ := h
  exact ⟨α, l, (iff_of_eq (congrFun hlang (α, l))).mp hr⟩

/-- Liveness transfers into the right summand. -/
theorem live_sum_inr {S₁ S₂ : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    {s : S₂} (h : Live aut₂ s) : Live (sumGAut aut₁ aut₂) (Sum.inr s) := by
  have hlang : autLang (genW T) aut₂ s
      = autLang (genW T) (sumGAut aut₁ aut₂) (Sum.inr s) :=
    autLang_eq_of_gautBisim (gAutHom_bisim (GAutHom.inr aut₁ aut₂) (genW T)) rfl
  obtain ⟨α, l, hr⟩ := h
  exact ⟨α, l, (iff_of_eq (congrFun hlang (α, l))).mp hr⟩

/-- Trimmedness of the summands gives trimmedness of the sum. -/
theorem sum_liveSteps {S₁ S₂ : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    (h₁ : LiveSteps aut₁) (h₂ : LiveSteps aut₂) :
    LiveSteps (sumGAut aut₁ aut₂) := by
  intro s α q s' hs
  cases s with
  | inl u =>
      rw [autStep_sumGAut_inl] at hs
      cases hu : autStep (genW T) aut₁ u α with
      | none => rw [hu] at hs; exact nomatch hs
      | some y =>
          obtain ⟨q1, u'⟩ := y
          rw [hu] at hs
          have hp : ((q1 : A), (Sum.inl u' : S₁ ⊕ S₂)) = (q, s') :=
            Option.some.inj hs
          have ht : (Sum.inl u' : S₁ ⊕ S₂) = s' := congrArg Prod.snd hp
          subst ht
          exact live_sum_inl (h₁ u α q1 u' hu)
  | inr u =>
      rw [autStep_sumGAut_inr] at hs
      cases hu : autStep (genW T) aut₂ u α with
      | none => rw [hu] at hs; exact nomatch hs
      | some y =>
          obtain ⟨q1, u'⟩ := y
          rw [hu] at hs
          have hp : ((q1 : A), (Sum.inr u' : S₁ ⊕ S₂)) = (q, s') :=
            Option.some.inj hs
          have ht : (Sum.inr u' : S₁ ⊕ S₂) = s' := congrArg Prod.snd hp
          subst ht
          exact live_sum_inr (h₂ u α q1 u' hu)

open GkatSumQuotient in
/-- **THE CORRECTED CONDITIONAL SUMMIT**: trimmed plan existence plus the
    normalization bridge give UA-free completeness of GKAT over the free Boolean
    algebra.  This replaces `completeness_of_decompCovered`, whose hypothesis is
    refuted above. -/
theorem completeness_of_decompCoveredTrim {A T : Type}
    (h : DecompCoveredTrim A T) (hn : NormalizationBridge A T) :
    FiniteAxiomsCompleteBA A T := by
  intro e f heq
  obtain ⟨e', hee', hle⟩ := hn e
  obtain ⟨f', hff', hlf⟩ := hn f
  have heq' : UniformLanguageEquivalent e' f' := by
    intro X W gs
    exact ((sound_BA W hee' gs).symm.trans (heq X W gs)).trans (sound_BA W hff' gs)
  obtain ⟨Q, quot, π, qsol, hroles, hstart⟩ := h e' f' heq' (sum_liveSteps hle hlf)
  have hef' : EquivBA e' f' :=
    certifiedThompson_uniform_solved_quotient π qsol
      (decomp_solves quot qsol hroles) hstart
  exact EquivBA.trans hee' (EquivBA.trans hef' (EquivBA.symm hff'))

#print axioms decompCovered_false
#print axioms completeness_of_decompCoveredTrim

/-! ## S2, opened: the acyclic case

    Role existence for a canonical quotient must produce a `StateRole` per state.
    The base stratum is acyclic: when the one-step target relation is well-founded,
    the equations solve THEMSELVES — define the solution by well-founded recursion
    and every state is a `fold`.  Rings then enter exactly at the cycles, which is
    the shape the walk-planner measured. -/

/-- The one-step target relation: `t` is a transition target of `s`. -/
def StepRel (aut : GAut S A T) (t s : S) : Prop :=
  ∃ e ∈ aut.trans s, e.2.2 = t

/-- `eqRHS` only reads the solution at transition targets. -/
theorem eqRHS_congr (aut : GAut S A T) {sol₁ sol₂ : S → Exp A T} (s : S)
    (h : ∀ e ∈ aut.trans s, sol₁ e.2.2 = sol₂ e.2.2) :
    eqRHS aut sol₁ s = eqRHS aut sol₂ s := by
  have haux : ∀ L : List (BExp T × A × S), (∀ e ∈ L, sol₁ e.2.2 = sol₂ e.2.2) →
      L.foldr (fun t acc => Exp.ite t.1 (.seq (.act t.2.1) (sol₁ t.2.2)) acc)
          (Exp.test (aut.hlt s))
        = L.foldr (fun t acc => Exp.ite t.1 (.seq (.act t.2.1) (sol₂ t.2.2)) acc)
          (Exp.test (aut.hlt s)) := by
    intro L
    induction L with
    | nil => intro _; rfl
    | cons hd tl ih =>
        intro hL
        show Exp.ite hd.1 (.seq (.act hd.2.1) (sol₁ hd.2.2)) _
          = Exp.ite hd.1 (.seq (.act hd.2.1) (sol₂ hd.2.2)) _
        rw [hL hd (by simp), ih (fun e he => hL e (by simp [he]))]
  exact haux _ h

open Classical in
/-- The self-solving assignment of a well-founded automaton. -/
noncomputable def dagSol (aut : GAut S A T)
    (hwf : WellFounded (StepRel aut)) : S → Exp A T :=
  hwf.fix (fun s rec =>
    eqRHS aut (fun t =>
      if h : StepRel aut t s then rec t h else .test .zero) s)

theorem dagSol_eq (aut : GAut S A T) (hwf : WellFounded (StepRel aut)) (s : S) :
    dagSol aut hwf s = eqRHS aut (dagSol aut hwf) s := by
  unfold dagSol
  rw [WellFounded.fix_eq]
  apply eqRHS_congr
  intro e he
  rw [dif_pos ⟨e, he, rfl⟩]

/-- **The acyclic stratum of S2**: an automaton with a well-founded step relation
    has a full `StateRole` cover — every state a `fold`. -/
theorem dag_roles (aut : GAut S A T) (hwf : WellFounded (StepRel aut)) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s :=
  ⟨dagSol aut hwf, fun s _ => StateRole.fold (dagSol_eq aut hwf s)⟩

#print axioms dag_roles

end GkatPlanExistence
