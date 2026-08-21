import GkatDecompProofs
import GkatDeadExitElimProofs

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

    S1 is done modulo S0; S0 and S2 are the open work.

    LATER (see `GkatTrimProofs`): the summit was rewired — trim the AUTOMATON,
    not the program; `completeness_of_roleCovered` reduces the open problem to
    role existence alone.  This file additionally carries the S2 strata:
    `dag_roles` (acyclic), `selfloop_dag_roles`, `selfarm_roles`, and
    `singleton_scc_roles` (the complete 1-cycle theorem). -/

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

/-! ## S2, the self-loop stratum

    One rung up from acyclic: every cycle is a head-position self-loop.  The
    solution is defined by well-founded recursion on a rank; self-loop states
    take the Salomaa closed form `(wh g p)·rest` and close by the `selfLoop`
    role (no side conditions), everything else folds. -/

/-- The Salomaa fold over a transition list (definitionally `eqRHS`). -/
def foldTL (sol : S → Exp A T) (h : BExp T)
    (L : List (BExp T × A × S)) : Exp A T :=
  L.foldr (fun t acc => Exp.ite t.1 (.seq (.act t.2.1) (sol t.2.2)) acc)
    (.test h)

theorem eqRHS_foldTL (aut : GAut S A T) (sol : S → Exp A T) (s : S) :
    eqRHS aut sol s = foldTL sol (aut.hlt s) (aut.trans s) := rfl

private theorem foldTL_congr {sol₁ sol₂ : S → Exp A T} (h : BExp T) :
    ∀ L : List (BExp T × A × S), (∀ e ∈ L, sol₁ e.2.2 = sol₂ e.2.2) →
    foldTL sol₁ h L = foldTL sol₂ h L := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons hd tl ih =>
      intro hL
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol₁ hd.2.2)) (foldTL sol₁ h tl)
        = Exp.ite hd.1 (.seq (.act hd.2.1) (sol₂ hd.2.2)) (foldTL sol₂ h tl)
      rw [hL hd (by simp), ih (fun e he => hL e (by simp [he]))]

open Classical in
/-- The recursion body: Salomaa closed form at a head self-arm, fold
    otherwise. -/
noncomputable def slBody (hlt : BExp T) (self : S) (solAt : S → Exp A T) :
    List (BExp T × A × S) → Exp A T
  | [] => .test hlt
  | (g, p, t) :: rest =>
      if t = self then .seq (.wh g (.act p)) (foldTL solAt hlt rest)
      else foldTL solAt hlt ((g, p, t) :: rest)

open Classical in
private theorem slBody_cons (hlt : BExp T) (self : S) (solAt : S → Exp A T)
    (g : BExp T) (p : A) (t : S) (rest : List (BExp T × A × S)) :
    slBody hlt self solAt ((g, p, t) :: rest)
      = if t = self then .seq (.wh g (.act p)) (foldTL solAt hlt rest)
        else foldTL solAt hlt ((g, p, t) :: rest) := rfl

open Classical in
/-- The self-loop-stratum solution, by well-founded recursion on the rank. -/
noncomputable def slSol (aut : GAut S A T) (rank : S → Nat) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    slBody (aut.hlt s) s (fun t =>
      if h : rank t < rank s then rec t h else .test .zero) (aut.trans s))

open Classical in
theorem slSol_eq (aut : GAut S A T) (rank : S → Nat) (s : S) :
    slSol aut rank s = slBody (aut.hlt s) s (fun t =>
      if _ : rank t < rank s then slSol aut rank t else .test .zero)
      (aut.trans s) := by
  unfold slSol
  rw [WellFounded.fix_eq]

open Classical in
/-- **The self-loop stratum of S2**: if every state's dispatch either descends
    strictly in rank or begins with a self-arm and then descends, the automaton
    is fully role-covered. -/
theorem selfloop_dag_roles (aut : GAut S A T) (rank : S → Nat)
    (hshape : ∀ s ∈ aut.states,
      (∀ e ∈ aut.trans s, rank e.2.2 < rank s) ∨
      (∃ g p rest, aut.trans s = (g, p, s) :: rest ∧
        ∀ e ∈ rest, rank e.2.2 < rank s)) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨slSol aut rank, fun s hs => ?_⟩
  rcases hshape s hs with hlow | ⟨g, p, rest, htr, hlow⟩
  · -- fold role
    refine StateRole.fold ?_
    rw [slSol_eq, eqRHS_foldTL]
    cases htr : aut.trans s with
    | nil => rfl
    | cons hd tl =>
        obtain ⟨g, p, t⟩ := hd
        have hts : ¬ (t = s) := by
          intro hteq
          have hlt := hlow (g, p, t) (by rw [htr]; simp)
          rw [hteq] at hlt
          exact Nat.lt_irrefl _ hlt
        rw [slBody_cons, if_neg hts]
        refine foldTL_congr (aut.hlt s) ((g, p, t) :: tl) ?_
        intro e he
        rw [dif_pos (hlow e (by rw [htr]; exact he))]
  · -- self-loop role
    have hsol : slSol aut rank s
        = .seq (.wh g (.act p))
            (foldTL (slSol aut rank) (aut.hlt s) rest) := by
      rw [slSol_eq, htr, slBody_cons, if_pos rfl]
      refine congrArg (Exp.seq (.wh g (.act p))) ?_
      refine foldTL_congr (aut.hlt s) rest ?_
      intro e he
      rw [dif_pos (hlow e he)]
    refine StateRole.selfLoop g p
      (foldTL (slSol aut rank) (aut.hlt s) rest) hsol ?_
    rw [eqRHS_foldTL, htr]
    rfl

#print axioms selfloop_dag_roles

/-! ## S2, the gathering stratum: self-arms in ANY position

    The commutation law `ite g₁ A (ite g₂ B C) ≡ ite (g₂∧¬g₁) B (ite g₁ A C)`
    (three axiom applications) walks a self-arm to the head, conjoining the
    negations of the guards it crosses.  With it, a state whose dispatch holds
    ONE self-arm anywhere is a `salomaaE` state. -/

/-- **Arm commutation**: a later arm may jump an earlier one at the price of
    conjoining the earlier guard's negation.  `u2`, `u3`, `u2`, `dneg`. -/
theorem arm_commute (g₁ g₂ : BExp T) (A₁ B C : Exp A T) :
    EquivBA (.ite g₁ A₁ (.ite g₂ B C))
      (.ite (.and g₂ (.not g₁)) B (.ite g₁ A₁ C)) := by
  refine EquivBA.trans (EquivBA.base (Equiv.u2 g₁ A₁ (.ite g₂ B C))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.u3 g₂ (.not g₁) B C A₁)) ?_
  refine EquivBA.ite_c (EquivBA.base (Equiv.refl B)) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.u2 (.not g₁) C A₁)) ?_
  exact EquivBA.ite_guard (GkatRingSupport.dneg_bval g₁)

/-- The running disjunction of a prefix's guards. -/
def orGuards : List (BExp T × A × S) → BExp T
  | [] => .zero
  | e :: rest => .or e.1 (orGuards rest)

/-- **Self-arm gathering**: a marked arm walks to the head of the fold, its
    guard conjoined with the negations of everything it crossed. -/
theorem self_arm_gather (sol : S → Exp A T) (h : BExp T) (gs : BExp T) (a : A)
    (t : S) : ∀ (pre post : List (BExp T × A × S)),
    EquivBA (foldTL sol h (pre ++ (gs, a, t) :: post))
      (.ite (.and gs (.not (orGuards pre))) (.seq (.act a) (sol t))
        (foldTL sol h (pre ++ post))) := by
  intro pre
  induction pre with
  | nil =>
      intro post
      show EquivBA (.ite gs (.seq (.act a) (sol t)) (foldTL sol h post)) _
      refine EquivBA.symm (EquivBA.ite_guard ?_)
      intro X W x
      show (bval W gs x && !false) = bval W gs x
      cases bval W gs x <;> rfl
  | cons e₁ pre' ih =>
      intro post
      show EquivBA
        (.ite e₁.1 (.seq (.act e₁.2.1) (sol e₁.2.2))
          (foldTL sol h (pre' ++ (gs, a, t) :: post)))
        (.ite (.and gs (.not (.or e₁.1 (orGuards pre'))))
          (.seq (.act a) (sol t))
          (.ite e₁.1 (.seq (.act e₁.2.1) (sol e₁.2.2))
            (foldTL sol h (pre' ++ post))))
      refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
        (ih post)) ?_
      refine EquivBA.trans (arm_commute e₁.1 (.and gs (.not (orGuards pre')))
        (.seq (.act e₁.2.1) (sol e₁.2.2)) (.seq (.act a) (sol t))
        (foldTL sol h (pre' ++ post))) ?_
      refine EquivBA.ite_guard ?_
      intro X W x
      show ((bval W gs x && !bval W (orGuards pre') x) && !bval W e₁.1 x)
        = (bval W gs x && !(bval W e₁.1 x || bval W (orGuards pre') x))
      cases bval W gs x <;> cases bval W (orGuards pre') x <;>
        cases bval W e₁.1 x <;> rfl

open Classical in
/-- Find the first self-arm of a dispatch list. -/
noncomputable def splitSelf (self : S) :
    List (BExp T × A × S) →
      Option (List (BExp T × A × S) × BExp T × A × List (BExp T × A × S))
  | [] => none
  | (g, a, t) :: rest =>
      if t = self then some ([], g, a, rest)
      else (splitSelf self rest).map
        (fun q => ((g, a, t) :: q.1, q.2.1, q.2.2.1, q.2.2.2))

open Classical in
private theorem splitSelf_cons (self : S) (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) :
    splitSelf self ((g, a, t) :: rest)
      = if t = self then some ([], g, a, rest)
        else (splitSelf self rest).map
          (fun q => ((g, a, t) :: q.1, q.2.1, q.2.2.1, q.2.2.2)) := rfl

open Classical in
/-- `splitSelf` is faithful: it returns the decomposition around the FIRST
    self-arm. -/
theorem splitSelf_spec (self : S) :
    ∀ (L pre : List (BExp T × A × S)) (g : BExp T) (a : A)
      (post : List (BExp T × A × S)),
    splitSelf self L = some (pre, g, a, post) →
    L = pre ++ (g, a, self) :: post := by
  intro L
  induction L with
  | nil => intro pre g a post h; exact nomatch h
  | cons hd rest ih =>
      intro pre g a post h
      obtain ⟨g₁, a₁, t₁⟩ := hd
      rw [splitSelf_cons] at h
      by_cases ht : t₁ = self
      · rw [if_pos ht] at h
        have hp := Option.some.inj h
        rw [show pre = [] from (congrArg (fun q => q.1) hp).symm,
            show g₁ = g from congrArg (fun q => q.2.1) hp,
            show rest = post from congrArg (fun q => q.2.2.2) hp,
            show a₁ = a from congrArg (fun q => q.2.2.1) hp, ht]
        rfl
      · rw [if_neg ht] at h
        cases hs : splitSelf self rest with
        | none => rw [hs] at h; exact nomatch h
        | some q =>
            obtain ⟨pre', g', a', post'⟩ := q
            rw [hs] at h
            have hp := Option.some.inj h
            have hpre : (g₁, a₁, t₁) :: pre' = pre :=
              congrArg (fun q => q.1) hp
            have hg : g' = g := congrArg (fun q => q.2.1) hp
            have ha : a' = a := congrArg (fun q => q.2.2.1) hp
            have hpost : post' = post := congrArg (fun q => q.2.2.2) hp
            rw [← hpre, ← hg, ← ha, ← hpost]
            show (g₁, a₁, t₁) :: rest = (g₁, a₁, t₁) :: (pre' ++ (g', a', self) :: post')
            rw [ih pre' g' a' post' hs]
  -- (the FIRST-arm property is not needed downstream; faithfulness suffices)

open Classical in
/-- If the list really decomposes around a self-arm whose complement never
    targets `self`, `splitSelf` finds exactly that decomposition. -/
theorem splitSelf_complete (self : S) :
    ∀ (pre : List (BExp T × A × S)) (g : BExp T) (a : A)
      (post : List (BExp T × A × S)),
    (∀ e ∈ pre, e.2.2 ≠ self) →
    splitSelf self (pre ++ (g, a, self) :: post) = some (pre, g, a, post) := by
  intro pre
  induction pre with
  | nil =>
      intro g a post _
      show splitSelf self ((g, a, self) :: post) = _
      rw [splitSelf_cons, if_pos rfl]
  | cons hd pre' ih =>
      intro g a post hne
      obtain ⟨g₁, a₁, t₁⟩ := hd
      show splitSelf self ((g₁, a₁, t₁) :: (pre' ++ (g, a, self) :: post)) = _
      rw [splitSelf_cons, if_neg (hne (g₁, a₁, t₁) (by simp)),
          ih g a post (fun e he => hne e (by simp [he]))]
      rfl

open Classical in
/-- The single-self-arm-anywhere solution: the gathered Salomaa closed form when
    a self-arm exists, the fold otherwise. -/
noncomputable def saSol (aut : GAut S A T) (rank : S → Nat) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    let solAt : S → Exp A T := fun t =>
      if h : rank t < rank s then rec t h else .test .zero
    match splitSelf s (aut.trans s) with
    | none => foldTL solAt (aut.hlt s) (aut.trans s)
    | some (pre, g, a, post) =>
        .seq (.wh (.and g (.not (orGuards pre))) (.act a))
          (foldTL solAt (aut.hlt s) (pre ++ post)))

open Classical in
theorem saSol_eq (aut : GAut S A T) (rank : S → Nat) (s : S) :
    saSol aut rank s
      = (match splitSelf s (aut.trans s) with
        | none => foldTL (fun t =>
            if _ : rank t < rank s then saSol aut rank t else .test .zero)
            (aut.hlt s) (aut.trans s)
        | some (pre, g, a, post) =>
            .seq (.wh (.and g (.not (orGuards pre))) (.act a))
              (foldTL (fun t =>
                  if _ : rank t < rank s then saSol aut rank t else .test .zero)
                (aut.hlt s) (pre ++ post))) := by
  unfold saSol
  rw [WellFounded.fix_eq]

open Classical in
/-- **The gathering stratum of S2**: one self-arm ANYWHERE in the dispatch,
    everything else descending, is fully role-covered — the arm walks to the
    head by commutation and closes as a `salomaaE` state. -/
theorem selfarm_roles (aut : GAut S A T) (rank : S → Nat)
    (hshape : ∀ s ∈ aut.states,
      (∀ e ∈ aut.trans s, rank e.2.2 < rank s) ∨
      (∃ pre g a post, aut.trans s = pre ++ (g, a, s) :: post ∧
        (∀ e ∈ pre, rank e.2.2 < rank s) ∧
        (∀ e ∈ post, rank e.2.2 < rank s))) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨saSol aut rank, fun s hs => ?_⟩
  rcases hshape s hs with hlow | ⟨pre, g, a, post, htr, hpre, hpost⟩
  · -- no self-arm can exist: every target descends, so target ≠ s
    have hnone : splitSelf s (aut.trans s) = none := by
      cases hsp : splitSelf s (aut.trans s) with
      | none => rfl
      | some q =>
          obtain ⟨pre, g, a, post⟩ := q
          exfalso
          have hL := splitSelf_spec s (aut.trans s) pre g a post hsp
          have hmem : (g, a, s) ∈ aut.trans s := by
            rw [hL]; simp
          have := hlow (g, a, s) hmem
          exact Nat.lt_irrefl _ this
    refine StateRole.fold ?_
    rw [saSol_eq, hnone, eqRHS_foldTL]
    refine foldTL_congr (aut.hlt s) (aut.trans s) ?_
    intro e he
    rw [dif_pos (hlow e he)]
  · -- gathered Salomaa
    have hne : ∀ e ∈ pre, e.2.2 ≠ s := by
      intro e he heq
      have := hpre e he
      rw [heq] at this
      exact Nat.lt_irrefl _ this
    have hsplit : splitSelf s (aut.trans s) = some (pre, g, a, post) := by
      rw [htr]
      exact splitSelf_complete s pre g a post hne
    have hRESTc : foldTL (fun t =>
          if _ : rank t < rank s then saSol aut rank t else .test .zero)
        (aut.hlt s) (pre ++ post)
        = foldTL (saSol aut rank) (aut.hlt s) (pre ++ post) := by
      refine foldTL_congr (aut.hlt s) (pre ++ post) ?_
      intro e he
      rcases List.mem_append.mp he with h1 | h2
      · rw [dif_pos (hpre e h1)]
      · rw [dif_pos (hpost e h2)]
    have hsol : saSol aut rank s
        = .seq (.wh (.and g (.not (orGuards pre))) (.act a))
            (foldTL (saSol aut rank) (aut.hlt s) (pre ++ post)) := by
      rw [saSol_eq, hsplit]
      exact congrArg _ hRESTc
    refine StateRole.salomaaE (.and g (.not (orGuards pre))) (.act a)
      (foldTL (saSol aut rank) (aut.hlt s) (pre ++ post)) hsol ?_
    rw [eqRHS_foldTL, htr]
    exact self_arm_gather (saSol aut rank) (aut.hlt s) g a s pre post

#print axioms selfarm_roles

/-! ## S2, the singleton-SCC theorem: arbitrary self-loops

    Arms merge as well as commute: `ite G₁ (A·X) (ite G₂ (B·X) R) ≡
    ite (G₁∨G₂) ((ite G₁ A B)·X) R`.  Recursing over the dispatch with the
    commutation and merge laws gathers ALL self-arms into a single guarded
    body, so every state whose cycles are self-loops — any number of self-arms,
    any positions — is a `salomaaE` state.  This subsumes `dag_roles`,
    `selfloop_dag_roles`, and `selfarm_roles`. -/

/-- **Arm merging**: two self-call arms fuse into one guarded body. -/
theorem arms_merge (G₁ G₂ : BExp T) (A₁ B X R : Exp A T) :
    EquivBA (.ite G₁ (.seq A₁ X) (.ite G₂ (.seq B X) R))
      (.ite (.or G₁ G₂) (.seq (.ite G₁ A₁ B) X) R) := by
  have harm1 : EquivBA (.seq (.test G₁) (.seq (.ite G₁ A₁ B) X))
      (.seq (.test G₁) (.seq A₁ X)) := by
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc' (.test G₁)
      (.ite G₁ A₁ B) X) ?_
    refine EquivBA.trans (EquivBA.seq_c
      (GkatGuardedAlgebra.test_seq_ite_of_implies A₁ B
        (GkatRingSupport.himp_self G₁))
      (EquivBA.base (Equiv.refl X))) ?_
    exact EquivBA.base (Equiv.s1 (.test G₁) A₁ X)
  have hinner : EquivBA (.seq (.test (.and (.not G₁) G₂)) (.ite G₁ A₁ B))
      (.seq (.test (.and (.not G₁) G₂)) B) := by
    refine EquivBA.trans (GkatGuardedAlgebra.test_seq_ite
      (.and (.not G₁) G₂) G₁ A₁ B) ?_
    exact GkatDeadExitElim.ite_zero_guard _ _ (fun Y W x => by
      show ((!bval W G₁ x && bval W G₂ x) && bval W G₁ x) = false
      cases bval W G₁ x <;> cases bval W G₂ x <;> rfl)
  have harm2 : EquivBA
      (.seq (.test (.and (.not G₁) G₂)) (.seq (.ite G₁ A₁ B) X))
      (.seq (.test (.and (.not G₁) G₂)) (.seq B X)) := by
    refine EquivBA.trans (GkatGuardedAlgebra.seq_assoc' _ _ X) ?_
    refine EquivBA.trans (EquivBA.seq_c hinner (EquivBA.base (Equiv.refl X))) ?_
    exact EquivBA.base (Equiv.s1 _ B X)
  have helse : EquivBA
      (.seq (.test (.not G₁)) (.ite G₂ (.seq (.ite G₁ A₁ B) X) R))
      (.seq (.test (.not G₁)) (.ite G₂ (.seq B X) R)) := by
    refine EquivBA.trans (GkatGuardedAlgebra.test_seq_ite (.not G₁) G₂ _ R) ?_
    refine EquivBA.trans (GkatResidue.ite_congr_under_guard harm2) ?_
    exact EquivBA.symm (GkatGuardedAlgebra.test_seq_ite (.not G₁) G₂
      (.seq B X) R)
  refine EquivBA.symm ?_
  refine EquivBA.trans (GkatRingSupport.ite_or_split G₁ G₂
    (.seq (.ite G₁ A₁ B) X) R) ?_
  refine EquivBA.trans (GkatResidue.ite_congr_under_guard harm1) ?_
  exact GkatRingSupport.ite_congr_under_else helse

open Classical in
/-- The gathered self-guard of a dispatch (with priority bookkeeping). -/
noncomputable def gGuard (t : S) : List (BExp T × A × S) → BExp T
  | [] => .zero
  | (g, _, u) :: rest =>
      if u = t then .or g (gGuard t rest)
      else .and (gGuard t rest) (.not g)

open Classical in
/-- The gathered self-body of a dispatch. -/
noncomputable def gBody (t : S) : List (BExp T × A × S) → Exp A T
  | [] => .test .zero
  | (g, a, u) :: rest =>
      if u = t then .ite g (.act a) (gBody t rest)
      else gBody t rest

open Classical in
/-- The non-self remainder of a dispatch. -/
noncomputable def gOthers (t : S) :
    List (BExp T × A × S) → List (BExp T × A × S)
  | [] => []
  | (g, a, u) :: rest =>
      if u = t then gOthers t rest
      else (g, a, u) :: gOthers t rest

open Classical in
private theorem gGuard_cons (t : S) (g : BExp T) (a : A) (u : S)
    (rest : List (BExp T × A × S)) :
    gGuard t ((g, a, u) :: rest)
      = if u = t then .or g (gGuard t rest)
        else .and (gGuard t rest) (.not g) := rfl

open Classical in
private theorem gBody_cons (t : S) (g : BExp T) (a : A) (u : S)
    (rest : List (BExp T × A × S)) :
    gBody t ((g, a, u) :: rest)
      = if u = t then .ite g (.act a) (gBody t rest) else gBody t rest := rfl

open Classical in
private theorem gOthers_cons (t : S) (g : BExp T) (a : A) (u : S)
    (rest : List (BExp T × A × S)) :
    gOthers t ((g, a, u) :: rest)
      = if u = t then gOthers t rest
        else (g, a, u) :: gOthers t rest := rfl

open Classical in
theorem gOthers_sub (t : S) :
    ∀ L : List (BExp T × A × S), ∀ e ∈ gOthers t L,
      e ∈ L ∧ e.2.2 ≠ t := by
  intro L
  induction L with
  | nil => intro e he; exact nomatch he
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      intro e he
      rw [gOthers_cons] at he
      by_cases hu : u = t
      · rw [if_pos hu] at he
        obtain ⟨h1, h2⟩ := ih e he
        exact ⟨by simp [h1], h2⟩
      · rw [if_neg hu] at he
        rcases List.mem_cons.mp he with heq | hmem
        · subst heq
          exact ⟨by simp, hu⟩
        · obtain ⟨h1, h2⟩ := ih e hmem
          exact ⟨by simp [h1], h2⟩

open Classical in
/-- **THE GATHERING THEOREM**: every dispatch is provably a single guarded
    self-call over its non-self remainder. -/
theorem multi_gather (sol : S → Exp A T) (h : BExp T) (t : S) :
    ∀ L : List (BExp T × A × S),
    EquivBA (foldTL sol h L)
      (.ite (gGuard t L) (.seq (gBody t L) (sol t))
        (foldTL sol h (gOthers t L))) := by
  intro L
  induction L with
  | nil =>
      exact EquivBA.symm (GkatDeadExitElim.ite_zero_guard _ _
        (fun X W x => rfl))
  | cons hd rest ih =>
      obtain ⟨g, a, u⟩ := hd
      rw [gGuard_cons, gBody_cons, gOthers_cons]
      by_cases hu : u = t
      · subst hu
        rw [if_pos rfl, if_pos rfl, if_pos rfl]
        show EquivBA (.ite g (.seq (.act a) (sol u)) (foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih) ?_
        exact arms_merge g (gGuard u rest) (.act a) (gBody u rest) (sol u)
          (foldTL sol h (gOthers u rest))
      · rw [if_neg hu, if_neg hu, if_neg hu]
        show EquivBA (.ite g (.seq (.act a) (sol u)) (foldTL sol h rest)) _
        refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih) ?_
        exact arm_commute g (gGuard t rest) (.seq (.act a) (sol u))
          (.seq (gBody t rest) (sol t)) (foldTL sol h (gOthers t rest))

open Classical in
/-- The singleton-SCC solution: the gathered Salomaa closed form, everywhere. -/
noncomputable def ssSol (aut : GAut S A T) (rank : S → Nat) : S → Exp A T :=
  (InvImage.wf rank Nat.lt_wfRel.wf).fix (fun s rec =>
    .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
      (foldTL (fun t => if h : rank t < rank s then rec t h else .test .zero)
        (aut.hlt s) (gOthers s (aut.trans s))))

open Classical in
theorem ssSol_eq (aut : GAut S A T) (rank : S → Nat) (s : S) :
    ssSol aut rank s
      = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (fun t =>
              if _ : rank t < rank s then ssSol aut rank t else .test .zero)
            (aut.hlt s) (gOthers s (aut.trans s))) := by
  unfold ssSol
  rw [WellFounded.fix_eq]

open Classical in
/-- **THE SELF-GATHER ROLE** — the atom of every Salomaa stratum in this
    development, extracted.  A state whose solution is its own self-arms
    looped in front of the fold of everything else has a `salomaaE` role
    with NO further hypotheses: `multi_gather` commutes the self-arms to
    the head of the dispatch, and `w3` does the rest.

    Five theorems in this corpus inline this argument
    (`singleton_scc_roles`, `assembly_roles`, `full_assembly_roles`,
    `walked_assembly_roles`, `chord_assembly_roles`).  Any future stratum
    that builds its solution in self-gathered form gets its roles from
    here, so the work of a new stratum is entirely in DEFINING the
    solution — never in discharging the role. -/
theorem self_gather_role (aut : GAut S A T) (sol : S → Exp A T) (s : S)
    (hsol : sol s = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
      (foldTL sol (aut.hlt s) (gOthers s (aut.trans s)))) :
    StateRole aut sol s :=
  StateRole.salomaaE (gGuard s (aut.trans s)) (gBody s (aut.trans s))
    (foldTL sol (aut.hlt s) (gOthers s (aut.trans s))) hsol
    (by
      rw [eqRHS_foldTL]
      exact multi_gather sol (aut.hlt s) s (aut.trans s))

#print axioms self_gather_role

open Classical in
/-- **THE SINGLETON-SCC THEOREM** (S2, complete 1-cycle stratum): an automaton
    whose every cycle is a self-loop — any number of self-arms, any positions —
    is fully role-covered.  Subsumes the acyclic, head-self-loop, and
    single-self-arm strata. -/
theorem singleton_scc_roles (aut : GAut S A T) (rank : S → Nat)
    (hshape : ∀ s ∈ aut.states, ∀ e ∈ aut.trans s,
      e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨ssSol aut rank, fun s hs => ?_⟩
  have hsol : ssSol aut rank s
      = .seq (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
          (foldTL (ssSol aut rank) (aut.hlt s) (gOthers s (aut.trans s))) := by
    rw [ssSol_eq]
    refine congrArg _ (foldTL_congr (aut.hlt s) (gOthers s (aut.trans s)) ?_)
    intro e he
    obtain ⟨heL, hene⟩ := gOthers_sub s (aut.trans s) e he
    rcases hshape s hs e heL with h1 | h2
    · exact absurd h1 hene
    · rw [dif_pos h2]
  exact self_gather_role aut (ssSol aut rank) s hsol

#print axioms singleton_scc_roles

end GkatPlanExistence
