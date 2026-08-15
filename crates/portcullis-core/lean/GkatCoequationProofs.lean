import GkatBehaviorProofs
import GkatDerivativeFiniteProofs

/-!
# The nesting coequation `W` and soundness `{⟦e⟧} ⊆ W` (Prop 6.2, `⊆` half — COMPLETE)

Half of `W = {⟦e⟧}` (Schmid–Kappé–Kozen–Silva, ICALP 2021, Prop 6.2/13) — the covariety
characterization of the GKAT-expressible behaviors, the completeness dual to the
`fig3_inexpressible` result. **Def 6.1**: `W` is the smallest set of behaviors (here:
guarded-string languages) containing the *tests* `{⟦b⟧}` and closed under

  1. sequential composition `L · M`   (`Comp` / `W.comp`),
  2. **derivative closure**: `(∀ (a,q) active, ∂₍ₐ,q₎ L ∈ W) ⟹ L ∈ W`   (`W.deriv`),
  3. the loop `InLoop V b L`   (`W.loop`) — GKAT's concrete `while` closure, the
     GKAT-specific instantiation of the paper's abstract continuation `▷`.

Because `den` denotes each expression constructor by exactly one of these operations
(`den (seq e f)` *is* `Comp ⟦e⟧ ⟦f⟧`; `den (wh b e)` *is* `InLoop V b ⟦e⟧`,
definitionally), soundness `⟦e⟧ ∈ W` is an induction on `e`. The key move is stating it
over *every* derivative `d ∈ derivs e` (`W_derivs_{test,act,seq,ite,wh}`): then the
derivative-closure cases (`act`, `ite` head) draw `W (⟦e'⟧)` for their next-states
straight from the hypothesis — no separate "`W` closed under derivatives" lemma, and the
composition-derivative union / determinism question never arises.

`den_mem_W : ∀ e, W (den e)` assembles the five bricks — the **soundness direction of
Prop 6.2, complete**. Remaining for `W = {⟦e⟧}`: the synthesis half `W ⊆ {⟦e⟧}`.

Axioms `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatCoequation

open GkatSyntax GkatGS GkatDeriv GkatBehavior

variable {A T Atom : Type} (V : T → Atom → Bool)

-- ── Behavior operations (guarded-string languages), read off the `den` clauses ───

/-- The **test behavior** `⟦b⟧`: accept the empty string exactly on `b`-atoms. -/
def testL (b : BExp T) : GS A Atom → Prop := fun gs => bval V b gs.1 = true ∧ gs.2 = []

/-- **Sequential composition** (fusion product) `L · M`: split the string at a fusion
    atom `L` reaches, then `M` continues. This is exactly `den (seq e f)`'s clause. -/
def Comp (L M : GS A Atom → Prop) : GS A Atom → Prop :=
  fun gs => ∃ l1 l2, gs.2 = l1 ++ l2 ∧ L (gs.1, l1) ∧ M (lastAtom gs.1 l1, l2)

/-- The **`(a,q)`-derivative** of a behavior (`GkatBehavior.langDeriv`), reused here. -/
def Deriv (L : GS A Atom → Prop) (a : Atom) (q : A) : GS A Atom → Prop := langDeriv L a q

/-- `(a,q)` is **active** for `L` if `L` actually performs action `q` at atom `a`. -/
def Active (L : GS A Atom → Prop) (a : Atom) (q : A) : Prop := ∃ v, Deriv L a q v

/-- `den (seq e f)` **is** the composition of the parts (definitional). -/
theorem den_seq_comp (e f : Exp A T) : den V (.seq e f) = Comp (den V e) (den V f) := rfl

/-- `den (test b)` **is** the test behavior (definitional). -/
theorem den_test_testL (b : BExp T) : den V (Exp.test b : Exp A T) = testL V b := rfl

-- ── The nesting coequation (Def 6.1; rules 1–2 fragment) ─────────────────────────

/-- **The nesting coequation `W`** (Def 6.1). Smallest set of behaviors containing every
    test `⟦b⟧` and closed under composition, derivative closure, and the loop. The loop
    rule uses GKAT's concrete `while` closure `InLoop` — `den (wh b e)` *is*
    `InLoop V b (den e)` definitionally — in place of the paper's abstract continuation
    `▷` (its GKAT-specific instantiation via `e^(b) = 1 ▷ (ẽ +_b 1)`); the resulting `W`
    is the same set `{⟦e⟧}`. The derivative-closure rule carries the nesting content that
    excludes Fig 3. -/
inductive W : (GS A Atom → Prop) → Prop where
  | gen (b : BExp T) : W (testL V b)
  | comp {L M} : W L → W M → W (Comp L M)
  | deriv {L} : (∀ a q, Active L a q → W (Deriv L a q)) → W L
  | loop (b : BExp T) {L} : W L → W (InLoop V b L)

/-- **`test` case:** `⟦b⟧` is a generator of `W`. -/
theorem W_den_test (b : BExp T) : W V (den V (Exp.test b : Exp A T)) := by
  rw [den_test_testL]; exact W.gen b

/-- **`seq` case:** `W` is closed under composition, and `den (seq e f)` is that
    composition. -/
theorem W_den_seq {e f : Exp A T} (he : W V (den V e)) (hf : W V (den V f)) :
    W V (den V (.seq e f)) := by
  rw [den_seq_comp]; exact W.comp he hf

/-- Every `(a,q)`-derivative of `⟦p⟧` is either inactive (`q ≠ p`) or the accepting
    behavior `⟦1⟧`: `∂₍ₐ,p₎⟦p⟧ = ⟦1⟧`. -/
theorem deriv_act_eq (p : A) (a : Atom) :
    Deriv (den V (Exp.act p : Exp A T)) a p = testL V (BExp.one : BExp T) := by
  funext w
  simp only [Deriv, langDeriv, den, testL, bval, eq_iff_iff]
  constructor
  · rintro ⟨a', b', heq⟩
    rw [Prod.mk.injEq, List.cons.injEq] at heq
    exact ⟨trivial, heq.2.2⟩
  · rintro ⟨_, hw⟩
    exact ⟨a, w.1, by rw [hw]⟩

/-- **`act` case:** `⟦p⟧ ∈ W` by derivative closure — its only active derivative is
    `⟦1⟧ = ⟦true⟧`, a generator. -/
theorem W_den_act (p : A) : W V (den V (Exp.act p : Exp A T)) := by
  apply W.deriv
  intro a q hact
  obtain ⟨v, hv⟩ := hact
  simp only [Deriv, langDeriv, den] at hv
  obtain ⟨a', b', heq⟩ := hv
  rw [Prod.mk.injEq, List.cons.injEq, Prod.mk.injEq] at heq
  obtain ⟨rfl, ⟨rfl, _⟩, _⟩ := heq
  rw [deriv_act_eq]; exact W.gen _

-- ── Strengthened soundness bricks: `W` for every *derivative* of a constructor ───
-- Stated over all of `derivs e`, so the `ite`/`while` derivative-closure cases can
-- draw `W (⟦e'⟧)` for the next-states `e'` straight from the induction hypothesis.

/-- **`test` (strengthened):** every derivative of `⟦b⟧` (just `⟦b⟧`) is in `W`. -/
theorem W_derivs_test (t : BExp T) :
    ∀ d ∈ derivs (Exp.test t : Exp A T), W V (den V d) := by
  intro d hd
  simp only [derivs, List.mem_cons, List.not_mem_nil, or_false] at hd
  subst hd; exact W_den_test V t

/-- **`act` (strengthened):** the derivatives of `⟦p⟧` are `⟦p⟧` and `⟦1⟧`, both in `W`. -/
theorem W_derivs_act (p : A) :
    ∀ d ∈ derivs (Exp.act p : Exp A T), W V (den V d) := by
  intro d hd
  simp only [derivs, List.mem_cons, List.not_mem_nil, or_false] at hd
  rcases hd with rfl | rfl
  · exact W_den_act V p
  · exact W_den_test V _

/-- **`seq` (strengthened):** if every derivative of `e` and of `f` is in `W`, so is
    every derivative of `seq e f` — the `d₀·f` states are compositions, the rest are
    `f`-derivatives. -/
theorem W_derivs_seq {e f : Exp A T}
    (he : ∀ d ∈ derivs e, W V (den V d)) (hf : ∀ d ∈ derivs f, W V (den V d)) :
    ∀ d ∈ derivs (.seq e f), W V (den V d) := by
  intro d hd
  simp only [derivs, List.mem_append, List.mem_map] at hd
  rcases hd with ⟨d0, hd0, rfl⟩ | hdf
  · rw [den_seq_comp]; exact W.comp (he d0 hd0) (hf f (mem_self f))
  · exact hf d hdf

/-- **`ite` case (the task-#1 headline).** If every derivative of `e` and of `f` is in
    `W`, so is every derivative of `ite b e f`. The non-head states are `e`/`f`-
    derivatives (IH); the head `⟦ite b e f⟧` enters by **derivative closure** — each of
    its active `(a,q)`-derivatives is `⟦e'⟧` for a next-state `e'` of `e` (if `a∈b`) or
    of `f`, and `e' ∈ derivs e`/`derivs f`, so `⟦e'⟧ ∈ W` straight from the hypothesis. -/
theorem W_derivs_ite {b : BExp T} {e f : Exp A T}
    (he : ∀ d ∈ derivs e, W V (den V d)) (hf : ∀ d ∈ derivs f, W V (den V d)) :
    ∀ d ∈ derivs (.ite b e f), W V (den V d) := by
  intro d hd
  simp only [derivs, List.mem_cons, List.mem_append] at hd
  rcases hd with rfl | hde | hdf
  · -- head `⟦ite b e f⟧`: derivative closure
    apply W.deriv
    intro a q hact
    obtain ⟨v, hv⟩ := hact
    simp only [Deriv] at hv ⊢
    rw [langDeriv_den] at hv
    obtain ⟨e', hne, _⟩ := hv
    rw [langDeriv_den_step V (.ite b e f) a q hne]
    simp only [next] at hne
    by_cases hb : bval V b a = true
    · rw [if_pos hb] at hne; exact he e' (deriv_mem e hne)
    · rw [if_neg hb] at hne; exact hf e' (deriv_mem f hne)
  · exact he d hde
  · exact hf d hdf

/-- **`while` case (task #2).** If every derivative of `e` is in `W`, so is every
    derivative of `wh b e`. The loop head `⟦wh b e⟧ = InLoop V b ⟦e⟧` enters by the loop
    rule; each body state `e'·⟦wh b e⟧` is a composition of `⟦e'⟧` (`e' ∈ derivs e`, IH)
    with the loop head. -/
theorem W_derivs_wh {b : BExp T} {e : Exp A T}
    (he : ∀ d ∈ derivs e, W V (den V d)) :
    ∀ d ∈ derivs (.wh b e), W V (den V d) := by
  have hwh : W V (den V (Exp.wh b e)) := W.loop b (he e (mem_self e))
  intro d hd
  simp only [derivs, List.mem_cons, List.mem_map] at hd
  rcases hd with rfl | ⟨e', he', rfl⟩
  · exact hwh
  · rw [den_seq_comp]; exact W.comp (he e' he') hwh

/-- **Soundness of the coequation (Prop 6.2, `⊆` half), full form.** Every derivative of
    every expression is in `W` — a clean induction on `e` assembling the five bricks. -/
theorem den_derivs_mem_W : ∀ (e : Exp A T), ∀ d ∈ derivs e, W V (den V d) := by
  intro e
  induction e with
  | act p => exact W_derivs_act V p
  | test t => exact W_derivs_test V t
  | seq e f ihe ihf => exact W_derivs_seq V ihe ihf
  | ite b e f ihe ihf => exact W_derivs_ite V ihe ihf
  | wh b e ihe => exact W_derivs_wh V ihe

/-- **`{⟦e⟧} ⊆ W`.** Every GKAT expression's behavior satisfies the nesting coequation
    — the soundness direction of Prop 6.2, complete. -/
theorem den_mem_W (e : Exp A T) : W V (den V e) :=
  den_derivs_mem_W V e e (mem_self e)

end GkatCoequation
