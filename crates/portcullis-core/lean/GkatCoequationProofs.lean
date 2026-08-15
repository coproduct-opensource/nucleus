import GkatBehaviorProofs

/-!
# The nesting coequation `W` and soundness `{⟦e⟧} ⊆ W` (Prop 6.2, `⊆` half)

Toward `W = {⟦e⟧}` (Schmid–Kappé–Kozen–Silva, ICALP 2021, Prop 6.2/13) — the covariety
characterization of the GKAT-expressible behaviors, the completeness dual to the
`fig3_inexpressible` result. **Def 6.1**: `W` is the smallest set of behaviors (here:
guarded-string languages) containing the *tests* `{⟦b⟧}` and closed under

  1. sequential composition `L · M`   (`Comp`),
  2. **derivative closure**: `(∀ (a,q) active, ∂₍ₐ,q₎ L ∈ W) ⟹ L ∈ W`   (`W.deriv`),
  3. continuation `L ▷ M`   (the loop primitive — pending).

Because `den` denotes each expression constructor by exactly one of these operations
(`den (seq e f)` *is* the fusion product `Comp ⟦e⟧ ⟦f⟧`, definitionally), soundness
`⟦e⟧ ∈ W` is an induction on `e`. This file establishes the operations, `W`, and the
three cases that need only rules 1–2: **`test`** (a generator), **`act`** (`∂⟦p⟧ = ⟦1⟧`,
so `⟦p⟧ ∈ W` by derivative closure), and **`seq`** (composition). The `ite` case (via
derivative closure, needing `W` closed under derivatives) and the `while` case (via `▷`
and the key identity `e^(b) = 1 ▷ (ẽ +_b 1)`) are the next bricks.

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

/-- **The nesting coequation `W`** (Def 6.1, sequential + derivative-closure rules).
    Smallest set of behaviors containing every test `⟦b⟧` and closed under composition
    and derivative closure. (The continuation rule `▷` is added with the `while` case.) -/
inductive W : (GS A Atom → Prop) → Prop where
  | gen (b : BExp T) : W (testL V b)
  | comp {L M} : W L → W M → W (Comp L M)
  | deriv {L} : (∀ a q, Active L a q → W (Deriv L a q)) → W L

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

end GkatCoequation
