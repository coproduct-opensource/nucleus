import GkatGuardedStringProofs

/-!
# The n=2 Uniqueness Axiom holds *semantically* — the frontier is derivability, not truth

GKAT completeness (Schmid–Kappé–Kozen–Silva, ICALP 2021, *Coequations, Coinduction,
and Completeness*) is proven only **relative to the Uniqueness Axiom (UA)** — the
schema "a guarded system of equations has a unique solution" (their Thm 17 / Cor 22
both *assume* UA). The open question is whether **UA follows from the other GKAT
axioms**; the authors write they "think this conjecture might be false." Pham (2026)
proved UA for Thompson automata and reduced completeness to **existence** of a
provable solution; `GkatFrontierProofs` localized the n=2 case to `LeftDistrib`,
which `GkatGuardedStringProofs.left_distrib_not_gkat_theorem` shows is *not* a GKAT
theorem — so the obvious syntactic route to n=2 existence is genuinely blocked.

This file pins down which side of the line the difficulty is on. It proves the
**n=2 (mutual-recursion) instance of UA is semantically valid** in the guarded-string
model: any two solutions of a guarded two-state system

    g₀ ≡ e₀·g₁ +_{b₀} f₀        g₁ ≡ e₁·g₀ +_{b₁} f₁

denote the *same* languages (`two_state_semantic_uniqueness`), given the productivity
side conditions `E(eᵢ) ≡ 0`. The proof is a well-founded induction on string length
in which productivity forces each `eᵢ`-hop to consume ≥1 step, so the mutual
recursion bottoms out.

**Consequence.** The n=2 UA instance is **TRUE** in the standard model — adding it is
sound, it cannot be refuted by the language/guarded-string semantics. So "UA might be
false" must mean **not syntactically derivable**, not semantically false. The frontier
is *provability*, not *truth* — exactly the gap `left_distrib_not_gkat_theorem`
exhibits (a semantically-blocked but not axiom-refuted elimination step).

And `productivity_is_necessary` sharpens *which* model can witness independence:
non-uniqueness needs **non-productivity** (a non-productive loop has two distinct
solutions, exhibited concretely). Since productive systems are forced unique **in the
standard model**, the **standard language model cannot witness the independence** for
productive systems — so any independence proof must use a *non-standard* model (or be
proof-theoretic). It does NOT rule out non-standard countermodels (constructing one is
exactly the open route); it only closes off the standard model.

This does NOT resolve the open problem (derivability of UA); it machine-checks the
standard-model half and localizes where a countermodel could still live, so the
remaining question is
sharp. Axioms `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatUniqFrontier

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- **One equation, one step.** Under productivity of `e`, if `G` and `G'` each solve
    `· ≡ e·H +_{bb} ff` (against possibly-different continuations `H`, `H'`), and `H`,
    `H'` already agree on all strings of length `≤ n`, then `G` and `G'` agree on all
    strings of length `≤ n+1`. The `e`-branch consumes a nonempty prefix (productivity),
    so its continuation is judged at length `≤ n`; the `ff`-branch is shared. -/
theorem uniq_step (n : Nat) (G G' H H' : Exp A T) (bb : BExp T) (e ff : Exp A T)
    (hpe : ∀ a : Atom, ¬ den V e (a, []))
    (hh : ∀ gs, den V G gs ↔ den V (.ite bb (.seq e H) ff) gs)
    (hh' : ∀ gs, den V G' gs ↔ den V (.ite bb (.seq e H') ff) gs)
    (ihH : ∀ (w' : List (A × Atom)) (a' : Atom),
      w'.length ≤ n → (den V H (a', w') ↔ den V H' (a', w')))
    (w : List (A × Atom)) (a : Atom) (hlen : w.length ≤ n + 1) :
    den V G (a, w) ↔ den V G' (a, w) := by
  rw [hh (a, w), hh' (a, w)]
  simp only [den_ite, den_seq]
  have bound : ∀ l1 l2 : List (A × Atom), w = l1 ++ l2 → l1 ≠ [] → l2.length ≤ n := by
    intro l1 l2 hl hne
    have hlen2 : l1.length + l2.length = w.length := by rw [hl, List.length_append]
    have : 0 < l1.length := by
      cases l1 with | nil => exact absurd rfl hne | cons _ _ => exact Nat.succ_pos _
    omega
  constructor
  · rintro (⟨hb, l1, l2, hl, hde, hg⟩ | ⟨hb, hf⟩)
    · have hne : l1 ≠ [] := by rintro rfl; exact hpe a hde
      exact Or.inl ⟨hb, l1, l2, hl, hde, (ihH l2 (lastAtom a l1) (bound l1 l2 hl hne)).mp hg⟩
    · exact Or.inr ⟨hb, hf⟩
  · rintro (⟨hb, l1, l2, hl, hde, hg⟩ | ⟨hb, hf⟩)
    · have hne : l1 ≠ [] := by rintro rfl; exact hpe a hde
      exact Or.inl ⟨hb, l1, l2, hl, hde, (ihH l2 (lastAtom a l1) (bound l1 l2 hl hne)).mpr hg⟩
    · exact Or.inr ⟨hb, hf⟩

/-- **One equation, empty string.** At the empty string the `e`-branch is impossible
    (productivity), so `G` and `G'` both collapse to the shared `¬bb ∧ ff` case. -/
theorem uniq_zero (G G' H H' : Exp A T) (bb : BExp T) (e ff : Exp A T)
    (hpe : ∀ a : Atom, ¬ den V e (a, []))
    (hh : ∀ gs, den V G gs ↔ den V (.ite bb (.seq e H) ff) gs)
    (hh' : ∀ gs, den V G' gs ↔ den V (.ite bb (.seq e H') ff) gs)
    (a : Atom) : den V G (a, []) ↔ den V G' (a, []) := by
  rw [hh (a, []), hh' (a, [])]
  simp only [den_ite, den_seq]
  constructor
  · rintro (⟨_, l1, l2, hl, hde, _⟩ | h)
    · obtain ⟨rfl, rfl⟩ : l1 = [] ∧ l2 = [] := by simpa using hl.symm
      exact absurd hde (hpe a)
    · exact Or.inr h
  · rintro (⟨_, l1, l2, hl, hde, _⟩ | h)
    · obtain ⟨rfl, rfl⟩ : l1 = [] ∧ l2 = [] := by simpa using hl.symm
      exact absurd hde (hpe a)
    · exact Or.inr h

/-- **The n=2 Uniqueness Axiom is semantically valid.** Any two solutions of the
    guarded two-state (mutually-recursive) system

        g₀ ≡ e₀·g₁ +_{b₀} f₀        g₁ ≡ e₁·g₀ +_{b₁} f₁

    denote equal languages, given productivity `E(e₀) ≡ 0 ≡ E(e₁)`. Well-founded
    induction on string length; productivity forces each hop to consume ≥1 step, so
    the two equations bottom out together. Hence UA (at n=2) is TRUE in the standard
    model — the open question about UA is its *derivability*, not its *truth*. -/
theorem two_state_semantic_uniqueness
    {b0 b1 : BExp T} {e0 e1 f0 f1 g0 g1 g0' g1' : Exp A T}
    (hp0 : ∀ a : Atom, ¬ den V e0 (a, [])) (hp1 : ∀ a : Atom, ¬ den V e1 (a, []))
    (hg0 : ∀ gs, den V g0 gs ↔ den V (.ite b0 (.seq e0 g1) f0) gs)
    (hg1 : ∀ gs, den V g1 gs ↔ den V (.ite b1 (.seq e1 g0) f1) gs)
    (hg0' : ∀ gs, den V g0' gs ↔ den V (.ite b0 (.seq e0 g1') f0) gs)
    (hg1' : ∀ gs, den V g1' gs ↔ den V (.ite b1 (.seq e1 g0') f1) gs) :
    (∀ gs, den V g0 gs ↔ den V g0' gs) ∧ (∀ gs, den V g1 gs ↔ den V g1' gs) := by
  suffices H : ∀ (n : Nat) (w : List (A × Atom)) (a : Atom), w.length ≤ n →
      (den V g0 (a, w) ↔ den V g0' (a, w)) ∧ (den V g1 (a, w) ↔ den V g1' (a, w)) by
    refine ⟨fun gs => ?_, fun gs => ?_⟩
    · have := (H gs.2.length gs.2 gs.1 (Nat.le_refl _)).1; simpa using this
    · have := (H gs.2.length gs.2 gs.1 (Nat.le_refl _)).2; simpa using this
  intro n
  induction n with
  | zero =>
      intro w a hlen
      obtain rfl : w = [] := by simpa using Nat.le_zero.mp hlen
      exact ⟨uniq_zero V g0 g0' g1 g1' b0 e0 f0 hp0 hg0 hg0' a,
             uniq_zero V g1 g1' g0 g0' b1 e1 f1 hp1 hg1 hg1' a⟩
  | succ n ih =>
      intro w a hlen
      exact ⟨uniq_step V n g0 g0' g1 g1' b0 e0 f0 hp0 hg0 hg0'
               (fun w' a' h => (ih w' a' h).2) w a hlen,
             uniq_step V n g1 g1' g0 g0' b1 e1 f1 hp1 hg1 hg1'
               (fun w' a' h => (ih w' a' h).1) w a hlen⟩

#print axioms two_state_semantic_uniqueness

-- ── Non-uniqueness needs NON-productivity: the STANDARD model can't witness it ──

/-!
`two_state_semantic_uniqueness` (and its single-state ancestor) turn on the
productivity side condition `E(eᵢ) ≡ 0`: productivity is what makes each loop hop
consume ≥1 step, so the recursion is well-founded and the solution is forced. This
section shows productivity is not decoration — **drop it and semantic uniqueness
fails outright**, exhibiting a single loop with two distinct solutions.

Take `b = prim ()`, body `test b` (so `E(test b) = b ≢ 0` — NOT productive), and
`f = ¬b`. The loop functional `Φ P` fixes `P` to `f` on `¬b`-atoms but leaves it
**free** on `b`-atoms (the body consumes nothing there, so the equation is
`P ⟺ P` at those atoms). Two fixpoints:

  `P1` = accept `(false,[])` only   (the least/`⟦f⟧` solution),
  `P2` = accept every empty string  (extra junk at the `b`-atom).

Both solve; they differ at `(true, [])`. Consequence, read together with the
uniqueness theorems above: in the **standard (guarded-string) model**, semantic
non-uniqueness requires non-productivity.

**Scope — an earlier, stronger claim retracted.** `two_state_semantic_uniqueness`
establishes n=2 UA in the *standard* model only; its well-foundedness comes from
guarded strings being finite. It does **not** show n=2 UA holds in every model of the
GKAT axioms. So this does **not** rule out a countermodel: a model-theoretic
independence proof would construct a *non-standard* model where UA fails, and nothing
here touches that. The honest conclusion is only that **the standard language model
cannot witness the independence** for productive systems — so any independence proof
must use a non-standard model (or be proof-theoretic). Whether such a model exists is
exactly the open question; this does not settle it.
-/

/-- Valuation: the primitive test reads the `Bool` atom. -/
def W0 : Unit → Bool → Bool := fun _ a => a

/-- The tail `f = ¬b`. -/
abbrev Fexp : Exp Unit Unit := .test (.not (.prim ()))

/-- `P` is a solution of the NON-productive loop `g ≡ (test b)·g +_b f`
    (`b = prim ()`, `f = ¬b`): the loop equation with `den g` abstracted to `P`. -/
def SolvesNP (P : GS Unit Bool → Prop) : Prop :=
  ∀ gs : GS Unit Bool, P gs ↔
    ((bval W0 (.prim ()) gs.1 = true ∧
        ∃ l1 l2, gs.2 = l1 ++ l2 ∧ (bval W0 (.prim ()) gs.1 = true ∧ l1 = []) ∧
          P (lastAtom gs.1 l1, l2)) ∨
     (bval W0 (.prim ()) gs.1 = false ∧ den W0 Fexp gs))

/-- Least solution: accept only the empty string at the exit (`¬b`) atom. -/
def P1 : GS Unit Bool → Prop := fun gs => gs.1 = false ∧ gs.2 = []
/-- A strictly larger solution: accept every empty string (junk at the `b` atom). -/
def P2 : GS Unit Bool → Prop := fun gs => gs.2 = []

theorem solves_P1 : SolvesNP P1 := by
  rintro ⟨a, w⟩
  simp only [P1, SolvesNP, bval, W0, den, Fexp]
  cases a with
  | false => simp
  | true =>
      constructor
      · rintro ⟨h, _⟩; exact absurd h (by decide)
      · rintro (⟨_, l1, l2, hl, ⟨_, rfl⟩, hp1, _⟩ | ⟨h, _⟩)
        · exact absurd hp1 (by decide)
        · exact absurd h (by decide)

theorem solves_P2 : SolvesNP P2 := by
  rintro ⟨a, w⟩
  simp only [P2, SolvesNP, bval, W0, den, Fexp]
  cases a with
  | false => simp
  | true =>
      constructor
      · intro hw; exact Or.inl ⟨rfl, [], w, rfl, ⟨rfl, rfl⟩, hw⟩
      · rintro (⟨_, l1, l2, hl, ⟨_, rfl⟩, hp2⟩ | ⟨h, _⟩)
        · simpa using hl.trans (by simpa using hp2)
        · exact absurd h (by decide)

theorem P1_ne_P2 : ¬ (∀ gs, P1 gs ↔ P2 gs) := by
  intro h
  have := (h (true, [])).mpr rfl
  exact absurd this.1 (by decide)

/-- **Productivity is necessary for uniqueness.** The non-productive loop
    `g ≡ (test b)·g +_b (¬b)` has two distinct solutions `P1 ≠ P2` in the
    guarded-string model. With `two_state_semantic_uniqueness` (productive systems
    ARE unique *in the standard model*), this pins standard-model non-uniqueness to
    non-productivity — so the standard language model cannot witness UA's
    independence for productive systems. It does NOT rule out a non-standard
    countermodel (the open route); it only closes off the standard model. -/
theorem productivity_is_necessary :
    SolvesNP P1 ∧ SolvesNP P2 ∧ ¬ (∀ gs, P1 gs ↔ P2 gs) :=
  ⟨solves_P1, solves_P2, P1_ne_P2⟩

#print axioms productivity_is_necessary

end GkatUniqFrontier
