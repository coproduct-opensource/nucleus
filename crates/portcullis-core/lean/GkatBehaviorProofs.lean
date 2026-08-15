import GkatDerivativeProofs

/-!
# The behavior coalgebra — foundation for the nesting-coequation inexpressibility

**Project (multi-session): the first machine-checked GKAT inexpressibility.** GKAT
expression behaviors are exactly the guarded-string languages satisfying the *nesting
coequation* `W` (Schmid–Kappé–Kozen–Silva, ICALP 2021, Def. 12; Prop. 13:
`W = {⟦e⟧ | e ∈ Exp}`). A language `L ∉ W` is denoted by no expression. Mechanizing
this needs (i) `W` as a predicate on *behaviors* (guarded-string languages with their
derivative structure), (ii) Prop. 13, (iii) a concrete `L ∉ W`. See the plan in
`docs/theory/gkat-inexpressibility-plan.md`.

This file is **milestone 1**: the behavior coalgebra `⟨Lhalt, langDeriv⟩` on languages
and the fact that `den` is a coalgebra homomorphism into it (so `W`, defined over this
structure, can be pushed along `den`). These are `den_nil` / `den_cons` lifted from
"does `⟦e⟧` accept `(a,w)`" to the language's own halt/derivative operations.

  * `Lhalt L a`      — `L` accepts the empty string at atom `a` (the output).
  * `langDeriv L a q` — the `(a,q)`-derivative language: `{v | a·q·v ∈ L}`.
  * `Lhalt_den`      — `Lhalt ⟦e⟧ a ↔ E(e) a`  (den preserves output; = `den_nil`).
  * `langDeriv_den`  — `langDeriv ⟦e⟧ a q = ⟦next e a on q⟧`  (den preserves the
                       transition; = `den_cons`). So `den` is a homomorphism.

Axioms `[propext]`, `sorryAx`-free.
-/

namespace GkatBehavior

open GkatSyntax GkatGS GkatDeriv

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- The **output** of a language at an atom: does it accept the empty string there? -/
def Lhalt (L : GS A Atom → Prop) (a : Atom) : Prop := L (a, [])

/-- The **`(a,q)`-derivative** of a language: the residual after reading atom `a` then
    action `q`. `langDeriv L a q` accepts `v` iff `L` accepts `a·q·v`. -/
def langDeriv (L : GS A Atom → Prop) (a : Atom) (q : A) : GS A Atom → Prop :=
  fun v => L (a, (q, v.1) :: v.2)

/-- **`den` preserves outputs.** `⟦e⟧` halts at `a` iff `E(e)` holds there. (= `den_nil`) -/
theorem Lhalt_den (e : Exp A T) (a : Atom) :
    Lhalt (den V e) a ↔ bval V (E e) a = true := den_nil V e a

/-- **`den` preserves transitions.** The `(a,q)`-derivative of `⟦e⟧` is the language of
    the expression `e` steps to on `(a,q)` — the residual `e'` when `next e a = some
    (q,e')`, and the empty language otherwise. (= `den_cons`) So `den : Exp → Behavior`
    is a coalgebra homomorphism `⟨E, next⟩ → ⟨Lhalt, langDeriv⟩`. -/
theorem langDeriv_den (e : Exp A T) (a : Atom) (q : A) (v : GS A Atom) :
    langDeriv (den V e) a q v ↔ ∃ e', next V e a = some (q, e') ∧ den V e' v := by
  obtain ⟨a', w⟩ := v; exact den_cons V e a q a' w

/-- Corollary: when `e` steps on `(a,q)` to `e'`, the derivative language is exactly
    `⟦e'⟧` — the deterministic transition of the behavior. -/
theorem langDeriv_den_step (e : Exp A T) (a : Atom) (q : A) {e' : Exp A T}
    (hne : next V e a = some (q, e')) : langDeriv (den V e) a q = den V e' := by
  funext v; apply propext
  rw [langDeriv_den]
  constructor
  · rintro ⟨e'', hne'', hd⟩
    rw [hne, Option.some.injEq, Prod.mk.injEq] at hne''; obtain ⟨_, rfl⟩ := hne''; exact hd
  · intro hd; exact ⟨e', hne, hd⟩

#print axioms Lhalt_den
#print axioms langDeriv_den

end GkatBehavior
