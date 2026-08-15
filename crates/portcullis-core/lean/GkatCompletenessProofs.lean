import GkatDerivativeProofs

/-!
# Bisimilarity = language equivalence — the completeness direction

`GkatBisimulationProofs.bisim_sound` gave the soundness half of the coinductive
characterization (bisimilar ⟹ equivalent). This file completes it: language
equivalence is **itself** a bisimulation, so `⟦e⟧ = ⟦f⟧` iff a bisimulation relates
`e` and `f`.

The subtlety a naive bisimulation trips on is **dead residuals**: `e` can step via `q`
to a residual `e'` with *empty* language while `f` does not step via `q` at all — yet
`e` and `f` are still language-equivalent (both reject every `q`-string). The fix is
bisimulation **up to emptiness** (`BisimUpTo`): a step need only be matched *or* lead
to an empty residual. Then

  * `bisim_upto_sound` : `BisimUpTo R → R e f → ⟦e⟧ = ⟦f⟧` — the dead case is
    discharged by contradiction (a residual that accepts a string cannot be empty),
  * `langEq_is_bisim_upto` : language equivalence is a `BisimUpTo` — completeness,
  * `bisim_upto_iff` : `⟦e⟧ = ⟦f⟧ ↔ ∃ R, BisimUpTo R ∧ R e f`.

Together with `GkatDerivativeFiniteProofs.derivs_closed` (the reachable pairs live in
the finite `derivs e × derivs f`) this is exactly the theory a decision procedure
executes: search that finite square for an up-to-emptiness bisimulation. Assembling
the runnable `Decidable (⟦e⟧=⟦f⟧)` additionally needs a `Fintype` atom set and
decidable emptiness (empty iff no reachable derivative halts) — a bounded engineering
layer on top of the pieces now all present.

Axioms `[propext]`, `sorryAx`-free.
-/

namespace GkatComplete

open GkatSyntax GkatGS GkatDeriv

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- Language equivalence: `e` and `f` accept exactly the same guarded strings. -/
def langEq (e f : Exp A T) : Prop := ∀ gs : GS A Atom, den V e gs ↔ den V f gs

/-- `e` accepts no guarded string. -/
def Lempty (e : Exp A T) : Prop := ∀ gs : GS A Atom, ¬ den V e gs

/-- Stepping is deterministic membership: after `e` steps at `a` via `q` to `e'`,
    `e` accepts `(a,(q,a')::w)` iff `e'` accepts `(a',w)`. -/
theorem den_cons_step {e e' : Exp A T} {a : Atom} {q : A} {a' : Atom} {w : List (A × Atom)}
    (hne : next V e a = some (q, e')) :
    den V e (a, (q, a') :: w) ↔ den V e' (a', w) := by
  rw [den_cons]
  constructor
  · rintro ⟨e'', hne'', hd⟩
    rw [hne, Option.some.injEq, Prod.mk.injEq] at hne''; obtain ⟨_, rfl⟩ := hne''; exact hd
  · intro hd; exact ⟨e', hne, hd⟩

/-- **Bisimulation up to emptiness.** Halting agrees, and each one-step derivative is
    matched by an equally-labelled `R`-related derivative on the other side — unless
    its residual has empty language. -/
def BisimUpTo (R : Exp A T → Exp A T → Prop) : Prop :=
  ∀ e f, R e f →
    (∀ a, bval V (E e) a = bval V (E f) a) ∧
    (∀ a q e', next V e a = some (q, e') →
      Lempty V e' ∨ ∃ f', next V f a = some (q, f') ∧ R e' f') ∧
    (∀ a q f', next V f a = some (q, f') →
      Lempty V f' ∨ ∃ e', next V e a = some (q, e') ∧ R e' f')

/-- **Soundness.** An up-to-emptiness bisimulation is contained in language
    equivalence. Length induction on the guarded string; the dead-residual case is
    impossible when the string is actually accepted. -/
theorem bisim_upto_sound {R : Exp A T → Exp A T → Prop} (hR : BisimUpTo V R) :
    ∀ {e f : Exp A T}, R e f → langEq V e f := by
  have H : ∀ (l : List (A × Atom)) (e f : Exp A T) (a : Atom),
      R e f → (den V e (a, l) ↔ den V f (a, l)) := by
    intro l
    induction l with
    | nil => intro e f a hef; simp only [den_nil, (hR e f hef).1 a]
    | cons hd tl ih =>
        intro e f a hef; obtain ⟨q, a'⟩ := hd
        obtain ⟨_, hfwd, hbwd⟩ := hR e f hef
        rw [den_cons, den_cons]
        constructor
        · rintro ⟨e', hne, hde'⟩
          rcases hfwd a q e' hne with hem | ⟨f', hnf, hrel⟩
          · exact absurd hde' (hem _)
          · exact ⟨f', hnf, (ih e' f' a' hrel).mp hde'⟩
        · rintro ⟨f', hnf, hdf'⟩
          rcases hbwd a q f' hnf with hem | ⟨e', hne, hrel⟩
          · exact absurd hdf' (hem _)
          · exact ⟨e', hne, (ih e' f' a' hrel).mpr hdf'⟩
  intro e f hef gs; simpa using H gs.2 e f gs.1 hef

/-- **Completeness.** Language equivalence is itself an up-to-emptiness bisimulation:
    equal languages agree on halting (`den_nil`) and, at each step, either both sides
    take the same action to language-equal residuals or the residual is empty. -/
theorem langEq_is_bisim_upto : BisimUpTo V (langEq V : Exp A T → Exp A T → Prop) := by
  intro e f hef
  refine ⟨fun a => ?_, fun a q e' hne => ?_, fun a q f' hnf => ?_⟩
  · -- halting agrees
    have h := hef (a, []); rw [den_nil V e a, den_nil V f a] at h
    rcases Bool.eq_false_or_eq_true (bval V (E e) a) with h1 | h1 <;>
      rcases Bool.eq_false_or_eq_true (bval V (E f) a) with h2 | h2 <;> simp_all
  · -- forward step: match, or the residual is empty
    by_cases hf : ∃ f', next V f a = some (q, f')
    · obtain ⟨f', hnf⟩ := hf
      refine Or.inr ⟨f', hnf, fun gs => ?_⟩
      obtain ⟨α, w⟩ := gs
      exact (den_cons_step V hne).symm.trans ((hef (a, (q, α) :: w)).trans (den_cons_step V hnf))
    · refine Or.inl (fun gs hde' => ?_)
      obtain ⟨α, w⟩ := gs
      have hrhs : den V f (a, (q, α) :: w) := (hef (a, (q, α) :: w)).mp ((den_cons_step V hne).mpr hde')
      rw [den_cons] at hrhs; obtain ⟨f'', hnf'', _⟩ := hrhs
      exact hf ⟨f'', hnf''⟩
  · -- backward step (symmetric)
    by_cases he : ∃ e', next V e a = some (q, e')
    · obtain ⟨e', hne⟩ := he
      refine Or.inr ⟨e', hne, fun gs => ?_⟩
      obtain ⟨α, w⟩ := gs
      exact (den_cons_step V hne).symm.trans ((hef (a, (q, α) :: w)).trans (den_cons_step V hnf))
    · refine Or.inl (fun gs hdf' => ?_)
      obtain ⟨α, w⟩ := gs
      have hlhs : den V e (a, (q, α) :: w) := (hef (a, (q, α) :: w)).mpr ((den_cons_step V hnf).mpr hdf')
      rw [den_cons] at hlhs; obtain ⟨e'', hne'', _⟩ := hlhs
      exact he ⟨e'', hne''⟩

/-- **Bisimilarity = language equivalence.** `⟦e⟧ = ⟦f⟧` iff some up-to-emptiness
    bisimulation relates `e` and `f`. -/
theorem bisim_upto_iff (e f : Exp A T) :
    langEq V e f ↔ ∃ R, BisimUpTo V R ∧ R e f :=
  ⟨fun h => ⟨langEq V, langEq_is_bisim_upto V, h⟩,
   fun ⟨_, hR, hef⟩ => bisim_upto_sound V hR hef⟩

#print axioms bisim_upto_sound
#print axioms langEq_is_bisim_upto
#print axioms bisim_upto_iff

end GkatComplete
