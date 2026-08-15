import GkatDerivativeProofs

/-!
# Bisimulation ⟹ language equivalence: the coinduction principle for GKAT

The coalgebra `⟨E, next⟩` (`GkatDerivativeProofs`) makes GKAT expression equivalence
a **bisimulation** question: `⟦e⟧ = ⟦f⟧` iff the derivative automata of `e` and `f`
are bisimilar (Smolka et al. POPL'20). This file machine-checks the **soundness**
half — the coinduction principle — over the guarded-string model:

  `bisim_sound` : if `R` is a bisimulation and `R e f`, then `⟦e⟧ = ⟦f⟧`.

A **bisimulation** is a relation `R` on expressions that (1) agrees on halting
(`E e = E f` at every atom) and (2) matches one-step derivatives: whenever one side
steps via action `q` to a residual, the other steps via the same `q` to an
`R`-related residual. The proof is a length induction on the guarded string using
`den_nil` (halting) and `den_cons` (steps).

So to prove `⟦e⟧ = ⟦f⟧` it suffices to exhibit a bisimulation containing `(e,f)`.
`bisim_diagonal` gives reflexivity, and `u1_via_bisim` works a concrete example:
`⟦b?e:e⟧ = ⟦e⟧` (GKAT's U1), by the two-element bisimulation `Δ ∪ {(b?e:e, e)}` —
their derivatives coincide because both `ite` branches are `e`.

**Toward a decision procedure.** `bisim_sound` is the soundness the search relies on:
a decision procedure enumerates the residual pairs reachable from `(e,f)` (a
bisimulation candidate) and checks the two conditions; it terminates because the set
of derivatives of a fixed expression is finite up to language-equivalence
(Brzozowski/Antimirov). Machine-checking that finiteness — and the completeness
direction (equivalent expressions admit a bisimulation, modulo identifying
language-empty "dead" residuals) — is the remaining step to a runnable checker; this
file delivers the sound coinduction principle it rests on.

Axioms `[propext]`, `sorryAx`-free.
-/

namespace GkatBisim

open GkatSyntax GkatGS GkatDeriv

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- A **bisimulation**: halting agrees, and one-step derivatives match (same action,
    `R`-related residuals) in both directions. -/
def Bisim (R : Exp A T → Exp A T → Prop) : Prop :=
  ∀ e f, R e f →
    (∀ a, bval V (E e) a = bval V (E f) a) ∧
    (∀ a q e', next V e a = some (q, e') → ∃ f', next V f a = some (q, f') ∧ R e' f') ∧
    (∀ a q f', next V f a = some (q, f') → ∃ e', next V e a = some (q, e') ∧ R e' f')

/-- **The coinduction principle.** A bisimulation is contained in language
    equivalence: `R e f` implies `⟦e⟧` and `⟦f⟧` accept exactly the same guarded
    strings. Length induction on the string, via `den_nil`/`den_cons`. -/
theorem bisim_sound {R : Exp A T → Exp A T → Prop} (hR : Bisim V R) :
    ∀ {e f : Exp A T}, R e f → ∀ gs : GS A Atom, den V e gs ↔ den V f gs := by
  have H : ∀ (l : List (A × Atom)) (e f : Exp A T) (a : Atom),
      R e f → (den V e (a, l) ↔ den V f (a, l)) := by
    intro l
    induction l with
    | nil =>
        intro e f a hef
        simp only [den_nil, (hR e f hef).1 a]
    | cons hd tl ih =>
        intro e f a hef; obtain ⟨q, a'⟩ := hd
        obtain ⟨_, hfwd, hbwd⟩ := hR e f hef
        rw [den_cons, den_cons]
        constructor
        · rintro ⟨e', hne, hde'⟩
          obtain ⟨f', hnf, hrel⟩ := hfwd a q e' hne
          exact ⟨f', hnf, (ih e' f' a' hrel).mp hde'⟩
        · rintro ⟨f', hnf, hdf'⟩
          obtain ⟨e', hne, hrel⟩ := hbwd a q f' hnf
          exact ⟨e', hne, (ih e' f' a' hrel).mpr hdf'⟩
  intro e f hef gs
  simpa using H gs.2 e f gs.1 hef

/-- Equality is a bisimulation — reflexivity of the method. -/
theorem bisim_diagonal : Bisim V (fun x y : Exp A T => x = y) := by
  rintro e f rfl
  exact ⟨fun _ => rfl, fun a q e' h => ⟨e', h, rfl⟩, fun a q f' h => ⟨f', h, rfl⟩⟩

/-- `next` ignores an `ite` whose two branches coincide. -/
private theorem next_ite_self (b : BExp T) (e : Exp A T) (a : Atom) :
    next V (.ite b e e) a = next V e a := by
  simp only [next]; split <;> rfl

/-- **Worked example (U1 via bisimulation).** `⟦b?e:e⟧ = ⟦e⟧`. Witnessed by the
    bisimulation `Δ ∪ {(b?e:e, e)}`: `E(b?e:e) = E e` (a Boolean identity), and the
    derivative of `b?e:e` is the derivative of `e` (both branches are `e`), so the
    residual pair is on the diagonal. -/
theorem u1_via_bisim (b : BExp T) (e : Exp A T) :
    ∀ gs : GS A Atom, den V (.ite b e e) gs ↔ den V e gs := by
  have hbisim : Bisim V (fun x y => x = y ∨ (x = .ite b e e ∧ y = e)) := by
    rintro x y (rfl | ⟨rfl, rfl⟩)
    · exact ⟨fun _ => rfl, fun a q e' h => ⟨e', h, Or.inl rfl⟩,
        fun a q f' h => ⟨f', h, Or.inl rfl⟩⟩
    · refine ⟨fun a => ?_, fun a q e' h => ?_, fun a q f' h => ?_⟩
      · simp only [E, bval]
        rcases Bool.eq_false_or_eq_true (bval V b a) with hb | hb <;> simp [hb]
      · rw [next_ite_self] at h; exact ⟨e', h, Or.inl rfl⟩
      · exact ⟨f', by rw [next_ite_self]; exact h, Or.inl rfl⟩
  exact bisim_sound V hbisim (Or.inr ⟨rfl, rfl⟩)

#print axioms bisim_sound
#print axioms u1_via_bisim

end GkatBisim
