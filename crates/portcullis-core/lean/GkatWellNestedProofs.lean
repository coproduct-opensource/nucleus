import GkatGuardedStringProofs

/-!
# Where the pullback witnesses come from: structure (Track 1) and invariance (Track 2)

`GkatChainEliminationProofs` reduced an `n`-state guarded cycle to `UA₁` given a
guard-pullback witness at each crossing (`UAₙ = UA₁ + (n−1) witnesses`). This file pushes
on where those witnesses come from — the two literature-grounded tracks.

## Track 1 — structure: well-nested systems need NO witness

Well-nested GKAT automata (the Kleene theorem: every expression ↔ a well-nested automaton;
Schmid–Kappé–Kozen–Silva) are structured/nested loops — the class for which Pham *derived*
uniqueness. Structurally, their intermediate states are **pure continuations**
(`g₁ ≡ e₁·g₂`, no branch), so there is no inner guard to push a prefix past: the
chain-elimination kernel collapses by **`S1` alone**, no witness.

* `chain_elim_pure` — the witness-free kernel.
* `pure_cycle_solvable` — a cycle of pure continuations reduces to a single loop and closes
  by `W3`, with NO pullback witness. This is the well-nested / Thompson case.

## Track 2 — hypotheses: the regime-1 witness is sound under invariance

The framework is **Kleene algebra with hypotheses** (Doumane–Kuperberg–Pous–Pradic '19;
Pous–Rot–Wagemaker '24). Commutation/commutativity hypotheses are *not* freely eliminable —
"Kleene algebra with commutativity conditions is undecidable" (CSL 2025) — so the honest
move is semantic grounding, not syntactic elimination.

* `frame_law_semantic_of_invariance` — if the action `e` **preserves the guard `b`**
  (`b` has the same value before and after any `e`-run — the Hoare-invariant hypothesis
  `{b}e{b}`, `{¬b}e{¬b}`), then the frame law (the regime-1 pullback, `c = b`) holds in the
  guarded-string model. So the witness one needs for `chain_elim` is **semantically justified
  exactly by an invariance hypothesis** — the natural, verification-provided form.

All sorry-free; Track 1 depends on NO axioms.
-/

namespace GkatWellNested

open GkatSyntax GkatGS

variable {A T : Type}

/-! ## Track 1 — well-nested / pure-continuation systems are witness-free -/

/-- **Witness-free chain elimination.** When the intermediate state is a *pure continuation*
    `g₁ ≡ e₁·g₂` (no branch), eliminating it needs only `S1` — no guard to push a prefix
    past, so no pullback witness. This is the structural reason well-nested (Pham/Thompson)
    systems avoid the Uniqueness-Axiom obstruction entirely. -/
theorem chain_elim_pure {b0 : BExp T} {e0 e1 f0 g0 g1 g2 : Exp A T}
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.seq e1 g2)) :
    Equiv g0 (.ite b0 (.seq (.seq e0 e1) g2) f0) :=
  Equiv.trans h0
    (Equiv.ite_c
      (Equiv.trans (Equiv.seq_c (Equiv.refl e0) h1) (Equiv.symm (Equiv.s1 e0 e1 g2)))
      (Equiv.refl f0))

/-- **A well-nested cycle is solvable with NO witness.** A cycle whose intermediate states
    are pure continuations (`g₁ ≡ e₁·g₂`, `g₂ ≡ e₂·g₀`) collapses to the single loop
    `(e₀·e₁·e₂)^(b₀)·f₀` by `chain_elim_pure` (S1 only) then `W3`. The witness-free, n-ary
    generalization of `two_state_existence_pure_return`, and the structural home of Pham's
    Thompson-automata uniqueness. -/
theorem pure_cycle_solvable {b0 : BExp T} {e0 e1 e2 f0 g0 g1 g2 : Exp A T}
    (hguard : Equiv (Exp.test (E (.seq (.seq e0 e1) e2)) : Exp A T) (.test .zero))
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.seq e1 g2))
    (h2 : Equiv g2 (.seq e2 g0)) :
    Equiv g0 (.seq (.wh b0 (.seq (.seq e0 e1) e2)) f0) :=
  salomaa_solution_unique hguard (chain_elim_pure (chain_elim_pure h0 h1) h2)

/-! ## Track 2 — the regime-1 witness is sound under a test-invariance hypothesis -/

variable {Atom : Type} (V : T → Atom → Bool)

/-- **The frame law holds under invariance.** If `e` preserves the guard `b` — `b` has the
    same truth value at the start and end atom of every `e`-run (the Hoare hypotheses
    `{b}e{b}` and `{¬b}e{¬b}`) — then in the guarded-string model
    `e·(b?x:y) ≡ b?(e·x):(e·y)` (the regime-1 pullback, `c = b`). So the witness
    `chain_elim` needs is exactly what an invariance hypothesis provides, semantically. The
    proof simply relocates the guard test across `e` using invariance. -/
theorem frame_law_semantic_of_invariance {b : BExp T} {e : Exp A T}
    (hinv : ∀ (a : Atom) (l : List (A × Atom)),
      den V e (a, l) → bval V b (lastAtom a l) = bval V b a) :
    ∀ (x y : Exp A T) (gs : GS A Atom),
      den V (.seq e (.ite b x y)) gs ↔ den V (.ite b (.seq e x) (.seq e y)) gs := by
  rintro x y ⟨a0, w⟩
  constructor
  · rintro ⟨l1, l2, hw, he, hite⟩
    have hbb : bval V b (lastAtom a0 l1) = bval V b a0 := hinv a0 l1 he
    rcases hite with ⟨hb, hx⟩ | ⟨hb, hy⟩
    · exact Or.inl ⟨hbb ▸ hb, l1, l2, hw, he, hx⟩
    · exact Or.inr ⟨hbb ▸ hb, l1, l2, hw, he, hy⟩
  · rintro (⟨hb, l1, l2, hw, he, hx⟩ | ⟨hb, l1, l2, hw, he, hy⟩)
    · exact ⟨l1, l2, hw, he, Or.inl ⟨(hinv a0 l1 he).trans hb, hx⟩⟩
    · exact ⟨l1, l2, hw, he, Or.inr ⟨(hinv a0 l1 he).trans hb, hy⟩⟩

#print axioms chain_elim_pure
#print axioms pure_cycle_solvable
#print axioms frame_law_semantic_of_invariance

end GkatWellNested
