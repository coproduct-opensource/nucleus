import GkatGuardedAlgebraProofs

/-!
# Eliminating an unknown at an UNDECIDED crossing — the dead-exit kernel

`GkatChainEliminationProofs` reduces the uniqueness scheme to `UAₙ = UA₁ + (n−1) guard-pullback
witnesses`, and `GkatDecidedUAProofs` supplies those witnesses whenever the crossing guard is
DECIDED by its prefix — constant across atoms.  That is the only witness-producing route the
corpus has, and it is measured (`span-search`, NA=2, K=5) to cover

    ALL-decided systems  1010 / 9245  =  10.9%

of the systems completeness must solve, against a pool base rate of 24.5%.  So 89% of the space
is out of its reach, and not marginally.

This file adds a SECOND elimination case, disjoint from decidedness in general: an unknown may
be eliminated when its **exit is dead**.

    g₀ ≡ e₀·g₁ +_{b₀} f₀        g₁ ≡ e₁·g₀ +_{b₁} 0
    ⟹  g₀ ≡ (e₀ · b₁? · e₁)^(b₀) · f₀

No pullback witness appears, and `b₁` is arbitrary — in particular it may be undecided, which
is exactly the case the witness route cannot reach.  The reason it works is that a guarded
choice whose else arm FAILS is an assertion (`ite_zero_else`), and an assertion is a plain
factor: it associates into the body, where the nesting that blocks `chain_elim` never forms.
The obstruction to eliminating an unknown is the CHOICE at the crossing, not the guard; kill
the choice by any means and the guard stops mattering.

Automaton-side reading: `f₁ ≡ 0` says state `g₁` never halts — where it does not step, it
rejects.  Rejection and halting are genuinely different here, and conflating them is a mistake
this development already made once and corrected (`reject is not halt`, which moved
completeness from 13615 to 19558 of 20020 by letting `0 ≡ 0·s(x)` discharge dead branches).

Scope: this is one kernel, not a completeness proof.  It eliminates one unknown from one
crossing under one hypothesis.  What it establishes is that decidedness is not the only route
through a crossing, which the 10.9% figure makes worth knowing.
-/

namespace GkatDeadExitElim

open GkatSyntax GkatGS GkatFaithful GkatGuardedAlgebra

variable {A T : Type}

/-- **The dead-exit elimination kernel.**  A two-state guarded cycle whose intermediate state
    cannot halt collapses to a single `W3` loop, with the crossing guard absorbed into the body
    as an assertion.  `b₁` is unconstrained. -/
theorem chain_elim_dead_exit {b0 b1 : BExp T} {e0 e1 f0 g0 g1 : Exp A T}
    (hE0 : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e0) x = false)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) (.test .zero))) :
    EquivBA g0 (.seq (.wh b0 (.seq e0 (.seq (.test b1) e1))) f0) := by
  -- the intermediate state is an assertion followed by its body
  have hg1 : EquivBA g1 (.seq (.test b1) (.seq e1 g0)) :=
    EquivBA.trans h1 (ite_zero_else b1 (.seq e1 g0))
  -- so g₀'s body re-associates into (e₀ · b₁? · e₁) · g₀, with no choice left to cross
  have hbody : EquivBA (.seq e0 g1) (.seq (.seq e0 (.seq (.test b1) e1)) g0) :=
    EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl e0)) hg1)
      (EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl e0))
          (EquivBA.symm (seq_assoc (.test b1) e1 g0)))
        (EquivBA.symm (seq_assoc e0 (.seq (.test b1) e1) g0)))
  -- a Salomaa equation in one unknown, productive because e₀ is
  have hsol : EquivBA g0 (.ite b0 (.seq (.seq e0 (.seq (.test b1) e1)) g0) f0) :=
    EquivBA.trans h0 (EquivBA.ite_c hbody (EquivBA.base (Equiv.refl f0)))
  refine EquivBA.w3_ba (EquivBA.baTest ?_) hsol
  intro X W x
  show (bval W (E e0) x && _) = false
  rw [hE0 X W x]; rfl

/-- **Uniqueness at a dead-exit crossing.**  Any two solutions of the cycle agree, with no
    guard-pullback witness and no assumption on `b₁`.  This is `UA₂` for the shape. -/
theorem ua2_of_dead_exit {b0 b1 : BExp T} {e0 e1 f0 : Exp A T}
    (hE0 : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e0) x = false)
    {g0 g1 g0' g1' : Exp A T}
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) (.test .zero)))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') (.test .zero))) :
    EquivBA g0 g0' :=
  EquivBA.trans (chain_elim_dead_exit hE0 h0 h1)
    (EquivBA.symm (chain_elim_dead_exit hE0 h0' h1'))

/-- The intermediate unknowns agree too, once the leading ones do. -/
theorem ua2_of_dead_exit_snd {b0 b1 : BExp T} {e0 e1 f0 : Exp A T}
    (hE0 : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e0) x = false)
    {g0 g1 g0' g1' : Exp A T}
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (.ite b1 (.seq e1 g0) (.test .zero)))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0))
    (h1' : EquivBA g1' (.ite b1 (.seq e1 g0') (.test .zero))) :
    EquivBA g1 g1' :=
  EquivBA.trans h1
    (EquivBA.trans
      (EquivBA.ite_c
        (EquivBA.seq_c (EquivBA.base (Equiv.refl e1))
          (ua2_of_dead_exit hE0 h0 h1 h0' h1'))
        (EquivBA.base (Equiv.refl _)))
      (EquivBA.symm h1'))

#print axioms chain_elim_dead_exit
#print axioms ua2_of_dead_exit
#print axioms ua2_of_dead_exit_snd

end GkatDeadExitElim
