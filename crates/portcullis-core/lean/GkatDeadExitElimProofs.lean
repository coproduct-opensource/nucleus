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

The kernel is proved twice: once for a single transition, and once for a state with an
ARBITRARY transition list (`chain_elim_dead_exit_fold`).  The second is the one the 17.4%
measurement actually needs — that figure counts every never-halting state regardless of how
many transitions it has, so the single-transition kernel alone would not have earned it.

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


/-! ## Arbitrarily many branches

    The kernel above takes a state with ONE transition.  Real automaton states have up to one
    transition per atom, and their equation is a fold

        g₁ ≡ α₁?(a₁·g₀) : α₂?(a₂·g₀) : … : 0

    so the single-transition kernel does not reach them, and a measurement that counts every
    never-halting state is counting more than that kernel proves.  This section closes the gap.

    The mechanism is U5, used in the direction that FACTORS A COMMON TAIL.  Every branch ends
    in the same unknown, so the whole fold factors as `U · g₀` where `U` is the same fold with
    the unknown stripped — and the base case works because `0 ≡ 0 · g₀` by S2, which is exactly
    the reject-is-not-halt distinction doing real work again. -/

/-- One branch of a state's transition list: a guard and the body taken under it. -/
abbrev Branch (A T : Type) := BExp T × Exp A T

/-- The state's equation: each branch runs its body and returns to `g₀`; the fold ends in
    rejection. -/
def branchFold (bs : List (Branch A T)) (g0 : Exp A T) : Exp A T :=
  bs.foldr (fun p acc => .ite p.1 (.seq p.2 g0) acc) (.test .zero)

/-- The same fold with the unknown stripped out. -/
def branchBody (bs : List (Branch A T)) : Exp A T :=
  bs.foldr (fun p acc => .ite p.1 p.2 acc) (.test .zero)

/-- **A never-halting state factors through its successor.**  `U5` pulls the common tail out
    of every branch at once; `S2` supplies the base case, `0 ≡ 0·g₀`. -/
theorem branchFold_factor (bs : List (Branch A T)) (g0 : Exp A T) :
    EquivBA (branchFold bs g0) (.seq (branchBody bs) g0) := by
  induction bs with
  | nil => exact EquivBA.symm (EquivBA.base (Equiv.s2 g0))
  | cons b bs ih =>
      show EquivBA (.ite b.1 (.seq b.2 g0) (branchFold bs g0))
        (.seq (.ite b.1 b.2 (branchBody bs)) g0)
      exact EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih)
        (EquivBA.symm (ite_seq_right b.1 b.2 (branchBody bs) g0))

/-- **The dead-exit kernel, at arbitrary branch count.**  A two-state cycle whose intermediate
    state never halts collapses to one `W3` loop, however many transitions that state has and
    whatever its guards do. -/
theorem chain_elim_dead_exit_fold {b0 : BExp T} {e0 f0 g0 g1 : Exp A T}
    (bs : List (Branch A T))
    (hE0 : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e0) x = false)
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : EquivBA g1 (branchFold bs g0)) :
    EquivBA g0 (.seq (.wh b0 (.seq e0 (branchBody bs))) f0) := by
  have hbody : EquivBA (.seq e0 g1) (.seq (.seq e0 (branchBody bs)) g0) :=
    EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl e0))
        (EquivBA.trans h1 (branchFold_factor bs g0)))
      (EquivBA.symm (seq_assoc e0 (branchBody bs) g0))
  refine EquivBA.w3_ba (EquivBA.baTest ?_)
    (EquivBA.trans h0 (EquivBA.ite_c hbody (EquivBA.base (Equiv.refl f0))))
  intro X W x
  show (bval W (E e0) x && _) = false
  rw [hE0 X W x]; rfl

/-- **UA₂ at a never-halting crossing of any branch count.** -/
theorem ua2_of_dead_exit_fold {b0 : BExp T} {e0 f0 : Exp A T} (bs : List (Branch A T))
    (hE0 : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E e0) x = false)
    {g0 g1 g0' g1' : Exp A T}
    (h0 : EquivBA g0 (.ite b0 (.seq e0 g1) f0)) (h1 : EquivBA g1 (branchFold bs g0))
    (h0' : EquivBA g0' (.ite b0 (.seq e0 g1') f0)) (h1' : EquivBA g1' (branchFold bs g0')) :
    EquivBA g0 g0' :=
  EquivBA.trans (chain_elim_dead_exit_fold bs hE0 h0 h1)
    (EquivBA.symm (chain_elim_dead_exit_fold bs hE0 h0' h1'))

#print axioms branchFold_factor
#print axioms chain_elim_dead_exit_fold
#print axioms ua2_of_dead_exit_fold

#print axioms chain_elim_dead_exit
#print axioms ua2_of_dead_exit
#print axioms ua2_of_dead_exit_snd



/-! ## The atom-indexed kernel

    `chain_elim_dead_exit_fold` demands the eliminated state NEVER HALT.  That is far stronger
    than what the elimination actually needs, and the gap is large: measured, a per-STATE
    condition reaches 17.4% of the systems completeness must solve, while the same rule applied
    PER LEAF-ATOM reaches 99.74%.  A state may halt freely, so long as no halt sits at an atom
    where the variable recurs.

    The reason is that the fold's branches are guarded by disjoint atoms, so the recurring
    branches and the halting ones never overlap.  Gathering the recurring branches turns the
    equation into Salomaa form `x ≡ E·x +_b F`, where `F` keeps every halt — and then it is
    W3, with no side condition beyond productivity of `E`.

    The gathering step is below.  It is U5 (factor the common tail out of each branch), U3
    (reassociate the accumulated guard), and a congruence under `¬α` to see that `α ∨ β` and
    `β` agree in the else arm. -/

/-- The disjunction of a branch list's guards. -/
def orGuards (bs : List (Branch A T)) : BExp T :=
  bs.foldr (fun p acc => .or p.1 acc) .zero

/-- The branch list with the common tail stripped. -/
def bodyFold (bs : List (Branch A T)) : Exp A T :=
  bs.foldr (fun p acc => .ite p.1 p.2 acc) (.test .zero)

/-- A choice on an unsatisfiable guard is its else arm. -/
theorem ite_zero_guard {z : BExp T} (e f : Exp A T)
    (hz : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W z x = false) :
    EquivBA (.ite z e f) f :=
  EquivBA.trans (EquivBA.base (Equiv.u2 z e f))
    (ite_taut f e (fun X W x => by
      show (!bval W z x) = true
      rw [hz X W x]; rfl))

/-- Gathering step: `P +_α (Q +_β R) ≡ (P +_α Q) +_{α∨β} R`. -/
theorem ite_gather {α β : BExp T} (P Q R : Exp A T) :
    EquivBA (.ite α P (.ite β Q R)) (.ite (.or α β) (.ite α P Q) R) := by
  refine EquivBA.symm (EquivBA.trans (EquivBA.base (Equiv.u3 α (.or α β) P Q R)) ?_)
  refine EquivBA.trans (EquivBA.ite_guard (fun _ W x => by
    show (bval W α x && (bval W α x || bval W β x)) = bval W α x
    cases bval W α x <;> rfl)) ?_
  -- in the else arm `α ∨ β` and `β` agree, since `¬α` holds there
  have hmid : EquivBA (.seq (.test (.not α)) (.ite (.or α β) Q R))
      (.seq (.test (.not α)) (.ite β Q R)) := by
    refine EquivBA.trans (test_seq_ite (.not α) (.or α β) Q R) ?_
    refine EquivBA.trans (EquivBA.ite_guard
      (b := .and (.not α) (.or α β)) (c := .and (.not α) β)
      (fun _ W x => by
        show ((!bval W α x) && (bval W α x || bval W β x))
          = ((!bval W α x) && bval W β x)
        cases bval W α x <;> cases bval W β x <;> rfl)) ?_
    exact EquivBA.symm (test_seq_ite (.not α) β Q R)
  refine EquivBA.trans (EquivBA.base (Equiv.u2 α P (.ite (.or α β) Q R))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.u4 (.not α) (.ite (.or α β) Q R) P)) ?_
  refine EquivBA.trans
    (EquivBA.ite_c (e := .seq (.test (.not α)) (.ite (.or α β) Q R))
      (e' := .seq (.test (.not α)) (.ite β Q R)) hmid (EquivBA.base (Equiv.refl P))) ?_
  exact EquivBA.trans
    (EquivBA.symm (EquivBA.base (Equiv.u4 (.not α) (.ite β Q R) P)))
    (EquivBA.symm (EquivBA.base (Equiv.u2 α P (.ite β Q R))))

/-- **Factoring a common tail out of a whole fold, with an arbitrary fallback.**

    Every branch runs its own body and then the SAME `g`; the fallback is untouched and may
    halt.  The result is Salomaa-shaped in `g`. -/
theorem guardedFold_factor_gen (bs : List (Branch A T)) (g fb : Exp A T) :
    EquivBA (guardedFold (bs.map (fun p => (p.1, .seq p.2 g))) fb)
      (.ite (orGuards bs) (.seq (bodyFold bs) g) fb) := by
  induction bs with
  | nil =>
      exact EquivBA.symm (ite_zero_guard _ _ (fun _ _ _ => rfl))
  | cons b bs ih =>
      show EquivBA (.ite b.1 (.seq b.2 g) (guardedFold (bs.map _) fb)) _
      refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih) ?_
      refine EquivBA.trans (ite_gather _ _ _) ?_
      exact EquivBA.ite_c (EquivBA.symm (ite_seq_right b.1 b.2 (bodyFold bs) g))
        (EquivBA.base (Equiv.refl fb))

/-- **The atom-indexed elimination kernel.**  A state whose recurring branches all return to
    itself, with halts allowed anywhere else, eliminates by W3 alone. -/
theorem self_elim_atom_indexed (bs : List (Branch A T)) (fb : Exp A T) {g : Exp A T}
    (hE : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E (bodyFold bs)) x = false)
    (hg : EquivBA g (guardedFold (bs.map (fun p => (p.1, .seq p.2 g))) fb)) :
    EquivBA g (.seq (.wh (orGuards bs) (bodyFold bs)) fb) :=
  EquivBA.w3_ba (EquivBA.baTest hE)
    (EquivBA.trans hg (guardedFold_factor_gen bs g fb))

#print axioms ite_gather
#print axioms guardedFold_factor_gen
#print axioms self_elim_atom_indexed

end GkatDeadExitElim
