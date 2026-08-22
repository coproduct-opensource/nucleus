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

/-! ## The elimination step, with an arbitrary tail

    Gaussian elimination on a GKAT system picks a state, solves its own equation by W3, and
    substitutes the closed form into the rest.  Substitution is congruence, so the only step
    that needs an argument is solving — and the branches that recur must be gathered before W3
    applies.  The corpus already has the gathering: `guardedFold_move_to_front_of_disjoint`
    permutes a branch to the front whenever its guard is disjoint from what it crosses, which
    for atom guards is automatic.

    So with the recurring branches at the front, `guardedFold_append` turns the appended fold
    into a nested one and `self_elim_atom_indexed` finishes.  The tail is arbitrary: it may
    halt, and it may contain other unknowns. -/

/-- **One elimination step.**  A state whose recurring branches lead the fold is solved by W3,
    with everything else — halts, other unknowns — carried untouched into the tail. -/
theorem elim_front (rec : List (Branch A T)) (rest : List (BExp T × Exp A T))
    (fb : Exp A T) {x : Exp A T}
    (hE : ∀ (X : Type) (W : T → X → Bool) (y : X), bval W (E (bodyFold rec)) y = false)
    (hx : EquivBA x (guardedFold (rec.map (fun p => (p.1, .seq p.2 x)) ++ rest) fb)) :
    EquivBA x (.seq (.wh (orGuards rec) (bodyFold rec)) (guardedFold rest fb)) := by
  refine self_elim_atom_indexed rec (guardedFold rest fb) hE ?_
  rw [guardedFold_append] at hx
  exact hx

#print axioms elim_front

/-! ## Composing steps

    One step leaves the tail alone, so steps compose whenever the tail's unknowns are ALREADY
    SOLVED — substituting a closed expression is congruence and nothing more.  That is why a
    chain of states, each with its own self-loop, needs no witness anywhere: solve the last,
    substitute, solve the next.

    It is also exactly where the general case stops.  If the tail's unknown is not yet solved,
    substituting `x := U^(B)·Tail` puts the next unknown UNDER a product, and gathering it again
    would need `a·(fold)` distributed over the fold — the left-distributivity that GKAT does not
    have.  So composition is free down a chain and blocked around a cycle, which is the same
    boundary the kernels hit, now visible at the level of the procedure rather than the rule. -/

/-- **Two levels of a chain.**  `x₂` is solved first and its closed form substituted into `x₁`'s
    fold by congruence; then `x₁` is solved.  No guard-pullback witness appears. -/
theorem elim_two_level (rec1 rec2 : List (Branch A T)) (β : BExp T) (a fb1 fb2 : Exp A T)
    {x1 x2 : Exp A T}
    (hE1 : ∀ (X : Type) (W : T → X → Bool) (y : X), bval W (E (bodyFold rec1)) y = false)
    (hE2 : ∀ (X : Type) (W : T → X → Bool) (y : X), bval W (E (bodyFold rec2)) y = false)
    (h1 : EquivBA x1 (guardedFold (rec1.map (fun p => (p.1, .seq p.2 x1)) ++ [(β, .seq a x2)]) fb1))
    (h2 : EquivBA x2 (guardedFold (rec2.map (fun p => (p.1, .seq p.2 x2))) fb2)) :
    EquivBA x1
      (.seq (.wh (orGuards rec1) (bodyFold rec1))
        (guardedFold [(β, .seq a (.seq (.wh (orGuards rec2) (bodyFold rec2)) fb2))] fb1)) := by
  -- solve the tail state first; its solution is closed
  have hx2 : EquivBA x2 (.seq (.wh (orGuards rec2) (bodyFold rec2)) fb2) := by
    refine elim_front rec2 [] fb2 hE2 ?_
    rw [List.append_nil]
    exact h2
  -- substitute it into x₁'s fold: congruence, no distribution
  refine elim_front rec1 [(β, .seq a (.seq (.wh (orGuards rec2) (bodyFold rec2)) fb2))] fb1 hE1 ?_
  refine EquivBA.trans h1 ?_
  rw [guardedFold_append, guardedFold_append]
  refine guardedFold_fallback_congr _ ?_
  show EquivBA (.ite β (.seq a x2) fb1) (.ite β (.seq a _) fb1)
  exact EquivBA.ite_c (EquivBA.seq_c (EquivBA.base (Equiv.refl a)) hx2)
    (EquivBA.base (Equiv.refl fb1))

#print axioms elim_two_level

/-! ## An elimination certificate

    `elim_two_level` shows two steps compose; the blocker for stating the whole route in Lean is
    that "eliminable" needs a certificate — a LIST of steps, checkable, of any length.  A chain
    is the case where composition is free (each substitution targets an already-closed tail), so
    that is the certificate this section builds.

    A `Level` is one state's data: its recurring branches, the guard and action of its single
    forward exit, and its fallback.  `chainSol` reads off the closed form, `ChainOK` is the
    checkable hypothesis, and `chain_solves` is the induction.  Nothing here searches; a
    certificate found by any means (the harness tries orders exhaustively) is checked by it. -/

/-- One level of a chain: recurring branches, forward guard, forward action, fallback. -/
abbrev Level (A T : Type) := List (Branch A T) × BExp T × Exp A T × Exp A T

/-- The closed form the certificate denotes. -/
def chainSol : List (Level A T) → Exp A T → Exp A T
  | [], z => z
  | L :: rest, z =>
      .seq (.wh (orGuards L.1) (bodyFold L.1))
        (guardedFold [(L.2.1, .seq L.2.2.1 (chainSol rest z))] L.2.2.2)

/-- The unknown a chain currently exposes: the head's, or the terminal expression. -/
def nextUnk : List (Level A T × Exp A T) → Exp A T → Exp A T
  | [], z => z
  | p :: _, _ => p.2

/-- The certificate's checkable content: each level's equation, and productivity of its body. -/
def ChainOK : List (Level A T × Exp A T) → Exp A T → Prop
  | [], _ => True
  | (L, x) :: rest, z =>
      (∀ (X : Type) (W : T → X → Bool) (y : X), bval W (E (bodyFold L.1)) y = false)
      ∧ EquivBA x (guardedFold (L.1.map (fun p => (p.1, .seq p.2 x)) ++
            [(L.2.1, .seq L.2.2.1 (nextUnk rest z))]) L.2.2.2)
      ∧ ChainOK rest z

/-- **A chain certificate solves its head.**  Induction on the certificate: solve the tail,
    substitute its closed form by congruence, then one `elim_front`. -/
theorem chain_solves : ∀ (l : List (Level A T × Exp A T)) (z : Exp A T),
    ChainOK l z → EquivBA (nextUnk l z) (chainSol (l.map Prod.fst) z)
  | [], z, _ => EquivBA.base (Equiv.refl z)
  | (L, x) :: rest, z, h => by
      obtain ⟨hE, hx, hrest⟩ := h
      have ih := chain_solves rest z hrest
      show EquivBA x (.seq (.wh (orGuards L.1) (bodyFold L.1))
        (guardedFold [(L.2.1, .seq L.2.2.1 (chainSol (rest.map Prod.fst) z))] L.2.2.2))
      refine elim_front L.1 [(L.2.1, .seq L.2.2.1 (chainSol (rest.map Prod.fst) z))]
        L.2.2.2 hE ?_
      refine EquivBA.trans hx ?_
      rw [guardedFold_append, guardedFold_append]
      refine guardedFold_fallback_congr _ ?_
      show EquivBA (.ite L.2.1 (.seq L.2.2.1 (nextUnk rest z)) L.2.2.2)
        (.ite L.2.1 (.seq L.2.2.1 _) L.2.2.2)
      exact EquivBA.ite_c (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ih)
        (EquivBA.base (Equiv.refl _))

#print axioms chain_solves

/-! ## A two-state SCC

    `chain_solves` takes singleton SCCs only, and 14.3% of the start-merged quotients contain a
    multi-state one — measured, all of size 2 or 3, and 98.2% of them eliminate anyway.  So the
    checker, not the mathematics, is the binding constraint.  This closes the size-2 case.

    The mechanism the harness uses, read off its successes: if one state's branches ALL lead to
    the other and its fallback is dead, `branchFold_factor` turns it into a clean product
    `U·y` — not a choice, a product.  Substituting that into the other state's equation turns
    its `x`-branch into a `y`-branch, so EVERY branch recurs to `y`, and `elim_front` closes it.

    The dead fallback is what makes this work and is not a convenience: with a live fallback the
    factored form is `ite B (U·y) fb`, and substituting puts `y` under a choice inside a product
    — the nesting left-distributivity cannot undo. -/

/-- **A two-state SCC eliminates** when one state factors through the other. -/
theorem elim_scc2 (bsx recy : List (Branch A T)) (β : BExp T) (ax fby : Exp A T)
    {x y : Exp A T}
    (hE : ∀ (X : Type) (W : T → X → Bool) (z : X),
      bval W (E (bodyFold (recy ++ [(β, Exp.seq ax (bodyFold bsx))]))) z = false)
    (hx : EquivBA x (branchFold bsx y))
    (hy : EquivBA y (guardedFold (recy.map (fun p : Branch A T => (p.1, Exp.seq p.2 y)) ++
            [(β, .seq ax x)]) fby)) :
    EquivBA y (.seq (.wh (orGuards (recy ++ [(β, Exp.seq ax (bodyFold bsx))]))
      (bodyFold (recy ++ [(β, Exp.seq ax (bodyFold bsx))]))) fby) := by
  -- x is a PRODUCT through y, not a choice
  have hxy : EquivBA x (.seq (bodyFold bsx) y) :=
    EquivBA.trans hx (branchFold_factor bsx y)
  -- so y's x-branch becomes a y-branch, and every branch now recurs to y
  have hstep : EquivBA y (guardedFold
      ((recy ++ [(β, Exp.seq ax (bodyFold bsx))]).map (fun p : Branch A T => (p.1, Exp.seq p.2 y))) fby) := by
    refine EquivBA.trans hy ?_
    rw [List.map_append]
    rw [guardedFold_append, guardedFold_append]
    refine guardedFold_fallback_congr _ ?_
    show EquivBA (.ite β (.seq ax x) fby) (.ite β (.seq (Exp.seq ax (bodyFold bsx)) y) fby)
    exact EquivBA.ite_c
      (EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl ax)) hxy)
        (EquivBA.symm (seq_assoc ax (bodyFold bsx) y)))
      (EquivBA.base (Equiv.refl fby))
  refine elim_front (recy ++ [(β, Exp.seq ax (bodyFold bsx))]) [] fby hE ?_
  rw [List.append_nil]
  exact hstep

/-- And then the other state's solution follows by substitution. -/
theorem elim_scc2_fst (bsx recy : List (Branch A T)) (β : BExp T) (ax fby : Exp A T)
    {x y : Exp A T}
    (hE : ∀ (X : Type) (W : T → X → Bool) (z : X),
      bval W (E (bodyFold (recy ++ [(β, Exp.seq ax (bodyFold bsx))]))) z = false)
    (hx : EquivBA x (branchFold bsx y))
    (hy : EquivBA y (guardedFold (recy.map (fun p : Branch A T => (p.1, Exp.seq p.2 y)) ++
            [(β, .seq ax x)]) fby)) :
    EquivBA x (.seq (bodyFold bsx)
      (.seq (.wh (orGuards (recy ++ [(β, Exp.seq ax (bodyFold bsx))]))
        (bodyFold (recy ++ [(β, Exp.seq ax (bodyFold bsx))]))) fby)) :=
  EquivBA.trans (EquivBA.trans hx (branchFold_factor bsx y))
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (elim_scc2 bsx recy β ax fby hE hx hy))

#print axioms elim_scc2
#print axioms elim_scc2_fst

/-! ## The certificate needs no ordering

    `chain_solves` threads a tail through a linear chain, and measurement says only 24.6% of
    start-merged quotients are linear while 85.7% have all-singleton SCCs.  The gap looked like
    missing machinery for topological order.  It is not: `elim_front` already takes an ARBITRARY
    forward branch list, so if the certificate PRODUCER substitutes the already-solved forward
    bodies, each level is an independent check and the checker never needs the order.

    That is the right division.  Finding an order is search, and search belongs to the producer;
    the checker verifies one `elim_front` per level, in any sequence, with no accumulator. -/

/-- One level of a certificate: recurring branches, forward branches with ALREADY-SUBSTITUTED
    bodies, and the fallback. -/
abbrev LevelG (A T : Type) := List (Branch A T) × List (BExp T × Exp A T) × Exp A T

/-- The closed form a level denotes. -/
def levelSol (L : LevelG A T) : Exp A T :=
  .seq (.wh (orGuards L.1) (bodyFold L.1)) (guardedFold L.2.1 L.2.2)

/-- **One level checks.**  This is `elim_front` in certificate shape. -/
theorem level_solves (L : LevelG A T) {x : Exp A T}
    (hE : ∀ (X : Type) (W : T → X → Bool) (y : X), bval W (E (bodyFold L.1)) y = false)
    (hx : EquivBA x (guardedFold (L.1.map (fun p : Branch A T => (p.1, Exp.seq p.2 x)) ++ L.2.1)
            L.2.2)) :
    EquivBA x (levelSol L) :=
  elim_front L.1 L.2.1 L.2.2 hE hx

/-- **A whole certificate checks, in any order.**  Every level is verified independently; no
    accumulator, no topological sort, no threading.  The producer's job was to substitute. -/
theorem levels_solve (ls : List (LevelG A T × Exp A T))
    (h : ∀ p ∈ ls,
      (∀ (X : Type) (W : T → X → Bool) (y : X), bval W (E (bodyFold p.1.1)) y = false) ∧
      EquivBA p.2 (guardedFold
        (p.1.1.map (fun q : Branch A T => (q.1, Exp.seq q.2 p.2)) ++ p.1.2.1) p.1.2.2)) :
    ∀ p ∈ ls, EquivBA p.2 (levelSol p.1) := by
  intro p hp
  obtain ⟨hE, hx⟩ := h p hp
  exact level_solves p.1 hE hx

#print axioms level_solves
#print axioms levels_solve

/-- **The existence half.**  `levelSol` SATISFIES the equation whose solutions it describes —
    W1-existence through the factored fold.  With `level_solves` (uniqueness) this completes
    the pair: a level's closed form is THE solution, so a certificate producer may define a
    quotient solution state-by-state as `levelSol` and discharge each `SolvesBA` obligation
    with this lemma. -/
theorem level_satisfies (L : LevelG A T) :
    EquivBA (levelSol L)
      (guardedFold (L.1.map (fun p : Branch A T => (p.1, Exp.seq p.2 (levelSol L))) ++ L.2.1)
        L.2.2) := by
  have hunroll : EquivBA (levelSol L)
      (.ite (orGuards L.1) (.seq (bodyFold L.1) (levelSol L)) (guardedFold L.2.1 L.2.2)) :=
    EquivBA.base (GkatSyntax.salomaa_solution_exists (orGuards L.1) (bodyFold L.1)
      (guardedFold L.2.1 L.2.2))
  rw [guardedFold_append]
  exact EquivBA.trans hunroll
    (EquivBA.symm (guardedFold_factor_gen L.1 (levelSol L) (guardedFold L.2.1 L.2.2)))

#print axioms level_satisfies

/-! ## Existence for the two-state SCC certificate

    `elim_scc2` is the uniqueness half of the size-2 SCC case; a certificate EMITTER needs the
    existence half — that the closed forms actually satisfy the pair's equations, so a quotient
    solution assembled from them discharges `SolvesBA` directly.

    With `x` the state that factors through `y` (all branches to `y`, dead fallback) and

        solY := levelSol (recy ++ [(β, ax · bodyFold bsx)], [], fby)
        solX := bodyFold bsx · solY

    the `x` obligation is `branchFold_factor` read backwards, and the `y` obligation is
    `level_satisfies` at the combined level plus one associativity step inside the fold. -/

/-- Congruence in the body of a fold's last entry. -/
theorem guardedFold_last_congr (A' : List (BExp T × Exp A T)) {g : BExp T}
    {e e' fb : Exp A T} (h : EquivBA e e') :
    EquivBA (guardedFold (A' ++ [(g, e)]) fb) (guardedFold (A' ++ [(g, e')]) fb) := by
  rw [guardedFold_append, guardedFold_append]
  exact guardedFold_fallback_congr A'
    (EquivBA.ite_c h (EquivBA.base (Equiv.refl fb)))

/-- **The `y` obligation.**  The SCC pair's closed form for `y` satisfies `y`'s equation, with
    `x`'s branch carrying `x`'s own closed form. -/
theorem scc2_satisfies_y (bsx recy : List (Branch A T)) (β : BExp T) (ax fby : Exp A T) :
    EquivBA
      (levelSol (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby))
      (guardedFold
        (recy.map (fun p : Branch A T =>
            (p.1, Exp.seq p.2 (levelSol (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby)))) ++
          [(β, Exp.seq ax
            (Exp.seq (bodyFold bsx)
              (levelSol (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby))))])
        fby) := by
  refine EquivBA.trans (level_satisfies (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby)) ?_
  have hmap : ((recy ++ [(β, Exp.seq ax (bodyFold bsx))]).map
        (fun p : Branch A T => (p.1, Exp.seq p.2
          (levelSol (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby)))) ++
          ([] : List (BExp T × Exp A T)))
      = (recy.map (fun p : Branch A T => (p.1, Exp.seq p.2
          (levelSol (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby)))) ++
         [(β, Exp.seq (Exp.seq ax (bodyFold bsx))
            (levelSol (recy ++ [(β, Exp.seq ax (bodyFold bsx))], [], fby)))]) := by
    rw [List.append_nil, List.map_append]
    rfl
  rw [hmap]
  exact guardedFold_last_congr _ (seq_assoc ax (bodyFold bsx) _)

/-- **The `x` obligation.**  `bodyFold bsx · solY` satisfies `x`'s equation. -/
theorem scc2_satisfies_x (bsx : List (Branch A T)) (solY : Exp A T) :
    EquivBA (Exp.seq (bodyFold bsx) solY) (branchFold bsx solY) :=
  EquivBA.symm (branchFold_factor bsx solY)

#print axioms scc2_satisfies_y
#print axioms scc2_satisfies_x

end GkatDeadExitElim
