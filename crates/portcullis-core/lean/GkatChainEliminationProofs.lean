import GkatFaithfulnessProofs

/-!
# The n-ary decomposition: chain-elimination reduces a guarded cycle to `UA₁`

`GkatUAIndependenceProofs` decomposed the crossed *two*-state instance of the Uniqueness
Axiom as `UA₂ = UA₁ + a guard-pullback witness`. This file lifts that to the **full
scheme**: an `n`-state guarded cycle

    g₀ ≡ e₀·g₁ +_{b₀} f₀ ,  g₁ ≡ e₁·g₂ +_{b₁} f₁ ,  … ,  g_{n-1} ≡ e_{n-1}·g₀ +_{b_{n-1}} f_{n-1}

is reduced to a single `W3` (`UA₁`) loop by **iterating one kernel rule**, given a
guard-pullback witness at each crossing.

* `chain_elim` — the KERNEL: eliminate one intermediate state `g₁`, folding its equation
  into `g₀`'s so that `g₀` is expressed directly in terms of the *next* state `g₂`:

      g₀ ≡ (c₁∧b₀)?((e₀·e₁)·g₂):(b₀?(e₀·f₁):f₀).

  The witness `∀ x y, e₀·(b₁?x:y) ≡ c₁?(e₀·x):(e₀·y)` (i.e. `c₁ = wp(e₀,b₁)`) discharges
  the one step that would otherwise be `LeftDistrib`; the rest is congruence, `S1`, `U3`.
  This is exactly the reshaping of `crossed_closed_form_of_pullback`, now parametric in
  the continuation, hence composable.

* `Reduction` / `nary_cycle_solvable` — an inductive certificate applies the kernel any
  finite number of times, then closes the resulting self-loop with `W3`. This is the
  machine-checked arbitrary-`n` theorem; the number of crossings is its `Nat` index.
* `Introduction` / `introduction_equiv` — the reverse arbitrary-length certificate:
  `chain_intro^(n)` reconstructs the crossed states from the canonical loop solution,
  proving existence without a productivity side condition.
* `three_cycle_solvable_of_pullbacks` — the kernel applied twice, then `W3`, solves a
  **3-state cycle**. The pattern `chain_elim^(n-1) ∘ W3` gives the general `n`: each
  witness folds one state, the composite body `e₀·e₁·…` and guard `c…∧b₀` accumulate, and
  a single productive loop remains. So `UAₙ = UA₁ + (n−1) guard-pullback witnesses`.

The pullback condition is stated inline (`∀ x y, …`) so this file is self-contained on
`GkatSyntaxProofs`. All theorems are pure derivations — `sorryAx`-free, NO axioms.
-/

namespace GkatChainElim

open GkatSyntax

variable {A T : Type}

/-- **The chain-elimination kernel.** Given `g₀ ≡ e₀·g₁ +_{b₀} f₀` and
    `g₁ ≡ e₁·g₂ +_{b₁} f₁`, plus a guard-pullback witness `c₁` for `(e₀,b₁)`, eliminate
    `g₁`: `g₀` is expressed directly over the *next* state `g₂` with the composite body
    `e₀·e₁`. Iterating this around a cycle collapses it to a single self-loop. -/
theorem chain_elim {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g0 g1 g2 : Exp A T}
    (hpb : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g2) f1)) :
    Equiv g0 (.ite (.and c1 b0) (.seq (.seq e0 e1) g2) (.ite b0 (.seq e0 f1) f0)) :=
  Equiv.trans h0
  (Equiv.trans (Equiv.ite_c (Equiv.seq_c (Equiv.refl e0) h1) (Equiv.refl f0))
  (Equiv.trans (Equiv.ite_c (hpb (.seq e1 g2) f1) (Equiv.refl f0))
  (Equiv.trans
    (Equiv.ite_c (Equiv.ite_c (Equiv.symm (Equiv.s1 e0 e1 g2)) (Equiv.refl (.seq e0 f1)))
      (Equiv.refl f0))
    (Equiv.u3 c1 b0 (.seq (.seq e0 e1) g2) (.seq e0 f1) f0))))

/-- An arbitrary-length chain-elimination certificate. `Reduction g₀ n g b e f` says that
    after crossing `n` guarded intermediate states, the head equation has been reduced to

        `g₀ ≡ b ? (e · g) : f`.

    `base` records the initial equation. Each `step` carries exactly the next state's
    equation and the pullback witness needed to cross its guard. The constructor computes
    the accumulated guard, body, and exit, so malformed elimination traces are unrepresentable. -/
inductive Reduction (g₀ : Exp A T) : Nat → Exp A T → BExp T → Exp A T → Exp A T → Prop where
  | base {g : Exp A T} {b : BExp T} {e f : Exp A T}
      (h : Equiv g₀ (.ite b (.seq e g) f)) : Reduction g₀ 0 g b e f
  | step {n : Nat} {g₁ g₂ : Exp A T} {b₀ b₁ c₁ : BExp T}
      {e₀ e₁ f₀ f₁ : Exp A T}
      (r : Reduction g₀ n g₁ b₀ e₀ f₀)
      (hpb : ∀ x y : Exp A T,
        Equiv (.seq e₀ (.ite b₁ x y)) (.ite c₁ (.seq e₀ x) (.seq e₀ y)))
      (h₁ : Equiv g₁ (.ite b₁ (.seq e₁ g₂) f₁)) :
      Reduction g₀ (n + 1) g₂ (.and c₁ b₀) (.seq e₀ e₁)
        (.ite b₀ (.seq e₀ f₁) f₀)

/-- Every finite reduction certificate denotes the reduced head equation it claims.
    Induction on the certificate is precisely `chain_elim^(n)`. -/
theorem reduction_equiv {g₀ g : Exp A T} {n : Nat} {b : BExp T} {e f : Exp A T}
    (r : Reduction g₀ n g b e f) : Equiv g₀ (.ite b (.seq e g) f) := by
  induction r with
  | base h => exact h
  | step r hpb h₁ ih => exact chain_elim hpb ih h₁

/-- **The arbitrary-`n` cycle theorem.** If a finite chain reduction returns to its head,
    the whole guarded cycle is one Salomaa loop. Thus an `n`-state cycle (represented by
    `n-1` crossings after its head equation) needs exactly the witnesses stored in the
    certificate and one final `W3`; there is no meta-level ellipsis left in the theorem. -/
theorem nary_cycle_solvable {g₀ : Exp A T} {n : Nat} {b : BExp T} {e f : Exp A T}
    (r : Reduction g₀ n g₀ b e f)
    (hguard : Equiv (Exp.test (E e) : Exp A T) (.test .zero)) :
    Equiv g₀ (.seq (.wh b e) f) :=
  salomaa_solution_unique hguard (reduction_equiv r)

/-- Two arbitrary-length reductions of two candidate heads to the same productive final
    equation agree. This is the `UAₙ` uniqueness conclusion, factored through `UA₁`. -/
theorem nary_cycle_unique {g₀ g₀' : Exp A T} {n m : Nat}
    {b : BExp T} {e f : Exp A T}
    (r : Reduction g₀ n g₀ b e f) (r' : Reduction g₀' m g₀' b e f)
    (hguard : Equiv (Exp.test (E e) : Exp A T) (.test .zero)) : Equiv g₀ g₀' :=
  Equiv.trans (nary_cycle_solvable r hguard)
    (Equiv.symm (nary_cycle_solvable r' hguard))

/-- **Three-state cycle solved via two witnesses + `W3`.** The `n=3` instance of the
    n-ary decomposition: two applications of `chain_elim` fold `g₁` then `g₂` into a single
    productive self-loop on `g₀`, closed by `W3`. The witnesses are `c₁ = wp(e₀,b₁)` and
    `c₂ = wp(e₀·e₁, b₂)` (the second on the *composite* body — exactly what iterating the
    kernel produces). Generalizes `crossed_closed_form_of_pullback` (the n=2 case). -/
theorem three_cycle_solvable_of_pullbacks
    {b0 b1 b2 c1 c2 : BExp T} {e0 e1 e2 f0 f1 f2 g0 g1 g2 : Exp A T}
    (hguard : Equiv (Exp.test (E (.seq (.seq e0 e1) e2)) : Exp A T) (.test .zero))
    (hpb1 : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hpb2 : ∀ x y : Exp A T,
      Equiv (.seq (.seq e0 e1) (.ite b2 x y))
            (.ite c2 (.seq (.seq e0 e1) x) (.seq (.seq e0 e1) y)))
    (h0 : Equiv g0 (.ite b0 (.seq e0 g1) f0))
    (h1 : Equiv g1 (.ite b1 (.seq e1 g2) f1))
    (h2 : Equiv g2 (.ite b2 (.seq e2 g0) f2)) :
    Equiv g0
      (.seq (.wh (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2))
        (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))) :=
  -- fold g₁ (g₀ now over g₂), then fold g₂ (g₀ now a self-loop), then W3
  salomaa_solution_unique hguard (chain_elim hpb2 (chain_elim hpb1 h0 h1) h2)

/-- **The reverse kernel (for EXISTENCE).** If `h` satisfies the *reduced* equation over
    the next state `g₂`, then `h` satisfies the *original* two-state form with the
    intermediate state reconstructed as `g₁ := b₁?(e₁·g₂):f₁`. This is `chain_elim`'s
    reshaping run backwards; iterating it rebuilds every intermediate state of the cycle,
    so the witness-built closed form provably SOLVES the system. -/
theorem chain_intro {b0 b1 c1 : BExp T} {e0 e1 f0 f1 g2 h : Exp A T}
    (hpb : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hred : Equiv h (.ite (.and c1 b0) (.seq (.seq e0 e1) g2) (.ite b0 (.seq e0 f1) f0))) :
    Equiv h (.ite b0 (.seq e0 (.ite b1 (.seq e1 g2) f1)) f0) :=
  Equiv.trans hred (Equiv.symm
    (Equiv.trans (Equiv.ite_c (hpb (.seq e1 g2) f1) (Equiv.refl f0))
    (Equiv.trans
      (Equiv.ite_c (Equiv.ite_c (Equiv.symm (Equiv.s1 e0 e1 g2)) (Equiv.refl (.seq e0 f1)))
        (Equiv.refl f0))
      (Equiv.u3 c1 b0 (.seq (.seq e0 e1) g2) (.seq e0 f1) f0))))

/-- An arbitrary-length reverse-elimination certificate. `Introduction n h rhs` records
    that the synthesized head `h` is obtained from one canonical Salomaa solution followed
    by `n` applications of `chain_intro`. Unlike `Reduction`, this certificate contains no
    pre-existing unknown solutions: every crossed state is reconstructed as its guarded
    equation, which is exactly the existence direction needed by synthesis. -/
inductive Introduction : Nat → Exp A T → Exp A T → Prop where
  | base (b : BExp T) (e f : Exp A T) :
      Introduction 0 (.seq (.wh b e) f) (.ite b (.seq e (.seq (.wh b e) f)) f)
  | step {n : Nat} {h g₂ : Exp A T} {b₀ b₁ c₁ : BExp T}
      {e₀ e₁ f₀ f₁ : Exp A T}
      (r : Introduction n h
        (.ite (.and c₁ b₀) (.seq (.seq e₀ e₁) g₂) (.ite b₀ (.seq e₀ f₁) f₀)))
      (hpb : ∀ x y : Exp A T,
        Equiv (.seq e₀ (.ite b₁ x y)) (.ite c₁ (.seq e₀ x) (.seq e₀ y))) :
      Introduction (n + 1) h (.ite b₀ (.seq e₀ (.ite b₁ (.seq e₁ g₂) f₁)) f₀)

/-- Every finite introduction certificate is a proof that its canonical closed form solves
    the fully reconstructed nested cycle equation. Induction is `chain_intro^(n)` on top of
    `salomaa_solution_exists`. -/
theorem introduction_equiv {n : Nat} {h rhs : Exp A T} (r : Introduction n h rhs) :
    Equiv h rhs := by
  induction r with
  | base b e f => exact salomaa_solution_exists b e f
  | step r hpb ih => exact chain_intro hpb ih

/-- An arbitrary-length reverse-elimination certificate for a Thompson-shaped loop body.
    There is one guarded loop head, while every intermediate state is a pure continuation.
    Consequently each reconstruction step uses only sequential associativity: unlike
    `Introduction`, no guard-pullback witness is needed. -/
inductive PureIntroduction : Nat → Exp A T → Exp A T → Prop where
  | base (b : BExp T) (e f : Exp A T) :
      PureIntroduction 0 (.seq (.wh b e) f) (.ite b (.seq e (.seq (.wh b e) f)) f)
  | step {n : Nat} {h g₂ : Exp A T} {b : BExp T} {e₀ e₁ f : Exp A T}
      (r : PureIntroduction n h (.ite b (.seq (.seq e₀ e₁) g₂) f)) :
      PureIntroduction (n + 1) h (.ite b (.seq e₀ (.seq e₁ g₂)) f)

/-- Every finite pure-continuation reconstruction is derivable from the original finite
    rules. This is the certificate-level, arbitrary-arity Thompson-loop theorem: the base
    is the scalar Salomaa solution and every additional control state is introduced by
    `S1` alone. -/
theorem pureIntroduction_equiv {n : Nat} {h rhs : Exp A T}
    (r : PureIntroduction n h rhs) : Equiv h rhs := by
  induction r with
  | base b e f => exact salomaa_solution_exists b e f
  | @step n h g₂ b e₀ e₁ f r ih =>
      exact Equiv.trans ih
        (Equiv.ite_c (Equiv.s1 e₀ e₁ g₂) (Equiv.refl f))

/-- Right-associated execution of pure continuation bodies before returning to `head`. -/
def pureNest : List (Exp A T) → Exp A T → Exp A T
  | [], head => head
  | e :: es, head => .seq e (pureNest es head)

/-- The single expression obtained by composing a loop head body with all of its pure
    continuation bodies, in control-flow order. -/
def pureBody : Exp A T → List (Exp A T) → Exp A T :=
  List.foldl Exp.seq

/-- Construct the complete reverse-elimination trace for any finite Thompson-shaped loop.
    The resulting closed form executes the left-associated composite `pureBody e₀ es` in
    the scalar `while`, while its equation exposes the original right-associated chain of
    pure continuation states. -/
def pureIntroduction (b : BExp T) (e₀ f : Exp A T) (es : List (Exp A T)) :
    PureIntroduction es.length
      (.seq (.wh b (pureBody e₀ es)) f)
      (.ite b
        (.seq e₀ (pureNest es (.seq (.wh b (pureBody e₀ es)) f)))
        f) := by
  induction es generalizing e₀ with
  | nil => exact PureIntroduction.base b e₀ f
  | cons e₁ es ih =>
      change PureIntroduction (es.length + 1)
        (.seq (.wh b (pureBody (.seq e₀ e₁) es)) f)
        (.ite b
          (.seq e₀
            (.seq e₁
              (pureNest es (.seq (.wh b (pureBody (.seq e₀ e₁) es)) f))))
          f)
      exact PureIntroduction.step (ih (e₀ := .seq e₀ e₁))

/-- Fully automatic arbitrary-length Thompson-loop equation, using only the finite GKAT
    rules. This is the list-level form needed by a future automaton-to-certificate bridge. -/
theorem pureCycle_equiv (b : BExp T) (e₀ f : Exp A T) (es : List (Exp A T)) :
    Equiv
      (.seq (.wh b (pureBody e₀ es)) f)
      (.ite b
        (.seq e₀ (pureNest es (.seq (.wh b (pureBody e₀ es)) f)))
        f) :=
  pureIntroduction_equiv (pureIntroduction b e₀ f es)

/-! ## Full two-sorted certificates for Thompson continuation states -/

/-- Equations for every pure continuation state in a list. A state whose remaining bodies
    are `e :: es` denotes `e · pureNest es head`; its raw deterministic automaton equation
    is `1 ? (e · pureNest es head) : 0`. Keeping this evidence inductively retains the whole
    state family rather than erasing it to the collapsed head equation. -/
inductive PureTailEquationsBA (head : Exp A T) : List (Exp A T) → Prop where
  | nil : PureTailEquationsBA head []
  | cons (e : Exp A T) (es : List (Exp A T))
      (equation : GkatFaithful.EquivBA (pureNest (e :: es) head)
        (.ite .one (.seq e (pureNest es head)) (.test .zero)))
      (rest : PureTailEquationsBA head es) :
      PureTailEquationsBA head (e :: es)

/-- Every list of pure continuation bodies automatically supplies all of its equations.
    Each state is definitional on the left and uses the derived `ite_one` law on the right. -/
def pureTailEquationsBA (head : Exp A T) : ∀ es : List (Exp A T),
    PureTailEquationsBA head es
  | [] => .nil
  | e :: es => .cons e es
      (GkatFaithful.EquivBA.symm (GkatFaithful.ite_one _ _))
      (pureTailEquationsBA head es)

/-- A complete provable solution certificate for one Thompson-shaped loop SCC: one guarded
    head and an arbitrary finite list of unconditional continuation states. -/
structure PureLoopSolutionBA (b : BExp T) (e₀ f : Exp A T) (es : List (Exp A T)) where
  head : Exp A T
  headEquation : GkatFaithful.EquivBA head
    (.ite b (.seq e₀ (pureNest es head)) f)
  tailEquations : PureTailEquationsBA head es

/-- Construct the full state-family solution. The head is the scalar loop over the composed
    body; `pureCycle_equiv` proves its guarded equation and `pureTailEquationsBA` reconstructs
    every unconditional state. No UA or semantic argument occurs in this compiler. -/
def pureLoopSolutionBA (b : BExp T) (e₀ f : Exp A T) (es : List (Exp A T)) :
    PureLoopSolutionBA b e₀ f es where
  head := .seq (.wh b (pureBody e₀ es)) f
  headEquation := GkatFaithful.EquivBA.base (pureCycle_equiv b e₀ f es)
  tailEquations := pureTailEquationsBA _ es

/-- **EXISTENCE for the 3-cycle (no productivity needed).** The witness-built closed form
    `CF` actually solves the 3-state cycle: reconstructing `g₂ := b₂?(e₂·CF):f₂` and
    `g₁ := b₁?(e₁·g₂):f₁`, `CF ≡ b₀?(e₀·g₁):f₀`. Two `chain_intro`s on top of the canonical
    loop solution (`salomaa_solution_exists`, which needs no side-condition) — the existence
    direction the completeness programme actually needs (Pham reduced completeness to
    existence). The `chain_intro^(n-1) ∘ salomaa_solution_exists` pattern gives general `n`. -/
theorem three_cycle_solves_of_pullbacks
    {b0 b1 b2 c1 c2 : BExp T} {e0 e1 e2 f0 f1 f2 : Exp A T}
    (hpb1 : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hpb2 : ∀ x y : Exp A T,
      Equiv (.seq (.seq e0 e1) (.ite b2 x y))
            (.ite c2 (.seq (.seq e0 e1) x) (.seq (.seq e0 e1) y))) :
    let CF : Exp A T := .seq (.wh (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2))
              (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))
    Equiv CF (.ite b0 (.seq e0 (.ite b1 (.seq e1 (.ite b2 (.seq e2 CF) f2)) f1)) f0) :=
  chain_intro hpb1 (chain_intro hpb2
    (salomaa_solution_exists (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2)
      (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))))

/-- The certificate-level form of `three_cycle_solves_of_pullbacks`. It preserves the
    two reverse-elimination steps instead of immediately erasing them to an equivalence,
    allowing downstream finite-cycle compilers to retain the reconstructed state family. -/
def threeCycleIntroduction
    {b0 b1 b2 c1 c2 : BExp T} {e0 e1 e2 f0 f1 f2 : Exp A T}
    (hpb1 : ∀ x y : Exp A T, Equiv (.seq e0 (.ite b1 x y)) (.ite c1 (.seq e0 x) (.seq e0 y)))
    (hpb2 : ∀ x y : Exp A T,
      Equiv (.seq (.seq e0 e1) (.ite b2 x y))
            (.ite c2 (.seq (.seq e0 e1) x) (.seq (.seq e0 e1) y))) :
    let CF : Exp A T := .seq (.wh (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2))
              (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0))
    Introduction 2 CF
      (.ite b0 (.seq e0 (.ite b1 (.seq e1 (.ite b2 (.seq e2 CF) f2)) f1)) f0) :=
  Introduction.step
    (Introduction.step
      (Introduction.base (.and c2 (.and c1 b0)) (.seq (.seq e0 e1) e2)
        (.ite (.and c1 b0) (.seq (.seq e0 e1) f2) (.ite b0 (.seq e0 f1) f0)))
      hpb2)
    hpb1

#print axioms chain_elim
#print axioms chain_intro
#print axioms reduction_equiv
#print axioms nary_cycle_solvable
#print axioms nary_cycle_unique
#print axioms introduction_equiv
#print axioms pureIntroduction_equiv
#print axioms pureIntroduction
#print axioms pureCycle_equiv
#print axioms pureTailEquationsBA
#print axioms pureLoopSolutionBA
#print axioms three_cycle_solvable_of_pullbacks
#print axioms three_cycle_solves_of_pullbacks
#print axioms threeCycleIntroduction

end GkatChainElim
