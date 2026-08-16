import GkatCyclicCoverProofs

/-!
# The degree-`k` cyclic cover

The search gate settled which degree the synthesis needs.  For every crux pullback,

    period(P) = lcm(period e, period f)          273 / 273, at K = 5 and K = 6

so covering the pullback means cyclic-covering `e`'s loop to degree
`lcm(period e, period f) / period e` — computable from the two programs, with no search.
The observed periods are 1, 2, 3 and 6, so **degree 3 occurs**, and degree 3 is exactly what
composition cannot reach: `cyclicCover` composed with itself gives 2, 4, 8, … (see
`GkatCofinality.cyclicCover4`).  Hence this file.

## Where the naive induction fails, and what it actually needs

The obvious route is to induct on the degree with the step

    InitCover (loop g X) (loop g B)  →  InitCover (loop g (X ; (g ? B : 1))) (loop g B)

Working degree 3 out by hand shows the *construction* is fine — the concern that the extra
`(g ? B : 1).initHlt` conjunct breaks the guards is unfounded, because the outer exit block
is always subsumed by an earlier inner one and is unreachable by list ordering, exactly as in
the degree-2 proof.  What fails is the **induction hypothesis**, and for a sharper reason.

`InitCover (loop g X) (loop g B)` constrains `firstMatch` over the *combined* list

    X.core.trans s  ++  X.initTrans.map (and (X.core.hlt s) (and g ·))

— body transitions and back edges together.  The step needs the two blocks *separately*: in
`bodyK (n+1)`, the block that advances from copy `i` to copy `i+1` plays the role of `B`'s
back edge, while the enclosing loop supplies the back edge only for the last copy.  From
`firstMatch (L₁ ++ L₂) = firstMatch (L₁' ++ L₂')` one cannot recover
`firstMatch L₁ = firstMatch L₁'`, so the hypothesis is genuinely too weak.

Strengthening to a cover of the *bodies* does not help either: `X ; (g ? B : 1)` does not
cover `B`, since `hlt (inl u) = B.hlt u ∧ (g ? B : 1).initHlt`.  That is precisely why
`cyclicCover` is stated about the loops.

So the invariant is neither "the loops cover" nor "the bodies cover".  It is the
**parameterized** one: `bodyK g B n` behaves like `B` *relative to an arbitrary continuation*,
with the continuation supplying whatever the enclosing context contributes — the next copy's
entry for the inner copies, the loop's back edge for the last.  That is the same shape as
`ParamSolvesBA` / `eqRHSParam` / `ParametricCanonicalBA` in
`GkatThompsonUniquenessProofs`, which exist because the Thompson certificate needed exactly
this move: a statement about a component that survives being embedded in a context.

Proving the parameterized form settles every degree at once, rather than degree 3 by a
second three-hundred-line replay of the degree-2 argument.
-/

namespace GkatCyclicK
open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatSynthesis GkatCyclicCover
variable {A T : Type}

/-- The state type of the `k`-fold body: index `n` is degree `n+1`. -/
def BodyState (S : Type) : Nat → Type
  | 0 => S
  | (n + 1) => Sum (BodyState S n) (Sum S Empty)

/-- `B ; (g ? B : 1) ; ... ; (g ? B : 1)` with `n` appended copies — degree `n+1`. -/
def bodyK {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    (n : Nat) → InitializedGAut (BodyState S n) A T
  | 0 => B
  | (n + 1) =>
      seqInitialized (bodyK g B n) (iteInitialized g B (thompsonTest (A := A) BExp.one))

/-- Every copy folds onto the original body. -/
def bodyMap {S : Type} : (n : Nat) → BodyState S n → S
  | 0, s => s
  | (n + 1), Sum.inl u => bodyMap n u
  | (n + 1), Sum.inr (Sum.inl u) => u
  | (n + 1), Sum.inr (Sum.inr z) => nomatch z

/-- Degree 1 is the identity: `bodyK g B 0` is `B` itself. -/
def cyclicCover1 {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    InitCover (loopInitialized g (bodyK g B 0)) (loopInitialized g B) :=
  InitCover.id _

/-- **The target.**  Repeating the loop body `n+1` times refines the loop, at every degree.

    Degree 2 is `GkatCyclicCover.cyclicCover`, proved; degrees 4, 8, … follow by composing it
    with itself.  What is open is every other degree — 3 first, which the gate shows is
    actually needed. -/
def CyclicCoverK (A T : Type) : Prop :=
  ∀ {S : Type} (g : BExp T) (B : InitializedGAut S A T) (n : Nat),
    Nonempty (InitCover (loopInitialized g (bodyK g B n)) (loopInitialized g B))

/-- Non-vacuity: degree 1 holds, so the statement is satisfiable at some degree. -/
theorem cyclicCoverK_degree_one {S : Type} (g : BExp T) (B : InitializedGAut S A T) :
    Nonempty (InitCover (loopInitialized g (bodyK g B 0)) (loopInitialized g B)) :=
  ⟨cyclicCover1 g B⟩

#print axioms cyclicCover1
#print axioms cyclicCoverK_degree_one

end GkatCyclicK
