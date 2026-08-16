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

## Where the naive induction fails

The obvious route is to induct on the degree, with the step

    InitCover (loop g X) (loop g B)  →  InitCover (loop g (X ; (g ? B : 1))) (loop g B)

and it does not work, for a reason worth recording so it is not rediscovered.

A cover *of the loops* carries strictly less information than the step needs.  `loop g X`
sets `hlt u = X.hlt u ∧ ¬g`, so `φ.coreHlt_eq` says only that `X.hlt u` and `B.hlt (map u)`
agree **at ¬g atoms** — at `g` atoms both sides are false and the equation is vacuous.  But
the appended `seq` routes its exits by `X.hlt u` at *every* atom, `g` atoms included, so the
step needs agreement the hypothesis does not provide.

Strengthening to a cover of the *bodies* does not help either: `X ; (g ? B : 1)` does not
cover `B`.  Its `hlt (inl u)` is `B.hlt u ∧ (g ? B : 1).initHlt`, which is not equivalent to
`B.hlt u`.  That is why `cyclicCover` is stated about the loops in the first place.

So the induction needs an invariant that is neither "the loops cover" nor "the bodies cover",
and finding it is the open part.  The definitions and the target are stated here so the
obligation is named rather than implicit.
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
