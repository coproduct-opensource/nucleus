import GkatSyntaxProofs

/-!
# Semantic layer: observation, saturation, and guard-definability

The syntactic obstruction to eliminating UA (see `GkatUAIndependenceProofs`) is the
guard-pullback witness `c` with `e·(b?x:y) ≡ c?(e·x):(e·y)`, morally `c = wp(e,b)`.
Whether such a `c` *exists as a GKAT test* is a **definability** question, and it has a
crisp characterization: a semantic predicate is expressible by a test exactly when it
**descends to the observation quotient** — is constant on states that agree on all
primitive tests.

This file builds that layer over an abstract state type `S` with a primitive valuation
`V : T → S → Bool`:

* `beval` — Boolean evaluation of a test at a state.
* `ObsEq` — states agreeing on every primitive test.
* `Saturated` / `Definable` — descending to the quotient vs. test-expressible.
* `definable_imp_saturated` — the **obstruction direction**: any test respects `ObsEq`,
  so a predicate splitting an observation class is NOT test-definable.
* `wpSem`, `wp_not_definable` — the **tiny regime-3 fixture**: a deterministic action
  whose `wp(e,b)` splits an observation atom, hence is provably guard-non-definable —
  the genuine obstruction, with no model-search, `sorryAx`-free.

This separates the three regimes cleanly (see `GkatUAIndependenceProofs`): decoupled
(`c=b`), crossed-but-definable (`c=b̄`, saturated), and crossed-non-definable (here).
-/

namespace GkatObs

open GkatSyntax

variable {T S : Type}

/-- Boolean evaluation of a test at a semantic state, relative to a primitive valuation. -/
def beval (V : T → S → Bool) : BExp T → S → Bool
  | .zero,    _ => false
  | .one,     _ => true
  | .prim t,  s => V t s
  | .and b c, s => beval V b s && beval V c s
  | .or b c,  s => beval V b s || beval V c s
  | .not b,   s => ! beval V b s

/-- Observational equivalence: states that agree on all primitive tests. -/
def ObsEq (V : T → S → Bool) (s t : S) : Prop := ∀ p : T, V p s = V p t

/-- A semantic predicate is guard-definable if some test's evaluation matches it. -/
def Definable (V : T → S → Bool) (P : S → Bool) : Prop :=
  ∃ b : BExp T, ∀ s, beval V b s = P s

/-- P descends to the observation quotient: constant on `ObsEq` classes. -/
def Saturated (V : T → S → Bool) (P : S → Bool) : Prop :=
  ∀ s t, ObsEq V s t → P s = P t

/-- Every test respects observational equivalence (induction on the test): a test is a
    Boolean combination of primitives, so it cannot see finer than the primitives. -/
theorem beval_respects_obseq (V : T → S → Bool) (b : BExp T) {s t : S}
    (h : ObsEq V s t) : beval V b s = beval V b t := by
  induction b with
  | zero => rfl
  | one => rfl
  | prim p => exact h p
  | and b c ihb ihc => simp only [beval, ihb, ihc]
  | or b c ihb ihc => simp only [beval, ihb, ihc]
  | not b ih => simp only [beval, ih]

/-- **(B), obstruction direction.** Guard-definable ⟹ saturated. Contrapositive: a
    predicate that splits an observation class is expressible by NO GKAT test. This is
    the load-bearing fact for turning inexpressibility into an obstruction. -/
theorem definable_imp_saturated (V : T → S → Bool) {P : S → Bool}
    (h : Definable V P) : Saturated V P := by
  obtain ⟨b, hb⟩ := h
  intro s t hst
  rw [← hb s, ← hb t]; exact beval_respects_obseq V b hst

/-- Semantic weakest precondition of a test `b` across a deterministic action `e`:
    `wp(e,b)(s) = b(e s)`. This is the semantic object the pullback witness `c` must
    represent syntactically. -/
def wpSem (V : T → S → Bool) (e : S → S) (b : BExp T) : S → Bool :=
  fun s => beval V b (e s)

/-- `wp(e,b)` is guard-definable ⟹ it descends across `e`: the effect of `e` on the
    observable `b` factors through the observation quotient. (Instance of `(B)`.) -/
theorem wp_definable_imp_descends (V : T → S → Bool) (e : S → S) (b : BExp T)
    (h : Definable V (wpSem V e b)) :
    ∀ s t, ObsEq V s t → beval V b (e s) = beval V b (e t) :=
  definable_imp_saturated V h

/-! ## The tiny non-definable crossing (regime 3)

One primitive test, four states. Two states `0,1` agree on every test (both `¬b`), but
the action `e` sends `0` into the `b`-region and fixes `1` outside it. So `wp(e,b)`
splits the observation atom `{0,1}` — no test can express it. -/

namespace Fixture

/-- Single primitive test, true exactly on the "upper half" `{2,3}` of `Fin 4`. -/
def V : Unit → Fin 4 → Bool := fun _ s => decide (2 ≤ s.val)

/-- Action toggling only state `0` up into the `b`-region; identity elsewhere. -/
def act : Fin 4 → Fin 4 := fun s => if s = 0 then 2 else s

/-- States `0` and `1` are observationally equivalent (both fail the only test). -/
theorem obseq_0_1 : ObsEq V (0 : Fin 4) 1 := by intro p; cases p; decide

/-- Yet `wp(act, b)` distinguishes them: `b(act 0)=b(2)=⊤`, `b(act 1)=b(1)=⊥`. -/
theorem wp_splits :
    beval V (.prim ()) (act 0) ≠ beval V (.prim ()) (act 1) := by decide

/-- **The obstruction, certified.** `wp(act, b)` is expressible by no GKAT test: it
    splits an observation atom, contradicting `definable_imp_saturated`. A regime-3
    (crossed-and-non-definable) crossing, proven with no model search. -/
theorem wp_not_definable : ¬ Definable V (wpSem V act (.prim ())) := by
  intro h
  exact wp_splits (wp_definable_imp_descends V act (.prim ()) h 0 1 obseq_0_1)

end Fixture

#print axioms definable_imp_saturated
#print axioms Fixture.wp_not_definable

end GkatObs
