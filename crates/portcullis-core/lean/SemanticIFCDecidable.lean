import Mathlib.Data.Fintype.Basic
import Mathlib.Order.BooleanAlgebra.Defs
import SemanticIFC

/-!
# Decidable Internal Logic — Foundation Types

First step in the decidable internal logic roadmap (issue #1428, tracking #1427).

## Goal

Provide `Bool`-valued mirrors of the `Prop`-valued types in `SemanticIFC.lean`,
so that the internal logic of the presheaf topos becomes mechanically decidable
for finite `Secret` types.

This file does not touch the existing classical formalization. It provides:

1. `FiniteSecret` — type class bundling `Fintype` + `DecidableEq`
2. `DProp Secret := Secret → Bool` — decidable propositions
3. Boolean algebra structure on `DProp`
4. Coercion `DProp.toProp : DProp Secret → Proposition Secret`
5. `ThreeSecret` instance and example `#eval` propositions

Subsequent issues (#1429, #1430, #1431, #1432) will build on these types
to provide decidable forcing, decidable observation levels, computable
sheaf cohomology, and decidable security games.
-/

namespace SemanticIFCDecidable

open SemanticIFC

/-! ## FiniteSecret type class

Bundles the requirements needed for the internal logic to be decidable:
- `Fintype` so universal/existential quantifiers over `Secret` are decidable
- `DecidableEq` so individual secrets can be compared mechanically

Lives in `Type` (not `Type u`) so that `Proposition Secret := Secret → Prop`
in the existing `SemanticIFC` namespace remains compatible.
-/

class FiniteSecret (Secret : Type) : Type where
  toFintype : Fintype Secret
  toDecidableEq : DecidableEq Secret

attribute [instance] FiniteSecret.toFintype FiniteSecret.toDecidableEq

/-! ## DProp — decidable propositions

A `DProp` is a `Bool`-valued function on secrets. Unlike `Proposition Secret`
(which is `Secret → Prop`), every `DProp` is mechanically evaluable: for any
concrete secret `s`, the value `p s : Bool` is computed by ordinary reduction.
-/

abbrev DProp (Secret : Type) := Secret → Bool

namespace DProp
variable {Secret : Type}

/-- The constantly-true proposition. -/
def constTrue : DProp Secret := fun _ => true

/-- The constantly-false proposition. -/
def constFalse : DProp Secret := fun _ => false

/-- Negation of a decidable proposition. -/
def neg (p : DProp Secret) : DProp Secret := fun s => !p s

/-- Conjunction of two decidable propositions. -/
def and (p q : DProp Secret) : DProp Secret := fun s => p s && q s

/-- Disjunction of two decidable propositions. -/
def or (p q : DProp Secret) : DProp Secret := fun s => p s || q s

/-- Implication of two decidable propositions. -/
def imp (p q : DProp Secret) : DProp Secret := fun s => !p s || q s

instance : Inhabited (DProp Secret) := ⟨constFalse⟩

/-! ### Pointwise order: `p ≤ q` iff `p s → q s` for all secrets -/

instance : LE (DProp Secret) := ⟨fun p q => ∀ s, p s = true → q s = true⟩

instance : Bot (DProp Secret) := ⟨constFalse⟩
instance : Top (DProp Secret) := ⟨constTrue⟩

@[simp] theorem constFalse_apply (s : Secret) : (constFalse : DProp Secret) s = false := rfl
@[simp] theorem constTrue_apply (s : Secret) : (constTrue : DProp Secret) s = true := rfl
@[simp] theorem neg_apply (p : DProp Secret) (s : Secret) : (neg p) s = !p s := rfl
@[simp] theorem and_apply (p q : DProp Secret) (s : Secret) : (and p q) s = (p s && q s) := rfl
@[simp] theorem or_apply (p q : DProp Secret) (s : Secret) : (or p q) s = (p s || q s) := rfl
@[simp] theorem imp_apply (p q : DProp Secret) (s : Secret) : (imp p q) s = (!p s || q s) := rfl

/-! ### Coercion to classical `Proposition`

A `DProp` lifts to a classical proposition by reading `true` as `True`. This
lets us connect decidable theorems to the existing classical theory in
`SemanticIFC.lean` without rewriting any proofs.
-/

/-- Coerce a decidable proposition to a classical proposition. -/
def toProp (p : DProp Secret) : Proposition Secret := fun s => p s = true

@[simp] theorem toProp_apply (p : DProp Secret) (s : Secret) :
    p.toProp s ↔ p s = true := Iff.rfl

@[simp] theorem toProp_constTrue : (constTrue : DProp Secret).toProp = fun _ => True := by
  funext s
  simp [toProp, constTrue]

@[simp] theorem toProp_constFalse : (constFalse : DProp Secret).toProp = fun _ => False := by
  funext s
  simp [toProp, constFalse]

theorem toProp_neg (p : DProp Secret) :
    (neg p).toProp = fun s => ¬ p.toProp s := by
  funext s
  simp [toProp, neg]

theorem toProp_and (p q : DProp Secret) :
    (and p q).toProp = fun s => p.toProp s ∧ q.toProp s := by
  funext s
  simp [toProp, and, Bool.and_eq_true]

theorem toProp_or (p q : DProp Secret) :
    (or p q).toProp = fun s => p.toProp s ∨ q.toProp s := by
  funext s
  simp [toProp, or, Bool.or_eq_true]

end DProp

/-! ## ThreeSecret instance

The classical formalization defines `ThreeSecret` as `inductive ThreeSecret | A | B | C`
with `deriving DecidableEq, Repr`. We provide the `FiniteSecret` instance and
a few example decidable propositions.
-/

instance : Fintype ThreeSecret where
  elems := {ThreeSecret.A, ThreeSecret.B, ThreeSecret.C}
  complete := fun s => by cases s <;> decide

instance : FiniteSecret ThreeSecret where
  toFintype := inferInstance
  toDecidableEq := inferInstance

namespace ThreeSecretExamples
open DProp

/-- The proposition "the secret is A". -/
def isA : DProp ThreeSecret := fun s => decide (s = ThreeSecret.A)

/-- The proposition "the secret is B". -/
def isB : DProp ThreeSecret := fun s => decide (s = ThreeSecret.B)

/-- The proposition "the secret is C". -/
def isC : DProp ThreeSecret := fun s => decide (s = ThreeSecret.C)

/-- The proposition "the secret is not B" (negation of `isB`). -/
def notB : DProp ThreeSecret := neg isB

/-- The proposition "the secret is A or B". -/
def isAorB : DProp ThreeSecret := or isA isB

/-! ### Sanity checks via `decide`

These run as ordinary Lean computations. If anything goes wrong,
`#eval` will tell us immediately.
-/

example : isA ThreeSecret.A = true := by decide
example : isA ThreeSecret.B = false := by decide
example : isA ThreeSecret.C = false := by decide

example : (and isA isB) ThreeSecret.A = false := by decide
example : (or isA isB) ThreeSecret.A = true := by decide
example : (or isA isB) ThreeSecret.C = false := by decide
example : (neg isB) ThreeSecret.B = false := by decide
example : (neg isB) ThreeSecret.A = true := by decide

/-- The classical theorem `isA → ¬ isB` follows trivially from the decidable version. -/
example : ∀ s, (and isA isB) s = false := by decide

end ThreeSecretExamples

end SemanticIFCDecidable
