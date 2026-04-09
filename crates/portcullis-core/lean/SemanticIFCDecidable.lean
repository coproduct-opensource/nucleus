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

/-! ## DObsLevel — decidable observation levels

A `DObsLevel` is the Bool-valued mirror of `ObsLevel`. The equivalence
relation lives in `Bool` instead of `Prop`, with refl/symm/trans laws
expressed as `Bool` equalities. This makes `dForces` (issue #1430)
mechanically decidable for any finite `Secret` type.

The classical `ObsLevel` is unchanged; we provide a coercion
`DObsLevel.toObsLevel : DObsLevel Secret → ObsLevel Secret` so the
existing classical theorems remain applicable.
-/

structure DObsLevel (Secret : Type) where
  /-- The Bool-valued equivalence relation. -/
  rel : Secret → Secret → Bool
  /-- Reflexivity: every secret is related to itself. -/
  refl : ∀ s, rel s s = true
  /-- Symmetry: if s₁ is related to s₂, then s₂ is related to s₁. -/
  symm : ∀ s₁ s₂, rel s₁ s₂ = true → rel s₂ s₁ = true
  /-- Transitivity. -/
  trans : ∀ s₁ s₂ s₃, rel s₁ s₂ = true → rel s₂ s₃ = true → rel s₁ s₃ = true

namespace DObsLevel
variable {Secret : Type}

/-- The coarsest observation level: everything is related to everything.
    Reveals nothing about the secret. -/
def bot : DObsLevel Secret where
  rel _ _ := true
  refl _ := rfl
  symm _ _ _ := rfl
  trans _ _ _ _ _ := rfl

/-- The finest observation level: only equal secrets are related.
    Reveals everything (requires `DecidableEq`). -/
def top [DecidableEq Secret] : DObsLevel Secret where
  rel s₁ s₂ := decide (s₁ = s₂)
  refl s := by simp
  symm s₁ s₂ h := by
    have : s₁ = s₂ := of_decide_eq_true h
    simp [this]
  trans s₁ s₂ s₃ h₁ h₂ := by
    have e₁ : s₁ = s₂ := of_decide_eq_true h₁
    have e₂ : s₂ = s₃ := of_decide_eq_true h₂
    simp [e₁, e₂]

/-! ### Refinement order

`E₁ ≤ E₂` means `E₂` refines `E₁`: every pair related under `E₂` is also
related under `E₁`. So `E₂` distinguishes more secrets, `E₁` is coarser.
This matches the classical `ObsLevel` order in `SemanticIFC.lean`.
-/

instance : LE (DObsLevel Secret) where
  le E₁ E₂ := ∀ s₁ s₂, E₂.rel s₁ s₂ = true → E₁.rel s₁ s₂ = true

instance : Preorder (DObsLevel Secret) where
  le_refl _ _ _ h := h
  le_trans E₁ E₂ E₃ h₁₂ h₂₃ s₁ s₂ h₃ := h₁₂ s₁ s₂ (h₂₃ s₁ s₂ h₃)

/-- `bot` is below everything (it's the coarsest). -/
theorem bot_le (E : DObsLevel Secret) : (bot : DObsLevel Secret) ≤ E := by
  intro _ _ _
  rfl

/-- Everything is below `top` (it's the finest). -/
theorem le_top [DecidableEq Secret] (E : DObsLevel Secret) : E ≤ (top : DObsLevel Secret) := by
  intro s₁ s₂ h
  have : s₁ = s₂ := of_decide_eq_true h
  rw [this]
  exact E.refl s₂

/-! ### Coercion to classical `ObsLevel`

Reading the Bool-valued relation as a Prop-valued relation gives us
back the classical `ObsLevel`. This bridge lets us apply the existing
classical theorems to anything we prove decidably.
-/

/-- Coerce a `DObsLevel` to a classical `ObsLevel`. -/
def toObsLevel (E : DObsLevel Secret) : ObsLevel Secret where
  rel s₁ s₂ := E.rel s₁ s₂ = true
  equiv := {
    refl := E.refl
    symm := fun {s₁ s₂} h => E.symm s₁ s₂ h
    trans := fun {s₁ s₂ s₃} h₁ h₂ => E.trans s₁ s₂ s₃ h₁ h₂
  }

@[simp] theorem toObsLevel_rel (E : DObsLevel Secret) (s₁ s₂ : Secret) :
    E.toObsLevel.rel s₁ s₂ ↔ E.rel s₁ s₂ = true := Iff.rfl

/-- Refinement order is preserved by the coercion. -/
theorem toObsLevel_monotone {E₁ E₂ : DObsLevel Secret} (h : E₁ ≤ E₂) :
    E₁.toObsLevel ≤ E₂.toObsLevel := by
  intro s₁ s₂ h₂
  exact h s₁ s₂ h₂

end DObsLevel

/-! ## ThreeSecret instances

The classical formalization defines four observation levels for `ThreeSecret`:
`bot` (everything equivalent), `obsAC` (A≡C), `obsBC` (B≡C), and `top` (all distinct).

These are the diamond poset whose H¹ is non-zero (the alignment tax). We
provide Bool-valued mirrors here so they're `#eval`-able.
-/

namespace ThreeSecretObs
open DObsLevel ThreeSecret

/-- A and C are equivalent; B is distinct. -/
def obsAC : DObsLevel ThreeSecret where
  rel s₁ s₂ := match s₁, s₂ with
    | A, A => true | A, C => true | C, A => true
    | B, B => true | C, C => true | _, _ => false
  refl s := by cases s <;> rfl
  symm s₁ s₂ h := by cases s₁ <;> cases s₂ <;> first | rfl | exact h
  trans s₁ s₂ s₃ h₁ h₂ := by
    cases s₁ <;> cases s₂ <;> cases s₃ <;>
      first | rfl | (exfalso; exact Bool.false_ne_true h₁)
            | (exfalso; exact Bool.false_ne_true h₂)

/-- B and C are equivalent; A is distinct. -/
def obsBC : DObsLevel ThreeSecret where
  rel s₁ s₂ := match s₁, s₂ with
    | A, A => true | B, B => true | B, C => true
    | C, B => true | C, C => true | _, _ => false
  refl s := by cases s <;> rfl
  symm s₁ s₂ h := by cases s₁ <;> cases s₂ <;> first | rfl | exact h
  trans s₁ s₂ s₃ h₁ h₂ := by
    cases s₁ <;> cases s₂ <;> cases s₃ <;>
      first | rfl | (exfalso; exact Bool.false_ne_true h₁)
            | (exfalso; exact Bool.false_ne_true h₂)

/-! ### Sanity checks

These are decidable computations on the four ThreeSecret observation levels.
-/

example : (bot : DObsLevel ThreeSecret).rel A B = true := by decide
example : (bot : DObsLevel ThreeSecret).rel B C = true := by decide
example : obsAC.rel A C = true := by decide
example : obsAC.rel A B = false := by decide
example : obsBC.rel B C = true := by decide
example : obsBC.rel A B = false := by decide
example : (top : DObsLevel ThreeSecret).rel A A = true := by decide
example : (top : DObsLevel ThreeSecret).rel A B = false := by decide

/-- `obsAC ≠ obsBC` because they distinguish different secrets. -/
example : obsAC.rel A C ≠ obsBC.rel A C := by decide

/-- The three intermediate ObsLevels: bot is coarsest, top is finest,
    obsAC and obsBC are incomparable. -/
example : (bot : DObsLevel ThreeSecret) ≤ obsAC := bot_le obsAC
example : (bot : DObsLevel ThreeSecret) ≤ obsBC := bot_le obsBC
example : obsAC ≤ (top : DObsLevel ThreeSecret) := le_top obsAC
example : obsBC ≤ (top : DObsLevel ThreeSecret) := le_top obsBC

end ThreeSecretObs

end SemanticIFCDecidable
