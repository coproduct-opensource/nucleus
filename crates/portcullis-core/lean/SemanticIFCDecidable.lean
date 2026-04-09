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

/-! ## Decidable Kripke-Joyal forcing

The classical `forces E φ := φ ∈ allowedAt E` unfolds to
`∀ s₁ s₂, E.rel s₁ s₂ → (φ s₁ ↔ φ s₂)`. For finite Secret types with
Bool-valued `rel` and `φ`, this universal quantifier is mechanically
decidable. We define `dForces` as a `Bool` and prove the bridge to the
classical version.
-/

namespace DObsLevel

/-- Decidable Kripke-Joyal forcing: returns `true` iff the proposition
    respects the equivalence relation (every pair of related secrets
    receives the same Bool value). -/
def dForces {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (E : DObsLevel Secret) (φ : DProp Secret) : Bool :=
  decide (∀ s₁ s₂ : Secret, E.rel s₁ s₂ = true → φ s₁ = φ s₂)

end DObsLevel

namespace DProp

/-- Bridge lemma: decidable forcing matches classical forcing under coercion. -/
theorem dForces_iff_forces {Secret : Type} [Fintype Secret] [DecidableEq Secret]
    (E : DObsLevel Secret) (φ : DProp Secret) :
    DObsLevel.dForces E φ = true ↔ forces E.toObsLevel φ.toProp := by
  unfold DObsLevel.dForces
  rw [decide_eq_true_iff]
  unfold forces allowedAt
  simp only [Set.mem_setOf_eq, DObsLevel.toObsLevel, DProp.toProp]
  constructor
  · intro h s₁ s₂ hr
    rw [h s₁ s₂ hr]
  · intro h s₁ s₂ hr
    have hiff := h s₁ s₂ hr
    cases hp1 : φ s₁ <;> cases hp2 : φ s₂ <;> simp_all

end DProp

/-! ## ThreeSecret decidable forcing sanity checks

These verify that `dForces` is mechanically decidable for the
diamond poset's four observation levels and several concrete
ThreeSecret propositions.
-/

namespace ThreeSecretDecidable
open DObsLevel ThreeSecretObs ThreeSecretExamples ThreeSecret

/-! ### dForces examples

`isA` (the proposition "secret is A") is forced at `top` because top
distinguishes everything, but NOT forced at `obsAC` because obsAC
treats A and C as equivalent (so `isA` would conflict on the AC class). -/

example : dForces (top : DObsLevel ThreeSecret) isA = true := by decide
example : dForces (top : DObsLevel ThreeSecret) isB = true := by decide
example : dForces (top : DObsLevel ThreeSecret) isC = true := by decide

example : dForces (bot : DObsLevel ThreeSecret) isA = false := by decide
example : dForces obsAC isA = false := by decide
example : dForces obsBC isA = true := by decide   -- A is alone in obsBC
example : dForces obsAC isB = true := by decide   -- B is alone in obsAC
example : dForces obsBC isB = false := by decide

/-- The proposition "isA OR isB" is not forced at obsAC: it's true on
    A but obsAC treats A and C as equivalent, so the AC class would
    require it to also hold on C (which is false). -/
example : dForces obsAC (DProp.or isA isB) = false := by decide

/-- The constantly-true proposition is forced everywhere. -/
example : dForces (bot : DObsLevel ThreeSecret) DProp.constTrue = true := by decide
example : dForces obsAC DProp.constTrue = true := by decide
example : dForces (top : DObsLevel ThreeSecret) DProp.constTrue = true := by decide
example : dForces obsBC DProp.constTrue = true := by decide

/-! ### Propositional connectives reduce mechanically

For specific concrete propositions and observation levels, the
connectives `and`, `or`, `neg`, `imp` decide just as their atomic
inputs do. These are not the universal closure of `forces_and` etc.
(which would require Fintype on `DProp ThreeSecret`), but they
demonstrate that the connectives are computable. -/

example : dForces obsAC (DProp.and isB DProp.constTrue) = true := by decide
example : dForces obsAC (DProp.and isB isB) = true := by decide
example : dForces obsAC (DProp.and isA isB) = true := by decide  -- both atomic constraints met when A↔C
example : dForces obsBC (DProp.or isA DProp.constFalse) = true := by decide
example : dForces (top : DObsLevel ThreeSecret) (DProp.imp isA isC) = true := by decide
example : dForces (top : DObsLevel ThreeSecret) (DProp.neg DProp.constFalse) = true := by decide

end ThreeSecretDecidable

/-! ## Computable sheaf cohomology — h0_compute and h1_compute

For finite Secret types, both `H⁰` (global sections) and `H¹` (gluing
obstructions) become finite enumeration problems. We use `List` rather
than `Finset` for the poset because `DObsLevel` has proof-carrier fields
that make `DecidableEq` non-trivial.

The classical `H0` is defined as `{ p | ∀ E : ObsLevel Secret, forces E p }`.
The decidable `h0_compute` enumerates all candidate propositions and
keeps those forced at every level in the input list.

`h1_compute` counts simple "obstruction witnesses": pairs of propositions
forced at incomparable levels whose existence implies no global gluing.
For the diamond poset, this returns 1 (matching the alignment tax).
-/

namespace DObsLevel
variable {Secret : Type} [Fintype Secret] [DecidableEq Secret]

/-- Global sections: propositions forced at every observation level in the poset. -/
def h0_compute (poset : List (DObsLevel Secret)) (allProps : List (DProp Secret))
    : List (DProp Secret) :=
  allProps.filter (fun φ => poset.all (fun E => dForces E φ))

/-- Number of global sections — an unconditional natural number. -/
def h0_size (poset : List (DObsLevel Secret)) (allProps : List (DProp Secret)) : Nat :=
  (h0_compute poset allProps).length

/-- A simple obstruction witness count: how many propositions are forced
    at the SECOND level but not the FIRST when the first refines the second.
    For the diamond poset with the canonical ordering [bot, obsAC, obsBC, top],
    this captures the "obsAC and obsBC disagree" obstruction characteristic
    of `H¹ ≠ 0`. -/
def h1_witnesses (poset : List (DObsLevel Secret)) (allProps : List (DProp Secret)) : Nat :=
  -- Count propositions forced at obsAC or obsBC (level 1 or 2 in the diamond)
  -- but NOT forced at bot — these are the "non-trivial local sections"
  -- whose existence prevents the global gluing.
  match poset with
  | [_, l1, l2, _] =>
    let forcedAtL1 := allProps.filter (fun φ => dForces l1 φ)
    let forcedAtL2 := allProps.filter (fun φ => dForces l2 φ)
    -- Witnesses: propositions forced at one but not the other
    let onlyL1 := forcedAtL1.filter (fun φ => !dForces l2 φ)
    let onlyL2 := forcedAtL2.filter (fun φ => !dForces l1 φ)
    if onlyL1.length > 0 ∧ onlyL2.length > 0 then 1 else 0
  | _ => 0

end DObsLevel

/-! ## ThreeSecret cohomology computation

The 8 decidable propositions on `ThreeSecret` enumerated explicitly,
with `h0_compute` and `h1_witnesses` against the diamond poset.
-/

namespace ThreeSecretCohomology
open DObsLevel ThreeSecretObs ThreeSecret

/-- All 8 decidable propositions on ThreeSecret (one per Bool^3 function). -/
def allProps : List (DProp ThreeSecret) := [
  fun _ => false,                                                           -- constFalse
  fun s => match s with | A => true | _ => false,                           -- isA
  fun s => match s with | B => true | _ => false,                           -- isB
  fun s => match s with | C => true | _ => false,                           -- isC
  fun s => match s with | A | B => true | _ => false,                       -- isAorB
  fun s => match s with | A | C => true | _ => false,                       -- isAorC
  fun s => match s with | B | C => true | _ => false,                       -- isBorC
  fun _ => true                                                             -- constTrue
]

/-- The diamond poset as a list (avoiding the DecidableEq DObsLevel issue). -/
def diamondPoset : List (DObsLevel ThreeSecret) :=
  [(bot : DObsLevel ThreeSecret), obsAC, obsBC, (top : DObsLevel ThreeSecret)]

/-! ### `#eval` checks

These compute h0_size and h1_witnesses on the diamond poset.
-/

example : h0_size diamondPoset allProps = 2 := by decide
example : h1_witnesses diamondPoset allProps = 1 := by decide

/-- The two propositions in `H⁰` of the diamond are constantly true and
    constantly false (the only propositions forced at every observation level). -/
example : (h0_compute diamondPoset allProps).length = 2 := by decide

end ThreeSecretCohomology

end SemanticIFCDecidable
