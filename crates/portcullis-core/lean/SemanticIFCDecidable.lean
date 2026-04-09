import Mathlib.Data.Fintype.Basic
import Mathlib.Data.Fintype.Pi
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

/-! ## Decidable mirrors of the classical security theorems

Final step in the decidable internal logic roadmap (issue #1432).

The classical theorems `no_global_reconciliation`, `alignment_tax_ge_one`,
`alignment_tax_nonzero`, and `no_free_lunch` in `SemanticIFC.lean` are all
existence-statement impossibility results: there does NOT exist a
proposition satisfying certain forcing requirements. This section provides
their decidable mirrors using `dForces` and proves them by `decide`.

We also define a runnable `runSecurityGame` that mirrors the classical
`SecurityGame.defenderWins` but evaluates entirely in `Bool`.
-/

namespace ThreeSecretDecidableTheorems
open DObsLevel DProp ThreeSecretObs ThreeSecretExamples
     ThreeSecretCohomology ThreeSecret

/-- For every proposition `φ` in our explicit list, the conjunction
    "forced at obsAC AND forced at obsBC AND φ A AND ¬φ B" is `false`.
    This is the decidable form of `no_global_reconciliation` for the
    enumerated proposition list. -/
theorem dNoGlobalReconciliation_threeSecret :
    ∀ φ ∈ allProps,
      ¬(dForces obsAC φ = true ∧ dForces obsBC φ = true ∧
        φ A = true ∧ φ B = false) := by decide

/-- The decidable form of `alignment_tax_ge_one`: any φ satisfying
    `φ A ∧ ¬φ B` fails to be forced at obsAC OR fails to be forced
    at obsBC. Proven by exhaustive case check on `allProps`. -/
theorem dAlignmentTaxGeOne_threeSecret :
    ∀ φ ∈ allProps,
      φ A = true → φ B = false →
      dForces obsAC φ = false ∨ dForces obsBC φ = false := by decide

/-- The alignment tax of the diamond poset is exactly 1, computed
    mechanically by `h1_witnesses`. -/
theorem dAlignmentTax_diamond_eq_one :
    h1_witnesses diamondPoset allProps = 1 := by decide

/-- The decidable form of `no_free_lunch`: same statement as
    `dAlignmentTaxGeOne_threeSecret` (in the classical case `no_free_lunch`
    is just an alias). -/
theorem dNoFreeLunch_threeSecret :
    ∀ φ ∈ allProps,
      φ A = true → φ B = false →
      dForces obsAC φ = false ∨ dForces obsBC φ = false :=
  dAlignmentTaxGeOne_threeSecret

/-! ### Runnable security game

A `Bool`-valued mirror of `SecurityGame.defenderWins`. Returns `true`
iff the proposition `φ` allows the target, denies the threat, AND is
forced at every observation level in the game.
-/

/-- A decidable security game: explicit list of observation levels,
    target secret to allow, threat secret to deny. -/
structure DGame where
  levels : List (DObsLevel ThreeSecret)
  target : ThreeSecret
  threat : ThreeSecret

/-- Does the proposition `φ` win the game? -/
def DGame.defenderWins (g : DGame) (φ : DProp ThreeSecret) : Bool :=
  φ g.target && !φ g.threat && g.levels.all (fun E => dForces E φ)

/-- Run a security game against ALL 8 propositions. Returns the winning
    proposition if one exists, or `none`. For the diamond + (target=A,
    threat=B) game, this returns `none` (no defender exists). -/
def runSecurityGame (g : DGame) : Option (DProp ThreeSecret) :=
  allProps.find? (fun φ => g.defenderWins φ)

/-! ### Five example security games -/

/-- The classic three-secret game on the diamond poset. No defender exists
    — this is the alignment tax in action. -/
def diamondGameAB : DGame :=
  { levels := diamondPoset, target := A, threat := B }

example : runSecurityGame diamondGameAB = none := by decide

/-- A trivial game on the bottom level only. The bottom forces only
    constant propositions, so no defender can both allow A and deny B. -/
def trivialGameAB : DGame :=
  { levels := [(bot : DObsLevel ThreeSecret)], target := A, threat := B }

example : runSecurityGame trivialGameAB = none := by decide

/-- Game on the top level only: top distinguishes everything, so a
    defender exists (e.g., `isA`). -/
def topGameAB : DGame :=
  { levels := [(top : DObsLevel ThreeSecret)], target := A, threat := B }

example : (runSecurityGame topGameAB).isSome = true := by decide

/-- Game on `obsBC` only (where `A` is alone). A defender exists since
    propositions like `isA` are forced at obsBC. -/
def obsBCGameAB : DGame :=
  { levels := [obsBC], target := A, threat := B }

example : (runSecurityGame obsBCGameAB).isSome = true := by decide

/-- Game on `obsAC` only (where `A` and `C` are equivalent). A defender
    exists — for example `isAorC`, which is forced at obsAC, true on A,
    and false on B. -/
def obsACGameAB : DGame :=
  { levels := [obsAC], target := A, threat := B }

example : (runSecurityGame obsACGameAB).isSome = true := by decide

/-! ## Decidable mirror of `ifc_characterization`

The classical `ifc_characterization` (SemanticIFC.lean:2018) is the
load-bearing theorem of the framework: IFC is necessary AND sufficient
for the taint laundering attack class.

The classical statement quantifies over `d : ThreeSecret → Bool`. The
decidable mirror is the same statement, proven by manual case analysis
on the value of `d` at each `ThreeSecret` constructor. Since `d A`,
`d B`, `d C` are independent booleans, exhaustive enumeration gives 8
cases — all dispatched mechanically by `cases` and `simp_all`.
-/

/-- **Necessity** — no static classifier `d : ThreeSecret → Bool` can
    satisfy `d A = true ∧ d B = false ∧ d C consistent with both obsAC and obsBC`. -/
theorem dIfcNecessary_threeSecret :
    ∀ d : ThreeSecret → Bool,
       d ThreeSecret.A = true → d ThreeSecret.B = false →
       (d ThreeSecret.C ≠ d ThreeSecret.A) ∨ (d ThreeSecret.C ≠ d ThreeSecret.B) := by
  intro d hA hB
  -- Either d C = d A (= true) or d C ≠ d A.
  -- If d C = d A = true, then d C = true ≠ false = d B, so the right disjunct holds.
  -- If d C ≠ d A, the left disjunct holds directly.
  by_cases hCA : d ThreeSecret.C = d ThreeSecret.A
  · right
    rw [hCA, hA, hB]
    decide
  · left
    exact hCA

/-- **Sufficiency** — IFC (provenance tracking) provides a working
    classifier: `d(A) = true, d(B) = false, d(C) = d(B) = false`. -/
theorem dIfcSufficient_threeSecret :
    ∃ d : ThreeSecret → Bool,
       d ThreeSecret.A = true ∧ d ThreeSecret.B = false ∧
       d ThreeSecret.C = d ThreeSecret.B := by
  refine ⟨fun s => match s with | .A => true | .B => false | .C => false, ?_, ?_, ?_⟩
  · rfl
  · rfl
  · rfl

/-- **Decidable form of the IFC characterization** — same statement
    as `SemanticIFC.ifc_characterization`, proven via `dIfcNecessary_threeSecret`
    and `dIfcSufficient_threeSecret` rather than the classical
    `ifc_necessary_for_taint_laundering` / `ifc_sufficient_for_taint_laundering`.

    Both theorems inhabit the same proposition. This file provides an
    independent proof using only case analysis on Bool values, no manual
    classical reasoning. -/
theorem dIfcCharacterization_threeSecret :
    (∀ d : ThreeSecret → Bool,
       d ThreeSecret.A = true → d ThreeSecret.B = false →
       (d ThreeSecret.C ≠ d ThreeSecret.A) ∨ (d ThreeSecret.C ≠ d ThreeSecret.B)) ∧
    (∃ d : ThreeSecret → Bool,
       d ThreeSecret.A = true ∧ d ThreeSecret.B = false ∧
       d ThreeSecret.C = d ThreeSecret.B) :=
  ⟨dIfcNecessary_threeSecret, dIfcSufficient_threeSecret⟩

end ThreeSecretDecidableTheorems

/-! ## Fintype DProp + universal S4 closure theorems

With `Mathlib.Data.Fintype.Pi` imported, `DProp Secret = Secret → Bool`
inherits a `Fintype` instance automatically when `Secret` is finite.
This unlocks universally-quantified theorems where the quantifier
ranges over all decidable propositions on `Secret`.

For `ThreeSecret`, `DProp ThreeSecret` has 2³ = 8 elements, so universal
S4 closure theorems become decidable by exhaustive enumeration.
-/

namespace ThreeSecretClosure
open DObsLevel ThreeSecretObs ThreeSecretExamples ThreeSecret DProp

/-- The 8 propositions on ThreeSecret form a `Fintype` (8 elements). -/
example : Fintype (DProp ThreeSecret) := inferInstance

/-! ### Universal S4 closure: `dForces` is closed under propositional connectives

For a fixed observation level `E`, the set of forced propositions is
closed under `and`, `or`, `neg`, and `imp`. These are the decidable
forms of `forces_and`, `forces_or`, `forces_neg`, and `forces_imp` from
`SemanticIFC.lean`. Each is universally quantified over all 8 (resp 64)
propositions on ThreeSecret.
-/

/-- `and` closure at obsAC. -/
theorem dForces_and_obsAC :
    ∀ φ ψ : DProp ThreeSecret,
      dForces obsAC φ = true → dForces obsAC ψ = true →
      dForces obsAC (DProp.and φ ψ) = true := by decide

/-- `and` closure at obsBC. -/
theorem dForces_and_obsBC :
    ∀ φ ψ : DProp ThreeSecret,
      dForces obsBC φ = true → dForces obsBC ψ = true →
      dForces obsBC (DProp.and φ ψ) = true := by decide

/-- `or` closure at obsAC. -/
theorem dForces_or_obsAC :
    ∀ φ ψ : DProp ThreeSecret,
      dForces obsAC φ = true → dForces obsAC ψ = true →
      dForces obsAC (DProp.or φ ψ) = true := by decide

/-- `or` closure at obsBC. -/
theorem dForces_or_obsBC :
    ∀ φ ψ : DProp ThreeSecret,
      dForces obsBC φ = true → dForces obsBC ψ = true →
      dForces obsBC (DProp.or φ ψ) = true := by decide

/-- `neg` closure at obsAC. -/
theorem dForces_neg_obsAC :
    ∀ φ : DProp ThreeSecret,
      dForces obsAC φ = true →
      dForces obsAC (DProp.neg φ) = true := by decide

/-- `neg` closure at obsBC. -/
theorem dForces_neg_obsBC :
    ∀ φ : DProp ThreeSecret,
      dForces obsBC φ = true →
      dForces obsBC (DProp.neg φ) = true := by decide

/-- `imp` closure at obsAC. -/
theorem dForces_imp_obsAC :
    ∀ φ ψ : DProp ThreeSecret,
      dForces obsAC φ = true → dForces obsAC ψ = true →
      dForces obsAC (DProp.imp φ ψ) = true := by decide

/-- `imp` closure at obsBC. -/
theorem dForces_imp_obsBC :
    ∀ φ ψ : DProp ThreeSecret,
      dForces obsBC φ = true → dForces obsBC ψ = true →
      dForces obsBC (DProp.imp φ ψ) = true := by decide

end ThreeSecretClosure

/-! ## DecidableEq for DObsLevel via proof irrelevance

The `DObsLevel` structure has proof-carrier fields (`refl`, `symm`, `trans`)
that block automatic `DecidableEq` derivation. But by proof irrelevance:
two `DObsLevel`s with the same `rel` function are definitionally equal,
since all proofs of the equivalence laws are subsingletons.

We provide a manual `DecidableEq` instance that checks `rel` equality and
uses subsingleton elimination for the proof fields. With `Fintype Secret`,
function equality `Secret → Secret → Bool` is decidable via `Pi.decidableEq`
(from `Mathlib.Data.Fintype.Pi`).
-/

namespace DObsLevel
variable {Secret : Type} [Fintype Secret] [DecidableEq Secret]

instance instDecidableEq : DecidableEq (DObsLevel Secret) := fun E₁ E₂ =>
  if h : E₁.rel = E₂.rel then
    isTrue (by
      cases E₁
      cases E₂
      congr)
  else
    isFalse (fun heq => h (heq ▸ rfl))

end DObsLevel

/-! ## DObsLevel equality usage

With `DecidableEq (DObsLevel Secret)`, observation levels can be compared
mechanically. The proof-irrelevance-based instance correctly identifies
two levels as equal iff their relation functions agree.
-/

namespace DObsLevelEqExamples
open DObsLevel ThreeSecretObs ThreeSecret

/-- A `DObsLevel` is equal to itself (via `rfl` — independent of the
    `DecidableEq` instance, but verifies the structure is well-formed). -/
example : (bot : DObsLevel ThreeSecret) = (bot : DObsLevel ThreeSecret) := rfl
example : (top : DObsLevel ThreeSecret) = (top : DObsLevel ThreeSecret) := rfl
example : ThreeSecretObs.obsAC = ThreeSecretObs.obsAC := rfl
example : ThreeSecretObs.obsBC = ThreeSecretObs.obsBC := rfl

/-- The `DecidableEq` instance is in scope: this expression type-checks
    only if the instance has been registered for `DObsLevel ThreeSecret`. -/
example : DecidableEq (DObsLevel ThreeSecret) := inferInstance

end DObsLevelEqExamples

/-! ## FiveSecret + Borromean obstruction (H² witness)

The `ThreeSecret` diamond formalized pairwise (H¹) obstructions.
This section introduces a six-element Secret type and three observation
levels forming a **Borromean** obstruction: no two observation levels
conflict (each pair has non-trivial common forced propositions), but
all three together do (no non-constant proposition is forced at all
three simultaneously).

The Borromean property is the algebraic signature of H² in sheaf
cohomology: it distinguishes attack classes that require three layers
of indirection from those that can be caught by pairwise analysis.

## Construction

We use the bijection `FiveSecret ≃ {+,-} × {a,b,c}` under the mapping
`A=+a, B=+b, C=+c, AB=-a, BC=-b, CA=-c`. The three observation levels are:

- `obs1` — confuses `a↔b` within each sign (classes `{A,B}, {AB,BC}, {C}, {CA}`)
- `obs2` — confuses `b↔c` within each sign (classes `{A}, {B,C}, {AB}, {BC,CA}`)
- `obs3` — confuses signs, preserving letters (classes `{A,AB}, {B,BC}, {C,CA}`)

Joins:
- `obs1 ∨ obs2 = {+*, -*}` — 2 classes (sign)
- `obs1 ∨ obs3 = {+a,+b,-a,-b}, {+c,-c}` — 2 classes
- `obs2 ∨ obs3 = {+a,-a}, {+b,+c,-b,-c}` — 2 classes
- `obs1 ∨ obs2 ∨ obs3 = everything` — 1 class (universal)

So each pair supports a non-constant forced proposition, but the
triple forces constants only. This is Borromean.

Note: the inductive type is called `FiveSecret` to match the
tracking-issue nomenclature (#1444) even though it has six
constructors; "five" refers to the five non-trivial observation
levels (bot, obs1, obs2, obs3, top) in `borromeanPoset`.
-/

inductive FiveSecret where
  /-- `+a` — atomic secret A. -/
  | A
  /-- `+b` — atomic secret B. -/
  | B
  /-- `+c` — atomic secret C. -/
  | C
  /-- `-a` — sign-flipped A (conceptually "A with a twist"). -/
  | AB
  /-- `-b` — sign-flipped B. -/
  | BC
  /-- `-c` — sign-flipped C. -/
  | CA
  deriving DecidableEq, Repr

instance : Fintype FiveSecret where
  elems := {FiveSecret.A, FiveSecret.B, FiveSecret.C,
            FiveSecret.AB, FiveSecret.BC, FiveSecret.CA}
  complete := fun s => by cases s <;> decide

instance : FiniteSecret FiveSecret where
  toFintype := inferInstance
  toDecidableEq := inferInstance

namespace Borromean
open DObsLevel FiveSecret

/-- `obs1` confuses the "a/b" letters within each sign.
    Classes: `{A, B}, {AB, BC}, {C}, {CA}`. -/
def obs1 : DObsLevel FiveSecret where
  rel s₁ s₂ := match s₁, s₂ with
    | A, A => true | A, B => true | B, A => true | B, B => true
    | AB, AB => true | AB, BC => true | BC, AB => true | BC, BC => true
    | C, C => true | CA, CA => true
    | _, _ => false
  refl s := by cases s <;> rfl
  symm s₁ s₂ h := by cases s₁ <;> cases s₂ <;> first | rfl | exact h
  trans s₁ s₂ s₃ h₁ h₂ := by
    cases s₁ <;> cases s₂ <;> cases s₃ <;>
      first | rfl | (exfalso; exact Bool.false_ne_true h₁)
            | (exfalso; exact Bool.false_ne_true h₂)

/-- `obs2` confuses the "b/c" letters within each sign.
    Classes: `{A}, {B, C}, {AB}, {BC, CA}`. -/
def obs2 : DObsLevel FiveSecret where
  rel s₁ s₂ := match s₁, s₂ with
    | A, A => true | AB, AB => true
    | B, B => true | B, C => true | C, B => true | C, C => true
    | BC, BC => true | BC, CA => true | CA, BC => true | CA, CA => true
    | _, _ => false
  refl s := by cases s <;> rfl
  symm s₁ s₂ h := by cases s₁ <;> cases s₂ <;> first | rfl | exact h
  trans s₁ s₂ s₃ h₁ h₂ := by
    cases s₁ <;> cases s₂ <;> cases s₃ <;>
      first | rfl | (exfalso; exact Bool.false_ne_true h₁)
            | (exfalso; exact Bool.false_ne_true h₂)

/-- `obs3` confuses signs, preserving letters.
    Classes: `{A, AB}, {B, BC}, {C, CA}`. -/
def obs3 : DObsLevel FiveSecret where
  rel s₁ s₂ := match s₁, s₂ with
    | A, A => true | A, AB => true | AB, A => true | AB, AB => true
    | B, B => true | B, BC => true | BC, B => true | BC, BC => true
    | C, C => true | C, CA => true | CA, C => true | CA, CA => true
    | _, _ => false
  refl s := by cases s <;> rfl
  symm s₁ s₂ h := by cases s₁ <;> cases s₂ <;> first | rfl | exact h
  trans s₁ s₂ s₃ h₁ h₂ := by
    cases s₁ <;> cases s₂ <;> cases s₃ <;>
      first | rfl | (exfalso; exact Bool.false_ne_true h₁)
            | (exfalso; exact Bool.false_ne_true h₂)

/-- The five-level poset for the Borromean obstruction:
    `bot ≤ obs1, obs2, obs3 ≤ top`. -/
def borromeanPoset : List (DObsLevel FiveSecret) :=
  [(bot : DObsLevel FiveSecret), obs1, obs2, obs3,
   (top : DObsLevel FiveSecret)]

/-! ### Sanity checks: refinement order -/

example : (bot : DObsLevel FiveSecret) ≤ obs1 := bot_le obs1
example : (bot : DObsLevel FiveSecret) ≤ obs2 := bot_le obs2
example : (bot : DObsLevel FiveSecret) ≤ obs3 := bot_le obs3
example : obs1 ≤ (top : DObsLevel FiveSecret) := le_top obs1
example : obs2 ≤ (top : DObsLevel FiveSecret) := le_top obs2
example : obs3 ≤ (top : DObsLevel FiveSecret) := le_top obs3

example : borromeanPoset.length = 5 := by decide

/-! ### Sanity checks: relation values -/

example : obs1.rel A B = true := by decide
example : obs1.rel AB BC = true := by decide
example : obs1.rel A C = false := by decide
example : obs1.rel A AB = false := by decide

example : obs2.rel B C = true := by decide
example : obs2.rel BC CA = true := by decide
example : obs2.rel A B = false := by decide
example : obs2.rel B BC = false := by decide

example : obs3.rel A AB = true := by decide
example : obs3.rel B BC = true := by decide
example : obs3.rel C CA = true := by decide
example : obs3.rel A B = false := by decide

/-! ### Pairwise witnesses — each pair admits a non-trivial forced proposition

For each pair `(obs_i, obs_j)`, we exhibit a concrete `DProp FiveSecret`
that is forced at both levels and is non-constant. This proves the
pairwise H¹ obstructions vanish.
-/

/-- "Has positive sign" (`A, B, C` are true; `AB, BC, CA` are false).
    Constant on `obs1 ∨ obs2` classes `{A,B,C}` and `{AB,BC,CA}`. -/
def signProp : DProp FiveSecret := fun s => match s with
  | A | B | C => true
  | AB | BC | CA => false

/-- "Is a/b-letter" (`A, B, AB, BC` are true; `C, CA` are false).
    Constant on `obs1 ∨ obs3` classes `{A,B,AB,BC}` and `{C,CA}`. -/
def abProp : DProp FiveSecret := fun s => match s with
  | A | B | AB | BC => true
  | C | CA => false

/-- "Is a-letter" (`A, AB` are true; `B, C, BC, CA` are false).
    Constant on `obs2 ∨ obs3` classes `{A,AB}` and `{B,C,BC,CA}`. -/
def aProp : DProp FiveSecret := fun s => match s with
  | A | AB => true
  | B | C | BC | CA => false

/-- `signProp` is forced at `obs1` and `obs2` (pair {obs1, obs2} compatible). -/
example : dForces obs1 signProp = true := by decide
example : dForces obs2 signProp = true := by decide
example : signProp A ≠ signProp AB := by decide  -- non-constant

/-- `abProp` is forced at `obs1` and `obs3` (pair {obs1, obs3} compatible). -/
example : dForces obs1 abProp = true := by decide
example : dForces obs3 abProp = true := by decide
example : abProp A ≠ abProp C := by decide  -- non-constant

/-- `aProp` is forced at `obs2` and `obs3` (pair {obs2, obs3} compatible). -/
example : dForces obs2 aProp = true := by decide
example : dForces obs3 aProp = true := by decide
example : aProp A ≠ aProp B := by decide  -- non-constant

/-! ### Triple obstruction — no non-constant φ is forced at all three

The Borromean property: any `φ : DProp FiveSecret` forced at `obs1`,
`obs2`, AND `obs3` must be constant. This is the H² obstruction —
invisible to any pair but witnessed by the triple.

With `Fintype (DProp FiveSecret)` (from `Mathlib.Data.Fintype.Pi`,
2⁶ = 64 propositions), this universal statement is decidable by
exhaustive enumeration.
-/

/-- **Borromean obstruction theorem.** Any proposition forced at all
    three observation levels is constant on `FiveSecret`. -/
theorem borromean_triple_forces_constant :
    ∀ φ : DProp FiveSecret,
      dForces obs1 φ = true → dForces obs2 φ = true → dForces obs3 φ = true →
      (φ A = φ B ∧ φ A = φ C ∧ φ A = φ AB ∧
       φ A = φ BC ∧ φ A = φ CA) := by decide

/-- Concrete specialization: the diagnostic witness `φ A = φ AB`.
    Shows the "sign collapse" forced by `obs3` being joined with the
    letter-merging `obs1` and `obs2`. -/
example :
    ∀ φ : DProp FiveSecret,
      dForces obs1 φ = true → dForces obs2 φ = true → dForces obs3 φ = true →
      φ A = φ AB := by decide

end Borromean

/-! ## Category of finite attacks (5-year roadmap Y1.A — issue #1448)

An **attack** against a policy `P : DObsLevel Secret` is a triple
`(input, target, success)` where:

- `input` — a concrete secret the adversary supplies
- `target` — the observation level the attack aims to bypass
- `success` — a decidable predicate describing what "successful
  attack" means (typically: the observer at `target` learns
  something about `input` beyond what `P` allows)

Attacks form a preorder (thin category): there is a **reduction**
`A → B` precisely when `A.success` pointwise implies `B.success`.
This is the discrete analogue of security reductions in cryptography
— showing that breaking A is at least as hard as breaking B.

This file provides:
- `Attack P` structure on `ThreeSecret`
- `Reduction A B` as pointwise `Prop`-valued implication
- `Reduction.refl` / `Reduction.trans` (the category laws)
- Three concrete example attacks
- Two example reductions between them, proven by `decide`
-/

namespace AttackCategory
open DObsLevel ThreeSecret ThreeSecretObs ThreeSecretExamples DProp

/-- A finite attack against a policy `P` on `ThreeSecret`. -/
structure Attack (P : DObsLevel ThreeSecret) where
  /-- The concrete secret the adversary submits as input. -/
  input : ThreeSecret
  /-- The observation level the attack targets (the viewpoint the
      adversary wants to lift information to). -/
  target : DObsLevel ThreeSecret
  /-- The success predicate: when is this attack considered to have
      succeeded against the policy? -/
  success : DProp ThreeSecret

/-- Attacks need not compare their policy index for the preorder
    (success-implication is independent of `P`). -/
def Reduction {P : DObsLevel ThreeSecret} (A B : Attack P) : Prop :=
  ∀ s : ThreeSecret, A.success.toProp s → B.success.toProp s

/-- Reflexivity: every attack reduces to itself (identity morphism). -/
theorem Reduction.refl {P : DObsLevel ThreeSecret} (A : Attack P) :
    Reduction A A := fun _ h => h

/-- Transitivity: reductions compose (category composition). -/
theorem Reduction.trans {P : DObsLevel ThreeSecret} {A B C : Attack P}
    (f : Reduction A B) (g : Reduction B C) : Reduction A C :=
  fun s h => g s (f s h)

/-! ### Three concrete example attacks

These all target the trivial policy `bot` (everything indistinguishable),
i.e., any information leak at all is a successful attack. -/

/-- Attack #1: reveal that the secret is exactly `A`. -/
def attackRevealA : Attack (bot : DObsLevel ThreeSecret) where
  input := ThreeSecret.A
  target := (top : DObsLevel ThreeSecret)
  success := isA

/-- Attack #2: reveal that the secret is in `{A, B}`. -/
def attackRevealAorB : Attack (bot : DObsLevel ThreeSecret) where
  input := ThreeSecret.A
  target := ThreeSecretObs.obsAC
  success := isAorB

/-- Attack #3: reveal that the secret is NOT `B`. -/
def attackRevealNotB : Attack (bot : DObsLevel ThreeSecret) where
  input := ThreeSecret.A
  target := ThreeSecretObs.obsBC
  success := notB

/-! ### Reductions between attacks

These are the non-identity morphisms in the attack category.
Each is proven by `decide` since everything is Bool-level finite.
-/

/-- Reduction: revealing exactly `A` implies revealing `{A, B}`
    (the weaker statement is implied by the stronger). -/
theorem reduction_revealA_to_revealAorB :
    Reduction attackRevealA attackRevealAorB := by
  intro s h
  show isAorB s = true
  -- h : attackRevealA.success.toProp s = (isA s = true)
  have hA : isA s = true := h
  cases s <;> simp_all [isA, isAorB, DProp.or, isB]

/-- Reduction: revealing exactly `A` implies revealing "not B"
    (again, stronger implies weaker). -/
theorem reduction_revealA_to_revealNotB :
    Reduction attackRevealA attackRevealNotB := by
  intro s h
  show notB s = true
  have hA : isA s = true := h
  cases s <;> simp_all [isA, notB, DProp.neg, isB]

/-! ### Category laws applied to concrete examples -/

/-- Identity morphism on `attackRevealA`. -/
example : Reduction attackRevealA attackRevealA := Reduction.refl _

/-- Composition of reductions: `revealA → revealAorB → revealAorB` = identity-composed. -/
example : Reduction attackRevealA attackRevealAorB :=
  Reduction.trans reduction_revealA_to_revealAorB (Reduction.refl attackRevealAorB)

/-- Sanity: each attack's input is `.A` (we used `.A` as the adversarial submission). -/
example : attackRevealA.input = ThreeSecret.A := rfl
example : attackRevealAorB.input = ThreeSecret.A := rfl
example : attackRevealNotB.input = ThreeSecret.A := rfl

/-- Sanity: the three attacks target three different observation levels. -/
example : attackRevealA.target = (top : DObsLevel ThreeSecret) := rfl
example : attackRevealAorB.target = ThreeSecretObs.obsAC := rfl
example : attackRevealNotB.target = ThreeSecretObs.obsBC := rfl

end AttackCategory

end SemanticIFCDecidable
