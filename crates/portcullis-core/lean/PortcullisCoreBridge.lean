import Types
import Mathlib.Order.Heyting.Basic

/-!
# HeytingAlgebra Instance for Aeneas-Generated CapabilityLevel

Proves that the Aeneas-generated `portcullis_core.CapabilityLevel` —
machine-translated from production Rust — is a `HeytingAlgebra`.

All proofs discharge via `decide` over the 3-element type.
No SMT oracle, no Z3 — kernel-checked by the Lean 4 type-checker.
-/

open portcullis_core

namespace PortcullisCoreBridge

-- ═══════════════════════════════════════════════════════════════════════
-- Natural number encoding (matching Rust #[repr(u8)] discriminants)
-- ═══════════════════════════════════════════════════════════════════════

def toNat : CapabilityLevel → Nat
  | .Never   => 0
  | .LowRisk => 1
  | .Always  => 2

theorem toNat_injective : Function.Injective toNat := by
  intro a b h
  cases a <;> cases b <;> first | rfl | (simp [toNat] at h)

-- ═══════════════════════════════════════════════════════════════════════
-- DecidableEq
-- ═══════════════════════════════════════════════════════════════════════

instance : DecidableEq CapabilityLevel :=
  fun a b => match a, b with
  | .Never, .Never => isTrue rfl
  | .Never, .LowRisk => isFalse (by intro h; cases h)
  | .Never, .Always => isFalse (by intro h; cases h)
  | .LowRisk, .Never => isFalse (by intro h; cases h)
  | .LowRisk, .LowRisk => isTrue rfl
  | .LowRisk, .Always => isFalse (by intro h; cases h)
  | .Always, .Never => isFalse (by intro h; cases h)
  | .Always, .LowRisk => isFalse (by intro h; cases h)
  | .Always, .Always => isTrue rfl

-- ═══════════════════════════════════════════════════════════════════════
-- LE, LT, Decidable instances
-- ═══════════════════════════════════════════════════════════════════════

instance instLE : LE CapabilityLevel where
  le a b := toNat a ≤ toNat b

instance instLT : LT CapabilityLevel where
  lt a b := toNat a < toNat b

instance instDecidableLE : DecidableRel (α := CapabilityLevel) (· ≤ ·) :=
  fun a b => inferInstanceAs (Decidable (toNat a ≤ toNat b))

instance instDecidableLT : DecidableRel (α := CapabilityLevel) (· < ·) :=
  fun a b => inferInstanceAs (Decidable (toNat a < toNat b))

-- ═══════════════════════════════════════════════════════════════════════
-- Preorder → PartialOrder → LinearOrder
-- ═══════════════════════════════════════════════════════════════════════

instance instPreorder : Preorder CapabilityLevel where
  le_refl a := Nat.le_refl _
  le_trans _ _ _ h1 h2 := Nat.le_trans h1 h2
  lt_iff_le_not_ge a b := Nat.lt_iff_le_not_le

instance instPartialOrder : PartialOrder CapabilityLevel where
  le_antisymm a b h1 h2 := toNat_injective (Nat.le_antisymm h1 h2)

instance instLinearOrder : LinearOrder CapabilityLevel where
  le_total a b := Nat.le_total _ _
  toDecidableLE := instDecidableLE

-- ═══════════════════════════════════════════════════════════════════════
-- Bounded lattice (⊥ = Never, ⊤ = Always)
-- ═══════════════════════════════════════════════════════════════════════

theorem le_always (a : CapabilityLevel) : a ≤ .Always := by cases a <;> decide
theorem never_le (a : CapabilityLevel) : .Never ≤ a := by cases a <;> decide

instance instBot : Bot CapabilityLevel := ⟨.Never⟩
instance instTop : Top CapabilityLevel := ⟨.Always⟩

instance instBoundedOrder : BoundedOrder CapabilityLevel where
  bot_le := never_le
  le_top := le_always

-- ═══════════════════════════════════════════════════════════════════════
-- Heyting implication and complement
-- ═══════════════════════════════════════════════════════════════════════

instance instHImp : HImp CapabilityLevel where
  himp a b := if a ≤ b then .Always else b

instance instCompl : Compl CapabilityLevel where
  compl a := if a ≤ (⊥ : CapabilityLevel) then .Always else .Never

-- ═══════════════════════════════════════════════════════════════════════
-- HeytingAlgebra axioms
-- ═══════════════════════════════════════════════════════════════════════

theorem le_himp_iff (a b c : CapabilityLevel) :
    a ≤ b ⇨ c ↔ a ⊓ b ≤ c := by
  cases a <;> cases b <;> cases c <;> decide

theorem himp_bot (a : CapabilityLevel) :
    a ⇨ (⊥ : CapabilityLevel) = aᶜ := by
  cases a <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- The HeytingAlgebra instance
-- ═══════════════════════════════════════════════════════════════════════

instance instGeneralizedHeytingAlgebra : GeneralizedHeytingAlgebra CapabilityLevel where
  le_top  := le_always
  le_himp_iff a b c := le_himp_iff a b c

instance instHeytingAlgebra : HeytingAlgebra CapabilityLevel where
  bot_le  := never_le
  himp_bot := himp_bot

end PortcullisCoreBridge
