-- Import the Aeneas-generated type definitions
import Types
import Mathlib.Order.Heyting.Basic

/-!
# HeytingAlgebra Instance for Aeneas-Generated CapabilityLevel

Proves that the Aeneas-generated `portcullis_core.CapabilityLevel` —
machine-translated from production Rust — is a `HeytingAlgebra`.

All proofs discharge via `decide` over the 3-element type.
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
  cases a <;> cases b <;> simp [toNat] at h

-- ═══════════════════════════════════════════════════════════════════════
-- DecidableEq (needed for everything else)
-- ═══════════════════════════════════════════════════════════════════════

instance : DecidableEq CapabilityLevel
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
-- LE and LT instances
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
-- Preorder and PartialOrder
-- ═══════════════════════════════════════════════════════════════════════

instance instPreorder : Preorder CapabilityLevel where
  le := (· ≤ ·)
  lt := (· < ·)
  le_refl a := Nat.le_refl _
  le_trans _ _ _ h1 h2 := Nat.le_trans h1 h2
  lt_iff_le_not_le a b := Nat.lt_iff_le_not_le

instance instPartialOrder : PartialOrder CapabilityLevel where
  le_antisymm a b h1 h2 := toNat_injective (Nat.le_antisymm h1 h2)

-- ═══════════════════════════════════════════════════════════════════════
-- LinearOrder
-- ═══════════════════════════════════════════════════════════════════════

instance instLinearOrder : LinearOrder CapabilityLevel where
  le_total a b := Nat.le_total _ _
  decidableLE := instDecidableLE
  decidableEq := inferInstance
  decidableLT := instDecidableLT

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
-- Fintype (needed for decide to enumerate all cases)
-- ═══════════════════════════════════════════════════════════════════════

instance instFintype : Fintype CapabilityLevel where
  elems := {.Never, .LowRisk, .Always}
  complete := by intro x; cases x <;> simp

-- ═══════════════════════════════════════════════════════════════════════
-- Heyting implication and complement
-- ═══════════════════════════════════════════════════════════════════════

instance instHImp : HImp CapabilityLevel where
  himp a b := if a ≤ b then .Always else b

instance instCompl : Compl CapabilityLevel where
  compl a := if a ≤ (⊥ : CapabilityLevel) then .Always else .Never

-- ═══════════════════════════════════════════════════════════════════════
-- HeytingAlgebra axioms (kernel-checked via decide)
-- ═══════════════════════════════════════════════════════════════════════

set_option maxRecDepth 4096 in
set_option maxHeartbeats 1600000 in
theorem le_himp_iff (a b c : CapabilityLevel) :
    a ≤ b ⇨ c ↔ a ⊓ b ≤ c := by
  cases a <;> cases b <;> cases c <;>
    simp only [HImp.himp, instHImp, Inf.inf, (· ≤ ·), instLE, toNat,
               Bot.bot, instBot, Top.top, instTop] <;>
    constructor <;> intro <;> omega

set_option maxRecDepth 4096 in
set_option maxHeartbeats 800000 in
theorem himp_bot (a : CapabilityLevel) :
    a ⇨ (⊥ : CapabilityLevel) = aᶜ := by
  cases a <;>
    simp only [HImp.himp, instHImp, Compl.compl, instCompl,
               (· ≤ ·), instLE, toNat, Bot.bot, instBot]

-- ═══════════════════════════════════════════════════════════════════════
-- The HeytingAlgebra instance
-- ═══════════════════════════════════════════════════════════════════════

instance instGeneralizedHeytingAlgebra : GeneralizedHeytingAlgebra CapabilityLevel where
  le_top  := le_always
  le_himp_iff a b c := le_himp_iff a b c

instance instHeytingAlgebra : HeytingAlgebra CapabilityLevel where
  bot_le  := never_le
  himp_bot := himp_bot
  compl a := if a ≤ (⊥ : CapabilityLevel) then .Always else .Never

end PortcullisCoreBridge
