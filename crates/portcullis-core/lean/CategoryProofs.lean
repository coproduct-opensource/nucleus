import PortcullisCore.Types
import PortcullisCore.CoreFuns
import Mathlib.Order.Heyting.Basic

/-!
# Categorical Composition Laws for Aeneas-Generated CapabilityLevel

Proves the semilattice and lattice laws that correspond to the Rust
`category.rs` module's `MeetSemilattice` and `JoinSemilattice` traits.

This is the first known use of Aeneas to prove Mathlib algebraic
structure laws on production Rust types. The proofs discharge via
`decide` over the 3-element type — kernel-checked, no sorry.

## What This Proves

- **Meet semilattice laws**: idempotent, commutative, associative for inf
- **Join semilattice laws**: idempotent, commutative, associative for sup
- **Absorption laws**: meet/join absorb each other (full lattice)
- **Monotonicity**: meet is deflationary (a ⊓ b ≤ a)

These correspond 1:1 to the exhaustive property tests in
`portcullis-core/src/category.rs`.
-/

open portcullis_core
open PortcullisCoreBridge

namespace CategoryProofs

-- We reuse the HeytingAlgebra instance from PortcullisCoreBridge,
-- which gives us Lattice (and thus SemilatticeInf + SemilatticeSup).

-- ═══════════════════════════════════════════════════════════════════════
-- Meet semilattice laws (SemilatticeInf on CapabilityLevel)
-- ═══════════════════════════════════════════════════════════════════════

/-- Meet is idempotent: a ⊓ a = a -/
theorem meet_idempotent (a : CapabilityLevel) : a ⊓ a = a := by
  cases a <;> decide

/-- Meet is commutative: a ⊓ b = b ⊓ a -/
theorem meet_commutative (a b : CapabilityLevel) : a ⊓ b = b ⊓ a := by
  cases a <;> cases b <;> decide

/-- Meet is associative: (a ⊓ b) ⊓ c = a ⊓ (b ⊓ c) -/
theorem meet_associative (a b c : CapabilityLevel) : (a ⊓ b) ⊓ c = a ⊓ (b ⊓ c) := by
  cases a <;> cases b <;> cases c <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Join semilattice laws (SemilatticeSup on CapabilityLevel)
-- ═══════════════════════════════════════════════════════════════════════

/-- Join is idempotent: a ⊔ a = a -/
theorem join_idempotent (a : CapabilityLevel) : a ⊔ a = a := by
  cases a <;> decide

/-- Join is commutative: a ⊔ b = b ⊔ a -/
theorem join_commutative (a b : CapabilityLevel) : a ⊔ b = b ⊔ a := by
  cases a <;> cases b <;> decide

/-- Join is associative: (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c) -/
theorem join_associative (a b c : CapabilityLevel) : (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c) := by
  cases a <;> cases b <;> cases c <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Absorption laws (Lattice on CapabilityLevel)
-- ═══════════════════════════════════════════════════════════════════════

/-- Absorption: a ⊓ (a ⊔ b) = a -/
theorem absorption_inf_sup (a b : CapabilityLevel) : a ⊓ (a ⊔ b) = a := by
  cases a <;> cases b <;> decide

/-- Absorption: a ⊔ (a ⊓ b) = a -/
theorem absorption_sup_inf (a b : CapabilityLevel) : a ⊔ (a ⊓ b) = a := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Monotonicity — meet is deflationary
-- ═══════════════════════════════════════════════════════════════════════

/-- Meet is deflationary on the left: a ⊓ b ≤ a -/
theorem meet_le_left (a b : CapabilityLevel) : a ⊓ b ≤ a := by
  cases a <;> cases b <;> decide

/-- Meet is deflationary on the right: a ⊓ b ≤ b -/
theorem meet_le_right (a b : CapabilityLevel) : a ⊓ b ≤ b := by
  cases a <;> cases b <;> decide

/-- Join is expansionary on the left: a ≤ a ⊔ b -/
theorem le_join_left (a b : CapabilityLevel) : a ≤ a ⊔ b := by
  cases a <;> cases b <;> decide

/-- Join is expansionary on the right: b ≤ a ⊔ b -/
theorem le_join_right (a b : CapabilityLevel) : b ≤ a ⊔ b := by
  cases a <;> cases b <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Distributivity (bonus — CapabilityLevel is a distributive lattice)
-- ═══════════════════════════════════════════════════════════════════════

/-- Distributivity: a ⊓ (b ⊔ c) = (a ⊓ b) ⊔ (a ⊓ c) -/
theorem meet_distrib_join (a b c : CapabilityLevel) :
    a ⊓ (b ⊔ c) = (a ⊓ b) ⊔ (a ⊓ c) := by
  cases a <;> cases b <;> cases c <;> decide

/-- Distributivity: a ⊔ (b ⊓ c) = (a ⊔ b) ⊓ (a ⊔ c) -/
theorem join_distrib_meet (a b c : CapabilityLevel) :
    a ⊔ (b ⊓ c) = (a ⊔ b) ⊓ (a ⊔ c) := by
  cases a <;> cases b <;> cases c <;> decide

-- ═══════════════════════════════════════════════════════════════════════
-- Proof count: 14 theorems (matching 14 Rust property tests in category.rs)
-- ═══════════════════════════════════════════════════════════════════════

end CategoryProofs
