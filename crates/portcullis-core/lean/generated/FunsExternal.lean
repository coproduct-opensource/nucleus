-- External function implementations for Aeneas-generated portcullis_core.
--
-- These provide concrete definitions for the axioms in FunsExternal_Template.lean.
-- The Aeneas-generated code calls PartialOrd::le and PartialOrd::ge for
-- CapabilityLevel comparisons. We define them using the same toNat encoding
-- used by the HeytingAlgebra proof.
import Aeneas
import PortcullisCore.Types
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

set_option maxHeartbeats 1000000
open portcullis_core

/-- Natural number encoding matching Rust #[repr(u8)] discriminants. -/
private def toNat : CapabilityLevel → Nat
  | .Never   => 0
  | .LowRisk => 1
  | .Always  => 2

/-- [core::hash::impls::{core::hash::Hash for u8}::hash] -/
@[rust_fun "core::hash::impls::{core::hash::Hash<u8>}::hash"]
noncomputable def U8.Insts.CoreHashHash.hash
  {H : Type} (_hasherInst : core.hash.Hasher H) (x : Std.U8) (h : H) : Result H :=
  ok h  -- stub: hash is not needed for lattice proofs

/-- [PartialOrd::le for CapabilityLevel]: a ≤ b via natural number encoding.
    Matches the Rust derived PartialOrd which compares discriminants. -/
@[simp]
def CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le
  (a b : CapabilityLevel) : Result Bool :=
  ok (Nat.ble (toNat a) (toNat b))

/-- [PartialOrd::ge for CapabilityLevel]: a ≥ b via natural number encoding. -/
@[simp]
def CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.ge
  (a b : CapabilityLevel) : Result Bool :=
  ok (Nat.ble (toNat b) (toNat a))
