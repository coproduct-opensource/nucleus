-- Curated subset of Aeneas-generated functions for verification.
--
-- Extracted from the full Funs.lean (which has trait impls that don't
-- compile under Lean 4.28 due to API changes in Ord/PartialOrd fields).
-- These are the lattice operations we verify: meet, join, implies,
-- complement, leq. The function bodies are UNMODIFIED from Aeneas output.
import Aeneas
import PortcullisCore.Types
import PortcullisCore.FunsExternal
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000

namespace portcullis_core

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::meet]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 58:4-60:5
    Visibility: public -/
def CapabilityLevel.meet
  (self : CapabilityLevel) (other : CapabilityLevel) :
  Result CapabilityLevel
  := do
  let b ←
    CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le self other
  if b
  then ok self
  else ok other

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::join]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 63:4-65:5
    Visibility: public -/
def CapabilityLevel.join
  (self : CapabilityLevel) (other : CapabilityLevel) :
  Result CapabilityLevel
  := do
  let b ←
    CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.ge self other
  if b
  then ok self
  else ok other

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::implies]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 70:4-76:5
    Visibility: public -/
def CapabilityLevel.implies
  (self : CapabilityLevel) (other : CapabilityLevel) :
  Result CapabilityLevel
  := do
  let b ←
    CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le self other
  if b
  then ok CapabilityLevel.Always
  else ok other

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::complement]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 79:4-81:5
    Visibility: public -/
def CapabilityLevel.complement
  (self : CapabilityLevel) : Result CapabilityLevel := do
  CapabilityLevel.implies self CapabilityLevel.Never

/-- [portcullis_core::{portcullis_core::CapabilityLevel}::leq]:
    Source: 'crates/portcullis-core/src/lib.rs', lines 84:4-86:5
    Visibility: public -/
def CapabilityLevel.leq
  (self : CapabilityLevel) (other : CapabilityLevel) : Result Bool := do
  CapabilityLevel.Insts.CoreCmpPartialOrdCapabilityLevel.le self other

end portcullis_core
