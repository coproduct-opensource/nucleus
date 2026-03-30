import Lake
open Lake DSL

package «portcullisCore» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

-- Aeneas standard library (provides Result monad, scalar types, etc.)
-- Pinned to the same commit used to generate PortcullisCore.lean
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "b2b5e3d" / "backends" / "lean"

-- Mathlib for HeytingAlgebra typeclass
-- Version must be compatible with Aeneas's Lean toolchain (v4.28.0-rc1)
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.28.0-rc1"

-- Aeneas-generated types, curated function subset, and external implementations
lean_lib «PortcullisCore» where
  roots := #[`PortcullisCore.Types, `PortcullisCore.CoreFuns, `PortcullisCore.FunsExternal]
  srcDir := "generated"

-- HeytingAlgebra bridge proof + function correspondence theorems
lean_lib «PortcullisCoreBridge» where
  roots := #[`PortcullisCoreBridge]

-- Exposure tracker proofs (uninhabitable state detector)
lean_lib «ExposureProofs» where
  roots := #[`ExposureProofs]

-- IFC label lattice proofs (Flow Kernel foundation)
lean_lib «FlowProofs» where
  roots := #[`FlowProofs]

-- Kernel decision logic proofs (decide_pure correctness)
lean_lib «DecidePureProofs» where
  roots := #[`DecidePureProofs]

-- FlowGraph causal DAG proofs (label monotonicity, taint preservation)
lean_lib «FlowGraphProofs» where
  roots := #[`FlowGraphProofs]
