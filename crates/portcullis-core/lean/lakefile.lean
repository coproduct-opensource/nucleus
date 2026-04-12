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

-- Declassification rule safety proofs
lean_lib «DeclassifyProofs» where
  roots := #[`DeclassifyProofs]

-- FlowGraph causal DAG proofs (label monotonicity, taint preservation)
lean_lib «FlowGraphProofs» where
  roots := #[`FlowGraphProofs]

-- Compartment ceiling proofs (research/draft/execute/breakglass ordering)
lean_lib «CompartmentProofs» where
  roots := #[`CompartmentProofs]

-- Delegation narrowing proofs (monotone attenuation, scope subset)
lean_lib «DelegationProofs» where
  roots := #[`DelegationProofs]

-- DerivationClass DPI invariant proofs (no silent cleansing, monotone join)
lean_lib «DerivationProofs» where
  roots := #[`DerivationProofs]

-- IFC semilattice typeclass instances: ConfLevel, IntegLevel, IFCLabel2 (#1123-#1127)
lean_lib «IFCSemilatticeProofs» where
  roots := #[`IFCSemilatticeProofs]

-- Semantic IFC: Galois connection on propositions, channel model, soundness
lean_lib «SemanticIFC» where
  roots := #[`SemanticIFC]

-- Decidable internal logic: Bool-valued mirrors of Proposition for finite Secret types
-- (Issue #1428, tracking #1427)
lean_lib «SemanticIFCDecidable» where
  roots := #[`SemanticIFCDecidable]

-- Čech cohomology scaffold for finite posets (Phase 8 Y6.0, issue #1493)
-- Load-bearing prerequisite for alignment_tax = H¹ theorem (#1479).
lean_lib «CechCohomology» where
  roots := #[`CechCohomology]

-- Comparison Theorem: Čech ≅ Topos for finite Alexandrov posets (#1493)
-- Proof skeleton replacing the comparison axiom.
lean_lib «ComparisonTheorem» where
  roots := #[`ComparisonTheorem]

-- GF(2) rank-nullity scaffold supporting Honest Fundamental Theorem.
lean_lib «RankNullity» where
  roots := #[`RankNullity]
