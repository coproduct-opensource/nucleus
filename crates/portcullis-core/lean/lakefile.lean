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
-- Experiment: bumped to v4.29.0-rc6 (aeneas still pinned to v4.28.0-rc1 — may break)
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.29.0-rc6"

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

-- Simplex acyclicity: cone construction for H¹ = 0 under uniform presheaf.
lean_lib «SimplexAcyclic» where
  roots := #[`SimplexAcyclic]

-- Alignment Tax bridge: operational declassification count = rank H¹.
lean_lib «AlignmentTaxBridge» where
  roots := #[`AlignmentTaxBridge]

-- Universal Detection Impossibility: abstract Rice-style theorem.
lean_lib «UniversalDetection» where
  roots := #[`UniversalDetection]

-- Mathlib bridge: gaussRankBool ↔ Matrix.rank for unconditional closure.
lean_lib «MatrixBridge» where
  roots := #[`MatrixBridge]

-- Multi-agent cohomology: lifting IFC sheaf to communication graphs.
lean_lib «MultiAgentCohomology» where
  roots := #[`MultiAgentCohomology]

-- Concrete alignment-tax non-vacuity: smoke tests on diamond / directInject.
lean_lib «AlignmentTaxConcrete» where
  roots := #[`AlignmentTaxConcrete]

-- Alignment sample complexity: Fano-analog lower bound for fine-tuning.
lean_lib «AlignmentSampleComplexity» where
  roots := #[`AlignmentSampleComplexity]

-- Compositional alignment: Mayer-Vietoris-analog for spec composition.
lean_lib «CompositionalAlignment» where
  roots := #[`CompositionalAlignment]
-- PAC / VC-dimension bridge: classical learning-theory equivalence for rank H¹.
lean_lib «PACVCBridge» where
  roots := #[`PACVCBridge]

-- Universality theorem: rank H¹ is a complete invariant for alignment specs.
lean_lib «UniversalityTheorem» where
  roots := #[`UniversalityTheorem]

-- Higher obstruction theory: H² and Grothendieck spectral sequence analog.
lean_lib «HigherObstruction» where
  roots := #[`HigherObstruction]

-- Euler characteristic: single-invariant collapse + Möbius combinatorial bridge.
lean_lib «EulerCharacteristic» where
  roots := #[`EulerCharacteristic]
-- Entropic cocycle: Shannon-entropy-valued H¹ class (Baudot-Bennequin analog).
lean_lib «EntropicCocycle» where
  roots := #[`EntropicCocycle]
