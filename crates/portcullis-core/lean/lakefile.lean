import Lake
open Lake DSL

package «portcullisCore» where
  -- Release mode compiles tactic C code with -O3 (vs default debug). Faster
  -- native-decide / algorithm-heavy proofs at the cost of slower initial build.
  buildType := .release
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    -- Raise default heartbeat budget so individual theorems needn't override.
    -- Individual declarations can still bump higher with `set_option`.
    ⟨`maxHeartbeats, (400000 : Nat)⟩
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

-- Braid-group cohomology speculation: divisibility checks + research targets.
lean_lib «BraidCohomology» where
  roots := #[`BraidCohomology]

-- AugmentedBorromean: adds missing obs_ac, empirically tests S₃ symmetry.
lean_lib «AugmentedBorromean» where
  roots := #[`AugmentedBorromean]

-- AugmentedBorromeanActions: explicit S₃ permutation matrices on C¹, rank tests.
lean_lib «AugmentedBorromeanActions» where
  roots := #[`AugmentedBorromeanActions]

-- BraidObstruction: char-2 obstruction to braid-group lift via set-theoretic rack.
lean_lib «BraidObstruction» where
  roots := #[`BraidObstruction]

-- DiamondActions: Z/2 action test on diamondSite's H¹ = 2.
lean_lib «DiamondActions» where
  roots := #[`DiamondActions]

-- Braid empirical: S₃ symmetry + Brunnian drop tests via native_decide.
lean_lib «BraidEmpirical» where
  roots := #[`BraidEmpirical]

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
-- Quantum extension: von Neumann cocycle + Born-rule quadratic sample bound.
lean_lib «QuantumExtension» where
  roots := #[`QuantumExtension]
-- Persistent alignment: barcode-valued cost over training filtrations.
lean_lib «PersistentAlignment» where
  roots := #[`PersistentAlignment]

-- Lipschitz-equivariance: certified robustness radius from rank H¹.
lean_lib «LipschitzEquivariance» where
  roots := #[`LipschitzEquivariance]
