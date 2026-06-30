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
  "https://github.com/AeneasVerif/aeneas.git" @ "5138c03bd39e870abe1ad3a572865cf8c15f43d6" / "backends" / "lean"

-- Mathlib for HeytingAlgebra typeclass
-- Version must be compatible with Aeneas's Lean toolchain (v4.30.0-rc2)
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.30.0-rc2"

-- Aeneas-generated types, curated function subset, and external implementations
lean_lib «PortcullisCore» where
  roots := #[`PortcullisCore.Types, `PortcullisCore.CoreFuns, `PortcullisCore.FunsExternal]
  srcDir := "generated"

-- HeytingAlgebra bridge proof + function correspondence theorems
lean_lib «PortcullisCoreBridge» where
  roots := #[`PortcullisCoreBridge]

-- Aeneas-generated integrity-axis enforcement core (from real Rust:
-- crates/nucleus-ifc-kernel/src/extracted/ifc_integrity.rs — the IFC source
-- moved out of portcullis-core in MVK M3). The function bodies are UNMODIFIED
-- Aeneas output (only the inter-module import path in Funs.lean was retargeted
-- from NucleusIfcKernel.Types to PortcullisCoreIFC.Types so this lib does not
-- collide with the «PortcullisCore» lib).
lean_lib «PortcullisCoreIFC» where
  roots := #[`PortcullisCoreIFC.Types, `PortcullisCoreIFC.Funs]
  srcDir := "generated-ifc"

-- Noninterference theorem proven OVER the Aeneas-generated IFC core above.
lean_lib «IntegrityNoninterferenceExtracted» where
  roots := #[`IntegrityNoninterferenceExtracted]

-- Aeneas-generated capability residuated-quantale core (from real Rust:
-- crates/nucleus-ifc-kernel/src/extracted/capability_quantale.rs). UNMODIFIED
-- Aeneas output (only the inter-module import in Funs.lean was retargeted from
-- NucleusIfcKernel.Types to PortcullisCoreCapQuantale.Types so this lib does not
-- collide with the «PortcullisCore» / «PortcullisCoreIFC» libs).
lean_lib «PortcullisCoreCapQuantale» where
  roots := #[`PortcullisCoreCapQuantale.Types, `PortcullisCoreCapQuantale.Funs]
  srcDir := "generated-cap-quantale"

-- The residuation adjunction (a⊗b≤c ⟺ b≤a⊸c) proven OVER the Aeneas-generated
-- capability core above — the formal realization of the enriching value V.
lean_lib «CapabilityResiduatedQuantaleProofs» where
  roots := #[`CapabilityResiduatedQuantaleProofs]

-- Confidentiality-axis noninterference over the extracted core (D1/C1; STAGED —
-- builds once aeneas-ifc-scoped extracts the ifc_confidentiality functions)
lean_lib «ConfidentialityNoninterferenceExtracted» where
  roots := #[`ConfidentialityNoninterferenceExtracted]

-- Exposure tracker proofs (uninhabitable state detector)
lean_lib «ExposureProofs» where
  roots := #[`ExposureProofs]

-- IFC label lattice proofs (Flow Kernel foundation)
lean_lib «FlowProofs» where
  roots := #[`FlowProofs]

-- Multi-hop non-interference unwinding theorem (D1/M1; Mathlib-free, zero axioms)
lean_lib «UnwindingNoninterference» where
  roots := #[`UnwindingNoninterference]

-- Unwinding theorem instantiated over the real IFCLabel2 lattice (D1/M1b; Mathlib)
lean_lib «UnwindingIFC» where
  roots := #[`UnwindingIFC]

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

-- Register the remaining categorical-proof modules as build targets so the
-- olog catkb audit can resolve `#print axioms` and run the leanchecker
-- second-kernel re-check against their built oleans (DoD B4/B5). These hold
-- PROVEN theorems the KB cites (category / delegation-category / Galois).
lean_lib «CategoryProofs» where
  roots := #[`CategoryProofs]

lean_lib «DelegationCategoryProofs» where
  roots := #[`DelegationCategoryProofs]

lean_lib «GaloisConnectionProofs» where
  roots := #[`GaloisConnectionProofs]

-- Generic attenuation algebra: deflationary+monotone closure, meet-cap
-- collapse, chain order-independence (Lean side of src/attenuation.rs)
lean_lib «AttenuationProofs» where
  roots := #[`AttenuationProofs]

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

-- AugmentedBorromeanTheorems: formal theorems for the S₃ action values.
lean_lib «AugmentedBorromeanTheorems» where
  roots := #[`AugmentedBorromeanTheorems]

-- BraidObstruction: char-2 obstruction to braid-group lift via set-theoretic rack.
lean_lib «BraidObstruction» where
  roots := #[`BraidObstruction]

-- DiamondActions: Z/2 action test on diamondSite's H¹ = 2.
lean_lib «DiamondActions» where
  roots := #[`DiamondActions]

-- RealWorldActions: Z/2 action tests on BLP, Biba, PrivEsc, Indirect posets.
lean_lib «RealWorldActions» where
  roots := #[`RealWorldActions]

-- Braid empirical: S₃ symmetry + Brunnian drop tests via native_decide.
lean_lib «BraidEmpirical» where
  roots := #[`BraidEmpirical]

-- Braid analysis: structural explanation of BraidEmpirical's 36/44 asymmetry.
lean_lib «BraidAnalysis» where
  roots := #[`BraidAnalysis]

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

-- Monoidal structure on permission composition (meet/join commutative monoids,
-- distributive lattice). Imported by ConstructiveSecurity as the capability-
-- lattice instance Φ. Mathlib-free; pure Lean core.
lean_lib «MonoidalPermissionProofs» where
  roots := #[`MonoidalPermissionProofs]

-- Constructive cryptography (Maurer TOSCA 2011): cryptographic algebra +
-- compatible pseudo-metric, the construction relation R --(π,ε)--> S, and the
-- composition theorem (serial/parallel/identity). Mathlib-free; pure Lean core.
-- Instantiates Φ with the permission lattice (imports MonoidalPermissionProofs).
lean_lib «ConstructiveSecurity» where
  roots := #[`ConstructiveSecurity]

-- WASI 0.3.0 world functor: capability lattice → component import world.
-- φ : CapabilityLevel → WasiGrant is a lattice homomorphism (meet/join/bounds
-- preserved), so "most-restrictive-wins compiles to import intersection".
-- Mirrors crates/portcullis-wasi/src/lib.rs. Mathlib-free; pure Lean core.
lean_lib «WasiWorldFunctor» where
  roots := #[`WasiWorldFunctor]

-- Soundness of the WASI IFC boundary monitor: the floating label admits a sink
-- iff every source read admits it (monitor_sound). The formal backing FIDES
-- lacks. Mirrors crates/portcullis-wasi/src/ifc.rs (+ host.rs enforcement).
lean_lib «WasiIfcBoundary» where
  roots := #[`WasiIfcBoundary]

-- Previously-orphaned PROVEN libs: sorry-free and kernel-checked but never
-- registered as build targets, so `lake build` / CI never compiled them even
-- though README cites the Belnap bilattice as "kernel-checked". Registering
-- them puts the cited claims under the proven-tier CI gate. Both verified to
-- compile clean against the pinned toolchain (2026-06-21).
lean_lib «BelnapDecisionProofs» where
  roots := #[`BelnapDecisionProofs]

lean_lib «RepairAlgebraProofs» where
  roots := #[`RepairAlgebraProofs]

-- NOTE: LabeledTypeProofs.lean and CategoryProofs.lean are NOT registered /
-- gated here because they do NOT currently compile against the pinned toolchain
-- (LabeledTypeProofs uses unbound auto-implicits under `autoImplicit := false`;
-- CategoryProofs is missing a `Min CapabilityLevel` instance after a Mathlib
-- order refactor). They were orphaned/ungated and silently rotted. Tracked as
-- Tier 3 (STALE) in CONJECTURES.md — do not cite them as proven until repaired.
-- CategoryProofs remains a lean_lib target above (pre-existing) but is excluded
-- from the proven-tier build list in portcullis-core-proven-lean.yml.
