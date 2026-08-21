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

-- Assurance coverage: the gate suite as a covering family. Vocabulary ported
-- from olog/claim-calculus (Lean 4.32 there, 4.30 here — see the file header for
-- why it is copied rather than required). Mathlib-free and dependency-free.
lean_lib «AssuranceCoverage» where
  roots := #[`AssuranceCoverage]

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

-- Aeneas-generated scope-binding core (from real Rust:
-- crates/nucleus-ifc-kernel/src/extracted/mediation.rs). UNMODIFIED Aeneas
-- output (only the inter-module import in Funs.lean was retargeted from
-- NucleusIfcKernel.Types to PortcullisCoreMediation.Types so this lib does not
-- collide with the other generated libs).
lean_lib «PortcullisCoreMediation» where
  roots := #[`PortcullisCoreMediation.Types, `PortcullisCoreMediation.Funs]
  srcDir := "generated-mediation"

-- Scope binding proven OVER the Aeneas-generated core above: a discharge
-- authorizes the action it was earned for and nothing else (first half of
-- complete mediation).
lean_lib «MediationScopeExtracted» where
  roots := #[`MediationScopeExtracted]

-- Aeneas-generated declassification decision core (from real Rust:
-- crates/nucleus-ifc-kernel/src/extracted/declassify.rs). UNMODIFIED Aeneas
-- output (only the inter-module import in Funs.lean was retargeted from
-- NucleusIfcKernel.Types to PortcullisCoreDeclass.Types so this lib does not
-- collide with the other generated libs, which re-export opcode/cflows_to).
lean_lib «PortcullisCoreDeclass» where
  roots := #[`PortcullisCoreDeclass.Types, `PortcullisCoreDeclass.Funs]
  srcDir := "generated-declass"

-- Sink-scoped, one-shot declassification proven OVER the Aeneas-generated core
-- above: released data reaches a sink only through an operation the signed mask
-- admits (O4/O5), and a token authorizes at most one application (O3). Replaces
-- the hand model in DeclassifyProofs.lean.
lean_lib «DeclassifySinkScopeExtracted» where
  roots := #[`DeclassifySinkScopeExtracted]

lean_lib «PortcullisCoreEgress» where
  roots := #[`PortcullisCoreEgress.Types, `PortcullisCoreEgress.Funs]
  srcDir := "generated-egress"

-- Egress confinement proven OVER the Aeneas-generated matcher above: the
-- network policy is the real enforcement boundary for shell effects.
lean_lib «EgressConfinementExtracted» where
  roots := #[`EgressConfinementExtracted]

lean_lib «PortcullisCoreCredential» where
  roots := #[`PortcullisCoreCredential.Types, `PortcullisCoreCredential.Funs]
  srcDir := "generated-credential"

-- FM-1: a credential never reaches the guest, proven over the extracted
-- delivery relation as a corollary of the confidentiality axis.
lean_lib «CredentialNoninterferenceExtracted» where
  roots := #[`CredentialNoninterferenceExtracted]

lean_lib «PortcullisCoreIdentity» where
  roots := #[`PortcullisCoreIdentity.Types, `PortcullisCoreIdentity.Funs]
  srcDir := "generated-identity"

-- FM-5: identity material never reaches the agent workload, proven over the
-- extracted delivery relation at the intra-VM boundary (three principals).
lean_lib «IdentityMaterialNoninterferenceExtracted» where
  roots := #[`IdentityMaterialNoninterferenceExtracted]

lean_lib «PortcullisCoreChannel» where
  roots := #[`PortcullisCoreChannel.Types, `PortcullisCoreChannel.Funs]
  srcDir := "generated-channel"

-- FM-5 phase 2: no channel (env/argv/cwd/stdio/fd/uid) delivers identity
-- material to the workload — the channel enumeration proved total.
lean_lib «ChannelAdmissionExtracted» where
  roots := #[`ChannelAdmissionExtracted]

-- Binds the snapshot clone-safety per-pod keys to the extracted Cmdline
-- noninterference proof above: the keys with a Secret-labelled MaterialKind
-- inherit `the_cmdline_delivers_no_secret_to_the_workload`; the residue
-- (auth_secret=Internal, AWS creds=no material) is a checked boundary.
lean_lib «SnapshotChannelBindingProofs» where
  roots := #[`SnapshotChannelBindingProofs]

-- Confidentiality-axis noninterference over the extracted core (D1/C1; STAGED —
-- builds once aeneas-ifc-scoped extracts the ifc_confidentiality functions)
lean_lib «ConfidentialityNoninterferenceExtracted» where
  roots := #[`ConfidentialityNoninterferenceExtracted]

-- Authority-axis noninterference over the extracted core (twin of integrity;
-- builds once aeneas-ifc-scoped extracts the ifc_authority functions). Proves
-- the AUTHORITY half of the anti-prompt-injection guarantee: web content
-- (NoAuthority) can never direct a Directive-privileged action.
lean_lib «AuthorityNoninterferenceExtracted» where
  roots := #[`AuthorityNoninterferenceExtracted]

-- Derivation-axis noninterference over the extracted core (the determinism-
-- provenance lattice; builds once aeneas-ifc-scoped extracts the ifc_derivation
-- functions). Proves AI-derived / opaque data can never reach a sink that
-- requires Deterministic (reproducible) provenance.
lean_lib «DerivationNoninterferenceExtracted» where
  roots := #[`DerivationNoninterferenceExtracted]

-- Provenance-axis noninterference over the extracted core (the source-set
-- powerset lattice; builds once aeneas-ifc-scoped extracts the ifc_provenance
-- functions). The FIFTH and final flows_to conjunct: a datum carrying a source
-- the sink does not accept can never be admitted over any op sequence.
lean_lib «ProvenanceNoninterferenceExtracted» where
  roots := #[`ProvenanceNoninterferenceExtracted]

-- Exposure tracker proofs (uninhabitable state detector)
lean_lib «ExposureProofs» where
  roots := #[`ExposureProofs]

-- IFC label lattice proofs (Flow Kernel foundation)
lean_lib «FlowProofs» where
  roots := #[`FlowProofs]

-- Multi-hop non-interference unwinding theorem (D1/M1; Mathlib-free, zero axioms)
lean_lib «UnwindingNoninterference» where
  roots := #[`UnwindingNoninterference]

-- Reference pod-execution semantics — Phase 0 falsification spike: a coarse-grained
-- monitor LTS whose event trace makes two-run noninterference NON-vacuous, discharged
-- by the extracted identity delivery theorem. Plan: graceful-puzzling-beaver.md.
lean_lib «PodMachineSpike» where
  roots := #[`PodMachineSpike]

lean_lib «PodCrossView» where
  roots := #[`PodCrossView]

-- The identity oracle mirrored in plain Lean (no Aeneas/Mathlib), proved faithful
-- to the extracted `identity_reaches_workload` — the toolchain bridge that lets the
-- iris-lean pod machine branch on the shipped decision. Plan: graceful-puzzling-beaver.md.
lean_lib «IdentityOracleMirror» where
  roots := #[`IdentityOracleMirror]

-- The v2 half of the toolchain bridge: the confidentiality lattice, the material
-- label table, and the principal ceiling, mirrored in plain Lean and PROVED equal
-- to the shipped extraction. Machine v2's mirrors previously had no faithfulness
-- theorem at all.
lean_lib «ConfidentialityOracleMirror» where
  roots := #[`ConfidentialityOracleMirror]

-- The INTEGRITY axis — the second, orthogonal dimension of the reference machine
-- (Machine v3 gate 1). Integrity MEETS where confidentiality JOINS, and its
-- flows-to points the other way; those mirrors need their own anchor.
lean_lib «IntegrityOracleMirror» where
  roots := #[`IntegrityOracleMirror]

-- The CHANNEL dimension (Machine v3 gate 2): delivery becomes a three-argument
-- judgement over (channel, material, principal), and three of the seven channels
-- are material-closed by construction rather than by policy.
lean_lib «ChannelOracleMirror» where
  roots := #[`ChannelOracleMirror]

-- Unwinding theorem instantiated over the real IFCLabel2 lattice (D1/M1b; Mathlib)
lean_lib «UnwindingIFC» where
  roots := #[`UnwindingIFC]

-- Kernel decision logic proofs (decide_pure correctness)
lean_lib «DecidePureProofs» where
  roots := #[`DecidePureProofs]

-- Declassification rule safety proofs
lean_lib «DeclassifyProofs» where
  roots := #[`DeclassifyProofs]

lean_lib «SessionCeilingProofs» where
  roots := #[`SessionCeilingProofs]

-- GKAT syntax + equational axioms (POPL'20 Fig.1) and the single-state Salomaa
-- reduction (existence via W1/U5/S1/S4, uniqueness via W3) — the base case of the
-- completeness reduction, done syntactically. General-n existence is open.
lean_lib «GkatSyntaxProofs» where
  roots := #[`GkatSyntaxProofs]

lean_lib «GkatGuardedStringProofs» where
  roots := #[`GkatGuardedStringProofs]

lean_lib «GkatInexpressibleProofs» where
  roots := #[`GkatInexpressibleProofs]

lean_lib «GkatUniquenessFrontierProofs» where
  roots := #[`GkatUniquenessFrontierProofs]

lean_lib «GkatExistenceFrontierProofs» where
  roots := #[`GkatExistenceFrontierProofs]

-- UA₂ = UA₁ + a guard-pullback witness: the wp-definability decomposition of the
-- Uniqueness Axiom, and a new sufficient condition for GKAT-solvability.
lean_lib «GkatUAIndependenceProofs» where
  roots := #[`GkatUAIndependenceProofs]

-- Semantic observation layer: guard-definability ⟺ descent to the observation
-- quotient, with a certified non-definable (regime-3) crossing.
lean_lib «GkatObservationProofs» where
  roots := #[`GkatObservationProofs]

-- No guard-pullback witness exists for a genuine action (the model side of the
-- obstruction, via GkatGS.sound in the guarded-string model).
lean_lib «GkatPullbackWitnessProofs» where
  roots := #[`GkatPullbackWitnessProofs]

lean_lib «GkatDerivativeProofs» where
  roots := #[`GkatDerivativeProofs]

-- Where the pullback witnesses come from: well-nested systems are witness-free
-- (Track 1), and the regime-1 witness is sound under a test-invariance hypothesis
-- (Track 2, KA-with-hypotheses).
lean_lib «GkatWellNestedProofs» where
  roots := #[`GkatWellNestedProofs]

lean_lib «GkatHardFrontierProofs» where
  roots := #[`GkatHardFrontierProofs]

lean_lib «GkatOrderedBAProofs» where
  roots := #[`GkatOrderedBAProofs]

lean_lib «GkatCyclicOrderedBridgeProofs» where
  roots := #[`GkatCyclicOrderedBridgeProofs]

lean_lib «GkatBisimulationProofs» where
  roots := #[`GkatBisimulationProofs]

lean_lib «GkatCompletenessProofs» where
  roots := #[`GkatCompletenessProofs]

lean_lib «GkatDerivativeFiniteProofs» where
  roots := #[`GkatDerivativeFiniteProofs]

lean_lib «GkatDecisionProofs» where
  roots := #[`GkatDecisionProofs]

lean_lib «GkatBehaviorProofs» where
  roots := #[`GkatBehaviorProofs]

lean_lib «GkatInexpressibilityProofs» where
  roots := #[`GkatInexpressibilityProofs]

lean_lib «GkatCoequationProofs» where
  roots := #[`GkatCoequationProofs]

lean_lib «GkatFaithfulnessProofs» where
  roots := #[`GkatFaithfulnessProofs]

-- Kleene synthesis, Phase 1: the GKAT automaton carrier `GAut` (finite, BExp-guarded,
-- deterministic), the derivative automaton `derivAut e` (guarded transitions read off
-- `next`, `autLang = den`), well-formedness, and the automaton-level nesting coequation
-- `Nested` — proven for every `derivAut e` and shown to reject the Fig 3 witness. Toward
-- the completeness half `W ⊆ {⟦e⟧}` (rel UA).
lean_lib «GkatKleeneProofs» where
  roots := #[`GkatKleeneProofs]

lean_lib «GkatThompsonUniquenessProofs» where
  roots := #[`GkatThompsonUniquenessProofs]

-- Derived guarded-algebra laws (U/S axioms only, no model, no uniqueness principle)
-- used by the null-language elimination: assertion/guarded-choice interchange, the
-- case-split insertion law, and the kill law that turns a right-hand Boolean fact into
-- a rewrite of the preceding program.
lean_lib «GkatGuardedAlgebraProofs» where
  roots := #[`GkatGuardedAlgebraProofs]

-- Atom transfer (`den` only reads the primitive tests of the expression) plus the
-- finite dead-cell test `deadTestOver`: the device that turns "no guarded string starts
-- here" into a Boolean guard the finite axioms can rewrite with.
lean_lib «GkatAtomTransferProofs» where
  roots := #[`GkatAtomTransferProofs]

-- Semantic side conditions of the null-language induction: fresh sum carriers for the
-- action case, the intermediate dead region for sequencing, and the loop invariant.
lean_lib «GkatNullSemanticsProofs» where
  roots := #[`GkatNullSemanticsProofs]

-- NULL-LANGUAGE COMPLETENESS: a GKAT program with no guarded strings is provably 0,
-- from the finite axioms alone (W3 only; no UA, no completeness hypothesis). Discharges
-- the dead-branch obligation that previously assumed FiniteAxiomsCompleteBA.
lean_lib «GkatNullLanguageProofs» where
  roots := #[`GkatNullLanguageProofs]

-- Where UA is actually still needed: the guard-pullback witness is DERIVABLE (as the
-- constant 1 or 0) exactly on the decided regions, and the leftover residue provably
-- branches both ways. Sharpens GkatUAIndependenceProofs / GkatPullbackWitnessProofs.
lean_lib «GkatDecidedPullbackProofs» where
  roots := #[`GkatDecidedPullbackProofs]

-- Composition check: the dead-branch rewrite the completeness endgame needs, now with
-- NO completeness hypothesis (it previously assumed FiniteAxiomsCompleteBA).
lean_lib «GkatDeadBranchProofs» where
  roots := #[`GkatDeadBranchProofs]

-- UA ELIMINATED at every decided crossing: post_all PRODUCES the guard-pullback witness
-- that GkatUAIndependenceProofs could only assume, so UA2 becomes a theorem of the
-- finite axioms there (W3 = UA1 is the only fixpoint principle used).
lean_lib «GkatDecidedUAProofs» where
  roots := #[`GkatDecidedUAProofs]

-- The sharp reduction: full finite-axiom completeness is EQUIVALENT to the statement
-- that behaviourally identical positions inside ONE program's own Thompson automaton
-- carry provably equal labels. Nothing about arbitrary equation systems survives.
lean_lib «GkatCompletenessReductionProofs» where
  roots := #[`GkatCompletenessReductionProofs]

-- Completeness ENTAILS UA at every arity: "completeness with UA eliminated" is not a
-- softer target than "UA is derivable", and the contrapositive gives the exact shape a
-- negative resolution must take.
lean_lib «GkatCompletenessImpliesUAProofs» where
  roots := #[`GkatCompletenessImpliesUAProofs]

-- The counter-model interface: one field per finite axiom, soundness of EquivBA, and the
-- composed refutation lemma. Makes a negative resolution fill-in-the-blank.
lean_lib «GkatModelProofs» where
  roots := #[`GkatModelProofs]

-- The positive route reduced to ONE statement, following Grabmayer-Fokkink
-- crystallization: if any two language-equivalent programs are covered by the Thompson
-- automaton of a third program, completeness follows with no uniqueness axiom.
lean_lib «GkatCrystallizationProofs» where
  roots := #[`GkatCrystallizationProofs]

-- Brick 1 of the crystallization construction: the syntactic layering (loop-nesting rank)
-- and the component-closure facts that make "loops are never mutually nested" formal.
lean_lib «GkatLayeringProofs» where
  roots := #[`GkatLayeringProofs]

-- The n-ary decomposition of the Uniqueness Axiom: chain-elimination reduces an
-- n-state guarded cycle to a single W3 loop given a pullback witness per crossing
-- (UAₙ = UA₁ + (n−1) witnesses).
lean_lib «GkatChainEliminationProofs» where
  roots := #[`GkatChainEliminationProofs]

-- Snapshot clone-safety: the cmdline key classification is disjoint, the
-- snapshot_safety guard is sound+complete, and unsafety is fail-closed (monotone).
-- Lifts the Rust test-gates #2300/#2301; bound to production by the snapshot.rs
-- parity test.
lean_lib «SnapshotCloneSafetyProofs» where
  roots := #[`SnapshotCloneSafetyProofs]

-- One-theorem admissibility for user-defined loops: a monotone endomap on the
-- exposure lattice inherits the ratchet at its least fixpoint (Knaster–Tarski by
-- strict rank ascent). Ties the shipped session-ceiling fold to that lfp.
lean_lib «ExposureLoopFixpointProofs» where
  roots := #[`ExposureLoopFixpointProofs]

-- GKAT guarded loop ↔ least fixed point: GKAT's unique guarded fixed point of a
-- monotone body coincides with the Knaster–Tarski lfp our ratchet computes, so a
-- guarded loop inherits the ratchet; the general-guard boundary is a falsification.
lean_lib «GkatGuardedLoopBridge» where
  roots := #[`GkatGuardedLoopBridge]

-- GKAT `while b do body` as a monotone cascade step: under a guardedness
-- condition on the test, the guarded loop is a monotone endomap that inherits the
-- ratchet — extends the cascade surface to if/while.
lean_lib «GkatWhileStep» where
  roots := #[`GkatWhileStep]

-- A minimal ordered (inequational) GKAT: the least-fixpoint / star-induction rule,
-- proven sound for guarded-string language inclusion. The Kozen/DDP-style order the
-- equational theory drops (using Salomaa/UA instead).
lean_lib «GkatOrderedProofs» where
  roots := #[`GkatOrderedProofs]

-- User-authored cascades over the REAL derivation diamond inherit the ratchet:
-- RankedLattice instance for the DerivationClass lattice + monotone step
-- vocabulary + the one-theorem cascade admissibility (loop_admissible fired at
-- the shipped lattice). Anchored to production by the Rust parity test (Brick B).
lean_lib «DerivationCascadeAdmissible» where
  roots := #[`DerivationCascadeAdmissible]

lean_lib «ReceiptChainProofs» where
  roots := #[`ReceiptChainProofs]

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

-- K4 SPIKE: governance-monotonicity completeness (mathlib-free model + crux proof)
lean_lib «GovernanceCompletenessSpike» where
  roots := #[`GovernanceCompletenessSpike]

-- The collapse target refuted: an explicit uniformly-equivalent pair whose forced
-- quotient is not syntax-generated, so `CommonSyntacticCollapse` is false. Completeness
-- is untouched (the pair is provably equal); the live target is the span,
-- `CommonSyntacticRefinement`.
lean_lib «GkatCollapseRefutationProofs» where
  roots := #[`GkatCollapseRefutationProofs]

-- The repair survives the counterexample: `h = if b then e else f` covers both sides of
-- the pair that refutes `CommonSyntacticCollapse`, so `CommonSyntacticRefinement` holds
-- there. Both cover legs are constructed and checked.
lean_lib «GkatSpanWitnessProofs» where
  roots := #[`GkatSpanWitnessProofs]

-- Phase C engine: covers compose along the Thompson constructors, so synthesis is a
-- structural recursion. `InitCover` is the pseudostate-preserving cover the induction needs.
lean_lib «GkatSynthesisProofs» where
  roots := #[`GkatSynthesisProofs]

-- The positive fork discharged on the pair that refutes the cospan: `if b then e else f`
-- is a common intermediate covering both sides and solvable by the syntax.
lean_lib «GkatPositiveForkProofs» where
  roots := #[`GkatPositiveForkProofs]

lean_lib «GkatUnrollCoverProofs» where
  roots := #[`GkatUnrollCoverProofs]

-- The complementary refinement: repeating the loop body is a degree-2 cyclic cover of the
-- loop. Unrolling lengthens the tail; this changes the cycle, which is the covering degree.
lean_lib «GkatCyclicCoverProofs» where
  roots := #[`GkatCyclicCoverProofs]

-- Factors the single residual obligation into two independent halves: the span exists, and
-- Thompson automata are cofinal below Thompson automata.
lean_lib «GkatCofinalityProofs» where
  roots := #[`GkatCofinalityProofs]

-- Discharges the constructive half: the fibre product of two covers of a common system,
-- with both projections proved to be covers.
lean_lib «GkatPullbackProofs» where
  roots := #[`GkatPullbackProofs]

-- Refutes CommonTarget (a cover cannot turn a stepping pseudostate into a non-stepping one)
-- and repairs it with the productivity precondition the search always applied.
lean_lib «GkatCommonTargetProofs» where
  roots := #[`GkatCommonTargetProofs]

-- The behavioural target: lockstep matching of two normal automata with equal language.
lean_lib «GkatQuotientProofs» where
  roots := #[`GkatQuotientProofs]

-- The period law: a covering map cannot shorten the cycle it sits over.
lean_lib «GkatPeriodProofs» where
  roots := #[`GkatPeriodProofs]

-- The exit law: a GKAT while-loop has exactly one exit condition, tested at the entry.
lean_lib «GkatLoopExitProofs» where
  roots := #[`GkatLoopExitProofs]

-- The degree-k cyclic cover: repeating the loop body k times.
lean_lib «GkatCyclicKProofs» where
  roots := #[`GkatCyclicKProofs]

-- Guard-split duplication: the third refinement move, as a cover.
lean_lib «GkatDupCoverProofs» where
  roots := #[`GkatDupCoverProofs]

-- The refinement closure the search explores, as one relation, with every member a cover.
lean_lib «GkatRefinesProofs» where
  roots := #[`GkatRefinesProofs]

-- The residue, discharged: pair #3 of the eight open instances, proved without UA.
lean_lib «GkatResidueProofs» where
  roots := #[`GkatResidueProofs]

-- The residue as a family: a general loop guard, and the core at the top of a loop body.
lean_lib «GkatResidueFamilyProofs» where
  roots := #[`GkatResidueFamilyProofs]

-- Eliminating an unknown at an UNDECIDED crossing: the dead-exit kernel.
lean_lib «GkatDeadExitElimProofs» where
  roots := #[`GkatDeadExitElimProofs]

-- The nesting coequation closed under quotients: the covariety's other half.
lean_lib «GkatNestedClosureProofs» where
  roots := #[`GkatNestedClosureProofs]

-- Thompson automata satisfy the nesting coequation: the covariety chain's last leaf.
lean_lib «GkatThompsonNestedProofs» where
  roots := #[`GkatThompsonNestedProofs]

-- Semantically solvable automata satisfy the nesting coequation.
lean_lib «GkatSolvableNestedProofs» where
  roots := #[`GkatSolvableNestedProofs]

-- The certificate pipeline's first instance: CERT #3, kernel-checked end to end.
lean_lib «GkatCertPilotProofs» where
  roots := #[`GkatCertPilotProofs]

-- Support lemmas for emitted certificates (constant-valuation evaluation).
lean_lib «GkatCertSupportProofs» where
  roots := #[`GkatCertSupportProofs]

-- Emitted instance certificates (machine-generated by span-search/emit_cert.py).
lean_lib «GkatCertGen1» where
  roots := #[`GkatCertGen1]

lean_lib «GkatCertGen2» where
  roots := #[`GkatCertGen2]

lean_lib «GkatCertGen3» where
  roots := #[`GkatCertGen3]

lean_lib «GkatCertGen4» where
  roots := #[`GkatCertGen4]

lean_lib «GkatCertGen5» where
  roots := #[`GkatCertGen5]

lean_lib «GkatCertGen6» where
  roots := #[`GkatCertGen6]

lean_lib «GkatCertK4n1» where
  roots := #[`GkatCertK4n1]

lean_lib «GkatCertK4n2» where
  roots := #[`GkatCertK4n2]

lean_lib «GkatCertK4n3» where
  roots := #[`GkatCertK4n3]

lean_lib «GkatCertT1» where
  roots := #[`GkatCertT1]

lean_lib «GkatCertT2» where
  roots := #[`GkatCertT2]

lean_lib «GkatCertR5» where
  roots := #[`GkatCertR5]

lean_lib «GkatRingSupportProofs» where
  roots := #[`GkatRingSupportProofs]

lean_lib «GkatCertSupportBoolProofs» where
  roots := #[`GkatCertSupportBoolProofs]

lean_lib «GkatMixPilotProofs» where
  roots := #[`GkatMixPilotProofs]

lean_lib «GkatRingPlanProofs» where
  roots := #[`GkatRingPlanProofs]

lean_lib «GkatRingPlan2Proofs» where
  roots := #[`GkatRingPlan2Proofs]

lean_lib «GkatRingDecompProofs» where
  roots := #[`GkatRingDecompProofs]

lean_lib «GkatDecompPilotProofs» where
  roots := #[`GkatDecompPilotProofs]

lean_lib «GkatDecompProofs» where
  roots := #[`GkatDecompProofs]

lean_lib «GkatPlanExistenceProofs» where
  roots := #[`GkatPlanExistenceProofs]

lean_lib «GkatNormalizationProofs» where
  roots := #[`GkatNormalizationProofs]

lean_lib «GkatTrimProofs» where
  roots := #[`GkatTrimProofs]

lean_lib «GkatCycleProofs» where
  roots := #[`GkatCycleProofs]

lean_lib «GkatLoopFreeProofs» where
  roots := #[`GkatLoopFreeProofs]

lean_lib «GkatAtomicLoopProofs» where
  roots := #[`GkatAtomicLoopProofs]

lean_lib «GkatChainLoopProofs» where
  roots := #[`GkatChainLoopProofs]

lean_lib «GkatOrbitProofs» where
  roots := #[`GkatOrbitProofs]

lean_lib «GkatChainFragmentProofs» where
  roots := #[`GkatChainFragmentProofs]

lean_lib «GkatListPigeonProofs» where
  roots := #[`GkatListPigeonProofs]

lean_lib «GkatGuardDecideProofs» where
  roots := #[`GkatGuardDecideProofs]

lean_lib «GkatDecideProofs» where
  roots := #[`GkatDecideProofs]

lean_lib «GkatWalkedOrbitProofs» where
  roots := #[`GkatWalkedOrbitProofs]

lean_lib «GkatTwoLoopProofs» where
  roots := #[`GkatTwoLoopProofs]

lean_lib «GkatThreeLoopProofs» where
  roots := #[`GkatThreeLoopProofs]

lean_lib «GkatCertR1» where
  roots := #[`GkatCertR1]

lean_lib «GkatCertR2» where
  roots := #[`GkatCertR2]

lean_lib «GkatCertR3» where
  roots := #[`GkatCertR3]

lean_lib «GkatCertR4» where
  roots := #[`GkatCertR4]

lean_lib «GkatCertR6» where
  roots := #[`GkatCertR6]

lean_lib «GkatK6R01» where
  roots := #[`GkatK6R01]

lean_lib «GkatK6R02» where
  roots := #[`GkatK6R02]

lean_lib «GkatK6R03» where
  roots := #[`GkatK6R03]

lean_lib «GkatK6R04» where
  roots := #[`GkatK6R04]

lean_lib «GkatK6R05» where
  roots := #[`GkatK6R05]

lean_lib «GkatK6R06» where
  roots := #[`GkatK6R06]

lean_lib «GkatK6R07» where
  roots := #[`GkatK6R07]

lean_lib «GkatK6R08» where
  roots := #[`GkatK6R08]

lean_lib «GkatK6R09» where
  roots := #[`GkatK6R09]

lean_lib «GkatK6R10» where
  roots := #[`GkatK6R10]

lean_lib «GkatK6R11» where
  roots := #[`GkatK6R11]

lean_lib «GkatK6R12» where
  roots := #[`GkatK6R12]

lean_lib «GkatK6R13» where
  roots := #[`GkatK6R13]

lean_lib «GkatK6R14» where
  roots := #[`GkatK6R14]

lean_lib «GkatK6R15» where
  roots := #[`GkatK6R15]

lean_lib «GkatK6R16» where
  roots := #[`GkatK6R16]

lean_lib «GkatK6R17» where
  roots := #[`GkatK6R17]

lean_lib «GkatK6R18» where
  roots := #[`GkatK6R18]

lean_lib «GkatK6R19» where
  roots := #[`GkatK6R19]

lean_lib «GkatK6R20» where
  roots := #[`GkatK6R20]

lean_lib «GkatK6R21» where
  roots := #[`GkatK6R21]

lean_lib «GkatK6R22» where
  roots := #[`GkatK6R22]

lean_lib «GkatK6R23» where
  roots := #[`GkatK6R23]

lean_lib «GkatK6R24» where
  roots := #[`GkatK6R24]

lean_lib «GkatK6R25» where
  roots := #[`GkatK6R25]

lean_lib «GkatK6R26» where
  roots := #[`GkatK6R26]

lean_lib «GkatK6R27» where
  roots := #[`GkatK6R27]

lean_lib «GkatK6R28» where
  roots := #[`GkatK6R28]

lean_lib «GkatK6R29» where
  roots := #[`GkatK6R29]

lean_lib «GkatK6R30» where
  roots := #[`GkatK6R30]

lean_lib «GkatK6R31» where
  roots := #[`GkatK6R31]

lean_lib «GkatK6R32» where
  roots := #[`GkatK6R32]

lean_lib «GkatK6R33» where
  roots := #[`GkatK6R33]

lean_lib «GkatK6R34» where
  roots := #[`GkatK6R34]

lean_lib «GkatK6R35» where
  roots := #[`GkatK6R35]

lean_lib «GkatK6R36» where
  roots := #[`GkatK6R36]

lean_lib «GkatK6R37» where
  roots := #[`GkatK6R37]

lean_lib «GkatK6R38» where
  roots := #[`GkatK6R38]

lean_lib «GkatK6R39» where
  roots := #[`GkatK6R39]

lean_lib «GkatK6R40» where
  roots := #[`GkatK6R40]

lean_lib «GkatK6R41» where
  roots := #[`GkatK6R41]

lean_lib «GkatK6R42» where
  roots := #[`GkatK6R42]

lean_lib «GkatK6R43» where
  roots := #[`GkatK6R43]

lean_lib «GkatK6R44» where
  roots := #[`GkatK6R44]

lean_lib «GkatK6R45» where
  roots := #[`GkatK6R45]

lean_lib «GkatK6R46» where
  roots := #[`GkatK6R46]

lean_lib «GkatK6R47» where
  roots := #[`GkatK6R47]

lean_lib «GkatK6R48» where
  roots := #[`GkatK6R48]

lean_lib «GkatK6R49» where
  roots := #[`GkatK6R49]

lean_lib «GkatK6R50» where
  roots := #[`GkatK6R50]

lean_lib «GkatK6R51» where
  roots := #[`GkatK6R51]

lean_lib «GkatK6R52» where
  roots := #[`GkatK6R52]

lean_lib «GkatK6R53» where
  roots := #[`GkatK6R53]

lean_lib «GkatK6R54» where
  roots := #[`GkatK6R54]

lean_lib «GkatK6R55» where
  roots := #[`GkatK6R55]

lean_lib «GkatK6R56» where
  roots := #[`GkatK6R56]

lean_lib «GkatK6R57» where
  roots := #[`GkatK6R57]

lean_lib «GkatK6R58» where
  roots := #[`GkatK6R58]

lean_lib «GkatK6R59» where
  roots := #[`GkatK6R59]

lean_lib «GkatK6R60» where
  roots := #[`GkatK6R60]

lean_lib «GkatK6R61» where
  roots := #[`GkatK6R61]

lean_lib «GkatK6R62» where
  roots := #[`GkatK6R62]

lean_lib «GkatK6R63» where
  roots := #[`GkatK6R63]

lean_lib «GkatK6R64» where
  roots := #[`GkatK6R64]

lean_lib «GkatK6R65» where
  roots := #[`GkatK6R65]

lean_lib «GkatK6R66» where
  roots := #[`GkatK6R66]

lean_lib «GkatK6R67» where
  roots := #[`GkatK6R67]

lean_lib «GkatK6R68» where
  roots := #[`GkatK6R68]

lean_lib «GkatK6R69» where
  roots := #[`GkatK6R69]

lean_lib «GkatK6R70» where
  roots := #[`GkatK6R70]

lean_lib «GkatK6R71» where
  roots := #[`GkatK6R71]

lean_lib «GkatK6R72» where
  roots := #[`GkatK6R72]

lean_lib «GkatK6R73» where
  roots := #[`GkatK6R73]

lean_lib «GkatK6R74» where
  roots := #[`GkatK6R74]

lean_lib «GkatK6R75» where
  roots := #[`GkatK6R75]

lean_lib «GkatK6R76» where
  roots := #[`GkatK6R76]

lean_lib «GkatK6R77» where
  roots := #[`GkatK6R77]

lean_lib «GkatK6R78» where
  roots := #[`GkatK6R78]

lean_lib «GkatK6R79» where
  roots := #[`GkatK6R79]

lean_lib «GkatK6R80» where
  roots := #[`GkatK6R80]

-- Normal form: non-vacuity, and which constructor destroys which half.
lean_lib «GkatNormalProofs» where
  roots := #[`GkatNormalProofs]

lean_lib «GkatTotalizationProofs» where
  roots := #[`GkatTotalizationProofs]

-- Narrows the n=2 existence frontier: degenerate (tautologous / unsatisfiable) exit guards
-- are not genuinely two-exit, so existence holds there without LeftDistrib.
lean_lib «GkatExistenceNarrowProofs» where
  roots := #[`GkatExistenceNarrowProofs]

lean_lib «GkatW0Proofs» where
  roots := #[`GkatW0Proofs]

lean_lib «GkatSumQuotientProofs» where
  roots := #[`GkatSumQuotientProofs]

lean_lib «GkatGapWitnessProofs» where
  roots := #[`GkatGapWitnessProofs]

lean_lib «GkatElimProofs» where
  roots := #[`GkatElimProofs]

lean_lib «GkatCensusProofs» where
  roots := #[`GkatCensusProofs]

lean_lib «GkatGuardTransportProofs» where
  roots := #[`GkatGuardTransportProofs]
