# Research-tier conjectures — NOT proven theorems

This file is the **authoritative manifest** that separates the two tiers of the
`portcullis-core` Lean tree. It exists because *overclaiming a non-proof is an
attack surface*: a reader (or auditor, or downstream doc) must never mistake an
open conjecture for a kernel-checked theorem.

It is also a **CI contract**. The gate
`.github/workflows/portcullis-core-proven-lean.yml` asserts that **every `.lean`
file containing a proof-hole (`sorry` / `admit`) is listed in the
`RESEARCH-TIER` table below**. If a *proven* file ever silently acquires a
`sorry`, the gate fails — a real proof cannot regress unnoticed, and a research
hole cannot be smuggled out of quarantine.

> Last reconciled: 2026-06-28. Authoritative counts (comment-stripped):
> **34 proof-hole `sorry` terms across exactly 10 files**, zero elsewhere in the tree.
> (2026-06-28: `MatrixBridge` discharged in full — 6 holes → 0 — and promoted
> research → proven; removed from the allowlist below and added to Tier 1.)

---

## Tier 1 — PROVEN (kernel-checked, `sorry`-free)

These libraries are discharged by the Lean 4 kernel with no proof holes. They
are the enforcement / lattice / IFC / algebra core and the Aeneas-bridged
extracted Rust core. The CI gate builds them and bans `sorry` / `admit` /
`sorryAx`.

| Library | Subject |
|---|---|
| `PortcullisCoreBridge` | HeytingAlgebra bridge + Aeneas fn correspondence |
| `PortcullisCoreIFC` + `IntegrityNoninterferenceExtracted` | noninterference over Aeneas-extracted Rust IFC core (clean axiom set asserted) |
| `ExposureProofs` | exposure-tracker monoid + gating |
| `FlowProofs` | IFC label lattice / flow kernel |
| `FlowGraphProofs` | causal-DAG label propagation (†) |
| `DeclassifyProofs` | declassification rule safety |
| `DecidePureProofs` | `decide_pure()` decision-logic correctness |
| `CompartmentProofs` | compartment-ceiling ordering |
| `DelegationProofs` | delegation narrowing / attenuation |
| `DerivationProofs` | DerivationClass DPI invariants |
| `IFCSemilatticeProofs` | ConfLevel / IntegLevel / IFCLabel2 instances |
| `DelegationCategoryProofs`, `GaloisConnectionProofs` | categorical / Galois structure |
| `AttenuationProofs`, `MonoidalPermissionProofs` | attenuation algebra + permission monoid |
| `SemanticIFC` | Galois connection on propositions, channel soundness |
| `ConstructiveSecurity` | Maurer constructive-crypto composition (Mathlib-free) |
| `WasiWorldFunctor`, `WasiIfcBoundary` | capability→WASI lattice homomorphism + boundary-monitor soundness |
| `BelnapDecisionProofs`, `RepairAlgebraProofs` | Belnap bilattice, repair algebra (newly registered build targets, verified to compile) |
| `MatrixBridge` | `gaussRankBool` (algorithmic GF(2) Gaussian elimination) ↔ `Matrix.rank`; Gaussian-elimination correctness + GF(2) rank subadditivity (discharged 2026-06-28, `#print axioms` = propext/Classical.choice/Quot.sound) |

**(†) Disclosed TCB note:** `FlowGraphProofs.lean` (lines 130/144/158),
`CechCohomology.lean`, and the native-decide research libs below use the
`native_decide` tactic, which adds the `Lean.ofReduceBool` axiom and trusts the
**native compiler**, i.e. it is *outside the pure Lean kernel*. These are
`sorry`-free but not pure-kernel-checked. The gate **discloses** `native_decide`
via a `#print axioms` audit rather than hard-banning it (the Mathlib-free
sibling trees — `ck-policy`, `nucleus-rubric`, `nucleus-econ-kernels` — do ban
it; `portcullis-core` cannot because it is load-bearing in `FlowGraphProofs`).

---

## Tier 2 — RESEARCH (CONJECTURE — open proof holes)

**These results are NOT proven.** Do not cite any theorem in these files as
"proven", "kernel-checked", or "formally verified". They are the
alignment-tax / Čech-cohomology / braid-group research cluster. Each file
carries a `CONJECTURE` banner at its head.

| Library | Open `sorry` | What is conjectured (and where the hole is) |
|---|---:|---|
| `SemanticIFCDecidable` | 13 | Float `BEq` lacks `LawfulBEq`; neighbor-transitivity, foldl/countP, BFS class-rep lemmas |
| `ComparisonTheorem` | 7 | Čech ≅ Topos for finite Alexandrov posets (Laudal/Oberst; 2 are native_decide-timeout fallbacks, "Python-verified") |
| `AlignmentTaxBridge` | 5 | `operationalTax = rank H¹` (the central alignment-tax conjecture) |
| `RankNullity` | 1 | GF(2) rank subadditivity — foundation for the whole alignment-tax chain |
| `SimplexAcyclic` | 1 | cone construction ⇒ H¹ = 0 |
| `MultiAgentCohomology` | 1 | IFC sheaf lift to communication graphs |
| `HigherObstruction` | 1 | H² / spectral-sequence analog |
| `CompositionalAlignment` | 1 | Mayer-Vietoris-analog for spec composition |
| `UniversalityTheorem` | 2 | rank H¹ as a complete invariant |
| `PACVCBridge` | 2 | PAC / VC-dimension equivalence |
| **Total** | **34** | across **10** files |

**Machine-readable allowlist** (the CI gate parses exactly the lines between the
markers below — these are the only files permitted to contain a proof hole):

<!-- GATE-ALLOWLIST:BEGIN -->
```
SemanticIFCDecidable
ComparisonTheorem
AlignmentTaxBridge
RankNullity
SimplexAcyclic
MultiAgentCohomology
HigherObstruction
CompositionalAlignment
UniversalityTheorem
PACVCBridge
```
<!-- GATE-ALLOWLIST:END -->

### Tier 2b — CONJECTURE by computation (`sorry`-free, but native_decide / scaffold)

These have no `sorry`, so they pass the build, but they are **research-tier by
subject**: concrete cohomology / braid values asserted via `native_decide`
(native-compiler trust, see the TCB note above) or abstract scaffolds. They are
**not** part of the proven enforcement core and must not be cited as verified
security guarantees.

`CechCohomology`, `AlignmentTaxConcrete`, `AugmentedBorromean`,
`AugmentedBorromeanActions`, `AugmentedBorromeanTheorems`, `BraidObstruction`,
`BraidEmpirical`, `BraidCohomology`, `BraidAnalysis`, `DiamondActions`,
`RealWorldActions`, `UniversalDetection`, `EulerCharacteristic`,
`LipschitzEquivariance`, `EntropicCocycle`, `QuantumExtension`,
`PersistentAlignment`, `AlignmentSampleComplexity`.

---

## Tier 3 — STALE (does NOT currently compile — needs repair)

Surfaced 2026-06-21 when the proven-tier gate first attempted to build the full
core. These files claim to be "kernel-checked, sorry-free" in their own headers,
but they do **not** compile against the pinned toolchain (`v4.30.0-rc2` +
Mathlib `v4.30.0-rc2`). They were ungated/orphaned and silently rotted. **Do not
cite their theorems as proven until repaired.** They are excluded from the
proven build list in `portcullis-core-proven-lean.yml`.

| File | Failure | Likely cause |
|---|---|---|
| `CategoryProofs.lean` | `failed to synthesize Min CapabilityLevel` at line 109 (`a ⊔ (b ⊓ c) = …`) | Mathlib `Inf`→`Min` / `Sup`→`Max` order refactor; the lattice instance no longer exposes `Min`/`Max` for `decide` |
| `LabeledTypeProofs.lean` | ~48 `Unknown identifier T/U/I/C` errors | declarations use auto-implicit type vars (`T U : Type`, `I : IntegTag`, `C : ConfTag`) but the package sets `autoImplicit := false`; file was never compiled under the current config. Fix: add explicit `{T U : Type} {I : IntegTag} {C : ConfTag}` binders |

When repaired: re-add `LabeledTypeProofs` as a `lean_lib` in `lakefile.lean`,
add both back to the build list in the gate, and delete this section.

---

## How the gate uses this file

The CI step parses the `RESEARCH-TIER` table (the backticked library names in
the "Tier 2" table only) into an allowlist of files permitted to contain
`sorry`. It then greps the whole tree for proof-hole `sorry` / `admit`. Any hit
in a file **not** on the allowlist fails the build. Adding a new proven file is
free (it just must stay hole-free); discharging a research hole is free (delete
the row). The only thing that fails is silent regression.
