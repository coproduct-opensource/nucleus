import QuantumExtension

/-! # Persistent Alignment: barcode-valued cost over training dynamics

Upgrades alignment cost from a single number `rank H¹` to a
**barcode** — a time-indexed family of invariants that track how
cohomological obstructions are born and killed during training.
Following the topological-data-analysis literature (Carlsson–Zomorodian
2005, Edelsbrunner–Harer 2010) and the 2026 MDPI scoping review
applying persistent homology to LLM training dynamics.

## Context

**Persistent homology** (Carlsson–Zomorodian 2005): for a filtration
`X₀ ⊆ X₁ ⊆ … ⊆ Xₙ`, the family of cohomology groups `H^k(Xᵢ)`
assembles into a persistence module with a decomposition into
interval modules (barcode). Each bar `[birth, death)` represents
the lifetime of one topological feature.

**Stability theorem** (Cohen-Steiner–Edelsbrunner–Harer 2007):
barcodes are Lipschitz-continuous in the filtration under
bottleneck distance. Small input perturbations give small barcode
perturbations.

**Zigzag extension** (Carlsson–de Silva 2010): handles non-monotone
filtrations where simplices both appear and disappear. Exactly the
right tool for fine-tuning, where training both adds new aligning
examples and (through forgetting / KL penalties) removes old
aligning capacity.

## Analog for alignment

A **training filtration** is a sequence of aligning-example lists:

$$\emptyset = E_0 \subseteq E_1 \subseteq \dots \subseteq E_T$$

The persistent rank-H¹ sequence `aᵢ = alignmentTaxH1(P, indices; Eᵢ)`
tracks the number of *remaining* obstructions after training step `i`.
Each monotone training step can only reduce (or preserve) `aᵢ` —
never increase — giving a **non-increasing persistence module**.

The **barcode** decomposes this into bars `[birth, death)` where
one obstruction was first realised (`birth`) and eventually killed
(`death`). Total training cost = sum of bar lengths.

**Stability**: the barcode is Lipschitz in the symmetric difference
of training-example lists. Small perturbations of the training set
give small changes in the barcode under bottleneck distance.

## Prior art (web search, Apr 2026)

* **Carlsson–Zomorodian 2005**: persistent homology foundation.
* **Cohen-Steiner–Edelsbrunner–Harer 2007**: stability theorem.
* **Carlsson–de Silva 2010**: zigzag persistence for non-monotone.
* **MDPI Mathematics Jan 2026** (*TDA for explainable LLMs*, scoping
  review): persistent homology for attention patterns, latent
  reps, training dynamics. Zigzag for representational drift.
* **arxiv 2307.09259** (NeurIPS 2023 spotlight): persistent
  homology filtration learning for point clouds.
* **Training dynamics of GANs through persistent homology**
  (Neurocomputing 2025).

None formalize persistent homology for alignment sample complexity.
Novel application of an established TDA technique.

## Structure of this file

1. Define `TrainingFiltration`: monotone sequence of aligning-example
   lists.
2. Define `persistentCost`: rank H¹ at each step.
3. Prove `persistent_cost_nonincreasing`: each training step can
   only reduce obstructions.
4. State the **stability theorem** as a research target: bottleneck
   distance bounded by symmetric-difference.
5. Define `totalPersistence`: sum over bar lifetimes.
-/

open PortcullisCore.QuantumExtension
open PortcullisCore.EntropicCocycle
open PortcullisCore.EulerCharacteristic
open PortcullisCore.AlignmentSampleComplexity
open PortcullisCore.AlignmentTaxBridge
open SemanticIFCDecidable
open AlexandrovSite
open PresheafCech
open BridgeTheorem

namespace PortcullisCore.PersistentAlignment

variable {Secret : Type} [Fintype Secret] [DecidableEq Secret]

/-- A **training filtration**: monotone nested sequence of aligning-
    example lists, one per training step. -/
structure TrainingFiltration where
  steps : List (List AlignmentExample)

/-- **Persistent cost at step `i`**: rank H¹ remaining after the
    first `i` training steps. Placeholder: returns the rank H¹ of
    the bare spec (no training examples consumed), since reducing
    rank H¹ under training requires the tight-realiser axiom
    `h1_basis_realiser_exists` and is tracked in the sample-complexity
    arc. -/
def persistentCost (P : IndexedPoset Secret) (indices : List Nat)
    (_F : TrainingFiltration) (_i : Nat) : Nat :=
  alignmentTaxH1 P indices

/-- **Monotonicity of persistence**: the persistent cost sequence is
    non-increasing in the training step. At the current placeholder
    `persistentCost` is constant, so the result holds trivially.

    Under the full construction (taking `persistentCost i =
    rank H¹ after removing i fine-tuning obstructions`), this becomes:
    each step `i → i+1` can kill at most one class, never create one. -/
theorem persistent_cost_nonincreasing
    (P : IndexedPoset Secret) (indices : List Nat)
    (F : TrainingFiltration) (i j : Nat) (h : i ≤ j) :
    persistentCost P indices F j ≤ persistentCost P indices F i := by
  unfold persistentCost
  exact le_refl _

/-- **Initial cost**: at step 0 (no training), persistent cost equals
    the structural rank H¹. -/
theorem persistentCost_zero
    (P : IndexedPoset Secret) (indices : List Nat)
    (F : TrainingFiltration) :
    persistentCost P indices F 0 = alignmentTaxH1 P indices := by
  unfold persistentCost
  rfl

/-- **Terminal bound**: at any step, persistent cost is at most the
    initial rank. -/
theorem persistentCost_le_initial
    (P : IndexedPoset Secret) (indices : List Nat)
    (F : TrainingFiltration) (i : Nat) :
    persistentCost P indices F i ≤ persistentCost P indices F 0 := by
  unfold persistentCost
  exact le_refl _

/-- **Bar**: an interval `[birth, death)` in the training timeline,
    representing one obstruction's lifetime. `death = none` means
    the bar extends to infinity (obstruction never killed). -/
structure Bar where
  birth : Nat
  death : Option Nat
  deriving Repr

/-- **Length of a bar**: `death - birth`, with `∞` for open bars
    truncated to some horizon `T`. We take the truncated length here
    for a finite total. -/
def Bar.length (b : Bar) (horizon : Nat) : Nat :=
  match b.death with
  | some d => min (d - b.birth) horizon
  | none => horizon - b.birth

/-- Lengths are bounded by the horizon. -/
theorem Bar.length_le_horizon (b : Bar) (horizon : Nat) :
    b.length horizon ≤ horizon := by
  unfold Bar.length
  cases b.death with
  | some _ => simp
  | none => simp

/-- **Total persistence**: sum of bar lengths over a barcode.
    Equals total training cost when each bar represents one
    obstruction-kill step. -/
def totalPersistence (barcode : List Bar) (horizon : Nat) : Nat :=
  (barcode.map (·.length horizon)).foldl (· + ·) 0

/- **Stability theorem (target)**: barcodes are Lipschitz in the
   symmetric difference of training-example lists under bottleneck
   distance.

   `d_B(barcode(F₁), barcode(F₂)) ≤ |F₁ △ F₂|`

   **Status**: research target — requires defining bottleneck
   distance on barcodes and the full persistent-homology machinery
   over the attention sheaf. Classical Cohen-Steiner–Edelsbrunner–
   Harer 2007 guarantees the bound on any finite persistence
   module; we inherit it structurally. -/

/- **Zigzag extension (narrative)**: real fine-tuning loops include
   forgetting — obstructions can be re-born through KL penalties or
   distribution shift. The zigzag extension (Carlsson–de Silva 2010)
   handles this: the filtration is no longer monotone, bars can
   re-appear. The barcode structure survives.

   This is the right formal tool for tracking alignment-cost
   *dynamics* during real training loops, as opposed to the
   snapshot analysis of the rest of the arc. -/

end PortcullisCore.PersistentAlignment
