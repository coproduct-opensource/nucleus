# Semantic IFC Research Plan

Discrete tasks for formalizing Levels 2-3 of the IFC hierarchy in Lean 4.
Each task is self-contained, testable, and builds on the previous.

## Phase 1: Infrastructure (Week 1)

### Task 1.1: Lean 4 project setup for nucleus-proofs
- [ ] Create `crates/portcullis-core/lean/SemanticIFC/` directory
- [ ] Add lakefile.lean with Mathlib dependency
- [ ] Import: `Mathlib.Order.GaloisConnection.Defs`, `Mathlib.CategoryTheory.Topos.Classifier`, `Mathlib.Order.Closure`
- [ ] Verify builds against current Mathlib4 master
- **Depends on:** nothing
- **Validates:** toolchain works

### Task 1.2: Define the Secret and Proposition types
- [ ] `Secret : Type` — the type of secrets (abstract, parameterized)
- [ ] `Proposition : Secret → Prop` — a predicate on secrets
- [ ] `AllowedKnowledge : Set (Secret → Prop)` — a set of allowed propositions
- [ ] Show `AllowedKnowledge` forms a `CompleteLattice` (it's `Set (Secret → Prop)`, which is `PowerSet`, which is a complete lattice via Mathlib's `Set.instCompleteLattice`)
- **Depends on:** 1.1
- **Validates:** `#check (inferInstance : CompleteLattice (Set (Secret → Prop)))`

### Task 1.3: Port IFCLabel to Lean 4 (lightweight model)
- [ ] Define `IntegLevel : Type` with `Adversarial | Untrusted | Trusted`
- [ ] Define `ConfLevel : Type` with `Public | Internal | Secret`
- [ ] Define `IFCLabel` as a product with `join` and `meet`
- [ ] Prove `IFCLabel` is a `Lattice` (using Mathlib's `Lattice` class)
- [ ] Or reuse the existing Aeneas-generated Lean code in `lean/generated/`
- **Depends on:** 1.1
- **Validates:** existing Lean infrastructure works for new proofs
- **Note:** We already have `IFCSemilatticeProofs.lean` — check if it can be extended

## Phase 2: Galois Connection on Propositions (Week 1-2)

### Task 2.1: Define the abstraction and concretization functions
- [ ] `α : Set Secret → Set (Secret → Prop)` — given a set of secrets, return propositions true of all of them
- [ ] `γ : Set (Secret → Prop) → Set Secret` — given a set of propositions, return all secrets satisfying them
- [ ] Formally: `α(S) = { p : Secret → Prop | ∀ s ∈ S, p s }` (propositions true of all elements)
- [ ] Formally: `γ(P) = { s : Secret | ∀ p ∈ P, p s }` (secrets satisfying all propositions)
- **Depends on:** 1.2
- **Validates:** definitions type-check

### Task 2.2: Prove the Galois connection
- [ ] Prove: `α(S) ⊆ P ↔ S ⊆ γ(P)` (the adjunction)
- [ ] Use Mathlib's `GaloisConnection` structure
- [ ] This should be a short proof — it's essentially `∀∃` quantifier shuffling
- **Depends on:** 2.1
- **Validates:** `#check (⟨α, γ, proof⟩ : GaloisConnection ...)`
- **Prior art:** This is a standard construction (the "Galois connection between a set and its predicates" appears in many lattice theory textbooks)

### Task 2.3: Derive the closure operator
- [ ] The composition `γ ∘ α : Set Secret → Set Secret` is a closure operator
- [ ] Use Mathlib's `GaloisConnection.closureOperator` to get this for free
- [ ] Prove: the closed sets are exactly the "proposition-definable" sets
- [ ] This means: a set S of secrets is closed iff it equals { s | ∀ p ∈ α(S), p(s) }
- **Depends on:** 2.2
- **Validates:** `GaloisConnection.closureOperator` produces a `ClosureOperator`

## Phase 3: Channel Model (Week 2)

### Task 3.1: Define the channel type
- [ ] `Channel (Secret : Type) (Output : Type) := Secret → Output`
- [ ] This is the deterministic channel model from QIF (Smith 2009)
- [ ] For LLM summarization: `Secret = TaintedContext`, `Output = String` (bounded by schema)
- **Depends on:** 1.2

### Task 3.2: Define the "learnable propositions" from a channel
- [ ] Given `f : Secret → Output`, the learnable propositions are:
- [ ] `learnable(f) = { p : Secret → Prop | ∃ g : Output → Prop, ∀ s, p(s) ↔ g(f(s)) }`
- [ ] Meaning: a proposition is learnable iff it can be computed from the output
- [ ] This is the kernel of the channel — propositions that factor through f
- **Depends on:** 3.1
- **Validates:** `learnable(f)` is a well-formed `Set (Secret → Prop)`

### Task 3.3: Prove learnable propositions form a sub-Heyting-algebra
- [ ] `learnable(f)` is closed under ∧, ∨, → (Heyting operations)
- [ ] This means the set of things the observer can learn has logical structure
- [ ] The observer can learn `p ∧ q` iff they can learn `p` and `q` independently
- **Depends on:** 3.2
- **Validates:** `#check (inferInstance : HeytingAlgebra (learnable f))` — or prove manually

## Phase 4: Soundness Theorem (Week 2-3)

### Task 4.1: Define schema-bounded channels
- [ ] `SchemaBoundedChannel` — a channel where the output type is restricted
- [ ] For `OutputSchema::Enumeration(values)`: output type is `Fin n`
- [ ] For `OutputSchema::MaxChars(n)`: output type is `{ s : String // s.length ≤ n }`
- [ ] For `OutputSchema::FreeText` with `max_tokens = k`: output type is `Fin (V^k)` where V = vocab size
- **Depends on:** 3.1

### Task 4.2: Prove the quantitative bound
- [ ] For a channel `f : Secret → Fin n`, `|learnable(f)| ≤ n` (at most n equivalence classes)
- [ ] This is the core QIF result: channel capacity bounds learnable propositions
- [ ] For `Enumeration(values)`: `|learnable(f)| ≤ |values|`
- [ ] For `MaxChars(k)`: `|learnable(f)| ≤ 256^k` (in practice, much less due to DPI)
- **Depends on:** 4.1, 3.2
- **Validates:** the quarantine compartment's schema actually bounds what's learnable

### Task 4.3: Prove the DPI filter reduces learnable propositions
- [ ] A DPI filter that rejects outputs matching pattern P effectively restricts the output space
- [ ] If the filter removes m of n possible outputs, `|learnable(f)| ≤ n - m`
- [ ] More precisely: `learnable(dpi ∘ f) ⊆ learnable(f)` (DPI can only remove learnability)
- **Depends on:** 4.2, 3.2
- **Validates:** DPI is monotone — adding filters never increases leakage

### Task 4.4: The Soundness Theorem
- [ ] **MAIN RESULT:** For a quarantine compartment with config C:
  `learnable(distill_C) ⊆ AllowedKnowledge(C)`
- [ ] Where `AllowedKnowledge(C)` is derived from the schema + DPI + token bound
- [ ] This says: the quarantine compartment provably restricts what the observer can learn to the allowed set
- **Depends on:** 4.2, 4.3, 2.2
- **Validates:** the entire quarantine architecture is sound

## Phase 5: Subobject Classifier (Week 3-4)

### Task 5.1: Define the category of IFC-safe computations
- [ ] Objects: types with IFC labels (`Labeled<T, I, C>`)
- [ ] Morphisms: functions that respect the flow relation
- [ ] Use Mathlib's `CategoryTheory.Category` class
- **Depends on:** 1.3
- **Note:** This is the category where we want to show the subobject classifier exists

### Task 5.2: Show AllowedKnowledge is a subobject classifier candidate
- [ ] The "truth morphism" `true : 1 → Ω` where `Ω = AllowedKnowledge`
- [ ] For every monic `m : U ↣ X` (subtype inclusion with label constraint), there exists a unique `χ : X → Ω` such that U = pullback of true along χ
- [ ] The characteristic map `χ` encodes "which propositions distinguish elements of U from elements of X \ U"
- **Depends on:** 5.1, 2.1
- **Note:** This is the hardest task. May require restricting to a subcategory.

### Task 5.3: Prove the subobject classifier axioms
- [ ] Use Mathlib's `CategoryTheory.HasClassifier`
- [ ] Show the pullback square commutes
- [ ] Show uniqueness of the characteristic morphism
- **Depends on:** 5.2
- **Validates:** `#check (inferInstance : HasClassifier (IFCSafeCategory Secret))`

## Phase 6: Quarantine as Morphism (Week 4)

### Task 6.1: Show the quarantine compartment is a morphism
- [ ] The quarantine compartment maps `Labeled<Context, Adversarial, Secret>` to `Labeled<Summary, Untrusted, Internal>`
- [ ] This is a morphism in the IFC-safe category iff the flow is within the allowed set
- [ ] Prove: the quarantine compartment, with its schema + DPI + token bound, satisfies the morphism condition
- **Depends on:** 5.1, 4.4
- **Validates:** the quarantine compartment is "a morphism in the topos of safe computations"

### Task 6.2: Show composition of quarantine compartments is a morphism
- [ ] Sequential distillation: `distill_1 ; distill_2`
- [ ] The composed leakage is bounded by the sum of individual leakages
- [ ] In the topos: composition of morphisms is a morphism (this is trivial once 6.1 is established)
- **Depends on:** 6.1
- **Validates:** sequential distillation composes correctly

## Dependencies Graph

```
1.1 → 1.2 → 2.1 → 2.2 → 2.3
1.1 → 1.3 → 5.1 → 5.2 → 5.3 → 6.1 → 6.2
1.2 → 3.1 → 3.2 → 3.3
3.1 → 4.1 → 4.2 → 4.4
3.2 → 4.3 → 4.4 → 6.1
2.2 → 4.4
```

Critical path: 1.1 → 1.2 → 2.1 → 2.2 → 3.1 → 3.2 → 4.1 → 4.2 → 4.4 → 6.1

## Prior Art to Port/Build On

- **Mathlib4 GaloisConnection**: `Mathlib.Order.GaloisConnection.Defs` — ready to use
- **Mathlib4 ClosureOperator**: `Mathlib.Order.Closure` — automatic from Galois connection
- **Mathlib4 Subobject Classifier**: `Mathlib.CategoryTheory.Topos.Classifier` — `HasClassifier`
- **b-mehta/topos**: Lean 3 formalization of elementary toposes — reference for Phase 5
- **esope/robustness_coq**: Coq formalization of robust declassification — port to Lean 4 for Phase 4
- **affeldt-aist/infotheo**: Coq information theory — reference for channel capacity bounds
- **Mahadevan 2025**: "Category of LLMs forms a topos" — cite for the LLM channel model
- **Folttmann thesis**: Internal language of a topos in Lean — reference for Phase 5-6
- **Existing nucleus Lean proofs**: `IFCSemilatticeProofs.lean`, `FlowProofs.lean` — extend for Phase 1.3

## Success Criteria

Phase 2 complete (Galois connection proved) = **publishable result** for agent security
Phase 4 complete (soundness theorem) = **the differentiator** vs Fides/Cedar
Phase 6 complete (topos morphism) = **the full theory** — unprecedented in this domain
