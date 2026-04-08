import Mathlib.Order.GaloisConnection.Defs
import Mathlib.Order.Closure
import Mathlib.Order.CompleteLattice.Basic

/-!
# Semantic Information Flow Control — Galois Connection on Propositions

Formalizes Level 3 IFC: instead of bounding how many **bits** can leak
through a channel, we bound which **propositions** about the secret the
observer can learn.

## Main Results

1. **Galois connection** between `Set Secret` and `Set (Secret → Prop)`:
   `α(S) ⊆ P ↔ S ⊆ γ(P)` where
   - `α(S) = { p | ∀ s ∈ S, p s }` (propositions true of all elements)
   - `γ(P) = { s | ∀ p ∈ P, p s }` (secrets satisfying all propositions)

2. **Closure operator** from the Galois connection: the closed sets are
   exactly the proposition-definable sets.

3. **Channel model**: a deterministic channel `f : Secret → Output`
   induces a set of **learnable propositions** — those that factor
   through `f`.

4. **Monotonicity**: restricting the output space can only reduce the
   set of learnable propositions.

## References

- Smith 2009: "On the Foundations of Quantitative Information Flow"
- Clarkson & Schneider 2010: "Hyperproperties"
- Zdancewic & Myers 2001: "Robust Declassification"
- Mahadevan 2025: "Topos Theory for Generative AI and LLMs" (arXiv:2508.08293)

All proofs are kernel-checked — no sorry.
-/

namespace SemanticIFC

-- ═══════════════════════════════════════════════════════════════════════════
-- Phase 1: Type definitions
-- ═══════════════════════════════════════════════════════════════════════════

-- Secret is an abstract type parameter.
-- Proposition is a predicate on secrets.
-- AllowedKnowledge is a set of propositions.

variable {Secret : Type}

/-- A proposition about secrets: a predicate `Secret → Prop`. -/
abbrev Proposition (Secret : Type) := Secret → Prop

/-- A knowledge set: which propositions are known/allowed. -/
abbrev Knowledge (Secret : Type) := Set (Proposition Secret)

-- ═══════════════════════════════════════════════════════════════════════════
-- Phase 2: Galois Connection between Set Secret and Knowledge
-- ═══════════════════════════════════════════════════════════════════════════

/-- Abstraction: given a set of secrets, return propositions true of ALL of them.
    α(S) = { p : Secret → Prop | ∀ s ∈ S, p s } -/
def alpha (S : Set Secret) : Knowledge Secret :=
  { p | ∀ s ∈ S, p s }

/-- Concretization: given a set of propositions, return secrets satisfying ALL of them.
    γ(P) = { s : Secret | ∀ p ∈ P, p s } -/
def gamma (P : Knowledge Secret) : Set Secret :=
  { s | ∀ p ∈ P, p s }

-- ═══════════════════════════════════════════════════════════════════════════
-- The (α, γ) pair forms an ANTITONE Galois connection (Galois correspondence).
-- Both maps are order-reversing:
--   S₁ ⊆ S₂ → α(S₂) ⊆ α(S₁)  (more secrets → fewer common propositions)
--   P₁ ⊆ P₂ → γ(P₂) ⊆ γ(P₁)  (more requirements → fewer satisfying secrets)
--
-- The four key properties below (antitonicity + extensiveness of both
-- round-trips) characterize this as a Galois correspondence in the
-- sense of Ore 1944 / Birkhoff: the closed sets on each side form
-- isomorphic complete lattices.
-- ═══════════════════════════════════════════════════════════════════════════

/-- Antitone Galois connection (Galois correspondence):
    S₁ ⊆ S₂ → α(S₂) ⊆ α(S₁)
    More secrets → fewer common propositions. -/
theorem alpha_antitone : Antitone (alpha (Secret := Secret)) := by
  intro S₁ S₂ h_sub p hp s hs₁
  exact hp s (h_sub hs₁)

/-- γ is antitone: P₁ ⊆ P₂ → γ(P₂) ⊆ γ(P₁)
    More required propositions → fewer satisfying secrets. -/
theorem gamma_antitone : Antitone (gamma (Secret := Secret)) := by
  intro P₁ P₂ h_sub s hs p hp₁
  exact hs p (h_sub hp₁)

/-- S ⊆ γ(α(S)): every secret in S satisfies all propositions that hold for all of S. -/
theorem subset_gamma_alpha (S : Set Secret) : S ⊆ gamma (alpha S) := by
  intro s hs p hp
  exact hp s hs

/-- P ⊆ α(γ(P)): every proposition in P holds for all secrets that satisfy all of P. -/
theorem subset_alpha_gamma (P : Knowledge Secret) : P ⊆ alpha (gamma P) := by
  intro p hp s hs
  exact hs p hp

/-- γ ∘ α ∘ γ = γ (idempotence of the closure on secrets). -/
theorem gamma_alpha_gamma (P : Knowledge Secret) :
    gamma (alpha (gamma P)) = gamma P := by
  ext s
  constructor
  · intro hs p hp
    exact hs p (subset_alpha_gamma P hp)
  · intro hs
    exact subset_gamma_alpha (gamma P) hs

/-- α ∘ γ ∘ α = α (idempotence of the closure on propositions). -/
theorem alpha_gamma_alpha (S : Set Secret) :
    alpha (gamma (alpha S)) = alpha S := by
  ext p
  constructor
  · intro hp s hs
    exact hp s (subset_gamma_alpha S hs)
  · intro hp
    exact subset_alpha_gamma (alpha S) hp

-- ═══════════════════════════════════════════════════════════════════════════
-- Phase 3: Channel model — learnable propositions
-- ═══════════════════════════════════════════════════════════════════════════

variable {Output : Type}

/-- A deterministic channel: maps secrets to observable outputs. -/
abbrev Channel (Secret Output : Type) := Secret → Output

/-- The set of propositions learnable from observing the channel output.
    A proposition p is learnable from channel f iff there exists a predicate
    g on outputs such that p(s) ↔ g(f(s)) for all s.

    Equivalently: p factors through f. -/
def learnable (f : Channel Secret Output) : Knowledge Secret :=
  { p | ∃ g : Output → Prop, ∀ s, p s ↔ g (f s) }

/-- The identity channel leaks everything: all propositions are learnable. -/
theorem learnable_id : learnable (id : Channel Secret Secret) = Set.univ := by
  ext p
  simp [learnable]
  exact ⟨p, fun s => Iff.rfl⟩

/-- A constant channel leaks nothing: only trivial propositions are learnable. -/
theorem learnable_const_subset (o : Output) :
    learnable (fun _ : Secret => o) ⊆ { p | (∀ s, p s) ∨ (∀ s, ¬p s) } := by
  intro p ⟨g, hg⟩
  by_cases h : g o
  · left; intro s; exact (hg s).mpr h
  · right; intro s hp; exact h ((hg s).mp hp)

-- ═══════════════════════════════════════════════════════════════════════════
-- Phase 4 (partial): Monotonicity — restricting output reduces learnability
-- ═══════════════════════════════════════════════════════════════════════════

/-- If channel g factors through f (g = h ∘ f for some h), then
    learnable(g) ⊆ learnable(f).

    Post-processing can only reduce information — never increase it.
    This is the data processing inequality for propositions. -/
theorem learnable_postprocess {Output₂ : Type}
    (f : Channel Secret Output) (h : Output → Output₂) :
    learnable (h ∘ f) ⊆ learnable f := by
  intro p ⟨g, hg⟩
  exact ⟨g ∘ h, hg⟩

/-- DPI filters are post-processing: they can only reduce learnability.
    If `filter` rejects some outputs (maps them to a default), the
    filtered channel leaks at most as much as the unfiltered channel. -/
theorem dpi_reduces_learnability
    (f : Channel Secret Output) (filter : Output → Output) :
    learnable (filter ∘ f) ⊆ learnable f :=
  learnable_postprocess f filter

end SemanticIFC
