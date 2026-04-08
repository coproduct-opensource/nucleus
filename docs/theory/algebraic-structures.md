# Algebraic Structures in Nucleus

The `portcullis_core::category` module provides a unified trait hierarchy
for all lattice types in the system. This document maps the mathematical
structures to their Rust implementations and verification status.

## Trait Hierarchy

```text
Lattice                         meet, join, leq
  │
  ├── BoundedLattice            top, bottom
  │     │
  │     └── CompleteLattice     meet_all, join_all (blanket impl)
  │           │
  │           └── Frame         (+ DistributiveLattice)
  │                 │
  │                 └── Nucleus  apply, is_fixed_point
  │
  ├── ProductLattice<A, B>      pointwise meet/join
  │
  └── MonotoneMap<A, B>         a ≤ b ⟹ f(a) ≤ f(b)
        │
        └── JoinPreserving      f(a ∨ b) = f(a) ∨ f(b)
```

## Types Implementing Lattice

### portcullis-core (8 types)

| Type | Structure | Bounded | Verified |
|------|-----------|---------|----------|
| `CapabilityLevel` | 3-element chain | Yes | Lean + Kani |
| `CapabilityLattice` | 13-dim product of chains | Yes | Lean (Heyting algebra) |
| `ConfLevel` | 3-element chain (covariant) | Yes | Lean |
| `IntegLevel` | 3-element chain (contravariant) | Yes | Lean |
| `AuthorityLevel` | 4-element chain (contravariant) | Yes | Lean |
| `DerivationClass` | 5-element lattice with diamond | Yes | Lean |
| `Freshness` | 2D product (observed_at × ttl) | Yes | Tests |
| `IFCLabel` | 6-dim product (mixed variance) | No* | Lean + Kani |

\* `IFCLabel::bottom()` uses `Freshness { observed_at: u64::MAX, ttl_secs: 0 }`
(newest observation, no expiry). `BoundedLattice` awaits the merge of the
`Freshness::leq` fix (#1386).

### portcullis (12 types)

| Type | Structure | Bounded | Notes |
|------|-----------|---------|-------|
| `PermissionLattice` | 7-dim product + nucleus constraint | Yes | Frame |
| `CapabilityLattice` | 13-dim + extensions | Yes | Heyting algebra |
| `BudgetLattice` | 3-dim product (cost × tokens) | — | |
| `CommandLattice` | Allowlist/blocklist pair | — | |
| `PathLattice` | Allowlist/blocklist pair | — | |
| `TimeLattice` | Interval (valid_from, valid_until) | — | |
| `ProgressLattice` | 6-dim product of 5-element chains | Yes | Frame |
| `WorkIntent` | Structured work description | Yes | |
| `IsolationLattice` | 4-element chain | Yes | |
| `CodeRegion` | Source location lattice | Yes | |
| `Verdict` | Belnap bilattice (truth axis) | Yes | |
| `FlowState` | Wrapper over IFCLabel | — | |

### Generic

| Type | Structure | Bounded |
|------|-----------|---------|
| `ProductLattice<A, B>` | Pointwise product | Yes (if both bounded) |

## Key Properties

### Monotonicity (tested via `verify_monotone`)

| Transformation | Domain → Codomain | Property |
|---------------|-------------------|----------|
| `join(_, taint)` | IFCLabel → IFCLabel | Monotone + join-preserving |
| `meet(_, ceiling)` | CapabilityLevel → CapabilityLevel | Monotone (delegation narrowing) |
| `UninhabitableQuotient::apply` | PermissionLattice → PermissionLattice | Deflationary + idempotent |

### Lattice Laws (tested via `verify_lattice_laws`)

All 20 types pass the generic lattice law tests:
- **Commutativity**: `a ∧ b = b ∧ a`, `a ∨ b = b ∨ a`
- **Associativity**: `(a ∧ b) ∧ c = a ∧ (b ∧ c)`
- **Idempotence**: `a ∧ a = a`, `a ∨ a = a`
- **Absorption**: `a ∧ (a ∨ b) = a`
- **leq consistency**: `a ≤ b ⟺ a ∧ b = a`

Bounded types additionally pass:
- **Top identity**: `a ∧ ⊤ = a`
- **Bottom identity**: `a ∨ ⊥ = a`
- **Top annihilator**: `a ∨ ⊤ = ⊤`
- **Bottom annihilator**: `a ∧ ⊥ = ⊥`

## The Nucleus Operator

The uninhabitable-state constraint is a **kernel operator** (deflationary +
idempotent) on `PermissionLattice`, not a full frame-theoretic nucleus
(it does NOT preserve meets — Verus proof: `proof_nucleus_not_meet_preserving`).

```text
UninhabitableQuotient::apply : PermissionLattice → PermissionLattice

Properties:
  j(j(x)) = j(x)         (idempotent)     — verified
  j(x) ≤ x               (deflationary)   — verified
  j(x ∧ y) ≠ j(x) ∧ j(y) (NOT meet-preserving) — counterexample proven
```

Fixed points are closed under the **quotient meet** (`PermissionLattice::meet`
re-normalizes internally), not the raw lattice meet.

## Combinators

```rust
use portcullis_core::category::{meet_all_bounded, join_all_bounded, ProductLattice};

// Fold any bounded lattice
let min_cap = meet_all_bounded(capability_levels); // top() for empty

// Product lattice — pointwise operations
let pair = ProductLattice(ConfLevel::Secret, IntegLevel::Trusted);
```

## Relationship to Formal Proofs

| Algebraic Structure | Trait | Lean | Kani | Verus |
|--------------------|----|------|------|-------|
| IFC semilattice | `Lattice for IFCLabel` | 19 theorems | — | — |
| Capability Heyting algebra | `Lattice for CapabilityLattice` | 23 theorems | 26 harnesses | — |
| Exposure monoid | — (not a lattice) | 16 theorems | — | — |
| Nucleus operator | `Nucleus<PermissionLattice>` | — | — | 297 VCs |
| Monotone maps | `MonotoneMap<A, B>` | `join_monotone_left` | `proof_derivation_join_monotone` | — |
