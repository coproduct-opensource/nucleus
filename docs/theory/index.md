# Theoretical Foundations

Formal structures underlying the nucleus security kernel. Each document
describes the mathematical framework, its implementation in Rust, and
its verification status (Lean proofs, Kani BMC, or unit tests).

## Documents

- [Algebraic Structures](algebraic-structures.md) — Unified `Lattice` trait
  hierarchy: 20 types, `ProductLattice`, `MonotoneMap`, generic verification
  harnesses, and the relationship between Rust traits and formal proofs.

- [Repair Algebra](repair-algebra.md) — Policy denial as program rewriting:
  retraction, Galois connection, and free-forgetful adjunction between raw
  and checked ActionTerms.

- [IFC Semilattice](ifc-semilattice.md) — The `IFCLabel` join operation as
  a bounded semilattice with covariant (confidentiality, provenance) and
  contravariant (integrity, authority) dimensions. Lean proofs in
  `IFCSemilatticeProofs.lean`. Implements `Lattice` trait.

## Implemented (not yet documented)

- **Belnap Bilattice** — `Verdict` in `bilattice.rs`. Four-valued policy
  logic with truth and knowledge orderings. Implements `Lattice` (truth axis)
  and `BoundedLattice`. De Morgan duality verified by unit tests.

- **Heyting Algebra** — `CapabilityLattice` in `heyting.rs`. 13-dimensional
  product of bounded chains. Implements `Lattice`, `BoundedLattice`,
  `DistributiveLattice`, `HeytingAlgebra`. Adjunction verified by Kani.

- **Labeled Type System** — `Labeled<T, I, C>` in `labeled.rs`. Compile-time
  IFC via phantom types. `IntegAtLeast<Floor>` and `ConfAtMost<Ceiling>` as
  subtyping constraints.

- **Discharge Witnesses** — `Discharged<O>` in `discharge.rs`. Linear proof
  tokens with private `Seal` field. `RepairHint` for automated self-repair.

- **Galois Connections** — `TrustDomainBridge` in `galois.rs`. Principled
  trust domain translation with adjunction verification.
