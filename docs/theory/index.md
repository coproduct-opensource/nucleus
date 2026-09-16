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

- [GKAT's fixed point](gkat-fixed-point.md) — Why the guarded fragment, what
  the `while` axiom costs (unique fixed point + guardedness, completeness open),
  and the bridge to the least-fixed-point exposure ratchet
  (`GkatGuardedLoopBridge.lean`). Every `Gkat*.lean` file is in the proven
  tier — on the `lake build` list of
  `.github/workflows/portcullis-core-proven-lean.yml`, on no research-tier
  allowlist, and so under the `sorry` ban.

- [GKAT inexpressibility](gkat-inexpressibility-plan.md) — Research plan for the
  first machine-checked "no GKAT expression denotes `L`" result, via the nesting
  coequation `W`. Milestone 1 landed; 2–5 open. Sections are appended in
  discovery order, so the later ones supersede the earlier "honest assessment".

## Implemented (not yet documented)

- **IFC Semilattice** — `IFCLabel`'s join as a bounded semilattice with
  covariant (confidentiality, provenance) and contravariant (integrity,
  authority) dimensions. Proved in `IFCSemilatticeProofs.lean`; implements
  `Lattice`. This list linked `ifc-semilattice.md` for as long as it has
  existed, and that file has never been written — a dead link in a list whose
  purpose is to say what is documented.

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
