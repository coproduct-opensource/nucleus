# Theoretical Foundations

Formal structures underlying the nucleus security kernel. Each document
describes the mathematical framework, its implementation in Rust, and
its verification status (Lean proofs, Kani BMC, or unit tests).

## Documents

- [Repair Algebra](repair-algebra.md) — Policy denial as program rewriting:
  retraction, Galois connection, and free-forgetful adjunction between raw
  and checked ActionTerms.

## Planned

- **IFC Semilattice** — The `IFCLabel` join operation as a bounded semilattice
  with covariant (confidentiality, provenance) and contravariant (integrity,
  authority) dimensions. Lean proofs in `IFCSemilatticeProofs.lean`.

- **Belnap Bilattice** — Four-valued policy logic (Allow, Deny, Unknown,
  Conflict) with truth and knowledge orderings. De Morgan duality between
  `truth_meet`/`truth_join` and `knowledge_meet`/`knowledge_join`.

- **Heyting Algebra** — The `CapabilityLattice` as a product of 13 bounded
  chains. Distributivity, implication (a → b = max{c | c ∧ a ≤ b}), and
  pseudo-complement. Kani proofs of the adjunction property.

- **Labeled Type System** — `Labeled<T, I, C>` as a compile-time approximation
  of the runtime IFC semilattice. `IntegAtLeast<Floor>` and `ConfAtMost<Ceiling>`
  as subtyping constraints encoded via trait bounds.

- **Discharge Witnesses** — `Discharged<O>` as a linear proof token. The sealing
  pattern (private `Seal` field) as an encoding of the "only the prover can
  mint proofs" axiom.
