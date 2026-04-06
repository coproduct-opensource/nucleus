# Theoretical Foundations

Formal structures underlying the nucleus security kernel. Each document
describes the mathematical framework, its implementation in Rust, and
its verification status (Lean proofs, Kani BMC, or unit tests).

## Documents

- [IFC Semilattice](ifc-semilattice.md) — The `IFCLabel` join operation as a
  product semilattice with mixed variance. Covariant confidentiality (Bell-LaPadula),
  contravariant integrity (Biba), and the absorption properties that make
  contamination permanent. Label propagation as a functor from the flow graph
  to the label lattice.

- [Belnap Bilattice](belnap-bilattice.md) — Four-valued policy logic with
  independent truth and knowledge orderings. De Morgan duality between meet/join.
  How AllOf, AnyOf, Not, and FirstMatch combinators map to bilattice operations.
  The Conflict value as RequiresApproval.

- [Heyting Algebra](heyting-algebra.md) — The `CapabilityLattice` as a product
  of 13 bounded chains. The implication operation (a → b), the currying adjunction
  (meet ⊣ implies), pseudo-complement, and why 3-valued permissions require
  Heyting rather than Boolean algebra.

- [Labeled Type System](labeled-types.md) — `Labeled<T, I, C>` as an endofunctor
  with phantom type parameters encoding IFC. Subtyping via trait bounds
  (`IntegAtLeast`, `ConfAtMost`). The Galois connection between compile-time
  tags and runtime labels. Declassification as a gated natural transformation.

- [Discharge Witnesses](discharge-witnesses.md) — `Discharged<O>` as a linear
  proof token. The sealing pattern as a provability predicate encoding. The
  monoidal structure of obligations (commutative, idempotent tensor product).

- [Repair Algebra](repair-algebra.md) — Policy denial as program rewriting.
  Retraction (idempotent per-check repair), Galois connection between the
  obligation lattice and the admissible term powerset, and the free-forgetful
  adjunction between raw and checked ActionTerms.

## The Categorical Stack

The structures compose in layers:

```
                    Repair Algebra
                   (Galois connection, adjunction)
                          │
                   ┌──────┴──────┐
                   │             │
            Discharge        Labeled Types
         (linear proofs)   (phantom functor)
                   │             │
                   └──────┬──────┘
                          │
                  ┌───────┴───────┐
                  │               │
           IFC Semilattice    Heyting Algebra
          (label propagation)  (permissions)
                  │               │
                  └───────┬───────┘
                          │
                   Belnap Bilattice
                  (policy verdicts)
```

The bilattice is the foundation — it defines the verdict algebra. The IFC
semilattice and Heyting algebra build on it to track data flow and permissions.
Discharge witnesses and labeled types provide structural enforcement (linear
proofs and compile-time tags). The repair algebra sits at the top, consuming
all other structures to transform denials into admissible actions.
