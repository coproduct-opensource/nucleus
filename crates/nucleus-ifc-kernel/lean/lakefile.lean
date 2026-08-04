import Lake
open Lake DSL

-- Sorry-free lattice-soundness proofs for the IFC label kernel that the Rust
-- crate `nucleus-ifc-kernel` (`crates/nucleus-ifc-kernel/src/ifc_lattice.rs`) is
-- parity-pinned to: the `DerivationClass` join-semilattice (commutative,
-- associative, idempotent, bounded) plus its documented "no silent cleansing"
-- invariant, and the covariant `ConfLevel` chain (join = max) with its
-- least-element / upper-bound / monotonicity laws.
--
-- Mathlib-free: finite inductive enums + exhaustive `cases`/`rfl`/`decide`,
-- mirroring the discipline of `crates/ck-policy/lean` and
-- `crates/nucleus-rubric/lean`. No Mathlib, no native_decide, no
-- `sorry`/`admit`/`axiom`.
package «nucleusIfcKernel» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib «Ifc» where
  roots := #[`Ifc]
