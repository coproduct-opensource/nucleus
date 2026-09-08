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

-- Second-opinion axiom audit (#2567): `lake exe axiom-audit --root Ifc` walks
-- every declaration under the root from the compiled oleans and fails on
-- sorryAx, native_decide's axiom or any home-rolled `axiom`. Dependency-free
-- (imports only `Lean`), so it builds under this toolchain. Driven by
-- scripts/lean-axiom-audit.sh, never called bare.
require «axiom-audit» from git
  "https://github.com/leanprover-community/axiom-audit" @ "v0.1.2"

@[default_target]
lean_lib «Ifc» where
  roots := #[`Ifc]
