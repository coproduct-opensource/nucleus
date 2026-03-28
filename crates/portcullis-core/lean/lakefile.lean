import Lake
open Lake DSL

package «portcullisCore» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

-- Aeneas standard library (provides Result monad, scalar types, etc.)
-- Pinned to the same commit used to generate PortcullisCore.lean
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "b2b5e3d" / "backends" / "lean"

-- Mathlib for HeytingAlgebra typeclass
-- Version must be compatible with Aeneas's Lean toolchain (v4.28.0-rc1)
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.28.0-rc1"

-- The Aeneas-generated Lean type definitions from portcullis-core Rust crate
-- (split-file mode: Types.lean has just the types, Funs.lean has implementations)
lean_lib «PortcullisCoreTypes» where
  roots := #[`Types]
  srcDir := "generated"

-- The HeytingAlgebra bridge proof
lean_lib «PortcullisCoreBridge» where
  roots := #[`PortcullisCoreBridge]
