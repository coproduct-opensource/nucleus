import Lake
open Lake DSL

-- The auction soundness proofs (truthfulness, Pigouvian welfare, credible
-- clearing, settlement decision, budget conservation) that `nucleus-econ-kernels`
-- is parity-pinned to. Mathlib-free: omega + structural recursion over µUSD Nat.
package «nucleus» where
  leanOptions := #[⟨`autoImplicit, false⟩]

-- Second-opinion axiom audit (#2567): `lake exe axiom-audit --root <Lib>` walks
-- every declaration under the root from the compiled oleans and fails on
-- sorryAx, native_decide's axiom or any home-rolled `axiom`. Dependency-free
-- (imports only `Lean`), so it builds under this toolchain. Driven by
-- scripts/lean-axiom-audit.sh, never called bare.
require «axiom-audit» from git
  "https://github.com/leanprover-community/axiom-audit" @ "v0.1.2"

@[default_target]
lean_lib «Nucleus» where
  roots := #[`Nucleus]
