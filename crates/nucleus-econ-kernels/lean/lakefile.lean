import Lake
open Lake DSL

-- The auction soundness proofs (truthfulness, Pigouvian welfare, credible
-- clearing, settlement decision, budget conservation) that `nucleus-econ-kernels`
-- is parity-pinned to. Mathlib-free: omega + structural recursion over µUSD Nat.
package «nucleus» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib «Nucleus» where
  roots := #[`Nucleus]
