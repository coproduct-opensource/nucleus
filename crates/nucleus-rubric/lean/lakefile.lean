import Lake
open Lake DSL

-- The cardinal-scoring soundness proofs (faithful inertness, total preorder,
-- RV-grade monotonicity, scalarized-winner Pareto-optimality) that
-- `nucleus-rubric` is parity-pinned to. Mathlib-free: `Nat` + `omega` +
-- structural recursion / list induction, mirroring `nucleus-econ-kernels/lean`.
package «nucleusRubric» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib «Nucleus» where
  roots := #[`Nucleus]
