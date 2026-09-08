import Lake
open Lake DSL

-- The CI pipeline and merge queue as a Lean model: the invariants
-- `crates/ci-spec` DECIDES over the workflow tree (I1 twin completeness, I3
-- reported-and-not-skippable, the queue's accounting/order/cancel-safety)
-- are the HYPOTHESES here, and the properties the merge queue relies on are
-- the theorems. Mathlib-free: `Nat` + `List` + `Bool` + `decide` / `simp` +
-- structural induction, the discipline of `crates/ck-policy/lean`. No
-- Mathlib, no native_decide, no `sorry`/`admit`.
--
-- `CiSpecBite` is the guarded/unguarded differential: each theorem there
-- drops ONE hypothesis of a `CiSpec` theorem and proves the failure is
-- reachable (the 2026-09-05 defects, as machine-checked counterexamples).
-- It imports `CiSpec` and defines nothing — scripts/check-ci-spec-bite.sh
-- asserts that, so the bite cannot quietly become a different model.
package «ciSpec» where
  leanOptions := #[⟨`autoImplicit, false⟩]

-- Second-opinion axiom audit (#2567): `lake exe axiom-audit --root CiSpec`
-- walks every declaration under the namespace from the compiled oleans and
-- fails on sorryAx, Lean.ofReduceBool (native_decide) or any home-rolled
-- `axiom`. Driven by scripts/lean-axiom-audit.sh, never called bare.
require «axiom-audit» from git
  "https://github.com/leanprover-community/axiom-audit" @ "v0.1.2"

@[default_target]
lean_lib «CiSpec» where
  roots := #[`CiSpec]

lean_lib «CiSpecBite» where
  roots := #[`CiSpecBite]
