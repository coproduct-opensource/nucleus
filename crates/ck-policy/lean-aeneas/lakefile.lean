import Lake
open Lake DSL

-- Constitutional Kernel monotonicity-gate CORE — tier-1 deductive bridge.
--
-- This package proves the SOUNDNESS of the Aeneas-EXTRACTED core
-- (`generated/Funs.lean`, produced by Charon+Aeneas from
-- `crates/ck-policy/src/extracted.rs`) — NOT a hand-written model. The proofs in
-- `CkPolicyAeneas.lean` reason about the GENERATED `extracted.passed_core`,
-- `extracted.subset_u32`, `extracted.budget_within`, `extracted.rules_non_weakening`.
--
-- # Mathlib posture (HONEST)
--
-- The Aeneas Lean *standard library* (`require aeneas`, providing `Result`,
-- `Std.U32`, `Slice`, `Array`, the `loop` combinator the generated code uses)
-- itself `require`s Mathlib at this pinned commit. So importing the generated
-- `Funs.lean` transitively depends on Mathlib — UNAVOIDABLE; identical posture to
-- the `crates/portcullis-core/lean` Aeneas precedent.
--
-- "Mathlib-free" here is therefore a PROOF-DISCIPLINE claim, not a dependency
-- claim: `CkPolicyAeneas.lean` uses only `simp`/`omega`/`decide`/structural
-- reasoning + the Aeneas Std lemmas — NO Mathlib lemmas, NO `native_decide`, NO
-- `sorry`/`admit`. The hand-written model package next door
-- (`crates/ck-policy/lean`) remains fully Mathlib-free (no Aeneas dep at all).
package «ckPolicyAeneas» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`maxHeartbeats, (1000000 : Nat)⟩
  ]

-- Aeneas standard library (Result monad, scalar/array/slice types, loop combinator).
-- Pinned to the EXACT commit of the `nightly-2026.06.10` release whose bundled
-- Charon+Aeneas generated `generated/{Funs,Types}.lean`. (Same commit the
-- portcullis-core lean package pins.)
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @ "5138c03bd39e870abe1ad3a572865cf8c15f43d6" / "backends" / "lean"

-- Mathlib pin must match the Aeneas Lean toolchain (v4.30.0-rc2). Aeneas Std
-- transitively requires Mathlib; we pin it here so the lake-manifest is stable.
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.30.0-rc2"

-- The Aeneas-generated core (committed verbatim — DO NOT hand-edit).
lean_lib «CkPolicy» where
  roots := #[`CkPolicy.Types, `CkPolicy.Funs]
  srcDir := "generated"

-- Soundness proofs OVER the extracted core (the tier-1 bridge).
@[default_target]
lean_lib «CkPolicyAeneas» where
  roots := #[`CkPolicyAeneas]
