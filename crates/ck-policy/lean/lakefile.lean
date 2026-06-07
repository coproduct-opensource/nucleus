import Lake
open Lake DSL

-- The Constitutional Kernel monotonicity-gate soundness proofs that the Rust
-- crate `ck-policy` (`crates/ck-policy/src/lib.rs`, `check_monotonicity`) is
-- parity-pinned to: T1 conditional soundness, `meta_gap` (the anti-coup hole),
-- and `strengthened_gate_closes_it` (the constructive fix across a 2-step chain).
-- Mathlib-free: `Nat` + `List` + `Bool` + `omega` / `decide` + structural
-- induction, mirroring `crates/nucleus-rubric/lean`. No Mathlib, no native_decide,
-- no `sorry`/`admit`.
package «ckPolicy» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib «Ck» where
  roots := #[`Ck]
