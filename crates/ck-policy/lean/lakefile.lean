import Lake
open Lake DSL

-- The Constitutional Kernel monotonicity-gate soundness proofs that the Rust
-- crate `ck-policy` (`crates/ck-policy/src/lib.rs`, `check_monotonicity`) is
-- parity-pinned to: T1 soundness (incl. unconditional non-weakening),
-- `weak_gate_admits_coup` (the pre-fix hole), `new_gate_rejects_coup` (the fix
-- on the same witness), and `strengthened_gate_closes_it` (transitive anti-coup).
-- Mathlib-free: `Nat` + `List` + `Bool` + `omega` / `decide` + structural
-- induction, mirroring `crates/nucleus-rubric/lean`. No Mathlib, no native_decide,
-- no `sorry`/`admit`.
package «ckPolicy» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib «Ck» where
  roots := #[`Ck]
