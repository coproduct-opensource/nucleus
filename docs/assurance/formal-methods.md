# Formal Methods Plan

Goal: move from model checking to machine-checked proofs for the core lattice
and nucleus (`ν`) properties, while keeping the spec small and auditable.

## Scope (initial)
- Permission lattice order and join/meet.
- Nucleus `ν` (normalization) laws:
  - Idempotent: ν(ν(x)) = ν(x)
  - Monotone: x ≤ y ⇒ ν(x) ≤ ν(y)
  - Deflationary: ν(x) ≤ x
- Trifecta obligations as a derived constraint.

## Plan
1. **Lean 4 spec** of the lattice structure and ν (small, pure model).
2. **Proofs** of ν laws + meet/join compatibility (minimal theorem set).
3. **Traceability**: map each Rust field to the spec with a short “spec ↔ code”
   reference table.
4. **CI gate** for proof check (separate job; fails on proof regressions).

## What Kani Covers (and doesn’t)
- Kani is used for bounded model checking on Rust implementations.
- Kani **does not** replace theorem proving; it complements the proof layer.

## Non-goals (initial)
- Full refinement proofs from Rust to Lean.
- End-to-end OS isolation proofs.
