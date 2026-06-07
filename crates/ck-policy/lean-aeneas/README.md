# ck-policy — Aeneas-extracted monotonicity-gate CORE

This directory holds the **Charon + Aeneas extraction** of the self-contained
monotonicity-gate core in `crates/ck-policy/src/extracted.rs`.

`generated/Funs.lean` and `generated/Types.lean` are produced by the pipeline
below and committed verbatim — **do not hand-edit them**. Regenerate with the
exact toolchain (see "Provenance") and commit the result.

## Pipeline

```
crates/ck-policy/src/extracted.rs       (Aeneas-subset Rust: ints/bool/arrays/slices)
        │  charon cargo --preset aeneas --start-from 'ck_policy::extracted::passed_core'
        ▼
        ck_policy.llbc                   (Charon MIR → LLBC)
        │  aeneas -backend lean -split-files ck_policy.llbc -dest lean-aeneas/generated
        ▼
generated/{Funs,Types}.lean             (Aeneas Lean 4 model)
```

`passed_core` and its callees (`subset_u32`, `dropped_u32`, `budget_within`,
`rules_non_weakening`, the per-axis `*_violated`) translate cleanly — **no
`FunsExternal.lean` hand-curation was required** (the LLBC has no opaque
functions). `Types.lean` is empty (the core uses only primitive types).

## The three honesty tiers (DO NOT CONFLATE)

* **DEDUCTIVE (tier-1 — the bridge this dir establishes).** The Lean here is a
  formal Charon→Aeneas translation of the extracted Rust core, not a hand
  transcription. Lean theorems proved *about these definitions* are deductive
  facts about the extracted model.
* **STATISTICAL (tier-4 — sampled).** The extracted core is bound to the
  PRODUCTION `ck_policy::check_monotonicity` (which operates on
  `BTreeSet<String>` manifests and cannot itself be extracted) by parity
  proptests. A proptest is **not** a proof; it narrows the model↔production gap
  probabilistically.

The honest end-to-end claim: *a self-contained, monomorphized core that
faithfully mirrors the gate's verdict was extracted by Charon+Aeneas and (in the
proof layer) is proven in Lean; that core is bound to production
`check_monotonicity` by a parity proptest.* It is **not** "the literal
`check_monotonicity` was verified."

## TCB caveat — verified Rust != verified binary

These artifacts trust **Charon** (MIR → LLBC), **Aeneas** (LLBC → Lean), the
**Lean kernel**, and **rustc** (which compiles the production binary). The proof
is about the extracted model of the source, not the running machine code.

## Provenance (pin — update when regenerating)

* Aeneas release: `nightly-2026.05.30` (AeneasVerif/aeneas, macOS x86_64 tarball)
* Charon: bundled in that release, version `0.1.204`
* Charon rustc toolchain: `nightly-2026-02-22` (from the tarball's
  `rust-toolchain`, components `rustc-dev,llvm-tools-preview,rust-src`)
* Aeneas Lean backend output namespace: `ck_policy`
