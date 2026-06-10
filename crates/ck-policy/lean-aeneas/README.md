# ck-policy — Aeneas-extracted monotonicity-gate CORE

This directory holds the **Charon + Aeneas extraction** of the self-contained
monotonicity-gate core in `crates/ck-policy/src/extracted.rs`.

`generated/CkPolicy/Funs.lean` and `generated/CkPolicy/Types.lean` are produced
by the pipeline below and committed verbatim — **do not hand-edit them**.
Regenerate with the exact toolchain (see "Provenance") and commit the result.
(Aeneas emits `Funs.lean`/`Types.lean` FLAT; they are moved into the `CkPolicy/`
subdir so the lakefile's `srcDir := "generated"` + `roots := [CkPolicy.Types,
CkPolicy.Funs]` resolve them. The drift CI compares the flat regenerated files to
the committed `generated/CkPolicy/*` ones.)

The tier-1 SOUNDNESS PROOFS over this generated core live in
`CkPolicyAeneas.lean` (built by `.github/workflows/ck-policy-aeneas.yml`); the
tier-4 PARITY binding to production `check_monotonicity` is
`crates/ck-policy/tests/policy_aeneas_parity.rs`.

## Pipeline

```
crates/ck-policy/src/extracted.rs       (Aeneas-subset Rust: ints/bool/arrays/slices)
        │  charon cargo --preset aeneas --start-from 'ck_policy::extracted::passed_core'
        │                               --dest-file /tmp/ck_policy.llbc
        ▼
        ck_policy.llbc                   (Charon MIR → LLBC)
        │  aeneas -backend lean -split-files ck_policy.llbc -dest <tmp>
        │  (then move Funs.lean / Types.lean into generated/CkPolicy/)
        ▼
generated/CkPolicy/{Funs,Types}.lean    (Aeneas Lean 4 model)
        │  CkPolicyAeneas.lean proves soundness OVER these defs (tier-1)
        ▼
policy_aeneas_parity.rs binds the core to production check_monotonicity (tier-4)
```

> Footgun: Charon only emits LLBC when the target crate actually RECOMPILES.
> After a `cargo test`/`cargo build` warms the cache, `charon cargo …` finishes
> in <1s and produces NO llbc (no error). Fix: `touch src/extracted.rs src/lib.rs`
> (or `cargo clean -p ck-policy`) before extracting.

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

### The tier-1 theorems (`CkPolicyAeneas.lean`)

Each is proved DIRECTLY over the generated defs; `#print axioms` on each is
`[propext, Classical.choice, Quot.sound]` (no `sorryAx`, no `native_decide`):

* `passed_core_decomp` — gate `ok true` ⇒ every generated safety scan returned
  its safe value (cap/io/proofreq/budget `ok false`, `rules_non_weakening` `ok true`).
* `budget_not_violated` — budget "not violated" ⇒ generated `budget_within` `ok true`.
* `rules_non_weakening_sound` — generated `rules_non_weakening` `ok true` ⇒ child
  disables no parent-enabled flag (FULL loop-free decode of the anti-coup conjunct).
* `T1_extracted_gate_sound` — the combined soundness theorem (analogue of
  `Ck.Policy.T1_gate_sound`, over the GENERATED `passed_core`).

## Mathlib posture (HONEST)

The Aeneas Lean STANDARD LIBRARY (`import Aeneas`) transitively `require`s Mathlib
at the pinned commit, so building the generated/proof files pulls Mathlib —
UNAVOIDABLE, identical to the `crates/portcullis-core/lean` precedent. The proofs
in `CkPolicyAeneas.lean` are nonetheless "Mathlib-free" as a PROOF DISCIPLINE:
they use only structural `cases`/`split_ifs`/`injection` + Aeneas Std bind lemmas,
no Mathlib lemmas, no `native_decide`. The sibling HAND-WRITTEN model package
(`crates/ck-policy/lean`) has no Aeneas dependency and is fully Mathlib-free.

Build: `cd crates/ck-policy/lean-aeneas && lake exe cache get && lake build
CkPolicyAeneas`. The Aeneas stdlib itself contains internal `sorry`s (in
`Aeneas/Std/Slice.lean`, `String.lean`); these are IRRELEVANT to our claim —
the `#print axioms` audit proves no soundness theorem depends on them.

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
