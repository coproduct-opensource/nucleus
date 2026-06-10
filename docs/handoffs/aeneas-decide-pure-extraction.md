# Handoff: Make `decide_pure` a genuinely Aeneas-extracted kernel

**Queue position:** anchoring loop, AFTER P2 (SNARK Pigou-seam), BEFORE P3 (verifier registry).
**Repo:** `/Users/bcrisp/coproduct/nucleus` · **Crate:** `crates/portcullis-core`
**Status at handoff:** investigation complete, read-only, no changes made.

## TL;DR
A comment claims Aeneas can't extract `decide_pure` because it "cannot translate `==`
on enums." **This is false on the current toolchain** — the checked-in generated output
already contains a clean translated body for enum equality. The real reasons `decide_pure`
isn't extracted: (1) it was left out of the Charon extraction scope, and (2) proof
ergonomics over Aeneas's monadic `==` are uglier than over a hand-written model.

## Evidence (verify before starting)
| Claim | File:line | Finding |
|---|---|---|
| "Aeneas cannot translate `==` on enums" | `crates/portcullis-core/lean/DecidePureProofs.lean:11-12` | STALE/FALSE |
| Enum `==` already translates | `crates/portcullis-core/lean/generated/Funs.lean:71-76` | real body: `CoreCmpPartialEqCapabilityLevel.eq` via `read_discriminant self`/`other` → `ok (self1 = other1)` — non-opaque |
| Toolchain already latest | `crates/portcullis-core/flake.nix:6` | `aeneas.url = "github:AeneasVerif/aeneas"`, no flake.lock → floats to HEAD. Charon nightly 2026-02-07. Nothing to upgrade. |
| `decide_pure` deps not extracted | grep `lean/generated/` | `should_gate`, `project_exposure`, `ExposureSet`, `classify_exfil` absent — extraction scoped to lattice algebra only (`CapabilityLevel` + `CapabilityLattice` meet/join/leq/implies/complement) |
| Rust source of truth | `crates/portcullis-core/src/lib.rs:2002` (`decide_pure`); enum `CapabilityLevel` at `:165` | `decide_pure` uses `if level == CapabilityLevel::Never …` (derived PartialEq) + `should_gate` (match + bool + Option) |
| Hand-written Lean model (current) | `crates/portcullis-core/lean/DecidePureProofs.lean` | 6 proven theorems over a model mirroring Rust, NOT over extracted code. Zero `sorry`. |
| Upstream context | charon#769 "excessively verbose LLBC for PartialEq" (closed 2025-07) | confirms derived PartialEq translates (verbosely) |

## Task 1 — Fix the stale comment (low effort, do regardless)
`crates/portcullis-core/lean/DecidePureProofs.lean:11-12`. Replace the false "Aeneas cannot
translate `==` on enums or `should_gate`" with an accurate note: this is a hand-written model
for proof convenience; enum `==` *does* translate (see `generated/Funs.lean`
`CoreCmpPartialEqCapabilityLevel.eq` via `read_discriminant`); the model exists because
(a) `decide_pure` + exposure deps were outside the Charon extraction scope, and (b) proving
over Aeneas's `Result`-monadic `==` is more verbose than over a `DecidableEq` inductive.

## Task 2 — Genuinely extract `decide_pure` (the real work)
Goal: the extracted function carries the proofs, not a parallel hand-written model
(the "proven kernel = measured kernel = zkVM image" direction).
1. Widen Charon extraction scope to include exposure module + `decide_pure` and deps:
   `ExposureSet`, `Operation`, `is_uninhabitable`, `classify_exfil`, `project_exposure`,
   `should_gate`, `decide_pure`. All constructs (match, bool, struct-update `{ x with … }`,
   enum `==` via existing trait eq, Option) are Aeneas-supported. Pipeline:
   `crates/portcullis-core/flake.nix` (`#translate` app) and/or `scripts/aeneas-translate.sh`
   — `charon --cargo --crate portcullis-core` → `aeneas -backend lean portcullis-core.llbc
   -dest lean/generated`. Check whether scoping is via `#[charon::opaque]`/module visibility
   or a Charon include filter; ensure exposure items aren't filtered out.
   **Convention:** use pre-built Aeneas binaries + the sibling `coproduct-opensource/aeneas-ci@v1`
   action; scope Charon with `--start-from`; never build OCaml locally. Real re-extraction
   most likely runs in CI, not on the 16GB dev box.
2. Re-run pipeline; confirm `decide_pure` + deps appear in `lean/generated/`.
3. Prove a refinement lemma bridging generated → model:
   `theorem decide_pure_refines : ∀ level exp op, (generated decide_pure) level exp op =
   DecidePureProofs.decide_pure level exp op` (account for the `Result`/`ok` monadic wrapper;
   `read_discriminant` has standard Aeneas simp lemmas; mostly `simp`/`decide`/case-analysis).
4. Transfer the 6 theorems (`never_always_denies`, `lowrisk_always_requires_approval`,
   `allow_requires_always_and_no_gate`, `gate_exfil_iff`, `monotonicity`, `exhaustiveness`)
   onto the generated function via the refinement, OR re-state directly over the generated def.
   Keep zero `sorry`.

### Acceptance criteria
- `lean/generated/` contains `decide_pure` + all deps; clean axiom audit
  (only `[propext, Classical.choice, Quot.sound]`, matching `IntegrityNoninterferenceExtracted.lean`).
- A refinement lemma (or direct proofs) ties extracted `decide_pure` to the proven safety props.
- `cargo test -p portcullis-core` + Lean build both green in CI.
- Task-1 comment updated to reflect that `decide_pure` is now extracted.

### Optional (only if monadic-eq proofs are painful)
Rewrite the two `level == CapabilityLevel::Never/LowRisk` comparisons in
`src/lib.rs:decide_pure` as `match level { … }` for cleaner Lean. Cosmetic — prefer keeping
`==` unless the refinement proof is genuinely blocked.

## Guardrails
- Vendor-neutral (nucleus is MIT, no LLM-vendor refs).
- Match the extracted-proof style of `IntegrityNoninterferenceExtracted.lean` (kernel-checked,
  axiom-audited, no proof holes).
- `lake build` may flake on a 504 elan download → `gh run rerun <id> --failed`.
- `CARGO_TERM_COLOR=never` set once. Don't commit/push unless asked (loop is authorized to PR).
