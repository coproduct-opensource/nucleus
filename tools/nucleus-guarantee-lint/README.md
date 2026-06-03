# `nucleus-guarantee-lint` — the `aeneas_eligible` screen

A standalone [Dylint](https://github.com/trailofbits/dylint) lint crate. Its single
`LateLintPass`, **`aeneas_eligible`**, flags any function that uses a construct which
makes it **ineligible** for [Aeneas](https://github.com/AeneasVerif/aeneas) extraction
into a pure functional model (Lean / F\* / Coq / HOL4).

## HONESTY: this is a SCREEN, not a proof

`aeneas_eligible` computes a **necessary condition** — a *screen*. It is **not**:

- a proof that a function *is* extractable;
- a proof that the extracted model is *correct*;
- a guarantee of anything.

The lint only ever asserts **ineligibility** on a hit. A clean pass asserts **nothing**:
a function that passes can still be rejected by Aeneas's borrow-checked symbolic
interpreter (e.g. [aeneas#802](https://github.com/AeneasVerif/aeneas/issues/802),
"borrow checking error on valid Rust code"). Aeneas is alpha software and its supported
subset is a moving target, so the screen is biased toward **DENY when uncertain**.

Nothing in this crate is named or documented as *proving* extractability or correctness.

## The deny-set it screens (implemented)

A function is flagged if its signature or body contains ANY of:

| Construct | Where detected | Aeneas rationale (Research Report 3) |
|---|---|---|
| `unsafe` fn | `FnHeader::is_unsafe()` | aeneas#743 — unsafe semantics not modeled |
| user `unsafe { }` block | `BlockCheckMode::UnsafeBlock(UserProvided)` | aeneas#743 |
| `async` fn | `FnHeader::is_async()` | charon#609 — unsupported even at the Charon layer |
| `async { }` block / `async` closure | `ClosureKind::Coroutine`/`CoroutineClosure(Async)` | charon#609 |
| closure | `ClosureKind::Closure` | aeneas#924 — fragile, default-deny |
| `dyn Trait` in signature | `TyKind::TraitObject(.., Dyn)` | no functional model for dynamic dispatch |
| raw pointer `*const`/`*mut` in signature | `TyKind::Ptr` | aeneas#743 — borrows-only model |
| FFI / `extern` call | `tcx.is_foreign_item(callee_def_id)` | charon limitations.md — opaque bodies |
| inline `asm!` | `ExprKind::InlineAsm` | no functional model |

## Deny-set rows NOT yet implemented (flagged for the verifier)

These rows from Research Report 3 are **not** screened by this scaffold. A clean pass
does **not** cover them — see the `// TODO(deny-set)` markers in `src/lib.rs`:

- floats `f32`/`f64` ([aeneas#828](https://github.com/AeneasVerif/aeneas/issues/828))
- nested loops / break-to-outer-label / return-inside-loop (aeneas#964, #822)
- non-`Vec` std collections (`HashMap`, `BTreeMap`, …) — only `Vec` ships an Aeneas model
- iterator-combinator chains (`.map`/`.filter`/`.collect`) (aeneas#1053/#1043/#464)

## Future hook: signed per-hash guarantee receipt (NOT in this scaffold)

This crate is the **screen only**. A future pass would, for each function that passes,
compute a stable digest and emit a *signed per-hash guarantee receipt* binding
`hash(StableMIR body OR rustfmt-normalized source) + toolchain + profile`. The receipt
would certify only "passed the screen under `<toolchain, profile>`" — never "is
extractable" and never "is correct". See the `// TODO(guarantee-receipt)` block in
`src/lib.rs`.

## Version pins (a lockstep triple)

Per Research Report 1 (Dylint authoring SOTA, verified 2026-06), these three move
together — never bump one in isolation:

| Pin | Value | Source |
|---|---|---|
| toolchain channel | `nightly-2026-04-16` | `rust-toolchain.toml` (required by dylint_linting 6.0.1) |
| toolchain components | `rustc-dev`, `llvm-tools-preview` | required or `extern crate rustc_*` won't resolve |
| `clippy_utils` | git rev `f6d310692116e9a527ce6d0b3526c965d9c5d7b9` | matched to that nightly |
| `dylint_linting` / `dylint_testing` | `6.0.1` (released 2026-05-26) | crates.io |

## Build & run

```sh
# One-time tooling (do NOT add these to this crate's deps):
cargo install cargo-dylint dylint-link

# Install the pinned toolchain + components:
rustup toolchain install nightly-2026-04-16 \
  --component rustc-dev --component llvm-tools-preview

# Build the cdylib and run the UI test (from this crate root):
cargo build
cargo test            # runs the dylint_testing UI snapshot test

# Run the lint against a target project:
cargo dylint --lib nucleus_guarantee_lint
```

### macOS: `DYLD_FALLBACK_LIBRARY_PATH` (verified blocker + fix)

On macOS the built `…@<toolchain>.dylib` references `@rpath/librustc_driver-*.dylib`
but carries **no `LC_RPATH`**, so the dylint-driver's `dlopen` fails with
`Library not loaded: @rpath/librustc_driver-…`. Point the dynamic loader at the
toolchain `lib` dir when running the test (this was required here to get a green UI
test):

```sh
export DYLD_FALLBACK_LIBRARY_PATH="$(rustc +nightly-2026-04-16 --print sysroot)/lib"
cargo test --test ui
```

(Not needed on Linux, where the equivalent rpath is baked in.)

`dylint-link` must be on `PATH` at build time so the `@TOOLCHAIN`-suffixed dynamic
library name Dylint expects is produced. Register persistently in a linted project via:

```toml
[workspace.metadata.dylint]
libraries = [{ path = "path/to/nucleus-guarantee-lint" }]
```

then `cargo dylint --all`.

## Regenerating the UI snapshot

`cargo test --test ui`; on a mismatch the harness prints
`Actual stderr saved to <PATH>` — copy that file over `ui/main.stderr`. (This is the
compiletest_rs copy-the-path workflow. NOTE: `cargo test -- --bless` does NOT work
through this harness — libtest rejects the `--bless` arg before compiletest sees it,
contra a generic Research-1 note; use the copy-the-path flow.)

The UI harness (`tests/ui.rs`) passes `--rustc-flags=--edition=2024`, because
compiletest does not inherit this crate's edition and the fixtures use `async fn`
(a hard error under the default edition 2015).
