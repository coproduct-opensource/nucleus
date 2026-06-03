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

## Signed per-hash guarantee receipts (IMPLEMENTED — v0)

When configured (see below), the lint emits a **signed per-hash GUARANTEE RECEIPT** for
each screened function. The pure receipt logic (hash / canonicalize / sign / verify)
lives in the sibling crate [`receipt/`](receipt/) (`nucleus_guarantee_receipt`), which has
**no rustc dependency** and is unit-testable without the compiler.

### A receipt is a SCREEN RESULT, NOT a proof

> A guarantee receipt attests **exactly one thing**: that the `aeneas_eligible` *screen*
> produced a particular `result` for a particular function, at one exact
> `(normalized_source, toolchain, profile_id)` triple, identified by `anchor_hash`. It is
> **NOT** a proof that the function is extractable, **NOT** a proof that any extracted
> model is correct, and **NOT** a guarantee of anything beyond "the screen returned this
> result for this hash". A `result = "clean"` receipt is the output of a
> **necessary-condition** screen — the unscreened deny-set rows (floats, nested loops,
> non-`Vec` collections, iterator combinators) are carried as `"not_screened"`, never
> `"pass"`. **Change the source → the hash changes → the receipt is void (fail-closed).**
> The guarantee is **toolchain-relative**: it holds only for the exact rustc recorded in
> `toolchain`.

### Receipt JSON (schema_version = 0)

Canonicalized with RFC 8785 / JCS (sorted keys, no insignificant whitespace) and
ed25519-signed over those canonical bytes:

```json
{"anchor_hash":"…hex sha256…","guarantees":{"no_async":"pass","no_closures":"pass","no_dyn_in_sig":"pass","no_ffi_call":"pass","no_floats":"not_screened","no_inline_asm":"pass","no_iterator_combinators":"not_screened","no_nested_loops":"not_screened","no_non_vec_collections":"not_screened","no_raw_ptr":"pass","no_unsafe":"pass"},"ineligible_reasons":[],"item_kind":"fn","item_path":"crate::clean_add","profile_id":"aeneas-eligible-v1","result":"clean","schema_version":0,"toolchain":"nightly-2026-04-16"}
```

`anchor_hash = SHA-256( b"nucleus.guarantee-receipt.v0" ‖ normalized_source ‖ toolchain ‖ profile_id )`,
lowercase hex.

- **v0 `normalized_source`** = the raw source snippet of the function from its HIR span
  (`clippy_utils::source::snippet_opt`). This is **whitespace- and comment-sensitive**:
  reformatting voids the receipt. **v1 TODO**: switch to a reformat-robust anchor
  (rustfmt-normalized source, or a StableMIR-body hash).
- **`toolchain`** is read from `RUSTUP_TOOLCHAIN` (falls back to the pinned
  `nightly-2026-04-16`).
- **`profile_id`** is the constant `aeneas-eligible-v1`.

Written to `<receipt_dir>/<anchor_hash>.json` and `<receipt_dir>/<anchor_hash>.sig`
(signature as lowercase hex).

### Config (`dylint.toml`)

See [`dylint.toml.example`](dylint.toml.example). In a *linted* workspace's root:

```toml
[nucleus_guarantee_lint]
emit_receipts = true
receipt_dir = "target/guarantee-receipts"
signing_key_path = "secrets/guarantee-witness.key"   # 32-byte ed25519 secret, raw OR hex
```

**Fail-loud honesty:** if `emit_receipts = true` but the key is empty/missing/invalid,
the pass ABORTS with an error. It never substitutes a zero/fake key.

### Verifying a receipt (holder side)

```sh
# Build the verifier (pure crate — no rustc-dev / dylint needed):
cargo build -p nucleus_guarantee_receipt --bin verify-guarantee-receipt

# Verify signature against the witness PUBLIC key (hex or file):
verify-guarantee-receipt --json <h>.json --sig <h>.sig --pubkey-hex <64hex>

# Optionally bind-check the anchor to a source file (fail-closed if it differs):
verify-guarantee-receipt --json <h>.json --sig <h>.sig --pubkey-hex <64hex> --source fn.txt
```

Or call `nucleus_guarantee_receipt::verify_receipt(json, sig, &pubkey)` / the
fail-closed `verify_receipt_bound_to(...)` directly.

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

# Build the cdylib (the lint pass):
cargo build -p nucleus_guarantee_lint

# Run the dylint_testing UI snapshot test (needs the macOS DYLD env below):
cargo test -p nucleus_guarantee_lint --test ui

# Run the lint against a target project:
cargo dylint --lib nucleus_guarantee_lint
```

### Receipt crate (PURE — no rustc/dylint needed)

The `receipt/` member builds and tests as a normal crate (no `rustc-dev`, no
`cargo-dylint`, no `DYLD_*`):

```sh
cd receipt
cargo test                                   # 11 unit + 2 integration tests
cargo build --bin verify-guarantee-receipt   # holder-side verifier
cargo run --example emit_sample_receipt -- testdata/sample   # demo: emit + sign a receipt
```

(It is a separate crate because a `#![feature(rustc_private)]` cdylib that links
`rustc_driver` **cannot** also emit an `rlib`/`bin` — the sysroot crates ship dylib-only,
producing `error: X only shows up once`. Splitting the pure logic out keeps it
rlib/bin-buildable AND unit-testable without the compiler.)

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
