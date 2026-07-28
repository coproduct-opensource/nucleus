# `nucleus-mediation-lint` — the `mediated` pass

A standalone [Dylint](https://github.com/trailofbits/dylint) lint crate. Its single
`LateLintPass`, **`mediated`**, flags any publicly reachable function that can reach a
raw I/O primitive without passing through a function that demands an `Authority` by
value — **closed under the call graph**.

## Why this exists

Global mediation — *"every side effect in the system is preceded by a scoped
discharge"* — is a whole-program property. Lean cannot prove it directly, for two
reasons:

1. The effect layer performs real I/O, so it is outside the Charon/Aeneas extractable
   subset. The call sites where mediation matters are exactly the ones the prover
   cannot see.
2. "Every effect anywhere" quantifies over code not yet written. A theorem about a
   function is a function property; this is not.

**seL4 has the same shape and resolves it the same way.** It assumes compiler,
assembly, hardware and kernel-initialisation correctness, and imposes *syntactic*
restrictions — no calls through function pointers, no `goto`, no `switch`
fall-through — that are checked outside Isabelle so that the proof has a statically
known call graph to reason about.

So the property is factored:

| Part | Mechanism | Establishes |
|---|---|---|
| A | Lean theorem over the extracted model | *If* every effect entry point consumes a scoped `Authority`, *then* every trace is mediated |
| B | **this lint** | the premise of A, over the real Rust |
| C | trusted | rustc's affine move enforcement; this deny-set's completeness; Aeneas extraction fidelity |

Neither A nor B is worth much alone. A is a conditional with an undischarged
premise; B is a static check with no statement of what it buys.

## This is a SUFFICIENT condition — the opposite of its sibling

The sibling `nucleus-guarantee-lint` is careful that `aeneas_eligible` is *"a SCREEN,
not a proof — a clean pass asserts nothing"*, because Aeneas may reject code the
screen accepts. That posture is correct there and **wrong here**.

A clean pass from `mediated` is meant to assert something real, because that is what
discharges A's premise. For that to hold, two things must be true:

1. **The deny-set covers every raw I/O primitive** reachable from the scanned crates.
   Incompleteness is *unsoundness*, not noise — a missing entry makes an unmediated
   path report clean, the one failure mode this lint exists to prevent.
2. **The call-graph closure is sound.** Constructs that defeat static call
   resolution *within a crate* — function pointers, `dyn` dispatch, FFI, inline
   `asm!` — are **reported**, never skipped. Silently ignoring them would convert
   a hole in the analysis into a clean pass.
3. **The lint runs over the whole mediated set.** Dylint analyses one crate at a
   time, so a cross-crate callee is covered by *its own* pass — and because it must
   be exported to be callable, the `is_exported` filter cannot hide it. This is why
   cross-crate edges are not reported at the call site: doing so attributes the
   finding to every caller instead of to the defect, and an early version produced
   **299 such reports against 15 real findings** on `portcullis-effects` alone.
   Running the lint over only part of the set silently weakens the guarantee.

## What a clean pass does NOT establish

- **That the authority is *spent*, only that it is *demanded*.** A function taking
  `Authority` and calling `drop` on it passes. What closes that is elsewhere:
  `Authority` is `!Clone` and `#[must_use]`, `spend` is its only consuming method, and
  the scope check inside `spend` is what the Lean theorem is stated over. The lint
  proves the token reaches the boundary; the type and the theorem cover what happens
  there.
- **Anything about crates it does not run on.** Soundness is relative to the scanned
  set. `nucleus` and `nucleus-tool-proxy` legitimately call `std::process` and
  `reqwest` for their *own* infrastructure — jailer spawn, HTTP serving — which is not
  agent-attributed effect. **"Mediated crates" is a defined set**, named in the CI
  invocation, not "everything".
- **That the deny-set matches the kernel's real syscall surface.** A `libc` call
  through FFI is caught as an unresolved call, not decoded.

## Running it

```sh
DYLINT_LIBRARY_PATH=tools/nucleus-mediation-lint/target/debug \
  cargo dylint --lib nucleus_mediation_lint -- -p portcullis-effects
```

## Known limitation: UI tests do not run on macOS

`cargo test --test ui` fails on macOS with
`dlopen failed: Library not loaded: @rpath/librustc_driver-*.dylib`. The dylib
resolves `rustc_driver` through `@rpath`, which `DYLD_FALLBACK_LIBRARY_PATH` does not
satisfy; `DYLD_LIBRARY_PATH` does satisfy it, but macOS SIP strips `DYLD_*` from the
child processes the test harness spawns.

**This is pre-existing and not specific to this crate** — the sibling
`nucleus-guarantee-lint` fails identically on the same host, verified. The UI suite is
therefore a Linux-CI check. Direct `dlopen` of the built dylib with
`DYLD_LIBRARY_PATH` set succeeds, so the build itself is sound.

## Findings on first run (not yet acted on)

Run against `portcullis-effects` and its dependencies, the pass reports 15 functions
reaching raw I/O with no `Authority`. They fall into two groups, and the split is the
"mediated set" decision made concrete:

- **Agent-facing, and worth closing:** `capability_traits::{read_file, write_file}` —
  unmediated filesystem helpers sitting next to the mediated effect traits.
- **Infrastructure, probably out of set:** `*::load_from_dir` config loaders,
  `sink::JsonlSink`, `merkle::MerkleSink` (audit writing). These are the runtime's own
  I/O, not agent-attributed effect — the same category as jailer spawn and HTTP
  serving.

Neither group is fixed here. The lint's job is to make the boundary explicit and
force the decision; deciding it is separate work.
