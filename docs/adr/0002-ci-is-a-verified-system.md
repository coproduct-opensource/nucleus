# ADR 0002 — The CI pipeline and merge queue are a verified system, held to the runtime's standard

- Status: accepted (2026-09-05)
- Tracks: the CI-invariant inventory of 2026-09-05; PRs #2642 (repairs), #2643 (`ci-spec`), #2644 (live parity), #2645 / #2646 (Lean model), the queue-mirror PR, this document
- Applies to: `.github/workflows/**`, `ci/**`, `scripts/check-*.sh`, the merge-queue ruleset, branch protection

## Context

Between 2026-09-04 and 2026-09-05 almost nothing merged for fifteen hours. The merge
queue ejected entries by its 60-minute check timeout while four or five build runners
served every pull request's own runs; `strict` branch protection forced a rebase before
every merge; a push to a queued PR silently dequeued it. An inventory taken while
diagnosing that stall found something worse than slowness: **required status checks that
were green by construction**.

- `Proof Count Ratchet` did `grep -rc` over a directory, fed the multi-line result into
  `$(( ))`, hit a division by zero, and compared an empty operand with `[ "" -lt 72 ]` —
  which errors, which `if` reads as false, which passes. Vacuous since 2026-03-30.
- `Code Coverage (llvm-cov)` piped `cargo llvm-cov --fail-under-lines` into `tee` under
  GitHub's default shell, which has no `pipefail`; the threshold could never red. The
  first run that *could* fail revealed the workspace coverage build had never compiled on
  a runner at all, and then that the real number was 83.47 %, not the asserted 85 %.
- `Mutation Testing`'s baseline build failed under `-D warnings` and its checker's marker
  regex matched the failure text "no mutants were tested".
- One required context, `Scoped Aeneas (Rust → Lean 4) + parity tests`, was produced by
  four jobs in two twin pairs; two `-noop` twins ignored lists that had drifted from the
  real twins' `paths`; seven required contexts hung off two detector jobs that were not
  themselves required, so a red detector reported them all as SKIPPED — and GitHub counts
  a skipped required check as passed.

None of the invariants those defects broke was written down. There was not even a list
of the required contexts in the repository; it lived only in GitHub's settings.

The obvious fix — read the workflows carefully, add more `-noop` twins by hand, write a
checklist — is the shape that drifts. Every one of the defects above had been reviewed.
The repository already holds its *runtime* to a different standard: a typed model of the
thing enforced, decision procedures with founding-defect fixtures, hand-written Lean
theorems whose hypotheses are those decision procedures, model↔live parity ("boot it,
then measure"), ledgers that cannot outrun their wiring, and a gate of gates that
perturbs every gate and demands red. This decision applies that standard to CI itself.

## Decision

1. **The CI configuration is a typed model, and its invariants are decision procedures.**
   `crates/ci-spec` parses every workflow, the required-check ledger and the merge-queue
   pin into a model and decides nine invariants over it (twin completeness, producer
   injectivity, reported-and-unskippable under `merge_group`, concurrency safety, scope
   parity, gate integrity, timeouts within the queue budget, wired-and-inventoried
   gates, non-vacuity of the model). Each invariant carries a fixture of the defect it was
   written for and must go red on it. The check is a required context, `CI configuration
   is sound (CI-1)`, and `2` ("could not look") is a red, never a pass.
2. **The required-check set and the merge-queue constants live in the tree,** in
   `ci/required-checks.txt` (population pinned, grow-only) and `ci/merge-queue.toml`, and
   a scheduled job holds them in lockstep with GitHub (`cargo xtask ci-spec live-parity`).
   A UI edit becomes a red within thirty minutes. Without a token that can read branch
   protection the job is red, because a parity check that passes when it cannot see is
   the vacuity it exists to find.
3. **The properties the queue relies on are theorems, in Lean, Mathlib-free,** with the
   decision procedures of (1) as their hypotheses: twin coverage (`twin_covers`), required
   verdicts exist (`T1`), queue accounting and order (`T3`, `T4`), cancel-safety and
   push-dequeues (`T5`, `T6`), and no timeout ejection under the budget (`T7`, Graham's
   bound in `Nat`). Every theorem has a **bite**: the same statement with one hypothesis
   dropped, proved reachable on the concrete 2026-09-05 shape, by `decide`. A bite file
   may only drop hypotheses; a gate enforces that it adds no semantics.
4. **The model is pinned to the live path in three ways:** a Rust mirror of the Lean
   transition function, golden vectors rendered into `Golden.lean` and checked by `decide`
   (regenerate-and-diff), and the merge queue's real history replayed through the mirror
   nightly — a transition the model rejects is a red, a window with nothing to replay is
   undecided. A bounded Kani proof over the Rust mirror is not yet earned (CBMC did not
  finish on this host); the ledger says so.
5. **Every gate can fail, and says how.** Every `scripts/check-*.sh` is probed by the gate
   of gates; every inline `run:` gate is inventoried in `ci/inline-gates.txt` with its
   falsifier or as `UNCOVERED` under a ceiling that only shrinks; a threshold is set to
   its measured truth with a dated note, never to a number nobody measured.
6. **Claims about CI are a ledger.** `docs/assurance/ci-assurance.md` carries the status
   table (`PROVED` / `DECIDED` / `TESTED` / `NOT-YET`) with evidence handles that must
   dereference and falsifiers that must be wired, gated by
   `scripts/check-ci-assurance-ledger.sh` with a two-direction population pin.

## First consumer

`.github/workflows/ci.yml` (`ci-spec` job), `.github/workflows/ci-assurance.yml`
(`live-parity`, `trace-check`), `.github/workflows/ci-spec-lean.yml` and its noop twin,
`crates/ci-spec`, `ci/lean` (`CiSpec`, `CiSpecBite`), `ci/required-checks.txt`,
`ci/merge-queue.toml`, `ci/inline-gates.txt`, `ci/gate-integrity-allowlist.txt`,
`scripts/check-ci-spec.sh`, `scripts/check-ci-spec-bite.sh`,
`scripts/check-ci-spec-golden.sh`, `scripts/check-ci-assurance-ledger.sh`.

## Consequences

- Adding a required context is a change to `ci/required-checks.txt` (raise the pin) AND
  to branch protection; the scheduled parity job reports either half done alone.
- A new path-filtered required workflow needs a `-noop` twin whose `paths-ignore` is the
  real `paths` verbatim; `ci-spec` reds otherwise, and `twin_covers` says why.
- A required job may `needs:` only jobs that are themselves required contexts, or use
  `always()` and read their results explicitly.
- Every new gate step must be inventoried with its falsifier; the `UNCOVERED` ceiling
  does not rise.
- The merge-queue constants are hypotheses of a theorem: changing them in the UI is a
  red until the pin — and the theorem's reading — follows.
- The straddling case of twins (a change touching both a filtered and an unfiltered path
  fires both twins under one name) is a GitHub semantics limit; `twin_both_iff` states it
  and `ci-spec` reports it rather than pretending it is fixed.

## Rejected

- **TLA+/TLC for the queue model** (Mergify and Aviator have published specs in exactly
  this shape). Rejected because it adds a Java toolchain and a second proof census with
  no axiom audit, sorry-ban, lean-lib coverage or Proof Count Ratchet integration; the
  Lean model reuses all of those. Their specs are cited as prior art.
- **Kani only, no Lean.** Bounded and no liveness; the capacity theorem and the order
  theorem are unbounded statements.
- **Hand-maintained twin checklists and a "required checks" wiki page.** The exact
  shape that drifted: two copies of one fact with nothing comparing them.
- **Making every gate a shell script so the gate of gates covers it.** The inline
  steps that were vacuous stay inline; the inventory brings them into the accounting
  without a rewrite, and the ceiling ratchets them down.
- **Lowering the coverage threshold silently to make the gate green.** It was reset to
  the measured 83.47 % with a dated note in the step, and may only rise.
