# CI Assurance — what is proved, decided, tested, and not yet

The CI pipeline and merge queue are held to the standard of the runtime (ADR 0002). This
document is the ledger of that claim, in the form `docs/north-star.md` uses: one row per
clause, a status from a closed vocabulary, evidence handles that must dereference, and the
gate that catches the status regressing. `scripts/check-ci-assurance-ledger.sh` enforces
every column, pins the population (rows may only be added; a removal is an owner decision
recorded in `scripts/ci-assurance-ledger-ratchet.txt`), and pins the `NOT-YET` count so a
promotion lowers it in the same change and a demotion raises it on the record.

**The sentence.** *A required check that is green is green because it ran, on the merge
queue's branch, and could have failed; the merge queue merges in order, is not ejected by
its own timeout when the work fits, and matches the configuration this tree describes.*

## Status vocabulary

| status | meaning |
|---|---|
| `PROVED` | a Lean theorem over the model (`ci/lean`), sorry-free and axiom-audited, whose hypotheses are decided on the tree |
| `DECIDED` | a decision procedure (`crates/ci-spec`) runs on every pull request and merge group over the real workflow tree, with a founding-defect fixture |
| `TESTED` | asserted against GitHub's live state or history (scheduled parity, trace replay) |
| `NOT-YET` | stated and not yet earned; the row names what is missing |

#### Status — what is proved, what is decided, what is not yet

| # | Clause | Status | Evidence | Falsified by |
| --- | --- | --- | --- | --- |
| CI-1 | "green because it ran" — a path-filtered required workflow and its `-noop` twin never leave a change with NEITHER report | PROVED | `ci/lean/CiSpec/Pipeline.lean#twin_covers`, `crates/ci-spec/src/invariants/twins.rs#CI-I1-PATHS` | `scripts/check-ci-spec.sh` |
| CI-2 | "on the merge queue's branch" — every required context has exactly one producing twin pair, triggered on `merge_group`, whose job cannot be skipped there | PROVED | `ci/lean/CiSpec/Pipeline.lean#T1_required_verdicts_exist`, `crates/ci-spec/src/invariants/producers.rs#CI-I2-DUP`, `crates/ci-spec/src/invariants/merge_group.rs#CI-I3-NEEDS` | `scripts/check-ci-spec.sh` |
| CI-3 | "could have failed" — no inline gate has a fail-open shape: a swallowed status feeding an emptiness-satisfied verdict, a grep for badness with no arrival floor, a pipeline without `pipefail`, `continue-on-error`, or a numeric test on an unestablished operand | DECIDED | `crates/ci-spec/src/invariants/gates.rs#check_step`, `crates/ci-spec/tests/founding_defects.rs#gi006_the_real_ratchet_is_caught_and_its_repair_is_clean` | `scripts/check-ci-spec.sh` |
| CI-4 | "could have failed" — every gate script is invoked by a workflow and every inline gate is inventoried with its falsifier or under a shrink-only `UNCOVERED` ceiling | DECIDED | `crates/ci-spec/src/invariants/wired.rs#check`, `ci/inline-gates.txt` | `scripts/check-gates-can-fail.sh` |
| CI-5 | "matches the configuration this tree describes" — the required-check ledger equals branch protection and the merge-queue pin equals the ruleset | TESTED | `crates/ci-spec/src/live.rs#parity`, `.github/workflows/ci-assurance.yml` | `.github/workflows/ci-assurance.yml` |
| CI-6 | "merges in order" — every reachable queue state is consistent, merges are a subsequence of enqueues, cancelling a dequeued PR's run changes nothing the queue reads, a push dequeues | PROVED | `ci/lean/CiSpec/Queue.lean#T4_merge_order`, `ci/lean/CiSpec/Queue.lean#T5_cancel_safe`, `ci/lean/CiSpec/Queue.lean#T6_push_dequeues`, `crates/ci-spec/tests/queue_parity.rs#t3_t4_hold_on_every_reachable_state` | `scripts/check-ci-spec-golden.sh` |
| CI-7 | "is not ejected by its own timeout when the work fits" — with build concurrency 1 and no competing runs, a group whose work plus `q·L` fits `(q+1)·T` finishes by `T` | PROVED | `ci/lean/CiSpec/Capacity.lean#T7_no_timeout_ejection`, `ci/lean/CiSpecBite.lean#budget_60_did_not_fit` | `scripts/check-ci-spec-bite.sh` |
| CI-8 | "merges in order" — the merge queue's real history replays through the model with no rejected transition | TESTED | `crates/ci-spec/src/trace.rs#replay` | `.github/workflows/ci-assurance.yml` |
| CI-9 | "when the work fits" — the concrete first-least-loaded scheduler is an instance of the schedules T7 covers, and `needs:` chains are modelled | NOT-YET | `ci/lean/CiSpec/Capacity.lean#What is NOT proved` | — |
| CI-10 | "is not ejected" — `strict` branch protection with a queue is a rebase livelock (T8), and `strict = false` with fairness merges or ejects every entry | NOT-YET | `ci/merge-queue.toml#strict` | — |
| CI-11 | "merges in order" — a bounded Kani proof of the accounting invariant over the Rust mirror (attempted at 3 PRs × 4/3/2 events; CBMC exceeded an hour, then was killed under host memory pressure) | NOT-YET | `crates/ci-spec/src/queue.rs#NOT-YET` | — |

*Clause fragments quote the sentence above; the ledger gate checks they do. A row whose
status is `PROVED` names a theorem; `DECIDED` names a rule id or function and a fixture;
`TESTED` names the code and the workflow that runs it against GitHub; `NOT-YET` names the
file that states the gap.*

## What each mechanism does NOT establish

- **`ci-spec` reads YAML; it does not run gates.** A structurally sound gate can assert the
  wrong thing. Gate detection is the `exit 1` / `::error::` heuristic inherited from
  proofcard, stated as such; cross-step dataflow (a `lake build` in one step establishing
  the files a later grep reads) is not modelled and is allowlisted with that reason.
- **The Lean model is hand-written, not extracted.** The Rust mirror is bound to it by
  golden vectors and proptest — probabilistic and finite, as the K4 parity file says of
  itself; a bounded Kani proof of the mirror is NOT-YET (CI-11). The CI configuration itself is not in Lean; `ci-spec`'s
  decisions are the theorems' hypotheses.
- **Twins straddle.** A change touching both a filtered and an unfiltered path fires both
  twins under one name (`twin_both_iff`). GitHub decides which check run the rollup reads;
  `ci-spec` reports the shape, it does not fix it.
- **Live parity needs a token.** Reading branch protection needs repository
  *Administration: read*; without `CI_ASSURANCE_TOKEN` the scheduled job is red by design.
- **The capacity model has independent jobs.** `needs:` chains, speculative groups
  (`max_entries_to_build > 1`) and runner start-up latency are not modelled; the pin is
  concurrency 1 and live parity holds it.

## How to reproduce

```sh
cargo xtask ci-spec check                    # I1–I9 over the tree; exit 0 / 1 / 2
cargo xtask ci-spec live-parity              # ledger ↔ GitHub (needs an admin-read token)
cargo xtask ci-spec trace-check --since-hours 24
scripts/check-ci-spec-golden.sh              # Rust mirror ↔ Lean model, by decide
scripts/check-ci-spec-bite.sh                # the bite adds no semantics
scripts/check-ci-assurance-ledger.sh         # this table cannot outrun its wiring
scripts/check-gates-can-fail.sh              # every gate reds on its subject
(cd ci/lean && lake build CiSpec CiSpecBite) # the theorems
scripts/lean-axiom-audit.sh ci/lean CiSpec,CiSpecBite

```
