# The merge queue's critical path is one gate re-lexing the workspace (2026-10-08)

#3339 measured the merge queue's throughput as one group's wall time: a median of 27 minutes and up
to 45. That wall time is one job, `Live-path gates (one pod)`. This note profiles that job, ranks the
ways to shorten it, and records the one that was taken.

## 1. The profile

**Method.** The last 29 completed `merge_group` runs of `ci.yml` (2026-10-07 17:49 to 2026-10-08
16:41 UTC, all green). Step timings come from the jobs API. Per-probe timings come from each job's
log: the gap between a probe's `run` line and its verdict line.

| | median | max |
|---|---:|---:|
| job wall | 23.9 min | 37.4 min |
| wait for a runner | 45 s | 183 s |

| step | median s | max s |
|---|---:|---:|
| checkout + toolchain | 4 | 5 |
| declassify sink scope | 34 | 52 |
| C2 lineage (builds node, cli, tool-proxy) | 87 | 122 |
| C1 inbound fences | 84 | 120 |
| every perturbation still bites (`--vacuity-only`) | 26 | 39 |
| **every gate REDs and GREENs (`gates-can-fail --for-event merge_group`)** | **1225** | **1901** |

The job is a critical path, not a capacity problem: the runner wait is under a minute. The gate of
gates is 85 % of it. Inside that step the probe seconds rank like this (sum over the 29 runs):

| probe family | runs it ran in | median s per run | share of all probe seconds |
|---|---:|---:|---:|
| **`xtask test-shards --check`** (3 probes) | **26 / 29** | **414** | **38 %** |
| `xtask scorecard` (5 probes) | 22 | 176 | 13 % |
| `check-c1-inbound-fences.sh` | 24 | 109 | 9 % |
| `check-sandbox-trusted-base.sh` | 15 | 159 | 8 % |
| `xtask proof-obligations` (2 probes) | 15 | 129 | 6 % |
| everything else (~50 probes) | | | 26 % |

`test-shards` runs in almost every group, for two reasons. Its inputs include the `.gatehouse/`
plan files, which most changes touch. And the merge-queue backstop runs every probe whenever
`Cargo.lock` or any manifest moves, which 15 of the 29 groups did. Each probe runs its gate three
times: baseline, perturbed, restored. So a group pays for nine `test-shards --check` runs, about 46 s
each on the build runner.

**Where those 46 s go.** A 10-second `sample` of a local run (debug build, as `cargo run -p xtask`
builds it) put all of it under `test_shards::compile_reads` → `nucleus_action_key::escapes::scan` →
`proc_macro2::TokenStream::from_str`. `compile_reads` scans each of the ~90 workspace members.
Each scan lexes every `.rs` file in that member's whole dependency closure. A crate that many
closures share was tokenized once per crate that depends on it.

## 2. The options, ranked by minutes saved against what the job proves

1. **Lex each file once (taken).** Whether a read is covered depends on whose closure is asking.
   Everything before that is a function of the file alone: which `include_str!`/`include_bytes!`
   sites it has, and what each argument resolves to. So the file's sites are cached and each closure
   is applied to them. Nothing the gate decides changes; only the redundant lexing goes. Expected:
   about 5.5 of the critical path's 24 minutes. Risk: a cache that kept something
   closure-dependent. The test below is built to catch that.
2. **Build xtask optimised** (`[profile.dev.package.xtask]`, or `--release` in the probe engine).
   This would shorten every xtask probe, not just one. But a profile override on `proc-macro2` or
   its dependants changes the fingerprint of the host build of every proc-macro in the workspace,
   which is the compiler-cache seed #3330 just re-pinned. Not taken. It is worth measuring
   separately against the seed.
3. **Parallelise probes inside the pod.** Probes perturb and restore real files in one tree, so
   they must run serially or each in its own copy of the tree. A copy per worker keeps the "one pod"
   (one checkout, one build) and could cut the step by the core count. It is the larger structural
   win and the riskier one: the engine's restore guard and its `main is red` base-tree logic both
   assume one tree. Not taken here.
4. **Split the four gates into separate jobs.** Here "one pod" is a cost choice, not a soundness
   property: the three earlier steps each built `portcullis` and `nucleus-node` on their own runner
   until they were merged into this job. The gate of gates also needs a tree nothing else has
   written to, and this job meets that because cargo's outputs are gitignored. Splitting would move
   the first three steps (about 3.5 min) off the critical path, at the price of three more builds
   per group from a pool that #3339 found saturated. Not worth it while the gate of gates is
   20 minutes.
5. **Narrow the backstop.** The rule that `Cargo.lock` or any manifest selects every probe is there
   to cover undeclared inputs. Weakening it would trade proof for time. Rejected.

## 3. The change and its measurement

`escapes::Lexer` lexes each file once and keeps its sites. `escapes::scan` is now a fresh
`Lexer`'s scan, so the two can only differ through the cache. `test_shards::compile_reads` and
`tests/escapes_population.rs` hold one `Lexer` across every member.

**Proven answer-identical, three ways:**

- Every one of the workspace's 95 crates, scanned by the old code and the new, dumped as `Debug`
  and compared byte for byte: identical (`cmp`). 45 of the 95 have at least one site.
- `tests/escapes_population.rs` now scans the whole workspace through one shared `Lexer` and
  asserts each crate's result equals a fresh scan.
- `escapes::tests::a_shared_lexer_answers_each_closure_as_a_fresh_scan_does` uses one file whose
  read is covered for one closure and escapes for another, in both orders. It was driven red on a
  cache that kept the first closure's prefixes ("b through a shared lexer, order [a, b]"), then
  green when restored.

**Measured, local** (Apple M-series, debug xtask, warm build, `/usr/bin/time -p cargo run -q -p
xtask -- test-shards --check`): **18.45 s → 2.90 s.** Same output: 37 patterns, 13 escaping reads.

**Measured, CI:** see §4 (filled in from the pull request's and the merge group's runs).

## 4. CI before/after

_Pending: filled from this PR's `Live-path gates (one pod)` run and from the first merge-group run
after it lands._

## What this does not claim

- It does not shorten the other 62 % of probe seconds. Option 3 is where those minutes are.
- The local 6.4× ratio need not carry over to the build runner. §4 is the measurement that counts.
- `test-shards` also runs in `gatehouse-plan.yml`, which gets faster too, but that job is not on the
  merge queue's critical path.
