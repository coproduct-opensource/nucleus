# Kani BMC — what is actually verified

This file exists because the nightly Kani gate reported a coverage claim it had never
achieved. It records what the model checker has proved, what it has not, and the
measurements behind the distinction.

> Reconciled 2026-08-31 against Kani 0.67.0 (the version pinned in
> `.github/workflows/kani-nightly.yml`), run both in CI and locally on the same version.
> Revised the same day after further measurement — see *Corrections* at the end.

## Summary

`crates/ck-kernel/src/kani.rs` defines **17** proof harnesses. They fall into two groups,
and the split is exact:

| group | count | touches `BTreeSet<String>`? | status |
| --- | --- | --- | --- |
| bitmask / lattice tier | 5 | no | **verified** |
| refinement bridge | 1 | yes | **never verified** |
| admission-path tier | 11 | yes | **never verified** |

The five fast-tier harnesses run on every PR and push and are green. **Everything else
— 12 of 17 — has never completed**, in CI or locally.

The dividing line is not `Kernel::admit`, as this document first claimed. It is
`BTreeSet<String>`. Every harness that constructs one fails to terminate; no harness
that avoids one does.

### The bridge is part of the gap

`proof_refinement_bitmask_agrees_with_btreeset` is the proof that would let the bitmask
results stand in for the production `BTreeSet` path — it asserts that
`child.is_subset(&parent)` and `(child_bits & !parent_bits) == 0` always agree. It builds
`BTreeSet<String>`, and **it does not verify either** (no result in 7 minutes locally).

So the bitmask tier proves the lattice arithmetic, and nothing formally connects that
arithmetic to the types the kernel actually uses. That gap is worth naming plainly rather
than leaving implied by a passing fast tier.

Note also what the bridge would and would not carry even if it verified: it is a lemma
about **one predicate**. It says nothing about whether `Kernel::admit` calls that
predicate on the right fields, returns `Rejected`, cites `IoConfinement`, or keeps the
rejected candidate out of the lineage — which is what the 11 admission-path harnesses
assert.

## What was wrong before

The nightly ran `-p ck-kernel` as a single job under one 60-minute budget. Its last 30
scheduled runs — every run in the retained history — failed. The log shows why:

```
09:17:57  Checking harness kani::proof_io_repo_write_targets_widening_rejected...
10:15:39  ##[error]The operation was canceled.
```

One harness consumed the entire budget and the other sixteen were never attempted. The
job summary nonetheless advertised "11 symbolic BTreeSet proofs via admit() pipeline" as
nightly coverage. The `Kani (full)` job for `portcullis` failed the same way for a
different reason: it dies after 3–10 minutes with `exit code 143` and "runner has
received a shutdown signal", which is memory exhaustion, not a timeout.

## Measurements

Run locally on Kani 0.67.0, harness
`proof_io_repo_write_targets_widening_rejected`:

| variant | result |
| --- | --- |
| as committed (4-element symbolic universe) | no result in 10 min; cbmc at **3.2 GB** after 3 min, still climbing |
| universe reduced to 2 elements (4 subsets) | no result in 10 min |
| set made **fully concrete** (no `kani::any` at all) | no result in 7 min |

And the simplest harness in the tier, `proof_identical_policy_config_patch_admitted` —
which uses no `symbolic_set` at all:

| harness | result |
| --- | --- |
| `proof_identical_policy_config_patch_admitted` | no result in **10 min** |

The concrete-set row is the informative one. **The symbolic set is not the bottleneck.** With
every nondeterministic choice removed the harness still does not terminate, so the cost
is the size of the code under verification — `Kernel::admit` over `BTreeSet<String>`
policies, with `format!`-built rejection messages and deep `PolicyManifest` clones — not
the state space. Shrinking the universe or rewriting `symbolic_set` will not fix it.

GitHub-hosted `ubuntu-24.04` runners have 16 GB, which is consistent with the
`portcullis` job's OOM signature.

## What the sharding changes

`kani-constitutional-full` is now a matrix with **one job per harness** and
`fail-fast: false`. This does not make an unverified proof verify. It makes the gate
honest and legible:

- each harness gets its own runner and its own 30-minute budget;
- a slow proof can no longer prevent the other sixteen from being attempted;
- a red nightly names exactly which harnesses failed;
- the rolled-up job keeps the original status name, `Kani (constitutional kernel full)`,
  so existing branch protection still resolves.

Expect the nightly to stay red until the admission-path tier is addressed. That is the
correct signal: those proofs are not passing today, and the previous configuration was
red anyway while reporting a coverage claim it had not earned.

## Corrections

This file first proposed three fixes in order of promise. Two were then measured and
**both fail**, so they are struck rather than left standing:

| candidate | verdict |
| --- | --- |
| ~~1. Stubbing (`-Z stubbing`) the `format!` / `chrono` / clone machinery~~ | **struck** |
| ~~2. A narrower `#[cfg(kani)]` entry point avoiding `WitnessBundle`~~ | **struck** |
| 3. Eliminate `String` from the verified path | the only route left |

The measurements that struck them:

| probe | what it removes | result |
| --- | --- | --- |
| `check_monotonicity` called directly, no `Kernel::admit` | 216 lines of lineage, `format!`, `warn!`, `WitnessBundle` | no result in 10 min |
| `parent_policy()` built, then `assert!(pp.version == 1)` | **everything** — no symbolic input, no logic | no result in 5 min |
| `proof_refinement_bitmask_agrees_with_btreeset` | — | no result in 7 min |

The second row is the one that decides it. A harness that constructs the fixture and
asserts a constant does not terminate. There is no entry point narrower than that, and
nothing left for stubbing to remove: the cost is `BTreeSet<String>` construction itself,
roughly ten such fields built from string literals.

This matches what Kani's own engineering writing describes. CBMC's field-sensitivity
transform in 5.85.0 was what first made `BTreeSet` harnesses solvable at all, and it
still degraded runtime on a quarter of the harnesses it was measured against. Heap-backed
collections are a known frontier for this tool, not a misconfiguration here.

## What a real fix needs

Only candidate 3 survives: **the verified path must not build `BTreeSet<String>`.**

That means a representation change, not a harness change — interned ids or bitmasks in
the types the proofs traverse, with a refinement argument connecting them to the
production types. The refinement proof already in the tree is the right shape for that
argument, but it is currently on the wrong side of the tractability line: it builds the
very thing it is trying to bridge. A version over interned ids would verify and would
carry real weight.

Until that lands, the honest claim is narrower than the one this file opened with:

> Five harnesses verify, and they prove lattice arithmetic over bitmasks. Nothing that
> touches the kernel's actual policy types has been verified, and the bridge between the
> two representations is unverified too.
