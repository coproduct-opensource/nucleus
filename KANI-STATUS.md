# Kani BMC — what is actually verified

This file exists because the nightly Kani gate reported a coverage claim it had never
achieved. It records what the model checker has proved, what it has not, and the
measurements behind the distinction.

> Reconciled 2026-08-31 against Kani 0.67.0 (the version pinned in
> `.github/workflows/kani-nightly.yml`), run both in CI and locally on the same version.

## Summary

`crates/ck-kernel/src/kani.rs` defines **17** proof harnesses. They fall into two groups,
and the split is exact:

| group | count | drives `Kernel::admit`? | status |
| --- | --- | --- | --- |
| bitmask / lattice tier | 6 | no | **verified** |
| admission-path tier | 11 | yes | **never verified** |

The five fast-tier harnesses run on every PR and push and are green. The sixth,
`proof_refinement_bitmask_agrees_with_btreeset`, bridges the bitmask and `BTreeSet`
representations for the subset check.

**No harness that exercises `Kernel::admit` has ever completed**, in CI or locally.

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

## What a real fix needs

The admission path has to become tractable for CBMC, not merely re-tiered. In rough
order of promise:

1. **Stubbing** (`-Z stubbing`). Kani's documentation names this situation directly:
   code that Kani supports but that verifies badly. Candidates are the `format!`
   rejection-message construction, `chrono::Utc::now()` in `make_witness_for_proof`, and
   the `PolicyManifest` deep clones — none of which the admission *decision* depends on.
2. **A narrower entry point.** The properties under proof are about the decision logic.
   A `#[cfg(kani)]` seam that exercises the invariant checks without constructing a full
   `WitnessBundle` would shrink the program by a large factor.
3. **`BTreeSet<String>` → interned ids** in the verified path, with the existing
   refinement proof extended to cover the encoding.

Until one of these lands, the honest claim is the one at the top of this file: the
bitmask tier is verified; the admission path is not.
