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

## portcullis: what the per-PR harnesses prove

`crates/portcullis/src/kani.rs` runs five harnesses on every PR and push (the `Kani` job
in `kani-nightly.yml`). Every one of them traverses `CapabilityLattice` or `ExposureSet`,
and both types are **narrower under Kani than in production**: their `extensions` field
(`BTreeMap<ExtensionOperation, CapabilityLevel>` / `BTreeSet<ExtensionExposureLabel>`) is
`#[cfg(not(kani))]`, for the same reason the ck-kernel tier above never terminates — CBMC
cannot construct the heap-backed collection. So `meet`, `join`, `leq`, `union`,
`is_superset_of`, the Heyting `implies`, the permission digest, and
`UninhabitableState::is_triggered` all take a different path in the proof than in the
binary.

Every such site is enumerated with a justification in `kani-divergence.toml`, and
`scripts/check-kani-divergence.sh` (the `cfg(kani) divergences are inventoried and
ratcheted` job) fails on an unlisted site, a stale entry, or any growth of the total
against the PR base. The count is 62 sites in 41 distinct (file, attribute, guarded line)
groups; 11 are harness modules that change nothing, 26 are the mechanical struct-literal
consequences of the two omitted fields, and the rest are the operations and predicates
listed below.

The harnesses are therefore relabelled here as **`*_core_dims`** proofs. The source
names are unchanged for now (the `--harness` arguments in the workflow and the proof-count
census key on them); the label states what each one actually establishes.

| harness (as `*_core_dims`) | proves | does **not** prove |
| --- | --- | --- |
| `proof_capability_distributive_core_dims` | meet distributes over join on the 13 core capability dimensions | the same law on extension dimensions — covered by `test_extension_mock_matches_production_btreemap` (exhaustive, 2 keys × 4 states), not by BMC |
| `proof_exposureset_monoid_identity_core_dims` | `empty()` is the two-sided identity of `union` on the three frozen labels | identity for the extension-label set half of `union` (set union with `{}`; true by construction, not machine-checked) |
| `proof_exposureset_uninhabitable_iff_count_three_core_dims` | `is_uninhabitable() ⟺ count() == 3` | nothing narrower: both sides read only the three core bools in every build, so this one is exact for production too |
| `proof_operation_exposure_completeness_core_dims` | every `Operation` maps to a core `ExposureLabel` set as specified | anything about extension exposure labels (none are attached to operations today) |
| `proof_clinejection_blocked_core_dims` | the CLI-injection path is denied given the core `UntrustedContent`/`ExfilVector` exposure | denial decisions that depend on `required_ext_labels`: `is_triggered` sets `ext_met = true` under Kani, so a combo with extension requirements is proved *at least as* denied as production, not equal to it |

Two sites are semantic divergences rather than domain narrowings, and are worth naming
outside the table:

- **`certificate.rs` permission digest** omits the extension bytes under Kani. Any digest
  property proved under Kani holds for extension-free permissions only.
- **`uninhabitable_state.rs` `is_triggered`** treats every required extension label as met
  under Kani. The direction is fail-closed (the verified predicate denies at least as often
  as production), but it is not the production predicate; the extension cases are covered
  by two unit tests only.

The way out is the one KANI-STATUS already names for ck-kernel: a Kani-tractable
representation for the extension dimensions (fixed slots or interned ids, as `LedgerCore`
did for the budget ledger) with a refinement argument to the `BTreeMap`. Until then the
divergence total in `kani-divergence.toml` may only shrink.

## What runs today

`src/kani.rs` carries `#![cfg(kani)]`, so **its harnesses compile only under `cargo kani`** —
the twelve that never verify contribute nothing to any ordinary build. Enumerated
stand-ins now live in `src/lib.rs` under `mod tests::enumerated_admission` and run on every
`cargo test`.

They are not a weaker substitute at the fixture's size. Each harness's symbolic domain is
four `kani::any::<bool>()` over a four-element universe — sixteen subsets — so enumeration
is equivalent in strength; three of the twelve contained no `kani::any` at all. The
exception is `proof_budget_escalation_always_rejected`, a genuine forall over 480 symbolic
bits, where the stand-in checks the eight per-field boundaries and is explicitly weaker.

The stand-ins also assert what the harnesses never did: that the decision **cites the
axis-specific invariant**. `admit` runs eight gates before the monotonicity check, so
`matches!(d, Rejected { .. })` alone stays green while the gate a harness is named after
rots. `AdmissionDecision` has four variants, so `Rejected` is a strictly stronger claim
than "not accepted". A control case asserts an identical policy is *accepted*, without
which every rejection case could pass vacuously.

If Kani ever handles `BTreeSet<String>`, the harnesses reclaim the unbounded quantifier
for free. These tests are the floor, not the ambition.

Until that lands, the honest claim is narrower than the one this file opened with:

> Five harnesses verify, and they prove lattice arithmetic over bitmasks. Nothing that
> touches the kernel's actual policy types has been verified, and the bridge between the
> two representations is unverified too.
