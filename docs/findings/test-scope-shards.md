# The test suite as two scope shards: what generating them found (2026-10-05)

`cargo xtask test-shards` generates `test-node` and `test-libs` from `.gatehouse/test-shards.toml`,
`cargo metadata`, the tracked files and `.gatehouse/shards/base.json` (until the shards entered the
plan, `.gatehouse/gates/test.json`); `tools/test-shard` writes the
stubs a shard's pod needs and execs the run. The design and the measurement behind the two-shard
layout are gatehouse's `docs/sublinear-testing.md` (§3–4, §4a); the prototype was nucleus#3138.
Three things turned up writing the real one, each on nucleus `0462daae3`.

## 1. The measured layout was already stale, and the generator refused it

The layout was measured on `2fc73eda` (2026-10-02). `nucleus-microvm-host` was added after that
tree (#3070) and depends on `nucleus-spec`, a `test-node` crate. In `test-libs`'s pod
`nucleus-spec` is an empty stub, so `test-libs` would have failed to BUILD. The generator's
closure check (a `test-libs` package whose tests build a `test-node` crate) refused the layout:

```
test-libs packages whose tests build a test-node crate ...: ["nucleus-microvm-host -> nucleus-spec"]
```

`nucleus-microvm-host` moved to `test-node`. A layout is a function of the dependency graph, and
the graph moves weekly; that is why the generator, not a person, decides whether it still holds.

## 2. The coarse scope's first spelling was not derivable; 53 patterns is

The point of `test-libs`'s scope is that the writ kernel DERIVES its hash: an asserted hash never
lets a receipt cross a tree (gatehouse F-182). Measured with gatehouse's
`gate scope witness <def> --repo . --tree HEAD --check` (gatehouse#263):

| spelling of `test-libs`'s scope | includes | excludes | patterns | at `0462daae3` |
|---|---|---|---|---|
| one exclude per top-level entry of each `test-node` crate; SDK inputs listed one by one | 28 | 46 | 74 | **refused** `error[Capacity]` |
| `crates/<c>/*/*/**` per crate plus its loose files; `sdks/verifier-js/**` with its outputs excluded; `tools/test-shard/**` | 18 | 35 | **53** | **derived** `44616e52…` |

74 is exactly the count gatehouse measured refused on 2026-10-02 (65–69 derived). Computed over
the tracked files, the 74-pattern spelling selects 1,207 and the 53-pattern one 1,211: the same
files plus four the wider SDK include now binds (`sdks/verifier-js/{.gitignore,README.md,demo.html,
demo.js}`) — more than the shard reads, never less. `test-node` (`**`) derives
(`31860339…`). `crates/<c>/*/**` would have been one pattern cheaper and wrong: `**` matches zero
segments, so it also matches `crates/<c>/Cargo.toml`, and an exclude always wins over an include.

**The headroom is about a dozen patterns.** Each new `test-node` crate costs at least one, each
loose top-level file in one costs one, and each fixture outside `crates/` costs one.
`cargo xtask test-shards --gate <gate>` refuses a scope that stops deriving; it is not wired in
yet because the pinned gatehouse predates `--check`.

## 3. A shard pod builds: measured

The `test-libs` selection materialized from the generated scope (1,211 of 2,394 tracked files),
then:

* `cargo metadata` before the runner: **refused** (`failed to load manifest for workspace member
  crates/nucleus-perf`) — the reason the runner exists.
* the generated runner step, with its command replaced by `cargo metadata`: **43 stubs written,
  93 members loaded**, exit 0.
* `cargo check --tests --keep-going` over the shard's selection (`--workspace --exclude` the 14
  `test-node` packages) with workspace feature unification: **one failure,
  `nucleus-verifier-service`'s build script**, which reads `sdks/verifier-js/pkg/` — the output of
  the shard's step 0, which this check did not run. Nothing else failed.

The full nextest run in the gate image has not been made.

## 4. `gate-defs` does not compare scope excludes

`crates/xtask/src/gate_defs.rs` compares the plan and the gate definitions on "scope inclusion",
and says so: "scope exclusions are not part of this comparison". Until now no gate had an exclude,
so nothing was missing. `test-libs` has 35. When the plan declares it, the comparison must cover
excludes, or the plan the kernel admitted and the selection the lane hashes can differ in exactly
the part that makes the shard derivable. **Done 2026-10-05:** `gate-defs` compares `scope.exclude` with the plan's `exclude`
(absent in a plan elaborated by an older gatehouse, which reads as excluding nothing), with a test
each way round.

## 5. In the plan: the kernel's glob order is not the selection's glob order

The shards entered `pipeline.writ` on 2026-10-05 (gatehouse pinned at `efa1e1a`, which has
`Gate.exclude`), as terms `cargo xtask test-shards` renders from the same JSON it writes, so the
plan and the executor definitions agree by construction and `gate-defs` still checks them against
the kernel's own elaboration. The first rendering was **refused by two conjuncts**, found by
binding each conjunct as its own `So` term:

* **`writesOutsideScope_b`.** test-libs declared each stub as a write, one path per file
  (`crates/nucleus/src/lib.rs`), inside an exclude `crates/nucleus/*/*/**`. **I assumed the
  kernel's `coveredGlob` matched what `gatehouse-scope` and this repository's `glob_match` match.
  It does not:** probed directly, the prelude derives `crates/nucleus/src/lib.rs ⊑
  crates/nucleus/src/**` and `crates/nucleus/*/*/** ⊑ crates/**`, but **not**
  `crates/nucleus/src/lib.rs ⊑ crates/nucleus/*/*/**` and not `… ⊑ crates/nucleus/*/**` — its order
  has no single-segment `*`. So the exclude arm of `insideScope` never fired for the `*/*/**`
  excludes, the one exclude form the derivation caps admit (§2), and every stub under one read as
  a write into the scope. Fixed in the generator, not by widening anything: a stub is DECLARED as
  the exclude that holds it (each `crates/<c>/*/*/**` holding one, plus the literal files and
  test-node's `src/**`/`tests/**`), which the kernel derives by reflexivity. That is also the
  truer statement — the gate may write where its selection carved the node crates out — and it no
  longer moves when a test file is added. The runner still gets one `--stub` per path.
* **`bounded_b`.** The ceiling's `**` has no top in that order either (probed: `.env`, `lib.rs`,
  `tools/test-shard/**` are not `⊑ **`), so test-libs's explicit reads had to be listed in the
  ceiling, as every other gate's already were; and the ceiling's writes gained `crates/**` for the
  stub regions. The plan's comment above `ceiling` says why that admits no write a gate could use
  against what it verifies (`writesOutsideScope_b` still refuses writes inside a gate's own scope).

This is gatehouse F-186's shape one level down: F-186 said a stub wildcard must not name
test-libs's own crates; it did not say a stub path must be derivably inside its exclude, because
the excludes it was tested with were `crates/<c>/**`, which the order handles.

## 6. Stubbing every target made test-libs move with every node test file (2026-10-06)

**The wrong belief:** every target `cargo metadata` reports needs a stub, or cargo cannot load
the workspace. The generator stubbed all 49 of them: roots, and every `tests/*.rs` of every node
crate. Then #3227 and #3238 each added a test file to a node crate. Each one changed test-libs's
definition and the plan hash. Every open pull request's committed generation then went stale
against main: CI checks the merge commit, and `test-shards --check` went red on pull requests
that touched no node crate (#3225, run 37413103259).

**What is true:** cargo needs a file only for a crate's roots (`src/lib.rs`, `src/main.rs`) and
for targets the manifest DECLARES. A target it merely discovered under `tests/`, `benches/`,
`examples/` or `src/bin/` needs no stub: in test-libs's pod that directory is excluded, an absent
directory discovers nothing, and that is not an error. `load_bearing` in
`crates/xtask/src/test_shards.rs` keeps only those, which is 18 stubs. Adding a test file to a
node crate no longer moves test-libs.

**Method:** test-libs's selection was materialized from `git ls-files` with the gate's own
include and exclude patterns (1,234 files). The gate's runner then wrote the 18 stubs and ran
`cargo metadata --no-deps --offline`, which loaded all 94 workspace members, exit 0. The lane run
is still the real measurement.

## 7. Live on the lanes: a PR waits less and the lanes spend more, because the seed is `test`'s (2026-10-06)

#3225 merged at 15:58Z. Its push set plan `e35be2e0` at 16:03Z through the OIDC upload, with
nobody touching it, and the shards ran on the x86 lanes within the hour. Both passed. Measured from
each attempt's `controller.log`: the step time, and `gate_cache`'s compile counts. Every run was on
seed `main-160a26deb`.

| gate | runs | step time | compiled workspace / registry |
|---|---|---|---|
| old `test` (same seed, earlier today) | 4 | 320-352 s, mean 329 s | 35-38 / **3** |
| `test-node` | 3 | 257-276 s | 45 / **41** |
| `test-libs` | 2 | 263-267 s | 62 / **48** |

**What it means:**
- **Wait:** a pull request's wait falls by about 60 s (329 s against ~265 s in parallel).
- **Cost:** lane-seconds rise to about 530 s whenever both shards run (+60%).
- **The cause:** the registry recompiles. The seed was harvested from the old whole-workspace
  `test` build. Each shard resolves a different feature set (`--workspace-features`, and its own
  package selection), so 41-48 registry crates no longer match the seed's artifacts and are
  rebuilt every time.

**The wrong belief:** that a shard inherits `test`'s seed for free because they share the image,
tools and seed pin (`.gatehouse/shards/base.json`). They share the pin, not the compilation.

**What follows:**
- **Per-shard seeds.** Each shard needs a seed built from its own command, so its registry count
  returns to near zero. That is the harvest work already pending (gatehouse
  docs/sublinear-testing.md); the shards make it a requirement, not an optimisation.
- **Not yet measured:** whether `test-libs` is reused across trees whose changes touch only node
  crates. That is the saving the shards exist for, and it needs scope-derived reuse to happen on
  real pull requests. Re-measure lane-seconds per PR once per-shard seeds land, over enough PRs to
  see the reuse rate.

## Not yet

* ~~**The plan.**~~ Done 2026-10-05, see §5.
* **The fixtures were re-measured 2026-10-06 at `160a26deb`** (strace and dep-info on a spot VM):
  every read a `test-libs` crate makes falls inside the generated scope, except
  `sdks/verifier-js/pkg/*`, which step 0 writes in the pod and step 1 reads, an output rather than a
  tree input. One new crate's probes were added to the layout. Serial test work grew from 303 s to
  362 s.