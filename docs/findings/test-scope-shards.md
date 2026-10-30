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

## 7. Live on the lanes: a PR waits less and the lanes spend more (2026-10-06; the cause given here is corrected in §8)

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

## 8. §7 compared two seeds' ages, not two layouts (corrected 2026-10-06)

**The wrong belief in §7:** that the shards recompile 41-48 registry crates because each shard
resolves a different feature set from the whole-workspace build its seed came from, so each shard
needs a seed of its own. The "old `test`: 3 registry crates, 329 s" baseline in §7 came from early
on 2026-10-06, when seed `main-160a26deb` still matched main. The shards ran after main had moved.

Measured from controld's receipts (`sandbox.cache.compiled_registry` and duration), every run on
seed `main-160a26deb-x86_64-t`:

| old `test`, by hour (UTC) | runs | registry crates recompiled | mean time |
|---|---|---|---|
| 03 | 5 | 0-2 | 353 s |
| 04-06 (#3238's rmcp 2.2 merged 04:41; #3230/#3231 added `nucleus-node-evidence` at 00:46/01:25) | 24 | 0 then 66 | 309-412 s |
| 07-16 | 24 | 66-67 | 427-477 s |

**At the same drift:**
- **Old `test`** recompiled 67 registry crates in about 447 s.
- **`test-node`** recompiles 41-44 in 292 s (mean of 21 runs).
- **`test-libs`** recompiles 112 in 379 s (6 runs). Its step 0, the verifier SDK's wasm build,
  accounts for 64 of them; that step was seeded too, and its units went stale with the rest.
- **Both shards per tree:** about 671 lane-seconds against 447 (+50%), and a wait of about 379 s
  against 447 (-15%).

**So the cause is a stale seed, not a per-shard mismatch.** With workspace feature unification, the
shards' units are the full build's units (gatehouse docs/sublinear-testing.md §5: 0 units differ,
and a shard at the seed's own tree compiled 0 crates). A dependency change anywhere in the
workspace changes registry units for every build, the old `test` included. Per-shard seeds would go
stale exactly the same way. The lever is keeping the seed fresh: gatehouse
docs/seed-freshness-2026-10-06.md measures it (stale for about 72% of seeded `test` and `clippy`
runs over the week, about 13% of all gate time) and designs automatic re-minting.

**What §7 still gets right:** the shards cost more lane-seconds per tree than the old gate whenever
both run. The +50% at equal drift is the honest number. Whether the reuse of `test-libs` on
node-only trees repays it still needs measuring over real pull requests, after the seed is fresh.

## 9. A config filter the `test-libs` pod cannot see, and #3512's heads by lane (2026-10-30)

**The defect.** `2c51b6d34` (#3508's `55dbe3dae`) added a `.config/nextest.toml` override with
the filter `binary_id(nucleus::child_seccomp)`. nextest refuses a `binary_id()` or `binary()` that
names no test binary it knows of, and it checks that when it loads the config, before it builds.
`test-libs` runs in a materialized pod. Its scope excludes `crates/nucleus/*/*/**`, so `nucleus`
has no test targets there. The whole config was refused, exit 96:
`failed to parse profile.default.overrides at index 3 … no binary IDs matched this`. That was
#3512 at `8134a7c50`, gatehouse leaf 18146, on the classic arm64 lane.

**Red, then green.** Both were run in an arm64 Apple `container` (rust 1.96.1, cargo-nextest
0.9.145), with the plan's step-1 argv for `test-libs`.
- **The pod's file set**: `git ls-files`, kept if it matches the gate's `scope` and dropped if it
  matches its `exclude`. 1381 of 2774 files.
- **The old filter**: refused, exit 96, with 0 crates compiled. This is the red.
- **A full checkout**, with the same `--exclude nucleus` argv and the old filter: it parsed and
  ran 6463 tests, all passing. So `--exclude` was not the cause. The missing files were.
- **Also refused in the pod**: `package(nucleus) and binary(child_seccomp)` ("no binary names
  matched this"), the regex forms `binary_id(/^nucleus::child_seccomp$/)` and
  `package(nucleus) and binary(/^child_seccomp$/)`, and `binary_id(=nucleus::child_seccomp)`.
- **`package(nucleus) and kind(test)`** parsed in a fresh pod. 6463 tests ran and all passed.
  This is the green.
- **With `nucleus` in the run** (`-p nucleus`, its three test binaries), the new override still
  applies. Every passing test showed its output, including `child_seccomp`'s stderr
  `control: unshare ok / clone ok`. With the override removed, none did.
- **The price.** `child_landlock` and `child_workspace` now show their passing output too.

`verifier-js/pkg` was a stand-in in those runs, with its digest appended to
`embedded-wasm.pins` in the scratch copy only. That changes what is embedded, not how nextest
reads its config. The first green attempt failed to build, with `E0463` ("can't find crate")
in `nucleus-federation`'s tests. A rerun with nothing changed built and passed. Cause not found.

**#3512's previous head, `8134a7c50`, was decided on the classic lane.** This note was at
`tools/test-shard/classic-lane-2026-10-30.md` and is moved here. `tools/**` is a constitutional
path, so it made #3512 a guardrail change for a note. The facts from that note:
- `7a61338f8` (tree `384ec3bf4`) was decided on the trusted-launch lane, node `node-9e7b2c870`.
  Eight required gates held.
- `clippy-libs` (leaf 18120) and `test-libs` (leaf 18126) failed with
  `unshare: Operation not permitted`. Their recipes `unshare` a mount namespace to put the
  workspace where the verifier SDK's digest pins it. The trusted launcher refuses that. The
  launcher's workspace bind replaces it, but only for a plan that declares `checkout_at`, and
  main's served plan does not yet (#3511, gatehouse F-322).
- On the classic stack (node `cb47c1b64`, agent `6ed2dfda7`) those `unshare`s run.
  `clippy-libs` held there. `test-libs` hit the defect above.
- **Do not run a plan that declares `checkout_at` on classic.** The classic agent parses steps
  with `deny_unknown_fields` and refuses the job (gatehouse F-325).

**A wrong assumption.** The old note expected `text-north-star`'s held trusted-launch receipt
(leaf 18123) to be reused, because the note did not change that gate's scope. The classic worker
ran the gate anyway, and it failed on the node's `svid_key_later_fetch` breach (leaf 18143). That
failure then also decided `text-north-star` for `7a61338f8`, whose explain page flipped from
held to failed. The receipt lookup is keyed on `(gate_def, scope)` and takes the newest receipt,
whichever lane signed it. This section is under `docs/**`, which is in `text-north-star`'s scope,
so this head re-decides that gate. It runs on the trusted-launch lane.

## Not yet

* ~~**The plan.**~~ Done 2026-10-05, see §5.
* **The fixtures were re-measured 2026-10-06 at `160a26deb`** (strace and dep-info on a spot VM):
  every read a `test-libs` crate makes falls inside the generated scope, except
  `sdks/verifier-js/pkg/*`, which step 0 writes in the pod and step 1 reads, an output rather than a
  tree input. One new crate's probes were added to the layout. Serial test work grew from 303 s to
  362 s.
