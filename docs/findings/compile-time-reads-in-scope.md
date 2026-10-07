# A shard scope must hold what its build reads at compile time (2026-10-07)

nucleus#3287 restores #3254's test block in `crates/nucleus-node/src/upstreams.rs`, which reads
the shipped example registry with
`include_str!("../../../examples/egress-git-remote/upstreams.toml")`. The change was correct and
`gatehouse/required` went red anyway: `clippy` (later `clippy-node`) failed with exit 101.
The gate's scope did not include that file, so a pod materialized from the scope does not have it.

**That was one of two defects, and not the first one the pod hit.** clippy-node also lacked
`tools/test-shard/**`, the runner its only step builds. That fails every tree, before any lint
runs, and the red was reused across trees (docs/findings/clippy-split.md, nucleus#3296). The
reproduction below ran `cargo clippy` directly, skipped the runner, and so saw only this defect.
**The wrong belief: that a reproduction leaving out the gate's wrapper reproduces the gate.** Both
defects are real. With #3296's runner fix alone, #3287's tree still fails: running the gate's own
argv (`-p nucleus-node`) over that scope (1,920 files) gives the same `couldn't read …` error,
exit 101.

## 1. Reproduced: the scope, not the change, is what fails

The `clippy-node` scope at #3287 rebased onto `2a360ad90` (1,917 tracked files), materialized into
an empty directory, then, outside the runner,
`cargo clippy --offline --all-targets --all-features --locked --no-deps -p nucleus-node -- -D warnings`:

```
error: couldn't read `crates/nucleus-node/src/../../../examples/egress-git-remote/upstreams.toml`: No such file or directory (os error 2)
error: could not compile `nucleus-node` (bin "nucleus-node" test) due to 1 previous error
exit=101
```

The same command over the regenerated scope (1,918 files, the one added being the example):
exit 0.

## 2. The wrong belief: #3289 might already have fixed it

It could not have. #3289 changed how `test-libs` and `clippy-libs` EXCLUDE an excluded crate's
top-level files. `clippy-node`'s scope is not computed at all: it is the hand-written include list
of `.gatehouse/shards/clippy-base.json`, copied through. Nothing derived any of the four shard
scopes from what the sources read; `test-libs`'s `[fixtures]` are an strace measurement dated
2026-10-02/06, and "Re-measure before trusting a regeneration made long after this date" was the
only guard. A measurement cannot see a read added after it.

## 3. The fix: the generator derives compile-time reads from the source

`cargo xtask test-shards` now runs `nucleus_action_key::escapes::scan` (a `proc_macro2` token
walk, the same one the escapes ratchet counts with; not a regex, per gatehouse F-144/F-152) over
each workspace member's build closure, with the generator's own closure (dev-dependencies at the
root, normal and build edges below). Every literal `include_str!`/`include_bytes!` target outside
the closure is then:

* tracked, in a node package: appended to `test-node`'s and `clippy-node`'s includes when no
  existing pattern covers it (with #3287's reader: `examples/egress-git-remote/upstreams.toml`, the
  only one);
* tracked, in a libs package: made a fixture when nothing covers it, so it is kept inside an
  excluded node crate or included outside `crates/` (today: none, all already covered);
* untracked: refused unless a declared write produces it (today: the verifier SDK's `pkg/`).

Each generated scope is then checked to cover its group's reads, so a later edit to the
generation cannot drop one silently. Reads a token walk cannot resolve (`concat!(env!(..))`,
`OUT_DIR` joins) are printed, not assumed covered: there are **0** at this tree.

Measured on `2a360ad90`: 12 escaping (package, site) reads, 3 distinct tracked node targets, 2 libs;
with #3287's reader, 13 and 4. The escapes ratchet counts the same 13.

## 4. The derivation cost (gatehouse F-208): one leaf, one pattern

`gate scope witness <def> --repo . --tree HEAD --check`, gatehouse `cb55244` with the certificate
size printed (method of F-208); `MAX_ROWS` is 2^22 = 4,194,304 and reduction rows are the largest
table for every scope:

| scope | patterns | reduction rows | of the cap |
|---|---|---|---|
| clippy-node before | 19 | 3,332,773 | 79.5 % |
| **clippy-node after** (this change alone) | **20** | **3,382,925** | **80.7 %** |
| clippy-node with #3296's `tools/test-shard/**` too | 21 | 3,440,901 | 82.0 % |
| clippy-libs (unchanged) | 34 | 3,316,954 | 79.1 % |
| test-libs (unchanged) | 37 | 3,440,088 | 82.0 % |
| test-node (unchanged, `**`) | 1 | 3,241,191 | 77.3 % |

test-libs and clippy-libs agree with F-208's figures at #3289 (3,439,494 and 3,316,388) to within
the files added since, which is the calibration. All four derive.

## 5. Two gaps this change found, one closed

**`test-shards --check` did not run on the change that needed it.** It runs only in
`gatehouse-plan.yml`, whose `pull_request` filter is `.gatehouse/**`; #3287 touched no file there.
Closed by a unit test in xtask, `the_committed_shard_scopes_cover_every_compile_time_read`, which
recomputes the reads and checks the four committed scopes. xtask's tests run in `test-node`, whose
scope is `**`, so a new `include_str!` outside a shard's scope reds there with the file named.
Driven red first: against the committed `clippy-node.json` of `2a360ad90` it fails naming
`examples/egress-git-remote/upstreams.toml`; regenerated, it passes.

**A change that needs a scope widened cannot go green by itself (not closed).** controld runs
every PR under the plan it SERVES, and the plan is uploaded from `main`. The evidence is #3287's
first verdict: its tree (`657ca8135`) declared `clippy-node` and `clippy-libs`, and the verdict
ran and failed a gate named `clippy`, the unsplit gate of the plan production was then serving
(`f640ab13`, F-208). So #3287's own regenerated `clippy-node.json` changes nothing for #3287.

The widening therefore lands first, from a tree with no reader, where the generator has nothing to
derive: `.gatehouse/shards/clippy-base.json` names `examples/egress-git-remote/upstreams.toml` by
hand, last in its include list. The generator appends a derived read last too, so when #3287
removes the hand entry its regeneration is byte-identical (checked: `clippy-node.json` and
`pipeline.writ` from the hand entry on `main` equal those derived at #3287), and #3287 changes no
gate definition. The general case wants controld to run a PR whose plan is kernel-admitted under
that plan, or the queue to order a plan change ahead of its readers; neither exists.
