# trust-atlas (SPIKE)

An egglog-backed trust/maturity atlas over the two-repo verification surface
(`coproduct-opensource/nucleus` + `coproduct-private/spiffy`). It answers two
questions with checkable citations on every fact:

1. `trust-atlas weakest-link` — the end-to-end chain for the receipt claim
   (hub → substrate-core → nucleus-receipt → verifier SDK), per-edge maturity
   + provenance, the MIN, and the path discontinuities.
2. `trust-atlas findings` — gates that exist but are not required on main
   (workflow present, advisory only), plus sorry'd-file findings and live
   `#[kani::proof]` harness facts.

Standalone workspace (own `[workspace]` table, listed in the root `exclude`),
mirroring `tools/nucleus-guarantee-lint`. Build/test inside `tools/trust-atlas`.

```
cd tools/trust-atlas
cargo test
cargo run -- weakest-link
cargo run -- findings [--repo PATH] [--no-live]
```

## Honest scope: what is live vs fixture

| Input | Status |
|---|---|
| Required status checks on `nucleus` main | **LIVE** (`gh api …/branches/main/protection/required_status_checks`), falls back to fixture with a `[fixture]` marker |
| `nucleus` workflow list | **LIVE** (`gh api …/actions/workflows`); the workflow→job-context mapping is still `[fixture]` (the API does not expose job contexts) |
| `#[kani::proof]` harnesses | **LIVE** (grep of `--repo`, file:line provenance; string-literal mentions excluded, matching the fixture's 113-not-114 honesty note) |
| spiffy gates, Lean libs/sorry audit, equivalences, trust path | **FIXTURE ONLY** — `fixtures/recon/*.json`, mined 2026-06-10 by read-only agents and checked in verbatim with a `_provenance` note |

The two reports print provenance for every fact they rest on; `Atlas::citation`
returns an error rather than printing an uncited fact.

## Maturity lattice semantics

i64 ranks; the egglog `maturity` function merges with `(min old new)` — trust
of a composition is the MEET (weakest link). This deliberately mirrors the
repo's own attenuation algebra (`crates/portcullis-core/src/attenuation.rs`):
authority/trust only tightens.

| rank | meaning |
|---|---|
| 5 KernelChecked | Lean sorry-free in CI / Kani BMC |
| 4 ParityPinned | golden-bytes pin, exhaustive parity, extraction-freshness gate |
| 3 PropertyTested | proptest parity |
| 2 Attested | cited file:line evidence, no machine check on the claim itself |
| 1 Stated | claimed in prose / unmerged PR |
| 0 Unenforced | absent edge, advisory-only gate |

Path maturity is min along a path (`edge-maturity` propagation rule), max
across alternative paths. Equivalences from the recon are loaded as
`(union lhs rhs)` — ALWAYS, even when a fragment condition applies; the
condition goes to a side table (`equiv-fragment` + a Rust map) and is printed,
never used to skip the union.

A consequence worth noticing in the `weakest-link` output: the unmerged
re-export claim (rank 1) is unioned with the JCS-pinned `nucleus-receipt`
(rank 4), and min-merge resolves the class to 1 — equivalence transport plus
the meet means an optimistic identity claim *drags down* the pinned side
rather than laundering rank 4 onto the unproven side. That is exactly the
attenuation posture.

## egglog-vs-ascent verdict

**Equivalence transport works cleanly in egglog 2.0 and is the real
differentiator.** Concrete evidence from this build:

- The transport test (`equivalence_transport_makes_facts_queryable_from_the_other_side`)
  passed on the first run: after `(union (Art "a") (Art "b"))`, a `maturity`
  fact asserted on `a` is retrievable querying `b`, with no transport rule
  written by us — congruence closure does it. In ascent (or any plain Datalog)
  we would have had to reify an `equiv(a, b)` relation, write symmetry/
  transitivity rules, and add an explicit `maturity(b, m) :- equiv(a, b),
  maturity(a, m)` rule per fact table — and then hand-resolve the merge
  semantics when both sides carry facts. Here `:merge (min old new)` composes
  with union automatically (`equivalence_transport_min_merges_across_the_union`).
- Lattice semantics are first-class: `:merge` on a function gives meet
  semantics per key with no user-visible aggregation pass. Ascent has lattice
  support too (`lattice` columns), so this alone would not justify egglog;
  the union+merge interaction is what ascent does not give you.
- API ergonomics: mixed. The embedding surface is pleasant
  (`EGraph::default()` + `parse_and_run_program` + matching
  `CommandOutput::ExtractBest`), and error messages carry source spans into
  the embedded string. But querying is stringly: we extract values by
  formatting `(extract (maturity (Art "…")))` and parsing the printed term,
  and "does this fact exist" is `(check …)` mapped through `Result`. Ascent,
  being a proc-macro over Rust types, would give typed tuples back for free.
  For a CI tool this matters; for a spike it was fine. (egglog's typed
  `command_macro`/`prelude` layer exists but the textual program was faster
  to iterate on and keeps the model readable as one `.egg` file.)
- Perf at this scale is a non-issue: ~60 base facts, 3 rules, `(run 64)`
  saturates in well under a millisecond inside the test suite; the whole
  test binary runs in ~0.1 s. Neither engine would be the bottleneck —
  `gh api` latency dominates the live path.
- Two small footguns we actually hit: `(run N)` emits a `RunSchedule` report
  whose `Display` is empty-ish, so naive "first output" parsing is wrong — you
  must pattern-match `CommandOutput::ExtractBest` specifically; and
  `(extract …)` on a key with no function entry returns `Err` rather than an
  Option, so absence-vs-error is conflated unless you treat extract failures
  as "no fact" (we do, and accept the coarseness for a spike).

Verdict: keep egglog for the atlas. The recon ground truth is full of
"X == Y modulo fragment" claims, and union-with-min-merge models exactly
that — including the honest failure mode where an unmerged identity claim
weakens the class instead of strengthening the weak side.

## Next steps

- More live extractors: workflow→job-context mapping via the Actions runs API
  (jobs of the latest run per workflow), sorry-token grep over the Lean tree,
  parity-test discovery by walking `tests/*parity*.rs` headers.
- CI ratchet: commit a baseline (`unenforced gate count`, `end-to-end min`)
  and fail the job when a finding regresses — same shape as the proof-count
  ratchet that the findings report shows is itself currently unenforced.
- Promote the chain definition from a hardcoded 4-node constant to fixture
  data so other claims (e.g. the econ golden-vector chain) get the same
  treatment.
- Wire `nucleus-wasm`'s closed-source verification edge in as an explicit
  alternative path so `path-maturity`'s max-across-paths semantics earns its
  keep (today there is exactly one path and it is broken in three places).
