# text-gates, split by what each check reads (2026-10-06)

**Why:** `text-gates` ran eleven grep-style checks in one gate that declared `git_history`. A gate
keyed on the commit is never reused across trees, so none of its verdicts ever were. Measured in
gatehouse `docs/reuse-misses-2026-10-06.md`, that was about 27% of nucleus gate time.
gatehouse `docs/narrow-scopes-counterfactual-2026-10-06.md` (#292) priced grouping by read set at
about +$12/week, and found one gate per check loses money (a fixed ~22 s per attempt).

**The wrong belief:** that the checks needed `git_history` because they call `git`. `git_history`
means "my answer depends on ANOTHER commit". Only `check-kani-divergence.sh` does that (it fetches
the base ref). Five others need a repository, but only read THIS tree: `git ls-files`, `git grep`,
or `rev-parse --show-toplevel` with no fallback. gatehouse's `git_checkout` exists for exactly
that, and costs no reuse. The other five need no git: their `rev-parse` falls back to `.`, or they
use none.

## Classification

| check | git | what it reads | gate |
|---|---|---|---|
| check-kani-divergence | `git fetch` / `cat-file` of the BASE ref | crates/**/*.rs, kani-divergence.toml, base ref | **text-history** (`git_history`) |
| check-verify-strict | rev-parse (fallback) | crates/ (rg *.rs), verify-strict-allowlist.txt | text-sweep |
| check-sandbox-trusted-base | rev-parse (no fallback), `git ls-files crates` | crates/**/*.rs, sandbox-trusted-base.txt, .sandbox-unpinned-ceiling | text-sweep (`git_checkout`) |
| check-failclosed-verifiers | rev-parse (no fallback), `git ls-files crates` | crates/**/*.rs | text-sweep (`git_checkout`) |
| check-extracted-callsites | rev-parse (fallback) | extracted-callsites-manifest.txt + the crate files it names | text-sweep |
| check-declassify-governor-keys-sealed | `git grep -- '*.rs'` (every tracked .rs in the pod) | crates/**, tests/** | text-sweep (`git_checkout`) |
| check-mediation | rev-parse (fallback) | crates/{nucleus,nucleus-tool-proxy,nucleus-mcp}/src, 3 allowlists | text-narrow |
| check-task-compiler-offline | none | crates/nucleus-task-compiler/** | text-narrow |
| check-ingest-hashed | rev-parse (fallback) | 5 crates' src, ingest-hashed-allowlist.txt | text-narrow |
| check-sealed-home | rev-parse (fallback) | crates/portcullis-effects/src, sealed-home-allowlist.txt | text-narrow |
| check-north-star-ledger | rev-parse (fallback) | docs/north-star.md, ratchet, .github/workflows/, and any evidence path the ledger cites | **text-north-star** (old scope, whole) |

**Method:** read each script for `git` invocations and for every path it opens or searches
(`SCOPE_DIRS`, globs, manifest-named files). No script calls or sources another.

- `text-north-star` keeps the old scope whole, because its evidence paths come from the doc and
  can name anything the old gate saw.
- `text-sweep` keeps `tests/**`, because `git grep -- '*.rs'` saw `tests/` under the old scope.

## The gates

| gate | scope patterns | derives at HEAD | measuredMs (estimate) | timeout |
|---|---|---|---|---|
| text-history | 3 | no, by design: keyed on the commit | 79,454 | 360 s |
| text-sweep | 11 | yes | 397,272 | 1,620 s |
| text-narrow | 15 | yes | 317,818 | 1,320 s |
| text-north-star | 8 | yes | 79,454 | 360 s |

measuredMs is the old 874 s split by check count, an ESTIMATE until the first runs measure it.
Each timeout is about 4× its estimate, inside `timeoutMeasured_b`'s 2-10×.

## Nothing dropped

`ci/gatehouse-replacements.txt` maps each of the eleven retired contexts to the gate that now runs
its script. ci-spec CI-RP-2 requires every command the replaced context ran to be one its gate
runs.

**Driven red:** removing `scripts/check-mediation.sh` from `text-narrow` gives
`CRITICAL [CI-RP-2] … Mediation backstop gate (North Star) … runs scripts/check-mediation.sh, and
gate text-narrow does not`. Restoring it makes it green.

## What CI-RP-2 had been passing by accident

Splitting surfaced a false finding. The kani relay's error text quotes its step's name,
"…justified; the total only shrinks". CI-RP's tokenizer splits on `;` even inside quotes, so it
read a program named `the`. Under the single gate, the eleven scripts' combined text happened to
contain a part starting with `the`, so it was "covered".

The general point: **a gate built from many scripts can satisfy CI-RP-2 for one context with
text from another context's script.** A narrower gate is a stricter test of the replacement claim.
The step name is reworded here ("…justified, and the total only shrinks"). The tokenizer's
quote-blindness is left for a separate change to ci-spec.

## Not yet measured

- **Reuse:** #292's +$11.69/week assumed three groups, with kani inside the sweepers and
  declassify inside the narrow group. The actual split is four gates, one more 22 s attempt per
  tree, roughly −$3/week, so expect about +$8-9/week. Re-measure from receipts after a week.
- **Per-gate times:** these are estimates until the lanes report them.
