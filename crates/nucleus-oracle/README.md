# nucleus-oracle

A self-contained, **deterministic**, sandboxed **held-out grading oracle**.

Given a solver's *recorded* execution outputs bundled against a grading bundle,
`nucleus-oracle` decidably produces a grade plus a tamper-evident `GradeReceipt`,
and **quarantines** submissions that show oracle-gaming signals. It is the layer
that *populates* rubric grades with the correct, honest `nucleus-rubric`
provenance, so a downstream `Rubric` ranks only the one load-bearing dimension.

It mirrors the load-bearing primitive of `nucleus-recompute` / `nucleus-eval`:
re-derive outputs from declared inputs and accept a number only when a re-run
reproduces it byte-for-byte.

## HONEST SCOPE (read this first)

- **It grades RECORDED outputs. It executes nothing.** No subprocess, no network,
  no LLM. The live solver run that *produced* those outputs is a separate concern
  handled outside this crate. Every signal here is a pure, deterministic,
  integer/byte-only computation over recorded data.
- **Only the exact held-out recompute is load-bearing.** The pass-rate
  `matched / total` over held-out cases (by byte-equality) is the only dimension
  tagged `Provenance::RecomputeVerified`. It is the only number allowed to move a
  downstream rank.
- **MR-coverage and mutation-kill are STATISTICAL adequacy signals — carried, not
  load-bearing.** A metamorphic relation that is exact and byte-checkable is
  recompute-verified *as a boolean*, but the interpretation of MR *coverage* (how
  many hold) as quality is statistical. Likewise mutation kill-score answers "do
  the held-out cases have teeth?", which is test-adequacy, not a correctness
  proof. Both are tagged `Provenance::Attested` and are provably inert on the
  rank.
- **k-of-n is determinism-PINNING, not consensus.** It requires `>= k` of `n`
  recorded re-runs *of this one grader* to produce byte-identical results. There
  is no trust-distributed multi-party agreement; do not call it consensus.
- **The quarantine gate is a CONSERVATIVE structural guard, not a universal
  anti-cheat.** It fires on three specific, decidable, named signals
  (nondeterminism, a structural leakage flag the bundle carries, and the
  degenerate "passes everything / kills nothing" case) and nothing more. The
  leakage check in particular reads an explicit structural flag — it is not a
  fuzzy heuristic and will not catch novel exploits it was not told about.

## The four signals

| # | Signal | Honesty tier | Role |
|---|--------|--------------|------|
| 1 | Exact held-out recompute (`matched/total`, byte-equality) | **RecomputeVerified** | **Load-bearing** grade |
| 2 | Metamorphic-relation coverage (exact, byte-checkable relations) | Attested | Carried, inert |
| 3 | k-of-n determinism-pinning (`>= k` of `n` re-runs byte-identical) | — (quarantine gate) | Nondeterminism guard |
| 4 | Mutation kill-score (`killed/total`) | Attested | Carried, inert; 0-kill + 100%-pass = degenerate |

## The honesty-tier mapping (THE boundary)

`grade_rubric_inputs` turns a non-quarantined `GradeReceipt` into rubric inputs:

- exact held-out pass-rate → `Provenance::RecomputeVerified` (load-bearing),
  graded by the recomputed `matched` count, `max_grade = total`;
- MR-coverage and mutation-kill → `Provenance::Attested` (carried, inert);
- a **quarantined** receipt mints **NO** `RecomputeVerified` criterion — the
  load-bearing dimension is omitted entirely, so the gate refuses to mint
  load-bearing credit even when the recomputed pass-rate is perfect.

## Quarantine reasons

- `DeterminismNotPinned { max_agreement, n, k }` — fewer than `k` of `n` re-runs
  agree byte-for-byte (nondeterministic output).
- `HeldOutExpectedLeaked` — the bundle's structural flag says the solver's "pass"
  only stands because held-out expected bytes were echoed verbatim from inputs
  that should have been absent.
- `DegenerateNoTeeth { matched, total, mutants_total }` — 100% exact pass-rate
  over a non-empty held-out set while 0 of a non-empty mutant set was killed.

## Example

```
cargo run -p nucleus-oracle --example grade_held_out
```

## WASM safety

Integer/byte-only (no float); `serde` + `serde_json` + `sha2` + `hex` +
`thiserror` + path deps only. No `ring` / `tokio` / `redb` / entropy `rand`.
Builds for `wasm32` like `nucleus-eval` / `nucleus-rubric`.
