# Measurements ledger

Decisive numbers, with the commit that produced them and the run file (under `runs/`,
git-ignored, durable across reboots — do NOT write run outputs to /tmp).  Every claim
here is machine-measured; kernel-checked claims say so explicitly.

## Closure sizes (deterministic given NA, maxk)

| NA | maxk | closure | note |
|----|------|---------|------|
| 2  | 5    | 2,902,884 | cacheable: `runs/closure_na2_k5.bin` (180MB, loads in ~4s) |
| 4  | 2    | 1,756,797 | converges in 7 rounds, 2.6s |
| 4  | 3    | >40M, unconverged at round 4 | INFEASIBLE on 48GB — use PAD_MIXSAMPLE or K=2 |

## The k=6 (NA=2) union conjunct — commit 47075e09 era, run lean6c (lost to tmp wipe; numbers preserved here)

- FULL SOUND TEST (eliminable OR Thompson at some merged-start congruence):
  **265,136 / 265,216 — exactly 80 failures**, all decidable
  (smallest quotients k=3: 2, k=4: 26, k=5: 54, none above pool bound 5).
- Refinement witness discharges **0** of the 80.
- Residue profile vs covered: halt-in-cycle 1.000 vs 0.745, **two-halt 0.000** vs 0.227.
- Six failures printed as programs; **all six have kernel-checked UA-free
  `EquivBA` proofs** (`GkatCertR1..R6`, commits 4a51c979, f0b04abe) via ring/parking.
- Ring classifier: 6/6 failure quotients ring-uniform (every listed quotient);
  walk-planner 6/6 structurally identical to the hand proofs (commits acdce0fe, cdcdac02).
- The k=6 re-run printing all 80 failures (cap raised to 80) has NOT yet completed
  (two attempts lost: tmp wipe, then kernel panics).  The 74 unprinted failures remain
  the open sample-bias risk on the "residue = rings" claim.

## Uniformity / mixed-halt (the invariant hunt)

- RETRACTED (commit 2240cd49): "minimal Thompson behaviors tri-case-uniform
  20,000/20,000" — was a `take(20000)` smallest-member artifact.
- Stride-sampled NA=2 K=5 pool (runs/mh2c.txt): ring-uniform 19,651/20,000;
  non-uniform 349, coarsest quotient restores 106, **162 already-minimal non-uniform**
  (tri-case classifier = certificate-recipe coverage, NOT an invariant).
- **UniformHalt** (no mutually-reachable pair with different nonzero halt guards):
  - NA=2: 0/20,000 stride-sampled; 0/100,000 random expressions (runs/mix2.txt).
  - **NA=4: 529/100,000 random Thompson automata have mixed-halt SCCs and ALL 529
    survive minimization** (runs/mix4.txt) — 2-state minimal examples exist.
    UniformHalt is a T=1 guard-algebra artifact; linear parking cannot handle the
    mixed shape.  The k=6 evidential base lives in the easy fragment.

## NA=4 K=2 sweep (the decisive frontier experiment)

- equivalent pairs 232,052; **crux 214,635** (runs/na4k2b.txt, dry run without
  PAD_ORACLE — union conjunct requires PAD_ORACLE=1).
- Union conjunct at NA=4: **PENDING** (runs/na4k2c.txt in flight).

## Operational

- Two kernel panics 2026-08-18 ("watchdogd no checkins"): whole-frontier par-collect
  allocation storm.  Fixed (commit 2240cd49): chunked rounds + local dedup +
  fingerprint interner + PAD_MAXLIST clean abort.  Regression: identical closure and
  measurements, peak RSS 3.4GB at NA=2 K=5.
- Mechanism-test diagnostic gated behind PAD_MECH (commit 1113d9c6) — it burned 10h
  at NA=4 without feeding any live question.
- Full sweep env (union conjunct + failures):
  `PADDED=1 PAD_TOTAL=1 PAD_SAMPLE=1 PAD_ROUNDS=1 PAD_FRONTIER=50
   PAD_PARTS_ROUNDS=1 PAD_PARTS_FRONTIER=200 PAD_ORACLE=1 PAD_ORACLE_N=2`.
- Closure cache: `PAD_SAVE_CLOSURE=path` / `PAD_LOAD_CLOSURE=path`.
- mimalloc global allocator: ~8% CPU-time reduction on the classify workload,
  identical outputs; macOS system allocator serializes under parallel churn.
