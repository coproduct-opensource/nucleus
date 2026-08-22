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
- **The k=6 re-run completed (runs/na2k6_full.txt): all 80 failures printed, every
  headline number reproduced exactly** (265,136/265,216; sizes 2/26/54; union conjunct
  265,134; only-elim 39,066; only-Thompson 1,920) — validating the memoization, gates,
  and caps end-to-end.  **Classifier + planner over all 80 (runs/attack80.txt):
  80/80 ring-uniform, 80/80 walk-planned, zero unplannable.**  Sample-bias risk
  RETIRED.  Step census across the 80 plans: Act 64, Park 59, SelfLoop 30, Inline 21,
  DeadGuard 17, Sub 8, Branch 6 — all seven kinds covered by the kernel-checked
  recipes in GkatCertR1-R6.  The ring-mode generator needs NO new construction.
- **CERTIFIED (commit 69d8a9b1): GkatK6R01..80 — all 80 residue pairs have
  machine-generated kernel-checked UA-free EquivBA proofs (emit_ring.py), standard
  axioms only, 80/80 pass.**  The k=6/NA=2 union conjunct is witnessed end-to-end.

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
- FORGE (sampled crux, pool-free witnesses; validated 1500/1500 at NA=2): at NA=4
  depth<=6 k 3..8: 1999/2000 covered by elimination; ONE residue candidate at k=4
  (mixed-halt sum, two-atom halts; verdict survives full oracle budgets) —
  runs/forge_na4_full.txt.  The first object to survive the witness kit anywhere.
- **GAUNTLET RESULT (runs/forge_na4_gauntlet.txt): candidate independently verified
  equivalent (product-BFS bisim) and then FELL to SUBSET PARKING — interior halt
  guards need only be subsets of the header's exit guard.  Classifier v3: candidate
  reclassifies ring-only, NA=4 forge neither=0 all strata, k=6 80/80 unchanged.
  Paper + classifier verified; Lean certification awaits the T=2 support layer.**
- **CERTIFIED (commit 463e54cd): GkatMixPilotProofs — the candidate's UA-free
  equivalence kernel-checked via subset parking, first certificate at two primitive
  tests.  Emitted from Rust (emit_mix_pilot, PAD_EMIT_MIX), first-emission compile.
  Support: GkatCertSupportBoolProofs (Tst=Bool layer) + ite_or_split +
  test_header_absorb_sub (axiom-free).**
- **Union conjunct at NA=4 K=2: 214,635 / 214,635 (100.0%), residue ZERO**
  (runs/na4k2j.txt).  only-elimination 3,104; only-Thompson 0 — elimination at some
  merged-start congruence covers the entire space by itself.  Need-a-KA-step: 0 (no
  unguarded-union obstruction at all).  NON-VACUOUS: covered-population profile has
  two-halt 0.710, halt-in-cycle 0.997; 85% of pullbacks carry two-halt 2-cycles; the
  start-merging congruence is Thompson AND start-identifying for 98.6%.  Measured
  under HANDICAPPED oracles (PAD_ELIM_BUDGET=100k = 20x cut, PAD_LLEE_BUDGET=20k =
  10x cut) — 100% with weakened witnesses is the strong direction.
- Memo telemetry vindicated both hypotheses in one run: random-population diagnostics
  hit 0-2.5% (no reuse — those bands were capped/gated, commits 1113d9c6..b9e0253f),
  while the live sweep climbed 52.8% -> 87.4% over 1.9M calls (massive quotient reuse).
- Six NA=2-calibrated diagnostic bands were the entire runtime cost at NA=4; the live
  computation was never the bottleneck.

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

## SCC census (PAD_SCC_CENSUS, 2026-08-20) — the S2 stratum census

Canonical quotient of the TRIMMED sum (liveness-trim + language minimization,
mirroring Lean `canonicalQuotient (trimAut (SUMof e f))`), per forge-sampled
language-equivalent pair; states classified against the PROVED strata.

- NA=2, depth<=6, 20000 pairs: **99.3% of pairs fully covered by fold+salomaaE**
  (singleton_scc_roles).  11474 quotient states: 10475 fold, 624 singleton-self,
  375 (3.3%) in multi-state SCCs.  EVERY multi-SCC shape observed has
  halting-members + exit-arms = 1 (single way out).
- NA=4, depth<=7, 20000 pairs: **96.8% fully covered**.  48096 states: 44016
  fold, 2705 singleton-self, 1375 (2.9%) multi.  Shape histogram dominated by
  (size, simple, 1 halting, 0 exits): 439+80+4 = 523 of ~638 SCCs (~82%);
  single-exit-no-halt simple cycles next; multi-port shapes (two halting members
  or halts+exits mixed) are a 3-occurrence tail.

DESIGN CONSEQUENCE: the priority ring stratum is SINGLE-PORT SIMPLE CYCLES
(one member carries the halt-or-exit port; interiors are halt-free with all
arms to their single successor).  For that shape NO PARKING is needed: interior
equations collapse to straight lines (ite b e 0? = b?e), the cycle composes
into one Salomaa body at the port, and multi_gather (proved, arbitrary target)
does the per-state gathering.  Parking is only needed for the rare multi-port
tail.

## Walked-coverage census (2026-08-20, second refinement)

NA=4, depth<=7, 60000 pairs, walked-coverage classifier added (unique
non-self in-SCC successors forming one cycle, no exits, subset halts, port
halt/step exclusivity — the walked_cycle_roles hypotheses):

- pairs fully covered by fold+salomaaE: 57776/59947 (96.4%)
- multi-state SCCs: 2171 total; **walked-covered: 1936 (89.2%)**;
  OPEN: 235 (exit-flavored ports ~185, non-subset-halt/tree shapes ~50)

So proved-theorem coverage after walked_cycle_roles: all but 235 SCC
instances in 60k pairs.  The open residue = multi-member exit ports +
two-independent-halt cycles + genuine tree walks.

## Exit-port coverage (2026-08-20, third refinement)

walked_exit_cycle_roles added (port carries arbitrary residual: exits + halt;
interior halts fall through the port exit fold — three bval-level conditions).
Census classifier extended to exit-ports.  NA=4, 60k pairs:

- multi-state SCCs: 2171; **walked-covered: 2127 (98.0%)**; OPEN: 44
- open residue = 44 instances in 59947 pairs (0.07% of pairs): multi-member
  exits, non-subset halts, tree shapes.
