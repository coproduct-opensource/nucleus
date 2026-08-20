# Summit todo — the three remaining spans

- [x] 1. **General decomposition theorem** (`decomp_solves`): witness-form —
      `StateRole` (fold | ring-header | member/extSol-shaped) per state of an
      arbitrary automaton; witness ⟹ SolvesBA.  All plumbing lives in the witness
      fields (equalities with the API shapes), per the composition pilot's contract.
- [x] 2. **Conditional summit wiring** (`completeness_of_decompCovered`): the open
      problem formally reduced to plan existence — decomposition-witnessed quotient
      existence ⟹ FiniteAxiomsCompleteBA, via decomp_solves +
      certifiedThompson_uniform_solved_quotient.
- [~] 3. **Plan existence attack (research)** — OPENED:
      - [x] hypothesis named (DecompCovered, in item 2)
      - [x] strategy recorded (GkatPlanExistenceProofs docstring: S1 canonical
            quotient / S2 role existence / S3 assembly)
      - [x] S1a proved: sum_starts_language_equal — the sum's two starts are
            language-equal at every carrier/valuation ([propext, Quot.sound])
      - [x] S1b: the canonical start-merging quotient as a
            UniformBehavioralGAutQuotient — PROVED modulo trimmedness:
            * stage A: generic-valuation collapse (bval/autStep/autRun naturality);
              step matching under LiveSteps; UniformStateEquiv is a GAutBisim at
              every carrier/valuation (uniformStateEquiv_bisim)
            * stage B: canonical quotient by GENERIC BISIMILARITY — design
              correction: language equality is too coarse under silent transitions;
              bisimilarity quotients need NO trim (canonicalQuotient, choice-based
              representatives, no quotient types)
            * stage C: start merge — canonical_quotient_merges_starts
              [propext, Classical.choice, Quot.sound]
      - [~] S0: the trim hypothesis (NormalizationBridge) — OPENED, loop-free
            stratum proved (GkatNormalizationProofs):
            * outG: the input-guard-indexed output-guard interface algebra
            * outG_emits: g?·e ≡ g?·(e·(outG g e)?) in the finite axioms
            * prune + prune_equiv (+ _top): dead-branch elimination provable,
              deadness propagates syntactically (prune = 0? on empty behaviours)
            * spine now UNCONDITIONAL over all of GKAT: loops handled soundly
              (outG wh = 1 via s5; prune keeps bodies), LoopFree dropped
            * wh_emits_exit: PRODUCTIVE loops provably emit their exit guard ¬b
              (w1 + else_guard_test + w3_ba) — axiom-free, no UA
            * wh_test_collapse: ALL pure-test loop bodies collapse,
              wh b (c?) ≡ (¬b)? — includes the divergent wh 1 (1?) ≡ 0?, the
              first unguarded-loop elimination (w2 identifies test bodies,
              w3_ba kills the 0?-bodied loop) — axiom-free, no UA
            * KEYSTONE DONE (all axiom-free): dPart (structural productive part
              — POPL'20 D(e) without atom-indexed sums; the wh case bakes the
              productive body in, dissolving the ¬E·D ≡ D tightening lemma);
              fundamental (FT: e ≡ ite (E e) 1? (dPart e)); productive_loop +
              guardedness_normalization (every loop body provably replaceable by
              a strictly productive one, via w2); wh_emits_exit_all (every loop
              ends in ¬b, no hypotheses); wh_one_zero (wh 1 e ≡ 0?, every body)
            * NEXT: tight prune through loop bodies (wh b e ≡ wh b (b?·e) now
              derivable for productive bodies via w3_ba), tight loop outG, then
              Thompson silent-freeness of pruned terms (the mountain), then wire
              into NormalizationBridge
      - [~] S2: role existence for the canonical quotient (the research core) —
            OPENED, acyclic stratum proved (dag_roles: WellFounded StepRel ⟹ full
            fold cover via dagSol well-founded recursion).  NEXT: single-SCC ring
            stratum against the compositional ring API, then the general
            SCC-decomposition assembly (walk-planner as the constructive skeleton)

Status log:
- (start) all three open.
- 1 DONE: GkatDecompProofs.decomp_solves, [propext] only.
- 3 OPENED: S1a proved; S1b + S2 are the remaining mathematics of the open problem.
- 2 DONE: completeness_of_decompCovered — the open problem is FORMALLY one hypothesis
  (DecompCovered) away from proved, on standard axioms.
- S1b DONE (modulo S0): the canonical quotient exists for EVERY automaton, and merges
  the starts of any trimmed Thompson sum of uniformly equivalent programs.  The open
  problem is now S0 (trim, engineering-mathematics) + S2 (roles, the research core).
- REFUTATION + CORRECTION: DecompCovered as stated is FALSE (decompCovered_false —
  the pair (a·0, 0): language-equal, non-bisimilar starts, so no behavioural quotient
  merges them).  The summit is restated as completeness_of_decompCoveredTrim:
  DecompCoveredTrim (trim as hypothesis) + NormalizationBridge (S0: every program
  provably equivalent to one with a trimmed Thompson automaton, using s3 = early
  termination) ⟹ FiniteAxiomsCompleteBA.  sum_liveSteps glues summand trimmedness.
  All on [propext, Classical.choice, Quot.sound]; full lake build green.

## THE REWIRE (GkatTrimProofs) — the mountain bypass

The syntactic route (NormalizationBridge / Thompson silent-freeness) is
SUPERSEDED on the critical path by the automaton-level trim:

- trimAut: drop dead-target transitions, conjoin surviving guards with the
  negation of prior dead guards (firstMatch priority preserved exactly)
- autLang_trimAut: per-state languages unchanged at every carrier/valuation
- liveSteps_trimAut: LiveSteps by construction → START MERGE UNCONDITIONAL
- trim_dead_sol: dead states have provably-zero solutions in the trimmed system
- trim_fold_equiv + solvesBA_untrim: solutions of the trimmed system provably
  solve the original (dead arms die by s3; under-guard ite algebra)
- completeness_of_roleCovered: **THE REWIRED SUMMIT** — the open problem is now
  ONE hypothesis, RoleCovered: the canonical quotient of the trimmed Thompson
  sum of every ULE pair is role-covered.  Everything else (quotient existence,
  start merge, descent, untrim, component restriction, Thompson uniqueness) is
  a theorem.  [propext, Classical.choice, Quot.sound]

RoleCovered is exactly the object the harness measures (trim + canonize before
everything).  Remaining mathematics: S2 (roles) — acyclic stratum proved
(dag_roles); next: single-SCC rings, then SCC-DAG assembly.

## S2 stratum ledger (GkatPlanExistenceProofs / GkatDecompProofs)

- [x] acyclic: dag_roles (WF step relation ⟹ all folds)
- [x] head-position self-loops: selfloop_dag_roles (StateRole.selfLoop, closes
      by salomaa_solution_exists, no side conditions)
- [x] single self-arm anywhere: selfarm_roles (arm_commute walks the arm to the
      head; StateRole.salomaaE = EquivBA-massaged Salomaa state)
- [x] THE SINGLETON-SCC THEOREM: singleton_scc_roles — any number of self-arms,
      any positions (arms_merge fuses self-calls; multi_gather = every dispatch
      is provably one guarded self-call over its non-self remainder).  Subsumes
      all previous strata.  [propext, Classical.choice, Quot.sound]
- [ ] multi-state SCCs (the research frontier): post-action branching defeats
      direct Salomaa folding (left distribution FAILS in GKAT — corpus
      theorem), which is exactly why rings need walk/parking.  Next moves:
      (a) harness measurement — what fraction of canonical trimmed-quotient
      states at the frontier are covered by fold+salomaaE alone, and which
      multi-state SCC shapes actually occur; (b) the unbranching-cycle
      reduction (cycles whose return paths are single unconditional arms
      flatten to composite-body self-loops by s1); (c) the general ring
      existence theory against extHeaderSol/extSol (walk-planner as the
      constructive skeleton, absorption via the outG emission theory).

## Cycle stratum (GkatCycleProofs, 2026-08-20)

- StateRole gains equivFold (the fully general escape hatch — witnesses are
  whole EquivBA derivations); decomp_solves still [propext]
- single_port_cycle_roles: THE SINGLE-PORT CYCLE THEOREM (cycle-local) — for a
  simple cycle whose interiors are halt-free with all arms to their single
  successor, and whose solution takes the chain closed forms, every member has
  a StateRole: the port is a salomaaE state whose body is the composed cycle
  (chain_expand + prod_assoc + multi_gather), interiors are equivFolds via the
  straight-line collapse (ite G Z 0? ≡ G?·Z).  NO parking, NO side conditions.
  [propext, Classical.choice, Quot.sound]
- This covers the census-dominant multi-SCC shape (~82% at NA=4).  Remaining:
  the ambient ASSEMBLY (define the solution by WF recursion mixing strata) and
  the multi-port tail (parking — rare: 3 in 20k pairs).

## Assembly + parked cycles (GkatCycleProofs, 2026-08-20, second push)

- assembly_roles: THE ASSEMBLY THEOREM — one solution by WF recursion on rank
  dispatching gathered-Salomaa closed forms at base states and chain/port
  closed forms on designated single-port simple cycles; all congruences reduce
  to pointwise foldTL rewriting.  [propext, Classical.choice, Quot.sound]
- Multi-port census dump (PAD_CENSUS_N=60000, NA=4): 12 multi-port SCCs in 60k
  pairs; EVERY halt-flavored instance has interior halt guards ⊆ the port halt
  guard (subset parking!); exit-flavored instances share one external target.
- parked_cycle_roles: THE PARKED CYCLE THEOREM — simple cycles with interior
  halts ⊆ port halt: park_absorb (halts absorb the port solution, via
  test_header_absorb) + pChain_split (u5 right-distributes the port solution
  out of the whole parked chain) close the port as salomaaE; interiors are
  equivFolds of literal chain forms.  [propext, Classical.choice, Quot.sound]

Remaining observed-but-unproved shapes: branchy multi-state SCCs (interior
with ≥2 distinct in-SCC successors — needs the tree-walk machinery,
GkatRingPlan2 Sub/Branch style) and multi-member exit ports; both rare.
Also: assembly extension to dispatch parked cycles (mechanical).

## CLOSE-OUT (2026-08-20)

full_assembly_roles: the complete three-way assembly — base states,
single-port cycles, and parked cycles under one WF-recursive solution.
Parked closed forms reference no other solutions (their port REST is a bare
halt test), so parked cycles impose no rank conditions at all.
[propext, Classical.choice, Quot.sound]; full lake build green.

### State of the programme at close-out

THE SUMMIT: completeness_of_roleCovered (GkatTrimProofs) — the open problem is
ONE hypothesis: RoleCovered (roles for canonical quotients of trimmed Thompson
sums).  Everything else is a theorem on standard axioms.

ROLE-EXISTENCE COVERAGE (toward RoleCovered), proved:
- singleton_scc_roles — all 1-cycle automata (any self-arms, any positions)
- single_port_cycle_roles + parked_cycle_roles — simple cycles with one port,
  and multi-halt cycles under subset parking (census: every observed
  halt-flavored multi-port instance satisfies it)
- full_assembly_roles — all of the above mixed under one recursion
Census: fold+salomaaE alone already covers 96.4–99.3% of pairs; the cycle
theorems cover the dominant multi-SCC shapes.

REMAINING (the true open residue):
1. Branchy multi-state SCCs (interior with ≥2 in-SCC successors): needs tree
   walks (GkatRingPlan2 Sub/Branch style) — rare in census.
2. Multi-member exit ports (exits on different cycle members): the two-exit
   obstruction territory — rarest.
3. The final step from shape-coverage theorems to RoleCovered itself: prove
   canonical trimmed quotients ALWAYS decompose into the covered shapes (or
   extend the shape library until they do).  This is the research core that
   remains genuinely open.

## Walked cycles (2026-08-20, continuation)

- double_gather: gather a dispatch twice — self-arms, then next-arms
- wChain/walkedPortE + wChain_split: walked chains with local wh prefixes;
  the port solution right-distributes out (assoc through wh, u5 on steps,
  park_absorb on halts)
- walked_cycle_roles: cycles whose members may each SELF-LOOP, with parked
  halts and single next-successors — every member (port included) a salomaaE
  state; the port's own self-loop folds into the cycle body by arms_merge.
  [propext, Classical.choice, Quot.sound]
- Census (60k pairs, NA=4): 89.2% of ALL multi-state SCCs are walked-covered;
  open residue = 235 instances (exit ports ~185, non-subset halts/trees ~50).

## Exit ports (2026-08-20, continuation 2)

- fold_absorb + park_absorb_exits: a parked halt falls through the port exit
  fold to the final halt (disjoint from exit guards, inside the port halt,
  excluded from the loop guard)
- walked_exit_cycle_roles: the walked cycle with an ARBITRARY port residual
  (exits + halt).  [propext, Classical.choice, Quot.sound]
- Census: 2127/2171 = 98.0% of multi-SCCs covered; 44 open instances in 60k
  pairs (multi-member exits, non-subset halts, trees).
