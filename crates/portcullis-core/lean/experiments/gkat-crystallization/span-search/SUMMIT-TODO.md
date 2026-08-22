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

## THE GIANT STEP (2026-08-20): LOOP-FREE COMPLETENESS — UNCONDITIONAL

loopfree_complete (GkatLoopFreeProofs):
  LoopFree e → LoopFree f → UniformLanguageEquivalent e f → EquivBA e f
on [propext, Classical.choice, Quot.sound].  NO other hypotheses.  The
pipeline's FIRST CLOSED THEOREM: the finite GKAT axioms + test BA are
complete for the loop-free fragment, no uniqueness axiom.

Route (every layer of the rewired pipeline exercised end-to-end):
- loopFree_initRanked: loop-free Thompson automata carry structural ranks
  (InitRanked: init arms under top, core arms descend); optRank/sumGAut_ranked
  lift to the closed sum
- bounded_quot_solvesBA (THE ACYCLICITY ENGINE): the canonical quotient of a
  ranked automaton is provably solvable — trim_quot_bisim/quot_lang_eq make
  quotient languages equal trim languages at EVERY carrier element, cleanAut
  drops never-firing arms, and a firing arm strictly decreases the exact
  maximum accepted length (maxlenB + witness + prepend-pump), so the cleaned
  quotient is singleton-SCC-shaped
- equivBA_of_quot_solvesBA closes the pair (trim, descent, untrim, component
  restriction, Thompson uniqueness, start merge).

The engine is fragment-agnostic: ANY class of programs whose Thompson sums
can be ranked (or whose quotients can otherwise be shown acyclic) inherits
completeness the same way.  The general case reduces to: canonical quotients
of (possibly looping) Thompson sums decompose into the proved shape library.

## ATOMIC-LOOP COMPLETENESS (2026-08-20, keep-pushing round)

atomicloops_complete (GkatAtomicLoopProofs): the finite GKAT axioms + test BA
are complete for uniformly-language-equivalent programs whose loops range
over single actions (wh b (act p) bodies + all loop-free structure).  The
SECOND unconditional completeness theorem — now WITH LOOPS.  No UA, no
hypotheses, [propext, Classical.choice, Quot.sound].

The engine behind it, rankSelf_quot_solvesBA (THE SELF-LOOP ENGINE):
canonical quotients of rank-modulo-self-loop automata are provably solvable,
by MINIMAL-RANK-REALIZER DESCENT — a firing quotient arm between distinct
states takes languages to derivatives; the minimal-rank source realizer must
fire to a realizer that is either itself (forcing the quotient states equal
via rep-fixedness) or strictly lower, so minRank strictly descends.  minRank
is a hand-rolled monotone-predicate minimum (minUpTo) — Mathlib-free.

NEXT ESCALATIONS: (a) one-action-per-body loops (tests around the action —
needs the loopInitialized back-edge analysis for test-padded bodies);
(b) nested atomic loops (wh over bodies containing atomic loops — back-edges
into loop headers create 2-cycles: needs the walked-cycle shapes inside the
engine, i.e. rank-modulo-COVERED-SCC engines); (c) the general case.

## GUARDED-LOOP COMPLETENESS (loop iteration 1)

gloops_complete: THE THIRD unconditional theorem — completeness for programs
whose loop bodies carry at most one action with arbitrary test padding: real
WHILE loops wh b (g?; p; h?).  [propext, Classical.choice, Quot.sound]

The structural trick: NoAct bodies have UNINHABITED Thompson carriers
(noAct_empty) and OneAct bodies SUBSINGLETON ones (oneAct_subsingleton), so
every loopInitialized back-edge is a self-arm for free — the whole loop case
of the rank induction closes by subsingleton/elim.

Web-search note (Grabmayer LICS'22 crystallization): LLEE charts are NOT
closed under bisimulation collapse; the fix is near-collapse with SCCs
"collapsed or twin-crystal".  Our shape-library strategy is the exact GKAT
analog; the twin-crystal notion is the model for characterizing our
multi-port tail in the general attack.

NEXT: multi-action loop bodies (2+ core states → back-edges create genuine
in-body cycles: needs rank-modulo-COVERED-SCC — fold the walked-cycle shape
library into the minimal-realizer descent engine); nested loops.

## THE CYCLE DICHOTOMY (loop iteration 2)

quot_cycle_dichotomy (GkatChainLoopProofs): for a RANK-MODULO-SIMPLE-CYCLE
source (successor function nxt; every arm targets nxt s or strictly
descends — subsumes mod-self via nxt = id), each state of the cleaned
canonical quotient carries a minimal realizer u such that EVERY cleaned arm
is (i) a self-arm, (ii) strictly descending in minimal-realizer rank, or
(iii) exactly the class of nxt u — a UNIQUE quotient cycle-successor.

I.e. the rank-modulo-simple-cycle class is CLOSED under canonical
quotients (quotient-side nxt' c := ⟦nxt u_c⟧).  The GKAT analog of
Grabmayer's LLEE-preservation-under-near-collapse and the coequation
paper's minimization-preserves-nesting.  [propext, Classical.choice,
Quot.sound]

NEXT (iterations 3+): (a) orbit/period machinery — qnxt-orbits in the
finite states list are cycles (pigeonhole or minUpTo-style first-return);
(b) instantiate full_assembly_roles/walked_exit on the quotient cycles
(single-port condition from chain-body halt structure); (c) ChainLoops
fragment rank (wh over multi-action chains) → the fourth unconditional
completeness theorem.

## THE WALKED-EXIT ASSEMBLY (loop iteration 3)

walked_assembly_roles (GkatCycleProofs): the engine-facing assembly — an
automaton whose every state is BASE (arms self or strictly descending; the
gathered Salomaa form covers self-arms) or a member of a designated
WALKED-EXIT cycle is fully role-covered.  Exactly the two shapes the cycle
dichotomy produces on cleaned canonical quotients.  Closed forms carry the
ambient solution only in the port residual (walkedExitPortE_congr /
wChain_term_congr keep all congruences pointwise).
[propext, Classical.choice, Quot.sound]

REMAINING for the fourth unconditional theorem (multi-action loop bodies):
1. ORBIT MACHINERY: from quot_cycle_dichotomy, build the cy-assignment —
   qnxt-orbits close (source periodicity: nxt^k u = u on cycle states),
   canonical basepoint per orbit (bisimRep-style choice-coherence), periods,
   positions; derive the walked_assembly hcy coherence bundle (rank equality
   from minRank along cycles; hint_nil/himpc/hdisj/hexcl from the source
   chain-halt structure).
2. ChainLoops fragment: Thompson rank-mod-nxt for wh over multi-action
   chains (nxt follows the chain, wraps at the back-edge).
3. Glue: rankNxt_quot_solvesBA := dichotomy + orbits + walked_assembly +
   solvesBA_unclean; then chainloops_complete.

## THE ORBIT CORE (loop iteration 4)

GkatOrbitProofs — the bridge from the dichotomy to the walked-exit assembly,
built on the DIRECT-ORBIT design: the quotient orbit of a cycle class c0 is
m j := rep (nxt^[j] u0) for the canonical minimal realizer u0 — closure is
then a two-liner (rep (nxt^k u0) = rep u0 = c0 by source periodicity +
rep-fixedness + repfixed-lang-eq), no pigeonhole needed.

- uc: canonical realizer via choose(minRank_spec); uc_rank: it sits EXACTLY
  at minRank (le_antisymm of the spec bound and minimality)
- live_trim_iff: trim liveness = source liveness (from autRun_trimAut)
- orbit_step: a realizer's firing target carries the class derivative
- nxtIter + orbit_track: source orbits stay trim-live under the firing
  hypothesis (trim steps land live)
All [propext, Classical.choice, Quot.sound].

NEXT (iteration 5+): the language-tracking strengthening (L(rep(nxt^j u0))
follows the derivatives — needs the min-level argument: at the orbit minimum
the firing target must be the nxt-successor), then the cy-bundle assembly
(m, len := source period, positions, hint_nil/himpc/hdisj/hexcl from
chain-shape hypotheses) → rankNxt_quot_solvesBA → chainloops_complete.

## CYCLE LEVEL MINIMALITY (loop iteration 5)

- realizer_propagate: a realizer of an orbit language walks forward around
  the cycle WITHOUT rank increase — its firing target at each cycle atom
  realizes the next orbit language (derivative matching through the shared
  word), and the mod-nxt arm dichotomy plus rank(nxt s) = rank s cap the
  rank at every step.
- cycle_level_min: on a periodic source orbit whose basepoint is a minimal
  realizer of its own language, EVERY orbit class sits at exactly the
  basepoint's rank — a better realizer anywhere on the cycle would propagate
  around to beat the basepoint at its own language.
Both [propext, Classical.choice, Quot.sound].

The analytical core of the orbit machinery is now complete.  Remaining for
chainloops_complete: (a) the minimal QUOTIENT period (positions injective —
least p ≥ 1 with rep(nxtIter p u0) = rep u0, via minUpTo on p ≤ k) and the
cy-bundle construction discharging walked_assembly_roles' coherence
(hint_nil/himpc/hdisj/hexcl from chain-shape source hypotheses, level
equality from cycle_level_min); (b) ChainLoops fragment rank; (c) glue.

## ORBIT COMBINATORICS (loop iteration 6)

- nxtIter_add / qorb_periodic: the quotient orbit inherits the source period
- min_fire: a firing whose target rank is not below the source must land
  exactly on the nxt-successor (mod-nxt arm dichotomy)
- class_succ_eq: CLASS-SUCCESSOR WELL-DEFINEDNESS — two same-rank source
  states with equal languages firing at a common live-derivative atom have
  nxt-successors with equal languages.  With cycle_level_min supplying the
  min-level hypothesis, the quotient successor is a FUNCTION of the class —
  quotient orbits behave like function orbits, enabling the classic
  least-period/injectivity arguments.
All [propext, Classical.choice, Quot.sound].

Web-search note: Böhm–Jacopini is propositionally FALSE (Kozen–Tseng 2008 —
the paper where GKAT was born as "propositional while programs"), so no
single-loop normal form collapses the fragment ladder; it must be climbed.

REMAINING for chainloops_complete: least quotient period (findFrom search +
injectivity via class_succ_eq), canonical orbit basepoint (choice-coherence
on the rotation-invariant orbit predicate), the cy-bundle side conditions
(interior classes have no descending arms — semantic, from chain-shape
sources), fragment rank, glue.

## SHIFTED-ORBIT TRACKING (loop iteration 7)

- nxtIter_wrap/mul_period/mod: orbit wrap arithmetic (all indices reduce
  mod the source period)
- orbit_live_all / orbit_nofix_all / cycle_level_all: liveness, nofix, and
  level facts at unbounded indices
- minRank_lang_congr / rep_lang_congr: minimal ranks and representatives
  are LANGUAGE-DETERMINED (the trim is LiveSteps, so language equality is
  bisimilarity)
- orbit_lang_determined: SHIFTED-ORBIT TRACKING — any same-rank realizer of
  an orbit language generates the SAME orbit of languages, shifted by the
  position.  One induction over class_succ_eq with cycle_level_all
  supplying the min-level hypothesis at every step.
All [propext, Classical.choice, Quot.sound].

CONSEQUENCE: orbit SETS are basepoint-independent (rep-orbits of orbit-mates
are rotations of each other, via rep_lang_congr on the tracked languages) —
the canonical-basepoint construction is now purely mechanical.  Remaining:
basepoint + least period + cy-bundle side conditions + fragment rank + glue.

## QUOTIENT-CYCLE ENUMERATION (loop iteration 8)

- qsucc_well_defined / qsucc_iter: equal orbit classes have equal successor
  classes (class_succ_eq + rep_lang_congr), iterated
- findFrom + findFrom_spec: bounded upward search with first-hit minimality
- qPeriod + qPeriod_spec: the first-return period of the quotient orbit —
  least p in [1, k] with the p-th class equal to the basepoint class
- qorb_injective: ORBIT INJECTIVITY below the first-return period — a
  coincidence at (i, j) shifts by k - i to the basepoint (k-periodicity),
  contradicting first-return minimality.
All [propext, Classical.choice, Quot.sound].

The quotient cycle is now a genuine finite cycle: well-defined successor,
period, pairwise-distinct members m j := rep (nxtIter j u₀) for j < qPeriod.
Remaining for chainloops_complete: canonical basepoint (port detection),
the cy-bundle side conditions, fragment rank, glue.

## ORBIT ROTATION + CANONICAL BASEPOINT (loop iteration 9)

- shift_per / shift_nofix / shift_min: the FULL hypothesis bundle transports
  to any shifted basepoint nxtIter i u0 (periodicity, non-fixedness, and rank
  minimality via cycle_level_all + minRank_le)
- InOrbit + inOrbit_shift: ORBIT ROTATION — orbit membership is basepoint-
  independent (forward: index shift; backward: explicit div/mod decomposition
  i = k*q + r, witness (k-r) + j%k wraps through the source period)
- firstMem (hand-rolled List.find, Classical) + congr/mem/isSome specs
- basepoint + basepoint_shift: every orbit member selects the SAME canonical
  basepoint (firstMem_congr over the rotated predicate)
- basepoint_isSome: the basepoint exists whenever ⟦u0⟧ is in the state list,
  and is itself an in-list orbit member.
All [propext, Classical.choice, Quot.sound].

Remaining for chainloops_complete: cy-bundle side conditions (port detection,
interior-class arm targeting from the dichotomy), fragment rank, glue.

## THE ORBIT DICHOTOMY + hint_nil BRIDGE (loop iteration 10)

- orbit_dichotomy: the ABSTRACT successor of quot_cycle_dichotomy (⟦nxt u⟧
  for a choice-picked realizer u) IS the concrete next orbit class
  ⟦nxtIter (j+1) u₀⟧ — rank identification via cycle_level_all + shift_min,
  successor identification via class_succ_eq + rep_lang_congr. Every cleaned
  quotient arm at an orbit class: self ∨ minRank-descending ∨ NEXT-ON-CYCLE.
- orbit_arms_pinned / orbit_arms_pinned_nxtAt: descent-free classes have
  every arm pinned to self-or-next, through the nxtAt wrap at qPeriod
  (qm_wrap = first-return periodicity).
- hint_nil_of_pinned: pinned arms collapse the double gOthers — the
  walked-exit interior side condition hint_nil holds SEMANTICALLY.
All [propext, Classical.choice, Quot.sound].

The first cy-bundle side condition is discharged from pure semantics.
Remaining: himpc/hdisj/hexcl (halt-guard conditions — need the fragment's
halt structure), fragment rank, glue rankNxt_quot_solvesBA.

## HALT-GUARD SIDE CONDITIONS (loop iteration 11)

- guardImplies_of_empty / guardEmpty_and_left: empty guards imply anything
  and annihilate conjunctions
- orbit_halt_empty: EMPTY-WORD-FREE => EMPTY HALT GUARD. An orbit member
  accepting no empty word gives its quotient class a halt guard that is
  empty at EVERY valuation — bval_gen naturality reduces arbitrary (W, x)
  to the generic atom, where the class halt = rep halt = trim halt is the
  empty-word acceptance test, killed by rep_lang transfer. Uses the fact
  that trimAut/bisimQuotAut/cleanAut ALL preserve hlt verbatim.
- cy_halt_conditions_of_empty: an empty halt guard discharges himpc, hdisj,
  AND hexcl against any port, any len.
All [propext, Classical.choice, Quot.sound].

ALL FOUR cy-bundle side conditions now derived semantically:
  hint_nil  <- orbit_arms_pinned_nxtAt + hint_nil_of_pinned (iter 10)
  himpc/hdisj/hexcl <- orbit_halt_empty + cy_halt_conditions_of_empty (iter 11)
The fragment must supply: no-descent at interior classes + empty-word-
freeness at interior orbit members — both TRUE for chain bodies by
construction. Remaining: fragment rank, glue rankNxt_quot_solvesBA.

## THE ORBIT CY-BUNDLE (loop iteration 12)

- orbit_rank_eq: every orbit class sits at minRank level rank u0
  (cycle_level_all twice)
- orbit_port_descent: the port's non-self non-next arms strictly descend —
  double gOthers_sub peel + orbit_dichotomy at j=0, next-branch excluded
  because nxtAt wraps only at len and 2 <= qPeriod
- orbit_cy_bundle: the COMPLETE per-orbit hypothesis package of
  walked_assembly_roles — rank equality, port descent, hint_nil, himpc,
  hdisj, hexcl — for m j := qm j at len := qPeriod. Fragment supplies just:
  interior descent-freeness + interior empty-word-freeness (+ 2 <= qPeriod,
  states membership).
All [propext, Classical.choice, Quot.sound].

Remaining for chainloops_complete: the global cy function (assign each
quotient state its orbit data; position via qorb_injective, well-definedness
via basepoint_shift), fragment definition + rank, glue.

## ROTATION + WITNESS INVARIANCE (loop iteration 13)

- qPeriod_shift: the first-return period is ROTATION-INVARIANT. Mod-reduce
  the shift, transport the base return outward by qsucc_iter, transport the
  shifted return back by the (k - i') basepoint shift (the qorb_injective
  pattern), antisymmetry through the two minimality specs.
- orbit_m_eq: any same-rank realizer of an orbit language enumerates the
  SAME classes, shifted (orbit_lang_determined + rep_lang_congr).
- qPeriod_congr: WITNESS INVARIANCE — any periodic same-rank realizer u1
  (own period k1, possibly a different source orbit entirely) has the same
  first-return period: pointwise sequence equality via orbit_m_eq, then
  antisymmetry of the two first-return specs, then qPeriod_shift.
All [propext, Classical.choice, Quot.sound].

The quotient cycle data (len, m) is now provably CANONICAL: independent of
which orbit member computes it and which source witness it uses. This is
everything the global cy function needs for well-definedness. Remaining:
assemble cy + positions (qorb_injective), fragment definition, glue.

## CY-ASSEMBLY SUPPORT LAYER (loop iteration 14)

- qorb_period_all / qorb_qmod: the class sequence is qPeriod-periodic;
  every orbit index reduces mod the first-return period (mul-induction +
  div_add_mod)
- orbit_track_from: CROSS-WITNESS TRACKING — orbits of different witnesses
  (different source cycles, own periods) that meet in one class track
  together forever (rank equality via the two cycle_level_all's, then
  orbit_m_eq)
- inOrbit_track: ORBIT-CLOSURE — a witness containing one class of an orbit
  contains them all (track + source-period index surgery)
- firstMem_congr_mem: list-relative firstMem congruence
- qpos + qpos_spec + qpos_qm: the canonical position function — choose the
  InOrbit index, reduce mod qPeriod; position of the j-th class IS j
  (trichotomy + qorb_injective both ways).
All [propext, Classical.choice, Quot.sound].

Everything the global cy assignment consumes now exists. Next: define orbCy
by firstMem over the orbit list, discharge hcy (coherence via inOrbit_track
+ firstMem_congr_mem + qpos_qm, bundle via orbit_cy_bundle), apply
walked_assembly_roles -> rankNxt_quot_solvesBA.

## THE ORBIT GLUE: rankNxt_quot_solvesBA (loop iteration 15)

- orbCy: the global cycle assignment — first-match search over the orbit
  list; stores (qPeriod, canonical enumeration from the found rep, qpos).
- rankNxt_quot_solvesBA: THE CANONICAL QUOTIENT OF A RANK-MODULO-SIMPLE-
  CYCLE AUTOMATON IS SOLVABLE, given an orbit list covering all non-base
  classes. hcy discharge: destructure the stored triple (Option/Prod
  injEq + subst), coherence = every class of one cycle finds the SAME rep
  (inOrbit_track both ways + firstMem_congr_mem) with canonical positions
  (qpos_qm), bundle components 5-10 = orbit_cy_bundle verbatim. hbase from
  the cover (firstMem_isSome kills the none case). walked_assembly_roles +
  decomp_solves + solvesBA_unclean close it.
[propext, Classical.choice, Quot.sound] — FIRST PASS.

THE ORBIT LAYER IS COMPLETE. The generalization ladder now reads:
  singleton_scc_roles -> rankSelf_quot_solvesBA (self-loops)      [done]
  orbit machinery     -> rankNxt_quot_solvesBA (simple cycles)    [DONE]
Remaining for chainloops_complete: the ChainLoops fragment — Thompson
automata of wh b (p1;...;pn) chains are rank-mod-nxt with a covering orbit
list (hos/hcover discharge by construction), then the completeness wrapper
(equivBA_of_quot_solvesBA pattern from atomicloops_complete).

## INTERIOR DESCENT-FREENESS FROM DETERMINISTIC STEPPING (loop iteration 16)

- interior_no_desc: an orbit member that steps UNIQUELY to its successor at
  every atom (hstep_uniq: autStep = some (a, next) for all alpha) gives its
  quotient class NO descending arms. Every cleaned quotient arm fires at
  some atom; the class word at that atom must start with the unique source
  letter (letter extraction by determinism); the arm target's language is
  then THE successor's language (derivative pinch from both sides), and
  successor + self both sit at cycle level rank u0 — descent is
  Nat.lt_irrefl. [propext, Classical.choice, Quot.sound] — FIRST PASS.

This converts rankNxt_quot_solvesBA's hnodesc obligation (about CLEANED
QUOTIENT arms — hard for a fragment to see) into hstep_uniq (a constructive
single-step fact about the source Thompson automaton — chain positions have
one guard-1 arm). Fragment obligations for chainloops_complete now:
  per orbit rep: hk/hper/hlive/hnofix/hmin, 2 <= qPeriod, hstates,
                 hstep_uniq at interiors, hnoeps at interiors
  global: hdec/hnxt_rank/hfire, cover (minRank realizer case-split)
Next: ChainLoops inductive + chain-Thompson structural facts.

## THE FIRED-ARM WEAKENING (loop iteration 17)

Obstacle found while reading loopInitialized: the Thompson loop construction
adds feedback arms to EVERY body state (guard hlt(state) ∧ b ∧ init-guard).
At interior chain positions hlt is semantically empty, so these arms never
fire — but they exist syntactically, targeting the loop head, violating
hdec as stated (target ≠ nxt, equal rank).

Fix: hdec is only ever CONSUMED on arms found by firstMatch — arms that
fired at a generic atom. Weakened hdec across the entire orbit layer to
  ∀ s, ∀ e ∈ aut.trans s, (∃ α, bval (genW T) e.1 α = true) → dichotomy
- trimList_target_mem_fires: trim membership + the original guard fires
  wherever the trimmed guard does (trim guards are g ∧ ¬D conjunctions)
- firstMatch_mem_fires: firstMatch returns a FIRING arm
- 27 signatures weakened in GkatOrbitProofs + quot_cycle_dichotomy;
  3 hdecT consumption sites patched with firing witnesses.
ZERO new errors — every proof in the layer survived the weakening intact.

Phantom feedback arms of loopInitialized are now exempt: the fragment
discharges them by refuting the firing witness (their guards are
semantically empty). The hdec obligation is now constructively provable
for chain Thompson automata.

## QUEUED CAMPAIGN: DE-CHOICE (user-approved 2026-08-20)

After chainloops_complete lands, the standing loop pivots to removing
Classical.choice from the axiom base (target: [propext, Quot.sound], making
the completeness witness computable). Phases:
1. Finite-support satisfiability: bval depends only on tests occurring in
   the guard => decidable by finite Boolean enumeration.
2. Decidable liveness (bounded reachability over the finite state list).
3. Decidable bisimilarity (partition refinement at genW over mentioned
   tests); bisimRep := first-bisimilar-in-list (canonical, choice-free).
4. minRank as list-minimum over aut.states; requantify hmin over states.
5. Replace classical dites/by_cases with decidable instances; shrink axiom
   prints file by file.

## THE CHAIN SHAPE THEOREM (loop iteration 18)

New file GkatChainFragmentProofs.lean:
- Chain: bodies that are sequences of actions
- ChainInit: deterministic silent-free entry (initHlt semantically zero,
  one everywhere-firing init arm into first, all fired init arms agree)
- ChainSpine: recursive spine predicate — interior states silent +
  deterministic (everywhere-firing arm to successor, all fired arms agree,
  distinct from the rest), last state halts everywhere with no arms
- chainSpine_seq_right / chainSpine_seq_left: the spine survives Thompson
  sequential composition — right summand verbatim, left summand with its
  last state rewired into the right head through the glue arms (the glue
  guard leftHlt ∧ rightInit fires everywhere at the junction, nowhere at
  interiors; left-last's composite halt dies against rightInitHlt)
- chainInit_seq: entry survives on the left
- chain_shape: EVERY chain body's Thompson automaton is a spine with
  deterministic entry, states = spine exactly.
Axioms: [propext, Quot.sound] — CHOICE-FREE (a head start on the queued
de-choice campaign).

Also queued this iteration (user-approved): the DE-CHOICE campaign after
chainloops_complete. Next: the loop case — loopInitialized of a spine is
rank-mod-nxt with the orbit bundle facts (hstep_uniq/hnoeps/hfire/hdec),
then toGAut/sumGAut transport, os construction, wrapper.

## THE SPINE WALK (loop iteration 19)

- spineNext: the successor along a list, wrapping at the end — THE nxt
  function the orbit layer will consume for chain loops
- spineNext_at: successor of the j-th element is the j+1-st (first-
  occurrence hit justified by head-not-in-tail)
- spineNext_last: the last element wraps
- spine_iter: j steps from the head land on the j-th element
- spine_period: the walk closes after length steps (stated successor-form
  n+1 to avoid subtraction-motive rewrites)
- spine_distinct: positional pairwise distinctness (feeds hnofix)
(spineNext uses classical decEq — will become derived DecidableEq in the
de-choice pass; spine_distinct itself is already choice-free.)

Remaining for chainloops_complete: the W-level fact bundle (loopInitialized
of a spine: fired-arm classification with the three-way b case split
(b unsat -> descending ranks/no orbit; not-b unsat -> dead/base; both sat ->
constant rank + orbit with port basepoint l[len-1])), the none~last
language identification for the init class, toGAut/sumGAut transport, os
construction, wrapper.

## THE LOOP ARM CLASSIFICATION (loop iteration 20)

Positional extraction of ChainSpine (spine_hlt_int_at / spine_fired_at /
spine_real_at / spine_last_nil / spine_hlt_last), then the complete
classification of loopInitialized b B over a spine — FIRST PASS, zero
errors:
- loop_hlt_int: interior loop states are silent (body-hlt zero kills the
  ∧ ¬b)
- loop_hlt_port: the port halts EXACTLY at ¬b
- loop_arms_interior: fired interior arms go only to the spine successor
  (feedback arms die on the silent interior halt conjunct)
- loop_arms_port: fired port arms feed back exactly to the head
  (body arms vanish — trans last = []; ChainInit.fired pins the target)
- loop_real_interior: an everywhere-firing arm to the successor
- loop_real_port: a feedback arm firing EXACTLY with b, to the head.

These are precisely hdec/hfire/hstep_uniq/hnoeps shaped, pre-trim.
Remaining: three-way b case split + toGAut/sumGAut transport + trim-level
step lemmas + none~last identification + os/cover assembly + wrapper.

## THE SUM-LEVEL DICHOTOMY (loop iteration 20b, "Continue")

- chain_exhaustive: every value of a chain state type is on the spine
  (Unit/Sum structural induction)
- loop_arms_all: CONSOLIDATED loop dichotomy — every fired arm of
  loopInitialized follows spineNext (position case split via
  getElem_of_mem: interior -> spineNext_at, port -> spineNext_last)
- toGAut_chain_arms: the init state's fired arms enter the head (double
  map unwrap + ChainInit.fired); core states follow spineNext
- sum_chain_hdec: THE Σ-LEVEL FIRED DICHOTOMY — for the sum of two chain
  loops with rank (init=1, core=0), every fired arm follows the Sum-lifted
  Option.map spine successor or strictly descends. This IS the weakened
  hdec hypothesis of rankNxt_quot_solvesBA, discharged for the actual
  SUMof-shaped automaton.
- sum_chain_nxt_rank: the lifted successor preserves the 0/1 rank (hnxt_rank).
ALL FIRST PASS, zero errors.

hdec + hnxt_rank for the composite are now DONE. Remaining: trim-level
hfire/hstep_uniq/hnoeps transport (autStep_sumGAut_inl/inr + a toGAut
autStep lemma + trim step preservation), liveness facts, none~last
identification, os/cover assembly, wrapper.

## TRIM TRANSPARENCY + RUN EMBEDDINGS (loop iteration 21)

- trimList_all_live: when all arm targets are live, trimming is an
  explicit guard conjunction with ¬0 — nothing is dropped, D never grows
- firstMatch_guard_conj_notzero: conjoining ¬0 changes no firing
- autStep_trimAut_all_live: TRIM TRANSPARENCY — at an all-live-targets
  state, the trimmed automaton steps exactly as the raw one, at EVERY
  valuation (the bridge from raw arm facts to trim-level hfire/hstep_uniq)
- autStep_toGAut_some + coreAut + autRun_toGAut_some: internal runs
  through the initialization wrapper are core runs
- autRun_sumGAut_inl/inr: summand runs are sum runs (word induction over
  the existing step lemmas).
Run embeddings need only [propext].

Remaining: spine liveness (exit-satisfiable => every spine state live in
the composite via the embeddings), hfire/hstep_uniq assembly through
autStep_trimAut_all_live, hnoeps transport, none~last, os/cover, wrapper.

## DETERMINISTIC STEPS + SPINE LIVENESS (loop iteration 22)

- firstMatch_some_target: a firing arm with all firing arms agreeing pins
  firstMatch to the common target
- loop_step_interior: at EVERY atom, the loop steps j -> j+1 (this is
  hstep_uniq's core content)
- loop_step_port: under b, the port feeds back to the head (hfire's core
  content at the port)
- spine_live_core: exit satisfiable => every spine state runs forward to
  the port and exits (induction on distance-to-port; the word is built
  from the actual firstMatch letters)
- spine_live_sum_inl/inr: liveness lifted through toGAut + sumGAut into
  the composite — the hlive/hstates-side obligations.
All [propext, Quot.sound] — choice-free.

The obligations of rankNxt_quot_solvesBA now discharged for chain-loop
composites: hdec, hnxt_rank, core-level hfire/hstep_uniq, liveness.
Remaining: assemble hfire at trim level (targets-live plumbing via
certificate InitTargetsListed/CoreStructural + autStep_trimAut_all_live),
hnoeps transport (hlt passes through verbatim), none~last, qPeriod >= 2,
os/cover assembly, wrapper.

## TRIM-LEVEL COMPOSITE STEPS (loop iteration 23)

- loop_targets_spine: all loop arms (body + feedback) target the spine —
  certificate CoreTargetsListed + InitTargetsListed + exhaustiveness
- spine_mem_live_inl / sum_targets_live_inl: every composite arm at a loop
  state has a live target
- sum_chain_step_interior: IN THE TRIMMED COMPOSITE, interior loop states
  step deterministically to their successor at EVERY atom
  (trim transparency + sum/toGAut step lemmas + loop_step_interior)
- sum_chain_step_port: under b, the trimmed composite feeds the port back
  to the head
- sum_chain_noeps: interior silence survives to the trimmed composite
  (hlt passes through every layer verbatim).
ZERO ERRORS FIRST PASS.

These ARE the hfire, hstep_uniq (interior_no_desc input), and hnoeps
obligations of rankNxt_quot_solvesBA, discharged at the exact automaton
the wrapper uses. Remaining: periodicity/hnofix packaging (spine_iter +
spine_distinct through the Sum/Option lift), qPeriod >= 2 + none~last,
os/cover assembly, the wrapper.

## COMPOSITE hfire + PORT WALK (loop iteration 24)

- nxtIter_lift_inl/inr: iteration commutes with the Sum/Option lift
- spine_iter_port / spine_period_port / spine_nofix_port: the PORT-based
  walk — iteration from the port traverses the spine, closes after length
  steps, never fixes below the period (needs 2 <= length; the length-1
  wrap-to-self case is exactly where hne is refuted instead)
- sum_targets_live_inr + sum_chain_step_interior_inr/port_inr: right-
  summand mirrors of the trim-level steps
- sum_chain_hfire: THE COMPOSITE hfire — every state of the trimmed sum
  with a moving lifted successor fires to it at some atom: init states
  are successor-fixed (vacuous), interiors fire at every atom, ports fire
  at a b-satisfying atom, and the length-1 port refutes the moving
  hypothesis.

The FULL orbit-bundle obligations of rankNxt_quot_solvesBA are now
discharged for chain-loop composites (both-satisfiable case):
  hdec, hnxt_rank, hfire GLOBAL, hper/hnofix (port walk + lift),
  hlive, hmin (rank 0 trivial), hstep_uniq, hnoeps.
Remaining: qPeriod >= 2 + none~last + hstates (quotient membership) +
os/cover assembly + the wrapper + degenerate-guard branches.

## THE INIT-PORT IDENTIFICATION (loop iteration 25)

- lang_eq_of_step_hlt: two states stepping and halting identically have
  the same language — NO induction needed (successors literally equal)
- autStep_toGAut_none: the init pseudostate's step is the init-arm match
- firstMatch_map_guard_congr: firstMatch only sees guard VALUES
- sum_targets_live_none_inl: init arms have live targets
- sum_chain_none_lang: THE INIT-PORT IDENTIFICATION — in the trimmed
  composite, ⟦inl none⟧'s language = ⟦port⟧'s language: both halt exactly
  at ¬b (initHlt = ¬b vs hlt_port ∧ ¬b with hlt_port ≡ 1), and both step
  identically (the port's body arms vanish, its feedback guards are the
  init guards under an always-true halt conjunct — firstMatch congruence).

The cover's last semantic ingredient. ⟦inl none⟧ = ⟦port⟧ via
rep_lang_congr => the init class IS on the orbit (position 0).
Remaining: qPeriod >= 2, hstates/spineNext_mem closure, os/cover
assembly, wrapper, degenerate branches.

## ORBIT-BUNDLE PACKAGING (loop iteration 25b, "Continue")

- spineNext_mem / spineNext_iter_mem: the spine is closed under its
  successor and all iterates
- sum_chain_states: spine members' classes are quotient states (hstates)
- sum_chain_hper: the lifted period at the port (nxtIter_lift +
  spine_period_port)
- sum_chain_hnofix: the lifted walk never fixes below the period
  (inl/some injectivity down to spine_nofix_port)
- sum_chain_qperiod2: 2 <= qPeriod — if the quotient period were 1, the
  port's class would equal the head's class, giving language equality
  refuted at (exit-atom, []): the port halts there, the head (interior,
  len >= 2) is silent. (Generalize-the-qPeriod-term first: omega treats
  syntactically distinct occurrences as distinct atoms.)

EVERY per-orbit obligation of rankNxt_quot_solvesBA is now proved for the
chain-loop composite (both-sat case): the os entry
(inl (some port), l.length) has hk/hper/hlive/hnofix/hmin/qPeriod>=2/
hstates/hnodesc (via interior_no_desc + hstep_uniq)/hnoeps. Remaining:
the cover (init class via none~port + orbit membership of spine classes;
inr side; degenerate branches), then the master assembly + wrapper.

## THE COVER (loop iteration 26)

- sum_targets_live_none_inr + sum_chain_none_lang_inr: right mirrors of
  the init-port identification
- sum_chain_cover: EVERY quotient class of the chain-loop composite is on
  one of the two listed orbits. Four class shapes: inl none -> port class
  at index 0 (rep_lang_congr over the init-port language equality);
  inl (some s) -> port iterate at index j+1 (lift + spine_iter_port);
  inr mirrors. ZERO ERRORS FIRST PASS. No base branch needed in the
  both-sat case.

ALL hypotheses of rankNxt_quot_solvesBA now proved for the chain-loop
composite (both-sat): hdec, hnxt_rank, hfire, os = two port entries with
full bundles (hk/hper/hlive/hnofix/hmin/qP>=2/hstates/hnodesc via
interior_no_desc/hnoeps), hcover. NEXT: the master assembly theorem
(chain_loops_solvable: instantiate rankNxt with all of the above +
interior_no_desc plumbing at iterate positions), then the wrapper
(equivBA_of_quot_solvesBA) for wh b1 chain1 ~ wh b2 chain2, then the
degenerate branches.

## THE MASTER ASSEMBLY: chain_loops_solvable (loop iteration 26b, "Proceed")

chain_loops_solvable: THE CANONICAL QUOTIENT OF THE SUM OF TWO CHAIN-LOOP
THOMPSON AUTOMATA IS SOLVABLE — rankNxt_quot_solvesBA instantiated with
the complete stack: sum_chain_hdec/nxt_rank/hfire, the two-port orbit
list with full bundles (hper/hnofix/hlive/hmin/qP>=2/hstates/
interior_no_desc-fed-by-deterministic-steps/hnoeps), and the total cover.
[propext, Classical.choice, Quot.sound], no sorries.

Fix inventory: qPeriod atoms are opaque to omega — convert bounds with
Nat.lt_of_lt_of_le at the TERM level; wrapped iterate equations need rw
of the inner lemma, not exact; named-hole ?tag inside obtain is not a
thing — hoist to have.

This is the existence half of the fourth theorem. Remaining:
1. chain_shape upgrade: also return hexh (chain_exhaustive), hlen2
   (2 <= spine length for multi-action chains), head-tie hfl.
2. The wrapper: ChainLoopPair fragment (e = wh b1 chain1, f = wh b2
   chain2, guards nondegenerate) -> chainloops_complete via
   equivBA_of_quot_solvesBA. Note SUMof A T e f must be DEFEQ-related to
   sumGAut (toGAut (certifiedThompson e).aut) ... — check SUMof def.
3. Degenerate branches (b unsat / not-b unsat / len 1) via
   prune/atomic-loop routes.

## ============================================================
## THE FOURTH UNCONDITIONAL COMPLETENESS THEOREM (loop iteration 27)
## ============================================================

chainloops_complete: UNIFORMLY EQUIVALENT WHILE LOOPS OVER MULTI-ACTION
CHAIN BODIES WITH NONDEGENERATE GUARDS ARE PROVABLY EQUAL FROM THE FINITE
GKAT AXIOMS ALONE. No uniqueness axiom. [propext, Classical.choice,
Quot.sound], no sorries.

  theorem chainloops_complete (b1 b2) (hc1 : Chain2 body1)
    (hc2 : Chain2 body2) (guards nondegenerate)
    (heq : UniformLanguageEquivalent (wh b1 body1) (wh b2 body2)) :
    EquivBA (wh b1 body1) (wh b2 body2)

This is the head-position Salomaa frontier with genuinely multi-action
bodies — the stratum atomicloops_complete could not reach, the case the
literature's "UA seems necessary in both known completeness proofs"
referred to. The wrapper: chain_shape + chain_loops_solvable +
equivBA_of_quot_solvesBA, with SUMof defeq to the sumGAut/toGAut/
loopInitialized composite.

THE LADDER: loopfree_complete -> atomicloops_complete -> gloops_complete
-> CHAINLOOPS_COMPLETE. Four unconditional strata, zero uses of UA.

Remaining polish: degenerate guards (b unsat via descending-rank base;
not-b unsat via dead/trim; single-action bodies via atomicloops route) to
drop the nondegeneracy hypotheses. Then per the user-approved queue: the
DE-CHOICE campaign.

## DEGENERATE GUARDS COLLAPSE (loop iteration 28)

- ite_false: ite 0 e f ≡ f — u4 inserts test-of-guard, s2 kills the then
  arm, ite_zero_then converts, s4 finishes
- wh_zero_skip: wh 0 e ≡ skip (w1 unroll + ite_false)
- wh_guard_semantic_one: guard true at every GENERIC atom => the loop is
  assert-false (bval_gen upgrades to all valuations, wh_guard swaps to
  the literal, S0's wh_one_zero finishes)
- wh_guard_semantic_zero: guard false at every generic atom => skip.
BOTH DEPEND ON NO AXIOMS — pure finite-axiom syntactic derivations.

For the hypothesis-free chainloops closure, remaining case analysis:
degenerate side collapses to test 0/test 1; then test-vs-test via
soundness-transported heq + baTest; test-vs-live-loop refuted by a
constructed loop word (needs den-level or automaton-level word
construction + soundness transport EquivBA -> ULE). Also mixed
single-action-vs-multi (needs a one-sided-orbit assembly variant or the
atomic route). NEXT per queue after closure: DE-CHOICE campaign.

## ============================================================
## THE HYPOTHESIS-FREE FOURTH THEOREM (iteration 28b, "Continue")
## ============================================================

chainloops_complete_free: UNIFORMLY EQUIVALENT WHILE LOOPS OVER
MULTI-ACTION CHAIN BODIES ARE PROVABLY EQUAL FROM THE FINITE AXIOMS —
ARBITRARY GUARDS, no uniqueness axiom, no side conditions beyond the
Chain2 shape. [propext, Classical.choice, Quot.sound].

  theorem chainloops_complete_free (b1 b2) (hc1 : Chain2 body1)
    (hc2 : Chain2 body2) (heq : ULE (wh b1 body1) (wh b2 body2)) :
    EquivBA (wh b1 body1) (wh b2 body2)

Closure pieces (28b): ule_congr_left/right + ule_symm (soundness
transports over sound_BA); test_test_equiv (uniform test equality =>
baTest); chain_den_word (a chain denotes its actions between ANY atoms);
wh_chain_word (a live loop denotes a word with an action);
test_ne_liveloop (tests never equal live loops); a 9-way classical case
split (degenerate sides collapse via wh_guard_semantic_one/zero, mixed
test-vs-live refuted, live-live delegates to chainloops_complete).

THE LADDER (all UA-free, no semantic side conditions):
  loopfree_complete -> atomicloops_complete -> gloops_complete
  -> chainloops_complete_free

PIVOT: per the user-approved queue, the loop now moves to the DE-CHOICE
campaign (plan under QUEUED CAMPAIGN above).

## DE-CHOICE PHASE 1: DECIDABLE GUARD SATISFIABILITY (iteration 29)

New file GkatGuardDecideProofs.lean:
- testsOf: the primitive tests occurring in a guard
- override / enumAtoms: all Boolean assignments over a finite test list
- bval_testsOf: FINITE SUPPORT — generic evaluation sees only occurring
  tests
- enumAtoms_complete: the enumeration realizes every atom on the list
- guardSatDecidable / guardRefDecidable: DECIDABLE satisfiability and
  refutability of guards at generic atoms, over [DecidableEq T] —
  computable instances at [propext, Quot.sound]. NO CHOICE.

Every Classical.em on guard degeneracy in the ladder (the 9-way split of
chainloops_complete_free, the collapse selection) can now run on these
instances. Next phases: decidable liveness (bounded reachability),
decidable bisimilarity at genW over mentioned tests (partition
refinement, bisimRep := first-in-list), minRank as list-min, then sweep
the classical dites.

## DE-CHOICE PHASE 2a: DECIDABLE BOUNDED LIVENESS (iteration 30)

- effList: arms with DISJOINT effective first-match guards (each conjoined
  with the negation of the accumulated earlier guards)
- effList_guard_refutes / effList_fires: a firing effective arm IS the
  first match — firstMatch fully decomposed into guard satisfiability
- liveWithin n s: acceptance within n steps; equation lemmas
- decideExMem: hand-rolled decidable bounded existential (no Mathlib)
- liveWithinDec: DECIDABLE bounded liveness — computable structural
  recursion over guardSatDecidable, [DecidableEq T] only
- liveWithin_live: bounded liveness IS liveness ([propext] only).

Remaining for phase 2: the completeness direction (Live -> liveWithin
|pool| under target-closure) via run splicing at a repeated state — the
pigeonhole/pumping argument; then trimListD := computable trim.

## DE-CHOICE PHASE 2b-1: THE CHAIN CORRESPONDENCE (iteration 31)

- liveWithin_of_acc / liveWithin_mono: acceptance lives at every bound;
  bounds are monotone
- effList_of_firstMatch: converse decomposition — a first match IS a
  firing effective arm
- StepChain: states linked by satisfiable effective arms, ending in
  acceptance
- liveWithin_chain / chain_liveWithin: bounded liveness ⟷ chains
  (length k+1 states = liveWithin k)
- run_liveWithin_len: any run gives bounded liveness at its own length —
  ZERO axioms.

Remaining for phase 2: chain dedup against a closed pool ([DecidableEq S]:
not_nodup_split extraction, splice preserves StepChain, Nodup+subset =>
length <= pool) => live_iff_liveWithin => computable trim.

## DE-CHOICE PHASE 2b-2: LIVENESS IS DECIDABLE (iteration 32)

- GkatListPigeonProofs.lean (NEW, import-free): removeOne (choice-free
  removal — core List.erase lemmas pull Classical.choice!) +
  long_in_pool_has_dup (constructive pigeonhole). Kept import-free
  because the Gkat import chain carries an ambient classical instance
  that pollutes downstream decidable case splits.
- effList_target_mem, stepChain_mem_pool (chains stay in closed pools),
  stepChain_drop, stepChain_splice (splice at a repeated state, head
  preserved), chain_shorten (strong-induction shrink to |pool|)
- live_iff_liveWithin: LIVE <-> liveWithin |pool| over a closed pool —
  [propext, Quot.sound], CHOICE-FREE. With liveWithinDec this makes
  liveness DECIDABLE.

Axiom-leak lessons: core List.length_erase_of_mem depends on
Classical.choice; ambient classical instances from imports silently win
instance resolution — isolate constructive kernels in import-free files.

Remaining de-choice: computable trim (trimListD via the decidable
liveness + equivalence to trimList), then bisim (phase 3), minRank
(phase 4), sweep (phase 5).

## DE-CHOICE PHASE 2c: THE COMPUTABLE TRIM (iteration 33)

- liveWithinInst: the decidable-liveness instance (beats low-priority
  Classical.propDecidable; computability check confirms resolution)
- trimListD / trimAutD: the COMPUTABLE trim — [propext, Quot.sound],
  compiles without noncomputable markers
- trimListD_eq_trimList / trimAutD_eq_trimAut: over a pool closed under
  transitions and covering all targets, the computable trim IS trimAut
  (the equality theorems inherit choice from trimList's own classical
  definition — the computable OBJECT is clean).

PHASE 2 COMPLETE. Every theorem about trimAut transports to trimAutD by
rewriting along trimAutD_eq_trimAut. Next: phase 3 — decidable
bisimilarity at genW (the big one: de-chooses bisimRep and every
quotient theorem), then minRank as list-min, then the sweep.

## DE-CHOICE PHASE 3a: THE STEP-EQUIVALENCE LADDER (iteration 34)

- optStepRel + stepEquivWithin: n-step equivalence at the generic
  valuation (halting agreement at every level, deterministic steps
  matched with related successors)
- genBisimilar_stepEquiv: bisimilar => every level (induction, the
  backward clause refutes asymmetric steps)
- stepEquiv_all_bisim: ALL levels => bisimilar — witnessed by the
  all-level relation ITSELF, explicitly, so no choice; determinism of
  autStep makes the matching successor unique across levels
- genBisimilar_iff_stepEquiv: THE LADDER CHARACTERIZATION — generic
  bisimilarity IS the intersection of the finite levels. Depends on NO
  AXIOMS AT ALL.
- stepEquivWithin_antitone (also axiom-free).

Remaining phase 3: stabilization (pair-pigeonhole: level N = level N+1 at
N = |pool|^2 forces all levels — the partition refinement bound), then
per-level decidability (finite support over pool tests), then
bisimRepD := first-in-list + the quotient transport.

Lean lesson: `cases h : term` rewrites term in the goal — subsequent
rw [h] finds nothing; check the goal, not the plan.

## DE-CHOICE PHASE 3b: EVERY LEVEL DECIDES (iteration 35)

- decideAllMem / decImp / decAnd / decNot: hand-rolled decidability
  combinators (instance-resolution-proof)
- guardEqDecidable: decidable guard equality at generic atoms (enum over
  the union support)
- armsOr + firstMatch_none_iff: stepping fails exactly where no guard
  fires
- forall_optStepRel_iff: THE STEP CONDITION IS FINITE — the forall-atom
  step clause is a finite conjunction over effective-arm pairs:
  co-satisfiable arms agree in letter and drop a level; no arm fires
  against the other side's none-region ([propext] only)
- stepEquivWithinDec: THE LEVEL DECISION PROCEDURE — structural recursion
  over [DecidableEq T] + [DecidableEq A], at [propext, Quot.sound].

Remaining phase 3: count-based stabilization (filter-length measure over
the pair list, strict drop per refinement, hence a fixpoint by |pool|^2)
=> genBisimilar decidable => bisimRepD := first-equivalent-in-list.

## DE-CHOICE PHASE 3c: BISIMILARITY DECIDES (iteration 36)

- stepEquiv_le (generalized antitone), autStep_target_pool,
  stepEquiv_stable_succ (a stable level propagates upward on a closed
  pool)
- pairList + filter_length_mono + filter_eq_of_length_eq (equal filter
  counts under pointwise implication force pointwise equivalence)
- desc_fix: a descending Nat function has a fixpoint within its initial
  value (pure constructive arithmetic)
- genBisimilar_iff_pairBound: STABILIZATION — on a closed pool, generic
  bisimilarity IS step equivalence at the |pool|^2 pair bound (the
  Moore/partition-refinement bound, via the eqCnt measure)
- genBisimilarDec: DECIDABLE GENERIC BISIMILARITY on closed pools —
  computable, [propext, Quot.sound].

The keystone of phase 3. Remaining: bisimRepD := first-equivalent-in-
list + coherence lemmas (rep equal iff bisimilar; idempotence), then the
quotient tower transport (bisimQuotAutD = bisimQuotAut over closed
pools), then minRank (phase 4) and the sweep (phase 5).

Lean lessons: `set` is Mathlib (banned) — hoist counters to private
defs; unifier picks the wrong filter instance — pin (p := f); explicit
type ascription forces defeq through private defs.

## DE-CHOICE PHASE 3d: THE CANONICAL REPRESENTATIVE (iteration 37)

- findBisim: first-equivalent-in-pool search over genBisimilarDec (letI
  the instance, so the ite reduces by cases on the decision term)
- findBisim_bisim / _mem / _coherent: the search finds an equivalent
  in-pool state, and equivalent queries find THE SAME state (mixed
  decision branches refuted by symm/trans; both carried the same
  existential invariant so the exhausted case is vacuous)
- bisimRepDT: the total canonical representative (dite on membership)
  with the FULL bisimRep spec: bisimRepDT_bisim, bisimRepDT_coherent,
  bisimRepDT_idem, bisimRepDT_mem — all [propext, Quot.sound].

Classical.choose's three load-bearing properties are now matched by a
computable function. Remaining phase 3: bisimQuotAutD (quotient over
bisimRepDT) + transport of quot_lang_eq/canonicalQuotient facts; then
phase 4 (minRank as bounded search over the pool — MOSTLY DONE ALREADY
via minUpTo once realizers restrict to states), phase 5 sweep.

## DE-CHOICE PHASE 3e: THE COMPUTABLE QUOTIENT (iteration 38)

- bisimQuotAutD: the canonical quotient over bisimRepDT — computable
- bisimQuotAutD_step: same one-step retargeting correspondence
  (firstMatch_retarget, unchanged)
- bisimQuotD_bisim_gen: the computable representative graph restricted
  to the pool is a bisimulation — the classical proof transplants
  verbatim, with autStep_target_pool discharging the membership
  obligations that bisimRepDT_coherent adds
- quotD_lang_eq: quotient classes carry their states' languages.
ALL FIRST PASS, [propext, Quot.sound].

PHASE 3 COMPLETE: satisfiability, liveness, trim, bisimilarity,
representative, quotient — the entire canonical-quotient pipeline is
computable and choice-free. Remaining: phase 4 (minRank over the pool)
+ phase 5 (sweep + assemble the computable witness end-to-end).

## DE-CHOICE PHASE 4: THE COMPUTABLE MINIMAL RANK (iteration 39)

- leastB + leastB_correct: bounded minimization of a monotone Bool
  predicate — hit-or-all-fail plus minimality, one induction
- existsRealizer + existsRealizer_iff: decidable pool-realizer search
  (rank <= n AND bisimilar-to-c, via genBisimilarDec with explicit
  @decide instances)
- minRankD + minRankD_spec + minRankD_le: the computable minimal rank
  over a pool, with the classical spec shape — [propext, Quot.sound]
- minRankD_eq_minRank: THE BRIDGE — on a trimmed automaton with an
  exhaustive pool, minRankD IS minRank, by spec antisymmetry (language
  equality <-> bisimilarity under LiveSteps closes both directions).

PHASE 4 COMPLETE. Remaining: phase 5 — the sweep + end-to-end assembly
of the computable witness (run the existence pipeline over
trimAutD/bisimQuotAutD/minRankD for chain-loop composites).

## ============================================================
## THE CERTIFIED DECISION PROCEDURE (iteration 40, "Continue")
## ============================================================

New file GkatDecideProofs.lean:
- thompsonDecEq / thompson_exhaustive / sumof_exhaustive: Thompson state
  types have decidable equality and enumerate — structurally, for ALL
  programs (Empty/Unit/Sum recursion)
- autLang_sum_inl/inr: languages through the sum embeddings
- ule_iff_start_bisim: PROGRAM EQUIVALENCE IS START-STATE BISIMILARITY
  in the trimmed Thompson sum (certifiedThompson_start_language +
  genericity + the LiveSteps capstone)
- uleDec: THE EQUIVALENCE DECIDER — UniformLanguageEquivalent is
  Decidable for ALL GKAT programs over decidable alphabets. Computes on
  trimAutD, transported along trimAutD_eq_trimAut. COMPILES COMPUTABLY.
- chainloops_equivBA_dec: THE CERTIFIED DECISION PROCEDURE — provable
  equivalence (EquivBA, finite axioms, NO UA) of chain-loop programs is
  Decidable: completeness (chainloops_complete_free) one way, soundness
  (sound_BA) the other, decision by uleDec.

Axiom prints carry Classical.choice only in ERASED proof positions (the
transport iffs mention classical trimAut); the computational content is
choice-free and executable. The de-choice campaign's goal — a certified,
computable decision path for the fourth theorem — is DELIVERED.

## THE WHOLE LADDER DECIDES (iteration 41)

- loopfree_equivBA_dec / atomicloops_equivBA_dec / gloops_equivBA_dec:
  the certified decision procedure extends to every stratum of the
  ladder by the same three-line pattern (completeness + soundness +
  uleDec). All computable.

THE CONSOLIDATED ARTIFACT LIST:
  Four unconditional completeness theorems (no UA):
    loopfree_complete, atomicloops_complete, gloops_complete,
    chainloops_complete_free
  One universal equivalence decider: uleDec (all GKAT programs)
  Four certified provable-equivalence deciders (one per stratum)
  A complete choice-free semantic pipeline (guards, liveness, trim,
    bisimilarity, representatives, quotient, minRank)
  The orbit layer (rankNxt_quot_solvesBA) for future strata.

THE REMAINING SUMMIT: nested loops (well-nestedness covariety per
ICALP'21 remains open in the literature; our orbit layer is parametric
in (rank, nxt) — the hierarchical-nxt generalization is the route).

## ============================================================
## THE NESTED-LOOP CAMPAIGN OPENS (iteration 42)
## ============================================================

New file GkatWalkedOrbitProofs.lean — the walked orbit layer:
- WalkedDec: the THREE-WAY fired-arm discipline (self OR successor OR
  descent) — the shape of states carrying inner loops
- walked_min_fire: minimal-level firings land on self-or-successor
- walked_class_succ_eq: the class successor is STILL well-defined at
  non-degenerate positions — with self-arms admitted, the new self-case
  (a realizer self-looping at the advance atom) would identify the class
  with its successor, refuted by hnontriv (adjacent orbit classes
  distinct, which qorb_injective supplies along genuine cycles).

KEY DESIGN DISCOVERY (scoping): walked_exit_cycle_roles ALREADY tolerates
member self-loops — the assembly is nested-ready; only the ORBIT layer
needs the three-way generalization. The campaign map: walk the orbit
layer's ~15 theorems through WalkedDec with hnontriv threaded at
class-successor uses (available below qPeriod via injectivity);
degenerate positions fold into the base branch. Then the fragment:
Thompson of wh b (chain-with-atomic-inner-loops) satisfies WalkedDec.
Target: NESTEDLOOPS_COMPLETE — the fifth theorem, covering the census's
remaining 2%.

## WALKED PROPAGATION + TRACKING (iteration 42b, "Proceed")

- walked_realizer_propagate: the three-way case adds a TRIVIAL branch —
  a self-landing realizer keeps its own rank (rank v = rank w)
- walked_cycle_level_min / walked_cycle_level_all: unchanged arguments
  over the walked propagate
- walked_qsucc_well_defined / walked_qsucc_iter: quotient-successor
  tracking with hnontriv (fragment-supplied adjacent-language
  distinctness) threaded to each walked_class_succ_eq site.

The walked orbit layer now has: min_fire, class_succ_eq, propagate,
cycle levels, qsucc tracking. Remaining to mirror: orbit_lang_determined,
qPeriod machinery (nxt-generic — check direct reuse), qorb_injective
(walked bundle), dichotomy + cy-bundle + glue (walked rankNxt), then the
nested fragment (WalkedDec by construction + hnontriv via shortest-exit
words) and nestedloops_complete.

## WALKED TRACKING + INJECTIVITY (iteration 43)

- walked_shift_min: rank minimality transports along walked orbits
- walked_orbit_lang_determined: shifted-orbit tracking, hnontriv at each
  successor site
- walked_qorb_injective: distinct classes below the first-return period
  (the qPeriod machinery — findFrom, qPeriod_spec, qorb_periodic, the
  nxtIter arithmetic — reused VERBATIM from GkatOrbit: it is nxt-generic).

Confirmed from the ICALP'21 record this iteration: well-nestedness is NOT
a covariety (quotients can break it) — which is exactly why this
machinery carries semantic invariants (WalkedDec survives collapse via
the dichotomy) instead of syntactic nesting. Remaining mirror:
walked quot_cycle_dichotomy + orbit_dichotomy + cy-bundle + glue, then
the nested fragment + nestedloops_complete.

## QUEUED CAMPAIGN: THE OPEN PROBLEM (user-directed 2026-08-20)

After the nested-loop campaign closes (nestedloops_complete), the
standing loop pivots to THE open problem itself: full GKAT completeness
with the uniqueness axiom eliminated — discharging RoleCovered for ALL
programs, not a fragment. The planned assault, building on everything
now proved:

1. GENERAL HIERARCHICAL DISCIPLINE: replace the single nxt with a
   per-level successor family (rank-indexed), subsuming WalkedDec; the
   dichotomy generalizes to "self ∨ some-level successor ∨ descend".
   Thompson automata of ARBITRARY programs satisfy it by construction
   (structural induction extending chain_shape to all of Exp).
2. GENERAL hnontriv: the shortest-exit-word stratification for arbitrary
   well-nested bodies; degenerate positions fold to base as established.
3. THE COVER for arbitrary programs: every quotient class is on some
   listed orbit or base — the minRank-realizer case split generalized
   (the census's residual instances are the test set).
4. Assembly: the walked/hierarchical rankNxt glue + wrapper =
   FiniteAxiomsCompleteBA A T — the full theorem.
5. Fallback checkpoints if blocked: publish the strata + the span
   reduction (equivBA_of_quot_solvesBA means ANY role-existence advance
   lifts); the decider artifacts stand regardless.

Sequence: nested campaign -> THE OPEN PROBLEM. De-choice is DONE.

## THE WALKED DICHOTOMIES (iteration 44)

- walked_quot_cycle_dichotomy: the quotient dichotomy keeps its exact
  SHAPE (self / descent / successor-class) under WalkedDec — the
  realizer's new self-landing case folds into the existing
  self-refutation (a self-landing makes the arm target's language the
  class's own, contradicting the branch's non-self assumption)
- walked_orbit_dichotomy: the abstract successor is the concrete next
  orbit class, with hnontriv at the single class_succ_eq site.
Both first pass.

Walked mirror scoreboard: 12 of ~15 theorems done. Remaining: walked
cy-bundle (rank-eq/port-descent/hint_nil/halt conditions — the halt and
pinning layers are hdec-free or dichotomy-fed, mostly reusable), walked
glue (walked rankNxt via orbCy — the orbCy architecture is nxt-generic),
then the NESTED FRAGMENT (spines with inner self-loops: WalkedDec by
construction, hnontriv by shortest-exit stratification) and
nestedloops_complete.

## THE WALKED CY-BUNDLE COMPONENTS (iteration 45)

- walked_orbit_rank_eq / walked_orbit_arms_pinned_nxtAt /
  walked_orbit_port_descent: rank equality, self-or-next pinning through
  the qPeriod wrap, and port descent under WalkedDec. All first pass.
  The halt layer (orbit_halt_empty, cy_halt_conditions_of_empty,
  hint_nil_of_pinned, qm_wrap) reuses verbatim — discipline-free.

Remaining: walked orbit_cy_bundle packaging + walked qorb_qmod/qpos/
inOrbit_track mirrors + walked glue (orbCy is nxt-generic), then the
NESTED FRAGMENT: spines-with-inner-self-loops (WalkedDec by
construction; hnontriv by shortest-exit stratification; the walked
interior-no-descent via per-atom self-or-next stepping) and
nestedloops_complete — the fifth theorem.

## WALKED POSITIONS + TRACKING (iteration 46)

- walked_qorb_period_all / walked_qorb_qmod: class-level periodicity and
  mod reduction under WalkedDec
- walked_qpos_spec / walked_qpos_qm: canonical positions with walked
  injectivity (qpos def reused verbatim)
- walked_orbit_track_from / walked_inOrbit_track: cross-witness tracking
  and orbit closure. All first pass.

THE WALKED MIRROR IS FUNCTIONALLY COMPLETE for the glue: every lemma the
rankNxt discharge consumed now has a walked twin (or reuses verbatim).
Remaining: walked_rankNxt_quot_solvesBA (the glue — orbCy reused, hcy
discharge re-threaded with hnontriv in hos), then the NESTED FRAGMENT.

## ============================================================
## THE WALKED GLUE (iteration 47, "continue")
## ============================================================

- walked_orbit_cy_bundle: the complete per-orbit package under WalkedDec
- walked_rankNxt_quot_solvesBA: A WALKED RANK-MODULO-CYCLE AUTOMATON
  WITH A COVERING ORBIT LIST HAS A SOLVABLE CANONICAL QUOTIENT. orbCy
  and walked_assembly_roles reuse verbatim (the assembly always allowed
  member self-loops); hos gains hnontriv per entry; coherence re-threads
  through walked_inOrbit_track + walked_qpos_qm.

THE WALKED ORBIT LAYER IS COMPLETE (~24 theorems, zero redesigns).
Remaining for nestedloops_complete: THE NESTED FRAGMENT —
1. nested spine shape (members with optional atomic inner self-loops)
   through act/seq/inner-wh Thompson composition
2. WalkedDec for the looped composite (fired arms: inner-self, outer-
   next, or the port feedback)
3. hnontriv via shortest-exit stratification
4. hfire/hnoeps/hstates/cover mirrors of the chain fragment
5. the wrapper.

## ============================================================
## THE TWO-LOOP FRAGMENT OPENS (iteration 48)
## ============================================================

SCOPING DISCOVERY (the iteration's core product): general inner loops
are SKIPPABLE — the ¬c bypass creates per-atom branching to two forward
cycle positions, genuinely beyond WalkedDec (the census hard 2%,
confirmed by hand-computing Thompson automata). BUT the shape
  wh b ((wh c q); r)
— inner loop first, one trailing action — fits WalkedDec EXACTLY: the
re-entry skip lands on the port itself (self-arm), giving two
interlocking cycles (inner self-loop + outer 2-cycle) sharing states.

New file GkatTwoLoopProofs.lean:
- twoLoop/twoLoopBody/twoLoopAut/twoNxt defs
- two_state_dec (every target is self-or-swap — ZERO AXIOMS; hdec is
  free in a 2-state space), twoNxt_period/nofix
- twoLoop_hlt_inl (interior silence) / twoLoop_hlt_inr (port exits ¬b)
- twoLoop_step_inl_self/adv, twoLoop_step_inr_feed/self/none: the FIVE
  concrete step facts at (c), (¬c), (b∧c), (b∧¬c), (¬b) atoms — the
  show-normal-forms machine-verify the hand-computed automaton.

Remaining: Σ-level (liveness under sat(b∧c)/sat(¬c)/sat(¬b), trim
transparency, walked-hos discharge with hnontriv from port/interior
ε-distinctness, cover with init~port), the wrapper:
TWOLOOPS_COMPLETE — the FIFTH theorem, first with genuinely nested
cycles.

## QUEUED CAMPAIGN: STEELMAN HARDENING (user-directed 2026-08-20)

After the open-problem campaign, the loop pivots to pre-empting the
steelman objections (analysis on record in session):
1. GkatStatementKernel.lean — the ~200-line trusted statement base a
   referee must read, annotated with paper citations.
2. BA-congruence derivability: baTest/ite_guard/wh_guard derivable from
   the published syntactic Boolean-algebra axioms.
3. Model equivalence: UniformLanguageEquivalent <-> guarded-string
   language equality over atoms 2^T; note the language-vs-bisimulation
   fork explicitly.
4. Edge cases: T/A empty/degenerate; no typeclass leakage into the
   completeness statement.
5. Harness validation: differential-test uleDec against an independent
   GKAT implementation.
6. Claim-wording pass: n-ary UA scheme eliminated (W3 = n=1 retained);
   language-model completeness; decidability-not-efficiency.

FULL QUEUE: two-loop/nested -> OPEN PROBLEM -> STEELMAN HARDENING.

## TWO-LOOP LIVENESS + TRIM STEPS (iteration 49)

- twoLoop_live_inl/inr/all: both states live given sat(¬c) + sat(¬b)
  (inner advances at a ¬c-atom then exits; port exits immediately) —
  liveness words of length ≤ 1, through the run embeddings
- twoLoop_targets_live: every composite arm target is one of the two
  live states (no list reasoning — totality of Sum Unit Unit)
- twoLoop_trim_step_inl_self/adv + inr_feed/self: the four trim-level
  composite steps at (c), (¬c), (b∧c), (b∧¬c) atoms.
All first pass.

Remaining: parity lemma (nxtIter twoNxt alternates) -> hper/hnofix/
hnontriv/qPeriod≥2 at Σ; hnodesc (minRank 0); init~port; cover; the
walked-hos assembly; twoloops_complete.

## TWO-LOOP ORBIT BUNDLE (iteration 50)

- twoNxt_iter: the swap walk alternates by parity
- twoLoop_lang_ne: THE ε-SEPARATION — the port accepts the empty word at
  a ¬b-atom, the inner state never does; the two classes are distinct
- twoLoop_noeps_inl: interior silence at the trimmed composite
- twoNxtL + twoLoop_hper (period two, lifted) + twoLoop_hnofix
- twoLoop_hnontriv: adjacent orbit languages differ — the walk
  alternates between the ε-separated classes (parity case split; odd j
  makes j+1 even — the mislabeled branch was the only fix needed).

Remaining for twoloops_complete: qPeriod ≥ 2 (mirror of the chain
argument over lang_ne), hnodesc via minRank 0, hstates, hfire (needs
sat(b∧c) + the inr-side mirrors of liveness/steps), init~port, cover,
walked-hos assembly, wrapper.

## TWO-LOOP PERIOD, DESCENT, MEMBERSHIP, INIT (iteration 51)

- twoRank (init 1, core 0) + twoLoop_minRank_zero + twoLoop_hnodesc:
  descent-freeness is FREE — nothing descends below rank zero
- twoLoop_hstates: concrete quotient membership for both core states
- twoLoop_qperiod2: the ε-separated classes make a genuine 2-cycle
  (period-1 collapse refuted by twoLoop_lang_ne through the rep-lang
  sandwich)
- twoLoop_step_init_feed/skip/none: the three init-state step facts
  (enter inner at b∧c, SKIP TO PORT at b∧¬c, rest at ¬b) — the init
  behaves exactly as the port does, setting up init~port.

Remaining: inr-side mirrors + hfire + init~port via lang_eq_of_step_hlt
+ cover + walked-hos assembly + wrapper => TWOLOOPS_COMPLETE.

## TWO-LOOP INIT~PORT + LEFT COVER (iteration 52)

- twoLoop_targets_live_none: init arms have live targets
- twoLoop_none_lang: THE INIT-PORT IDENTIFICATION — steps agree by the
  (b,c)-atom case split (feed/feed, skip/self, none/none) and halts are
  both ¬b
- twoLoop_cover_inl: every left class is on the port orbit — init via
  rep_lang_congr over the identification (index 0), port at 0, inner at
  1 (rfl-level iterate).

Remaining for twoloops_complete: inr mirrors (live/targets/trim-steps/
none_lang/cover — mechanical), hfire (sat(b∧c) hypothesis), the
walked-hos assembly, wrapper. ONE OR TWO FIRINGS.

## TWO-LOOP RIGHT MIRRORS (iteration 53)

All right-summand mirrors first pass: live_all_r, targets_live_r (+none),
trim steps (self/adv/feed), none_lang_r, twoNxtR, cover_inr.

EVERYTHING for twoloops_complete is now proved except the final
assembly: hdec/hnxt_rank/hfire at the pair level (two_state_dec makes
hdec near-trivial), the os-list hos tuples (all components proved), the
combined cover, walked_rankNxt_quot_solvesBA application, and the
equivBA_of_quot_solvesBA wrapper. NEXT FIRING: THE FIFTH THEOREM.

## TWO-LOOP RIGHT ORBIT BUNDLE (iteration 54)

hper_r, hnofix_r, lang_ne_r, hnontriv_r, qperiod2_r, twoRankR +
minRank_zero_r + hnodesc_r, hstates_r, noeps_inl_r — the complete
right-summand orbit bundle. All proved.

EVERY component of both hos tuples now exists. NEXT FIRING: the
assembly (twoLoops_solvable via walked_rankNxt_quot_solvesBA — note
twoNxtL twoNxt = twoNxtR twoNxt definitionally, so one nxt serves both
sides) + the wrapper = TWOLOOPS_COMPLETE.

## ============================================================
## THE FIFTH UNCONDITIONAL COMPLETENESS THEOREM (iteration 55)
## ============================================================

twoloops_complete: UNIFORMLY EQUIVALENT TWO-LOOP PROGRAMS — GENUINELY
NESTED CYCLES — ARE PROVABLY EQUAL FROM THE FINITE GKAT AXIOMS ALONE.
No uniqueness axiom. [propext, Classical.choice, Quot.sound], no
sorries.

  theorem twoloops_complete :
    (guard nondegeneracies: sat(¬c), sat(¬b), sat(b∧c) each side) ->
    ULE (wh b1 ((wh c1 q1); r1)) (wh b2 ((wh c2 q2); r2)) ->
    EquivBA (wh b1 ((wh c1 q1); r1)) (wh b2 ((wh c2 q2); r2))

This is the FIRST completeness result for programs whose Thompson
automata have genuinely interlocking cycles — the shape the literature
flagged as "unlikely" reachable via well-nested methods (non-closure
under homomorphisms), reached here precisely BECAUSE the invariants are
semantic and quotient-stable. The walked orbit layer (24 theorems, zero
redesigns) carried it.

THE LADDER: loopfree -> atomicloops -> gloops -> chainloops(free) ->
TWOLOOPS. Five unconditional strata, zero uses of UA.

Assembly lessons: obtain CONSUMES hypotheses (use id-copies);
twoNxtL twoNxt = twoNxtR twoNxt needs a defeq bridge lemma for rw;
pair-projection beta-noise from subst blocks rewrites.

NEXT per user queue: the OPEN PROBLEM campaign (branching-successor
discipline for skippable inner loops — the located obstacle), then
STEELMAN HARDENING.

## ============================================================
## THE OPEN-PROBLEM CAMPAIGN OPENS: THE CHORD (iteration 56)
## ============================================================

DESIGN (the pivot's core): the branching obstacle resolves in two
coordinated moves —
1. ASSEMBLY: a cycle with forward chords still unrolls to ONE Salomaa
   equation per basepoint (every path returns within a lap), so w3
   alone solves it — the chord-cycle role generalizes wChain's linear
   dispatch to a guarded DAG dispatch.
2. ORBIT: the atom-indexed derivative is class-determined, so a
   successor SET (the forward cascade) replaces the successor function;
   pinning says fired arms hit self ∨ the cascade ∨ descent.

New file GkatThreeLoopProofs.lean — the minimal beyond-walked program
wh b (p; (wh c q); r): cycle p → q → r → p with CHORD p → r (skip) and
self-loop at q. Machine-verified: the branch (p enters at c / SKIPS TO
THE PORT at ¬c — the chord), inner self/adv, port feed/rest (with the
two phantom feedback arms written out), and the halt structure
(p, q silent; r exits ¬b). All [propext, Quot.sound].

Next: the chord-cycle role at the GkatCycle level (the w3 unrolling for
the 3-cycle-with-chord), then the branching orbit layer (successor
sets), then sixth theorem threeloops_complete, then generalize.

## Iteration 57 — THE CHORD-CYCLE ROLE THEOREM (assembly half of the open problem)

`chord3_roles` (GkatThreeLoopProofs.lean, axioms **[propext]** only): for any
automaton and solution family with the chord-3 shape —

- `sol Q = (wh c q); (r; sol R)`  (inner loop solved locally)
- `sol P = ite c (q; sol Q) (r; sol R)`  (the branch dispatch)
- `sol R = wh b (p; chordPre)` where `chordPre = ite c (q; ((wh c q); r)) r`
  (ONE while-loop over the full lap body)

and gathered-equation hypotheses `EquivBA (eqRHS s) (dispatch form)` for each
state — **all three states get StateRoles**:

- `Q` via `salomaaE` (w3's one-unknown power),
- `P` via `equivFold` (its solution IS its dispatch — syntactic),
- `R` via `equivFold` through the derivation chain:
  `sol R ≡[w1] ite b ((p;chordPre); sol R) 1 ≡[s1] ite b (p; (chordPre; sol R)) 1`
  and the **factoring lemma** `chordPre; sol R ≡ sol P` via `u5`
  (seq-over-ite distribution) + `s1` associations.

**This is the designed elimination order, machine-checked**: inner self-loops
first (Salomaa, local), then the branch state (fold after substitution), then
the port (Salomaa on the unrolled lap). The chord costs NO new axiom — the
per-atom branching to two forward positions is dissolved by elimination
before the port equation is formed, so w3 (n=1) suffices. No n-ary UA.

Remaining for `threeloops_complete` (sixth theorem): the ORBIT half — the
branching-successor discipline (successor SETS / cascade pinning) to show the
canonical quotient of the trimmed Thompson sum has this shape, i.e. the
analogue of `walked_rankNxt_quot_solvesBA` for chord automata; then cover +
assembly as in the fifth theorem.

Next bite: the branching orbit layer — define the chord discipline
(self ∨ enter ∨ skip ∨ descent with enter/skip both forward) and prove the
class-successor lemma for atom-indexed successor sets.

## Iteration 58 — the TAILED chord role (assembly-ready) + literature check

Web check: the skip-free GKAT line (Kappe et al., arXiv 2301.11301) and
Weighted GKAT (2504.20385) still frame UA as necessary in both known
general completeness proofs; skip-free is the only published UA-free
fragment. Our five theorems + the chord program are beyond that line.

`chord3_roles_tail` (GkatThreeLoopProofs.lean, axioms **[propext]**):
the port now carries a continuation `tail` — its gathered descent arms and
halt — so the theorem applies to real quotient ports (exits below cycle
rank), exactly what `walked_assembly_roles`-style assembly feeds. Same lap
derivation; the tail rides along by `u5` right-distribution + `s4`
skip-left. Gotcha: `u5` is oriented distributed→factored, so the unroll
uses `EquivBA.symm` around it.

Assembly design (read `walked_assembly_roles` + `asmSolW` this iteration):
the chord analogue keys a classifier `cy : S → Option (chord cluster × pos)`
with closed forms per position (port = tailed wh-lap, branch = the c-dispatch,
inner = (wh c qB);(rB; port-form)) and derives the `hrhs` equations via
`eqRHS_foldTL` + `double_gather` (u := inner, v := port targets) + guard
domination — `double_gather` already gathers ANY two distinguished targets,
so the branch state needs no new gathering machinery.

Next bite: `chord_assembly_roles` — the classifier-keyed WF-recursion
solution (asmSolC) + the per-cluster role theorem consuming gathered-arm
bundle facts, mirroring `walked_assembly_roles`.

## Iteration 59 — split-parameter chord roles + the else-collapse massage

Two new certified pieces in GkatThreeLoopProofs.lean:

- `chord_else_collapse` (**zero axioms**): a two-way dispatch whose guards
  cover (`GuardImplies (¬g₁) g₂`) and whose halt is empty collapses:
  `ite g₁ X (ite g₂ Y (test h)) ≡ ite g₁ X Y`. Route:
  `ite_else_restrict` (Faithfulness) → `ite_guard` (¬g₁∧g₂ ≡ ¬g₁ under the
  cover) → `baTest` (empty halt → 0) → `ite_zero_else` → symm
  `ite_restrict_else` (GuardedAlgebra). This is THE massage that turns
  `double_gather`'s three-layer output into the chord dispatch shape.

- `chord3_roles_split` (**[propext]**, first-try): the roles theorem with
  SEPARATE gathered data at the branch state (`cG qB rB`) and the inner
  state (`cQ qBQ rBQ`) — on a real quotient each state gathers its own arm
  list, so the guards need not coincide syntactically. `chordPreS` splices
  the inner state's own solved loop into the branch dispatch; the factoring
  lemma is parameter-agnostic.

The per-cluster derivation pipeline is now fully stocked:
`eqRHS_foldTL` → `double_gather` (any two distinguished targets) →
`chord_else_collapse` → `chord3_roles_split`. What remains for the sixth
theorem is the classifier assembly (`asmSolC` + `chord_assembly_roles`
mirroring `walked_assembly_roles`) and the fragment facts for the concrete
threeLoop quotient (cover, liveness, guard facts — the twoLoop playbook).

Lit check: cyclic proof systems for GKAT (2405.07505) and GKAT automata
learning both work modulo the standard UA-based completeness; nothing
touching UA-free nested/chord fragments.

## Iteration 60 — THE CHORD ASSEMBLY THEOREM (the assembly half is DONE)

`chord_assembly_roles` (GkatThreeLoopProofs.lean, axioms
[propext, Classical.choice, Quot.sound] — same profile as
`walked_assembly_roles`), **built first try**: an automaton whose every
state is base (arms self or strictly descending) or a member of a
designated chord-3 cluster — port with descent exits, covering branch
dispatch, covering inner loop, empty interior halts — is fully
role-covered.

The machinery: closed forms `chordPortE` / `chordBranchE` / `chordInnerE`
over gathered arm data (`gGuard`/`gBody`/`gOthers`), the WF-recursion
solution `asmSolC` keyed by a classifier
`cy : S → Option ((S × S × S) × Nat)` (positions 0=port, 1=branch,
2=inner), congruence lemmas discharging the rank guards, and the cluster
bundle: coherence, rank equality, port descent, interior `gOthers = []`,
guard covers (`GuardImplies (¬enter) exit`), empty interior halts.
Per-cluster roles via `eqRHS_foldTL` → `double_gather` /
`multi_gather` → `chord_else_collapse` → `chord3_roles_split`.

Local re-declaration needed: `foldTL_congr'` is private in
GkatCycleProofs → `foldTL_congrC`.

**Status of the open problem**: the ASSEMBLY half is complete and general.
Remaining is the FRAGMENT/ORBIT half: exhibit the classifier and discharge
the bundle facts for the canonical quotient of the trimmed Thompson sum of
two threeLoop programs — the twoLoop playbook (concrete steps → liveness →
trim transparency → quotient cover → the bundle) but with the branching
cluster in place of the walked cycle. Then `threeloops_complete` closes.

Next bite: start the threeLoop fragment facts — sum-automaton step lemmas
(Σ-lifts of the six step lemmas), liveness of the three states, and the
language-distinctness facts (`hnontriv` analogues: lang P ≠ lang Q ≠
lang R under guard-nondegeneracy sat hypotheses).

## Iteration 60b (user-directed) — THE CHOICE-FREE CHORD ASSEMBLY

User asked: can we eliminate choice? Trace: `Classical.choice` enters the
assembly SOLELY through the classical `if u = t` state-equality decisions
in `gGuard`/`gBody`/`gOthers` (GkatPlanExistence, `open Classical`). The
EquivBA cores were already clean (`arms_merge`/`arm_commute`/
`ite_zero_guard`/`foldTL`: zero axioms).

De-choiced in GkatThreeLoopProofs.lean via the trimAutD/bisimRepDT
pattern, with `[DecidableEq S]`:
- `gGuardD`/`gBodyD`/`gOthersD` (computable) + `gOthersD_sub`
- `multi_gatherD`, `double_gatherD` — **ZERO axioms**
- `chordPortED`/`chordInnerED`/`chordBranchED` + congruences, `asmSolCD`
- **`chord_assembly_rolesD` : [propext, Quot.sound]** — choice ELIMINATED
  from the entire assembly half of the open problem.
- Bridges `gGuardD_eq_gGuard`/`gBodyD_eq_gBody`/`gOthersD_eq_gOthers` for
  interop with classical-side lemmas (proved by `simp only` equation
  unfolding + double `if_pos/if_neg`; the private classical cons lemmas
  are inaccessible and the two `ite`s carry different Decidable
  instances, so `rfl`/`show` transport does NOT work — rewrite each side).

Whole-chain de-choice (summit reduction + fragment) remains a STEELMAN
HARDENING item. The fragment half should now target the D-bundle
directly (concrete state types have structural DecidableEq via
thompsonDecEq), so the sixth theorem can inherit the leaner profile.

Next bite (back on mainline): the threeLoop fragment facts — Σ-lifted
step lemmas, liveness, language distinctness, quotient cover — feeding
`chord_assembly_rolesD`.

## Iteration 61 — fragment facts, left side: liveness + trim transparency

Route decision locked in after reading the walked glue tail and
`cleanAut`: the sixth theorem needs NO general branching-orbit layer.
The pipeline is `chord_assembly_roles` applied to
`cleanAut (bisimQuotAut (trimAut sum))` → `decomp_solves` →
`solvesBA_unclean` → `equivBA_of_quot_solvesBA`, with the cluster bundle
facts COMPUTED CONCRETELY: `cleanList` provably drops the port's two
phantom arms (guards contain `.and .zero`), so the cleaned quotient arm
lists are 1–2 elements and the gathered-guard facts are direct
computations. (cleanAut is classical → the sixth theorem carries choice
like theorems 1–5; cleanAutD is STEELMAN work.)

New block in GkatThreeLoopProofs.lean (12 lemmas, twoLoop playbook):
- `threeLoop_live_r/q/p/all` — every core state live given sat(¬c),
  sat(¬b); runs [(r, αb)] through the chord/adv arms.
- `threeLoop_targets_live` — all composite arm targets live (double
  List.mem_map unpack).
- `threeLoop_trim_step_p_enter/p_skip/q_self/q_adv/r_feed/r_none` — the
  trimmed sum steps are the concrete steps verbatim
  (`autStep_trimAut_all_live`). Gotcha: the `none` case needs a trailing
  `rfl` (nested `Option.map` on `none` isn't closed by `rw`).

Next: the right-side (_r) mirrors, then the language facts (ε-separation
`lang P ≠ lang Q ≠ lang R` under nondegeneracy sats + cross-side
pairings), then bisimRep computations and the classifier.

## Iteration 62 — right-summand mirrors + init–port identification

16 more fragment lemmas in GkatThreeLoopProofs.lean, all first-try:

- `threeLoop_targets_live_none(+_r)`, `threeLoop_live_all_r`,
  `threeLoop_targets_live_r` — right-summand liveness mirrors.
- Six `threeLoop_trim_step_*_r` — trimmed right-side steps verbatim.
- `threeLoop_step_init_enter/none` — the init pseudostate arm list is
  [(b∧1, p, pState), 2 phantoms with .zero guards] (discovered via
  #reduce); at `b`-atoms init enters the lap doing `p`, exactly like the
  port.
- **`threeLoop_none_lang(+_r)`** — init ~ port: the start class IS the
  port class in the trimmed sum (`lang_eq_of_step_hlt`, no induction).

The port-basepoint picture from twoLoop carries over unchanged: the
quotient cluster is (R̂ = start class, P̂, Q̂). Remaining for the sixth
theorem: language-separation facts (P̂/Q̂/R̂ pairwise distinct under
nondegeneracy sats: need sat(b∧c), sat(b∧¬c) style witnesses), cross-side
pairings (lang Pl = lang Pr etc. from the ULE hypothesis via word
analysis), bisimRep computations, the concrete classifier + bundle
discharge (cleanList phantom-drop), and assembly into
`threeLoops_solvable` + `threeloops_complete`.

## Iteration 63 — COURSE CORRECTION: the true chord witness

**Discovery**: `wh b (p; (wh c q); r)` is NOT a chord witness. The branch
state (post-p) and the inner-loop head have IDENTICAL residuals
(`(wh c q); r; loop`) — an inner while at the head of its residual always
re-enters at the branch position, so the two states are bisimilar and the
canonical quotient collapses to the walked 2-cycle shape (port + one
self-loop class). Its completeness follows from the WALKED machinery; it
never exercises the chord assembly. This holds for ANY inner body:
skippable inner whiles are quotient-invisible. The census 2% must be
realized by branches that rejoin LATER than the skip.

**The true witness**: `chordLoop b c p x y := wh b (p; ite c (x; y) y)`.
Thompson states: P = post-p (branch), X = post-x (mid), Yl/Yr = post-y
(collapse into the port with init). Quotient: port → P → X → port with
the CHORD P → port. P maps per-atom onto TWO forward positions — beyond
WalkedDec — and the cluster fits `chord_assembly_roles` exactly, with
the inner state (X) having a semantically-zero self-guard (the assembly
never required an actual self-loop: `wh 0 body ≡ skip` rides through
salomaaE with E(gBody)=0 trivially).

Grounded in GkatThreeLoopProofs.lean (14 lemmas, all first-try, arm
lists via #reduce): chordBody/chordLoop/chordLoopAut,
chord_step_p_enter (c: detour via x), chord_step_p_skip (¬c: THE CHORD,
y straight to the skip-port), chord_step_x (unconditional y → detour
port), chord_step_yl/yr_feed/none, chord_hlt_p/x (silent),
chord_hlt_yl/yr (¬b), chord_step_init_enter/none.

Note: the old threeLoop fragment lemmas (iterations 61–62) remain valid
and useful as a walked-stratum instance; the sixth-theorem chain now
proceeds on chordLoop. Next: liveness + trim transparency for the
chordLoop sum, then Yl~Yr~init~port language identifications, then
separations (port ≠ P ≠ X) under sat(¬b), sat(b∧c), and cross-side
pairings.

## Iteration 64 — chordLoop fragment, left side (16 lemmas, zero errors)

GkatThreeLoopProofs.lean:
- `chord_live_yr/yl/x/p/all` — liveness (x needs only sat(¬b): fire `y`
  at the exit atom itself, then halt).
- `chord_targets_live(+_none)` — composite arm targets live.
- Seven `chord_trim_step_*` — trimmed sum steps verbatim (p_enter,
  p_skip, x, yl_feed, yl_none, yr_feed, yr_none).
- **`chord_yl_yr_lang`** — detour port ~ skip port (the two post-`y`
  states), by `lang_eq_of_step_hlt`.
- **`chord_none_lang`** — init ~ skip port.

So the port class {init, Yl, Yr} is language-identified on the left
summand. Quotient picture locked: three classes port/P/X. Next: right
mirrors, then the SEPARATIONS (port ≠ P ≠ X: port halts at ¬b, P and X
silent → port separated by sat(¬b); P vs X: at a c-atom P fires x while
X fires y — separation via action mismatch x ≠ y OR depth via sat(b∧c);
choose hypotheses carefully), then cross-side pairings from ULE, then
the classifier + bundle.

## Iteration 65 — right mirrors + THE SEPARATIONS (both summands)

22 more lemmas across two commits:

Right mirrors (12, zero-error): chord_live_all_r, chord_targets_live_r
(+none_r), seven trim steps _r, chord_yl_yr_lang_r, chord_none_lang_r.

Separations (10): chord_noeps_p/x(+_r) — interior silence;
chord_lang_ne_p_yr, chord_lang_ne_x_yr (+_r) — port separated from both
interiors by the empty word at a ¬b-atom;
**chord_lang_ne_p_x (+_r)** — the branch/mid separation via the
one-step probe ⟨α_c, [(y, α_¬b)]⟩: X fires y into the detour port and
halts; P's step at a c-atom is pinned to (x, X) by determinism, so
accepting the probe forces the mid state to halt — it is silent. Works
UNIFORMLY in x, y (no x ≠ y hypothesis: the some-injection yields the
action equality for free). New nondegeneracy hypothesis: sat(c)
(hentC) — necessary, since with c empty both ite arms collapse and
P ~ X.

Gotcha again: `obtain ⟨..⟩ := hexitB` CONSUMES hexitB → use `id hexitB`
when the bundle is reused downstream.

Nondegeneracy set for the sixth theorem now locked: sat(b), sat(¬b),
sat(b∧c)?... — precise set: hentC = sat(c), hexitC = sat(¬c),
hexitB = sat(¬b). (sat(b) not yet needed; the feed arms only matter
inside lang facts guarded by b-atoms.)

Next: cross-side pairings (lang Pl = lang Pr, lang Xl = lang Xr,
lang portL = lang portR from the ULE start hypothesis — one-step
determinism transfer, no induction: P-classes are the b∧c / b∧¬c
derivatives of the start class, X-classes the c-derivative of P), then
bisimRep computations, classifier, bundle.

## Iteration 66 — CROSS-SIDE PAIRINGS + derivative transfer

Five lemmas in GkatThreeLoopProofs.lean:

- `chord_lang_deriv` ([propext, Quot.sound]): **derivative transfer** —
  equal languages + both states stepping at an atom + nonempty first
  successor language ⟹ fired actions EQUAL and successor languages
  equal. Deterministic-automaton language calculus, generic in the
  automaton; the concrete engine for all pairings. (Gotcha: subst on the
  extracted action equality eliminates the wrong variable — rewrite h₂
  with it instead.)

- `chord_pair_port` — transitivity through init~port both sides.
- `chord_pair_p` — port pairing transfers along the feedback arms at a
  shared b∧b′-atom (hentB : ∃ α, b α ∧ b′ α), yielding **p = p′** plus
  the branch pairing. Witness for nonemptiness: the skip probe.
- `chord_pair_x` — branch pairing transfers along the enter arms at a
  shared c∧c′-atom (hentC), yielding **x = x′** plus the mid pairing.
- `chord_pair_y` — mid pairing transfers along the unconditional arms,
  yielding **y = y′** plus the detour-port pairing.

The action equalities come FROM the semantic hypothesis — the sixth
theorem needs no syntactic side conditions on actions. Nondegeneracy
set: sat(¬b), sat(¬c), sat(b∧b′), sat(c∧c′) (+ mirrored ¬b′, ¬c′).

All six live classes are now paired and separated. Next: bisimRep
computations (rep values at the 12 sum states from the pair/sep facts),
the classifier cy, cleanList phantom-drop on the quotient arm lists,
bundle discharge, `chordLoops_solvable`, `chordloops_complete`.

## Iteration 67 — THE CLASS CENSUS + representative distinctness

Read the quotient machinery precisely: `bisimQuotAut` keeps carrier S,
states = map rep, trans retargeted by rep; `bisimRep` is a
Classical.choose over bisimilarity — but the carrier is the concrete
10-value sum type, so the rep is always one of the 10 values and the
census classifies it.

New in GkatThreeLoopProofs.lean:
- `chordSum` / `chordRepR` / `chordRepP` / `chordRepX` — the
  completeness-pair sum and its three class representatives.
- **`chord_census`**: ∀ s (all 10 carrier values), rep s ∈ {R̂, P̂, X̂} —
  a 10-way case split stitched from none_lang, yl_yr_lang, and the
  cross-side pairings. This makes hbase VACUOUS-ready: every quotient
  state is a cluster member.
- **`chord_reps_distinct`**: R̂ ≠ P̂ ≠ X̂ via rep_lang + the separations
  (defeq-ascription trick to convert chordRep* equalities into bisimRep
  form for rewriting; aut₂ must be passed explicitly — inference can't
  synthesize it from the refine hole).

The classifier is now definable: cy s = if s = R̂ then (cluster, 0)
else if s = P̂ then (cluster, 1) else if s = X̂ then (cluster, 2) else
none — coherence from distinctness, totality-on-states from the census.

Next: the quotient ARM computations — trimList of each port state's
arm list, retarget by rep, cleanList phantom-drop → the port's cleaned
quotient arms are exactly [(guard, p, P̂)]; same for P̂ (two arms) and
X̂ (one arm); then the gathered-guard bundle facts, chordLoops_solvable,
chordloops_complete.

## Iteration 68 — representative membership, all three classes

`chord_repP_cases` (P̂ ∈ {inl P, inr P}), `chord_repX_cases`
(X̂ ∈ {inl X, inr X}), `chord_repR_cases` (R̂ ∈ the six port values) —
each by a 10-way carrier case split: the rep has the class language
(`rep_lang`), and the separations + pairings kill every value outside
the class. repR was first-try; repP/repX needed two mechanical fixes
(hlang ascribed in wrapper form so `rw [hval]` finds the pattern;
`aut₂` passed explicitly to the `refine`d separation lemmas — plus a
replace-script indentation bite).

With census + distinctness + membership, the classifier data is
complete. The LAST block before assembly: quotient arm computations —
for each of the 10 concrete states, compute
`cleanList (map retarget (trimList arms))`:
- trimList via `trimList_all_live` (targets all live, D stays .zero;
  guards decorated g∧¬0);
- retarget by rep: real targets → P̂/X̂/R̂ (rfl or pairing-congr),
  phantom targets also map into cluster reps — which is why cleanList
  matters: phantom guards contain ∧0 conjuncts → GuardEmpty → DROPPED;
- kept arms need ¬GuardEmpty witnesses (sat(b)/sat(c)/sat(¬c) at genW).
Expected: port states → [(bᵢ-guard, p, P̂)]; branch states →
[(c-guard, x, X̂), (¬c-guard, y, R̂)]; mid states → [(⊤-guard, y, R̂)].
Then the gathered-guard facts are tiny-list computations, the bundle
discharges, and chordLoops_solvable + chordloops_complete close.

## Iteration 69 — FIRST QUOTIENT ARM COMPUTATION (the pipeline validates)

`chord_qarms_x`: the mid state's cleaned quotient arm list is literally
`[((1∧1)∧¬0, y, R̂)]`. The full pipeline, now proven workable:

1. `show` unfolds cleanAut/bisimQuotAut/trimAut projections (all rfl).
2. `trimList_all_live` (targets-live hypothesis ASCRIBED to chordSum
   form — the lemma otherwise instantiates at sumGAut form and the rw
   misses) turns trimming into guard decoration `g∧¬0`.
3. A second `show` states the decorated+retargeted literal; phantom
   targets that are rfl-reps (P, X, Yr) written directly as chordRep
   wrappers; only rep(Yl) needs a rewrite (`hrepYl` via yl_yr_lang).
4. `cleanList_consC` (local re-declaration; the original is private) ×5
   with `if_neg h1` (real arm: refute GuardEmpty by evaluating at
   `Unit, fun _ _ => false` — nomatch) and `if_pos h2..h5` (phantoms:
   the ∧0 conjunct is LEFTMOST so `bval` reduces to false and the
   GuardEmpty proofs are literally `fun X W v => rfl`).
5. Final `rfl`.

Key discoveries: (a) phantom emptiness is rfl — no case analysis on
b/c needed; (b) the GuardEmpty conditions must be stated as explicit
`have`s with the exact accumulated-D terms (an inline lambda can't
infer the condition; T must be annotated when the guard has no free
tests); (c) hrepYl rewrites BOTH Yl-targets at once.

Remaining: the same computation for the other 9 states (branch states:
2 kept arms with sat(c)/sat(¬c) refutation witnesses; port states:
1 kept arm with sat(b); right side with primes), then the bundle facts
(gOthers/gGuard on 1–2 element literals), the classifier, and assembly.

## Iteration 70 — ALL TEN QUOTIENT ARM LISTS COMPUTED

The nine remaining arm computations were PROGRAM-GENERATED from the
validated chord_qarms_x pattern (a Python emitter producing guard terms,
accumulated-D conditions, unfolded bval expressions, and witness
refutations) and built with ZERO errors on the second run. One
generator fix was needed: dropped-arm GuardEmpty proofs must `show` the
UNFOLDED Bool expression over the generic valuation W (not `show _ =
false`) so that `cases bval W c u` finds its occurrences.

The complete cleaned quotient picture (all [propext, Classical.choice,
Quot.sound]):
- `chord_qarms_x/x_r`: mid → [(⊤-dec, y/y', R̂)]
- `chord_qarms_p/p_r`: branch → [(c-dec, x, X̂), (¬c-dec, y, R̂)] (and
  primed) — THE TWO-ARM DISPATCH, phantom-free
- `chord_qarms_yl/yr/yl_r/yr_r`: ports → [(b-dec, p, P̂)] (and primed)
- `chord_qarms_none/none_r`: inits → [((b∧1)-dec, p, P̂)] (and primed)

Every possible rep identity now has a computed literal arm list. The
bundle facts are next: gOthers/gGuard on these 1–2 element literals
(pure computation), GuardImplies covers (c-dec vs ¬c-dec: semantic,
two-case), GuardEmpty halts (silent states), then the classifier +
chord_assembly_roles application → chordLoops_solvable →
chordloops_complete.

## Iteration 71 — CHORD QUOTIENT SOLVABILITY (the bundle discharges)

Two blocks, both first-try after generation fixes:

1. **Packaged bundle facts** (rep-independent, existentially quantified
   so the rep identity never leaks): `chord_portarms` (∃ g a, trans R̂ =
   [(g,a,P̂)] — 6-way rcases over repR_cases feeding the qarms lemmas),
   `chord_brancharms` (∃ g₁ g₂ a₁ a₂, trans P̂ = the dispatch ∧
   GuardImplies (¬g₁) g₂ — the cover proved per-side by cases on
   c/c′-value), `chord_midarms` (+ ⊤-ness of the mid guard),
   `chord_hlts_empty` (interior halts empty for every rep identity).
   Local re-declarations gOthers_consK/gGuard_consK (originals private).

2. **`chordLoops_solvable`**: classifier `chordCy` (three equality
   tests against the reps), the 13-conjunct hcy bundle assembled from
   shared haves (coherence via distinctness; gOthers computations on
   the 1–2 element literals; GuardImplies covers via the packaged
   implications; rank facts rfl at constant rank), hbase VACUOUS via
   the census (map-membership + census → cy ≠ none), then
   `chord_assembly_roles` → `decomp_solves` → `solvesBA_unclean`.

**The orbit half of the open problem is DONE for the chord witness**:
`∃ qsol, SolvesBA (bisimQuotAut (trimAut (chordSum ...))) qsol` with
only sat-nondegeneracy + start-language-equality hypotheses.

Remaining for the SIXTH THEOREM `chordloops_complete`: the final bridge
— relate chordSum to SUMof A T (chordLoop b c p x y) (chordLoop ...)
(the certifiedThompson sum equivBA_of_quot_solvesBA expects) and derive
heq from the ULE hypothesis; mirror the twoloops_complete endgame.

## Iteration 72 — ★ THE SIXTH THEOREM: chordloops_complete ★

**`chordloops_complete`** (GkatThreeLoopProofs.lean, axioms
[propext, Classical.choice, Quot.sound]):

  Uniformly equivalent chord programs `wh b (p; ite c (x; y) y)` are
  provably equivalent with the FINITE axioms — under the nondegeneracy
  sats (shared sat(b∧b′), shared sat(c∧c′), sat(¬c), sat(¬b), both
  sides) — no n-ary uniqueness axiom, `w3` (one unknown) throughout.

The chord program is the minimal shape BEYOND the walked discipline:
its branch state maps per-atom onto TWO forward cycle positions. This
was the located obstacle — the reason UA was believed necessary. It
falls.

Endgame details: `hstart` (trimmed-sum start-language equality) is
extracted verbatim from `ule_iff_start_bisim`'s forward direction
(autLang_trimAut ×2 → show at certifiedThompson form (defeq) →
autLang_sum_inl/inr + certifiedThompson_start_language ×2 → funext +
propext of the ULE hypothesis). Then chordLoops_solvable +
`equivBA_of_quot_solvesBA` (chordSum ≡ SUMof definitionally). One
import fix: GkatDecideProofs (autLang_sum_inl/inr) was not in the
chain — added import + open GkatDecide.

SIX UNCONDITIONAL COMPLETENESS THEOREMS, no UA:
loopfree → atomicloops → gloops → chainloops_complete_free →
twoloops_complete → **chordloops_complete**.

Remaining campaign: generalize to FiniteAxiomsCompleteBA (arbitrary
programs — hierarchical clusters, general census machinery); then
STEELMAN HARDENING (statement kernel, model equivalence, cleanAutD,
whole-chain de-choice, uleDec differential testing, claim wording).

## Iteration 73 — THE GENERALIZATION DESIGN (FiniteAxiomsCompleteBA campaign opens)

Deep analysis + recon of the Kleene-direction machinery (WNAutE:
Exp-labeled generalized automaton, self-loop + strictly-descending
exits, `wnSolE_solves` via `salomaa_solution_exists` — the terminal
form of state elimination, ALREADY certified).

**The design**: general Gaussian elimination needs NO structural
assumption on same-rank SCCs (no feedback vertex, no well-nestedness):

- Forward elimination over any linear order of a rank class: at step i,
  substitute earlier parametric forms, MERGE the state's self-arms
  (multi_gather/arms_merge — bodies are action-headed ⟹ productive ⟹
  w3 applies), Salomaa-close ⟹ parametric form in LATER unknowns only.
  The last state closes fully; back-substitute.
- The naive Brzozowski–McCluskey obstruction (composite arms through an
  eliminated state sharing one entry guard but multiple targets — the
  determinism violation that motivated well-nestedness) is DODGED
  because we eliminate by SUBSTITUTION INTO EQUATIONS, not by arm
  rewiring: multi-target continuations stay inside the substituted
  expression.
- Formalization vehicle: expression-labeled automata (ELabAut,
  generalizing GAut arms to (BExp × Exp × S)) + a roles interface +
  ONE-STEP ELIMINATION lemma (role-coverage of the u-substituted
  automaton lifts to the original) + induction on rank-class size,
  terminating at WNAutE/wnSolE.
- This subsumes the walked AND chord assemblies as special cases and
  would give: EVERY canonical quotient is role-covered ⟹
  FiniteAxiomsCompleteBA (with the census/liveness side conditions the
  fragments discharge per-program — the remaining general work there:
  general cover machinery).

Foundation laid this iteration: GkatElimProofs.lean with ELabAut,
foldTLE/eqRHSEL, ERole (fold/salomaaE/equivFold analogues), the
GAut → ELabAut embedding, and roles transfer.

## Iteration 74 — THE SUBSTITUTION HOMOMORPHISM (zero axioms)

Recon first: w3's side condition is DERIVATION-LEVEL
(`Equiv (test (E e)) (test zero)`), and w3_ba likewise — so
substitution transports it through the derivation itself. The
GkatCyclicOrderedBridge "proof-graph substitution" is the separate
cyclic-proof-system program, not reusable here.

New in GkatElimProofs.lean, all **ZERO AXIOMS**, first try:
- `substA (σ : A → Exp A' T)` — action substitution, guards untouched.
- `bval_E_substA` — with semantically-productive images, the
  empty-word guard is semantically unchanged (structural induction;
  E(wh)/E(test) are alphabet-free).
- `equiv_substA` — base `Equiv` maps into `EquivBA` under productive
  substitution: 19-case induction; every axiom is its own image since
  `substA` commutes with all constructors except `act`; the w3 case
  re-derives its side condition as
  `baTest (bval_E_substA) ⨾ trans (IH of the side derivation)` —
  the side condition's own IH is exactly what's needed because
  `substA` is the identity on tests.
- **`equivBA_substA`** — EquivBA closed under productive action
  substitution. THE elimination engine: closed forms substitute
  through equations while preserving provability.

This is also independently a STEELMAN asset (instantiating proven
equivalences under action refinement).

Next: the call-marker vehicle — equations as expressions over A ⊕ S
(calls as actions), the one-step elimination lemma (solve state u,
substitute via equivBA_substA), and the schedule induction down to
WNAutE.

## Iteration 75 — the call-marker transport layer (zero axioms again)

THE ARCHITECTURE LOCKED during analysis: the naive plan (substitute
closed forms for calls via the homomorphism) is blocked because closed
forms are NOT productive (port tails halt), and equivBA_substA demands
productive images. The fix that dissolves it:

- All elimination derivations live over the call alphabet A ⊕ S (calls
  = trailing actions; right-linearity keeps every w3 body call-free,
  so those derivations exist at the call level).
- The FINAL per-state facts have CALL-FREE endpoints (full
  back-substitution), i.e. both sides are `embedC` images.
- ONE transport brings them home: `collapseC` (real actions restored,
  stray calls ↦ `test zero` — strictly productive since E(test 0) = 0,
  and A may even be empty). Substitution composition + identity give
  `collapse_embed`, and `equivBA_of_embed` follows from the
  homomorphism with the trivially-productive collapse.
- Inside the elimination, substitution steps are SYNTACTIC
  (substA_comp — no provability transport needed): resolving the
  u-substituted equation equals resolving the original once
  sol u := resolve(closed form of u), by pure composition of
  substitutions.

New (all ZERO axioms, first try): `embedC`, `substA_comp`, `substA_id`,
`collapseC`, `collapse_embed`, `equivBA_of_embed`.

Lit note: Grabmayer's crystallization for Milner's system and the
formalized unique-solution theorems (1712.09402) are the nearest
neighbours — both work modulo bisimilarity with unique-solution
RULES; our elimination avoids uniqueness entirely (existence-side
only, w3 per step).

Next: the elimination step itself — CallSys := S → Exp (A ⊕ S) T
right-linear; gather-calls lemma (merge u-calls into Salomaa form at
call level); elimStep + the descending-recursion solution; the
schedule induction; then the roles bridge to GAut quotients.

## Iteration 76 — RTree: the elimination calculus core (all zero axioms)

Deep design first (recorded): general trees admit exactly TWO gather
situations — (i) hoisted self-calls (top-level br guards; pre-of-call
chains collapse by s1) → arm-level Salomaa; (ii) single-target
subtrees (every leaf calls u) → u5-factoring. The schedule's job is to
arrange every elimination into (i)/(ii). Working conjecture for the
census side (SINGLE-EXIT): every SCC of a canonical quotient of a
Thompson automaton carries its halting/descending arms at a single
class (the port) — true in all six strata; syntactic SCCs exit only
via their loop header; to be proven or hypothesized at the general
theorem. Interior sub-SCCs (nested loops) handle hierarchically:
innermost close to single-target calls, cascading outward.

New in GkatElimProofs.lean (ALL ZERO AXIOMS, first try):
- `RTree` (halt / call / br / pre) + `resolveT` — the right-linear
  equation carrier.
- `AllCalls` + `factorE` + **`factor_spec`** — the generalized
  hPfactor: a single-target tree resolves to its factored prefix
  followed by the target (u5 + s1 induction).
- `substT` + **`resolve_substT`** — substituting a state's closed tree
  for its calls is SYNTACTICALLY sound (pure Eq, given the assignment
  solves the state as that tree). No derivation transport mid-pipeline.
- **`elim_close`** — the closing step: equation `br G tl rest` with
  single-target tl is solved by `(wh G (factorE tl)); resolveT rest` —
  one salomaa_solution_exists + factoring + congruence.

The elimination calculus now has: transport (equivBA_of_embed),
factoring, syntactic substitution, and closing. Next: the schedule —
a per-SCC elimination order + the induction assembling ERole/StateRole
coverage for automata satisfying SINGLE-EXIT hierarchy; then the
census bridge to canonical quotients.

## Iteration 77 — schedule machinery (all zero axioms)

New in GkatElimProofs.lean, all zero axioms first try:
- `CallOnly` (call support) + `resolveT_congr` (resolution reads only
  the support) + `callOnly_mono` + `callOnly_substT` (substitution
  support arithmetic).
- **`backSol`** — the back-substitution solution: structural recursion
  over the schedule list; head state's value = its closed tree
  resolved against the tail's solution. `backSol_head/ne/ext`.
- **`stepSubst`** — the left-to-right cascade substitution of the
  closed prefix (maintains the forward-parametric invariant: each
  closed tree calls only later states + externals).
- **`resolve_stepSubst`** — the cascade is resolution-invisible when
  the assignment solves every closed state as its tree (foldl
  induction over resolve_substT).

Remaining for the general assembly: THE SCHEDULE SOUNDNESS THEOREM —
certificate structure per step (split br G tl rest with AllCalls-self
tl + support condition, or fold step), and the induction: backSol
solves every scheduled state's ORIGINAL equation (via
resolve_stepSubst + elim_close + resolveT_congr with the support
invariant), plus externals untouched. Then: bridge to ERole/StateRole,
and the census side (SINGLE-EXIT hierarchy for canonical quotients).

## Iteration 77b — ★ SCHEDULE SOUNDNESS ★ (the general elimination theorem)

**`sched_solves`** (GkatElimProofs.lean, [propext] only, first try on
the clean write): for ANY equation system `sys : S → RTree S A T`, any
external support P/ext, and any schedule (list of (state, closed tree)
pairs) certified by:

- `Supp P steps` — forward-parametric support: each closed tree calls
  only strictly-later scheduled states or externals; states distinct,
  off the external support;
- `SchedOk sys [] steps` — per-step closing: each closed tree is the
  Salomaa closing `pre (wh G (factorE tl)) tr` of a top split
  `br G tl tr` (with `AllCalls u tl`) of the CASCADE-SUBSTITUTED
  equation — or, for fold states, the substituted equation itself —

the back-substitution solution `backSol ext steps` PROVABLY (EquivBA)
solves every scheduled state's ORIGINAL equation. One w3 per closing
step; no uniqueness principle anywhere.

Proof architecture: `supp_member` (member support weakening) →
`backSol_solves_closed` (solved-as-closed, via resolveT_congr +
backSol_ne agreement) → the positioned induction `sched_solves_from`
(split-point over the full list; per step: solved-as-closed +
resolve_stepSubst collapse the cascade, then elim_close or plain
rewriting; List.append_assoc shifts the split).

**What this means**: the assembly side of FiniteAxiomsCompleteBA is now
REDUCED to schedule EXISTENCE — exhibiting, for each canonical
quotient, an elimination order whose cascade-substituted equations
split at the top (the two gather situations). The walked and chord
assemblies become schedule instances. Remaining: (1) the GAut ↔ RTree
system bridge (arms → trees, ERole/StateRole from sched_solves);
(2) schedule existence for canonical quotients (SINGLE-EXIT hierarchy,
the census side — the actual remaining mathematical content of the
open problem); (3) the fragments as sanity instances.

## Iteration 78 — ★ THE GENERALIZED SCHEDULE ASSEMBLY ★

**`sched_assembly_roles`** ([propext, Quot.sound]): a flat automaton
with rank-bounded arms (`rank e.2.2 ≤ rank s`) and ONE certified
schedule per rank class (Supp below-rank + SchedOk + rank-exactness +
coverage) is FULLY ROLE-COVERED.

Machinery: `treeOf` (flat equations as trees, `resolve_treeOf` — zero
axioms), `callOnly_treeOf` (arm descent bounds call support; the
projection must be generalized into an aux for the list induction),
`rankSol` (rank-stratified back-substitution: each level closes its
schedule over the levels below), `rankSol_stable` (levels above a
state's rank never move its value — backSol_ext + rank-exactness),
and the final congruence dance (solved value = stratified value by
rfl; resolveT_congr transports the equation across stability;
resolve_treeOf lands on eqRHS; StateRole.equivFold).

**STATUS OF THE OPEN PROBLEM**: with `equivBA_of_quot_solvesBA` +
`decomp_solves`/`solvesBA_unclean`, FiniteAxiomsCompleteBA is now
reduced to: for every canonical quotient of a trimmed Thompson sum of
a ULE pair, EXHIBIT rank + per-rank schedules satisfying the five
certificate conditions. All six strata become schedule instances. The
remaining mathematics is SCHEDULE EXISTENCE — the census structure
theorem (SINGLE-EXIT hierarchy: order each SCC port-last, interiors by
the two gather situations). One theorem stands between the corpus and
the full conjecture.

Next: (a) sanity-instance one stratum (e.g. rebuild singleton-SCC or
the chord as a schedule) to validate the certificate ergonomics;
(b) begin the census structure theorem.

## Iteration 79 — EquivBA-mediated SchedOk + instance support

Certificate ergonomics fix discovered by attempting the singleton-SCC
instance: real quotient trees have SCATTERED self-arms (br-chains),
never literal top splits. `SchedOk` upgraded: the split/fold clauses
now take ∀-sol EquivBA-mediated rearrangement hypotheses
(`∀ sol, EquivBA (resolveT sol (stepSubst pre (sys u))) (resolveT sol
(.br G tl tr))`) instead of syntactic equality — instantiated at
backSol in the soundness proof (two-line patch, same axiom profiles:
sched_solves [propext], sched_assembly_roles [propext, Quot.sound]).
The rearrangement engine for instances is the EXISTING multi_gather:
G := gGuard, tl := .call (gBody) u (AllCalls trivially!), tr :=
armChain (gOthers) — resolve_armChain connects tree and flat worlds.

Instance-support lemmas (zero axioms): substT_noop / stepSubst_noop
(cascades are no-ops on call-free trees — singleton-SCC states never
call same-rank peers), armChain + resolve_armChain + treeOf_armChain +
callOnly_armChain.

Next: assemble the singleton-SCC schedule instance end-to-end (list
plumbing: per-rank state lists, nodup hypothesis, coverage), then the
census structure theorem.

## Iteration 80 — VALIDATION: singleton-SCC re-derived via schedules

**`singleton_scc_sched`** ([propext, Classical.choice, Quot.sound] —
choice only from the classical gGuard/gBody gathering in ssTree): the
S2 stratum (every cycle a self-loop) re-derived END-TO-END through
`sched_assembly_roles`. The certificate ergonomics VALIDATE:

- Closed trees: `ssTree s = pre (wh gGuard gBody) (armChain gOthers)`.
- Rearrangement: `multi_gather` + `resolve_treeOf`/`resolve_armChain`
  discharge the ∀-sol split hypothesis in four lines.
- Cascade no-op: `stepSubst_noop` via the call-support analysis
  (self-or-descending targets never hit same-rank peers).
- Supp/SchedOk: clean list inductions over a per-rank enumeration
  (`Pairwise (· ≠ ·)` destructured by constructor — no Nodup API
  needed).

Instance inputs: enum : Nat → List S with rank-exactness, pairwise-ne,
coverage — the shape the census structure theorem must produce.

Two tactic notes: `rw [h1]` on a ≤-goal needs an explicit
`Nat.le_refl` (rfl-closing fails for ≤); rank contradictions want the
rewrites chained INTO the hypothesis then omega.

The pipeline GAut → schedules → roles is now proven navigable. Next:
the census structure theorem — produce enumerations + schedules for
canonical quotients (SINGLE-EXIT hierarchy; walked and chord cluster
schedules as the next validation rungs).

## Iteration 81 — the pruning toolkit (zero axioms)

Strategic analysis first (recorded): the chord/walked schedule
instances hit dead interior halts inside cascaded trees — AllCalls
fails syntactically — and the rearrangement clause must PRUNE them.
Also identified the census theorem's real cost: general SCC/topological
machinery (Mathlib-free graph theory); the practical route is witness
constructors for the strata now, graph generality later.

New (zero axioms): `halt_prune` (a dead-halt branch is its guard as a
test prefix — the branch guard rides into the factored lap body,
producing the wh_exit-style normal forms), `ite_true_collapse`
(semantically-true guards select their branch; derivation via
ite_restrict_else → kill ¬g by baTest+s2 → ite_zero_else →
baTest(g≡1)+s4), and their tree-level wrappers
resolve_halt_prune/resolve_true_collapse.

Namespace note: GuardEmpty lives in GkatRingPlan (open added).

Next: the walked 2-cycle schedule instance (one Salomaa interior + a
port cascading through it, exercising factoring + pruning together),
then the chord instance, then the census witness constructors.

## Iteration 82 — THE WALKED 2-CYCLE VIA SCHEDULES (cascade validated)

**`walked_two_cycle_sched`** ([propext, Quot.sound] — leaner than the
classical walked assembly, since literal arm lists avoid the classical
gathering): an abstract 2-state automaton (interior with hoisted
self-loop + exit, port feeding back, interior halt empty) is fully
role-covered via `sched_assembly_roles` with rank ≡ 0 and the two-step
schedule:

- interior: syntactic top split (rearrangement is refl after the
  treeOf rewrite), closes to `pre (wh c qa) (exit-branch)`;
- port: the cascade substitutes the interior's closed tree into the
  feedback arm; the rearrangement prunes the dead interior halt
  (`halt_prune` — the ¬c exit-test rides into the lap) and the split
  factors the lap `pa;((wh c qa);((test nc); ra))` — exactly the
  twoLoop closed form, now produced by GENERAL machinery.

Fix notes: CallOnly goals should be closed by direct anonymous
constructors (defeq) — `show`-ing the unfolded Prop shape is fragile;
`[] ++ l` needs a defeq `show` before rewriting stepSubst equations.

Validated: multi-state cascades, pruning-in-rearrangement, factoring.
Next: the chord 3-state instance (branch state = fold step mid-cascade
— the remaining certificate pattern), then the census witness
constructors for canonical quotients.

## Iteration 82b — THE CHORD 3-CYCLE VIA SCHEDULES (all patterns validated)

**`chord_three_sched`** ([propext, Quot.sound] — leaner than the
bespoke chord assembly, no classical gathering): the abstract chord
shape (mid → port; branch → mid/port; port feeds back; interior halts
empty) fully role-covered via the generalized machinery. The schedule:

- mid: FOLD step (closed tree = its own equation, refl rearrangement);
- branch: FOLD OVER THE CASCADE — the mid's closed tree substitutes
  into the enter arm, the substituted equation IS the closed tree;
- port: cascade through both, DOUBLE `halt_prune` (both interior
  halts), factoring the branching lap
  `pa;(ite cg (xa;(gx?;ya)) (ncg?;ya'))` — the chordPre form produced
  by general machinery. AllCalls on a branching lap is a conjunction
  (⟨rfl, rfl⟩, not rfl).

CERTIFICATE PATTERNS NOW ALL VALIDATED: syntactic split, fold, fold
over cascade, split over cascade with pruning, single- and
multi-branch factoring. The generalized assembly SUBSUMES the walked
and chord bespoke assemblies with BETTER axiom profiles.

Next: the census witness constructors — produce these abstract shapes
(arm lists + emptiness + distinctness) from canonical quotients, per
stratum first (re-deriving theorems 4–6 through schedules), then the
general SINGLE-EXIT construction.

## Iteration 83 — THE SIXTH THEOREM VIA THE GENERAL PIPELINE (first try)

**`chordloops_complete_sched`** ([propext, Classical.choice,
Quot.sound]): `chordloops_complete` re-derived END-TO-END through the
generalized elimination — census facts (portarms/brancharms/midarms/
hlts_empty/reps_distinct/census) instantiate `chord_three_sched` at
the cleaned chord quotient; then decomp_solves → solvesBA_unclean →
equivBA_of_quot_solvesBA. FIRST TRY.

The bespoke `chord_assembly_roles` is now OFF the mainline: the
general schedule machinery + the fragment census facts suffice. This
is the full pipeline pattern for the census constructors:

  fragment census facts (arm lists at reps + emptiness + distinctness
  + census) → abstract shape instance → sched_assembly_roles →
  summit reduction.

The remaining work for FiniteAxiomsCompleteBA is now PURELY the census
side: for an arbitrary ULE pair, produce (a) the quotient class
structure (reps, distinctness, census — the general analogue of the
chord's 10-case lemmas), (b) the cleaned arm lists at reps, (c) the
schedule shape. (a)+(b) for arbitrary programs = the general census
structure theorem (SINGLE-EXIT hierarchy + SCC machinery). The
schedule-shape side (c) is DONE in general (SchedOk certificates).

## Iteration 84 — THE FOREST CONSTRUCTOR (first general census constructor)

**`forest_class_sched`** ([propext, Classical.choice, Quot.sound]): a
rank class whose same-rank calls are SELF or STRICTLY LATER in the
enumeration (self-loops over a DAG) schedules with cascade-free
multi_gather closings — every state's cascade is a no-op (its calls
are self/later/lower, never earlier), so each closes on its own arm
list. Subsumes singleton_scc_sched and handles acyclic SCC interiors.
The "later" hypothesis is split-form:
`enum r = L₁ ++ s :: L₂ → arms of s target self ∨ lower ∨ L₂`.

Supporting: `pairwise_append_parts` (Pairwise splits across an append
— cross-relations + right part; gotcha: `nomatch ha, h` parses the
comma INTO nomatch's discriminants — parenthesize). Also
`sched_assembly_roles`'s hdesc weakened to member states (the roles
proof only ever uses it under membership) — un-enumerated junk states
are now unconstrained, which the constructors need.

Next constructors: the PORT constructor (one designated cycle-closer
per SCC: interiors forest-schedule, port closes through the cascade
with pruning+factoring — the walked/chord instances generalized to
arbitrary interior DAGs), then the Thompson census (produce the
enumerations from program structure).

## Iteration 85 — THE PRUNING MACHINE (zero axioms)

The general port constructor needs to clean dead interior halts at
ARBITRARY depth in cascaded trees (the hand-pruning of the walked and
chord instances generalized). New, all zero axioms first try:

- `DeadHalts` — every halt leaf semantically empty.
- `pruneT : RTree → Option RTree` — dead subtrees collapse; a pruned
  sibling's guard rides in as a test prefix (`pre (test g)` /
  `pre (test ¬g)`); `none` = entirely dead.
- `dead_resolve` — fully dead trees resolve to `test 0` (u1 for
  both-dead branches, s3 under prefixes).
- **`prune_resolve`** — pruning preserves resolution (ite_zero_else /
  ite_zero_then at the mixed branches).
- **`prune_allCalls`** — pruning a port-targeted (CallOnly (· = o))
  tree yields `AllCalls o` — ready for `factor_spec`.

Proof-shape note: the `match pruneT l, pruneT r with ...` equations
need explicit `show`-normalized rewrites per case pair (12 cases per
lemma but fully mechanical).

Remaining for the PORT CONSTRUCTOR: the chain-gather (tree-level
multi_gather over br-chains: partition top-level branches into
port-reaching — factored via factor_spec after pruning — and others),
then the constructor: interiors forest-style, port closes through
cascade + prune + chain-gather + factor. Then the Thompson census.

## Iteration 86 — THE CHAIN GATHER (zero axioms)

**`port_gather`**: tree-level multi_gather. A top-level branch chain
(`chainT`) partitions by a Bool selector into port-reaching branches —
each factored by `factor_spec` and merged by `arms_merge` into ONE
Salomaa arm `(selBody; sol o)` under the gathered guard `selGuard` —
over the remainder chain (`selOthers`), with `arm_commute` pushing
unselected branches through. Zero axioms. (Gotcha: if-unfold `have`s
need `rfl` after `rw [hsel]` in BOTH polarities.)

THE PORT-CONSTRUCTOR TOOLKIT IS NOW COMPLETE:
cascade (stepSubst) → prune (pruneT + prune_resolve/prune_allCalls) →
chain-gather (port_gather: selGuard/selBody/selOthers) →
factor (factor_spec) → close (elim_close). Each step zero-axiom.

Next: assemble THE PORT CONSTRUCTOR — the general SCC schedule
(interiors forest-style with arms self ∨ later ∨ port; port closes via
the five-step pipeline over its cascaded chain), subsuming the walked
and chord instances as 1- and 2-interior cases. Then the Thompson
census (enumerations from program structure) closes the remaining path
to FiniteAxiomsCompleteBA.

## Iteration 87 — the chain bridges (all zero axioms, first try)

Five bridges between the schedule world and the gather world:

- `substT_chainT` / `stepSubst_chainT` — substitution and cascades
  distribute over branch chains (with the map-fusion sublemmas inline).
- `treeOf_chainT` — flat equations are chains of prefixed calls.
- `pruneBranch` + `chain_prune_congr` — branchwise pruning preserves
  chain resolution (dead branches stay in place harmlessly — they
  carry no calls, so Supp is unaffected).
- `substT_deadHalts` — dead halts survive substitution.

THE PORT STEP'S FULL DERIVATION CHAIN now type-checks on paper:
stepSubst closedPre (treeOf o)
  =[treeOf_chainT + stepSubst_chainT]  chainT h (cascaded branches)
  ≡[chain_prune_congr]                 chainT h (pruned branches)
  ≡[port_gather]                       ite selGuard (selBody; sol o) rest
  →[elim_close]                        closed.

Next: THE PORT CONSTRUCTOR — the schedule assembly threading the
invariants (interiors: forest hypotheses + DeadHalts + no descents;
port: the above chain) through the Supp/SchedOk inductions. The last
constructor before the Thompson census.

## Iteration 88 — cascade invariants + the selector (port constructor, chunk 1)

New lemmas for the port constructor:
- `ssTree_deadHalts` — forest closed trees have dead halts when the
  state's halt is empty.
- `stepSubst_deadHalts` — dead halts thread through cascades (zero ax).
- **`stepSubst_callOnly`** ([propext]) — THE CASCADE SUPPORT COLLAPSE:
  cascading a Supp-certified prefix over a tree whose calls lie in
  prefix ∪ P leaves calls only in P. This is what makes the port's
  cascaded branches CallOnly-port.
- `callsB`/`haltFreeB` (Boolean selector) + `allCalls_of_bools` +
  `callOnly_of_callsB` — the port_gather selector: selected = calls
  all target the port AND halt-free (post-pruning).

Gotchas: `▸` with a pair-equality cast needs the rw-at form;
Bool-coerced equality in defs needs `show s = o` before
`of_decide_eq_true` (the unifier won't reduce the Prop through the
def).

Chunk 2 next: `scc_rank_sched` — the per-rank SCC certificate
(interiors forest-style + the port's five-step closing), then the
mixed per-rank assembly.

## Iteration 89 — prune/selector interplay (port constructor, chunk 2)

Six lemmas (near-all zero axioms): `pairwise_append_left`,
`callOnly_pruneT` (pruning preserves call support), `pruneT_haltFree`
(pruned trees are halt-free BY CONSTRUCTION — pruneT never emits halt
nodes), `pruneT_none_noCalls` (fully dead ⟹ call-free, any support),
`callsB_of_callOnly` (selector completeness), `selOthers_sub`
(unselected branches come from the list, unselected).

These close the port constructor's case analysis: every cascaded port
branch is (a) interior-target ⟹ CallOnly-port (stepSubst_callOnly) ⟹
pruned-some ⟹ selected (callsB_of_callOnly + pruneT_haltFree), or
dead ⟹ call-free; (b) self ⟹ selected; (c) descent ⟹ unselected with
lower-rank calls. So the others-chain is always lower-rank-or-dead —
Supp-safe — and selected branches are AllCalls (allCalls_of_bools).

Next (chunk 3, the assembly): `scc_rank_sched` — ∃ steps with the
four certificates; interiors via the forest logic against the
ints++[o] enumeration; the port via
treeOf_chainT → stepSubst_chainT → chain_prune_congr → port_gather
(sel := callsB && haltFreeB) with tl := .call selBody o (the
single-call-node trick). Then the mixed per-rank assembly.

## Iteration 90 — ★ THE SCC CONSTRUCTOR ★ (port constructor complete)

**`scc_rank_sched`** ([propext, Classical.choice, Quot.sound], ~350
lines, three micro-fixes): a rank class shaped as ONE single-exit SCC —
interiors whose same-rank arms are self ∨ later-interior ∨ port, with
empty halts and no descents; a port whose arms are interiors ∨ self ∨
descent — yields a certified schedule (Supp + SchedOk + rank-exactness
+ coverage), with explicit closed trees:

- interiors: `ssTree` (multi_gather Salomaa, cascade no-op);
- port: `sccPortTree` = `pre (wh selGuard selBody) (chainT hlt others)`
  where the branches are the cascaded (`sccCasc`), pruned
  (`pruneBranch`) port arms, selected by `sccSel = callsB && haltFreeB`.

The port's SchedOk clause runs the full five-step pipeline in twelve
lines: treeOf_chainT → stepSubst_chainT → List.map_map →
chain_prune_congr → port_gather, with tl := `.call selBody o` (the
single-call-node trick). The branch classification (hothersCO) is the
long pole: interior-branches selected-or-dead, self-branches always
selected, descent-branches untouched-and-lower.

Fix notes: pruneBranch-fold on rewritten scrutinees needs pair-eta
(`show (b₀.1, literal) = b₀; rw [← hnoop]`); avoid `subst` on
`L₁ = ints` (eliminates the wrong side) — rw instead; `hc.symm` for
target-vs-cross inequality direction.

WITH FOREST + SCC CONSTRUCTORS, the census toolkit covers: acyclic
classes, self-loop classes, and single-exit SCCs with DAG interiors —
every shape in all six strata, now producible generically. Remaining
for FiniteAxiomsCompleteBA: nested sub-SCCs (hierarchy — interior
cycles among interiors), and the Thompson census (enumerations +
shape facts from the minimal automaton structure of ULE pairs).

## Iteration 91 — HIERARCHY ARCHITECTURE: composition + the general port step

**`Supp_append`** / **`SchedOk_append`** ([propext]): schedules
concatenate — the left segment certified against (right-states ∨ P),
the right against P; distinctness and off-support facts for the left
segment come FREE from its own Supp (the hP field carries both).
Plus `supp_not_P` (schedule states are off the external support).

**`port_step_sched`** ([propext, Quot.sound] — leaner than
scc_rank_sched, no classical gathering): a port closes over ANY
certified prefix — hypotheses are just: the prefix Supp-supports
toward {o}, its trees are dead-halted, its states are at rank r, and
the port's arms hit prefix-states ∨ self ∨ lower. Produces the
single-step Supp + SchedOk with `genPortTree` (the sccPortTree
generalized to arbitrary prefixes). The entire scc_rank_sched branch
classification transplants verbatim with steps-membership replacing
interior-membership.

NESTED HIERARCHY IS NOW A COMPOSITION PATTERN: inner-SCC schedules
(built by the same constructors, supported toward their sub-ports)
compose under outer ports via Supp_append/SchedOk_append +
port_step_sched. No new closing mathematics needed — arbitrary
loop-nesting depth is handled by iterating the port step.

Remaining for FiniteAxiomsCompleteBA: THE THOMPSON CENSUS alone —
enumerations + shape facts from minimal-automaton structure (the
single open risk: multi-exit mutual cycles, believed unrealizable).
Then: STEELMAN HARDENING.

## Iteration 92 — THE CENSUS LAYER OPENS: the reachability rank

GkatCensusProofs.lean created. The canonical rank for arbitrary finite
automata, with NO graph algorithms — pure filter arithmetic over an
inductive Reach with classical decidability:

  `reachRank aut s := |states.filter (Reach aut s ·)|`

- **`reachRank_le`** — arms weakly shrink the rank (reach-set
  monotonicity + `filter_length_le`).
- **`reachRank_eq`** — mutually reachable states have EQUAL rank
  (subset both ways).
- **`reachRank_lt`** — an arm that leaves an SCC forever drops rank
  STRICTLY (the source witnesses itself: s ∈ reachSet s \ reachSet t;
  `filter_length_lt` — works even with duplicate state lists, no Nodup
  needed).
- **`reachRank_hdesc`** — the assembly's descent hypothesis holds
  outright for every automaton.

This kills the "Mathlib-free SCC machinery" cost estimate: no
condensation computation, no topological sort — the rank IS the SCC
structure, extracted by cardinality.

Census remaining: (1) the same-rank ⟹ same-SCC converse (rank-equal +
reachable ⟹ mutually reachable — needed to know rank classes are
SCC-unions); (2) the per-class enumeration + single-exit facts for
quotients of Thompson sums (THE risk locus); (3) plumbing into
forest/port constructors.

## Iteration 92b — SCC DETECTION

**`reach_back_of_rank_eq`**: reachability + equal reachRank forces
MUTUAL reachability (via filter_eq_of_length_eq from the DE-CHOICE
toolkit — subset filters with equal length are pointwise equal, so the
source, reachable from itself, is reachable from the target). 

Consequences for the census: rank classes are unions of SCCs;
rank-preserving arms never leave an SCC; an arm is intra-SCC iff it
preserves reachRank (reachRank_lt gives the converse). The SCC
structure is now fully characterized by ONE Nat-valued function with
four lemmas — the enumeration construction can work rank class by
rank class, splitting classes into SCCs by mutual-reachability, with
no additional graph machinery.

## Iteration 93 — THE BLOCK CONSTRUCTOR (first try, zero errors)

The composable unit for the census, all landed in one build:

- `Supp_target` — support targets strengthen under implication (with
  off-support discipline); the lemma that lets one prefix certificate
  serve two composition contexts.
- `forest_prefix_supp` / `forest_prefix_ok` — the interior-prefix
  certificates extracted standalone (generic in the exit).
- **`scc_block_schedP`** ([propext, Quot.sound-profile via parts]): a
  single-exit SCC block — interiors (self ∨ later ∨ port, empty halts)
  + port (interiors ∨ self ∨ P) — certified against an ARBITRARY
  external support P. Proof: forest prefix + port_step_schedP composed
  by Supp_append/SchedOk_append with Supp_target re-targeting.

With P abstract, blocks compose freely: multiple SCCs per rank (P :=
other-blocks ∨ lower — legitimized by same_rank_arm_mutual: same-rank
arms are intra-SCC, so cross-block arms don't exist), and NESTING
(inner blocks with P := outer-continuation). The census's assembly
side is now a Lego kit: reachRank + blocks + append + 
sched_assembly_roles.

Remaining: the top-level Lego theorem (rank classes → block lists →
full schedule family) and then the single risk locus: single-exit
facts for canonical quotients of Thompson sums.

## Iteration 94 — PREFIX IRRELEVANCE (the composition toolkit completes)

**`stepSubst_append`** (cascades split across appended prefixes —
List.foldl_append) and **`SchedOk_disjoint_prefix`** ([propext,
Quot.sound]): a block's closing certificate survives ANY prefix its
equations never call — both the split and fold clauses transport by a
single cascade-noop rewrite, and the inner accumulator shifts by
associativity.

THE COMPOSITION TOOLKIT IS COMPLETE:
- concatenate: Supp_append / SchedOk_append
- retarget: Supp_target
- reorder past uncalled prefixes: SchedOk_disjoint_prefix
- blocks: scc_block_schedP (abstract external support)
- ports over anything: port_step_schedP
- leaves: forest_prefix_supp/ok, forest_class_sched

Any hierarchical arrangement of single-exit SCC blocks across ranks
now assembles mechanically. The ONLY remaining input the census must
supply: per rank class, the block decomposition data (ints/port lists
+ arm-shape facts + halt emptiness) — pure facts about canonical
quotients, no more scheduling mathematics.

Next: the census facts for quotients of Thompson sums — starting with
the SINGLE-EXIT structure theorem (syntactic Thompson SCCs exit only
at loop headers; quotient pairing preserves it).

## Iteration 95 — halt invariance + THE CENSUS ENDGAME DESIGN

**`bisim_hlt_invariant`**: bisimilar states agree on halting behaviour
at the generic valuation (GAutBisim's first component surfaced). Exit
patterns are language-invariant: a halting class never absorbs a
silent state.

**THE DESIGN** (worked through the rotation example): for e = wh b (p;q)
and rotated f = p; wh b (q;p), the SCC-pairing danger (two exit classes
in one merged SCC) DOES NOT ARISE: ε/halt-visibility separates every
head-class from every mid-class (heads accept halt-words, mids are
silent), so the two syntactic SCCs stay disjoint in the quotient, each
its own block. GENERAL PRINCIPLE: quotient merges preserve exit
positions; merged SCCs have matched ports.

The formal route to the census facts:
1. THE SYNTACTIC STRUCTURE THEOREM: for every program e,
   certifiedThompson e admits a hierarchy of single-exit blocks —
   structural induction over the Thompson construction (act/test:
   empty; seq/ite: block unions + rank shifts; wh: new port over the
   body's blocks). "Compile e to its schedule."
2. QUOTIENT TRANSPORT: rep-classes' arms are a member's arms
   retargeted (bisimQuotAut trans-of-rep); the quotient schedule =
   dedup of the syntactic schedules of BOTH summands; merge-robustness
   from halt invariance + reachRank (merged states have equal
   languages ⟹ matched block positions).
3. Feed scc_block_schedP / composition / sched_assembly_roles.

Steps 1 and 2 are the remaining work — multi-iteration but now fully
specified; no scheduling mathematics remains, only Thompson structure
and rep-class bookkeeping.

## Iteration 96 — SINGLE-EXIT REFUTED; THE SELF-CLOSE CLAUSE ABSORBS IT

**The conjecture falls**: reading `loopInitialized` — EVERY body state
with nonzero halt gets feedback arms and a live residual halt. So
`wh b (ite c (p; test d) q)` yields an SCC whose two states (post-p,
post-q) BOTH halt (d∧¬b and ¬b) — a genuine two-exit mutual cycle in
a canonical quotient, realized by a six-symbol program. The danger
shape from the odds analysis is REAL.

**And it doesn't matter**: manual verification shows the class
solutions are the syntactic residuals (sol Q = wh b BODY,
sol P = (test d); sol Q — mid-halt states are TEST-PREFIXED calls to
the port), and the port verifies by W1-UNROLLING + guard algebra — no
w3, no factoring, no single-target requirement. The schedule framework
absorbs this via a THIRD SchedOk clause, the **self-close**:

  ∀ sol, sol u = resolveT sol C →
    EquivBA (resolveT sol C) (resolveT sol (cascaded equation))

Soundness extension: at the step, solved-as-closed supplies exactly
the hypothesis; the chain closes as before (three-line patch).
Subsumes fold (refl) and split (elim_close); transported through
SchedOk_disjoint_prefix; instances patched (Or.inr → Or.inr ∘ Or.inl).
All axiom profiles unchanged.

**Strategic consequence**: the census's closed forms for ports need
not be Salomaa-manufactured — they can be the STANDARD THOMPSON
SOLUTIONS (certifiedThompson's `standard` field), verified through the
ThompsonCertificateBA machinery, with mid-halt states as test-prefixed
calls. The syntactic structure theorem should compile e's certificate
into schedule clauses directly — reusing the mountain of Thompson
uniqueness work instead of re-deriving lap structure.

## Iteration 97 — CERTIFICATE RECON + the quotient-equation bridge

**Recon payoff — ParametricCanonicalBA is the master key**: the
Thompson certificates already prove per-program
uniqueness-WITHOUT-UA: `∀ finish sol, ParamSolvesBA aut sol finish →
∀ state, EquivBA (sol state) ((standard state); finish)` — any
parametric solution factors through the standard one. Plus
StandardSolvesBA (= ParamSolvesBA at finish := 1), InitHaltDisjointBA,
InitTargetsListed. The census verification clauses should be derived
FROM canonicity rather than re-proving unroll identities.

**Compilation design sharpened**: every Thompson state's closed tree
is a PREFIX-CALL CHAIN — mid-states: `.call (finish-the-lap expr,
inner loops inlined whole) (outermost port)`; ports:
`.pre (wh g FULLBODY) (continuation-call)`. Nested loops form ONE SCC
whose states ALL call the outermost port directly, so SCC schedules
are trivial in shape: [non-port states, any order] ++ [port]. The
whole difficulty concentrates in the self-close verification clauses,
to be discharged via the certificate lemmas.

**First transport brick**: `eqRHS_quot` ([Classical.choice] only) —
the canonical quotient's equation at ANY carrier state is the
underlying automaton's equation with the solution precomposed by
bisimRep. (Tactic note: list inductions over projected arm lists need
the generalized-aux + foldTL-folded `show` forms, or `rw [ih]` misses.)

Next: the compilation skeleton — per-program schedule data (the
prefix-call trees from the syntax tree) and the wh-case verification
clause via canonicity.

## Iteration 98 — PAIR GATHERING (dispatch extensionality, step one)

The transport problem precisely stated: quotient SCC classes' reps
alternate SIDES (bisimRep chooses arbitrarily), so class equations mix
left- and right-syntax — neither side's canonicity applies directly.
THE FIX: dispatch extensionality — bisimilar states' equations are
EquivBA-equal under class-constant solutions — letting every class
verify against its LEFT member's syntax (every class HAS a left
member: reachable class sets of the two starts coincide under ULE).

Step one landed: **`pair_gather`** (ZERO axioms): equations normalize
per (target, action) pair — `foldTL ≡ ite (gGuardPA t a L)
((act a); sol t) (foldTL (gOthersPA t a L))` — after which the
gathered body is a SINGLE ACTION and two bisimilar dispatches differ
only by pointwise-equal guards. Proof mirrors multi_gather; the
matched-pair case needs an extra u1-collapse (arms_merge with equal
bodies). Namespace note: EquivBA lives in GkatFaithful.

Next: iterate to the full pair-normal form (gatherChain over a pair
list), then extensionality proper (pointwise-equal gathered guards ⟹
EquivBA via ite_guard chains), then the left-member census.

## Iteration 99 — ★ DISPATCH EXTENSIONALITY ★ + THE UNIFICATION ROUTE

**`dispatch_ext`** (ZERO axioms): matched dispatches over DIFFERENT
state spaces are EquivBA-equal — a positional certificate `PairsOk`
(each matched (t₁,t₂,action) triple: pointwise-equal gathered guards
on the CURRENT residuals + equivalent continuations) zipped down by
`pair_gather` on both sides with `ite_guard` at each step, plus a
residual bridge. (Design lesson: the certificate must be positional —
guard agreements are about stripped residuals, not the originals.)

**THE UNIFICATION ROUTE** (the answer to "biggest step against the
census"): completeness WITHOUT quotient-solving, by strong induction
on reachRank —

  claim: all members of every class have EquivBA-equal standard
  solutions.

  At rank r: a class member m lives in some syntactic loop scope; the
  rank-r SCC subsystem = that loop's certified wrapped automaton with
  lower-rank continuations as the parametric finish (IH-unified).
  Any other member m′ (other side) induces, via DISPATCH EXTENSIONALITY
  along the bisimulation, a second solution of THE SAME parametric
  subsystem; **ParametricCanonicalBA of the enclosing loop's
  certificate** forces both ≡ standard·finish — UNIFIED. At the start
  classes, ULE gives e ≡ f. No schedules, no quotient SolvesBA, no
  gather/prune pipeline on the critical path — those remain as the
  independent general-automata theory.

Remaining for the route: (1) loop-scope ↔ SCC correspondence
(syntactic structure facts); (2) standard-solution compositionality
(standards factor through loop scopes — likely already how `standard`
is defined); (3) the bisim-partner plumbing (classes have members
both sides; matched pairs from the step function); (4) the rank
induction assembly. All four are bookkeeping-flavored; the
mathematical content is now fully covered by certificates +
dispatch_ext.

## Iteration 100 — THE PARTNER THEOREM (unification route, item 3)

All zero axioms, first-or-second try:

- `SReach` — semantic (firing-step) reachability at genW.
- **`sreach_partner`** — bisimilarity transports semantic
  reachability: every state reachable from one start has a bisimilar
  partner reachable from the other (generalized induction over the
  reach derivation, stepping the bisim pair via genBisimilar_bisim's
  forward component). Under ULE (starts bisimilar via
  ule_iff_start_bisim), every left-reachable class of the trim-sum has
  a right member and vice versa — the two-sided-members fact the
  unification route needs.
- `firstMatch_mem_of_some` (the fired arm is listed), `step_arm`,
  `sreach_reach` — firing paths refine arm paths, so the reachRank
  theory (descent, SCC-constancy, strict drops) applies along
  semantic reachability.

Unification route status: (3) partner plumbing CORE DONE. Remaining:
(1) loop-scope ↔ SCC correspondence, (2) standard compositionality —
both live inside the CertifiedThompson.seq/ite/loop construction
proofs (next recon target), then (4) the rank-induction assembly.

## Iteration 101 — compositionality confirmed + THE CIRCULARITY AND ITS RESOLUTION

**Recon**: standard-solution compositionality (route item 2) is
DEFINITIONAL — seq: left states get `(leftStandard s)·rightProgram`,
right states inherit; loop: `(bodyStandard s)·(wh g program)`; ite:
inherited. Every state's standard = local standard × context
continuation, by construction. Item (2) closes by reading.

**THE OBSTACLE FOUND**: ParametricCanonicalBA is ∀-listed-states, but
Thompson automata have unreachable states (dead branches: syntactic
`ite 0`, semantic contradictory guards). The partner family (needed
for canonicity application) only exists on the reachable cone; padding
unreachable states with `standard·F` is CIRCULAR (unreachable states
can target reachable ones, whose unification is the conclusion).

**THE RESOLUTION (hybrid family)**: unreachable regions of Thompson
automata decompose into DEAD SUB-THOMPSONS with boundary
continuations; their own certificates supply solutions at ANY
continuation via right multiplication. The hybrid family — partner
standards on the reachable cone, `(local dead standard)·(boundary
value)` elsewhere — solves EVERYWHERE, no circularity: reachable
states' targets are reachable (forward closure), dead states' values
are free.

**The generic step landed**: `paramSolves_seq` ([propext]) — a
parametric solution right-multiplied by `g` is a parametric solution
at `finish·g` (guardedFold_seq_right by u5-symm chain;
guardedFold_map_congr + s1 re-association per branch; fallback s1).
Plus guardedFold_fallback_congr / guardedFold_map_congr helpers.

Remaining for the route: the dead-region decomposition (structural),
the subsystem lemma (ambient equations of loop states = parametric
equations — the seq/loop construction shapes), and the rank-induction
assembly.

## Iteration 102 — CLASS GATHERING (the pair-level flaw found and fixed)

**Design flaw caught before it bit**: the pair-level PairsOk
certificate is UNUSABLE for real bisimulations — a counterpart state
may split one (target, action) guard across several distinct-but-
bisimilar targets, so pointwise pair-guard equality fails. The correct
granularity is (target-CLASS, action).

Landed (zero axioms both):
- `gGuardPC`/`gOthersPC` + **`class_gather`** — a (class, action)
  pair collects into ONE Salomaa arm over a COMMON continuation V,
  given class members' solutions are EquivBA V (the continuation
  congruence rides inside the gather — arms_merge with equalized
  bodies + u1).
- **`gGuardPC_firstMatch`** — the gathered guard fires at an atom IFF
  the dispatch's firstMatch does the action into the class: the exact
  bridge from bisimulation step-agreement to pointwise guard equality.
  (Tactic: resolve `if_pos/if_neg` BEFORE rewriting the bval that
  feeds the condition, or the pattern is clobbered.)

With these, the class-level dispatch extensionality is assembly:
bisimilar states + class-constant-up-to-EquivBA continuations ⟹
equations EquivBA-equal, with the PairsOk-analogue certificates now
DERIVABLE from GAutBisim (step agreement per atom). Next: the
class-level dispatch_ext assembly, then the subsystem lemma.

## Iteration 103 — CLASS DISPATCH EXTENSIONALITY (zero axioms, first try)

**`dispatch_ext_class`**: dispatches matched class-by-class — the
positional `ClassesOk` certificate carries, per (class₁, class₂,
action, continuation) entry, pointwise-equal gathered class-guards on
the current residuals and class-consistent solutions (EquivBA the
common continuation) on BOTH sides. The zip is even cleaner than the
pair version: both sides gather to the SAME arm `(act a); V`, so the
branch step is refl — only the guard needs `ite_guard`.

Note for the application (recorded): the guard/halt pointwise
hypotheses need ∀-valuation equality while bisimulation gives
genW-agreement — but genW is UNIVERSAL: `bval W b x = bval genW b
(fun t => W t x)` (bval_gen), so genW-pointwise agreement lifts to all
valuations. No gap.

The extensionality toolkit is now bisim-complete:
gGuardPC_firstMatch converts step-agreement into guard-pointwise
facts; class_gather + dispatch_ext_class convert those into equation
equivalence. Remaining census items: the ClassesOk constructor from
GAutBisim (choose entries = occurring (class, action) pairs), the
subsystem lemma, dead-region decomposition, rank induction.

## Iteration 104 — the valuation lift + THE RESIDUAL-PRESERVATION ANALYSIS

**`pointwise_of_genW`** (zero axioms): guard agreement at genW lifts
to all valuations (genW is free; bval_gen factors every valuation
through it). Bisimulation facts now feed baTest/ite_guard directly.

**Analysis — the ClassesOk constructor's subtlety found**: positional
stripping does NOT preserve dispatch-matching for raw lists — a
SHADOWED arm (never firing in the full dispatch, different class)
becomes live in the residual after its shadower is stripped,
producing pointwise-unequal residual guards even though the full
dispatches match. Counterexample: [(⊤,a,X)] vs
[(⊤,a,X′),(⊤,b,Y)] — matched full dispatches, mismatched residuals.

**Resolution: CLEANEDNESS.** In cleaned lists every arm's effective
region is nonempty, so equal class-action firing functions force
region-by-region arm matching, and stripping by (class, action)
preserves the correspondence. The ClassesOk constructor must
therefore be built over cleanAut arm lists — consistent with the
route (the quotient pipeline already cleans), but the constructor's
hypotheses must carry cleanedness. This is exactly the predicted
layer-bridging friction, now precisely located.

Next: the residual-preservation lemma for cleaned dispatches (the
constructor's core), then the ClassesOk constructor from GAutBisim +
cleanedness, then the subsystem lemma.

## Iteration 105 — ★ CONTEXTUAL DISPATCH EXTENSIONALITY ★ (zero errors)

**The cleanedness fix was itself refuted** during design: shadowed
REGIONS of surviving arms are unconstrained by dispatch matching even
in cleaned lists ([(p,a,X),(q,a,Y)] vs [(p,a,X),(q∧¬p,a,Y)] — matched,
cleaned, residual-mismatched inside p). The true design: CONTEXTUAL —
guard agreement is only ever needed UNDER the accumulated dispatch
context, which the zip threads as a test prefix and strengthens by
each entry's negation. Works on RAW lists — the cleanedness
dependency vanishes entirely (a simplification!).

Landed, zero errors on first build:
- `test_ite_split` — (test C); ite G X Y ≡ ite (C∧G) X
  ((test (C∧¬G)); Y): the context-tightening split
  (test_seq_ite + ite_restrict_else + s6/baTest).
- `CtxOk` — the context-threaded certificate (nil case IS the residual
  bridge under the final context).
- **`dispatch_ext_ctx`** — the contextual zip: class_gather both
  sides, split, ite_guard under context (Boolean case on C), the else
  re-tests via baTest and recurses on the strengthened context.

The supply side (next): `residual_firstMatch_ctx` — under the
accumulated context, the stripped residual's firstMatch equals the
full dispatch's — converting full-dispatch bisim agreement into
per-entry under-context guard agreement. Then the ClassesOk/CtxOk
constructor from GAutBisim closes the extensionality chapter.

## Iteration 106 — STRIPPING IS INVISIBLE BELOW THE CONTEXT (zero axioms)

**`firstMatch_gOthersPC`**: when a (class, action) entry's gathered
guard is false at an atom, removing its arms leaves the dispatch
unchanged there — the residual's firstMatch IS the full dispatch's.
Clean double induction over the arm list with Boolean or/and-not
decompositions of the gathered guard.

This is the last analytical piece of the extensionality chapter: the
chain is now
  bisim step agreement (per atom, full dispatches)
  → [firstMatch_gOthersPC, iterated] residual agreement under context
  → [gGuardPC_firstMatch] under-context gathered-guard equality
  → [pointwise_of_genW on C∧G] all-valuation form
  → [CtxOk] certificate
  → [dispatch_ext_ctx] equation equivalence.

Remaining: THE CONSTRUCTOR assembly (bisim + class-consistent sol →
CtxOk over the concatenated entry list, residuals emptying, halts by
bisim_hlt_invariant + s6/baTest, then strip the test-1 prefix) —
yielding THE EQUATION TRANSPORT THEOREM: bisimilar states' equations
are EquivBA-equal under class-consistent solutions. Then the
subsystem lemma and the rank induction.

## Iteration 107 — ★ THE EQUATION TRANSPORT THEOREM ★

**`equation_transport`**: bisimilar states' equations are
EquivBA-equal under ANY class-consistent solution family —

  GenBisimilar aut s₁ s₂ →
  (∀ u u′, GenBisimilar u u′ → EquivBA (sol u) (sol u′)) →
  EquivBA (eqRHS aut sol s₁) (eqRHS aut sol s₂)

— proved in one build modulo a single pinned baTest. The certificate
construction: entries = every arm of BOTH states as (class-of-target,
action, sol-of-target); the aux induction carries three invariants —
entry well-formedness, stripping-invisibility under the context
(re-established each stage via firstMatch_gOthersPC on both sides,
side 2 through the guard agreement), and residual COVERAGE (remaining
entries cover remaining arms — at nil this forces empty residuals; the
recursion is self-maintaining since a surviving arm's coverer cannot
be the stripped entry). Halts bridge by bisim_hlt_invariant through
s6/baTest/pointwise_of_genW; the test-1 prefix strips by s4.

THE EXTENSIONALITY CHAPTER IS CLOSED. The unification route now
reads: rank induction where the IH gives class-consistency of the
candidate family at lower ranks + within-rank via the enclosing
loop's canonicity, with equation_transport converting bisimilarity
into the equation-equality that ParamSolvesBA needs. Remaining: the
subsystem lemma (ambient loop-state equations = parametric equations),
the dead-region decomposition, and the induction assembly.

## Iteration 108 — the induction restructures to SYNTAX PAIRS + subsystem bricks

**Design event**: chasing the same-rank circularity to ground revealed
its true resolution — same-CLASS-INTERNAL unification (two bisimilar
states of ONE side's loop) reduces via canonicity to
`standard(v) ≡ standard(v′)` for the WRAPPED sub-labels, which is the
unification claim for the SUB-PROGRAM pair — a strictly smaller
instance. THE INDUCTION IS ON SYNTACTIC SIZE OF THE PROGRAM PAIR, not
rank: UNIF(e,f) uses UNIF at sub-loops (well-founded ✓), canonicity at
each loop level, equation-transport/dispatch machinery for the
cross-side steps, and IH-unification for the exits (lower loops =
smaller subterms of the continuation... to be organized). The rank
layer (reachRank) remains for organizing exits/dead regions.

**Bricks** (zero axioms): `foldTL_append` (dispatches split over
appends) and `foldTL_guard_factor` (a guard conjoined onto every arm
and the halt factors out as a test prefix — s6 + test_seq_ite chain).
These are the seq-subsystem lemma's two halves: the composite equation
at a left state = left-arm chain with fallback (factored continuation
dispatch) = eqRHSParam left (sol∘inl) (initRHSParam right ...).

Next: assemble the seq-subsystem lemma from the bricks, then the loop-
subsystem analogue (feedback arms factor by the same pattern), then
the syntax-pair induction skeleton.

## Iteration 109 — ★ THE SEQ SUBSYSTEM LEMMA ★

**`seq_subsystem`** ([propext]): in a sequential composite, a left
state's parametric equation IS the left system's parametric equation
whose finish is the right system's initial dispatch —

  eqRHSParam (seqGSystem Lc R) sol F (inl s)
    ≡ eqRHSParam Lc (sol∘inl) (initRHSParam R (sol∘inr) F) s

— fully parametric in the ambient continuation F, so it composes
through arbitrarily nested contexts. Supporting (zero axioms):
`guardedFold_append` (folds split over appends) and
`guardedFold_guard_factor` (a guard conjoined onto every branch and
the fallback halt factors out as a test prefix — s6/s1 base,
test_seq_ite step). The assembly: split the composite branch list,
factor the appended right-init part, done — three moves.

(Tactic notes: transitionBranches must be map-unfolded EXPLICITLY in
`show` for map_map to fire, and the show's lambdas need type
ascriptions — equation-type elaboration cannot infer binder domains.)

This is route item (1) half done: the seq case. Remaining subsystem
cases: ite (same pattern, two sides guarded) and LOOP (feedback arms
factor by the same guard_factor with hlt·guard·init decoration — the
key case connecting SCCs to wrapped certificates). Then the
syntax-pair induction skeleton.

## Iteration 110 — ★ THE LOOP SUBSYSTEM LEMMA ★ (first try)

**`loop_subsystem`** ([propext]): a wrapped state's parametric
equation is the BODY's parametric equation whose finish is the loop's
OWN initial dispatch —

  eqRHSParam (loopInitialized g body).core sol F s
    ≡ eqRHSParam body.core sol
        (initRHSParam (loopInitialized g body) sol F) s

— re-enter through the feedback or exit through the ambient
continuation. THE statement that makes an SCC "the body system with a
feedback finish": quotient cycles now connect directly to the wrapped
certificates that ParametricCanonicalBA speaks about. The proof is
seq_subsystem's three moves verbatim — the feedback decoration
(hlt·(guard·init)) factors through guardedFold_guard_factor with
hG := body-halt, h := ¬guard, and the residual inner fold is
DEFINITIONALLY the wrapped automaton's initRHSParam.

Subsystem chapter: seq ✓ loop ✓ — remaining: ite (no appended arms —
expected near-trivial retag) and the initial-state variants. Then the
syntax-pair induction skeleton: UNIF(e,f) by strong induction on
|e|+|f|, with canonicity + subsystem lemmas at each loop level,
equation transport for cross-side steps, and sub-loop UNIF instances
for class-internal consistency.

## Iteration 111 — THE SUBSYSTEM CHAPTER CLOSES

**`sum_subsystem_inl/inr`** ([propext]): disjoint-union states keep
their own side's parametric equations verbatim (one map-fusion each) —
the ite core is a sum, so this closes the ite case.

**Init dispatches need NO new work**: `ParametricInitialBA` (in every
certificate) already states `initRHSParam aut sol finish ≡
program·finish` for ANY parametric solution — the init-state variants
of the subsystem story were proven months ago.

SUBSYSTEM CHAPTER COMPLETE: seq (finish := right's init dispatch),
loop (finish := the loop's own init dispatch — feedback or exit),
sum/ite (verbatim), inits (certificates). Every state of every
Thompson automaton, at any nesting depth, has its ambient equation
expressible as its innermost system's parametric equation with a
composed finish — by iterating these four.

THE REMAINING WORK IS ONE THEOREM: the syntax-pair induction
UNIF(e, f) — bisimilar-reachable pairs in trim(SUMof e f) have
EquivBA-equal standards — by strong induction on |e|+|f|, using:
canonicity (per-loop, from certificates) + subsystem lemmas (to
instantiate canonicity at nested scopes) + equation_transport /
dispatch machinery (cross-side) + partner theorem (existence) +
sub-loop UNIF (class-internal consistency) + IH-unified exits.
Completeness = UNIF at the starts via ule_iff_start_bisim. Then
FiniteAxiomsCompleteBA. The final assembly is large but every
constituent is now proven.

## Iteration 112 — course-correction: the wiring target was mis-scoped

Attempted to WIRE the assembled subsystem/extensionality bricks into a
single closeable bridge theorem: define `stdSol := Sum.elim
(initializedStandard e std_e) (initializedStandard f std_f)` on
`SUMof A T e f`, set `qsol := stdSol` (or `stdSol ∘ bisimRep`), and
try to derive `SolvesBA (bisimQuotAut (trimAut (SUMof e f))) qsol`
from two hypotheses: (A) `SolvesBA (trimAut (SUMof e f)) stdSol`
directly, and (B) UNIF as bisim-respecting `stdSol` (exactly
`equation_transport`'s `hsol` shape). The `eqRHS_quot` reduction +
`bisimRep` idempotence + a short new EquivBA-level `foldTL` branch-
congruence lemma make the wiring FROM (A)+(B) TO the quotient-solves
goal fully mechanical — no gap there.

**But (A) is the wrong ask.** `sumof_exhaustive` proves `aut.states`
for `SUMof A T e f` (hence `trimAut (SUMof A T e f)`, same `.states`
field) is EXHAUSTIVE — literally every element of the carrier type,
including every syntactically-dead/unreachable state Thompson
construction produces (e.g. an `ite (test 0) p q` branch). Demanding
`SolvesBA aut stdSol` at ALL of them forces `stdSol` — the ACTUAL
canonical Thompson label, a fixed particular expression — to satisfy
its OWN equation even at dead states, which resurfaces exactly the
circularity flagged at `dead_thompson_label_eq_zero_of_complete`
("any successful pruning proof must establish this special
null-language case directly for Thompson labels" — proving a
PARTICULAR canonical expression collapses to `.test .zero` is not
free). This is the SAME dead-region trap iteration 108 already hit
and routed around once (rank/hybrid-family → syntax-pair); framing
the wiring through raw `SolvesBA` of `stdSol` reopens it needlessly.

**The resolution, confirmed against `GkatDecomp.StateRole` /
`dag_roles`**: `SolvesBA` is never the right target to hand-construct
directly. `StateRole.fold` only demands `sol s = eqRHS aut sol s` for
SOME `sol` — not that `sol` equal any particular canonical
expression, let alone `.test .zero`, at any state. `dag_roles` gives
this for FREE, by well-founded recursion on `StepRel`, for an entire
ACYCLIC automaton (this is exactly `loopfree_complete`'s engine). The
six existing completeness theorems all follow the same shape: a
single `sol` built by well-founded recursion on a RANK (not raw
`StepRel`, since real automata have cycles) that is `fold` off-cycle
and `selfLoop`/`salomaaE`/`member`/`header` on-cycle — `reachRank`
(Nat-valued, trivially well-founded) is exactly this ranking function,
already built in the census layer. Dead/acyclic states, reachable or
not, cost NOTHING under this scheme: they get `fold` automatically,
with whatever closed form the recursion produces, never needing to
equal `stdSol` or `.test .zero` or anything externally meaningful.

**So the correctly-scoped remaining theorem is narrower than "solve
the whole exhaustive state space" and narrower than my attempted
`stdSol`+UNIF wiring**: it is exactly `RoleCovered` as originally
stated — `StateRole` existence for canonical-quotient states inside a
NONTRIVIAL SCC (same-`reachRank` mutually-reachable block spanning
possibly both e's and f's automata), built via rank-based recursion
whose EXIT continuations (lower rank, hence already assigned by the
IH) feed as the `finish` parameter into `ParametricCanonicalBA` at
each loop level through the subsystem lemmas (seq/loop/sum), with
`equation_transport` + `sreach_partner` supplying the cross-side
matching that lets a same-class member borrow another side's
already-established local structure. This is IDENTICAL in content to
what iterations 97-111 already targeted — this iteration's contribution
is confirming (against `decomp_solves`/`dag_roles`, not just
intuition) that the natural-looking `stdSol`-global-`SolvesBA` shortcut
is a dead end, so the next iteration should build `qsol` via explicit
rank-recursion + `StateRole` case dispatch (mirroring `slSol`/`saSol`'s
existing pattern in GkatPlanExistenceProofs.lean) rather than via a
`SolvesBA aut stdSol` hypothesis. No new theorem lands this iteration;
this is a scoping correction that avoids a wasted future attempt.

## Iteration 113 — the induction is native to the QUOTIENT; the missing brick is LOCATE

**Web check**: Hung Pham's 2026 Bucknell thesis (the SAME Pham already
cited in GkatThompsonUniquenessProofs.lean's docstring for
`ParametricCanonicalBA`) proves exactly the per-automaton solution-
uniqueness fact this repo already has, and explicitly frames full
completeness as reducing to EXISTENCE of a solution for the trimmed
automaton — i.e. published work is now converging on this repo's own
strategy (role/witness existence over UA-elimination-by-brute-force).
Still open since 2019; only skip-free GKAT (Kappé-Schmid-Silva) has a
full UA-free proof; well-nested automata are confirmed NOT closed
under quotient (rules out a naive well-nestedness route, already
known here). No SCC-decomposition technique found in the literature —
the S2-stratum/singleton-SCC/schedule-calculus angle here appears
novel. Calibration unchanged: genuinely open, field leans negative,
but this repo's strategy now has independent external confirmation.

**Re-derivation, sharper than iteration 112**: chasing "how does a
rank-recursion `qsol` actually get BUILT for `RoleCovered`" to ground
resolves the last imprecision in 112's own framing (which spoke of
"same-reachRank, possibly cross-side block" — but raw `reachRank` is
a literal-state count and is NOT obviously bisimulation-invariant
across two differently-sized Thompson constructions, so organizing
the induction on TWO SIDES' ranks jointly would have been the wrong
frame again). The fix: **`RoleCovered`'s domain is already the
QUOTIENT automaton** (`bisimQuotAut (trimAut (SUMof A T e f))`) —
states there are single REPRESENTATIVES (one raw state chosen per
class by `bisimRep`/`Classical.choose`), so `reachRank`/`dag_roles`/
`slSol`/`saSol`-style rank recursion applies NATIVELY and UNIFORMLY
to this ONE automaton — no two-sided bookkeeping needed at the
induction-organizing level at all. The two-sidedness only enters when
CLOSING one representative's own equation.

**The representative-closing step is already fully assembled**: a
representative `s` is some raw state, hence sits in EITHER e's or f's
own certified Thompson tree, at some nesting depth. Its ambient
quotient equation, by `eqRHS_quot`, is `eqRHS aut (qsol∘bisimRep) s`
for `aut := trimAut (SUMof e f)` — by iterating the subsystem lemmas
(seq/loop/sum, ALL closed since iteration 111) down to `s`'s innermost
enclosing loop/leaf, this equals that subsystem's OWN `eqRHSParam` at
an appropriate composed `finish`. **`StandardSolvesBA.withContinuation`**
(already proven, zero new work — `GkatThompsonUniquenessProofs.lean:195`)
says `.seq (standard state) finish` UNCONDITIONALLY satisfies that
subsystem's own parametric equations at that `finish`, for ANY finish
— no schedule, no Gaussian elimination, no rank recursion needed
WITHIN one side's own loop. So `qsol(s) := .seq (standard_side s) finish`
closes s's own equation outright, PROVIDED: (a) `finish` is built
correctly from the exit continuations (already-assigned, lower in the
induction), and (b) every DIRECT successor `t` of `s` (within `s`'s
OWN loop) has `qsol (bisimRep t) ≡ standard_side(t); finish` — i.e.
the value the quotient ACTUALLY assigned at `t`'s class (which might
be a REPRESENTATIVE CHOSEN FROM THE OTHER SIDE, if `bisimRep` picked
a cross-side partner) agrees with what `s`'s own side would want
there. THIS single per-edge consistency check — not global `SolvesBA`,
not a two-sided rank-matched induction — is the entire remaining
content, and it is exactly one instance of `equation_transport`
(`GenBisimilar aut t (bisimRep aut t)`, already have `bisimRep_bisim`)
combined with `ParametricCanonicalBA.unique` (both candidate values
solve the SAME local system at the SAME finish once agreement is
assumed on THEIR successors — induction closes by well-founded
recursion on the quotient rank, exactly as `dag_roles`/`slSol` do).

**The one missing structural brick, now named precisely: LOCATE.**
None of the above compiles into a construction yet because nothing
in the repo currently maps an ARBITRARY raw state of
`certifiedThompson A T p` to "which subsystem (at which nesting
depth) it belongs to, and what its local `standard` map is" — the
subsystem lemmas (`seq_subsystem`/`loop_subsystem`/`sum_subsystem_*`)
each show the equation identity GIVEN you already know a state has
the shape `.inl s`/`.inr s` for a NAMED nested `GSystem`; walking an
opaque `(certifiedThompson A T p).State` down to its innermost home
requires an induction mirroring `certifiedThompson`'s OWN recursive
definition (test/act base cases; seq/ite/wh recursive cases building
the nested `Sum`/`Option` state types) — a genuine, well-scoped, but
not-yet-built piece of machinery. This is the same content the ledger
called "syntax-pair induction," now sharpened: it is not induction on
BISIMILAR PAIRS at all — it is a single-sided structural recursion
(LOCATE) over ONE certified Thompson tree, needed on both e's and f's
side independently, that the cross-side unification argument above
then consumes. Next concrete step: build LOCATE (recursion on
`certifiedThompson`'s match arms, producing per-state: the enclosing
`InitializedGAut`/`GSystem`, the local `standard`, and the ambient
`finish`-composition path back to the top), THEN wire the rank
recursion + representative-closing step above into `RoleCovered`.

## Iteration 114 — ★ RIGIDITY + FREE EXISTENCE ★ (and iteration 112 was WRONG)

Web: nothing newer than Pham's 2026 thesis / Kappé-Schmid-Silva
skip-free line; no arXiv result settling n-ary UA elimination either
way. Weighted GKAT (ICALP 2025) and ProbGKAT are different variants.

**NINE new theorems, all type-checked, all sorry-free** (verified by
`lake build GkatCensusProofs`, axiom profiles printed below):

1. `sumGAut_toGAut_eqRHS_inl/inr` [propext] — the ambient equation of
   an internal state of a Thompson SUM *is* that side's own parametric
   equation at finish `1`. The two branch lists fuse to the same list
   (two `map_map`s) and the fallbacks differ by `s5` alone. Uses the
   pre-existing `eqRHS_eq_guardedFold` bridge (`eqRHS` is foldr over
   `.trans`, NOT defeq to `guardedFold (transitionBranches ...)` —
   foldr-over-map needs induction, which that lemma already did).

2. `sum_solution_forced_left/right` [propext, Quot.sound] — **THE
   FORCED-SOLUTION THEOREM**: ANY `SolvesBA` of the raw Thompson sum
   is, at every internal state of either side, provably that state's
   canonical Thompson label. Immediate from (1) + the certificate's
   `ParametricCanonicalBA` at finish `1`, + `s5`. Choice-free.

3. `sum_solution_rigid` [propext, Quot.sound] — **RIGIDITY**: any two
   solutions of the raw sum agree provably at every internal state.
   The solution space is a SINGLE `EquivBA` class.

4. `eqRHS_sumGAut_inl/inr` (zero axioms) — equations of a disjoint
   union are the summands' own equations.

5. `stdSum` + `sum_solves_std` [propext, Quot.sound] — **EXISTENCE IS
   FREE**: the canonical labelling solves the raw sum outright, from
   `certifiedThompson_toGAut_solves` on each side plus (4).

6. `equivBA_of_unif` [propext, Classical.choice, Quot.sound] — the
   entire open problem in ONE LINE.

**ITERATION 112'S CENTRAL CLAIM WAS WRONG, and (5) refutes it in
Lean.** 112 recorded that demanding `SolvesBA` of the sum at the
canonical labelling "reopens the dead-region circularity" because
`SUMof`'s state list is exhaustive. The error: a dead state's label
satisfying its OWN equation is NOT the same as that label provably
collapsing to `0`. The former is `certifiedThompson_toGAut_solves`,
proven long ago, free, dead states included. The latter (the genuine
`dead_thompson_label_eq_zero_of_complete` circularity) is needed only
for TRIMMING — and `solvesBA_untrim` already runs that direction
(trim-solution → raw-solution), which is the direction actually used.
So the `stdSol` route was never blocked by what 112 said blocked it.
Recording this plainly: 112's scoping correction was itself a
mis-scoping, caught by formalizing rather than reasoning about it.

**WHAT RIGIDITY ACTUALLY BUYS — and what it costs.** Honest reading:

* GOOD: the whole `RoleCovered` / `StateRole` / schedule / Gaussian-
  elimination apparatus is OFF the critical path for completeness. A
  quotient solution lifts (`lift_solvesBA`) to a raw solution, so by
  rigidity ANY `qsol` witnessing `RoleCovered` is forced to satisfy
  `qsol ∘ bisimRep ≡ stdSum` at every internal state. There was never
  any freedom in the choice of `qsol` to be clever about. The role
  framing was UNIF in disguise the whole time.

* SOBERING: consequently `equivBA_of_unif` is a REFORMULATION, not a
  reduction that makes progress on its own. UNIF at the two starts IS
  completeness (the start labels ARE `e` and `f`, and `ule_iff_start_
  bisim` makes ULE ⟺ start bisimilarity). UNIF is EQUIVALENT to the
  open problem, not weaker than it. Nothing here shrinks the hard
  core; it strips everything that ISN'T the hard core.

**THE HARD CORE, now stated with zero scaffolding**: bisimilar states
of `trimAut (SUMof A T e f)` carry `EquivBA`-equal canonical Thompson
labels. No quotients, no trimming obligations, no role witnesses, no
schedules, no dead-state pruning, no LOCATE (iteration 113's named
brick is also unnecessary — `ParametricCanonicalBA` speaks about a
whole program's flattened system at once, so nothing ever walks the
syntax tree). Just: bisimilar ⟹ provably equal labels.

Next: attack UNIF directly. The available leverage is `equation_
transport` (bisimilar states' equations are EquivBA-equal under a
class-consistent family — note `stdSum` is exactly the family whose
class-consistency UNIF asserts, so this is a fixpoint/coinduction
shape, not a straight implication) plus the subsystem lemmas for
factoring labels of nested states. The coinductive character is now
explicit and unavoidable: UNIF is self-referential in precisely the
way UA would have discharged, which is why the axiom was there.

## Iteration 115 — ★ THE ACYCLIC HALF OF UNIF, PROVEN ★ (fixpoint confined to cycles)

Iteration 114 ended by calling UNIF "self-referential in precisely the
way UA would have discharged".  That was right but INCOMPLETE: the
self-reference is real, and it is CONFINED TO CYCLES.  Six new
theorems, all type-checked sorry-free:

* `foldr_congr_equivBA`, `eqRHS_congr_equivBA` (ZERO axioms) —
  equations respect `EquivBA` at the arm targets.
* `bisimRep_idem` — representatives are idempotent
  (`bisimRep_coherent ∘ bisimRep_bisim`).
* **`unif_of_wf`** [propext, Classical.choice, Quot.sound] — if every
  arm strictly descends a rank ON CLASSES, then every state's label is
  provably equal to its class representative's label.
* `unif_bisim_of_wf` — hence bisimilar states carry provably-equal
  labels.
* `unif_sum_of_wf` — the Thompson-sum instance, discharging the
  solving hypothesis by `sum_solves_std` + `sumof_exhaustive`.

**THE MOVE THAT BREAKS THE CIRCULARITY (in the acyclic case).**  The
obstruction was: `equation_transport` needs a CLASS-CONSISTENT family,
and `stdSum` being class-consistent IS UNIF.  The escape: do not use
`sol`; use **`sol' := sol ∘ bisimRep`** — "the label of my class
representative".  `sol'` is class-consistent BY CONSTRUCTION and for
free, because bisimilar states have LITERALLY EQUAL representatives
(`bisimRep_coherent`), so the values are equal, not merely `EquivBA`.
No UNIF is needed to know that.  Then

    sol x  ≈  eqRHS sol x           (sol solves)
           ≈  eqRHS sol' x          (arm-target UNIF, from the IH)
           ≈  eqRHS sol' (rep x)    (equation_transport — sol' is OK!)
           ≈  eqRHS sol (rep x)     (arm-target UNIF, from the IH)
           ≈  sol (rep x)           (sol solves)

The two outer steps are free.  The transport step is free.  The two
inner conversions need UNIF ONLY AT THE ARM TARGETS — so along a
strictly descending rank the induction closes.  `bisimRep_idem` is
what lets the second conversion reuse `hdesc` at `rep x`.

**WHAT IS AND IS NOT SETTLED.**  Settled: UNIF is a theorem on any
well-founded class graph, with no uniqueness axiom, no schedules, no
role witnesses, no trimming.  Not settled, and this is the whole
residue: a class that can reach ITSELF.  There the arm targets do not
descend, the IH is unavailable, and the chain's two inner conversions
are exactly the statement being proved.  This is precisely where the
n-ary UA does its work, and it is precisely the six strata's content
(loopfree/atomic/gloops/chain/two/chord were each a cyclic case
cracked by hand).  So iteration 115 does NOT shrink the hard core —
it proves that everything OUTSIDE the hard core is now free, and
states the hard core as sharply as it can be stated:

    for a class C that reaches itself, and s, t ∈ C on opposite sides
    of the sum, prove EquivBA (stdSum s) (stdSum t)

with `sum_solves_std` (both are solutions), `sum_solution_rigid` (the
solution space is one class), the subsystem lemmas, and per-loop
`ParametricCanonicalBA` all available as leverage, and with the
acyclic surroundings already unified by `unif_of_wf`.

Note the shape this leaves: the induction may now be run on a rank
that is only required to descend ACROSS classes, with cyclic classes
as the base cases.  That is exactly the `scc_block_schedP` /
`scc_rank_sched` interface built in iterations 83-96 — the schedule
calculus is NOT dead after all; iteration 114 retired it from the
critical path for the ACYCLIC part, and this iteration shows the
cyclic part is where it was always meant to apply.

### Iteration 115 addendum — the literature explains WHY the residue is cyclic

Search (independence/non-finite-basis angle) returned the structural
reason, which is worth recording because it validates the shape of
what is left:

* **No independence result exists.**  Smolka et al. (POPL 2020) left
  UA-derivability explicitly open; Kappé-Schmid-Silva (ESOP 2023) say
  it "remains open" and add they think it "might be false" — but NO
  model separating UA from the other axioms has been produced.  The
  gap is open, not known-closed and not known-unclosable.  (Field
  prior still leans negative; this is a named pessimistic conjecture
  from the primary authors, not evidence.)
* **The classical negative results are about EQUATIONAL systems, not
  uniqueness rules.**  Redko (1964) and Aceto-Fokkink-Ingólfsdóttir
  (BRICS RS-96-36) show the equational theory of regular expressions
  is not finitely based, even over a one-letter alphabet.  So SOME
  non-equational principle is mandatory.  Kozen's is star induction
  (`ax ≤ x → a*x ≤ x`) — a quasi-identity requiring the semilattice
  ORDER and a least fixpoint.  Salomaa's is the uniqueness rule, which
  is not even a quasi-identity (not substitution-closed).
* **GKAT has no order and no least fixpoint** — which is exactly why
  Kozen's escape route is unavailable and why a uniqueness principle
  reappears.  This repo's `w3` IS a uniqueness rule, restricted to ONE
  unknown.

That places the campaign precisely: the non-equational power is
already present and already finite (`w3`, n=1).  The whole question is
whether ONE-unknown uniqueness plus the finite equations can simulate
n-unknown uniqueness.  Simulating it means eliminating unknowns one at
a time — **Gaussian elimination** — which is exactly the RTree /
`SchedOk` / `scc_block_schedP` calculus of iterations 73-96, and
exactly what the six hand-cracked strata each did.

So the picture is coherent end to end: `unif_of_wf` (115) makes every
acyclic part free; the cyclic residue needs one-unknown-at-a-time
elimination; the elimination calculus exists and is validated on six
strata.  What does NOT exist is a GENERAL construction of a schedule
for an ARBITRARY cyclic class — every instance so far was built by
hand against a specific witness automaton.  That, and only that, is
the open problem now.

## Iteration 116 — UNIF MODULO CYCLES; and iteration 114 overstated the RoleCovered obituary

**Three new theorems, type-checked sorry-free** [propext,
Classical.choice, Quot.sound]:

* **`unif_of_wf_mod_cycles`** — UNIF holds as soon as every arm either
  strictly descends the class rank OR ALREADY SATISFIES UNIF AT ITS
  OWN TARGET.  Strictly stronger than `unif_of_wf` (115): the
  descent hypothesis weakens to a disjunction, and the proof is the
  same five-step chain with an `rcases` at each arm.
* `unif_bisim_of_wf_mod_cycles`, `unif_sum_of_wf_mod_cycles` — the
  bisimilar-pair and Thompson-sum corollaries.

This turns "the cyclic case is what's left" from a plan into a
THEOREM, and localizes the residue as tightly as it goes: not
"arbitrary bisimilar pairs inside a cyclic class", but specifically
"the targets of the arms that stay inside a class".

**CORRECTION TO ITERATION 114.**  114 concluded that rigidity puts the
whole `RoleCovered`/`StateRole` apparatus "off the critical path".
That overstated it.  Rigidity forces the VALUE of any solution
(everything is `EquivBA`-equal to `stdSum`); it says NOTHING about
whether a solution is CONSTRUCTIBLE, and construction is the useful
direction — `equivBA_of_quot_solvesBA` consumes ANY `qsol`, and
`dagSol`/`slSol`/`saSol` build them outright by well-founded recursion.
Rigidity and constructibility are compatible: `saSol` simply produces
an expression that happens to be `EquivBA`-equal to `stdSum`.  The
role route is alive; 114's obituary was wrong, in the same way 112's
dead-state claim was wrong — reasoning about the machinery instead of
running it.

**WHAT IS ACTUALLY COVERED ALREADY.**  Re-reading the strata against
this: the SINGLETON-SCC THEOREM (commit 050b7483) covers EVERY
one-cycle automaton GENERALLY, not per-witness — multiple self-arms
gather into one by `arm_commute` (u2/u3/u2/dneg) plus u5 right-
distribution, so a class whose SCC is itself alone closes by `w3`
regardless of arm count.  `dag_roles` covers acyclic.  So the residue
is NOT "cyclic classes" in general — it is precisely **SCCs
containing TWO OR MORE DISTINCT CLASSES, mutually reachable**.  That
is exactly an n-unknown system with n ≥ 2, and exactly what the six
hand-cracked strata were each doing by hand.

**THE RESIDUE, FINAL FORM.**  A multi-class SCC gives k ≥ 2 mutually
recursive unknowns.  `w3` is uniqueness for ONE unknown.  Closing the
problem means simulating k-unknown uniqueness by k applications of
one-unknown uniqueness — Gaussian elimination — with the substitution
steps discharged by `equivBA_substA` (proven, zero axioms) and the
productivity side conditions free (every arm contributes
`.seq (.act a) _`, so self-reference is always action-guarded).  The
machinery is `RTree`/`SchedOk`/`stepSubst`/`backSol`/`sched_solves`
(iterations 73-96, all proven).  The gap is the GENERAL CONSTRUCTION
of a schedule for an arbitrary multi-class SCC; every existing
instance was built by hand against a named witness automaton.

### Iteration 116 addendum — ★ the published obstruction is NAMED, and it is the one this repo already attacked ★

The n-ary-from-unary search returned the single most calibrating
result of the campaign.  From Kappé-Schmid-Silva (skip-free GKAT,
arXiv 2301.11301) and the ICALP'21 coequations paper, verbatim:

> "the case for general n does not seem to follow easily from the case
> where n = 1.  The problem here is that, **unlike the analogous
> situation for Kleene algebra, there is no general method to transform
> a left-affine system with n+1 unknowns into one with n unknowns**,
> even though this is possible in certain cases."

> "The other axioms of GKAT contain the instantiation of (UA) for n=1,
> which has so far been sufficient in all handwritten proofs of
> equivalence that we know.  Yet (UA) seems to be necessary in both
> known completeness proofs."

And the MECHANISM they name for why elimination fails:

> "replacing action symbols in a valid GKAT equation with arbitrary
> GKAT expressions might yield an invalid equation"

— i.e. **substitution, the step elimination depends on, is not sound
in GKAT.**  In classical KA it is: matrices over a KA form a KA, the
n-ary star is definable from the unary one, and Braibant-Pous
mechanized exactly that reduction in Coq.  GKAT has no order, no
matrices, and unsound substitution, so the classical route is closed
three ways over.

**THIS REPO'S POSITION ON THE NAMED MECHANISM.**  `equivBA_substA`
(GkatElimProofs.lean:180, ZERO axioms, verified again this iteration)
proves precisely the missing principle in restricted form:

    σ : A → Exp A' T,  (∀ a X W x, bval W (E (σ a)) x = false)
      → EquivBA e f → EquivBA (substA σ e) (substA σ f)

Substitution IS sound when every replacement is PRODUCTIVE (never
accepts the empty guarded string).  The `w3_ba` case is the one that
matters and it goes through: the guardedness side condition transports
via `baTest` + `bval_E_substA`.  So the general-unsoundness objection
does not apply to productive substitutions, and elimination only ever
substitutes into positions of the form `.seq (.act a) _`.  The
remaining productivity worry — that an eliminated unknown's CLOSED
form `(wh G BODY)·REST` need not itself be productive — is what the
call-marker layer (`embedC`/`collapseC`/`equivBA_of_embed`, iteration
73-78) was built for: calls map to `test 0`, which IS productive.

**HONEST CALIBRATION.**  What this does NOT establish: sound
substitution is a PREREQUISITE for an elimination method, not a
method.  The authors' actual claim is the stronger "no general method
to go from n+1 unknowns to n", and that stands unrefuted — having a
sound substitution principle does not by itself produce the schedule.
What it DOES establish, and this is genuinely new information for
calibration: the specific mechanism the domain experts cite as the
blocker is one this repo has a proven, axiom-free answer to, and the
secondary obstruction they would hit next (unproductive closed forms)
is one the repo anticipated and built the call-marker transport for.
The campaign is not pushing against the published objection in
ignorance of it; it is pushing at the exact joint the objection names,
with the joint already loosened.

Residue unchanged and now doubly confirmed from outside: a GENERAL
construction of an elimination schedule for an arbitrary multi-class
SCC.  Both this repo and the literature agree that is the whole
problem.  The literature says no general method is known.  This repo
has the substitution soundness, the productivity transport, the
schedule soundness theorem (`sched_solves`), the assembly
(`sched_assembly_roles`), the SCC constructors (`scc_rank_sched`,
`scc_block_schedP`), and six worked instances — and lacks only the
general schedule-existence construction.

## Iteration 117 — ★ THE ELIMINATION STEP, AND EXACTLY WHY IT IS CONDITIONAL ★

**Five new theorems, ZERO AXIOMS** (no choice, no propext, no
Quot.sound — fully constructive):

* `productive_act_prefix` — any action-headed prefix is productive, so
  it can serve as a `w3` loop body downstream.
* **`elim_to_prefix`** — a state whose gathered equation is a self-loop
  followed by a UNIFORM single exit closes, by ONE `w3`, to a PREFIX
  times that exit: `U ≈ ite G (B·U) (P·V)` ⟹ `U ≈ ((wh G B)·P)·V`.
* **`elim_affine_step`** — substituting a prefix-form closed solution
  into an arm body yields another arm body (`s1` reassociation).
* **`elim_reduces`** — the two together: **n+1 → n**, with the new
  prefix still productive, so the next `w3` applies and elimination
  RECURSES.
* `elim_back` — back-substitution recovers the eliminated unknown once
  its exit is known, so a full schedule reconstructs every original
  unknown, not only the last.

**THE DIAGNOSIS — why elimination is conditional, stated exactly.**
A left-affine system needs every unknown in position
`guard → prefix · unknown`, with all guards read AT THE CURRENT STATE.
Eliminating `U` substitutes its closed form `(wh G B)·R` under an
action, giving `a·(wh G B)·R`.

* `R = P·V` (prefix times ONE unknown, no residual guard, no residual
  halt): reassociates by `s1` to `(a·(wh G B)·P)·V` — still
  `prefix · unknown`.  Left-affine, one fewer unknown.  ✓ PROVEN above.
* `R` branches (`ite h (b·V₁) (ite h' (b'·V₂) …)`): the substituted
  form is `a·(wh G B)·(ite h …)` and **`h` is read AFTER `a` has
  executed**.  NO AXIOM MOVES A GUARD LEFTWARD PAST AN ACTION — `u5`
  distributes a guard already at the FRONT
  (`(ite g p q)·r ≡ ite g (p·r) (q·r)`), and `test_seq_ite` commutes a
  guard past a TEST, but nothing commutes one past an action.
  Left-affineness is destroyed; the reduced system leaves the class
  `w3` can close.  ✗

**In Kleene algebra this cannot arise**: choice is unconditional, so
`a(p+q) = ap + aq` redistributes any branching back to the front, and
matrices over a KA form a KA.  GKAT's choice is GUARDED — state
dependent — and that single difference is the entire obstruction.  It
is also exactly what "skip-free"/"uniform exit" restrictions buy: they
force `R` into the first shape by construction, which is why
Kappé-Schmid-Silva could eliminate UA there and not in general.

So "no general method to transform n+1 unknowns into n" is now, in
this repo, a PROVEN METHOD PLUS A PRECISELY CHARACTERIZED SIDE
CONDITION: uniform exit of the eliminated state.  That reframes the
open problem one more time, and sharply:

    **Does every multi-class SCC of a canonical Thompson-sum quotient
    admit an elimination ORDER in which each state, at the time it is
    eliminated, has a uniform exit?**

Not "does some state have a uniform exit" (the refuted single-exit
conjecture, iteration 96) but "is there an ORDER" — and crucially the
exits are computed against the ALREADY-ELIMINATED remainder, so a
state with two exits now may have one later, once the other has been
absorbed into a prefix.  The iteration-96 counterexample
`wh b (ite c (p; test d) q)` refuted the static single-exit property;
it does NOT refute the dynamic ordering question, which is strictly
weaker and, as far as this ledger knows, untouched.  Also relevant:
`GkatDeadExitElim.elim_scc2` already exists in the repo — 2-SCC
elimination machinery predating this campaign, worth re-reading
against the new framing.

Next: attack the ordering question — either construct an order for an
arbitrary multi-class SCC, or find a witness SCC where no order works
(which would be the first genuine negative result of the campaign and
would explain the field's pessimism concretely).

### Iteration 117 addendum — the diagnosis was already in the repo, and there is MEASURED data

Honesty check after committing: `GkatDeadExitElimProofs.lean` (the
two-state-SCC section, predating this whole campaign) already contains
the diagnosis 117 presents as new, in one sentence:

> "The dead fallback is what makes this work and is not a convenience:
> with a live fallback the factored form is `ite B (U·y) fb`, and
> substituting puts `y` under a choice inside a product — the nesting
> left-distributivity cannot undo."

That is exactly `elim_reduces`'s side condition and exactly the
guard-after-action argument.  So 117 independently re-derived a fact
this repo had already written down.  What 117 genuinely adds is the
GENERAL, zero-axiom statement of the step (`elim_to_prefix` /
`elim_affine_step` / `elim_reduces` / `elim_back`, none of which were
stated in general form before — `elim_scc2` is the size-2 instance),
plus the reframing to the ORDERING question.  Recording the overlap
because the ledger's value depends on it being trustworthy.

**THE MEASURED DATA, which is the real find.**  The same file records
harness measurements over start-merged quotients:

* 85.7% have ALL-SINGLETON SCCs — fully covered by the singleton-SCC
  theorem (050b7483).
* 14.3% contain a multi-state SCC — **all measured ones of size 2 or
  3** — and **98.2% of those eliminate anyway**.
* 24.6% are linear chains (`chain_solves`).

So the residue is not "multi-class SCCs" in the abstract: it is the
measured ~1.8% of multi-state SCCs that did NOT eliminate under the
harness's mechanism.  That is a concrete, finite, already-observed
target — far better than a universally-quantified conjecture.

**NEXT STEP, and it is now obvious**: recover the non-eliminating
instances from the harness.  Either (a) they all fall to an
elimination ORDER the harness never tried (it eliminates greedily, and
`elim_reduces` shows exits are computed against the ALREADY-ELIMINATED
remainder, so order matters and the harness may simply have picked
badly) — in which case the ordering question has a constructive
answer; or (b) one of them provably admits NO order, which would be
the campaign's first genuine negative result and would concretely
explain the field's pessimism.  Both outcomes are valuable and the
experiment is cheap.  Note also the measured sizes are 2 and 3 only,
so a full case analysis at k=2 and k=3 may settle it outright.

### Iteration 117 addendum 2 — the mechanism is right, the ATTRIBUTION was wrong, and the real published obstruction DOES NOT APPLY HERE

The left-affine search corrected 117 on a point that matters, and the
correction is good news.

**(a) The definition.**  Schmid-Kappé-Kozen-Silva, ICALP 2021, Def 7.1:
a left-affine system is `xᵢ = eᵢ₁·x₁ +_{bᵢ₁} ⋯ +_{bᵢₙ} cᵢ` with the
`bᵢⱼ` pairwise disjoint, `cᵢ` Boolean and disjoint from them.
Guards-at-the-head is baked into the SHAPE, not an extra side
condition.  The extra condition for uniqueness is exactly this repo's
productivity: "productive coefficients, i.e. `E(eᵢⱼ) ≡ 0`".

**(b) My mechanism is CORRECT but is NOT the published reason.**  GKAT
has only RIGHT distributivity (G8) `(x +_b y)z = xz +_b yz`; left
distributivity `a(x +_b y) = ax +_b ay` is absent AND UNSOUND, because
`a` may change `b`'s truth.  That is precisely 117's "a guard pulls
left past tests but never past actions", independently confirmed.  So
it is a correct SUFFICIENT obstruction to the naive elimination.  But
Kappé-Schmid-Silva's Remark 2.6 cites **[31] = Kozen & Tseng, "The
Böhm-Jacopini theorem is false, propositionally" (MPC 2008)** — so the
obstruction they actually mean is **EXPRESSIVENESS**: the solution of a
left-affine system need not be a while program AT ALL.  That is much
deeper than a shape problem, and 117 wrongly implied the literature
gave the shape reason.  Corrected here.

**(c) AND THAT OBSTRUCTION DOES NOT APPLY TO THIS CAMPAIGN'S SYSTEMS.**
This is the substantive point.  Böhm-Jacopini-falsity says a GENERAL
left-affine system may have no GKAT-expression solution — the target
does not exist in the syntax, so no elimination could ever produce it.
But the systems here are not general: they come from Thompson automata
of actual programs, and **`sum_solves_std` (iteration 114) PROVES a
solution exists and exhibits it** — the canonical labelling.  Rigidity
(`sum_solution_rigid`) then pins every solution to that one class.  So
for every instance this campaign must solve, the solution is known to
be expressible and is already in hand as syntax; the only open question
is whether it satisfies the QUOTIENT's equations (= UNIF).  The
deepest published obstruction is inapplicable to these instances by a
theorem this repo already has.

**(d) Skip-free, corrected.**  Skip-free does NOT make the
guard-after-action problem disappear — left distributivity is still
absent there.  It BYPASSES systems entirely, reducing to
Grabmayer-Fokkink one-free star expressions modulo bisimulation and
then to language semantics by dead-branch pruning.  Its payoff is that
(UA) goes AND the guardedness proviso drops (RSP with no side
condition).  So it is not a template to imitate here.

**Net calibration.**  Two of the three barriers the field cites are now
accounted for: substitution-unsoundness is answered by
`equivBA_substA` (productive case, proven, zero axioms), and
expressiveness-of-solutions is inapplicable by `sum_solves_std`.  What
remains is the one this repo can still see clearly: the shape problem
of 117 — and the measured data says it bites in ~1.8% of multi-state
SCCs, all of size 2-3.  That is the whole remaining target.

## Iteration 118 — ★ THE OPEN INSTANCES, RECOVERED AND ANALYSED ★

Acting on 117's "next step is obvious": added an **OPEN-SCC dump** to
`scc_census` in span-search/src/main.rs (additive, ~30 lines: prints
every multi-state SCC no proved stratum covers, its port count, and
the full quotient so exit targets are readable).  Then ran it.

**MEASURED, NA=2** (30k language-equivalent pairs, depth ≤ 6, k ≤ 10):
99.3% of pairs FULLY covered by proved strata.  17070 quotient states:
15630 fold, 860 singleton-self, 580 in multi-state SCCs.  218
multi-state SCCs: 195 walked-covered, **23 open**.  And the striking
part: **ZERO multi-port SCCs.  Every shape in the histogram has
halting-members + exit-arms ≤ 1.**  At two atoms, the two-port case
the elimination step cannot handle SIMPLY DOES NOT OCCUR.

**MEASURED, NA=4** (30k pairs, depth ≤ 8, k ≤ 12): 96.6% of pairs
fully covered.  1021 multi-state SCCs: 1011 walked-covered, **10
open**.  Multi-port DOES occur here — 4 dumps — so the phenomenon
needs ≥ 3 atoms, which is why every earlier NA=2 sweep missed it.

**WORKED ANALYSIS #1 — an "open" instance that is actually
ELIMINABLE.**  OPEN-SCC #1 (pair #211, k=3, scc {0,1,2}, ports=1):

    s0: hl=0110  st=[s1, -, -, s2]
    s1: hl=0000  st=[s0,s0,s0,s0]
    s2: hl=0000  st=[s1,s2,s2,s2]

Eliminate s2 first.  Its equation is
`s2 ≈ ite{1,2,3} (p·s2) (ite{0} (q·s1) (test 0))` — self-loop plus ONE
exit, and **the fallback is `test 0`, DEAD**, since s2 does not halt.
So `ite{0} (q·s1) (test 0) ≡ {0}?·q·s1` by dead-branch collapse, and
`w3` gives `s2 ≈ ((wh{1,2,3} p)·{0}?·q)·s1` — **a PREFIX times s1**.
That is exactly `elim_reduces`' hypothesis, so left-affineness
survives.  Substituting into s0 turns its s2-arm into another s1-arm;
both of s0's arms now target s1, and `arms_merge`/u5 fuse them into
`s0 ≈ ite G (V·s1) (test{1,2})`.  Then `s1 ≈ t·s0` (all atoms, dead
fallback), substitute, and s0 becomes a pure self-loop closed by one
more `w3`.  **Fully eliminated, order s2 → s1 → s0.**

So this instance is open only to the HARNESS's classifier, not to the
mathematics — precisely what `GkatDeadExitElimProofs.lean` already
warned ("the checker, not the mathematics, is the binding
constraint").  Note what made it work: the DEAD FALLBACK.  A
non-halting state's residual collapses to a prefix, which is the
uniform-exit condition arriving for free.

**WORKED ANALYSIS #2 — an instance that RESISTS BOTH ORDERS.**
OPEN-SCC #3 (pair #14074, k=3, scc {0,1}, **ports=2**):

    s0: hl=0000  st=[s1, X2, s0, X2]
    s1: hl=0000  st=[s1,  -, s0, X2]        (q2: hl=1111, no arms)

Eliminate s1: gather its atom-0 self-loop, `w3` gives
`s1 ≈ (wh{0} a)·(ite{2} (b·s0) ({3}?·c))`.  The residual has TWO live
targets — s0 AND the exit X2 — so it is NOT a prefix times one
unknown.  Substituting into s0 puts s0 under guard `{2}` read AFTER
`d·(wh{0}a)` has executed, and no axiom moves a guard left past an
action.  Eliminate s0 instead: gather its atom-2 self-loop, `w3` gives
`s0 ≈ (wh{2} f)·(ite{0} (d·s1) (…{1}?e…{3}?g…))` — again a live exit
alongside the in-SCC target, and substituting into s1 fails the same
way.  **Both orders break left-affineness.**

This is the first CONCRETE, MEASURED instance of the hard shape, and
its signature is exactly what 117 predicted: **two ports, each with a
LIVE exit**, so no state's residual collapses to a prefix.  It is the
census-level realization of iteration 96's `wh b (ite c (p; test d) q)`
refutation.

**WHAT THIS MEANS.**  The residue is now a concrete, exhibited
automaton rather than a quantifier.  Three readings, and the ledger
should not prejudge between them:
1. A cleverer closing exists for two-port SCCs that this campaign has
   not found (the six strata each found one for their shape — chord in
   particular was two-position).
2. Two-port SCCs need genuinely more than one-unknown uniqueness, and
   this is the concrete seed of a negative result.
3. Two-port SCCs of CANONICAL QUOTIENTS OF LANGUAGE-EQUIVALENT PAIRS
   may be constrained in a way arbitrary two-port SCCs are not — the
   NA=2 sweep found ZERO of them in 30000 pairs, which is evidence
   this shape is rare and possibly structurally restricted.

**LITERATURE, and it settles the expressiveness worry definitively.**
The Böhm-Jacopini search returned: Kozen-Tseng's counterexample is a
3-state REDUCED automaton (no nontrivial autobisimulation), and by
their own Lemmas 1+5 **a quotient by a congruence is bisimilar to the
original, hence guarded-string-equal — so every quotient of a
while-program automaton IS equivalent to a while program, and the KT
automaton is NOT a bisimulation quotient of any program automaton.**
Böhm-Jacopini cannot bite a quotient-only construction at the level of
behavior.  117's addendum-2 claim is confirmed by the source itself.
Structurally quotients DO escape well-nestedness (ICALP'21 Fig. 4,
8 states, v₁≡v₄ / v₃≡v₆) — that is the published evidence that killed
the well-nestedness route, which this repo abandoned long ago.  Also:
the real characterization of expressible behavior is ICALP'21's
NESTING COEQUATION W (well-nestedness is sufficient, NOT necessary —
refuted there), and no decidability result for while-expressibility
appears to exist.

**NEXT**: attack OPEN-SCC #3 directly.  It is two states, four atoms,
fully written out above — small enough to settle by hand or by
exhaustive search over closing strategies.  Settling it either yields
the two-port closing (and with it, plausibly, the general method) or
produces the campaign's first genuine negative result.

## Iteration 119 — ★ THE TWO-PORT INSTANCE, SOLVED BY HAND — AND IT SAYS ELIMINATION IS THE WRONG TOOL ★

Extended the census dump to retain and print the GENERATING
EXPRESSIONS for each open instance (buckets now carry `(Aut, String)`,
pairs carry both source programs).  With the actual programs in hand,
OPEN-SCC #3 can be worked all the way through by hand.

**The instance, fully reduced.**  Exit target `X2` halts on every atom
with no arms, so `X2 ≈ test 1` and every `p·X2 ≈ p`.  Writing atoms
α0..α3:

    s0 ≈ [α0] p·s1 + [α1] p + [α2] p·s0 + [α3] p
    s1 ≈ [α0] p·s1 + [α2] p·s0 + [α3] p          (rejects α1)

Gather s1's α0 self-loop and close by `w3`:
`s1 ≈ W·R` with `W := wh α0 p`, `R := ite α2 (p·s0) (ite α3 p 0)`.
Substituting into s0 and noticing that s0's tail below α1 IS `R`:

    s0 ≈ ite α0 (p·W·R) (ite α1 p R)
    s1 ≈ ite α0 (p·W·R) R              (w1-unroll of W·R, via u5)

**They differ ONLY in the α1 branch**, which yields a clean derived
relation worth recording in its own right:

    ★ s0 ≈ ite α1 p s1 ★

(check: α1 → p on both readings; α0 → p·W·R both; α2 → p·s0 both;
α3 → p both).  So the two members of a two-port SCC differ by a single
GUARDED PATCH — one atom's worth of behaviour.  If that generalizes,
two-port SCC members are never far apart, which is a structural handle
the campaign has not had.

**And now the obstruction, in its sharpest possible form.**
Substituting back gives a SINGLE-UNKNOWN equation:

    s0 ≈ ite α1 p ( W · ( ite α2 (p·s0) (α3?·p) ) )

One unknown, one occurrence, everything else closed.  And `w3` still
cannot close it — because `w3` requires `x ≈ ite G (BODY·x) REST`, with
the exit REST at the TOP, whereas here the exit `α3?·p` is reached only
AFTER `W` has run.  **This is a loop with an exit in the middle of its
body.**  Not a multi-unknown problem at all — a single-unknown problem
outside `w3`'s shape.

That is the crispest statement of the residue the campaign has
produced: not "n unknowns need n-ary uniqueness", but **"one unknown
can already sit outside unary uniqueness's shape, because GKAT's loop
construct has exactly one exit and its guard is read at the top."**

**THE STRATEGIC CONCLUSION, and it redirects the campaign.**  The
language of this instance IS expressible — the harness printed the two
source programs that generate it (both are `wh`-programs over two
tests; recorded in the dump).  So a solution EXISTS as syntax; what
fails is reaching it BY ELIMINATION.  Since `sum_solves_std`
(iteration 114) already proves the solution exists and exhibits it as
the canonical labelling, and `sum_solution_rigid` pins every solution
to that one class, **the elimination route is strictly weaker than the
unification route here**: elimination tries to CONSTRUCT what
canonicity already HANDS us.

So iteration 116's correction ("the RoleCovered route is alive") should
be sharpened once more: the role/schedule route is alive but is NOT the
one that closes two-port SCCs.  For those, the move is to stop
constructing and start transporting — use `ParametricCanonicalBA` on
the SOURCE programs together with the subsystem lemmas, which is
exactly the machinery iterations 100-111 built and 114-116 sharpened.

**Revised residue.**  Prove UNIF at in-class arm targets
(`unif_of_wf_mod_cycles`' remaining hypothesis) for two-port SCCs, via
per-side canonicity rather than elimination.  The derived patch
relation `s0 ≈ ite α1 p s1` suggests the shape of the argument: within
a class, members differ by guarded patches on atoms where one side
halts and the other rejects, and `bisim_hlt_invariant` already says
bisimilar states agree on halting — so the patches must be
reconstructible from the bisimulation itself.

## Iteration 120 — ★ THE GUARDED PATCH LEMMA ★ (zero axioms)

Iteration 119's hand derivation `s0 ≈ ite α1 p s1` is now a GENERAL
THEOREM, not a per-instance trick.  Three new results, **all zero
axioms** — no choice, no propext, no Quot.sound:

* **`patch_of_common_tail`** — if `X ≈ ite G Px Q` and `Y ≈ ite G Py Q`
  (same guard, same tail), then `X ≈ ite G Px Y`.  Proof: `ite_c` with
  hY, then `ite_else_restrict` at `G/G`, then `ite_guard` collapses
  `¬G ∧ G` to `0`, then `ite_zero`.  Four moves.
* `patch_symm` — the relation holds both ways: each side is the other
  patched at `G`.
* **`dispatch_patch`** — the automaton-level form: two states whose
  dispatch lists share a common SUFFIX, whose leading guards agree, and
  whose halts agree, satisfy `sol u ≈ ite g (a·sol t) (sol v)` under
  ANY solution.  Exactly iteration 119's relation, for arbitrary
  automata.

**Why this matters.**  A patch relation costs NOTHING: no uniqueness,
no productivity side condition, no elimination, no rank.  It relates
two members of an SCC DIRECTLY.  That is precisely the currency the
unification route trades in and the elimination route cannot use —
elimination needs `prefix · unknown` shapes, whereas a patch is
`ite G (something) unknown`, which is a dispatch arm, not a product.

Both measured two-port SCCs (118, 119) have the patch shape: their two
classes' dispatches agree except at ONE atom.  With `dispatch_patch`
that agreement is now mechanically convertible into an `EquivBA` fact
relating the two classes' labels, for free, in any instance where the
dispatches line up.

**Honest scope.**  This does NOT close two-port SCCs.  It converts one
observed regularity into a reusable theorem, and it supplies exactly
the kind of cheap inter-class relation the unification route needs.
What is still missing is the step FROM patch relations TO UNIF: a
patch says how two classes differ, not that a raw state agrees with
its representative.  The bridge would be: patches compose along a
bisimulation, and `bisim_hlt_invariant` already forces bisimilar states
to agree on halting, so the guard region of a patch between bisimilar
states should be provably empty — collapsing the patch to plain
equality.  That is the next concrete target, and it is now a statement
about `dispatch_patch`'s `g`, not about elimination at all.

## Iteration 121 — ★ THE LOOP-STATE SOLUTION IS FORCED ★ + a correction to 120's stated target

**FIRST, THE CORRECTION.**  Iteration 120 ended by proposing: "the
guard region of a patch between BISIMILAR states should be provably
empty, collapsing the patch to equality."  Checked before spending an
iteration on it — **it is confused, on two counts.**

* `dispatch_patch`'s hypothesis is that the two states share a LITERAL
  common suffix of their dispatch lists (same list, hence the same
  target states).  Bisimilar states in general share no such suffix;
  their targets are bisimilar-but-DIFFERENT.  So `dispatch_patch` does
  not even apply to the bisimilar case.
* And for bisimilar `u, v` the difference is not a guard region at all.
  By `bisim_hlt_invariant` they already agree on halting, and at every
  atom they either both reject, both halt, or both do the SAME action
  to bisimilar targets.  The gap is entirely "different targets that
  ought to have equal labels" — which is `equation_transport`, i.e.
  UNIF itself, not a guard to be emptied.

So the patch lemma relates DISTINCT CLASSES inside one SCC (which is
what both measured instances have), not bisimilar states.  Recorded
because a wrong next-target is exactly the kind of thing this ledger
exists to catch early; three iterations in a row (112, 114, 120) have
now proposed a step that dissolved on contact, and the pattern is
always the same — reasoning about machinery instead of running it.

**WHAT THE PATCH ACTUALLY BUYS, restated.**  In the 119 instance,
`s0 ≈ ite α1 p s1` expresses s0 with NO occurrence of s0 on the right.
That IS an elimination — it performs the n→1 reduction the literature
reports as missing, for free, with no productivity condition.  So the
"no general method to go from n+1 unknowns to n" is answered whenever
dispatches share a suffix.  **The obstruction was never the n→1 step.
It is the FINAL 1-unknown closing**, which 119 showed lands outside
`w3`'s shape.

**SECOND, THE THEOREMS** (both [propext], first try):

* **`loop_solution_canonical`** — every state inside a Thompson loop
  has its solution FORCED to `bodyStd s · (the loop's own re-entry
  dispatch)`, for ANY ambient continuation `F`.  Proof is two lines:
  feed `hsol` through `loop_subsystem` to reindex the ambient equation
  as the BODY's parametric equation at finish := the loop's own init
  dispatch, then apply the body's `ParametricCanonicalBA`.
* **`loop_solutions_agree`** — two parametric solutions of a loop agree
  at every body state, given only that their re-entry dispatches agree.
  **This is n-unknown uniqueness for a Thompson loop, with no UA** —
  delivered by canonicity alone.

**WHY THIS IS THE RIGHT SHAPE.**  Decoding the source programs the
harness printed in 118-119 shows what the actual solution of a two-port
SCC looks like: not a freshly constructed `wh`, but **the ORIGINAL
program's loop, re-used** — `(body residual) · (the loop's re-entry)`.
Elimination would have to INVENT that `wh` from the quotient's arms;
canonicity HANDS IT OVER, because the quotient's SCC is (by
`loop_subsystem`) the body system with a feedback finish.  That is the
concrete mechanism behind 119's conclusion that unification strictly
dominates elimination, and `loop_solution_canonical` is that mechanism
stated as a theorem.

**RESIDUE.**  `loop_solutions_agree` needs the two re-entry dispatches
to agree — and those are built from the solutions themselves, so this
is the same fixpoint, now localized to ONE expression per loop instead
of one per state.  That is a genuine narrowing: the unknown is no
longer "does every state agree with its representative" but "do the two
sides' loop RE-ENTRY DISPATCHES agree", a single `EquivBA` obligation
per loop.  Next: discharge it from bisimilarity of the loop headers,
where `equation_transport` applies to ONE pair rather than to every
in-class arm target.

### Iteration 121 addendum — ★ ELIMINATION IS PROVABLY IMPOSSIBLE IN GENERAL — the redirect is now forced, not chosen ★

The loop-with-mid-exit search returned the most decisive strategic
result of the campaign.

**(a) Loop rotation IS valid and IS already in this repo.**
`loop {A; if h break; B} ≡ A; while ¬h do (B; A)` is propositionally
valid, W1-derivable, pure code duplication, NO auxiliary Boolean.  This
repo already has it: `GkatResidueFamily.loop_rotation`.  Adjacent tests
also merge — KT note Kosaraju's own Fig. 2 counterexample collapses to
`while b·c do p` once Boolean combinations of tests are allowed.  **The
merge fails exactly when an ACTION separates the two tests**, which is
precisely iteration 119's shape (`W` and `q` separate `g` and `h`).  So
rotation is a real tool, and it is exactly one notch short of the
residue.

**(b) THE DECISIVE FACT.**  Smolka et al., GKAT (POPL 2020),
**Remark 6.1**: it would be **UNSOUND to assume that left-affine systems
with n ≥ 2 unknowns have solutions at all**.  Only n = 1
(`x = e·x +_b d`) has guaranteed existence, via W1.  Their
counterexample is precisely Kozen-Tseng's system.  And a KT-style
argument on iteration 119's own two-state shape
(`x = W·y +_¬g p`, `y = q·x +_h r`) shows it has NO while program when
`p, w, q, r` are distinct and `g, h` independent: after `r` the body
must fall through to the top test, and no choice of loop guard
reproduces "halt now" versus "iterate".

**(c) THEREFORE THE ELIMINATION ROUTE CANNOT EXIST.**  Not "has not
been found" — CANNOT.  A general elimination method would have to solve
arbitrary n ≥ 2 left-affine systems, and those systems provably need
not have solutions.  Any method that always succeeds is therefore
refuted outright.  This closes the route that iterations 73-96 built
and that 117 proved a conditional step for — `elim_reduces` remains
correct and useful, but its uniform-exit side condition is now known to
be ESSENTIAL rather than an artifact of not trying hard enough.

**(d) AND IT FORCES THE REMAINING ROUTE.**  Iteration 118's search
established (Kozen-Tseng Lemmas 1+5) that a quotient by a congruence is
bisimilar to the original, hence guarded-string-equal — so **every
quotient of a program automaton DOES have a solution**.  Put beside (b):
the systems this campaign must solve sit in a STRICTLY SMALLER class
than "arbitrary left-affine systems", and the ONLY thing that can
distinguish them is their PROGRAM ORIGIN.  So any successful method
must consume program-origin, and cannot be a general system-solving
procedure.  That is exactly `loop_solution_canonical` (iteration 121):
the solution is the ORIGINAL loop re-used, handed over by canonicity,
never constructed from the quotient's arms.

Iterations 119 and 121 redirected to unification on the strength of one
worked instance.  That redirect is now **forced by a published
impossibility result**, not chosen on taste.  The campaign is on the
only route that can work.

**(e) Criterion, for the eventual hardening.**  The exact
characterization of while-expressible behaviour is NOT well-nestedness
(Schmid-Kappé-Kozen-Silva ICALP'21 Fig. 4: well-nested automata are not
closed under homomorphism, so it is sufficient but not necessary) but
the **nesting coequation W** (their Prop. 6.2: W = the set of GKAT
program behaviours).  Any claim this campaign makes about "which
automata are expressible" must be phrased against W, not
well-nestedness.

**Net effect on the residue.**  Unchanged in content, sharpened in
status: discharge the per-loop re-entry agreement of
`loop_solutions_agree` from bisimilarity of the loop headers.  What
changed is that no alternative route remains to hedge with.

## Iteration 122 — ★ THE RE-ENTRY FIXPOINT DISSOLVES ★ (an inductive engine)

Iteration 121 closed with the residue "discharge the per-loop re-entry
agreement of `loop_solutions_agree`", noting the re-entry dispatches
are built from the solutions themselves, so the fixpoint remained —
merely localized to one expression per loop.  **It is not a fixpoint at
all.**  Three new theorems:

* **`reentry_agree_of_finish`** (ZERO axioms) — two solutions' re-entry
  dispatches agree whenever their ambient continuations do.  The proof
  is three links, and the whole trick is that `ParametricInitialBA` —
  sitting in every certificate since long before this campaign —
  ALREADY EVALUATES a re-entry dispatch: for ANY parametric solution it
  equals `program · finish`.  Feed both solutions through it and the
  self-reference is gone; only `F₁ ≈ F₂` remains.
* **`loop_solutions_agree_of_finish`** [propext] — **THE INDUCTIVE
  ENGINE**: two parametric solutions of a Thompson loop agree at EVERY
  body state as soon as their ambient continuations agree.  No
  uniqueness axiom, no re-entry bookkeeping, no fixpoint.
* `loop_solution_closed` [propext] — the closed form named outright:
  any parametric solution at `F` is pinned to
  `bodyStd s · (loopProgram · F)`, re-entry already evaluated.

**Why this is the advance it looks like.**  Every previous formulation
of the residue was self-referential in the way UA exists to discharge —
that is what made the problem hard and what the field's pessimism is
about.  `reentry_agree_of_finish` removes the self-reference from the
loop case outright, using a fact the repo has had all along.  What
replaces it is a straightforward implication: **agreement propagates
INWARD**, from a program's outside toward its innermost loop states.
That is an induction on nesting depth, not a fixpoint.

**Honest scope, and it is a real limit.**  `loop_solutions_agree_of_
finish` compares two solutions of the SAME loop — same guard, same
body.  UNIF needs to compare `e`'s loop with `f`'s loop, which are
DIFFERENT automata, and canonicity cannot bridge two different
automata by itself.  So this discharges the SAME-SIDE half.

**The decomposition this suggests, recorded but NOT yet verified**
(three proposed next-targets in a row have dissolved on contact, so
this is flagged as a conjecture to test, not a plan to execute):
cross-side UNIF may reduce to SAME-SIDE UNIF plus a partner map.
Sketch: define `sol_f(u) := std_e(partner u)` for `f`-states `u`; if
that is a `ParamSolvesBA` of `f`'s core at finish 1, canonicity forces
`std_e(partner u) ≈ std_f(u)`, which IS cross-side UNIF.  Checking the
`ParamSolvesBA` obligation, bisimilarity matches `u`'s arms with
`partner u`'s arms at the same actions and bisimilar targets, and the
residual gap is `std_e(t_e) ≈ std_e(partner t_f)` for two BISIMILAR
`e`-STATES — i.e. same-side UNIF within `e` alone.  If that holds, the
cross-side problem is strictly reducible to a one-program problem,
where full structural induction on syntax is available because
`certifiedThompson` is defined by recursion on the program.

**Known obstruction to that sketch, stated up front**: dead states.
`partner` exists for reachable states (`sreach_partner`) but a dead
`f`-state need not have a bisimilar `e`-partner, and `ParamSolvesBA`
quantifies over ALL listed states.  Dead targets of live states would
force comparing `std_e(dead)` with `std_f(dead)`, which is the
`dead_thompson_label_eq_zero_of_complete` circularity.  Trimming is the
usual answer but `ParametricCanonicalBA` speaks about the RAW core, not
the trim.  So the sketch is not yet a route — it is a candidate whose
one known gap is already identified.

**Next**: test the sketch's same-side lemma directly — do bisimilar
states of ONE program's Thompson automaton have provably equal standard
labels?  Small enough to settle, and it is the load-bearing half.

### Iteration 122 addendum — the same-side conjecture, tested against the literature (and against itself)

The same-side search returned three things that change the assessment
of 122's own conjecture — one encouraging, one cautionary, one that
nearly kills it and then does not.

**(a) Same-side bisimilarity is REAL, and its canonical cause is
harmless.**  Position/Thompson automata are famously NOT reduced
(Ilie-Yu; Champarnaud-Ziadi; Maia-Moreira-Reis CIAA 2014 — partial
derivative automata are exactly quotients of position automata BY
BISIMULATIONS).  Distinct states of ONE expression's automaton can be
bisimilar, and the canonical cause is duplicated/shared subterms, e.g.
`ite c p p`.  But note what that costs HERE: `ite c p p` builds
`sumGSystem` of p's system with p's system, so the two bisimilar states
are `inl s` and `inr s` and their standard labels are both p's standard
at `s` — **literally the same expression**.  For the canonical cause,
same-side UNIF is syntactic identity, free.

**(b) No published no-collapse theorem, and no
bisimilar-implies-provably-equal theorem.**  Brzozowski's finiteness is
modulo ACI — a FIXED NORMALIZATION and a syntactic-identity criterion,
not "bisimilar residuals are provably equal from the axioms".  For GKAT
specifically, Antimirov-style derivatives underpin the decision
procedure, but nothing of the form this campaign needs exists.

**(c) THE DECOMPOSITION IS NOVEL — and it is CIRCULAR unless the
induction is on SIZE.**  The search found no precedent for
"same-expression bisimilarity ⟹ provable label equality, then bootstrap
to two expressions via a partner map"; published routes go through
disjoint union + bisimulation collapse + solvability of the collapse
(Smolka et al., ProbGKAT, Weighted GKAT), and Grabmayer-Fokkink work
chart-globally.  Novelty is good news; but testing the conjecture
against ITSELF exposes the catch: **same-side UNIF EMBEDS cross-side
UNIF.**  Take `ite c (p;q) (p;q')` with `q ≈ q'` semantically but
syntactically different — its two branch states are bisimilar, and
their labels are `q·rest` and `q'·rest`, so proving same-side UNIF
there IS proving `q ≈ q'`, an arbitrary cross-side instance.  So
same-side and cross-side are MUTUALLY REDUCIBLE and neither is
"simpler" outright.

**What saves it is exactly what iteration 108 proposed and could not
then justify: induct on SIZE.**  The embedded instance `(q, q')` lives
in strictly smaller subterms of `P`, and the reduction runs
cross-side`(e,f)` → same-side`(e)`, where `|e| < |e| + |f|`.  So the
two reductions descend in `|e| + |f|` in opposite directions and the
induction is plausibly well-founded.  Iteration 108 reached this
structure by intuition and 112-114 abandoned it; it is now re-derived
from a mechanism (partner maps + canonicity) rather than a hunch, and
122's inductive engine — agreement propagates inward — is the tool it
was missing.

**Status: a candidate route with TWO known gaps, both named** — dead
states (no guaranteed partner; `ParametricCanonicalBA` is about the raw
core, not the trim) and the size-induction bookkeeping (the two
reductions must be shown to descend together).  Not yet a plan.  Next
iteration should test the smallest nontrivial same-side case in Lean
rather than reason about it further.

## Iteration 123 — ★ THE PARTNER RETRACTION THEOREM ★ — the decomposition is proved

Iteration 122 recorded a conjecture and flagged it as "to test, not to
execute".  Tested, and it holds.  Three theorems:

* **`partner_class_consistent`** (ZERO axioms) — a partner-retracted
  family `sol ∘ π` is class-consistent, given same-side UNIF on the
  retract.  Pure transitivity: `u ~ v` gives `π u ~ u ~ v ~ π v` with
  both partners inside `S₀`.
* **`solves_of_partner`** — **if `S₀` is closed under arms, `π`
  retracts every state onto a bisimilar element of `S₀` and fixes `S₀`,
  `sol` solves on `S₀`, and same-side UNIF holds on `S₀`, then
  `sol ∘ π` solves the WHOLE automaton.**
* **`cross_unif_of_same_side`** — on the Thompson sum: with a total
  partner map onto the left side, same-side UNIF there forces every
  right-side internal state's canonical label to equal its partner's.
  **Cross-side UNIF from same-side UNIF.**

**The mechanism, and why it escapes the usual circularity.**  Three
links.  At `π u` the family `sol ∘ π` agrees with `sol` **literally,
not up to `EquivBA`** — because `S₀` is arm-closed and `π` fixes `S₀`,
so every arm target of `π u` is already a fixed point.  No UNIF is
needed to rewrite the equation there; it is an equality, discharged by
`eqRHS_congr`.  Then `equation_transport` carries the equation from
`π u` to `u`, legitimate because `sol ∘ π` is class-consistent, and
that comes from same-side UNIF alone.  Same-side UNIF is the ONLY new
input; everything else is structure the repo already had.

**LITERATURE CHECK, and it sharpens the claim.**  "Solve the target,
pull back along π" is precedented and load-bearing: a map with
`u ∼ π(u)` respecting transitions is a **functional bisimulation**
(coalgebra homomorphism; p-morphism / bounded morphism / zig-zag
morphism in modal logic), and solution-transfer along one is a
workhorse of Grabmayer-Fokkink's 1-free completeness (LICS 2020) and
Grabmayer's full Milner completeness (LICS 2022).  What has NO
precedent is retracting onto ONE SIDE rather than onto the collapse.

And the search names the reason: **π : A+B → A can only be a functional
bisimulation if A is already its own collapse** — no two distinct
bisimilar reachable states.  That would make the technique a special
case, inheriting the same side condition.

**But `solves_of_partner` does NOT require π to be a functional
bisimulation.**  It never asks π to commute with transitions — only
that `u ~ π u`, that π fixes `S₀`, and that `S₀` is arm-closed.  The
collapsedness requirement is replaced by `hsame`: instead of FORBIDDING
A from having distinct bisimilar states, we handle them ALGEBRAICALLY,
by requiring their labels to be provably equal.  That is exactly the
same-side UNIF hypothesis, and it is why the retraction works on a
non-collapsed A.  So the technique is a genuine variant of the
precedented one, with the side condition traded for a proof obligation
— which is the trade this whole campaign is about.

**REMAINING GAPS, both already named and neither closed.**
1. **The partner map.**  `cross_unif_of_same_side` takes π as a
   hypothesis.  `sreach_partner` supplies partners for REACHABLE states
   under ULE; dead and unreachable states need not have one, and the
   arm-closure/fixing conditions must be checked for whatever π is
   built.  This is the dead-state gap in its current form.
2. **Same-side UNIF itself.**  Now the sole mathematical input.  Per
   122's addendum it EMBEDS cross-side UNIF (`ite c (p;q) (p;q')`), so
   it is not simpler outright — the induction must be on SIZE, with
   cross-side`(e,f)` → same-side`(e)` descending because
   `|e| < |e| + |f|`, and same-side`(P)` → cross-side on strictly
   smaller subterms.

The route is now three named pieces: partner construction, same-side
UNIF, and the size induction that ties them.  All three are stated;
none is hand-waved; two are open.

## Iteration 124 — the size-induction interface, and the dead-state gap gets an answer from the literature

**Six new lemmas** (all `rfl`, [propext, Quot.sound] from the ambient
`certifiedThompson` definitions) giving the structural interface the
size induction on same-side UNIF needs:

* `ite_standard_inl` / `ite_standard_inr` — an `ite`'s branches keep
  their own subprogram's labels, verbatim.
* `seq_standard_inl` — a `seq`'s left factor's label is its own label
  followed by the right program.
* `wh_standard` — **and here the naive statement is FALSE.**  A loop
  adds no states, so `standard s = bodyStandard s` looks right; it is
  NOT definitional and does not hold.  The truth is
  `standard s = bodyStandard s · (wh g b)` — the feedback shows up in
  the LABELLING, not only in the arms.  Worth having found by building
  it rather than assuming it; a size induction that assumed the naive
  form would have silently mis-stated its own inductive hypothesis.
* **`dup_branch_standard_eq` / `dup_branch_unif`** — the two branches of
  a DUPLICATED conditional `ite c p p` carry LITERALLY EQUAL labels, so
  same-side UNIF there is `rfl`.  The literature names duplicated
  subterms as the canonical cause of distinct-but-bisimilar states in
  one expression's automaton (position automata are non-reduced;
  partial-derivative automata are their bisimulation quotients).  For
  standard labels that cause costs nothing.  The canonical case of the
  remaining input is discharged.

**THE DEAD-STATE GAP — the literature's verdict, and it is useful.**
Searched for whether a labelling on the accessible/live part extends to
the whole automaton.  Answer: **no clean extension theorem exists, and
none is expected.**  In coalgebra the canonical normalization is
simple-quotient-then-least-subcoalgebra, yielding a WELL-POINTED
coalgebra (Adámek-Milius-Moss-Sousa) — and the accessible part is a
CORREFLECTION, so a labelling on `Reach(B)` is unique but does NOT
canonically extend to `B`.  Extension is a genuine extra obligation,
not a functorial freebie.

And GKAT/KAT proofs never prove "dead ⟹ labelled 0" by extension —
they NORMALIZE IT AWAY: dead states are found by a separate backward
reachability pass and their incoming arms rewritten to immediate
rejection, so the labelling is only ever defined on a trimmed automaton
whose language semantics is provably unchanged.  **That is what breaks
the circularity**, and it is exactly what this repo's `trimAut` /
`solvesBA_untrim` already do.

**Consequence for the route.**  The recommendation is explicit: if the
surrounding argument needs the untrimmed automaton, do NOT extend the
labelling — prove a TRANSPORT lemma instead and reformulate over
trimmed automata only.  This repo currently has the tension in exactly
that shape: `ParametricCanonicalBA` speaks about the RAW Thompson core,
while bisimilarity and the partner map live on `trimAut`.  So the
partner gap (iteration 123's gap 1) is not a hole to be plugged by
cleverness — it is a signal that the canonicity interface should be
re-based onto the trim.  That is a concrete, bounded engineering task
on machinery that already exists, not a new mathematical unknown.

**Route status.**  Three named pieces: (1) partner construction — now
understood as "re-base canonicity onto the trim", with `solvesBA_untrim`
as the existing half; (2) same-side UNIF — canonical cause discharged
today, general case open; (3) the size induction — its structural
interface now exists, with `wh_standard` correcting the shape of the
loop case before it could mislead.

## Iteration 125 — ★ THE RAW/TRIM SCISSORS, AND THE ONE HYPOTHESIS THAT CLOSES THEM ★

Acting on 124's literature verdict ("don't extend a labelling from the
live part — normalize the dead part away and work on the trim"), making
it concrete exposes the gap in its sharpest form yet.  It is a pair of
scissors:

* on the **RAW** sum we have SOLVING (`sum_solves_std`, iteration 114)
  — but the bisimilarity `ULE` hands us is about `trimAut`
  (`ule_iff_start_bisim`);
* on the **TRIM** we have BISIMILARITY — but not solving, because
  `solvesBA_untrim` runs trim → raw and the reverse needs dead labels
  to collapse.

`equation_transport` and the partner retraction (`solves_of_partner`)
need BOTH at once, on ONE automaton.  Neither side of the scissors has
both.  That, precisely, is what the "dead-state gap" has been all along
— stated here for the first time as a property of two automata rather
than as a vague obstruction.

**`solvesBA_trim_of_dead`** closes them from a single named hypothesis:
a solution of the RAW system whose DEAD states carry provably-zero
labels **also solves the TRIM**.  It is the exact converse of
`solvesBA_untrim`, with the dead-label collapse supplied as an input
rather than extracted from a trim solution; the proof mirrors
`solvesBA_untrim`'s chain (`not_zero_strip` / `trim_fold_equiv` /
`not_zero_strip`) with `hdead` fed in directly.

**So the entire remaining dependency is now ONE named obligation:**

    dead Thompson states carry provably-zero standard labels
      ∀ t, ¬ Live aut t → EquivBA (stdSum t) (test 0)

which is verbatim what `dead_thompson_label_eq_zero_of_complete`
already warns "any successful pruning proof must establish directly for
Thompson labels".  The repo has been circling this since long before
this campaign; it is now isolated as the single input to a mechanism
that is otherwise complete.

**Is it tractable?**  Genuinely unclear, and worth not overselling.
Points for: it is a NULL-language special case, not full completeness,
and the repo already proves the hardest-looking instance —
`productive_while_true_eq_zero` kills a productive `while 1 do p`, whose
language is empty for non-termination reasons.  `certifiedThompson_
state_empty_iff` and `uniformExpLempty_iff_zero` already connect dead
states to empty labels.  Points against: emptiness of a GKAT product
`X·Y` is not "some factor is empty" — it can arise from the last atom of
every `X`-string starting no `Y`-string — so a structural induction has
real cases to discharge, and nothing in the repo currently does that.

**Route status, all three pieces now named and none hand-waved:**
1. **Dead labels are zero** — sole input to `solvesBA_trim_of_dead`;
   isolated today; tractability open.
2. **Same-side UNIF** — canonical cause (duplicated subterms)
   discharged in 124; general case open, needs the size induction.
3. **The size induction** — structural interface built in 124, with the
   loop case corrected.

## Iteration 126 — ★ THE LAST DEPENDENCY WAS ALREADY HALF-BUILT — it is S0, not a new problem ★

Went to attack 125's isolated obligation (dead Thompson labels are
provably zero) and first traced whether the repo had anything pointed
at it.  It has a great deal, and the assessment changes materially.

**`GkatNormalizationProofs.lean` was built for exactly this.**  Its own
docstring: `outG g e` is "the OUTPUT GUARD of `g?·e` — the tightest test
its accepted strings' last atoms satisfy", and `outG_emits` "lets
emptiness propagate through `seq` (the continuation's input guard is the
head's output guard), which is exactly what pruning and, **later,
Thompson silent-freeness** need."  That is verbatim the crux case I
identified: `X · test b ≈ 0` when `X`'s output atoms all falsify `b`.
With `outG_emits` it is three moves — insert the output guard, conjoin,
`s3`.

And the file goes further than its own docstring claims (which warns
pruning "does not descend into loop bodies"):

* `outG_emits` — THE EMISSION THEOREM, unconditional for EVERY GKAT
  program.
* `prune_equiv` / **`prune_equiv_top`** — THE PRUNING THEOREM,
  `e ≡ prune 1 e`, unconditional for EVERY GKAT program.
* `guardedness_normalization` — every loop body may be replaced by a
  strictly productive one.
* `wh_emits_exit_all` — every loop provably emits its exit guard, NO
  productivity hypothesis.
* `wh_prune_body` — pruning DOES descend through loop bodies (the
  docstring caveat is stale).

**So the algebra half of the obligation is DONE and unconditional.**

**And the remaining half is `NormalizationBridge` — S0, a hypothesis
this repo named years ago.**  `NormalizationBridge : ∀ e, ∃ e',
EquivBA e e' ∧ LiveSteps (certifiedThompson e').aut.toGAut`.  The
witness is `prune 1 e`; `prune_equiv_top` already gives the `EquivBA`
half unconditionally.  What is missing is purely automaton-level: that a
PRUNED program's Thompson automaton has live steps.

**Why that discharges 125's obligation outright.**  `solvesBA_trim_of_
dead` needs dead labels to vanish only where they are USED — at the
targets of arms.  So today's **`solvesBA_trim_of_dead_arms`** restates
it in the per-arm form: only dead targets of arms matter, unreachable
dead states in the carrier are irrelevant.  Under `LiveSteps` every
firing step lands on a live state, so that hypothesis is discharged
(modulo never-firing arms, whose guards are empty and which die by
`guard_zero_test`).  `sum_liveSteps` already lifts liveness from both
sides to the sum.

**Net: the last dependency is not a new mathematical problem.**  It is
S0, the oldest named hypothesis in this programme, whose ALGEBRA is
finished and whose remaining content is the structural fact that
pruning yields silent-free Thompson automata.  That is a bounded
automaton-level induction over `prune`'s own recursion, against
machinery (`outG`, `prune`, `wh_prune_body`) that already exists.

**Route status — three pieces, all named, none hand-waved:**
1. **S0 / `NormalizationBridge`** — algebra done (`prune_equiv_top`);
   remaining: pruned ⟹ `LiveSteps`.  Bounded, structural.
2. **Same-side UNIF** — canonical cause discharged (124); general case
   open, needs the size induction.
3. **The size induction** — interface built (124), loop case corrected.

Honest caveat: (2) remains the genuinely open mathematics.  (1) moving
from "unknown difficulty" to "known shape, existing machinery" is real
but it is the piece the repo was always going to have to finish anyway.

## Iteration 127 — the same-side induction: assembly is FREE, all content is BISIMILARITY TRANSFER

Four new lemmas, each a single congruence step on top of iteration
124's label projections:

* `wh_same_side_step` — body-label agreement lifts to the loop
  (`std = bodyStd · (wh g b)`, so one `seq_c`).
* `ite_same_side_inl_step` — same-branch agreement lifts verbatim.
* **`ite_same_side_cross_step`** — CROSS-branch: a same-side instance
  for `ite c p q` consumes a CROSS-side instance for `(p, q)`, on
  strictly smaller subprograms.  This is the descent that makes the
  size induction well-founded, and it is now a theorem rather than a
  remark.
* `seq_same_side_inl_step` — agreement lifts through the appended right
  program.

**The point is what they COST: nothing.**  Every constructor's label is
its subprogram's label placed in a fixed context, so agreement lifts by
one congruence.  The size induction's ASSEMBLY half is therefore free,
and that localizes the remaining difficulty exactly:

> **All remaining content of same-side UNIF is BISIMILARITY TRANSFER** —
> that two states bisimilar in a COMPOSITE's automaton are bisimilar in
> the SUBPROGRAM's automaton.

Per construction:
* **`ite` / sum** — immediate; the summands do not interact, and
  `autLang_sum_inl/inr` already give the language halves.
* **`seq`** — awkward: a left state's arms leave into the right
  automaton when the left halts, so composite-bisimilarity of two left
  states is not obviously left-bisimilarity.
* **`wh` — the real question.**  `loopInitialized` adds feedback arms
  that BOTH states must match, so loop-bisimilarity is a priori neither
  weaker nor stronger than body-bisimilarity.  The induction needs
  **loop ⟹ body**.  Plausible sketch: loop arms are body arms plus
  feedback decorated by `body.core.hlt`, and matching the feedback
  forces the halt guards to agree, after which the body arms must match
  on their own — but this is NOT yet checked, and per the standing
  lesson it is recorded as a sketch, not a step.

**Route status.**  Three pieces, all named:
1. **S0 / `NormalizationBridge`** — algebra done unconditionally
   (`prune_equiv_top`); remaining: pruned ⟹ `LiveSteps`.  Bounded.
2. **Same-side UNIF** — canonical cause discharged (124); assembly
   discharged (today); remaining content is exactly bisimilarity
   transfer, with `wh` the load-bearing case.
3. **The size induction** — interface and descent step now both exist.

The shape of the whole argument is now visible end to end, with one
genuinely open lemma (`wh` bisimilarity transfer) and one bounded
engineering task (S0).

### Iteration 127 addendum — the loop transfer direction we need is the EASY one

The bisimilarity-transfer search answered case (2) directly, and the
answer favours the induction.

**Standard results.**  (a) A coalgebra homomorphism preserves
bisimilarity, and an INJECTIVE one (subcoalgebra inclusion) also
REFLECTS it — so whenever the subautomaton is a genuine subcoalgebra,
transfer is free both ways.  Coproducts of coalgebras are disjoint with
mono injections.  (b) Thompson-style operators are definable by a
distributive law (GSOS format), and bisimilarity is then automatically a
CONGRUENCE for them — the general "congruence for automaton
constructions" result.

**Per case:**
* **Sum / `ite`** — trivial, as expected: each summand is a subcoalgebra
  of the disjoint union, so bisimilarity is preserved AND reflected.
* **Loop** — no clean citable lemma, because the body is NOT a
  subcoalgebra of the loop (feedback arms leave it).  But the two
  directions split, and **the one this induction needs is the easy
  one**: *loop-bisimilar ⟹ body-bisimilar by RESTRICTION* — body
  transitions are contained in loop transitions, so the extra feedback
  arms only ADD constraints.  The direction that requires a uniform-exit
  hypothesis is body-bisimilar ⟹ loop-bisimilar, which the induction
  does NOT use.
* **Concat** — same argument under the same condition.

**So the load-bearing case is de-risked**, and this is the first time in
the campaign that a needed direction turned out to be the cheap one
rather than the expensive one.

**One complication this repo has that the generic statement does not**,
recorded so the eventual proof does not assume it away: `loopInitialized`
does not merely ADD arms, it also REWRITES the halt —
`core.hlt state = body.core.hlt state ∧ ¬guard`.  So the body is not a
sub-coalgebra even up to added transitions, and "restriction" is not
literally available.  Loop-bisimilarity gives halt agreement only where
`¬guard`; where `guard` holds, a body state that halts takes a FEEDBACK
arm while one that does not takes a body arm or rejects, and matching
those forces the body halts to agree anyway.  That is the argument to
write, and it is a genuine argument rather than a restriction — but it
is bounded and the shape is now known.

**Route status, unchanged in structure and better in confidence:**
1. S0 / `NormalizationBridge` — algebra done; pruned ⟹ `LiveSteps`
   remaining.  Bounded.
2. Same-side UNIF — canonical cause and assembly both discharged;
   remaining content is bisimilarity transfer, whose needed direction is
   now known to be the cheap one, with the halt-rewrite wrinkle named.
3. The size induction — interface and descent step both exist.

## Iteration 128 — ★ THE LOOP TRANSFER LEMMA IS FALSE — caught by counterexample before writing Lean ★

Iteration 127's addendum recorded, on the strength of a literature
answer, that the direction the size induction needs — **loop-bisimilar
⟹ body-bisimilar** — holds "by restriction, since body transitions are
contained in loop transitions and the extra arms only add constraints".
Before writing it, constructed the argument concretely.  **It is false,
and the wrinkle 127 itself recorded is exactly why.**

**The counterexample.**  `loopInitialized` does not merely add arms; it
REWRITES the halt: `loop.hlt s = body.hlt s ∧ ¬guard`.  Take an atom α
with `guard α` true, and a body with

    body.initTrans : at α, action a → u
    s : body.hlt s = α,  body.trans s = []        (halts at α, no arms)
    t : body.hlt t = 0,  body.trans t = [(α, a, u)]  (steps a → u at α)

In the LOOP at α: `guard` holds, so `loop.hlt s = α ∧ ¬guard = false`
and `loop.hlt t = false` — both non-halting.  For `s`, halt-disjointness
means no body arm fires, so the FEEDBACK arm fires
(`body.hlt s ∧ guard ∧ tr.1` = true) giving `a → u`.  For `t`, the body
arm fires giving `a → u`.  **Identical observable behaviour: s and t are
LOOP-bisimilar.**  In the BODY at α, `s` halts and `t` does not — **NOT
body-bisimilar.**

So the composite's acceptance rewrite lets "halts, then re-enters via
init" be indistinguishable from "steps directly", and the two are only
merged INSIDE the loop.  The body is not a subcoalgebra, so reflection
genuinely fails; 127's citation described the transitions-only case.

**And the campaign does not need the lemma anyway — which the same
counterexample shows.**  What the induction actually needs is
`std_loop s ≈ std_loop t`, i.e. `bodyStd s · W ≈ bodyStd t · W` with
`W = wh g b`.  In the counterexample `bodyStd s ≉ bodyStd t` (one
accepts at α, the other does not) — yet the COMPOSITES are equal:
`bodyStd s · W` at α is `test α · W ≈ W`, which unrolls (`w1`, `guard`
true) to `initBody · W ≈ a · uStd · W`; and `bodyStd t · W` at α is
`a · uStd · W`.  **Equal.**  Composition with the loop merges precisely
what the loop-bisimulation merged.

**So `wh_same_side_step` (iteration 127) is TRUE but its hypothesis is
not always available**, and the loop case of same-side UNIF must not be
routed through body-label agreement.  The correct tool is the one
iterations 121-122 already built: `loop_solution_canonical` /
`loop_solutions_agree_of_finish`, which compare two solutions of the
SAME loop given agreeing continuations, and which work at the COMPOSITE
level where the merge actually happens.

**Process note.**  This is the fourth proposed next-step to dissolve
(112, 114, 120, 127) — but the first caught by CONSTRUCTING AN EXPLICIT
COUNTEREXAMPLE before writing any Lean, and the first where a literature
answer, not my own reasoning, was the thing that misled.  The citation
was about transitions-only constructions; this repo's loop rewrites
acceptance.  Lesson to carry: **a literature result must be checked
against THIS repo's actual definitions, not against the shape the
question was asked in.**

**Route status, corrected:**
1. S0 / `NormalizationBridge` — algebra done; pruned ⟹ `LiveSteps`
   remaining.  Bounded.  UNCHANGED.
2. Same-side UNIF — `ite`/sum case is genuinely trivial (summands ARE
   subcoalgebras).  `seq` and `wh` must go through composite-level
   canonicity, NOT through subprogram bisimilarity.  The 121-122
   machinery is the right tool and is already built; what is missing is
   the argument that the continuations agree.
3. The size induction — the descent (`ite_same_side_cross_step`) still
   holds; the `wh` rung needs re-planning around (2).

### Iteration 128 addendum — the counterexample is confirmed, and the honest weaker statement is exactly what the campaign needs

The follow-up search confirms 128's finding and corrects 127's citation.

* **Expected, not novel.**  Bisimilarity is PRESERVED by coalgebra
  homomorphisms and REFLECTED only along them.  The loop construction
  changes the OUTPUT MAP (acceptance) on body states, so
  `body ↪ loop` is not a G-coalgebra homomorphism and the body is not a
  subcoalgebra.  Reflection has no reason to hold, and the witness —
  accepting-at-α (takes the feedback arm) versus non-accepting with a
  body transition to the same target — is **the canonical shape of that
  failure**: the loop merges the two "next-step" mechanisms into one
  observation and discards the acceptance bit.
* **127's citation was over-general.**  Standard GKAT presentations
  (Smolka et al.; Schmid-Kappé-Kozen-Silva) are careful to state only
  that the construction preserves language/behavioural semantics and
  well-nestedness — **never that it reflects bisimilarity into the
  body.**  The earlier answer described the transitions-only case.
* **The direction that DOES hold is the other one**: body-bisimilar ⟹
  loop-bisimilar (the construction is functorial on the body's
  transition structure once the guard is fixed).  Note this is the
  reverse of what 127 claimed to need — and it is the one the induction
  cannot use.
* **★ The honest weaker statement is exactly the campaign's target ★**:
  loop-bisimilarity of `s, t` gives equality of their behaviour
  RELATIVE TO THE LOOP CONTEXT — the guarded languages
  `⟨s⟩·(b·⟨body⟩)*·b̄`-style continuations — i.e. precisely
  `bodyStd s · W ≈ bodyStd t · W` semantically, and NOT body-level trace
  equivalence.  "If you want body-level conclusions you must re-derive
  them, not reflect them."  That is the same conclusion 128 reached from
  the counterexample, arrived at independently: **work at the composite
  level, never at the body level.**
* **Reflection's actual side condition**, for the record: it holds when
  the construction only adds transitions on states already REJECTING
  under the loop guard — i.e. guard-disjointness / uniform exit, the
  same hypothesis family as the ring-witness stratum.  No paper isolates
  it as a named lemma.

**Net.**  The semantic fact the induction wants is true and is the
standard one; what is needed is its PROVABLE counterpart at the
composite level, which is exactly what `loop_solution_canonical` and
`loop_solutions_agree_of_finish` (iterations 121-122) speak about.  The
`wh` rung of the size induction should be built from those, with the
continuation-agreement obligation as its input — not from any
subprogram-bisimilarity reduction.

## Iteration 129 — the clean form S0 must deliver, and the `wh` rung re-planned

**`solvesBA_trim_of_all_live`**: with every LISTED arm pointing at a
live state, a solution of the raw system solves the trimmed one — no
dead-label obligation at all, the hypothesis of
`solvesBA_trim_of_dead_arms` simply going vacuous.  Three lines on top
of iteration 126.

**Why state it separately: it is STRICTLY STRONGER than `LiveSteps`,
and that distinction was about to be papered over.**  `LiveSteps`
constrains only FIRING steps — `autStep`, i.e. `firstMatch`.  This
constrains every arm in the LIST.  A SHADOWED arm (satisfiable guard,
always pre-empted by an earlier arm) can point at a dead state and never
fire, so `LiveSteps` alone does NOT discharge the hypothesis.  Iteration
126 wrote "under `LiveSteps` every firing step lands on a live state, so
that hypothesis is discharged (modulo never-firing arms…)" — the
parenthetical was doing real work and is now a named gap rather than an
aside.  **S0 must be aimed at no-dead-arm-targets, not at `LiveSteps`**,
or else at `LiveSteps` plus an argument that shadowed dead arms have
empty effective guards.

**The `wh` rung, re-planned after 128's refutation.**  The loop case
cannot go through body-label agreement (128's counterexample), so it
must be built at the composite level from iterations 121-122:
`loop_solution_canonical` pins every loop-state solution to
`bodyStd s · (loop re-entry)`, and `loop_solutions_agree_of_finish`
makes two solutions of the SAME loop agree once their ambient
continuations agree.  What that leaves is a genuine mismatch worth
stating plainly: **those theorems compare two SOLUTIONS, while same-side
UNIF compares two STATES of ONE solution.**  Converting between the two
would mean building a second solution family by swapping along the
bisimulation — which needs the equations to respect the swap, i.e.
UNIF.  Circular.

So the `wh` rung is NOT yet re-planned into a route; it is re-planned
into a precise obstruction: *two states of one solution, not two
solutions.*  That is the sharpest form the core difficulty has taken,
and it is the same circularity the campaign has been circling since
iteration 114, now localized to a single structural mismatch rather
than spread across the argument.

**Route status, honest:**
1. **S0** — algebra done; target corrected today to no-dead-arm-targets
   (stronger than `LiveSteps`).  Bounded but not yet done.
2. **Same-side UNIF** — `ite`/sum trivial; `seq` and `wh` need the
   composite level, where the two-solutions-vs-two-states mismatch is
   the open core.
3. **The size induction** — descent step holds; `wh` rung blocked on (2).

### Iteration 129 addendum — S0's remaining half is HARDER than iteration 126 judged

Searched whether "normalized expression ⟹ Thompson automaton has no
dead states" is known.  The answer downgrades iteration 126's
"bounded engineering task" assessment, and the reason is precise.

* **For CLASSICAL regular expressions it is folklore-easy.**  Reduce to
  a ∅-free expression (`0+e=e`, `0·e=0`, `0*=1`), and then every
  position is on some accepting path — reachability from First/Follow
  closure, co-reachability from Last/Follow, by routine structural
  induction.  Sakarovitch frames it via the standard automaton of a
  reduced expression.  **The subtlety is entirely in the ∅-elimination
  pass, not in trimness.**
* **For GKAT it is NOT published, and the reason is exactly this
  repo's situation.**  Kappé-Schmid-Silva (skip-free GKAT) Definition 14
  defines the dead set as a **GREATEST FIXPOINT over atoms** — "for all
  α ∈ At, `h(x)(α) = ⊥` or `h(x)(α) ∈ Σ × D`" — i.e. deadness is
  coinductive and atom-indexed, NOT a per-subterm property.  Their
  Definition 15 normalizes **on expressions** (`⌊e₁·e₂⌋ = 0` when `e₂`
  is dead) with Lemma 11 giving `e ≡ ⌊e⌋` — but they **never state that
  `⌊e⌋`'s automaton has no dead states.**  Normalization is used to
  redirect dead transitions to reject; deadness is decided
  semantically/coinductively rather than derived by induction.
  **"The atom-indexing is what blocks the naive induction."**
* **No formalization exists** of position-automaton trimness in any
  proof assistant (Coq/Isabelle regex work formalizes derivatives and
  equivalence checking, never trimness).

**Honest re-grading.**  Iteration 126 called S0's remainder "a bounded
structural induction over `prune`'s own recursion".  That was the
classical-regex intuition.  With tests, the property being inducted on
is a greatest fixpoint over atoms, which is precisely what defeats a
naive structural induction — and the closest published work
deliberately routes around it rather than proving it.  So S0's
remainder is **not** clearly bounded; it is a second open problem of
its own, smaller than the core but not free.

This also explains, retroactively, why `NormalizationBridge` has sat as
a HYPOTHESIS in this repo since long before this campaign while its
algebra half got finished: the algebra was tractable and the automaton
half is the part that resists.

**Route status, re-graded honestly:**
1. **S0** — algebra done unconditionally; automaton half now assessed as
   a second open problem (atom-indexed greatest fixpoint defeats naive
   induction), not bounded engineering.
2. **Same-side UNIF** — `ite`/sum trivial; `seq`/`wh` blocked on the
   two-states-vs-two-solutions mismatch (this iteration).
3. **Size induction** — descent holds; `wh` rung blocked on (2).

## Iteration 130 — ★ THE EMISSION SCISSORS ★ — S0 re-routed from states to labels

**`zero_of_emission_disjoint`** (ZERO axioms, first try): a product
`X·Y` whose left factor's OUTPUT guard is disjoint from its right
factor's INPUT guard is provably `0`.  Six moves — `s1`, `s6`,
`guard_zero_test`, `s2`, `s3` — no induction, no uniqueness, no
productivity side condition.

**Why this matters: it re-routes S0 around the thing that blocked it.**
Iteration 129 graded S0's automaton half as a second open problem
because deadness is an atom-indexed GREATEST FIXPOINT, which defeats
structural induction over STATES.  But the dead-label obligation can be
met from the LABEL side instead, and there the repo already holds half
the machinery: `outG_emits` proves `g?·e ≡ g?·(e·(outG g e)?)`
UNCONDITIONALLY for every GKAT program — every program provably emits
its output guard.

The obligation's hard case was always the product: `X·Y` empty though
neither factor is, because every `X`-string ends at an atom starting no
`Y`-string.  That is precisely guard-disjointness, and
`zero_of_emission_disjoint` closes it outright once both emissions are
available.

**So S0's automaton half converts into: build `inG`, the DUAL of
`outG`, with its admission theorem `Y ≡ (inG Y)?·Y`.**  That is a
structural induction on EXPRESSIONS — the exact shape that already
worked for `outG` — rather than one on an atom-indexed greatest fixpoint
over states.  A different and much better-understood problem.

**Not over-claiming, having done exactly that at iteration 126.**  Two
things are genuinely open in this re-routing:
1. **`inG` must be TIGHT, not merely sound.**  The reduction from
   "composite empty" to "guards disjoint" needs both `outG` and `inG` to
   be exact: if `α ∈ outG X` and `α ∈ inG Y` then the composite is
   nonempty, so emptiness gives disjointness — but only if neither
   over-approximates.  A sound-but-loose `inG` proves nothing here.
2. **Loops are where `outG` is already loose.**  The normalization
   file's own docstring says `outG` over-approximates a loop's output by
   `1`.  `wh_emits_exit_all` gives the tight exit guard for loops, so
   the material exists, but tightening `outG` at loops is real work and
   the same question will arise for `inG`.

So: S0's automaton half moves from "blocked by the wrong induction
principle" to "needs a dual construction plus two tightness results" —
better shaped, not yet done, and explicitly not graded as bounded.

**Route status:**
1. **S0** — algebra done; automaton half re-routed today from states to
   labels; needs `inG` + tightness of `inG`/`outG` at loops.
2. **Same-side UNIF** — blocked on the two-states-vs-two-solutions
   mismatch (129), which remains the campaign's core difficulty.
3. **Size induction** — descent holds; `wh` rung blocked on (2).

## Iteration 131 — ★ THE HOMOMORPHISM PARTNER ★ — a second, UNIF-free way to build the second solution

(Search note: the relevant literature question — when a partner map is
a functional bisimulation, and what it costs — was already answered at
iteration 123 (Grabmayer-Fokkink solution transfer; "π : A+B → A is a
functional bisimulation only if A is already its own collapse").  That
answer applies verbatim here, so this iteration reuses it rather than
re-issuing the same query.)

Iteration 129 localized the core difficulty to a structural mismatch:
**canonicity compares two SOLUTIONS; UNIF compares two STATES of one
solution.**  The bridge is a second solution family built from the
first.  `solves_of_partner` (123) builds one — but only by ASSUMING
same-side UNIF.  Today: **there is a second sufficient condition, and it
needs no UNIF at all.**

* `foldTL_retarget` (ZERO axioms) — retargeting an arm list and
  reindexing the solution are the SAME operation.
* **`solves_of_hom`** (ZERO axioms) — if `σ` commutes with halts and
  arms (a functional bisimulation / coalgebra homomorphism), then
  `sol ∘ σ` solves whenever `sol` does.  **Not up to `EquivBA` — the two
  equations are LITERALLY EQUAL.**  No bisimilarity hypothesis, no
  same-side UNIF, no arm-closure.

With canonicity this closes immediately: `sol` and `sol ∘ σ` are two
solutions of the same Thompson system, so they agree, giving
`sol s ≈ sol (σ s)` — **UNIF along σ, outright.**

**What this explains.**  It says exactly why `solves_of_partner` needed
`hsame`: its π was only required to LAND on a bisimilar state, never to
COMMUTE.  Two independent sufficient conditions for the same
conclusion, trading against each other —

| condition on π | extra cost |
|---|---|
| commutes with structure (homomorphism) | none |
| merely lands bisimilar | same-side UNIF |

**And the dichotomy is sharp.**  Per iteration 123's search, a partner
map onto one side is a functional bisimulation only if that side is
ALREADY ITS OWN COLLAPSE — no two distinct bisimilar states.  But if
`e`'s automaton is collapsed, same-side UNIF for `e` is VACUOUS.  So the
two conditions coincide at the boundary: **either `e` is collapsed (σ
can commute, and same-side UNIF is empty), or it is not (σ cannot
commute, and same-side UNIF is exactly the price).**  There is no third
option, and no free lunch hiding between them.

That is a genuine structural clarification rather than a route: it shows
the campaign's remaining obligation is not an artifact of how
`solves_of_partner` was set up, but the intrinsic cost of a
non-collapsed side.  Same-side UNIF is load-bearing by necessity.

**Route status — unchanged in substance, sharper in justification:**
1. **S0** — algebra done; automaton half re-routed to labels (130);
   needs `inG` + tightness.
2. **Same-side UNIF** — now shown to be UNAVOIDABLE, not incidental:
   it is precisely the price of a non-collapsed side.
3. **Size induction** — descent holds; `wh` rung blocked on (2).

## Iteration 132 — ★ THE `ite` RUNG OF THE SIZE INDUCTION, PROVED ★

The size induction needs, at each constructor, that two states
bisimilar in the COMPOSITE's automaton are bisimilar in the
SUBPROGRAM's.  Iteration 128 REFUTED this for `wh` (the loop rewrites
acceptance).  For `ite` the literature calls it immediate — summands
are subcoalgebras.  Today it is proved rather than assumed:

* **`firstMatch_map`** (ZERO axioms) — `firstMatch` commutes with
  retargeting along ANY map.  The repo's existing `firstMatch_retarget`
  is ENDO-typed (`S' → S'`) and therefore cannot cross `Sum.inl` or
  `some`; this is the heterogeneous version those steps need.
* `step_core` — a core state's step is a `firstMatch` over the core arm
  list, retargeted by `some`.
* `step_ite_inl` — a left-injected state's step in an `ite` is a
  `firstMatch` over the SAME underlying list, retargeted by
  `some ∘ Sum.inl`.
* **`ite_bisim_reflect_inl`** — **`ite` REFLECTS BISIMILARITY into its
  left branch.**  The relation "their left-injections are bisimilar in
  the composite" is exhibited as a bisimulation on the subprogram; both
  step directions go through in lockstep because both sides run
  `firstMatch` over the same list, and the halts coincide
  definitionally (`sumGSystem`'s `hlt` on `inl` IS the left's `hlt`).

**Where this leaves the three rungs of the size induction:**

| constructor | bisimilarity transfer | label assembly (127) |
|---|---|---|
| `ite` | **PROVED today** | proved |
| `seq` | open | proved |
| `wh`  | **REFUTED (128)** — needs a composite-level argument | proved |

So the `ite` rung is complete end to end: transfer + assembly +
`ite_same_side_cross_step`'s descent onto strictly smaller subprograms.
That is one full constructor of the same-side induction closed, with no
uniqueness axiom anywhere.

**Honest position.**  `ite` was always going to be the easy rung, and
closing it does not touch the two hard ones.  `wh` remains blocked by
128's counterexample and 129's two-states-vs-two-solutions mismatch, and
131 showed that mismatch is intrinsic rather than an artifact.  What
today buys is that the induction is no longer three open rungs plus an
unverified plan — it is one proved rung, one open, one needing a
different technique, with the descent structure checked.

**Route status:**
1. **S0** — algebra done; automaton half re-routed to labels (130);
   needs `inG` + tightness.
2. **Same-side UNIF** — `ite` rung closed today; `seq` open; `wh`
   needs the composite-level argument, which is the campaign's core.
3. **Size induction** — descent proved (127), `ite` transfer proved
   (132).

## Iteration 133 — ★ THE `seq` RUNG IS REFUTED TOO — one mechanism, one criterion ★

(Search note: the governing literature answer — "reflection holds only
when the inclusion is a homomorphism, i.e. the construction only adds
transitions on states already rejecting under the guard" — was obtained
at iteration 128 and is stated at exactly the generality needed here, so
this iteration reuses it rather than re-issuing the query.)

Iteration 132 left `seq` transfer as the one OPEN rung.  Checked it
against the actual definition rather than assuming it easier than `wh`.
**`seqGSystem` has EXACTLY `loopInitialized`'s shape:**

    hlt  (inl s) = left.hlt s ∧ right.initHlt          -- REWRITTEN
    trans(inl s) = (left arms, retargeted)
                   ++ right.initTrans guarded by left.hlt s   -- ADDED

Halt rewritten, arms added under the halt guard — the two features that
iteration 128's counterexample exploited.  **So the same counterexample
refutes `seq` reflection**: take a left state `s` with `left.hlt s = α`
and no left arms, and a left state `t` with `left.hlt t = 0` carrying a
left arm at `α` with action `a` to a state bisimilar to `right`'s init
target.  At `α`, if `right.initHlt` is false, both composite halts are
false; `s` fires its ADDED arm into the right side and `t` fires its own
left arm, both with action `a` to bisimilar targets.  **Composite-
bisimilar, not left-bisimilar.**

**THE CRITERION, now uniform.**  A Thompson constructor REFLECTS
bisimilarity into its subprogram exactly when it does NOT rewrite
acceptance on that subprogram's states:

| constructor | rewrites acceptance? | reflects bisimilarity |
|---|---|---|
| `ite` (`sumGSystem`) | no — `hlt (inl s) = left.hlt s` | **YES (proved, 132)** |
| `seq` (`seqGSystem`) | yes — `∧ right.initHlt` | **NO (today)** |
| `wh`  (`loopInitialized`) | yes — `∧ ¬guard` | **NO (128)** |

`ite` is the only constructor that leaves acceptance alone, and it is
exactly the only one that reflects.  That matches the literature
criterion verbatim.

**Why this is a SIMPLIFICATION, not just a second loss.**  Iteration 132
listed three rungs needing three treatments: one proved, one open, one
refuted.  There are really only TWO cases, split by a single structural
property — and the two refuted rungs fail for the SAME reason and
therefore need the SAME technique: composite-level canonicity
(`loop_solution_canonical`, `loop_solutions_agree_of_finish`,
`seq_subsystem`).  The campaign's remaining work is ONE technique
applied twice, not two separate problems.

**And it retroactively justifies the subsystem chapter.**  Iterations
109-111 proved `seq_subsystem` and `loop_subsystem` — that an ambient
equation at a `seq`-left or loop-body state IS the subprogram's
parametric equation at a composed finish.  Those are exactly the
composite-level replacements for the two reflection lemmas that do not
exist.  The subsystem chapter was built for precisely the two
constructors that turn out to need it, before the reason was known.

**Route status:**
1. **S0** — algebra done; automaton half re-routed to labels (130).
2. **Same-side UNIF** — `ite` rung closed (132); `seq` and `wh` both
   refuted-by-reflection and both routed to composite-level canonicity,
   where the two-states-vs-two-solutions mismatch (129, shown intrinsic
   at 131) is the single remaining obstruction.
3. **Size induction** — descent proved (127); `ite` transfer proved
   (132); `seq`/`wh` transfers now known impossible, so those rungs must
   be built by subsystem canonicity instead.

## Iteration 134 — the fixpoint MOVED rather than vanished; `prune` avoids the new construction

(Search note: reused iteration 129's answer — deadness in GKAT is an
atom-indexed greatest fixpoint, per Kappé-Schmid-Silva Def. 14 — which
is precisely what this iteration re-tests against 130's re-routing.)

**Correction to iteration 130.**  That iteration re-routed S0's
dead-label obligation from states to labels and named the missing piece
as `inG`, an input-guard dual to `outG`, calling it "a structural
induction on EXPRESSIONS — the shape that worked for `outG`".  Working
it out shows **the fixpoint does not disappear under that re-routing; it
MOVES.**  A TIGHT `inG` for `wh b e` asks *from which atoms does this
loop terminate* — a genuine fixpoint, the same atom-indexed one 129
identified.  So 130's grading was again too optimistic, in the same way
126's was.

**But the two sides are NOT symmetric, and that is the real content.**
* **OUTPUT guards are cheap and tight.**  `wh_emits_exit_all` gives a
  loop's output guard as exactly `¬b` — no fixpoint, no productivity
  hypothesis, already proved.  A loop exits precisely where its guard
  fails; nothing to compute.
* **INPUT guards carry the fixpoint.**  "Does this loop terminate from
  α" is not structural.

So the difficulty is localized to one side, and it is the side that can
be avoided.

**`zero_of_prune_zero`**: if `X` emits `g` and `prune g Y = 0`, then
`X·Y` is provably zero.  The repo ALREADY HAS the guard-relative
deadness detector — `prune`, with `prune_equiv` proving
`g?·e ≡ g?·(prune g e)` unconditionally — so no input guard need be
constructed at all.  **The obligation becomes a COMPLETENESS property of
an existing function** ("semantically dead under `g` ⟹ `prune g` returns
`0`") rather than the construction of a new one.

That is a strictly better place to stand than 130's: same fixpoint
underneath, but attached to a function that is already defined, already
proved sound, and already exercised throughout
`GkatNormalizationProofs`.  Whether `prune`'s completeness at loops is
any easier than a tight `inG` is NOT claimed — the fixpoint is still
there, and this ledger has now twice over-graded S0.  Recording it as:
same difficulty, better-positioned.

**Route status:**
1. **S0** — algebra done; obligation now stated as `prune`-completeness
   (today) rather than `inG`-construction (130); fixpoint at loop INPUT
   guards is the real content, and is NOT graded as bounded.
2. **Same-side UNIF** — `ite` rung closed (132); `seq`/`wh` refuted for
   reflection (128, 133) and routed to subsystem canonicity, where the
   two-states-vs-two-solutions mismatch (129, intrinsic per 131) stands.
3. **Size induction** — descent proved; `ite` transfer proved.

## Iteration 135 — ★ DIVERGENCE REGIONS ARE PROVABLY ZERO ★ — the fixpoint becomes a CERTIFICATE

Iteration 134 localized S0's remaining difficulty to loop INPUT guards:
"from which atoms does this loop diverge" is a greatest fixpoint, not a
structural property, and that is what defeats every induction tried.

**`diverging_region_zero`**: given a region `D` with

    (i)  `D ⊆ b`                — the loop never exits inside `D`
    (ii) `outG D e ⊆ D`         — one pass of the body stays inside `D`

and a strictly productive body, **`D?·(wh b e) ≈ 0`**, provably, with no
uniqueness axiom.

**The proof, and why it closes.**  Unroll by `w1`; kill the exit arm
with (i) via `test_seq_ite_of_implies`; emit the body's output guard by
`outG_emits`; re-absorb it into `D` with (ii) via `test_absorb_left`.
What comes out is

    X ≈ (D? · e · (outG D e)?) · X

— a Salomaa equation **with no exit branch at all**.  Wrap it as
`ite 1 (BODY·X) 0` (`ite_true_collapse`), apply `w3` once, and `s3`
collapses `(wh 1 BODY)·0` to `0`.

**Why this is the right shape.**  The fixpoint is not COMPUTED — it is
SUPPLIED, and certified by two guard implications.  Whoever knows the
divergence region hands over `D` plus (i) and (ii), and the algebra does
the rest.  That converts the obstruction from "prove a coinductive
property by structural induction" (impossible, per 129/134) into
"exhibit a witness and check two implications" — and checking a guard
implication is decidable, not a proof obligation of the same kind.

This also subsumes the repo's existing `wh_one_zero` /
`productive_while_true_eq_zero` (take `D := 1`, `b := 1`), generalizing
them from the whole-space case to an arbitrary certified region.

**Honest scope, having over-graded S0 twice already.**  This does NOT
prove S0.  It proves the loop case of the dead-label obligation GIVEN a
region.  What remains for S0 is that the divergence region EXISTS as a
`BExp` and that its two implications hold — plausible, since a loop's
divergence set is a fixpoint over the finitely-generated Boolean algebra
of the program's own tests and therefore stabilizes, but not proved and
explicitly **not graded as bounded**.

**Route status:**
1. **S0** — algebra done; dead-label obligation's LOOP case now
   discharged given a certified divergence region (today); what remains
   is exhibiting that region.
2. **Same-side UNIF** — `ite` rung closed (132); `seq`/`wh` refuted for
   reflection (128, 133), routed to subsystem canonicity, where the
   two-states-vs-two-solutions mismatch (129, intrinsic per 131) stands.
   **This is the campaign's core and is untouched.**
3. **Size induction** — descent proved (127); `ite` transfer proved
   (132).

## Iteration 136–137 — consolidation, and the first STEELMAN finding

**Published a status artifact** consolidating the campaign: six
unconditional theorems, the ten load-bearing reduction results with
their axiom profiles, four refutations, the measured census, the
corrections log, and the field context.  The corrections are on the
page deliberately — a status document that lists only wins is not
checkable, and this campaign's credibility rests on four routes having
died with recorded reasons.

**Then the queued STEELMAN HARDENING campaign, started.**

* **`sorry` audit across the whole GKAT cluster: CLEAN.**  Every match
  for `sorry`/`admit` is the English word "admit" in prose or the phrase
  "sorry-free" in a docstring.  No proof hole anywhere.
* **Axiom audit of all seven headline results**: `loopfree_complete`,
  `atomicloops_complete`, `gloops_complete`, `chainloops_complete_free`,
  `twoloops_complete`, `chordloops_complete`, `uleDec` — all at exactly
  **`[propext, Classical.choice, Quot.sound]`**, Lean's three standard
  axioms, none with `sorryAx`.
* **★ FIRST HARDENING FINDING — a claim in the repo was imprecise. ★**
  `uleDec`'s docstring read "decidable — computably, with no choice",
  and its axiom profile reports `Classical.choice`.  Investigated rather
  than assumed either way, and BOTH halves turn out to be true of
  different things:
  - the DECISION PROCEDURE really is computable and choice-free — Lean
    accepts the `def` without `noncomputable`, so the `Decidable` DATA
    runs;
  - the CORRECTNESS ARGUMENT is classical — the proof that the
    computable `trimAutD`/`genBisimilarDec` pipeline agrees with the
    `Classical.choose`-based `trimAut` goes through choice.

  The docstring conflated algorithm with proof.  Rewritten to state
  both precisely and to name where the choice enters.  **The same
  imprecision had already propagated into the published artifact** ("
  computably, choice-free") and was corrected there too.

That is exactly what the hardening campaign exists to catch: not a
broken proof, but a claim that says more than the proof supports.  One
found on the first pass.

**Literature check**: nothing new on the core question — no GKAT
completeness result, no UA elimination beyond skip-free, no post-thesis
Pham preprint.  Two items worth cataloguing that were not in the
ledger: a **cyclic proof system for GKAT** (arXiv 2405.07505, 2024),
which SIDESTEPS the axiomatic-completeness question via cyclic proofs
rather than answering it, and GKAT automata learning (arXiv 2204.14153).
Also confirmed: the coalgebraic side of Smolka et al. was verified in
**Coq**, and **no Lean or Isabelle GKAT formalization exists** — this
cluster still appears to be the only one.

## Iteration 138 — ★ SECOND HARDENING FINDING: "six unconditional theorems" was an OVERCLAIM ★

Audited the actual Lean signatures of all six completeness theorems
rather than trusting how the ledger has described them for ~60
iterations.  The result splits them:

| theorem | hypotheses beyond ULE |
|---|---|
| `loopfree_complete` | `LoopFree e`, `LoopFree f` — **fragment only** |
| `atomicloops_complete` | `AtomicLoops e/f` — **fragment only** |
| `gloops_complete` | `GLoops e/f` — **fragment only** |
| `chainloops_complete_free` | `Chain2 body₁/body₂` — **fragment only** |
| `twoloops_complete` | **+ SIX satisfiability hypotheses** |
| `chordloops_complete` | **+ SIX satisfiability hypotheses** |

`twoloops_complete` assumes each loop guard is both satisfiable and
refutable on both sides (`hexitC₁ hexitB₁ hbc₁` and primes);
`chordloops_complete` assumes shared entry on `b` and on `c` plus
exit-exists for `b`, `c` and their primes.  These are non-degeneracy
conditions — the loops must actually be enterable and exitable — and
they are mild.  **But they are hypotheses, and "unconditional" was the
wrong word.**  It has been in the ledger, the memory file, and (since
iteration 136) the published artifact.

**Fixed everywhere**: the artifact section is retitled, each theorem now
carries its hypothesis class inline, and the page's own corrections log
records the change.  The literature check confirms this matters: the
convention (skip-free GKAT, 1-free regular expressions) is that the
restriction goes in the TITLE and the formal statement, that the
semantics is named as part of the claim, and that saying "we prove
completeness for GKAT" when it holds for a fragment or under hypotheses
is **treated as an overclaim by reviewers**.  The accepted move is to
name the restricted class as a first-class object — which this repo
does for four of six (`LoopFree`, `AtomicLoops`, `GLoops`, `Chain2`)
and does NOT for the two that use side conditions instead.

**And the fix is plausibly available.**  `chainloops_complete_free`
earns its `_free` suffix by handling degenerate guards with internal
`Classical.em` case analysis (an unsatisfiable loop guard collapses the
loop to `1` via `wh_guard_semantic_zero`) instead of assuming them away.
**That is a template.**  Concrete hardening task, now named: apply the
same case analysis to `twoloops_complete` and `chordloops_complete` to
produce `_free` variants, at which point all six become fragment-only
and "unconditional within its fragment" becomes accurate.

**Running hardening tally:** two audits clean (`sorry`-freeness, axiom
profiles), two overclaims found and fixed (`uleDec`'s
computability-vs-proof conflation; "unconditional"), one concrete
follow-up task identified.  Both overclaims were about *how results
were described*, not about whether they hold — which is the failure
mode a machine-checked corpus is most exposed to, since the prover
never checks the prose.

## Iteration 139 — the degenerate cases are collapses, confirmed both ways

Acting on 138's named task: make `twoloops`/`chordloops` hypothesis-
free by case analysis, using `chainloops_complete_free` as the template.
Two collapse lemmas, **both ZERO AXIOMS**:

* **`twoLoop_b_unsat`** — an unenterable outer guard makes the two-loop
  `skip`.  Immediate from `wh_guard_semantic_zero`.
* **`twoLoop_no_overlap`** — **when the two guards never hold together,
  the inner loop is INVISIBLE and the two-loop collapses to an ATOMIC
  loop** `wh b (act r)` — already covered by `atomicloops_complete`.
  Under `b` the inner loop takes its exit branch immediately (`w1`
  unroll, `u2` flip so the implication points the right way,
  `test_seq_ite_of_implies`), the body therefore agrees with `act r`
  under `b`, and `wh_congr_under_guard` lifts that to the loops.  This
  was the degenerate case that looked like it might hide content, and
  it does not — it lands in an earlier stratum.

**The literature check confirms the diagnosis independently**, which is
what settles whether 138's finding was cosmetic or substantive:

* **Non-degeneracy is NOT assumed in the literature.**  Neither Smolka
  et al. nor the coequations/completeness papers hypothesize satisfiable
  guards; degeneracy is absorbed by the guarded-union axioms
  (`e +₀ f = f`, `e +₁ f = e`), and case analysis on `b` is "routine
  inside proofs, never a hypothesis".  So the four siblings' style is
  the field's style and the two outliers are the anomaly.
* **The collapse lemmas are one-liners**: `e^(0) = 1` from unrolling;
  `e^(1)·f = 0` for productive `e` from the fixpoint axiom.
* **Verdict, verbatim**: "removing satisfiability hypotheses is routine
  bookkeeping, PROVIDED your fixpoint/uniqueness rule is available for
  the `b=1` divergent case — that step is trivial but not free."

This repo HAS that rule, and more than the minimum: `wh_one_zero`
handles `b=1` outright, and iteration 135's `diverging_region_zero`
generalizes it from the whole space to an arbitrary certified region.
The one thing the field says you must have in hand, the campaign had
already built for a different reason.

* Also recorded, and useful for calibration: **"the real difficulty in
  GKAT lives in PRODUCTIVITY (`E(e)=0`), not guard satisfiability — that
  is where the axiomatization actually strains."**  Consistent with this
  campaign's own experience: every hard step has turned on productivity
  side conditions (`w3`'s guardedness, `equivBA_substA`'s productive
  substitution, `elim_reduces`' action-headed prefixes), never on guard
  degeneracy.

**So 138's finding stands as a WORDING defect, not a mathematical one** —
the hypotheses are removable and the removal is bookkeeping.  That is
the honest grading: the overclaim was real and worth fixing, and the
underlying theorems are not weaker than they looked.

**Remaining for this task**: the other degenerate cases (`b` valid,
`c` valid) and the assembly into `twoloops_complete_free`, then the same
for `chordloops`.  Each collapse lands in an earlier stratum, so the
assembly is a case split over already-proved results rather than new
mathematics.

## Iteration 140 — ★ THE TWO-LOOP DEGENERACY TOOLKIT IS COMPLETE ★ (all four, zero axioms)

`twoloops_complete`'s six hypotheses are three conditions per side.
Each has exactly one negation, and every negation now has a collapse
lemma — **all four at ZERO AXIOMS**:

| failing hypothesis | what the two-loop becomes |
|---|---|
| `b` unsatisfiable | `twoLoop_b_unsat` → `1` (skip) |
| `b` valid (never exits) | **`twoLoop_b_valid` → `0`** |
| `c` valid (inner never exits) | **`twoLoop_c_valid` → `¬b?`** |
| `b ∧ c` unsatisfiable | `twoLoop_no_overlap` → `wh b (act r)` |

Today's two: an always-true outer guard makes the loop divergent, so
`wh_one_zero` — which the repo proves for EVERY body with NO side
condition — sends it straight to `0`.  An always-true INNER guard makes
the inner loop divergent, so the body is `0` by `s2`, and
`wh_test_collapse` turns the test-bodied outer loop into the plain test
`¬b`.

**Every degenerate case lands on a TEST or in an EARLIER STRATUM.**
Three of the four become pure Boolean assertions; the fourth becomes an
atomic loop, already covered by `atomicloops_complete`.  Nothing lands
anywhere new.  That is the structural reason the satisfiability
hypotheses are removable, now demonstrated case by case rather than
asserted.

**What remains for `twoloops_complete_free`** is the assembly: a case
split where the two sides may degenerate differently.  The mixed cases
need a SEPARATION argument — a live two-loop cannot be language-equal
to a test, because its language contains a string with an action while
a test's contains only single atoms.  `chainloops_complete_free`
already contains exactly this move ("a test never equals a live loop,
which denotes a word with an action"), so the pattern exists in-repo
and needs instantiating rather than inventing.

**Hardening tally so far**: two audits clean (`sorry`, axiom profiles),
two overclaims found and fixed (`uleDec`'s algorithm-vs-proof
conflation; "unconditional"), and the fix for the second is now four
collapse lemmas deep with only the assembly left.

### Iteration 140 addendum — the separation step is routine, and the field says so

Checked whether the remaining assembly step (a live loop cannot equal a
test) is standard or hides work.  It is standard, and instructively so:

* **Separation is not a named lemma anywhere** — it falls straight out
  of the guarded-string grading.  A test's denotation sits inside `At`:
  every accepted string has ZERO actions.  Any string containing an
  action letter therefore cannot be in it.  Proofs in the literature
  "use it silently".  The nearest named machinery is Kozen's `E(e)`
  accepting-immediately decomposition, with Salomaa's empty-word
  property as the KA analogue.
* **Liveness is NOT argued from satisfiable-guard-plus-productive-body**,
  which is what this ledger assumed at iteration 140.  The standard move
  (ICALP'21, productive loops) is to SPLIT `e` into `E(e)` plus a
  strictly productive part and REWRITE to an equivalent productive loop,
  rather than to argue that some particular loop is live.  Worth
  recording as a course-correction before building the assembly the
  wrong way — and note this repo already has the rewrite:
  `guardedness_normalization` produces exactly the productive
  replacement, and `wh_congr_under_guard` installs it.
* **The both-tests branch** reduces to equality of two Boolean guards as
  subsets of atoms, discharged by BA completeness — "explicitly a base
  case, always one line".  This repo's `EquivBA.baTest` is precisely
  that one line.

So all three ingredients of the assembly are routine AND already
present in the repo: separation from the grading, productivity by
rewriting rather than liveness argument, and the both-tests base case by
`baTest`.  The assembly is bookkeeping over existing parts, which is the
same verdict iteration 139's search gave for the task as a whole.

**Calibration note.**  Two searches in a row have now confirmed that the
hypotheses flagged at 138 are removable by routine means.  The
hardening finding was real — the wording overclaimed — but the
mathematics behind it is not in doubt, and the repair path is fully
mapped with no new ideas required.

## Iteration 141 — ★ THE ASSEMBLY IS NOT ROUTINE: one of the four cases leaves the fragment ★

Attempted the `twoloops_complete_free` assembly and found that
iterations 139–140 graded it too optimistically.  **Three of the four
degenerate cases are routine; the fourth is not.**

**Read the template properly first.**  `chainloops_complete_free`'s
actual case structure, now inspected line by line:
* both sides collapse to TESTS → `test_test_equiv` after transporting
  the equivalence with `ule_congr_left/right` (BA completeness, the
  one-line base case the literature describes);
* one side collapses to a TEST, the other is LIVE → **`absurd`** — the
  case is VACUOUS, killed by separation exactly as the field does it.

That template covers a collapse **to a test**.  Checking the four
two-loop collapses against it:

| collapse | target | covered by the template? |
|---|---|---|
| `b` unsat | `1` | yes — a test |
| `b` valid | `0` | yes — a test |
| `c` valid | `¬b?` | yes — a test |
| **no `b∧c` overlap** | **`wh b (act r)`** | **NO — an atomic loop, not a test** |

**The fourth case leaves the fragment rather than collapsing out of
it.**  A no-overlap two-loop becomes an ATOMIC LOOP; if the other side
is a LIVE two-loop, the pair is (atomic loop, two-loop) — and no
existing stratum covers it.  Checked directly rather than assumed:
`wh b (act r)` is in `AtomicLoops` (constructor `wh b p`), but
`twoLoop` is NOT in `GLoops`, because `GLoops.whOne` needs a `OneAct`
body and `twoLoop`'s body `(wh c (act q)); act r` carries TWO action
occurrences.  So `atomicloops_complete` does not apply (the two-loop
isn't atomic) and `gloops_complete` does not apply (the two-loop isn't
GLoops).  Separation does not apply either — both sides emit actions,
so there is no contradiction to derive.

**This is the known pitfall**: fragment completeness theorems do not
compose across fragments, and a degenerate case that collapses a program
into a DIFFERENT fragment must then be compared against a
non-degenerate program of the original one.  The standard resolutions
are to prove completeness for the union, or to show the degeneracy
forces the other side to degenerate too.  Neither is available here for
free: whether `b₁ ∧ c₁` unsatisfiable forces `b₂ ∧ c₂` unsatisfiable
under language equivalence is **not obvious and is not proved**.

**Correcting the record.**  Iteration 139 wrote "the assembly is a case
split over already-proved results rather than new mathematics" and 140
repeated it.  That is right for three cases and wrong for the fourth.
The satisfiability hypotheses of `twoloops_complete` are therefore
**not** removable by pure bookkeeping — removing `hbc` specifically
needs either an atomic-vs-two-loop completeness result or a proof that
no-overlap propagates across language equivalence.

**Status change.**  `twoloops_complete_free` moves from "bookkeeping,
pending" to "three cases done, one genuinely open".  The two overclaims
found at 137–138 remain correctly diagnosed; what was wrong was my
estimate of the REPAIR cost, which is the third estimate this campaign
has had to revise downward on contact.  The collapse lemmas of
iterations 139–140 all stand and are all still needed.

### Iteration 141 addendum — the pitfall is named, and the two repair options are the ones identified

The cross-fragment search confirms 141's finding and names the
machinery:

* **Fragment completeness genuinely does not compose.**  "Complete for
  A" quantifies only over pairs INSIDE A; a mixed pair is in the scope
  of neither theorem, and the derivation "may need axioms/normal forms
  present in neither system".  So the atomic-vs-two-loop pair really is
  outside everything proved here — not an oversight in how the strata
  were stated.
* **The recognized notion is CONSERVATIVITY**: an axiomatic conservative
  extension is one where any equality between A-terms derivable from
  A ∪ B is already derivable in A.  That is the property that licenses
  reasoning across a fragment boundary, and **it must be proved, not
  assumed**.  Skip-free GKAT is the canonical worked instance — a
  fragment axiomatized on its own and then RELATED BACK to full GKAT,
  rather than assumed to embed for free.
* **Two repairs, exactly the two 141 identified**: (a) prove
  completeness for the closure/union with a single normal form covering
  both, or (b) prove the degenerate case FORCES the other side to
  degenerate too, collapsing the mixed pair into a same-fragment pair.
  "(b) is much cheaper when it holds; if it doesn't, you're on the hook
  for (a)."

**So the concrete question for `twoloops_complete_free` is (b)**: does
`b₁ ∧ c₁` unsatisfiable, together with language equivalence, force
`b₂ ∧ c₂` unsatisfiable?  If yes, the mixed case disappears and the
assembly closes.  If no, removing `hbc` requires a genuine
atomic-vs-two-loop completeness result — option (a).

That is a sharp, decidable-looking question about two-loop languages,
and it is the right next thing to settle.  Note it is a question about
the WITNESS PROGRAMS, not about the general open problem: whichever way
it goes, it affects only how `twoloops_complete`'s hypotheses are
stated, never whether the theorem holds.

## Iteration 142 — ★ THE MIXED CASE IS VACUOUS — option (b) holds ★

Iteration 141 left a sharp question: does `b₁ ∧ c₁` unsatisfiable,
together with language equivalence, force the other side to degenerate?
Worked it out.  **The answer is better than "forces degeneracy": the
mixed case is IMPOSSIBLE.**  Four steps, each a guarded-string
observation.

Setting: side 1 has `b₁ ∧ c₁` unsatisfiable, so by `twoLoop_no_overlap`
it is the atomic loop `wh b₁ (act r₁)`.  Side 2 is LIVE — `b₂ ∧ c₂`
satisfiable at some `α`, and `b₂`, `c₂` both refutable.

**1. The guards must coincide: `b₁ ≡ b₂`.**  At any atom where `¬b₁`,
side 1's loop exits immediately and ACCEPTS the single-atom string.  At
any atom where `b₂` holds, side 2 must run its body and CANNOT accept a
single-atom string.  So `¬b₁ ⟹ ¬b₂`.  Symmetrically `¬b₂ ⟹ ¬b₁`.
Hence `b₁ ≡ b₂`.

**2. The first actions must agree: `r₁ = q₂`.**  At the witness atom `α`
we now have `b₁`, `b₂`, `c₂` all true — and `c₁` FALSE, since `b₁ ∧ c₁`
is unsatisfiable and `b₁` holds.  Side 1 emits `r₁`; side 2 enters its
inner loop and emits `q₂`.  Equality of languages forces `r₁ = q₂`.

**3. The killer: side 2 cannot halt where side 1 can.**  After that
first action both sides sit at an arbitrary next atom `α₁` — but side 1
is back at its LOOP HEAD, while side 2 is INSIDE the inner loop, which
must still emit the body's tail `r₂` before it can ever re-test `b₂`.
So side 1 accepts `α r₁ α₁` whenever `¬b₁` at `α₁`, and side 2 accepts
`α q₂ α₁` never.  With `r₁ = q₂` from step 2, that is a contradiction —
**provided some atom has `¬b₁`.**

**4. And if no atom has `¬b₁`, that is a contradiction too.**  `b₁`
valid makes side 1's loop divergent, so its language is EMPTY.  But
`b₁ ≡ b₂` from step 1 makes `b₂` valid, contradicting side 2's
`hexitB₂` — and independently, side 2 with `¬b₂` somewhere accepts a
single-atom string, so its language is nonempty.

**Every branch contradicts.  The mixed case is vacuous.**

**What this settles.**  141's question has the cheap answer: option (b),
the one the literature calls "much cheaper when it holds", DOES hold
here.  So `twoloops_complete_free` needs no atomic-vs-two-loop
completeness result and no conservativity theorem — the fourth
degenerate case joins the other three in being discharged by
separation-style reasoning, just with a longer chain (four steps rather
than one) because the collapse target emits actions.

**Honest status.**  This is a hand-verified argument, not yet Lean.
Steps 1 and 4 are single-atom acceptance facts and should formalize
directly against `autLang`/`den`; step 3 is the one needing care, since
it asserts side 2's inability to halt mid-body — which is exactly the
"body tail must still run" structural fact, and the repo's
`chord_noeps_*` / liveness lemmas are the nearest existing pattern.
Recording the argument in full so the formalization is transcription
rather than rediscovery.

**Revised status of the hardening task**: `twoloops_complete_free` is
four collapse lemmas (done, zero axioms) plus a vacuity argument
(derived today, not yet formal).  No new mathematics is required — and
this time that claim is backed by a worked argument rather than an
estimate, which is what the last three revisions were missing.

## Iteration 143 — step 1 formalized, and it generalizes past the two-loop

Started transcribing iteration 142's vacuity argument.  **Step 1 lands,
and it is not specific to two-loops at all:**

* **`wh_den_nil`** [propext] — a loop accepts an action-free guarded
  string EXACTLY where its guard fails.  **The body is irrelevant.**
  Both halves were already in the repo without ever being stated
  together: `InLoop_nil` gives the forward direction, the `InLoop.exit`
  constructor the backward one.
* **`wh_guards_agree_of_ule`** [propext] — **language-equivalent loops
  have pointwise-equal guards, whatever their bodies.**  Iteration 142
  derived `b₁ ≡ b₂` for the specific atomic-vs-two-loop pair; the same
  argument needs nothing about either body, so the general statement is
  the honest one.

That is a better result than the argument called for, and it is
reusable well beyond this task: any completeness case analysis that
pairs two loops now gets guard agreement for free, which is exactly the
kind of step that has been done ad hoc inside the strata proofs.

**Remaining of the transcription**: step 2 (first actions agree — a
one-action-deep language observation), step 3 (side 2 cannot halt
mid-body — the structural core, needing that the inner loop's exit
still owes the body's tail), step 4 (validity forces empty language,
already available in spirit via `twoLoop_b_valid` plus `wh_one_zero`).
Step 3 remains the one with real content; steps 2 and 4 should follow
the shape of step 1.

**Position after this iteration.**  The hardening task
`twoloops_complete_free` now stands at: four collapse lemmas proved
(zero axioms), the vacuity argument derived in full, and its first step
formalized and generalized.  Nothing about it has required new
mathematics, which is now a claim backed by two proved lemmas and a
worked argument rather than by an estimate — the correction that
iterations 139-141 kept having to make.

## Iteration 144 — ★ THE VACUITY THEOREM IS PROVED — and it is SHORTER than the hand argument ★

Iteration 142 derived the mixed case's impossibility by hand in FOUR
steps.  Formalizing it needed only TWO.

* **`twoLoop_two_actions`** [propext] — **a two-loop entered with both
  guards true owes at least TWO actions.**  The inner loop cannot be
  silent there (`wh_den_nil`'s contrapositive) and the body's tail
  `act r` always fires exactly once, so the first outer iteration alone
  already owes two.
* **`atomicLoop_one_action`** (ZERO axioms) — an atomic loop emits
  exactly ONE action and can stop, wherever its guard holds now and
  fails next.
* **`no_overlap_vs_live_absurd`** [propext] — **a no-overlap two-loop
  cannot be language-equivalent to a live one.**  Guards agree by
  iteration 143's `wh_guards_agree_of_ule`; the atomic side accepts a
  one-action string at the both-guards witness; language equivalence
  forces the live side to accept it; `twoLoop_two_actions` says it owes
  two.  Contradiction.

**Two of the hand argument's four steps turned out to be unnecessary.**
Step 2 (`r₁ = q₂`) is not needed at all — the one-action string is built
with `r₁`, and the two-loop owes two actions REGARDLESS of which action
is involved, so no matching of action letters is required.  Step 4 is
absorbed: the exit atom that lets the atomic side stop comes straight
from the live side's own `hexitB₂`, transported across the agreed
guards.  The hand derivation reasoned about matching first actions and
then about divergence, and neither was load-bearing.

Worth recording as a methodological point, since this campaign's errors
have run the other way: **the hand argument was over-complicated, not
wrong.**  Formalizing simplified it, which is the opposite of the usual
direction and a reason to formalize earlier rather than later.

**Status of `twoloops_complete_free`**: four collapse lemmas (zero
axioms) + the vacuity theorem (proved today) + the assembly case split.
Every ingredient the repair needs now exists as a checked theorem.  The
remaining assembly is the case analysis itself — three test-collapses
against `chainloops_complete_free`'s template, the fourth against
`no_overlap_vs_live_absurd`, and both-live against
`twoloops_complete`.

**Hardening tally**: two audits clean; two overclaims found and fixed;
the repair for the second is now seven proved lemmas deep with only
mechanical assembly left.

## Iteration 145 — the last non-mechanical ingredient; the repair is now assembly-only

The remaining mixed cases pair a collapsed side that is a pure TEST
against a LIVE two-loop.  Three lemmas, **all ZERO AXIOMS**:

* **`twoLoop_live_accepts`** — **a live two-loop accepts a two-action
  string.**  Its three liveness hypotheses supply exactly the atoms
  needed to build one: enter at an atom where both guards hold, leave
  the inner loop where `c` fails, leave the outer loop where `b` fails.
  The witness is `(a, [(q, a₂), (r, a₃)])`, constructed directly from
  the `InLoop` constructors.
* `test_no_action` — a test accepts no string that performs an action.
  One projection; it was always there in `den_test` and never named.
* **`live_twoLoop_ne_test`** — **a live two-loop is never
  language-equivalent to a test.**

**`twoloops_complete_free`'s ingredient set is now complete.**  Every
branch of its case analysis resolves to a checked theorem:

| branch | discharged by |
|---|---|
| both sides live | `twoloops_complete` |
| side collapses to `1` / `0` / `¬b?`, other live | **`live_twoLoop_ne_test`** |
| side collapses to an atomic loop, other live | **`no_overlap_vs_live_absurd`** |
| both collapse to tests | `EquivBA.baTest` after transport |
| both collapse to atomic loops | `atomicloops_complete` |

with the collapses themselves supplied by `twoLoop_b_unsat`,
`twoLoop_b_valid`, `twoLoop_c_valid`, `twoLoop_no_overlap`.

**What remains is the case split itself** — mechanical, because no
branch needs anything not already proved.  That is the same claim
iterations 139-140 made prematurely and 141 had to retract; the
difference now is that the retraction's cause (the no-overlap branch
leaving the fragment) has been closed by an actual theorem rather than
an estimate, and the test-vs-live branches have been closed too.

**Ten lemmas deep.**  The hardening finding at 138 — that two of the six
theorems carry hypotheses the ledger had been calling "unconditional" —
has produced: four collapse lemmas, two guard/acceptance primitives that
generalize past two-loops, and four vacuity results.  None of it is new
mathematics; all of it was needed to say precisely what the six
theorems prove.

## Iteration 146 — ★ `twoloops_complete_free` — THE OVERCLAIM IS REPAIRED ★

**`twoloops_complete_free`** [propext, Classical.choice, Quot.sound]:
completeness for two-loop programs with **NO satisfiability hypotheses
on any guard**.  The six that `twoloops_complete` carries are gone.

**`twoLoop_trichotomy`** is what made the assembly tractable: every
two-loop is provably a TEST, or provably a NON-DEGENERATE ATOMIC LOOP,
or LIVE — with the atomic branch's own degeneracies already pushed into
the test branch.  That turns a six-hypothesis scramble into a 3 × 3
table, and every one of the nine cells is a proved theorem:

| | test | atomic | live |
|---|---|---|---|
| **test** | `test_test_equiv` | ✗ `live_atomicLoop_ne_test` | ✗ `live_twoLoop_ne_test` |
| **atomic** | ✗ | `atomicloops_complete` | ✗ `no_overlap_vs_live_absurd` |
| **live** | ✗ | ✗ | `twoloops_complete` |

Six of the nine cells are IMPOSSIBLE, discharged by the vacuity results
of iterations 144–145; the three diagonal cells are the earlier strata
doing their job.  The assembly compiled on the first attempt.

**Five of the six theorems are now hypothesis-free.**  `loopfree`,
`atomicloops`, `gloops`, `chainloops_free`, and now `twoloops_free` take
nothing beyond membership in their fragment and language equivalence.
**Only `chordloops_complete` still carries side conditions** — and it
has the same shape (shared-entry and exit-exists on `b` and `c`, both
sides), so the same trichotomy-plus-vacuity pattern should apply, with
`chordLoop`'s extra branch structure the only new work.

**The hardening arc, closed for this theorem.**  Iteration 138 found
that the ledger had been calling six theorems "unconditional" when two
carried hypotheses.  Rather than only fixing the wording, the campaign
went and removed the hypotheses: eleven lemmas across iterations
139–146 — four collapses, two guard/acceptance primitives that
generalize past two-loops, four vacuity results, and the trichotomy —
none of them new mathematics, all of them needed to make the word
"unconditional" true rather than merely retracted.

## Iteration 147 — the chord repair's collapses land in `Chain2`, and its `b`-hypotheses halve

Started the last outstanding hardening item, `chordloops_complete_free`.
Three lemmas, **all ZERO AXIOMS**, and the news is good on both fronts.

* **`chordLoop_c_valid`** — an always-true inner guard makes the chord
  loop `wh b (p; (x; y))`.
* **`chordLoop_c_unsat`** — an always-false inner guard makes it
  `wh b (p; y)`.
* **`chordLoop_collapse_chain2`** — **both targets are `Chain2` bodies.**
  `Chain` is any nested sequence of actions, so `p; y` and `p; (x; y)`
  both qualify.

**That is a better landing spot than the two-loop repair had.**  There,
the no-overlap collapse fell into `AtomicLoops` and needed a fresh
vacuity argument (`no_overlap_vs_live_absurd`, four lemmas' worth).
Here the stratum absorbing the collapse is `chainloops_complete_free` —
which is ALREADY hypothesis-free, so nothing has to be repaired
underneath the repair.

**And the `b`-side hypotheses halve for free.**  `chordloops_complete`
carries THREE conditions on the outer guards: shared entry `b ∧ b'`,
plus exit-exists for `b` and for `b'` separately.  Both sides are
loops, so **`wh_guards_agree_of_ule` (iteration 143) gives `b ≡ b'`** —
whereupon shared entry is just satisfiability of `b`, and the two exit
conditions are one.  Three become two, with no work, from a lemma
proved for a different purpose four iterations ago.

**What remains for the chord repair.**  A trichotomy in the shape of
`twoLoop_trichotomy` — chord loops are provably a test, or provably a
`Chain2` loop, or live — plus the mixed-case vacuity.  The vacuity
argument here is an ACTION-COUNT one and is worth recording before it
is built: a `Chain2` loop with body `p; y` emits exactly two actions per
iteration, one with `p; (x; y)` exactly three, while a LIVE chord loop
emits two on `¬c` iterations and three on `c` iterations.  So a live
chord accepts strings of lengths not congruent to the chain's fixed
stride, and the contradiction is arithmetic rather than structural —
a different shape from the two-loop's one-versus-two argument, and the
one genuinely new piece.

**Hardening status**: five of six theorems hypothesis-free; the sixth
has its collapses proved, its landing stratum confirmed already free,
and its `b`-conditions reduced from three to two.

## Iteration 148 — the STRIDE invariant: a chain loop's action count is a multiple of its body

Iteration 147 named the chord repair's one genuinely new piece as an
ARITHMETIC vacuity.  Its core is now proved:

* **`chain2_even`** [propext] — a loop with a two-action chain body
  accepts only strings whose action count is EVEN.
* **`chain3_mod`** [propext] — a three-action chain body forces counts
  divisible by three.

Both are two-line inductions on `InLoop`: the exit case contributes
zero, each step contributes exactly the body's fixed length, and
`Nat.add_mod_left` closes it.  **A chain loop has a STRIDE**, and its
accepted lengths are the multiples of that stride.

**That is exactly what separates a chain loop from a live chord.**  A
live chord emits TWO actions on `¬c` iterations and THREE on `c` ones,
so it accepts strings of both lengths — and no single stride absorbs
both: 3 is not even, 2 is not a multiple of 3.  So each of the two
mixed cases of `chordloops_complete_free` dies by an arithmetic
mismatch rather than a structural one.

**Tactic notes** (both cost a rebuild and are worth recording): the
`InLoop` induction needs the guarded string GENERALIZED — inducting
with the index fixed as `(a, l)` fails with "index in target's type is
not a variable", so the statement must quantify over `gs` and conclude
about `gs.2.length`.  And when the induction is set up via
`have h' : InLoop … := h`, the inductive hypothesis carries the
recursive premise as an argument, so the step case closes with
`exact ih hrec` rather than `exact ih`.

**Remaining for `chordloops_complete_free`**: the two acceptance
witnesses (a live chord accepts a two-action string via a `¬c` entry
and a three-action string via a `c` entry — same construction as
`twoLoop_live_accepts`), the trichotomy in the shape of
`twoLoop_trichotomy`, and the 3 × 3 assembly.  Every piece now has a
worked precedent from the two-loop repair except the stride argument,
which is proved above.

## Iteration 149 — the chord vacuities land: both mixed cases die by arithmetic

Four lemmas; the two witnesses at **ZERO AXIOMS**, the two vacuities at
[propext].

* **`chordLoop_accepts_three`** / **`chordLoop_accepts_two`** — a chord
  loop accepts a three-action string when the branch guard holds after
  `p`, and a two-action string when it fails.  **Note where `c` is
  read**: `chordBody = p · (x·y +_c y)`, so the branch guard is tested
  at the POST-`p` atom, not at the loop head — the witnesses thread
  that correctly, which is the one place this construction differs from
  `twoLoop_live_accepts`.
* **`live_chord_ne_chain2`** — a live chord is never a two-stride chain
  loop: its three-action string has ODD length, and `chain2_even` says
  the chain accepts only even ones.
* **`live_chord_ne_chain3`** — a live chord is never a three-stride
  chain loop: its two-action string is not a multiple of three.

**Both mixed cases of `chordloops_complete_free` are now closed**, and
exactly as predicted at iteration 147: by arithmetic on action counts
rather than by structure.  The prediction was made before the stride
invariant existed and held up, which is a change from this campaign's
recent record on forecasts.

**Tactic note**: `nomatch` closed `2 % 3 = 0` but not `3 % 2 = 0` —
the latter needed `absurd h (by decide)` with the type ascribed to
`(3 : Nat) % 2 = 0` first, so the numeral reduces before `decide` runs.

**Remaining for `chordloops_complete_free`**: a live-chord-vs-test
vacuity (five lines: any of the two witnesses plus `test_no_action`),
the trichotomy in the shape of `twoLoop_trichotomy`, and the 3 × 3
assembly.  All three have exact precedents from the two-loop repair.

**Where the hardening campaign stands**: five of six theorems
hypothesis-free; the sixth has its collapses proved, its landing
stratum confirmed already free, its `b`-conditions halved by
`wh_guards_agree_of_ule`, and now both of its mixed-case vacuities
discharged.

## Iteration 150 — the chord vacuity set is COMPLETE; and `hentC` is the one hypothesis that resists

Four more lemmas, three at **ZERO AXIOMS**:

* **`live_chord_ne_test`** — a chord loop with a usable OUTER guard is
  never a test.  Only the outer guard's non-degeneracy is needed:
  whichever way the branch guard falls at the post-`p` atom, one of the
  two acceptance witnesses fires.
* **`chain2_ne_test`**, **`chain3_ne_test`** — the chain-loop collapse
  targets are not tests either, once their guard is usable.
* **`chordLoop_tetrachotomy`** — every chord loop is provably a TEST, a
  TWO-STRIDE chain loop, a THREE-STRIDE chain loop, or LIVE, with the
  outer guard's degeneracies already pushed into the test branch so the
  chain branches carry a usable guard.

**The 4 × 4 assembly is now fully covered except one cell**, and that
cell is worth stating carefully.

**`hentC` does not follow from the per-side liveness conditions.**
`chordloops_complete` needs SHARED inner-guard entry — `∃α, c ∧ c'` —
and the tetrachotomy's live branch gives only `c` satisfiable and `c'`
satisfiable SEPARATELY.  Guard agreement rescues the outer guards
(`wh_guards_agree_of_ule` gives `b ≡ b'`, so shared entry on `b` and
both exit conditions collapse to satisfiability plus refutability of a
single guard) — but `c` and `c'` are INNER guards of the two sides and
no such agreement applies.

So the honest current statement of the chord repair is **six
satisfiability hypotheses reduced to ONE**, not to zero.

**`hentC` does look derivable, and the sketch is recorded rather than
claimed.**  Assume `c` and `c'` disjoint.  At a post-`p` atom where both
fail, both sides emit their tail action, forcing `y = y'`.  At an atom
where `c` holds (so `c'` fails), side 1 emits three actions while side 2
emits two, and matching them forces `x = y` and then `y = p`; symmetric
reasoning on the `c'` side forces all six action letters equal.  With a
single letter throughout, side 2 accepts a two-action string at an atom
where the outer guard next fails, while side 1 is mid-body after two
actions and cannot halt — contradiction.  Several steps, each of the
shape already proved above, but not yet written.

**Hardening status**: five of six theorems hypothesis-free; the sixth
reduced from six hypotheses to one, with every mixed case of its
assembly discharged and the residual hypothesis identified precisely
along with a route to removing it.

## Iteration 151 — ★ `chordloops_complete_of_shared_entry`: SIX HYPOTHESES DOWN TO ONE ★

**`chordloops_complete_of_shared_entry`** [propext, Classical.choice,
Quot.sound] — completeness for chord-loop programs assuming ONLY shared
inner-guard entry `∃α, c ∧ c'`.  The other five satisfiability
conditions are gone.  Sixteen cases, compiled on the first attempt:

* **diagonal** — `test_test_equiv`; `chainloops_complete_free` for all
  FOUR chain-vs-chain combinations (both collapse targets are `Chain2`,
  so two-stride and three-stride mix freely); `chordloops_complete` for
  live-vs-live.
* **twelve mixed cells** — every one impossible, by
  `chain2_ne_test`, `chain3_ne_test`, `live_chord_ne_test`,
  `live_chord_ne_chain2`, `live_chord_ne_chain3`.
* **`hentB` supplied for free** — `wh_guards_agree_of_ule` gives
  `b ≡ b'`, so shared entry on the OUTER guard follows from `b` being
  satisfiable, which the live branch already provides.

**Why `hentC` stays.**  It is the one condition guard agreement cannot
reach: `b` and `b'` are loop guards of the two top-level loops, so
language equivalence pins them together, but `c` and `c'` sit INSIDE
the bodies where no such pinning applies.  The sketch at iteration 150
for deriving it stands unproved and is deliberately not claimed.

---

### The hardening campaign, closed out

Iteration 138 audited the six completeness theorems against their Lean
signatures and found the ledger had been calling them "unconditional"
when two carried satisfiability hypotheses.  Thirteen iterations later:

| theorem | before | after |
|---|---|---|
| `loopfree` | fragment only | unchanged |
| `atomicloops` | fragment only | unchanged |
| `gloops` | fragment only | unchanged |
| `chainloops_free` | fragment only | unchanged |
| `twoloops` | **+6 hypotheses** | **`_free` — 0** |
| `chordloops` | **+6 hypotheses** | **`_of_shared_entry` — 1** |

Roughly thirty lemmas, none of them new mathematics: collapse lemmas,
guard/acceptance primitives that generalize past their originating
fragment (`wh_den_nil`, `wh_guards_agree_of_ule`), stride invariants,
acceptance witnesses, vacuity results, and two shape classifications.
All of it existed only to make a word true that had been asserted
without being checked.

**The pattern worth carrying**: the prover never checks the prose.  Two
audits came back clean and two claims came back wrong, both of them
about how results were *described* rather than whether they *held* — and
that is exactly the exposure a machine-checked corpus has.

## Iteration 152 — ★ `chordloops_complete_free`: ALL SIX THEOREMS ARE NOW HYPOTHESIS-FREE ★

Iteration 150 recorded `hentC` — shared inner-guard entry — as the one
condition that resisted, with a five-step derivation sketched but not
claimed.  **It is derivable, and the sketch was the long way round.**

* **`chord_three_at_c`** [propext] — a chord loop owes THREE actions
  through a `c`-atom: at the post-`p` atom the branch guard holds, so
  the body still owes `x` and `y`.
* **`chord_shared_entry`** — if `c` and `c'` were disjoint, then at an
  atom where `c` holds the OTHER side's branch guard FAILS, so that
  side accepts a two-action string through it, while this side owes
  three.  Contradiction.
* **`chordloops_complete_free`** — the sixteen-case assembly with the
  hypothesis gone.

**Iteration 150's sketch forced all six action letters equal first, via
four separate matchings, and only then reached a contradiction.  None
of that is needed — no letters are matched at all.**  That is the
second time in this campaign that formalizing SHORTENED a hand
argument (iteration 144 was the first, cutting four steps to two).  The
lesson is consistent enough now to state: informal reasoning here has
systematically over-constrained the problem, reaching for equalities
the machine turns out not to need.

---

### The hardening campaign, final

| theorem | before iteration 138 | now |
|---|---|---|
| `loopfree_complete` | fragment only | unchanged |
| `atomicloops_complete` | fragment only | unchanged |
| `gloops_complete` | fragment only | unchanged |
| `chainloops_complete_free` | fragment only | unchanged |
| `twoloops_complete` | **+6 hypotheses** | **`_free` — 0** |
| `chordloops_complete` | **+6 hypotheses** | **`_free` — 0** |

**All six completeness theorems now assume nothing beyond membership in
their named fragment and language equivalence.**  "Unconditional" — the
word the ledger used for sixty iterations without checking it — is now
true.

Roughly thirty-five lemmas got it there, none of them new mathematics.
Several outlived their purpose: `wh_den_nil` and
`wh_guards_agree_of_ule` are general facts about loops, the stride
invariants are general facts about chain bodies, and the two shape
classifications are reusable normal forms.

**Tactic note**: `by_contra` is Mathlib; this cluster is Mathlib-free.
Use `refine Classical.byContradiction (fun h => ?_)`.

## Iteration 153 — auditing the AXIOMS themselves (the trusted base)

The hardening campaign's lesson was *the prover never checks the prose*.
The sharpest version of that exposure is one this ledger has never
audited: **are the axioms right?**  Everything proved here is
`EquivBA`-derivability, so if `EquivBA` is not GKAT-plus-Boolean-algebra
then the whole corpus proves something else.

**Verified internally this iteration:**

* **The axiom inventory.**  `Equiv` has exactly: equivalence (refl,
  symm, trans), congruence (seq_c, ite_c, wh_c), U1–U5, S1–S5, W1–W3.
  Nothing else.  U1 idempotence, U2 skew commutativity, U3 skew
  associativity, U4 guard absorption, U5 right distributivity; S1
  associativity and the four `0`/`1` laws; W1 unrolling, W2 tightening,
  W3 the fixpoint rule with side condition `E(e) ≡ 0`.
* **`E` matches the standard definition** — `act ↦ 0`, `test b ↦ b`,
  `seq ↦ ∧`, `ite ↦ (b∧E e) ∨ (¬b∧E f)`, `wh b _ ↦ ¬b`.
* **The model is the standard one.**  `GS A Atom = Atom × List (A × Atom)`
  is the guarded-string representation `α₀ p₁ α₁ … αₙ`, and soundness is
  PROVED, not assumed, for both layers: `GkatGS.sound` and
  `GkatFaithful.sound_BA`, each at `[propext, Quot.sound]`.
* **No axiom is stated as `axiom`.**  Everything is an inductive
  constructor of `Equiv`/`EquivBA`, so the trusted base is exactly the
  two inductive types plus Lean's own three axioms.

**One finding, and it is about a justification rather than a mistake.**
`EquivBA`'s Boolean layer is stated SEMANTICALLY: `baTest`, `ite_guard`
and `wh_guard` take `∀ X W x, bval W b x = bval W c x` — equality under
every carrier and valuation — where the paper's Figure 1 says the
congruence is generated together with THE LAWS of Boolean algebra,
i.e. syntactic BA-derivability.

These coincide, because equality in the free Boolean algebra on `T` is
exactly agreement under all Boolean valuations.  But **that coincidence
is assumed here, not proved and not cited** — and the direction of risk
is real: if semantic guard equality were STRICTLY WEAKER as a hypothesis
(i.e. the rule stronger), then `EquivBA` would be a stronger system than
GKAT + BA and every "provable from the finite axioms" claim would be
overclaimed by exactly that gap.

The file's docstring asserts the clauses "are required by Figure 1's
statement" — which is the right instinct, but it argues NECESSITY, not
SUFFICIENCY.  What is missing is the other direction: that they add
nothing beyond BA.

**Recorded as the first item of the trusted-statement-kernel work**:
either prove BA completeness for the free algebra on `T` in-repo, or
cite it explicitly at the definition site.  It is the one place where a
claim about what the axioms ARE rests on an unstated mathematical fact.

### Iteration 153 addendum — the axioms check out verbatim; one question survives, one is resolved

Compared the repo's `Equiv` against Figure 1 of the POPL'20 paper,
transcribed from the arXiv **LaTeX source of v4** rather than from
prose.  Result:

**★ ALL THIRTEEN AXIOMS MATCH EXACTLY. ★**

| | paper | repo |
|---|---|---|
| U1 | `e +_b e ≡ e` | `ite b e e ≈ e` ✓ |
| U2 | `e +_b f ≡ f +_b̄ e` | `ite b e f ≈ ite ¬b f e` ✓ |
| U3 | `(e +_b f) +_c g ≡ e +_{bc} (f +_c g)` | `ite c (ite b e f) g ≈ ite (b∧c) e (ite c f g)` ✓ |
| U4 | `e +_b f ≡ be +_b f` | `ite b e f ≈ ite b (b?·e) f` ✓ |
| U5 | `eg +_b fg ≡ (e +_b f)·g` | `ite b (e·g) (f·g) ≈ (ite b e f)·g` ✓ |
| S1–S5 | assoc, `0e=0`, `e0=0`, `1e=e`, `e1=e` | identical ✓ |
| W1 | `e^{(b)} ≡ e e^{(b)} +_b 1` | identical ✓ |
| W2 | `(e +_c 1)^{(b)} ≡ (ce)^{(b)}` | identical ✓ |
| W3 | `g ≡ eg +_b f ⟹ g ≡ e^{(b)}f`, if `E(e) ≡ 0` | identical ✓ |

Including the details that would be easy to get wrong: **U3's left
guard on the right-hand side is the PRODUCT `bc`**, and **U5 is stated
with the products on the left** — both as in the repo.  `E` matches on
all five clauses.

**And no Figure-2 fact is taken as an axiom.**  The paper's Figure 2
lists twelve DERIVABLE facts (U3′, U4′, U5′ left-distributivity, U6–U8,
W4–W7).  A formalization that assumed any of them would be strictly
stronger than the paper.  The repo's `Equiv` has exactly U1–U5, S1–S5,
W1–W3 and nothing else — checked constructor by constructor.

**Iteration 153's concern is RESOLVED by the source.**  I flagged that
the repo states the Boolean layer semantically while the paper says
"laws of Boolean algebra", and that the coincidence was assumed.  The
paper itself supplies it: `Bexp/≡_BA` is the free Boolean algebra on
`T`, and **`≡_BA` is complete for the truth-assignment semantics**.  So
the repo's `∀ X W x, bval W b x = bval W c x` IS `≡_BA`, on the paper's
own statement.  Citable, not assumed.

**One question survives, and it is the real one.**  The paper defines
`≡` as the smallest congruence *with respect to all operators*
satisfying Figure 1 and subsuming `≡_BA` **in the sense that
`b ≡_BA c` implies `b ≡ c`** — that is, subsumption stated at the TEST
level.  The repo additionally has `ite_guard` and `wh_guard`, which
transport Boolean equality through GUARD POSITIONS (`b ≡ c ⟹
e +_b f ≡ e +_c f`).  Whether that follows from "congruence with
respect to all operators" — treating the guard as an argument of `+_·`
— or is an addition beyond the paper is **not settled here**, and it
matters: if it is an addition, `EquivBA` is stronger than GKAT + BA and
the phrase "from the finite axioms" is off by exactly that.

**One representation note.**  `s6` (`b?·c? ≡ (b∧c)?`) has no counterpart
in Figure 1 because the paper does not need one: there `Bexp ⊆ Exp` and
Boolean `·` IS sequencing, the same symbol.  This repo keeps `BExp` and
`Exp` as separate types, so `s6` is the bridge that identification
requires.  Sound (it is inside the proved `sound_BA`), and forced by the
representation rather than added to the theory — but worth stating as
such.

**And the campaign's framing is confirmed verbatim.**  The paper's UA
is: any Salomaa system of left-affine equations has AT MOST one solution
— existence explicitly NOT assumed, citing Kozen–Tseng.  For `n = 1`,
W1 gives existence and W3 gives uniqueness.  **"UA is precisely the
multi-variable generalization of W3"** — which is exactly what this
programme has been claiming to eliminate, stated in the source's own
terms.

## Iteration 154 — the trusted base now states what it rests on

The surviving audit question was whether `ite_guard`/`wh_guard` — guard-
position transport of Boolean equality — is part of the paper's
congruence or an addition beyond it.  **Settled by inspection, and the
answer is recorded at the definition site rather than in a ledger.**

**The inspection**: no Figure-1 axiom ever replaces a guard by a
BA-equal one.  Every guard-bearing axiom fixes its guards
SYNTACTICALLY — U1, U4, W1 carry a single `b` on both sides; U2 negates
it (`b̄`); U3 forms a product (`bc`); U5 and W2 likewise.  **So guard
transport is not derivable from the equations.**

**And it is indispensable, not optional.**  U2 applied twice gives
`e +_b f ≡ f +_{b̄} e ≡ e +_{¬¬b} f`.  Without guard transport the
theory cannot return to `e +_b f` — it could not undo a double negation
in a guard.  A reading of the paper on which guard transport is absent
would make GKAT pathologically weak, which is strong evidence the
intended reading is that `+_·` and `·^(·)` take their guard from
`Bexp ⊆ Exp` and the congruence clause covers it.

**Recorded honestly as a READING.**  `EquivBA`'s docstring now gives the
provenance of every clause beyond `Equiv`: which are congruence at
operand positions, which is the `≡_BA`-subsumption clause verbatim
(with the paper's own free-BA completeness explaining why the semantic
formulation is not stronger), which are congruence at guard positions
**under a stated reading, with the consequence spelled out if the
reading is wrong**, and which is a representation bridge forced by
keeping `BExp` and `Exp` as separate types.

That last distinction matters and had never been written down: `s6` is
not an extra axiom about GKAT — in the paper `b·c` and `b ∧ c` are
literally the same term, because `Bexp ⊆ Exp` and Boolean product IS
sequencing.  Separating the types is this development's choice, and
`s6` is its cost.

**Why this is the right form of the fix.**  The hardening campaign's
finding was that the prover never checks the prose.  A ledger entry is
prose too.  Putting the provenance in the docstring at the definition
puts it where anyone auditing `EquivBA` will read it — and states the
one place a claim rests on interpretation rather than on a theorem,
along with exactly what would follow if the interpretation were wrong.

**Trusted-base status**: axioms verbatim-verified against the LaTeX
source (153); no Figure-2 derivable fact assumed; soundness proved not
assumed; `sorry`-free; the sole interpretive dependency identified,
argued, and documented in place.

## Iteration 155 — the SEMANTICS is audited: ULE is the paper's equality, not something stronger

Continuing the trusted-base work.  Every completeness theorem here has
the shape `UniformLanguageEquivalent e f → EquivBA e f` — and ULE
quantifies over ALL carriers and valuations, whereas POPL'20 fixes a
finite `T` and takes guarded strings over its ATOMS.

**The risk was directional and real.**  If ULE were STRICTLY STRONGER —
harder to satisfy — then `ULE → EquivBA` would cover FEWER pairs than
the paper's completeness statement, and calling the six theorems
"completeness" would overclaim.  A weaker hypothesis makes a stronger
theorem; a stronger hypothesis quietly makes a weaker one.

**`ule_iff_generic`** [propext, Quot.sound] settles it:

    UniformLanguageEquivalent e f
      ↔ ∀ gs, den (genW T) e gs ↔ den (genW T) f gs

Quantifying over all carriers adds NOTHING beyond the truth-assignment
model, whose atoms are exactly the assignments `T → Bool`.  So the
hypothesis of every completeness theorem here IS the paper's semantic
equality.

**The reduction was already implicit** in `ule_iff_start_bisim`, which
silently used it in its reverse direction: `bval` factors through the
generic valuation (`bval_gen`), so a language is determined by its
behaviour at `genW T`, and `uniformStateEquiv_of_gen` lifts that from
the generic valuation to all of them.  Stating it outright means the
claim can be checked without reading another proof to find it.

**Trusted-base status after 153–155.**  Four things an auditor would
want, now each either proved or documented in place:
1. **The axioms** — verbatim against the LaTeX source; no Figure-2
   derivable fact assumed; no `axiom` declarations.
2. **The Boolean layer** — provenance of every clause at the definition
   site, with the one interpretive dependency (guard-position
   congruence) argued and its consequence-if-wrong spelled out.
3. **The model** — standard guarded strings; soundness PROVED for both
   layers, not assumed.
4. **The semantics of the hypothesis** — ULE is the paper's equality
   (today).

What remains of the queued STEELMAN list: edge cases (empty `T`, empty
`A`), and a differential-testing harness for `uleDec` against a
reference implementation.  Both are finite and neither touches the open
mathematics.

## Iteration 156 — the decider is EXECUTED, not just proved

Every audit in 153–155 was about STATEMENTS: are the axioms the
paper's, is the Boolean layer faithful, is the hypothesis's semantics
the right one.  None of them tests COMPUTATION.  `uleDec` is a genuine
decision procedure — Lean accepts it without `noncomputable` — so it
can be RUN, and running it exercises the whole stack (Thompson
construction, trimming, bisimilarity quotient, decidable equality)
against expected answers in a way a proof about those same definitions
structurally cannot.

**Ten smoke tests, all correct**, now in the file as regression checks:

| test | expected | got |
|---|---|---|
| `p ≟ p` | true | ✓ |
| `p ≟ q` (distinct actions) | false | ✓ |
| `p +_b p ≟ p` (U1) | true | ✓ |
| `1? ≟ p` (test vs action) | false | ✓ |
| `p^(0) ≟ 1?` (**W5**) | true | ✓ |
| `p^(1) ≟ 0?` (**W6**, divergence is empty) | true | ✓ |
| `p·1? ≟ p` (S5) | true | ✓ |
| `p·0? ≟ 0?` (S3) | true | ✓ |
| `p +_b q ≟ p +_{¬¬b} q` (guard BA-equality) | true | ✓ |
| `p +_b q ≟ q +_b p` (branches swapped) | **false** | ✓ |

**Three of these are load-bearing rather than decorative.**

* **W5 and W6 are Figure-2 DERIVABLE facts** — the paper's `e^{(0)} ≡ 1`
  and `e^{(1)} ≡ 0`.  Neither is an axiom here, so the decider agreeing
  with them is independent evidence that the model computes the paper's
  semantics.  W6 in particular checks that a productive loop which never
  exits denotes the EMPTY language, which is the subtlest point in the
  whole guarded-string model and the one iteration 135's
  `diverging_region_zero` is about.
* **The last two are negative controls.**  A decider that always
  answered "true" would pass seven of these; it fails on distinct
  actions, on test-vs-action, and on swapped branches.  The
  swapped-branch case is the sharpest: `p +_b q` and `q +_b p` have the
  same subterms and differ only in order, so it catches a model that
  had lost track of which branch the guard selects.
* **The `¬¬b` case** confirms guard Boolean-equality is respected by the
  MODEL, which is the semantic counterpart of iteration 154's
  guard-position congruence question.  If the model did not identify
  BA-equal guards, `sound_BA` could not hold — and here it is,
  computed.

**STEELMAN list status.**  Trusted base (axioms, Boolean layer, model,
hypothesis semantics) audited across 153–155; executable validation done
today.  What remains queued is edge cases (empty `T`, empty `A`) — and
note the theorems are polymorphic in both, so Lean has already checked
them there; what an edge-case pass would add is NON-VACUITY evidence,
not soundness.

## Iteration 157 — ★ ITERATION 154 WAS WRONG: guard transport IS derivable, and it is now proved in-repo ★

Iteration 154 asserted, on the strength of an inspection I described as
settling the matter, that guard-position transport is **not** derivable
from Figure 1 — and wrote that into `EquivBA`'s docstring as the one
place a claim rests on interpretation.  **Both of its specific claims
were false.**

* I wrote: "U2 applied twice gives `e +_{¬¬b} f`, so without guard
  transport the theory could not even undo a double negation."
  **U2 applied twice IS the undoing.**
  `e +_b f ≡ f +_{b̄} e ≡ e +_{¬¬b} f` is a DERIVATION, not an
  obstacle.  I read a two-step derivation as a trap.
* I wrote: "guard transport is NOT derivable from the equations."
  **It is**, and the derivation is short.

**`GkatGuardTransportProofs.lean`** (new, in the lakefile, `[propext]`,
sorry-free) settles it against a DELIBERATELY WEAKENED relation:
Figure 1, plus `≡_BA` at TEST positions, plus the `s6` representation
bridge, with congruence at **operand positions only** — no
guard-position constructor anywhere.  In that relation:

* **`ite_guard`** — `b ≡_BA c → (e +_b f) ≡ (e +_c f)` — is a THEOREM.
  Route: `U2×2 → U6 → U8 → U8' → U4' → canon → transport`.
* **`wh_guard_productive`** — the same for loops with productive bodies,
  via `W1 + ite_guard + W3`.

**The route matters, and this is the part I would have got wrong.**  The
published derivation of U8 goes through U5' and U3' — but U3' is itself
derived using a guard-transport step, so **the published route is
circular for this purpose.**  The proof instead instantiates the AXIOM
U3 at `e := 0`, `b := 1`, `c := b̄`.  Anyone re-deriving this from the
paper's Figure 2 would walk straight into the circularity.

**Consequence, and it is entirely good.**  `EquivBA` does NOT exceed the
paper's `≡`: the two guard constructors are admissible, so the relation
is the same with or without them.  **The interpretive dependency
identified at 153–154 is gone** — not resolved by argument, discharged
by proof.  Every downstream claim of provability "from the finite
axioms" now stands without a reading attached.

**The lesson, sharper than the earlier ones.**  The hardening campaign's
finding was *the prover never checks the prose*.  Iteration 154 was that
failure in its purest form: I inspected thirteen axioms, drew a
metatheoretic conclusion — "not derivable" — and wrote it into the
source as established.  A negative claim about derivability is exactly
what inspection cannot establish, and I asserted one anyway.  **The fix
was not to argue better but to build the weakened relation and let the
prover answer.**  That is now a file rather than a paragraph.

**Trusted base, final**: axioms verbatim; no Figure-2 fact assumed; the
Boolean layer's every clause with proved provenance and NO remaining
interpretive dependency; soundness proved; ULE proved to be the paper's
semantics; the decider executed on ten cases including negative
controls.

## Iteration 158 — the admissibility gap is narrower than it looked: `wh_guard` is barely used, and its main use needs nothing

Iteration 157 proved `ite_guard` admissible unconditionally and
`wh_guard` admissible for PRODUCTIVE bodies.  That left a gap — general
loop-guard transport — whose closure would need porting the productive-
loop normalization (`dPart`, `fundamental`) into the standalone file, a
substantial job.  **Checking where `wh_guard` is actually used shrinks
the gap to almost nothing.**

**`EquivBA.wh_guard` is used in exactly TWO places in the entire
development**, both wrappers in `GkatChainFragmentProofs`:
`wh_guard_semantic_zero` (swap the guard to `0`) and
`wh_guard_semantic_one` (swap it to `1`).  Nothing else in ~40 files
touches it.

**The `0` case needs no loop-guard transport at all.**  Three new
theorems in the standalone weakened relation, all `[propext]`:

* `ite_one` — `e +_1 f ≡ e`, from U8 and S4.
* **`u7`** — `e +_0 f ≡ f`, via U2, the derived `ite_guard`, and
  `ite_one`.
* **`wh_zero_free`** — **a loop with a semantically-false guard is
  `skip`, with NO transport on the LOOP.**  W1 moves the guard into an
  `ite`, where the now-derived `ite_guard` applies, and U7 finishes.

So the wrapper the development leans on most is derivable without
`wh_guard` entirely.  The trick generalizes the point of 157: **W1 turns
a loop-guard question into a conditional-guard question**, and
conditional guards are settled.

**What is left of the gap.**  Only `wh_guard_semantic_one`, and only
because its composite target (`wh b e ≡ 0` for a valid guard) routes
through exit emission rather than unrolling: `wh_emits_exit_all` gives
`wh b e ≡ (wh b e)·(¬b)?`, and with `b ≡_BA 1` that is `·0?`, hence `0`
by S3.  That derivation also uses no `wh_guard` — but it lives on
`productive_loop`, which has not been ported to the standalone setting,
so it is verified in the repo rather than in the deliberately weakened
relation.

**Honest status of the admissibility claim.**  `ite_guard`: proved
admissible outright.  `wh_guard`: proved admissible for productive
bodies; its two actual uses are one case proved transport-free and one
case whose repo derivation is transport-free but not yet reproduced in
the weakened relation.  **No claim anywhere in the development depends
on an unproved reading** — which is the property iteration 154 wrongly
asserted was unavailable, and 157–158 have now actually established.

## Iteration 159 — `wh_guard` eliminated from the census layer; two structural uses remain repo-wide

Iteration 158 relied on a reported count of `wh_guard` uses.  **Grepped
it myself, and the report was low**: there were SIX, not two — the four
extra were my own, introduced during this session's hardening work
(`twoLoop_b_valid`, `twoLoop_c_valid`, and the two shape
classifications), every one of them the `wh_guard (c := .one)` idiom
followed by `wh_one_zero`.  Same lesson as 154, one level down: I
repeated a number instead of checking it.

**`wh_valid_zero`** (ZERO axioms) removes the idiom entirely:

    (∀ α, bval b α = true) → wh b e ≡ 0?

`wh_emits_exit_all` says every loop provably ends in its exit guard
`¬b`; when `b` is valid that guard is `0`, and `s3` finishes.  No
loop-guard transport, no productivity hypothesis, any body.  All four
census uses now go through it, and **`GkatCensusProofs.lean` contains no
use of `EquivBA.wh_guard` at all**.

**Repo-wide, actual uses are now down to two**, both wrappers in
`GkatChainFragmentProofs`, and both with known transport-free routes:
* the `0` wrapper — `GkatGuardTransport.wh_zero_free`'s route (W1 moves
  the guard into an `ite`, then U7);
* the `1` wrapper — `wh_valid_zero`'s route above.

(The third hit, in `GkatElimProofs`, is the `wh_guard` CASE of the
substitution homomorphism's induction, not a use of the rule — it has to
be there as long as the constructor exists.)

**Also verified directly rather than by report**: `GkatNormalizationProofs`
contains no `wh_guard` at all, so the `productive_loop` →
`wh_emits_exit_all` → `wh_one_zero` chain that `wh_valid_zero` rests on
is genuinely transport-free.  That was the load-bearing assumption in
158's argument and it holds.

**Where this leaves the constructor.**  `EquivBA.wh_guard` is now used
twice in ~40 files, both replaceable.  Doing so would make it entirely
unused, at which point it could be deleted and the admissibility
question would not merely be answered but be moot.  `ite_guard` is a
different matter — used in ~40 files and genuinely convenient — but
iteration 157 already proved it admissible outright, so its presence
costs nothing.

## Iteration 160 — `wh_guard` is now UNUSED across the whole development — and deliberately kept

Rewrote the last two uses, both wrappers in `GkatChainFragmentProofs`,
transport-free.  **Both are now at ZERO AXIOMS**, where before they
invoked the `wh_guard` constructor:

* `wh_guard_semantic_one` — `wh_emits_exit_all` gives `wh b e ≡
  (wh b e)·(¬b)?`; a valid guard makes `(¬b)?` be `0?`, and `s3`
  finishes.
* `wh_guard_semantic_zero` — `w1` moves the guard into an `ite`, where
  guard equality is admissible (iteration 157), and `ite_zero` finishes.

**`EquivBA.wh_guard` now has NO uses anywhere in ~40 files.**  The only
remaining occurrences are its own declaration and two INDUCTION CASES
(`GkatElimProofs`' substitution homomorphism, `GkatModelProofs`' model
interpretation) which exist solely because the constructor does.

**Considered deleting it, and decided not to — the reason is the
interesting part.**  Deleting would make the admissibility question moot
and make every theorem a claim about a strictly smaller system, which
sounds like a pure gain.  But `wh_guard`'s general admissibility (for
NON-productive bodies) is still unproved, so a relation without it might
be strictly weaker than the paper's `≡` — and then the corpus would be
proving completeness for **a different system than GKAT**.  Stronger
results, less faithful claim.  Faithfulness is the property this whole
audit has been protecting, so the constructor stays.

**What can be said instead, and it costs nothing.**  Since no proof uses
it, **every theorem in the development is already provable in `EquivBA`
minus `wh_guard`.**  That is strictly stronger than the theorems as
stated, holds without touching a definition, and leaves the stated
results faithful to the paper.  Both readings are now available to a
reader, which is better than picking one.

**The guard-transport thread, closed** (154 → 160):
* 154 asserted guard transport underivable — **wrong**, and wrong in the
  one way inspection cannot catch (a negative derivability claim).
* 157 proved `ite_guard` admissible outright, against a deliberately
  weakened relation, avoiding the published route's circularity.
* 158 proved the `0` case of loop transport needs nothing.
* 159 removed the idiom from the census layer via `wh_valid_zero`, after
  finding my own use-count had been reported low.
* 160 removed the last two uses, leaving the constructor unused.

## Iteration 161 — ALL TWELVE of the paper's derivable facts confirmed by execution

Iteration 156 executed the decider on ten smoke tests, two of which
(W5, W6) were Figure-2 facts.  This iteration does the **remaining ten**,
plus a negative control.  Every one agrees:

| Figure-2 fact | statement | decider |
|---|---|---|
| U3′ | `e +_b (f +_c g) ≡ (e +_b f) +_{b+c} g` | true ✓ |
| U4′ | `e +_b f ≡ e +_b b̄f` | true ✓ |
| **U5′** | `b(e +_c f) ≡ be +_c bf` | true ✓ |
| U6 | `e +_b 0 ≡ be` | true ✓ |
| U7 | `e +_0 f ≡ f` | true ✓ |
| U8 | `b(e +_b f) ≡ be` | true ✓ |
| W4 | `e^{(b)} ≡ e^{(b)}·b̄` | true ✓ |
| W4′ | `e^{(b)} ≡ (be)^{(b)}` | true ✓ |
| W6′ | `b^{(c)} ≡ c̄` | true ✓ |
| W7 | `e^{(c)} ≡ e^{(bc)}·e^{(c)}` | true ✓ |
| W5, W6 | (iteration 156) | true ✓ |
| **negative control** | full left distribution `e(f +_c g) ≡ ef +_c eg` | **false** ✓ |

**Why this is worth having.**  None of the twelve is an axiom in this
development — `Equiv` carries only U1–U5, S1–S5, W1–W3.  So the decider
agreeing with all twelve is **independent evidence that the model
computes the paper's semantics**, obtained by running code rather than
by reading definitions.  Twelve published theorems, twelve agreements.

**The negative control is the sharpest of the set.**  U5′ says left
distribution IS valid when the left factor is a TEST; the control says
it FAILS for a general left factor — and those two sit adjacent in the
table, differing only in whether `b` is a test or an action.  The
decider distinguishes them.  That matches the repo's own machine-checked
`left_distrib_fails` / `left_distrib_not_ba_theorem`, now confirmed a
second way: once by proof, once by computation.

**Validation status.**  The trusted base is audited (axioms verbatim,
Boolean layer with proved provenance, model standard, soundness proved,
hypothesis semantics proved to be the paper's), the one interpretive
dependency is discharged (157–160), and the model is now cross-checked
against every derivable fact the paper lists, plus a control that
distinguishes the valid fragment of left distribution from the invalid
one.

## Iteration 162 — the published record catches up with the validation work

Iterations 153–161 audited the trusted base, discharged the guard-
transport question, and cross-checked the model by execution — and none
of it had reached the artifact, which still described only the
mathematics.  That gap mattered: **the validation is arguably the most
credible part of the campaign**, and it existed only in a ledger.

Added a **"How this is checked"** section, opening on the reason it
exists — *a machine-checked corpus is exposed in one specific way: the
prover verifies the proofs, never the prose around them* — and listing
what was audited rather than assumed:

* **the axioms** — all thirteen verbatim against the LaTeX source,
  including U3's product guard and U5's orientation; no derivable fact
  assumed; no `axiom` declarations.
* **guard transport** — admissible, proved against a deliberately
  weakened relation, with the note that the published route to it is
  circular and a different U3 instantiation avoids that.
* **the semantics** — proved equal to the paper's, with the reason it
  matters stated: a stronger hypothesis would quietly make the theorems
  cover fewer pairs.
* **soundness** — proved for both layers, not cited.
* **execution** — 12 of 12 derivable facts, plus the control separating
  valid from invalid left distribution.

And added iteration 154 to the corrections log as the sharpest entry:
asserting a NEGATIVE derivability claim from inspection, writing it into
the source as established, and being wrong — with the fix recorded as
*build the weakened relation and let the prover answer*.

**Why the corrections stay on a public page.**  A status document that
lists only wins is not checkable.  Five entries now, each naming what
was claimed, what was wrong, and what closed it.  The campaign's
credibility rests more on those than on the theorem count — and
iteration 154's entry is the one that best demonstrates the discipline,
because it is a case where the ledger's own method caught the ledger's
own error.

## Iteration 163 — the guard-transport story is now COMPLETE up to one named published lemma

Iteration 160 kept `EquivBA.wh_guard` (unused but faithful) partly
because its GENERAL admissibility — non-productive bodies — was
unproved, so removing it might have made the relation strictly weaker
than the paper's.  **That residue is now reduced to a single named
lemma.**

**`wh_guard_of_norm`** [propext]: general loop-guard transport follows
from **POPL'20 Lemma 3.9 alone** — every loop is equivalent to one with
a productive body — and from nothing else.  Given the normalization,
route `wh b e ≡ wh b ê ≡ wh c ê ≡ wh c e`, the middle step by
`wh_guard_productive`.

**Why this is worth the four lines.**  It converts "the general case is
open in this file" into "the general case is exactly Lemma 3.9" — a much
smaller and much more useful statement, because the main development
**already proves that lemma** (`GkatNormalization.productive_loop`), and
because iteration 159 verified BY GREP that `GkatNormalizationProofs`
contains no `wh_guard`, so there is no circularity in appealing to it.

So the position is now precise on both sides:
* **In the weakened relation** (congruence at operand positions only):
  `ite_guard` outright; `wh_guard` for productive bodies; general
  `wh_guard` modulo Lemma 3.9, which is not ported here.
* **In the main development**: Lemma 3.9 is proved, transport-free.  So
  general loop-guard transport is admissible there too — the only thing
  missing is that the two halves live in different files.

**And the practical consequence is unchanged and better justified.**
`wh_guard` has no uses anywhere; `ite_guard` is admissible outright.
Every theorem in the corpus is provable in `EquivBA` minus `wh_guard`,
and — given the above — that relation is not weaker than the paper's.
The reason iteration 160 gave for keeping the constructor (faithfulness
risk) has now largely evaporated; what remains is a file-organization
gap, not a mathematical one.

**Guard-transport thread, final** (154 → 163): a false negative claim,
corrected by building a weakened relation and proving admissibility;
every use in ~40 files then eliminated; and the last general case
reduced to a single published lemma the repo already has.

## Iteration 164 — MEASURED: same-side bisimilarity is ubiquitous, not a corner case

Iteration 131 proved a sharp dichotomy: **either a program's automaton
is already its own bisimulation collapse — in which case same-side UNIF
is VACUOUS and a commuting partner map exists — or same-side UNIF is
exactly the price.**  That left an obvious empirical question never
asked: **how often are Thompson automata already collapsed?**

Added `min_classes` to the census harness (the same partition-refinement
fixpoint it already runs on trimmed sums, applied to a single automaton)
and measured, over 60,000 generated program automata per configuration:

| atoms | automata | NOT already minimal | states collapsed |
|---|---|---|---|
| 2 | 60,000 | **58,724 (97.9%)** | 133,770 |
| 4 | 60,000 | **58,466 (97.4%)** | 89,493 |

**Essentially every Thompson automaton has distinct bisimilar states** —
roughly 1.5–2.3 of them collapse per automaton.  The dichotomy's
"collapsed" branch fires in about 2% of cases.

**What this settles, and it is not what I hoped.**  I had wondered
whether Thompson automata might usually be collapsed, which would have
made same-side UNIF a rare corner case and the campaign's residue much
smaller.  **They essentially never are.**  Same-side UNIF cannot be
dismissed as an edge case; it is the common case, which is consistent
with its being the core difficulty rather than an artifact of the route.
It also closes off routing around the problem via "assume the automaton
is collapsed" — that assumption would discard 97% of instances.

**What it does NOT settle, and the distinction matters.**  Being
non-minimal does not make an instance HARD.  The literature's canonical
cause of same-side bisimilarity is duplicated subterms, and iteration
124 proved that case costs nothing: `ite c p p`'s two branch states
carry LITERALLY EQUAL labels, so UNIF there is `rfl`.  The 97% figure
counts bisimilar PAIRS, not difficult ones.

**The measurement that would actually discriminate**: of the bisimilar
state pairs, what fraction have syntactically DIFFERENT standard labels?
Those are the ones needing real work; the rest are `rfl`.  The harness
works on abstract automata without labels, so that measurement needs the
Thompson labelling threaded through — a bigger change than today's, and
the natural next experiment.

**Honest reading**: a negative datum, recorded because it removes a
hoped-for shortcut rather than because it advances the proof.  The
dichotomy stands; its cheap branch is empirically empty.

## Iteration 165 — full-cluster regression check after the audit edits

The 153–163 audit touched files that ~40 others depend on:
`GkatFaithfulnessProofs` (the `EquivBA` docstring — the definition
itself untouched), `GkatChainFragmentProofs` (both loop wrappers
rewritten transport-free), `GkatDecideProofs` (the `uleDec` docstring),
`GkatCensusProofs` (extensively), and the lakefile (one new library).
Every check so far had been per-library.

**Built all 191 Gkat libraries explicitly** — the cluster has no default
target, so `lake build` alone is a no-op, which is exactly the trap that
makes a "clean build" easy to believe without having one.

    385 jobs — Build completed successfully

No errors, no `sorryAx`, no `declaration uses sorry` warnings anywhere in
the cluster.

**Two things worth recording from the mechanics**, both of which would
have produced a false all-clear:

* `lake build` with no argument reports success having done NOTHING
  ("0 jobs").  A regression check that reads only the exit status would
  pass on a broken tree.
* In `zsh`, an unquoted `$LIBS` is NOT word-split, so
  `lake build $LIBS` passes all 191 names as ONE target and fails with
  "unknown target" — which at least fails loudly.  `xargs` is the fix.

The pattern is the same one this campaign keeps meeting from a different
direction: a check that appears to pass because it never ran.  Same
family as an axiom profile nobody printed, or a use-count repeated
rather than grepped.

## Iteration 166 — same-side UNIF is not always `rfl`, and the frequency question hits a tooling wall

Iteration 164's follow-up: of the ubiquitous bisimilar state pairs, how
many have SYNTACTICALLY DIFFERENT labels?  Those need real proof; the
rest are `rfl` (iteration 124).

**The scale measurement failed, and the reason is worth recording.**
Counting such pairs across an automaton means calling `uleDec` on every
pair of labels — and each call rebuilds and trims a Thompson SUM and
decides bisimilarity on it.  At elaboration time that exceeded a
ten-minute budget on four small expressions, one containing a loop.
**`uleDec` is decidable but not cheap**, and elaboration-time `#eval` is
the wrong place to run a census.  Killed it rather than let it run.

**A single decisive witness does the qualitative job.**  Inside
`ite b (p ; (q +_b q)) (p ; q)`, the two post-`p` continuations are
`q +_b q` and `q`.  Executed:

* `uleDec (q +_b q) q` → **true** (language-equal)
* `(q +_b q) = q` → **false** (syntactically different)

So **same-side unification is not always `rfl`** — there really are
bisimilar state pairs whose labels differ syntactically.  Iteration 124
discharged the duplicated-subterm case; this shows that case is not the
only one, which is what 164 left open.

**Honest limits of the witness.**  It is EASY: the two labels differ by
U1, one axiom.  It establishes that the trivial case is not exhaustive,
NOT that hard cases are common — and iteration 122 already showed
same-side UNIF can embed an arbitrary cross-side instance, so hard cases
certainly exist.  What stays unmeasured is the DISTRIBUTION: what
fraction of bisimilar label pairs need more than a couple of axioms.

**What that measurement would need**: the Rust census harness with the
Thompson labelling threaded through, so equivalence is decided by the
fast automaton path rather than by re-elaborating Lean per pair.  That
is a real piece of work and is now the named next experiment — with the
performance reason for doing it there rather than in Lean recorded, so
the next attempt does not repeat today's dead end.

---

## Iteration 167 — THE MASKING LEMMA: the `seq` half of same-side unification, PRICED AND PAID

Two housekeeping acts and one real theorem.

**Housekeeping first.** The two GKAT memory files had grown to 194KB
combined (72KB + 121KB) — append-only logs loading into every session.
That is not recall, it is crowding.  Both rewritten as durable facts
only (6KB + 5KB); the narrative already lives here, in git, where it
belongs.  The rule I broke and am now recording: **memory is curated,
not append-only** — a memory file that reads like this ledger has stopped
being a memory file.

**The theorem.**  Iteration 133 refuted bisimilarity reflection at `seq`:
two states of `e` can be bisimilar inside `seq e f` while `e` alone
distinguishes them.  That refutation said only THAT reflection fails.
It never said what the failure COSTS — and for 34 iterations I have been
treating it as an obstruction rather than asking for its price.

The price is small and it is now paid.

A state's standard label is a guarded fold whose fallback is its exit.
Inside `seq e f` the exit becomes `exit ; F`, with `F` the label of `f`'s
start.  So two states of `e` whose exit TESTS differ still carry
EquivBA-equal labels inside the composite exactly when `F` is dead on the
region where the exits differ.  **Masking is nothing else**: a difference
survives the composite iff the continuation is live where the difference
lives.

`GkatCensus.seq_mask_of_dead_region` (GkatCensusProofs.lean):

    hdead  : EquivBA (test r ; F) (test 0)
    hagree : ¬r ∧ c  =  ¬r ∧ d   (semantically, at every valuation)
    ⊢ EquivBA (test c ; F) (test d ; F)

Proof: split on `r` with U1 (duplicate the branch), gate the THEN branch
with U4 and the ELSE branch with `gate_else` (U2, U4, U2, and `¬¬r = r`
by `baTest`); the `r` branch dies via `dead_conj` (S6 to fuse the tests,
`and_comm_test` to commute them, S1 to reassociate, the certificate, S3);
the `¬r` branches match by `baTest` on `hagree`.

**`#print axioms` on all four new theorems: does not depend on any
axioms.**  Not `[propext]` — nothing at all.  U1, U2, U4, S1, S3, S6,
`baTest`, congruence.  No uniqueness axiom.  Not even W3.

Also landed:
* `seq_mask_of_dead_tail` — the degenerate case `F` itself dead, which is
  where the 133 counterexample actually lived, now discharged outright.
* `guardedFold_congr_fallback` — the dual of `foldr_congr_equivBA`
  (that one varies the SOLUTION under a fixed fallback; this varies the
  FALLBACK under fixed branches).  The exit IS the fallback, so this is
  what lifts masking from an exit test to a whole label.
* `label_mask_of_dead_region` — the composite: two states of `e` agreeing
  on every transition and differing only in halt carry EquivBA-equal
  labels inside `seq e f`, given the certificate.

**Why this is the biggest available step.**  It converts the standing
`seq` obstruction into a side condition WITH A NAMED DISCHARGER.  The
side condition is a dead-region certificate — and `diverging_region_zero`
(iteration 136) already produces exactly those for loops, from two guard
implications.  The two open pieces were never independent: **S0's
divergence region is the certificate that the `seq` half of same-side
UNIF consumes.**  That link is new today.

**What is NOT proved, stated plainly.**  This handles states agreeing on
transitions and differing only in halt.  General same-side UNIF also has
to handle states whose TRANSITION LISTS differ, which is the size
induction, untouched.  And the side condition's NECESSITY is unproved: I
believe the dead-region hypothesis is exactly right rather than merely
sufficient, and iteration 154 is the standing reminder that a belief
about derivability is worth nothing until the prover rules.  Do not read
this entry as more than it says.

**Odds, unchanged at ~46%**, and the field's prior remains that this
problem does not close.  Today removed an obstruction I had been carrying
as structural; it did not touch the size induction, which is still the
mountain.

---

## Iteration 168 — MASKING NEEDS NO CERTIFICATE, AND THE SAME-BRANCHES CASE FALLS

Yesterday's masking lemma shipped with a hypothesis: a region `r` on which
`F` is provably zero, with `diverging_region_zero` named as the intended
supplier and the S0 divergence region named as the link.  **That was one
step too timid, and today's first act is to retract it.**

The region is not something to search for.  It is already determined by
the two exit tests: **take `r := c ∧ ¬d`, the region where they disagree.**
If the two composites are language-equal at all, then `test (c ∧ ¬d) ; F`
has empty language — the hypothesis says exactly that — and
`nullLanguage_complete` turns empty language into a proof of `0` from the
finite axioms.  The dead-region hypothesis discharges ITSELF.

`GkatCensus.seq_mask_complete`:

    UniformLanguageEquivalent (test c ; F) (test d ; F)
      →  EquivBA (test c ; F) (test d ; F)

Unconditional.  No side condition, no expressibility question about
"where `F` is dead", **and no appeal to the S0 divergence region after
all** — yesterday's claimed link between the two open pieces was real
mathematics but the wrong direction: S0 is not needed here.  Recording
that as a correction, not a refinement.

Supporting: `den_test_seq` (a leading test just gates `F` at the start
atom) and `mask_region_empty` (the disagreement region is uniformly
empty).  Axioms `[propext, Classical.choice, Quot.sound]`, inherited
entirely from `nullLanguage_complete` — the same profile as the six
completeness theorems.

**Then the second half: the fallback is only observed where every guard
fails.**  `guardedFold_congr_fallback` (yesterday) demands the two
fallbacks be equal EVERYWHERE.  A label never asks that much: the
fallback is the state's EXIT, taken only at atoms where no transition
guard fires.  So:

* `fallbackRegion B` — every guard of `B` false.
* `ite_else_congr_gated` — the else arm need only agree UNDER `¬g`
  (U2 flips, U4 asserts, `¬¬g = g` flips back).
* `seq_test_guardedFold` — an assertion pushes through a whole fold,
  conjoining onto every guard, via `test_seq_ite` (the valid test-only
  fragment of left distribution — full left distribution is refuted, and
  is a standing negative control in the smoke tests).
* `guardedFold_congr_fallback_gated` — the honest congruence.  Proved by
  a RELATIVIZED induction: the statement carries an accumulated assertion
  `r`, each `ite` contributes its own `¬g` to it, and
  `test_seq_guard_congr` re-associates.  The un-relativized statement
  does NOT go through — the inductive hypothesis is strictly too weak,
  which is why yesterday's version had the blanket hypothesis.

Composing the two halves:

**`label_mask_complete_gated` — THE SAME-BRANCHES CASE OF SAME-SIDE
UNIFICATION.**  Two states of one automaton that agree on every
transition carry provably equal labels as soon as their exits are
language-equivalent on the region where the exit is actually taken.  No
minimality, no productivity, no certificate, no uniqueness axiom.

Six new theorems; four report NO axioms at all, two carry
`nullLanguage_complete`'s profile.  `lake build GkatCensusProofs` clean,
first try, both halves.

**What remains, stated without inflation.**  Same-side UNIF still needs
the case where the two states' TRANSITION LISTS differ — the size
induction, untouched by today.  What today removes is the halt/exit
dimension of the problem entirely: exits can now be reconciled whenever
the languages permit, so the induction only ever has to fight about
transitions.  That is a real narrowing of the remaining work, not a
solution to it.

**Odds: ~52%**, up from 46.  Two consecutive iterations have found the
standing obstruction cheaper than advertised, and the second one showed
the first was still overpricing it.  The mountain is unmoved; the foothills
are gone.  The field's prior that this problem does not close still stands
and I am not claiming otherwise.

**Method note, and it is the same one as yesterday, sharper.**  Yesterday
I asked "what does the refutation cost?" and got a certificate.  Today I
asked "who pays the certificate?" and the answer was: the hypothesis
already did.  **When a lemma ships with a side condition, ask whether the
theorem's own hypothesis already implies it before going looking for a
supplier.**  I have now over-priced this same obstruction twice in two
days.

---

## Iteration 169 — DECISION LISTS THAT DECIDE THE SAME THING ARE PROVABLY EQUAL

168 closed the EXIT dimension of same-side unification.  Today is the
TRANSITION dimension — the piece I have been calling "the size
induction" and treating as the mountain.

**The reframing that did the work.**  I had been asking: how do two
bisimilar states' branch LISTS relate?  Wrong question, and it has no
good answer — bisimilarity never compares lists.  It compares what they
SELECT: at each atom, the same action, into targets that carry equal
labels.  So the lemma the induction actually needs is not about lists at
all:

    two guarded folds that select EquivBA-equal expressions at every
    atom are EquivBA-equal.

`GkatCensus.guardedFold_select_congr`:

    (∀ X W x, EquivBA (selectFull W x B fb) (selectFull W x B' fb'))
      →  EquivBA (guardedFold B fb) (guardedFold B' fb')

**No assumption whatsoever about either list** — not ordered, not
deduplicated, not irredundant, not the same length, not even
satisfiable.  Branches that never fire are killed by their own
unsatisfiability; branches firing on overlapping regions are reconciled
region by region.

The engine is the same relativized induction as 168's
`fold_fallback_gated_aux`, for the same reason: every statement carries
an accumulated assertion `r`, `test_seq_ite` pushes it inward,
`split_assertion` splits it on the next guard.  Supporting:
`fold_const_under` (a fold selecting a FIXED expression throughout a
region equals it there) and `fold_select_under` (the relativized
headline).

**The classical content is one lemma and one question.**  `const_under`
asks only whether a region is SATISFIABLE.  Unsatisfiable → both sides
are `0` by `test_unsat_seq`.  Satisfiable → a single witness atom
transports the hypothesis.  That is the entire use of `Classical.em` in
the construction; everything else is axiom-free (`split_assertion`,
`selectFull_transitionBranches`: no axioms at all).

**Landed at the automaton too**, so this is not an abstract lemma looking
for a home:
* `selectFull_transitionBranches` — the selection of a labelled
  transition list IS `firstMatch`, read through the labelling.  Zero
  axioms.
* `eqRHS_congr_of_select` — two states of one automaton whose Salomaa
  right-hand sides select EquivBA-equal expressions at every atom have
  EquivBA-equal right-hand sides, whatever their transition lists look
  like.

**Why this is exactly the shape bisimilarity supplies.**  `GAutBisim`'s
first conjunct is GLOBAL halt agreement — `∀ a, bval (hlt s) a = bval
(hlt t) a` — so the fall-through case closes by `baTest` at every atom,
not merely at the atom under consideration.  Its other two conjuncts give
the same action into related targets.  Both feed `eqRHS_congr_of_select`
directly.

**What is left, stated precisely.**  The ONE-STEP lemma is done.  What
remains is the recursion: `EquivBA (sol s') (sol t')` for the targets is
the hypothesis of the step, so closing same-side UNIF now needs a
well-founded argument that discharges it — the labels are defined by a
recursion, and the induction must be on program size because same-side
UNIF embeds cross-side (iteration 122).  That is a real remaining piece
and I am not claiming it.  What today removes is the belief that the
transition lists themselves were the obstacle.  They were not.

**A duplicate, recorded.**  Yesterday's `guardedFold_congr_fallback` is a
re-derivation of the pre-existing `GkatFaithful.guardedFold_fallback_congr`
(GkatFaithfulnessProofs.lean:521).  I did not grep before proving.  Same
species as the counting error at 159: **check the repo before deriving a
utility lemma.**  It is harmless but it is waste, and it is the second
time this file has grown a duplicate.

**Odds: ~58%**, up from 52.  Three consecutive iterations have each shown
the standing obstruction to be a wrong framing rather than a hard
theorem, and each was cheaper than the last.  That is a real trend, and I
am reporting it as one — while noting the obvious counter-hypothesis:
the three cheap wins may simply have been the reducible part, with the
recursion the actual irreducible core.  The field's prior that this
problem does not close still stands.

**Method note.**  All three of 167/168/169 came from the same move:
**stop asking how the obstruction can be overcome and ask what the
obstruction is actually a statement ABOUT.**  133 said "reflection fails
at seq" — about exits.  Today said "the lists differ" — but bisimilarity
was never about lists.  Twice now the obstruction dissolved on being
restated in the vocabulary of the thing that actually supplies the
hypothesis.

**Process note, third occurrence.**  The `cd`-into-a-relative-path
failure silently skipped this ledger append on the first attempt, exactly
as recorded before.  Absolute paths for heredocs, always.

---

## Iteration 170 — THE TWO OPEN HYPOTHESES ARE ONE, AND THE QUOTIENT LIFTS FOR FREE

**First, a correction to my own plan.**  I set out today to prove that
`sol ∘ bisimRep` solves the automaton's system — which, with
`certifiedThompson_solution_unique` (unconditional, finite axioms only),
would close same-side unification outright.  **It does not work, and the
failure is instructive.**  Comparing `eqRHS aut sol (σ s)` against
`eqRHS aut (sol∘σ) s`, the branch targets are `u` on one side and `σ u'`
on the other with `u ~ u'`, so `σ u = σ u'` and the gap is exactly
`sol u ≡ sol (σ u)` — the conclusion, at a different state.  **Circular.**
Moving the comparison to `eqRHS aut (sol∘σ) (σ s)` relocates the gap
without closing it.  Recording this so it is not attempted a fourth time:
**`sol ∘ bisimRep` solves IFF unification holds; it is not an
independent route to it.**

**Second, a duplication caught BEFORE proving it.**  I was about to
formalize "same-side UNIF reduces to quotient solvability" as today's
headline.  `GkatSumQuotient.completeness_of_sumQuotientSolvable` has been
in this repo the whole time, with `SumQuotientSolvable` as a named `Prop`
and the reduction proved.  That file's own header records this as its
"fourth duplication".  I grepped first this time — 169's lesson applied
one iteration later, which is the point of writing it down.

**What is actually new today.**

The repository has been carrying TWO open hypotheses under two names, and
tracking them as separate work:
  * `SumQuotientSolvable` — a solution for a behavioural QUOTIENT of the
    Thompson sum;
  * same-side UNIF — bisimilar states of ONE automaton carry
    EquivBA-equal labels.

**They are the same hypothesis.**  The bridge is a labelling CONSTANT on
bisimilarity classes: a quotient solution, read back onto the original
state space.

* `class_constant_solves_of_reps` — **THE NEW LEMMA.**  A class-constant
  labelling that satisfies the equations at ONE REPRESENTATIVE of each
  class satisfies them at EVERY state.  So reading a quotient solution
  back costs nothing, and "solve the quotient" is literally "solve the
  automaton with a class-constant labelling".
  This is what 169's `guardedFold_select_congr` was built for, and it is
  the NON-CIRCULAR use of bisimilarity: the branch targets are merely
  bisimilar, but on a class-constant labelling they carry LITERALLY EQUAL
  expressions, so no inductive hypothesis is consumed.  Contrast the
  failed route above, where the labelling was NOT class-constant and the
  same step demanded the conclusion.
* `select_congr_of_bisim` — bisimilar states select equal labels under a
  class-constant labelling.  `[propext]` only.
* `unif_of_class_constant_solution` — UNIF from a class-constant solution
  plus solution uniqueness.  **No axioms at all.**
* `class_constant_solution_of_unif` — the converse.  Together: an
  equivalence.

**The consequence, stated plainly.**  What remains of the open problem is
**EXISTENTIAL, not coinductive.**  There is nothing further to prove
about bisimulation, quotients, or reflection.  There is an expression to
exhibit: a class-constant solution of the trimmed Thompson sum.  Every
line of 167–170 has been converting coinductive-looking obligations into
this one existence question, and it is now the whole of the remainder.

**This also matches where the literature says the frontier is.**  Today's
search: "a proper characterization of solvable automata would go a long
way towards proving a completeness theorem for GKAT", and
"well-nestedness is only a SUFFICIENT condition for the existence of a
solution — automata that do admit a solution exist which are not
well-nested."  So the field's open question is solvability, and the
repository's measurement agrees: sum-quotient solvability held on
9221/9245 = 99.7% of instances, against a 45.4% base rate.

**Odds: ~58%, unchanged.**  Today did not move the frontier; it
identified two frontiers as one and removed the last coinductive framing
around it.  That is consolidation, not advance, and I decline to price it
as advance — especially after three iterations of genuine progress, where
the temptation to extrapolate is exactly when to stop.  The field's prior
that this problem does not close still stands.

**Method note.**  Two of today's three findings were about MY OWN plan
rather than about GKAT: one route was circular, one target was already
proved.  Both were caught by doing the analysis and the grep BEFORE
writing Lean.  The prover would have caught the first eventually and
never the second.

---

## Iteration 171 — UNIQUENESS WITHOUT UA, AND TWO FACTS FROM THE SOURCE

Today's biggest move was reading the paper properly rather than around
it.  Two PDF fetches failed on compressed streams; the ar5iv HTML
rendering worked.  From Smolka–Kappé–Foster–Rot–Silva, ICALP 2021:

**FACT 1 — the well-nestedness route is REFUTED, by the authors.**  Their
Figure 4 gives a well-nested automaton whose quotient (identify `v₁` with
`v₄`, `v₃` with `v₆`) is NOT well-nested.  I had this queued as the next
route to try — "show the behavioural quotient of a Thompson sum is
well-nested, then apply well-nested ⇒ solvable".  It is false at the
first step.  **Do not search for it.**  This is the cheapest refutation
of the campaign: one fetch, no Lean.

**FACT 2 — but the quotient stays in the expressible class.**  `Cov(W)`
is a covariety, closed under homomorphic images (Prop. 13/14), and a
quotient IS a homomorphic image.  So the quotient satisfies the nesting
coequation even though it is not well-nested.  What it loses is only the
SYNTACTIC witness, which is exactly the thing we need — so this explains
precisely why the gap is where it is, rather than closing it.

**FACT 3 — where UA is actually used.**  Exactly one place: the
bisimulation yields a Salomaa system admitting BOTH derivative labellings
as solutions, and UA collapses them (Thm. 17, Cor. 22).  **In their proof,
as in ours, EXISTENCE is free and UNIQUENESS is the whole of what UA
buys.**  That is worth stating flatly because this project has spent
iterations treating existence as the hard half.

**The theorem: buying some of that uniqueness back.**

`GkatCensus.unique_of_surjective_hom` — if the SOURCE system has provably
unique solutions and `φ` is a homomorphism onto the target's listed
states, then the TARGET system has provably unique solutions.  Two
solutions of the target pull back along `φ`, uniqueness upstairs
identifies the pullbacks, surjectivity carries it back down.  **No
axioms at all.**

Consequence: a behavioural quotient of a Thompson sum inherits uniqueness
from `certifiedThompson_solution_unique` — **without UA**, which is
exactly the step the published proof spends UA on.  So **any
class-constant solution that exists is THE solution**; nothing is lost by
choosing badly, and the entire remaining gap is existence.  Combined with
170's equivalence, the `huniq` hypothesis there is now discharged for the
automata that matter.

**A THIRD DUPLICATION, and this one I half-caught.**  I wrote `eqRHS_hom`
and `solves_pullback` before finding `GkatKleene.eqRHS_hom` and
`GAutHom.lift_solvesBA` (Pham Thm 5.6) already in the corpus.  I HAD
grepped — for `solves_pullback`, `pullback_solves`, `surjective.*hom` —
and missed them because I searched for my own names rather than the
CONCEPT.  Both duplicates are now deleted and the theorem is restated
over the existing `GAutHom`.  **Grep for the concept and for the
literature's name for it, not for the name you were about to give it.**
Three duplications in three days (169 `guardedFold_fallback_congr`, 170
`completeness_of_sumQuotientSolvable` — caught in time, 171 these two).
The corpus is now large enough that this is the dominant waste mode.

**Odds: ~58%, unchanged, and I want to be explicit about why not higher.**
Today removed a route (well-nestedness) and removed a hypothesis
(uniqueness).  Removing a false route does not increase the chance of
success; it only stops a waste.  And uniqueness was never the piece I was
stuck on — Fact 3 says it was the piece the LITERATURE was stuck on, and
this development had already bought it for Thompson systems.  The
existence question is untouched.  The field's prior that this problem
does not close still stands.

---

## Iteration 172 — NO LADDER: the residue is the open question, and the odds come DOWN

No Lean today.  Three findings, one of them about my own estimate.

**FINDING 1 — no published result solves the class the remaining
hypothesis lives in.**  Fetched the automata-learning paper (arXiv
2204.14153, HTML).  **Corollary 4.10**: minimization of a normal
G-coalgebra preserves the nesting coequation.  So the quotient we need
IS in the nesting class — confirming 171's covariety reading from the
other paper.  But the paper gives **no algorithm and no constructive
proof that nesting-coequation automata are solvable**; it is about
learning and minimization, not equation solving.  Combined with 171's
finding that well-nestedness is not preserved by quotients, the position
is:

    well-nested          ⇒ solvable          (published)
    well-nested          ⇏ closed under quotient   (published, Fig. 4)
    nesting coequation   = expressible behaviours  (published)
    nesting coequation   ⇒ solvable          NOBODY HAS PROVED THIS

That last line is the whole of what is left here.  **There is no ladder
from the literature.**  The reduction has landed on the open question
itself, stated sharply — which is a real achievement and is also exactly
why it is hard.

**FINDING 2 — the concrete frontier is 44 instances, and it is already
mapped.**  MEASUREMENTS.md (2026-08-20) has a sharper picture than I had
been carrying: with `fold` + `salomaaE` + `walked_cycle_roles` +
`walked_exit_cycle_roles`, coverage of multi-state SCCs is 2127/2171 =
**98.0%**, leaving **44 open instances in 59947 pairs (0.07%)**, shaped
as multi-member exit ports, non-subset halts, and genuine tree walks.
That is the next stratum and it is a role-theorem-sized piece of work,
not a one-sitting lemma.  Naming it here as the next target rather than
starting it badly at the end of an iteration.

**FINDING 3 — GkatCensusProofs is a LEAF.**  Nothing imports it
(`grep -l '^import GkatCensusProofs' *.lean` is empty).  So
`lake build GkatCensusProofs` — 69 jobs — is a COMPLETE check for the
last six iterations' work, and the 278-lib full builds I have been
launching in the background were never load-bearing for it.  Three of
them were killed mid-run anyway.  Recording so I stop paying for a check
that verifies nothing my changes could break.

**THE ODDS COME DOWN: ~58% → ~45%.**

I ran 46 → 52 → 58 over three iterations that each dissolved a standing
obstruction.  That was extrapolation from the reducible part.  What
Finding 1 establishes is that the part which has NOT fallen has no
external ladder, and is precisely the field's open question.  The honest
reading of the last six iterations is: the reduction got much sharper —
which genuinely helps, since a crisp existential statement is more
attackable than a coinductive tangle — while the core did not move at
all.  Net, roughly back to where this window started.

**A trend in how fast obstacles fall says nothing about the obstacle that
has not fallen.**  I want that written down, because the three cheap wins
made 58% feel earned at the time and it was not.  The field's prior that
this problem does not close still stands, and nothing here has touched
it.

**Artifact refreshed** — https://claude.ai/code/artifact/ce815f05-bd9c-4e31-b6de-0ad16805e88a
was ~35 iterations stale and materially misdescribed the state.  Now
carries: the single remaining existential hypothesis, the collapse of the
coinductive part (167–171, six theorems), the two new refutations
(well-nestedness of the quotient; the circular read-back), and four new
corrections including this odds revision.

---

## Iteration 173 — INTO THE RESIDUE: non-subset halts fall to the masking idea

172 named the concrete frontier: 44 open SCC instances in 59947 pairs,
shaped as multi-member exit ports, NON-SUBSET HALTS, and tree walks.
Today takes the second of the three.

**Why the subset condition is real, and where it isn't.**
`parked_cycle_roles` requires every interior halt to be a SUBSET of the
port's halt guard.  That is not a technicality.  A GKAT loop exits at ONE
place on ONE test, so a cycle whose interiors halt outside the port's halt
has a second, independent exit — and the trailing `test` after the loop
cannot tell which exit was taken, because "which position" is not a test.
That is the honest content of the condition, and it is why the shape sits
in the residue.

**But the trailing test does not have to be the port's halt.**  Let it be
an arbitrary `C` covering every interior halt.  Parking absorbs exactly as
before (`park_absorb` was already general in its `c`; only its call sites
were specialized).  The one new obligation is that `C` agree with the port
halt WHERE THE LOOP ACTUALLY EXITS — on `¬G`.  Inside `G` the two may
differ freely: **the loop never stops there to look.**

    himp   : ∀ j, GuardImplies (hlt (m j)) C          -- was: ⟹ hlt (m 0)
    hexcl  : GuardImplies C (¬ portStepGuard)
    hport  : ¬G ∧ hlt (m 0)  =  ¬G ∧ C                -- the whole weakening

`GkatCycle.parked_cycle_roles_gated`, with `pChain_split_gated` and
`parkedPortG`.  `parkedPortG aut m len (aut.hlt (m 0)) = parkedPortE`
definitionally (`parkedPortG_hlt`, `rfl`), so `parked_cycle_roles` is the
special case where `hport` is reflexivity.  Nothing is lost and the old
theorem is untouched.

**This is the masking idea, transplanted.**  167–168 established that a
difference confined to a region the program never observes costs nothing,
and paid for it with `seq_mask_of_dead_region`.  Here the unobserved
region is `G` — where the loop is still stepping — and the payment is one
`ite`-else congruence under the guard.  The recent abstract work reaching
the concrete census residue in one iteration is the first evidence that
167–172 bought something operational rather than only something tidy.

**A FOURTH DUPLICATION, found while writing this.**  168's `gate_else`
(in GkatCensusProofs) is `GkatGuardedAlgebra.ite_restrict_else`, which has
been in the corpus the whole time — I used the pre-existing one here.
That is four in five days: `guardedFold_fallback_congr`,
`completeness_of_sumQuotientSolvable` (caught), `eqRHS_hom` +
`GAutHom.lift_solvesBA`, and now `ite_restrict_else`.  Every one is a
small guarded-algebra utility.  **The corpus has a guarded-algebra utility
file (`GkatGuardedAlgebraProofs.lean`, ~30 theorems); READ ITS THEOREM
LIST before deriving anything of that shape.**  That is a concrete
procedure, which the previous three resolutions to "grep better" were not.

**Scope, stated plainly.**  This closes one of three residue shapes at the
CYCLE-LOCAL level.  It does not touch multi-member exit ports or tree
walks, and it does not re-run the census — so the 44 has NOT been
re-measured and I am not claiming a new coverage number.  What is claimed
is a strictly more general theorem, machine-checked, subsuming the old
one.

**Odds: ~45%, unchanged.**  One residue shape of three, at one level of a
multi-level argument, with the top-level existence question untouched.
Yesterday's recalibration stands.

---

## Iteration 174 — RETRACTION: 173 did NOT cover non-subset halts, and Kosaraju says nothing local can

**Iteration 173's headline is wrong and I am retracting it in Lean, not in
prose.**

`parked_cycle_roles_gated` was described as admitting NON-SUBSET interior
halts, on the strength of replacing `GuardImplies (hlt (m j)) (hlt (m 0))`
with `GuardImplies (hlt (m j)) C` for an "arbitrary" exit test `C`.  `C`
is not arbitrary.  Two theorems, both zero axioms:

* `gated_exit_forced` — `hexcl : C ⟹ ¬G` and
  `hport : ¬G ∧ hlt (m 0) = ¬G ∧ C` together PIN `C ≡ ¬G ∧ hlt (m 0)`.
  There is no freedom in the parameter at all.
* `gated_himp_subset` — therefore `himp` still forces
  `hlt (m j) ⟹ hlt (m 0)`.  **The subset condition survives unchanged.**

What 173 actually bought: the ORIGINAL `hexcl`, requiring the PORT's own
halt to exclude the port's step guard, is gone.  The port halt may now
overlap its step guard freely; only its restriction to `¬G` is used.  A
real generalization, and a much smaller one than announced.  The section
header and both docstrings in `GkatCycleProofs.lean` have been rewritten
to say so — the source must not carry the false claim, which is the whole
of the iteration-154 lesson.

**And the larger claim could never have been true.**  Today's search
surfaced Kosaraju's theorem in the form that settles it: *a flowchart is
reducible to a structured program WITHOUT auxiliary variables iff it
contains no loop with two distinct exits.*  GKAT has no auxiliary
variables.  A cycle with two incomparable halts IS a loop with two
distinct exits.  **So no single `wh` expresses it, whatever the parking
algebra does.**

That is the most useful thing today produced, and it is a route closure,
not a lemma:

  **THE ROLE LADDER HAS A CEILING, AND TWO OF THE THREE RESIDUE SHAPES ARE
  ABOVE IT.**  "Non-subset halts" and "multi-member exit ports" are both
  loops with two distinct exits.  No amount of further parking, gating, or
  walking machinery reaches them, because the obstruction is Kosaraju's
  and not the algebra's.  Coverage there has to come from UNROLLING or
  STATE DUPLICATION — changing the automaton — which is exactly what the
  span era's un-sharing did, and what the span-era ledger recorded as
  covering 100% of its measured residue.  **Stop extending the role
  ladder; the next move on the residue is un-sharing.**

**How this failure happened, precisely.**  I introduced a parameter,
observed that the hypothesis mentioning it was formally weaker, and
described the theorem by that hypothesis — without checking whether the
OTHER hypotheses constrained the parameter.  They pinned it completely.
The Lean was correct throughout; only the reading was wrong.  Fourth time
in this campaign that the prose outran the proof (112, 139, 154, 173), and
the first where the error was in a claim I made the same day I proved the
theorem.

**A generalization is only as weak as its WHOLE hypothesis set.  Before
describing a new parameter as free, solve for it.**  That is a mechanical
check and it takes one minute; it would have caught this before the commit.

**Odds: ~45%, unchanged.**  Yesterday's number did not price the residue
progress, so retracting it costs nothing.  Kosaraju's ceiling is genuinely
informative but it closes a route rather than opening one.

---

## Iteration 175 — I RAN THE CENSUS, AND THE RESIDUE IS NOT WHAT 174 SAID

Two iterations in a row I described the residue from memory of an old
MEASUREMENTS.md entry.  Today I ran it.  Dump saved at
`runs/open-scc-NA2-depth7-20k.txt`.

**The measurement** (NA=2, semantic guards=4, depth≤7, 20000 pairs,
3.4M generation tries):

    pairs analysed              19998
    FULLY covered by proved strata (fold + salomaaE)   19876  (99.4%)
    quotient states             10540 — fold 9732, singleton-self 473,
                                        in multi-state SCCs 335
    multi-state SCCs            122 — walked-covered 107, **OPEN 15**
    SAME-SIDE: automata measured 40000; NOT already minimal 39231 (98.1%)

**EVERY ONE OF THE 15 OPEN SCCs HAS A BRANCHER.**  A brancher is a state
with two DIFFERENT in-SCC successors (`st=[s2,s0]`).  Not one of the 15 is
a two-distinct-exit loop; all 15 have `ports=1`.  The shape histogram
confirms it: every `branchy` row is a `(size, branchy, halting, exits,
branchers≥1)` entry, and the simple rows are all covered.

**SO 174's CHARACTERIZATION WAS WRONG, AND I AM CORRECTING IT.**
Iteration 174 concluded, from Kosaraju, that "non-subset halts and
multi-member exit ports — two of the three residue shapes — are provably
beyond any single-`wh` role theorem".  The Kosaraju argument itself is
sound and the two theorems that retracted 173 stand.  What is wrong is the
premise that those are the residue.  **They are not.**  At these
parameters the residue is branchy cycles, and I took "the residue" from a
remembered summary of an older run at different parameters instead of
measuring.

**And the branchy residue is NOT Kosaraju-blocked — it is expressible.**
Take OPEN-SCC #1: `0 → 1`, `1 → {2, 0}`, `2 → {2, 1}`.  From state 1 both
alternatives RETURN TO 1: via 2 (which self-loops, then back to 1) or via
0 (straight back to 1).  That is one loop head whose body BRANCHES AND
REJOINS — `wh G (ite g pathA pathB)` — a single `wh` with an `ite` body.
Every one of the 15 has this shape.  Nothing needs unrolling, nothing
needs auxiliary variables, and 174's "stop extending the role ladder" is
therefore premature: the ladder's next rung is exactly the right move.

**THE NEXT TARGET, PRECISELY.**  A role theorem for a single-port SCC
whose walk from the port may BRANCH AND REJOIN — the branching arms being
straight lines (possibly with self-loops) that reconverge at a cycle
position.  `straight_line` and `chain_expand` already exist for the arms;
what is new is the branch/rejoin algebra at the brancher, where `u5` and
`multi_gather` have to commute an `ite` past the shared suffix.  This is
the same shape as `chordloops_complete_free` (iteration ~94), which proved
the CHORD case at the expression level — so the mathematics is precedented
even though the automaton-level role theorem is not written.

**Also found: the full 278-lib build has been failing on non-GKAT files
the whole time.**  `CategoryProofs.lean` errors with `unknown namespace
PortcullisCoreBridge` — collateral from a 2024 refactor that carved the
IFC monitor out of portcullis-core.  Nothing imports it.  Restricting to
the 191 GKAT libs: **385 jobs, ZERO errors, clean.**  So the GKAT cluster
is intact and the "full build" noise I have been chasing for four
iterations was never about this work.  The right check is
`xargs lake build < gkat-libs`.

**Odds: ~45%, unchanged.**  A measurement and a correction; the frontier
moved sideways, not down.  What did improve is that the next target is now
a named shape with 15 concrete instances on disk rather than a
recollection.

**Method note, and it is the third time this week.**  167–174 produced two
wrong characterizations (173's "non-subset halts fall", 174's "the residue
is Kosaraju-blocked"), both from reasoning about remembered data instead
of the data.  **The census takes four minutes to run.  Run it before
describing what is open.**

---

## Iteration 176 — ALL 15 OPEN SCCs ARE REDUCIBLE, AND 14 HAVE EXACTLY ONE BRANCHER

175 measured that the residue is branchy.  Today asks the structural
question that decides whether the role ladder can reach it, and answers it
with a test rather than an eyeball.

**THE TEST.**  Hecht–Ullman T1/T2, run over the 15 dumped open SCCs
(Hecht-Ullman T1/T2, now a census check).  T1 drops a
self-loop; T2 merges a non-header node having a unique predecessor into
that predecessor; a flow graph is reducible iff T1/T2 collapse it to a
single node.

    open SCCs: 15;  T1/T2-REDUCIBLE: 15;  irreducible: 0

    sizes 3,3,4,3,4,3,4,3,5,3,3,3,3,4,4
    branchers per SCC: 2,1,1,1,1,1,1,1,1,1,1,1,1,1,1

**EVERY ONE IS REDUCIBLE.  FOURTEEN OF FIFTEEN HAVE EXACTLY ONE BRANCHER.**

That settles the question 174 got wrong from the other direction.
Reducible means the loops form a NESTED family, which is exactly the
structure a nest of `wh`s expresses — no auxiliary variables, no
unrolling, no Kosaraju obstruction.  **The role ladder can reach the
residue.**  What it needs is one more rung, and the rung is now specified
by measurement rather than by guesswork:

  **NEXT TARGET: a role theorem for a walked cycle with ONE extra in-SCC
  arm from one position, targeting an ancestor.**  Sizes 3–5.  This is
  `chord3_roles` (which handles size 3 with a supplied closed form)
  generalized to arbitrary cycle length, or equivalently
  `walked_cycle_roles` with `hint_nil` relaxed at exactly one position.

**Also landed: `self_gather_role`, the atom, extracted.**  Five theorems in
this corpus inline the same three lines — `StateRole.salomaaE` on the
self-arms plus `multi_gather` to commute them to the head.  Pulled out
with NO hypotheses beyond the shape of the solution, and
`singleton_scc_roles` rewired to call it.

The point of the extraction is not tidiness.  It says where the work in a
new stratum actually is: **discharging the role is free once the solution
is in self-gathered form, so the entire cost of a new stratum is DEFINING
the solution.**  That is worth knowing before starting the branchy rung.

**A caveat on the reducibility test, stated because it matters.**  The
header used is the first state the census prints for each SCC, which is
its entry.  If a different entry were the true one the verdict could
differ — reducibility is relative to the entry.  I did not verify the
census prints the entry first; I read it from the dumps' structure.  The
15/15 result should be re-confirmed once the branchy rung is being
written against a specific instance.

**Odds: ~45%, unchanged.**  This is a measurement plus a refactor.  It
tells the next iteration exactly what to prove and rules out the
obstruction 174 feared, which is worth a great deal procedurally and
nothing probabilistically until the theorem exists.

---

## Iteration 177 — THE CHORDED CYCLE: the rung the measurement asked for

175 dumped the 15 open SCCs; 176 proved all 15 reducible.  Today reads
their edge sets and builds the rung.

**THIRTEEN OF THE FIFTEEN ARE ONE SHAPE.**  Printing the edge sets:

    x6  n=3  0→1, 1→0, 1→2, 2→0                halt at 0
    x3  n=4  0→1, 1→0, 1→3, 3→2, 2→0           halt at 0
    x1  n=4  0→3, 3→1, 1→0, 1→2, 2→0           halt at 0
    x1  n=5  0→4, 4→3, 3→1, 1→0, 1→2, 2→0      halt at 0
    x1  n=4  0→3, 3→2, 2→1, 1→3, 1→0           halt at 3
    x1  n=3  0→1, 0→2, 1→0, 2→1                halt at 1
    ---- the two that are not:
    x1  n=3  0→1, 1→0, 1→2, 2→1, 2→2           halt at 0   (nested)
    x1  n=3  0→2, 2→1, 1→0, 1→2                halt at 0   (nested)

Every one of the first six is: **a cycle through every member, plus ONE
extra arm from an interior position straight back to the port.**  A long
lap with a chord short-circuiting it.  The chord always sits at a position
`c` with `1 ≤ c` and `c + 1 < len` — checked instance by instance.

**`GkatCycle.chorded_cycle_roles`** — proved, sorry-free,
`[propext, Classical.choice, Quot.sound]`, with `cChain`, `cChain_succ`,
`cPortE`, and `cChain_split`.

The algebra is the parked cycle's with one extra alternative.  The chord
arm ends at the port, so it is already `something ; sol (m 0)`; `s2` turns
the dead fallback into `0 ; sol (m 0)` and `u5` factors the port solution
out of BOTH alternatives exactly as it does out of a plain chain.
Downstream is unchanged: `park_absorb` on the halt arms, `salomaaE` at the
port.  At the chord position `double_gather` replaces `multi_gather` —
gather the lap arm first, the chord arm from the remainder, and the rest
is empty.

**Cost, for the record: one constructor case in the chain, one case in the
split, one gather swap.**  That is what 176's `self_gather_role` predicted
— the role discharges itself once the solution has the right shape, and
all the work was in defining `cChain`.

**SCOPE, AND I AM NOT INFLATING IT.**  This is a CYCLE-LOCAL role theorem:
it takes the closed forms as hypotheses (`hsol_int`, `hsol_port`), like
`parked_cycle_roles` and `walked_cycle_roles` before it.  **The census
count has NOT moved**, and will not until an ASSEMBLY theorem defines the
solution by recursion — the `walked_assembly_roles` step.  What exists
today is the cycle-local half of the rung, which is the half that contains
the new mathematics.

**Two instances remain unaddressed** (#1 and #2), and they are genuinely
different: nested loops rather than a chord — an inner cycle inside the
outer one.  Recorded so the next iteration does not discover it by
surprise.

**One Lean note worth keeping.**  `cChain` does not reduce under `whnf`,
because `j = c` is undecided for a variable `j`, so `show` cannot unfold
it.  Every proof rewrites with the explicit equation lemma `cChain_succ`
(`:= rfl`) and then `if_pos`/`if_neg`.  This cost two build cycles to
find; the pattern generalizes to any chain definition with a positional
test.

**Odds: ~45%, unchanged.**  A rung on a ladder whose top is still the
existence question.  Progress is real and local.

---

## Iteration 178 — THE CHORDED ASSEMBLY, AND 13/15 VERIFIED AGAINST IT

177 left the chorded stratum half-built: a cycle-LOCAL theorem taking
closed forms as hypotheses, with the explicit note that the census count
would not move until an ASSEMBLY defined the solution by recursion.  Both
halves now exist, and the instances have been checked against them.

**`GkatCycle.chorded_assembly_roles`** (with `asmSolC`, `asmSolC_eq`) —
proved first try, sorry-free, `[propext, Classical.choice, Quot.sound]`.
An automaton whose every state is BASE (arms self or strictly descending)
or a member of a designated chorded cycle is fully role-covered.

**The assembly is much lighter than the walked one, for a reason worth
recording.**  A chorded cycle's port arms all re-enter the cycle and its
interiors' arms all stay in it, so **`cPortE` and `cChain` mention no
`sol` at all** — the SCC's solution is closed in `aut, m, len, c`.  The
recursion is needed only at base states, and the cycle branch of the
fixpoint equation needs NO congruence lemma: it is already syntactically
right.  The walked assembly needs `walkedExitPortE_congr` and
`wChain_term_congr` precisely because its port folds `sol` over descending
arms; a chorded cycle has none.  **Expect this whenever a stratum's cycles
are self-contained.**  The base case is now one line —
`self_gather_role`, extracted in 176.

**VERIFICATION AGAINST THE MEASURED INSTANCES** (`verify_chorded.py`, in
the repo).  For each of the 15 dumped open SCCs, brute-force a lap over
permutations and check every hypothesis the Lean theorem asks for: lap
through every member, port arms all to `m 1`, interior arms all to the
next position, a chord at `c` with `1 ≤ c` and `c + 1 < len`, interiors
silent, port halting, port halt excluding its step guard.

    all hypotheses verified: 13 / 15

    #1  n=3  NOT CHORDED — nested loops, a genuinely different shape
    #2  n=3  chorded lap found, but an INTERIOR HALTS

**#2 is not a refutation, and I want to be exact about that.**  My check
tests `himp` in the strong form "interiors do not halt at all".  The Lean
hypothesis is weaker — `GuardImplies (hlt (m j)) (hlt (m 0))` — so #2 may
well satisfy the theorem; I did not evaluate the guard implication.  Two
instances are therefore UNRESOLVED, one certainly a different shape and
one merely unchecked.

**What this does and does not claim.**  The theorem is proved and 13 of
the 15 measured open SCCs provably satisfy its hypotheses.  It does NOT
follow that the census's open count drops to 2: the census classifier does
not know about the chorded stratum, so re-running it would still report
15.  Wiring the classifier is a separate, mechanical job, and until it is
done the 13 is a hand-verified figure about a dump, not a measured
coverage rate.  I am recording it as the former.

**Odds: ~45%, unchanged.**  Two iterations of real, verified progress on a
stratum — and the top of the ladder is still the existence question for
arbitrary quotients, which nothing here touches.  The residue shrinking
from 15 shapes to 2 at these parameters says the ladder is climbable at
this scale; it says nothing about whether every quotient is reachable.

---

## Iteration 179 — THE COUNT MOVES: chorded classifier wired, and the first IRREDUCIBLE instance

178 verified 13/15 by hand and said plainly that the census count had not
moved because the classifier did not know the stratum.  Today it does.

**THE CLASSIFIER.**  Added to `scc_census`, mirroring
`chorded_assembly_roles`' hypotheses exactly.  No permutation search is
needed: the chord state is the unique brancher, its two in-SCC successors
are the port and the lap's next position, so the lap reconstructs by
following unique successors from the candidate port.

    NA=2, depth<=7, 20000 pairs:
      multi-state SCCs: walked 107; CHORDED 13; OPEN 2      (was OPEN 15)

**The 13 is now MEASURED, and it cross-checks.**  The Rust classifier and
178's independent Python verifier — different implementations, one
following unique successors and one brute-forcing permutations — agree on
13, and on WHICH 13.  The two survivors are exactly #1 and #2, the ones
the Python flagged.

**AT SCALE (NA=4, depth<=7, 60000 pairs), which is the number that
matters:**

    pairs fully covered by fold+salomaaE:  57823/59993 = 96.4%
    multi-state SCCs: 2170 — walked 2126, CHORDED 13, OPEN 31
    (was 2127/2171 covered = 98.0%; now 2139/2170 = 98.6%)

So the chorded stratum is worth 13 SCCs at NA=4, not the 29 the NA=2 run
might have suggested.  **The residue at scale is 31, and it is a different
population from the NA=2 residue** — recording that because I have twice
been burned by carrying a residue characterization across parameters.

**THE NA=4 RESIDUE, characterized:**

    n=3  1 halt  0 exits  2 branchers  -> 11
    n=3  1 halt  0 exits  1 brancher   ->  9
    n=3  2 halts 0 exits  {3,1,0} br   ->  6
    n=4  1 halt  0 exits  {1,2} br     ->  2
    n=3  3 halts 0 exits  2 branchers  ->  1
    n=2  2 halts 0 exits  2 branchers  ->  1
    n=2  0 halts 3 exits  2 branchers  ->  1

Reading the 9 one-brancher instances individually gives TWO next targets,
both small variants rather than new mathematics:

  * **CHORD AT THE PORT** (`c = 0`), which `chorded_cycle_roles` excludes
    by `1 ≤ c`.  Instance #3: `0 → {1,2}, 1 → 0, 2 → 1`, halt at 0 — the
    port itself branches into a short lap `0→1→0` and a long one
    `0→2→1→0`.  Needs `double_gather` at the port and a two-branch loop
    body, so `cPortE`'s shape changes; the rest is unchanged.
  * **CHORD TO AN INTERIOR** — a genuinely NESTED loop.  Instances #2, #9:
    the brancher sits at the last lap position and its extra arm targets
    an interior, creating an inner cycle.  This is the same shape as the
    two NA=2 survivors, so it is now the dominant unsolved case at both
    scales.

**AND THE FIRST IRREDUCIBLE INSTANCE.**  Running 176's T1/T2 test over the
31: **30 reducible, 1 NOT** — and #26 is irreducible from EVERY choice of
header:

    #26  scc = [0,1,2]   0 → {1,2}   1 → {0,2}   2 → {0,1,2}

The complete digraph on three nodes with a self-loop.  By Kosaraju this is
not a structured program without auxiliary variables, so **no nest of
`wh`s expresses it and no role theorem will ever cover it.**  Its language
is still GKAT-expressible — it is a quotient of a Thompson sum of
equivalent programs — but only by an automaton that DUPLICATES states.

That vindicates iteration 174's "the role ladder has a ceiling", for one
instance out of 2170, and for a shape 174 did not name.  174 was right
about the existence of a ceiling and wrong about where it sits.  **1 in
2170 is where it sits, at these parameters.**

**Odds: ~45%, unchanged.**  Coverage 98.0% → 98.6% is a real measured
gain.  It is also the wrong quantity to price: an existence theorem must
hold for every quotient, and a 1-in-2170 irreducible instance is a
concrete demonstration that the ladder alone cannot get there.  What would
move the number is a construction for duplication-requiring quotients, and
nothing in this iteration is one.

---

## Iteration 180 — RETRACTION: there was no irreducible instance; it was a parser bug

**179's headline finding is FALSE and I am retracting it.**

179 reported "the first IRREDUCIBLE instance": open SCC #26 at NA=4,
allegedly the complete digraph on three nodes, irreducible from every
header, and therefore provably beyond any role theorem by Kosaraju.  That
instance does not exist.  Its actual dump is

    OPEN-SCC #26  scc [0,1,2]
      state 0: hl=1010 st=[s1,-,s2,-]
      state 1: hl=0000 st=[s0,s0,s0,s0]
      state 2: hl=0000 st=[s1,s2,s2,s2]

i.e. `0→{1,2}`, `1→{0}`, `2→{1,2}` — which T1/T2 reduces immediately (drop
the self-loop at 2, merge 2 into its unique predecessor 0, merge 1 into 0).
**Reducible.**

**The bug.**  `analyze_open_sccs.py` split the dump on `OPEN-SCC #` and
then consumed every `state N: hl=… st=[…]` line in the block.  The NA=4
dump also contains twelve `MULTI-PORT #` sections whose rows have exactly
that shape, so block #26 swallowed the rows of the MULTI-PORT section that
followed it and invented the edges `1→2` and `2→0`.  The NA=2 dump has NO
MULTI-PORT sections, which is why 175/176's results there were unaffected.

**CORRECTED FINDINGS, with the fixed parser:**

    NA=4, 31 open SCCs:  T1/T2-REDUCIBLE 31; irreducible 0
    NA=2, 15 open SCCs:  T1/T2-REDUCIBLE 15; irreducible 0   (unchanged)
    chorded verification at NA=2:  13 / 15                   (unchanged)

**So there is NO measured instance beyond the role ladder.**  Every open
SCC at both scales is reducible, hence a nest of `wh`s in principle.
Iteration 174's ceiling is still a theorem — Kosaraju is real — but it has
zero measured instances, and 179's claim that it "sits at 1 in 2170" is
withdrawn.  The right reading is the opposite of 179's: **keep climbing;
nothing observed is out of reach.**

**One finding from 179 SURVIVES, and it is worth having.**  Added
`nested(&q)` and `total_aut(&q)` to the dump:

    all 31 open quotients satisfy the NESTING COEQUATION (true)
    28 of 31 are TOTAL; 3 are not

The coequation is necessary for a behaviour to be an expression's, so this
confirms the covariety reading from 171 empirically: no residue instance
is a counterexample to expressibility.  The three non-total ones are the
`GkatTotalization` chapter's business, not a new obstruction.

**How this happened, exactly.**  I printed the PARSED edge set and reasoned
from it.  I never printed the raw dump block for #26 until today.  A parser
over a semi-structured text dump is a place where a silent merge produces a
plausible object, and a plausible object survives review.

**The check that would have caught it, now in both scripts:** assert that
the number of parsed state rows equals the SCC size.  A block boundary
error violates it immediately.  That is a mechanical guard, not a
resolution to be careful — the fourth time this campaign has needed one.

**VERIFY A PARSER AGAINST THE RAW TEXT FOR AT LEAST ONE INSTANCE BEFORE
DRAWING A CONCLUSION FROM IT.**

**Odds: ~45%, unchanged.**  A retraction that makes the measured picture
better, not worse, and I decline to move the number on it — the existence
question is about all quotients, not the ones a generator happens to reach.

---

## Iteration 181 — 180 USED THE WRONG CRITERION; the right one finds 3 blocked instances

180's parser fix stands: the edges really were wrong, and every open SCC
really is T1/T2-reducible.  **180's CONCLUSION from that does not stand.**
I wrote "no measured instance is beyond the role ladder" on the strength of
reducibility.  Reducibility is the wrong test.

    REDUCIBILITY (Hecht-Ullman T1/T2) is about loop ENTRY — one header per
    loop.
    KOSARAJU's condition is about loop EXITS — a flowchart is a structured
    program WITHOUT auxiliary variables iff no loop has two distinct exits.

A graph can be reducible and still have two exits.  Testing entry and
concluding about exits is a straight non-sequitur, and I made it.

**MEASURED PROPERLY** (the census's exit-state counter).  An SCC's
exits are its members that halt or carry an arm out of the SCC — the
census's `ports`.  Over the 31 NA=4 open SCCs:

    single exit state  28 / 31      MULTI-EXIT (Kosaraju-blocked)  3 / 31

So there ARE measured instances beyond any variable-free nest of `wh`s —
**3 of 2170 multi-state SCCs** — found by the right test.  179 claimed 1 in
2170 by a broken parser; 180 claimed 0 by the wrong criterion; the answer
is 3, and it took both errors to get here.

**THE 28 REACHABLE ONES, rooted at their unique exit state:**

    chords=1  at=(0,)        ->  7    the PORT itself branches
    chords=1  at=(len-1,)    ->  5    chord at the LAST lap position
    chords=2  at=(0,1)       -> 10
    chords=2  at=(0,2)       ->  6

Every one of them has `some chord to interior` — the extra arm targets a
lap position, not the port.  **That is the difference from the stratum
already proved.**  `chorded_cycle_roles` handles exactly one chord, from an
interior position `1 ≤ c < len-1`, targeting the PORT.  None of the 28
matches: they chord to interiors, at positions the theorem excludes, and
over half carry two chords.

**THE NEXT TARGET, now exactly specified: a lap with one arbitrary chord
`c → d`.**  A backward chord (`d` before `c` in lap order) creates an inner
loop nested inside the outer lap — two `w3` applications, inner then
outer.  A forward chord is the two-laps shape already handled, rotated.
Twelve of the 28 have one chord; the sixteen with two need it twice, so the
one-chord theorem is the prerequisite either way.

**Why I keep getting the residue characterization wrong.**  Four times now:
173 (hypothesis pinned), 174 (residue misremembered), 179 (parser), 180
(wrong criterion).  Every one was a claim ABOUT the measurement rather than
a measurement.  The pattern is that I compute something adjacent to the
question — reducibility instead of exits, a parsed graph instead of the raw
dump — and then answer the question I meant to ask.  **State the criterion
in the same words as the claim before running anything.**

**Odds: ~45%, unchanged.**  Three Kosaraju-blocked instances in 2170 is a
genuine, small, correctly-measured obstruction for the ladder — and the
ladder was never the route to the general theorem anyway.

---

## Iteration 182 — THE NESTED-CHORD STRATUM: two `w3` applications, built to plan

181 wrote the derivation and stopped.  Today executed it.  Both halves,
sorry-free, `[propext, Classical.choice, Quot.sound]`:

* `nWalk`, `nWalk_split`, `nInner`, `nTail`, `nPortE`, `nLastE`
* `nested_chord_roles` — the cycle-local theorem
* `asmSolN`, `asmSolN_eq`, `nested_chord_assembly_roles` — the assembly

**This is the first stratum with TWO NESTED LOOPS.**  Every earlier one —
single-port, parked, walked, walked-exit, chorded — closes with one `wh`
at the port.  This closes with a `wh` inside a `wh`: the inner loop at the
BRANCHER, the outer at the port, `w3` applied twice.  That mechanism is
what any nested-loop stratum needs, and it now exists.

**The plan held exactly.**  Every step of `NESTED-CHORD-PLAN.md` went
through as written: `s2` on the dead fallbacks, `u5` to factor the walk,
`double_gather` at the brancher, `w3` inner then outer.  Three build
cycles, all three failures mechanical (`u5` needed the `nTail` unfolding
staged, two `rfl`s omitted) — **none of them mathematical**.  Deriving
before building is the difference between three mechanical fixes and a
half-finished stratum, and it is now two-for-two.

**`nWalk_split` is UNCONDITIONAL** — no length bound, no halt hypotheses,
no `park_absorb`.  Interiors are silent, so every fallback is literally
`test 0`, which `s2` rewrites to `0 ; X`, and `u5` factors the
continuation out of the whole walk.  Compare `pChain_split`, which needs
`himp` and `hexcl` because its interiors may halt.  **The silence of the
interiors is doing all the work**, and it is a MEASURED fact about the
residue, not an assumption of convenience.

**Assembly was cheap again, for the reason 178 recorded**: the cycle's
closed forms mention no `sol`, so the recursion is needed only at base
states and the cycle branch of the fixpoint equation needs no congruence
lemma.  Base case is one line, `self_gather_role`.

**SCOPE.**  This covers a lap whose LAST position chords back to position
1 — 5 of the 31 measured NA=4 open SCCs.  The classifier does not know
this stratum yet, so **the census count has not moved**; wiring it is next
and mechanical.  Still uncovered: chord AT the port (7), two-chord cases
(16), and the 3 MULTI-EXIT instances that no nest of `wh`s can reach.

**Odds: ~45%, unchanged.**  A stratum, built to spec, that does not touch
the existence question for arbitrary quotients.

---

## Iteration 183 — THE LADDER CANNOT CLOSE IT, AND THE MEASUREMENT SAYS SO

Two measurements and one strategic conclusion.

**MEASUREMENT 1 — every reachable open SCC is LAMINAR.**  Rooting each of
the 31 NA=4 open SCCs at its unique exit state and reading the chord set:

    silent interiors, LAMINAR, 1 chord, all backward   ->  5
    silent interiors, LAMINAR, 2 chords, all backward  ->  6
    silent interiors, LAMINAR, 1 chord, has forward    ->  7
    silent interiors, LAMINAR, 2 chords, has forward   -> 10
    MULTI-EXIT                                         ->  3

**Not one instance has interior halts, a crossing chord pair, or more than
two chords.**  So a SINGLE theorem — a lap with a laminar chord set —
covers all 28, and the three further strata I had queued (chord-at-port,
two-backward, forward+backward) would be four times the work for the same
coverage.  Design written up in `LAMINAR-CHORD-PLAN.md`, with the two
chord kinds and the `seg a b` recursion.  `chorded_cycle_roles` and
`nested_chord_roles` are its two proved special cases.

**MEASUREMENT 2 — the multi-exit residue is NOT a totality artefact.**  I
suspected it might be: 3 of 31 quotients are non-total, and 3 are
multi-exit, and the completeness chain totalizes anyway.  **The sets are
different** — only #4 is both; #5 and #11 are total AND multi-exit.  A
clean negative that kills the hypothesis before it cost anything.

    #11  0 → {0,1}, 1 → 2, 2 → {1,0};  0 and 2 both halt on one atom,
         while 1 CONTINUES on that same atom.

The loop must remember whether it is at 0/2 or at 1.  That is exactly the
flag Kosaraju says is unavoidable.

**THE CONCLUSION, and it is the real content of this iteration.**

**THE ROLE LADDER CANNOT CLOSE THIS PROBLEM.**  It stands at 98.6% and is
PROVABLY unable to reach the rest: multi-exit loops are not nests of `wh`s
without auxiliary variables, and GKAT has none.  I have spent seven
iterations (176–182) climbing it, producing four real strata, and the
top-level statement — a class-constant solution for EVERY quotient — is
exactly where it was.  Chasing 98.6% → 99.x% is chasing a number that
cannot reach 100 by this method.

I am recording that plainly rather than continuing, because the pattern
was becoming self-sustaining: each iteration's measurement named the next
rung, and each rung was genuinely provable, and none of it approached the
question.  **A ladder that provably cannot reach the roof is not a route,
however many rungs it has.**

**What the ladder DID buy, stated fairly.**  The nested-elimination
mechanism (`w3` inner then outer, the rotation to head a loop at its
brancher) is general and reusable.  `self_gather_role` isolated the role
obligation so a new stratum costs only its solution definition.  And the
census apparatus now measures coverage honestly, which is how this
conclusion became visible at all.

**THE NEXT ROUTE: DUPLICATION.**  Kosaraju's own theorem names the repair
— duplicate states so each exit becomes a head at a different time.  The
span era built exactly this and never connected it here:
`GkatTotalizationProofs`' `splitCover` and `hasThompsonCover_of_splitN`,
with a measured "one level of un-sharing covers 100% of the uncovered
padded kernel pairs".  That is a different construction on a different
object, and it is where the next iterations should go.

**Odds: ~45%, unchanged.**  Nothing today moved the frontier; it made the
frontier's shape honest.  If anything the discipline of saying "this route
tops out" is worth more than the four strata that preceded it.

---

## Iteration 184 — THE CENSUS WAS MEASURING THE WRONG QUOTIENT; the true residue is ONE PAIR

183 concluded the role ladder tops out at 98.6% and named duplication as
the next route.  That conclusion was drawn against the wrong object, and
today's measurement corrects it.

**THE FRAMING ERROR.**  The census classifies SCCs of the **FULL
bisimulation collapse**.  `SumQuotientSolvable` asks for SOME behavioural
quotient with a solution — the full collapse is the TOP of the lattice of
congruences, not the whole of it.  A coarser quotient still identifying the
two starts is equally admissible, and it may avoid the shape the full
collapse creates.  `solvable_somewhere_in_lattice` has been in the harness
the whole time, with a comment saying exactly this; the SCC census never
called it.

**THE MEASUREMENT** (NA=4, depth<=7, 60000 pairs):

    pairs with an OPEN SCC in the FULL collapse:                31
    of those, SOLVABLE SOMEWHERE IN THE BISIMULATION LATTICE:   30

**So the true residue is ONE PAIR in 59993 — not 31.**  Every ladder
stratum built in 176–182 was chasing a residue that a coarser quotient
mostly dissolves.  Coverage for the hypothesis that actually matters is
59992/59993 = **99.998%**.

**183's conclusion, corrected.**  "The role ladder cannot close this" is
still true as stated — the ladder alone cannot — but the inference I drew
from it, that duplication is the next route, is wrong.  **The lattice is
the next route**, and it is not a construction to be invented: it is a
choice of quotient, already implemented, already measured.  Duplication and
"collapse less" are the same idea, and the second is free.

**THE ONE RESISTANT PAIR IS DUMPED**
(`runs/lattice-resistant-NA4-60k.txt`).  Sum has 11 states, satisfies the
nesting coequation, and is total.  Both source programs are recorded.

    sum state 0: hl=1000 st=[1,1,2,-]      sum state 6: hl=1000 st=[5,6,7,-]
    sum state 1: hl=1000 st=[1,1,2,-]      sum state 7: hl=0000 st=[8,8,8,8]
    sum state 2: hl=0000 st=[3,3,3,3]      sum state 8: hl=1000 st=[9,6,7,-]
    sum state 3: hl=1000 st=[2,1,2,-]      sum state 9: hl=0000 st=[10,10,10,10]
    sum state 4: hl=1000 st=[5,6,7,-]      sum state 10: hl=1000 st=[9,6,7,-]
    sum state 5: hl=1000 st=[5,6,7,-]

**THIS IS A CANDIDATE, NOT A REFUTATION, and the distinction is the whole
of its value.**  `solvable_somewhere_in_lattice` enumerates congruences and
runs `symbolic_eliminable_raw` on each; the oracle is sound in the
direction that matters for REJECTING non-nested automata, but it is not
complete, and the enumeration has a budget.  A `false` means "not found",
not "does not exist".  So this pair is the first place to look, and the two
questions to ask of it are: does the enumeration reach the right
congruence, and is the elimination oracle complete on what it reaches.

**The right next step is to settle that one pair**, either by finding its
solution by hand — it is 11 states, and both generating expressions are
recorded — or by proving no congruence solves it.  Settling it decides
whether `SumQuotientSolvable` survives, and nothing else on the board
decides anything comparable.

**Odds: ~45%, held deliberately.**  99.998% coverage is a much better
number than 98.6%, and I am not moving on it: a single resistant instance
is exactly what a counterexample looks like before it is confirmed, and an
existence theorem needs all of them.  If the one pair turns out solvable,
that is when the number moves.

**Method note.**  Seven iterations of ladder work were spent on a residue
defined by a choice — the full collapse — that the hypothesis never
required.  The harness contained the correction the whole time, in a
function with a comment stating it.  **When a measurement defines the work,
check that it measures the object the HYPOTHESIS names.**

---

## Iteration 185 — THE RESISTANT PAIR, WORKED OUT: every admissible quotient is two-exit

184 found exactly one pair in 59993 that no quotient in the bisimulation
lattice solves, and said the next step was to settle it.  Settled far
enough to be decisive about the ROUTE.

**FIRST: it is not a search-budget artefact.**  Re-ran the lattice search
at caps 512, 4096 and 65536.  **30/31 at every cap.**  The enumeration is
not the limit.

**SECOND: this pair has EXACTLY TWO admissible quotients, and both are
MULTI-EXIT.**  Computed and cross-checked by hand and by script
(`runs/lattice-resistant-analysis.md`):

    principal congruence of (start_e ~ start_f)   4 states, SCC exits at 2
    full bisimulation collapse                    3 states, SCC exits at 2

Nothing lies between — merging any other pair of blocks would identify a
halting state with a non-halting one, which is not a congruence.  **So for
this pair the lattice offers no escape at all.**  184's reading, that a
coarser quotient dissolves the multi-exit shape, holds for 30 of the 31 and
provably fails for this one.

**THIRD: why elimination fails, in three lines.**  With `A = a0∨a1`,
`B = a2`, `C = a3` and `E = p;p`, the collapse is

    X0 = ite A (p;X0) (ite B (p;X2) (test C))
    X2 = p;X1
    X1 = ite (a0∨a2) (p;X2) (ite a1 (p;X0) (test C))

`X2` goes trivially, `w3` closes `X0`, and substituting leaves

    X1 = ite (a0∨a2) (E;X1) (ite a1 (p; wh A p; ite B (E;X1) (test C)) (test C))

**`X1` occurs in BOTH branches**, the second behind an action, so it is not
a top-level guarded self-call and `w3` does not apply.  Eliminating `X1`
first leaves `X0` doubled by the same symmetry.  This is the two-exit
obstruction in its smallest form: the loop is leavable from `X0` on `C` and
from `X1` on `C`, and which exit is taken is not a test at the head.

**WHAT IT ESTABLISHES, precisely.**  All three blocks' languages ARE
expressible — each contains a Thompson state of `e` or `f`, whose label is
an expression — and the quotient satisfies the nesting coequation.  So this
is no counterexample to expressibility.  **It is an obstruction to the
ROUTE**: `SumQuotientSolvable` is consumed by producing a solution and then
invoking uniqueness, and here a solution cannot be produced by elimination
from any admissible quotient.  It is **not yet** a refutation of the
hypothesis, because elimination is sufficient for finding a solution and
not necessary.

**THE OPEN QUESTION THIS INSTANCE POSES**, which is now the sharpest
statement of the whole campaign's remainder:

    Does the 3-state system above have a solution in GKAT expressions at
    all — by any means, not only by elimination?

If yes, the route survives and elimination needs strengthening.  If no,
**`SumQuotientSolvable` is FALSE** and the reduction chain that rests on it
dies — while completeness itself would remain open, since `e ≡ f` may still
be derivable by other means.

**Odds: ~45%, held.**  A concrete, minimal, fully characterized obstruction
is worth more than a percentage, and I decline to move the number until the
question above is answered either way.  It cuts both directions: settling
it "yes" restores the route, settling it "no" kills a reduction the project
has carried since the span era.

---

## Iteration 186 — THE RESISTANT PAIR IS SOLVABLE; the missing elimination move, found

185 posed the sharpest question the campaign has had: does the 3-state
system of the one lattice-resistant pair have a GKAT solution at all?
**It does.**

    X1 = wh a0 (p;p) ; X0
    X2 = p ; X1
    X0 = wh ¬a3 (ite (a0∨a1) p (p;p ; wh a0 (p;p))) ; test a3

Verified semantically before claiming: all three closed forms have exactly
the automaton's languages on every guarded string of up to 8 actions —
12863 / 14592 / 15488 strings, exact set equality, no discrepancy either
way.  (The first run appeared to disagree; the enumeration bounds were
mismatched by one atom.  Checked and fixed before drawing the conclusion —
the parser lesson from 180, applied in time this once.)

**THE MOVE CLASSICAL ELIMINATION LACKS.**  `X0` and `X1` differ ONLY at
atom `a0`: off `a0` both send `a1 → X0`, `a2 → X2`, and halt on `a3`.  So

    test ¬a0 ; X1  ≡  test ¬a0 ; X0

is PROVABLE — their dispatches select identically throughout `¬a0`.  Then
the trivial `X1 = ite a0 (p;X2) X1` becomes `X1 = ite a0 (p;X2) X0` by
rewriting the else arm, which is only ever observed on `¬a0`.  **That is a
Salomaa equation in `X1` with `X0` as its exit**, and `w3` closes it.
Substituting back turns `X0`'s equation into a Salomaa equation too.

Ordinary Gaussian elimination SUBSTITUTES an unknown's DEFINITION.  This
move IDENTIFIES TWO UNKNOWNS on a region that cannot tell them apart.
**The two-exit obstruction dissolves because the second exit was never
separate** — it was the same exit reached through a state that agrees off
one atom.

**LANDED IN LEAN** (`GkatCensusProofs.lean`, sorry-free):

* `eqRHS_congr_of_select_under` — selection congruence, RELATIVIZED: two
  states selecting EquivBA-equal expressions throughout a region have
  EquivBA-equal right-hand sides under that region's assertion.
* `gated_unknown_identification` — the move itself, on a solved system.
* `ite_else_swap` — the rewrite it licenses.  **Zero axioms.**

**The engine was already here.**  `fold_select_under`, the relativized
selection congruence, has been private in this file since iteration 169,
proved for a different purpose.  It is exactly what the new move needs.
That is the second time this month a needed tool turned out to be already
in the corpus; the difference is that this time I went looking.

**CONSEQUENCE, stated exactly.**  `SumQuotientSolvable` SURVIVES this
instance.  What failed was `symbolic_eliminable_raw` — a sufficient method
for finding a solution, not a complete one, which is precisely the caveat
185 attached to it.  So the measured picture is now:

    NA=4, 60000 pairs: 59993 analysed; ZERO known-unsolvable instances

**Odds: 45% → 52%.**  This is the first move in this window that changed
what I believe about the hypothesis rather than about the measurement.  A
concrete candidate counterexample was produced, examined, and DISSOLVED,
and the reason it dissolved is a general mechanism now in Lean rather than
an accident of this instance.  I am not going higher: one instance is one
instance, the general existence question is untouched, and the field's
prior that this problem does not close still stands.

---

## Iteration 187 — AT SCALE: 23 resistant pairs, and the new move covers 18 of them

186 solved one resistant instance and moved the odds on it.  Today ran the
census four times larger to find out whether that instance was
representative.  **It was mostly, not entirely.**

**THE SCALED MEASUREMENT** (NA=4, depth<=7, **240000 pairs**):

    pairs analysed                                    239967
    multi-state SCCs: walked 10504, chorded 115, OPEN    269
    of the 269 open pairs, LATTICE-SOLVABLE               246
    LATTICE-RESISTANT                                      23   (~1 in 10 400)

**The 1-in-60000 rate from 184 was a small-sample figure** — the true rate
is about six times higher.  Recording that because I quoted 184's number
as if it were the rate.

**IS THE NEW MOVE APPLICABLE?**  For each of the 23, take the full collapse
and look for two states of its multi-state SCC differing on a PROPER subset
of atoms — the precondition of `gated_unknown_identification`:

    applicable, states differ at 1 atom       12
    applicable, states differ at 2 atoms       6
    NOT APPLICABLE — no pair agrees anywhere    5

**18 of 23**, and the twelve one-atom cases are exactly the shape 186
solved by hand.  So the move is real and general enough to matter, and it
is NOT universal.

**THE FIVE THAT RESIST IT** all have a TWO-state SCC whose states differ at
EVERY atom.  Representative:

    q0: hl=1100 st=[q1,q1,-,-]      q1: hl=0000 st=[q0,q2,q0,q0]
    q2: hl=1000 st=[q2,q2,q2,-]

`q2` closes by `w3`; the SCC `{q0,q1}` then gives

    X0 = ite (a0∨a1) (p ; ite a1 (p;X2) (p;X0)) (test (a2∨a3))

— **a loop whose body has an EARLY EXIT**, and the two exits do different
things: leave at the top when the atom is outside `a0∨a1` and accept, or
leave mid-body when the atom after the first `p` is `a1` and run `X2`.  No
two states agree on any atom, so no region licenses the gated rewrite.

**Odds: 52% → 50%.**  186's bump was priced on ONE instance; a sample
twenty-three times larger shows the mechanism covers most of them and not
all.  Nudging back, not retreating: there is still no known-unsolvable
instance anywhere in 240000 pairs, and "the move does not apply" is not
"no solution exists" — exactly the distinction 185 drew and 186 vindicated.
Pricing that distinction correctly is the whole discipline here.

**NEXT OBJECT, named precisely: the five early-exit loops.**  Two states,
differing everywhere, one loop with an exit in the middle of its body.
Either they are solvable by a further move — and then that move is the next
general mechanism — or one of them is the counterexample this campaign has
been unable to produce for 187 iterations.

---

## Iteration 188 — ALL 23 ACCOUNTED FOR: exit absorption is the second move

187 left five resistant instances that gated identification cannot reach —
a two-state SCC differing at every atom, giving a loop whose body has an
EARLY EXIT.  **All five are solvable, by one observation: the escape
branch is not a break.**

    X2 = wh (a0∨a1∨a2) p ; test a3
    X0 = wh (a0∨a1) (p ; ite a1 (p ; X2) p) ; test (a2∨a3)
    X1 = ite a1 (p ; X2) (p ; X0)

Verified before claiming: exact language equality with the automaton on
every guarded string up to eight actions — 8116 / 9322 / 9841 strings.

**WHY IT WORKS.**  `X2` terminates only at `a3`.  `a3` is NOT in the outer
guard `a0∨a1`, so after the escape control returns to the loop head, the
guard rejects, and **the loop's own exit does the break's work**; and `a3`
IS in the trailing test `a2∨a3`, so that exit accepts.  The mid-body exit
is absorbed into the loop's normal exit and the branch is simply inlined.

**Checked on all five**: the escape continuation's halt atoms lie outside
the loop guard and inside the trailing test, every time.

**LANDED: `GkatCycle.exit_absorb`, ZERO AXIOMS.**  A continuation
terminating only inside a region `r` absorbs a following loop-and-test
when `r ⟹ c` and `c ⟹ ¬g`.  It is `park_absorb` lifted from a test to an
arbitrary continuation — the lemma has been in this file since the parked
stratum, one generalization away from this use.

**THE TALLY, at NA=4 over 240000 pairs:**

    lattice-resistant instances                    23
      solved by gated_unknown_identification (186) 18
      solved by exit_absorb (188)                   5
      UNACCOUNTED FOR                               0

**Every measured instance is now accounted for.**  Two moves beyond
classical elimination do it: IDENTIFY two unknowns on a region that cannot
tell them apart, and ABSORB a mid-body exit into the loop's own exit.
Both are small, both are provable from the finite axioms, and both were
found by taking a concrete resistant instance seriously rather than by
generalizing.

**Odds: 50% → 58%.**  This is a real update and I want to say why it is
not larger.  What changed: the resistant set is no longer a mystery — it
has a complete two-move account, and the moves are general mechanisms in
Lean, not case analysis.  What did NOT change: these are 23 instances out
of a generator's output, the moves are not proved SUFFICIENT in general,
and no theorem yet says every quotient yields to them.  The gap between
"every measured instance falls" and "every instance falls" is exactly the
gap this problem has always been.  The field's prior still stands.

**NEXT: prove a sufficiency theorem.**  The target is now clean —
elimination, plus gated identification, plus exit absorption, solves every
behavioural quotient of a Thompson sum.  That is a statement about a
three-rule calculus rather than about shapes, and it is the first time the
remainder has had that form.

---

## Iteration 189 — CROSS-VALIDATED: 69/69 across four populations, and both moves are needed

188 accounted for all 23 resistant instances in one population and priced
the odds cautiously because it was one generator's output.  Today: three
more populations, chosen to differ in the parameters that matter.

the census's move classifiers decides, per resistant instance, which move
applies — gated identification if two SCC states differ on a PROPER subset
of atoms, exit absorption if the escape continuation's halt atoms lie
outside the head's step guard and inside its halt mask.

    population                       resistant   gated   absorption   covered
    NA=4, depth<=7,  240000 pairs         23        18        5        23/23
    NA=3, depth<=7,  240000 pairs         21        13        8        21/21
    NA=2, depth<=7,  240000 pairs          4         0        4         4/4
    NA=4, depth<=10, 240000 pairs         21        18        3        21/21
    ---------------------------------------------------------------------
    TOTAL                                 69                          69/69

**Three atom counts, two expression depths, about 960 000 pairs, and every
lattice-resistant instance is covered.**

**BOTH MOVES ARE INDEPENDENTLY NECESSARY.**  At NA=2 the split is 0 gated /
4 absorption; at NA=4 it is 18 gated / 3–5 absorption.  Neither move
subsumes the other, and the mix shifts with the atom count — which is what
you would want to see if they are two genuine mechanisms rather than one
mechanism observed twice.

**THE PROXY, STATED HONESTLY.**  `check_moves.py` tests APPLICABILITY —
the move's precondition — not that the resulting system is solved.  Full
solutions were constructed and language-verified for exactly TWO
instances: 186's gated case (12863/14592/15488 strings, exact) and 188's
absorption case (8116/9322/9841, exact).  For the other 67 the
precondition is checked and the construction is not.  **69/69 is a
precondition rate, and I am not quoting it as a solution rate.**

**Odds: 58% → 60%.**  A small bump for a large increase in breadth,
deliberately small because the strengthened evidence is about
preconditions.  What would justify a real move is either the automated
construct-and-verify over all 69, or the sufficiency theorem.

**NEXT, in order:**

1. **Automate construct-and-verify** for the absorption cases — the
   construction there is fixed (`wh guard (step ; escape-dispatch) ; test
   trail`), so all 20 can be built and language-checked mechanically.
   That converts a precondition rate into a solution rate for those.
2. **The sufficiency theorem**: elimination + gated identification + exit
   absorption solves every behavioural quotient of a Thompson sum.  Still
   the target, and still the only thing that would close this.

---

## Iteration 190 — 20 OF THE 69 ARE NOW VERIFIED SOLUTIONS, NOT PRECONDITIONS

189 reported 69/69 and said plainly that it was a PRECONDITION rate, with
full solutions constructed and language-verified for exactly two instances.
Today closes that gap for the absorption half.

**the census's `absorption_verified`** builds the solution the absorption
move prescribes and checks it against the automaton:

    X_h = wh g (p ; <o's dispatch: back-to-h ↦ p, escape to w ↦ p ; X_w>)
          ; test trail

with `g` the head's step guard, `trail` its halt mask, and escape
continuations supplied as ORACLE LANGUAGES read off the quotient — so only
the absorption step itself is under test, not the rest of the automaton.

    population        absorption cases   VERIFIED   MISMATCH
    NA=2, depth<=7            4              4          0
    NA=3, depth<=7            8              8          0
    NA=4, depth<=7            5              5          0
    NA=4, depth<=10           3              3          0
    ----------------------------------------------------
    TOTAL                    20             20          0

Every instance the absorption move claims is now a CONSTRUCTED,
LANGUAGE-CHECKED solution.  The 49 skipped are exactly the gated cases —
the counts match the classifier's split instance for instance, which is a
consistency check I did not have before.

**THE TALLY, restated with the right labels:**

    lattice-resistant instances (4 populations, ~960 000 pairs)   69
      exit absorption — VERIFIED SOLUTIONS                        20
      gated identification — PRECONDITION CHECKED ONLY            49
      unaccounted for                                              0

**Odds: 60%, held.**  The upgrade is real — a construction that could have
mismatched and did not, twenty times — but it covers under a third of the
instances, and the gated majority is still evidence of a weaker kind.
Moving the number on a partial upgrade would be exactly the extrapolation
187 had to correct.

**NEXT: the same treatment for the gated cases.**  Harder, because the
absorption construction is a fixed shape while gated identification is a
REWRITE followed by elimination, so the solver has to search: substitute
closed forms, apply Salomaa where an unknown's equation permits it, and
use the gated rewrite when stuck.  That is a small symbolic eliminator
over 2–3 unknowns with oracle languages for everything outside the SCC —
a real build, and the right one, so it gets its own iteration rather than
the tail of this one.

---

## Iteration 191 — RUST-ONLY TOOLING (mandate), and every resistant SCC is MULTI-EXIT

**A standing mandate arrived mid-iteration: tooling is Rust, never Python.**
Recorded in memory as `rust-only-tooling`.  All six analysis scripts added
during 176–190 are retired, and the checks they performed now live in the
census itself, where the automata are already in hand:

    absorption_verified   builds `wh g (p ; <o's dispatch>) ; test trail`
                          from the a_test/a_act/a_seq/a_ite/a_wh combinators,
                          with escape continuations taken as the quotient
                          entered at the target, and compares guarded-string
                          languages to 7 actions
    gated_applicable      two SCC states differing on a PROPER subset of atoms
    t1t2_reducible        Hecht-Ullman, on the SCC
    exit_states           SCC members that halt or step out — Kosaraju's count

**This is strictly better than the port would have been.**  The scripts
parsed the census's own text dump; the Rust checks read the automaton
directly.  That removes the parsing step entirely — and a silent
block-boundary bug in exactly that step produced iteration 179's published
false finding.  A whole class of error is gone rather than translated.

**The Rust checks REPRODUCE the retired scripts' numbers exactly:**

    NA=2  gated 0   absorption 5, verified 5
    NA=3  gated 13  absorption 8, verified 8
    NA=4  gated 18  absorption 5, verified 5

(NA=2 reads 5 rather than the scripts' 4 because the Rust pass scans every
SCC of the quotient, not only the largest — one more instance of the shape,
and it verifies.)

**AND A NEW FACT, free from the new counters:**

    lattice-resistant SCCs, NA=3: 21 total; T1/T2-reducible 21; MULTI-EXIT 21
    lattice-resistant SCCs, NA=4: 23 total; T1/T2-reducible 23; MULTI-EXIT 23

**EVERY lattice-resistant SCC is MULTI-EXIT, and every one is reducible.**
That is the sharpest structural statement the census has produced.  It says
the two new moves are aimed exactly where they should be: multi-exit is
precisely what defeats plain elimination, reducibility is precisely what
says a nest of loops could exist, and the resistant set is the intersection.
It also retires any lingering worry that the resistant instances are
irreducible monsters — none is.

**Two older span-era generators (`emit_cert.py`, `emit_ring.py`, ~1000
lines) are retired rather than ported**: nothing references them, their
Lean output is already committed, and the ring/cert pilot route they served
was superseded long ago.  Git history keeps them if that judgement is wrong.

**Odds: 60%, held.**  A tooling migration and one structural observation;
the mathematics did not move.

**Note on what did NOT get finished.**  The general symbolic eliminator for
the 49 gated cases was attempted this iteration and does not work yet: the
search finds a candidate, and moving the language check inside the search
made it correct but too slow to finish a population.  The attempt is
discarded rather than committed half-working.  Porting it to Rust — inside
the census, using the existing combinators — is both the mandate-compliant
move and, on today's evidence, the faster one.

---

## Iteration 192 — THE SYMBOLIC ELIMINATOR, MIGRATED AND MADE TO WORK: 46/49 VERIFIED

190 said the gated cases needed a solver and that it should be Rust inside the
census.  Built, and the optimization that mattered was not the one I expected.

**THE MIGRATION.**  `calculus_solves` in the census: an expression IR (`Ex`)
with `Unk` for an unsolved SCC state and `Sub` for an oracle outside it, and a
backtracking search over three rules —

    SUBST     an equation with no self-occurrence is a definition; substitute
    LOOPIFY   with a self-occurrence, propose `wh g (body[X := 1]) ; fallback`
              — exactly `w3` when every branch ends in `X`, and iteration 188's
              EXIT ABSORPTION when a branch instead runs a continuation that
              terminates outside `g`
    GATED     iteration 186: two unknowns agreeing off a region `r`

**THE OPTIMIZATION THAT MATTERED.**  My first version realized each candidate
as an automaton with the Thompson combinators and compared languages.  Every
proposal came back **`overflow`** — composing oracles with `a_seq`/`a_wh` blows
past `MAXK` after two or three steps.  The search was not being told "wrong",
it was being told nothing, and it failed on instances I had solved BY HAND.

Evaluating the DENOTATION instead — `ex_accepts`, straight recursion on
guarded strings with unknowns read as their oracles — has no size limit and is
exact.  That single change took NA=3 from 1/2 to 2/2 and NA=4 from 0/1 to 1/1.
**A trace found it in one run after an hour of reasoning had not**; the verdict
string I printed was the whole diagnosis.

The same evaluation is also the pruning.  Any correct solution satisfies
`sol_s[X_t := q@t] ≡ q@s`, so a proposal is checked THE MOMENT IT IS MADE and a
wrong `LOOPIFY` dies with its subtree instead of at the leaf.  Runs that
previously timed out at 900s now finish inside the census.

**THE RESULT** (NA=2/3/4, depth<=7, 240000 pairs each):

    NA=2   5 / 5    NA=3   20 / 21    NA=4   21 / 23     TOTAL 46 / 49

**These are VERIFIED SOLUTIONS**, not preconditions: each is a constructed
expression whose guarded-string language matches the quotient's on every string
up to 5 actions, for every state of the SCC, with no unknown left in it.

**AND THE HONEST CORRECTION THAT COMES WITH IT.**  Iterations 188 and 189
reported "all 23 accounted for" and "69/69", and I labelled those a PRECONDITION
rate at the time.  With a solver that actually constructs and checks, the rate
is **46/49 — three resist.**  The precondition was a weaker signal than it
looked, exactly as the label said, and now there is a number that means what it
says.

**THE THREE, dumped.**  All the same shape: two states with IDENTICAL
transitions whose halt masks differ at exactly one atom, one ACCEPTING there and
the other REJECTING (no step, no halt).

    q0: hl=1100 st=[q0,q1,-,-]     q2: hl=1000 st=[q0,q1,-,-]
    q1: hl=0000 st=[q2,q2,q2,q2]

I found a real bug in the GATED rule while looking at them — the rewritten
fallback was bare `X_v`, silently asserting `X_u ≡ X_v` and dropping the guard,
where it should be `ite r (test (hl_u ∧ r)) X_v`.  Fixed, and **it did not
change the count**: the three resist for some further reason.  Recording the
fix as correct-but-not-the-cause rather than claiming it.

**Odds: 60%, held.**  The verified rate went from 20/69 to 46/49, which is a
much better instrument — and it also revealed three genuine resisters where the
precondition count had said zero.  Those cancel.

**NEXT: the three.**  They are small, dumped, and share one shape.  Either a
fourth move handles them, or they are the first evidence that the calculus is
incomplete.

---

## Iteration 193 — 99/99: the calculus solves every measured resistant instance

192 left three resisters and said either a fourth move handles them or the
calculus is incomplete.  **Neither: it was one condition in the search.**

**THE BUG.**  A GATED rewrite of a state that only REJECTS on the differing
atom produces an equation with NO BRANCHES — all its content is in the
fallback.  `LOOPIFY`/`SUBST` skipped equations with an empty branch list.
One `br.is_empty() ||`, and exactly that shape was unreachable.

**THE SHAPE, worked by hand first** (which is how the condition was found —
the derivation existed, so the search had to be wrong):

    q0: hl=1100 st=[q0,q1,-,-]      q2: hl=1000 st=[q0,q1,-,-]
    q1: hl=0000 st=[q2,q2,q2,q2]

`q0` and `q2` have IDENTICAL transitions, differing only at `a2` where `q0`
ACCEPTS and `q2` REJECTS.  GATED gives `X2 = ite a2 0 X0`, which is CLOSED.
Substituting and rewriting `ite a2 0 X0 ≡ test(¬a2) ; X0` puts BOTH step
branches in `… ; X0` form, and `w3` closes it.

**THE RESULT — six populations, 240000 pairs each:**

    NA=2 depth<=7    5 / 5      NA=2 depth<=10    3 / 3
    NA=3 depth<=7   21 / 21     NA=3 depth<=10   26 / 26
    NA=4 depth<=7   23 / 23     NA=4 depth<=10   21 / 21
    -----------------------------------------------------
    TOTAL                                       99 / 99

**Every lattice-resistant SCC in ~1.44 million pairs is solved, and every
solution is CONSTRUCTED AND LANGUAGE-CHECKED** — not a precondition, not an
applicability rate.  Three atom counts, two expression depths.

**What this is, and what it is not.**  It is: a three-rule calculus —
elimination, gated identification, exit absorption — that solves every hard
instance a large generator produces, with each answer verified.  It is not:
a proof that it always does.  The gap between "every measured instance" and
"every instance" is the same gap this problem has had for 193 iterations,
and no amount of measurement closes it.

**Odds: 60% → 66%.**  The instrument that produced 46/49 yesterday now
produces 99/99, and the difference was a search bug rather than mathematics
— so the evidence is about the calculus, not about my patience with it.
Two things keep this from going higher: the calculus has no sufficiency
proof, and none of it is in Lean yet.  Both are nameable next steps, which
is itself worth something.

**NEXT, and now the whole remainder in two lines:**

1. **Formalize the calculus in Lean** — `gated_unknown_identification` and
   `exit_absorb` exist; what is missing is the elimination loop as a theorem
   about systems rather than a search over instances.
2. **Prove sufficiency**: every behavioural quotient of a Thompson sum is
   solved by these three rules.  That is the last statement standing between
   this development and `SumQuotientSolvable`, hence completeness.

---

## Iteration 194 — THE GATED REWRITE IS IN LEAN, in the form the solver uses

193 named the remainder in two lines: formalize the calculus, then prove
sufficiency.  This is the first line's hardest piece.

**`GkatCensus.gated_rewrite`** — sorry-free, `[propext, Classical.choice,
Quot.sound]`:

    sol u  ≡  ite d (sol u) (sol v)

given that `u` and `v` select EquivBA-equal expressions off `d`.  Not the
SEMANTIC statement of iteration 186, the EQUATIONAL one: an unknown may be
replaced by another INSIDE THE ELSE ARM of the region where they differ,
because the else arm is only ever observed there.  `u1` duplicates,
`ite_else_swap` rewrites the else arm, and the hypothesis is
`gated_unknown_identification` at `¬d`.  **Three lines, and it is the whole
rule.**

**`GkatCensus.gated_rewrite_reject`** — the case that closed the last three
measured instances:

    sol u  ≡  ite d 0 (sol v)        when `u` rejects throughout `d`

The rewritten equation is then CLOSED — the self-reference is gone — which
is precisely what let `w3` finish.  `u4` asserts `d` in the then arm and the
rejection hypothesis collapses it.

**ALL THREE RULES ARE NOW IN LEAN:**

    elimination        self_gather_role / StateRole.salomaaE   (w3)
    exit absorption    exit_absorb                             (zero axioms)
    gated rewrite      gated_rewrite, gated_rewrite_reject

Each is a theorem about a solved system, provable from the finite axioms,
with no uniqueness axiom anywhere.

**WHAT IS STILL MISSING, precisely.**  The rules are sound INDIVIDUALLY.
What is not formalized is the LOOP: that iterating them terminates with a
labelling that solves the whole system.  In the Rust solver that is a search
with a budget; as a theorem it needs a measure that decreases — the obvious
candidate is the number of unknowns, since SUBST and LOOPIFY each eliminate
one, but GATED eliminates none and must therefore be bounded separately (the
solver bounds it by forbidding a second rewrite of the same unknown, which
is a hint at the right measure rather than a proof).

**Odds: 66%, held.**  A formalization step that adds no new mathematics — the
rule was already understood and measured; today it is machine-checked.  The
number moves when the loop or the sufficiency proof lands, not before.

---

## Iteration 195 — THE LOOP'S SOUNDNESS IS FINISHED; only SUFFICIENCY is left

194 said the loop was unformalized and would need a decreasing measure.  That
was the wrong diagnosis, and today's work says why: the loop has two halves,
and only one of them is mathematics.

**SOUNDNESS — now complete.**  Every rule has a CONSTRUCTIVE form producing a
role for the state it assigns, and `decomp_solves` (already in the corpus)
turns a full assignment of roles into `SolvesBA`:

    SUBST      definitional
    LOOPIFY    `StateRole.salomaaE`, discharged by `salomaa_solution_exists`,
               with `exit_absorb` for the absorbing case
    GATED      `gated_solves` → `gated_role`          ← today

**The missing piece was the GATED rule's constructive form**, and the reason
it was missing is worth recording.  `gated_rewrite` (194) says: GIVEN a
labelling that already solves the system, two states agreeing off `d` are
interchangeable in the else arm.  That is the right statement for reasoning
about a solution and **the wrong one for building one** — the calculus does
not have a solution yet, it is making one.

`gated_solves` is the constructive form: DEFINE `sol u := ite d D (sol v)`
with `D` agreeing with `u`'s own equation on `d`; then `sol u` SATISFIES
`u`'s equation, assuming nothing about the rest of the system beyond `v`
satisfying its own.  `split_on`, `ite_c`, `eqRHS_congr_of_select_under`,
`unsplit` — four steps.  In the rejecting case the caller takes `D := 0` and
`hD` becomes "`u` rejects throughout `d`".

Also landed: `ite_then_swap`, the dual of `ite_else_swap`, **zero axioms**.

**SO THE MEASURE 194 CALLED FOR IS NOT NEEDED.**  A decreasing measure would
be needed to prove the loop TERMINATES.  But soundness does not require
termination: if the loop stops with every state assigned, `decomp_solves`
gives `SolvesBA` regardless of how it got there.  Termination only matters
for the ALGORITHM, and the algorithm is Rust and measured.  194's "needs a
decreasing measure" was reasoning about the wrong obligation.

**WHAT IS ACTUALLY LEFT, and it is one sentence.**

    SUFFICIENCY: on every behavioural quotient of a Thompson sum, the three
    rules can be applied until every state is assigned.

That is the whole remainder.  It is not a packaging question and no amount of
Lean plumbing reaches it — it is the statement that a concrete calculus is
complete for a concrete class, measured true on 99/99 hard instances across
1.44 million pairs and proved for none.

**Odds: 66%, held.**  Soundness closing is real progress and changes nothing
about the odds: it was always the half that was going to close.

---

## Iteration 196 — STRESSING THE CALCULUS: 228/269, and the two mechanisms are complementary

195 reduced the remainder to one sentence — SUFFICIENCY.  Before attempting
it, the disciplined move is to try to FALSIFY it, and the cheap way is to run
the calculus on a much harder sample than the lattice-resistant set.

**The change**: the calculus now runs on EVERY open SCC of the full collapse,
not only the ~1-in-10⁴ lattice-resistant ones.  That is roughly a ten-fold
larger sample of hard instances.

**NA=4, 240000 pairs:**

    open SCCs in the full collapse                                269
      solved by the calculus ON THE FULL COLLAPSE                 228
      NOT solved on the full collapse                              41
    lattice-resistant (no quotient the old oracle solves)           23
      solved by the calculus                                    23/23

**So the calculus is NOT universally applicable to the full collapse** —
41 of 269 resist it there.  That is a real limitation and it is the first
time the calculus has failed on anything.

**But the two mechanisms are exactly complementary.**  All 23
lattice-resistant SCCs are solved by the calculus; therefore all 41
calculus-failures lie inside the 246 that a COARSER quotient solves.  Union:
269 of 269.  **Every measured open pair is handled either by the calculus on
the full collapse or by a coarser quotient**, and neither mechanism covers
the other's residue.

**WHICH SHARPENS THE SUFFICIENCY STATEMENT.**  It is not "the calculus solves
the full collapse" — measurably false.  It is:

    for every language-equivalent pair, SOME admissible quotient is solved
    by the three rules.

The full collapse is the top of the congruence lattice, not the whole of it;
iteration 184 learned that once already, and I had quietly let the sharper
version drift back to the loose one.

**AND A MEASUREMENT I COULD NOT AFFORD.**  Running the calculus over the
WHOLE lattice — every admissible congruence, not just the full collapse — is
the direct test of the sentence above.  It is hundreds of congruences per
pair, each with its own SCC search and language check, and it makes the
census unrunnable at 10⁵ pairs.  Left behind `PAD_CALC_LATTICE`, off by
default, and reported as not-yet-measured rather than folded into a number.

**Odds: 66%, held.**  The falsification attempt found a genuine limitation of
the calculus and did not falsify the hypothesis; those roughly cancel.

---

## Iteration 197 — OPTIMIZATION PASS: 6x, and it was the phase I had not measured

**Instrumented first, per the standing lesson, and it paid for the fourth
time.**  I assumed the three-rule calculus was the cost and spent two changes
on it: `accepts_at` (walking from a state instead of copying a 320-byte `Aut`
per oracle leaf) and a verdict memo keyed on a structural hash of the
proposal.  The memo cut `ex_accepts` from **124 million to 50 million** calls
per 60 000 pairs, preserved every solved count — and moved the wall clock by
nothing.

Phase timers said why:

    [phases] total 0.1s = lattice 0.0s + calculus 0.1s + absorption 0.0s

**The entire analysis was 0.1s of a 9s run.**  The other 8.9s was PAIR
GENERATION — and it was the only serial phase in a program that is parallel
everywhere else, which is where the previous three passes on this harness
each found their win.

**The fix**: draw one seed per try serially (nanoseconds, keeps the draw order
deterministic), map the batch through `genexp` → `canon` → `behaviour` in
parallel with rayon, merge into the buckets serially.

    NA=3, 60 000 pairs      9.0s  ->  1.5s     (6.2x)
    NA=2, 240 000 pairs     timeout (>550s)  ->  4.6s
    NA=4, 240 000 pairs     timeout (>550s)  ->  6.1s

**CAVEAT, stated plainly**: the sample is NOT bit-identical to previous runs —
each try now uses its own xorshift stream seeded from the serial one.  Rates
are comparable; specific instance dumps are not.  Earlier passes on this
harness preserved outputs exactly, and this one does not.

**AND THE FIRST INSTANCE NEITHER MECHANISM HANDLES.**  On the new sample,
NA=4 at 240 000 pairs:

    lattice-resistant SCCs solved by the calculus: 14 / 15

The one that resists:

    q2: hl=1000 st=[q3,q3,-,-]        halts a3; steps a0,a1 -> q3
    q3: hl=0001 st=[-,-,q2,-]         halts a0; steps a2 -> q2

**Two exit states, and neither exit can be absorbed.**  Head the loop at q2:
its guard is `{a0,a1}`, and q3's accept sits at `a0` — INSIDE the guard, so
the loop continues where it should stop.  Head it at q3: guard `{a2}`, q2's
accept at `a3` is outside it so the loop does exit — but the trailing test is
then `a0`, which fails at `a3`.  Absorption needs the exit atom outside the
guard AND inside the trailing test, and no rotation gives both.

This pair is **lattice-resistant and calculus-resistant** — the first instance
in the campaign that neither mechanism covers.  It is a CANDIDATE, on the same
terms as iteration 185's: resistance is not a proof of unsolvability, and 186
dissolved the last such candidate with a move that did not exist yet.

**Odds: 66% -> 62%.**  A 6x faster instrument found, in its first larger
sample, an instance the calculus does not solve.  That is the correct
direction for the evidence to move, and it is small because one candidate is
one candidate — 185 produced one and it turned out solvable.

**NEXT: settle it**, exactly as 185/186 settled the last one.  Either a fourth
move handles it — and the two-exit analysis above says what that move must do
— or it is the counterexample.

---

## Iteration 198 — THE NEW RESISTER IS SOLVABLE: entry restriction, the third move

197 produced the first instance neither the lattice nor the calculus handles
and called it a candidate on 185's terms.  **It is solvable**, and the move
that solves it is new.

    q0: hl={a3} st=[q1,q1,-,-]        q1: hl={a0} st=[-,-,q0,-]

    X1 = test{a0,a2} ; wh {a2} (p ; ite a3 1 (test{a0,a1} ; p ; test{a0,a2}))
         ; test{a0,a3}
    X0 = ite {a0,a1} (p ; X1) (test{a3})

**Checked, not argued** (`PAD_CHECK_CAND`, Rust, in the census binary): exact
guarded-string language equality with the automaton at depths 4, 6 and 8, for
both states.

**THE MOVE: PRE-GUARD THE LOOP AND ASSERT AT THE END OF ITS BODY.**  Exit
absorption (188) needs the escaping exit's atom to be OUTSIDE the loop guard
AND INSIDE the trailing test.  Here no rotation gives both: head at `q0` and
its guard `{a0,a1}` contains `q1`'s accept atom `a0`; head at `q1` and the
guard `{a2}` excludes `q0`'s accept atom `a3`, but the trailing test is then
`{a0}`, which rejects `a3`.

The repair is to WIDEN the trailing test to `{a0,a3}` and make that safe by
controlling which atoms can reach the loop head:

* the PRE-GUARD `test{a0,a2}` kills the initial entry at `a1`/`a3`, where
  `q1` rejects;
* the body's TRAILING ASSERTION `test{a0,a2}` kills the RE-entries at
  `a1`/`a3`;
* the `a3` escape from `q0` returns to the head unasserted, the guard fails,
  and the widened trailing test accepts it.

So the loop head is only ever reached on atoms where the wider test is
correct, and the two exits collapse into one.

**This GENERALIZES exit absorption** rather than sitting beside it.
Absorption asks the automaton to be shaped so one trailing test already
serves both exits; entry restriction MAKES that true by restricting the
entry and re-entry regions.  188's rule is the case where the restriction is
vacuous.

**THE GENERAL LEMMA, stated for the next iteration to prove:**

    if the body always terminates inside a region R, and the loop is entered
    inside R, then the trailing test is only ever evaluated on R ∧ ¬g — so any
    two trailing tests agreeing there are interchangeable.

That is provable with `w3_ba`: both sides solve the same Salomaa equation
once `R` is carried through the body.  It is the fourth rule, and the first
one whose Lean form is not already sitting in the corpus.

**Odds: 62% -> 66%.**  Back where 196 left it, and for the same reason 186
moved it: a concrete candidate counterexample was produced, examined, and
dissolved by a mechanism that generalizes rather than a trick that fits.
Twice now the candidate has fallen; that is a pattern worth noticing and not
yet worth trusting.

---

## Iteration 199 — ENTRY RESTRICTION IS IN LEAN, and it is a loop invariant

198 solved the new resister by hand and named the general lemma.  Proved,
first try, and with **ZERO AXIOMS** — no `propext`, no choice.

**`GkatCensus.entry_restricted_trailing`:**

    hprod : E(B) ≡ 0                         -- w3's productivity side condition
    hB    : B ; test R  ≡  B                 -- the body always ends inside R
    hF    : ¬(R∧g) ∧ R ∧ F₁  =  ¬(R∧g) ∧ R ∧ F₂
    ⊢  test R ; wh g B ; test F₁  ≡  test R ; wh g B ; test F₂

**The algebra is a loop invariant, in the Hoare sense**, and today's search
made that explicit: establishment is the pre-guard `test R`, preservation is
`hB`, and the postcondition is exactly `R ∧ ¬g` — which is why two trailing
tests agreeing there are interchangeable.  I had been calling this
"pre-guarding and asserting"; it is the oldest idea in program verification,
arriving from the other direction.

**The proof is `w3` used for UNIQUENESS, not construction.**  Both sides
satisfy the same Salomaa equation — `Y ≡ ite (R∧g) (B ; Y) (test (R∧F₁))` —
once `R` is carried through the body by `s1` and `hB`, and once the second
side's fallback is swapped by `ite_else_swap` on the region where the
hypothesis holds.  `w3_ba` then identifies them.  Five steps.

**ALL FOUR RULES ARE NOW IN LEAN:**

    elimination        self_gather_role / StateRole.salomaaE   (w3)
    exit absorption    exit_absorb                             (zero axioms)
    gated rewrite      gated_solves / gated_role
    entry restriction  entry_restricted_trailing               (zero axioms)

and `exit_absorb` is the vacuous-restriction case of the last, so the two
loop rules are one rule with a parameter.

**WHAT IS LEFT is unchanged and is still one sentence**: SUFFICIENCY — that
on every behavioural quotient of a Thompson sum the rules can be applied
until every state is assigned.  Four rules now instead of three, which is
weaker evidence for sufficiency, not stronger: each new rule is a case the
previous set could not reach.

**Odds: 66%, held.**  Formalizing a rule I already had adds no evidence about
whether the set is complete.  What would move the number is the Rust solver
learning the fourth rule and the resistant counts going to zero again at
scale — that is the next measurement, and it is a real one, because 197
showed a larger sample finds what a smaller one misses.

---

## Iteration 200 — THE SOLVER LEARNS THE FOURTH RULE, and the resister closes

199 proved entry restriction in Lean and said the real test was teaching it to
the solver and re-measuring.  Done.

**THE IMPLEMENTATION is one generalization, not a fourth branch.**  LOOPIFY
already proposed `wh g (body with X_s := 1) ; fallback`.  Entry restriction is
the same construction with two parameters:

    sol s := test P ; wh g (body with X_s := test P) ; test F

`P` is the region the loop head may be reached in — asserted BEFORE the loop
and again wherever the body returns — and `F` is the trailing test, which may
then be WIDENED past `s`'s own halt to cover a mid-body exit that
`exit_absorb` cannot reach.  **Plain LOOPIFY is `P = all`, `F = hl(s)`**, so
one construction covers both rules, exactly as the Lean says (`exit_absorb` is
the vacuous-restriction case of `entry_restricted_trailing`).

The candidate set is deliberately tiny: `P` is everything or `s`'s live atoms;
`F` is `s`'s halt mask alone or widened by one atom outside the guard.  Four
to ten proposals per state.  The language check disposes of wrong guesses, and
a small guess-and-check beats analysing which invariant is needed — which is
also how the loop-invariant literature does it.

**THE MEASUREMENT** (240 000 pairs each, post-parallel sample):

    NA=2   lattice-resistant SCCs solved   12 / 12
    NA=4   lattice-resistant SCCs solved   15 / 15      (was 14 / 15)
    NA=3   8 / 8 at 60 000,  13 / 13 at 120 000

**197's resister closes**, and nothing else regressed.  Open SCCs solved on
the full collapse at NA=4 went 213 -> 214.

**A performance note, unresolved.**  NA=3 at 240 000 pairs still runs past
400s while NA=2 and NA=4 finish in 5-6s.  It is not generation — NA=3 needs
117 tries per pair against NA=4's 76, so at most 1.5x — and it completes fine
at 120 000.  Something is superlinear in the analysis at NA=3 specifically.
Recorded as open rather than guessed at; the last two times I guessed at this
harness's hot spot I was wrong.

**Odds: 66%, held.**  A rule I already had, now mechanised, closing an instance
I already knew it closed.  The evidence about SUFFICIENCY is unchanged: four
rules cover everything measured, and there is still no theorem that four
suffice.  What 197 taught is that a bigger sample finds new shapes, so the
honest next move is a bigger sample — not another rule.

---

## 201 — THE HALT-IN-BODY RULE.  The bigger sample paid, and rule 5 is proved.

200's ledger said the honest next move was a bigger sample, not another rule.
The bigger sample produced another rule.  Both halves of that sentence matter.

**First, the perf note at 200 was wrong about its own cause, twice over.**
Phase timers say NA=3 analyses 180 000 pairs in 0.6s — the analysis was never
the problem.  Two things were:

1. *The reporting wall.*  Every lattice-resistant pair dumped two fully
   parenthesised `Exp` trees, and Rust's `println!` flushes per line, so a run
   finding thousands of them spent its life in `write(2)`.  Now gated behind
   `PAD_CENSUS_DUMP`, with two exceptions that ALWAYS print: a
   calculus-resistant SCC (the thing the census exists to find) and an
   absorption MISMATCH (a soundness alarm, not a statistic).
2. *A memory ceiling.*  With the dump gated, NA=3 dies at `exit=137` — SIGKILL
   — at ~291s whether N is 240 000 or 480 000.  Identical time for doubled work
   is the signature of an OOM, not of slow analysis.  Still open; not guessed
   at.  What it did NOT turn out to be is anything superlinear in the analysis,
   which is what 200 supposed.

**Second, and the real result.**  Before dying, the 480k NA=3 sweep found a
three-state SCC the four-rule calculus cannot solve — at depth 5 *and* at depth
9, so not a search-depth shortfall:

    q0: hl={a0,a1} st=[-,-,q1]   q1: hl={} st=[q1,q2,q1]   q2: hl={a1} st=[q0,-,q1]

Two exit states, q0 and q2.  Kosaraju says no aux-variable-free structuring of
the GRAPH exists — but the automaton is a bisimulation quotient of a Thompson
sum, so every state is bisimilar to a Thompson state, and a solution must
exist.  Solving it by hand:

    Seg = wh {a0,a2} p ; p
    X1  = Seg ; X2
    X2  = wh {a2} Seg ; ite a1 1 (p ; X0)
    X0  = ite a2 (p ; Seg ; wh {a2} Seg ; ite a1 1 (p ; X0)) 1

The last line is the new shape: it recurses under a test (`a0`) that DIFFERS
from its entry test (`a2`), and the recursion site sits inside an `ite` whose
other branch is a HALT, not a dead end.  Neither `exit_absorb` (which needs the
mid-body exit reachable from the head's own halt) nor `entry_restricted_trailing`
(which needs one trailing test to cover every exit) reaches an exit living
*inside* the body.

It loopifies anyway:

    X0 = wh {a2} (p ; Seg ; wh {a2} Seg ; ite a0 p 1)

`ex_matches` confirms X0, X1, X2 all MATCH the automaton at depths 4, 6, 8, 10
(`PAD_CHECK_R201`), so the derivation is checked, not argued.

**Rule 5, proved in Lean, ZERO AXIOMS** (`halt_in_body_loopify`) — not even
`propext` or `Classical.choice`:

    X ≡ ite g (D · ite c (P · X) 1) 1     and     D · ¬g ≡ D
    ────────────────────────────────────────────────────────
    X ≡ wh g (D · ite c P 1)

The hypothesis `D · ¬g ≡ D` — the body lands outside the loop guard — is what
pays for it: in the else arm of `c` the unknown unrolls to `1`, so dropping the
recursive call there is exactly what turns the body into `D · ite c P 1` with
`g` alone as the guard.  One trailing conditional action serves as BOTH the
back-edge and the second exit.  `w3_ba` at one unknown; no n-ary uniqueness.
Supporting lemma `ite_zero_guard`, also zero axioms.

**Odds: 66%, held — and the reasons cut both ways.**  Against: the four-rule
calculus was NOT complete, and I had said at 200 that the evidence for
sufficiency was unchanged while quietly hoping four was the number.  It was
five.  A calculus that grows a rule each time the sample grows is not obviously
converging, and the field's prior that this problem does not close still
stands.  For: the new rule was found, derived, machine-checked against the
witness, and proved in Lean inside a single iteration, and it needed no new
axiom and no auxiliary variable — the `w3_ba`-at-one-unknown budget absorbed
it.  Five rules is still a finite calculus.

**Next.**  Teach the solver rule 5 (as 200 taught it rule 4 — likely another
generalisation of LOOPIFY rather than a fifth branch), then fix the OOM, then
sample again.  The sampling loop is working: it is producing shapes faster than
I can guess at them.

---

## 202 — THE SOLVER LEARNS RULE 5, AND THE FULL COLLAPSE CLOSES AT NA=3 AND NA=4.

The literature's standard fix for a loop with several exits is a REGISTER that
records which exit fired, examined after the loop — an auxiliary variable,
exactly what GKAT forbids.  Every rule in this calculus is a register-free way
to carry the same information; rule 5 carries it in a trailing conditional
action.

**What the solver was missing was one mask.**  Plain LOOPIFY takes the loop
guard to be the union of ALL the state's branch masks.  That is wrong whenever
a state's branches SPLIT between returning to itself and leaving for another
state: `wh` over the union never exits at the leaving atoms.  For 201's
resister, `q1` has `{a0,a2}` returning and `{a1}` leaving, so no proposal the
solver could make was even the right shape.  The fix:

    sol s := wh g_self (returning branches, X_s := 1)
             ; dispatch(leaving branches, fallback)

where `g_self` is the union of the masks of the branches whose body actually
mentions `X_s`.

**Tracing this by hand reproduces 201's derivation exactly**, `q1` then `q2`
then `q0`, including the final step where `X0` appears nested inside
`ite a0 (p·X0) 1` rather than at a tail.  `PAD_CHECK_R201` now reports the
calculus solving the resister at depth 5 as well as 9.

**What is proved and what is not.**  When `X_s` sits at the TAIL of the body,
the construction is plain Salomaa elimination — `w3` at one unknown, long
proved; the solver simply was not proposing that guard.  When `X_s` sits
NESTED inside `ite c (P·X_s) 1` with the body landing outside the guard, it is
`halt_in_body_loopify`, proved at 201.  Substituting `X_s := 1` under
ARBITRARY deeper nesting is broader than either rule, and is NOT proved.  That
gap is named here rather than papered over; it is the next Lean target.

**Measured, 240 000 pairs (NA=3 at 120 000, where it does not yet OOM):**

    NA=2   lattice-resistant 12/12    full-collapse open SCCs 102/104
    NA=3   lattice-resistant 13/13    full-collapse open SCCs 190/190
    NA=4   lattice-resistant 15/15    full-collapse open SCCs 250/250

The middle column is unchanged; the right-hand column is the result.  At 200
the full collapse at NA=4 stood at 214/250 and the calculus NEEDED the lattice
search to make up the difference — 196's complementarity.  It no longer does at
NA=3 or NA=4: the calculus alone now solves the full collapse outright.  That
is a stronger statement than anything measured before, because the full
collapse is a SINGLE canonical quotient, not an existential over the lattice.

**Two residual failures at NA=2 (102/104).**  They are not lattice-resistant —
all 12 of those fall — so a coarser quotient solves them and they were never
dumped.  That is a REPORTING gap: `CALCULUS-RESISTANT` only prints inside the
lattice-resistant branch, so a full-collapse failure that the lattice rescues
is invisible.  Worth closing before the next sample; an unprinted failure is
how 179's false finding happened.

**Odds: 68%, up 2.**  The move is small and the reason is specific: the thing
that improved is not "another rule covers another case" but that a SINGLE
canonical quotient — no existential, no search over the lattice — is now solved
outright on two of three populations.  SumQuotientSolvable only needs SOME
quotient, so full-collapse coverage is strictly more than required.  Against
it: NA=2 still has two holes, the arbitrary-nesting substitution the solver
performs is broader than the two rules that justify it, and the field's prior
that this problem does not close still stands.

---

## 203 — TWO HARNESS BUGS BEHIND THE "FAILURES", AND WHAT SURVIVES THEM.

The field's own frontier, restated by a 2025 Bucknell thesis: a uniqueness
theorem for solutions of Thompson-generated automata is in hand ("any two
solutions of the same automaton are provably equal"), and that is described as
opening a direction toward completeness.  That is exactly this development's
`certifiedThompson_solution_unique`.  Uniqueness is settled; EXISTENCE is the
open half, here and there.

**Bug 1 — the failure dump was dead code.**  The full-collapse calculus failure
report sat behind

    } else if { pair_calc_ok = false; false } {

a condition block evaluating to `false`, so only the side effect ran and the
dump never executed.  Every full-collapse failure since the counter was added
has been invisible.  This is the same shape of bug as 179's, which produced a
published false finding, so it now prints unconditionally — dump flag or not.

**Bug 2 — "failure" included "never attempted".**  `calculus_solves` opened
with a bare `if scc.len() > 5 { return false; }`.  An SCC too large to try was
returned as a FAILURE and counted as one.  Every rate published up to 202 was
deflated by SCCs the calculus never looked at.  Now `calculus_attempted` is the
caller's guard, the cap is raised to 7 and tunable via `PAD_CALC_MAXSCC`, and
skips are reported separately as UNKNOWN and excluded from the denominator.

**Corrected measurement (240 000 pairs; NA=3 at 120 000):**

    NA=2   103/104      NA=3   190/190      NA=4   250/250
    SCCs not attempted at cap 7: 0, 0, 0

202's NA=2 figure of 102/104 was wrong in my favour and against it at once: one
of the two "failures" was a six-state SCC that was never tried, and it solves
immediately once the cap allows it.  **The improvement from 102/104 to 103/104
is a harness fix, not mathematics.**  Nothing about the calculus changed.

**A hypothesis raised, refuted, and then un-refuted — worth recording because
the middle step was the honest one.**  Kosaraju: a loop with two distinct exits
cannot be structured without NODE SPLITTING.  Node splitting is un-collapsing —
descending the bisimulation lattice to a FINER quotient — which is exactly the
freedom `SumQuotientSolvable`'s existential grants.  If every full-collapse
failure were multi-exit, that would EXPLAIN 196's complementarity rather than
restate it.  Measuring it immediately produced a counterexample (`exits=1`),
which killed the hypothesis — and then the cap fix showed that counterexample
was the un-attempted six-state SCC, not a real single-exit failure.

**Where that leaves the claim: ONE instance.**  The sole surviving
full-collapse failure in 600 000 pairs is the NA=2 3-cycle

    q0: st=[q1,q2]   q2: st=[q3,q3]   q3: st=[q0,q4]

with `exits=2`, no halts anywhere, and its two exits leaving to DIFFERENT
external states.  By hand, every rotation fails identically: head `q0` gives
guard `a1` and body `p·p·ite a0 p (p·Y4)`, but after `p·Y4` control has left
for `Y4` and the loop re-tests `a1` regardless; head `q3` mirrors it; head `q2`
has no test at all so the guard is everything and the loop never exits.  Rule 5
does not apply — its sibling arm must be a HALT, and here it is `p·Y4`, an
arbitrary continuation.  It is lattice-solvable, as the complementarity
predicts.  **n=1 is not evidence for the Kosaraju explanation; it is one
instance consistent with it.**  Say so plainly.

**Odds: 68%, held.**  Deliberately not raised.  The headline numbers improved,
but every point of that improvement came from fixing my own instrumentation,
and two measurement bugs in one iteration is evidence that the published rates
have been noisier than claimed.  What genuinely improved is the reporting
floor: failures now print, and skips can no longer masquerade as failures.

**Next.**  The Kosaraju explanation is worth testing properly, which needs many
more full-collapse failures than one — so: raise the cap further, sample
harder, and count exits on every failure.  If it holds at n in the dozens, it
converts the complementarity from a measured coincidence into a reason.

---

## 204 — THE CANONICAL QUOTIENT.  The existential gets a name.

**Why this became urgent.**  Carter–Ferrante–Thomborson (2003), "Folklore
Confirmed: Reducible Flow Graphs are Exponentially Larger": making an
irreducible graph reducible by NODE SPLITTING can require `2^(n-1)` nodes, and
that bound is unavoidable.  Node splitting is un-collapsing — descending the
bisimulation lattice — and here the supply of nodes is capped by the Thompson
sum.  If restoring solvability ever needed more nodes than the sum affords,
`SumQuotientSolvable` would be FALSE.  That makes the existential worth
replacing, not just proving.

**There is a canonical candidate, and it needs no search.**  Proving `e ≡ f`
requires identifying the two start states; identifying them FORCES identifying
their successors atom by atom, to a fixpoint.  The smallest congruence
containing `(0, start_b)` is therefore the LEAST quotient any proof could use —
every admissible quotient is coarser.  Since the pair is language-equivalent
the two starts are bisimilar, so the closure stays inside bisimilarity and is
automatically behavioural.  `start_congruence` computes it by union-find in
`O(k^2 · NA)` per round.

**Measured on every open pair (240 000; NA=3 at 120 000):**

    NA=2   canonical solved 103/104      NA=3   190/190      NA=4   250/250
    not behavioural: 0, 0, 0        too big to build: 0, 0, 0      skipped: 0

The "not behavioural 0" is the prediction confirmed: the closure never leaves
bisimilarity, on any of 544 pairs.

**The rate is identical to the full collapse** — same numerator, same
denominator, same single failing pair.  That is not a coincidence to wave at:
it says the LEAST and GREATEST admissible quotients behave alike here, which is
what one would expect if solvability is not actually delicate in the lattice
for these instances.

**The one failure is my calculus, not the quotient.**  Pair #156950's canonical
quotient is `eliminable=true` under the independent elimination oracle, and
`nested=true`.  Its shape, and the reason the earlier hand analysis stalled:

    c0: st=[c1,c2]   c1: hl=11 st=[-,-]   c2: st=[c3,c3]
    c3: st=[c4,c5]   c4: st=[c1,c2]       c5: st=[c1,c5]

`c1` halts on BOTH atoms with no transitions — it is `1`.  So the "exit to an
external state" that defeated rule 5 at 203 was a HALT all along; what is
genuinely external is `c5 = wh{a1}(p)·p`.  The SCC `{c2,c3,c4}` therefore has
one halt-exit and one continuation-exit, and rule 5 handles only the halt.

**CAVEAT, stated rather than buried:** `eliminable=true` is an ORACLE verdict.
That oracle is known sound on REJECTION for non-nested automata; its
ACCEPTANCE is not independently language-checked here.  So the correct claim is
"the oracle reports this solvable", not "this is verified solvable".
Extracting the expression and language-checking it is the next step, and until
then the 543/544 figure carries that one asterisk.

**What this changes about the target.**  The remainder was: *for every
language-equivalent pair, SOME admissible quotient is solved by the rules.*  It
can now be attempted as: *the LEAST admissible quotient — computed, not chosen
— is solved by the rules.*  That is strictly harder as a statement and strictly
easier as a proof obligation, because there is no longer a quotient to conjure:
`start_congruence` produces it.

**Odds: 70%, up 2.**  The rise is for the target's shape, not for new coverage:
an existential over an exponentially large lattice has been replaced by a
canonical construction that holds on 544 of 544 pairs (543 by the calculus, one
by oracle).  Against it: that last pair still needs a rule my calculus does not
have, the oracle's acceptance is unverified, and the field's prior that this
problem does not close still stands.

---

## 205 — THE NESTING COEQUATION IS NOT THE MISSING INGREDIENT.  A negative result.

**The literature news that prompted this.**  The question well-nestedness left
open — is it NECESSARY? — has been settled, and the answer is no: there is an
automaton bisimilar to a Thompson construction that is not well-nested, and a
non-well-nested automaton whose behaviour is still an expression's.  The
COMPLETE characterization of automata exhibiting the behaviour of a GKAT
expression is the NESTING COEQUATION, which forms a covariety
(Schmid–Kappé–Kozen–Silva).

That looked like a shortcut past this whole development.  If the canonical
quotient always satisfies the nesting coequation, then an expression for it
EXISTS by a known theorem, with no dependence on this five-rule calculus being
complete.  So measure it.

**Measured, and it holds everywhere:**

    CANONICAL QUOTIENT SATISFIES THE NESTING COEQUATION
      NA=2  239 831/239 831     NA=3  119 976/119 976     NA=4  239 954/239 954

599 761 of 599 761.  No exceptions.

**And then the base rate, which is why this is a negative result.**  The same
predicate on the two quotients we did NOT choose:

    raw Thompson sum          239 831/239 831, 119 976/119 976, 239 954/239 954
    full bisimulation collapse   identical, to the pair

100% everywhere.  The measurement distinguishes nothing.  **The reason is a
theorem already in the notes: `Cov(W)` is a COVARIETY, closed under
homomorphic images.  A Thompson sum satisfies the nesting coequation, a
quotient is a homomorphic image, so EVERY quotient satisfies it — including
every one in the lattice.**  Measuring it on canonical quotients was measuring
covariety closure.

**Non-vacuity, checked rather than assumed** (`PAD_NESTED_SANITY`).  A
predicate that is always `true` looks identical to one that holds by theorem,
so `nested` was put to automata NOT built from expressions — random transition
tables at k = 3..6:

    NA=2   216 / 247 / 591 / 724 violations per 20 000   (k = 3,4,5,6)
    NA=3   134 / 144 / 483 / 608
    NA=4    43 /  67 / 199 / 275

It discriminates — weakly (1-4%), and more as k grows, but it is not constant.
So the 100% on quotients is real covariety closure, not a broken predicate.

**Why the shortcut fails, stated precisely.**  If "satisfies the nesting
coequation ⟹ solvable" were enough for THIS target, the problem would already
be closed, since every quotient satisfies it for free.  It is not, because the
characterization gives SEMANTIC solvability — the state's behaviour is that of
some expression — whereas the target needs a SYNTACTIC solution: a labelling
satisfying the automaton's equations up to `EquivBA`, in the axiom system.
Going from "both sides denote the same thing" to "both sides are provably
equal" IS completeness, so using it here would be circular.

**That gap is exactly what the five-rule calculus is for**, and this iteration
is the first time the remainder has been located that precisely: not "which
automata are solvable" (settled, by a covariety) but "which solvable automata
admit a solution CONSTRUCTED from the finite axioms".

**Odds: 70%, held.**  A tempting route was closed off, which is worth
something, but no coverage changed and no theorem was proved.  The clarification
is real: the field's characterization is settled and does not transfer, so
nothing about this remainder can be borrowed from it.  The field's prior that
the problem does not close still stands.

**Next.**  Back to the syntactic gap: pair #156950's canonical quotient, whose
SCC has one halt-exit and one continuation-exit.  Extract a solution and
language-check it — the `eliminable=true` oracle verdict is still unverified,
and it is now the only asterisk on 544/544.

---

## 206 — RULE 6, AND THE LAST ASTERISK COMES OFF.

204 left one unverified claim: pair #156950's canonical quotient was reported
`eliminable=true` by an oracle whose ACCEPTANCE is not language-checked.  It
was the only SCC in 600 000 pairs the five-rule calculus could not solve, and
the only asterisk on 544/544.  Both are now gone.

**Solving it by hand.**  The collapse is

    d0: st=[c1,d2]   c1: hl=11 st=[-,-]   d2: st=[d3,d3]
    d3: st=[d0,c5]   c5: st=[c1,c5]

so `c1` is `1` and `c5 = wh{a1}(p) ; p`.  203 recorded this SCC as having "two
exits to distinct external states"; 204 corrected half of that (`c1` is a
halt).  The remaining obstruction was the OTHER exit, `p ; c5`, an arbitrary
continuation that rule 5 cannot absorb because rule 5's mid-body exit must be a
halt.

The observation that closes it: **`c5` ends in `p`, and the loop's own trailing
expression is `p`.**  Take the mid-body exit to be `p ; wh{a1}(p)`.  That exits
at `¬a1`, so the outer guard is then FALSE, the loop exits, and the shared
trailing `p` fires — reconstituting `c5` exactly:

    X = wh a1 ( p ; p ; ite a0 p (p ; wh a1 p) ) ; p

`PAD_CHECK_R206`: MATCHES at depths 4, 6, 8, 10, 12, for `d0` and for `c5`.
The oracle was right, and now it is verified rather than trusted.  **544/544,
no asterisk.**

**RULE 6, proved in Lean, ZERO AXIOMS** (`trailing_suffix_shared`):

    X ≡ ite g (D · ite c (P · X) (H · F)) F     and     H · ¬g ≡ H
    ─────────────────────────────────────────────────────────────
    X ≡ wh g (D · ite c P H) · F

A mid-body exit need not be a halt.  It needs to LAND OUTSIDE THE GUARD and
SHARE THE LOOP'S TRAILING SUFFIX.

**Two things worth noting about its shape.**  First, `D` needs NO landing
hypothesis, unlike rule 5: the else arm is discharged entirely by `H`'s own
landing, since `H · ¬g ≡ H` lets `¬g` be carried across `H` to meet the
unknown.  Second, **rule 5 is NOT a special case** — at `H = 1` the hypothesis
`1 · ¬g ≡ 1` would force `g ≡ 0`.  The two rules are genuinely distinct: rule 5
pays for its halt with a hypothesis on `D`, rule 6 pays for its continuation
with a hypothesis on `H`.

**Odds: 71%, up 1 — and the small size of that step is the point.**  For: the
last known failure across 600 000 pairs is closed, verified by construction
rather than by oracle, and the rule needed no new axiom and no auxiliary
variable — still `w3_ba` at one unknown.  Against, and it is the same objection
as at 201, now with more evidence behind it: the rule count has gone
3 → 4 → 5 → 6 over roughly six iterations, one new rule per sample enlargement.
205 removed the possibility of borrowing a completeness argument from the
literature's characterization, so this calculus has to be complete on its own,
and a calculus that grows a rule whenever it is stressed is not visibly
converging.  What would change my mind is a sample enlargement that produces NO
new rule.  That has not happened yet.

**Next.**  Teach the solver rule 6, then enlarge the sample and see whether the
pattern finally breaks.

---

## 208 — THE REGRESSION FIXED, AND THE PRE-REGISTERED TEST FINALLY RUNS.

**The fix was cheapest-first**, which is what the constraint-search literature
calls the ordering heuristic and what 207 got backwards.  `calc_search` is
exponential in state-list length; the bare SCC succeeds on all but a handful of
SCCs; 207 paid for the context-extended search on EVERY one of them.  Reversing
the order keeps the completeness the context buys and pays for it only where it
is needed.  Two further hot-path fixes, found by looking rather than guessing:
`std::env::var` was being called PER CANDIDATE inside `calc_search`
(`PAD_CALC_TRACE`) and per SCC for `PAD_CALC_MAXSCC` / `PAD_NO_CALC` — all
three now resolve once through a `OnceLock`.

    same sample as 207:  NA=2 4.9s, NA=4 7.4s, results identical (0 failures)

**The test I pre-registered at 206 has now run.**  I wrote there that what
would move the odds is "a sample enlargement producing NO new rule".  Enlarging
along expression DEPTH (7 → 9 and 11) and automaton bound (`kmax` 10 → 12):

    NA=4  depth 9,  240k   open 241   failures 0   canonical 241/241
    NA=4  depth 11, 240k   open 236   failures 0   canonical 236/236
    NA=3  depth 9,  120k   open 166   failures 0   canonical 166/166
    NA=2  depth 11, 120k   open  32   failures 0   canonical  32/32
    NA=2  depth 11,  60k   open  17   failures 0   canonical  17/17

692 open SCCs at greater depth, zero failures, zero unattempted, both ends of
the lattice, every verdict language-checked.  **This is the first sample
enlargement in this program that did not produce a new rule.**

**The honest qualification, because it weakens the test.**  The enlargement is
along DEPTH and `kmax`, not along the count of hard instances: the open-SCC
counts (241, 236, 166, 32, 17) are COMPARABLE TO OR LOWER THAN the depth-7
runs' (250, 190, 104).  Deeper expressions do not mean proportionally more hard
SCCs — the census generates more folds instead.  So this tests the calculus
against structurally LARGER instances, which is what I wanted, but not against
MORE of them, which is the other axis and the one that produced rules 5 and 6.
NA=2 at depth 9 and depth 11 at 240k still time out, so the largest NA=2
enlargement did not run.

**Odds: 73%, up 2.**  A pre-registered falsification test was met, and that
should count for more than another incremental measurement — it is the first
evidence in six iterations that the rule-per-sample pattern is not endless.  I
am not taking the full step I would for a clean pass, because the enlargement
was along the weaker of the two axes and the largest NA=2 configuration did not
complete.  Rules 5 and 6 both came from the SAME structural family — mid-body
exits — and rule 6 closed the general case of it, which is a better reason to
expect convergence than the count alone suggests.  Still no theorem, and the
field's prior that this problem does not close still stands.

**Next.**  Enlarge along the OTHER axis: more pairs at depth 7-9 until the open
SCC count is several times 250, and see whether the pattern holds there too.
The NA=2 timeouts at 240k/depth 9+ are the immediate obstacle.

---

## 209 — THE SAMPLER IS SATURATED.  Switch to EXHAUSTIVE ENUMERATION.
## Plus a correction to 205.

**The random sampler is exhausted, and the numbers say so exactly.**

    NA=4 depth 7,  4M pairs   1 761 720 quotient states, 1170 open SCCs
    NA=4 depth 7, 16M pairs   1 761 720 quotient states, 1170 open SCCs   IDENTICAL
    NA=2 depth 7, 16x pairs   open SCCs 104 -> 121                        1.16x
    NA=4 depth 9,  4M pairs   858 open  (FEWER than depth 7's 1170)

Sixteen million pairs give bit-identical results to four million: the generator
has enumerated its reachable population and further sampling returns duplicates.
This is the coverage-closure curve the testing literature describes, and it
means **sampling expression pairs can no longer falsify anything.**  All of
those runs are 0 failures, both ends of the lattice — but a saturated
instrument reporting 100% is not evidence, it is the instrument's ceiling.

**So change instrument: enumerate the AUTOMATA directly.**  Each state assigns,
per atom, one of {halt, no transition, target} — `(k+2)^(k·NA)` automata,
exhaustive for small `k`.  This cannot miss a small counterexample, because it
looks at every one.

**First run, and the correction it forced.**  Filtering by `nested` — on 205's
reading that the nesting coequation CHARACTERIZES automata whose behaviour is
an expression's — the enumeration immediately reported 80 unsolved automata at
NA=2 k=3 and 102 at NA=3 k=2.  That looked like rules 7 through many.

It was not.  Every one returns `eliminable=false` from the independent
elimination oracle, and hand-checking the smallest confirms it: e.g.

    q0: hl={a0,a1} st=[-,-,q1]     q1: hl={a1,a2} st=[q0,-,-]

is `X0 = ite{a0,a1} 1 (p·X1)`, `X1 = ite{a1,a2} 1 (p·X0)` — two exits and no
guard that can tell them apart.  It is not solvable, so the calculus failing on
it is CORRECT, not a gap.

**CORRECTION TO 205: `nested` is NECESSARY, not sufficient.**  205 wrote that
the nesting coequation "characterizes automata exhibiting the behaviour of a
GKAT expression" and used that to argue the canonical-quotient measurement was
about covariety closure.  The covariety half stands — every quotient of a
Thompson sum satisfies it, which is why that measurement was vacuous.  But
`nested` as implemented ADMITS automata that are not solvable at all, so it
cannot be used as a solvability oracle on automata that did not arise from
expressions.  Filtering by `symbolic_eliminable_raw` instead is what the test
requires.

**With the correct filter, exhaustive enumeration finds NOTHING:**

    NA=2 k=2:    256 automata   solvable-but-unsolved: 0
    NA=2 k=3: 15 625 automata   solvable-but-unsolved: 0
    NA=3 k=2:  4 096 automata   solvable-but-unsolved: 0

Zero, over EVERY automaton of those shapes — not a sample of them.

**Odds: 75%, up 2.**  Exhaustive beats saturated sampling: for the small cases
the calculus is now verified complete against every automaton the elimination
oracle calls solvable, which is a different KIND of evidence from any previous
iteration's rates.  Held back from more by three things, all real: the
exhaustive reach is only k <= 3 so far (k=4 at NA=2 is running), the filter is
an ORACLE rather than a proof of solvability, and I had to correct a claim I
published four iterations ago in the course of getting here — which is exactly
the base rate one should apply to the claims not yet corrected.

**Next.**  Finish k=4 at NA=2 and k=3 at NA=4; then push the exhaustive reach
as far as compute allows, since it is now the only instrument that can falsify.

---

## 210 — THE k=4 CRASH, AND A GUARD THAT COST A SOLUTION BEFORE IT SAVED ONE.

**The k=4 exhaustive run was not slow, it was dying.**  It printed k=2 and k=3
and then vanished at 146s with `terminated abnormally` and 1248s of user time —
no panic message, clean-looking exit status because the status came from the
tail of a pipe.  Worth stating plainly: I read that as a timeout for one
iteration before checking stderr.  It was a crash.

**Cause.**  `calc_search`'s final resolution loop substitutes every solution
into every other, `scc.len()+1` times over.  Each round can SQUARE the
expression size.  At two or three states that is harmless; at four or more with
a context-extended list it exhausts memory and the process is killed.

**The fix, and the part worth recording.**  A node-count guard bails the
candidate out when a term exceeds a cap — sound, since it only means this
candidate is not pursued and the search reports failure rather than a wrong
answer.  But at `EX_CAP = 20 000` **the census REGRESSED**: NA=4 went from 0
full-collapse failures to 1, and canonical 250/250 to 249/250.  Legitimate
solutions genuinely need large intermediates, so the cap is a
CORRECTNESS-AFFECTING knob, not free insurance.

Because the failure mode is squaring, sizes jump from thousands to hundreds of
millions in a single round — so a cap two orders of magnitude higher stops the
crash while leaving real solutions untouched.  At `EX_CAP = 2 000 000`, all
three populations are back to 100%:

    NA=2 104/104     NA=3 190/190     NA=4 250/250      full collapse AND canonical

**I would not have caught that by reasoning about it.**  The guard looked
obviously safe; it silently cost a solution, and only re-running the census
before trusting it showed so.  That is the second time this program has been
saved by re-measuring a change that "could not" affect results — 203's dead
failure dump was the first.

**Odds: 75%, held.**  Nothing was learned about the mathematics this iteration.
A crash was diagnosed and a guard was calibrated; the exhaustive k=4 run is
only now able to start.  Holding rather than moving is the honest report when
an iteration is entirely instrumental — and the 20 000-cap regression is a mild
argument in the other direction, since it shows the measured 100% rates are
sensitive to a harness constant nobody had reason to examine.

**Next.**  The k=4 NA=2 enumeration (1 679 616 automata) is running.  Then k=3
at NA=4, and push the exhaustive reach as far as compute allows — it is the
only instrument left that can falsify.

---

## 211 — THE LITERATURE NAMES THE FAMILY I FOUND, AND A NECESSARY CONDITION FALLS OUT.

**The unsolvable automata 209 found are the KNOWN unsolvable family.**  The
GKAT literature describes them exactly:

> "there is no condition that terminates the loop: on one branch, a certain
> atom resumes the loop while another terminates execution, whereas on the
> other branch this is reversed"

and warns that adding a `twostate` operator only climbs an INFINITE HIERARCHY
of such automata, each inexpressible in terms of the last.  209's smallest
instance —

    q0: hl={a0,a1} st=[-,-,q1]     q1: hl={a1,a2} st=[q0,-,-]

— is precisely that: `a2` resumes at `q0` and terminates at `q1`; `a0`
terminates at `q0` and resumes at `q1`.  I derived that by hand without knowing
the family existed, and the elimination oracle rejected all 102 of them.  Three
independent routes agreeing is the best validation the filter has had.

**The infinite hierarchy is NOT a threat to this target**, and it is worth
saying why: it concerns the EXPRESSIVENESS of the language — which automata are
denotable at all — whereas the remainder here quantifies only over automata
that ARE solvable, being quotients of Thompson sums.  The hierarchy is a reason
the solvability FILTER is essential, not a reason the problem is unclosable.

**A necessary condition for 2-state loops, verified exhaustively.**  The
literature says a proper characterization of solvable automata "would go a long
way".  For a strongly connected `{u,v}`, write `C_u` for the atoms at `u` that
continue and `H_u` for those that halt.  A loop headed at `u` must take `C_u`
as its guard; the body runs, arrives at `v`, and must exit on `H_v` — which can
only happen if the head's guard is already false there.  So:

    solvable  ⟹  H_v ∩ C_u = ∅   or   H_u ∩ C_v = ∅

Tested against the elimination oracle over EVERY strongly connected 2-state
automaton:

    NA=2     49 automata   agree 47 (95.9%)   false negatives 0
    NA=3  1 369 automata   agree 1135 (82.9%) false negatives 0
    NA=4 30 625 automata   agree 21227 (69.3%) false negatives 0

**Zero false negatives in 32 043 automata**: the predicate NEVER calls
unsolvable something the oracle solves.  So it is a genuine NECESSARY
condition, and it is exactly the literature's informally stated obstruction,
now checked rather than described.

**It is NOT sufficient, and the gap grows with the atom count** — 2, 234, 9398
automata pass the predicate and are still unsolvable (agreement falls 96% → 83%
→ 69%).  So there are further obstructions this condition does not see, and
more atoms means more of them.  A one-sided condition is a real but partial
result; I am not going to call it a characterization.

**Also: the k=4 guard was in the wrong place.**  210's size guard checked
AFTER `ex_subst`, but the blowup happens INSIDE the substitution — which is why
k=4 kept dying with the guard installed and I twice mistook the death for a
timeout.  Substituting `occ` occurrences of a term of size `n_r` into one of
size `n_i` gives `n_i + occ·(n_r−1)`, so it is now bounded BEFORE anything is
built.  Census re-verified at 104/104 and 250/250; k=4 relaunched.

**Odds: 75%, held.**  The literature agreement is reassuring about the
instrument, not about the conjecture, and the necessary condition is one-sided
with a gap that widens as atoms increase.  Nothing this iteration made the
remainder smaller.

---

## 212 — A THEOREM, AND THE OVERCLAIM I CAUGHT IN ITS OWN DOCSTRING.

**`two_state_solvable`, proved in Lean, zero axioms.**  Read a 2-state loop as
an equation at its head `u` — guard `g = C_u`, body `D` reaching `v`,
continuation test `c = C_v`, back-edge `P`, and in the else arm a HALT with
region `h = H_v`:

    X ≡ ite g (D · ite c (P · X) (h · F)) F

211's exhaustively measured necessary condition `H_v ∩ C_u = ∅` says exactly
`h ⟹ ¬g`, and THAT IS VERBATIM rule 6's hypothesis `H · ¬g ≡ H` at
`H = test h`.  The measurement handed the proof its hypothesis.

**I first wrote that up as "completeness at two states".  It is not, and
checking my own claim is what showed it.**  Rule 6's CONCLUSION is
`wh g (D · ite c P (test h)) · F` — the trailing `F` sits AFTER the loop, so a
mid-body exit at an atom of `H_v` must still pass `F = test H_u`.  That needs
`H_v ⊆ H_u`, which is strictly stronger than `H_v ∩ C_u = ∅` (halts and
transitions are disjoint at `u`, so the former implies the latter).  The
theorem is true; the claim around it was not.

**The refined condition, measured the same way:**

                       211: H_v ∩ C_u = ∅      212: H_v ⊆ H_u ∨ H_u ⊆ H_v
    NA=2     49            95.9%                      95.9%
    NA=3  1 369            82.9%                      89.9%
    NA=4 30 625            69.3%                      85.5%
    false negatives           0                          0

Zero false negatives for BOTH, in all 32 043 automata — so the refined
condition is also necessary, and it is markedly tighter, closing about half the
gap at NA=4.  Deriving it from the shape of an already-proved rule's CONCLUSION,
rather than from the shape of its hypothesis, is what found it.

**Still only necessary.**  138 automata at NA=3 and 4 454 at NA=4 satisfy the
refined condition and remain unsolvable, so obstructions exist that neither
condition sees.  A characterization would need those too.

**Odds: 76%, up 1.**  A small, real gain: the first theorem in this development
whose hypothesis was DERIVED FROM A MEASUREMENT rather than guessed, and a
necessary condition tightened by reading a proved rule's conclusion back
against the data.  Not more, because the headline I nearly published —
completeness at two states — turned out to be false on inspection, and the
remaining gap at NA=4 is still 4 454 automata wide.

**Next.**  Find the obstruction the refined condition misses: take the NA=3
false positives (138 of them, small enough to inspect) and look for what they
share.  Whatever it is, it is the next necessary condition — and by 212's
pattern, plausibly the next rule's hypothesis.

---

## 213 — THE SOLVABILITY ORACLE IS BROKEN.  RETRACTING 211 AND 212's HEADLINES.

**The finding.**  `symbolic_eliminable_raw` — the oracle this development has
used since 204 to decide whether an automaton is solvable — is INCOMPLETE, and
here is the witness.  NA=3, `code=131`:

    q0: a0 -> q1, {a1,a2} halt        q1: a0 -> q0, {a1,a2} halt

    X0 = wh a0 (p ; ite a0 p 1) ; test{a1,a2}

MATCHES at depths 4, 6, 8, 10, 12, and the calculus solves it too.  The oracle
says `eliminable = false`.  It is simply wrong.

**How I found it.**  212's plan was to inspect the 138 NA=3 "false positives"
for a shared obstruction.  Dead atoms covered 120 of 138 (and 4 368 of 4 454 at
NA=4) — but `code=131` has none and is perfectly symmetric, so I solved it by
hand expecting to learn what made it hard.  It was not hard.  The oracle was
wrong.

**What this retracts.**

*211's headline — "a NECESSARY condition, zero false negatives in 32 043
automata" — is WITHDRAWN.  So is 212's refinement.*  Both were computed against
the oracle.  Re-running with a language-VERIFIED witness as the truth source
(calculus success carries a checked witness, so it PROVES solvability; take the
union with the oracle as the best available lower bound):

                    vs the oracle (211/212)      vs verified witnesses (213)
    NA=2   49          95.9%  /  95.9%              100.00%   FP 0   FN 0
    NA=3 1369          82.9%  /  89.9%               96.06%   FP 0   FN 54

The direction of the error REVERSES.  There are no false positives at all —
and 54 FALSE NEGATIVES at NA=3: automata that ARE solvable while failing the
condition.  **So the condition was never necessary.  The oracle's
incompleteness was manufacturing the evidence for its necessity.**  It is exact
at NA=2 (49/49) and that is all that survives.

**It also undermines 209's coverage claim.**  "SOLVABLE (elimination oracle)
but UNSOLVED by the calculus: 0" used the oracle as the FILTER.  An oracle that
under-reports solvability makes that filter admit too few automata, so the
enumeration tested a SUBSET of what it claimed.  The zero is still a zero over
what was tested; the coverage around it was overstated.

**And it puts a question mark on today's other result.**  The k=4 enumeration
finished: 1 679 616 automata, **720 reported as `eliminable=true` but unsolved
by the calculus**.  Under any earlier iteration that would be the headline —
720 candidate rule-7 instances.  It is not, because it rests on the same
oracle, in the other direction: an oracle wrong about `false` may be wrong about
`true`.  Hand-reading the first, `code=14859`, its SCC `{q0,q1}` has `a0`
resuming at `q0` and exiting at `q1` while `a1` does the reverse — the
literature's UNSOLVABLE pattern — which suggests these may be oracle
FALSE POSITIVES rather than calculus gaps.  I am not claiming either way: the
instrument is not trustworthy in either direction and must be replaced first.

**Odds: 74%, DOWN 2.**  Nothing was learned that makes the calculus look worse
— it solved `code=131`, which the oracle could not, and no verified
counterexample to it exists anywhere in this development.  What changed is my
confidence in the MEASUREMENTS: the primary solvability instrument is
demonstrably unreliable, two iterations of published "necessary conditions"
were artifacts of it, and the exhaustive coverage claim was weaker than
reported.  A number resting on broken instruments should move down when the
breakage is found, not stay put because the breakage happened to be in a
convenient direction.

**Next, and it is now the only sound instrument.**  A BRUTE-FORCE EXPRESSION
SEARCH: enumerate expressions up to a depth bound, build each one's automaton,
and language-compare.  A hit proves solvable; exhausting the bound proves
unsolvable up to that depth.  Both directions verified, no oracle.  That is
what should have been deciding solvability all along.

---

## 214 — A SOUND INSTRUMENT AT LAST, AND THE 720 EVAPORATE.

213 ended with the solvability oracle discredited in one direction and
suspected in the other, and 720 k=4 automata whose status therefore could not
be called.  This iteration builds the instrument that should have been deciding
solvability all along and settles all of it.

**`synth`: brute-force expression search with observational dedup.**  Enumerate
expressions bottom-up by size, keeping ONE representative per BEHAVIOUR — the
standard observational-equivalence pruning from enumerative program synthesis,
which keys on what a term does rather than how it is written and cuts the
retained set by roughly an order of magnitude.  Behaviour is the accept-set over
all guarded strings up to a length bound, packed into a `u128`.  A hit is a
WITNESS, so it proves solvable; exhausting the size bound proves unsolvable UP
TO THAT SIZE.  No oracle in either direction.

**It validates against known ground truth, both ways:**

    code=131  (oracle said UNSOLVABLE)          ->  wh a0 p          SOLVED
    code=176  (literature says UNSOLVABLE)      ->  none             agrees
    code=14859 (oracle said SOLVABLE)           ->  none, size <=12

The first is a sharper rebuke to the oracle than 213 managed: the automaton is
not merely solvable, it is `wh a0 p` — a bare while-loop, with a redundant
two-state encoding.  My 213 hand-solution `wh a0 (p ; ite a0 p 1) ; test{a1,a2}`
was correct but needlessly elaborate; the search found the obvious one.

The second is the check that matters most, because an instrument that always
finds something proves nothing: on the family the literature calls unsolvable,
`synth` returns nothing.

**THE 720 ARE PHANTOM.**  `code=14859` has NO expression up to size 12, so the
oracle's `eliminable=true` was a FALSE POSITIVE.  213's hand-reading was right:
its SCC has `a0` resuming at `q0` and exiting at `q1` while `a1` does the
reverse — exactly the literature's unsolvable pattern.  So the k=4 enumeration's
720 "solvable but unsolved by the calculus" are not counterexamples to the
calculus.  **The oracle is wrong in BOTH directions**, and every verdict that
rested on it — 209's, 211's, 212's, and the k=4 720 — was measuring the oracle.

**Where that leaves the calculus: no verified counterexample exists anywhere in
this development.**  Every instance ever reported against it has, on
examination, been either a harness bug (203's dead dump, 203's size cap, 210's
guard) or an oracle artifact (the 720, 211/212's "necessary conditions").  The
only genuine gaps found by measurement — 201's and 206's resisters — were
closed by rules 5 and 6 and proved in Lean.

**Odds: 77%, up 3 from 213's 74%, and 1 above the pre-drop 76%.**  213's drop
was for measuring with a broken instrument; that is now fixed and validated
against ground truth in both directions, which is worth more than restoring the
old number.  The largest outstanding cloud — 720 candidate counterexamples —
has been dispelled by construction rather than argument.  Held below any bigger
jump by the honest limit of the instrument: `synth`'s negative results are
"no expression of size <= 12 over guarded strings of <= 5 atoms", which is a
BOUNDED negative, not a proof of unsolvability.

**Next.**  Re-run the k=3 and k=4 exhaustive enumerations with `synth` as the
solvability filter instead of the oracle.  That is the first exhaustive test in
this development whose every verdict is verified in both directions — and the
first that could produce a counterexample I would believe.

---

## 215 — THE FIRST FULLY-VERIFIED EXHAUSTIVE ZERO, AND A VACUITY BUG CAUGHT IN THE SAME RUN.

**`synth` is now the exhaustive enumeration's solvability filter**, replacing
two discredited oracles.  It runs only where the calculus FAILS — rare — so an
exponential search is affordable, and a hit there is a WITNESS that the
automaton is solvable while the calculus could not solve it: a real
counterexample, not an oracle verdict.

**Result, NA=2, every automaton with k <= 3:**

    k=2:    256 automata   solvable-but-unsolved: 0
    k=3: 15 625 automata   solvable-but-unsolved: 0     (54s)

**This is the first exhaustive result in this development whose every verdict is
verified in both directions** — solvable by exhibited expression, unsolved by
language-checked search, no oracle anywhere.

**And in the same run, a silent-vacuity bug in the new instrument.**  The
guarded-string bound for the behaviour signature was a hard-coded 5.  At NA=3
that is 3+9+27+81+243 = 363 strings, which exceeds the 128-bit signature, so
`synth` hit its `seqs.len() > 128` guard and returned `None` — EVERY TIME.  The
filter never fired, and the NA=3 line would have read "0 counterexamples"
while testing nothing at all.  I nearly published it.

Fixed two ways: the bound is now DERIVED from `NA` (`seq_len`: 6 for NA=2, 4
for NA=3, 3 for NA=4 — NA=2 is now stronger than before, 126 strings against
62), and the silent `return None` is now an `assert!` that says exactly why a
negative would be vacuous.  A bounds check that answers "no" is
indistinguishable from a real "no"; it must refuse to answer instead.  NA=3 now
runs genuinely slowly, which is the evidence that the filter is firing.

**That is the third silent-vacuity class this session** — 203's dead failure
dump, 210's guard that quietly discarded solutions, and now this.  All three
had the same shape: a fast path that returns the FAVOURABLE answer when it
cannot do the work.

**Odds: 77%, held.**  A real gain — the first exhaustive zero verified in both
directions — offset by finding another way my own instrument was reporting
success without testing anything.  The NA=2 k<=3 result stands on its own and
is not affected by the bug (62 strings was under the limit, so that filter was
firing).  The NA=3 figure from the same run is WITHDRAWN.

**Next.**  NA=2 k=4 (1 679 616 automata) with the verified filter, and NA=3
k<=3 now that its search actually runs.

---

## 216 — THE ENUMERATION DOES NOT DEPEND ON THE TARGET.  8x, and a route closed.

**The observation.**  `synth` re-enumerated expressions from scratch for every
automaton, which is why the exhaustive runs were compute-bound.  But an
expression containing no `Sub`/`Unk` has a behaviour determined by `NA` alone —
the target automaton is consulted only to compute the SIGNATURE TO MATCH, never
to evaluate a candidate.  So enumerate ONCE into a table from
behaviour-signature to representative expression, and "is this automaton
solvable by an expression of size <= N" becomes a hash lookup: per-automaton
cost falls from an exponential search to O(1) plus one verification.

    NA=2, k <= 3:   54s  ->  6.8s        (table built in 0.2s)

The table is small because observational dedup is doing real work: **2 677
distinct behaviours at size <= 10**, against an astronomically larger raw
expression count.

**A route closed, honestly.**  If the behaviour table SATURATED — if raising
the size bound stopped adding behaviours — then "not in the table" would become
an UNCONDITIONAL negative rather than a size-bounded one, and every negative
result this instrument has produced would strengthen.  Measured:

    size <=  6      106 behaviours
    size <=  8      523
    size <= 10    2 677
    size <= 12   13 897
    size <= 14   68 484

It does not saturate; it grows about 5x per +2 in size.  So `synth`'s negatives
remain "no expression of size <= N", and that is a permanent property of this
instrument, not a temporary compute limit.  Worth knowing rather than assuming:
I had expected saturation and would have claimed unconditional negatives on it.

**What this means for the standing results.**  Every negative reported by
`synth` — the 720 phantoms at 214, the exhaustive zeros at 215 — stays exactly
as strong as it was, and no stronger.  The gain here is reach, not certainty:
the same claims can now be made over far more automata.

**Odds: 77%, held.**  A pure instrument iteration: an 8x speedup and one
hoped-for strengthening measured and refused.  Nothing about the mathematics
moved.

**Next.**  NA=2 k=4 (1 679 616 automata) with the table filter is running.  Then
NA=3, now that per-automaton cost is a lookup.

---

## 217 — THE PIVOT: INDUCT ON THE EXPRESSION, NOT ON THE AUTOMATON.

**Why pivot.**  Every instrument failure this session traces to ONE thing:
deciding whether an ARBITRARY automaton is solvable.  `nested` was necessary
but not sufficient (205); `symbolic_eliminable_raw` is wrong in BOTH directions
(213, 214); `synth` gives only size-bounded negatives, and 216 measured that
the route to unconditional ones is closed.  That is not bad luck — CHARACTERIZING
SOLVABLE AUTOMATA IS THE LITERATURE'S OWN OPEN PROBLEM, and I kept
re-discovering that I cannot shortcut it.

**But the target theorem never quantifies over arbitrary automata.**  Its
automata are behavioural quotients of Thompson automata OF EXPRESSIONS, and the
expression is always in hand.  So induct on the expression, where
`GkatThompson`'s `seqGSystem` / `loopInitialized` / `sumGSystem` decomposition
gives exactly the case structure the six rules already have.

**The remainder, written as one predicate** (`ThompsonUnif`): bisimilar states
of `e`'s Thompson automaton carry `EquivBA`-equal standard labels.  By
`unif_of_class_constant_solution` / `class_constant_solution_of_unif` (iteration
170) this is EQUIVALENT to `SumQuotientSolvable`, and
`completeness_of_sumQuotientSolvable` turns that into completeness.  So
`∀ e, ThompsonUnif e` IS the theorem — no reformulation left to do.

**Landed, no `sorry` and no new axiom** (`propext`, `Quot.sound` only):

    thompsonUnif_test       vacuous: `test t`'s automaton has NO states
    thompsonUnif_act        one state, so reflexivity
    thompsonUnif_of_steps   the induction, discharged

**What that leaves is exactly three hypotheses** — `seq`, `ite`, `wh` — carried
as explicit arguments rather than as `sorry`, which is what makes it CHECKABLE
that they are all that is open.  A reader can confirm the reduction without
trusting me about what remains.

One design note worth keeping: stating `ThompsonUnif` over `aut.toGAut` would
have dragged the initial pseudostate into what should be a base case (at
`act a`, `none` and `some ()` are not bisimilar, but PROVING that is work, not a
base case).  Quantifying over a start state of the CORE instead makes `test`
vacuous FOR THE RIGHT REASON — there are no states at all — and `act` a
one-state reflexivity.

**Odds: 77%, held.**  No new mathematics: this is a restatement, and a
restatement does not make a theorem more likely to be true.  What it changes is
what I can work on — three concrete inductive steps instead of an existential
over automata I have repeatedly failed to characterize.  The `wh` case is the
one that decides it, and it is where rules 5 and 6 must earn their place: a
loop's Thompson automaton is exactly where bisimilar states can sit on opposite
sides of the back edge.

**Next.**  The `wh` step.  If it goes through, `seq` and `ite` should follow the
same pattern; if it breaks, the break will name the missing rule, the way 201's
and 206's resisters did.

---

## 218 — THE `wh` CASE, ANATOMISED.  Two definitional facts, and the residual named.

**Two structural facts, both `rfl`:**

    loop_state_eq     (wh b e)'s Thompson states ARE e's — `loopInitialized`
                      adds back EDGES, never states
    loop_standard_eq  std_loop s = std_body s ; wh b e

The first is the one I did not expect: a loop's Thompson automaton has exactly
the body's state set, with the back edge encoded as extra transitions guarded
by `hlt_body ∧ b`.  Together they turn the `wh` step into a statement with no
automaton construction left in it:

    loop-bisimilar u, v  ⟹  std_body u · wh b e  ≡  std_body v · wh b e

**And that is WEAKER than `std_body u ≡ std_body v`.**  The trailing loop may
equalise labels the body keeps apart — which is precisely the trailing-suffix
phenomenon rule 6 was proved for.  So the `wh` case is where rules 5 and 6 must
earn their place, exactly as 217 predicted, and now for a structural reason
rather than a hunch.

**`thompsonUnif_wh_of_residual` splits the step and discharges the easy half.**
When loop-bisimilar states are also BODY-bisimilar, the induction hypothesis
plus `seq` congruence finishes immediately.  What remains is the residual:
loop-bisimilar but NOT body-bisimilar.  That is possible because the loop's halt
is `hlt_body ∧ ¬b`, so two states may differ in the body exactly where `b` holds
and the back edge fires — the difference is confined to a region where both
states restart the loop.

So the remainder is now:

    seq step        open
    ite step        open
    wh step         reduced to ONE residual case, easy half proved

all carried as explicit hypotheses, still no `sorry` and no new axiom.

**A census note, reported because it is a non-result.**  NA=2 k=4 (1 679 616
automata) timed out at 900s even with 216's lookup-first gating.  That gating
did not help, and the reason is informative: MOST 4-state NA=2 automata have
behaviour expressible at size <= 10, so the table gate rarely fires and the
calculus runs on nearly all of them.  Relaunched without a wall-clock limit.

**Odds: 77%, held.**  Further reduction, no new mathematics.  A theorem does not
become more likely to be true by being restated more precisely — but the
residual case is now small enough to attack directly, and its shape says which
of the six rules should close it.

**Next.**  The residual: loop-bisimilar, not body-bisimilar.  Show the
difference is confined to the `hlt_body ∧ b` region and that postcomposition
with `wh b e` absorbs it — a rule-6-shaped argument.

---

## 219 — THE `wh` RESIDUAL IS NON-EMPTY.  The shortcut is closed.

218 left the `wh` step reduced to one residual: states bisimilar in the LOOP
automaton but not in the BODY.  If that residual were EMPTY — if
loop-bisimilarity always equalled body-bisimilarity — the hypothesis would be
vacuous and the `wh` case would follow from the induction hypothesis alone.
Measure before proving.

**Derivation first.**  `loopInitialized` differs from the body at exactly one
place: atoms where `hlt_body(s)` holds AND the guard `b` holds, where the body
HALTS and the loop takes the back edge instead.  So a residual pair needs an
atom at which `b` holds and exactly ONE of the two states halts in the body,
with the back-edge target loop-bisimilar to wherever the other state goes.

**Measured** (`PAD_WH_RESIDUAL`; `a_wh` matches `loopInitialized` exactly — same
state count, `hl ∧ ¬g`, back edge to the body's initial transition):

    NA=2    61 441 loops    residual pairs in 3 892     (6.3%)
    NA=3    92 130          4 631                       (5.0%)
    NA=4   107 650          3 975                       (3.7%)

**Non-empty, and not rare.**  The `wh` step genuinely needs the residual
argument.

**The smallest example, which shows the mechanism.**  NA=2, guard `a1`, body:

    q0: hl={a0}      a1 -> q0          body block 0,  loop block 0
    q2: hl={a0,a1}   (no transitions)  body block 2,  loop block 0

In the BODY they differ: at `a1`, `q0` continues and `q2` halts.  In the LOOP,
`q2`'s halt sits under the guard, so it becomes a BACK EDGE to the body's entry
— which lands at `q0`.  The two states become indistinguishable only because
the loop restarts.  Their labels are `std_B(q0) · wh a1 e` and
`std_B(q2) · wh a1 e`, and the trailing loop is what absorbs the difference:
precisely the trailing-suffix shape rule 6 was proved for, arrived at from the
Thompson construction rather than from a census resister.

**A consistency check that passed:** "residual pair exists" and "loop partition
strictly coarser" have IDENTICAL counts in all three populations (3892/3892,
4631/4631, 3975/3975), as they must — each implies the other.  Two independent
counters agreeing exactly is weak evidence the instrument is wired right, and
after this session's record that is worth having.

**Odds: 76%, DOWN 1.**  A hoped-for shortcut is closed: the `wh` case needs new
mathematics, not just the induction hypothesis.  That is genuine evidence the
induction is harder than 217 hoped, and it should cost something.  What it does
not do is make the statement less likely TRUE — the residual pairs all look like
rule-6 absorptions, and rule 6 is already proved.

**Next.**  The residual claim: `u ~_loop v` with the difference confined to the
`hlt_body ∧ b` region implies `std_B(u) · wh b e ≡ std_B(v) · wh b e`.  The
route I can see is a class-constant solution for the LOOP automaton plus
`certifiedThompson_solution_unique`; the obstacle is that
`class_constant_solves_of_reps` wants unification at successors, which is what
is being proved.  Whether the loop's structure supplies a well-founded order
there is the next question.

---

## 220 — THE RESIDUAL WAS AN ARTIFACT OF THE WRONG INDUCTION HYPOTHESIS.

219 measured the `wh` residual at 3-6% and concluded the step needs new
mathematics.  It needs a different HYPOTHESIS, and the diagnosis is visible in
two more `rfl` facts:

    loop_core_hlt    loop halt = body halt ∧ ¬b
    loop_core_trans  and there the halt becomes a BACK EDGE into the body's own
                     entry transitions, guarded by hlt_body ∧ b

**A loop is the body with its halts REDIRECTED.**  So asking whether two states
are bisimilar IN THE BODY is asking the wrong question — the loop never compares
them there.  It compares them in the redirected body, and `ThompsonUnif e`
says nothing about that.  The 3-6% residual was measuring my hypothesis's
weakness, not an obstruction in the mathematics.

**The repo was already parametric for exactly this reason.**
`ParamSolvesBA sys sol finish` — solutions relative to a trailing continuation,
with uniqueness quantified over `finish`.  My `ThompsonUnif` used the
non-parametric form.  Corrected:

    ThompsonUnifP e := for EVERY redirection guard `c` and EVERY trailing `F`,
                       states bisimilar in the `c`-redirected body carry
                       EquivBA-equal `std s ; F`

**`thompsonUnif_wh_of_param` then discharges the whole `wh` step in one line**
— instantiate the redirection at the loop's own guard and the continuation at
the loop itself; `loop_state_eq` and `loop_standard_eq` make both sides
definitionally right.  No residual, no case split, no appeal to rules 5 or 6.
Zero axioms beyond `propext`/`Quot.sound`.

**The honest cost, stated because it is real.**  Strengthening the hypothesis
moves the difficulty rather than removing it: proving `∀ e, ThompsonUnifP e`
now has its OWN `wh` case, which redirects an already-redirected system —
double redirection.  What has been bought is that the difficulty is now in a
statement the repo's machinery was built for, instead of in a statement that
was structurally unable to express the comparison being made.

**Odds: 77%, up 1, recovering 219's drop.**  219 charged the theorem for what
turned out to be my own mis-specification; that charge is refunded, and not
more.  The `wh` step of the ORIGINAL statement is now proved outright, which is
the first of the three steps to fall, but the strengthened statement it rests on
is not yet established.

**Next.**  Redo the base cases and `of_steps` parametrically — `test` should
still be vacuous and `act` still a one-state reflexivity — then the parametric
`seq` and `ite` steps, and the double-redirection `wh` case.

---

## 221 — RETRACTING 220.  `ThompsonUnifP` IS FALSE; 219 WAS RIGHT.

220 claimed the `wh` residual was "an artifact of the wrong induction
hypothesis" and discharged the step in one line from a parametric predicate.
**The predicate is false, so the discharge is vacuous.**  Checking it took one
instantiation.

**The refutation.**  `ThompsonUnifP` quantifies over an ARBITRARY trailing `F`.
Take `F = test 1`: the conclusion collapses to `std u ≡ std v`.  But the
hypothesis only asks for bisimilarity in the REDIRECTED body — and 219 measured
that 3-6% of loops contain states that are redirect-bisimilar while NOT
body-bisimilar.  Not body-bisimilar means their body behaviours DIFFER, so
`std u ≡ std v` is refuted by soundness.  219's own smallest example is a
witness: guard `a1`, body `q0 : hl={a0}, a1 → q0` and `q2 : hl={a0,a1}` — loop
block equal, body blocks 0 and 2.

**And the obvious repair destroys the content.**  Tying `F` to the redirection
(`F := wh c e`) makes the predicate true, but it then reads
`∀ c, ThompsonUnif (.wh c e)` — the `wh` step becomes its own hypothesis.  The
parametric route, at least in this form, buys nothing.

**So 219 stands and 220 does not.**  The residual is real, it is 3-6% of loops,
and the `wh` step needs genuine mathematics.  `thompsonUnif_wh_of_param` stays
in the file, marked VACUOUS with the refutation written above it, rather than
deleted — the record of which of two contradictory claims was right matters
more than a tidy file.

**What I should have done.**  219 handed me a measurement that said the residual
is real; 220 proposed a shortcut and I did not test the shortcut against that
same measurement before publishing it.  One instantiation — `F = 1` — was all
it took, and I had the counterexample already sitting in 219's output.  The
rule this session keeps re-teaching, now in a new place: a hypothesis is an
instrument too, and it must be checked for vacuity before results are built on
it.  Three of those were harness bugs; this one was a definition.

**Odds: 76%, DOWN 1 — withdrawing 220's increase.**  Back to 219's position
exactly.  The theorem's truth is unchanged by my having been wrong about it: the
`wh` residual was real before 220 and is real after.  I am not deducting further
for the error itself, because the error cost an iteration rather than corrupting
a result — the retraction is complete and the file says so.

**Next.**  The residual, honestly this time.  The states in a residual pair
differ in the body exactly where the body halts and the guard holds, and there
BOTH restart the loop.  That is a statement about the body's halt region, not
about arbitrary continuations — so the right strengthening quantifies over
REDIRECTIONS, with the continuation DETERMINED by the redirection, not free.

---

## 222 — 132 "COUNTEREXAMPLES" AT k=4, AND WHY THEY ARE NON-MINIMALITY ARTIFACTS.
## Plus: the literature's open questions are, verbatim, this project's.

**The literature first, because it reframes the odds.**  Kappé–Schmid–Silva,
*A Complete Inference System for Skip-free GKAT* (ESOP 2023).  Skip-free
excludes programs that can terminate WITHOUT executing an action:

    e ::= 0 | p | e₁ +_b e₂ | e₁·e₂ | e₁^(b) e₂

On that fragment the axiomatization is **purely equational — no guardedness side
condition at all**, with `x^(b) y = x(x^(b) y) +_b y` unconditioned, proved by
reduction to Grabmayer–Fokkink one-free regular expressions.  And on the full
language they write that the questions "whether (UA) can be derived from the
other GKAT axioms and whether the non-algebraic side condition can be removed"
**remain open**.  Those are this project's two questions, stated by the people
who posed them.  It is worth knowing that the target is the field's live
problem and not a gap in my reading — and equally worth knowing that skip-free
does NOT hand it over: it buys equational completeness by excluding exactly the
immediate-termination behaviour that makes the general case hard.

**Then the census delivered 132 apparent counterexamples**, k=4, NA=2, over all
1 679 616 automata — and with the SOUND filter (`synth`, a verified witness),
not the discredited oracle.  Under any earlier iteration that is the headline.

**It is not, and hand-checking the first one shows why.**  `code=159545`:

    q0: st=[q3,q2]   q1: hl={a1} st=[q1,-]   q2: st=[q1,q0]   q3: hl={a1} st=[q1,-]

`q1` and `q3` are LITERALLY IDENTICAL, so `q1 ~ q3`; then `q0 ~ q2` by symmetry,
and the automaton collapses to two states solved by `wh a1 p ; p ; wh a0 p`.
The calculus fails only because it sees `Sub(q1)` and `Sub(q3)` as DISTINCT
OPAQUE ORACLES.  That is non-minimality, not a gap in the rules.

**And the enumeration was testing the wrong objects.**  The target theorem
quantifies over behavioural QUOTIENTS of Thompson sums, which are
bisimulation-minimal by construction.  A raw enumerated automaton is not.  So
the exhaustive test has been strictly harder than the theorem all along — in a
way that manufactures failures.  Minimising before the calculus runs:

    NA=2 k=2:    256 automata   0
    NA=2 k=3: 15 625 automata   0      (unchanged — these were already minimal)
    NA=2 k=4: 1 679 616         re-running

**Odds: 76%, held.**  Two things pulling opposite ways and cancelling.  Against:
I have now had to explain away a counterexample count for the second time, and
"the instrument was testing something harder than the theorem" is a comfortable
thing to conclude — it is right here, but it is the kind of conclusion that
needs the minimised rerun to confirm it, which is pending.  For: the literature
confirms the target is the field's open question rather than a misreading, and
the one hand-checked instance dissolved completely rather than partially.

**Next.**  The minimised k=4 rerun.  If it returns 0, the 132 are explained and
the exhaustive result stands at k<=4.  If it returns anything, those are real
and hand-checking them is the next iteration.

---

## 224 — THE ROUTE, CONFIRMED FROM THE SOURCE.  LLEE IS THE MISSING STRUCTURE.

223's caveat is discharged, and the answer is stronger than the caveat asked
for.  From Grabmayer's paper directly:

> "For proper-step LLEE-charts, bisimulation collapse preserves LLEE.  However,
> when empty-step transitions are present, LLEE-1-charts are not closed under
> bisimulation collapse."

> "all provable solutions of a guarded LLEE-1-chart are Mil-provably equal"

and every prechart with LLEE ADMITS a solution — existence, not merely
uniqueness.  So my inference at 223 was right for the right reason: GKAT
transitions all carry actions, GKAT is the proper-step case, and the certificate
survives collapse.  The 0-in-131 714 measurement now has a proof behind it
rather than a hypothesis.

**But the important thing is the chain this exposes:**

    Thompson(e) has LLEE                    structural, by construction
    LLEE ⟹ a solution EXISTS                existence, not just uniqueness
    proper-step ⟹ LLEE survives collapse    the fact just confirmed
    ────────────────────────────────────────────────────────────────────
    the collapse of a Thompson sum is solvable
      ⟹ SumQuotientSolvable ⟹ completeness

Every link is PROVED in the regular-expression setting.  What is missing is the
GKAT translation of each, not the ideas.  And it explains, after the fact, why
six rules kept sufficing: **they are the GKAT loop-elimination moves, and LLEE
is the structural condition under which elimination is guaranteed to terminate
with a solution.**  I derived rules 5 and 6 from resisters without knowing they
were instances of a known elimination discipline.

**What this replaces.**  217's plan was an induction on expressions with three
open steps, and 219-221 established that its `wh` step is genuinely hard and
that the obvious strengthening is false.  The LLEE route does not need that
induction: LLEE is proved for Thompson charts structurally, and then the
collapse is handled by a CLOSURE theorem rather than by re-doing the induction
on the quotient.  That is exactly the step 217's plan had no answer for.

**The translation risk, stated up front.**  GKAT's notion of termination is not
Milner's.  A GKAT loop body TERMINATES in order to iterate — halting is how
`wh b e` returns to its head — whereas LLEE's condition is that "no successful
termination can occur mid-loop".  Those may or may not line up; if they do not,
the LLEE definition needs a guarded analogue and the closure proof may not
transfer.  This is the thing to check first, and it is checkable before any Lean
is written.

**Meanwhile, what the exhaustive data already says.**  At k<=4, NA=2, over all
1 695 497 automata, minimised, both directions verified: solvable-but-unsolved =
0.  Since every calculus success carries a language-checked witness, the
converse is automatic.  **So on that population the six-rule calculus IS the
solvability characterization, exactly** — the thing the GKAT literature says
"would go a long way".  Empirically, on a bounded population, but exactly.

**Odds: 79%, up 1.**  A confirmed route with every link already proved somewhere
is worth more than another measurement, and it arrives precisely where 221 left
the induction stuck.  Only +1 because the translation risk above is real and
unassessed, and because a route being proved elsewhere has, in this session,
twice not survived contact with my setting (205's characterization, 220's
parametric IH).

**Next.**  Check the termination mismatch: does LLEE's "no successful
termination mid-loop" have a guarded analogue that GKAT's Thompson charts
satisfy?  Measure it on Thompson automata before writing any Lean.

---

## 225 — REDUCIBILITY IS NOT THE CHARACTERIZATION.  And a filter audit that came out safe.

**The termination mismatch 224 flagged, resolved on paper.**  Milner's LLEE
requires no successful termination mid-loop — you exit only at the head.  GKAT's
Thompson construction INLINES the head into the body's exit points:
`loop_core_hlt`, proved `rfl` at 220, says the loop's halts are exactly
`hlt_body ∧ ¬b`.  So termination inside a GKAT loop body happens precisely where
the body completes AND the guard says stop — "termination only at the head",
distributed over the body's completion points rather than concentrated in one
state.  The condition survives translation; it is not the obstacle.

**So which structure IS solvability?**  The exhaustive runs give a
characterization by ALGORITHM (the six rules solve exactly the solvable
automata at k<=4/NA=2).  LLEE promises one by STRUCTURE.  The cheapest
LLEE-adjacent candidate already in the harness is T1/T2 reducibility — single
dominating loop entry, the entry-side half of "loops are never mutually
nested".  Cross-tabulated over every minimised automaton:

    NA=2 k=2   reducible&solvable   32 | reducible&UNsolvable   4 | irred&solvable 0
    NA=2 k=3   reducible&solvable 1540 | reducible&UNsolvable 972 | irred&solvable 8

**972 reducible-but-unsolvable at k=3: reducibility is NOT sufficient.**  That is
the expected shape rather than a surprise — LLEE is strictly more than a single
dominating entry, and the parts I did not implement (the layering, the
termination condition) are exactly what the 972 must be violating.  The cheap
proxy fails, and it fails informatively: the missing content of LLEE is the
layering, not the entry condition.

**A filter audit, prompted by the `irred&solvable 8` cell.**  `synth_lookup`
tests STATE 0 only, not system-solvability — an automaton can have an
expressible start state while some other state's behaviour is not expressible.
That makes those 8 cells unreliable and I am not drawing a conclusion from them.

But it matters more for the exhaustive result, so I checked the direction: the
counterexample filter is "solvable AND calculus fails", and requiring ALL states
solvable is STRICTLY STRONGER, so it admits FEWER automata.  A stricter filter
can only lower a count that is already 0.  **The k<=4 exhaustive zero is
conservative in the safe direction and stands**; tightening the filter would
only strengthen it.

**Odds: 79%, held.**  A cheap proxy for LLEE was tested and failed, which costs
nothing because it was never the plan — the plan is LLEE itself, and this says
what LLEE's content is beyond the obvious part.  The filter audit is a small
positive: a weakness found in the instrument that happens to point the safe way,
verified rather than assumed.

**Next.**  Implement LLEE properly — the loop-elimination procedure with its
layering condition — and test the chain: do Thompson automata satisfy it, is it
preserved by collapse, and does it coincide with calculus-solvability?  That
last equivalence, if it holds, is the characterization.

---

## 226 — THE REMAINDER IS ONE CLOSURE PROPERTY.

Reading this development against Grabmayer's architecture rather than my own
changes what the open part IS.  His proof is not an induction that survives
quotienting; it is a STRUCTURAL CERTIFICATE that is (i) present on every chart
of an expression, (ii) sufficient for a solution to exist, and (iii) CLOSED
UNDER BISIMULATION COLLAPSE for proper-step charts — GKAT's case.

**(i) and (ii) are already done in this repo**, and have been for some time:

    sum_solves_std                        the Thompson SUM is solvable, outright
    decomp_solves                         role-coverage gives SolvesBA
    completeness_of_sumQuotientSolvable   quotient-solvability gives completeness

**So the entire remainder is (iii).**  Stated and machine-checked
(`propext`/`Quot.sound` only):

    QuotientClosure A T :=
      a solvable automaton has a solvable behavioural quotient

    sumQuotientSolvable_of_closure :
      QuotientClosure + a start-identifying quotient  ⟹  SumQuotientSolvable

and `completeness_of_sumQuotientSolvable` carries that to completeness.  The
second hypothesis is bookkeeping — the two start pseudostates of a
language-equivalent pair ARE bisimilar, so the full collapse identifies them;
it is a hypothesis only because building that collapse as a
`UniformBehavioralGAutQuotient` is construction work.  The content is
`QuotientClosure`.

**What this replaces.**  217 framed the remainder as an induction on
expressions with three open steps, and 219-221 spent three iterations
establishing that its `wh` step is genuinely hard and that the obvious
strengthening is false.  That framing is superseded: ONE property, not three
steps, and a property that someone has proved in the neighbouring setting.

**Why the naive proof of it fails, recorded so it is not re-attempted.**
Transporting the solution — label each block by a representative's label —
requires bisimilar states to carry PROVABLY equal labels, which is same-side
unification, which is what is being proved.  Grabmayer's move is not to
transport the solution but to RE-DERIVE it from a certificate that survives the
collapse.  That is why a certificate is needed at all.

**Three independent supports for the same statement, which is why this moves
the number:**
  * proved in the neighbouring setting, for exactly GKAT's case (proper-step),
    confirmed verbatim from the paper at 224;
  * measured here at 223 — 0 breakages in 131 714 Thompson automata, with the
    collapse strictly shrinking ~60% of them;
  * the reduction to it is now machine-checked.

**Odds: 80%, up 1.**  A restatement does not make a theorem truer — but this
one aligns the remainder with a PROVED architecture instead of an invented one,
which is a different thing from 217's restatement, and it is the first time the
open part has been a single named property with a precedent.  Only +1 because
the precedent's proof runs through LLEE, which I have not defined for GKAT, and
my role-coverage may not be the certificate that survives.

**Next.**  The certificate.  Either port LLEE to guarded charts, or prove that
role-coverage itself is collapse-stable — 223's measurement says it is, on
131 714 automata.

---

## 227 — TESTING `QuotientClosure` REFUTED MY OWN STATEMENT OF IT.  Corrected.

226 reduced the whole remainder to one property and I wrote it down before
testing it.  Testing it took one run.

**The test.**  A Thompson automaton of a random expression is solvable by
construction, so if the property holds, EVERY behavioural quotient of it must
be solvable.  223 had checked only the full collapse; 226's statement quantifies
over the whole congruence lattice, so check the lattice:

    NA=2   6 757 solvable automata   25 899 quotients   failures 0
    NA=3   6 757                     19 407             failures 0
    NA=4   6 757                     16 631             failures 4

**Four failures — and they refute the STATEMENT, not the route.**  Every failing
quotient is NON-MINIMAL.  The dumped one has `c0`, `c3`, `c4`, `c5` literally
identical (`hl=011 st=[-,-,c1,c1]`) — four pairwise-bisimilar states left
unmerged, which the solver treats as four distinct opaque oracles.  That is 222's
artifact, and this time it is not a harness excuse: **it is a defect in what I
wrote.**  `SumQuotientSolvable` needs only SOME quotient, and the natural one is
the full collapse; quantifying over ALL behavioural quotients, including
deliberately un-collapsed ones, demanded strictly more than the theorem ever
needs.

**Corrected**: `QuotientClosure` now carries a minimality hypothesis — no two
distinct states of the quotient are bisimilar — and the reduction
`sumQuotientSolvable_of_closure` threads it through, still machine-checked with
`propext`/`Quot.sound` only.  Under that restriction the measurement is 0
failures in 131 714 automata (223).  The comment in the source records the
refutation, so the hypothesis cannot later look like an unmotivated
strengthening.

**This is the second time in three iterations that testing a definition, rather
than the mathematics, changed the answer** — 221's `ThompsonUnifP` was false at
`F = 1`, and 226's `QuotientClosure` was false at non-minimal quotients.  Both
were caught by instantiating rather than by reasoning.  The habit that keeps
paying: after stating a property, immediately look for the cheapest instance
that could refute it.

**Odds: 80%, held.**  The route is unchanged and the corrected property is the
one Grabmayer actually proves — his closure theorem is about collapse, not about
arbitrary quotients, so the correction moves my statement TOWARD the precedent
rather than away from it.  Not raised, because I published an untested
definition two iterations running and the correction is mine to absorb, not the
theorem's to be credited with.

**Next.**  The certificate.  Role-coverage will not serve — `StateRole` is
parameterised by the solution, so "role-covered" is close to a restatement of
solvable, while LLEE is a property of the GRAPH alone.  So: port LLEE to guarded
charts, defining it on the automaton and checking on Thompson automata that it
holds, survives collapse, and coincides with calculus-solvability.

---

## 228 — A GRAPH-ONLY CERTIFICATE THAT SURVIVES COLLAPSE AND IMPLIES SOLVABILITY.

The certificate has to be a property of the GRAPH, not of a solution — that is
why role-coverage cannot serve (`StateRole` is parameterised by `sol`) and why
LLEE can.  Translating LLEE's loop condition into guard language:

Milner's LLEE forbids successful termination mid-loop; you leave only at the
head.  GKAT inlines the head into the body's exit points, and `loop_core_hlt`
(`rfl`, 220) says exactly how — in `wh b e` every body state halts at
`hlt_body ∧ ¬b` and every back edge fires at `hlt_body ∧ b`.  **One guard
separates staying from leaving, uniformly across the whole loop.**  As a
property of the graph: take `b` to be the atoms on which an SCC moves
internally, and require that no state of the SCC halts inside `b`, rejects
inside `b`, or leaves the SCC inside `b`.

**Measured on Thompson automata of random expressions:**

                                    NA=2        NA=3        NA=4
    (a) holds on Thompson       18546/19857   17608       17029     ~90%
    (b) survives collapse       19857/19857   19857       19857     100%
    (c) guard-but-UNSOLVABLE          0           0           0
        solvable-but-no-guard        1283        2231        2817

**Two of the three requirements are met, and they are the two that matter for
the route:**
  * **(b) it survives bisimulation collapse — 100%, no exceptions.**  This is
    the property role-coverage could not have and the one Grabmayer's whole
    architecture turns on.
  * **(c) it is SUFFICIENT for solvability — 0 counterexamples in ~60 000
    automata across three populations.**  A uniform guard always yields a
    solvable automaton.

**It fails (a), and it fails informatively.**  About 10% of Thompson automata
lack a uniform guard, and the cases are NESTED loops: an outer SCC that contains
an inner loop unions both guards, so no single `b` separates.  That is exactly
the LAYERING that 225 identified as LLEE's content beyond the obvious part —
LLEE permits nested loops at different levels, and my condition is its
single-level restriction.

So this is not the certificate yet; it is the certificate's bottom layer, and
the measurement says the layered version is what to build.

**Odds: 81%, up 1.**  First graph-only property in this development with
collapse-stability and sufficiency both VERIFIED rather than hoped — and those
are the two the route needs, with (a) being the one a layered definition is
designed to fix.  Only +1 because a single-level condition failing on nested
loops is the easy part of LLEE working and the hard part untested.

**Next.**  The layered version: pick a header, take the outer guard to be the
atoms on which back edges into it fire, remove those edges, recurse on the SCCs
that fall out.  Re-run (a), (b), (c) — the target is (a) at 100% with (b) and
(c) holding.

---

## 229 — RETRACTING 228's DIAGNOSIS.  The failures are not nesting.

228 measured that `uniform_guard` holds on only ~90% of Thompson automata and
asserted the failures are NESTED loops.  I asserted it; I did not measure it.
Measuring it:

                            NA=2   NA=3   NA=4
    failing SCCs            1265   2173   2830
      halt-inside-guard      657   1307   1861    ~52%
      reject-inside-guard    554   1137   1679    ~44%
      leave-inside-guard     146    264    351    ~12%
      contain an inner loop    5     15     26    <1%

**Nesting is under 1%.  The diagnosis was wrong.**

**The real cause, which the algebra gives directly.**  In `wh b e` a body state's
internally-moving atoms are `bodymove(s) ∪ (hlt(s) ∩ b)` — and `bodymove(s)` has
NOTHING to do with `b`; it is wherever the body happens to step.  So the union
over all states of the SCC is strictly LARGER than the real loop guard, and
genuine loop-exit halts (`hlt ∩ ¬b`) land inside it whenever some other state
steps there.  A loop state never halts inside its TRUE guard —
`loop_core_hlt` guarantees exactly that — so all 657 halt-failures are an
artifact of how I computed `b`, not a property of the automaton.

**What that means for the fix.**  The guard must be read off the BACK EDGES —
the transitions that restart the loop — not off all internal transitions.  And
separating back edges from body edges is precisely what LLEE's transition
labelling does: loop-entry transitions marked at levels.  So the missing content
is not layering-as-nesting but the labelling that distinguishes a back edge from
an ordinary step.  228's "bottom layer" framing was right about the shape and
wrong about the mechanism.

**What still stands, because it was measured rather than argued:** `uniform_guard`
survives bisimulation collapse 100% (19 857/19 857, all three populations) and is
SUFFICIENT for solvability (0 counterexamples in ~60 000).  Those results are
unaffected — a condition being too strong does not make it unsound, and both are
properties of the condition as implemented.

**Odds: 80%, DOWN 1 — giving back 228's increase.**  Part of that +1 rested on
expecting a layered definition to fix requirement (a); that expectation is now
refuted, and the route to (a) runs through identifying back edges, which is
strictly more work than adding levels to a condition I already had.  The two
verified properties keep the route alive; the estimate of how far it is should
not have moved on an unmeasured belief.

**Next.**  Identify back edges structurally — for each SCC, find the entry set
(the states a restart lands on) and take the guard from the transitions INTO it,
rather than from every internal transition.  Then re-run (a), (b), (c).

---

## 230 — SCC IS NOT A LOOP.  Second guard-reading falsified, and the reason is now clear.

229 said the guard must come from the BACK EDGES, not from all internal
transitions.  `loopInitialized` makes that readable off the graph: a loop's
entry transitions (from outside) and its back edges are the SAME list,
`body.initTrans`, guarded by `b`, landing on the same targets.  So take

    b := the atoms on which an SCC is entered from outside it

and `loop_core_hlt` predicts sharply that **no state of a loop halts inside its
entry guard**, since a loop's halt is `hlt_body ∧ ¬b`.  Falsifiable, and it
should hold on every Thompson automaton.

**It does not.**

    NA=2   2039 / 2146 loop SCCs   (95%)
    NA=3   2915 / 3085             (94%)
    NA=4   3669 / 3901             (94%)

**The counterexample says exactly what is wrong.**

    q0: st=[q2,q2]   q1: st=[q2,q2]   q2: st=[q4,q4]
    q3: st=[q4,q4]   q4: hl={a1} st=[q1,-]

The SCC is `{q1,q2,q4}`, entered from `q0` — which is outside it — on BOTH
atoms, while `q4` halts on `a1`.  So the entry guard is not the loop guard,
because `q0` is not entering the loop at the loop's entry.  **The SCC is not a
single `wh` body.**

**That is the same error as 229's, one level up, and it names the real
constraint: AN SCC IS NOT A LOOP.**  The loop structure is strictly finer than
the SCC decomposition — a single strongly connected component can span more than
one loop construct, and no assignment of one guard per SCC can be right.  Both
attempts failed for this reason and only this reason.

**And it is exactly why LLEE labels TRANSITIONS rather than components.**  Its
certificate assigns loop-entry markings at levels to individual edges, which is
the granularity the structure actually has.  I have now established by two
falsifications what the paper's definition encodes by construction.

**Odds: 80%, held.**  The route — certificate plus closure — is untouched; what
moved is my model of the certificate, from "a guard per SCC" to "a labelling per
transition", which is what the precedent uses.  Not lowered, because the two
verified facts that make the route worth pursuing are unaffected: `uniform_guard`
is collapse-stable (100%) and sufficient for solvability (0 counterexamples in
~60 000).  Not raised, because two iterations produced no forward progress, only
a corrected model.

**Next.**  Transition-level labelling: for each SCC compute a loop-nesting
forest (Havlak/Ramalingam), read a guard PER LOOP rather than per SCC, and check
`loop_core_hlt`'s prediction against that.  If the prediction holds at 100% on
Thompson automata, that labelling is the certificate.

---

## 231 — TRANSITION GRANULARITY WORKS.  94% -> 99%.  And a one-example generalisation punished.

230 established that the certificate must live at TRANSITION granularity.  The
standard construction there is the natural loop of a DFS back edge: for a back
edge `s -a-> h` with `h` an ancestor on the DFS stack, `h` is a loop HEADER and
its natural loop is `{h}` plus every state reaching `s` without passing through
`h`.  Guard := the atoms on which that loop's back edges fire.
`loop_core_hlt`'s prediction, at last asked at the right granularity: no state
of a natural loop halts inside its own loop guard.

    NA=2   18 445 / 18 475 natural loops   99.84%      (SCC-level was 95%)
    NA=3   22 366 / 22 496                 99.42%      (94%)
    NA=4   24 928 / 25 186                 98.99%      (94%)

**Transition granularity is right** — the error rate falls by roughly a factor
of six, and 230's diagnosis is confirmed by the improvement rather than by
argument.

**Then I broke it.**  One violating case —

    q0,q1: st=[q2,q2,q2,q2]      q2: hl={a2,a3} st=[q1,q1,-,-]

— has back edges `q1 -> q2` at ALL FOUR atoms, giving guard `1111`, so `q2`'s
own halts fall inside it.  But `q1 -> q2` is a BODY MOVE, not a restart, and
reading the guard off the header's moves into the body gives `{a0,a1}`, under
which the violation disappears.  Convincing, and I changed the guard.  Measured:

    96.3% / 94.2% / 92.6%   —   strictly WORSE than the back-edge guard

**So the generalisation from that one example is false, and the back-edge guard
stands.**  Reverted, with the number recorded in the source so the same
"obvious" change is not made again.  This is the third time this session that a
claim derived by reasoning from a single instance was refuted by the first
measurement of it — and the first two (228's nesting, 226's `QuotientClosure`)
cost an iteration each because I published before checking.  This one cost
minutes, because the check ran before the write-up.

**The remaining ~1%, diagnosed from the second violation** — `q0: hl={a3}
st=[q1,q0,q0,-]`, `q1: hl={a2,a3} st=[q1,q0,-,-]` — is a genuine NESTED pair:
`q1` carries a self-loop inside the outer `q0 <-> q1` loop, and the outer guard
must be computed on the graph with the inner loop already eliminated.  That is
LAYERED elimination, which is the "L" in LLEE, and it is the one piece of the
definition not yet implemented.

**Odds: 80%, held.**  Real progress on the certificate — the granularity
question is settled and the residue is one named mechanism — but the iteration
also produced a wrong turn that measurement caught, and no property has yet been
shown to hold at 100% on Thompson automata, which is requirement (a).

**Next.**  Layered elimination: compute the loop-nesting forest, eliminate
innermost loops first, and read each outer guard on the reduced graph.  Target
is (a) at 100%, with (b) collapse-stability and (c) sufficiency re-checked.

---

## 233 — THE EXISTENTIAL BARELY HELPS.  A structural mismatch I have been glossing.

232 blamed its shortfalls on committing to one labelling and named the fix:
search over elimination orders instead.  Done — at each step try eliminating ANY
eligible loop, succeed if any order reaches an acyclic graph.

                                NA=2                 NA=3
    (a) LLEE-exists holds   13 227/13 248 99.84%     99.28%
    (b) survives collapse   13 201/13 248 99.65%     99.31%
    (c) LLEE-but-UNSOLVABLE        0                    0
        solvable-but-no-LLEE      53                  145

**Sufficiency holds a fourth time — 0 counterexamples.**  But the existential
bought about 0.05 percentage points, not the missing 0.16, and **(a) is still
not 100%.**  232's diagnosis was therefore only a small part of the story.

**Three refinements, 94% -> 99% -> 99.84%, never closing, each trading one
defect for another.  That pattern indicts the model, not the implementation —
and there is a mismatch I have been glossing over since 224.**

**Milner's charts have PLAIN ACTION transitions.  GKAT's have GUARDED ones.**
LLEE was designed where a transition is `s -a-> t`; in GKAT it is
`s -(g,a)-> t`, and a state's behaviour is a decision list over atoms.  Every
condition I have written — "no state of the body halts inside the guard" — is my
own guess at what LLEE's "no successful termination mid-loop" becomes when
transitions carry tests.  The measurements say that guess is close (99.8%) and
not right.  I should have flagged this at 224 when I wrote "only the GKAT
translation is missing": the translation is not a formality, it is the content.

**What survives regardless.**  Across four independent formulations —
`uniform_guard`, natural-loop guards, layered elimination, and now the
existential — the SUFFICIENCY direction has never once failed: a graph-only
certificate that succeeds always yields a solvable automaton, over ~200 000
automata cumulatively.  That direction is not in doubt.  It is completeness on
Thompson automata, requirement (a), that resists.

**Odds: 79%, DOWN 1.**  Three iterations of refinement have not reached
requirement (a), and the reason now looks structural rather than incidental:
LLEE's conditions are stated for unguarded charts and I have been guessing their
guarded analogue. That is a larger gap than "port the definition", which is how
224 priced it, and the price should come down accordingly.  The route is not
refuted — sufficiency and 223's collapse measurement both stand — but it is
further away than I said.

**Next.**  Stop guessing the guarded analogue and derive it: take
`loopInitialized` and `seqGSystem` and read off what IS true of every Thompson
chart's loops, rather than proposing conditions and testing them.  The
construction is in the repo; the conditions should be extracted from it, not
invented.

---

## 234 — SEARCHING THE GUARD BREAKS SOUNDNESS.  Seven iterations, requirement (a) unmet.

233 said to derive the condition rather than guess it.  Derived, from
`loopInitialized`: the only edges a loop adds are back edges guarded by
`hlt_body(s) ∧ guard ∧ gᵢ`, and its halt is `hlt_body(s) ∧ ¬guard`.  So back
edges lie inside the guard and halts outside it — **the condition tested since
228 is the right one.**  What is approximate is the graph-level RECOVERY of
which edges are back edges and what the guard is; an added back edge is
indistinguishable from a body edge when the body has a similar one.  233 searched
elimination ORDERS but always took the guard from the natural loop.  So search
the guard too.

                                NA=2      NA=3
    (a) holds on              99.76%    99.58%      no improvement
    (b) survives collapse     99.53%    99.21%
    (c) cert-but-UNSOLVABLE        0         1      <- soundness BROKE
        solvable-but-no-cert        52        89

**Two findings, and the second is the one that counts.**

**(1) Guard-identification was not the defect** — (a) did not improve, so the
~0.2% of Thompson automata failing the certificate fail for some other reason.

**(2) Searching the guard BREAKS SUFFICIENCY.**  Across `uniform_guard`,
natural-loop guards, layered elimination, and the order-existential — four
formulations, ~200 000 automata — a certificate that succeeded ALWAYS yielded a
solvable automaton.  Letting the guard range freely admits certificates that
correspond to no real loop, and one certified an UNSOLVABLE automaton.  **The
guard is not free to choose; it must stay tied to graph structure.**  That is a
useful boundary: it says the certificate's guard is DETERMINED, not existential,
even though the loop decomposition is existential.

**Seven iterations (228-234) on the certificate, and requirement (a) has never
been met.**  Each refinement improved something and left the target unreached,
and this one regressed the direction that had been invariant.  That is worth
stating without dressing.

**The check I should run before an eighth attempt:** are my Rust constructors
(`a_seq`, `a_ite`, `a_wh`) actually faithful to the Lean `certifiedThompson`?
Every (a) measurement assumes they are.  If `a_seq` merges a state the Lean
construction keeps distinct, or omits a pseudostate, then the automata I have
been calling Thompson charts are not, and a persistent ~0.2% failure rate is
exactly what that would look like.  This should have been verified at 228,
before seven iterations were spent testing conditions against them.

**Odds: 78%, DOWN 1.**  A soundness break plus no progress on the target, over
a stretch that has now consumed seven iterations.  The route's load-bearing
facts are untouched — 223's collapse measurement, and sufficiency for the four
structurally-tied formulations — so this is a cost of execution, not a refutation.
But an estimate that does not move after seven unproductive iterations is not
tracking anything.

**Next.**  Verify `a_seq`/`a_ite`/`a_wh` against `certifiedThompson` before
proposing anything further.

---

## 236 — THE SUB-CHART GENERATOR IS NARROWER, NOT BROADER.  This line has stalled.

235 localised the residual to the candidate generator and prescribed enumerating
LLEE's loop sub-charts directly: a body `B` with an entry `h ∈ B` such that every
edge into `B` from outside targets `h`.

                            NA=2      NA=3
    (a) holds on          99.15%    98.37%      WORSE than natural loops
    (b) survives collapse 99.96%    99.81%      better
    (c) cert-but-UNSOLVABLE     0         1     soundness broke again
        solvable-but-no-cert     2         6

**(a) got worse, and budget was not the reason** — raising it from 40 000 to
2 000 000 changed nothing (2670/2693 both times), so the failures are genuine
for this generator.  **The generator is NARROWER, not broader**: requiring
single entry EXCLUDES the multi-entry natural loops the DFS version allowed.  I
prescribed it as a broadening and implemented a restriction.

**And soundness broke at NA=3 for the second time in three iterations** — 234's
guard search and now this.

**Standing back, because nine iterations warrant it.**  Five certificate
formulations since 228: `uniform_guard`, natural-loop guards, layered
elimination, order-existential, guard-search, sub-charts.  Requirement (a) peaked
at **99.84% with the FIRST and simplest**, and every variation since has been
neutral or worse, twice at the cost of soundness.  That is not a search
converging; it is a search wandering.

**What I think is actually wrong.**  Grabmayer's LLEE is a LABELLING with a
descent condition — transitions marked as loop-entries at natural-number levels,
with descent into a loop accompanied by a decrease, and loops never mutually
nested.  Every formulation I have written drops the descent/level bookkeeping and
keeps only the halt condition.  The two soundness breaks are exactly what
dropping "loops never mutually nested" would produce: a certificate accepting a
decomposition that no consistent layering admits.  I have been approximating a
definition rather than implementing it.

**Odds: 77%, DOWN 1.**  Nine iterations, requirement (a) never met, best result
from the first attempt, two soundness regressions.  The route's load-bearing
facts still stand — 223's collapse measurement and sufficiency for the
structurally-tied formulations — but my ability to execute this particular step
is the thing being measured now, and it is measuring badly.

**Next, and it should be a change of method, not another variation.**  Implement
LLEE's actual labelling — levels on transitions, descent condition, no mutual
nesting — from the paper's definition rather than from my reconstruction of it.
If that does not reach (a) at 100% on faithful Thompson automata, then either the
guarded case genuinely differs from Milner's or my reading of the definition is
wrong, and both are worth knowing before more iterations are spent.

---

## 237 — (L2) WAS THE MISSING CONDITION.  Requirements (a) AND (b) AT 100%.

236 concluded the line had stalled and that the fix was to stop reconstructing
LLEE and read its definition.  Done.  A loop sub-chart with start vertex `vₛ`:

    (L1)  there is an infinite path from vₛ;
    (L2)  EVERY infinite path from vₛ RETURNS to vₛ after a positive number
          of transitions;
    (L3)  immediate termination is only permitted at vₛ   (↓ ⊆ {vₛ}).

**(L2) is the condition I never implemented, across five formulations and nine
iterations.**  It says `vₛ` CUTS EVERY CYCLE in the body — no cycle may avoid the
head — which is exactly what forbids mutually nested loops, and 236 had already
diagnosed dropping that as the cause of both soundness breaks without realising
it was a stated condition I had simply not read.

(L3) needed the guarded relativisation the whole exercise has been about:
Milner's `↓` is a state property, GKAT's `hlt` is a TEST, so "terminates" becomes
"terminates inside the loop's guard".  That part I had right since 228.

**Measured, implementing L1/L2/L3 as stated:**

    NA=2   13 126/13 126 (a)   13 126/13 126 (b)   0 unsound, 0 missed
    NA=3   13 126/13 126 (a)   13 126/13 126 (b)   1 cert-but-calculus-fails, 0 missed

**Requirement (a) — every Thompson automaton carries the certificate — is MET at
100%, for the first time in ten iterations.  Requirement (b) — it survives
bisimulation collapse — is MET at 100%.**  Those are the two properties the route
needs from a certificate; the third, certificate ⟹ solvable, is Grabmayer's
theorem to port rather than to measure.

**The one discrepancy, not glossed.**  At NA=3, one automaton carries the
certificate while the CALCULUS fails on it.  `solve` there is my six-rule
calculus, not `synth`, so this may be a gap in the calculus rather than
unsoundness of the certificate — those are very different findings and I am not
guessing which.  Adjudicating it needs `synth`'s verified witness.  NA=4 timed
out and is untested.

**What this says about the last nine iterations.**  Five formulations, two
soundness breaks, requirement (a) peaking at 99.84% — all of it because I was
approximating a definition I had not read carefully, and specifically because I
never asked whether the body's cycles must pass through the head.  236's
"change method, don't vary again" was right, and the method that worked was
reading the source.

**Odds: 81%, up 4.**  The largest single move in this program, and it earns it:
the two requirements the route depends on went from "never met in nine
iterations" to 100% on 26 000 automata each, and the fix was a stated condition
rather than another tuned heuristic.  Held below a larger jump by the
unadjudicated NA=3 case, the untested NA=4 population, and the fact that
(c) — certificate implies solvable — is exactly the part still owed to a proof.

**Next.**  Adjudicate the NA=3 case with `synth`, and run NA=4.

---

## 238 — THE (c) DISCREPANCY IS A CALCULUS GAP, NOT CERTIFICATE UNSOUNDNESS.

237 left one NA=3 automaton carrying the L1/L2/L3 certificate while the six-rule
calculus failed on it, and refused to guess whether that was a calculus gap or
an unsound certificate.  Adjudicated with `synth`, which decides by exhibiting
an expression:

    CERT HOLDS, CALCULUS FAILS — synth witness: none at this size bound

    c0: st=[c1,c1,c1]        c1: st=[c2,c0,c3]
    c2: hl={a2} st=[c2,c0,-] c3: hl={a0} st=[-,c0,c3]

The tool printed "certificate SUSPECT" on that verdict.  **The tool's reasoning
is wrong, and the argument against it is short enough to be decisive.**  `qq` is
the bisimulation COLLAPSE of a Thompson automaton, and every state of a Thompson
automaton is expressible by construction — that is what `certifiedThompson`'s
`standard` labelling IS.  Collapse preserves each state's behaviour.  So every
state of `qq` is expressible, and `synth` finding nothing at size <= 10 is a
SIZE-BOUND artifact, not evidence of unsolvability.

**So the automaton is solvable, the certificate is sound on it, and the failure
is in the CALCULUS.**  That is the good outcome for the route — requirements (a)
and (b) are what the route needs from the certificate, and both stand at 100%
over 26 000 automata; the calculus is a separate instrument that does not enter
the closure argument.

**A correction to the harness's logic, recorded because it will recur.**
"`synth` found no witness at size <= N" and "unsolvable" are different
statements, and for automata KNOWN to come from expressions the second is false
by construction regardless of what the first says.  The message should say
"unwitnessed at this bound", never "suspect".  216 measured that the behaviour
table does not saturate, so this gap is permanent and the confusion would
otherwise recur at every size bound.

**Confirming run in flight:** the same test at size <= 14 (68 484 behaviours
against 2 677), which should produce the witness if the size-bound reading is
right.  Reported next iteration either way — if the witness still does not
appear at 14, that is worth knowing precisely because the argument above says it
must appear eventually.

**Odds: 81%, held.**  The adjudication went the favourable way, but it went there
by an argument I could have made at 237 without running anything, so it is a
clarification rather than new evidence.  Requirements (a) and (b) are unchanged
at 100%; NA=4 is still untested.

**Next.**  Read the size-14 run; then NA=4.

---

## 239 — THE ARCHITECTURE IS NOW MACHINE-CHECKED, ABSTRACT OVER THE CERTIFICATE.

Ten iterations of measurement found the certificate (237) and adjudicated its
one discrepancy (238).  The measurements have done their job; this moves the
architecture into Lean.

**`sumQuotientSolvable_of_certificate`** — for ANY predicate `Cert` on automata:

    hsum       the Thompson SUM of two expressions carries it
    hcollapse  it survives passage to a MINIMAL behavioural quotient
    hsolve     carrying it implies a solution exists
    ──────────────────────────────────────────────────────────────
    SumQuotientSolvable  ⟹  completeness of the finite axioms

**`quotientClosure_of_certificate`** — and such a certificate yields 226's
closure property directly, WITHOUT the transport argument 227 proved cannot
work.  That theorem needs **no axioms at all**; the first needs only
`propext`/`Quot.sound`.

**Why abstracting over `Cert` is the right move rather than a dodge.**  It
separates the architecture from the candidate.  The architecture is
Grabmayer's and is now checked; the candidate is the L1/L2/L3 loop-sub-chart
property, and if it turns out to need adjustment — as it has repeatedly — the
chain above does not move.  It also states the obligations in a form where each
can be attacked independently, and two of the three are exactly what 237-238
measured at 100% over 26 000 automata.

**Where each obligation stands:**

    hsum       measured 100% (13 126/13 126 at NA=2 and NA=3)   unproved
    hcollapse  measured 100% (13 126/13 126 at NA=2 and NA=3)   unproved
    hsolve     Grabmayer's "every prechart with LLEE admits a
               solution", proved in the regular-expression
               setting; the GKAT analogue is what the six rules
               do constructively                                unproved

**Odds: 81%, held.**  A machine-checked restatement is not new mathematics — all
three obligations are hypotheses — but it makes the target precise, keeps the
architecture stable against further revisions of the certificate, and records
that two of three are measured at 100%.  Nothing here justifies moving the
number.

**Next.**  NA=4 for `hsum` and `hcollapse` is running.  Then the first real
proof: `hsum`, by structural induction on the expression — every Thompson
automaton carries the certificate — which is where `loop_state_eq`,
`loop_core_hlt` and `loop_core_trans` (all `rfl`, from 218 and 220) should
finally pay off, since they describe exactly the loop a `wh` introduces.

---

## 240 — THE FIRST PIECE OF THE CERTIFICATE, PROVED RATHER THAN MEASURED.

239 put the architecture in Lean with three unproved obligations.  This proves a
piece of the first one.

**`wh_loop_L3`** — LLEE's condition (L3), "immediate termination only at the
loop's start", in its guarded form: no body state terminates INSIDE the loop's
guard.  For `wh b e` every body state's halt is `hlt_body s ∧ ¬b`, so conjoining
`b` gives `0` at every valuation — for every state, every expression, every
guard.  Proved, `propext`/`Quot.sound` only.  **`wh_loop_halt_implies`** restates
it as `GuardImplies (hlt s) (¬b)`: a body state can only terminate where the loop
is already leaving.

**This is the payoff for `loop_core_hlt`** (`rfl`, iteration 220).  Nine
iterations, 228 through 236, were spent GUESSING what LLEE's termination
condition becomes under guards — five formulations, two soundness breaks, a
peak of 99.84%.  237 read the condition from the source; this iteration shows
the `wh` case of it is not merely 100% on 26 000 samples but true outright, and
the proof is four lines because the construction already said so.

**What is proved, precisely, and what is not.**  This is condition (L3) for the
loop that a single `wh` introduces.  `hsum` needs all three conditions
(L1/L2/L3) for every loop of every Thompson automaton, which additionally
requires:

  * (L1)/(L2) for the `wh` loop — L2 being "the head cuts every cycle in the
    body", the condition 237 identified as the one never implemented;
  * that `seq` and `ite` introduce no NEW loops, so the certificate is inherited
    from the sub-expressions.

The second should be straightforward — neither constructor adds a back edge —
and is the natural next target.

**A failed run, reported:** 238's confirming check at synth size <= 14 timed out
at 900s and produced nothing.  It was never load-bearing: 238's argument that the
missing witness is a size-bound artifact is a proof, not a conjecture — every
state of a Thompson automaton is expressible by construction, and collapse
preserves behaviour.  The run would have been a redundant confirmation of
something already settled.  NA=4 for `hsum`/`hcollapse` is still running.

**Odds: 81%, held.**  One condition, for one constructor, of the first of three
obligations.  Real — it is the first part of the certificate that is proved
rather than sampled — but far too small to move the estimate.

**Next.**  `seq` and `ite` introduce no new loops; then (L1)/(L2) for `wh`.

---

## 241 — `wh` IS THE ONLY LOOP-CREATING CONSTRUCTOR.  Proved.

`hsum` needs the certificate for EVERY loop of a Thompson automaton.  If `seq` or
`ite` could create loops, each would need its own (L1)/(L2)/(L3) argument; if
they cannot, the certificate is inherited from sub-expressions and only `wh`
needs work.

**They cannot, and the reason is one-directional edges:**

    seq_inr_closed   in `seqGSystem`, a RIGHT state's transitions all target
                     right states — control passes left-to-right when the left
                     half halts, and NEVER back
    sum_inl_closed   in `sumGSystem` (which `ite` uses), a left state's
                     transitions stay left
    sum_inr_closed   …and a right state's stay right — the two halves are
                     mutually unreachable, the choice being made once at the
                     initial pseudostate

All three proved, `propext`/`Quot.sound` only.  So every cycle lies wholly inside
one sub-automaton, and **`wh` is the only constructor that creates a cycle.**

**Where `hsum` now stands.**  Combined with 240's `wh_loop_L3`:

    seq, ite    create no loops                                    PROVED
    wh   (L3)   no body state terminates inside the loop's guard   PROVED
    wh   (L1)   an infinite path leaves the head                   open
    wh   (L2)   the head cuts every cycle in the body              open
    assembly    a cycle in a sum lies wholly in one side           open

The assembly step is the closure lemmas turned into a statement about cycles
rather than single transitions; it should be mechanical.  **(L2) is the real
remaining content**, and it is the same condition 237 found had never been
implemented in nine iterations of measurement — which is at least consistent
about where the difficulty lives.

**Odds: 81%, held.**  Three structural lemmas that were always going to be true
and took four lines each.  They matter for the shape of the induction — the
`wh` case is now the ONLY case — but proving the easy parts of a proof does not
change the odds of the hard part.

**Next.**  (L2) for the `wh` loop: in `wh b e`, does the loop's head cut every
cycle of the body?  Note this is a statement about `e`'s OWN cycles, so it will
need the induction hypothesis — which is the first point in this development
where the expression-induction 217 proposed genuinely earns its place.

---

## 242 — THERE IS NO CANONICAL LOOP HEAD.  GKAT inlines it, and it shows.

241 left (L2) as the remaining content of `hsum`.  Before attempting it: (L2) is
stated for a loop sub-chart with a SINGLE start vertex `vₛ`, but
`loopInitialized`'s back edges target `body.initTrans`'s targets — a SET of entry
states, one per atom.  The construction hands over no canonical head, and the
Rust check has been finding heads by SEARCH.  A Lean proof must exhibit one.

**Measured — for each loop SCC, how many of its states are a valid head (L2 and
guarded-L3, whole SCC as body)?**

    valid heads      0      1      2     3+
    NA=2  (1484)    240    567    606    71
    NA=3  (2124)    622    900    548    54
    NA=4  (2615)    986   1098    491    40

    an ENTRY state is a valid head:  850/1071, 1051/1609, 1181/2058
                                       79%       65%       57%

**16-38% of loop SCCs admit NO valid head at all.**  So 237's 100% did not come
from finding one head per SCC — it came from decompositions whose bodies are
PROPER SUBSETS of the SCC, nested sub-charts found by subset enumeration.  And
there is no canonical selection rule: "the entry state is the head" holds only
57-79% of the time, falling as the atom count rises.

**The underlying reason is the one that has shaped this whole translation.**
Milner's charts have an explicit loop head; **GKAT's Thompson construction
INLINES it** — `loopInitialized` keeps the body's state set and distributes the
head's guard test over the body's exit points (`loop_state_eq`, `rfl`, from 218).
There is simply no vertex through which all of a GKAT loop's cycles pass, because
the vertex was compiled away.

**What that costs.**  `hsum` cannot be proved by exhibiting a head per SCC; it
needs the nested sub-chart decomposition constructed, and the natural source for
it is the EXPRESSION structure rather than the graph — for `wh b e` the outer
body is `e`'s states and `e`'s own loops nest inside.  That is a real
construction, not a lemma, and it is more work than 241 implied.

**One idea worth recording rather than pursuing now:** an equivalent Thompson
construction that keeps an EXPLICIT head state for `wh` would make (L2) apply
directly, since it would restore the vertex Milner's charts have.  Such an
automaton is bisimilar to the inlined one.  The catch is that bisimulation
collapse would then remove the explicit head again — which is exactly the
tension crystallization exists to manage, and 223 measured GKAT does not suffer.
Whether those two facts can be held together is the question.

**Odds: 80%, DOWN 1.**  The measurement was the right thing to run before
attempting (L2) and it came back unfavourable: the proof obligation is a
construction over nested sub-charts, not the exhibition of a state.  241's
"(L2) is the real remaining content" was right; its implied difficulty was
understated.

**Next.**  Decide between constructing the nested decomposition from the
expression structure, and the explicit-head variant above.  The second is
cheaper if the collapse tension resolves; measure that before committing.

---

## 243 — THE EXPLICIT-HEAD ROUTE REFUTES ITSELF.  You can have the head or the closure, not both.

242 left two routes for `hsum`: construct the nested sub-chart decomposition from
the expression structure, or use a Thompson variant that keeps an EXPLICIT head
state for `wh` so that (L2)'s single start vertex exists canonically.  242 said
measure the collapse tension before committing.  No measurement is needed — the
second route refutes itself.

**To un-inline the head, a body state that COMPLETES must return to the head
consuming no action.**  The body finishing and the guard being re-tested is a
single step in Milner's charts.  In GKAT it would be an EMPTY-STEP transition,
and GKAT has none: every GKAT transition carries an action.  **That is precisely
why `loopInitialized` inlines the head in the first place.**

**So the explicit-head route does not buy a canonical head for free.**  It moves
GKAT out of the PROPER-STEP case — where 223 measured collapse preserving the
certificate 131 714 times out of 131 714, and where 224 confirmed from the paper
that "for proper-step LLEE-charts, bisimulation collapse preserves LLEE" — and
into the EMPTY-STEP case, where Grabmayer proved it does NOT and had to invent
crystallization.

**You can have the explicit head or the collapse-closure, not both.  That trade
IS what his paper is about**, and this development has been sitting on the
favourable side of it without understanding why.  The inlining that has made
every (L2) formulation awkward for fifteen iterations is the same inlining that
makes requirement (b) hold at 100%.

**That resolves the choice.**  Route (i) — construct the nested decomposition
from the expression structure — is the one to take.  For `wh b e` the outer
body is `e`'s states and `e`'s own loops nest inside, so the decomposition is
read off the expression, which is exactly the structure the induction already
has.  The alternative is to import crystallization, which is strictly more work
for a problem 223 says GKAT does not have.

**What this is worth.**  A route eliminated by reasoning rather than by four
iterations of implementing it — which, given that 228-236 were four iterations of
implementing the wrong thing, is the lesson from that stretch actually being
applied.  It also explains the architecture of the whole approach in this
setting for the first time: the two requirements the route needs, (a) canonical
structure and (b) collapse-stability, pull in opposite directions, and GKAT's
constructor already chose (b).

**Odds: 80%, held.**  Nothing proved, one route correctly eliminated, and a
structural understanding of why the remaining one is the only one.  That is
clarity, not progress.

**Next.**  Route (i): define the nested decomposition as a function of the
EXPRESSION — for `wh b e`, body = `e`'s states with `e`'s decomposition nested
inside — and prove (L1)/(L2) for it by induction, where the induction hypothesis
supplies the body's own decomposition.

---

## 244 — (L2′) PER-SCC FAILS TOO.  But the failure hands over the right formulation.

243 chose route (i) and 242 showed there is no canonical single head.  Working
`wh c (ite b p q)` by hand shows why: its body has TWO entry states, and after
inlining both have edges to both, so the GRAPH carries three cycles where the
EXPRESSION has one loop.  **Inlining does not merely remove Milner's head — it
multiplies one loop into one cycle per entry atom.**

So the natural guarded analogue looked like (L2′): every cycle passes through the
ENTRY SET rather than through a vertex.  That set is determined by the graph, so
no search is needed.  Measured:

    NA=2   892/1412 loop SCCs   63%
    NA=3  1273/2061             62%
    NA=4  1591/2565             62%

**Refuted, and for the same reason one level up: an SCC contains a whole NEST of
loops.**  An inner `wh` and its enclosing `wh` merge into ONE strongly connected
component once the outer's back edges connect everything, so no single entry set
cuts all the cycles either.  Every per-SCC formulation — head (242), entry set
(244) — fails for this one reason, which is why 237's working version needed
subset enumeration and proper-subset bodies.

**But the failure identifies the right formulation, and the lemma for it is
already proved.**  The condition must be applied PER LAYER, and `loop_core_trans`
(`rfl`, iteration 220) says exactly what removing a layer leaves:

    trans of (wh b e)  =  trans of e  ++  the back edges

**So deleting a layer's back edges returns PRECISELY `e`'s own Thompson
automaton.**  The obligation after eliminating the outer layer is therefore not a
fresh acyclicity check — it is the INDUCTION HYPOTHESIS, applied to `e`.  That is
what an induction on the expression is for, and it is the first formulation in
this stretch that does not require searching the graph at all: the layers ARE the
`wh` nesting of the expression.

**The shape of `hsum` is now determined:**

    seq, ite    create no loops                                PROVED   (241)
    wh   (L3)   no body state halts inside the loop's guard    PROVED   (240)
    wh   layer  removing its back edges yields e's automaton   `rfl`    (220)
    wh   (L1)   an infinite path leaves the layer              open
    induction   assemble the above over the expression         open

**Odds: 80%, held.**  A formulation refuted at 62% and replaced by one built on a
lemma already in hand.  Nothing proved this iteration, but the remaining
obligations no longer mention graph search — which is what made every previous
formulation unprovable rather than merely unproved.

**Next.**  State the layered certificate as a function of the EXPRESSION and
prove `hsum` by induction, with `loop_core_trans` discharging the layer step and
the IH discharging the body.

---

## 245 — THE `wh` LAYER IS FULLY CHARACTERISED.  The guard was never in the graph.

244 established the per-layer formulation and left the back edges to be
characterised.  Done, and both halves proved first try:

    wh_backedge_guard_implies   every appended back edge carries guard
                                `hlt_body s ∧ (b ∧ gᵢ)`, hence implies `b`
    wh_layer_separates          back edges INSIDE the guard, halts OUTSIDE it

Together: **the guard `b` separates "iterate" from "leave" at every state of the
layer** — the guarded form of "you exit a loop only at its head", proved outright
rather than measured at 100%.

**And the guard is `b`, the `wh`'s own test — determined by the EXPRESSION, not
recovered from the graph.**  That is the fact iterations 228-236 spent nine
attempts trying to reconstruct from transition data: `uniform_guard` took it from
all internal transitions (wrong, 229), natural loops took it from back edges
(99.84%, 231), a free search over guards broke soundness (234) and concluded it
"must stay tied to graph structure".  It never was in the graph.  It is written
in the expression, and `loopInitialized` puts it into every back edge it appends.

**A note on why `Cert` cannot be defined over expressions**, recorded because it
is tempting and wrong: `hcollapse` applies `Cert` to the QUOTIENT, which has no
expression.  So `Cert` must be the existential over layered decompositions —
what 237 tests, at 100% for both `hsum` and `hcollapse` — and `hsum`'s proof
EXHIBITS the witness from the expression structure.  Defining `Cert` inductively
over `Exp` would make `hsum` trivial and `hcollapse` unstatable.

**`hsum` now stands at:**

    seq, ite    create no loops                              PROVED  (241)
    wh   layer  back edges in the guard, halts outside it    PROVED  (245)
    wh   layer  removing back edges yields e's automaton     `rfl`   (220)
    wh   (L1)   an infinite path leaves the layer            open
    induction   assemble the above over the expression       open

**Odds: 80%, held.**  The layer is characterised and the guard question — nine
iterations of it — is closed by reading the construction.  But (L1) and the
assembly remain, and `hcollapse` and `hsolve` have not been touched.  Real, and
too small to move the number.

**Next.**  (L1) for the layer, then the induction that assembles these into
`hsum`.

---

## 246 — A LAYER IS A DIFFERENCE BETWEEN TWO AUTOMATA, NOT A SUB-GRAPH.

**(L1) is not a proof obligation.**  It says the sub-chart is a real loop — "there
is an infinite path from `vₛ`" — so in the induction it is a CASE SPLIT: either
the layer has back edges, or there is no cycle and nothing to eliminate.  That
leaves the assembly, and the assembly needed the right object.

**`IsLayer sys base b`** — `sys` is `base` with one loop layer at guard `b`:
every state's transitions are `base`'s followed by extra BACK EDGES all inside
`b`, and every state's halt is `base`'s restricted to `¬b`.

**`wh_isLayer`** — `wh b e`'s automaton is EXACTLY one layer over `e`'s.  Proved
from `loop_core_trans` and `loop_core_hlt` (both `rfl` since 220) plus 245's
guard characterisation.

**The formulation is the finding.**  A layer is a DIFFERENCE BETWEEN TWO
AUTOMATA, not a sub-graph picked out of one.  That is why nothing recovered it
from the transition relation: 242's head search, 244's entry sets, and nine
iterations of guard reconstruction (228-236) were all looking INSIDE a single
graph for something that exists only as a relation BETWEEN `wh b e`'s automaton
and `e`'s.  Milner's charts let you point at the loop because the head is a
vertex; GKAT's compile the head away, and what survives is the difference.

That also explains, in retrospect, why `loop_core_trans` — an append, `rfl`,
sitting in the file since iteration 220 — was the lemma every formulation kept
almost using.  The append IS the layer.

**`hsum` now stands at:**

    seq, ite     create no loops                            PROVED  (241)
    wh   layer   back edges inside the guard, halts outside PROVED  (245)
    wh   layer   `wh b e` is one layer over `e`             PROVED  (246)
    wh   (L1)    non-degeneracy — a case split, not an obligation
    induction    the inductive "layered" predicate on automata, and the
                 assembly over the expression                open

**Odds: 80%, held.**  The object is right and three of the pieces are proved,
but `hsum` itself is not, and `hcollapse` and `hsolve` remain untouched.  A
better formulation is not a theorem.

**Next.**  The inductive `Layered` predicate on automata — `acyclic`, or a layer
over something layered — and `hsum` by induction on the expression, with
`wh_isLayer` discharging the `wh` case and 241's closure lemmas the others.

---

## 247 — THE CERTIFICATE IS AN INDUCTIVE PREDICATE, AND THE `wh` CASE IS THREE LINES.

**`Layered sys`** — an automaton is layered when it is ACYCLIC, or is one loop
layer over something layered.  Stated on the AUTOMATON, not on an expression,
because `hcollapse` must apply it to the quotient (245).  Acyclicity is witnessed
by a rank every transition strictly decreases — the finite-state form of LLEE's
"elimination terminates at a chart without infinite paths", which avoids needing
a path predicate at all.

**Proved:**

    layered_test   no states; vacuous rank
    layered_act    one state, no transitions
    layered_wh     Layered.layer (wh_isLayer b e) h

**`layered_wh` is three lines.**  The `wh` case is the one iterations 228-246
could not formulate — five certificate variants, two soundness breaks, a peak of
99.84%, and 242/244 refuting the head and entry-set readings at 16-38% and 62%.
Once a layer is the DIFFERENCE between `wh b e`'s automaton and `e`'s (246)
rather than a sub-graph of either, the case is `Layered.layer` applied to a fact
that has been `rfl` since iteration 220.

**What remains of `hsum`: `seq` and `ite`.**  Those need `Layered` to relate
automata with DIFFERENT state types — `Sum S₁ S₂` against `S₁` and `S₂` — which
is what 241's closure lemmas are for: a right state's transitions stay right, a
left state's stay left, so cycles never cross the seam and a rank can be built
componentwise.  Mechanical, but not free: it is the one place the state type
changes.

    layered_test / layered_act    base cases                  PROVED  (247)
    layered_wh                    the loop case               PROVED  (247)
    layered_seq / layered_ite     componentwise, via 241       open
    hsum                          assemble by induction on e   open
    hcollapse, hsolve             untouched

**Odds: 81%, up 1.**  Three of the five `hsum` cases proved, including the one
that was believed hardest and consumed sixteen iterations.  The remaining two
are of a kind that has not resisted before — 241 already proved the facts they
need — which is a different situation from any point in the 228-246 stretch.
Only +1: `hsum` is one of three obligations and the other two are untouched.

**Next.**  `layered_seq` and `layered_ite` by componentwise rank, then `hsum`.

---

## 248 — `IsLayer` NEEDED RELATIVISING, AND A LAYER NOW LIFTS INTO A SUM.

Attempting `layered_seq`/`layered_ite` immediately exposed a defect in 246's
`IsLayer`: `hlt_eq` demanded `sys.hlt s = base.hlt s ∧ ¬b` at EVERY state.  In a
sum, a layer living in the left component leaves right states untouched, so the
uniform equation fails there and **a component's layer is not a layer of the
whole automaton** — the seq/ite cases could not even be STATED.

**Relativised**: `IsLayer sys base b dom` now carries the set of states the layer
touches, requiring the guard equations only ON `dom` and requiring `sys` and
`base` to AGREE off it.  For `wh` the domain is everything (the whole body is the
loop), so `wh_isLayer`, `layered_wh`, `layered_test` and `layered_act` all still
hold unchanged.

That is the right shape independently of the sum problem: a loop layer touches a
loop BODY, not an entire automaton.  246 got away with uniformity only because
`wh` happens to be the case where the body is everything.

**`sum_isLayer_left`** — a layer in the left component IS a layer of
`sumGSystem L R`, with domain carried into the left and empty on the right.
Proved: transitions map through the append (`List.map_append`), guards are
unchanged by the injection, and `outside` discharges the entire right half.

**Where `hsum` stands:**

    layered_test / layered_act    base cases                  PROVED  (247)
    layered_wh                    the loop case               PROVED  (247)
    IsLayer relativised           layers touch a body          done   (248)
    sum_isLayer_left              a layer lifts into a sum    PROVED  (248)
    sum_isLayer_right             symmetric                    open
    layered_sum / layered_seq     double induction on the two
                                  Layered derivations          open
    hsum                          assemble over the expression open

**Odds: 81%, held.**  A necessary correction and one lemma.  The correction is
the kind that would have blocked the seq/ite cases entirely, so finding it by
attempting them rather than by inspection is the process working — but a fixed
definition and a lifting lemma are not `hsum`.

**Next.**  `sum_isLayer_right`, then `layered_sum` by induction on both
derivations: acyclic/acyclic gives a componentwise rank via 241's closure
lemmas, and a layer on either side lifts by the two lemmas above.

---

## 249 — 492 CALCULUS GAPS AT NA=3 k=3, AND THE SYMMETRIC LIFTING LEMMA.

**The long-running NA=3 exhaustive enumeration finished**: 1 953 125 automata at
k=3, minimised, filtered by verified `synth` witness — **492 solvable-but-unsolved
by the six-rule calculus.**  First instance:

    q0: hl={a0} st=[-,q2,q1]     q1: dead     q2: hl={a2} st=[q0,-,-]

A two-state loop `q0 ↔ q2` with `H(q0) = {a0}` and `H(q2) = {a2}` — neither
halt-set contains the other, which is exactly the condition iteration 212
measured as necessary for a 2-state loop to be solvable by these rules.

**Stated carefully, because it is easy to over- or under-read.**

  * These are CANDIDATE gaps, not confirmed: `synth_lookup` checks STATE 0 only,
    so an automaton can pass the filter while some other state of the failing
    SCC is not expressible.  225's audit showed this direction is conservative
    for a count of zero; it is NOT conservative for a count of 492.
  * **It does not bear on the LLEE route.**  239's architecture needs `hsolve` —
    that a CERTIFICATE implies a solution exists — not that my six rules find
    one.  The calculus is an instrument for measuring, not a component of the
    proof.
  * **It does retire a claim I made at 223**: "on that population the six-rule
    calculus IS the solvability characterization, exactly".  That was NA=2 with
    k <= 4, where it held over 1 695 497 automata.  At NA=3 with k=3 it fails
    492 times in 1 953 125.  The claim was scoped correctly when made; recording
    the boundary now that it is known.

**Also proved: `sum_isLayer_right`**, the mirror of 248 — a layer in the right
component is a layer of the sum, domain empty on the left.  Both lifting lemmas
are now in hand, which is what `layered_sum`'s inductive step needs.

    layered_test / layered_act    PROVED (247)
    layered_wh                    PROVED (247)
    sum_isLayer_left / _right     PROVED (248, 249)
    layered_sum                   double induction              open
    layered_seq                   `seqGSystem` is not `sumGSystem`  open
    hsum                          assembly                      open

**A caution for `layered_seq` worth writing down before attempting it:**
`seqGSystem` is NOT `sumGSystem` — a left state's transitions include the RIGHT
half's entry transitions, guarded by `left.hlt s` (241's `seq_inr_closed` only
says the right half is closed, not that the left is).  So the seq case needs its
own argument, and the rank must account for the one-way crossing.

**Odds: 81%, held.**  A mirror lemma, and a measurement that costs the calculus
a claim while leaving the route untouched.  Neither moves the estimate.

**Next.**  `layered_sum` by induction on both derivations; then `layered_seq`
with the one-way crossing handled.

---

## 250 — `layered_sum` AND `layered_ite` PROVED.  FOUR OF FIVE `hsum` CASES DONE.

**`layered_sum`** — the sum of two layered automata is layered, by induction on
both derivations:

  * **acyclic / acyclic**: the ranks combine componentwise as `Sum.elim r₁ r₂`.
    This is sound precisely because 241 proved cycles never cross the seam — a
    left state's transitions stay left, a right state's stay right — so every
    transition decreases its OWN component's rank.  241 was proved nine
    iterations ago for exactly this moment.
  * **layer on either side**: 248/249's lifting lemmas carry it into the sum, and
    the induction hypothesis handles the base.

**`layered_ite`** follows definitionally: `iteInitialized`'s core IS
`sumGSystem` of the two branches.

    layered_test / layered_act    base cases        PROVED  (247)
    layered_wh                    the loop case     PROVED  (247)
    layered_sum / layered_ite     the choice case   PROVED  (250)
    layered_seq                   the sequence case  open
    hsum                          assembly           open

**Only `seq` remains, and 249 already flagged why it is not a repeat of `ite`.**
`seqGSystem` is not `sumGSystem`: a LEFT state's transitions include the RIGHT
half's ENTRY transitions, guarded by `left.hlt s`.  241's `seq_inr_closed` says
the right half is closed, not that the left is — control crosses the seam
one-way, when the left half halts.  So the componentwise rank does not transfer
unchanged; it needs the crossing to be a DECREASE, which means ranking all left
states above all right states.  That is available: `Sum.elim (fun x => r₁ x +
maxR + 1) r₂` for a bound `maxR` on the right ranks.

**Odds: 81%, held.**  Four of five cases, and the fifth has a known shape with a
known fix.  But `hsum` is one of three obligations and `hcollapse`/`hsolve`
remain untouched, so the estimate should not move until a whole obligation
closes.

**Next.**  `layered_seq` with the offset rank, then `hsum` by induction on the
expression.

---

## 251 — THE `seq` ACYCLIC CASE, PROVED.  And a shape problem in the layer case.

**`layered_seq_acyclic`** — proved first try.  `seqGSystem` crosses the seam
ONE-WAY (a left state's transitions include the right half's ENTRY transitions,
guarded by `left.hlt s`), so `layered_sum`'s componentwise rank does not
transfer; the crossing must itself be a decrease.  It is, once every left state
outranks every right one: `GSystem.states` is a `List`, so the right ranks are
bounded by a fold-max `M` (defined Mathlib-free), `InitTargetsListed` puts every
crossing target in that list, and ranking left states at `r₁ x + M + 1` makes
the crossing strictly decreasing.

**And attempting the LAYER case for `seq` surfaces a real shape problem, worth
recording rather than rushing.**  `IsLayer` requires

    sys.trans s  =  base.trans s ++ extra

— the back edges APPENDED.  For a layer in the left component of a sequence:

    sys.trans (inl s)  =  (L'.trans s ++ extra).map inl  ++  R.initTrans.map …
                       =  (L'.trans s).map inl ++ extra.map inl ++ R.initTrans.map …
    base.trans (inl s) =  (L'.trans s).map inl           ++  R.initTrans.map …

**The extra sits in the MIDDLE, not at the end.**  So `sys.trans s ≠
base.trans s ++ extra` and `IsLayer` does not apply as stated.

Whether that matters SEMANTICALLY is a separate question — transition lists are
resolved by `firstMatch`, so order is only observable when guards overlap, and
`CoreHaltDisjoint` constrains that.  But the definition as written is
syntactic, so either it needs relaxing to "`extra` inserted somewhere, with
disjointness" or the seq layer case needs a different route.  248 already had to
relativise `IsLayer` once when the sum case would not state; this is the same
kind of pressure from the seq case, and guessing at the fix is exactly what
228-236 punished.

    layered_test / act / wh / sum / ite    PROVED  (247, 250)
    layered_seq  acyclic case              PROVED  (251)
    layered_seq  layer case                blocked on the IsLayer shape
    hsum         assembly                  open

**Odds: 81%, held.**  One case proved, one obstacle found and NOT papered over.

**Next.**  Decide the `IsLayer` shape question properly: check whether
`firstMatch` is insensitive to where the extra block sits given the guard
disjointness the Thompson invariants already provide, and only then adjust the
definition.

---

## 252 — `IsLayer` MUST BE SEMANTIC.  The `seq` case restricts, it does not merely insert.

251 found that a `seq` layer puts its back edges in the MIDDLE rather than
appending them, and left open whether relaxing "appended" to "inserted somewhere,
with disjointness" would suffice.  Working the case precisely says it would not.

For `seq (wh b e) f`, writing `L'` for `e`'s core and `R` for `f`'s:

    sys.trans (inl s)  = (L'.trans s).map inl ++ backedges.map inl
                         ++ R.initTrans guarded by (L'.hlt s ∧ ¬b ∧ …)
    base.trans (inl s) = (L'.trans s).map inl
                         ++ R.initTrans guarded by (L'.hlt s ∧ …)

**The trailing block's GUARDS change too** — from `L'.hlt s ∧ g` to
`L'.hlt s ∧ ¬b ∧ g`.  That is necessary and correct: where `e` halts, the
sequence must proceed to `f` only when `¬b`, and loop back when `b`.  But it is a
different relation from insertion, and no weakening of "appended" to "inserted"
captures it.

**Why the `wh` case hid this.**  There, `base.trans s = L'.trans s` and the back
edges are guarded by `hlt ∧ b`, while `CoreHaltDisjoint` makes every base
transition's guard disjoint from `hlt` — so the two blocks never overlap and
appending is faithful.  In a sequence the trailing block IS guarded by `hlt`,
which is exactly where the back edges live, so they must be separated by `b` and
`¬b`.  246's syntactic `IsLayer` worked because `wh` is the case where the layer
and the base cannot collide.

**So the fix is not another syntactic weakening — `IsLayer` has to be SEMANTIC:**
a layer splits a state's EXIT behaviour by the guard, taking the back edge on `b`
and doing what the base did on `¬b`.  Stated through `firstMatch` that is one
condition covering both cases, where the syntactic version needs a different
shape per constructor.

**This is 248 for the third time**, and the pattern is now clear enough to state
as a rule: **every time `IsLayer` has been defined syntactically it has failed at
the next constructor** — uniform-halt failed at `sum` (248), append-shape failed
at `seq` (251, 252).  The object being defined is a relation between BEHAVIOURS;
defining it on list structure keeps encoding one constructor's accident.

**Odds: 81%, held.**  No proof, but a definition question settled by working the
case rather than by patching and re-measuring — which is what 228-236 cost four
iterations by not doing.  The remaining `hsum` cases are unchanged in number;
what changed is that the next attempt has a reason to work.

**Next.**  Restate `IsLayer` semantically via `firstMatch`, re-derive
`wh_isLayer` and the sum lifting lemmas from it, then the `seq` layer case.

---

## 253 — THE SHAPE THAT COVERS BOTH CASES, DESIGNED AND NOT YET LANDED.

252 concluded `IsLayer` must become semantic.  Before refactoring to `firstMatch`
— which would break the SYNTACTIC rank proofs in `layered_sum` and
`layered_seq_acyclic`, both of which decompose transition-list membership — I
looked for a syntactic shape general enough for both constructors.  There is one:

    base.trans s = pre ++ post
    sys.trans s  = pre ++ extra ++ post.map (fun tr => (¬b ∧ tr.1, tr.2))
                   with every guard in `extra` implying `b`

`wh` is the case `post = []`: `CoreHaltDisjoint` keeps the back edges from
colliding with anything, so appending is faithful and 246 got away with it.
`seq` is `pre = (L'.trans s).map inl`, `post =` the right half's ENTRY block —
guarded by `hlt`, exactly where the back edges live, so it must be RESTRICTED to
`¬b` rather than left alone.  One shape, both constructors, and the rank proofs
survive because membership still decomposes.

**Not landed.**  Changing the field ripples into `wh_isLayer`,
`sum_isLayer_left` and `sum_isLayer_right`, and I could not finish all three
within this iteration.  **The file was reverted to green rather than committed
with `sorryAx` in it** — the repo has held zero `sorry` in this cluster
throughout, and a half-migrated definition would silently weaken every theorem
downstream of it while still printing axioms lines that look fine.

**What is actually owed**, so the next attempt is bookkeeping rather than
rediscovery:

    wh_isLayer         pre = base.trans s, extra = back edges, post = []
                       (two `List.append_nil` rewrites)
    sum_isLayer_left   pre' = pre.map inl, extra' = extra.map inl,
                       post' = post.map inl; needs
                       (post.map restrict).map inl = (post.map inl).map restrict,
                       which is `List.map_map` on both sides
    sum_isLayer_right  symmetric
    layered_seq        then available for the first time

**Odds: 81%, held.**  A design step and a clean revert.  Reverting is the right
call and costs an iteration; committing a partially-migrated `IsLayer` would have
cost more, because every theorem above it would still typecheck against the old
shape while the new one was unproved.

**Next.**  Land the shape across all three lemmas in one go, then `layered_seq`.

---

## 254 — THE SHAPE LANDED.  `IsLayer` now covers `wh` and `seq` alike.

253 designed the shape and reverted rather than commit a half-migration.  This
lands it across every affected lemma in one pass:

    base.trans s = pre ++ post
    sys.trans s  = pre ++ extra ++ post.map (fun tr => (¬b ∧ tr.1, tr.2))
                   with every guard in `extra` implying `b`

    wh_isLayer         post = [], two `simp` steps
    sum_isLayer_left   pre/extra/post each mapped through `inl`; the new
                       obligation is
                       (post.map restrict).map inl = (post.map inl).map restrict,
                       which `List.map_map` on both sides closes by `rfl`
    sum_isLayer_right  symmetric

**Zero errors, no `sorryAx`, and all nine theorems still proved** —
`wh_isLayer`, `layered_wh`, `layered_test`, `layered_act`,
`sum_isLayer_left/right`, `layered_sum`, `layered_ite`,
`layered_seq_acyclic`.  The rank proofs survived untouched, which was the whole
reason for keeping the definition syntactic rather than moving to `firstMatch`
(252's first instinct).

**What this unblocks.**  `layered_seq`'s LAYER case is now statable for the first
time: 251 found it blocked because a `seq` layer inserts back edges in the middle
AND restricts the trailing block's guards, and the shape now expresses exactly
that.

    layered_test / act / wh / sum / ite   PROVED  (247, 250)
    layered_seq  acyclic case             PROVED  (251)
    layered_seq  layer case               now STATABLE, open
    hsum         assembly                 open

**Odds: 81%, held.**  A definition migration is plumbing, however necessary.  The
number should move when `hsum` closes, not when its prerequisites do.

**Next.**  `layered_seq`'s layer case with the new shape, then `hsum` by
induction on the expression.

---

## 255 — THE SYNTACTIC SHAPE BREAKS ON ASSOCIATIVITY.  252 was right, with a bound.

254's shape got `layered_seq`'s layer case statable.  Working it through, it does
not close, and the reason is exact.  At `inl s`, writing `L` for the layered left
half and `L'` for its base:

    sys's trailing init guards        (L'.hlt s ∧ ¬b) ∧ tr.1
    POST.map restrict's init guards    ¬b ∧ (L'.hlt s ∧ tr.1)

**Semantically equal, syntactically different** — they differ by associativity
and commutativity of `∧`.  `sys` gets its guard from `L.hlt s = L'.hlt s ∧ ¬b`
being substituted into `seqGSystem`'s `L.hlt s ∧ tr.1`; the shape's `restrict`
conjoins `¬b` on the OUTSIDE.  Nothing in the list structure is wrong: `pre`,
`extra` and `post` line up exactly, lengths and targets match.  Only the guard
TERMS differ.

**So 252's instinct was right, and this bounds how right.**  It concluded
`IsLayer` must be semantic; 253/254 kept it syntactic to protect the rank proofs,
which was also right — those survived the migration untouched.  The resolution is
neither: **the LIST STRUCTURE stays syntactic, and only the GUARDS go semantic.**

    split : ∀ s, dom s → ∃ pre extra post post',
      base.trans s = pre ++ post
      sys.trans s  = pre ++ extra ++ post'
      every guard in `extra` implies `b`
      post' matches post pointwise: same targets, and each guard EQUIVALENT
        (not equal) to `¬b ∧` the corresponding one

Rank proofs decompose membership through `pre`/`extra`/`post'` exactly as now, so
they are untouched again; the AC problem disappears because `bval` equality is
insensitive to it.

**Not landed, for the reason 253 gave and 254 vindicated**: it changes the field
again, and a half-migration would leave every downstream theorem typechecking
against a shape that is no longer proved.  The pointwise relation also needs
defining Mathlib-free — this cluster has no `List.Forall₂` — which is a small
recursive definition, not a one-liner.

**Odds: 81%, held.**  Second shape failure in the `seq` case, but the first was
diagnosed and fixed and this one is diagnosed with a fix specified.  The pattern
across 248, 252 and 255 is consistent and now well understood: every attempt to
state a layer purely on syntax has broken at the point where guards are
manipulated rather than merely carried.

**Next.**  Define the pointwise guard-equivalence relation, migrate `IsLayer` to
the hybrid shape in one pass, then `layered_seq`.

---

## 256 — THE HYBRID SHAPE LANDED.  Structure syntactic, guards semantic.

255 specified it; this lands it in one pass, as 253's rule requires.

**`RestrictedTo b post post'`** — a Mathlib-free inductive (this cluster has no
`List.Forall₂`): same targets and actions in the same order, each guard of
`post'` EQUIVALENT to `¬b ∧` the corresponding guard of `post`.  Plus
`RestrictedTo.map`, which carries it through a retargeting injection — the
lemma the `Sum` lifting needs.

**`IsLayer`** now reads: `base.trans s = pre ++ post`, `sys.trans s = pre ++
extra ++ post'`, every guard in `extra` implying `b`, and
`RestrictedTo b post post'`.

**Why this is the resolution rather than a third guess.**  252 said go semantic;
253/254 kept it syntactic to protect the rank proofs.  Both were right about
different halves: the LIST STRUCTURE must stay syntactic, because the rank
proofs decompose membership through `pre`/`extra`/`post'`; only the GUARDS need
to be semantic, because that is the only place 255's associativity mismatch
lives.  Splitting the definition along that line makes both concerns disappear
at once.

**Zero errors, no `sorryAx`, all nine theorems still proved** — `wh_isLayer`
(now `post = post' = []`, discharged by `RestrictedTo.nil`), `layered_wh`,
`layered_test`, `layered_act`, `sum_isLayer_left/right` (the map-composition
step 254 needed is gone; `RestrictedTo.map` replaces it), `layered_sum`,
`layered_ite`, `layered_seq_acyclic`.

This is the THIRD migration of `IsLayer` — 248 relativised it to a domain, 254
generalised its shape, 256 split syntax from semantics — and each was forced by
the next constructor rather than chosen.  All three landed whole, never
half-migrated.

    layered_test / act / wh / sum / ite   PROVED
    layered_seq  acyclic case             PROVED
    layered_seq  layer case               unblocked, open
    hsum         assembly                 open

**Odds: 81%, held.**  Plumbing again, and the number moves when `hsum` closes.
But this is the first time the definition has no known obstruction ahead of it:
255's mismatch was the last identified reason `layered_seq` could not close.

**Next.**  `layered_seq`'s layer case, which should now go through:
`post` = the right half's entry block at guards `L'.hlt s ∧ g`, `post'` = the
same at `(L'.hlt s ∧ ¬b) ∧ g`, and `RestrictedTo` holds because both sides
compute `hlt && !b && g`.

---

## 257 — `seq_isLayer_left` PROVED.  The case blocked since 251 is closed.

Two further migrations were needed, both found by attempting the case rather
than by inspection, and both landed whole:

  * **`hlt_eq` had to go semantic too.**  In a sequence `sys.hlt (inl s)` is
    `(L'.hlt s ∧ ¬b) ∧ R.initHlt` while the field demanded
    `(L'.hlt s ∧ R.initHlt) ∧ ¬b` — 255's associativity mismatch again, in the
    halt component this time.  256 had fixed it only for the transition guards.
  * **Two `RestrictedTo` combinators**: `.append`, and `.of_map` for two maps
    over the SAME list with pointwise-related guards — which is exactly how a
    sequence's trailing entry block relates across a layer.

**`seq_isLayer_left`** then goes through.  The proof says what 252 diagnosed:
a `seq` layer does two things at once, and the shape now expresses both —
`pre` and `extra` from the layer, `post` = the left half's remaining transitions
FOLLOWED BY the right half's entry block, `post'` = the same with `¬b` conjoined.
`RestrictedTo.map` handles the first part, `RestrictedTo.of_map` the second,
`RestrictedTo.append` joins them.

**Zero errors, no `sorryAx`, ten theorems proved.**

    layered_test / act / wh / sum / ite    PROVED
    layered_seq  acyclic case              PROVED  (251)
    seq_isLayer_left                       PROVED  (257)
    layered_seq  assembled                 open — mechanical now
    hsum                                   open

**What is left of `hsum` is assembly.**  `layered_seq` needs the induction on
the two `Layered` derivations, exactly as `layered_sum` at 250: acyclic/acyclic
is `layered_seq_acyclic`, a layer on the left is `seq_isLayer_left`, and a layer
on the right needs its mirror — which is simpler, since `seqGSystem`'s right
half is untouched by the construction (241's `seq_inr_closed`).

**Odds: 82%, up 1.**  The `seq` layer case is the obstacle that consumed 251
through 256 — six iterations of definition work, three `IsLayer` migrations —
and it is now proved.  Every remaining step of `hsum` has a worked precedent:
`layered_sum` is the template for the assembly, and the right-hand mirror is
easier than the left.  Not more than +1 because `hsum` still is not closed and
`hcollapse`/`hsolve` remain untouched.

**Next.**  `seq_isLayer_right`, then `layered_seq`, then `hsum`.

---

## 258 — **`hsum` IS PROVED.**  One of 239's three obligations is closed.

`thompson_layered : ∀ e, Layered (certifiedThompson A T e).aut.core` — every
Thompson automaton carries the certificate, by induction on the expression, no
`sorry` and no axioms beyond `propext`/`Quot.sound`.

    test, act   no transitions at all                          247
    ite         layered_ite via layered_sum                    250
    wh          Layered.layer applied to a fact `rfl` since 220 247
    seq         layered_seq                                    258

**What closed the `seq` case.**  `seq_isLayer_right` — simpler than the left, as
241 predicted: `seqGSystem` touches the right half not at all, so the layer
passes straight through and the whole left half is discharged by `outside`.
Then `layered_seq` by induction on both derivations, the `layered_sum` template.

**And a fourth `IsLayer` migration, forced like the other three.**  The induction
needs `InitTargetsListed` to survive passage to the base, which requires knowing
a layer does not change the STATE LIST.  True of every construction —
`loopInitialized` keeps the body's list verbatim — but not recorded, so
`states_eq` was added and threaded through all four lifting lemmas.  Four
migrations (248 domain, 254 shape, 256 syntax/semantics, 258 states), every one
discovered by attempting the next case rather than by inspection, every one
landed whole.

**Where the whole thing stands.**

    hsum        every Thompson automaton carries the certificate   PROVED
    hcollapse   the certificate survives a minimal quotient        measured 100%
                (13 126/13 126 at NA=2 and NA=3, iteration 237)    unproved
    hsolve      the certificate implies a solution exists          unproved
                (Grabmayer's "every prechart with LLEE admits a
                 solution", in the neighbouring setting)

    sumQuotientSolvable_of_certificate  chains the three           PROVED (239)
    completeness_of_sumQuotientSolvable carries it to completeness PROVED (repo)

**Odds: 84%, up 2.**  The first of the three obligations is closed outright, and
it is the one that ran through thirty iterations of certificate-hunting
(228-257) — five formulations, two soundness breaks, four definition migrations.
It is now a theorem.  Not more than +2 because the two remaining obligations are
untouched by this proof and `hsolve` in particular is the one Grabmayer proves
by a different route than anything here.

**Next.**  `hcollapse`: the certificate survives passage to a minimal
behavioural quotient.  237 measured it at 100% and 223 measured the underlying
property at 131 714/131 714, and 243 established GKAT sits on the favourable
side of the proper-step/empty-step divide — so the target is right; the proof is
open.

---

## 259 — THE METHOD FOR `hcollapse`, NAMED FROM THE SOURCE.

258 closed `hsum`.  The next obligation is `hcollapse`: the certificate survives
passage to a minimal behavioural quotient.  Before attempting it, the literature
says how it is done — and it is not what I would have tried.

> "The class of finite LLEE-precharts is closed under arbitrary homomorphic
> images, with the main tool being the **connect-through-to** operation, which
> preserves bisimilarity while identifying bisimilar states."

**So `hcollapse` is proved ONE BISIMILAR PAIR AT A TIME**, each identification
preserving the certificate, then iterated — not by transporting a `Layered`
derivation across the whole quotient at once.

**That matters because the wholesale transport does not obviously work**, and it
is worth writing down why before it is attempted a third time.  Given
`IsLayer sys base b dom` and a quotient map `π` for `sys`, the natural move is to
quotient `base` by the SAME partition.  But `π` identifies states bisimilar in
`sys`, and `base` is `sys` MINUS its back edges — those states need not be
bisimilar in `base`, so the induced map need not be well defined on `base` at
all.  A single-pair operation sidesteps this: it never asks `base` to accept
`sys`'s partition wholesale.

**Also confirmed, and it is the stronger statement:** closure holds under
ARBITRARY homomorphic images, not merely the minimal collapse.  That is more
than `hcollapse` needs — 227 had to restrict `QuotientClosure` to minimal
quotients after measuring 4 failures at NA=4, and those were failures of MY
CALCULUS on non-minimal quotients, not of the certificate.  The certificate
formulation should not need the minimality hypothesis at all.

**Where this leaves the three obligations:**

    hsum        PROVED                                              258
    hcollapse   method identified (connect-through-to, pairwise);
                measured 100% at 237; unproved
    hsolve      unproved; Grabmayer's "every prechart with LLEE
                admits a solution"

**Odds: 84%, held.**  A method identified is not a proof, and the literature
precedent was already priced in at 224.  What is new is narrower: the SHAPE of
the induction, which is pairwise rather than global, and the observation that
the certificate version of closure should not need 227's minimality restriction.

**Next.**  Define the single-pair identification and prove it preserves
`Layered` — the acyclic case first, where the proper-step argument does the work
(a cycle in the image lifts to an infinite path upstairs, contradicting the
rank).

---

## 260 — THE CERTIFICATE SURVIVES ARBITRARY QUOTIENTS.  0 in 41 716.

259 read from Grabmayer that LLEE-precharts are closed under ARBITRARY
homomorphic images — stronger than the minimal-collapse closure `hcollapse`
needs.  Tested in this setting: take Thompson automata carrying the certificate
(`thompson_layered`, proved at 258), quotient by EVERY behavioural congruence in
the lattice, and check the certificate survives each.

    NA=2   3928 certified automata   16 853 quotients (14 363 non-minimal)   LOST 0
    NA=3   3928                      13 229          (10 930 non-minimal)   LOST 0
    NA=4   3928                      11 634          ( 9 461 non-minimal)   LOST 0

**Zero losses in 41 716 quotients, 34 754 of them NON-minimal.**

**This explains 227 retroactively.**  That iteration measured 4 failures at NA=4
and added a minimality hypothesis to `QuotientClosure`, correctly, because the
property being measured was "the six-rule CALCULUS solves it".  The certificate
is a different object and does not need the restriction — the minimality
hypothesis was compensating for the calculus, exactly as 259 suspected.

**What it does NOT change, and this is worth being precise about.**  In 239's
architecture `hcollapse` is a HYPOTHESIS of
`sumQuotientSolvable_of_certificate`.  Dropping minimality from it would make
that hypothesis STRONGER — harder to discharge, not easier.  So the Lean
statement stays as it is, and what this measurement buys is MARGIN: the
obligation as stated is weaker than what appears to be true, so a proof has room
to be less careful than the statement allows.  `hstart` supplies the full
collapse, which is minimal, so nothing downstream needs adjusting either.

**Odds: 84%, held.**  A confirmation, on a population 41 716 wide, of a claim
already read from the literature at 259 and already priced in at 224.  Margin is
not progress.  What would move the number is `hcollapse` proved, not measured
again.

**Next.**  The single-pair identification in Lean, acyclic case first: a cycle in
the image lifts to an infinite path upstairs, contradicting the rank — the
proper-step argument 243 showed GKAT is on the right side of.

---

## 261 — `hcollapse`'s ACYCLIC CASE: the argument is clean, the definition needs a fifth migration.

Working the acyclic case of `hcollapse` — a homomorphic image of an acyclic
automaton is acyclic — gives a clean argument and one obstacle.

**The argument.**  Define `rank' q` as the MINIMUM rank over `q`'s preimages;
`Nat.find` supplies it in core Lean, with `Nat.find_spec` giving a preimage that
ACHIEVES the minimum and `Nat.find_min'` giving minimality.  Then for `q → q'`
in the quotient, take the minimising preimage `s` of `q`: the bisimulation gives
`t` with `s → t` and `π t = q'`, so

    rank' q' ≤ rank t < rank s = rank' q

That is the whole proof, and it needs no finiteness machinery — `Nat.find`
replaces the "minimum over a finite set" that a first attempt would reach for.

**The obstacle.**  `Layered.acyclic` quantifies its rank condition over ALL
states.  For a quotient state with NO preimage — possible, since
`UniformBehavioralGAutQuotient`'s `onto_states` covers only LISTED states —
`rank'` has nothing to be defined from, and nothing constrains that state's
transitions.  So the certificate has to say what is actually true of these
automata: `CoreTargetsListed` keeps every transition among listed states, so the
condition belongs over `sys.states`, not over `S`.

**Attempted and reverted.**  The restriction ripples into four proofs —
`layered_act`, `layered_sum`'s acyclic case, `layered_seq_acyclic`, and
`layered_seq`'s use of the two rank hypotheses — and needs membership-extraction
lemmas (`inl x ∈ sumGSystem.states → x ∈ L.states` and the `seq` analogue) that
do not exist yet.  Reverted to green rather than committed half-done, per 253.

**This would be the fifth `IsLayer`/`Layered` migration**, and like the other
four it is forced by the next thing attempted rather than chosen: 248 domain,
254 shape, 256 syntax/semantics, 258 states, and now 261 listed-states.  The
pattern is consistent enough to expect one more when `hsolve` is attempted.

**Odds: 84%, held.**  The acyclic case has a complete argument on paper and a
known, bounded obstacle; that is progress in understanding, not in proof.

**Next.**  The membership-extraction lemmas, then the listed-states migration in
one pass, then `hcollapse`'s acyclic case.

---

## 262 — THE FIFTH MIGRATION LANDED.  And a sixth mismatch, named.

**Landed:** `Layered.acyclic` now quantifies over LISTED states, with four
membership-extraction lemmas (`sum_states_inl/inr`, `seq_states_inl/inr`) and
all four dependent proofs updated in one pass.  Zero errors, no `sorryAx`,
`thompson_layered` still proved.  That is the fifth migration in the series and
the first one that did not need a revert.

**And attempting `hcollapse`'s acyclic case immediately finds the sixth
mismatch.**  `GAutBisim` — the repo's bisimulation, and what
`UniformBehavioralGAutQuotient.bisim_graph` provides — is stated via `autStep`,
the FIRST-MATCHING transition at an atom.  `Layered.acyclic` quantifies over
EVERY ENTRY of the transition list.  A list entry whose guard is shadowed by an
earlier entry never fires, so it cannot be lifted through the bisimulation — yet
the rank condition still demands it decrease.  The two notions of "edge" do not
line up.

**Two ways out, and the choice matters.**

  * **(a) Make `acyclic` a condition on `autStep` edges**, which is the
    semantically right notion — a shadowed transition cannot contribute to a
    cycle because it never fires.  This is a sixth migration and a heavier one:
    `layered_sum` and `layered_seq_acyclic` currently reason by list membership
    and would have to reason about `firstMatch` instead.
  * **(b) Prove the two coincide for these automata**, via an invariant that a
    Thompson state's transition guards are MUTUALLY DISJOINT — plausible, since
    the construction is deterministic — but `CoreStructural` records only
    `CoreTargetsListed` and `CoreHaltDisjoint`, not mutual disjointness of the
    transition guards themselves.  So it would need proving through all five
    constructors.

**(a) is more honest and (b) is less work, which is exactly the trade that
produced 253's rule.**  Not choosing under time pressure; the choice wants the
same treatment 252-256 got — work one case of each far enough to see which
breaks.

**Odds: 84%, held.**  A migration landed and an obstacle named.  Six mismatches
now, every one found by attempting the next case rather than by inspection, which
is the process working — but `hcollapse` is not closer to proved than it was two
iterations ago, only better understood.

**Next.**  Decide (a) vs (b) by attempting `layered_sum`'s acyclic case under (a)
and the disjointness invariant under (b) for one constructor each.

---

## 263 — ROUTE (a) CHOSEN AND LANDED.  `acyclic` now speaks the bisimulation's language.

262 left a choice: (a) restate `acyclic` on `autStep`/`firstMatch` edges, or
(b) prove list-membership and first-matching coincide via a mutual-disjointness
invariant.  **Decided by checking what each can reuse**, not by preference:

  * **(b)** needs a new invariant — "a Thompson state's transition guards are
    mutually disjoint" — proved through all five constructors.  It IS true (`ite`
    splits on `g`/`¬g`, `seq` gets it from `InitHaltDisjoint`, `wh` inherits),
    but nothing in the repo records it.
  * **(a)** needs `firstMatch` to commute with `map` and `append` — and
    `GkatKleeneProofs` has ALL of it already: `firstMatch_append_none`,
    `firstMatch_append_some`, `firstMatch_map_target_to`,
    `firstMatch_map_guard_target`.

So (a) is both the more honest notion AND the cheaper one.  Landed.

**The bridge that made it cheap** is `firstMatch_mem_of_some` (sitting in this
file since long before): a first-matching step yields LIST MEMBERSHIP of that
transition.  So the crossing case of `layered_seq_acyclic` — where the step
enters the right half and its target must be shown listed — keeps its old
argument verbatim.  Only the cases that follow a step needed rewriting.

**Zero errors, no `sorryAx`, `thompson_layered` still proved.**  Six migrations
now: 248 domain, 254 shape, 256 syntax/semantics, 258 states, 261/262
listed-states, 263 firstMatch — every one forced by attempting the next case.

**What this unblocks.**  `Layered.acyclic` and `GAutBisim` now speak the same
language, which is what 261's argument needed: define `rank' q` as the minimum
rank over `q`'s preimages via `Nat.find`; for `q → q'` take the minimising
preimage and lift the step through the bisimulation.  The type mismatch that
blocked it is gone.

    hsum       PROVED                                    258
    hcollapse  acyclic case now formalisable             open
               layer case                                open
    hsolve                                               open

**Odds: 85%, up 1.**  A decision made on evidence rather than taste, and the
migration it required landed whole and first-try after the analysis.  The
acyclic case of `hcollapse` has a complete argument AND, now, a statement it can
be written against.  Only +1: it is still unwritten, and the layer case of
`hcollapse` — the pairwise connect-through-to induction — is untouched.

**Next.**  `hcollapse`'s acyclic case, written against the new definition.

---

## 264 — **`hcollapse`'s ACYCLIC CASE IS PROVED.**

`acyclic_quotient` — a behavioural quotient of an acyclic automaton is acyclic.
261's argument, writable at last because 263 made `Layered.acyclic` speak in
`firstMatch` steps, which is exactly what `autStep` is: the certificate and the
bisimulation now quantify over the SAME edges.

**The proof.**  `rank' q` is the least rank among `q`'s listed preimages.  Given
a step `q → r.2`, take a preimage `s` ACHIEVING that minimum and push the step
BACKWARDS through the bisimulation to `s → s'` with `π s' = r.2`; then

    rank' r.2  ≤  rank s'  <  rank s  =  rank' q

`targets` is what places `s'` back in `aut.states` so it counts as a preimage —
Thompson automata supply it from `CoreTargetsListed`.

**`Nat.find` does not exist here**, so the minimum was built directly: `minOf1`
with the two facts the argument needs — it is a LOWER BOUND and it is ACHIEVED —
plus a `minOfList` wrapper.  Four small inductions.  This is the Mathlib-free
constraint costing about twenty lines, which is the usual price in this cluster.

**Where the three obligations stand:**

    hsum       PROVED                                          258
    hcollapse  acyclic case PROVED                             264
               layer case — the pairwise connect-through-to
               induction 259 identified                        open
    hsolve                                                     open

**Odds: 86%, up 1.**  The acyclic case is the base case of `hcollapse` and it is
now a theorem; more to the point, it is the first place the certificate and the
bisimulation have actually been made to interact, which is what six migrations
were for.  Only +1 because the layer case is the substantial half and is
untouched — and because `acyclic_quotient` needed `Classical.choice`, the first
theorem in this chain to do so.

**Next.**  `hcollapse`'s layer case: given `IsLayer sys base b dom` and a
quotient of `sys`, produce a layer over something layered downstairs.  259
established the method is pairwise identification rather than wholesale
transport, and recorded why the wholesale version fails.

---

## 265 — `hcollapse`'s LAYER CASE: the obstruction, located exactly.

**First finding: `UniformBehavioralGAutQuotient` is the wrong notion for a
STRUCTURAL certificate.**  It relates `aut` and `quot` only through
`bisim_graph`; `quot.trans` is otherwise unconstrained.  So there is no way to
say which of `quot`'s transitions are BACK EDGES — and `IsLayer` is a statement
about exactly that.  The repo already has the right notion: **`GAutHom`**, whose

    trans_eq : aut₂.trans (mapState s) = (aut₁.trans s).map (retarget mapState)

makes the image's transition list literally the source's with targets mapped.
Back edges map to back edges, positionally.  And `gAutHom_bisim` derives the
bisimulation from a hom, so nothing in 239's architecture breaks — `hstart` just
has to supply a hom-based quotient, which the canonical collapse is.

**Second finding: `IsLayer` DOES transport, and by an argument that works.**
Given `φ : GAutHom aut₁ aut₂` and `IsLayer sys base b dom`, define `base'` by
CHOOSING a preimage `s` for each image state `q` and setting

    base'.hlt q   := base.hlt s          base'.trans q := (base.trans s).map φ

Then `IsLayer (image) base' b dom'` holds: `sys.trans q = aut₂.trans (φ s) =
(pre ++ extra ++ post').map φ`, which splits as `pre.map φ ++ extra.map φ ++
post'.map φ`; guards are untouched by `φ` (only targets move), so the back-edge
condition survives and `RestrictedTo.map` carries the restriction.  The halt
equation holds for the chosen preimage, which is all `IsLayer` asks.

**Third finding, and it is the obstruction: `Layered base'` does NOT follow from
`Layered base`.**  `base'` is built from CHOSEN preimages, so for a
non-chosen `s'` with `φ s' = q` we have `base'.trans q = (base.trans s).map φ`,
not `(base.trans s').map φ` — the two need not agree, because `s` and `s'` are
bisimilar in `sys` but need not be in `base`.  **So `base'` is not a homomorphic
image of `base`, and the induction hypothesis does not apply to it.**  This is
259's observation, now pinned to the exact place it bites: not in transporting
the layer, which works, but in re-establishing the certificate BELOW the layer.

**That is precisely what connect-through-to is for.**  Identifying one pair at a
time lets the base's structure be repaired at each step, instead of demanding
that `base` accept a partition derived from `sys` wholesale.

**Odds: 86%, held.**  No proof this iteration — but the layer case now has its
obstruction isolated to a single sentence, and two of its three parts are
settled: the right quotient notion is `GAutHom`, and `IsLayer` transports along
it.  Analysis is not progress, and the number should not move for it.

**Next.**  Define connect-through-to — identify ONE bisimilar pair — and prove
it preserves `Layered`, with the layer case repairing `base` rather than
transporting it.

---

## 266 — CONNECT-THROUGH, READ FROM THE SOURCE.  `hcollapse` is much harder than 259 implied.

Extracted the LICS'20 text directly (the PDF was fetchable but binary; `pypdf`
got it) rather than reconstruct — 228-236's lesson.  The definition:

> **Definition 6.1.** "The connect-w₁-through-to-w₂ chart `C(w₁)↠w₂` of `C` is
> obtained by redirecting all incoming transitions at `w₁` over to `w₂`, and, if
> `w₁` is the start vertex of `C`, making `w₂` the new start vertex; in this way
> `w₁` gets unreachable, and it is removed with other unreachable vertices."
>
> **Lemma 6.2.** "If `w₁ ↔ w₂` in `C`, then `C(w₁)↠w₂ ↔ C`."

**And then, immediately after:**

> "While the connect-through operation of bisimilar vertices in a chart thus
> results in a bisimilar chart, **its application to a LLEE-witness does not need
> to yield a LLEE-witness again: the property LEE may be lost.**"

Example 6.3 exhibits the failure.  So closure is NOT "identify a pair, repeat",
which is how 259's one-line summary read.  It needs **Proposition 6.4**: a
bisimilar pair can always be selected in one of THREE mutually exclusive
categories (C1)/(C2)/(C3), each handled by a DIFFERENT transformation I/II/III,
each with its own LOOP-LEVEL ADAPTATION (LI/LII/LIII) applied before or after
the connect-through, plus a final clean-up turning loop-entry transitions back
into body transitions when they no longer induce an infinite path.

**And a problem with my formulation, not just its difficulty.**  Grabmayer's
LLEE-witness is an ENTRY/BODY LABELLING carrying natural-number LOOP LEVELS, and
LI/LII/LIII are operations ON THOSE LEVELS — "replace α by α+m", "turn the body
transitions from ŵ₂ into loop-entry transitions with loop label γ".  **My
`Layered` has no levels.**  It is an inductive elimination — acyclic, or a layer
over something layered — which encodes the elimination ORDER implicitly and
offers nothing to adapt.  Supporting the closure proof would need a seventh
migration, to an explicit level labelling.

**Odds: 84%, DOWN 2.**  Not because the theorem looks less true — 237 and 260
measured the certificate surviving 41 716 quotients without a loss — but because
`hcollapse` is now known to be several pages of case analysis over a
representation I do not have, rather than the induction 259 suggested.  My
estimate has been carrying an assumption that the remaining two obligations were
of comparable size to `hsum`; that assumption is now falsified for one of them,
and honesty requires the number to absorb it rather than the narrative.

**What this does not change.**  `hsum` is proved.  `acyclic_quotient` is proved.
The architecture is machine-checked.  The route is the same route; the distance
along it is longer than stated.

**Next.**  Decide whether to migrate `Layered` to an explicit level labelling —
which is what the closure proof manipulates — or to look for a GKAT-specific
argument that avoids Prop. 6.4's case analysis.  GKAT is proper-step, and 223's
0-in-131 714 suggests its collapse may be better behaved than the general case;
that is worth checking before importing three transformations.

---

## 267 — GKAT MAY NOT NEED PROP. 6.4 AT ALL.  0 losses in 47 584 connect-throughs.

266 read Grabmayer's Def. 6.1 and the warning that follows it: connect-through
on a bisimilar pair yields a bisimilar chart, but "its application to a
LLEE-witness does not need to yield a LLEE-witness again" — hence Prop. 6.4's
three-way selection and three level-adapting transformations.  Before importing
that machinery, measure whether GKAT needs it.

Implemented connect-through exactly as defined — redirect all incoming
transitions at `w1` to `w2`, redirect the initial arrows, garbage-collect `w1` —
and applied it to EVERY bisimilar pair of certified Thompson automata:

    NA=2   18 736 connect-through steps   certificate LOST on 0
    NA=3   15 262                         LOST 0
    NA=4   13 586                         LOST 0

**47 584 steps, zero losses.**  In GKAT, connect-through on ANY bisimilar pair
preserves the certificate — no careful pair selection, no case analysis.

**A hypothesis for why, flagged as a hypothesis.**  266 noted that Example 6.3
lives in LICS'20, which IS the proper-step paper, so being proper-step cannot be
the reason.  But **Milner's charts are NONDETERMINISTIC** — a vertex may carry
several `a`-transitions — while **GKAT automata are DETERMINISTIC**: each
state's behaviour is a decision list over atoms, and `CoreHaltDisjoint` plus the
construction make the outgoing choice a function of the atom.  Bisimilar GKAT
states therefore have identical guard structure, which constrains what
redirection can do far more than in the general case.  If that is the mechanism,
it is DETERMINISM, not proper-step, that makes GKAT's collapse well-behaved —
and Prop. 6.4's care is machinery for a difficulty GKAT does not have.

**This is now the third independent measurement pointing the same way**: 223
(collapse never breaks solvability, 0 in 131 714), 260 (certificate survives
arbitrary quotients, 0 in 41 716), and now 267 (connect-through never loses it,
0 in 47 584).  Different operations, different populations, same answer.

**Odds: 86%, up 2 — restoring 266's drop.**  266 lowered the estimate on the
belief that `hcollapse` requires several pages of case analysis over a
representation I lack.  That belief is now measured false FOR GKAT, on the
operation the case analysis exists to control.  I am not going above 86%:
this is a measurement, the mechanism is a hypothesis, and a proof still has to
be written — but the specific reason for the markdown is gone.

**Next.**  Test the determinism hypothesis directly: construct a
NONDETERMINISTIC chart in Milner's style where connect-through loses the
certificate (Example 6.3's shape), and confirm the GKAT analogue cannot be
built.  If determinism is the mechanism, `hcollapse` should be provable by a
direct argument, and that argument is the next target.

---

## 268 — THE "L" IN LLEE IS MISSING FROM MY CERTIFICATE.

266 raised a representation gap: Grabmayer's LLEE-witness carries natural-number
LOOP LEVELS and the closure transformations operate on them, while my `Layered`
is an inductive elimination with no levels.  I argued the elimination ORDER
induces levels, and tested whether those levels are LAYERED — whether an
earlier-eliminated loop that overlaps a later one is CONTAINED in it.

    NA=2   6570/6570 greedy elimination succeeded   nested 6525  (99.3%)  depth ≤5
    NA=3   6570/6570                                nested 6446  (98.1%)  depth ≤7
    NA=4   6570/6570                                nested 6369  (96.9%)  depth ≤8

**Two findings, and the second is a gap in my own formulation.**

**(1) Greedy elimination succeeds 100%** — first-found loop at each step, no
backtracking.  That is stronger than `llee_L123`, which searches over orders,
and it suggests the search 233/234 built was never needed.

**(2) The induced levels are NOT always nested — and layeredness is a condition
I never encoded.**  "Loops are never mutually nested" is the L in LLEE.  My
`Layered` requires L1/L2/L3 of each layer and permits ANY elimination order,
with no constraint relating the layers to each other.  So **my certificate is
potentially strictly weaker than Grabmayer's**, and the 1-3% of automata whose
greedy decomposition interleaves are where the difference shows.

**Which reading is right is not yet known, and the two differ a lot:**

  * **(a)** A nested order always EXISTS and greedy merely missed it.  Then
    layeredness is free, adding it to `Layered` is safe, and `thompson_layered`
    needs re-proving with nested orders — annoying but bounded.
  * **(b)** Some Thompson automata genuinely admit no nested decomposition.
    Then my `Layered` is weaker than LLEE, and `hsolve` — "the certificate
    implies a solution exists" — may be FALSE for it, since Grabmayer's
    existence proof uses layeredness.

**This also re-reads 267 with more caution.**  That measured connect-through
preserving MY certificate, not LLEE.  If mine is weaker, preservation is a
weaker statement than it appeared, and the determinism hypothesis is less
supported than 267 claimed.

**Odds: 85%, DOWN 1.**  A condition of the source definition turns out to be
absent from my formalisation, discovered only by computing the object it
constrains.  That is the same failure mode as 228-236 — approximating a
definition rather than implementing it — recurring after I thought it was
behind me.

**Next.**  Decide (a) vs (b): for each automaton whose greedy decomposition
interleaves, search all elimination orders for a nested one.  If one always
exists, add layeredness and re-prove; if not, the certificate needs rebuilding
before `hsolve` can be attempted.

---

## 269 — READING (b): LAYEREDNESS IS UNSATISFIABLE HERE.  My certificate is not LLEE.

268 left two readings.  Searched all elimination orders for a nested one:

    NA=2   greedy nested 6525   found by search 45    NO nested order  0
    NA=3   greedy nested 6446   found by search 119   NO nested order  5
    NA=4   greedy nested 6369   found by search 188   NO nested order 13

Search recovers most interleaving cases — but **18 Thompson automata admit NO
nested decomposition at all** under my loop-sub-chart definition.  So reading (b)
holds: **adding layeredness to `Layered` would make `hsum` FALSE**, and `hsum`
is already PROVED for the certificate as it stands.

**What that means, stated carefully.**  Grabmayer's theorem — every chart
interpretation of a star expression has LLEE — is about MILNER charts:
nondeterministic, action-labelled, with a termination sink.  My guarded
translation is not that, and 268/269 now show the difference is REAL rather than
cosmetic: **my layer notion and LLEE's do not coincide, and layeredness is not a
property GKAT's Thompson automata have under my definitions.**

**Two consequences, one bad and one not.**

  * **Bad: Grabmayer's `hsolve` cannot be imported.**  His proof that a
    certificate yields a solution USES layeredness.  Mine has no layeredness to
    use, so that half of the literature route is unavailable — which is the
    piece 224 was most confident about.
  * **Not bad: `hsum` and the collapse measurements stand.**  They were always
    about MY certificate.  `thompson_layered` is proved, `acyclic_quotient` is
    proved, and 223/260/267 measured MY certificate surviving collapse across
    220 000 cases.  None of that depended on the certificate being LLEE.

**And there is a constructive `hsolve` already in hand, unnoticed.**  The
six-rule calculus IS a procedure taking a decomposition to a solution — that is
what `decomp_solves` and the census have been doing all along.  Its cases are the
elimination rules, and it has never once produced a wrong solution.  So `hsolve`
may be provable HERE by the calculus rather than imported from a setting whose
hypotheses GKAT does not satisfy.

**Odds: 85%, held.**  Losing the ability to import `hsolve` is a real cost.
Discovering that a constructive replacement has been sitting in the development
since iteration 206 is a real gain.  They are close enough in size that moving
the number would be pretending to more precision than I have.

**Next.**  `hsolve` via the calculus: `Layered sys → ∃ sol, SolvesBA sys sol`, by
induction on the `Layered` derivation — acyclic gives a fold, a layer gives a
`wh`, which is what rules 1-6 do case by case.

---

## 270 — `hsolve`'s MACHINERY, AND 263's MIGRATION WENT THE WRONG WAY.

269 said `hsolve` must be built here rather than imported.  Started building it,
and the construction immediately corrected an earlier decision.

**Built:** `solFuel` — the solution of an acyclic system computed with a fuel
budget, a state's label being the guarded fold of its transitions over the
labels computed at lower fuel — plus `solFuel_stable`, that once the fuel
exceeds a state's rank the label stops changing, and `guardedFold_trans_congr`,
that two labellings agreeing on targets fold alike.  `solFuel` needs NO axioms.

**And the correction.**  Building a solution folds over EVERY entry of a state's
transition list, including entries whose guard is shadowed — so termination
needs the LIST form of the rank condition.  263 had weakened `acyclic` to the
`firstMatch` form, because 262 found the bisimulation speaks in `autStep`.

**The list form is STRONGER and implies the `firstMatch` form** — every
first-matching transition is a list entry, which is exactly what
`firstMatch_mem_of_some` says, and `acyclic_quotient` already calls that lemma
for its `targets` hypothesis.  So the list form serves BOTH obligations and the
`firstMatch` form serves only one.  **263 chose the weaker of two options
because it was the "semantically right" notion; the right criterion was which
one both consumers can use.**

Reverted `acyclic` to the list form and restored the four proofs.  Green, zero
`sorryAx`, `thompson_layered` and `acyclic_quotient` both still proved —
`acyclic_quotient` needs no change at all, since it takes its rank hypothesis as
its own parameter rather than from `Layered`.

**Seven migrations now** (248, 254, 256, 258, 261/262, 263, 270), and this is
the first that UNDID a previous one rather than extending it.  Worth noting
plainly: 263's write-up called the choice "decided by evidence rather than
taste", and the evidence considered was which route had lemmas available — not
which form the eventual consumers needed.

**Odds: 85%, held.**  Real machinery built for `hsolve`, and a wrong turn
corrected before it cost anything.  Neither moves the estimate.

**Next.**  The acyclic case of `hsolve`: `sol s := solFuel sys (rank s) s`
satisfies `sol s = eqRHS sys sol s`, by `solFuel_stable` at the targets — then
`decomp_solves` gives `SolvesBA`.

---

## 271 — `hsolve`'s ACYCLIC CASE, PROVED WITH NO AXIOMS AT ALL.

    solFuel_solves        sol s = the guarded fold of s's transitions over sol
    acyclic_has_solution  an acyclic system HAS a solution

Reading `sol s := solFuel sys (rank s) s`, each state's label IS the right-hand
side of its own equation.  At rank `0` a state has no transitions and the fold
is its halt test; above `0` the fuel is one more than every target's rank, so
`solFuel_stable` replaces the lower-fuel labels by `sol` itself.

**Both need NO axioms — not `propext`, not `Quot.sound`, nothing.**  And the
equation holds ON THE NOSE rather than up to `EquivBA`, which is stronger than
`decomp_solves` asks for: this is `StateRole.fold`, its easiest case.

**All three obligations now have their base case proved:**

    hsum       PROVED outright                                      258
    hcollapse  acyclic case PROVED (acyclic_quotient)               264
               layer case                                           open
    hsolve     acyclic case PROVED (acyclic_has_solution)           271
               layer case                                           open

**And the two open halves are the same shape**: given `IsLayer sys base b dom`
and something known about `base`, establish it for `sys`.  For `hcollapse` that
is "carries the certificate"; for `hsolve` it is "has a solution", where the
construction is `wh` — which is what rules 1-6 do, case by case, and what
`decomp_solves` assembles.

**Odds: 86%, up 1.**  A third obligation's base case closed, with the cleanest
proof in the development — zero axioms, definitional equality.  Only +1 because
both remaining halves are layer cases, which is where every difficulty in this
program has lived since 218.

**Next.**  `hsolve`'s layer case: from a solution of `base` and
`IsLayer sys base b dom`, build one for `sys`.  The shape is
`sol_sys s = wh b (…) ; sol_base s`, which is `salomaa_solution_exists` plus the
guard bookkeeping rules 5 and 6 already carry.

---

## 272 — `hsolve`'s LAYER CASE: the algebra exists, but only for THOMPSON-shaped layers.

Looked for what the layer case needs before writing it, and found most of it
already proved — with one gap that matters.

**What exists.**  `StateRole.salomaaE` is exactly the shape a layer state wants:

    sol s = seq (wh G BODY) rest      with   eqRHS ≈ ite G (seq BODY (sol s)) rest

and `decomp_solves` consumes it.  More: `loop_subsystem`, `seq_subsystem` and
`sum_subsystem_inl/inr` — all proved in this file — ARE the layer algebra, stated
parametrically over a trailing continuation.  `loop_subsystem` says a loop's
equation reduces to the BODY's equation with the loop itself as the trailing
continuation, which is precisely "solve the base, then append the loop".

**And 218's `loop_standard_eq` says what the layer solution looks like:**
`std_loop s = std_body s ; wh b e` — the loop expression is appended AFTER the
base solution and is THE SAME for every state of the layer.  Not `wh b BODY_s`
per state, which is what I would have written: the back edge does not return to
`s`, it returns to the layer's ENTRY, so the loop is global to the layer.

**The gap.**  Those lemmas are stated for the Thompson CONSTRUCTORS —
`loopInitialized`, `seqGSystem`, `sumGSystem` — not for an abstract `IsLayer`.
`hsolve` has to apply to the QUOTIENT's layers, which are not Thompson-shaped.
So the algebra is proved for the wrong objects, and generalising it to `IsLayer`
is the actual work.

**That said, the shape is now known rather than guessed:**

    sol_sys s := sol_base s ; W     where  W = wh b E,  E the layer's entry
                                    expression, SHARED across the layer

which is what `salomaaE` needs and what `loop_subsystem` proves in the concrete
case.

**Odds: 86%, held.**  Finding that the algebra exists is worth something;
finding it is attached to the concrete constructors rather than to `IsLayer`
cancels it.  No proof, so no movement.

**Next.**  Generalise `loop_subsystem` from `loopInitialized` to `IsLayer` — the
statement is the same, and 246's insight that a layer is a DIFFERENCE between
two automata is what should let the proof go through without the constructor.

---

## 273 — `IsLayer` IS MISSING THE THING THAT MAKES A LAYER A LOOP.

Tried to generalise `loop_subsystem` from `loopInitialized` to abstract
`IsLayer`.  It does not go through, and the reason is a gap in `IsLayer`, not in
the algebra.

**Unfolding both sides.**  With `sys.trans s = pre ++ extra ++ post'` and
`base.trans s = pre ++ post`:

  * **on `¬b`**: the extra edges cannot fire (their guards imply `b`), `post'`
    behaves as `post` (that is what `RestrictedTo` says), and
    `hlt_sys s = hlt_base s`.  The two sides agree.
  * **on `b`**: the layer takes a back edge, `post'` is switched off, and
    `hlt_sys s = 0`.  So the layer's behaviour there must be the loop step.

For that step to be `wh b E` with a **shared** `E` — which 272 established is
the shape, since the back edge returns to the layer's ENTRY rather than to `s` —
the extra edges at each state must factor as

    (base.hlt s ∧ b ∧ gᵢ, aᵢ, tᵢ)     for ONE entry list (gᵢ, aᵢ, tᵢ)
                                       common to the whole layer

**`loopInitialized` does exactly that** — its back edges are
`body.initTrans` guarded by `hlt_body s ∧ b`.  **`IsLayer` does not record it.**
It says only that each state's extra guards imply `b`, which permits every state
to have its OWN unrelated back edges.  That is not a loop; it is an arbitrary
addition of `b`-guarded transitions.

**So `IsLayer` is too weak, and in the one respect that matters for `hsolve`.**
An eighth migration is needed: carry the layer's shared ENTRY LIST, with each
state's extra edges being that list gated by the state's own base-halt.

**Worth noting what this predicts about the other obligations.**  `hsum` and
`hcollapse`'s acyclic case were proved WITHOUT the entry condition, so they
survive strengthening — a stronger `IsLayer` only makes `wh_isLayer` harder to
establish, and `loopInitialized` satisfies the condition definitionally, so that
should be `rfl`-adjacent.  The sum and seq lifting lemmas carry the entry list
through their injections.  So this is a strengthening the existing proofs should
absorb rather than resist.

**Odds: 86%, held.**  A gap found by attempting the proof rather than by
inspection — the eighth time in this series, and the pattern is now completely
consistent: every deficiency in `IsLayer` has surfaced when a consumer needed
something the definition did not promise.  No proof, so no movement.

**Next.**  The eighth migration: add the shared entry list to `IsLayer`, re-prove
`wh_isLayer` and the four lifting lemmas, then `loop_subsystem` for `IsLayer`.

**Grabmayer's definition confirms the shape (web search, this iteration).**  In
LLEE a **loop chart is generated by a SET `U` of loop-entry transitions
departing from ONE vertex `vₛ`** — the entries are a single shared set attached
to a single vertex, not per-state edges; and (W2) requires that no vertex other
than the loop's entry vertex emits an entry transition at the same or higher
level.  The correspondence to GKAT is exact: my `extra` edges are the
composition "state halts × `b` × take an entry transition" — *return to `vₛ`,
then take one of `U`* — so **the shared entry list IS `U`**.  He gets the
condition structurally, because the entry transitions live at `vₛ`; I have to
state it as a hypothesis, because in GKAT the return is fused into each state's
own edge list.  Independent confirmation that the missing condition is the right
one rather than an artifact of my encoding.

---

## 274 — 272's SHAPE WAS WRONG, AND THE RIGHT ONE IS A NORMAL FORM (PROVED).

**The correction.**  272 read 218's `loop_standard_eq` as saying a layer's
solution is `sol_sys s := sol_base s ; W`.  **That is FALSE for a layer sitting
inside a SEQUENCE.**  Take `seq (wh b e) f`.  At a left state `inl s` the true
solution is

    (e-solution at s) ; W ; (f-solution)

whereas `sol_base (inl s) ; W` is `(e-solution at s) ; (f-solution) ; W`.
**`W` is INSERTED where the layer's back edges sit, not APPENDED at the end.**
218's shape is the special case `post = []` — exactly what `wh` gives, which is
what made the misreading invisible.

**What this kills.**  The layer lemma cannot have `loop_subsystem`'s form
("`base`'s equation with a different trailing continuation"), because `post`
sits between the insertion point and the end.  273's plan — generalise
`loop_subsystem` to `IsLayer` — was aiming at a statement that is not true.

**What is true, and is now PROVED: `layer_normal_form`.**

```
EquivBA (eqRHSParam sys sol F s)
        (guardedFold (tb pre sol
                      ++ tb (extra gated by b) sol
                      ++ tb (post gated by ¬b) sol)
                     (paramFallback (sys.hlt s) F))
```

The layer rewrites a state's decision list into `pre`, then `b`-gated back
edges, then `¬b`-gated tail.  **Stated for an ABSTRACT split — no `IsLayer`
field beyond `split`, and no Thompson constructor anywhere.**  This is what 273
was reaching for, in the form that survives `seq`.

**Proved by SELECTION** (`guardedFold_select_congr`, 233): two guarded decision
lists are `EquivBA` as soon as their first-matches agree at every world.  Here
they agree SYNTACTICALLY — gating `extra` by `b` changes no guard's value (its
guards already imply `b`), and gating `post` by `¬b` reproduces `post'` exactly,
which is precisely what `RestrictedTo` says.  No case analysis on the automaton.
Three new private lemmas: `selectFull_append`, `selectFull_gate_implies`,
`selectFull_restricted`.  Axioms: `propext, Classical.choice, Quot.sound` — the
cluster's standard set, **no `sorryAx`**.

**Note the entry condition was NOT needed for this.**  273's shared-entry list
is required to IDENTIFY the `b`-branch across states as one loop `wh b E`; it is
not required to SPLIT the equation.  The eighth migration therefore stands, but
it now comes AFTER a lemma that is already proved without it, rather than being
a prerequisite for one that was mis-stated.

**Odds: 87%** (+1).  A machine-checked lemma on the layer path, and a false
shape removed before it could cost a migration.  The field's prior that the
problem does not close still stands.

**Next.**  Fold the `b`-gated and `¬b`-gated blocks into `ite b (entry fold)
(base's tail)` via `ite_guardedFold_partition`, which turns the normal form into
the loop-shaped statement `hsolve` consumes.

---

## 275 — THE LAYER, IN LOOP FORM (PROVED).

`layer_ite_form`: folding 274's two gated blocks back together under a single
top-level conditional gives the shape `hsolve` actually consumes.

```
EquivBA (eqRHSParam sys sol F s)
        (guardedFold (tb pre sol)
          (ite b (guardedFold (tb extra sol) (paramFallback (sys.hlt s) F))
                 (guardedFold (tb post  sol) (paramFallback (sys.hlt s) F))))
```

In words: **a state of the layer runs its `pre` block, and where `pre` does not
fire it takes the LOOP if the guard holds and behaves like `base` if it does
not.**  This is `loop_subsystem`'s content for an ABSTRACT layer, in the form
274 showed is forced — **the conditional sits at the INSERTION POINT (after
`pre`), not at the end**, which is exactly why the `seq` case broke 272's shape.

**Proof**: 274 plus `ite_guardedFold_partition` run BACKWARDS, with `u1`
(`ite b e e ≈ e`) collapsing the duplicated fallback the partition law
introduces.  One new private bridge, `transitionBranches_gate` (gating guards
commutes with labelling).  **Still no `IsLayer` field beyond `split`, still no
Thompson constructor.**  Axioms `propext, Classical.choice, Quot.sound` — **no
`sorryAx`**; whole file green.

**Independent confirmation of the remainder (web search).**  Pham's thesis is
now indexed with an abstract that states the position exactly: the three loop
axioms of Smolka et al. are derivable from a single axiom, a uniqueness theorem
holds for solutions of Thompson-generated equation systems, and the work
"reduc[es] the remaining work to showing that A SOLUTION EXISTS for the relevant
automaton."  That is `hsolve`, named from the outside.  The architecture 239
built is not idiosyncratic — it is the field's own statement of what is left.

**Odds: 88%** (+1).  Two machine-checked lemmas on the layer path in two
iterations, the second delivering the exact shape the obligation consumes.  The
field's prior that the problem does not close still stands.

**Next.**  Sharpen the two branches: under `b` the fallback is `0` (the layer's
halt is `base.hlt ∧ ¬b`), so the true branch is a pure entry fold; under `¬b`
it is `base`'s own fallback.  Both are `guardedFold_congr_fallback_gated`.  Then
the true branch is where 273's shared-entry list finally earns its keep.

---

## 276 — THE LOOP IS GLOBAL TO THE LAYER (PROVED), AND THE FORM `hsolve` CONSUMES.

Two theorems, both zero-`sorry`.

**`layer_entry_shared`** — what 273's shared-entry condition BUYS, and the whole
reason to want it.  Under `b`, EVERY state of the layer does

    test (base.hlt s) ; E

with **ONE `E` shared by the entire layer**.  The only per-state part is the
halt test; the loop body does not depend on which state fell into it.  That is
the algebraic content of "the back edge returns to the layer's ENTRY rather
than to `s`", and it is what will let a single `wh b E` serve every state.

Proved by `guardedFold_guard_factor` (parametric guard factoring, 1341): the
per-state halt conjoined onto every back edge factors out as a test prefix,
leaving a fold that mentions `s` NOWHERE.  The layer's halt semantics
(`base.hlt ∧ ¬b`) is exactly what makes the fallback factor along with it.
Compiled first try.  **Axioms: `propext` ALONE.**

**`layer_loop_form`** — 275 and the above, composed:

    pre , then  IF b THEN (test (base.hlt s) ; E) ELSE (base's own tail)

Every trace of the layer's identity is now confined to two places: the halt
test `base.hlt s`, and `base`'s tail.  `E` is the same expression at every
state.  `GuardImplies` for the back edges is now DERIVED from the entry shape
rather than assumed.  Axioms `propext, Classical.choice, Quot.sound`.

**This is the statement 272 was reaching for and mis-stated, 273 identified the
missing hypothesis for, 274 and 275 proved the split of, and that the shared
entry list finally pays for.**  Four iterations, one theorem, no retraction
outstanding.

**Odds: 89%** (+1).  The layer path now has four machine-checked lemmas and the
target shape in hand; what remains on `hsolve` is the FIXPOINT step — turning
`sol s ≈ pre-fold(ite b (halt ; E) tail)` into an actual `sol` via `wh`.  The
field's prior that the problem does not close still stands.

**Next.**  The fixpoint.  With the layer's equation in loop form, `sol_sys` is
built from `sol_base` at the finish `wh b E`-and-continue, which is what
`ParametricCanonicalBA` is stated to consume — and `W3` restricted to one
unknown is exactly the axiom that closes it.  Check whether the eighth
migration (folding `entry` into `IsLayer`) is still needed, or whether taking
the entry list as a hypothesis at the point of use suffices.

---

## 277 — `loop_subsystem` FOR AN ABSTRACT LAYER (PROVED).  AND THE CONSTRAINT IT COMES WITH.

**The theorem.**  273 wanted `loop_subsystem` generalised from `loopInitialized`
to an abstract layer.  274 showed the generalisation is FALSE in general.  What
274 did not say, and what is true, is that **the obstruction is EXACTLY
`post ≠ []`**:

```
layer_subsystem :
  sys.trans s = base.trans s ++ entry.map (fun tr => (base.hlt s ∧ b ∧ tr.1, tr.2))
  →  sys.hlt s ≈ base.hlt s ∧ ¬b
  →  EquivBA (eqRHSParam sys sol F s) (eqRHSParam base sol E s)
```

with `E` the shared entry fold.  **No algebra left to do**: with `post = []` the
insertion point IS the end, and 276's shared-`E` lemma turns the whole back-edge
block into `test (base.hlt s) ; E`, which is LITERALLY `paramFallback
(base.hlt s) E`.  The proof is `guardedFold_append` then 276.  Compiled first
try; **axioms `propext` ALONE**.

**Sanity check that it really generalises.**  `loop_subsystem_of_layer` derives
the `loopInitialized` case from it — and **both hypotheses discharge by `rfl`**.
The abstract statement covers the concrete one definitionally.  `propext` alone.

**The constraint, stated honestly.**  `wh_isLayer` already has `post = []`
(`CoreHaltDisjoint` keeps the back edges from colliding — 246's observation).
`post` becomes nonempty only when a layer is LIFTED THROUGH A `seq`.  Proof that
no `G` rescues that case: base's `post` guards are not disjoint from `b` (in
`seq (wh b e) f` at `inl s`, `post` is `f`'s entry block gated by `e`'s halt,
which fires under `b`), so on `b` the base equation runs `post` while the layer
skips it — no choice of finish can repair a difference that is not at the end.

⇒ **`hsolve` cannot strip an abstract layer off an arbitrary automaton.**  The
recursion must follow the CONSTRUCTION: peel the `seq` first (`seq_subsystem`,
already proved, 1370) and apply `layer_subsystem` to the left component, where
`post` is empty again.  **This is a real constraint on `Layered`** — a NINTH
migration, splitting `Layered.layer` into a `post = []` loop constructor plus
explicit `sum`/`seq` LIFTING constructors.  Note this makes `layered_sum` and
`layered_seq` (250, 258) SIMPLER, not harder: they become the constructors
themselves rather than theorems pushing a layer through.

**Confirmation from LLEE (web search).**  Grabmayer's loop-subchart elimination
"involves removing all loop-entry transitions of that subchart AND THEN REMOVING
ALL VERTICES AND TRANSITIONS THAT BECOME UNREACHABLE" — the unreachability sweep
is the analogue of the `post = []` requirement, and "LLEE is satisfied when
loop-entry transitions are never removed from the body of a previously
eliminated loop sub-chart" is the ordering my nested `Layered` already encodes.

**Odds: 90%** (+1).  `loop_subsystem` generalised and machine-checked with the
concrete case falling out by `rfl`, against a genuine constraint on the
induction — but one that comes with its fix already proved.  The field's prior
that the problem does not close still stands.

**Next.**  The ninth migration: restructure `Layered` as acyclic / `post = []`
loop / `sum`-lift / `seq`-lift, re-prove `thompson_layered` (all four cases are
now constructors or existing lemmas), and then `hsolve` by recursion on it with
`layer_subsystem` at the loop constructor and `seq_subsystem`/`sum_subsystem` at
the lifts.

---

## 278 — THE NINTH MIGRATION IS CANCELLED, THE REMAINDER IS ONE OBLIGATION, AND THE LITERATURE SAYS IT IS TRUE.

**The ninth migration is cancelled.**  Before restructuring `Layered` to follow
the construction (277's conclusion), I checked what the repository already gives
for construction-shaped automata.  It gives everything: `certifiedThompson`
carries `standard`, its certificate carries `standardSolves :
ParamSolvesBA aut.core standard (.test .one)`, and
`StandardSolvesBA.withContinuation` lifts that to EVERY finish.  Verified by
`thompson_has_solution`, a two-line theorem, now in the file.

**So a `Layered` restructured to follow the construction would prove nothing
new** — it would re-derive by recursion exactly what the certificate already
hands over.  277's plan is dropped before it cost an iteration.

**The remainder is ONE obligation, not two.**  `hsolve` was never needed for
Thompson automata; it was only ever needed for the QUOTIENT.

    hsum       every Thompson automaton carries the certificate    PROVED
    hcollapse  the certificate survives the quotient               OPEN
    hsolve     free for Thompson (278); needed only for the quotient

`hsolve` and `hcollapse` are not independent.  They are one statement:
**produce a solution for the minimal behavioural quotient.**  Every layer lemma
274-277 proved is a tool for that single statement, and `Layered` matters only
insofar as THE QUOTIENT satisfies it.

**And the literature says the quotient statement is TRUE.**  From this
iteration's search, on LEE/LLEE:

> **"LLEE is preserved along functional bisimilarity, and consequently, also by
> the operation of bisimulation collapse."**

That is `hcollapse`, as a theorem, in the published record — together with the
proof technique: **do not prove preservation under the minimal quotient
directly; prove it along an arbitrary FUNCTIONAL BISIMILARITY, and take the
collapse as the special case.**  A surjective homomorphism is easier to induct
over than a minimality condition, because pushing a layer FORWARD along a map
has none of the `post` trouble that pushing a solution BACKWARD had (277).

**The caveat, stated.**  269 established my certificate is NOT LLEE — 18
Thompson automata admit no nested decomposition — so the result does not
transfer as a citation.  What transfers is (a) evidence that a
structure-of-this-kind IS preserved by collapse rather than destroyed by it, and
(b) the generalisation that makes the induction go.

**Odds: 91%** (+1).  A planned migration cancelled before it was paid for, the
remainder collapsed from two obligations to one, and independent evidence that
the one obligation is true with a known technique.  The field's prior that the
problem does not close still stands.

**Next.**  State and attack `Layered`-preservation along a FUNCTIONAL
BISIMULATION (a surjective `GAutHom`), rather than along the minimal quotient.
`acyclic` should push forward if the map is rank-compatible; the layer case is
where 265 located the obstruction, and the forward direction is the one that
avoids 277's `post` problem.

---

## 279 — THE BASE IS DETERMINED ALONG A HOMOMORPHISM (PROVED), AND A CORRECTION TO 278.

**Two theorems.**

`LoopLayer sys base b entry` — 277's `post = []` layer as a named structure:
`sys.trans s = base.trans s ++ entry.map (base.hlt s ∧ b ∧ ·)`, halts
`base.hlt ∧ ¬b`, same state list.  `wh_loopLayer`: `wh b e`'s automaton is one,
over `e`'s, with `e`'s own initial transitions as the shared entry list — all
three fields `rfl` or 220.

`loopLayer_fiber_agree` — **the base is DETERMINED by its image.**  If two
states have the same retargeted transition list, so do their bases, and their
base halts are EQUAL SYNTACTICALLY.

**Why this is the pushforward's missing piece.**  Pushing a layer forward along
`f : S → S'` means building `base'` from `base`, which needs `base` determined
by its image or `base'` is not well defined.  **For the general `IsLayer` this
FAILS** — the split is existential, so two states with the same image may split
their (equal) images differently and nothing forces the same cut.  **That is why
265 found the layer case blocked.**  For `post = []` it SUCCEEDS: the back-edge
block has the SAME LENGTH at every state (it is the shared `entry`, gated), so
the cut point is forced and `List.append_inj'` recovers the base transitions;
the base halt comes back from the head of the block, whose guard is
syntactically `base.hlt s ∧ b ∧ g₀`.  A layer with no entries is not a loop.

**So the `post = []` restriction, forced on `hsolve` by 277, is exactly what
makes `hcollapse`'s pushforward well defined.**  The two obligations 278 merged
into one want the same hypothesis.  Axioms: `propext` alone for both.

**CORRECTION TO 278.**  278 quoted "LLEE is preserved along functional
bisimilarity, and consequently by bisimulation collapse" as evidence the
remaining obligation is true.  This iteration's search shows that is the
**1-FREE** case.  Grabmayer–Fokkink explicitly record that **process graphs with
EMPTY-STEP transitions satisfying LLEE are NOT closed under bisimulation
collapse**, and circumnavigate it with a LLEE-preserving CRYSTALLIZATION
procedure yielding "near-collapsed" graphs whose SCCs are collapsed or of
"twin-crystal" shape.  GKAT's halting/tests are the analogue of empty steps, so
278's evidence is weaker than I stated: the good case is 1-free, and mine is not.

**What survives the correction, and is worth more than the quote was.**  The
technique: their collapse result is proved **by a STEP-WISE construction of the
bisimulation collapse** — one identification at a time, not the whole quotient
at once.  That is directly actionable, and it is exactly the shape of 265's
pairwise connect-through-to induction.  And the empirical position is unchanged
and is about MY structure, not LLEE: the certificate survived arbitrary
quotients 0/41 716, connect-through never lost it 0/47 584, collapse never broke
solvability 0/131 714.

**Odds: 91%, HELD.**  Two machine-checked lemmas resolving exactly why 265 was
blocked, against a genuine weakening of 278's cited evidence.  The field's prior
that the problem does not close still stands — and this iteration is a reminder
of why it stands: the nearest published analogue of my obligation is FALSE in
the setting nearest mine, and needed a new construction to repair.

**Next.**  Build the pushforward on `LoopLayer` using `loopLayer_fiber_agree`:
given a surjective structural hom `f : sys → sys'`, construct `base'` via a
section and show `LoopLayer sys' base' b (entry.map f)`.  Then attempt it
STEP-WISE — one merged pair at a time — rather than for an arbitrary quotient.

---

## 280 — THE PUSHFORWARD (PROVED).  `hcollapse`'s LAYER CASE, AT FULL GENERALITY.

`loopLayer_pushforward`: **a loop layer pushes forward along an arbitrary
SURJECTIVE STRUCTURAL HOMOMORPHISM**, with the same guard and the image of the
entry list.  The base downstairs is built by `pushBase` — choose a section of
the surjection and transport the base upstairs through it — and 279 is exactly
what says the choice of representative does not matter.  Axioms
`propext, Classical.choice`; the choice is the section and nothing else.

**This is the generality 278's search pointed at**: not a minimal quotient, an
arbitrary surjective structural hom.  The minimal quotient is one instance; a
SINGLE MERGED PAIR — the step-wise construction Grabmayer–Fokkink use, 279 — is
another, and it comes for free from the same theorem.

**265's blockage is now resolved, not worked around.**  265 located the
obstruction; 279 named it (the existential split is not determined by the
image); 280 removes it (with `post = []` it IS determined, so `pushBase` is well
defined).

**Scope, stated honestly.**  `LoopLayer` is TOTAL (every state) and has
`post = []`, so as it stands only a TOP-LEVEL `wh` satisfies it —
`seq (wh b e) f` is not a `LoopLayer` over anything.  The intended route is to
compose with `seq_subsystem`/`sum_subsystem` (both proved), which reduce a
composite's equations to its components', and apply the pushforward where the
loop actually is.  Until that composition is done, the pushforward is a tool of
narrow applicability with a broad statement.

**The other open gap, named.**  The theorem assumes the quotient map is a
STRUCTURAL hom — transition lists map exactly, same order, same guards.  A
behavioural quotient need not be.  This iteration's search gives partial
support: "every stutter-insensitive bisimulation on any deterministic labelled
transition system admits a deterministic quotient", and GKAT automata are
deterministic per atom.  It also gives the general warning, which is the field's
prior in one sentence: **"the factorization (collapse) of infinite transition
graphs with respect to bisimulation equivalence shows that almost none of the
more complex classes of the process taxonomy are preserved by this operation."**

**Odds: 92%** (+1).  The layer case of `hcollapse` machine-checked at a
generality that also delivers the step-wise construction, against a scope
caveat that is real and now written down.  The field's prior that the problem
does not close still stands.

**Next.**  Compose: `seq_subsystem`/`sum_subsystem` to reduce a composite to its
components, so the pushforward applies where the loop is; and check whether a
behavioural quotient of a GKAT automaton is a structural hom in the list
representation, or only up to guard equivalence.

---

## 281–282 — BOTH OF 280'S SCOPE GAPS, CLOSED.

280 proved `hcollapse`'s layer case and named two gaps that limited it.  Both
are now closed, machine-checked.

### 281 — the STRUCTURAL-HOM assumption dissolves.

280 assumed the quotient map is a structural homomorphism — lists map exactly,
same order, same guards.  A BEHAVIOURAL quotient need not be: two bisimilar
states can carry syntactically different guarded decision lists inducing the
same first-match behaviour.  This was the gap most likely to sink the route.

It dissolves on re-reading 280's proof: **the proof only ever touches
REPRESENTATIVES.**  Every use of the hypotheses is at
`Classical.choose (hsurj s')`, never at an arbitrary fibre member.  So the
hypothesis weakens to

    sys'.trans s' = (sys.trans (rep s')).map (retarget f)
    sys'.hlt   s' =  sys.hlt   (rep s')

— "the quotient's dynamics at each class is a REPRESENTATIVE's, retargeted" —
which a behavioural quotient satisfies BY CONSTRUCTION, since that is how one
builds it.  `loopLayer_pushforward_rep`, `propext + Classical.choice`.  `entry`
need not even be nonempty any more: 279's fibre lemma was what wanted a head to
read the base halt off, and this route does not use it.

### 282 — a loop NESTED in a sequence, peeled.

280's other gap: `LoopLayer` is total with `post = []`, so only a TOP-LEVEL `wh`
satisfies it.  277 named the fix — peel the sequence first, apply the layer
lemma to the left component where `post` is empty again — and here it is
carried out.  `seq_subsystem` reduces a left state's equation in `seq L R` to
`L`'s own equation at the finish "R's initial dispatch"; `layer_subsystem` (277)
then strips the loop off `L`.  **The two compose by transitivity and nothing
else** — the ambient continuation `seq_subsystem` hands down is exactly the
parameter `layer_subsystem` accepts, which is why both were kept parametric from
the start.  `seq_layer_subsystem` and `sum_layer_subsystem`, `propext` alone.

Worth noting what this shows about 277's constraint.  "The recursion must follow
the construction" sounded like a restriction; it is a two-line proof.  The layer
lemmas are not weaker for being applied at the right place — they are applied
there by COMPOSITION, and the composition is the identity on the difficulty.

### What is left, stated plainly.

That the `sys'` of 281 is behaviourally equivalent to `sys` — that `f` is a
bisimulation — is a separate obligation, about the QUOTIENT's correctness rather
than the layer.  This iteration's search says it is the standard coalgebraic
fact: **"a relation is a bisimulation if and only if there exists a G-coalgebra
structure map making canonical projection maps into homomorphisms"**, and
"every coalgebra has a simple quotient given by the cointersection of all
quotient coalgebras."  So the representative construction IS a homomorphism at
the behavioural level — which is the direction 281 needs.

**Odds: 93%** (+1).  Both named scope gaps closed in one turn, machine-checked,
and the residue is a standard coalgebraic fact rather than a new obstruction.
The field's prior that the problem does not close still stands.

**Next.**  Assemble: a `Layered` built on `LoopLayer` (acyclic | loop), its
pushforward by induction combining 264's `acyclic_quotient` with 281, and the
bisimulation obligation for the representative quotient.

---

## 283 — THE JOIN: `hcollapse`'s OUTPUT NOW FEEDS `hsolve`'s INPUT.

Assembling the two halves exposed a mismatch 270 knew about and left standing.

  * `acyclic_quotient` (264) produces the **FIRSTMATCH** rank condition — every
    step the automaton can actually TAKE decreases the rank.  That is the only
    form a bisimulation can supply: bisimilarity compares SELECTIONS, never
    lists.
  * `acyclic_has_solution` (271) consumes the **LIST** condition — every LISTED
    transition decreases.

The list form is strictly stronger: a branch whose guard is covered by earlier
guards never wins a first match, so it may point ANYWHERE without making the
automaton cyclic.  The two halves did not compose, and the gap is real rather
than bureaucratic — after a quotient, dead branches are exactly what one expects
to find.

**The join, proved.**  A dead branch cannot be pruned constructively; deciding
whether a guard is ever reached first is not a computation available here.  (The
literature agrees: this iteration's search finds the analogous "cleaning" rule
in GKAT decision procedures **requires Boolean satisfiability checking** to
eliminate dead branches.  Avoiding the prune was the right call, not a
shortcut.)  It does not need to be pruned.  `solFuel` still builds the right
expression; what fails is `solFuel_stable`, which asked for SYNTACTIC equality
of two fuel levels and gets it only when every listed target is smaller.
Replace it by **EquivBA-stability** (`solFuel_stable_sem`), proved by selection:
two fuel levels agree at every world because at every world only a LIVE branch
is selected, and live branches do decrease.  Dead branches are carried along,
differing syntactically and observed by nothing.

That is 233's `guardedFold_select_congr` doing exactly the work it was built for
— a guarded fold is compared by what it SELECTS, never by what it LISTS — and it
turns the weaker hypothesis into the same conclusion.

`acyclic_has_solution_sem`: **`hsolve`'s acyclic case, from the hypothesis
`hcollapse` actually supplies.**  Plus `firstMatch_none_of_rank_zero`,
`solFuel_none`, `solFuel_congr_step`.  All zero-`sorry`; whole file green.

**Odds: 94%** (+1).  The acyclic half of the remainder now composes end to end —
quotient in, solution out — with no hypothesis mismatch left between the two
theorems.  The field's prior that the problem does not close still stands.

**Next.**  The same join for the LAYER half: `LayeredL` (acyclic | `LoopLayer`)
with the firstMatch form in the acyclic constructor, its pushforward by
induction (264 + 281), and solvability by recursion (283 + 277/282).

---

## 284–285 — `hsolve` IS CLOSED.  AND IT NEEDS W1, NOT W3.

### 284 — the layer case.

Given a loop layer over a base with a standard solution `std`, put

    D   := the ENTRY DISPATCH, `guardedFold (transitionBranches entry std) 0`
    W   := `wh b D`
    sol := `fun s => std s ; W`

and `sol` solves `sys`.  Three steps: `layer_subsystem` (277) turns `sys`'s
equation at `s` into `base`'s equation at the finish `E`; `E ≈ W` by gating
(`ite_guardedFold_partition`), by distributing the trailing `W` out of the entry
fold (`entryFold_seq`, new, proved by selection), and then by **W1**;
`StandardSolvesBA.withContinuation` closes it, since `base`'s standard solution
times any finish solves `base` at that finish and here the finish is `W`.

**Only W1 is used, and this is the point of the whole programme.**  W3 — the
Salomaa rule, the one restricted to a single unknown — is a UNIQUENESS
principle, and uniqueness is what the certificate already supplies.  EXISTENCE
needs only that a loop UNFOLDS.  `W` is not FOUND by solving a fixpoint
equation; it is BUILT and then checked, and the knot ties itself.

This iteration's search confirms the reading from the source: Salomaa's rule
"assert[s] that if the regular language `a` does not contain the empty word then
`a*b` is **the UNIQUE solution** of the fixed point equation `x = ax + b`".
Uniqueness is what the rule buys; that `a*b` IS a solution is unfolding.

### 285 — the induction closes.

`LayeredL` := acyclic (in the FIRSTMATCH form 283 taught it to accept) | loop
(`LoopLayer` over a `LayeredL` base).  `layeredL_has_solution`: **every layered
automaton has a solution.**

Note the shape that makes the recursion work: `loopLayer_has_solution` consumes
a solution of `base` at finish `1` and produces a solution of `sys` at finish
`1`.  Input and output are the SAME predicate, so no separate parametric
invariant is needed — `withContinuation` supplies the parametricity internally,
exactly where it is used.

**Status of the three obligations.**

    hsum       every Thompson automaton carries the certificate    PROVED
    hcollapse  layer case (pushforward)                            PROVED (280/281)
               acyclic case                                        PROVED (264)
               assembling the induction                            OPEN
    hsolve     acyclic                                             PROVED (283)
               layer                                               PROVED (284)
               ASSEMBLED                                           PROVED (285)

**What is honestly still open.**  `hsolve` is closed FOR `LayeredL`.  Whether
the QUOTIENT is `LayeredL` is the remaining question, and `LayeredL` as defined
has no `sum`/`seq` constructors — so even a Thompson automaton is not `LayeredL`
unless it is a top-level loop over a layered base.  278 argued lifting
constructors prove nothing new FOR THOMPSON AUTOMATA, which is true, but
`layeredL_has_solution` needs them to reach nested loops, and 282 shows the
solution-level composition that discharges them.  That is the next step, and it
is mechanical rather than conceptual.

**Odds: 95%** (+1).  `hsolve` — open in some form since 239, and the layer case
open since 271 — is closed, and closed using only the loop UNFOLDING axiom.  The
field's prior that the problem does not close still stands.

**Next.**  Add `sum`/`seq` constructors to `LayeredL` and discharge them in
`layeredL_has_solution` by 282's composition; then `thompson_layeredL`; then the
`hcollapse` induction.

---

## 286 — `hsum` AND `hsolve` MEET.  THE REMAINDER IS ONE STATEMENT.

`LayeredL` extended with `sum` and `seq` constructors (S is now an INDEX, so
constructors may change the state type), and all four cases of
`layeredL_has_solution` discharged:

  * **acyclic** — 283, in the firstMatch form a bisimulation can supply;
  * **loop** — 284, needing only W1;
  * **sum / seq** — 282's composition, where `seq_subsystem`'s ambient
    continuation is exactly `withContinuation`'s parameter.  One new one-liner,
    `seq_subsystem_inr`, which is `sum_subsystem_inr` DEFINITIONALLY: a
    sequence touches its right half not at all.

`thompson_layeredL` — **`hsum` for `LayeredL`: every Thompson automaton is
layered.**  One constructor per syntactic form; every case definitional or 279.
Compiled first try.  `propext, Quot.sound`.

`thompson_has_solution_via_layers` — the two halves composed.  This re-derives
278's free solvability through the layer predicate, which is the point: it
certifies that **`LayeredL` is satisfiable by the whole language**, not just by
top-level loops, so the predicate is not vacuous where it matters.

### THE REMAINDER, IN ONE STATEMENT

    every Thompson automaton is LayeredL                    PROVED (286)
    every LayeredL automaton has a solution                 PROVED (285)
    ------------------------------------------------------------------
    the QUOTIENT is LayeredL                                OPEN

and its two cases are already proved in isolation:
`loopLayer_pushforward_rep` (281) for the loop, `acyclic_quotient` (264) for the
acyclic.  What is missing is the INDUCTION assembling them — and the `sum`/`seq`
constructors, which a quotient need not respect, are exactly where it will be
hard.

**Confirmation of the technique (web search).**  Grabmayer's collapse result is
proved "directly ... based on its set of **IMAGES** mapped through the
bisimulation function from the LLEE chart, and the constrained relation between
the images and their ... **PRE-IMAGES** on the LLEE chart."  That is
`pushBase` — structure downstairs built from the images, well-definedness from
the fibres — arrived at independently in 279-281.  The same source repeats the
warning: LLEE with EMPTY-STEP transitions is not closed under collapse, unlike
LLEE with only proper steps, and my back edges (`base.hlt s ∧ b`, a halt-then-
loop) are on the empty-step side of that line.

**Odds: 96%** (+1).  Two of the three obligations are now complete theorems, and
the third is a single statement with both its cases proved in isolation.  The
field's prior that the problem does not close still stands, and the empty-step
warning is the specific reason it should.

**Next.**  The induction for "the quotient is `LayeredL`", starting with what a
quotient does to the `sum`/`seq` constructors — the case the literature says is
the hard one.

---

## 287 — WHAT A QUOTIENT DOES TO `sum` AND `seq`, AND THE OPENING IT LEAVES.

286 left one statement open — the quotient is `LayeredL` — and named the
`sum`/`seq` constructors as the hard part.  They are hard for a concrete reason:
**the quotient of a sum is not a sum of quotients.**  In the architecture the
whole POINT of the sum is that the two expressions' start states are bisimilar,
so the collapse merges ACROSS the halves and the `inl`/`inr` partition is
destroyed.

**But it is not destroyed symmetrically, and that is the opening.**  Choose
representatives that PREFER one block.  Then a class containing a member of the
preferred block gets a representative IN that block; so if the block was closed
under transitions upstairs, the classes with a representative in it are closed
downstairs.  **A quotient turns a two-block automaton into a two-block
automaton — one block closed, the other feeding into it — even though it does
not turn a SUM into a sum.**

And that is exactly the structure `sum` and `seq` already have:
`sum_inr_closed` and `seq_inr_closed` (both proved, 247) say the right half is
closed, and nothing else about either constructor is used by
`layeredL_has_solution` beyond the equations that closure justifies.

**Proved this iteration.**  `quotient_closed_block` — the general fact, needing
neither the section property nor minimality, only that the representative choice
prefers the block.  `preferringRep` with `preferringRep_prefers` and
`preferringRep_section` — such a choice always EXISTS (classically), and is
still a section.  All zero-`sorry`.

**What this does NOT yet give.**  Replacing `sum`/`seq` by a single `split`
constructor ("a partition into two blocks, edges one way, both layered") needs
`layeredL_has_solution` to handle it, and the non-closed block is NOT an
automaton on its own — its transitions leave into the closed block.  Solving it
means solving a system with EXTERNAL continuations, per-target rather than the
single trailing `finish` that `eqRHSParam` carries.  That generalisation is new
work and is not estimated yet.  It is the honest reason this iteration does not
move the number.

**Odds: 96%, HELD.**  A structural opening for the case the literature calls
hard, with its three enabling lemmas machine-checked — but the generalisation
they enable is unbuilt, and I have learned not to price unbuilt generalisations.
The field's prior that the problem does not close still stands.

**Next.**  Generalise the solution machinery from a single trailing `finish` to
per-target external continuations, which is what a `split` constructor needs;
then `split` replaces `sum`/`seq` and `quotient_closed_block` carries it through
the collapse.

---

## 288 — SOLVING OUTSIDE A CLOSED BLOCK.  THE "UNESTIMATED" MACHINERY WAS A SEED CHANGE.

287 stopped at a generalisation it called unbuilt and unestimated: the block
outside a closed set is NOT an automaton on its own, its transitions leave into
the closed block, and the single trailing `finish` `eqRHSParam` carries cannot
express what happens at the boundary — each outgoing transition needs its OWN
continuation, the closed block's already-known solution at that target.

**It needs no new algebra, only a new SEED.**  `solFuel` (271) starts from the
halt test; `solExt` starts from a supplied `sol₀` ON the block and the halt test
off it, and never touches the block again.  A boundary transition is then
handled by the recursion itself: its target is in the block, so EVERY fuel level
returns the SAME expression there, and stability sees no difference at all.  The
per-target continuation problem disappears because the per-target values are
constants of the recursion.

The rank condition weakens accordingly: a step out of the block-complement must
either LAND IN THE BLOCK — nothing more asked of it — or decrease.  That is the
honest content of "the complement is acyclic RELATIVE to the block".

**One subtlety worth recording**, because it is what forces `rank s < n` rather
than `rank s ≤ n`: a state of rank `0` may still step INTO the block, so fuel
`0` does not suffice to unfold it.  Every state needs one level of fuel more
than its rank — and the base case then becomes vacuous, which is why the proof
is shorter than 283's rather than longer.

**Proved**: `solExt`, `solExt_block`, `solExt_out`, `solExt_stable`,
`solExt_has_solution`, and the combination
`split_acyclic_has_solution` — *a closed block solved, plus a relatively acyclic
complement, solves the whole system*.  The block's own equations survive because
the block is CLOSED: they mention no state outside it, so
`guardedFold_trans_congr` transports them verbatim.  All zero-`sorry`.

**What remains for a full `split`.**  The complement must be allowed to be
LAYERED, not merely acyclic — loops outside the block.  That is the same
`LayeredL` recursion relativised to a complement, and 288's seed handles the
boundary in every case, so the remaining work is structural rather than
algebraic.

**Odds: 97%** (+1).  The generalisation 287 declined to price turned out to cost
one definition and no new algebra, which removes the largest unknown in the
remaining path.  The field's prior that the problem does not close still stands.

**Next.**  Relativise the `LayeredL` recursion to a complement — `LoopLayer`
outside a closed block — so `split` accepts a layered complement, not only an
acyclic one.

---

## 289 — A SEQUENCE IS A LAYER TOO.  THE HARD CASE IS THE CASE ALREADY SOLVED.

286 and 287 both named the `seq` constructor as the hard case for the quotient.
Looking at what `seqGSystem` actually does to a left state:

    sys.trans s = base.trans s ++ (R's ENTRY block, gated by `base.hlt s`)

— which is, letter for letter, `LoopLayer`'s shape.  **A SEQUENCE AND A LOOP ARE
THE SAME CONSTRUCTION.**  Both append ONE SHARED entry list to every state of a
region, gated by that state's own halt.  They differ in exactly two places: the
loop's entry block carries the guard `b` and targets the region ITSELF, while
the sequence's carries no guard and targets a CLOSED BLOCK; and the loop's halt
becomes `base.hlt ∧ ¬b` where the sequence's becomes `base.hlt ∧ R.initHlt`.

This matters because everything 279-281 proved about loop layers was proved
about the SHAPE, not about the loop.  In particular the pushforward: the base
downstairs is built from representatives, and the shared entry block — being
shared and of fixed length — pins the cut.

**Proved**: `SeqLayer`; `seq_seqLayer` (a sequence IS a layer over the DISJOINT
UNION of its halves, `sumGSystem L R.core` — the sequence with its connecting
block removed; every field `rfl` or one `List.map_map`); and
`seqLayer_pushforward_rep`, by 281's argument verbatim.  `propext` and
`Classical.choice` only.

**And removing a `seq` layer leaves a `sum`**, which is what makes the recursion
terminate — the connecting block is the only thing a sequence adds.

The literature's loop elimination is the same move: it "repeatedly identifies a
loop subgraph, DROPS ITS LOOP-ENTRY TRANSITIONS, and performs garbage
collection."  Dropping the shared entry block is exactly what removing either
layer does.

**What is untouched, and it is now the only thing.**  The `sum` constructor
under a quotient — where the MERGING ACROSS HALVES actually happens, and the
reason `Q` is not a sum of quotients at all.  287's `quotient_closed_block` and
`preferringRep` are aimed at it and are proved; the induction using them is not.

**Odds: 98%** (+1).  The case twice named hard dissolved into the case already
solved, and the pattern is now five for five — 271→283, 272→284, 280's gaps→281
and 282, 287→288, 286/287's `seq`→289 — every named obstruction in this stretch
has turned out smaller than its name.  Against that, the `sum` case genuinely
has not been attempted, and it is the one where the collapse does its work.  The
field's prior that the problem does not close still stands.

**Next.**  The `sum` case under a quotient: assemble `quotient_closed_block` and
`preferringRep` into the induction step, using that a quotient of a two-block
automaton is a two-block automaton even when it is not a sum.

---

## 290 — THE SUM'S QUOTIENT, END TO END — AND THE EXACT SHAPE OF WHAT IS LEFT.

`sum_quotient_has_solution`.  Take a quotient of `sumGSystem L R` whose
representatives PREFER the left half.  Then the classes with a left
representative form a CLOSED block (287 — `inl` is closed upstairs and the
preference transports it), and a solution on that block extends over the
complement (288) as soon as the complement is acyclic RELATIVE to the block.
So the quotient is solvable.

**This is the first end-to-end statement about the collapse in the series:
quotient in, solution out, with no hypothesis about the quotient beyond how its
dynamics is read off representatives.**  Compiled first try.

### The restriction, and why it is not bureaucratic

The complement must be RELATIVELY ACYCLIC.  A loop in the complement is not
covered — and cannot be covered by simply relativising 284.  Working out why is
the substantive part of this iteration:

284's construction sets `sol := std s ; W`, and that requires the base's
solutions to HAVE the form `std s ; W`.  A state whose run can EXIT into the
block does not: the exit branch carries no `W`, because leaving the layer for a
closed block means the loop never fires again.  So the entry fold is no longer
`D ; W` and `entryFold_seq` does not apply.

**And that is not an artifact of the encoding.**  In a Thompson automaton a
loop's body NEVER escapes except through the halt-gate — which is exactly why
`LoopLayer` is stated TOTAL, and why 277's `post = []` was forced.  A collapse
that merges a loop-body state with an outside state destroys that property, and
**this is precisely the failure the literature records: LLEE with EMPTY-STEP
transitions is not closed under bisimulation collapse** (279), repaired there
only by a new construction (crystallization).  GKAT's halt-gated back edges are
on the empty-step side of that line.

So the relatively-acyclic complement is exactly the case where NO SUCH MERGE HAS
HAPPENED, and the remaining case is exactly the one the literature says needs
more than a preservation argument.

**Odds: 98%, HELD.**  A positive end-to-end result on the collapse, against a
now-precise identification of the one case that is genuinely hard and is known
to be hard.  Those cancel.  The field's prior that the problem does not close
still stands, and this iteration is the sharpest statement yet of why.

**Next.**  The loop-in-the-complement case — either by finding that GKAT's
determinism rules out the destructive merge (the automata here are deterministic
per atom, unlike the process graphs the counterexamples live in), or by porting
the crystallization repair.

---

## 291 — 290's PESSIMISM WAS WRONG.  A LOOP IN THE COMPLEMENT EXITS AS A `SeqLayer`.

**Correcting myself.**  290 restricted the complement to being relatively
ACYCLIC and read that restriction as "the case where no destructive merge has
happened".  That reading was too gloomy.  **A loop in the complement is
ORDINARY, not pathological**: in `ite c e f` with `f` containing a loop and
`f`'s states unmerged, the complement simply contains `f`'s loop.  290's
restriction therefore excludes a routine case, not only a pathological one — and
the pathology I attributed to it was mostly my own overstatement.

**What actually matters is how such a loop EXITS into the block**, and it exits
the way every loop in a Thompson automaton exits: through the HALT-GATE, into a
SHARED entry block.  In `seq (wh d g) h` the body's states carry `g.hlt ∧ ¬d`
gated transitions into `h`'s entry; after a collapse that puts `h` in the block,
those are halt-gated shared entry transitions whose TARGETS LIE IN THE BLOCK.
**That is exactly `SeqLayer`** — whose `entry` list 289 left unconstrained as to
where it points.  So the complement is a `SeqLayer` over something, and removing
it leaves the loop total again, which is precisely 282's peel-the-seq-first move
one level down.

**Proved**: `seqLayer_subsystem` — 277's `layer_subsystem`, for sequences rather
than loops.  Same proof, same tool: parametric guard factoring turns the
per-state halt conjoined onto every entry transition into a test prefix, so the
whole entry block becomes a FINISH.  `propext` ALONE.

**And it specialises back**, the same check 277 ran for the loop:
`seq_subsystem_of_layer` reproduces the concrete `seq_subsystem` by reducing
through the abstract layer and then through the sum.  `propext` alone.  The
abstraction is faithful.

**On the determinism hope, negatively.**  290 suggested GKAT's per-atom
determinism might rule out the destructive merge outright.  This iteration's
search does not support that: deterministic systems have "computational
advantages but NOT uniformly better structure preservation across all process
classes", and the taxonomy result is stated for transition graphs generally.
Determinism is not a free pass; the structure has to be carried, and carrying it
is what 279-291 have been doing.

**Odds: 98%, HELD — and held deliberately.**  Two theorems on `propext` alone
plus a faithful-abstraction check is real progress, but it partly cancels my own
overstatement in 290, and the assembly it enables is not done.  Assembly has
surfaced a genuine mismatch before (283, where the two halves did not compose
until the hypothesis forms were reconciled), and I will not price this one until
it compiles.  The field's prior that the problem does not close still stands.

**Next.**  The relativised `LayeredL` on a domain — acyclic-relative (288) /
loop total on the domain (284) / `SeqLayer` on the domain (291) — with the
solution theorem by induction, and the pushforward by induction from 264, 281
and 289.

---

## 292 — THE SAME MACHINERY AT AN ARBITRARY FINISH.

The relativised recursion needs its pieces at an ARBITRARY finish, not only at
`1`: 291's `seqLayer_subsystem` hands the base a finish BUILT FROM THE ENTRY
BLOCK, so whatever solves the base must solve it there.

288's `solExt` had the halt test as its leaf.  Generalising it to
`paramFallback (hlt s) F` needed one thing 283 did not provide: **selection
through `transitionBranches` at an ARBITRARY fallback rather than a test** —
the same induction with the fallback carried instead of fixed.

**Proved**: `selectFull_tb_gen`; `fold_congr_step` (283's `solFuel_congr_step`
freed of its test); `solExtF` with `solExtF_block`, `solExtF_out`,
`solExtF_stable`, `solExtF_has_solution` — **the extension at an arbitrary
finish**; and `seqLayer_extends`, 291's reduction in the form the recursion
consumes: whatever solves the base at the finish the entry block builds, solves
the layer at `F`.  All compiled first try.  `seqLayer_extends` on `propext`
alone.

**Every case of the relativised recursion now has its lemma.**

    acyclic-relative, any finish     solExtF_has_solution      (292)
    sequence layer, any finish       seqLayer_extends          (292 via 291)
    loop layer, closed domain        loopLayer_has_solution    (284)
    pushforward: acyclic             acyclic_quotient          (264)
    pushforward: loop                loopLayer_pushforward_rep (281)
    pushforward: sequence            seqLayer_pushforward_rep  (289)

What is left is the INDUCTIVE that ties them together and the two inductions
over it.

**Odds: 98%, HELD** — deliberately, per 291's policy: the assembly is not done,
assembly has surfaced a genuine mismatch before (283), and I will not price this
one until it compiles.

**Note: the session's WEB SEARCH BUDGET IS EXHAUSTED** (200/200).  Later
iterations of this loop cannot include the search step; the proof work
continues.

**Next.**  Define `LayeredOn sys dom` — acyclic-relative / loop over a CLOSED
domain / sequence layer whose entry points OUTSIDE the domain — and prove
`layeredOn_has_solution` by induction, then the pushforward.

---

## 293–294 — THE RELATIVISED RECURSION, ASSEMBLED.  IT COMPILES.

### 293 — the loop case, relativised.

`LoopLayerOn` (a loop confined to a domain, with `outside` as `SeqLayer` has
it), `LoopLayer.toOn`, and `loopLayerOn_has_solution` — 284's construction on a
domain.  The construction never looks outside the domain, because the entry
list points into it and the base's transitions stay in it.

**One mechanical obstacle worth recording.**  284 finished with
`StandardSolvesBA.withContinuation`, whose hypothesis quantifies over
`aut.states`, while the relativised hypothesis holds only on the domain.  But
`withContinuation`'s proof is PER-STATE — it uses the hypothesis at the state it
is proving about and nowhere else — and `eqRHSParam` reads only `trans` and
`hlt`, never `states`.  So apply it to the system with its state list replaced
by the SINGLETON `[s]`: definitionally the same automaton everywhere
`eqRHSParam` looks, and a hypothesis over one state is exactly what is
available.

### 294 — the inductive, and `hsolve` relativised.

`LayeredOn sys P` — "given a solution on the block `P`, the rest of `sys` can be
solved" — with one constructor per lemma of the last six iterations:

  * **acyclic** relative to the block (288/292);
  * **sequence layer** whose shared entry points INTO the block (289/291).  The
    finish it needs is then computable from the block's solution ALONE, which is
    exactly why the entry must point there and not back;
  * **loop layer** confined to the complement, over a base on which the
    complement is CLOSED (284/293) — the loop must not be able to leave, and it
    cannot, because the sequence layers carrying the exits have already been
    peeled.

`layeredOn_has_solution`: **a layered complement is solvable at any finish,
given any solution on the block.**  The loop case delivers at finish `1` (284's
construction is tied to `w1`) and is lifted to `F` by right-multiplication —
sound HERE precisely because the complement is closed, so no branch escapes into
the block and every branch carries the `F`.

**Zero errors, zero `sorryAx`, 8 883 lines.**

**Odds: 99%** (+1), and raised under the policy set in 291: I said I would not
price the assembly until it compiled.  It compiles, and — unlike 283 — no
hypothesis mismatch surfaced when the pieces met.

**What is honestly left.**  The SOLUTION side is complete and general.  The
PUSHFORWARD side is not assembled: `LayeredOn` must be shown to survive a
quotient, with cases at 264 (acyclic), 281 (loop — needs relativising to
`LoopLayerOn`) and 289 (sequence, done).  Then `LayeredOn` must be connected to
the architecture's `sumQuotientSolvable_of_certificate`.  That is real work, not
bookkeeping.

**Next.**  `layeredOn_pushforward` by induction — relativise 281 to
`LoopLayerOn` first, since 289's sequence case is already relativised and 264's
acyclic case is already stated for a behavioural quotient.

---

## 295 — GROW THE BLOCK; AND THE ACYCLIC CASE PUSHES FORWARD WITHOUT A BISIMULATION.

### The `split` constructor.

294's `seq` constructor demands that a layer's entry point INTO the block, so a
recursion starting from an EMPTY block must be able to ENLARGE it.  `split` does
that: pick a CLOSED region `C` disjoint from the block, solve `C` first —
legitimate at any input, since a closed region's equations mention nothing
outside it — then solve the rest with `P ∪ C` as the block.  **This is what
turns `seqGSystem`'s right half into something a sequence layer may point at.**
Its case in `layeredOn_has_solution` is three lines plus a transport of the
`C`-equations through `guardedFold_trans_congr`, and it compiled first try.

### The acyclic pushforward, without the bisimulation.

264 proved `hcollapse`'s acyclic case USING the bisimulation: `rank'` was the
MINIMUM rank over a class's preimages, and a step downstairs was pushed
BACKWARDS through the bisimulation to find a preimage achieving it.

**Relativised, it needs neither.**  Choose the representative RANK-MINIMAL in
its class among members outside the block; then `rank' := rank ∘ rep` works
directly:

  * if the target's class meets the BLOCK, the preferring representative puts
    the target's representative in the block, and the first disjunct discharges
    it with NO rank comparison at all;
  * otherwise every member of the target's class is outside the block, so the
    rank-minimal representative has rank at most the actual target's — already
    below `rank (rep c)`.

**The two properties do not conflict, because they apply to DISJOINT cases**:
preference decides classes meeting the block, minimality decides the rest.  That
is why one representative can serve both, and it is what removes the
bisimulation from the argument.

`acyclic_rel_pushforward` and `layeredOn_acyclic_push`, taking both properties as
hypotheses; both are satisfiable, `preferringRep` (287) being the first half.
`firstMatch_map` turned out to be already proved (2902) — reused rather than
duplicated.

**Odds: 99%, HELD.**  One more constructor on the solution side and the first
pushforward case, both clean — but the pushforward's `seq` and `loop` cases are
still unassembled and the connection to the architecture is untouched.

**Next.**  The `seq` and `loop` cases of `layeredOn_pushforward` (289 and 281,
relativised), then the induction, then the transport lemmas that carry a
component's `LayeredOn` into a `sum`/`seq` — which is what `thompson_layeredOn`
needs.

---

## 296 — THE LOOP PUSHFORWARD, RELATIVISED.  ALL THREE LAYER SHAPES NOW PUSH FORWARD.

`loopLayerOn_pushforward_rep` — 281's theorem with a domain, which is 289's
proof plus the two extra fields the loop carries (the semantic halt equation and
the `outside` clause).  Compiled first try, `propext + Classical.choice`.

    acyclic     layeredOn_acyclic_push          (295)
    sequence    seqLayer_pushforward_rep        (289)
    loop        loopLayerOn_pushforward_rep     (296)

**What is NOT yet assembled, and the precise reason.**  The INDUCTION over
`LayeredOn`.  295 identified what stands in its way: the acyclic case wants the
representative to be RANK-MINIMAL, but **the rank is existential INSIDE each
acyclic node while the representative is GLOBAL to the quotient**, so one
representative cannot be minimal for every node at once.  Nor does taking
`rank'` to be the fibre-minimum rescue it: the step downstairs is the
REPRESENTATIVE's step, so the minimum must be ACHIEVED at the representative or
the comparison does not close.

The resolution is 264's and it is available: use the BISIMULATION to transfer
the step to a minimising preimage.  That is exactly what `acyclic_quotient`
already assumes, and it is true in the application.  Confirmed this iteration
that `Nat.find` is in scope in this file (four uses), so the minimum-over-
preimages construction 264 used can be reused rather than rebuilt.

**Odds: 99%, HELD.**  The layer-level pushforwards are complete, but the
induction is the step where the hypothesis forms have to agree, and that is
exactly where 283 found a real mismatch.  Not pricing it until it compiles.

**Next.**  `layeredOn_pushforward` by induction, with the acyclic case taking
the bisimulation (264's argument, relativised to a block) and the sequence and
loop cases taking 289 and 296.

---

## 297 — TWO RETRACTIONS, AND THE ACYCLIC PUSHFORWARD VIA THE BISIMULATION.

### Retraction 1 — `Nat.find`.

296 claimed `Nat.find` is in scope in this file, citing four occurrences.  **All
four are inside DOC COMMENTS**, and one of them says the opposite: `Nat.find`
does NOT exist here (no Mathlib).  Confirmed by compiling
`example (h : ∃ n : Nat, n > 3) : Nat := Nat.find h` → `unknown constant`.  The
minimum must come from `minOf1`/`minOfList` (6831-6884), which is exactly why
264 built them.  The claim came from a grep that did not separate code from
prose.

### Retraction 2 — the build cache.

Asked whether the Lean compile is optimally cached, I answered "as bad as it can
be — zero oleans, 61 121 lines re-elaborated per check".  **That was wrong**, and
wrong from a bad glob: I looked in `.lake/build/lib/*.olean`; the path is
`.lake/build/lib/lean/`.  Measured:

    lake env lean GkatCensusProofs.lean   2.8s     (what this loop runs)
    lake build GkatCensusProofs (no edit) 0.9s
    oleans present                        290

Caching is essentially optimal: all 66 imports load from `.olean`, and the 2.8s
is elaboration of the 9k-line file being edited — unavoidable without splitting
it.  No 61k-line re-elaboration was ever happening.

### The theorem.

295 needed the representative RANK-MINIMAL, which one global representative
cannot be for every acyclic node at once.  **The bisimulation removes the need**:
define `rank'` as the minimum rank over a class's LISTED preimages OUTSIDE the
block, take the preimage ACHIEVING it, and push the step backwards to THAT
preimage rather than to the representative.

The block downstairs is "SOME listed preimage lies in the block", which agrees
with 295's `P ∘ rep` whenever the representative prefers the block (287).  The
disjunction falls to a case split on whether the step's target is in the block —
and in the branch where it is not, the target is a legitimate member of its own
class's minimising set, so `rank'` decreases.

`fibreOut`, `fibreOut_le`, `fibreOut_achieved`, `acyclic_bisim_pushforward`.
Compiled first try.

**Odds: 99%, HELD.**  The case 295 and 296 could not reach is proved, but this
iteration also produced two false claims of my own — both from reading a grep
instead of the thing itself.  Neither touched a proof; both would have misled
the next step.

**Next.**  `layeredOn_pushforward` by induction: acyclic by 297, sequence by 289,
loop by 296 — with the block downstairs stated uniformly as "some listed
preimage lies in the block".

---

## 298 — THE INDUCTION NEEDS ONE CONDITION, AND IT IS THE ONE 290 NAMED.

297 restated with the block downstairs as `P ∘ rep`, which is both the form the
induction consumes and the shorter proof: `¬ P (rep c)` becomes immediate rather
than derived, and the in-block branch is exactly `hpref`.  Recompiled clean.

Then attempted `layeredOn_pushforward` by induction.  **It does not close, and
working out why gives a single sharp condition rather than a list.**

**First obstruction — the loop's entry condition.**  The `loop` constructor
carries `∀ tr ∈ entry, ¬ P tr.2.2`.  Downstairs that becomes
`¬ P (rep (f t))` for each entry target `t` with `¬ P t`.  `hpref` gives the
WRONG direction — it gives `P t → P (rep (f t))`.  The converse fails exactly
when a loop-entry target MERGES with a block state.

**Second obstruction — the bisimulation does not transport.**  The acyclic case
(297) needs `hbisim` for the system AT THAT NODE, which is the fully-peeled
base, not the original `sys`.  And it does not transport: in a `SeqLayer`,
`firstMatch` in `sys` agrees with `firstMatch` in `base` only on worlds where
`base` FIRES; where `base` falls through, `sys` takes an entry transition
instead, so two `sys`-bisimilar states can differ in `base`.

**Both reduce to the same condition.**  295's alternative to `hbisim` was a
RANK-MINIMAL representative, rejected because the rank is existential per
acyclic node while the representative is global.  But the acyclic nodes of a
derivation sit on DISJOINT regions — `split`'s two subderivations concern `C`
and its complement — so one representative CAN be rank-minimal on each region
separately, **provided no class crosses a region boundary.**  That is the same
condition the first obstruction wants.  So:

    THE INDUCTION CLOSES IFF EVERY BLOCK APPEARING IN THE DERIVATION
    IS A UNION OF CLASSES

— i.e. the collapse never merges a block state with a non-block state.  **This
is exactly 290's "destructive merge", now derived from the proof rather than
guessed at**, and it is a condition on the SPLITS, which are the closed regions
the derivation chooses: a `seq`'s right half, a `sum`'s halves.

**And it is not free.**  Whether the collapse respects those regions is not up
to us — in the completeness application the whole point is that the two halves'
start states merge.

**Odds: 98%** (−1).  The plan of the last ten iterations — prove the three
pushforward cases, then assemble — does not work as stated, and the reason is
structural rather than bookkeeping.  What survives is better than what it
replaces: a single named condition, derived, instead of a diffuse worry.  The
field's prior that the problem does not close still stands, and this is the
clearest reason yet why.

**Next.**  Either (a) show the derivation can always be REORGANISED so its
blocks are unions of classes — the splits are ours to choose, even if the
collapse is not; or (b) drop the derivation-pushforward strategy and build the
downstairs derivation directly by induction on the EXPRESSION.

---

## 299 — BLOCKS CAN BE SATURATED.

298 showed the pushforward induction closes exactly when every block is a UNION
OF CLASSES, and left that as a condition the collapse might not grant.  But
**the blocks come from `split`, and `split`'s blocks are OURS to choose.**  So
the question is whether a block can always be REPLACED by its class-saturation,
and for the property `split` actually needs the answer is yes:

    THE SATURATION OF A CLOSED SET IS CLOSED.

If `s ~ t` with `t` in the block and `s` steps to `s'`, the bisimulation gives
`t` a matching step to some `t'` with `s' ~ t'`, and closure puts `t'` in the
block — so `s'` is in the saturation.  `saturation_closed` (`propext` alone);
`saturation_is_union` (NO axioms).

**Why this required weakening `split` first, and what it cost.**  The argument
produces a MATCHING STEP, and steps are SELECTIONS, not list members — a dead
branch of `s` has no counterpart at `t` at all.  So the saturation is closed
under `firstMatch` steps and NOT under list membership, which is what `split`
asked for.  `split` has been weakened to the selection form, and its case in
`layeredOn_has_solution` now goes through `fold_congr_step` (292) instead of
`guardedFold_trans_congr` — **the same list-versus-selection trade 283 made**,
paying syntactic equality for `EquivBA` and getting the weaker hypothesis in
return.  That this trade keeps coming up, always in the same direction, is now
a pattern worth naming: **whenever a hypothesis is too strong, check whether it
is asking about the LIST when the proof only observes the SELECTION.**

**What is still open, and it is the substantive part.**  Saturating a block
ENLARGES it, so `split`'s two subderivations must survive the enlargement: the
enlarged block must still be SOLVABLE, and still DISJOINT from `P`.  Neither is
automatic, and the first is the real question — in the completeness application
the saturation of `f`'s states includes every `e`-state bisimilar to one, so the
enlarged block mixes the two halves.

**Odds: 98%, HELD.**  298's condition is now shown ARRANGEABLE in principle,
which recovers part of what 298 cost — but "the enlarged block is still
solvable" is untouched, and it is where the difficulty moved rather than
vanished.

**Next.**  Whether a saturated block is still solvable: it is closed and a union
of classes, and it is the image of a solvable region under the collapse — which
is the same question one level down, so the honest move is to check whether the
recursion on saturated blocks is WELL-FOUNDED before assuming it terminates.

---

## 300 — SATURATEDNESS IS AN INVARIANT, SO DISJOINTNESS IS FREE.

299 left two things to check when a block is replaced by its saturation: the
enlarged block must still be DISJOINT from `P`, and it must still be SOLVABLE.
**The first is free**, and for a reason worth stating: **saturatedness is an
INVARIANT of the recursion.**

  * the recursion starts at `P = ∅`, saturated vacuously (`saturated_empty`);
  * `split` replaces `P` by `P ∪ C`, and a union of saturated sets is saturated
    (`saturated_or`);
  * `seq` and `loop` do not change the block at all.

So at every node the block is a union of classes — and then disjointness
transports (`saturation_disjoint`): a member of `P` equivalent to a member of
`C` would drag that member into `P`, contradicting the original disjointness.
All three lemmas are **axiom-free**.

### The remainder, in one statement

    THE SATURATION OF A LAYERED CLOSED BLOCK IS STILL LAYERED

Everything else in `hcollapse` is now proved:

    solution side, relativised          layeredOn_has_solution     (294/295/299)
    pushforward: acyclic                acyclic_bisim_pushforward  (297/298)
    pushforward: sequence               seqLayer_pushforward_rep   (289)
    pushforward: loop                   loopLayerOn_pushforward_rep(296)
    blocks can be saturated             saturation_closed          (299)
    saturatedness is invariant          saturated_empty/_or        (300)
    disjointness survives saturation    saturation_disjoint        (300)

**And the remaining statement is the whole difficulty, not a side condition.**
The saturation of a `seq`'s right half contains every left-half state bisimilar
to a right-half one, so the block a `split` must solve MIXES THE TWO HALVES —
which is the same shape as the original problem one level down.  That is either
a genuine recursion (and then it terminates, the state list being finite) or a
genuine circularity, and telling those apart is the next thing worth doing.

**Odds: 98%, HELD.**  One of 299's two sub-conditions discharged cleanly and
axiom-free; the other is the hard one and I said so when I split them.

**Next.**  Decide whether "the saturation of a layered block is layered" is a
well-founded recursion or a circularity: the saturated block is strictly
LARGER than the original, so the obvious induction on block size runs the WRONG
WAY — find the measure that decreases, or find that none does.

---

## 301 — SATURATION DIES AT THE TOP-LEVEL SUM.  BUILD THE DERIVATION DOWNSTAIRS.

### The negative.

299 and 300 developed SATURATION as the way to make every block a union of
classes.  Tested where it matters, it fails.  In the completeness application
`sys = sumGSystem L R` with `start_L ~ start_R`, so by bisimulation **every
reachable `L`-state is bisimilar to some `R`-state**.  The top-level split takes
`C = R`'s states; its saturation therefore contains EVERY REACHABLE STATE, and
"solve `C'` given the rest" IS the original problem.

**Saturation destroys the top-level split exactly in the case the whole
programme is about.**  299 and 300's lemmas stay true and stay useful — the
saturation of a closed set is closed, saturatedness is invariant, disjointness
survives — but the STRATEGY of saturating a `sum`'s split is dead.  Two
iterations spent on a route that was circular where it counted.

### The redirect, and why it is better.

**Stop pushing derivations forward.**  A quotient's blocks are SETS OF CLASSES,
so they are saturated for free — 298's condition is VACUOUS downstairs.  Build
`Q`'s derivation directly, using 287's preferring representative for the split:
the classes with an `inl` representative are closed, so they are a legal `C`,
and the two remaining obligations are about `L` and `R` SEPARATELY.  Those are
structurally smaller expressions — **a well-founded recursion where saturation
was a circular one.**

`sum_quotient_layered_of_split`: the top-level split, downstairs.  Reduces
`LayeredOn Q ∅` to the two component obligations, with closure supplied by 287
and converted from list form to `firstMatch` form through
`firstMatch_mem_of_some`.  `propext, Quot.sound`.

**Odds: 98%, HELD.**  A dead strategy identified by testing it against the case
that matters rather than by inspection, and replaced by one whose recursion is
well-founded on expression structure.  That is worth what the two lost
iterations cost, and no more.

**Next.**  The two component obligations: `LayeredOn Q (classes with an inl rep)`
— solve the R-only classes given the L-classes — and its mirror.  The first is
about the image of `R` restricted to classes with no `L`-partner, and 287's
argument shows that region's complement is closed in `R`, so the recursion has
somewhere to go.

---

## 302 — THE RECURSION IS WELL-FOUNDED DOWNSTAIRS, AND 299 SURVIVES ITS STRATEGY.

300 asked whether "the saturation of a layered block is layered" is a genuine
recursion or a genuine circularity.  301 redirected downstairs but left the
worry that the circularity recurs one level down: inside `ite c e₁ e₂` a split
at `e₂`'s states need not be a union of classes either, and saturating it mixes
`e₁` with `e₂` again.

**It does not recur, and the reason is the whole point.**  Bisimilar states have
the SAME CLASS, so **the IMAGE of a saturated block is the image of the half it
started from** — the extra states saturation pulled in contribute NO NEW
CLASSES.  Mixing is an UPSTAIRS phenomenon.  Downstairs a block is always "the
image of a sub-automaton", and the recursion is on EXPRESSION STRUCTURE.

**So 300's question has an answer: a genuine recursion, not a circularity** —
the same construction decreases when measured downstairs and does not when
measured upstairs.  That is exactly the difference between 299's route and
301's, and it is why 301's redirect was the right move rather than a lateral
one.

**And 299's lemma survives its strategy's death.**  Obligation B needs: the
`R`-states having an `L`-partner form a CLOSED set.  That is `saturation_closed`
applied with `C` = "is `inl`" — **the saturation of "is `inl`" IS "has an
`L`-partner"**.  The lemma proved for a dead strategy is exactly the lemma the
live one wants.  `inl_partner_closed`, `propext + Quot.sound`.

**Odds: 99%** (+1).  300 posed a fork — recursion or circularity — and it
resolved on the recursion side, which is the side the programme needs.  The
field's prior that the problem does not close still stands.

**Next.**  State the induction on expressions: for every `g` and every closed
block of classes `B`, the image of `Thompson(g)`'s automaton is `LayeredOn`
relative to `B`.  The `ite` case is 301's split plus this iteration's closure;
`seq` is the same with 289's layer; `wh` is 296's; `test`/`act` are acyclic.

---

## 303 — THE EXPRESSION INDUCTION: SHAPE, BASE CASES, AND `wh`.

302 established the recursion belongs downstairs and runs on expression
structure.  Committing to its statement:

    for every expression `g`, every quotient `Qsys` of `g`'s Thompson
    automaton, and every block `B` lying OUTSIDE the quotient's image,
    `Qsys` is `LayeredOn B`

Three points about the shape, each load-bearing:

  * **the block is OUTSIDE the image** — `B` is what has already been solved,
    the image is what this call must solve, and that makes `¬ B c` synonymous
    with "`c` is a class of `g`'s automaton";
  * **the dynamics is read off representatives only OFF the block** — demanding
    it everywhere would make the `ite` case unusable, since there `Qsys` also
    carries the other branch's classes;
  * **`rep` need not be total in any useful sense** — for `test` its codomain is
    `Empty`, and that is not a degeneracy to work around, it is what PROVES the
    base case: a class outside the block would need a representative, there are
    none, so the block is everything and `acyclic` fires vacuously.

`quotient_layered_test`, `quotient_layered_act`, and `quotient_layered_wh`.

**The `wh` case is the substantive one**, and its trick is worth recording: the
base system downstairs is **BUILT, not assumed** — off the block it is `e`'s
dynamics read through the representative, on the block it is whatever `Qsys`
already had.  That makes `LoopLayerOn`'s `outside` clause true BY CONSTRUCTION,
which is what turns a TOTAL loop upstairs into a loop CONFINED TO THE IMAGE
downstairs — exactly what the recursion needs.

**A mechanical note that cost most of the iteration.**  `List.map_append` and
`List.map_map` exist and work in isolation but would NOT fire in this goal —
neither by `rw` nor by `simp`, the latter reporting the argument as unused.
Three local structural-recursion helpers (`map_append'`, `map_map'`,
`gate_map_comm`) replaced them, applied as TERMS via `Eq.trans` and `congr 1`
rather than as rewrite rules.  When a standard list lemma refuses to match a
goal that visibly contains its pattern, stop probing and supply the term.

**Odds: 99%, HELD.**  Three of five cases of the induction, including the one
carrying the loop machinery.  `ite` and `seq` remain, and they are where the
split and the sequence layer have to meet the recursion.

**Next.**  The `ite` case: `sum_quotient_layered_of_split` (301) supplies the
split, `inl_partner_closed` (302) supplies its closure, and the two branches are
recursive calls on `e` and `f`.

---

## 304 — THE `ite` CASE.  FOUR OF FIVE.

With 303's shape fixed, the `ite` case reduces to `LayeredOn.split` at
`C` = "the classes of the LEFT branch", plus two recursive calls.  The split
constructor is immediate; what had to be PROVED is that `C` is CLOSED, and that
is where the quotient's structure enters.

**It needs exactly two facts and no more.**  The image misses the block
(`hout`), and the representative PREFERS the left branch (`hpref`, 287).  A step
out of a left class lands, upstairs, in the left half — sums have no cross
edges — so its class HAS a left preimage; preference then makes that class's own
representative left, which is the definition of `C`.

`sum_left_block_closed`, stated for an ARBITRARY `sumGSystem` rather than for
`ite`'s automaton so the `seq` case can reuse it, and `quotient_layered_ite`.
Both compiled first try.

**Worth noting which block each recursive call receives.**  The LEFT call gets
"everything that is not a left class", so its own image is exactly `e`'s
classes.  The RIGHT call gets `B` TOGETHER WITH the left classes, which is what
makes it a call about `f` alone.  That asymmetry IS the split, and it is why the
recursion descends rather than repeating itself.

    test    quotient_layered_test    (303)
    act     quotient_layered_act     (303)
    wh      quotient_layered_wh      (303)
    ite     quotient_layered_ite     (304)
    seq     OPEN

**The `seq` plan, from the shape.**  A sequence's entry block points at `f`'s
classes, and `LayeredOn.seq` requires a layer's entry to point INTO the block.
So the order is forced: **split off the right part FIRST**, making `f`'s classes
part of the block, and only THEN peel the sequence layer whose entry now points
there.  `seq_inr_closed` (247) gives the closure, 289 gives the layer.

**Odds: 99%, HELD.**  Four of five cases, and the fifth has a forced plan rather
than an open question.

**Next.**  The `seq` case: split at the right classes, then `LayeredOn.seq` with
289's layer, then recurse on `e`.

---

## 305 — THE PREFERENCE DIRECTION IS FORCED, AND ONE LEMMA SERVES BOTH CASES.

304 split `ite` at the LEFT branch, using a representative preferring `inl`.
**The `seq` case cannot do that.**  Only a sequence's RIGHT half is closed — the
left half runs into the right through the connecting block — so a sequence must
split at its RIGHT classes, which needs a representative preferring `inr`.

A representative is GLOBAL to the quotient, so both preferences cannot hold at
one node.  They do not have to: **`ite`'s halves are BOTH closed, so `ite` may
split either way, while `seq` may not.**  The uniform choice is therefore forced
to `inr`, and 304's left-handed version becomes an alternative rather than the
main line.

The preference is still PER-NODE, not per-quotient — at an inner node it ranks
that node's own two halves.  A single global representative satisfies all of
them by ranking the expression tree's LEAVES, right before left, consistently.
That is a construction to discharge later, not an obstruction, and it is now
written down as an obligation rather than assumed away.

**Proved**: `right_block_closed`, stated once for ANY system whose `inr`
transitions are the right component's retargeted — true of `sumGSystem` and
`seqGSystem` alike, both by `rfl` — and `quotient_layered_split_right`, the
split that serves `ite` and `seq` together.

**What remains of `seq`** is only the layer step: discharging the left
obligation `LayeredOn Qsys (B ∨ right classes)` by `LayeredOn.seq` with 289's
`SeqLayer`, whose entry now points into the block because the right part joined
it first.  That ordering was forced by the constructor and is why the split had
to come first.

**Odds: 99%, HELD.**  A correction to 304's handedness, found by attempting the
next case rather than by inspection, plus the lemma that now serves both.

**Next.**  The `seq` layer step, and with it the fifth case.

---

## 306 — THE `seq` LAYER STEP.  ALL FIVE CASES OF THE EXPRESSION INDUCTION.

After 305's split has put the right classes into the block, what remains is to
peel the connecting block.  The construction mirrors 303's `wh` exactly: **the
base system downstairs is BUILT, not assumed** — off the block it is the
DISJOINT UNION `sumGSystem L R.core` read through the representative, on the
block it is whatever `Qsys` already had — so `SeqLayer`'s `outside` clause holds
by construction and the layer is confined to the image.

**That the base is the disjoint union is 289's observation doing its work.**  A
sequence is a layer over the SUM of its halves, so removing the layer leaves an
`ite`-shaped node, and the recursion continues on `e` with the right classes
already in the block.  The entry targets land in the block for the reason 305
arranged: they are `R`'s initial targets, so their classes have `inr` preimages,
and the preferring representative puts them in the right-class block.

`seq_gate_comm` (a fourth term-level map helper) and
`quotient_layered_seq_left`.

    test    quotient_layered_test          (303)
    act     quotient_layered_act           (303)
    wh      quotient_layered_wh            (303)
    ite     quotient_layered_ite           (304), or split_right (305)
    seq     quotient_layered_split_right   (305)
          + quotient_layered_seq_left      (306)

**All five cases proved**, each taking its recursive hypotheses as arguments.

### What remains, precisely

  1. **Tie the five into an induction on `Exp`** — the case lemmas each take the
     sub-quotient data (`j`, `rep`, `htrans`, `hhlt`) as hypotheses, and the
     induction must CONSTRUCT that data at each node from the parent's.
  2. **Construct the global preferring representative** — 305's obligation: one
     `rep` ranking the expression tree's leaves right-before-left, satisfying
     every node's `hpref` at once.
  3. **Connect to `sumQuotientSolvable_of_certificate`** — the architecture's
     entry point, which is what turns "the quotient is `LayeredOn`" into
     completeness.

**Odds: 99%, HELD.**  The five cases are the mathematical content and they are
done; (1)–(3) are construction and plumbing, but plumbing has produced genuine
mismatches twice in this series (283, 305), so they are not yet free.

**Next.**  (2), the preferring representative — it is self-contained, it is the
one item that is a construction rather than an assembly, and (1) cannot be
stated cleanly until the `rep` it quantifies over is known to exist.

---

## 307 — 303's SHAPE CANNOT BE INSTANTIATED.  USE A WITNESS, NOT A FUNCTION.

**A defect found by trying to construct the representative, not by inspection.**
303 gave each case a total `rep : Q → State`.  For `test` the state type is
`Empty`, so supplying such a function REQUIRES `Q` ITSELF TO BE EMPTY.
`quotient_layered_test`'s proof is correct and its statement is true, and **it
can never be applied to anything**.  The same defect blocks every recursive call
whose sub-expression has no states.

That is why 305's "leaf ordering" kept feeling heavier than it should: it was
trying to build a total function into a type that may be empty.

**The fix: ask for a WITNESS PER CLASS instead of a function.**  The hypothesis
becomes "for every class outside the block there EXISTS a state whose dynamics
it carries" — what a quotient actually provides, and it needs no inhabitant when
there are no classes to witness.  `test` then proves itself: a class outside the
block would produce an element of `Empty`.

**And 305's obligation dissolves.**  The preference becomes a property of the
WITNESS rather than of a global choice function: each node picks its own
witness, and "prefer `inr`" is a condition on that pick, not on one function
serving every node at once.  No leaf ordering, no total order on states, no
nested fallbacks.

`quotient_layered_test'` and `quotient_layered_act'` in the new form.  The
`wh`, `ite` and `seq` cases still need migrating.

**Odds: 99%, HELD.**  A real defect in the shape I committed to four iterations
ago, caught the only way it could be — by trying to USE the thing rather than
prove it — and its fix removes a standing obligation rather than adding one.

**Next.**  Migrate `wh`, `ite`, `seq` to the witness form.  The `wh` and `seq`
proofs construct their base system from `rep`; with witnesses that construction
becomes a `dite` on the class being outside the block, choosing the witness.

---

## 308 — THE SPLIT IN WITNESS FORM, AND A BETTER BLOCK.

Migrating 305's split to 307's witness form does more than remove the unusable
`rep`.  With a representative the block had to be "the representative is `inr`"
— a fact about a CHOICE.  With witnesses it becomes

    the class HAS an `inr` preimage

which is a fact about the QUOTIENT, needs no choice function, and is manifestly
a union of classes.  The preference likewise stops being a property of a global
function and becomes a hypothesis about what witnesses the dynamics: **if a
class has an `inr` preimage, its dynamics is witnessed by an `inr` state.**
That is a condition one can verify of a quotient one is BUILDING, which the
`rep`-based version never was.

`right_block_closed'` and `quotient_layered_split_right'`, both compiled first
try.  `wh` and `seq_left` still to migrate — they construct their base system,
which becomes a `dite` on the class being outside the block, choosing the
witness.

**Odds: 99%, HELD.**  A migration, and one that improved the statement it
migrated rather than merely relocating it.

### STANDING INSTRUCTION FOR AFTER THE PROOF CLOSES

Recorded to memory (`gkat-post-proof-agenda`).  When the full proof closes, the
loop does NOT stop and does NOT drift — it switches to, in order:

  1. **STEELMAN OBJECTIONS.**  Attack the finished proof as a hostile referee
     would.  Priorities from this proof's own shape: is `LayeredOn` VACUOUS
     where it matters (the base-rate control that caught 205); does
     `sumQuotientSolvable_of_certificate` really deliver completeness or has the
     hard part moved into its hypotheses; is W3 truly unused — check transitive
     AXIOM DEPENDENCIES, not the prose; are the `Classical.choice` uses
     eliminable or load-bearing; does any theorem quantify so as to be
     unusable — **the defect 307 found: true, proved, and impossible to
     instantiate.**
  2. **Obvious connections**, then **3. distant ones**, from the candidate list
     in that memory.

**Next.**  Migrate `wh` and `seq_left` to the witness form.

---

## 309 — `wh` IN WITNESS FORM.

303's construction survives the migration unchanged in spirit: the base system
downstairs is still BUILT rather than assumed, so `LoopLayerOn`'s `outside`
clause holds by construction.  What changes is what it is built FROM — a `dite`
on the class lying outside the block, whose positive branch carries the very
proof it needs to name the witness.  **That is the shape 307's fix makes
available and the `rep` version could not express: the witness exists only where
there is something to witness.**

Note the two uses of the SAME witness — transitions and halt — which is why
`hwit` packages them in ONE existential.  Split into two, the halt could come
from a different state than the transitions, and the layer's halt equation would
then be about the wrong automaton.

**A second rewriting lesson, sharper than 303's.**  `rw` failed here with
"motive is not type correct", and the reason generalises: **the witness's TYPE
mentions the term being rewritten** (`Classical.choose (hwit c hc)` depends on a
proof about `Qsys.trans c`), so abstracting that term makes the witness
ill-typed.  Term application has no motive to typecheck, so the fix is the same
one 303 reached for a different reason: `Eq.trans` and `congrArg` throughout,
never `rw`, once dependent witnesses are in play.

    test    quotient_layered_test'          (307)
    act     quotient_layered_act'           (307)
    ite/seq quotient_layered_split_right'   (308)
    wh      quotient_layered_wh'            (309)
    seq     seq_left — LAST ONE TO MIGRATE

**Odds: 99%, HELD.**

**Next.**  `quotient_layered_seq_left` in witness form — the same `dite`
construction, over `sumGSystem L R.core` instead of `e`'s core.

---

## 310 — `seq` IN WITNESS FORM.  THE MIGRATION IS COMPLETE.

The last case, and one thing gets SIMPLER in the migration.  The `rep` version
needed a separate hypothesis `hinl` saying the representative of a non-block
class is a left state.  **In witness form that hypothesis disappears into the
witness's TYPE** — the witness is drawn from `S₁` directly.  It is justified for
the same reason it was assumed: the block already contains every right class
(305's split runs first), so a class outside it has no right preimage at all.

**A hypothesis that becomes a type is a hypothesis that can no longer be
forgotten at a call site**, which is the second thing 307's shape bought, after
applicability.

    test    quotient_layered_test'          (307)
    act     quotient_layered_act'           (307)
    ite/seq quotient_layered_split_right'   (308)
    wh      quotient_layered_wh'            (309)
    seq     quotient_layered_seq_left'      (310)

**All five cases, in a form that can actually be instantiated.**  Compiled first
try.  Whole file: zero errors, zero `sorryAx`.

**Odds: 99%, HELD.**

**Next.**  Tie the five into the induction on `Exp`.  The remaining work is
CONSTRUCTING the sub-quotient data at each node: given the parent's `j` and its
witness hypothesis, produce the child's.  For `wh` the state type is unchanged,
so the child's data IS the parent's; for `ite` and `seq` it is the parent's
composed with an injection, and the witness must be shown to land in the right
half — which is what 308's `hwitR` and 310's `S₁`-valued witness are for.

---

## 311 — THE PREFERENCE HYPOTHESIS IS UNNECESSARY.

305 introduced a PREFERRING representative so the block "the class is a right
class" would be closed; 308 kept it as a condition on the witness.  **Neither is
needed.**

The block downstairs is "the class HAS an `inr` preimage" — and that is exactly
the SATURATION of "is `inr`", whose closure **299 already proved**, from the
BISIMULATION.  The bisimulation is a hypothesis the acyclic case (297) needs
regardless, so this costs nothing new and removes a hypothesis that had to be
threaded through every node of the induction.

The argument downstairs: a class with an `inr` preimage `u` has its dynamics
witnessed by SOME preimage `s`, possibly a left one.  **It does not matter.**
`u` and `s` are in the same class, so the bisimulation gives `u` a matching
step; the right half is closed upstairs, so `u`'s step lands right; and the two
steps agree after `j`.  The target class therefore has an `inr` preimage —
established without ever asking which preimage the quotient chose.

`right_block_closed_bisim`, `propext` ALONE.

**What this says about 305–311.**  305 raised an obligation (a global leaf
ordering), 307 shrank it (a per-node witness property), 311 deleted it.  Three
iterations chasing something that was an artefact of stating the block in terms
of a CHOICE rather than in terms of the QUOTIENT.  The lesson is the same one
307 taught in a different key: **when a hypothesis needs threading everywhere,
suspect the definition it serves.**

**Odds: 99%, HELD.**  A standing obligation eliminated rather than discharged,
which is better, but no new ground taken.

**Next.**  The induction on `Exp`, now with one fewer hypothesis to construct at
each node: `hout`, the witness, and the bisimulation — all three of which the
parent supplies to the child directly, since `wh` keeps the state type and
`ite`/`seq` compose `j` with an injection.

---

## 312 — `hbisim` TRANSPORTS THROUGH `ite`, AND NOT THROUGH `wh` OR `seq`.

Assembling the induction, `hbisim` is needed at each `ite`/`seq` node by 311,
and the recursive calls need it for the SUB-automata.  Whether it transports
splits:

**Through `ite` it does, because A SUM CHANGES NOTHING.**  A left state's
transitions in `sumGSystem L R` are exactly `L`'s, retargeted; agreeing in the
sum is agreeing in `L`.  `sum_bisim_restrict`, `propext` alone.

**Through `wh` and `seq` it does NOT**, for the same reason in both: those
constructors ADD transitions to the sub-automaton — back edges for `wh`, the
entry block for `seq` — and **behaviour in the WHOLE can agree where behaviour
in the PART does not.**  Concretely for `seq`: let `s, t` be left states with
`j (inl s) = j (inl t)`; suppose `L` fires at `s` and not at `t`, and `t`
instead takes an `R`-entry step whose target lands in the same class as `s`'s
target.  They agree in `seqGSystem` and differ in `L` — `s` steps, `t` does not.
This needs an `L`-state and an `R`-state to be bisimilar, which nothing forbids.
`wh` is the same with back edges in place of the entry block.

### This is 298's second obstruction, not gone

302 established the recursion is well-founded downstairs.  **It did not remove
the bisimulation-transport problem, and I did not check that it had.**  Moving
downstairs LOCALISED the obstruction — it is now exactly "`hbisim` for `g` does
not give `hbisim` for `g`'s sub-automata under `wh` and `seq`" — but it is the
same obstruction 298 named.

**Candidate fix**: carry `hbisim` for EVERY sub-automaton, as a predicate
`BisimAll g j` defined by recursion on `g` conjoining each node's own `hbisim`
with its children's.  Definable, and each case can destruct it.  The cost moves
to the FINAL application: it must supply a quotient respecting every
sub-automaton's bisimilarity **while still identifying the two start states**.
Whether such a quotient exists is a genuine open question and is the same
tension as the "destructive merge" of 290 — a quotient coarse enough to do its
job and fine enough to preserve structure.

**Odds: 98%** (−1).  An obstruction I had treated as resolved is not, and the
correction is mine to make: 302 answered the well-foundedness fork and I let
that stand in for the transport question, which it never addressed.  One
compiled lemma (the `ite` half) against one re-opened problem.

**Next.**  Define `BisimAll` and carry it through the induction — that at least
makes the five cases compose — and then attack the existence question it
creates, which is the real remainder.

---

## 313 — HOW NARROW 312's CORNER ACTUALLY IS.

312 said `hbisim` does not transport through `wh` or `seq`.  True, but looser
than the facts, and the correction matters: it is the difference between
"usually broken" and "broken only in a corner one can hope to rule out".

**A layer's added transitions come AFTER the sub-automaton's.**  Both
`loop_core_trans` and `seqGSystem` APPEND the entry block to the component's own
list, and `firstMatch` scans in order.  So **wherever the component FIRES, the
composite takes the component's step, unchanged** — `firstMatch_append_left` and
`wh_step_eq_body_step`, with no hypothesis about halts or guards at all.

So the divergence 312 described cannot happen at a world where BOTH states'
components fire: there the two behaviours are literally the same steps.  It
requires

  * a world where ONE component fires and the OTHER does not, AND
  * the second state's ENTRY step to match the first's component step in BOTH
    action and target class.

That is far narrower than 312 stated.  It is a coincidence between an internal
step and an entry step — and the entry block is SHARED across the whole layer,
so the coincidence has to hold against a fixed list, not an arbitrary one.

**Odds: 98%, HELD.**  Narrowing an obstruction is not removing it, and I have
been burned this week by treating the two as the same (312's own correction of
302).  The number moves when the corner is excluded or exhibited, not before.

**Next.**  MEASURE it.  Enumerate small expressions, build their Thompson
automata, compute the coarsest bisimulation of the whole, and check whether it
ever identifies two states of a sub-automaton that are NOT bisimilar within that
sub-automaton.  If it never does, `hbisim` transports in practice and 312's
worry is theoretical; if it does, the witness is the counterexample that decides
the shape of the fix.  **Rust, per the standing mandate — a new mode in the
existing harness, not a script.**

---

## 314 — MEASURED: 312's CORNER IS INHABITED, AND MINIMALLY.

New Rust mode `PAD_BISIM_TRANSPORT` (per the standing mandate — a mode in the
existing harness, not a script).  Build the Thompson closure by depth; at every
composite, compare the coarsest bisimulation of the WHOLE against each
component's own.  The composite is checked BEFORE canonicalisation, since
`canon` renumbers states and would destroy the alignment between a component's
indices and its offset.

    BISIM TRANSPORT: 436 700 component-checks, 1392 violations  (~0.3%)
    FIRST VIOLATION — wh, at k = 2:
      part  = seq (act a) (act a):  q0 --a--> q1 --halt-->,   q0 ≁ q1
      whole = wh 1 (seq (act a) (act a)):  back edge q1 --a--> q0,
              so both states do `a` forever and q0 ~ q1

**312's obstruction is real, it is not a corner, and it appears at TWO STATES.**
It also survives the harness's action-blindness: both transitions carry the same
`a`, so distinguishing actions does not remove it.  313's narrowing was correct
about the mechanism and wrong to imply rarity mattered — one example is enough.

**What this kills.**  The `BisimAll` plan as framed in 312: carrying `hbisim`
for every sub-automaton is not something the COARSEST bisimulation provides, and
the coarsest is what "the quotient" has meant throughout.

**What it opens, and it is not nothing.**  *We never needed the minimal
quotient.*  Completeness needs SOME quotient that identifies the two start
states and is solvable.  In this very example, refusing to merge `q0` and `q1`
leaves the Thompson automaton itself — solvable by construction.  So the object
to look for is the coarsest relation that is a bisimulation, RESPECTS EVERY
SUB-AUTOMATON, and still identifies the starts.  Whether the third survives the
second is the question 312 should have asked and this iteration makes concrete.

**Odds: 98%, HELD.**  A suspected obstruction confirmed inhabited — which 312
already priced — against a genuine out that the confirmation itself exposed.
The measurement cost one iteration and settled what reasoning had been circling
for three.

**Next.**  Does the sub-automaton-respecting bisimulation still identify the two
start states?  Measurable with the same machinery: build `sum(Thompson e,
Thompson f)` for semantically-equal `e, f`, compute the finest
sub-automaton-respecting bisimulation, and check whether the starts land
together.

---

## 315 — 311 WAS A REGRESSION.  THE PREFERENCE ROUTE IS BISIMULATION-FREE.

311 removed 305/308's PREFERENCE hypothesis by proving the split's closure from
the BISIMULATION instead.  That looked like a simplification and read like one
for four iterations.  **314 measured what it cost**: `hbisim` does not transport
from a composite to its components and fails at TWO STATES, so a route needing
`hbisim` at every node of a recursion over sub-expressions cannot work.

**Preference needs no transport, because it is not a property the quotient must
happen to have — it is a property of the WITNESS WE CHOOSE.**  The quotient's
dynamics at a class is DEFINED from a witness; every preimage of a class is
behaviourally equivalent, so any choice yields a correct quotient.  We are free
to choose, and choosing right is a CONSTRUCTION rather than a hope.  That is the
difference between the two routes, and it is why the one that looked harder is
the one that works.

**And the construction reduces to two facts, both proved, both axiom-free.**
Weight states so that at the node in question every RIGHT state outweighs every
LEFT state; take the witness of maximal weight in its class.  Then:

  * `max_is_inr` — a class containing a right state has a RIGHT witness.  This
    IS the preference hypothesis.
  * `max_inl_all_inl` — a class whose witness is LEFT has ALL members left.
    This is why the order RESTRICTS to the left half at an inner node, which is
    what lets the recursion continue.

Everything else 305 called a "leaf ordering" is arranging such a weight by
recursion on the expression, and these two lemmas say exactly what that
recursion must supply: `hlt` at each node, and nothing more.

**Odds: 99%** (+1, restoring 312's drop).  The obstruction that caused the drop
is now routed around rather than fought, and the route's two load-bearing facts
are proved with no axioms at all.  312's penalty was for a problem I no longer
need to solve.

**A note on the four iterations.**  311 → 314 was not wasted: 311's bisimulation
argument is still the *right* one wherever `hbisim` IS available, and 314's
harness mode is reusable.  But the lesson is sharp — **a hypothesis that can be
CONSTRUCTED beats one that must be INHERITED, even when the second looks
weaker.**

**Next.**  Build the weight by recursion on the expression: `test`/`act` give
anything, `ite`/`seq` give left-then-right with a strict offset, `wh` inherits
its body's.

---

## 316 — THE WEIGHT, BY RECURSION ON THE EXPRESSION.  305's OBLIGATION IS DISCHARGED.

315 reduced 305's "leaf ordering" to supplying, at each `ite`/`seq` node, a
weight in which every RIGHT state outweighs every LEFT one.  Built:

  * the recursion must carry a BOUND alongside the weight — to place the right
    half strictly above the left, one has to know where the left half ENDS — so
    `stateWeight g` returns a PAIR, weight and bound, built together;
  * `test` has no states, `act` has one, both bound `0`;
  * `ite` and `seq` place the left half at its own weights and the right half
    OFFSET past the left's bound, so **the strict inequality is by construction
    rather than by comparison**;
  * `wh` inherits its body's unchanged — a loop adds transitions, never states,
    which is the same fact `LoopLayer.states_eq` records.

**That `ite` and `seq` get the IDENTICAL clause is 289's observation once more**:
they differ in what they connect, never in what states they have.

`stateWeight`, `stateWeight_le`, `stateWeight_ite_lt`, `stateWeight_seq_lt`.

**So 305's obligation — raised, shrunk by 307, deleted by 311, resurrected by
314 — is now DISCHARGED**, and by construction rather than by hypothesis.  The
cycle is worth naming: an obligation that keeps coming back is usually real, and
the versions of it that "dissolve" are usually the ones stated in terms of
something incidental.

**Odds: 99%, HELD.**

**What is left of the whole thing**

  1. **the witness selection** — pick, in each class, a preimage of maximal
     `stateWeight`; `minOf1`/`minOfList` (264) already give maxima over a list,
     and the state list is finite;
  2. **the induction on `Exp`**, assembling 307-310's five witness-form cases
     with `max_is_inr` (315) supplying each node's preference from (1) and
     `max_inl_all_inl` (315) letting the recursion descend into the left half;
  3. **the connection to `sumQuotientSolvable_of_certificate`**.

**Next.**  (1) — the witness selection, which is the last construction; (2) and
(3) are assembly.

---

## 317 — THE WITNESS SELECTION.  EVERY CONSTRUCTION IS NOW DONE.

316 built the weight; what remained was to pick, in each class, a preimage of
MAXIMAL weight.  264 built minima over a list of NATURALS for `hcollapse`'s
acyclic case; the natural object here is an ARGMAX over a list of STATES, and
carrying the element rather than its weight is worth the separate development —
it avoids having to recover a witness from an achieved minimum afterwards.

`argMax` with `argMax_start`, `argMax_or`, `argMax_ge`, and
**`exists_max_witness`: a maximal witness exists in every inhabited class.**

**Note the shape of the hypothesis.**  The lemma takes `s₀ ∈ L` with
`j s₀ = c` rather than asserting the class is nonempty.  The caller always has
that preimage in hand — a class IS the image of something — and asking for it
keeps the conclusion free of any choice the caller cannot see.  That is 307's
lesson applied before the fact rather than after: **state the hypothesis in the
form the call site can actually supply.**

### Every construction the proof needs is now built

    the weight                   stateWeight            (316)
    right outweighs left         stateWeight_ite/seq_lt (316)
    max witness ⇒ preference     max_is_inr             (315)
    left witness ⇒ all left      max_inl_all_inl        (315)
    a maximal witness exists     exists_max_witness     (317)
    the five case lemmas         307-310

**What is left is ASSEMBLY**: the induction on `Exp` tying the five cases
together, and the connection to `sumQuotientSolvable_of_certificate`.

**Odds: 99%, HELD.**  Every piece is built and nothing is assumed that cannot be
supplied — but assembly has surfaced genuine mismatches twice in this series
(283, 305), and once produced a theorem that could not be instantiated at all
(307).  The number moves when the induction compiles.

**Next.**  The induction on `Exp`.

---

## 318 — THE WITNESS BUNDLE, AND THE FIRST THREE CASES ON IT.

Assembling the induction shows the 307-form witness is not quite enough.  The
recursive call needs two things the case lemmas were not passing on:

  * **`j s = c`** — that the witness really is a PREIMAGE of the class.  The
    cases never used it; the IH does.
  * **MAXIMALITY** of the witness in its class — which is how 315–317 deliver
    each node's preference.

Rather than thread four conjuncts through five lemmas by hand, the bundle is
named.  **`QuotWit core w Qsys B j`**: every class outside the block is carried
by a preimage of MAXIMAL WEIGHT, and the quotient's dynamics there is that
preimage's.

**Maximality is stated over the TYPE, not over the state list** — that is what
the cases consume, and it keeps the finiteness bookkeeping in ONE place (the
eventual top-level construction) instead of in every case.  317's
`exists_max_witness` supplies it from a list when the time comes.

`quotient_layered_test''`, `quotient_layered_act''`, `quotient_layered_wh''`.
All three compiled first try.

**Why `wh` costs nothing extra.**  Its base's bundle inherits BOTH new conjuncts
from the parent's — the preimage fact verbatim, and maximality because
`stateWeight (.wh b e) = stateWeight e` BY DEFINITION.  A loop adds transitions,
never states, so it cannot change the weights.  The same fact that made
`LoopLayer.states_eq` `rfl` makes this free.

**Odds: 99%, HELD.**

**Next.**  `ite` and `seq` on the bundle — there maximality must transport along
an INJECTION rather than an identity, which 316's definition was built to make
immediate: `stateWeight (.ite b e f) (inl u) = stateWeight e u`, so a maximal
`inl` witness upstairs is a maximal witness downstairs.  Then the induction.

---

## 319 — `hout` IS FALSE IN THE CASE OF INTEREST.

Attempting the `ite` case on 318's bundle hits a mismatch, and it is not
mechanical.

**Every case lemma carries `hout : ∀ s, ¬ B (j s)`** — "the block misses the
image".  It is what discharges `LayeredOn.loop`'s requirement that a layer's
entry targets lie OUTSIDE the block, and the analogous condition on base
targets.  It has been in the shape since 303.

**The split makes it false.**  `LayeredOn.split` hands its second obligation the
block `P ∨ C`.  Split `ite b e f` at the RIGHT classes and the `e`-call's block
contains every class with an `inr` preimage — so `hout` for `j ∘ inl` fails at
exactly those `e`-states whose class also contains an `f`-state.  Split at the
LEFT classes instead and the failure moves to the `f`-call, symmetrically.
**Whichever way the split goes, the second call's `hout` fails on
cross-half-identified classes.**

**And those are not an edge case — they are the point.**  In the completeness
application `e ≈ f`, so essentially every reachable class has preimages in BOTH
halves.  The hypothesis threaded through the entire induction is false precisely
where the theorem is needed.

### Why it bites, concretely

Inside `e`, a `wh`'s shared entry list may have targets whose classes lie in the
block.  `LayeredOn.loop` demands they do not.  `LayeredOn.seq` demands they ALL
do.  **A shared entry list with SOME targets in the block and some outside fits
neither constructor** — and nothing rules that out.

### Resolution direction

If an entry lands in the block, the back edge exits into already-solved
territory, so relative to the block the region has no cycle through that entry —
which is `acyclic`-relative territory (288's `solExt`), not `loop` territory.
So the constructor that applies depends on WHERE THE ENTRY LANDS, and the mixed
case needs either a constructor that splits the entry list or a prior
observation that mixing cannot occur.

**Odds: 97%** (−1).  A hypothesis carried since 303 is false in the target case,
and the fix is at the level of the case lemmas' shape rather than their proofs.
This is the third time assembly has surfaced a real mismatch (283, 305, now
319), which is exactly why I have refused to price assembly as free — but it is
still a genuine setback, and a larger one than either earlier instance because
it touches every case.

**Next.**  Weaken `hout` to what the cases actually NEED, per case: `loop` needs
its entry outside the block, `seq` needs its entry inside, and the choice
between them is a property of the layer, not of the whole induction.  Decide
whether a mixed entry list can occur — measurable with 314's harness — before
designing a constructor for it.

---

## 320 — MEASURED: CROSS-CLASS IDENTIFICATION IS COMMON, NOT EXOTIC.

319 sharpened to this: `LayeredOn.loop`'s `hentry`/`hclosed` are conditions on
CLASSES, not on transitions.  A loop body's transitions stay inside the body —
but a body state's CLASS can contain a state from OUTSIDE it, and then the class
lies in a block the loop is supposed to avoid.  So the decisive question is not
about steps at all: **does a component's states get identified with
non-component states?**

New mode `PAD_CROSS_CLASS`:

    1570 components, 251 with a state identified outside the component (16.0%)
    FIRST: ite g (act a) (act a) — the two halves' single states are bisimilar

**Common, and trivially so.**  The smallest example is two identical branches.
And in the completeness application `e ≈ f`, so it is not 16% but essentially
universal.

**So 319's concern is confirmed at the level it was raised**: the class-level
conditions will fail routinely, and the `hout`-carrying shape cannot be patched
by choosing the split direction more cleverly.

**What is NOT yet settled, and it is the whole question.**  Cross-class
identification makes the block INTERSECT the image; it does not by itself make
an entry list MIXED.  If ALL of a component's classes are in the block, a `wh`'s
entries are all in it too — that is `seq`-shaped, and fine.  If NONE are, it is
`loop`-shaped, and fine.  **Only a genuinely SPLIT entry list fits neither**, and
whether that occurs is one more measurement, not an inference from 16%.

**Odds: 97%, HELD.**  The measurement confirmed the mechanism and did not
resolve the question — which is what it was for.  Confirming a concern is not
the same as confirming the failure it points at, and 313→314 already taught me
not to conflate those.

**Next.**  Measure MIXEDNESS directly: for a `wh` inside a composite, and the
block "classes with a preimage in the other half", are the entry targets' classes
ever split between block and non-block?

---

## 321 — MEASURED: SPLIT ENTRY LISTS OCCUR.  THE CONSTRUCTOR SET IS INCOMPLETE.

320 left the decisive question open: cross-class identification makes the block
INTERSECT a component's image, but only a genuinely SPLIT entry list fits
neither `loop` nor `seq`.  New mode `PAD_MIXED_ENTRY` builds `ite g (wh g2 body) r`,
takes the block to be the classes with a RIGHT-half preimage, and asks whether
the `wh`'s back-edge targets straddle it.

    139 200 (wh-in-ite) configurations
     19 200 with more than one distinct entry target
        744 with a SPLIT entry list  —  0.53% of all, 3.9% of those that could

    FIRST — guard 11, entry targets {q0, q1}
      body        q0 halts always;  q1 stuck
      wh 11 body  q0 -a0-> q0,  q0 -a1-> q1
      right       one stuck state q2
      so q1 ~ q2 (both stuck, never halting) and the block {q1,q2}
      contains q1 but NOT q0 — the entry list straddles it

**So 319's gap is real, not hypothetical.**  A shared entry list can have some
targets in the block and some outside, and the constructor set covers neither
that configuration nor any refinement of it: `LayeredOn.loop` requires all
entries outside, `LayeredOn.seq` requires all inside, and the entries are ONE
list whose order matters, so they cannot simply be separated — guarded folds are
order-sensitive and the entry guards need not be disjoint.

**Odds: 96%** (−1).  This is the failure the concern pointed at, now exhibited,
which is a different thing from 320's confirmation of the mechanism — and I
priced them differently on purpose.  The constructor set needs either a new
case or a reason the configuration cannot arise where it matters; neither is in
hand.

**What is NOT ruled out.**  The example is degenerate in a suggestive way: the
in-block entry target `q1` is STUCK — it neither halts nor steps.  If split
entry lists only ever arise with dead targets, the fix could be a pruning
argument rather than a new constructor.  That is the next measurement, and it is
cheap: re-run counting only splits whose in-block targets are live.

**Next.**  Are the in-block targets of a split entry list ever LIVE?

---

## 322 — MEASURED: EVERY SPLIT ENTRY LIST IS MADE OF DEAD TARGETS.

321 exhibited the configuration the constructor set cannot express and noted its
example was degenerate in a suggestive way — the in-block entry target was
STUCK.  Extended `PAD_MIXED_ENTRY` with backward reachability from halting
states (`productive_states`) and re-ran:

    744 split entry lists
      0 with a LIVE (productive) in-block entry target

**Every one of them has only NON-PRODUCTIVE targets in the block.**

### Why that closes the gap rather than dodging it

A non-productive state is behaviourally `0`.  `LayeredOn.loop`'s
`∀ tr ∈ entry, ¬ P tr.2.2` exists to guarantee the solution's equation at a
non-block state references only non-block values — so that the family
`stdL · F` and the actual `sol` agree at every target.  **If the offending
target is behaviourally `0`, they agree anyway**: `sol₀ t ≈ 0` and
`stdL t ; F ≈ 0 ; F ≈ 0`.  The congruence goes through unchanged.

So the requirement weakens from

    every entry target lies outside the block

to

    every entry target lies outside the block OR is behaviourally zero

which is a side condition on the LAYER, provable where it holds, rather than a
new constructor.  And 283's selection machinery is already the right tool for
the `≈ 0` half.

**Odds: 97%** (+1, undoing 321's drop).  The exhibited failure is confined to a
mechanism with a known fix, which is a materially better position than 321's —
but the fix is not built and the measurement is one shape (`wh`-in-`ite`) at
NA = 2, k ≤ 5, so it is evidence and not a theorem.

**The conjecture it suggests**, worth stating because it would make the side
condition automatic: *a LIVE entry target cannot lie in the block.*  Intuition —
if it did, the loop would return to it and continue productively, so the loop's
behaviour is realised in the other half too, which forces enough further
identification that the entry list stops being split.  Unproved, and the
measurement is consistent with it.

**Next.**  Weaken `LayeredOn.loop`'s entry condition to "outside the block or
behaviourally zero", and re-prove the loop case of `layeredOn_has_solution` with
the `≈ 0` targets discharged by `fold_congr_step`.

---

## 323 — A STUCK STATE'S SOLUTION IS ZERO, AND THAT IS THE WEAKENING.

322 measured that every SPLIT entry list has only NON-PRODUCTIVE targets in the
block, and argued the requirement weakens to "outside the block OR behaviourally
zero".  Here is the fact that makes it sound.

`LayeredOn.loop`'s entry condition exists so that, at a non-block state, the
family `stdL · F` and the actual `sol` agree at every target.  **They agree at a
target where BOTH are zero** — and a target that cannot move and cannot halt
forces exactly that of ANY solution: its equation collapses to
`paramFallback 0 F`, which is `0 ; F`, which is `0` by `s2`.

`stuck_solution_zero` — **NO AXIOMS AT ALL** — and `zero_targets_agree`, which
needs no hypothesis about the block whatsoever.

**So the offending targets need no new constructor.**  They need the congruence
to be `EquivBA` rather than syntactic — which `fold_congr_step` (292) already
provides — plus these two lemmas to supply the `≈ 0` facts.  **The
list-versus-selection trade for the FOURTH time, and always in the same
direction: 283, 292, 299, 323.**  At this point it is not a trick but the
grain of the material: *a guarded fold is what it selects, and any hypothesis
phrased about what it LISTS is stronger than the proof needs.*

**Scope, stated.**  The lemma covers a state that is IMMEDIATELY stuck.  322's
non-productive states are more general — one may reach a stuck state after
several steps — and that generalisation is a separate induction along the
productivity ordering.  Not needed until the plumbing demands it, and 322's
first example was immediately stuck.

**Odds: 97%, HELD.**  The enabling lemma for the weakening is proved and free of
axioms; the weakening itself is not yet threaded through `LayeredOn.loop` and
`layeredOn_has_solution`.

**Next.**  Thread it: weaken the constructor's entry field to admit stuck
targets, and re-prove the loop case with `guardedFold_trans_congr` replaced by
`fold_congr_step` and the stuck targets discharged by 323.

---

## 324 — THE CONGRUENCE THAT ADMITS ZERO TARGETS, AND WHERE THE ZEROS COME FROM.

323 supplied the two `≈ 0` facts; `congr_with_zero_targets` consumes them.  Two
labellings give equivalent folds as soon as, at every SELECTED target, they are
either literally equal or BOTH ZERO.  First disjunct: the old requirement.
Second: 322's escape hatch.

**And the missing piece is now identifiable, which it was not two iterations
ago.**  In the loop case the two labellings are `sol` — which is `sol₀` on the
block — and the family `solB · W · F`, which is `sol₀ · W · F` there.  They agree
only if `sol₀` is ZERO at the target, and `sol₀` is an ARBITRARY input to
`layeredOn_has_solution`, so nothing forces it.

**The fix is to strengthen the contract**: require `sol₀` to SOLVE the block,
not merely to be some function on it.  Then 323 applies to `sol₀` at a stuck
target and delivers `sol₀ t ≈ 0` for free.

**And the hypothesis is available at every call site** — checked, not assumed:

  * `split`'s first subderivation already PRODUCES a solution on `C`, and its
    second call's `sol₀` is exactly that;
  * `acyclic` (via `solExtF_has_solution`) leaves `sol₀` untouched on the block,
    so the hypothesis passes straight through;
  * `loop` and `seq` likewise pass it down.

So the strengthening costs nothing at the call sites and buys the zeros.  **That
it was not needed until now is exactly why the contract was weaker: the block's
values were never READ before, only carried.**  322's escape hatch is the first
thing that reads them.

**Odds: 97%, HELD.**  The consuming step is proved and the missing hypothesis is
identified with its availability verified case by case — but the contract change
is not made and the loop case is not re-proved.

**Next.**  Strengthen `layeredOn_has_solution`'s contract to "`sol₀` solves the
block", re-prove its four cases under it (three are pass-through), then weaken
`LayeredOn.loop`'s entry field and close 319.

---

## 325 — THE ZERO PROPAGATES; THE HYPOTHESIS DOES NOT COMPOSE THROUGH `split`.

324 identified the missing hypothesis as "`sol₀` is zero at stuck block states".
Two things about it.

**Good — zero propagates through the loop case's family.**  That family is
`(sol₀ t ; W) ; F`, and if `sol₀ t ≈ 0` the whole thing is `0` by `s2` twice.
So at a stuck block target BOTH labellings are zero and 324's congruence fires.
`seq_seq_zero`, **no axioms**.

**Not good — the hypothesis does NOT compose through `split`'s FIRST call.**
`split` passes the OUTER `sol₀` to a call whose block is `¬C`, and the
hypothesis is known only on `P`.  `P ∩ C = ∅` gives `P ⊆ ¬C`, so it covers PART
of the new block and not the rest — and `sol₀` is arbitrary there, so nothing
supplies the remainder.  324 checked composition at three call sites and I
believed it; this is the fourth, and it fails.

**The fix, and its cost.**  NORMALISE: pass `fun t => if stuck t then 0 else
sol₀ t` to the first call, which satisfies the hypothesis by construction.  The
cost is that the theorem's conclusion `sol s = sol₀ s` on the block must weaken
to `EquivBA` — the normalised input differs from `sol₀` exactly at stuck block
states, where the hypothesis itself says the two are equivalent.

**Affordable for the usual reason**: the block's values are only ever CONSUMED
through a guarded fold, and `fold_congr_step` compares folds up to `EquivBA`.
**Fifth instance of the same trade** (283, 292, 299, 323, 325).  What it costs
concretely is re-proving `split`'s gluing step, which currently uses `rw` on a
syntactic equality.

**Odds: 97%, HELD.**  One axiom-free lemma, and a composition failure found by
checking the fourth call site after asserting three — which is the right way
round, but 324 should have checked all four before claiming it composed.

**Next.**  Weaken the conclusion to `EquivBA` on the block, normalise at
`split`'s first call, and re-prove the gluing step with `fold_congr_step`.

---

## 326 — THE REDESIGN LANDS.  319's GAP IS CLOSED AT THE SOLUTION LEVEL.

All four pieces 322–325 identified, in one compiling change:

  * **`StuckAt`** — a state that can neither move nor halt — and
    `fold_congr_list`, the list-form congruence the new proofs need;
  * **`LayeredOn.loop` weakened**: its entry and base targets may now lie in the
    block PROVIDED they are stuck.  That is 322's escape hatch, made a
    constructor field;
  * **`hz` added to `layeredOn_has_solution`**: `sol₀` is ZERO at stuck block
    states, which 323 shows is forced of any real solution;
  * **the conclusion weakened to `EquivBA` on the block**, which is what lets
    `split` NORMALISE its first call's input to zero at stuck states — 325's
    unavoidable step.

All four cases re-proved under the new contract.  The `split` case now
establishes `hz` for BOTH its calls: for `P` states from the outer hypothesis
through the normalisation, and for `C` states from `stuck_solution_zero` applied
to its first subderivation's own solution — the block's values being read for
the first time, exactly as 324 predicted.

**Zero errors, zero `sorryAx`, 10 799 lines.**

**Odds: 98%** (+1).  319's gap — a hypothesis carried since 303 and false in the
target case — is closed where it was diagnosed.  The remaining trace of it is in
the CASE LEMMAS (`quotient_layered_wh''` and friends still carry `hout` and
supply `Or.inl`), where the same weakening now applies because the constructor
accepts it.

**Next.**  Weaken `hout` in the case lemmas from "the block misses the image" to
"misses it, or the offending target is stuck", and re-attempt the `ite` case
that 319 blocked.

---

## 327 — THE BLANKET `hout` IS GONE FROM THE `wh` CASE.

319 found "the block misses the image" false in the target case; 326 made the
constructor accept STUCK targets in the block.  So the case lemma can now ask
for **exactly what the constructor needs and no more**:

    hentry : the disjunction at the ENTRY targets
    hbody  : the disjunction at the BODY's transition targets

instead of `hout : ∀ s, ¬ B (j s)` at every state of the image.

**Why the blanket form was wrong in the same way 307's was.**  A hypothesis that
quantifies over more than the proof CONSUMES can be true of the proof and false
at the call site — 307's version was unusable because its type could not be
inhabited, this one because its statement is false where it is needed.  Both are
the same failure to state the hypothesis in the form the caller can supply.

`quotient_layered_wh''` recompiled on the new signature; the two uses of `hout`
become direct applications of the precise hypotheses, with the body one applied
at the class's own witness.

**Odds: 98%, HELD.**  A clean weakening that removes a false hypothesis, but
whether the precise conditions are SUPPLYABLE at the `ite` call site is now the
question — and it is a sharper one than 319's, since 322 measured the entry half
favourably and said nothing about the body half.

**Next.**  The same weakening for the `seq` case, then the `ite` assembly with
the two precise conditions — where `hentry` is 322's measured-favourable half
and `hbody` is unmeasured.

---

## 328 — MEASURED: `hbody` FAILS, AND SO DOES THE ACYCLIC ESCAPE.  THE ROOT CAUSE IS THE FIXED BLOCK SOLUTION.

New mode `PAD_BODY_COND`, two numbers:

    BODY COND        70 632 steps from a class outside the block;
                     11 264 land inside it (15.95%), 10 704 of those LIVE (15.15%)
    NON-BLOCK REGION 57 600 regions, 13 304 contain a cycle (23.10%)

**`hbody` fails comprehensively**, and trivially: the first violation is the left
half's halting state being bisimilar to the right half's.  322's stuck-target
escape hatch covers ENTRY lists and does nothing for BODY transitions.

**And the acyclic escape is not available either.**  288's `solExt` tolerates
steps INTO the block — so if the non-block region were acyclic, `hbody`'s failure
would not matter.  It is cyclic 23% of the time, so the loop constructor is
genuinely needed, and it is the loop constructor that cannot take those steps.

### The root cause, and it is not the constructors

`wh b D`'s solution requires the body to be solved PARAMETRICALLY in the loop's
continuation — that is what `withContinuation` does, multiplying the whole
solution by `W`.  A block whose solution is a FIXED function cannot be
multiplied: its values do not scale with the continuation.  But **they should**
— a run that enters the block and later halts must continue with the ambient
finish, exactly like everything else.

**So the fix is to carry STANDARD solutions rather than fixed ones**: the
contract should produce a `std` with "`std · F` solves at finish `F`", and
should RECEIVE the block's solution in the same form.  Then the loop case
multiplies uniformly and block targets stop being special.  284 considered this
shape and set it aside because of blocks; 328 says blocks are precisely why it
is needed.

`split` composes under it — the first call produces a standard `std_C`, the
second receives it — and the acyclic case should too, since `solExt`'s fold
carries `· F` through every branch by `guardedFold_seq_right`.

**Odds: 97%** (−1).  Two measured failures against one redesign that addresses
the cause rather than the symptom.  The current shape is wrong in a way three
iterations of patching (322, 326, 327) could not fix, and I should have suspected
that when the second patch was needed.

**Next.**  Restate the contract in standard form — `∃ std, ∀ F, (std · F) solves`
— and re-derive the four cases under it.

---

## 329 — RETRACTING 328's REDESIGN, AND WHAT IS ACTUALLY TRUE ABOUT CLOSED BLOCKS.

**328's fix does not work, and saying so before building it is the point of
working it through first.**  The claim was that carrying STANDARD solutions
would let block values scale with the continuation and stop being special.
Worked through: at a block target inside a loop's region, the base's equation at
finish `W ; F` supplies `std₀ t ; (W ; F)`, while the contract fixes the block's
value at the AMBIENT `F`.  **The mismatch survives the reshaping.**

**It survives because it is structural, not notational.**  A state inside a
loop's body has a value that genuinely depends on the loop's continuation — the
run reaches it, the body finishes, the loop re-tests its guard.  Calling such a
state "already solved at the ambient finish" is simply FALSE.  So the fix cannot
be to re-parametrise; it has to be to stop putting such states in the block.

### The fact that makes that tractable

**A block closed under steps is closed under REACHABILITY** (`closed_reaches`),
so **any cycle through a block state lies entirely in the block**
(`closed_scc_saturated`).  A closed block cannot cut a cycle in half: every
strongly connected region is wholly inside it or wholly outside.  **No hypothesis
beyond closure** — both lemmas are axiom-free.

That is exactly the property "the block does not cut through a loop" wants, for
the CYCLIC part.  What it does not give — and what 328 measured — is the
non-cyclic part: a body state that never returns has no forward path back into
the loop, so closure cannot drag the loop in with it, and such a state can sit
in the block while the loop around it does not.

**Odds: 97%, HELD.**  A proposed fix retracted before it was built, against a
free structural fact that constrains where the real fix can live.  The retraction
costs nothing that 328 had not already priced; the SCC fact is new.

**Next.**  The remaining gap is exactly the NON-CYCLIC body states in the block.
Measure how often a loop's body has a block state that is not on any cycle —
that is the residue after `closed_scc_saturated` does its work, and it is a
strictly smaller target than 328's 15%.

---

## 330 — GROUNDING THE TARGET: THE QUOTIENT IS OURS TO CHOOSE.

Went and read `SumQuotientSolvable` rather than reasoning from memory about it,
which I had been doing for twenty-odd iterations.  It asks, for
language-equivalent `e, f`, for

    SOME quotient `Q` of the sum, SOME solution of it, and the two start
    pseudostates identified

— and **nothing about minimality**.  `sumQuotientSolvable_of_certificate` adds
minimality in its `hstart`, but that is a choice made to suit 264's acyclic
pushforward, not a demand of the target.

**So the quotient is OURS TO CHOOSE**, and I have been treating it as given
since 287.  That is the reframing: not "does the collapse decompose?" but
**"can I construct a quotient that decomposes?"**

### First measurement under the finest choice

`min_congruence` is the finest quotient identifying the two starts.
`PAD_MINCONG`:

    50 language-equivalent ordered pairs, 16 with a CONSISTENT congruence
    41 classes total, 25 drawing from ONE half only (61.0%)
    6 of 16 quotients have EVERY class drawing from both halves (37.5%)

**Mixed, and honestly so.**  For 37.5% of the quotients the split is trivial and
319–329's difficulty is empty.  For the rest, 61% of classes still draw from one
half, so the difficulty persists — the finest quotient is not automatically the
convenient one.

**And a caveat worth recording**: 34 of 50 pairs have NO consistent minimal
congruence at all — merging the starts forces merging states whose halts differ
syntactically.  So "finest" is not always available either; the useful quotient
lies somewhere between identity and the full collapse, and finding it is the
new question.

**Odds: 98%** (+1).  A freedom the target grants that I had not been using, found
by reading the definition instead of remembering it — against a measurement
saying the obvious way to use it is not enough.  **The lesson is the cheap one:
re-read the goal periodically; twenty iterations of reasoning from memory cost
more than the two minutes this took.**

**Next.**  What property must a quotient have for the decomposition to work, and
can one with that property always be constructed?  That is a better-posed
question than any asked since 319.

---

## 331 — BLOCKS FOR FREE: THE REACHABLE CLOSURE OF ANYTHING IS CLOSED.

330 reframed the question from "does the collapse decompose?" to "what shape of
decomposition can we always arrange?".  The natural answer is **not the
EXPRESSION's shape** — that is what 319–329 kept fighting — but the quotient's
own **SCC CONDENSATION**: solve bottom-up, giving each strongly connected region
the ones below it as a block.

Two things make it attractive.  329 shows such a block cannot cut a cycle in
half.  And the blocks come for free: **the set of states reachable from ANY set
is closed** (`reachClosure_closed`, with `Reaches.snoc`), so **every down-set of
the condensation is a legal block with no further argument**.  Both axiom-free.

**Why this is a better frame than the expression one.**  The expression's shape
imposes blocks (a `seq`'s right half, an `ite`'s branch) that the quotient has
no reason to respect — which is exactly what 319 found and 320/321/328 measured.
The condensation's blocks are defined BY the quotient, so they respect it by
construction.  Choosing the decomposition to fit the object rather than the
object's history is the move 330's freedom makes available.

**The obstacle, named so it is not rediscovered.**  Exits from a strongly
connected region into the block are what `LayeredOn.seq` is FOR — its entry
points into the block by design (305/306).  But `SeqLayer`'s shape demands those
exits be ONE SHARED LIST gated by each state's own halt.  Arbitrary exits from
an SCC are not of that shape.  In a Thompson automaton they are, since they come
from `seq` constructions; **whether they survive quotienting is the next
measurement.**

**Odds: 98%, HELD.**  A cleaner frame with its enabling lemmas proved and its
obstacle named — but the obstacle is the same KIND that has cost the last twelve
iterations, and I will not price it before measuring.

**Next.**  Do the SCC exits of a quotient have the `SeqLayer` shape — one shared
halt-gated entry list?

---

## 332 — MEASURED: SCC EXITS ARE PER-ATOM SINGLE-VALUED.  331's OBSTACLE DOES NOT BITE.

331 named the obstacle to the condensation frame: `SeqLayer` demands an SCC's
exits form ONE SHARED entry list.  The sharpest necessary condition of that, in
the per-atom representation, is that **all states of an SCC exiting on the SAME
ATOM exit to the SAME TARGET**.  `PAD_SCC_EXIT`, measured on the QUOTIENT since
that is what the proof must decompose:

    NA = 2, K = 6:  672 SCCs, 120 with an exit, 0 conflicts
    NA = 3, K = 6:  302 SCCs, 0 with an exit   — UNINFORMATIVE

**Zero conflicts in 120 exiting SCCs.**  Every one has per-atom single-valued
exits, which is exactly what a shared entry list needs.

**And the NA = 3 run tells us nothing** — the closure never reached an automaton
whose quotient has an exiting SCC at that cap.  Reporting it as confirmation
would be reporting the absence of the test as the passing of it.

**Odds: 98%, HELD** — deliberately.  120 samples at ONE atom count is thin
support for a UNIVERSAL claim, and universals are exactly what sampling
confirms worst.  313 called a corner narrow on similar reasoning and 314 found
it inhabited at two states; the difference there was that the claim under test
was existential.  This one moves the number when it is proved or when the sample
is much larger and spans atom counts.

**What the measurement does buy**: the condensation frame's one named obstacle
has no counterexample in the range where the question is even askable, so it is
worth BUILDING rather than worth more measuring.

**Next.**  State the condensation decomposition in Lean: an SCC, the down-set
below it as a block, its exits as a `SeqLayer` into that block, and the
remaining closed region as a `LoopLayerOn`.  331's `reachClosure_closed` gives
the block; 329 gives that it does not cut the cycle.

---

## 333 — THE CONDENSATION FRAME, MADE CONCRETE.

331 proposed it, 332 measured its obstacle away.  The frame is exactly two
moves, both now statable against the existing constructors, both axiom-free:

  * **`layeredOn_split_reach`** — take any set, close it under reachability,
    split there.  331 proves such a set is closed so `LayeredOn.split` accepts it
    with no further argument; 329 adds that it never cuts a cycle.  Every
    down-set of the condensation is a legal block, and the recursion down the
    condensation is this move iterated.
  * **`layeredOn_region`** — a strongly connected region above a block: peel its
    EXITS as a `SeqLayer` into the block (`LayeredOn.seq`, and 332 measured those
    exits per-atom single-valued), leaving a region closed w.r.t. the block, then
    peel that as a `LoopLayerOn`.  **The order is forced, exactly as 305 found:**
    the loop constructor needs its region closed, which it is only after the
    exits are gone.

**Both are two-line compositions, and that is the finding.**  The frame's content
is CHOOSING the decomposition, not proving anything new about it — the
constructors built over 294–326 already accept this shape.  Twelve iterations
were spent making them accept the EXPRESSION's shape, which they never did.

**Odds: 98%, HELD.**  Framing made concrete is not new content, and I said so in
the file rather than letting two short theorems read as progress.

**Next.**  The induction over the condensation, and the construction of the two
layers at each region — neither needs a new constructor, which is what 333
establishes.

## 334 — `split` was too strong, and weakening it closed the condensation induction

**The obstruction, found by building the thing.** 333 said the condensation frame
needed no new constructor. Building the induction refuted that in one step:
`LayeredOn.split` required its peeled set `C` to be closed **absolutely**, and
under that hypothesis the condensation recursion is impossible. Peel the bottom
level, and the block is non-empty; every subsequent peel must be a non-empty
closed set **disjoint from the block** — but a closed set contains everything it
reaches, and every region reaches the bottom. So absolute closure admits exactly
one peel and then jams.

**The fix is one hypothesis.** `C` closed *relative to the block*:

```lean
(∀ s, C s → ∀ … , firstMatch W x (sys.trans s) = some r → C r.2 ∨ P r.2)
```

The solution proof survives untouched — the congruence step needed `sol₂ = sol₁`
at every target of a `C`-state, and that holds on `P` for the same reason it held
on `C` (`hin2` already covers `P ∨ C`; the disjunct just arrives swapped). One
`.symm`. All five existing call sites still go through by `Or.inl`.

**What it unlocks.** With relative closure the peel `C := {lvl = n}` against the
block `P := {lvl < n}` is legal, and the induction closes:

```lean
theorem layeredOn_of_levels (lvl : S → Nat)
    (hmono  : ∀ s …, firstMatch W x (sys.trans s) = some r → lvl r.2 ≤ lvl s)
    (hregion : ∀ n, LayeredOn sys (fun s => ¬ (lvl s = n))) :
    ∀ k n, (∀ s, lvl s < n + k) → LayeredOn sys (fun s => lvl s < n)
```

and its discharge `layeredOn_empty_of_levels`, which gives `LayeredOn sys ∅` —
the **empty** block. Both `[propext, Quot.sound]`, no `choice`, no `sorry`.

**Non-vacuity, checked at the consumer.** `solves_of_levels` feeds the empty
block to `layeredOn_has_solution`, whose conclusion is conditional on `¬ P`;
with `P = False` that condition evaporates and what comes out is an
unconditional full parametric solution — the exact shape `hcollapse` asks for.
An empty block is what makes the theorem say anything.

**`PAD_CONDENSATION` — how much work is left, and it is bounded.**
4000 quotients, 14922 regions:

| measurement | value |
|---|---|
| quotients where the component ordering is not step-monotone | **0** — `hmono` is real |
| max condensation depth (peels the induction makes) | **7** |
| max region size | **3** |
| non-trivial regions | 968 — sizes `1:915  2:52  3:1` |
| single-cycle regions | **967 (99.9%)** |
| richer regions | **1** |

The `hmono` line is the control: region sizes read off a wrong ordering would
measure nothing, so the ordering is checked before anything is reported from it.

The one richer region is `q0: st=[q0,q1,q1] | q1: st=[q0,…]` — a self-loop nested
inside a 2-cycle. `LayeredOn.loop` recurses on `LayeredOn base P`, so loop-over-
loop is already expressible; that case needs nesting, not a new constructor.

**The finding.** Every remaining obligation is now per-region, and a region is at
most three states, 94.5% of them one state with a self-loop. Twelve iterations
(319–330) tried to decompose along the expression's shape; the decomposition the
constructors actually wanted was along the *quotient's own* condensation, and the
only thing standing in its way was a hypothesis strictly stronger than the proof
of `split` ever used.

**Next.** Discharge `hregion` for the single-cycle region — 99.9% of the mass and
the shape `layeredOn_region` was built for.

## 335 — the region hypothesis discharged for the shape that carries 94.5% of it

334 reduced everything to `hregion : ∀ n, LayeredOn sys (fun s => lvl s ≠ n)`.
335 discharges it for the shapes the census says dominate, and fixes the
instantiability defect that would have made the reduction ornamental.

**`layeredOn_region_closed`** — the general region, side conditions named as
properties of the *peeled* system rather than of the expression that built it:

- `hin : ∀ s, ¬P s → ∀ tr ∈ mid.trans s, ¬ P tr.2.2` — the region is closed in
  `mid`, i.e. after the exits have been peeled;
- `hacyc` — `base` is acyclic on the region, i.e. after one loop layer is peeled.

Both of `layeredOn_region`'s awkward hypotheses (`hle`, `hlc`) follow from `hin`,
because `LoopLayerOn.trans_eq` puts `base.trans s` and the gated `loopEntry`
inside `mid.trans s`: `List.mem_append.mpr` on the left for one, on the right
composed with `List.mem_map.mpr` for the other.

**`layeredOn_singleton_region`** — one state with a self-loop. `base.trans t = []`
collapses both side conditions at once: nothing is left to be acyclic about and
closure is vacuous. **Axiom-free** — not even `propext`.

**`layeredOn_level_singleton` / `layeredOn_level_empty`** — the two forms the
induction actually consumes, both axiom-free. The empty level is free (the
complement of the block is empty), and `hregion` quantifies over all `n`, so it
had to be said.

**The instantiability fix.** `hregion`'s block is `lvl s ≠ n`, so its complement
arrives **double-negated** — exactly the defect 307 caught, where a theorem is
true, proved, and unusable. `level_dom` strips it via `Decidable.not_not`, which
for `Nat` equality costs nothing and in particular does **not** pull in `choice`.
`layeredOn_level_singleton` therefore takes `huniq : ∀ s, lvl s = n → s = t` in
the positive form a caller can actually supply.

**Why the singleton peel has no side condition.** Atoms at a singleton region
partition into halt `H`, self-loop `L`, exit `X`. The chain forces
`base.hlt = ⊤`, `b = L`, `mid.hlt = ⊤ ∧ ¬L = H ∪ X`, `h₀ = H`, and
`sys.hlt = mid.hlt ∧ h₀ = H` — consistent with no constraint left over. Guard
order does not matter either: `L` and `X` are disjoint, so `firstMatch` sees the
same thing whichever list is appended first.

**What is NOT covered.** The 53 regions of size ≥ 2 (5.5%). A simple cycle is
fine under `layeredOn_region_closed` — peel exits, peel one back-edge, the
remainder is a path. The single richer region (a self-loop nested in a 2-cycle)
runs into the shared-entry shape 332 measured: `LoopLayerOn`'s `entry` is
appended at EVERY region state, so a loop belonging to one state still has to
appear, syntactically, in the other's transition list.

**Next.** The multi-state cycle: instantiate `layeredOn_region_closed` with the
rank that a peeled simple cycle admits.

## 336 — the chain instantiated on `while p do a`

**`RegionLevel sys lvl n`** packages one level's peel data as a single Prop —
`mid`, `base`, the two layers, closure in `mid`, a rank for `base`. Nothing in it
mentions the expression that built the automaton, which is the whole point of the
condensation frame. With it:

- `layeredOn_of_regionLevel : RegionLevel sys lvl n → LayeredOn sys (lvl · ≠ n)`
- `regionLevel_of_singleton` — the self-loop singleton is regional; `base.trans t = []`
  supplies closure (mid's only edges at `t` are the gated self-loops, targets `t`)
  and the rank (nothing left to rank)
- **`solves_of_region_levels`** — bounded, step-non-increasing `lvl`, every level
  unoccupied or regional ⟹ a full parametric solution. End to end.

**The live risk was satisfiability, and it is now discharged.** `SeqLayer.trans_eq`,
`SeqLayer.hlt_eq` and `LoopLayerOn.trans_eq` are **syntactic** equations on `BExp`s
and lists — not `bval` equations. A frame whose layer equations no real automaton
satisfies would be worth nothing, and nothing proved so far ruled that out. So:

```lean
def demoBase : GSystem Unit Unit Unit := { hlt := fun _ => .one, trans := fun _ => [] , … }
def demoMid  := …  -- one loop layer, gated exactly as LoopLayerOn demands
def demoSys  := …  -- seq layer with an EMPTY exit list

theorem demo_solves : ∃ sol : Unit → Exp Unit Unit,
    ∀ s, EquivBA (sol s) (eqRHSParam demoSys sol (.test .one) s)
```

One state, halting except on `p`, looping to itself on `p` — **`while p do a`**,
the canonical automaton for which the Uniqueness Axiom is invoked. Every layer
equation closes by `rfl` except `sys.trans = mid.trans ++ []`, which is
`(List.append_nil _).symm`. `[propext, Classical.choice, Quot.sound]`, no `sorry`.

**Why the syntactic equations are affordable.** 330 established the target needs
only SOME quotient identifying the two starts — no minimality. A quotient's `hlt`
expressions are therefore ours to choose, so the `and`-shapes the seq and loop
layers demand can be arranged when the quotient is built, rather than discovered
in an automaton handed to us.

**Base-rate control.** `RegionLevel` is not trivially satisfiable. The degenerate
route — peel every transition as an exit, leaving `mid` and `base` empty — dies on
`hentry : ∀ tr ∈ entry, lvl tr.2.2 ≠ n`: a self-loop's target is IN the level, so
self-loops cannot be peeled as exits. The loop layer is forced to do the work.

**Next.** The multi-state cycle instance — the same demo one size up, which is
where `LoopLayerOn`'s shared `entry` first has to carry more than one state.

## 337 — the two-state cycle, and why the shared entry is not an obstruction

336's demo had one state, so `LoopLayerOn`'s shared `entry` never had to
distinguish region states. 337 builds the first case where it does: `none` a
level-0 sink, `some false → some true → some false` a level-1 two-cycle exiting
to the sink. Both levels are shown regional and the chain closes:

```lean
theorem d2_solves : ∃ sol : Option Bool → Exp Unit Unit,
    ∀ s, EquivBA (sol s) (eqRHSParam d2Sys sol (.test .one) s)
```

`[propext, Classical.choice, Quot.sound]`, no `sorry`.

**The mechanism.** 332 measured the shared-entry shape and found 0 conflicts, but
never said *why* it is harmless. Here is why. `LoopLayerOn` appends `entry` at
EVERY region state, so a back-edge belonging to one state appears, syntactically,
in the other's list too. The gate is

```lean
BExp.and (base.hlt s) (BExp.and b tr.1)
```

and `base.hlt` is **per state**. Crucially `LoopLayerOn.hlt_eq` reads
`bval (sys.hlt s) = bval (base.hlt s) && !bval b`, which constrains `base.hlt s`
only where `b` is **false** — on `b`-atoms it is entirely free. So `base.hlt`
doubles as the selector saying at which region states the shared entry actually
fires.

In the instance: `base.hlt (some false) = zero`, so the shared back-edge gate
`zero ∧ p ∧ 1` is unsatisfiable at `t₀` — present but inert — while
`base.hlt (some true) = one` makes the same entry live on `p` at `t₁`. The
spurious edge costs nothing because it can never be taken.

**The exit is real too.** `t₀` never halts and steps unconditionally to `t₁`;
`t₁` halts on `¬p` in `base`, which is exactly where the seq layer's exit to the
sink fires. So this is a while-loop with a two-state body, not a degenerate case.

**What this settles.** The 53 regions of size ≥ 2 that 335 left open have no
shape obstruction — the shared entry was the only structural doubt, and it is a
free parameter, not a constraint. What remains for them is `hacyc`: a rank on the
peeled region, which for a simple cycle is the position along the path (here
`rank t₀ = 1 > 0 = rank t₁`).

**Next.** Whether `hmono` and the per-level peel can be produced *uniformly* from
a quotient, rather than instance by instance — the construction, not the frame.

## 338 — the frame made checkable, and the remainder named

**The problem with the chain as of 337.** Three of its hypotheses quantified over
EVERY atom type `X`, assignment `W` and atom `x`: `hmono`, the region's rank, and
`LoopLayerOn.hlt_eq`. A construction that has to produce them for an arbitrary
quotient cannot discharge that by inspection — it would have to reason about all
possible atom structures at every state. Each now has a syntactic form that
implies it:

- `step_mem` / `mono_of_syntactic` — a `firstMatch` step is a member of the list
  it searched (`firstMatch_mem_of_some`, 264-era), so `hmono` reduces to *no
  syntactic transition raises the level*. **Axiom-free.**
- `rank_of_syntactic` — the same move for the region's rank.
- `LoopLayerOn.ofSyntactic` — the `bval` field follows from the halt shape
  `sys.hlt s = and (base.hlt s) (not b)`, which is what the peel produces anyway.

`SeqLayer` was already syntactic in all four fields. So `RegionLevelSyn` and
`solves_of_syntactic_levels` restate the whole chain as **finite inspection of
transition lists plus `BExp` equations** — nothing about atoms.

**The remainder, as one predicate.**

```lean
def SyntacticallyLayered (sys) : Prop :=
  ∃ (lvl : S → Nat) (B : Nat), (∀ s, lvl s < B) ∧
    (∀ s, ∀ tr ∈ sys.trans s, lvl tr.2.2 ≤ lvl s) ∧
    (∀ n, (∀ s, lvl s ≠ n) ∨ RegionLevelSyn sys lvl n)
```

`solves_of_syntacticallyLayered` is `hsolve` for it. Against the certificate
architecture of 286 that leaves exactly one obligation:

```
every Thompson automaton is SyntacticallyLayered        (hsum — condensation of
                                                          a Thompson automaton)
every SyntacticallyLayered automaton has a solution     PROVED (338)
------------------------------------------------------------------------
the QUOTIENT is SyntacticallyLayered                    OPEN (hcollapse)
```

This is a **different** open statement from 286's. 286 needed the quotient to be
`LayeredL`, whose `sum`/`seq` constructors a quotient does not respect — 287
identified that as the hard part and 319–330 confirmed it. `SyntacticallyLayered`
has no `sum` or `seq` constructor to respect: it asks only for a level function
and a per-level peel, both of which are properties of the quotient's own graph.

**Next.** The level function's existence for a finite system — the condensation
itself. That is the one place the route still needs graph theory rather than
list manipulation.

## 339 — the level function is free, and its levels are the SCCs

338 left one graph-theoretic gap: `SyntacticallyLayered` needs a bounded level
function no transition raises, and the condensation supplies one only if you
compute a condensation. **You do not have to.**

```lean
noncomputable def reachLevel (sys) (s : S) : Nat := countReach sys s sys.states
```

— the number of the system's own states that `s` can reach. A successor's
reachable set is contained in its predecessor's, so the count never rises along
an edge. No SCC algorithm, no pigeonhole, no decidable reachability, no fuel: the
whole proof is three inductions over `sys.states`, comparing the two counts term
by term (`countReach_mono`). `Classical` appears only in the indicator.

- `reachLevel_bound : reachLevel sys s < sys.states.length + 1`
- `reachLevel_mono : ∀ s, ∀ tr ∈ sys.trans s, reachLevel sys tr.2.2 ≤ reachLevel sys s`
- `syntacticallyLayered_of_regions` — **two of the three conjuncts of
  `SyntacticallyLayered` now hold for EVERY system.** The entire remaining
  content of the predicate is the per-level peel.

**And the levels are not a crude approximation of the condensation — they are the
condensation.**

```lean
theorem reachLevel_scc (hs : s ∈ sys.states) (hst : SReaches sys s t)
    (hlvl : reachLevel sys t = reachLevel sys s) : SReaches sys t s
```

If `s` reaches `t` and the two counts tie, `t` reaches `s`. The argument is
arithmetic, not graph theory: `countReach` is a sum of pointwise-`≤` indicator
terms, and a sum of such terms can only tie if **every** term ties
(`add_eq_left` + `Nat.add_left_cancel`), so the two reachable sets agree on every
counted state — including `s` itself, which `s` reaches by `refl`.

Consequences: a level is a disjoint union of mutually-unreachable SCCs, any edge
leaving a level drops it strictly, and regions stay as small as the census
measured (max 3, 94.5% singletons).

**Where the route now stands.**

```
bounded level function, non-increasing        FREE for every system (339)
each level unoccupied or peelable             the whole remaining content
   · singleton self-loop region               PROVED (335)
   · region closed in mid, ranked base        PROVED (336)
   · shared entry across region states        NOT an obstruction (337)
   · every hypothesis a finite list check     PROVED (338)
every SyntacticallyLayered system solves      PROVED (338)
```

**Next.** The peel construction itself: given a level and the automaton's lists,
produce `mid`, `base`, `h₀`, `b`, `entry`, `loopEntry` and the rank — the one
step that is still done by hand in `d2_region_one`.

## 340 — the quotient's SHAPE is free, and the chain now speaks the target's language

**The fact that changes the construction problem.** `UniformBehavioralGAutQuotient`
carries `mapState`, `maps_states`, `onto_states` and `bisim_graph` — and **nothing
syntactic about `quot.trans` or `quot.hlt`**. Two candidate quotients that select
the same transition at every atom and halt on the same atoms are equally valid
quotients of the same automaton. 330 established that no *minimality* is
required; this is stronger and more useful: the transition LISTS themselves are
ours to choose — length, order, guards, and inert padding included.

That matters because every layer equation in the peel is syntactic. The peel does
not have to be *discovered* in a quotient handed over; it can be *built into* the
quotient. 339's `reachLevel` is unaffected either way, since it depends only on
which targets appear.

**But only if solutions survive the reshaping**, which is the content here:

```lean
theorem eqRHS_equiv_of_behaviour (aut aut' : GAut S A T) (sol) (s)
    (htr : ∀ X W x, firstMatch W x (aut.trans s) = firstMatch W x (aut'.trans s))
    (hh  : ∀ X W x, bval W (aut.hlt s) x = bval W (aut'.hlt s) x) :
    EquivBA (eqRHS aut sol s) (eqRHS aut' sol s)
```

and its consequence `solvesBA_of_behaviour`. This is the recurring move of
283/292/299/323/325 — **compare folds by SELECTION, not by list** — applied one
level up, to the automaton rather than to a fold. `selectFull` on a transition
list's branches is `firstMatch` on the list (4954), so agreement of `firstMatch`
is agreement of the selected branch, and `guardedFold_select_congr` does the rest.
The `none` branch is where the two halt tests meet, and `EquivBA.baTest` takes
exactly the `bval` agreement hypothesis.

**And the chain now lands in the target's own language.**

```lean
theorem solvesBA_of_syntacticallyLayered (aut : GAut S A T)
    (h : SyntacticallyLayered ⟨aut.states, aut.hlt, aut.trans⟩) :
    ∃ sol, GkatKleene.SolvesBA aut sol
```

via `solvesBA_of_paramSolution` (**axiom-free**), which is `foldr_fallback_congr`
plus `fallback_equiv` — `eqRHS` and `eqRHSParam` at ending `1` differ only in
their fallback, and those agree by S5. So `hsolve` for
`sumQuotientSolvable_of_certificate` is now a theorem, stated in the exact form
that theorem consumes.

**Where the route stands.**

```
hsolve  = solvesBA_of_syntacticallyLayered              PROVED (340)
hsum    = every Thompson automaton SyntacticallyLayered  open, but 286 proved the
                                                         LayeredL analogue
hcollapse = the quotient is SyntacticallyLayered         THE REMAINDER
```

and `hcollapse` is now a *construction* problem with the shape constraint lifted:
build a quotient in peeled form, then transport the solution back with
`solvesBA_of_behaviour`.

**Next.** The peel construction, exploiting the freedom: given a level's states
and their behaviour, emit `base`, `mid` and `sys` directly — the generic version
of `d2Base`/`d2Mid`/`d2Sys`.

## 341 — the peel constructed, every level at once

340 showed the quotient's transition lists are ours to choose. 341 spends that
freedom: the layers are no longer *exhibited* for a given system, they are
*emitted*.

**One level.** `loopPeel` and `seqPeel` build the intermediate and outer systems
from the trimmed one; `loopPeel_layer` and `seqPeel_layer` are the layer
structures, **axiom-free**. Level equality is decidable, so the `if`s cost no
`Classical`. `regionLevelSyn_of_peel` turns four finite list checks into
`RegionLevelSyn`.

**Every level at once — and this is where the shape had to change.**
`SyntacticallyLayered` needs every level regional *for the same system*, and both
layer structures carry an `outside` field insisting `mid` and `base` agree off
the region. So level `n`'s intermediates cannot be "raw plus level `n`'s layers":
they must be **the fully peeled system with level `n`'s two layers removed**.
Peeling level by level and composing does not typecheck, and that is not a
technicality — it is the statement that each level is peeled *in situ*.

```lean
def peeledSys raw bs h₀s loops exits lvl   -- every level's layers, simultaneously
def midSys  … n   -- peeledSys with level n's EXIT layer stripped back to raw
def baseSys … n   -- peeledSys with BOTH of level n's layers stripped
```

`midSys_loopLayer` and `peeledSys_seqLayer` — **both axiom-free**. Then
`regionLevelSyn_peeled`, `peeled_mono`, and the capstone:

```lean
theorem syntacticallyLayered_peeled (raw bs h₀s loops exits lvl rank B)
    (hbound) (hraw) (hloopIn) (hexitLe) (hexit) (hrawIn) (hrawRank) :
    SyntacticallyLayered (peeledSys raw bs h₀s loops exits lvl)
```

and `solvesBA_peeled`, which delivers `∃ sol, SolvesBA aut sol` for the
corresponding G-automaton — the exact form `hsolve` consumes.

**What the hypotheses actually say.** Read plainly: the raw system's transitions
never raise the level, its intra-level edges are **ranked** (so raw is the
automaton with its back-edges removed), the per-level `loops` are the back-edges
(targets in their own level), and the per-level `exits` leave the level
downward. That is a complete recipe, and every conjunct is a finite check.

**What is left, stated honestly.** `solvesBA_peeled` solves the system it
*builds*. `hcollapse` needs it to solve the quotient it is *handed*. The bridge
is 340's `solvesBA_of_behaviour`, and its premise is the remaining obligation:

> given a quotient, split each state's transition list into `raw`, `loops` and
> `exits` such that the gated reassembly selects the same transition at every
> atom.

The gating is `and (raw.hlt s) (and b tr.1)` for loops and
`and (and (raw.hlt s) (not b)) tr.1` for exits, so the split is not free — it is
a guard-algebra obligation, and it is the one thing between here and the
certificate. 337 already showed the per-state selector that makes shared entries
harmless; this is the same question asked of the whole level at once.

**Next.** That split: from a quotient's lists, produce `raw`/`loops`/`exits` and
prove `firstMatch` agreement.

## 342 — the last obligation, derived to a per-atom condition, and a counterexample

341 left one thing: split a quotient's lists into `raw`/`loops`/`exits` whose
gated reassembly selects the same transition at every atom. Working the gating
out turns that into something finite and sharp.

**The derivation.** At a level-`n` state `s`, the peeled list fires in this order:

1. a `raw` transition, if one of its guards holds;
2. else a loop entry, gated `raw.hlt s ∧ bs n ∧ tr.1`;
3. else an exit entry, gated `raw.hlt s ∧ ¬bs n ∧ tr.1`;
4. else halt, iff `raw.hlt s ∧ ¬bs n ∧ h₀s n`.

`bs n` is ONE test shared by the whole level, and steps 2 and 3/4 sit on opposite
sides of it. Hence:

> **`bs n` must be true on every back-edge atom of the level, and false on every
> exit atom and every halting atom of the level.**

Intra-level edges that *decrease* the rank go into `raw` and constrain nothing,
so the back-edge set is ours to choose — any set whose removal leaves the region
acyclic. With regions of size ≤ 3 that is at most six rank orderings to try.

**`PAD_BACKATOM`, over 4000 quotients / 968 non-trivial regions:**

| | |
|---|---|
| regions admitting SOME rank ordering with no clash | **967 (99.90%)**, 915 of them singletons |
| regions where EVERY ordering clashes | **1** |

**The counterexample is real.** `q0: hl=000 st=[–,q1,q1] | q1: hl=110 st=[q0,–,–]`.
Rank `q0 < q1`: `q0→q1` becomes a back-edge on atoms 1,2, but `q1` *halts* on
atoms 1,2 — clash. Rank `q1 < q0`: `q1→q0` becomes a back-edge on atom 0, but
`q0` halts on atom 0 — clash. Both orderings fail, and there is no third.

So the one-seq-one-loop-per-level shape is **not** universally instantiable. This
is a genuine limit found by measurement, not a gap in the proof effort.

**The escape, and the tension it creates.** The obvious fix is to duplicate `q1`
into a back-edge copy and a halting copy — flow-graph structuring needs node
DUPLICATION, exactly the point flagged in the post-proof agenda as the best
surprise-connection candidate (Böhm–Jacopini / Kosaraju). Duplication is legal
only if the quotient need not be minimal, and 330 established that
`SumQuotientSolvable` requires no minimality.

**But `sumQuotientSolvable_of_certificate`'s `hstart` does demand it:**

```lean
(∀ u v, GkatPlanExistence.GenBisimilar quot u v → u = v)
```

That is minimality, in the hypothesis I would have to supply. So either the
duplication route needs `hstart` weakened, or the clashing region needs a
different treatment. **This is the fork, and it is not resolved by wanting it to
be.** Naming it now rather than discovering it later.

**Housekeeping.** The default census prints
`Thompson automata failing backedge/halt disjointness (must be 0): 1062` — a
"must be 0" label on a count that is not 0, i.e. a false assertion in an old
diagnostic. Relabelled as a measurement; 342 shows the condition genuinely fails
for some automata, so the gate framing was wrong.

**Next.** Resolve the fork: check whether `hstart`'s minimality is load-bearing
for the rest of the certificate argument, or whether a non-minimal quotient still
satisfies everything `sumQuotientSolvable_of_certificate` actually uses.

## 343 — 342's counterexample RETRACTED, the real condition measured, and the fork closed

**The retraction first.** 342 reported one region where every rank ordering
clashes and drew a fork from it. That measurement was wrong. It counted an atom
with no transition as a HALTING atom, but a state can also be **dead** there — no
transition and no halt. A dead atom constrains `bs n` not at all: setting
`raw.hlt s` false at that atom kills the loop gate, the exit gate and the halt
condition together, which is exactly deadness. Only a genuinely halting atom
forces `bs n` false.

Corrected, the 342 counterexample dissolves: `q0` is dead on atom 0, not halting,
so the ordering `rank q1 < rank q0` works. **There is no counterexample.**

**And the condition I derived was too weak anyway.** Both the loop list and the
exit list are shared by the whole level and scanned in order, so at any atom the
first matching entry fires for *every* region state whose `raw.hlt` is true
there. That forces more than a true/false split on `bs n`:

> At each atom, every region state not handled by `raw` and not dead must agree —
> **same kind and same target**. And exits **shadow** halting: an exit entry sits
> before the fallback, so no state may halt at an atom where another exits.

**`PAD_BACKATOM`, now measuring the strong condition:**

| | 4k quotients | 20k quotients |
|---|---|---|
| non-trivial regions | 968 | 5722 |
| admit a rank ordering with full agreement | **968 (100%)** | **5722 (100%)** |
| multi-state regions (agreement not trivial) | 53 → all admit | 126 → all admit |
| **base-rate control**: multi-state regions where at least ONE ordering clashes | **51 / 53** | **126 / 126** |
| regions where every ordering clashes | 0 | 0 |

The control is the point. 915 of 968 regions are singletons, where agreement is
vacuous — so a bare 100% would have proved nothing. Among the regions where the
condition can bite, it **does** bite: at the wider setting every single one has a
rank ordering that fails, and every single one has another that succeeds. The
choice of back-edge set is doing real work, and it always exists.

**The fork closed, in Lean.** Even though the counterexample dissolved, 342's
architectural question deserved an answer, and it is: minimality is only plumbing.

```lean
theorem sumQuotientSolvable_of_solver
    (hquot : ∀ e f, UniformLanguageEquivalent e f →
      ∃ Q quot π, (∃ qsol, SolvesBA quot qsol) ∧
        π.mapState (Sum.inl none) = π.mapState (Sum.inr none)) :
    SumQuotientSolvable A T
```

`GenBisimilar quot u v → u = v` is produced by `hstart`, consumed by `hcollapse`,
and appears nowhere in `SumQuotientSolvable`. Drop the `Cert` layer and it
vanishes. `sumQuotientSolvable_of_certificate_via_solver` factors the old
architecture through the new one, so this is a strict generalisation, not a rival
— and state duplication is legal if it is ever needed after all.

**Where the route stands.**

```
bounded non-increasing level function        FREE for every system      (339)
every SyntacticallyLayered system solves     PROVED                     (338)
the peel, constructed for every level        PROVED                     (341)
hsolve in the target's own language          PROVED                     (340)
minimality not required anywhere             PROVED                     (343)
the per-atom agreement condition             100%, control passes       (343)
-------------------------------------------------------------------------------
the split as a THEOREM, not a measurement    THE REMAINDER
```

**Next.** Turn the measured condition into the Lean construction: define
`raw`/`loops`/`exits` from a level's agreement data and prove `firstMatch`
agreement.

## 344 — guard normalisation: making the split legal

343 measured the per-atom condition and it held. Turning it into Lean runs
straight into a mismatch that no amount of measuring would have surfaced:

> the split of a state's list into `raw` / `loops` / `exits` is a **partition**,
> but `firstMatch` is **order-sensitive** — an entry fires only if no earlier
> guard holds. Partitioning a list can therefore change its behaviour.

Both facts are reconciled at once by normalising the guards: fold the negations
of all preceding guards into each guard.

```lean
def disjoinAux (acc : BExp T) : List (BExp T × A × S) → List (BExp T × A × S)
  | [] => []
  | (g, r) :: tl => (BExp.and acc g, r) :: disjoinAux (BExp.and acc (BExp.not g)) tl
```

- **`firstMatch_disjoin`** — normalising changes no behaviour. `[propext]`.
  Proved through `firstMatch_disjoinAux`, whose statement carries the accumulator
  as `if bval acc x then firstMatch L else none`; the `acc = false` case is what
  makes the induction go through, and it is invisible if you only state the
  `acc = one` corollary.
- **`disjoin_exclusive`** — normalised guards are pairwise exclusive at every
  atom. `[propext]`. The invariant needed is stronger than exclusivity alone:
  every entry's guard must also *imply* the accumulator, which is what lets a
  tail entry's truth force the head guard false.
- **`firstMatch_of_exclusiveAt`** — in an exclusive list, "the first entry that
  fires" and "the entry that fires" are the same thing. **Axiom-free.**
- **`firstMatch_eq_of_exclusiveAt`** — two exclusive lists with the same firing
  entries have the same `firstMatch`.

That last one is the tool the whole construction was waiting for: **a normalised
transition list may be split into `raw`, `loops` and `exits` and reassembled in
any order.** 340 established that reshaping preserves solutions; 344 establishes
that the particular reshaping the peel needs is behaviour-preserving.

Worth noting what this cost: nothing about atoms. Exclusivity is stated at a
single `(W, x)` and every lemma is quantified over it, so the tool composes with
the `firstMatch`-agreement obligations of 340 without a translation step.

**Next.** Use it: define `raw`/`loops`/`exits` as the three parts of the
normalised list and discharge `solvesBA_of_behaviour`'s premise.

## 345 — the state-level agreement, proved

344 made partitioning legal. 345 uses it, and reaches the theorem the whole
construction has been aimed at since 341.

**The partition.** `firstMatch_partition3` / `firstMatch_split`: any transition
list fires exactly as the three-way partition of its normalisation, in the order
`(raw ++ loops) ++ exits` — which is `peeledSys.trans`'s shape on the nose. There
is **no side condition on the two classifying predicates at all**; exclusivity
does all the work, so `raw`, `loops` and `exits` may be carved out however the
peel wants.

**The gates.** The peel does not use the entries as they stand — it wraps them:

| | gate | needs, where the guard holds |
|---|---|---|
| loop entry | `hlt ∧ (b ∧ g)` | `hlt` true and `b` **true** |
| exit entry | `(hlt ∧ ¬b) ∧ g` | `hlt` true and `b` **false** |

`bval_gate_eq` and `bval_exit_gate_eq` (both `[propext]`) say the wrapping is
invisible under exactly those conditions, and `firstMatch_map_guard` lifts them
from one guard to a whole list. The two conditions are **precisely 343's measured
per-atom condition**, which is the first time the measurement and the proof have
been the same statement rather than two statements about the same thing.

**The theorem.**

```lean
theorem firstMatch_peel_agrees (W x) (L) (hltE b) (p q)
    (hloop : ∀ tr ∈ (disjoin L).filter loopPart, bval W tr.1 x = true →
       bval W hltE x = true ∧ bval W b x = true)
    (hexit : ∀ tr ∈ (disjoin L).filter exitPart, bval W tr.1 x = true →
       bval W hltE x = true ∧ bval W b x = false) :
    firstMatch W x L = firstMatch W x (peel's reassembly of L)
```

That is `solvesBA_of_behaviour`'s transition obligation, discharged at one state
from 343's condition. `firstMatch_append_congr` (`[propext]`) is the glue.

**What is NOT yet done — two things, both real.**

1. **The shared list.** `loops n` and `exits n` are ONE list per level; the
   theorem above uses each state's own filtered part. For a singleton level those
   coincide, which covers the 94.5% the census measures — but the multi-state
   case needs 343's agreement to be turned into an actual shared list, not just
   a per-atom consistency fact.
2. **The halt agreement.** `solvesBA_of_behaviour` has a second premise, on
   `bval` of the halt tests, and nothing above touches it.

Neither is hand-waved by the theorem proved here; both are named because the
theorem proved here makes it obvious what they are.

**Next.** The halt agreement — the smaller of the two, and independent of the
shared-list question.

## 346 — the halt half, and the shared tests constructed

345 discharged `solvesBA_of_behaviour`'s transition premise at a state. 346 does
the halt premise, and along the way settles something that had been waved at
since 341: **what `bs n` and `h₀s n` actually ARE.**

**They cannot be sets of atoms** — `T` is abstract, there is no atom type to
carve up. They do not have to be. Both are finite `BExp` folds over tests the
level already has:

- `bs n` := `bigOr` of the level's loop guards;
- `h₀s n` := `bigOr` of the level's halt tests.

`bval_bigOr_true` / `bval_bigOr_false` characterise them (`[propext]`), and that
is the whole construction — no atom reasoning anywhere.

**The theorem.**

```lean
theorem bval_peel_hlt_eq (W x) (rawHlt qh) (levelLoops levelHlts)
    (hmem     : qh ∈ levelHlts)
    (hraw     : bval W qh x = true → bval W rawHlt x = true)
    (hloopoff : bval W qh x = true → ∀ g ∈ levelLoops, bval W g x = false)
    (hnot     : bval W qh x = false → bval W rawHlt x = true →
                  (∃ g ∈ levelLoops, bval W g x = true) ∨
                  (∀ h ∈ levelHlts, bval W h x = false)) :
    bval W ((rawHlt ∧ ¬ bigOr levelLoops) ∧ bigOr levelHlts) x = bval W qh x
```

`[propext]`. Read the hypotheses and they are 343's condition again, on the halt
side: where `s` halts it is not raw and no loop guard of the level fires; where
`s` does not halt but is still non-raw, either a loop guard fires (so `¬ bs n`
kills the test) or nothing in the level halts (so `h₀s n` does) — that last
disjunct being exactly the **"exits shadow halting"** clause 343 measured.

**Both premises of `solvesBA_of_behaviour` are now discharged at the state level**
— transitions by 345, halt by 346, from the same measured condition.

**The one thing left, and how it goes.** `loops n` / `exits n` must be ONE list
per level, while 345 uses each state's own filtered part. The shared list should
be the concatenation of every level state's part, and working through it shows
the agreement condition is not merely sufficient but *exactly* what is needed,
in both directions:

- when `s`'s own part fires at an atom, some entry of the concatenation fires
  there too, and agreement forces it to have the same target;
- when `s`'s part does NOT fire but another state's entry does, `s` would be
  dragged into a loop it should not take — unless agreement rules that atom out,
  which it does, because a state that is non-raw and non-dead must agree in kind
  with the one that loops.

The second direction is the one that would have been missed by treating the
condition as a convenience. It is not: it is load-bearing.

**Next.** The shared list itself — the concatenation, and the two directions
above as one lemma.

## 347 — the shared list, and the transition obligation closed

346 left one thing on the transition side: `loops n` and `exits n` are ONE list
per level, while 345 reasoned with each state's own filtered part.

**`firstMatch_shared`** bridges them, and both directions of 343's agreement
appear as hypotheses because both are used:

- **`hagree`** — when an entry of the SHARED list fires, this state's own part
  fires with the same target. Drop it and the shared list hands `s` another
  state's back-edge.
- **`hback`** — when this state's own part fires, something in the shared list
  fires too. Drop it and `s` silently stops looping.

The proof needed two small facts that turned out not to be in the corpus:
`firstMatch_some_guard` (a `some` result comes from an entry whose guard actually
holds — **axiom-free**) and `firstMatch_none_all_false` (its converse). The
existing `firstMatch_mem_of_some` gives membership but *not* that the guard is
true, which is the half the argument needs.

`firstMatch_shared_exit` is the same argument at the opposite polarity of `b`.

**And the assembly:**

```lean
theorem firstMatch_peel_shared_agrees … :
    firstMatch W x L
      = firstMatch W x (((disjoin L).filter p ++ sharedLoop.map loopGate)
                          ++ sharedExit.map exitGate)
```

A state's transition list fires exactly as `peeledSys.trans` does at that state —
its own raw part, then the LEVEL's shared loop list gated by its own halt test,
then the LEVEL's shared exit list. **That is `solvesBA_of_behaviour`'s first
premise in the form the construction actually produces**, and with 346 the second
premise is done too.

**Where the route stands.**

```
level function, free for every system                  339
every SyntacticallyLayered system solves               338
the peel constructed, every level at once              341
solutions survive reshaping                            340
minimality required nowhere                            343
transition premise, SHARED lists                       347
halt premise                                           346
------------------------------------------------------------------
build sharedLoop/sharedExit from a quotient and
discharge hagree/hback from the agreement condition     THE REMAINDER
```

**What the remainder is, precisely.** `hagree` and `hback` are currently
hypotheses, stated per state and per atom. They *encode* 343's measured
condition, but nothing yet constructs the two shared lists from a quotient and
proves them. The construction is the concatenation of every level state's part;
what has to be proved is that 343's agreement makes that concatenation behave, at
every state, like each state's own part.

**Next.** That construction — `sharedLoop := (level states).flatMap loopPart` and
the two hypotheses discharged from agreement.

## 348 — the shared lists BUILT, not assumed

347 closed the transition obligation but left `hagree` and `hback` as hypotheses.
348 constructs the shared lists and discharges both.

```lean
sharedLoop := states.flatMap (fun s' => (disjoin (L s')).filter loopPart)
```

`shared_flatMap` — the two hypotheses fall straight out:

- **`hback`** because a state's own part is a sublist of the concatenation, so
  the witness is the entry itself;
- **`hagree`** because agreement says any firing entry of ANY state's part is the
  entry that EVERY state's part fires.

Neither needs a case analysis; the work was choosing the construction so they
would be immediate, which is what `List.mem_flatMap` in both directions gives.

**`firstMatch_peel_level`** then says: every state of a level fires exactly as
`peeledSys.trans` does there, with the shared lists **built** rather than
assumed. Its only remaining inputs are the gate conditions and the agreement
condition — both of them 343's measurement, now stated as Lean hypotheses at a
single `(W, x)`.

**Where the route stands.**

```
level function, free for every system                    339
every SyntacticallyLayered system solves                 338
the peel constructed, every level at once                341
solutions survive reshaping                              340
minimality required nowhere                              343
transition premise, shared lists BUILT                   348
halt premise                                             346
------------------------------------------------------------------
the capstone: instantiate peeledSys from a quotient      THE REMAINDER
```

**What the capstone needs, concretely.** All four ingredients are now
constructible from a quotient and nothing else:

| ingredient | construction |
|---|---|
| `levelStates n` | `aut.states.filter (lvl · = n)` |
| `loops n` / `exits n` | `flatMap` of the level states' parts (348) |
| `bs n` | `bigOr` of the level's loop guards (346) |
| `h₀s n` | `bigOr` of the level's halt tests (346) |
| `raw.trans s` | `(disjoin (aut.trans s)).filter p` |
| `raw.hlt s` | the state's non-raw non-dead test |

so the capstone is an instantiation, not a new idea. What it will cost is
hypothesis bookkeeping: the gate, agreement and halt conditions have to be
carried per level and per `(W, x)`, and `solvesBA_peeled`'s region conditions
have to be met by the same classifiers `p`, `q` and rank.

**Next.** That instantiation, with `levelStates` defined and the two behaviour
premises of `solvesBA_of_behaviour` produced from it.

## 349 — THE CAPSTONE: the peel instantiated from a quotient

Every object the construction needs is now built from `aut`, `lvl`, the two
classifiers `p`, `q` and `rawHlt` — nothing exhibited by hand, nothing assumed to
exist:

```lean
def levelStates aut lvl n := aut.states.filter (lvl · = n)
def peelRaw    aut p rawHlt := ⟨aut.states, rawHlt, fun s => (disjoin (aut.trans s)).filter p⟩
def peelLoops  aut lvl p q n := (levelStates aut lvl n).flatMap (…filter loopPart)
def peelExits  aut lvl p q n := (levelStates aut lvl n).flatMap (…filter exitPart)
def peelBs     aut lvl p q n := bigOr ((peelLoops …).map (·.1))
def peelH0     aut lvl n     := bigOr ((levelStates …).map aut.hlt)
def peelAut    aut lvl p q rawHlt := peeledSys (peelRaw …) (peelBs …) (peelH0 …) …
```

- **`peelAut_trans_agrees`** — every listed state fires exactly as the built peel
  does, from the gate and agreement conditions.
- **`peelAut_hlt_agrees`** — same for the halt test, from 346's conditions.
- **`solvesBA_of_peel`** — the two together plus
  `SyntacticallyLayered (peelAut …)` give `∃ sol, SolvesBA aut sol`.

One correction on the way: the hypotheses first went in stated for a single state
`s`, but `firstMatch_peel_level` needs them across the whole level — agreement is
a statement about a level, not about a state, and writing it per-state made it
look weaker than it is. Restated by level index, it goes through.

`solvesBA_of_behaviour` also had to be weakened from `∀ s` to `∀ s ∈ aut.states`;
it was only ever used at listed states, and the stronger form is not provable for
a peel that says nothing about unlisted ones.

**Where the route stands.**

```
level function, free for every system                    339
every SyntacticallyLayered system solves                 338
the peel constructed, every level at once                341
solutions survive reshaping                              340
minimality required nowhere                              343
transition + halt premises, shared lists built           346-348
the peel INSTANTIATED from a quotient                    349
------------------------------------------------------------------
the classifiers p, q and the rank, and the region
conditions they must satisfy                             THE REMAINDER
```

**What the remainder is.** `solvesBA_of_peel` takes
`SyntacticallyLayered (peelAut …)` as a hypothesis; 341's
`syntacticallyLayered_peeled` supplies it, but its region conditions are
statements about `p`, `q` and a rank: `p` must pick the rank-decreasing
intra-level edges, `q` the intra-level back-edges, and the rest must exit
downward. Producing those classifiers from a quotient is the condensation fact
(339: levels ARE the SCCs) plus a rank on each region — the rank ordering 343
measured and found always to exist.

**Next.** Define `p`, `q` and the rank from the quotient's own graph, and
discharge 341's region conditions.

## 350 — the classifiers, the region conditions, and the route in one statement

**A refactor first, forced by the mathematics.** `p` and `q` were functions of an
ENTRY. Whether an intra-level edge is "raw" is not a property of the entry — it is
`rank target < rank source`, a statement about both endpoints. So the classifiers
now take the source state, `p q : S → (BExp T × A × S) → Bool`, and each state
classifies its own entries. `firstMatch_peel_level` and the whole `Instantiation`
section were rewritten around it; nothing else moved, because every earlier lemma
is stated for one list at a time.

**The classifiers.**

```lean
def rawPred  lvl rank s tr := decide (lvl tr.2.2 = lvl s) && decide (rank (lvl s) tr.2.2 < rank (lvl s) s)
def loopPred lvl      s tr := decide (lvl tr.2.2 = lvl s)
```

Raw keeps the intra-level rank-decreasing edges; among what is left, the
intra-level ones are the back-edges and the rest leave the level — downward, by
monotonicity.

**`syntacticallyLayered_peelAut`** discharges **all six** region conditions of
341 from these definitions plus `hbound` and `hmono` — and 339 supplies both for
free, for every system. One supporting lemma was needed: `mem_disjoin_target`
(**axiom-free**) — normalising rewrites guards, never targets, which is what lets
`hmono` on the quotient carry over to the normalised lists.

**The route in one statement:**

```lean
theorem solvesBA_of_agreement (aut) (lvl) (rank) (B) (rawHlt)
    (hbound) (hmono) (htr) (hh) : ∃ sol, SolvesBA aut sol
```

A quotient is solvable given a bounded non-raising level function, a per-level
rank, and **the behavioural agreement between the quotient and the peel built
from it**. Every structural obligation — layers, levels, shared lists, region
conditions — is discharged inside.

**What is left is exactly one thing**, and it is 343's measured condition: the
two `firstMatch`/`bval` agreements, for the specific classifiers above. 346-348
reduce them to the gate and agreement hypotheses; what remains is to prove those
hypotheses hold, which is where the measurement says they do (100%, control
passing) but the proof does not yet.

**Next.** The agreement hypotheses themselves — `hagreeL`/`hgateL` and their exit
and halt counterparts, for `rawPred`/`loopPred`.

## 351 — 343's condition stated once, and the transition hypotheses derived from it

**The four agreement hypotheses are not theorems.** They are properties of the
automaton — which is exactly why 343 had to measure them rather than prove them.
What CAN be proved is that all four follow from one natural statement:

```lean
def LevelAgreement aut lvl rank : Prop :=
  ∀ W x n, ∀ a ∈ levelStates aut lvl n, ∀ c ∈ levelStates aut lvl n, ∀ r,
    firstMatch W x (nonRaw aut lvl rank c) = some r →
    firstMatch W x (nonRaw aut lvl rank a) = some r
```

*At any atom, if one state of a level fires a non-raw transition to `r`, every
state of that level fires to `r`.* Note what is NOT in it: any mention of loops
versus exits. **Kind agreement comes for free** — two states firing to the SAME
target agree on whether that target is inside the level, hence on the kind. 343
measured kind and target agreement as two clauses; only one is primitive.

`peelRawHlt s := bigOr (nonRaw s guards) ∨ aut.hlt s` — true exactly where `s` is
neither handled by `raw` nor dead, which is what 343's derivation required of it.

**Derived, all four:**

| | |
|---|---|
| `gateL_of_agreement` | a firing loop entry makes the level's loop test true and the firing state's halt test true |
| `agreeL_of_agreement` | **`[propext]` only** |
| `gateE_of_agreement` | the interesting half: the level's loop test is FALSE at an exit atom — if any loop guard fired there, agreement would force this state to the same INTRA-level target, but it is firing OUT |
| `agreeE_of_agreement` | **`[propext]` only** |

plus `rawHlt_of_halt`, the first of the three halt-side hypotheses, immediate
from `peelRawHlt`'s definition.

**What is left: two halt-side hypotheses**, and they need one more property of
the automaton beyond agreement —

> a state does not both halt and transition at the same atom

— determinism, which every guarded automaton has but which nothing in the
development has yet been made to state. `hloopoff` needs it to turn "s halts
here" into "s's non-raw part fires nothing here"; `hnot` needs it plus agreement
for the "exits shadow halting" clause.

**Next.** That determinism property, and the two remaining halt hypotheses.

## 352 — THE THEOREM OF THE ARC

```lean
theorem solvesBA_of_levelAgreement (aut) (lvl) (rank) (B)
    (hbound : ∀ s, lvl s < B)
    (hmono  : ∀ s, ∀ tr ∈ aut.trans s, lvl tr.2.2 ≤ lvl s)
    (hdet   : HaltDeterministic aut)
    (hagree : LevelAgreement aut lvl rank) :
    ∃ sol, GkatKleene.SolvesBA aut sol
```

`[propext, Classical.choice, Quot.sound]`. No `sorry`.

A quotient automaton is solvable as soon as three things hold of it: a bounded
level function no transition raises, determinism, and level agreement.
**Everything else is discharged inside** — the layers (294-326), the condensation
(331-339), the peel (341-349), guard normalisation (344), the shared lists
(347-348), the region conditions (350), the gates (351).

`HaltDeterministic` had to be introduced this iteration: *no state both halts and
transitions at the same atom*. Every guarded automaton has it and nothing in the
development had been made to say it. `nonRaw_none_of_halt` turns it into "a
halting state fires nothing non-raw", which is what both remaining halt
hypotheses needed — `loopoff_of_agreement` (if the level's loop test fired where
`s` halts, agreement would make `s` fire, and a halting state fires nothing) and
`hnot_of_agreement` (the exits-shadow-halting clause, same argument run at
another state of the level).

### What this does NOT prove

Three hypotheses stand between this and `hcollapse`, and it is worth being exact
about their status, because two of them are *measured*, not proved:

| hypothesis | status |
|---|---|
| `hbound`, `hmono` | **free** — 339's `reachLevel` supplies both for every system |
| `hdet` | true of every guarded automaton; not yet proved for the quotients in question |
| `rank` + `hagree` | **measured only** — 343: 100% of 5722 regions, control passing |

So the single open mathematical statement is now:

> **for every quotient there EXISTS a rank making `LevelAgreement` hold.**

343 measured exactly that (and the control matters: 126/126 multi-state regions
have some rank ordering that FAILS, so the existential is doing work and is not
vacuous). But measured is not proved, and 342 is the standing reminder — a
measurement artifact there manufactured a counterexample and an architectural
fork out of nothing.

**Odds: 98%, unchanged.** The architecture is complete and the remainder is one
sharply-stated existential with a passing control behind it. That is not the same
as a proof, and the field's prior that this problem does not close still stands.

**Next.** Prove `HaltDeterministic` for the quotient construction, then attack the
rank existential.

## 353 — an attempted REFUTATION of `LevelAgreement`, and why it survives

352 made `LevelAgreement` load-bearing on measurement alone. The right response to
that is not another confirmatory run — it is an attempt to break it.

**A rank-free necessary condition.** An exit leaves its level, so it is never
raw, whatever the rank. Therefore:

> if two states of a region exit to DIFFERENT targets at the SAME atom,
> `LevelAgreement` fails outright and no choice of rank can save it.

That is a hard refutation test with no existential to search over. Added to
`PAD_BACKATOM` and run at increasing scale:

| pool | regions | multi-state | **exit conflicts** | control: some ordering fails |
|---|---|---|---|---|
| G=2 R=3 cap 4k | 968 | 53 | **0** | 51/53 |
| G=3 R=4 cap 30k | 7 882 | 196 | **0** | 190/196 |
| G=4 R=5 cap 120k | **41 885** | 695 | **0** | 672/695 |

Ten times the earlier scale, and the hypothesis does not break. The control keeps
passing throughout — 672 of 695 multi-state regions have a rank ordering that
*fails*, so the existential is real work, not a triviality.

**A process note.** The first attempt at this run reported three identical
results for three different parameter sets. zsh does not word-split unquoted
variables, so `set -- $cfg` left every run on the defaults. Three identical
numbers for three different configurations is the signature of a harness that
isn't reading its inputs; it should be checked for, not explained away.

**Why it survives — the mechanism.** Exit agreement is not luck. In GKAT, an SCC
comes from a **while-loop**, and a while-loop has exactly **one exit
continuation**: every state of the body, when the loop test fails, goes to the
same successor. So exits from a region agree *structurally*, not accidentally.
That is also why the census's `entry/body-separated subclass` counter exists.

The open question is whether the collapse can break it — by merging states from
two different loops into one SCC, whose exits would then differ. The measurement
says it does not, over 41 885 regions.

**This is now the shape of the remaining proof**, and it is a much better shape
than "a measured existential":

1. exits from a loop body in a Thompson automaton go to a single continuation —
   structural, provable by induction on the expression;
2. a behavioural quotient preserves that;
3. hence `LevelAgreement`, with the rank read off the body's own order.

**Next.** Measure step 2 directly — whether any collapse merges two loops into a
single SCC — since that is the one place the structural argument could fail.

## 354 — 353's step 2 is FALSE, and the true statement is sharper

353 proposed a three-step route to `LevelAgreement`, whose step 2 was "the
collapse preserves one-exit-continuation". `PAD_LOOPMERGE` measures that joint
directly, and **it is false**:

| pool | non-trivial quotient SCCs | preimage spans ≥2 source loops |
|---|---|---|
| G=2 R=3 cap 4k | 968 | **6** (0.62%), max span 2 |
| G=4 R=5 cap 120k | 41 885 | **902** (2.15%), max span **3** |

The collapse fuses loops, routinely. So "each SCC comes from one while-loop" does
not survive the quotient, and a proof resting on it would have rested on
something false.

**The conclusion survives, for a sharper reason.** Every merge is *inside a
single quotient state*: bisimilar states from different source loops collapsing
into one block, which agree on everything trivially. The shape that would
actually cause trouble — two **distinct** quotient states in one SCC, drawn from
**disjoint** source loops, each bringing its own exit continuation — is

```
0 quotient SCCs contain TWO DISTINCT states drawn from DISJOINT source loops
```

**0 of 41 885**, and correspondingly 0 of the 902 merged SCCs have two different
exit targets at one atom.

**The repaired route.** (1) exits from a loop body go to a single continuation —
structural, by induction on the expression; (2) **a quotient SCC's distinct
states never come from disjoint source loops** — measured 0/41 885, now a crisp
statement about how bisimulation interacts with strong connectivity rather than a
vague appeal to structure; (3) hence a region keeps its single exit continuation
and `LevelAgreement` holds.

**Why step 2 is not yet proved, precisely.** A cycle downstairs lifts to source
transitions, but the lifted path leaves and re-enters blocks at *different*
members: `u₁ → v₁` with `v₁ ∈ b₂`, and `v₂ → u₂` with `v₂ ∈ b₂`, `v₁ ≠ v₂`. To
close the cycle upstairs one needs `v₁ ~ v₂` to transport reachability — true,
but it transports only up to bisimilarity, i.e. back to the same statement
downstairs. The argument is circular and I have not found the way out.

**Odds: 98%, unchanged.** Two iterations running, a proposed proof step has been
refuted by its own measurement (353's step 2 here, 342's counterexample before).
The measurements keep landing; the proofs behind them keep needing repair.

**A harness note.** This entry was nearly lost: `cd <relative path> && cat >> …`
short-circuited when the `cd` failed, the ledger write never ran, and the commit
went out with the code but no entry. Worse, the recovery attempt appended an
unrelated root-level `SUMMIT-TODO.md` into this one before being reverted with
`git checkout`. Use absolute paths for ledger writes; a failed `cd` in a `&&`
chain is silent unless the tail is checked.

**Next.** Step 2 without the circularity — likely by strengthening what is lifted
from "reaches" to something bisimulation already respects.

## 355 — the circularity was mine, not the problem's

354 called step 2's proof circular. It is not — the circularity came from trying
to lift a downstairs cycle **state by state**, when only **SCC-level
reachability** is needed:

> if source loop `C₁` has an edge into `C₂` and `C₂` has an edge back into `C₁`,
> then `C₁` and `C₂` are mutually reachable, hence the same loop.

No cycle has to be lifted; two independent edges suffice, and they come from the
two directions of the downstairs cycle separately. In Lean, with 339's
`reachLevel` doing the work of an SCC computation:

```lean
theorem reachLevel_eq_of_mutual (huv : SReaches sys u v) (hvu : SReaches sys v u) :
    reachLevel sys u = reachLevel sys v
```

— two applications of `countReach_mono` and `Nat.le_antisymm`, nothing more.
Plus `not_mutual_of_level_ne`, the contrapositive in the form 354 wants, and
`sreaches_of_mem`.

**How much ground that covers, measured.**

```
42 584 blocks in non-trivial quotient SCCs
   902 (2.118%) have a preimage spanning MORE THAN ONE source loop (max 3)
```

So the argument as proved covers **97.88%** of blocks — every block whose
preimage lies in a single source loop. And 902 is exactly the number of merged
SCCs from 354, confirming what that iteration found: each merge lives inside one
block.

**The case split, and what is still measured.**

* **two distinct blocks in one SCC** — SCC-level reachability forces their source
  loops to intersect, so they share a loop and a single exit continuation.
  *Proved, for blocks lying in one source loop each.*
* **within one block** — all preimages are bisimilar, so they agree on
  everything, exits included. *Trivial.*

What is **not** closed is the interaction: a multi-loop block sitting beside
another block in the same SCC. There the forward lift ends at some `v ∈ b₂` and
the backward lift starts at some `v' ∈ b₂` with `v ≠ v'`, and closing it needs
reachability transported along bisimilarity — which lands back downstairs. The
measurement says the bad shape (`cross`) never occurs, 0 of 41 885, but that case
is measured, not proved.

**Odds: 98%, unchanged.** A self-inflicted obstacle was removed, which is not the
same as progress on the problem. The honest ledger is: one case proved, one case
trivial, one case measured.

**Next.** The interaction case — whether a multi-loop block can be forced to
share a loop with its SCC neighbours, or whether that needs a genuinely different
argument.

## 356 — the interaction case: an argument, and a measurement that it is empty

355 left one shape uncovered: a quotient SCC with ≥2 blocks, one of which spans
several source loops. Two independent results this iteration.

**1. The argument, which closes it.** The apparent obstruction was that the
forward lift ends at `v ∈ b₂` while the backward lift starts at a different
`v' ∈ b₂`. But **blocks ARE bisimilarity classes**, so "a state bisimilar to
`u'`" is literally "a state of `b₁`" — the transport lands exactly where it is
needed, not merely up to something.

So: `u₁ ⇝ v` (forward lift), and since `v ~ v'` and `v' ⇝ u'`, also `v ⇝ u''`
for some `u'' ∈ b₁`. Iterate. The sequence `u₁, u'', u'''', …` lives in the
finite set `b₁`, so **some state repeats** — and a repeat is a cycle through
`b₁` and `b₂`, putting their preimages in one source SCC. Finiteness plus the
fact that bisimilarity classes are exactly the blocks is what closes it; 354's
"circular" reading missed both.

Formalising it needs a pigeonhole (an infinite sequence in a finite list
repeats), which is real work in a Mathlib-free file. It is not yet in Lean.

**2. The measurement, which says the case is empty.**

```
INTERACTION CASE: 0 quotient SCCs have >=2 blocks AND a block spanning
                    several source loops
```

**0 of 41 885.** Every multi-loop block turns out to be a *singleton* SCC — a
self-loop, alone in its region. So on the measured class the case split is
exhaustive with no residue:

| shape | status |
|---|---|
| SCC with ≥2 blocks, each in one source loop | **proved** (355, SCC-level reachability) |
| multi-loop block alone in its SCC | **trivial** — its preimages are bisimilar |
| multi-loop block beside another block | **never occurs** (0 / 41 885); argument above if it ever does |

**What this is and is not.** It is not a proof that the interaction case is
impossible — the census is bounded (≤4 core states, 3 atoms), and "does not
arise here" is not "cannot arise". It is that the one gap in the case analysis
is empirically empty *and* has an argument if it is ever non-empty, which is a
better position than either alone.

**Odds: 98%, unchanged.** The remaining chain is: structural single-exit
continuation (not yet proved), its transport through the quotient (argued and
measured, not formalised), `LevelAgreement` (follows), `HaltDeterministic` (not
yet proved for these quotients). Four items, none of them formalised, all of
them now stated sharply enough to be attacked one at a time.

**Next.** `HaltDeterministic` for the quotient — the smallest of the four, and
the only one that needs no new mathematics.

## 357 — `HaltDeterministic` discharged: it was already in the corpus

352 introduced `HaltDeterministic` as a hypothesis on the grounds that "every
guarded automaton has it". That is an assertion about the representation, not a
theorem, and the peel genuinely needs it — `eqRHS_equiv_of_behaviour` demands the
two halt tests agree at EVERY atom, including atoms where a transition fires and
the halt test is otherwise irrelevant. So it was worth checking.

**Measured first.** `PAD_HALTDET`, over the largest pool:

| | source | quotient |
|---|---|---|
| (state, atom) pairs | 1 455 834 | 1 240 380 |
| **both halts and steps** | **0** | **0** |
| neither — DEAD | 296 921 (20.40%) | 273 064 (22.01%) |

Zero violations, and the dead column is the striking one: **a fifth of all
(state, atom) pairs are dead** — neither halting nor stepping. 342 treated dead
as halting and manufactured a counterexample out of it; at 20% of the data that
was never going to be a corner case.

**Then found it was already proved.** `GkatKleene.WF`'s first conjunct is

```lean
∀ s ∈ aut.states, ∀ a, bval V (aut.hlt s) a = true → autStep V aut s a = none
```

which is `HaltDeterministic` verbatim (`autStep = firstMatch ∘ trans`).
`UniformWF` is it under every interpretation, and
`UniformBehavioralGAutQuotient.uniformWF` **already transports it to quotients**.
So:

```lean
theorem haltDeterministic_of_uniformWF (h : UniformWF aut) : HaltDeterministic aut
```

**Axiom-free.** One correction was needed: my predicate quantified over ALL
states where the corpus quantifies over LISTED ones. The corpus is right — a peel
says nothing about unlisted states — and every use site already had membership in
hand.

**The remaining chain, updated.**

| item | status |
|---|---|
| bounded non-raising level function | **free** (339) |
| `HaltDeterministic` | **PROVED** (357, via `UniformWF`) |
| structural single-exit continuation | open |
| its transport through the quotient | argued (356) + measured, not formalised |
| `LevelAgreement` | follows from the two above |

**Odds: 98%, unchanged.** One of four items closed, and it closed by recognising
existing work rather than by proving anything new — which is worth noting as a
process point: the corpus is large enough that "assume it, it's obviously true"
is a worse move than grepping for it.

**Next.** The structural single-exit continuation — the last item needing new
mathematics.

## 358 — "one exit continuation" is FALSE; "one exiting STATE" is true

353 named the mechanism behind `LevelAgreement` as *a loop body has one exit
continuation*, and 354-357 built on it. Every measurement of exits so far was
taken on QUOTIENTS. The structural claim is about the SOURCE — that is where an
induction on the expression would prove it — so `PAD_SRCEXIT` measures it there.

```
SRCEXIT: 42 815 non-trivial SCCs in Thompson automata, 12 780 with an exit
  2 161 have MORE THAN ONE distinct exit target (16.91%), max 2
      0 have more than one state WITH an exiting edge (0.00%), max 1
```

**The claim as stated is false**, and not marginally: 16.9% of exiting loop
bodies exit to two different targets. The smallest witness is a three-state
automaton whose head goes to `q1` on one atom and `q2` on another.

**What is true is the neighbouring statement**: exactly **one state** of a loop
body ever has an exiting edge — the head. It may exit to different places on
different atoms; what it may not do is share the privilege.

**And that is the statement `LevelAgreement` actually wants.** Agreement is
per-atom: at atom `x`, every non-raw state of the level must fire to the same
target. With a rank counting position in the body, the non-head states simply
march forward — every intra-body edge decreases the rank, so they are **raw** —
and the head alone is ever non-raw. Agreement over a set with at most one
non-raw member is vacuous.

So the corrected chain is:

1. **only the head of a loop body has exiting edges** — measured 0/12 780, and
   this is the thing to prove by induction on the expression;
2. there is a rank making every non-head intra-body edge raw — 343's measured
   rank ordering, in a form that now has a structural reason rather than a
   search;
3. hence at most one state of a region is ever non-raw, and `LevelAgreement` is
   immediate.

**Why the old version looked right.** On quotients, exits per atom were
single-valued (332, 343), and I read that as "one exit continuation". It is not:
single-valued *per atom* is compatible with several targets *across* atoms. The
quotient measurements were correct; the structural sentence I attached to them
was not.

**Odds: 98%, unchanged.** A named mechanism was refuted and replaced by a
sharper one that explains the same data — the third time in this stretch that a
proposed proof step has fallen to its own measurement (342, 354, 358). The
pattern is worth stating plainly: the measurements have been reliable, and the
prose I wrap around them has not.

**Next.** Step 1 by induction on the expression: `seq`, `ite` and `wh` each
preserve "only the head exits", with `wh` the case that creates the head.

## 359 — RETRACTION: 352's `LevelAgreement` is unsatisfiable, and 352 is vacuous where it matters

358's corrected picture — in a loop body only the HEAD is ever non-raw — implies
something about the Lean I had not checked. `LevelAgreement` as formalised says:

> if ONE state of a level fires a non-raw transition to `r`, then **EVERY** state
> of that level fires to `r`.

If only the head is ever non-raw, then at an atom where the head fires, the
non-head states do **not** fire, and the hypothesis is false. `PAD_STRONGAGREE`
tests it directly:

```
695 multi-state quotient regions
681 of 695 (97.99%) admit NO rank ordering under which
    "one fires => all fire" holds at every atom
```

**So `solvesBA_of_levelAgreement` — 352's "theorem of the arc" — has a hypothesis
that cannot be met for 98% of multi-state regions.** The theorem is true and
`sorry`-free; it is also, for the case that matters, **vacuous**. That is exactly
the defect 307 found and the post-proof agenda lists first: *a theorem whose
statement quantifies in a way that makes it unusable.* I wrote it, called it the
theorem of the arc, and did not check its hypothesis against the automata.

**What 343 actually measured, versus what I formalised.** 343 measured agreement
among states that are neither raw nor dead — the **ACTIVE** ones. The Lean
predicate quantifies over **ALL** states of the level. The measurement supports
the weak form; I formalised the strong one and carried it through seven
iterations without noticing the gap.

**What survives.**

* Singleton regions — 94.5% of non-trivial regions — satisfy the strong form
  trivially, so 352 applies there unchanged.
* Everything structural (339-351, 357) is untouched: the layers, the peel, the
  shared lists, guard normalisation, `HaltDeterministic`.
* The four derived lemmas (351) are still correct proofs; they just consume a
  hypothesis that is too strong.

**The repair, and why it is not merely cosmetic.** Weakening the predicate to

```lean
firstMatch W x (nonRaw c) = some r → firstMatch W x (nonRaw a) ≠ none →
  firstMatch W x (nonRaw a) = some r
```

makes it satisfiable — and under 358's picture it becomes nearly trivial, since
at most one state is active. But `gateL_of_agreement` currently DERIVES
`bval (peelRawHlt a) x = true` from the fact that `a` fires, and with the weaker
hypothesis it cannot. The real fix is in `firstMatch_shared`: it routes through
`firstMatch_gated`, which demands the gate be *invisible*, when all that is
needed is that **both sides agree** — and where the gate is false at a state,
both sides are silent and agree for free. That case has to be handled directly
instead of being assumed away.

**Odds: 97% (−1).** Not for the defect itself — the repair is clear and the
structure is intact — but for calibration. This is the fourth time in this
stretch that a claim of mine has fallen to a measurement (342, 354, 358, 359),
and the fourth is different in kind: it invalidated the usability of something I
had already called finished. The field's prior that this problem does not close
still stands, and I should be slower to name milestones.

**Next.** The `firstMatch_shared` restructure, so the weak agreement suffices.

## 360 — the repair: shared lists without the strong hypothesis

359 found the fault: `firstMatch_shared` routed through `firstMatch_gated`, which
demands the gate be **invisible**. That forces every state of a level to be
active whenever any is — false for 98% of multi-state regions.

All that is actually needed is that **both sides agree**, and where the gate is
false at a state, both sides are *silent* and agree for free. Splitting on the
state's own halt test instead of assuming it away:

```lean
theorem firstMatch_shared_weak (W x) (rawHlt b) (shared part)
    (hactive : ∀ tr ∈ part,   bval W tr.1 x = true → bval W rawHlt x = true)
    (hbtrue  : ∀ tr ∈ shared, bval W tr.1 x = true → bval W b x = true)
    (hagree  : ∀ tr ∈ shared, bval W tr.1 x = true →
                 bval W rawHlt x = true →        -- ← the state is ACTIVE
                   firstMatch W x part = some tr.2)
    (hback   : …) :
    firstMatch W x (shared.map loopGate) = firstMatch W x part
```

`[propext, Quot.sound]`. The proof is a case split the old one never made:

* **`rawHlt` false** — the state is inactive. Every gated guard is false, so the
  gated list is silent; and by `hactive` the state's own part is silent too.
  Both `none`. This is the case the old proof assumed away.
* **`rawHlt` true** — the gate is transparent *on this list*, by `hbtrue`, and
  the old argument runs unchanged.

`firstMatch_shared_exit_weak` is the twin at the opposite polarity of `b`, and
`firstMatch_peel_shared_weak` assembles both into the same conclusion 345 had —
with every agreement premise now conditioned on the state being active.

**What the new premises cost: nothing.** `hbtrue`/`hbfalse` hold by construction,
since `peelBs` *is* the disjunction of the level's loop guards; `hactive` holds
by construction, since `peelRawHlt` *is* the disjunction of the state's non-raw
guards (plus its halt test). So the weak form's premises are two definitional
facts and the weak agreement — the form 343 measured.

**Not yet done.** The weak lemmas exist; the chain above them
(`firstMatch_peel_level` → `peelAut_trans_agrees` → `solvesBA_of_levelAgreement`)
still consumes the strong form. Threading it through is mechanical but it is not
done, and until it is, 352 remains vacuous for multi-state regions.

**Odds: 97%, unchanged.** The repair works where it was diagnosed; that is
evidence the diagnosis was right, not that the theorem is fixed.

**Next.** Thread the weak lemmas up through `firstMatch_peel_level` and restate
`LevelAgreement` in the active form.

## 361 — threading the weak form up: three of four premises are definitional

`shared_flatMap_weak` and `firstMatch_peel_level_weak` carry 360's repair up to
the level, with the same conclusion as `firstMatch_peel_level` and every
agreement premise conditioned on activity.

**`LevelAgreementActive`** replaces 352's predicate:

```lean
firstMatch W x (nonRaw c) = some r →
  bval W (peelRawHlt a) x = true →        -- ← `a` is ACTIVE at this atom
    firstMatch W x (nonRaw a) = some r
```

The precondition is exactly right, and it is worth saying why rather than
asserting it. `peelRawHlt a` is the disjunction of `a`'s non-raw guards with its
halt test, so — because `disjoin` makes guards exclusive and `HaltDeterministic`
separates halting from stepping — it is true at an atom **iff `a` is neither raw
nor dead there**. That is precisely the set 343 measured over, so the predicate
and the measurement are now the same statement. 359's fault was that they were
not.

**Three of the four weak premises need no agreement at all** — they follow from
the definitions:

| premise | source |
|---|---|
| `hactL`, `hactE` | `peelRawHlt_of_nonRaw` — a firing non-raw entry puts its own guard in the disjunction |
| `hbL` | `peelBs_of_loop` — a firing loop entry of any level state is one of `peelBs`'s disjuncts |
| `hbE` | still needs agreement (it is `gateE`'s content) |

with `mem_nonRaw_of_loop` / `mem_nonRaw_of_exit` as the sublist facts. All
`[propext, Quot.sound]`.

**Still to do**: `hbE` and the two agreement premises from
`LevelAgreementActive`, then `peelAut_trans_agrees_weak` and a repaired capstone.
Until those land, 352 is still vacuous for multi-state regions — the repair is
three steps in, not finished.

**Odds: 97%, unchanged.**

**Next.** `hbE` from `LevelAgreementActive`, then the capstone.

## 362 — the repair lands: `solvesBA_of_levelAgreementActive`

```lean
theorem solvesBA_of_levelAgreementActive (aut) (lvl) (rank) (B)
    (hbound) (hmono) (hdet : HaltDeterministic aut)
    (hagree : LevelAgreementActive aut lvl rank) :
    ∃ sol, GkatKleene.SolvesBA aut sol
```

Same conclusion as 352, on the hypothesis 359 showed to be the satisfiable one.
`[propext, Classical.choice, Quot.sound]`, no `sorry`.

The six lemmas that carry it, all compiled first try:

| | |
|---|---|
| `bE_of_active` | the level's loop test is FALSE at an exit atom — the one premise that still needs agreement, applicable because the exiting state is itself active |
| `agreeL_of_active`, `agreeE_of_active` | `[propext]` only |
| `loopoff_of_active`, `hnot_of_active` | the halt premises; both apply agreement at a HALTING state, whose activity comes free from `rawHlt_of_halt` |
| `peelAut_trans_agrees_active` | the transition premise |

**Does the hypothesis match what was measured?** This is the question 359 punished
me for not asking, so: `LevelAgreementActive` demands agreement among states with
`bval (peelRawHlt a) x = true`, i.e. those that fire a non-raw transition **or
halt**. `PAD_BACKATOM` builds a per-atom demand from exactly three kinds —
back-edge-to-`t`, exit-to-`t`, halt — and counts any mismatch as a clash,
skipping raw and dead states. **The two are the same set and the same
disagreement.** So the 100% (5 722 regions, control 126/126) is evidence for this
predicate, not a neighbouring one.

**Where the route stands.**

| item | status |
|---|---|
| bounded non-raising level function | **free** (339) |
| `HaltDeterministic` | **proved** (357, from `UniformWF`) |
| the whole peel, layers, shared lists, gates | **proved** (338-351, 360-362) |
| `LevelAgreementActive` | **measured** 100%, control passing; not proved |

So the remainder is one predicate again — but this time it is the predicate the
measurement actually tests, and the structural route to it (358: only the head of
a loop body is ever non-raw, so at most one state of a region is active, so
agreement is vacuous) is stated and unrefuted.

**Odds: 97%, unchanged.** The repair is complete and the hypothesis is now
honestly matched to its evidence. That restores what 359 cost; it does not add to
it. I am not calling this a milestone.

**Next.** The structural route to `LevelAgreementActive`: at most one state of a
region is active at any atom.

## 363 — 358's structural route is nearly exact, and "nearly" is measurable

358 proposed reducing `LevelAgreementActive` to vacuity: *only the head of a loop
body is ever non-raw, so at most one state of a region is active at any atom, so
agreement holds trivially.* Measured, on 41 885 quotient regions:

```
under the FIRST clash-free ordering: 27 (region, atom) pairs have >1 active
                                     state; max active 2
searching ALL orderings:             672 of 695 multi-state regions admit an
                                     ordering that is clash-free AND leaves
                                     at most one active state per atom
```

Two things follow, and the second is the one that matters.

**The choice of ordering is not incidental.** Reading off the first clash-free
permutation understates what a better choice achieves — 27 offending pairs
becomes 23 offending *regions* once every ordering is searched. Any measurement
that picks "the first one that works" is measuring the search order as much as
the object.

**The route is exact for 96.7% and false for the rest.** 23 of 695 multi-state
regions (3.3%) admit **no** ordering that makes agreement vacuous. In those,
two states of a region are simultaneously active and genuinely **agree** —
agreement is doing real work, not standing in for a triviality.

**Why that is consistent with 358.** 358 measured the SOURCE: only one state per
loop body has an exiting edge, 0 of 12 780. The 23 exceptions are in QUOTIENTS,
where the collapse can put two blocks in one region and let both exit at the same
atom — to the same target, which is why agreement survives while vacuity does
not. The rank-free test confirms the surviving half directly: **0 regions where
two states exit to different targets at the same atom**, over all 41 885.

So the proof of `LevelAgreementActive` cannot route through vacuity. It has to go
through the statement the measurements have never contradicted:

> every exit of a quotient region, at a given atom, goes to the same target.

which is 353's original mechanism, relocated from the source to the quotient
where it belongs.

**Odds: 97%, unchanged.** A proposed shortcut was bounded rather than refuted —
it covers 96.7% and the remainder is characterised. The target predicate is
unchanged and still unrefuted at scale.

**Next.** The quotient-level single-target-exit statement, and whether the
collapse argument of 355-356 delivers it.

## 364 — probing the joints: exits never coincide, and 693/695 regions have one header

363 left the proof needing "all exits of a region at one atom share a target".
Rather than reason further about the lifting joints, `PAD_TWOEXIT` probes them.

```
695 multi-state quotient regions
  0  (region, atom) pairs where TWO OR MORE blocks exit at once
693  of 695 regions have a SINGLE HEADER — a state whose removal from the
     edge set leaves the region acyclic
```

**The exit half is not just single-valued, it is single-SOURCE.** No two blocks
of a region ever exit at the same atom — 0 of 695. So the statement 363 asked
for is true for a stronger reason than expected: there is nothing to agree
*about*, because at most one block exits per atom.

**Which relocates 363's 23 exceptions.** If exits never coincide, the 23 regions
where two states are simultaneously active cannot be two exiters. They must be
two **back-edges** — and by agreement, to the same target.

**And that half is structural too, almost.** 693 of 695 regions have a single
header: every cycle passes through one state, so every back-edge points at it,
so two simultaneous back-edges necessarily share a target. That is the dual of
the exit fact and it settles the loop half of agreement for 99.7% of regions.

**The residue is exactly 2 regions**, which have no single header — irreducible,
multi-entry loops. Agreement still held there (it held everywhere, 41 885/41 885),
but not for this reason. Irreducibility is not an artefact either: the default
census reports 11 139 irreducible Thompson automata, so it is a real
sub-population and not a rounding error.

So `LevelAgreementActive` now decomposes into three parts with three different
statuses:

| part | why | status |
|---|---|---|
| exits agree | at most one block exits per atom | measured 0/695 violations |
| back-edges agree | single header, all back-edges point at it | measured 693/695 |
| halting vs active | exits-shadow-halting | measured (343) |
| irreducible regions | — | **2 regions, no structural reason yet** |

**Odds: 97%, unchanged.** The decomposition is sharper and two of its three parts
have a structural reason rather than a bare measurement. The residue is small and
named, which is not the same as handled.

**Next.** The 2 irreducible regions — whether agreement there has a reason, or
whether the route needs to exclude them.
