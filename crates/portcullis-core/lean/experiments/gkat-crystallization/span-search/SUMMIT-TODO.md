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
