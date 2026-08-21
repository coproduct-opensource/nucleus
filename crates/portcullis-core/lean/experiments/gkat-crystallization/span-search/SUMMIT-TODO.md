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
