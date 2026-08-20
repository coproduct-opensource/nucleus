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
