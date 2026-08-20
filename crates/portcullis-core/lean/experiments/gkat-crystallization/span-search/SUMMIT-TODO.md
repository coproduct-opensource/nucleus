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
      - [ ] S0: the trim hypothesis — LiveSteps for the Thompson sum (silent-freeness
            of Thompson automata of normalized programs + the dead-code bridge in
            EquivBA for arbitrary programs)
      - [ ] S2: role existence for the canonical quotient (the mathematical core)

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
