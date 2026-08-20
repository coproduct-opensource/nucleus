# Summit todo — the three remaining spans

- [x] 1. **General decomposition theorem** (`decomp_solves`): witness-form —
      `StateRole` (fold | ring-header | member/extSol-shaped) per state of an
      arbitrary automaton; witness ⟹ SolvesBA.  All plumbing lives in the witness
      fields (equalities with the API shapes), per the composition pilot's contract.
- [x] 2. **Conditional summit wiring** (`completeness_of_decompCovered`): the open
      problem formally reduced to plan existence — decomposition-witnessed quotient
      existence ⟹ FiniteAxiomsCompleteBA, via decomp_solves +
      certifiedThompson_uniform_solved_quotient.
- [ ] 3. **Plan existence attack (research)**: formal statement of the existence
      hypothesis; strategy record; first structural sub-conjecture formalized and
      measurement-checked.

Status log:
- (start) all three open.
- 1 DONE: GkatDecompProofs.decomp_solves, [propext] only.
- 2 DONE: completeness_of_decompCovered — the open problem is FORMALLY one hypothesis
  (DecompCovered) away from proved, on standard axioms.
