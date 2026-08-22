
---

## 207 — SCC-LOCAL REASONING IS INCOMPLETE.  Rule 6 in the solver; the trend test BLOCKED.

**Teaching the solver rule 6 exposed something structural.**  The
implementation is `share_tail`/`strip_suffix`: in each arm of the body's
decision structure, drop a suffix equal to the loop's trailing expression.  It
did not work, and the reason turned out to matter more than the fix.

States outside the SCC enter the search as opaque `Ex::Sub` oracles.  For 206's
resister the tail reads `p ; Sub(c1)` and the mid-body exit `p ; Sub(c5)` — no
shared SYNTACTIC suffix, even though `Sub(c1) = 1` makes the real shared suffix
`p`.  Measured directly:

    r206 calculus, SCC only [0,2,3]        false
    r206 calculus, whole automaton [0..4]  true   (depth 5, and 9)

**So the obstruction is oracle opacity, not the rule — and the general
statement is that SCC-LOCAL REASONING IS INCOMPLETE for GKAT solving.**  The
trailing suffix a mid-body exit shares with its loop's tail can live in a state
OUTSIDE the SCC.  Every previous iteration solved SCC by SCC and would have
missed this whole family.

`scc_with_context` extends an SCC with the outside states it reaches whose own
SCC is a SINGLETON — those are solvable by the existing SUBST/elimination
moves, and solving them here makes their expressions visible to the suffix
match.  Non-singleton neighbours stay oracles: they are other loops with their
own solutions, and pulling them in would merge two independent problems.

The compiler literature reaches the same restructuring — "routing all the
original exits from the loop to a MERGE node introduced at the bottom of the
loop" — but pays for it with a CONTROL VARIABLE recording which exit fired.
GKAT has no such variable, so the guard's falsity does the selecting, which is
precisely why rule 6 carries `H · ¬g ≡ H` and why the language check has to
confirm each proposal.

**Measured, 240 000 pairs (NA=3 at 120 000), zero skips:**

    full collapse        NA=2 104/104    NA=3 190/190    NA=4 250/250
    canonical quotient   NA=2 104/104    NA=3 190/190    NA=4 250/250

Everything measured, at both ends of the lattice, is solved.  600 000 pairs, no
failures, no unattempted SCCs, no oracle verdicts — every one language-checked.

**THE TEST I NAMED AS DECISIVE DID NOT RUN.**  At 206 I wrote that what would
move the odds is a sample enlargement producing NO new rule.  Enlarging the
sample now times out: depth 8 and depth 10 at 60 000 pairs both exceed 240s,
and depth 11 at 120 000 pairs COMPLETED before this change.  So this is a
performance REGRESSION from `scc_with_context`, not a pre-existing limit —
`calc_search` is exponential in the state-list length and the lists are now
longer, and on failure the census pays for two searches (context, then bare
SCC) instead of one.

**Odds: 71%, held — deliberately, despite a clean 544/544.**  The perfect score
is on the SAME sample size as 206's, and the one enlargement that would have
tested the rule-per-sample trend is exactly what I broke.  Reporting 100% while
the test designed to falsify the trend cannot run would be reporting the
favourable half of the iteration.  The structural finding — SCC-locality is
insufficient — is real and is the part worth keeping.

**Next, in order.**  Fix the regression (memoize across the two calls; try the
bare SCC first since it is cheaper and usually succeeds; cap the context
extension by SCC size rather than the global cap).  Then run the enlarged
sample and find out whether the trend breaks.

---

## 223 — TWO CLEAN RESULTS: k=4 EXHAUSTIVE AT ZERO, AND THE CRYSTALLIZATION OBSTACLE DOES NOT APPLY.

**1. The k=4 exhaustive enumeration, minimised, returns 0.**

    NA=2 k=2:       256 automata   solvable-but-unsolved: 0
    NA=2 k=3:    15 625            0
    NA=2 k=4: 1 679 616            0

222's 132 were entirely non-minimality artifacts, as the hand-check predicted.
**This is now an exhaustive result over EVERY NA=2 automaton with at most four
states — 1 695 497 of them — with every verdict verified in both directions**
(solvable by exhibited expression, unsolved by language-checked search).  No
oracle anywhere in it.

**2. Grabmayer's obstacle — the one crystallization exists to solve — does not
apply to GKAT, and that is measurable.**

Grabmayer–Fokkink: LLEE (layered loop existence and elimination) is a
STRUCTURAL certificate of solvability — "every prechart with the LLEE-property
admits a unique solution", and "every chart interpretation of a star expression
has the LLEE-property".  Their difficulty, and mine as measured back at 196:
graphs satisfying LLEE are **not closed under bisimulation collapse**, so the
collapse of a solvable graph can lose its certificate.  Their fix is a
LLEE-preserving CRYSTALLIZATION yielding near-collapsed graphs whose SCCs are
collapsed or of twin-crystal shape.  This repo's directory has been named
`gkat-crystallization` since long before I understood why.

Measured here (`PAD_COLLAPSE_BREAKS`) — Thompson automata of random expressions,
solvable by construction; solve, collapse, solve again:

    NA=2   65 857 automata   solved before 65 857, after 65 857   BROKEN: 0
    NA=3   65 857            before 65 856, after 65 857          BROKEN: 0
                             collapse strictly shrank ~60% of them

**Zero breakages**, with the collapse genuinely doing work in three cases out of
five.  (One NA=3 automaton went the OTHER way — unsolved before collapse,
solved after — which is the SCC-oracle-opacity artifact from 207 again.)

**And the reason is in the parenthetical of their own statement:** it is graphs
with EMPTY-STEP transitions that fail to be closed under collapse, "unlike
process graphs with LLEE that only have PROPER-STEP transitions".  Every GKAT
transition carries an action.  **GKAT is the proper-step case**, so the
certificate survives collapse and no crystallization is needed — the full
collapse, and 204's canonical quotient, are sound targets after all.

**Caveat, stated because it matters:** the proper-step reading is my inference
from a search summary of the parenthetical, not from reading the paper's
definitions.  The 0/131 714 measurement is the evidence I actually have; the
explanation is a hypothesis that fits it.

**Odds: 78%, up 2.**  Two independent positives.  The exhaustive result is the
strongest evidence this development has produced — every four-state NA=2
automaton, verified both ways, no counterexample — and it is a different KIND of
evidence from a sampling rate.  Separately, a structural worry imported from the
literature, which would have forced a crystallization construction into the Lean
proof, is measured absent and has a principled reason to be absent.  Held below
a larger jump because both are still k<=4 and NA=2, and because the
proper-step explanation is unverified against the source.

**Next.**  NA=3 exhaustive at k<=3 with the minimised filter, and verify the
proper-step claim against the actual Grabmayer definitions rather than a summary.

---

## 232 — LAYERED ELIMINATION LANDS.  Sound, and incomplete for a nameable reason.

231 diagnosed the residual ~1% as NESTING and named layered elimination as the
fix.  Implemented: repeatedly take the INNERMOST natural loops, check the halt
condition against their own guard, remove their back edges, continue on the
reduced graph.  The worked case from 231 —

    q0: hl={a3} st=[q1,q0,q0,-]      q1: hl={a2,a3} st=[q1,q0,-,-]

— now passes: eliminating the inner self-loop `q1 -a0-> q1` first leaves
`q1: st=[-,q0,-,-]`, so the outer back edge is `q1 -a1-> q0` alone with guard
`{a1}`, and both states' halts lie outside it.

**Measured:**

                                   NA=2                NA=3
    (a) layered-LLEE holds     19 755/19 778 99.88%    99.44%
    (b) survives collapse      19 688/19 778 99.55%    99.22%
    (c) LLEE-but-UNSOLVABLE            0                   0
        solvable-but-no-LLEE          96                 221

**Sufficiency is robust: 0 counterexamples.**  Whenever this graph-only test
succeeds, the automaton is solvable — across ~40 000 automata, no exceptions,
which is the third distinct certificate formulation to hold that direction.

**But (a) and (b) both fall short of 100%, and one cause explains both.**  LLEE
is an EXISTENTIAL over labellings — a chart has it if SOME valid loop labelling
exists — while my procedure COMMITS to one, the innermost-first natural loops of
a particular DFS.  So `llee_layered` is a sound SUFFICIENT TEST for LLEE, not a
decision procedure, and it will report failure whenever the canonical labelling
fails even if another would succeed.  That is exactly the shape of both
shortfalls, and it also explains why collapse-stability slipped from
`uniform_guard`'s 100% to 99.5%: the collapse can force a different labelling
than the one my DFS picks.

**Worth stating plainly: (b) at 99.5% is NOT evidence against Grabmayer's
closure theorem**, because I am not testing LLEE — I am testing one labelling
strategy.  223's measurement of the property that actually matters, solvability
surviving collapse, remains 0 failures in 131 714.

**Odds: 80%, held.**  A sound layered certificate is real progress and its
sufficiency is now confirmed three ways over — but requirement (a) is still not
met, and the fix (search over labellings rather than commit to one) is
identified, not done.  Nothing here justifies moving the number in either
direction.

**Next.**  Make the test an existential: backtracking search over which loops to
eliminate and in what order, rather than the innermost-first DFS choice.  Target
remains (a) at 100% on Thompson automata with (b) and (c) intact.
