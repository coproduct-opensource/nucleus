
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
