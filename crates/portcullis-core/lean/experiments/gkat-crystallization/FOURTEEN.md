# The fourteen resisting automata

The whole GKAT completeness programme is one open statement, `PaddedDiagPullbackCovered`,
and after every reduction the concrete residue is the fourteen automata below.

They are **branch pieces of a padded kernel pair**: the part of the synchronised product of
two language-equivalent, total, dead-canonical programs that is reachable from one entry
branch, listed with its entry restricted to that branch.  Covering them is exactly the
remaining hypothesis of `RestrictedBranchesCovered`.

## Format

`NA = 2` atoms.  `ih` and `hl_i` are bitmasks over atoms (bit `x` set = halts at atom `x`).
`it` and `st_i` are 1-based target states, `0` meaning no transition.  Actions are not
tracked: the harness works over a single action alphabet, which is sound here because
homogeneity makes every transition into a state carry that state's own action.

## What is established about them

* All five states, all satisfy the nesting coequation (`nested`), all have a single entry
  branch, seven reducible and seven not.
* **Not** explained by pool size: they are within the `K = 5` cap, so every program of at
  most five states was enumerated and none of them is one.
* **Not** explained by non-total inputs: they descend from the `PAD_TOTAL` population.
* **Not** repaired by un-sharing: a single entry branch un-shares to itself plus an empty
  piece, so there is no progress to make.
* They resist a shared refinement closure of **267,991 automata** built from **396 seeds**
  spanning their behaviour class, reaching **16 states**, saturated — no target was newly
  covered after round 0 across seven rounds.

## What they are candidate counterexamples *to*

Not to `PaddedDiagPullbackCovered`.  `RestrictedBranchesCovered` is a **sufficient** condition
for it, never a necessary one: the statement asks only for *some* listing `l` with the
diagonal inside it such that `pullbackOn φ ψ base l` is Thompson-covered, and the branch split
is one way to produce one.  These fourteen say that *that route* stalls on some inputs; they
say nothing about whether another listing works.

Two facts make the distinction concrete.  One level of un-sharing covers **2181 of 2181**
pullbacks, so the pullbacks themselves are covered — what is unverified for these cases is
only whether the covering un-shared automaton is *Thompson*, which needs both its parts to be.
Refinement covers the pullback directly in **1535 of 2181** cases — measured on all of them,
not sampled.  (An earlier "196 of 200" figure came from `take(200)`, which is the first two
hundred rather than a random draw, and overstated the rate.)

So the honest status is: candidate counterexamples to the branch-split route, inside an open
statement that still has no counterexample.

That said, the branch route is the *strongest* known route, not a sideshow: un-sharing covers
2181 of 2181 while refinement covers 1535 of 2181.  These fourteen are therefore obstacles on
the best available path, and clearing them matters more, not less.

## What is NOT established

Refinement is not complete: `RefinementSuffices` is refuted, so a cover outside the
refinement closure remains possible, and these are **candidates**, not a refutation.

The structural story is **withdrawn**.  All fourteen have a two-exit cycle and ten have a
two-halt cycle, but the base rates among *pullbacks* — which is the population these are drawn
from — are **72%** and **56%**.  Against that control both figures are unremarkable.  (The
earlier comparison used the base rate among Thompson automata, 46.9% and 1.5%, which is the
wrong population.)

A controlled comparison of the full residue against the covered pullbacks finds **no**
separating structural feature at all: two-exit 71.4% vs 72.7%, two-halt 55.8% vs 56.3%,
nested 100% vs 100%, reducible 76.0% vs 76.3%.  The only difference is size — 6.63 states
against 6.25 — which is what a search-reach limit looks like rather than an obstruction.

## The automata

         1	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=Some((1, 4)) cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 4] | hl2=0 st2=[2, 3] | hl3=0 st3=[5, 3] | hl4=1 st4=[0, 1]
         2	    PARTRESIST k=5 nested=true red=true 2exit=Some((0, 1)) 2halt=Some((1, 4)) cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 4] | hl2=0 st2=[5, 3] | hl3=0 st3=[5, 3] | hl4=1 st4=[0, 1]
         3	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=Some((2, 4)) cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[2, 3] | hl2=2 st2=[4, 0] | hl3=0 st3=[2, 5] | hl4=2 st4=[1, 0]
         4	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 2)) 2halt=None cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[4, 5] | hl2=2 st2=[1, 0] | hl3=0 st3=[2, 5] | hl4=2 st4=[4, 0]
         5	    PARTRESIST k=5 nested=true red=true 2exit=Some((0, 1)) 2halt=Some((2, 3)) cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[2, 4] | hl2=2 st2=[5, 0] | hl3=2 st3=[1, 0] | hl4=0 st4=[2, 4]
         6	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=Some((1, 4)) cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 4] | hl2=0 st2=[5, 4] | hl3=0 st3=[5, 3] | hl4=1 st4=[0, 1]
         7	    PARTRESIST k=5 nested=true red=true 2exit=Some((0, 1)) 2halt=None cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 1] | hl2=0 st2=[4, 3] | hl3=1 st3=[0, 5] | hl4=0 st4=[4, 3]
         8	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=Some((2, 4)) cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[4, 5] | hl2=2 st2=[4, 0] | hl3=0 st3=[2, 5] | hl4=2 st4=[1, 0]
         9	    PARTRESIST k=5 nested=true red=true 2exit=Some((0, 2)) 2halt=None cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[2, 4] | hl2=2 st2=[1, 0] | hl3=2 st3=[5, 0] | hl4=0 st4=[2, 4]
        10	    PARTRESIST k=5 nested=true red=true 2exit=Some((0, 1)) 2halt=Some((1, 3)) cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 1] | hl2=0 st2=[4, 5] | hl3=1 st3=[0, 1] | hl4=0 st4=[2, 3]
        11	    PARTRESIST k=5 nested=true red=true 2exit=Some((0, 1)) 2halt=Some((2, 4)) cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[4, 5] | hl2=2 st2=[1, 0] | hl3=0 st3=[2, 3] | hl4=2 st4=[1, 0]
        12	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=Some((1, 4)) cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 4] | hl2=0 st2=[2, 1] | hl3=0 st3=[5, 3] | hl4=1 st4=[0, 1]
        13	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=Some((2, 4)) cands=46 | ih=0 it=[1, 0] | hl0=0 st0=[2, 3] | hl1=0 st1=[1, 3] | hl2=2 st2=[4, 0] | hl3=0 st3=[2, 5] | hl4=2 st4=[1, 0]
        14	    PARTRESIST k=5 nested=true red=false 2exit=Some((0, 1)) 2halt=None cands=46 | ih=0 it=[0, 1] | hl0=0 st0=[2, 3] | hl1=1 st1=[0, 1] | hl2=0 st2=[4, 5] | hl3=1 st3=[0, 5] | hl4=0 st4=[4, 3]
