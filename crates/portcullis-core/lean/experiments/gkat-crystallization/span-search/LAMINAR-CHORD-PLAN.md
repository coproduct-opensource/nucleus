# One general theorem instead of four special strata

## The measurement that decides the design

Over the 31 open SCCs at NA=4 (`runs/open-scc-NA4-depth7-60k.txt`), rooting
each lap at its unique exit state:

    silent interiors, LAMINAR chords, 1 chord, all backward   ->  5
    silent interiors, LAMINAR chords, 2 chords, all backward  ->  6
    silent interiors, LAMINAR chords, 1 chord, has forward    ->  7
    silent interiors, LAMINAR chords, 2 chords, has forward   -> 10
    MULTI-EXIT (Kosaraju-blocked)                             ->  3

**Every non-multi-exit instance has silent interiors and a LAMINAR chord
set.**  Not one has interior halts, a non-laminar chord pair, or more than
two chords.  So a single theorem — a lap with a laminar chord set — covers
all 28, and building `chord-at-port`, `two-backward-chords`,
`forward+backward` as separate strata would be four times the work for the
same coverage.  `chorded_cycle_roles` and `nested_chord_roles` are the two
special cases already proved; this generalizes both.

## The two chord kinds

Root the lap at the port, positions `0 … len-1`.  A chord runs `c → d`.

* **BACKWARD** (`d ≤ c`): a loop over `[d, c]`.  Handled by
  `nested_chord_roles`' mechanism — the inner `wh` heads AT `c`, the
  brancher, because that is where the chord guard is a test; its body is
  `bc ; seg d c`.
* **FORWARD** (`d > c`): a skip past `c+1 … d-1`.  Both routes rejoin at
  `d`, so the walk at `c` is a two-way `ite` and no loop is created.
  Handled by `chorded_cycle_roles`' mechanism (`s2` on the dead fallback,
  `u5` to factor).

Laminarity is exactly what makes the recursion well-founded: nested or
disjoint intervals, never crossing.

## The construction

`seg a b` — the expression walking positions `a … b`, with every chord
whose interval lies inside `[a, b]` already closed.  Well-founded on
`b - a`:

    seg a a  =  1
    seg a b  =  <arm a→a+1, or the forward-chord ite at a> ; seg (a+1) b
                with, at each position c in [a,b] heading a BACKWARD chord
                to some d in [a,c], the factor `wh gc (bc ; seg d c)`
                inserted on arrival at c

The port then closes as before: `X_0 = wh G (B ; seg 1 (len-1) ; tail) ;
test h_0`, one `w3` at the port plus one `w3` per backward chord.

## What it still cannot do, and why that is the point

The 3 MULTI-EXIT instances have two distinct exit states in one loop.  By
Kosaraju no nest of `wh`s expresses them WITHOUT auxiliary variables, and
GKAT has none.  Checked and rejected: they are not a totality artefact —
only one of the three is non-total, the other two are total.

    #11  0 → {0,1}, 1 → 2, 2 → {1,0};  0 and 2 both halt on one atom,
         1 continues on that same atom.

The loop must remember whether it is at 0/2 or at 1.  That is the flag
Kosaraju says is unavoidable — and the automaton-level answer is
DUPLICATION: unroll so each exit becomes the head at a different time.

**So the ladder cannot close the problem.**  It reaches 98.6% and is
PROVABLY unable to reach the rest.  The general theorem above is worth
building because it collapses four planned strata into one, not because it
finishes anything; the multi-exit cases need the span era's un-sharing
(`GkatTotalizationProofs`: `splitCover`, `hasThompsonCover_of_splitN`),
which is a different construction on a different object.
