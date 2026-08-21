# The nested-chord stratum: derivation before construction

Target shape, from iteration 181's classification of the 31 open SCCs at
NA=4 (`classify_open_sccs.py`):

    lap  m 0 → m 1 → … → m (len-1) → m 0
    port m 0 is the UNIQUE exit state (halts; interiors are silent)
    one extra arm at position `len-1` targeting position `1`

At `len = 3` this is `0 → 1, 1 → 2, 2 → {0,1}`, which is 5 of the 31.
It is the first stratum needing TWO nested `wh`s, which is why it is worth
deriving on paper first: the mechanism generalizes, the shape does not.

## Why it is solvable, and where each axiom enters

Write `X_j` for `sol (m j)`, `g_j`/`b_j` for the lap arm at position `j`,
`gc`/`bc` for the chord arm at `len-1`, `h_j` for `hlt (m j)`.
Interiors are silent, so `h_j = 0` for `1 ≤ j < len` — that is the
measured fact the whole derivation rests on.

**Step 1 — the interior chain factors.**  For `1 ≤ j ≤ len-2` the dispatch
is `X_j = ite g_j (b_j ; X_{j+1}) (test 0)`.  By `s2` the dead fallback is
`test 0 ≡ 0 ; X_{j+1}`, so `u5` factors:

    X_j  ≡  (ite g_j b_j 0) ; X_{j+1}

Iterating, `X_1 ≡ C ; X_{len-1}` with `C` the straight-line walk — exactly
what `pChain_split` already does, with `term` left free.

**Step 2 — the inner loop is a Salomaa equation AT THE BRANCHER.**  The
brancher's dispatch, gathered with the chord arm first (`double_gather`):

    X_{len-1} ≡ ite gc (bc ; X_1) (ite gn (bn ; X_0) (test 0))

Substituting Step 1 (`X_1 ≡ C ; X_{len-1}`):

    X_{len-1} ≡ ite gc ((bc ; C) ; X_{len-1}) (ite gn (bn ; X_0) (test 0))

which is `w3`'s shape with `E := bc ; C` productive (`bc` is an action):

    X_{len-1} ≡ wh gc (bc ; C) ; (ite gn (bn ; X_0) (test 0))          (I)

**The rotation is the whole trick.**  The inner loop's head is the
BRANCHER, not the chord's target, because a `wh` tests its guard at the
top and `gc` is the test available at the brancher's atom.  Trying to head
the inner loop at `m 1` fails: the "continue" condition is not a test at
`m 1`'s atom, it is a test three actions later.

**Step 3 — the outer loop is a second Salomaa equation.**  Interiors are
silent, so the trailing dispatch in (I) again has a dead fallback and `u5`
factors it:

    ite gn (bn ; X_0) (test 0)  ≡  (ite gn bn 0) ; X_0

so `X_{len-1} ≡ wh gc (bc ; C) ; (ite gn bn 0) ; X_0`, and with Step 1,
`X_1 ≡ C ; wh gc (bc ; C) ; (ite gn bn 0) ; X_0`.  The port's dispatch is
`X_0 = ite G (B ; X_1) (test h_0)`, giving

    X_0 ≡ ite G ((B ; C ; wh gc (bc ; C) ; (ite gn bn 0)) ; X_0) (test h_0)

`w3` again, with the whole lap body productive (`B` is an action):

    X_0 ≡ wh G (B ; C ; wh gc (bc ; C) ; (ite gn bn 0)) ; test h_0      (II)

Two `w3` applications, inner then outer.  No uniqueness axiom.

## Construction plan

* `nChain aut m len term k j` — reuse `pChain`; the straight walk over
  positions `1 … len-2` is `pChain aut m len term (len-2) 1`.
* `nInner aut m len` — `wh gc (bc ; pChain aut m len (.test .one) (len-2) 1)`.
* `nPortE aut m len` — the right-hand side of (II).
* `nChain_split` — as `pChain_split`, with the chord arm handled by the
  `double_gather` case and `park_absorb` unchanged on the halt arms.
* `nested_chord_roles` — port by `salomaaE` on (II), brancher by
  `salomaaE` on (I), interiors by `equivFold` on Step 1.
* `nested_chord_assembly_roles` — as `chorded_assembly_roles`; the closed
  forms again mention no `sol`, so no congruence lemma is needed.

## What this does NOT cover

The other measured classes: chord AT the port (`at=(0,)`, 7 instances) and
the two-chord cases (16).  Both need the same nesting mechanism plus a
second gather; the one-chord theorem is the prerequisite either way.

Three of the 31 are MULTI-EXIT and Kosaraju-blocked — no nest of `wh`s
reaches them at all, whatever is built here.
