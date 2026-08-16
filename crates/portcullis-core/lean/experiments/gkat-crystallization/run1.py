"""Step 1 of the week-one experiment: the plan's own W1-unrolling pair."""
from itertools import product
from crystal import *

nT = 2
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
b = PRIM(0)

bodies = [ACT('p'),
          SEQ(ACT('p'), ACT('q')),
          ITE(PRIM(1), ACT('p'), ACT('q')),
          ITE(PRIM(1), ACT('p'), TEST(ONE)),          # body may halt immediately
          WH(PRIM(1), ACT('p')),                      # nested loop body
          SEQ(ACT('p'), WH(PRIM(1), ACT('q')))]

print('W1 unrolling:  while b do X   vs   if b then (X ; while b do X) else 1\n')
for X in bodies:
    e = WH(b, X)
    f = ITE(b, SEQ(X, WH(b, X)), TEST(ONE))
    Ae, Af = Aut(e, atoms), Aut(f, atoms)
    equiv = canon(Ae) == canon(Af)
    find, groups, ok = joint_trace_quotient(Ae, Af)
    ie = quotient_injective(Ae, 0, find, groups)
    i_f = quotient_injective(Af, 1, find, groups)
    js = jstar_signature(Ae, Af, find)
    print(f'  X = {eshow(X)}')
    print(f'    equivalent: {equiv}   J* well-formed: {ok}')
    print(f'    |reach e| = {len(Ae.reachable())}  |reach f| = {len(Af.reachable())}  '
          f'|J*| = {len(js)}')
    print(f'    reach(e) -> J* injective: {ie}    reach(f) -> J* injective: {i_f}')
    print(f'    => J* == reach(thompson(e)): {ie and len(js) == len(Ae.reachable())}')
    print()
