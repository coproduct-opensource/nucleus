"""Step 2: search for genuine crux pairs — equivalent e,f where NEITHER Thompson
automaton is the forced target J*, so a real crystallization is required."""
import sys
from itertools import product, combinations
from collections import deque
from crystal import *

nT = 2
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
MAXSIZE = int(sys.argv[1]) if len(sys.argv) > 1 else 4

acts = ['p', 'q']
guards = [PRIM(0), PRIM(1)]
tests = [ONE]

def canon_raw(A):
    """Canonical form of the *un-minimised* reachable automaton (BFS-labelled)."""
    order, dq, rows = {START: 0}, deque([START]), {}
    while dq:
        s = dq.popleft()
        row = []
        for o in A.step[s]:
            if o is None:
                row.append(None)
            else:
                if o[1] not in order:
                    order[o[1]] = len(order); dq.append(o[1])
                row.append((o[0], o[1]))
        rows[s] = (A.halt[s], row)
    return tuple((order[s], rows[s][0],
                  tuple((r[0], order[r[1]]) if r else None for r in rows[s][1]))
                 for s in sorted(order, key=lambda x: order[x]))

exps = enumerate_exps(MAXSIZE, acts, guards, tests)
print(f'enumerated {len(exps)} expressions up to size {MAXSIZE}')

shapes = {}      # canon_raw -> (size, exp, Aut)
for e in exps:
    A = Aut(e, atoms)
    cr = canon_raw(A)
    if cr not in shapes or esize(e) < shapes[cr][0]:
        shapes[cr] = (esize(e), e, A)
print(f'distinct reachable automaton shapes: {len(shapes)}')

classes = {}     # canon (behaviour) -> [(size, exp, Aut)]
for (_, e, A) in shapes.values():
    classes.setdefault(canon(A), []).append((esize(e), e, A))
multi = {k: sorted(v) for k, v in classes.items() if len(v) > 1}
print(f'behaviour classes: {len(classes)}  (with >1 shape: {len(multi)})')

crux, covered, pairs = [], 0, 0
for k, v in multi.items():
    for (se, e, Ae), (sf, f, Af) in combinations(v, 2):
        pairs += 1
        find, groups, ok = joint_trace_quotient(Ae, Af)
        if not ok:
            print('!! non-bisimilar merge — equivalence test disagrees', eshow(e), eshow(f))
            continue
        ie = quotient_injective(Ae, 0, find, groups)
        i_f = quotient_injective(Af, 1, find, groups)
        if ie or i_f:
            covered += 1
        else:
            js = jstar_signature(Ae, Af, find)
            crux.append((se + sf, len(js), e, f, Ae, Af, js))

print(f'\nequivalent pairs examined: {pairs}')
print(f'  already-covered (J* is one side\'s own automaton): {covered}')
print(f'  CRUX (neither side is the target): {len(crux)}')

crux.sort(key=lambda r: (r[0], r[1]))
for (sz, njs, e, f, Ae, Af, js) in crux[:12]:
    print(f'\n  size {sz}: |J*|={njs}  |reach e|={len(Ae.reachable())} '
          f'|reach f|={len(Af.reachable())}')
    print(f'    e = {eshow(e)}')
    print(f'    f = {eshow(f)}')

import pickle
with open('crux.pkl', 'wb') as fh:
    pickle.dump([(sz, njs, e, f, js) for (sz, njs, e, f, Ae, Af, js) in crux], fh)
print(f'\nsaved {len(crux)} crux pairs to crux.pkl')
