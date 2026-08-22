"""Step 3: is the forced target J* realised by the Thompson automaton of SOME h?"""
import sys, pickle
from itertools import product, combinations
from collections import deque
from crystal import *

nT = 2
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
MAXSIZE = int(sys.argv[1]) if len(sys.argv) > 1 else 4
POOL    = int(sys.argv[2]) if len(sys.argv) > 2 else 5   # size bound for candidate h

acts = ['p', 'q']
guards = [PRIM(0), PRIM(1)]
tests = [ONE]

def canon_raw(A):
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

# --- candidate pool of targets h: every shape realised by an expression up to POOL
pool = {}
for h in enumerate_exps(POOL, acts, guards, tests):
    cr = canon_raw(Aut(h, atoms))
    if cr not in pool or esize(h) < esize(pool[cr]):
        pool[cr] = h
print(f'target pool: {len(pool)} Thompson shapes from expressions up to size {POOL}')

crux = pickle.load(open('crux.pkl', 'rb'))
print(f'crux pairs from run2: {len(crux)}\n')

realised, unrealised = 0, []
for (sz, njs, e, f, js) in crux:
    if js in pool:
        realised += 1
    else:
        unrealised.append((sz, njs, e, f, js))

print(f'J* realised by a Thompson automaton: {realised}/{len(crux)}')
print(f'J* NOT realised (candidate counterexamples): {len(unrealised)}')

unrealised.sort(key=lambda r: (r[1], r[0]))
for (sz, njs, e, f, js) in unrealised[:15]:
    print(f'\n  |J*|={njs}  size {sz}')
    print(f'    e = {eshow(e)}')
    print(f'    f = {eshow(f)}')
    for row in js:
        print(f'      state {row[0]}: halt={"".join("1" if h else "0" for h in row[1])} '
              f'step={row[2]}')

# a few realised examples, to show what the crystallized target looks like
print('\n--- sample realised targets (h is a genuine third program) ---')
shown = 0
for (sz, njs, e, f, js) in sorted(crux, key=lambda r: (r[0], r[1])):
    h = pool.get(js)
    if h is None or eshow(h) in (eshow(e), eshow(f)):
        continue
    print(f'  e = {eshow(e)}\n  f = {eshow(f)}\n  h = {eshow(h)}   (|J*|={njs})\n')
    shown += 1
    if shown >= 6:
        break
