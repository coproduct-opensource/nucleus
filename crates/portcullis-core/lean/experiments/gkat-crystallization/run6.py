"""Step 6: the canonical span candidate is the PULLBACK thompson(e) x_beh thompson(f).
Is it Thompson-realisable?  (This is the dual of the refuted question.)"""
import sys, pickle
from itertools import product
from collections import deque
from crystal import *

nT = 2
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
b, c = PRIM(0), PRIM(1)

def canon_raw_states(halt, step, start):
    order, dq, rows = {start: 0}, deque([start]), {}
    while dq:
        s = dq.popleft()
        row = []
        for o in step[s]:
            if o is None: row.append(None)
            else:
                if o[1] not in order:
                    order[o[1]] = len(order); dq.append(o[1])
                row.append((o[0], o[1]))
        rows[s] = (halt[s], row)
    return tuple((order[s], rows[s][0],
                  tuple((r[0], order[r[1]]) if r else None for r in rows[s][1]))
                 for s in sorted(order, key=lambda x: order[x]))

def canon_raw(A): return canon_raw_states(A.halt, A.step, START)

def pullback(Ae, Af):
    """Reachable fiber product; projections are automatically covers when total+onto."""
    halt, step = {}, {}
    start = (START, START)
    dq, seen = deque([start]), {start}
    while dq:
        (u, v) = dq.popleft()
        halt[(u, v)] = Ae.halt[u]
        row = []
        for i in range(len(atoms)):
            ou, ov = Ae.step[u][i], Af.step[v][i]
            if ou is None or ov is None:
                row.append(None)
            else:
                t = (ou[1], ov[1])
                if t not in seen:
                    seen.add(t); dq.append(t)
                row.append((ou[0], t))
        step[(u, v)] = tuple(row)
    return halt, step, start, seen

def proj_onto(seen, idx, A):
    return {s[idx] for s in seen} == set(A.states)

# ------------------------------------------------ pool of Thompson shapes
acts, guards, tests = ['p'], [PRIM(0), PRIM(1), NOT(PRIM(0))], [ONE]
POOL = int(sys.argv[1]) if len(sys.argv) > 1 else 5
pool = {}
for h in enumerate_exps(POOL, acts, guards, tests):
    A = Aut(h, atoms)
    if len(A.reachable()) != len(A.states):
        continue                              # need fully reachable to be a clean cover
    cr = canon_raw(A)
    if cr not in pool or esize(h) < esize(pool[cr]):
        pool[cr] = h
print(f'pool: {len(pool)} fully-reachable Thompson shapes (expressions <= size {POOL})')

crux = pickle.load(open('crux.pkl', 'rb'))
# restrict to the single-action / two-guard fragment the pool covers
def uses_only(e, acts_ok):
    k = e[0]
    if k == 'act': return e[1] in acts_ok
    if k == 'test': return True
    if k == 'seq': return uses_only(e[1], acts_ok) and uses_only(e[2], acts_ok)
    if k == 'ite': return uses_only(e[2], acts_ok) and uses_only(e[3], acts_ok)
    if k == 'wh': return uses_only(e[2], acts_ok)
sel = [r for r in crux if uses_only(r[2], {'p'}) and uses_only(r[3], {'p'})]
print(f'crux pairs in the single-action fragment: {len(sel)}')

hit = miss = degen = 0
misses = []
for (sz, njs, e, f, js) in sel:
    Ae, Af = Aut(e, atoms), Aut(f, atoms)
    halt, step, start, seen = pullback(Ae, Af)
    if not (proj_onto(seen, 0, Ae) and proj_onto(seen, 1, Af)):
        degen += 1
        continue
    cr = canon_raw_states(halt, step, start)
    if cr in pool: hit += 1
    else:
        miss += 1; misses.append((sz, len(seen), e, f))

print(f'\npullback is a Thompson shape : {hit}')
print(f'pullback NOT in pool         : {miss}')
print(f'projections not surjective   : {degen}')
misses.sort()
for (sz, n, e, f) in misses[:10]:
    print(f'  size {sz} |pullback|={n}\n    e = {eshow(e)}\n    f = {eshow(f)}')
