"""Cross-check the Rust closure against the Python semantic algebra (itself validated
against the literal Lean transcription)."""
import sys
from itertools import product
from crystal import *
from igsem import *

nT, K = 1, int(sys.argv[1]) if len(sys.argv) > 1 else 1
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
NA = len(atoms)

def guard_of(mask):
    terms = []
    for i, al in enumerate(atoms):
        if not mask[i]: continue
        lit = ONE
        for j in range(nT):
            pp = PRIM(j) if al[j] else NOT(PRIM(j))
            lit = pp if lit == ONE else AND(lit, pp)
        terms.append(lit)
    if not terms: return ZERO
    g = terms[0]
    for t in terms[1:]: g = OR(g, t)
    return g
GUARDS = [(tuple(m), guard_of(m)) for m in product([False, True], repeat=NA)]

def full_canon(S):
    """canonical form, only if fully reachable"""
    if len(reachable_sem(S)) != S.k: return None
    return canon_sem(S)

seen, frontier = {}, {}
def offer(store, S):
    if S.k > K: return
    c = full_canon(S)
    if c is not None and c not in seen:
        seen[c] = S; store[c] = S
for (gv, gx) in GUARDS: offer(frontier, sem_test(gv))
offer(frontier, sem_act('p', NA))
while frontier:
    nxt = {}
    items = list(seen.values()); front = list(frontier.values())
    for X in front:
        for (gv, _) in GUARDS: offer(nxt, sem_wh(gv, X))
        for Y in items:
            offer(nxt, sem_seq(X, Y)); offer(nxt, sem_seq(Y, X))
            for (gv, _) in GUARDS:
                offer(nxt, sem_ite(gv, X, Y)); offer(nxt, sem_ite(gv, Y, X))
    frontier = nxt

def mask(vec): return sum(1 << i for i, v in enumerate(vec) if v)
def stp(o): return 0 if o is None else 1 + o[1]

lines = []
for c, S in seen.items():
    k, ih, it, hl, st = c
    s = f"k={k} ih={mask(ih)} it={[stp(o) for o in it]}"
    for x in range(k):
        s += f" | hl{x}={mask(hl[x])} st{x}={[stp(o) for o in st[x]]}"
    lines.append(s)
lines.sort()
print(len(lines))
for l in lines: print("DUMP", l)
