"""Step 5: the repair.  Replace the COSPAN (common quotient) by a SPAN (common
refinement): find h whose Thompson automaton covers BOTH thompson(e) and thompson(f).

`equivBA_of_cover` already turns each leg into EquivBA, so a span gives completeness by
transitivity with no new machinery at all.
"""
import sys, pickle
from itertools import product
from collections import deque
from crystal import *

nT = 2
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
b, c = PRIM(0), PRIM(1)

def guard_of(mask):
    terms = []
    for i, al in enumerate(atoms):
        if not mask[i]: continue
        lit = ONE
        for j in range(nT):
            p = PRIM(j) if al[j] else NOT(PRIM(j))
            lit = p if lit == ONE else AND(lit, p)
        terms.append(lit)
    if not terms: return ZERO
    g = terms[0]
    for t in terms[1:]: g = OR(g, t)
    return g
ALL_GUARDS = [guard_of(m) for m in product([False, True], repeat=len(atoms))]

def covers(Ah, Ae):
    """Is there a UniformBehavioralGAutQuotient thompson(h) -> thompson(e), start|->start?

    Deterministic, so the map is forced by BFS from the start; we only check consistency,
    totality (every h-state must be mapped) and surjectivity onto e's listed states.
    """
    if len(Ah.reachable()) != len(Ah.states):
        return False                      # unreachable h-states would need mapping too
    m, dq = {START: START}, deque([START])
    while dq:
        s = dq.popleft()
        t = m[s]
        if Ah.halt[s] != Ae.halt[t]:
            return False
        for i in range(len(atoms)):
            os_, ot = Ah.step[s][i], Ae.step[t][i]
            if (os_ is None) != (ot is None):
                return False
            if os_ is None:
                continue
            if os_[0] != ot[0]:
                return False
            if os_[1] in m:
                if m[os_[1]] != ot[1]:
                    return False
            else:
                m[os_[1]] = ot[1]; dq.append(os_[1])
    if len(m) != len(Ah.states):
        return False
    return set(m.values()) == set(Ae.states)

def candidates(e, f):
    for g in ALL_GUARDS:
        yield ITE(g, e, f)
        yield ITE(g, f, e)
        yield ITE(g, e, e)
        yield ITE(g, f, f)

# ------------------------------------------------ the refuting pair, in detail
e0 = SEQ(ACT('p'), WH(b, ACT('p')))
f0 = SEQ(ITE(b, TEST(ONE), ACT('p')), WH(b, ACT('p')))
Ae0, Af0 = Aut(e0, atoms), Aut(f0, atoms)
print('refuting pair:')
print(f'  e = {eshow(e0)}')
print(f'  f = {eshow(f0)}')
print(f'  thompson(f) covers thompson(e)? {covers(Af0, Ae0)}')
print(f'  thompson(e) covers thompson(f)? {covers(Ae0, Af0)}')
found = None
for h in candidates(e0, f0):
    Ah = Aut(h, atoms)
    if covers(Ah, Ae0) and covers(Ah, Af0):
        found = h; break
print(f'  common REFINEMENT h: {eshow(found) if found else "none in the family"}')
if found:
    Ah = Aut(found, atoms)
    print(f'    |thompson(h)| = {len(Ah.states)}  covers e ({len(Ae0.states)}) '
          f'and f ({len(Af0.states)})')

# ------------------------------------------------ every crux pair from run2
crux = pickle.load(open('crux.pkl', 'rb'))
print(f'\nspan test over all {len(crux)} crux pairs from the size-4 sweep:')
ok = bad = 0
misses = []
for (sz, njs, e, f, js) in crux:
    Ae, Af = Aut(e, atoms), Aut(f, atoms)
    hit = None
    for h in candidates(e, f):
        Ah = Aut(h, atoms)
        if covers(Ah, Ae) and covers(Ah, Af):
            hit = h; break
    if hit: ok += 1
    else:
        bad += 1
        misses.append((sz, e, f))
print(f'  common refinement found: {ok}/{len(crux)}')
print(f'  no refinement in the tested family: {bad}')
misses.sort()
for (sz, e, f) in misses[:8]:
    print(f'    size {sz}:  e = {eshow(e)}\n              f = {eshow(f)}')
