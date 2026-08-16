"""Step 4: DECIDE the candidate refutation of `CommonSyntacticCollapse`.

Candidate pair (all states reachable on both sides, so the target is pinned exactly):
    e =  p ; while b do p
    f = (if b then 1 else p) ; while b do p

J* has 2 states and is already bisimulation-collapsed, so any admissible target
thompson(h) must be ISOMORPHIC to J*: exactly one core state, i.e. h contains exactly
one action occurrence.

This script computes the COMPLETE set of Thompson automata of one-action expressions by
closing the Thompson combinators to a fixpoint over the (finite) semantic state space —
so the answer is a decision, not a bounded search.
"""
import sys
from itertools import product
from collections import deque
from crystal import *

nT = int(sys.argv[1]) if len(sys.argv) > 1 else 2
atoms = [tuple(v) for v in product([False, True], repeat=nT)]
NA = len(atoms)
b, c = PRIM(0), PRIM(1)

# ---------------------------------------------------------------- the pair
e = SEQ(ACT('p'), WH(b, ACT('p')))
f = SEQ(ITE(b, TEST(ONE), ACT('p')), WH(b, ACT('p')))
Ae, Af = Aut(e, atoms), Aut(f, atoms)

print(f'tests={nT}  atoms={NA}')
print(f'e = p ; while b do p            states={len(Ae.states)} reachable={len(Ae.reachable())}')
print(f'f = (if b then 1 else p) ; while b do p   states={len(Af.states)} '
      f'reachable={len(Af.reachable())}')
print(f'equivalent (uniform, all atoms): {canon(Ae) == canon(Af)}')
assert len(Ae.reachable()) == len(Ae.states) and len(Af.reachable()) == len(Af.states), \
    'joint automaton is NOT fully reachable — h could carry extra dead states'

find, groups, ok = joint_trace_quotient(Ae, Af)
js = jstar_signature(Ae, Af, find)
print(f'J* well-formed: {ok}   |J*| = {len(js)}')
for row in js:
    print(f'   state {row[0]}: halt={"".join("1" if h else "0" for h in row[1])}  step={row[2]}')

# J* already collapsed?  (then the target is forced to be J* on the nose)
cls = bisim_partition([Ae, Af])
reps = {}
for k in groups:
    reps.setdefault(find(k), k)
sigs = [cls[r] for r in reps.values()]
print(f'J* is bisimulation-collapsed: {len(set(sigs)) == len(sigs)}')

# ------------------------------------------- all semantic guards over nT tests
def guard_of(mask):
    """canonical BExp realising the truth-table `mask` (a tuple of bools over atoms)"""
    terms = []
    for i, al in enumerate(atoms):
        if not mask[i]:
            continue
        lit = ONE
        for j in range(nT):
            p = PRIM(j) if al[j] else NOT(PRIM(j))
            lit = p if lit == ONE else AND(lit, p)
        terms.append(lit)
    if not terms: return ZERO
    g = terms[0]
    for t in terms[1:]: g = OR(g, t)
    return g

ALL_GUARDS = [guard_of(m) for m in product([False, True], repeat=NA)]
print(f'semantic guards over {nT} tests: {len(ALL_GUARDS)}')

# ------------------------------------------- Thompson combinators on IGs
def ig_act(a):
    u = ('u',)
    return IG([u], {u: ONE}, {u: []}, ZERO, [(ONE, a, u)])
def ig_test(g): return IG([], {}, {}, g, [])

def ig_seq(lf, rt):
    states = [L(s) for s in lf.states] + [R(s) for s in rt.states]
    hlt = {L(s): AND(lf.hlt[s], rt.initHlt) for s in lf.states}
    hlt.update({R(s): rt.hlt[s] for s in rt.states})
    trans = {L(s): ([(g, a, L(t)) for (g, a, t) in lf.trans[s]]
                    + [(AND(lf.hlt[s], g), a, R(t)) for (g, a, t) in rt.initTrans])
             for s in lf.states}
    trans.update({R(s): [(g, a, R(t)) for (g, a, t) in rt.trans[s]] for s in rt.states})
    return IG(states, hlt, trans, AND(lf.initHlt, rt.initHlt),
              [(g, a, L(t)) for (g, a, t) in lf.initTrans]
              + [(AND(lf.initHlt, g), a, R(t)) for (g, a, t) in rt.initTrans])

def ig_ite(g, lf, rt):
    states = [L(s) for s in lf.states] + [R(s) for s in rt.states]
    hlt = {L(s): lf.hlt[s] for s in lf.states}
    hlt.update({R(s): rt.hlt[s] for s in rt.states})
    trans = {L(s): [(gg, a, L(t)) for (gg, a, t) in lf.trans[s]] for s in lf.states}
    trans.update({R(s): [(gg, a, R(t)) for (gg, a, t) in rt.trans[s]] for s in rt.states})
    return IG(states, hlt, trans,
              OR(AND(g, lf.initHlt), AND(NOT(g), rt.initHlt)),
              [(AND(g, gg), a, L(t)) for (gg, a, t) in lf.initTrans]
              + [(AND(NOT(g), gg), a, R(t)) for (gg, a, t) in rt.initTrans])

def ig_wh(g, bd):
    states = list(bd.states)
    hlt = {s: AND(bd.hlt[s], NOT(g)) for s in states}
    trans = {s: (list(bd.trans[s])
                 + [(AND(bd.hlt[s], AND(g, gg)), a, t) for (gg, a, t) in bd.initTrans])
             for s in states}
    return IG(states, hlt, trans, NOT(g),
              [(AND(g, gg), a, t) for (gg, a, t) in bd.initTrans])

def key_of(ig):
    """Complete semantic fingerprint of a ONE-core-state IG (start + the state u)."""
    assert len(ig.states) == 1
    u = ig.states[0]
    ih = tuple(bval(ig.initHlt, al) for al in atoms)
    it = tuple((lambda o: (o[0], 0) if o else None)(first_match(ig.initTrans, al))
               for al in atoms)
    uh = tuple(bval(ig.hlt[u], al) for al in atoms)
    ut = tuple((lambda o: (o[0], 0) if o else None)(first_match(ig.trans[u], al))
               for al in atoms)
    return (ih, it, uh, ut)

# ------------------------------------------- fixpoint closure
seen = {}          # key -> witness expression
frontier = {}
for a in ['p']:
    ig, ex = ig_act(a), ACT(a)
    seen[key_of(ig)] = ex; frontier[key_of(ig)] = (ig, ex)

tests_ig = [(ig_test(g), TEST(g), g) for g in ALL_GUARDS]
rounds = 0
while frontier:
    rounds += 1
    nxt = {}
    def offer(ig, ex):
        k = key_of(ig)
        if k not in seen:
            seen[k] = ex; nxt[k] = (ig, ex)
    for (ig, ex) in list(frontier.values()):
        for (tg, tex, g) in tests_ig:
            offer(ig_seq(tg, ig), SEQ(tex, ex))
            offer(ig_seq(ig, tg), SEQ(ex, tex))
        for g in ALL_GUARDS:
            offer(ig_wh(g, ig), WH(g, ex))
            for (tg, tex, _) in tests_ig:
                offer(ig_ite(g, ig, tg), ITE(g, ex, tex))
                offer(ig_ite(g, tg, ig), ITE(g, tex, ex))
    frontier = nxt
    print(f'  round {rounds}: {len(seen)} distinct one-action Thompson automata '
          f'(+{len(nxt)} new)')

print(f'\nCLOSED: {len(seen)} distinct one-action Thompson automata (complete set)')

# ------------------------------------------- does any of them realise J*?
target_start_halt = js[0][1]
target_start_step = tuple((r[0], 0) if r else None for r in js[0][2])
target_u_halt = js[1][1]
target_u_step = tuple((r[0], 0) if r else None for r in js[1][2])
target = (target_start_halt, target_start_step, target_u_halt, target_u_step)
print(f'target J* fingerprint: {target}')

if target in seen:
    print(f'\n*** REALISED by h = {eshow(seen[target])} — NOT a counterexample')
else:
    print('\n*** NOT REALISED by any one-action expression.')
    print('    Since the joint automaton is fully reachable and J* is already collapsed,')
    print('    no h whatsoever admits the required quotient.')
    print('    => CommonSyntacticCollapse is FALSE as stated.')
    # show the closest misses
    near = [(k, v) for k, v in seen.items() if k[2] == target_u_halt and k[3] == target_u_step]
    print(f'\n    automata with the right loop state ({len(near)}), all with a wrong start:')
    for k, v in near[:8]:
        print(f'      start halt={"".join("1" if x else "0" for x in k[0])} '
              f'step={k[1]}   h = {eshow(v)}')
