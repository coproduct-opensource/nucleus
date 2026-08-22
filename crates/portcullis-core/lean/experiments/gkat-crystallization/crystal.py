"""Week-one falsification experiment for `CommonSyntacticCollapse` (Brick Three).

Faithful executable mirror of the Lean definitions in
crates/portcullis-core/lean/GkatThompsonUniquenessProofs.lean:
  thompsonTest / thompsonAction / iteInitialized / seqInitialized / loopInitialized
  sumGSystem / seqGSystem / InitializedGAut.toGAut / firstMatch / autStep / bval

Purpose: GKAT automata are DETERMINISTIC, so a functional bisimulation quotient that
identifies the two starts is FORCED: it must be the joint trace quotient J*.  This script
computes J* and asks whether it is realised by a Thompson automaton.
"""
from itertools import product
from collections import deque

# ---------------------------------------------------------------- BExp

ZERO = ('0',)
ONE = ('1',)
def PRIM(i): return ('p', i)
def AND(a, b): return ('&', a, b)
def OR(a, b): return ('|', a, b)
def NOT(a): return ('~', a)

def bval(b, atom):
    k = b[0]
    if k == '0': return False
    if k == '1': return True
    if k == 'p': return atom[b[1]]
    if k == '&': return bval(b[1], atom) and bval(b[2], atom)
    if k == '|': return bval(b[1], atom) or bval(b[2], atom)
    if k == '~': return not bval(b[1], atom)
    raise AssertionError(b)

# ---------------------------------------------------------------- Exp

def ACT(a): return ('act', a)
def TEST(b): return ('test', b)
def SEQ(e, f): return ('seq', e, f)
def ITE(b, e, f): return ('ite', b, e, f)
def WH(b, e): return ('wh', b, e)

def bshow(b):
    k = b[0]
    if k == '0': return '0'
    if k == '1': return '1'
    if k == 'p': return 'bcde'[b[1]]
    if k == '&': return f'({bshow(b[1])}&{bshow(b[2])})'
    if k == '|': return f'({bshow(b[1])}|{bshow(b[2])})'
    if k == '~': return f'~{bshow(b[1])}'

def eshow(e):
    k = e[0]
    if k == 'act': return e[1]
    if k == 'test': return bshow(e[1])
    if k == 'seq': return f'{eshow(e[1])};{eshow(e[2])}'
    if k == 'ite': return f'if {bshow(e[1])} then {eshow(e[2])} else {eshow(e[3])}'
    if k == 'wh': return f'while {bshow(e[1])} do ({eshow(e[2])})'

def esize(e):
    k = e[0]
    if k in ('act', 'test'): return 1
    if k == 'seq': return 1 + esize(e[1]) + esize(e[2])
    if k == 'ite': return 1 + esize(e[2]) + esize(e[3])
    if k == 'wh': return 1 + esize(e[2])

# --------------------------------------------- InitializedGAut (Lean-faithful)

class IG:
    """core = (states, hlt: dict, trans: dict), plus initHlt / initTrans."""
    __slots__ = ('states', 'hlt', 'trans', 'initHlt', 'initTrans')
    def __init__(self, states, hlt, trans, initHlt, initTrans):
        self.states, self.hlt, self.trans = states, hlt, trans
        self.initHlt, self.initTrans = initHlt, initTrans

def L(s): return ('L', s)
def R(s): return ('R', s)

def thompson(e):
    k = e[0]
    if k == 'test':                                   # thompsonTest
        return IG([], {}, {}, e[1], [])
    if k == 'act':                                    # thompsonAction
        u = ('u',)
        return IG([u], {u: ONE}, {u: []}, ZERO, [(ONE, e[1], u)])
    if k == 'ite':                                    # iteInitialized
        g, lf, rt = e[1], thompson(e[2]), thompson(e[3])
        states = [L(s) for s in lf.states] + [R(s) for s in rt.states]
        hlt = {L(s): lf.hlt[s] for s in lf.states}
        hlt.update({R(s): rt.hlt[s] for s in rt.states})
        trans = {L(s): [(gg, a, L(t)) for (gg, a, t) in lf.trans[s]] for s in lf.states}
        trans.update({R(s): [(gg, a, R(t)) for (gg, a, t) in rt.trans[s]] for s in rt.states})
        initHlt = OR(AND(g, lf.initHlt), AND(NOT(g), rt.initHlt))
        initTrans = ([(AND(g, gg), a, L(t)) for (gg, a, t) in lf.initTrans]
                     + [(AND(NOT(g), gg), a, R(t)) for (gg, a, t) in rt.initTrans])
        return IG(states, hlt, trans, initHlt, initTrans)
    if k == 'seq':                                    # seqInitialized / seqGSystem
        lf, rt = thompson(e[1]), thompson(e[2])
        states = [L(s) for s in lf.states] + [R(s) for s in rt.states]
        hlt = {L(s): AND(lf.hlt[s], rt.initHlt) for s in lf.states}
        hlt.update({R(s): rt.hlt[s] for s in rt.states})
        trans = {L(s): ([(gg, a, L(t)) for (gg, a, t) in lf.trans[s]]
                        + [(AND(lf.hlt[s], gg), a, R(t)) for (gg, a, t) in rt.initTrans])
                 for s in lf.states}
        trans.update({R(s): [(gg, a, R(t)) for (gg, a, t) in rt.trans[s]] for s in rt.states})
        initHlt = AND(lf.initHlt, rt.initHlt)
        initTrans = ([(gg, a, L(t)) for (gg, a, t) in lf.initTrans]
                     + [(AND(lf.initHlt, gg), a, R(t)) for (gg, a, t) in rt.initTrans])
        return IG(states, hlt, trans, initHlt, initTrans)
    if k == 'wh':                                     # loopInitialized
        g, bd = e[1], thompson(e[2])
        states = list(bd.states)
        hlt = {s: AND(bd.hlt[s], NOT(g)) for s in states}
        trans = {s: (list(bd.trans[s])
                     + [(AND(bd.hlt[s], AND(g, gg)), a, t) for (gg, a, t) in bd.initTrans])
                 for s in states}
        initHlt = NOT(g)
        initTrans = [(AND(g, gg), a, t) for (gg, a, t) in bd.initTrans]
        return IG(states, hlt, trans, initHlt, initTrans)
    raise AssertionError(e)

START = None  # InitializedGAut.toGAut materialises the pseudostate as `none`

def to_gaut(ig):
    """states / hlt / trans of `ig.toGAut`, start = None."""
    states = [START] + [('s', s) for s in ig.states]
    hlt = {START: ig.initHlt}
    trans = {START: [(g, a, ('s', t)) for (g, a, t) in ig.initTrans]}
    for s in ig.states:
        hlt[('s', s)] = ig.hlt[s]
        trans[('s', s)] = [(g, a, ('s', t)) for (g, a, t) in ig.trans[s]]
    return states, hlt, trans

def first_match(trs, atom):
    for (g, a, t) in trs:
        if bval(g, atom):
            return (a, t)
    return None

# ---------------------------------------------------------------- semantics

class Aut:
    """Deterministic guarded automaton evaluated at every atom (= uniformity)."""
    def __init__(self, e, atoms):
        self.exp = e
        self.states, hlt, trans = to_gaut(thompson(e))
        self.halt = {s: tuple(bval(hlt[s], al) for al in atoms) for s in self.states}
        self.step = {s: tuple(first_match(trans[s], al) for al in atoms) for s in self.states}
        # Lean's UniformWF: halting and stepping are disjoint at every atom.
        for s in self.states:
            for i in range(len(atoms)):
                assert not (self.halt[s][i] and self.step[s][i] is not None), \
                    f'UniformWF violated in {eshow(e)} at {s}'

    def reachable(self):
        seen, dq = {START}, deque([START])
        while dq:
            s = dq.popleft()
            for o in self.step[s]:
                if o is not None and o[1] not in seen:
                    seen.add(o[1]); dq.append(o[1])
        return seen

def bisim_partition(auts):
    """Coarsest bisimulation over the disjoint union of several automata."""
    nodes = [(i, s) for i, A in enumerate(auts) for s in A.states]
    sig = {(i, s): (auts[i].halt[s], tuple(o[0] if o else None for o in auts[i].step[s]))
           for (i, s) in nodes}
    idx = {b: n for n, b in enumerate(sorted(set(sig.values()), key=repr))}
    cur = {k: idx[v] for k, v in sig.items()}
    while True:
        sig = {(i, s): (cur[(i, s)],
                        tuple(cur[(i, o[1])] if o else None for o in auts[i].step[s]))
               for (i, s) in nodes}
        idx = {b: n for n, b in enumerate(sorted(set(sig.values()), key=repr))}
        nxt = {k: idx[v] for k, v in sig.items()}
        if len(set(nxt.values())) == len(set(cur.values())):
            return nxt
        cur = nxt

def canon(A):
    """Canonical form of the reachable behaviour from the start (minimised, BFS-labelled)."""
    cls = bisim_partition([A])
    order, dq = {cls[(0, START)]: 0}, deque([START])
    seen = {cls[(0, START)]}
    rows = {}
    while dq:
        s = dq.popleft()
        c = cls[(0, s)]
        row = []
        for o in A.step[s]:
            if o is None:
                row.append(None)
            else:
                cc = cls[(0, o[1])]
                if cc not in seen:
                    seen.add(cc); order[cc] = len(order); dq.append(o[1])
                row.append((o[0], cc))
        rows[c] = (A.halt[s], tuple(row))
    return tuple(sorted(
        (order[c], rows[c][0], tuple((r[0], order[r[1]]) if r else None for r in rows[c][1]))
        for c in rows))

# ------------------------------------------- the forced joint trace quotient J*

def joint_trace_quotient(Ae, Af):
    """Least step-closed equivalence on reach(e) (+) reach(f) identifying the two starts.

    Any functional bisimulation quotient of the joint automaton that identifies the two
    starts factors through this; so the target's reachable part is FORCED to be J*.
    Returns (find, classes, ok) — ok is False if a merged pair is not bisimilar
    (i.e. the two programs are not equivalent).
    """
    parent = {}
    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry
            return True
        return False
    for s in Ae.reachable(): find((0, s))
    for s in Af.reachable(): find((1, s))
    dq = deque()
    if union((0, START), (1, START)):
        dq.append(((0, START), (1, START)))
    while dq:
        x, y = dq.popleft()
        Ax, Ay = (Ae if x[0] == 0 else Af), (Ae if y[0] == 0 else Af)
        for i in range(len(Ax.step[x[1]])):
            ox, oy = Ax.step[x[1]][i], Ay.step[y[1]][i]
            if ox is not None and oy is not None:
                nx, ny = (x[0], ox[1]), (y[0], oy[1])
                if union(nx, ny):
                    dq.append((nx, ny))
    # sanity: merged states must be bisimilar
    cls = bisim_partition([Ae, Af])
    groups = {}
    for k in list(parent):
        groups.setdefault(find(k), []).append(k)
    ok = all(len({cls[m] for m in g}) == 1 for g in groups.values())
    return find, groups, ok

def quotient_injective(A, side, find, groups):
    """Is reach(A) -> J* injective?  (If yes, A's own automaton already IS the target.)"""
    seen = set()
    for s in A.reachable():
        r = find((side, s))
        if r in seen:
            return False
        seen.add(r)
    return True

def jstar_signature(Ae, Af, find):
    """Canonical BFS signature of J* (start class first)."""
    rep = {}
    def cls_of(x): return find(x)
    order, dq = {}, deque()
    root = cls_of((0, START))
    order[root] = 0
    rep[root] = (0, START)
    dq.append(root)
    rows = {}
    while dq:
        c = dq.popleft()
        side, s = rep[c]
        A = Ae if side == 0 else Af
        row = []
        for o in A.step[s]:
            if o is None:
                row.append(None)
            else:
                cc = cls_of((side, o[1]))
                if cc not in order:
                    order[cc] = len(order); rep[cc] = (side, o[1]); dq.append(cc)
                row.append((o[0], cc))
        rows[c] = (A.halt[s], row)
    return tuple(sorted(
        (order[c], rows[c][0], tuple((r[0], order[r[1]]) if r else None for r in rows[c][1]))
        for c in rows))

# ---------------------------------------------------------------- enumeration

def enumerate_exps(max_size, acts, guards, tests):
    by_size = {1: [ACT(a) for a in acts] + [TEST(b) for b in tests]}
    for n in range(2, max_size + 1):
        out = []
        for i in range(1, n):
            j = n - i
            if j < 1: continue
            for x in by_size.get(i, []):
                for y in by_size.get(j, []):
                    out.append(SEQ(x, y))
                    for g in guards:
                        out.append(ITE(g, x, y))
        for x in by_size.get(n - 1, []):
            for g in guards:
                out.append(WH(g, x))
        by_size[n] = out
    return [e for n in sorted(by_size) for e in by_size[n]]
