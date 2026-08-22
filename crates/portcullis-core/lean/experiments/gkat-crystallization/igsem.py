"""Semantic Thompson algebra: the automaton of a composite depends only on the
*semantics* (halt vectors + step functions + initial data) of its components.

Each clause below is read off the Lean definitions in GkatThompsonUniquenessProofs.lean
(thompsonTest / thompsonAction / iteInitialized / seqInitialized / loopInitialized,
seqGSystem / sumGSystem) with `firstMatch` evaluated pointwise per atom.  `check_algebra`
cross-validates every clause against the literal transcription in crystal.py.

State i of an IG is a core state; the initial pseudostate is separate (init*).
A step is either None or (action, target-state-index).
"""
from crystal import (ZERO, ONE, PRIM, AND, OR, NOT, bval, ACT, TEST, SEQ, ITE, WH,
                     thompson, to_gaut, first_match, eshow, esize)


class Sem:
    """(k core states, initHlt[atom], initStep[atom], hlt[state][atom], step[state][atom])"""
    __slots__ = ('k', 'ih', 'it', 'hl', 'st')

    def __init__(self, k, ih, it, hl, st):
        self.k, self.ih, self.it, self.hl, self.st = k, ih, it, hl, st

    def key(self):
        return (self.k, self.ih, self.it, self.hl, self.st)


def sem_test(gvec):
    return Sem(0, tuple(gvec), tuple(None for _ in gvec), (), ())


def sem_act(a, na):
    return Sem(1, tuple(False for _ in range(na)), tuple((a, 0) for _ in range(na)),
               ((True,) * na,), ((None,) * na,))


def _shift(o, off):
    return None if o is None else (o[0], o[1] + off)


def sem_ite(g, L, R):
    na = len(g)
    off = L.k
    ih = tuple(L.ih[i] if g[i] else R.ih[i] for i in range(na))
    it = tuple(L.it[i] if g[i] else _shift(R.it[i], off) for i in range(na))
    hl = tuple(L.hl) + tuple(R.hl)
    st = tuple(L.st) + tuple(tuple(_shift(o, off) for o in row) for row in R.st)
    return Sem(L.k + R.k, ih, it, hl, st)


def sem_seq(L, R):
    na = len(L.ih)
    off = L.k
    ih = tuple(L.ih[i] and R.ih[i] for i in range(na))
    it = tuple(L.it[i] if L.it[i] is not None
               else (_shift(R.it[i], off) if L.ih[i] else None) for i in range(na))
    hl = tuple(tuple(L.hl[s][i] and R.ih[i] for i in range(na)) for s in range(L.k)) \
        + tuple(R.hl)
    st = tuple(tuple(L.st[s][i] if L.st[s][i] is not None
                     else (_shift(R.it[i], off) if L.hl[s][i] else None)
                     for i in range(na)) for s in range(L.k)) \
        + tuple(tuple(_shift(o, off) for o in row) for row in R.st)
    return Sem(L.k + R.k, ih, it, hl, st)


def sem_wh(g, B):
    na = len(g)
    ih = tuple(not g[i] for i in range(na))
    it = tuple(B.it[i] if g[i] else None for i in range(na))
    hl = tuple(tuple(B.hl[s][i] and not g[i] for i in range(na)) for s in range(B.k))
    st = tuple(tuple(B.st[s][i] if B.st[s][i] is not None
                     else (B.it[i] if (B.hl[s][i] and g[i]) else None)
                     for i in range(na)) for s in range(B.k))
    return Sem(B.k, ih, it, hl, st)


# ------------------------------------------------------------------ from expressions

def sem_of_exp(e, atoms):
    """Ground truth: build via the literal transcription in crystal.py, then read off."""
    ig = thompson(e)
    idx = {s: n for n, s in enumerate(ig.states)}
    ih = tuple(bval(ig.initHlt, al) for al in atoms)

    def conv(o):
        return None if o is None else (o[0], idx[o[1]])
    it = tuple(conv(first_match(ig.initTrans, al)) for al in atoms)
    hl = tuple(tuple(bval(ig.hlt[s], al) for al in atoms) for s in ig.states)
    st = tuple(tuple(conv(first_match(ig.trans[s], al)) for al in atoms) for s in ig.states)
    return Sem(len(ig.states), ih, it, hl, st)


def check_algebra(atoms, guards, acts, rounds=200):
    """Every combinator clause must agree with the literal transcription."""
    import itertools
    pool = [ACT(a) for a in acts] + [TEST(g) for g in guards]
    for _ in range(rounds):
        new = []
        for x in pool[:14]:
            for y in pool[:14]:
                new.append(SEQ(x, y))
                for g in guards[:6]:
                    new.append(ITE(g, x, y))
            for g in guards[:6]:
                new.append(WH(g, x))
        for e in new:
            if esize(e) > 5:
                continue
            assert sem_of_exp(e, atoms).key() == _sem_rec(e, atoms).key(), eshow(e)
        pool = new[:40] + pool
        break
    return True


def _sem_rec(e, atoms):
    """Build semantically, via the algebra."""
    na = len(atoms)
    k = e[0]
    if k == 'test':
        return sem_test(tuple(bval(e[1], al) for al in atoms))
    if k == 'act':
        return sem_act(e[1], na)
    if k == 'ite':
        g = tuple(bval(e[1], al) for al in atoms)
        return sem_ite(g, _sem_rec(e[2], atoms), _sem_rec(e[3], atoms))
    if k == 'seq':
        return sem_seq(_sem_rec(e[1], atoms), _sem_rec(e[2], atoms))
    if k == 'wh':
        g = tuple(bval(e[1], al) for al in atoms)
        return sem_wh(g, _sem_rec(e[2], atoms))
    raise AssertionError(e)


# ------------------------------------------------------------------ canonical form

def canon_sem(S):
    """Canonical fingerprint up to renumbering: BFS from the pseudostate, then any
    unreachable states appended by refined signature (they are behaviourally inert for
    cover purposes, and every positive hit is re-verified against a real expression)."""
    na = len(S.ih)
    order, dq = {}, []
    for i in range(na):
        o = S.it[i]
        if o is not None and o[1] not in order:
            order[o[1]] = len(order); dq.append(o[1])
    qi = 0
    while qi < len(dq):
        s = dq[qi]; qi += 1
        for i in range(na):
            o = S.st[s][i]
            if o is not None and o[1] not in order:
                order[o[1]] = len(order); dq.append(o[1])
    rest = sorted(set(range(S.k)) - set(order),
                  key=lambda s: repr((S.hl[s],
                      tuple((o[0], -1) if o else None for o in S.st[s]))))
    for s in rest:
        order[s] = len(order)

    def m(o):
        return None if o is None else (o[0], order[o[1]])
    inv = sorted(range(S.k), key=lambda s: order[s])
    return (S.k, S.ih, tuple(m(o) for o in S.it),
            tuple(S.hl[s] for s in inv),
            tuple(tuple(m(o) for o in S.st[s]) for s in inv))


def reachable_sem(S):
    na = len(S.ih)
    seen, dq = set(), []
    for i in range(na):
        o = S.it[i]
        if o is not None and o[1] not in seen:
            seen.add(o[1]); dq.append(o[1])
    qi = 0
    while qi < len(dq):
        s = dq[qi]; qi += 1
        for i in range(na):
            o = S.st[s][i]
            if o is not None and o[1] not in seen:
                seen.add(o[1]); dq.append(o[1])
    return seen
