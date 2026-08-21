#!/usr/bin/env python3
"""Construct and LANGUAGE-VERIFY the exit-absorption solution, per instance.

`check_moves.py` reports which move's PRECONDITION holds.  This builds the
solution the absorption move prescribes and checks it against the automaton,
turning a precondition into a verified solution for those instances.

Shape handled (the measured one): a two-state SCC {h, o} where h is the
unique halting member, h steps only to o, and o steps back to h or out of
the SCC.  The prescribed solution is

    X_h = wh g (p ; <o's dispatch: back-to-h ↦ p, escape to w ↦ p ; X_w>) ; test trail

with g = h's step guard and trail = h's halt mask.  Escape continuations are
supplied as ORACLE LANGUAGES read off the quotient, so only the absorption
step itself is under test.

Usage:  python3 verify_absorption.py runs/lr-NA4-d7.txt [N]
"""
import itertools
import re
import sys
from collections import Counter

from check_moves import parse, collapse


def quotient(hl, st, na):
    part = collapse(hl, st, na)
    blk = {s: i for i, b in enumerate(part) for s in b}
    n = len(part)
    q = {i: (hl[part[i][0]],
             [None if st[part[i][0]][j] is None else blk[st[part[i][0]][j]]
              for j in range(na)]) for i in range(n)}
    return q, n


def scc_of(q, n):
    adj = {i: {t for t in q[i][1] if t is not None} for i in range(n)}

    def reach(a):
        seen, stk = {a}, [a]
        while stk:
            x = stk.pop()
            for y in adj[x]:
                if y not in seen:
                    seen.add(y)
                    stk.append(y)
        return seen
    best, seen = None, set()
    for i in range(n):
        if i in seen:
            continue
        c = sorted(j for j in range(n) if j in reach(i) and i in reach(j))
        seen |= set(c)
        if len(c) > 1 and (best is None or len(c) > len(best)):
            best = c
    return best


def aut_lang(q, start, na, N):
    out = set()

    def go(s, seq, d):
        a = seq[-1]
        if q[s][0] >> a & 1:
            out.add(tuple(seq))
        if d == 0:
            return
        t = q[s][1][a]
        if t is not None:
            for b in range(na):
                go(t, seq + [b], d - 1)
    for a in range(na):
        go(start, [a], N)
    return out


def den(e, seq):
    t = e[0]
    if t == 'test':
        return len(seq) == 1 and seq[0] in e[1]
    if t == 'act':
        return len(seq) == 2
    if t == 'lang':
        return tuple(seq) in e[1]
    if t == 'seq':
        return any(den(e[1], seq[:i + 1]) and den(e[2], seq[i:])
                   for i in range(len(seq)))
    if t == 'ite':
        return den(e[2], seq) if seq[0] in e[1] else den(e[3], seq)
    if t == 'wh':
        if seq[0] not in e[1]:
            return len(seq) == 1
        return any(den(e[2], seq[:i + 1]) and den(e, seq[i:])
                   for i in range(1, len(seq)))
    raise Exception(t)


def build(q, na, scc, N):
    """Return (X_h expression, h) or (None, reason)."""
    heads = [x for x in scc if q[x][0] != 0]
    if len(heads) != 1 or len(scc) != 2:
        return None, 'shape not the measured one'
    h = heads[0]
    o = scc[0] if scc[1] == h else scc[1]
    if any(q[h][1][a] not in (None, o) for a in range(na)):
        return None, 'head steps outside the SCC'
    g = {a for a in range(na) if q[h][1][a] is not None}
    trail = {a for a in range(na) if q[h][0] >> a & 1}
    P = ('act',)
    body_tail = ('test', {a for a in range(na) if q[o][0] >> a & 1})
    for b in range(na):
        t = q[o][1][b]
        if t is None:
            continue
        cont = P if t == h else ('seq', P, ('lang', frozenset(
            aut_lang(q, t, na, N))))
        body_tail = ('ite', {b}, cont, body_tail)
    return ('seq', ('wh', g, ('seq', P, body_tail)), ('test', trail)), h


def main(path, N=7):
    allseq = [list(s) for n in range(N + 1)
              for s in itertools.product(range(4), repeat=n + 1)]
    res = Counter()
    for hl, st, na in parse(path):
        seqs = [s for s in allseq if all(x < na for x in s)]
        q, n = quotient(hl, st, na)
        scc = scc_of(q, n)
        if scc is None:
            res['no SCC'] += 1
            continue
        e, h = build(q, na, scc, N)
        if e is None:
            res['skipped: ' + h] += 1
            continue
        want = aut_lang(q, h, na, N)
        got = {tuple(s) for s in seqs if den(e, s)}
        res['VERIFIED' if want == got else 'MISMATCH'] += 1
    print("%s (strings up to %d actions)" % (path, N))
    for k, v in res.most_common():
        print("   %-34s %d" % (k, v))


if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 7)
