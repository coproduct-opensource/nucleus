#!/usr/bin/env python3
"""For each lattice-resistant pair, which of the two post-elimination moves applies?

  GATED IDENTIFICATION (iteration 186): two states of the multi-state SCC whose
  dispatches differ on a PROPER subset of atoms — then one may stand for the
  other on the region where they agree.

  EXIT ABSORPTION (iteration 188): the SCC has a unique halting member (the
  loop head) and the other member escapes to a continuation whose halt atoms
  lie OUTSIDE the head's step guard and INSIDE its halt mask — then the loop's
  own exit does the break's work.

Usage:  python3 check_moves.py runs/lattice-resistant-NA4-240k.txt
"""
import re
import sys
from collections import Counter


def parse(path):
    txt = open(path).read()
    for b in re.split(r'\n?  LATTICE-RESISTANT PAIR ', txt)[1:]:
        hl, st = {}, {}
        for line in b.split('\n'):
            m = re.match(r'\s+sum state (\d+): hl=(\S+) st=\[(.*)\]', line)
            if not m:
                continue
            s = int(m.group(1))
            hl[s] = int(m.group(2), 2)
            st[s] = [None if t.strip() == '-' else int(t.strip())
                     for t in m.group(3).split(',')]
        if st:
            yield hl, st, len(next(iter(st.values())))


def collapse(hl, st, na):
    K = sorted(st)
    part = [sorted(K)]
    while True:
        blk = {s: i for i, b in enumerate(part) for s in b}
        sig = {s: (hl[s], tuple(None if st[s][i] is None else blk[st[s][i]]
                                for i in range(na))) for s in K}
        new = {}
        for i, b in enumerate(part):
            for s in b:
                new.setdefault((i, sig[s]), []).append(s)
        np = [sorted(v) for v in new.values()]
        if len(np) == len(part):
            return [sorted(x) for x in np]
        part = np


def analyse(hl, st, na):
    part = collapse(hl, st, na)
    blk = {s: i for i, b in enumerate(part) for s in b}
    n = len(part)
    q = {i: (hl[part[i][0]],
             [None if st[part[i][0]][j] is None else blk[st[part[i][0]][j]]
              for j in range(na)]) for i in range(n)}
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

    seen, scc = set(), None
    for i in range(n):
        if i in seen:
            continue
        c = sorted(j for j in range(n) if j in reach(i) and i in reach(j))
        seen |= set(c)
        if len(c) > 1 and (scc is None or len(c) > len(scc)):
            scc = c
    if scc is None:
        return 'no multi-state SCC'
    # gated identification
    for a in scc:
        for c in scc:
            if a >= c:
                continue
            diff = [j for j in range(na)
                    if q[a][1][j] != q[c][1][j]
                    or ((q[a][0] >> j & 1) != (q[c][0] >> j & 1))]
            if len(diff) < na:
                return 'gated identification'
    # exit absorption
    heads = [x for x in scc if q[x][0] != 0]
    if len(heads) != 1:
        return 'neither (no unique halting head)'
    h = heads[0]
    guard = [j for j in range(na) if q[h][1][j] is not None]
    trail = q[h][0]
    esc = {t for x in scc if x != h for t in q[x][1]
           if t is not None and t not in scc}
    if not esc:
        return 'neither (no escape target)'
    halts, frontier, done = 0, set(esc), set()
    while frontier:
        x = frontier.pop()
        if x in done:
            continue
        done.add(x)
        halts |= q[x][0]
        for t in q[x][1]:
            if t is not None and t not in scc:
                frontier.add(t)
    if all(not (halts >> j & 1) for j in guard) and (halts & ~trail) == 0:
        return 'exit absorption'
    return 'neither'


def main(path):
    c = Counter(analyse(*inst) for inst in parse(path))
    tot = sum(c.values())
    print("%s: %d lattice-resistant instances" % (path, tot))
    for k, v in c.most_common():
        print("   %-34s %d" % (k, v))
    covered = c['gated identification'] + c['exit absorption']
    print("   %-34s %d / %d" % ("COVERED BY THE TWO MOVES", covered, tot))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1
         else 'runs/lattice-resistant-NA4-240k.txt')
