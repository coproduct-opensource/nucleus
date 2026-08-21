#!/usr/bin/env python3
"""Classify the dumped open SCCs by the shape a role theorem would need.

Two DIFFERENT graph conditions matter here and are easy to confuse:

  * REDUCIBILITY (Hecht-Ullman T1/T2) is about loop ENTRY — every loop has
    a single header.  `analyze_open_sccs.py` tests this.
  * KOSARAJU's condition is about loop EXITS — a flowchart is a structured
    program WITHOUT auxiliary variables iff no loop has two distinct exits.

A graph can be reducible and still have two exits, so reducibility does NOT
imply a role theorem can reach it.  This script tests the exit condition,
then roots a lap at the unique exit state and reports where the extra
(chord) arms sit — which is what picks the next stratum.

Usage:  python3 classify_open_sccs.py runs/open-scc-NA4-depth7-60k.txt
"""
import itertools
import sys
from collections import Counter

from verify_chorded import parse


def main(path):
    cnt = Counter()
    for _tag, scc, st, hl in parse(path):
        na = len(next(iter(st.values())))
        n = len(scc)
        succ = {s: sorted({int(st[s][i][1:]) for i in range(na)
                           if st[s][i].startswith('s')}) for s in scc}
        halts = [s for s in scc if hl[s] != 0]
        exiters = [s for s in scc
                   if any(st[s][i].startswith('X') for i in range(na))]
        ports = sorted(set(halts) | set(exiters))
        if len(ports) != 1:
            cnt[('MULTI-EXIT (Kosaraju-blocked)', n, len(ports), '', ())] += 1
            continue
        p = ports[0]
        best = None
        for perm in itertools.permutations([s for s in scc if s != p]):
            m = [p] + list(perm)
            nxt = {m[j]: m[(j + 1) % n] for j in range(n)}
            if not all(nxt[u] in succ[u] for u in scc):
                continue
            extra = [(u, v) for u in scc for v in succ[u] if v != nxt[u]]
            if best is None or len(extra) < len(best[1]):
                best = (m, extra)
        if best is None:
            cnt[('no lap from the exit state', n, None, '', ())] += 1
            continue
        m, extra = best
        tgt = ('all chords to port' if all(v == p for _, v in extra)
               else 'some chord to interior')
        pos = tuple(sorted(m.index(u) for u, _ in extra))
        cnt[('lap rooted at exit state', n, len(extra), tgt, pos)] += 1
    print("open SCCs, lap ROOTED AT THE UNIQUE EXIT STATE:")
    for k, v in cnt.most_common():
        print("   {:<30} n={} chords={} {:<24} at={} -> {}"
              .format(k[0], k[1], k[2], k[3], k[4], v))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1
         else 'runs/open-scc-NA4-depth7-60k.txt')
