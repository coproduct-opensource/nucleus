#!/usr/bin/env python3
"""Check which dumped open SCCs satisfy `chorded_assembly_roles`' hypotheses.

The Lean theorem asks for a lap through every member (`m 0 … m (len-1)`,
closing back to `m 0`), with:

  * every arm of the port `m 0` targeting `m 1`;
  * every arm of an interior `m j`, `j ≠ c`, targeting `nxtAt m len j`;
  * the chord position `c` (with `1 ≤ c` and `c + 1 < len`) additionally
    carrying an arm straight back to `m 0`;
  * interior halts below the port halt — checked here in the strong form
    "interiors do not halt at all";
  * the port's halt excluding its step guard.

Brute-forces the lap over permutations (SCC sizes here are ≤ 5).

Usage:  python3 verify_chorded.py runs/open-scc-NA2-depth7-20k.txt
"""
import itertools
import re
import sys


def parse(path):
    txt = open(path).read()
    for block in re.split(r'\n  OPEN-SCC #', txt)[1:]:
        head = block.split('\n')[0]
        scc = [int(x) for x in
               re.search(r'scc \[([0-9, ]+)\]', head).group(1).split(',')]
        st, hl = {}, {}
        for line in block.split('\n'):
            m = re.match(r'\s+state (\d+): hl=(\S+) st=\[(.*)\]\s*$', line)
            if not m or int(m.group(1)) not in scc:
                continue
            u = int(m.group(1))
            hl[u] = int(m.group(2), 2)
            st[u] = [t.strip() for t in m.group(3).split(',')]
        yield head.split(' ')[0], scc, st, hl


def target(st, u, i):
    t = st[u][i]
    if t == '-':
        return None
    return ('in', int(t[1:])) if t.startswith('s') else ('out', t)


def find_chorded(scc, st, na):
    n = len(scc)
    for perm in itertools.permutations(scc):
        m = list(perm)
        nxt = lambda j: m[(j + 1) % n]
        if not all(any(target(st, m[j], i) == ('in', nxt(j))
                       for i in range(na)) for j in range(n)):
            continue
        if not all(target(st, m[0], i) in (None, ('in', m[1]))
                   for i in range(na)):
            continue
        for c in range(1, n):
            if not (1 <= c and c + 1 < n):
                continue
            good = True
            for j in range(1, n):
                for i in range(na):
                    t = target(st, m[j], i)
                    if t is None:
                        continue
                    allowed = ((('in', nxt(c)), ('in', m[0])) if j == c
                               else (('in', nxt(j)),))
                    if t not in allowed:
                        good = False
            has_chord = (any(target(st, m[c], i) == ('in', m[0])
                             for i in range(na)) and nxt(c) != m[0])
            if good and has_chord:
                return m, c
    return None


def main(path):
    ok = tot = 0
    for tag, scc, st, hl in parse(path):
        tot += 1
        na = len(next(iter(st.values())))
        found = find_chorded(scc, st, na)
        if found is None:
            print("  #%-3s n=%d  NOT CHORDED (different shape)" % (tag, len(scc)))
            continue
        m, c = found
        interiors_silent = all(hl.get(m[j], 0) == 0 for j in range(1, len(m)))
        port_halts = hl.get(m[0], 0) != 0
        exclusive = all(not (hl[m[0]] >> i & 1) or st[m[0]][i] == '-'
                        for i in range(na))
        verdict = interiors_silent and port_halts and exclusive
        ok += 1 if verdict else 0
        print("  #%-3s n=%d  chorded lap=%s c=%d  interiors-silent=%s "
              "port-halts=%s halt/step-exclusive=%s  ->  %s"
              % (tag, len(scc), m, c, interiors_silent, port_halts,
                 exclusive, "VERIFIED" if verdict else "not verified"))
    print("\nall hypotheses verified: %d / %d" % (ok, tot))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1
         else 'runs/open-scc-NA2-depth7-20k.txt')
