#!/usr/bin/env python3
"""Structural analysis of the OPEN SCCs dumped by PAD_SCC_CENSUS.

Answers the question the role ladder needs answered: are the open SCCs
REDUCIBLE (nested loops, expressible as nested `wh` without auxiliary
variables), or irreducible (Kosaraju-blocked)?

Test: Hecht-Ullman T1/T2.  T1 drops a self-loop; T2 merges a non-header
node with a unique predecessor into that predecessor.  A flow graph is
reducible iff T1/T2 reduce it to a single node.

Usage:  python3 analyze_open_sccs.py runs/open-scc-NA2-depth7-20k.txt
"""
import re
import sys


def t1t2_reducible(nodes, edges, header):
    """Hecht-Ullman T1/T2 reducibility test."""
    E = {n: set(edges[n]) for n in nodes}
    N = set(nodes)
    changed = True
    while changed and len(N) > 1:
        changed = False
        for n in list(N):                       # T1: drop self-loops
            if n in E[n]:
                E[n].discard(n)
                changed = True
        for n in list(N):                       # T2: merge unique-pred node
            if n == header or n not in N:
                continue
            preds = [p for p in N if n in E[p]]
            if len(preds) == 1:
                p = preds[0]
                E[p].discard(n)
                E[p] |= (E[n] - {n})
                for m in N:
                    if m != p:
                        E[m].discard(n)
                N.discard(n)
                del E[n]
                changed = True
                break
    return len(N) == 1, len(N)


def parse(path):
    txt = open(path).read()
    for block in re.split(r'\n  OPEN-SCC #', txt)[1:]:
        head = block.split('\n')[0]
        scc = [int(x) for x in
               re.search(r'scc \[([0-9, ]+)\]', head).group(1).split(',')]
        edges = {n: set() for n in scc}
        for line in block.split('\n'):
            if line.startswith('    --'):
                break
            m = re.match(r'\s+state (\d+): hl=\S+ st=\[(.*)\]\s*$', line)
            if not m or int(m.group(1)) not in edges:
                continue
            u = int(m.group(1))
            for tok in m.group(2).split(','):
                tok = tok.strip()
                if tok.startswith('s'):
                    v = int(tok[1:])
                    if v in edges:
                        edges[u].add(v)
        # Sanity check that saved this analysis once already: the dump has
        # other sections (MULTI-PORT, full-quotient) whose lines look alike,
        # and a parser that swallows them silently invents edges.
        assert len(edges) == len(scc) and all(edges[n] is not None for n in scc)
        yield head.split(' ')[0], scc, edges


def main(path):
    red = tot = 0
    for tag, scc, edges in parse(path):
        # header: the first state the census lists for the SCC, which is its entry
        ok, residual = t1t2_reducible(scc, edges, scc[0])
        branchers = sum(1 for n in scc if len(edges[n]) > 1)
        tot += 1
        red += 1 if ok else 0
        print("  #%s size=%d reducible=%s residual=%d branchers=%d"
              % (tag, len(scc), ok, residual, branchers))
    print("open SCCs: %d;  T1/T2-REDUCIBLE: %d;  irreducible: %d"
          % (tot, red, tot - red))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1
         else 'runs/open-scc-NA2-depth7-20k.txt')
