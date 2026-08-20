#!/usr/bin/env python3
"""Ring-mode certificate generator.

Consumes one CERT #A block plus its RING SCC walk plan (both from a PAD_ATTACK run)
and emits a complete Lean instance certificate: emitted bisimulation skeleton (via
emit_cert.emit) with ring/parking solutions and SolvesBA proofs assembled from the
combinator kit validated by GkatCertR1-R6 (GkatRingSupportProofs).

Usage: emit_ring.py <attack-run-file> <pair-number> <lean-name>
"""
import re, sys
import emit_cert as EC

BT = "bT"
NBT = "(BExp.not bT)"


def atom_guard(a):
    return NBT if a == 0 else BT


def parse_plan(text, pairno):
    """The RING SCC plan between 'ATTACK #<n>' and its 'CERT #A<n>' block."""
    start = text.index(f"ATTACK #{pairno}\n")
    end = text.index(f"  CERT #A{pairno}\n")
    seg = text[start:end]
    m = re.search(r"RING SCC \[([0-9, ]+)\] header=(\d+) exit=0b(\d+)", seg)
    plan = {"members": [int(x) for x in m.group(1).split(",")],
            "header": int(m.group(2)), "exit": int(m.group(3), 2), "walk": []}
    for sm in re.finditer(r"state (\d+): (\[.*\])", seg):
        plan["walk"].append((int(sm.group(1)), parse_steps(sm.group(2))))
    return plan


def parse_steps(s):
    import ast
    s = re.sub(r"(SelfLoop|Act|Park|DeadGuard|Inline|Sub|Branch)\(", r"('\1', ", s)
    return ast.literal_eval(s)


# ---------------- expression building ----------------

def seq(*xs):
    """Right-nested .seq of expression strings."""
    out = xs[-1]
    for x in reversed(xs[:-1]):
        out = f"(.seq {x} {out})"
    return out


def raw_factor(step, ring, embed_rest=None):
    """The raw (sol-free except Inline) factor expression for one step."""
    k = step[0]
    if k == "SelfLoop":
        return f"(.wh {atom_guard(step[1])} pA)"
    if k == "Act":
        return "pA"
    if k == "Park":
        c = ring.cexp
        return f"(.ite {c} (.test {c}) pA)"
    if k == "DeadGuard":
        return f"(.ite {atom_guard(step[1])} pA (.test BExp.zero))"
    if k == "Inline":
        return f"(.ite {atom_guard(step[1])} (.seq pA sol{step[2]}) pA)"
    if k == "Branch":
        assert step[2] == [], "only direct-to-header branch sides"
        assert embed_rest is not None
        return f"(.ite {atom_guard(step[1])} pA {seq('pA', embed_rest)})"
    raise Exception(k)


class Ring:
    def __init__(self, d, plan):
        self.d, self.plan = d, plan
        self.h = plan["header"]
        self.c = plan["exit"]
        self.cexp = EC.mask_bexp(self.c)
        self.gexp = EC.mask_bexp(3 & ~self.c)
        self.scc = set(s for s, _ in plan["walk"]) | {self.h}
        for s, steps in plan["walk"]:
            for st in steps:
                if st[0] == "Sub":
                    for (u, _) in st[2]:
                        self.scc.add(u)

    def sub_inner_raw(self, substep):
        """Raw body of an inner while: seq of the inner state's factors."""
        parts = []
        for (_, usteps) in substep[2]:
            for ust in usteps:
                parts.append(raw_factor(ust, self))
        return seq("pA", *parts) if len(parts) else "pA"

    def walk_parts(self, i):
        """(state, [raw parts], next_state, steps).  Branch embeds the raw remainder."""
        s, steps = self.plan["walk"][i]
        nxt = self.plan["walk"][i + 1][0] if i + 1 < len(self.plan["walk"]) else self.h
        parts = []
        for st in steps:
            if st[0] == "Sub":
                parts.append(f"(.wh {atom_guard(st[1])} {self.sub_inner_raw(st)})")
            elif st[0] == "Branch":
                rest = self.suffix_raw(i + 1)
                parts.append(f"(.ite {atom_guard(st[1])} pA "
                             f"{seq('pA', rest) if rest else 'pA'})")
                nxt = st[3]
            else:
                parts.append(raw_factor(st, self))
        return s, parts, nxt, steps

    def suffix_raw(self, i):
        """Raw expression of walk positions i.. (None past the end)."""
        if i >= len(self.plan["walk"]):
            return None
        _, parts, _, steps = self.walk_parts(i)
        if steps and steps[-1][0] == "Branch":
            return seq(*parts) if len(parts) > 1 else parts[0]
        nxt_raw = self.suffix_raw(i + 1)
        if nxt_raw is None:
            return seq(*parts) if len(parts) > 1 else parts[0]
        return seq(*(parts + [nxt_raw]))

    def spine(self):
        """The flattened BODY parts: header edge pA then every walk part in order,
        stopping at (and including) a Branch factor."""
        out = ["pA"]
        for i in range(len(self.plan["walk"])):
            _, parts, _, steps = self.walk_parts(i)
            out.extend(parts)
            if steps and steps[-1][0] == "Branch":
                break
        return out

    def body(self):
        sp = self.spine()
        return seq(*sp)


def suffix_str(parts, j):
    return seq(*parts[j:]) if len(parts) - j > 1 else parts[j]


def spine_chain(parts, solH):
    """Proof term: EquivBA (.seq BODY solH) (p ; sol_first) via right-spine s1 pushes.
    parts = flattened spine; the chain stops one before the end (last suffix is defeq
    to the final state's sol)."""
    m = len(parts)
    def P(j):
        if j == m - 2:
            return f"(EquivBA.base (Equiv.s1 {parts[j]} {parts[j+1]} {solH}))"
        return (f"(EquivBA.trans (EquivBA.base (Equiv.s1 {parts[j]} "
                f"{suffix_str(parts, j+1)} {solH}))\n"
                f"      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) {P(j+1)}))")
    return P(0)


def eqrhs(d, c, sol):
    """The eqRHS text for class c, matching emit()'s QAut trans order (recs then fwds)."""
    cl = d["cls"][c]
    entries = [(EC.mask_bexp(1 << a), c) for a in cl["rec"]]
    entries += [(EC.mask_bexp(1 << a), t) for a, t in cl["fwd"]]
    out = f"(.test {EC.mask_bexp(cl['hlt'])})"
    for g, t in reversed(entries):
        out = f"(.ite {g} (.seq pA {sol(t)}) {out})"
    return out


def orient(nat_guard, then_txt, else_txt, want_first_guard, dead_arm, himp_pair):
    """Bridge a natural `ite nat_guard then else` to the eqRHS orientation.
    Returns (extra proof steps text applied after the natural form)."""
    steps = []
    if nat_guard != want_first_guard:
        steps.append(f"(EquivBA.base (Equiv.u2 {nat_guard} {then_txt} {else_txt}))")
    if dead_arm:
        b, z, himp = himp_pair
        steps.append(f"(else_expand {b} {z} ({himp}))")
    return steps


def chain(*terms):
    terms = [t for t in terms if t]
    out = terms[-1]
    for t in reversed(terms[:-1]):
        out = f"(EquivBA.trans {t}\n    {out})"
    return out


def emit_ring(d, plan, name, attack_text, pairno):
    ring = Ring(d, plan)
    h, cexp, gexp = ring.h, ring.cexp, ring.gexp
    k = d["k"]
    cls = d["cls"]
    sol = lambda c: f"sol{c}"

    # dependency graph over classes
    deps = {c: set() for c in range(k)}
    walk_next = {}
    walk_steps = {}
    for i, (s, steps) in enumerate(plan["walk"]):
        _, parts, nxt, _ = ring.walk_parts(i)
        walk_next[s] = nxt
        walk_steps[s] = steps
        deps[s].add(nxt)
        deps[s].add(h)
        for st in steps:
            if st[0] == "Inline":
                deps[s].add(st[2])
                deps[h].add(st[2])   # BODY embeds sol_ext
            if st[0] == "Sub":
                for (u, usteps) in st[2]:
                    deps[u] = {s}     # inner sol references owner
                    walk_steps[u] = usteps
                    walk_next[u] = s
    for c in range(k):
        if c in ring.scc:
            continue
        for _, t in cls[c]["fwd"]:
            deps[c].add(t)

    # topo order (SCC cycle broken: header's only deps are inline exts)
    order = []
    done = set()
    def visit(c, stack):
        if c in done or c in stack:
            return
        stack.add(c)
        for t in sorted(deps[c]):
            if t != c:
                visit(t, stack)
        stack.discard(c)
        done.add(c)
        order.append(c)
    for c in range(k):
        visit(c, set())

    L = []
    A = L.append
    A("/-! ## Ring solutions (machine-generated; see emit_ring.py).")
    A(f"    SCC {sorted(ring.scc)} header={h} exit={cexp}; the walk plan and every proof")
    A("    recipe follow GkatRingSupportProofs and the GkatCertR1-R6 instances. -/")
    A("")

    # solution definitions in dependency order (BODY is emitted just before the
    # header's solution — it embeds inline-exit sols, which must come first)
    body = ring.body()
    proofs = {}   # class -> (target text, proof text)
    for c in order:
        if c == h:
            A(f"def BODY : Exp Act Tst := {body}")
            A(f"def sol{h} : Exp Act Tst := (.seq (.wh {gexp} BODY) (.test {cexp}))")
        elif c in walk_steps and c in ring.scc:
            steps = walk_steps[c]
            i = next((j for j, (s, _) in enumerate(plan["walk"]) if s == c), None)
            if i is not None:
                _, parts, nxt, _ = ring.walk_parts(i)
                if steps and steps[-1][0] == "Branch":
                    A(f"def sol{c} : Exp Act Tst := {seq(*(parts + [sol(h)]))}")
                else:
                    A(f"def sol{c} : Exp Act Tst := {seq(*(parts + [sol(nxt)]))}")
            else:
                # inner sub state
                parts = [raw_factor(st, ring) for st in steps]
                A(f"def sol{c} : Exp Act Tst := {seq(*(parts + [sol(walk_next[c])]))}")
        else:
            cl = cls[c]
            if cl["rec"]:
                recs = "[" + ", ".join(f"({EC.mask_bexp(1 << a)}, pA)" for a in cl["rec"]) + "]"
                fwds = "[" + ", ".join(
                    f"({EC.mask_bexp(1 << a)}, Exp.seq pA sol{t})" for a, t in cl["fwd"]) + "]"
                A(f"def L{c} : LevelG Act Tst := ({recs}, {fwds}, (Exp.test {EC.mask_bexp(cl['hlt'])}))")
                A(f"def sol{c} : Exp Act Tst := levelSol L{c}")
            else:
                A(f"def sol{c} : Exp Act Tst := {eqrhs(d, c, sol)}")
    A("")

    # header absorption
    himp_h = f"himp_intro_dneg {BT}" if ring.c == 2 else f"himp_self {NBT}"
    A(f"private theorem habs{h} : EquivBA (.seq (.test {cexp}) sol{h}) (.test {cexp}) :=")
    A(f"  test_header_absorb {cexp} {gexp} BODY ({himp_h})")
    A("")

    # absorption lemmas for inline ext cones: abs{c} : (sol{c} ; sol{h}) ≡ sol{c}
    ext_roots = set()
    for s, steps in walk_steps.items():
        for st in steps:
            if st[0] == "Inline":
                ext_roots.add(st[2])
    abs_needed = []
    seen_abs = set()
    def collect_cone(c):
        if c in seen_abs:
            return
        seen_abs.add(c)
        for _, t in cls[c]["fwd"]:
            collect_cone(t)
        abs_needed.append(c)
    for r in sorted(ext_roots):
        collect_cone(r)
    for c in abs_needed:
        cl = cls[c]
        entries = [(EC.mask_bexp(1 << a), t) for a, t in cl["fwd"]]
        hlt = cl["hlt"]
        leaf = (f"(EquivBA.base (Equiv.s2 sol{h}))" if hlt == 0
                else f"habs{h}")
        assert hlt == 0 or hlt == ring.c, f"ext leaf halt {hlt} not in {{0, c}}"
        def absorb_level(j):
            if j == len(entries):
                return leaf
            g, t = entries[j]
            rest_txt = eqrhs_suffix(d, c, sol, j + 1)
            then_inner = (f"(EquivBA.trans (EquivBA.base (Equiv.s1 pA sol{t} sol{h}))\n"
                          f"      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) abs{t}))")
            return (f"(EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 {g} "
                    f"(.seq pA sol{t}) {rest_txt} sol{h})))\n"
                    f"    (EquivBA.ite_c {then_inner} {absorb_level(j+1)}))")
        if cl["rec"]:
            # levelSol ext: split at the seq spine, absorb through the fold half
            W = f"(.wh (orGuards L{c}.1) (bodyFold L{c}.1))"
            F = f"(guardedFold L{c}.2.1 L{c}.2.2)"
            A(f"private theorem absF{c} : EquivBA (.seq {F} sol{h}) {F} :=")
            A(f"  {absorb_level(0)}")
            A(f"private theorem abs{c} : EquivBA (.seq sol{c} sol{h}) sol{c} :=")
            A(f"  EquivBA.trans (EquivBA.base (Equiv.s1 {W} {F} sol{h}))")
            A(f"    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) absF{c})")
        else:
            A(f"private theorem abs{c} : EquivBA (.seq sol{c} sol{h}) sol{c} :=")
            A(f"  {absorb_level(0)}")
        A("")

    # per-state SolvesBA proofs
    for c in order:
        target = eqrhs(d, c, sol)
        if c == h:
            sp = ring.spine()
            first = plan["walk"][0][0]
            A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
            A(f"  EquivBA.trans (EquivBA.base (salomaa_solution_exists {gexp} BODY (.test {cexp})))")
            A(f"    (EquivBA.ite_c {spine_chain(sp, f'sol{h}')} (EquivBA.base (Equiv.refl _)))")
            A("")
            proofs[c] = f"ringE{c}"
            continue
        if c in walk_steps and c in ring.scc:
            steps = walk_steps[c]
            kinds = [st[0] for st in steps]
            cl = cls[c]
            if kinds == ["Park"]:
                base = f"(park_solves {cexp} pA sol{h} habs{h})"
                if ring.c == 1:
                    base = (f"(EquivBA.trans {base}\n"
                            f"    (EquivBA.ite_guard (dneg_bval {BT})))")
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  {base}")
            elif kinds == ["Act"]:
                nxt = walk_next[c]
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  both_arms {NBT} {BT} (.seq pA sol{nxt}) (himp_dneg {BT})")
            elif kinds == ["SelfLoop", "Act"] or kinds == ["SelfLoop", "Park"]:
                a = steps[0][1]
                nxt = walk_next[c]
                ag = atom_guard(a)
                og = atom_guard(1 - a)
                himp = f"himp_dneg {BT}" if a == 0 else f"himp_self {NBT}"
                assert kinds[1] == "Act", "selfloop+park unsupported"
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  EquivBA.trans (EquivBA.base (salomaa_solution_exists {ag} pA (.seq pA sol{nxt})))")
                A(f"    (else_expand {ag} {og} ({himp}))")
            elif kinds == ["DeadGuard"]:
                a, t = steps[0][1], steps[0][2]
                ag = atom_guard(a)
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.u5 {ag} pA (.test BExp.zero) sol{t})))")
                A(f"    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.s2 sol{t})))")
            elif kinds == ["Inline"]:
                a, ext, t = steps[0][1], steps[0][2], steps[0][3]
                ag = atom_guard(a)
                og = atom_guard(1 - a)
                then_chain = (f"(EquivBA.trans (EquivBA.base (Equiv.s1 pA sol{ext} sol{t}))\n"
                              f"      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) abs{ext}))")
                himp = f"himp_dneg {BT}" if a == 0 else f"himp_self {NBT}"
                flip = "" if a == 0 else f"(EquivBA.base (Equiv.u2 {ag} (.seq pA sol{ext}) (.seq pA sol{t})))"
                steps_txt = [
                    f"(EquivBA.symm (EquivBA.base (Equiv.u5 {ag} (.seq pA sol{ext}) pA sol{t})))",
                    f"(EquivBA.ite_c {then_chain} (EquivBA.base (Equiv.refl _)))",
                ]
                if a == 1:
                    steps_txt.append(f"(EquivBA.base (Equiv.u2 {BT} (.seq pA sol{ext}) (.seq pA sol{t})))")
                    steps_txt.append(f"(else_expand {NBT} {BT} (himp_dneg {BT}))")
                else:
                    steps_txt.append(f"(else_expand {NBT} {BT} (himp_dneg {BT}))")
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  {chain(*steps_txt)}")
            elif kinds[0] == "Sub":
                st0 = steps[0]
                a = st0[1]
                ag = atom_guard(a)
                og = atom_guard(1 - a)
                nxt = walk_next[c]
                u = st0[2][0][0]
                inner_parts = []
                for (_, usteps) in st0[2]:
                    for ust in usteps:
                        inner_parts.append(raw_factor(ust, ring))
                ib = seq("pA", *inner_parts)
                then_chain = spine_chain(["pA"] + inner_parts, f"sol{c}")
                steps_txt = [
                    f"(EquivBA.base (salomaa_solution_exists {ag} {ib} (.seq pA sol{nxt})))",
                    f"(EquivBA.ite_c {then_chain} (EquivBA.base (Equiv.refl _)))",
                ]
                if a == 1:
                    steps_txt.append(
                        f"(EquivBA.base (Equiv.u2 {BT} (.seq pA sol{u}) (.seq pA sol{nxt})))")
                steps_txt.append(f"(else_expand {NBT} {BT} (himp_dneg {BT}))")
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  {chain(*steps_txt)}")
            elif kinds == ["Branch"]:
                st = steps[0]
                a, t = st[1], st[3]
                ag = atom_guard(a)
                i = next(j for j, (s, _) in enumerate(plan["walk"]) if s == c)
                rest = ring.suffix_raw(i + 1)
                F_then = "pA"
                F_else = seq("pA", rest)
                # else chain: (p ; REST) ; sol_h  ≡ p ; sol_t via spine chain on REST
                rest_parts = []
                for j in range(i + 1, len(plan["walk"])):
                    _, ps, _, ss = ring.walk_parts(j)
                    rest_parts.extend(ps)
                    if ss and ss[-1][0] == "Branch":
                        break
                else_chain = spine_chain(["pA"] + rest_parts, f"sol{h}")
                steps_txt = [
                    f"(EquivBA.symm (EquivBA.base (Equiv.u5 {ag} {F_then} {F_else} sol{h})))",
                    f"(EquivBA.ite_c (EquivBA.base (Equiv.refl _)) {else_chain})",
                ]
                if a == 1:
                    steps_txt.append(f"(EquivBA.base (Equiv.u2 {BT} (.seq pA sol{h}) (.seq pA sol{t})))")
                steps_txt.append(f"(else_expand {NBT} {BT} (himp_dneg {BT}))")
                A(f"theorem ringE{c} : EquivBA sol{c} {target} :=")
                A(f"  {chain(*steps_txt)}")
            else:
                raise Exception(f"unsupported pattern {kinds}")
            A("")
            proofs[c] = f"ringE{c}"
        else:
            cl = cls[c]
            proofs[c] = (f"level_satisfies L{c}" if cl["rec"]
                         else "EquivBA.base (Equiv.refl _)")

    sols_text = "\n".join(L)
    arms = {c: (proofs[c] if proofs[c].startswith("ringE") or True else proofs[c])
            for c in range(k)}

    # assemble the full file on the emit() skeleton
    full = EC.emit(d, name)
    a0 = full.index("abbrev SUM := sumGAut eAut fAut\n")
    a0 = full.index("\n\n", a0) + 2
    b0 = full.index("def QAut : GAut Nat Act Tst where")
    full = full[:a0] + sols_text + "\n\n" + full[b0:]
    full = full.replace("import GkatCertSupportProofs",
                        "import GkatCertSupportProofs\nimport GkatRingSupportProofs")
    full = full.replace(
        "open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport",
        "open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport\n"
        "open GkatGuardedAlgebra GkatRingSupport")
    qa = full.index("theorem qsol_solves")
    qb = full.index("theorem cert")
    def arm_sub(m):
        c = int(m.group(1))
        return f"  | {c}, _ => exact {arms[c]}"
    full = full[:qa] + re.sub(r"  \| (\d+), _ => exact .*", arm_sub, full[qa:qb]) + full[qb:]
    return full


def eqrhs_suffix(d, c, sol, j):
    """The eqRHS ite chain of class c from fwd-entry j on (for absorb recursion)."""
    cl = d["cls"][c]
    entries = [(EC.mask_bexp(1 << a), t) for a, t in cl["fwd"]]
    out = f"(.test {EC.mask_bexp(cl['hlt'])})"
    for g, t in reversed(entries[j:]):
        out = f"(.ite {g} (.seq pA sol{t}) {out})"
    return out


if __name__ == "__main__":
    text = open(sys.argv[1]).read()
    n = sys.argv[2]
    name = sys.argv[3]
    blocks = re.split(r"  CERT #A", text)
    block = next(b for b in blocks if b.startswith(n + "\n"))
    d = EC.parse(block)
    plan = parse_plan(text, n)
    print(emit_ring(d, plan, name, text, n))
