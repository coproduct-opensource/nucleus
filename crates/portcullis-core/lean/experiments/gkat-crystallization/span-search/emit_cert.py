#!/usr/bin/env python3
"""Emit a Lean instance proof from a PAD_EMIT certificate block.

Reads the certificate text (one CERT block) and writes a .lean file following the
GkatCertPilotProofs skeleton, with all state computations discharged through
GkatCertSupport.autStep_unit / bval_hlt_unit (constant-valuation + rfl)."""
import re, sys

def mask_bexp(m):
    return {0: "BExp.zero", 1: "(BExp.not bT)", 2: "bT", 3: "BExp.one"}[m]

def mask_bool_expr(m):
    # bval at valuation bit w: returns Lean Bool expr in (W () x)
    return {0: "false", 1: "(!(W () x))", 2: "(W () x)", 3: "true"}[m]

def guard_fires(m, bit):
    # does atom-guard mask m fire when W () x = bit?  atom1 <-> bit true
    return bool(m & (2 if bit else 1))

def parse(cert):
    d = {}
    d['e'] = re.search(r'LEAN e := (.*)', cert).group(1).strip()
    d['f'] = re.search(r'LEAN f := (.*)', cert).group(1).strip()
    d['k'] = int(re.search(r'quotient k=(\d+)', cert).group(1))
    # per-class data
    d['cls'] = {}
    for m in re.finditer(r's(\d+): rec=\[(.*?)\] fwd=\[(.*?)\] hlt=0b(\d+)', cert):
        c = int(m.group(1))
        rec = re.findall(r'atom(\d)', m.group(2))
        fwd = re.findall(r'\(atom(\d), act, s(\d+)\)', m.group(3))
        d['cls'][c] = {'rec': [int(a) for a in rec],
                       'fwd': [(int(a), int(t)) for a, t in fwd],
                       'hlt': int(m.group(4), 2)}
    d['order'] = [int(x) for x in re.search(r'solve order \(reverse-topological\): \[(.*?)\]',
                    cert).group(1).split(',')]
    # sum table
    d['sum'] = {}
    for m in re.finditer(r'^      (\d+): hlt=0b(\d+) steps=\["?(-|\d+)"?, "?(-|\d+)"?\]',
                         cert, re.M):
        i = int(m.group(1))
        st = [None if m.group(3) == '-' else int(m.group(3)),
              None if m.group(4) == '-' else int(m.group(4))]
        d['sum'][i] = {'hlt': int(m.group(2), 2), 'st': st}
    # qmap rows
    d['epaths'] = re.findall(r'inl \(some (.*?)\) -> s(\d+)', cert)
    d['fpaths'] = re.findall(r'inr \(some (.*?)\) -> s(\d+)', cert)
    d['e_none'] = int(re.search(r'qmap \(e-side\): none -> s(\d+)', cert).group(1))
    d['f_none'] = int(re.search(r'qmap \(f-side\): none -> s(\d+)', cert).group(1))
    return d

def state_terms(d):
    # sum index -> (lean term, class)
    ka = 1 + len(d['epaths'])
    out = {0: (f"(Sum.inl none)", d['e_none'])}
    for i, (p, c) in enumerate(d['epaths']):
        out[1 + i] = (f"(Sum.inl (some {p}))", int(c))
    out[ka] = (f"(Sum.inr none)", d['f_none'])
    for i, (p, c) in enumerate(d['fpaths']):
        out[ka + 1 + i] = (f"(Sum.inr (some {p}))", int(c))
    return out

def mem_chain(j):
    s = "(List.Mem.head _)"
    for _ in range(j):
        s = f"(List.Mem.tail _ {s})"
    return s

def emit(d, name):
    st = state_terms(d)
    k = d['k']
    L = []
    A = L.append
    A(f"import GkatCertSupportProofs")
    A(f"import GkatDeadExitElimProofs")
    A(f"import GkatSumQuotientProofs")
    A("")
    A(f"/-! # {name}: emitted instance certificate (machine-generated; see emit_cert.py) -/")
    A("")
    A(f"namespace {name}")
    A("")
    A("open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport")
    A("")
    A("abbrev Tst := Unit")
    A("abbrev Act := Unit")
    A("def bT : BExp Tst := .prim ()")
    A("def pA : Exp Act Tst := .act ()")
    A(f"def eP : Exp Act Tst := {d['e']}")
    A(f"def fP : Exp Act Tst := {d['f']}")
    A("")
    A("abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut")
    A("abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut")
    A("abbrev SUM := sumGAut eAut fAut")
    A("")
    # solutions, in solve order
    sols = {}
    for c in d['order']:
        cl = d['cls'][c]
        recs = "[" + ", ".join(f"({mask_bexp(1 << a)}, pA)" for a in cl['rec']) + "]"
        fwds = "[" + ", ".join(
            f"({mask_bexp(1 << a)}, Exp.seq pA sol{t})" for a, t in cl['fwd']) + "]"
        fb = f"(Exp.test {mask_bexp(cl['hlt'])})"
        if cl['rec']:
            A(f"def L{c} : LevelG Act Tst := ({recs}, {fwds}, {fb})")
            A(f"def sol{c} : Exp Act Tst := levelSol L{c}")
        else:
            A(f"def sol{c} : Exp Act Tst := guardedFold {fwds} {fb}")
        sols[c] = f"sol{c}"
    A("")
    # quotient automaton over Nat states
    A("def QAut : GAut Nat Act Tst where")
    A("  states := [" + ", ".join(str(c) for c in range(k)) + "]")
    A("  hlt")
    for c in range(k):
        A(f"    | {c} => {mask_bexp(d['cls'][c]['hlt'])}")
    A("    | _ => BExp.zero")
    A("  trans")
    for c in range(k):
        cl = d['cls'][c]
        entries = [f"({mask_bexp(1 << a)}, (), {c})" for a in cl['rec']]
        entries += [f"({mask_bexp(1 << a)}, (), {t})" for a, t in cl['fwd']]
        A(f"    | {c} => [" + ", ".join(entries) + "]")
    A("    | _ => []")
    A(f"  start := {d['e_none']}")
    A("")
    # qmap
    A("def qmap : Sum (Option (certifiedThompson Act Tst eP).State)")
    A("             (Option (certifiedThompson Act Tst fP).State) → Nat")
    A(f"  | .inl none => {d['e_none']}")
    for p, c in d['epaths']:
        A(f"  | .inl (some {p}) => {c}")
    A(f"  | .inr none => {d['f_none']}")
    for p, c in d['fpaths']:
        A(f"  | .inr (some {p}) => {c}")
    A("  | _ => 0")
    A("")
    A("variable {X : Type} (W : Tst → X → Bool) (x : X)")
    A("")
    # QAut step lemmas per class per bit
    for c in range(k):
        cl = d['cls'][c]
        for bit in (False, True):
            tgt = None
            for a in cl['rec']:
                if guard_fires(1 << a, bit):
                    tgt = c; break
            if tgt is None:
                for a, t in cl['fwd']:
                    if guard_fires(1 << a, bit):
                        tgt = t; break
            bs = "true" if bit else "false"
            res = "none" if tgt is None else f"some ((), {tgt})"
            A(f"theorem qstep_{c}_{bs} (h : W () x = {bs}) :")
            A(f"    autStep W QAut {c} x = {res} := by")
            A(f"  rw [autStep_unit, h]; rfl")
    A("")
    # bisim
    A("theorem qmap_bisim : GAutBisim W SUM QAut (fun s q => qmap s = q) := by")
    A("  rintro s1 s2 rfl")
    A("  match s1 with")
    # Empty-state arms: none needed generically? add wildcard-free total match; Empty paths appear only if expressions contain tests inside ites; emit nomatch arms by scanning paths is complex — rely on totality of listed arms + a catch: we cannot add wildcard in match on goal-relevant term... The listed constructors cover all inhabitants iff no Empty-typed slots; certs with tests DO have Empty components but they're uninhabited so no arms needed?? Lean requires exhaustive match: nomatch arms needed for Empty branches. Use `| .inl (some pth) => exact nomatch ...` impossible generically. Instead: end with omitted-case check at compile.
    for idx in sorted(st):
        term, c = st[idx]
        cl = d['cls'][c]
        A(f"  | {term.strip('()') if False else term[1:-1]} =>")
        A("      first | simp only [qmap] | skip")
        A("      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩")
        A(f"      · show bval W (SUM.hlt {term}) a = bval W (QAut.hlt {c}) a")
        A(f"        rw [bval_hlt_unit SUM, bval_hlt_unit QAut]")
        A(f"        cases hb : W () a <;> rfl")
        # fwd
        A(f"      · rw [autStep_unit] at hst")
        A(f"        cases hb : W () a with")
        for bit in (False, True):
            bs = "true" if bit else "false"
            tgt = d['sum'][idx]['st'][1 if bit else 0]
            A(f"        | {bs} =>")
            A(f"            rw [hb] at hst")
            if tgt is None:
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) SUM {term} ()")
                A(f"                = none := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            exact absurd hst (by simp)")
            else:
                tterm, tcls = st[tgt]
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) SUM {term} ()")
                A(f"                = some ((), {tterm}) := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            have hs := congrArg Prod.snd (Option.some.inj hst)")
                A(f"            subst hs")
                A(f"            exact ⟨{tcls}, qstep_{c}_{bs} W a hb, rfl⟩")
        # bwd
        A(f"      · rw [autStep_unit] at hst")
        A(f"        cases hb : W () a with")
        for bit in (False, True):
            bs = "true" if bit else "false"
            # QAut's step at (c, bit)
            qtgt = None
            for a in cl['rec']:
                if guard_fires(1 << a, bit):
                    qtgt = c; break
            if qtgt is None:
                for a, t in cl['fwd']:
                    if guard_fires(1 << a, bit):
                        qtgt = t; break
            stgt = d['sum'][idx]['st'][1 if bit else 0]
            A(f"        | {bs} =>")
            A(f"            rw [hb] at hst")
            if qtgt is None:
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) QAut {c} ()")
                A(f"                = none := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            exact absurd hst (by simp)")
            else:
                assert stgt is not None, f"cert mismatch state {idx} bit {bit}"
                tterm, tcls = st[stgt]
                assert tcls == qtgt, f"class mismatch {idx} {bit}"
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) QAut {c} ()")
                A(f"                = some ((), {qtgt}) := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            have hs := congrArg Prod.snd (Option.some.inj hst)")
                A(f"            subst hs")
                A(f"            refine ⟨{tterm}, ?_, rfl⟩")
                A(f"            rw [autStep_unit, hb]")
                A(f"            rfl")
    A("")
    # quotient structure
    A("def qquot : UniformBehavioralGAutQuotient SUM QAut where")
    A("  mapState := qmap")
    A("  maps_states := by")
    A("    intro s _")
    A("    match s with")
    for idx in sorted(st):
        term, c = st[idx]
        A(f"    | {term[1:-1]} => exact {mem_chain(c)}")
    A("  onto_states := by")
    A("    intro q hq")
    # witness per class: first sum state with that class
    A("    match q, hq with")
    ka = 1 + len(d['epaths'])
    for c in range(k):
        wit = next(i for i in sorted(st) if st[i][1] == c)
        term, _ = st[wit]
        if wit == 0:
            mem = "(List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _))))"
        elif wit < ka:
            inner = term[len("(Sum.inl (some "):-2]
            mem = ("(List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ "
                   f"(List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP {inner}))))))")
        elif wit == ka:
            mem = "(List.mem_append.mpr (Or.inr (List.mem_map_of_mem (List.Mem.head _))))"
        else:
            inner = term[len("(Sum.inr (some "):-2]
            mem = ("(List.mem_append.mpr (Or.inr (List.mem_map_of_mem (List.Mem.tail _ "
                   f"(List.mem_map_of_mem (GkatTotalization.thompson_states_complete fP {inner}))))))")
        A(f"    | {c}, _ => exact ⟨{term}, {mem}, rfl⟩")
    A("  bisim_graph := fun _ W => qmap_bisim W")
    A("")
    A("def qsol : Nat → Exp Act Tst")
    for c in range(k):
        A(f"  | {c} => sol{c}")
    A("  | _ => Exp.test BExp.zero")
    A("")
    A("theorem qsol_solves : SolvesBA QAut qsol := by")
    A("  intro s hs")
    A("  match s, hs with")
    for c in range(k):
        cl = d['cls'][c]
        if cl['rec']:
            A(f"  | {c}, _ => exact level_satisfies L{c}")
        else:
            A(f"  | {c}, _ => exact EquivBA.base (Equiv.refl _)")
    A("")
    A("theorem cert : EquivBA eP fP :=")
    A("  certifiedThompson_uniform_solved_quotient qquot qsol qsol_solves rfl")
    A("")
    A("#print axioms cert")
    A("")
    A(f"end {name}")
    return "\n".join(L) + "\n"

def parse_t(cert):
    d = {}
    d['e'] = re.search(r'LEAN e := (.*)', cert).group(1).strip()
    d['f'] = re.search(r'LEAN f := (.*)', cert).group(1).strip()
    d['g'] = re.search(r'LEAN g := (.*)', cert).group(1).strip()
    d['g_tbl'] = {}; d['sum'] = {}; d['epaths'] = []; d['fpaths'] = []
    sec = None
    for ln in cert.split('\n'):
        if 'LEAN g table' in ln: sec = 'g'; continue
        if 'LEAN sum table' in ln: sec = 's'; continue
        if 'LEAN tmap (e-side)' in ln:
            sec = 'e'; d['e_none'] = re.search(r'none -> (\(.*\))', ln).group(1); continue
        if 'LEAN tmap (f-side)' in ln:
            sec = 'f'; d['f_none'] = re.search(r'none -> (\(.*\))', ln).group(1); continue
        if sec == 'g':
            m = re.match(r'\s+(\d+): hlt=0b(\d+) steps=\[(.*)\] path=(\(.*\))\s*$', ln)
            if m:
                steps = re.findall(r'"(.*?)"', m.group(3))
                d['g_tbl'][int(m.group(1))] = {'hlt': int(m.group(2), 2),
                    'st': [None if s == '-' else s for s in steps], 'path': m.group(4)}
        elif sec == 's':
            m = re.match(r'\s+(\d+): hlt=0b(\d+) steps=\["?(-|\d+)"?, "?(-|\d+)"?\]', ln)
            if m:
                d['sum'][int(m.group(1))] = {'hlt': int(m.group(2), 2),
                    'st': [None if m.group(3) == '-' else int(m.group(3)),
                           None if m.group(4) == '-' else int(m.group(4))]}
        elif sec == 'e':
            m = re.match(r'\s+inl \(some (.*)\) -> (\(.*\))\s*$', ln)
            if m: d['epaths'].append((m.group(1), m.group(2)))
            else: sec = None
        elif sec == 'f':
            m = re.match(r'\s+inr \(some (.*)\) -> (\(.*\))\s*$', ln)
            if m: d['fpaths'].append((m.group(1), m.group(2)))
            else: sec = None
    return d

def state_terms_t(d):
    # sum index -> (lean term, g-path of its class)
    ka = 1 + len(d['epaths'])
    out = {0: ("(Sum.inl none)", d['e_none'])}
    for i, (p, gp) in enumerate(d['epaths']):
        out[1 + i] = (f"(Sum.inl (some {p}))", gp)
    out[ka] = ("(Sum.inr none)", d['f_none'])
    for i, (p, gp) in enumerate(d['fpaths']):
        out[ka + 1 + i] = (f"(Sum.inr (some {p}))", gp)
    return out

def emit_t(d, name):
    st = state_terms_t(d)
    gidx = {v['path']: i for i, v in d['g_tbl'].items()}
    assert d['e_none'] == d['f_none'], "merged starts map to different g states"
    # consistency: sum table vs g table through the map
    for i in sorted(st):
        term, gp = st[i]
        g = d['g_tbl'][gidx[gp]]; s = d['sum'][i]
        assert s['hlt'] == g['hlt'], f"hlt mismatch sum{i}"
        for b in (0, 1):
            stgt, gtgt = s['st'][b], g['st'][b]
            if stgt is None:
                assert gtgt is None, f"step mismatch sum{i} bit{b}"
            else:
                assert gtgt == st[stgt][1], f"target mismatch sum{i} bit{b}"
    L = []
    A = L.append
    A("import GkatCertSupportProofs")
    A("import GkatDeadExitElimProofs")
    A("import GkatSumQuotientProofs")
    A("")
    A(f"/-! # {name}: emitted Thompson-witness certificate (machine-generated; see emit_cert.py -t) -/")
    A("")
    A(f"namespace {name}")
    A("")
    A("open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim GkatCertSupport")
    A("")
    A("abbrev Tst := Unit")
    A("abbrev Act := Unit")
    A("def bT : BExp Tst := .prim ()")
    A("def pA : Exp Act Tst := .act ()")
    A(f"def eP : Exp Act Tst := {d['e']}")
    A(f"def fP : Exp Act Tst := {d['f']}")
    A(f"def gP : Exp Act Tst := {d['g']}")
    A("")
    A("abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut")
    A("abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut")
    A("abbrev SUM := sumGAut eAut fAut")
    A("abbrev gC := certifiedThompson Act Tst gP")
    A(f"def START : gC.State := {d['e_none']}")
    A("def TAut : GAut gC.State Act Tst := coreGAut gC START")
    A("")
    A("def tmap : Sum (Option (certifiedThompson Act Tst eP).State)")
    A("             (Option (certifiedThompson Act Tst fP).State) → gC.State")
    A(f"  | .inl none => {d['e_none']}")
    for p, gp in d['epaths']:
        A(f"  | .inl (some {p}) => {gp}")
    A(f"  | .inr none => {d['f_none']}")
    for p, gp in d['fpaths']:
        A(f"  | .inr (some {p}) => {gp}")
    A("  | _ => START")
    A("")
    A("variable {X : Type} (W : Tst → X → Bool) (x : X)")
    A("")
    # TAut step lemmas per g state per bit
    for gi in sorted(d['g_tbl']):
        g = d['g_tbl'][gi]
        for bit in (False, True):
            tgt = g['st'][1 if bit else 0]
            bs = "true" if bit else "false"
            res = "none" if tgt is None else f"some ((), ({tgt} : gC.State))"
            A(f"theorem tstep_{gi}_{bs} (h : W () x = {bs}) :")
            A(f"    autStep W TAut ({g['path']} : gC.State) x = {res} := by")
            A(f"  rw [autStep_unit, h]; rfl")
    A("")
    A("theorem tmap_bisim : GAutBisim W SUM TAut (fun s q => tmap s = q) := by")
    A("  rintro s1 s2 rfl")
    A("  match s1 with")
    for idx in sorted(st):
        term, gp = st[idx]
        gi = gidx[gp]
        g = d['g_tbl'][gi]
        A(f"  | {term[1:-1]} =>")
        A("      first | simp only [tmap] | skip")
        A("      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩")
        A(f"      · show bval W (SUM.hlt {term}) a = bval W (TAut.hlt {gp}) a")
        A(f"        rw [bval_hlt_unit SUM, bval_hlt_unit TAut]")
        A(f"        cases hb : W () a <;> rfl")
        # fwd
        A(f"      · rw [autStep_unit] at hst")
        A(f"        cases hb : W () a with")
        for bit in (False, True):
            bs = "true" if bit else "false"
            stgt = d['sum'][idx]['st'][1 if bit else 0]
            A(f"        | {bs} =>")
            A(f"            rw [hb] at hst")
            if stgt is None:
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) SUM {term} ()")
                A(f"                = none := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            exact absurd hst (by simp)")
            else:
                tterm, tgp = st[stgt]
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) SUM {term} ()")
                A(f"                = some ((), {tterm}) := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            have hs := congrArg Prod.snd (Option.some.inj hst)")
                A(f"            subst hs")
                A(f"            exact ⟨{tgp}, tstep_{gi}_{bs} W a hb, rfl⟩")
        # bwd
        A(f"      · rw [autStep_unit] at hst")
        A(f"        cases hb : W () a with")
        for bit in (False, True):
            bs = "true" if bit else "false"
            gtgt = g['st'][1 if bit else 0]
            stgt = d['sum'][idx]['st'][1 if bit else 0]
            A(f"        | {bs} =>")
            A(f"            rw [hb] at hst")
            if gtgt is None:
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) TAut ({gp} : gC.State) ()")
                A(f"                = none := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            exact absurd hst (by simp)")
            else:
                assert stgt is not None, f"cert mismatch state {idx} bit {bit}"
                tterm, tgp = st[stgt]
                assert tgp == gtgt, f"class mismatch {idx} {bit}"
                A(f"            have hred : autStep (fun _ (_ : Unit) => {bs}) TAut ({gp} : gC.State) ()")
                A(f"                = some ((), ({gtgt} : gC.State)) := by rfl")
                A(f"            rw [hred] at hst")
                A(f"            have hs := congrArg Prod.snd (Option.some.inj hst)")
                A(f"            subst hs")
                A(f"            refine ⟨{tterm}, ?_, rfl⟩")
                A(f"            rw [autStep_unit, hb]")
                A(f"            rfl")
    A("")
    A("def tquot : UniformBehavioralGAutQuotient SUM TAut where")
    A("  mapState := tmap")
    A("  maps_states := fun s _ => GkatTotalization.thompson_states_complete gP (tmap s)")
    A("  onto_states := by")
    A("    intro q hq")
    A("    match q, hq with")
    ka = 1 + len(d['epaths'])
    for gi in sorted(d['g_tbl']):
        gp = d['g_tbl'][gi]['path']
        wit = next(j for j in sorted(st) if st[j][1] == gp)
        term, _ = st[wit]
        if wit == 0:
            mem = "(List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _))))"
        elif wit < ka:
            inner = term[len("(Sum.inl (some "):-2]
            mem = ("(List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ "
                   f"(List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP {inner}))))))")
        elif wit == ka:
            mem = "(List.mem_append.mpr (Or.inr (List.mem_map_of_mem (List.Mem.head _))))"
        else:
            inner = term[len("(Sum.inr (some "):-2]
            mem = ("(List.mem_append.mpr (Or.inr (List.mem_map_of_mem (List.Mem.tail _ "
                   f"(List.mem_map_of_mem (GkatTotalization.thompson_states_complete fP {inner}))))))")
        A(f"    | {gp[1:-1]}, _ => exact ⟨{term}, {mem}, rfl⟩")
    A("  bisim_graph := fun _ W => tmap_bisim W")
    A("")
    A("theorem cert : EquivBA eP fP :=")
    A("  certifiedThompson_uniform_solved_quotient tquot gC.standard (coreGAut_solves gC START) rfl")
    A("")
    A("#print axioms cert")
    A("")
    A(f"end {name}")
    return "\n".join(L) + "\n"

if __name__ == "__main__":
    text = open(sys.argv[1]).read()
    if sys.argv[2] == '-t':
        n = sys.argv[3]
        blocks = re.split(r'  CERT-T #', text)
        block = next(b for b in blocks if b.startswith(n))
        print(emit_t(parse_t(block), f"GkatCertT{n}"))
    else:
        n = sys.argv[2]
        blocks = re.split(r'  CERT #', text)
        block = next(b for b in blocks if b.startswith(n))
        print(emit(parse(block), f"GkatCertGen{n}"))
