//! B′: does a common syntactic **refinement** (a span) always exist?
//!
//! Closes the Thompson combinators to a fixpoint over *fully reachable* automata with at
//! most `MAXK` core states, then, for every crux pair, asks whether some `h` in that
//! closure covers both sides.
//!
//! Two facts make the bound sound rather than a sampling artefact:
//!   * composition never decreases the core-state count (`seq`/`ite` add, `wh` preserves),
//!     so an automaton with `k` states is only ever built from automata with `<= k`;
//!   * an unreachable state of a component stays unreachable in every composite, so a
//!     fully reachable composite is built only from fully reachable components.
//! Together: the closure below is *complete* for fully reachable targets with `<= MAXK`
//! core states. A "no span" verdict is a decision over that class, not a failed search.
//!
//! Each combinator clause is the pointwise-`firstMatch` reading of the Lean definitions in
//! GkatThompsonUniquenessProofs.lean, cross-validated against the literal transcription in
//! ../igsem.py (`check_algebra`).
//!
//! Single action alphabet: the cospan refutation lives in the one-action fragment, and a
//! step is then determined by its target.

use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};

const MAXK: usize = 16;

// ---------------------------------------------------------------- hashing
//
// The closure reaches 56M automata at K=6, so hashing is the dominant cost of the whole
// program: every produced candidate is looked up, and most lookups hit. SipHash (the std
// default) is built for HashDoS resistance we do not need here. FxHash — the rustc hasher —
// is several times faster on short keys, and `Aut`'s own `Hash` below writes only the *used*
// prefix (`k` states), turning ~20 hasher calls per automaton into ~4 + k.

#[derive(Default, Clone, Copy)]
struct FxHasher {
    hash: u64,
}

impl std::hash::Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        let mut h = self.hash;
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            let v = u64::from_le_bytes(c.try_into().unwrap());
            h = (h.rotate_left(5) ^ v).wrapping_mul(SEED);
        }
        let mut tail = 0u64;
        for &b in chunks.remainder() {
            tail = (tail << 8) | b as u64;
        }
        self.hash = (h.rotate_left(5) ^ tail).wrapping_mul(SEED);
    }
    #[inline]
    fn write_u8(&mut self, b: u8) {
        const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        self.hash = (self.hash.rotate_left(5) ^ b as u64).wrapping_mul(SEED);
    }
}

#[derive(Default, Clone, Copy)]
struct FxBuild;

impl std::hash::BuildHasher for FxBuild {
    type Hasher = FxHasher;
    #[inline]
    fn build_hasher(&self) -> FxHasher {
        FxHasher { hash: 0 }
    }
}

type FxMap<K, V> = HashMap<K, V, FxBuild>;
type FxSet<K> = HashSet<K, FxBuild>;

/// A Thompson automaton, semantically. Atom masks are bitmaps over `NA` atoms; a step is
/// `0` for "no step" and `1 + target` otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Aut<const NA: usize> {
    k: u8,
    ih: u8,
    it: [u8; NA],
    hl: [u8; MAXK],
    st: [[u8; NA]; MAXK],
}

/// Hash only the live prefix. Unused slots are zeroed by construction, so this agrees with
/// the derived `PartialEq` while touching a fraction of the bytes.
impl<const NA: usize> std::hash::Hash for Aut<NA> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        h.write_u8(self.k);
        h.write_u8(self.ih);
        h.write(&self.it);
        let k = self.k as usize;
        h.write(&self.hl[..k]);
        for s in 0..k {
            h.write(&self.st[s]);
        }
    }
}

impl<const NA: usize> Aut<NA> {
    fn blank() -> Self {
        Aut { k: 0, ih: 0, it: [0; NA], hl: [0; MAXK], st: [[0; NA]; MAXK] }
    }
}

#[inline]
fn bit(mask: u8, i: usize) -> bool {
    mask >> i & 1 == 1
}
#[inline]
fn set_bit(mask: &mut u8, i: usize, v: bool) {
    if v {
        *mask |= 1 << i;
    }
}
#[inline]
fn shift(step: u8, off: u8) -> u8 {
    if step == 0 { 0 } else { step + off }
}

// ---------------------------------------------------------------- combinators

fn a_test<const NA: usize>(g: u8) -> Aut<NA> {
    let mut a = Aut::blank();
    a.ih = g;
    a
}

fn a_act<const NA: usize>() -> Aut<NA> {
    let mut a = Aut::blank();
    a.k = 1;
    a.ih = 0;
    a.it = [1; NA];
    a.hl[0] = (1u8 << NA) - 1;
    a
}

fn a_ite<const NA: usize>(g: u8, l: &Aut<NA>, r: &Aut<NA>) -> Option<Aut<NA>> {
    let k = l.k as usize + r.k as usize;
    if k > MAXK {
        return None;
    }
    let mut a = Aut::blank();
    a.k = k as u8;
    for i in 0..NA {
        let (src_h, src_t) = if bit(g, i) { (l.ih, l.it[i]) } else { (r.ih, shift(r.it[i], l.k)) };
        set_bit(&mut a.ih, i, bit(src_h, i));
        a.it[i] = src_t;
    }
    for s in 0..l.k as usize {
        a.hl[s] = l.hl[s];
        a.st[s] = l.st[s];
    }
    for s in 0..r.k as usize {
        let d = l.k as usize + s;
        a.hl[d] = r.hl[s];
        for i in 0..NA {
            a.st[d][i] = shift(r.st[s][i], l.k);
        }
    }
    Some(a)
}

fn a_seq<const NA: usize>(l: &Aut<NA>, r: &Aut<NA>) -> Option<Aut<NA>> {
    let k = l.k as usize + r.k as usize;
    if k > MAXK {
        return None;
    }
    let mut a = Aut::blank();
    a.k = k as u8;
    for i in 0..NA {
        set_bit(&mut a.ih, i, bit(l.ih, i) && bit(r.ih, i));
        a.it[i] = if l.it[i] != 0 {
            l.it[i]
        } else if bit(l.ih, i) {
            shift(r.it[i], l.k)
        } else {
            0
        };
    }
    for s in 0..l.k as usize {
        for i in 0..NA {
            set_bit(&mut a.hl[s], i, bit(l.hl[s], i) && bit(r.ih, i));
            a.st[s][i] = if l.st[s][i] != 0 {
                l.st[s][i]
            } else if bit(l.hl[s], i) {
                shift(r.it[i], l.k)
            } else {
                0
            };
        }
    }
    for s in 0..r.k as usize {
        let d = l.k as usize + s;
        a.hl[d] = r.hl[s];
        for i in 0..NA {
            a.st[d][i] = shift(r.st[s][i], l.k);
        }
    }
    Some(a)
}

fn a_wh<const NA: usize>(g: u8, b: &Aut<NA>) -> Aut<NA> {
    let mut a = Aut::blank();
    a.k = b.k;
    for i in 0..NA {
        set_bit(&mut a.ih, i, !bit(g, i));
        a.it[i] = if bit(g, i) { b.it[i] } else { 0 };
    }
    for s in 0..b.k as usize {
        for i in 0..NA {
            set_bit(&mut a.hl[s], i, bit(b.hl[s], i) && !bit(g, i));
            a.st[s][i] = if b.st[s][i] != 0 {
                b.st[s][i]
            } else if bit(b.hl[s], i) && bit(g, i) {
                b.it[i]
            } else {
                0
            };
        }
    }
    a
}

/// How an automaton in the closure was built — enough to re-run the constructors, which is
/// what an unrolling needs.
#[derive(Clone, Copy, Debug)]
enum Prov {
    Leaf,
    Seq(u32, u32),
    Ite(u8, u32, u32),
    Wh(u8, u32),
}

// ---------------------------------------------------------------- canonical form

/// BFS-renumber from the pseudostate. `None` when some state is unreachable — those are
/// pruned, which is sound because unreachability is inherited by every composite.
fn canon<const NA: usize>(a: &Aut<NA>) -> Option<Aut<NA>> {
    let k = a.k as usize;
    let mut order = [u8::MAX; MAXK];
    // BFS frontier as a fixed ring: every state is enqueued at most once, so MAXK suffices
    // and the per-call heap allocation a VecDeque would make disappears.
    let mut queue = [0usize; MAXK];
    let (mut qh, mut qt) = (0usize, 0usize);
    let mut n = 0u8;
    for i in 0..NA {
        if a.it[i] != 0 {
            let t = (a.it[i] - 1) as usize;
            if order[t] == u8::MAX {
                order[t] = n;
                n += 1;
                queue[qt] = t;
                qt += 1;
            }
        }
    }
    while qh < qt {
        let s = queue[qh];
        qh += 1;
        for i in 0..NA {
            if a.st[s][i] != 0 {
                let t = (a.st[s][i] - 1) as usize;
                if order[t] == u8::MAX {
                    order[t] = n;
                    n += 1;
                    queue[qt] = t;
                    qt += 1;
                }
            }
        }
    }
    if (n as usize) != k {
        return None;
    }
    let mut inv = [0usize; MAXK];
    for s in 0..k {
        inv[order[s] as usize] = s;
    }
    let mut c = Aut::blank();
    c.k = a.k;
    c.ih = a.ih;
    let m = |x: u8| -> u8 { if x == 0 { 0 } else { order[(x - 1) as usize] + 1 } };
    for i in 0..NA {
        c.it[i] = m(a.it[i]);
    }
    for d in 0..k {
        let s = inv[d];
        c.hl[d] = a.hl[s];
        for i in 0..NA {
            c.st[d][i] = m(a.st[s][i]);
        }
    }
    Some(c)
}

// ---------------------------------------------------------------- behaviour

/// Minimised reachable behaviour of the pseudostate — the key under which two automata can
/// possibly be language-equivalent.
///
/// Allocation-free apart from the returned key. At most `MAXK` states means every working
/// structure is a fixed-size array, and the partition-refinement fixpoint runs in place;
/// the previous version built a `HashMap` and two `HashSet`s *per refinement round*, which
/// dominated the closure build since this is called once for all 56M members.
fn behaviour<const NA: usize>(a: &Aut<NA>) -> Vec<u8> {
    let k = a.k as usize;

    // initial partition: by halt mask, densely renumbered so class ids index arrays directly
    let mut cls = [0u8; MAXK];
    {
        let mut seen = [255u8; 256];
        let mut n = 0u8;
        for s in 0..k {
            let h = a.hl[s] as usize;
            if seen[h] == 255 {
                seen[h] = n;
                n += 1;
            }
            cls[s] = seen[h];
        }
    }

    // refine until the class count stops growing
    let mut nclasses = {
        let mut m = [false; MAXK];
        let mut c = 0usize;
        for s in 0..k {
            if !m[cls[s] as usize] {
                m[cls[s] as usize] = true;
                c += 1;
            }
        }
        c
    };
    loop {
        let mut sigs: [(u8, [u8; NA]); MAXK] = [(0, [0u8; NA]); MAXK];
        let mut next = [0u8; MAXK];
        let mut n = 0usize;
        for s in 0..k {
            let mut row = [255u8; NA];
            for i in 0..NA {
                if a.st[s][i] != 0 {
                    row[i] = cls[(a.st[s][i] - 1) as usize];
                }
            }
            let sig = (cls[s], row);
            let mut hit = None;
            for j in 0..n {
                if sigs[j] == sig {
                    hit = Some(j as u8);
                    break;
                }
            }
            next[s] = match hit {
                Some(j) => j,
                None => {
                    sigs[n] = sig;
                    n += 1;
                    (n - 1) as u8
                }
            };
        }
        cls = next;
        if n == nclasses {
            break;
        }
        nclasses = n;
    }

    // canonical BFS over classes, taking the first state reached as each class's witness
    let mut order = [255u8; MAXK];
    let mut norder = 0u8;
    let mut queue = [0usize; MAXK];
    let (mut qh, mut qt) = (0usize, 0usize);
    let mut out: Vec<u8> = Vec::with_capacity(1 + NA + nclasses * (1 + NA));
    out.push(a.ih);
    for i in 0..NA {
        if a.it[i] != 0 {
            let c = cls[(a.it[i] - 1) as usize] as usize;
            if order[c] == 255 {
                order[c] = norder;
                norder += 1;
                queue[qt] = (a.it[i] - 1) as usize;
                qt += 1;
            }
        }
    }
    for i in 0..NA {
        out.push(if a.it[i] == 0 { 255 } else { order[cls[(a.it[i] - 1) as usize] as usize] });
    }
    while qh < qt {
        let s = queue[qh];
        qh += 1;
        out.push(a.hl[s]);
        for i in 0..NA {
            if a.st[s][i] != 0 {
                let c = cls[(a.st[s][i] - 1) as usize] as usize;
                if order[c] == 255 {
                    order[c] = norder;
                    norder += 1;
                    queue[qt] = (a.st[s][i] - 1) as usize;
                    qt += 1;
                }
            }
        }
        for i in 0..NA {
            out.push(if a.st[s][i] == 0 {
                255
            } else {
                order[cls[(a.st[s][i] - 1) as usize] as usize]
            });
        }
    }
    out
}

// ---------------------------------------------------------------- covers

/// A functional bisimulation `h -> e`, pseudostate to pseudostate, onto every state of `e`.
fn covers<const NA: usize>(h: &Aut<NA>, e: &Aut<NA>) -> bool {
    if h.ih != e.ih {
        return false;
    }
    let mut m = [u8::MAX; MAXK];
    let mut queue = [0usize; MAXK];
    let (mut qh, mut qt) = (0usize, 0usize);
    let mut mapped = 0usize;
    for i in 0..NA {
        if (h.it[i] == 0) != (e.it[i] == 0) {
            return false;
        }
        if h.it[i] == 0 {
            continue;
        }
        let (s, t) = ((h.it[i] - 1) as usize, e.it[i] - 1);
        if m[s] == u8::MAX {
            m[s] = t;
            mapped += 1;
            queue[qt] = s;
            qt += 1;
        } else if m[s] != t {
            return false;
        }
    }
    while qh < qt {
        let s = queue[qh];
        qh += 1;
        let t = m[s] as usize;
        if h.hl[s] != e.hl[t] {
            return false;
        }
        for i in 0..NA {
            if (h.st[s][i] == 0) != (e.st[t][i] == 0) {
                return false;
            }
            if h.st[s][i] == 0 {
                continue;
            }
            let (s2, t2) = ((h.st[s][i] - 1) as usize, e.st[t][i] - 1);
            if m[s2] == u8::MAX {
                m[s2] = t2;
                mapped += 1;
                queue[qt] = s2;
                qt += 1;
            } else if m[s2] != t2 {
                return false;
            }
        }
    }
    if mapped != h.k as usize {
        return false;
    }
    let mut hit = [false; MAXK];
    for s in 0..h.k as usize {
        hit[m[s] as usize] = true;
    }
    (0..e.k as usize).all(|t| hit[t])
}

// ------------------------------------------------- the forced joint quotient

/// Union-find over `e`'s and `f`'s states under the least step-closed equivalence that
/// identifies the two pseudostates. Returns `(injective on e, injective on f)`.
fn forced_injectivity<const NA: usize>(e: &Aut<NA>, f: &Aut<NA>) -> (bool, bool) {
    let ke = e.k as usize;
    let n = ke + f.k as usize;
    let mut par: Vec<usize> = (0..n).collect();
    fn find(par: &mut Vec<usize>, mut x: usize) -> usize {
        while par[x] != x {
            par[x] = par[par[x]];
            x = par[x];
        }
        x
    }
    let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
    let mut uni = |par: &mut Vec<usize>, q: &mut VecDeque<(usize, usize)>, a: usize, b: usize| {
        let (ra, rb) = (find(par, a), find(par, b));
        if ra != rb {
            par[ra] = rb;
            q.push_back((a, b));
        }
    };
    for i in 0..NA {
        if e.it[i] != 0 && f.it[i] != 0 {
            uni(&mut par, &mut queue, (e.it[i] - 1) as usize, ke + (f.it[i] - 1) as usize);
        }
    }
    while let Some((x, y)) = queue.pop_front() {
        for i in 0..NA {
            let sx = if x < ke { e.st[x][i] } else { f.st[x - ke][i] };
            let sy = if y < ke { e.st[y][i] } else { f.st[y - ke][i] };
            if sx == 0 || sy == 0 {
                continue;
            }
            let nx = if x < ke { (sx - 1) as usize } else { ke + (sx - 1) as usize };
            let ny = if y < ke { (sy - 1) as usize } else { ke + (sy - 1) as usize };
            uni(&mut par, &mut queue, nx, ny);
        }
    }
    let mut se: HashSet<usize> = HashSet::new();
    for s in 0..ke {
        se.insert(find(&mut par, s));
    }
    let mut sf: HashSet<usize> = HashSet::new();
    for s in 0..f.k as usize {
        sf.insert(find(&mut par, ke + s));
    }
    (se.len() == ke, sf.len() == f.k as usize)
}

/// A program whose automaton never halts anywhere accepts no guarded string at all: its
/// language is empty, so it is provably `0` by `nullLanguage_complete` and needs no span.
fn live<const NA: usize>(a: &Aut<NA>) -> bool {
    a.ih != 0 || (0..a.k as usize).any(|s| a.hl[s] != 0)
}

/// Every state — pseudostate included — can still reach a halt. A state that cannot is a
/// dead region: its language is empty, so `nullLanguage_complete` proves it `0` outright
/// and it is exactly what Phase A pruning removes.
fn all_productive<const NA: usize>(a: &Aut<NA>) -> bool {
    let k = a.k as usize;
    let mut prod = [false; MAXK];
    for s in 0..k {
        prod[s] = a.hl[s] != 0;
    }
    loop {
        let mut changed = false;
        for s in 0..k {
            if prod[s] {
                continue;
            }
            for i in 0..NA {
                if a.st[s][i] != 0 && prod[(a.st[s][i] - 1) as usize] {
                    prod[s] = true;
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }
    if !(0..k).all(|s| prod[s]) {
        return false;
    }
    a.ih != 0 || (0..NA).any(|i| a.it[i] != 0 && prod[(a.it[i] - 1) as usize])
}

/// The forced joint quotient: the least step-closed equivalence identifying the two
/// pseudostates. Determinism pins it, so any cospan target's reachable part must be this.
/// `None` when it needs more than `MAXK` core states.
fn forced_quotient<const NA: usize>(e: &Aut<NA>, f: &Aut<NA>) -> Option<Aut<NA>> {
    let ke = e.k as usize;
    let n = ke + f.k as usize;
    let mut par: Vec<usize> = (0..n).collect();
    fn find(par: &mut Vec<usize>, mut x: usize) -> usize {
        while par[x] != x {
            par[x] = par[par[x]];
            x = par[x];
        }
        x
    }
    let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
    let mut uni = |par: &mut Vec<usize>, q: &mut VecDeque<(usize, usize)>, a: usize, b: usize| {
        let (ra, rb) = (find(par, a), find(par, b));
        if ra != rb {
            par[ra] = rb;
            q.push_back((a, b));
        }
    };
    for i in 0..NA {
        if e.it[i] != 0 && f.it[i] != 0 {
            uni(&mut par, &mut queue, (e.it[i] - 1) as usize, ke + (f.it[i] - 1) as usize);
        }
    }
    while let Some((x, y)) = queue.pop_front() {
        for i in 0..NA {
            let sx = if x < ke { e.st[x][i] } else { f.st[x - ke][i] };
            let sy = if y < ke { e.st[y][i] } else { f.st[y - ke][i] };
            if sx == 0 || sy == 0 {
                continue;
            }
            let nx = if x < ke { (sx - 1) as usize } else { ke + (sx - 1) as usize };
            let ny = if y < ke { (sy - 1) as usize } else { ke + (sy - 1) as usize };
            uni(&mut par, &mut queue, nx, ny);
        }
    }
    // number the classes, e-side first
    let mut idx: HashMap<usize, u8> = HashMap::new();
    let mut rep: Vec<usize> = Vec::new();
    for s in 0..n {
        let r = find(&mut par, s);
        if !idx.contains_key(&r) {
            if rep.len() >= MAXK {
                return None;
            }
            idx.insert(r, rep.len() as u8);
            rep.push(s);
        }
    }
    let mut a = Aut::<NA>::blank();
    a.k = rep.len() as u8;
    a.ih = e.ih;
    let cls = |par: &mut Vec<usize>, idx: &HashMap<usize, u8>, s: usize| -> u8 {
        let r = find(par, s);
        idx[&r] + 1
    };
    for i in 0..NA {
        a.it[i] = if e.it[i] == 0 { 0 } else { cls(&mut par, &idx, (e.it[i] - 1) as usize) };
    }
    for c in 0..rep.len() {
        let s = rep[c];
        let (hl, st) = if s < ke { (e.hl[s], e.st[s]) } else { (f.hl[s - ke], f.st[s - ke]) };
        a.hl[c] = hl;
        for i in 0..NA {
            a.st[c][i] = if st[i] == 0 {
                0
            } else {
                let t = if s < ke { (st[i] - 1) as usize } else { ke + (st[i] - 1) as usize };
                cls(&mut par, &idx, t)
            };
        }
    }
    Some(a)
}

// ---------------------------------------------------------------- pullback

/// The reachable fibre product of two language-equivalent automata. Its two projections
/// are covers, so it is *the* canonical span candidate: any `h` covering both maps onto it.
/// `None` when it needs more than `MAXK` states.
fn pullback<const NA: usize>(e: &Aut<NA>, f: &Aut<NA>) -> Option<Aut<NA>> {
    let mut idx: HashMap<(u8, u8), u8> = HashMap::new();
    let mut order: Vec<(u8, u8)> = Vec::new();
    let mut queue: VecDeque<(u8, u8)> = VecDeque::new();
    let mut get = |idx: &mut HashMap<(u8, u8), u8>,
                   order: &mut Vec<(u8, u8)>,
                   queue: &mut VecDeque<(u8, u8)>,
                   p: (u8, u8)|
     -> Option<u8> {
        if let Some(&n) = idx.get(&p) {
            return Some(n);
        }
        if order.len() >= MAXK {
            return None;
        }
        let n = order.len() as u8;
        idx.insert(p, n);
        order.push(p);
        queue.push_back(p);
        Some(n)
    };
    let mut a = Aut::<NA>::blank();
    a.ih = e.ih;
    for i in 0..NA {
        if (e.it[i] == 0) != (f.it[i] == 0) {
            return None;
        }
        if e.it[i] == 0 {
            a.it[i] = 0;
        } else {
            let n = get(&mut idx, &mut order, &mut queue, (e.it[i] - 1, f.it[i] - 1))?;
            a.it[i] = n + 1;
        }
    }
    while let Some(p) = queue.pop_front() {
        let n = idx[&p] as usize;
        let (se, sf) = (p.0 as usize, p.1 as usize);
        if e.hl[se] != f.hl[sf] {
            return None;
        }
        a.hl[n] = e.hl[se];
        for i in 0..NA {
            if (e.st[se][i] == 0) != (f.st[sf][i] == 0) {
                return None;
            }
            if e.st[se][i] == 0 {
                a.st[n][i] = 0;
            } else {
                let t = get(&mut idx, &mut order, &mut queue,
                            (e.st[se][i] - 1, f.st[sf][i] - 1))?;
                a.st[n][i] = t + 1;
            }
        }
    }
    a.k = order.len() as u8;
    Some(a)
}

/// The nesting coequation, automaton level (Schmid-Kappe-Kozen-Silva, ICALP'21; `Nested`
/// in GkatKleeneProofs): no two MUTUALLY reachable states carry complementary halt guards.
/// Every expression's automaton satisfies it, so a system that violates it is the
/// behaviour of no GKAT expression at any size.
fn nested<const NA: usize>(a: &Aut<NA>) -> bool {
    let k = a.k as usize;
    // reach1[i][j] : j reachable from i in one or more steps
    // one u16 row per state (MAXK = 16), so transitive closure is 16 OR-ops, not k^3
    // bool writes through two levels of heap indirection
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 {
                r[i] |= 1 << (a.st[i][x] - 1);
            }
        }
    }
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 {
                r[i] |= rm;
            }
        }
    }
    let full = (1u8 << NA) - 1;
    for i in 0..k {
        for j in 0..k {
            if r[i] >> j & 1 == 1 && r[j] >> i & 1 == 1 && (a.hl[i] ^ a.hl[j]) == full {
                return false; // complementary halt guards on a mutual cycle
            }
        }
    }
    true
}

/// Does this automaton contain a genuinely TWO-EXIT 2-cycle: two distinct mutually
/// reachable states, each of which can leave the cycle (halt, or step outside the pair)?
/// That is the configuration the n=2 existence frontier leaves open. If syntax-generated
/// automata never contain it, the open case never arises where completeness needs it.
fn two_exit_cycle<const NA: usize>(a: &Aut<NA>) -> Option<(usize, usize)> {
    let k = a.k as usize;
    // one u16 row per state (MAXK = 16), so transitive closure is 16 OR-ops, not k^3
    // bool writes through two levels of heap indirection
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 {
                r[i] |= 1 << (a.st[i][x] - 1);
            }
        }
    }
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 {
                r[i] |= rm;
            }
        }
    }
    // "can leave the pair {u,v}": halts somewhere, or steps to a state outside {u,v}
    let leaves = |u: usize, v: usize| -> bool {
        if a.hl[u] != 0 {
            return true;
        }
        (0..NA).any(|x| {
            a.st[u][x] != 0 && {
                let t = (a.st[u][x] - 1) as usize;
                t != u && t != v
            }
        })
    };
    for u in 0..k {
        for v in 0..k {
            if u != v && r[u] >> v & 1 == 1 && r[v] >> u & 1 == 1
                && leaves(u, v) && leaves(v, u) {
                return Some((u, v));
            }
        }
    }
    None
}

/// The narrower question: two mutually reachable distinct states that BOTH halt.
fn two_halt_cycle<const NA: usize>(a: &Aut<NA>) -> Option<(usize, usize)> {
    let k = a.k as usize;
    // one u16 row per state (MAXK = 16), so transitive closure is 16 OR-ops, not k^3
    // bool writes through two levels of heap indirection
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 {
                r[i] |= 1 << (a.st[i][x] - 1);
            }
        }
    }
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 {
                r[i] |= rm;
            }
        }
    }
    for u in 0..k {
        for v in 0..k {
            if u != v && r[u] >> v & 1 == 1 && r[v] >> u & 1 == 1
                && a.hl[u] != 0 && a.hl[v] != 0 {
                return Some((u, v));
            }
        }
    }
    None
}

/// All one-step unrollings of an automaton: rewrite some `while g do B` occurring anywhere
/// inside it as `if g then (B ; while g do B) else 1`.  This is the refinement move — the
/// automaton-level image of `unrollCover` and the `unroll_in_*` context lemmas.
fn unroll_variants<const NA: usize>(
    list: &[Aut<NA>], prov: &[Prov], idx: u32, depth: u32, out: &mut Vec<Aut<NA>>,
) {
    if depth == 0 || out.len() > 4000 {
        return;
    }
    let full = (1u8 << NA) - 1;
    match prov[idx as usize] {
        Prov::Leaf => {}
        Prov::Wh(g, b) => {
            // the unrolling itself
            if let Some(inner) = a_seq(&list[b as usize], &list[idx as usize]) {
                if let Some(u) = a_ite(g, &inner, &a_test::<NA>(full)) {
                    out.push(u);
                }
            }
            // or unroll something inside the body, then re-wrap
            let mut sub = Vec::new();
            unroll_variants(list, prov, b, depth - 1, &mut sub);
            for v in sub {
                out.push(a_wh(g, &v));
            }
        }
        Prov::Seq(l, r) => {
            let mut sl = Vec::new();
            unroll_variants(list, prov, l, depth - 1, &mut sl);
            for v in sl {
                if let Some(a) = a_seq(&v, &list[r as usize]) { out.push(a); }
            }
            let mut sr = Vec::new();
            unroll_variants(list, prov, r, depth - 1, &mut sr);
            for v in sr {
                if let Some(a) = a_seq(&list[l as usize], &v) { out.push(a); }
            }
        }
        Prov::Ite(g, l, r) => {
            let mut sl = Vec::new();
            unroll_variants(list, prov, l, depth - 1, &mut sl);
            for v in sl {
                if let Some(a) = a_ite(g, &v, &list[r as usize]) { out.push(a); }
            }
            let mut sr = Vec::new();
            unroll_variants(list, prov, r, depth - 1, &mut sr);
            for v in sr {
                if let Some(a) = a_ite(g, &list[l as usize], &v) { out.push(a); }
            }
        }
    }
}

/// A candidate program as a tree, so refinements can be *iterated* — the automaton alone
/// cannot be re-refined, since the constructors are not invertible.
#[derive(Clone)]
enum Tree<const NA: usize> {
    Leaf(Aut<NA>),
    Seq(Box<Tree<NA>>, Box<Tree<NA>>),
    Ite(u8, Box<Tree<NA>>, Box<Tree<NA>>),
    Wh(u8, Box<Tree<NA>>),
}

fn to_tree<const NA: usize>(list: &[Aut<NA>], prov: &[Prov], idx: u32) -> Tree<NA> {
    match prov[idx as usize] {
        Prov::Leaf => Tree::Leaf(list[idx as usize]),
        Prov::Seq(l, r) => Tree::Seq(Box::new(to_tree(list, prov, l)),
                                     Box::new(to_tree(list, prov, r))),
        Prov::Ite(g, l, r) => Tree::Ite(g, Box::new(to_tree(list, prov, l)),
                                            Box::new(to_tree(list, prov, r))),
        Prov::Wh(g, b) => Tree::Wh(g, Box::new(to_tree(list, prov, b))),
    }
}

fn eval<const NA: usize>(t: &Tree<NA>) -> Option<Aut<NA>> {
    match t {
        Tree::Leaf(a) => Some(*a),
        Tree::Seq(l, r) => a_seq(&eval(l)?, &eval(r)?),
        Tree::Ite(g, l, r) => a_ite(*g, &eval(l)?, &eval(r)?),
        Tree::Wh(g, b) => Some(a_wh(*g, &eval(b)?)),
    }
}

/// One-step refinements of a tree.
///   * **W1-unrolling**: `while g do B  ⟶  if g then (B ; while g do B) else 1`
///   * **guard-split duplication** (`dup`): `e ⟶ if g then e else e`, which doubles a
///     subterm's states and enters the copies under complementary guards.  This is the move
///     that produced the span witness for the refuting pair, and it is not an unrolling.
/// The degree-k cyclic cover of a loop, as syntax:
///
///     while g do b   ==>   while g do (b ; (g ? b : 1) ; ... ; (g ? b : 1))     [k-1 copies]
///
/// This is the ONE move that changes the covering degree.  W1-unrolling lengthens the tail
/// and guard-split duplication widens the automaton; both leave the cycle length alone, so
/// both saturate.  Repeating the body multiplies the number of action occurrences inside the
/// loop, i.e. multiplies the cycle length by k -- exactly a degree-k cyclic cover of the
/// circle.  Semantically it is an identity: the inner `g ? b : 1` performs the same
/// test-and-body the next outer iteration would, and when the inner test fails nothing runs
/// before the outer test, which therefore also fails.
fn cyclic_cover<const NA: usize>(g: u8, b: &Tree<NA>, k: u32) -> Tree<NA> {
    let full = (1u8 << NA) - 1;
    let mut body = b.clone();
    for _ in 1..k {
        body = Tree::Seq(Box::new(body), Box::new(Tree::Ite(g,
            Box::new(b.clone()),
            Box::new(Tree::Leaf(a_test::<NA>(full))))));
    }
    Tree::Wh(g, Box::new(body))
}

/// Every cyclic cover of degree 2..=kmax, at every loop position in the tree. Used only to
/// check the move is a semantic identity.
fn cyclic_variants<const NA: usize>(t: &Tree<NA>, kmax: u32, out: &mut Vec<Tree<NA>>) {
    match t {
        Tree::Leaf(_) => {}
        Tree::Wh(g, b) => {
            for k in 2..=kmax { out.push(cyclic_cover(*g, b, k)); }
            let mut sub = Vec::new();
            cyclic_variants(b, kmax, &mut sub);
            for v in sub { out.push(Tree::Wh(*g, Box::new(v))); }
        }
        Tree::Seq(l, r) => {
            let mut s = Vec::new();
            cyclic_variants(l, kmax, &mut s);
            for v in s { out.push(Tree::Seq(Box::new(v), r.clone())); }
            let mut s = Vec::new();
            cyclic_variants(r, kmax, &mut s);
            for v in s { out.push(Tree::Seq(l.clone(), Box::new(v))); }
        }
        Tree::Ite(g, l, r) => {
            let mut s = Vec::new();
            cyclic_variants(l, kmax, &mut s);
            for v in s { out.push(Tree::Ite(*g, Box::new(v), r.clone())); }
            let mut s = Vec::new();
            cyclic_variants(r, kmax, &mut s);
            for v in s { out.push(Tree::Ite(*g, l.clone(), Box::new(v))); }
        }
    }
}

fn refinements<const NA: usize>(
    t: &Tree<NA>, nguards: u8, unr: bool, dup: bool, cyc: u32, depth: u32,
    out: &mut Vec<Tree<NA>>,
) {
    if depth == 0 || out.len() > 60000 {
        return;
    }
    let full = (1u8 << NA) - 1;
    if dup {
        for g in 0..nguards {
            out.push(Tree::Ite(g, Box::new(t.clone()), Box::new(t.clone())));
        }
    }
    match t {
        Tree::Leaf(_) => {}
        Tree::Wh(g, b) => {
            if unr {
                out.push(Tree::Ite(*g,
                    Box::new(Tree::Seq(b.clone(), Box::new(t.clone()))),
                    Box::new(Tree::Leaf(a_test::<NA>(full)))));
            }
            for k in 2..=cyc {
                out.push(cyclic_cover(*g, b, k));
            }
            let mut sub = Vec::new();
            refinements(b, nguards, unr, dup, cyc, depth - 1, &mut sub);
            for v in sub { out.push(Tree::Wh(*g, Box::new(v))); }
        }
        Tree::Seq(l, r) => {
            let mut sl = Vec::new();
            refinements(l, nguards, unr, dup, cyc, depth - 1, &mut sl);
            for v in sl { out.push(Tree::Seq(Box::new(v), r.clone())); }
            let mut sr = Vec::new();
            refinements(r, nguards, unr, dup, cyc, depth - 1, &mut sr);
            for v in sr { out.push(Tree::Seq(l.clone(), Box::new(v))); }
        }
        Tree::Ite(g, l, r) => {
            let mut sl = Vec::new();
            refinements(l, nguards, unr, dup, cyc, depth - 1, &mut sl);
            for v in sl { out.push(Tree::Ite(*g, Box::new(v), r.clone())); }
            let mut sr = Vec::new();
            refinements(r, nguards, unr, dup, cyc, depth - 1, &mut sr);
            for v in sr { out.push(Tree::Ite(*g, l.clone(), Box::new(v))); }
        }
    }
}

// ---------------------------------------------------------------- the full space

/// Every transition skeleton on at most `kmax` fully reachable states, in BFS-canonical
/// form.  Slots are filled in the order `init.it[..]`, `st[0][..]`, `st[1][..]`, ..., and a
/// slot may target only an already-discovered state or the next undiscovered index — which
/// is exactly the image of `canon`, so nothing is produced twice and nothing is missed.
///
/// This is the space the closure is a *sample* of.  The closure holds only syntax-generated
/// automata; the question this generator exists to answer is whether anything else in here
/// is bisimilar to an expression without being covered by one.
fn gen_skeletons<const NA: usize>(kmax: usize, out: &mut Vec<Aut<NA>>) {
    fn rec<const NA: usize>(
        a: &mut Aut<NA>, slot: usize, seen: usize, kmax: usize, out: &mut Vec<Aut<NA>>,
    ) {
        if slot >= NA + seen * NA {
            a.k = seen as u8;
            out.push(*a);
            return;
        }
        let limit = if seen < kmax { seen + 1 } else { seen };
        let from_init = slot < NA;
        let (st, i) = if from_init { (0usize, slot) } else {
            ((slot - NA) / NA, (slot - NA) % NA)
        };
        for t in 0..=limit {
            if from_init { a.it[i] = t as u8; } else { a.st[st][i] = t as u8; }
            let seen2 = if t == seen + 1 { seen + 1 } else { seen };
            rec(a, slot + 1, seen2, kmax, out);
        }
        if from_init { a.it[i] = 0; } else { a.st[st][i] = 0; }
    }
    let mut a = Aut::<NA>::blank();
    rec(&mut a, 0, 0, kmax, out);
}

/// **The bisimilarity-to-cover test, run on the whole space rather than on pullbacks.**
///
/// For every fully reachable automaton `p` with at most `kmax` states: if some expression in
/// the closure has `p`'s behaviour — i.e. `p` *is* bisimilar to a GKAT expression — does some
/// expression also **cover** `p`?  A `p` that answers yes to the first and no to the second,
/// after refinement, refutes `Nested ⟹ HasThompsonCover` and with it the induction the whole
/// programme now rests on.
fn expansion_test<const NA: usize>(
    kmax: usize, list: &[Aut<NA>], prov: &[Prov], by_beh: &FxMap<Vec<u8>, Vec<usize>>,
    nguards: u8, pulls: &FxSet<Aut<NA>>,
) {
    let mut skel: Vec<Aut<NA>> = Vec::new();
    gen_skeletons::<NA>(kmax, &mut skel);
    println!("\nEXPANSION TEST (the whole space, not just pullbacks), kmax = {kmax}");
    println!("  transition skeletons: {}", skel.len());
    let nmask = 1u32 << NA;

    let acc = skel.par_iter().map(|sk| {
        let k = sk.k as usize;
        let mut tot = 0u64;      // canonical, fully reachable
        let mut dead = 0u64;     // ... but with an empty-language region (Phase A prunes)
        let mut bisim = 0u64;    // ... productive AND bisimilar to an expression
        let mut direct = 0u64;   // ... and directly covered by one
        let mut resist: Vec<Aut<NA>> = Vec::new();
        // halt masks: the pseudostate's, then one per state
        let combos = (nmask as u64).pow(k as u32 + 1);
        for code in 0..combos {
            let mut a = *sk;
            let mut c = code;
            a.ih = (c % nmask as u64) as u8;
            c /= nmask as u64;
            for s in 0..k {
                a.hl[s] = (c % nmask as u64) as u8;
                c /= nmask as u64;
            }
            match canon(&a) {
                Some(cc) if cc == a => {}
                _ => continue,
            }
            tot += 1;
            // Same Phase A precondition the pair search uses: a dead region has empty
            // language and is discharged outright by `nullLanguage_complete`, so an
            // uncovered dead automaton is not a counterexample to anything.
            if !live(&a) || !all_productive(&a) {
                dead += 1;
                continue;
            }
            let cands = match by_beh.get(&behaviour(&a)) { Some(v) => v, None => continue };
            bisim += 1;
            if cands.iter().any(|&n| covers(&list[n], &a)) { direct += 1; continue; }
            resist.push(a);
        }
        (tot, dead, bisim, direct, resist)
    }).reduce(|| (0u64, 0u64, 0u64, 0u64, Vec::new()), |mut x, y| {
        x.0 += y.0; x.1 += y.1; x.2 += y.2; x.3 += y.3; x.4.extend(y.4); x
    });

    let (tot, dead, bisim, direct, resist) = acc;
    println!("  canonical fully reachable automata : {tot}");
    println!("  dropped as dead / null-language    : {dead}");
    println!("  productive AND bisimilar to an exp : {bisim}");
    println!("  DIRECTLY covered by an expression  : {direct}");
    println!("  not directly covered               : {}", resist.len());

    // the ones that need refinement: same three moves as the pullback test
    // deeper and wider than the pullback test: the residue here is small enough that the
    // search can afford it, and depth is the only lever left once K is out of reach
    let rounds: u32 = std::env::var("EXPAND_ROUNDS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(4);
    let cap: usize = std::env::var("EXPAND_CAP").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(200_000);
    println!("  refinement search: {rounds} rounds, frontier cap {cap}");
    let rescued: Vec<bool> = resist.par_iter().map(|p| {
        let cands = &by_beh[&behaviour(p)];
        for &n in cands.iter() {
            let mut frontier = vec![to_tree(list, prov, n as u32)];
            for _ in 0..rounds {
                let mut next: Vec<Tree<NA>> = Vec::new();
                for t in frontier.iter() {
                    refinements(t, nguards, true, true, 3, 3, &mut next);
                }
                for t in next.iter() {
                    if let Some(v) = eval(t) {
                        if let Some(c) = canon(&v) {
                            if covers(&c, p) { return true; }
                        }
                    }
                }
                frontier = next;
                if frontier.len() > cap { frontier.truncate(cap); }
            }
        }
        false
    }).collect();
    let nres = rescued.iter().filter(|b| !**b).count();
    println!("  rescued by refinement              : {}", rescued.len() - nres);
    println!("  RESIST (bisimilar but uncovered)   : {nres}");
    let mut isp = 0usize;
    for (p, ok) in resist.iter().zip(rescued.iter()) {
        if !*ok {
            let ispull = pulls.contains(p);
            if ispull { isp += 1; }
            println!("    UNCOVERED pullback={ispull} k={} ih={} it={:?} hl={:?} st={:?}",
                p.k, p.ih, &p.it[..], &p.hl[..p.k as usize], &p.st[..p.k as usize]);
        }
    }
    println!("  of the uncovered, ARE a crux pullback : {isp}  (the rest are outside the \
              class `CommonCoveredIntermediate` needs)");
}

// ---------------------------------------------------------------- driver

fn run<const NA: usize>(maxk: usize, pairk: usize) {
    let nguards = 1u8 << NA;
    println!("atoms = {NA}, semantic guards = {nguards}, closure bound K = {maxk}, pairs from k <= {pairk}");

    // ---- closure
    //
    // Three things keep this from being hopeless at K = 6 (56M automata):
    //   * bucketing by core-state count, since `seq`/`ite` add and only k_x + k_y <= maxk
    //     can produce anything in range;
    //   * carrying the closure index *alongside* each automaton, so the innermost loop does
    //     no hashing at all — it used to pay a hash lookup per (x, y) pair;
    //   * filtering against `seen` inside the parallel section, so the round's output holds
    //     only genuinely new automata instead of every product.
    let mut seen: FxMap<Aut<NA>, u32> = FxMap::default();
    let mut list: Vec<Aut<NA>> = Vec::new();
    let mut prov: Vec<Prov> = Vec::new();
    let mut frontier: Vec<u32> = Vec::new();
    {
        let mut seed = |a: Aut<NA>| {
            if let Some(c) = canon(&a) {
                if !seen.contains_key(&c) {
                    seen.insert(c, list.len() as u32);
                    frontier.push(list.len() as u32);
                    list.push(c);
                    prov.push(Prov::Leaf);
                }
            }
        };
        for g in 0..nguards {
            seed(a_test::<NA>(g));
        }
        seed(a_act::<NA>());
    }

    // bucket by core-state count, extended in place each round rather than rebuilt
    let mut bucket: Vec<Vec<(Aut<NA>, u32)>> = vec![Vec::new(); maxk + 1];
    let mut bucketed = 0usize;

    let mut round = 0;
    while !frontier.is_empty() {
        round += 1;
        while bucketed < list.len() {
            let a = list[bucketed];
            bucket[a.k as usize].push((a, bucketed as u32));
            bucketed += 1;
        }
        let seen_ref = &seen;
        let bucket_ref = &bucket;
        let list_ref = &list;
        let produced: Vec<(Aut<NA>, Prov)> = frontier
            .par_iter()
            .flat_map_iter(|&xi| {
                let x = &list_ref[xi as usize];
                let mut out: Vec<(Aut<NA>, Prov)> = Vec::new();
                {
                    let mut push = |a: Option<Aut<NA>>, pv: Prov| {
                        if let Some(a) = a {
                            if a.k as usize <= maxk {
                                if let Some(c) = canon(&a) {
                                    if !seen_ref.contains_key(&c) {
                                        out.push((c, pv));
                                    }
                                }
                            }
                        }
                    };
                    for g in 0..nguards {
                        push(Some(a_wh(g, x)), Prov::Wh(g, xi));
                    }
                    let room = maxk - x.k as usize;
                    for ky in 0..=room {
                        for &(ref y, yi) in bucket_ref[ky].iter() {
                            push(a_seq(x, y), Prov::Seq(xi, yi));
                            push(a_seq(y, x), Prov::Seq(yi, xi));
                            for g in 0..nguards {
                                push(a_ite(g, x, y), Prov::Ite(g, xi, yi));
                                push(a_ite(g, y, x), Prov::Ite(g, yi, xi));
                            }
                        }
                    }
                }
                out
            })
            .collect();
        let mut fresh: Vec<u32> = Vec::new();
        for (a, pv) in produced {
            if !seen.contains_key(&a) {
                seen.insert(a, list.len() as u32);
                fresh.push(list.len() as u32);
                list.push(a);
                prov.push(pv);
            }
        }
        println!("  round {round}: {} automata (+{})", list.len(), fresh.len());
        frontier = fresh;
    }
    println!("CLOSED: {} fully reachable Thompson automata with <= {maxk} core states", list.len());
    if std::env::var("DUMP").is_ok() {
        let mut lines: Vec<String> = list
            .iter()
            .map(|a| {
                let mut s = format!("k={} ih={} it={:?}", a.k, a.ih, &a.it[..]);
                for x in 0..a.k as usize {
                    s += &format!(" | hl{}={} st{}={:?}", x, a.hl[x], x, &a.st[x][..]);
                }
                s
            })
            .collect();
        lines.sort();
        for l in lines { println!("DUMP {l}"); }
    }

    // ---- the entry/body-separated sublcass: no `seq` after something that can terminate
    // immediately.  This is the automaton-level form of the skip-free framework's
    // "entry vs body" partition (Kappe-Schmid, FoSSaCS'25), whose absence is exactly why
    // full GKAT is excluded there.
    let mut entryonly: HashSet<Aut<NA>> = HashSet::new();
    {
        let mut ef: Vec<Aut<NA>> = Vec::new();
        let mut front: Vec<Aut<NA>> = Vec::new();
        for g in 0..nguards {
            if let Some(c) = canon(&a_test::<NA>(g)) {
                if entryonly.insert(c) { ef.push(c); front.push(c); }
            }
        }
        if let Some(c) = canon(&a_act::<NA>()) {
            if entryonly.insert(c) { ef.push(c); front.push(c); }
        }
        while !front.is_empty() {
            let mut bucket: Vec<Vec<Aut<NA>>> = vec![Vec::new(); maxk + 1];
            for a in ef.iter() { bucket[a.k as usize].push(*a); }
            let produced: Vec<Aut<NA>> = front
                .par_iter()
                .flat_map_iter(|x| {
                    let mut out: Vec<Aut<NA>> = Vec::new();
                    {
                        let mut push = |a: Option<Aut<NA>>| {
                            if let Some(a) = a {
                                if a.k as usize <= maxk {
                                    if let Some(c) = canon(&a) { out.push(c); }
                                }
                            }
                        };
                        for g in 0..nguards { push(Some(a_wh(g, x))); }
                        let room = maxk - x.k as usize;
                        for ky in 0..=room {
                            for y in bucket[ky].iter() {
                                if x.ih == 0 { push(a_seq(x, y)); }
                                if y.ih == 0 { push(a_seq(y, x)); }
                                for g in 0..nguards {
                                    push(a_ite(g, x, y));
                                    push(a_ite(g, y, x));
                                }
                            }
                        }
                    }
                    out
                })
                .collect();
            let mut fresh: Vec<Aut<NA>> = Vec::new();
            for a in produced {
                if entryonly.insert(a) { ef.push(a); fresh.push(a); }
            }
            front = fresh;
        }
        println!("  entry/body-separated subclass: {} automata", entryonly.len());
    }

    // ---- index by behaviour
    let mut by_beh: FxMap<Vec<u8>, Vec<usize>> = FxMap::default();
    for (n, a) in list.iter().enumerate() {
        by_beh.entry(behaviour(a)).or_default().push(n);
    }
    println!("  behaviour classes: {}", by_beh.len());

    // ---- crux pairs drawn from the small end, span searched over the whole closure
    let mut pairs = 0usize;
    let mut crux: Vec<(usize, usize)> = Vec::new();
    for idxs in by_beh.values() {
        let small: Vec<usize> = idxs
            .iter()
            .cloned()
            .filter(|&n| {
                list[n].k as usize <= pairk
                    && live(&list[n])
                    && (std::env::var("ANYDEAD").is_ok() || all_productive(&list[n]))
                    && (!std::env::var("SKIPFREE").is_ok() || entryonly.contains(&list[n]))
            })
            .collect();
        for i in 0..small.len() {
            for j in (i + 1)..small.len() {
                pairs += 1;
                let (a, b) = (&list[small[i]], &list[small[j]]);
                let (ie, if_) = forced_injectivity(a, b);
                if !ie && !if_ {
                    crux.push((small[i], small[j]));
                }
            }
        }
    }
    println!("equivalent pairs (k <= {pairk}): {pairs}   CRUX (neither side is the target): {}", crux.len());

    // ---- the COSPAN question: is the forced quotient itself a Thompson automaton?
    let fq: Vec<(usize, usize, bool, bool)> = crux
        .par_iter()
        .map(|&(i, j)| match forced_quotient(&list[i], &list[j]) {
            None => (i, j, false, false),
            Some(q) => match canon(&q) {
                None => (i, j, true, false),
                Some(c) => (i, j, true, seen.contains_key(&c)),
            },
        })
        .collect();
    let fq_sized = fq.iter().filter(|r| r.2).count();
    let fq_thom = fq.iter().filter(|r| r.3).count();
    println!("forced quotient representable: {fq_sized} / {}   IS Thompson: {fq_thom}   NOT: {}",
        crux.len(), fq_sized - fq_thom);

    // ---- span search
    let results: Vec<(usize, usize, bool)> = crux
        .par_iter()
        .map(|&(i, j)| {
            let (e, f) = (&list[i], &list[j]);
            let cands = &by_beh[&behaviour(e)];
            let found = cands.iter().any(|&n| covers(&list[n], e) && covers(&list[n], f));
            (i, j, found)
        })
        .collect();

    // ---- the canonical candidate: is the pullback itself a Thompson automaton?
    let pb: Vec<(usize, usize, u8, bool, bool)> = crux
        .par_iter()
        .map(|&(i, j)| match pullback(&list[i], &list[j]) {
            None => (i, j, 0, false, false),                    // too big to represent
            Some(p) => match canon(&p) {
                None => (i, j, p.k, true, false),               // unreachable states: reject
                Some(c) => (i, j, p.k, true, seen.contains_key(&c)),
            },
        })
        .collect();
    let sized = pb.iter().filter(|r| r.3).count();
    let decid = pb.iter().filter(|r| r.3 && (r.2 as usize) <= maxk).count();
    let thomp = pb.iter().filter(|r| r.4).count();
    println!("\npullback representable (<= {MAXK} states): {sized} / {}", crux.len());
    println!("  of which decidable at K={maxk} (|P| <= K): {decid}");
    println!("  pullback IS a Thompson automaton        : {thomp}");
    let bad: Vec<&(usize, usize, u8, bool, bool)> =
        pb.iter().filter(|r| r.3 && (r.2 as usize) <= maxk && !r.4).collect();
    println!("  pullback decidable but NOT Thompson     : {}", bad.len());
    for (i, j, k, _, _) in bad.iter().take(4) {
        println!("    |P|={k}\n      e = {:?}\n      f = {:?}", list[*i], list[*j]);
    }

    // ---- the positive fork, measured: is the INTERMEDIATE itself solvable?
    // `HasThompsonCover P` — some Thompson automaton covers the pullback. This is the
    // single remaining obligation of `completeness_of_solvable_intermediate`.
    let solv: Vec<(usize, usize, u8, bool)> = crux
        .par_iter()
        .map(|&(i, j)| match pullback(&list[i], &list[j]).and_then(|p| canon(&p)) {
            None => (i, j, 0, false),
            Some(p) => {
                let cands = &by_beh[&behaviour(&p)];
                let found = cands.iter().any(|&n| covers(&list[n], &p));
                (i, j, p.k, found)
            }
        })
        .collect();
    let s_dec = solv.iter().filter(|r| r.2 > 0 && (r.2 as usize) <= maxk).count();
    let s_hit = solv.iter().filter(|r| r.3).count();
    println!("\nintermediate (pullback) solvable by the syntax: {s_hit}");
    println!("  of {} crux pairs, {s_dec} have |P| <= K so the answer is decided", crux.len());
    println!("  decided-but-unsolvable: {}",
        solv.iter().filter(|r| r.2 > 0 && (r.2 as usize) <= maxk && !r.3).count());

    // ---- does any pullback violate the nesting coequation?  If one does, NO expression
    // can cover it at any size, and the positive fork fails for that pair.
    let mut nn = 0usize;
    let mut nn_unsolv = 0usize;
    for (i, j, k, ok) in solv.iter() {
        if let Some(p) = pullback(&list[*i], &list[*j]) {
            if !nested(&p) {
                nn += 1;
                if !ok && *k > 0 { nn_unsolv += 1; }
            }
        }
    }
    println!("pullbacks violating the nesting coequation: {nn}  (of which unsolvable: {nn_unsolv})");
    // and a sanity check the other way: every Thompson automaton must satisfy it
    let bad_thompson = list.par_iter().filter(|a| !nested(a)).count();
    println!("Thompson automata violating it (must be 0): {bad_thompson}");

    // ---- retargeted: do the systems that actually NEED solving — the pullbacks —
    // contain the open two-exit configuration?  For a Thompson automaton existence is free
    // (its own canonical labelling), so the question is only about these.
    let mut pb_exit = 0usize; let mut pb_halt = 0usize; let mut pb_tot = 0usize;
    for &(i, j) in crux.iter() {
        if let Some(p) = pullback(&list[i], &list[j]) {
            pb_tot += 1;
            if two_exit_cycle(&p).is_some() { pb_exit += 1; }
            if two_halt_cycle(&p).is_some() { pb_halt += 1; }
        }
    }
    println!("\npullbacks with a two-EXIT 2-cycle : {pb_exit} / {pb_tot}");
    println!("pullbacks with a two-HALT 2-cycle : {pb_halt} / {pb_tot}");
    let mut solv_halt = 0usize; let mut unsolv_halt = 0usize;
    let mut solv_n = 0usize; let mut unsolv_n = 0usize;
    for (i, j, k, ok) in solv.iter() {
        if *k == 0 { continue; }
        if let Some(p) = pullback(&list[*i], &list[*j]) {
            let h = two_halt_cycle(&p).is_some();
            if *ok { solv_n += 1; if h { solv_halt += 1; } }
            else { unsolv_n += 1; if h { unsolv_halt += 1; } }
        }
    }
    println!("  among SOLVABLE pullbacks   : {solv_halt} / {solv_n} have a two-halt 2-cycle");
    println!("  among UNSOLVABLE pullbacks : {unsolv_halt} / {unsolv_n} have a two-halt 2-cycle");

    // ---- THE MECHANISM TEST, three ways: iterated unrolling, a larger bound (MAXK), and
    // a second refinement move (guard-split duplication).
    let unsolved: Vec<(usize, usize)> = solv.iter()
        .filter(|r| r.2 > 0 && !r.3)
        .map(|r| (r.0, r.1)).collect();
    // ---- SOUNDNESS OF THE CYCLIC-COVER MOVE.
    // Before using it as a refinement we check it is a semantic identity: repeating the
    // loop body must not change the behaviour of the whole program.  Checked over a large
    // prefix of the closure, for degrees 2 and 3, at every loop position in the tree.
    {
        let cap = list.len().min(400_000);
        let (checked, bad): (usize, usize) = (0..cap).into_par_iter()
            .map(|n| {
                let t = to_tree(&list, &prov, n as u32);
                let base = match eval(&t) { Some(a) => a, None => return (0, 0) };
                let bb = behaviour(&base);
                let mut v = Vec::new();
                cyclic_variants(&t, 3, &mut v);
                let (mut c, mut b) = (0, 0);
                for r in v.iter() {
                    if let Some(a) = eval(r) {
                        c += 1;
                        if behaviour(&a) != bb { b += 1; }
                    }
                }
                (c, b)
            })
            .reduce(|| (0, 0), |x, y| (x.0 + y.0, x.1 + y.1));
        println!("\ncyclic-cover soundness: {checked} variants over {cap} programs, \
                  behaviour mismatches: {bad}");
    }

    println!("\nrefinement test on {} uncoverable pullbacks (MAXK={MAXK}):", unsolved.len());
    for &(mode_unr, mode_dup, mode_cyc, rounds, label) in
        [(true, false, 1u32, 1u32, "W1 x1"), (true, false, 1, 2, "W1 x2"),
         (true, true, 1, 1, "W1+dup x1"), (true, true, 1, 2, "W1+dup x2"),
         (false, false, 2, 1, "cyc2 alone x1"), (false, false, 2, 2, "cyc2 alone x2"),
         (false, false, 2, 3, "cyc2 alone x3"),
         (true, false, 2, 1, "W1+cyc2 x1"), (true, false, 2, 2, "W1+cyc2 x2"),
         (true, false, 2, 3, "W1+cyc2 x3"),
         (true, true, 2, 1, "W1+dup+cyc2 x1"), (true, true, 2, 2, "W1+dup+cyc2 x2"),
         (true, true, 3, 1, "everything x1")].iter() {
        let mut rescued = 0usize;
        let mut biggest = 0usize;
        for &(i, j) in unsolved.iter() {
            let p = match pullback(&list[i], &list[j]).and_then(|p| canon(&p)) {
                Some(p) => p, None => continue,
            };
            let cands = &by_beh[&behaviour(&p)];
            let mut found = false;
            'cand: for &n in cands.iter() {
                let mut frontier = vec![to_tree(&list, &prov, n as u32)];
                for _ in 0..rounds {
                    let mut next: Vec<Tree<NA>> = Vec::new();
                    for t in frontier.iter() {
                        refinements(t, nguards, mode_unr, mode_dup, mode_cyc, 3, &mut next);
                    }
                    for t in next.iter() {
                        if let Some(a) = eval(t) {
                            if a.k as usize > biggest { biggest = a.k as usize; }
                            if let Some(c) = canon(&a) {
                                if covers(&c, &p) { found = true; break; }
                            }
                        }
                    }
                    if found { break 'cand; }
                    frontier = next;
                    if frontier.len() > 12000 { frontier.truncate(12000); }
                }
            }
            if found { rescued += 1; } else if rounds == 2 && mode_dup && mode_cyc >= 2 {
                print!("    resistant: |P|={} cands={}", p.k, cands.len());
                println!(" twoHalt={}", two_halt_cycle(&p).is_some());
            }
        }
        println!("  {label:<14}: rescued {rescued} / {}  (largest variant {biggest} states)",
            unsolved.len());
    }

    if let Ok(ek) = std::env::var("EXPAND_K") {
        // Which automata does the programme actually need covered?  Only the pullbacks of
        // equivalent pairs — `CommonCoveredIntermediate` asks for *some* common covered
        // intermediate, and the pullback is the canonical one.  An uncovered automaton that
        // is not a pullback refutes the general statement without touching the programme.
        let mut pulls: FxSet<Aut<NA>> = FxSet::default();
        for &(i, j) in crux.iter() {
            if let Some(p) = pullback(&list[i], &list[j]).and_then(|p| canon(&p)) {
                pulls.insert(p);
            }
        }
        expansion_test(ek.parse().unwrap(), &list, &prov, &by_beh, nguards, &pulls);
    }

    let hit = results.iter().filter(|r| r.2).count();
    let misses: Vec<&(usize, usize, bool)> = results.iter().filter(|r| !r.2).collect();
    println!("\nSPAN FOUND        : {hit}");
    println!("NO span (k <= {maxk}): {}", misses.len());
    let fmt = |a: &Aut<NA>| {
        let mut s = format!("k={} ih={} it={:?}", a.k, a.ih, &a.it[..]);
        for x in 0..a.k as usize {
            s += &format!(" | hl{}={} st{}={:?}", x, a.hl[x], x, &a.st[x][..]);
        }
        s
    };
    for (i, j, _) in misses.iter() {
        println!("NOSPAN\t{}\t{}", fmt(&list[*i]), fmt(&list[*j]));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let na: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(2);
    let maxk: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(4);
    let pairk: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(3);
    match na {
        2 => run::<2>(maxk, pairk),
        3 => run::<3>(maxk, pairk),
        4 => run::<4>(maxk, pairk),
        _ => panic!("atoms must be 2, 3 or 4"),
    }
}
