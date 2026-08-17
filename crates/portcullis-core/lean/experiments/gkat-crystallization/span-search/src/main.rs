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
/// `Total` in the Lean development's sense: every state, at every atom, either HALTS or
/// STEPS.  This is stronger than the textbook GKAT transition function `2 + Sigma x X`,
/// which also allows the reject outcome; the completeness chain needs accept-or-step because
/// bisimilarity coincides with language equivalence only for a complete transition function.
/// `PaddedPullbackCovered` is only ever applied to total automata, so a pullback built from
/// non-total inputs is not an instance of it.
fn total_aut<const NA: usize>(a: &Aut<NA>) -> bool {
    let k = a.k as usize;
    for x in 0..NA {
        if !bit(a.ih, x) && a.it[x] == 0 { return false; }
        for i in 0..k {
            if !bit(a.hl[i], x) && a.st[i][x] == 0 { return false; }
        }
    }
    true
}

/// Un-sharing: a cover may duplicate states, so a survivor whose two initial branches
/// SHARE reachable states can still be covered — give each branch its own private copy and
/// map both copies back.  This is the cover that a forward refinement search from a capped
/// pool will never stumble into, because the un-shared automaton is larger than anything the
/// pool contains.
fn unshare<const NA: usize>(p: &Aut<NA>) -> Option<Aut<NA>> {
    let k = p.k as usize;
    // reach set of each initial branch
    let mut reach = [[false; MAXK]; NA];
    for x in 0..NA {
        if p.it[x] == 0 { continue; }
        let mut stack = vec![(p.it[x] - 1) as usize];
        while let Some(u) = stack.pop() {
            if reach[x][u] { continue; }
            reach[x][u] = true;
            for y in 0..NA {
                if p.st[u][y] != 0 { stack.push((p.st[u][y] - 1) as usize); }
            }
        }
    }
    // one private copy per branch, only for the states that branch can reach
    let mut idx = [[usize::MAX; MAXK]; NA];
    let mut n = 0usize;
    for x in 0..NA {
        for u in 0..k {
            if reach[x][u] { idx[x][u] = n; n += 1; }
        }
    }
    if n > MAXK { return None; }
    let mut h = Aut::<NA>::blank();
    h.k = n as u8;
    h.ih = p.ih;
    for x in 0..NA {
        h.it[x] = if p.it[x] == 0 { 0 } else { (idx[x][(p.it[x] - 1) as usize] + 1) as u8 };
        for u in 0..k {
            if !reach[x][u] { continue; }
            let i = idx[x][u];
            h.hl[i] = p.hl[u];
            for y in 0..NA {
                h.st[i][y] = if p.st[u][y] == 0 { 0 }
                    else { (idx[x][(p.st[u][y] - 1) as usize] + 1) as u8 };
            }
        }
    }
    Some(h)
}

/// The un-shared automaton is an `ite` of the two private branches by construction.  Build
/// those parts explicitly so the cover can be *exhibited* as a program rather than merely
/// asserted: if each part is in the generated pool it is the automaton of a program, and the
/// whole is the automaton of `if g then <part0> else <part1>`.
fn unshare_parts<const NA: usize>(p: &Aut<NA>) -> Option<(u8, Aut<NA>, Aut<NA>)> {
    if NA != 2 { return None; }
    let k = p.k as usize;
    let mut parts: Vec<Aut<NA>> = Vec::new();
    for x in 0..NA {
        let mut reach = [false; MAXK];
        if p.it[x] != 0 {
            let mut stack = vec![(p.it[x] - 1) as usize];
            while let Some(u) = stack.pop() {
                if reach[u] { continue; }
                reach[u] = true;
                for y in 0..NA {
                    if p.st[u][y] != 0 { stack.push((p.st[u][y] - 1) as usize); }
                }
            }
        }
        let mut idx = [usize::MAX; MAXK];
        let mut n = 0usize;
        for u in 0..k { if reach[u] { idx[u] = n; n += 1; } }
        let mut a = Aut::<NA>::blank();
        a.k = n as u8;
        // this part is entered only on the atoms this branch owns
        a.ih = if bit(p.ih, x) { 1u8 << x } else { 0 };
        a.it[x] = if p.it[x] == 0 { 0 } else { (idx[(p.it[x] - 1) as usize] + 1) as u8 };
        for u in 0..k {
            if !reach[u] { continue; }
            let i = idx[u];
            a.hl[i] = p.hl[u];
            for y in 0..NA {
                a.st[i][y] = if p.st[u][y] == 0 { 0 }
                    else { (idx[(p.st[u][y] - 1) as usize] + 1) as u8 };
            }
        }
        parts.push(a);
    }
    let b = parts.pop().unwrap();
    let a = parts.pop().unwrap();
    Some((1u8, a, b))
}

/// Does a PARTNER FUNCTION exist?  `σ` is forced along every run of the synchronised
/// product: the entry pins it, and each step propagates it.  So a partner function exists
/// only if the reachable pair relation is SINGLE-VALUED in the first component — no state
/// reached carrying two different partners.  This is exactly the sharing that un-sharing
/// repairs, and it is the last open question in the Lean chain
/// (`PartnerExists` / `completeness_of_partner`).
///
/// Returns (functional-in-first, functional-in-second, |reachable pairs|).
fn partner_functional<const NA: usize>(a0: &Aut<NA>, a1: &Aut<NA>) -> (bool, bool, usize) {
    let mut seen: std::collections::HashSet<(u8, u8)> = std::collections::HashSet::new();
    let mut queue: VecDeque<(u8, u8)> = VecDeque::new();
    for x in 0..NA {
        if a0.it[x] != 0 && a1.it[x] != 0 {
            let p = (a0.it[x] - 1, a1.it[x] - 1);
            if seen.insert(p) { queue.push_back(p); }
        }
    }
    while let Some((u, v)) = queue.pop_front() {
        for y in 0..NA {
            let (su, sv) = (a0.st[u as usize][y], a1.st[v as usize][y]);
            if su != 0 && sv != 0 {
                let p = (su - 1, sv - 1);
                if seen.insert(p) { queue.push_back(p); }
            }
        }
    }
    let mut first: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
    let _ = &queue;
    let mut second: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
    let mut f1 = true;
    let mut f2 = true;
    for &(u, v) in seen.iter() {
        if let Some(&w) = first.get(&u) { if w != v { f1 = false; } } else { first.insert(u, v); }
        if let Some(&w) = second.get(&v) { if w != u { f2 = false; } } else { second.insert(v, u); }
    }
    (f1, f2, seen.len())
}

/// The same question, asked ONE ENTRY BRANCH AT A TIME.  If `σ` fails globally only because
/// different atoms enter the product at different pairs, then a per-branch partner function
/// exists — and that is precisely un-sharing: give each branch its own private copy, each
/// carrying its own `σ`.
fn partner_functional_perbranch<const NA: usize>(a0: &Aut<NA>, a1: &Aut<NA>) -> bool {
    for x in 0..NA {
        if a0.it[x] == 0 || a1.it[x] == 0 { continue; }
        let mut seen: std::collections::HashSet<(u8, u8)> = std::collections::HashSet::new();
        let mut queue: VecDeque<(u8, u8)> = VecDeque::new();
        let p0 = (a0.it[x] - 1, a1.it[x] - 1);
        seen.insert(p0);
        queue.push_back(p0);
        while let Some((u, v)) = queue.pop_front() {
            for y in 0..NA {
                let (su, sv) = (a0.st[u as usize][y], a1.st[v as usize][y]);
                if su != 0 && sv != 0 {
                    let p = (su - 1, sv - 1);
                    if seen.insert(p) { queue.push_back(p); }
                }
            }
        }
        let mut first: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
        for &(u, v) in seen.iter() {
            if let Some(&w) = first.get(&u) { if w != v { return false; } }
            else { first.insert(u, v); }
        }
    }
    true
}

/// Recursive un-sharing.  A branch piece has strictly fewer states than its parent, so if
/// every piece is either already a program automaton or splits further, the recursion is
/// well-founded and IS the induction that would discharge `RestrictedBranchesCovered`.
/// Returns Some(depth) if it resolves, None if it stalls (a piece that is not in the pool and
/// does not shrink under un-sharing).
fn unshare_rec<const NA: usize>(p: &Aut<NA>, list: &[Aut<NA>],
    by_beh: &FxMap<Vec<u8>, Vec<usize>>, depth: usize, budget: usize) -> Option<usize> {
    let c = canon(p)?;
    if let Some(cands) = by_beh.get(&behaviour(&c)) {
        if cands.iter().any(|&n| list[n] == c) { return Some(depth); }
    }
    if depth >= budget { return None; }
    let (g, a, b) = unshare_parts(p)?;
    // progress check: a piece must be strictly smaller, or the recursion cannot terminate
    if a.k as usize >= p.k as usize || b.k as usize >= p.k as usize { return None; }
    let h = a_ite(g, &a, &b)?;
    let hc = canon(&h)?;
    if !covers(&hc, p) { return None; }
    let da = if a.k == 0 { Some(depth) } else {
        unshare_rec(&a, list, by_beh, depth + 1, budget) };
    let db = if b.k == 0 { Some(depth) } else {
        unshare_rec(&b, list, by_beh, depth + 1, budget) };
    match (da, db) { (Some(x), Some(y)) => Some(x.max(y)), _ => None }
}

/// Is the state set `mask` closed under transitions?
fn sub_closed<const NA: usize>(h: &Aut<NA>, mask: u16) -> bool {
    for u in 0..h.k as usize {
        if mask & (1 << u) == 0 { continue; }
        for y in 0..NA {
            let t = h.st[u][y];
            if t != 0 && mask & (1 << (t - 1)) == 0 { return false; }
        }
    }
    true
}

/// The sub-automaton on `mask`, renumbered, with a supplied entry.  `keep` decides, per
/// state and atom, whether a transition leaving `mask` is dropped (`None` if it must not).
fn sub_aut<const NA: usize>(h: &Aut<NA>, mask: u16, ih: u8, it: [u8; NA],
    drop_out: bool) -> Option<Aut<NA>> {
    let mut idx = [usize::MAX; MAXK];
    let mut n = 0usize;
    for u in 0..h.k as usize {
        if mask & (1 << u) != 0 { idx[u] = n; n += 1; }
    }
    let mut a = Aut::<NA>::blank();
    a.k = n as u8;
    a.ih = ih;
    for y in 0..NA {
        a.it[y] = if it[y] == 0 { 0 } else {
            let t = (it[y] - 1) as usize;
            if idx[t] == usize::MAX { return None; }
            (idx[t] + 1) as u8
        };
    }
    for u in 0..h.k as usize {
        if mask & (1 << u) == 0 { continue; }
        let i = idx[u];
        a.hl[i] = h.hl[u];
        for y in 0..NA {
            let t = h.st[u][y];
            if t == 0 { a.st[i][y] = 0; continue; }
            let t = (t - 1) as usize;
            if idx[t] == usize::MAX {
                if !drop_out { return None; }
                a.st[i][y] = 0;
            } else {
                a.st[i][y] = (idx[t] + 1) as u8;
            }
        }
    }
    Some(a)
}

/// **Is `h` the Thompson automaton of some GKAT program?**  Decides by inverting the
/// construction rather than by enumerating every program: try each constructor, rebuild with
/// `a_ite` / `a_seq` / `a_wh`, and compare canonically.  This is what lets a 6-12 state
/// candidate be classified without a pool that reaches that far — the enumeration blows past
/// 55M automata at six states, while this touches one automaton at a time.
fn is_thompson<const NA: usize>(h: &Aut<NA>, guards: &[u8], depth: usize,
    memo: &mut FxMap<Aut<NA>, bool>) -> bool {
    let c = match canon(h) { Some(c) => c, None => return false };
    if let Some(&b) = memo.get(&c) { return b; }
    if depth == 0 { return false; }
    let r = is_thompson_raw(&c, guards, depth, memo);
    memo.insert(c, r);
    r
}

/// A sub-automaton's entry is only partly determined by the composite: `a_ite` guards `L`'s
/// entry by `g`, so `L`'s behaviour on the other atoms is invisible in the result and must be
/// existentially completed.  Getting this wrong made the oracle reject `ite(a,a)` and `wh(a)`.
fn is_thompson_free<const NA: usize>(a: &Aut<NA>, free: u8, guards: &[u8], depth: usize,
    memo: &mut FxMap<Aut<NA>, bool>) -> bool {
    let mut fs: Vec<usize> = Vec::new();
    for y in 0..NA { if bit_set(free, y) { fs.push(y); } }
    if fs.is_empty() { return is_thompson(a, guards, depth, memo); }
    let opts = a.k as usize + 1;
    let total = opts.pow(fs.len() as u32) * (1usize << fs.len());
    for code in 0..total {
        let mut b = a.clone();
        let mut c = code;
        let mut okc = true;
        for &y in fs.iter() {
            let t = c % opts; c /= opts;
            b.it[y] = t as u8;
        }
        for &y in fs.iter() {
            let h = c % 2; c /= 2;
            if h == 1 { b.ih |= 1 << y; } else { b.ih &= !(1u8 << y); }
        }
        // NB: a Thompson pseudostate MAY be stuck at an atom — `0?` is stuck everywhere — so
        // no halt-or-step constraint is imposed on the completion.
        let _ = &mut okc;
        if is_thompson(&b, guards, depth, memo) { return true; }
    }
    false
}

/// Existentially complete BOTH invisible parts of a `seq` left factor: its entry outside the
/// composite's reach, and its halt bits at atoms where the right factor neither halts nor
/// steps.  Neither affects the rebuild, so both are free and must be enumerated rather than
/// guessed — taking them maximally was the last heuristic in the oracle.
fn is_thompson_free2<const NA: usize>(a: &Aut<NA>, free_entry: u8, free_hl: u8,
    guards: &[u8], depth: usize, memo: &mut FxMap<Aut<NA>, bool>) -> bool {
    let k = a.k as usize;
    let mut hs: Vec<usize> = Vec::new();
    for y in 0..NA { if bit_set(free_hl, y) { hs.push(y); } }
    if hs.is_empty() { return is_thompson_free(a, free_entry, guards, depth, memo); }
    let combos = 1usize << (k * hs.len());
    if combos > 8192 { return is_thompson_free(a, free_entry, guards, depth, memo); }
    for code in 0..combos {
        let mut b = a.clone();
        let mut c = code;
        for u in 0..k {
            for &y in hs.iter() {
                if c & 1 == 1 { b.hl[u] |= 1 << y; } else { b.hl[u] &= !(1u8 << y); }
                c >>= 1;
            }
        }
        if is_thompson_free(&b, free_entry, guards, depth, memo) { return true; }
    }
    false
}

fn is_thompson_raw<const NA: usize>(h: &Aut<NA>, guards: &[u8], depth: usize,
    memo: &mut FxMap<Aut<NA>, bool>) -> bool {
    let k = h.k as usize;
    // leaves
    if k == 0 {
        return guards.iter().any(|&g| canon(&a_test::<NA>(g)) == canon(h));
    }
    if k == 1 && canon(&a_act::<NA>()) == canon(h) { return true; }
    let full: u16 = if k == 16 { u16::MAX } else { (1u16 << k) - 1 };
    // wh: the loop's initHlt is ¬g, so the guard is forced
    {
        let g = (!h.ih) & (((1u16 << NA) - 1) as u8);
        let mut bit = [0u8; NA];
        let mut ok = true;
        for y in 0..NA {
            if bit_set(g, y) { bit[y] = h.it[y]; }
            else if h.it[y] != 0 { ok = false; }
        }
        if ok {
            // positions that could be back edges
            let mut amb: Vec<(usize, usize)> = Vec::new();
            for u in 0..k {
                for y in 0..NA {
                    if bit_set(g, y) && h.st[u][y] != 0 && h.st[u][y] == bit[y] {
                        amb.push((u, y));
                    }
                }
            }
            if amb.len() <= 14 {
                for choice in 0..(1u32 << amb.len()) {
                    let mut b = Aut::<NA>::blank();
                    b.k = h.k;
                    b.ih = 0;
                    b.it = bit;
                    for u in 0..k { b.hl[u] = h.hl[u]; b.st[u] = h.st[u]; }
                    for (j, &(u, y)) in amb.iter().enumerate() {
                        if choice & (1 << j) != 0 {
                            b.st[u][y] = 0;
                            b.hl[u] |= 1 << y;
                        }
                    }
                    let freeb = (!g) & (((1u16 << NA) - 1) as u8);
                    if canon(&a_wh(g, &b)) == canon(h)
                        && is_thompson_free(&b, freeb, guards, depth - 1, memo) { return true; }
                end_of_choice(); }
            }
        }
    }
    // ite and seq: split the state set
    if k >= 1 {
        let nmasks: u32 = 1u32 << k;
        for m in 0..nmasks {
            let mask = m as u16;
            let comp = full & !mask;
            // ite: both sides closed
            if sub_closed(h, mask) && sub_closed(h, comp) {
                for &g in guards.iter() {
                    let mut itl = [0u8; NA];
                    let mut itr = [0u8; NA];
                    let mut ok = true;
                    for y in 0..NA {
                        if bit_set(g, y) {
                            itl[y] = h.it[y];
                            if h.it[y] != 0 && mask & (1 << (h.it[y] - 1)) == 0 { ok = false; }
                        } else {
                            itr[y] = h.it[y];
                            if h.it[y] != 0 && comp & (1 << (h.it[y] - 1)) == 0 { ok = false; }
                        }
                    }
                    if !ok { continue; }
                    let l = match sub_aut(h, mask, h.ih & g, itl, false) { Some(a) => a, None => continue };
                    let r = match sub_aut(h, comp, h.ih & !g, itr, false) { Some(a) => a, None => continue };
                    if let Some(built) = a_ite(g, &l, &r) {
                        let nm2 = ((1u16 << NA) - 1) as u8;
                        if canon(&built) == canon(h)
                            && is_thompson_free(&l, (!g) & nm2, guards, depth - 1, memo)
                            && is_thompson_free(&r, g & nm2, guards, depth - 1, memo) {
                            return true;
                        }
                    }
                }
            }
            // seq: the right part must be closed
            if sub_closed(h, comp) {
                let nm = ((1u16 << NA) - 1) as u8;
                for rih in 0..=nm {
                    for lih in 0..=nm {
                        let mut itr = [0u8; NA];
                        let mut itl = [0u8; NA];
                        let mut ok = true;
                        for y in 0..NA {
                            let t = h.it[y];
                            if t == 0 { continue; }
                            if mask & (1 << (t - 1)) != 0 { itl[y] = t; }
                            else { itr[y] = t; if !bit_set(lih, y) { ok = false; } }
                        }
                        if !ok { continue; }
                        let mut lhl = [0u8; MAXK];
                        for u in 0..k {
                            if mask & (1 << u) == 0 { continue; }
                            let mut m2 = h.hl[u];
                            for y in 0..NA {
                                let t = h.st[u][y];
                                if t != 0 && comp & (1 << (t - 1)) != 0 {
                                    m2 |= 1 << y;
                                    if itr[y] == 0 { itr[y] = t; }
                                    else if itr[y] != t { ok = false; }
                                }
                            }
                            lhl[u] = m2;
                        }
                        if !ok { continue; }
                        // `L`'s halt guard is masked by `R.ih`, so bits where `R` neither
                        // halts nor steps are invisible to the rebuild.  Keep them minimal
                        // here and complete them existentially in the recursion.
                        let mut freeh = 0u8;
                        for y in 0..NA {
                            if !bit_set(rih, y) && itr[y] == 0 { freeh |= 1 << y; }
                        }
                        // `R`'s entry is invisible at atoms no `L` state exits on
                        let mut freer = 0u8;
                        for y in 0..NA { if itr[y] == 0 { freer |= 1 << y; } }
                        let mut l = match sub_aut(h, mask, lih, itl, true) { Some(a) => a, None => continue };
                        {
                            let mut n = 0usize;
                            for u in 0..k {
                                if mask & (1 << u) == 0 { continue; }
                                l.hl[n] = lhl[u]; n += 1;
                            }
                        }
                        let r = match sub_aut(h, comp, rih, itr, false) { Some(a) => a, None => continue };
                        if let Some(built) = a_seq(&l, &r) {
                            if canon(&built) == canon(h)
                                && is_thompson_free2(&l, 0, freeh, guards, depth - 1, memo)
                                && is_thompson_free(&r, freer, guards, depth - 1, memo) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

#[inline]
fn end_of_choice() {}

#[inline]
fn bit_set(mask: u8, i: usize) -> bool { mask & (1 << i) != 0 }

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

/// A candidate program as a **hashconsed** term.  Refinements have to be *iterated* — the
/// automaton alone cannot be re-refined, since the constructors are not invertible — but
/// boxed trees made that quadratic: variants overlap almost entirely, so the same subterm
/// was rebuilt, re-hashed and re-evaluated once per variant containing it.
///
/// The idea is the useful half of an e-graph, without the semantic quotient.  (The quotient
/// itself would be worse than useless here: an e-class groups programs that are *equal*,
/// and the whole search is over the different automata equal programs produce, so e-classes
/// merge exactly the distinction being searched.)  Nodes are interned to `u32` ids, so
/// structural sharing is automatic and dedup is pointer equality.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Node<const NA: usize> {
    Leaf(Aut<NA>),
    Seq(u32, u32),
    Ite(u8, u32, u32),
    Wh(u8, u32),
}

/// Interned terms, each carrying its automaton.  The automaton is computed **at intern
/// time**, so every distinct subterm is evaluated exactly once no matter how many variants
/// contain it — the analysis is bottom-up over the shared structure.
struct Pool<const NA: usize> {
    nodes: Vec<Node<NA>>,
    index: FxMap<Node<NA>, u32>,
    val: Vec<Option<Aut<NA>>>,
}

impl<const NA: usize> Pool<NA> {
    fn new() -> Self {
        Pool { nodes: Vec::new(), index: FxMap::default(), val: Vec::new() }
    }

    fn intern(&mut self, n: Node<NA>) -> u32 {
        if let Some(&i) = self.index.get(&n) {
            return i;
        }
        let v = match n {
            Node::Leaf(a) => Some(a),
            Node::Seq(x, y) => match (self.val[x as usize], self.val[y as usize]) {
                (Some(a), Some(b)) => a_seq(&a, &b),
                _ => None,
            },
            Node::Ite(g, x, y) => match (self.val[x as usize], self.val[y as usize]) {
                (Some(a), Some(b)) => a_ite(g, &a, &b),
                _ => None,
            },
            Node::Wh(g, x) => self.val[x as usize].map(|a| a_wh(g, &a)),
        };
        let i = self.nodes.len() as u32;
        self.nodes.push(n);
        self.val.push(v);
        self.index.insert(n, i);
        i
    }

    #[inline]
    fn aut(&self, i: u32) -> Option<Aut<NA>> {
        self.val[i as usize]
    }

    fn leaf(&mut self, a: Aut<NA>) -> u32 { self.intern(Node::Leaf(a)) }

    /// Rebuild a closure member as a term, following its provenance.
    fn of_prov(&mut self, list: &[Aut<NA>], prov: &[Prov], idx: u32) -> u32 {
        let n = match prov[idx as usize] {
            Prov::Leaf => Node::Leaf(list[idx as usize]),
            Prov::Seq(l, r) => {
                let a = self.of_prov(list, prov, l);
                let b = self.of_prov(list, prov, r);
                Node::Seq(a, b)
            }
            Prov::Ite(g, l, r) => {
                let a = self.of_prov(list, prov, l);
                let b = self.of_prov(list, prov, r);
                Node::Ite(g, a, b)
            }
            Prov::Wh(g, b) => {
                let x = self.of_prov(list, prov, b);
                Node::Wh(g, x)
            }
        };
        self.intern(n)
    }
}

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
fn cyclic_cover<const NA: usize>(pool: &mut Pool<NA>, g: u8, b: u32, k: u32) -> u32 {
    let full = (1u8 << NA) - 1;
    let one = pool.leaf(a_test::<NA>(full));
    let mut body = b;
    for _ in 1..k {
        let branch = pool.intern(Node::Ite(g, b, one));
        body = pool.intern(Node::Seq(body, branch));
    }
    pool.intern(Node::Wh(g, body))
}

/// Every cyclic cover of degree 2..=kmax, at every loop position.  Used only to check the
/// move is a semantic identity.
fn cyclic_variants<const NA: usize>(pool: &mut Pool<NA>, t: u32, kmax: u32, out: &mut Vec<u32>) {
    match pool.nodes[t as usize] {
        Node::Leaf(_) => {}
        Node::Wh(g, b) => {
            for k in 2..=kmax {
                let v = cyclic_cover(pool, g, b, k);
                out.push(v);
            }
            let mut sub = Vec::new();
            cyclic_variants(pool, b, kmax, &mut sub);
            for v in sub {
                let w = pool.intern(Node::Wh(g, v));
                out.push(w);
            }
        }
        Node::Seq(l, r) => {
            let mut sub = Vec::new();
            cyclic_variants(pool, l, kmax, &mut sub);
            for v in sub { let w = pool.intern(Node::Seq(v, r)); out.push(w); }
            let mut sub = Vec::new();
            cyclic_variants(pool, r, kmax, &mut sub);
            for v in sub { let w = pool.intern(Node::Seq(l, v)); out.push(w); }
        }
        Node::Ite(g, l, r) => {
            let mut sub = Vec::new();
            cyclic_variants(pool, l, kmax, &mut sub);
            for v in sub { let w = pool.intern(Node::Ite(g, v, r)); out.push(w); }
            let mut sub = Vec::new();
            cyclic_variants(pool, r, kmax, &mut sub);
            for v in sub { let w = pool.intern(Node::Ite(g, l, v)); out.push(w); }
        }
    }
}

fn refinements<const NA: usize>(
    pool: &mut Pool<NA>, t: u32, nguards: u8, unr: bool, dup: bool, cyc: u32, depth: u32,
    out: &mut Vec<u32>,
) {
    if depth == 0 || out.len() > 60000 {
        return;
    }
    let full = (1u8 << NA) - 1;
    if dup {
        for g in 0..nguards {
            let w = pool.intern(Node::Ite(g, t, t));
            out.push(w);
        }
    }
    match pool.nodes[t as usize] {
        Node::Leaf(_) => {}
        Node::Wh(g, b) => {
            if unr {
                let one = pool.leaf(a_test::<NA>(full));
                let body = pool.intern(Node::Seq(b, t));
                let w = pool.intern(Node::Ite(g, body, one));
                out.push(w);
            }
            for k in 2..=cyc {
                let v = cyclic_cover(pool, g, b, k);
                out.push(v);
            }
            let mut sub = Vec::new();
            refinements(pool, b, nguards, unr, dup, cyc, depth - 1, &mut sub);
            for v in sub { let w = pool.intern(Node::Wh(g, v)); out.push(w); }
        }
        Node::Seq(l, r) => {
            let mut sub = Vec::new();
            refinements(pool, l, nguards, unr, dup, cyc, depth - 1, &mut sub);
            for v in sub { let w = pool.intern(Node::Seq(v, r)); out.push(w); }
            let mut sub = Vec::new();
            refinements(pool, r, nguards, unr, dup, cyc, depth - 1, &mut sub);
            for v in sub { let w = pool.intern(Node::Seq(l, v)); out.push(w); }
        }
        Node::Ite(g, l, r) => {
            let mut sub = Vec::new();
            refinements(pool, l, nguards, unr, dup, cyc, depth - 1, &mut sub);
            for v in sub { let w = pool.intern(Node::Ite(g, v, r)); out.push(w); }
            let mut sub = Vec::new();
            refinements(pool, r, nguards, unr, dup, cyc, depth - 1, &mut sub);
            for v in sub { let w = pool.intern(Node::Ite(g, l, v)); out.push(w); }
        }
    }
}

#[inline]
fn gcd_u32(mut x: u32, mut y: u32) -> u32 { while y != 0 { let t = x % y; x = y; y = t; } x }

/// The **period** of each nontrivial strongly connected component: the gcd of *all* cycle
/// lengths in it, not of the shortest cycle per state (which is only an over-approximation
/// and is what the first version of `features` got wrong).  Computed the classical way —
/// BFS levels inside the component, then the gcd of `|lev[u] + 1 - lev[v]|` over its edges.
///
/// This is the group-theoretic invariant: a covering map sends a cycle of length `n` to a
/// closed walk of length `n`, so `period(p)` divides every cycle length of any cover of `p`,
/// hence `period(p) | period(h)`.  That is a theorem, and it follows from `star_bijection`.
/// Cycles cannot pass through the pseudostate — nothing steps into it — so only core states
/// take part.
fn scc_periods<const NA: usize>(a: &Aut<NA>) -> Vec<u32> {
    let k = a.k as usize;
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 { r[i] |= 1 << (a.st[i][x] - 1); }
        }
    }
    let adj = r;
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 { r[i] |= rm; }
        }
    }
    let mut comp = [usize::MAX; MAXK];
    let mut out: Vec<u32> = Vec::new();
    for i in 0..k {
        if comp[i] != usize::MAX || r[i] >> i & 1 != 1 { continue; }
        let id = out.len();
        comp[i] = id;
        for j in (i + 1)..k {
            if comp[j] == usize::MAX && r[i] >> j & 1 == 1 && r[j] >> i & 1 == 1 {
                comp[j] = id;
            }
        }
        let mut lev = [u32::MAX; MAXK];
        lev[i] = 0;
        let mut q = VecDeque::new();
        q.push_back(i);
        while let Some(u) = q.pop_front() {
            for v in 0..k {
                if comp[v] == id && adj[u] >> v & 1 == 1 && lev[v] == u32::MAX {
                    lev[v] = lev[u] + 1;
                    q.push_back(v);
                }
            }
        }
        let mut g = 0u32;
        for u in 0..k {
            if comp[u] != id || lev[u] == u32::MAX { continue; }
            for v in 0..k {
                if comp[v] == id && adj[u] >> v & 1 == 1 && lev[v] != u32::MAX {
                    let d = (lev[u] as i64 + 1 - lev[v] as i64).unsigned_abs() as u32;
                    g = gcd_u32(g, d);
                }
            }
        }
        out.push(if g == 0 { 1 } else { g });
    }
    out
}

/// The divisibility filter the period law licenses: every component of a cover maps into
/// some component of the target, and its period must be a multiple of that one's.  Sound,
/// and cheaper than the `covers` BFS it guards.
fn period_compatible<const NA: usize>(h: &Aut<NA>, p: &Aut<NA>) -> bool {
    let dp = scc_periods(p);
    if dp.is_empty() { return true; }
    scc_periods(h).iter().all(|dh| dp.iter().any(|d| dh % d == 0))
}

/// Candidate **labelling** invariants.  The period law bounds how big a cover must be but
/// can never forbid one, since `cyclicCover` multiplies the period by any `k` — so an
/// impossibility obstruction has to live in the halt labelling, which `π₁` does not see.
/// Returns (distinct halt masks on cycles, halting states not sharing their component's
/// mask, distinct BFS levels mod period carrying a halt).
fn halt_shape<const NA: usize>(a: &Aut<NA>) -> [u32; 3] {
    let k = a.k as usize;
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 { r[i] |= 1 << (a.st[i][x] - 1); }
        }
    }
    let adj = r;
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 { r[i] |= rm; }
        }
    }
    let mut masks: Vec<u8> = Vec::new();
    for i in 0..k {
        if r[i] >> i & 1 == 1 && a.hl[i] != 0 && !masks.contains(&a.hl[i]) { masks.push(a.hl[i]); }
    }
    let mut comp = [usize::MAX; MAXK];
    let mut ncomp = 0usize;
    let mut mismatched = 0u32;
    let mut levels: Vec<(usize, u32)> = Vec::new();
    for i in 0..k {
        if comp[i] != usize::MAX || r[i] >> i & 1 != 1 { continue; }
        let id = ncomp;
        ncomp += 1;
        comp[i] = id;
        for j in (i + 1)..k {
            if comp[j] == usize::MAX && r[i] >> j & 1 == 1 && r[j] >> i & 1 == 1 { comp[j] = id; }
        }
        let mut lev = [u32::MAX; MAXK];
        lev[i] = 0;
        let mut q = VecDeque::new();
        q.push_back(i);
        while let Some(u) = q.pop_front() {
            for v in 0..k {
                if comp[v] == id && adj[u] >> v & 1 == 1 && lev[v] == u32::MAX {
                    lev[v] = lev[u] + 1;
                    q.push_back(v);
                }
            }
        }
        let mut g = 0u32;
        for u in 0..k {
            if comp[u] != id || lev[u] == u32::MAX { continue; }
            for v in 0..k {
                if comp[v] == id && adj[u] >> v & 1 == 1 && lev[v] != u32::MAX {
                    g = gcd_u32(g, (lev[u] as i64 + 1 - lev[v] as i64).unsigned_abs() as u32);
                }
            }
        }
        let d = if g == 0 { 1 } else { g };
        let mut first: Option<u8> = None;
        for u in 0..k {
            if comp[u] != id || a.hl[u] == 0 { continue; }
            match first {
                None => first = Some(a.hl[u]),
                Some(m) => if m != a.hl[u] { mismatched += 1; },
            }
            if lev[u] != u32::MAX {
                let l = (id, lev[u] % d);
                if !levels.contains(&l) { levels.push(l); }
            }
        }
    }
    [masks.len() as u32, mismatched, levels.len() as u32]
}

/// **Reducibility**, the classical structuredness test for flow graphs: every strongly
/// connected subgraph has a single entry, equivalently every back edge's head dominates its
/// tail, equivalently deleting the back edges leaves a DAG.
///
/// Why this and not LEE: structured `if`/`while` programs always produce reducible graphs,
/// but the classical converse is "reducible implies structured **with multilevel break and
/// continue**" — and GKAT has neither.  So reducibility is *necessary* for a GKAT automaton
/// and not obviously sufficient, which is exactly the gap the counterexamples might live in.
/// Node 0 is the pseudostate; node `i+1` is core state `i`.
fn reducible<const NA: usize>(a: &Aut<NA>) -> bool {
    // Allocation-free: at most MAXK + 1 = 17 nodes, so successors and predecessors are u32
    // bitmasks and every working array is fixed.  The first version allocated about
    // 3(n+1)+6 Vecs per call, which is ruinous when the caller sweeps 56M automata.
    let n = a.k as usize + 1;
    let mut succ = [0u32; MAXK + 1];
    for x in 0..NA {
        if a.it[x] != 0 { succ[0] |= 1 << a.it[x]; }
    }
    for i in 0..a.k as usize {
        for x in 0..NA {
            if a.st[i][x] != 0 { succ[i + 1] |= 1 << a.st[i][x]; }
        }
    }
    // reverse postorder from 0, with an explicit stack
    let mut rpo = [u8::MAX; MAXK + 1];
    let mut order = [0usize; MAXK + 1];
    let mut nord = 0usize;
    {
        let mut stack = [(0usize, 0usize); MAXK + 2];
        let mut sp = 0usize;
        let mut entered = [false; MAXK + 1];
        stack[0] = (0, 0);
        sp = 1;
        entered[0] = true;
        while sp > 0 {
            let (u, mut i) = stack[sp - 1];
            let mut pushed = false;
            while i < n {
                if succ[u] >> i & 1 == 1 && !entered[i] {
                    entered[i] = true;
                    stack[sp - 1].1 = i + 1;
                    stack[sp] = (i, 0);
                    sp += 1;
                    pushed = true;
                    break;
                }
                i += 1;
            }
            if !pushed {
                stack[sp - 1].1 = n;
                order[nord] = u;
                nord += 1;
                sp -= 1;
            }
        }
    }
    for i in 0..nord {
        rpo[order[nord - 1 - i]] = i as u8;
    }
    let mut pred = [0u32; MAXK + 1];
    for u in 0..n {
        for v in 0..n {
            if succ[u] >> v & 1 == 1 { pred[v] |= 1 << u; }
        }
    }
    // iterative dominators (Cooper-Harvey-Kennedy)
    let mut idom = [u8::MAX; MAXK + 1];
    idom[0] = 0;
    let mut changed = true;
    while changed {
        changed = false;
        for k in 0..nord {
            let u = order[nord - 1 - k];
            if u == 0 || rpo[u] == u8::MAX { continue; }
            let mut new = u8::MAX;
            for p in 0..n {
                if pred[u] >> p & 1 != 1 || rpo[p] == u8::MAX || idom[p] == u8::MAX { continue; }
                new = if new == u8::MAX { p as u8 } else {
                    let (mut x, mut y) = (new as usize, p);
                    while x != y {
                        while rpo[x] > rpo[y] { x = idom[x] as usize; }
                        while rpo[y] > rpo[x] { y = idom[y] as usize; }
                    }
                    x as u8
                };
            }
            if new != u8::MAX && idom[u] != new { idom[u] = new; changed = true; }
        }
    }
    // delete back edges (head dominates tail), then test the remainder for acyclicity
    let mut fwd = [0u32; MAXK + 1];
    for u in 0..n {
        if rpo[u] == u8::MAX { continue; }
        for v in 0..n {
            if succ[u] >> v & 1 != 1 || rpo[v] == u8::MAX { continue; }
            let mut x = u;
            let mut dom = false;
            loop {
                if x == v { dom = true; break; }
                if x == 0 { break; }
                let nx = idom[x];
                if nx == u8::MAX || nx as usize == x { break; }
                x = nx as usize;
            }
            if !dom { fwd[u] |= 1 << v; }
        }
    }
    let mut indeg = [0u8; MAXK + 1];
    for u in 0..n {
        for v in 0..n {
            if fwd[u] >> v & 1 == 1 { indeg[v] += 1; }
        }
    }
    let mut queue = [0usize; MAXK + 1];
    let (mut qh, mut qt) = (0usize, 0usize);
    let mut live = 0usize;
    for u in 0..n {
        if rpo[u] == u8::MAX { continue; }
        live += 1;
        if indeg[u] == 0 { queue[qt] = u; qt += 1; }
    }
    let mut done = 0usize;
    while qh < qt {
        let u = queue[qh];
        qh += 1;
        done += 1;
        for v in 0..n {
            if fwd[u] >> v & 1 == 1 {
                indeg[v] -= 1;
                if indeg[v] == 0 { queue[qt] = v; qt += 1; }
            }
        }
    }
    done == live
}

/// **The back-edge/halt disjointness test — REFUTED as a necessary condition.**
///
/// The idea, read off `loopInitialized`: `wh g B` fires its back edges on `g` and halts on
/// `¬g`, so within a loop the re-entering atoms and the terminating atoms are disjoint, and
/// embedding in a `seq` or `ite` only conjoins further.  If that survived to the automaton
/// level it would be a sound necessary condition for coverability, since covers preserve
/// halt masks and steps.
///
/// **It does not.**  1062 of the 156601 Thompson automata at K=4 fail it, so it is neither a
/// necessary condition nor a sound filter.  The reason is the approximation, not the idea:
/// "back edge" here is the dominator-based notion and "the loop body" is approximated by the
/// strongly connected component, and neither matches the syntactic loop that
/// `loop_halt_below_entry` quantifies over.  Nested and composed loops merge components, so
/// an edge that is a dominator-back-edge need not be a `wh` back edge guarded by `g`.
///
/// Kept because the measurement is the point: the Lean exit law
/// (`GkatLoopExit.halt_below_entry_of_cover`) is stated against a *known* loop target and is
/// true; this shows it does not lift to a criterion on a bare automaton by this route.
fn backedge_halt_disjoint<const NA: usize>(a: &Aut<NA>) -> bool {
    let k = a.k as usize;
    let n = k + 1;
    let mut succ = [0u32; MAXK + 1];
    for x in 0..NA {
        if a.it[x] != 0 { succ[0] |= 1 << a.it[x]; }
    }
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 { succ[i + 1] |= 1 << a.st[i][x]; }
        }
    }
    // reverse postorder + dominators, same as `reducible`
    let mut rpo = [u8::MAX; MAXK + 1];
    let mut order = [0usize; MAXK + 1];
    let mut nord = 0usize;
    {
        let mut stack = [(0usize, 0usize); MAXK + 2];
        let mut sp = 1usize;
        let mut entered = [false; MAXK + 1];
        stack[0] = (0, 0);
        entered[0] = true;
        while sp > 0 {
            let (u, mut i) = stack[sp - 1];
            let mut pushed = false;
            while i < n {
                if succ[u] >> i & 1 == 1 && !entered[i] {
                    entered[i] = true;
                    stack[sp - 1].1 = i + 1;
                    stack[sp] = (i, 0);
                    sp += 1;
                    pushed = true;
                    break;
                }
                i += 1;
            }
            if !pushed { stack[sp - 1].1 = n; order[nord] = u; nord += 1; sp -= 1; }
        }
    }
    for i in 0..nord { rpo[order[nord - 1 - i]] = i as u8; }
    let mut pred = [0u32; MAXK + 1];
    for u in 0..n {
        for v in 0..n {
            if succ[u] >> v & 1 == 1 { pred[v] |= 1 << u; }
        }
    }
    let mut idom = [u8::MAX; MAXK + 1];
    idom[0] = 0;
    let mut changed = true;
    while changed {
        changed = false;
        for t in 0..nord {
            let u = order[nord - 1 - t];
            if u == 0 || rpo[u] == u8::MAX { continue; }
            let mut new = u8::MAX;
            for p in 0..n {
                if pred[u] >> p & 1 != 1 || rpo[p] == u8::MAX || idom[p] == u8::MAX { continue; }
                new = if new == u8::MAX { p as u8 } else {
                    let (mut x, mut y) = (new as usize, p);
                    while x != y {
                        while rpo[x] > rpo[y] { x = idom[x] as usize; }
                        while rpo[y] > rpo[x] { y = idom[y] as usize; }
                    }
                    x as u8
                };
            }
            if new != u8::MAX && idom[u] != new { idom[u] = new; changed = true; }
        }
    }
    // mutual reachability on core states, for "same component as u"
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 { r[i] |= 1 << (a.st[i][x] - 1); }
        }
    }
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 { r[i] |= rm; }
        }
    }
    for u in 0..k {
        for x in 0..NA {
            let tgt = a.st[u][x];
            if tgt == 0 { continue; }
            let v = tgt as usize; // node index in the dominator graph
            // back edge?  v dominates u+1
            let mut y = u + 1;
            let mut dom = false;
            loop {
                if y == v { dom = true; break; }
                if y == 0 { break; }
                let ny = idom[y];
                if ny == u8::MAX || ny as usize == y { break; }
                y = ny as usize;
            }
            if !dom { continue; }
            // does any state of u's component halt at atom x?
            for w in 0..k {
                let same = w == u || (r[u] >> w & 1 == 1 && r[w] >> u & 1 == 1);
                if same && a.hl[w] >> x & 1 == 1 { return false; }
            }
        }
    }
    true
}

/// A compact structural fingerprint, for separating the automata a Thompson automaton can
/// cover from the ones it cannot. Guessing the invariant has failed twice; this measures it.
fn features<const NA: usize>(a: &Aut<NA>) -> [u32; 10] {
    let k = a.k as usize;
    let mut r = [0u16; MAXK];
    for i in 0..k {
        for x in 0..NA {
            if a.st[i][x] != 0 { r[i] |= 1 << (a.st[i][x] - 1); }
        }
    }
    let adj = r;
    for m in 0..k {
        let rm = r[m];
        for i in 0..k {
            if r[i] >> m & 1 == 1 { r[i] |= rm; }
        }
    }
    let mut comp = [usize::MAX; MAXK];
    let mut ncomp = 0usize;
    let mut maxscc = 0usize;
    for i in 0..k {
        if comp[i] != usize::MAX { continue; }
        comp[i] = ncomp;
        let mut sz = 1;
        for j in (i + 1)..k {
            if comp[j] == usize::MAX && r[i] >> j & 1 == 1 && r[j] >> i & 1 == 1 {
                comp[j] = ncomp;
                sz += 1;
            }
        }
        if sz > maxscc { maxscc = sz; }
        ncomp += 1;
    }
    let cyclic = (0..k).filter(|&i| r[i] >> i & 1 == 1).count();
    let mut cyclens: Vec<u32> = Vec::new();
    for i in 0..k {
        if r[i] >> i & 1 != 1 { continue; }
        let mut dist = [u32::MAX; MAXK];
        let mut q = VecDeque::new();
        for j in 0..k {
            if adj[i] >> j & 1 == 1 && dist[j] == u32::MAX { dist[j] = 1; q.push_back(j); }
        }
        while let Some(u) = q.pop_front() {
            if u == i { break; }
            for j in 0..k {
                if adj[u] >> j & 1 == 1 && dist[j] == u32::MAX {
                    dist[j] = dist[u] + 1;
                    q.push_back(j);
                }
            }
        }
        if dist[i] != u32::MAX { cyclens.push(dist[i]); }
    }
    let periods = scc_periods(a);
    let g = periods.iter().fold(0u32, |acc, &c| gcd_u32(acc, c));
    let lmax = periods.iter().copied().max().unwrap_or(0);
    let lmin = cyclens.iter().copied().min().unwrap_or(0);
    let halting = (0..k).filter(|&i| a.hl[i] != 0).count();
    let halt_on_cycle = (0..k).filter(|&i| a.hl[i] != 0 && r[i] >> i & 1 == 1).count();
    let full = (1u8 << NA) - 1;
    let fullhalt_cycle = (0..k)
        .filter(|&i| a.hl[i] == full && r[i] >> i & 1 == 1).count();
    let hs = halt_shape(a);
    [ncomp as u32, maxscc as u32, cyclic as u32, g, lmin, lmax,
     halt_on_cycle as u32, hs[0], hs[1], hs[2]]
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
        let mut overs = 0u64;    // ... and itself COVERS a Thompson automaton
        let mut overs_ok = 0u64; // ... and is covered too (the cofinality hypothesis holds)
        let mut red_direct = 0u64; // ... and reducible
        let mut fsum = [0u64; 10]; // feature sums for the *directly covered* control group
        let mut resist: Vec<(Aut<NA>, bool)> = Vec::new();
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
            let over0 = cands.iter().any(|&n| covers(&a, &list[n]));
            if over0 { overs += 1; }
            if cands.iter().any(|&n| covers(&list[n], &a)) {
                direct += 1;
                if over0 {
                    overs_ok += 1;
                    if reducible(&a) { red_direct += 1; }
                    let f = features(&a);
                    for i in 0..10 { fsum[i] += f[i] as u64; }
                }
                continue;
            }
            // Does `a` COVER a Thompson automaton?  Under Stallings' correspondence that
            // means pi_1(a) sits inside a Thompson subgroup — the situation a pullback is
            // always in, since P -> e is a cover.  Splitting the residue on this separates
            // "arbitrary automaton" from "the shape the programme has to handle".
            let over = cands.iter().any(|&n| covers(&a, &list[n]));
            resist.push((a, over));
            let _ = over;
        }
        (tot, dead, bisim, direct, overs, overs_ok, red_direct, fsum, resist)
    }).reduce(|| (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, [0u64; 10], Vec::new()), |mut x, y| {
        x.0 += y.0; x.1 += y.1; x.2 += y.2; x.3 += y.3; x.4 += y.4; x.5 += y.5; x.6 += y.6;
        for i in 0..10 { x.7[i] += y.7[i]; }
        x.8.extend(y.8); x
    });

    let (tot, dead, bisim, direct, overs, overs_ok, red_direct, fsum, resist) = acc;
    println!("  canonical fully reachable automata : {tot}");
    println!("  [t] expansion scan done");
    println!("  dropped as dead / null-language    : {dead}");
    println!("  productive AND bisimilar to an exp : {bisim}");
    println!("  DIRECTLY covered by an expression  : {direct}");
    println!("  not directly covered               : {}", resist.len());
    println!("  COVER a Thompson automaton (hyp.)  : {overs}");
    println!("    ... of those, covered directly   : {overs_ok}");
    println!("    ... of THOSE, reducible          : {red_direct}   <- the control group");

    // the ones that need refinement: same three moves as the pullback test
    // deeper and wider than the pullback test: the residue here is small enough that the
    // search can afford it, and depth is the only lever left once K is out of reach
    let rounds: u32 = std::env::var("EXPAND_ROUNDS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(4);
    let cap: usize = std::env::var("EXPAND_CAP").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(200_000);
    // Only the hypothesis class is searched.  An automaton that covers no Thompson automaton
    // is outside `ThompsonCofinal` and cannot refute it however the search turns out, so
    // spending the refinement budget there buys nothing — at kmax=4 it is the difference
    // between 166 searches and 8404.  The skipped count is reported, not silently dropped.
    let hyp: Vec<&(Aut<NA>, bool)> = resist.iter().filter(|(_, o)| *o).collect();
    println!("  refinement search: {rounds} rounds, frontier cap {cap}, \
on the {} in the hypothesis class ({} outside it, not searched)",
        hyp.len(), resist.len() - hyp.len());

    // The search used to be `for p { for candidate { rounds } }`, parallel over `p` alone.
    // Four things were wrong with that, in increasing order of cost.
    //
    //   * **Load imbalance.**  Work stealing cannot rescue 166 items whose costs differ by
    //     orders of magnitude — one thread grinds while the rest sit idle.
    //   * **No early exit across candidates.**  Once one candidate covered `p`, every other
    //     candidate for that `p` was wasted; nothing told them to stop.
    //   * **No sharing.**  Refinement variants overlap almost entirely, so boxed trees
    //     rebuilt, re-hashed and re-evaluated the same subterm once per variant containing
    //     it.  `Pool` interns terms and computes each one's automaton at intern time.
    //   * **The closure was recomputed per pair.**  A candidate's refinement closure does
    //     not depend on which `p` it is being tested against — yet it was regrown 21028
    //     times instead of once per distinct candidate.  Grouping by candidate also means
    //     `canon` runs once per distinct term rather than once per (term, p).
    use std::sync::atomic::{AtomicBool, Ordering};
    let found: Vec<AtomicBool> = (0..hyp.len()).map(|_| AtomicBool::new(false)).collect();
    let mut by_cand: FxMap<u32, Vec<usize>> = FxMap::default();
    for (i, (p, _)) in hyp.iter().enumerate() {
        for &n in by_beh[&behaviour(p)].iter() {
            by_cand.entry(n as u32).or_default().push(i);
        }
    }
    let cand_list: Vec<(u32, Vec<usize>)> = by_cand.into_iter().collect();
    // The period law as a filter: sound, and cheaper than the `covers` BFS it guards.
    // Hoisted so each target's periods are computed once, and each candidate term's once —
    // not once per (term, target) pair.
    let pperiods: Vec<Vec<u32>> = hyp.iter().map(|(p, _)| scc_periods(p)).collect();
    println!("    {} distinct candidates over {} (automaton, candidate) pairs",
        cand_list.len(), cand_list.iter().map(|c| c.1.len()).sum::<usize>());
    cand_list.par_iter().for_each(|(n, ps)| {
        if ps.iter().all(|&i| found[i].load(Ordering::Relaxed)) { return; }
        let mut pool = Pool::<NA>::new();
        let root = pool.of_prov(list, prov, *n);
        let mut frontier = vec![root];
        let mut seen: FxSet<u32> = FxSet::default();
        seen.insert(root);
        let mut tried: FxSet<Aut<NA>> = FxSet::default();
        for _ in 0..rounds {
            let mut next: Vec<u32> = Vec::new();
            for &t in frontier.iter() {
                refinements(&mut pool, t, nguards, true, true, 3, 3, &mut next);
            }
            let mut keep: Vec<u32> = Vec::with_capacity(next.len());
            for t in next {
                if !seen.insert(t) { continue; }
                if let Some(v) = pool.aut(t) {
                    if let Some(c) = canon(&v) {
                        if tried.insert(c) {
                            let cper = scc_periods(&c);
                            for &i in ps.iter() {
                                if found[i].load(Ordering::Relaxed) { continue; }
                                let p = &hyp[i].0;
                                // a cover is onto, so fewer states than `p` cannot work
                                if c.k < p.k { continue; }
                                let dp = &pperiods[i];
                                if !dp.is_empty()
                                    && !cper.iter().all(|dh| dp.iter().any(|d| dh % d == 0)) {
                                    continue;
                                }
                                if covers(&c, p) { found[i].store(true, Ordering::Relaxed); }
                            }
                        }
                    }
                }
                keep.push(t);
            }
            frontier = keep;
            if frontier.len() > cap { frontier.truncate(cap); }
            if ps.iter().all(|&i| found[i].load(Ordering::Relaxed)) { return; }
        }
    });
    let rescued: Vec<bool> = found.iter().map(|b| b.load(Ordering::Relaxed)).collect();
    let nres = rescued.iter().filter(|b| !**b).count();
    println!("  of those, rescued by refinement    : {}", rescued.len() - nres);
    println!("  RESIST *within the hypothesis*     : {nres}   <- refutes ThompsonCofinal if > 0");
    // ---- what separates them?
    {
        let names = ["sccs", "maxscc", "cyclic", "gcdperiod", "mincyc", "maxperiod",
                     "haltcyc", "haltmasks", "maskclash", "haltlevels"];
        let bad: Vec<[u32; 10]> = hyp.iter().zip(rescued.iter())
            .filter(|(_, ok)| !**ok).map(|((p, _), _)| features(p)).collect();
        let good: Vec<[u32; 10]> = hyp.iter().zip(rescued.iter())
            .filter(|(_, ok)| **ok).map(|((p, _), _)| features(p)).collect();
        let redbad = hyp.iter().zip(rescued.iter())
            .filter(|(_, ok)| !**ok).filter(|((p, _), _)| reducible(p)).count();
        let redgood = hyp.iter().zip(rescued.iter())
            .filter(|(_, ok)| **ok).filter(|((p, _), _)| reducible(p)).count();
        println!("\n  REDUCIBLE: {redbad} / {} uncovered, {redgood} / {} rescued",
            bad.len(), good.len());
        let bhbad = hyp.iter().zip(rescued.iter())
            .filter(|(_, ok)| !**ok).filter(|((p, _), _)| backedge_halt_disjoint(p)).count();
        let bhgood = hyp.iter().zip(rescued.iter())
            .filter(|(_, ok)| **ok).filter(|((p, _), _)| backedge_halt_disjoint(p)).count();
        println!("  BACKEDGE/HALT DISJOINT: {bhbad} / {} uncovered, {bhgood} / {} rescued",
            bad.len(), good.len());
        println!("\n  FEATURE SEPARATION (hypothesis class only)");
        // The proper control is every DIRECTLY covered member of the hypothesis class, not
        // just the ones that happened to need refinement — conditioning on "needed
        // refinement" makes both groups unusual and can manufacture a difference.
        println!("    {:<12} {:>14} {:>14} {:>16}",
            "feature", "uncovered", "rescued", "direct-covered");
        for i in 0..10 {
            let mb = if bad.is_empty() { 0.0 } else {
                bad.iter().map(|f| f[i] as f64).sum::<f64>() / bad.len() as f64 };
            let mg = if good.is_empty() { 0.0 } else {
                good.iter().map(|f| f[i] as f64).sum::<f64>() / good.len() as f64 };
            let md = if overs_ok == 0 { 0.0 } else { fsum[i] as f64 / overs_ok as f64 };
            println!("    {:<12} {:>14.3} {:>14.3} {:>16.3}", names[i], mb, mg, md);
        }
        // exact value sets, which matter more than means for small integers
        for i in 0..10 {
            let mut vb: Vec<u32> = bad.iter().map(|f| f[i]).collect();
            vb.sort_unstable(); vb.dedup();
            let mut vg: Vec<u32> = good.iter().map(|f| f[i]).collect();
            vg.sort_unstable(); vg.dedup();
            let only_bad: Vec<u32> = vb.iter().copied().filter(|v| !vg.contains(v)).collect();
            let only_good: Vec<u32> = vg.iter().copied().filter(|v| !vb.contains(v)).collect();
            if !only_bad.is_empty() || !only_good.is_empty() {
                println!("    {:<12} uncovered-only {:?}   covered-only {:?}",
                    names[i], only_bad, only_good);
            }
        }
    }

    let (mut isp, mut iso) = (0usize, 0usize);
    for ((p, over), ok) in hyp.iter().zip(rescued.iter()) {
        if !*ok {
            let ispull = pulls.contains(p);
            if ispull { isp += 1; }
            if *over { iso += 1; }
            println!("    UNCOVERED pullback={ispull} coversThompson={over} \
k={} ih={} it={:?} hl={:?} st={:?}",
                p.k, p.ih, &p.it[..], &p.hl[..p.k as usize], &p.st[..p.k as usize]);
        }
    }
    println!("  of the uncovered, ARE a crux pullback     : {isp}");
    println!("  of the uncovered, COVER a Thompson autom. : {iso}");
}

// ---------------------------------------------------------------- driver

fn run<const NA: usize>(maxk: usize, pairk: usize) {
    let nguards = 1u8 << NA;
    // Phase timing. The last two optimisation passes both found their biggest win in a
    // measurement rather than a guess, so measure first.
    let t0 = std::time::Instant::now();
    let mut mark = t0;
    let mut phase = |name: &str, mark: &mut std::time::Instant| {
        let now = std::time::Instant::now();
        println!("  [t] {name}: {:.1}s", now.duration_since(*mark).as_secs_f64());
        *mark = now;
    };
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
    phase("closure", &mut mark);
    {
        // Sanity for the predicate: a structured program's flow graph must be reducible.
        // If any syntax-generated automaton is irreducible, the test is wrong, not the theory.
        let bad = list.par_iter().filter(|a| !reducible(a)).count();
        println!("  irreducible Thompson automata (must be 0): {bad}");
        let bh = list.par_iter().filter(|a| !backedge_halt_disjoint(a)).count();
        println!("  Thompson automata failing backedge/halt disjointness (must be 0): {bh}");
    }
    phase("reducibility sweep", &mut mark);
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
    //
    // This was a sequential loop over all 56M closure members, each computing a partition
    // refinement — 106s of a 188s run, on one core, while everything around it used eight.
    // The map itself has to be built serially, but the expensive half does not: compute the
    // keys in parallel a chunk at a time, then insert.  Chunking keeps the transient key
    // buffer bounded instead of materialising 56M of them at once.
    // Preallocated: a map growing from empty to 36.6M keys rehashes about twenty-five times,
    // and rehashing dominates — parallelising the key computation alone only bought 10%.
    let mut by_beh: FxMap<Vec<u8>, Vec<usize>> =
        FxMap::with_capacity_and_hasher(list.len(), FxBuild);
    {
        const CHUNK: usize = 1 << 22;
        let mut base = 0usize;
        while base < list.len() {
            let hi = (base + CHUNK).min(list.len());
            let keys: Vec<Vec<u8>> = list[base..hi].par_iter().map(behaviour).collect();
            for (i, k) in keys.into_iter().enumerate() {
                by_beh.entry(k).or_default().push(base + i);
            }
            base = hi;
        }
    }
    println!("  behaviour classes: {}", by_beh.len());
    phase("by_beh", &mut mark);

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
    // Controlled Node Splitting is the classical route from an irreducible flow graph to a
    // reducible one, and it works by *duplicating nodes* — which is precisely the
    // guard-split duplication move.  If that is what is going on here, "the pullback is not
    // itself syntax-generated" should coincide with "the pullback is irreducible".
    {
        let (mut tr, mut tn, mut nr, mut nn) = (0usize, 0usize, 0usize, 0usize);
        for r in pb.iter() {
            if !r.3 { continue; }
            if let Some(p) = pullback(&list[r.0], &list[r.1]).and_then(|q| canon(&q)) {
                match (r.4, reducible(&p)) {
                    (true, true) => tr += 1,
                    (true, false) => tn += 1,
                    (false, true) => nr += 1,
                    (false, false) => nn += 1,
                }
            }
        }
        // Kosaraju: a program is reducible to a structured program *without adding
        // variables* iff it has no loop with two distinct exits.  GKAT has neither extra
        // variables nor `break`, so the residue should be exactly the two-exit loops.
        for r in pb.iter() {
            if !r.3 || r.4 { continue; }
            if let Some(p) = pullback(&list[r.0], &list[r.1]).and_then(|q| canon(&q)) {
                if !reducible(&p) { continue; }
                let f = features(&p);
                println!("    RESIDUE |P|={} ih={} it={:?} hl={:?} st={:?}  haltcyc={} \
periods={:?}", p.k, p.ih, &p.it[..], &p.hl[..p.k as usize], &p.st[..p.k as usize],
                    f[6], scc_periods(&p));
            }
        }
        println!("\n  is-Thompson x reducible:");
        println!("    Thompson     & reducible {tr:>4}    Thompson     & irreducible {tn:>4}");
        println!("    NOT Thompson & reducible {nr:>4}    NOT Thompson & irreducible {nn:>4}");
    }
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
                // The period law says every actual cover must pass the divisibility filter.
                // It is a theorem (a covering sends an n-cycle to a closed n-walk), so a
                // violation here is a bug in the implementation, not a discovery.
                let viol = cands.iter()
                    .any(|&n| covers(&list[n], &p) && !period_compatible(&list[n], &p));
                if viol { println!("  PERIOD LAW VIOLATED (bug) at |P|={}", p.k); }
                (i, j, p.k, found)
            }
        })
        .collect();
    let s_dec = solv.iter().filter(|r| r.2 > 0 && (r.2 as usize) <= maxk).count();
    let s_hit = solv.iter().filter(|r| r.3).count();
    phase("pairs + pullbacks", &mut mark);
    // ---- GATE for the synthesis plan.
    // If the cover is built by inducting on one side with the other side's position as a
    // parameter, the loop case emits a degree-d cyclic cover, and the period law says which
    // d.  So: for each covered pullback, how much longer is the covering automaton's cycle
    // than the pullback's?  Those ratios are exactly the degrees `cyclicCover` must reach.
    {
        let mut pairs: FxMap<(u32, u32), usize> = FxMap::default();
        for r in solv.iter().filter(|r| r.3) {
            if let Some(p) = pullback(&list[r.0], &list[r.1]).and_then(|p| canon(&p)) {
                let pp = scc_periods(&p).into_iter().max().unwrap_or(0);
                let cands = &by_beh[&behaviour(&p)];
                if let Some(b) = cands.iter().filter(|&&n| covers(&list[n], &p))
                    .map(|&n| scc_periods(&list[n]).into_iter().max().unwrap_or(0))
                    .min() {
                    *pairs.entry((pp, b)).or_default() += 1;
                }
            }
        }
        let mut ks: Vec<((u32, u32), usize)> = pairs.into_iter().collect();
        ks.sort();
        println!("\n  (pullback period, min covering period) -> count:");
        for ((pp, b), c) in ks.iter() {
            println!("    ({pp}, {b})  x{c}");
        }
        // The real gate.  The synthesis inducts on ONE side, so the degree its loop case must
        // emit is measured against *that side's* period, not against the pullback's.  The
        // prediction from the fibre-product-of-covers law is period(P) = lcm(period e,
        // period f) — i.e. the required degree is lcm/period(e), computable from the two
        // programs alone, with no search.
        let mut lcmstat: FxMap<(u32, u32, u32, bool), usize> = FxMap::default();
        for r in solv.iter() {
            if let Some(p) = pullback(&list[r.0], &list[r.1]).and_then(|p| canon(&p)) {
                let pe = scc_periods(&list[r.0]).into_iter().max().unwrap_or(0);
                let pf = scc_periods(&list[r.1]).into_iter().max().unwrap_or(0);
                let pp = scc_periods(&p).into_iter().max().unwrap_or(0);
                let g = gcd_u32(pe, pf);
                let l = if g == 0 { 0 } else { pe / g * pf };
                lcmstat.entry((pe, pf, pp, pp == l)).and_modify(|c| *c += 1).or_insert(1);
            }
        }
        let mut ls: Vec<((u32, u32, u32, bool), usize)> = lcmstat.into_iter().collect();
        ls.sort();
        let agree: usize = ls.iter().filter(|((_, _, _, ok), _)| *ok).map(|(_, c)| c).sum();
        let total: usize = ls.iter().map(|(_, c)| c).sum();
        println!("\n  GATE: period(P) = lcm(period e, period f)?  {agree} / {total}");
        for ((pe, pf, pp, ok), c) in ls.iter() {
            if !ok { println!("    MISMATCH e={pe} f={pf} P={pp}  x{c}"); }
        }
    }
    // ---- GATE 2, the decisive one for `RefinementSuffices`.
    // Every measurement so far has drawn the covering automaton from the whole behaviour
    // class — *any* program with the right behaviour.  But the synthesis, and the Lean
    // statement `GkatRefines.RefinementSuffices`, need the cover to be a refinement of `e`
    // (or `f`) ITSELF.  That is strictly stronger and has never been tested.
    {
        let rounds: u32 = std::env::var("G2_ROUNDS").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(3);
        let cap: usize = std::env::var("G2_CAP").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(20000);
        let res: Vec<bool> = solv.par_iter().map(|r| {
            let p = match pullback(&list[r.0], &list[r.1]).and_then(|q| canon(&q)) {
                Some(q) => q, None => return false,
            };
            for &n in [r.0, r.1].iter() {
                let mut pool = Pool::<NA>::new();
                let root = pool.of_prov(&list, &prov, n as u32);
                if let Some(a) = pool.aut(root) {
                    if let Some(c) = canon(&a) { if covers(&c, &p) { return true; } }
                }
                let mut frontier = vec![root];
                let mut seen: FxSet<u32> = FxSet::default();
                seen.insert(root);
                for _ in 0..rounds {
                    let mut next: Vec<u32> = Vec::new();
                    for &t in frontier.iter() {
                        refinements(&mut pool, t, nguards, true, true, 3, 3, &mut next);
                    }
                    let mut keep: Vec<u32> = Vec::new();
                    for t in next {
                        if !seen.insert(t) { continue; }
                        if let Some(a) = pool.aut(t) {
                            if let Some(c) = canon(&a) {
                                if c.k >= p.k && covers(&c, &p) { return true; }
                            }
                        }
                        keep.push(t);
                    }
                    frontier = keep;
                    if frontier.len() > cap { frontier.truncate(cap); }
                }
            }
            false
        }).collect();
        let ok = res.iter().filter(|b| **b).count();
        println!("\n  GATE 2 (RefinementSuffices): a refinement of e or f covers the \
pullback: {ok} / {}", res.len());
    }
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
    {
        // Cross-tabulate reducibility against solvability, rather than reporting a rate.
        let (mut rr, mut rn, mut ir, mut inn) = (0usize, 0usize, 0usize, 0usize);
        for r in solv.iter() {
            if let Some(p) = pullback(&list[r.0], &list[r.1]).and_then(|p| canon(&p)) {
                match (reducible(&p), r.3) {
                    (true, true) => rr += 1,
                    (true, false) => rn += 1,
                    (false, true) => ir += 1,
                    (false, false) => inn += 1,
                }
            }
        }
        println!("\n  pullback reducible x covered:");
        println!("    reducible   & covered {rr:>4}   reducible   & NOT {rn:>4}");
        println!("    irreducible & covered {ir:>4}   irreducible & NOT {inn:>4}");
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
                let mut pool = Pool::<NA>::new();
                let t = pool.of_prov(&list, &prov, n as u32);
                let base = match pool.aut(t) { Some(a) => a, None => return (0, 0) };
                let bb = behaviour(&base);
                let mut v = Vec::new();
                cyclic_variants(&mut pool, t, 3, &mut v);
                let (mut c, mut b) = (0, 0);
                for r in v.iter() {
                    if let Some(a) = pool.aut(*r) {
                        c += 1;
                        if behaviour(&a) != bb { b += 1; }
                    }
                }
                (c, b)
            })
            .reduce(|| (0, 0), |x, y| (x.0 + y.0, x.1 + y.1));
        phase("pullback refinement table", &mut mark);
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
                let mut pool = Pool::<NA>::new();
                let root = pool.of_prov(&list, &prov, n as u32);
                let mut frontier = vec![root];
                let mut seen: FxSet<u32> = FxSet::default();
                seen.insert(root);
                for _ in 0..rounds {
                    let mut next: Vec<u32> = Vec::new();
                    for &t in frontier.iter() {
                        refinements(&mut pool, t, nguards, mode_unr, mode_dup, mode_cyc, 3,
                            &mut next);
                    }
                    let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                    for t in next {
                        if !seen.insert(t) { continue; }
                        if let Some(a) = pool.aut(t) {
                            if a.k as usize > biggest { biggest = a.k as usize; }
                            if let Some(c) = canon(&a) {
                                if covers(&c, &p) { found = true; break; }
                            }
                        }
                        keep.push(t);
                    }
                    if found { break 'cand; }
                    frontier = keep;
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

    if std::env::var("PADDED").is_ok() {
        // The completeness chain forms exactly ONE pullback, and not a general one: the
        // kernel pair of the behavioural quotient of two PADDED programs
        //     padOne  e f = if 1 then e else f      padZero e f = if 0 then e else f
        // which share a core.  Both legs of the span are the same map `rep`, so the object is
        // the language-equivalence relation presented as an automaton.  This sweep measures
        // that class, which no earlier run did — every previous number was for arbitrary
        // pullbacks of arbitrary equivalent pairs.
        let full: u8 = ((1u16 << NA) - 1) as u8;
        let mut total = 0usize;
        let mut covered = 0usize;
        let mut nested_ok = 0usize;
        let mut uncovered: Vec<Aut<NA>> = Vec::new();
        let (mut pf_total, mut pf_first, mut pf_second, mut pf_either, mut pf_pairs) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut pf_branch = 0usize;
        let require_total = std::env::var("PAD_TOTAL").is_ok();
        let mut skipped_nontotal = 0usize;
        for &(i, j) in crux.iter() {
            let a1 = match a_ite(full, &list[i], &list[j]) { Some(a) => a, None => continue };
            let a0 = match a_ite(0, &list[i], &list[j]) { Some(a) => a, None => continue };
            if require_total && !(total_aut(&a0) && total_aut(&a1)) {
                skipped_nontotal += 1;
                continue;
            }
            let p = match pullback(&a0, &a1).and_then(|q| canon(&q)) {
                Some(q) => q, None => continue,
            };
            total += 1;
            {
                let (f1, f2, n) = partner_functional(&a0, &a1);
                pf_total += 1;
                if f1 { pf_first += 1; }
                if f2 { pf_second += 1; }
                if f1 || f2 { pf_either += 1; }
                if partner_functional_perbranch(&a0, &a1) { pf_branch += 1; }
                pf_pairs += n;
            }
            if nested(&p) { nested_ok += 1; }
            let mut found = false;
            if let Some(cands) = by_beh.get(&behaviour(&p)) {
                for &n in cands.iter() {
                    if covers(&list[n], &p) { found = true; break; }
                }
            }
            if found { covered += 1; } else { uncovered.push(p); }
        }
        println!("\nPADDED KERNEL PAIRS: {total}   (skipped non-total: {skipped_nontotal})");
        println!("  covered directly : {covered}");
        println!("  nested           : {nested_ok} / {total}   (Lean says this must be total)");
        println!("  uncovered directly: {}", uncovered.len());
        // VALIDATE THE ORACLE against ground truth before using it for anything.  Every
        // automaton in the pool is Thompson by construction, so the oracle must accept it;
        // and a <=K-state automaton absent from the pool is not Thompson, so it must reject.
        if std::env::var("PAD_ORACLE").is_ok() {
            let guards: Vec<u8> = (0..(1u8 << NA)).collect();
            let depth = std::env::var("PAD_ORACLE_DEPTH").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(8);
            let nsample = std::env::var("PAD_ORACLE_N").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(400);
            let mut memo: FxMap<Aut<NA>, bool> = FxMap::default();
            let mut pos = 0usize;
            let mut posn = 0usize;
            let mut byk = [(0usize, 0usize); MAXK + 1];
            let step = (list.len() / nsample.max(1)).max(1);
            for (i, a) in list.iter().enumerate() {
                if i % step != 0 { continue; }
                if a.k as usize > 6 { continue; }
                posn += 1;
                let ok = is_thompson(a, &guards, depth, &mut memo);
                if ok { pos += 1; }
                byk[a.k as usize].1 += 1;
                if ok { byk[a.k as usize].0 += 1; }
            }
            // negatives: pullbacks with <= maxk states that are absent from the pool
            let mut neg = 0usize;
            let mut negn = 0usize;
            for p in uncovered.iter() {
                if p.k as usize > maxk { continue; }
                let c = match canon(p) { Some(c) => c, None => continue };
                let inpool = by_beh.get(&behaviour(&c))
                    .map(|v| v.iter().any(|&n| list[n] == c)).unwrap_or(false);
                if inpool { continue; }
                negn += 1;
                if negn > 300 { break; }
                if !is_thompson(&c, &guards, depth, &mut memo) { neg += 1; }
            }
            // self-test on hand-built automata whose provenance is known
            {
                let act = a_act::<NA>();
                let t1 = a_test::<NA>(((1u16 << NA) - 1) as u8);
                let s2 = a_seq(&act, &act);
                let i2 = a_ite(1, &act, &act);
                let w1 = a_wh(1, &act);
                println!("    self-test: act={} test={} seq(a,a)={} ite(a,a)={} wh(a)={}",
                    is_thompson(&act, &guards, depth, &mut memo),
                    is_thompson(&t1, &guards, depth, &mut memo),
                    s2.as_ref().map(|x| is_thompson(x, &guards, depth, &mut memo))
                        .unwrap_or(false),
                    i2.as_ref().map(|x| is_thompson(x, &guards, depth, &mut memo))
                        .unwrap_or(false),
                    is_thompson(&w1, &guards, depth, &mut memo));
                if let Some(x) = s2.as_ref() { println!("    seq(a,a): k={} ih={} it={:?} hl0={} st0={:?} hl1={} st1={:?}",
                    x.k, x.ih, &x.it[..], x.hl[0], &x.st[0][..], x.hl[1], &x.st[1][..]); }
            }
            {
                // the chain from the traced failure: a;0 , a;a;0 , a;a;a;0
                let mut x1 = Aut::<NA>::blank();
                x1.k = 1; x1.ih = 0; for y in 0..NA { x1.it[y] = 1; }
                x1.hl[0] = 0; for y in 0..NA { x1.st[0][y] = 0; }
                let mut x2 = Aut::<NA>::blank();
                x2.k = 2; x2.ih = 0; for y in 0..NA { x2.it[y] = 1; }
                x2.hl[0] = 0; for y in 0..NA { x2.st[0][y] = 2; }
                x2.hl[1] = 0; for y in 0..NA { x2.st[1][y] = 0; }
                let t0 = a_test::<NA>(0);
                let act = a_act::<NA>();
                println!("    chain: test0={} act={} a;0={} a;a;0={}",
                    is_thompson(&t0, &guards, depth, &mut memo),
                    is_thompson(&act, &guards, depth, &mut memo),
                    is_thompson(&x1, &guards, depth, &mut memo),
                    is_thompson(&x2, &guards, depth, &mut memo));
                if let Some(z) = a_seq(&act, &t0) {
                    print!("    a_seq(act,test0): k={} ih={} it={:?}", z.k, z.ih, &z.it[..]);
                    for i in 0..z.k as usize { print!(" | hl{}={} st{}={:?}", i, z.hl[i], i, &z.st[i][..]); }
                    println!("  canon_eq_x1={}", canon(&z) == canon(&x1));
                }
            }
            // show one small failure in full, with what each constructor branch found
            {
                let mut shown = 0;
                for a in list.iter() {
                    if a.k != 3 || shown >= 1 { continue; }
                    if is_thompson(a, &guards, depth, &mut memo) { continue; }
                    shown += 1;
                    print!("    FAIL k=3 ih={} it={:?}", a.ih, &a.it[..]);
                    for x in 0..3 { print!(" | hl{}={} st{}={:?}", x, a.hl[x], x, &a.st[x][..]); }
                    println!();
                    let full: u16 = 7;
                    for m in 1u16..8 {
                        let comp = full & !m;
                        if comp == 0 { continue; }
                        println!("      mask={m:03b} Lclosed={} Rclosed={}",
                            sub_closed(a, m), sub_closed(a, comp));
                    }
                    let g = (!a.ih) & 3;
                    println!("      wh: forced g={g}, it ok on non-g = {}",
                        (0..NA).all(|y| bit_set(g, y) || a.it[y] == 0));
                }
            }
            println!("  ORACLE VALIDATION (depth {depth}):");
            println!("    pool automata accepted   : {pos} / {posn}   (must be all)");
            for j in 0..=6 {
                if byk[j].1 > 0 { println!("      k={j}: {} / {}", byk[j].0, byk[j].1); }
            }
            println!("    non-pool <=K rejected    : {neg} / {negn}   (must be all)");
        }
        // THE TRUE RATE.  The two routes are independent and both incomplete, so neither
        // number alone is `ReachListCovered`.  Compute both per pullback and take the union.
        if std::env::var("PAD_UNION").is_ok() {
            let rounds = std::env::var("PAD_U_ROUNDS").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(3);
            let frcap = std::env::var("PAD_U_FRONTIER").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(60000);
            let mut direct = vec![false; uncovered.len()];
            let mut branch = vec![false; uncovered.len()];
            let mut explored_tot = 0usize;
            // --- route A: cover the pullback itself
            let mut groups: FxMap<Vec<u8>, Vec<usize>> = FxMap::default();
            for (i, p) in uncovered.iter().enumerate() {
                groups.entry(behaviour(p)).or_default().push(i);
            }
            for (beh, idxs) in groups.iter() {
                let seeds = match by_beh.get(beh) { Some(v) => v, None => continue };
                let mut pool = Pool::<NA>::new();
                let mut frontier: Vec<u32> = Vec::new();
                let mut seen: FxSet<u32> = FxSet::default();
                for &n in seeds.iter() {
                    let r = pool.of_prov(&list, &prov, n as u32);
                    if seen.insert(r) { frontier.push(r); }
                }
                for _ in 0..rounds {
                    let mut next: Vec<u32> = Vec::new();
                    for &t in frontier.iter() {
                        refinements(&mut pool, t, nguards, true, true, 3, 3, &mut next);
                    }
                    let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                    for t in next {
                        if !seen.insert(t) { continue; }
                        explored_tot += 1;
                        if let Some(a) = pool.aut(t) {
                            if let Some(c) = canon(&a) {
                                for &i in idxs.iter() {
                                    if !direct[i] && covers(&c, &uncovered[i]) { direct[i] = true; }
                                }
                            }
                        }
                        keep.push(t);
                    }
                    frontier = keep;
                    if frontier.len() > frcap { frontier.truncate(frcap); }
                    if idxs.iter().all(|&i| direct[i]) { break; }
                }
            }
            // --- route B: cover both branch parts
            let mut parts: Vec<Aut<NA>> = Vec::new();
            let mut index: FxMap<Aut<NA>, usize> = FxMap::default();
            let mut per: Vec<(usize, usize)> = Vec::new();
            for p in uncovered.iter() {
                match unshare_parts(p) {
                    None => per.push((usize::MAX, usize::MAX)),
                    Some((_, a, b)) => {
                        let mut ids = [usize::MAX; 2];
                        for (k, q) in [&a, &b].iter().enumerate() {
                            if q.k == 0 { continue; }
                            if let Some(c) = canon(q) {
                                let id = *index.entry(c.clone()).or_insert_with(|| {
                                    parts.push(c.clone()); parts.len() - 1 });
                                ids[k] = id;
                            }
                        }
                        per.push((ids[0], ids[1]));
                    }
                }
            }
            let mut pdone = vec![false; parts.len()];
            let mut pgroups: FxMap<Vec<u8>, Vec<usize>> = FxMap::default();
            for (i, q) in parts.iter().enumerate() {
                pgroups.entry(behaviour(q)).or_default().push(i);
            }
            for (beh, idxs) in pgroups.iter() {
                let seeds = match by_beh.get(beh) { Some(v) => v, None => continue };
                for &i in idxs.iter() {
                    if let Some(c) = canon(&parts[i]) {
                        if seeds.iter().any(|&n| list[n] == c) { pdone[i] = true; }
                    }
                }
                if idxs.iter().all(|&i| pdone[i]) { continue; }
                let mut pool = Pool::<NA>::new();
                let mut frontier: Vec<u32> = Vec::new();
                let mut seen: FxSet<u32> = FxSet::default();
                for &n in seeds.iter() {
                    let r = pool.of_prov(&list, &prov, n as u32);
                    if seen.insert(r) { frontier.push(r); }
                }
                for _ in 0..rounds {
                    let mut next: Vec<u32> = Vec::new();
                    for &t in frontier.iter() {
                        refinements(&mut pool, t, nguards, true, true, 3, 3, &mut next);
                    }
                    let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                    for t in next {
                        if !seen.insert(t) { continue; }
                        explored_tot += 1;
                        if let Some(a) = pool.aut(t) {
                            if let Some(c) = canon(&a) {
                                for &i in idxs.iter() {
                                    if !pdone[i] && covers(&c, &parts[i]) { pdone[i] = true; }
                                }
                            }
                        }
                        keep.push(t);
                    }
                    frontier = keep;
                    if frontier.len() > frcap { frontier.truncate(frcap); }
                    if idxs.iter().all(|&i| pdone[i]) { break; }
                }
            }
            for (i, &(x, y)) in per.iter().enumerate() {
                let ok = |j: usize| j == usize::MAX || pdone[j];
                if (x != usize::MAX || y != usize::MAX) && ok(x) && ok(y) { branch[i] = true; }
            }
            let da = direct.iter().filter(|&&b| b).count();
            let db = branch.iter().filter(|&&b| b).count();
            let un = (0..uncovered.len()).filter(|&i| direct[i] || branch[i]).count();
            let bo = (0..uncovered.len()).filter(|&i| direct[i] && branch[i]).count();
            println!("  UNION OF THE TWO ROUTES (rounds {rounds}, frontier {frcap}):");
            println!("    direct only  : {}", da - bo);
            println!("    branch only  : {}", db - bo);
            println!("    both         : {bo}");
            println!("    UNION        : {un} / {}", uncovered.len());
            println!("    NEITHER      : {} / {}", uncovered.len() - un, uncovered.len());
            println!("    explored     : {explored_tot}");
            // CONTROLLED COMPARISON.  Which features separate the residue from the covered
            // population?  Both groups are pullbacks of total instances, so the covered group
            // is a proper control — a rate here is only evidence relative to it.
            {
                let nei: Vec<usize> = (0..uncovered.len())
                    .filter(|&i| !direct[i] && !branch[i]).collect();
                let cov: Vec<usize> = (0..uncovered.len())
                    .filter(|&i| direct[i] || branch[i]).collect();
                let rate = |g: &Vec<usize>, f: &dyn Fn(&Aut<NA>) -> bool| -> f64 {
                    if g.is_empty() { return 0.0; }
                    100.0 * (g.iter().filter(|&&i| f(&uncovered[i])).count() as f64)
                        / (g.len() as f64)
                };
                let mean = |g: &Vec<usize>, f: &dyn Fn(&Aut<NA>) -> f64| -> f64 {
                    if g.is_empty() { return 0.0; }
                    g.iter().map(|&i| f(&uncovered[i])).sum::<f64>() / (g.len() as f64)
                };
                println!("  FEATURE SEPARATION  (residue {} vs covered {}):",
                    nei.len(), cov.len());
                let bools: [(&str, &dyn Fn(&Aut<NA>) -> bool); 4] = [
                    ("two-exit cycle", &|a: &Aut<NA>| two_exit_cycle(a).is_some()),
                    ("two-halt cycle", &|a: &Aut<NA>| two_halt_cycle(a).is_some()),
                    ("nested",         &|a: &Aut<NA>| nested(a)),
                    ("reducible",      &|a: &Aut<NA>| reducible(a)),
                ];
                for (name, f) in bools.iter() {
                    println!("    {:<16} residue {:>6.1}%   covered {:>6.1}%",
                        name, rate(&nei, *f), rate(&cov, *f));
                }
                println!("    {:<16} residue {:>6.2}    covered {:>6.2}", "states (mean)",
                    mean(&nei, &|a: &Aut<NA>| a.k as f64),
                    mean(&cov, &|a: &Aut<NA>| a.k as f64));
                for j in 0..10 {
                    let fr = mean(&nei, &|a: &Aut<NA>| features(a)[j] as f64);
                    let fc = mean(&cov, &|a: &Aut<NA>| features(a)[j] as f64);
                    if (fr - fc).abs() > 0.15 * (fc.abs().max(1.0)) {
                        println!("    feature[{j}]       residue {fr:>6.2}    covered {fc:>6.2}");
                    }
                }
            }
            println!("    => ReachListCovered holds for {} / {} = {:.1}%",
                total - (uncovered.len() - un), total,
                100.0 * ((total - (uncovered.len() - un)) as f64) / (total as f64));
        }
        // `ReachListCovered` is now the WHOLE obligation, and it is exactly this: is the
        // pullback (which the harness builds by BFS from the entry, so it IS the reachable
        // listing) covered by some Thompson automaton?  Measure it on every uncovered case,
        // grouping targets by behaviour so one closure serves a whole class.
        if std::env::var("PAD_FULLRESCUE").is_ok() {
            let rounds = std::env::var("PAD_FR_ROUNDS").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(3);
            let frcap = std::env::var("PAD_FR_FRONTIER").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(60000);
            let mut groups: FxMap<Vec<u8>, Vec<usize>> = FxMap::default();
            for (i, p) in uncovered.iter().enumerate() {
                groups.entry(behaviour(p)).or_default().push(i);
            }
            let mut cov = 0usize;
            let mut res = 0usize;
            let mut explored_tot = 0usize;
            let ngroups = groups.len();
            for (beh, idxs) in groups.iter() {
                let seeds = match by_beh.get(beh) { Some(v) => v, None => {
                    res += idxs.len(); continue; } };
                let mut hit = vec![false; idxs.len()];
                let mut pool = Pool::<NA>::new();
                let mut frontier: Vec<u32> = Vec::new();
                let mut seen: FxSet<u32> = FxSet::default();
                for &n in seeds.iter() {
                    let r = pool.of_prov(&list, &prov, n as u32);
                    if seen.insert(r) { frontier.push(r); }
                }
                for _ in 0..rounds {
                    let mut next: Vec<u32> = Vec::new();
                    for &t in frontier.iter() {
                        refinements(&mut pool, t, nguards, true, true, 3, 3, &mut next);
                    }
                    let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                    for t in next {
                        if !seen.insert(t) { continue; }
                        explored_tot += 1;
                        if let Some(a) = pool.aut(t) {
                            if let Some(c) = canon(&a) {
                                for (j, &i) in idxs.iter().enumerate() {
                                    if !hit[j] && covers(&c, &uncovered[i]) { hit[j] = true; }
                                }
                            }
                        }
                        keep.push(t);
                    }
                    frontier = keep;
                    if frontier.len() > frcap { frontier.truncate(frcap); }
                    if hit.iter().all(|&b| b) { break; }
                }
                for b in hit { if b { cov += 1; } else { res += 1; } }
            }
            println!("  REACHLISTCOVERED, measured on every uncovered pullback:");
            println!("    behaviour groups : {ngroups}");
            println!("    covered          : {cov} / {}", uncovered.len());
            println!("    RESISTING        : {res} / {}", uncovered.len());
            println!("    explored         : {explored_tot}  (rounds {rounds}, frontier {frcap})");
            println!("    => ReachListCovered holds for {} / {} total-instance pairs",
                total - res, total);
        }
        // CONTROL.  "All the resisters have a two-exit cycle" means nothing without the base
        // rate among Thompson automata themselves.  Comparing a suspicious set against no
        // control group is the mistake that overturned the `sccs` signal early in this
        // programme; do not repeat it.
        {
            let (mut te, mut th, mut n5) = (0usize, 0usize, 0usize);
            for a in list.iter() {
                if a.k as usize != 5 { continue; }
                n5 += 1;
                if two_exit_cycle(a).is_some() { te += 1; }
                if two_halt_cycle(a).is_some() { th += 1; }
            }
            println!("  CONTROL — Thompson automata (k=5) in the pool: {n5}");
            println!("    with a two-exit cycle : {te}  ({:.1}%)",
                100.0 * (te as f64) / (n5.max(1) as f64));
            println!("    with a two-halt cycle : {th}  ({:.1}%)",
                100.0 * (th as f64) / (n5.max(1) as f64));
        }
        println!("  PARTNER FUNCTION (is the forced pairing single-valued?):");
        println!("    functional in 1st component : {pf_first} / {pf_total}");
        println!("    functional in 2nd component : {pf_second} / {pf_total}");
        println!("    functional in either        : {pf_either} / {pf_total}");
        println!("    functional PER ENTRY BRANCH : {pf_branch} / {pf_total}");
        println!("    mean reachable pairs        : {:.2}",
            (pf_pairs as f64) / (pf_total.max(1) as f64));
        // Does ONE LEVEL of un-sharing suffice in general?  Tree unfolding always covers,
        // but is infinite on cyclic automata; one level is finite.  Measure it on EVERY
        // uncovered pullback, not just the ones a forward search failed to rescue.
        {
            let mut us_cov = 0usize;
            let mut us_big = 0usize;
            let mut us_exhibited = 0usize;
            let mut us_fail: Vec<Aut<NA>> = Vec::new();
            for p in uncovered.iter() {
                match unshare(p) {
                    None => { us_big += 1; }
                    Some(h) => {
                        let ok = canon(&h).map(|c| covers(&c, p)).unwrap_or(false);
                        if ok { us_cov += 1; } else { us_fail.push(p.clone()); }
                        if let Some((g, a, b)) = unshare_parts(p) {
                            let ina = canon(&a).map(|c| by_beh.get(&behaviour(&c))
                                .map(|v| v.iter().any(|&n| list[n] == c)).unwrap_or(false))
                                .unwrap_or(false);
                            let inb = canon(&b).map(|c| by_beh.get(&behaviour(&c))
                                .map(|v| v.iter().any(|&n| list[n] == c)).unwrap_or(false))
                                .unwrap_or(false);
                            let cov = a_ite(g, &a, &b).and_then(|x| canon(&x))
                                .map(|x| covers(&x, p)).unwrap_or(false);
                            if ina && inb && cov { us_exhibited += 1; }
                        }
                    }
                }
            }
            println!("  UNSHARE on ALL uncovered ({}):", uncovered.len());
            println!("    covers by one level : {us_cov}");
            println!("    too big (> MAXK)    : {us_big}");
            println!("    fully exhibited     : {us_exhibited}");
            println!("    one level FAILS     : {}", us_fail.len());
            // THE BRANCH ROUTE, MEASURED PROPERLY.  "fully exhibited" only asked whether each
            // part is ITSELF in the pool.  The route needs each part to be COVERED, which is
            // weaker — well-nested automata are not closed under homomorphic images, so a
            // part can be covered without being one.  Parts bigger than the cap were never
            // testable by lookup at all.
            if std::env::var("PAD_PARTSFULL").is_ok() {
                let rounds = std::env::var("PAD_PF_ROUNDS").ok()
                    .and_then(|v| v.parse::<usize>().ok()).unwrap_or(3);
                let frcap = std::env::var("PAD_PF_FRONTIER").ok()
                    .and_then(|v| v.parse::<usize>().ok()).unwrap_or(60000);
                // collect distinct parts
                let mut parts: Vec<Aut<NA>> = Vec::new();
                let mut index: FxMap<Aut<NA>, usize> = FxMap::default();
                let mut per: Vec<(usize, usize)> = Vec::new();
                for p in uncovered.iter() {
                    match unshare_parts(p) {
                        None => per.push((usize::MAX, usize::MAX)),
                        Some((_, a, b)) => {
                            let mut ids = [usize::MAX; 2];
                            for (k, q) in [&a, &b].iter().enumerate() {
                                if q.k == 0 { continue; }
                                if let Some(c) = canon(q) {
                                    let id = *index.entry(c.clone()).or_insert_with(|| {
                                        parts.push(c.clone()); parts.len() - 1 });
                                    ids[k] = id;
                                }
                            }
                            per.push((ids[0], ids[1]));
                        }
                    }
                }
                let mut done = vec![false; parts.len()];
                let mut groups: FxMap<Vec<u8>, Vec<usize>> = FxMap::default();
                for (i, q) in parts.iter().enumerate() {
                    groups.entry(behaviour(q)).or_default().push(i);
                }
                let mut explored_tot = 0usize;
                for (beh, idxs) in groups.iter() {
                    let seeds = match by_beh.get(beh) { Some(v) => v, None => continue };
                    for &i in idxs.iter() {
                        if let Some(c) = canon(&parts[i]) {
                            if seeds.iter().any(|&n| list[n] == c) { done[i] = true; }
                        }
                    }
                    if idxs.iter().all(|&i| done[i]) { continue; }
                    let mut pool = Pool::<NA>::new();
                    let mut frontier: Vec<u32> = Vec::new();
                    let mut seen: FxSet<u32> = FxSet::default();
                    for &n in seeds.iter() {
                        let r = pool.of_prov(&list, &prov, n as u32);
                        if seen.insert(r) { frontier.push(r); }
                    }
                    for _ in 0..rounds {
                        let mut next: Vec<u32> = Vec::new();
                        for &t in frontier.iter() {
                            refinements(&mut pool, t, nguards, true, true, 3, 3, &mut next);
                        }
                        let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                        for t in next {
                            if !seen.insert(t) { continue; }
                            explored_tot += 1;
                            if let Some(a) = pool.aut(t) {
                                if let Some(c) = canon(&a) {
                                    for &i in idxs.iter() {
                                        if !done[i] && covers(&c, &parts[i]) { done[i] = true; }
                                    }
                                }
                            }
                            keep.push(t);
                        }
                        frontier = keep;
                        if frontier.len() > frcap { frontier.truncate(frcap); }
                        if idxs.iter().all(|&i| done[i]) { break; }
                    }
                }
                let pdone = done.iter().filter(|&&b| b).count();
                let mut both = 0usize;
                for &(x, y) in per.iter() {
                    let ok = |i: usize| i == usize::MAX || done[i];
                    if x != usize::MAX || y != usize::MAX {
                        if ok(x) && ok(y) { both += 1; }
                    }
                }
                println!("  BRANCH ROUTE, parts COVERED (not just in pool):");
                println!("    distinct parts        : {}", parts.len());
                println!("    parts covered         : {pdone} / {}", parts.len());
                println!("    pullbacks with BOTH   : {both} / {}", uncovered.len());
                println!("    explored              : {explored_tot}");
            }
            // Does the recursion close?  Each branch piece is strictly smaller, so if every
            // piece eventually lands in the pool the induction is well-founded.
            let budget = std::env::var("PAD_REC_DEPTH").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(6);
            let mut rec_ok = 0usize;
            let mut rec_fail = 0usize;
            let mut depth_hist = [0usize; 12];
            for p in uncovered.iter() {
                match unshare_rec(p, &list, &by_beh, 0, budget) {
                    Some(d) => { rec_ok += 1; if d < 12 { depth_hist[d] += 1; } }
                    None => { rec_fail += 1; }
                }
            }
            // Are the stalling parts simply BIGGER than the pool cap?  A part with more
            // states than maxk cannot be in `list` no matter how expressible it is, and that
            // confound has been mistaken for a real failure before.
            let mut fail_parts_big = 0usize;
            let mut fail_parts_small = 0usize;
            let mut fail_maxpart = 0u8;
            for p in uncovered.iter() {
                if unshare_rec(p, &list, &by_beh, 0, budget).is_some() { continue; }
                if let Some((_, a, b)) = unshare_parts(p) {
                    for q in [&a, &b] {
                        if q.k == 0 { continue; }
                        let inpool = canon(q).map(|c| by_beh.get(&behaviour(&c))
                            .map(|v| v.iter().any(|&n| list[n] == c)).unwrap_or(false))
                            .unwrap_or(false);
                        if inpool { continue; }
                        if q.k as usize > maxk { fail_parts_big += 1; }
                        else { fail_parts_small += 1; }
                        if q.k > fail_maxpart { fail_maxpart = q.k; }
                    }
                }
            }
            println!("  STALLING PARTS: bigger than pool cap {fail_parts_big}, \
within cap {fail_parts_small}, largest {fail_maxpart} (cap {maxk})");
            // Pool membership asks "is this part ITSELF a program automaton".  The real
            // question is whether it is COVERED by one, and un-sharing's whole point is that
            // the cover is usually larger than the target.  So run the cover search on the
            // within-cap parts that a lookup missed.
            {
                let mut targets: FxSet<Aut<NA>> = FxSet::default();
                for p in uncovered.iter() {
                    if unshare_rec(p, &list, &by_beh, 0, budget).is_some() { continue; }
                    if let Some((_, a, b)) = unshare_parts(p) {
                        for q in [&a, &b] {
                            if q.k == 0 || q.k as usize > maxk { continue; }
                            if let Some(c) = canon(q) {
                                let inpool = by_beh.get(&behaviour(&c))
                                    .map(|v| v.iter().any(|&n| list[n] == c)).unwrap_or(false);
                                if !inpool { targets.insert(c); }
                            }
                        }
                    }
                }
                let prr = std::env::var("PAD_PARTS_ROUNDS").ok()
                    .and_then(|v| v.parse::<usize>().ok()).unwrap_or(4);
                let prf = std::env::var("PAD_PARTS_FRONTIER").ok()
                    .and_then(|v| v.parse::<usize>().ok()).unwrap_or(40000);
                let mut covered_now = 0usize;
                let mut resist = 0usize;
                let mut explored_tot = 0usize;
                for q in targets.iter() {
                    let cands = match by_beh.get(&behaviour(q)) { Some(v) => v, None => {
                        resist += 1; continue; } };
                    let mut found = false;
                    'q: for &n in cands.iter() {
                        let mut pool = Pool::<NA>::new();
                        let root = pool.of_prov(&list, &prov, n as u32);
                        let mut frontier = vec![root];
                        let mut seen: FxSet<u32> = FxSet::default();
                        seen.insert(root);
                        for _ in 0..prr {
                            let mut next: Vec<u32> = Vec::new();
                            for &t in frontier.iter() {
                                refinements(&mut pool, t, nguards, true, true, 3, 4,
                                    &mut next);
                            }
                            let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                            for t in next {
                                if !seen.insert(t) { continue; }
                                explored_tot += 1;
                                if let Some(a) = pool.aut(t) {
                                    if let Some(c) = canon(&a) {
                                        if covers(&c, q) { found = true; break; }
                                    }
                                }
                                keep.push(t);
                            }
                            if found { break 'q; }
                            frontier = keep;
                            if frontier.len() > prf { frontier.truncate(prf); }
                        }
                    }
                    if found { covered_now += 1; } else {
                        resist += 1;
                        print!("    PARTRESIST k={} nested={} red={} 2exit={:?} 2halt={:?} \
cands={}", q.k, nested(q), reducible(q), two_exit_cycle(q), two_halt_cycle(q),
                            by_beh.get(&behaviour(q)).map(|v| v.len()).unwrap_or(0));
                        print!(" | ih={} it={:?}", q.ih, &q.it[..]);
                        for x in 0..q.k as usize {
                            print!(" | hl{}={} st{}={:?}", x, q.hl[x], x, &q.st[x][..]);
                        }
                        println!();
                    }
                }
                // SHARED CLOSURE.  Fourteen separate searches over the same behaviour class
                // rebuild the same automata fourteen times; the 8-round attempt cleared only
                // 2 of 34 for that reason.  Build the closure ONCE from the union of the
                // seeds and test every generated automaton against every open target.
                if std::env::var("PAD_SHARED").is_ok() {
                    let rounds = std::env::var("PAD_SHARED_ROUNDS").ok()
                        .and_then(|v| v.parse::<usize>().ok()).unwrap_or(6);
                    let fr = std::env::var("PAD_SHARED_FRONTIER").ok()
                        .and_then(|v| v.parse::<usize>().ok()).unwrap_or(400000);
                    let open: Vec<Aut<NA>> = targets.iter().cloned().collect();
                    let mut hit = vec![false; open.len()];
                    let mut seeds: FxSet<usize> = FxSet::default();
                    for q in open.iter() {
                        if let Some(v) = by_beh.get(&behaviour(q)) {
                            for &n in v.iter() { seeds.insert(n); }
                        }
                    }
                    let mut pool = Pool::<NA>::new();
                    let mut frontier: Vec<u32> = Vec::new();
                    let mut seen: FxSet<u32> = FxSet::default();
                    for &n in seeds.iter() {
                        let r = pool.of_prov(&list, &prov, n as u32);
                        if seen.insert(r) { frontier.push(r); }
                    }
                    let mut explored = 0usize;
                    let mut biggest = 0u8;
                    for rd in 0..rounds {
                        let mut next: Vec<u32> = Vec::new();
                        for &t in frontier.iter() {
                            refinements(&mut pool, t, nguards, true, true, 3, 4, &mut next);
                        }
                        let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                        for t in next {
                            if !seen.insert(t) { continue; }
                            explored += 1;
                            if let Some(a) = pool.aut(t) {
                                if a.k > biggest { biggest = a.k; }
                                if let Some(c) = canon(&a) {
                                    for (i, q) in open.iter().enumerate() {
                                        if !hit[i] && covers(&c, q) { hit[i] = true; }
                                    }
                                }
                            }
                            keep.push(t);
                        }
                        frontier = keep;
                        if frontier.len() > fr { frontier.truncate(fr); }
                        let done = hit.iter().filter(|&&b| b).count();
                        println!("    shared round {rd}: explored {explored}, biggest {biggest}, \
covered {done}/{}", open.len());
                        if done == open.len() { break; }
                    }
                    let done = hit.iter().filter(|&&b| b).count();
                    println!("  SHARED CLOSURE ({} seeds, {rounds} rounds, frontier {fr}):",
                        seeds.len());
                    println!("    explored {explored}, biggest {biggest} states");
                    println!("    covered {done} / {}, RESISTING {}", open.len(),
                        open.len() - done);
                }
                // `RestrictedBranchesCovered` is SUFFICIENT, not necessary.  If a pullback's
                // branch parts resist but the pullback ITSELF is covered, then the branch
                // route is simply the wrong route and the open statement is untouched.
                if std::env::var("PAD_PARENTS").is_ok() {
                    let mut parents: Vec<Aut<NA>> = Vec::new();
                    for p in uncovered.iter() {
                        if unshare_rec(p, &list, &by_beh, 0, budget).is_some() { continue; }
                        if let Some((_, a, b)) = unshare_parts(p) {
                            let mut bad = false;
                            for q in [&a, &b] {
                                if q.k == 0 || q.k as usize > maxk { continue; }
                                if let Some(c) = canon(q) {
                                    if targets.contains(&c) { bad = true; }
                                }
                            }
                            if bad { parents.push(p.clone()); }
                        }
                    }
                    let mut pcov = 0usize;
                    let mut pres = 0usize;
                    for p in parents.iter() {
                        let cands = match by_beh.get(&behaviour(p)) { Some(v) => v,
                            None => { pres += 1; continue; } };
                        let mut found = false;
                        'p2: for &n in cands.iter() {
                            let mut pool = Pool::<NA>::new();
                            let root = pool.of_prov(&list, &prov, n as u32);
                            let mut frontier = vec![root];
                            let mut seen: FxSet<u32> = FxSet::default();
                            seen.insert(root);
                            for _ in 0..3 {
                                let mut next: Vec<u32> = Vec::new();
                                for &t in frontier.iter() {
                                    refinements(&mut pool, t, nguards, true, true, 3, 3,
                                        &mut next);
                                }
                                let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                                for t in next {
                                    if !seen.insert(t) { continue; }
                                    if let Some(a) = pool.aut(t) {
                                        if let Some(c) = canon(&a) {
                                            if covers(&c, p) { found = true; break; }
                                        }
                                    }
                                    keep.push(t);
                                }
                                if found { break 'p2; }
                                frontier = keep;
                                if frontier.len() > 30000 { frontier.truncate(30000); }
                            }
                        }
                        if found { pcov += 1; } else { pres += 1; }
                    }
                    println!("  PARENTS of resisting parts: {}", parents.len());
                    println!("    pullback ITSELF covered by refinement : {pcov}");
                    println!("    pullback itself resists              : {pres}");
                }
                println!("  WITHIN-CAP STALLING PARTS (distinct): {}", targets.len());
                println!("    covered by refinement : {covered_now}");
                println!("    still resisting       : {resist}");
                println!("    (rounds {prr}, frontier {prf}, explored {explored_tot})");
            }
            println!("  RECURSIVE un-sharing (budget {budget}):");
            println!("    resolves : {rec_ok} / {}", uncovered.len());
            println!("    stalls   : {rec_fail} / {}", uncovered.len());
            print!("    depth    :");
            for d in 0..8 { print!(" {}:{}", d, depth_hist[d]); }
            println!();
            for p in us_fail.iter().take(6) {
                print!("    USFAIL k={} nested={} red={} ih={} it={:?}",
                    p.k, nested(p), reducible(p), p.ih, &p.it[..]);
                for x in 0..p.k as usize {
                    print!(" | hl{}={} st{}={:?}", x, p.hl[x], x, &p.st[x][..]);
                }
                println!();
            }
        }
        // Direct coverage alone is not informative: a cover is onto, so a candidate needs at
        // least as many states as the target, and the candidate pool is capped at `maxk`
        // while padded kernel pairs are systematically larger.  Rescue with the refinement
        // closure, which is what the statement actually allows.
        let sample = std::env::var("PAD_SAMPLE").ok()
            .and_then(|v| v.parse::<usize>().ok()).unwrap_or(200).min(uncovered.len());
        let rounds_p = std::env::var("PAD_ROUNDS").ok()
            .and_then(|v| v.parse::<usize>().ok()).unwrap_or(2);
        let frontier_cap = std::env::var("PAD_FRONTIER").ok()
            .and_then(|v| v.parse::<usize>().ok()).unwrap_or(8000);
        // Degree matters: the period law says period(P) = lcm(period e, period f), and
        // period 3 occurs, so composing degree-2 covers (reaching only 2, 4, 8) cannot be
        // enough.  Default to 3.
        let cycmax = std::env::var("PAD_CYC").ok()
            .and_then(|v| v.parse::<u32>().ok()).unwrap_or(3);
        let mut rescued = 0usize;
        let mut too_big = 0usize;
        let mut survivors: Vec<Aut<NA>> = Vec::new();
        for p in uncovered.iter().take(sample) {
            let cands = match by_beh.get(&behaviour(p)) { Some(v) => v, None => continue };
            if cands.iter().all(|&n| (list[n].k as usize) < p.k as usize) { too_big += 1; }
            let mut found = false;
            'c: for &n in cands.iter() {
                let mut pool = Pool::<NA>::new();
                let root = pool.of_prov(&list, &prov, n as u32);
                let mut frontier = vec![root];
                let mut seen: FxSet<u32> = FxSet::default();
                seen.insert(root);
                for _ in 0..rounds_p {
                    let mut next: Vec<u32> = Vec::new();
                    for &t in frontier.iter() {
                        refinements(&mut pool, t, nguards, true, true, cycmax, 3, &mut next);
                    }
                    let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                    for t in next {
                        if !seen.insert(t) { continue; }
                        if let Some(a) = pool.aut(t) {
                            if let Some(c) = canon(&a) {
                                if covers(&c, p) { found = true; break; }
                            }
                        }
                        keep.push(t);
                    }
                    if found { break 'c; }
                    frontier = keep;
                    if frontier.len() > frontier_cap { frontier.truncate(frontier_cap); }
                }
            }
            if found { rescued += 1; } else { survivors.push(p.clone()); }
        }
        println!("  sample           : {sample} of {}", uncovered.len());
        println!("  ..all candidates smaller than target: {too_big} / {sample}");
        println!("  ..rescued by refinement ({rounds_p} rounds, frontier {frontier_cap}, cyc {cycmax}): \
{rescued} / {sample}");
        println!("  ..survivors      : {}", survivors.len());
        // Kosaraju / Ashcroft-Manna: a loop with two distinct exits cannot be structured
        // into a while-program without auxiliary variables, and GKAT has neither auxiliary
        // variables nor multi-level breaks.  So a two-exit cycle in a survivor is the
        // classical obstruction, and the earlier residue of this programme was exactly one.
        let mut with_two_exit = 0usize;
        let mut with_two_halt = 0usize;
        let mut irreducible = 0usize;
        let mut shapes: FxSet<Aut<NA>> = FxSet::default();
        for p in survivors.iter() {
            let cands = by_beh.get(&behaviour(p)).map(|v| v.len()).unwrap_or(0);
            let maxc = by_beh.get(&behaviour(p))
                .map(|v| v.iter().map(|&n| list[n].k).max().unwrap_or(0)).unwrap_or(0);
            let te = two_exit_cycle(p);
            let th = two_halt_cycle(p);
            if te.is_some() { with_two_exit += 1; }
            if th.is_some() { with_two_halt += 1; }
            if !reducible(p) { irreducible += 1; }
            shapes.insert(p.clone());
            println!("  PADSURVIVOR k={} cands={} maxcand_k={} nested={} red={} 2exit={:?} \
2halt={:?}", p.k, cands, maxc, nested(p), reducible(p), te, th);
            print!("    ih={} it={:?}", p.ih, &p.it[..]);
            for x in 0..p.k as usize {
                print!(" | hl{}={} st{}={:?}", x, p.hl[x], x, &p.st[x][..]);
            }
            println!();
        }
        // Focus: the only survivors whose non-coverage is NOT confounded by pool size are
        // those with a candidate at least as large as the target (a cover is onto).  Give
        // those a much larger budget — if they still resist, they are real.
        if std::env::var("PAD_FOCUS").is_ok() {
            let fr = std::env::var("PAD_FOCUS_ROUNDS").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(6);
            let ff = std::env::var("PAD_FOCUS_FRONTIER").ok()
                .and_then(|v| v.parse::<usize>().ok()).unwrap_or(200000);
            let mut adequate = 0usize;
            let mut still = 0usize;
            for p in survivors.iter() {
                let cands = match by_beh.get(&behaviour(p)) { Some(v) => v, None => continue };
                let maxc = cands.iter().map(|&n| list[n].k).max().unwrap_or(0);
                // Size-adequacy gates DIRECT coverage only.  Refinement grows automata —
                // duplication doubles — so a 5-state candidate can reach a 6-state cover in
                // one round.  PAD_FOCUS_ALL runs the big budget on every survivor.
                if std::env::var("PAD_FOCUS_ALL").is_err() && (maxc as usize) < p.k as usize {
                    continue;
                }
                adequate += 1;
                let mut found = false;
                let mut explored = 0usize;
                let mut biggest_seen = 0u8;
                let mut atleast_target = 0usize;
                'f: for &n in cands.iter() {
                    let mut pool = Pool::<NA>::new();
                    let root = pool.of_prov(&list, &prov, n as u32);
                    let mut frontier = vec![root];
                    let mut seen: FxSet<u32> = FxSet::default();
                    seen.insert(root);
                    for _ in 0..fr {
                        let mut next: Vec<u32> = Vec::new();
                        for &t in frontier.iter() {
                            refinements(&mut pool, t, nguards, true, true, cycmax, 4,
                                &mut next);
                        }
                        let mut keep: Vec<u32> = Vec::with_capacity(next.len());
                        for t in next {
                            if !seen.insert(t) { continue; }
                            explored += 1;
                            if let Some(a) = pool.aut(t) {
                                if a.k > biggest_seen { biggest_seen = a.k; }
                                if a.k >= p.k { atleast_target += 1; }
                                if let Some(c) = canon(&a) {
                                    if covers(&c, p) { found = true; break; }
                                }
                            }
                            keep.push(t);
                        }
                        if found { break 'f; }
                        frontier = keep;
                        if frontier.len() > ff { frontier.truncate(ff); }
                    }
                }
                if found {
                    println!("  FOCUS k={} RESCUED (explored {explored})", p.k);
                } else {
                    still += 1;
                    println!("  FOCUS k={} STILL UNCOVERED after {fr} rounds \
(explored {explored}, biggest {biggest_seen} states, {atleast_target} of size >= target)",
                        p.k);
                }
            }
            println!("  size-adequate survivors: {adequate}, still uncovered: {still}");
        }
        {
            let mut unshared_covers = 0usize;
            let mut unshared_expressible = 0usize;
            for p in survivors.iter() {
                match unshare(p) {
                    None => println!("  UNSHARE k={} : too big", p.k),
                    Some(h) => {
                        let c = canon(&h);
                        let cov = c.as_ref().map(|c| covers(c, p)).unwrap_or(false);
                        if cov { unshared_covers += 1; }
                        let inlist = c.as_ref()
                            .map(|c| by_beh.get(&behaviour(c))
                                .map(|v| v.iter().any(|&n| list[n] == *c)).unwrap_or(false))
                            .unwrap_or(false);
                        if inlist { unshared_expressible += 1; }
                        println!("  UNSHARE k={} -> {} states, covers={} in_pool={} nested={}",
                            p.k, h.k, cov, inlist,
                            c.as_ref().map(|c| nested(c)).unwrap_or(false));
                    }
                }
            }
            let mut exhibited = 0usize;
            for p in survivors.iter() {
                if let Some((g, a, b)) = unshare_parts(p) {
                    let ca = canon(&a);
                    let cb = canon(&b);
                    let ina = ca.as_ref().map(|c| by_beh.get(&behaviour(c))
                        .map(|v| v.iter().any(|&n| list[n] == *c)).unwrap_or(false))
                        .unwrap_or(false);
                    let inb = cb.as_ref().map(|c| by_beh.get(&behaviour(c))
                        .map(|v| v.iter().any(|&n| list[n] == *c)).unwrap_or(false))
                        .unwrap_or(false);
                    let built = a_ite(g, &a, &b).and_then(|h| canon(&h));
                    let cov = built.as_ref().map(|h| covers(h, p)).unwrap_or(false);
                    if cov && ina && inb { exhibited += 1; }
                    println!("  EXHIBIT k={} parts {}+{} in_pool={}/{} ite_covers={}",
                        p.k, a.k, b.k, ina, inb, cov);
                }
            }
            println!("  covers EXHIBITED as `if g then P0 else P1` : {exhibited} / {}",
                survivors.len());
            println!("  un-shared covers  : {unshared_covers} / {}", survivors.len());
            println!("  ..and in the pool : {unshared_expressible} / {}", survivors.len());
        }
        println!("  survivors with two-exit cycle : {with_two_exit} / {}", survivors.len());
        println!("  survivors with two-halt cycle : {with_two_halt} / {}", survivors.len());
        println!("  survivors irreducible         : {irreducible} / {}", survivors.len());
        println!("  distinct survivor shapes      : {}", shapes.len());
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
