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
