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

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
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
/// Orbits, in Caron and Ziadi's sense: the non-trivial strongly connected components.  For a
/// GKAT Thompson automaton every orbit is a loop body, because `wh` is the only constructor
/// that creates a cycle.
fn orbits<const NA: usize>(h: &Aut<NA>) -> Vec<u16> {
    let k = h.k as usize;
    let mut reach = [0u16; MAXK];
    for i in 0..k {
        for y in 0..NA {
            if h.st[i][y] != 0 { reach[i] |= 1 << (h.st[i][y] - 1); }
        }
    }
    for m in 0..k {
        for i in 0..k {
            if reach[i] & (1 << m) != 0 { reach[i] |= reach[m]; }
        }
    }
    let mut seen = 0u16;
    let mut out: Vec<u16> = Vec::new();
    for i in 0..k {
        if seen & (1 << i) != 0 { continue; }
        let mut comp = 1u16 << i;
        for j in 0..k {
            if i != j && reach[i] & (1 << j) != 0 && reach[j] & (1 << i) != 0 {
                comp |= 1 << j;
            }
        }
        // non-trivial: more than one state, or a self-loop
        let nontrivial = comp.count_ones() > 1 || reach[i] & (1 << i) != 0;
        if nontrivial { out.push(comp); }
        seen |= comp;
    }
    out
}

/// **REFUTED — unsound, kept as the record of why.**  Validation: 19055 / 20020 pool automata,
/// and every pool automaton is Thompson by construction, so this is not necessary.
///
/// Smallest counterexample found: `k=2`, entry `[1,2]`, `s0 -> s1` at both atoms and
/// `s1 -> s0` at atom 0.  The two states form one orbit and both are entry targets, so at
/// atom 0 two orbit states point into the entry set at different targets — which this test
/// calls a violation.  It is not one: `s0 -> s1` is a *body-internal* edge, not a back edge.
/// The graph does not distinguish the two, and no local test can.  That is precisely the
/// "partly determined" trap that sank hand-inversion, reappearing at the graph level, and it
/// is why Caron and Ziadi need reduction rules rather than a flat local predicate.
///
/// Original (wrong) rationale follows.  `loopInitialized` appends, to every body state, the whole
/// of the body's entry transition list guarded by that state's halt guard.  So inside an orbit
/// every state that can leave the body re-enters it at the *same* target per atom — the back
/// edges all come from one fixed list.  That is Caron and Ziadi's `Out(O) x In(O) ⊆ E`
/// condition in the guarded setting, and it is NECESSARY for a Thompson automaton.
///
/// Concretely: for each orbit, and each atom, the set of edges from orbit states into the
/// orbit's entry set must be single-valued.
fn orbit_stable<const NA: usize>(h: &Aut<NA>) -> bool {
    let k = h.k as usize;
    for o in orbits(h).iter() {
        // entry set: orbit states entered from outside the orbit, or from the pseudostate
        let mut ins = 0u16;
        for y in 0..NA {
            if h.it[y] != 0 {
                let t = (h.it[y] - 1) as usize;
                if o & (1 << t) != 0 { ins |= 1 << t; }
            }
        }
        for u in 0..k {
            if o & (1 << u) != 0 { continue; }
            for y in 0..NA {
                if h.st[u][y] != 0 {
                    let t = (h.st[u][y] - 1) as usize;
                    if o & (1 << t) != 0 { ins |= 1 << t; }
                }
            }
        }
        if ins == 0 { continue; }
        // every edge from inside the orbit into the entry set must agree, per atom
        let mut tgt = [usize::MAX; NA];
        for u in 0..k {
            if o & (1 << u) == 0 { continue; }
            for y in 0..NA {
                if h.st[u][y] == 0 { continue; }
                let t = (h.st[u][y] - 1) as usize;
                if ins & (1 << t) == 0 { continue; }
                if tgt[y] == usize::MAX { tgt[y] = t; }
                else if tgt[y] != t { return false; }
            }
        }
    }
    true
}



/// **Targeted layer streaming — sound POSITIVES for Thompson-ness above the pool.**
///
/// An expression with `n` actions has immediate subexpressions with at most `n` actions
/// (tests contribute none), so the `n`-state Thompson automata are reachable from the pool by
/// combination.  Deciding membership for a specific target therefore does not need the layer
/// STORED, only enumerated — and because every automaton produced here really is the Thompson
/// automaton of an expression, ANY HIT IS A PROOF.  Misses are inconclusive, which is the safe
/// direction: this can only raise measured coverage, never falsely.
///
/// `rounds` bounds how often `wh`/`ite`-with-a-test wrappers may be re-applied within the
/// layer.  Unbounded closure at n=6 is the 55M the brief flags; bounded, storage is O(frontier)
/// and a miss simply stays unknown.

/// **Trim then canonicalise.**  `canon` REJECTS an automaton whose states are not all reachable
/// from the initial transitions, and quotients of a sum routinely are not — which silently
/// removed every k>=6 quotient from every measurement that ran through `canon`.  Unreachable
/// states cannot affect behaviour, and a Thompson automaton is trim by construction, so
/// dropping them is the right normalisation rather than a relaxation.
fn trim_canon<const NA: usize>(a: &Aut<NA>) -> Option<Aut<NA>> {
    let k = a.k as usize;
    let mut order = [u8::MAX; MAXK];
    let mut queue = [0usize; MAXK];
    let (mut qh, mut qt) = (0usize, 0usize);
    let mut n = 0u8;
    for i in 0..NA {
        if a.it[i] != 0 {
            let t = (a.it[i] - 1) as usize;
            if order[t] == u8::MAX { order[t] = n; n += 1; queue[qt] = t; qt += 1; }
        }
    }
    while qh < qt {
        let s = queue[qh]; qh += 1;
        for i in 0..NA {
            if a.st[s][i] != 0 {
                let t = (a.st[s][i] - 1) as usize;
                if order[t] == u8::MAX { order[t] = n; n += 1; queue[qt] = t; qt += 1; }
            }
        }
    }
    if n as usize > MAXK { return None; }
    let mut inv = [usize::MAX; MAXK];
    for s in 0..k { if order[s] != u8::MAX { inv[order[s] as usize] = s; } }
    let mut c = Aut::blank();
    c.k = n;
    c.ih = a.ih;
    let m = |x: u8| -> u8 { if x == 0 { 0 } else { order[(x - 1) as usize] + 1 } };
    for i in 0..NA { c.it[i] = m(a.it[i]); }
    for d in 0..n as usize {
        let s = inv[d];
        c.hl[d] = a.hl[s];
        for i in 0..NA { c.st[d][i] = m(a.st[s][i]); }
    }
    Some(c)
}


/// **The THIRD witness: a common refinement.**
///
/// `equivBA_of_common_refinement` is proved in the corpus, and `Refines` (unroll, dup, cyc plus
/// congruence) is a sound derivation — it discharged residue pair #3, whose two sides differ
/// only by where the iteration boundary falls.  The sum route's witness set has only ever
/// tested "eliminable OR Thompson", so a pair discharged by a refinement chain counts as a
/// failure.  This closes that gap.
fn refinement_witness<const NA: usize>(
    list: &[Aut<NA>], prov: &[Prov], i: u32, j: u32, nguards: u8, rounds: u32, cap: usize,
) -> bool {
    let mut pool = Pool::<NA>::new();
    let ri = pool.of_prov(list, prov, i);
    let rj = pool.of_prov(list, prov, j);
    fn close<const NA: usize>(pool: &mut Pool<NA>, root: u32, nguards: u8,
        rounds: u32, cap: usize) -> FxSet<Aut<NA>> {
        let mut seen: FxSet<u32> = FxSet::default();
        let mut auts: FxSet<Aut<NA>> = FxSet::default();
        let mut frontier = vec![root];
        seen.insert(root);
        if let Some(a) = pool.aut(root) { if let Some(c) = canon(&a) { auts.insert(c); } }
        for _ in 0..rounds {
            let mut next: Vec<u32> = Vec::new();
            for &t in frontier.iter() {
                refinements(pool, t, nguards, true, true, 2, 2, &mut next);
            }
            let mut keep: Vec<u32> = Vec::new();
            for t in next {
                if !seen.insert(t) { continue; }
                if let Some(a) = pool.aut(t) { if let Some(c) = canon(&a) { auts.insert(c); } }
                keep.push(t);
                if keep.len() >= cap { break; }
            }
            if keep.is_empty() { break; }
            frontier = keep;
        }
        auts
    }
    let ai = close(&mut pool, ri, nguards, rounds, cap);
    let aj = close(&mut pool, rj, nguards, rounds, cap);
    ai.iter().any(|a| aj.contains(a))
}



/// Rebuild the STRUCTURAL (construction-ordered) automaton from provenance — no canon.
fn structural<const NA: usize>(list: &[Aut<NA>], prov: &[Prov], idx: u32) -> Aut<NA> {
    match prov[idx as usize] {
        Prov::Leaf => {
            let a = &list[idx as usize];
            if a.k == 0 { a_test(a.ih) } else { a_act() }
        }
        Prov::Seq(l, r) =>
            a_seq(&structural(list, prov, l), &structural(list, prov, r)).unwrap(),
        Prov::Ite(g, l, r) =>
            a_ite(g, &structural(list, prov, l), &structural(list, prov, r)).unwrap(),
        Prov::Wh(g, b) => a_wh(g, &structural(list, prov, b)),
    }
}

/// canon's BFS order over a structural automaton: `order[structural] = canonical`.
fn canon_order<const NA: usize>(a: &Aut<NA>) -> [u8; MAXK] {
    let k = a.k as usize;
    let mut order = [u8::MAX; MAXK];
    let mut queue = [0usize; MAXK];
    let (mut qh, mut qt) = (0usize, 0usize);
    let mut n = 0u8;
    for i in 0..NA {
        if a.it[i] != 0 {
            let t = (a.it[i] - 1) as usize;
            if order[t] == u8::MAX { order[t] = n; n += 1; queue[qt] = t; qt += 1; }
        }
    }
    while qh < qt {
        let s = queue[qh]; qh += 1;
        for i in 0..NA {
            if a.st[s][i] != 0 {
                let t = (a.st[s][i] - 1) as usize;
                if order[t] == u8::MAX { order[t] = n; n += 1; queue[qt] = t; qt += 1; }
            }
        }
    }
    let _ = k;
    order
}

/// Lean syntax for a guard mask at NA=2 with a single primitive test `bT`.
fn mask_lean(g: u8) -> String {
    match g {
        0 => "BExp.zero".to_string(),
        1 => "(BExp.not bT)".to_string(),
        2 => "bT".to_string(),
        _ => "BExp.one".to_string(),
    }
}

/// Lean `Exp` term for a provenance node (NA = 2, T = Unit, A = Unit).
fn expr_lean<const NA: usize>(list: &[Aut<NA>], prov: &[Prov], idx: u32) -> String {
    match prov[idx as usize] {
        Prov::Leaf => {
            let a = &list[idx as usize];
            if a.k == 0 { format!("(Exp.test {})", mask_lean(a.ih)) } else { "pA".to_string() }
        }
        Prov::Seq(l, r) => format!("(Exp.seq {} {})",
            expr_lean(list, prov, l), expr_lean(list, prov, r)),
        Prov::Ite(g, l, r) => format!("(Exp.ite {} {} {})",
            mask_lean(g), expr_lean(list, prov, l), expr_lean(list, prov, r)),
        Prov::Wh(g, b) => format!("(Exp.wh {} {})", mask_lean(g), expr_lean(list, prov, b)),
    }
}

/// Lean `State` injection paths for a provenance node's Thompson automaton, in the harness's
/// state order (a_ite/a_seq put the left component first; a_wh keeps the body's).
fn state_paths<const NA: usize>(list: &[Aut<NA>], prov: &[Prov], idx: u32) -> Vec<String> {
    match prov[idx as usize] {
        Prov::Leaf => {
            let a = &list[idx as usize];
            if a.k == 0 { vec![] } else { vec!["()".to_string()] }
        }
        Prov::Seq(l, r) | Prov::Ite(_, l, r) => {
            let mut out: Vec<String> = state_paths(list, prov, l).into_iter()
                .map(|s| format!("(Sum.inl {s})")).collect();
            out.extend(state_paths(list, prov, r).into_iter()
                .map(|s| format!("(Sum.inr {s})")));
            out
        }
        Prov::Wh(_, b) => state_paths(list, prov, b),
    }
}

/// A canon-INVARIANT signature: `canon` only renumbers states, so the multiset of
/// (halt mask, out-degree) pairs and the state count survive it.  Candidates whose signature
/// matches no target cannot BE a target, and are dropped before paying for `canon` — which is
/// the hot cost in the layer sweep.
fn sig<const NA: usize>(a: &Aut<NA>) -> u64 {
    let k = a.k as usize;
    let mut v: [u16; MAXK] = [0; MAXK];
    for sx in 0..k {
        let deg = (0..NA).filter(|&i| a.st[sx][i] != 0).count() as u16;
        v[sx] = ((a.hl[sx] as u16) << 4) | deg;
    }
    v[..k].sort_unstable();
    let mut h: u64 = 0xcbf29ce484222325;
    h ^= k as u64; h = h.wrapping_mul(0x100000001b3);
    for x in v[..k].iter() {
        h ^= *x as u64; h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn stream_layer<const NA: usize>(
    by_k: &[Vec<Aut<NA>>], n: usize, nguards: u8, rounds: usize,
    targets: &FxSet<Aut<NA>>,
) -> FxSet<Aut<NA>> {
    let mut hits: FxSet<Aut<NA>> = FxSet::default();
    let mut layer: Vec<Aut<NA>> = Vec::new();
    let mut seenl: FxSet<Aut<NA>> = FxSet::default();
    let tsig: FxSet<u64> = targets.iter().map(|t| sig(t)).collect();
    let mut note = |a: &Aut<NA>, hits: &mut FxSet<Aut<NA>>| {
        if !tsig.contains(&sig(a)) { return; }
        if let Some(c) = canon(a) {
            if targets.contains(&c) { hits.insert(c); }
        }
    };
    // seed: one combination step from strictly lower layers (tests have k = 0).
    // Parallel over the left operand; each worker keeps its own hit set and layer chunk,
    // merged serially.  The signature prune runs inside the worker, so `canon` is paid only
    // by candidates that could actually be a target.
    let tsig2 = tsig.clone();
    for i in 0..=n {
        if hits.len() == targets.len() { break; }
        let j = n - i;
        if i >= by_k.len() || j >= by_k.len() { continue; }
        let chunks: Vec<(FxSet<Aut<NA>>, Vec<Aut<NA>>)> = by_k[i]
            .par_iter()
            .map(|l| {
                let mut h: FxSet<Aut<NA>> = FxSet::default();
                let mut lay: Vec<Aut<NA>> = Vec::new();
                let mut take = |a: Aut<NA>, h: &mut FxSet<Aut<NA>>, lay: &mut Vec<Aut<NA>>| {
                    if tsig2.contains(&sig(&a)) {
                        if let Some(c) = canon(&a) {
                            if targets.contains(&c) { h.insert(c); }
                        }
                    }
                    if a.k as usize == n { lay.push(a); }
                };
                for r in by_k[j].iter() {
                    if let Some(a) = a_seq(l, r) { take(a, &mut h, &mut lay); }
                    for g in 0..nguards {
                        if let Some(a) = a_ite(g, l, r) { take(a, &mut h, &mut lay); }
                    }
                }
                (h, lay)
            })
            .collect();
        for (h, lay) in chunks {
            for c in h { hits.insert(c); }
            for a in lay { if seenl.insert(a) { layer.push(a); } }
        }
    }
    // bounded re-wrapping inside the layer: wh, and ite against a test
    for _ in 0..rounds {
        if hits.len() == targets.len() { break; }
        let mut next: Vec<Aut<NA>> = Vec::new();
        for b in layer.iter() {
            for g in 0..nguards {
                let a = a_wh(g, b);
                note(&a, &mut hits);
                if a.k as usize == n && seenl.insert(a) { next.push(a); }
                if 0 < by_k.len() {
                    for t in by_k[0].iter() {
                        if let Some(a) = a_ite(g, b, t) {
                            note(&a, &mut hits);
                            if a.k as usize == n && seenl.insert(a) { next.push(a); }
                        }
                        if let Some(a) = a_ite(g, t, b) {
                            note(&a, &mut hits);
                            if a.k as usize == n && seenl.insert(a) { next.push(a); }
                        }
                        if let Some(a) = a_seq(t, b) {
                            note(&a, &mut hits);
                            if a.k as usize == n && seenl.insert(a) { next.push(a); }
                        }
                        if let Some(a) = a_seq(b, t) {
                            note(&a, &mut hits);
                            if a.k as usize == n && seenl.insert(a) { next.push(a); }
                        }
                    }
                }
            }
        }
        if next.is_empty() { break; }
        layer = next;
    }
    hits
}

/// **REFUTED — NOT a necessary condition.  Kept as a record of why.**
///
/// Validation caught it: 2 / 20000 pool automata, which are Thompson by construction, violate
/// it.  The smallest is `((p +_b p) ; (p ; b?))^(1)`, whose orbit is `{s0, s2}` while `s1` sits
/// in the loop BODY without lying on any cycle.  So the premise below — that an orbit is a loop
/// body, hence that every edge into it from outside is a loop entry — is FALSE.  The edge
/// `s1 → s2` is body-internal and lands on a different state than the entry `→ s0` does.
///
/// This is the "invisible entry under a guard" trap in its graph-theoretic form, and it is the
/// same ambiguity that sank the flat stability test: a body-internal edge into the entry set
/// cannot be told from a loop entry by inspecting the graph.
///
/// An orbit is the body `B` of some `wh g B`, and `loopInitialized` is the only constructor
/// that creates a cycle.  Every edge into `B` from OUTSIDE therefore comes from the loop's own
/// entry transitions, which are `initTrans B` conjoined with `g` — one target per atom, fixed
/// by `B` alone.  So for each atom, every external edge into the orbit lands on the SAME state,
/// no matter which outside state it leaves from.
///
/// This is the companion of `orbit_entry_halt_disjoint` and shares its virtue: it looks only at
/// edges crossing INTO the orbit, which are unambiguous, never at internal edges, which cannot
/// be told apart from back edges by inspecting the graph.  That ambiguity is what sank the flat
/// stability test.
#[allow(dead_code)]
fn orbit_entry_unique<const NA: usize>(h: &Aut<NA>) -> bool {
    let k = h.k as usize;
    for o in orbits(h).iter() {
        let mut tgt = [usize::MAX; NA];
        // entries from the initial pseudostate
        for y in 0..NA {
            if h.it[y] != 0 {
                let t = (h.it[y] - 1) as usize;
                if o & (1 << t) != 0 {
                    if tgt[y] == usize::MAX { tgt[y] = t; } else if tgt[y] != t { return false; }
                }
            }
        }
        // entries from states outside the orbit
        for u in 0..k {
            if o & (1 << u) != 0 { continue; }
            for y in 0..NA {
                if h.st[u][y] == 0 { continue; }
                let t = (h.st[u][y] - 1) as usize;
                if o & (1 << t) == 0 { continue; }
                if tgt[y] == usize::MAX { tgt[y] = t; } else if tgt[y] != t { return false; }
            }
        }
    }
    true
}

/// **Orbit entry/halt disjointness — a NECESSARY condition, from the guard law.**
///
/// CAUTION, and this was found the hard way.  The justification below assumes an orbit IS a
/// loop body.  That assumption is FALSE — see `orbit_entry_unique`, refuted by a pool automaton
/// whose loop body contains a state off every cycle.  This condition nevertheless survives
/// validation on 20000 pool automata, so it is EMPIRICALLY VALIDATED, not proved.  Treat a
/// refutation it reports as strong evidence rather than as a theorem.
///
/// `loopInitialized` is the only constructor that creates a cycle, so every orbit is a loop
/// body `B` of some `wh g B`.  It is also the only way into `B`: every edge from outside `B`
/// into `B` is one of the loop's entry transitions, and those are conjoined with `g`.  And
/// every state of `B` gets halt guard `body.hlt u ∧ ¬g`, possibly restricted further by an
/// enclosing context.  So an atom that enters the orbit satisfies `g`, and no state of the
/// orbit may halt there.
///
/// Unlike stability this needs no back-edge identification — which is what sank the flat
/// stability test, since a body-internal edge into the entry set is indistinguishable from a
/// back edge by looking at the graph.  Entry edges come from *outside* the orbit, so they are
/// unambiguous.
fn orbit_entry_halt_disjoint<const NA: usize>(h: &Aut<NA>) -> bool {
    let k = h.k as usize;
    for o in orbits(h).iter() {
        for y in 0..NA {
            // is the orbit entered at atom y, from the pseudostate or from any state outside it?
            let mut entered = h.it[y] != 0 && o & (1 << (h.it[y] - 1)) != 0;
            for u in 0..k {
                if o & (1 << u) != 0 || h.st[u][y] == 0 { continue; }
                if o & (1 << (h.st[u][y] - 1)) != 0 { entered = true; }
            }
            if !entered { continue; }
            for u in 0..k {
                if o & (1 << u) != 0 && h.hl[u] & (1 << y) != 0 { return false; }
            }
        }
    }
    true
}

/// The orbit's entry map, read off the edges that come in from outside it.  Every edge into
/// a loop body from outside is one of the loop's own entry transitions, so this is well
/// defined; `None` at an atom means the orbit is not entered there.  Returns `Err` if two
/// incoming edges disagree, which `orbit_entry_single_valued` reports as a violation.
fn orbit_entry_map<const NA: usize>(h: &Aut<NA>, o: u16) -> Result<[usize; NA], ()> {
    let k = h.k as usize;
    let mut ent = [usize::MAX; NA];
    for y in 0..NA {
        let mut put = |t: usize, ent: &mut [usize; NA]| -> bool {
            if ent[y] == usize::MAX { ent[y] = t; true } else { ent[y] == t }
        };
        if h.it[y] != 0 {
            let t = (h.it[y] - 1) as usize;
            if o & (1 << t) != 0 && !put(t, &mut ent) { return Err(()); }
        }
        for u in 0..k {
            if o & (1 << u) != 0 || h.st[u][y] == 0 { continue; }
            let t = (h.st[u][y] - 1) as usize;
            if o & (1 << t) != 0 && !put(t, &mut ent) { return Err(()); }
        }
    }
    Ok(ent)
}

/// **REFUTED — unsound.**  19820 / 20020 pool automata.  Counterexample `k=3`, entry `[1,2]`,
/// `s0 -> s2`, `s1 -> s2`, `s2 -> s0` at atom 0: the orbit is `{s0,s2}`, entered at atom 0 both
/// from the pseudostate (at `s0`) and from `s1` (at `s2`).  The premise is wrong — a maximal
/// SCC is not a loop body, so an edge into it from outside need not be a loop entry edge.
///
/// Original (wrong) rationale follows.  **Entry single-valuedness — a NECESSARY condition.**  `loopInitialized` conjoins the loop
/// guard onto one fixed transition list, `body.initTrans`, and that list is the only way into
/// the body.  So however many states outside an orbit step into it, at a given atom they all
/// land on the same state.  Like entry/halt disjointness this quantifies only over edges from
/// OUTSIDE the orbit, so it never has to tell a back edge from a body-internal one.
fn orbit_entry_single_valued<const NA: usize>(h: &Aut<NA>) -> bool {
    orbits(h).iter().all(|&o| orbit_entry_map(h, o).is_ok())
}

/// **REFUTED — unsound.**  10400 / 20020 pool automata, the worst of the three.
/// Counterexample `k=2`, entry `[1,2]`, `s0` stuck, `s1` self-looping at both atoms: the orbit
/// `{s1}` is entered from outside only at atom 1, so the entry map is undefined at atom 0 and
/// the atom-0 self-loop is never deleted.  The loop's `initTrans` is only PARTLY VISIBLE in
/// the graph — the enclosing context never enters at atom 0, so that entry is unobservable.
///
/// Original (wrong) rationale follows.  **Orbit reduction — the Caron and Ziadi shape.**  Repeatedly: take the orbits of
/// the surviving graph; for each, delete every edge from inside it that lands on its entry
/// state for that atom — in a genuine `wh g B` those are exactly the back edges, since
/// `loopInitialized` routes each body state's exit through `body.initTrans`.  Then recurse,
/// which is what peels nested loops.  A Thompson automaton must reduce to an acyclic graph.
///
/// The deletion can also remove a body-internal edge that happens to land on the entry state,
/// because the graph cannot distinguish the two.  That over-deletion only makes breaking the
/// cycle EASIER, so the test stays necessary — it can reject, never wrongly accept.  Trading
/// completeness for soundness this way is what the flat stability test got backwards.
fn orbit_reduces<const NA: usize>(h: &Aut<NA>) -> bool {
    let k = h.k as usize;
    let mut st = h.st;
    for _ in 0..(MAXK + 1) {
        let cur = Aut::<NA> { k: h.k, it: h.it, st, hl: h.hl, ih: h.ih };
        let os = orbits(&cur);
        if os.is_empty() { return true; }
        let mut cut = false;
        for &o in os.iter() {
            let ent = match orbit_entry_map(&cur, o) { Ok(e) => e, Err(()) => return false };
            for u in 0..k {
                if o & (1 << u) == 0 { continue; }
                for y in 0..NA {
                    if st[u][y] == 0 { continue; }
                    if (st[u][y] - 1) as usize == ent[y] { st[u][y] = 0; cut = true; }
                }
            }
        }
        // an orbit no edge of which points at its own entry cannot be a loop body
        if !cut { return false; }
    }
    false
}

/// **LLEE, done properly — per-vertex loop-subchart elimination.**
///
/// Grabmayer and Fokkink: a chart has LEE if repeatedly eliminating LOOP SUBCHARTS leaves a
/// chart with no infinite path, and every prechart with (layered) LEE admits a UNIQUE
/// solution.  A loop chart has a single start vertex `v` such that every infinite path from
/// `v` returns to `v`; the transitions out of `v` are the loop-entry transitions.
///
/// The earlier vacuous version forced ONE entry to serve a whole SCC, which is wrong: an SCC
/// can need several nested eliminations.  `wh 1 (p +_b q)` is the smallest witness — two
/// mutually-reachable states, each self-looping, so no single vertex carries every cycle, yet
/// it is plainly Thompson.  Peeling per VERTEX, innermost first, handles it.
///
/// The GKAT termination clause is the visible form of `loopInitialized`: halting inside the
/// body is `body.hlt ∧ ¬g` and the back edge is `body.hlt ∧ g`, so the atoms at which body
/// states halt must be disjoint from the atoms at which they take back edges.
static LLEE_MEMO: std::sync::OnceLock<(
    std::collections::hash_map::RandomState,
    std::collections::hash_map::RandomState,
    Vec<std::sync::Mutex<FxMap<(u64, u64), bool>>>,
)> = std::sync::OnceLock::new();

/// Memoized like `symbolic_eliminable`: LLEE is a pure function of the automaton.
fn llee<const NA: usize>(h: &Aut<NA>) -> bool {
    use std::hash::BuildHasher;
    let (h1, h2, shards) = LLEE_MEMO.get_or_init(|| {
        (std::collections::hash_map::RandomState::new(),
         std::collections::hash_map::RandomState::new(),
         (0..64).map(|_| std::sync::Mutex::new(FxMap::default())).collect())
    });
    let key = (h1.hash_one(&(NA as u64, h)), h2.hash_one(&(NA as u64, h)));
    let shard = &shards[(key.0 as usize) & 63];
    if let Some(&v) = shard.lock().unwrap().get(&key) { return v; }
    let mut budget = std::env::var("PAD_LLEE_BUDGET").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(200000usize);
    let v = llee_go(h, h.st, &mut budget);
    shard.lock().unwrap().insert(key, v);
    v
}

/// LLEE is an EXISTENTIAL property — a witness labelling has to exist — so deciding it is a
/// search with backtracking, not a greedy peel.  Committing to the first eliminable loop
/// subchart can block every later one, which is why the greedy version rejected Thompson
/// automata that are LLEE by construction (`GkatLayeringProofs`).
fn llee_go<const NA: usize>(h: &Aut<NA>, st: [[u8; NA]; MAXK], budget: &mut usize) -> bool {
    let k = h.k as usize;
    let cur = Aut::<NA> { k: h.k, it: h.it, st, hl: h.hl, ih: h.ih };
    if orbits(&cur).is_empty() { return true; }
    if *budget == 0 { return false; }
    *budget -= 1;
    bump(&CALC_NODES);
    let mut ent = [usize::MAX; NA];
    loop {
        let mut carry = 0usize;
        while carry < NA {
            ent[carry] = if ent[carry] == usize::MAX { 0 } else { ent[carry] + 1 };
            if ent[carry] < k { break; }
            ent[carry] = usize::MAX; carry += 1;
        }
        if carry >= NA { return false; }
        if (0..NA).all(|y| ent[y] == usize::MAX) { continue; }

        let mut isent = 0u16;
        for y in 0..NA { if ent[y] != usize::MAX { isent |= 1 << ent[y]; } }

        for sub in 1u32..(1u32 << NA) {
            let mut inl = isent;
            let mut stack: Vec<usize> = Vec::new();
            for v in 0..k {
                if isent & (1 << v) == 0 { continue; }
                for y in 0..NA {
                    if sub & (1 << y) == 0 || st[v][y] == 0 { continue; }
                    let t = (st[v][y] - 1) as usize;
                    if inl & (1 << t) == 0 { inl |= 1 << t; stack.push(t); }
                }
            }
            while let Some(u) = stack.pop() {
                for y in 0..NA {
                    if st[u][y] == 0 { continue; }
                    let t = (st[u][y] - 1) as usize;
                    if isent & (1 << t) != 0 { continue; }
                    if inl & (1 << t) == 0 { inl |= 1 << t; stack.push(t); }
                }
            }
            // "until the entry is reached again": stop AT an entry target, and keep only
            // states that can get back to one
            {
                let mut canret = isent;
                let mut changed = true;
                while changed {
                    changed = false;
                    for u in 0..k {
                        if inl & (1 << u) == 0 || canret & (1 << u) != 0 { continue; }
                        for y in 0..NA {
                            if st[u][y] == 0 { continue; }
                            let t = (st[u][y] - 1) as usize;
                            if canret & (1 << t) != 0 { canret |= 1 << u; changed = true; break; }
                        }
                    }
                }
                inl &= canret;
            }
            if inl == 0 { continue; }

            let mut back = 0u32;
            let mut nback = 0usize;
            let mut cut = st;
            for u in 0..k {
                if inl & (1 << u) == 0 { continue; }
                for y in 0..NA {
                    if ent[y] == usize::MAX || st[u][y] == 0 { continue; }
                    if (st[u][y] - 1) as usize == ent[y] {
                        back |= 1 << y; nback += 1; cut[u][y] = 0;
                    }
                }
            }
            if nback == 0 { continue; }
            if !acyclic_on(&cut, k, inl) { continue; }
            // control leaves the body only OFF the back-edge atoms: in `seq (wh g B) C` a
            // body state exits guarded by `B.hlt u ∧ ¬g` and loops back on `B.hlt u ∧ g`
            let mut exits = 0u32;
            for u in 0..k {
                if inl & (1 << u) == 0 { continue; }
                exits |= h.hl[u] as u32;
                for y in 0..NA {
                    if st[u][y] == 0 { continue; }
                    let t = (st[u][y] - 1) as usize;
                    if inl & (1 << t) == 0 { exits |= 1 << y; }
                }
            }
            if exits & back != 0 { continue; }

            if llee_go(h, cut, budget) { return true; }
        }
    }
}

/// Is the subgraph induced on `mask` acyclic?  Used for "every infinite path returns to v":
/// the loop body with the entry vertex removed must have no cycle of its own.
fn acyclic_on<const NA: usize>(st: &[[u8; NA]; MAXK], k: usize, mask: u16) -> bool {
    let mut reach = [0u16; MAXK];
    for i in 0..k {
        if mask & (1 << i) == 0 { continue; }
        for y in 0..NA {
            if st[i][y] == 0 { continue; }
            let t = (st[i][y] - 1) as usize;
            if mask & (1 << t) != 0 { reach[i] |= 1 << t; }
        }
    }
    for m in 0..k {
        for i in 0..k {
            if reach[i] & (1 << m) != 0 { reach[i] |= reach[m]; }
        }
    }
    (0..k).all(|i| mask & (1 << i) == 0 || reach[i] & (1 << i) == 0)
}

/// **Peelable — is the automaton's equation system solvable by Gaussian elimination?**
///
/// This is the object the problem actually turns on.  Pham's thesis section 4.3.3 shows the
/// peeling argument is not restricted to Thompson automata: it solves a non-Thompson system
/// by substituting, reducing to a SINGLE-VARIABLE fixpoint `s(b) ≡ q·s(b) +_β α`, and
/// applying W0 — which this development now has as a derived law (`GkatW0Proofs`).  And the
/// standing obstruction in the literature is exactly the absence of such a procedure: "some
/// systems of equations do not have any solution, and the lack of a procedure to construct
/// solutions encumbers a proof of uniqueness".
///
/// A state can be peeled when every atom sends it to ITSELF or to an already-solved state.
/// Its equation is then `s(x) ≡ e·s(x) +_b f` with `b` the atoms that return to `x` and `f`
/// built from solved states — precisely W0's shape, so W0 solves it outright.  Determinism is
/// what makes this work: each atom has exactly one successor, so substitution never needs the
/// `+` that GKAT does not have.
///
/// Failure is mutual recursion — two states each waiting on the other — which is the same
/// condition as "loops mutually nested", the LLEE failure.  Unlike every oracle tried so far,
/// this is SOUND for the purpose at hand rather than merely necessary: a peeling order is a
/// CONSTRUCTION of a solution, not evidence that one might exist.
fn peelable<const NA: usize>(h: &Aut<NA>) -> bool {
    let k = h.k as usize;
    let mut solved = 0u16;
    for _ in 0..=k {
        let mut found = false;
        for x in 0..k {
            if solved & (1 << x) != 0 { continue; }
            // Substitution keeps the shape only when the eliminated variable's solution
            // puts the remaining variable in TAIL position.  GKAT has no left distribution —
            // `left_distrib_fails` is proved in GkatGuardedStringProofs — so `p·(u +_c v)`
            // cannot be rearranged to isolate a variable inside a branch.  A state with at
            // most one unsolved non-self successor substitutes as a prefix `p` (or `q·p`,
            // by associativity S1) and leaves the successor at the tail, which is exactly
            // W0's shape.  Two distinct unsolved successors would put a branch under a
            // prefix, and nothing in GKAT can pull the variable back out.
            let mut outs = 0u16;
            for y in 0..NA {
                if h.st[x][y] == 0 { continue; }
                let t = (h.st[x][y] - 1) as usize;
                if t != x && solved & (1 << t) == 0 { outs |= 1 << t; }
            }
            if outs.count_ones() <= 1 { solved |= 1 << x; found = true; }
        }
        if !found { break; }
    }
    solved.count_ones() as usize == k
}

/// Largest bisimulation by partition refinement — the standard GKAT minimization.  Returns
/// the block index of each state and the block count.
fn bisim_blocks<const NA: usize>(h: &Aut<NA>) -> ([usize; MAXK], usize) {
    let k = h.k as usize;
    let mut blk = [0usize; MAXK];
    // initial partition: by halt mask, and by which atoms have a transition at all
    let mut sig0: Vec<(u8, u32)> = Vec::new();
    for x in 0..k {
        let mut def = 0u32;
        for y in 0..NA { if h.st[x][y] != 0 { def |= 1 << y; } }
        let s = (h.hl[x], def);
        blk[x] = match sig0.iter().position(|&t| t == s) {
            Some(i) => i,
            None => { sig0.push(s); sig0.len() - 1 }
        };
    }
    let mut nb = sig0.len();
    loop {
        let mut sig: Vec<(usize, [usize; NA])> = Vec::new();
        let mut nblk = [0usize; MAXK];
        for x in 0..k {
            let mut succ = [usize::MAX; NA];
            for y in 0..NA {
                if h.st[x][y] != 0 { succ[y] = blk[(h.st[x][y] - 1) as usize]; }
            }
            let s = (blk[x], succ);
            nblk[x] = match sig.iter().position(|t| *t == s) {
                Some(i) => i,
                None => { sig.push(s); sig.len() - 1 }
            };
        }
        if sig.len() == nb { return (blk, nb); }
        blk = nblk; nb = sig.len();
    }
}

/// **Symbolic elimination — does Gaussian elimination actually solve the system?**
///
/// This decides by the ALGEBRA rather than by a graph proxy, which is the one direction five
/// graph predicates did not refute.  The tracked state is, for each variable and atom, the
/// set of variables appearing at the leaves of that branch.
///
/// A variable `x` can be isolated exactly when, at every atom whose branch mentions `x`, `x`
/// is the ONLY variable there.  That is U5 read backwards: `(A·s(x)) +_b (B·s(x))` collapses
/// to `(A +_b B)·s(x)`, so a common tail can be pulled out of a branch — but a branch with
/// two DIFFERENT variables at its leaves cannot be, since GKAT has no left distribution
/// (`left_distrib_fails`, proved).  Once isolated the equation is `e·s(x) +_b f`, which is
/// W0's shape, and W0 is now a derived law here.
///
/// It runs on the BISIMULATION QUOTIENT, and that is not an optimisation.
/// `wh 1 ((p +_b q);(r +_b t))` is Thompson yet defeats elimination state-by-state, because
/// the two branch states are bisimilar and their solutions coincide; on the quotient the
/// same system eliminates in two steps.
static ELIM_MEMO: std::sync::OnceLock<(
    std::collections::hash_map::RandomState,
    std::collections::hash_map::RandomState,
    Vec<std::sync::Mutex<FxMap<(u64, u64), bool>>>,
)> = std::sync::OnceLock::new();
static ELIM_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ELIM_HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Memoized: eliminability is a pure function of the automaton, and the same canonical
/// quotients recur across hundreds of thousands of crux pairs.  128-bit fingerprint keys,
/// 64 shards.  Every 5M calls the hit rate goes to stderr — the progress telemetry the
/// silent phases lacked.
fn symbolic_eliminable<const NA: usize>(h: &Aut<NA>) -> bool {
    use std::hash::BuildHasher;
    use std::sync::atomic::Ordering;
    let (h1, h2, shards) = ELIM_MEMO.get_or_init(|| {
        (std::collections::hash_map::RandomState::new(),
         std::collections::hash_map::RandomState::new(),
         (0..64).map(|_| std::sync::Mutex::new(FxMap::default())).collect())
    });
    let key = (h1.hash_one(&(NA as u64, h)), h2.hash_one(&(NA as u64, h)));
    let shard = &shards[(key.0 as usize) & 63];
    let calls = ELIM_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if calls % 100_000 == 0 {
        let hits = ELIM_HITS.load(Ordering::Relaxed);
        eprintln!("[elim] {}k calls, {:.1}% memo hits", calls / 1_000,
            100.0 * hits as f64 / calls as f64);
    }
    if let Some(&v) = shard.lock().unwrap().get(&key) {
        ELIM_HITS.fetch_add(1, Ordering::Relaxed);
        return v;
    }
    let v = symbolic_eliminable_gen(h, true);
    shard.lock().unwrap().insert(key, v);
    v
}

fn symbolic_eliminable_raw<const NA: usize>(h: &Aut<NA>) -> bool {
    symbolic_eliminable_gen(h, false)
}

/// **Symbolic elimination, with leaves indexed by the ATOM THEY ARE REACHED AT.**
///
/// The previous abstraction collapsed each branch to one variable set plus a halt flag.  That
/// loses the fact the loop case turns on: in `wh g B` a body state halts on `body.hlt ∧ ¬g` and
/// takes its back edge on `body.hlt ∧ g`, so the halt leaves and the back-edge leaves sit at
/// DISJOINT atoms.  Collapsed together they look like "a branch with both a variable and a
/// halt", which blocks U5; kept apart they are exactly `e·s(Z) +_g f`, which is W0's shape.
///
/// So a branch is now a map from leaf-atom to leaf-kind: `vv[x][y][β]` is the set of variables
/// at leaves reached at atom β, and `hh[x][y][β]` records a halt leaf there.
fn symbolic_eliminable_gen<const NA: usize>(h: &Aut<NA>, collapse: bool) -> bool {
    let (blk, nb) = if collapse {
        bisim_blocks(h)
    } else {
        let mut b = [0usize; MAXK];
        for x in 0..h.k as usize { b[x] = x; }
        (b, h.k as usize)
    };
    let k = h.k as usize;
    if nb > 16 { return false; }
    let mut vv = [[[0u16; NA]; NA]; MAXK];
    let mut hh = [[[false; NA]; NA]; MAXK];
    for x in 0..k {
        let bx = blk[x];
        for y in 0..NA {
            if h.st[x][y] != 0 {
                let t = blk[(h.st[x][y] - 1) as usize];
                // the successor is entered after an action, at an unconstrained atom
                for beta in 0..NA { vv[bx][y][beta] |= 1 << t; }
            } else if h.hl[x] & (1 << y) != 0 {
                // a halt leaf, reached at the atom the branch is taken at
                hh[bx][y][y] = true;
            }
        }
    }
    let mut budget = std::env::var("PAD_ELIM_BUDGET").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(2000000usize);
    // Depth 2 was measured to rescue NOTHING — pool completeness 19718/20020 and
    // sum-quotients 9221/9245 both unchanged — while nesting the entry-list enumeration,
    // which is ~nb^NA per level and dominates on the 10-state sums.  Keep depth 1.
    try_entries::<NA>(&mut vv, &mut hh, nb, &mut budget, 1)
}

/// Introduce loop-entry variables, up to `depth` of them.
///
/// One `Z` suffices for a single loop, but a NESTED loop needs one per level: the inner body
/// must be solved as a unit before the outer entry can be, and each is a pseudostate with no
/// variable of its own.  Since the stalls are overwhelmingly multi-exit loops, allowing more
/// than one is the natural place to look for the procedure's missing completeness.
fn try_entries<const NA: usize>(vv: &mut [[[u16; NA]; NA]; MAXK],
    hh: &mut [[[bool; NA]; NA]; MAXK], nb: usize, budget: &mut usize, depth: usize) -> bool {
    if elim2::<NA>(&mut vv.clone(), &mut hh.clone(), (1u16 << nb) - 1, nb, budget) {
        return true;
    }
    if depth == 0 || nb + 1 > MAXK { return false; }
    let mut ent = [usize::MAX; NA];
    loop {
        let mut carry = 0usize;
        while carry < NA {
            ent[carry] = if ent[carry] == usize::MAX { 0 } else { ent[carry] + 1 };
            if ent[carry] < nb { break; }
            ent[carry] = usize::MAX; carry += 1;
        }
        if carry >= NA { return false; }
        if (0..NA).all(|y| ent[y] == usize::MAX) { continue; }
        let z = nb;
        let mut v2 = *vv;
        let mut h2 = *hh;
        for y in 0..NA {
            for beta in 0..NA {
                v2[z][y][beta] = if ent[y] == usize::MAX { 0 } else { 1 << ent[y] };
                h2[z][y][beta] = false;
            }
        }
        for x in 0..z {
            for y in 0..NA {
                if ent[y] == usize::MAX { continue; }
                let all_entry = (0..NA).all(|beta|
                    v2[x][y][beta] == (1 << ent[y]) && !h2[x][y][beta]);
                if all_entry {
                    for beta in 0..NA { v2[x][y][beta] = 1 << z; }
                }
            }
        }
        if *budget == 0 { return false; }
        if try_entries::<NA>(&mut v2, &mut h2, z + 1, budget, depth - 1) { return true; }
    }
}

fn elim_ka<const NA: usize>(vv: &mut [[[u16; NA]; NA]; MAXK], hh: &mut [[[bool; NA]; NA]; MAXK],
    live: u16, nb: usize, budget: &mut usize, ka_left: usize) -> bool {
    if live == 0 { return true; }
    if *budget == 0 { return false; }
    *budget -= 1;
    bump(&CALC_NODES);
    for relaxed in [false, true] {
        if relaxed && ka_left == 0 { continue; }
        for x in 0..nb {
            if live & (1 << x) == 0 { continue; }
            let mut strict = true;
            'chk: for y in 0..NA {
                for beta in 0..NA {
                    if vv[x][y][beta] & (1 << x) != 0
                        && (vv[x][y][beta] != (1 << x) || hh[x][y][beta]) { strict = false; break 'chk; }
                }
            }
            if relaxed == strict { continue; }
            let mut solv = [[0u16; NA]; NA];
            let mut solh = [[false; NA]; NA];
            for al in 0..NA {
                for beta in 0..NA {
                    solv[al][beta] = vv[x][al][beta] & !(1 << x);
                    solh[al][beta] = hh[x][al][beta];
                }
            }
            for _ in 0..(NA + 1) {
                for al in 0..NA {
                    for gam in 0..NA {
                        if vv[x][al][gam] & (1 << x) == 0 { continue; }
                        for beta in 0..NA {
                            solv[al][beta] |= solv[gam][beta];
                            if solh[gam][beta] { solh[al][beta] = true; }
                        }
                    }
                }
            }
            let saved = *vv; let savedh = *hh;
            for z in 0..nb {
                if live & (1 << z) == 0 || z == x { continue; }
                for y in 0..NA {
                    let mut nv = [0u16; NA]; let mut nh = [false; NA];
                    for beta in 0..NA { nv[beta] = vv[z][y][beta] & !(1 << x); nh[beta] = hh[z][y][beta]; }
                    for al in 0..NA {
                        if vv[z][y][al] & (1 << x) == 0 { continue; }
                        for beta in 0..NA {
                            nv[beta] |= solv[al][beta];
                            if solh[al][beta] { nh[beta] = true; }
                        }
                    }
                    for beta in 0..NA { vv[z][y][beta] = nv[beta]; hh[z][y][beta] = nh[beta]; }
                }
            }
            let next_ka = if relaxed { ka_left - 1 } else { ka_left };
            if elim_ka::<NA>(vv, hh, live & !(1 << x), nb, budget, next_ka) { return true; }
            *vv = saved; *hh = savedh;
        }
    }
    false
}

fn elim2<const NA: usize>(vv: &mut [[[u16; NA]; NA]; MAXK], hh: &mut [[[bool; NA]; NA]; MAXK],
    live: u16, nb: usize, budget: &mut usize) -> bool {
    if live == 0 { return true; }
    if *budget == 0 { return false; }
    *budget -= 1;
    bump(&CALC_NODES);
    for x in 0..nb {
        if live & (1 << x) == 0 { continue; }
        // U5 pulls a common tail out of a branch only when, AT EACH LEAF-ATOM, the tail is the
        // only thing there: no second variable and no halt.
        let mut ok = true;
        'chk: for y in 0..NA {
            for beta in 0..NA {
                if vv[x][y][beta] & (1 << x) != 0
                    && (vv[x][y][beta] != (1 << x) || hh[x][y][beta]) { ok = false; break 'chk; }
            }
        }
        if !ok { continue; }
        // x's solution, PER START ATOM.  Unioning across start atoms would throw away exactly
        // the precision this representation exists for.  `solv[α][β]` is where `s(x)` started
        // at α can leave a leaf at β; the loop closure accounts for x re-entering itself.
        let mut solv = [[0u16; NA]; NA];
        let mut solh = [[false; NA]; NA];
        for al in 0..NA {
            for beta in 0..NA {
                solv[al][beta] = vv[x][al][beta] & !(1 << x);
                solh[al][beta] = hh[x][al][beta];
            }
        }
        for _ in 0..(NA + 1) {
            for al in 0..NA {
                for gam in 0..NA {
                    if vv[x][al][gam] & (1 << x) == 0 { continue; }
                    for beta in 0..NA {
                        solv[al][beta] |= solv[gam][beta];
                        if solh[gam][beta] { solh[al][beta] = true; }
                    }
                }
            }
        }
        let saved = *vv;
        let savedh = *hh;
        for z in 0..nb {
            if live & (1 << z) == 0 || z == x { continue; }
            for y in 0..NA {
                let mut nv = [0u16; NA];
                let mut nh = [false; NA];
                for beta in 0..NA {
                    nv[beta] = vv[z][y][beta] & !(1 << x);
                    nh[beta] = hh[z][y][beta];
                }
                for al in 0..NA {
                    if vv[z][y][al] & (1 << x) == 0 { continue; }
                    for beta in 0..NA {
                        nv[beta] |= solv[al][beta];
                        if solh[al][beta] { nh[beta] = true; }
                    }
                }
                for beta in 0..NA { vv[z][y][beta] = nv[beta]; hh[z][y][beta] = nh[beta]; }
            }
        }
        if elim2::<NA>(vv, hh, live & !(1 << x), nb, budget) { return true; }
        *vv = saved; *hh = savedh;
    }
    false
}

/// Disjoint sum of two automata's core systems.  This is the object the completeness route
/// actually needs: `Me + Mf`, whose bisimulation quotient must have a solution.  The
/// pseudostates play no part in whether the core system is solvable, so only cores are summed.
/// `InitializedGAut.toGAut`: adjoin the pseudostate as a real state, with the initial
/// transitions and the initial halt guard.  The Lean statement `SumQuotientSolvable` sums the
/// TO-GAUT versions, so summing cores alone measures a different object — the initial dynamics
/// are exactly where `e` and `f` differ, and dropping them drops the states the completeness
/// argument identifies.
fn to_gaut<const NA: usize>(a: &Aut<NA>) -> Option<Aut<NA>> {
    let k = a.k as usize;
    if k + 1 > MAXK { return None; }
    let mut st = [[0u8; NA]; MAXK];
    let mut hl = [0u8; MAXK];
    // state 0 is the pseudostate; old state i becomes i+1
    hl[0] = a.ih;
    for y in 0..NA { st[0][y] = if a.it[y] == 0 { 0 } else { a.it[y] + 1 }; }
    for x in 0..k {
        hl[x + 1] = a.hl[x];
        for y in 0..NA { st[x + 1][y] = if a.st[x][y] == 0 { 0 } else { a.st[x][y] + 1 }; }
    }
    let mut it = [0u8; NA];
    for y in 0..NA { it[y] = 1; }
    Some(Aut { k: (k + 1) as u8, it, ih: 0, st, hl })
}

fn sum_core<const NA: usize>(a: &Aut<NA>, b: &Aut<NA>) -> Option<Aut<NA>> {
    let a = &to_gaut(a)?;
    let b = &to_gaut(b)?;
    let (ka, kb) = (a.k as usize, b.k as usize);
    if ka + kb > MAXK { return None; }
    let mut st = [[0u8; NA]; MAXK];
    let mut hl = [0u8; MAXK];
    for x in 0..ka {
        hl[x] = a.hl[x];
        for y in 0..NA { st[x][y] = a.st[x][y]; }
    }
    for x in 0..kb {
        hl[ka + x] = b.hl[x];
        for y in 0..NA {
            st[ka + x][y] = if b.st[x][y] == 0 { 0 } else { b.st[x][y] + ka as u8 };
        }
    }
    Some(Aut { k: (ka + kb) as u8, it: a.it, ih: a.ih, st, hl })
}

/// Collapse an automaton by a block map — the bisimulation quotient as an automaton.
fn quotient_by<const NA: usize>(h: &Aut<NA>, blk: &[usize; MAXK], nb: usize) -> Option<Aut<NA>> {
    if nb > MAXK { return None; }
    let k = h.k as usize;
    let mut st = [[0u8; NA]; MAXK];
    let mut hl = [0u8; MAXK];
    for x in 0..k {
        let b = blk[x];
        hl[b] = h.hl[x];
        for y in 0..NA {
            st[b][y] = if h.st[x][y] == 0 { 0 } else { (blk[(h.st[x][y] - 1) as usize] + 1) as u8 };
        }
    }
    let mut it = [0u8; NA];
    for y in 0..NA {
        it[y] = if h.it[y] == 0 { 0 } else { (blk[(h.it[y] - 1) as usize] + 1) as u8 };
    }
    Some(Aut { k: nb as u8, it, ih: h.ih, st, hl })
}

/// **The degree of the adjunction.**  Elimination over a FIELD needs only division; over a
/// RING it stalls, and the classical repair is to adjoin — to look for zeros "in an overfield,
/// or even in an arbitrary algebra" — rather than to divide.  GKAT is the ring-like case: it
/// has no left distribution, so `(A·s(x)) +_b 1` cannot be factored, and elimination stalls
/// exactly there.
///
/// The GKAT analogue of adjoining an element is introducing an AUXILIARY STATE — splitting a
/// shared state so the two uses can be solved separately.  That is precisely Ashcroft and
/// Manna's result that auxiliary variables are unavoidable for restructuring, and Kozen and
/// Tseng's that they cannot be dispensed with propositionally.
///
/// So the invariant to measure is the DEGREE: how many adjunctions before the system becomes
/// solvable by elimination.  Degree 0 is "already solvable"; a small uniform bound would be a
/// structure theorem; unbounded degree is the obstruction itself.
fn elim_degree<const NA: usize>(h: &Aut<NA>, maxd: usize) -> Option<usize> {
    let mut cur = *h;
    for d in 0..=maxd {
        if symbolic_eliminable(&cur) { return Some(d); }
        match unshare(&cur) {
            Some(next) => { cur = next; }
            None => return None,
        }
    }
    None
}

/// Adjoin a BOOLEAN FLAG: the two-fold product `A × {0,1}` in which the program may set the
/// flag freely on every transition, while halting is inherited from `A`.  Projection is a
/// cover, so anything provable about the product transfers.  This is Böhm and Jacopini's
/// auxiliary variable at the automaton level — a genuinely NEW element, as opposed to
/// `unshare`, which only adjoins a copy and was measured to help on 0 of 462.
fn flag_product<const NA: usize>(a: &Aut<NA>, choice: u64) -> Option<Aut<NA>> {
    let k = a.k as usize;
    if 2 * k > MAXK { return None; }
    let mut st = [[0u8; NA]; MAXK];
    let mut hl = [0u8; MAXK];
    let mut bit = 0usize;
    for x in 0..k {
        for f in 0..2usize {
            let idx = x * 2 + f;
            hl[idx] = a.hl[x];
            for y in 0..NA {
                if a.st[x][y] == 0 { st[idx][y] = 0; continue; }
                let nx = (a.st[x][y] - 1) as usize;
                let nf = ((choice >> (bit % 64)) & 1) as usize;
                bit += 1;
                st[idx][y] = (nx * 2 + nf + 1) as u8;
            }
        }
    }
    let mut it = [0u8; NA];
    for y in 0..NA {
        it[y] = if a.it[y] == 0 { 0 } else { ((a.it[y] - 1) as usize * 2 + 1) as u8 };
    }
    Some(Aut { k: (2 * k) as u8, it, ih: a.ih, st, hl })
}

/// **The minimal intermediate quotient.**  Grabmayer's crystallization: LLEE is not closed
/// under bisimulation collapse, so do not fully collapse — perform a layering-preserving NEAR
/// collapse and land back inside the well-behaved class.  Read as a Galois picture, the
/// bisimulations of an automaton form a lattice between the identity and the largest one, and
/// full collapse is the top of it.  The completeness argument does not need the top: it needs
/// only enough to identify the two start states.
///
/// So this computes the SMALLEST congruence identifying them — merge the two initial targets
/// at each atom, then close under "if x ~ y then succ(x,·) ~ succ(y,·)" — which is the
/// intermediate quotient nearest the bottom of the lattice, adjoining only what is required.
/// The block map of the MINIMAL congruence identifying the two initial dispatches —
/// `min_congruence`'s computation, stopping before it builds the quotient automaton.
/// 330 needs the blocks themselves, to ask which halves each class draws from.
fn min_congruence_blocks<const NA: usize>(a: &Aut<NA>, b: &Aut<NA>)
    -> Option<([usize; MAXK], usize, usize)> {
    let su = sum_core(a, b)?;
    let ka = a.k as usize;
    let n = su.k as usize;
    let mut par: Vec<usize> = (0..n).collect();
    fn find(par: &mut Vec<usize>, x: usize) -> usize {
        let mut r = x;
        while par[r] != r { r = par[r]; }
        let mut c = x;
        while par[c] != c { let nx = par[c]; par[c] = r; c = nx; }
        r
    }
    let mut work: Vec<(usize, usize)> = Vec::new();
    for y in 0..NA {
        if a.it[y] != 0 && b.it[y] != 0 {
            work.push(((a.it[y] - 1) as usize, (b.it[y] - 1) as usize + ka));
        }
    }
    while let Some((x, y)) = work.pop() {
        let (rx, ry) = (find(&mut par, x), find(&mut par, y));
        if rx == ry { continue; }
        if su.hl[x] != su.hl[y] { return None; }
        par[rx] = ry;
        for t in 0..NA {
            let (sx, sy) = (su.st[x][t], su.st[y][t]);
            if sx == 0 && sy == 0 { continue; }
            if sx == 0 || sy == 0 { return None; }
            work.push(((sx - 1) as usize, (sy - 1) as usize));
        }
    }
    let mut blk = [0usize; MAXK];
    let mut seen: Vec<usize> = Vec::new();
    for x in 0..n {
        let r = find(&mut par, x);
        blk[x] = match seen.iter().position(|&t| t == r) {
            Some(i) => i,
            None => { seen.push(r); seen.len() - 1 }
        };
    }
    Some((blk, seen.len(), ka))
}

/// **`PAD_SCC_EXIT`** (iteration 332).
///
/// 331 proposed decomposing a quotient along its own SCC condensation and named
/// the obstacle: `SeqLayer`'s shape demands the exits from a strongly connected
/// region be ONE SHARED entry list, gated by each state's own halt.  The
/// sharpest necessary condition of that shape, in the per-atom representation,
/// is simple: **all states of an SCC that exit on the SAME ATOM must exit to the
/// SAME TARGET.**  If two do not, no shared entry list exists and the shape
/// fails outright.
///
/// Measured on the QUOTIENT — build the automaton, collapse it, and ask the
/// question of the collapsed object, since that is what the proof must
/// decompose.
fn scc_exit<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    { let a = a_act::<NA>(); if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
    for _ in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for r in &cur {
                if let Some(a) = a_seq::<NA>(l, r) {
                    if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
                }
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
                    }
                }
            }
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
            }
        }
        if pool.len() >= cap { break; }
    }
    let (mut sccs, mut with_exit, mut conflict) = (0usize, 0usize, 0usize);
    let mut first: Option<String> = None;
    for a in &pool {
        let (blk, nb) = bisim_blocks(a);
        let Some(q) = quotient_by(a, &blk, nb) else { continue };
        for o in orbits(&q) {
            sccs += 1;
            let mut exits = false;
            let mut bad = false;
            for i in 0..NA {
                let mut tgt: Option<usize> = None;
                for u in 0..q.k as usize {
                    if o & (1u16 << u) == 0 { continue; }
                    let tv = q.st[u][i];
                    if tv == 0 { continue; }
                    let t = (tv - 1) as usize;
                    if o & (1u16 << t) != 0 { continue; }   // stays inside the SCC
                    exits = true;
                    match tgt {
                        None => tgt = Some(t),
                        Some(t0) => if t0 != t { bad = true; },
                    }
                }
            }
            if exits { with_exit += 1; }
            if bad {
                conflict += 1;
                if first.is_none() {
                    first = Some(format!("SCC mask {o:b}\n    {}", show_aut("quot ", &q)));
                }
            }
        }
    }
    println!("SCC EXIT: {sccs} SCCs in quotients, {with_exit} with an exit, \
              {conflict} where two states exit on the SAME ATOM to DIFFERENT TARGETS \
              ({:.2}% of those with an exit)",
        100.0 * conflict as f64 / with_exit.max(1) as f64);
    match first {
        None => println!("  no conflict: every SCC's exits are per-atom single-valued, which \
                          is what a SHARED entry list needs"),
        Some(msg) => println!("  FIRST CONFLICT\n    {msg}"),
    }
}

/// The standard census pool: every automaton reachable from tests and the single
/// action by `seq`/`ite`/`wh`, up to `cap`, deduplicated by canonical form.
fn build_pool<const NA: usize>(nguards: u8, rounds: usize, cap: usize) -> Vec<Aut<NA>> {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    { let a = a_act::<NA>(); if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
    for _ in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for r in &cur {
                if let Some(a) = a_seq::<NA>(l, r) {
                    if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
                }
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
                    }
                }
            }
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
            }
        }
        if pool.len() >= cap { break; }
    }
    pool
}

/// **`PAD_STRONGAGREE`** (iteration 359).
///
/// A worry raised by 358's corrected picture.  The Lean `LevelAgreement` says:
/// if ONE state of a level fires a non-raw transition to `r`, then EVERY state
/// of that level fires to `r`.  But 358 found that in a loop body only the HEAD
/// is ever non-raw — the others march forward and are raw.  If that is right,
/// then at an atom where the head fires, the non-head states do NOT fire, and
/// the hypothesis as formalised is FALSE.
///
/// Note what 343 actually measured: agreement among states that are neither raw
/// nor dead — i.e. among the ACTIVE ones.  That is the weak form.  The Lean
/// predicate is the strong form.  This measures the strong form directly.
fn strongagree<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let pool = build_pool::<NA>(nguards, rounds, cap);
    let (mut regions, mut checked, mut violated) = (0usize, 0usize, 0usize);
    let mut first: Option<String> = None;
    for a in &pool {
        let (blk, nb) = bisim_blocks(a);
        let Some(q) = quotient_by(a, &blk, nb) else { continue };
        for comp in sccs_of(&q) {
            if comp.len() < 2 { continue; }          // strong form is vacuous on singletons
            regions += 1;
            // best case over rank orderings: does ANY ordering satisfy the STRONG form?
            let m = comp.len();
            let mut perm: Vec<usize> = (0..m).collect();
            let mut any_ok = false;
            loop {
                let mut rank = [0usize; MAXK];
                for (i, &pi) in perm.iter().enumerate() { rank[comp[pi]] = i; }
                let mut ok = true;
                for x in 0..NA {
                    let (mut fires, mut idle) = (0usize, 0usize);
                    for &u in &comp {
                        let tv = q.st[u][x];
                        let active = if tv == 0 { false } else {
                            let t = (tv - 1) as usize;
                            // non-raw = not an intra-region rank-decreasing edge
                            !(comp.contains(&t) && rank[t] < rank[u])
                        };
                        if active { fires += 1; } else { idle += 1; }
                    }
                    if fires > 0 && idle > 0 { ok = false; }
                }
                if ok { any_ok = true; break; }
                if !next_perm(&mut perm) { break; }
            }
            checked += 1;
            if !any_ok {
                violated += 1;
                if first.is_none() {
                    first = Some(format!("region {comp:?}\n    {}", show_aut("quot ", &q)));
                }
            }
        }
    }
    println!("STRONGAGREE: {regions} multi-state quotient regions (strong form is vacuous \
              on singletons, so only these can test it)");
    println!("  {violated} of {checked} ({:.2}%) admit NO rank ordering under which \
              'one fires => all fire' holds at every atom",
        100.0 * violated as f64 / checked.max(1) as f64);
    match first {
        None => println!("  the STRONG form survives: some ordering always makes every region \
                          state fire together"),
        Some(m) => println!("  FIRST VIOLATION — the Lean `LevelAgreement` is UNSATISFIABLE here\n    {m}"),
    }
}

/// **`PAD_SRCEXIT`** (iteration 358).
///
/// The last item needing new mathematics is the structural claim behind
/// `LevelAgreement`: **a loop body has ONE exit continuation.**  Every earlier
/// measurement of exits was taken on QUOTIENTS; the structural claim is about
/// the SOURCE, and it is the source version that an induction on the expression
/// would prove.  So measure it where the claim actually lives.
///
/// Two numbers, because the claim has two readable strengths:
///   * how many DISTINCT targets the edges leaving an SCC have (the claim says 1);
///   * how many distinct STATES of the SCC have any leaving edge at all (the
///     stronger reading: only the loop head exits).
fn srcexit<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let pool = build_pool::<NA>(nguards, rounds, cap);
    let (mut sccs, mut with_exit, mut multi_target, mut multi_source) = (0, 0, 0, 0);
    let (mut maxt, mut maxs) = (0usize, 0usize);
    let mut first: Option<String> = None;
    for a in &pool {
        for comp in sccs_of(a) {
            let selfloop = comp.len() == 1
                && (0..NA).any(|x| a.st[comp[0]][x] == (comp[0] + 1) as u8);
            if comp.len() == 1 && !selfloop { continue; }
            sccs += 1;
            let mut tgts: Vec<usize> = Vec::new();
            let mut srcs: Vec<usize> = Vec::new();
            for &u in &comp {
                for x in 0..NA {
                    let tv = a.st[u][x];
                    if tv == 0 { continue; }
                    let t = (tv - 1) as usize;
                    if comp.contains(&t) { continue; }
                    if !tgts.contains(&t) { tgts.push(t); }
                    if !srcs.contains(&u) { srcs.push(u); }
                }
            }
            if tgts.is_empty() { continue; }
            with_exit += 1;
            if tgts.len() > maxt { maxt = tgts.len(); }
            if srcs.len() > maxs { maxs = srcs.len(); }
            if tgts.len() > 1 {
                multi_target += 1;
                if first.is_none() {
                    first = Some(format!("SCC {comp:?} exits to {tgts:?}\n    {}",
                        show_aut("src  ", a)));
                }
            }
            if srcs.len() > 1 { multi_source += 1; }
        }
    }
    println!("SRCEXIT: {sccs} non-trivial SCCs in Thompson automata, {with_exit} with an exit");
    println!("  {multi_target} have MORE THAN ONE distinct exit target ({:.4}%), max {maxt} \
              — the structural claim says this must be 0",
        100.0 * multi_target as f64 / with_exit.max(1) as f64);
    println!("  {multi_source} have more than one state WITH an exiting edge ({:.2}%), max {maxs} \
              — the stronger 'only the loop head exits' reading",
        100.0 * multi_source as f64 / with_exit.max(1) as f64);
    match first {
        None => println!("  every loop body has a SINGLE exit continuation, as the structural \
                          claim predicts"),
        Some(m) => println!("  FIRST MULTI-TARGET SCC\n    {m}"),
    }
}

/// **`PAD_HALTDET`** (iteration 357).
///
/// 352 introduced `HaltDeterministic` — no state both halts and transitions at
/// the same atom — as a hypothesis, on the grounds that "every guarded automaton
/// has it".  That is an assertion about the corpus's representation, not a
/// theorem, and the peel genuinely needs it: `eqRHS_equiv_of_behaviour` demands
/// the two halt tests agree at EVERY atom, including atoms where a transition
/// fires and the halt test is otherwise irrelevant.  So it is worth checking
/// rather than asserting.
fn haltdet<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let pool = build_pool::<NA>(nguards, rounds, cap);
    let (mut states, mut both, mut qstates, mut qboth) = (0usize, 0usize, 0usize, 0usize);
    let (mut dead, mut qdead) = (0usize, 0usize);
    let mut first: Option<String> = None;
    for a in &pool {
        for u in 0..a.k as usize {
            for x in 0..NA {
                states += 1;
                let halts = (a.hl[u] >> x) & 1 == 1;
                let steps = a.st[u][x] != 0;
                if halts && steps {
                    both += 1;
                    if first.is_none() {
                        first = Some(format!("state q{u} atom {x}\n    {}",
                            show_aut("src  ", a)));
                    }
                }
                if !halts && !steps { dead += 1; }
            }
        }
        let (blk, nb) = bisim_blocks(a);
        let Some(q) = quotient_by(a, &blk, nb) else { continue };
        for u in 0..q.k as usize {
            for x in 0..NA {
                qstates += 1;
                let halts = (q.hl[u] >> x) & 1 == 1;
                let steps = q.st[u][x] != 0;
                if halts && steps { qboth += 1; }
                if !halts && !steps { qdead += 1; }
            }
        }
    }
    println!("HALTDET: {states} (state, atom) pairs in Thompson automata, \
              {qstates} in their quotients");
    println!("  BOTH halts and steps: {both} source ({:.4}%), {qboth} quotient ({:.4}%) \
              — must be 0 for HaltDeterministic",
        100.0 * both as f64 / states.max(1) as f64,
        100.0 * qboth as f64 / qstates.max(1) as f64);
    println!("  neither (DEAD): {dead} source ({:.2}%), {qdead} quotient ({:.2}%) \
              — dead atoms are legal and 343 relies on them",
        100.0 * dead as f64 / states.max(1) as f64,
        100.0 * qdead as f64 / qstates.max(1) as f64);
    match first {
        None => println!("  HaltDeterministic holds throughout: halting and stepping are \
                          exclusive at every atom, source and quotient alike"),
        Some(m) => println!("  FIRST VIOLATION\n    {m}"),
    }
}

/// **`PAD_LOOPMERGE`** (iteration 354).
///
/// 353 found the mechanism behind `LevelAgreement`: an SCC in GKAT comes from a
/// while-loop, and a while-loop has exactly ONE exit continuation, so a region's
/// exits agree structurally rather than accidentally.  That argument has one
/// weak joint — the collapse.  If a bisimulation quotient ever merged states
/// from TWO different loops into a single SCC, that SCC would inherit two exit
/// continuations and the structural argument would break.
///
/// This measures the joint directly: for each non-trivial SCC of a quotient,
/// how many distinct non-trivial SCCs of the SOURCE automaton its preimage
/// spans.  Two or more is a merge.
fn loopmerge<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let pool = build_pool::<NA>(nguards, rounds, cap);
    let (mut qsccs, mut merged, mut merged_conflict) = (0usize, 0usize, 0usize);
    let mut cross_loop = 0usize;
    let (mut blocks_seen, mut blocks_multi, mut blocks_max) = (0usize, 0usize, 0usize);
    let mut interaction = 0usize;
    let mut spanmax = 0usize;
    let mut first_merge: Option<String> = None;
    for a in &pool {
        let (blk, nb) = bisim_blocks(a);
        let Some(q) = quotient_by(a, &blk, nb) else { continue };
        let k = a.k as usize;
        // source SCC index per state, and which source SCCs are non-trivial
        let src = sccs_of(a);
        let mut scomp = [usize::MAX; MAXK];
        let mut snontriv = vec![false; src.len()];
        for (ci, mem) in src.iter().enumerate() {
            for &m in mem { scomp[m] = ci; }
            let selfloop = mem.len() == 1
                && (0..NA).any(|x| a.st[mem[0]][x] == (mem[0] + 1) as u8);
            snontriv[ci] = mem.len() > 1 || selfloop;
        }
        for comp in sccs_of(&q) {
            let selfloop = comp.len() == 1
                && (0..NA).any(|x| q.st[comp[0]][x] == (comp[0] + 1) as u8);
            if comp.len() == 1 && !selfloop { continue; }
            qsccs += 1;
            let mut spans: Vec<usize> = Vec::new();
            for u in 0..k {
                if !comp.contains(&blk[u]) { continue; }
                let ci = scomp[u];
                if ci == usize::MAX || !snontriv[ci] { continue; }
                if !spans.contains(&ci) { spans.push(ci); }
            }
            if spans.len() > spanmax { spanmax = spans.len(); }
            // Sharper: is the span WITHIN one quotient state (bisimilar sources,
            // which agree on everything trivially), or ACROSS two distinct
            // quotient states drawn from different source loops?  Only the second
            // could put two exit continuations in one region.
            {
                let mut cross = false;
                for &b1 in &comp {
                    for &b2 in &comp {
                        if b1 >= b2 { continue; }
                        let mut c1: Vec<usize> = Vec::new();
                        let mut c2: Vec<usize> = Vec::new();
                        for u in 0..k {
                            let ci = scomp[u];
                            if ci == usize::MAX || !snontriv[ci] { continue; }
                            if blk[u] == b1 && !c1.contains(&ci) { c1.push(ci); }
                            if blk[u] == b2 && !c2.contains(&ci) { c2.push(ci); }
                        }
                        if !c1.is_empty() && !c2.is_empty()
                            && c1.iter().all(|x| !c2.contains(x)) { cross = true; }
                    }
                }
                if cross { cross_loop += 1; }
            }
            let mut nmulti_here = 0usize;
            // How much ground does the SCC-level-reachability proof cover?  It
            // assumes each block's preimage lies in ONE source loop.  Count the
            // blocks for which that fails.
            for &b in &comp {
                let mut cs: Vec<usize> = Vec::new();
                for u in 0..k {
                    if blk[u] != b { continue; }
                    let ci = scomp[u];
                    if ci == usize::MAX || !snontriv[ci] { continue; }
                    if !cs.contains(&ci) { cs.push(ci); }
                }
                blocks_seen += 1;
                if cs.len() > 1 { blocks_multi += 1; nmulti_here += 1; }
                if cs.len() > blocks_max { blocks_max = cs.len(); }
            }
            // The INTERACTION case: an SCC with >= 2 blocks, at least one of which
            // spans several source loops.  This is the only shape the SCC-level
            // reachability proof does not cover; if it never occurs, the worry is
            // hypothetical for this class of automata.
            if comp.len() >= 2 && nmulti_here > 0 { interaction += 1; }
            if spans.len() >= 2 {
                merged += 1;
                // does the merged SCC have two different exit targets at one atom?
                let mut exit_tgt = [usize::MAX; 16];
                let mut clash = false;
                for &u in &comp {
                    for x in 0..NA {
                        let tv = q.st[u][x];
                        if tv == 0 { continue; }
                        let t = (tv - 1) as usize;
                        if comp.contains(&t) { continue; }
                        if exit_tgt[x] == usize::MAX { exit_tgt[x] = t; }
                        else if exit_tgt[x] != t { clash = true; }
                    }
                }
                if clash { merged_conflict += 1; }
                if first_merge.is_none() {
                    first_merge = Some(format!(
                        "quotient SCC {comp:?} spans {} source loops, exit clash {clash}\n    {}",
                        spans.len(), show_aut("src  ", a)));
                }
            }
        }
    }
    println!("LOOPMERGE: {qsccs} non-trivial SCCs in quotients");
    println!("  {merged} whose preimage spans TWO OR MORE non-trivial source loops \
              ({:.3}%); max span {spanmax}",
        100.0 * merged as f64 / qsccs.max(1) as f64);
    println!("  {cross_loop} quotient SCCs contain TWO DISTINCT states drawn from DISJOINT \
              source loops (the only shape that could bring two exit continuations together)");
    println!("  of those merged SCCs, {merged_conflict} have two different exit targets \
              at one atom (this is the number that would break the structural argument)");
    println!("  PROOF COVERAGE: {blocks_seen} blocks in non-trivial quotient SCCs, \
              {blocks_multi} of them ({:.3}%) have a preimage spanning MORE THAN ONE source \
              loop (max {blocks_max}) — the case the SCC-reachability argument does not cover",
        100.0 * blocks_multi as f64 / blocks_seen.max(1) as f64);
    println!("  INTERACTION CASE: {interaction} quotient SCCs have >=2 blocks AND a block \
              spanning several source loops — the one shape the proof does not cover");
    match first_merge {
        None => println!("  no merge anywhere: the collapse never fuses two loops into one SCC, \
                          so a region keeps its single exit continuation"),
        Some(m) => println!("  FIRST MERGE\n    {m}"),
    }
}

/// **`PAD_BACKATOM`** (iteration 342).
///
/// 341 left exactly one obligation: from a quotient's transition lists, produce
/// `raw` / `loops` / `exits` whose gated reassembly selects the same transition
/// at every atom.  Working the gating out gives a sharp, finite condition.
///
/// The peeled list at a level-`n` state `s` fires, at atom `x`, in this order:
///   1. a `raw` transition, if one of its guards holds;
///   2. else a loop entry, gated `raw.hlt s ∧ bs n ∧ tr.1`;
///   3. else an exit entry, gated `raw.hlt s ∧ ¬bs n ∧ tr.1`;
///   4. else halt, iff `raw.hlt s ∧ ¬bs n ∧ h₀s n`.
///
/// `bs n` is ONE test shared by the whole level.  Steps 2 and 3/4 sit on opposite
/// sides of it.  So an atom that is a BACK-EDGE atom for one state of the level
/// may not be an EXIT-or-HALT atom for another state of the same level:
///
/// > **`bs n` must be true on every back-edge atom of the level and false on
/// > every exit atom and every halting atom of the level.**
///
/// Intra-level edges that DECREASE the rank go into `raw` and constrain nothing,
/// so the back-edge set is ours to choose — any set whose removal leaves the
/// region acyclic.  With regions of size ≤ 3 that is at most 6 rank orderings to
/// try.  This measures whether SOME ordering avoids the clash.
fn backatom<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let pool = build_pool::<NA>(nguards, rounds, cap);
    let (mut regions, mut ok, mut bad) = (0usize, 0usize, 0usize);
    let mut first_bad: Option<String> = None;
    let mut singleton_ok = 0usize;
    let (mut multi, mut multi_ok, mut some_ordering_fails, mut every_ordering_fails) =
        (0usize, 0usize, 0usize, 0usize);
    let mut exit_conflict = 0usize;
    let (mut multi_active, mut max_active) = (0usize, 0usize);
    let mut vacuous_regions = 0usize;
    let mut first_exit_conflict: Option<String> = None;
    for a in &pool {
        let (blk, nb) = bisim_blocks(a);
        let Some(q) = quotient_by(a, &blk, nb) else { continue };
        for comp in sccs_of(&q) {
            let selfloop = comp.len() == 1
                && (0..NA).any(|x| q.st[comp[0]][x] == (comp[0] + 1) as u8);
            if comp.len() == 1 && !selfloop { continue; }
            regions += 1;
            // try every rank ordering of the region (size <= 3 in practice)
            let m = comp.len();
            let mut perm: Vec<usize> = (0..m).collect();
            let mut any = false;
            let mut vacuous_ok = false;
            let mut nclash = 0usize;
            let mut ntried = 0usize;
            loop {
                ntried += 1;
                let mut rank = [0usize; MAXK];
                for (i, &pi) in perm.iter().enumerate() { rank[comp[pi]] = i; }
                // At each atom the whole level shares ONE loop list and ONE exit
                // list, both scanned in order, so every region state that is not
                // handled by `raw` and is not dead must agree at that atom — same
                // kind AND same target.  Exits also SHADOW halting: an exit entry
                // sits before the fallback, so a state cannot halt at an atom where
                // another state of the level exits.
                //   0 = nothing demanded yet
                //   1|target<<4 = back-edge to target   2|target<<4 = exit to target
                //   3 = halt
                let mut demand = [0u32; 16];
                let mut clash = false;
                for &u in &comp {
                    for x in 0..NA {
                        let tv = q.st[u][x];
                        let halts = (q.hl[u] >> x) & 1 == 1;
                        let want: u32 = if tv == 0 {
                            // dead atom: `raw.hlt s` false there kills every branch
                            if halts { 3 } else { 0 }
                        } else {
                            let t = (tv - 1) as usize;
                            if !comp.contains(&t) { 2 | ((t as u32) << 4) }
                            else if rank[t] < rank[u] { 0 }
                            else { 1 | ((t as u32) << 4) }
                        };
                        if want == 0 { continue; }
                        if demand[x] == 0 { demand[x] = want; }
                        else if demand[x] != want { clash = true; }
                    }
                }
                if !clash {
                    // Does THIS ordering also make agreement vacuous (<=1 active
                    // per atom)?  Search all orderings, not just the first that
                    // avoids a clash — "the first one that works" is an arbitrary
                    // choice and would understate what a better choice achieves.
                    {
                        let mut worst = 0usize;
                        for x in 0..NA {
                            let mut act = 0usize;
                            for &u in &comp {
                                let tv = q.st[u][x];
                                let halts = (q.hl[u] >> x) & 1 == 1;
                                let a = if tv == 0 { halts } else {
                                    let t = (tv - 1) as usize;
                                    !(comp.contains(&t) && rank[t] < rank[u])
                                };
                                if a { act += 1; }
                            }
                            if act > worst { worst = act; }
                        }
                        if worst <= 1 { vacuous_ok = true; }
                    }
                    if !any {
                        // First ordering that works: how many states of the region
                        // are ACTIVE (non-raw firing, or halting) at a single atom?
                        // 358's structural route claims at most one — if that is
                        // right, agreement is vacuous rather than merely satisfied.
                        for x in 0..NA {
                            let mut act = 0usize;
                            for &u in &comp {
                                let tv = q.st[u][x];
                                let halts = (q.hl[u] >> x) & 1 == 1;
                                let a = if tv == 0 { halts } else {
                                    let t = (tv - 1) as usize;
                                    !(comp.contains(&t) && rank[t] < rank[u])
                                };
                                if a { act += 1; }
                            }
                            if act > 1 { multi_active += 1; }
                            if act > max_active { max_active = act; }
                        }
                    }
                    any = true;
                } else { nclash += 1; }
                if !next_perm(&mut perm) { break; }
            }
            if m > 1 {
                multi += 1;
                if vacuous_ok { vacuous_regions += 1; }
                if any { multi_ok += 1; }
                if nclash > 0 { some_ordering_fails += 1; }
                if nclash == ntried { every_ordering_fails += 1; }
            }
            // RANK-INDEPENDENT necessary condition: an exit leaves the level, so it
            // is never raw whatever the rank.  If two region states exit to
            // DIFFERENT targets at the same atom, LevelAgreement fails outright and
            // no choice of rank can save it.  A hit here refutes the hypothesis.
            {
                let mut exit_tgt = [usize::MAX; 16];
                for &u in &comp {
                    for x in 0..NA {
                        let tv = q.st[u][x];
                        if tv == 0 { continue; }
                        let t = (tv - 1) as usize;
                        if comp.contains(&t) { continue; }        // intra-level
                        if exit_tgt[x] == usize::MAX { exit_tgt[x] = t; }
                        else if exit_tgt[x] != t {
                            exit_conflict += 1;
                            if first_exit_conflict.is_none() {
                                first_exit_conflict =
                                    Some(format!("region {comp:?} atom {x}\n    {}",
                                        show_aut("quot ", &q)));
                            }
                        }
                    }
                }
            }
            if any {
                ok += 1;
                if m == 1 { singleton_ok += 1; }
            } else {
                bad += 1;
                if first_bad.is_none() {
                    first_bad = Some(format!("region {comp:?}\n    {}", show_aut("quot ", &q)));
                }
            }
        }
    }
    println!("BACKATOM: {regions} non-trivial regions in quotients");
    println!("  {ok} admit a rank ordering where the whole level AGREES at every atom \
              ({:.2}%), of which {singleton_ok} are singletons",
        100.0 * ok as f64 / regions.max(1) as f64);
    println!("  {bad} where EVERY ordering clashes");
    println!("  MULTI-STATE regions (where agreement is not trivial): {multi}, \
              of which {multi_ok} admit an ordering");
    println!("  base-rate control: {some_ordering_fails} multi-state regions have at least \
              ONE ordering that clashes (so the condition bites and the choice matters); \
              {every_ordering_fails} have all orderings clash");
    println!("  STRUCTURAL ROUTE (358): under the FIRST working ordering, {multi_active} \
              (region, atom) pairs have MORE THAN ONE active state; max active {max_active}. \
              1 means agreement is VACUOUS, not merely satisfied");
    println!("  BEST ORDERING: {vacuous_regions} of {multi} multi-state regions admit a \
              clash-free ordering that ALSO leaves at most one active state per atom \
              (i.e. agreement vacuous, 358's structural route exact)");
    println!("  RANK-FREE REFUTATION TEST: {exit_conflict} regions where two states exit to \
              DIFFERENT targets at the SAME atom (any hit refutes LevelAgreement outright)");
    if let Some(m) = &first_exit_conflict {
        println!("  FIRST EXIT CONFLICT\n    {m}");
    }
    match first_bad {
        None => println!("  no clash anywhere: the shared level test `bs n` always exists"),
        Some(m) => println!("  FIRST CLASH\n    {m}"),
    }
}

/// Next lexicographic permutation, in place; false when the last is reached.
fn next_perm(p: &mut [usize]) -> bool {
    let n = p.len();
    if n < 2 { return false; }
    let mut i = n - 1;
    while i > 0 && p[i - 1] >= p[i] { i -= 1; }
    if i == 0 { return false; }
    let mut j = n - 1;
    while p[j] <= p[i - 1] { j -= 1; }
    p.swap(i - 1, j);
    p[i..].reverse();
    true
}

/// **`PAD_CONDENSATION`** (iteration 334).
///
/// 334 proved `layeredOn_empty_of_levels`: a level function that never increases
/// along a step, plus a solution for each SINGLE level in isolation, gives a
/// solution for the whole system with an EMPTY block.  Everything that remains
/// is therefore per-region, so the decision-relevant number is **how big a
/// region gets** and **how many levels the induction climbs**.
///
/// Three things measured on quotients (the objects the proof decomposes):
///   1. the level function itself — that `sccs_of`'s ordering really is
///      non-increasing along every edge, which is `hmono`.  A harness that
///      reported region sizes from a WRONG ordering would be measuring nothing.
///   2. condensation depth: how many distinct levels, i.e. how many times the
///      induction peels.
///   3. region size and shape: is a non-trivial region a single cycle (one
///      `LoopLayerOn` suffices) or something that needs nesting?
fn condensation<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let pool = build_pool::<NA>(nguards, rounds, cap);
    let (mut quots, mut nsccs, mut nontrivial, mut mono_bad) = (0usize, 0usize, 0usize, 0usize);
    let mut maxregion = 0usize;
    let mut maxdepth = 0usize;
    let mut hist: Vec<usize> = vec![0; MAXK + 1];
    let (mut single_cycle, mut multi) = (0usize, 0usize);
    let mut first_multi: Option<String> = None;
    for a in &pool {
        let (blk, nb) = bisim_blocks(a);
        let Some(q) = quotient_by(a, &blk, nb) else { continue };
        quots += 1;
        let comps = sccs_of(&q);
        let k = q.k as usize;
        // level = index of the state's component, with components numbered so
        // that a later component never precedes an earlier one along an edge.
        let mut lvl = [0usize; MAXK];
        for (ci, mem) in comps.iter().enumerate() { for &m in mem { lvl[m] = ci; } }
        // hmono check, and orient: if edges INCREASE the index, flip.
        let (mut up, mut down) = (0usize, 0usize);
        for s in 0..k { for x in 0..NA { if q.st[s][x] != 0 {
            let t = (q.st[s][x] - 1) as usize;
            if lvl[t] > lvl[s] { up += 1; } else if lvl[t] < lvl[s] { down += 1; }
        }}}
        if up > 0 && down > 0 { mono_bad += 1; }
        if up > 0 && down == 0 {
            let top = comps.len() - 1;
            for s in 0..k { lvl[s] = top - lvl[s]; }
        }
        let mut depth = 0usize;
        for s in 0..k { if lvl[s] + 1 > depth { depth = lvl[s] + 1; } }
        if depth > maxdepth { maxdepth = depth; }
        for mem in comps.iter() {
            nsccs += 1;
            let selfloop = mem.len() == 1 && (0..NA).any(|x| q.st[mem[0]][x] == (mem[0] + 1) as u8);
            if mem.len() == 1 && !selfloop { continue; }
            nontrivial += 1;
            hist[mem.len().min(MAXK)] += 1;
            if mem.len() > maxregion { maxregion = mem.len(); }
            // single cycle? every member has exactly ONE distinct intra-region successor
            let mut cyc = true;
            for &u in mem {
                let mut tg: Option<usize> = None;
                for x in 0..NA { if q.st[u][x] != 0 {
                    let t = (q.st[u][x] - 1) as usize;
                    if !mem.contains(&t) { continue; }
                    match tg { None => tg = Some(t), Some(t0) => if t0 != t { cyc = false; } }
                }}
                if tg.is_none() { cyc = false; }
            }
            if cyc { single_cycle += 1; } else {
                multi += 1;
                if first_multi.is_none() && mem.len() > 1 {
                    first_multi = Some(format!("region {mem:?}\n    {}", show_aut("quot ", &q)));
                }
            }
        }
    }
    println!("CONDENSATION: {quots} quotients, {nsccs} regions, {nontrivial} non-trivial");
    println!("  hmono: {mono_bad} quotients where the component ordering is NOT monotone \
              along edges (must be 0 for the level function to exist)");
    println!("  max condensation depth {maxdepth} (= peels the induction makes), \
              max region size {maxregion}");
    println!("  non-trivial region shape: {single_cycle} single-cycle ({:.1}%), {multi} richer",
        100.0 * single_cycle as f64 / nontrivial.max(1) as f64);
    let sizes: Vec<String> = (1..=MAXK).filter(|&i| hist[i] > 0)
        .map(|i| format!("{i}:{}", hist[i])).collect();
    println!("  region sizes {}", sizes.join(" "));
    match first_multi {
        None => println!("  every non-trivial region is a single cycle: ONE LoopLayerOn per \
                          region suffices, no nesting"),
        Some(m) => println!("  FIRST RICHER REGION\n    {m}"),
    }
}

/// **`PAD_MINCONG`** (iteration 330).
///
/// Grounding the target showed `SumQuotientSolvable` accepts ANY behavioural
/// quotient identifying the two start pseudostates — NOT the minimal one.  The
/// finest such quotient is `min_congruence`.  Under it, how much of the
/// difficulty 319-329 fought even exists?  The question is the class
/// composition: a class drawing from BOTH halves cannot make a split
/// problematic, because there is nothing outside the block for it to be outside
/// of.  Only classes drawing from ONE half create a non-trivial complement.
fn mincong<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    { let a = a_act::<NA>(); if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
    for _ in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for r in &cur {
                if let Some(a) = a_seq::<NA>(l, r) {
                    if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
                }
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
                    }
                }
            }
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                if pool.len() < cap { if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } } }
            }
        }
        if pool.len() >= cap { break; }
    }
    let (mut pairs, mut ok, mut mixedonly) = (0usize, 0usize, 0usize);
    let mut classes_tot = 0usize;
    let mut classes_one = 0usize;
    for i in 0..pool.len() {
        for j in 0..pool.len() {
            if i == j { continue; }
            if behaviour(&pool[i]) != behaviour(&pool[j]) { continue; }
            pairs += 1;
            let Some((blk, nb, ka)) = min_congruence_blocks(&pool[i], &pool[j]) else { continue };
            ok += 1;
            let n = pool[i].k as usize + pool[j].k as usize;
            let mut from_a = vec![false; nb];
            let mut from_b = vec![false; nb];
            for x in 0..n {
                if x < ka { from_a[blk[x]] = true; } else { from_b[blk[x]] = true; }
            }
            let one = (0..nb).filter(|&c| !(from_a[c] && from_b[c])).count();
            classes_tot += nb;
            classes_one += one;
            if one == 0 { mixedonly += 1; }
        }
    }
    println!("MIN CONGRUENCE: {pairs} language-equivalent ordered pairs, {ok} with a \
              consistent congruence");
    println!("  classes: {classes_tot} total, {classes_one} drawing from ONE half only \
              ({:.1}%)", 100.0 * classes_one as f64 / classes_tot.max(1) as f64);
    println!("  {mixedonly} of {ok} quotients have EVERY class drawing from BOTH halves \
              ({:.1}%) — for those the split is trivial and 319-329's difficulty is empty",
        100.0 * mixedonly as f64 / ok.max(1) as f64);
}

fn min_congruence<const NA: usize>(a: &Aut<NA>, b: &Aut<NA>) -> Option<Aut<NA>> {
    let su = sum_core(a, b)?;
    let ka = a.k as usize;
    let n = su.k as usize;
    let mut par: Vec<usize> = (0..n).collect();
    fn find(par: &mut Vec<usize>, x: usize) -> usize {
        let mut r = x;
        while par[r] != r { r = par[r]; }
        let mut c = x;
        while par[c] != c { let nx = par[c]; par[c] = r; c = nx; }
        r
    }
    let mut work: Vec<(usize, usize)> = Vec::new();
    for y in 0..NA {
        if a.it[y] != 0 && b.it[y] != 0 {
            work.push(((a.it[y] - 1) as usize, (b.it[y] - 1) as usize + ka));
        }
    }
    while let Some((x, y)) = work.pop() {
        let (rx, ry) = (find(&mut par, x), find(&mut par, y));
        if rx == ry { continue; }
        if su.hl[x] != su.hl[y] { return None; }
        par[rx] = ry;
        for t in 0..NA {
            let (sx, sy) = (su.st[x][t], su.st[y][t]);
            if sx == 0 && sy == 0 { continue; }
            if sx == 0 || sy == 0 { return None; }
            work.push(((sx - 1) as usize, (sy - 1) as usize));
        }
    }
    let mut blk = [0usize; MAXK];
    let mut seen: Vec<usize> = Vec::new();
    for x in 0..n {
        let r = find(&mut par, x);
        blk[x] = match seen.iter().position(|&t| t == r) {
            Some(i) => i,
            None => { seen.push(r); seen.len() - 1 }
        };
    }
    quotient_by(&su, &blk, seen.len())
}

/// Does some state INSIDE a cycle halt?  This is the automaton-level reading of "not
/// skip-free": the skip-free fragment restricts Boolean statements to control positions, so no
/// `assert` sits in a loop body, and halting inside a cycle is exactly what that excludes.
/// Skip-free GKAT is known to be COMPLETE WITHOUT UA, so if the systems elimination stalls on
/// are the ones halting mid-cycle, this file's frontier and the literature's coincide.
fn halt_in_cycle<const NA: usize>(a: &Aut<NA>) -> bool {
    orbits(a).iter().any(|&o| {
        (0..a.k as usize).any(|u| o & (1 << u) != 0 && a.hl[u] != 0)
    })
}

/// Congruence closure from a set of seed merges.  Returns the block map, or `None` if the
/// merges are inconsistent — two states with different halt behaviour, or one defined where
/// the other is not, cannot be identified.
fn close_congruence<const NA: usize>(h: &Aut<NA>, seeds: &[(usize, usize)]) -> Option<([usize; MAXK], usize)> {
    let k = h.k as usize;
    let mut par: Vec<usize> = (0..k).collect();
    fn find(par: &mut Vec<usize>, x: usize) -> usize {
        let mut r = x;
        while par[r] != r { r = par[r]; }
        let mut c = x;
        while par[c] != c { let n = par[c]; par[c] = r; c = n; }
        r
    }
    let mut work: Vec<(usize, usize)> = seeds.to_vec();
    while let Some((a, b)) = work.pop() {
        let (ra, rb) = (find(&mut par, a), find(&mut par, b));
        if ra == rb { continue; }
        if h.hl[a] != h.hl[b] { return None; }
        par[ra] = rb;
        for y in 0..NA {
            let (sa, sb) = (h.st[a][y], h.st[b][y]);
            if sa == 0 && sb == 0 { continue; }
            if sa == 0 || sb == 0 { return None; }
            work.push(((sa - 1) as usize, (sb - 1) as usize));
        }
    }
    let mut blk = [0usize; MAXK];
    let mut seen: Vec<usize> = Vec::new();
    for x in 0..k {
        let r = find(&mut par, x);
        blk[x] = match seen.iter().position(|&t| t == r) {
            Some(i) => i,
            None => { seen.push(r); seen.len() - 1 }
        };
    }
    Some((blk, seen.len()))
}

/// The DISTINCT congruences of the lattice, deduplicated.
///
/// Enumerating subsets of the mergeable pairs generates 2^p candidates, but many close to the
/// SAME congruence — the closure is idempotent and merges propagate.  Running an expensive
/// test on each subset therefore repeats work proportional to the collision rate.  Closing
/// first and deduplicating by block map makes the enumeration output-sensitive: the cost
/// becomes the number of congruences that actually exist, not the number of ways to name them.
fn lattice_congruences<const NA: usize>(su: &Aut<NA>) -> Vec<([usize; MAXK], usize)> {
    let k = su.k as usize;
    let (blk, _) = bisim_blocks(su);
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for a in 0..k {
        for b in (a + 1)..k {
            if blk[a] == blk[b] { pairs.push((a, b)); }
        }
    }
    let mut out: Vec<([usize; MAXK], usize)> = Vec::new();
    if pairs.is_empty() { return out; }
    // The congruence lattice is generated by its PRINCIPAL congruences under join, so build it
    // that way instead of enumerating 2^pairs subsets.  The old code enumerated subsets and
    // returned EMPTY above 12 pairs — a hard search cutoff that silently gave those systems no
    // quotients at all, which is exactly the kind of limit that looks like an obstruction.
    let cap: usize = std::env::var("PAD_LATTICE_CAP").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(512);
    let mut seeds: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut push = |c: ([usize; MAXK], usize), sd: Vec<(usize, usize)>,
                    out: &mut Vec<([usize; MAXK], usize)>,
                    seeds: &mut Vec<Vec<(usize, usize)>>| {
        if !out.iter().any(|(b, n)| *n == c.1 && b[..k] == c.0[..k]) {
            out.push(c);
            seeds.push(sd);
        }
    };
    for &pr in pairs.iter() {
        if let Some(c) = close_congruence(su, &[pr]) { push(c, vec![pr], &mut out, &mut seeds); }
    }
    // every congruence is a join of PRINCIPALS, so joining each new one against the principals
    // alone reaches the whole lattice — O(n x principals) closures instead of O(n^2).
    let np = out.len();
    let mut i = 0usize;
    while i < out.len() && out.len() < cap {
        for j in 0..np {
            if out.len() >= cap { break; }
            let mut sd = seeds[i].clone();
            sd.extend(seeds[j].iter().copied());
            if let Some(c) = close_congruence(su, &sd) { push(c, sd, &mut out, &mut seeds); }
        }
        i += 1;
    }
    out
}

/// Is SOME congruence in the lattice a Thompson automaton?  The conjunct asks for any
/// behavioural quotient with a solution, and a Thompson quotient carries the standard solution
/// outright.  Checking only the full collapse tests one point of the lattice; the residue is
/// made of collapses that left the Thompson class, so a FINER quotient may still be inside it.
fn thompson_somewhere_in_lattice<const NA: usize>(su: &Aut<NA>,
    seen: &Interner) -> bool {
    // TRIM before looking up.  `canon` rejects automata with unreachable states, and quotients
    // of a sum routinely have them — which silently hid 44851 of 55627 quotients from this
    // test.  Dropping unreachable states is the corpus's proved dead-code elimination, not a
    // relaxation, so the lookup is still exact.
    let k = su.k as usize;
    let (blk, nb) = bisim_blocks(su);
    if let Some(q) = quotient_by(su, &blk, nb) {
        if trim_canon(&q).and_then(|t| canon(&t))
            .map(|c| seen.contains(&c)).unwrap_or(false) { return true; }
    }
    for (b2, nb2) in lattice_congruences(su) {
        if let Some(q) = quotient_by(su, &b2, nb2) {
            if trim_canon(&q).and_then(|t| canon(&t))
                .map(|c| seen.contains(&c)).unwrap_or(false) { return true; }
        }
    }
    false
}

/// **Search the LATTICE of bisimulations, not just its endpoints.**  `SumQuotientSolvable`
/// asks for SOME behavioural quotient with a solution; the full collapse is only the top of
/// the lattice and the start-identifying congruence only near the bottom.  This enumerates
/// intermediate congruences, generated by merging subsets of the pairs the full collapse
/// merges, and asks whether any of them is solvable.
/// `start_b` is the sum-index of the SECOND program's start (`a.k + 1` after
/// `to_gaut` folds each entry pseudostate into state 0), so the first start is
/// always state 0.
///
/// **A congruence that does not identify the two starts is not admissible**:
/// `SumQuotientSolvable` asks for a quotient whose start images coincide, and
/// a quotient that keeps them apart proves nothing about `e ≡ f`.  This check
/// was missing, so every lattice figure before iteration 197 counted quotients
/// that were solvable but useless.
/// **THE CANONICAL QUOTIENT** (iteration 204).  `SumQuotientSolvable` is an
/// EXISTENTIAL — *some* behavioural quotient of the Thompson sum has a
/// solution — and an existential is a poor target: the search over the
/// congruence lattice is expensive, and proving one requires exhibiting a
/// quotient out of thin air.
///
/// There is a canonical candidate.  Proving `e ≡ f` requires identifying the
/// two start states, and identifying them FORCES identifying their successors
/// atom-by-atom, and so on.  The smallest congruence containing `(0, start_b)`
/// is therefore the LEAST quotient any proof could use — every admissible
/// quotient is coarser.  It needs no search: close `(0, start_b)` under
/// successors to a fixpoint.
///
/// Because the pair is language-equivalent the two starts are bisimilar, so
/// the closure stays inside bisimilarity and is automatically a behavioural
/// congruence; the halt-mask check below is a guard, not an expectation.
///
/// This matters because of the exponential-blowup theorem for node splitting
/// (Carter–Ferrante–Thomborson 2003): making an irreducible graph reducible
/// can need `2^(n-1)` nodes, and here the supply of nodes is capped by the
/// Thompson sum.  If solvability ever required descending BELOW this canonical
/// quotient by more than the sum affords, the existential would fail.  So the
/// sharp question is whether the LEAST quotient is already solvable.
fn start_congruence<const NA: usize>(su: &Aut<NA>, start_b: usize)
    -> Option<([usize; MAXK], usize)>
{
    let k = su.k as usize;
    if start_b >= k { return None; }
    let mut uf: [usize; MAXK] = [0; MAXK];
    for (i, e) in uf.iter_mut().enumerate().take(k) { *e = i; }
    fn find(uf: &mut [usize; MAXK], x: usize) -> usize {
        let mut r = x;
        while uf[r] != r { r = uf[r]; }
        let mut c = x;
        while uf[c] != c { let n = uf[c]; uf[c] = r; c = n; }
        r
    }
    let ra = find(&mut uf, 0);
    let rb = find(&mut uf, start_b);
    if ra != rb { uf[ra] = rb; }
    // Close under successors: whenever two states are identified, so are their
    // targets on every atom where both are defined.
    loop {
        let mut changed = false;
        for u in 0..k {
            for v in (u + 1)..k {
                if find(&mut uf, u) != find(&mut uf, v) { continue; }
                for y in 0..NA {
                    let (tu, tv) = (su.st[u][y], su.st[v][y]);
                    if tu == 0 || tv == 0 { continue; }
                    let (pu, pv) = (find(&mut uf, (tu - 1) as usize),
                        find(&mut uf, (tv - 1) as usize));
                    if pu != pv { uf[pu] = pv; changed = true; }
                }
            }
        }
        if !changed { break; }
    }
    // Renumber classes, block 0 first, and verify the merge is behavioural.
    let mut blk = [0usize; MAXK];
    let mut reps: Vec<usize> = Vec::new();
    for x in 0..k {
        let r = find(&mut uf, x);
        blk[x] = match reps.iter().position(|&t| t == r) {
            Some(i) => i,
            None => { reps.push(r); reps.len() - 1 }
        };
    }
    for u in 0..k {
        for v in (u + 1)..k {
            if blk[u] != blk[v] { continue; }
            if su.hl[u] != su.hl[v] { return None; }
            for y in 0..NA {
                if (su.st[u][y] == 0) != (su.st[v][y] == 0) { return None; }
            }
        }
    }
    Some((blk, reps.len()))
}

fn solvable_somewhere_in_lattice<const NA: usize>(su: &Aut<NA>, elim: bool,
    start_b: usize) -> bool {
    // The top-of-lattice verdict is precomputed; recomputing it here ran the full backtracking
    // elimination for every pair, including the 9221 already known solvable.
    if elim { return true; }
    let k = su.k as usize;
    let (blk, _) = bisim_blocks(su);
    for (b2, nb2) in lattice_congruences(su) {
        if b2[0] != b2[start_b] { continue; }
        if let Some(q) = quotient_by(su, &b2, nb2) {
            if symbolic_eliminable_raw(&q) { return true; }
        }
    }
    false
}

/// **THE CALCULUS OVER THE WHOLE LATTICE.**  `SumQuotientSolvable` asks for
/// SOME behavioural quotient with a solution, so the honest test of the
/// three-rule calculus is not "does it solve the full collapse" but "does it
/// solve ANY admissible quotient".  The full collapse is only the top of the
/// congruence lattice.
///
/// Every multi-state SCC of the candidate quotient must be solved; the
/// singleton and acyclic parts are the already-proved strata.
fn calculus_somewhere_in_lattice<const NA: usize>(su: &Aut<NA>, n: usize,
    start_b: usize) -> bool {
    let try_q = |q: &Aut<NA>| -> bool {
        sccs_of(q).iter().all(|c| c.len() < 2 || calculus_solves(q, c, n))
    };
    let mut tried = 0usize;
    let (blk, nb) = bisim_blocks(su);
    if let Some(q) = quotient_by(su, &blk, nb) {
        if try_q(&q) { return true; }
    }
    for (b2, nb2) in lattice_congruences(su) {
        if b2[0] != b2[start_b] { continue; }
        tried += 1;
        if tried > 96 { break; }
        if let Some(q) = quotient_by(su, &b2, nb2) {
            if try_q(&q) { return true; }
        }
    }
    false
}

/// Render a closure member as the expression it was built from.  The pool is closed under
/// `a_wh`/`a_seq`/`a_ite` starting from tests and actions, so every member IS the Thompson
/// automaton of an expression, and its provenance is that expression.
fn expr_of<const NA: usize>(list: &[Aut<NA>], prov: &[Prov], idx: u32, d: usize) -> String {
    if d == 0 { return "…".to_string(); }
    match prov[idx as usize] {
        Prov::Leaf => {
            let a = &list[idx as usize];
            if a.k == 0 { format!("[t{}]", a.ih) } else { "p".to_string() }
        }
        Prov::Seq(l, r) => format!("({};{})", expr_of(list, prov, l, d - 1),
                                              expr_of(list, prov, r, d - 1)),
        Prov::Ite(g, l, r) => format!("({} +{} {})", expr_of(list, prov, l, d - 1), g,
                                                     expr_of(list, prov, r, d - 1)),
        Prov::Wh(g, b) => format!("({})^{}", expr_of(list, prov, b, d - 1), g),
    }
}

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
    // The hand-inverted decomposition oracle is REFUTED (10/301) and its subset
    // enumeration explodes combinatorially beyond NA=2 (16 guards hung a sweep for
    // 1h19m at 18 cores).  Reject conservatively there; it only feeds diagnostics.
    if NA > 2 { return false; }
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
    // The hand-inverted decomposition oracle is REFUTED (10/301) and its subset
    // enumeration explodes combinatorially beyond NA=2 (16 guards hung a sweep for
    // 1h19m at 18 cores).  Reject conservatively there; it only feeds diagnostics.
    if NA > 2 { return false; }
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
    // The hand-inverted decomposition oracle is REFUTED (10/301) and its subset
    // enumeration explodes combinatorially beyond NA=2 (16 guards hung a sweep for
    // 1h19m at 18 cores).  Reject conservatively there; it only feeds diagnostics.
    if NA > 2 { return false; }
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
    // The hand-inverted decomposition oracle is REFUTED (10/301) and its subset
    // enumeration explodes combinatorially beyond NA=2 (16 guards hung a sweep for
    // 1h19m at 18 cores).  Reject conservatively there; it only feeds diagnostics.
    if NA > 2 { return false; }
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


/// Parse the harness's printed program syntax back into an automaton + Lean term.
/// Grammar (fully parenthesised): `p`, `[tN]`, `(X;Y)`, `(X +N Y)`, `(X)^N`.
fn parse_attack<const NA: usize>(s: &[u8], pos: &mut usize) -> (Aut<NA>, String, Vec<String>) {
    let (a, st, paths) = match s[*pos] {
        b'p' => { *pos += 1; (a_act(), "pA".to_string(), vec!["()".to_string()]) }
        b'[' => {
            *pos += 2;
            let n = s[*pos] - b'0';
            *pos += 2;
            (a_test(n), format!("(Exp.test {})", mask_lean(n)), vec![])
        }
        b'(' => {
            *pos += 1;
            let (l, ls, lp) = parse_attack(s, pos);
            let (a, st, paths) = match s[*pos] {
                b')' => (l, ls, lp),
                b';' => {
                    *pos += 1;
                    let (r, rs, rp) = parse_attack(s, pos);
                    let mut ps: Vec<String> = lp.iter().map(|q| format!("(Sum.inl {q})")).collect();
                    ps.extend(rp.iter().map(|q| format!("(Sum.inr {q})")));
                    (a_seq(&l, &r).unwrap(), format!("(Exp.seq {ls} {rs})"), ps)
                }
                b' ' => {
                    *pos += 2;
                    let n = s[*pos] - b'0';
                    *pos += 2;
                    let (r, rs, rp) = parse_attack(s, pos);
                    let mut ps: Vec<String> = lp.iter().map(|q| format!("(Sum.inl {q})")).collect();
                    ps.extend(rp.iter().map(|q| format!("(Sum.inr {q})")));
                    (a_ite(n, &l, &r).unwrap(), format!("(Exp.ite {} {ls} {rs})", mask_lean(n)), ps)
                }
                c => panic!("parse_attack: unexpected {}", c as char),
            };
            assert_eq!(s[*pos], b')');
            *pos += 1;
            (a, st, paths)
        }
        c => panic!("parse_attack: unexpected {}", c as char),
    };
    if *pos < s.len() && s[*pos] == b'^' {
        *pos += 1;
        let n = s[*pos] - b'0';
        *pos += 1;
        (a_wh(n, &a), format!("(Exp.wh {} {st})", mask_lean(n)), paths)
    } else {
        (a, st, paths)
    }
}



/// Number of bisimulation classes of an automaton — the size of its
/// behavioural minimization.  Same partition-refinement fixpoint the census
/// uses on the trimmed sum, applied to a single automaton.
fn min_classes<const NA: usize>(a: &Aut<NA>) -> usize {
    let k = a.k as usize;
    let mut cls = [0u8; MAXK];
    {
        let mut seen = [255u8; 256];
        let mut n = 0u8;
        for s in 0..k {
            let h = a.hl[s] as usize;
            if seen[h] == 255 { seen[h] = n; n += 1; }
            cls[s] = seen[h];
        }
    }
    loop {
        let mut sigs: Vec<(u8, [u8; NA])> = Vec::new();
        let mut next = [0u8; MAXK];
        for s in 0..k {
            let mut row = [255u8; NA];
            for i in 0..NA {
                if a.st[s][i] != 0 { row[i] = cls[(a.st[s][i] - 1) as usize]; }
            }
            let sig = (cls[s], row);
            let j = match sigs.iter().position(|x| *x == sig) {
                Some(j) => j,
                None => { sigs.push(sig); sigs.len() - 1 }
            };
            next[s] = j as u8;
        }
        let (mut c0, mut c1) = (0usize, 0usize);
        {
            let mut m = [false; MAXK];
            for s in 0..k { if !m[cls[s] as usize] { m[cls[s] as usize] = true; c0 += 1; } }
            let mut m2 = [false; MAXK];
            for s in 0..k { if !m2[next[s] as usize] { m2[next[s] as usize] = true; c1 += 1; } }
        }
        cls = next;
        if c1 == c0 { break; }
    }
    let mut m = [false; MAXK];
    let mut c = 0usize;
    for s in 0..k { if !m[cls[s] as usize] { m[cls[s] as usize] = true; c += 1; } }
    c
}

/// SCCs of a quotient's transition graph (Kosaraju on <= MAXK states).

// ---- absorption verification (Rust; replaces the retired Python checker) ----

/// The same automaton, entered at core state `s`.
fn entry_at<const NA: usize>(q: &Aut<NA>, s: usize) -> Aut<NA> {
    let mut a = *q;
    a.ih = q.hl[s];
    a.it = q.st[s];
    a
}

/// Does the automaton accept `seq` when STARTED AT CORE STATE `s`?
///
/// The obvious spelling is `accepts(&entry_at(q, s), seq)`, and that is what
/// this replaces: `entry_at` copies the whole `Aut` — `MAXK * NA` bytes of
/// transition table — and it was being called once per oracle leaf per string,
/// inside a function the instrumentation clocked at 124 MILLION calls per
/// 60 000 pairs.  Walking from `s` directly copies nothing.
fn accepts_at<const NA: usize>(q: &Aut<NA>, s: usize, seq: &[usize]) -> bool {
    let mut cur = s;
    for (i, &x) in seq.iter().enumerate() {
        if i + 1 == seq.len() { return bit(q.hl[cur], x); }
        let t = q.st[cur][x];
        if t == 0 { return false; }
        cur = (t - 1) as usize;
    }
    false
}

/// Does `a` accept the guarded string whose atom sequence is `seq`?
fn accepts<const NA: usize>(a: &Aut<NA>, seq: &[usize]) -> bool {
    let mut idx: Option<usize> = None;
    for (i, &x) in seq.iter().enumerate() {
        let (hl, st) = match idx {
            None => (a.ih, a.it),
            Some(s) => (a.hl[s], a.st[s]),
        };
        if i + 1 == seq.len() {
            return bit(hl, x);
        }
        let t = st[x];
        if t == 0 {
            return false;
        }
        idx = Some((t - 1) as usize);
    }
    false
}

fn lang_walk<const NA: usize>(a: &Aut<NA>, b: &Aut<NA>, seq: &mut Vec<usize>,
                              n: usize) -> bool {
    if accepts(a, seq) != accepts(b, seq) {
        return false;
    }
    if seq.len() > n {
        return true;
    }
    for x in 0..NA {
        seq.push(x);
        let ok = lang_walk(a, b, seq, n);
        seq.pop();
        if !ok {
            return false;
        }
    }
    true
}

/// Guarded-string language equality up to `n` actions.
fn lang_eq<const NA: usize>(a: &Aut<NA>, b: &Aut<NA>, n: usize) -> bool {
    let mut seq: Vec<usize> = Vec::new();
    for x in 0..NA {
        seq.push(x);
        let ok = lang_walk(a, b, &mut seq, n);
        seq.pop();
        if !ok {
            return false;
        }
    }
    true
}

/// **Hecht-Ullman T1/T2**: drop self-loops, merge a non-header node having a
/// unique predecessor into it; the flow graph is REDUCIBLE iff this collapses
/// it to a single node.  Reducibility is about loop ENTRY, and is NOT the same
/// as Kosaraju's exit condition (iteration 181 conflated them once).
fn t1t2_reducible<const NA: usize>(q: &Aut<NA>, scc: &[usize]) -> bool {
    let n = scc.len();
    let mut edge = vec![vec![false; n]; n];
    for (i, &u) in scc.iter().enumerate() {
        for a in 0..NA {
            let t = q.st[u][a];
            if t == 0 { continue; }
            if let Some(j) = scc.iter().position(|&x| x == (t - 1) as usize) {
                edge[i][j] = true;
            }
        }
    }
    let mut live: Vec<bool> = vec![true; n];
    let mut count = n;
    loop {
        let mut changed = false;
        for i in 0..n { if live[i] && edge[i][i] { edge[i][i] = false; changed = true; } }
        for i in 1..n {
            if !live[i] { continue; }
            let preds: Vec<usize> = (0..n).filter(|&j| live[j] && edge[j][i]).collect();
            if preds.len() != 1 { continue; }
            let p = preds[0];
            edge[p][i] = false;
            for j in 0..n { if edge[i][j] && j != i { edge[p][j] = true; } }
            for j in 0..n { edge[j][i] = false; }
            live[i] = false;
            count -= 1;
            changed = true;
            break;
        }
        if !changed || count == 1 { break; }
    }
    count == 1
}

/// The SCC members that leave it — halt, or step outside.  Kosaraju: a loop
/// with two DISTINCT exits is no structured program without auxiliary
/// variables, and GKAT has none.
fn exit_states<const NA: usize>(q: &Aut<NA>, scc: &[usize]) -> usize {
    scc.iter().filter(|&&s| {
        q.hl[s] != 0 || (0..NA).any(|a| {
            let t = q.st[s][a];
            t != 0 && !scc.contains(&((t - 1) as usize))
        })
    }).count()
}

/// **GATED IDENTIFICATION, applicability.**  Two states of the SCC whose
/// dispatches differ on a PROPER subset of atoms — then on the region where
/// they agree one may stand for the other (iteration 186).
fn gated_applicable<const NA: usize>(q: &Aut<NA>, scc: &[usize]) -> bool {
    for (i, &u) in scc.iter().enumerate() {
        for &v in scc.iter().skip(i + 1) {
            let mut diff = 0usize;
            for a in 0..NA {
                if q.st[u][a] != q.st[v][a] || bit(q.hl[u], a) != bit(q.hl[v], a) {
                    diff += 1;
                }
            }
            if diff < NA { return true; }
        }
    }
    false
}

/// **EXIT ABSORPTION, constructed and checked.**  For a two-state SCC `{h, o}`
/// with `h` the unique halting member stepping only to `o`, build
///
///     X_h = wh g (p ; <o's dispatch: back-to-h -> p, escape to w -> p ; w>)
///           ; test trail
///
/// with escape continuations taken as the quotient entered at `w`, and compare
/// languages with the quotient entered at `h`.  `None` when the shape does not
/// apply or a combinator overflows `MAXK`.
fn absorption_verified<const NA: usize>(q: &Aut<NA>, scc: &[usize], n: usize)
    -> Option<bool>
{
    if scc.len() != 2 { return None; }
    let heads: Vec<usize> = scc.iter().cloned().filter(|&s| q.hl[s] != 0).collect();
    if heads.len() != 1 { return None; }
    let h = heads[0];
    let o = if scc[0] == h { scc[1] } else { scc[0] };
    let mut g = 0u8;
    for i in 0..NA {
        let t = q.st[h][i];
        if t == 0 { continue; }
        if (t - 1) as usize != o { return None; }
        g |= 1 << i;
    }
    if g == 0 { return None; }
    let p = a_act::<NA>();
    let mut disp = a_test::<NA>(q.hl[o]);
    for i in 0..NA {
        let t = q.st[o][i];
        if t == 0 { continue; }
        let tt = (t - 1) as usize;
        let cont = if tt == h { p } else { a_seq(&p, &entry_at(q, tt))? };
        disp = a_ite(1 << i, &cont, &disp)?;
    }
    let body = a_seq(&p, &disp)?;
    let prop = a_seq(&a_wh(g, &body), &a_test::<NA>(q.hl[h]))?;
    Some(lang_eq(&prop, &entry_at(q, h), n))
}


// ---- the three-rule calculus, as a search (Rust; the Python attempt is retired)

/// A candidate solution under construction.  `Unk` is an unsolved SCC state,
/// `Sub` an oracle: the quotient entered at a state outside the SCC.
#[derive(Clone, Debug, PartialEq)]
enum Ex {
    Test(u8),
    Act,
    Sub(usize),
    Unk(usize),
    Seq(Box<Ex>, Box<Ex>),
    Ite(u8, Box<Ex>, Box<Ex>),
    Wh(u8, Box<Ex>),
}

// Instrumentation for the optimization pass.  My own recorded lesson from three
// earlier passes on this harness: EVERY real win was redundant or unparallelized
// work, never allocator pressure — so measure before touching anything.
static CALC_NODES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static CALC_ACCEPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static CALC_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static CALC_SKIPPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[inline]
fn bump(c: &std::sync::atomic::AtomicUsize) {
    c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn ex_occurs(e: &Ex, s: usize) -> bool {
    match e {
        Ex::Unk(t) => *t == s,
        Ex::Seq(a, b) | Ex::Ite(_, a, b) => ex_occurs(a, s) || ex_occurs(b, s),
        Ex::Wh(_, a) => ex_occurs(a, s),
        _ => false,
    }
}

/// Any unsolved SCC state still referenced?  At the leaf every reference must
/// be gone — an expression naming an unknown is not a solution, however well
/// its oracle reading happens to match.
fn ex_occurs_any(e: &Ex, scc: &[usize]) -> bool {
    scc.iter().any(|&t| ex_occurs(e, t))
}

/// Node count, used to stop the resolution loop's squaring blowup.  Counts
/// with an explicit budget so a already-huge term costs O(cap), not O(size).
fn ex_size(e: &Ex, cap: usize) -> usize {
    fn go(e: &Ex, n: &mut usize, cap: usize) {
        if *n > cap { return; }
        *n += 1;
        match e {
            Ex::Seq(a, b) | Ex::Ite(_, a, b) => { go(a, n, cap); go(b, n, cap); }
            Ex::Wh(_, a) => go(a, n, cap),
            _ => {}
        }
    }
    let mut n = 0;
    go(e, &mut n, cap);
    n
}

/// How many times the unknown `s` occurs — the multiplier in a substitution.
fn ex_count(e: &Ex, s: usize) -> usize {
    match e {
        Ex::Unk(t) if *t == s => 1,
        Ex::Seq(a, b) | Ex::Ite(_, a, b) => ex_count(a, s) + ex_count(b, s),
        Ex::Wh(_, a) => ex_count(a, s),
        _ => 0,
    }
}

/// `e = H ; f`  ⟹  `H`.  Sequences are right-nested, so the suffix is found by
/// walking the right spine.
fn strip_suffix(e: &Ex, f: &Ex) -> Option<Ex> {
    if e == f { return Some(Ex::Test(0xFF)); }
    match e {
        Ex::Seq(a, b) => {
            if **b == *f { return Some((**a).clone()); }
            strip_suffix(b, f).map(|b2| Ex::Seq(a.clone(), Box::new(b2)))
        }
        _ => None,
    }
}

/// **RULE 6 IN THE SOLVER** (iteration 207): TRAILING-SUFFIX SHARING.
///
/// `trailing_suffix_shared` says a mid-body exit need not be a halt — it needs
/// to LAND OUTSIDE THE GUARD and SHARE THE LOOP'S TRAILING SUFFIX.  So in each
/// arm of the body's decision structure, if the arm ENDS in the loop's trailing
/// expression `f`, drop that suffix: the arm then falls out of the loop (its
/// guard is false where it lands) and the shared trailing `f` supplies the
/// dropped part.
///
/// The compiler literature reaches the same restructuring by routing every loop
/// exit to a MERGE node at the bottom of the loop — but pays for it with a
/// control variable saying which exit fired.  GKAT has no such variable; here
/// the guard's falsity does the selecting, which is exactly why the rule needs
/// `H · ¬g ≡ H` and the language check has to confirm it.
///
/// The recursive arm is never stripped: after substitution it ends in the
/// unknown's assertion, not in `f`.
fn share_tail(e: &Ex, f: &Ex) -> Ex {
    match e {
        Ex::Ite(m, a, b) =>
            Ex::Ite(*m, Box::new(share_tail(a, f)), Box::new(share_tail(b, f))),
        Ex::Seq(a, b) => match strip_suffix(e, f) {
            Some(h) => h,
            None => Ex::Seq(a.clone(), Box::new(share_tail(b, f))),
        },
        _ => e.clone(),
    }
}

fn ex_subst(e: &Ex, s: usize, r: &Ex) -> Ex {
    match e {
        Ex::Unk(t) if *t == s => r.clone(),
        Ex::Seq(a, b) => Ex::Seq(Box::new(ex_subst(a, s, r)), Box::new(ex_subst(b, s, r))),
        Ex::Ite(g, a, b) => Ex::Ite(*g, Box::new(ex_subst(a, s, r)), Box::new(ex_subst(b, s, r))),
        Ex::Wh(g, a) => Ex::Wh(*g, Box::new(ex_subst(a, s, r))),
        _ => e.clone(),
    }
}

/// Does the candidate accept this guarded string?  Every REMAINING unknown is
/// read as the oracle it must denote — the quotient entered at that state.
///
/// Evaluating the DENOTATION rather than building the expression's automaton
/// is what makes the search work at all: composing oracles with the Thompson
/// combinators blows past `MAXK` after two or three steps, and every proposal
/// came back `overflow` instead of a verdict.  Denotationally there is no size
/// limit, and the check is exact.
///
/// It is also the pruning: a correct solution satisfies `sol_s[X_t := q@t] ≡
/// q@s`, so a proposal is checked THE MOMENT IT IS MADE and a wrong `LOOPIFY`
/// dies with its subtree rather than at the leaf.
fn ex_accepts<const NA: usize>(e: &Ex, q: &Aut<NA>, seq: &[usize]) -> bool {
    bump(&CALC_ACCEPTS);
    match e {
        Ex::Test(m) => seq.len() == 1 && bit(*m, seq[0]),
        Ex::Act => seq.len() == 2,
        Ex::Sub(i) | Ex::Unk(i) => accepts_at(q, *i, seq),
        Ex::Seq(a, b) => (0..seq.len()).any(|i|
            ex_accepts(a, q, &seq[..=i]) && ex_accepts(b, q, &seq[i..])),
        Ex::Ite(g, a, b) =>
            if bit(*g, seq[0]) { ex_accepts(a, q, seq) } else { ex_accepts(b, q, seq) },
        Ex::Wh(g, a) => {
            if !bit(*g, seq[0]) { return seq.len() == 1; }
            (1..seq.len()).any(|i|
                ex_accepts(a, q, &seq[..=i]) && ex_accepts(e, q, &seq[i..]))
        }
    }
}

fn ex_walk<const NA: usize>(e: &Ex, q: &Aut<NA>, s: usize, seq: &mut Vec<usize>,
                            n: usize) -> bool {
    if ex_accepts(e, q, seq) != accepts_at(q, s, seq) { return false; }
    if seq.len() > n { return true; }
    for x in 0..NA {
        seq.push(x);
        let ok = ex_walk(e, q, s, seq, n);
        seq.pop();
        if !ok { return false; }
    }
    true
}

/// Does the candidate denote exactly the quotient's language at `s`, on every
/// guarded string of up to `n` actions?
fn ex_matches<const NA: usize>(e: &Ex, q: &Aut<NA>, s: usize, n: usize) -> bool {
    let mut seq: Vec<usize> = Vec::new();
    for x in 0..NA {
        seq.push(x);
        let ok = ex_walk(e, q, s, &mut seq, n);
        seq.pop();
        if !ok { return false; }
    }
    true
}

/// Structural hash, for the verdict memo.
fn ex_hash(e: &Ex, h: &mut std::collections::hash_map::DefaultHasher) {
    use std::hash::Hasher;
    match e {
        Ex::Test(m) => { h.write_u8(1); h.write_u8(*m); }
        Ex::Act => h.write_u8(2),
        Ex::Sub(i) => { h.write_u8(3); h.write_usize(*i); }
        Ex::Unk(i) => { h.write_u8(4); h.write_usize(*i); }
        Ex::Seq(a, b) => { h.write_u8(5); ex_hash(a, h); ex_hash(b, h); }
        Ex::Ite(g, a, b) => { h.write_u8(6); h.write_u8(*g); ex_hash(a, h); ex_hash(b, h); }
        Ex::Wh(g, a) => { h.write_u8(7); h.write_u8(*g); ex_hash(a, h); }
    }
}

fn ex_key(s: usize, e: &Ex) -> u64 {
    use std::hash::Hasher;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write_usize(s);
    ex_hash(e, &mut h);
    h.finish()
}

fn ex_dispatch(branches: &[(u8, Ex)], fallback: &Ex) -> Ex {
    let mut e = fallback.clone();
    for (g, c) in branches.iter().rev() {
        e = Ex::Ite(*g, Box::new(c.clone()), Box::new(e));
    }
    e
}

type Eqs = Vec<Option<(Vec<(u8, Ex)>, Ex)>>;

/// The dispatch of SCC state `s`, as branches plus fallback.
fn eq_of<const NA: usize>(q: &Aut<NA>, scc: &[usize], s: usize) -> (Vec<(u8, Ex)>, Ex) {
    let mut br = Vec::new();
    for a in 0..NA {
        let t = q.st[s][a];
        if t == 0 { continue; }
        let tt = (t - 1) as usize;
        let tail = if scc.contains(&tt) { Ex::Unk(tt) } else { Ex::Sub(tt) };
        br.push((1u8 << a, Ex::Seq(Box::new(Ex::Act), Box::new(tail))));
    }
    (br, Ex::Test(q.hl[s]))
}

/// **LOOPIFY / GATED search.**  LOOPIFY proposes `wh g (body with the unknown
/// replaced by `1`) ; fallback` — exactly `w3` when every branch ends in the
/// unknown, and exit absorption when a branch instead runs a continuation that
/// terminates outside `g`.  It is not sound unconditionally, so the language
/// check at the leaf disposes of wrong proposals and the search backtracks.
fn calc_search<const NA: usize>(q: &Aut<NA>, scc: &[usize], eq: &Eqs,
    sols: &mut Vec<Option<Ex>>, left: usize, depth: usize, budget: &mut usize,
    n: usize, gated: u16, memo: &mut FxMap<u64, bool>) -> bool
{
    if *budget == 0 { return false; }
    *budget -= 1;
    bump(&CALC_NODES);
    if left == 0 {
        // resolve residual references, then verify every SCC state
        let mut fin: Vec<Ex> = scc.iter().map(|&s| sols[s].clone().unwrap()).collect();
        // SIZE GUARD.  This resolution loop substitutes every solution into
        // every other, `scc.len()+1` times, so each round can SQUARE the
        // expression size.  Harmless at two or three states; at four or more
        // with a context-extended list it exhausts memory and kills the
        // process — which is exactly how the k=4 exhaustive run died
        // (`terminated abnormally`, 1248s of user time, no panic message).
        // Bailing out here is sound: it only means this candidate is not
        // pursued, and the search reports failure rather than a wrong answer.
        // The cap is a CORRECTNESS-AFFECTING knob, not free insurance: at
        // 20 000 the NA=4 census lost a solution it previously found (250/250
        // became 249/250), because legitimate solutions need large
        // intermediates.  Since the failure mode is SQUARING, sizes jump from
        // thousands to hundreds of millions in one round, so a cap two orders
        // of magnitude higher still stops the crash while leaving real
        // solutions untouched.  Verified by re-running the census to 250/250.
        const EX_CAP: usize = 2_000_000;
        for _ in 0..=scc.len() {
            for i in 0..fin.len() {
                for j in 0..fin.len() {
                    if i != j {
                        let r = fin[j].clone();
                        // PRE-check, not post-check.  Testing the size AFTER
                        // `ex_subst` is too late — the blowup happens INSIDE
                        // the substitution, which is why the k=4 run kept dying
                        // even with a guard in place.  Substituting `occ`
                        // occurrences of a term of size `n_r` into one of size
                        // `n_i` yields `n_i + occ*(n_r-1)`, so bound that
                        // before building anything.
                        let n_i = ex_size(&fin[i], EX_CAP);
                        let n_r = ex_size(&r, EX_CAP);
                        let occ = ex_count(&fin[i], scc[j]);
                        if n_i + occ * n_r > EX_CAP { return false; }
                        fin[i] = ex_subst(&fin[i], scc[j], &r);
                    }
                }
            }
        }
        for (i, &s) in scc.iter().enumerate() {
            if ex_occurs_any(&fin[i], scc) { return false; }
            if !ex_matches(&fin[i], q, s, n) { return false; }
        }
        return true;
    }
    if depth == 0 { return false; }
    // LOOPIFY
    for &s in scc.iter() {
        let (br, fb) = match &eq[s] { Some(x) => x.clone(), None => continue };
        // An equation with NO branches is still an equation — after a GATED
        // rewrite of a state that only REJECTS on the differing atom, the
        // branches are empty and the whole content is in the fallback.
        // Skipping those is what made the last three instances unreachable.
        if ex_occurs(&fb, s) { continue; }
        let mut g = 0u8;
        for (m, _) in br.iter() { g |= *m; }
        let all: u8 = if NA >= 8 { 0xFF } else { ((1u16 << NA) - 1) as u8 };
        let plain = ex_dispatch(&br, &fb);
        let selfref = ex_occurs(&plain, s);
        // No self-occurrence: the equation is already a definition, so SUBSTITUTE.
        // Wrapping a `wh` there would loop a body that never returns to `s`.
        //
        // With a self-occurrence, the proposal is LOOPIFY — and iteration 199's
        // ENTRY RESTRICTION generalizes it with two parameters:
        //
        //     sol s := test P ; wh g (body with X_s := test P) ; test F
        //
        // `P` is the region the loop head is allowed to be reached in, asserted
        // BEFORE the loop and again wherever the body returns; `F` is the
        // trailing test, which may then be WIDENED past `s`'s own halt to cover
        // a mid-body exit that `exit_absorb` cannot reach.  Plain LOOPIFY is
        // `P = all`, `F = hl(s)`, so one construction covers both rules.
        //
        // The candidate set is deliberately tiny — `P` is either everything or
        // `s`'s live atoms, `F` is `s`'s halt mask alone or widened by one atom
        // outside the guard — because the language check disposes of wrong
        // guesses and a small guess-and-check beats an analysis of which
        // invariant is needed.
        let live = q.hl[s] | g;
        let mut cands: Vec<(u8, Ex)> = Vec::new();
        if !selfref {
            cands.push((all, plain.clone()));
        } else {
            let base = ex_dispatch(&br, &Ex::Test(0));
            for &p_mask in [all, live].iter() {
                let body = ex_subst(&base, s, &Ex::Test(p_mask));
                let mut fs: Vec<Ex> = vec![fb.clone()];
                if p_mask != all {
                    for a in 0..NA {
                        if g >> a & 1 == 1 { continue; }
                        if let Ex::Test(m) = fb {
                            fs.push(Ex::Test(m | (1 << a)));
                        }
                    }
                }
                for f in fs {
                    let loop_ = Ex::Seq(Box::new(Ex::Wh(g, Box::new(body.clone()))),
                        Box::new(f));
                    cands.push((p_mask, if p_mask == all { loop_ } else {
                        Ex::Seq(Box::new(Ex::Test(p_mask)), Box::new(loop_))
                    }));
                }
            }
            // RULE 5: HALT-IN-BODY LOOPIFICATION (iteration 201).  Plain
            // LOOPIFY takes the loop guard to be the union of ALL branch
            // masks, which is wrong for a state whose branches SPLIT between
            // returning to `s` and leaving for another state: `wh` over the
            // union never exits at the leaving atoms.  Take the guard to be
            // only the RETURNING atoms and let the leaving branches become
            // the trailing expression:
            //
            //     sol s := wh g_self (returning branches, X_s := 1)
            //              ; dispatch(leaving branches, fallback)
            //
            // `halt_in_body_loopify` is what licenses this when the recursion
            // sits inside a branch body whose sibling arm is a halt: the loop
            // guard being false at the landing point subsumes that halt, so
            // one trailing conditional serves as back-edge AND second exit.
            let mut g_self = 0u8;
            let mut self_br: Vec<(u8, Ex)> = Vec::new();
            let mut out_br: Vec<(u8, Ex)> = Vec::new();
            for (m, e) in br.iter() {
                if ex_occurs(e, s) { g_self |= *m; self_br.push((*m, e.clone())); }
                else { out_br.push((*m, e.clone())); }
            }
            // `g_self == g` is plain LOOPIFY, already proposed above.
            if g_self != 0 && g_self != g {
                let body = ex_subst(&ex_dispatch(&self_br, &Ex::Test(all)), s,
                    &Ex::Test(all));
                let tail = ex_dispatch(&out_br, &fb);
                cands.push((all, Ex::Seq(
                    Box::new(Ex::Wh(g_self, Box::new(body.clone()))),
                    Box::new(tail.clone()))));
                // RULE 6: share the trailing suffix with every mid-body exit
                // that ends in it.  Try both the full tail and, when the tail
                // is a guarded dispatch, its then-arm — the loop exits into a
                // known region, so the guard wrapping the tail is often
                // redundant there and the arm is what a mid-body exit actually
                // shares.
                let mut fs: Vec<Ex> = vec![tail.clone()];
                if let Ex::Ite(_, t, _) = &tail { fs.push((**t).clone()); }
                for f in fs {
                    let shared = share_tail(&body, &f);
                    if shared != body {
                        cands.push((all, Ex::Seq(
                            Box::new(Ex::Wh(g_self, Box::new(shared))),
                            Box::new(tail.clone()))));
                    }
                }
            }
        }
        for (_pm, sol) in cands {
        if ex_occurs(&sol, s) { continue; }
        // PRUNE AT THE PROPOSAL: read the remaining unknowns as their oracles
        // and check this state's language now.
        let kind = if selfref { "LOOPIFY" } else { "SUBST" };
        // VERDICT MEMO.  The search reaches the same candidate by many rule
        // orders, and each check costs a full language walk — the dominant
        // cost by two orders of magnitude.  Hash the proposal once and reuse.
        let key = ex_key(s, &sol);
        let ok = match memo.get(&key) {
            Some(v) => *v,
            None => { let v = ex_matches(&sol, q, s, n); memo.insert(key, v); v }
        };
        let verdict = if ok { "ok" } else { "lang" };
        if calc_trace() {
            println!("      [calc] depth={depth} left={left} {kind}(X{s}) -> {verdict}");
        }
        if verdict != "ok" { continue; }
        let mut eq2 = eq.clone();
        eq2[s] = None;
        for &u in scc.iter() {
            if let Some((b, f)) = &eq[u] {
                if u == s { continue; }
                eq2[u] = Some((b.iter().map(|(m, c)| (*m, ex_subst(c, s, &sol))).collect(),
                               ex_subst(f, s, &sol)));
            }
        }
        sols[s] = Some(sol);
        if calc_search(q, scc, &eq2, sols, left - 1, depth - 1, budget, n, gated, memo) { return true; }
        sols[s] = None;
        }
    }
    // GATED
    for &u in scc.iter() {
        if eq[u].is_none() { continue; }
        for &v in scc.iter() {
            if u == v || eq[v].is_none() { continue; }
            let mut r = 0u8;
            let mut ndiff = 0usize;
            for a in 0..NA {
                if q.st[u][a] != q.st[v][a] || bit(q.hl[u], a) != bit(q.hl[v], a) {
                    r |= 1 << a;
                    ndiff += 1;
                }
            }
            if ndiff >= NA { continue; }
            let ui = match scc.iter().position(|&x| x == u) { Some(i) => i, None => continue };
            if gated >> ui & 1 == 1 { continue; }
            if calc_trace() {
                println!("      [calc] depth={depth} left={left} GATED(X{u} <- X{v}, r={r:04b})");
            }
            let (br0, _) = eq_of(q, scc, u);
            // Rebuilding from the ORIGINAL dispatch drops every substitution
            // already made, so re-apply the solved unknowns — otherwise the
            // rewritten equation reintroduces an eliminated unknown and the
            // final resolution cycles.
            let br: Vec<(u8, Ex)> = br0.into_iter()
                .filter(|(m, _)| m & r != 0)
                .map(|(m, c)| {
                    let mut c2 = c;
                    for &t in scc.iter() {
                        if let Some(st) = &sols[t] { c2 = ex_subst(&c2, t, st); }
                    }
                    (m, c2)
                })
                .collect();
            let mut eq2 = eq.clone();
            // The fallback must KEEP THE GUARD.  Inside `r` the states differ,
            // so `u` falls back to its OWN halt there (`0` when it neither
            // steps nor halts); only outside `r` may `v` stand for it.  Writing
            // the fallback as bare `X_v` drops the guard and silently asserts
            // `X_u ≡ X_v` — which is exactly the three instances that resisted:
            // identical transitions, halt masks differing at one atom, one
            // accepting there and the other rejecting.
            eq2[u] = Some((br, Ex::Ite(r, Box::new(Ex::Test(q.hl[u] & r)),
                                          Box::new(Ex::Unk(v)))));
            if calc_search(q, scc, &eq2, sols, left, depth - 1, budget, n,
                gated | (1 << ui), memo) { return true; }
        }
    }
    false
}

/// Does the three-rule calculus solve this SCC, with the answer LANGUAGE-CHECKED?
/// Largest SCC the calculus search will attempt.  Raised from the hard-coded 5
/// at iteration 203; `PAD_CALC_MAXSCC` overrides.  The search is exponential in
/// SCC size, so this trades runtime for coverage — but a skipped SCC must be
/// reported as skipped, not as a failure.
fn calc_max_scc() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("PAD_CALC_MAXSCC").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(7))
}

/// Hot-path env lookups, resolved once.  `std::env::var` allocates and locks
/// the environment on every call; `PAD_CALC_TRACE` in particular sat inside
/// `calc_search`'s candidate loop, so it ran per proposal.
fn calc_trace() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("PAD_CALC_TRACE").is_ok())
}

fn no_calc() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| std::env::var("PAD_NO_CALC").is_ok())
}

/// Whether the calculus will even try this SCC — the caller's guard, so that
/// "too big to attempt" is never silently folded into "the calculus failed".
fn calculus_attempted(scc: &[usize]) -> bool { scc.len() <= calc_max_scc() }

/// **SCC-LOCAL REASONING IS INCOMPLETE** (iteration 207).
///
/// Rule 6 (`trailing_suffix_shared`) needs to SEE that a mid-body exit ends in
/// the same expression as the loop's trailing suffix.  But states outside the
/// SCC enter the search as opaque `Ex::Sub` oracles, so for 206's resister the
/// tail reads `p ; Sub(c1)` and the mid-body exit `p ; Sub(c5)` — no shared
/// syntactic suffix, even though `Sub(c1) = 1` makes the real shared suffix
/// `p`.  Measured: that SCC is unsolvable given the SCC alone and solvable at
/// depth 5 given the whole automaton.  The obstruction is oracle opacity, not
/// the rule.
///
/// So extend the SCC with the outside states it can reach whose OWN SCC is a
/// singleton — those are solvable by the existing SUBST/elimination moves, and
/// solving them here makes their expressions syntactically visible to the
/// suffix match.  Non-singleton neighbours are left as oracles: they are other
/// loops, with their own solutions, and pulling them in would merge two
/// independent problems.
fn scc_with_context<const NA: usize>(q: &Aut<NA>, scc: &[usize],
    singleton: &[bool]) -> Vec<usize>
{
    let mut out: Vec<usize> = scc.to_vec();
    let mut i = 0;
    while i < out.len() {
        let s = out[i];
        i += 1;
        for y in 0..NA {
            let t = q.st[s][y];
            if t == 0 { continue; }
            let t = (t - 1) as usize;
            if out.contains(&t) || !singleton[t] { continue; }
            if out.len() >= calc_max_scc() { return out; }
            out.push(t);
        }
    }
    out
}

/// Which states lie in a SINGLETON strongly connected component.
fn singleton_states<const NA: usize>(q: &Aut<NA>) -> Vec<bool> {
    let mut v = vec![true; q.k as usize];
    for c in sccs_of(q) {
        if c.len() >= 2 { for &s in c.iter() { v[s] = false; } }
    }
    v
}

fn calculus_solves<const NA: usize>(q: &Aut<NA>, scc: &[usize], n: usize) -> bool {
    let k = q.k as usize;
    let mut eq: Eqs = vec![None; k];
    for &s in scc.iter() { eq[s] = Some(eq_of(q, scc, s)); }
    let mut sols: Vec<Option<Ex>> = vec![None; k];
    bump(&CALC_CALLS);
    // SIZE CAP.  This used to be a bare `if scc.len() > 5 { return false }`,
    // so an SCC too big to attempt was reported as a calculus FAILURE — the
    // rates published up to 202 were deflated by SCCs that were never tried
    // at all.  `calculus_attempted` is now the caller's guard, and the cap is
    // raised and tunable; anything over it must be counted as SKIPPED, never
    // as failed.
    if scc.len() > calc_max_scc() { bump(&CALC_SKIPPED); return false; }
    let mut budget = 400_000usize;
    let mut memo: FxMap<u64, bool> = FxMap::default();
    calc_search(q, scc, &eq, &mut sols, scc.len(), 3 * scc.len() + 3, &mut budget, n, 0,
        &mut memo)
}

fn sccs_of<const NA: usize>(q: &Aut<NA>) -> Vec<Vec<usize>> {
    let k = q.k as usize;
    let mut order: Vec<usize> = Vec::new();
    let mut seen = [false; MAXK];
    for s0 in 0..k {
        if seen[s0] { continue; }
        // iterative DFS with post-order
        let mut stack: Vec<(usize, usize)> = vec![(s0, 0)];
        seen[s0] = true;
        while let Some(&(s, i)) = stack.last() {
            if i >= NA { order.push(s); stack.pop(); continue; }
            stack.last_mut().unwrap().1 += 1;
            if q.st[s][i] != 0 {
                let t = (q.st[s][i] - 1) as usize;
                if !seen[t] { seen[t] = true; stack.push((t, 0)); }
            }
        }
    }
    // reverse graph
    let mut radj: Vec<Vec<usize>> = vec![Vec::new(); k];
    for s in 0..k { for a in 0..NA { if q.st[s][a] != 0 {
        radj[(q.st[s][a] - 1) as usize].push(s); } } }
    let mut comp = [usize::MAX; MAXK];
    let mut out: Vec<Vec<usize>> = Vec::new();
    for &s0 in order.iter().rev() {
        if comp[s0] != usize::MAX { continue; }
        let c = out.len();
        let mut members = vec![s0];
        comp[s0] = c;
        let mut st2 = vec![s0];
        while let Some(s) = st2.pop() {
            for &t in radj[s].iter() {
                if comp[t] == usize::MAX { comp[t] = c; members.push(t); st2.push(t); }
            }
        }
        out.push(members);
    }
    out
}

/// Halt masks reachable from `s` (including s's own).
fn reachable_halts<const NA: usize>(q: &Aut<NA>, s: usize) -> u8 {
    let mut seen = [false; MAXK];
    let mut st = vec![s];
    seen[s] = true;
    let mut acc = 0u8;
    while let Some(u) = st.pop() {
        acc |= q.hl[u];
        for a in 0..NA {
            if q.st[u][a] != 0 {
                let t = (q.st[u][a] - 1) as usize;
                if !seen[t] { seen[t] = true; st.push(t); }
            }
        }
    }
    acc
}

/// **The ring/uniformity classifier.**  Necessary-shape check for the ring witness: every
/// nontrivial SCC has (a) all its member halts on ONE shared guard mask c != 0 (interior
/// states may be halt-free), (b) at least one member halting exactly on c (a header
/// candidate), and (c) every halt reachable from the SCC also on c (exit continuations
/// terminate through the same guard, so they can be inlined).  Singleton SCCs are always
/// fine (guardedFold / levelSol).  This is the SHAPE the six Lean-certified ring
/// solutions (GkatCertR1-R6) instantiate; it does not itself build the walk.
fn ring_uniform<const NA: usize>(q: &Aut<NA>) -> bool {
    let sccs = sccs_of(q);
    'scc: for members in sccs.iter() {
        if members.len() <= 1 { continue; }
        let mut c = 0u8;
        for &s in members.iter() { c |= q.hl[s]; }
        if c == 0 {
            // No internal halts.  Case A: DEAD — no halt reachable from the SCC at
            // all: every member solves as `test 0` (S2/S3).  Case B2: EDGE-EXIT RING —
            // all exits concentrated at one header member as out-edges; the loop's
            // fallback is the exit continuation (plain levelSol shape).
            let mut reach = 0u8;
            for &s in members.iter() { reach |= reachable_halts(q, s); }
            if reach == 0 { continue 'scc; }                       // dead: zero solutions
            let mut exit_members = members.iter().filter(|&&s| (0..NA).any(|a|
                q.st[s][a] != 0 && !members.contains(&((q.st[s][a] - 1) as usize))));
            let h = match (exit_members.next(), exit_members.next()) {
                (Some(&h), None) => h,                              // exits at one member
                _ => return false,
            };
            let _ = h;
            continue 'scc;
        }
        // SUBSET parking (the mixed-halt candidate's lesson): an interior halt may be
        // any SUBSET of the header's exit guard — the parked atom still fails the loop
        // guard and passes the exit test.  Header: a state whose halt IS the join.
        for &s in members.iter() {
            if q.hl[s] & !c != 0 { return false; }              // outside the join
        }
        if !members.iter().any(|&s| q.hl[s] == c) { return false; } // no header
        // exits' reachable halts must stay on c
        for &s in members.iter() {
            for a in 0..NA {
                if q.st[s][a] != 0 {
                    let t = (q.st[s][a] - 1) as usize;
                    if !members.contains(&t) {
                        let rh = reachable_halts(q, t);
                        if rh & !c != 0 { return false; }
                    }
                }
            }
        }
    }
    true
}


/// One factor of a ring body walk.
#[derive(Debug, Clone)]
enum RingStep {
    /// Plain action to the next walk state (both atoms same target, or lone live atom).
    Act(usize),
    /// Halt on the exit guard, parked; action to next on the complement.
    Park(usize),
    /// Self-loop on atom `a` (inner `wh`), then the state's remaining behaviour follows.
    SelfLoop(usize),
    /// `ite (atom a) (p ; sol_ext) p`: exit to an already-solved state, inlined; continue to next.
    Inline(usize, usize, usize),
    /// `ite (atom a) p 0?`: dead guard (reject on the other atom); continue to next.
    DeadGuard(usize, usize),
    /// Nested sub-cycle entered on atom `a` at this state: inner while with its own walk.
    Sub(usize, Vec<(usize, Vec<RingStep>)>),
    /// Branch: on atom `a`, a linear side chain to the header; else continue the trunk.
    Branch(usize, Vec<(usize, Vec<RingStep>)>, usize),
}

/// Is a factor actionless under the exit guard `c`?  (Parked runs pass through these.)
fn park_transparent(s: &RingStep) -> bool {
    matches!(s, RingStep::Park(_) | RingStep::SelfLoop(_))
}

/// Validity: once a walk parks, every later factor must be transparent under `c`.
fn walk_park_valid(walk: &[(usize, Vec<RingStep>)]) -> bool {
    let mut parked = false;
    for (_, steps) in walk.iter() {
        for st in steps.iter() {
            if parked && !park_transparent(st) { return false; }
            if matches!(st, RingStep::Park(_)) { parked = true; }
        }
    }
    true
}

/// A linear chain from `t` to the header: Act/Park/SelfLoop/DeadGuard only, no
/// branching, park-valid.  Used for the side arm of a Branch factor.
fn side_chain<const NA: usize>(q: &Aut<NA>, members: &[usize], h: usize, t0: usize, c: u8)
    -> Option<Vec<(usize, Vec<RingStep>)>> {
    let inscc = |t: usize| members.contains(&t);
    let mut cur = t0;
    let mut out: Vec<(usize, Vec<RingStep>)> = Vec::new();
    let mut fuel = 2 * members.len() + 4;
    while cur != h {
        if fuel == 0 { return None; }
        fuel -= 1;
        let s = cur;
        if !inscc(s) { return None; }
        let mut steps: Vec<RingStep> = Vec::new();
        let selfatoms: Vec<usize> = (0..NA)
            .filter(|&a| q.st[s][a] != 0 && (q.st[s][a] - 1) as usize == s).collect();
        if selfatoms.len() > 1 { return None; }
        for &a in selfatoms.iter() { steps.push(RingStep::SelfLoop(a)); }
        let rest: Vec<usize> = (0..NA).filter(|a| !selfatoms.contains(a)).collect();
        let ins: Vec<(usize, usize)> = rest.iter().cloned()
            .filter(|&a| q.st[s][a] != 0 && (q.st[s][a] - 1) as usize != s)
            .map(|a| (a, (q.st[s][a] - 1) as usize)).collect();
        let halts: Vec<usize> = rest.iter().cloned()
            .filter(|&a| q.st[s][a] == 0 && q.hl[s] & (1 << a) != 0).collect();
        let rejects: Vec<usize> = rest.iter().cloned()
            .filter(|&a| q.st[s][a] == 0 && q.hl[s] & (1 << a) == 0).collect();
        if q.hl[s] != 0 && q.hl[s] & !c != 0 { return None; }
        if ins.len() != 1 && !(ins.len() == 2 && ins[0].1 == ins[1].1) { return None; }
        let t = ins[0].1;
        if !inscc(t) { return None; }
        if ins.len() == 2 { steps.push(RingStep::Act(t)); }
        else if !halts.is_empty() { steps.push(RingStep::Park(t)); }
        else if !rejects.is_empty() { steps.push(RingStep::DeadGuard(ins[0].0, t)); }
        else { steps.push(RingStep::Act(t)); }
        out.push((s, steps));
        cur = t;
    }
    if !walk_park_valid(&out) { return None; }
    Some(out)
}

/// Attempt a walk plan for one SCC: header + ordered per-state factor lists.
/// Returns (header, walk as [(state, factors)]) or None.
fn plan_scc<const NA: usize>(q: &Aut<NA>, members: &[usize]) -> Option<(usize, Vec<(usize, Vec<RingStep>)>)> {
    let inscc = |t: usize| members.contains(&t);
    let mut c = 0u8;
    for &s in members.iter() { c |= q.hl[s]; }
    if c == 0 { return None; }
    // header: halts exactly on c, exactly one out-transition, target in SCC
    'hdr: for &h in members.iter() {
        if q.hl[h] != c { continue; }
        let outs: Vec<(usize, usize)> = (0..NA)
            .filter(|&a| q.st[h][a] != 0)
            .map(|a| (a, (q.st[h][a] - 1) as usize)).collect();
        if outs.len() != 1 || !inscc(outs[0].1) { continue; }
        let mut cur = outs[0].1;
        let mut visited = vec![h];
        let mut walk: Vec<(usize, Vec<RingStep>)> = Vec::new();
        let mut fuel = 4 * members.len() + 8;
        while cur != h {
            if visited.contains(&cur) { continue 'hdr; }
            if fuel == 0 { continue 'hdr; }
            fuel -= 1;
            visited.push(cur);
            let s = cur;
            let mut steps: Vec<RingStep> = Vec::new();
            // self-loop first
            let selfatoms: Vec<usize> = (0..NA)
                .filter(|&a| q.st[s][a] != 0 && (q.st[s][a] - 1) as usize == s).collect();
            if selfatoms.len() > 1 { continue 'hdr; }
            for &a in selfatoms.iter() { steps.push(RingStep::SelfLoop(a)); }
            let rest: Vec<usize> = (0..NA).filter(|a| !selfatoms.contains(a)).collect();
            let ins: Vec<(usize, usize)> = rest.iter().cloned()
                .filter(|&a| q.st[s][a] != 0 && inscc((q.st[s][a] - 1) as usize) && (q.st[s][a] - 1) as usize != s)
                .map(|a| (a, (q.st[s][a] - 1) as usize)).collect();
            let exts: Vec<(usize, usize)> = rest.iter().cloned()
                .filter(|&a| q.st[s][a] != 0 && !inscc((q.st[s][a] - 1) as usize))
                .map(|a| (a, (q.st[s][a] - 1) as usize)).collect();
            let halts: Vec<usize> = rest.iter().cloned()
                .filter(|&a| q.st[s][a] == 0 && q.hl[s] & (1 << a) != 0).collect();
            let rejects: Vec<usize> = rest.iter().cloned()
                .filter(|&a| q.st[s][a] == 0 && q.hl[s] & (1 << a) == 0).collect();
            if q.hl[s] != 0 && q.hl[s] & !c != 0 { continue 'hdr; }
            let next: usize;
            match ins.len() {
                1 => {
                    let (_, t) = ins[0];
                    if !halts.is_empty() {
                        steps.push(RingStep::Park(t));
                    } else if let Some(&(ae, te)) = exts.first() {
                        if reachable_halts(q, te) & !c != 0 { continue 'hdr; }
                        steps.push(RingStep::Inline(ae, te, t));
                    } else if !rejects.is_empty() {
                        steps.push(RingStep::DeadGuard(ins[0].0, t));
                    } else {
                        steps.push(RingStep::Act(t));
                    }
                    next = t;
                }
                2 => {
                    let (a0, t0) = ins[0];
                    let (a1, t1) = ins[1];
                    if t0 == t1 { steps.push(RingStep::Act(t0)); next = t0; }
                    else if {
                        let returns_chk = |t: usize| -> bool {
                            let mut seen = [false; MAXK];
                            let mut st2 = vec![t];
                            seen[t] = true;
                            while let Some(u) = st2.pop() {
                                if u == s { return true; }
                                if u == h { continue; }
                                for a in 0..NA {
                                    if q.st[u][a] != 0 {
                                        let v = (q.st[u][a] - 1) as usize;
                                        if !seen[v] { seen[v] = true; st2.push(v); }
                                    }
                                }
                            }
                            false
                        };
                        (returns_chk(ins[0].1) && !returns_chk(ins[1].1))
                            || (returns_chk(ins[1].1) && !returns_chk(ins[0].1))
                    } {
                        // one branch is a sub-cycle returning to s without passing h
                        let returns = |t: usize| -> bool {
                            let mut seen = [false; MAXK];
                            let mut st2 = vec![t];
                            seen[t] = true;
                            while let Some(u) = st2.pop() {
                                if u == s { return true; }
                                if u == h { continue; }
                                for a in 0..NA {
                                    if q.st[u][a] != 0 {
                                        let v = (q.st[u][a] - 1) as usize;
                                        if !seen[v] { seen[v] = true; st2.push(v); }
                                    }
                                }
                            }
                            false
                        };
                        let (a0, t0) = ins[0];
                        let (a1, t1) = ins[1];
                        let (asub, tsub, tcont) = if returns(t0) && !returns(t1) { (a0, t0, t1) }
                            else if returns(t1) && !returns(t0) { (a1, t1, t0) }
                            else { continue 'hdr };
                        // inner walk from tsub back to s: only Act/DeadGuard/SelfLoop factors
                        let mut icur = tsub;
                        let mut iwalk: Vec<(usize, Vec<RingStep>)> = Vec::new();
                        let mut ifuel = 2 * members.len() + 4;
                        let ok = loop {
                            if icur == s { break true; }
                            if ifuel == 0 { break false; }
                            ifuel -= 1;
                            let u = icur;
                            if q.hl[u] != 0 { break false; }
                            let mut isteps: Vec<RingStep> = Vec::new();
                            let uself: Vec<usize> = (0..NA)
                                .filter(|&a| q.st[u][a] != 0 && (q.st[u][a] - 1) as usize == u).collect();
                            if uself.len() > 1 { break false; }
                            for &a in uself.iter() { isteps.push(RingStep::SelfLoop(a)); }
                            let urest: Vec<usize> = (0..NA).filter(|a| !uself.contains(a)).collect();
                            let uins: Vec<(usize, usize)> = urest.iter().cloned()
                                .filter(|&a| q.st[u][a] != 0)
                                .map(|a| (a, (q.st[u][a] - 1) as usize)).collect();
                            let urejects: Vec<usize> = urest.iter().cloned()
                                .filter(|&a| q.st[u][a] == 0).collect();
                            match uins.len() {
                                1 => {
                                    let (ua, ut) = uins[0];
                                    if !urejects.is_empty() { isteps.push(RingStep::DeadGuard(ua, ut)); }
                                    else { isteps.push(RingStep::Act(ut)); }
                                    iwalk.push((u, isteps));
                                    icur = ut;
                                }
                                2 if uins[0].1 == uins[1].1 => {
                                    isteps.push(RingStep::Act(uins[0].1));
                                    let t = uins[0].1;
                                    iwalk.push((u, isteps));
                                    icur = t;
                                }
                                _ => break false,
                            }
                        };
                        if !ok { continue 'hdr; }
                        steps.push(RingStep::Sub(asub, iwalk));
                        steps.push(RingStep::Act(tcont));
                        next = tcont;
                    }
                    else if ins.iter().any(|&(_, t)| t == h) {
                        // BRANCH: one arm to the header directly, the other continues the
                        // trunk — or a linear side chain to the header (checked below).
                        let (ah, _) = *ins.iter().find(|&&(_, t)| t == h).unwrap();
                        let (_, tc) = *ins.iter().find(|&&(_, t)| t != h).unwrap();
                        steps.push(RingStep::Branch(ah, Vec::new(), tc));
                        next = tc;
                    }
                    else if let Some((aside, side, tcont)) = {
                        // try each arm as a linear side chain to the header
                        let mut found: Option<(usize, Vec<(usize, Vec<RingStep>)>, usize)> = None;
                        for (i, &(ai, ti)) in ins.iter().enumerate() {
                            let other = ins[1 - i].1;
                            if let Some(chain) = side_chain(q, members, h, ti, c) {
                                // side chain must not re-enter the trunk
                                if chain.iter().all(|(u, _)| *u != other && !visited.contains(u)) {
                                    found = Some((ai, chain, other));
                                    break;
                                }
                            }
                        }
                        found
                    } {
                        steps.push(RingStep::Branch(aside, side, tcont));
                        next = tcont;
                    }
                    else { continue 'hdr; }
                }
                _ => continue 'hdr,
            }
            walk.push((s, steps));
            cur = next;
        }
        if !walk_park_valid(&walk) { continue 'hdr; }
        return Some((h, walk));
    }
    None
}

/// Print a ring plan for every nontrivial SCC of `q`; returns false if any SCC has no plan.
fn print_ring_plan<const NA: usize>(q: &Aut<NA>) -> bool {
    let sccs = sccs_of(q);
    let mut ok = true;
    for members in sccs.iter() {
        let nontrivial = members.len() > 1;
        if !nontrivial { continue; }
        match plan_scc(q, members) {
            Some((h, walk)) => {
                let mut c = 0u8;
                for &s in members.iter() { c |= q.hl[s]; }
                println!("    RING SCC {:?} header={} exit=0b{:02b}", members, h, c);
                for (s, steps) in walk.iter() {
                    println!("      state {s}: {:?}", steps);
                }
            }
            None => { println!("    RING SCC {:?}: NO PLAN", members); ok = false; }
        }
    }
    ok
}

/// PAD_ATTACK: the k=6 residue pairs, re-analysed in isolation.  For each pair: every
/// merged-start congruence quotient with its size / eliminability / pool verdict, and the
/// full table of each small quotient — the raw material for a hand proof.
fn attack_residue<const NA: usize>(list: &[Aut<NA>], seen: &Interner) {
    // Base rate first (standing rule): how common is the ring/uniform shape among
    // automata KNOWN to be fine (the Thompson pool itself)?
    {
        let mut uni = 0usize;
        let mut tot = 0usize;
        // THE UNIFORMIZATION EXPERIMENT.  Uniformity is FALSE for ~4% of Thompson
        // automata, so the general invariant must be existential: SOME quotient
        // uniformizes.  Candidate canonical construction: the coarsest behavioural
        // quotient.  Test it on exactly the automata where uniformity fails.
        let mut nonuni = 0usize;
        let mut restored = 0usize;
        let mut already_min = 0usize;
        let mut samples = 0usize;
        let stride = (list.len() / 20000).max(1);
        for a in list.iter().step_by(stride).take(20000) {
            if let Some(g) = to_gaut(a) {
                tot += 1;
                if ring_uniform(&g) { uni += 1; } else {
                    nonuni += 1;
                    if nonuni <= 5 {
                        println!("  GENUINE NON-UNIFORM #{nonuni} (k={}):", g.k);
                        for s in 0..g.k as usize {
                            let steps: Vec<String> = (0..NA).map(|i|
                                if g.st[s][i] == 0 { "-".to_string() }
                                else { format!("{}", g.st[s][i] - 1) }).collect();
                            println!("    {s}: hlt=0b{:02b} st={:?}", g.hl[s], steps);
                        }
                    }
                    let (blk, nb) = bisim_blocks(&g);
                    if nb == g.k as usize { already_min += 1; }
                    if let Some(q) = quotient_by(&g, &blk, nb) {
                        if ring_uniform(&q) { restored += 1; }
                        else if samples < 5 {
                            samples += 1;
                            println!("  UNIFORMIZATION FAILURE sample #{samples} (k={} -> {nb}):", g.k);
                            for s in 0..q.k as usize {
                                let steps: Vec<String> = (0..NA).map(|i|
                                    if q.st[s][i] == 0 { "-".to_string() }
                                    else { format!("{}", q.st[s][i] - 1) }).collect();
                                println!("    {s}: hlt=0b{:02b} st={:?}", q.hl[s], steps);
                            }
                        }
                    }
                }
            }
        }
        println!("RING-UNIFORM base rate on pool automata : {uni} / {tot}");
        println!("UNIFORMIZATION: non-uniform {nonuni}, coarsest-quotient restores {restored}, already-minimal {already_min}");
        // The decisive sub-question: do MIXED-HALT SCCs (two mutually-reachable states
        // with different nonzero halt guards) occur at all?  At NA=2 the guard algebra
        // may be too small for them; at NA=4 (two primitive tests) they are the shape
        // linear parking cannot handle.
        let mut mixed = 0usize;
        let mut mixed_min = 0usize;
        let mut shown = 0usize;
        for a in list.iter().step_by(stride).take(20000) {
            if let Some(g) = to_gaut(a) {
                let has_mixed = |q: &Aut<NA>| sccs_of(q).iter().any(|members|
                    members.len() > 1 && members.iter().any(|&s| q.hl[s] != 0
                        && members.iter().any(|&t| q.hl[t] != 0 && q.hl[t] != q.hl[s])));
                if has_mixed(&g) {
                    mixed += 1;
                    let (blk, nb) = bisim_blocks(&g);
                    if let Some(q) = quotient_by(&g, &blk, nb) {
                        if has_mixed(&q) {
                            mixed_min += 1;
                            if shown < 3 {
                                shown += 1;
                                println!("  MIXED-HALT MINIMAL sample #{shown} (k={}):", q.k);
                                for s in 0..q.k as usize {
                                    let steps: Vec<String> = (0..NA).map(|i|
                                        if q.st[s][i] == 0 { "-".to_string() }
                                        else { format!("{}", q.st[s][i] - 1) }).collect();
                                    println!("    {s}: hlt={:#06b} st={:?}", q.hl[s], steps);
                                }
                            }
                        }
                    }
                }
            }
        }
        println!("MIXED-HALT SCCs: raw {mixed} / 20000, surviving minimization {mixed_min}");
    }
    if std::env::var("PAD_ATTACK_NOPAIRS").is_ok() { return; }
    let filed: Vec<(String, String)> = std::env::var("PAD_ATTACK_FILE").ok()
        .map(|f| {
            let txt = std::fs::read_to_string(&f).expect("PAD_ATTACK_FILE unreadable");
            let mut es: Option<String> = None;
            let mut out = Vec::new();
            for line in txt.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("e = ") { es = Some(rest.to_string()); }
                else if let Some(rest) = t.strip_prefix("f = ") {
                    out.push((es.take().expect("f without e"), rest.to_string()));
                }
            }
            out
        })
        .unwrap_or_default();
    let pairs: [(&str, &str); 6] = [
        ("((([t2] +2 p);(p)^2);(((([t0] +2 p);([t1] +1 p));([t2] +2 p)))^1)",
         "((p;(p)^2);(((([t0] +2 p);([t1] +1 p));([t2] +2 p)))^1)"),
        ("(((p;(([t0] +1 p) +2 (p;[t1]))))^2 +2 (p;[t1]))",
         "((([t1] +1 p);((p;[t1]) +1 [t2]));((p;((p;((p;[t1]) +1 [t2])) +2 [t1])))^2)"),
        ("(([t0] +2 p);((p;((([t0] +1 p);[t1]) +2 (([t0] +2 p);([t2] +2 p)))))^1)",
         "(((p;((p;(((([t0] +1 p);([t0] +2 p)))^2;p)) +1 [t2])))^1 +1 [t0])"),
        ("((p;(((p;p);(p)^2) +2 p)))^2",
         "((p;(((([t0] +1 p);([t2] +2 p));(p)^2) +2 p)))^2"),
        ("(((([t0] +1 p);([t2] +2 p)) +2 [t1]);(((p)^1;(([t0] +1 p);([t2] +2 p))))^1)",
         "(((p)^1;([t0] +1 p));((p;(((p)^1;([t0] +1 p)) +1 [t2])))^1)"),
        ("((((p;p);(p)^1);(([t0] +1 p);([t1] +1 p))))^2",
         "((((([t0] +1 p);([t1] +1 p));(p)^1);(([t0] +1 p);([t1] +1 p))))^2"),
    ];
    let all_pairs: Vec<(String, String)> = if filed.is_empty() {
        pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    } else { filed };
    let mut ring_yes = 0usize;
    let mut ring_no = 0usize;
    for (pi, (es, fs)) in all_pairs.iter().enumerate() {
        let mut pos = 0usize;
        let (ae, el, epaths) = parse_attack::<NA>(es.as_bytes(), &mut pos);
        assert_eq!(pos, es.len(), "trailing input in e #{}", pi + 1);
        pos = 0;
        let (af, fl, fpaths) = parse_attack::<NA>(fs.as_bytes(), &mut pos);
        assert_eq!(pos, fs.len(), "trailing input in f #{}", pi + 1);
        println!("ATTACK #{}", pi + 1);
        println!("  e = {es}");
        println!("  f = {fs}");
        println!("  LEAN e := {el}");
        println!("  LEAN f := {fl}");
        println!("  behaviour equal : {}", behaviour(&ae) == behaviour(&af));
        let ka = match to_gaut(&ae) { Some(g) => g.k as usize, None => { println!("  e not convertible"); continue } };
        let su = match sum_core(&ae, &af) { Some(s) => s, None => { println!("  no sum"); continue } };
        println!("  sum: k={} (e-side 0..{}, f-side {}..{})", su.k, ka - 1, ka, su.k as usize - 1);
        for s in 0..su.k as usize {
            let steps: Vec<String> = (0..NA).map(|i|
                if su.st[s][i] == 0 { "-".to_string() } else { format!("{}", su.st[s][i] - 1) }).collect();
            println!("    {s}: hlt={:#04b} st={:?}", su.hl[s], steps);
        }
        let base = match close_congruence(&su, &[(0, ka)]) { Some(c) => c, None => { println!("  starts not mergeable"); continue } };
        let mut cands: Vec<([usize; MAXK], usize)> = vec![base];
        for cg in lattice_congruences(&su).iter() {
            if cg.0[0] == cg.0[ka] { cands.push(*cg); }
        }
        println!("  merged-start congruences : {}", cands.len());
        let mut best_cert: Option<([usize; MAXK], usize, Aut<NA>)> = None;
        for (b2, nb2) in cands.iter() {
            if let Some(q) = quotient_by(&su, b2, *nb2) {
                let qq = trim_canon(&q).unwrap_or(q);
                if qq.k == *nb2 as u8
                    && best_cert.as_ref().map(|c| (qq.k as usize) < c.1).unwrap_or(true) {
                    best_cert = Some((*b2, *nb2, q));
                }
                let elim = symbolic_eliminable(&qq);
                let inpool = canon(&qq).map(|c| seen.contains(&c)).unwrap_or(false);
                let ring = ring_uniform(&qq);
                println!("    quotient k={} elim={elim} pool={inpool} ring={ring} classes={:?}",
                    qq.k, &b2[..su.k as usize]);
                if (qq.k as usize) <= 6 {
                    println!("      init: ih={:#04b} it={:?}", qq.ih,
                        (0..NA).map(|i| if qq.it[i] == 0 { "-".to_string() }
                            else { format!("{}", qq.it[i] - 1) }).collect::<Vec<_>>());
                    for s in 0..qq.k as usize {
                        let steps: Vec<String> = (0..NA).map(|i|
                            if qq.st[s][i] == 0 { "-".to_string() } else { format!("{}", qq.st[s][i] - 1) }).collect();
                        println!("      {s}: hlt={:#04b} st={:?}", qq.hl[s], steps);
                    }
                }
            }
        }
        if let Some((_, _, ref q)) = best_cert {
            if ring_uniform(q) { ring_yes += 1; } else { ring_no += 1;
                println!("  RING-NONUNIFORM pair #{}", pi + 1); }
            if !print_ring_plan(q) { println!("  RING-UNPLANNABLE pair #{}", pi + 1); }
        }
        // CERT block for the smallest untrimmed-clean quotient, in emit_cert.py's format.
        if let Some((blk, nb, q)) = best_cert {
            println!("  CERT #A{}", pi + 1);
            println!("    quotient k={nb}");
            println!("    LEAN e := {el}");
            println!("    LEAN f := {fl}");
            for c in 0..nb {
                let recs: Vec<String> = (0..NA)
                    .filter(|&i| q.st[c][i] as usize == c + 1)
                    .map(|i| format!("atom{i}")).collect();
                let fwds: Vec<String> = (0..NA)
                    .filter(|&i| q.st[c][i] != 0 && q.st[c][i] as usize != c + 1)
                    .map(|i| format!("(atom{i}, act, s{})", q.st[c][i] - 1)).collect();
                println!("    s{c}: rec=[{}] fwd=[{}] hlt=0b{:02b}",
                    recs.join(", "), fwds.join(", "), q.hl[c]);
            }
            let order: Vec<String> = (0..nb).rev().map(|c| c.to_string()).collect();
            println!("    solve order (reverse-topological): [{}]", order.join(", "));
            for s in 0..su.k as usize {
                let steps: Vec<String> = (0..NA).map(|i|
                    if su.st[s][i] == 0 { "\"-\"".to_string() }
                    else { format!("\"{}\"", su.st[s][i] - 1) }).collect();
                println!("      {s}: hlt=0b{:02b} steps=[{}]", su.hl[s], steps.join(", "));
            }
            println!("    qmap (e-side): none -> s{}", blk[0]);
            for (i, pth) in epaths.iter().enumerate() {
                println!("      inl (some {pth}) -> s{}", blk[1 + i]);
            }
            println!("    qmap (f-side): none -> s{}", blk[ka]);
            for (i, pth) in fpaths.iter().enumerate() {
                println!("      inr (some {pth}) -> s{}", blk[ka + 1 + i]);
            }
        }
    }
    println!("RING-UNIFORM smallest quotients : {ring_yes} yes, {ring_no} no");
}



/// Global closure interner keyed by 128-bit fingerprints instead of full canonical
/// automata: two independently-seeded SipHash states give a (u64, u64) key, cutting
/// seen-set key memory ~6x (collision odds at 10^8 keys are ~2^-48 — negligible for
/// measurement integrity).  FastDedup-style fingerprinting; the `list` keeps the full
/// automata, so nothing downstream loses information.
struct Interner {
    h1: std::collections::hash_map::RandomState,
    h2: std::collections::hash_map::RandomState,
    map: FxMap<(u64, u64), u32>,
}

impl Interner {
    fn new() -> Self {
        Interner {
            h1: std::collections::hash_map::RandomState::new(),
            h2: std::collections::hash_map::RandomState::new(),
            map: FxMap::default(),
        }
    }
    fn fp<T: std::hash::Hash>(&self, t: &T) -> (u64, u64) {
        use std::hash::BuildHasher;
        (self.h1.hash_one(t), self.h2.hash_one(t))
    }
    fn contains<T: std::hash::Hash>(&self, t: &T) -> bool {
        self.map.contains_key(&self.fp(t))
    }
    fn insert<T: std::hash::Hash>(&mut self, t: &T, v: u32) {
        let k = self.fp(t);
        self.map.insert(k, v);
    }
    fn get<T: std::hash::Hash>(&self, t: &T) -> Option<&u32> {
        self.map.get(&self.fp(t))
    }
    #[allow(dead_code)]
    fn len(&self) -> usize { self.map.len() }
}


/// Closure cache: the (list, prov) pair is deterministic given (NA, maxk), and rebuilding
/// it dominates iteration time for attack/classifier runs.  Raw little-endian dump with a
/// params header; the interner is rebuilt on load (its hash seeds are per-process).
fn save_closure<const NA: usize>(path: &str, maxk: usize, list: &[Aut<NA>], prov: &[Prov]) {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).expect("save_closure"));
    f.write_all(b"GKCL1\0").unwrap();
    f.write_all(&(NA as u32).to_le_bytes()).unwrap();
    f.write_all(&(maxk as u32).to_le_bytes()).unwrap();
    f.write_all(&(list.len() as u64).to_le_bytes()).unwrap();
    for a in list.iter() {
        f.write_all(&[a.k, a.ih]).unwrap();
        f.write_all(&a.it[..]).unwrap();
        for s in 0..MAXK { f.write_all(&a.st[s][..]).unwrap(); }
        f.write_all(&a.hl[..]).unwrap();
    }
    for pv in prov.iter() {
        match pv {
            Prov::Leaf => f.write_all(&[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            Prov::Seq(l, r) => {
                f.write_all(&[1u8, 0]).unwrap();
                f.write_all(&l.to_le_bytes()).unwrap();
                f.write_all(&r.to_le_bytes()).unwrap();
            }
            Prov::Ite(g, l, r) => {
                f.write_all(&[2u8, *g]).unwrap();
                f.write_all(&l.to_le_bytes()).unwrap();
                f.write_all(&r.to_le_bytes()).unwrap();
            }
            Prov::Wh(g, b) => {
                f.write_all(&[3u8, *g]).unwrap();
                f.write_all(&b.to_le_bytes()).unwrap();
                f.write_all(&0u32.to_le_bytes()).unwrap();
            }
        }
    }
}

fn load_closure<const NA: usize>(path: &str, maxk: usize) -> Option<(Vec<Aut<NA>>, Vec<Prov>)> {
    use std::io::Read;
    let mut f = std::io::BufReader::new(std::fs::File::open(path).ok()?);
    let mut hdr = [0u8; 6];
    f.read_exact(&mut hdr).ok()?;
    if &hdr != b"GKCL1\0" { return None; }
    let mut w4 = [0u8; 4];
    f.read_exact(&mut w4).ok()?;
    if u32::from_le_bytes(w4) as usize != NA { return None; }
    f.read_exact(&mut w4).ok()?;
    if u32::from_le_bytes(w4) as usize != maxk { return None; }
    let mut w8 = [0u8; 8];
    f.read_exact(&mut w8).ok()?;
    let n = u64::from_le_bytes(w8) as usize;
    let mut list: Vec<Aut<NA>> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut a = Aut::<NA> { k: 0, ih: 0, it: [0; NA], st: [[0; NA]; MAXK], hl: [0; MAXK] };
        let mut b2 = [0u8; 2];
        f.read_exact(&mut b2).ok()?;
        a.k = b2[0]; a.ih = b2[1];
        f.read_exact(&mut a.it[..]).ok()?;
        for s in 0..MAXK { f.read_exact(&mut a.st[s][..]).ok()?; }
        f.read_exact(&mut a.hl[..]).ok()?;
        list.push(a);
    }
    let mut prov: Vec<Prov> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut rec = [0u8; 10];
        f.read_exact(&mut rec).ok()?;
        let l = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]);
        let r = u32::from_le_bytes([rec[6], rec[7], rec[8], rec[9]]);
        prov.push(match rec[0] {
            0 => Prov::Leaf,
            1 => Prov::Seq(l, r),
            2 => Prov::Ite(rec[1], l, r),
            3 => Prov::Wh(rec[1], l),
            _ => return None,
        });
    }
    Some((list, prov))
}


/// PAD_FORGE: the sampled crux forge — union-conjunct evidence beyond closure reach.
/// Random expressions per size stratum; behaviour-hash collisions give equivalent pairs;
/// each pair's merged-start congruence lattice is tested with POOL-FREE witnesses only
/// (symbolic elimination + the ring/uniformity shape).  Losing the Thompson-pool witness
/// only under-counts coverage, so "neither" is a conservative residue-candidate list.
/// Env: PAD_FORGE_N (target pairs, default 2000), PAD_FORGE_DEPTH (default 6),
/// PAD_FORGE_KMIN/KMAX (default 3/8).

/// PAD_EMIT_MIX: emit the complete Lean certificate for a subset-parking 2-ring pair
/// (the mixed-halt frontier shape) over Tst = Bool.  Returns false if the quotient does
/// not match the supported shape.  Paths are translated from construction order to the
/// canon numbering the sum uses (the python pilot's misalignment bug, fixed at the
/// source: the harness owns canon_order).
#[allow(clippy::too_many_arguments)]
fn emit_mix_pilot<const NA: usize>(path: &str, ae: &str, be: &str,
    astr: &Aut<NA>, bstr: &Aut<NA>, apaths: &[String], bpaths: &[String],
    su: &Aut<NA>, q: &Aut<NA>, blk: &[usize; MAXK], nb: usize) -> bool {
    if NA != 4 || nb != 2 { return false; }
    // shape: header h (halt = join, one self atom, one step atom to s); s (two self
    // atoms, one exit atom to h, halt a proper subset of the join)
    let join = q.hl[0] | q.hl[1];
    let h = if q.hl[0] == join { 0usize } else if q.hl[1] == join { 1 } else { return false };
    let s = 1 - h;
    if q.hl[s] & !join != 0 || q.hl[s] == join { return false; }
    let selfa: Vec<usize> = (0..NA).filter(|&a| q.st[h][a] as usize == h + 1).collect();
    let stepa: Vec<usize> = (0..NA).filter(|&a| q.st[h][a] as usize == s + 1).collect();
    if selfa.len() != 1 || stepa.len() != 1 { return false; }
    let sself: Vec<usize> = (0..NA).filter(|&a| q.st[s][a] as usize == s + 1).collect();
    let sexit: Vec<usize> = (0..NA).filter(|&a| q.st[s][a] as usize == h + 1).collect();
    if sself.len() != 2 || sexit.len() != 1 { return false; }
    let (ha, pa) = (selfa[0], stepa[0]);
    let (r1, r2, xa) = (sself[0], sself[1], sexit[0]);
    let m = |a: usize| mask_lean_gen::<NA>(1u8 << a);
    let g_step = m(pa);
    let g_self = m(ha);
    let g_r1 = m(r1);
    let g_r2 = m(r2);
    let g_x = m(xa);
    let g_ch = mask_lean_gen::<NA>(q.hl[h]);
    let g_cs = mask_lean_gen::<NA>(q.hl[s]);
    // sum-index -> (lean term, class): 0 = e-init; canon-core j -> 1+j; then f side
    let ka = astr.k as usize + 1;
    let aord = canon_order(astr);
    let bord = canon_order(bstr);
    let mut terms: Vec<(String, usize)> = Vec::new();
    terms.push(("(Sum.inl none)".to_string(), blk[0]));
    for j in 0..astr.k as usize {
        let i = (0..astr.k as usize).find(|&i| aord[i] as usize == j).unwrap();
        terms.push((format!("(Sum.inl (some {}))", apaths[i]), blk[1 + j]));
    }
    terms.push(("(Sum.inr none)".to_string(), blk[ka]));
    for j in 0..bstr.k as usize {
        let i = (0..bstr.k as usize).find(|&i| bord[i] as usize == j).unwrap();
        terms.push((format!("(Sum.inr (some {}))", bpaths[i]), blk[ka + 1 + j]));
    }
    // quotient step table per class per atom
    let qstep = |c: usize, a: usize| -> Option<usize> {
        if q.st[c][a] == 0 { None } else { Some(q.st[c][a] as usize - 1) }
    };
    let mut out = String::new();
    let mut w = |t: &str| { out.push_str(t); out.push('\n'); };
    w("import GkatCertSupportBoolProofs");
    w("import GkatRingSupportProofs");
    w("import GkatRingPlanProofs");
    w("import GkatDeadExitElimProofs");
    w("");
    w("/-! # GkatMixPilot: the mixed-halt frontier candidate, certified (emitted from Rust;");
    w("    see emit_mix_pilot in span-search).  Subset parking over Tst = Bool: the interior");
    w("    halt guard is a proper subset of the header's exit guard.  First certificate at");
    w("    two primitive tests. -/");
    w("");
    w("namespace GkatMixPilot");
    w("");
    w("open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatDeadExitElim");
    w("open GkatCertSupportBool GkatGuardedAlgebra GkatRingSupport GkatResidue");
    w("");
    w("abbrev Tst := Bool");
    w("abbrev Act := Unit");
    w("def bT1 : BExp Tst := .prim true");
    w("def bT2 : BExp Tst := .prim false");
    w("def pA : Exp Act Tst := .act ()");
    w(&format!("def eP : Exp Act Tst := {ae}"));
    w(&format!("def fP : Exp Act Tst := {be}"));
    w("");
    w("abbrev eAut := (certifiedThompson Act Tst eP).aut.toGAut");
    w("abbrev fAut := (certifiedThompson Act Tst fP).aut.toGAut");
    w("abbrev SUM := sumGAut eAut fAut");
    w("");
    w("/-! ## The ring plan (reflection: data + a finite check; ringPlan_solves does");
    w("    the mathematics) -/");
    w("");
    w("open GkatRingPlan");
    w("");
    w("def PLAN : RingPlan Act Tst where");
    w(&format!("  hSelfG := {g_self}"));
    w("  hSelfA := ()");
    w(&format!("  hStepG := {g_step}"));
    w("  hStepA := ()");
    w(&format!("  exitG := {g_ch}"));
    w(&format!("  entries := [{{ selfG := .or {g_r1} {g_r2}, selfA := (), stepG := {g_x}, stepA := (), hltG := {g_cs} }}]"));
    w("");
    w("theorem wf : WellFormedRing PLAN where");
    w("  nonempty := by simp [PLAN]");
    w("  hdr_disj := by");
    w("    intro X W x");
    w(&format!("    show (bval W {g_step} x && bval W {g_self} x) = false"));
    w("    cases hb1 : W true x <;> cases hb2 : W false x <;> simp [bval, bT1, bT2, hb1, hb2]");
    w("  interior_dead := by");
    w("    intro e he");
    w("    simp [PLAN] at he");
    w("  last_off := by");
    w("    intro e he X W x h");
    w("    simp [PLAN] at he");
    w("    subst he");
    w("    revert h");
    w(&format!("    show bval W {g_cs} x = true → bval W (.not (.or {g_step} {g_self})) x = true"));
    w("    cases hb1 : W true x <;> cases hb2 : W false x <;> simp [bval, bT1, bT2, hb1, hb2]");
    w("  last_sub := by");
    w("    intro e he X W x");
    w("    simp [PLAN] at he");
    w("    subst he");
    w(&format!("    show (bval W {g_cs} x && bval W {g_ch} x) = bval W {g_cs} x"));
    w("    cases hb1 : W true x <;> cases hb2 : W false x <;> simp [bval, bT1, bT2, hb1, hb2]");
    w("");
    w("/-! ## Quotient, map, bisimulation -/");
    w("");
    w("def QAut : GAut Nat Act Tst := planAut PLAN");
    w("");
    w("def qmap : Sum (Option (certifiedThompson Act Tst eP).State)");
    w("             (Option (certifiedThompson Act Tst fP).State) → Nat");
    for (t, c) in terms.iter() {
        let pat = if t.starts_with("(Sum.inl none)") { ".inl none".to_string() }
            else if t.starts_with("(Sum.inr none)") { ".inr none".to_string() }
            else if t.starts_with("(Sum.inl") {
                format!(".inl (some {})", &t[len_inl(t)..t.len() - 2])
            } else {
                format!(".inr (some {})", &t[len_inl(t)..t.len() - 2])
            };
        w(&format!("  | {pat} => {c}"));
    }
    w("  | _ => 0");
    w("");
    w("variable {X : Type} (W : Tst → X → Bool) (x : X)");
    w("");
    for c in 0..2usize {
        for b1 in [false, true] {
            for b2 in [false, true] {
                let a = (b1 as usize) | ((b2 as usize) << 1);
                let res = match qstep(c, a) {
                    None => "none".to_string(),
                    Some(t) => format!("some ((), {t})"),
                };
                w(&format!("theorem qstep_{c}_{}{} (h1 : W true x = {b1}) (h2 : W false x = {b2}) :",
                    b1 as u8, b2 as u8));
                w(&format!("    autStep W QAut {c} x = {res} := by"));
                w("  rw [autStep_bool, h1, h2]; rfl");
            }
        }
    }
    w("");
    w("theorem qmap_bisim : GAutBisim W SUM QAut (fun s q => qmap s = q) := by");
    w("  rintro s1 s2 rfl");
    w("  match s1 with");
    for (idx, (t, c)) in terms.iter().enumerate() {
        let inner = &t[1..t.len() - 1];
        w(&format!("  | {inner} =>"));
        w("      first | simp only [qmap] | skip");
        w("      refine ⟨fun a => ?_, fun a q s' hst => ?_, fun a q s2' hst => ?_⟩");
        w(&format!("      · show bval W (SUM.hlt {t}) a = bval W (QAut.hlt {c}) a"));
        w("        rw [bval_hlt_bool SUM, bval_hlt_bool QAut]");
        w("        cases hb1 : W true a <;> cases hb2 : W false a <;> rfl");
        for dir in 0..2 {
            w("      · rw [autStep_bool] at hst");
            w("        cases hb1 : W true a with");
            for b1 in [false, true] {
                w(&format!("        | {b1} =>"));
                w("          rw [hb1] at hst");
                w("          cases hb2 : W false a with");
                for b2 in [false, true] {
                    let a = (b1 as usize) | ((b2 as usize) << 1);
                    let stgt = if su.st[idx][a] == 0 { None } else { Some(su.st[idx][a] as usize - 1) };
                    let qtgt = qstep(*c, a);
                    let cv = format!("(fun b (_ : Unit) => cond b {b1} {b2})");
                    w(&format!("          | {b2} =>"));
                    w("              rw [hb2] at hst");
                    if dir == 0 {
                        match stgt {
                            None => {
                                w(&format!("              have hred : autStep {cv} SUM {t} () = none := by rfl"));
                                w("              rw [hred] at hst");
                                w("              exact absurd hst (by simp)");
                            }
                            Some(tg) => {
                                let (tt, tc) = &terms[tg];
                                w(&format!("              have hred : autStep {cv} SUM {t} ()"));
                                w(&format!("                  = some ((), {tt}) := by rfl"));
                                w("              rw [hred] at hst");
                                w("              have hs := congrArg Prod.snd (Option.some.inj hst)");
                                w("              subst hs");
                                w(&format!("              exact ⟨{tc}, qstep_{c}_{}{} W a hb1 hb2, rfl⟩",
                                    b1 as u8, b2 as u8));
                            }
                        }
                    } else {
                        match qtgt {
                            None => {
                                w(&format!("              have hred : autStep {cv} QAut {c} () = none := by rfl"));
                                w("              rw [hred] at hst");
                                w("              exact absurd hst (by simp)");
                            }
                            Some(qt) => {
                                let tg = stgt.expect("cert mismatch");
                                let (tt, tc) = &terms[tg];
                                assert_eq!(*tc, qt, "class mismatch");
                                w(&format!("              have hred : autStep {cv} QAut {c} ()"));
                                w(&format!("                  = some ((), {qt}) := by rfl"));
                                w("              rw [hred] at hst");
                                w("              have hs := congrArg Prod.snd (Option.some.inj hst)");
                                w("              subst hs");
                                w(&format!("              refine ⟨{tt}, ?_, rfl⟩"));
                                w("              rw [autStep_bool, hb1, hb2]");
                                w("              rfl");
                            }
                        }
                    }
                }
            }
        }
    }
    w("");
    w("def qquot : UniformBehavioralGAutQuotient SUM QAut where");
    w("  mapState := qmap");
    w("  maps_states := by");
    w("    intro s _");
    w("    match s with");
    for (t, c) in terms.iter() {
        let inner = &t[1..t.len() - 1];
        let mut chain = "(List.Mem.head _)".to_string();
        for _ in 0..*c { chain = format!("(List.Mem.tail _ {chain})"); }
        w(&format!("    | {inner} => exact {chain}"));
    }
    w("  onto_states := by");
    w("    intro q hq");
    w("    match q, hq with");
    for c in 0..2usize {
        let (wi, (t, _)) = terms.iter().enumerate().find(|(_, (_, tc))| *tc == c).unwrap();
        let mem = if wi == 0 {
            "(List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.head _))))".to_string()
        } else if wi < ka {
            let inner = &t["(Sum.inl (some ".len()..t.len() - 2];
            format!("(List.mem_append.mpr (Or.inl (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete eP {inner}))))))")
        } else if wi == ka {
            "(List.mem_append.mpr (Or.inr (List.mem_map_of_mem (List.Mem.head _))))".to_string()
        } else {
            let inner = &t["(Sum.inr (some ".len()..t.len() - 2];
            format!("(List.mem_append.mpr (Or.inr (List.mem_map_of_mem (List.Mem.tail _ (List.mem_map_of_mem (GkatTotalization.thompson_states_complete fP {inner}))))))")
        };
        w(&format!("    | {c}, _ => exact ⟨{t}, {mem}, rfl⟩"));
    }
    w("  bisim_graph := fun _ W => qmap_bisim W");
    w("");
    w("theorem qsol_solves : SolvesBA QAut (planSol PLAN) :=");
    w("  ringPlan_solves PLAN wf");
    w("");
    w("theorem cert : EquivBA eP fP :=");
    w("  certifiedThompson_uniform_solved_quotient qquot (planSol PLAN) qsol_solves rfl");
    w("");
    w("#print axioms cert");
    w("");
    w("end GkatMixPilot");
    std::fs::write(path, out).is_ok()
}

fn len_inl(_t: &str) -> usize { "(Sum.inl (some ".len() }


/// PAD_SCC_CENSUS: the S2 stratum census.  For forge-sampled language-equivalent pairs,
/// build the canonical quotient of the TRIMMED sum (liveness-trim, then language
/// minimization — on a deterministic trimmed automaton bisimilarity IS language equality,
/// mirroring the Lean `canonicalQuotient (trimAut (SUMof e f))`), decompose into SCCs, and
/// classify every state against the PROVED strata: fold (acyclic position) / salomaaE
/// (singleton SCC, any number of self-arms) / OPEN (multi-state SCC).  Multi-state SCCs
/// get a shape histogram feeding the ring-stratum design.
/// Env: PAD_CENSUS_N (pairs, default 20000), PAD_CENSUS_DEPTH (default 6),
/// PAD_CENSUS_KMIN/KMAX (default 3/10).
/// **CHECK ONE CANDIDATE.**  Iteration 197 turned up the first SCC neither the
/// lattice nor the calculus handles:
///
///     q0: hl={a3} st=[q1,q1,-,-]        q1: hl={a0} st=[-,-,q0,-]
///
/// Two exits, and neither absorbs under either rotation.  The hand derivation
/// says a THIRD move works — PRE-GUARD the loop and ASSERT at the end of its
/// body, so that one trailing test can serve both exits:
///
///     X1 = test{a0,a2} ; wh {a2} (p ; ite a3 1 (test{a0,a1} ; p ; test{a0,a2}))
///          ; test{a0,a3}
///     X0 = ite {a0,a1} (p ; X1) (test{a3})
///
/// The pre-guard kills the initial entry at `a1`/`a3` where `q1` rejects; the
/// body's trailing assertion kills the RE-entries at `a1`/`a3`; and the `a3`
/// escape from `q0` returns to the head unasserted, where the guard fails and
/// the trailing test accepts it.  Checked here rather than argued.
fn check_candidate<const NA: usize>() {
    if NA != 4 { println!("check_candidate: needs NA=4"); return; }
    let mut q = Aut::<NA>::blank();
    q.k = 2;
    q.hl[0] = 1 << 3;                 // q0 halts on a3
    for (i, &t) in [2u8, 2, 0, 0].iter().enumerate() { q.st[0][i] = t; }  // a0,a1 -> q1
    q.hl[1] = 1 << 0;                 // q1 halts on a0
    for (i, &t) in [0u8, 0, 1, 0].iter().enumerate() { q.st[1][i] = t; }  // a2 -> q0
    let m = |bits: &[usize]| -> u8 { bits.iter().fold(0u8, |acc, &b| acc | 1 << b) };
    let p = Ex::Act;
    let body = Ex::Seq(Box::new(p.clone()), Box::new(Ex::Ite(m(&[3]),
        Box::new(Ex::Test(m(&[0, 1, 2, 3]))),
        Box::new(Ex::Seq(Box::new(Ex::Test(m(&[0, 1]))),
            Box::new(Ex::Seq(Box::new(p.clone()),
                Box::new(Ex::Test(m(&[0, 2]))))))))));
    let x1 = Ex::Seq(Box::new(Ex::Test(m(&[0, 2]))),
        Box::new(Ex::Seq(Box::new(Ex::Wh(m(&[2]), Box::new(body))),
            Box::new(Ex::Test(m(&[0, 3]))))));
    let x0 = Ex::Ite(m(&[0, 1]),
        Box::new(Ex::Seq(Box::new(p), Box::new(x1.clone()))),
        Box::new(Ex::Test(m(&[3]))));
    for n in [4usize, 6, 8] {
        println!("  candidate at depth {n}: X0 {} ; X1 {}",
            if ex_matches(&x0, &q, 0, n) { "MATCHES" } else { "differs" },
            if ex_matches(&x1, &q, 1, n) { "MATCHES" } else { "differs" });
    }
}

/// **THE HALT-IN-BODY RESISTER** (iteration 201).  A 480k-pair NA=3 sweep
/// turned up a three-state SCC the four-rule calculus cannot solve:
///
///     q0: hl={a0,a1} st=[-,-,q1]   q1: hl={} st=[q1,q2,q1]   q2: hl={a1} st=[q0,-,q1]
///
/// Two exit states (q0 and q2), so Kosaraju says no aux-variable-free
/// structuring of the GRAPH exists — but the automaton is a bisimulation
/// quotient of a Thompson sum, so a solution must exist all the same.  By
/// hand:
///
///     Seg = wh {a0,a2} p ; p                 -- q1's self-loop, ending at q2
///     X1  = Seg ; X2
///     X2  = wh {a2} Seg ; ite a1 1 (p ; X0)
///     X0  = ite a2 (p ; Seg ; wh {a2} Seg ; ite a1 1 (p ; X0)) 1
///
/// The last line recurses under a test (`a0`) that DIFFERS from its entry test
/// (`a2`), and the recursion site sits inside an `ite` whose other branch is a
/// HALT, not a dead end.  That is the new shape.  It loopifies because the
/// halt branch is subsumed by the loop guard already being false there:
///
///     X0 = wh {a2} (p ; Seg ; wh {a2} Seg ; ite a0 p 1)
///
/// After the inner `wh {a2}` exits, `¬a2` holds, so `ite a0 p 1` does `p` on
/// `a0` (re-entering the head) and NOTHING on `a1` — where the outer guard
/// `a2` is then false, so the loop exits and accepts, which is exactly what
/// `q2`'s `a1` halt wanted.  One trailing conditional action serves as both
/// the back-edge and the second exit.  Checked here rather than argued.
fn check_r201<const NA: usize>() {
    if NA != 3 { println!("check_r201: needs NA=3"); return; }
    let all: u8 = 0b111;
    let mut q = Aut::<NA>::blank();
    q.k = 3;
    q.hl[0] = 0b011;                                            // q0 halts on a0,a1
    for (i, &t) in [0u8, 0, 2].iter().enumerate() { q.st[0][i] = t; }
    q.hl[1] = 0b000;                                            // q1 never halts
    for (i, &t) in [2u8, 3, 2].iter().enumerate() { q.st[1][i] = t; }
    q.hl[2] = 0b010;                                            // q2 halts on a1
    for (i, &t) in [1u8, 0, 2].iter().enumerate() { q.st[2][i] = t; }
    let p = || Ex::Act;
    let seq = |x: Ex, y: Ex| Ex::Seq(Box::new(x), Box::new(y));
    // Seg = wh {a0,a2} p ; p
    let seg = seq(Ex::Wh(0b101, Box::new(p())), p());
    // X0 = wh {a2} (p ; Seg ; wh {a2} Seg ; ite a0 p 1)
    let body = seq(p(), seq(seg.clone(), seq(
        Ex::Wh(0b100, Box::new(seg.clone())),
        Ex::Ite(0b001, Box::new(p()), Box::new(Ex::Test(all))))));
    let x0 = Ex::Wh(0b100, Box::new(body));
    // X2 = wh {a2} Seg ; ite a1 1 (p ; X0)      X1 = Seg ; X2
    let x2 = seq(Ex::Wh(0b100, Box::new(seg.clone())),
        Ex::Ite(0b010, Box::new(Ex::Test(all)), Box::new(seq(p(), x0.clone()))));
    let x1 = seq(seg, x2.clone());
    for n in [4usize, 6, 8, 10] {
        println!("  r201 at depth {n}: X0 {} ; X1 {} ; X2 {}",
            if ex_matches(&x0, &q, 0, n) { "MATCHES" } else { "differs" },
            if ex_matches(&x1, &q, 1, n) { "MATCHES" } else { "differs" },
            if ex_matches(&x2, &q, 2, n) { "MATCHES" } else { "differs" });
    }
    println!("  r201 calculus (depth 5): {}", calculus_solves(&q, &[0, 1, 2], 5));
    println!("  r201 calculus (depth 9): {}", calculus_solves(&q, &[0, 1, 2], 9));
}

/// **NON-VACUITY FOR `nested`** (iteration 205).  The census measured the
/// nesting coequation holding on 599 761 of 599 761 canonical quotients — and
/// on the raw Thompson sum and full collapse at the same 100% rate.  That is
/// what a covariety predicts (`Cov(W)` is closed under homomorphic images, so
/// if the sum satisfies it every quotient does), but it is also what a broken
/// predicate that always returns `true` would look like.  Distinguish them by
/// asking `nested` about automata NOT built from expressions at all.
/// **THE LAST RESISTER, SOLVED** (iteration 206).  Pair #156950's collapse is
/// the only SCC in 600 000 pairs the five-rule calculus cannot solve.  It is a
/// 3-cycle with a halt-exit AND a continuation-exit:
///
///     d0: st=[c1,d2]   c1: hl=11 st=[-,-]   d2: st=[d3,d3]
///     d3: st=[d0,c5]   c5: st=[c1,c5]
///
/// so `c1` is `1` and `c5 = wh{a1}(p) ; p`.  Rule 5 cannot reach it because the
/// mid-body exit is `p ; c5`, an arbitrary continuation rather than a halt.
///
/// But `c5` ENDS in `p`, and the loop's own trailing expression is `p`.  Take
/// the mid-body exit to be `p ; wh{a1}(p)` — which exits at `¬a1`, so the outer
/// guard `a1` is then FALSE, the loop exits, and the shared trailing `p` fires,
/// reconstituting `c5` exactly:
///
///     X = wh a1 ( p ; p ; ite a0 p (p ; wh a1 p) ) ; p
///
/// The mid-body exit need not be a halt.  It needs to LAND OUTSIDE THE GUARD
/// and SHARE THE LOOP'S TRAILING SUFFIX.  That is rule 6.
fn check_r206<const NA: usize>() {
    if NA != 2 { println!("check_r206: needs NA=2"); return; }
    let mut q = Aut::<NA>::blank();
    q.k = 5;
    q.hl[0] = 0b00; for (i, &t) in [2u8, 3].iter().enumerate() { q.st[0][i] = t; }
    q.hl[1] = 0b11; for (i, &t) in [0u8, 0].iter().enumerate() { q.st[1][i] = t; }
    q.hl[2] = 0b00; for (i, &t) in [4u8, 4].iter().enumerate() { q.st[2][i] = t; }
    q.hl[3] = 0b00; for (i, &t) in [1u8, 5].iter().enumerate() { q.st[3][i] = t; }
    q.hl[4] = 0b00; for (i, &t) in [2u8, 5].iter().enumerate() { q.st[4][i] = t; }
    let p = || Ex::Act;
    let seq = |x: Ex, y: Ex| Ex::Seq(Box::new(x), Box::new(y));
    // X = wh a1 ( p ; p ; ite a0 p (p ; wh a1 p) ) ; p
    let body = seq(p(), seq(p(), Ex::Ite(0b01, Box::new(p()),
        Box::new(seq(p(), Ex::Wh(0b10, Box::new(p())))))));
    let x0 = seq(Ex::Wh(0b10, Box::new(body)), p());
    // c5 = wh a1 p ; p, for the external state, as a cross-check
    let x4 = seq(Ex::Wh(0b10, Box::new(p())), p());
    for n in [4usize, 6, 8, 10, 12] {
        println!("  r206 at depth {n}: X(d0) {} ; X(c5) {}",
            if ex_matches(&x0, &q, 0, n) { "MATCHES" } else { "differs" },
            if ex_matches(&x4, &q, 4, n) { "MATCHES" } else { "differs" });
    }
    println!("  r206 calculus, SCC only [0,2,3] (depth 5): {}",
        calculus_solves(&q, &[0, 2, 3], 5));
    // Rule 6 needs to SEE the shared suffix, but states outside the SCC enter
    // the search as opaque `Ex::Sub` oracles: the tail is `p ; Sub(c1)` and the
    // mid-body exit is `p ; Sub(c5)`, which share no syntactic suffix even
    // though `Sub(c1) = 1` makes the real shared suffix `p`.  Handing the
    // solver the WHOLE automaton turns those oracles into unknowns it must
    // solve, so the suffix becomes visible.  If this succeeds where the
    // SCC-only call fails, the blocker is oracle opacity, not the rule.
    println!("  r206 calculus, whole automaton [0..4] (depth 5): {}",
        calculus_solves(&q, &[0, 1, 2, 3, 4], 5));
    println!("  r206 calculus, whole automaton [0..4] (depth 9): {}",
        calculus_solves(&q, &[0, 1, 2, 3, 4], 9));
}

/// **EXHAUSTIVE ENUMERATION OF SMALL AUTOMATA** (iteration 209).
///
/// The random sampler is SATURATED: at NA=4 depth 7, 4M and 16M pairs give the
/// identical 1 761 720 quotient states and the identical 1170 open SCCs, and
/// NA=2 gains 1.16x open SCCs for 16x the pairs.  A saturated sampler cannot
/// falsify anything, so sampling expression PAIRS is the wrong instrument now.
///
/// Enumerate the automata directly instead.  Each state assigns, per atom, one
/// of: halt, no transition, or a target — `(k+2)^(k·NA)` automata, exhaustive
/// for the small cases.  By the Schmid-Kappé-Kozen-Silva characterization
/// `nested` holds exactly of automata whose behaviour is some GKAT expression's,
/// so:
///
///     nested(a)  AND  the calculus cannot solve `a`   =   a rule-7 instance
///
/// This is a strictly stronger test than any amount of sampling: it cannot miss
/// a small counterexample, because it looks at every one.
fn exhaustive<const NA: usize>() {
    let kmax: usize = std::env::var("PAD_EXH_K").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(4);
    // Built ONCE: the expression enumeration is independent of the target, so
    // every automaton below decides solvability by a hash lookup instead of
    // its own exponential search.
    let t0 = std::time::Instant::now();
    let table = synth_table::<NA>(synth_size(), seq_len(NA));
    println!("  synth table: {} distinct behaviours at size <= {}, built in {:.1}s",
        table.len(), synth_size(), t0.elapsed().as_secs_f64());
    for k in 2..=kmax {
        let choices = k + 2;                       // halt | dead | k targets
        let cells = k * NA;
        let total: u64 = (choices as u64).pow(cells as u32);
        let hits: Vec<u64> = (0..total).into_par_iter().filter(|&code| {
            let mut a = Aut::<NA>::blank();
            a.k = k as u8;
            let mut c = code;
            for s in 0..k {
                for y in 0..NA {
                    let d = (c % choices as u64) as usize;
                    c /= choices as u64;
                    if d == 0 { a.hl[s] |= 1 << y; }
                    else if d == 1 { /* no transition, no halt */ }
                    else { a.st[s][y] = (d - 1) as u8; }
                }
            }
            // every state must be reachable from 0, else it is a smaller
            // automaton already covered at a lower k
            let mut seen = vec![false; k];
            let mut stack = vec![0usize];
            seen[0] = true;
            while let Some(x) = stack.pop() {
                for y in 0..NA {
                    let t = a.st[x][y];
                    if t == 0 { continue; }
                    let t = (t - 1) as usize;
                    if !seen[t] { seen[t] = true; stack.push(t); }
                }
            }
            if !seen.iter().all(|&b| b) { return false; }
            // CHEAPEST FIRST — and 216 INVERTED which one is cheapest.  While
            // solvability came from an oracle costing ~9ms, the calculus ran
            // first; now `synth_lookup` is a hash lookup and `calculus_solves`
            // is the exponential one, so the order flips.
            //
            // A counterexample needs BOTH "solvable" AND "calculus fails", so
            // either test may gate the other.  Gate on the lookup: an automaton
            // whose behaviour is not in the table is not known solvable and can
            // never be a counterexample, whatever the calculus does with it.
            // MINIMISE FIRST.  The target theorem is about behavioural
            // QUOTIENTS of Thompson sums, which are bisimulation-minimal by
            // construction; a raw enumerated automaton is not.  That
            // difference is not cosmetic: at k=4 the un-minimised run reported
            // 132 "counterexamples", and the first one hand-checked
            // (code=159545) has q1 and q3 literally identical, so q1 ~ q3 and
            // then q0 ~ q2, collapsing to two states solved by
            // `wh a1 p ; p ; wh a0 p`.  The calculus failed only because it
            // sees `Sub(q1)` and `Sub(q3)` as DISTINCT OPAQUE ORACLES — an
            // artifact of non-minimality, not a gap in the rules.
            let a = match bisim_blocks(&a) { (blk, nb) =>
                match quotient_by(&a, &blk, nb) { Some(q) => q, None => return false } };
            let sccs = sccs_of(&a);
            if !sccs.iter().any(|c| c.len() >= 2) { return false; }
            // Solvability by CONSTRUCTION, not by an oracle.  Both oracles
            // tried before failed here: `nested` admits unsolvable automata
            // (205's reading was too strong) and `symbolic_eliminable_raw` is
            // wrong in BOTH directions (213, 214), producing the 80/102
            // phantoms at k<=3 and the 720 phantoms at k=4.  A table hit is a
            // WITNESS, verified by `ex_matches` before it is believed.
            if synth_lookup(&table, &a, 0, seq_len(NA)).is_none() { return false; }
            let sing = singleton_states(&a);
            let solved = sccs.iter().all(|c| c.len() < 2
                || calculus_solves(&a, c, 6)
                || calculus_solves(&a, &scc_with_context(&a, c, &sing), 6));
            !solved
        }).collect();
        println!("  exhaustive NA={NA} k={k}: {total} automata; \
            SOLVABLE (witness from brute-force search) but UNSOLVED by the calculus: {}", hits.len());
        for &code in hits.iter().take(4) {
            let mut a = Aut::<NA>::blank();
            a.k = k as u8;
            let mut c = code;
            for s in 0..k {
                for y in 0..NA {
                    let d = (c % choices as u64) as usize;
                    c /= choices as u64;
                    if d == 0 { a.hl[s] |= 1 << y; } else if d != 1 {
                        a.st[s][y] = (d - 1) as u8;
                    }
                }
            }
            // TWO EXPLANATIONS, and they must be told apart before this is
            // reported as a finding: either these are genuine rule-7
            // instances, or `nested` is not a faithful solvability oracle for
            // automata that did not come from expressions.  The independent
            // elimination oracle decides.
            println!("    UNSOLVED code={code} (eliminable={}):",
                symbolic_eliminable_raw(&a));
            for s in 0..k {
                let row: Vec<String> = (0..NA).map(|i| {
                    let t = a.st[s][i];
                    if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                }).collect();
                println!("      q{s}: hl={:04b} st=[{}]", a.hl[s], row.join(","));
            }
        }
    }
}

/// Expression-size bound for the brute-force search.  A NEGATIVE from `synth`
/// means "no expression of at most this size", never "unsolvable" — so this
/// constant is the strength of every negative result the enumeration reports,
/// and it is stated rather than buried.
fn synth_size() -> usize {
    std::env::var("PAD_SYNTH_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(10)
}

/// Guarded-string length bound for the behaviour signature, DERIVED from `NA`
/// so the signature fits a `u128`.
///
/// This was a hard-coded 5, which is a silent-vacuity bug: at NA=3 that is
/// 3+9+27+81+243 = 363 strings, `synth` bails on `seqs.len() > 128` and returns
/// `None` every single time — so the enumeration's filter never fires and its
/// "0 counterexamples" means nothing.  Derive the bound instead, and let
/// `synth` announce loudly if it is ever asked for something it cannot
/// represent, rather than answering `None`.
fn seq_len(na: usize) -> usize {
    let mut l = 1;
    let mut total = 0usize;
    loop {
        let next = total + na.pow(l as u32);
        if next > 128 { return l - 1; }
        total = next;
        l += 1;
    }
}

/// All guarded strings with at most `l` atoms, as atom-index sequences.
fn all_seqs<const NA: usize>(l: usize) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<Vec<usize>> = (0..NA).map(|x| vec![x]).collect();
    for _ in 1..l {
        out.extend(cur.iter().cloned());
        let mut nxt = Vec::new();
        for s in cur.iter() {
            for x in 0..NA { let mut t = s.clone(); t.push(x); nxt.push(t); }
        }
        cur = nxt;
    }
    out.extend(cur);
    out
}

/// **THE ENUMERATION DOES NOT DEPEND ON THE TARGET** (iteration 216).
///
/// `synth` re-enumerates expressions from scratch for every automaton it is
/// asked about, which is why the exhaustive runs are compute-bound.  But an
/// expression containing no `Sub`/`Unk` has a behaviour determined by `NA`
/// alone — the target automaton is consulted only to compute the SIGNATURE TO
/// MATCH, never to evaluate a candidate.
///
/// So enumerate ONCE into a table from behaviour-signature to a representative
/// expression, and "is this automaton solvable by an expression of size <= N"
/// becomes a hash lookup.  Per-automaton cost drops from an exponential search
/// to O(1) plus one verification.
fn synth_table<const NA: usize>(maxsize: usize, l: usize) -> FxMap<u128, Ex> {
    let seqs = all_seqs::<NA>(l);
    assert!(seqs.len() <= 128,
        "synth_table: {} guarded strings exceeds the 128-bit signature", seqs.len());
    // Any automaton works as the evaluation context: candidates contain no
    // `Sub`/`Unk`, so `ex_accepts` never consults it.
    let dummy = Aut::<NA>::blank();
    let sig = |e: &Ex| -> u128 {
        let mut s: u128 = 0;
        for (i, w) in seqs.iter().enumerate() {
            if ex_accepts(e, &dummy, w) { s |= 1u128 << i; }
        }
        s
    };
    let all: u8 = if NA >= 8 { 0xFF } else { ((1u16 << NA) - 1) as u8 };
    let mut table: FxMap<u128, Ex> = FxMap::default();
    let mut levels: Vec<Vec<Ex>> = vec![Vec::new()];
    let mut lvl1: Vec<Ex> = Vec::new();
    for m in 0..=all {
        let e = Ex::Test(m);
        if table.insert(sig(&e), e.clone()).is_none() { lvl1.push(e); }
    }
    { let e = Ex::Act;
      if table.insert(sig(&e), e.clone()).is_none() { lvl1.push(e); } }
    levels.push(lvl1);
    for n in 2..=maxsize {
        let mut cur: Vec<Ex> = Vec::new();
        for a in levels[n - 1].iter() {
            for g in 1..=all {
                let e = Ex::Wh(g, Box::new(a.clone()));
                if table.insert(sig(&e), e.clone()).is_none() { cur.push(e); }
            }
        }
        for i in 1..n - 1 {
            let j = n - 1 - i;
            if j == 0 || i >= levels.len() || j >= levels.len() { continue; }
            for a in levels[i].iter() {
                for b in levels[j].iter() {
                    let mut cands =
                        vec![Ex::Seq(Box::new(a.clone()), Box::new(b.clone()))];
                    for g in 1..all {
                        cands.push(Ex::Ite(g, Box::new(a.clone()), Box::new(b.clone())));
                    }
                    for e in cands {
                        if table.insert(sig(&e), e.clone()).is_none() { cur.push(e); }
                    }
                }
            }
        }
        levels.push(cur);
    }
    table
}

/// Solvability by table lookup: signature match, then a real language check at
/// greater depth so a signature collision cannot produce a false witness.
fn synth_lookup<const NA: usize>(table: &FxMap<u128, Ex>, q: &Aut<NA>,
    start: usize, l: usize) -> Option<Ex>
{
    let seqs = all_seqs::<NA>(l);
    let mut target: u128 = 0;
    for (i, w) in seqs.iter().enumerate() {
        if accepts_at(q, start, w) { target |= 1u128 << i; }
    }
    let e = table.get(&target)?;
    if ex_matches(e, q, start, l + 3) { Some(e.clone()) } else { None }
}

/// **BRUTE-FORCE EXPRESSION SEARCH** (iteration 214) — the instrument 213 said
/// this development should have been using all along.
///
/// Every solvability verdict since 204 came from `symbolic_eliminable_raw`,
/// which 213 proved INCOMPLETE by exhibiting an automaton it rejects and an
/// expression that solves it.  An oracle wrong in one direction may be wrong in
/// the other, so its verdicts cannot decide anything — including the 720 k=4
/// automata it called solvable-but-unsolved.
///
/// This decides solvability by CONSTRUCTION instead.  Enumerate expressions
/// bottom-up by size, keeping one representative per BEHAVIOUR — the standard
/// observational-equivalence dedup from enumerative program synthesis, which
/// keys on what a term does rather than how it is written and cuts the retained
/// set by about an order of magnitude.  A hit is a witness, so it PROVES
/// solvable; exhausting the size bound proves unsolvable UP TO THAT SIZE, which
/// is a bounded but honest negative.  No oracle in either direction.
fn synth<const NA: usize>(q: &Aut<NA>, start: usize, maxsize: usize, l: usize)
    -> Option<Ex>
{
    let seqs = all_seqs::<NA>(l);
    assert!(seqs.len() <= 128,
        "synth: {} guarded strings exceeds the 128-bit signature at NA={NA}, l={l} — \
         this silently returned None before, making every negative VACUOUS",
        seqs.len());
    let sig = |e: &Ex| -> u128 {
        let mut s: u128 = 0;
        for (i, w) in seqs.iter().enumerate() {
            if ex_accepts(e, q, w) { s |= 1u128 << i; }
        }
        s
    };
    let mut target: u128 = 0;
    for (i, w) in seqs.iter().enumerate() {
        if accepts_at(q, start, w) { target |= 1u128 << i; }
    }
    let all: u8 = if NA >= 8 { 0xFF } else { ((1u16 << NA) - 1) as u8 };
    let mut seen: FxMap<u128, ()> = FxMap::default();
    let mut levels: Vec<Vec<Ex>> = vec![Vec::new()];       // index by size
    let mut check = |e: &Ex, seen: &mut FxMap<u128, ()>| -> Option<Ex> {
        let s = sig(e);
        if s == target && ex_matches(e, q, start, l + 3) { return Some(e.clone()); }
        if seen.contains_key(&s) { None } else { seen.insert(s, ()); None }
    };
    let mut lvl1: Vec<Ex> = Vec::new();
    for m in 0..=all { let e = Ex::Test(m);
        if let Some(h) = check(&e, &mut seen) { return Some(h); }
        lvl1.push(e); }
    { let e = Ex::Act;
      if let Some(h) = check(&e, &mut seen) { return Some(h); }
      lvl1.push(e); }
    levels.push(lvl1);
    for n in 2..=maxsize {
        let mut cur: Vec<Ex> = Vec::new();
        // Wh(g, a) with |a| = n-1
        for a in levels[n - 1].iter() {
            for g in 0..=all {
                if g == 0 { continue; }              // `wh 0 a` is just `1`
                let e = Ex::Wh(g, Box::new(a.clone()));
                let s = sig(&e);
                if s == target && ex_matches(&e, q, start, l + 3) { return Some(e); }
                if seen.insert(s, ()).is_none() { cur.push(e); }
            }
        }
        // Seq(a,b) and Ite(g,a,b) with |a| + |b| = n-1
        for i in 1..n - 1 {
            let j = n - 1 - i;
            if j == 0 || i >= levels.len() || j >= levels.len() { continue; }
            for a in levels[i].iter() {
                for b in levels[j].iter() {
                    let mut cands = vec![Ex::Seq(Box::new(a.clone()), Box::new(b.clone()))];
                    for g in 1..all {
                        cands.push(Ex::Ite(g, Box::new(a.clone()), Box::new(b.clone())));
                    }
                    for e in cands {
                        let s = sig(&e);
                        if s == target && ex_matches(&e, q, start, l + 3) {
                            return Some(e);
                        }
                        if seen.insert(s, ()).is_none() { cur.push(e); }
                    }
                }
            }
        }
        levels.push(cur);
    }
    None
}

/// **IS THE ELIMINATION ORACLE COMPLETE?** (iteration 213.)
///
/// 212 called `H_v ⊆ H_u ∨ H_u ⊆ H_v` a NECESSARY condition with false
/// POSITIVES — automata passing it that the oracle calls unsolvable.  But
/// `code=131` at NA=3 has no dead atoms and total symmetry:
///
///     q0: a0 -> q1, {a1,a2} halt        q1: a0 -> q0, {a1,a2} halt
///
/// and by hand `X0 = wh a0 (p ; ite a0 p 1) ; test{a1,a2}` solves it: on the
/// `¬a0` branch control sits at `q1` with the same atom, the loop guard is
/// false, the loop exits, and the trailing test accepts exactly `{a1,a2}`.
/// That is rule 5's shape and it should be solvable.
///
/// If it is, the "false positives" are FALSE NEGATIVES OF THE ORACLE, the
/// oracle is incomplete, and every agreement percentage computed against it —
/// 211's and 212's alike — is measuring the oracle, not the mathematics.
/// Language-check rather than argue.
fn oracle_check<const NA: usize>() {
    if NA != 3 { println!("oracle_check: needs NA=3"); return; }
    let mut q = Aut::<NA>::blank();
    q.k = 2;
    q.hl[0] = 0b110; for (i, &t) in [2u8, 0, 0].iter().enumerate() { q.st[0][i] = t; }
    q.hl[1] = 0b110; for (i, &t) in [1u8, 0, 0].iter().enumerate() { q.st[1][i] = t; }
    let p = || Ex::Act;
    let seq = |x: Ex, y: Ex| Ex::Seq(Box::new(x), Box::new(y));
    // X0 = wh a0 (p ; ite a0 p 1) ; test{a1,a2}
    let body = seq(p(), Ex::Ite(0b001, Box::new(p()), Box::new(Ex::Test(0b111))));
    let x0 = seq(Ex::Wh(0b001, Box::new(body.clone())), Ex::Test(0b110));
    // X1 is the same expression by symmetry
    for n in [4usize, 6, 8, 10, 12] {
        println!("  oracle_check depth {n}: X0 {} ; X1 {}",
            if ex_matches(&x0, &q, 0, n) { "MATCHES" } else { "differs" },
            if ex_matches(&x0, &q, 1, n) { "MATCHES" } else { "differs" });
    }
    println!("  oracle says eliminable = {}", symbolic_eliminable_raw(&q));
    println!("  calculus solves it     = {}", calculus_solves(&q, &[0, 1], 6));
}

/// Put the brute-force search to the three cases that matter (iteration 214):
/// one the oracle wrongly rejected, one the literature says is unsolvable, and
/// one of the 720 the oracle called solvable-but-unsolved.
fn synth_check<const NA: usize>() {
    let mk = |k: u8, hl: &[u8], st: &[&[u8]]| -> Aut<NA> {
        let mut a = Aut::<NA>::blank();
        a.k = k;
        for s in 0..(k as usize) {
            a.hl[s] = hl[s];
            for y in 0..NA { a.st[s][y] = st[s][y]; }
        }
        a
    };
    if NA == 3 {
        // 213's witness: oracle says unsolvable, an expression exists.
        let a = mk(2, &[0b110, 0b110], &[&[2u8, 0, 0][..], &[1u8, 0, 0][..]]);
        println!("  synth code=131 (oracle said UNSOLVABLE): {:?}",
            synth(&a, 0, 8, 4).map(|e| format!("{e:?}")));
        // The literature's unsolvable family: an atom resumes at one state and
        // terminates at the other, reversed on the other branch.
        let b = mk(2, &[0b011, 0b110], &[&[0u8, 0, 2][..], &[1u8, 0, 0][..]]);
        println!("  synth code=176 (literature: UNSOLVABLE): {:?}",
            synth(&b, 0, 8, 4).map(|e| format!("{e:?}")));
    }
    if NA == 2 {
        // One of the k=4 720: oracle said eliminable, calculus failed.
        let c = mk(4, &[0, 0, 0, 0b11], &[&[2u8, 3][..], &[3u8, 1][..], &[4u8, 0][..], &[0u8, 0][..]]);
        for sz in [8usize, 10, 12] {
            println!("  synth code=14859 (oracle said SOLVABLE, calculus failed), size<={sz}: {:?}",
                synth(&c, 0, sz, 5).map(|e| format!("{e:?}")));
        }
    }
}

/// **A CANDIDATE CHARACTERIZATION OF SOLVABLE 2-STATE LOOPS** (iteration 211).
///
/// The GKAT literature describes the unsolvable family exactly: "there is no
/// condition that terminates the loop: on one branch, a certain atom resumes
/// the loop while another terminates execution, whereas on the other branch
/// this is reversed" — and warns that adding a `twostate` operator only climbs
/// an INFINITE HIERARCHY of such automata.  It also says a proper
/// characterization of SOLVABLE automata "would go a long way" towards
/// completeness.
///
/// For a strongly connected 2-state automaton `{u,v}` write `C_u` for the atoms
/// at `u` that continue (transition to `v`), `H_u` for those that halt.  A
/// while-loop with head `u` must take `C_u` as its guard; the body runs `p`,
/// arrives at `v`, and must RETURN on `C_v` and EXIT on `H_v`.  The exit can
/// only happen if the head's guard is already false there:
///
///     solvable-with-head-u   iff   H_v ∩ C_u = ∅
///
/// so the candidate characterization is `H_v ∩ C_u = ∅  OR  H_u ∩ C_v = ∅`,
/// the disjunction being the choice of which state heads the loop.  The
/// literature's unsolvable example is exactly the case where BOTH intersections
/// are non-empty.
///
/// Tested against `symbolic_eliminable_raw` over EVERY 2-state automaton.
fn characterize<const NA: usize>() {
    let choices = 2 + 2;
    let cells = 2 * NA;
    let total: u64 = (choices as u64).pow(cells as u32);
    let (mut agree, mut n, mut fp, mut fnn) = (0u64, 0u64, 0u64, 0u64);
    let msk: u8 = ((1u16 << NA) - 1) as u8;
    let mut fp_dead = 0u64;
    let mut fp_shown = 0usize;
    let fp_dump = std::env::var("PAD_FP_DUMP").is_ok();
    let mut fp_ex: Vec<u64> = Vec::new();
    let mut fn_ex: Vec<u64> = Vec::new();
    for code in 0..total {
        let mut a = Aut::<NA>::blank();
        a.k = 2;
        let mut c = code;
        for s in 0..2 {
            for y in 0..NA {
                let d = (c % choices as u64) as usize;
                c /= choices as u64;
                if d == 0 { a.hl[s] |= 1 << y; }
                else if d != 1 { a.st[s][y] = (d - 1) as u8; }
            }
        }
        // strongly connected: 0 -> 1 and 1 -> 0 must both occur
        let goes = |x: usize, t: usize| (0..NA).any(|y| a.st[x][y] == (t + 1) as u8);
        if !(goes(0, 1) && goes(1, 0)) { continue; }
        let cont = |x: usize, t: usize| -> u8 {
            (0..NA).fold(0u8, |m, y|
                if a.st[x][y] == (t + 1) as u8 { m | 1 << y } else { m })
        };
        let (c0, c1) = (cont(0, 1), cont(1, 0));
        let (h0, h1) = (a.hl[0], a.hl[1]);
        // 211's predicate: the mid-body halt must lie outside the head's guard.
        let _weak = (h1 & c0) == 0 || (h0 & c1) == 0;
        // REFINED (212).  Working rule 6's conclusion through the 2-state shape
        // shows more is needed.  `wh C_u (p ; ite C_v q (test H_v)) ; test H_u`
        // puts the TRAILING test after the loop, so a mid-body exit at an atom
        // of `H_v` must still pass `test H_u` — i.e. `H_v ⊆ H_u`.  That implies
        // `H_v ∩ C_u = ∅` (halts and transitions are disjoint at `u`), so it is
        // strictly stronger, and it should account for 211's false positives.
        let pred = (h1 & !h0) == 0 || (h0 & !h1) == 0;
        // TRUTH SOURCE, corrected at 213.  `symbolic_eliminable_raw` is
        // INCOMPLETE: `code=131` at NA=3 is solved by
        // `wh a0 (p ; ite a0 p 1) ; test{a1,a2}`, language-checked at five
        // depths, and the oracle still says false.  A calculus success carries
        // a language-verified witness, so it PROVES solvability; the oracle
        // only suggests it.  Take the union — either witness counts — which is
        // the best lower bound on solvability available here.
        let truth = calculus_solves(&a, &[0, 1], 6) || symbolic_eliminable_raw(&a);
        n += 1;
        if pred == truth { agree += 1; }
        else if pred && !truth {
            if fp_ex.len() < 3 { fp_ex.push(code); }
            fp += 1;
            // WHAT DO THE SURVIVORS SHARE?  Dead atoms — those with neither a
            // halt nor a transition — are the one feature neither the 211 nor
            // the 212 condition looks at, and a dead atom REJECTS where the
            // loop would have to continue or exit.  Tally the false positives
            // by whether either state has one.
            let d0 = !(c0 | h0) & msk;
            let d1 = !(c1 | h1) & msk;
            if d0 != 0 || d1 != 0 { fp_dead += 1; }
            if fp_dump && fp_shown < 8 {
                fp_shown += 1;
                println!("    FP code={code}: C0={c0:03b} H0={h0:03b} D0={d0:03b} \
                    | C1={c1:03b} H1={h1:03b} D1={d1:03b}");
            }
        }
        else { if fn_ex.len() < 3 { fn_ex.push(code); } fnn += 1; }
    }
    println!("  characterize NA={NA}: {n} strongly connected 2-state automata; \
        predicate agrees with the elimination oracle {agree} ({:.2}%)",
        100.0 * agree as f64 / n.max(1) as f64);
    println!("    predicate says SOLVABLE, oracle says not: {fp}  (examples {fp_ex:?})");
    println!("    predicate says UNSOLVABLE, oracle says solvable: {fnn}  (examples {fn_ex:?})");
    println!("    of the {fp} false positives, {fp_dead} have a DEAD atom (neither halt nor transition) at some state");
}

/// **IS THE `wh` RESIDUAL EVEN NON-EMPTY?** (iteration 219.)
///
/// 218 reduced the `wh` induction step to one residual case: states that are
/// bisimilar in the LOOP automaton but not in the BODY.  Working out when that
/// can happen: `loopInitialized` differs from the body ONLY at atoms where
/// `hlt_body(s)` holds and the guard `b` holds — there the body HALTS while the
/// loop takes the back edge.  So the residual needs an atom at which `b` holds
/// and exactly ONE of the two states halts in the body, with the back-edge
/// target loop-bisimilar to where the other state goes.
///
/// If no such pair ever exists, loop-bisimilarity EQUALS body-bisimilarity, the
/// residual hypothesis is vacuous, and the `wh` step follows from the induction
/// hypothesis alone — the case would be closed.  So measure it before proving
/// anything.  `a_wh` matches `loopInitialized` exactly (same state count,
/// `hl ∧ ¬g`, back edge to the body's initial transition), so the harness can
/// decide this directly.
fn wh_residual<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x1234_5678_9ABC_DEF0;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let all: u8 = if NA >= 8 { 0xFF } else { ((1u16 << NA) - 1) as u8 };
    let (mut tried, mut residual, mut coarser) = (0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..400_000 {
        let body = match genexp::<NA>(&mut rnd, 4, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if body.k < 2 { continue; }
        let g = (rnd() % (all as u64 + 1)) as u8;
        if g == 0 || g == all { continue; }
        let loop_ = a_wh(g, &body);
        tried += 1;
        let (bb, _) = bisim_blocks(&body);
        let (bl, _) = bisim_blocks(&loop_);
        let k = body.k as usize;
        let mut found = false;
        for u in 0..k {
            for v in (u + 1)..k {
                if bl[u] == bl[v] && bb[u] != bb[v] { found = true; }
            }
        }
        if found {
            residual += 1;
            if shown < 3 {
                shown += 1;
                println!("    RESIDUAL: guard={g:03b}, body k={}", body.k);
                for s in 0..k {
                    let row: Vec<String> = (0..NA).map(|i| {
                        let t = body.st[s][i];
                        if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                    }).collect();
                    println!("      body q{s}: hl={:03b} st=[{}]  bodyblk={} loopblk={}",
                        body.hl[s], row.join(","), bb[s], bl[s]);
                }
            }
        }
        // Does the loop ever merge at all beyond what the body merges?
        let nb = (0..k).map(|s| bb[s]).collect::<std::collections::BTreeSet<_>>().len();
        let nl = (0..k).map(|s| bl[s]).collect::<std::collections::BTreeSet<_>>().len();
        if nl < nb { coarser += 1; }
    }
    println!("  wh_residual NA={NA}: {tried} loops tested; \
        loop-bisimilar-but-not-body-bisimilar pairs found in {residual}; \
        loop partition strictly coarser in {coarser}");
}

/// **DOES BISIMULATION COLLAPSE BREAK SOLVABILITY?** (iteration 223.)
///
/// Grabmayer–Fokkink's obstacle, in their setting: process graphs satisfying
/// the LLEE property (layered loop existence and elimination — a STRUCTURAL
/// certificate of solvability, since "every prechart with the LLEE-property
/// admits a unique solution", and "every chart interpretation of a star
/// expression has the LLEE-property") are **not closed under bisimulation
/// collapse**.  Their fix is a LLEE-preserving CRYSTALLIZATION producing
/// near-collapsed graphs whose SCCs are collapsed or of twin-crystal shape.
///
/// If the same holds here, it explains a fact this census found independently —
/// that the full collapse sometimes resists while a finer quotient does not —
/// and it says the Lean proof should target a CRYSTALLIZED quotient rather than
/// the full collapse or the canonical one.
///
/// The measurement: a Thompson automaton of a random expression is solvable by
/// construction, so the calculus should handle it.  Collapse it and ask again.
/// Any case where the calculus succeeds BEFORE and fails AFTER is the GKAT
/// analogue of LLEE not surviving collapse.
fn collapse_breaks<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0xC0FFEE_1234_5678;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut pre_ok, mut post_ok, mut broke, mut shrank) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..200_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        let solve = |q: &Aut<NA>| -> bool {
            let sing = singleton_states(q);
            sccs_of(q).iter().all(|c| c.len() < 2
                || calculus_solves(q, c, 6)
                || calculus_solves(q, &scc_with_context(q, c, &sing), 6))
        };
        let before = solve(&a);
        let (blk, nb) = bisim_blocks(&a);
        let q = match quotient_by(&a, &blk, nb) { Some(q) => q, None => continue };
        n += 1;
        if nb < a.k as usize { shrank += 1; }
        let after = solve(&q);
        if before { pre_ok += 1; }
        if after { post_ok += 1; }
        if before && !after {
            broke += 1;
            if shown < 3 {
                shown += 1;
                println!("    COLLAPSE BROKE IT: k {} -> {}", a.k, nb);
                for s in 0..(q.k as usize) {
                    let row: Vec<String> = (0..NA).map(|i| {
                        let t = q.st[s][i];
                        if t == 0 { "-".to_string() } else { format!("c{}", t - 1) }
                    }).collect();
                    println!("      collapsed c{s}: hl={:03b} st=[{}]", q.hl[s],
                        row.join(","));
                }
            }
        }
    }
    println!("  collapse_breaks NA={NA}: {n} Thompson automata; \
        calculus solves BEFORE collapse {pre_ok}, AFTER {post_ok}; \
        collapse strictly shrank {shrank}; SOLVED-THEN-BROKEN {broke}");
}

/// **WHICH STRUCTURAL PREDICATE IS SOLVABILITY?** (iteration 225.)
///
/// The exhaustive runs establish, at k<=4 / NA=2 over 1 695 497 minimised
/// automata, that the six-rule calculus solves exactly the solvable ones.  That
/// is a characterization by an ALGORITHM.  LLEE says there should be one by a
/// STRUCTURE, and the cheapest LLEE-adjacent candidate already in this harness
/// is T1/T2 reducibility — loops with a single dominating entry, which is what
/// "loops are never mutually nested" amounts to on the entry side.
///
/// Cross-tabulate, over every minimised automaton: is every SCC reducible, and
/// is the automaton solvable (verified witness)?  Four cells; the interesting
/// ones are the disagreements.
fn char2<const NA: usize>() {
    let kmax: usize = std::env::var("PAD_EXH_K").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(3);
    let table = synth_table::<NA>(synth_size(), seq_len(NA));
    println!("  synth table: {} behaviours", table.len());
    for k in 2..=kmax {
        let choices = k + 2;
        let cells = k * NA;
        let total: u64 = (choices as u64).pow(cells as u32);
        // (reducible, solvable) -> count
        let counts: [u64; 4] = (0..total).into_par_iter().map(|code| {
            let mut acc = [0u64; 4];
            let mut a = Aut::<NA>::blank();
            a.k = k as u8;
            let mut c = code;
            for s in 0..k {
                for y in 0..NA {
                    let d = (c % choices as u64) as usize;
                    c /= choices as u64;
                    if d == 0 { a.hl[s] |= 1 << y; }
                    else if d != 1 { a.st[s][y] = (d - 1) as u8; }
                }
            }
            let mut seen = vec![false; k];
            let mut stack = vec![0usize];
            seen[0] = true;
            while let Some(x) = stack.pop() {
                for y in 0..NA {
                    let t = a.st[x][y];
                    if t == 0 { continue; }
                    let t = (t - 1) as usize;
                    if !seen[t] { seen[t] = true; stack.push(t); }
                }
            }
            if !seen.iter().all(|&b| b) { return acc; }
            let a = match bisim_blocks(&a) { (blk, nb) =>
                match quotient_by(&a, &blk, nb) { Some(q) => q, None => return acc } };
            let sccs = sccs_of(&a);
            if !sccs.iter().any(|c| c.len() >= 2) { return acc; }
            let red = sccs.iter().all(|c| c.len() < 2 || t1t2_reducible(&a, c));
            let sol = synth_lookup(&table, &a, 0, seq_len(NA)).is_some();
            acc[(red as usize) * 2 + (sol as usize)] += 1;
            acc
        }).reduce(|| [0u64; 4], |mut x, y| { for i in 0..4 { x[i] += y[i]; } x });
        println!("  char2 NA={NA} k={k}: \
            reducible&solvable {} | reducible&UNsolvable {} | \
            IRreducible&solvable {} | irreducible&unsolvable {}",
            counts[3], counts[2], counts[1], counts[0]);
    }
}

fn nested_sanity<const NA: usize>() {
    let mut st0: u64 = 0xA5A5_1234_DEAD_BEEF;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    for &k in [3usize, 4, 5, 6].iter() {
        let (mut yes, mut no) = (0usize, 0usize);
        for _ in 0..20_000 {
            let mut a = Aut::<NA>::blank();
            a.k = k as u8;
            for s in 0..k {
                let r = rnd();
                a.hl[s] = ((r >> 32) as u8) & ((1u16 << NA) - 1) as u8;
                for y in 0..NA {
                    let v = ((r >> (y * 5)) & 0x1f) as usize;
                    // leave some atoms undefined, otherwise every state is total
                    a.st[s][y] = if v % 4 == 0 { 0 } else { ((v % k) + 1) as u8 };
                }
                // a halt and a transition cannot share an atom
                for y in 0..NA { if a.st[s][y] != 0 { a.hl[s] &= !(1 << y); } }
            }
            if nested(&a) { yes += 1; } else { no += 1; }
        }
        println!("  nested_sanity k={k}: satisfies {yes}, VIOLATES {no} (of {})",
            yes + no);
    }
}

fn scc_census<const NA: usize>(nguards: u8) {
    let npairs: usize = std::env::var("PAD_CENSUS_N").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(20_000);
    let depth: usize = std::env::var("PAD_CENSUS_DEPTH").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(6);
    let kmin: usize = std::env::var("PAD_CENSUS_KMIN").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(3);
    let kmax: usize = std::env::var("PAD_CENSUS_KMAX").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(10);
    // THE REPORTING WALL.  Every lattice-resistant pair dumps two fully
    // parenthesised `Exp` trees, and `println!` flushes per line, so a run
    // that finds thousands of them spends all its time in write(2) — the
    // analysis phases are milliseconds by comparison.  Off by default so the
    // census scales; set PAD_CENSUS_DUMP=1 to study individual resisters.
    let dump = std::env::var("PAD_CENSUS_DUMP").is_ok();
    let mut st0: u64 = 0x5EEDCAFE12345678;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    // keep the GENERATING EXPRESSION alongside each automaton: when a census
    // instance turns out to be open, the two source programs are the fastest
    // route to understanding it (their canonical labels are candidate solutions).
    let mut buckets: FxMap<Vec<u8>, Vec<(Aut<NA>, String)>> = FxMap::default();
    let mut pairs: Vec<(Aut<NA>, Aut<NA>, String, String)> = Vec::new();
    let mut tries = 0usize;
    // GENERATION IS THE WHOLE COST.  Phase timers put the entire analysis —
    // lattice search, calculus, absorption checks, classifiers — at 0.1s of a
    // 9s run at 60 000 pairs; the rest is this loop, and it is superlinear
    // because later pairs need more tries.  It was also the only serial phase
    // in a program that is parallel everywhere else, which is exactly where the
    // last three optimization passes on this harness found their win.
    //
    // The expensive part per try is `genexp` -> `canon` -> `behaviour`, all
    // pure.  Draw one seed per try SERIALLY (nanoseconds, and it keeps the
    // draw order deterministic), then map the batch in parallel and merge into
    // the buckets serially.  NOTE: the sample is NOT bit-identical to the
    // pre-parallel runs — each try now uses its own xorshift stream seeded from
    // the serial one — so instance dumps differ between versions while the
    // rates do not.
    const GEN_CHUNK: usize = 4096;
    while pairs.len() < npairs && tries < 50_000_000 {
        let seeds: Vec<u64> = (0..GEN_CHUNK).map(|_| rnd()).collect();
        tries += GEN_CHUNK;
        let batch: Vec<(Aut<NA>, Vec<u8>, String)> = seeds
            .par_iter()
            .filter_map(|&seed| {
                let mut st = seed | 1;
                let mut r = move || {
                    st ^= st << 13;
                    st ^= st >> 7;
                    st ^= st << 17;
                    st
                };
                let (a, ae, _ap) = genexp::<NA>(&mut r, depth, nguards, kmax)?;
                if (a.k as usize) < kmin || (a.k as usize) > kmax { return None; }
                let c = canon(&a)?;
                let beh = behaviour(&c);
                Some((c, beh, ae))
            })
            .collect();
        for (c, beh, ae) in batch {
            if pairs.len() >= npairs { break; }
            let v = buckets.entry(beh).or_default();
            if v.iter().any(|(x, _)| *x == c) { continue; }
            for (x, xe) in v.iter() {
                if pairs.len() < npairs { pairs.push((*x, c, xe.clone(), ae.clone())); }
            }
            if v.len() < 8 { v.push((c, ae.clone())); }
        }
    }
    println!("SCC CENSUS (NA={NA}, depth<={depth}, k in [{kmin},{kmax}]): {} pairs over {} tries",
        pairs.len(), tries);
    let mut n_states = 0usize;
    let mut n_fold = 0usize;
    let mut n_self = 0usize;
    let mut n_multi = 0usize;
    let mut pairs_done = 0usize;
    let mut pairs_covered = 0usize;
    let mut multi_hist: FxMap<(usize, bool, usize, usize, usize), usize> = FxMap::default();
    let mut multi_examples: Vec<String> = Vec::new();
    let mut multi_port_dumps = 0usize;
    let mut open_dumps = 0usize;
    let mut n_walked_scc = 0usize;
    let mut n_side = 0usize;
    let mut n_side_collapsed = 0usize;
    let mut side_shrink_total = 0usize;
    let mut n_open_scc = 0usize;
    let mut n_chorded_scc = 0usize;
    let mut n_open_pairs = 0usize;
    let mut n_open_pairs_lattice = 0usize;
    let mut n_absorb_shape = 0usize;
    let mut n_absorb_verified = 0usize;
    let mut n_gated_scc = 0usize;
    let mut n_res_reducible = 0usize;
    let mut n_res_multiexit = 0usize;
    let mut n_res_scc = 0usize;
    let mut n_calculus = 0usize;
    let mut n_open_calc = 0usize;
    let mut n_fail_scc = 0usize;
    let mut n_calc_skipped = 0usize;
    let mut n_canon = 0usize;
    let mut n_canon_nested = 0usize;
    let mut n_allcanon = 0usize;
    let mut n_base = 0usize;
    let mut n_base_sum_nested = 0usize;
    let mut n_base_full_nested = 0usize;
    let mut n_allcanon_nested = 0usize;
    let mut n_canon_ok = 0usize;
    let mut n_canon_skipped = 0usize;
    let mut n_canon_toobig = 0usize;
    let mut n_canon_nonbehav = 0usize;
    let mut n_fail_exits = 0usize;
    let mut n_fail_multiexit = 0usize;
    let mut n_open_calc_ok = 0usize;
    let mut n_open_calc_lattice = 0usize;
    // Coarse phase timers.  Three earlier optimization passes on this harness
    // all found their win in a phase I had not predicted, so measure the
    // phases before touching any of them.
    let mut t_lat = std::time::Duration::ZERO;
    let mut t_calc = std::time::Duration::ZERO;
    let mut t_absorb = std::time::Duration::ZERO;
    let t_all = std::time::Instant::now();
    for (a, b, aexp, bexp) in pairs.iter() {
        // SAME-SIDE collapse measurement: is each program's OWN automaton
        // already its own bisimulation quotient?  Iteration 131's dichotomy
        // says same-side UNIF is vacuous exactly when it is.
        for side in [a, b] {
            n_side += 1;
            let mc = min_classes(side);
            if mc < side.k as usize {
                n_side_collapsed += 1;
                side_shrink_total += side.k as usize - mc;
            }
        }
        let su = match sum_core(a, b) { Some(s) => s, None => continue };
        let k = su.k as usize;
        // liveness fixpoint (Live in the Lean sense: nonempty language)
        let mut live = [false; MAXK];
        loop {
            let mut changed = false;
            for s in 0..k {
                if live[s] { continue; }
                let mut l = su.hl[s] != 0;
                if !l {
                    for i in 0..NA {
                        let t = su.st[s][i];
                        if t != 0 && live[(t - 1) as usize] { l = true; break; }
                    }
                }
                if l { live[s] = true; changed = true; }
            }
            if !changed { break; }
        }
        // trimAut: dead-target arms become rejection
        let mut tr = su;
        for s in 0..k {
            for i in 0..NA {
                let t = tr.st[s][i];
                if t != 0 && !live[(t - 1) as usize] { tr.st[s][i] = 0; }
            }
        }
        for i in 0..NA {
            let t = tr.it[i];
            if t != 0 && !live[(t - 1) as usize] { tr.it[i] = 0; }
        }
        // language minimization = the canonical bisimilarity quotient of the trim
        let mut cls = [0u8; MAXK];
        {
            let mut seen = [255u8; 256];
            let mut n = 0u8;
            for s in 0..k {
                let h = tr.hl[s] as usize;
                if seen[h] == 255 { seen[h] = n; n += 1; }
                cls[s] = seen[h];
            }
        }
        loop {
            let mut sigs: Vec<(u8, [u8; NA])> = Vec::new();
            let mut next = [0u8; MAXK];
            for s in 0..k {
                let mut row = [255u8; NA];
                for i in 0..NA {
                    if tr.st[s][i] != 0 { row[i] = cls[(tr.st[s][i] - 1) as usize]; }
                }
                let sig = (cls[s], row);
                let j = match sigs.iter().position(|x| *x == sig) {
                    Some(j) => j,
                    None => { sigs.push(sig); sigs.len() - 1 }
                };
                next[s] = j as u8;
            }
            let (mut c0, mut c1) = (0usize, 0usize);
            {
                let mut m = [false; MAXK];
                for s in 0..k { if !m[cls[s] as usize] { m[cls[s] as usize] = true; c0 += 1; } }
                let mut m2 = [false; MAXK];
                for s in 0..k { if !m2[next[s] as usize] { m2[next[s] as usize] = true; c1 += 1; } }
            }
            cls = next;
            if c1 == c0 { break; }
        }
        let nb = {
            let mut m = [false; MAXK];
            let mut c = 0usize;
            for s in 0..k { if !m[cls[s] as usize] { m[cls[s] as usize] = true; c += 1; } }
            c
        };
        let mut blk = [0usize; MAXK];
        for s in 0..k { blk[s] = cls[s] as usize; }
        let q0 = match quotient_by(&tr, &blk, nb) { Some(q) => q, None => continue };
        let q = match trim_canon(&q0) { Some(q) => q, None => continue };
        pairs_done += 1;
        let sccs = sccs_of(&q);
        let singles = singleton_states(&q);
        let mut covered = true;
        let mut pair_open = false;
        let mut pair_calc_ok = true;
        for scc in sccs.iter() {
            if scc.len() == 1 {
                let s = scc[0];
                let selfarms = (0..NA).filter(|&i| q.st[s][i] as usize == s + 1).count();
                n_states += 1;
                if selfarms == 0 { n_fold += 1; } else { n_self += 1; }
            } else {
                n_states += scc.len();
                n_multi += scc.len();
                covered = false;
                let inscc = |t: usize| scc.contains(&t);
                let mut n_halting = 0usize;
                let mut n_exit_arms = 0usize;
                let mut branchers = 0usize;
                let mut simple = true;
                for &s in scc.iter() {
                    if q.hl[s] != 0 { n_halting += 1; }
                    let mut itargets: Vec<usize> = Vec::new();
                    for i in 0..NA {
                        let t = q.st[s][i];
                        if t != 0 {
                            let t = (t - 1) as usize;
                            if inscc(t) {
                                if !itargets.contains(&t) { itargets.push(t); }
                            } else { n_exit_arms += 1; }
                        }
                    }
                    if itargets.len() >= 2 { branchers += 1; }
                    if itargets.len() != 1 { simple = false; }
                }
                // walked-coverage: some port choice makes this a walked parked
                // cycle (walked_cycle_roles): unique non-self in-SCC successors
                // forming one cycle, no exits, subset halts, port exclusivity
                let walked = 'w: {
                    // unique non-self in-SCC successors forming one cycle
                    let mut succ: Vec<(usize, usize)> = Vec::new();
                    for &s in scc.iter() {
                        let mut ns: Vec<usize> = Vec::new();
                        for i in 0..NA {
                            let t = q.st[s][i];
                            if t != 0 {
                                let t = (t - 1) as usize;
                                if t != s && inscc(t) && !ns.contains(&t) { ns.push(t); }
                            }
                        }
                        if ns.len() != 1 { break 'w false; }
                        succ.push((s, ns[0]));
                    }
                    let get = |s: usize| succ.iter().find(|x| x.0 == s).map(|x| x.1).unwrap();
                    let mut cur = scc[0];
                    let mut cnt = 0usize;
                    loop {
                        cur = get(cur);
                        cnt += 1;
                        if cur == scc[0] { break; }
                        if cnt > scc.len() { break 'w false; }
                    }
                    if cnt != scc.len() { break 'w false; }
                    // some port choice p: exits confined to p, interior halts
                    // fall through p's exit fold (walked_exit_cycle_roles)
                    scc.iter().any(|&p| {
                        let mut exitmask = 0u8;
                        let mut ok = true;
                        for &s in scc.iter() {
                            for i in 0..NA {
                                let t = q.st[s][i];
                                if t != 0 && !inscc((t - 1) as usize) {
                                    if s == p { exitmask |= 1 << i; }
                                    else { ok = false; }
                                }
                            }
                        }
                        if !ok { return false; }
                        let mut cyclemask = 0u8;
                        for i in 0..NA {
                            let t = q.st[p][i];
                            if t != 0 && inscc((t - 1) as usize) { cyclemask |= 1 << i; }
                        }
                        scc.iter().all(|&s| s == p
                            || (q.hl[s] & !q.hl[p] == 0
                                && q.hl[s] & exitmask == 0
                                && q.hl[s] & cyclemask == 0))
                    })
                };
                // chorded-coverage: some lap through EVERY member plus ONE
                // interior arm straight back to the port — the hypotheses of
                // `chorded_assembly_roles`.  The chord state is the unique
                // brancher; its two in-SCC successors are the port and the
                // lap's next position, so the lap reconstructs by following
                // unique successors.  No permutation search is needed.
                let chorded = 'c: {
                    if walked || branchers != 1 || scc.len() < 3 { break 'c false; }
                    let succs = |s: usize| -> Vec<usize> {
                        let mut ns: Vec<usize> = Vec::new();
                        for i in 0..NA {
                            let t = q.st[s][i];
                            if t != 0 {
                                let t = (t - 1) as usize;
                                if inscc(t) && !ns.contains(&t) { ns.push(t); }
                            }
                        }
                        ns
                    };
                    for &s in scc.iter() {
                        for i in 0..NA {
                            let t = q.st[s][i];
                            if t != 0 && !inscc((t - 1) as usize) { break 'c false; }
                        }
                    }
                    let cst = match scc.iter().find(|&&s| succs(s).len() >= 2) {
                        Some(&s) => s, None => break 'c false };
                    let cs = succs(cst);
                    if cs.len() != 2 { break 'c false; }
                    let mut good = false;
                    for pick in 0..2 {
                        let p = cs[pick];
                        let nx = cs[1 - pick];
                        if p == cst { continue; }
                        let mut lap: Vec<usize> = vec![p];
                        let mut cur = p;
                        let mut ok = true;
                        loop {
                            let n = if cur == cst { nx } else {
                                let s1 = succs(cur);
                                if s1.len() != 1 { ok = false; break; }
                                s1[0]
                            };
                            if n == p { break; }
                            if lap.contains(&n) { ok = false; break; }
                            lap.push(n);
                            cur = n;
                            if lap.len() > scc.len() { ok = false; break; }
                        }
                        if !ok || lap.len() != scc.len() { continue; }
                        let cpos = match lap.iter().position(|&x| x == cst) {
                            Some(i) => i, None => continue };
                        if !(cpos >= 1 && cpos + 1 < lap.len()) { continue; }
                        if succs(p) != vec![lap[1]] { continue; }
                        let mut stepmask = 0u8;
                        for i in 0..NA {
                            if q.st[p][i] != 0 { stepmask |= 1 << i; }
                        }
                        if q.hl[p] & stepmask != 0 { continue; }
                        if !scc.iter().all(|&s| s == p || (q.hl[s] & !q.hl[p] == 0)) {
                            continue;
                        }
                        good = true;
                        break;
                    }
                    good
                };
                if walked { n_walked_scc += 1; }
                else if chorded { n_chorded_scc += 1; }
                else {
                    n_open_scc += 1;
                    pair_open = true;
                    // STRESS THE CALCULUS on EVERY open SCC, not only the
                    // lattice-resistant ones: the resistant set is ~1 in 10^4
                    // pairs, the open set ~10x larger, and both are hard.
                    // An SCC too big to attempt is SKIPPED, not failed — see
                    // `calculus_attempted`.  Folding the two together is what
                    // made 202's NA=2 rate read 102/104 when one of the two
                    // "failures" had never been tried.  A skip is UNKNOWN, so
                    // it is excluded from the denominator and the pair is
                    // conservatively not counted as calculus-solved.
                    if !calculus_attempted(scc) {
                        n_calc_skipped += 1;
                        pair_calc_ok = false;
                        continue;
                    }
                    n_open_calc += 1;
                    let t0 = std::time::Instant::now();
                    // Give the search its outside context (see
                    // `scc_with_context`): rule 6 cannot match a shared suffix
                    // through an opaque oracle.  Fall back to the bare SCC if
                    // the extension gained nothing.
                    // CHEAPEST FIRST.  `calc_search` is exponential in the
                    // state-list length, so try the bare SCC before the
                    // context-extended list: the bare call succeeds on all but
                    // a handful of SCCs, and 207 paid for the expensive search
                    // on every one of them.  Ordering it this way keeps the
                    // completeness the context buys while paying for it only
                    // where it is actually needed.
                    let calc_ok = no_calc()
                        || calculus_solves(&q, scc, 5)
                        || calculus_solves(&q,
                            &scc_with_context(&q, scc, &singles), 5);
                    t_calc += t0.elapsed();
                    if calc_ok {
                        n_open_calc_ok += 1;
                    } else {
                        // ALWAYS printed.  This dump used to sit behind
                        // `else if { pair_calc_ok = false; false }` — a block
                        // evaluating to `false`, so only the side effect ran
                        // and every full-collapse calculus failure was
                        // invisible.  That is exactly the shape of bug that
                        // produced 179's false finding, so it prints
                        // unconditionally now, dump flag or not.
                        pair_calc_ok = false;
                        // KOSARAJU'S CONDITION, measured at the point of
                        // failure: a loop with two distinct exits cannot be
                        // structured without NODE SPLITTING.  Splitting a node
                        // is un-collapsing — descending the bisimulation
                        // lattice to a FINER quotient — which is exactly the
                        // freedom `SumQuotientSolvable`'s existential grants.
                        // If every full-collapse failure is multi-exit, that is
                        // an explanation for the complementarity 196 measured,
                        // not just a restatement of it.
                        n_fail_exits += exit_states(&q, scc);
                        n_fail_scc += 1;
                        if exit_states(&q, scc) > 1 { n_fail_multiexit += 1; }
                        println!("  CALCULUS FAILS on open scc {scc:?} (pair #{pairs_done}): \
                            exits={} reducible={}",
                            exit_states(&q, scc), t1t2_reducible(&q, scc));
                        for &s in scc.iter() {
                            let row: Vec<String> = (0..NA).map(|i| {
                                let t = q.st[s][i];
                                if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                            }).collect();
                            println!("    q{s}: hl={:04b} st=[{}]", q.hl[s], row.join(","));
                        }
                    }
                }
                // OPEN dump: the SCCs no proved stratum covers.  These are the
                // residue the elimination-order question is about, so print them
                // in full — including which members are ports (halt or carry an
                // external arm), since a port count >= 2 is exactly the case
                // `elim_reduces`' uniform-exit side condition rules out.
                if !walked && !chorded && open_dumps < 40 {
                    open_dumps += 1;
                    let nports = scc.iter().filter(|&&s| {
                        q.hl[s] != 0 || (0..NA).any(|i| {
                            let t = q.st[s][i];
                            t != 0 && !inscc((t - 1) as usize)
                        })
                    }).count();
                    println!("  OPEN-SCC #{open_dumps} (pair #{pairs_done}, quotient k={}, scc {:?}, ports={nports}):",
                        q.k, scc);
                    for &s in scc.iter() {
                        let row: Vec<String> = (0..NA).map(|i| {
                            let t = q.st[s][i];
                            if t == 0 { "-".to_string() }
                            else {
                                let t = (t - 1) as usize;
                                if inscc(t) { format!("s{t}") } else { format!("X{t}") }
                            }
                        }).collect();
                        println!("    state {s}: hl={:04b} st=[{}]", q.hl[s], row.join(","));
                    }
                    println!("    nesting coequation (whole quotient): {}; total: {}",
                        nested(&q), total_aut(&q));
                    println!("    -- source programs (language-equivalent pair):");
                    println!("       e = {aexp}");
                    println!("       f = {bexp}");
                    // the whole quotient, so the exit targets X* are readable too
                    println!("    -- full quotient:");
                    for s in 0..(q.k as usize) {
                        let row: Vec<String> = (0..NA).map(|i| {
                            let t = q.st[s][i];
                            if t == 0 { "-".to_string() } else { format!("{}", t - 1) }
                        }).collect();
                        println!("       q{s}: hl={:04b} st=[{}]", q.hl[s], row.join(","));
                    }
                }
                *multi_hist.entry((scc.len(), simple, n_halting, n_exit_arms, branchers))
                    .or_insert(0) += 1;
                if multi_examples.len() < 5 {
                    multi_examples.push(format!("scc {:?} in quotient k={} (pair #{})",
                        scc, q.k, pairs_done));
                }
                // multi-PORT dump: ports = members that halt or carry external arms
                let ports = scc.iter().filter(|&&s| {
                    q.hl[s] != 0 || (0..NA).any(|i| {
                        let t = q.st[s][i];
                        t != 0 && !inscc((t - 1) as usize)
                    })
                }).count();
                if ports >= 2 && multi_port_dumps < 40 {
                    multi_port_dumps += 1;
                    println!("  MULTI-PORT #{multi_port_dumps} (pair #{pairs_done}, quotient k={}, scc {:?}):", q.k, scc);
                    for &s in scc.iter() {
                        let row: Vec<String> = (0..NA).map(|i| {
                            let t = q.st[s][i];
                            if t == 0 { "-".to_string() }
                            else {
                                let t = (t - 1) as usize;
                                if inscc(t) { format!("s{t}") } else { format!("X{t}") }
                            }
                        }).collect();
                        println!("    state {s}: hl={:04b} st=[{}]", q.hl[s], row.join(","));
                    }
                }
            }
        }
        // THE LATTICE QUESTION.  The census classifies SCCs of the FULL
        // bisimulation collapse, but `SumQuotientSolvable` asks only for SOME
        // behavioural quotient with a solution — the full collapse is the top
        // of the lattice, not the whole of it.  For every pair the strata
        // leave open, ask whether ANY intermediate congruence is solvable.
        // ALL-PAIRS canonical-nesting check.  The per-open-pair version below
        // covers only the hard residue; the claim that matters is universal,
        // so ask it of every language-equivalent pair the census generates.
        if let Some((cb, cnb)) = start_congruence(&su, a.k as usize + 1) {
            if let Some(cq) = quotient_by(&su, &cb, cnb) {
                n_allcanon += 1;
                if nested(&cq) { n_allcanon_nested += 1; }
            }
        }
        // BASE RATE.  A near-universal property proves nothing about the
        // canonical quotient, so measure the same predicate on the two
        // quotients we did NOT choose: the raw Thompson sum (finest) and the
        // full bisimulation collapse (coarsest).  If those violate the nesting
        // coequation at a real rate and the canonical never does, the result
        // is about the canonical quotient.  If they never violate it either,
        // the measurement is vacuous and must be reported as such.
        n_base += 1;
        if nested(&su) { n_base_sum_nested += 1; }
        if nested(&q) { n_base_full_nested += 1; }
        if pair_open {
            n_open_pairs += 1;
            // Only search the lattice when the FULL COLLAPSE already failed —
            // that is ~15% of open pairs, and the lattice pass is the expensive
            // one (hundreds of congruences, each with its own SCC search).
            // Gated behind PAD_CALC_LATTICE: the lattice pass is hundreds of
            // congruences per pair, each with its own SCC search, and it makes
            // the census itself unrunnable at 10^5 pairs.
            if pair_calc_ok {
                n_open_calc_lattice += 1;
            } else if std::env::var("PAD_CALC_LATTICE").is_ok()
                && calculus_somewhere_in_lattice(&su, 4, a.k as usize + 1) {
                n_open_calc_lattice += 1;
            }
            // THE CANONICAL QUOTIENT, measured on every open pair.  This is
            // the LEAST congruence identifying the two starts, so it needs no
            // search and no existential — if the calculus solves it, the
            // target theorem can NAME its quotient instead of asserting one
            // exists.
            match start_congruence(&su, a.k as usize + 1) {
                None => n_canon_nonbehav += 1,
                Some((cb, cnb)) => match quotient_by(&su, &cb, cnb) {
                    None => n_canon_toobig += 1,
                    Some(cq) => {
                        n_canon += 1;
                        // THE NESTING COEQUATION.  Schmid-Kappe-Kozen-Silva
                        // settled the question well-nestedness left open: the
                        // COMPLETE characterization of automata exhibiting the
                        // behaviour of a GKAT expression is the nesting
                        // coequation (a covariety), not well-nestedness, which
                        // is strictly too restrictive.  So if the canonical
                        // quotient satisfies it, an expression EXISTS for it —
                        // by a known theorem, with no dependence on this
                        // calculus being complete.  That makes this the single
                        // most informative bit to measure per pair.
                        if nested(&cq) { n_canon_nested += 1; }
                        else {
                            println!("  CANONICAL QUOTIENT VIOLATES THE NESTING COEQUATION (pair #{pairs_done}, k={}):",
                                cq.k);
                            for s in 0..(cq.k as usize) {
                                let row: Vec<String> = (0..NA).map(|i| {
                                    let t = cq.st[s][i];
                                    if t == 0 { "-".to_string() }
                                    else { format!("c{}", t - 1) }
                                }).collect();
                                println!("    c{s}: hl={:04b} st=[{}]", cq.hl[s],
                                    row.join(","));
                            }
                        }
                        let sc = sccs_of(&cq);
                        if sc.iter().any(|c| c.len() >= 2 && !calculus_attempted(c)) {
                            n_canon_skipped += 1;
                        } else if { let csg = singleton_states(&cq);
                            // Cheapest first here too, and `singleton_states`
                            // hoisted out of the per-SCC closure.
                            sc.iter().all(|c| c.len() < 2
                                || calculus_solves(&cq, c, 5)
                                || calculus_solves(&cq,
                                    &scc_with_context(&cq, c, &csg), 5)) } {
                            n_canon_ok += 1;
                        } else {
                            // Separate "my calculus is incomplete here" from
                            // "this quotient is genuinely unsolvable": the
                            // independent elimination oracle decides it.
                            println!("  CANONICAL QUOTIENT UNSOLVED (pair #{pairs_done}, k={}): \
                                eliminable={} nested={}",
                                cq.k, symbolic_eliminable_raw(&cq), nested(&cq));
                            for s in 0..(cq.k as usize) {
                                let row: Vec<String> = (0..NA).map(|i| {
                                    let t = cq.st[s][i];
                                    if t == 0 { "-".to_string() }
                                    else { format!("c{}", t - 1) }
                                }).collect();
                                println!("    c{s}: hl={:04b} st=[{}]", cq.hl[s],
                                    row.join(","));
                            }
                        }
                    }
                }
            }
            let tl = std::time::Instant::now();
            let lat = !std::env::var("PAD_NO_LAT").is_ok()
                && solvable_somewhere_in_lattice(&su, false, a.k as usize + 1);
            t_lat += tl.elapsed();
            if lat { n_open_pairs_lattice += 1; }
            else {
                // THE CANDIDATE.  A pair no intermediate congruence solves is a
                // candidate counterexample to `SumQuotientSolvable` — the oracle
                // is sound on rejection of non-nested automata but not complete,
                // so this is a candidate, not a refutation.  Dump it whole.
                if dump {
                    println!("  LATTICE-RESISTANT PAIR #{pairs_done} (sum k={}):", su.k);
                    for s in 0..(su.k as usize) {
                        let row: Vec<String> = (0..NA).map(|i| {
                            let t = su.st[s][i];
                            if t == 0 { "-".to_string() } else { format!("{}", t - 1) }
                        }).collect();
                        println!("    sum state {s}: hl={:04b} st=[{}]", su.hl[s], row.join(","));
                    }
                    println!("    nesting coequation: {}; total: {}", nested(&su), total_aut(&su));
                    println!("    e = {aexp}");
                    println!("    f = {bexp}");
                }
                // EXIT ABSORPTION, constructed and language-checked in Rust
                for c in sccs_of(&q) {
                    if c.len() < 2 { continue; }
                    n_res_scc += 1;
                    if t1t2_reducible(&q, &c) { n_res_reducible += 1; }
                    if exit_states(&q, &c) > 1 { n_res_multiexit += 1; }
                    if gated_applicable(&q, &c) {
                        n_gated_scc += 1;
                        if dump { println!("    gated identification applies on scc {c:?}"); }
                    }
                    if calculus_solves(&q, &c, 5) {
                        n_calculus += 1;
                        if dump {
                            println!("    THREE-RULE CALCULUS solves scc {c:?} (language-checked)");
                        }
                    } else {
                        // ALWAYS printed, dump or not: an SCC the calculus cannot
                        // solve is the one thing this census exists to find.
                        println!("  PAIR #{pairs_done} (sum k={}):", su.k);
                        println!("    CALCULUS-RESISTANT scc {c:?}:");
                        for &s in c.iter() {
                            let row: Vec<String> = (0..NA).map(|i| {
                                let t = q.st[s][i];
                                if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                            }).collect();
                            println!("      q{s}: hl={:04b} st=[{}]", q.hl[s], row.join(","));
                        }
                    }
                    let ta = std::time::Instant::now();
                    let av = absorption_verified(&q, &c, 7);
                    t_absorb += ta.elapsed();
                    if let Some(ok) = av {
                        n_absorb_shape += 1;
                        if ok { n_absorb_verified += 1; }
                        // A MISMATCH is a soundness alarm, not a statistic: it
                        // says a construction the Lean proves correct disagreed
                        // with the language.  Never silence it.
                        if dump || !ok {
                            println!("    exit absorption on scc {c:?}: {}",
                                if ok { "VERIFIED" } else { "MISMATCH" });
                        }
                    }
                }
            }
        }
        if covered { pairs_covered += 1; }
    }
    println!("  SAME-SIDE: automata measured: {n_side}; NOT already minimal: {n_side_collapsed} ({:.1}%); total states collapsed: {side_shrink_total}",
        100.0 * n_side_collapsed as f64 / n_side.max(1) as f64);
    println!("  pairs analysed: {pairs_done}; FULLY covered by proved strata (fold+salomaaE): {pairs_covered} ({:.1}%)",
        100.0 * pairs_covered as f64 / pairs_done.max(1) as f64);
    println!("  quotient states: {n_states}; fold: {n_fold}; singleton-self: {n_self}; in multi-state SCCs: {n_multi}");
    println!("  multi-state SCCs: walked-covered (walked_cycle_roles): {n_walked_scc}; chorded-covered (chorded_assembly_roles): {n_chorded_scc}; OPEN: {n_open_scc}");
    println!("  pairs with an OPEN SCC in the FULL collapse: {n_open_pairs}; of those, SOLVABLE SOMEWHERE IN THE BISIMULATION LATTICE: {n_open_pairs_lattice}");
    println!("  lattice-resistant SCCs: gated-identification applicable {n_gated_scc}; of absorption shape {n_absorb_shape}, VERIFIED by construction {n_absorb_verified}");
    println!("  lattice-resistant SCCs: {n_res_scc} total; T1/T2-reducible {n_res_reducible}; MULTI-EXIT (Kosaraju) {n_res_multiexit}");
    println!("  lattice-resistant SCCs SOLVED BY THE THREE-RULE CALCULUS (language-checked): {n_calculus} / {n_res_scc}");
    println!("  ALL OPEN SCCs put to the calculus: {n_open_calc}; SOLVED (language-checked): {n_open_calc_ok}");
    println!("  FULL-COLLAPSE calculus failures: {n_fail_scc}; MULTI-EXIT (Kosaraju) {n_fail_multiexit}; total exit states {n_fail_exits}");
    println!("  SCCs NOT ATTEMPTED (larger than the size cap {}): {n_calc_skipped} — counted as UNKNOWN, not as failures",
        calc_max_scc());
    println!("  CANONICAL QUOTIENT (least congruence identifying the two starts) measured on {n_canon} open pairs; SOLVED by the calculus: {n_canon_ok}; skipped (over size cap) {n_canon_skipped}; too big to build {n_canon_toobig}; not behavioural {n_canon_nonbehav}");
    println!("  CANONICAL QUOTIENT SATISFIES THE NESTING COEQUATION: open pairs {n_canon_nested}/{n_canon}; ALL pairs {n_allcanon_nested}/{n_allcanon}");
    println!("  BASE RATE for the same predicate on quotients NOT chosen: raw Thompson sum {n_base_sum_nested}/{n_base}; full bisimulation collapse {n_base_full_nested}/{n_base}");
    println!("  OPEN PAIRS where the CALCULUS solves SOME quotient in the lattice: {n_open_calc_lattice} / {n_open_pairs}");
    println!("  [phases] total {:.1}s = lattice {:.1}s + calculus {:.1}s + absorption {:.1}s + rest {:.1}s",
        t_all.elapsed().as_secs_f64(), t_lat.as_secs_f64(), t_calc.as_secs_f64(),
        t_absorb.as_secs_f64(),
        t_all.elapsed().as_secs_f64() - t_lat.as_secs_f64() - t_calc.as_secs_f64()
            - t_absorb.as_secs_f64());
    println!("  [calc cost] calls {}; search nodes {}; ex_accepts {}",
        CALC_CALLS.load(std::sync::atomic::Ordering::Relaxed),
        CALC_NODES.load(std::sync::atomic::Ordering::Relaxed),
        CALC_ACCEPTS.load(std::sync::atomic::Ordering::Relaxed));
    let mut hist: Vec<_> = multi_hist.into_iter().collect();
    hist.sort_by(|x, y| y.1.cmp(&x.1));
    println!("  multi-state SCC shapes (size, cycle-kind, halting-members, exit-arms, branchers) -> count:");
    for ((sz, simple, nh, nx, br), c) in hist.iter().take(30) {
        println!("    ({sz}, {}, {nh}, {nx}, {br}) -> {c}", if *simple { "simple" } else { "branchy" });
    }
    for ex in multi_examples { println!("    example: {ex}"); }
}

fn forge<const NA: usize>(nguards: u8) {
    let npairs: usize = std::env::var("PAD_FORGE_N").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(2000);
    let depth: usize = std::env::var("PAD_FORGE_DEPTH").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(6);
    let kmin: usize = std::env::var("PAD_FORGE_KMIN").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(3);
    let kmax: usize = std::env::var("PAD_FORGE_KMAX").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(8);
    let mut st: u64 = 0xDEADBEEFCAFEF00D;
    let mut rnd = move || { st ^= st << 13; st ^= st >> 7; st ^= st << 17; st };
    // bucket entries carry the STRUCTURAL automaton and its paths alongside the canon
    // form: canon renumbers by BFS, and Lean-side state paths follow construction
    // order, so the pilot emitter needs canon_order to translate between them.
    let mut buckets: FxMap<Vec<u8>, Vec<(Aut<NA>, String, Aut<NA>, Vec<String>)>> = FxMap::default();
    let mut pairs: Vec<(Aut<NA>, Aut<NA>, String, String, Aut<NA>, Aut<NA>, Vec<String>, Vec<String>)> = Vec::new();
    let mut sampled = 0usize;
    let mut tries = 0usize;
    while pairs.len() < npairs && tries < 30_000_000 {
        tries += 1;
        if let Some((a, ae, ap)) = genexp::<NA>(&mut rnd, depth, nguards, kmax) {
            if (a.k as usize) < kmin || (a.k as usize) > kmax { continue; }
            let c = match canon(&a) { Some(c) => c, None => continue };
            sampled += 1;
            let beh = behaviour(&c);
            let v = buckets.entry(beh).or_default();
            if v.iter().any(|(x, _, _, _)| *x == c) { continue; }
            for (x, xe, xs, xp) in v.iter() {
                if pairs.len() < npairs {
                    pairs.push((*x, c, xe.clone(), ae.clone(), *xs, a, xp.clone(), ap.clone()));
                }
            }
            if v.len() < 8 { v.push((c, ae.clone(), a, ap.clone())); }
        }
    }
    println!("FORGE (NA={NA}, depth<={depth}, k in [{kmin},{kmax}]):");
    println!("  sampled {sampled} distinct-canon automata over {tries} tries");
    println!("  equivalent pairs found: {}", pairs.len());
    let mut by_k: FxMap<usize, (usize, usize, usize, usize)> = FxMap::default();
    let mut shown = 0usize;
    let emit_mix = std::env::var("PAD_EMIT_MIX").ok();
    let mut emitted_mix = false;
    for (a, b, ae, be, astr, bstr, apaths, bpaths) in pairs.iter() {
        let ka = match to_gaut(a) { Some(g) => g.k as usize, None => continue };
        let su = match sum_core(a, b) { Some(s) => s, None => continue };
        let kk = a.k.max(b.k) as usize;
        let e = by_k.entry(kk).or_insert((0, 0, 0, 0));
        e.0 += 1;
        let base = match close_congruence(&su, &[(0, ka)]) { Some(c) => c, None => continue };
        let mut cands: Vec<([usize; MAXK], usize)> = vec![base];
        for cg in lattice_congruences(&su).iter() {
            if cg.0[0] == cg.0[ka] { cands.push(*cg); }
        }
        let mut elim_ok = false;
        let mut ring_ok = false;
        for (b2, nb2) in cands.iter() {
            if let Some(q) = quotient_by(&su, b2, *nb2) {
                let qq = trim_canon(&q).unwrap_or(q);
                if symbolic_eliminable(&qq) { elim_ok = true; break; }
                if ring_uniform(&qq) { ring_ok = true; }
            }
        }
        if elim_ok { e.1 += 1; }
        else if ring_ok {
            e.2 += 1;
            if let Some(path) = emit_mix.as_ref() {
                if !emitted_mix && NA == 4 {
                    // smallest merged-start quotient + its class map
                    let mut best: Option<([usize; MAXK], usize)> = None;
                    for (b2, nb2) in cands.iter() {
                        if best.as_ref().map(|x| *nb2 < x.1).unwrap_or(true) {
                            best = Some((*b2, *nb2));
                        }
                    }
                    if let Some((blk, nb)) = best {
                        if let Some(q) = quotient_by(&su, &blk, nb) {
                            if emit_mix_pilot::<NA>(path, ae, be, astr, bstr,
                                    apaths, bpaths, &su, &q, &blk, nb) {
                                emitted_mix = true;
                                println!("  PILOT EMITTED to {path}");
                            }
                        }
                    }
                }
            }
        }
        else {
            e.3 += 1;
            if shown < 6 {
                shown += 1;
                println!("  FORGE RESIDUE CANDIDATE #{shown} (k={kk}, sum k={}):", su.k);
                println!("    INDEPENDENT product-bisim equivalent : {}", product_bisim(a, b));
                println!("    LEAN e := {ae}");
                println!("    LEAN f := {be}");
                for s in 0..su.k as usize {
                    let steps: Vec<String> = (0..NA).map(|i|
                        if su.st[s][i] == 0 { "-".to_string() }
                        else { format!("{}", su.st[s][i] - 1) }).collect();
                    println!("    {s}: hlt={:#06b} st={:?}", su.hl[s], steps);
                }
                println!("    merged-start quotients:");
                for (b2, nb2) in cands.iter() {
                    if let Some(q) = quotient_by(&su, b2, *nb2) {
                        let qq = trim_canon(&q).unwrap_or(q);
                        println!("      quotient k={} classes={:?}", qq.k, &b2[..su.k as usize]);
                        for s in 0..qq.k as usize {
                            let steps: Vec<String> = (0..NA).map(|i|
                                if qq.st[s][i] == 0 { "-".to_string() }
                                else { format!("{}", qq.st[s][i] - 1) }).collect();
                            println!("        {s}: hlt={:#06b} st={:?}", qq.hl[s], steps);
                        }
                    }
                }
            }
        }
    }
    let mut ks: Vec<usize> = by_k.keys().cloned().collect();
    ks.sort();
    println!("  stratum  pairs  elim  ring-only  neither");
    for k in ks {
        let (n, e, r, x) = by_k[&k];
        println!("  k={k:<2}     {n:<6} {e:<5} {r:<9} {x}");
    }
}

fn mask_lean_gen<const NA: usize>(m: u8) -> String {
    // NA=2: one primitive bT.  NA=4: two primitives bT1 bT2, atom = bit0|bit1<<1.
    if NA == 2 { return mask_lean(m); }
    if m == 0 { return "BExp.zero".to_string(); }
    if m == 0b1111 { return "BExp.one".to_string(); }
    let lit = |on: bool, name: &str| if on { name.to_string() }
        else { format!("(BExp.not {name})") };
    let mut terms: Vec<String> = Vec::new();
    for a in 0..4u8 {
        if m & (1 << a) != 0 {
            terms.push(format!("(BExp.and {} {})",
                lit(a & 1 != 0, "bT1"), lit(a & 2 != 0, "bT2")));
        }
    }
    let mut out = terms.pop().unwrap();
    while let Some(t) = terms.pop() { out = format!("(BExp.or {t} {out})"); }
    out
}

/// Independent equivalence check: product BFS — a different algorithm from behaviour().
fn product_bisim<const NA: usize>(a: &Aut<NA>, b: &Aut<NA>) -> bool {
    let (ga, gb) = match (to_gaut(a), to_gaut(b)) {
        (Some(x), Some(y)) => (x, y),
        _ => return false,
    };
    let mut seen: FxSet<(u8, u8)> = FxSet::default();
    let mut queue: Vec<(u8, u8)> = vec![(0, 0)];
    seen.insert((0, 0));
    while let Some((x, y)) = queue.pop() {
        if ga.hl[x as usize] != gb.hl[y as usize] { return false; }
        for i in 0..NA {
            let tx = ga.st[x as usize][i];
            let ty = gb.st[y as usize][i];
            if tx == 0 && ty == 0 { continue; }
            if tx == 0 || ty == 0 { return false; }
            let pr = (tx - 1, ty - 1);
            if seen.insert(pr) { queue.push(pr); }
        }
    }
    true
}

fn genexp<const NA: usize>(rnd: &mut impl FnMut() -> u64, depth: usize, nguards: u8,
    maxk: usize) -> Option<(Aut<NA>, String, Vec<String>)> {
    let pick = rnd() % if depth == 0 { 2 } else { 5 };
    match pick {
        0 => Some((a_act(), "pA".to_string(), vec!["()".to_string()])),
        1 => {
            let g = (rnd() % nguards as u64) as u8;
            Some((a_test(g), format!("(Exp.test {})", mask_lean_gen::<NA>(g)), Vec::new()))
        }
        2 => {
            let (l, ls, lp) = genexp(rnd, depth - 1, nguards, maxk)?;
            let (r, rs, rp) = genexp(rnd, depth - 1, nguards, maxk)?;
            let a = a_seq(&l, &r)?;
            if a.k as usize <= maxk {
                let mut ps: Vec<String> = lp.iter().map(|q| format!("(Sum.inl {q})")).collect();
                ps.extend(rp.iter().map(|q| format!("(Sum.inr {q})")));
                Some((a, format!("(Exp.seq {ls} {rs})"), ps))
            } else { None }
        }
        3 => {
            let g = (rnd() % nguards as u64) as u8;
            let (l, ls, lp) = genexp(rnd, depth - 1, nguards, maxk)?;
            let (r, rs, rp) = genexp(rnd, depth - 1, nguards, maxk)?;
            let a = a_ite(g, &l, &r)?;
            if a.k as usize <= maxk {
                let mut ps: Vec<String> = lp.iter().map(|q| format!("(Sum.inl {q})")).collect();
                ps.extend(rp.iter().map(|q| format!("(Sum.inr {q})")));
                Some((a, format!("(Exp.ite {} {ls} {rs})", mask_lean_gen::<NA>(g)), ps))
            } else { None }
        }
        _ => {
            let g = (rnd() % nguards as u64) as u8;
            let (b, bs, bp) = genexp(rnd, depth - 1, nguards, maxk)?;
            Some((a_wh(g, &b), format!("(Exp.wh {} {bs})", mask_lean_gen::<NA>(g)), bp))
        }
    }
}

/// PAD_MIXSAMPLE: random Thompson expressions (no closure — crash-safe), measuring the
/// rate of MIXED-HALT SCCs.  This is the NA=4 question the exhaustive closure cannot
/// reach on 48GB: with two primitive tests, do loop bodies produce mutually-reachable
/// halting states with different guards?
fn mixsample<const NA: usize>(nguards: u8, maxk: usize) {
    // deterministic xorshift
    let mut st: u64 = 0x9E3779B97F4A7C15;
    let mut rnd = move || { st ^= st << 13; st ^= st >> 7; st ^= st << 17; st };
    let has_mixed = |q: &Aut<NA>| sccs_of(q).iter().any(|members|
        members.len() > 1 && members.iter().any(|&s| q.hl[s] != 0
            && members.iter().any(|&t| q.hl[t] != 0 && q.hl[t] != q.hl[s])));
    let mut tot = 0usize;
    let mut mixed = 0usize;
    let mut mixed_min = 0usize;
    let mut shown = 0usize;
    let mut tries = 0usize;
    while tot < 100_000 && tries < 2_000_000 {
        tries += 1;
        if let Some((a, _, _)) = genexp::<NA>(&mut rnd, 5, nguards, maxk) {
            if a.k < 2 { continue; }
            if let Some(g) = to_gaut(&a) {
                tot += 1;
                if has_mixed(&g) {
                    mixed += 1;
                    let (blk, nb) = bisim_blocks(&g);
                    if let Some(q) = quotient_by(&g, &blk, nb) {
                        if has_mixed(&q) {
                            mixed_min += 1;
                            if shown < 3 {
                                shown += 1;
                                println!("  MIXED-HALT MINIMAL sample #{shown} (k={}):", q.k);
                                for s in 0..q.k as usize {
                                    let steps: Vec<String> = (0..NA).map(|i|
                                        if q.st[s][i] == 0 { "-".to_string() }
                                        else { format!("{}", q.st[s][i] - 1) }).collect();
                                    println!("    {s}: hlt={:#06b} st={:?}", q.hl[s], steps);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("MIXSAMPLE (random Thompson, NA={NA}, depth<=5, k<={maxk}):");
    println!("  sampled {tot}, mixed-halt SCC raw {mixed}, surviving minimization {mixed_min}");
}

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
    if std::env::var("PAD_MIXSAMPLE").is_ok() {
        mixsample::<NA>(nguards as u8, 12.min(MAXK - 1));
        return;
    }
    if std::env::var("PAD_FORGE").is_ok() {
        forge::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_CHECK_CAND").is_ok() {
        check_candidate::<NA>();
        return;
    }
    if std::env::var("PAD_CHECK_R206").is_ok() {
        check_r206::<NA>();
        return;
    }
    if std::env::var("PAD_EXHAUST").is_ok() {
        exhaustive::<NA>();
        return;
    }
    if std::env::var("PAD_NESTED").is_ok() {
        nested_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_LEVELS").is_ok() {
        levels_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_CONNECT").is_ok() {
        connect_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_CERTQ").is_ok() {
        cert_arbitrary_quotient::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_L2P").is_ok() {
        l2prime_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_HEADS").is_ok() {
        head_census::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_L123").is_ok() {
        l123_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_SUBCHART").is_ok() {
        subchart_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_GUARDSEARCH").is_ok() {
        guardsearch_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_EXISTS").is_ok() {
        exists_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_LAYERED").is_ok() {
        layered_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_LOOPGUARD").is_ok() {
        loopguard_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_ENTRY_GUARD").is_ok() {
        entry_guard_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_GUARD_DIAG").is_ok() {
        guard_diag::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_LLEE").is_ok() {
        llee_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_STRONGAGREE").is_ok() {
        let g: u8 = std::env::var("G").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let r: usize = std::env::var("R").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let c: usize = std::env::var("CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
        strongagree::<3>(g, r, c);
        return;
    }
    if std::env::var("PAD_SRCEXIT").is_ok() {
        let g: u8 = std::env::var("G").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let r: usize = std::env::var("R").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let c: usize = std::env::var("CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
        srcexit::<3>(g, r, c);
        return;
    }
    if std::env::var("PAD_HALTDET").is_ok() {
        let g: u8 = std::env::var("G").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let r: usize = std::env::var("R").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let c: usize = std::env::var("CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
        haltdet::<3>(g, r, c);
        return;
    }
    if std::env::var("PAD_LOOPMERGE").is_ok() {
        let g: u8 = std::env::var("G").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let r: usize = std::env::var("R").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let c: usize = std::env::var("CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
        loopmerge::<3>(g, r, c);
        return;
    }
    if std::env::var("PAD_BACKATOM").is_ok() {
        let g: u8 = std::env::var("G").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let r: usize = std::env::var("R").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let c: usize = std::env::var("CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
        backatom::<3>(g, r, c);
        return;
    }
    if std::env::var("PAD_CONDENSATION").is_ok() {
        let g: u8 = std::env::var("G").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let r: usize = std::env::var("R").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
        let c: usize = std::env::var("CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
        condensation::<3>(g, r, c);
        return;
    }
    if std::env::var("PAD_SCC_EXIT").is_ok() {
        let rounds: usize = std::env::var("PAD_BT_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let cap: usize = std::env::var("PAD_BT_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
        scc_exit::<NA>(nguards as u8, rounds, cap);
        return;
    }
    if std::env::var("PAD_MINCONG").is_ok() {
        let rounds: usize = std::env::var("PAD_BT_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
        let cap: usize = std::env::var("PAD_BT_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
        mincong::<NA>(nguards as u8, rounds, cap);
        return;
    }
    if std::env::var("PAD_BODY_COND").is_ok() {
        let rounds: usize = std::env::var("PAD_BT_ROUNDS").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(2);
        let cap: usize = std::env::var("PAD_BT_CAP").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(120);
        body_cond::<NA>(nguards as u8, rounds, cap);
        return;
    }
    if std::env::var("PAD_MIXED_ENTRY").is_ok() {
        let rounds: usize = std::env::var("PAD_BT_ROUNDS").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(2);
        let cap: usize = std::env::var("PAD_BT_CAP").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(120);
        mixed_entry::<NA>(nguards as u8, rounds, cap);
        return;
    }
    if std::env::var("PAD_CROSS_CLASS").is_ok() {
        let rounds: usize = std::env::var("PAD_BT_ROUNDS").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(3);
        let cap: usize = std::env::var("PAD_BT_CAP").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(250);
        cross_class::<NA>(nguards as u8, rounds, cap);
        return;
    }
    if std::env::var("PAD_BISIM_TRANSPORT").is_ok() {
        let rounds: usize = std::env::var("PAD_BT_ROUNDS").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(3);
        let cap: usize = std::env::var("PAD_BT_CAP").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(400);
        bisim_transport::<NA>(nguards as u8, rounds, cap);
        return;
    }
    if std::env::var("PAD_CLOSURE").is_ok() {
        closure_test::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_CHAR2").is_ok() {
        char2::<NA>();
        return;
    }
    if std::env::var("PAD_COLLAPSE_BREAKS").is_ok() {
        collapse_breaks::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_WH_RESIDUAL").is_ok() {
        wh_residual::<NA>(nguards as u8);
        return;
    }
    if std::env::var("PAD_SYNTH").is_ok() {
        synth_check::<NA>();
        return;
    }
    if std::env::var("PAD_ORACLE_CHECK").is_ok() {
        oracle_check::<NA>();
        return;
    }
    if std::env::var("PAD_CHARACTERIZE").is_ok() {
        characterize::<NA>();
        return;
    }
    if std::env::var("PAD_NESTED_SANITY").is_ok() {
        nested_sanity::<NA>();
        return;
    }
    if std::env::var("PAD_CHECK_R201").is_ok() {
        check_r201::<NA>();
        return;
    }
    if std::env::var("PAD_SCC_CENSUS").is_ok() {
        scc_census::<NA>(nguards as u8);
        return;
    }

    // ---- closure
    //
    // Three things keep this from being hopeless at K = 6 (56M automata):
    //   * bucketing by core-state count, since `seq`/`ite` add and only k_x + k_y <= maxk
    //     can produce anything in range;
    //   * carrying the closure index *alongside* each automaton, so the innermost loop does
    //     no hashing at all — it used to pay a hash lookup per (x, y) pair;
    //   * filtering against `seen` inside the parallel section, so the round's output holds
    //     only genuinely new automata instead of every product.
    let mut seen = Interner::new();
    let mut list: Vec<Aut<NA>> = Vec::new();
    let mut prov: Vec<Prov> = Vec::new();
    let mut frontier: Vec<u32> = Vec::new();
    let mut cached = false;
    if let Ok(pth) = std::env::var("PAD_LOAD_CLOSURE") {
        if let Some((l, pv)) = load_closure::<NA>(&pth, maxk) {
            list = l;
            prov = pv;
            for (i, a) in list.iter().enumerate() { seen.insert(a, i as u32); }
            println!("CLOSED (cached from {pth}): {} automata", list.len());
            cached = true;
        } else {
            println!("  closure cache miss or mismatch at {pth}; rebuilding");
        }
    }
    if !cached {
    {
        let mut seed = |a: Aut<NA>| {
            if let Some(c) = canon(&a) {
                if !seen.contains(&c) {
                    seen.insert(&c, list.len() as u32);
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
        // Chunked rounds with a hard cap.  A single whole-frontier collect can allocate
        // tens of GB before dedup (NA=4, K=3) — fast enough to starve watchdogd and
        // panic the machine (panic-full-2026-08-18: "no checkins from watchdogd").
        // Chunking bounds peak memory to one chunk's candidates and lets the cap abort
        // cleanly between chunks.
        let cap: usize = std::env::var("PAD_MAXLIST").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);
        let mut fresh: Vec<u32> = Vec::new();
        for chunk in frontier.chunks(50_000) {
        let seen_ref = &seen;
        let list_ref = &list;
        let produced: Vec<(Aut<NA>, Prov)> = chunk
            .par_chunks(512)
            .flat_map_iter(|xs| {
                let mut local: FxSet<Aut<NA>> = FxSet::default();
                let mut out: Vec<(Aut<NA>, Prov)> = Vec::new();
                for &xi in xs {
                let x = &list_ref[xi as usize];
                {
                    let mut push = |a: Option<Aut<NA>>, pv: Prov| {
                        if let Some(a) = a {
                            if a.k as usize <= maxk {
                                if let Some(c) = canon(&a) {
                                    if !seen_ref.contains(&c) && local.insert(c) {
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
                            // `ite g y x` is the same automaton as `ite (!g) x y`: the guards
                            // are complementary and `Aut` resolves transitions per atom, so
                            // branch order carries no information.  Since `g` ranges over ALL
                            // masks, the swapped form is already generated at `!g` — computing
                            // it again doubled the `ite` work in the closure's inner loop, and
                            // the closure is what dominates the run.
                            for g in 0..nguards {
                                push(a_ite(g, x, y), Prov::Ite(g, xi, yi));
                            }
                        }
                    }
                }
                }
                out
            })
            .collect();
        for (a, pv) in produced {
            if !seen.contains(&a) {
                seen.insert(&a, list.len() as u32);
                fresh.push(list.len() as u32);
                list.push(a);
                prov.push(pv);
            }
        }
        if list.len() > cap {
            println!("  ABORT: closure exceeded PAD_MAXLIST={cap} at round {round} ({} automata)",
                list.len());
            std::process::exit(2);
        }
        }
        println!("  round {round}: {} automata (+{})", list.len(), fresh.len());
        frontier = fresh;
    }
    println!("CLOSED: {} fully reachable Thompson automata with <= {maxk} core states", list.len());
    if let Ok(pth) = std::env::var("PAD_SAVE_CLOSURE") {
        save_closure::<NA>(&pth, maxk, &list, &prov);
        println!("  closure saved to {pth}");
    }
    }
    phase("closure", &mut mark);
    {
        // Sanity for the predicate: a structured program's flow graph must be reducible.
        // If any syntax-generated automaton is irreducible, the test is wrong, not the theory.
        let bad = list.par_iter().filter(|a| !reducible(a)).count();
        println!("  irreducible Thompson automata (must be 0): {bad}");
        let bh = list.par_iter().filter(|a| !backedge_halt_disjoint(a)).count();
        // NOT an assertion: 342 derived the real disjointness condition and found it
        // genuinely fails for some automata, so a "must be 0" label here was wrong.
        println!("  Thompson automata failing backedge/halt disjointness: {bh} \
                  (a measurement, not a gate — see 342)");
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

    if std::env::var("PAD_ATTACK").is_ok() {
        attack_residue::<NA>(&list, &seen);
        return;
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
                Some(c) => (i, j, true, seen.contains(&c)),
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
                Some(c) => (i, j, p.k, true, seen.contains(&c)),
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
        // DOES THE canon-REJECTS-NON-TRIM BUG REACH THE MAIN CONJUNCT?  The conjunct is the
        // pullback LISTED ON ITS REACHABLE STATES, so trimming is the intended semantics, not a
        // relaxation — and `unshare_rec` bails at `canon(p)?`, so a non-trim pullback stalls.
        {
            let (mut ntrim, mut shrank, mut tot) = (0usize, 0usize, 0usize);
            for r in pb.iter() {
                if let Some(q) = pullback(&list[r.0], &list[r.1]) {
                    tot += 1;
                    if canon(&q).is_none() { ntrim += 1; }
                    if let Some(t) = trim_canon(&q) { if t.k < q.k { shrank += 1; } }
                }
            }
            let pcx = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
            println!("  [diag] pullbacks: {tot}, canon-rejected (non-trim) {ntrim} ({:.1}%), shrink under trim {shrank}",
                pcx(ntrim, tot));
        }
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
    if std::env::var("PAD_PULLTABLE").is_ok() {
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
    if std::env::var("PAD_MECH").is_ok() {
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
            let mut lneg = 0usize;
            let mut pneg = 0usize;
            let mut sneg = 0usize;
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
                if !llee(&c) { lneg += 1; }
                if !peelable(&c) { pneg += 1; }
                if !symbolic_eliminable(&c) { sneg += 1; }
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
            // Validate the NECESSARY condition: every pool automaton is Thompson, so every
            // one of them must satisfy it.  A necessary condition can only reject, which is
            // the useful direction — a candidate cover it rejects is definitely not Thompson.
            {
                let mut ok = 0usize; let mut n = 0usize;
                let step2 = (list.len() / 20000).max(1);
                for (i, a) in list.iter().enumerate() {
                    if i % step2 != 0 { continue; }
                    n += 1;
                    if orbit_stable(a) { ok += 1; }
                }
                let mut eok = 0usize; let mut en = 0usize;
                for (i, a) in list.iter().enumerate() {
                    if i % step2 != 0 { continue; }
                    en += 1;
                    if orbit_entry_halt_disjoint(a) { eok += 1; }
                }
                let mut ero = 0usize; let mut ern = 0usize;
                for p in uncovered.iter().take(300) { ern += 1; if orbit_entry_halt_disjoint(p) { ero += 1; } }
                let mut lp = 0usize; let mut ln = 0usize;
                for (i, a) in list.iter().enumerate() {
                    if i % step2 != 0 { continue; }
                    ln += 1;
                    if llee(a) { lp += 1; }
                }
                let (mut lr, mut lrn) = (0usize, 0usize);
                for p in uncovered.iter().take(300) { lrn += 1; if llee(p) { lr += 1; } }
                let mut pk = 0usize; let mut pn = 0usize;
                for (i, a) in list.iter().enumerate() {
                    if i % step2 != 0 { continue; }
                    pn += 1;
                    if peelable(a) { pk += 1; }
                }
                let (mut pr, mut prn) = (0usize, 0usize);
                for p in uncovered.iter().take(300) { prn += 1; if peelable(p) { pr += 1; } }
                let mut sk = 0usize; let mut sn = 0usize;
                for (i, a) in list.iter().enumerate() {
                    if i % step2 != 0 { continue; }
                    sn += 1;
                    if symbolic_eliminable(a) { sk += 1; }
                }
                let (mut sr, mut srn) = (0usize, 0usize);
                for p in uncovered.iter().take(300) { srn += 1; if symbolic_eliminable(p) { sr += 1; } }
                {
                    // THE THESIS ROUTE'S OBLIGATION, measured directly: does the bisimulation
                    // quotient of the SUM `Me + Mf` have a solution?  That is what
                    // `uniform_sum_quotient_solution_reductionBA` consumes, and it is a
                    // different object from the pullback this programme has been covering.
                    let mut good = 0usize; let mut tot = 0usize; let mut toobig = 0usize;
                    // This block runs BEFORE the per-pair precompute, so it cannot reuse it;
                    // parallelise instead.  The sums are independent.
                    let sums: Vec<Option<Aut<NA>>> = crux.iter()
                        .map(|&(i, j)| sum_core(&list[i], &list[j])).collect();
                    toobig += sums.iter().filter(|s| s.is_none()).count();
                    tot += sums.iter().filter(|s| s.is_some()).count();
                    good += sums.par_iter().filter(|s| match s {
                        Some(su) => symbolic_eliminable(su),
                        None => false,
                    }).count();
                {
                    // THE DECISIVE SOUNDNESS TEST.  The Figure 3 automaton of Smolka et al.
                    // has a behaviour NO GKAT expression denotes (`fig3_inexpressible`, proved
                    // in GkatInexpressibilityProofs).  By `sem_solves_autLang` a solution
                    // would yield an expression denoting exactly that behaviour, so Figure 3's
                    // system HAS NO SOLUTION and any sound procedure must reject it.
                    // v0 halts on ¬b and steps to v1 on b-atoms; v1 halts on b and steps to v0
                    // on ¬b-atoms.  Atom 0 = b, atom 1 = ¬b.
                    let mut st = [[0u8; NA]; MAXK];
                    st[0][0] = 2; st[1][1] = 1;
                    let mut hl = [0u8; MAXK];
                    hl[0] = 2; hl[1] = 1;
                    let mut it3 = [0u8; NA];
                    it3[0] = 1;
                    let f3 = Aut::<NA> { k: 2, it: it3, ih: 0, st, hl };
                    {
                    // THE SOUNDNESS CONTROL, as a POPULATION rather than one instance.
                    // The nesting coequation is an IFF: a GKAT automaton's states behave like
                    // GKAT programs exactly when it lies in the covariety.  A solution makes
                    // every state's behaviour expressible (`sem_solves_autLang`), so a
                    // NON-NESTED automaton provably has NO SOLUTION.  Every sound procedure
                    // must reject all of them; the rejection rate IS the soundness measure.
                    let mut rng: u64 = 0xD1B54A32D192ED03;
                    let mut rnd = move || { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng };
                    let (mut n, mut rs, mut rp, mut rl) = (0usize, 0usize, 0usize, 0usize);
                    let mut sample: Vec<Aut<NA>> = Vec::new();
                    let mut tried = 0usize;
                    let ncap = if NA > 2 { 500 } else { 5000 };
                    while n < ncap && tried < 4000000 {
                        tried += 1;
                        let kk = 4 + (rnd() % 5) as usize;
                        let mut st = [[0u8; NA]; MAXK];
                        let mut hl = [0u8; MAXK];
                        // WELL-FORMEDNESS.  A GKAT automaton state either halts at an atom
                        // or steps at it, never both — `haltStepDisjoint`.  The first version
                        // of this control generated states doing both, which are not GKAT
                        // automata at all, so "must be rejected" was meaningless for them and
                        // the soundness figure was measured against a contaminated population.
                        for x in 0..kk {
                            hl[x] = 0;
                            for y in 0..NA {
                                match rnd() % 3 {
                                    0 => { hl[x] |= 1 << y; st[x][y] = 0; }
                                    1 => { st[x][y] = 0; }
                                    _ => {
                                        let r = 1 + rnd() % (kk as u64);
                                        st[x][y] = r as u8;
                                    }
                                }
                            }
                        }
                        let mut it0 = [0u8; NA];
                        for y in 0..NA { it0[y] = (rnd() % ((kk + 1) as u64)) as u8; }
                        let ra = Aut::<NA> { k: kk as u8, it: it0, ih: (rnd() % 4) as u8, st, hl };
                        let ra = match canon(&ra) { Some(c) => c, None => continue };
                        if nested(&ra) { continue; }          // keep only the must-reject ones
                        n += 1;
                        sample.push(ra);
                    }
                    // The three procedures are the cost here — generation is cheap, and the
                    // profile put this whole block at 181s of a ~216s measured run.  They are
                    // independent per sample, so run them in parallel.
                    let tallies: (usize, usize, usize) = sample
                        .par_iter()
                        .map(|ra| (!symbolic_eliminable(ra) as usize,
                                   !peelable(ra) as usize,
                                   !llee(ra) as usize))
                        .reduce(|| (0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2));
                    rs += tallies.0; rp += tallies.1; rl += tallies.2;
                    // THE DISCRIMINATOR.  The control above keeps only NON-nested automata and
                    // measures REJECTION — it tests soundness against semantic unsolvability.
                    // The complement decides a different question: does `symbolic_eliminable`
                    // track SOLVABILITY or DERIVABILITY?  Nested automata are exactly the
                    // solvable ones.  If elim2 accepts essentially all of them it is measuring
                    // solvability, which the covariety gives for free; if it rejects a real
                    // fraction it is stricter, and may track derivability.
                    {
                        let mut rng4: u64 = 0x9E3779B97F4A7C15;
                        let mut rnd4 = move || { rng4 ^= rng4 << 13; rng4 ^= rng4 >> 7; rng4 ^= rng4 << 17; rng4 };
                        let mut pos: Vec<Aut<NA>> = Vec::new();
                        let mut tried4 = 0usize;
                        let pcap = if NA > 2 { 500 } else { 5000 };
                        while pos.len() < pcap && tried4 < 4000000 {
                            tried4 += 1;
                            let kk = 4 + (rnd4() % 5) as usize;
                            let mut st = [[0u8; NA]; MAXK];
                            let mut hl = [0u8; MAXK];
                            for x in 0..kk {
                                for y in 0..NA {
                                    if rnd4() % 3 == 0 { hl[x] |= 1 << y; }
                                    else if rnd4() % 2 == 0 { st[x][y] = 1 + (rnd4() % kk as u64) as u8; }
                                }
                            }
                            let mut it0 = [0u8; NA];
                            for y in 0..NA { it0[y] = 1 + (rnd4() % kk as u64) as u8; }
                            let ra = Aut::<NA> { k: kk as u8, it: it0, ih: (rnd4() % 4) as u8, st, hl };
                            let ra = match canon(&ra) { Some(c) => c, None => continue };
                            if !nested(&ra) { continue; }      // keep only the SOLVABLE ones
                            pos.push(ra);
                        }
                        let acc = pos.par_iter().filter(|ra| symbolic_eliminable(ra)).count();
                        let pc9 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                        println!("    DISCRIMINATOR: elim2 accepts {acc} / {} nested (solvable) automata ({:.1}%)",
                            pos.len(), pc9(acc, pos.len()));
                    }
                    // print one unsound acceptance: non-nested (hence no solution) yet llee-accepted
                    {
                        let mut rng3: u64 = 0xD1B54A32D192ED03;
                        let mut rnd3 = move || { rng3 ^= rng3 << 13; rng3 ^= rng3 >> 7; rng3 ^= rng3 << 17; rng3 };
                        let mut shown = 0;
                        let mut t2 = 0usize;
                        // At NA=2 the hunt finds its unsound accepts within thousands of
                        // tries; at NA>2 llee has produced none, and grinding 4M random
                        // automata through llee (all memo misses) costs hours.
                        let t2cap = if NA > 2 { 100_000 } else { 4_000_000 };
                        while shown < 2 && t2 < t2cap {
                            t2 += 1;
                            let kk = 4 + (rnd3() % 5) as usize;
                            let mut st = [[0u8; NA]; MAXK];
                            let mut hl = [0u8; MAXK];
                            for x in 0..kk {
                                hl[x] = 0;
                                for y in 0..NA {
                                    match rnd3() % 3 {
                                        0 => { hl[x] |= 1 << y; st[x][y] = 0; }
                                        1 => { st[x][y] = 0; }
                                        _ => {
                                            let r = 1 + rnd3() % (kk as u64);
                                            st[x][y] = r as u8;
                                        }
                                    }
                                }
                            }
                            let mut it0 = [0u8; NA];
                            for y in 0..NA { it0[y] = (rnd3() % ((kk + 1) as u64)) as u8; }
                            let ra = Aut::<NA> { k: kk as u8, it: it0, ih: (rnd3() % 4) as u8, st, hl };
                            let ra = match canon(&ra) { Some(c) => c, None => continue };
                            if nested(&ra) || !llee(&ra) { continue; }
                            shown += 1;
                            println!("    UNSOUND ACCEPT k={} it={:?} ih={}", ra.k, &ra.it[..NA], ra.ih);
                            for i in 0..ra.k as usize {
                                println!("      s{i}: st={:?} hl={:b}", &ra.st[i][..NA], ra.hl[i]);
                            }
                        }
                    }
                    println!("  SOUNDNESS CONTROL — non-nested automata (NO solution exists):");
                    println!("    symbolic elimination rejects : {rs} / {n}   (must be all)");
                    println!("    peelable rejects             : {rp} / {n}   (must be all)");
                    println!("    llee rejects                 : {rl} / {n}   (must be all)");
                }
                println!("  FIGURE 3 (inexpressible — every sound test MUST reject):");
                    println!("    symbolic elimination : {}", symbolic_eliminable(&f3));
                    println!("    peelable             : {}", peelable(&f3));
                    println!("    llee                 : {}", llee(&f3));
                }
                if std::env::var("PAD_LLEE_VALIDATE").is_ok() {
                {
                    // THE DECISIVE MEASUREMENT.  Grabmayer: the image of the process
                    // interpretation is NOT closed under bisimulation collapse, so quotienting
                    // can DESTROY LLEE.  This route quotients the sum and hopes the result is
                    // LLEE — so whether that ever fails is the question the route lives on.
                    let mut good = 0usize; let mut tot = 0usize;
                    let mut arb = 0usize; let mut arbn = 0usize;
                    let mut rng2: u64 = 0x2545F4914F6CDD1D;
                    let mut rnd2 = move || { rng2 ^= rng2 << 13; rng2 ^= rng2 >> 7; rng2 ^= rng2 << 17; rng2 };
                    for &(i, j) in crux.iter() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            tot += 1;
                            let (blk, nb) = bisim_blocks(&su);
                            if let Some(q) = quotient_by(&su, &blk, nb) {
                                if llee(&q) { good += 1; }
                            }
                        }
                        let a = (rnd2() as usize) % list.len();
                        let b = (rnd2() as usize) % list.len();
                        if let Some(su) = sum_core(&list[a], &list[b]) {
                            arbn += 1;
                            let (blk, nb) = bisim_blocks(&su);
                            if let Some(q) = quotient_by(&su, &blk, nb) {
                                if llee(&q) { arb += 1; }
                            }
                        }
                    }
                    println!("  IS THE SUM-QUOTIENT LLEE?  (the route lives on this)");
                    println!("    equivalent pairs : {good} / {tot}");
                    println!("    CONTROL arbitrary: {arb} / {arbn}");
                }
                }
                {
                    // FULL COLLAPSE vs MINIMAL INTERMEDIATE QUOTIENT, on the same pairs.
                    let (mut mn, mut mtot, mut mfail) = (0usize, 0usize, 0usize);
                    for &(i, j) in crux.iter() {
                        match min_congruence(&list[i], &list[j]) {
                            None => { mfail += 1; }
                            Some(q) => { mtot += 1; if symbolic_eliminable_raw(&q) { mn += 1; } }
                        }
                    }
                    let (mut fn_, mut ftot2) = (0usize, 0usize);
                    for &(i, j) in crux.iter() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            let (blk, nb) = bisim_blocks(&su);
                            if let Some(q) = quotient_by(&su, &blk, nb) {
                                ftot2 += 1;
                                if symbolic_eliminable_raw(&q) { fn_ += 1; }
                            }
                        }
                    }
                    println!("  INTERMEDIATE vs TOP OF THE LATTICE (no pre-collapse in either):");
                    println!("    minimal congruence  : {mn} / {mtot}   (not a congruence: {mfail})");
                    println!("    full collapse       : {fn_} / {ftot2}");
                }
                {
                    phase("oracle: pre", &mut mark);
                    // PRECOMPUTED PER-PAIR FACTS.  The measurement section iterated `crux`
                    // twenty times and recomputed `symbolic_eliminable` on fourteen of those
                    // passes — a backtracking search with a 2M-node budget, redone per block.
                    // Computing it once in parallel makes the whole section one pass over the
                    // pairs instead of fourteen.
                    let facts: Vec<(bool, Option<Aut<NA>>)> = crux
                        .par_iter()
                        .map(|&(i, j)| match sum_core(&list[i], &list[j]) {
                            None => (false, None),
                            Some(su) => {
                                let e = symbolic_eliminable(&su);
                                let (blk, nb0) = bisim_blocks(&su);
                                let q = quotient_by(&su, &blk, nb0).and_then(|q| canon(&q));
                                (e, q)
                            }
                        })
                        .collect();

                    // THE UNSOLVED QUOTIENTS, characterised against a same-population base rate.
                    let (mut fh, mut fn_, mut oh2, mut on2) = (0usize, 0usize, 0usize, 0usize);
                    let (mut fsz, mut osz) = (0usize, 0usize);
                    let mut shown = 0;
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            let (blk, nb) = bisim_blocks(&su);
                            let q = match quotient_by(&su, &blk, nb) { Some(q) => q, None => continue };
                            let th = two_halt_cycle(&q).is_some();
                            if facts[ci].0 {
                                on2 += 1; osz += nb; if th { oh2 += 1; }
                            } else {
                                fn_ += 1; fsz += nb; if th { fh += 1; }
                                if shown < 2 {
                                    shown += 1;
                                    println!("    FAIL quotient k={} it={:?}", q.k, &q.it[..NA]);
                                    for t in 0..q.k as usize {
                                        println!("      s{t}: st={:?} hl={:b}", &q.st[t][..NA], q.hl[t]);
                                    }
                                }
                            }
                        }
                    }
                    let pc2 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                    // THE DEFINITION QUANTIFIES OVER SOME QUOTIENT, not the full collapse.
                    // The lattice of bisimulations sits between the identity and the largest;
                    // testing only its top understates what the hypothesis allows.  Take the
                    // union over the two endpoints already computed.
                    let (mut anyq, mut anyn) = (0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            anyn += 1;
                            let top = facts[ci].0;
                            let bot = match min_congruence(&list[i], &list[j]) {
                                Some(q) => symbolic_eliminable_raw(&q),
                                None => false,
                            };
                            if top || bot { anyq += 1; }
                        }
                    }
                    phase("facts precompute", &mut mark);
                    println!("  SOLVABLE AT EITHER END OF THE LATTICE (what the definition allows):");
                    println!("    top or bottom : {anyq} / {anyn}");
                    let (mut latq, mut latn) = (0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            latn += 1;
                            if solvable_somewhere_in_lattice(&su, facts[ci].0,
                                list[i].k as usize + 1) { latq += 1; }
                        }
                    }
                    phase("lattice endpoints", &mut mark);
                    println!("  SOLVABLE ANYWHERE IN THE LATTICE:");
                    println!("    some congruence : {latq} / {latn}");
                    // VACUOUS AS IMPLEMENTED — 0/24 on the failures AND 0/9221 on the solved
                    // ones.  The rooted-quotient canonical forms simply never key into the
                    // pool, so this measures pool indexing rather than expressibility.  Kept
                    // with its base rate, because without the control the 0/24 would have read
                    // as evidence of inexpressibility and hence of a refutation.
                    //
                    // Original intent: a solution makes every state expressible; so if
                    // some state of a failing quotient has a behaviour no pool automaton has,
                    // that quotient is UNSOLVABLE and the live conjunct is refuted.  A negative
                    // is inconclusive — the pool is bounded — but a positive is not.
                    let (mut allexp, mut expn, mut nst) = (0usize, 0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            if facts[ci].0 { continue; }
                            let (blk, nb) = bisim_blocks(&su);
                            let q = match quotient_by(&su, &blk, nb) { Some(q) => q, None => continue };
                            expn += 1;
                            if nested(&q) { nst += 1; }
                            let mut ok = true;
                            for st0 in 0..q.k as usize {
                                let mut rooted = q;
                                for y in 0..NA { rooted.it[y] = (st0 + 1) as u8; }
                                rooted.ih = 0;
                                let c = match canon(&rooted) { Some(c) => c, None => { ok = false; break } };
                                if !by_beh.contains_key(&behaviour(&c)) { ok = false; break; }
                            }
                            if ok { allexp += 1; }
                        }
                    }
                    // THE BASE RATE.  Without it, "0/24 in the pool" measures pool coverage
                    // rather than expressibility.  Same check on quotients the procedure SOLVES,
                    // which therefore provably have all states expressible.
                    let (mut sexp, mut sexpn) = (0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            if !facts[ci].0 { continue; }
                            let (blk, nb) = bisim_blocks(&su);
                            let q = match quotient_by(&su, &blk, nb) { Some(q) => q, None => continue };
                            sexpn += 1;
                            let mut ok = true;
                            for st0 in 0..q.k as usize {
                                let mut rooted = q;
                                for y in 0..NA { rooted.it[y] = (st0 + 1) as u8; }
                                rooted.ih = 0;
                                let c = match canon(&rooted) { Some(c) => c, None => { ok = false; break } };
                                if !by_beh.contains_key(&behaviour(&c)) { ok = false; break; }
                            }
                            if ok { sexp += 1; }
                        }
                    }
                    phase("lattice eliminable sweep", &mut mark);
                    // DISTANCE FROM GKAT: fewest KA-only steps that make it solvable.
                    let mut dist = [0usize; 6];
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            if facts[ci].0 { continue; }
                            let (blk, nb0) = bisim_blocks(&su);
                            let q = match quotient_by(&su, &blk, nb0) { Some(q) => q, None => continue };
                            let kq = q.k as usize;
                            let mut vv = [[[0u16; NA]; NA]; MAXK];
                            let mut hh = [[[false; NA]; NA]; MAXK];
                            for x in 0..kq {
                                for y in 0..NA {
                                    if q.st[x][y] != 0 {
                                        let t = (q.st[x][y] - 1) as usize;
                                        for beta in 0..NA { vv[x][y][beta] |= 1 << t; }
                                    } else if q.hl[x] & (1 << y) != 0 { hh[x][y][y] = true; }
                                }
                            }
                            let mut found = 5usize;
                            for d in 1..5 {
                                let mut b2 = 200000usize;
                                if elim_ka::<NA>(&mut vv.clone(), &mut hh.clone(),
                                    (1u16 << kq) - 1, kq, &mut b2, d) { found = d; break; }
                            }
                            dist[found] += 1;
                        }
                    }
                    phase("distance from GKAT", &mut mark);
                    // IS THE QUOTIENT ITSELF A THOMPSON AUTOMATON?  If it is, it provably has
                    // a solution (the standard one), so the KA step is the PROCEDURE's need,
                    // not the system's — and "distance 1" is incompleteness, not obstruction.
                    let (mut fpool, mut fpn, mut spool, mut spn) = (0usize, 0usize, 0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            let (blk, nb0) = bisim_blocks(&su);
                            let q = match quotient_by(&su, &blk, nb0) { Some(q) => q, None => continue };
                            let inpool = canon(&q).map(|c| seen.contains(&c)).unwrap_or(false);
                            if facts[ci].0 { spn += 1; if inpool { spool += 1; } }
                            else { fpn += 1; if inpool { fpool += 1; } }
                        }
                    }
                    let pc3 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                    {
                        // WORKED BY HAND — why elimination cannot reach these, in principle.
                        //
                        // A witness this prints, with b = atom 0:
                        //     s0: b -> s1, ¬b -> reject      s1: b -> s1, ¬b -> s2
                        //     s2: b -> s3, ¬b -> HALT        s3: b -> s1, ¬b -> HALT
                        // as an equation system:
                        //     s(s0) ≡ p0·s(s1) +_b 0
                        //     s(s1) ≡ p1·s(s1) +_b q1·s(s2)
                        //     s(s2) ≡ p2·s(s3) +_b 1
                        //     s(s3) ≡ p3·s(s1) +_b 1
                        //
                        // Eliminating s3 then s2 then s1 gives
                        //     s(s1) ≡ p1·s(s1) +_b q1·(p2·(p3·s(s1) +_b 1) +_b 1)
                        // and eliminating s1 first gives
                        //     s(s2) ≡ p2·(p3·p1^(b)·q1·s(s2) +_b 1) +_b 1
                        // Both end at `X ≡ p2·(A·X +_b 1) +_b 1`: X nested under a prefix with
                        // the other branch a bare `1`.  Isolating X needs p2 distributed over
                        // +_b, and the guard is evaluated AFTER p2 runs — `left_distrib_fails`.
                        //
                        // This automaton is IN THE POOL, so it carries the standard solution.
                        // The system is solvable and elimination cannot solve it: the standard
                        // solution is read off the SYNTAX, assigning each state "the rest of the
                        // program", which the equation system does not carry.  So elimination
                        // cannot replace structure recovery on the instances that matter, and
                        // every purely-elimination fix here has been null for that reason —
                        // copies 0/462, flags 0/462, nested entries 0, atom-indexed leaves 0.
                        //
                        // One quotient that IS Thompson yet defeats elimination: a reproducible
                        // witness of the missing move, since such a system provably has the
                        // standard solution and the failure is therefore procedural.
                        let mut shown = 0;
                        for (ci, &(i, j)) in crux.iter().enumerate() {
                            if shown >= 2 { break; }
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                if facts[ci].0 { continue; }
                                let (blk, nb0) = bisim_blocks(&su);
                                let q = match quotient_by(&su, &blk, nb0) { Some(q) => q, None => continue };
                                let c = match canon(&q) { Some(c) => c, None => continue };
                                if !seen.contains(&c) { continue; }
                                shown += 1;
                                let widx = *seen.get(&c).unwrap();
                                println!("    IN-POOL YET UNSOLVED  k={} it={:?} ih={}", c.k, &c.it[..NA], c.ih);
                                println!("      EXPRESSION: {}", expr_of(&list, &prov, widx, 14));
                                for t in 0..c.k as usize {
                                    println!("      s{t}: st={:?} hl={:b}", &c.st[t][..NA], c.hl[t]);
                                }
                            }
                        }
                    }
                    // THE COMBINED TEST.  Elimination is sound but incomplete; being in the
                    // pool is a DIFFERENT sound witness — a pool member is Thompson-generated,
                    // so it carries the standard solution outright.  Their disjunction is still
                    // sound and strictly stronger than either.
                    let (mut comb, mut combn) = (0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            combn += 1;
                            if facts[ci].0 { comb += 1; continue; }
                            let (blk, nb0) = bisim_blocks(&su);
                            if let Some(q) = quotient_by(&su, &blk, nb0) {
                                if canon(&q).map(|c| seen.contains(&c)).unwrap_or(false) {
                                    comb += 1;
                                }
                            }
                        }
                    }
                    // If a Thompson automaton has at most `maxk` states then it IS in the
                    // pool: `seq`/`ite` components are strictly smaller than the result and
                    // `wh` preserves size, so the closure reaches it by induction.  So for the
                    // unknown quotients, size decides whether "not in the pool" is informative.
                    let mut szhist = [0usize; 12];
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            if facts[ci].0 { continue; }
                            let (blk, nb0) = bisim_blocks(&su);
                            if let Some(q) = quotient_by(&su, &blk, nb0) {
                                if canon(&q).map(|c| seen.contains(&c)).unwrap_or(false) { continue; }
                                let kk = canon(&q).map(|c| c.k as usize).unwrap_or(0);
                                if kk < 12 { szhist[kk] += 1; }
                            }
                        }
                    }
                    {
                        // Exhibit the residue.  These are the objects the whole programme now
                        // reduces to: 3 states, nested, not eliminable, not Thompson-generated.
                        let mut shown = 0;
                        let mut distinct: Vec<Aut<NA>> = Vec::new();
                        for (ci, &(i, j)) in crux.iter().enumerate() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                if facts[ci].0 { continue; }
                                let (blk, nb0) = bisim_blocks(&su);
                                if let Some(q) = quotient_by(&su, &blk, nb0) {
                                    if let Some(c) = canon(&q) {
                                        if seen.contains(&c) { continue; }
                                        if distinct.iter().any(|d| *d == c) { continue; }
                                        distinct.push(c);
                                        if shown < 4 {
                                            shown += 1;
                                            println!("    UNKNOWN #{shown}  k={} it={:?} ih={}",
                                                c.k, &c.it[..NA], c.ih);
                                            for t in 0..c.k as usize {
                                                println!("      s{t}: st={:?} hl={:b}",
                                                    &c.st[t][..NA], c.hl[t]);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        println!("    distinct unknown quotients: {}", distinct.len());
                        // IS EACH UNKNOWN THE BISIMULATION COLLAPSE OF A POOL AUTOMATON?
                        // The pool is Thompson-generated, and `canon` only trims — it does not
                        // merge bisimilar states — so a collapse of a pool member need not be
                        // in the pool.  If an unknown IS such a collapse, its behaviour is
                        // expressible even though the automaton is not Thompson.
                        let mut hit = 0usize;
                        for u in distinct.iter() {
                            let mut found = false;
                            for a in list.iter() {
                                if a.k < u.k { continue; }
                                let (blk, nb1) = bisim_blocks(a);
                                if nb1 != u.k as usize { continue; }
                                if let Some(q) = quotient_by(a, &blk, nb1) {
                                    if let Some(c) = canon(&q) { if c == *u { found = true; break; } }
                                }
                            }
                            if found { hit += 1; }
                        }
                        println!("    …of which are a COLLAPSE of a pool automaton: {hit} / {}",
                            distinct.len());
                    }
                    {
                        // PERIOD SIGNATURE, controlled for SIZE.  The residue is 3-state and
                        // the solved population averages 2.32, so an uncontrolled comparison
                        // would just be measuring size again.  Compare only 3-state quotients.
                        let mut fper = [0usize; 8];
                        let mut sper = [0usize; 8];
                        let (mut fn3, mut sn3) = (0usize, 0usize);
                        for (ci, &(i, j)) in crux.iter().enumerate() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                let elim = facts[ci].0;
                                let (blk, nb0) = bisim_blocks(&su);
                                let q = match quotient_by(&su, &blk, nb0) { Some(q) => q, None => continue };
                                let c = match canon(&q) { Some(c) => c, None => continue };
                                if c.k != 3 { continue; }
                                let ps = scc_periods(&c);
                                let m = ps.iter().copied().max().unwrap_or(0) as usize;
                                if elim { sn3 += 1; if m < 8 { sper[m] += 1; } }
                                else { fn3 += 1; if m < 8 { fper[m] += 1; } }
                            }
                        }
                        // Does the quotient's period come from an LCM the sources force?
                        // A cover must respect periods, and `cyc` is a degree-k cyclic cover,
                        // so a common target's period is lcm(period e, period f).  If the
                        // residue is where that lcm exceeds what the moves reach, the period
                        // signal has a mechanism rather than being a correlation.
                        let (mut flcm, mut fpn2, mut slcm, mut spn2) = (0usize, 0usize, 0usize, 0usize);
                        for (ci, &(i, j)) in crux.iter().enumerate() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                let elim = facts[ci].0;
                                let (blk, nb0) = bisim_blocks(&su);
                                let q = match quotient_by(&su, &blk, nb0) { Some(q) => q, None => continue };
                                let c = match canon(&q) { Some(c) => c, None => continue };
                                if c.k != 3 { continue; }
                                let pe = scc_periods(&list[i]).iter().copied().max().unwrap_or(1).max(1);
                                let pf = scc_periods(&list[j]).iter().copied().max().unwrap_or(1).max(1);
                                fn gcd(a: u32, b: u32) -> u32 { if b == 0 { a } else { gcd(b, a % b) } }
                                let coprime = gcd(pe, pf) == 1 && pe > 1 && pf > 1;
                                if elim { spn2 += 1; if coprime { slcm += 1; } }
                                else { fpn2 += 1; if coprime { flcm += 1; } }
                            }
                        }
                        let pc4 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                        {
                            // DIRECT CHECK of the closure argument.  Unknown #1 can be written
                            // by hand as `wh ¬a (p ; ite a 1 (p;p))`.  If that is right it is
                            // Thompson with 3 states, so the closure MUST contain it — and if
                            // it does not, the "not in pool ⟹ not Thompson" inference is wrong.
                            let pp = a_seq(&a_act::<NA>(), &a_act::<NA>());
                            if let Some(pp) = pp {
                                for g in 0..(1u8 << NA) {
                                    for g2 in 0..(1u8 << NA) {
                                        let inner = a_ite(g2, &a_test::<NA>(3), &pp);
                                        if let Some(inner) = inner {
                                            if let Some(body) = a_seq(&a_act::<NA>(), &inner) {
                                                let w = a_wh(g, &body);
                                                if let Some(c) = canon(&w) {
                                                    if c.k == 3 {
                                                        let inp = seen.contains(&c);
                                                        println!("    HAND EXPR g={g} g2={g2} -> k=3 it={:?} ih={} inpool={}",
                                                            &c.it[..NA], c.ih, inp);
                                                        for t in 0..3 {
                                                            println!("        s{t}: st={:?} hl={:b}", &c.st[t][..NA], c.hl[t]);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        println!("  DO THE SOURCES HAVE COPRIME PERIODS?  (3-state, size-controlled)");
                        println!("    unsolved : {flcm} / {fpn2}  ({:.1}%)", pc4(flcm, fpn2));
                        println!("    solved   : {slcm} / {spn2}  ({:.1}%)", pc4(slcm, spn2));
                        println!("  PERIOD SIGNATURE, 3-STATE QUOTIENTS ONLY (size-controlled):");
                        println!("    unsolved (n={fn3}) by max period : {:?}", &fper[..6]);
                        println!("    solved   (n={sn3}) by max period : {:?}", &sper[..6]);
                    }
                    println!("  THE UNKNOWN QUOTIENTS, BY SIZE (maxk = {maxk}):");
                    for kk in 0..12 { if szhist[kk] > 0 { println!("    {kk} states : {}", szhist[kk]); } }
                    let (mut lat2, mut lat2n) = (0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            lat2n += 1;
                            // `solvable_somewhere_in_lattice` was already measured at 9221
                            // with no gain, so re-running it here only duplicates the expensive
                            // 2^12 elimination sweep.  The new question is whether a FINER
                            // quotient is Thompson.
                            if facts[ci].0 || thompson_somewhere_in_lattice(&su, &seen) { lat2 += 1; }
                        }
                    }
                    phase("thompson-in-lattice sweep", &mut mark);
                    // HOW MUCH IS ALREADY SETTLED BY THE LITERATURE?  Skip-free GKAT is
                    // complete without UA, and "proofs of equivalence in skip-free GKAT
                    // transfer without any loss to full GKAT" — so a pair whose BOTH sides are
                    // skip-free needs nothing from this programme, and no sound model can
                    // separate it.  `halt_in_cycle` is the automaton-level reading of an
                    // assert in a loop body.
                    let (mut sf, mut sfn, mut nonsf_ok, mut nonsf) = (0usize, 0usize, 0usize, 0usize);
                    for (ci, &(i, j)) in crux.iter().enumerate() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            sfn += 1;
                            let skipfree = !halt_in_cycle(&list[i]) && !halt_in_cycle(&list[j]);
                            if skipfree { sf += 1; continue; }
                            nonsf += 1;
                            if facts[ci].0 || thompson_somewhere_in_lattice(&su, &seen) { nonsf_ok += 1; }
                        }
                    }
                    let pc5 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                    {
                        // THE EIGHT, AS PROGRAMS.  Both routes terminate here, so the actual
                        // expressions are worth having: a derivation for even one pair
                        // discharges it, and a separating model needs one of these to separate.
                        let mut shown = 0;
                        for (ci, &(i, j)) in crux.iter().enumerate() {
                            if shown >= 12 { break; }
                            if facts[ci].0 { continue; }
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                if thompson_somewhere_in_lattice(&su, &seen) { continue; }
                                shown += 1;
                                println!("    OPEN PAIR #{shown}");
                                println!("      e = {}", expr_of(&list, &prov, i as u32, 12));
                                println!("      f = {}", expr_of(&list, &prov, j as u32, 12));
                            }
                        }
                    }
                    // IS THE UNDECIDED CROSSING REAL?  `ua2_eliminated_of_decided` produces a
                    // guard-pullback witness exactly when a crossing guard is constant across
                    // atoms — an action may be followed by ANY atom, so a mixed guard is never
                    // predictable in advance.  If every state of every system we must solve is
                    // decided, chain_elim + decided witnesses + W3 already close the theorem.
                    let decided = |a: &Aut<NA>| -> (usize, usize) {
                        let (mut d, mut t) = (0usize, 0usize);
                        for sx in 0..a.k as usize {
                            let n = (0..NA).filter(|&i| a.st[sx][i] != 0).count();
                            t += 1;
                            if n == 0 || n == NA { d += 1; }
                        }
                        (d, t)
                    };
                    // dead exit: the state never halts — where it does not step, it rejects.
                    // `chain_elim_dead_exit` eliminates such a state whatever its guard does.
                    let elimable = |a: &Aut<NA>| -> (usize, usize, usize) {
                        let (mut d, mut u, mut t) = (0usize, 0usize, 0usize);
                        for sx in 0..a.k as usize {
                            let n = (0..NA).filter(|&i| a.st[sx][i] != 0).count();
                            let dec = n == 0 || n == NA;
                            let dead = a.hl[sx] == 0;
                            t += 1;
                            if dec { d += 1; }
                            if dec || dead { u += 1; }
                        }
                        (d, u, t)
                    };
                    let (mut ud, mut ut, mut uall, mut un) = (0usize, 0usize, 0usize, 0usize);
                    for &(i, j) in crux.iter() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            let (_, u, t) = elimable(&su);
                            ud += u; ut += t; un += 1;
                            if u == t { uall += 1; }
                        }
                    }
                    let (mut bu, mut bt2, mut bua, mut bn2) = (0usize, 0usize, 0usize, 0usize);
                    for a in list.iter().take(20000) {
                        let (_, u, t) = elimable(a);
                        bu += u; bt2 += t; bn2 += 1;
                        if u == t { bua += 1; }
                    }
                    let (mut dst, mut tst, mut dall, mut nall) = (0usize, 0usize, 0usize, 0usize);
                    for &(i, j) in crux.iter() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            let (d, t) = decided(&su);
                            dst += d; tst += t; nall += 1;
                            if d == t { dall += 1; }
                        }
                    }
                    // base rate on a population known to be fine: the pool itself
                    let (mut bd, mut bt, mut ba, mut bn) = (0usize, 0usize, 0usize, 0usize);
                    for a in list.iter().take(20000) {
                        let (d, t) = decided(a);
                        bd += d; bt += t; bn += 1;
                        if d == t { ba += 1; }
                    }
                    let pc6 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                    // UA-COUNTEREXAMPLE CANDIDATES.  Two solutions of one system are
                    // language-equivalent, so every UA counterexample is a crux pair; and a
                    // system with no cycle has trivially unique solutions.  So the candidate
                    // set is the crux pairs whose system has a cycle.
                    let has_cycle = |a: &Aut<NA>| -> bool {
                        let k = a.k as usize;
                        (0..k).any(|u| {
                            let mut seen = 0u32;
                            let mut stack: Vec<usize> = (0..NA)
                                .filter(|&i| a.st[u][i] != 0)
                                .map(|i| (a.st[u][i] - 1) as usize).collect();
                            while let Some(v) = stack.pop() {
                                if v == u { return true; }
                                if seen & (1 << v) != 0 { continue; }
                                seen |= 1 << v;
                                for i in 0..NA {
                                    if a.st[v][i] != 0 { stack.push((a.st[v][i] - 1) as usize); }
                                }
                            }
                            false
                        })
                    };
                    let (mut cyc_n, mut cyc_elim, mut tot_n) = (0usize, 0usize, 0usize);
                    for &(i, j) in crux.iter() {
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            tot_n += 1;
                            if has_cycle(&su) {
                                cyc_n += 1;
                                let (_, u, t) = elimable(&su);
                                if u == t { cyc_elim += 1; }
                            }
                        }
                    }
                    // IS THE RESIDUE AN OBSTRUCTION, OR JUST SEARCH REACH?
                    // `orbit_entry_halt_disjoint` is a NECESSARY condition for being a Thompson
                    // automaton, derived from the guard law rather than by inverting the
                    // construction: every orbit is a loop body `wh g B`, every edge into it is
                    // an entry conjoined with `g`, and orbit states carry halt guard `... ∧ ¬g`.
                    // So it can never reject a real Thompson automaton — which makes it a sound
                    // REFUTER, and a refuted quotient is provably out of reach rather than
                    // merely unfound.  Validate that claim on the pool before using it.
                    let refuted = |a: &Aut<NA>| -> bool { !orbit_entry_halt_disjoint(a) };
                    let mut false_refute = 0usize;
                    for (ai, a) in list.iter().take(20000).enumerate() {
                        if refuted(a) {
                            false_refute += 1;
                            if false_refute <= 2 {
                                println!("    WRONGLY REFUTED #{false_refute}: k={} ih={} it={:?}", a.k, a.ih, a.it);
                                for sx in 0..a.k as usize {
                                    println!("      s{sx}: hl={} st={:?}", a.hl[sx], &a.st[sx][..NA]);
                                }
                                println!("      orbits={:?} halt_disj={} entry_uniq={}",
                                    orbits(a), orbit_entry_halt_disjoint(a), orbit_entry_unique(a));
                                println!("      expr={}", expr_of(&list, &prov, ai as u32, 12));
                            }
                        }
                    }
                    println!("  THOMPSON REFUTER VALIDATION:");
                    println!("    pool automata wrongly refuted : {false_refute} / {} (must be 0)",
                        list.len().min(20000));
                    if false_refute == 0 {
                        let (mut all_ref, mut any_ref, mut nn) = (0usize, 0usize, 0usize);
                        for &(i, j) in crux.iter() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                nn += 1;
                                let ls = lattice_congruences(&su);
                                let mut all = true;
                                let mut any = false;
                                let mut nq = 0usize;
                                for cg in ls.iter() {
                                    if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                        nq += 1;
                                        if refuted(&q) { any = true; } else { all = false; }
                                    }
                                }
                                // NON-VACUITY: an empty lattice makes `all` true for free.
                                if nq == 0 { nn -= 1; continue; }
                                if all { all_ref += 1; }
                                if any { any_ref += 1; }
                            }
                        }
                        // POWER OF THE INSTRUMENT.  `0/4017` is only evidence if the refuter
                        // can detect the thing at all.  Calibrate on a population KNOWN to be
                        // non-Thompson: quotients small enough to decide against the pool
                        // (k <= K) whose canonical form is absent from it.
                        // the pool holds every Thompson automaton of an expression with <= K
                        // actions, and a Thompson automaton with k states comes from exactly k
                        // actions — so for k <= K, absence from the pool IS non-Thompson.
                        let poolk = list.iter().map(|a| a.k as usize).max().unwrap_or(0);
                        let (mut neg, mut neg_caught, mut pos_seen) = (0usize, 0usize, 0usize);
                        for &(i, j) in crux.iter() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                for cg in lattice_congruences(&su).iter() {
                                    if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                        if (q.k as usize) > poolk { continue; }
                                        let isT = canon(&q).map(|c| seen.contains(&c))
                                            .unwrap_or(false);
                                        if isT { pos_seen += 1; continue; }
                                        neg += 1;
                                        if refuted(&q) { neg_caught += 1; }
                                    }
                                }
                            }
                        }
                        // HOW LIVE IS THE ENGINEERING BLOCKER?  Pool membership DECIDES
                        // Thompson-ness for k <= K.  Only quotients larger than the pool need
                        // an oracle at all, so count them before building one.
                        let (mut big, mut small) = (0usize, 0usize);
                        let mut bigk = [0usize; MAXK + 1];
                        for &(i, j) in crux.iter() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                for cg in lattice_congruences(&su).iter() {
                                    if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                        if (q.k as usize) > poolk {
                                            big += 1;
                                            bigk[(q.k as usize).min(MAXK)] += 1;
                                        } else { small += 1; }
                                    }
                                }
                            }
                        }
                        println!("    BLOCKER LIVENESS: quotients needing an oracle (k > {poolk}) : {big} / {} ({:.1}%)",
                            big + small, pc6(big, big + small));
                        println!("           sizes above the pool: {:?}", &bigk[..]);
                        // VALIDATE THE STREAMER on the k=5 layer, where the pool is ground
                        // truth — and seed it only from k <= 4, so nothing is found trivially.
                        {
                            let mut by_k4: Vec<Vec<Aut<NA>>> = vec![Vec::new(); 5];
                            let mut by_k5: Vec<Vec<Aut<NA>>> = vec![Vec::new(); 6];
                            for a in list.iter() {
                                let kk = a.k as usize;
                                if kk <= 4 { by_k4[kk].push(*a); }
                                if kk <= 5 { by_k5[kk].push(*a); }
                            }
                            let t5: FxSet<Aut<NA>> = list.iter().filter(|a| a.k as usize == 5)
                                .filter_map(|a| canon(a)).collect();
                            let n5 = t5.len();
                            // DEPTH/COMPLETENESS CURVE, measured where ground truth exists.
                            // Storing the layer is what costs memory, so use the SMALLEST depth
                            // that is complete at k=5 and carry it up.  Positives stay sound at
                            // every depth; only completeness varies.
                            // The depth curve is settled (0: 68.2%, 1: 86.6%, 2: 100.0%) and
                            // costs 2.7M automata per depth, so it is off unless asked for.
                            let mut best_depth = 2usize;
                            let redo = std::env::var("PAD_STREAMER").is_ok();
                            for d in 0..=(if redo { 3 } else { 0usize.wrapping_sub(1) }) {
                                let h = stream_layer(&by_k4, 5, 1u8 << NA, d, &t5);
                                println!("    STREAMER VALIDATION (k=5 from k<=4, depth {d}): {} / {n5} ({:.1}%)",
                                    h.len(), pc6(h.len(), n5));
                                if h.len() == n5 { best_depth = d; break; }
                            }
                            if !redo { println!("    STREAMER: depth curve cached (complete at depth 2); set PAD_STREAMER=1 to redo"); }
                            println!("    -> smallest complete depth at k=5: {best_depth}");
                            // now the live question: the k=6 quotients nothing could decide
                            let mut t6: FxSet<Aut<NA>> = FxSet::default();
                            for &(i, j) in crux.iter() {
                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                    for cg in lattice_congruences(&su).iter() {
                                        if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                            if q.k as usize == 6 {
                                                if let Some(c) = canon(&q) { t6.insert(c); }
                                            }
                                        }
                                    }
                                }
                            }
                            let mut raw6 = 0usize; let mut canon_fail = 0usize;
                            for &(i, j) in crux.iter() {
                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                    for cg in lattice_congruences(&su).iter() {
                                        if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                            if q.k as usize == 6 {
                                                raw6 += 1;
                                                if canon(&q).is_none() { canon_fail += 1; }
                                            }
                                        }
                                    }
                                }
                            }
                            println!("    [diag] k=6 quotients seen {raw6}, canon failed {canon_fail}");
                            {
                                let mut after = [0usize; MAXK + 1];
                                let mut nowT = 0usize; let mut tot = 0usize;
                                for &(i, j) in crux.iter() {
                                    if let Some(su) = sum_core(&list[i], &list[j]) {
                                        for cg in lattice_congruences(&su).iter() {
                                            if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                                if (q.k as usize) <= poolk { continue; }
                                                tot += 1;
                                                if let Some(t) = trim_canon(&q) {
                                                    after[(t.k as usize).min(MAXK)] += 1;
                                                    if (t.k as usize) <= poolk
                                                        && canon(&t).map(|c| seen.contains(&c))
                                                            .unwrap_or(false) { nowT += 1; }
                                                }
                                            }
                                        }
                                    }
                                }
                                println!("    [diag] AFTER TRIM, sizes of the {tot} oversized quotients: {:?}", &after[..]);
                                println!("    [diag] of those, now decidable AND Thompson: {nowT}");
                            }
                            let n6 = t6.len();
                            let h6 = stream_layer(&by_k5, 6, 1u8 << NA, best_depth, &t6);
                            println!("    k=6 QUOTIENTS DECIDED THOMPSON (sound positives): {} / {n6} ({:.1}%)",
                                h6.len(), pc6(h6.len(), n6));
                        }
                        println!("    POWER: known non-Thompson quotients caught {neg_caught} / {neg} ({:.1}%)",
                            pc6(neg_caught, neg));
                        println!("           (known Thompson quotients seen for scale: {pos_seen})");
                        println!("    crux systems with EVERY lattice quotient refuted : {all_ref} / {nn} ({:.1}%)",
                            pc6(all_ref, nn));
                        println!("    crux systems with SOME quotient refuted          : {any_ref} / {nn} ({:.1}%)",
                            pc6(any_ref, nn));
                    }
                    println!("  UA-COUNTEREXAMPLE CANDIDATES (crux pairs whose system has a cycle):");
                    println!("    candidates {cyc_n} / {tot_n} ({:.1}%), of which the kernels reach {cyc_elim} ({:.1}%)",
                        pc6(cyc_n, tot_n), pc6(cyc_elim, cyc_n));
                    println!("  IS THE UNDECIDED CROSSING REAL? (decided = guard constant across atoms)");
                    println!("    sum systems : states decided {dst}/{tst} ({:.1}%), ALL-decided systems {dall}/{nall} ({:.1}%)",
                        pc6(dst, tst), pc6(dall, nall));
                    println!("    pool base   : states decided {bd}/{bt} ({:.1}%), ALL-decided automata {ba}/{bn} ({:.1}%)",
                        pc6(bd, bt), pc6(ba, bn));
                    println!("    + DEAD-EXIT kernel (decided OR never-halting):");
                    println!("      sum systems : states {ud}/{ut} ({:.1}%), ALL-eliminable systems {uall}/{un} ({:.1}%)",
                        pc6(ud, ut), pc6(uall, un));
                    println!("      pool base   : states {bu}/{bt2} ({:.1}%), ALL-eliminable {bua}/{bn2} ({:.1}%)",
                        pc6(bu, bt2), pc6(bua, bn2));
                    println!("  ALREADY SETTLED BY SKIP-FREE COMPLETENESS (no UA needed):");
                    println!("    both sides skip-free : {sf} / {sfn}  ({:.1}%)", pc5(sf, sfn));
                    println!("    NOT skip-free        : {nonsf}, of which this programme discharges {nonsf_ok}  ({:.1}%)",
                        pc5(nonsf_ok, nonsf));
                    println!("  FULL SOUND TEST (any congruence: eliminable OR Thompson):");
                    println!("    solvable : {lat2} / {lat2n}");
                    // THE DECIDING COMPARISON.  If the residue differs from the covered
                    // population ONLY BY SIZE, it is a search-reach limit; if a structural
                    // feature separates them, it is an obstruction.  Same diagnostic that read
                    // the 391 pullback residue, now applied to the sum-quotient residue.
                    {
                        // feature vector: states, has-cycle, reducible, halt-in-cycle,
                        // decided-state fraction, two-exit states, two-halt states
                        let feats = |a: &Aut<NA>| -> [f64; 7] {
                            let k = a.k as usize;
                            let mut twoex = 0usize; let mut twoha = 0usize; let mut dec = 0usize;
                            for sx in 0..k {
                                let mut tg: Vec<u8> = (0..NA).filter(|&i| a.st[sx][i] != 0)
                                    .map(|i| a.st[sx][i]).collect();
                                tg.sort_unstable(); tg.dedup();
                                if tg.len() >= 2 { twoex += 1; }
                                if (a.hl[sx].count_ones() as usize) >= 2 { twoha += 1; }
                                let n = (0..NA).filter(|&i| a.st[sx][i] != 0).count();
                                if n == 0 || n == NA { dec += 1; }
                            }
                            [k as f64,
                             if orbits(a).is_empty() { 0.0 } else { 1.0 },
                             if reducible(a) { 1.0 } else { 0.0 },
                             if halt_in_cycle(a) { 1.0 } else { 0.0 },
                             if k == 0 { 0.0 } else { dec as f64 / k as f64 },
                             twoex as f64, twoha as f64]
                        };
                        let (mut cov, mut res) = ([0f64; 7], [0f64; 7]);
                        let (mut nc, mut nr2) = (0usize, 0usize);
                        for (ci, &(i, j)) in crux.iter().enumerate() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                let ok = facts[ci].0 || thompson_somewhere_in_lattice(&su, &seen);
                                let f = feats(&su);
                                if ok { for t in 0..7 { cov[t] += f[t]; } nc += 1; }
                                else { for t in 0..7 { res[t] += f[t]; } nr2 += 1; }
                            }
                        }
                        let nm = ["states", "has-cycle", "reducible", "halt-in-cycle",
                                  "decided-frac", "two-exit", "two-halt"];
                        // THE OPEN QUESTION, MADE MEASURABLE.  Direct elimination stops exactly
                    // where it would need an UNGUARDED UNION (a halt or a second variable on a
                    // recurrence atom, created by substitution).  Does the congruence lattice
                    // always contain a quotient where that never happens?
                    {
                        let (mut nfail, mut byelim, mut bythom, mut byboth, mut neither) =
                            (0usize, 0usize, 0usize, 0usize, 0usize);
                        for &(i, j) in crux.iter() {
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                if symbolic_eliminable(&su) { continue; }
                                nfail += 1;
                                let mut e_ok = false; let mut t_ok = false;
                                for cg in lattice_congruences(&su).iter() {
                                    if let Some(q) = quotient_by(&su, &cg.0, cg.1) {
                                        if symbolic_eliminable(&q) { e_ok = true; }
                                        if trim_canon(&q).and_then(|t| canon(&t))
                                            .map(|c| seen.contains(&c)).unwrap_or(false) { t_ok = true; }
                                    }
                                }
                                match (e_ok, t_ok) {
                                    (true, true) => byboth += 1,
                                    (true, false) => byelim += 1,
                                    (false, true) => bythom += 1,
                                    (false, false) => neither += 1,
                                }
                            }
                        }
                        // IS THE 100% VACUOUS?  `sum_core` keeps only A's initial transitions, so
                    // B's half is unreachable and TRIMMING COULD DELETE IT — leaving Thompson(e)
                    // alone, which is trivially Thompson.  The conjunct demands the two START
                    // STATES be identified; the harness never checked that.  Check it now.
                    {
                        let (mut ok_any, mut ok_start, mut n) = (0usize, 0usize, 0usize);
                        for &(i, j) in crux.iter() {
                            let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                n += 1;
                                let mut any = false; let mut wstart = false;
                                let (blk, nb) = bisim_blocks(&su);
                                let mut cands: Vec<([usize; MAXK], usize)> = vec![(blk, nb)];
                                cands.extend(lattice_congruences(&su));
                                for (b2, nb2) in cands.iter() {
                                    if let Some(q) = quotient_by(&su, b2, *nb2) {
                                        let isT = trim_canon(&q).and_then(|t| canon(&t))
                                            .map(|c| seen.contains(&c)).unwrap_or(false);
                                        if !isT { continue; }
                                        any = true;
                                        // the conjunct's start condition: both starts in one block
                                        if ka < su.k as usize && b2[0] == b2[ka] { wstart = true; }
                                    }
                                }
                                if any { ok_any += 1; }
                                if wstart { ok_start += 1; }
                            }
                        }
                        let pc7 = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
                        // THE EXPLICIT WITNESS.  For deterministic language-equivalent automata,
                        // "reachable by the same guarded string" is a bisimulation and a
                        // congruence, and it collapses Mf onto Me — which IS Thompson.  That
                        // congruence is generated by the SINGLE SEED (start_A, start_B).  If the
                        // conjunct always has this witness, the 83.8% is a search artifact.
                        {
                            let (mut hit, mut nn2, mut noclose) = (0usize, 0usize, 0usize);
                            for &(i, j) in crux.iter() {
                                let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                    if ka >= su.k as usize { continue; }
                                    nn2 += 1;
                                    match close_congruence(&su, &[(0, ka)]) {
                                        None => noclose += 1,
                                        Some((b2, nb2)) => {
                                            if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                if trim_canon(&q).and_then(|t| canon(&t))
                                                    .map(|c| seen.contains(&c)).unwrap_or(false) { hit += 1; }
                                            }
                                        }
                                    }
                                }
                            }
                            // THE UNION CONJUNCT.  Thompson alone is refuted (83.7%).  The
                            // statement that survives is `SumQuotientSolvable`: some quotient
                            // IDENTIFYING THE STARTS is Thompson OR eliminable.  Both witnesses,
                            // one quotient, start condition enforced.
                            {
                                let (mut u_ok, mut u_n, mut only_e, mut only_t) =
                                    (0usize, 0usize, 0usize, 0usize);
                                let mut refw = 0usize;
                                for &(i, j) in crux.iter() {
                                    let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                    if let Some(su) = sum_core(&list[i], &list[j]) {
                                        if ka >= su.k as usize { continue; }
                                        u_n += 1;
                                        let base = match close_congruence(&su, &[(0, ka)]) {
                                            Some(c) => c, None => continue };
                                        // candidates: the least start-merging congruence, and its
                                        // joins with the other principals
                                        let mut cands: Vec<([usize; MAXK], usize)> = vec![base];
                                        for cg in lattice_congruences(&su).iter() {
                                            if cg.0[0] == cg.0[ka] { cands.push(*cg); }
                                        }
                                        let (mut e_ok, mut t_ok) = (false, false);
                                        for (b2, nb2) in cands.iter() {
                                            if let Some(q) = quotient_by(&su, b2, *nb2) {
                                                if symbolic_eliminable(&q) { e_ok = true; }
                                                if trim_canon(&q).and_then(|t| canon(&t))
                                                    .map(|c| seen.contains(&c)).unwrap_or(false) { t_ok = true; }
                                            }
                                        }
                                        if !(e_ok || t_ok) {
                                            if refinement_witness(&list, &prov, i as u32, j as u32,
                                                1u8 << NA, 3, 4000) { refw += 1; }
                                        }
                                        if e_ok || t_ok { u_ok += 1; }
                                        if e_ok && !t_ok { only_e += 1; }
                                        if t_ok && !e_ok { only_t += 1; }
                                    }
                                }
                                // THE RIGHT TEST.  "Is it Thompson" is far too strong: the class
                                // of automata whose behaviour IS GKAT-expressible is the NESTING
                                // COEQUATION, a covariety — closed under quotients and coproducts,
                                // and preserved by minimisation.  Thompson automata satisfy it, so
                                // the sum does, so every quotient should.  Measure it.
                                if std::env::var("PAD_DIAG").is_ok() {
                                    let (mut nst, mut nn3) = (0usize, 0usize);
                                    for &(i, j) in crux.iter() {
                                        let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                        if let Some(su) = sum_core(&list[i], &list[j]) {
                                            if ka >= su.k as usize { continue; }
                                            if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                    nn3 += 1;
                                                    let qq = trim_canon(&q).unwrap_or(q);
                                                    if nested(&qq) { nst += 1; }
                                                }
                                            }
                                        }
                                    }
                                    // HOW MUCH OF THE ROUTE DOES THE LEAN CERTIFICATE REACH?
                                // `chain_solves` checks a CHAIN: self-loops plus forward edges,
                                // each substitution hitting an already-closed tail.  A
                                // multi-state SCC needs the case left-distributivity blocks.  So
                                // the certificate's reach is exactly the quotients whose SCCs are
                                // all singletons.
                                if std::env::var("PAD_DIAG").is_ok() {
                                    let (mut sing, mut nn4) = (0usize, 0usize);
                                    for &(i, j) in crux.iter() {
                                        let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                        if let Some(su) = sum_core(&list[i], &list[j]) {
                                            if ka >= su.k as usize { continue; }
                                            if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                    let qq = trim_canon(&q).unwrap_or(q);
                                                    nn4 += 1;
                                                    if orbits(&qq).iter()
                                                        .all(|o| o.count_ones() <= 1) { sing += 1; }
                                                }
                                            }
                                        }
                                    }
                                    // WHAT IS THE REMAINING OBJECT?  Size distribution of the
                                    // multi-state SCCs, and whether they are eliminable anyway.
                                    {
                                        let mut dist = [0usize; MAXK + 1];
                                        let (mut multi, mut multi_elim) = (0usize, 0usize);
                                        for &(i, j) in crux.iter() {
                                            let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                                if ka >= su.k as usize { continue; }
                                                if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                    if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                        let qq = trim_canon(&q).unwrap_or(q);
                                                        let mx = orbits(&qq).iter()
                                                            .map(|o| o.count_ones() as usize).max().unwrap_or(0);
                                                        if mx >= 2 {
                                                            multi += 1;
                                                            dist[mx.min(MAXK)] += 1;
                                                            if symbolic_eliminable(&qq) { multi_elim += 1; }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // DOES `elim_scc2` ACTUALLY APPLY?  Its hypothesis is that
                                        // one state of the pair steps ONLY into the other and never
                                        // halts — a dead fallback with a common tail.  Measure the
                                        // fraction of size-2 SCCs that have that shape.
                                        if std::env::var("PAD_DIAG").is_ok() {
                                            let (mut sh, mut n2) = (0usize, 0usize);
                                            for &(i, j) in crux.iter() {
                                                let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                                    if ka >= su.k as usize { continue; }
                                                    if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                        if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                            let qq = trim_canon(&q).unwrap_or(q);
                                                            for o in orbits(&qq).iter() {
                                                                if o.count_ones() != 2 { continue; }
                                                                n2 += 1;
                                                                let mut mem: Vec<usize> = Vec::new();
                                                                for t in 0..qq.k as usize {
                                                                    if o & (1 << t) != 0 { mem.push(t); }
                                                                }
                                                                let (u, v) = (mem[0], mem[1]);
                                                                let facs = |a: usize, b: usize| -> bool {
                                                                    qq.hl[a] == 0 && (0..NA).all(|y|
                                                                        qq.st[a][y] == 0
                                                                        || (qq.st[a][y] - 1) as usize == b)
                                                                };
                                                                if facs(u, v) || facs(v, u) { sh += 1; }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            println!("  DOES elim_scc2 APPLY? (one state factors through the other, dead exit)");
                                            println!("    shape holds : {sh} / {n2} ({:.1}%)", pc7(sh, n2));
                                        }
                                        // TWIN-CRYSTAL TEST.  Grabmayer: SCCs that resist collapse take a
                                        // "twin-crystal" shape — bisimilar copies that cannot be merged.  If my
                                        // multi-state SCCs are twins, a coarser quotient collapses them and they
                                        // are not really the hard case.  If their states are NOT bisimilar, they
                                        // are genuinely distinct and the twin-crystal frame does not apply.
                                        {
                                            let (mut tw, mut nsc) = (0usize, 0usize);
                                            for &(i, j) in crux.iter() {
                                                let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                                    if ka >= su.k as usize { continue; }
                                                    if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                        if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                            let qq = trim_canon(&q).unwrap_or(q);
                                                            let (bb, _) = bisim_blocks(&qq);
                                                            for o in orbits(&qq).iter() {
                                                                if o.count_ones() < 2 { continue; }
                                                                nsc += 1;
                                                                let mut mem: Vec<usize> = Vec::new();
                                                                for t in 0..qq.k as usize {
                                                                    if o & (1 << t) != 0 { mem.push(t); }
                                                                }
                                                                if mem.iter().any(|&a| mem.iter().any(|&b| a != b && bb[a] == bb[b])) { tw += 1; }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // DOES elim2 ACCEPT THE SHAPE I CLAIM IS UNDERIVABLE?  A 2-cycle where
                                            // BOTH states have a live fallback is blocked at expression level in both
                                            // elimination orders.  If elim2 REJECTS those, my doubt evaporates and the
                                            // 98.2% comes from other shapes.  If it accepts them, the doubt is real.
                                            {
                                                let (mut both, mut both_acc) = (0usize, 0usize);
                                                for &(i, j) in crux.iter() {
                                                    let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                    if let Some(su) = sum_core(&list[i], &list[j]) {
                                                        if ka >= su.k as usize { continue; }
                                                        if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                            if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                                let qq = trim_canon(&q).unwrap_or(q);
                                                                let mut hit = false;
                                                                for o in orbits(&qq).iter() {
                                                                    if o.count_ones() != 2 { continue; }
                                                                    let mut mem: Vec<usize> = Vec::new();
                                                                    for t in 0..qq.k as usize {
                                                                        if o & (1 << t) != 0 { mem.push(t); }
                                                                    }
                                                                    if qq.hl[mem[0]] != 0 && qq.hl[mem[1]] != 0 { hit = true; }
                                                                }
                                                                if !hit { continue; }
                                                                both += 1;
                                                                if symbolic_eliminable(&qq) { both_acc += 1; }
                                                            }
                                                        }
                                                    }
                                                }
                                                if std::env::var("PAD_DIAG").is_ok() {
                                                    let (mut n2, mut dead, mut dead_single) = (0usize, 0usize, 0usize);
                                                    for &(i, j) in crux.iter() {
                                                        let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                        if let Some(su) = sum_core(&list[i], &list[j]) {
                                                            if ka >= su.k as usize { continue; }
                                                            if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                                if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                                    let qq = trim_canon(&q).unwrap_or(q);
                                                                    for o in orbits(&qq).iter() {
                                                                        if o.count_ones() != 2 { continue; }
                                                                        n2 += 1;
                                                                        let mut mem: Vec<usize> = Vec::new();
                                                                        for t in 0..qq.k as usize {
                                                                            if o & (1 << t) != 0 { mem.push(t); }
                                                                        }
                                                                        let (u, v) = (mem[0], mem[1]);
                                                                        let dd = |a: usize| qq.hl[a] == 0;
                                                                        let single = |a: usize, b: usize| (0..NA).all(|y|
                                                                            qq.st[a][y] == 0 || (qq.st[a][y] - 1) as usize == b);
                                                                        if dd(u) || dd(v) { dead += 1; }
                                                                        if (dd(u) && single(u, v)) || (dd(v) && single(v, u)) { dead_single += 1; }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    println!("  WHICH CONDITION BINDS? (size-2 SCCs)");
                                                    println!("    total {n2}, at least one DEAD fallback : {dead} ({:.1}%)", pc7(dead, n2));
                                                    println!("    ... AND that state single-successor    : {dead_single} ({:.1}%)", pc7(dead_single, n2));
                                                }
                                                println!("  DOES elim2 ACCEPT THE BLOCKED SHAPE? (2-cycle, BOTH fallbacks live)");
                                                println!("    quotients with that shape : {both}");
                                                println!("    of those, elim2 ACCEPTS   : {both_acc} ({:.1}%)", pc7(both_acc, both));
                                            }
                                            println!("  TWIN-CRYSTAL TEST (are the SCC states bisimilar?):");
                                            println!("    SCCs containing a bisimilar pair : {tw} / {nsc} ({:.1}%)", pc7(tw, nsc));
                                        }
                                        println!("  THE REMAINING OBJECT (multi-state SCCs):");
                                        println!("    quotients with one : {multi}");
                                        println!("    largest SCC size   : {:?}", &dist[2..8]);
                                        println!("    of those, ELIMINABLE anyway : {multi_elim} ({:.1}%)",
                                            pc7(multi_elim, multi));
                                    }
                                    // VALIDATE THE ORACLE AGAINST THE PROOFS.  The brief's harness
                                    // checks elim2 against the POOL; this checks it against
                                    // LEAN-PROVED ground truth.  `chain_solves` proves a
                                    // chain-shaped system solvable, so elim2 must accept every
                                    // chain-shaped quotient — a disagreement is a gap in the
                                    // oracle that the proofs can see and the pool cannot.
                                    {
                                        let (mut ch, mut ch_ok) = (0usize, 0usize);
                                        for &(i, j) in crux.iter() {
                                            let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                                if ka >= su.k as usize { continue; }
                                                if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                    if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                        let qq = trim_canon(&q).unwrap_or(q);
                                                        if orbits(&qq).iter().all(|o| o.count_ones() <= 1) {
                                                            ch += 1;
                                                            if symbolic_eliminable(&qq) { ch_ok += 1; }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // Extend the same validation into the RISKY region: the
                                        // size-2 SCCs of the shape `elim_scc2` proves.  Those are
                                        // inside the 14.3% where oracle and proofs could disagree.
                                        {
                                            let (mut s2, mut s2_ok) = (0usize, 0usize);
                                            for &(i, j) in crux.iter() {
                                                let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                                    if ka >= su.k as usize { continue; }
                                                    if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                        if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                            let qq = trim_canon(&q).unwrap_or(q);
                                                            let os = orbits(&qq);
                                                            if os.iter().map(|o| o.count_ones()).max().unwrap_or(0) != 2 { continue; }
                                                            let mut shape = false;
                                                            for o in os.iter() {
                                                                if o.count_ones() != 2 { continue; }
                                                                let mut mem: Vec<usize> = Vec::new();
                                                                for t in 0..qq.k as usize {
                                                                    if o & (1 << t) != 0 { mem.push(t); }
                                                                }
                                                                let facs = |a: usize, b: usize| -> bool {
                                                                    qq.hl[a] == 0 && (0..NA).all(|y|
                                                                        qq.st[a][y] == 0
                                                                        || (qq.st[a][y] - 1) as usize == b)
                                                                };
                                                                if facs(mem[0], mem[1]) || facs(mem[1], mem[0]) { shape = true; }
                                                            }
                                                            if !shape { continue; }
                                                            s2 += 1;
                                                            if symbolic_eliminable(&qq) { s2_ok += 1; }
                                                        }
                                                    }
                                                }
                                            }
                                            // IS THE LINEAR-CHAIN RESTRICTION BINDING?  `chain_solves`
                                        // takes ONE forward exit per level, so its reach may be
                                        // below the 85.7% chain-shaped figure.  Measure how many
                                        // chain-shaped quotients are LINEAR: every state has at
                                        // most one distinct forward successor.
                                        {
                                            let (mut lin, mut chn) = (0usize, 0usize);
                                            for &(i, j) in crux.iter() {
                                                let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                if let Some(su) = sum_core(&list[i], &list[j]) {
                                                    if ka >= su.k as usize { continue; }
                                                    if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                        if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                            let qq = trim_canon(&q).unwrap_or(q);
                                                            if !orbits(&qq).iter().all(|o| o.count_ones() <= 1) { continue; }
                                                            chn += 1;
                                                            let ok = (0..qq.k as usize).all(|u| {
                                                                let mut fw: Vec<u8> = (0..NA)
                                                                    .filter(|&y| qq.st[u][y] != 0
                                                                        && (qq.st[u][y] - 1) as usize != u)
                                                                    .map(|y| qq.st[u][y]).collect();
                                                                fw.sort_unstable(); fw.dedup();
                                                                fw.len() <= 1
                                                            });
                                                            if ok { lin += 1; }
                                                        }
                                                    }
                                                }
                                            }
                                            // ROBUSTNESS.  Suppose elim2 is discounted ENTIRELY on
                                            // multi-state SCCs without the `elim_scc2` shape — the
                                            // cases where both states have live fallbacks and both
                                            // elimination orders nest, i.e. genuine UA_2 instances.
                                            // Does the Thompson witness still cover them?
                                            if std::env::var("PAD_DIAG").is_ok() {
                                                let (mut susp, mut susp_t) = (0usize, 0usize);
                                                for &(i, j) in crux.iter() {
                                                    let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                                    if let Some(su) = sum_core(&list[i], &list[j]) {
                                                        if ka >= su.k as usize { continue; }
                                                        if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                            if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                                let qq = trim_canon(&q).unwrap_or(q);
                                                                let os = orbits(&qq);
                                                                if os.iter().all(|o| o.count_ones() <= 1) { continue; }
                                                                let mut shape = false;
                                                                for o in os.iter() {
                                                                    if o.count_ones() != 2 { continue; }
                                                                    let mut mem: Vec<usize> = Vec::new();
                                                                    for t in 0..qq.k as usize {
                                                                        if o & (1 << t) != 0 { mem.push(t); }
                                                                    }
                                                                    let facs = |a: usize, b: usize| -> bool {
                                                                        qq.hl[a] == 0 && (0..NA).all(|y|
                                                                            qq.st[a][y] == 0
                                                                            || (qq.st[a][y] - 1) as usize == b)
                                                                    };
                                                                    if facs(mem[0], mem[1]) || facs(mem[1], mem[0]) { shape = true; }
                                                                }
                                                                if shape { continue; }
                                                                susp += 1;
                                                                // does ANY start-merging quotient give Thompson?
                                                                let mut cands: Vec<([usize; MAXK], usize)> = vec![(b2, nb2)];
                                                                for cg in lattice_congruences(&su).iter() {
                                                                    if cg.0[0] == cg.0[ka] { cands.push(*cg); }
                                                                }
                                                                for (c2, cn2) in cands.iter() {
                                                                    if let Some(qz) = quotient_by(&su, c2, *cn2) {
                                                                        if trim_canon(&qz).and_then(|t| canon(&t))
                                                                            .map(|c| seen.contains(&c))
                                                                            .unwrap_or(false) { susp_t += 1; break; }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                println!("  ROBUSTNESS: discount elim2 on unshaped multi-SCCs — does Thompson cover?");
                                                println!("    unshaped multi-SCC quotients : {susp}");
                                                println!("    of those, a Thompson quotient exists : {susp_t} ({:.1}%)",
                                                    pc7(susp_t, susp));
                                            }
                                            println!("  IS THE LINEAR RESTRICTION BINDING? (one forward successor per state)");
                                            println!("    linear : {lin} / {chn} chain-shaped ({:.1}%)", pc7(lin, chn));
                                        }
                                        println!("  ORACLE vs PROOFS, risky region (elim2 on the elim_scc2 shape):");
                                            println!("    elim2 accepts : {s2_ok} / {s2} ({:.1}%)  (must be all)",
                                                pc7(s2_ok, s2));
                                        }
                                        println!("  ORACLE vs PROOFS (elim2 on chain-shaped, which chain_solves proves):");
                                        println!("    elim2 accepts : {ch_ok} / {ch} ({:.1}%)  (must be all)",
                                            pc7(ch_ok, ch));
                                    }
                                    println!("  CERTIFICATE REACH (all SCCs singleton = chain-shaped):");
                                    println!("    chain-shaped : {sing} / {nn4} ({:.1}%)", pc7(sing, nn4));
                                }
                                println!("  IS THE START-MERGED QUOTIENT NESTED? (the covariety test)");
                                    println!("    nested : {nst} / {nn3} ({:.1}%)", pc7(nst, nn3));
                                }
                                // THE FAILURES: are they DECIDABLE?  "No Thompson quotient" is only
                                // meaningful if the quotient is small enough to look up.  Report
                                // the sizes of the failures' quotients against the pool bound.
                                {
                                    let poolk2 = list.iter().map(|a| a.k as usize).max().unwrap_or(0);
                                    let mut szs = [0usize; MAXK + 1];
                                    let mut undec = 0usize;
                                    for &(i, j) in crux.iter() {
                                        let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                        if let Some(su) = sum_core(&list[i], &list[j]) {
                                            if ka >= su.k as usize { continue; }
                                            let base = match close_congruence(&su, &[(0, ka)]) {
                                                Some(c) => c, None => continue };
                                            let mut cands: Vec<([usize; MAXK], usize)> = vec![base];
                                            for cg in lattice_congruences(&su).iter() {
                                                if cg.0[0] == cg.0[ka] { cands.push(*cg); }
                                            }
                                            let mut ok = false;
                                            let mut minsz = MAXK;
                                            for (b2, nb2) in cands.iter() {
                                                if let Some(q) = quotient_by(&su, b2, *nb2) {
                                                    let qq = trim_canon(&q).unwrap_or(q);
                                                    if (qq.k as usize) < minsz { minsz = qq.k as usize; }
                                                    if symbolic_eliminable(&qq) { ok = true; }
                                                    if canon(&qq).map(|c| seen.contains(&c))
                                                        .unwrap_or(false) { ok = true; }
                                                }
                                            }
                                            if !ok {
                                                szs[minsz.min(MAXK)] += 1;
                                                if minsz > poolk2 { undec += 1; }
                                            }
                                        }
                                    }
                                    // THE FAILURES, AS PROGRAMS.  Printing the eight residue pairs
                                    // turned them from opaque into four lines of syntax, and three
                                    // fell the same day.  Same move here.
                                    {
                                        let mut shown = 0;
                                        for &(i, j) in crux.iter() {
                                            if shown >= 80 { break; }
                                            let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                            if let Some(su) = sum_core(&list[i], &list[j]) {
                                                if ka >= su.k as usize { continue; }
                                                let base = match close_congruence(&su, &[(0, ka)]) {
                                                    Some(c) => c, None => continue };
                                                let mut cands: Vec<([usize; MAXK], usize)> = vec![base];
                                                for cg in lattice_congruences(&su).iter() {
                                                    if cg.0[0] == cg.0[ka] { cands.push(*cg); }
                                                }
                                                let mut ok = false;
                                                let mut best = MAXK;
                                                for (b2, nb2) in cands.iter() {
                                                    if let Some(q) = quotient_by(&su, b2, *nb2) {
                                                        let qq = trim_canon(&q).unwrap_or(q);
                                                        if (qq.k as usize) < best { best = qq.k as usize; }
                                                        if symbolic_eliminable(&qq) { ok = true; }
                                                        if canon(&qq).map(|c| seen.contains(&c))
                                                            .unwrap_or(false) { ok = true; }
                                                    }
                                                }
                                                if ok { continue; }
                                                shown += 1;
                                                println!("    FAILURE #{shown} (smallest quotient k={best})");
                                                println!("      e = {}", expr_of(&list, &prov, i as u32, 14));
                                                println!("      f = {}", expr_of(&list, &prov, j as u32, 14));
                                            }
                                        }
                                    }
                                    println!("  THE FAILURES: smallest quotient size (pool bound {poolk2}):");
                                    println!("    sizes {:?}", &szs[..]);
                                    println!("    of which UNDECIDABLE (k > {poolk2}) : {undec}");
                                }
                                // VALIDATE THE NEW WITNESS before citing it.  It must FIRE on
                                // language-equivalent pairs and NEVER on non-equivalent ones —
                                // soundness is by construction (Refines moves are proved), so the
                                // control is the one that matters, and non-vacuity is the other half.
                                {
                                    // SATURATION LADDER.  The closure is exponential in rounds, so 0.4% at
                                    // rounds=2 is a LOWER BOUND.  If the curve climbs, a deeper search is
                                    // worth building; if it plateaus, the witness is intrinsically weak.
                                    for rd in (1..=4u32).filter(|_| std::env::var("PAD_REFLADDER").is_ok()) {
                                        let hits = crux.iter().take(600).filter(|&&(a, b)|
                                            refinement_witness(&list, &prov, a as u32, b as u32,
                                                1u8 << NA, rd, 3000)).count();
                                        println!("    power at rounds={rd} : {hits} / 600 ({:.1}%)",
                                            100.0 * hits as f64 / 600.0);
                                    }
                                    let (mut fires, mut fn2) = (0usize, 0usize);
                                    for &(a, b) in crux.iter().take(if std::env::var("PAD_REFVAL").is_ok() { 1500 } else { 0 }) {
                                        fn2 += 1;
                                        if refinement_witness(&list, &prov, a as u32, b as u32,
                                            1u8 << NA, 2, 1500) { fires += 1; }
                                    }
                                    let (mut bad, mut bn) = (0usize, 0usize);
                                    let mut r5: u64 = 0x2545F4914F6CDD1D;
                                    let mut rr = move || { r5 ^= r5 << 13; r5 ^= r5 >> 7; r5 ^= r5 << 17; r5 };
                                    while bn < if std::env::var("PAD_REFVAL").is_ok() { 1500 } else { 0 } {
                                        let a = (rr() as usize) % list.len();
                                        let b = (rr() as usize) % list.len();
                                        if behaviour(&list[a]) == behaviour(&list[b]) { continue; }
                                        bn += 1;
                                        if refinement_witness(&list, &prov, a as u32, b as u32,
                                            1u8 << NA, 2, 1500) { bad += 1; }
                                    }
                                    println!("  REFINEMENT WITNESS VALIDATION:");
                                    println!("    fires on equivalent pairs : {fires} / {fn2} ({:.1}%)  (non-vacuity)", pc7(fires, fn2));
                                    println!("    fires on NON-equivalent   : {bad} / {bn}  (must be 0)");
                                }
                                println!("    of the failures, a COMMON REFINEMENT discharges : {refw}");
                                // CERTIFICATE EXTRACTION.  For chain-shaped start-merged quotients, dump the
                                // per-state level data (recurring branches, forward branches, fallback) plus a
                                // reverse-topological order — everything the Lean checker (`level_satisfies` +
                                // `levels_solve`) consumes.  Producer data first, emitted proofs second.
                                if std::env::var("PAD_EMIT").is_ok() {
                                    let want: usize = std::env::var("PAD_EMIT").ok()
                                        .and_then(|v| v.parse().ok()).unwrap_or(3);
                                    let mut done = 0usize;
                                    for &(i, j) in crux.iter() {
                                        if done >= want { break; }
                                        let ka = match to_gaut(&list[i]) { Some(g) => g.k as usize, None => continue };
                                        if let Some(su) = sum_core(&list[i], &list[j]) {
                                            if ka >= su.k as usize { continue; }
                                            if let Some((b2, nb2)) = close_congruence(&su, &[(0, ka)]) {
                                                if let Some(q) = quotient_by(&su, &b2, nb2) {
                                                    let qq = trim_canon(&q).unwrap_or(q);
                                                    let tmode = std::env::var("PAD_EMIT_T").is_ok();
                                                    if tmode {
                                                        if symbolic_eliminable(&qq) { continue; }
                                                        let gidx = match canon(&qq).and_then(|c| seen.get(&c).copied()) {
                                                            Some(g) => g as usize, None => continue };
                                                        done += 1;
                                                        println!("  CERT-T #{done}");
                                                        println!("    LEAN e := {}", expr_lean(&list, &prov, i as u32));
                                                        println!("    LEAN f := {}", expr_lean(&list, &prov, j as u32));
                                                        println!("    LEAN g := {}", expr_lean(&list, &prov, gidx as u32));
                                                        let gpaths = state_paths(&list, &prov, gidx as u32);
                                                        let gs = structural(&list, &prov, gidx as u32);
                                                        let gord = canon_order(&gs);
                                                        let mut path_of_trim = vec![String::new(); qq.k as usize];
                                                        for (sidx, pth) in gpaths.iter().enumerate() {
                                                            let c = gord[sidx];
                                                            if c != u8::MAX { path_of_trim[c as usize] = pth.clone(); }
                                                        }
                                                        println!("    LEAN g table (structural index: hlt, steps, path):");
                                                        for sx in 0..gs.k as usize {
                                                            let tg: Vec<String> = (0..NA).map(|y|
                                                                if gs.st[sx][y] == 0 { "-".to_string() }
                                                                else { gpaths[(gs.st[sx][y]-1) as usize].clone() }).collect();
                                                            println!("      {}: hlt={:#04b} steps={:?} path={}",
                                                                sx, gs.hl[sx], tg, gpaths[sx]);
                                                        }
                                                        println!("    LEAN sum table (index: hlt, steps by atom):");
                                                        for sx in 0..su.k as usize {
                                                            let tgts: Vec<String> = (0..NA).map(|y|
                                                                if su.st[sx][y] == 0 { "-".to_string() }
                                                                else { format!("{}", su.st[sx][y] - 1) }).collect();
                                                            println!("      {}: hlt={:#04b} steps={:?}", sx, su.hl[sx], tgts);
                                                        }
                                                        let gpath_of = |sum_idx: usize| -> String {
                                                            let b = b2[sum_idx];
                                                            if let Some(qraw) = quotient_by(&su, &b2, nb2) {
                                                                let mut ord = [u8::MAX; MAXK];
                                                                let mut queue = [0usize; MAXK];
                                                                let (mut qh, mut qt2) = (0usize, 0usize);
                                                                let mut n = 0u8;
                                                                for y in 0..NA {
                                                                    if qraw.it[y] != 0 {
                                                                        let t = (qraw.it[y] - 1) as usize;
                                                                        if ord[t] == u8::MAX { ord[t] = n; n += 1; queue[qt2] = t; qt2 += 1; }
                                                                    }
                                                                }
                                                                while qh < qt2 {
                                                                    let sq = queue[qh]; qh += 1;
                                                                    for y in 0..NA {
                                                                        if qraw.st[sq][y] != 0 {
                                                                            let t = (qraw.st[sq][y] - 1) as usize;
                                                                            if ord[t] == u8::MAX { ord[t] = n; n += 1; queue[qt2] = t; qt2 += 1; }
                                                                        }
                                                                    }
                                                                }
                                                                if ord[b] == u8::MAX { return "UNREACHABLE".to_string(); }
                                                                return path_of_trim[ord[b] as usize].clone();
                                                            }
                                                            "?".to_string()
                                                        };
                                                        let permute2 = |idx: u32| -> Vec<String> {
                                                            let paths = state_paths(&list, &prov, idx);
                                                            let sa = structural(&list, &prov, idx);
                                                            let ord = canon_order(&sa);
                                                            let mut out = vec![String::new(); paths.len()];
                                                            for (sidx, p) in paths.iter().enumerate() {
                                                                let c = ord[sidx];
                                                                if c != u8::MAX { out[c as usize] = p.clone(); }
                                                            }
                                                            out
                                                        };
                                                        let pe2 = permute2(i as u32);
                                                        let pf2 = permute2(j as u32);
                                                        println!("    LEAN tmap (e-side): none -> {}", gpath_of(0));
                                                        for (pi, path) in pe2.iter().enumerate() {
                                                            println!("      inl (some {}) -> {}", path, gpath_of(1 + pi));
                                                        }
                                                        println!("    LEAN tmap (f-side): none -> {}", gpath_of(ka));
                                                        for (pi, path) in pf2.iter().enumerate() {
                                                            println!("      inr (some {}) -> {}", path, gpath_of(ka + 1 + pi));
                                                        }
                                                        continue;
                                                    }
                                                    if !orbits(&qq).iter().all(|o| o.count_ones() <= 1) { continue; }
                                                    done += 1;
                                                    println!("  CERT #{done}");
                                                    println!("    e = {}", expr_of(&list, &prov, i as u32, 14));
                                                    println!("    f = {}", expr_of(&list, &prov, j as u32, 14));
                                                    println!("    quotient k={} ih={} it={:?}", qq.k, qq.ih, &qq.it[..]);
                                                    for sx in 0..qq.k as usize {
                                                        let mut rec: Vec<String> = Vec::new();
                                                        let mut fwd: Vec<String> = Vec::new();
                                                        for y in 0..NA {
                                                            if qq.st[sx][y] == 0 { continue; }
                                                            let t = (qq.st[sx][y] - 1) as usize;
                                                            if t == sx { rec.push(format!("(atom{y}, act)")); }
                                                            else { fwd.push(format!("(atom{y}, act, s{t})")); }
                                                        }
                                                        println!("    s{sx}: rec={:?} fwd={:?} hlt={:#04b}", rec, fwd, qq.hl[sx]);
                                                    }
                                                    // reverse-topological order over the condensation (singleton SCCs)
                                                    let k = qq.k as usize;
                                                    let mut order: Vec<usize> = Vec::new();
                                                    let mut placed = vec![false; k];
                                                    while order.len() < k {
                                                        for sx in 0..k {
                                                            if placed[sx] { continue; }
                                                            let ready = (0..NA).all(|y| {
                                                                if qq.st[sx][y] == 0 { return true; }
                                                                let t = (qq.st[sx][y] - 1) as usize;
                                                                t == sx || placed[t]
                                                            });
                                                            if ready { placed[sx] = true; order.push(sx); }
                                                        }
                                                    }
                                                    println!("    solve order (reverse-topological): {:?}", order);
                    // Lean-side data for the emitter
                    println!("    LEAN e := {}", expr_lean(&list, &prov, i as u32));
                    println!("    LEAN f := {}", expr_lean(&list, &prov, j as u32));
                    // paths in CANONICAL order: pool automata are canon-BFS-renumbered,
                    // so permute construction-order paths through canon's BFS.
                    let permute = |idx: u32| -> Vec<String> {
                        let paths = state_paths(&list, &prov, idx);
                        let sa = structural(&list, &prov, idx);
                        debug_assert_eq!(canon(&sa).as_ref(), Some(&list[idx as usize]));
                        let ord = canon_order(&sa);
                        let mut out = vec![String::new(); paths.len()];
                        for (sidx, p) in paths.iter().enumerate() {
                            let c = ord[sidx];
                            if c != u8::MAX { out[c as usize] = p.clone(); }
                        }
                        out
                    };
                    let pe = permute(i as u32);
                    let pf = permute(j as u32);
                    // class of each sum state, in trim order: recompute the trim renumbering
                    let mut cls_of = |sum_idx: usize| -> String {
                        let b = b2[sum_idx];
                        // map block id to trimmed index via the same BFS trim_canon performs
                        if let Some(qraw) = quotient_by(&su, &b2, nb2) {
                            if let Some(_qt) = trim_canon(&qraw) {
                                // recompute BFS order over qraw
                                let mut ord = [u8::MAX; MAXK];
                                let mut queue = [0usize; MAXK];
                                let (mut qh, mut qt2) = (0usize, 0usize);
                                let mut n = 0u8;
                                for y in 0..NA {
                                    if qraw.it[y] != 0 {
                                        let t = (qraw.it[y] - 1) as usize;
                                        if ord[t] == u8::MAX { ord[t] = n; n += 1; queue[qt2] = t; qt2 += 1; }
                                    }
                                }
                                while qh < qt2 {
                                    let sq = queue[qh]; qh += 1;
                                    for y in 0..NA {
                                        if qraw.st[sq][y] != 0 {
                                            let t = (qraw.st[sq][y] - 1) as usize;
                                            if ord[t] == u8::MAX { ord[t] = n; n += 1; queue[qt2] = t; qt2 += 1; }
                                        }
                                    }
                                }
                                if ord[b] == u8::MAX { return "UNREACHABLE".to_string(); }
                                return format!("s{}", ord[b]);
                            }
                        }
                        "?".to_string()
                    };
                    // full SUM state table: hlt mask + per-atom step target index
                    println!("    LEAN sum table (index: hlt, steps by atom):");
                    for sx in 0..su.k as usize {
                        let tgts: Vec<String> = (0..NA).map(|y|
                            if su.st[sx][y] == 0 { "-".to_string() }
                            else { format!("{}", su.st[sx][y] - 1) }).collect();
                        println!("      {}: hlt={:#04b} steps={:?}", sx, su.hl[sx], tgts);
                    }
                    println!("    LEAN qmap (e-side): none -> {}", cls_of(0));
                    for (pi, path) in pe.iter().enumerate() {
                        println!("      inl (some {}) -> {}", path, cls_of(1 + pi));
                    }
                    println!("    LEAN qmap (f-side): none -> {}", cls_of(ka));
                    for (pi, path) in pf.iter().enumerate() {
                        println!("      inr (some {}) -> {}", path, cls_of(ka + 1 + pi));
                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                println!("  THE UNION CONJUNCT (starts merged, Thompson OR eliminable):");
                                println!("    holds : {u_ok} / {u_n} ({:.1}%)", pc7(u_ok, u_n));
                                println!("    only elimination works : {only_e}");
                                println!("    only Thompson works    : {only_t}");
                            }
                            println!("  THE EXPLICIT WITNESS (congruence generated by the two starts):");
                            println!("    seed closes and quotient is Thompson : {hit} / {nn2} ({:.1}%)",
                                pc7(hit, nn2));
                            println!("    seed fails to close                  : {noclose}");
                        }
                        println!("  IS THE 100% VACUOUS?  (does the Thompson quotient MERGE THE STARTS?)");
                        println!("    some quotient is Thompson            : {ok_any} / {n} ({:.1}%)", pc7(ok_any, n));
                        println!("    ... AND identifies the two starts    : {ok_start} / {n} ({:.1}%)", pc7(ok_start, n));
                    }
                    println!("  DOES A QUOTIENT AVOID THE UNION?  (of the systems needing a KA step)");
                        println!("    need a KA step directly : {nfail}");
                        println!("      a quotient ELIMINATES  : {}", byelim + byboth);
                        println!("      only Thompson helps    : {bythom}");
                        println!("      neither                : {neither}");
                    }
                    println!("  RESIDUE vs COVERED (search-reach shows ONLY a size gap):");
                        println!("    covered {nc}, residue {nr2}");
                        for t in 0..7 {
                            let a = if nc == 0 { 0.0 } else { cov[t] / nc as f64 };
                            let b = if nr2 == 0 { 0.0 } else { res[t] / nr2 as f64 };
                            println!("      {:<14} covered {:>7.3}   residue {:>7.3}   delta {:>+7.3}",
                                nm[t], a, b, b - a);
                        }
                    }
                    println!("  COMBINED SOUND TEST (eliminable OR Thompson):");
                    println!("    solvable : {comb} / {combn}");
                    println!("  IS THE QUOTIENT ITSELF THOMPSON?  (then it provably has a solution)");
                    println!("    unsolved quotients in pool : {fpool} / {fpn}  ({:.1}%)", pc3(fpool, fpn));
                    println!("    CONTROL, solved ones       : {spool} / {spn}  ({:.1}%)", pc3(spool, spn));
                    println!("  DISTANCE FROM GKAT (fewest KA-only elimination steps):");
                    for d in 1..5 { println!("    needs {d} KA step(s) : {}", dist[d]); }
                    println!("    still unsolved (>4) : {}", dist[5]);
                    println!("  ARE THE UNSOLVED QUOTIENTS EVEN SOLVABLE?  (necessary conditions)");
                    println!("    nested (finite kernel)      : {nst} / {expn}");
                    println!("    every state in the pool     : {allexp} / {expn}");
                    println!("    CONTROL, solved quotients   : {sexp} / {sexpn}   (base rate)");
                    println!("  THE UNSOLVED QUOTIENTS, vs the solved ones:");
                    println!("    failed  : {fn_}  two-halt {:.1}%  mean states {:.2}",
                        pc2(fh, fn_), if fn_ == 0 { 0.0 } else { fsz as f64 / fn_ as f64 });
                    println!("    solved  : {on2}  two-halt {:.1}%  mean states {:.2}",
                        pc2(oh2, on2), if on2 == 0 { 0.0 } else { osz as f64 / on2 as f64 });
                }
                phase("residue characterisation", &mut mark);
                println!("  SUM-QUOTIENT SOLVABILITY (the thesis route's obligation):");
                    println!("    Me+Mf quotients solved      : {good} / {tot}   (too big: {toobig})");
                    // THE BASE RATE.  The sums are 10-state automata but the test was
                    // validated on automata of at most 5 states.  If random automata of the
                    // same size also solve, 9245/9245 is not evidence of anything.
                    let mut rng: u64 = 0x9E3779B97F4A7C15;
                    let mut rnd = || { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; rng };
                    let mut rgood = 0usize; let rtot = 20000usize;
                    let mut rsample: Vec<Aut<NA>> = Vec::new();
                    for _ in 0..rtot {
                        let kk = 10usize;
                        let mut st = [[0u8; NA]; MAXK];
                        let mut hl = [0u8; MAXK];
                        // WELL-FORMEDNESS.  A GKAT automaton state either halts at an atom
                        // or steps at it, never both — `haltStepDisjoint`.  The first version
                        // of this control generated states doing both, which are not GKAT
                        // automata at all, so "must be rejected" was meaningless for them and
                        // the soundness figure was measured against a contaminated population.
                        for x in 0..kk {
                            hl[x] = 0;
                            for y in 0..NA {
                                match rnd() % 3 {
                                    0 => { hl[x] |= 1 << y; st[x][y] = 0; }
                                    1 => { st[x][y] = 0; }
                                    _ => {
                                        let r = 1 + rnd() % (kk as u64);
                                        st[x][y] = r as u8;
                                    }
                                }
                            }
                        }
                        rsample.push(Aut::<NA> { k: kk as u8, it: [1; NA], ih: 0, st, hl });
                    }
                    // Generation is sequential (an xorshift chain) but the checks are
                    // independent, so collect first and run the elimination in parallel.
                    rgood += rsample.par_iter().filter(|a| symbolic_eliminable(a)).count();
                    println!("    CONTROL random 10-state    : {rgood} / {rtot}   (base rate)");
                    // THE SHARPER CONTROL, from the same population: sums of ARBITRARY pool
                    // pairs, which are Thompson but generally NOT equivalent.  This separates
                    // "the pair is equivalent" from "both halves are Thompson".
                    let mut pgood = 0usize; let mut ptot = 0usize;
                    let mut psample: Vec<Aut<NA>> = Vec::new();
                    while ptot < 9245 {
                        let i = (rnd() as usize) % list.len();
                        let j = (rnd() as usize) % list.len();
                        if let Some(su) = sum_core(&list[i], &list[j]) {
                            ptot += 1;
                            psample.push(su);
                        }
                    }
                    pgood += psample.par_iter().filter(|a| symbolic_eliminable(a)).count();
                    println!("    CONTROL arbitrary pool sums: {pgood} / {ptot}   (Thompson, not equivalent)");
                }
                {
                    // THE DEGREE DISTRIBUTION, on the pool automata elimination cannot solve
                    // directly.  Every one of them HAS a solution (Theorem 4.5), so any
                    // failure here is elimination stalling, and the degree says how far.
                    let mut deg = [0usize; 5];
                    let mut unb = 0usize; let mut tot = 0usize;
                    for (i, a) in list.iter().enumerate() {
                        if i % step2 != 0 { continue; }
                        if symbolic_eliminable(a) { continue; }
                        tot += 1;
                        match elim_degree(a, 4) {
                            Some(d) if d < 5 => deg[d] += 1,
                            _ => unb += 1,
                        }
                    }
                    let mut appl = 0usize;
                    for (i, a) in list.iter().enumerate() {
                        if i % step2 != 0 || symbolic_eliminable(a) { continue; }
                        if unshare(a).is_some() { appl += 1; }
                    }
                    // ADJOIN A FLAG instead of a copy.  If one boolean closes them all, the
                    // extension has degree 2 and that is a structure theorem.
                    let mut rngf: u64 = 0x853C49E6748FEA9B;
                    let mut rndf = move || { rngf ^= rngf << 13; rngf ^= rngf >> 7; rngf ^= rngf << 17; rngf };
                    // 302 stalled automata x 3000 flag products was ~900k elimination calls,
                    // and the profile put the run's remaining time here.  The choices are
                    // independent per automaton, so draw them up front and check in parallel.
                    // The FILTER also runs elimination — over ~20000 sampled pool automata —
                    // so it has to be parallel too, not just the flag products inside it.
                    let sampled: Vec<Aut<NA>> = list.iter().enumerate()
                        .filter(|(i, _)| i % step2 == 0).map(|(_, a)| *a).collect();
                    let stalledv: Vec<Aut<NA>> = sampled.par_iter()
                        .filter(|a| !symbolic_eliminable(a)).copied().collect();
                    let stalled: Vec<(Aut<NA>, Vec<u64>)> = stalledv.into_iter()
                        .map(|a| (a, (0..3000).map(|_| rndf()).collect()))
                        .collect();
                    let ftot = stalled.len();
                    let flagged = stalled.par_iter().filter(|(a, choices)| {
                        choices.iter().any(|&c| match flag_product(a, c) {
                            Some(hp) => symbolic_eliminable(&hp),
                            None => false,
                        })
                    }).count();
                phase("sum-quotient + controls", &mut mark);
                    println!("  ADJOIN A BOOLEAN FLAG (Böhm-Jacopini's auxiliary variable):");
                    println!("    stalled automata closed by one flag : {flagged} / {ftot}");
                    // WHICH SHAPE STALLS?  With a base rate from the SAME population — pool
                    // automata that eliminate fine — so the feature is not read off the
                    // failures alone.  CF-GKAT (POPL 2025) extends GKAT with indicator
                    // variables precisely to handle EARLY TERMINATION IN A LOOP BODY, which is
                    // the pattern elimination stalls on here.
                    let (mut sh, mut sn, mut oh, mut on) = (0usize, 0usize, 0usize, 0usize);
                    for (i, a) in list.iter().enumerate() {
                        if i % step2 != 0 { continue; }
                        let th = two_halt_cycle(a).is_some();
                        if symbolic_eliminable(a) { on += 1; if th { oh += 1; } }
                        else { sn += 1; if th { sh += 1; } }
                    }
                    let pc = |x: usize, n: usize| if n == 0 { 0.0 } else { 100.0 * x as f64 / n as f64 };
                    let pc = |x: usize, n: usize| if n == 0 { 0.0 } else { 100.0 * x as f64 / n as f64 };
                    let (mut sc, mut oc) = (0usize, 0usize);
                    for (i, a) in list.iter().enumerate() {
                        if i % step2 != 0 { continue; }
                        let hc = halt_in_cycle(a);
                        if symbolic_eliminable(a) { if hc { oc += 1; } } else if hc { sc += 1; }
                    }
                phase("flag adjunction", &mut mark);
                    println!("  IS THE FRONTIER 'NOT SKIP-FREE'?  (halts inside a cycle)");
                    println!("    stalled  halting mid-cycle   : {sc} / {sn}  ({:.1}%)", pc(sc, sn));
                    println!("    eliminating, same feature    : {oc} / {on}  ({:.1}%)", pc(oc, on));
                    println!("  WHICH SHAPE STALLS ELIMINATION?  (two-halt cycle, with base rate)");
                    println!("    stalled  with two-halt cycle : {sh} / {sn}  ({:.1}%)", pc(sh, sn));
                    println!("    eliminating, same feature    : {oh} / {on}  ({:.1}%)", pc(oh, on));
                    println!("  DEGREE OF THE ADJUNCTION (pool automata elimination stalls on):");
                    println!("    unshare even applicable : {appl} / {tot}");
                    println!("    stalled            : {tot}");
                    for d in 1..5 { println!("    solvable after {d}   : {}", deg[d]); }
                    println!("    still unsolved (>4): {unb}");
                }
                phase("frontier + stall shape + degree", &mut mark);
                println!("  SYMBOLIC ELIMINATION on the bisimulation quotient (W0 + U5):");
                println!("    pool automata satisfying it : {sk} / {sn}   (must be all)");
                println!("    uncovered pullbacks         : {sr} / {srn}   (THE TARGET)");
                for a in list.iter() {
                    if !symbolic_eliminable(a) {
                        println!("    SYMB COUNTEREXAMPLE k={} it={:?}", a.k, &a.it[..NA]);
                        for i in 0..a.k as usize {
                            println!("      s{i}: st={:?} hl={:b}", &a.st[i][..NA], a.hl[i]);
                        }
                        break;
                    }
                }
                phase("pool validation: elimination", &mut mark);
                println!("  PEELABLE (Gaussian elimination solves the system, via W0):");
                println!("    pool automata satisfying it : {pk} / {pn}   (must be all)");
                println!("    uncovered pullbacks         : {pr} / {prn}   (THE TARGET)");
                for a in list.iter() {
                    if !peelable(a) {
                        println!("    PEEL COUNTEREXAMPLE k={} it={:?}", a.k, &a.it[..NA]);
                        for i in 0..a.k as usize {
                            println!("      s{i}: st={:?} hl={:b}", &a.st[i][..NA], a.hl[i]);
                        }
                        break;
                    }
                }
                phase("pool validation: peelable", &mut mark);
                println!("  LLEE (proved necessary: GkatLayeringProofs):");
                println!("    pool automata satisfying it : {lp} / {ln}   (must be all)");
                println!("    uncovered pullbacks         : {lr} / {lrn}");
                for a in list.iter() {
                    if !llee(a) {
                        println!("    LLEE COUNTEREXAMPLE k={} it={:?}", a.k, &a.it[..NA]);
                        for i in 0..a.k as usize {
                            println!("      s{i}: st={:?} hl={:b}", &a.st[i][..NA], a.hl[i]);
                        }
                        break;
                    }
                }
                phase("pool validation: llee", &mut mark);
                println!("  ORBIT ENTRY/HALT DISJOINTNESS as a necessary condition:");
                println!("    pool automata satisfying it : {eok} / {en}   (must be all)");
                println!("    uncovered pullbacks         : {ero} / {ern}");
                let mut sv = 0usize; let mut rd = 0usize; let mut nn = 0usize;
                for (i, a) in list.iter().enumerate() {
                    if i % step2 != 0 { continue; }
                    nn += 1;
                    if orbit_entry_single_valued(a) { sv += 1; }
                    if orbit_reduces(a) { rd += 1; }
                }
                let (mut rsv, mut rrd, mut rnn) = (0usize, 0usize, 0usize);
                for p in uncovered.iter() {
                    rnn += 1;
                    if orbit_entry_single_valued(p) { rsv += 1; }
                    if orbit_reduces(p) { rrd += 1; }
                }
                println!("  ENTRY SINGLE-VALUEDNESS as a necessary condition:");
                println!("    pool automata satisfying it : {sv} / {nn}   (must be all)");
                println!("    uncovered pullbacks         : {rsv} / {rnn}");
                println!("  ORBIT REDUCTION as a necessary condition:");
                println!("    pool automata satisfying it : {rd} / {nn}   (must be all)");
                println!("    uncovered pullbacks         : {rrd} / {rnn}");
                for tag in ["sv", "rd"] {
                    for a in list.iter() {
                        let bad = if tag == "sv" { !orbit_entry_single_valued(a) } else { !orbit_reduces(a) };
                        if bad {
                            println!("    {tag} COUNTEREXAMPLE k={} it={:?}", a.k, &a.it[..NA]);
                            for i in 0..a.k as usize {
                                println!("      s{i}: st={:?} hl={:b}", &a.st[i][..NA], a.hl[i]);
                            }
                            println!("      orbits={:?}", orbits(a));
                            break;
                        }
                    }
                }
                println!("  ORBIT-STABILITY as a necessary condition:");
                println!("    pool automata satisfying it : {ok} / {n}   (must be all)");
                let mut ro = 0usize; let mut rn = 0usize;
                for p in uncovered.iter() { rn += 1; if orbit_stable(p) { ro += 1; } }
                println!("    uncovered pullbacks         : {ro} / {rn}");
                for a in list.iter() {
                    if !orbit_stable(a) {
                        println!("    COUNTEREXAMPLE k={} it={:?}", a.k, &a.it[..NA]);
                        for i in 0..a.k as usize {
                            println!("      s{i}: st={:?} hl={:b}", &a.st[i][..NA], a.hl[i]);
                        }
                        println!("      orbits={:?}", orbits(a));
                        break;
                    }
                }
            }
            println!("  ORACLE VALIDATION (depth {depth}):");
            println!("    pool automata accepted   : {pos} / {posn}   (must be all)");
            for j in 0..=6 {
                if byk[j].1 > 0 { println!("      k={j}: {} / {}", byk[j].0, byk[j].1); }
            }
            println!("    non-pool <=K rejected    : {neg} / {negn}   (must be all)");
            // THE CONTROL for LLEE.  A necessary condition that accepts everything is
            // vacuous, so measure it on automata known NOT to be in the pool.
            println!("    LLEE non-pool rejected   : {lneg} / {negn}   (discrimination)");
            println!("    PEEL non-pool rejected   : {pneg} / {negn}   (discrimination)");
            println!("    SYMB non-pool rejected   : {sneg} / {negn}   (discrimination)");
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

/// **`PAD_BISIM_TRANSPORT`** (iteration 314).
///
/// 312 found that `hbisim` need not transport from a composite to its
/// components: two states of a component can be bisimilar in the WHOLE and not
/// in the PART, because `wh` and `seq` ADD transitions.  313 narrowed the corner
/// — the added transitions come LAST, so a divergence needs one component to
/// fire where the other does not, AND the second's entry step to match the
/// first's component step in both action and target class.
///
/// This decides whether that corner is inhabited.  Build the Thompson closure by
/// depth; at every composite, compare the coarsest bisimulation of the WHOLE
/// against each component's own.  A violation is the counterexample that settles
/// 312 and dictates the fix; no violation over a large closure is evidence the
/// corner is empty for Thompson automata, which is the only case the proof needs.
///
/// The composite is checked BEFORE canonicalisation — `canon` renumbers states,
/// which would destroy the alignment between a component's indices and its
/// offset in the composite.  Only the pooled copy is canonical.
fn transport_violation<const NA: usize>(
    a: &Aut<NA>, off: usize, p: &Aut<NA>,
) -> Option<(usize, usize)> {
    let (ba, _) = bisim_blocks(a);
    let (bp, _) = bisim_blocks(p);
    for s in 0..p.k as usize {
        for t in (s + 1)..p.k as usize {
            if ba[off + s] == ba[off + t] && bp[s] != bp[t] {
                return Some((s, t));
            }
        }
    }
    None
}

fn show_aut<const NA: usize>(tag: &str, a: &Aut<NA>) -> String {
    let mut out = format!("{tag} k={} ih={:0w$b} it=[", a.k, a.ih, w = NA);
    for i in 0..NA {
        out.push_str(&format!("{}{}", if i > 0 { "," } else { "" }, a.it[i]));
    }
    out.push(']');
    for s in 0..a.k as usize {
        out.push_str(&format!(" | q{s}: hl={:0w$b} st=[", a.hl[s], w = NA));
        for i in 0..NA {
            out.push_str(&format!("{}{}", if i > 0 { "," } else { "" }, a.st[s][i]));
        }
        out.push(']');
    }
    out
}

/// **`PAD_CROSS_CLASS`** (iteration 320).
///
/// 319 found that `LayeredOn.loop`'s `hentry`/`hclosed` are conditions on
/// CLASSES, not on transitions: a loop body's transitions stay inside the body,
/// but a body state's CLASS can contain a state from outside it, and then the
/// class lies in a block the loop is supposed to avoid.  That is what would make
/// a shared entry list "mixed", which fits neither `loop` nor `seq`.
///
/// So the decisive question is not about steps at all — it is whether a
/// component's states get identified with non-component states.  Count it.
/// Backward reachability from halting states: a state is PRODUCTIVE when some
/// run from it can halt.  A non-productive state is behaviourally `0`, so a
/// transition into one is dead weight in a guarded fold — which is why 322 asks
/// whether the split entry lists 321 found are made only of such targets.
fn productive_states<const NA: usize>(a: &Aut<NA>) -> [bool; MAXK] {
    let mut p = [false; MAXK];
    for s in 0..a.k as usize {
        if a.hl[s] != 0 { p[s] = true; }
    }
    loop {
        let mut changed = false;
        for s in 0..a.k as usize {
            if p[s] { continue; }
            for i in 0..NA {
                let t = a.st[s][i];
                if t != 0 && p[(t - 1) as usize] { p[s] = true; changed = true; break; }
            }
        }
        if !changed { break; }
    }
    p
}

/// **`PAD_BODY_COND`** (iteration 328).
///
/// 327 replaced the blanket `hout` by exactly two conditions: `hentry` at a
/// loop's entry targets — 322 measured that one favourably — and `hbody` at the
/// BODY's transition targets, which nothing has measured.
///
/// `hbody` says: for a class OUTSIDE the block, every transition target's class
/// is also outside the block, OR is stuck.  In the `ite` setting with the block
/// taken as "classes with a right-half preimage", that reads: **a purely-left
/// class never steps to a LIVE mixed class.**  320 measured cross-class
/// identification at 16%, so this is the condition most likely to fail, and it
/// is the one the `ite` assembly needs.
fn body_cond<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    {
        let a = a_act::<NA>();
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    for _ in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for r in &cur {
                if let Some(a) = a_seq::<NA>(l, r) {
                    if pool.len() < cap {
                        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                    }
                }
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        if pool.len() < cap {
                            if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                        }
                    }
                }
            }
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                if pool.len() < cap {
                    if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                }
            }
        }
        if pool.len() >= cap { break; }
    }
    let (mut steps, mut bad, mut bad_live) = (0usize, 0usize, 0usize);
    let mut first: Option<String> = None;
    for l in &pool {
        for r in &pool {
            for g in 0..nguards {
                if let Some(a) = a_ite::<NA>(g, l, r) {
                    let (blk, _) = bisim_blocks(&a);
                    let prod = productive_states(&a);
                    let mut in_c = [false; MAXK];
                    for t in l.k as usize..a.k as usize { in_c[blk[t]] = true; }
                    for u in 0..l.k as usize {
                        if in_c[blk[u]] { continue; }   // u's class is already in the block
                        for i in 0..NA {
                            let tv = a.st[u][i];
                            if tv == 0 { continue; }
                            let t = (tv - 1) as usize;
                            steps += 1;
                            if in_c[blk[t]] {
                                bad += 1;
                                if prod[t] {
                                    bad_live += 1;
                                    if first.is_none() {
                                        first = Some(format!(
                                            "q{u} -atom{i}-> q{t}: source class outside the \
                                             block, target class inside it and LIVE\n    {}\n    {}\n    {}",
                                            show_aut("whole", &a), show_aut("left ", l),
                                            show_aut("right", r)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Does the non-block region even CONTAIN a cycle?  If not, the acyclic-relative
    // constructor (288's solExt) applies — and it ALLOWS steps into the block, so
    // hbody's failure would be irrelevant.
    let (mut regions, mut cyclic) = (0usize, 0usize);
    for l in &pool {
        for r in &pool {
            for g in 0..nguards {
                if let Some(a) = a_ite::<NA>(g, l, r) {
                    let (blk, _) = bisim_blocks(&a);
                    let mut in_c = [false; MAXK];
                    for t in l.k as usize..a.k as usize { in_c[blk[t]] = true; }
                    // reachability within the non-block region, by closure
                    let k = a.k as usize;
                    let mut reach = [[false; MAXK]; MAXK];
                    for u in 0..k {
                        if in_c[blk[u]] { continue; }
                        for i in 0..NA {
                            let tv = a.st[u][i];
                            if tv == 0 { continue; }
                            let t = (tv - 1) as usize;
                            if !in_c[blk[t]] { reach[u][t] = true; }
                        }
                    }
                    for m in 0..k { for u in 0..k { if reach[u][m] {
                        for v in 0..k { if reach[m][v] { reach[u][v] = true; } }
                    } } }
                    regions += 1;
                    if (0..k).any(|u| !in_c[blk[u]] && reach[u][u]) { cyclic += 1; }
                }
            }
        }
    }
    println!("NON-BLOCK REGION: {regions} regions, {cyclic} contain a cycle ({:.2}%)",
        100.0 * cyclic as f64 / regions.max(1) as f64);
    println!("BODY COND: {steps} steps from a class outside the block; {bad} land inside it \
              ({:.2}%), of which {bad_live} have a LIVE target ({:.2}%)",
        100.0 * bad as f64 / steps.max(1) as f64,
        100.0 * bad_live as f64 / steps.max(1) as f64);
    match first {
        None => println!("  hbody HOLDS on this closure: every step out of a non-block class \
                          lands outside the block or on a dead state"),
        Some(msg) => println!("  FIRST VIOLATION\n    {msg}"),
    }
}

/// **`PAD_MIXED_ENTRY`** (iteration 321).
///
/// 320 showed cross-class identification is common, which makes the block
/// INTERSECT a component's image.  That alone is harmless: if ALL of a `wh`'s
/// entry targets land in the block the layer is `seq`-shaped, and if NONE do it
/// is `loop`-shaped.  **Only a SPLIT entry list fits neither constructor**, and
/// that is what this measures.
///
/// Build `ite g (wh g2 body) r`.  The block is the classes with a preimage in
/// the RIGHT half.  The `wh`'s back edges target the BODY's initial targets, at
/// the same state indices in the composite since `a_wh` keeps the body's states
/// and `a_ite` places the left half at offset 0.  Ask whether those targets'
/// classes fall on both sides of the block.
fn mixed_entry<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    {
        let a = a_act::<NA>();
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    for _ in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for r in &cur {
                if let Some(a) = a_seq::<NA>(l, r) {
                    if pool.len() < cap {
                        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                    }
                }
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        if pool.len() < cap {
                            if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                        }
                    }
                }
            }
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                if pool.len() < cap {
                    if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                }
            }
        }
        if pool.len() >= cap { break; }
    }
    let (mut total, mut multi, mut mixed) = (0usize, 0usize, 0usize);
    let mut mixed_live = 0usize;
    let mut first: Option<String> = None;
    let mut first_live: Option<String> = None;
    for body in &pool {
        for g2 in 0..nguards {
            let lw = a_wh::<NA>(g2, body);
            // the wh's back-edge targets, as state indices of the composite
            let mut tgts: Vec<usize> = Vec::new();
            for i in 0..NA {
                if bit(g2, i) && body.it[i] != 0 {
                    let t = (body.it[i] - 1) as usize;
                    if !tgts.contains(&t) { tgts.push(t); }
                }
            }
            if tgts.is_empty() { continue; }
            for r in &pool {
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, &lw, r) {
                        total += 1;
                        if tgts.len() > 1 { multi += 1; }
                        let (blk, _) = bisim_blocks(&a);
                        let mut in_c = [false; MAXK];
                        for t in lw.k as usize..a.k as usize { in_c[blk[t]] = true; }
                        let (mut any_in, mut any_out) = (false, false);
                        for &t in &tgts {
                            if in_c[blk[t]] { any_in = true; } else { any_out = true; }
                        }
                        if any_in && any_out {
                            mixed += 1;
                            let prod = productive_states(&a);
                            let live_in = tgts.iter().any(|&t| in_c[blk[t]] && prod[t]);
                            if live_in {
                                mixed_live += 1;
                                if first_live.is_none() {
                                    first_live = Some(format!(
                                        "guard {g2:0w$b}, entry targets {tgts:?}\n    {}\n    {}\n    {}",
                                        show_aut("whole", &a), show_aut("body ", body),
                                        show_aut("right", r), w = NA));
                                }
                            }
                            if first.is_none() {
                                first = Some(format!(
                                    "guard {g2:0w$b}, entry targets {tgts:?}\n    {}\n    {}\n    {}",
                                    show_aut("whole", &a), show_aut("body ", body),
                                    show_aut("right", r), w = NA));
                            }
                        }
                    }
                }
            }
        }
    }
    println!("MIXED ENTRY: {total} (wh-in-ite) configurations, {multi} with >1 distinct \
              entry target, {mixed} with a SPLIT entry list ({:.2}%)",
        100.0 * mixed as f64 / total.max(1) as f64);
    println!("  of those, {mixed_live} have a LIVE (productive) in-block entry target");
    match first {
        None => println!("  none: a wh's entry targets never straddle the block, so every \
                          layer is either loop-shaped or seq-shaped"),
        Some(msg) => println!("  FIRST SPLIT\n    {msg}"),
    }
    match first_live {
        None => println!("  NO LIVE SPLIT: every split entry list has only NON-PRODUCTIVE \
                          targets in the block, so pruning dead branches removes the \
                          configuration entirely"),
        Some(msg) => println!("  FIRST LIVE SPLIT\n    {msg}"),
    }
}

fn cross_class_count<const NA: usize>(a: &Aut<NA>, lo: usize, hi: usize) -> usize {
    let (blk, _) = bisim_blocks(a);
    let mut n = 0usize;
    for s in lo..hi {
        for t in 0..a.k as usize {
            if t >= lo && t < hi { continue; }
            if blk[s] == blk[t] { n += 1; }
        }
    }
    n
}

fn cross_class<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    {
        let a = a_act::<NA>();
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    let (mut comps, mut crossed) = (0usize, 0usize);
    let mut first: Option<String> = None;
    for round in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for r in &cur {
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        // the LEFT half is the component; is any of its states
                        // identified with a state of the right half?
                        comps += 1;
                        let n = cross_class_count(&a, 0, l.k as usize);
                        if n > 0 {
                            crossed += 1;
                            if first.is_none() {
                                first = Some(format!(
                                    "ite: {n} cross-half identifications\n    {}\n    {}\n    {}",
                                    show_aut("whole", &a), show_aut("left ", l),
                                    show_aut("right", r)));
                            }
                        }
                        if pool.len() < cap {
                            if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                        }
                    }
                }
                if let Some(a) = a_seq::<NA>(l, r) {
                    comps += 1;
                    if cross_class_count(&a, 0, l.k as usize) > 0 { crossed += 1; }
                    if pool.len() < cap {
                        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                    }
                }
            }
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                if pool.len() < cap {
                    if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                }
            }
        }
        println!("  round {round}: pool = {}, components = {comps}, with cross-class = {crossed}",
            pool.len());
        if pool.len() >= cap { break; }
    }
    println!("CROSS-CLASS: {comps} components, {crossed} with a state identified outside \
              the component ({:.1}%)",
        100.0 * crossed as f64 / comps.max(1) as f64);
    match first {
        None => println!("  none: a component's states are never identified with states \
                          outside it, so 319's mixed entry list cannot arise"),
        Some(msg) => println!("  FIRST\n    {msg}"),
    }
}

fn bisim_transport<const NA: usize>(nguards: u8, rounds: usize, cap: usize) {
    let mut pool: Vec<Aut<NA>> = Vec::new();
    let mut seen: FxSet<Aut<NA>> = FxSet::default();
    for g in 0..nguards {
        let a = a_test::<NA>(g);
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    {
        let a = a_act::<NA>();
        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
    }
    let (mut checked, mut bad) = (0usize, 0usize);
    let mut first: Option<String> = None;
    let mut note = |a: &Aut<NA>, parts: &[(usize, &Aut<NA>)], what: &str,
                    checked: &mut usize, bad: &mut usize, first: &mut Option<String>| {
        for &(off, p) in parts {
            *checked += 1;
            if let Some((s, t)) = transport_violation(a, off, p) {
                *bad += 1;
                if first.is_none() {
                    *first = Some(format!(
                        "{what}: component states q{s},q{t} (offset {off}) are bisimilar in the \
                         WHOLE but not in the PART\n    {}\n    {}",
                        show_aut("whole ", a), show_aut("part  ", p)));
                }
            }
        }
    };
    for round in 0..rounds {
        let cur: Vec<Aut<NA>> = pool.clone();
        for l in &cur {
            for g in 0..nguards {
                let a = a_wh::<NA>(g, l);
                note(&a, &[(0, l)], "wh", &mut checked, &mut bad, &mut first);
                if pool.len() < cap {
                    if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                }
            }
            for r in &cur {
                if let Some(a) = a_seq::<NA>(l, r) {
                    note(&a, &[(0, l), (l.k as usize, r)], "seq",
                        &mut checked, &mut bad, &mut first);
                    if pool.len() < cap {
                        if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                    }
                }
                for g in 0..nguards {
                    if let Some(a) = a_ite::<NA>(g, l, r) {
                        note(&a, &[(0, l), (l.k as usize, r)], "ite",
                            &mut checked, &mut bad, &mut first);
                        if pool.len() < cap {
                            if let Some(c) = canon(&a) { if seen.insert(c) { pool.push(c); } }
                        }
                    }
                }
            }
        }
        println!("  round {round}: pool = {}, component-checks = {checked}, violations = {bad}",
            pool.len());
        if pool.len() >= cap { break; }
    }
    println!("BISIM TRANSPORT: {checked} component-checks, {bad} violations");
    match first {
        None => println!("  no counterexample: the coarsest bisimulation of a Thompson \
                          composite never identifies two component states that the \
                          component's own bisimulation separates"),
        Some(msg) => println!("  FIRST VIOLATION\n    {msg}"),
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

/// **TESTING `QuotientClosure` DIRECTLY** (iteration 227).
///
/// 226 reduced the entire remainder to one property: a solvable automaton has a
/// solvable behavioural quotient.  223 tested only the FULL collapse; the
/// property quantifies over EVERY behavioural quotient, so test the whole
/// congruence lattice.  A Thompson automaton of a random expression is solvable
/// by construction, so every quotient of it must be solvable if the property
/// holds — and a single failure refutes the route cheaply, which is the point of
/// running this before writing any Lean.
fn closure_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x5150_ABCD_9876_4321;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut auts, mut quots, mut bad) = (0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..20_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        let solve = |q: &Aut<NA>| -> bool {
            let sing = singleton_states(q);
            sccs_of(q).iter().all(|c| c.len() < 2
                || calculus_solves(q, c, 6)
                || calculus_solves(q, &scc_with_context(q, c, &sing), 6))
        };
        if !solve(&a) { continue; }          // only test genuinely solvable ones
        auts += 1;
        for (blk, nb) in lattice_congruences(&a) {
            let q = match quotient_by(&a, &blk, nb) { Some(q) => q, None => continue };
            quots += 1;
            if !solve(&q) {
                bad += 1;
                if shown < 3 {
                    shown += 1;
                    println!("    CLOSURE FAILS: {} states -> {} states", a.k, nb);
                    for s in 0..(q.k as usize) {
                        let row: Vec<String> = (0..NA).map(|i| {
                            let t = q.st[s][i];
                            if t == 0 { "-".to_string() } else { format!("c{}", t - 1) }
                        }).collect();
                        println!("      c{s}: hl={:03b} st=[{}]", q.hl[s], row.join(","));
                    }
                }
            }
        }
    }
    println!("  closure_test NA={NA}: {auts} solvable Thompson automata; \
        {quots} behavioural quotients checked; QuotientClosure FAILURES: {bad}");
}

/// **THE GKAT TRANSLATION OF LLEE'S LOOP CONDITION** (iteration 228).
///
/// Milner's LLEE forbids successful termination mid-loop — you leave a loop only
/// at its head.  GKAT inlines the head into the body's exit points, and
/// `loop_core_hlt` (proved `rfl` at 220) says how: in `wh b e`, EVERY body state
/// halts exactly at `hlt_body ∧ ¬b`, and every back edge fires exactly at
/// `hlt_body ∧ b`.  So one guard `b` separates staying from leaving, UNIFORMLY
/// across the whole loop.
///
/// As a property of the graph alone: an SCC has a uniform guard if, taking `b`
/// to be the atoms on which it moves internally, no state of the SCC halts
/// inside `b` and no transition leaves the SCC inside `b`.  Equivalently, `b`
/// tells you "stay" and `¬b` tells you "go", the same way at every state.
///
/// This is the candidate certificate: a property of the transition graph, not of
/// any solution — which is what role-coverage could not be, and what has to be
/// true if the certificate is to survive collapse.
fn uniform_guard<const NA: usize>(q: &Aut<NA>, scc: &[usize]) -> bool {
    let inscc = |t: usize| scc.contains(&t);
    let mut b: u8 = 0;
    for &s in scc.iter() {
        for a in 0..NA {
            let t = q.st[s][a];
            if t != 0 && inscc((t - 1) as usize) { b |= 1 << a; }
        }
    }
    for &s in scc.iter() {
        for a in 0..NA {
            if b >> a & 1 == 0 { continue; }
            if q.hl[s] >> a & 1 == 1 { return false; }      // halts inside the guard
            let t = q.st[s][a];
            if t == 0 { return false; }                      // rejects inside the guard
            if !inscc((t - 1) as usize) { return false; }    // leaves inside the guard
        }
    }
    true
}

/// Test the candidate certificate on the three things it must satisfy.
fn llee_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x9E3779B97F4A7C15;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut thom, mut coll, mut agree, mut ug_not_sol, mut sol_not_ug) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..60_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        let ug = |q: &Aut<NA>| sccs_of(q).iter().all(|c| c.len() < 2 || uniform_guard(q, c));
        let solve = |q: &Aut<NA>| -> bool {
            let sing = singleton_states(q);
            sccs_of(q).iter().all(|c| c.len() < 2
                || calculus_solves(q, c, 6)
                || calculus_solves(q, &scc_with_context(q, c, &sing), 6))
        };
        n += 1;
        // (a) every Thompson automaton should satisfy it
        if ug(&a) { thom += 1; }
        // (b) preserved by bisimulation collapse
        let (blk, nb) = bisim_blocks(&a);
        if let Some(q) = quotient_by(&a, &blk, nb) {
            if !ug(&a) || ug(&q) { coll += 1; }
            // (c) does it coincide with calculus-solvability?
            let (u, s) = (ug(&q), solve(&q));
            if u == s { agree += 1; }
            else if u { ug_not_sol += 1; } else { sol_not_ug += 1; }
        }
    }
    println!("  llee_test NA={NA}: {n} Thompson automata; \
        (a) uniform-guard holds on {thom}; (b) survives collapse {coll}; \
        (c) on collapses: agrees with solvable {agree}, \
        guard-but-UNsolvable {ug_not_sol}, solvable-but-NO-guard {sol_not_ug}");
}

/// **WHY DOES `uniform_guard` FAIL?** (iteration 229.)  228 asserted the ~10%
/// failures are NESTED loops.  That was asserted, not measured, and the algebra
/// suggests a plainer cause: at a body state the internally-moving atoms are
/// `bodymove(s) ∪ (hlt(s) ∩ b)`, and BOTH parts vary per state, so demanding one
/// uniform set across a whole SCC may be too strong regardless of nesting.
/// Classify the failures instead of guessing.
fn guard_diag<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0xDEADBEEF_12345678;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut bad, mut by_halt, mut by_reject, mut by_leave, mut nested_scc) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..60_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        for c in sccs_of(&a) {
            if c.len() < 2 || uniform_guard(&a, &c) { continue; }
            bad += 1;
            let inscc = |t: usize| c.contains(&t);
            let mut b: u8 = 0;
            for &s in c.iter() {
                for y in 0..NA {
                    let t = a.st[s][y];
                    if t != 0 && inscc((t - 1) as usize) { b |= 1 << y; }
                }
            }
            let (mut h, mut r, mut l) = (false, false, false);
            for &s in c.iter() {
                for y in 0..NA {
                    if b >> y & 1 == 0 { continue; }
                    if a.hl[s] >> y & 1 == 1 { h = true; continue; }
                    let t = a.st[s][y];
                    if t == 0 { r = true; }
                    else if !inscc((t - 1) as usize) { l = true; }
                }
            }
            if h { by_halt += 1; }
            if r { by_reject += 1; }
            if l { by_leave += 1; }
            // NESTING TEST: does the SCC break into >1 nontrivial sub-SCC after
            // removing SOME state's incoming edges?  A nested loop does.
            let mut sub = a;
            for &s in c.iter() {
                for y in 0..NA {
                    let t = sub.st[s][y];
                    if t != 0 && !inscc((t - 1) as usize) { sub.st[s][y] = 0; }
                }
            }
            let inner = sccs_of(&sub).iter().filter(|d| d.len() >= 2 && d.len() < c.len()).count();
            if inner > 0 { nested_scc += 1; }
        }
    }
    println!("  guard_diag NA={NA}: {bad} failing SCCs; \
        cause halt-inside-guard {by_halt}, reject-inside {by_reject}, \
        leave-inside {by_leave}; contain a proper inner loop (NESTED) {nested_scc}");
}

/// **THE GUARD, READ OFF THE ENTRY EDGES** (iteration 230).
///
/// 229 showed the union over INTERNAL transitions is the wrong guard: a body's
/// own steps happen at atoms unrelated to the loop guard.  The right one comes
/// from `loopInitialized`, where the loop's ENTRY transitions (from outside) and
/// its BACK EDGES are the same list — `body.initTrans` — guarded by `b`.  They
/// land on the same targets, so the guard is recoverable from the graph as:
///
///     b := the atoms on which the SCC is entered from OUTSIDE it
///          (including from the initial pseudostate)
///
/// and `loop_core_hlt` (`rfl`, 220) then predicts, sharply: **no state of a loop
/// halts at an atom inside its entry guard**, because a loop's halt is
/// `hlt_body ∧ ¬b`.  Falsifiable, and it should hold on EVERY Thompson
/// automaton if the reading is right.
fn entry_guard<const NA: usize>(q: &Aut<NA>, scc: &[usize]) -> u8 {
    let inscc = |t: usize| scc.contains(&t);
    let mut b: u8 = 0;
    for y in 0..NA {
        // from the initial pseudostate
        let t = q.it[y];
        if t != 0 && inscc((t - 1) as usize) { b |= 1 << y; }
        // from any state outside the SCC
        for s in 0..(q.k as usize) {
            if inscc(s) { continue; }
            let t = q.st[s][y];
            if t != 0 && inscc((t - 1) as usize) { b |= 1 << y; }
        }
    }
    b
}

fn entry_guard_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x243F6A8885A308D3;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut sccs_n, mut ok, mut empty_b, mut coll_ok, mut coll_n) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..60_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        let check = |q: &Aut<NA>| -> (usize, usize, usize) {
            let (mut n, mut good, mut eb) = (0, 0, 0);
            for c in sccs_of(q) {
                if c.len() < 2 { continue; }
                n += 1;
                let b = entry_guard(q, &c);
                if b == 0 { eb += 1; }
                if c.iter().all(|&s| q.hl[s] & b == 0) { good += 1; }
            }
            (n, good, eb)
        };
        let (n, g, eb) = check(&a);
        sccs_n += n; ok += g; empty_b += eb;
        if g < n && shown < 3 {
            shown += 1;
            println!("    ENTRY-GUARD VIOLATED, k={}:", a.k);
            for s in 0..(a.k as usize) {
                let row: Vec<String> = (0..NA).map(|i| {
                    let t = a.st[s][i];
                    if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                }).collect();
                println!("      q{s}: hl={:03b} st=[{}]", a.hl[s], row.join(","));
            }
        }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(q) = quotient_by(&a, &blk, nb) {
            let (n2, g2, _) = check(&q);
            coll_n += n2; coll_ok += g2;
        }
    }
    println!("  entry_guard_test NA={NA}: {sccs_n} loop SCCs; \
        no-halt-inside-entry-guard holds on {ok}; entry guard empty on {empty_b}; \
        after collapse {coll_ok}/{coll_n}");
}

/// **A GUARD PER LOOP, NOT PER SCC** (iteration 231).
///
/// 230 established the constraint: an SCC is not a loop, so no per-SCC guard can
/// be right.  Loop structure lives at TRANSITION granularity, which is why LLEE
/// labels edges.  The standard construction at that granularity is the natural
/// loop of a DFS back edge: for a back edge `s -a-> h` (target `h` an ancestor
/// of `s` on the DFS stack), `h` is a loop HEADER and its natural loop is `{h}`
/// together with every state that can reach `s` without passing through `h`.
///
/// Then the guard of that loop is the atoms on which its back edges fire, and
/// `loop_core_hlt` (`rfl`, 220) predicts: **no state of the natural loop halts
/// at an atom of its own loop guard**, because a loop's halt is `hlt ∧ ¬b`.
/// This is the same prediction as 230's, now asked at the granularity the
/// structure actually has.
fn natural_loops<const NA: usize>(q: &Aut<NA>) -> Vec<(usize, Vec<usize>, u8)> {
    let k = q.k as usize;
    // iterative DFS recording back edges (target on the current stack)
    let mut onstack = vec![false; k];
    let mut visited = vec![false; k];
    let mut back: Vec<(usize, usize, u8)> = Vec::new();   // (from, header, atom)
    let mut stack: Vec<(usize, usize)> = Vec::new();      // (state, next atom index)
    for root in 0..k {
        if visited[root] { continue; }
        visited[root] = true; onstack[root] = true;
        stack.push((root, 0));
        while let Some(&mut (s, ref mut i)) = stack.last_mut() {
            if *i >= NA { onstack[s] = false; stack.pop(); continue; }
            let y = *i; *i += 1;
            let t = q.st[s][y];
            if t == 0 { continue; }
            let t = (t - 1) as usize;
            if onstack[t] { back.push((s, t, y as u8)); }
            else if !visited[t] {
                visited[t] = true; onstack[t] = true; stack.push((t, 0));
            }
        }
    }
    // group back edges by header, build each natural loop
    let mut out: Vec<(usize, Vec<usize>, u8)> = Vec::new();
    let mut headers: Vec<usize> = back.iter().map(|e| e.1).collect();
    headers.sort_unstable(); headers.dedup();
    for h in headers {
        let mut b: u8 = 0;
        let mut body: Vec<usize> = vec![h];
        for &(s, hh, y) in back.iter() {
            if hh != h { continue; }
            b |= 1 << y;
            // states reaching s without passing through h
            if !body.contains(&s) { body.push(s); }
            let mut i = 0;
            while i < body.len() {
                let x = body[i]; i += 1;
                if x == h { continue; }
                for p in 0..(q.k as usize) {
                    if p == h || body.contains(&p) { continue; }
                    if (0..NA).any(|y2| q.st[p][y2] == (x + 1) as u8) { body.push(p); }
                }
            }
        }
        // 231: the guard is read off the BACK EDGES.  Reading it instead off
        // the header.s own moves into the body — which one violating example
        // suggested — measured WORSE (96.3/94.2/92.6% against 99.8/99.4/99.0%),
        // so that generalisation from a single case is wrong and this stands.
        out.push((h, body, b));
    }
    out
}

fn loopguard_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x13198A2E03707344;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut ok, mut cn, mut cok) = (0usize, 0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..60_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        let check = |q: &Aut<NA>| -> (usize, usize) {
            let mut good = 0; let mut tot = 0;
            for (_h, body, b) in natural_loops(q) {
                tot += 1;
                if body.iter().all(|&s| q.hl[s] & b == 0) { good += 1; }
            }
            (tot, good)
        };
        let (t, g) = check(&a);
        n += t; ok += g;
        if g < t && shown < 2 {
            shown += 1;
            println!("    LOOP-GUARD VIOLATED, k={}:", a.k);
            for s in 0..(a.k as usize) {
                let row: Vec<String> = (0..NA).map(|i| {
                    let x = a.st[s][i];
                    if x == 0 { "-".to_string() } else { format!("q{}", x - 1) }
                }).collect();
                println!("      q{s}: hl={:03b} st=[{}]", a.hl[s], row.join(","));
            }
            for (h, body, b) in natural_loops(&a) {
                println!("      loop header q{h} guard={b:03b} body={body:?}");
            }
        }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            let (t2, g2) = check(&qq); cn += t2; cok += g2;
        }
    }
    println!("  loopguard_test NA={NA}: {n} natural loops; \
        no-halt-inside-loop-guard holds on {ok}; after collapse {cok}/{cn}");
}

/// **LAYERED LOOP ELIMINATION — the "L" in LLEE** (iteration 232).
///
/// 231 got `loop_core_hlt`'s prediction to ~99% at natural-loop granularity, and
/// diagnosed the residual as NESTING: an inner loop inside an outer one, where
/// the outer guard must be computed only AFTER the inner loop is eliminated.
/// Worked example from 231:
///
///     q0: hl={a3} st=[q1,q0,q0,-]      q1: hl={a2,a3} st=[q1,q0,-,-]
///
/// Read flat, the outer loop's back edges give a guard containing `a2`, and
/// `q1` halts there — a violation.  Eliminate the inner self-loop `q1 -a0-> q1`
/// first and `q1` becomes `st=[-,q0,-,-]`; the outer back edge is then `q1 -a1->
/// q0` alone, guard `{a1}`, and both states' halts lie outside it.
///
/// So: repeatedly take the INNERMOST loops, check the halt condition against
/// their own guard, remove their back edges, and continue on the reduced graph.
/// The automaton has the property iff this runs to an acyclic graph without a
/// violation.
fn llee_layered<const NA: usize>(q: &Aut<NA>) -> bool {
    let mut g = *q;
    loop {
        let loops = natural_loops(&g);
        if loops.is_empty() { return true; }
        let mut progressed = false;
        for (h, body, b) in loops.iter() {
            // innermost: no OTHER loop's body is strictly contained in this one
            let innermost = !loops.iter().any(|(h2, body2, _)| {
                h2 != h && body2.len() < body.len()
                    && body2.iter().all(|s| body.contains(s))
            });
            if !innermost { continue; }
            if body.iter().any(|&s| g.hl[s] & b != 0) { return false; }
            for &s in body.iter() {
                for y in 0..NA {
                    if b >> y & 1 == 0 { continue; }
                    if g.st[s][y] == (*h + 1) as u8 { g.st[s][y] = 0; }
                }
            }
            progressed = true;
        }
        if !progressed { return false; }
    }
}

fn layered_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0xA4093822299F31D0;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut a_ok, mut b_ok, mut agree, mut l_not_s, mut s_not_l) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..60_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        n += 1;
        if llee_layered(&a) { a_ok += 1; }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            if !llee_layered(&a) || llee_layered(&qq) { b_ok += 1; }
            let solve = {
                let sing = singleton_states(&qq);
                sccs_of(&qq).iter().all(|c| c.len() < 2
                    || calculus_solves(&qq, c, 6)
                    || calculus_solves(&qq, &scc_with_context(&qq, c, &sing), 6))
            };
            let l = llee_layered(&qq);
            if l == solve { agree += 1; }
            else if l { l_not_s += 1; } else { s_not_l += 1; }
        }
    }
    println!("  layered_test NA={NA}: {n} Thompson automata; \
        (a) layered-LLEE holds on {a_ok}; (b) survives collapse {b_ok}; \
        (c) agrees with solvable {agree}, LLEE-but-UNsolvable {l_not_s}, \
        solvable-but-no-LLEE {s_not_l}");
}

/// **LLEE AS AN EXISTENTIAL OVER LABELLINGS** (iteration 233).
///
/// 232's test committed to one elimination order — innermost-first natural
/// loops of a particular DFS — which made it a sound SUFFICIENT test rather than
/// a decision procedure, and explained both its shortfalls at once: it reports
/// failure whenever the canonical labelling fails, even when another labelling
/// would succeed.
///
/// LLEE asks whether SOME valid labelling exists, so search: at each step, try
/// eliminating ANY eligible loop, and succeed if any order runs to an acyclic
/// graph.  A loop is eligible when no state of its body halts inside its own
/// guard — the `loop_core_hlt` condition — and eliminating it removes its back
/// edges, after which loops that were not DFS-natural before may become so.
fn llee_exists<const NA: usize>(g: &Aut<NA>, budget: &mut usize) -> bool {
    if *budget == 0 { return false; }
    *budget -= 1;
    let loops = natural_loops(g);
    if loops.is_empty() { return true; }
    for (h, body, b) in loops.iter() {
        if body.iter().any(|&s| g.hl[s] & b != 0) { continue; }   // ineligible
        let mut g2 = *g;
        for &s in body.iter() {
            for y in 0..NA {
                if b >> y & 1 == 0 { continue; }
                if g2.st[s][y] == (*h + 1) as u8 { g2.st[s][y] = 0; }
            }
        }
        if g2.st == g.st { continue; }                            // no progress
        if llee_exists(&g2, budget) { return true; }
    }
    false
}

fn exists_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x082EFA98EC4E6C89;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut a_ok, mut b_ok, mut agree, mut l_not_s, mut s_not_l) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..40_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        n += 1;
        let mut bud = 20_000usize;
        let la = llee_exists(&a, &mut bud);
        if la { a_ok += 1; }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            let mut bud2 = 20_000usize;
            let lq = llee_exists(&qq, &mut bud2);
            if !la || lq { b_ok += 1; }
            let solve = {
                let sing = singleton_states(&qq);
                sccs_of(&qq).iter().all(|c| c.len() < 2
                    || calculus_solves(&qq, c, 6)
                    || calculus_solves(&qq, &scc_with_context(&qq, c, &sing), 6))
            };
            if lq == solve { agree += 1; }
            else if lq { l_not_s += 1; } else { s_not_l += 1; }
        }
    }
    println!("  exists_test NA={NA}: {n} Thompson automata; \
        (a) LLEE-exists holds on {a_ok}; (b) survives collapse {b_ok}; \
        (c) agrees with solvable {agree}, LLEE-but-UNsolvable {l_not_s}, \
        solvable-but-no-LLEE {s_not_l}");
}

/// **SEARCH THE GUARD TOO** (iteration 234).
///
/// Derived from `loopInitialized` rather than guessed: the ONLY edges a loop
/// adds are back edges guarded by `hlt_body(s) ∧ guard ∧ gᵢ`, and the loop's
/// halt is `hlt_body(s) ∧ ¬guard`.  So back edges lie INSIDE the guard and halts
/// lie OUTSIDE it — which is the condition tested since 228.  The condition is
/// right.  What is approximate is the graph-level RECOVERY of which edges are
/// back edges and what the guard is: an added back edge is indistinguishable
/// from a body edge whenever the body has a similar one.
///
/// 233 searched elimination ORDERS but always took the guard to be the atoms of
/// the natural loop's back edges.  Search the guard as well: for each loop
/// header, try every candidate guard `b`, designate as back edges exactly the
/// edges into the header at atoms of `b`, and require no body state to halt
/// inside `b`.
fn llee_guard_search<const NA: usize>(g: &Aut<NA>, budget: &mut usize) -> bool {
    if *budget == 0 { return false; }
    *budget -= 1;
    let loops = natural_loops(g);
    if loops.is_empty() { return true; }
    let all: u8 = if NA >= 8 { 0xFF } else { ((1u16 << NA) - 1) as u8 };
    for (h, body, _) in loops.iter() {
        for b in 1..=all {
            // the guard must cover at least one edge into the header
            let mut fires = false;
            for &s in body.iter() {
                for y in 0..NA {
                    if b >> y & 1 == 1 && g.st[s][y] == (*h + 1) as u8 { fires = true; }
                }
            }
            if !fires { continue; }
            if body.iter().any(|&s| g.hl[s] & b != 0) { continue; }
            let mut g2 = *g;
            for &s in body.iter() {
                for y in 0..NA {
                    if b >> y & 1 == 0 { continue; }
                    if g2.st[s][y] == (*h + 1) as u8 { g2.st[s][y] = 0; }
                }
            }
            if g2.st == g.st { continue; }
            if llee_guard_search(&g2, budget) { return true; }
        }
    }
    false
}

fn guardsearch_test<const NA: usize>(nguards: u8) {
    let table = synth_table::<NA>(synth_size(), seq_len(NA));
    let mut st0: u64 = 0xBE5466CF34E90C6C;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut a_ok, mut b_ok, mut l_not_s, mut s_not_l) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..30_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        n += 1;
        let mut bud = 60_000usize;
        let la = llee_guard_search(&a, &mut bud);
        if la { a_ok += 1; }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            let mut b2 = 60_000usize;
            let lq = llee_guard_search(&qq, &mut b2);
            if !la || lq { b_ok += 1; }
            let solve = {
                let sing = singleton_states(&qq);
                sccs_of(&qq).iter().all(|c| c.len() < 2
                    || calculus_solves(&qq, c, 6)
                    || calculus_solves(&qq, &scc_with_context(&qq, c, &sing), 6))
            };
            let witness = synth_lookup(&table, &qq, 0, seq_len(NA)).is_some();
            if lq && !solve {
                l_not_s += 1;
                println!("    CERT HOLDS, CALCULUS FAILS — synth witness: {}",
                    if witness { "EXISTS (so this is a CALCULUS gap)" }
                    else { "none at this size bound (certificate SUSPECT)" });
                for s in 0..(qq.k as usize) {
                    let row: Vec<String> = (0..NA).map(|i| {
                        let t = qq.st[s][i];
                        if t == 0 { "-".to_string() } else { format!("c{}", t - 1) }
                    }).collect();
                    println!("      c{s}: hl={:03b} st=[{}]", qq.hl[s], row.join(","));
                }
            }
            if solve && !lq { s_not_l += 1; }
        }
    }
    println!("  guardsearch_test NA={NA}: {n} Thompson automata; \
        (a) holds on {a_ok}; (b) survives collapse {b_ok}; \
        (c) cert-but-UNsolvable {l_not_s}, solvable-but-no-cert {s_not_l}");
}

/// **LOOP SUB-CHARTS, ENUMERATED DIRECTLY** (iteration 236).
///
/// 235 localised the residual to the candidate GENERATOR: DFS natural loops are
/// strictly narrower than LLEE's loop sub-charts, and 233/234 both searched over
/// natural loops, so both ranged over the wrong axis.
///
/// LLEE's notion: a loop sub-chart is a body `B` with an entry `h ∈ B` such that
/// every edge into `B` from OUTSIDE `B` targets `h` — single entry, but `B` need
/// not be what a DFS discovers.  Enumerate those directly (subsets of each SCC),
/// take the guard from the edges of `B` back into `h`, require no state of `B` to
/// halt inside it, eliminate, recurse.
fn loop_subcharts<const NA: usize>(g: &Aut<NA>) -> Vec<(usize, Vec<usize>, u8)> {
    let k = g.k as usize;
    let mut out = Vec::new();
    for c in sccs_of(g) {
        if c.len() > 12 { continue; }
        for mask in 1u32..(1u32 << c.len()) {
            let b: Vec<usize> = c.iter().enumerate()
                .filter(|(i, _)| mask >> i & 1 == 1).map(|(_, &s)| s).collect();
            for &h in b.iter() {
                // single entry: every edge from outside B into B lands on h
                let mut ok = true;
                for s in 0..k {
                    if b.contains(&s) { continue; }
                    for y in 0..NA {
                        let t = g.st[s][y];
                        if t == 0 { continue; }
                        let t = (t - 1) as usize;
                        if b.contains(&t) && t != h { ok = false; }
                    }
                }
                if !ok { continue; }
                // guard: atoms on which B steps back into h
                let mut gd: u8 = 0;
                for &s in b.iter() {
                    for y in 0..NA {
                        if g.st[s][y] == (h + 1) as u8 { gd |= 1 << y; }
                    }
                }
                if gd == 0 { continue; }
                out.push((h, b.clone(), gd));
            }
        }
    }
    out
}

fn llee_subchart<const NA: usize>(g: &Aut<NA>, budget: &mut usize) -> bool {
    if *budget == 0 { return false; }
    *budget -= 1;
    if sccs_of(g).iter().all(|c| c.len() < 2
        && !(0..NA).any(|y| g.st[c[0]][y] == (c[0] + 1) as u8)) { return true; }
    for (h, body, gd) in loop_subcharts(g) {
        if body.iter().any(|&s| g.hl[s] & gd != 0) { continue; }
        let mut g2 = *g;
        for &s in body.iter() {
            for y in 0..NA {
                if gd >> y & 1 == 1 && g2.st[s][y] == (h + 1) as u8 { g2.st[s][y] = 0; }
            }
        }
        if g2.st == g.st { continue; }
        if llee_subchart(&g2, budget) { return true; }
    }
    false
}

fn subchart_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x452821E638D01377;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut a_ok, mut b_ok, mut l_not_s, mut s_not_l) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..8_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        n += 1;
        let mut bud = 2_000_000usize;
        let la = llee_subchart(&a, &mut bud);
        if la { a_ok += 1; }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            let mut b2 = 2_000_000usize;
            let lq = llee_subchart(&qq, &mut b2);
            if !la || lq { b_ok += 1; }
            let solve = {
                let sing = singleton_states(&qq);
                sccs_of(&qq).iter().all(|c| c.len() < 2
                    || calculus_solves(&qq, c, 6)
                    || calculus_solves(&qq, &scc_with_context(&qq, c, &sing), 6))
            };
            if lq && !solve { l_not_s += 1; }
            if solve && !lq { s_not_l += 1; }
        }
    }
    println!("  subchart_test NA={NA}: {n} Thompson automata; \
        (a) holds on {a_ok}; (b) survives collapse {b_ok}; \
        (c) cert-but-UNsolvable {l_not_s}, solvable-but-no-cert {s_not_l}");
}

/// **LLEE'S ACTUAL CONDITIONS** (iteration 237), from the paper rather than
/// reconstructed.  A loop sub-chart with start vertex `vₛ` must satisfy:
///
///   (L1) there is an infinite path from `vₛ`;
///   (L2) EVERY infinite path from `vₛ` RETURNS to `vₛ` after a positive number
///        of transitions;
///   (L3) immediate termination is only permitted at `vₛ`  (`↓ ⊆ {vₛ}`).
///
/// **(L2) is the condition I never implemented across five formulations.**  It
/// says `vₛ` CUTS EVERY CYCLE in the body — no cycle may avoid the head — which
/// is exactly what forbids mutually nested loops, and 236 diagnosed dropping
/// that as the cause of both soundness breaks.
///
/// (L3) is the halt condition tested since 228, in its guarded relativisation:
/// Milner's `↓` is a state property while GKAT's `hlt` is a TEST, so "terminates"
/// becomes "terminates within the loop's guard", i.e. `hlt(s) ∩ b = ∅` for body
/// states.
fn llee_subcharts_L123<const NA: usize>(g: &Aut<NA>) -> Vec<(usize, Vec<usize>, u8)> {
    let mut out = Vec::new();
    for c in sccs_of(g) {
        if c.len() > 10 { continue; }
        for mask in 1u32..(1u32 << c.len()) {
            let body: Vec<usize> = c.iter().enumerate()
                .filter(|(i, _)| mask >> i & 1 == 1).map(|(_, &s)| s).collect();
            for &h in body.iter() {
                // guard: atoms on which the body steps back into h  (L1: nonempty)
                let mut gd: u8 = 0;
                for &s in body.iter() {
                    for y in 0..NA {
                        if g.st[s][y] == (h + 1) as u8 { gd |= 1 << y; }
                    }
                }
                if gd == 0 { continue; }
                // (L2) every cycle in the body passes through h: the induced
                // subgraph on body \ {h} must be ACYCLIC.
                let rest: Vec<usize> = body.iter().copied().filter(|&s| s != h).collect();
                let mut acyclic = true;
                {
                    let mut indeg: Vec<usize> = rest.iter().map(|&v| rest.iter()
                        .filter(|&&u| (0..NA).any(|y| g.st[u][y] == (v + 1) as u8))
                        .count()).collect();
                    let mut removed = vec![false; rest.len()];
                    let mut progress = true;
                    while progress {
                        progress = false;
                        for i in 0..rest.len() {
                            if removed[i] || indeg[i] != 0 { continue; }
                            removed[i] = true; progress = true;
                            for j in 0..rest.len() {
                                if removed[j] { continue; }
                                if (0..NA).any(|y| g.st[rest[i]][y] == (rest[j] + 1) as u8) {
                                    indeg[j] -= 1;
                                }
                            }
                        }
                    }
                    if removed.iter().any(|&r| !r) { acyclic = false; }
                }
                if !acyclic { continue; }
                out.push((h, body.clone(), gd));
            }
        }
    }
    out
}

fn llee_L123<const NA: usize>(g: &Aut<NA>, budget: &mut usize) -> bool {
    if *budget == 0 { return false; }
    *budget -= 1;
    let cyclic = sccs_of(g).iter().any(|c| c.len() >= 2
        || (0..NA).any(|y| g.st[c[0]][y] == (c[0] + 1) as u8));
    if !cyclic { return true; }
    for (h, body, gd) in llee_subcharts_L123(g) {
        // (L3), guarded: no body state terminates inside the loop's guard
        if body.iter().any(|&s| g.hl[s] & gd != 0) { continue; }
        let mut g2 = *g;
        for &s in body.iter() {
            for y in 0..NA {
                if gd >> y & 1 == 1 && g2.st[s][y] == (h + 1) as u8 { g2.st[s][y] = 0; }
            }
        }
        if g2.st == g.st { continue; }
        if llee_L123(&g2, budget) { return true; }
    }
    false
}

fn l123_test<const NA: usize>(nguards: u8) {
    // 238: adjudicate (c) with a VERIFIED WITNESS, not the calculus.  237 left one
    // NA=3 case where the certificate holds and the six-rule calculus fails —
    // which is a calculus gap or certificate unsoundness, and those are very
    // different findings.  `synth` decides by exhibiting an expression.
    let table = synth_table::<NA>(synth_size(), seq_len(NA));
    let mut st0: u64 = 0xBE5466CF34E90C6C;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut a_ok, mut b_ok, mut l_not_s, mut s_not_l) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for _ in 0..40_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        n += 1;
        let mut bud = 200_000usize;
        let la = llee_L123(&a, &mut bud);
        if la { a_ok += 1; }
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            let mut b2 = 200_000usize;
            let lq = llee_L123(&qq, &mut b2);
            if !la || lq { b_ok += 1; }
            let solve = {
                let sing = singleton_states(&qq);
                sccs_of(&qq).iter().all(|c| c.len() < 2
                    || calculus_solves(&qq, c, 6)
                    || calculus_solves(&qq, &scc_with_context(&qq, c, &sing), 6))
            };
            let witness = synth_lookup(&table, &qq, 0, seq_len(NA)).is_some();
            if lq && !solve {
                l_not_s += 1;
                println!("    CERT HOLDS, CALCULUS FAILS — synth witness: {}",
                    if witness { "EXISTS (so a CALCULUS gap)" }
                    else { "none at this size bound (certificate SUSPECT)" });
                for s in 0..(qq.k as usize) {
                    let row: Vec<String> = (0..NA).map(|i| {
                        let t = qq.st[s][i];
                        if t == 0 { "-".to_string() } else { format!("c{}", t - 1) }
                    }).collect();
                    println!("      c{s}: hl={:03b} st=[{}]", qq.hl[s], row.join(","));
                }
            }
            if solve && !lq { s_not_l += 1; }
        }
    }
    println!("  l123_test NA={NA}: {n} Thompson automata; \
        (a) holds on {a_ok}; (b) survives collapse {b_ok}; \
        (c) cert-but-UNsolvable {l_not_s}, solvable-but-no-cert {s_not_l}");
}

/// **IS THE LOOP HEAD CANONICAL?** (iteration 242.)
///
/// (L2) is stated for a loop sub-chart with a SINGLE start vertex `vₛ`.  But
/// `loopInitialized`'s back edges target `body.initTrans`'s targets — a SET of
/// entry states, one per atom — so the construction hands us no canonical head,
/// and the Rust check has been finding heads by search.  A Lean proof must
/// EXHIBIT one.
///
/// So measure: for each loop SCC of a Thompson automaton, how many of its states
/// can serve as a valid head (satisfying L2 and guarded-L3 with the whole SCC as
/// body)?  If it is usually one, that one is the canonical choice.  If it is
/// many, a selection rule is needed; if it is sometimes ZERO, then the working
/// decomposition uses a PROPER SUBSET of the SCC as body and the proof is harder
/// than exhibiting a state.
fn head_census<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x3F84D5B5B5470917;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let mut hist = [0usize; 8];
    let mut sccs_n = 0usize;
    let mut entry_is_head = 0usize;
    let mut entry_known = 0usize;
    for _ in 0..40_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        for c in sccs_of(&a) {
            if c.len() < 2 { continue; }
            sccs_n += 1;
            let mut heads: Vec<usize> = Vec::new();
            for &h in c.iter() {
                // guard from edges of the SCC back into h
                let mut gd: u8 = 0;
                for &s in c.iter() {
                    for y in 0..NA { if a.st[s][y] == (h + 1) as u8 { gd |= 1 << y; } }
                }
                if gd == 0 { continue; }
                if c.iter().any(|&s| a.hl[s] & gd != 0) { continue; }        // L3
                // L2: c \ {h} acyclic
                let rest: Vec<usize> = c.iter().copied().filter(|&s| s != h).collect();
                let mut indeg: Vec<usize> = rest.iter().map(|&v| rest.iter()
                    .filter(|&&u| (0..NA).any(|y| a.st[u][y] == (v + 1) as u8)).count())
                    .collect();
                let mut removed = vec![false; rest.len()];
                let mut prog = true;
                while prog {
                    prog = false;
                    for i in 0..rest.len() {
                        if removed[i] || indeg[i] != 0 { continue; }
                        removed[i] = true; prog = true;
                        for j in 0..rest.len() {
                            if removed[j] { continue; }
                            if (0..NA).any(|y| a.st[rest[i]][y] == (rest[j] + 1) as u8) {
                                indeg[j] -= 1;
                            }
                        }
                    }
                }
                if removed.iter().all(|&r| r) { heads.push(h); }
            }
            hist[heads.len().min(7)] += 1;
            // is an ENTRY state (target of an edge from outside the SCC) a head?
            let mut entries: Vec<usize> = Vec::new();
            for s in 0..(a.k as usize) {
                if c.contains(&s) { continue; }
                for y in 0..NA {
                    let t = a.st[s][y];
                    if t != 0 && c.contains(&((t - 1) as usize)) {
                        entries.push((t - 1) as usize);
                    }
                }
            }
            for y in 0..NA {
                let t = a.it[y];
                if t != 0 && c.contains(&((t - 1) as usize)) { entries.push((t - 1) as usize); }
            }
            if !entries.is_empty() {
                entry_known += 1;
                if entries.iter().any(|e| heads.contains(e)) { entry_is_head += 1; }
            }
        }
    }
    println!("  head_census NA={NA}: {sccs_n} loop SCCs; valid-head counts \
        0:{} 1:{} 2:{} 3:{} 4:{} 5:{} 6:{} 7+:{}; \
        an ENTRY state is a valid head in {entry_is_head}/{entry_known}",
        hist[0], hist[1], hist[2], hist[3], hist[4], hist[5], hist[6], hist[7]);
}

/// **(L2′): EVERY CYCLE PASSES THROUGH THE ENTRY SET** (iteration 244).
///
/// 242 found no canonical single head, and working `wh c (ite b p q)` by hand
/// shows why: its body has TWO entry states, and after inlining both have edges
/// to both, so the graph carries three cycles where the expression has ONE loop.
/// Inlining does not merely remove Milner's head — it MULTIPLIES a loop into one
/// cycle per entry atom.
///
/// So the guarded analogue of (L2) is not "every infinite path returns to a
/// vertex `vₛ`" but "every infinite path returns to the ENTRY SET" — the states
/// a restart can land on.  That set is DETERMINED by the graph (no search): the
/// states of the SCC reachable from outside it, including from the initial
/// pseudostate.  Concretely, (L2′) says `SCC \ E` is acyclic.
fn l2prime_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0xC0AC29B7C97C50DD;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut ok, mut cn, mut cok) = (0usize, 0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..40_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        let check = |q: &Aut<NA>, dump: bool| -> (usize, usize) {
            let (mut tot, mut good) = (0, 0);
            for c in sccs_of(q) {
                if c.len() < 2 { continue; }
                tot += 1;
                // entry set: states of the SCC targeted from outside it
                let mut e: Vec<usize> = Vec::new();
                for y in 0..NA {
                    let t = q.it[y];
                    if t != 0 && c.contains(&((t - 1) as usize)) { e.push((t - 1) as usize); }
                }
                for s in 0..(q.k as usize) {
                    if c.contains(&s) { continue; }
                    for y in 0..NA {
                        let t = q.st[s][y];
                        if t != 0 && c.contains(&((t - 1) as usize)) { e.push((t - 1) as usize); }
                    }
                }
                // (L2'): C \ E is acyclic
                let rest: Vec<usize> = c.iter().copied().filter(|s| !e.contains(s)).collect();
                let mut indeg: Vec<usize> = rest.iter().map(|&v| rest.iter()
                    .filter(|&&u| (0..NA).any(|y| q.st[u][y] == (v + 1) as u8)).count())
                    .collect();
                let mut removed = vec![false; rest.len()];
                let mut prog = true;
                while prog {
                    prog = false;
                    for i in 0..rest.len() {
                        if removed[i] || indeg[i] != 0 { continue; }
                        removed[i] = true; prog = true;
                        for j in 0..rest.len() {
                            if removed[j] { continue; }
                            if (0..NA).any(|y| q.st[rest[i]][y] == (rest[j] + 1) as u8) {
                                indeg[j] -= 1;
                            }
                        }
                    }
                }
                if removed.iter().all(|&r| r) { good += 1; }
                else if dump { println!("    (L2') FAILS on scc {c:?}, entry set {e:?}"); }
            }
            (tot, good)
        };
        let (t, g) = check(&a, shown < 2 && { shown += 1; true });
        n += t; ok += g;
        let (blk, nb) = bisim_blocks(&a);
        if let Some(qq) = quotient_by(&a, &blk, nb) {
            let (t2, g2) = check(&qq, false); cn += t2; cok += g2;
        }
    }
    println!("  l2prime_test NA={NA}: {n} loop SCCs; (L2') holds on {ok}; \
        after collapse {cok}/{cn}");
}

/// **IS THE CERTIFICATE PRESERVED BY ARBITRARY QUOTIENTS?** (iteration 260.)
///
/// 259 read from Grabmayer that "the class of finite LLEE-precharts is closed
/// under ARBITRARY homomorphic images" — stronger than the minimal-collapse
/// closure `hcollapse` needs.  227 had to add a minimality hypothesis to
/// `QuotientClosure` after 4 failures at NA=4, but those were failures of the
/// six-rule CALCULUS on non-minimal quotients, not of a certificate.  If the
/// certificate really is closed under arbitrary quotients, the Lean statement
/// needs no minimality hypothesis at all.
///
/// Test: take Thompson automata (which carry the certificate by `thompson_layered`,
/// proved at 258), quotient by EVERY behavioural congruence in the lattice, and
/// check the certificate survives each one.
fn cert_arbitrary_quotient<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x6A09E667F3BCC908;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut auts, mut quots, mut bad, mut nonmin) = (0usize, 0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..12_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        let mut bud = 200_000usize;
        if !llee_L123(&a, &mut bud) { continue; }   // only certified starting points
        auts += 1;
        for (blk, nb) in lattice_congruences(&a) {
            let q = match quotient_by(&a, &blk, nb) { Some(q) => q, None => continue };
            quots += 1;
            let (qb, qnb) = bisim_blocks(&q);
            if qnb < q.k as usize { nonmin += 1; }
            let mut b2 = 200_000usize;
            if !llee_L123(&q, &mut b2) {
                bad += 1;
                if shown < 3 {
                    shown += 1;
                    println!("    CERT LOST on a quotient: {} states -> {} (minimal? {})",
                        a.k, nb, qnb == q.k as usize);
                    for s in 0..(q.k as usize) {
                        let row: Vec<String> = (0..NA).map(|i| {
                            let t = q.st[s][i];
                            if t == 0 { "-".to_string() } else { format!("c{}", t - 1) }
                        }).collect();
                        println!("      c{s}: hl={:03b} st=[{}]", q.hl[s], row.join(","));
                    }
                }
            }
        }
    }
    println!("  cert_arbitrary_quotient NA={NA}: {auts} certified Thompson automata; \
        {quots} behavioural quotients ({nonmin} of them NON-minimal); \
        certificate LOST on {bad}");
}

/// **CONNECT-THROUGH, AND DOES GKAT NEED PROP 6.4's CARE?** (iteration 267.)
///
/// Grabmayer Def 6.1: the connect-`w1`-through-to-`w2` chart redirects all
/// incoming transitions at `w1` over to `w2`, then garbage-collects `w1`.  Lemma
/// 6.2 says the result is bisimilar — but Example 6.3 shows the LLEE property
/// CAN BE LOST, which is why closure needs Prop 6.4's three-way case analysis
/// and three level-adapting transformations.
///
/// Crucially that example lives in the LICS'20 paper, which is the PROPER-STEP
/// (1-free) setting — so being proper-step does not by itself avoid the
/// difficulty.  But GKAT has structure Milner's charts lack: every transition
/// carries a GUARD, and at each state the guards are determined by tests.  If
/// that constrains bisimilar pairs enough, GKAT's collapse may not need the
/// case analysis.  Measure before importing three transformations.
fn connect_through<const NA: usize>(a: &Aut<NA>, w1: usize, w2: usize) -> Option<Aut<NA>> {
    let k = a.k as usize;
    if w1 == w2 || w1 >= k || w2 >= k { return None; }
    // redirect every transition targeting w1 to w2, and the initial arrows too
    let mut b = *a;
    for s in 0..k {
        for y in 0..NA {
            if b.st[s][y] == (w1 + 1) as u8 { b.st[s][y] = (w2 + 1) as u8; }
        }
    }
    for y in 0..NA {
        if b.it[y] == (w1 + 1) as u8 { b.it[y] = (w2 + 1) as u8; }
    }
    // garbage-collect w1 (now unreachable) by renumbering
    let mut idx = vec![usize::MAX; k];
    let mut n = 0usize;
    for s in 0..k { if s != w1 { idx[s] = n; n += 1; } }
    let mut c = Aut::<NA>::blank();
    c.k = n as u8;
    c.ih = b.ih;
    for y in 0..NA {
        c.it[y] = if b.it[y] == 0 { 0 } else { (idx[(b.it[y] - 1) as usize] + 1) as u8 };
    }
    for s in 0..k {
        if s == w1 { continue; }
        let d = idx[s];
        c.hl[d] = b.hl[s];
        for y in 0..NA {
            c.st[d][y] = if b.st[s][y] == 0 { 0 }
                else { (idx[(b.st[s][y] - 1) as usize] + 1) as u8 };
        }
    }
    Some(c)
}

fn connect_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0xBB67AE8584CAA73B;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut pairs, mut lost) = (0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..20_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        let mut bud = 200_000usize;
        if !llee_L123(&a, &mut bud) { continue; }
        let (blk, _) = bisim_blocks(&a);
        for w1 in 0..(a.k as usize) {
            for w2 in 0..(a.k as usize) {
                if w1 == w2 || blk[w1] != blk[w2] { continue; }
                let c = match connect_through(&a, w1, w2) { Some(c) => c, None => continue };
                pairs += 1;
                let mut b2 = 200_000usize;
                if !llee_L123(&c, &mut b2) {
                    lost += 1;
                    if shown < 3 {
                        shown += 1;
                        println!("    LEE LOST connecting q{w1} -> q{w2} (k {} -> {}):",
                            a.k, c.k);
                        for s in 0..(a.k as usize) {
                            let row: Vec<String> = (0..NA).map(|i| {
                                let t = a.st[s][i];
                                if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                            }).collect();
                            println!("      q{s}: hl={:03b} st=[{}]", a.hl[s], row.join(","));
                        }
                    }
                }
            }
        }
    }
    println!("  connect_test NA={NA}: {pairs} connect-through steps on bisimilar pairs \
        of certified automata; certificate LOST on {lost}");
}

/// **DOES MY `Layered` YIELD GRABMAYER'S LEVEL LABELLING?** (iteration 268.)
///
/// 266 raised a representation gap: Grabmayer's LLEE-witness is an entry/body
/// labelling carrying natural-number LOOP LEVELS, and the closure proof's
/// transformations LI/LII/LIII operate on those levels — while my `Layered` is
/// an inductive elimination with no levels at all.
///
/// But the elimination ORDER induces levels: a loop eliminated at step `n` is
/// nested inside one eliminated later, so `n` IS its loop level.  If every
/// successful elimination yields a labelling satisfying the descent condition —
/// "an edge descending into a loop accompanies a descent in the labelling" —
/// then the two representations carry the same information and 266's gap is
/// cosmetic.
///
/// Records, for each certified automaton, the elimination depth reached and
/// whether the induced levels are STRICTLY NESTED: every loop eliminated at a
/// later step must contain, as a subset of its body, every earlier-eliminated
/// loop it overlaps.  That containment is what "layered" means.
fn levels_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x3C6EF372FE94F82B;
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut layered_ok, mut nested_ok, mut maxdepth) =
        (0usize, 0usize, 0usize, 0usize);
    for _ in 0..20_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        // replay the elimination greedily, recording each layer's body
        let mut g = a;
        let mut layers: Vec<Vec<usize>> = Vec::new();
        loop {
            let cyclic = sccs_of(&g).iter().any(|c| c.len() >= 2
                || (0..NA).any(|y| g.st[c[0]][y] == (c[0] + 1) as u8));
            if !cyclic { break; }
            let mut progressed = false;
            for (h, body, gd) in llee_subcharts_L123(&g) {
                if body.iter().any(|&s| g.hl[s] & gd != 0) { continue; }
                let mut g2 = g;
                for &s in body.iter() {
                    for y in 0..NA {
                        if gd >> y & 1 == 1 && g2.st[s][y] == (h + 1) as u8 {
                            g2.st[s][y] = 0;
                        }
                    }
                }
                if g2.st == g.st { continue; }
                layers.push(body.clone());
                g = g2;
                progressed = true;
                break;
            }
            if !progressed { break; }
        }
        let done = !sccs_of(&g).iter().any(|c| c.len() >= 2
            || (0..NA).any(|y| g.st[c[0]][y] == (c[0] + 1) as u8));
        n += 1;
        if !done { continue; }
        layered_ok += 1;
        if layers.len() > maxdepth { maxdepth = layers.len(); }
        // LAYEREDNESS: an earlier-eliminated (inner) layer that overlaps a later
        // one must be CONTAINED in it — loops are nested, never interleaved.
        let mut nested = true;
        for i in 0..layers.len() {
            for j in (i + 1)..layers.len() {
                let overlap = layers[i].iter().any(|s| layers[j].contains(s));
                if overlap && !layers[i].iter().all(|s| layers[j].contains(s)) {
                    nested = false;
                }
            }
        }
        if nested { nested_ok += 1; }
    }
    println!("  levels_test NA={NA}: {n} automata; greedy elimination succeeded on \
        {layered_ok}; of those, induced levels STRICTLY NESTED on {nested_ok}; \
        max nesting depth {maxdepth}");
}

/// **(a) OR (b)? DOES A NESTED ELIMINATION ORDER ALWAYS EXIST?** (iteration 269.)
///
/// 268 found greedy elimination always succeeds but its induced levels are
/// nested only ~97-99% of the time, and that LAYEREDNESS — the "L" in LLEE — is
/// absent from my `Layered`.  Two readings: (a) a nested order always exists and
/// greedy missed it, so layeredness is free; (b) some Thompson automata admit no
/// nested decomposition, in which case my certificate is weaker than LLEE and
/// `hsolve` may fail for it.
///
/// Search all elimination orders, requiring nesting INCREMENTALLY: each new
/// layer must, for every earlier layer it overlaps, CONTAIN that layer.
fn nested_search<const NA: usize>(g: &Aut<NA>, layers: &mut Vec<Vec<usize>>,
    budget: &mut usize) -> bool
{
    if *budget == 0 { return false; }
    *budget -= 1;
    let cyclic = sccs_of(g).iter().any(|c| c.len() >= 2
        || (0..NA).any(|y| g.st[c[0]][y] == (c[0] + 1) as u8));
    if !cyclic { return true; }
    for (h, body, gd) in llee_subcharts_L123(g) {
        if body.iter().any(|&s| g.hl[s] & gd != 0) { continue; }
        // layeredness: every earlier layer this one overlaps must be inside it
        let ok = layers.iter().all(|prev| {
            let overlap = prev.iter().any(|s| body.contains(s));
            !overlap || prev.iter().all(|s| body.contains(s))
        });
        if !ok { continue; }
        let mut g2 = *g;
        for &s in body.iter() {
            for y in 0..NA {
                if gd >> y & 1 == 1 && g2.st[s][y] == (h + 1) as u8 { g2.st[s][y] = 0; }
            }
        }
        if g2.st == g.st { continue; }
        layers.push(body.clone());
        if nested_search(&g2, layers, budget) { return true; }
        layers.pop();
    }
    false
}

fn nested_test<const NA: usize>(nguards: u8) {
    let mut st0: u64 = 0x3C6EF372FE94F82B;   // same seed as 268
    let mut rnd = move || { st0 ^= st0 << 13; st0 ^= st0 >> 7; st0 ^= st0 << 17; st0 };
    let (mut n, mut greedy_nested, mut search_nested, mut no_nested) =
        (0usize, 0usize, 0usize, 0usize);
    let mut shown = 0usize;
    for _ in 0..20_000 {
        let a = match genexp::<NA>(&mut rnd, 5, nguards, MAXK - 1) {
            Some((a, _, _)) => a, None => continue };
        if a.k < 2 { continue; }
        n += 1;
        // greedy, as at 268
        let mut g = a; let mut layers: Vec<Vec<usize>> = Vec::new();
        loop {
            let cyclic = sccs_of(&g).iter().any(|c| c.len() >= 2
                || (0..NA).any(|y| g.st[c[0]][y] == (c[0] + 1) as u8));
            if !cyclic { break; }
            let mut prog = false;
            for (h, body, gd) in llee_subcharts_L123(&g) {
                if body.iter().any(|&s| g.hl[s] & gd != 0) { continue; }
                let mut g2 = g;
                for &s in body.iter() {
                    for y in 0..NA {
                        if gd >> y & 1 == 1 && g2.st[s][y] == (h + 1) as u8 {
                            g2.st[s][y] = 0;
                        }
                    }
                }
                if g2.st == g.st { continue; }
                layers.push(body.clone()); g = g2; prog = true; break;
            }
            if !prog { break; }
        }
        let mut nested = true;
        for i in 0..layers.len() {
            for j in (i + 1)..layers.len() {
                if layers[i].iter().any(|s| layers[j].contains(s))
                    && !layers[i].iter().all(|s| layers[j].contains(s)) { nested = false; }
            }
        }
        if nested { greedy_nested += 1; continue; }
        // greedy interleaved — is there a nested order at all?
        let mut ls: Vec<Vec<usize>> = Vec::new();
        let mut bud = 500_000usize;
        if nested_search(&a, &mut ls, &mut bud) { search_nested += 1; }
        else {
            no_nested += 1;
            if shown < 3 {
                shown += 1;
                println!("    NO NESTED ORDER, k={}:", a.k);
                for s in 0..(a.k as usize) {
                    let row: Vec<String> = (0..NA).map(|i| {
                        let t = a.st[s][i];
                        if t == 0 { "-".to_string() } else { format!("q{}", t - 1) }
                    }).collect();
                    println!("      q{s}: hl={:03b} st=[{}]", a.hl[s], row.join(","));
                }
            }
        }
    }
    println!("  nested_test NA={NA}: {n} automata; greedy already nested {greedy_nested}; \
        nested order FOUND BY SEARCH {search_nested}; NO nested order {no_nested}");
}
