//! **Whole-fabric recompute** — phantom-authority detection over the entire
//! delegation graph at once.
//!
//! Today's `verify_certificate` recomputes a *single* delegation chain (meet the
//! edges, check `leq`). The Enriched-Reflection model (see the spiffy doctrine
//! *"authorization is natural in the execution site"*) generalizes this to the
//! whole fabric: model the signed delegation edges as a **V-enriched graph**
//! whose objects are principals and whose `hom(i, j) ∈ V` is the capability
//! transported from `i` to `j`, then take its **closure**.
//!
//! The closure is the free construction over the edge graph — *everything the
//! edges derive, nothing more*. For capability the enriching value `V` is the
//! capability lattice with the quantale product `⊗ = meet` (weakest-link
//! attenuation along a path) and `∨ = join` (the strongest path between two
//! principals). So
//!
//! ```text
//! closure(i, j) = ⋁_{paths i→j} ⨅_{edges on the path} cap(edge)
//! ```
//!
//! — the **bottleneck** (max-min) transitive closure, computed by Floyd–Warshall
//! over the `(∨, ⊗) = (join, meet)` semiring (valid because the capability
//! lattice is distributive, so `meet` distributes over `join`).
//!
//! [`witnesses`] then checks a *claimed* authority matrix against the closure:
//! a relying party's asserted `hom(i, j)` is sound iff it is `≤ closure(i, j)`
//! for every pair — i.e. **no principal claims more authority than the cited
//! edges actually derive, over any path.** The single-edge `n = 2` case is
//! exactly today's `verify_certificate` (recompute the edge, check `leq`); this
//! generalizes it to all principals and all paths simultaneously.
//!
//! Generic over any [`BoundedLattice`] `V`; `⊗` is instantiated as `meet` (the
//! capability quantale's product — see [`crate::quantale`]). A future
//! generalization can take `V: crate::quantale::Quantale` to cover non-meet
//! products (e.g. an additive budget axis).

use portcullis_core::category::{BoundedLattice, Lattice};

/// A finite **V-enriched graph**: a dense `n × n` hom-matrix over objects
/// (principals/policy-versions), where `hom(i, j) ∈ V` is the authority
/// transported from `i` to `j`. Row-major.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VGraph<V> {
    n: usize,
    hom: Vec<V>,
}

impl<V: Lattice + BoundedLattice + Clone> VGraph<V> {
    /// The identity graph on `n` objects: `⊤` on the diagonal (a principal has
    /// full authority to itself — the `⊗`-unit), `⊥` everywhere else (no edge).
    pub fn identity(n: usize) -> Self {
        let mut hom = vec![V::bottom(); n * n];
        for i in 0..n {
            hom[i * n + i] = V::top();
        }
        VGraph { n, hom }
    }

    /// Number of objects.
    pub fn order(&self) -> usize {
        self.n
    }

    /// `hom(i, j)`.
    pub fn get(&self, i: usize, j: usize) -> &V {
        &self.hom[i * self.n + j]
    }

    /// Add a delegation edge `i → j` carrying capability `cap`. Parallel edges
    /// between the same pair **join** (the strongest grant wins).
    pub fn add_edge(&mut self, i: usize, j: usize, cap: V) {
        let idx = i * self.n + j;
        self.hom[idx] = self.hom[idx].join(&cap);
    }

    /// The **closure**: `closure(i, j) = ⋁_paths ⨅_edges` — the strongest
    /// capability derivable from the cited edges along any path. Floyd–Warshall
    /// over the `(∨ = join, ⊗ = meet)` semiring. Idempotent (`closure∘closure =
    /// closure`); the result is the free V-category on the edge graph.
    pub fn closure(&self) -> VGraph<V> {
        let n = self.n;
        let mut h = self.hom.clone();
        for k in 0..n {
            for i in 0..n {
                let ik = h[i * n + k].clone();
                for j in 0..n {
                    // h[i][j] ← h[i][j] ∨ (h[i][k] ⊗ h[k][j])
                    let via = ik.meet(&h[k * n + j]);
                    let idx = i * n + j;
                    h[idx] = h[idx].join(&via);
                }
            }
        }
        VGraph { n, hom: h }
    }
}

/// **Whole-fabric soundness check.** An `asserted` authority matrix is sound
/// against the closure of the cited edges iff every claimed `hom(i, j)` is
/// `≤ closure(i, j)` — no principal claims more authority than the edges
/// actually derive, over any path. `false` if the orders differ or any entry
/// asserts phantom authority.
pub fn witnesses<V: Lattice>(asserted: &VGraph<V>, closure: &VGraph<V>) -> bool {
    asserted.n == closure.n
        && asserted
            .hom
            .iter()
            .zip(closure.hom.iter())
            .all(|(a, c)| a.leq(c))
}

/// Build a [`VGraph`] from a delegation chain/DAG given as `(from, to, cap)`
/// edges over principals identified by `P: Eq`. Returns the graph and the
/// principal→index ordering (first-seen order). The graph's [`VGraph::closure`]
/// is the whole-fabric recompute over this chain; the `n = 2` single-edge case
/// reproduces `verify_certificate`.
pub fn from_certificate_chain<P, V>(edges: &[(P, P, V)]) -> (VGraph<V>, Vec<P>)
where
    P: Eq + Clone,
    V: Lattice + BoundedLattice + Clone,
{
    // First-seen principal ordering.
    let mut principals: Vec<P> = Vec::new();
    let index_of = |p: &P, ps: &mut Vec<P>| -> usize {
        if let Some(k) = ps.iter().position(|q| q == p) {
            k
        } else {
            ps.push(p.clone());
            ps.len() - 1
        }
    };
    // Pre-collect indices (two passes so `identity(n)` knows `n`).
    let mut idx_edges = Vec::with_capacity(edges.len());
    for (from, to, cap) in edges {
        let i = index_of(from, &mut principals);
        let j = index_of(to, &mut principals);
        idx_edges.push((i, j, cap.clone()));
    }
    let mut g = VGraph::identity(principals.len());
    for (i, j, cap) in idx_edges {
        g.add_edge(i, j, cap);
    }
    (g, principals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::CapabilityLevel::{self, Always, LowRisk, Never};

    #[test]
    fn single_edge_closure_reproduces_verify_certificate() {
        // n = 2, one edge A→B: the closure's hom(A,B) is exactly the edge cap —
        // the base case today's verify_certificate covers.
        let (g, ps) = from_certificate_chain(&[("A", "B", LowRisk)]);
        let c = g.closure();
        let (a, b) = (0, 1);
        assert_eq!(ps, vec!["A", "B"]);
        assert_eq!(*c.get(a, b), LowRisk);
    }

    #[test]
    fn chain_closure_is_the_weakest_link() {
        // A→B (Always) →C (LowRisk): the transported authority A⇝C is the MEET
        // (weakest link) = LowRisk.
        let (g, ps) = from_certificate_chain(&[("A", "B", Always), ("B", "C", LowRisk)]);
        let c = g.closure();
        let idx = |p| ps.iter().position(|q| *q == p).unwrap();
        assert_eq!(*c.get(idx("A"), idx("C")), LowRisk);
    }

    #[test]
    fn multipath_closure_is_the_strongest_path() {
        // Two A⇝C paths: direct A→C (Never) and A→B→C (meet(Always,LowRisk)=LowRisk).
        // The closure takes the JOIN (strongest path) = LowRisk.
        let (g, ps) =
            from_certificate_chain(&[("A", "C", Never), ("A", "B", Always), ("B", "C", LowRisk)]);
        let c = g.closure();
        let idx = |p| ps.iter().position(|q| *q == p).unwrap();
        assert_eq!(*c.get(idx("A"), idx("C")), LowRisk);
    }

    #[test]
    fn witnesses_rejects_phantom_authority() {
        // Edges derive A⇝C = LowRisk. Asserting LowRisk is sound; asserting
        // Always (more than derivable) is phantom authority and is rejected.
        let (g, ps) = from_certificate_chain(&[("A", "B", Always), ("B", "C", LowRisk)]);
        let closure = g.closure();
        let (a, c) = (
            ps.iter().position(|q| *q == "A").unwrap(),
            ps.iter().position(|q| *q == "C").unwrap(),
        );

        let mut honest = VGraph::<CapabilityLevel>::identity(ps.len());
        honest.add_edge(a, c, LowRisk);
        assert!(witnesses(&honest, &closure), "an honest claim must verify");

        let mut phantom = VGraph::<CapabilityLevel>::identity(ps.len());
        phantom.add_edge(a, c, Always);
        assert!(
            !witnesses(&phantom, &closure),
            "phantom authority must be rejected"
        );
    }

    #[test]
    fn closure_is_idempotent() {
        let (g, _) =
            from_certificate_chain(&[("A", "B", Always), ("B", "C", LowRisk), ("C", "D", Always)]);
        let c1 = g.closure();
        let c2 = c1.closure();
        assert_eq!(c1, c2, "closure must be idempotent (a free construction)");
    }
}
