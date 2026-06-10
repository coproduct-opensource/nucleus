//! The attenuation algebra: **authority only tightens**.
//!
//! Five mechanisms in this workspace independently implement the same
//! law — capability meet, delegation narrowing, budget caveats
//! (platform), constitutional monotonicity (ck-policy), IFC taint
//! join (dually) — each as bespoke field-by-field code. This module
//! names the shared object once: an [`Attenuation`] is a **monotone
//! deflationary endomap** on a lattice, and every "things may only
//! narrow across hops" rule is an instance.
//!
//! # Laws
//!
//! For an attenuation `f` over lattice `L` and all `x, y ∈ L`:
//!
//! - **deflationary**: `f(x) ≤ x` — applying never grants authority;
//! - **monotone**: `x ≤ y ⇒ f(x) ≤ f(y)` — attenuating a smaller
//!   authority never yields more than attenuating a larger one.
//!
//! Both laws are closed under composition ([`Compose`]), and the
//! canonical instance [`MeetCap`] composes *commutatively*:
//! `MeetCap(a) ∘ MeetCap(b) = MeetCap(a ⊓ b)`, so the **effective
//! authority at the end of a delegation chain is the meet of all
//! caps, independent of association or application order**
//! ([`chain_effective_authority`]). That order-independence falls out
//! of meet's commutativity + associativity — the same lemmas the Lean
//! side already carries for the capability lattice.
//!
//! Laws are sample-verified here ([`verify_attenuation_laws`], in the
//! style of [`crate::category::verify_lattice_laws`]) and stated for
//! machine-checking in `lean/PortcullisCore/Attenuation.lean`
//! (composition closure + chain order-independence).
//!
//! # Honest domain note (delegation instance)
//!
//! [`DelegationScope`]'s order is *glob-coverage* (`"src/**"` covers
//! `"src/lib.rs"`) while its `intersect` is literal element
//! intersection — a sound under-approximation of the true meet, not
//! the greatest lower bound (`["src/**"] ∩ ["src/lib.rs"] = ∅`). So
//! `DelegationConstraints` is a true lattice only on its **literal
//! fragment** (glob-free scopes), which is what
//! [`LiteralDelegation`] exposes and what the parity tests cover.
//! On the full glob fragment, narrowing remains *deflationary*
//! (sound: never widens) but meet-optimality is not claimed.

use crate::category::Lattice;
use crate::delegation::{DelegationConstraints, DelegationScope};

/// A monotone deflationary endomap on the lattice `L`.
///
/// See the module docs for the two laws. Implementations should be
/// checked with [`verify_attenuation_laws`] over a representative
/// sample (and, where they mirror a Lean theorem, kept parity-pinned
/// to it).
pub trait Attenuation<L: Lattice> {
    /// Apply the attenuation. The result must satisfy
    /// `attenuate(x) ≤ x` for every `x`.
    fn attenuate(&self, x: &L) -> L;
}

/// The canonical attenuation: meet with a fixed cap.
///
/// - deflationary: `x ⊓ c ≤ x` (meet is a lower bound)
/// - monotone: `x ≤ y ⇒ x ⊓ c ≤ y ⊓ c` (meet is monotone)
/// - composition collapses: capping by `a` then `b` equals capping by
///   `a ⊓ b`, in any order.
#[derive(Debug, Clone, PartialEq)]
pub struct MeetCap<L: Lattice>(pub L);

impl<L: Lattice> Attenuation<L> for MeetCap<L> {
    fn attenuate(&self, x: &L) -> L {
        x.meet(&self.0)
    }
}

/// Composition of two attenuations, applied right-to-left
/// (`Compose(f, g)` is `f ∘ g`). Deflationarity and monotonicity are
/// closed under composition, so this is again an attenuation — that
/// closure is the Lean theorem `Attenuation.comp` mirrors.
#[derive(Debug, Clone, PartialEq)]
pub struct Compose<F, G>(pub F, pub G);

impl<L: Lattice, F: Attenuation<L>, G: Attenuation<L>> Attenuation<L> for Compose<F, G> {
    fn attenuate(&self, x: &L) -> L {
        self.0.attenuate(&self.1.attenuate(x))
    }
}

/// Effective authority at the end of a chain of meet-caps: the start
/// authority met with every cap. By meet commutativity/associativity
/// this is independent of the order the caps were applied in — the
/// keystone property for multi-hop delegation (RFC 8693 act-chains,
/// SPIFFE delegation): verifiers may fold the chain in any order and
/// agree.
pub fn chain_effective_authority<L: Lattice>(start: &L, caps: &[L]) -> L {
    caps.iter().fold(start.clone(), |acc, cap| acc.meet(cap))
}

/// Sample-based law checker for an [`Attenuation`], in the style of
/// [`crate::category::verify_lattice_laws`]: returns a list of law
/// violations (empty = all laws hold on the sample).
pub fn verify_attenuation_laws<L, A>(f: &A, samples: &[L]) -> Vec<String>
where
    L: Lattice + std::fmt::Debug,
    A: Attenuation<L>,
{
    let mut violations = Vec::new();
    for x in samples {
        let fx = f.attenuate(x);
        if !fx.leq(x) {
            violations.push(format!("deflationary violated: f({x:?}) = {fx:?} ⋠ {x:?}"));
        }
        for y in samples {
            if x.leq(y) {
                let fy = f.attenuate(y);
                if !fx.leq(&fy) {
                    violations.push(format!(
                        "monotone violated: {x:?} ≤ {y:?} but f(x) = {fx:?} ⋠ f(y) = {fy:?}"
                    ));
                }
            }
        }
    }
    violations
}

// ═══════════════════════════════════════════════════════════════════════
// Delegation instance — the literal (glob-free) fragment is a lattice
// ═══════════════════════════════════════════════════════════════════════

/// [`DelegationConstraints`] restricted to **literal scopes** (no `*`
/// or `**` patterns), where element containment *is* the scope order
/// and literal intersection *is* the meet — i.e. the fragment on
/// which `(constraints, narrow)` is genuinely the meet-attenuation
/// instance of this algebra. Construct with [`LiteralDelegation::new`],
/// which rejects glob patterns.
#[derive(Debug, Clone)]
pub struct LiteralDelegation(DelegationConstraints);

/// Lattice equality is SET equality on scopes — `Vec` carries
/// incidental ordering that join/meet must not observe (deriving
/// `PartialEq` would break join commutativity: `a ∨ b` and `b ∨ a`
/// list elements in different orders).
impl PartialEq for LiteralDelegation {
    fn eq(&self, other: &Self) -> bool {
        scope_set_eq(&self.0.scope, &other.0.scope)
            && self.0.max_delegation_depth == other.0.max_delegation_depth
            && self.0.expires_at == other.0.expires_at
    }
}

impl LiteralDelegation {
    /// Wrap literal-fragment constraints. Returns `None` if any scope
    /// entry contains a glob metacharacter (`*`), since on that
    /// fragment `intersect` under-approximates the meet and the
    /// lattice laws below would be unsound to claim.
    pub fn new(c: DelegationConstraints) -> Option<Self> {
        let has_glob = c
            .scope
            .allowed_paths
            .iter()
            .chain(c.scope.allowed_repos.iter())
            .any(|p| p.contains('*'));
        if has_glob { None } else { Some(Self(c)) }
    }

    /// The underlying constraints.
    pub fn constraints(&self) -> &DelegationConstraints {
        &self.0
    }
}

fn scope_union(a: &DelegationScope, b: &DelegationScope) -> DelegationScope {
    let mut paths = a.allowed_paths.clone();
    let new_paths: Vec<_> = b
        .allowed_paths
        .iter()
        .filter(|p| !paths.contains(p))
        .cloned()
        .collect();
    paths.extend(new_paths);
    let mut sinks = a.allowed_sinks.clone();
    let new_sinks: Vec<_> = b
        .allowed_sinks
        .iter()
        .filter(|s| !sinks.contains(s))
        .copied()
        .collect();
    sinks.extend(new_sinks);
    let mut repos = a.allowed_repos.clone();
    let new_repos: Vec<_> = b
        .allowed_repos
        .iter()
        .filter(|r| !repos.contains(r))
        .cloned()
        .collect();
    repos.extend(new_repos);
    DelegationScope {
        allowed_paths: paths,
        allowed_sinks: sinks,
        allowed_repos: repos,
    }
}

/// Set-equality on scopes (order-insensitive), since `Vec` carries
/// incidental ordering the lattice must not observe.
fn scope_set_eq(a: &DelegationScope, b: &DelegationScope) -> bool {
    a.is_subset_of(b) && b.is_subset_of(a)
}

impl Lattice for LiteralDelegation {
    fn meet(&self, other: &Self) -> Self {
        Self(DelegationConstraints {
            scope: self.0.scope.intersect(&other.0.scope),
            max_delegation_depth: self
                .0
                .max_delegation_depth
                .min(other.0.max_delegation_depth),
            expires_at: self.0.expires_at.min(other.0.expires_at),
        })
    }

    fn join(&self, other: &Self) -> Self {
        Self(DelegationConstraints {
            scope: scope_union(&self.0.scope, &other.0.scope),
            max_delegation_depth: self
                .0
                .max_delegation_depth
                .max(other.0.max_delegation_depth),
            expires_at: self.0.expires_at.max(other.0.expires_at),
        })
    }

    fn leq(&self, other: &Self) -> bool {
        self.0.scope.is_subset_of(&other.0.scope)
            && self.0.max_delegation_depth <= other.0.max_delegation_depth
            && self.0.expires_at <= other.0.expires_at
    }
}

impl PartialEq<LiteralDelegation> for DelegationConstraints {
    fn eq(&self, other: &LiteralDelegation) -> bool {
        scope_set_eq(&self.scope, &other.0.scope)
            && self.max_delegation_depth == other.0.max_delegation_depth
            && self.expires_at == other.0.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::verify_lattice_laws;
    use crate::{CapabilityLattice, SinkClass};

    fn lit(paths: &[&str], depth: u32, expiry: u64) -> LiteralDelegation {
        LiteralDelegation::new(DelegationConstraints {
            scope: DelegationScope {
                allowed_paths: paths.iter().map(|s| s.to_string()).collect(),
                allowed_sinks: vec![SinkClass::WorkspaceWrite],
                allowed_repos: vec!["org/a".to_string()],
            },
            max_delegation_depth: depth,
            expires_at: expiry,
        })
        .expect("literal fragment")
    }

    fn samples() -> Vec<LiteralDelegation> {
        vec![
            lit(&[], 0, 100),
            lit(&["src/lib.rs"], 1, 200),
            lit(&["src/lib.rs", "tests/it.rs"], 2, 300),
            lit(&["tests/it.rs"], 3, 150),
        ]
    }

    #[test]
    fn meet_cap_satisfies_attenuation_laws_on_capability_lattice() {
        // The flagship lattice: every cap is a lawful attenuation.
        let pts = [CapabilityLattice::bottom(), CapabilityLattice::top()];
        for cap in &pts {
            let f = MeetCap(cap.clone());
            assert_eq!(verify_attenuation_laws(&f, &pts), Vec::<String>::new());
        }
    }

    #[test]
    fn literal_delegation_is_a_lawful_lattice() {
        // The point of the newtype: on the glob-free fragment, the
        // bespoke (intersect, min, min) really is a lattice. (With
        // glob patterns this is exactly what FAILS — see module docs.)
        assert_eq!(verify_lattice_laws(&samples()), Vec::<String>::new());
    }

    #[test]
    fn narrow_is_the_meet_attenuation_on_the_literal_fragment() {
        // Parity between the bespoke checker and the algebra:
        //   narrow(p, c) = Some(·)  ⟺  c ≤ p, and the narrowed value
        //   IS the lattice meet (= c when c ≤ p).
        for p in samples() {
            for c in samples() {
                let narrowed = p.constraints().narrow(c.constraints());
                let algebra = MeetCap(c.clone()).attenuate(&p);
                match narrowed {
                    Some(n) => {
                        assert!(
                            c.leq(&p),
                            "narrow accepted a non-narrowing child: {c:?} ⋠ {p:?}"
                        );
                        assert!(n == algebra, "narrow ≠ meet: {n:?} vs {algebra:?}");
                    }
                    None => assert!(
                        !c.leq(&p),
                        "narrow rejected a lattice-narrower child: {c:?} ≤ {p:?}"
                    ),
                }
            }
        }
    }

    #[test]
    fn chain_effective_authority_is_order_independent() {
        // The keystone: fold the caps in any order, same authority.
        let caps = samples();
        let start = lit(&["src/lib.rs", "tests/it.rs"], 9, 999);
        let forward = chain_effective_authority(&start, &caps);
        let mut reversed = caps.clone();
        reversed.reverse();
        let backward = chain_effective_authority(&start, &reversed);
        assert!(
            forward.leq(&backward) && backward.leq(&forward),
            "chain authority depends on application order: {forward:?} vs {backward:?}"
        );
    }

    #[test]
    fn compose_collapses_to_single_meet_cap() {
        // MeetCap(a) ∘ MeetCap(b) = MeetCap(a ⊓ b) — pointwise.
        let caps = samples();
        for a in &caps {
            for b in &caps {
                let composed = Compose(MeetCap(a.clone()), MeetCap(b.clone()));
                let collapsed = MeetCap(a.meet(b));
                for x in &caps {
                    let lhs = composed.attenuate(x);
                    let rhs = collapsed.attenuate(x);
                    assert!(lhs.leq(&rhs) && rhs.leq(&lhs));
                }
            }
        }
    }

    #[test]
    fn glob_scopes_are_rejected_from_the_literal_fragment() {
        // ["src/**"] ⊓ ["src/lib.rs"] under literal intersect is ∅,
        // but the true meet is ["src/lib.rs"] — so the newtype must
        // refuse glob scopes rather than claim lattice laws for them.
        let glob = DelegationConstraints {
            scope: DelegationScope {
                allowed_paths: vec!["src/**".to_string()],
                allowed_sinks: vec![SinkClass::WorkspaceWrite],
                allowed_repos: vec![],
            },
            max_delegation_depth: 1,
            expires_at: 100,
        };
        assert!(LiteralDelegation::new(glob).is_none());
    }
}
