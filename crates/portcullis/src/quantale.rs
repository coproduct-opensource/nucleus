//! **The enriching value object `V`: capability as a residuated quantale.**
//!
//! The Enriched-Reflection model of the PCA fabric is a *quantale-enriched
//! category*. Its enriching value `V` is the capability lattice equipped with a
//! monoidal product `⊗`. This module makes that structure first-class:
//!
//! - [`Quantale`]: a bounded lattice with a monoid `(⊗, I)` where `⊗`
//!   distributes over `∨` and annihilates `⊥`. For capability the monoid is
//!   **meet** with unit **⊤** (idempotent, commutative).
//! - [`ResiduatedQuantale`]: `⊗` has a right adjoint `⊸` (the residual / internal
//!   hom) — `a ⊗ b ≤ c  ⟺  b ≤ a ⊸ c`. For `⊗ = meet` the residual is exactly the
//!   **Heyting implication**, so `a ⊸ c` is the *optimal* (greatest) attenuation
//!   of an authority that still keeps `a ⊗ b ≤ c`.
//!
//! These traits live in `portcullis` (mirroring the dependency-free
//! `coproduct-algebra` traits, which a public crate can't depend on); the impls
//! are *orphan-free* (local trait, `portcullis-core` type). For the finite
//! [`CapabilityLevel`] every law is checked **exhaustively** — for a finite type
//! an exhaustive check over all tuples is a complete proof.

use portcullis_core::category::{BoundedLattice, Lattice};
use portcullis_core::{CapabilityLattice, CapabilityLevel};

/// A unital quantale: a [`BoundedLattice`] that is also a monoid `(⊗, I)` with
/// `⊗` distributing over `∨` and annihilating `⊥`.
///
/// Laws (see [`verify_quantale`]): `(⊗, unit)` is a monoid; `a ⊗ (b ∨ c) =
/// (a ⊗ b) ∨ (a ⊗ c)`; `a ⊗ ⊥ = ⊥`.
pub trait Quantale: BoundedLattice {
    /// The monoidal unit `I`.
    fn unit() -> Self;
    /// The monoidal product `a ⊗ b`.
    fn tensor(&self, other: &Self) -> Self;
}

/// A residuated quantale: `⊗` has a right adjoint `⊸` satisfying the adjunction
/// `a ⊗ b ≤ c  ⟺  b ≤ a ⊸ c` (see [`verify_residuation`]). When `⊗ = meet`, the
/// residual is the Heyting implication.
pub trait ResiduatedQuantale: Quantale {
    /// The residual `a ⊸ c = ⋁{ b | a ⊗ b ≤ c }`.
    fn residual(&self, ceiling: &Self) -> Self;
}

// ── CapabilityLevel (3-element chain) — a residuated quantale ──────────────

impl Quantale for CapabilityLevel {
    fn unit() -> Self {
        // ⊤ is the unit of meet: a ∧ ⊤ = a.
        CapabilityLevel::Always
    }
    fn tensor(&self, other: &Self) -> Self {
        // The capability monoid is meet (weakest-link / attenuation).
        Lattice::meet(self, other)
    }
}

impl ResiduatedQuantale for CapabilityLevel {
    fn residual(&self, ceiling: &Self) -> Self {
        // Heyting implication on a chain: a ⊸ c = ⊤ if a ≤ c, else c.
        // (For a > c: max{b | a ∧ b ≤ c} = c.)
        if Lattice::leq(self, ceiling) {
            CapabilityLevel::Always
        } else {
            *ceiling
        }
    }
}

// ── CapabilityLattice (13-dim product) — a quantale (the enriching V) ──────
//
// The product of quantales is a quantale, pointwise: ⊗ = meet, unit = ⊤. The
// residual is also pointwise Heyting implication, but the lattice does not
// expose its 13 fields here, so `ResiduatedQuantale` for the product is left for
// the field-accessor follow-on; `Quantale` (the enriching structure the V-Cat
// needs) is available now via the existing meet/top.

impl Quantale for CapabilityLattice {
    fn unit() -> Self {
        <CapabilityLattice as BoundedLattice>::top()
    }
    fn tensor(&self, other: &Self) -> Self {
        Lattice::meet(self, other)
    }
}

// ── Law-checkers (return violations; empty ⇒ the laws hold) ────────────────

/// Verify the quantale laws over `samples`: unit (`a⊗I = I⊗a = a`),
/// associativity, `⊥`-annihilation (`a⊗⊥ = ⊥`), and distribution of `⊗` over `∨`.
pub fn verify_quantale<Q>(samples: &[Q]) -> Vec<String>
where
    Q: Quantale + std::fmt::Debug,
{
    let mut bad = Vec::new();
    let unit = Q::unit();
    let bottom = Q::bottom();
    for a in samples {
        if a.tensor(&unit) != *a || unit.tensor(a) != *a {
            bad.push(format!("unit law fails at {a:?}"));
        }
        if a.tensor(&bottom) != bottom || bottom.tensor(a) != bottom {
            bad.push(format!("bottom-annihilation fails at {a:?}"));
        }
        for b in samples {
            for c in samples {
                if a.tensor(&b.tensor(c)) != a.tensor(b).tensor(c) {
                    bad.push(format!("associativity fails at {a:?},{b:?},{c:?}"));
                }
                // a ⊗ (b ∨ c) = (a ⊗ b) ∨ (a ⊗ c)
                if a.tensor(&b.join(c)) != a.tensor(b).join(&a.tensor(c)) {
                    bad.push(format!("⊗/∨ distribution fails at {a:?},{b:?},{c:?}"));
                }
            }
        }
    }
    bad
}

/// Verify the residuation adjunction `a ⊗ b ≤ c ⟺ b ≤ a ⊸ c` over all triples
/// in `samples`, and that `a ⊸ c` is the *greatest* such `b`.
pub fn verify_residuation<Q>(samples: &[Q]) -> Vec<String>
where
    Q: ResiduatedQuantale + std::fmt::Debug,
{
    let mut bad = Vec::new();
    for a in samples {
        for c in samples {
            let r = a.residual(c);
            for b in samples {
                let lhs = a.tensor(b).leq(c); // a ⊗ b ≤ c
                let rhs = b.leq(&r); // b ≤ a ⊸ c
                if lhs != rhs {
                    bad.push(format!(
                        "adjunction fails: a={a:?} b={b:?} c={c:?} (a⊗b≤c={lhs}, b≤a⊸c={rhs})"
                    ));
                }
            }
            // `r` itself must satisfy a ⊗ r ≤ c (it is the greatest such b).
            if !a.tensor(&r).leq(c) {
                bad.push(format!(
                    "residual not below ceiling: a={a:?} c={c:?} r={r:?}"
                ));
            }
        }
    }
    bad
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEVELS: [CapabilityLevel; 3] = [
        CapabilityLevel::Never,
        CapabilityLevel::LowRisk,
        CapabilityLevel::Always,
    ];

    #[test]
    fn capability_level_is_a_quantale() {
        // Exhaustive over the 3-element chain ⇒ a complete proof.
        assert!(verify_quantale(&LEVELS).is_empty());
    }

    #[test]
    fn capability_level_is_residuated() {
        // The residuation adjunction holds for all 27 triples ⇒ CapabilityLevel
        // is a residuated quantale (= Heyting algebra in the quantale view).
        assert!(verify_residuation(&LEVELS).is_empty());
    }

    #[test]
    fn residual_is_optimal_attenuation() {
        // a ⊸ c is the greatest authority that, met with a, stays ≤ c.
        use CapabilityLevel::*;
        // Always ⊸ LowRisk = LowRisk (must drop to the ceiling).
        assert_eq!(Always.residual(&LowRisk), LowRisk);
        // LowRisk ⊸ Always = Always (already below ⇒ no constraint).
        assert_eq!(LowRisk.residual(&Always), Always);
        // a ⊸ a = ⊤ (a ≤ a).
        for &a in &LEVELS {
            assert_eq!(a.residual(&a), Always);
        }
    }

    #[test]
    fn capability_lattice_product_is_a_quantale() {
        // The enriching value object V: ⊗ = meet, unit = ⊤. Spot-check the
        // monoid + annihilation laws on the 13-dim product.
        let top = <CapabilityLattice as BoundedLattice>::top();
        let bottom = <CapabilityLattice as BoundedLattice>::bottom();
        assert_eq!(top.tensor(&bottom), bottom, "⊥-annihilation on the product");
        assert_eq!(top.tensor(&top), top, "unit on the product");
        assert_eq!(CapabilityLattice::unit(), top, "the product unit is ⊤");
    }
}
