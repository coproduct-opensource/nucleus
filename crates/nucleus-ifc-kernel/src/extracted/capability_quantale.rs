//! Capability as a **residuated quantale** — the slice the residuation
//! adjunction is extracted over (the Enriched-Reflection model's enriching
//! value object `V`; see the spiffy doctrine
//! *"authorization is natural in the execution site"*).
//!
//! The capability scalar `Never < LowRisk < Always` is a 3-element chain. As a
//! quantale its monoid is **meet** (`⊗ = ∧`, weakest-link attenuation) with unit
//! `⊤ = Always`. Meet has a right adjoint `⊸` (the residual / Heyting
//! implication): `a ⊗ b ≤ c  ⟺  b ≤ a ⊸ c`, so `a ⊸ c` is the *optimal*
//! (greatest) attenuation of an authority that still keeps `a ⊗ b ≤ c`.
//!
//! Aeneas translates each function to a CONCRETE body (no opaque `Ord` axiom),
//! so the extracted Lean mirrors the production `CapabilityLevel` clauses. The
//! exhaustive parity tests below pin this mirror to the real
//! `CapabilityLevel::{meet, join, leq}`, and pin `capresidual` to its defining
//! adjunction over all 27 triples — for a 3-element type that is a complete
//! proof of the residuated-quantale laws.

/// Capability level — mirrors the production [`crate::CapabilityLevel`]. The
/// `#[repr(u8)]` discriminants ARE the capability order.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapLevel {
    /// Never allow — bottom element (⊥).
    Never = 0,
    /// Low-risk — auto-approve only low-risk operations.
    LowRisk = 1,
    /// Always auto-approve — top element (⊤).
    Always = 2,
}

/// Numeric rank — `Never=0 < LowRisk=1 < Always=2`, exactly the `#[repr(u8)]`
/// discriminants. The rank order IS the capability order.
pub fn caprank(l: CapLevel) -> u8 {
    match l {
        CapLevel::Never => 0,
        CapLevel::LowRisk => 1,
        CapLevel::Always => 2,
    }
}

/// The quantale monoidal unit `I = ⊤ = Always` (the unit of meet: `a ∧ ⊤ = a`).
pub fn capunit() -> CapLevel {
    CapLevel::Always
}

/// The lattice bottom `⊥ = Never` (the meet annihilator: `a ∧ ⊥ = ⊥`).
pub fn capbot() -> CapLevel {
    CapLevel::Never
}

/// Capability meet `a ∧ b` — the quantale product `⊗` (weakest-link): the MIN by
/// rank. Mirrors `CapabilityLevel::meet`.
pub fn capmeet(a: CapLevel, b: CapLevel) -> CapLevel {
    if caprank(a) <= caprank(b) {
        a
    } else {
        b
    }
}

/// Capability join `a ∨ b` — the MAX by rank. Mirrors `CapabilityLevel::join`.
pub fn capjoin(a: CapLevel, b: CapLevel) -> CapLevel {
    if caprank(a) >= caprank(b) {
        a
    } else {
        b
    }
}

/// Capability order `a ≤ b` — `caprank(a) <= caprank(b)`. Mirrors
/// `CapabilityLevel::leq`.
pub fn capleq(a: CapLevel, b: CapLevel) -> bool {
    caprank(a) <= caprank(b)
}

/// The **residual** `a ⊸ c` — the right adjoint of meet (the Heyting
/// implication). On a chain: `a ⊸ c = ⊤` if `a ≤ c`, else `c`. It is the
/// greatest `b` with `a ∧ b ≤ c`, i.e. optimal attenuation under a ceiling.
pub fn capresidual(a: CapLevel, c: CapLevel) -> CapLevel {
    if capleq(a, c) {
        CapLevel::Always
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEVELS: [CapLevel; 3] = [CapLevel::Never, CapLevel::LowRisk, CapLevel::Always];

    fn to_prod(l: CapLevel) -> crate::CapabilityLevel {
        match l {
            CapLevel::Never => crate::CapabilityLevel::Never,
            CapLevel::LowRisk => crate::CapabilityLevel::LowRisk,
            CapLevel::Always => crate::CapabilityLevel::Always,
        }
    }

    #[test]
    fn meet_join_leq_match_production_capability_level() {
        for &a in &LEVELS {
            for &b in &LEVELS {
                assert_eq!(
                    to_prod(capmeet(a, b)),
                    crate::CapabilityLevel::meet(to_prod(a), to_prod(b)),
                    "meet mismatch at {a:?},{b:?}"
                );
                assert_eq!(
                    to_prod(capjoin(a, b)),
                    crate::CapabilityLevel::join(to_prod(a), to_prod(b)),
                    "join mismatch at {a:?},{b:?}"
                );
                assert_eq!(
                    capleq(a, b),
                    crate::CapabilityLevel::leq(to_prod(a), to_prod(b)),
                    "leq mismatch at {a:?},{b:?}"
                );
            }
        }
    }

    #[test]
    fn residuation_adjunction_holds_for_all_triples() {
        // a ⊗ b ≤ c  ⟺  b ≤ a ⊸ c, over all 27 triples ⇒ a complete proof that
        // capability is a residuated quantale (= Heyting algebra) under meet.
        for &a in &LEVELS {
            for &c in &LEVELS {
                let r = capresidual(a, c);
                for &b in &LEVELS {
                    let lhs = capleq(capmeet(a, b), c); // a ⊗ b ≤ c
                    let rhs = capleq(b, r); // b ≤ a ⊸ c
                    assert_eq!(lhs, rhs, "adjunction fails at a={a:?} b={b:?} c={c:?}");
                }
                // r is itself below the ceiling under a (greatest such b).
                assert!(capleq(capmeet(a, r), c), "residual exceeds ceiling at a={a:?} c={c:?}");
            }
        }
    }

    #[test]
    fn quantale_unit_and_annihilation() {
        for &a in &LEVELS {
            assert_eq!(capmeet(a, capunit()), a, "unit law");
            assert_eq!(capmeet(capunit(), a), a, "unit law (left)");
            assert_eq!(capmeet(a, capbot()), capbot(), "⊥-annihilation");
        }
    }
}
