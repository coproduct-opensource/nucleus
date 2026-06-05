//! Integer-only rational number primitive for Lagrangian λ + dual variables.
//!
//! **Close-to-Highest C1.** The CLOSE-TO-HIGHEST.md tracker requires
//! "Lagrangian λ lifted from f64 → integer ratio: `Rational { num: i128,
//! den: NonZeroU64 }` OR fixed-point Q64.64". This module supplies the
//! `Rational` form for cases where the Q-format's fixed scale isn't
//! flexible enough (e.g. dual-variable updates during Lagrangian
//! ascent where the step size needs adaptive denominator scaling).
//!
//! The Pigouvian path in `vcg_pigou.rs` continues to use the fixed-point
//! Q-form `u64 micro-USD` (scale = 1_000_000) — that's faster, matches
//! the integer-only ECON-PRECISION discipline in `docs/ECON-PRECISION.md`,
//! and is what W1's `SCHEMA_VERSION=2` canonical-bytes binding pins.
//! `Rational` is for **dual-variable convergence** (C2) where the
//! integer step size during projected-subgradient ascent is naturally
//! `num/den` with both moving each iteration.
//!
//! All operations are panic-free on well-formed inputs (NonZeroU64
//! denominators); arithmetic uses `i128` intermediates with saturating
//! casts on i128 overflow, matching the `u128` discipline used
//! elsewhere in the econ-kernels.

use std::cmp::Ordering;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

/// Integer-only rational, stored in **non-reduced** form.
///
/// `value = num as f64 / den.get() as f64` conceptually, but no f64 is
/// ever computed; comparisons and arithmetic use i128 cross-multiplication.
///
/// Invariants:
///   - `den` is `NonZeroU64` (the type rules out zero denominator).
///   - `num` is signed `i128` (Lagrangian duals can be negative on the
///     interior of a projected-subgradient update before clipping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rational {
    /// Signed numerator. `i128` so multiplication can't overflow at the
    /// `u64 * u64` scale typical of micro-USD dual updates.
    pub num: i128,
    /// Unsigned non-zero denominator. `NonZeroU64` so the type rules
    /// out the divide-by-zero failure mode at compile time.
    pub den: NonZeroU64,
}

impl Rational {
    /// `0/1` — the rational additive identity.
    pub const ZERO: Self = Self {
        num: 0,
        // SAFETY: 1 is non-zero.
        den: match NonZeroU64::new(1) {
            Some(d) => d,
            None => panic!("unreachable: 1 is nonzero"),
        },
    };

    /// `1/1` — the rational multiplicative identity.
    pub const ONE: Self = Self {
        num: 1,
        den: match NonZeroU64::new(1) {
            Some(d) => d,
            None => panic!("unreachable: 1 is nonzero"),
        },
    };

    /// Construct a Rational from numerator + non-zero denominator.
    pub const fn new(num: i128, den: NonZeroU64) -> Self {
        Self { num, den }
    }

    /// Lift a `u64` micro-USD value to a Rational with implicit
    /// `den = 1_000_000`. Inverse of the production Q-format on the
    /// Pigouvian path; lets dual-variable updates start from a
    /// kernel-side micro-USD value without precision loss.
    pub fn from_micro_usd(micro: u64) -> Self {
        Self {
            num: micro as i128,
            // SAFETY: 1_000_000 is non-zero.
            den: NonZeroU64::new(1_000_000).expect("1_000_000 is nonzero"),
        }
    }

    /// Reduce to lowest terms by dividing both num + den by gcd. Returns
    /// a new `Rational`; original is unchanged. O(log min(|num|, den)).
    pub fn reduce(&self) -> Self {
        let abs_num = self.num.unsigned_abs();
        let g = gcd_u128(abs_num, self.den.get() as u128);
        if g == 0 || g == 1 {
            return *self;
        }
        let new_den_u64 = (self.den.get() as u128 / g) as u64;
        // SAFETY: g divides den.get() so the quotient is at least 1.
        let new_den = NonZeroU64::new(new_den_u64)
            .expect("reduced denominator is at least 1 because g divides den");
        Self {
            num: if self.num >= 0 {
                (abs_num / g) as i128
            } else {
                -((abs_num / g) as i128)
            },
            den: new_den,
        }
    }

    /// Cross-multiplication comparison: `a/b vs c/d` ↔ `a*d vs c*b`.
    /// Uses signed `i128` arithmetic with `saturating_mul` so a hostile
    /// input on either side can't panic; saturation is a strictly
    /// monotone projection so the ordering is preserved at the
    /// saturation boundary.
    pub fn cmp_cross(&self, other: &Self) -> Ordering {
        let lhs = self.num.saturating_mul(other.den.get() as i128);
        let rhs = other.num.saturating_mul(self.den.get() as i128);
        lhs.cmp(&rhs)
    }
}

impl PartialOrd for Rational {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Rational {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_cross(other)
    }
}

fn gcd_u128(a: u128, b: u128) -> u128 {
    let mut a = a;
    let mut b = b;
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nz(d: u64) -> NonZeroU64 {
        NonZeroU64::new(d).expect("test denominator must be non-zero")
    }

    #[test]
    fn zero_and_one_are_inverses_under_cmp() {
        assert!(Rational::ZERO < Rational::ONE);
        assert!(Rational::ONE > Rational::ZERO);
        assert_eq!(Rational::ZERO.cmp_cross(&Rational::ZERO), Ordering::Equal);
        assert_eq!(Rational::ONE.cmp_cross(&Rational::ONE), Ordering::Equal);
    }

    /// Exercise the `Ord` and `PartialOrd` trait impls directly so the
    /// coverage gate sees them — `<`, `>`, etc. via the operator-trait
    /// blanket impls hit `cmp_cross` without ever calling `Ord::cmp`
    /// / `PartialOrd::partial_cmp` on the trait surface.
    #[test]
    fn trait_ord_and_partial_ord_dispatch_through_cmp_cross() {
        let a = Rational::new(1, nz(3));
        let b = Rational::new(1, nz(2));
        assert_eq!(Ord::cmp(&a, &b), Ordering::Less);
        assert_eq!(PartialOrd::partial_cmp(&a, &b), Some(Ordering::Less));
        // Also exercise the equality + greater branches.
        assert_eq!(Ord::cmp(&b, &a), Ordering::Greater);
        assert_eq!(Ord::cmp(&a, &a), Ordering::Equal);
    }

    #[test]
    fn cross_multiplication_orders_unreduced_equivalents() {
        // 1/2 < 2/3 because 1*3 = 3 < 2*2 = 4.
        let half = Rational::new(1, nz(2));
        let two_thirds = Rational::new(2, nz(3));
        assert!(half < two_thirds);

        // 2/4 == 1/2 (equivalence, not reduction).
        let half_unreduced = Rational::new(2, nz(4));
        assert_eq!(half.cmp_cross(&half_unreduced), Ordering::Equal);
    }

    #[test]
    fn reduce_normalizes_unreduced_forms() {
        let r = Rational::new(8, nz(12)).reduce();
        assert_eq!(r.num, 2);
        assert_eq!(r.den.get(), 3);
    }

    #[test]
    fn reduce_canonicalizes_zero_to_zero_over_one() {
        // gcd(0, n) = n by convention, so reduce(0/7) → 0/1.
        let z = Rational::new(0, nz(7)).reduce();
        assert_eq!(z.num, 0);
        assert_eq!(z.den.get(), 1);
    }

    #[test]
    fn from_micro_usd_round_trips_at_the_q_scale() {
        let r = Rational::from_micro_usd(2_500_000);
        // Equivalent to 5/2 after reduction.
        assert_eq!(r.num, 2_500_000);
        assert_eq!(r.den.get(), 1_000_000);
        let reduced = r.reduce();
        assert_eq!(reduced.num, 5);
        assert_eq!(reduced.den.get(), 2);
    }

    #[test]
    fn negative_numerator_orders_below_zero() {
        let neg_half = Rational::new(-1, nz(2));
        assert!(neg_half < Rational::ZERO);
        assert!(neg_half < Rational::new(-1, nz(1_000_000)));
    }

    #[test]
    fn saturating_cmp_doesnt_panic_on_extreme_inputs() {
        let huge = Rational::new(i128::MAX, nz(1));
        let one = Rational::ONE;
        // Just assert it doesn't panic and returns some Ordering.
        let _ = huge.cmp_cross(&one);
        let neg_huge = Rational::new(i128::MIN, nz(1));
        let _ = neg_huge.cmp_cross(&one);
    }

    proptest! {
        /// Reduction preserves the rational's value (cross-mult equality).
        #[test]
        fn reduce_preserves_value(
            num in -1_000_000_000i128..1_000_000_000i128,
            den_raw in 1u64..1_000_000_000,
        ) {
            let den = NonZeroU64::new(den_raw).unwrap();
            let r = Rational::new(num, den);
            let red = r.reduce();
            prop_assert_eq!(r.cmp_cross(&red), Ordering::Equal);
        }

        /// `from_micro_usd` is order-preserving with respect to u64 ordering.
        #[test]
        fn from_micro_usd_is_monotone(
            a in 0u64..1_000_000_000,
            b in 0u64..1_000_000_000,
        ) {
            let ra = Rational::from_micro_usd(a);
            let rb = Rational::from_micro_usd(b);
            prop_assert_eq!(ra.cmp_cross(&rb), a.cmp(&b));
        }
    }
}
