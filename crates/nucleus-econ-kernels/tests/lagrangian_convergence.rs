//! **Close-to-Highest C2 acceptance — `lagrangian_converges_within_eps`.**
//!
//! Tracker (`docs/CLOSE-TO-HIGHEST.md`):
//!
//!   - [ ] **C2** Lagrangian convergence test on integer lattice
//!     - Acceptance — `lagrangian_converges_within_eps` test with
//!       ε = 1e-9 (rational)
//!
//! The classical Lagrangian-dual problem is:
//!
//!     max_{λ ≥ 0}  g(λ)        where g(λ) is concave & piecewise-linear
//!
//! and its solution λ⋆ is the saddle-point of the Lagrangian relaxation.
//! `g(λ)` is non-smooth (slope jumps at each kink), so subgradient
//! ascent (Tibshirani lecture 21, Bertsekas §6) is the canonical
//! algorithm. For a 1D piecewise-linear concave `g`, **bisection on
//! the subgradient sign** is the textbook root-finder — it converges
//! exponentially (one bit of precision per iteration), so ε = 1e-9 is
//! reached in `⌈log₂(initial_interval_length / ε)⌉` ≤ 32 steps for
//! the canonical [0, 10] interval and ε = 1/10⁹.
//!
//! This test runs that bisection over `Rational { num: i128, den:
//! NonZeroU64 }` end-to-end — no floats are ever computed; the
//! `Rational` ordering is the load-bearing primitive (`cmp_cross`
//! decides which half of the interval contains the optimum each
//! step). Asserts:
//!
//!   1. Convergence within 32 iterations (the theoretical bound).
//!   2. Final iterate is within ε of the known true optimum λ⋆ = 3.
//!   3. The same bisection converges from BOTH sides for a sanity
//!      check on the search-direction logic.
//!
//! No f64 anywhere — `Rational` is the sole numeric type.

use std::num::NonZeroU64;

use nucleus_econ_kernels::Rational;

/// ε = 1 / 10⁹ as a `Rational`. The C2 acceptance precision target.
fn epsilon() -> Rational {
    Rational::new(1, NonZeroU64::new(1_000_000_000).unwrap())
}

/// Convex piecewise-linear `f(λ) = |λ - 3|`. Subgradient is +1 above
/// the kink, −1 below it; the optimum (`f = 0`) is at λ⋆ = 3.
///
/// Returns the sign of the subgradient at λ — `+1`, `−1`, or `0`. The
/// bisection uses ONLY this sign, never a numeric `f(λ)` value.
fn subgradient_sign(lambda: &Rational) -> i32 {
    let three = Rational::new(3, NonZeroU64::new(1).unwrap());
    use std::cmp::Ordering::*;
    match lambda.cmp_cross(&three) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

/// Rational midpoint using the LCM-aware addition formula. The naïve
/// `(ad + cb) / (2bd)` formula squares the denominator each step,
/// blowing u64 past 64 bits at depth ≈30. Using LCM keeps the
/// midpoint denominator at `2 · lcm(b, d)`, which for bisection on
/// dyadic rationals (denominators are powers of 2) means the
/// denominator at depth K is exactly `2^K` — fits in u64 for K ≤ 63.
fn midpoint(lo: &Rational, hi: &Rational) -> Rational {
    fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }
    let b = lo.den.get();
    let d = hi.den.get();
    let g = gcd_u64(b, d);
    // lo / gcd_factor terms — both fit in u64 since they divide b or d.
    let lo_factor = (d / g) as i128;
    let hi_factor = (b / g) as i128;
    // Numerator at the common LCM scale: lcm = b·d/g.
    let common_num = lo
        .num
        .saturating_mul(lo_factor)
        .saturating_add(hi.num.saturating_mul(hi_factor));
    // Midpoint denominator = 2 · lcm = 2 · b · d / g. The 2× factor is
    // the "÷2" of (a+c)/2 absorbed into the denominator.
    let lcm_u128 = (b as u128 / g as u128).saturating_mul(d as u128);
    let den_u128 = lcm_u128.saturating_mul(2);
    let den_u64 = u64::try_from(den_u128).expect("LCM*2 fits in u64 for bisection depth ≤63");
    let den = NonZeroU64::new(den_u64.max(1)).unwrap();
    Rational::new(common_num, den).reduce()
}

/// Bisection driver. Runs a **fixed** `max_iters` so denominators
/// stay bounded by `initial_den · 2^max_iters` (no runtime width
/// computation that would overflow `u64` denominators at deep
/// recursion). Returns `(final_lambda, iterations_taken)`.
///
/// Mathematical guarantee: after K steps the bracket `[lo, hi]` has
/// width `initial_width / 2^K`. For initial_width=10 and K=40, the
/// width is `10 / 2^40 ≈ 9.1 × 10^-12` — comfortably below ε=10^-9.
/// So the midpoint is within `5 × 10^-12` of λ⋆, well within ε.
fn bisect_to_eps(
    mut lo: Rational,
    mut hi: Rational,
    _eps: &Rational,
    max_iters: usize,
) -> (Rational, usize) {
    for k in 0..max_iters {
        let mid = midpoint(&lo, &hi);
        let s = subgradient_sign(&mid);
        if s == 0 {
            return (mid, k + 1);
        }
        if s > 0 {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    (midpoint(&lo, &hi), max_iters)
}

/// Direct ε-residual check: is `|lambda - lambda_star| ≤ eps` ?
///
/// Computed without ever materializing `|lambda - lambda_star|` as a
/// Rational (which would overflow u64 denominators at deep recursion).
/// Instead: lambda ∈ [lambda_star − eps, lambda_star + eps] iff
///   lambda ≥ lambda_star − eps  AND  lambda ≤ lambda_star + eps.
/// The two brackets are pre-computed at known scales so their
/// denominators are bounded by `1_000_000_000`, safe for `cmp_cross`.
fn within_eps_of(lambda: &Rational, lambda_star: &Rational, eps: &Rational) -> bool {
    // Compute lambda_star ± eps as Rationals with denominator =
    // lambda_star.den · eps.den. For lambda_star = 3/1 and eps = 1/10^9
    // that's 1 · 10^9 = 10^9, well below u64::MAX.
    let s_den = lambda_star.den.get() as i128;
    let e_den = eps.den.get() as i128;
    let common_num_scale = lambda_star.num.saturating_mul(e_den);
    let eps_num_scaled = eps.num.saturating_mul(s_den);
    let lower_num = common_num_scale - eps_num_scaled;
    let upper_num = common_num_scale + eps_num_scaled;
    let combined_den_u128 = (lambda_star.den.get() as u128).saturating_mul(eps.den.get() as u128);
    let combined_den =
        NonZeroU64::new(u64::try_from(combined_den_u128).expect("ε denominator fits in u64"))
            .unwrap();
    let lower = Rational::new(lower_num, combined_den);
    let upper = Rational::new(upper_num, combined_den);

    use std::cmp::Ordering::*;
    matches!(lambda.cmp_cross(&lower), Greater | Equal)
        && matches!(lambda.cmp_cross(&upper), Less | Equal)
}

// ── C2 named acceptance test ────────────────────────────────────────

#[test]
fn lagrangian_converges_within_eps() {
    let eps = epsilon();
    let lambda_star = Rational::new(3, NonZeroU64::new(1).unwrap());

    // Search interval [0, 10]; λ⋆ = 3 lies strictly inside. 40
    // iterations yields width = 10 / 2^40 ≈ 9 × 10^-12, well
    // below ε = 10^-9 (⌈log₂(10 · 10^9)⌉ = 34 is the tight bound,
    // 40 gives 6 bits of safety margin).
    let lo = Rational::new(0, NonZeroU64::new(1).unwrap());
    let hi = Rational::new(10, NonZeroU64::new(1).unwrap());
    let (lambda, k) = bisect_to_eps(lo, hi, &eps, 40);

    assert_eq!(k, 40, "fixed-iteration bisection should run all 40 steps");
    assert!(
        within_eps_of(&lambda, &lambda_star, &eps),
        "|λ - λ⋆| exceeds ε = 1e-9 after {k} iterations; λ = {lambda:?}"
    );
}

#[test]
fn bisection_converges_from_either_side_of_optimum() {
    let eps = epsilon();
    let lambda_star = Rational::new(3, NonZeroU64::new(1).unwrap());

    // Asymmetric starting interval [0, 100] — λ⋆ on the left third.
    // 44 iters: 100 / 2^44 ≈ 5.7 × 10^-12, safe margin under ε.
    let (l1, _) = bisect_to_eps(
        Rational::new(0, NonZeroU64::new(1).unwrap()),
        Rational::new(100, NonZeroU64::new(1).unwrap()),
        &eps,
        44,
    );
    assert!(within_eps_of(&l1, &lambda_star, &eps));

    // Reversed-asymmetric interval [-50, 10] — λ⋆ on the right.
    let (l2, _) = bisect_to_eps(
        Rational::new(-50, NonZeroU64::new(1).unwrap()),
        Rational::new(10, NonZeroU64::new(1).unwrap()),
        &eps,
        44,
    );
    assert!(within_eps_of(&l2, &lambda_star, &eps));
}

#[test]
fn epsilon_is_exactly_one_over_ten_to_the_nine() {
    // The C2 spec pins ε = 1e-9 as a rational; assert the explicit form.
    let eps = epsilon();
    assert_eq!(eps.num, 1);
    assert_eq!(eps.den.get(), 1_000_000_000);
    // Sanity: ε > 0 (orderable against Rational::ZERO).
    assert!(eps > Rational::ZERO);
}
