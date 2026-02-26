//! Work progress lattice for monotone agent loop movement.
//!
//! Models work item progress as a product lattice of 6 orthogonal dimensions,
//! each a 5-level linear order. The partial order captures the intuition that
//! progress in one dimension does not imply progress in another: reviewed code
//! that hasn't been tested is incomparable with tested code that hasn't been
//! reviewed.
//!
//! # Mathematical Structure
//!
//! ```text
//! ProgressLattice = ReviewDepth × DesignMaturity × Implementation
//!                 × TestCoverage × Integration × MergeReadiness
//!
//! ProgressLevel:  None < Sketched < Drafted < Reviewed < Validated
//! ```
//!
//! Since each dimension is a finite linear order, their product is a finite
//! distributive lattice — and trivially a frame. All lattice operations are
//! componentwise (min for meet, max for join).
//!
//! # Height and Distance
//!
//! The **height** function `h: L → ℕ` maps a lattice position to the sum of
//! its dimension ordinals, giving a scalar measure of total progress:
//!
//! - `h(⊥) = 0` — no work done (raw prompt)
//! - `h(⊤) = 24` — fully validated across all 6 dimensions
//!
//! The **signed distance** `d(a, b) = h(b) - h(a)` is positive for forward
//! progress and negative for backtracking. The backtracking cost function
//! (in the vendor-specific layer) uses `|d|` as the base cost.
//!
//! # Terminal Object
//!
//! The top element `⊤` (all dimensions `Validated`) is the terminal object:
//! every work item has a unique morphism to "merged into main." The
//! Knaster-Tarski theorem guarantees that any monotone (inflationary) layer
//! function has a least fixed point — convergence is guaranteed.
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::progress::{ProgressLattice, ProgressLevel};
//! use lattice_guard::frame::{Lattice, BoundedLattice};
//!
//! let mut a = ProgressLattice::bottom();
//! a.review_depth = ProgressLevel::Reviewed;
//! a.implementation = ProgressLevel::Drafted;
//!
//! let mut b = ProgressLattice::bottom();
//! b.review_depth = ProgressLevel::Sketched;
//! b.test_coverage = ProgressLevel::Validated;
//!
//! // Meet: componentwise min
//! let m = a.meet(&b);
//! assert_eq!(m.review_depth, ProgressLevel::Sketched);
//! assert_eq!(m.implementation, ProgressLevel::None);
//! assert_eq!(m.test_coverage, ProgressLevel::None);
//!
//! // Join: componentwise max
//! let j = a.join(&b);
//! assert_eq!(j.review_depth, ProgressLevel::Reviewed);
//! assert_eq!(j.implementation, ProgressLevel::Drafted);
//! assert_eq!(j.test_coverage, ProgressLevel::Validated);
//!
//! // Height
//! assert_eq!(a.height(), 5); // Reviewed(3) + Drafted(2)
//! assert_eq!(b.height(), 5); // Sketched(1) + Validated(4)
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::frame::{BoundedLattice, CompleteLattice, DistributiveLattice, Frame, Lattice};

// ═══════════════════════════════════════════════════════════════════════════
// PROGRESS LEVEL — 5-element linear order
// ═══════════════════════════════════════════════════════════════════════════

/// Progress level for a single dimension of work.
///
/// A 5-element linear order: `None < Sketched < Drafted < Reviewed < Validated`.
///
/// Each level represents a qualitative milestone in the refinement of a work
/// artifact. The ordering is total: every two levels are comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ProgressLevel {
    /// No work done on this dimension.
    #[default]
    None = 0,
    /// Initial outline or rough draft — structure exists, details missing.
    Sketched = 1,
    /// First complete version — all sections filled in.
    Drafted = 2,
    /// Peer-reviewed or critiqued — feedback incorporated.
    Reviewed = 3,
    /// Passed automated validation — CI, tests, linting all green.
    Validated = 4,
}

impl ProgressLevel {
    /// Ordinal value (0–4) for height computation.
    pub fn ordinal(self) -> u32 {
        self as u32
    }

    /// Componentwise min (meet on a linear order).
    pub fn min(self, other: Self) -> Self {
        if self <= other {
            self
        } else {
            other
        }
    }

    /// Componentwise max (join on a linear order).
    pub fn max(self, other: Self) -> Self {
        if self >= other {
            self
        } else {
            other
        }
    }

    /// Advance to the next level, saturating at `Validated`.
    pub fn advance(self) -> Self {
        match self {
            Self::None => Self::Sketched,
            Self::Sketched => Self::Drafted,
            Self::Drafted => Self::Reviewed,
            Self::Reviewed => Self::Validated,
            Self::Validated => Self::Validated,
        }
    }

    /// Regress to the previous level, saturating at `None`.
    pub fn regress(self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Sketched => Self::None,
            Self::Drafted => Self::Sketched,
            Self::Reviewed => Self::Drafted,
            Self::Validated => Self::Reviewed,
        }
    }
}

impl std::fmt::Display for ProgressLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Sketched => write!(f, "sketched"),
            Self::Drafted => write!(f, "drafted"),
            Self::Reviewed => write!(f, "reviewed"),
            Self::Validated => write!(f, "validated"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROGRESS DIMENSION — which axis of the product lattice
// ═══════════════════════════════════════════════════════════════════════════

/// Identifies which dimension of the progress lattice a layer can advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ProgressDimension {
    /// How deeply the problem has been analyzed/reviewed.
    ReviewDepth,
    /// How mature the design/proposal is.
    DesignMaturity,
    /// How far along the implementation is.
    Implementation,
    /// How well tested the implementation is.
    TestCoverage,
    /// How well integrated with the existing system.
    Integration,
    /// How ready for final merge (PR created, CI passing, etc.).
    MergeReadiness,
}

impl ProgressDimension {
    /// All dimensions in canonical order.
    pub const ALL: [Self; 6] = [
        Self::ReviewDepth,
        Self::DesignMaturity,
        Self::Implementation,
        Self::TestCoverage,
        Self::Integration,
        Self::MergeReadiness,
    ];
}

impl std::fmt::Display for ProgressDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReviewDepth => write!(f, "review_depth"),
            Self::DesignMaturity => write!(f, "design_maturity"),
            Self::Implementation => write!(f, "implementation"),
            Self::TestCoverage => write!(f, "test_coverage"),
            Self::Integration => write!(f, "integration"),
            Self::MergeReadiness => write!(f, "merge_readiness"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROGRESS LATTICE — product of 6 progress dimensions
// ═══════════════════════════════════════════════════════════════════════════

/// The work progress lattice: a product of 6 progress dimensions.
///
/// This is a bounded distributive lattice (and frame) with componentwise
/// ordering. The partial order captures independence between dimensions:
/// reviewed but untested code is incomparable with tested but unreviewed code.
///
/// # Lattice Properties
///
/// - **Bottom** `⊥`: all dimensions `None` (raw prompt, no work done)
/// - **Top** `⊤`: all dimensions `Validated` (fully validated, merged)
/// - **Meet** `∧`: componentwise min (most restrictive)
/// - **Join** `∨`: componentwise max (least restrictive)
/// - **Leq** `≤`: componentwise `<=`
///
/// # Height
///
/// `height() = Σ dimension.ordinal()`, ranging from 0 (bottom) to 24 (top).
/// The height function is a lattice homomorphism to (ℕ, min, max).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProgressLattice {
    /// How deeply the problem has been analyzed/reviewed.
    pub review_depth: ProgressLevel,
    /// How mature the design/proposal is.
    pub design_maturity: ProgressLevel,
    /// How far along the implementation is.
    pub implementation: ProgressLevel,
    /// How well tested the implementation is.
    pub test_coverage: ProgressLevel,
    /// How well integrated with the existing system.
    pub integration: ProgressLevel,
    /// How ready for final merge (PR created, CI passing, etc.).
    pub merge_readiness: ProgressLevel,
}

impl ProgressLattice {
    /// Height of a lattice position: sum of dimension ordinals.
    ///
    /// `height(⊥) = 0`, `height(⊤) = 24`.
    pub fn height(&self) -> u32 {
        self.review_depth.ordinal()
            + self.design_maturity.ordinal()
            + self.implementation.ordinal()
            + self.test_coverage.ordinal()
            + self.integration.ordinal()
            + self.merge_readiness.ordinal()
    }

    /// Signed distance from `self` to `target`.
    ///
    /// Positive means `target` is higher (forward progress).
    /// Negative means `target` is lower (backtracking).
    /// Zero means same height (not necessarily same position).
    pub fn signed_distance(&self, target: &Self) -> i32 {
        target.height() as i32 - self.height() as i32
    }

    /// Get the level for a specific dimension.
    pub fn dimension(&self, dim: ProgressDimension) -> ProgressLevel {
        match dim {
            ProgressDimension::ReviewDepth => self.review_depth,
            ProgressDimension::DesignMaturity => self.design_maturity,
            ProgressDimension::Implementation => self.implementation,
            ProgressDimension::TestCoverage => self.test_coverage,
            ProgressDimension::Integration => self.integration,
            ProgressDimension::MergeReadiness => self.merge_readiness,
        }
    }

    /// Set the level for a specific dimension.
    pub fn set_dimension(&mut self, dim: ProgressDimension, level: ProgressLevel) {
        match dim {
            ProgressDimension::ReviewDepth => self.review_depth = level,
            ProgressDimension::DesignMaturity => self.design_maturity = level,
            ProgressDimension::Implementation => self.implementation = level,
            ProgressDimension::TestCoverage => self.test_coverage = level,
            ProgressDimension::Integration => self.integration = level,
            ProgressDimension::MergeReadiness => self.merge_readiness = level,
        }
    }

    /// Advance a specific dimension by one level (saturating at Validated).
    ///
    /// Returns a new lattice position. This is an inflationary operation:
    /// `self.advance(dim) >= self` for all `dim`.
    pub fn advance(&self, dim: ProgressDimension) -> Self {
        let mut result = self.clone();
        let current = result.dimension(dim);
        result.set_dimension(dim, current.advance());
        result
    }

    /// Regress a specific dimension by one level (saturating at None).
    ///
    /// Returns a new lattice position. This is a deflationary operation:
    /// `self.regress(dim) <= self` for all `dim`.
    pub fn regress(&self, dim: ProgressDimension) -> Self {
        let mut result = self.clone();
        let current = result.dimension(dim);
        result.set_dimension(dim, current.regress());
        result
    }

    /// Per-dimension breakdown of which dimensions regressed between two positions.
    ///
    /// Returns a list of (dimension, from_level, to_level) for each dimension
    /// where `target < self`.
    pub fn regressions(
        &self,
        target: &Self,
    ) -> Vec<(ProgressDimension, ProgressLevel, ProgressLevel)> {
        ProgressDimension::ALL
            .iter()
            .filter_map(|&dim| {
                let from = self.dimension(dim);
                let to = target.dimension(dim);
                if to < from {
                    Some((dim, from, to))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if this position is the terminal object (all Validated).
    pub fn is_terminal(&self) -> bool {
        self == &Self::top()
    }

    /// Fraction of progress toward the terminal object (0.0 to 1.0).
    pub fn completion_fraction(&self) -> f64 {
        self.height() as f64 / Self::top().height() as f64
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FRAME TRAIT IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

impl Lattice for ProgressLattice {
    fn meet(&self, other: &Self) -> Self {
        Self {
            review_depth: self.review_depth.min(other.review_depth),
            design_maturity: self.design_maturity.min(other.design_maturity),
            implementation: self.implementation.min(other.implementation),
            test_coverage: self.test_coverage.min(other.test_coverage),
            integration: self.integration.min(other.integration),
            merge_readiness: self.merge_readiness.min(other.merge_readiness),
        }
    }

    fn join(&self, other: &Self) -> Self {
        Self {
            review_depth: self.review_depth.max(other.review_depth),
            design_maturity: self.design_maturity.max(other.design_maturity),
            implementation: self.implementation.max(other.implementation),
            test_coverage: self.test_coverage.max(other.test_coverage),
            integration: self.integration.max(other.integration),
            merge_readiness: self.merge_readiness.max(other.merge_readiness),
        }
    }

    fn leq(&self, other: &Self) -> bool {
        self.review_depth <= other.review_depth
            && self.design_maturity <= other.design_maturity
            && self.implementation <= other.implementation
            && self.test_coverage <= other.test_coverage
            && self.integration <= other.integration
            && self.merge_readiness <= other.merge_readiness
    }
}

impl BoundedLattice for ProgressLattice {
    fn top() -> Self {
        Self {
            review_depth: ProgressLevel::Validated,
            design_maturity: ProgressLevel::Validated,
            implementation: ProgressLevel::Validated,
            test_coverage: ProgressLevel::Validated,
            integration: ProgressLevel::Validated,
            merge_readiness: ProgressLevel::Validated,
        }
    }

    fn bottom() -> Self {
        Self {
            review_depth: ProgressLevel::None,
            design_maturity: ProgressLevel::None,
            implementation: ProgressLevel::None,
            test_coverage: ProgressLevel::None,
            integration: ProgressLevel::None,
            merge_readiness: ProgressLevel::None,
        }
    }
}

impl DistributiveLattice for ProgressLattice {}

impl CompleteLattice for ProgressLattice {
    fn meet_all<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter()
            .reduce(|a, b| a.meet(&b))
            .unwrap_or_else(Self::top)
    }

    fn join_all<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter()
            .reduce(|a, b| a.join(&b))
            .unwrap_or_else(Self::bottom)
    }
}

impl Frame for ProgressLattice {}

impl std::fmt::Display for ProgressLattice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Progress(review={}, design={}, impl={}, test={}, integ={}, merge={} | h={})",
            self.review_depth,
            self.design_maturity,
            self.implementation,
            self.test_coverage,
            self.integration,
            self.merge_readiness,
            self.height(),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Lattice law verification ──────────────────────────────────────

    fn sample_positions() -> Vec<ProgressLattice> {
        vec![
            ProgressLattice::bottom(),
            ProgressLattice::top(),
            ProgressLattice {
                review_depth: ProgressLevel::Reviewed,
                implementation: ProgressLevel::Drafted,
                ..Default::default()
            },
            ProgressLattice {
                review_depth: ProgressLevel::Sketched,
                test_coverage: ProgressLevel::Validated,
                ..Default::default()
            },
            ProgressLattice {
                design_maturity: ProgressLevel::Drafted,
                integration: ProgressLevel::Reviewed,
                merge_readiness: ProgressLevel::Sketched,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_meet_commutativity() {
        for a in sample_positions() {
            for b in sample_positions() {
                assert_eq!(a.meet(&b), b.meet(&a), "meet must be commutative");
            }
        }
    }

    #[test]
    fn test_join_commutativity() {
        for a in sample_positions() {
            for b in sample_positions() {
                assert_eq!(a.join(&b), b.join(&a), "join must be commutative");
            }
        }
    }

    #[test]
    fn test_meet_associativity() {
        let samples = sample_positions();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    assert_eq!(
                        a.meet(&b.meet(c)),
                        a.meet(b).meet(c),
                        "meet must be associative"
                    );
                }
            }
        }
    }

    #[test]
    fn test_join_associativity() {
        let samples = sample_positions();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    assert_eq!(
                        a.join(&b.join(c)),
                        a.join(b).join(c),
                        "join must be associative"
                    );
                }
            }
        }
    }

    #[test]
    fn test_idempotence() {
        for a in sample_positions() {
            assert_eq!(a.meet(&a), a, "meet must be idempotent");
            assert_eq!(a.join(&a), a, "join must be idempotent");
        }
    }

    #[test]
    fn test_absorption() {
        for a in sample_positions() {
            for b in sample_positions() {
                // a ∧ (a ∨ b) = a
                assert_eq!(a.meet(&a.join(&b)), a, "absorption: a ∧ (a ∨ b) = a");
                // a ∨ (a ∧ b) = a
                assert_eq!(a.join(&a.meet(&b)), a, "absorption: a ∨ (a ∧ b) = a");
            }
        }
    }

    #[test]
    fn test_distributivity() {
        let samples = sample_positions();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    // a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)
                    let lhs = a.meet(&b.join(c));
                    let rhs = a.meet(b).join(&a.meet(c));
                    assert_eq!(lhs, rhs, "meet must distribute over join");

                    // a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)
                    let lhs = a.join(&b.meet(c));
                    let rhs = a.join(b).meet(&a.join(c));
                    assert_eq!(lhs, rhs, "join must distribute over meet");
                }
            }
        }
    }

    // ── Bounded lattice laws ──────────────────────────────────────────

    #[test]
    fn test_top_is_meet_identity() {
        let top = ProgressLattice::top();
        for a in sample_positions() {
            assert_eq!(a.meet(&top), a, "a ∧ ⊤ = a");
        }
    }

    #[test]
    fn test_bottom_is_join_identity() {
        let bottom = ProgressLattice::bottom();
        for a in sample_positions() {
            assert_eq!(a.join(&bottom), a, "a ∨ ⊥ = a");
        }
    }

    #[test]
    fn test_bottom_is_meet_annihilator() {
        let bottom = ProgressLattice::bottom();
        for a in sample_positions() {
            assert_eq!(a.meet(&bottom), bottom, "a ∧ ⊥ = ⊥");
        }
    }

    #[test]
    fn test_top_is_join_annihilator() {
        let top = ProgressLattice::top();
        for a in sample_positions() {
            assert_eq!(a.join(&top), top, "a ∨ ⊤ = ⊤");
        }
    }

    // ── Partial order consistency ─────────────────────────────────────

    #[test]
    fn test_leq_consistent_with_meet() {
        for a in sample_positions() {
            for b in sample_positions() {
                // a ≤ b iff a ∧ b = a
                assert_eq!(
                    a.leq(&b),
                    a.meet(&b) == a,
                    "leq must be consistent with meet"
                );
            }
        }
    }

    #[test]
    fn test_leq_reflexive() {
        for a in sample_positions() {
            assert!(a.leq(&a), "leq must be reflexive");
        }
    }

    #[test]
    fn test_leq_antisymmetric() {
        for a in sample_positions() {
            for b in sample_positions() {
                if a.leq(&b) && b.leq(&a) {
                    assert_eq!(a, b, "leq must be antisymmetric");
                }
            }
        }
    }

    #[test]
    fn test_leq_transitive() {
        let samples = sample_positions();
        for a in &samples {
            for b in &samples {
                for c in &samples {
                    if a.leq(b) && b.leq(c) {
                        assert!(a.leq(c), "leq must be transitive");
                    }
                }
            }
        }
    }

    // ── Complete lattice ──────────────────────────────────────────────

    #[test]
    fn test_meet_all_empty_is_top() {
        let result = ProgressLattice::meet_all(std::iter::empty());
        assert_eq!(result, ProgressLattice::top());
    }

    #[test]
    fn test_join_all_empty_is_bottom() {
        let result = ProgressLattice::join_all(std::iter::empty());
        assert_eq!(result, ProgressLattice::bottom());
    }

    #[test]
    fn test_meet_all_is_greatest_lower_bound() {
        let samples = sample_positions();
        let result = ProgressLattice::meet_all(samples.clone());
        // Result should be ≤ every element
        for s in &samples {
            assert!(result.leq(s), "meet_all must be ≤ every element");
        }
    }

    #[test]
    fn test_join_all_is_least_upper_bound() {
        let samples = sample_positions();
        let result = ProgressLattice::join_all(samples.clone());
        // Every element should be ≤ result
        for s in &samples {
            assert!(s.leq(&result), "every element must be ≤ join_all");
        }
    }

    // ── Height and distance ──────────────────────────────────────────

    #[test]
    fn test_height_bottom_is_zero() {
        assert_eq!(ProgressLattice::bottom().height(), 0);
    }

    #[test]
    fn test_height_top_is_24() {
        assert_eq!(ProgressLattice::top().height(), 24);
    }

    #[test]
    fn test_height_monotone() {
        // a ≤ b implies h(a) ≤ h(b)
        for a in sample_positions() {
            for b in sample_positions() {
                if a.leq(&b) {
                    assert!(
                        a.height() <= b.height(),
                        "height must be monotone: {} ≤ {} but h({}) > h({})",
                        a,
                        b,
                        a.height(),
                        b.height()
                    );
                }
            }
        }
    }

    #[test]
    fn test_signed_distance_symmetry() {
        for a in sample_positions() {
            for b in sample_positions() {
                assert_eq!(
                    a.signed_distance(&b),
                    -b.signed_distance(&a),
                    "signed_distance must be antisymmetric"
                );
            }
        }
    }

    #[test]
    fn test_signed_distance_self_is_zero() {
        for a in sample_positions() {
            assert_eq!(a.signed_distance(&a), 0);
        }
    }

    // ── Advance and regress ──────────────────────────────────────────

    #[test]
    fn test_advance_is_inflationary() {
        for a in sample_positions() {
            for dim in ProgressDimension::ALL {
                let advanced = a.advance(dim);
                assert!(a.leq(&advanced), "advance must be inflationary");
            }
        }
    }

    #[test]
    fn test_regress_is_deflationary() {
        for a in sample_positions() {
            for dim in ProgressDimension::ALL {
                let regressed = a.regress(dim);
                assert!(regressed.leq(&a), "regress must be deflationary");
            }
        }
    }

    #[test]
    fn test_advance_at_top_is_idempotent() {
        let top = ProgressLattice::top();
        for dim in ProgressDimension::ALL {
            assert_eq!(top.advance(dim), top, "advance at top must be idempotent");
        }
    }

    #[test]
    fn test_regress_at_bottom_is_idempotent() {
        let bottom = ProgressLattice::bottom();
        for dim in ProgressDimension::ALL {
            assert_eq!(
                bottom.regress(dim),
                bottom,
                "regress at bottom must be idempotent"
            );
        }
    }

    // ── Regressions ──────────────────────────────────────────────────

    #[test]
    fn test_regressions_empty_when_forward() {
        let a = ProgressLattice::bottom();
        let b = ProgressLattice::top();
        assert!(a.regressions(&b).is_empty(), "no regressions going forward");
    }

    #[test]
    fn test_regressions_detect_backtrack() {
        let a = ProgressLattice {
            review_depth: ProgressLevel::Reviewed,
            implementation: ProgressLevel::Drafted,
            ..Default::default()
        };
        let b = ProgressLattice {
            review_depth: ProgressLevel::Sketched,    // regression
            implementation: ProgressLevel::Validated, // progress
            ..Default::default()
        };
        let regs = a.regressions(&b);
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].0, ProgressDimension::ReviewDepth);
        assert_eq!(regs[0].1, ProgressLevel::Reviewed);
        assert_eq!(regs[0].2, ProgressLevel::Sketched);
    }

    // ── Terminal and completion ───────────────────────────────────────

    #[test]
    fn test_is_terminal() {
        assert!(ProgressLattice::top().is_terminal());
        assert!(!ProgressLattice::bottom().is_terminal());
    }

    #[test]
    fn test_completion_fraction() {
        assert!((ProgressLattice::bottom().completion_fraction() - 0.0).abs() < f64::EPSILON);
        assert!((ProgressLattice::top().completion_fraction() - 1.0).abs() < f64::EPSILON);
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn test_display() {
        let p = ProgressLattice {
            review_depth: ProgressLevel::Reviewed,
            implementation: ProgressLevel::Drafted,
            ..Default::default()
        };
        let s = format!("{p}");
        assert!(s.contains("review=reviewed"));
        assert!(s.contains("impl=drafted"));
        assert!(s.contains("h=5"));
    }

    // ── Frame law: finite meets distribute over arbitrary joins ──────

    #[test]
    fn test_frame_law_finite_meet_distributes_over_arbitrary_join() {
        let samples = sample_positions();
        // For each a, check a ∧ (⋁ᵢ bᵢ) = ⋁ᵢ (a ∧ bᵢ)
        for a in &samples {
            let join_all = ProgressLattice::join_all(samples.clone());
            let lhs = a.meet(&join_all);
            let rhs = ProgressLattice::join_all(samples.iter().map(|b| a.meet(b)));
            assert_eq!(lhs, rhs, "frame law: a ∧ (⋁ bᵢ) = ⋁ (a ∧ bᵢ)");
        }
    }
}
