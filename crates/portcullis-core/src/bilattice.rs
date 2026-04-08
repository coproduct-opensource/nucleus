//! Belnap bilattice for policy decisions (#1150, #1152-#1156).
//!
//! A four-valued logic with two orderings:
//! - **Truth**: is the operation permitted? (Deny < Unknown < Allow)
//! - **Information**: how much do we know? (Unknown < {Allow,Deny} < Conflict)
//!
//! Five operations on this structure are **functionally complete** — any policy
//! composition is expressible (Bruni et al., ACM TISSEC).
//!
//! ## DX Entry Point
//!
//! You don't need to know it's a "Belnap bilattice." Just use 4 values:
//! - `Allow` — yes
//! - `Deny` — no
//! - `Unknown` — not enough info (= RequiresApproval in nucleus)
//! - `Conflict` — two sources disagree (= Quarantined in nucleus)

/// A four-valued policy verdict forming a Belnap bilattice.
///
/// Two independent orderings:
/// ```text
/// Truth:       Deny < Unknown < Allow
/// Information: Unknown < {Allow, Deny} < Conflict
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Operation is permitted.
    Allow,
    /// Operation is denied.
    Deny,
    /// Not enough information to decide — needs human input.
    Unknown,
    /// Contradictory signals — two sources disagree.
    Conflict,
}

impl Verdict {
    // ── Truth-axis operations ───────────────────────────────────────

    /// Truth-meet: most restrictive on the truth axis (AND).
    ///
    /// | ∧_t    | Allow   | Deny    | Unknown | Conflict |
    /// |--------|---------|---------|---------|----------|
    /// | Allow  | Allow   | Deny    | Unknown | Conflict |
    /// | Deny   | Deny    | Deny    | Deny    | Deny     |
    /// | Unknown| Unknown | Deny    | Unknown | Deny     |
    /// | Conflict| Conflict| Deny   | Deny    | Conflict |
    pub fn truth_meet(self, other: Self) -> Self {
        use Verdict::*;
        match (self, other) {
            (Deny, _) | (_, Deny) => Deny,
            (Unknown, Allow) | (Allow, Unknown) => Unknown,
            (Unknown, Unknown) => Unknown,
            (Unknown, Conflict) | (Conflict, Unknown) => Deny,
            (Conflict, Conflict) => Conflict,
            (Conflict, Allow) | (Allow, Conflict) => Conflict,
            (Allow, Allow) => Allow,
        }
    }

    /// Truth-join: most permissive on the truth axis (OR).
    ///
    /// | ∨_t    | Allow   | Deny    | Unknown | Conflict |
    /// |--------|---------|---------|---------|----------|
    /// | Allow  | Allow   | Allow   | Allow   | Allow    |
    /// | Deny   | Allow   | Deny    | Unknown | Conflict |
    /// | Unknown| Allow   | Unknown | Unknown | Allow    |
    /// | Conflict| Allow  | Conflict| Allow   | Conflict |
    pub fn truth_join(self, other: Self) -> Self {
        use Verdict::*;
        match (self, other) {
            (Allow, _) | (_, Allow) => Allow,
            (Unknown, Deny) | (Deny, Unknown) => Unknown,
            (Unknown, Unknown) => Unknown,
            (Unknown, Conflict) | (Conflict, Unknown) => Allow,
            (Conflict, Conflict) => Conflict,
            (Conflict, Deny) | (Deny, Conflict) => Conflict,
            (Deny, Deny) => Deny,
        }
    }

    /// Negate: flip truth axis (Allow <-> Deny), preserve info axis.
    pub fn negate(self) -> Self {
        use Verdict::*;
        match self {
            Allow => Deny,
            Deny => Allow,
            Unknown => Unknown,
            Conflict => Conflict,
        }
    }

    // ── Information-axis operations ─────────────────────────────────

    /// Information-meet: least informative (consensus minimum).
    ///
    /// | ∧_k      | Allow   | Deny    | Unknown | Conflict |
    /// |----------|---------|---------|---------|----------|
    /// | Allow    | Allow   | Unknown | Unknown | Allow    |
    /// | Deny     | Unknown | Deny    | Unknown | Deny     |
    /// | Unknown  | Unknown | Unknown | Unknown | Unknown  |
    /// | Conflict | Allow   | Deny    | Unknown | Conflict |
    pub fn info_meet(self, other: Self) -> Self {
        use Verdict::*;
        match (self, other) {
            (Unknown, _) | (_, Unknown) => Unknown,
            (Allow, Allow) => Allow,
            (Deny, Deny) => Deny,
            (Conflict, Conflict) => Conflict,
            (Conflict, x) | (x, Conflict) => x,
            (Allow, Deny) | (Deny, Allow) => Unknown,
        }
    }

    /// Information-join: most informative (can produce Conflict).
    ///
    /// | ∨_k      | Allow   | Deny    | Unknown | Conflict |
    /// |----------|---------|---------|---------|----------|
    /// | Allow    | Allow   | Conflict| Allow   | Conflict |
    /// | Deny     | Conflict| Deny    | Deny    | Conflict |
    /// | Unknown  | Allow   | Deny    | Unknown | Conflict |
    /// | Conflict | Conflict| Conflict| Conflict| Conflict |
    pub fn info_join(self, other: Self) -> Self {
        use Verdict::*;
        match (self, other) {
            (Conflict, _) | (_, Conflict) => Conflict,
            (Allow, Allow) => Allow,
            (Deny, Deny) => Deny,
            (Unknown, Unknown) => Unknown,
            (Unknown, x) | (x, Unknown) => x,
            (Allow, Deny) | (Deny, Allow) => Conflict,
        }
    }

    // ── Convenience ────────────────────────────────────────────────

    /// Whether this verdict allows the operation.
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this verdict denies the operation.
    pub fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }

    /// Whether this verdict represents insufficient information.
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Whether this verdict represents contradictory signals.
    pub fn is_conflict(self) -> bool {
        matches!(self, Self::Conflict)
    }

    /// Whether this verdict is decided (Allow or Deny, not Unknown/Conflict).
    pub fn is_decided(self) -> bool {
        matches!(self, Self::Allow | Self::Deny)
    }

    /// Truth ordering value (for comparison): Deny=0, Unknown=1, Allow=2, Conflict=1.
    pub fn truth_rank(self) -> u8 {
        match self {
            Self::Deny => 0,
            Self::Unknown | Self::Conflict => 1,
            Self::Allow => 2,
        }
    }

    /// Information ordering value: Unknown=0, Allow/Deny=1, Conflict=2.
    pub fn info_rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Allow | Self::Deny => 1,
            Self::Conflict => 2,
        }
    }
}

// ── Lattice implementation for Verdict ─────────────────────────────────
//
// Uses the TRUTH axis for meet/join/leq, since the truth ordering
// (Deny < Unknown < Allow) is the security-relevant one:
// - meet = most restrictive (AND)
// - join = most permissive (OR)
// - leq = "at most as permissive"

impl crate::category::Lattice for Verdict {
    fn meet(&self, other: &Self) -> Self {
        self.truth_meet(*other)
    }
    fn join(&self, other: &Self) -> Self {
        self.truth_join(*other)
    }
    fn leq(&self, other: &Self) -> bool {
        // a ≤ b iff a ∧ b = a (standard lattice definition).
        // Cannot use truth_rank because Unknown and Conflict are
        // incomparable on the truth axis.
        self.truth_meet(*other) == *self
    }
}

impl crate::category::BoundedLattice for Verdict {
    fn top() -> Self {
        Verdict::Allow
    }
    fn bottom() -> Self {
        Verdict::Deny
    }
}

impl core::fmt::Display for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Deny => write!(f, "DENY"),
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Conflict => write!(f, "CONFLICT"),
        }
    }
}

impl Verdict {
    /// Convert a combinator [`CheckResult`] to a `Verdict` **lossily**.
    ///
    /// # Security warning
    ///
    /// `CheckResult::RequiresApproval` and `CheckResult::Abstain` both map to
    /// `Verdict::Unknown`. This is **intentionally lossy**: the bilattice has
    /// no variant that encodes "human approval required," so the obligation is
    /// dropped. Once flattened to `Unknown`, `truth_join(Unknown, Allow) = Allow`
    /// — a downstream Allow from any source silently overrides the approval gate.
    ///
    /// **Do not use this method** when `RequiresApproval` must be enforced. Use
    /// the combinator layer directly and check [`CheckResult::is_allow`] /
    /// [`CheckResult::is_deny`] before invoking bilattice operations (#1204).
    ///
    /// This method is provided for cases where the caller has already handled
    /// the `RequiresApproval` branch and only needs a `Verdict` for subsequent
    /// information-lattice aggregation.
    #[deprecated(
        since = "1.1.0",
        note = "lossy: RequiresApproval maps to Unknown, enabling silent approval bypass \
                via truth_join(Unknown, Allow) = Allow. Use try_from_check_result() instead (#1204)."
    )]
    pub fn from_check_result_lossy(cr: super::combinators::CheckResult) -> Self {
        match cr {
            super::combinators::CheckResult::Allow => Verdict::Allow,
            super::combinators::CheckResult::Deny(_) => Verdict::Deny,
            super::combinators::CheckResult::RequiresApproval(_) => Verdict::Unknown,
            super::combinators::CheckResult::Abstain => Verdict::Unknown,
        }
    }

    /// Convert a [`CheckResult`] to a `Verdict`, refusing to erase
    /// `RequiresApproval` (#1204).
    ///
    /// Returns `Err(reason)` when the check result is `RequiresApproval`,
    /// forcing the caller to handle the approval obligation explicitly
    /// before entering the bilattice. `Abstain` maps to `Unknown` (safe:
    /// no obligation carried).
    ///
    /// This is the **safe replacement** for [`from_check_result_lossy`].
    pub fn try_from_check_result(cr: super::combinators::CheckResult) -> Result<Self, String> {
        match cr {
            super::combinators::CheckResult::Allow => Ok(Verdict::Allow),
            super::combinators::CheckResult::Deny(_) => Ok(Verdict::Deny),
            super::combinators::CheckResult::Abstain => Ok(Verdict::Unknown),
            super::combinators::CheckResult::RequiresApproval(reason) => Err(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Verdict::*;

    // ── Truth-meet (AND) ───────────────────────────────────────────

    #[test]
    fn truth_meet_deny_absorbs() {
        assert_eq!(Allow.truth_meet(Deny), Deny);
        assert_eq!(Deny.truth_meet(Allow), Deny);
        assert_eq!(Unknown.truth_meet(Deny), Deny);
        assert_eq!(Deny.truth_meet(Unknown), Deny);
    }

    #[test]
    fn truth_meet_identity() {
        for v in [Allow, Deny, Unknown, Conflict] {
            assert_eq!(v.truth_meet(v), v, "idempotent: {v}.truth_meet({v})");
        }
    }

    #[test]
    fn truth_meet_commutative() {
        let vals = [Allow, Deny, Unknown, Conflict];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(a.truth_meet(b), b.truth_meet(a), "commutative: {a} ∧ {b}");
            }
        }
    }

    // ── Truth-join (OR) ────────────────────────────────────────────

    #[test]
    fn truth_join_allow_absorbs() {
        assert_eq!(Allow.truth_join(Deny), Allow);
        assert_eq!(Deny.truth_join(Allow), Allow);
        assert_eq!(Unknown.truth_join(Allow), Allow);
    }

    #[test]
    fn truth_join_identity() {
        for v in [Allow, Deny, Unknown, Conflict] {
            assert_eq!(v.truth_join(v), v);
        }
    }

    #[test]
    fn truth_join_commutative() {
        let vals = [Allow, Deny, Unknown, Conflict];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(a.truth_join(b), b.truth_join(a), "commutative: {a} ∨ {b}");
            }
        }
    }

    // ── Negate ─────────────────────────────────────────────────────

    #[test]
    fn negate_flips_truth() {
        assert_eq!(Allow.negate(), Deny);
        assert_eq!(Deny.negate(), Allow);
    }

    #[test]
    fn negate_preserves_info() {
        assert_eq!(Unknown.negate(), Unknown);
        assert_eq!(Conflict.negate(), Conflict);
    }

    #[test]
    fn double_negate_identity() {
        for v in [Allow, Deny, Unknown, Conflict] {
            assert_eq!(v.negate().negate(), v);
        }
    }

    // ── Information-meet ───────────────────────────────────────────

    #[test]
    fn info_meet_unknown_absorbs() {
        for v in [Allow, Deny, Unknown, Conflict] {
            assert_eq!(Unknown.info_meet(v), Unknown);
            assert_eq!(v.info_meet(Unknown), Unknown);
        }
    }

    #[test]
    fn info_meet_commutative() {
        let vals = [Allow, Deny, Unknown, Conflict];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(a.info_meet(b), b.info_meet(a), "commutative: {a} ∧_k {b}");
            }
        }
    }

    // ── Information-join ───────────────────────────────────────────

    #[test]
    fn info_join_conflict_absorbs() {
        for v in [Allow, Deny, Unknown, Conflict] {
            assert_eq!(Conflict.info_join(v), Conflict);
            assert_eq!(v.info_join(Conflict), Conflict);
        }
    }

    #[test]
    fn info_join_detects_contradiction() {
        assert_eq!(Allow.info_join(Deny), Conflict);
        assert_eq!(Deny.info_join(Allow), Conflict);
    }

    #[test]
    fn info_join_commutative() {
        let vals = [Allow, Deny, Unknown, Conflict];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(a.info_join(b), b.info_join(a), "commutative: {a} ∨_k {b}");
            }
        }
    }

    // ── De Morgan duality ──────────────────────────────────────────

    #[test]
    fn de_morgan_truth() {
        let vals = [Allow, Deny, Unknown, Conflict];
        for &a in &vals {
            for &b in &vals {
                assert_eq!(
                    a.truth_meet(b).negate(),
                    a.negate().truth_join(b.negate()),
                    "De Morgan: ¬(a∧b) = ¬a∨¬b for {a},{b}"
                );
            }
        }
    }

    // ── Cross-axis interaction ─────────────────────────────────────

    #[test]
    fn truth_meet_is_restrictive_join_is_permissive() {
        // truth_meet(Allow, Deny) should be more restrictive than either alone
        assert!(Allow.truth_meet(Deny).truth_rank() <= Allow.truth_rank());
        assert!(Allow.truth_meet(Deny).truth_rank() <= Deny.truth_rank());
        // truth_join(Allow, Deny) should be more permissive
        assert!(Allow.truth_join(Deny).truth_rank() >= Allow.truth_rank());
    }

    #[test]
    fn info_join_never_loses_information() {
        let vals = [Allow, Deny, Unknown, Conflict];
        for &a in &vals {
            for &b in &vals {
                assert!(
                    a.info_join(b).info_rank() >= a.info_rank(),
                    "info_join should not lose info: {a} ∨_k {b}"
                );
            }
        }
    }

    // ── Conversion ─────────────────────────────────────────────────

    #[test]
    #[allow(deprecated)]
    fn from_check_result_lossy_basic() {
        use super::super::combinators::CheckResult;
        assert_eq!(Verdict::from_check_result_lossy(CheckResult::Allow), Allow);
        assert_eq!(
            Verdict::from_check_result_lossy(CheckResult::Deny("x".into())),
            Deny
        );
        assert_eq!(
            Verdict::from_check_result_lossy(CheckResult::RequiresApproval("x".into())),
            Unknown
        );
        assert_eq!(
            Verdict::from_check_result_lossy(CheckResult::Abstain),
            Unknown
        );
    }

    #[test]
    #[allow(deprecated)]
    fn requires_approval_is_overrideable_by_truth_join_documenting_the_lossy_gap() {
        use super::super::combinators::CheckResult;
        let approval_as_verdict =
            Verdict::from_check_result_lossy(CheckResult::RequiresApproval("review".into()));
        assert_eq!(approval_as_verdict, Unknown);
        assert_eq!(approval_as_verdict.truth_join(Allow), Allow);
    }

    // ── try_from_check_result (#1204) ───────────────────────────────

    #[test]
    fn try_from_check_result_allow_ok() {
        use super::super::combinators::CheckResult;
        assert_eq!(
            Verdict::try_from_check_result(CheckResult::Allow),
            Ok(Allow)
        );
    }

    #[test]
    fn try_from_check_result_deny_ok() {
        use super::super::combinators::CheckResult;
        assert_eq!(
            Verdict::try_from_check_result(CheckResult::Deny("x".into())),
            Ok(Deny)
        );
    }

    #[test]
    fn try_from_check_result_abstain_ok() {
        use super::super::combinators::CheckResult;
        assert_eq!(
            Verdict::try_from_check_result(CheckResult::Abstain),
            Ok(Unknown)
        );
    }

    #[test]
    fn try_from_check_result_requires_approval_is_err() {
        use super::super::combinators::CheckResult;
        let result = Verdict::try_from_check_result(CheckResult::RequiresApproval("review".into()));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "review");
    }

    // ── Lattice trait tests ───────────────────────────────────────────

    #[test]
    fn verdict_lattice_laws() {
        use crate::category::verify_bounded_lattice_laws;
        let samples = vec![Allow, Deny, Unknown, Conflict];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "Verdict lattice violations: {v:?}");
    }

    // ── into_verdict tests ────────────────────────────────────────────

    #[test]
    fn into_verdict_preserves_approval_reason() {
        use super::super::combinators::CheckResult;
        let (v, reason) = CheckResult::RequiresApproval("review".into()).into_verdict();
        assert_eq!(v, Unknown);
        assert_eq!(reason, Some("review".into()));
    }

    #[test]
    fn into_verdict_allow_no_reason() {
        use super::super::combinators::CheckResult;
        let (v, reason) = CheckResult::Allow.into_verdict();
        assert_eq!(v, Allow);
        assert!(reason.is_none());
    }
}
