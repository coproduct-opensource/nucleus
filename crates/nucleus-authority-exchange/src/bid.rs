//! What may be bid, and by whom.
//!
//! # The rule this module exists to make structural
//!
//! **An agent may not bid for its own authority.** The value of a bid must be a
//! function of the *principal's* declared task value, carried inside the signed
//! delegation certificate, and the agent must be unable to raise it.
//!
//! This is not a preference. If the bid is model-controlled then injected content
//! can raise its own price and buy capability — the lethal trifecta with a
//! checkout counter. The live posted-price path this crate supersedes has exactly
//! that shape today: `nucleus-tool-proxy`'s `evaluate_permission_bid` parses
//! `value_estimate` **and `trust_tier`** out of a client-supplied
//! `x-nucleus-permission-bid` header with no verification, and `trust_tier`
//! selects a discount down to 0.1×. It is reached only when no request-borne
//! certificate is present, and other gates still apply — but the screen itself is
//! self-scored.
//!
//! So the ceiling is a type, not a check. [`CertifiedCeiling`] has a private
//! field and, outside this crate's own tests, exactly one public constructor:
//! [`CertifiedCeiling::from_verified`], which reads the budget of a
//! [`portcullis::VerifiedPermissions`] — a value that cannot be built by struct
//! literal (it is sealed, #2450) and therefore cannot be forged by a caller who
//! never verified a certificate chain. A bid above its ceiling is a
//! [`BidError::AboveCeiling`], never a clamp: silently lowering a bid would make
//! the mechanism price something the principal did not ask for.

use nucleus_econ_types::{AgentId, MicroUsd};
use nucleus_permission_market::PermissionDimension;

/// A spend ceiling that came from a verified delegation certificate.
///
/// The private field is the whole point: a `CertifiedCeiling` in hand is evidence
/// that someone walked a certificate chain, because there is no other way to get
/// one (C-1 — evidence has a private constructor and is minted by the checker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CertifiedCeiling(MicroUsd);

impl CertifiedCeiling {
    /// The ceiling, in micro-USD.
    #[must_use]
    pub fn get(self) -> MicroUsd {
        self.0
    }

    /// Read the spend ceiling out of a verified delegation certificate.
    ///
    /// # Rounding
    ///
    /// `max_cost_usd` is a `Decimal`; the ceiling is micro-USD. The conversion
    /// **truncates toward zero**, and the direction is load-bearing rather than
    /// incidental: rounding up would let a bid exceed the authority the
    /// certificate actually granted, by up to a micro-dollar, every round. A
    /// ceiling must never be generous.
    ///
    /// A negative or unrepresentable budget yields [`MicroUsd::ZERO`] — a
    /// certificate that grants no spend authorises no bid, which is the
    /// fail-closed reading (B-2: `None` may not mean unrestricted).
    #[cfg(feature = "certificate")]
    #[must_use]
    pub fn from_verified(verified: &portcullis::VerifiedPermissions) -> Self {
        use rust_decimal::prelude::ToPrimitive;

        let usd = verified.effective().budget.max_cost_usd;
        let micros = (usd * rust_decimal::Decimal::from(1_000_000u32)).trunc();
        CertifiedCeiling(MicroUsd::new(micros.to_u64().unwrap_or(0)))
    }

    /// Fixture constructor. Deliberately `cfg(test)`: if this were public the
    /// type would carry no evidence at all, and every guarantee in this module
    /// would reduce to a comment.
    #[cfg(test)]
    pub(crate) fn for_test(micros: u64) -> Self {
        CertifiedCeiling(MicroUsd::new(micros))
    }

    /// An unbounded ceiling, for [`crate::test_support`] only. Gated on the
    /// `test-support` feature, which `default` does not enable: a production
    /// dependency cannot reach it, so the evidence this type carries survives.
    #[cfg(feature = "test-support")]
    pub(crate) fn unbounded_for_testing() -> Self {
        CertifiedCeiling(MicroUsd::MAX)
    }
}

/// Why a bid could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BidError {
    /// The requested value exceeds what the certificate authorises. Refused, not
    /// clamped — see the module docs.
    #[error("bid of {requested} µUSD exceeds the certified ceiling of {ceiling} µUSD")]
    AboveCeiling {
        /// What was asked for.
        requested: u64,
        /// What the certificate allows.
        ceiling: u64,
    },
    /// A zero bid is not a bid. It cannot win, it cannot set a price, and it
    /// makes a round look contended when it is not — which is exactly the
    /// vacuity [`crate::Round`] refuses.
    #[error("a zero-value bid cannot be submitted")]
    ZeroValue,
}

/// One agent's bid for one contended authority slot.
///
/// Fields are private and there is no `Default`: a bid that nobody authorised
/// must be unrepresentable rather than merely invalid (B-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBid {
    bidder: AgentId,
    dimension: PermissionDimension,
    value: MicroUsd,
}

impl SignedBid {
    /// Build a bid, refusing anything the certificate does not authorise.
    ///
    /// # Errors
    ///
    /// [`BidError::AboveCeiling`] if `requested` exceeds `ceiling`, and
    /// [`BidError::ZeroValue`] for a zero bid.
    pub fn new(
        bidder: AgentId,
        dimension: PermissionDimension,
        requested: MicroUsd,
        ceiling: CertifiedCeiling,
    ) -> Result<Self, BidError> {
        if requested == MicroUsd::ZERO {
            return Err(BidError::ZeroValue);
        }
        if requested > ceiling.get() {
            return Err(BidError::AboveCeiling {
                requested: requested.get(),
                ceiling: ceiling.get().get(),
            });
        }
        Ok(SignedBid {
            bidder,
            dimension,
            value: requested,
        })
    }

    /// Who bid.
    #[must_use]
    pub fn bidder(&self) -> &AgentId {
        &self.bidder
    }

    /// Which scarce authority was bid for.
    #[must_use]
    pub fn dimension(&self) -> PermissionDimension {
        self.dimension
    }

    /// The bid value, in micro-USD.
    #[must_use]
    pub fn value(&self) -> MicroUsd {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(requested: u64, ceiling: u64) -> Result<SignedBid, BidError> {
        SignedBid::new(
            AgentId::new("spiffe://example/ns/a/sa/b"),
            PermissionDimension::NetworkEgress,
            MicroUsd::new(requested),
            CertifiedCeiling::for_test(ceiling),
        )
    }

    /// The defect this module exists for: a bid above the certified ceiling is a
    /// construction failure, not a clamp.
    #[test]
    fn a_bid_above_the_ceiling_is_refused_not_clamped() {
        let err = bid(10_001, 10_000).expect_err("should refuse");
        assert_eq!(
            err,
            BidError::AboveCeiling {
                requested: 10_001,
                ceiling: 10_000
            }
        );
    }

    #[test]
    fn a_bid_at_the_ceiling_is_allowed() {
        let b = bid(10_000, 10_000).expect("at the ceiling is within it");
        assert_eq!(b.value(), MicroUsd::new(10_000));
    }

    #[test]
    fn a_zero_bid_is_refused() {
        assert_eq!(bid(0, 10_000).expect_err("zero"), BidError::ZeroValue);
    }

    /// A certificate granting no spend authorises no bid.
    #[test]
    fn a_zero_ceiling_admits_nothing() {
        assert!(bid(1, 0).is_err());
    }

    /// The conversion must never round a ceiling upward. Checked here on the
    /// arithmetic, because the `Decimal` path is only compiled with the feature.
    #[cfg(feature = "certificate")]
    #[test]
    fn the_budget_conversion_truncates_rather_than_rounds() {
        use rust_decimal::Decimal;
        use rust_decimal::prelude::ToPrimitive;
        // $0.0000019 is 1.9 µUSD. A ceiling of 2 would authorise more than the
        // certificate granted.
        let usd = Decimal::new(19, 7);
        let micros = (usd * Decimal::from(1_000_000u32)).trunc();
        assert_eq!(micros.to_u64(), Some(1));
    }
}
