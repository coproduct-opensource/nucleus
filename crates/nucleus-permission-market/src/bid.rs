//! Permission bids and grants — the request/response protocol for the market.
//!
//! # A bid is derived from a certificate, never declared by a request
//!
//! `PermissionBid` used to be a public struct with public fields and
//! `Deserialize`, parsed out of an `X-Nucleus-Permission-Bid` request header.
//! Its `value_estimate` was whatever the caller wrote; its `trust_tier` too. A
//! caller that declared a large value at the `platform` tier won every
//! dimension at a tenth of the price, and it cost nothing to do so (#2526).
//!
//! Now the fields are private and there is exactly one public constructor:
//! [`PermissionBid::from_verified`], which reads the bid out of a
//! [`portcullis::VerifiedPermissions`]. That type is sealed — it cannot be
//! built by struct literal anywhere — so a `PermissionBid` in hand is evidence
//! that someone walked a delegation certificate chain, and the value it carries
//! is the ceiling the *principal* delegated, not a number the agent chose.
//! `Deserialize` is gone on purpose: a bid that could arrive on the wire is a
//! bid the wire could set.
//!
//! The mapping from certificate to bid is the one `cert_bridge::certificate_to_bid`
//! used to hold. It lives here now so that the crate whose type it produces is
//! the crate that decides what the type means (G-1).

use serde::{Deserialize, Serialize};

#[cfg(feature = "certificate")]
use portcullis::VerifiedPermissions;

use crate::dimension::{PermissionDimension, TrustTier};

/// A bid for scarce authority, derived from a verified delegation certificate.
///
/// Fields are private and there is no `Deserialize`: see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionBid {
    skill_id: String,
    requested: Vec<PermissionDimension>,
    /// The principal's spend ceiling for this authority, in micro-USD.
    value_micro: u64,
    trust_tier: TrustTier,
}

impl PermissionBid {
    /// Derive a bid from a verified certificate chain.
    ///
    /// The requested dimensions are the ones the chain's effective capabilities
    /// reach at all (any level above `Never`), plus `Approval` when the chain
    /// carries obligations. The value is the effective budget's `max_cost_usd`
    /// in micro-USD, **truncated toward zero** — a ceiling rounded up would bid
    /// more than the principal delegated. The trust tier is a function of chain
    /// depth ([`TrustTier::from_chain_depth`]): it comes from verification, not
    /// from anything a request could say.
    #[cfg(feature = "certificate")]
    #[must_use]
    pub fn from_verified(verified: &VerifiedPermissions) -> Self {
        use portcullis::CapabilityLevel;
        use rust_decimal::prelude::ToPrimitive;

        let lattice = verified.effective();
        let caps = &lattice.capabilities;
        let above = |l: CapabilityLevel| l > CapabilityLevel::Never;
        let mut requested = Vec::new();

        if above(caps.read_files)
            || above(caps.write_files)
            || above(caps.edit_files)
            || above(caps.glob_search)
            || above(caps.grep_search)
        {
            requested.push(PermissionDimension::Filesystem);
        }
        if above(caps.run_bash) {
            requested.push(PermissionDimension::CommandExec);
        }
        if above(caps.web_search)
            || above(caps.web_fetch)
            || above(caps.git_push)
            || above(caps.create_pr)
        {
            requested.push(PermissionDimension::NetworkEgress);
        }
        if !lattice.obligations.is_empty() {
            requested.push(PermissionDimension::Approval);
        }

        // `checked_mul` and truncation: a budget too large to represent bids
        // ZERO, never a saturated maximum.
        let value_micro = lattice
            .budget
            .max_cost_usd
            .checked_mul(rust_decimal::Decimal::from(1_000_000u32))
            .map(|d| d.trunc())
            .and_then(|d| d.to_u64())
            .unwrap_or(0);

        PermissionBid {
            skill_id: verified.leaf_identity().to_string(),
            requested,
            value_micro,
            trust_tier: TrustTier::from_chain_depth(verified.chain_depth()),
        }
    }

    /// Fixture constructor. `cfg(test)` on purpose: a public one would make
    /// every guarantee in this module a comment.
    #[cfg(test)]
    pub(crate) fn for_test(
        skill_id: &str,
        requested: Vec<PermissionDimension>,
        value_micro: u64,
        trust_tier: TrustTier,
    ) -> Self {
        PermissionBid {
            skill_id: skill_id.to_string(),
            requested,
            value_micro,
            trust_tier,
        }
    }

    /// The bidding identity — the certificate chain's leaf.
    #[must_use]
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    /// The dimensions bid for.
    #[must_use]
    pub fn requested(&self) -> &[PermissionDimension] {
        &self.requested
    }

    /// The principal's ceiling, micro-USD.
    #[must_use]
    pub fn value_micro(&self) -> u64 {
        self.value_micro
    }

    /// The tier verification assigned.
    #[must_use]
    pub fn trust_tier(&self) -> TrustTier {
        self.trust_tier
    }
}

/// Grant decision with pricing details.
///
/// Returned by `PermissionMarket::evaluate_bid()`. The caller receives both
/// granted and denied dimensions with their prices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrant {
    /// Dimensions that were granted (value ≥ price).
    pub granted: Vec<PermissionDimension>,
    /// Dimensions that were denied, with the price that was too high.
    pub denied: Vec<DeniedDimension>,
    /// Total price across all granted dimensions, micro-USD.
    pub total_cost_micro: u64,
    /// Optional expiry (unix timestamp) for the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// A denied dimension with the price the bid could not meet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeniedDimension {
    /// Which dimension.
    pub dimension: PermissionDimension,
    /// The effective price (λ × discount), micro-USD, that the bid needed to
    /// meet.
    pub price_micro: u64,
}

impl PermissionGrant {
    /// Whether all requested dimensions were granted.
    #[must_use]
    pub fn fully_granted(&self) -> bool {
        self.denied.is_empty()
    }

    /// Whether any dimension was granted.
    #[must_use]
    pub fn partially_granted(&self) -> bool {
        !self.granted.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_grant() {
        let grant = PermissionGrant {
            granted: vec![PermissionDimension::Filesystem],
            denied: vec![],
            total_cost_micro: 500_000,
            expires_at: None,
        };
        assert!(grant.fully_granted());
        assert!(grant.partially_granted());
    }

    #[test]
    fn partial_grant() {
        let grant = PermissionGrant {
            granted: vec![PermissionDimension::Filesystem],
            denied: vec![DeniedDimension {
                dimension: PermissionDimension::CommandExec,
                price_micro: 10_000_000,
            }],
            total_cost_micro: 500_000,
            expires_at: None,
        };
        assert!(!grant.fully_granted());
        assert!(grant.partially_granted());
    }

    #[test]
    fn full_denial() {
        let grant = PermissionGrant {
            granted: vec![],
            denied: vec![DeniedDimension {
                dimension: PermissionDimension::NetworkEgress,
                price_micro: 50_000_000,
            }],
            total_cost_micro: 0,
            expires_at: None,
        };
        assert!(!grant.fully_granted());
        assert!(!grant.partially_granted());
    }

    /// A bid serialises (for logs) and does NOT deserialise. The second half
    /// is the guarantee, and it is the type's: there is no `Deserialize` impl
    /// to call. This test pins the first half so a future `derive` that adds
    /// the second would have to touch a test named for it.
    #[test]
    fn a_bid_serialises_for_logging_only() {
        let bid = PermissionBid::for_test(
            "spiffe://example.org/agent",
            vec![PermissionDimension::Filesystem],
            5_000_000,
            TrustTier::Verified,
        );
        let json = serde_json::to_string(&bid).unwrap();
        assert!(json.contains("\"value_micro\":5000000"));
        assert_eq!(bid.skill_id(), "spiffe://example.org/agent");
        assert_eq!(bid.value_micro(), 5_000_000);
        assert_eq!(bid.trust_tier(), TrustTier::Verified);
    }

    #[test]
    fn grant_roundtrip_json() {
        let grant = PermissionGrant {
            granted: vec![PermissionDimension::Filesystem],
            denied: vec![DeniedDimension {
                dimension: PermissionDimension::Approval,
                price_micro: 42_000_000,
            }],
            total_cost_micro: 1_500_000,
            expires_at: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&grant).unwrap();
        let parsed: PermissionGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, grant);
    }
}
