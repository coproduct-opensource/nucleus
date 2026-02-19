//! Permission bids and grants — the request/response protocol for the market.

use serde::{Deserialize, Serialize};

use crate::dimension::{PermissionDimension, TrustTier};

/// A skill's permission bid.
///
/// Submitted with each tool-proxy request via the `X-Nucleus-Permission-Bid`
/// header. The market evaluates the bid against current λ prices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionBid {
    /// Identifier of the requesting skill/plugin.
    pub skill_id: String,
    /// Permission dimensions being requested.
    pub requested: Vec<PermissionDimension>,
    /// Declared value of the operation (higher = more willing to pay).
    ///
    /// This is an abstract unit — the orchestrator calibrates what "1.0"
    /// means in terms of real cost (e.g. USD, tokens, compute-seconds).
    pub value_estimate: f64,
    /// Trust tier from publisher verification.
    pub trust_tier: TrustTier,
}

/// Grant decision with pricing details.
///
/// Returned by `PermissionMarket::evaluate_bid()`. The caller receives
/// both granted and denied dimensions with their prices, enabling
/// the skill to adapt (e.g. retry with higher value, or skip the operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrant {
    /// Dimensions that were granted (value >= price).
    pub granted: Vec<PermissionDimension>,
    /// Dimensions that were denied, with the price that was too high.
    pub denied: Vec<DeniedDimension>,
    /// Total cost charged across all granted dimensions.
    pub total_cost: f64,
    /// Optional expiry (unix timestamp) for the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// A denied dimension with the price the bid couldn't meet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedDimension {
    pub dimension: PermissionDimension,
    /// The effective price (λ * discount_factor) that the bid needed to meet.
    pub price: f64,
}

impl PermissionGrant {
    /// Whether all requested dimensions were granted.
    pub fn fully_granted(&self) -> bool {
        self.denied.is_empty()
    }

    /// Whether any dimension was granted.
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
            total_cost: 0.5,
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
                price: 10.0,
            }],
            total_cost: 0.5,
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
                price: 50.0,
            }],
            total_cost: 0.0,
            expires_at: None,
        };
        assert!(!grant.fully_granted());
        assert!(!grant.partially_granted());
    }

    #[test]
    fn bid_roundtrip_json() {
        let bid = PermissionBid {
            skill_id: "nucleus-plugin".into(),
            requested: vec![
                PermissionDimension::Filesystem,
                PermissionDimension::CommandExec,
            ],
            value_estimate: 5.0,
            trust_tier: TrustTier::Verified,
        };
        let json = serde_json::to_string(&bid).unwrap();
        let parsed: PermissionBid = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.skill_id, "nucleus-plugin");
        assert_eq!(parsed.requested.len(), 2);
        assert_eq!(parsed.trust_tier, TrustTier::Verified);
    }

    #[test]
    fn grant_roundtrip_json() {
        let grant = PermissionGrant {
            granted: vec![PermissionDimension::Filesystem],
            denied: vec![DeniedDimension {
                dimension: PermissionDimension::Approval,
                price: 42.0,
            }],
            total_cost: 1.5,
            expires_at: Some(1700000000),
        };
        let json = serde_json::to_string(&grant).unwrap();
        let parsed: PermissionGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.granted.len(), 1);
        assert_eq!(parsed.denied.len(), 1);
        assert!((parsed.total_cost - 1.5).abs() < f64::EPSILON);
        assert_eq!(parsed.expires_at, Some(1700000000));
    }
}
