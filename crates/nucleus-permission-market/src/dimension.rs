//! Permission dimensions — each axis in the constraint space has its own λ.

use serde::{Deserialize, Serialize};

/// A permission dimension represents a distinct capability axis.
///
/// Each dimension has an independent Lagrange multiplier (price).
/// When utilization of a dimension is low, its λ ≈ 0 (cheap).
/// As utilization approaches the limit, λ grows exponentially.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDimension {
    /// File read/write/glob/grep operations.
    Filesystem,
    /// Command execution (shell, process spawning).
    CommandExec,
    /// Outbound network requests (web_fetch, web_search).
    NetworkEgress,
    /// Approval meta-permission (approve other operations).
    Approval,
}

impl PermissionDimension {
    /// All known dimensions, in canonical order.
    pub const ALL: &[PermissionDimension] = &[
        PermissionDimension::Filesystem,
        PermissionDimension::CommandExec,
        PermissionDimension::NetworkEgress,
        PermissionDimension::Approval,
    ];

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::CommandExec => "command_exec",
            Self::NetworkEgress => "network_egress",
            Self::Approval => "approval",
        }
    }

    /// Map a tool-proxy endpoint path to its primary dimension.
    pub fn from_endpoint(path: &str) -> Option<Self> {
        match path {
            "/v1/read" | "/v1/write" | "/v1/glob" | "/v1/grep" => Some(Self::Filesystem),
            "/v1/run" => Some(Self::CommandExec),
            "/v1/web_fetch" | "/v1/web_search" => Some(Self::NetworkEgress),
            "/v1/approve" => Some(Self::Approval),
            _ => None,
        }
    }
}

/// Trust tier for a skill/plugin publisher.
///
/// Higher trust tiers receive a discount on permission prices,
/// reflecting lower risk from verified publishers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Unverified or unknown publisher.
    Unverified,
    /// Community-verified (e.g. published to a registry with basic checks).
    Community,
    /// Organization-verified (e.g. signed by a known org key).
    Verified,
    /// Platform-level trust (e.g. built-in tools, first-party plugins).
    Platform,
}

impl TrustTier {
    /// Price discount factor for this trust tier.
    ///
    /// Lower values mean cheaper permissions:
    /// - `Unverified`: 1.0x (full price)
    /// - `Community`: 0.8x
    /// - `Verified`: 0.5x
    /// - `Platform`: 0.1x (nearly free)
    pub fn discount_factor(&self) -> f64 {
        match self {
            Self::Unverified => 1.0,
            Self::Community => 0.8,
            Self::Verified => 0.5,
            Self::Platform => 0.1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_dimensions_listed() {
        assert_eq!(PermissionDimension::ALL.len(), 4);
    }

    #[test]
    fn endpoint_mapping() {
        assert_eq!(
            PermissionDimension::from_endpoint("/v1/read"),
            Some(PermissionDimension::Filesystem)
        );
        assert_eq!(
            PermissionDimension::from_endpoint("/v1/run"),
            Some(PermissionDimension::CommandExec)
        );
        assert_eq!(
            PermissionDimension::from_endpoint("/v1/web_fetch"),
            Some(PermissionDimension::NetworkEgress)
        );
        assert_eq!(
            PermissionDimension::from_endpoint("/v1/approve"),
            Some(PermissionDimension::Approval)
        );
        assert_eq!(PermissionDimension::from_endpoint("/v1/health"), None);
    }

    #[test]
    fn trust_discount_ordering() {
        assert!(TrustTier::Platform.discount_factor() < TrustTier::Verified.discount_factor());
        assert!(TrustTier::Verified.discount_factor() < TrustTier::Community.discount_factor());
        assert!(TrustTier::Community.discount_factor() < TrustTier::Unverified.discount_factor());
    }

    #[test]
    fn trust_discount_bounds() {
        for tier in [
            TrustTier::Unverified,
            TrustTier::Community,
            TrustTier::Verified,
            TrustTier::Platform,
        ] {
            let d = tier.discount_factor();
            assert!(
                d > 0.0 && d <= 1.0,
                "discount {d} out of bounds for {tier:?}"
            );
        }
    }
}
