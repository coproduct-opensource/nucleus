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
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::CommandExec => "command_exec",
            Self::NetworkEgress => "network_egress",
            Self::Approval => "approval",
        }
    }

    /// Map a tool-proxy endpoint path to its primary dimension.
    #[must_use]
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

/// Trust tier of a bidder, **assigned by certificate verification**.
///
/// Higher tiers pay less. The tier is a function of delegation chain depth
/// ([`TrustTier::from_chain_depth`]) and nothing else: a request cannot
/// declare one (#2526).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// No verified chain. Not reachable from a certificate; kept as the tier
    /// a market with no discount evaluates at.
    Unverified,
    /// Transitive delegate (chain depth ≥ 2).
    Community,
    /// Direct delegate of the root (chain depth 1).
    Verified,
    /// The root authority itself (chain depth 0).
    Platform,
}

impl TrustTier {
    /// The tier a delegation chain of `depth` earns.
    ///
    /// - Depth 0: root authority itself → `Platform`
    /// - Depth 1: direct delegate → `Verified`
    /// - Depth 2+: transitive delegate → `Community`
    ///
    /// `Unverified` is never returned: a chain that verified is, by
    /// construction, not unverified.
    #[must_use]
    pub fn from_chain_depth(depth: usize) -> Self {
        match depth {
            0 => Self::Platform,
            1 => Self::Verified,
            _ => Self::Community,
        }
    }

    /// Price multiplier for this tier, in basis points of the full price.
    ///
    /// - `Unverified`: 10 000 (full price)
    /// - `Community`: 8 000
    /// - `Verified`: 5 000
    /// - `Platform`: 1 000
    #[must_use]
    pub fn discount_bps(&self) -> u32 {
        match self {
            Self::Unverified => 10_000,
            Self::Community => 8_000,
            Self::Verified => 5_000,
            Self::Platform => 1_000,
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
        assert!(TrustTier::Platform.discount_bps() < TrustTier::Verified.discount_bps());
        assert!(TrustTier::Verified.discount_bps() < TrustTier::Community.discount_bps());
        assert!(TrustTier::Community.discount_bps() < TrustTier::Unverified.discount_bps());
    }

    #[test]
    fn trust_discount_bounds() {
        for tier in [
            TrustTier::Unverified,
            TrustTier::Community,
            TrustTier::Verified,
            TrustTier::Platform,
        ] {
            let d = tier.discount_bps();
            assert!(
                d > 0 && d <= 10_000,
                "discount {d} out of bounds for {tier:?}"
            );
        }
    }

    #[test]
    fn chain_depth_trust_mapping() {
        assert_eq!(TrustTier::from_chain_depth(0), TrustTier::Platform);
        assert_eq!(TrustTier::from_chain_depth(1), TrustTier::Verified);
        assert_eq!(TrustTier::from_chain_depth(2), TrustTier::Community);
        assert_eq!(TrustTier::from_chain_depth(5), TrustTier::Community);
        assert_eq!(TrustTier::from_chain_depth(10), TrustTier::Community);
    }

    /// No depth reaches `Unverified`: verification never yields "unverified".
    #[test]
    fn verification_never_yields_unverified() {
        for depth in 0..64 {
            assert_ne!(TrustTier::from_chain_depth(depth), TrustTier::Unverified);
        }
    }
}
