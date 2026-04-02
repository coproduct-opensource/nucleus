//! Cross-agent IFC label join logic.
//!
//! When an agent receives a response from a remote agent (via mTLS), the
//! response data's label must be the join (least upper bound) of the local
//! agent's label and the remote agent's label extracted from its peer
//! certificate's IFC extension.
//!
//! This ensures taint propagation: if the remote agent has `Adversarial`
//! integrity, the joined label inherits `Adversarial` integrity. If the
//! remote has `NoAuthority`, the joined label cannot steer privileged actions.
//!
//! # Proxy wiring (deferred)
//!
//! The actual integration point is in `nucleus-tool-proxy` where the mTLS
//! handshake provides the peer certificate. This module implements the core
//! join logic as a pure library function, independent of transport.

use portcullis_core::{DerivationClass, IFCLabel, IntegLevel};

/// Record of a cross-agent label join, preserving both original labels for audit.
#[derive(Debug, Clone)]
pub struct CrossAgentExchange {
    /// The local agent's label before the exchange.
    pub local_label: IFCLabel,
    /// The remote agent's label, extracted from its peer certificate IFC extension.
    pub remote_label: IFCLabel,
    /// The SPIFFE ID of the remote agent (e.g. `spiffe://example.org/agent/foo`).
    pub remote_spiffe_id: String,
    /// The joined label: `local_label.join(remote_label)`.
    pub joined_label: IFCLabel,
    /// Unix timestamp when the exchange was recorded.
    pub timestamp: u64,
}

/// Compute the cross-agent join and return an audit record.
///
/// The joined label is the lattice join (least upper bound) of the local and
/// remote labels. This is the fundamental IFC taint propagation rule:
///
/// - If the remote has `Adversarial` integrity, the result has `Adversarial` integrity.
/// - If the remote has `NoAuthority`, the result has `NoAuthority`.
/// - Confidentiality is max (most secret wins).
/// - Provenance is the union of both sets.
/// - Freshness takes the oldest timestamp and shortest TTL.
/// - Derivation follows the lattice join (OpaqueExternal absorbs everything).
pub fn join_cross_agent(
    local: &IFCLabel,
    remote: &IFCLabel,
    remote_id: &str,
    timestamp: u64,
) -> CrossAgentExchange {
    let joined_label = (*local).join(*remote);
    CrossAgentExchange {
        local_label: *local,
        remote_label: *remote,
        remote_spiffe_id: remote_id.to_string(),
        joined_label,
        timestamp,
    }
}

impl CrossAgentExchange {
    /// Returns `true` if the response data requires a `ReductionWitness` before
    /// it can enter a verified processing lane.
    ///
    /// Reduction is required when the remote label carries:
    /// - `IntegLevel::Adversarial` — the remote agent is adversarially controlled
    /// - `DerivationClass::OpaqueExternal` — the data origin is opaque/unverifiable
    ///
    /// In both cases, the data cannot be trusted without an explicit reduction
    /// step (human review, deterministic re-derivation, etc.) that produces a
    /// `ReductionWitness` attesting the data has been verified.
    pub fn requires_reduction(&self) -> bool {
        self.remote_label.integrity == IntegLevel::Adversarial
            || self.remote_label.derivation == DerivationClass::OpaqueExternal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::{
        AuthorityLevel, ConfLevel, DerivationClass, Freshness, IntegLevel, ProvenanceSet,
    };

    /// A trusted internal agent label.
    fn trusted_local() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 1711900000,
                ttl_secs: 3600,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// A trusted remote peer (same org, verified).
    fn trusted_remote() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::TOOL,
            freshness: Freshness {
                observed_at: 1711900100,
                ttl_secs: 7200,
            },
            authority: AuthorityLevel::Suggestive,
            derivation: DerivationClass::AIDerived,
        }
    }

    /// An adversarial remote peer (unknown org, no IFC extension → default).
    fn adversarial_remote() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet::EMPTY,
            freshness: Freshness {
                observed_at: 0,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::OpaqueExternal,
        }
    }

    #[test]
    fn join_with_trusted_peer_preserves_trust() {
        let local = trusted_local();
        let remote = trusted_remote();
        let exchange = join_cross_agent(
            &local,
            &remote,
            "spiffe://example.org/agent/peer",
            1711900200,
        );

        // Confidentiality: max(Internal, Internal) = Internal
        assert_eq!(exchange.joined_label.confidentiality, ConfLevel::Internal,);
        // Integrity: min(Trusted, Trusted) = Trusted (both trusted)
        assert_eq!(exchange.joined_label.integrity, IntegLevel::Trusted);
        // Provenance: USER ∪ TOOL
        assert!(exchange
            .joined_label
            .provenance
            .contains(ProvenanceSet::USER));
        assert!(exchange
            .joined_label
            .provenance
            .contains(ProvenanceSet::TOOL));
        // Authority: min(Directive, Suggestive) = Suggestive
        assert_eq!(exchange.joined_label.authority, AuthorityLevel::Suggestive,);
        // Derivation: join(Deterministic, AIDerived) = AIDerived
        assert_eq!(exchange.joined_label.derivation, DerivationClass::AIDerived,);
        // Freshness: oldest observed_at, shortest TTL
        assert_eq!(exchange.joined_label.freshness.observed_at, 1711900000);
        assert_eq!(exchange.joined_label.freshness.ttl_secs, 3600);

        // Trusted peer does not require reduction
        assert!(!exchange.requires_reduction());

        // Audit fields preserved
        assert_eq!(exchange.local_label, local);
        assert_eq!(exchange.remote_label, remote);
        assert_eq!(exchange.remote_spiffe_id, "spiffe://example.org/agent/peer");
        assert_eq!(exchange.timestamp, 1711900200);
    }

    #[test]
    fn join_with_adversarial_peer_taints_result() {
        let local = trusted_local();
        let remote = adversarial_remote();
        let exchange = join_cross_agent(
            &local,
            &remote,
            "spiffe://untrusted.org/agent/evil",
            1711900300,
        );

        // Integrity: min(Trusted, Adversarial) = Adversarial — taint propagates
        assert_eq!(exchange.joined_label.integrity, IntegLevel::Adversarial,);
        // Authority: min(Directive, NoAuthority) = NoAuthority — can't steer
        assert_eq!(exchange.joined_label.authority, AuthorityLevel::NoAuthority,);
        // Derivation: join(Deterministic, OpaqueExternal) = OpaqueExternal
        assert_eq!(
            exchange.joined_label.derivation,
            DerivationClass::OpaqueExternal,
        );
        // Confidentiality: max(Internal, Public) = Internal
        assert_eq!(exchange.joined_label.confidentiality, ConfLevel::Internal,);
        // Provenance: USER ∪ EMPTY = USER
        assert!(exchange
            .joined_label
            .provenance
            .contains(ProvenanceSet::USER));
    }

    #[test]
    fn adversarial_peer_requires_reduction() {
        let local = trusted_local();
        let remote = adversarial_remote();
        let exchange = join_cross_agent(
            &local,
            &remote,
            "spiffe://untrusted.org/agent/evil",
            1711900300,
        );

        assert!(
            exchange.requires_reduction(),
            "adversarial remote must require reduction"
        );
    }

    #[test]
    fn opaque_external_derivation_requires_reduction() {
        let local = trusted_local();
        // Remote with Trusted integrity but OpaqueExternal derivation
        let remote = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: 1711900100,
                ttl_secs: 600,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::OpaqueExternal,
        };
        let exchange = join_cross_agent(
            &local,
            &remote,
            "spiffe://partner.org/agent/scraper",
            1711900400,
        );

        assert!(
            exchange.requires_reduction(),
            "OpaqueExternal derivation must require reduction even with Trusted integrity"
        );
        // Integrity is still Trusted (both are Trusted)
        assert_eq!(exchange.joined_label.integrity, IntegLevel::Trusted);
    }

    #[test]
    fn untrusted_without_opaque_does_not_require_reduction() {
        let local = trusted_local();
        // Remote with Untrusted integrity (not Adversarial) and AIDerived
        let remote = IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::MODEL,
            freshness: Freshness {
                observed_at: 1711900050,
                ttl_secs: 1800,
            },
            authority: AuthorityLevel::Suggestive,
            derivation: DerivationClass::AIDerived,
        };
        let exchange = join_cross_agent(
            &local,
            &remote,
            "spiffe://example.org/agent/helper",
            1711900500,
        );

        // Untrusted (not Adversarial) + AIDerived (not OpaqueExternal) → no reduction
        assert!(
            !exchange.requires_reduction(),
            "Untrusted + AIDerived should not require reduction"
        );
        // But integrity is still downgraded: min(Trusted, Untrusted) = Untrusted
        assert_eq!(exchange.joined_label.integrity, IntegLevel::Untrusted);
    }
}
