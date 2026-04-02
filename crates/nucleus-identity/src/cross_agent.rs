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

use sha2::{Digest, Sha256};

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

/// Receipt linking two agents' receipt chains for a cross-agent interaction.
///
/// When Agent A calls Agent B, both agents record a `CrossAgentReceipt` in their
/// respective receipt chains. The receipt captures both SPIFFE IDs, the underlying
/// label exchange, and SHA-256 hashes of the request and response payloads. The
/// `receipt_hash` field is a deterministic hash over all other fields, enabling
/// both chains to independently verify the same interaction.
#[derive(Debug, Clone)]
pub struct CrossAgentReceipt {
    /// SPIFFE ID of the local agent (the one recording this receipt).
    pub local_spiffe_id: String,
    /// SPIFFE ID of the remote agent (the peer in this interaction).
    pub remote_spiffe_id: String,
    /// The IFC label exchange record from the interaction.
    pub exchange: CrossAgentExchange,
    /// SHA-256 hash of the outbound request payload.
    pub request_hash: [u8; 32],
    /// SHA-256 hash of the inbound response payload.
    pub response_hash: [u8; 32],
    /// Deterministic SHA-256 hash of all fields above.
    pub receipt_hash: [u8; 32],
}

impl CrossAgentReceipt {
    /// Create a new receipt from an exchange and raw request/response payloads.
    ///
    /// Hashes the request and response, then computes the deterministic
    /// `receipt_hash` covering all fields.
    pub fn new(
        exchange: CrossAgentExchange,
        local_spiffe_id: &str,
        remote_spiffe_id: &str,
        request: &[u8],
        response: &[u8],
    ) -> Self {
        let request_hash: [u8; 32] = Sha256::digest(request).into();
        let response_hash: [u8; 32] = Sha256::digest(response).into();
        let receipt_hash = Self::compute_hash(
            local_spiffe_id,
            remote_spiffe_id,
            &exchange,
            &request_hash,
            &response_hash,
        );
        Self {
            local_spiffe_id: local_spiffe_id.to_string(),
            remote_spiffe_id: remote_spiffe_id.to_string(),
            exchange,
            request_hash,
            response_hash,
            receipt_hash,
        }
    }

    /// Compute the deterministic receipt hash.
    ///
    /// The hash covers, in order:
    /// 1. `local_spiffe_id` (length-prefixed UTF-8)
    /// 2. `remote_spiffe_id` (length-prefixed UTF-8)
    /// 3. Exchange timestamp (big-endian u64)
    /// 4. Exchange local label (binary encoding)
    /// 5. Exchange remote label (binary encoding)
    /// 6. Exchange joined label (binary encoding)
    /// 7. Exchange remote_spiffe_id (length-prefixed UTF-8)
    /// 8. Request hash (32 bytes)
    /// 9. Response hash (32 bytes)
    fn compute_hash(
        local_id: &str,
        remote_id: &str,
        exchange: &CrossAgentExchange,
        request_hash: &[u8; 32],
        response_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Length-prefixed strings for domain separation
        Self::hash_string(&mut hasher, local_id);
        Self::hash_string(&mut hasher, remote_id);

        // Exchange fields
        hasher.update(exchange.timestamp.to_be_bytes());
        Self::hash_label(&mut hasher, &exchange.local_label);
        Self::hash_label(&mut hasher, &exchange.remote_label);
        Self::hash_label(&mut hasher, &exchange.joined_label);
        Self::hash_string(&mut hasher, &exchange.remote_spiffe_id);

        // Payload hashes
        hasher.update(request_hash);
        hasher.update(response_hash);

        hasher.finalize().into()
    }

    /// Hash a length-prefixed UTF-8 string into the hasher.
    fn hash_string(hasher: &mut Sha256, s: &str) {
        hasher.update((s.len() as u32).to_be_bytes());
        hasher.update(s.as_bytes());
    }

    /// Hash an IFC label in deterministic binary form.
    fn hash_label(hasher: &mut Sha256, label: &IFCLabel) {
        hasher.update([label.confidentiality as u8]);
        hasher.update([label.integrity as u8]);
        hasher.update([label.provenance.bits()]);
        hasher.update(label.freshness.observed_at.to_be_bytes());
        hasher.update(label.freshness.ttl_secs.to_be_bytes());
        hasher.update([label.authority as u8]);
        hasher.update([label.derivation as u8]);
    }

    /// Verify that the `receipt_hash` matches a fresh computation over all fields.
    pub fn verify(&self) -> bool {
        let expected = Self::compute_hash(
            &self.local_spiffe_id,
            &self.remote_spiffe_id,
            &self.exchange,
            &self.request_hash,
            &self.response_hash,
        );
        self.receipt_hash == expected
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

    // ── CrossAgentReceipt tests ──────────────────────────────────────────

    fn make_receipt(request: &[u8], response: &[u8]) -> CrossAgentReceipt {
        let exchange = join_cross_agent(
            &trusted_local(),
            &trusted_remote(),
            "spiffe://example.org/agent/peer",
            1711900200,
        );
        CrossAgentReceipt::new(
            exchange,
            "spiffe://example.org/agent/local",
            "spiffe://example.org/agent/peer",
            request,
            response,
        )
    }

    #[test]
    fn receipt_hash_is_deterministic() {
        let r1 = make_receipt(b"hello", b"world");
        let r2 = make_receipt(b"hello", b"world");
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_hash_changes_with_different_request() {
        let r1 = make_receipt(b"hello", b"world");
        let r2 = make_receipt(b"goodbye", b"world");
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_hash_changes_with_different_response() {
        let r1 = make_receipt(b"hello", b"world");
        let r2 = make_receipt(b"hello", b"changed");
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_hash_changes_with_different_exchange() {
        let exchange_trusted = join_cross_agent(
            &trusted_local(),
            &trusted_remote(),
            "spiffe://example.org/agent/peer",
            1711900200,
        );
        let exchange_adversarial = join_cross_agent(
            &trusted_local(),
            &adversarial_remote(),
            "spiffe://untrusted.org/agent/evil",
            1711900300,
        );

        let r1 = CrossAgentReceipt::new(
            exchange_trusted,
            "spiffe://example.org/agent/local",
            "spiffe://example.org/agent/peer",
            b"req",
            b"resp",
        );
        let r2 = CrossAgentReceipt::new(
            exchange_adversarial,
            "spiffe://example.org/agent/local",
            "spiffe://untrusted.org/agent/evil",
            b"req",
            b"resp",
        );
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_hash_changes_with_different_local_id() {
        let exchange = join_cross_agent(
            &trusted_local(),
            &trusted_remote(),
            "spiffe://example.org/agent/peer",
            1711900200,
        );
        let r1 = CrossAgentReceipt::new(
            exchange.clone(),
            "spiffe://example.org/agent/alice",
            "spiffe://example.org/agent/peer",
            b"req",
            b"resp",
        );
        let r2 = CrossAgentReceipt::new(
            exchange,
            "spiffe://example.org/agent/bob",
            "spiffe://example.org/agent/peer",
            b"req",
            b"resp",
        );
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_verify_succeeds_for_valid_receipt() {
        let r = make_receipt(b"request payload", b"response payload");
        assert!(r.verify(), "freshly constructed receipt must verify");
    }

    #[test]
    fn receipt_verify_fails_when_tampered() {
        let mut r = make_receipt(b"request payload", b"response payload");
        // Flip a bit in the request hash
        r.request_hash[0] ^= 0xFF;
        assert!(!r.verify(), "tampered receipt must not verify");
    }

    #[test]
    fn receipt_stores_correct_payload_hashes() {
        use sha2::{Digest as _, Sha256};
        let req = b"the request";
        let resp = b"the response";
        let r = make_receipt(req, resp);

        let expected_req: [u8; 32] = Sha256::digest(req).into();
        let expected_resp: [u8; 32] = Sha256::digest(resp).into();

        assert_eq!(r.request_hash, expected_req);
        assert_eq!(r.response_hash, expected_resp);
    }

    #[test]
    fn receipt_all_fields_included_in_hash() {
        // Changing timestamp alone must produce a different receipt hash.
        let local = trusted_local();
        let remote = trusted_remote();
        let e1 = join_cross_agent(&local, &remote, "spiffe://example.org/agent/peer", 1000);
        let e2 = join_cross_agent(&local, &remote, "spiffe://example.org/agent/peer", 2000);

        let r1 = CrossAgentReceipt::new(
            e1,
            "spiffe://example.org/agent/local",
            "spiffe://example.org/agent/peer",
            b"req",
            b"resp",
        );
        let r2 = CrossAgentReceipt::new(
            e2,
            "spiffe://example.org/agent/local",
            "spiffe://example.org/agent/peer",
            b"req",
            b"resp",
        );
        assert_ne!(
            r1.receipt_hash, r2.receipt_hash,
            "different timestamps must produce different hashes"
        );
    }
}
