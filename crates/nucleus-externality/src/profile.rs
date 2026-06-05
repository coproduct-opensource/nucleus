//! `ExternalityProfile` — the K-dimensional bundle of signed claims
//! co-attached to a `LineageEdge` (per P4) or a `CallerBundle` (per W1).
//!
//! **Pigouvian P1.** A profile is a `BTreeMap<ResourceDim,
//! SignedExternalityClaim>` — at most one claim per dimension, with
//! the BTreeMap giving deterministic iteration order so the
//! `canonical_externality_bytes` digest is order-stable across hosts
//! / endianness / hashmap salts.
//!
//! ## Digest contract
//!
//! ```text
//! canonical = PROFILE_DOMAIN
//!          || u32_be(n_claims)
//!          || for each (dim, claim) in dim-sorted order:
//!               canonical_claim_bytes(claim)
//! ```
//!
//! The digest commits to BOTH the set of present dimensions AND each
//! claim's contents (each claim's canonical bytes already include
//! `resource.as_canonical_tag()` so a wholesale dim-swap is caught).
//! SHA-256 the digest for a 32-byte commitment usable as a Merkle leaf
//! or as the `content_hash_hex` of the parent edge.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim::{canonical_claim_bytes, SignedExternalityClaim};
use crate::dim::ResourceDim;

/// Domain prefix for the K-dim profile canonical bytes. Bumping
/// invalidates every prior profile digest. v1 contract.
pub const PROFILE_DOMAIN: &[u8] = b"nucleus/externality/profile/v1\0";

/// K-dimensional bundle of signed externality claims.
///
/// At most one claim per `ResourceDim`. The `BTreeMap` backing gives
/// deterministic iteration order for the canonical digest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalityProfile {
    /// `ResourceDim -> SignedExternalityClaim`. Sorted by `ResourceDim`
    /// per the enum's `Ord` impl, which matches `ResourceDim::all()`'s
    /// declaration order.
    pub dimensions: BTreeMap<ResourceDim, SignedExternalityClaim>,
}

impl ExternalityProfile {
    /// An empty profile (no externalities declared). The auction's
    /// Pigouvian re-weighting sees an empty profile as zero tax.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) the claim for a given dimension. Returns
    /// the previous claim if one was present — useful for the
    /// at-most-once invariant the runner enforces upstream.
    pub fn insert(
        &mut self,
        dim: ResourceDim,
        claim: SignedExternalityClaim,
    ) -> Option<SignedExternalityClaim> {
        self.dimensions.insert(dim, claim)
    }

    /// Look up the claim for a dimension, if any.
    pub fn get(&self, dim: ResourceDim) -> Option<&SignedExternalityClaim> {
        self.dimensions.get(&dim)
    }

    /// Number of declared dimensions.
    pub fn len(&self) -> usize {
        self.dimensions.len()
    }

    /// `true` if no dimensions declared.
    pub fn is_empty(&self) -> bool {
        self.dimensions.is_empty()
    }

    /// The profile's overall assurance: the **minimum** rung across its claims —
    /// a bundle is only as trustworthy as its weakest-attested dimension. The
    /// caller supplies `rung_of`, which derives each claim's achieved rung from
    /// its verification outcomes (see [`crate::assess_rung`]); keeping it a
    /// closure lets the verifier plug in TEE / dispute / envelope checks without
    /// this crate depending on them.
    ///
    /// Returns `None` for an empty profile (no claims → no assurance to report).
    pub fn min_assurance_rung(
        &self,
        rung_of: impl Fn(&crate::dim::ResourceDim, &SignedExternalityClaim) -> crate::AssuranceRung,
    ) -> Option<crate::AssuranceRung> {
        self.dimensions
            .iter()
            .map(|(dim, claim)| rung_of(dim, claim))
            .min()
    }
}

/// Canonical bytes for the whole profile, used as the digest input
/// for either an edge's `content_hash_hex` or a Merkle leaf.
///
/// Format:
/// ```text
/// PROFILE_DOMAIN
/// || u32_be(n_claims)
/// || for each (dim, claim) in dim-sorted order:
///       canonical_claim_bytes(claim)
/// ```
pub fn canonical_externality_bytes(p: &ExternalityProfile) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(PROFILE_DOMAIN);
    let n = p.dimensions.len() as u32;
    out.extend_from_slice(&n.to_be_bytes());
    // BTreeMap's iter is in `Ord` order, which is deterministic.
    for (_dim, claim) in p.dimensions.iter() {
        out.extend_from_slice(&canonical_claim_bytes(claim));
    }
    out
}

/// 32-byte SHA-256 commitment over the canonical bytes. Suitable for
/// pinning into an edge's `content_hash_hex` or for use as a Merkle
/// leaf when the externality cube (Q1-Q4) merklizes its slices.
pub fn externality_digest(p: &ExternalityProfile) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical_externality_bytes(p));
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::sign_claim;
    use ed25519_dalek::SigningKey;

    fn oracle() -> SigningKey {
        SigningKey::from_bytes(&[33u8; 32])
    }

    fn mk_claim(dim: ResourceDim, units: u64) -> SignedExternalityClaim {
        sign_claim(
            &oracle(),
            SignedExternalityClaim {
                resource: dim,
                units_micro: units,
                ts_unix_micros: 1_700_000_000_000_000,
                not_after_unix_micros: 1_700_000_000_000_000 + 3_600_000_000,
                subject_identity: "spiffe://nucleus.io/ns/agents/sa/a1".into(),
                kid: "oracle-1".into(),
                sig_b64: String::new(),
            },
        )
    }

    #[test]
    fn empty_profile_digest_is_stable() {
        let p = ExternalityProfile::new();
        let d1 = externality_digest(&p);
        let d2 = externality_digest(&p);
        assert_eq!(d1, d2);
        // The empty profile still has the v1 domain prefix; its
        // digest is the SHA-256 of "PROFILE_DOMAIN || u32_be(0)".
        let mut h = Sha256::new();
        h.update(PROFILE_DOMAIN);
        h.update((0u32).to_be_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(d1, expected);
    }

    #[test]
    fn insertion_order_independent_digest() {
        // The whole point of using BTreeMap. Build two profiles with
        // the same claims inserted in different orders; their
        // digests must match.
        let c_gpu = mk_claim(ResourceDim::GpuSeconds, 1_000_000);
        let c_co2 = mk_claim(ResourceDim::GridCarbonGramsCo2, 500_000);
        let c_verif = mk_claim(ResourceDim::PeerVerifierMillis, 2_500_000);

        let mut p1 = ExternalityProfile::new();
        p1.insert(ResourceDim::GpuSeconds, c_gpu.clone());
        p1.insert(ResourceDim::GridCarbonGramsCo2, c_co2.clone());
        p1.insert(ResourceDim::PeerVerifierMillis, c_verif.clone());

        let mut p2 = ExternalityProfile::new();
        p2.insert(ResourceDim::PeerVerifierMillis, c_verif);
        p2.insert(ResourceDim::GpuSeconds, c_gpu);
        p2.insert(ResourceDim::GridCarbonGramsCo2, c_co2);

        assert_eq!(externality_digest(&p1), externality_digest(&p2));
    }

    #[test]
    fn distinct_units_distinct_digests() {
        let mut p1 = ExternalityProfile::new();
        p1.insert(
            ResourceDim::GpuSeconds,
            mk_claim(ResourceDim::GpuSeconds, 1_000_000),
        );
        let mut p2 = ExternalityProfile::new();
        p2.insert(
            ResourceDim::GpuSeconds,
            mk_claim(ResourceDim::GpuSeconds, 2_000_000),
        );
        assert_ne!(externality_digest(&p1), externality_digest(&p2));
    }

    #[test]
    fn missing_dim_changes_digest() {
        let mut p1 = ExternalityProfile::new();
        p1.insert(
            ResourceDim::GpuSeconds,
            mk_claim(ResourceDim::GpuSeconds, 1_000_000),
        );
        let mut p2 = p1.clone();
        p2.insert(
            ResourceDim::GridCarbonGramsCo2,
            mk_claim(ResourceDim::GridCarbonGramsCo2, 500_000),
        );
        assert_ne!(externality_digest(&p1), externality_digest(&p2));
    }

    #[test]
    fn insert_returns_previous_claim() {
        let mut p = ExternalityProfile::new();
        let original = mk_claim(ResourceDim::GpuSeconds, 1_000_000);
        assert!(p
            .insert(ResourceDim::GpuSeconds, original.clone())
            .is_none());
        let replacement = mk_claim(ResourceDim::GpuSeconds, 2_000_000);
        let prev = p.insert(ResourceDim::GpuSeconds, replacement);
        assert_eq!(prev, Some(original));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn round_trips_json() {
        let mut p = ExternalityProfile::new();
        p.insert(
            ResourceDim::GpuSeconds,
            mk_claim(ResourceDim::GpuSeconds, 1_000_000),
        );
        p.insert(
            ResourceDim::FxVolatilityDelta,
            mk_claim(ResourceDim::FxVolatilityDelta, 250),
        );
        let json = serde_json::to_string(&p).unwrap();
        let back: ExternalityProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert_eq!(externality_digest(&p), externality_digest(&back));
    }

    #[test]
    fn canonical_bytes_include_domain_prefix() {
        let p = ExternalityProfile::new();
        let bytes = canonical_externality_bytes(&p);
        assert!(
            bytes.starts_with(PROFILE_DOMAIN),
            "canonical bytes must start with PROFILE_DOMAIN"
        );
    }

    #[test]
    fn domain_prefix_is_versioned() {
        assert_eq!(PROFILE_DOMAIN, b"nucleus/externality/profile/v1\0");
    }

    #[test]
    fn min_assurance_rung_is_the_weakest_link() {
        use crate::AssuranceRung;
        let mut p = ExternalityProfile::new();
        p.insert(
            ResourceDim::GpuSeconds,
            mk_claim(ResourceDim::GpuSeconds, 1_000_000),
        );
        p.insert(
            ResourceDim::GridCarbonGramsCo2,
            mk_claim(ResourceDim::GridCarbonGramsCo2, 500_000),
        );

        // Carbon is the strongly-attested one (R4), GPU is only signed (R1):
        // the profile's overall rung is the MINIMUM = R1.
        let rung = p
            .min_assurance_rung(|dim, _claim| match dim {
                ResourceDim::GridCarbonGramsCo2 => AssuranceRung::ZkUpperEnvelope,
                _ => AssuranceRung::OracleSigned,
            })
            .unwrap();
        assert_eq!(rung, AssuranceRung::OracleSigned, "weakest link wins");

        // When every claim is strongly attested, the floor rises.
        let all_strong = p
            .min_assurance_rung(|_dim, _claim| AssuranceRung::ZkUpperEnvelope)
            .unwrap();
        assert_eq!(all_strong, AssuranceRung::ZkUpperEnvelope);
    }

    #[test]
    fn min_assurance_rung_none_for_empty_profile() {
        let p = ExternalityProfile::new();
        assert!(p
            .min_assurance_rung(|_, _| crate::AssuranceRung::ZkUpperEnvelope)
            .is_none());
    }
}
