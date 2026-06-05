//! `ResourceDim` — the K dimensions an externality can occupy.
//!
//! Each variant is a *resource* whose consumption imposes a cost on
//! parties not directly involved in the agent's auction. The signed-
//! externality envelope ([`crate::SignedExternalityClaim`]) carries one
//! `(ResourceDim, units_micro)` per dimension; the Pigouvian rate
//! setter assigns a `λ_k` rate to each.
//!
//! ## Why this enum is closed
//!
//! Adding a new dimension is a wire-format change — every verifier
//! must learn the new domain tag. We deliberately keep this enum
//! `#[non_exhaustive]` so callers MUST handle the unknown-variant
//! case (forward-compat), but new variants land via PR + Lean spec
//! bump (so the truthful-VCG proof can re-establish over the new
//! dimension).
//!
//! ## Canonical tags
//!
//! Each variant has a stable byte tag used in
//! [`crate::canonical_externality_bytes`]. Tags are pinned per the
//! `docs/ECON-PRECISION.md` discipline — bumping a tag invalidates
//! every prior signature.

use serde::{Deserialize, Serialize};

/// Domain prefix that every canonical-bytes encoding of a
/// `ResourceDim` is prefixed with. Bumping the version invalidates
/// every prior `SignedExternalityClaim` signature.
pub const RESOURCE_DIM_DOMAIN: &[u8] = b"nucleus/externality/dim/v1\0";

/// A resource whose consumption is an externality on third parties.
///
/// See module docs for the wire / forward-compat contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceDim {
    /// GPU compute time consumed, in micro-seconds (1e-6 sec).
    /// Signed by a TEE-attested compute oracle (Intel TDX /
    /// AMD SEV-SNP / Nitro Enclave).
    GpuSeconds,
    /// Grid carbon intensity × electrical energy, in micro-grams
    /// CO₂-equivalent. Signed by a grid-intensity oracle; bounded
    /// by an upper-envelope zk-SNARK proof (per Verifiable Carbon
    /// Accounting).
    GridCarbonGramsCo2,
    /// Peer-verifier CPU / I/O time imposed on the witness
    /// federation when this call's lineage edges get verified.
    /// Signed by the verifier-federation aggregator.
    /// Units: micro-seconds.
    PeerVerifierMillis,
    /// Bits added to the corpus when this call's artifact is
    /// ingested into the shared verifier-training corpus. Signed by
    /// the corpus-hashing oracle. Units: micro-bits (so 1 bit =
    /// 1_000_000).
    CorpusBitsAdded,
    /// **Negative externality** (= positive spillover): knowledge
    /// produced by this call that other agents can later use.
    /// Signed by the reputation service. Subtracted from the
    /// Pigouvian tax in the re-weighting step. Units: micro-bits.
    KnowledgeSpillover,
    /// FX volatility imposed on subsequent FX-denominated bids
    /// (the D5 oracle reports this back). Signed by the D5 FX
    /// oracle. Units: micro-basis-points.
    FxVolatilityDelta,
    /// Auction-clearing delay imposed on downstream auctions,
    /// computed deterministically from the clearing time + the
    /// gateway window. Units: micro-seconds.
    AuctionDelay,
    /// **Freshwater consumed** by the compute that backs this call —
    /// direct datacenter cooling + the water embedded in the
    /// electricity drawn (thermoelectric withdrawal). Units:
    /// micro-litres (so 1 L = 1_000_000). Signed by the same TEE-
    /// attested compute oracle that reports `GpuSeconds`, multiplied
    /// by a regional water-usage-effectiveness (WUE) factor.
    ///
    /// Priced separately from carbon because water scarcity is
    /// *local* — a gram of CO₂ has the same social cost wherever it
    /// is emitted, but a litre drawn from a stressed basin costs far
    /// more than one from a wet region. The Tier-1 λ is a
    /// scarcity-weighted shadow price (see
    /// `docs/rfcs/initial-pigouvian-structure.md`).
    ///
    /// Appended at the end of the enum (after `AuctionDelay`) so every
    /// pre-existing variant keeps its discriminant — `Ord` order is
    /// unchanged, so prior multi-dimension profile digests / claim
    /// signatures remain valid (Water simply sorts last).
    WaterLitresConsumed,
}

impl ResourceDim {
    /// Stable byte tag used in canonical signing bytes. MUST be
    /// `&'static [u8]` so callers can avoid allocations on the hot
    /// signing path.
    pub fn as_canonical_tag(self) -> &'static [u8] {
        match self {
            ResourceDim::GpuSeconds => b"gpu_s",
            ResourceDim::GridCarbonGramsCo2 => b"co2_g",
            ResourceDim::PeerVerifierMillis => b"verif_ms",
            ResourceDim::CorpusBitsAdded => b"corpus_b",
            ResourceDim::KnowledgeSpillover => b"k_spill",
            ResourceDim::FxVolatilityDelta => b"fx_vol",
            ResourceDim::AuctionDelay => b"auc_del",
            ResourceDim::WaterLitresConsumed => b"water_l",
        }
    }

    /// All variants, in canonical-tag order. Useful for iteration in
    /// rate-setter loops and tests.
    pub fn all() -> &'static [ResourceDim] {
        &[
            ResourceDim::GpuSeconds,
            ResourceDim::GridCarbonGramsCo2,
            ResourceDim::PeerVerifierMillis,
            ResourceDim::CorpusBitsAdded,
            ResourceDim::KnowledgeSpillover,
            ResourceDim::FxVolatilityDelta,
            ResourceDim::AuctionDelay,
            ResourceDim::WaterLitresConsumed,
        ]
    }

    /// `true` if consumption of this resource is a *positive*
    /// externality (a benefit to third parties). The rate-setter
    /// applies these as a subsidy rather than a tax.
    pub fn is_positive_externality(self) -> bool {
        matches!(self, ResourceDim::KnowledgeSpillover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tags_unique() {
        // Tag collisions would let a malicious claim swap dimensions
        // without invalidating the signature.
        let mut seen = std::collections::BTreeSet::new();
        for d in ResourceDim::all() {
            assert!(
                seen.insert(d.as_canonical_tag()),
                "duplicate canonical tag for {d:?}"
            );
        }
        assert_eq!(seen.len(), ResourceDim::all().len());
    }

    #[test]
    fn all_includes_every_variant() {
        // Sanity check that `all()` actually enumerates the enum.
        let count = ResourceDim::all().len();
        assert_eq!(count, 8, "expected 8 dimensions, got {count}");
    }

    #[test]
    fn round_trips_json() {
        let v = ResourceDim::GridCarbonGramsCo2;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"grid_carbon_grams_co2\"");
        let back: ResourceDim = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn knowledge_spillover_is_the_only_positive() {
        for d in ResourceDim::all() {
            let pos = d.is_positive_externality();
            assert_eq!(
                pos,
                matches!(d, ResourceDim::KnowledgeSpillover),
                "{d:?} positive flag wrong"
            );
        }
    }

    #[test]
    fn domain_prefix_is_versioned() {
        // V1 contract — bumping invalidates every prior signature.
        assert_eq!(RESOURCE_DIM_DOMAIN, b"nucleus/externality/dim/v1\0");
    }

    #[test]
    fn canonical_tag_is_stable() {
        // Pin every tag to its v1 byte string. A future PR that
        // wants to rename a tag fails this test and is forced to
        // bump RESOURCE_DIM_DOMAIN.
        assert_eq!(ResourceDim::GpuSeconds.as_canonical_tag(), b"gpu_s");
        assert_eq!(ResourceDim::GridCarbonGramsCo2.as_canonical_tag(), b"co2_g");
        assert_eq!(
            ResourceDim::PeerVerifierMillis.as_canonical_tag(),
            b"verif_ms"
        );
        assert_eq!(ResourceDim::CorpusBitsAdded.as_canonical_tag(), b"corpus_b");
        assert_eq!(
            ResourceDim::KnowledgeSpillover.as_canonical_tag(),
            b"k_spill"
        );
        assert_eq!(ResourceDim::FxVolatilityDelta.as_canonical_tag(), b"fx_vol");
        assert_eq!(ResourceDim::AuctionDelay.as_canonical_tag(), b"auc_del");
        assert_eq!(
            ResourceDim::WaterLitresConsumed.as_canonical_tag(),
            b"water_l"
        );
    }

    #[test]
    fn water_is_a_negative_externality() {
        // Water is a tax dimension (a cost on third parties), not a
        // positive spillover — it must NOT be flagged positive, or the
        // rate-setter would pay agents to consume water.
        assert!(!ResourceDim::WaterLitresConsumed.is_positive_externality());
    }

    #[test]
    fn water_sorts_last_so_prior_digests_are_stable() {
        // Water was appended at the end of the enum specifically so the
        // derived `Ord` (by discriminant = declaration order) leaves
        // every pre-existing variant's position unchanged. If a future
        // edit inserts a variant earlier, this test fails and forces a
        // PROFILE_DOMAIN / RESOURCE_DIM_DOMAIN bump.
        let all = ResourceDim::all();
        assert_eq!(*all.last().unwrap(), ResourceDim::WaterLitresConsumed);
        for w in all.windows(2) {
            assert!(w[0] < w[1], "all() must be in strict Ord order");
        }
    }
}
