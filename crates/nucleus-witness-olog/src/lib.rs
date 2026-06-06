//! `nucleus-witness-olog` — the Phase 2 contract (P2.1): the `Gov` functor that
//! turns an admitted witness into an accumulated **olog fact**, and the signed
//! **accumulation manifest** that records it.
//!
//! This is the bridge that makes proof-of-work *accumulate and compose* instead of
//! staying per-transaction: `Gov : 𝓦 → 𝓞` maps admitted [`functor::WitnessNode`]s
//! (content-addressed, lineage-linked) to [`functor::OlogFact`]s in the categorical
//! KB, and each is bound into a transparency-loggable [`manifest::AccumulationManifest`].
//!
//! **Scope (P2.1):** types + the functor trait + the load-bearing **no-upgrade
//! invariant** (Gov carries the witness's assurance rung/tier through unchanged —
//! trust in, trust out — never manufacturing or strengthening trust). The wiring
//! to the real `merge-gate` witness archive and the live `olog` instance store is
//! **P2.2**; the [`functor::WitnessDigest`] / instance-digest here are 32-byte
//! stand-ins P2.2 unifies with `ck-types::ArtifactDigest` and real olog instances.
//!
//! The functoriality theorem (`Gov(g ∘ f) = Gov(g) ∘ Gov(f)` ⇒ proven work
//! composes) is the Lean goal stated in `docs/rfcs/witness-olog-functor.md`; this
//! crate encodes the per-object behaviour + the no-upgrade invariant as tests.

#![forbid(unsafe_code)]

pub mod bond;
pub mod functor;
pub mod manifest;
pub mod pin;

pub use bond::{
    canonical_bond_bytes, canonical_ownership_bytes, canonical_root_attestation_bytes,
    canonical_signed_recompute_bytes, canonical_witness_claim_bytes, deters, forfeiture_amount,
    forfeiture_on_fork, mint_bond, release_bond, required_bond, sign_ownership, sign_recompute,
    sign_root_attestation, sign_witness_claim, slash, staying_is_rational,
    total_canonical_collateral, verify_bond, verify_ownership, verify_root_attestation,
    verify_signed_recompute, verify_witness_claim, AmountMicro, Bond, BondError, BondStanding,
    LedgerRoot, Refutation, RootAttestation, SignedOwnership, SignedRecompute, SignedWitnessClaim,
    SlashOutcome, BOND_BPS_SCALE, BOND_DOMAIN, FORK_COST_THEOREM_MODELED,
};
pub use functor::{
    accumulate, AdmissionVerdict, FakeWitnessSource, Gov, LineageEdge, NoUpgradeGov, OlogFact,
    Tier, WitnessDigest, WitnessNode, WitnessSource,
};
pub use manifest::{
    canonical_manifest_bytes, manifest_from_fact, sign_manifest, verify_manifest,
    AccumulationManifest, ManifestError, MANIFEST_DOMAIN,
};
pub use pin::{
    accept_fact, canonical_checkpoint_bytes, sign_checkpoint, LogIdentity, PinnedLog,
    SignedCheckpoint, TrustRejection, CHECKPOINT_DOMAIN,
};
