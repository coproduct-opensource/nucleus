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

pub mod functor;
pub mod manifest;

pub use functor::{
    AdmissionVerdict, Gov, LineageEdge, NoUpgradeGov, OlogFact, Tier, WitnessDigest, WitnessNode,
};
pub use manifest::{
    canonical_manifest_bytes, manifest_from_fact, sign_manifest, verify_manifest,
    AccumulationManifest, ManifestError, MANIFEST_DOMAIN,
};
