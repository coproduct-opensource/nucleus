//! Coproduct Pigouvian externality layer.
//!
//! Bridges the substrate's existing VCG clearing kernel
//! (`nucleus-econ-kernels`) with a cross-auction / cross-time
//! externality-pricing mechanism so the auction internalizes the social
//! cost of running an agent — compute-watts, GPU-seconds, peer-verifier
//! load, corpus pollution, carbon, FX volatility, downstream auction
//! delay.
//!
//! # SOTA inspirations
//!
//! - **Two-stage VCG-with-externalities** —
//!   [arXiv 2305.01477](https://arxiv.org/pdf/2305.01477) on
//!   interdependent valuations + externalities; bidders' utilities
//!   are re-weighted by signed externality claims BEFORE the kernel
//!   sees them.
//! - **AI-driven Pigouvian prices** —
//!   [arXiv 2106.06060](https://arxiv.org/pdf/2106.06060) on
//!   sustainability-aware production-market pricing.
//! - **Hierarchical multi-agent learning convergence** —
//!   [arXiv 2601.03451](https://arxiv.org/pdf/2601.03451) shows that
//!   when dependency graphs are hierarchical (which our lineage
//!   edges are by construction), Pigouvian rates converge to a
//!   stable equilibrium without misreport incentives.
//! - **Verifiable Carbon Accounting** — zk-SNARK proofs of bounded
//!   emissions plus TEE-attested oracle signatures keep externality
//!   claims non-disclosing while peer-verifiable.
//! - **OLAP rollup pattern** — the sibling `tomato` repo's
//!   `Aggregate.fs` cube semantics transfer cleanly: every signed
//!   `EdgeKind::Externality` rolls up into an
//!   `(resource_dim, window, identity_class, federation_member)`
//!   cube whose slice-derivative gives the marginal Pigouvian rate.
//!
//! # Integer-only discipline
//!
//! The economic math stays integer per `docs/ECON-PRECISION.md`:
//! `effective_minus_pigou_micro = bid - Σ λ_k · ext_k / 1_000_000`
//! computed in `u128` with saturation to `u64`. No floats in the
//! Pigouvian path; the `[lints]` workspace inherit denies
//! `clippy::float_arithmetic`.

#![deny(clippy::float_arithmetic)]

mod claim;
mod dim;
mod oracle;
mod profile;

pub use claim::{
    canonical_claim_bytes, sign_claim, verify_claim, ClaimError, SignedExternalityClaim,
};
pub use dim::{ResourceDim, RESOURCE_DIM_DOMAIN};
pub use oracle::{
    verify_vca_claim, OracleError, OracleRegistry, TeeAttestation, TeeVendor, UpperEnvelopeProof,
    VcaExternalityClaim,
};
pub use profile::{
    canonical_externality_bytes, externality_digest, ExternalityProfile, PROFILE_DOMAIN,
};
