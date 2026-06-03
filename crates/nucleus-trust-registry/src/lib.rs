// SPDX-License-Identifier: MIT
//
//! `nucleus-trust-registry` — "Let's Encrypt for agents": a PR-rooted,
//! GitHub-OIDC-attested, transparency-logged SPIFFE **federation
//! enrollment** registry.
//!
//! It answers one operational question: *which foreign SPIFFE trust
//! domains do we federate with, and who attested each one?* It produces a
//! deterministic [`compile::FederationSet`] that feeds the inbound
//! validator (`nucleus-oidc-core::FederationStore`), and an append-only,
//! witness-cosigned transparency log of every trust-root binding.
//!
//! # NON-CUSTODIAL — this is NOT a CA
//!
//! The registry **records, distributes, and verifies**
//! trust-domain → JWK-Set bindings. It is **never** a certificate
//! authority and **never** a keyholder: it does not mint keys, does not
//! sign on behalf of enrolled domains, and does not hold their private
//! material. Each enrolled domain runs its own SPIFFE authority; we only
//! pin the public JWK Set it publishes.
//!
//! # Honest caveat #1 — what the OIDC proof actually proves
//!
//! The GitHub Actions OIDC proof-of-control
//! ([`verify_proof_of_control`]) proves that the enrolling PR ran inside
//! a repository owned by **the GitHub org whose numeric id is pinned in
//! the metadata** (`repository_owner_id`, matched as a NUMERIC pin so an
//! org rename / re-registration cannot squat an existing enrollment).
//!
//! It does **NOT** prove the enroller owns the SPIFFE **trust domain**.
//! v1 anchors enrollment authority to a GitHub identity. A DNS-01-style
//! proof that you actually control the trust-domain name is **v2** — do
//! not read "proves GitHub-org control" as "proves trust-domain
//! ownership".
//!
//! # Honest caveat #2 — auditable, not un-backdoorable
//!
//! The transparency log makes a misbehaving maintainer **detectable**,
//! not **impossible**. A binding is trusted only if its leaf is in a
//! witness-cosigned Signed Tree Head ([`tlog::verify_binding_in_log`]),
//! so a backdated or out-of-band insertion that never entered the
//! cosigned log is rejected, and tampering with a bundle breaks its
//! inclusion proof. But a maintainer who colludes with the witness can
//! still enroll a binding — transparency surfaces that for auditors; it
//! does not prevent it.
//!
//! # Honest caveat #3 — MVP trust base
//!
//! MVP = a **single** registry maintainer + a **single** witness. We do
//! NOT borrow Sigstore's threshold-signing / key-ceremony language: there
//! is no quorum and no ceremony here. Adding witnesses is a drop-in (the
//! cosign primitive is per-witness), but until then the witness is a
//! single point of trust.
//!
//! # Single-tenant value
//!
//! The immediate, real use is enrolling your **own** trust domains —
//! `prod` / `staging` / `edge` / `ci` — each running its own SPIFFE
//! authority across failure domains, with the registry as the auditable
//! record of which ones federate. No external party is required.
//!
//! # Dormant metering seam
//!
//! Verifying an enrollment (proof-of-control + transparency inclusion) is
//! a unit of proven work and a natural metering point. That seam is
//! **documented only** — there is no payment, no token, and no counter
//! wired anywhere in this crate.
//!
//! # Reuse map (net-new logic is thin)
//!
//! - SPIFFE bundle / JWK Set parsing + the inbound validator:
//!   `nucleus-oidc-core` (`SpiffeBundle`, `Jwks`, `FederationStore`).
//! - The alg-pinned `jsonwebtoken` verify pattern for the OIDC proof:
//!   mirrors `nucleus-oidc-core::spiffe_federation`.
//! - The Merkle log + STH: `ct_merkle` + `nucleus-lineage`
//!   (`Ed25519Witness`, `SignedTreeHead`, `format_checkpoint_body`).
//! - The witness cosignature: `nucleus-witness` (`WitnessKey`,
//!   `verify_cosign_line`).

pub mod compile;
pub mod error;
pub mod federation;
pub mod metadata;
pub mod proof;
pub mod tlog;

pub use compile::{
    check_no_silent_rotation, check_pr_diff, compile, CompiledBinding, FederationSet,
};
pub use error::RegistryError;
pub use federation::{apply_to_store, build_federation_store};
pub use metadata::{DomainEnrollment, DomainMetadata, DOMAINS_SUBDIR, PROFILE_HTTPS_WEB};
pub use proof::{verify_proof_of_control, ProofClaims, GITHUB_ISSUER};
pub use tlog::{
    binding_leaf, verify_binding_in_log, AppendedLeaf, SealedLog, StoredInclusion, TrustLog,
    LOG_ORIGIN,
};
