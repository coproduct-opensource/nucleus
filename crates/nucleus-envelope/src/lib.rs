//! Portable provenance bundles for nucleus agent sessions.
//!
//! A [`Bundle`] is the on-wire artifact a nucleus control plane hands its
//! customer at the end of a session: the agent's structured payload (hard
//! stats, AI-generated summary, anything JSON) plus an [`Envelope`] that
//! carries the signed IFC lineage subgraph proving how the payload was
//! produced.
//!
//! # Trust model — read this before pitching to anyone
//!
//! The bundle is **portable** (anyone can carry the bytes), but it is
//! **not self-anchoring**. The JWKS embedded in the envelope is
//! producer-supplied material; a forger fabricating a whole bundle
//! controls it. Therefore [`verify_bundle`] requires a [`TrustAnchor`]
//! the verifier obtained out-of-band (file under `chmod 400`, OIDC
//! discovery, signed operator bundle). The trust anchor's JWKS — not
//! the embedded one — is what every signature is checked against.
//!
//! [`TrustAnchor::self_check_only`] exists as an explicit opt-in to
//! "verify the envelope against the JWKS it carries." That proves the
//! bundle is internally consistent (no later mutation could go
//! undetected) but does **not** prove the producer is who they claim.
//! The [`VerificationReport`] flags this mode so downstream code can
//! refuse to treat it as a provenance claim.
//!
//! # Composition layers
//!
//! 1. **Per-edge proofs** (from `nucleus-lineage::Proof`) — each edge's
//!    Ed25519 signature covers `canonical_edge_bytes(edge, prev_hash)`.
//!    Tampering with any edge breaks signature verification.
//! 2. **Hash chain** — each edge's `prev_hash` field points to the previous
//!    edge's content hash. Splicing/reordering breaks the chain.
//! 3. **Signed tree heads** (from `nucleus-lineage::SignedTreeHead`) — the
//!    witness's Ed25519 signature over `(tree_size, timestamp_ms, root_hash)`
//!    attests "at this moment, the log had N entries." The Merkle anchor's
//!    STH binds the session edges by inclusion proof; `checkpoints` are
//!    verified against the same witness key, against the anchor, and — when
//!    the bundle carries the whole log — against roots recomputed from its
//!    edges ([`CheckpointVerification`]).
//! 4. **Payload binding** — the producer's signature over the canonical
//!    payload hash, the chain head, the Merkle root and the envelope
//!    metadata ([`binding`]).
//!
//! # Scope limits
//!
//! Checkpoints of a log larger than the session cannot be recomputed from
//! the bundle, which does not carry the other sessions' edges or a
//! consistency proof: they are checked for signature, equivocation and
//! agreement with the anchor only. A bundle without a payload binding has
//! no producer signature over its payload or its metadata; require one with
//! [`TrustAnchor::require_payload_binding`].
//!
//! # Example
//!
//! ```ignore
//! use nucleus_envelope::{build_bundle, BundleBuilder};
//! use nucleus_lineage::{InMemorySink, CallSpiffeId};
//!
//! let pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer")?;
//! // ... agent runs, sink fills with edges ...
//! let bundle = BundleBuilder::new(pod)
//!     .payload(serde_json::json!({"summary": "..."}))
//!     .sink(&sink)
//!     .jwks(issuer_jwks)
//!     .checkpoints(checkpoints)
//!     .build()?;
//! let json = serde_json::to_string(&bundle)?;
//! ```

pub mod binding;
pub mod bundle;
#[cfg(feature = "c2pa")]
pub mod c2pa_export;
pub mod extract;
pub mod interop;
pub mod verify;

#[cfg(feature = "c2pa")]
pub use c2pa_export::{C2paExportError, NUCLEUS_C2PA_ASSERTION_LABEL};
pub use interop::in_toto::{
    DSSE_INTOTO_PAYLOAD_TYPE, DsseEnvelope, DsseSignature, IN_TOTO_STATEMENT_TYPE, InTotoError,
    NUCLEUS_PREDICATE_TYPE, NUCLEUS_SUBJECT_NAME, ResourceDescriptor, Statement,
};
pub use interop::sigstore::{
    PublicKeyIdentifier, SIGSTORE_BUNDLE_V03_MEDIA_TYPE, SigstoreBundle, TimestampVerificationData,
    VerificationMaterial,
};
pub use interop::slsa::{
    BuildDefinition, Builder as SlsaBuilder, Metadata as SlsaMetadata, NUCLEUS_BUILD_TYPE,
    Provenance, RunDetails, SLSA_PROVENANCE_V1_PREDICATE_TYPE,
};

pub use binding::{
    BindingError, NUCLEUS_BUNDLE_PAYLOAD_TYPE, PayloadBinding, payload_hash,
    signed_bytes as binding_signed_bytes,
};
pub use bundle::{
    Bundle, BundleBuilder, BundleError, ENVELOPE_SCHEMA_VERSION, EdgeInclusionProof, Envelope,
    EnvelopeAttestation, EnvelopeMeta, MIN_SUPPORTED_ENVELOPE_SCHEMA_VERSION, MerkleAnchor,
    canonical_bundle_hash,
};
pub use extract::{SessionSubgraph, extract_session_subgraph};
pub use verify::{
    CheckpointVerification, TrustAnchor, VerificationReport, VerifyBundleError, verify_bundle,
};
