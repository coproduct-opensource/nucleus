//! Portable provenance bundles for nucleus agent sessions.
//!
//! A [`Bundle`] is the on-wire artifact a nucleus control plane hands its
//! customer at the end of a session: the agent's structured payload (hard
//! stats, AI-generated summary, anything JSON) plus an [`Envelope`] that
//! carries the signed IFC lineage subgraph proving how the payload was
//! produced.
//!
//! The envelope is self-contained: a verifier needs only the bundle bytes
//! and the embedded JWKS / witness key material to re-validate every claim,
//! without access to nucleus's running state.
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
//!    attests "at this moment, the log had N entries." STHs are wire-included
//!    but their full-log Merkle binding is not enforced in v1 (see crate
//!    docs §"Scope limits").
//!
//! # Scope limits (v1)
//!
//! Per-STH **inclusion proofs** binding session edges to the signed root
//! are NOT in v1. The envelope ships the STH as a contemporaneous time
//! attestation; cryptographic linkage between session edges and the STH
//! root requires audit-path generation from the Merkle tree (a v2 follow-up
//! tracked against `MemoryBackedTree::prove_inclusion`). Today's edge-level
//! and chain-level integrity remain fully enforced.
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

pub mod bundle;
pub mod extract;
pub mod verify;

pub use bundle::{Bundle, BundleBuilder, BundleError, Envelope, EnvelopeMeta};
pub use extract::{extract_session_subgraph, SessionSubgraph};
pub use verify::{verify_bundle, VerificationReport, VerifyBundleError};
