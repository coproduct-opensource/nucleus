//! Per-call SPIFFE-derived data lineage for nucleus tool calls.
//!
//! Each tool invocation, LLM call, or derived artifact gets a child
//! [`CallSpiffeId`] derived from its parent's identity. The path encodes
//! the lineage; an optional content-hash suffix makes IDs content-addressed
//! (identical data → identical ID, regardless of derivation path).
//!
//! Lineage edges form a DAG persisted via the [`LineageSink`] trait.
//! The `nucleus lineage` CLI walks this DAG to answer "where did this data
//! come from".
//!
//! # Path scheme
//!
//! ```text
//! spiffe://<trust>/ns/<ns>/sa/<sa>                              ← pod (root)
//!   /call/<uuid>/tool/<tool>                                    ← tool call
//!   /call/<uuid>/llm/<provider>/prompt/sha256:<hex>             ← LLM input
//!   /call/<uuid>/llm/<provider>/response/sha256:<hex>           ← LLM output
//!   /call/<uuid>/derived/sha256:<hex>                           ← downstream artifact
//! ```
//!
//! # Cargo features
//!
//! - `insecure-local-issuer` *(non-default)* — enables the in-process
//!   [`LocalIssuer`] demo JWT-SVID minter + edge signer. Pulls in
//!   `jsonwebtoken`, `rand`, and the `pkcs8` + `rand_core` features of
//!   `ed25519-dalek`. **Do not enable in production.** (`dev` is a deprecated
//!   alias kept for one release.)
//!
//! Verification (the [`verify`] module) is always available — production
//! callers reading lineage logs need exactly this surface.
//!
//! [`LocalIssuer`]: crate::local_issuer::LocalIssuer

pub mod checkpoint;
pub mod cosign;
pub mod edge;
pub mod file_signer;
pub mod id;
pub mod issuer;
pub mod merkle;
pub mod policy;
pub mod proof;
pub mod prover;
pub mod signed_note;
pub mod sink;
pub mod verify;

// Re-export ct-merkle types we expose at the API boundary so downstream
// crates (nucleus-envelope) don't need to depend on ct-merkle directly.
pub use ct_merkle::{ConsistencyProof, InclusionProof, InclusionVerifError, RootHash};

#[cfg(feature = "insecure-local-issuer")]
pub mod local_issuer;

pub use checkpoint::{
    canonical_sth_bytes, Ed25519Witness, SignedTreeHead, TreeWitness, VerifyOnlyWitness,
    WitnessError,
};
#[cfg(feature = "http")]
pub use cosign::{C2spHttpWitnessClient, HttpWitnessClient};
pub use cosign::{Cosignature, CosignatureKind, InProcessWitness, WitnessClient};
pub use edge::{EdgeKind, LineageEdge, SourceClass, VerifierAttestation};
pub use file_signer::Pkcs8FileSigner;
pub use id::{CallSpiffeId, IdError, MAX_URI_LEN};
pub use issuer::{EdgeSigner, IdentityFetcher, IssuerError, SigningProvider, SvidClaims};
pub use merkle::{read_checkpoints, verify_log, MerkleConfig, MerkleError, MerkleSink};
pub use policy::{Group, Log, Policy, PolicyError, Threshold, Witness};
pub use proof::{canonical_edge_bytes, edge_content_hash, Proof};
pub use prover::MerkleProver;
pub use signed_note::{
    checkpoint_signed_bytes, ed25519_key_id, format_checkpoint_body, format_signature_line,
    parse_signature_line, validate_key_name, validate_origin, ParsedSignatureLine, SignedNoteError,
    MAX_KEY_NAME_LEN, MAX_ORIGIN_LEN, SIG_LINE_PREFIX, SIG_TYPE_COSIGNATURE, SIG_TYPE_ED25519,
};
#[cfg(feature = "sink-io")]
pub use sink::JsonlSink;
pub use sink::{InMemorySink, LineageSink, SinkError};
pub use verify::{
    total_pigouvian_micro_usd, verify_chain, verify_proof, Jwk, Jwks, StaticKeyResolver,
    VerifyError,
};

#[cfg(feature = "insecure-local-issuer")]
pub use local_issuer::LocalIssuer;
