//! Per-call SPIFFE-derived data lineage for nucleus tool calls.
//!
//! Each tool invocation, LLM call, or derived artifact gets a child
//! [`CallSpiffeId`] derived from its parent's identity. The path encodes
//! the lineage; an optional content-hash suffix makes IDs content-addressed
//! (identical data → identical ID, regardless of derivation path).
//!
//! Lineage edges form an append-only DAG persisted via the [`LineageSink`]
//! trait. The `nucleus lineage` CLI walks this DAG to answer "where did
//! this data come from".
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
//! The trust-domain authority and `/ns/<ns>/sa/<sa>` prefix are owned by the
//! orchestrator (typically nucleus-node); this crate only manipulates the
//! `/call/...` suffix.

pub mod edge;
pub mod id;
pub mod issuer;
pub mod sink;

pub use edge::{EdgeKind, LineageEdge};
pub use id::{CallSpiffeId, IdError};
pub use issuer::{IdentityFetcher, IssuerError, LocalIssuer, SvidClaims};
pub use sink::{InMemorySink, JsonlSink, LineageSink, SinkError};
