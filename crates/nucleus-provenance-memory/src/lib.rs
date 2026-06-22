//! Provenance-backed, taint-labeled, recompute-verified, CRDT-mergeable
//! persistent memory for AI agents.
//!
//! This crate closes the **memory-poisoning** gap (AgentPoison NeurIPS'24, MINJA
//! NeurIPS'25, MemoryGraft Dec'25): an attacker who plants a record into an
//! agent's long-term memory — often via query-only interaction, with no write
//! access — can steer the agent's later actions across sessions. Capability-first
//! memory frameworks (MemGPT/Letta, mem0, A-MEM) treat stored memory as
//! trusted-by-default; this crate treats it as **untrusted until a record both
//! re-derives from its cited sources AND is declassified by a signed witness**.
//!
//! # The one object
//!
//! A [`MemoryRecord`](record::MemoryRecord) is, simultaneously:
//! 1. **content-hash-idempotent** — keyed by a [`ContentHash`](hash::ContentHash)
//!    over its canonical bytes, so the same value derived the same way is the
//!    same record (dedup is free, tampering invalidates the key);
//! 2. **taint-labeled** — carries a `portcullis_core::memory::MemoryLabel`
//!    (confidentiality × integrity × derivation class), reusing the IFC lattice;
//! 3. **signed-lineage-anchored** — every write/read emits a
//!    `nucleus_lineage::EdgeKind::DocumentRetrieved{source_class: Memory}` edge
//!    (the documented-but-previously-unwired memory↔lineage binding);
//! 4. **recompute-verified** — its [`MemoryLabel`] and (for deterministic
//!    derivations) its very value are *re-derived* from its cited source records
//!    via a generic [`RecomputeMemory`](recompute::RecomputeMemory) transform and
//!    admitted only on a [`RecomputeVerdict::Match`](recompute::RecomputeVerdict);
//! 5. **CRDT-mergeable** — held in a [`ProvenanceMemorySet`](crdt::ProvenanceMemorySet),
//!    a recompute-gated join-semilattice (idempotent/commutative/associative,
//!    fail-closed on divergence) ported from the proven
//!    `nucleus_creditworthiness::ReputationSet`.
//!
//! Using a record at a sensitive sink requires a
//! [`SignedDeclassify`](declassify::SignedDeclassify): a k-of-n Ed25519-witnessed
//! [`DeclassifyWitness`](declassify::DeclassifyWitness) gated through the monotone
//! `DerivationClass` lattice ("promotion does not cleanse").
//!
//! # Differentiation vs the 2026 prior art (honest)
//!
//! Two 2026 preprints overlap this thesis: **MemLineage** (arXiv 2605.14421 —
//! lineage-DAG taint propagation + Ed25519 + RFC6962 Merkle log + sensitive-action
//! gate) and **Portable Agent Memory** (arXiv 2605.11032 — BLAKE3 content-hash +
//! recompute-of-hashes + capability tokens). This crate deliberately occupies the
//! territory **neither** of them does:
//!
//! - **Recompute of the DERIVATION step, not just the hash.** MemLineage tags
//!   ancestry but never proves a stored memory is a faithful *function* of its
//!   cited sources; Portable Memory recomputes only that the content *hashes*
//!   match. We re-run the declared transform over the cited source records and
//!   require the result to hash-match — closing the exact MINJA/MemoryGraft seam
//!   (a planted "summary" that doesn't actually follow from its sources is
//!   rejected). Honest scope: only *deterministic* derivations are recomputable;
//!   free-form LLM summaries are quarantined as
//!   [`MemoryDerivation::OpaqueLlm`](record::MemoryDerivation) and can never reach
//!   `MayInform` without an explicit `HumanPromoted` witness.
//! - **Recompute-gated CRDT merge.** Neither paper merges signed taint-labeled
//!   lineage as a CRDT. Ours is the only recompute-gated join-semilattice for
//!   memory: replicas converge on the same *admitted-evidence* set regardless of
//!   gossip order/duplication, and a forged record never joins.
//! - **Read-side confidentiality / IFC.** Both papers scope to integrity only.
//!   We carry `ConfLevel` and feed declassification through the same IFC algebra
//!   the rest of nucleus uses, so memory has *bidirectional* flow control.
//!
//! # Honest scope (v1)
//!
//! Deterministic derivations only (extraction / templating / structured
//! distillation); non-deterministic LLM steps are quarantined, never verified.
//! Provenance is only as strong as key custody (same assumption as MemLineage /
//! Portable Memory). Adaptive/laundering adversaries and the quantitative-IFC
//! lattice upgrade are deferred. No transport here — the CRDT is pure, exactly
//! like [`ReputationSet`](https://docs.rs/nucleus-creditworthiness).

#![forbid(unsafe_code)]

pub mod crdt;
pub mod declassify;
pub mod hash;
pub mod ifc;
pub mod lineage;
pub mod recompute;
pub mod record;

pub use crdt::ProvenanceMemorySet;
pub use declassify::{declassify, DeclassifyError, DeclassifyWitness, SignedDeclassify};
pub use hash::ContentHash;
pub use ifc::memory_ifc_label;
pub use lineage::memory_lineage_edge;
pub use recompute::{RecomputeMemory, RecomputeVerdict, TransformRegistry};
pub use record::{MemoryDerivation, MemoryRecord, TransformId};

// Re-export the portcullis-core memory types this crate's API surfaces, so
// consumers (e.g. the tool-proxy memory endpoints) get one import home.
pub use portcullis_core::memory::{MemoryAuthority, MemoryLabel, SchemaType};
// The lattice level types that appear in `MemoryLabel`'s constructors/accessors.
pub use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};
// `SourceClass` is part of `MemoryDerivation::RawIngest`'s public surface.
pub use nucleus_lineage::SourceClass;
