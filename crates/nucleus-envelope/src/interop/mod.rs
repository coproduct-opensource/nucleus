//! Interop adapters that re-emit a [`Bundle`](crate::Bundle) as
//! standard provenance formats consumed by ecosystem verifiers.
//!
//! Each submodule targets one wire format. None pull heavy
//! transitive dependencies (the heavy one, C2PA, lives in
//! [`crate::c2pa_export`] behind its own feature flag); the formats
//! here are all pure JSON + base64 + Ed25519, the primitives the
//! envelope already uses.

pub mod in_toto;
pub mod sigstore;
pub mod slsa;
