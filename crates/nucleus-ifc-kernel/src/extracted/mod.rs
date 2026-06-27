//! Subset-safe, Aeneas-extractable slices of the enforcement core.
//!
//! Aeneas (the Rust→Lean verifier) cannot translate the *whole*
//! `portcullis-core` crate — `String`/`Vec`/`BTreeMap`/closures in unrelated
//! code make a whole-crate translation crash. The standard Aeneas workflow is
//! to *scope* the extraction to a dependency-free subgraph and translate only
//! that.
//!
//! This module hosts pure, `String`-free restatements of individual
//! enforcement decisions, written so their reachable dependency subgraph stays
//! inside Aeneas's supported safe-Rust subset. Each function is a byte-faithful
//! mirror of the corresponding clause in the production `IFCLabel`/`SinkClass`
//! code in `lib.rs`, and is bound to that production code by exhaustive parity
//! tests (see each submodule's `#[cfg(test)]` block).
//!
//! The extraction roots live here so the CI extractor can name them with
//! `charon ... --start-from portcullis_core::extracted::ifc_integrity::<fn>`.

pub mod ifc_confidentiality;
pub mod ifc_integrity;
