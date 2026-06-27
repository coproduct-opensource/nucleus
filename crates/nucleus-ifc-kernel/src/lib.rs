//! `nucleus-ifc-kernel` — the IFC admission core.
//!
//! This crate is the minimal, dependency-free reference monitor carved out of
//! `portcullis-core` (MVK M3). It is the source of truth for:
//!
//! - [`CapabilityLevel`] — the 3-element permission lattice scalar
//!   (`Never < LowRisk < Always`) — and the product [`CapabilityLattice`].
//! - The exposure detector + the pure capability decision (`decide_pure`).
//! - The IFC label lattice: [`IFCLabel`], [`ConfLevel`], [`IntegLevel`],
//!   [`AuthorityLevel`], [`ProvenanceSet`], [`Freshness`], [`DerivationClass`]
//!   with `join`/`meet`/`flows_to`/`leq`.
//! - The operation/sink vocabulary: [`Operation`], [`SinkClass`],
//!   `required_*`, `default_sink_class`, [`is_exfil_operation`].
//! - The [`flow`] tracker, the [`ifc_api`] safety-check surface, the
//!   [`discharge`] preflight pipeline, and [`effect`]/[`storage_lane`].
//! - The Aeneas-extracted IFC slices in [`extracted`] that the
//!   noninterference theorems are proven over.
//!
//! ## Why a separate crate?
//!
//! Aeneas (Rust MIR → Lean 4) requires dependency-free code. Physically
//! isolating the reference monitor into its own crate makes the kernel
//! boundary a *mechanical* property (the dependency graph), not a convention:
//! this crate cannot reach into `witness`/`memory`/`enterprise`/etc. because
//! it does not depend on them.
//!
//! `portcullis-core` depends on this crate and re-exports its surface, so every
//! existing `portcullis_core::{IFCLabel, Operation, CapabilityLevel, flow, …}`
//! path continues to resolve unchanged.
//!
//! Serde support is gated behind the optional `serde` feature flag.

// Lattice scalar — private module, re-exported at the crate root so
// `nucleus_ifc_kernel::CapabilityLevel` resolves.
mod capability_level;
pub use capability_level::*;

// Information Flow Control label lattice (MVK M1).
mod ifc_lattice;
pub use ifc_lattice::*;

// Operation & sink-class vocabulary (MVK M1b).
mod ifc_ops;
pub use ifc_ops::*;

// The capability product lattice + the exposure detector / pure decision —
// the rest of the Aeneas-verified surface (MVK M3 whole-core).
mod capability_lattice;
pub use capability_lattice::*;

mod exposure;
pub use exposure::*;

pub mod discharge;
pub mod effect;
pub mod extracted;
pub mod flow;
pub mod ifc_api;
pub mod storage_lane;
