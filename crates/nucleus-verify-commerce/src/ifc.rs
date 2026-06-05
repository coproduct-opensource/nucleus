//! The IFC gate types — now **homed in `nucleus-ifc`** (`nucleus_ifc::decision`)
//! so the decision is wasm-safe and shared verbatim with the `@nucleus/verify`
//! recompute SDK: the recompute re-derives the verdict with the EXACT same code
//! the production gate runs, so it can never drift from enforcement.
//!
//! See [`nucleus_ifc::decision`] for the honesty boundary (model-level, declared
//! inputs, per-call, fails closed).

pub use nucleus_ifc::decision::{DeclaredInput, FlowDeclaration, IfcVerdict};
