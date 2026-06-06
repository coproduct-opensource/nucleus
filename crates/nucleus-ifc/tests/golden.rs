//! Golden-vector reader for the IFC decision gate (the seal's IFC arm, gap G3).
//!
//! Pins `FlowDeclaration::decide()` — the model-level lethal-trifecta gate — to a
//! single-source JSON of (inputs, sink_public) → (allow, declared_inputs). The
//! SAME vectors feed the WASM `recomputeVerdict` binding, so the Rust gate and the
//! in-browser recompute cannot drift from each other (or from these verdicts)
//! without turning CI red. Mirrors the seal pattern used for the econ kernels.
//!
//! Gated on the `decision` feature (which `decide()` lives behind); CI's
//! `cargo test --all-features` exercises it.
#![cfg(feature = "decision")]

use std::path::PathBuf;

use nucleus_ifc::decision::{DeclaredInput, FlowDeclaration};
use serde::Deserialize;

#[derive(Deserialize)]
struct GoldenFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "_name", default)]
    name: String,
    inputs: Vec<DeclaredInput>,
    #[serde(default)]
    requires_authority: bool,
    #[serde(default)]
    sink_public: bool,
    allow: bool,
    declared_inputs: Vec<String>,
}

#[test]
fn ifc_decision_matches_golden_vectors() {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "golden", "ifc.json"]
        .iter()
        .collect();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let golden: GoldenFile =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path:?}: {e}"));

    assert!(!golden.vectors.is_empty(), "golden file has no vectors");

    for v in &golden.vectors {
        let mut decl = FlowDeclaration::new(v.inputs.iter().copied());
        decl.requires_authority = v.requires_authority;
        decl.sink_public = v.sink_public;

        let verdict = decl.decide();

        assert_eq!(verdict.is_allow(), v.allow, "allow mismatch: {}", v.name);
        assert_eq!(
            verdict.declared_inputs, v.declared_inputs,
            "declared_inputs mismatch: {}",
            v.name
        );
    }
}
