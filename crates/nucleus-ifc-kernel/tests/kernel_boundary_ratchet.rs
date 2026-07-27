//! IFC kernel boundary ratchet — post-split form (MVK M3).
//!
//! The IFC reference monitor was a ~5k-LOC near-leaf subgraph of the 38.5k-LOC
//! `portcullis-core`. In M3 it was physically carved into THIS crate
//! (`nucleus-ifc-kernel`), so the boundary is now enforced *mechanically* by the
//! dependency graph: this crate's `Cargo.toml` depends only on `serde` (optional),
//! so a kernel file simply CANNOT reach into `witness`/`memory`/`enterprise`/
//! `CapabilityLattice`/etc. — those crates/types are not in scope.
//!
//! This test is the residual lint that survives the split. Its erosion-prevention
//! purpose (a PR making `flow.rs` reach into non-kernel machinery) is now covered
//! by the crate boundary; what remains useful here is:
//!
//! - flagging any `use crate::*` / `crate::*` wildcard, which would obscure the
//!   kernel's internal coupling surface; and
//! - asserting every `crate::<root-item>` a kernel file names is an ENUMERATED
//!   kernel primitive (so a new crate-root export is a deliberate, reviewed
//!   addition rather than an accident).
//!
//! Every source file in this crate is a kernel file (the crate IS the kernel),
//! so there is no longer a `lib.rs` "root residual" frontier to fence and no
//! non-kernel module allowlist — both concepts went away with the split.
//!
//! ## Honest scope / limitations
//!
//! - Text-based: it scans comments/strings too (a doc example naming
//!   `crate::enterprise::Foo` would redden it — a false positive in the SAFE
//!   direction). It does not resolve macro-generated paths.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The dedicated source files that make up the IFC kernel (paths relative to the
/// crate root). Post-split this is every non-`lib.rs` source file in the crate.
const KERNEL_FILES: &[&str] = &[
    "src/capability_level.rs",
    "src/capability_lattice.rs",
    "src/exposure.rs",
    "src/hash_types.rs",
    "src/ifc_lattice.rs",
    "src/ifc_ops.rs",
    "src/flow.rs",
    "src/ifc_api.rs",
    "src/effect.rs",
    "src/storage_lane.rs",
    "src/discharge.rs",
    "src/extracted/mod.rs",
    "src/extracted/ifc_integrity.rs",
    "src/extracted/ifc_confidentiality.rs",
];

/// Intra-crate modules a kernel file may name — every module of THIS crate.
/// (Kept in sync with `declared_modules()` below, which is asserted to be a
/// subset, so an added kernel module must be added here deliberately.)
const KERNEL_MODULES: &[&str] = &[
    "capability_level",
    "capability_lattice",
    "exposure",
    "hash_types",
    "ifc_lattice",
    "ifc_ops",
    "flow",
    "ifc_api",
    "effect",
    "storage_lane",
    "discharge",
    "extracted",
];

/// Crate-root items (types/fns) DEFINED in a kernel file and referenced by other
/// kernel files via the crate-root re-export. These are kernel-internal, so
/// `crate::IFCLabel` / `crate::Operation` / `crate::CapabilityLevel` etc. are
/// allowed.
const KERNEL_ROOT_PRIMITIVES: &[&str] = &[
    // capability_level.rs (M3)
    "CapabilityLevel",
    // ifc_lattice.rs (M1)
    "ConfLevel",
    "IntegLevel",
    "AuthorityLevel",
    "ProvenanceSet",
    "Freshness",
    "DerivationClass",
    "IFCLabel",
    // hash_types.rs (InputsAuthorized brick 1)
    "ContentHash",
    // ifc_ops.rs (M1b)
    "Operation",
    "SinkClass",
    "is_exfil_operation",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every module declared in lib.rs via `(pub )?mod <name>;`.
fn declared_modules() -> BTreeSet<String> {
    let lib = fs::read_to_string(crate_root().join("src/lib.rs")).expect("read src/lib.rs");
    let mut mods = BTreeSet::new();
    for line in lib.lines() {
        let t = line.trim();
        let rest = t
            .strip_prefix("pub mod ")
            .or_else(|| t.strip_prefix("mod "));
        if let Some(rest) = rest
            && let Some(name) = rest.strip_suffix(';')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            mods.insert(name.to_string());
        }
    }
    mods
}

/// Collect the first path segment of every `crate::<seg>` occurrence in `src`.
/// `crate::*` yields the sentinel `"*"` so the wildcard can be flagged.
fn crate_refs(src: &str) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    let bytes = src.as_bytes();
    let needle = "crate::";
    let mut i = 0;
    while let Some(pos) = src[i..].find(needle) {
        let start = i + pos + needle.len();
        if bytes.get(start) == Some(&b'*') {
            refs.insert("*".to_string());
            i = start;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if end > start {
            refs.insert(src[start..end].to_string());
        }
        i = start;
    }
    refs
}

#[test]
fn kernel_files_only_depend_on_kernel_code() {
    let declared = declared_modules();
    let kernel_mods: BTreeSet<&str> = KERNEL_MODULES.iter().copied().collect();
    let root_primitives: BTreeSet<&str> = KERNEL_ROOT_PRIMITIVES.iter().copied().collect();

    // Sanity: every name in KERNEL_MODULES must be a real declared module, and
    // every declared module must be enumerated in KERNEL_MODULES (so adding a new
    // kernel module forces a deliberate update here).
    for m in KERNEL_MODULES {
        assert!(
            declared.contains(*m),
            "ratchet config names module `{m}`, which is not declared in lib.rs"
        );
    }
    for m in &declared {
        assert!(
            kernel_mods.contains(m.as_str()),
            "lib.rs declares module `{m}` not enumerated in KERNEL_MODULES — add it (and its \
             source file to KERNEL_FILES) so the kernel boundary stays explicit"
        );
    }

    let mut violations: Vec<String> = Vec::new();

    for rel in KERNEL_FILES {
        let src = fs::read_to_string(crate_root().join(rel))
            .unwrap_or_else(|e| panic!("read kernel file {rel}: {e}"));
        for seg in crate_refs(&src) {
            if seg == "*" {
                violations.push(format!(
                    "{rel} uses a `crate::*` wildcard — import kernel items explicitly so the \
                     boundary stays visible"
                ));
            } else if declared.contains(seg.as_str()) {
                // It's a module path: every declared module is a kernel module
                // (the crate IS the kernel), so this is always allowed. The
                // `declared ⊆ KERNEL_MODULES` assertion above keeps that honest.
            } else if !root_primitives.contains(seg.as_str()) {
                // It's a crate-ROOT item: must be an enumerated kernel primitive.
                violations.push(format!(
                    "{rel} depends on un-enumerated crate-root item `crate::{seg}` — if it is a \
                     kernel primitive add it to KERNEL_ROOT_PRIMITIVES, otherwise keep it out of \
                     the kernel"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "MVK boundary violated — a kernel file reached past the enumerated kernel surface:\n{}",
        violations.join("\n")
    );
}
