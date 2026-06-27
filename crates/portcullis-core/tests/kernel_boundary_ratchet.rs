//! Minimum Viable IFC Kernel — boundary ratchet (RFC `minimum-viable-ifc-kernel.md`, M0).
//!
//! The IFC reference monitor is a ~5k-LOC near-leaf subgraph of the 38.5k-LOC
//! `portcullis-core`. This test makes that boundary ENFORCEABLE TODAY — before
//! the physical crate split (M3) — by failing if any dedicated kernel source file
//! gains an intra-crate dependency on a NON-kernel module.
//!
//! It is the "ratchet the dep-count so the boundary can't erode" artifact: a PR
//! that makes `flow.rs` reach into `witness`/`memory`/`enterprise`/etc. turns this
//! test red, so the reference monitor can't silently absorb downstream machinery.
//!
//! ## Scope (honest)
//!
//! - Covers the DEDICATED kernel files (`flow`, `ifc_api`, `effect`,
//!   `storage_lane`, `extracted/*`). The lib.rs lattice block joins the ratchet
//!   once extracted to its own module (M1).
//! - Detects MODULE-level deps (`crate::<module>::…`). A kernel file using a
//!   crate-root re-export of a non-kernel type (`crate::SomeType`) is not caught
//!   by v1 — module deps are the dominant erosion vector. (Crate-root fns/types
//!   like `crate::is_exfil_operation` / `crate::IFCLabel` are intentionally
//!   allowed: they are the kernel's own root primitives.)

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The dedicated source files that make up the IFC kernel today (paths relative
/// to the crate root). The lib.rs lattice block is tracked separately until M1.
const KERNEL_FILES: &[&str] = &[
    "src/ifc_lattice.rs",
    "src/flow.rs",
    "src/ifc_api.rs",
    "src/effect.rs",
    "src/storage_lane.rs",
    "src/extracted/mod.rs",
    "src/extracted/ifc_integrity.rs",
    "src/extracted/ifc_confidentiality.rs",
];

/// Intra-crate modules the kernel is ALLOWED to depend on — itself.
const KERNEL_MODULES: &[&str] = &["flow", "ifc_api", "effect", "storage_lane", "extracted"];

/// Known, documented residual entanglements to be removed by a named rung. Each
/// entry MUST still be referenced by the kernel (asserted below) so a completed
/// decoupling forces its removal from this list.
///
/// EMPTY as of M2: the lone `discharge` entanglement was inverted — the kernel
/// now defines the `PolicyDischarged` capability contract and `discharge`
/// satisfies it (`discharge.rs`), so the IFC kernel names no downstream module.
const ALLOWLISTED_RESIDUALS: &[&str] = &[];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every module declared in lib.rs via `(pub )?mod <name>;`.
fn declared_modules() -> BTreeSet<String> {
    let lib = fs::read_to_string(crate_root().join("src/lib.rs")).expect("read src/lib.rs");
    let mut mods = BTreeSet::new();
    for line in lib.lines() {
        let t = line.trim();
        // Match `mod x;` and `pub mod x;` declarations (not `mod x {`).
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
fn crate_refs(src: &str) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    let bytes = src.as_bytes();
    let needle = b"crate::";
    let mut i = 0;
    while let Some(pos) = src[i..].find("crate::") {
        let start = i + pos + needle.len();
        let mut end = start;
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            refs.insert(src[start..end].to_string());
        }
        i = start;
    }
    refs
}

#[test]
fn kernel_files_only_depend_on_kernel_modules() {
    let declared = declared_modules();
    let kernel: BTreeSet<&str> = KERNEL_MODULES.iter().copied().collect();
    let allowlist: BTreeSet<&str> = ALLOWLISTED_RESIDUALS.iter().copied().collect();

    // Sanity: the kernel module names and allowlist must be real modules.
    for m in KERNEL_MODULES.iter().chain(ALLOWLISTED_RESIDUALS) {
        assert!(
            declared.contains(*m),
            "ratchet config names `{m}`, which is not a declared module in lib.rs"
        );
    }

    // The disallowed set: every declared module that is neither kernel nor an
    // explicitly allowlisted residual.
    let disallowed: BTreeSet<&str> = declared
        .iter()
        .map(String::as_str)
        .filter(|m| !kernel.contains(m) && !allowlist.contains(m))
        .collect();

    let mut violations: Vec<String> = Vec::new();
    let mut residuals_seen: BTreeSet<&str> = BTreeSet::new();

    for rel in KERNEL_FILES {
        let src = fs::read_to_string(crate_root().join(rel)).unwrap_or_else(|e| {
            panic!("read kernel file {rel}: {e}");
        });
        for seg in crate_refs(&src) {
            if disallowed.contains(seg.as_str()) {
                violations.push(format!("{rel} depends on non-kernel module `crate::{seg}`"));
            }
            if let Some(r) = allowlist.get(seg.as_str()) {
                residuals_seen.insert(*r);
            }
        }
    }

    assert!(
        violations.is_empty(),
        "MVK boundary violated — the IFC kernel reached into downstream modules:\n{}\n\n\
         Either keep the decision out of the kernel, or (if genuinely core) bring \
         the module into KERNEL_MODULES and the RFC's member set.",
        violations.join("\n")
    );

    // Keep the allowlist honest: an entry no longer referenced is stale and must
    // be deleted (its decoupling rung is done).
    for r in &allowlist {
        assert!(
            residuals_seen.contains(r),
            "allowlisted residual `{r}` is no longer referenced by any kernel file — \
             its decoupling is complete; remove it from ALLOWLISTED_RESIDUALS."
        );
    }
}
