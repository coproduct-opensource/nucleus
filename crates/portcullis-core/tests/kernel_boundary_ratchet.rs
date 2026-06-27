//! Minimum Viable IFC Kernel — boundary ratchet (RFC `minimum-viable-ifc-kernel.md`, M0).
//!
//! The IFC reference monitor is a ~5k-LOC near-leaf subgraph of the 38.5k-LOC
//! `portcullis-core`. This test makes that boundary ENFORCEABLE TODAY — before
//! the physical crate split (M3) — by failing if any dedicated kernel source file
//! gains a dependency on non-kernel code.
//!
//! It is the "ratchet the dep-count so the boundary can't erode" artifact: a PR
//! that makes `flow.rs` reach into `witness`/`memory`/`enterprise`/`CapabilityLattice`/
//! etc. turns this test red, so the reference monitor can't silently absorb
//! downstream machinery.
//!
//! ## What it catches
//!
//! For each dedicated kernel file it scans every `crate::<seg>` and flags:
//! - a `seg` that is a declared MODULE outside the kernel (and not an explicitly
//!   allowlisted coupling) — e.g. `crate::witness::…`;
//! - a `seg` that is a crate-ROOT item (type/fn) not defined in a kernel file and
//!   not an enumerated residual — e.g. `crate::CapabilityLattice` (closes the
//!   blind spot a v1 module-only scan had);
//! - any `use crate::*` / `crate::*` wildcard, which would import the whole crate
//!   root past the scanner.
//!
//! ## Honest scope / limitations
//!
//! - Covers the DEDICATED kernel files. The kernel's residual crate-root deps that
//!   still live in `lib.rs` (`Operation`, `SinkClass`, `is_exfil_operation`) are
//!   enumerated in [`ROOT_RESIDUALS`] — they are tracked, not invisible — and are
//!   slated to move into a kernel module (M1b). The `discharge` coupling is the
//!   cleanse escape-hatch's intended proof requirement (#1358), enumerated in
//!   [`MODULE_ALLOWLIST`].
//! - Text-based: it scans comments/strings too (a doc example naming
//!   `crate::enterprise::Foo` in a kernel file would redden it — a false positive
//!   in the SAFE direction). It does not resolve macro-generated paths.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The dedicated source files that make up the IFC kernel today (paths relative
/// to the crate root).
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

/// Intra-crate modules the kernel is allowed to depend on — itself.
const KERNEL_MODULES: &[&str] = &[
    "ifc_lattice",
    "flow",
    "ifc_api",
    "effect",
    "storage_lane",
    "extracted",
];

/// Non-kernel MODULES the kernel may name — INTENDED couplings, not erosion. Each
/// MUST still be referenced (asserted below) so a removed coupling forces removal
/// from this list.
///
/// - `discharge`: the human-authorized cleanse escape-hatch
///   (`SessionCleanseToken::authorize`) requires a `discharge::DischargedBundle`
///   as proof the policy pipeline ran (#1358). This is a deliberate dependency of
///   a privileged declassification on the enforcement pipeline's proof — not a
///   leak. (A sealed-trait inversion was tried and rejected: it widened in-crate
///   token-minting authority and would not survive the M3 crate split.)
const MODULE_ALLOWLIST: &[&str] = &["discharge"];

/// Crate-root items (types/fns) DEFINED in a kernel file (`ifc_lattice.rs`) and
/// referenced by other kernel files via the crate-root re-export. These are
/// kernel-internal, so `crate::IFCLabel` etc. are allowed.
const KERNEL_ROOT_PRIMITIVES: &[&str] = &[
    "ConfLevel",
    "IntegLevel",
    "AuthorityLevel",
    "ProvenanceSet",
    "Freshness",
    "DerivationClass",
    "IFCLabel",
];

/// Crate-root items the kernel depends on that STILL live in `lib.rs` (not yet a
/// kernel file). Enumerated so they are tracked, not invisible; slated to move
/// into a kernel module (M1b). Each MUST still be referenced (asserted below).
const ROOT_RESIDUALS: &[&str] = &["Operation", "SinkClass", "is_exfil_operation"];

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
    let mod_allow: BTreeSet<&str> = MODULE_ALLOWLIST.iter().copied().collect();
    let root_primitives: BTreeSet<&str> = KERNEL_ROOT_PRIMITIVES.iter().copied().collect();
    let root_residuals: BTreeSet<&str> = ROOT_RESIDUALS.iter().copied().collect();

    // Sanity: kernel module names and the module allowlist must be real modules.
    for m in KERNEL_MODULES.iter().chain(MODULE_ALLOWLIST) {
        assert!(
            declared.contains(*m),
            "ratchet config names module `{m}`, which is not declared in lib.rs"
        );
    }

    let mut violations: Vec<String> = Vec::new();
    let mut allow_seen: BTreeSet<&str> = BTreeSet::new();

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
                // It's a module path: must be a kernel module or an allowlisted coupling.
                if kernel_mods.contains(seg.as_str()) {
                    // ok
                } else if let Some(m) = mod_allow.get(seg.as_str()) {
                    allow_seen.insert(*m);
                } else {
                    violations.push(format!("{rel} depends on non-kernel module `crate::{seg}`"));
                }
            } else {
                // It's a crate-ROOT item: must be a kernel primitive or a tracked residual.
                if root_primitives.contains(seg.as_str()) {
                    // ok — defined in a kernel file, re-exported at the root
                } else if let Some(r) = root_residuals.get(seg.as_str()) {
                    allow_seen.insert(*r);
                } else {
                    violations.push(format!(
                        "{rel} depends on un-enumerated crate-root item `crate::{seg}` — if it is \
                         a kernel primitive add it to KERNEL_ROOT_PRIMITIVES, if it is a residual \
                         in lib.rs add it to ROOT_RESIDUALS, otherwise keep it out of the kernel"
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "MVK boundary violated — the IFC kernel reached into non-kernel code:\n{}",
        violations.join("\n")
    );

    // Keep the allowlists honest: an entry no longer referenced is stale and must
    // be deleted (its decoupling/extraction rung is done).
    for entry in MODULE_ALLOWLIST.iter().chain(ROOT_RESIDUALS) {
        assert!(
            allow_seen.contains(entry),
            "allowlisted entry `{entry}` is no longer referenced by any kernel file — \
             its decoupling/extraction is complete; remove it from MODULE_ALLOWLIST/ROOT_RESIDUALS."
        );
    }
}
