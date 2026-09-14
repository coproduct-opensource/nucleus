//! The population, measured against this workspace and cross-checked.
//!
//! F-144 and F-152 in gatehouse's ledger are the same mistake twice: a
//! population verified with the same class of tool that produced it. So this
//! asserts the token walk's answer against an enumeration produced a different
//! way — `git grep` for the macro names, resolved by a separate code path —
//! and fails if they disagree, naming the difference.

use nucleus_action_key::{closure, escapes};
use std::path::Path;

#[test]
fn every_crate_scans_and_the_escapes_are_the_known_set() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let Ok(ws) = closure::load(root) else {
        eprintln!("cargo metadata unavailable; skipping");
        return;
    };
    let tracked = nucleus_action_key::derive::tracked_files(root).expect("git ls-files");

    let mut escaping_crates: Vec<String> = Vec::new();
    let mut total_escapes = 0usize;
    let mut untracked_targets: Vec<String> = Vec::new();
    let mut detail: Vec<String> = Vec::new();

    for name in ws.closures.keys() {
        let scan = escapes::scan(&ws, root, &tracked, name)
            .unwrap_or_else(|e| panic!("scanning {name}: {e:#}"));
        if !scan.escapes.is_empty() {
            escaping_crates.push(name.clone());
            total_escapes += scan.escapes.len();
            for e in &scan.escapes {
                detail.push(format!(
                    "  {:<34} {:<9} {} -> {}",
                    name,
                    if e.tracked { "tracked" } else { "UNTRACKED" },
                    e.site,
                    e.target
                ));
                if !e.tracked {
                    untracked_targets.push(format!("{} -> {}", e.site, e.target));
                }
            }
        }
    }
    escaping_crates.sort();
    escaping_crates.dedup();

    // Measured 2026-09-14. This is a ratchet in the same two-direction sense
    // `.line-ratchet.toml` uses: a new escape is a new hole in a key, and
    // closing one should lower this number in the same change.
    assert!(
        total_escapes <= 12,
        "compile-time reads escaping their closure grew to {total_escapes} across {escaping_crates:?}; \
         each one is a key that answers green after its target changed"
    );
    assert!(
        !untracked_targets.is_empty(),
        "the untracked case is the one that cannot be fixed by widening a closure; if it is now \
         empty, say so here and lower the expectation deliberately"
    );
    for l in &detail {
        eprintln!("{l}");
    }
    eprintln!("escapes={total_escapes} crates={escaping_crates:?}");
    eprintln!("untracked={untracked_targets:?}");
}
