//! `cargo xtask workspace-members` — a crate outside the workspace is invisible to every
//! gate that says `--workspace`.
//!
//! `Cargo.toml` lists members explicitly rather than by glob, so a new crate joins the
//! workspace only when someone remembers to add it. Forget, and the crate still compiles
//! locally, still has tests, still looks like part of the repository — and is reached by
//! none of `cargo clippy --workspace`, `cargo test --workspace`, the totality census, the
//! dead-code ratchet or the line ratchet's build. **Nothing fails.** That is the whole
//! difficulty: the evidence of the mistake is the absence of evidence.
//!
//! # The rule
//!
//! Every `crates/*/Cargo.toml` is a workspace member, or a deliberate `exclude` entry. There
//! is no third state, and today there is one crate in it.
//!
//! Measured 2026-09-12: 87 crate directories, 82 members, 5 non-members — four of them in
//! `exclude` with the reason beside them (WASM-only, Leptos CSR, Python bindings via maturin,
//! a RISC-V zkVM guest) and `crates/nucleus-policy` in neither list.
//!
//! # Why the membership is asked of CARGO
//!
//! Not of a regex over `Cargo.toml`. Writing this gate, a hand-rolled scan of the `members`
//! array found 48 of the 82 and reported thirty real members as undeclared — the same shape
//! as gatehouse F-144, a population verified with the class of tool whose failure mode is
//! matching less than you meant. `cargo metadata` is cargo's own answer to the question, so
//! it cannot disagree with the build for a reason this gate invented.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// A scan finding far fewer has stopped reading the tree. Measured 2026-09-12: 87.
const MIN_DIRS: usize = 60;

/// Directory names under `crates/` that hold a `Cargo.toml`.
pub fn crate_dirs(root: &Path) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let dir = root.join("crates");
    for e in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let p = e?.path();
        if p.is_dir() && p.join("Cargo.toml").is_file() {
            if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                out.insert(n.to_string());
            }
        }
    }
    Ok(out)
}

/// The `exclude = [...]` entries naming a path under `crates/`.
pub fn excluded(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(start) = manifest.find("\nexclude = [") else {
        return out;
    };
    let rest = &manifest[start..];
    let Some(end) = rest.find("\n]") else {
        return out;
    };
    for line in rest[..end].lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        // `"crates/name",  # why` — the quoted path, whatever follows it.
        if let Some(q1) = t.find('"')
            && let Some(q2) = t[q1 + 1..].find('"')
        {
            let path = &t[q1 + 1..q1 + 1 + q2];
            if let Some(name) = path.strip_prefix("crates/") {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// Member crate directories, asked of cargo rather than parsed.
fn members(root: &Path) -> Result<BTreeSet<String>> {
    let out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = BTreeSet::new();
    // `"manifest_path":"/…/crates/<name>/Cargo.toml"`, without taking a json dependency.
    let mut i = 0usize;
    while let Some(hit) = text[i..].find("/crates/") {
        let s = i + hit + "/crates/".len();
        let Some(slash) = text[s..].find('/') else {
            break;
        };
        let name = &text[s..s + slash];
        if text[s + slash..].starts_with("/Cargo.toml") {
            set.insert(name.to_string());
        }
        i = s + slash;
    }
    Ok(set)
}

pub fn check(root: &Path) -> Result<()> {
    let dirs = crate_dirs(root)?;
    if dirs.len() < MIN_DIRS {
        bail!(
            "found {} crate director(ies) under crates/, floor {MIN_DIRS} — the scan is wrong",
            dirs.len()
        );
    }
    let members = members(root)?;
    if members.is_empty() {
        bail!("cargo metadata reported no member under crates/ — nothing to compare against");
    }
    let manifest = fs::read_to_string(root.join("Cargo.toml")).context("reading Cargo.toml")?;
    let excluded = excluded(&manifest);

    let mut failures = 0usize;
    for d in &dirs {
        if members.contains(d) || excluded.contains(d) {
            continue;
        }
        println!("  FAIL  crates/{d} is neither a workspace member nor an `exclude` entry.");
        println!(
            "        Nothing builds it: `cargo clippy --workspace`, `cargo test --workspace`,\n\
             \x20       the totality census and the dead-code ratchet all range over members.\n\
             \x20       Add it to `members` if it is code this repository owns, or to `exclude`\n\
             \x20       with the reason beside it if it is built another way."
        );
        failures += 1;
    }

    // A stale `exclude` entry names a directory that is not there — an exemption for a crate
    // nobody has, which reads like a live decision.
    for e in &excluded {
        if !dirs.contains(e) {
            println!(
                "  FAIL  Cargo.toml excludes crates/{e}, and no such directory exists. A stale \
                 exclusion reads as a deliberate choice about something that is gone."
            );
            failures += 1;
        }
    }

    if failures > 0 {
        bail!("{failures} crate(s) outside both lists");
    }
    println!(
        "ok: {} crate director(ies); {} members, {} excluded by decision, none unaccounted",
        dirs.len(),
        dirs.len() - excluded.len(),
        excluded.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_entries_are_read_with_their_reasons() {
        let m = "\nexclude = [\n    \"crates/a\",       # WASM-only\n    # a comment line\n    \"sdks/b\",         # not under crates/\n    \"crates/c\",\n]\n";
        let e = excluded(m);
        assert!(e.contains("a"), "{e:?}");
        assert!(e.contains("c"), "{e:?}");
        assert!(!e.contains("b"), "a non-crates path leaked in: {e:?}");
        assert_eq!(e.len(), 2, "{e:?}");
    }

    #[test]
    fn a_missing_exclude_section_is_not_a_crash() {
        assert!(excluded("[workspace]\nmembers = [\"crates/a\"]\n").is_empty());
    }

    /// The shipped tree, read the way the gate reads it.
    #[test]
    fn the_scan_reaches_the_crates_directory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let d = crate_dirs(&root).expect("crates/ is readable");
        assert!(d.len() >= MIN_DIRS, "found {} crate dir(s)", d.len());
        assert!(
            d.contains("xtask"),
            "this crate is not in its own scan: {d:?}"
        );
    }

    /// Every `exclude` entry must name a directory that exists — checked here as well as in
    /// the gate, because a stale exemption is the failure this file is least likely to notice.
    #[test]
    fn no_exclude_entry_is_stale() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let d = crate_dirs(&root).expect("crates/ is readable");
        let m = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
        for e in excluded(&m) {
            assert!(
                d.contains(&e),
                "Cargo.toml excludes crates/{e}, which is not there"
            );
        }
    }
}
