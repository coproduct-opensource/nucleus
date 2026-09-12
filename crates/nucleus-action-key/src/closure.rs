//! The read-set a crate actually has, derived rather than declared.
//!
//! # Why this exists, when `derive` already computes a read-set
//!
//! [`crate::derive`] takes a job's `paths:` filter — a declaration, written by
//! hand, and only present on 11 of the 48 required contexts. The census names
//! the other 37, and the honest answer there was "someone has to declare what
//! these read".
//!
//! That answer was wrong, and this module is why. A Rust crate's read-set is
//! not a matter of opinion: it is the crate's own sources plus the sources of
//! every workspace crate it depends on, and `cargo metadata` already knows the
//! graph exactly. **Nothing has to be declared, so nothing can be declared
//! wrongly** — which is the one weakness the `paths:` key carries and the one
//! gatehouse's scope-as-oid was built to remove.
//!
//! # What it is worth, measured
//!
//! Over nucleus's last 39 first-parent merges to `main`, against 82 workspace
//! crates (2026-09-12):
//!
//! | | |
//! |---|---|
//! | merges affecting **zero** crates | **13 of 39 (33%)** |
//! | median crates affected | **1 of 82** |
//! | merges invalidating everything (`Cargo.lock` / toolchain) | 5 (13%) |
//!
//! A third of merges to `main` are CI-only — workflows, scripts, docs — and
//! every one of them currently rebuilds and re-tests all 82 crates in the merge
//! queue, because `ci.yml`'s `changed-crates` sets `all=true` for
//! `merge_group`. That is not a bug: a merge group is a new combination, and
//! narrowing it on the PR's diff would be unsound. A receipt keyed on a closure
//! is the thing that can narrow it soundly.
//!
//! This independently reproduces gatehouse's own figure — `docs/scope-fanout.md`
//! measured 37% of merged changes running zero gates under per-crate scopes, by
//! a different method.
//!
//! # What it does not claim
//!
//! The closure covers **workspace-internal** dependencies. A change to an
//! external crate moves `Cargo.lock`, which is in every closure, so the whole
//! workspace invalidates — correct, and the 13% above. It says nothing about a
//! crate reading a file at runtime that is not a source file of any crate:
//! `include_str!`, a fixture directory, a `build.rs` reading the tree. Those
//! are real and unmodelled, and the shadow lane is what would find them.

use crate::ReadEntry;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Files every crate's closure contains, because a change to one of them
/// changes what every crate compiles to.
const WORKSPACE_WIDE: &[&str] = &["Cargo.lock", "rust-toolchain.toml"];

/// The workspace's crates and the internal dependency graph between them.
#[derive(Debug, Default)]
pub struct Workspace {
    /// Crate name -> its directory, repo-relative.
    pub dirs: BTreeMap<String, String>,
    /// Crate name -> the workspace crates it depends on, transitively,
    /// including itself.
    pub closures: BTreeMap<String, BTreeSet<String>>,
}

/// Read the workspace graph from `cargo metadata`.
///
/// Shelling out rather than linking `cargo_metadata`: the same choice
/// [`crate::derive`] makes for `git ls-files`, and for the same reason — the
/// authority on the graph is cargo, not a reimplementation of it here.
pub fn load(root: &Path) -> Result<Workspace> {
    let out = std::process::Command::new("cargo")
        .arg("metadata")
        .args(["--format-version", "1", "--all-features"])
        .current_dir(root)
        .output()
        .context("running `cargo metadata`")?;
    anyhow::ensure!(
        out.status.success(),
        "`cargo metadata` failed in {root:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parsing cargo metadata")?;
    from_metadata(&meta, root)
}

/// The pure half, so the graph logic is testable from a fixture rather than
/// from whatever this workspace happens to contain today.
pub fn from_metadata(meta: &serde_json::Value, root: &Path) -> Result<Workspace> {
    // Resolve the root once: see the note on `strip_prefix` below.
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let members: BTreeSet<&str> = meta
        .get("workspace_members")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    anyhow::ensure!(
        !members.is_empty(),
        "cargo metadata listed no workspace members: a closure over nothing is not a read-set"
    );

    // id -> name, and id -> directory.
    let mut name_of: BTreeMap<&str, String> = BTreeMap::new();
    let mut dirs: BTreeMap<String, String> = BTreeMap::new();
    for pkg in meta
        .get("packages")
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let (Some(id), Some(name), Some(mp)) = (
            pkg.get("id").and_then(|v| v.as_str()),
            pkg.get("name").and_then(|v| v.as_str()),
            pkg.get("manifest_path").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        if !members.contains(id) {
            continue;
        }
        name_of.insert(id, name.to_string());
        let dir = Path::new(mp).parent().unwrap_or(Path::new("."));
        // Both sides canonicalized. Cargo reports `manifest_path` resolved, and
        // on macOS `/var` is a symlink to `/private/var` — so a tempdir root
        // arrives as `/var/...` while cargo says `/private/var/...`, and a bare
        // `strip_prefix` silently fails. It does not error: it leaves the path
        // ABSOLUTE, the prefix match against repo-relative filenames then finds
        // nothing, and every crate's read-set quietly collapses to the two
        // workspace-wide files. A key over almost nothing still looks like a
        // key, which is why this is a refusal rather than a fallback.
        let rel = dir
            .strip_prefix(&canonical_root)
            .or_else(|_| dir.strip_prefix(root))
            .map_err(|_| {
                anyhow::anyhow!(
                    "crate {name}'s manifest at {} is not under the workspace root {}: a \
                     read-set derived from it would silently be empty",
                    dir.display(),
                    canonical_root.display()
                )
            })?;
        dirs.insert(name.to_string(), rel.to_string_lossy().replace('\\', "/"));
    }

    // The resolved graph, restricted to workspace members.
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in meta
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(|n| n.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(id) = node.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if !members.contains(id) {
            continue;
        }
        let deps = node
            .get("deps")
            .and_then(|d| d.as_array())
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|d| d.get("pkg").and_then(|v| v.as_str()))
            .filter(|p| members.contains(p))
            .collect();
        edges.insert(id, deps);
    }

    let mut closures = BTreeMap::new();
    for id in &members {
        let Some(name) = name_of.get(id) else {
            continue;
        };
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        walk(id, &edges, &mut seen);
        let names = seen
            .iter()
            .filter_map(|i| name_of.get(i).cloned())
            .collect::<BTreeSet<String>>();
        closures.insert(name.clone(), names);
    }
    Ok(Workspace { dirs, closures })
}

/// Depth-first over the internal graph. Iterative, so a dependency cycle — which
/// cargo forbids but a fixture can express — cannot blow the stack.
fn walk<'a>(start: &'a str, edges: &BTreeMap<&'a str, Vec<&'a str>>, seen: &mut BTreeSet<&'a str>) {
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(deps) = edges.get(id) {
            stack.extend(deps.iter().copied());
        }
    }
}

impl Workspace {
    /// The read-set for one crate: every tracked file under each closure
    /// member's directory, plus the workspace-wide files.
    ///
    /// `tracked` is the repository's tracked-file list, passed in rather than
    /// re-read per crate — this is called once per crate and `git ls-files`
    /// over a large tree is not free.
    pub fn read_set(
        &self,
        root: &Path,
        tracked: &[String],
        crate_name: &str,
    ) -> Result<Vec<ReadEntry>> {
        let Some(members) = self.closures.get(crate_name) else {
            anyhow::bail!("{crate_name} is not a workspace crate");
        };
        let prefixes: Vec<String> = members
            .iter()
            .filter_map(|m| self.dirs.get(m))
            .map(|d| format!("{d}/"))
            .collect();

        let mut out = Vec::new();
        for f in tracked {
            let wide = WORKSPACE_WIDE.contains(&f.as_str());
            if !wide && !prefixes.iter().any(|p| f.starts_with(p.as_str())) {
                continue;
            }
            out.push(ReadEntry {
                path: f.clone(),
                digest: digest_of(root, f)?,
            });
        }
        out.sort();
        Ok(out)
    }
}

fn digest_of(root: &Path, rel: &str) -> Result<[u8; 32]> {
    let bytes = std::fs::read(root.join(rel)).with_context(|| format!("reading {rel}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&bytes));
    Ok(out)
}

/// The action key for `cargo <gate> -p <crate>`.
///
/// Same absorption as [`crate::ActionKey::derive`] — tagged, length-prefixed,
/// no `Debug` — with the crate's closure standing where a job's `paths:` filter
/// would. The gate's own code and the toolchain still enter it: a weakened gate
/// must not answer green from its stronger self's history, and the same clippy
/// under two compilers is two gates.
pub fn key_for_crate(
    ws: &Workspace,
    root: &Path,
    tracked: &[String],
    crate_name: &str,
    gate: &str,
    gate_files: &[ReadEntry],
) -> Result<crate::ActionKey> {
    let read_set = ws.read_set(root, tracked, crate_name)?;
    Ok(crate::ActionKey::derive(&crate::Inputs {
        // The context is the (gate, crate) pair: `clippy` over `portcullis` is
        // a different obligation from `clippy` over `nucleus-node`, and a key
        // that conflated them would answer one with the other's receipt.
        context: format!("{gate}::{crate_name}"),
        read_set,
        gate: gate_files.to_vec(),
        toolchain: Vec::new(),
    }))
}
