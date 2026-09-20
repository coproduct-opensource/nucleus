//! `cargo xtask visibility` — nucleus depends on nothing private.
//!
//! [ADR 0008](../../../docs/adr/0008-the-public-private-line.md) states the rule this gate
//! decides: the dependency arrow between this repository and the private repositories built
//! on it is one-way. A private repository may depend on nucleus by version or by rev.
//! Nucleus depends on nothing private — no `git` dependency, no alternate registry, no path
//! dependency escaping the repository.
//!
//! # Why the property needs a gate at all
//!
//! It holds today, and it holds by habit. That is exactly the shape this repository has
//! learned to distrust: the evidence of the mistake would be the absence of evidence. A
//! single `git = "https://github.com/coproduct-private/…"` in one manifest compiles, tests,
//! reds no existing gate, and quietly makes a public build unreproducible for anyone outside
//! the org — the failure is discovered by a stranger cloning the repo, which is the worst
//! possible discovery channel for an open-core promise.
//!
//! # Why it takes both halves
//!
//! The gate reads the resolved graph **and** every manifest, because neither alone decides
//! the question.
//!
//! Manifests alone are not enough, and the first run of this gate proved it. The tempting
//! argument is that crates.io forbids a published package from declaring a `git` or `path`
//! dependency, so a non-registry source could only ever be declared here. That argument
//! holds for registry packages and fails for git ones: a git-sourced crate is not published,
//! so it may declare whatever it likes. `dlc-d` pulls `dlc-d-macro` from the same repository,
//! and no manifest in this tree names it. Only `cargo metadata` sees it.
//!
//! The graph alone is not enough either: `cargo metadata` at the root resolves the root
//! workspace, and this repository contains thirteen more. A satellite could declare anything
//! and the root query would never look.
//!
//! So: `cargo metadata` for the graph it resolves — cargo's own answer, which cannot disagree
//! with the build for a reason this gate invented (the lesson of `workspace_members.rs`) —
//! plus a manifest sweep that reaches every workspace in the repository.
//!
//! # A-19
//!
//! Driven red before it was trusted green, on 2026-09-20: a
//! `git = "https://github.com/coproduct-private/spiffy.git"` dependency added to
//! `tools/nucleus-observed-lint`'s `[dependencies]` — a satellite, so the root graph query
//! still succeeds and only the manifest sweep can see it — produced
//! `FAIL … declares spiffy-hub: git dependency on …` and a non-zero exit; removing it
//! restored the green line. The first placement of that probe landed in
//! `[package.metadata.rust-analyzer]` and was correctly *not* flagged, which is the reason
//! `every_dependency_table_is_read` exists.
//!
//! # The satellites
//!
//! Thirteen directories under this repository carry their own `[workspace]` — the dylint
//! passes, the zkVM guest, the fuzz targets, and three standalone examples whose dependency
//! trees are deliberately kept out of the main build. A new one would escape a root-level
//! check entirely, so the gate pins the set: a workspace root that is not in
//! `DECLARED_SATELLITES` fails until someone lists it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The only source a dependency of this repository may resolve to, besides the tree itself.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Standalone `[workspace]` roots, relative to the repository root. Each is outside the main
/// build on purpose; each is still part of this repository and still bound by ADR 0008, so
/// each is swept. A root that is not listed here fails the gate: an unlisted satellite is a
/// place the rule would not be checked.
const DECLARED_SATELLITES: &[&str] = &[
    "crates/portcullis-zkvm-guest",
    "examples/a2a-server",
    "examples/marketplace-live",
    "examples/x402-sepolia",
    "fuzz",
    "tools/nucleus-cb4a-lint",
    "tools/nucleus-egress-lint",
    "tools/nucleus-guarantee-lint",
    "tools/nucleus-identity-lint",
    "tools/nucleus-mediation-lint",
    "tools/nucleus-observed-lint",
    "tools/nucleus-preimage-lint",
    "tools/nucleus-rest-pattern-lint",
];

/// A resolved graph far smaller than the real one has stopped reading. Measured 2026-09-20:
/// the root workspace resolves well over a thousand packages.
const MIN_PACKAGES: usize = 300;

/// Git dependencies this repository is allowed to declare, named one by one.
///
/// ADR 0008's rule is that nucleus depends on nothing **private**. A git dependency on a
/// public sibling does not cross that line, but it is not free either: it makes a build
/// depend on a host rather than on crates.io, and a repository that is public today can be
/// made private tomorrow without anything here changing. So they are permitted and
/// *enumerated* — adding one is a deliberate edit to this list, and the list is short enough
/// to re-verify by hand.
///
/// Each entry is `(crate name, repository URL)`. Both must match. Measured 2026-09-20: five
/// names across two upstreams — four declared by manifests here, one reached transitively.
const PUBLIC_GIT_UPSTREAMS: &[(&str, &str)] = &[
    // The Delegation Logic Calculus: proof-term vocabulary (`dlc-core`), its decision
    // procedure (`dlc-d`) and its signature layer (`dlc-crypto`), used by
    // `nucleus-policy-cert`, `portcullis` and `nucleus-tool-proxy`.
    // `coproduct-opensource/delegation_calc` is public, is not on crates.io, and every
    // dependency on it is pinned by rev.
    ("dlc-core", DELEGATION_CALC),
    ("dlc-crypto", DELEGATION_CALC),
    ("dlc-d", DELEGATION_CALC),
    // Declared by `dlc-d`, not by anything here — visible only in the resolved graph.
    ("dlc-d-macro", DELEGATION_CALC),
    // The dylint passes link against clippy's internals, which are deliberately unpublished;
    // there is no crates.io form of this dependency to move to. Each of the eight
    // `tools/nucleus-*-lint` satellites pins the same rev.
    ("clippy_utils", "https://github.com/rust-lang/rust-clippy"),
];

const DELEGATION_CALC: &str = "https://github.com/coproduct-opensource/delegation_calc.git";

/// Why one dependency declaration is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A `git = "…"` source that is not an enumerated public upstream.
    Git(String),
    /// An alternate registry. crates.io is the only one a public build may assume.
    Registry(String),
    /// A `path = "…"` that leaves the repository.
    EscapingPath(String),
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Git(u) => write!(f, "git dependency on {u}"),
            Self::Registry(r) => write!(f, "alternate registry {r}"),
            Self::EscapingPath(p) => write!(f, "path dependency escaping the repository: {p}"),
        }
    }
}

/// Every refused dependency declared by one manifest's TOML, named `name -> why`.
///
/// `manifest_dir` is where a relative `path` resolves from; `root` is the boundary it may not
/// cross. Walks every dependency table a manifest can carry, including
/// `[target.'cfg(…)'.dependencies]` and `[workspace.dependencies]`.
pub fn refused(
    toml_text: &str,
    manifest_dir: &Path,
    root: &Path,
) -> Result<Vec<(String, Verdict)>> {
    /// The three names a dependency table can have, wherever it is nested.
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

    let doc: toml::Value = toml::from_str(toml_text).context("parsing manifest TOML")?;
    let mut out = Vec::new();
    let mut tables: Vec<&toml::Value> = Vec::new();

    for kind in KINDS {
        if let Some(d) = doc.get(kind) {
            tables.push(d);
        }
        if let Some(d) = doc.get("workspace").and_then(|w| w.get(kind)) {
            tables.push(d);
        }
    }
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for (_cfg, spec) in targets {
            for kind in KINDS {
                if let Some(d) = spec.get(kind) {
                    tables.push(d);
                }
            }
        }
    }

    for table in tables {
        let Some(deps) = table.as_table() else {
            continue;
        };
        for (name, spec) in deps {
            let Some(spec) = spec.as_table() else {
                continue; // `serde = "1"` — a plain version is crates.io by definition.
            };
            if let Some(u) = spec.get("git").and_then(toml::Value::as_str)
                && !PUBLIC_GIT_UPSTREAMS
                    .iter()
                    .any(|(n, url)| n == name && *url == u)
            {
                out.push((name.clone(), Verdict::Git(u.to_string())));
            }
            if let Some(r) = spec.get("registry").and_then(toml::Value::as_str) {
                out.push((name.clone(), Verdict::Registry(r.to_string())));
            }
            if let Some(p) = spec.get("path").and_then(toml::Value::as_str)
                && escapes(manifest_dir, p, root)
            {
                out.push((name.clone(), Verdict::EscapingPath(p.to_string())));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Does `dir/rel` land outside `root`? Resolved lexically, so a path that does not exist yet
/// is still decided — a gate that only refused paths present on disk would pass on the very
/// commit that introduces one.
fn escapes(dir: &Path, rel: &str, root: &Path) -> bool {
    let mut parts: Vec<std::ffi::OsString> = dir
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    for c in Path::new(rel).components() {
        match c {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::CurDir => {}
            other => parts.push(other.as_os_str().to_os_string()),
        }
    }
    let joined: PathBuf = parts.iter().collect();
    !joined.starts_with(root)
}

/// Every `Cargo.toml` the repository **contains**, asked of git.
///
/// Not a directory walk. A walk found 25 workspace roots where there are 13, because a
/// developer's nested `git worktree` sitting in the tree looks exactly like a subdirectory —
/// and scratch checkouts, `target/`, and vendored trees all read as repository content. Git
/// knows which files are the repository's; nothing else in the working copy does, and a gate
/// whose population depends on what happens to be lying around is a gate whose verdict
/// changes between two clones of the same commit.
pub fn manifests(root: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", "*Cargo.toml", "Cargo.toml"])
        .current_dir(root)
        .output()
        .context("running git ls-files")?;
    if !out.status.success() {
        bail!(
            "git ls-files failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut paths: Vec<PathBuf> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|rel| root.join(rel))
        .filter(|p| p.file_name().is_some_and(|n| n == "Cargo.toml"))
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// The satellite `[workspace]` roots actually present, relative to `root`.
pub fn satellites(root: &Path) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for m in manifests(root)? {
        if m.parent() == Some(root) {
            continue; // the root workspace itself
        }
        let text = fs::read_to_string(&m).with_context(|| format!("reading {}", m.display()))?;
        let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        // A bare `[workspace]` with no `members` is the idiom every satellite here uses: it
        // detaches the crate from the parent workspace. Requiring `members` would miss all
        // twelve of them, so the table's presence is what counts.
        if doc.get("workspace").is_some()
            && let Some(parent) = m.parent()
            && let Ok(rel) = parent.strip_prefix(root)
        {
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(out)
}

/// The sources every package in the root workspace's resolved graph came from.
///
/// Asked of cargo rather than reconstructed, for the reason `workspace_members.rs` records:
/// cargo's answer cannot disagree with the build.
fn resolved_sources(root: &Path) -> Result<Vec<(String, Option<String>)>> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--locked"])
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
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parsing cargo metadata JSON")?;
    let packages = meta
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .context("cargo metadata carried no `packages` array")?;
    Ok(packages
        .iter()
        .map(|p| {
            let name = p
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_string();
            let source = p
                .get("source")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            (name, source)
        })
        .collect())
}

pub fn check(root: &Path) -> Result<()> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut failures = 0usize;

    // 1. The resolved graph of the main workspace, per cargo.
    let sources = resolved_sources(&root)?;
    if sources.len() < MIN_PACKAGES {
        bail!(
            "cargo metadata resolved {} package(s), floor {MIN_PACKAGES} — the scan is wrong",
            sources.len()
        );
    }
    for (name, source) in &sources {
        match source.as_deref() {
            None | Some(CRATES_IO) => {}
            // The same enumerated public upstreams the manifest sweep allows. Matched on the
            // URL cargo records, which carries the `?rev=` and `#sha` the manifest pinned.
            Some(g)
                if g.strip_prefix("git+").is_some_and(|u| {
                    PUBLIC_GIT_UPSTREAMS
                        .iter()
                        .any(|(n, url)| n == name && u.starts_with(url))
                }) => {}
            Some(other) => {
                println!("  FAIL  {name} resolves to {other}");
                println!(
                    "        ADR 0008: nucleus depends on nothing private. A public clone must\n\
                     \x20       build from crates.io and this tree alone."
                );
                failures += 1;
            }
        }
    }

    // 2. Every manifest's own declarations — the satellites included.
    let found = satellites(&root)?;
    let declared: BTreeSet<String> = DECLARED_SATELLITES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for s in found.difference(&declared) {
        println!("  FAIL  {s}/Cargo.toml is a `[workspace]` root this gate does not know about.");
        println!(
            "        An unlisted satellite is a place ADR 0008 would not be checked. Add it to\n\
             \x20       DECLARED_SATELLITES, or fold the crate into the main workspace."
        );
        failures += 1;
    }
    for s in declared.difference(&found) {
        println!(
            "  FAIL  DECLARED_SATELLITES names {s}, which is not a workspace root here. A stale \
             entry reads as a live decision about something that is gone."
        );
        failures += 1;
    }

    let all = manifests(&root)?;
    for m in &all {
        let text = fs::read_to_string(m).with_context(|| format!("reading {}", m.display()))?;
        let dir = m.parent().unwrap_or(&root);
        for (name, why) in refused(&text, dir, &root)? {
            let rel = m.strip_prefix(&root).unwrap_or(m).display();
            println!("  FAIL  {rel} declares {name}: {why}");
            failures += 1;
        }
    }

    if failures > 0 {
        bail!("{failures} dependency declaration(s) reach outside the public world");
    }
    println!(
        "ok: {} package(s) resolved, all crates.io or in-tree; {} manifest(s) across {} \
         workspace(s) declare no git, alternate-registry or escaping-path dependency",
        sources.len(),
        all.len(),
        found.len() + 1
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/repo";

    fn refuse(toml_text: &str) -> Vec<(String, Verdict)> {
        refused(toml_text, Path::new("/repo/crates/x"), Path::new(ROOT)).expect("parses")
    }

    /// The defect this gate exists for, in the shape it would actually arrive.
    #[test]
    fn a_private_git_dependency_is_refused() {
        let r = refuse(
            "[dependencies]\n\
             gatehouse = { git = \"https://github.com/coproduct-private/gatehouse.git\", rev = \"abc\" }\n",
        );
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(matches!(r[0].1, Verdict::Git(_)), "{r:?}");
    }

    /// A git dependency nobody enumerated is refused whether or not its far end is public —
    /// a repository that is public today can be made private tomorrow, and nothing in this
    /// tree would change when it happened.
    #[test]
    fn an_unenumerated_git_dependency_is_refused_even_when_public() {
        let r = refuse("[dependencies]\nfoo = { git = \"https://github.com/rust-lang/foo\" }\n");
        assert_eq!(r.len(), 1, "{r:?}");
    }

    /// The enumerated public upstream passes — and only under its own name and URL, so the
    /// allowance cannot be borrowed by a second dependency pointed somewhere else.
    #[test]
    fn an_enumerated_public_upstream_is_allowed_only_as_itself() {
        let (name, url) = PUBLIC_GIT_UPSTREAMS[0];
        assert!(
            refuse(&format!(
                "[dependencies]\n{name} = {{ git = \"{url}\", rev = \"abc\" }}\n"
            ))
            .is_empty(),
            "the enumerated upstream was refused"
        );
        assert_eq!(
            refuse(&format!(
                "[dependencies]\n{name} = {{ git = \"https://github.com/elsewhere/x.git\" }}\n"
            ))
            .len(),
            1,
            "the name alone bought an allowance"
        );
        assert_eq!(
            refuse(&format!("[dependencies]\nother = {{ git = \"{url}\" }}\n")).len(),
            1,
            "the URL alone bought an allowance"
        );
    }

    #[test]
    fn an_alternate_registry_is_refused() {
        let r = refuse("[dependencies]\nfoo = { version = \"1\", registry = \"internal\" }\n");
        assert!(matches!(r[0].1, Verdict::Registry(_)), "{r:?}");
    }

    #[test]
    fn an_in_tree_path_dependency_is_fine() {
        assert!(refuse("[dependencies]\nck-types = { path = \"../ck-types\" }\n").is_empty());
    }

    #[test]
    fn a_path_leaving_the_repository_is_refused() {
        let r = refuse("[dependencies]\nplat = { path = \"../../../spiffy/crates/x\" }\n");
        assert!(matches!(r[0].1, Verdict::EscapingPath(_)), "{r:?}");
    }

    /// The historical shape from the sibling repos: a path dep on a tree that is not there.
    /// It must be refused on declaration, not on whether the directory happens to exist.
    #[test]
    fn an_escaping_path_is_decided_without_touching_the_disk() {
        assert!(escapes(
            Path::new("/repo/crates/x"),
            "../../../nucleus-platform/vendor/nucleus-lineage",
            Path::new(ROOT)
        ));
        assert!(!escapes(
            Path::new("/repo/crates/x"),
            "../ck-types",
            Path::new(ROOT)
        ));
    }

    #[test]
    fn plain_version_dependencies_are_not_flagged() {
        assert!(refuse("[dependencies]\nserde = \"1\"\nanyhow = \"1\"\n").is_empty());
    }

    /// Dev, build and target tables are dependency tables too — a gate that read only
    /// `[dependencies]` would pass a tree that builds against a private repo in CI.
    #[test]
    fn every_dependency_table_is_read() {
        let r = refuse(
            "[dev-dependencies]\n\
             a = { git = \"https://x/a\" }\n\
             [build-dependencies]\n\
             b = { git = \"https://x/b\" }\n\
             [target.'cfg(unix)'.dependencies]\n\
             c = { git = \"https://x/c\" }\n\
             [workspace.dependencies]\n\
             d = { git = \"https://x/d\" }\n",
        );
        let names: Vec<&str> = r.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["a", "b", "c", "d"], "{r:?}");
    }

    /// The shipped tree, read the way the gate reads it.
    #[test]
    fn the_scan_reaches_the_repository() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = root.canonicalize().expect("repo root");
        let m = manifests(&root).expect("manifests are readable");
        assert!(m.len() > 60, "found {} manifest(s)", m.len());
        assert!(
            m.iter().any(|p| p.ends_with("crates/xtask/Cargo.toml")),
            "this crate is not in its own scan"
        );
    }

    /// Non-vacuity for the satellite pin: the declared list must match the tree exactly, in
    /// both directions, or the sweep silently narrows.
    #[test]
    fn the_declared_satellites_are_exactly_the_ones_present() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = root.canonicalize().expect("repo root");
        let found = satellites(&root).expect("satellites are readable");
        let declared: BTreeSet<String> = DECLARED_SATELLITES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(found, declared, "satellite workspaces drifted");
    }

    /// The property ADR 0008 asserts, over the tree as it stands.
    #[test]
    fn no_manifest_in_this_repository_reaches_outside() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = root.canonicalize().expect("repo root");
        for m in manifests(&root).expect("manifests") {
            let text = fs::read_to_string(&m).expect("readable");
            let dir = m.parent().expect("parent");
            let r = refused(&text, dir, &root).expect("parses");
            assert!(r.is_empty(), "{}: {r:?}", m.display());
        }
    }
}
