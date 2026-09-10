//! `cargo xtask pin-parity` — one fact, written many times, must have one value.
//!
//! This repo already holds the doctrine. `ci/release-builds-rootfs-inputs.sh:17`:
//! *"Two lists that must agree, in two files, is exactly the shape that drifts."*
//! `ci/docker-rust-matches-msrv.sh:15`: *"Two facts in two files that must agree"*.
//! `ci/merge-group-scope-parity.sh` keeps a path predicate equal to its own copy, and
//! `line-ratchet.yml` was given one shared parser after two hand-rolled ones read
//! different field sets. Five pairs are gated that way.
//!
//! These are not. Each is a version — in one case a version **and its checksum** —
//! copied across many files with nothing asserting the copies agree:
//!
//! | fact | copies | why a split hurts |
//! |---|---|---|
//! | elan release + its SHA-256 | 12 workflows, ~36 lines | a stale copy is a supply-chain hazard, not just drift |
//! | `AENEAS_RELEASE`, `CHARON_NIGHTLY` | 6 workflows, 12 lines | a partial bump splits the extraction fleet, and the halves disagree about generated Lean |
//! | first-party `lean-toolchain` | 9 files | two Lean versions cannot share a `.lake` cache |
//!
//! **All three agree today.** That is the point of gating them now: the cost of the gate
//! is lowest while it is green, and each is one hurried edit away from splitting. The
//! `.lake/packages/**` copies are deliberately excluded — those are upstream packages'
//! own toolchains, and they legitimately differ (`axiom-audit` is on v4.32.0-rc1,
//! `LeanSearchClient` on v4.27.0-rc1). Gating them would be gating someone else's choice.
//!
//! # What decides this
//!
//! Committed workflow YAML and committed `lean-toolchain` files. No `crates/**` source, no
//! toolchain, no network. Same class as `gatehouse-pin` — see gatehouse `docs/tiering.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// One fact that appears in several files and must have a single value.
struct Fact {
    /// What the fact is, for the failure message.
    name: &'static str,
    /// Why a split is worse than untidy.
    stake: &'static str,
    /// Occurrences as (file, value).
    sightings: Vec<(PathBuf, String)>,
}

impl Fact {
    fn distinct(&self) -> BTreeMap<&str, Vec<&Path>> {
        let mut by_value: BTreeMap<&str, Vec<&Path>> = BTreeMap::new();
        for (path, value) in &self.sightings {
            by_value.entry(value.as_str()).or_default().push(path);
        }
        by_value
    }
}

fn workflows(root: &Path) -> Result<Vec<PathBuf>> {
    let dir = root.join(".github/workflows");
    let mut out: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect();
    out.sort();
    Ok(out)
}

/// Everything between `marker` and the next whitespace or `delim`, per line.
fn scan(text: &str, marker: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        while let Some(i) = rest.find(marker) {
            let after = &rest[i + marker.len()..];
            let end = after.find(delim).unwrap_or(after.len());
            let v = after[..end].trim().trim_matches('"').trim_matches('\'');
            if !v.is_empty() {
                out.push(v.to_string());
            }
            rest = &after[end.min(after.len())..];
        }
    }
    out
}

/// First-party `lean-toolchain` files: ours, not our dependencies'.
fn first_party_toolchains(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // `.lake/packages/**` holds upstream packages, each pinning its OWN Lean. Those
            // differ on purpose and are not ours to reconcile. Skip dot-dirs, build output,
            // and any separate checkout (a worktree carries a `.git` FILE).
            if name.starts_with('.')
                || matches!(name, "target" | "node_modules" | "vendor")
                || path.join(".git").exists()
            {
                continue;
            }
            first_party_toolchains(&path, out)?;
        } else if name == "lean-toolchain" {
            out.push(path);
        }
    }
    Ok(())
}

fn collect(root: &Path) -> Result<Vec<Fact>> {
    let wfs = workflows(root)?;
    let mut elan_version = Fact {
        name: "elan release",
        stake: "the version whose checksum is pinned beside it",
        sightings: Vec::new(),
    };
    let mut elan_sha = Fact {
        name: "elan tarball SHA-256",
        stake: "a stale checksum next to a bumped version fails closed; a stale PAIR does not",
        sightings: Vec::new(),
    };
    let mut aeneas = Fact {
        name: "AENEAS_RELEASE",
        stake: "two aeneas releases generate different Lean from the same Rust",
        sightings: Vec::new(),
    };
    let mut charon = Fact {
        name: "CHARON_NIGHTLY",
        stake: "charon and aeneas are extracted as a pair; splitting them splits the fleet",
        sightings: Vec::new(),
    };

    for path in &wfs {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        for v in scan(&text, "elan/releases/download/", '/') {
            elan_version.sightings.push((path.clone(), v));
        }
        // The checksum line is `echo "<64 hex>  /tmp/elan.tar.gz" | sha256sum -c -`.
        for line in text.lines() {
            if line.contains("/tmp/elan.tar.gz") && line.contains("sha256sum") {
                if let Some(h) = line
                    .split('"')
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                {
                    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                        elan_sha.sightings.push((path.clone(), h.to_string()));
                    }
                }
            }
        }
        for (fact, key) in [
            (&mut aeneas, "AENEAS_RELEASE:"),
            (&mut charon, "CHARON_NIGHTLY:"),
        ] {
            for line in text.lines() {
                let t = line.trim();
                if let Some(v) = t.strip_prefix(key) {
                    // A comment mentioning the key is not a declaration of it.
                    if !t.starts_with('#') {
                        fact.sightings
                            .push((path.clone(), v.trim().trim_matches('"').to_string()));
                    }
                }
            }
        }
    }

    let mut toolchains = Vec::new();
    first_party_toolchains(root, &mut toolchains)?;
    toolchains.sort();
    let mut lean = Fact {
        name: "first-party lean-toolchain",
        stake: "two Lean versions cannot share a .lake cache, and the second one rebuilds everything",
        sightings: Vec::new(),
    };
    for path in toolchains {
        let v = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?
            .trim()
            .to_string();
        lean.sightings.push((path, v));
    }

    Ok(vec![elan_version, elan_sha, aeneas, charon, lean])
}

pub fn check(root: &Path) -> Result<()> {
    let facts = collect(root)?;
    let mut split = 0usize;

    for fact in &facts {
        if fact.sightings.is_empty() {
            // A fact that has vanished is not a pass. If every copy of the elan block were
            // deleted or renamed, this gate would go quiet exactly when it stopped watching
            // anything — the vacuity failure the ledger ratchets exist to catch.
            bail!(
                "{}: no occurrences found. Either every copy was removed — in which case delete \
                 this fact — or the shape it is matched by changed and this gate is now watching \
                 nothing.",
                fact.name
            );
        }
        let by_value = fact.distinct();
        let n = fact.sightings.len();
        if by_value.len() == 1 {
            let (v, _) = by_value.iter().next().expect("one value");
            println!("ok: {} — {n} copies, all {v}", fact.name);
            continue;
        }
        split += 1;
        eprintln!(
            "SPLIT: {} has {} different values across {n} copies",
            fact.name,
            by_value.len()
        );
        eprintln!("       {}", fact.stake);
        for (value, paths) in by_value {
            eprintln!("  {value}");
            for p in paths {
                eprintln!("      {}", p.strip_prefix(root).unwrap_or(p).display());
            }
        }
    }

    if split > 0 {
        bail!(
            "{split} fact(s) written in several places with more than one value. \
             They must be bumped together, in one change."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn every_fact_is_actually_present_in_the_tree() {
        // Guards the gate against watching nothing: if a rename makes a matcher stop
        // matching, this fails rather than reporting a vacuous pass.
        for fact in collect(&root()).unwrap() {
            assert!(
                !fact.sightings.is_empty(),
                "{} matched nothing — the gate would be vacuous",
                fact.name
            );
        }
    }

    #[test]
    fn the_shipped_tree_agrees_with_itself() {
        check(&root()).expect("all duplicated pins agree today");
    }

    #[test]
    fn a_split_is_reported_with_both_sides() {
        let fact = Fact {
            name: "test",
            stake: "-",
            sightings: vec![
                (PathBuf::from("a.yml"), "v1".into()),
                (PathBuf::from("b.yml"), "v2".into()),
            ],
        };
        let d = fact.distinct();
        assert_eq!(d.len(), 2, "two values must be reported as a split");
        assert_eq!(d["v1"], vec![Path::new("a.yml")]);
    }

    #[test]
    fn upstream_toolchains_are_not_ours_to_reconcile() {
        let mut out = Vec::new();
        first_party_toolchains(&root(), &mut out).unwrap();
        assert!(
            !out.is_empty(),
            "there are first-party lean-toolchain files"
        );
        assert!(
            out.iter().all(|p| !p.to_string_lossy().contains(".lake")),
            ".lake/packages holds upstream pins, which legitimately differ"
        );
    }
}
