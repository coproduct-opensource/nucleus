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
//! | `leanprover/lean-action` pin | 13 workflows | the commit that installs the Lean toolchain; a stale copy is a supply-chain hazard, not just drift |
//! | `AENEAS_RELEASE`, `CHARON_NIGHTLY` | 6 workflows, 12 lines | a partial bump splits the extraction fleet, and the halves disagree about generated Lean |
//! | first-party `lean-toolchain` | 9 files | two Lean versions cannot share a `.lake` cache |
//! | the actions-runner image ref | 2 Dockerfiles | two runner images that must stay in lockstep |
//! | `RUSTUP_VERSION` + its two SHAs | 2 Dockerfiles | same shape, and `ci/fly-runner/Dockerfile*` sits outside `ci/docker-rust-matches-msrv.sh`'s `docker/Dockerfile*` glob |
//!
//! Deliberately NOT here: the `rust:` base image. `docker/Dockerfile.node` ships on
//! `rust:1.95-bookworm` while `ci/fly-runner/Dockerfile.manager` runs on
//! `rust:1.96.1-slim-bookworm`, and those are different services with no reason to agree.
//! `ci/docker-rust-matches-msrv.sh` already covers `docker/Dockerfile*` with the relation
//! that is actually wanted there — base >= MSRV, not base == anything. A gate asserting
//! equality across unrelated services would be a gate asserting the wrong thing.
//! | the workspace MSRV | `Cargo.toml` + `feature-matrix.yml` | `feature-matrix.yml:98` says "Must match `[workspace.package] rust-version`" — a comment |
//! | the Kani toolchain floor | 2 values **+ a job name** | `feature-matrix.yml:154` says "Must match the rustc that kani-verifier bundles" — also a comment. The version is embedded in the job's `name:`, which is a REQUIRED CONTEXT, so a bump that misses it leaves branch protection naming a floor that moved |
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
    // Was two facts: the elan release and the SHA-256 of its tarball, copied into
    // twelve hand-rolled install blocks. Those blocks are gone — `leanprover/lean-action`
    // installs the toolchain now — so the gate would have found zero copies and bailed,
    // which is exactly what it did and exactly what it should have done.
    //
    // The supply-chain control did not go away with them; it MOVED. What decides the elan
    // version is now the commit of the action that installs it, and that commit is copied
    // into thirteen workflows with nothing else asserting the copies agree. Same fact
    // shape, one layer out. Deleting the elan rows without adding this one would have
    // deleted the coverage too, which is the failure this gate exists to name.
    let mut lean_action = Fact {
        name: "leanprover/lean-action pin",
        stake: "this commit is what installs the Lean toolchain now, so a split pin means two \
                elan versions across the Lean fleet — the hazard the elan rows used to carry",
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
        // `uses: leanprover/lean-action@<sha> # v1` — the SHA runs to the first space.
        for v in scan(&text, "leanprover/lean-action@", ' ') {
            lean_action.sightings.push((path.clone(), v));
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

    // --- Dockerfile pairs -------------------------------------------------------------
    let dockerfiles: Vec<PathBuf> = ["docker", "ci/fly-runner"]
        .iter()
        .filter_map(|d| fs::read_dir(root.join(d)).ok())
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("Dockerfile"))
        })
        .collect();

    let mut runner_image = Fact {
        name: "actions-runner image",
        stake: "two runner images that must stay in lockstep, in two trees",
        sightings: Vec::new(),
    };
    let mut rustup = Fact {
        name: "RUSTUP_VERSION",
        stake: "ci/fly-runner/Dockerfile* is outside ci/docker-rust-matches-msrv.sh's glob",
        sightings: Vec::new(),
    };
    let mut dockerfiles = dockerfiles;
    dockerfiles.sort();
    for path in &dockerfiles {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        for line in text.lines() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("FROM ghcr.io/actions/actions-runner:") {
                runner_image.sightings.push((
                    path.clone(),
                    v.split_whitespace().next().unwrap_or(v).to_string(),
                ));
            }
            if let Some(v) = t.strip_prefix("ARG RUSTUP_VERSION=") {
                rustup.sightings.push((path.clone(), v.trim().to_string()));
            }
        }
    }

    // --- versions whose "must match" is only a comment ---------------------------------
    let cargo_toml = root.join("Cargo.toml");
    let fm = root.join(".github/workflows/feature-matrix.yml");
    let cargo_text = fs::read_to_string(&cargo_toml).context("reading Cargo.toml")?;
    let fm_text = fs::read_to_string(&fm).context("reading feature-matrix.yml")?;

    let msrv_declared = cargo_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("rust-version = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .context("Cargo.toml has no [workspace.package] rust-version")?;
    let mut msrv = Fact {
        name: "workspace MSRV",
        stake: "feature-matrix.yml says \"Must match [workspace.package] rust-version\" in a comment",
        sightings: vec![(cargo_toml.clone(), msrv_declared)],
    };
    let mut kani_floor = Fact {
        name: "Kani toolchain floor",
        stake: "the floor is also written into a job name, and that name is a required context",
        sightings: Vec::new(),
    };
    // The toolchain a job pins is the first `toolchain:` after its job id.
    for (job, fact) in [("  msrv:", &mut msrv), ("  kani-msrv:", &mut kani_floor)] {
        if let Some(i) = fm_text.find(job) {
            if let Some(v) = fm_text[i..]
                .lines()
                .find_map(|l| l.trim().strip_prefix("toolchain: "))
            {
                fact.sightings
                    .push((fm.clone(), v.trim().trim_matches('"').to_string()));
            }
        }
    }
    // The floor written into the job's display name — `Kani toolchain floor (1.93)`.
    if let Some(l) = fm_text
        .lines()
        .find(|l| l.trim().starts_with("name: Kani toolchain floor"))
    {
        if let (Some(a), Some(b)) = (l.find('('), l.rfind(')')) {
            kani_floor
                .sightings
                .push((fm.clone(), l[a + 1..b].to_string()));
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

    Ok(vec![
        lean_action,
        aeneas,
        charon,
        lean,
        runner_image,
        rustup,
        msrv,
        kani_floor,
    ])
}

pub fn check(root: &Path) -> Result<()> {
    let facts = collect(root)?;
    let mut split = 0usize;

    for fact in &facts {
        if fact.sightings.is_empty() {
            // A fact that has vanished is not a pass. If every copy of a pinned version were
            // deleted or renamed, this gate would go quiet exactly when it stopped watching
            // anything — the vacuity failure the ledger ratchets exist to catch. It has
            // already earned itself once: migrating the Lean workflows to
            // `leanprover/lean-action` removed every hand-rolled elan install, and this is
            // what said so rather than passing on an empty scan.
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
