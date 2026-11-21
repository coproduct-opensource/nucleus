//! `cargo xtask pnpm-lock-floors` — a pnpm lockfile keeps the overrides its project declares,
//! and resolves each floored package at or above its floor.
//!
//! # The defect this exists for
//!
//! `examples/openclaw-nucleus-plugin` overrides `@modelcontextprotocol/sdk` to `^1.31.0`
//! (GHSA-6qxp-vccf-f47h): `openclaw` asks for `^1.25.2`, which on its own resolves to
//! 1.30.0. In November 2026 four Dependabot pull requests (#3504, #3509, #3530, #3539) each
//! bumped one unrelated package and, in the same lockfile, deleted the `overrides:` block and
//! moved the SDK back to 1.30.0. Nothing in CI reads that lockfile, so all four were green on
//! that point and a reviewer had to notice it in a 3,000-line diff.
//!
//! The cause, reproduced on 2026-11-16: pnpm 11 no longer reads the `pnpm` field of
//! `package.json` ("The following keys were ignored: \"pnpm.overrides\""). Run on main's
//! `package.json` and lockfile, `pnpm@11.28.12 update --lockfile-only qs` drops the block
//! and resolves 1.30.0, the same lines Dependabot wrote. With the override in
//! `pnpm-workspace.yaml` instead, the same command keeps it and keeps 1.32.1. pnpm 10 reads
//! both places. So the override lives in `pnpm-workspace.yaml`, and `package.json` may not
//! carry a `pnpm` field at all: one that is silently ignored is a convention, not a setting.
//!
//! # What is checked, per floor
//!
//! 1. `package.json` has no `pnpm` field.
//! 2. `pnpm-workspace.yaml` overrides the package.
//! 3. The lockfile's `overrides:` block carries that override with the same specifier.
//! 4. Every version of the package the lockfile resolves is at or above the floor, and there
//!    is at least one: a lockfile that no longer mentions the package is not evidence that
//!    it is safe.
//!
//! # What decides this
//!
//! Committed files under each floor's directory. No network, no pnpm, no toolchain.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::de::IgnoredAny;

/// A package a lockfile must resolve at or above some version, and why.
struct Floor {
    /// The pnpm project, relative to the repository root.
    dir: &'static str,
    package: &'static str,
    min: Version,
    why: &'static str,
}

const FLOORS: &[Floor] = &[Floor {
    dir: "examples/openclaw-nucleus-plugin",
    package: "@modelcontextprotocol/sdk",
    min: Version(1, 31, 0),
    why: "GHSA-6qxp-vccf-f47h",
}];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// `1.32.1`, or `1.32.1-rc.0` read as its release. Anything else is an error, never a pass.
fn version(text: &str) -> Option<Version> {
    let core = text.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = Version(parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

#[derive(Deserialize)]
struct Workspace {
    #[serde(default)]
    overrides: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    overrides: BTreeMap<String, String>,
    #[serde(default)]
    packages: BTreeMap<String, IgnoredAny>,
}

/// Every failure for one floor, from the three files' text. Empty means it holds.
fn failures(
    floor: &Floor,
    package_json: &str,
    workspace: Option<&str>,
    lock: &str,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let manifest: serde_json::Value =
        serde_json::from_str(package_json).context("package.json is not JSON")?;
    if manifest.get("pnpm").is_some() {
        out.push(
            "package.json has a `pnpm` field; pnpm 11 ignores it, so an override there is \
             dropped by the next lockfile update. Move it to pnpm-workspace.yaml"
                .into(),
        );
    }
    let declared = match workspace {
        None => {
            out.push(format!(
                "no pnpm-workspace.yaml, so nothing overrides {}",
                floor.package
            ));
            None
        }
        Some(text) => {
            let ws: Workspace = nucleus_yaml::from_str(text)
                .map_err(|e| anyhow::anyhow!("pnpm-workspace.yaml: {e}"))?;
            let spec = ws.overrides.get(floor.package).cloned();
            if spec.is_none() {
                out.push(format!(
                    "pnpm-workspace.yaml does not override {}",
                    floor.package
                ));
            }
            spec
        }
    };
    let lock: Lock =
        nucleus_yaml::from_str(lock).map_err(|e| anyhow::anyhow!("pnpm-lock.yaml: {e}"))?;
    match (lock.overrides.get(floor.package), &declared) {
        (None, _) => out.push(format!(
            "pnpm-lock.yaml has no override for {}: the lockfile was written without it",
            floor.package
        )),
        (Some(locked), Some(declared)) if locked != declared => out.push(format!(
            "pnpm-lock.yaml overrides {} to {locked:?}, pnpm-workspace.yaml to {declared:?}",
            floor.package
        )),
        (Some(_), _) => {}
    }
    let prefix = format!("{}@", floor.package);
    let mut seen = 0usize;
    for key in lock.packages.keys() {
        let Some(rest) = key.strip_prefix(&prefix) else {
            continue;
        };
        seen += 1;
        match version(rest) {
            None => bail!("pnpm-lock.yaml: cannot read the version in {key:?}"),
            Some(v) if v < floor.min => out.push(format!(
                "pnpm-lock.yaml resolves {} {v}, below {} ({})",
                floor.package, floor.min, floor.why
            )),
            Some(_) => {}
        }
    }
    if seen == 0 {
        out.push(format!(
            "pnpm-lock.yaml resolves no {} at all, so its floor cannot be checked",
            floor.package
        ));
    }
    Ok(out)
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

pub fn check(root: &Path) -> Result<()> {
    let mut red = 0usize;
    for floor in FLOORS {
        let dir = root.join(floor.dir);
        let workspace_path = dir.join("pnpm-workspace.yaml");
        let workspace = match fs::read_to_string(&workspace_path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", workspace_path.display()));
            }
        };
        let found = failures(
            floor,
            &read(&dir.join("package.json"))?,
            workspace.as_deref(),
            &read(&dir.join("pnpm-lock.yaml"))?,
        )?;
        if found.is_empty() {
            println!(
                "ok: {} resolves {} at or above {} ({})",
                floor.dir, floor.package, floor.min, floor.why
            );
        }
        for f in &found {
            eprintln!("::error file={}/pnpm-lock.yaml::{f}", floor.dir);
        }
        red += found.len();
    }
    if red > 0 {
        bail!("{red} pnpm lockfile floor violation(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: &Floor = &FLOORS[0];
    const PACKAGE: &str = r#"{"name":"p","devDependencies":{"openclaw":"^2026.9.2"}}"#;
    const WORKSPACE: &str = "overrides:\n  '@modelcontextprotocol/sdk': ^1.31.0\n";

    fn lock(overrides: bool, sdk: &str) -> String {
        let block = if overrides {
            "overrides:\n  '@modelcontextprotocol/sdk': ^1.31.0\n\n"
        } else {
            ""
        };
        format!(
            "lockfileVersion: '9.0'\n\n{block}packages:\n\n  '@modelcontextprotocol/sdk@{sdk}':\n    \
             resolution: {{integrity: sha512-x}}\n\n  qs@6.17.1:\n    resolution: {{integrity: sha512-y}}\n"
        )
    }

    #[test]
    fn main_after_the_move_holds() {
        let found = failures(FLOOR, PACKAGE, Some(WORKSPACE), &lock(true, "1.32.1")).unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    /// The shape of #3504/#3509/#3530/#3539: the block gone and the SDK at 1.30.0.
    #[test]
    fn a_dropped_override_and_a_downgrade_are_both_named() {
        let found = failures(FLOOR, PACKAGE, Some(WORKSPACE), &lock(false, "1.30.0")).unwrap();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("no override"));
        assert!(found[1].contains("1.30.0, below 1.31.0"));
    }

    #[test]
    fn an_override_in_package_json_is_refused_because_pnpm_11_ignores_it() {
        let old = r#"{"pnpm":{"overrides":{"@modelcontextprotocol/sdk":"^1.31.0"}}}"#;
        let found = failures(FLOOR, old, None, &lock(true, "1.32.1")).unwrap();
        assert!(
            found.iter().any(|f| f.contains("`pnpm` field")),
            "{found:?}"
        );
        assert!(found.iter().any(|f| f.contains("no pnpm-workspace.yaml")));
    }

    #[test]
    fn a_lockfile_without_the_package_is_not_a_pass() {
        let empty = "lockfileVersion: '9.0'\n\noverrides:\n  '@modelcontextprotocol/sdk': ^1.31.0\n\npackages: {}\n";
        let found = failures(FLOOR, PACKAGE, Some(WORKSPACE), empty).unwrap();
        assert!(found.iter().any(|f| f.contains("resolves no")), "{found:?}");
    }

    #[test]
    fn an_unreadable_version_is_an_error_not_a_pass() {
        assert!(failures(FLOOR, PACKAGE, Some(WORKSPACE), &lock(true, "latest")).is_err());
        assert_eq!(version("1.32.1"), Some(Version(1, 32, 1)));
        assert_eq!(version("1.31.0-rc.1"), Some(Version(1, 31, 0)));
        assert_eq!(version("1.31"), None);
        assert!(Version(1, 30, 9) < Version(1, 31, 0));
    }

    /// The committed tree, so a unit-test run reds on the real files too.
    #[test]
    fn the_committed_plugin_holds() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        check(&root).unwrap();
    }
}
