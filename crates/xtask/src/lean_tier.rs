//! A Lean proof tier, derived: the package a workflow builds, the `lean_lib`s it builds there,
//! and every first-party module those libraries stand on.
//!
//! Nothing here is listed by hand (ADR 0007 F-3, G-1):
//!
//! * the tier is the package a workflow's `leanprover/lean-action` step builds, and what that
//!   step builds (`lean_action_builds::steps`) — named targets, or the lakefile's
//!   `@[default_target]`s when the step names none;
//! * a target's root modules come from its `lean_lib … roots := #[…]` in `lakefile.lean`;
//! * the first-party modules those roots stand on are their `import` closure, resolved against
//!   the package's own source directories (an import that resolves to no file in the package is
//!   a dependency's: Mathlib, Aeneas, `Init`).
//!
//! * whether the package depends on Mathlib is read from `lake-manifest.json`.
//!
//! `cargo xtask lean-replay` (#2592) and `cargo xtask lean-axiom-audit` (#3302) both read a
//! tier from here, so the module set one replays is the module set the other audits (G-1).

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::lean_action_builds::{self, Targets};

/// One `lean_lib` of a `lakefile.lean`.
#[derive(Debug, PartialEq, Eq)]
struct Lib {
    name: String,
    roots: Vec<String>,
    src_dir: String,
    default_target: bool,
}

/// A tier, fully derived.
#[derive(Debug)]
pub struct Tier {
    /// The package directory, relative to the repository root.
    pub dir: String,
    /// The `lean_lib`s the workflow builds, in the order it names them.
    pub libs: Vec<String>,
    /// Their root modules.
    pub roots: Vec<String>,
    /// Whether `lake-manifest.json` resolves Mathlib anywhere in the dependency set.
    pub mathlib: bool,
    /// Every first-party module the libraries' roots stand on, roots included, with the
    /// module's source file.
    pub closure: BTreeMap<String, PathBuf>,
}

/// Strip `«»` from a Lean identifier.
fn unquote(name: &str) -> String {
    name.replace(['«', '»'], "")
}

/// Everything in `src` outside `--` and (nested) `/- -/` comments. Newlines are kept, so a
/// line of the result is the same line of the source.
pub fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut depth = 0usize;
    while let Some(c) = chars.next() {
        let next = chars.peek().copied();
        if depth > 0 {
            if c == '-' && next == Some('/') {
                chars.next();
                depth -= 1;
                out.push(' ');
            } else if c == '/' && next == Some('-') {
                chars.next();
                depth += 1;
            } else if c == '\n' {
                out.push('\n');
            }
            continue;
        }
        if c == '/' && next == Some('-') {
            chars.next();
            depth += 1;
        } else if c == '-' && next == Some('-') {
            for c in chars.by_ref() {
                if c == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The modules a Lean file's header imports. The header is `module`? `prelude`? then
/// `[public] [meta] import [all] M`*; it ends at the first token that is none of those.
fn header_imports(src: &str) -> Vec<String> {
    let text = strip_comments(src);
    let mut toks = text.split_whitespace().peekable();
    let mut out = Vec::new();
    while let Some(&tok) = toks.peek() {
        match tok {
            "module" | "prelude" | "public" | "meta" | "private" => {
                toks.next();
            }
            "import" => {
                toks.next();
                if toks.peek() == Some(&"all") {
                    toks.next();
                }
                match toks.next() {
                    Some(m) => out.push(unquote(m)),
                    None => break,
                }
            }
            _ => break,
        }
    }
    out
}

/// The `lean_lib`s of a `lakefile.lean`, with their roots, source directory and whether they
/// are a `@[default_target]`. A lib this cannot read (`globs`, an unterminated root list) is an
/// error, never a lib with no roots.
fn parse_lakefile(text: &str) -> Result<Vec<Lib>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut libs = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix("lean_lib ") else {
            continue;
        };
        let name = unquote(
            rest.split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("lakefile line {}: lean_lib with no name", i + 1))?,
        );
        let default_target = lines[..i]
            .iter()
            .rev()
            .map(|l| l.trim())
            .find(|l| !l.is_empty() && !l.starts_with("--"))
            .is_some_and(|l| l == "@[default_target]");
        // The lib's body: its indented lines, up to the next top-level line.
        let body: String = lines[i + 1..]
            .iter()
            .take_while(|l| l.is_empty() || l.starts_with([' ', '\t']))
            .map(|l| strip_comments(l))
            .collect::<Vec<_>>()
            .join("\n");
        if body.contains("globs") {
            bail!("lean_lib «{name}» declares globs; only explicit roots are read");
        }
        let roots = match body.find("roots") {
            None => vec![name.clone()],
            Some(at) => {
                let after = &body[at..];
                let open = after
                    .find("#[")
                    .ok_or_else(|| anyhow!("lean_lib «{name}»: roots is not a #[…] literal"))?;
                let close = after[open..]
                    .find(']')
                    .ok_or_else(|| anyhow!("lean_lib «{name}»: unterminated roots"))?;
                let list = &after[open + 2..open + close];
                let roots: Vec<String> = list
                    .split(',')
                    .map(|r| unquote(r.trim().trim_start_matches('`')))
                    .filter(|r| !r.is_empty())
                    .collect();
                if roots.is_empty() {
                    bail!("lean_lib «{name}»: empty roots");
                }
                roots
            }
        };
        let src_dir = match body.find("srcDir") {
            None => ".".to_string(),
            Some(at) => {
                let after = &body[at..];
                let q = after
                    .find('"')
                    .ok_or_else(|| anyhow!("lean_lib «{name}»: srcDir is not a string"))?;
                let end = after[q + 1..]
                    .find('"')
                    .ok_or_else(|| anyhow!("lean_lib «{name}»: unterminated srcDir"))?;
                after[q + 1..q + 1 + end].to_string()
            }
        };
        libs.push(Lib {
            name,
            roots,
            src_dir,
            default_target,
        });
    }
    Ok(libs)
}

/// Whether `lake-manifest.json` resolves Mathlib anywhere in the dependency set.
fn depends_on_mathlib(manifest: &str) -> Result<bool> {
    let v: serde_json::Value = serde_json::from_str(manifest).context("lake-manifest.json")?;
    let packages = v["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("lake-manifest.json has no packages array"))?;
    let mut found = false;
    for p in packages {
        let name = p["name"]
            .as_str()
            .ok_or_else(|| anyhow!("lake-manifest.json: a package with no name"))?;
        found |= name == "mathlib";
    }
    Ok(found)
}

/// `A.B.C` as the relative path `A/B/C`.
pub fn module_path(module: &str) -> PathBuf {
    module.split('.').collect::<PathBuf>()
}

/// The source file of a first-party module, if the package has one.
fn source_of(pkg: &Path, src_dirs: &[String], module: &str) -> Option<PathBuf> {
    let rel = module_path(module).with_extension("lean");
    src_dirs
        .iter()
        .map(|d| pkg.join(d).join(&rel))
        .find(|p| p.is_file())
}

/// Derive one tier: the package at `dir` (relative to `root`), building `targets`.
pub fn derive_tier(root: &Path, dir: &str, targets: &Targets) -> Result<Tier> {
    let pkg = root.join(dir);
    let lakefile = std::fs::read_to_string(pkg.join("lakefile.lean"))
        .with_context(|| format!("{dir}/lakefile.lean"))?;
    let libs = parse_lakefile(&lakefile).with_context(|| format!("{dir}/lakefile.lean"))?;
    let manifest = std::fs::read_to_string(pkg.join("lake-manifest.json"))
        .with_context(|| format!("{dir}/lake-manifest.json"))?;
    let mathlib = depends_on_mathlib(&manifest).with_context(|| dir.to_string())?;
    let chosen: Vec<&Lib> = match targets {
        Targets::Default => libs.iter().filter(|l| l.default_target).collect(),
        Targets::Named(names) => names
            .iter()
            .map(|n| {
                libs.iter().find(|l| &l.name == n).ok_or_else(|| {
                    anyhow!(
                        "{dir}: the workflow builds `{n}`, which lakefile.lean does not declare"
                    )
                })
            })
            .collect::<Result<_>>()?,
    };
    if chosen.is_empty() {
        bail!("{dir}: the build names no lean_lib (no @[default_target] and no build-args)");
    }
    let mut src_dirs: Vec<String> = libs.iter().map(|l| l.src_dir.clone()).collect();
    src_dirs.sort();
    src_dirs.dedup();
    let mut roots: Vec<String> = Vec::new();
    for lib in &chosen {
        for r in &lib.roots {
            if !roots.contains(r) {
                roots.push(r.clone());
            }
        }
    }
    let mut closure = BTreeMap::new();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();
    while let Some(m) = queue.pop_front() {
        if closure.contains_key(&m) {
            continue;
        }
        let Some(src) = source_of(&pkg, &src_dirs, &m) else {
            if roots.contains(&m) {
                bail!("{dir}: root module {m} has no source file in the package");
            }
            continue; // a dependency's module
        };
        let text = std::fs::read_to_string(&src).with_context(|| src.display().to_string())?;
        queue.extend(header_imports(&text));
        closure.insert(m, src);
    }
    Ok(Tier {
        dir: dir.to_string(),
        libs: chosen.iter().map(|l| l.name.clone()).collect(),
        roots,
        mathlib,
        closure,
    })
}

/// The tiers a workflow builds, one per package directory.
pub fn derive_workflow(root: &Path, workflow: &Path) -> Result<Vec<Tier>> {
    let text = std::fs::read_to_string(root.join(workflow))
        .with_context(|| workflow.display().to_string())?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&text)?;
    let steps = lean_action_builds::steps(&yaml).with_context(|| workflow.display().to_string())?;
    // Two steps building in one package are one tier: merge what they build.
    let mut by_dir: BTreeMap<String, Targets> = BTreeMap::new();
    for step in steps {
        let merged = match (by_dir.remove(&step.directory), step.targets) {
            (None, t) => t,
            (Some(Targets::Named(mut a)), Targets::Named(b)) => {
                a.extend(b.into_iter().filter(|t| !a.contains(t)).collect::<Vec<_>>());
                Targets::Named(a)
            }
            (Some(Targets::Default), Targets::Default) => Targets::Default,
            (Some(_), _) => bail!(
                "{}: {} is built both bare and by name; cannot tell which is the tier",
                workflow.display(),
                step.directory
            ),
        };
        by_dir.insert(step.directory, merged);
    }
    if by_dir.is_empty() {
        bail!(
            "{}: no leanprover/lean-action step builds anything",
            workflow.display()
        );
    }
    by_dir
        .iter()
        .map(|(dir, targets)| derive_tier(root, dir, targets))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn header_imports_stop_at_the_first_command_and_skip_comments() {
        let src = "/-! doc\n  import NotThis -/\n-- import NorThis\nmodule\nprelude\nimport A.B\npublic meta import all «C»\nimport D -- trailing\n\ntheorem x : True := trivial\nimport E\n";
        assert_eq!(header_imports(src), ["A.B", "C", "D"]);
        assert_eq!(
            header_imports("theorem t : True := trivial"),
            Vec::<String>::new()
        );
        assert_eq!(header_imports("/- a /- nested -/ still -/ import Z"), ["Z"]);
    }

    #[test]
    fn lakefile_libs_read_roots_src_dirs_and_default_targets() {
        let text = "package «p» where\n  x := 1\n\n-- a lib\nlean_lib «Gen» where\n  roots := #[\n    `Gen.Types,\n    `Gen.Funs\n  ]\n  srcDir := \"generated\"\n\n@[default_target]\nlean_lib «Main» where\n  roots := #[`Main]\n\nlean_lib Bare where\n";
        let libs = parse_lakefile(text).unwrap();
        assert_eq!(
            libs,
            [
                Lib {
                    name: "Gen".into(),
                    roots: vec!["Gen.Types".into(), "Gen.Funs".into()],
                    src_dir: "generated".into(),
                    default_target: false
                },
                Lib {
                    name: "Main".into(),
                    roots: vec!["Main".into()],
                    src_dir: ".".into(),
                    default_target: true
                },
                Lib {
                    name: "Bare".into(),
                    roots: vec!["Bare".into()],
                    src_dir: ".".into(),
                    default_target: false
                },
            ]
        );
        assert!(parse_lakefile("lean_lib X where\n  globs := #[.submodules `X]\n").is_err());
        assert!(parse_lakefile("lean_lib X where\n  roots := #[`X\n").is_err());
    }

    #[test]
    fn mathlib_anywhere_in_the_manifest_is_read() {
        assert!(
            depends_on_mathlib(r#"{"packages":[{"name":"aeneas"},{"name":"mathlib"}]}"#).unwrap()
        );
        assert!(!depends_on_mathlib(r#"{"packages":[{"name":"axiom-audit"}]}"#).unwrap());
        assert!(!depends_on_mathlib(r#"{"packages":[]}"#).unwrap());
        assert!(depends_on_mathlib(r#"{"name":"x"}"#).is_err());
    }

    #[test]
    fn the_real_tiers_derive() {
        let root = repo();
        let ifc = derive_workflow(&root, Path::new(".github/workflows/ifc-lean.yml")).unwrap();
        assert_eq!(ifc.len(), 1);
        assert!(!ifc[0].mathlib);
        assert_eq!(ifc[0].roots, ["Ifc"]);
        assert!(
            ifc[0].closure.contains_key("Ifc.Lattice"),
            "{:?}",
            ifc[0].closure.keys()
        );

        let core = derive_workflow(
            &root,
            Path::new(".github/workflows/portcullis-core-proven-lean.yml"),
        )
        .unwrap();
        assert_eq!(core.len(), 1);
        let core = &core[0];
        assert!(core.mathlib);
        // Multi-line roots, and a generated srcDir, both resolved.
        assert!(
            core.closure
                .contains_key("PortcullisCoreAttenuation.FunsExternal")
        );
        assert!(core.closure.contains_key("PortcullisCoreIFC.Funs"));
        // No dependency's module leaks into the first-party closure.
        assert!(
            core.closure
                .keys()
                .all(|m| !m.starts_with("Mathlib") && !m.starts_with("Aeneas") && m != "Init")
        );
        // Every module carries the source file it was resolved from.
        assert!(core.closure.values().all(|p| p.is_file()));
    }

    #[test]
    fn a_target_the_lakefile_does_not_declare_is_an_error() {
        let err = derive_tier(
            &repo(),
            "crates/nucleus-ifc-kernel/lean",
            &Targets::Named(vec!["NoSuchLib".into()]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("NoSuchLib"));
    }
}
