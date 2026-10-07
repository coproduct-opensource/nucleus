//! `cargo xtask lean-replay` — a second kernel pass over the proven tier's `.olean` files (#2592).
//!
//! # Why this exists
//!
//! `lake build` elaborates a proof and the kernel checks it once, inside the same process that
//! wrote the `.olean`. Nothing ever re-checked what landed on disk: a constant that reached an
//! `.olean` without the kernel (a metaprogram calling `addDeclWithoutChecking`, an environment
//! extension rewriting a declaration, a tampered artifact restored from a cache) would be
//! imported downstream as a theorem. `leanchecker` (shipped with Lean, `lake env leanchecker`)
//! reads the `.olean` back and replays every constant through the kernel again.
//!
//! # What is replayed, and how
//!
//! Every input is DERIVED, never listed here (ADR 0007 F-3, G-1):
//!
//! * the tier is the package a workflow's `leanprover/lean-action` step builds, and its proven
//!   tier is what that step builds (`lean_action_builds::steps`, the reader the axiom audit and
//!   `check-lean-libs-built.sh` already use) — named targets, or the lakefile's
//!   `@[default_target]`s when the step names none;
//! * a target's root modules come from its `lean_lib … roots := #[…]` in `lakefile.lean`;
//! * the first-party modules those roots stand on are their `import` closure, resolved against
//!   the package's own source directories (an import that resolves to no file in the package is
//!   a dependency's: Mathlib, Aeneas, `Init`);
//! * the replay mode is decided by `lake-manifest.json`: a package with `mathlib` anywhere in
//!   its resolved dependency set is replayed FROM IMPORTS — each first-party module's own
//!   constants, into the environment its imports' `.olean`s produce — because `--fresh` would
//!   replay all of Mathlib and does not fit a CI job. A Mathlib-free package is replayed
//!   `--fresh`: each root's ENTIRE closure, `Init` included, into an empty environment, which
//!   trusts no `.olean` at all.
//!
//! # Verdict
//!
//! Exit 0: every planned module was replayed and the kernel accepted it. Exit 1: the kernel
//! rejected a module (ADR 0007 I-3: the rejection and the could-not-look path never share a
//! status). Exit 2: could not look — a target the lakefile does not declare, a module with no
//! source or no `.olean`, `lake` missing, or a run that did not report replaying every planned
//! module. The last is the non-vacuity assertion: the count comes from `leanchecker`'s own
//! `-v` output, checked against the derived plan, never from the plan alone.
//!
//! READS COMPILED OLEANS. Run it after the build it checks; CI does.
//!
//! # Proving it can fail
//!
//! `--self-test <package>` forges two one-theorem `.olean` files under the package's own
//! toolchain (`forge.lean`): identical but for ONE proof term, `Eq.refl 2` against `Eq.refl 3`
//! for `Nat.add 1 1 = 2`. Both go through the same runner and the same judge as a real tier, in
//! both modes. The forged module must be REJECTED, with the kernel naming the forged constant
//! (red for its own reason, not because the fixture failed to load), and the sound one must be
//! CLEAN (a checker that rejects everything would pass the first half alone).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};

use crate::lean_action_builds::{self, Targets};

/// The fixture writer `--self-test` runs under the probed package's toolchain.
const FORGE: &str = include_str!("forge.lean");
const SOUND: &str = "LeanReplayProbeSound";
const FORGED: &str = "LeanReplayProbeForged";

/// How `leanchecker` replays a module. Decided by the package's Mathlib dependency alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// `--fresh`: every constant of the module's import closure, into an empty environment.
    /// `leanchecker` takes exactly one module per `--fresh` run.
    Fresh,
    /// The module's own constants, into the environment its imports' `.olean`s produce.
    FromImports,
}

impl Replay {
    fn label(self) -> &'static str {
        match self {
            Replay::Fresh => "--fresh",
            Replay::FromImports => "from imports",
        }
    }
}

/// One `lean_lib` of a `lakefile.lean`.
#[derive(Debug, PartialEq, Eq)]
struct Lib {
    name: String,
    roots: Vec<String>,
    src_dir: String,
    default_target: bool,
}

/// A tier, fully derived: what is replayed, how, and why each module is in the plan.
#[derive(Debug)]
pub struct Tier {
    /// The package directory, relative to the repository root.
    dir: String,
    replay: Replay,
    /// The `lean_lib`s the workflow builds.
    libs: Vec<String>,
    /// Their root modules.
    roots: Vec<String>,
    /// Every first-party module the roots stand on, roots included.
    closure: BTreeSet<String>,
}

impl Tier {
    /// The modules handed to `leanchecker`, one run each. `--fresh` replays a root's whole
    /// closure, so the roots suffice; from imports, every first-party module is its own run.
    fn planned(&self) -> Vec<String> {
        match self.replay {
            Replay::Fresh => self.roots.clone(),
            Replay::FromImports => self.closure.iter().cloned().collect(),
        }
    }
}

/// One `leanchecker` process.
#[derive(Debug)]
struct Run {
    module: String,
    /// `None` when the process could not be started at all.
    status: Option<i32>,
    /// The modules `leanchecker -v` reported replaying.
    replayed: BTreeSet<String>,
    output: String,
    secs: f64,
}

/// The verdict over a set of runs. Three outcomes, three exit statuses (ADR 0007 A-1, I-3).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Clean,
    Rejected(Vec<String>),
    CouldNotLook(String),
}

impl Outcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Clean => 0,
            Outcome::Rejected(_) => 1,
            Outcome::CouldNotLook(_) => 2,
        }
    }
}

/// Strip `«»` from a Lean identifier.
fn unquote(name: &str) -> String {
    name.replace(['«', '»'], "")
}

/// Everything in `src` outside `--` and (nested) `/- -/` comments.
fn strip_comments(src: &str) -> String {
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

fn module_path(module: &str) -> PathBuf {
    module.split('.').collect::<PathBuf>()
}

/// The source file of a first-party module, if the package has one.
fn source_of(pkg: &Path, src_dirs: &BTreeSet<String>, module: &str) -> Option<PathBuf> {
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
    let replay = if depends_on_mathlib(&manifest).with_context(|| dir.to_string())? {
        Replay::FromImports
    } else {
        Replay::Fresh
    };
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
    let src_dirs: BTreeSet<String> = libs.iter().map(|l| l.src_dir.clone()).collect();
    let mut roots: Vec<String> = Vec::new();
    for lib in &chosen {
        for r in &lib.roots {
            if !roots.contains(r) {
                roots.push(r.clone());
            }
        }
    }
    let mut closure = BTreeSet::new();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();
    while let Some(m) = queue.pop_front() {
        if closure.contains(&m) {
            continue;
        }
        let Some(src) = source_of(&pkg, &src_dirs, &m) else {
            if roots.contains(&m) {
                bail!("{dir}: root module {m} has no source file in the package");
            }
            continue; // a dependency's module
        };
        let text = std::fs::read_to_string(&src).with_context(|| src.display().to_string())?;
        closure.insert(m);
        queue.extend(header_imports(&text));
    }
    Ok(Tier {
        dir: dir.to_string(),
        replay,
        libs: chosen.iter().map(|l| l.name.clone()).collect(),
        roots,
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
                "{}: {} is built both bare and by name; replay cannot tell which is the tier",
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

/// `leanchecker -v` prints `replaying M` (or `replaying M with --fresh`) before each module.
fn replayed_modules(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .filter_map(|l| l.strip_prefix("replaying "))
        .filter_map(|r| r.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Run `lake env leanchecker -v [--fresh] M` for each module, `jobs` at a time, in `pkg`.
/// `extra_path` is appended to the search path (Lake keeps an inherited `LEAN_PATH` last).
fn run_all(
    pkg: &Path,
    replay: Replay,
    modules: &[String],
    extra_path: Option<&Path>,
    jobs: usize,
) -> Vec<Run> {
    let next = AtomicUsize::new(0);
    let runs = Mutex::new(Vec::with_capacity(modules.len()));
    std::thread::scope(|s| {
        for _ in 0..jobs.clamp(1, modules.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(module) = modules.get(i) else { break };
                    let run = run_one(pkg, replay, module, extra_path);
                    if let Ok(mut v) = runs.lock() {
                        v.push(run);
                    }
                }
            });
        }
    });
    let mut runs = runs.into_inner().unwrap_or_default();
    runs.sort_by(|a, b| a.module.cmp(&b.module));
    runs
}

fn run_one(pkg: &Path, replay: Replay, module: &str, extra_path: Option<&Path>) -> Run {
    let start = Instant::now();
    let mut cmd = Command::new("lake");
    cmd.current_dir(pkg).args(["env", "leanchecker", "-v"]);
    if replay == Replay::Fresh {
        cmd.arg("--fresh");
    }
    cmd.arg(module);
    if let Some(p) = extra_path {
        cmd.env("LEAN_PATH", p);
    }
    match cmd.output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            Run {
                module: module.to_string(),
                status: Some(out.status.code().unwrap_or(-1)),
                replayed: replayed_modules(&stdout),
                output: format!("{stdout}{stderr}"),
                secs: start.elapsed().as_secs_f64(),
            }
        }
        Err(e) => Run {
            module: module.to_string(),
            status: None,
            replayed: BTreeSet::new(),
            output: format!(
                "could not run `lake env leanchecker` in {}: {e}",
                pkg.display()
            ),
            secs: start.elapsed().as_secs_f64(),
        },
    }
}

/// The verdict over `runs` for the `planned` modules. Rejection outranks could-not-look: a
/// kernel that refused a module has decided, whatever else went wrong.
fn judge(planned: &[String], runs: &[Run]) -> Outcome {
    if planned.is_empty() {
        return Outcome::CouldNotLook("the plan is empty: nothing would be replayed".into());
    }
    let rejected: Vec<String> = runs
        .iter()
        .filter(|r| r.status.is_some_and(|c| c != 0))
        .map(|r| r.module.clone())
        .collect();
    if !rejected.is_empty() {
        return Outcome::Rejected(rejected);
    }
    if let Some(r) = runs.iter().find(|r| r.status.is_none()) {
        return Outcome::CouldNotLook(r.output.clone());
    }
    let replayed: BTreeSet<&String> = runs.iter().flat_map(|r| r.replayed.iter()).collect();
    let missing: Vec<&String> = planned.iter().filter(|m| !replayed.contains(m)).collect();
    if !missing.is_empty() {
        return Outcome::CouldNotLook(format!(
            "leanchecker exited 0 without reporting a replay of {} planned module(s): {}",
            missing.len(),
            missing
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Outcome::Clean
}

fn print_plan(t: &Tier) {
    let planned = t.planned();
    println!(
        "tier {}: replay {}, {} lib(s), {} root module(s), {} first-party module(s) in the closure, {} leanchecker run(s)",
        t.dir,
        t.replay.label(),
        t.libs.len(),
        t.roots.len(),
        t.closure.len(),
        planned.len()
    );
    println!("  modules: {}", planned.join(" "));
}

/// Check every planned module of a tier has a built `.olean` before replaying anything: an
/// unbuilt module is "could not look", which `leanchecker`'s own error would not distinguish
/// from a rejection.
fn unbuilt(root: &Path, t: &Tier) -> Vec<String> {
    let lib = root.join(&t.dir).join(".lake/build/lib/lean");
    t.planned()
        .into_iter()
        .filter(|m| !lib.join(module_path(m).with_extension("olean")).is_file())
        .collect()
}

fn replay_tier(root: &Path, t: &Tier, jobs: usize) -> Outcome {
    let missing = unbuilt(root, t);
    if !missing.is_empty() {
        return Outcome::CouldNotLook(format!(
            "{}: no .olean for {} planned module(s) ({}); build the tier first",
            t.dir,
            missing.len(),
            missing.join(", ")
        ));
    }
    let planned = t.planned();
    let start = Instant::now();
    let runs = run_all(&root.join(&t.dir), t.replay, &planned, None, jobs);
    let outcome = judge(&planned, &runs);
    let slowest = runs
        .iter()
        .max_by(|a, b| a.secs.total_cmp(&b.secs))
        .map(|r| format!(", slowest {} {:.1}s", r.module, r.secs))
        .unwrap_or_default();
    match &outcome {
        Outcome::Clean => {
            let replayed: BTreeSet<&String> = runs.iter().flat_map(|r| r.replayed.iter()).collect();
            println!(
                "ok: {} — kernel accepted {} module(s) replayed {} ({} run(s), {} first-party module(s) covered) in {:.1}s wall{}",
                t.dir,
                replayed.len(),
                t.replay.label(),
                runs.len(),
                t.closure.len(),
                start.elapsed().as_secs_f64(),
                slowest
            );
        }
        Outcome::Rejected(mods) => {
            for r in runs.iter().filter(|r| mods.contains(&r.module)) {
                println!(
                    "::error::{}: the kernel REJECTED {} on replay {}:",
                    t.dir,
                    r.module,
                    t.replay.label()
                );
                println!("{}", r.output.trim_end());
            }
        }
        // Printed once, by the caller, with every other could-not-look reason.
        Outcome::CouldNotLook(_) => {}
    }
    outcome
}

/// Combine tier verdicts: any rejection is a rejection; else any could-not-look is.
fn worst(outcomes: Vec<Outcome>) -> Outcome {
    let mut rejected = Vec::new();
    let mut blind = Vec::new();
    for o in outcomes {
        match o {
            Outcome::Clean => {}
            Outcome::Rejected(m) => rejected.extend(m),
            Outcome::CouldNotLook(w) => blind.push(w),
        }
    }
    if !rejected.is_empty() {
        Outcome::Rejected(rejected)
    } else if !blind.is_empty() {
        Outcome::CouldNotLook(blind.join("; "))
    } else {
        Outcome::Clean
    }
}

/// `lean-replay --workflow <w> [--plan]`.
pub fn run(root: &Path, workflow: &Path, plan: bool, jobs: usize) -> Outcome {
    let tiers = match derive_workflow(root, workflow) {
        Ok(t) => t,
        Err(e) => return Outcome::CouldNotLook(format!("{e:#}")),
    };
    for t in &tiers {
        print_plan(t);
    }
    if plan {
        return Outcome::Clean;
    }
    worst(tiers.iter().map(|t| replay_tier(root, t, jobs)).collect())
}

/// `lean-replay --self-test <package>`: the forged module is rejected for its own reason and
/// the sound one is accepted, in both modes, through the runner and judge a tier uses.
pub fn self_test(pkg: &Path) -> Outcome {
    match self_test_inner(pkg) {
        Ok(()) => Outcome::Clean,
        Err(e) => Outcome::CouldNotLook(format!("self-test: {e:#}")),
    }
}

fn self_test_inner(pkg: &Path) -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let forge = tmp.path().join("forge.lean");
    std::fs::write(&forge, FORGE)?;
    let out = Command::new("lake")
        .current_dir(pkg)
        .args(["env", "lean", "--run"])
        .arg(&forge)
        .arg(tmp.path())
        .output()
        .with_context(|| format!("running `lake env lean --run` in {}", pkg.display()))?;
    if !out.status.success() {
        bail!(
            "the fixture writer failed in {}:\n{}{}",
            pkg.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for m in [SOUND, FORGED] {
        let olean = tmp.path().join(format!("{m}.olean"));
        if !olean.is_file() {
            bail!(
                "the fixture writer exited 0 and wrote no {}",
                olean.display()
            );
        }
    }
    let modes = [Replay::Fresh, Replay::FromImports];
    let cases: Vec<(Replay, &str)> = modes
        .iter()
        .flat_map(|&r| [(r, SOUND), (r, FORGED)])
        .collect();
    let results: Vec<(Replay, &str, Vec<Run>)> = std::thread::scope(|s| {
        let handles: Vec<_> = cases
            .iter()
            .map(|&(replay, m)| {
                let path = tmp.path();
                s.spawn(move || {
                    (
                        replay,
                        m,
                        run_all(pkg, replay, &[m.to_string()], Some(path), 1),
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().map_err(|_| anyhow!("a self-test thread panicked")))
            .collect::<Result<_>>()
    })?;
    let mut report = String::new();
    let mut failures = Vec::new();
    for (replay, m, runs) in &results {
        let verdict = judge(&[m.to_string()], runs);
        let output = runs.iter().map(|r| r.output.as_str()).collect::<String>();
        let secs: f64 = runs.iter().map(|r| r.secs).sum();
        let ok = if *m == SOUND {
            verdict == Outcome::Clean
        } else {
            // Red for ITS reason: rejected, by the kernel, naming the forged constant, after
            // leanchecker reported replaying the forged module.
            verdict == Outcome::Rejected(vec![FORGED.to_string()])
                && output.contains("(kernel)")
                && output.contains(&format!("{FORGED}.claim"))
                && runs.iter().any(|r| r.replayed.contains(*m))
        };
        let _ = writeln!(
            report,
            "  {:<12} {:<22} {:?} in {secs:.1}s — {}",
            replay.label(),
            m,
            verdict,
            if ok { "as required" } else { "WRONG" }
        );
        if !ok {
            failures.push(format!(
                "{} {m}: {verdict:?}\n{}",
                replay.label(),
                output.trim_end()
            ));
        }
    }
    print!("{report}");
    if !failures.is_empty() {
        bail!(
            "{} case(s) did not go as required:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
    println!(
        "ok: self-test in {} — the forged proof term is rejected by the kernel and the sound one accepted, --fresh and from imports",
        pkg.display()
    );
    Ok(())
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
    fn mathlib_anywhere_in_the_manifest_decides_the_mode() {
        assert!(
            depends_on_mathlib(r#"{"packages":[{"name":"aeneas"},{"name":"mathlib"}]}"#).unwrap()
        );
        assert!(!depends_on_mathlib(r#"{"packages":[{"name":"axiom-audit"}]}"#).unwrap());
        assert!(!depends_on_mathlib(r#"{"packages":[]}"#).unwrap());
        assert!(depends_on_mathlib(r#"{"name":"x"}"#).is_err());
    }

    #[test]
    fn the_real_tiers_derive_with_the_mode_their_manifest_decides() {
        let root = repo();
        let ifc = derive_workflow(&root, Path::new(".github/workflows/ifc-lean.yml")).unwrap();
        assert_eq!(ifc.len(), 1);
        assert_eq!(ifc[0].replay, Replay::Fresh);
        assert_eq!(ifc[0].roots, ["Ifc"]);
        assert!(
            ifc[0].closure.contains("Ifc.Lattice"),
            "{:?}",
            ifc[0].closure
        );

        let core = derive_workflow(
            &root,
            Path::new(".github/workflows/portcullis-core-proven-lean.yml"),
        )
        .unwrap();
        assert_eq!(core.len(), 1);
        let core = &core[0];
        assert_eq!(core.replay, Replay::FromImports);
        // Multi-line roots, and a generated srcDir, both resolved.
        assert!(
            core.closure
                .contains("PortcullisCoreAttenuation.FunsExternal")
        );
        assert!(core.closure.contains("PortcullisCoreIFC.Funs"));
        // No dependency's module leaks into the first-party closure.
        assert!(
            core.closure
                .iter()
                .all(|m| !m.starts_with("Mathlib") && !m.starts_with("Aeneas") && m != "Init")
        );
        assert_eq!(core.planned().len(), core.closure.len());
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

    fn run(module: &str, status: Option<i32>, replayed: &[&str]) -> Run {
        Run {
            module: module.into(),
            status,
            replayed: replayed.iter().map(|s| s.to_string()).collect(),
            output: String::new(),
            secs: 0.0,
        }
    }

    #[test]
    fn the_judge_separates_rejected_from_could_not_look_from_clean() {
        let plan = vec!["A".to_string(), "B".to_string()];
        assert_eq!(
            judge(
                &plan,
                &[run("A", Some(0), &["A"]), run("B", Some(0), &["B", "B.C"])]
            ),
            Outcome::Clean
        );
        assert_eq!(
            judge(&plan, &[run("A", Some(1), &["A"]), run("B", None, &[])]),
            Outcome::Rejected(vec!["A".into()])
        );
        assert!(matches!(
            judge(&plan, &[run("A", Some(0), &["A"]), run("B", None, &[])]),
            Outcome::CouldNotLook(_)
        ));
        // Exit 0 without the replay line is not a replay.
        assert!(matches!(
            judge(&plan, &[run("A", Some(0), &["A"]), run("B", Some(0), &[])]),
            Outcome::CouldNotLook(_)
        ));
        assert!(matches!(judge(&[], &[]), Outcome::CouldNotLook(_)));
        assert_eq!(
            [
                Outcome::Clean.exit_code(),
                Outcome::Rejected(vec![]).exit_code(),
                Outcome::CouldNotLook(String::new()).exit_code()
            ],
            [0, 1, 2]
        );
    }

    #[test]
    fn replay_lines_are_read_in_both_modes() {
        let got = replayed_modules("replaying A.B\nreplaying C with --fresh\nnoise\n");
        assert_eq!(
            got,
            ["A.B".to_string(), "C".to_string()].into_iter().collect()
        );
    }
}
