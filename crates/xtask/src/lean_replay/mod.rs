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
//! Every input is DERIVED, never listed here (ADR 0007 F-3, G-1), by `lean_tier` — the same
//! derivation `lean-axiom-audit` reads, so the replayed and the audited module sets are one:
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

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};

use crate::lean_tier::{self, Tier};

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
    /// The mode for a tier: from imports when Mathlib is anywhere in its resolved
    /// dependencies (`--fresh` would replay all of Mathlib), `--fresh` otherwise.
    fn of(t: &Tier) -> Replay {
        if t.mathlib {
            Replay::FromImports
        } else {
            Replay::Fresh
        }
    }

    fn label(self) -> &'static str {
        match self {
            Replay::Fresh => "--fresh",
            Replay::FromImports => "from imports",
        }
    }
}

/// The modules handed to `leanchecker`, one run each. `--fresh` replays a root's whole
/// closure, so the roots suffice; from imports, every first-party module is its own run.
fn planned(t: &Tier) -> Vec<String> {
    match Replay::of(t) {
        Replay::Fresh => t.roots.clone(),
        Replay::FromImports => t.closure.keys().cloned().collect(),
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
    let planned = planned(t);
    println!(
        "tier {}: replay {}, {} lib(s), {} root module(s), {} first-party module(s) in the closure, {} leanchecker run(s)",
        t.dir,
        Replay::of(t).label(),
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
    planned(t)
        .into_iter()
        .filter(|m| {
            !lib.join(lean_tier::module_path(m).with_extension("olean"))
                .is_file()
        })
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
    let planned = planned(t);
    let start = Instant::now();
    let runs = run_all(&root.join(&t.dir), Replay::of(t), &planned, None, jobs);
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
                Replay::of(t).label(),
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
                    Replay::of(t).label()
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
    let tiers = match lean_tier::derive_workflow(root, workflow) {
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

    fn repo() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_real_tiers_replay_in_the_mode_their_manifest_decides() {
        let root = repo();
        let ifc =
            lean_tier::derive_workflow(&root, Path::new(".github/workflows/ifc-lean.yml")).unwrap();
        assert_eq!(Replay::of(&ifc[0]), Replay::Fresh);
        assert_eq!(planned(&ifc[0]), ["Ifc"]);

        let core = lean_tier::derive_workflow(
            &root,
            Path::new(".github/workflows/portcullis-core-proven-lean.yml"),
        )
        .unwrap();
        let core = &core[0];
        assert_eq!(Replay::of(core), Replay::FromImports);
        assert_eq!(planned(core).len(), core.closure.len());
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
