//! `cargo xtask lean-axiom-audit` — the axioms of every declaration in a proven tier's whole
//! first-party closure (#3302, part of #2555).
//!
//! # Why this exists
//!
//! `scripts/lean-axiom-audit.sh` audits each built library's OWN modules: `axiom-audit --root
//! MatrixBridge` reports the declarations defined in `MatrixBridge`, and nothing it imports. The
//! proven tier's build, though, compiles — and `lean-replay` replays — every first-party module
//! those libraries import. On main at 9a0340668 that closure reached `RankNullity` and
//! `SemanticIFCDecidable`, research-tier files with open `sorry`s, through `MatrixBridge`. No
//! proven-tier gate looked at their declarations: the per-library audit did not import them as
//! a root, the replay accepts `sorryAx` (it is an axiom; the kernel admits it), and the textual
//! hole scan allowlists them by file name. A proven theorem was one `import` away from resting on
//! an open conjecture with every gate green.
//!
//! # What is audited
//!
//! Every input is DERIVED (ADR 0007 F-3, G-1) by `lean_tier`, the derivation `lean-replay`
//! uses: the workflow's Lean-action build names the tier and its libraries, the lakefile their
//! roots, and the roots' `import` closure the first-party modules. Each module is audited by the
//! pinned `axiom-audit` tool the package already requires, which builds the environment from the
//! compiled `.olean`s and reports, for every declaration defined in the module, the axioms it
//! transitively depends on. The closure is split into AUDIT UNITS — a module and its dotted
//! submodules, since `--root M` covers `M.*` — so every declaration is counted exactly once.
//!
//! # Policy (one decider: `Exceptions::tolerates`)
//!
//! * `propext`, `Classical.choice`, `Quot.sound` are allowed ([`ALLOWED`]).
//! * `sorryAx` is never tolerated, whatever any exceptions file says.
//! * A `native_decide` axiom (`<decl>._native.native_decide.ax_*`, or `Lean.ofReduceBool` on
//!   older toolchains) is tolerated only for a declaration NAMED in the package's
//!   `.axiom-audit-exceptions` — the same file, read the same way, as the per-library audit.
//! * An `axiom <name>` line there names an external-model axiom (Aeneas' `FunsExternal`),
//!   tolerated for every declaration that depends on it.
//! * Every other axiom fails.
//!
//! # Verdict
//!
//! Exit 0: every declaration in the closure is clean. Exit 1: at least one is not; each
//! offending declaration is printed with its axioms, and so is every built library whose own
//! closure reaches it — the library is not proven, whatever list it was written in. Exit 2:
//! could not look (ADR 0007 I-3). Non-vacuity is part of "could not look": every unit must
//! report a positive count, at least as many declarations as its sources declare with
//! `theorem`/`lemma`, and the units must cover exactly the derived closure.
//!
//! READS COMPILED OLEANS. Run it after the build it checks; CI does.
//!
//! # Proving it can fail
//!
//! `--self-test <package>` compiles `fixture.lean` (an axiom, a `sorry`, a `native_decide`, a
//! theorem using the axiom, and two clean theorems) under the package's toolchain and audits it
//! through the same runner and the same policy. The `sorry` theorem must be flagged with exactly
//! `sorryAx` (red for its own reason), the clean ones must not be (the allow half), and an
//! exceptions file that names every other offender — and `sorryAx` itself — must leave exactly
//! the `sorry` theorem flagged.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::lean_action_builds::Targets;
use crate::lean_tier::{self, Tier};

/// The axioms a proven declaration may depend on.
pub const ALLOWED: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];
/// What `sorry` and `admit` elaborate to. Never tolerated.
const SORRY: &str = "sorryAx";
/// The pre-4.2x `native_decide` axiom; newer toolchains mint one per declaration.
const REDUCE_BOOL: &str = "Lean.ofReduceBool";
const NATIVE_MARK: &str = "._native.native_decide.ax_";
const EXCEPTIONS: &str = ".axiom-audit-exceptions";

const FIXTURE: &str = include_str!("fixture.lean");
const FIXTURE_MODULE: &str = "AxiomAuditProbe";

/// The package's disclosed exceptions, from `.axiom-audit-exceptions`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Exceptions {
    /// Declarations allowed to introduce `native_decide`.
    native: BTreeSet<String>,
    /// External-model axioms, tolerated for every declaration.
    external: BTreeSet<String>,
}

impl Exceptions {
    /// One name per line; `#` comments and blank lines skipped; `axiom <name>` an external
    /// model. A line this cannot read is an error, never skipped.
    pub fn parse(text: &str) -> Result<Self> {
        let mut out = Exceptions::default();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["axiom", name] => {
                    out.external.insert((*name).to_string());
                }
                [name] if *name != "axiom" => {
                    out.native.insert((*name).to_string());
                }
                _ => bail!("{EXCEPTIONS} line {}: cannot read `{line}`", i + 1),
            }
        }
        Ok(out)
    }

    /// Whether `decl` may depend on `axiom`. The allowlist is checked by the caller.
    pub fn tolerates(&self, decl: &str, axiom: &str) -> bool {
        if axiom == SORRY {
            return false;
        }
        if axiom == REDUCE_BOOL {
            return self.native.contains(decl);
        }
        if let Some(at) = axiom.rfind(NATIVE_MARK) {
            return self.native.contains(&axiom[..at]);
        }
        self.external.contains(axiom)
    }

    fn load(pkg: &Path) -> Result<Self> {
        match std::fs::read_to_string(pkg.join(EXCEPTIONS)) {
            Ok(text) => Self::parse(&text).with_context(|| pkg.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("{}/{EXCEPTIONS}", pkg.display())),
        }
    }
}

/// One `axiom-audit` run: a module and its dotted submodules in the closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    root: String,
    members: Vec<String>,
}

/// Partition `modules` into units: a module is a unit's root iff no proper dotted prefix of it
/// is itself in the set. `axiom-audit --root M` audits `M` and `M.*`, so this counts every
/// declaration exactly once.
fn units<'a>(modules: impl IntoIterator<Item = &'a String>) -> Vec<Unit> {
    let all: BTreeSet<&String> = modules.into_iter().collect();
    let parent_in = |m: &str| {
        m.match_indices('.')
            .any(|(i, _)| all.iter().any(|o| o.as_str() == &m[..i]))
    };
    let roots: Vec<&String> = all.iter().copied().filter(|m| !parent_in(m)).collect();
    roots
        .into_iter()
        .map(|r| Unit {
            root: r.clone(),
            members: all
                .iter()
                .filter(|m| m.as_str() == r.as_str() || m.starts_with(&format!("{r}.")))
                .map(|m| (*m).clone())
                .collect(),
        })
        .collect()
}

/// `axiom-audit --json`'s report.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
struct ToolReport {
    #[serde(default)]
    audited: usize,
    #[serde(rename = "axiomsUsed", default)]
    axioms_used: Vec<String>,
    #[serde(default)]
    violations: Vec<ToolViolation>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ToolViolation {
    decl: String,
    axioms: Vec<String>,
}

/// One unit, run.
#[derive(Debug)]
struct UnitRun {
    unit: Unit,
    /// The tool's report, or why there is none.
    report: std::result::Result<ToolReport, String>,
    /// What its sources declare: the count it must at least reach.
    floor: Floor,
    secs: f64,
}

/// A declaration outside the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offense {
    unit: String,
    decl: String,
    /// The axioms it may not depend on.
    axioms: Vec<String>,
}

/// Three outcomes, three exit statuses (ADR 0007 A-1, I-3).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Clean,
    Offending(Vec<Offense>),
    CouldNotLook(String),
}

impl Outcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Clean => 0,
            Outcome::Offending(_) => 1,
            Outcome::CouldNotLook(_) => 2,
        }
    }
}

/// What a unit's sources declare, outside comments: the lower bound its audit must reach.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Floor {
    /// `theorem`/`lemma` commands. Each is a constant of the module, and elaboration adds more,
    /// never fewer, so the tool must audit at least this many.
    theorems: usize,
    /// Commands that declare any constant. Zero means an audit of zero is the right answer — an
    /// Aeneas `Types.lean` for a crate with no types opens and closes a namespace and nothing
    /// else — and anything else means zero is a miswired run.
    constants: usize,
}

impl std::ops::Add for Floor {
    type Output = Floor;
    fn add(self, o: Floor) -> Floor {
        Floor {
            theorems: self.theorems + o.theorems,
            constants: self.constants + o.constants,
        }
    }
}

fn declared(src: &str) -> Floor {
    const MODS: &str =
        r"^\s*(@\[[^\]]*\]\s*)?((private|protected|noncomputable|nonrec|partial|unsafe)\s+)*";
    let theorem = regex::Regex::new(&format!(r"{MODS}(theorem|lemma)\s")).expect("static regex");
    let constant = regex::Regex::new(&format!(
        r"{MODS}(theorem|lemma|def|abbrev|instance|structure|inductive|class|axiom|opaque)\s"
    ))
    .expect("static regex");
    let text = lean_tier::strip_comments(src);
    Floor {
        theorems: text.lines().filter(|l| theorem.is_match(l)).count(),
        constants: text.lines().filter(|l| constant.is_match(l)).count(),
    }
}

fn run_unit(pkg: &Path, unit: &Unit, extra_path: Option<&Path>, floor: Floor) -> UnitRun {
    let start = Instant::now();
    let mut cmd = Command::new("lake");
    cmd.current_dir(pkg).args([
        "env",
        "axiom-audit",
        "--root",
        &unit.root,
        "--modules",
        &unit.members.join(","),
        "--allow",
        &ALLOWED.join(","),
        "--json",
    ]);
    if let Some(p) = extra_path {
        // Lake keeps an inherited LEAN_PATH, after its own entries.
        cmd.env("LEAN_PATH", p);
    }
    let report = match cmd.output() {
        Err(e) => Err(format!(
            "could not run `lake env axiom-audit` in {}: {e}",
            pkg.display()
        )),
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            match (
                out.status.code(),
                serde_json::from_str::<ToolReport>(stdout.trim()),
            ) {
                (Some(0 | 1), Ok(r)) if r.error.is_none() => Ok(r),
                (code, Ok(r)) => Err(format!(
                    "axiom-audit exited {code:?}: {}",
                    r.error.unwrap_or_default()
                )),
                (code, Err(e)) => Err(format!(
                    "axiom-audit exited {code:?} without a JSON report ({e}):\n{}{}",
                    stdout.trim_end(),
                    stderr.trim_end()
                )),
            }
        }
    };
    UnitRun {
        unit: unit.clone(),
        report,
        floor,
        secs: start.elapsed().as_secs_f64(),
    }
}

/// Run every unit, `jobs` at a time.
fn run_units(
    pkg: &Path,
    units: &[(Unit, Floor)],
    extra_path: Option<&Path>,
    jobs: usize,
) -> Vec<UnitRun> {
    let next = AtomicUsize::new(0);
    let runs = Mutex::new(Vec::with_capacity(units.len()));
    std::thread::scope(|s| {
        for _ in 0..jobs.clamp(1, units.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some((unit, floor)) = units.get(i) else {
                        break;
                    };
                    let run = run_unit(pkg, unit, extra_path, *floor);
                    if let Ok(mut v) = runs.lock() {
                        v.push(run);
                    }
                }
            });
        }
    });
    let mut runs = runs.into_inner().unwrap_or_default();
    runs.sort_by(|a, b| a.unit.root.cmp(&b.unit.root));
    runs
}

/// The verdict over `runs`, which must cover exactly `expected` modules. An offense outranks
/// could-not-look: a declaration that depends on `sorryAx` has decided, whatever else failed.
fn judge(expected: &BTreeSet<String>, runs: &[UnitRun], exc: &Exceptions) -> Outcome {
    if expected.is_empty() {
        return Outcome::CouldNotLook("the closure is empty: nothing would be audited".into());
    }
    let mut offenses = Vec::new();
    let mut blind = Vec::new();
    let mut covered = BTreeSet::new();
    for run in runs {
        for m in &run.unit.members {
            if !covered.insert(m.clone()) {
                blind.push(format!("{m} is in two audit units"));
            }
        }
        let report = match &run.report {
            Ok(r) => r,
            Err(why) => {
                blind.push(format!("{}: {why}", run.unit.root));
                continue;
            }
        };
        if report.audited == 0 && run.floor.constants > 0 {
            blind.push(format!(
                "{}: audited 0 declarations, and its sources declare {}",
                run.unit.root, run.floor.constants
            ));
        } else if report.audited < run.floor.theorems {
            blind.push(format!(
                "{}: audited {} declaration(s), fewer than the {} theorem/lemma its sources declare",
                run.unit.root, report.audited, run.floor.theorems
            ));
        }
        for v in &report.violations {
            let bad: Vec<String> = v
                .axioms
                .iter()
                .filter(|a| !ALLOWED.contains(&a.as_str()) && !exc.tolerates(&v.decl, a))
                .cloned()
                .collect();
            if !bad.is_empty() {
                offenses.push(Offense {
                    unit: run.unit.root.clone(),
                    decl: v.decl.clone(),
                    axioms: bad,
                });
            }
        }
    }
    if &covered != expected {
        let missing: Vec<&String> = expected.difference(&covered).collect();
        let extra: Vec<&String> = covered.difference(expected).collect();
        blind.push(format!(
            "the audit units do not cover the closure: missing {missing:?}, extra {extra:?}"
        ));
    }
    if !offenses.is_empty() {
        for b in &blind {
            println!("::error::COULD NOT LOOK (outranked by the offenses below): {b}");
        }
        return Outcome::Offending(offenses);
    }
    if !blind.is_empty() {
        return Outcome::CouldNotLook(blind.join("; "));
    }
    Outcome::Clean
}

fn plan_units(t: &Tier) -> Result<Vec<(Unit, Floor)>> {
    units(t.closure.keys())
        .into_iter()
        .map(|u| {
            let mut floor = Floor::default();
            for m in &u.members {
                let path = &t.closure[m];
                let src =
                    std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
                floor = floor + declared(&src);
            }
            Ok((u, floor))
        })
        .collect()
}

fn unbuilt(root: &Path, t: &Tier) -> Vec<String> {
    let lib = root.join(&t.dir).join(".lake/build/lib/lean");
    t.closure
        .keys()
        .filter(|m| {
            !lib.join(lean_tier::module_path(m).with_extension("olean"))
                .is_file()
        })
        .cloned()
        .collect()
}

/// Build the pinned tool (a no-op once built). Never `lake update`: the manifest is committed.
fn build_tool(pkg: &Path) -> std::result::Result<(), String> {
    match Command::new("lake")
        .current_dir(pkg)
        .args(["build", "axiom-audit"])
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "`lake build axiom-audit` failed in {}:\n{}{}",
            pkg.display(),
            String::from_utf8_lossy(&o.stdout).trim_end(),
            String::from_utf8_lossy(&o.stderr).trim_end()
        )),
        Err(e) => Err(format!("could not run lake in {}: {e}", pkg.display())),
    }
}

fn audit_tier(root: &Path, t: &Tier, plan: &[(Unit, Floor)], jobs: usize) -> Outcome {
    let pkg = root.join(&t.dir);
    let missing = unbuilt(root, t);
    if !missing.is_empty() {
        return Outcome::CouldNotLook(format!(
            "{}: no .olean for {} module(s) of the closure ({}); build the tier first",
            t.dir,
            missing.len(),
            missing.join(", ")
        ));
    }
    let exc = match Exceptions::load(&pkg) {
        Ok(e) => e,
        Err(e) => return Outcome::CouldNotLook(format!("{e:#}")),
    };
    if let Err(why) = build_tool(&pkg) {
        return Outcome::CouldNotLook(why);
    }
    let start = Instant::now();
    let runs = run_units(&pkg, plan, None, jobs);
    let expected: BTreeSet<String> = t.closure.keys().cloned().collect();
    let outcome = judge(&expected, &runs, &exc);

    let audited: usize = runs
        .iter()
        .filter_map(|r| r.report.as_ref().ok())
        .map(|r| r.audited)
        .sum();
    let floor = runs.iter().fold(Floor::default(), |acc, r| acc + r.floor);
    let empty = runs
        .iter()
        .filter(|r| r.report.as_ref().is_ok_and(|rep| rep.audited == 0))
        .count();
    let used: BTreeSet<&String> = runs
        .iter()
        .filter_map(|r| r.report.as_ref().ok())
        .flat_map(|r| r.axioms_used.iter())
        .collect();
    let slowest = runs
        .iter()
        .max_by(|a, b| a.secs.total_cmp(&b.secs))
        .map(|r| format!(", slowest {} {:.1}s", r.unit.root, r.secs))
        .unwrap_or_default();
    println!(
        "tier {}: {} declaration(s) audited across {} module(s) in {} run(s) ({} module(s) declare nothing; sources declare {} theorem/lemma) in {:.1}s wall{}",
        t.dir,
        audited,
        expected.len(),
        runs.len(),
        empty,
        floor.theorems,
        start.elapsed().as_secs_f64(),
        slowest
    );
    println!(
        "  axioms used anywhere in the closure: {}",
        summarize(&used)
    );
    match &outcome {
        Outcome::Clean => println!(
            "ok: {} — every declaration of every first-party module in the closure of {} built target(s) is within {{{}}} plus the disclosed exceptions",
            t.dir,
            t.libs.len(),
            ALLOWED.join(", ")
        ),
        Outcome::Offending(offenses) => report_offenses(root, t, offenses),
        Outcome::CouldNotLook(_) => {}
    }
    outcome
}

/// The axioms used, with the per-declaration `native_decide` axioms folded into one count.
fn summarize(used: &BTreeSet<&String>) -> String {
    let native = used.iter().filter(|a| a.contains(NATIVE_MARK)).count();
    let mut named: Vec<&str> = used
        .iter()
        .filter(|a| !a.contains(NATIVE_MARK))
        .map(|a| a.as_str())
        .collect();
    let folded = format!("{native} native_decide axiom(s)");
    if native > 0 {
        named.push(&folded);
    }
    named.join(", ")
}

/// Print every offense, then every built target whose own closure reaches one: such a target is
/// not proven, whatever list names it.
fn report_offenses(root: &Path, t: &Tier, offenses: &[Offense]) {
    let mut by_unit: BTreeMap<&str, Vec<&Offense>> = BTreeMap::new();
    for o in offenses {
        by_unit.entry(o.unit.as_str()).or_default().push(o);
    }
    for (unit, list) in &by_unit {
        println!(
            "::error::{}: {} declaration(s) in {unit} depend on an axiom outside {{{}}}:",
            t.dir,
            list.len(),
            ALLOWED.join(", ")
        );
        for o in list {
            println!("  {} depends on {}", o.decl, o.axioms.join(", "));
        }
    }
    let bad_units: Vec<Unit> = units(t.closure.keys())
        .into_iter()
        .filter(|u| by_unit.contains_key(u.root.as_str()))
        .collect();
    let mut unproven = 0;
    for lib in &t.libs {
        let reach = match lean_tier::derive_tier(root, &t.dir, &Targets::Named(vec![lib.clone()])) {
            Ok(own) => bad_units
                .iter()
                .flat_map(|u| u.members.iter())
                .filter(|m| own.closure.contains_key(*m))
                .cloned()
                .collect::<Vec<_>>(),
            Err(e) => vec![format!("<could not derive its closure: {e:#}>")],
        };
        if !reach.is_empty() {
            unproven += 1;
            println!(
                "::error::{}: target {lib} is NOT proven — its import closure reaches {}. Move it to the research build, or close the holes.",
                t.dir,
                reach.join(", ")
            );
        }
    }
    println!(
        "FAIL: {} — {} offending declaration(s) in {} module(s); {} of {} built target(s) have a closure that reaches one",
        t.dir,
        offenses.len(),
        by_unit.len(),
        unproven,
        t.libs.len()
    );
}

fn worst(outcomes: Vec<Outcome>) -> Outcome {
    let mut offending = Vec::new();
    let mut blind = Vec::new();
    for o in outcomes {
        match o {
            Outcome::Clean => {}
            Outcome::Offending(v) => offending.extend(v),
            Outcome::CouldNotLook(w) => blind.push(w),
        }
    }
    if !offending.is_empty() {
        Outcome::Offending(offending)
    } else if !blind.is_empty() {
        Outcome::CouldNotLook(blind.join("; "))
    } else {
        Outcome::Clean
    }
}

/// `lean-axiom-audit --workflow <w> [--plan]`.
pub fn run(root: &Path, workflow: &Path, plan: bool, jobs: usize) -> Outcome {
    let tiers = match lean_tier::derive_workflow(root, workflow) {
        Ok(t) => t,
        Err(e) => return Outcome::CouldNotLook(format!("{e:#}")),
    };
    let mut outcomes = Vec::new();
    for t in &tiers {
        let units = match plan_units(t) {
            Ok(u) => u,
            Err(e) => return Outcome::CouldNotLook(format!("{}: {e:#}", t.dir)),
        };
        println!(
            "tier {}: {} built target(s), {} first-party module(s) in the closure, {} audit run(s), sources declare {} theorem/lemma",
            t.dir,
            t.libs.len(),
            t.closure.len(),
            units.len(),
            units.iter().map(|(_, f)| f.theorems).sum::<usize>()
        );
        if plan {
            for (u, f) in &units {
                println!(
                    "  {} [{}] theorems>={} constants>={}",
                    u.root,
                    u.members.join(" "),
                    f.theorems,
                    f.constants
                );
            }
            continue;
        }
        outcomes.push(audit_tier(root, t, &units, jobs));
    }
    worst(outcomes)
}

/// `lean-axiom-audit --self-test <package>`.
pub fn self_test(pkg: &Path) -> Outcome {
    match self_test_inner(pkg) {
        Ok(()) => Outcome::Clean,
        Err(e) => Outcome::CouldNotLook(format!("self-test: {e:#}")),
    }
}

/// Removes the fixture source from the package on every exit path.
struct Remove(PathBuf);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `lean` requires its input inside the package root, so the source is written there (and
/// removed on return); the `.olean` goes to `out_dir`, which the audit adds to the search path.
fn compile_fixture(pkg: &Path, out_dir: &Path) -> Result<PathBuf> {
    let src = pkg.join(format!("{FIXTURE_MODULE}.lean"));
    if src.exists() {
        bail!("{} already exists; refusing to overwrite it", src.display());
    }
    std::fs::write(&src, FIXTURE)?;
    let _remove = Remove(src.clone());
    let olean = out_dir.join(format!("{FIXTURE_MODULE}.olean"));
    let out = Command::new("lake")
        .current_dir(pkg)
        .args(["env", "lean", "-o"])
        .arg(&olean)
        .arg(format!("{FIXTURE_MODULE}.lean"))
        .output()
        .with_context(|| format!("running `lake env lean` in {}", pkg.display()))?;
    if !out.status.success() || !olean.is_file() {
        bail!(
            "the fixture did not compile in {}:\n{}{}",
            pkg.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(olean)
}

fn self_test_inner(pkg: &Path) -> Result<()> {
    build_tool(pkg).map_err(|e| anyhow!(e))?;
    let tmp = tempfile::tempdir()?;
    compile_fixture(pkg, tmp.path())?;
    let module = FIXTURE_MODULE.to_string();
    let expected: BTreeSet<String> = [module.clone()].into();
    let floor = declared(FIXTURE);
    let plan = units(&expected)
        .into_iter()
        .map(|u| (u, floor))
        .collect::<Vec<_>>();
    let runs = run_units(pkg, &plan, Some(tmp.path()), 1);
    let mut report = String::new();
    let mut failures: Vec<String> = Vec::new();

    let flagged = |o: &Outcome| -> BTreeMap<String, Vec<String>> {
        match o {
            Outcome::Offending(v) => v
                .iter()
                .map(|o| (o.decl.clone(), o.axioms.clone()))
                .collect(),
            _ => BTreeMap::new(),
        }
    };

    // 1. No exceptions: the sorry, the native_decide and the axiom are each flagged; the
    //    sorry for its own reason; the clean theorems are not.
    let bare = judge(&expected, &runs, &Exceptions::default());
    let got = flagged(&bare);
    let _ = writeln!(report, "  no exceptions: {} flagged", got.len());
    if got.get("viaSorry").map(Vec::as_slice) != Some(&[SORRY.to_string()][..]) {
        failures.push(format!(
            "viaSorry must be flagged with exactly [{SORRY}], got {:?}",
            got.get("viaSorry")
        ));
    }
    for want in ["viaNative", "viaAxiom", "probeAxiom"] {
        if !got.contains_key(want) {
            failures.push(format!("{want} was not flagged"));
        }
    }
    for clean in ["clean", "cleanClassical"] {
        if got.contains_key(clean) {
            failures.push(format!("{clean} was flagged: {:?}", got[clean]));
        }
    }

    // 2. Every other offender disclosed — and `sorryAx` named too: only the sorry remains.
    let exc = Exceptions::parse("viaNative\naxiom probeAxiom\naxiom sorryAx\n")?;
    let disclosed = judge(&expected, &runs, &exc);
    let got = flagged(&disclosed);
    let _ = writeln!(
        report,
        "  every other offender disclosed, sorryAx named: {:?}",
        got.keys().collect::<Vec<_>>()
    );
    let only_sorry: BTreeMap<String, Vec<String>> =
        [("viaSorry".to_string(), vec![SORRY.to_string()])].into();
    if got != only_sorry {
        failures.push(format!(
            "with every other offender disclosed, exactly viaSorry must remain; got {got:?}"
        ));
    }

    // 3. Non-vacuity on the fixture: the floor was reached and the run did not go blind.
    if let Some(Ok(r)) = runs.first().map(|r| &r.report) {
        let _ = writeln!(
            report,
            "  audited {} declaration(s) >= {} declared theorem(s)",
            r.audited, floor.theorems
        );
    } else {
        failures.push(format!("the fixture run produced no report: {runs:?}"));
    }

    print!("{report}");
    if !failures.is_empty() {
        bail!(
            "{} requirement(s) failed:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
    println!(
        "ok: self-test in {} — a sorry is flagged as {SORRY} and never excused, native_decide and a home-rolled axiom are flagged unless disclosed, clean theorems pass",
        pkg.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn units_count_each_module_once() {
        let mods = s(&["A", "A.B", "A.B.C", "AB", "C.D", "C.E"]);
        let got = units(&mods);
        assert_eq!(
            got,
            [
                Unit {
                    root: "A".into(),
                    members: s(&["A", "A.B", "A.B.C"])
                },
                Unit {
                    root: "AB".into(),
                    members: s(&["AB"])
                },
                Unit {
                    root: "C.D".into(),
                    members: s(&["C.D"])
                },
                Unit {
                    root: "C.E".into(),
                    members: s(&["C.E"])
                },
            ]
        );
    }

    #[test]
    fn exceptions_parse_and_sorry_is_never_excused() {
        let exc = Exceptions::parse(
            "# comment\n\nFoo.bar\naxiom Ext.fold\naxiom sorryAx\nLean.ofReduceBool\n",
        )
        .unwrap();
        assert!(!exc.tolerates("Foo.bar", SORRY));
        assert!(!exc.tolerates("anything", SORRY));
        assert!(exc.tolerates("X", "Foo.bar._native.native_decide.ax_1_2"));
        assert!(!exc.tolerates("X", "Foo.baz._native.native_decide.ax_1_2"));
        assert!(exc.tolerates("Foo.bar", REDUCE_BOOL));
        assert!(!exc.tolerates("Foo.baz", REDUCE_BOOL));
        assert!(exc.tolerates("anything", "Ext.fold"));
        assert!(!exc.tolerates("anything", "Other.axiom"));
        assert!(Exceptions::parse("two words\n").is_err());
        assert!(Exceptions::parse("axiom\n").is_err());
    }

    #[test]
    fn the_real_exceptions_files_parse() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let core = Exceptions::load(&root.join("crates/portcullis-core/lean")).unwrap();
        assert!(!core.native.is_empty() && !core.external.is_empty());
    }

    #[test]
    fn declared_counts_skip_comments_and_read_modifiers() {
        let src = "/- theorem no : True := trivial -/\n-- lemma no\ntheorem a : True := trivial\n@[simp] private theorem b : True := trivial\n  protected lemma c : True := trivial\ndef d := 1\nexample : True := trivial\n";
        assert_eq!(
            declared(src),
            Floor {
                theorems: 3,
                constants: 4
            }
        );
        assert_eq!(
            declared(FIXTURE),
            Floor {
                theorems: 5,
                constants: 6
            }
        );
        // An Aeneas Types.lean for a crate with no types: zero is the right audit.
        assert_eq!(
            declared("import Aeneas\nnamespace ck_policy\nend ck_policy\n"),
            Floor::default()
        );
    }

    fn run(
        root: &str,
        members: &[&str],
        report: std::result::Result<ToolReport, String>,
    ) -> UnitRun {
        UnitRun {
            unit: Unit {
                root: root.into(),
                members: s(members),
            },
            report,
            floor: Floor {
                theorems: 1,
                constants: 1,
            },
            secs: 0.0,
        }
    }

    fn rep(
        audited: usize,
        violations: &[(&str, &[&str])],
    ) -> std::result::Result<ToolReport, String> {
        Ok(ToolReport {
            audited,
            axioms_used: vec![],
            violations: violations
                .iter()
                .map(|(d, a)| ToolViolation {
                    decl: d.to_string(),
                    axioms: s(a),
                })
                .collect(),
            error: None,
        })
    }

    #[test]
    fn the_judge_separates_offending_from_could_not_look_from_clean() {
        let expected: BTreeSet<String> = s(&["A", "B"]).into_iter().collect();
        let none = Exceptions::default();
        assert_eq!(
            judge(
                &expected,
                &[run("A", &["A"], rep(3, &[])), run("B", &["B"], rep(1, &[]))],
                &none
            ),
            Outcome::Clean
        );
        // An offense outranks a blind unit.
        assert_eq!(
            judge(
                &expected,
                &[
                    run("A", &["A"], rep(3, &[("A.x", &["sorryAx", "propext"])])),
                    run("B", &["B"], Err("boom".into()))
                ],
                &none
            ),
            Outcome::Offending(vec![Offense {
                unit: "A".into(),
                decl: "A.x".into(),
                axioms: s(&["sorryAx"])
            }])
        );
        // A tolerated violation is not an offense.
        let exc = Exceptions::parse("axiom Ext.fold\n").unwrap();
        assert_eq!(
            judge(
                &expected,
                &[
                    run("A", &["A"], rep(3, &[("A.x", &["Ext.fold"])])),
                    run("B", &["B"], rep(1, &[]))
                ],
                &exc
            ),
            Outcome::Clean
        );
        // Nothing audited, below the floor, a missing module, an empty closure: could not look.
        for runs in [
            vec![run("A", &["A"], rep(0, &[])), run("B", &["B"], rep(1, &[]))],
            vec![run("A", &["A"], rep(3, &[])), run("B", &["B"], rep(0, &[]))],
            vec![run("A", &["A"], rep(3, &[]))],
            vec![
                run("A", &["A"], rep(3, &[])),
                run("B", &["B"], Err("x".into())),
            ],
        ] {
            assert!(
                matches!(judge(&expected, &runs, &none), Outcome::CouldNotLook(_)),
                "{runs:?}"
            );
        }
        // A module whose sources declare nothing audits zero, and that is the right answer.
        let mut empty = run("B", &["B"], rep(0, &[]));
        empty.floor = Floor::default();
        assert_eq!(
            judge(&expected, &[run("A", &["A"], rep(3, &[])), empty], &none),
            Outcome::Clean
        );
        assert!(matches!(
            judge(&BTreeSet::new(), &[], &none),
            Outcome::CouldNotLook(_)
        ));
        assert_eq!(
            [
                Outcome::Clean.exit_code(),
                Outcome::Offending(vec![]).exit_code(),
                Outcome::CouldNotLook(String::new()).exit_code()
            ],
            [0, 1, 2]
        );
    }

    #[test]
    fn the_tool_report_parses() {
        let r: ToolReport = serde_json::from_str(
            r#"{"root":"M","allowed":["propext"],"audited":4,"ok":false,"axiomsUsed":["propext","sorryAx"],"violations":[{"decl":"M.x","axioms":["sorryAx"]}]}"#,
        )
        .unwrap();
        assert_eq!(r.audited, 4);
        assert_eq!(r.violations[0].decl, "M.x");
        let e: ToolReport =
            serde_json::from_str(r#"{"ok":false,"audited":0,"error":"no such module"}"#).unwrap();
        assert_eq!(e.error.as_deref(), Some("no such module"));
    }

    #[test]
    fn the_proven_tier_plans_one_unit_per_module_family() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let tiers = lean_tier::derive_workflow(
            &root,
            Path::new(".github/workflows/portcullis-core-proven-lean.yml"),
        )
        .unwrap();
        let plan = plan_units(&tiers[0]).unwrap();
        let covered: BTreeSet<&String> = plan.iter().flat_map(|(u, _)| &u.members).collect();
        assert_eq!(covered.len(), tiers[0].closure.len());
        assert!(plan.iter().map(|(_, f)| f.theorems).sum::<usize>() > 0);
    }
}
