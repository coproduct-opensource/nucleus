//! `cargo xtask gates-can-fail` — the gate of gates: every gate must FAIL on its own subject.
//!
//! Ported from `scripts/check-gates-can-fail.sh` (now a one-line shim CI still calls by that
//! path) and `scripts/gate-inputs.sh` (deleted; `inputs.rs`), and proved verdict-identical to
//! them on the real tree before it replaced them.
//!
//! # Why this exists
//!
//! Over two days, ten defects in this repo were found and every one was green. The ones with the
//! widest blast radius were in the things watching the runtime: two flagship Lean proofs no CI
//! job compiled (#2162); three theorem builds whose failure reported success, because `cmd | tee`
//! returns TEE's status; the vendor-neutrality gate exiting 1 into a discarded pipeline; a
//! cargo-mutants job printing "All mutants caught" over a crashed run. A gate that cannot fail
//! is indistinguishable from a gate that passes.
//!
//! So: for each gate, introduce a REAL violation of the property it names, assert it exits
//! non-zero, restore, and assert it exits zero again. Both halves are required — a gate that
//! fails on everything is as useless as one that fails on nothing, and only the restore half can
//! tell them apart. Gates without a perturbation are LISTED (`table::UNCOVERED`), and their
//! count is a ratchet that may only shrink.
//!
//! # Modes
//!
//! ```text
//! gates-can-fail                       every probe
//! gates-can-fail --vacuity-only        perturbations bite; no gate run
//! gates-can-fail --baseline-only       each gate green; nothing perturbed (safe on a dirty tree)
//! gates-can-fail --changed-from <rev>  probes whose inputs moved since <rev>
//! gates-can-fail --backstop-from <rev> every probe if gate code moved, else as above
//! gates-can-fail --for-event <event> <merge-group base>   what CI calls; the base may be ''
//!     ... [--changed-files <file>] [--plan]               a given diff; print, run nothing
//! gates-can-fail --inputs script <check-x.sh> | xtask <sub>   a probe's derived inputs
//! gates-can-fail --self-test           the input derivation's fixtures alone
//! ```
//!
//! `--vacuity-only` is the cheap half run first in CI: every perturbation still CHANGES its
//! target. It is seconds, and it catches the failure churn actually produces (two probes went
//! vacuous in one day on 2026-09-18). `--baseline-only` is the other cheap half: each gate GREEN
//! before anything is perturbed — the gauntlet runs it, since a red there is a red here.
//!
//! # Scoped runs
//!
//! A probe's answer is a function of the gate's code, the fixed files it reads, and the target.
//! If the tree differs from `<rev>` in none of those, the answer is the one on `<rev>`. Those
//! INPUTS are derived from the gate's own text (`inputs.rs`), never listed by hand. NOT covered
//! is the gate's subject CORPUS (a directory it walks): a change there can (a) turn the gate red
//! on the unperturbed tree, which its own check on the same commit reports, or (b) change its
//! response to the planted violation — an undeclared input. The full runs catch (b): the merge
//! queue (`--backstop-from`) runs every probe whenever the change touches gate code, and a push
//! to main runs every probe unconditionally. A `<rev>` not in the checkout runs every probe
//! rather than guess.
//!
//! # Main is red
//!
//! A gate already red before any perturbation decides nothing under perturbation. When this run
//! has a merge base, that red is measured there too — see `main_red.rs` for the split and why
//! "could not evaluate main" is never "main is red".

#[cfg(test)]
mod lifecycle_tests;
mod inputs;
mod main_red;
mod perturb;
mod restore;
mod selftest;
use restore::Restore;
pub mod table;
mod wiring;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use inputs::{ENGINE, Index};
use main_red::{BaseRequest, BaseTree, BaseVerdict, MainRef, PreRed, Presence, Program};
use table::{Family, Probe};

/// The subcommand itself: the prober, not a subject.
pub const SELF_SUB: &str = "gates-can-fail";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Probe,
    VacuityOnly,
    BaselineOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeKind {
    Full,
    Scoped,
    Backstop,
}

impl ScopeKind {
    fn name(self) -> &'static str {
        match self {
            ScopeKind::Full => "full",
            ScopeKind::Scoped => "scoped",
            ScopeKind::Backstop => "backstop",
        }
    }
}

#[derive(Debug)]
enum Request {
    Run(Opts),
    Inputs { kind: String, name: String },
    SelfTest,
}

#[derive(Clone, Debug)]
struct Opts {
    mode: Mode,
    scope: ScopeKind,
    base: String,
    changed_files: Option<String>,
    plan: bool,
}

/// The command line, with the script's own errors and exit code 2.
fn parse(args: &[String]) -> Result<Request, String> {
    let mut vacuity = false;
    let mut baseline = false;
    let mut scope = ScopeKind::Full;
    let mut base = String::new();
    let mut changed_files = None;
    let mut plan = false;
    let mut i = 0;
    let arg = |i: usize| args.get(i).cloned();
    while i < args.len() {
        match args[i].as_str() {
            "--baseline-only" => baseline = true,
            "--vacuity-only" => vacuity = true,
            // The revision may be EMPTY (a workflow expression that evaluated to nothing). A
            // base nobody can name runs every probe and says so; only a MISSING one is refused.
            "--changed-from" | "--backstop-from" => {
                let flag = args[i].clone();
                let Some(rev) = arg(i + 1) else {
                    return Err(format!("ERROR: {flag} needs a revision"));
                };
                scope = if flag == "--changed-from" {
                    ScopeKind::Scoped
                } else {
                    ScopeKind::Backstop
                };
                base = rev;
                i += 1;
            }
            // The workflow's one call, so which events get which scope is decided HERE. A pull
            // request's checkout is its merge commit, whose first parent is the base; the merge
            // queue names its base. Anything else -- a push to main above all -- is the full
            // run. ALWAYS two arguments, the second possibly empty (#3062).
            "--for-event" => {
                let (Some(event), Some(mg_base)) = (arg(i + 1), arg(i + 2)) else {
                    return Err("ERROR: --for-event needs <event> <merge-group base> (the base may be empty)".into());
                };
                match event.as_str() {
                    "pull_request" => {
                        scope = ScopeKind::Scoped;
                        base = "HEAD^1".into();
                    }
                    "merge_group" => {
                        scope = ScopeKind::Backstop;
                        base = mg_base;
                    }
                    _ => scope = ScopeKind::Full,
                }
                i += 2;
            }
            "--changed-files" => {
                let Some(f) = arg(i + 1).filter(|f| !f.is_empty()) else {
                    return Err("ERROR: --changed-files needs a file".into());
                };
                changed_files = Some(f);
                i += 1;
            }
            "--plan" => plan = true,
            "--inputs" => {
                let (Some(kind), Some(name)) = (arg(i + 1), arg(i + 2)) else {
                    return Err("ERROR: --inputs needs script <check-x.sh> | xtask <sub>".into());
                };
                return Ok(Request::Inputs { kind, name });
            }
            "--self-test" => return Ok(Request::SelfTest),
            other => return Err(format!("ERROR: unknown argument '{other}'")),
        }
        i += 1;
    }
    let mode = match (vacuity, baseline) {
        (false, false) => Mode::Probe,
        (true, false) => Mode::VacuityOnly,
        (false, true) => Mode::BaselineOnly,
        (true, true) => {
            return Err(
                "ERROR: --vacuity-only and --baseline-only are each one half; pass one.".into(),
            );
        }
    };
    if changed_files.is_some() && scope == ScopeKind::Full {
        scope = ScopeKind::Scoped;
        base = "the base of the given diff".into();
    }
    if (scope != ScopeKind::Full || plan) && mode != Mode::Probe {
        // The cheap halves are unscoped on purpose: they are seconds, and the vacuity half is
        // the one that catches a perturbation the tree moved under -- which any diff can do.
        return Err(
            "ERROR: --vacuity-only and --baseline-only always run every probe; they take no scope."
                .into(),
        );
    }
    if plan && scope == ScopeKind::Full {
        return Err("ERROR: --plan needs a diff: --changed-from, --backstop-from, --for-event or --changed-files.".into());
    }
    Ok(Request::Run(Opts {
        mode,
        scope,
        base,
        changed_files,
        plan,
    }))
}

/// The diff a scoped run is decided against, and the reason every probe runs, when one does.
#[derive(Clone, Debug)]
struct Scope {
    kind: ScopeKind,
    base_label: String,
    all: Option<String>,
    changed: Vec<String>,
    main: MainRef,
}

fn git_ok(root: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .args(args)
        .current_dir(root)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The scope, and the lines it prints.
fn scope_for(root: &Path, opts: &Opts) -> (Scope, Vec<String>) {
    let mut s = Scope {
        kind: opts.scope,
        base_label: opts.base.clone(),
        all: None,
        changed: Vec::new(),
        main: MainRef::NotApplicable,
    };
    if opts.scope == ScopeKind::Full {
        return (s, Vec::new());
    }
    if let Some(f) = &opts.changed_files {
        s.changed = fs::read_to_string(f)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
    } else if opts.base.is_empty() {
        s.base_label = "(no base)".into();
        s.all = Some("no base revision was given, so the diff cannot be read".into());
        s.main = MainRef::Unreadable {
            why: "no base revision was given".into(),
            fetch: None,
        };
    } else {
        let commit = git_ok(
            root,
            &[
                "rev-parse",
                "--verify",
                "-q",
                &format!("{}^{{commit}}", opts.base),
            ],
        )
        .map(|o| o.trim().to_string());
        match commit {
            None => {
                s.all = Some(format!(
                    "{} is not present in this checkout, so the diff cannot be read",
                    opts.base
                ));
                let fetchable =
                    opts.base.len() == 40 && opts.base.chars().all(|c| c.is_ascii_hexdigit());
                s.main = MainRef::Unreadable {
                    why: format!("{} is not present in this checkout", opts.base),
                    fetch: fetchable.then(|| opts.base.clone()),
                };
            }
            Some(sha) => {
                match git_ok(
                    root,
                    &["diff", "--name-only", "--no-renames", &opts.base, "HEAD"],
                ) {
                    None => {
                        s.all = Some(format!(
                            "git diff {} HEAD failed, so the diff cannot be read",
                            opts.base
                        ));
                    }
                    Some(out) => {
                        s.changed = out.lines().map(str::to_string).collect();
                        let short = sha.get(..9).unwrap_or(&sha).to_string();
                        s.base_label = format!("{} ({short})", opts.base);
                    }
                }
                s.main = MainRef::Known(sha);
            }
        }
    }
    let mut lines = vec![format!(
        "scope: {} from {} — {} path(s) changed",
        s.kind.name(),
        s.base_label,
        s.changed.len()
    )];
    apply_engine_and_backstop(&mut s);
    if let Some(why) = &s.all {
        lines.push(format!("scope: running EVERY probe — {why}"));
    }
    (s, lines)
}

/// Any engine path in the diff selects everything; in the backstop, so does any gate code.
fn apply_engine_and_backstop(s: &mut Scope) {
    if s.all.is_none() {
        'outer: for e in ENGINE {
            for f in &s.changed {
                if inputs::matches(e, f) {
                    s.all = Some(format!("the probe engine changed ({f})"));
                    break 'outer;
                }
            }
        }
    }
    // The roots are the merge queue's own filter from before scoping existed, widened to every
    // manifest and the toolchain, so the queue re-proves at least what it did then.
    if s.kind == ScopeKind::Backstop && s.all.is_none() {
        let roots = regex::Regex::new(
            r"^scripts/|^\.github/|^crates/xtask/|(^|/)Cargo\.toml$|^Cargo\.lock$|^rust-toolchain\.toml$|^\.cargo/",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        if let Some(hit) = s.changed.iter().find(|f| roots.is_match(f)) {
            s.all = Some(format!("backstop: {hit} is gate code"));
        }
    }
}

/// A scope built from a fixture diff, as `--changed-files` builds one.
fn fixture_scope(kind: ScopeKind, label: &str, changed: &[&str]) -> Scope {
    let mut s = Scope {
        kind,
        base_label: label.to_string(),
        all: None,
        changed: changed.iter().map(|c| (*c).to_string()).collect(),
        main: MainRef::NotApplicable,
    };
    apply_engine_and_backstop(&mut s);
    s
}

impl Probe {
    /// What the run prints for this probe, which is also what the self-test counts.
    fn label(&self) -> String {
        match &self.family {
            Family::Script { gate, flags: "" } => format!("{gate} ({})", self.desc),
            Family::Script { gate, flags } => format!("{gate} {flags} ({})", self.desc),
            Family::XtaskFlagged { sub, flags } => format!("xtask {sub} {flags} ({})", self.desc),
            Family::Xtask { sub }
            | Family::XtaskPartial { sub, .. }
            | Family::XtaskGenerated { sub, .. } => format!("xtask {sub} ({})", self.desc),
        }
    }

    /// The name a verdict line leads with.
    fn name(&self) -> String {
        match &self.family {
            Family::Script { gate, .. } => (*gate).to_string(),
            Family::XtaskFlagged { sub, flags } => format!("xtask {sub} {flags}"),
            Family::Xtask { sub }
            | Family::XtaskPartial { sub, .. }
            | Family::XtaskGenerated { sub, .. } => format!("xtask {sub}"),
        }
    }

    /// The probe's derived inputs: its gate's, its target, any file its flags name, and the
    /// files its own functions name.
    fn inputs(&self, idx: &Index) -> BTreeSet<String> {
        let (mut set, flags) = match &self.family {
            Family::Script { gate, flags } => {
                (idx.script_inputs(&format!("scripts/{gate}")), *flags)
            }
            Family::Xtask { sub } | Family::XtaskPartial { sub, .. } => (idx.xtask_inputs(sub), ""),
            Family::XtaskFlagged { sub, flags } => (idx.xtask_inputs(sub), *flags),
            Family::XtaskGenerated { sub, ci_flags, .. } => (idx.xtask_inputs(sub), *ci_flags),
        };
        set.insert(self.target.to_string());
        set.extend(idx.resolve(flags.split_whitespace()));
        let mut fns: Vec<&str> = Vec::new();
        if let Family::XtaskGenerated { generated, .. } = &self.family {
            fns.extend(generated.first().map(|g| g.gen_name));
            fns.push(self.perturb.name);
            fns.extend(generated.get(1).map(|g| g.gen_name));
        } else {
            fns.push(self.perturb.name);
        }
        set.extend(idx.function_inputs(&fns));
        set.retain(|s| !s.is_empty());
        set
    }
}

enum Decision {
    Run(String),
    Skip(usize),
}

fn decide(idx: &Index, scope: &Scope, probe: &Probe) -> Decision {
    if let Some(why) = &scope.all {
        return Decision::Run(why.clone());
    }
    let inputs = probe.inputs(idx);
    match inputs::first_hit(&inputs, &scope.changed) {
        Some((f, input)) => Decision::Run(format!("{f} changed (input {input})")),
        None => Decision::Skip(inputs.len()),
    }
}

/// One gate run as the probe asks it: program, the flags it is run with, and the base question.
struct Invocation {
    program: Program,
    args: Vec<String>,
    base: BaseRequest,
}

struct Harness {
    root: PathBuf,
    opts: Opts,
    scope: Scope,
    index: Option<Index>,
    failures: u32,
    covered: u32,
    selected: u32,
    skipped: u32,
    baseline_seen: BTreeSet<String>,
    base_tree: Option<Result<BaseTree, String>>,
    base_cache: BTreeMap<String, BaseVerdict>,
    base_seconds: f64,
    main_red: BTreeMap<String, String>,
    stop: Arc<AtomicBool>,
}

fn out(line: &str) {
    println!("{line}");
}

impl Harness {
    fn index(&mut self) -> &Index {
        if self.index.is_none() {
            match Index::new(&self.root) {
                Ok(i) => self.index = Some(i),
                Err(e) => {
                    out(&format!("ERROR: could not index the tree: {e}"));
                    std::process::exit(2);
                }
            }
        }
        self.index.as_ref().unwrap_or_else(|| unreachable!())
    }

    /// SIGINT/SIGTERM: restore whatever is perturbed, drop the base tree, and stop. A
    /// half-perturbed tree left behind by an interrupted run is worse than no check.
    fn interrupted(&mut self, guard: Option<&mut Restore>) {
        if self.stop.load(Ordering::SeqCst) {
            if let Some(g) = guard {
                if !self.restore(g) {
                    std::process::exit(2);
                }
            }
            self.base_tree = None;
            out("interrupted: restored the perturbed file and stopped.");
            std::process::exit(130);
        }
    }

    fn restore(&mut self, guard: &mut Restore) -> bool {
        match guard.restore() {
            Ok(()) => true,
            Err(error) => {
                self.fail(&[format!(
                    "  FAIL  could not restore the perturbed file: {error}"
                )]);
                false
            }
        }
    }

    fn run_gate(&mut self, inv: &Invocation, guard: Option<&mut Restore>) -> i32 {
        let rc = main_red::status_of(main_red::gate_command(
            &inv.program,
            &inv.args,
            &self.root,
            None,
        ));
        self.interrupted(guard);
        rc
    }

    fn fail(&mut self, lines: &[String]) {
        for l in lines {
            out(l);
        }
        self.failures += 1;
    }

    /// Prints the decision; true when the probe should RUN.
    fn scope_decide(&mut self, probe: &Probe) -> bool {
        if self.scope.kind == ScopeKind::Full {
            return true;
        }
        let label = probe.label();
        let scope = self.scope.clone();
        let decision = decide(self.index(), &scope, probe);
        match decision {
            Decision::Skip(n) => {
                out(&format!(
                    "  skip  {label} — none of its {n} inputs changed since {}",
                    scope.base_label
                ));
                self.skipped += 1;
                false
            }
            Decision::Run(why) => {
                out(&format!("  run   {label} — {why}"));
                self.selected += 1;
                !self.opts.plan
            }
        }
    }

    fn seen(&mut self, key: String) -> bool {
        self.opts.mode == Mode::BaselineOnly && !self.baseline_seen.insert(key)
    }

    /// The gate was red before anything was touched. Charged, unless main is red the same way.
    fn already_red(
        &mut self,
        name: &str,
        rc: i32,
        base: &BaseRequest,
        partial_flags: Option<&str>,
    ) {
        if matches!(self.scope.main, MainRef::NotApplicable) {
            let lines: Vec<String> = match partial_flags {
                Some(f) => vec![
                    format!("  FAIL  {name} — bare (without '{f}') the gate already exits {rc}"),
                    "        on a clean tree, so a red under perturbation would not be evidence.".into(),
                ],
                None => vec![
                    format!("  FAIL  {name} — already red (exit {rc}) BEFORE any perturbation."),
                    "        Not a restore failure and not a broken probe: this gate is failing on".into(),
                    "        this tree for its own reasons, so nothing it says under perturbation".into(),
                    "        would be evidence. Fix that red first, then this probe means something.".into(),
                ],
            };
            self.fail(&lines);
            return;
        }
        let (verdict, short) = self.base_verdict(base);
        let head = format!("{name} — already red (exit {rc}) BEFORE any perturbation");
        match main_red::classify(rc, &verdict) {
            PreRed::MainIsRed { base_rc } => {
                out(&format!("  main  {head}, and red on main ({short}, exit {base_rc}) too."));
                out("        Main's red, not this change's: reported, not charged here. Every other");
                out("        probe still runs and still decides this run.");
                if !self.main_red.contains_key(&base.key) {
                    // One annotation per gate, whatever number of its probes asked.
                    out(&format!(
                        "::warning title=main is red::{name} is red on the merge base {short} (exit {base_rc}) \
                         as well as on this change. Reported once and not charged to this change; it needs \
                         fixing on main, and its probes cannot decide anything until it is."
                    ));
                    self.main_red.insert(base.key.clone(), format!("{name} (exit {base_rc} on {short})"));
                }
            }
            PreRed::PrRegression => self.fail(&[
                format!("  FAIL  {head}, and GREEN on main ({short})."),
                "        This change turned it red. Fix that red first, then this probe means something.".into(),
            ]),
            PreRed::DifferentRed { base_rc } => self.fail(&[
                format!("  FAIL  {head}; main is red too, but with exit {base_rc}."),
                "        Not the same red, so it is not main's to own: this change moved it.".into(),
            ]),
            PreRed::NewGate(why) => self.fail(&[
                format!("  FAIL  {head}, and absent on main: {why}."),
                "        This change brought the gate in red.".into(),
            ]),
            PreRed::Unmeasured(why) => self.fail(&[
                format!("  FAIL  {head}, and main's verdict could not be measured:"),
                format!("        {why}. Could not look is not \"main is red\" (ADR 0007 A), so this is charged here."),
            ]),
        }
    }

    fn base_verdict(&mut self, req: &BaseRequest) -> (BaseVerdict, String) {
        if self.base_tree.is_none() {
            let t = main_red::resolve(&self.root, &self.scope.main)
                .and_then(|sha| BaseTree::create(&self.root, &sha));
            self.base_tree = Some(t);
        }
        let short = match &self.base_tree {
            Some(Ok(t)) => t.short().to_string(),
            _ => "the merge base".to_string(),
        };
        if let Some(v) = self.base_cache.get(&req.key) {
            return (v.clone(), short);
        }
        let v = match &self.base_tree {
            Some(Ok(t)) => {
                let (v, secs) = t.verdict(req);
                self.base_seconds += secs;
                out(&format!("        (measured on main in {secs:.1}s)"));
                v
            }
            Some(Err(why)) => BaseVerdict::CouldNotEvaluate(why.clone()),
            None => BaseVerdict::CouldNotEvaluate("no base tree".into()),
        };
        self.interrupted(None);
        self.base_cache.insert(req.key.clone(), v.clone());
        (v, short)
    }

    fn probe(&mut self, probe: &Probe) {
        if !self.scope_decide(probe) {
            return;
        }
        let name = probe.name();
        // Family preflight: CI parity, the target, and the invocation the probe runs.
        let mut temps: Vec<tempfile::NamedTempFile> = Vec::new();
        let (inv, dedup, partial) = match &probe.family {
            Family::Script { gate, flags } => {
                if self.seen(format!("<{gate}|{flags}>")) {
                    return;
                }
                if wiring::script_workflow_hits(&self.root, gate) == 0 {
                    return self.fail(&[
                        format!("  FAIL  {gate} — no workflow under .github/workflows/ invokes it"),
                        "        The gate can fail locally and never run. A gate CI does not"
                            .into(),
                        "        call enforces nothing, however carefully it is written.".into(),
                    ]);
                }
                let inv = wiring::script_invocations(&self.root, gate);
                if !inv.iter().any(|f| f == flags) {
                    let in_ci = inv.first().cloned().unwrap_or_default();
                    return self.fail(&[
                        format!("  FAIL  {gate} — CI invokes it as '{gate} {in_ci}' but this probe uses '{gate} {flags}'"),
                        "        Probing a gate differently from CI tests something CI does not run.".into(),
                    ]);
                }
                if !self.root.join("scripts").join(gate).is_file() {
                    return self.fail(&[format!("  ERROR: scripts/{gate} does not exist")]);
                }
                let invocation = Invocation {
                    program: Program::Script(gate),
                    args: split(flags),
                    base: BaseRequest {
                        key: format!("<{gate}|{flags}>"),
                        presence: Presence::Script(gate),
                        program: Program::Script(gate),
                        flags: (*flags).to_string(),
                        generated: &[],
                    },
                };
                let ok = if flags.is_empty() {
                    format!("  ok    {gate}")
                } else {
                    format!("  ok    {gate} {flags}")
                };
                (invocation, ok, None)
            }
            Family::Xtask { sub } => {
                if self.seen(format!("<xtask {sub}>")) {
                    return;
                }
                let inv = wiring::cmdsub(&wiring::xtask_invocations_joined(&self.root, sub));
                if inv.is_empty() && !wiring::xtask_mentioned(&self.root, sub) {
                    return self.fail(&[format!("  FAIL  xtask {sub} — no workflow invokes it")]);
                }
                if !inv.split('\n').any(str::is_empty) {
                    return self.fail(&[
                        format!(
                            "  FAIL  xtask {sub} — CI invokes it with flags ({})",
                            inv.split('\n').next().unwrap_or("")
                        ),
                        "        but probe_xtask runs it bare. Probing a gate differently from CI"
                            .into(),
                        "        tests something CI does not run.".into(),
                    ]);
                }
                if !self.root.join(probe.target).is_file() {
                    return self.fail(&[format!("  ERROR: {} does not exist", probe.target)]);
                }
                (
                    xtask_inv(sub, "", &[]),
                    format!("  ok    xtask {sub}"),
                    None,
                )
            }
            Family::XtaskFlagged { sub, flags } => {
                let inv = wiring::xtask_invocations(&self.root, sub);
                let lines = wiring::cmdsub_lines(&inv);
                if !lines.iter().any(|l| l == flags) {
                    return self.fail(&[
                        format!("  FAIL  xtask {sub} {flags} — no workflow invokes it with exactly those flags."),
                        format!("        CI runs: {}", wiring::cmdsub(&inv).replace('\n', "/")),
                        "        Probing a form CI does not run tests something CI does not run.".into(),
                    ]);
                }
                if !self.root.join(probe.target).is_file() {
                    return self.fail(&[format!("  ERROR: {} does not exist", probe.target)]);
                }
                if self.seen(format!("<xtask {sub} {flags}>")) {
                    return;
                }
                (
                    xtask_inv(sub, flags, &[]),
                    format!("  ok    xtask {sub} {flags}"),
                    None,
                )
            }
            Family::XtaskPartial {
                sub,
                ci_flags,
                marker,
            } => {
                let inv = wiring::xtask_invocations(&self.root, sub);
                if wiring::cmdsub(&inv).is_empty() {
                    return self.fail(&[format!("  FAIL  xtask {sub} — no workflow invokes it")]);
                }
                let lines = wiring::cmdsub_lines(&inv);
                if let Some(unexpected) = lines.iter().find(|l| l != ci_flags) {
                    return self.fail(&[
                        format!("  FAIL  xtask {sub} — CI invokes it as '{unexpected}',"),
                        format!("        but this probe is licensed against '{ci_flags}'. The flags moved:"),
                        "        re-read what the probe still covers before widening this.".into(),
                    ]);
                }
                if !self.root.join(probe.target).is_file() {
                    return self.fail(&[format!("  ERROR: {} does not exist", probe.target)]);
                }
                if self.seen(format!("<xtask {sub}>")) {
                    return;
                }
                (
                    xtask_inv(sub, "", &[]),
                    format!("  ok    xtask {sub}"),
                    Some((*ci_flags, *marker)),
                )
            }
            Family::XtaskGenerated {
                sub,
                ci_flags,
                generated,
            } => {
                let inv = wiring::xtask_invocations_joined(&self.root, sub);
                if wiring::cmdsub(&inv).is_empty() {
                    return self.fail(&[format!("  FAIL  xtask {sub} — no workflow invokes it")]);
                }
                if !wiring::cmdsub_lines(&inv).iter().any(|l| l == ci_flags) {
                    return self.fail(&[
                        format!(
                            "  FAIL  xtask {sub} — CI invokes it as: {}",
                            wiring::cmdsub(&inv).split('\n').next().unwrap_or("")
                        ),
                        format!("        but this probe claims parity with: {ci_flags}"),
                        "        Update the probe to match CI, or CI to match the probe.".into(),
                    ]);
                }
                // The probe's own flags may differ from CI's ONLY by the generated files' paths,
                // and those must sit OUTSIDE the repository.
                let mut local = (*ci_flags).to_string();
                for (n, g) in generated.iter().enumerate() {
                    let file = match tempfile::Builder::new()
                        .prefix(&format!("{}.", g.temp.0))
                        .suffix(g.temp.1)
                        .tempfile()
                    {
                        Ok(f) => f,
                        Err(e) => {
                            return self
                                .fail(&[format!("  FAIL  xtask {sub} — no temp file: {e}")]);
                        }
                    };
                    let path = file.path().to_string_lossy().into_owned();
                    let next = local.replacen(g.ci_name, &path, 1);
                    if next == local {
                        return self.fail(&if n == 0 {
                            vec![
                                format!("  FAIL  xtask {sub} — '{}' does not appear in CI's flags, so there is", g.ci_name),
                                "        nothing for the probe to substitute; use probe_xtask instead.".into(),
                            ]
                        } else {
                            vec![format!("  FAIL  xtask {sub} — '{}' does not appear in CI's flags either.", g.ci_name)]
                        });
                    }
                    if !file.path().is_absolute() {
                        return self.fail(&[format!("  FAIL  xtask {sub} — generated input '{path}' is a repo-relative path.")]);
                    }
                    local = next;
                    temps.push(file);
                }
                for (g, file) in generated.iter().zip(&temps) {
                    let p = file.path();
                    if !(g.write)(&self.root, p) {
                        return self.fail(&[format!(
                            "  FAIL  xtask {sub} — could not generate {} for the probe",
                            p.display()
                        )]);
                    }
                    let len = fs::metadata(p).map(|m| m.len());
                    if g.must_be_nonempty && !matches!(len, Ok(n) if n > 0) {
                        return self.fail(&[format!(
                            "  FAIL  xtask {sub} — {} produced nothing; an empty input is not a probe",
                            g.gen_name
                        )]);
                    }
                    if len.is_err() {
                        return self.fail(&[format!(
                            "  FAIL  xtask {sub} — {} produced no file at {}",
                            g.gen_name,
                            p.display()
                        )]);
                    }
                }
                if !self.root.join(probe.target).is_file() {
                    return self.fail(&[format!("  ERROR: {} does not exist", probe.target)]);
                }
                if self.seen(format!("<xtask {sub} {local}>")) {
                    return;
                }
                let mut invocation = xtask_inv(sub, ci_flags, generated);
                invocation.args = split(&local);
                (invocation, format!("  ok    xtask {sub}"), None)
            }
        };

        // The BASELINE, before anything is touched: `restored_rc` alone cannot tell "my
        // perturbation broke it" from "it was already red when I got here" (PR #2835). Skipped
        // with the other runs in vacuity mode.
        if self.opts.mode != Mode::VacuityOnly {
            let rc = self.run_gate(&inv, None);
            if rc != 0 {
                self.already_red(&name, rc, &inv.base, partial.map(|(f, _)| f));
                return;
            }
        }
        if self.opts.mode == Mode::BaselineOnly {
            out(&dedup);
            self.covered += 1;
            return;
        }

        let target = self.root.join(probe.target);
        let original = match fs::read(&target) {
            Ok(b) => b,
            Err(e) => {
                return self.fail(&[format!("  ERROR: {} could not be read: {e}", probe.target)]);
            }
        };
        let mut guard = Restore::new(target.clone(), original.clone());
        let before = String::from_utf8_lossy(&original).into_owned();
        let perturbed = (probe.perturb.apply)(&self.root, &before);
        if let Some(why) = &perturbed.complaint {
            out(&format!("  ERROR: {why}"));
        }
        if let Err(e) = fs::write(&target, perturbed.text.as_bytes()) {
            if !self.restore(&mut guard) {
                return;
            }
            return self.fail(&[format!("  ERROR: could not write {}: {e}", probe.target)]);
        }

        // Did the perturbation DO anything? One whose pattern no longer matches is a no-op, the
        // gate then passes on an unchanged tree, and the probe would report a working gate as
        // broken (#2582).
        if fs::read(&target).ok().as_deref() == Some(original.as_slice()) {
            if !self.restore(&mut guard) {
                return;
            }
            let mut lines = vec![format!(
                "  FAIL  {name} — the perturbation for '{}' changed {} not at all",
                probe.desc, probe.target
            )];
            if matches!(probe.family, Family::Script { .. }) {
                lines.push(
                    "        It is a no-op, so this probe tests nothing. The file moved".into(),
                );
                lines.push(
                    "        under it: update the perturbation to match what is there now.".into(),
                );
            }
            return self.fail(&lines);
        }

        if self.opts.mode == Mode::VacuityOnly {
            if !self.restore(&mut guard) {
                return;
            }
            self.covered += 1;
            return;
        }

        let (perturbed_rc, perturbed_out) = if partial.is_some() {
            let (rc, text) = main_red::output_of(main_red::gate_command(
                &inv.program,
                &inv.args,
                &self.root,
                None,
            ));
            self.interrupted(Some(&mut guard));
            (rc, text)
        } else {
            (self.run_gate(&inv, Some(&mut guard)), String::new())
        };
        if !self.restore(&mut guard) {
            return;
        }
        let restored_rc = self.run_gate(&inv, None);
        drop(temps);

        self.covered += 1;
        if perturbed_rc == 0 {
            let mut lines = vec![format!(
                "  FAIL  {name} — {} did NOT fail the gate (exit 0)",
                probe.desc
            )];
            if matches!(probe.family, Family::Script { .. }) {
                lines.push("        The gate cannot detect the thing it is named for.".into());
            }
            return self.fail(&lines);
        }
        if let Some((_, marker)) = partial {
            if !perturbed_out.contains(marker) {
                return self.fail(&[
                    format!(
                        "  FAIL  {name} — {} red the gate, but not for the reason under test:",
                        probe.desc
                    ),
                    format!(
                        "        expected '{marker}' in the output, got: {}",
                        perturbed_out.lines().next().unwrap_or("")
                    ),
                ]);
            }
        }
        if restored_rc != 0 {
            let lines: Vec<String> = match probe.family {
                Family::Script { .. } => vec![
                    format!("  FAIL  {name} — green before, still failing (exit {restored_rc}) after restore:"),
                    "        the perturbation left something behind. The baseline was checked above,".into(),
                    "        so this is the restore and not a pre-existing red.".into(),
                    "        Either the restore is broken or the gate fails on everything,".into(),
                    "        and a gate that always fails detects nothing either.".into(),
                ],
                Family::Xtask { .. } => vec![
                    format!("  FAIL  {name} — green before, still failing (exit {restored_rc}) after restore:"),
                    "        the perturbation left something behind. The baseline was checked above,".into(),
                    "        so this is the restore and not a pre-existing red.".into(),
                ],
                _ => vec![format!("  FAIL  {name} — still failing (exit {restored_rc}) after restore")],
            };
            return self.fail(&lines);
        }
        out(&format!(
            "  ok    {name} — RED on {}, GREEN when restored",
            probe.desc
        ));
    }
}

fn split(flags: &str) -> Vec<String> {
    flags.split_whitespace().map(str::to_string).collect()
}

fn xtask_inv(sub: &'static str, flags: &str, generated: &'static [table::Generated]) -> Invocation {
    Invocation {
        program: Program::Xtask(sub),
        args: split(flags),
        base: BaseRequest {
            key: if flags.is_empty() {
                format!("xtask {sub}")
            } else {
                format!("xtask {sub} {flags}")
            },
            presence: Presence::Xtask(sub),
            program: Program::Xtask(sub),
            flags: flags.to_string(),
            generated,
        },
    }
}

fn repo_root() -> PathBuf {
    git_ok(Path::new("."), &["rev-parse", "--show-toplevel"])
        .map(|s| PathBuf::from(s.trim()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The entry point; returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let req = match parse(args) {
        Ok(r) => r,
        Err(e) => {
            out(&e);
            return 2;
        }
    };
    let root = repo_root();
    let opts = match req {
        Request::Inputs { kind, name } => return print_inputs(&root, &kind, &name),
        Request::SelfTest => {
            return match Index::new(&root) {
                Ok(idx) => i32::from(!selftest::run(&root, &idx)),
                Err(e) => {
                    out(&format!("ERROR: {e}"));
                    2
                }
            };
        }
        Request::Run(o) => o,
    };

    // A dirty tree cannot be safely perturbed: the restore would have to guess what was yours.
    if opts.mode != Mode::BaselineOnly && !opts.plan {
        let dirty = git_ok(&root, &["status", "--porcelain"]);
        if dirty.as_deref().is_none_or(|s| !s.trim().is_empty()) {
            out("ERROR: the working tree is dirty. This script edits real files and");
            out("restores them from a copy; running it over uncommitted work risks that");
            out("work. Commit or stash first.");
            return 1;
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }

    let (scope, lines) = scope_for(&root, &opts);
    for l in &lines {
        out(l);
    }
    let mut h = Harness {
        root: root.clone(),
        opts: opts.clone(),
        scope,
        index: None,
        failures: 0,
        covered: 0,
        selected: 0,
        skipped: 0,
        baseline_seen: BTreeSet::new(),
        base_tree: None,
        base_cache: BTreeMap::new(),
        base_seconds: 0.0,
        main_red: BTreeMap::new(),
        stop,
    };

    // The derivation that scoping trusts, tested before it is trusted, in every mode that runs a
    // gate. Never from `--plan` itself, and the cheap halves stay cheap.
    if !opts.plan && opts.mode == Mode::Probe {
        out("The input derivation's own fixtures (gates-can-fail --self-test):");
        let ok = {
            let idx = h.index();
            selftest::run(&root, idx)
        };
        if !ok {
            h.failures += 1;
        }
        out("");
    }

    out("Probing whether each gate fails on its own subject...");
    out("");
    let probes = table::probes();
    for p in &probes {
        h.probe(p);
    }

    if opts.plan {
        out("");
        out(&format!(
            "plan: {} probe(s) would run, {} skipped. NOTHING WAS RUN.",
            h.selected, h.skipped
        ));
        return 0;
    }
    let code = account(&mut h, &probes);
    h.base_tree = None;
    code
}

/// The ratchet, the domain, and the verdict.
fn account(h: &mut Harness, probes: &[Probe]) -> i32 {
    let root = h.root.clone();
    out("");
    out(&format!("Covered: {} gate(s) probed.", h.covered));
    if h.scope.kind != ScopeKind::Full {
        out(&format!(
            "Scope: {} probe(s) selected, {} skipped because nothing they read changed since {}.",
            h.selected, h.skipped, h.scope.base_label
        ));
    }
    out(&format!(
        "Uncovered: {} (ceiling {}) — these have no perturbation yet:",
        table::UNCOVERED.len(),
        table::UNCOVERED_CEILING
    ));
    for u in table::UNCOVERED {
        out(&format!("    {u}"));
    }
    out(&format!(
        "Self-falsified in-workflow: {} — reds-on-revert runs on a toolchain this job lacks:",
        table::SELF_FALSIFIED.len()
    ));
    for s in table::SELF_FALSIFIED {
        out(&format!("    {s}"));
    }
    if table::UNCOVERED.len() > table::UNCOVERED_CEILING {
        out("");
        out(&format!(
            "VIOLATION: uncovered gate count rose above {}.",
            table::UNCOVERED_CEILING
        ));
        out("A new gate was added without a perturbation proving it can fail.");
        h.failures += 1;
    }

    // The ratchet's own completeness: derive the domain instead of declaring it -- glob the
    // gates, subtract the probed and the listed, and fail on the remainder.
    let listed = |rows: &[&str], gate: &str| {
        rows.iter().any(|r| {
            r.strip_prefix(gate)
                .is_some_and(|rest| rest.starts_with([' ', '\t']))
        })
    };
    let mut unaccounted: Vec<String> = Vec::new();
    let mut unwired: Vec<String> = Vec::new();
    let scripts = wiring::gate_scripts(&root);
    let probed_scripts: BTreeSet<&str> = table::probed_shell_gates();
    for gate in &scripts {
        if gate == "check-gates-can-fail.sh" {
            continue;
        }
        // Wiring is checked for EVERY gate, not just the probed ones.
        if wiring::script_workflow_hits(&root, gate) == 0 {
            unwired.push(gate.clone());
        }
        if probed_scripts.contains(gate.as_str())
            || listed(table::UNCOVERED, gate)
            || listed(table::SELF_FALSIFIED, gate)
        {
            continue;
        }
        unaccounted.push(gate.clone());
    }

    // The SECOND half of the domain: gates that are `cargo xtask` subcommands, derived from
    // everything CI runs -- workflows, scripts, composite actions.
    let xtask_gates = wiring::xtask_domain(&root);
    let probed_subs: BTreeSet<&str> = probes
        .iter()
        .filter_map(|p| match p.family {
            Family::Script { .. } => None,
            Family::Xtask { sub }
            | Family::XtaskFlagged { sub, .. }
            | Family::XtaskPartial { sub, .. }
            | Family::XtaskGenerated { sub, .. } => Some(sub),
        })
        .collect();
    for sub in &xtask_gates {
        let gate = format!("xtask {sub}");
        if probed_subs.contains(sub.as_str()) || listed(table::UNCOVERED, &gate) {
            continue;
        }
        // Covered through a script? The row names WHICH, and the row is verified.
        let mut shim = false;
        for row in table::SHIM_COVERED {
            let mut parts = row.split_whitespace();
            let (Some(s_sub), Some(s_script)) = (parts.next(), parts.next()) else {
                continue;
            };
            if s_sub != sub {
                continue;
            }
            let path = root.join(s_script);
            let calls = regex::Regex::new(&format!(
                r"xtask -- {}([^a-zA-Z0-9_-]|$)",
                regex::escape(sub)
            ))
            .map(|re| fs::read_to_string(&path).is_ok_and(|t| re.is_match(&t)))
            .unwrap_or(false);
            if !path.is_file() {
                h.fail(&[format!(
                    "  FAIL  xtask {sub} — SHIM_COVERED names {s_script}, which does not exist."
                )]);
            } else if !calls {
                h.fail(&[
                    format!(
                        "  FAIL  xtask {sub} — SHIM_COVERED says {s_script} covers it, and that"
                    ),
                    "        script does not invoke it. The route into CI moved; this row is"
                        .into(),
                    "        now an exemption for a gate nothing runs.".into(),
                ]);
            }
            shim = true;
            break;
        }
        if !shim {
            unaccounted.push(gate);
        }
    }
    // A SHIM_COVERED row for a subcommand no longer in the domain is a gate ranging over nothing.
    for row in table::SHIM_COVERED {
        let s_sub = row.split_whitespace().next().unwrap_or("");
        if !xtask_gates.contains(s_sub) {
            h.fail(&[format!(
                "  FAIL  SHIM_COVERED names xtask {s_sub}, which nothing in CI invokes at all."
            )]);
        }
    }
    // NON-VACUITY of the half just derived: had it matched nothing, every xtask gate would be
    // accounted for by having vanished from the domain.
    if xtask_gates.len() < 5 {
        out("");
        out(&format!(
            "ERROR: derived only {} xtask gate(s) from the workflows and scripts.",
            xtask_gates.len()
        ));
        out("The derivation is wrong, so the accounting below exempted every gate it");
        out("failed to see -- which is the failure this script exists to catch.");
        return 2;
    }
    if !unwired.is_empty() {
        out("");
        out(&format!(
            "VIOLATION: {} gate(s) are not invoked by any workflow:",
            unwired.len()
        ));
        for g in &unwired {
            out(&format!("    {g}"));
        }
        out("A gate that CI never calls enforces nothing. Add it to a workflow, or");
        out("delete it — an uncalled script in scripts/ reads as protection that");
        out("is not there.");
        h.failures += 1;
    }
    if !unaccounted.is_empty() {
        out("");
        out(&format!(
            "VIOLATION: {} gate(s) are neither probed nor listed as uncovered:",
            unaccounted.len()
        ));
        for g in &unaccounted {
            out(&format!("    {g}"));
        }
        out("Add a probe() for it, or add it to UNCOVERED with the reason a");
        out("perturbation is not available. An unaccounted gate is one this script");
        out("silently exempted, which is the exact failure it exists to catch.");
        h.failures += 1;
    }
    // NON-VACUITY of the accounting itself.
    if scripts.len() < 2 {
        out("");
        out(&format!(
            "ERROR: found {} gate script(s) under scripts/. The glob is wrong,",
            scripts.len()
        ));
        out("so the accounting above examined nothing and proved nothing.");
        h.failures += 1;
    } else {
        out(&format!(
            "accounting: {} gate script(s) found, {} probed, {} listed uncovered, {} unaccounted",
            scripts.len(),
            h.covered,
            table::UNCOVERED.len(),
            unaccounted.len()
        ));
    }
    if !h.main_red.is_empty() {
        out(&format!(
            "main is red: {} gate(s) red on the merge base as well as here (measuring main took {:.1}s);",
            h.main_red.len(),
            h.base_seconds
        ));
        out("    reported, not charged to this change, and not probed:");
        for g in h.main_red.values() {
            out(&format!("    main is red: {g}"));
        }
    }

    out("");
    let mode = h.opts.mode;
    if h.failures > 0 {
        match mode {
            Mode::BaselineOnly => {
                out(&format!(
                    "FAILED: {} gate(s) do not pass on this tree. Until they do, the full probe",
                    h.failures
                ));
                out(
                    "        cannot say anything about them -- and because it FAILS on a gate that is",
                );
                out(
                    "        already red, a red here is a red on 'Gates must fail on their own subject',",
                );
                out("        whether or not the gate is required on its own.");
            }
            Mode::VacuityOnly => out(&format!(
                "FAILED: {} perturbation(s) change nothing. A probe that cannot bite tests nothing.",
                h.failures
            )),
            Mode::Probe => out(&format!(
                "FAILED: {} problem(s). A gate that cannot fail is not a gate.",
                h.failures
            )),
        }
        return 1;
    }
    match mode {
        Mode::BaselineOnly => {
            out(&format!(
                "OK: all {} probed gate(s) pass on this tree. NOTHING WAS PERTURBED:",
                h.covered
            ));
            out("    this says they are green, not that they red on their own subject.");
        }
        Mode::VacuityOnly => {
            out("OK: every perturbation still changes its target. NO GATE WAS RUN:");
            out("    this says the probes still bite, not that the gates red on them.");
        }
        Mode::Probe if h.scope.kind != ScopeKind::Full && h.skipped > 0 => {
            out("OK: every SELECTED probe REDs on its own subject and GREENs when restored.");
            out(&format!(
                "    {} probe(s) were not re-asked: none of their inputs differ from {},",
                h.skipped, h.scope.base_label
            ));
            out("    so their answer is the one the full run on that tree gave.");
        }
        Mode::Probe => {
            out("OK: every probed gate REDs on its own subject and GREENs when restored.")
        }
    }
    if !h.main_red.is_empty() {
        out(&format!(
            "    Except {} gate(s) red on main, which no probe can ask anything until main is green.",
            h.main_red.len()
        ));
    }
    0
}

fn print_inputs(root: &Path, kind: &str, name: &str) -> i32 {
    let idx = match Index::new(root) {
        Ok(i) => i,
        Err(e) => {
            out(&format!("ERROR: {e}"));
            return 2;
        }
    };
    let set = match kind {
        "script" => idx.script_inputs(&format!("scripts/{name}")),
        "xtask" => idx.xtask_inputs(name),
        "fn" => idx.function_inputs(&[name]),
        _ => {
            out("usage: gates-can-fail --inputs script <check-x.sh> | xtask <sub>");
            return 2;
        }
    };
    for s in set {
        out(&s);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn for_event_always_takes_two_arguments_and_the_base_may_be_empty() {
        let Ok(Request::Run(o)) = parse(&args(&["--for-event", "pull_request", ""])) else {
            panic!("parse failed");
        };
        assert_eq!((o.scope, o.base.as_str()), (ScopeKind::Scoped, "HEAD^1"));
        let Ok(Request::Run(o)) = parse(&args(&["--for-event", "merge_group", ""])) else {
            panic!("parse failed");
        };
        assert_eq!((o.scope, o.base.as_str()), (ScopeKind::Backstop, ""));
        let Ok(Request::Run(o)) = parse(&args(&["--for-event", "push", ""])) else {
            panic!("parse failed");
        };
        assert_eq!(o.scope, ScopeKind::Full);
        assert!(parse(&args(&["--for-event", "merge_group"])).is_err());
    }

    #[test]
    fn the_cheap_halves_take_no_scope() {
        assert!(parse(&args(&["--vacuity-only", "--changed-from", "x"])).is_err());
        assert!(parse(&args(&["--baseline-only", "--plan"])).is_err());
        assert!(parse(&args(&["--plan"])).is_err());
    }

    #[test]
    fn the_engine_and_the_backstop_select_everything() {
        let s = fixture_scope(
            ScopeKind::Scoped,
            "f",
            &["crates/xtask/src/gates_can_fail/mod.rs"],
        );
        assert!(s.all.is_some());
        let s = fixture_scope(ScopeKind::Scoped, "f", &["scripts/demo.sh"]);
        assert!(s.all.is_none());
        let s = fixture_scope(ScopeKind::Backstop, "f", &["scripts/demo.sh"]);
        assert_eq!(
            s.all.as_deref(),
            Some("backstop: scripts/demo.sh is gate code")
        );
    }

    #[test]
    fn a_full_run_has_no_base_and_charges_a_red_as_it_always_did() {
        let o = Opts {
            mode: Mode::Probe,
            scope: ScopeKind::Full,
            base: String::new(),
            changed_files: None,
            plan: false,
        };
        let (s, lines) = scope_for(Path::new("."), &o);
        assert!(matches!(s.main, MainRef::NotApplicable));
        assert!(lines.is_empty());
    }

    #[test]
    fn an_empty_merge_group_base_is_unreadable_not_main_is_red() {
        let o = Opts {
            mode: Mode::Probe,
            scope: ScopeKind::Backstop,
            base: String::new(),
            changed_files: None,
            plan: false,
        };
        let (s, _) = scope_for(Path::new("."), &o);
        assert!(matches!(s.main, MainRef::Unreadable { fetch: None, .. }));
        assert!(s.all.is_some());
    }

    #[test]
    fn the_table_keeps_its_shape() {
        let probes = table::probes();
        assert_eq!(
            probes.len(),
            60,
            "the probe count is part of the accounting line"
        );
        let shell = probes
            .iter()
            .filter(|p| matches!(p.family, Family::Script { .. }))
            .count();
        assert!(
            shell >= 10,
            "too few shell probes ({shell}); the self-test would be vacuous"
        );
        for p in &probes {
            assert!(
                inputs::fn_source(perturb::SOURCE, p.perturb.name).is_some(),
                "{} is not a fn in perturb.rs, so its inputs cannot be derived",
                p.perturb.name
            );
        }
    }
}
