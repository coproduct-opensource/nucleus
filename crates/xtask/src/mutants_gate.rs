//! `cargo xtask mutants-gate` — plans and decides the sharded `Mutation Testing` gate.
//!
//! # Why sharded
//!
//! `Mutation Testing` runs cargo-mutants over the diff-scoped mutants of six security-critical
//! portcullis modules. With `--jobs 3 --profile mutants` (#3480), #3467's 129 mutants took
//! 36.5 minutes in one job, against a ~25-minute target; a full run (607 mutants, nightly and on
//! push) cannot finish in one job at all. So `coverage-matrix.yml` runs:
//!
//! 1. `mutants-plan`: the scope, then `cargo mutants --list --json` at the run's commit — the
//!    PLAN — and `mutants-gate plan`, which sizes the shard matrix from the plan's length.
//! 2. `mutants-shard` (a matrix, one job per shard): `cargo mutants --shard k/N --sharding
//!    round-robin`, uploading its report as `mutants-shard-<k>-of-<N>`. A failed shard is re-run
//!    on its own with "Re-run failed jobs".
//! 3. `Mutation Testing` (the required context, its name unchanged): `mutants-gate decide`.
//!
//! # Identity, not counts
//!
//! Round-robin sharding gives shard `k` exactly the plan entries at indices `i` with
//! `i % N == k` (checked against cargo-mutants 27.1.0's own `--list --shard`). So each shard's
//! share is known BY NAME from the plan, and `decide` requires each shard's outcomes to be that
//! share exactly: no mutant missing, none extra, none twice. The shares are disjoint and cover
//! the plan by construction, so per-shard equality is union-equals-plan with no overlap.
//!
//! # The interrupted-run defect this closes
//!
//! A cancelled run leaves an `outcomes.json` whose `total_mutants` is the count tested SO FAR.
//! The nightly of 2026-10-14 was cancelled at 49 of 607 and its report said
//! `total=49 tested=49`; #3467's run was cancelled at 80 of 129 and the report reader printed
//! `ok: 80 tested`. `scripts/check-mutants-report.sh` compared `tested == total` from inside that
//! report, so a truncated run satisfied it. Here a report with no `end_time`, or one that tested
//! fewer mutants than the plan gave its shard, is refused, naming the shard and the untested
//! mutants. The report's own aggregate counts are not read at all (ADR 0007 G-1).
//!
//! # Exit status (ADR 0007 A-2, A-5, I-3)
//!
//! 0 green; 1 the gate fails (a survivor, an unfinished or short run, a mismatched version);
//! 2 could not look (a missing or cancelled shard, an unreadable report, an unknown job
//! result, a report from a different commit). Neither non-zero status is ever a pass.
//!
//! `--self-test` drives `decide` through fixtures for every red case and the clean one; CI runs
//! it beside the real decision.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

/// The `coverage-matrix.yml` job ids whose results the decision reads.
const DETECTOR: &str = "changed-crates";
const PLAN: &str = "mutants-plan";
const SHARDS: &str = "mutants-shard";

/// Shard artifacts are `mutants-shard-<k>-of-<n>`.
const SHARD_PREFIX: &str = "mutants-shard-";

/// Console markers of a run whose UNMUTATED tree did not build or pass (#2562): nothing after
/// such a line was a mutant test.
const PREAMBLE_MARKERS: &[&str] = &["unmutated tree", "cargo build failed", "cargo test failed"];

/// How many mutants of a decision are worth naming in one line.
const NAMED: usize = 5;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Run the fixtures through `decide` and require each verdict.
    #[arg(long)]
    self_test: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Size the shard matrix from the plan (`cargo mutants --list --json`) and write
    /// `shard_count` and `shards` to the step's GITHUB_OUTPUT file.
    Plan {
        #[arg(long)]
        list: PathBuf,
        /// Mutants one shard is sized to hold.
        #[arg(long)]
        per_shard: usize,
        /// The most shards one run may take from the build pool.
        #[arg(long)]
        max_shards: usize,
        #[arg(long)]
        github_output: PathBuf,
    },
    /// Decide the `Mutation Testing` verdict from the plan and every shard's report.
    Decide {
        /// The aggregating job's `toJSON(needs)`.
        #[arg(long)]
        needs: String,
        /// The plan artifact: `list.json`, `commit.txt`, `version.txt`.
        #[arg(long)]
        plan: PathBuf,
        /// The directory the `mutants-shard-*` artifacts were downloaded into.
        #[arg(long)]
        shards: PathBuf,
        /// This run's commit; the plan and every shard must have run it.
        #[arg(long)]
        commit: String,
        /// The pinned cargo-mutants version; the plan and every report must carry it.
        #[arg(long)]
        expect_version: String,
        /// Timed-out mutants allowed across all shards (a timeout is an untested mutant).
        #[arg(long, default_value_t = 5)]
        max_timeout: usize,
        /// Unviable mutants allowed across all shards.
        #[arg(long, default_value_t = 50)]
        max_unviable: usize,
        /// Append a markdown report here (the step summary).
        #[arg(long)]
        summary: Option<PathBuf>,
    },
}

// ---------------------------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------------------------

/// The shard count for a plan of `planned` mutants: enough shards that none holds more than
/// `per_shard`, at most `max_shards`, and never more shards than mutants (so every round-robin
/// shard has work and therefore a report).
fn shard_count(planned: usize, per_shard: usize, max_shards: usize) -> Result<usize> {
    ensure!(
        planned > 0,
        "the plan lists no mutant: nothing to shard (the plan job stands down before this step)"
    );
    ensure!(
        per_shard > 0 && max_shards > 0,
        "--per-shard and --max-shards must be positive"
    );
    Ok(planned
        .div_ceil(per_shard)
        .clamp(1, max_shards)
        .min(planned))
}

fn plan(list: &Path, per_shard: usize, max_shards: usize, github_output: &Path) -> Result<()> {
    let listed: Vec<Listed> = read_json(list).map_err(anyhow::Error::msg)?;
    let n = shard_count(listed.len(), per_shard, max_shards)?;
    let shards: Vec<usize> = (0..n).collect();
    let text = format!(
        "shard_count={n}\nshards={}\n",
        serde_json::to_string(&shards)?
    );
    append_runner_file(github_output, &text)?;
    println!(
        "mutants plan: {} mutants -> {n} shard(s) of at most {} (per-shard target {per_shard}, cap {max_shards})",
        listed.len(),
        listed.len().div_ceil(n)
    );
    Ok(())
}

/// Add `text` to the end of a runner file (`GITHUB_OUTPUT`, the step summary) in one write.
/// Not `OpenOptions::append`: ADR 0007 G-1 reserves that for record logs (clippy.toml), and these
/// are files the runner reads once the step ends.
fn append_runner_file(path: &Path, text: &str) -> Result<()> {
    use std::io::{Seek as _, Write as _};
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    f.seek(std::io::SeekFrom::End(0))
        .with_context(|| format!("seek to the end of {}", path.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

// ---------------------------------------------------------------------------------------------
// Inputs, typed
// ---------------------------------------------------------------------------------------------

/// A GitHub job result as `toJSON(needs)` spells it. No other value parses (A-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum JobResult {
    Success,
    Failure,
    Cancelled,
    Skipped,
}

#[derive(Debug, Deserialize)]
struct Upstream {
    result: JobResult,
    outputs: BTreeMap<String, String>,
}

/// A `'true'`/`'false'` job output. Empty or anything else is not a value (A-1, A-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flag {
    True,
    False,
}

fn output<'a>(up: &'a Upstream, job: &str, key: &str) -> Result<&'a str, Problem> {
    up.outputs
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| Problem::CouldNotLook(format!("{job}.outputs.{key} is absent")))
}

fn flag(up: &Upstream, job: &str, key: &str) -> Result<Flag, Problem> {
    match output(up, job, key)? {
        "true" => Ok(Flag::True),
        "false" => Ok(Flag::False),
        other => Err(Problem::CouldNotLook(format!(
            "{job}.outputs.{key} is {other:?}, not 'true' or 'false'"
        ))),
    }
}

/// One cargo-mutants outcome. `scenario` is `"Baseline"` or `{"Mutant": {...}}`.
#[derive(Debug, Deserialize)]
struct Outcome {
    scenario: Scenario,
    summary: Summary,
}

#[derive(Debug, Deserialize)]
enum Scenario {
    Baseline,
    Mutant(Mutant),
}

/// A mutant's identity: its name carries file, line, column, function and replacement.
#[derive(Debug, Deserialize)]
struct Mutant {
    name: String,
}

/// cargo-mutants' `SummaryOutcome`, every variant named: a new one is a parse error, never a
/// silently uncounted mutant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum Summary {
    Success,
    CaughtMutant,
    MissedMutant,
    Unviable,
    Failure,
    Timeout,
}

/// `mutants.out/outcomes.json`. Its aggregate counts are deliberately not fields here.
#[derive(Debug, Deserialize)]
struct Outcomes {
    outcomes: Vec<Outcome>,
    end_time: Option<String>,
    cargo_mutants_version: String,
}

/// An entry of `cargo mutants --list --json`.
#[derive(Debug, Deserialize)]
struct Listed {
    name: String,
}

/// Why the gate is red. The two halves exit differently (I-3).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Problem {
    /// An input the decision needs is missing, cancelled, foreign or unreadable.
    CouldNotLook(String),
    /// The inputs are all there and say the gate fails.
    Fails(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Tally {
    caught: usize,
    missed: usize,
    timeout: usize,
    unviable: usize,
}

impl Tally {
    fn tested(&self) -> usize {
        self.caught + self.missed + self.timeout + self.unviable
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The detector says nothing that can move a portcullis mutant changed.
    NothingToMutate,
    /// The diff names none of the six modules, or none of its lines yields a mutant.
    NoMutantsInDiff,
    /// Every planned mutant tested by its shard, none survived, bounds held.
    Clean { shards: usize, tally: Tally },
    Red {
        problems: Vec<Problem>,
        survivors: Vec<String>,
        tally: Tally,
    },
}

impl Verdict {
    fn exit_code(&self) -> i32 {
        match self {
            Verdict::NothingToMutate | Verdict::NoMutantsInDiff | Verdict::Clean { .. } => 0,
            Verdict::Red { problems, .. } => {
                if problems
                    .iter()
                    .any(|p| matches!(p, Problem::CouldNotLook(_)))
                {
                    2
                } else {
                    1
                }
            }
        }
    }
}

struct Inputs<'a> {
    needs: &'a str,
    plan: &'a Path,
    shards: &'a Path,
    commit: &'a str,
    expect_version: &'a str,
    max_timeout: usize,
    max_unviable: usize,
}

fn red(p: Problem) -> Verdict {
    Verdict::Red {
        problems: vec![p],
        survivors: Vec::new(),
        tally: Tally::default(),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_trimmed(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let t = text.trim();
    if t.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(t.to_string())
}

fn sample(names: &[String]) -> String {
    let mut s: Vec<&str> = names.iter().take(NAMED).map(String::as_str).collect();
    if names.len() > NAMED {
        s.push("…");
    }
    s.join("; ")
}

// ---------------------------------------------------------------------------------------------
// Decide
// ---------------------------------------------------------------------------------------------

/// What the plan says, read once.
struct Plan {
    commit: String,
    version: String,
    /// Shard `k`'s share: the plan entries at `i % n == k`, sorted.
    shares: Vec<Vec<String>>,
}

fn read_plan(dir: &Path, n: usize, i: &Inputs<'_>) -> Result<Plan, Vec<Problem>> {
    let cnl = |s: String| vec![Problem::CouldNotLook(format!("plan: {s}"))];
    let listed: Vec<Listed> = read_json(&dir.join("list.json")).map_err(cnl)?;
    if listed.is_empty() {
        return Err(cnl(
            "the plan job said run=true but list.json names no mutant".into(),
        ));
    }
    if n == 0 || n > listed.len() {
        return Err(cnl(format!(
            "shard_count {n} is not between 1 and the plan's {} mutants",
            listed.len()
        )));
    }
    let commit = read_trimmed(&dir.join("commit.txt")).map_err(cnl)?;
    let raw_version = read_trimmed(&dir.join("version.txt")).map_err(cnl)?;
    let Some(version) = raw_version.strip_prefix("cargo-mutants ") else {
        return Err(cnl(format!(
            "version.txt is {raw_version:?}, not `cargo-mutants <version>`"
        )));
    };
    let mut problems = Vec::new();
    if commit != i.commit {
        problems.push(Problem::CouldNotLook(format!(
            "the plan was made at {commit}, not this run's commit {}",
            i.commit
        )));
    }
    if version != i.expect_version {
        problems.push(Problem::Fails(format!(
            "the plan was made by cargo-mutants {version}, not the pinned {}",
            i.expect_version
        )));
    }
    let mut shares = vec![Vec::new(); n];
    for (idx, l) in listed.into_iter().enumerate() {
        shares[idx % n].push(l.name);
    }
    for s in &mut shares {
        s.sort();
    }
    if problems.is_empty() {
        Ok(Plan {
            commit,
            version: version.to_string(),
            shares,
        })
    } else {
        Err(problems)
    }
}

/// The whole decision. Pure over its inputs: the job results and the files on disk.
fn decide(i: &Inputs<'_>) -> Verdict {
    let needs: BTreeMap<String, Upstream> = match serde_json::from_str(i.needs) {
        Ok(n) => n,
        Err(e) => {
            return red(Problem::CouldNotLook(format!(
                "--needs does not parse: {e}"
            )));
        }
    };
    let upstream = |job: &str| -> Result<&Upstream, Problem> {
        needs
            .get(job)
            .ok_or_else(|| Problem::CouldNotLook(format!("needs.{job} is absent")))
    };
    let succeeded = |job: &str| -> Result<&Upstream, Problem> {
        let up = upstream(job)?;
        match up.result {
            JobResult::Success => Ok(up),
            other => Err(Problem::CouldNotLook(format!(
                "{job} finished {other:?}, not Success: its answer was never produced"
            ))),
        }
    };

    let detector = match succeeded(DETECTOR) {
        Ok(u) => u,
        Err(p) => return red(p),
    };
    match flag(detector, DETECTOR, "mutate") {
        Ok(Flag::False) => return Verdict::NothingToMutate,
        Ok(Flag::True) => {}
        Err(p) => return red(p),
    }
    let planner = match succeeded(PLAN) {
        Ok(u) => u,
        Err(p) => return red(p),
    };
    match flag(planner, PLAN, "run") {
        Ok(Flag::False) => return Verdict::NoMutantsInDiff,
        Ok(Flag::True) => {}
        Err(p) => return red(p),
    }
    let n: usize = match output(planner, PLAN, "shard_count").map(str::parse) {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return red(Problem::CouldNotLook(format!(
                "{PLAN}.outputs.shard_count is not a count: {e}"
            )));
        }
        Err(p) => return red(p),
    };

    let mut problems = Vec::new();
    // A matrix that did not succeed is red even if every report is present: its result is the
    // only witness that no shard was cancelled after uploading a partial report.
    if let Err(p) = succeeded(SHARDS) {
        problems.push(p);
    }
    let plan = match read_plan(i.plan, n, i) {
        Ok(p) => p,
        Err(mut ps) => {
            problems.append(&mut ps);
            return Verdict::Red {
                problems,
                survivors: Vec::new(),
                tally: Tally::default(),
            };
        }
    };

    let dirs = match shard_dirs(i.shards, n) {
        Ok(d) => d,
        Err(e) => {
            problems.push(Problem::CouldNotLook(e));
            BTreeMap::new()
        }
    };
    let mut tally = Tally::default();
    let mut survivors = Vec::new();
    for (k, dir) in &dirs {
        let share = &plan.shares[*k];
        read_shard(
            *k,
            n,
            dir,
            share,
            &plan,
            &mut tally,
            &mut survivors,
            &mut problems,
        );
    }

    if tally.missed > 0 {
        problems.push(Problem::Fails(format!(
            "{} mutant(s) SURVIVED in security-critical modules: {}",
            tally.missed,
            sample(&survivors)
        )));
    }
    if tally.timeout > i.max_timeout {
        problems.push(Problem::Fails(format!(
            "{} mutants timed out (bound {}): a timeout is an untested mutant",
            tally.timeout, i.max_timeout
        )));
    }
    if tally.unviable > i.max_unviable {
        problems.push(Problem::Fails(format!(
            "{} unviable mutants (bound {}): the build is rejecting mutations wholesale",
            tally.unviable, i.max_unviable
        )));
    }

    if problems.is_empty() {
        Verdict::Clean { shards: n, tally }
    } else {
        Verdict::Red {
            problems,
            survivors,
            tally,
        }
    }
}

/// The `mutants-shard-<k>-of-<n>` directories, keyed by `k`: exactly `0..n`, all of `n`.
fn shard_dirs(root: &Path, n: usize) -> Result<BTreeMap<usize, PathBuf>, String> {
    let rd = fs::read_dir(root).map_err(|e| format!("shard artifacts {}: {e}", root.display()))?;
    let mut by_k = BTreeMap::new();
    for entry in rd {
        let entry = entry.map_err(|e| format!("{}: {e}", root.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let parsed = name.strip_prefix(SHARD_PREFIX).and_then(|rest| {
            let (k, of) = rest.split_once("-of-")?;
            Some((k.parse::<usize>().ok()?, of.parse::<usize>().ok()?))
        });
        match parsed {
            Some((k, of)) if of == n && k < n => {
                by_k.insert(k, entry.path());
            }
            Some((k, of)) => {
                return Err(format!(
                    "{name}: shard {k} of {of}, but the plan sized this run at {n} shards"
                ));
            }
            None => return Err(format!("{name}: not a {SHARD_PREFIX}<k>-of-<n> artifact")),
        }
    }
    let missing: Vec<usize> = (0..n).filter(|k| !by_k.contains_key(k)).collect();
    if !missing.is_empty() {
        return Err(format!(
            "shard(s) {missing:?} of {n} uploaded no report: their planned mutants were never looked at"
        ));
    }
    Ok(by_k)
}

#[allow(clippy::too_many_arguments)]
fn read_shard(
    k: usize,
    n: usize,
    dir: &Path,
    share: &[String],
    plan: &Plan,
    tally: &mut Tally,
    survivors: &mut Vec<String>,
    problems: &mut Vec<Problem>,
) {
    let who = format!("shard {k} of {n}");
    match fs::read_to_string(dir.join("console.log")) {
        Ok(text) => {
            if let Some(line) = text
                .lines()
                .find(|l| PREAMBLE_MARKERS.iter().any(|m| l.contains(m)))
            {
                problems.push(Problem::Fails(format!(
                    "{who}: cargo-mutants could not build or test the UNMUTATED tree, so no mutant was tested: {}",
                    line.trim()
                )));
            }
        }
        Err(e) => problems.push(Problem::CouldNotLook(format!("{who}: console.log: {e}"))),
    }
    match read_trimmed(&dir.join("commit.txt")) {
        Ok(c) if c == plan.commit => {}
        Ok(c) => problems.push(Problem::CouldNotLook(format!(
            "{who} ran commit {c}, not the plan's {}",
            plan.commit
        ))),
        Err(e) => problems.push(Problem::CouldNotLook(format!("{who}: {e}"))),
    }
    let outcomes: Outcomes = match read_json(&dir.join("mutants.out").join("outcomes.json")) {
        Ok(o) => o,
        Err(e) => {
            problems.push(Problem::CouldNotLook(format!(
                "{who}: no readable report ({e}); its {} planned mutants were never looked at",
                share.len()
            )));
            return;
        }
    };
    if outcomes.cargo_mutants_version != plan.version {
        problems.push(Problem::Fails(format!(
            "{who} ran cargo-mutants {}, not the plan's {}",
            outcomes.cargo_mutants_version, plan.version
        )));
    }
    let mut baselines_ok = 0usize;
    let mut tested: Vec<String> = Vec::new();
    for o in outcomes.outcomes {
        match (o.scenario, o.summary) {
            (Scenario::Baseline, Summary::Success) => baselines_ok += 1,
            (Scenario::Baseline, s) => problems.push(Problem::Fails(format!(
                "{who}: the unmutated baseline finished {s:?}, so no mutant was tested"
            ))),
            (Scenario::Mutant(m), s) => {
                match s {
                    Summary::CaughtMutant => tally.caught += 1,
                    Summary::MissedMutant => {
                        tally.missed += 1;
                        survivors.push(m.name.clone());
                    }
                    Summary::Timeout => tally.timeout += 1,
                    Summary::Unviable => tally.unviable += 1,
                    Summary::Success | Summary::Failure => {
                        problems.push(Problem::CouldNotLook(format!(
                            "{who}: mutant {} has summary {s:?}, which is not a mutant verdict",
                            m.name
                        )));
                    }
                }
                tested.push(m.name);
            }
        }
    }
    if baselines_ok != 1 {
        problems.push(Problem::Fails(format!(
            "{who}: {baselines_ok} successful baselines in the report, not exactly 1"
        )));
    }
    if outcomes.end_time.is_none() {
        problems.push(Problem::Fails(format!(
            "{who}: outcomes.json has no end_time: the run did not finish ({} of {} planned mutants tested)",
            tested.len(),
            share.len()
        )));
    }
    // Identity: the shard's outcomes are exactly its share of the plan.
    tested.sort();
    let (mut untested, mut foreign, mut twice) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for t in &tested {
        *seen.entry(t.as_str()).or_default() += 1;
    }
    let mut want: BTreeMap<&str, usize> = BTreeMap::new();
    for s in share {
        *want.entry(s.as_str()).or_default() += 1;
    }
    for (name, w) in &want {
        let got = seen.get(name).copied().unwrap_or(0);
        if got < *w {
            untested.push((*name).to_string());
        } else if got > *w {
            twice.push((*name).to_string());
        }
    }
    for name in seen.keys() {
        if !want.contains_key(name) {
            foreign.push((*name).to_string());
        }
    }
    if !untested.is_empty() {
        problems.push(Problem::Fails(format!(
            "{who} tested {} of its {} planned mutants; untested: {}",
            share.len() - untested.len(),
            share.len(),
            sample(&untested)
        )));
    }
    if !foreign.is_empty() {
        problems.push(Problem::Fails(format!(
            "{who} tested {} mutant(s) outside its share of the plan (another shard's, or none): {}",
            foreign.len(),
            sample(&foreign)
        )));
    }
    if !twice.is_empty() {
        problems.push(Problem::Fails(format!(
            "{who} reported {} mutant(s) more than once: {}",
            twice.len(),
            sample(&twice)
        )));
    }
}

fn render(v: &Verdict) -> (Vec<String>, String) {
    let mut console = Vec::new();
    let mut md = String::from("## Mutation Testing Report\n\n");
    md.push_str(
        "**Modules tested:** capability, guard, lattice, certificate, delegation, trust\n\n",
    );
    let counts = |t: &Tally| {
        format!(
            "- **tested:** {}\n- **caught:** {}\n- **survived:** {}\n- **timeout:** {}\n- **unviable:** {}\n",
            t.tested(),
            t.caught,
            t.missed,
            t.timeout,
            t.unviable
        )
    };
    match v {
        Verdict::NothingToMutate => {
            console.push("mutants: nothing that can change a portcullis mutant changed".into());
            md.push_str("nothing that can change a portcullis mutant changed in this diff\n");
        }
        Verdict::NoMutantsInDiff => {
            console.push("mutants: no mutants in this diff".into());
            md.push_str(
                "no mutants in this diff (none of the six modules' code changed); the nightly schedule runs them all\n",
            );
        }
        Verdict::Clean { shards, tally } => {
            console.push(format!(
                "ok: {shards} shard(s), every planned mutant tested by its shard: {} tested / {} caught / 0 survived / {} timeout / {} unviable",
                tally.tested(),
                tally.caught,
                tally.timeout,
                tally.unviable
            ));
            let _ = writeln!(
                md,
                "**Shards:** {shards}, each report complete and equal to its share of the plan\n"
            );
            md.push_str(&counts(tally));
        }
        Verdict::Red {
            problems,
            survivors,
            tally,
        } => {
            for p in problems {
                match p {
                    Problem::CouldNotLook(s) => {
                        console.push(format!("::error::COULD NOT LOOK: {s}"));
                    }
                    Problem::Fails(s) => console.push(format!("::error::{s}")),
                }
            }
            for s in survivors.iter().take(20) {
                console.push(format!("  MISSED {s}"));
            }
            md.push_str("**RED**\n\n");
            for p in problems {
                let (Problem::CouldNotLook(s) | Problem::Fails(s)) = p;
                let _ = writeln!(md, "- {s}");
            }
            md.push('\n');
            md.push_str(&counts(tally));
        }
    }
    (console, md)
}

/// The subcommand. Returns the process exit status.
pub fn run(args: Args) -> Result<i32> {
    match (args.self_test, args.cmd) {
        (true, None) => self_test().map(|()| 0),
        (
            false,
            Some(Cmd::Plan {
                list,
                per_shard,
                max_shards,
                github_output,
            }),
        ) => plan(&list, per_shard, max_shards, &github_output).map(|()| 0),
        (
            false,
            Some(Cmd::Decide {
                needs,
                plan,
                shards,
                commit,
                expect_version,
                max_timeout,
                max_unviable,
                summary,
            }),
        ) => {
            let v = decide(&Inputs {
                needs: &needs,
                plan: &plan,
                shards: &shards,
                commit: &commit,
                expect_version: &expect_version,
                max_timeout,
                max_unviable,
            });
            let (console, md) = render(&v);
            for line in console {
                println!("{line}");
            }
            if let Some(path) = &summary {
                append_runner_file(path, &md)?;
            }
            Ok(v.exit_code())
        }
        (true, Some(_)) => bail!("--self-test takes no subcommand"),
        (false, None) => bail!("give a subcommand (plan | decide) or --self-test"),
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures: shared by `--self-test` (run in CI beside the real decision) and the unit tests.
// ---------------------------------------------------------------------------------------------

/// What a fixture case must decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Green,
    Fails,
    CouldNotLook,
}

const FX_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const FX_VERSION: &str = "27.1.0";
const FX_PLAN: &[&str] = &["m0", "m1", "m2", "m3", "m4", "m5", "m6"];
const FX_SHARDS: usize = 3;

/// One shard as a fixture writes it.
#[derive(Clone)]
struct ShardFx {
    outcomes: Vec<(String, &'static str)>,
    baseline: &'static str,
    finished: bool,
    console: &'static str,
    commit: &'static str,
    version: &'static str,
    report: bool,
}

/// Shard `k`'s round-robin share of the fixture plan, all caught.
fn share_fx(k: usize) -> ShardFx {
    ShardFx {
        outcomes: FX_PLAN
            .iter()
            .enumerate()
            .filter(|(i, _)| i % FX_SHARDS == k)
            .map(|(_, n)| ((*n).to_string(), "CaughtMutant"))
            .collect(),
        baseline: "Success",
        finished: true,
        console: "Found 3 mutants to test\nok       Unmutated baseline in 59s build + 17s test\n",
        commit: FX_COMMIT,
        version: FX_VERSION,
        report: true,
    }
}

fn clean_shards() -> Vec<Option<ShardFx>> {
    (0..FX_SHARDS).map(|k| Some(share_fx(k))).collect()
}

fn needs_json(
    detector: &str,
    mutate: &str,
    plan: &str,
    run: &str,
    count: &str,
    shards: &str,
) -> String {
    serde_json::json!({
        DETECTOR: {"result": detector, "outputs": {"mutate": mutate, "all": "true", "crates": "portcullis"}},
        PLAN: {"result": plan, "outputs": {"run": run, "shard_count": count, "shards": "[0,1,2]"}},
        SHARDS: {"result": shards, "outputs": {}},
    })
    .to_string()
}

fn ok_needs() -> String {
    needs_json("success", "true", "success", "true", "3", "success")
}

struct Case {
    name: &'static str,
    needs: String,
    shards: Vec<Option<ShardFx>>,
    /// Override the `-of-<n>` suffix of shard `k`.
    of: Option<(usize, usize)>,
    plan_commit: &'static str,
    plan_version: &'static str,
    expect: Expect,
}

fn case(name: &'static str, needs: String, shards: Vec<Option<ShardFx>>, expect: Expect) -> Case {
    Case {
        name,
        needs,
        shards,
        of: None,
        plan_commit: FX_COMMIT,
        plan_version: "cargo-mutants 27.1.0",
        expect,
    }
}

fn with(edit: impl FnOnce(&mut Vec<Option<ShardFx>>)) -> Vec<Option<ShardFx>> {
    let mut s = clean_shards();
    edit(&mut s);
    s
}

fn shard(s: &mut [Option<ShardFx>], k: usize) -> &mut ShardFx {
    s[k].as_mut().unwrap_or_else(|| panic!("fixture shard {k}"))
}

fn cases() -> Vec<Case> {
    use Expect::{CouldNotLook, Fails, Green};
    let skipped = |m: &str, r: &str| needs_json("success", m, "skipped", r, "", "skipped");
    vec![
        case("all clean", ok_needs(), clean_shards(), Green),
        case(
            "detector: nothing to mutate",
            skipped("false", ""),
            Vec::new(),
            Green,
        ),
        case(
            "plan: no mutants in diff",
            needs_json("success", "true", "success", "false", "", "skipped"),
            Vec::new(),
            Green,
        ),
        case(
            "a survivor in one shard",
            ok_needs(),
            with(|s| shard(s, 1).outcomes[1].1 = "MissedMutant"),
            Fails,
        ),
        case(
            // The shape of the 2026-10-14 nightly and of #3467's cancelled run: a report that
            // agrees with itself, stops short of the plan, and has no end_time.
            "a truncated report (no end_time, short of the plan)",
            ok_needs(),
            with(|s| {
                let sh = shard(s, 0);
                sh.outcomes.truncate(1);
                sh.finished = false;
            }),
            Fails,
        ),
        case(
            "a report with no end_time but every mutant",
            ok_needs(),
            with(|s| shard(s, 2).finished = false),
            Fails,
        ),
        case(
            "a finished report short of its share",
            ok_needs(),
            with(|s| {
                shard(s, 0).outcomes.pop();
            }),
            Fails,
        ),
        case(
            "a shard uploaded no artifact",
            ok_needs(),
            with(|s| s[1] = None),
            CouldNotLook,
        ),
        case(
            "a shard uploaded no outcomes.json",
            ok_needs(),
            with(|s| shard(s, 1).report = false),
            CouldNotLook,
        ),
        case(
            "the shard matrix was cancelled",
            needs_json("success", "true", "success", "true", "3", "cancelled"),
            clean_shards(),
            CouldNotLook,
        ),
        case(
            "the shard matrix failed",
            needs_json("success", "true", "success", "true", "3", "failure"),
            clean_shards(),
            CouldNotLook,
        ),
        case(
            "the detector failed",
            needs_json("failure", "", "skipped", "", "", "skipped"),
            Vec::new(),
            CouldNotLook,
        ),
        case(
            "the plan job failed",
            needs_json("success", "true", "failure", "", "", "skipped"),
            Vec::new(),
            CouldNotLook,
        ),
        case(
            "an unknown job result",
            needs_json("success", "true", "success", "true", "3", "neutral"),
            clean_shards(),
            CouldNotLook,
        ),
        case(
            "an empty mutate output",
            skipped("", ""),
            Vec::new(),
            CouldNotLook,
        ),
        case(
            "a shard_count that is not a number",
            needs_json("success", "true", "success", "true", "", "success"),
            clean_shards(),
            CouldNotLook,
        ),
        case(
            "the plan's shard_count disagrees with the shards",
            needs_json("success", "true", "success", "true", "2", "success"),
            clean_shards(),
            CouldNotLook,
        ),
        case(
            "the unmutated tree failed",
            ok_needs(),
            with(|s| {
                let sh = shard(s, 0);
                sh.outcomes.clear();
                sh.baseline = "Failure";
                sh.console = "Found 3 mutants to test\nERROR cargo build failed in an unmutated tree, so no mutants were tested\n";
            }),
            Fails,
        ),
        case(
            "timeouts over the bound",
            ok_needs(),
            with(|s| {
                for o in &mut shard(s, 0).outcomes {
                    o.1 = "Timeout";
                }
            }),
            Fails,
        ),
        case(
            "a shard tested another shard's mutant (overlap)",
            ok_needs(),
            with(|s| shard(s, 2).outcomes.push(("m0".into(), "CaughtMutant"))),
            Fails,
        ),
        case(
            "an outcome outside the plan",
            ok_needs(),
            with(|s| {
                shard(s, 2)
                    .outcomes
                    .push(("not-planned".into(), "CaughtMutant"))
            }),
            Fails,
        ),
        case(
            "a mutant reported twice",
            ok_needs(),
            with(|s| {
                let first = shard(s, 1).outcomes[0].clone();
                shard(s, 1).outcomes.push(first);
            }),
            Fails,
        ),
        case(
            "a mutant with a non-verdict summary",
            ok_needs(),
            with(|s| shard(s, 0).outcomes[0].1 = "Success"),
            CouldNotLook,
        ),
        case(
            "a shard ran a different commit",
            ok_needs(),
            with(|s| shard(s, 2).commit = "ffffffffffffffffffffffffffffffffffffffff"),
            CouldNotLook,
        ),
        case(
            "a shard ran a different cargo-mutants",
            ok_needs(),
            with(|s| shard(s, 1).version = "27.0.0"),
            Fails,
        ),
        Case {
            plan_commit: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            ..case(
                "the plan is from another commit",
                ok_needs(),
                clean_shards(),
                CouldNotLook,
            )
        },
        Case {
            plan_version: "cargo-mutants 26.0.0",
            ..case(
                "the plan used an unpinned cargo-mutants",
                ok_needs(),
                clean_shards(),
                Fails,
            )
        },
        Case {
            of: Some((2, 4)),
            ..case(
                "a shard sized for a different count",
                ok_needs(),
                clean_shards(),
                CouldNotLook,
            )
        },
    ]
}

fn write_case(root: &Path, c: &Case) -> Result<(PathBuf, PathBuf)> {
    let plan = root.join("plan");
    let shards = root.join("shards");
    fs::create_dir_all(&plan)?;
    fs::create_dir_all(&shards)?;
    let list: Vec<_> = FX_PLAN
        .iter()
        .map(|n| serde_json::json!({"name": n, "file": "crates/portcullis/src/guard.rs"}))
        .collect();
    fs::write(plan.join("list.json"), serde_json::to_string(&list)?)?;
    fs::write(plan.join("commit.txt"), format!("{}\n", c.plan_commit))?;
    fs::write(plan.join("version.txt"), format!("{}\n", c.plan_version))?;
    for (k, fx) in c.shards.iter().enumerate() {
        let Some(fx) = fx else { continue };
        let of = match c.of {
            Some((kk, of)) if kk == k => of,
            _ => c.shards.len(),
        };
        let dir = shards.join(format!("{SHARD_PREFIX}{k}-of-{of}"));
        fs::create_dir_all(dir.join("mutants.out"))?;
        fs::write(dir.join("console.log"), fx.console)?;
        fs::write(dir.join("commit.txt"), format!("{}\n", fx.commit))?;
        if !fx.report {
            continue;
        }
        let mut outcomes =
            vec![serde_json::json!({"scenario": "Baseline", "summary": fx.baseline})];
        for (name, summary) in &fx.outcomes {
            outcomes.push(serde_json::json!({
                "scenario": {"Mutant": {"name": name, "file": "crates/portcullis/src/guard.rs"}},
                "summary": summary,
            }));
        }
        let n = fx.outcomes.len();
        let report = serde_json::json!({
            "outcomes": outcomes,
            // What an interrupted run writes: counts consistent with themselves. Never read.
            "total_mutants": n, "caught": n, "missed": 0, "timeout": 0, "unviable": 0,
            "start_time": "2026-10-14T00:00:00Z",
            "end_time": if fx.finished { serde_json::json!("2026-10-14T00:10:00Z") } else { serde_json::Value::Null },
            "cargo_mutants_version": fx.version,
        });
        fs::write(
            dir.join("mutants.out").join("outcomes.json"),
            serde_json::to_string(&report)?,
        )?;
    }
    Ok((plan, shards))
}

fn classify(v: &Verdict) -> Expect {
    match v.exit_code() {
        0 => Expect::Green,
        1 => Expect::Fails,
        _ => Expect::CouldNotLook,
    }
}

fn run_case(c: &Case) -> Result<Verdict> {
    let tmp = tempfile::tempdir()?;
    let (plan, shards) = write_case(tmp.path(), c)?;
    Ok(decide(&Inputs {
        needs: &c.needs,
        plan: &plan,
        shards: &shards,
        commit: FX_COMMIT,
        expect_version: FX_VERSION,
        max_timeout: 2,
        max_unviable: 50,
    }))
}

fn self_test() -> Result<()> {
    let all = cases();
    let mut wrong = Vec::new();
    for c in &all {
        let v = run_case(c)?;
        let got = classify(&v);
        if got != c.expect {
            wrong.push(format!(
                "{}: expected {:?}, got {got:?} ({v:?})",
                c.name, c.expect
            ));
        }
    }
    for n in [1usize, 59, 60, 61, 129, 607] {
        let k = shard_count(n, 60, 8)?;
        if k == 0 || k > n || k > 8 || (k < 8 && n.div_ceil(k) > 60) {
            wrong.push(format!("shard_count({n}, 60, 8) = {k}"));
        }
    }
    if shard_count(0, 60, 8).is_ok() {
        wrong.push("shard_count(0, ..) planned an empty run".into());
    }
    if !wrong.is_empty() {
        for w in &wrong {
            println!("::error::self-test: {w}");
        }
        bail!(
            "{} of the mutants-gate fixtures decided wrongly",
            wrong.len()
        );
    }
    println!(
        "ok: self-test: {} fixtures; a truncated report, a missing or cancelled shard, a survivor, an overlap, a foreign commit or version and every other red case red; a clean sharded run green",
        all.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> Case {
        cases()
            .into_iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no fixture {name}"))
    }

    fn verdict(name: &str) -> Verdict {
        run_case(&named(name)).unwrap_or_else(|e| panic!("{name}: {e:#}"))
    }

    fn problems(v: Verdict) -> Vec<Problem> {
        match v {
            Verdict::Red { problems, .. } => problems,
            other => panic!("expected red, got {other:?}"),
        }
    }

    fn says(ps: &[Problem], needle: &str) -> bool {
        ps.iter().any(|p| {
            let (Problem::CouldNotLook(s) | Problem::Fails(s)) = p;
            s.contains(needle)
        })
    }

    #[test]
    fn every_fixture_decides_as_declared() {
        for c in cases() {
            let v = run_case(&c).unwrap();
            assert_eq!(classify(&v), c.expect, "{}: {v:?}", c.name);
        }
    }

    #[test]
    fn the_self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn all_clean_is_green_and_counts_the_whole_plan() {
        match verdict("all clean") {
            Verdict::Clean { shards, tally } => {
                assert_eq!(shards, FX_SHARDS);
                assert_eq!(tally.caught, FX_PLAN.len());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_truncated_report_is_refused_by_name() {
        let ps = problems(verdict(
            "a truncated report (no end_time, short of the plan)",
        ));
        assert!(
            says(&ps, "shard 0 of 3: outcomes.json has no end_time"),
            "{ps:?}"
        );
        // Shard 0's share is m0, m3, m6; the report stopped after m0.
        assert!(
            says(
                &ps,
                "shard 0 of 3 tested 1 of its 3 planned mutants; untested: m3; m6"
            ),
            "{ps:?}"
        );
    }

    #[test]
    fn missing_shard_could_not_look_and_names_it() {
        let v = verdict("a shard uploaded no artifact");
        assert_eq!(v.exit_code(), 2);
        assert!(says(&problems(v), "shard(s) [1] of 3"));
    }

    #[test]
    fn cancelled_shard_could_not_look_even_with_every_report() {
        assert_eq!(verdict("the shard matrix was cancelled").exit_code(), 2);
    }

    #[test]
    fn survivor_is_red_and_named() {
        let v = verdict("a survivor in one shard");
        assert_eq!(v.exit_code(), 1);
        // Shard 1's share is m1, m4; the second is the survivor.
        assert!(says(
            &problems(v),
            "SURVIVED in security-critical modules: m4"
        ));
    }

    #[test]
    fn tested_not_planned_is_red_although_the_report_agrees_with_itself() {
        let ps = problems(verdict("a finished report short of its share"));
        assert!(
            says(&ps, "tested 2 of its 3 planned mutants; untested: m6"),
            "{ps:?}"
        );
    }

    #[test]
    fn overlap_is_red_by_identity() {
        let ps = problems(verdict("a shard tested another shard's mutant (overlap)"));
        assert!(
            says(&ps, "shard 2 of 3 tested 1 mutant(s) outside its share"),
            "{ps:?}"
        );
    }

    #[test]
    fn no_op_paths_are_green_only_on_an_exact_false() {
        assert_eq!(
            verdict("detector: nothing to mutate"),
            Verdict::NothingToMutate
        );
        assert_eq!(
            verdict("plan: no mutants in diff"),
            Verdict::NoMutantsInDiff
        );
        assert_eq!(verdict("an empty mutate output").exit_code(), 2);
    }

    #[test]
    fn needs_that_do_not_parse_could_not_look() {
        let tmp = tempfile::tempdir().unwrap();
        let v = decide(&Inputs {
            needs: "not json",
            plan: tmp.path(),
            shards: tmp.path(),
            commit: FX_COMMIT,
            expect_version: FX_VERSION,
            max_timeout: 5,
            max_unviable: 50,
        });
        assert_eq!(v.exit_code(), 2);
    }

    #[test]
    fn shard_count_follows_the_plan() {
        assert_eq!(shard_count(1, 60, 8).unwrap(), 1);
        assert_eq!(shard_count(60, 60, 8).unwrap(), 1);
        assert_eq!(shard_count(61, 60, 8).unwrap(), 2);
        assert_eq!(shard_count(129, 60, 8).unwrap(), 3);
        assert_eq!(shard_count(607, 60, 8).unwrap(), 8);
        // Never more shards than mutants, so every round-robin shard has a report.
        assert_eq!(shard_count(2, 1, 8).unwrap(), 2);
        assert_eq!(shard_count(3, 1, 2).unwrap(), 2);
        assert!(shard_count(0, 60, 8).is_err());
        assert!(shard_count(5, 0, 8).is_err());
    }

    #[test]
    fn plan_writes_the_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let list = tmp.path().join("list.json");
        let names: Vec<_> = (0..129)
            .map(|i| serde_json::json!({"name": format!("m{i}")}))
            .collect();
        fs::write(&list, serde_json::to_string(&names).unwrap()).unwrap();
        let out = tmp.path().join("out");
        plan(&list, 60, 8, &out).unwrap();
        assert_eq!(
            fs::read_to_string(&out).unwrap(),
            "shard_count=3\nshards=[0,1,2]\n"
        );
    }

    #[test]
    fn the_real_outcomes_shape_parses() {
        // Trimmed from cargo-mutants 27.1.0's report on #3481 (2026-10-14).
        let text = r#"{"outcomes":[
            {"scenario":"Baseline","summary":"Success","log_path":"log/baseline.log","diff_path":null,"phase_results":[]},
            {"scenario":{"Mutant":{"name":"crates/portcullis/src/capability.rs:77:9: replace Obligations::remove -> bool with true","file":"crates/portcullis/src/capability.rs","function":{"function_name":"Obligations::remove"},"genre":"FnValue","package":"portcullis","replacement":"true","span":{"start":{"line":77,"column":9},"end":{"line":77,"column":35}}}},"summary":"CaughtMutant","log_path":"log/x.log","diff_path":"diff/x.diff","phase_results":[]}],
            "total_mutants":129,"missed":1,"caught":95,"timeout":0,"unviable":33,"success":0,
            "start_time":"2026-10-14T16:54:40.91167845Z","end_time":"2026-10-14T17:30:25.311082629Z","cargo_mutants_version":"27.1.0"}"#;
        let o: Outcomes = serde_json::from_str(text).unwrap();
        assert_eq!(o.outcomes.len(), 2);
        assert!(o.end_time.is_some());
        assert_eq!(o.cargo_mutants_version, "27.1.0");
    }

    #[test]
    fn render_names_could_not_look() {
        let (console, md) = render(&verdict("a shard uploaded no artifact"));
        assert!(
            console
                .iter()
                .any(|l| l.starts_with("::error::COULD NOT LOOK"))
        );
        assert!(md.contains("RED"));
    }
}
