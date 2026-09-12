//! `xtask` — the workspace task runner.
//!
//! Rust-native replacement for ad-hoc shell scripts, invoked as `cargo xtask
//! <command>` (via the `.cargo/config.toml` alias) and fronted by `just`
//! recipes. Per the repo's "Rust-based tooling first" convention, build/CI/dev
//! orchestration that lives in `scripts/*.sh` is migrated here one command at a
//! time, so it is cross-platform, type-checked, and testable.
//!
//! Scripts that must stay shell — anything that runs *inside* the Firecracker
//! guest or at boot, in-container smoke tests, the GitHub-action entrypoint, and
//! the curl-bootstrap installer — are intentionally NOT ported.
//!
//! This first commit is the harness plus one read-only command (`scripts`),
//! which inventories the shell scripts and flags which are port candidates —
//! i.e. it tracks its own migration backlog. Subsequent commits port one
//! orchestration script per change.

use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Nucleus workspace task runner (cargo xtask <command>)",
    long_about = "Rust-native dev/CI task runner. Run via `cargo xtask <command>` \
                  or `just xtask <command>`. Shell scripts are migrated here over \
                  time; see `cargo xtask scripts` for the remaining backlog."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Prepare exact-tree, offline Rust build inputs for a nucleus microVM.
    BuildImage(build_image::Args),
    /// Build nucleus in a prepared microVM image and verify cold/warm artifacts.
    BuildRun(build_image::execute::Args),
    /// Run the microVM build experiment with a disposable bootstrap node/key.
    BuildBootstrap(build_image::execute::BootstrapArgs),
    /// Build again using a verified predecessor artifact as the disposable node.
    BuildSuccessor(build_image::successor::Args),
    /// Export only public build experiment evidence, excluding all private keys.
    BuildEvidence(build_image::execute::EvidenceArgs),
    /// Measure private image cloning and verification on this host filesystem.
    BuildCacheProbe(build_image::scratch_cache::ProbeArgs),
    /// Emit explicit Lean-action targets for the library coverage gate.
    LeanActionBuilds {
        /// Limit output to one workflow, for its per-theorem audit.
        #[arg(long)]
        workflow: Option<std::path::PathBuf>,
    },
    /// Inventory repo shell scripts and flag which are xtask port candidates.
    Scripts,
    /// The two pins naming gatehouse must agree: `.gatehouse/pipeline.writ`'s import
    /// digest must be the SHA-256 of `prelude/ci.writ` at `gatehouse-plan.yml`'s
    /// `GATEHOUSE_REF`. Decided from declarations alone; reads no source tree.
    GatehousePin {
        /// A checkout of `coproduct-private/gatehouse`, which must be AT the pinned ref.
        /// Without it only the two nucleus-side declarations can be read.
        #[arg(long)]
        gatehouse: Option<std::path::PathBuf>,
    },
    /// Line-count ratchet, split by what decides the verdict.
    ///
    /// The declaration half is decided by `.line-ratchet.toml` alone and would give
    /// the same answer against an empty checkout; the count half needs the tree. Both
    /// historical defects of this gate lived in the declaration half, because a shell
    /// script has `awk` and `head -1` where this has a parser.
    LineRatchet {
        /// Exit non-zero on a count violation. A malformed declaration fails either way.
        #[arg(long)]
        strict: bool,
        /// Emit the parsed `[[files]]` entries as JSON and exit, so the post-merge
        /// ratchet workflow can share this parser instead of hand-rolling a second one.
        #[arg(long)]
        entries: bool,
    },
    /// A SHA of this repo pinned by this repo must still match the working tree.
    SelfPin,
    /// One fact written in several files must have one value: the elan release and its
    /// checksum, the aeneas/charon pins, the first-party lean-toolchain files. Decided
    /// from committed declarations alone — no source tree, no toolchain.
    PinParity,
    /// A gate that is not running looks exactly like a gate that is passing.
    /// GitHub drops scheduled runs entirely under load -- not failed, not
    /// cancelled, never created -- and on 2026-09-09 `ci-assurance` lost about
    /// seven in a row with no notification (#2652). Reds when the newest
    /// conclusion is older than a multiple of the schedule's own period.
    ScheduleLiveness {
        /// `owner/repo` to ask about.
        #[arg(long, default_value = "coproduct-opensource/nucleus")]
        repo: String,
        /// Workflow file name under `.github/workflows`.
        #[arg(long, default_value = "ci-assurance.yml")]
        workflow: String,
        /// How many periods may pass before absence is a finding.
        #[arg(long, default_value_t = 3)]
        periods: u32,
    },
    /// Clippy reads ONE `clippy.toml` -- the nearest -- and does not merge, so a
    /// crate-level config silently drops every root entry. Measured: the two entries
    /// ADR 0007 wired were not enforced in `nucleus-tool-proxy`, which holds the HTTP
    /// and MCP effect boundary. Decided from committed files alone.
    ClippyConfig,
    /// The committed `POOLS` default in ci/fly-runner/manager.toml must be a
    /// configuration the manager accepts, checked with the manager's own validator.
    FlyPools,
    /// A workflow step that runs `git push` must carry its own credential, rather than
    /// the one `actions/checkout` left behind — that one is wired with `includeIf.gitdir`
    /// and depends on the runner's filesystem layout. Decided from the workflows alone.
    PushAuth,
    /// Every `--fail-under-lines` in coverage-matrix.yml must equal the value pinned in
    /// ci/coverage-floor.txt, so moving a coverage floor has to be written down. Decided
    /// from two committed files; measures no coverage.
    CoverageFloor,
    /// A gate's own timeout must fire before the job running it is killed, or a gate
    /// that overruns is reported as `cancelled` and carries no verdict. Decided from the
    /// workflow and the action definition alone.
    GateBudget,
    /// A `run:` block that pipes without `pipefail` discards the exit status of every command
    /// but the last. Decided from workflow YAML alone; reads no source tree.
    Pipefail,
    /// A crate outside the workspace is reached by no `--workspace` command. Decided from
    /// `cargo metadata` and Cargo.toml's own `exclude` list.
    WorkspaceMembers,
    /// A claim's falsifier must produce a REQUIRED context. A gate CI runs, that goes red, and
    /// that the merge queue merges past anyway enforces nothing — it is a red light beside an
    /// open gate. Ratcheted, not driven to zero: whether a given check should be required is a
    /// judgement about cost, and this only makes the gap visible and un-growable.
    AssuranceRequired,
    /// The scan-vs-allowlist family, decided once instead of by five copies of the same
    /// `#[cfg(test)]`-stripping awk program. Adds what the copies cannot say: a pattern that
    /// matches nothing has stopped watching, and an allowlist may only shrink.
    AllowlistGates {
        /// Compare this harness with the shell gate it replaces, script by script. The port is
        /// only worth having if it decides the same thing.
        #[arg(long)]
        parity: bool,
    },
    /// Every source Kani harness must have a CI lane or a named documented exception.
    KaniCoverage,
    /// A mechanism declared dead in `scripts/law-mechanisms-manifest.txt` must
    /// still be dead: its anchor present in the file that declares it, and
    /// absent from every other production region.
    ///
    /// Built from the 2026-09-09 audit finding that most of nucleus's
    /// algebraic unifications are already written, several machine-proved, and
    /// not wired to the enforcement path — the general case of the class C8
    /// gates for the Aeneas predicates.
    LawMechanisms,
    /// How far the tree is from ADR 0006's four objects, on the two arrows
    /// whose population can be enumerated from a source: `linearity` (a
    /// one-shot right taken by value) and `act_coverage` (a protected boundary
    /// carrying its target). `attenuation` and `lineage` are excluded because a
    /// hand-listed denominator is the metric equivalent of a gate that cannot
    /// fail — see `.convergence-ratchet.toml`.
    Convergence,
    /// A witness accepted and dropped is a gate that is present but does
    /// nothing. Every `_`-bound authority/attestation parameter in the
    /// production region must be declared in
    /// `scripts/inert-authority-manifest.txt`, with an exact count per
    /// `(file, impl target)` and a reason.
    ///
    /// The dual of `law-mechanisms`: that gate finds mechanisms with no call
    /// site, this finds mechanisms that are called and then ignored.
    InertAuthority,
    /// How much of the enforcement the repo *declares* is actually reachable —
    /// `B / D` over witness-accepting parameter sites, pinned as a floor in
    /// `.bound-ratchet.toml`.
    ///
    /// Built from the 2026-09-11 census of 868 issues: of the 120 that are
    /// `bug`-labelled or audit-prefixed, 72 (60%, 64 of them security) are one
    /// defect — a mechanism that exists and that nothing binds to the live
    /// path. This counts one exactly-enumerable class of it. `--measure`
    /// prints the census without gating; `--badge` emits shields.io JSON.
    Bound {
        #[arg(long)]
        measure: bool,
        #[arg(long)]
        badge: bool,
    },
    /// One card, one row per defect family, and a badge naming the WEAKEST —
    /// not an average, which would let a family at zero hide behind one at a
    /// hundred (ADR 0007 I-1).
    ///
    /// Each family reports population (obligations the tree declares),
    /// discharged (those a mechanism that can fail covers) and undeclared
    /// (sites with the family's shape that are outside the population). Pinned
    /// per family in `.scorecard-ratchet.toml`, two floors each: on the ratio,
    /// so it cannot fall, and on the population, because deleting an obligation
    /// raises the ratio without discharging anything.
    Scorecard {
        #[arg(long)]
        measure: bool,
        #[arg(long)]
        badge: bool,
    },
    /// Build every workspace crate in isolation (`cargo build -p <crate>`) to
    /// catch feature-unification-masked breakages — crates that compile in a
    /// full `--workspace` build but fail standalone (and on `cargo publish`)
    /// because a dependency feature is only enabled by a sibling crate.
    ///
    /// This is the bug class that hid the `nucleus-fly-oidc` missing-`json`
    /// reqwest feature and the `portcullis` `default-features = false` break.
    CheckIsolation,
    /// Constitutional gate (most-paranoid #5): run ck-kernel admission on a
    /// PolicyManifest amendment. Exits non-zero if the candidate is non-monotone
    /// (capability/IO/budget/proof-req escalation, anti-coup) or touches a
    /// `may_not_modify` path. This is the in-repo replacement for the external
    /// closed "Constitutional Gate" — the kernel is now actually invoked.
    PolicyGate {
        /// Path to the base (parent) PolicyManifest.toml.
        #[arg(long)]
        base: String,
        /// Path to the candidate (head) PolicyManifest.toml.
        #[arg(long)]
        candidate: String,
        /// Optional path to a newline-delimited list of changed repo files
        /// (checked against the parent's `may_not_modify` rules).
        #[arg(long)]
        changed_files: Option<String>,
    },
    /// Turn observed CANCELLED workflow runs into a SAFE set of re-runs.
    ///
    /// Re-running a run makes it new, so `cancel-in-progress` cancels its
    /// sibling in the same concurrency group. Re-running two runs of the SAME
    /// workflow on one PR therefore makes each cancel the other and the number
    /// of cancelled checks goes up.
    ///
    /// Reads `[{"pr":N,"workflow":"...","run_id":N}, ...]` on stdin and prints
    /// one run id per line: at most one per (pr, workflow), never dropping a
    /// workflow. The constraint is the map key, so the unsafe batch is not a
    /// value this can emit.
    RerunPlan,
    /// Where does one commit's CI time go? Pulls every workflow run for a
    /// commit through `gh api` and reports per-runner-label run-time and
    /// queue-wait distributions, the wall clock and critical path, the longest
    /// jobs with their longest steps, and setup-vs-work overhead. The number a
    /// CI-optimisation change has to move; run it before and after.
    CiTimings {
        /// Commit to report on (default: HEAD).
        #[arg(long)]
        sha: Option<String>,
        /// How many of the longest jobs to list.
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// Dump one JSON object per job instead of the report.
        #[arg(long)]
        json: bool,
    },
    /// How often does a merge-queue entry EJECT, and on what? The number that
    /// decides a batch size: batching multiplies the cost of a red, so a queue
    /// that does not know its ejection rate can only guess at one. Counts only
    /// DECIDED entries — an entry the queue still holds is in flight, not an
    /// ejection, which is the distinction measuring it by hand got wrong.
    CiEjections {
        /// Workflow runs to scan, paginated. A merge group is ~31 runs, so
        /// 100 is only ~3 entries; the default aims at a usable sample.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        /// Dump one JSON object per entry instead of the report.
        #[arg(long)]
        json: bool,
    },
    /// CI configuration is sound (CI-1): decide the invariants the merge queue
    /// relies on over a typed model of the workflows, the required-check
    /// ledger (ci/required-checks.txt) and the merge-queue pin
    /// (ci/merge-queue.toml). Exit 0 clean, 1 violation, 2 could not look.
    CiSpec {
        #[command(subcommand)]
        cmd: CiSpecCmd,
    },
    /// The exemplar scoreboard's anti-Goodhart ratchet (lower-is-better
    /// metrics may not rise, higher-is-better may not fall, `_GUARD`s may
    /// not drop). Ported from exemplar-scoreboard.yml's python3 heredoc.
    ScoreboardRatchet {
        /// The freshly generated scoreboard.json.
        #[arg(long)]
        current: String,
        /// The pinned baseline (scripts/exemplar-baseline.json).
        #[arg(long)]
        baseline: String,
    },
    /// Push the last N minutes of GitHub Actions job timings to an OTLP
    /// endpoint as OpenTelemetry metrics (queue wait, duration, conclusions,
    /// merge-queue depth). See crates/xtask/src/ci_otel.rs.
    CiOtel {
        /// Window in minutes (a job counts when its completed_at is inside).
        #[arg(long, default_value_t = 15)]
        since: u64,
        /// OTLP/HTTP base URL (default: $OTEL_EXPORTER_OTLP_ENDPOINT, else the in-cluster collector).
        #[arg(long)]
        endpoint: Option<String>,
        /// Print the OTLP JSON instead of sending it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum CiSpecCmd {
    /// Run every invariant and report.
    Check {
        /// Repository root (default: the git toplevel).
        #[arg(long)]
        repo: Option<String>,
        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the inline-gate inventory (ci/inline-gates.txt shape).
    /// Every check context a workflow produces that ci/required-checks.txt does
    /// NOT list. Advisory contexts block nothing, so one can be red on main
    /// indefinitely -- which happened on 2026-09-11. Prints the set so
    /// advisory-by-accident can be told from advisory-by-decision.
    Advisory {
        /// Repository root (defaults to the current directory).
        #[arg(long)]
        repo: Option<String>,
    },
    InlineGates {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Live parity: ci/required-checks.txt == GitHub branch protection, and
    /// ci/merge-queue.toml == the live merge-queue ruleset. Observation via
    /// `gh api` (needs a token that can read branch protection); a fetch
    /// that fails is exit 2, never a pass.
    LiveParity {
        #[arg(long)]
        repo: Option<String>,
        /// GitHub repository, owner/name.
        #[arg(long, default_value = "coproduct-opensource/nucleus")]
        github: String,
        #[arg(long)]
        json: bool,
    },
    /// Render crates/ci-spec/tests/golden/queue_traces.json as
    /// ci/lean/CiSpec/Golden.lean (stdout). CI regenerates and diffs.
    GenGolden {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Replay the merge queue's recent history (PR timeline events via
    /// `gh api graphql`) through the queue model. Exit 0 clean, 1 a
    /// transition the model rejects, 2 vacuous window / could not look.
    TraceCheck {
        #[arg(long, default_value = "coproduct-opensource/nucleus")]
        github: String,
        #[arg(long, default_value_t = 24)]
        since_hours: u64,
        #[arg(long)]
        json: bool,
    },
}

mod alg;
mod allowlist_gates;
mod assurance_required;
mod bound;
mod build_image;
mod ci_ejections;
mod ci_otel;
mod ci_spec;
mod ci_timings;
mod clippy_config;
mod convergence;
mod coverage_floor;
mod fly_pools;
mod gate_budget;
mod gatehouse_pin;
mod inert_authority;
mod kani_coverage;
mod law_mechanisms;
mod lean_action_builds;
mod life;
mod line_ratchet;
mod pin_parity;
mod pipefail;
mod push_auth;
mod rerun_plan;
mod schedule_liveness;
mod scoreboard;
mod scorecard;
mod self_pin;
mod suppress;
mod tot;
mod typed;
mod workspace_members;

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Scripts => scripts(),
        Command::BuildImage(args) => build_image::run(args),
        Command::BuildRun(args) => build_image::execute::run(args),
        Command::BuildBootstrap(args) => build_image::execute::bootstrap(args),
        Command::BuildSuccessor(args) => build_image::successor::run(args),
        Command::BuildEvidence(args) => build_image::execute::evidence(args),
        Command::BuildCacheProbe(args) => build_image::scratch_cache::probe(args),
        Command::LeanActionBuilds { workflow } => lean_action_builds::run(workflow.as_deref()),
        Command::CheckIsolation => check_isolation(),
        Command::PolicyGate {
            base,
            candidate,
            changed_files,
        } => policy_gate(&base, &candidate, changed_files.as_deref()),
        Command::RerunPlan => rerun_plan_cmd(),
        Command::CiTimings { sha, top, json } => ci_timings::ci_timings(sha, top, json),
        Command::CiEjections { limit, json } => ci_ejections::ci_ejections(limit, json),
        Command::SelfPin => match self_pin::check(&std::env::current_dir()?)? {
            // 2 is "could not look", which is never a pass. Mapped here rather than
            // exited from inside the check, so a unit test calling it survives.
            self_pin::Outcome::CouldNotLook => std::process::exit(2),
            self_pin::Outcome::Clean => Ok(()),
        },
        Command::PinParity => pin_parity::check(&std::env::current_dir()?),
        Command::ScheduleLiveness {
            repo,
            workflow,
            periods,
        } => match schedule_liveness::run(&repo, &workflow, periods) {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        Command::ClippyConfig => match clippy_config::run(&std::env::current_dir()?)? {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        Command::FlyPools => fly_pools::check(&std::env::current_dir()?),
        Command::PushAuth => push_auth::check(&std::env::current_dir()?),
        Command::CoverageFloor => coverage_floor::check(&std::env::current_dir()?),
        Command::GateBudget => gate_budget::check(&std::env::current_dir()?),
        Command::Pipefail => pipefail::check(&std::env::current_dir()?),
        Command::WorkspaceMembers => workspace_members::check(&std::env::current_dir()?),
        Command::AssuranceRequired => assurance_required::check(&std::env::current_dir()?),
        Command::AllowlistGates { parity } => {
            let root = std::env::current_dir()?;
            if parity {
                allowlist_gates::parity(&root)
            } else {
                allowlist_gates::check(&root)
            }
        }
        Command::KaniCoverage => kani_coverage::check(&std::env::current_dir()?),
        // Exit code mapped here rather than inside the check, so a unit test
        // calling `run()` survives — the SelfPin arm's reasoning.
        Command::Convergence => match convergence::run()? {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        Command::LawMechanisms => match law_mechanisms::run()? {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        // Exit code mapped here, not inside the check, for the SelfPin arm's
        // reason: a unit test calling `run()` must survive.
        Command::InertAuthority => match inert_authority::run()? {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        Command::Bound { measure, badge } => match bound::run(measure, badge)? {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        Command::Scorecard { measure, badge } => match scorecard::run(measure, badge)? {
            0 => Ok(()),
            code => std::process::exit(code),
        },
        Command::GatehousePin { gatehouse } => {
            gatehouse_pin::check(&std::env::current_dir()?, gatehouse)
        }
        Command::LineRatchet { strict, entries } => {
            if entries {
                line_ratchet::entries_json()
            } else {
                line_ratchet::check(strict)
            }
        }
        Command::CiSpec { cmd } => match cmd {
            CiSpecCmd::Check { repo, json } => ci_spec::check(repo, json),
            CiSpecCmd::Advisory { repo } => ci_spec::advisory(repo),
            CiSpecCmd::InlineGates { repo } => ci_spec::inline_gates(repo),
            CiSpecCmd::LiveParity { repo, github, json } => {
                ci_spec::live_parity(repo, &github, json)
            }
            CiSpecCmd::GenGolden { repo } => ci_spec::gen_golden(repo),
            CiSpecCmd::TraceCheck {
                github,
                since_hours,
                json,
            } => ci_spec::trace_check(&github, since_hours, json),
        },
        Command::ScoreboardRatchet { current, baseline } => {
            scoreboard::scoreboard_ratchet(&current, &baseline)
        }
        Command::CiOtel {
            since,
            endpoint,
            dry_run,
        } => ci_otel::ci_otel(since, endpoint, dry_run),
    }
}

/// Gate a PolicyManifest amendment through the constitutional kernel (Preflight
/// mode: monotonicity + `may_not_modify`, signatures skipped). Exits the process
/// with code 1 on rejection so CI fails the PR.
fn policy_gate(base: &str, candidate: &str, changed_files: Option<&str>) -> Result<()> {
    use ck_kernel::{GateMode, gate_manifest_amendment};
    use ck_types::{AdmissionDecision, PolicyManifest};

    let base_src =
        std::fs::read_to_string(base).with_context(|| format!("reading base manifest {base}"))?;
    let cand_src = std::fs::read_to_string(candidate)
        .with_context(|| format!("reading candidate manifest {candidate}"))?;
    let parent = PolicyManifest::from_toml(&base_src)
        .map_err(|e| anyhow!("parsing base manifest {base}: {e}"))?;
    let cand = PolicyManifest::from_toml(&cand_src)
        .map_err(|e| anyhow!("parsing candidate manifest {candidate}: {e}"))?;

    let files: Vec<String> = match changed_files {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading changed-files list {path}"))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        None => Vec::new(),
    };

    let outcome = gate_manifest_amendment(&parent, &cand, &files, GateMode::Preflight);
    match outcome.decision {
        AdmissionDecision::Accepted { .. } => {
            println!(
                "constitutional gate: PolicyManifest amendment ACCEPTED \
                 (monotone; may_not_modify respected)"
            );
            Ok(())
        }
        AdmissionDecision::Rejected { reasons } => {
            eprintln!("constitutional gate: PolicyManifest amendment REJECTED");
            for r in &reasons {
                eprintln!("  - {:?}: {}", r.invariant, r.message);
            }
            std::process::exit(1);
        }
        other => {
            // Quarantined / Expired — not an acceptance; fail the gate.
            eprintln!("constitutional gate: amendment NOT accepted: {other:?}");
            std::process::exit(1);
        }
    }
}

/// Shell scripts that must remain shell (run in the guest/at boot, in a
/// container, as the GH-action entrypoint, or as a curl-bootstrap installer).
/// Matched by path suffix.
const KEEP_AS_SHELL: &[&str] = &[
    "scripts/firecracker/guest-init.sh",
    "scripts/firecracker/guest-net.sh",
    "scripts/firecracker/build-rootfs.sh",
    "scripts/firecracker/build-scratch.sh",
    "scripts/container/smoke-test.sh",
    "scripts/action-entrypoint.sh",
    "scripts/install.sh",
];

/// Walk the repo (skipping `target/`, `.git/`, `node_modules/`) and list every
/// `*.sh`, marking each as a port candidate or "keep as shell".
fn scripts() -> Result<()> {
    let root = repo_root()?;
    let mut found = Vec::new();
    collect_sh(&root, &root, &mut found)?;
    found.sort();

    let (keep, port): (Vec<_>, Vec<_>) = found
        .iter()
        .partition(|rel| KEEP_AS_SHELL.iter().any(|k| rel.ends_with(k)));

    println!("Shell scripts ({} total)\n", found.len());
    println!("  PORT CANDIDATES → xtask + just ({}):", port.len());
    for p in &port {
        println!("    [ ] {p}");
    }
    println!("\n  KEEP AS SHELL ({}):", keep.len());
    for k in &keep {
        println!("    [x] {k}");
    }
    Ok(())
}

/// The workspace root = parent of this crate's manifest dir's parent
/// (`crates/xtask` → `crates` → root).
fn repo_root() -> Result<std::path::PathBuf> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("could not locate workspace root from {manifest:?}"))
}

fn collect_sh(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Skip build output, vendored trees, and any dot-dir (.git, .venv,
            // .lake, .verus, …) so the inventory shows only first-party scripts.
            if name.starts_with('.')
                || matches!(name, "target" | "node_modules" | "dist" | "vendor")
            {
                continue;
            }
            // Skip anything that is its own checkout. A git WORKTREE (`wt-2630/`,
            // `wt-hoist/`, …) carries a `.git` FILE rather than a directory, so the
            // dot-dir rule above does not see it and the walk descends into a second
            // copy of the whole repository. That is not a cosmetic miscount: this
            // command IS the port backlog, and it reported "164 total, 150 port
            // candidates" against a real 90 and 83 — a tracker roughly 2x wrong, in
            // the direction that makes the remaining work look hopeless. Testing for
            // `.git` catches worktrees, submodules and stray clones by what they are
            // rather than by a name pattern that the next worktree will not match.
            if path.join(".git").exists() {
                continue;
            }
            collect_sh(root, &path, out)?;
        } else if name.ends_with(".sh")
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

// ── check-isolation ──────────────────────────────────────────────────────────

/// Parse the package names of the workspace members out of
/// `cargo metadata --no-deps --format-version 1` output.
///
/// With `--no-deps`, the `packages` array contains exactly the workspace
/// members, so their `name` fields are the set we want to build in isolation.
/// Pure (no I/O) so it is unit-testable against a fixture.
fn parse_member_names(metadata_json: &str) -> Result<Vec<String>> {
    let value: serde_json::Value =
        serde_json::from_str(metadata_json).context("parsing cargo metadata JSON")?;
    let packages = value
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or_else(|| anyhow!("cargo metadata: missing `packages` array"))?;
    let mut names: Vec<String> = packages
        .iter()
        .filter_map(|pkg| pkg.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Build every workspace crate on its own with `cargo build -p <crate>` and
/// report which fail standalone. Exits non-zero if any crate fails, so it can
/// gate locally or in a (non-fast) CI lane.
fn check_isolation() -> Result<()> {
    let root = repo_root()?;

    let metadata = ProcessCommand::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .context("running `cargo metadata`")?;
    if !metadata.status.success() {
        return Err(anyhow!(
            "`cargo metadata` failed:\n{}",
            String::from_utf8_lossy(&metadata.stderr)
        ));
    }
    let names = parse_member_names(&String::from_utf8_lossy(&metadata.stdout))?;

    println!(
        "Building {} workspace crates in isolation (cargo build -p <crate>)...\n",
        names.len()
    );
    println!(
        "Note: crates with their OWN [workspace] (e.g. portcullis-zkvm-guest) are\n\
         not workspace members and are not swept here.\n"
    );

    let mut failed: Vec<String> = Vec::new();
    for name in &names {
        let status = ProcessCommand::new("cargo")
            .args(["build", "-p", name, "--quiet"])
            .current_dir(&root)
            .status()
            .with_context(|| format!("running `cargo build -p {name}`"))?;
        if status.success() {
            println!("  ok    {name}");
        } else {
            println!("  FAIL  {name}");
            failed.push(name.clone());
        }
    }

    if failed.is_empty() {
        println!("\nAll {} crates build standalone.", names.len());
        Ok(())
    } else {
        Err(anyhow!(
            "{} crate(s) fail to build in isolation (compile in --workspace but not \
             standalone — usually a missing dependency feature only enabled by a \
             sibling crate): {}",
            failed.len(),
            failed.join(", ")
        ))
    }
}

/// Read observed cancelled runs on stdin, print a safe re-run set.
///
/// The observation is I/O and belongs to the caller (`gh api graphql …`); this
/// is only the decision, which is why it is testable with no network.
fn rerun_plan_cmd() -> Result<()> {
    use std::io::Read;
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;

    #[derive(serde::Deserialize)]
    struct Observed {
        pr: u64,
        workflow: String,
        run_id: u64,
    }
    let observed: Vec<Observed> = serde_json::from_str(&raw).map_err(|e| {
        anyhow::anyhow!("stdin is not a JSON array of {{pr, workflow, run_id}}: {e}")
    })?;

    let plan = rerun_plan::RerunPlan::from_observed(observed.into_iter().map(|o| {
        rerun_plan::CancelledRun {
            pr: o.pr,
            workflow: o.workflow,
            run_id: o.run_id,
        }
    }));

    if plan.is_empty() {
        eprintln!("rerun-plan: nothing cancelled — no re-runs needed");
        return Ok(());
    }

    for id in plan.run_ids() {
        println!("{id}");
    }
    // Report the COVERAGE, not just the count: the failure a naive dedupe
    // introduces is dropping a workflow entirely, and that is invisible in a
    // number.
    for k in plan.keys() {
        eprintln!("  #{} {}", k.pr, k.workflow);
    }
    eprintln!(
        "rerun-plan: {} run(s), at most one per (pr, workflow)",
        plan.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_inventory_does_not_descend_into_another_checkout() {
        // A git worktree carries a `.git` FILE, so the dot-dir rule misses it and the
        // walk finds a second copy of every script in the repo. This command is the port
        // backlog, and it read 164/150 against a real 90/83 until that was fixed.
        let tmp = std::env::temp_dir().join("xtask-collect-sh-test");
        let _ = std::fs::remove_dir_all(&tmp);
        let inner = tmp.join("wt-copy");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(tmp.join("mine.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(inner.join("theirs.sh"), "#!/bin/sh\n").unwrap();
        // Make `inner` look like a worktree: a `.git` file, not a directory.
        std::fs::write(inner.join(".git"), "gitdir: /elsewhere\n").unwrap();

        let mut out = Vec::new();
        super::collect_sh(&tmp, &tmp, &mut out).unwrap();
        out.sort();
        assert_eq!(
            out,
            vec!["mine.sh".to_string()],
            "a worktree's scripts are not ours"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    use super::parse_member_names;

    #[test]
    fn parses_and_sorts_member_names() {
        let json = r#"{
            "packages": [
                {"name": "portcullis", "version": "1.0.0"},
                {"name": "nucleus-sdk", "version": "1.0.0"},
                {"name": "nucleus-envelope", "version": "1.0.0"}
            ],
            "workspace_members": []
        }"#;
        let names = parse_member_names(json).unwrap();
        assert_eq!(names, ["nucleus-envelope", "nucleus-sdk", "portcullis"]);
    }

    #[test]
    fn errors_when_packages_array_missing() {
        assert!(parse_member_names(r#"{"workspace_members": []}"#).is_err());
    }

    #[test]
    fn errors_on_invalid_json() {
        assert!(parse_member_names("not json").is_err());
    }
}
