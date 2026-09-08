//! `nucleus run --goal "…"`: intent → proposed minimum authority → one
//! confirmation → execution. And `nucleus run --grant FILE`: a previously
//! sealed grant → verification → execution with no confirmation at all.
//!
//! The person states the outcome. The compiler (`nucleus-task-compiler`)
//! derives the semantic effects the goal needs from the repository it is
//! stated in, lowers them to a permission lattice, meets that with the
//! `--ceiling` profile so the grant can never be wider than the ceiling, and
//! renders the result as five lines a person can approve:
//!
//! ```text
//! Goal:    fix the failing CI build
//! Can:     read CI logs and workflow runs · read and search workspace files · …
//! Cannot:  open a pull request (outside ceiling safe-pr-fixer) · push to remote branches · …
//! Limits:  $5.00 · 2h · api.github.com only · no .aws, .env, .ssh
//! Risk:    2 of 3 exposure legs (private data + untrusted content); exfiltration absent → …
//! ```
//!
//! One decision, then the existing run path executes under the compiled
//! lattice. Without a TTY the command refuses to run unless `--yes` names
//! the decision explicitly: an unattended run must not acquire authority by
//! default. `--dry-run` prints the grant and stops. `--save-grant PATH`
//! seals the accepted grant (signed with the host's grant key) so the same
//! task can be run again with `--grant PATH` and zero prompts (ADR 0004,
//! `C(T) = 0`).

use std::collections::BTreeSet;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use nucleus_task_compiler::{
    CompileInput, EffectProposer, ExternalCommandProposer, LimitOverrides, RuleProposer, compile,
};
use portcullis::{
    Disclosure, EffectCatalog, EffectId, SealedTaskGrant, TaskGrant, WeakeningCostConfig,
    render_grant,
};
use rust_decimal::Decimal;

use crate::config::Config;
use crate::grant::{
    load_or_create_grant_key, read_sealed, verified_line, verify_sealed, write_sealed,
};
use crate::profiles;
use crate::run::{self, RunArgs};

/// Exit status when a confirmation is required but no TTY can give one.
pub const EXIT_NEEDS_CONFIRMATION: i32 = 2;

/// What the compiler is asked for, independent of which command asks.
pub struct GoalRequest {
    /// The outcome, as stated.
    pub goal: String,
    /// The ceiling profile.
    pub ceiling: String,
    /// Effects to grant in addition to what the goal implies.
    pub effects: Vec<String>,
    /// An external proposer program.
    pub proposer: Option<PathBuf>,
    /// Spend ceiling override (only tightens).
    pub max_cost: Option<f64>,
}

impl GoalRequest {
    fn from_run(args: &RunArgs, goal: String) -> Self {
        Self {
            goal,
            ceiling: args.ceiling.clone(),
            effects: args.effects.clone(),
            proposer: args.proposer.clone(),
            max_cost: args.max_cost,
        }
    }
}

/// The outcome of the one confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Run (or seal) as shown.
    Accept,
    /// Seal without running (only offered when a save path is set).
    SaveOnly,
    /// Nothing happens.
    Abort,
}

/// Entry point, reached from `run::execute` when `--goal` is set.
pub async fn execute(args: RunArgs, global_config_path: &str) -> Result<()> {
    let goal = args
        .goal
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .ok_or_else(|| anyhow!("--goal cannot be empty"))?
        .to_string();

    let work_dir = canonical_work_dir(&args.dir)?;
    let request = GoalRequest::from_run(&args, goal.clone());
    let grant = compile_goal(&request, &work_dir)?;
    let catalog = load_catalog(&work_dir)?;
    let level: Disclosure = args.explain.parse().map_err(|e: String| anyhow!(e))?;

    if args.dry_run {
        if args.save_grant.is_some() {
            bail!("--save-grant seals an ACCEPTED grant; drop --dry-run (or pass --yes)");
        }
        print!("{}", render_grant(&grant, &catalog, level));
        return Ok(());
    }

    let decision = if args.save_grant.is_some() {
        confirm(&grant, &catalog, level, args.yes, "[R]un · [s]eal only")?
    } else {
        confirm(&grant, &catalog, level, args.yes, "[R]un")?
    };
    match decision {
        Decision::Abort => bail!("aborted: the grant was not accepted"),
        Decision::Accept | Decision::SaveOnly => {}
    }

    // The acceptance is the approval: seal it if asked, before anything runs.
    if let Some(path) = &args.save_grant {
        let key = load_or_create_grant_key(args.grant_key.as_deref())?;
        let sealed = SealedTaskGrant::seal(grant.clone(), crate::grant::approver_identity(), &key);
        write_sealed(&sealed, path)?;
        if decision == Decision::SaveOnly {
            return Ok(());
        }
    }

    run_under(&args, global_config_path, &grant.lattice, &work_dir, &goal).await
}

/// Entry point, reached from `run::execute` when `--grant` is set: verify
/// the sealed grant against this host's trusted signers and this
/// repository, then run with no confirmation.
pub async fn execute_grant(args: RunArgs, global_config_path: &str) -> Result<()> {
    let path = args
        .grant
        .as_ref()
        .ok_or_else(|| anyhow!("--grant needs a path"))?;
    if args.prompt.as_deref().is_some_and(|p| !p.is_empty()) {
        bail!("--grant carries its own goal; a prompt cannot be combined with it");
    }
    let work_dir = canonical_work_dir(&args.dir)?;
    let sealed = read_sealed(path)?;
    let ctx = nucleus_task_compiler::probe(&work_dir)
        .with_context(|| format!("probing {}", work_dir.display()))?;
    let verified = verify_sealed(
        &sealed,
        args.grant_key.as_deref(),
        &args.grant_signers,
        Some(&ctx.digest),
    )?;
    let grant = verified.grant();
    let catalog = load_catalog(&work_dir)?;
    let level: Disclosure = args.explain.parse().map_err(|e: String| anyhow!(e))?;

    println!("{}", verified_line(&verified));
    print!("{}", render_grant(grant, &catalog, level));
    if args.dry_run {
        return Ok(());
    }
    let goal = grant.goal.clone();
    run_under(&args, global_config_path, &grant.lattice, &work_dir, &goal).await
}

/// Everything from here is the ordinary run path with a compiled lattice in
/// place of a profile: same modes, same enforcement.
async fn run_under(
    args: &RunArgs,
    global_config_path: &str,
    lattice: &portcullis::PermissionLattice,
    work_dir: &Path,
    goal: &str,
) -> Result<()> {
    let global_config = Config::load(global_config_path)?;
    let resolved = run::resolve_config(args, &global_config)?;
    run::dispatch(args, resolved, lattice, work_dir, goal).await
}

fn canonical_work_dir(dir: &str) -> Result<PathBuf> {
    let expanded = shellexpand::tilde(dir).to_string();
    PathBuf::from(&expanded)
        .canonicalize()
        .with_context(|| format!("working directory {dir}"))
}

/// Show the grant and take the one decision. `accept_label` names the
/// accepting choice(s), e.g. `[R]un` or `[S]eal`; `[d]etails` cycles the
/// disclosure and `[a]bort` is always offered. With `yes` the grant is
/// printed and accepted. Without a TTY and without `yes` the process exits
/// with [`EXIT_NEEDS_CONFIRMATION`] after printing the grant to stderr.
pub fn confirm(
    grant: &TaskGrant,
    catalog: &EffectCatalog,
    mut level: Disclosure,
    yes: bool,
    accept_label: &str,
) -> Result<Decision> {
    if yes {
        print!("{}", render_grant(grant, catalog, level));
        return Ok(Decision::Accept);
    }
    if !io::stdin().is_terminal() {
        eprint!("{}", render_grant(grant, catalog, level));
        eprintln!();
        eprintln!("nucleus: this grant needs a confirmation and there is no terminal to give one.");
        eprintln!("         Re-run with --yes to accept it, or --dry-run to only show it.");
        std::process::exit(EXIT_NEEDS_CONFIRMATION);
    }
    let offers_save = accept_label.contains("[s]");
    loop {
        print!("{}", render_grant(grant, catalog, level));
        print!("\n{accept_label} · [d]etails · [a]bort: ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        match line.trim().to_ascii_lowercase().as_str() {
            "r" | "run" | "y" | "yes" => return Ok(Decision::Accept),
            "s" | "seal" | "save" if offers_save => return Ok(Decision::SaveOnly),
            "s" | "seal" if accept_label.starts_with("[S]") => return Ok(Decision::Accept),
            "d" | "details" => {
                level = match level {
                    Disclosure::Plain => Disclosure::Technical,
                    Disclosure::Technical => Disclosure::PolicyTrace,
                    Disclosure::PolicyTrace => Disclosure::Plain,
                };
                println!();
            }
            _ => return Ok(Decision::Abort),
        }
    }
}

/// The catalog a repository sees: the built-in effects plus its own under
/// `.nucleus/effects`.
pub fn load_catalog(work_dir: &Path) -> Result<EffectCatalog> {
    let mut catalog = EffectCatalog::builtin()?;
    catalog.load_from_dir(&work_dir.join(".nucleus/effects"))?;
    Ok(catalog)
}

/// Compile the goal under the ceiling named by the request.
pub fn compile_goal(request: &GoalRequest, work_dir: &Path) -> Result<TaskGrant> {
    let ctx = nucleus_task_compiler::probe(work_dir)
        .with_context(|| format!("probing {}", work_dir.display()))?;
    let catalog = load_catalog(work_dir)?;

    let ceiling = profiles::resolve(&request.ceiling).ok_or_else(|| {
        anyhow!(
            "unknown ceiling profile '{}' (see `nucleus profiles`)",
            request.ceiling
        )
    })?;

    let mut explicit = BTreeSet::new();
    for raw in &request.effects {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let id: EffectId = raw.parse().map_err(|e| anyhow!("--effects: {e}"))?;
        if catalog.get(&id).is_none() {
            bail!("--effects: unknown effect '{id}'");
        }
        explicit.insert(id);
    }

    let rules = RuleProposer;
    let external = request
        .proposer
        .clone()
        .map(|program| ExternalCommandProposer { program });
    let mut proposers: Vec<&dyn EffectProposer> = vec![&rules];
    if let Some(ext) = &external {
        proposers.push(ext);
    }

    let limits = LimitOverrides {
        max_cost_usd: request
            .max_cost
            .map(|c| Decimal::try_from(c).map_err(|e| anyhow!("--max-cost: {e}")))
            .transpose()?,
        duration_hours: None,
    };

    let grant = compile(CompileInput {
        goal: &request.goal,
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile: &request.ceiling,
        ceiling: &ceiling,
        proposers: &proposers,
        explicit: &explicit,
        limits,
        cost_config: &WeakeningCostConfig::default(),
    })?;
    Ok(grant)
}
