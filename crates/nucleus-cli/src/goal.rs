//! `nucleus run --goal "…"`: intent → proposed minimum authority → one
//! confirmation → execution.
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
//! default. `--dry-run` prints the grant and stops.

use std::collections::BTreeSet;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use nucleus_task_compiler::{
    CompileInput, EffectProposer, ExternalCommandProposer, LimitOverrides, RuleProposer, compile,
};
use portcullis::{
    Disclosure, EffectCatalog, EffectId, TaskGrant, WeakeningCostConfig, render_grant,
};
use rust_decimal::Decimal;

use crate::config::Config;
use crate::profiles;
use crate::run::{self, RunArgs};

/// Exit status when a confirmation is required but no TTY can give one.
pub const EXIT_NEEDS_CONFIRMATION: i32 = 2;

/// Entry point, reached from `run::execute` when `--goal` is set.
pub async fn execute(args: RunArgs, global_config_path: &str) -> Result<()> {
    let goal = args
        .goal
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .ok_or_else(|| anyhow!("--goal cannot be empty"))?
        .to_string();

    let work_dir = shellexpand::tilde(&args.dir).to_string();
    let work_dir = PathBuf::from(&work_dir)
        .canonicalize()
        .with_context(|| format!("working directory {}", args.dir))?;

    let grant = compile_goal(&args, &goal, &work_dir)?;
    let catalog = load_catalog(&work_dir)?;
    let mut level: Disclosure = args.explain.parse().map_err(|e: String| anyhow!(e))?;

    if let Some(path) = &args.save_grant {
        let json = serde_json::to_string_pretty(&grant)?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("grant written to {}", path.display());
    }

    if args.dry_run {
        print!("{}", render_grant(&grant, &catalog, level));
        return Ok(());
    }

    if args.yes {
        print!("{}", render_grant(&grant, &catalog, level));
    } else {
        if !io::stdin().is_terminal() {
            eprint!("{}", render_grant(&grant, &catalog, level));
            eprintln!();
            eprintln!(
                "nucleus: this grant needs a confirmation and there is no terminal to give one."
            );
            eprintln!("         Re-run with --yes to accept it, or --dry-run to only show it.");
            std::process::exit(EXIT_NEEDS_CONFIRMATION);
        }
        loop {
            print!("{}", render_grant(&grant, &catalog, level));
            print!("\n[R]un · [d]etails · [a]bort: ");
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            match line.trim().to_ascii_lowercase().as_str() {
                "r" | "run" | "y" | "yes" => break,
                "d" | "details" => {
                    level = match level {
                        Disclosure::Plain => Disclosure::Technical,
                        Disclosure::Technical => Disclosure::PolicyTrace,
                        Disclosure::PolicyTrace => Disclosure::Plain,
                    };
                    println!();
                }
                _ => bail!("aborted: the grant was not accepted"),
            }
        }
    }

    // Everything from here is the ordinary run path with the compiled
    // lattice in place of a profile: same modes, same enforcement.
    let global_config = Config::load(global_config_path)?;
    let resolved = run::resolve_config(&args, &global_config)?;
    run::dispatch(&args, resolved, &grant.lattice, &work_dir, &goal).await
}

fn load_catalog(work_dir: &std::path::Path) -> Result<EffectCatalog> {
    let mut catalog = EffectCatalog::builtin()?;
    catalog.load_from_dir(&work_dir.join(".nucleus/effects"))?;
    Ok(catalog)
}

/// Compile the goal under the ceiling named by the args.
fn compile_goal(args: &RunArgs, goal: &str, work_dir: &std::path::Path) -> Result<TaskGrant> {
    let ctx = nucleus_task_compiler::probe(work_dir)
        .with_context(|| format!("probing {}", work_dir.display()))?;
    let catalog = load_catalog(work_dir)?;

    let ceiling = profiles::resolve(&args.ceiling).ok_or_else(|| {
        anyhow!(
            "unknown ceiling profile '{}' (see `nucleus profiles`)",
            args.ceiling
        )
    })?;

    let mut explicit = BTreeSet::new();
    for raw in &args.effects {
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
    let external = args
        .proposer
        .clone()
        .map(|program| ExternalCommandProposer { program });
    let mut proposers: Vec<&dyn EffectProposer> = vec![&rules];
    if let Some(ext) = &external {
        proposers.push(ext);
    }

    let limits = LimitOverrides {
        max_cost_usd: args
            .max_cost
            .map(|c| Decimal::try_from(c).map_err(|e| anyhow!("--max-cost: {e}")))
            .transpose()?,
        duration_hours: None,
    };

    let grant = compile(CompileInput {
        goal,
        ctx: &ctx,
        catalog: &catalog,
        ceiling_profile: &args.ceiling,
        ceiling: &ceiling,
        proposers: &proposers,
        explicit: &explicit,
        limits,
        cost_config: &WeakeningCostConfig::default(),
    })?;
    Ok(grant)
}
