//! `nucleus observe` — progressive discovery of agent capabilities.
//!
//! Reads a JSONL log of tool calls (from audit log or stdin) and generates
//! a minimal policy profile that permits exactly the observed behavior.
//!
//! With `--grant FILE` the observations are attributed to the effects of a
//! grant instead (ADR 0004, milestone 3): the report says which effects the
//! run used, which it never did, the authority overhead ρ, and what was
//! denied; `--narrow NAME` emits a profile with the unused authority
//! removed, never above the grant, and `--save` installs it under
//! `~/.config/nucleus/profiles/` where `--profile NAME` finds it.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use portcullis::observe::{ObserveSession, format_summary, parse_jsonl_observations};
use portcullis::{TaskGrant, attribute_usage, narrow_grant, render_usage};

use crate::goal::load_catalog;
use crate::grant::read_grant;
use crate::profiles::{PROFILE_NAME_HELP, user_profiles_dir};

/// Observe agent behavior and generate a minimal policy profile.
#[derive(Args)]
pub struct ObserveArgs {
    /// Agent name for the generated profile.
    #[arg(short = 'n', long, default_value = "agent")]
    pub name: String,

    /// Path to JSONL audit log file. Use "-" or omit for stdin.
    /// Accepts both simple format and kernel Decision JSONL from --kernel-trace.
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Output file for generated YAML policy. Omit for stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Show summary report alongside policy.
    #[arg(long, default_value_t = true)]
    pub summary: bool,

    /// Attribute the observations to this grant's effects (a sealed grant
    /// from --save-grant / `nucleus grant seal`, or a plain grant JSON).
    #[arg(long, value_name = "FILE")]
    pub grant: Option<PathBuf>,

    /// With --grant: emit a profile named NAME with the unused authority
    /// removed (never above the grant).
    #[arg(long, value_name = "NAME", requires = "grant")]
    pub narrow: Option<String>,

    /// With --narrow: install the profile under ~/.config/nucleus/profiles/
    /// so `--profile NAME` and `--ceiling NAME` find it.
    #[arg(long, requires = "narrow")]
    pub save: bool,

    /// Repository whose `.nucleus/effects` should extend the catalog
    /// (default: current directory).
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,
}

pub fn execute(args: ObserveArgs) -> Result<()> {
    // Read input
    let input_data = match &args.input {
        Some(path) if path.to_str() != Some("-") => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?,
        _ => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read stdin")?;
            buf
        }
    };

    if input_data.trim().is_empty() {
        eprintln!("No observations to process. Provide JSONL input via --input or stdin.");
        eprintln!();
        eprintln!("Expected format (one JSON object per line):");
        eprintln!(r#"  {{"operation":"read_files","subject":"src/main.rs","succeeded":true}}"#);
        eprintln!(r#"  {{"operation":"web_fetch","subject":"https://docs.rs","succeeded":true}}"#);
        eprintln!(r#"  {{"operation":"git_push","subject":"origin main","succeeded":false}}"#);
        return Ok(());
    }

    // Parse observations
    let observations = parse_jsonl_observations(&input_data);

    if observations.is_empty() {
        eprintln!("No valid observations found in input.");
        return Ok(());
    }

    if let Some(grant_path) = &args.grant {
        return observe_against_grant(&args, grant_path, &observations);
    }

    // Build session
    let mut session = ObserveSession::new(&args.name);
    for obs in observations {
        session.record(obs);
    }

    // Synthesize profile
    let profile = session.synthesize();
    let yaml = profile.to_yaml().context("Failed to serialize profile")?;

    // Print summary to stderr if requested
    if args.summary {
        let summary = session.summary();
        let report = format_summary(&summary);
        eprintln!("{}", report);
    }

    // Output YAML
    match &args.output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            eprintln!("Policy written to {}", path.display());
        }
        None => {
            println!("{}", yaml);
        }
    }

    Ok(())
}

/// The `--grant` path: usage report, optional narrowing, optional install.
fn observe_against_grant(
    args: &ObserveArgs,
    grant_path: &Path,
    observations: &[portcullis::observe::Observation],
) -> Result<()> {
    let grant: TaskGrant = read_grant(grant_path)?;
    let work_dir = PathBuf::from(shellexpand::tilde(&args.dir).to_string());
    let catalog = load_catalog(&work_dir)?;
    let usage = attribute_usage(&grant, &catalog, observations);
    print!("{}", render_usage(&usage, &catalog));

    let Some(name) = &args.narrow else {
        return Ok(());
    };
    if !crate::profiles::is_valid_profile_name(name) {
        bail!("--narrow {name}: {PROFILE_NAME_HELP}");
    }
    let narrowed = narrow_grant(&grant, &usage, name);
    let yaml = narrowed
        .profile
        .to_yaml()
        .context("Failed to serialize the narrowed profile")?;
    eprintln!(
        "narrowed: {} effects and {} dimensions removed; the profile stays within the grant",
        narrowed.dropped_effects.len(),
        narrowed.dropped_operations.len()
    );

    if args.save {
        let path = install_profile(name, &yaml)?;
        eprintln!(
            "profile '{name}' installed at {} (use --profile {name} or --ceiling {name})",
            path.display()
        );
    }
    match &args.output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            eprintln!("Profile written to {}", path.display());
        }
        None if !args.save => println!("{yaml}"),
        None => {}
    }
    Ok(())
}

/// Write `yaml` as `~/.config/nucleus/profiles/<name>.yaml`.
pub fn install_profile(name: &str, yaml: &str) -> Result<PathBuf> {
    let dir = user_profiles_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{name}.yaml"));
    std::fs::write(&path, yaml).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}
