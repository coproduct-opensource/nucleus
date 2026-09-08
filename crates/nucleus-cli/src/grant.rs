//! `nucleus grant`: seal a compiled goal into a signed grant, and show one.
//!
//! Sealing is the approval. `nucleus grant seal --goal "…" -o FILE` compiles
//! the goal exactly as `nucleus run --goal` does, shows the five lines, and on
//! confirmation signs them with the host's grant key into a
//! [`SealedTaskGrant`]. `nucleus run --grant FILE` then runs it without
//! asking (ADR 0004, milestone 2: `C(T) = 0` for a previously approved
//! task), refusing if the file was edited, the signer is not trusted, the
//! grant expired, or the repository changed since it was approved.
//!
//! The grant key is an Ed25519 keypair the CLI creates on first use at
//! `~/.config/nucleus/keys/grant-signer.pem` (owner-read-only). Pass
//! `--grant-key` or set `NUCLEUS_GRANT_KEY` to use another, which is how a
//! CI job verifies a grant a person sealed on their machine: the job holds
//! only the public half, given as `--grant-signer HEX`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use clap::{Args, Subcommand};
use portcullis::{
    Disclosure, EffectCatalog, EscalationProposal, SealedTaskGrant, TaskGrant, VerifiedGrant,
    render_grant, render_proposal,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::config::nucleus_dir;
use crate::goal::{Decision, GoalRequest, compile_goal, confirm, load_catalog};
use crate::token::{pem_to_pkcs8, write_key_pem};

/// Seal a goal into a signed grant, or show one.
#[derive(Args)]
pub struct GrantArgs {
    #[command(subcommand)]
    pub command: GrantCommand,
}

#[derive(Subcommand)]
pub enum GrantCommand {
    /// Compile a goal, confirm it once, and sign it into a reusable grant.
    Seal(SealArgs),
    /// Verify a sealed grant and show what it allows.
    Show(ShowArgs),
    /// Turn every denial in a run's trace into an escalation proposal: what
    /// was attempted, why it was refused, the least authority that would
    /// allow it, the risk delta, and the one command that grants it.
    Propose(ProposeArgs),
    /// Re-seal a grant with effects added (or a raised budget), under the
    /// same ceiling, after the same single confirmation.
    Widen(WidenArgs),
}

#[derive(Args)]
pub struct ProposeArgs {
    /// The grant the run executed under (sealed or plain JSON).
    #[arg(long, value_name = "FILE")]
    pub grant: PathBuf,

    /// The run's kernel trace (JSONL of decisions).
    #[arg(short, long, value_name = "FILE")]
    pub input: PathBuf,

    /// Repository whose `.nucleus/effects` extend the catalog.
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Emit the proposals as JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct WidenArgs {
    /// The grant to widen (sealed or plain JSON).
    #[arg(long, value_name = "FILE")]
    pub grant: PathBuf,

    /// Effects to add (comma-separated ids such as git/commit).
    #[arg(long, value_delimiter = ',')]
    pub effects: Vec<String>,

    /// A raised spend ceiling in USD (never above the ceiling profile's).
    #[arg(long)]
    pub max_cost: Option<f64>,

    /// Accept without prompting (required without a TTY).
    #[arg(long)]
    pub yes: bool,

    /// How much of the grant to show: plain | technical | policy-trace.
    #[arg(long, default_value = "plain")]
    pub explain: String,

    /// Repository the grant is for (default: current directory).
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Where to write the re-sealed grant (default: overwrite --grant).
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Ed25519 key (PKCS#8 PEM) to sign with; created if missing.
    #[arg(long, env = "NUCLEUS_GRANT_KEY", value_name = "PATH")]
    pub grant_key: Option<PathBuf>,

    /// Identity recorded as the approver.
    #[arg(long, value_name = "IDENTITY")]
    pub approver: Option<String>,
}

#[derive(Args)]
pub struct SealArgs {
    /// The outcome you want.
    #[arg(long)]
    pub goal: String,

    /// The profile the grant may never exceed.
    #[arg(long, default_value = "codegen")]
    pub ceiling: String,

    /// Effects to grant in addition to what the goal implies (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub effects: Vec<String>,

    /// An external effect proposer (see `nucleus run --help`).
    #[arg(long, value_name = "PROGRAM")]
    pub proposer: Option<PathBuf>,

    /// Spend ceiling in USD (only ever tightens the ceiling's).
    #[arg(long)]
    pub max_cost: Option<f64>,

    /// Accept the grant without prompting (required without a TTY).
    #[arg(long)]
    pub yes: bool,

    /// How much of the grant to show: plain | technical | policy-trace.
    #[arg(long, default_value = "plain")]
    pub explain: String,

    /// Repository the grant is for (default: current directory).
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Where to write the sealed grant (JSON).
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: PathBuf,

    /// Ed25519 key (PKCS#8 PEM) to sign with; created if missing.
    #[arg(long, env = "NUCLEUS_GRANT_KEY", value_name = "PATH")]
    pub grant_key: Option<PathBuf>,

    /// Identity recorded as the approver.
    #[arg(long, value_name = "IDENTITY")]
    pub approver: Option<String>,
}

#[derive(Args)]
pub struct ShowArgs {
    /// The sealed grant.
    pub grant: PathBuf,

    /// How much to show: plain | technical | policy-trace.
    #[arg(long, default_value = "plain")]
    pub explain: String,

    /// Repository to check the grant against (default: current directory;
    /// `-` to skip the repository check).
    #[arg(short = 'd', long, default_value = ".")]
    pub dir: String,

    /// Ed25519 key (PKCS#8 PEM) whose public half is trusted as a signer.
    #[arg(long, env = "NUCLEUS_GRANT_KEY", value_name = "PATH")]
    pub grant_key: Option<PathBuf>,

    /// Additional trusted signer public keys (hex, 32 bytes). Repeatable.
    #[arg(long = "grant-signer", value_name = "HEX")]
    pub grant_signers: Vec<String>,
}

pub fn execute(args: GrantArgs) -> Result<()> {
    match args.command {
        GrantCommand::Seal(a) => seal(a),
        GrantCommand::Show(a) => show(a),
        GrantCommand::Propose(a) => propose(a),
        GrantCommand::Widen(a) => widen(a),
    }
}

// ── propose / widen ───────────────────────────────────────────────────────

/// The proposals for every distinct denial in `trace_text`, under `grant`.
pub fn proposals_for(
    grant: &TaskGrant,
    catalog: &EffectCatalog,
    trace_text: &str,
) -> Result<Vec<EscalationProposal>> {
    let denials = portcullis::denials_in_trace(trace_text);
    if denials.is_empty() {
        return Ok(Vec::new());
    }
    let ceiling = crate::profiles::resolve(&grant.ceiling_profile).ok_or_else(|| {
        anyhow!(
            "the grant's ceiling profile '{}' is not known on this host",
            grant.ceiling_profile
        )
    })?;
    let cost = portcullis::WeakeningCostConfig::default();
    Ok(denials
        .iter()
        .map(|d| {
            portcullis::propose_escalation(
                grant,
                &ceiling,
                catalog,
                &cost,
                d.operation,
                &d.subject,
                &d.reason,
            )
        })
        .collect())
}

fn propose(args: ProposeArgs) -> Result<()> {
    let grant = read_grant(&args.grant)?;
    let work_dir = PathBuf::from(shellexpand::tilde(&args.dir).to_string());
    let catalog = load_catalog(&work_dir)?;
    let text = std::fs::read_to_string(&args.input)
        .with_context(|| format!("reading the trace at {}", args.input.display()))?;
    let proposals = proposals_for(&grant, &catalog, &text)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&proposals)?);
        return Ok(());
    }
    if proposals.is_empty() {
        println!("no denials in {}", args.input.display());
        return Ok(());
    }
    let grant_ref = args.grant.display().to_string();
    for (i, p) in proposals.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print!("{}", render_proposal(p, &catalog, &grant_ref));
    }
    Ok(())
}

fn widen(args: WidenArgs) -> Result<()> {
    let grant = read_grant(&args.grant)?;
    let work_dir = shellexpand::tilde(&args.dir).to_string();
    let work_dir = PathBuf::from(&work_dir)
        .canonicalize()
        .with_context(|| format!("working directory {}", args.dir))?;
    let mut effects: Vec<String> = grant.can.iter().map(|e| e.to_string()).collect();
    for e in &args.effects {
        let e = e.trim();
        if !e.is_empty() && !effects.iter().any(|x| x == e) {
            effects.push(e.to_string());
        }
    }
    if args.effects.iter().all(|e| e.trim().is_empty()) && args.max_cost.is_none() {
        bail!("nothing to widen: pass --effects and/or --max-cost");
    }
    let request = GoalRequest {
        goal: grant.goal.clone(),
        ceiling: grant.ceiling_profile.clone(),
        effects,
        proposer: None,
        max_cost: args.max_cost,
    };
    let widened = compile_goal(&request, &work_dir)?;
    let catalog = load_catalog(&work_dir)?;
    let level: Disclosure = args.explain.parse().map_err(|e: String| anyhow!(e))?;
    let added: Vec<String> = widened
        .can
        .difference(&grant.can)
        .map(|e| e.to_string())
        .collect();
    let still_clipped: Vec<String> = args
        .effects
        .iter()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty() && !widened.can.iter().any(|c| c.to_string() == *e))
        .collect();
    if !still_clipped.is_empty() {
        eprintln!(
            "note: {} stay outside ceiling {} (a wider ceiling is a separate decision)",
            still_clipped.join(", "),
            grant.ceiling_profile
        );
    }
    eprintln!(
        "widening grant {}: adds {}",
        grant.id,
        if added.is_empty() {
            "no effects".to_string()
        } else {
            added.join(", ")
        }
    );
    match confirm(&widened, &catalog, level, args.yes, "[S]eal")? {
        Decision::Accept | Decision::SaveOnly => {}
        Decision::Abort => bail!("aborted: the widened grant was not sealed"),
    }
    let key = load_or_create_grant_key(args.grant_key.as_deref())?;
    let approver = args.approver.clone().unwrap_or_else(approver_identity);
    let sealed = SealedTaskGrant::seal(widened, approver, &key);
    let out = args.output.clone().unwrap_or_else(|| args.grant.clone());
    write_sealed(&sealed, &out)?;
    Ok(())
}

// ── keys ──────────────────────────────────────────────────────────────────

/// Where the host's grant key lives unless overridden.
pub fn default_grant_key_path() -> Result<PathBuf> {
    Ok(nucleus_dir()?.join("keys").join("grant-signer.pem"))
}

/// Load the grant key at `path` (default location when `None`), creating it
/// on first use. The file is owner-read-only.
pub fn load_or_create_grant_key(path: Option<&Path>) -> Result<Ed25519KeyPair> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_grant_key_path()?,
    };
    if path.exists() {
        return load_grant_key(&path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| anyhow!("generating the grant key: {e}"))?;
    write_key_pem(&path, pkcs8.as_ref())?;
    eprintln!("grant key created at {}", path.display());
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|e| anyhow!("parsing the grant key: {e}"))
}

/// Load an existing grant key.
pub fn load_grant_key(path: &Path) -> Result<Ed25519KeyPair> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("reading the grant key at {}", path.display()))?;
    let der = pem_to_pkcs8(&pem)?;
    Ed25519KeyPair::from_pkcs8(&der)
        .map_err(|e| anyhow!("parsing the grant key at {}: {e}", path.display()))
}

/// The signers a verification trusts: the local grant key's public half (if
/// the key exists or `key_path` names one) plus every `--grant-signer`.
pub fn trusted_signers(key_path: Option<&Path>, extra_hex: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let path = match key_path {
        Some(p) => p.to_path_buf(),
        None => default_grant_key_path()?,
    };
    if path.exists() {
        out.push(load_grant_key(&path)?.public_key().as_ref().to_vec());
    }
    for hex_key in extra_hex {
        let bytes = hex::decode(hex_key.trim())
            .with_context(|| format!("--grant-signer {hex_key}: not hex"))?;
        if bytes.len() != 32 {
            bail!(
                "--grant-signer {hex_key}: an Ed25519 public key is 32 bytes, got {}",
                bytes.len()
            );
        }
        out.push(bytes);
    }
    if out.is_empty() {
        bail!(
            "no trusted signer: no grant key at {} and no --grant-signer given",
            path.display()
        );
    }
    Ok(out)
}

/// The identity a grant is sealed as unless `--approver` says otherwise.
pub fn approver_identity() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into());
    format!("nucleus://grant-approver/{host}/{user}")
}

// ── seal ──────────────────────────────────────────────────────────────────

fn seal(args: SealArgs) -> Result<()> {
    let work_dir = shellexpand::tilde(&args.dir).to_string();
    let work_dir = PathBuf::from(&work_dir)
        .canonicalize()
        .with_context(|| format!("working directory {}", args.dir))?;
    let request = GoalRequest {
        goal: args.goal.trim().to_string(),
        ceiling: args.ceiling.clone(),
        effects: args.effects.clone(),
        proposer: args.proposer.clone(),
        max_cost: args.max_cost,
    };
    if request.goal.is_empty() {
        bail!("--goal cannot be empty");
    }
    let grant = compile_goal(&request, &work_dir)?;
    let catalog = load_catalog(&work_dir)?;
    let level: Disclosure = args.explain.parse().map_err(|e: String| anyhow!(e))?;

    match confirm(&grant, &catalog, level, args.yes, "[S]eal")? {
        Decision::Accept | Decision::SaveOnly => {}
        Decision::Abort => bail!("aborted: the grant was not sealed"),
    }

    let key = load_or_create_grant_key(args.grant_key.as_deref())?;
    let approver = args.approver.clone().unwrap_or_else(approver_identity);
    let sealed = SealedTaskGrant::seal(grant, approver, &key);
    write_sealed(&sealed, &args.output)?;
    Ok(())
}

/// Write a sealed grant as JSON and say what was written.
pub fn write_sealed(sealed: &SealedTaskGrant, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(sealed)?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    eprintln!(
        "sealed grant {} written to {} (cert {}, {} effects, expires {})",
        sealed.grant.id,
        path.display(),
        &sealed.fingerprint_hex()[..16],
        sealed.grant.can.len(),
        sealed.grant.not_after.format("%Y-%m-%d %H:%M UTC")
    );
    Ok(())
}

// ── show / verify ─────────────────────────────────────────────────────────

/// Read a grant from disk for attribution: a sealed grant (its readable
/// half) or a plain grant JSON. No verification: usage attribution reads
/// what was granted, it grants nothing.
pub fn read_grant(path: &Path) -> Result<TaskGrant> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the grant at {}", path.display()))?;
    if let Ok(sealed) = serde_json::from_str::<SealedTaskGrant>(&text) {
        return Ok(sealed.grant);
    }
    serde_json::from_str::<TaskGrant>(&text)
        .with_context(|| format!("{} is neither a sealed nor a plain grant", path.display()))
}

/// Read a sealed grant from disk.
pub fn read_sealed(path: &Path) -> Result<SealedTaskGrant> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading the grant at {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("{} is not a sealed grant", path.display()))
}

/// Verify `sealed` against the trusted signers and, unless `repo_digest` is
/// `None`, the repository it is about to run in.
pub fn verify_sealed(
    sealed: &SealedTaskGrant,
    key_path: Option<&Path>,
    extra_signers: &[String],
    repo_digest: Option<&str>,
) -> Result<VerifiedGrant> {
    let trusted = trusted_signers(key_path, extra_signers)?;
    sealed
        .verify(Utc::now(), &trusted, repo_digest)
        .map_err(|e| anyhow!("grant {} refused: {e}", sealed.grant.id))
}

/// The one line printed before a verified grant runs.
pub fn verified_line(v: &VerifiedGrant) -> String {
    let g = v.grant();
    let remaining = g.not_after - Utc::now();
    let mins = remaining.num_minutes().max(0);
    format!(
        "grant {} verified: sealed by {} (cert {}…), {} effects, {} left, no confirmation needed",
        g.id,
        v.approver(),
        &v.fingerprint_hex()[..16],
        g.can.len(),
        if mins >= 60 {
            format!("{}h{:02}m", mins / 60, mins % 60)
        } else {
            format!("{mins}m")
        }
    )
}

fn show(args: ShowArgs) -> Result<()> {
    let sealed = read_sealed(&args.grant)?;
    let level: Disclosure = args.explain.parse().map_err(|e: String| anyhow!(e))?;
    let repo_digest = if args.dir == "-" {
        None
    } else {
        let work_dir = shellexpand::tilde(&args.dir).to_string();
        let work_dir = PathBuf::from(&work_dir)
            .canonicalize()
            .with_context(|| format!("working directory {}", args.dir))?;
        Some(nucleus_task_compiler::probe(&work_dir)?.digest)
    };
    let catalog = match repo_digest {
        Some(_) => {
            let work_dir = PathBuf::from(shellexpand::tilde(&args.dir).to_string());
            load_catalog(&work_dir)?
        }
        None => EffectCatalog::builtin()?,
    };
    let verified = verify_sealed(
        &sealed,
        args.grant_key.as_deref(),
        &args.grant_signers,
        repo_digest.as_deref(),
    )?;
    println!("{}", verified_line(&verified));
    print!("{}", render_grant(verified.grant(), &catalog, level));
    Ok(())
}
