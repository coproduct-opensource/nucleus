use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use trust_atlas::model::Fixtures;
use trust_atlas::report;

#[derive(Parser)]
#[command(
    name = "trust-atlas",
    about = "egglog trust/maturity atlas over the nucleus + nucleus-platform verification surface (SPIKE)"
)]
struct Cli {
    /// Directory holding the recon fixtures (gates/verification/equivalences/trust_path).
    #[arg(long, default_value_os_t = Fixtures::default_dir())]
    fixtures: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// End-to-end chain for the receipt claim with per-edge maturity,
    /// provenance, the MIN, and path discontinuities.
    WeakestLink,
    /// Unenforced gates (workflow exists, not required) + sorry findings +
    /// live kani harness facts.
    Findings {
        /// Repo checkout to grep live for #[kani::proof] harnesses.
        #[arg(long, default_value_os_t = default_repo())]
        repo: PathBuf,
        /// Skip the live `gh api` gate extractor (fixture only).
        #[arg(long)]
        no_live: bool,
    },
}

fn default_repo() -> PathBuf {
    // tools/trust-atlas -> repo root of this checkout.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let fixtures = Fixtures::load(&cli.fixtures)?;
    let text = match cli.command {
        Cmd::WeakestLink => report::weakest_link(&fixtures)?,
        Cmd::Findings { repo, no_live } => report::findings(&fixtures, &repo, !no_live)?,
    };
    print!("{text}");
    Ok(())
}
