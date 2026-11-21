//! `nucleus-release verify`: check a release record from files.
//!
//! Exit status: 0 if every check was made and held, 1 if any check did not
//! hold, 2 if none failed and at least one could not be made — or the inputs
//! could not be read at all.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use nucleus_release_gate::keys::RoleKey;
use nucleus_release_gate::policy::ReleasePolicy;
use nucleus_release_gate::registry::ReleaseRecord;
use nucleus_release_server::archive::Archive;
use nucleus_release_server::record::{Report, Verdict, verify_record};
use nucleus_release_server::store::CheckpointStore;
use nucleus_weight_patch::CheckpointDigest;

#[derive(Parser)]
#[command(about = "Check a weight-patch release record from files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Replay the release log, each patch and each score.
    Verify {
        /// The digest of the checkpoint the registry was created with.
        #[arg(long)]
        genesis: CheckpointDigest,
        /// The release policy, as JSON.
        #[arg(long)]
        policy: PathBuf,
        /// The registry's public key, in hexadecimal.
        #[arg(long)]
        registry_key: RoleKey,
        /// The release log.
        #[arg(long)]
        releases: PathBuf,
        /// The checkpoint store.
        #[arg(long)]
        store: PathBuf,
        /// The archive of programs and transcripts.
        #[arg(long)]
        archive: PathBuf,
    },
}

fn verify(
    genesis: CheckpointDigest,
    policy: &Path,
    registry_key: RoleKey,
    releases: &Path,
    store: &Path,
    archive: &Path,
) -> anyhow::Result<Report> {
    let policy: ReleasePolicy = serde_json::from_str(
        &fs::read_to_string(policy).with_context(|| format!("reading {}", policy.display()))?,
    )
    .context("parsing the policy")?;
    let log =
        fs::read_to_string(releases).with_context(|| format!("reading {}", releases.display()))?;
    let records = log
        .lines()
        .map(serde_json::from_str::<ReleaseRecord>)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing the release log")?;
    let store = CheckpointStore::open(store).context("opening the checkpoint store")?;
    let archive = Archive::open(archive).context("opening the archive")?;
    Ok(verify_record(
        genesis,
        &policy,
        registry_key,
        &records,
        &store,
        &archive,
    ))
}

fn main() -> ExitCode {
    let Cli { command } = Cli::parse();
    let Command::Verify {
        genesis,
        policy,
        registry_key,
        releases,
        store,
        archive,
    } = command;
    let report = match verify(genesis, &policy, registry_key, &releases, &store, &archive) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("could not look: {e:#}");
            return ExitCode::from(2);
        }
    };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("could not look: {e}");
            return ExitCode::from(2);
        }
    }
    match report.verdict {
        Verdict::Verified => ExitCode::SUCCESS,
        Verdict::Refuted => ExitCode::from(1),
        Verdict::CouldNotLook => ExitCode::from(2),
    }
}
