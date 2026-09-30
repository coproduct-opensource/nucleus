//! `nucleus-hostctl`: the host side of running nucleus microVMs.
//!
//! - `probe` prints a JSON report of what this host provides and exits non-zero
//!   when a microVM cannot launch here.
//! - `seed <tree> <image> --owner UID:GID [--free-mib N]` builds a workspace
//!   scratch image, every entry owned by the workload, and prints its
//!   `sha-256:` digest.
//! - `harvest <image> <out>` replays the image's journal and copies its tree out.

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

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nucleus_microvm_host::ext4::RootOwner;
#[cfg(target_os = "linux")]
use nucleus_microvm_host::probe::HostRequirement;
use nucleus_microvm_host::probe::{self, kvm::Kvm};
use nucleus_microvm_host::workspace;
#[cfg(target_os = "linux")]
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "nucleus-hostctl",
    about = "Host side of running nucleus microVMs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Report what this host provides; non-zero exit when a microVM cannot launch.
    Probe {
        /// Also require what a pod with a `network` block needs (CAP_NET_ADMIN).
        #[arg(long)]
        network: bool,
    },
    /// Build an ext4 workspace image from a directory and print its digest.
    Seed {
        tree: PathBuf,
        image: PathBuf,
        /// The workload's `uid:gid`; every seeded entry is owned by it. No
        /// default: the node decides the workload uid, and a second copy of
        /// that number here would drift from it.
        #[arg(long, value_parser = parse_owner)]
        owner: RootOwner,
        /// Free space beyond the tree's own size, in MiB.
        #[arg(long, default_value_t = 1024)]
        free_mib: u32,
    },
    /// Replay an image's journal and copy its tree into an empty directory.
    Harvest { image: PathBuf, out: PathBuf },
}

/// One unmet requirement, as printed.
#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct Unmet {
    what: &'static str,
    because: &'static str,
    remedy: &'static str,
}

#[cfg(target_os = "linux")]
impl From<&HostRequirement> for Unmet {
    fn from(r: &HostRequirement) -> Self {
        Unmet {
            what: r.what,
            because: r.because,
            remedy: r.remedy,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct Report {
    kvm: Kvm,
    /// What a launch needs and this host lacks. Non-empty means refuse.
    launch_unmet: Vec<Unmet>,
    /// Hardening for cross-pod sharing that this host lacks. Informational.
    sharing_unmet: Vec<Unmet>,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Probe { network } => run_probe(network),
        Command::Seed {
            tree,
            image,
            owner,
            free_mib,
        } => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return fail(&format!("starting a runtime: {e}")),
            };
            match rt.block_on(workspace::seed(&tree, &image, owner, free_mib)) {
                Ok(digest) => {
                    println!("{}", digest.as_str());
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        Command::Harvest { image, out } => match workspace::harvest(&image, &out) {
            Ok(()) => {
                eprintln!("harvested {}", out.display());
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e.to_string()),
        },
    }
}

#[cfg(target_os = "linux")]
fn run_probe(network: bool) -> ExitCode {
    let unmet = |reqs: &[HostRequirement]| -> Vec<Unmet> {
        probe::unmet(reqs, probe::observe)
            .iter()
            .map(Unmet::from)
            .collect()
    };
    let report = Report {
        kvm: probe::kvm::probe(),
        launch_unmet: unmet(&probe::requirements(network)),
        sharing_unmet: unmet(&probe::sharing_requirements()),
    };
    let ready = report.kvm.is_usable() && report.launch_unmet.is_empty();
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => return fail(&format!("serialising the report: {e}")),
    }
    if ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The requirements are observed on Linux only. Reporting them as met or unmet
/// here would be a guess, so the probe refuses to answer rather than print one.
#[cfg(not(target_os = "linux"))]
fn run_probe(_network: bool) -> ExitCode {
    fail(&format!(
        "probe observes a Linux host; this is {} ({})",
        std::env::consts::OS,
        match probe::kvm::probe() {
            Kvm::Unusable { reason } => reason,
            other => format!("{other:?}"),
        }
    ))
}

/// `uid:gid`, both decimal.
fn parse_owner(s: &str) -> Result<RootOwner, String> {
    let (uid, gid) = s
        .split_once(':')
        .ok_or_else(|| format!("{s:?} is not uid:gid"))?;
    let num = |n: &str| {
        n.parse::<u32>()
            .map_err(|e| format!("{n:?} in {s:?} is not a uid/gid: {e}"))
    };
    Ok(RootOwner {
        uid: num(uid)?,
        gid: num(gid)?,
    })
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("nucleus-hostctl: {msg}");
    ExitCode::FAILURE
}
