//! `ci-fly-runner`: the manager for a warm, bounded pool of CI worker machines.
//!
//! Runs as one small machine with no public service. It holds the administrative credentials —
//! a forge token that can register runners, a substrate token for the worker app — and the
//! workers hold none: each receives exactly one job's runner registration and nothing else.
//!
//! Configuration (environment):
//!   GITHUB_TOKEN, FLY_API_TOKEN   the administrative credentials (secrets)
//!   RUNNER_IMAGE                  the worker image, pinned by digest
//!   GITHUB_REPO                   owner/name
//!   RUNNER_APP                    the app the workers live in
//!   POOLS                         JSON: [{label, guest, size, standby, volumes?, env?}]
//!   POLL_SECONDS                  pass period (default 20)
//!   IDLE_MINUTES                  how long a stopped machine above `standby` lives (default 30)
//!   LOOKBACK_RUNS                 how many recent runs to scan for queued jobs (default 30)
//!   FLY_REGION                    where machines are created (default iad)
//!
//! `--once` runs a single pass and exits: what the smoke workflow and a person debugging use.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use ci_fly_runner::api::{ForgeApi, MachinesApi, Ureq};
use ci_fly_runner::parse_pools;
use ci_fly_runner::reconcile::Manager;

const FORGE_API: &str = "https://api.github.com";
const MACHINES_API: &str = "https://api.machines.dev/v1";

fn var(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} is required"))
}

fn number(key: &str, default: u64) -> Result<u64, String> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .parse()
            .map_err(|_| format!("{key} must be a number, not {raw:?}")),
    }
}

fn run() -> Result<(), String> {
    let image = var("RUNNER_IMAGE")?;
    if !image.contains("@sha256:") {
        // A tag can be moved under a running pool: the machine that starts tomorrow would not be
        // the image whose timings were measured today.
        return Err("RUNNER_IMAGE must be pinned by digest".into());
    }
    let pools = parse_pools(&var("POOLS")?)?;
    let repo =
        std::env::var("GITHUB_REPO").unwrap_or_else(|_| "coproduct-opensource/nucleus".into());
    let app = std::env::var("RUNNER_APP").unwrap_or_else(|_| "nucleus-fly-build".into());
    let region = std::env::var("FLY_REGION").unwrap_or_else(|_| "iad".into());
    let poll = number("POLL_SECONDS", 20)?;
    let idle_secs = number("IDLE_MINUTES", 30)? * 60;
    let lookback = usize::try_from(number("LOOKBACK_RUNS", 30)?).unwrap_or(30);

    let mut manager = Manager::new(
        ForgeApi::new(Ureq::default(), FORGE_API, &var("GITHUB_TOKEN")?, &repo),
        MachinesApi::new(Ureq::default(), MACHINES_API, &var("FLY_API_TOKEN")?, &app),
        pools,
        image,
        region,
        lookback,
        idle_secs,
    );

    let once = std::env::args().any(|a| a == "--once");
    for pool in &manager.pools {
        println!(
            "pool {}: size {}, standby {}, {} volume(s)",
            pool.label,
            pool.size,
            pool.standby,
            pool.volumes.len()
        );
    }
    loop {
        match manager.tick(now_secs()) {
            Ok(report) => {
                let demand: Vec<String> = report
                    .demand
                    .iter()
                    .map(|(label, n)| format!("{label}={n}"))
                    .collect();
                println!(
                    "queued {} | started {} created {} retired {} runners removed {}",
                    demand.join(" "),
                    report.launched,
                    report.created,
                    report.retired,
                    report.runners_removed
                );
                for failure in &report.failures {
                    println!("failed: {failure}");
                }
            }
            // A pass that could not read the world changes nothing and is retried; the substrate
            // and the forge both have minutes of unavailability that mean nothing here.
            Err(error) => println!("pass failed: {error}"),
        }
        if once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(poll));
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ci-fly-runner: {error}");
            ExitCode::from(2)
        }
    }
}
