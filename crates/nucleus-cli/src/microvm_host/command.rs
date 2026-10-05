//! User-facing entry to the Apple Container host lifecycle.

use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand};
use nucleus_spec::microvm_host::HostNames;
use serde_json::{Value, json};

use super::container_cli::ContainerCli;
use super::lifecycle::{self, Expected, HostState};
use super::settings::HostSettings as UpArgs;

#[derive(Args)]
pub(crate) struct HostArgs {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the host and verify KVM plus the node's mTLS health endpoint
    Up(UpArgs),
    /// Inspect the host container without starting it (not a health check)
    Status(Selection),
}

#[derive(Args)]
struct Selection {
    /// Locally built microVM host image containing matched node/guest artifacts
    #[arg(long, value_parser = nonempty)]
    image: String,
    /// Use the separate nucleus-dev host and state volume
    #[arg(long)]
    development: bool,
}

impl Selection {
    fn names(&self) -> HostNames {
        if self.development {
            HostNames::DEV
        } else {
            HostNames::INSTALL
        }
    }
}

fn nonempty(value: &str) -> std::result::Result<String, String> {
    if value.trim().is_empty() {
        Err("image reference must not be empty".into())
    } else {
        Ok(value.to_owned())
    }
}

fn status(state: HostState) -> Value {
    match state {
        HostState::Absent => json!({"state":"absent"}),
        HostState::Stopped(owned) => json!({"state":"stopped", "container":owned.name()}),
        HostState::Running(owned, ports) => json!({
            "state":"running", "container":owned.name(),
            "node_url":format!("https://127.0.0.1:{}", ports.node),
            "health_checked":false,
        }),
        HostState::Stale { reason } => json!({"state":"stale", "reason":format!("{reason:?}")}),
    }
}

pub(crate) async fn execute(args: HostArgs) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("microvm-host requires macOS with Apple Container; use nucleus setup on Linux");
    }
    let report = tokio::task::spawn_blocking(move || execute_blocking(args)).await??;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn execute_blocking(args: HostArgs) -> Result<Value> {
    let cli = ContainerCli::system();
    match args.command {
        Command::Up(args) => {
            let config = args.config()?;
            let host =
                lifecycle::ensure_ready(&cli, &config).map_err(|error| anyhow!("{error}"))?;
            Ok(json!({
                "state":"ready", "container":host.container().name(),
                "node_url":host.node_url(), "identity_dir":host.identity_dir(),
                "state_dir":host.state_dir(), "relay_ports":host.relay_ports(),
            }))
        }
        Command::Status(selection) => {
            let result = cli.list_all();
            let raw = result
                .stdout()
                .ok_or_else(|| anyhow!("container list: {}", result.describe()))?;
            let state = lifecycle::host_state(
                raw,
                &Expected {
                    names: &selection.names(),
                    image: &selection.image,
                },
            )
            .map_err(|error| anyhow!("container list: {error}"))?;
            Ok(status(state))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Parse {
        #[command(flatten)]
        args: HostArgs,
    }

    #[test]
    fn up_requires_explicit_artifacts_and_positive_capacity() {
        for args in [
            vec!["nucleus", "up"],
            vec![
                "nucleus",
                "up",
                "--image",
                "host",
                "--kernel",
                "/tmp/Image",
                "--cpus",
                "0",
            ],
            vec![
                "nucleus",
                "up",
                "--image",
                "host",
                "--kernel",
                "/tmp/Image",
                "--ready-timeout-secs",
                "0",
            ],
        ] {
            assert!(Parse::try_parse_from(args).is_err());
        }
        let parsed =
            Parse::try_parse_from(["nucleus", "status", "--image", "host", "--development"])
                .unwrap();
        let Command::Status(selection) = parsed.args.command else {
            panic!("status")
        };
        assert_eq!(selection.names(), HostNames::DEV);
    }

    #[test]
    fn running_status_does_not_claim_readiness() {
        let raw = include_str!("fixtures/list-running.json");
        let state = lifecycle::host_state(
            raw,
            &Expected {
                names: &HostNames::DEV,
                image: "nucleus-dev-microvm-host:local",
            },
        )
        .unwrap();
        let report = status(state);
        assert_eq!(report["state"], "running");
        assert_eq!(report["health_checked"], false);
    }
}
