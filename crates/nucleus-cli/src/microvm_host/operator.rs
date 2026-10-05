//! Lifecycle commands follow the saved installation without selecting another
//! backend on failure. Stop acts only on the lifecycle's ownership witness.
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Value, json};

use super::container_cli::ContainerCli;
use super::lifecycle::{self, HostConfig, HostLock, HostState};
use super::{preflight, settings};

pub(crate) const DEFAULT_LIMA_NAME: &str = "nucleus";

pub(crate) fn selection<'a>(
    explicit: Option<&'a Path>,
    named_lima: bool,
    saved: Option<&'a Path>,
) -> Option<&'a Path> {
    explicit.or(if named_lima { None } else { saved })
}

fn report(value: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) async fn start(path: &Path) -> Result<()> {
    let host = settings::ready(path).await?;
    report(json!({
        "backend":"apple-container", "state":"ready",
        "container":host.container().name(), "node_url":host.node_url(),
        "identity_dir":host.identity_dir(),
    }))
}

pub(crate) async fn stop(path: &Path) -> Result<()> {
    ensure!(
        cfg!(target_os = "macos"),
        "Apple host selection requires macOS"
    );
    let cfg = settings::HostSettings::from_file(path)?.config_for_stop()?;
    let result =
        tokio::task::spawn_blocking(move || stop_existing(&ContainerCli::system(), &cfg)).await??;
    report(result)
}

fn observe(cli: &ContainerCli, cfg: &HostConfig) -> Result<HostState> {
    lifecycle::observe_state(cli, cfg).map_err(|error| anyhow!("{error}"))
}

fn stop_existing(cli: &ContainerCli, cfg: &HostConfig) -> Result<Value> {
    std::fs::create_dir_all(&cfg.state_dir)?;
    let _lock =
        HostLock::acquire(&cfg.state_dir, cfg.ready_timeout).map_err(|error| anyhow!("{error}"))?;
    let state = match observe(cli, cfg)? {
        HostState::Absent => "absent",
        HostState::Stopped(_) => "stopped",
        HostState::Stale { reason } => {
            bail!("refusing to stop a mismatched Apple host: {reason:?}")
        }
        HostState::Running(owned, _) => {
            let result = cli.stop(&owned);
            ensure!(
                result.succeeded(),
                "stopping Apple host: {}",
                result.describe()
            );
            match observe(cli, cfg)? {
                HostState::Stopped(_) => "stopped",
                HostState::Absent => "absent",
                HostState::Running(_, _) | HostState::Stale { .. } => {
                    bail!("Apple host did not become stopped after the stop command")
                }
            }
        }
    };
    Ok(json!({"backend":"apple-container", "state":state,
        "container":cfg.names.container, "state_preserved":true}))
}

/// Observe the selected host and check its existing KVM/mTLS surface. Never
/// start, replace, reconfigure, or mint an identity as a diagnostic side effect.
pub(crate) async fn doctor(path: &Path) -> Result<()> {
    let cfg = settings::configuration(path)?;
    let value = tokio::task::spawn_blocking(move || -> Result<Value> {
        let cli = ContainerCli::system();
        let (owned, ports) = match observe(&cli, &cfg)? {
            HostState::Running(owned, ports) => (owned, ports),
            HostState::Absent => bail!("Apple host is absent; run nucleus start"),
            HostState::Stopped(_) => bail!("Apple host is stopped; run nucleus start"),
            HostState::Stale { reason } => bail!("Apple host configuration differs: {reason:?}"),
        };
        let probe = cli.exec(
            &owned,
            &[
                &nucleus_spec::microvm_host::in_container_bin(nucleus_spec::microvm_host::HOSTCTL),
                "probe",
            ],
        );
        ensure!(
            matches!(
                preflight::kvm_from(&probe),
                preflight::KvmObservation::Usable
            ),
            "Apple host KVM probe failed: {}",
            probe.describe()
        );
        lifecycle::wait_host_healthy(
            &cli,
            &owned,
            &ports,
            &cfg,
            cfg.ready_timeout.min(Duration::from_secs(5)),
        )
        .map_err(|error| anyhow!("{error}"))?;
        let address = ports
            .node_address(cfg.connection)
            .map_err(|error| anyhow!(error))?;
        Ok(json!({"backend":"apple-container", "state":"healthy",
            "container":owned.name(), "node_url":format!("https://{address}"),
            "kvm_checked":true, "mtls_health_checked":true,
            "workload_verification_performed":false}))
    })
    .await??;
    report(value)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn an_explicit_selection_overrides_the_saved_installation() {
        let saved = Path::new("saved.json");
        let explicit = Path::new("explicit.json");
        assert_eq!(selection(None, false, Some(saved)), Some(saved));
        assert_eq!(selection(None, true, Some(saved)), None);
        assert_eq!(
            selection(Some(explicit), false, Some(saved)),
            Some(explicit)
        );
        assert_eq!(selection(None, false, None), None);
    }

    fn fixture() -> (tempfile::TempDir, ContainerCli, HostConfig, Value) {
        // CI may mount /tmp noexec; executable fixtures live beside this binary.
        let executable = std::env::current_exe().unwrap();
        let dir = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let program = dir.path().join("container");
        std::fs::write(
            &program,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$0.calls"
case "$1" in
  list) cat "$0.state" ;;
  stop) cp "$0.stopped" "$0.state" ;;
  *) exit 64 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let running: Value = serde_json::from_str(&lifecycle::running_fixture()).unwrap();
        let mut stopped = running.clone();
        stopped[0]["status"]["state"] = json!("stopped");
        std::fs::write(dir.path().join("container.state"), running.to_string()).unwrap();
        std::fs::write(dir.path().join("container.stopped"), stopped.to_string()).unwrap();
        let settings = dir.path().join("host.json");
        std::fs::write(
            &settings,
            json!({
                "image":"nucleus-dev-microvm-host:local", "kernel":"missing-kernel",
                "development":true, "state_dir":"state", "ready_timeout_secs":1
            })
            .to_string(),
        )
        .unwrap();
        // Stop must still work after an operator removes an old boot kernel.
        assert!(
            settings::HostSettings::from_file(&settings)
                .unwrap()
                .config()
                .is_err()
        );
        let config = settings::HostSettings::from_file(&settings)
            .unwrap()
            .config_for_stop()
            .unwrap();
        (dir, ContainerCli::at(program), config, running)
    }

    #[test]
    fn stop_preserves_state_and_is_idempotent_without_starting_anything() {
        let (dir, cli, cfg, _) = fixture();
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        let retained = cfg.state_dir.join("retained-identity");
        std::fs::write(&retained, b"retained installation").unwrap();
        assert_eq!(stop_existing(&cli, &cfg).unwrap()["state"], "stopped");
        assert_eq!(stop_existing(&cli, &cfg).unwrap()["state"], "stopped");
        assert_eq!(std::fs::read(retained).unwrap(), b"retained installation");
        let calls = std::fs::read_to_string(dir.path().join("container.calls")).unwrap();
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.starts_with("stop "))
                .count(),
            1
        );
        assert!(
            calls
                .lines()
                .all(|line| line.starts_with("list ") || line.starts_with("stop "))
        );
    }

    #[test]
    fn stop_refuses_foreign_or_mismatched_hosts_and_unreadable_observations() {
        let (dir, cli, cfg, running) = fixture();
        let mut foreign = running.clone();
        foreign[0]["configuration"]["labels"] = json!({});
        let mut different = running.clone();
        different[0]["configuration"]["image"]["reference"] = json!("different:tag");
        for contents in [
            foreign.to_string(),
            different.to_string(),
            "not JSON".into(),
        ] {
            std::fs::write(dir.path().join("container.state"), contents).unwrap();
            assert!(stop_existing(&cli, &cfg).is_err());
        }
        let calls = std::fs::read_to_string(dir.path().join("container.calls")).unwrap();
        assert!(calls.lines().all(|line| line.starts_with("list ")));
    }
}
