//! Explicit Apple host selection; readiness is required before pod creation.
use std::path::Path;

use super::{ResolvedConfig, RunArgs};
use crate::microvm_host::{lifecycle, settings};
use anyhow::Result;

pub(super) fn apply_default(args: &mut RunArgs, config: &crate::config::Config) {
    if args.apple_host_config.is_none()
        && !args.local
        && !args.hook
        && args.node_url.is_none()
        && args.identity_dir.is_none()
        && args.node_auth_secret.is_none()
    {
        args.apple_host_config = config.node.apple_host_config.clone();
    }
}

pub(super) fn configuration(path: &Path) -> Result<lifecycle::HostConfig> {
    settings::configuration(path)
}

pub(super) async fn ready(
    path: &Path,
    args: &RunArgs,
) -> Result<(ResolvedConfig, lifecycle::MicroVmHost)> {
    let host = settings::ready(path).await?;
    let client = crate::provision::mtls_client_from_identity_dir(host.identity_dir())?;
    let resolved = ResolvedConfig {
        node_url: host.node_url(),
        node_mtls_client: Some(client),
        node_auth_secret: None,
        node_actor: args.node_actor.clone(),
        kernel_path: args
            .kernel_path
            .clone()
            .unwrap_or_else(nucleus_spec::microvm_host::guest_kernel_path),
        rootfs_path: args
            .rootfs_path
            .clone()
            .unwrap_or_else(nucleus_spec::microvm_host::guest_rootfs_path),
    };
    Ok((resolved, host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Parse {
        #[command(flatten)]
        args: RunArgs,
    }

    #[test]
    fn saved_host_applies_to_ordinary_goal_and_grant_runs_but_not_explicit_modes() {
        let mut config = crate::config::Config::default();
        config.node.apple_host_config = Some("saved-host.json".into());
        for arguments in [
            vec!["ordinary task"],
            vec!["--goal", "goal.json"],
            vec!["--grant", "grant.json"],
        ] {
            let mut input = vec!["run"];
            input.extend(arguments);
            let mut parsed = Parse::try_parse_from(input).unwrap();
            apply_default(&mut parsed.args, &config);
            assert_eq!(parsed.args.apple_host_config, config.node.apple_host_config);
        }
        for extra in [
            vec!["--local"],
            vec!["--hook"],
            vec!["--node-url", "https://selected.example"],
            vec!["--identity-dir", "/selected"],
            vec!["--node-auth-secret", "explicit"],
        ] {
            let mut input = vec!["run", "ordinary task"];
            input.extend(extra);
            let mut parsed = Parse::try_parse_from(input).unwrap();
            apply_default(&mut parsed.args, &config);
            assert!(parsed.args.apple_host_config.is_none());
        }
    }

    #[test]
    fn selected_host_cannot_be_mixed_with_another_connection_or_mode() {
        for extra in [
            vec!["--local"],
            vec!["--hook"],
            vec!["--node-url", "https://other:8080"],
            vec!["--identity-dir", "/other"],
            vec!["--node-auth-secret", "unused"],
        ] {
            let mut args = vec!["run", "ordinary task", "--apple-host-config", "host.json"];
            args.extend(extra);
            assert!(Parse::try_parse_from(args).is_err());
        }
        let parsed = Parse::try_parse_from([
            "run",
            "ordinary task",
            "--apple-host-config",
            "host.json",
            "--dry-run",
        ])
        .unwrap();
        assert!(parsed.args.dry_run);
    }
}
