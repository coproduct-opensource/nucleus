//! Explicit Apple host selection; readiness is required before pod creation.
use std::path::Path;

use super::{ResolvedConfig, RunArgs};
use crate::microvm_host::{lifecycle, settings};
use anyhow::Result;

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
