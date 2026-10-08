//! Explicit directory transfer and workspace seeding through the checked host.
use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use clap::Args;
use nucleus_spec::{ArtifactDigest, microvm_host::NODE_STATE_DIR};
use serde_json::{Value, json};
use uuid::Uuid;

use super::container_cli::{ContainerCli, Outcome};
use super::lifecycle::{self, Owned};
use super::settings::HostSettings;

#[derive(Args)]
pub(super) struct SeedArgs {
    /// Same explicit JSON host settings accepted by run --apple-host-config
    #[arg(long)]
    host_config: PathBuf,
    /// Complete directory to copy, including hidden files; source is unchanged
    tree: PathBuf,
    /// Owner of files inside the guest (match the workload specification)
    #[arg(long)]
    workload_uid: NonZeroU32,
    #[arg(long)]
    workload_gid: u32,
    /// Match the node's configured jailer UID; no independent default
    #[arg(long)]
    jailer_uid: NonZeroU32,
    #[arg(long)]
    jailer_gid: u32,
    /// Free space beyond the source contents, in MiB
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..))]
    free_mib: u32,
}

fn completed(result: Outcome, operation: &str) -> Result<String> {
    result
        .stdout()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{operation}: {}", result.describe()))
}

pub(super) fn seed(cli: &ContainerCli, args: SeedArgs) -> Result<Value> {
    let source = args
        .tree
        .canonicalize()
        .context("resolving workspace directory")?;
    ensure!(source.is_dir(), "workspace source must be a directory");
    crate::workspace_scan::warn(&source, "it is about to become a pod's scratch disk");
    let source = source
        .to_str()
        .ok_or_else(|| anyhow!("workspace path must be UTF-8"))?;
    let config = HostSettings::from_file(&args.host_config)?.config()?;
    let host = lifecycle::ensure_ready(cli, &config).map_err(|e| anyhow!("{e}"))?;
    let id = Uuid::new_v4();
    // Apple copy writes the container root filesystem, not mounted volumes.
    // Stage there, then let hostctl create the disk on the shared state volume.
    let stage = format!("/tmp/nucleus-workspace-input-{id}");
    let disk = format!("{NODE_STATE_DIR}/scratch/workspace-{id}.ext4");
    let digest = transfer(cli, host.container(), source, &stage, &disk, &args)
        .with_context(|| format!(
            "workspace seeding failed; inspect staging {stage} and disk {disk} on {} before cleanup",
            host.container().name()
        ))?;
    Ok(json!({
        "container":host.container().name(),
        "node_url":host.node_url(),
        "image":{"scratch_path":disk,"scratch_digest":digest},
        "workload_owner":{"uid":args.workload_uid.get(),"gid":args.workload_gid},
    }))
}

fn transfer(
    cli: &ContainerCli,
    host: &Owned,
    source: &str,
    stage: &str,
    disk: &str,
    args: &SeedArgs,
) -> Result<ArtifactDigest> {
    completed(
        cli.exec(host, &["mkdir", "-m", "700", "--", stage]),
        "creating workspace staging",
    )?;
    let tree = format!("{stage}/tree");
    completed(cli.copy_into(host, source, &tree), "copying workspace")?;
    let owner = format!("{}:{}", args.workload_uid, args.workload_gid);
    let jailer_uid = args.jailer_uid.to_string();
    let jailer_gid = args.jailer_gid.to_string();
    let free = args.free_mib.to_string();
    let response = completed(
        cli.exec_workspace(
            host,
            &[
                "nucleus-hostctl",
                "seed",
                &tree,
                disk,
                "--owner",
                &owner,
                "--jailer-uid",
                &jailer_uid,
                "--jailer-gid",
                &jailer_gid,
                "--free-mib",
                &free,
            ],
        ),
        "building workspace disk",
    )?;
    let digest =
        ArtifactDigest::parse(response.trim()).map_err(|e| anyhow!("invalid seed digest: {e}"))?;
    // The only removed tree is this invocation's UUID staging directory. The
    // completed disk remains available for pod admission and later readback.
    completed(
        cli.exec(host, &["rm", "-rf", "--", stage]),
        "removing workspace staging",
    )?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Parse {
        #[command(flatten)]
        args: SeedArgs,
    }

    #[test]
    fn seed_requires_explicit_owners_and_positive_capacity() {
        let input = [
            "seed",
            "--host-config",
            "host.json",
            "/project with spaces",
            "--workload-uid",
            "1000",
            "--workload-gid",
            "1000",
            "--jailer-uid",
            "123",
            "--jailer-gid",
            "100",
            "--free-mib",
            "16",
        ];
        let parsed = Parse::try_parse_from(input).unwrap().args;
        assert_eq!(parsed.tree, PathBuf::from("/project with spaces"));
        assert_eq!(parsed.free_mib, 16);
        for flag in ["--workload-uid", "--jailer-uid", "--free-mib"] {
            let mut zero = input.to_vec();
            let value = zero.iter().position(|v| *v == flag).unwrap() + 1;
            zero[value] = "0";
            assert!(Parse::try_parse_from(zero).is_err());
        }
        assert!(Parse::try_parse_from(["seed", "--host-config", "host.json", "/project"]).is_err());
    }

    #[test]
    fn command_failure_and_timeout_are_not_digest_outputs() {
        for outcome in [
            Outcome::Missing,
            Outcome::TimedOut {
                after: std::time::Duration::from_secs(1),
            },
            Outcome::Failed {
                code: Some(1),
                stdout: "partial digest".into(),
                stderr: "copy failed".into(),
            },
        ] {
            let error = completed(outcome, "copying workspace").unwrap_err();
            assert!(error.to_string().contains("copying workspace"));
        }
    }
}
