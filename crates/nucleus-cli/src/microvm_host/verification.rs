//! Apple host adapter for the shared supervised-workload verifier.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{container_cli::ContainerCli, lifecycle::MicroVmHost};
use crate::workload_verification::{self, Manifest};

pub(crate) async fn verify(host: &MicroVmHost) -> Result<Value> {
    let owned = host.container().clone();
    let manifest: Manifest = tokio::task::spawn_blocking(move || -> Result<Manifest> {
        let outcome = ContainerCli::system().exec(
            &owned,
            &["cat", nucleus_spec::microvm_host::HOST_INPUT_MANIFEST_PATH],
        );
        let raw = outcome.stdout().with_context(|| {
            format!("reading local host input manifest: {}", outcome.describe())
        })?;
        serde_json::from_str(raw).context("invalid local host input manifest")
    })
    .await??;
    ensure!(manifest.is_aarch64(), "Apple host inputs must be aarch64");
    let client = crate::provision::mtls_client_from_identity_dir(host.identity_dir())?;
    workload_verification::verify(client, &host.node_url(), manifest).await
}
