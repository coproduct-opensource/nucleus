use std::path::Path;

use nucleus_spec::NetworkSpec;
use tokio::io::AsyncWriteExt;

use crate::ApiError;

pub async fn apply_network_policy(
    pod_dir: &Path,
    policy: Option<&NetworkSpec>,
) -> Result<(), ApiError> {
    let policy = match policy {
        Some(policy) => policy,
        None => return Ok(()),
    };

    if !policy.allow.is_empty() {
        let allowlist = policy.allow.join("\n");
        let path = pod_dir.join("net.allow");
        let mut file = tokio::fs::File::create(&path).await?;
        file.write_all(allowlist.as_bytes()).await?;
    }

    if !policy.deny.is_empty() {
        let denylist = policy.deny.join("\n");
        let path = pod_dir.join("net.deny");
        let mut file = tokio::fs::File::create(&path).await?;
        file.write_all(denylist.as_bytes()).await?;
    }

    Ok(())
}
