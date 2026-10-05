//! Save both raw streams before publishing the requested execution receipt.
use std::path::Path;

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use super::{HttpClient, REQUEST_TIMEOUT};

pub(super) async fn collect(
    client: &HttpClient,
    origin: &str,
    pod: Uuid,
    directory: &Path,
) -> Result<()> {
    // Fetch both before creating output. An unavailable or oversized stream
    // must not leave a directory that appears to contain a complete pair.
    let stdout = fetch(client, origin, pod, "workload-logs/stdout").await?;
    let stderr = fetch(client, origin, pod, "workload-logs/stderr").await?;
    save(directory, &stdout, &stderr)
}

async fn fetch(client: &HttpClient, origin: &str, pod: Uuid, resource: &str) -> Result<Vec<u8>> {
    let url = super::endpoint(origin, pod, resource)?;
    let (status, bytes) = client
        .send(
            reqwest::Method::GET,
            url.as_str(),
            &[],
            &[],
            REQUEST_TIMEOUT,
        )
        .await?;
    if status != 200 {
        let detail = serde_json::to_string(&super::super::node_error_detail(&bytes))?;
        bail!("raw log collection failed (HTTP {status}): {detail}; receipt was not saved");
    }
    Ok(bytes)
}

fn save(directory: &Path, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).with_context(|| {
        format!(
            "creating raw log directory {} (must not exist)",
            directory.display()
        )
    })?;
    let write = || -> Result<()> {
        super::save(&directory.join("stdout.bin"), stdout)?;
        super::save(&directory.join("stderr.bin"), stderr)?;
        Ok(())
    };
    write().with_context(|| {
        format!(
            "raw log directory {} may be partial; receipt was not saved and pod was not cancelled",
            directory.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_streams_keep_exact_bytes_and_private_permissions() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("logs");
        save(&output, b"hello\0\xff\r\n", b"").unwrap();
        assert_eq!(
            std::fs::read(output.join("stdout.bin")).unwrap(),
            b"hello\0\xff\r\n"
        );
        assert!(std::fs::read(output.join("stderr.bin")).unwrap().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for name in ["stdout.bin", "stderr.bin"] {
                assert_eq!(
                    std::fs::metadata(output.join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        assert!(save(&output, b"replacement", b"replacement").is_err());
        assert_eq!(
            std::fs::read(output.join("stdout.bin")).unwrap(),
            b"hello\0\xff\r\n"
        );
    }
}
