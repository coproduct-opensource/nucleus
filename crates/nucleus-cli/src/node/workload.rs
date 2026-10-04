//! Operator-facing access to the node's existing workload observation APIs.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Subcommand, ValueEnum};
use nucleus_spec::workload_result::WorkloadResult;
use uuid::Uuid;

use super::{HttpClient, REQUEST_TIMEOUT};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Save host admission metadata and public signer information for this workload
    Admission {
        /// New JSON file to retain separately from execution evidence
        #[arg(long)]
        output: PathBuf,
    },
    /// Print the supervisor's workload state as JSON
    Result,
    /// Save exact workload log bytes to a new file
    Logs {
        #[arg(value_enum)]
        stream: Stream,
        #[arg(long)]
        output: PathBuf,
    },
    /// Save a signed execution receipt, optionally with declared artifacts
    Collect {
        /// JSON object mapping declared artifact names to workspace paths
        #[arg(long)]
        artifacts: Option<PathBuf>,
        /// New JSON file; existing files are never overwritten
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Stream {
    Stdout,
    Stderr,
}

fn endpoint(origin: &str, pod: Uuid, resource: &str) -> Result<reqwest::Url> {
    let origin = reqwest::Url::parse(origin).context("invalid node URL")?;
    if origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        bail!("workload commands require an HTTPS node origin without a path or credentials");
    }
    Ok(origin.join(&format!("/v1/pods/{pod}/{resource}"))?)
}

fn selection(path: &Path) -> Result<Vec<u8>> {
    let selected: BTreeMap<String, String> = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .context("artifact manifest must be a JSON object mapping names to paths")?;
    if selected.is_empty() {
        bail!("artifact manifest is empty; omit --artifacts to collect only the receipt");
    }
    Ok(serde_json::to_vec(
        &serde_json::json!({"artifacts": selected}),
    )?)
}

/// Persist complete bytes in the destination directory, publishing only after
/// the write succeeds. `persist_noclobber` preserves an existing user file.
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .with_context(|| format!("saving {} (destination must not exist)", path.display()))?;
    Ok(())
}

pub(super) async fn run(
    client: &HttpClient,
    origin: &str,
    pod: Uuid,
    command: &Command,
) -> Result<()> {
    if !matches!(client, HttpClient::Mtls(_)) {
        bail!(
            "workload commands require mTLS; run nucleus setup or supply the client identity flags"
        );
    }
    let (resource, body) = match command {
        Command::Admission { .. } => ("workload-admission", None),
        Command::Result => ("workload-result", None),
        Command::Logs { stream, output: _ } => (
            match stream {
                Stream::Stdout => "workload-logs/stdout",
                Stream::Stderr => "workload-logs/stderr",
            },
            None,
        ),
        Command::Collect {
            artifacts,
            output: _,
        } => (
            "execution-receipt",
            artifacts.as_deref().map(selection).transpose()?,
        ),
    };
    let url = endpoint(origin, pod, resource)?;
    let method = if body.is_some() {
        reqwest::Method::POST
    } else {
        reqwest::Method::GET
    };
    let headers = if body.is_some() {
        vec![("content-type".into(), "application/json".into())]
    } else {
        Vec::new()
    };
    let (status, bytes) = client
        .send(
            method,
            url.as_str(),
            &headers,
            body.as_deref().unwrap_or_default(),
            REQUEST_TIMEOUT,
        )
        .await?;
    if status != 200 {
        let detail = serde_json::to_string(&super::node_error_detail(&bytes))?;
        bail!("workload request failed (HTTP {status}): {detail}");
    }
    match command {
        Command::Admission { output } => {
            let admitted: nucleus_spec::workload_admission::WorkloadAdmission =
                serde_json::from_slice(&bytes).context("invalid workload admission")?;
            if admitted.pod_id != pod.to_string() || admitted.session_id != pod.to_string() {
                bail!("workload admission identifies a different pod");
            }
            save(output, &serde_json::to_vec_pretty(&admitted)?)?;
            println!("Saved workload admission to {}", output.display());
        }
        Command::Result => {
            let result: WorkloadResult =
                serde_json::from_slice(&bytes).context("invalid workload result")?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Logs { stream: _, output } => {
            save(output, &bytes)?;
            println!("Saved {} bytes to {}", bytes.len(), output.display());
        }
        Command::Collect {
            artifacts: _,
            output,
        } => {
            // Export the node's wire document intact; collection is not an
            // independent signature or execution-policy verification.
            let _: serde_json::Value =
                serde_json::from_slice(&bytes).context("invalid receipt JSON")?;
            save(output, &bytes)?;
            println!(
                "Saved execution evidence to {}; independent verification is still required",
                output.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_manifest_preserves_declared_artifact_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            br#"{"patch":"changes.patch","tests":"test-results.json"}"#,
        )
        .unwrap();
        let request: serde_json::Value =
            serde_json::from_slice(&selection(&path).unwrap()).unwrap();
        assert_eq!(
            request,
            serde_json::json!({"artifacts":{"patch":"changes.patch","tests":"test-results.json"}})
        );
    }

    #[test]
    fn output_preserves_binary_bytes_and_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        let bytes = b"hello\0\xff\n";
        save(&path, bytes).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(save(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
