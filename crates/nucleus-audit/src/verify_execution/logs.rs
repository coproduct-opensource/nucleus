//! Check the exact retained bytes using the shared verified-execution witness.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use nucleus_ci_verdict::execution::{RecordedExecution, verify_execution};
use nucleus_receipt::Receipt;
use nucleus_spec::workload_result::MAX_LOG_BYTES;

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    /// Collected signed execution receipt
    #[arg(long)]
    receipt: PathBuf,
    /// Independently prepared RecordedExecution JSON, including pinned signer
    #[arg(long)]
    expectations: PathBuf,
    /// Exact saved stdout bytes, without text conversion
    #[arg(long)]
    stdout: PathBuf,
    /// Exact saved stderr bytes (supply an empty file for an empty stream)
    #[arg(long)]
    stderr: PathBuf,
}

fn bytes(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening log {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "log {} is not a regular file",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_LOG_BYTES,
        "log {} exceeds the node's {MAX_LOG_BYTES}-byte retention limit",
        path.display()
    );
    Ok(bytes)
}

impl Args {
    pub(super) fn verify(self) -> Result<serde_json::Value> {
        let expected: RecordedExecution = super::read(&self.expectations)?;
        let receipt: Receipt = super::read(&self.receipt)?;
        let execution = verify_execution(&receipt, &expected.as_expected())?;
        let logs = execution.verify_logs(bytes(&self.stdout)?, bytes(&self.stderr)?)?;
        let now = super::now()?;
        let (stdout, stderr) = logs.into_parts(now)?;
        let claim = execution.into_claim(now)?;
        Ok(serde_json::json!({
            "execution_verified": true,
            "log_bytes_verified": {"stdout":stdout.len(), "stderr":stderr.len()},
            "claim": claim,
        }))
    }
}
