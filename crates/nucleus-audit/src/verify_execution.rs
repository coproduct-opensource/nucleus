//! CLI adapters for the shared execution verifier; expectations are separate
//! operator inputs, never inferred from the evidence being verified.
use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use nucleus_ci_verdict::execution::{RecordedExecution, verify_artifacts, verify_execution};
use nucleus_receipt::Receipt;
use serde::Deserialize;

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Verify a collected execution receipt against independently supplied expectations
    VerifyExecution {
        #[arg(long)]
        receipt: PathBuf,
        /// RecordedExecution JSON from the trusted admission/controller record
        #[arg(long)]
        expectations: PathBuf,
    },
    /// Verify a collected bundle's execution receipt and every artifact's bytes
    VerifyArtifacts {
        #[arg(long)]
        bundle: PathBuf,
        /// RecordedExecution JSON including pinned signer and selected artifact paths
        #[arg(long)]
        expectations: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    receipt: Receipt,
    artifacts: BTreeMap<String, String>,
}

fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    serde_json::from_reader(std::io::BufReader::new(
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
    ))
    .with_context(|| format!("parsing {}", path.display()))
}

fn now() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?)
}

impl Command {
    pub(crate) fn run(self) -> Result<(), crate::AuditError> {
        self.verify()
            .map_err(|e| crate::AuditError::Backend(e.to_string()))
    }

    fn verify(self) -> Result<()> {
        let (claim, artifact_count) = match self {
            Self::VerifyExecution {
                receipt,
                expectations,
            } => {
                let expected: RecordedExecution = read(&expectations)?;
                let receipt: Receipt = read(&receipt)?;
                let verified = verify_execution(&receipt, &expected.as_expected())?;
                (verified.into_claim(now()?)?, None)
            }
            Self::VerifyArtifacts {
                bundle,
                expectations,
            } => {
                let expected: RecordedExecution = read(&expectations)?;
                let bundle: Bundle = read(&bundle)?;
                let bytes = bundle
                    .artifacts
                    .into_iter()
                    .map(|(name, encoded)| {
                        base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .with_context(|| format!("decoding artifact {name:?}"))
                            .map(|bytes| (name, bytes))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                let verified = verify_artifacts(&bundle.receipt, &expected.as_expected(), bytes)?;
                let (claim, bytes) = verified.into_parts(now()?)?;
                (claim, Some(bytes.len()))
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "execution_verified": true,
                "artifact_bytes_verified": artifact_count,
                "claim": claim,
            }))?
        );
        Ok(())
    }
}
