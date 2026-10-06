//! CLI adapters for the shared execution verifier; expectations are separate
//! operator inputs, never inferred from the evidence being verified.
use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use nucleus_ci_verdict::execution::{RecordedExecution, verify_artifacts, verify_execution};
use nucleus_receipt::Receipt;
use serde::Deserialize;

mod export;
mod logs;
mod node;
mod prepare;

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Prepare expectations offline from trusted admission and intended inputs
    PrepareExecution(prepare::Args),
    /// Verify exact stdout/stderr files against an independently verified execution receipt
    VerifyLogs(logs::Args),
    /// Verify a collected execution receipt against independently supplied
    /// expectations, and report the signing node's platform tier beside it
    VerifyExecution {
        #[arg(long)]
        receipt: PathBuf,
        /// RecordedExecution JSON from the trusted admission/controller record
        #[arg(long)]
        expectations: PathBuf,
        #[command(flatten)]
        platform: node::PlatformArgs,
    },
    /// Appraise a node's platform evidence (TPM quote + boot and IMA logs)
    /// against a reference manifest; succeeds only for `Attested`
    VerifyNodeEvidence(node::Args),
    /// Verify a collected bundle's execution receipt and every artifact's bytes
    VerifyArtifacts {
        #[arg(long)]
        bundle: PathBuf,
        /// RecordedExecution JSON including pinned signer and selected artifact paths
        #[arg(long)]
        expectations: PathBuf,
        /// Save verified bytes by artifact name in a new directory
        #[arg(long)]
        output_dir: Option<PathBuf>,
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
            .map_err(|e| crate::AuditError::Backend(format!("{e:#}")))
    }

    fn verify(self) -> Result<()> {
        let mut platform = serde_json::Value::Null;
        let (claim, artifact_count, output_dir) = match self {
            Self::VerifyNodeEvidence(args) => return args.run(),
            Self::VerifyLogs(args) => {
                println!("{}", serde_json::to_string_pretty(&args.verify()?)?);
                return Ok(());
            }
            Self::PrepareExecution(args) => {
                println!("{}", serde_json::to_string_pretty(&args.prepare(now()?)?)?);
                return Ok(());
            }
            Self::VerifyExecution {
                receipt,
                expectations,
                platform: platform_args,
            } => {
                let expected: RecordedExecution = read(&expectations)?;
                let receipt: Receipt = read(&receipt)?;
                let verified = verify_execution(&receipt, &expected.as_expected())?;
                // Authorization first (above); the platform is the second
                // axis of the composite verdict and never substitutes for it.
                let (report, attested) = node::platform(
                    &platform_args,
                    verified.claim(),
                    receipt.session.issued_at_micros,
                    &expected.verifying_key,
                )?;
                platform = serde_json::json!({
                    "verdict": if attested {
                        "authorized_on_an_attested_node"
                    } else {
                        "authorized_platform_not_attested"
                    },
                    "platform": report,
                });
                (verified.into_claim(now()?)?, None, None)
            }
            Self::VerifyArtifacts {
                bundle,
                expectations,
                output_dir,
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
                let claim = match &output_dir {
                    Some(path) => export::save(verified, path, now()?)?,
                    None => verified.into_parts(now()?)?.0,
                };
                let count = claim.artifacts.len();
                (claim, Some(count), output_dir)
            }
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "execution_verified": true,
                "artifact_bytes_verified": artifact_count,
                "artifacts_directory": output_dir,
                "claim": claim,
                "node_platform": platform,
            }))?
        );
        Ok(())
    }
}
