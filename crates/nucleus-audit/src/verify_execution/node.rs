//! Node platform evidence: appraise it on its own (`verify-node-evidence`)
//! and as the platform half of an execution receipt's composite verdict
//! (#2706, ADR 0011).
//!
//! Every comparison input is the relying party's: the executor key comes from
//! the receipt's pinned expectations or the command line, the reference
//! manifest and the anchors (trust roots, operator pins) from files the
//! operator of THIS verifier chose. Nothing the evidence says is used to check
//! the evidence.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use nucleus_ci_verdict::execution::{ExecutionClaim, NodePlatform};
use nucleus_node_evidence::{
    AnchorPolicy, Appraisal, AppraisalPolicy, ExecutorKey, Federation, FederationKeyAttestation,
    Freshness, FreshnessExpectation, KeyBinding, KeyRefusal, NodeEvidence, Nonce, OperatorPin,
    ReferenceManifest, Refusal, Tier, appraise, appraise_federation_keys, evidence_digest,
};

/// The relying party's anchors.
#[derive(clap::Args, Debug)]
pub(crate) struct AnchorArgs {
    /// A root certificate (PEM or DER) an AK certificate chain may end at.
    #[arg(long)]
    trust_root: Vec<PathBuf>,
    /// `SOURCE=SPKI_SHA256`: accept the operator's word that the AK with this
    /// fingerprint, fetched from SOURCE, is a TPM's. The weakest anchor that
    /// names hardware.
    #[arg(long)]
    operator_pin: Vec<String>,
    /// `SOURCE=SPKI_SHA256`: accept the AK with this fingerprint as a
    /// SOFTWARE TPM's (swtpm, as CI runs). No hardware holds that key, so
    /// whoever runs the emulator can sign any quote; the result is labelled
    /// `software_tpm`. Evidence claiming a software TPM is never anchored
    /// without this flag, and an `--operator-pin` never anchors it.
    #[arg(long)]
    allow_software_tpm_pin: Vec<String>,
}

/// Parse `SOURCE=SPKI_SHA256` pins given under `flag`.
fn pins(flag: &str, specs: &[String]) -> Result<Vec<OperatorPin>> {
    specs
        .iter()
        .map(|spec| {
            let (source, fp) = spec
                .rsplit_once('=')
                .ok_or_else(|| anyhow!("{flag} is SOURCE=SPKI_SHA256, got {spec:?}"))?;
            if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{flag} {spec:?}: the fingerprint is not SHA-256 hex");
            }
            Ok(OperatorPin {
                source: source.to_string(),
                ak_spki_sha256: fp.to_ascii_lowercase(),
            })
        })
        .collect()
}

fn der_of(bytes: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(bytes.to_vec());
    };
    if !text.contains("-----BEGIN") {
        return Ok(bytes.to_vec());
    }
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .context("PEM body is not base64")
}

impl AnchorArgs {
    fn policy(&self) -> Result<AnchorPolicy> {
        let mut trust_roots = Vec::new();
        for path in &self.trust_root {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            trust_roots.push(der_of(&bytes)?);
        }
        Ok(AnchorPolicy {
            trust_roots,
            operator_pins: pins("--operator-pin", &self.operator_pin)?,
            software_tpm_pins: pins("--allow-software-tpm-pin", &self.allow_software_tpm_pin)?,
        })
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn unix_now() -> Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?)
}

fn hex32(what: &str, s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| anyhow!("{what} must be 32 bytes of hex"))
}

/// `verify-node-evidence`.
#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    /// The evidence document (JSON).
    #[arg(long)]
    evidence: PathBuf,
    /// The reference manifest (JSON) to compare measurements with.
    #[arg(long)]
    reference: PathBuf,
    /// The executor's Ed25519 public key (hex) the evidence must be bound to.
    #[arg(long)]
    executor_ed25519: String,
    /// The federation key set the evidence must be bound to:
    /// `not-federated`, or the SHA-256 (hex) of the operator's published JWKS
    /// document. A node with a federation issuer (ADR 0010) binds its JWKS, so
    /// its evidence is refused under the default, and the refusal names the
    /// digest the evidence binds.
    #[arg(long, default_value = "not-federated")]
    federation: String,
    /// The nonce (hex) this verifier sent, for challenge-response evidence.
    #[arg(long, conflicts_with = "receipt_time")]
    nonce: Option<String>,
    /// For epoch evidence: the time (Unix seconds) it must be fresh at.
    #[arg(long)]
    receipt_time: Option<i64>,
    /// For epoch evidence: the oldest it may be at `--receipt-time`.
    #[arg(long, default_value_t = 900)]
    max_age_secs: u64,
    /// The issuer's published JWKS. With `--federation-key-attestation`, each
    /// of its keys is checked to be TPM-resident, certified by this
    /// evidence's AK, and usable only in the boot state the quote measured
    /// (ADR 0012).
    #[arg(long, requires = "federation_key_attestation")]
    jwks: Option<PathBuf>,
    /// The node's custody statements for those keys
    /// (`nucleus-federation-key-attestation/v1`).
    #[arg(long, requires = "jwks")]
    federation_key_attestation: Option<PathBuf>,
    #[command(flatten)]
    anchors: AnchorArgs,
}

impl Args {
    /// Appraise, print the EAR result, and succeed only for `Attested`.
    pub(crate) fn run(self) -> Result<()> {
        let evidence: NodeEvidence = read_json(&self.evidence)?;
        let reference: ReferenceManifest = read_json(&self.reference)?;
        let federation = match self.federation.as_str() {
            "not-federated" => Federation::NotFederated,
            hex => Federation::JwksSha256(hex32("--federation", hex)?),
        };
        let binding = KeyBinding {
            executor_key: ExecutorKey::Ed25519(hex32(
                "--executor-ed25519",
                &self.executor_ed25519,
            )?),
            federation,
        };
        let freshness = match (&self.nonce, self.receipt_time) {
            (Some(n), None) => FreshnessExpectation::Challenge {
                sent: Nonce::new(hex::decode(n).context("--nonce is not hex")?)
                    .map_err(|e| anyhow!("--nonce: {e}"))?,
            },
            (None, Some(receipt_time)) => FreshnessExpectation::Epoch {
                receipt_time,
                max_age_secs: self.max_age_secs,
                max_future_secs: 60,
            },
            _ => bail!("give exactly one of --nonce (challenge) or --receipt-time (epoch)"),
        };
        let anchors = self.anchors.policy()?;
        let now = unix_now()?;
        let policy = AppraisalPolicy {
            expected_binding: &binding,
            freshness,
            reference: &reference,
            anchors: &anchors,
            now,
        };
        let (Some(jwks), Some(attestation)) = (&self.jwks, &self.federation_key_attestation) else {
            let appraisal = appraise(&evidence, &policy).map_err(standalone_refusal)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&appraisal.to_ear(env!("CARGO_PKG_VERSION"), now))?
            );
            return match appraisal.tier() {
                Tier::Attested => Ok(()),
                other => bail!("node platform is not attested: {}", other.ear_status()),
            };
        };
        let jwks: serde_json::Value = read_json(jwks)?;
        let attestation: FederationKeyAttestation = read_json(attestation)?;
        let (appraisal, keys) = appraise_federation_keys(&evidence, &policy, &jwks, &attestation)
            .map_err(|r| match r {
            KeyRefusal::Evidence(e) => standalone_refusal(e),
            other => anyhow!("federation key custody refused: {other}"),
        })?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ear": appraisal.to_ear(env!("CARGO_PKG_VERSION"), now),
                "federation_keys": keys,
            }))?
        );
        // Both halves must pass: a TPM-bound key on a boot nobody vouched for
        // is bound to nothing a relying party trusts, and an attested boot
        // whose key is a file proves nothing about the key.
        if appraisal.tier() != &Tier::Attested {
            bail!(
                "node platform is not attested: {}",
                appraisal.tier().ear_status()
            );
        }
        let unbound: Vec<String> = keys
            .iter()
            .filter(|k| !k.is_tpm_bound())
            .map(|k| serde_json::to_string(k).unwrap_or_else(|e| e.to_string()))
            .collect();
        if !unbound.is_empty() {
            bail!(
                "federation keys not TPM-bound to this boot: {}",
                unbound.join(", ")
            );
        }
        Ok(())
    }
}

/// A refusal from `verify-node-evidence`, with what to do about it when the
/// fix is a flag: standalone, the federation set is the caller's to state,
/// because no signed receipt names the document (#3277).
fn standalone_refusal(r: Refusal) -> anyhow::Error {
    let hint = match &r {
        Refusal::FederationMismatch {
            bound: Federation::JwksSha256(d),
            ..
        } => format!(
            ". Pass --federation {} after checking that it is the SHA-256 of the operator's \
             published JWKS document, or verify through `verify-execution --node-evidence`, \
             which takes the federation set from the evidence document the signed receipt names",
            hex::encode(d)
        ),
        Refusal::FederationMismatch {
            bound: Federation::NotFederated,
            ..
        } => ". Pass --federation not-federated (the default)".into(),
        _ => String::new(),
    };
    anyhow!("node evidence refused: {r}{hint}")
}

/// The platform half of `verify-execution`.
#[derive(clap::Args, Debug)]
pub(crate) struct PlatformArgs {
    /// The node evidence document the receipt names (by SHA-256).
    #[arg(long, requires = "node_reference")]
    node_evidence: Option<PathBuf>,
    /// The reference manifest to appraise that evidence against.
    #[arg(long)]
    node_reference: Option<PathBuf>,
    /// The oldest the node's epoch evidence may be at the receipt's time.
    #[arg(long, default_value_t = 900)]
    max_evidence_age_secs: u64,
    /// Fail unless the platform tier is `Attested`.
    #[arg(long)]
    require_attested: bool,
    #[command(flatten)]
    anchors: AnchorArgs,
}

/// The composite verdict's platform half: a JSON report and whether it is
/// `Attested`. The receipt's own statement is never upgraded: a receipt that
/// says `Unattested` stays so whatever evidence is supplied beside it.
pub(crate) fn platform(
    args: &PlatformArgs,
    claim: &ExecutionClaim,
    receipt_time_micros: u64,
    verifying_key: &[u8; 32],
) -> Result<(serde_json::Value, bool)> {
    let report = match &claim.node_platform {
        NodePlatform::Unattested { reason } => (
            serde_json::json!({ "tier": "unattested", "reason": reason, "from": "receipt" }),
            false,
        ),
        NodePlatform::Evidence {
            evidence_sha256,
            epoch,
        } => match (&args.node_evidence, &args.node_reference) {
            (Some(evidence_path), Some(reference_path)) => {
                let bytes = std::fs::read(evidence_path)
                    .with_context(|| format!("reading {}", evidence_path.display()))?;
                if hex::encode(evidence_digest(&bytes)) != *evidence_sha256 {
                    bail!(
                        "{} is not the evidence document the receipt names ({evidence_sha256})",
                        evidence_path.display()
                    );
                }
                let evidence: NodeEvidence = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", evidence_path.display()))?;
                match &evidence.freshness {
                    Freshness::Epoch { counter, .. } if counter == epoch => {}
                    _ => bail!("the evidence document is not epoch {epoch}, as the receipt says"),
                }
                let reference: ReferenceManifest = read_json(reference_path)?;
                // Both halves of the binding are derived from the receipt, never
                // restated by the caller (ADR 0007 G): the executor key is the
                // receipt's verifying key, and the federation set is the one the
                // evidence document commits to, which is the receipt's fact too
                // because the signed receipt names that document's SHA-256
                // (checked above). The TPM's quote then commits to the same
                // binding (`QualifyingData`), so no `--federation` flag exists on
                // this path (#3277).
                let binding = KeyBinding {
                    executor_key: ExecutorKey::Ed25519(*verifying_key),
                    federation: evidence.binding.federation.clone(),
                };
                let receipt_time = i64::try_from(receipt_time_micros / 1_000_000)?;
                let anchors = args.anchors.policy()?;
                let now = unix_now()?;
                match appraise(
                    &evidence,
                    &AppraisalPolicy {
                        expected_binding: &binding,
                        freshness: FreshnessExpectation::Epoch {
                            receipt_time,
                            max_age_secs: args.max_evidence_age_secs,
                            max_future_secs: 60,
                        },
                        reference: &reference,
                        anchors: &anchors,
                        now,
                    },
                ) {
                    Ok(a) => appraised(&a, now),
                    Err(refusal) => (
                        serde_json::json!({ "tier": "refused", "refusal": refusal }),
                        false,
                    ),
                }
            }
            _ => (
                serde_json::json!({
                    "not_appraised": format!(
                        "the receipt names node evidence {evidence_sha256} (epoch {epoch}); \
                         pass --node-evidence and --node-reference to appraise it"
                    )
                }),
                false,
            ),
        },
    };
    if args.require_attested && !report.1 {
        bail!(
            "--require-attested: the node platform is not attested: {}",
            report.0
        );
    }
    Ok(report)
}

fn appraised(a: &Appraisal, now: i64) -> (serde_json::Value, bool) {
    (
        serde_json::json!({
            "tier": a.tier(),
            "ear": a.to_ear(env!("CARGO_PKG_VERSION"), now),
        }),
        a.tier() == &Tier::Attested,
    )
}
