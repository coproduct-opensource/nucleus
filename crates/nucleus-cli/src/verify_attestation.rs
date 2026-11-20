//! Relying-party verification of an attested SVID (North Star C9, ADR 0016).
//!
//! `nucleus verify-attestation` is the *outside* verifier: given the PEM certificate
//! chain a pod serves over `FETCH_SVID`, the node's trust bundle and the
//! measurements an operator expects, it decides whether to trust the pod's launch.
//!
//! Teeth:
//! * **issuer** — the leaf must chain to `--trust-bundle`; a launch claim on a
//!   certificate the node CA did not sign is a forgery (ADR 0016 S2).
//! * **fail-closed on absent** — `--require-attestation` (default) makes a served
//!   cert that carries no attestation extension an error, not a vacuous pass.
//! * **drift** — a measurement outside the `--expect-*` allow-lists is an error.
//! * **the root, stated** (ADR 0016 S8) — with `--launch-quote`, the TPM quote
//!   the leaf names (OID `.1.7`, served at `GET /v1/evidence/<sha256>`) is
//!   appraised by [`VerifiedLaunch::verify_tpm`] against the node reference and
//!   AK anchors given here. The verdict names the root: `TPM` only when the
//!   quote appraised `Attested` over this leaf's key and measurement, and
//!   `node CA only` otherwise, with the reason. A launch whose TPM root was not
//!   checked is never reported as TPM-rooted, and `--require-tpm-root` makes it
//!   an error.
//!
//! # Trust boundary (read this)
//!
//! The measurement is the node's own SHA-256 of the kernel, rootfs and config it
//! launched, signed by the node CA. Rooted in the CA alone, the guarantee is:
//! *IF you trust this node's CA key, THEN the pod ran these measurements.* Rooted
//! in the TPM, a CA key taken from a running node no longer forges a launch: the
//! forger also needs a quote over the forged key from an AK the anchors accept,
//! on a boot the reference accepts. The AK anchor is only as strong as the pin
//! or root passed here (`--operator-pin`, `--allow-software-tpm-pin`,
//! `--ak-trust-root`).

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use nucleus_identity::attestation::format_hash;
use nucleus_identity::{
    Appraised, AttestationRequirements, Claim, LaunchQuotePolicy, LaunchRoot, SelfMeasuredBackend,
    SvidAttestationBackend, TrustBundle, VerifiedAttestation, VerifiedLaunch,
    extract_launch_quote_digest,
};
use nucleus_node_evidence::{
    AnchorPolicy, ExecutorKey, Federation, KeyBinding, OperatorPin, ReferenceManifest,
};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyAttestationArgs {
    /// Path to the served SVID certificate chain (PEM).
    #[arg(long)]
    cert: PathBuf,

    /// Trust bundle (PEM roots) of the node whose CA issued the SVID. Required: a
    /// launch claim is worth only the signature over it, and a leaf that does not
    /// chain to this bundle is refused whatever it carries.
    #[arg(long = "trust-bundle")]
    trust_bundle: PathBuf,

    /// Expected kernel measurement (hex SHA-256). Repeatable; any listed value passes.
    #[arg(long = "expect-kernel")]
    expect_kernel: Vec<String>,

    /// Expected rootfs measurement (hex SHA-256). Repeatable; any listed value passes.
    #[arg(long = "expect-rootfs")]
    expect_rootfs: Vec<String>,

    /// Expected config measurement (hex SHA-256). Repeatable; any listed value passes.
    #[arg(long = "expect-config")]
    expect_config: Vec<String>,

    /// Fail closed if the served cert carries no attestation extension (default on).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    require_attestation: bool,

    #[command(flatten)]
    tpm: TpmRootArgs,
}

/// The TPM root of a launch (ADR 0016 D2): the quote document, and every input
/// the relying party appraises it with. None of these come from the quote.
#[derive(Args)]
struct TpmRootArgs {
    /// The launch quote document the leaf names (OID `.1.7`), as the node's
    /// public evidence listener serves it: `GET /v1/evidence/<sha256>`. The
    /// document is content-addressed, so a copy from anywhere is as good.
    #[arg(long = "launch-quote", requires_all = ["node_reference", "executor_ed25519"])]
    launch_quote: Option<PathBuf>,

    /// The reference manifest (JSON) the node's boot must match.
    #[arg(long = "node-reference", requires = "launch_quote")]
    node_reference: Option<PathBuf>,

    /// The node's executor Ed25519 public key (hex), as the operator publishes
    /// it: every quote the node takes is bound to it.
    #[arg(long = "executor-ed25519", requires = "launch_quote")]
    executor_ed25519: Option<String>,

    /// The federation key set the node's quotes bind: `not-federated`, or the
    /// SHA-256 (hex) of the operator's published JWKS document.
    #[arg(long, default_value = "not-federated")]
    federation: String,

    /// A root certificate (PEM or DER) an AK certificate chain may end at.
    #[arg(long = "ak-trust-root")]
    ak_trust_root: Vec<PathBuf>,

    /// `SOURCE=SPKI_SHA256`: accept the operator's word that the AK with this
    /// fingerprint, fetched from SOURCE, is a TPM's.
    #[arg(long = "operator-pin")]
    operator_pin: Vec<String>,

    /// `SOURCE=SPKI_SHA256`: accept the AK with this fingerprint as a SOFTWARE
    /// TPM's (swtpm). No hardware holds that key, and the result says so.
    #[arg(long = "allow-software-tpm-pin")]
    allow_software_tpm_pin: Vec<String>,

    /// Fail unless the launch is rooted in the node's TPM. Without it, a launch
    /// rooted in the node CA alone verifies, and the verdict says so by name.
    #[arg(long = "require-tpm-root")]
    require_tpm_root: bool,
}

/// The relying party's inputs to a launch-quote appraisal, read from files.
struct QuoteInputs {
    document: Vec<u8>,
    binding: KeyBinding,
    reference: ReferenceManifest,
    anchors: AnchorPolicy,
}

impl TpmRootArgs {
    /// The appraisal inputs, when a quote was supplied.
    fn inputs(&self) -> Result<Option<QuoteInputs>> {
        let Some(quote) = &self.launch_quote else {
            return Ok(None);
        };
        let (Some(reference), Some(executor)) = (&self.node_reference, &self.executor_ed25519)
        else {
            bail!("--launch-quote needs --node-reference and --executor-ed25519");
        };
        let document =
            std::fs::read(quote).with_context(|| format!("reading {}", quote.display()))?;
        let reference_bytes =
            std::fs::read(reference).with_context(|| format!("reading {}", reference.display()))?;
        let reference: ReferenceManifest = serde_json::from_slice(&reference_bytes)
            .with_context(|| format!("parsing {}", reference.display()))?;
        let federation = match self.federation.as_str() {
            "not-federated" => Federation::NotFederated,
            hex => Federation::JwksSha256(parse_hash(hex).context("--federation")?),
        };
        let binding = KeyBinding {
            executor_key: ExecutorKey::Ed25519(parse_hash(executor).context("--executor-ed25519")?),
            federation,
        };
        let mut trust_roots = Vec::new();
        for path in &self.ak_trust_root {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            trust_roots.push(der_of(&bytes)?);
        }
        let anchors = AnchorPolicy {
            trust_roots,
            operator_pins: pins("--operator-pin", &self.operator_pin)?,
            software_tpm_pins: pins("--allow-software-tpm-pin", &self.allow_software_tpm_pin)?,
        };
        Ok(Some(QuoteInputs {
            document,
            binding,
            reference,
            anchors,
        }))
    }
}

/// Parse `SOURCE=SPKI_SHA256` pins given under `flag`: the shape
/// `nucleus-audit verify-node-evidence` takes, so one pin works for both.
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

/// The DER bytes of a certificate given as PEM or DER.
fn der_of(bytes: &[u8]) -> Result<Vec<u8>> {
    match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN") => Ok(pem::parse(text)
            .context("AK trust root is not PEM")?
            .contents()
            .to_vec()),
        _ => Ok(bytes.to_vec()),
    }
}

fn parse_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim())
        .with_context(|| format!("invalid hex measurement '{hex_str}'"))?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "measurement must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })
}

/// What a verified launch is rooted in, as this command reports it. Closed, and
/// the CA-only arm says why: a root nobody checked is never the TPM (ADR 0007 A-1).
#[derive(Debug)]
enum Root {
    /// The launch quote the leaf names appraised `Attested` over its key and
    /// measurement.
    Tpm(Box<Appraised>),
    /// The node CA's signature alone vouches for the measurement.
    NodeCaOnly(NotTpm),
}

/// Why a launch is reported as rooted in the node CA alone.
#[derive(Debug, PartialEq, Eq)]
enum NotTpm {
    /// The leaf names no launch quote (OID `.1.7`): the node did not quote it.
    NoQuoteNamed,
    /// The leaf names this quote, and no `--launch-quote` was given, so the TPM
    /// root was not checked.
    QuoteNotChecked { named: [u8; 32] },
}

/// The verdict on a served SVID.
#[derive(Debug)]
enum Verdict {
    /// A measured launch on a leaf the bundle issued, within the allow-lists.
    Launch {
        attestation: Box<VerifiedAttestation>,
        root: Root,
    },
    /// The leaf carries no launch claim, and none was required.
    NoLaunch,
}

pub fn execute(args: VerifyAttestationArgs) -> Result<()> {
    match verify(&args)? {
        Verdict::Launch { attestation, root } => {
            let measurement = attestation
                .launch()
                .map(|l| l.to_hex_summary())
                .unwrap_or_default();
            println!(
                "OK: attested SVID verified via '{}' (assurance L{}) — {}",
                attestation.backend(),
                attestation.assurance().as_u8(),
                measurement
            );
            println!("  proves:     {}", fmt_claims(attestation.proven_claims()));
            println!(
                "  not proven: {}",
                fmt_claims(attestation.unproven_claims())
            );
            print_root(&root);
            Ok(())
        }
        Verdict::NoLaunch => {
            println!("OK: served SVID carries no attestation and none was required.");
            Ok(())
        }
    }
}

fn print_root(root: &Root) {
    match root {
        Root::Tpm(appraised) => {
            println!(
                "  root:       TPM — launch quote {} appraised Attested over this leaf's key \
                 and measurement (AK anchor {:?})",
                format_hash(appraised.quote_sha256()),
                appraised.appraisal().anchor()
            );
            let not_checked = appraised.appraisal().not_checked();
            if !not_checked.is_empty() {
                let names: Vec<&str> = not_checked.keys().copied().collect();
                println!("  boot not checked: {}", names.join(", "));
            }
        }
        Root::NodeCaOnly(NotTpm::NoQuoteNamed) => {
            println!("  root:       node CA only — TPM root NOT verified");
            println!(
                "  why:        the leaf names no launch quote (OID .1.7); trust is conditional \
                 on the node CA's key"
            );
        }
        Root::NodeCaOnly(NotTpm::QuoteNotChecked { named }) => {
            println!("  root:       node CA only — TPM root NOT verified");
            println!(
                "  why:        the leaf names launch quote {h}, which was not checked; fetch \
                 GET /v1/evidence/{h} from the node's public evidence listener and pass \
                 --launch-quote",
                h = format_hash(named)
            );
        }
    }
}

fn verify(args: &VerifyAttestationArgs) -> Result<Verdict> {
    let chain = std::fs::read_to_string(&args.cert)
        .with_context(|| format!("reading cert chain {}", args.cert.display()))?;

    let bundle_pem = std::fs::read_to_string(&args.trust_bundle)
        .with_context(|| format!("reading trust bundle {}", args.trust_bundle.display()))?;
    let trust_bundle = TrustBundle::from_pem(&bundle_pem)
        .with_context(|| format!("parsing trust bundle {}", args.trust_bundle.display()))?;

    let mut req = AttestationRequirements::any();
    for h in &args.expect_kernel {
        req = req.allow_kernel(parse_hash(h)?);
    }
    for h in &args.expect_rootfs {
        req = req.allow_rootfs(parse_hash(h)?);
    }
    for h in &args.expect_config {
        req = req.allow_config(parse_hash(h)?);
    }
    let quote = args.tpm.inputs()?;

    // The chain, the launch claim and the allow-lists, through the backend seam.
    let backend = SelfMeasuredBackend::new(trust_bundle.clone());
    let attestation = match backend.verify_svid(&chain, &req, args.require_attestation) {
        Ok(Some(va)) => va,
        Ok(None) if quote.is_some() || args.tpm.require_tpm_root => bail!(
            "attestation verification FAILED: the served SVID carries no launch claim, so no \
             launch quote can root it"
        ),
        Ok(None) => return Ok(Verdict::NoLaunch),
        Err(e) => bail!("attestation verification FAILED: {e}"),
    };

    let leaf = pem::parse(&chain).context("the served chain's first block is not PEM")?;
    let leaf = leaf.contents();
    let root = match quote {
        Some(q) => {
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            )?;
            let policy = LaunchQuotePolicy {
                expected_binding: &q.binding,
                reference: &q.reference,
                anchors: &q.anchors,
                now,
            };
            let verified = VerifiedLaunch::verify_tpm(leaf, &trust_bundle, &q.document, &policy)
                .map_err(|e| anyhow!("attestation verification FAILED: {e}"))?;
            match verified.root() {
                LaunchRoot::Tpm(appraised) => Root::Tpm(appraised.clone()),
                LaunchRoot::NodeCa => bail!(
                    "attestation verification FAILED: the TPM verifier returned a CA-only root"
                ),
            }
        }
        None => match extract_launch_quote_digest(leaf)
            .map_err(|e| anyhow!("attestation verification FAILED: {e}"))?
        {
            Some(named) => Root::NodeCaOnly(NotTpm::QuoteNotChecked { named }),
            None => Root::NodeCaOnly(NotTpm::NoQuoteNamed),
        },
    };
    if let (true, Root::NodeCaOnly(why)) = (args.tpm.require_tpm_root, &root) {
        bail!(
            "attestation verification FAILED: --require-tpm-root, and the launch is rooted in \
             the node CA only ({why:?})"
        );
    }
    Ok(Verdict::Launch {
        attestation: Box::new(attestation),
        root,
    })
}

/// Render a closed claim set as a readable list (or `(none)`).
fn fmt_claims(claims: &BTreeSet<Claim>) -> String {
    if claims.is_empty() {
        return "(none)".to_string();
    }
    claims
        .iter()
        .map(|c| format!("{c:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
#[path = "verify_attestation_tests.rs"]
mod tests;
