//! `nucleus envelope-export` — re-emit a verified [`Bundle`] as a standard
//! attestation: an in-toto / SLSA DSSE envelope or a Sigstore Bundle.
//!
//! The bundle is verified against `--trust-jwks` (a JWKS obtained
//! out-of-band, exactly as `nucleus envelope-verify --trust-jwks` uses it)
//! BEFORE anything is signed. A bundle that fails is not attested: the
//! signature on the export is the exporter vouching for the record, and an
//! unverified record is not one to vouch for. There is deliberately no
//! `--self-check` here — a bundle's own embedded JWKS is producer-controlled.
//!
//! The DSSE envelope is signed by `--signing-key` (PKCS#8 PEM, Ed25519). Its
//! public half is what a consumer hands `cosign verify-blob-attestation
//! --key`; the statement names every produced artifact by digest, so
//! `cosign … <artifact-file>` checks the file against the attestation.
//!
//! [`Bundle`]: nucleus_envelope::Bundle

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use clap::builder::{PossibleValuesParser, TypedValueParser};

use nucleus_envelope::{Bundle, ExportFormat, verify_bundle};
use nucleus_lineage::Pkcs8FileSigner;

use crate::envelope_verify::{read_bundle_bytes, trust_anchor_from_jwks_file};

fn format_parser() -> impl TypedValueParser<Value = ExportFormat> {
    PossibleValuesParser::new(ExportFormat::ALL.map(ExportFormat::name))
        .try_map(|name| name.parse::<ExportFormat>())
}

#[derive(Args, Debug)]
pub struct EnvelopeExportArgs {
    /// Path to the bundle JSON file. Use `-` for stdin.
    pub bundle: String,

    /// Attestation format to emit.
    #[arg(long, value_parser = format_parser())]
    pub format: ExportFormat,

    /// PKCS#8 PEM Ed25519 private key that signs the DSSE envelope.
    #[arg(long)]
    pub signing_key: PathBuf,

    /// JWKS obtained out-of-band. The bundle must verify against it before
    /// it is attested; the bundle's embedded JWKS is ignored.
    #[arg(long)]
    pub trust_jwks: PathBuf,

    /// Also require the bundle's payload binding to verify against the
    /// trust JWKS.
    #[arg(long)]
    pub require_binding: bool,

    /// Where to write the attestation. `-` (the default) writes to stdout.
    #[arg(long, default_value = "-")]
    pub out: String,
}

pub fn execute(args: EnvelopeExportArgs) -> Result<()> {
    let bytes = read_bundle_bytes(&args.bundle)?;
    let bundle: Bundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing bundle JSON from {}", args.bundle))?;

    let mut anchor = trust_anchor_from_jwks_file(&args.trust_jwks)?;
    if args.require_binding {
        anchor = anchor.require_payload_binding();
    }
    verify_bundle(&bundle, &anchor)
        .map_err(|e| anyhow!("refusing to attest a bundle that does not verify: {e}"))?;

    let signer = Pkcs8FileSigner::from_pkcs8_pem_file(&args.signing_key)
        .with_context(|| format!("loading signing key {}", args.signing_key.display()))?;
    let attestation = bundle
        .export_attestation(args.format, &signer)
        .with_context(|| format!("exporting as {}", args.format.name()))?;

    let mut json = serde_json::to_vec_pretty(&attestation).context("serializing attestation")?;
    json.push(b'\n');
    if args.out == "-" {
        std::io::stdout()
            .lock()
            .write_all(&json)
            .context("writing attestation to stdout")?;
    } else {
        std::fs::write(&args.out, &json)
            .with_context(|| format!("writing attestation to {}", args.out))?;
    }
    Ok(())
}
