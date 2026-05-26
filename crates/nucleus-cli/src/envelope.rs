//! `nucleus envelope` — extract a portable provenance [`Bundle`] from an
//! existing JSONL lineage log.
//!
//! Reads the log, filters edges under the supplied session-root SPIFFE id,
//! attaches the issuer JWKS plus any checkpoints in `--checkpoint-dir`,
//! pairs the lineage with a `--payload` JSON, and writes the bundle to
//! `--out` (or stdout).
//!
//! [`Bundle`]: nucleus_envelope::Bundle

use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::io::{Read, Write};
use std::path::PathBuf;

use nucleus_envelope::BundleBuilder;
use nucleus_lineage::{read_checkpoints, CallSpiffeId, JsonlSink, Jwks, SignedTreeHead};

#[derive(Args, Debug)]
pub struct EnvelopeArgs {
    /// Session root — the pod SPIFFE id whose lineage you want bundled.
    /// Every edge in the resulting bundle is structurally derived from
    /// this id.
    pub session_root: String,

    /// JSONL lineage log emitted by nucleus-tool-proxy.
    #[arg(long, default_value = "./nucleus-lineage.jsonl")]
    pub log: PathBuf,

    /// JSON Web Key Set with verifying keys for the issuers that signed
    /// edges in this log. Required — without it, the bundle is not
    /// verifiable offline.
    #[arg(long)]
    pub jwks: PathBuf,

    /// Directory containing `sth-*.json` checkpoint files. When present
    /// (and non-empty), the matching signed tree heads are attached to
    /// the envelope as time attestations. Per v1 docs, STH inclusion
    /// proofs binding session edges to a signed root land in v2.
    #[arg(long)]
    pub checkpoint_dir: Option<PathBuf>,

    /// File containing the JSON payload to wrap. Mutually exclusive with
    /// `--payload-stdin`. The payload's structure is opaque to nucleus —
    /// typically `{"stats": ..., "summary": ...}`.
    #[arg(long)]
    pub payload: Option<PathBuf>,

    /// Read the payload JSON from stdin.
    #[arg(long, conflicts_with = "payload")]
    pub payload_stdin: bool,

    /// Where to write the bundle. `-` (or unset) writes to stdout.
    #[arg(long, default_value = "-")]
    pub out: String,

    /// Build a bundle even if the session has zero edges. Off by default
    /// because empty envelopes are almost always programmer error.
    #[arg(long)]
    pub allow_empty: bool,
}

pub fn execute(args: EnvelopeArgs) -> Result<()> {
    let session_root: CallSpiffeId = args
        .session_root
        .parse()
        .with_context(|| format!("invalid session-root SPIFFE id: {}", args.session_root))?;

    let sink = JsonlSink::open(&args.log)
        .with_context(|| format!("opening lineage log {}", args.log.display()))?;

    let jwks_bytes = std::fs::read(&args.jwks)
        .with_context(|| format!("reading JWKS file {}", args.jwks.display()))?;
    let jwks: Jwks = Jwks::parse(&jwks_bytes)
        .with_context(|| format!("parsing JWKS at {}", args.jwks.display()))?;

    let checkpoints: Vec<SignedTreeHead> = match &args.checkpoint_dir {
        Some(dir) => read_checkpoints(dir)
            .with_context(|| format!("reading checkpoints from {}", dir.display()))?,
        None => Vec::new(),
    };

    let payload = read_payload(&args)?;

    let mut builder = BundleBuilder::new(session_root.clone())
        .payload(payload)
        .sink(&sink)
        .jwks(jwks)
        .checkpoints(checkpoints);
    if args.allow_empty {
        builder = builder.allow_empty();
    }

    let bundle = builder
        .build()
        .with_context(|| format!("assembling bundle for {}", session_root))?;

    write_bundle(&bundle, &args.out)?;
    Ok(())
}

fn read_payload(args: &EnvelopeArgs) -> Result<serde_json::Value> {
    match (&args.payload, args.payload_stdin) {
        (Some(path), false) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading payload from {}", path.display()))?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing payload JSON in {}", path.display()))
        }
        (None, true) => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading payload from stdin")?;
            serde_json::from_slice(&buf).context("parsing payload JSON from stdin")
        }
        (None, false) => Err(anyhow!(
            "no payload supplied; pass --payload <file> or --payload-stdin"
        )),
        (Some(_), true) => unreachable!("clap enforces conflicts_with"),
    }
}

fn write_bundle(bundle: &nucleus_envelope::Bundle, dest: &str) -> Result<()> {
    let json = serde_json::to_vec_pretty(bundle).context("serializing bundle")?;
    if dest == "-" {
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        h.write_all(&json).context("writing bundle to stdout")?;
        h.write_all(b"\n").context("writing trailing newline")?;
    } else {
        std::fs::write(dest, &json).with_context(|| format!("writing bundle to {}", dest))?;
    }
    Ok(())
}
