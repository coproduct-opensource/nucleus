//! `nucleus envelope-verify` — re-validate a [`Bundle`] standalone.
//!
//! Reads a bundle from a file (or stdin), runs
//! [`nucleus_envelope::verify_bundle`], and prints a one-line summary.
//! Exits non-zero on any verification failure; the error message names
//! the failing edge index and the underlying reason.
//!
//! In v1 this validates per-edge signatures + the hash chain + structural
//! membership under the session root. STH signatures and Merkle inclusion
//! proofs land in v2.
//!
//! [`Bundle`]: nucleus_envelope::Bundle

use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::io::Read;
use std::path::PathBuf;

use nucleus_envelope::{verify_bundle, Bundle};

#[derive(Args, Debug)]
pub struct EnvelopeVerifyArgs {
    /// Path to the bundle JSON file. Use `-` for stdin.
    pub bundle: String,

    /// Print the bundle's payload (pretty JSON) on success, in addition
    /// to the one-line summary. Off by default — verifiers often only
    /// want pass/fail.
    #[arg(long)]
    pub show_payload: bool,

    /// Output verification report as JSON instead of a human-readable
    /// summary. Useful for tooling and CI.
    #[arg(long)]
    pub json: bool,
}

pub fn execute(args: EnvelopeVerifyArgs) -> Result<()> {
    let bytes = read_bundle_bytes(&args.bundle)?;
    let bundle: Bundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing bundle JSON from {}", args.bundle))?;

    let report = verify_bundle(&bundle).map_err(|e| anyhow!("verification failed: {e}"))?;

    if args.json {
        let out = serde_json::json!({
            "ok": true,
            "session_root": bundle.envelope.session_root.to_string(),
            "edge_count": report.edge_count,
            "distinct_issuers": report.distinct_issuers,
            "checkpoint_count": report.checkpoint_count,
            "schema_version": bundle.envelope.meta.schema_version,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "ok: session_root={} edges={} issuers={} checkpoints={}",
            bundle.envelope.session_root,
            report.edge_count,
            report.distinct_issuers,
            report.checkpoint_count,
        );
        if args.show_payload {
            println!("---");
            println!("{}", serde_json::to_string_pretty(&bundle.payload)?);
        }
    }
    Ok(())
}

fn read_bundle_bytes(source: &str) -> Result<Vec<u8>> {
    if source == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading bundle from stdin")?;
        Ok(buf)
    } else {
        let path = PathBuf::from(source);
        std::fs::read(&path).with_context(|| format!("reading bundle from {}", path.display()))
    }
}
