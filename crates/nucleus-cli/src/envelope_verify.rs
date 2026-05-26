//! `nucleus envelope-verify` — re-validate a [`Bundle`] against a
//! caller-supplied trust anchor.
//!
//! One of `--trust-jwks <path>` or `--self-check` MUST be passed. The
//! former is the production path: the verifier loads a JWKS they obtained
//! out-of-band and the bundle's embedded JWKS is *ignored* (CRIT-1 in
//! the audit: a producer-controlled embedded JWKS is not a trust anchor).
//! The latter is an explicit opt-in to validating against the embedded
//! JWKS, useful for offline internal-consistency audits — the success
//! message clearly states this is NOT a provenance claim.
//!
//! [`Bundle`]: nucleus_envelope::Bundle

use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::io::Read;
use std::path::PathBuf;

use nucleus_envelope::{verify_bundle, Bundle, TrustAnchor, VerificationReport};
use nucleus_lineage::Jwks;

#[derive(Args, Debug)]
pub struct EnvelopeVerifyArgs {
    /// Path to the bundle JSON file. Use `-` for stdin.
    pub bundle: String,

    /// Path to a JWKS obtained out-of-band (file, OIDC discovery, signed
    /// operator bundle). Edges are verified against THIS JWKS, not the
    /// one embedded in the bundle. This is the production path.
    /// Mutually exclusive with `--self-check`.
    #[arg(long)]
    pub trust_jwks: Option<PathBuf>,

    /// Validate against the JWKS embedded in the bundle. **Not a
    /// provenance claim** — only proves the bundle is internally
    /// consistent. The success output clearly flags this mode.
    /// Mutually exclusive with `--trust-jwks`.
    #[arg(long, conflicts_with = "trust_jwks")]
    pub self_check: bool,

    /// Accept envelopes with zero edges. Off by default — an empty
    /// envelope authenticates nothing and is forgeable against any pod.
    #[arg(long)]
    pub allow_empty: bool,

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

    let anchor = match (&args.trust_jwks, args.self_check) {
        (Some(path), false) => {
            let jwks_bytes = std::fs::read(path)
                .with_context(|| format!("reading trust JWKS from {}", path.display()))?;
            let jwks = Jwks::parse(&jwks_bytes)
                .with_context(|| format!("parsing JWKS at {}", path.display()))?;
            TrustAnchor::from_jwks(jwks)
        }
        (None, true) => TrustAnchor::self_check_only(),
        (None, false) => {
            return Err(anyhow!(
                "must specify --trust-jwks <path> (production) or --self-check (audit-only); \
                 see `nucleus envelope-verify --help` and crate docs on trust model"
            ))
        }
        (Some(_), true) => unreachable!("clap conflicts_with"),
    };
    let anchor = if args.allow_empty {
        anchor.allow_empty()
    } else {
        anchor
    };

    let report =
        verify_bundle(&bundle, &anchor).map_err(|e| anyhow!("verification failed: {e}"))?;

    if args.json {
        emit_json_report(&bundle, &report)?;
    } else {
        emit_human_report(&bundle, &report);
        if args.show_payload {
            println!("---");
            println!("{}", serde_json::to_string_pretty(&bundle.payload)?);
        }
    }
    Ok(())
}

fn emit_human_report(bundle: &Bundle, report: &VerificationReport) {
    let mode = if report.trust_mode_self_check_only {
        "self-check (internal consistency only — NOT a provenance claim)"
    } else {
        "trusted JWKS"
    };
    println!(
        "ok ({mode}): session_root={} trust_domain={} edges={} issuers={} checkpoints={} \
         head_edge_hash={}",
        bundle.envelope.session_root,
        report.trust_domain,
        report.edge_count,
        report.kids.len(),
        report.checkpoint_count,
        if report.head_edge_hash_hex.is_empty() {
            "(empty envelope)"
        } else {
            &report.head_edge_hash_hex
        },
    );
    if !report.kids.is_empty() {
        println!("kids:");
        for kid in &report.kids {
            println!("  - {kid}");
        }
    }
}

fn emit_json_report(bundle: &Bundle, report: &VerificationReport) -> Result<()> {
    let out = serde_json::json!({
        "ok": true,
        "trust_mode": if report.trust_mode_self_check_only {
            "self_check_only"
        } else {
            "out_of_band"
        },
        "session_root": bundle.envelope.session_root.to_string(),
        "trust_domain": report.trust_domain,
        "edge_count": report.edge_count,
        "kids": report.kids,
        "checkpoint_count": report.checkpoint_count,
        "head_edge_hash_hex": report.head_edge_hash_hex,
        "schema_version": bundle.envelope.meta.schema_version,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
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
