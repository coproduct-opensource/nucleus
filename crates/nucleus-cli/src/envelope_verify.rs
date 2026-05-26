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

    /// **v2 trust extension.** Path to a file containing the witness's
    /// 32-byte Ed25519 public key (hex or base64, auto-detected). When
    /// the bundle carries a `merkle_anchor`, this key is REQUIRED — the
    /// verifier rejects bundles whose anchor it can't validate. When
    /// the bundle has no anchor, this flag is ignored.
    #[arg(long)]
    pub witness_pub: Option<PathBuf>,

    /// **v2.1 witness federation.** Path to a file containing an
    /// external witness's Ed25519 public key (hex or base64). Repeat
    /// for each trusted witness. Cosignatures on the STH from witnesses
    /// in this set count toward `--cosignature-threshold`.
    #[arg(long = "trusted-witness", value_name = "PATH")]
    pub trusted_witness: Vec<PathBuf>,

    /// **v2.1 witness federation.** Minimum number of cosignatures from
    /// trusted witnesses required. Default 0 (federation optional).
    #[arg(long, default_value_t = 0)]
    pub cosignature_threshold: usize,

    /// **v2.2 payload binding.** Require the bundle to carry a
    /// [`nucleus_envelope::PayloadBinding`] signed by a key in the
    /// trust JWKS. Without this, bundles without bindings still verify
    /// at chain/anchor level (backwards-compat).
    #[arg(long)]
    pub require_binding: bool,

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
    let anchor = match &args.witness_pub {
        Some(path) => {
            let key = read_witness_pubkey(path)
                .with_context(|| format!("reading witness pubkey from {}", path.display()))?;
            anchor.with_witness_pubkey(key)
        }
        None => anchor,
    };
    // v2.1 federation: add each trusted witness + threshold.
    let mut anchor = anchor;
    for path in &args.trusted_witness {
        let key = read_witness_pubkey(path)
            .with_context(|| format!("reading trusted-witness pubkey from {}", path.display()))?;
        anchor = anchor.with_trusted_witness(key);
    }
    if args.cosignature_threshold > 0 {
        anchor = anchor.cosignature_threshold(args.cosignature_threshold);
    }
    if args.require_binding {
        anchor = anchor.require_payload_binding();
    }

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
    let merkle = if report.merkle_verified {
        "verified"
    } else if bundle.envelope.merkle_anchor.is_some() {
        "present-but-unchecked"
    } else {
        "absent"
    };
    let binding = if report.payload_binding_verified {
        "verified"
    } else if bundle.binding.is_some() {
        "present-but-unchecked"
    } else {
        "absent"
    };
    println!(
        "ok ({mode}): session_root={} trust_domain={} edges={} issuers={} checkpoints={} \
         head_edge_hash={} merkle={} cosignatures={} binding={}",
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
        merkle,
        report.cosignatures_verified,
        binding,
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
        "merkle_verified": report.merkle_verified,
        "cosignatures_verified": report.cosignatures_verified,
        "matched_witness_pubkeys_hex": report.matched_witness_pubkeys_hex,
        "payload_binding_verified": report.payload_binding_verified,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Parse a witness pubkey file. Auto-detects hex (64 chars) and
/// base64 (44/43 chars) encodings; both decode to exactly 32 bytes.
/// Same shape as `lineage_verify::read_witness_pubkey`.
fn read_witness_pubkey(path: &std::path::Path) -> Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if let Ok(b) = hex::decode(trimmed) {
        if b.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            return Ok(out);
        }
    }
    if let Ok(b) = STANDARD.decode(trimmed) {
        if b.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            return Ok(out);
        }
    }
    Err(anyhow!(
        "witness pubkey file at {} did not parse as a 32-byte hex or base64 Ed25519 public key",
        path.display()
    ))
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
