//! `nucleus lineage-verify-chain` — validate the Merkle integrity of a
//! lineage log against published [`SignedTreeHead`] checkpoints.
//!
//! Steps:
//! 1. Load every edge from the JSONL log (oldest first).
//! 2. Replay them into a fresh in-memory Merkle tree.
//! 3. Read every `sth-*.json` in the checkpoint directory.
//! 4. For each STH: verify the witness signature, then check that the
//!    Merkle root at that `tree_size` matches `root_hash_hex`.
//!
//! Any mismatch (signature, root, or checkpoint-ahead-of-log) returns
//! non-zero; otherwise prints a one-line summary.

use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::path::PathBuf;

use nucleus_lineage::{read_checkpoints, verify_log, Ed25519Witness, JsonlSink, TreeWitness};

#[derive(Args, Debug)]
pub struct VerifyChainArgs {
    /// Path to the JSONL lineage log.
    #[arg(long, default_value = "./nucleus-lineage.jsonl")]
    pub log: PathBuf,

    /// Directory containing `sth-*.json` checkpoint files.
    #[arg(long, default_value = "./nucleus-lineage-checkpoints")]
    pub checkpoint_dir: PathBuf,

    /// Path to a file containing the witness's 32-byte Ed25519 public
    /// key (hex or base64, auto-detected). Use this to validate STHs
    /// produced by a witness whose key you trust out-of-band.
    #[arg(long)]
    pub witness_pub: PathBuf,
}

pub fn execute(args: VerifyChainArgs) -> Result<()> {
    let pub_bytes = read_witness_pubkey(&args.witness_pub)
        .with_context(|| format!("reading witness pubkey from {}", args.witness_pub.display()))?;
    let witness = Ed25519Witness::verify_only(pub_bytes)
        .context("constructing verify-only witness from public key")?;

    let sink = JsonlSink::open(&args.log)
        .with_context(|| format!("opening lineage log {}", args.log.display()))?;
    let checkpoints = read_checkpoints(&args.checkpoint_dir)
        .with_context(|| format!("reading checkpoints from {}", args.checkpoint_dir.display()))?;

    if checkpoints.is_empty() {
        return Err(anyhow!(
            "no checkpoints found in {}; the log either has no signed STHs yet \
             or the checkpoint-dir is wrong",
            args.checkpoint_dir.display()
        ));
    }

    verify_log(&sink, &checkpoints, &witness).with_context(|| {
        format!(
            "verifying {} edges against {} checkpoints",
            sink_edge_count(&sink).unwrap_or(0),
            checkpoints.len()
        )
    })?;

    println!(
        "ok: {} checkpoints validated against {} edges (kid={})",
        checkpoints.len(),
        sink_edge_count(&sink).unwrap_or(0),
        witness.kid()
    );
    Ok(())
}

fn read_witness_pubkey(path: &std::path::Path) -> Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    // Try hex first (64 chars), then base64 (44-char standard or 43 url-safe).
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

fn sink_edge_count(sink: &JsonlSink) -> Result<usize> {
    use nucleus_lineage::LineageSink;
    Ok(sink.iter()?.len())
}
