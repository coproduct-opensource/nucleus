//! `nucleus bundle` — content-addressed bundle transfer (topology #4).
//!
//! Address a serialized [`Bundle`] by its BLAKE3 root and fetch+verify it
//! from an untrusted peer over iroh-blobs (a bao-verified stream), then run
//! the EXISTING [`nucleus_envelope::verify_bundle`].
//!
//! # Honest scope (read before relying on this)
//!
//! - **No content discovery.** The node ticket is passed OUT-OF-BAND. There
//!   is NO DHT and no content routing — "DHT" is deferred/aspirational.
//! - **No availability guarantee.** A peer can be offline or lie about
//!   having the bytes; only the CORRECTNESS of delivered bytes is
//!   guaranteed (a peer cannot substitute content).
//! - **fetched != trusted.** BLAKE3 byte-integrity is ORTHOGONAL to envelope
//!   provenance: a perfect-hash fetch can STILL FAIL `verify_bundle`. You
//!   MUST pass `--trust-anchor` (an out-of-band JWKS) to get a provenance
//!   claim.
//! - The BLAKE3 hash printed here is a TRANSPORT id — it is **NOT a CID** and
//!   is DISTINCT from the envelope's SHA-256 canonical hash.
//! - Not wired into the WASM/browser verifier.
//!
//! [`Bundle`]: nucleus_envelope::Bundle

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;

use iroh::{endpoint::presets, protocol::Router, Endpoint};
use iroh_blobs::{store::mem::MemStore, ticket::BlobTicket, BlobFormat, BlobsProtocol};

use nucleus_bundle_cas::{fetch_bundle, publish_bundle, BundleHash};
use nucleus_envelope::Bundle;

use crate::envelope_verify::{trust_anchor_from_jwks_file, verify_and_report};

#[derive(Args, Debug)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub command: BundleCommand,
}

#[derive(Subcommand, Debug)]
pub enum BundleCommand {
    /// Publish a bundle: print its BLAKE3 transport hash + a node ticket,
    /// then SERVE the bytes until interrupted (Ctrl-C).
    ///
    /// The node ticket is shared OUT-OF-BAND with the fetcher — there is no
    /// discovery/DHT. The BLAKE3 hash is a transport id (NOT a CID, NOT the
    /// envelope canonical hash).
    Publish(PublishArgs),

    /// Fetch a bundle from a peer by node ticket + BLAKE3 hash over a
    /// bao-verified stream, then verify provenance with an out-of-band
    /// trust anchor. A correct hash does NOT imply a trusted producer.
    Fetch(FetchArgs),
}

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// Path to the bundle JSON file to publish.
    pub bundle: PathBuf,
}

#[derive(Args, Debug)]
pub struct FetchArgs {
    /// Node ticket (printed by `nucleus bundle publish`) identifying the
    /// peer to fetch from. Carries the peer's address out-of-band.
    pub node_ticket: String,

    /// Expected BLAKE3 transport hash (64 hex chars). The bao stream is
    /// rooted at this hash, so the peer cannot substitute other content.
    pub blake3_hash: String,

    /// Out-of-band JWKS trust anchor. REQUIRED for a provenance claim:
    /// byte-integrity alone is not trust. The embedded JWKS is ignored.
    #[arg(long)]
    pub trust_anchor: PathBuf,

    /// Print the verification report as JSON.
    #[arg(long)]
    pub json: bool,

    /// Print the verified bundle's payload on success.
    #[arg(long)]
    pub show_payload: bool,
}

pub async fn execute(args: BundleArgs) -> Result<()> {
    match args.command {
        BundleCommand::Publish(a) => publish(a).await,
        BundleCommand::Fetch(a) => fetch(a).await,
    }
}

async fn bind_endpoint() -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .bind()
        .await
        .map_err(|e| anyhow!("binding iroh endpoint: {e}"))?;
    endpoint.online().await;
    Ok(endpoint)
}

async fn publish(args: PublishArgs) -> Result<()> {
    let bytes = std::fs::read(&args.bundle)
        .with_context(|| format!("reading bundle from {}", args.bundle.display()))?;
    let bundle: Bundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing bundle JSON from {}", args.bundle.display()))?;

    let endpoint = bind_endpoint().await?;
    let store = MemStore::new();
    let hash = publish_bundle(&store, &bundle)
        .await
        .map_err(|e| anyhow!("publishing bundle to local store: {e}"))?;

    let addr = endpoint.addr();
    let ticket = BlobTicket::new(addr, hash.into(), BlobFormat::Raw);

    let blobs = BlobsProtocol::new(&store, None);
    let router = Router::builder(endpoint)
        .accept(iroh_blobs::ALPN, blobs)
        .spawn();

    println!("blake3-hash: {hash}");
    println!("node-ticket: {ticket}");
    eprintln!(
        "NOTE: BLAKE3 hash is a TRANSPORT id (not a CID, not the envelope canonical hash). \
         The fetcher must STILL verify provenance with an out-of-band trust anchor."
    );
    eprintln!("serving bundle; press Ctrl-C to stop...");

    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    router.shutdown().await.ok();
    Ok(())
}

async fn fetch(args: FetchArgs) -> Result<()> {
    let hash = BundleHash::from_str(&args.blake3_hash)
        .map_err(|e| anyhow!("invalid --blake3-hash: {e}"))?;

    let ticket =
        BlobTicket::from_str(&args.node_ticket).map_err(|e| anyhow!("invalid node ticket: {e}"))?;

    // Cross-check: the ticket's hash (if it carries one) must match the
    // explicitly-requested BLAKE3 hash, so a mismatched paste fails loud
    // rather than silently fetching the wrong content.
    let ticket_hash: BundleHash = ticket.hash().into();
    if ticket_hash != hash {
        return Err(anyhow!(
            "node ticket hash {ticket_hash} != requested blake3-hash {hash}; refusing to fetch"
        ));
    }
    let node_addr = ticket.addr().clone();

    let endpoint = bind_endpoint().await?;
    let store = MemStore::new();

    let bundle = fetch_bundle(&endpoint, &store, node_addr, hash)
        .await
        .map_err(|e| anyhow!("fetch failed: {e}"))?;

    // Byte-integrity is now guaranteed by the bao stream. Provenance is a
    // SEPARATE check against the operator-supplied out-of-band trust anchor.
    let anchor = trust_anchor_from_jwks_file(&args.trust_anchor)?;
    verify_and_report(&bundle, &anchor, args.json, args.show_payload)
}
