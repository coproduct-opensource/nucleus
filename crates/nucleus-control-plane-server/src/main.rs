//! `nucleus-control-plane-server` — REST server binary.
//!
//! For the MVP this is a single-process server with an in-memory job
//! registry and a single shared JSONL lineage sink. The `MockJobRunner`
//! is registered under the name `"mock"` so end-to-end smoke testing
//! works without any vendor SDKs.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use nucleus_control_plane::MockJobRunner;
use nucleus_control_plane_server::{build_app, registry::RunnerRegistry, state::build_demo_state};
use nucleus_lineage::{Ed25519Witness, JsonlSink, MerkleConfig, MerkleSink, TreeWitness};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "nucleus-control-plane-server", version)]
struct Cli {
    /// Bind address (host:port).
    #[arg(long, default_value = "127.0.0.1:8080", env = "NUCLEUS_BIND")]
    bind: String,
    /// JSONL lineage log file. Created if missing.
    #[arg(
        long,
        default_value = "./nucleus-lineage.jsonl",
        env = "NUCLEUS_LINEAGE_LOG"
    )]
    log: std::path::PathBuf,
    /// Where to publish the issuer's JWKS so clients can fetch the
    /// out-of-band trust anchor for `nucleus envelope-verify --trust-jwks`.
    #[arg(
        long,
        default_value = "./nucleus-lineage.jwks.json",
        env = "NUCLEUS_JWKS_OUT"
    )]
    jwks_out: std::path::PathBuf,
    /// SPIFFE trust domain authority (DNS-shaped, lowercase).
    #[arg(
        long,
        default_value = "control-plane.nucleus.local",
        env = "NUCLEUS_TRUST_DOMAIN"
    )]
    trust_domain: String,
    /// SPIFFE namespace segment.
    #[arg(long, default_value = "agents", env = "NUCLEUS_NAMESPACE")]
    namespace: String,
    /// SPIFFE service-account segment.
    #[arg(long, default_value = "control-plane", env = "NUCLEUS_SA")]
    service_account: String,
    /// Directory to write signed tree heads (RFC 6962 checkpoints) into.
    /// The Merkle tree commits every emitted edge; checkpoints are the
    /// witness-signed snapshots a verifier can use to anchor inclusion
    /// proofs.
    #[arg(
        long,
        default_value = "./nucleus-lineage-checkpoints",
        env = "NUCLEUS_CHECKPOINT_DIR"
    )]
    checkpoint_dir: std::path::PathBuf,
    /// How often (in emitted edges) to write a signed checkpoint to
    /// `checkpoint_dir`. Smaller = more file writes; larger = longer
    /// gap between time attestations. Production typically picks
    /// 100-10000 per the RFC 6962 v2 §3 guidance.
    #[arg(long, default_value_t = 64, env = "NUCLEUS_CHECKPOINT_INTERVAL")]
    checkpoint_interval: u64,
    /// Where to publish the Merkle witness's 32-byte Ed25519 verifying
    /// key (hex-encoded). Clients fetch this OOB and pass it to
    /// `nucleus envelope-verify --witness-pub`. Set alongside the
    /// JWKS path.
    #[arg(
        long,
        default_value = "./nucleus-witness.pub.hex",
        env = "NUCLEUS_WITNESS_PUB_OUT"
    )]
    witness_pub_out: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Route tracing to stderr so any stdout that the server writes
    // (none today, but the precedent matters) stays clean.
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nucleus=info,info")),
        )
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();

    // The on-disk JSONL log holds raw lineage edges; MerkleSink wraps
    // it to also maintain a Merkle tree + signed tree heads. The same
    // Arc<MerkleSink> serves as both LineageSink (for emission) and
    // MerkleProver (for inclusion-proof generation at bundle build).
    let jsonl = JsonlSink::open(&cli.log)
        .with_context(|| format!("opening lineage log {}", cli.log.display()))?;
    let witness = Ed25519Witness::from_seed(rand_seed());
    let witness_pubkey = witness.verifying_key_bytes();
    let merkle_cfg = MerkleConfig::new(&cli.checkpoint_dir).with_interval(cli.checkpoint_interval);
    let merkle_sink = Arc::new(
        MerkleSink::new(jsonl, witness, merkle_cfg)
            .with_context(|| "opening MerkleSink — check checkpoint_dir permissions")?,
    );

    // Register the mock driver. Real drivers (claude-code, openhands)
    // register themselves from downstream crates that depend on this
    // one — keeping nucleus vendor-neutral.
    let runners = RunnerRegistry::new().register("mock", Box::new(MockJobRunner));

    // Build the basic state via the demo factory, then plug in the
    // Merkle-aware sink + prover.
    let mut state = build_demo_state(
        runners,
        merkle_sink.clone(),
        cli.trust_domain.clone(),
        cli.namespace.clone(),
        cli.service_account.clone(),
    )?;
    state.merkle_prover = Some(merkle_sink.clone());
    state.witness_pubkey = Some(witness_pubkey);

    // Publish the witness pubkey (hex) so clients can pass it to
    // `nucleus envelope-verify --witness-pub`.
    let witness_hex = hex::encode(witness_pubkey);
    std::fs::write(&cli.witness_pub_out, &witness_hex).with_context(|| {
        format!(
            "writing witness pubkey to {}",
            cli.witness_pub_out.display()
        )
    })?;
    tracing::info!(
        "published witness pubkey ({} hex chars, kid={}) → {}",
        witness_hex.len(),
        merkle_sink.witness().kid(),
        cli.witness_pub_out.display()
    );

    // Publish the issuer's JWKS so clients have an out-of-band trust
    // anchor file they can pass to `nucleus envelope-verify --trust-jwks`.
    // In real deployments this would be served from a hardened endpoint;
    // for the MVP we write it next to the log.
    let jwks_bytes = serde_json::to_vec_pretty(&state.issuer.publish_jwks())?;
    std::fs::write(&cli.jwks_out, &jwks_bytes)
        .with_context(|| format!("writing JWKS to {}", cli.jwks_out.display()))?;
    tracing::info!(
        "published issuer JWKS to {} ({} bytes)",
        cli.jwks_out.display(),
        jwks_bytes.len()
    );

    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!("nucleus-control-plane-server listening on {}", cli.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM (k8s/Fly rolling deploys).
/// `axum::serve` uses this to stop accepting new connections and let
/// in-flight ones finish.
/// Generate a 32-byte seed from the OS RNG for the in-process Ed25519
/// witness. For real deployments, callers should swap to a Workload-API
/// or KMS-backed `TreeWitness` so the witness key is not in process
/// memory. The seed is dropped at the end of this function (the key
/// material lives inside the SigningKey).
fn rand_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
