//! `nucleus-control-plane-server` — REST server binary.
//!
//! For the MVP this is a single-process server with an in-memory job
//! registry and a single shared JSONL lineage sink. The `MockJobRunner`
//! is registered under the name `"mock"` so end-to-end smoke testing
//! works without any vendor SDKs.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
#[cfg(feature = "insecure-dev")]
use nucleus_control_plane::MockJobRunner;
use nucleus_control_plane_server::{
    build_app, registry::RunnerRegistry, require_auth_or_insecure, resolve_spiffe_auth,
    state::build_state,
};
use nucleus_lineage::{
    Ed25519Witness, EdgeSigner, JsonlSink, MerkleConfig, MerkleSink, SigningProvider, TreeWitness,
};
use nucleus_oidc_core::Jwks;

/// Load the production lineage signer from the environment, if configured.
///
/// `NUCLEUS_LINEAGE_KEY_PEM` (path to a PKCS#8 PEM file) takes precedence over
/// `NUCLEUS_LINEAGE_KEY` (base64-encoded PKCS#8 DER). Returns `None` when
/// neither is set (the caller then fails closed, or falls back under
/// `insecure-dev`). Most-paranoid #6.
fn load_production_signer(
) -> Option<Result<nucleus_lineage::Pkcs8FileSigner, nucleus_lineage::IssuerError>> {
    use nucleus_lineage::Pkcs8FileSigner;
    if let Ok(path) = std::env::var("NUCLEUS_LINEAGE_KEY_PEM") {
        return Some(Pkcs8FileSigner::from_pkcs8_pem_file(std::path::Path::new(
            &path,
        )));
    }
    if std::env::var("NUCLEUS_LINEAGE_KEY").is_ok() {
        return Some(Pkcs8FileSigner::from_env("NUCLEUS_LINEAGE_KEY"));
    }
    None
}

#[derive(Parser, Debug)]
#[command(name = "nucleus-control-plane-server", version)]
struct Cli {
    /// HTTP bind address (host:port).
    #[arg(long, default_value = "127.0.0.1:8080", env = "NUCLEUS_BIND")]
    bind: String,
    /// gRPC bind address (host:port). Per workspace convention the
    /// gRPC port is `HTTP port + 1000`. Set to empty string to
    /// disable the gRPC surface (default: 0.0.0.0:9080).
    #[arg(long, default_value = "0.0.0.0:9080", env = "NUCLEUS_GRPC_BIND")]
    grpc_bind: String,
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
    /// Path to the trust JWKS file that authorizes inbound JWT-SVIDs.
    /// Published by the nucleus-oidc-provider OP under
    /// `/.well-known/jwks.json` — operators mirror it to disk and
    /// point this flag at it. When unset, SPIFFE auth is disabled
    /// (legacy MVP behavior — every endpoint open).
    #[arg(long, env = "NUCLEUS_SPIFFE_TRUST_JWKS_PATH")]
    spiffe_trust_jwks_path: Option<std::path::PathBuf>,
    /// Required `aud` value on inbound JWT-SVIDs. Bundles minted by
    /// the OP for a different audience must not be replayable here —
    /// the RFC 8693 confused-deputy guard. Set in lockstep with
    /// `--spiffe-trust-jwks-path`.
    #[arg(long, env = "NUCLEUS_SPIFFE_ALLOWED_AUDIENCE")]
    spiffe_allowed_audience: Option<String>,
    /// Required `sub` prefix. Restricts callers to a specific SPIFFE
    /// namespace / service account.
    /// Example: `spiffe://prod.example.com/ns/agents/sa/`. Set in
    /// lockstep with the other two SPIFFE flags.
    #[arg(long, env = "NUCLEUS_SPIFFE_ALLOWED_SUBJECT_PREFIX")]
    spiffe_allowed_subject_prefix: Option<String>,
}

/// Thin CLI shim around the lib-side [`resolve_spiffe_auth`]. Reads
/// the JWKS file from disk when configured, then delegates the
/// partial-config gate to the unit-tested resolver.
fn cli_spiffe_auth(cli: &Cli) -> Result<Option<nucleus_control_plane_server::SpiffeAuthConfig>> {
    let trust_jwks = match &cli.spiffe_trust_jwks_path {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading SPIFFE trust JWKS {}", path.display()))?;
            let jwks: Jwks = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing SPIFFE trust JWKS {}", path.display()))?;
            Some(jwks)
        }
        None => None,
    };
    Ok(resolve_spiffe_auth(
        trust_jwks,
        cli.spiffe_allowed_audience.clone(),
        cli.spiffe_allowed_subject_prefix.clone(),
    )?)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Shared OTel bootstrap — emits to OTEL_EXPORTER_OTLP_ENDPOINT
    // when set, falls through to stderr-only otherwise.
    let _otel = nucleus_otel_bootstrap::init("nucleus-control-plane-server")?;

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

    // Fail-closed signer selection (most-paranoid #6). Production requires an
    // operator-managed Ed25519 key; only `--features insecure-dev` may fall back
    // to a random in-process LocalIssuer. No silent unsigned/demo path.
    let issuer: Arc<dyn SigningProvider> = match load_production_signer() {
        Some(Ok(s)) => {
            tracing::info!(kid = %s.kid(), "lineage signer: production Pkcs8FileSigner");
            Arc::new(s)
        }
        Some(Err(e)) => anyhow::bail!("FATAL: failed to load lineage signing key: {e}"),
        None => {
            #[cfg(feature = "insecure-dev")]
            {
                tracing::error!(
                    "no production signing key (NUCLEUS_LINEAGE_KEY_PEM / NUCLEUS_LINEAGE_KEY) — \
                     using INSECURE-DEV random LocalIssuer; DO NOT use in production"
                );
                Arc::new(nucleus_lineage::LocalIssuer::random()?)
            }
            #[cfg(not(feature = "insecure-dev"))]
            anyhow::bail!(
                "FATAL: no lineage signing key configured (set NUCLEUS_LINEAGE_KEY_PEM=<pkcs8 pem \
                 path> or NUCLEUS_LINEAGE_KEY=<base64 pkcs8 der>) and `insecure-dev` is not \
                 enabled — refusing to start fail-closed (most-paranoid #6)"
            )
        }
    };

    // Register agent drivers. Real drivers register themselves from downstream
    // crates via the driver registry — keeping nucleus vendor-neutral. The
    // mock driver is dev/test only; a production registry is empty and every job
    // fails closed with "unknown agent driver" until a real driver registers.
    let runners = RunnerRegistry::new();
    #[cfg(feature = "insecure-dev")]
    let runners = runners.register("mock", Box::new(MockJobRunner));

    // Build state with the chosen signer, then plug in the Merkle-aware sink + prover.
    let mut state = build_state(
        runners,
        merkle_sink.clone(),
        issuer,
        cli.trust_domain.clone(),
        cli.namespace.clone(),
        cli.service_account.clone(),
    );
    state.merkle_prover = Some(merkle_sink.clone());
    state.witness_pubkey = Some(witness_pubkey);

    // SPIFFE auth wiring. fail-loud on partial config; fail-CLOSED when auth is
    // unconfigured in a production build (require_auth_or_insecure) so the
    // orchestration API never boots open — mirroring the lineage-signer
    // discipline above (most-paranoid #6). Only `--features insecure-dev` may
    // boot without auth.
    match require_auth_or_insecure(cli_spiffe_auth(&cli)?)? {
        Some(cfg) => {
            tracing::info!(
                audience = %cfg.allowed_audience,
                subject_prefix = %cfg.allowed_subject_prefix,
                jwks_keys = cfg.trust_jwks.keys.len(),
                "SPIFFE JWT-SVID auth ENABLED — protected routes require Bearer token"
            );
            state.spiffe_auth = Some(Arc::new(cfg));
        }
        None => {
            // Reachable ONLY under `--features insecure-dev` — a production build
            // returns Err(AuthRequiredInProduction) above and never reaches here.
            tracing::warn!(
                "SPIFFE JWT-SVID auth DISABLED (insecure-dev build) — every endpoint is OPEN. \
                 This build must never run in production."
            );
        }
    }

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

    let app = build_app(state.clone());
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!(
        "nucleus-control-plane-server HTTP listening on {}",
        cli.bind
    );

    // Spawn the gRPC server alongside HTTP (workspace mandate: gRPC
    // for internal service-to-service). Disabled when --grpc-bind=""
    // — useful for tests that share the process with a different
    // gRPC server (e.g. when integrating into a larger orchestrator).
    let grpc_handle = if cli.grpc_bind.is_empty() {
        tracing::info!("gRPC surface DISABLED (--grpc-bind is empty)");
        None
    } else {
        let grpc_addr: std::net::SocketAddr = cli
            .grpc_bind
            .parse()
            .with_context(|| format!("parsing --grpc-bind {}", cli.grpc_bind))?;
        let service = nucleus_control_plane_server::grpc::GrpcJobService::new(state.clone());
        tracing::info!(
            "nucleus-control-plane-server gRPC listening on {}",
            grpc_addr
        );
        Some(tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(
                    nucleus_proto::control_plane::job_service_server::JobServiceServer::new(
                        service,
                    ),
                )
                .serve(grpc_addr)
                .await
            {
                tracing::error!(error = %e, "gRPC server stopped with error");
            }
        }))
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // HTTP server has stopped → SIGTERM was delivered. Drop the
    // gRPC task; tonic's `serve` exits when the future is cancelled.
    if let Some(h) = grpc_handle {
        h.abort();
        let _ = h.await;
    }
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
    // rand 0.10: `RngCore` trait renamed to `Rng` (carries `fill_bytes`);
    // `thread_rng()` removed in favor of `rng()`.
    use rand::Rng;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
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
