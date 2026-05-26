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
use nucleus_lineage::JsonlSink;
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

    let sink = Arc::new(
        JsonlSink::open(&cli.log)
            .with_context(|| format!("opening lineage log {}", cli.log.display()))?,
    );

    // Register the mock driver. Real drivers (claude-code, openhands)
    // register themselves from downstream crates that depend on this
    // one — keeping nucleus vendor-neutral.
    let runners = RunnerRegistry::new().register("mock", Box::new(MockJobRunner));

    let state = build_demo_state(
        runners,
        sink,
        cli.trust_domain.clone(),
        cli.namespace.clone(),
        cli.service_account.clone(),
    )?;

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
    axum::serve(listener, app).await?;
    Ok(())
}
