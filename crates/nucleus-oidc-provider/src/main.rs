//! `nucleus-oidc-provider` — OP service binary.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use nucleus_oidc_provider::{
    app::{build_app, AppState},
    federation::FederationRegistry,
    issuer::JwtIssuer,
    keystore::{InMemoryKeyStore, JwtKeyStore},
    JtiCache,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "nucleus-oidc-provider", version)]
struct Cli {
    /// Bind address (host:port). Container deployments typically expose 0.0.0.0:8080.
    #[arg(long, default_value = "0.0.0.0:8080", env = "NUCLEUS_OIDC_BIND")]
    bind: String,
    /// External HTTPS issuer URL. Must be `https://...` and resolvable
    /// to this service. Advertised as `iss` in minted tokens and as
    /// the `issuer` field of the discovery doc.
    #[arg(
        long,
        default_value = "https://oidc.nucleus.example/",
        env = "NUCLEUS_OIDC_ISSUER_URL"
    )]
    issuer_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nucleus_oidc_provider=info,info")),
        )
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();

    // Skeleton bootstrap: in-memory keystore with a fresh active key.
    // Production deployments swap this for `FileKeyStore::open_with_passphrase`
    // (task #53 wires the env-var / CLI plumbing).
    let keystore: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
    tracing::warn!(
        active_kid = %keystore.active_kid().unwrap_or_default(),
        "bootstrap: in-memory keystore (NOT durable). Wire FileKeyStore via task #53 for production."
    );

    if !cli.issuer_url.starts_with("https://") {
        anyhow::bail!(
            "issuer URL {:?} must start with `https://` (set NUCLEUS_OIDC_ISSUER_URL)",
            cli.issuer_url
        );
    }
    let issuer = Arc::new(
        JwtIssuer::new(
            keystore.clone(),
            cli.issuer_url.clone(),
            Duration::from_secs(300),
        )
        .context("constructing JwtIssuer")?,
    );
    // v1 bootstrap: empty static bundle (no upstream IdPs registered).
    // Operators populate the bundle from config; production deployments
    // swap to WorkloadApiBundleProvider once that lands (task v2.x).
    let bundle_provider: Arc<dyn nucleus_oidc_provider::spire::SpireBundleProvider> =
        Arc::new(nucleus_oidc_provider::spire::StaticBundleProvider::new());
    tracing::warn!(
        "bootstrap: empty static SPIRE bundle. Token endpoint will reject ALL \
         subject_tokens until upstream verifying keys are registered."
    );

    let state = AppState {
        keystore,
        issuer_url: Arc::from(cli.issuer_url.as_str()),
        issuer,
        jti_cache: Arc::new(JtiCache::new()),
        // Default: empty rule set (default-deny). Operators load rules via #53's
        // `--federation-rules-path` flag / SIGHUP reload.
        federation: Arc::new(FederationRegistry::empty()),
        bundle_provider,
    };
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!("nucleus-oidc-provider listening on {}", cli.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("shutdown complete");
    Ok(())
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
