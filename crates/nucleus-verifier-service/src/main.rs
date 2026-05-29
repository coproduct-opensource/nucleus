//! `nucleus-verifier-service` — public verifier-as-a-service binary.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use nucleus_verifier_service::{
    app::{with_rate_limit, AppState},
    build_app, connect_and_migrate,
    merkle::MerkleLog,
    retention, VerifierSigner,
};
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(name = "nucleus-verifier-service", version)]
struct Cli {
    /// Bind address (host:port). Fly.io exposes 0.0.0.0:8080 by default.
    #[arg(long, default_value = "0.0.0.0:8080", env = "NUCLEUS_VERIFIER_BIND")]
    bind: String,
    /// SQLite database URL or path. When set, every verify result is
    /// persisted and `/v1/bundles/{hash}/verify` is enabled. Without
    /// this flag the service runs stateless (original v0 behavior)
    /// and the lookup endpoint returns 503.
    ///
    /// Accepted forms:
    /// - `sqlite::memory:` (ephemeral; CI)
    /// - `sqlite:/data/verifier.db` (Fly.io volume mount)
    /// - `/data/verifier.db` (treated as `sqlite:<path>`)
    #[arg(long, env = "NUCLEUS_VERIFIER_DB")]
    db: Option<String>,
    /// Hex-encoded Ed25519 secret key (64 chars = 32 bytes) for STH
    /// signing. When set, `/v1/log/sth` returns a signed tree head
    /// and `/.well-known/jwks.json` publishes the matching public
    /// key with a stable `kid`. When unset, an ephemeral key is
    /// generated at startup — fine for dev, but the `kid` changes
    /// on every restart, breaking any client that cached the public
    /// key. Production deploys MUST set this via Fly.io secrets.
    #[arg(long, env = "NUCLEUS_VERIFIER_SIGNING_KEY", hide_env_values = true)]
    signing_key_hex: Option<String>,
    /// Retention window in days for the `verifications` table.
    /// When set, a background sweeper deletes rows older than
    /// (now - retention_days * 86400) once per hour. When unset
    /// (the default), rows are retained forever. Recommended
    /// production value is somewhere in [90, 365] depending on
    /// audit retention requirements. The transparency log
    /// (`log_entries`) is never swept regardless of this setting.
    #[arg(long, env = "NUCLEUS_VERIFIER_RETENTION_DAYS")]
    retention_days: Option<i64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Shared OTel bootstrap — emits to OTEL_EXPORTER_OTLP_ENDPOINT when
    // set, falls through to stderr-only otherwise. Guard MUST be held
    // until `axum::serve` returns so pending spans flush at shutdown.
    let _otel = nucleus_otel_bootstrap::init("nucleus-verifier-service")?;

    let cli = Cli::parse();

    let db = if let Some(url) = cli.db.as_deref() {
        let pool = connect_and_migrate(url)
            .await
            .with_context(|| format!("opening verifier DB at {url}"))?;
        tracing::info!(db = %url, "persistence enabled");
        Some(pool)
    } else {
        tracing::info!("persistence disabled (stateless mode); pass --db to enable hash-lookup");
        None
    };

    let signer = match cli.signing_key_hex.as_deref() {
        Some(hex) => {
            let s = VerifierSigner::from_secret_hex(hex).context(
                "NUCLEUS_VERIFIER_SIGNING_KEY must be 64-char hex (32-byte Ed25519 secret)",
            )?;
            tracing::info!(kid = %s.kid(), "STH signer loaded from env");
            Some(Arc::new(s))
        }
        None => {
            let s = VerifierSigner::random();
            tracing::warn!(
                kid = %s.kid(),
                "STH signer is EPHEMERAL — kid changes on restart; set NUCLEUS_VERIFIER_SIGNING_KEY in production"
            );
            Some(Arc::new(s))
        }
    };

    // Install the Prometheus exporter once at process startup. The
    // recorder is process-global; build_app receives an Arc<Handle>
    // that the /metrics route renders on demand.
    let metrics = match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            tracing::info!("Prometheus recorder installed; /metrics live");
            Some(Arc::new(handle))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Prometheus recorder install failed; /metrics will 503");
            None
        }
    };

    // Rebuild the in-memory Merkle tree from the persisted log
    // entries. O(n) at startup but n is small (verify rate * uptime).
    let merkle = if let Some(pool) = db.as_ref() {
        let log = MerkleLog::from_persisted_entries(pool)
            .await
            .context("rebuilding in-memory Merkle log from persisted entries")?;
        let size = log.size();
        tracing::info!(merkle_leaves = size, "Merkle log rebuilt at startup");
        Some(Arc::new(RwLock::new(log)))
    } else {
        None
    };

    let state = AppState {
        db: db.clone(),
        signer,
        metrics,
        merkle,
        witness: None, // iter-1: configurable via CLI in iter-2
    };

    // Retention sweeper — spawned only when persistence is enabled.
    // The token is cancelled in the shutdown signal so the sweeper
    // releases its DB connection before axum::serve returns.
    let shutdown_token = CancellationToken::new();
    let sweeper_handle = if let Some(pool) = db.as_ref() {
        let retention_secs = cli.retention_days.map(|days| days * 86_400);
        Some(retention::spawn(
            pool.clone(),
            retention_secs,
            retention::DEFAULT_SWEEP_INTERVAL_SECS,
            shutdown_token.clone(),
        ))
    } else {
        None
    };
    // with_rate_limit wraps the router with tower-governor's per-IP
    // token bucket; `into_make_service_with_connect_info::<SocketAddr>`
    // is REQUIRED so the default `PeerIpKeyExtractor` can find the
    // client IP. Without that pairing every request returns 500.
    let app = with_rate_limit(build_app(state));
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!("nucleus-verifier-service listening on {}", cli.bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    // axum::serve returned → SIGTERM/INT delivered. Cancel the
    // sweeper token so the background task exits its loop, then
    // join the handle so we don't drop a still-running task.
    shutdown_token.cancel();
    if let Some(h) = sweeper_handle {
        let _ = h.await;
    }
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
