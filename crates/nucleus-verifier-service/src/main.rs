//! `nucleus-verifier-service` — public verifier-as-a-service binary.

use anyhow::{Context, Result};
use clap::Parser;
use nucleus_verifier_service::build_app;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "nucleus-verifier-service", version)]
struct Cli {
    /// Bind address (host:port). Fly.io exposes 0.0.0.0:8080 by default.
    #[arg(long, default_value = "0.0.0.0:8080", env = "NUCLEUS_VERIFIER_BIND")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("nucleus_verifier_service=info,info")),
        )
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();

    let app = build_app();
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!("nucleus-verifier-service listening on {}", cli.bind);
    axum::serve(listener, app).await?;
    Ok(())
}
