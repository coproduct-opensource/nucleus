//! `nucleus-witness` binary: a C2SP `tlog-witness` server.
//!
//! MVP wiring: an in-memory origin store seeded from CLI flags, an
//! Ed25519 witness key from a seed file (or a dev seed), and the axum
//! router on a bind address. Production deployments should back the
//! store with durable storage (see `store::InMemoryStore` docs) and
//! load the witness key from an HSM / KMS rather than a seed file.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use nucleus_witness::{
    app::build_app, server::WitnessState, InMemoryStore, TrustedLogKey, WitnessKey,
};

/// C2SP tlog-witness server.
#[derive(Parser, Debug)]
#[command(name = "nucleus-witness", version, about)]
struct Cli {
    /// Bind address, e.g. 0.0.0.0:8443 (bind to all interfaces for
    /// 6PN / k8s accessibility).
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: String,

    /// Hex-encoded 32-byte Ed25519 seed for the witness signing key.
    /// In production, load from a secret manager — NOT a flag.
    #[arg(long, env = "NUCLEUS_WITNESS_SEED_HEX")]
    witness_seed_hex: Option<String>,

    /// C2SP witness name (the key_name in cosignature lines).
    #[arg(long, default_value = "nucleus.witness/local")]
    witness_name: String,

    /// A trusted origin to cosign for, in the form
    /// `origin|log_key_name|log_pubkey_hex`. Repeatable.
    #[arg(long = "origin")]
    origins: Vec<String>,
}

fn parse_origin_spec(spec: &str) -> Result<(String, TrustedLogKey)> {
    let parts: Vec<&str> = spec.split('|').collect();
    anyhow::ensure!(
        parts.len() == 3,
        "origin spec must be `origin|log_key_name|log_pubkey_hex`, got {spec:?}"
    );
    let pubkey_bytes = hex::decode(parts[2].trim())
        .with_context(|| format!("origin {:?}: pubkey hex decode", parts[0]))?;
    let pubkey: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("origin {:?}: pubkey must be 32 bytes", parts[0]))?;
    Ok((
        parts[0].to_string(),
        TrustedLogKey {
            key_name: parts[1].to_string(),
            pubkey,
        },
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let seed: [u8; 32] = match cli.witness_seed_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).context("witness seed hex decode")?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("witness seed must be 32 bytes"))?
        }
        None => {
            tracing::warn!(
                "no --witness-seed-hex provided; using a non-secret dev seed. \
                 DO NOT use this in production."
            );
            [0x11u8; 32]
        }
    };
    let witness_key = Arc::new(WitnessKey::from_seed(seed, cli.witness_name));
    tracing::info!(
        witness_name = witness_key.name(),
        pubkey_hex = %hex::encode(witness_key.verifying_key_bytes()),
        "witness key loaded"
    );

    let store = InMemoryStore::new();
    for spec in &cli.origins {
        let (origin, key) = parse_origin_spec(spec)?;
        tracing::info!(origin = %origin, log_key = %key.key_name, "trusting origin");
        store.add_origin(origin, vec![key], None);
    }
    if cli.origins.is_empty() {
        tracing::warn!("no --origin configured; every checkpoint will 404 until origins are added");
    }

    let state = WitnessState {
        store: Arc::new(store),
        witness_key,
    };

    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .with_context(|| format!("binding {}", cli.bind))?;
    tracing::info!(bind = %cli.bind, "nucleus-witness listening");
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}
