//! `nucleus-oidc-provider` — OP service binary.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nucleus_federation::keyring::{KeyDir, RotationPolicy};
use nucleus_federation::{FileCustody, KeyCustody};
use nucleus_oidc_provider::{
    FederationRules, JtiCache, OutsideIssuers,
    app::{AppState, build_app},
    federation::FederationRegistry,
    issuer::JwtIssuer,
    keystore::{InMemoryKeyStore, JwtKeyStore, KeyringKeyStore},
};

#[derive(Parser, Debug)]
#[command(name = "nucleus-oidc-provider", version, mut_args = |a| a.hide_env_values(true))]
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
    /// Directory holding the ES256 signing key (`nucleus-federation`'s keyring
    /// layout, file custody). Created with a fresh key on first start. When
    /// set the OP signs ES256; when absent it signs EdDSA with an in-memory
    /// key that does not survive a restart.
    #[arg(long, env = "NUCLEUS_OIDC_SIGNING_KEY_DIR")]
    signing_key_dir: Option<PathBuf>,
    /// TOML file of federation rules (`[[rule]]`) and outside-issuer bindings
    /// (`[[outside_issuer]]`). A file that does not parse or validate stops the
    /// OP from starting. Absent: no rules, so every exchange is refused.
    #[arg(long, env = "NUCLEUS_OIDC_FEDERATION_CONFIG")]
    federation_config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Rotate the ES256 signing key: the keyring's stage → promote → retire
    /// protocol on the signing key directory. Run as the directory's owner
    /// (the OP's user); a write by anyone else is refused.
    Keys {
        /// The signing key directory (as `--signing-key-dir`).
        #[arg(long, env = "NUCLEUS_OIDC_SIGNING_KEY_DIR", hide_env_values = true)]
        dir: PathBuf,
        #[command(subcommand)]
        step: KeyStep,
    },
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum KeyStep {
    /// Print the published keys and when the next step is allowed.
    Status,
    /// Generate the next key. Published from now on; never signs until promoted.
    Stage,
    /// Make the staged key current. Refused until it has been published for
    /// the relying parties' JWKS cache lifetime plus the longest token.
    Promote,
    /// Unpublish the previous key. Refused until its last token expired.
    Retire,
}

/// File custody on a host with no TPM. Named so the deployment's custody is
/// one grep away; the docs say plainly what it means.
const FILE_CUSTODY: KeyCustody = KeyCustody::File(FileCustody::NoTpmConfigured);

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before unix epoch")?
        .as_secs())
}

fn run_key_step(dir: &Path, step: KeyStep) -> Result<()> {
    let keys = KeyDir::new(dir);
    let policy = RotationPolicy::default();
    let now = now_unix()?;
    let state = match step {
        KeyStep::Status => keys.state(now)?,
        KeyStep::Stage => keys.stage(now, &FILE_CUSTODY)?.after,
        KeyStep::Promote => keys.promote(now, &policy)?.after,
        KeyStep::Retire => keys.retire(now, &policy)?.after,
    };
    let report = serde_json::json!({
        "current": state.current.kid,
        "next": state.next.as_ref().map(|s| &s.jwk.kid),
        "prev": state.prev.as_ref().map(|r| &r.jwk.kid),
        "promote_allowed_at": state.promote_allowed_at(&policy),
        "retire_allowed_at": state.retire_allowed_at(&policy),
        "jwks": state.jwks(),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // reqwest is built with `rustls-no-provider` (workspace convention); the
    // outside-issuer validator's JWKS fetches need a provider installed before
    // the first client is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls crypto provider"))?;

    let cli = Cli::parse();
    if let Some(Command::Keys { dir, step }) = &cli.command {
        return run_key_step(dir, *step);
    }

    // Shared OTel bootstrap — emits to OTEL_EXPORTER_OTLP_ENDPOINT
    // when set, falls through to stderr-only otherwise.
    let _otel = nucleus_otel_bootstrap::init("nucleus-oidc-provider")?;

    if !cli.issuer_url.starts_with("https://") {
        anyhow::bail!(
            "issuer URL {:?} must start with `https://` (set NUCLEUS_OIDC_ISSUER_URL)",
            cli.issuer_url
        );
    }

    let keystore: Arc<dyn JwtKeyStore> = match &cli.signing_key_dir {
        Some(dir) => {
            let store =
                KeyringKeyStore::open_or_create(dir, FILE_CUSTODY, RotationPolicy::default())
                    .with_context(|| {
                        format!("opening the signing key directory {}", dir.display())
                    })?;
            tracing::info!(
                active_kid = %store.active_kid().unwrap_or_default(),
                dir = %dir.display(),
                custody = "file (no TPM configured)",
                "signing ES256 with the keyring's current key"
            );
            Arc::new(store)
        }
        None => {
            let store = InMemoryKeyStore::new();
            tracing::warn!(
                active_kid = %store.active_kid().unwrap_or_default(),
                "no --signing-key-dir: signing EdDSA with an in-memory key that does NOT \
                 survive a restart. Relying parties lose every issued token's key on restart."
            );
            Arc::new(store)
        }
    };

    let issuer = Arc::new(
        JwtIssuer::new(
            keystore.clone(),
            cli.issuer_url.clone(),
            Duration::from_secs(300),
        )
        .context("constructing JwtIssuer")?,
    );

    let rules = match &cli.federation_config {
        Some(path) => FederationRules::read_from_file(path)
            .with_context(|| format!("loading federation config {}", path.display()))?,
        None => {
            tracing::warn!("no --federation-config: no rules, so every token exchange is refused");
            FederationRules::default()
        }
    };
    let outside_issuers = OutsideIssuers::build(&rules.outside_issuer, &cli.issuer_url)
        .context("binding outside issuers")?;
    tracing::info!(
        rules = rules.rule.len(),
        outside_issuers = outside_issuers.len(),
        "federation config loaded"
    );

    // v1 bootstrap: empty static bundle (no upstream IdPs registered).
    // Operators populate the bundle from config; production deployments
    // swap to WorkloadApiBundleProvider once that lands (task v2.x).
    let bundle_provider: Arc<dyn nucleus_oidc_provider::spire::SpireBundleProvider> =
        Arc::new(nucleus_oidc_provider::spire::StaticBundleProvider::new());
    tracing::info!(
        "empty static SPIRE bundle: JWT-SVID subject tokens are refused; outside-issuer \
         bindings are the only accepted subjects"
    );

    // The root a presented pod certificate must chain to. Absent by default:
    // an OP that has not been told which root to trust refuses certificates
    // outright rather than accepting whatever chain a caller minted.
    let cert_root_pubkey: Option<Vec<u8>> = match std::env::var("NUCLEUS_OIDC_CERT_ROOT_PUBKEY") {
        Ok(hex_key) if !hex_key.trim().is_empty() => {
            let raw =
                hex_decode(hex_key.trim()).context("NUCLEUS_OIDC_CERT_ROOT_PUBKEY must be hex")?;
            if raw.len() != 32 {
                anyhow::bail!(
                    "NUCLEUS_OIDC_CERT_ROOT_PUBKEY must be 32 bytes (Ed25519), got {}",
                    raw.len()
                );
            }
            tracing::info!("pod certificates will be verified against the pinned root");
            Some(raw)
        }
        _ => {
            tracing::info!(
                "no NUCLEUS_OIDC_CERT_ROOT_PUBKEY: federation rules using `scope_requires` \
                 will refuse, because an unpinned certificate proves nothing"
            );
            None
        }
    };

    let state = AppState {
        keystore,
        issuer_url: Arc::from(cli.issuer_url.as_str()),
        issuer,
        jti_cache: Arc::new(JtiCache::new()),
        federation: Arc::new(FederationRegistry::new(rules)),
        outside_issuers: Arc::new(outside_issuers),
        bundle_provider,
        cert_root_pubkey: cert_root_pubkey.map(Arc::new),
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

/// Decode a lowercase-or-uppercase hex string. Local rather than a dependency:
/// one call site, sixteen lines, and no reason to widen the OP's supply chain
/// for it.
fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has an odd number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex at byte {}: {e}", i / 2))
        })
        .collect()
}

#[cfg(test)]
mod help_env_tests;
