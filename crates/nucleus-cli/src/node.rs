//! Node command - interact with a running nucleus-node
//!
//! Test utilities for nucleus-node HTTP and gRPC APIs.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use nucleus_client::sign_http_headers;
use std::fs;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::PathBuf;
use std::time::Duration;

/// Interact with a running nucleus-node
#[derive(Args, Debug)]
pub struct NodeArgs {
    /// nucleus-node HTTP URL. `https://` since Move B: the node's HTTP
    /// listener requires mTLS unconditionally now — there is no plaintext
    /// mode left to default to.
    #[arg(
        long,
        default_value = "https://127.0.0.1:8080",
        env = "NUCLEUS_NODE_URL"
    )]
    pub url: String,

    /// Path to secrets.env file (or use --auth-secret)
    #[arg(long, env = "NUCLEUS_SECRETS_FILE")]
    pub secrets_file: Option<PathBuf>,

    /// Auth secret (hex-encoded, overrides secrets_file)
    #[arg(long, env = "NUCLEUS_NODE_AUTH_SECRET")]
    pub auth_secret: Option<String>,

    /// Actor identifier for request signing
    #[arg(long, default_value = "nucleus-cli")]
    pub actor: String,

    // === mTLS (Move A step 5; mandatory on the node's side since Move B) ===
    /// Path to this CLI's client certificate (PEM). Defaults to the identity
    /// `nucleus setup` already provisioned (`~/.config/nucleus/identity/
    /// cli-cert.pem`) when all three of `--tls-cert`/`--tls-key`/
    /// `--trust-bundle` are unset and that identity exists — see
    /// `apply_provisioned_identity_defaults`. Requires `--tls-key`.
    #[arg(long, env = "NUCLEUS_NODE_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,
    /// Path to this CLI's client private key (PEM). Requires `--tls-cert`.
    #[arg(long, env = "NUCLEUS_NODE_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
    /// Path to the trust bundle (PEM) that verifies the node's server
    /// certificate — the node's own CA root, not a public CA, since the
    /// node self-issues. Required alongside `--tls-cert`/`--tls-key`: without
    /// it the node's self-issued cert has no root to verify against.
    #[arg(long, env = "NUCLEUS_NODE_TRUST_BUNDLE")]
    pub trust_bundle: Option<PathBuf>,

    #[command(subcommand)]
    pub command: NodeCommand,
}

#[derive(Subcommand, Debug)]
pub enum NodeCommand {
    /// Check nucleus-node health
    Health,

    /// List all pods
    Pods,

    /// Create a pod from a YAML spec
    Create {
        /// Path to pod spec YAML file
        spec_file: PathBuf,
        /// Record this pod as a child of the given parent pod id (sets the
        /// `x-nucleus-parent-pod-id` header). For orchestrator/test use — the
        /// header is unauthenticated, so a real pod's lineage is instead
        /// established by the node from the authenticated caller.
        #[arg(long)]
        parent_pod_id: Option<String>,
    },

    /// Cancel (stop) a pod
    Cancel {
        /// Pod ID
        pod_id: String,
    },

    /// Stream logs from a pod
    Logs {
        /// Pod ID
        pod_id: String,

        /// Follow logs (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Byte offset to start from
        #[arg(long, default_value = "0")]
        offset: u64,
    },

    /// Generate a signed request (for debugging)
    Sign {
        /// HTTP method
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Request body (for POST/PUT)
        #[arg(short, long)]
        body: Option<String>,
    },
}

/// Fills in `--tls-cert`/`--tls-key`/`--trust-bundle` from the identity
/// `nucleus setup` already provisioned (Move A step 6:
/// `provision::mint_cli_identity`), when the caller passed none of the
/// three flags explicitly and all three provisioned files are present.
///
/// Move B made the node's HTTP listener mTLS-only, with no plaintext/HMAC
/// mode left to fall back to — before this, every default `nucleus node`
/// invocation on an otherwise fully set-up machine would silently attempt
/// (and fail) the now-nonexistent plaintext path, because nothing pointed
/// these flags at the identity `setup` already minted.
///
/// Only fills in the gap when ALL THREE flags are unset: a partial explicit
/// set must still hit `load_mtls_config`'s "must all be provided together"
/// error rather than being silently completed from defaults, and any flag
/// the caller DID set must never be overridden.
fn apply_provisioned_identity_defaults(args: &mut NodeArgs) {
    if args.tls_cert.is_some() || args.tls_key.is_some() || args.trust_bundle.is_some() {
        return;
    }
    let Ok(dir) = crate::config::Config::identity_dir() else {
        return;
    };
    if let Some((cert, key, bundle)) = provisioned_identity_paths_in(&dir) {
        args.tls_cert = Some(cert);
        args.tls_key = Some(key);
        args.trust_bundle = Some(bundle);
    }
}

/// The directory-parameterized half of [`apply_provisioned_identity_defaults`]
/// — split out so a test can point it at a tempdir instead of the real,
/// non-overridable `Config::identity_dir()`. `Some` only when all three
/// files `mint_cli_identity` writes are present; a partial set (e.g. a
/// half-written identity from an interrupted `setup`) is treated the same
/// as none, so `load_mtls_config`'s "must all be provided together" error
/// still fires rather than a silently completed partial default.
fn provisioned_identity_paths_in(dir: &std::path::Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let cert = dir.join("cli-cert.pem");
    let key = dir.join("cli-key.pem");
    let bundle = dir.join("trust-bundle.pem");
    (cert.is_file() && key.is_file() && bundle.is_file()).then_some((cert, key, bundle))
}

/// Execute the node command
pub async fn execute(mut args: NodeArgs) -> Result<()> {
    apply_provisioned_identity_defaults(&mut args);
    let agent = create_client(&args)?;
    let auth_secret = resolve_auth(&args)?;

    match args.command {
        NodeCommand::Health => health(&agent, &args.url, auth_secret.as_deref(), &args.actor).await,
        NodeCommand::Pods => {
            list_pods(&agent, &args.url, auth_secret.as_deref(), &args.actor).await
        }
        NodeCommand::Create {
            spec_file,
            parent_pod_id,
        } => {
            create_pod(
                &agent,
                &args.url,
                auth_secret.as_deref(),
                &args.actor,
                &spec_file,
                parent_pod_id.as_deref(),
            )
            .await
        }
        NodeCommand::Cancel { pod_id } => {
            cancel_pod(
                &agent,
                &args.url,
                auth_secret.as_deref(),
                &args.actor,
                &pod_id,
            )
            .await
        }
        NodeCommand::Logs {
            pod_id,
            follow,
            offset,
        } => {
            stream_logs(
                &agent,
                &args.url,
                auth_secret.as_deref(),
                &args.actor,
                &pod_id,
                follow,
                offset,
            )
            .await
        }
        NodeCommand::Sign { method, body } => {
            let secret = auth_secret.ok_or_else(|| {
                anyhow::anyhow!(
                    "`sign` produces HMAC-signed headers and needs an auth secret; mTLS mode \
                     has nothing to sign — present the client certificate instead"
                )
            })?;
            sign_request(&secret, &args.actor, &method, body.as_deref())
        }
    }
}

/// `Some(secret)` for the HMAC default; `None` when mTLS is configured — the
/// node's SPIFFE branch (`spiffe_context_for_request`) never consults HMAC
/// headers, so requiring an auth secret ALSO when presenting a client
/// certificate would be pure friction. Deliberately checks "any of the three
/// flags" rather than "all three": a partial set should surface
/// `load_mtls_config`'s "must all be provided together" error, not silently
/// fall back to requiring a secret the operator didn't intend to need.
fn resolve_auth(args: &NodeArgs) -> Result<Option<Vec<u8>>> {
    if args.tls_cert.is_some() || args.tls_key.is_some() || args.trust_bundle.is_some() {
        return Ok(None);
    }
    load_auth_secret(args).map(Some)
}

fn load_auth_secret(args: &NodeArgs) -> Result<Vec<u8>> {
    // Note: nucleus-node uses the hex string directly as bytes (not decoded),
    // so we return the hex string as ASCII bytes here.

    // 1. Check --auth-secret
    if let Some(hex_secret) = &args.auth_secret {
        // Return the hex string as bytes (not decoded)
        return Ok(hex_secret.as_bytes().to_vec());
    }

    // 2. Check --secrets-file
    if let Some(path) = &args.secrets_file {
        return load_secret_from_file(path, "NUCLEUS_NODE_AUTH_SECRET");
    }

    // 3. Check default location: /tmp/nucleus-node-state/secrets.env
    let default_path = PathBuf::from("/tmp/nucleus-node-state/secrets.env");
    if default_path.exists() {
        return load_secret_from_file(&default_path, "NUCLEUS_NODE_AUTH_SECRET");
    }

    // 4. Check Keychain (macOS) - keychain stores raw bytes, so hex-encode them
    #[cfg(target_os = "macos")]
    {
        use crate::keychain::{SecretKind, SecretStore};
        if let Some(secret) = SecretStore::get(SecretKind::NodeAuthSecret)? {
            // Keychain stores raw bytes, but server expects hex string as bytes
            return Ok(hex::encode(&secret).into_bytes());
        }
    }

    bail!(
        "No auth secret found. Provide via:\n\
         - --auth-secret <hex>\n\
         - --secrets-file <path>\n\
         - /tmp/nucleus-node-state/secrets.env\n\
         - macOS Keychain (via nucleus setup)"
    )
}

fn load_secret_from_file(path: &PathBuf, key: &str) -> Result<Vec<u8>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read secrets from {}", path.display()))?;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}=")) {
            // Return the hex string as bytes (not decoded) - server uses it as-is
            return Ok(value.trim().as_bytes().to_vec());
        }
    }

    bail!("{key} not found in {}", path.display())
}

/// Reads `--tls-cert`/`--tls-key`/`--trust-bundle` and returns a
/// `(client_cert, trust_roots)` pair when mTLS is configured, `None` when
/// none of the three flags is set (the plaintext default, unchanged).
///
/// A PARTIAL set is a hard error, the same discipline node/tool-proxy's own
/// `--tls-*` flags use: silently falling back to plaintext because one flag
/// was misspelled would turn a configuration mistake into an invisible
/// downgrade.
/// `(client identity PEM bundle, trust bundle PEM)` read from
/// `--tls-cert`/`--tls-key`/`--trust-bundle`, or `None` when none of the
/// three is set — the plaintext default, unchanged.
///
/// A PARTIAL set is a hard error, the same discipline node/tool-proxy's own
/// `--tls-*` flags use: silently falling back to plaintext because one flag
/// was misspelled would turn a configuration mistake into an invisible
/// downgrade.
fn load_mtls_config(args: &NodeArgs) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    match (&args.tls_cert, &args.tls_key, &args.trust_bundle) {
        (None, None, None) => Ok(None),
        (Some(cert_path), Some(key_path), Some(bundle_path)) => {
            let mut identity_pem = fs::read(cert_path)
                .with_context(|| format!("failed to read {}", cert_path.display()))?;
            let key_pem = fs::read(key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;
            // reqwest's `Identity::from_pem` wants cert and key concatenated
            // in one buffer, the same convention `nucleus-sdk::MtlsConfig`
            // already uses.
            identity_pem.push(b'\n');
            identity_pem.extend_from_slice(&key_pem);

            let bundle_pem = fs::read(bundle_path)
                .with_context(|| format!("failed to read {}", bundle_path.display()))?;
            if reqwest::Certificate::from_pem_bundle(&bundle_pem)
                .with_context(|| format!("invalid trust bundle {}", bundle_path.display()))?
                .is_empty()
            {
                bail!(
                    "trust bundle {} contains no certificates",
                    bundle_path.display()
                );
            }

            Ok(Some((identity_pem, bundle_pem)))
        }
        _ => bail!(
            "--tls-cert, --tls-key and --trust-bundle must all be provided together for mTLS \
             (or none, for the plaintext default)"
        ),
    }
}

/// The two transports this command speaks: plaintext HMAC (ureq, unchanged
/// from before mTLS support existed) or mTLS (reqwest — see the Cargo.toml
/// comment on the reqwest dependency for why ureq can't do this).
enum HttpClient {
    Plain(ureq::Agent),
    Mtls(reqwest::Client),
}

/// Builds the transport `load_mtls_config` selects.
fn create_client(args: &NodeArgs) -> Result<HttpClient> {
    match load_mtls_config(args)? {
        None => {
            let config = ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(30)))
                .build();
            Ok(HttpClient::Plain(config.into()))
        }
        Some((identity_pem, bundle_pem)) => {
            // reqwest's `rustls-no-provider` feature needs a provider
            // installed before building a `Client` — `main.rs` does this at
            // startup, but defensively (and idempotently: `install_default`
            // errors if one is already installed, hence `let _ =`) doing it
            // here too means this function works correctly wherever it's
            // called from, including tests. Same pattern nucleus-identity's
            // own `TlsServerConfig`/`TlsClientConfig` builders already use.
            let _ = rustls::crypto::ring::default_provider().install_default();

            let identity = reqwest::Identity::from_pem(&identity_pem)
                .context("failed to build client identity from --tls-cert/--tls-key")?;
            let roots = reqwest::Certificate::from_pem_bundle(&bundle_pem)
                .context("failed to parse --trust-bundle")?;

            let builder = reqwest::Client::builder()
                .identity(identity)
                .timeout(Duration::from_secs(30))
                // `tls_certs_only` — not repeated `add_root_certificate` —
                // is required here: reqwest refuses to combine
                // `danger_accept_invalid_hostnames` with the platform/webpki
                // default roots, exactly because that combination would mean
                // trusting a hostname-unverified cert from ANY public CA.
                // `tls_certs_only` replaces the trust store entirely with
                // ONLY `--trust-bundle`'s roots, which is what's actually
                // wanted: the chain IS still validated, against the node's
                // own CA and nothing else. Hostname/SNI matching is the ONLY
                // check skipped, because it's meaningless here — the node's
                // self-issued SVID carries a SPIFFE URI SAN, never a DNS or
                // IP SAN, since SPIFFE identity, not hostname, is this
                // system's trust model.
                .tls_certs_only(roots)
                .danger_accept_invalid_hostnames(true);

            Ok(HttpClient::Mtls(
                builder.build().context("failed to build mTLS client")?,
            ))
        }
    }
}

impl HttpClient {
    /// Sends a request and returns `(status, body)`. Not used for
    /// `stream_logs`, which needs a streaming read rather than a buffered
    /// body and branches on the backend itself.
    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        match self {
            HttpClient::Plain(agent) => {
                // ureq's typestate gives GET and POST builders distinct
                // types (`WithoutBody` / `WithBody`), so the two must stay
                // in separate branches rather than a common `let` binding.
                let result = if method == reqwest::Method::GET {
                    let mut req = agent.get(url);
                    for (key, value) in headers {
                        req = req.header(key, value);
                    }
                    req.call()
                } else {
                    let mut req = agent.post(url);
                    for (key, value) in headers {
                        req = req.header(key, value);
                    }
                    req.send(body)
                };
                match result {
                    Ok(mut resp) => {
                        let status = resp.status().as_u16();
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut resp.body_mut().as_reader(), &mut buf)?;
                        Ok((status, buf))
                    }
                    Err(ureq::Error::StatusCode(status)) => Ok((status, Vec::new())),
                    Err(e) => Err(e.into()),
                }
            }
            HttpClient::Mtls(client) => {
                let mut req = client.request(method, url);
                for (key, value) in headers {
                    req = req.header(key.as_str(), value.as_str());
                }
                if !body.is_empty() {
                    req = req.body(body.to_vec());
                }
                let resp = req.send().await?;
                let status = resp.status().as_u16();
                let bytes = resp.bytes().await?.to_vec();
                Ok((status, bytes))
            }
        }
    }
}

/// Signs `body` with HMAC when `secret` is present (the HMAC default); no
/// headers at all when it's `None` (mTLS mode — the client certificate
/// presented during the TLS handshake is the credential, and the node's
/// SPIFFE branch never looks at these headers).
fn maybe_sign(secret: Option<&[u8]>, actor: &str, body: &[u8]) -> Vec<(String, String)> {
    match secret {
        Some(secret) => sign_http_headers(secret, Some(actor), body).headers,
        None => Vec::new(),
    }
}

async fn health(client: &HttpClient, url: &str, secret: Option<&[u8]>, actor: &str) -> Result<()> {
    let endpoint = format!("{url}/v1/health");
    let headers = maybe_sign(secret, actor, b"");

    let (status, body) = client
        .send(reqwest::Method::GET, &endpoint, &headers, b"")
        .await
        .context("Health check failed")?;
    if status >= 300 {
        bail!("Health check failed with status {status}");
    }
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn list_pods(
    client: &HttpClient,
    url: &str,
    secret: Option<&[u8]>,
    actor: &str,
) -> Result<()> {
    let endpoint = format!("{url}/v1/pods");
    let headers = maybe_sign(secret, actor, b"");

    let (status, body) = client
        .send(reqwest::Method::GET, &endpoint, &headers, b"")
        .await
        .context("List pods failed")?;
    if status >= 300 {
        bail!("List pods failed with status {status}");
    }
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn create_pod(
    client: &HttpClient,
    url: &str,
    secret: Option<&[u8]>,
    actor: &str,
    spec_file: &PathBuf,
    parent_pod_id: Option<&str>,
) -> Result<()> {
    let endpoint = format!("{url}/v1/pods");

    // Read spec file
    let spec_content = fs::read_to_string(spec_file)
        .with_context(|| format!("Failed to read spec from {}", spec_file.display()))?;

    // Parse YAML to JSON
    let spec: serde_json::Value = serde_yaml::from_str(&spec_content)
        .with_context(|| format!("Invalid YAML in {}", spec_file.display()))?;

    let body = serde_json::to_string(&spec)?;

    let mut headers = maybe_sign(secret, actor, body.as_bytes());
    headers.push(("content-type".to_string(), "application/json".to_string()));
    if let Some(parent) = parent_pod_id {
        headers.push(("x-nucleus-parent-pod-id".to_string(), parent.to_string()));
    }

    let (status, resp_body) = client
        .send(reqwest::Method::POST, &endpoint, &headers, body.as_bytes())
        .await
        .context("Create pod failed")?;
    if status >= 300 {
        bail!("Create pod failed with status {status}");
    }
    let value: serde_json::Value = serde_json::from_slice(&resp_body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn cancel_pod(
    client: &HttpClient,
    url: &str,
    secret: Option<&[u8]>,
    actor: &str,
    pod_id: &str,
) -> Result<()> {
    let endpoint = format!("{url}/v1/pods/{pod_id}/cancel");
    let headers = maybe_sign(secret, actor, b"");

    let (status, _) = client
        .send(reqwest::Method::POST, &endpoint, &headers, b"")
        .await
        .context("Cancel pod failed")?;
    match status {
        s if s < 300 => {
            println!("Cancelled pod {pod_id}");
            Ok(())
        }
        404 => bail!("Pod {pod_id} not found"),
        s => bail!("Cancel pod failed with status {s}"),
    }
}

async fn stream_logs(
    client: &HttpClient,
    url: &str,
    secret: Option<&[u8]>,
    actor: &str,
    pod_id: &str,
    follow: bool,
    offset: u64,
) -> Result<()> {
    let endpoint = format!("{url}/v1/pods/{pod_id}/logs?follow={follow}&offset={offset}");
    let headers = maybe_sign(secret, actor, b"");

    // Genuinely branches per backend rather than going through
    // `HttpClient::send`: a `--follow`ed stream can run indefinitely, so it
    // needs a real streaming read, not a buffered body.
    match client {
        HttpClient::Plain(agent) => {
            let mut req = agent.get(&endpoint);
            for (key, value) in &headers {
                req = req.header(key, value);
            }
            match req.call() {
                Ok(response) => {
                    let reader = BufReader::new(response.into_body().into_reader());
                    for line in reader.lines() {
                        match line {
                            Ok(text) => {
                                println!("{text}");
                                std::io::stdout().flush().ok();
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    break;
                                }
                                return Err(e.into());
                            }
                        }
                    }
                    Ok(())
                }
                Err(ureq::Error::StatusCode(404)) => bail!("Pod {pod_id} not found"),
                Err(ureq::Error::StatusCode(status)) => {
                    bail!("Stream logs failed with status {status}")
                }
                Err(e) => bail!("Stream logs failed: {e}"),
            }
        }
        HttpClient::Mtls(reqwest_client) => {
            let mut req = reqwest_client.get(&endpoint);
            for (key, value) in &headers {
                req = req.header(key.as_str(), value.as_str());
            }
            let mut resp = req.send().await.context("Stream logs failed")?;
            match resp.status().as_u16() {
                404 => bail!("Pod {pod_id} not found"),
                s if s >= 300 => bail!("Stream logs failed with status {s}"),
                _ => {}
            }
            // Lines are not guaranteed to align with chunk boundaries, so
            // buffer across chunks and only print complete lines.
            let mut pending = Vec::new();
            while let Some(chunk) = resp.chunk().await? {
                pending.extend_from_slice(&chunk);
                while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = pending.drain(..=pos).collect();
                    let text = String::from_utf8_lossy(&line[..line.len() - 1]);
                    println!("{text}");
                    std::io::stdout().flush().ok();
                }
            }
            if !pending.is_empty() {
                println!("{}", String::from_utf8_lossy(&pending));
            }
            Ok(())
        }
    }
}

fn sign_request(secret: &[u8], actor: &str, method: &str, body: Option<&str>) -> Result<()> {
    let body_bytes = body.map(|b| b.as_bytes()).unwrap_or(b"");
    let signed = sign_http_headers(secret, Some(actor), body_bytes);

    println!("# Signed headers for {} request", method.to_uppercase());
    println!("# Timestamp: {}", signed.timestamp);
    println!();
    for (key, value) in &signed.headers {
        println!("{key}: {value}");
    }

    if let Some(body_str) = body {
        println!();
        println!("# Body:");
        println!("{body_str}");
    }

    println!();
    println!("# Example curl:");
    let mut curl = format!("curl -X {}", method.to_uppercase());
    for (key, value) in &signed.headers {
        curl.push_str(&format!(" \\\n  -H '{key}: {value}'"));
    }
    if body.is_some() {
        curl.push_str(" \\\n  -H 'Content-Type: application/json'");
        curl.push_str(" \\\n  -d '<body>'");
    }
    curl.push_str(" \\\n  <url>");
    println!("{curl}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_secret_from_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.env");

        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "NUCLEUS_NODE_AUTH_SECRET=deadbeef").unwrap();
        writeln!(file, "OTHER_SECRET=cafebabe").unwrap();

        // Secret is returned as the hex string bytes (not decoded)
        let secret = load_secret_from_file(&path, "NUCLEUS_NODE_AUTH_SECRET").unwrap();
        assert_eq!(secret, b"deadbeef".to_vec());

        let other = load_secret_from_file(&path, "OTHER_SECRET").unwrap();
        assert_eq!(other, b"cafebabe".to_vec());
    }

    #[test]
    fn test_missing_key_in_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.env");

        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "OTHER_KEY=value").unwrap();

        let result = load_secret_from_file(&path, "NUCLEUS_NODE_AUTH_SECRET");
        assert!(result.is_err());
    }

    // ── mTLS (Move A step 5) ────────────────────────────────────────────────

    fn base_args() -> NodeArgs {
        NodeArgs {
            url: "https://127.0.0.1:0".to_string(),
            secrets_file: None,
            auth_secret: None,
            actor: "test-cli".to_string(),
            tls_cert: None,
            tls_key: None,
            trust_bundle: None,
            command: NodeCommand::Health,
        }
    }

    // ── provisioned-identity defaults (Move B) ──────────────────────────────

    #[test]
    fn provisioned_identity_paths_are_found_when_all_three_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cli-cert.pem"), "CERT").unwrap();
        fs::write(dir.path().join("cli-key.pem"), "KEY").unwrap();
        fs::write(dir.path().join("trust-bundle.pem"), "BUNDLE").unwrap();

        let found = provisioned_identity_paths_in(dir.path());
        assert_eq!(
            found,
            Some((
                dir.path().join("cli-cert.pem"),
                dir.path().join("cli-key.pem"),
                dir.path().join("trust-bundle.pem"),
            ))
        );
    }

    #[test]
    fn provisioned_identity_paths_are_none_when_nothing_was_provisioned() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(provisioned_identity_paths_in(dir.path()), None);
    }

    /// A half-written identity (an interrupted `setup`, say) must not be
    /// treated as usable — only ALL THREE files present counts.
    #[test]
    fn provisioned_identity_paths_are_none_when_only_some_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cli-cert.pem"), "CERT").unwrap();
        fs::write(dir.path().join("cli-key.pem"), "KEY").unwrap();
        // trust-bundle.pem deliberately missing.
        assert_eq!(provisioned_identity_paths_in(dir.path()), None);
    }

    #[test]
    fn apply_provisioned_identity_defaults_never_overrides_an_explicit_flag() {
        // Even when the "provisioned" files would resolve to something else,
        // an explicitly-set flag (any one of the three) must survive
        // untouched — a partial explicit set is a configuration the caller
        // asked for, not a gap to fill in.
        let mut args = base_args();
        let explicit = PathBuf::from("/explicit/cert.pem");
        args.tls_cert = Some(explicit.clone());

        apply_provisioned_identity_defaults(&mut args);

        assert_eq!(args.tls_cert, Some(explicit));
        assert_eq!(args.tls_key, None);
        assert_eq!(args.trust_bundle, None);
    }

    #[test]
    fn load_mtls_config_is_none_when_no_flag_is_set() {
        let args = base_args();
        assert!(load_mtls_config(&args).unwrap().is_none());
    }

    #[test]
    fn resolve_auth_delegates_to_load_auth_secret_when_mtls_is_not_configured() {
        // Not "must error": this machine's own macOS Keychain may genuinely
        // hold a `node-auth-secret` from an earlier `nucleus setup` run (it
        // does, on the machine this was developed on), and clearing that as
        // a test side effect would be a much bigger footgun than the
        // property actually worth asserting here -- that `resolve_auth`
        // does NOT short-circuit to `None` for the plaintext default, it
        // defers entirely to `load_auth_secret`. Same explicit secret in
        // both calls makes the two paths deterministically comparable
        // regardless of what else is reachable in this environment.
        let mut args = base_args();
        args.auth_secret = Some("deadbeef".to_string());

        let via_resolve = resolve_auth(&args).unwrap();
        let via_load = load_auth_secret(&args).unwrap();
        assert_eq!(via_resolve, Some(via_load));
    }

    #[test]
    fn resolve_auth_is_none_when_mtls_is_configured_even_without_a_secret() {
        let mut args = base_args();
        args.tls_cert = Some(PathBuf::from("/does/not/matter/for/this/check.pem"));
        args.tls_key = Some(PathBuf::from("/does/not/matter/for/this/check.pem"));
        args.trust_bundle = Some(PathBuf::from("/does/not/matter/for/this/check.pem"));
        assert!(matches!(resolve_auth(&args), Ok(None)));
    }

    /// Each of the three flags alone -- and any two of three -- must be
    /// refused, not silently treated as "no mTLS" (which would downgrade to
    /// plaintext-equivalent HMAC-only behavior on what looks like a
    /// half-completed mTLS setup) or as "mTLS enabled" (which would attempt
    /// to load files that were never fully specified).
    #[test]
    fn load_mtls_config_refuses_a_partial_flag_set() {
        let combos: &[(bool, bool, bool)] = &[
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
        ];
        for &(cert, key, bundle) in combos {
            let mut args = base_args();
            let p = Some(PathBuf::from("/nonexistent.pem"));
            if cert {
                args.tls_cert = p.clone();
            }
            if key {
                args.tls_key = p.clone();
            }
            if bundle {
                args.trust_bundle = p;
            }
            assert!(
                load_mtls_config(&args).is_err(),
                "combo cert={cert} key={key} bundle={bundle} should be refused"
            );
        }
    }

    /// The property `--tls-cert`/`--tls-key`/`--trust-bundle` exist for,
    /// proven with a REAL TLS handshake rather than by inspecting
    /// `load_mtls_config`'s return value: a server built with
    /// `nucleus_identity::mtls`'s own primitives (the same code the node
    /// uses) requires and verifies a client certificate, and this module's
    /// `create_agent` — driven by the CLI flags exactly as a real invocation
    /// would set them — completes the handshake and receives the response.
    // `ureq` is blocking, and `health()` calls it directly (matching how
    // production code calls it) rather than through `spawn_blocking`. On the
    // default single-threaded test runtime that starves `server_handle`'s
    // task on the same worker -- a test-harness deadlock, not a TLS finding.
    // Two worker threads let the client's blocking call and the server's
    // task run concurrently, the same way they would as separate processes
    // in reality.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_client_completes_a_real_mtls_handshake() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let trust_domain = "cli-mtls-test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let server_identity = Identity::new(trust_domain, "system", "node");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let client_identity = Identity::new(trust_domain, "system", "cli");
        let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = ca
            .sign_csr(
                client_csr.csr(),
                client_csr.private_key(),
                &client_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client-cert.pem");
        let key_path = dir.path().join("client-key.pem");
        let bundle_path = dir.path().join("trust-bundle.pem");
        fs::write(&cert_path, client_cert.chain_pem()).unwrap();
        fs::write(&key_path, client_cert.private_key_pem()).unwrap();
        fs::write(
            &bundle_path,
            trust_bundle
                .roots()
                .iter()
                .map(|c| c.to_pem())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_trust_bundle = trust_bundle.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
                .build_acceptor()
                .unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with("GET /v1/health"),
                "server should have received the real request the agent sent"
            );
            tls.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
            )
            .await
            .unwrap();
        });

        let mut args = base_args();
        args.url = format!("https://{addr}");
        args.tls_cert = Some(cert_path);
        args.tls_key = Some(key_path);
        args.trust_bundle = Some(bundle_path);

        let agent = create_client(&args).unwrap();
        let secret = resolve_auth(&args).unwrap();
        assert!(
            secret.is_none(),
            "mTLS mode must not require an HMAC secret"
        );

        health(&agent, &args.url, secret.as_deref(), &args.actor)
            .await
            .expect("a real mTLS handshake against the SAME CA must succeed");

        server_handle.await.unwrap();
    }

    /// The refute half: `tls_certs_only` must actually be pinning to
    /// `--trust-bundle`'s roots, not accidentally falling back to a broader
    /// trust store. A server cert signed by an UNRELATED CA must be refused
    /// even though `danger_accept_invalid_hostnames` is set — proving that
    /// flag skips only the hostname check, not chain validation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_client_refuses_a_server_from_an_unrelated_ca() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
        use tokio::net::TcpListener;

        let real_domain = "cli-mtls-refuse-test.nucleus.local";
        let real_ca = SelfSignedCa::new(real_domain).unwrap();

        let client_identity = Identity::new(real_domain, "system", "cli");
        let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = real_ca
            .sign_csr(
                client_csr.csr(),
                client_csr.private_key(),
                &client_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // The server's cert and trust bundle come from a DIFFERENT CA than
        // the one the CLI is told to trust.
        let stranger_domain = "stranger.nucleus.local";
        let stranger_ca = SelfSignedCa::new(stranger_domain).unwrap();
        let server_identity = Identity::new(stranger_domain, "system", "node");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = stranger_ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let server_trust_bundle = stranger_ca.trust_bundle().clone();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client-cert.pem");
        let key_path = dir.path().join("client-key.pem");
        let bundle_path = dir.path().join("trust-bundle.pem");
        fs::write(&cert_path, client_cert.chain_pem()).unwrap();
        fs::write(&key_path, client_cert.private_key_pem()).unwrap();
        fs::write(
            // The REAL CA's bundle -- what the CLI is told to trust.
            &bundle_path,
            real_ca
                .trust_bundle()
                .roots()
                .iter()
                .map(|c| c.to_pem())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            let (stream, _peer) = tcp_listener.accept().await.unwrap();
            let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
                .build_acceptor()
                .unwrap();
            // The handshake itself may fail server-side too (the client's
            // cert isn't in the stranger CA's trust bundle either) -- either
            // side observing a failure is the property under test.
            let _ = acceptor.accept(stream).await;
        });

        let mut args = base_args();
        args.url = format!("https://{addr}");
        args.tls_cert = Some(cert_path);
        args.tls_key = Some(key_path);
        args.trust_bundle = Some(bundle_path);

        let agent = create_client(&args).unwrap();
        let secret = resolve_auth(&args).unwrap();

        let result = health(&agent, &args.url, secret.as_deref(), &args.actor).await;
        assert!(
            result.is_err(),
            "a server certificate from an unrelated CA must be refused, \
             even with hostname verification disabled"
        );

        server_handle.await.unwrap();
    }
}
