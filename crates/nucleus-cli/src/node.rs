//! Node command - interact with a running nucleus-node
//!
//! Test utilities for nucleus-node HTTP and gRPC APIs.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use nucleus_client::sign_http_headers;
use std::fs;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::PathBuf;
use std::time::Duration;

/// Interact with a running nucleus-node
#[derive(Args, Debug)]
pub struct NodeArgs {
    /// nucleus-node HTTP URL
    #[arg(
        long,
        default_value = "http://127.0.0.1:8080",
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

/// Execute the node command
pub async fn execute(args: NodeArgs) -> Result<()> {
    // Load auth secret
    let auth_secret = load_auth_secret(&args)?;

    match args.command {
        NodeCommand::Health => health(&args.url, &auth_secret, &args.actor).await,
        NodeCommand::Pods => list_pods(&args.url, &auth_secret, &args.actor).await,
        NodeCommand::Create { spec_file } => {
            create_pod(&args.url, &auth_secret, &args.actor, &spec_file).await
        }
        NodeCommand::Cancel { pod_id } => {
            cancel_pod(&args.url, &auth_secret, &args.actor, &pod_id).await
        }
        NodeCommand::Logs {
            pod_id,
            follow,
            offset,
        } => {
            stream_logs(
                &args.url,
                &auth_secret,
                &args.actor,
                &pod_id,
                follow,
                offset,
            )
            .await
        }
        NodeCommand::Sign { method, body } => {
            sign_request(&auth_secret, &args.actor, &method, body.as_deref())
        }
    }
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

fn create_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    config.into()
}

async fn health(url: &str, secret: &[u8], actor: &str) -> Result<()> {
    let agent = create_agent();
    let endpoint = format!("{url}/v1/health");

    let signed = sign_http_headers(secret, Some(actor), b"");

    let mut req = agent.get(&endpoint);
    for (key, value) in &signed.headers {
        req = req.header(key, value);
    }

    match req.call() {
        Ok(mut response) => {
            let body: serde_json::Value = response.body_mut().read_json()?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
        Err(ureq::Error::StatusCode(status)) => {
            bail!("Health check failed with status {status}");
        }
        Err(e) => bail!("Health check failed: {e}"),
    }
}

async fn list_pods(url: &str, secret: &[u8], actor: &str) -> Result<()> {
    let agent = create_agent();
    let endpoint = format!("{url}/v1/pods");

    let signed = sign_http_headers(secret, Some(actor), b"");

    let mut req = agent.get(&endpoint);
    for (key, value) in &signed.headers {
        req = req.header(key, value);
    }

    match req.call() {
        Ok(mut response) => {
            let body: serde_json::Value = response.body_mut().read_json()?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
        Err(ureq::Error::StatusCode(status)) => {
            bail!("List pods failed with status {status}");
        }
        Err(e) => bail!("List pods failed: {e}"),
    }
}

async fn create_pod(url: &str, secret: &[u8], actor: &str, spec_file: &PathBuf) -> Result<()> {
    let agent = create_agent();
    let endpoint = format!("{url}/v1/pods");

    // Read spec file
    let spec_content = fs::read_to_string(spec_file)
        .with_context(|| format!("Failed to read spec from {}", spec_file.display()))?;

    // Parse YAML to JSON
    let spec: serde_json::Value = serde_yaml::from_str(&spec_content)
        .with_context(|| format!("Invalid YAML in {}", spec_file.display()))?;

    let body = serde_json::to_string(&spec)?;
    let signed = sign_http_headers(secret, Some(actor), body.as_bytes());

    let mut req = agent.post(&endpoint);
    for (key, value) in &signed.headers {
        req = req.header(key, value);
    }
    req = req.header("content-type", "application/json");

    match req.send(&body) {
        Ok(mut response) => {
            let body: serde_json::Value = response.body_mut().read_json()?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
        Err(ureq::Error::StatusCode(status)) => {
            bail!("Create pod failed with status {status}");
        }
        Err(e) => bail!("Create pod failed: {e}"),
    }
}

async fn cancel_pod(url: &str, secret: &[u8], actor: &str, pod_id: &str) -> Result<()> {
    let agent = create_agent();
    let endpoint = format!("{url}/v1/pods/{pod_id}/cancel");

    let signed = sign_http_headers(secret, Some(actor), b"");

    let mut req = agent.post(&endpoint);
    for (key, value) in &signed.headers {
        req = req.header(key, value);
    }

    match req.send("") {
        Ok(_) => {
            println!("Cancelled pod {pod_id}");
            Ok(())
        }
        Err(ureq::Error::StatusCode(404)) => {
            bail!("Pod {pod_id} not found");
        }
        Err(ureq::Error::StatusCode(status)) => {
            bail!("Cancel pod failed with status {status}");
        }
        Err(e) => bail!("Cancel pod failed: {e}"),
    }
}

async fn stream_logs(
    url: &str,
    secret: &[u8],
    actor: &str,
    pod_id: &str,
    follow: bool,
    offset: u64,
) -> Result<()> {
    let agent = create_agent();
    let endpoint = format!("{url}/v1/pods/{pod_id}/logs?follow={follow}&offset={offset}");

    let signed = sign_http_headers(secret, Some(actor), b"");

    let mut req = agent.get(&endpoint);
    for (key, value) in &signed.headers {
        req = req.header(key, value);
    }

    match req.call() {
        Ok(response) => {
            // Stream the response body line by line
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
        Err(ureq::Error::StatusCode(404)) => {
            bail!("Pod {pod_id} not found");
        }
        Err(ureq::Error::StatusCode(status)) => {
            bail!("Stream logs failed with status {status}");
        }
        Err(e) => bail!("Stream logs failed: {e}"),
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
}
