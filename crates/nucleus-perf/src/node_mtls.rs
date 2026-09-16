//! The harness's one way to talk to a node: mTLS with a SPIFFE client identity.
//!
//! # Why this replaced request signing
//!
//! `podburst`, `toolcall` and `agency` signed node requests with the HMAC auth
//! secret. The node stopped accepting that in Move B — "mTLS with SPIFFE is the
//! only authentication method left" (`nucleus-node/src/auth.rs`) — so all three
//! failed at their first request against any current node, and nothing ran them
//! to notice. Found while building `guest-transcript`, which had to speak mTLS
//! from the start.
//!
//! The client has the same shape as `nucleus node`'s: the chain is verified
//! against the node's own CA and nothing else, and only hostname matching is
//! skipped, because the node's certificate names a SPIFFE URI, never a host.
//!
//! Calls to a pod's tool-proxy are not here: the node's signed proxy fronts
//! those, and `agency --local` signs its own.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// The client identity and the node's CA. Optional as flags so a mode that
/// reaches no node (`agency --local`) needs none; [`Node::connect`] refuses a
/// partial set.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct NodeTls {
    /// Client certificate PEM: a SPIFFE client identity the node authorizes.
    #[arg(long, env = "NUCLEUS_NODE_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,
    /// Client private key PEM.
    #[arg(long, env = "NUCLEUS_NODE_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
    /// The node's CA bundle PEM.
    #[arg(long, env = "NUCLEUS_NODE_TRUST_BUNDLE")]
    pub trust_bundle: Option<PathBuf>,
}

/// A node reached over mTLS. Cheap to clone; clones share the connection pool.
#[derive(Clone)]
pub struct Node {
    client: reqwest::blocking::Client,
    url: String,
}

impl Node {
    /// Build the client. All three of `tls` are required.
    pub fn connect(url: &str, tls: &NodeTls) -> Result<Self> {
        let (Some(cert), Some(key), Some(bundle)) =
            (&tls.tls_cert, &tls.tls_key, &tls.trust_bundle)
        else {
            bail!(
                "--tls-cert, --tls-key and --trust-bundle are all required to reach a node: it \
                 accepts mTLS with a SPIFFE client identity and nothing else"
            );
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut identity =
            std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
        identity.push(b'\n');
        identity.extend(std::fs::read(key).with_context(|| format!("reading {}", key.display()))?);
        let roots = reqwest::Certificate::from_pem_bundle(
            &std::fs::read(bundle).with_context(|| format!("reading {}", bundle.display()))?,
        )?;
        let client = reqwest::blocking::Client::builder()
            .identity(reqwest::Identity::from_pem(&identity)?)
            .tls_certs_only(roots)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            client,
            url: url.trim_end_matches('/').to_string(),
        })
    }

    /// GET a JSON body. The error carries the node's own words: a 4xx body is
    /// where it explains itself, and "status 400" alone turns a diagnosis into a
    /// guess.
    pub fn get_json(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{path}", self.url);
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status();
        let text = resp.text().map_err(|e| format!("{url}: body: {e}"))?;
        if !status.is_success() {
            return Err(format!("{url}: HTTP {status}: {}", text.trim()));
        }
        serde_json::from_str(&text).map_err(|e| format!("{url}: not JSON: {e}"))
    }

    fn post(&self, path: &str, body: &str, what: &str) -> Result<Value> {
        let resp = self
            .client
            .post(format!("{}{path}", self.url))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .with_context(|| what.to_string())?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!("{what}: HTTP {status}: {}", text.trim());
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).with_context(|| format!("{what}: unparseable response: {text}"))
    }

    /// Create a pod; its id.
    pub fn create_pod(&self, body: &str) -> Result<String> {
        let v = self.post("/v1/pods", body, "create pod")?;
        v.get("id")
            .or_else(|| v.get("pod_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .with_context(|| format!("no pod id in response: {v}"))
    }

    /// Create a pod; its id and the address of its tool-proxy.
    pub fn create_pod_with_proxy(&self, body: &str) -> Result<(String, String)> {
        let v = self.post("/v1/pods", body, "create pod")?;
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .with_context(|| format!("no pod id in response: {v}"))?;
        let proxy = v
            .get("proxy_addr")
            .and_then(Value::as_str)
            .with_context(|| format!("no proxy_addr in response: {v}"))?;
        Ok((id.to_string(), proxy.to_string()))
    }

    /// Every pod this identity may see. A non-2xx is an error, never an empty
    /// list: an auth failure that reads as "the node is up and idle" is a false
    /// pass.
    pub fn list_pods(&self) -> Result<Vec<Value>> {
        let v = self.get_json("/v1/pods").map_err(anyhow::Error::msg)?;
        Ok(v.get("pods")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.as_array().cloned())
            .unwrap_or_default())
    }

    pub fn cancel_pod(&self, id: &str) -> Result<()> {
        self.post(&format!("/v1/pods/{id}/cancel"), "", "cancel")
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A partial identity is refused by name rather than attempted: a half-set
    /// would otherwise surface as an opaque TLS handshake failure.
    #[test]
    fn a_partial_identity_is_refused_before_any_connection() {
        let partial = NodeTls {
            tls_cert: Some("/nonexistent/cert.pem".into()),
            tls_key: None,
            trust_bundle: None,
        };
        let Err(e) = Node::connect("https://127.0.0.1:1", &partial) else {
            panic!("a partial identity must not connect");
        };
        assert!(e.to_string().contains("all required"), "{e}");
    }
}
