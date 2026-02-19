//! Unified facade for nucleus services.
//!
//! [`Nucleus`] is the main entry point, combining proxy and node clients.
//! Use [`NucleusBuilder`] for ergonomic construction.

use std::sync::Arc;

use crate::auth::{AuthStrategy, MtlsConfig};
use crate::intent::{Intent, IntentProfile, IntentSession};
use crate::node::NodeClient;
use crate::proxy::ProxyClient;
use crate::Error;

/// Unified facade for nucleus services.
///
/// Provides access to both the tool-proxy (HTTP) and node (gRPC) services,
/// as well as the intent system for scoped permission sessions.
///
/// # Example
///
/// ```rust,no_run
/// use nucleus_sdk::{Nucleus, HmacAuth, Intent};
///
/// # async fn example() -> nucleus_sdk::Result<()> {
/// let nucleus = Nucleus::builder()
///     .proxy_url("http://127.0.0.1:8080")
///     .node_url("http://localhost:4001")
///     .auth(HmacAuth::new(b"secret", Some("user")))
///     .build()?;
///
/// // Direct proxy access
/// let proxy = nucleus.proxy()?;
/// let contents = proxy.read("src/main.rs").await?;
///
/// // Intent-scoped session
/// let session = nucleus.intent(Intent::CodeReview).await?;
/// let files = session.glob("**/*.rs", None, None).await?;
/// # Ok(())
/// # }
/// ```
pub struct Nucleus {
    proxy_url: Option<String>,
    node_url: Option<String>,
    auth: Option<Arc<dyn AuthStrategy>>,
    mtls: Option<MtlsConfig>,
}

impl Nucleus {
    /// Create a builder for configuring a Nucleus instance.
    pub fn builder() -> NucleusBuilder {
        NucleusBuilder::default()
    }

    /// Create a [`ProxyClient`] for the configured proxy URL.
    pub fn proxy(&self) -> Result<ProxyClient, Error> {
        let url = self.proxy_url.as_ref().ok_or_else(|| {
            Error::Config("proxy_url is required to create a ProxyClient".to_string())
        })?;
        self.proxy_at(url)
    }

    /// Create a [`ProxyClient`] pointing at a specific tool-proxy address.
    pub fn proxy_at(&self, url: &str) -> Result<ProxyClient, Error> {
        let auth: Option<Box<dyn AuthStrategy>> = self
            .auth
            .as_ref()
            .map(|a| Box::new(SharedAuth(Arc::clone(a))) as Box<dyn AuthStrategy>);
        ProxyClient::new(url, auth, self.mtls.as_ref())
    }

    /// Connect to the nucleus-node gRPC service.
    pub async fn node(&self) -> Result<NodeClient, Error> {
        let url = self.node_url.as_ref().ok_or_else(|| {
            Error::Config("node_url is required to create a NodeClient".to_string())
        })?;
        let auth: Option<Box<dyn AuthStrategy>> = self
            .auth
            .as_ref()
            .map(|a| Box::new(SharedAuth(Arc::clone(a))) as Box<dyn AuthStrategy>);
        NodeClient::connect(url, auth).await
    }

    /// Open an intent session.
    ///
    /// If `proxy_url` is configured, wraps the proxy directly with the intent profile.
    /// If only `node_url` is configured, creates a pod via gRPC and connects to
    /// its tool-proxy.
    pub async fn intent(&self, intent: Intent) -> Result<IntentSession, Error> {
        let profile = IntentProfile::resolve(intent)?;

        if let Some(proxy_url) = &self.proxy_url {
            let proxy = self.proxy_at(proxy_url)?;
            return Ok(IntentSession::new(proxy, profile, None));
        }

        let _node_url = self.node_url.as_ref().ok_or_else(|| {
            Error::Config("proxy_url or node_url is required to open an intent".to_string())
        })?;

        // Create a pod via gRPC with the intent's profile
        let node = self.node().await?;
        let spec = nucleus_spec::PodSpec::new(nucleus_spec::PodSpecInner {
            work_dir: ".".into(),
            timeout_seconds: 3600,
            policy: nucleus_spec::PolicySpec::Profile {
                name: profile.profile_name.to_string(),
            },
            budget_model: None,
            resources: None,
            network: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            credentials: None,
        });

        let result = node.create_pod(&spec).await?;
        if result.proxy_addr.is_empty() {
            return Err(Error::Other(
                "pod created but proxy address missing".to_string(),
            ));
        }

        let proxy = self.proxy_at(&result.proxy_addr)?;
        Ok(IntentSession::new(proxy, profile, Some(result.id)))
    }
}

/// Wrapper that delegates AuthStrategy to an Arc<dyn AuthStrategy>.
struct SharedAuth(Arc<dyn AuthStrategy>);

impl AuthStrategy for SharedAuth {
    fn sign_http(&self, body: &[u8]) -> Vec<(String, String)> {
        self.0.sign_http(body)
    }

    fn sign_grpc(&self, method: &str) -> Vec<(String, String)> {
        self.0.sign_grpc(method)
    }
}

/// Builder for [`Nucleus`].
///
/// At least one of `proxy_url` or `node_url` should be set.
#[derive(Default)]
pub struct NucleusBuilder {
    proxy_url: Option<String>,
    node_url: Option<String>,
    auth: Option<Arc<dyn AuthStrategy>>,
    mtls: Option<MtlsConfig>,
}

impl NucleusBuilder {
    /// Set the tool-proxy URL (e.g., `http://127.0.0.1:8080`).
    pub fn proxy_url(mut self, url: impl Into<String>) -> Self {
        self.proxy_url = Some(url.into());
        self
    }

    /// Set the nucleus-node gRPC URL (e.g., `http://localhost:4001`).
    pub fn node_url(mut self, url: impl Into<String>) -> Self {
        self.node_url = Some(url.into());
        self
    }

    /// Set the authentication strategy.
    pub fn auth(mut self, auth: impl AuthStrategy + 'static) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    /// Set mTLS configuration.
    pub fn mtls(mut self, config: MtlsConfig) -> Self {
        self.mtls = Some(config);
        self
    }

    /// Build the [`Nucleus`] instance.
    pub fn build(self) -> Result<Nucleus, Error> {
        if self.proxy_url.is_none() && self.node_url.is_none() {
            return Err(Error::Config(
                "at least one of proxy_url or node_url must be set".to_string(),
            ));
        }

        Ok(Nucleus {
            proxy_url: self.proxy_url,
            node_url: self.node_url,
            auth: self.auth,
            mtls: self.mtls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_requires_url() {
        let result = Nucleus::builder().build();
        assert!(result.is_err());
        let err = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        assert!(err
            .to_string()
            .contains("at least one of proxy_url or node_url"));
    }

    #[test]
    fn test_builder_with_proxy_url() {
        let nucleus = Nucleus::builder()
            .proxy_url("http://localhost:8080")
            .build()
            .unwrap();
        assert_eq!(nucleus.proxy_url.as_deref(), Some("http://localhost:8080"));
        assert!(nucleus.node_url.is_none());
    }

    #[test]
    fn test_builder_with_both_urls() {
        let nucleus = Nucleus::builder()
            .proxy_url("http://localhost:8080")
            .node_url("http://localhost:4001")
            .build()
            .unwrap();
        assert!(nucleus.proxy_url.is_some());
        assert!(nucleus.node_url.is_some());
    }

    #[test]
    fn test_builder_with_auth() {
        use crate::auth::HmacAuth;

        let nucleus = Nucleus::builder()
            .proxy_url("http://localhost:8080")
            .auth(HmacAuth::new(b"secret", Some("user")))
            .build()
            .unwrap();
        assert!(nucleus.auth.is_some());
    }

    #[test]
    fn test_proxy_requires_url() {
        let nucleus = Nucleus::builder()
            .node_url("http://localhost:4001")
            .build()
            .unwrap();
        let result = nucleus.proxy();
        assert!(result.is_err());
        let err = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        assert!(err.to_string().contains("proxy_url is required"));
    }

    #[test]
    fn test_proxy_at_custom_url() {
        let nucleus = Nucleus::builder()
            .proxy_url("http://localhost:8080")
            .build()
            .unwrap();
        let proxy = nucleus.proxy_at("http://other:9090");
        assert!(proxy.is_ok());
    }
}
