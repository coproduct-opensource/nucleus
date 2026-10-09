//! Name resolution, on the host (ADR 0015 §3). The guest has no resolver;
//! the proxy resolves the name the request carries, once per request, and
//! connects to that answer after [`crate::address::admit`] has checked it.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;

use crate::Refusal;

/// A resolver the proxy asks for a name's addresses.
pub trait Resolve: Send + Sync + 'static {
    /// The addresses `name` resolves to.
    fn resolve(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, Refusal>> + Send;
}

/// The resolver the E2 binary runs with: the proxy's network namespace has
/// no route out yet, so it resolves nothing.
///
/// The node starts the proxy in a fresh, empty network namespace. The
/// plumbing that gives that namespace a public-only route out lands with the
/// step that first sends a guest's traffic here (E6), together with a
/// resolver that reads the host's configuration before the proxy drops its
/// filesystem access. Until then every name is [`Refusal::NoOutboundPath`]:
/// unavailable, never a fallback.
#[derive(Debug, Clone, Copy)]
pub struct NoOutboundPath;

impl Resolve for NoOutboundPath {
    async fn resolve(&self, _name: &str) -> Result<Vec<IpAddr>, Refusal> {
        Err(Refusal::NoOutboundPath)
    }
}

/// A fixed table, for tests and fixtures: a name not in it does not resolve.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    table: BTreeMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    /// A resolver answering `name` with `addresses`.
    #[must_use]
    pub fn with(mut self, name: &str, addresses: &[IpAddr]) -> Self {
        self.table.insert(name.to_string(), addresses.to_vec());
        self
    }
}

impl Resolve for StaticResolver {
    async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, Refusal> {
        self.table.get(name).cloned().ok_or(Refusal::ResolveFailed)
    }
}
