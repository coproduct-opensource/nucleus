//! MCP server registry — allowlist + namespace scoping (#1334).
//!
//! Prevents [tool shadowing](https://modelcontextprotocol-security.io/ttps/tool-poisoning/tool-shadowing/)
//! by requiring MCP servers to be registered before their tools are accepted.
//! Tools are namespaced by server ID to prevent collisions.
//!
//! ## Usage
//!
//! ```rust
//! use portcullis_core::server_registry::ServerRegistry;
//!
//! let mut registry = ServerRegistry::new();
//!
//! // Register trusted servers
//! registry.trust("filesystem", "Local filesystem access");
//! registry.trust("github-api", "GitHub API integration");
//!
//! // Namespaced tool registration
//! assert!(registry.register_tool("filesystem", "read_file").is_ok());
//! assert!(registry.register_tool("unknown-server", "read_file").is_err());
//!
//! // Tool lookup by namespaced name
//! assert!(registry.is_tool_registered("filesystem/read_file"));
//! assert!(!registry.is_tool_registered("unknown/read_file"));
//! ```

use std::collections::{BTreeMap, BTreeSet};

/// Error when a server or tool registration is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The server is not in the allowlist.
    UntrustedServer { server_id: String },
    /// A tool with this namespaced name is already registered by a different server.
    ToolCollision {
        tool_name: String,
        existing_server: String,
        requesting_server: String,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedServer { server_id } => {
                write!(
                    f,
                    "untrusted MCP server: '{server_id}' is not in the allowlist"
                )
            }
            Self::ToolCollision {
                tool_name,
                existing_server,
                requesting_server,
            } => write!(
                f,
                "tool collision: '{tool_name}' already registered by '{existing_server}', \
                 denied for '{requesting_server}'"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// A trusted MCP server entry.
#[derive(Debug, Clone)]
struct TrustedServer {
    #[allow(dead_code)] // stored for audit, not yet exposed
    description: String,
    tools: BTreeSet<String>,
}

/// Registry of trusted MCP servers and their namespaced tools.
///
/// Only servers in the allowlist can register tools. Tools are namespaced
/// by `server_id/tool_name` to prevent shadowing collisions.
#[derive(Debug, Clone, Default)]
pub struct ServerRegistry {
    servers: BTreeMap<String, TrustedServer>,
    /// Reverse map: bare tool name → server that owns it.
    /// Detects collisions when two servers try to register the same tool name.
    tool_owners: BTreeMap<String, String>,
}

impl ServerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a server to the allowlist.
    pub fn trust(&mut self, server_id: impl Into<String>, description: impl Into<String>) {
        let id = server_id.into();
        self.servers.entry(id).or_insert_with(|| TrustedServer {
            description: description.into(),
            tools: BTreeSet::new(),
        });
    }

    /// Check if a server is trusted.
    pub fn is_trusted(&self, server_id: &str) -> bool {
        self.servers.contains_key(server_id)
    }

    /// Register a tool from a trusted server.
    ///
    /// Returns `Err` if the server isn't trusted or if another server
    /// already owns a tool with the same bare name.
    pub fn register_tool(&mut self, server_id: &str, tool_name: &str) -> Result<(), RegistryError> {
        // Check server is trusted
        if !self.servers.contains_key(server_id) {
            return Err(RegistryError::UntrustedServer {
                server_id: server_id.to_string(),
            });
        }

        // Check for collisions
        if let Some(existing) = self.tool_owners.get(tool_name)
            && existing != server_id
        {
            return Err(RegistryError::ToolCollision {
                tool_name: tool_name.to_string(),
                existing_server: existing.clone(),
                requesting_server: server_id.to_string(),
            });
        }

        // Register the tool
        self.tool_owners
            .insert(tool_name.to_string(), server_id.to_string());
        if let Some(server) = self.servers.get_mut(server_id) {
            server.tools.insert(tool_name.to_string());
        }
        Ok(())
    }

    /// Check if a namespaced tool is registered (format: "server_id/tool_name").
    pub fn is_tool_registered(&self, namespaced: &str) -> bool {
        if let Some((server_id, tool_name)) = namespaced.split_once('/') {
            self.servers
                .get(server_id)
                .is_some_and(|s| s.tools.contains(tool_name))
        } else {
            false
        }
    }

    /// Resolve a bare tool name to its owning server.
    pub fn tool_owner(&self, tool_name: &str) -> Option<&str> {
        self.tool_owners.get(tool_name).map(|s| s.as_str())
    }

    /// Number of trusted servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Number of registered tools across all servers.
    pub fn tool_count(&self) -> usize {
        self.tool_owners.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_server_rejected() {
        let mut reg = ServerRegistry::new();
        let err = reg.register_tool("evil", "read_file").unwrap_err();
        assert!(matches!(err, RegistryError::UntrustedServer { .. }));
        assert!(err.to_string().contains("not in the allowlist"));
    }

    #[test]
    fn trusted_server_can_register_tools() {
        let mut reg = ServerRegistry::new();
        reg.trust("fs", "filesystem");
        reg.register_tool("fs", "read_file").unwrap();
        reg.register_tool("fs", "write_file").unwrap();
        assert_eq!(reg.tool_count(), 2);
        assert!(reg.is_tool_registered("fs/read_file"));
    }

    #[test]
    fn tool_collision_detected() {
        let mut reg = ServerRegistry::new();
        reg.trust("legit", "legitimate server");
        reg.trust("evil", "malicious server");
        reg.register_tool("legit", "read_file").unwrap();
        let err = reg.register_tool("evil", "read_file").unwrap_err();
        assert!(matches!(err, RegistryError::ToolCollision { .. }));
        assert!(err.to_string().contains("already registered by"));
    }

    #[test]
    fn same_server_can_re_register() {
        let mut reg = ServerRegistry::new();
        reg.trust("fs", "filesystem");
        reg.register_tool("fs", "read_file").unwrap();
        reg.register_tool("fs", "read_file").unwrap(); // idempotent
        assert_eq!(reg.tool_count(), 1);
    }

    #[test]
    fn tool_owner_lookup() {
        let mut reg = ServerRegistry::new();
        reg.trust("github", "GitHub API");
        reg.register_tool("github", "create_pr").unwrap();
        assert_eq!(reg.tool_owner("create_pr"), Some("github"));
        assert_eq!(reg.tool_owner("unknown"), None);
    }

    #[test]
    fn namespaced_lookup_requires_slash() {
        let reg = ServerRegistry::new();
        assert!(!reg.is_tool_registered("no_slash_here"));
    }
}
