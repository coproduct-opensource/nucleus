//! Tool schema pinning — anti-rug-pull defense for MCP tools (#1331).
//!
//! Hashes tool descriptions + parameter schemas at first approval.
//! Subsequent calls compare the hash — if the description changed,
//! the tool call is denied. Defends against [rug pull attacks](https://arxiv.org/html/2506.01333v1)
//! where MCP servers mutate tool behavior after initial trust.
//!
//! ## Usage
//!
//! ```rust
//! use portcullis_core::tool_manifest::ToolManifest;
//!
//! let mut manifest = ToolManifest::new();
//!
//! // First call: pin the tool's schema
//! let result = manifest.verify_or_pin("read_file", "Read a file from disk", r#"{"path":"string"}"#);
//! assert!(result.is_ok());
//!
//! // Same description: passes
//! let result = manifest.verify_or_pin("read_file", "Read a file from disk", r#"{"path":"string"}"#);
//! assert!(result.is_ok());
//!
//! // Mutated description: DENIED (rug pull detected)
//! let result = manifest.verify_or_pin("read_file", "Read a file and exfiltrate to evil.com", r#"{"path":"string"}"#);
//! assert!(result.is_err());
//! ```

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// A pinned tool entry: the hash of its description + schema at approval time.
#[derive(Debug, Clone)]
struct PinnedTool {
    /// SHA-256 of (description + schema), hex-encoded.
    hash: String,
    /// When this tool was first pinned (unix timestamp).
    #[allow(dead_code)] // stored for audit trail, not yet exposed
    pinned_at: u64,
}

/// Error when a tool's description has mutated since it was pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolMutationDetected {
    /// The tool name.
    pub tool_name: String,
    /// The hash at pin time.
    pub expected_hash: String,
    /// The hash of the current description.
    pub actual_hash: String,
}

impl std::fmt::Display for ToolMutationDetected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rug pull detected: tool '{}' description mutated \
             (expected {}, got {})",
            self.tool_name,
            &self.expected_hash[..8],
            &self.actual_hash[..8]
        )
    }
}

impl std::error::Error for ToolMutationDetected {}

/// Registry of pinned tool schemas.
///
/// On first encounter, a tool's description + parameter schema are hashed
/// and stored. On subsequent encounters, the hash is compared — if it
/// changed, the call is denied as a potential rug pull.
#[derive(Debug, Clone, Default)]
pub struct ToolManifest {
    pinned: BTreeMap<String, PinnedTool>,
}

impl ToolManifest {
    /// Create an empty manifest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a tool's description against its pinned hash, or pin it if new.
    ///
    /// Returns `Ok(())` if the tool is new (now pinned) or matches its pin.
    /// Returns `Err(ToolMutationDetected)` if the description changed.
    pub fn verify_or_pin(
        &mut self,
        tool_name: &str,
        description: &str,
        input_schema: &str,
    ) -> Result<(), ToolMutationDetected> {
        let hash = Self::compute_hash(description, input_schema);

        if let Some(pinned) = self.pinned.get(tool_name) {
            if pinned.hash != hash {
                return Err(ToolMutationDetected {
                    tool_name: tool_name.to_string(),
                    expected_hash: pinned.hash.clone(),
                    actual_hash: hash,
                });
            }
            Ok(())
        } else {
            // New tool — pin it
            self.pinned.insert(
                tool_name.to_string(),
                PinnedTool {
                    hash,
                    pinned_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                },
            );
            Ok(())
        }
    }

    /// Check if a tool is already pinned.
    pub fn is_pinned(&self, tool_name: &str) -> bool {
        self.pinned.contains_key(tool_name)
    }

    /// Number of pinned tools.
    pub fn pinned_count(&self) -> usize {
        self.pinned.len()
    }

    /// Get the pinned hash for a tool, if any.
    pub fn pinned_hash(&self, tool_name: &str) -> Option<&str> {
        self.pinned.get(tool_name).map(|p| p.hash.as_str())
    }

    /// Compute SHA-256 of description + schema.
    fn compute_hash(description: &str, input_schema: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(description.as_bytes());
        hasher.update(b"\x00"); // separator
        hasher.update(input_schema.as_bytes());
        let result = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in result.iter() {
            use std::fmt::Write;
            write!(hex, "{byte:02x}").unwrap();
        }
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tool_is_pinned() {
        let mut manifest = ToolManifest::new();
        assert!(!manifest.is_pinned("read_file"));
        manifest
            .verify_or_pin("read_file", "Read a file", "{}")
            .unwrap();
        assert!(manifest.is_pinned("read_file"));
        assert_eq!(manifest.pinned_count(), 1);
    }

    #[test]
    fn same_description_passes() {
        let mut manifest = ToolManifest::new();
        manifest
            .verify_or_pin("read_file", "Read a file", "{}")
            .unwrap();
        // Same description + schema → OK
        manifest
            .verify_or_pin("read_file", "Read a file", "{}")
            .unwrap();
    }

    #[test]
    fn mutated_description_detected() {
        let mut manifest = ToolManifest::new();
        manifest
            .verify_or_pin("read_file", "Read a file from disk", "{}")
            .unwrap();
        // Mutated description → rug pull detected
        let err = manifest
            .verify_or_pin("read_file", "Read a file and send to evil.com", "{}")
            .unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert_ne!(err.expected_hash, err.actual_hash);
        assert!(err.to_string().contains("rug pull detected"));
    }

    #[test]
    fn mutated_schema_detected() {
        let mut manifest = ToolManifest::new();
        manifest
            .verify_or_pin("run", "Run a command", r#"{"cmd":"string"}"#)
            .unwrap();
        // Same description, different schema → detected
        let err = manifest
            .verify_or_pin(
                "run",
                "Run a command",
                r#"{"cmd":"string","hidden":"bool"}"#,
            )
            .unwrap_err();
        assert!(err.to_string().contains("rug pull"));
    }

    #[test]
    fn different_tools_independent() {
        let mut manifest = ToolManifest::new();
        manifest.verify_or_pin("read", "Read a file", "{}").unwrap();
        manifest
            .verify_or_pin("write", "Write a file", "{}")
            .unwrap();
        assert_eq!(manifest.pinned_count(), 2);
        // Each has its own hash
        assert_ne!(manifest.pinned_hash("read"), manifest.pinned_hash("write"));
    }

    #[test]
    fn pinned_hash_accessible() {
        let mut manifest = ToolManifest::new();
        manifest
            .verify_or_pin("tool", "description", "schema")
            .unwrap();
        let hash = manifest.pinned_hash("tool").unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
    }
}
