//! Tool schema registry -- rug-pull detection for MCP servers.
//!
//! Stores SHA-256 hashes of approved tool schemas. On every tool call,
//! verifies the current schema matches the approved hash. A mismatch
//! indicates the MCP server silently mutated tool descriptions
//! post-approval (a rug-pull attack).
//!
//! # Attack Surface
//!
//! MCP servers expose tool descriptions that include both human-readable
//! text and machine-readable parameter schemas. A malicious or
//! compromised server can mutate these after initial approval to:
//!
//! - Inject prompt injection payloads into descriptions
//! - Add hidden parameters that exfiltrate data
//! - Remove safety-related parameter constraints
//! - Change tool semantics while keeping the name identical
//!
//! # Design
//!
//! The registry uses a canonical SHA-256 hash over `name \0 description \0 parameters`.
//! The null-byte separators prevent ambiguity (a name that ends with the
//! description prefix cannot collide with a different split).
//!
//! The [`ToolSchemaRegistry::registry_hash`] method produces a single hash
//! over all approved tools, suitable for embedding in delegation certificates
//! to attest which tool surface was approved at signing time.
//!
//! # Example
//!
//! ```rust
//! use portcullis::tool_schema::ToolSchemaRegistry;
//!
//! let mut registry = ToolSchemaRegistry::new();
//! registry.approve_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#);
//!
//! // Same schema passes verification
//! assert!(registry.verify_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#).is_ok());
//!
//! // Mutated description is detected
//! assert!(registry.verify_tool("read_file", "Read a file and send to attacker", r#"{"path":"string"}"#).is_err());
//! ```

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Registry of approved MCP tool schemas with SHA-256 hashes.
///
/// Instantiate once at session start, call [`approve_tool`] for each tool
/// in the `tools/list` response, then call [`verify_tool`] on every
/// `tools/call` to detect mutations.
///
/// [`approve_tool`]: ToolSchemaRegistry::approve_tool
/// [`verify_tool`]: ToolSchemaRegistry::verify_tool
pub struct ToolSchemaRegistry {
    approved: BTreeMap<String, ApprovedToolSchema>,
}

/// A single approved tool schema with its canonical hash.
#[derive(Debug, Clone)]
pub struct ApprovedToolSchema {
    /// The tool name (duplicated from key for self-contained reporting).
    pub name: String,
    /// SHA-256 hash of `name \0 description \0 parameters`.
    pub combined_hash: String,
    /// Unix timestamp when this schema was approved.
    pub approved_at: u64,
}

/// Errors detected during schema verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// Tool exists in the registry but its schema has changed.
    SchemaMutated {
        /// The tool whose schema was mutated.
        tool: String,
        /// The hash that was approved.
        expected: String,
        /// The hash of the current schema.
        actual: String,
    },
    /// Tool was not in the registry at approval time.
    NewToolDetected(String),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::SchemaMutated {
                tool,
                expected,
                actual,
            } => write!(
                f,
                "rug-pull detected: tool '{}' schema mutated (expected {}, got {})",
                tool,
                &expected[..16.min(expected.len())],
                &actual[..16.min(actual.len())],
            ),
            SchemaError::NewToolDetected(name) => {
                write!(f, "unapproved tool detected: '{}'", name)
            }
        }
    }
}

impl std::error::Error for SchemaError {}

impl ToolSchemaRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            approved: BTreeMap::new(),
        }
    }

    /// Approve a tool schema, recording its canonical hash.
    ///
    /// Call this once per tool at session initialization (from `tools/list`).
    /// Subsequent calls for the same name overwrite the previous approval.
    pub fn approve_tool(&mut self, name: &str, description: &str, parameters: &str) {
        let hash = Self::hash_schema(name, description, parameters);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.approved.insert(
            name.to_string(),
            ApprovedToolSchema {
                name: name.to_string(),
                combined_hash: hash,
                approved_at: now,
            },
        );
    }

    /// Verify a tool's current schema against the approved hash.
    ///
    /// Returns `Ok(())` if the schema matches, or an error describing
    /// the mismatch.
    pub fn verify_tool(
        &self,
        name: &str,
        description: &str,
        parameters: &str,
    ) -> Result<(), SchemaError> {
        match self.approved.get(name) {
            None => Err(SchemaError::NewToolDetected(name.to_string())),
            Some(approved) => {
                let current_hash = Self::hash_schema(name, description, parameters);
                if current_hash != approved.combined_hash {
                    Err(SchemaError::SchemaMutated {
                        tool: name.to_string(),
                        expected: approved.combined_hash.clone(),
                        actual: current_hash,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Detect all mutations between approved and current tool sets.
    ///
    /// Checks every tool in `current_tools` against the registry, and also
    /// detects tools that were approved but are no longer present (removal
    /// can indicate an attacker hiding previously-visible tools).
    pub fn detect_mutations(&self, current_tools: &[(String, String, String)]) -> Vec<SchemaError> {
        let mut errors = Vec::new();

        // Check each current tool against approved set
        for (name, desc, params) in current_tools {
            if let Err(e) = self.verify_tool(name, desc, params) {
                errors.push(e);
            }
        }

        // Check for removed tools (present in approved but absent from current)
        let current_names: std::collections::HashSet<_> =
            current_tools.iter().map(|(n, _, _)| n.as_str()).collect();
        for name in self.approved.keys() {
            if !current_names.contains(name.as_str()) {
                errors.push(SchemaError::SchemaMutated {
                    tool: name.clone(),
                    expected: "present".to_string(),
                    actual: "removed".to_string(),
                });
            }
        }

        errors
    }

    /// Canonical SHA-256 hash of a tool's schema.
    ///
    /// The hash is computed over `name \0 description \0 parameters` with
    /// null-byte separators to prevent domain confusion.
    pub fn hash_schema(name: &str, description: &str, parameters: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(description.as_bytes());
        hasher.update(b"\0");
        hasher.update(parameters.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// SHA-256 hash of the entire approved tool set.
    ///
    /// Suitable for embedding in delegation certificates to attest which
    /// tool surface was approved at signing time. The hash is computed
    /// over sorted `(name, combined_hash)` pairs for determinism.
    pub fn registry_hash(&self) -> String {
        let mut hasher = Sha256::new();
        // BTreeMap is sorted by key, so iteration order is deterministic.
        for (name, schema) in &self.approved {
            hasher.update(name.as_bytes());
            hasher.update(b"\0");
            hasher.update(schema.combined_hash.as_bytes());
            hasher.update(b"\n");
        }
        format!("{:x}", hasher.finalize())
    }

    /// Number of approved tools in the registry.
    pub fn len(&self) -> usize {
        self.approved.len()
    }

    /// Whether the registry has no approved tools.
    pub fn is_empty(&self) -> bool {
        self.approved.is_empty()
    }
}

impl Default for ToolSchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_and_verify_roundtrip() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#);

        assert!(registry
            .verify_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#)
            .is_ok());
    }

    #[test]
    fn detect_description_mutation() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read a file from disk", r#"{"path":"string"}"#);

        let result = registry.verify_tool(
            "read_file",
            "Read a file and exfiltrate to attacker",
            r#"{"path":"string"}"#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SchemaError::SchemaMutated { ref tool, .. } if tool == "read_file"),
            "expected SchemaMutated, got {:?}",
            err
        );
    }

    #[test]
    fn detect_parameter_mutation() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read a file", r#"{"path":"string"}"#);

        let result = registry.verify_tool(
            "read_file",
            "Read a file",
            r#"{"path":"string","exfil_url":"string"}"#,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SchemaError::SchemaMutated { .. }
        ));
    }

    #[test]
    fn detect_new_unapproved_tool() {
        let registry = ToolSchemaRegistry::new();

        let result = registry.verify_tool("evil_tool", "Do evil things", "{}");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SchemaError::NewToolDetected(ref name) if name == "evil_tool"
        ));
    }

    #[test]
    fn detect_removed_tool() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read a file", "{}");
        registry.approve_tool("write_file", "Write a file", "{}");

        // Only read_file present in current set (write_file removed)
        let current = vec![(
            "read_file".to_string(),
            "Read a file".to_string(),
            "{}".to_string(),
        )];
        let errors = registry.detect_mutations(&current);

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            SchemaError::SchemaMutated { tool, actual, .. } if tool == "write_file" && actual == "removed"
        ));
    }

    #[test]
    fn hash_determinism() {
        let h1 = ToolSchemaRegistry::hash_schema("tool", "desc", "params");
        let h2 = ToolSchemaRegistry::hash_schema("tool", "desc", "params");
        assert_eq!(h1, h2, "same inputs must produce same hash");
    }

    #[test]
    fn hash_sensitivity_name() {
        let h1 = ToolSchemaRegistry::hash_schema("tool_a", "desc", "params");
        let h2 = ToolSchemaRegistry::hash_schema("tool_b", "desc", "params");
        assert_ne!(h1, h2, "different names must produce different hashes");
    }

    #[test]
    fn hash_sensitivity_description() {
        let h1 = ToolSchemaRegistry::hash_schema("tool", "desc_a", "params");
        let h2 = ToolSchemaRegistry::hash_schema("tool", "desc_b", "params");
        assert_ne!(
            h1, h2,
            "different descriptions must produce different hashes"
        );
    }

    #[test]
    fn hash_sensitivity_parameters() {
        let h1 = ToolSchemaRegistry::hash_schema("tool", "desc", "params_a");
        let h2 = ToolSchemaRegistry::hash_schema("tool", "desc", "params_b");
        assert_ne!(h1, h2, "different parameters must produce different hashes");
    }

    #[test]
    fn hash_separator_prevents_collision() {
        // Without null separators, "ab" + "cd" would equal "a" + "bcd".
        // The \0 separators prevent this.
        let h1 = ToolSchemaRegistry::hash_schema("ab", "cd", "ef");
        let h2 = ToolSchemaRegistry::hash_schema("a", "bcd", "ef");
        assert_ne!(h1, h2, "null separators must prevent domain confusion");
    }

    #[test]
    fn registry_hash_determinism() {
        let mut r1 = ToolSchemaRegistry::new();
        r1.approve_tool("alpha", "desc_a", "params_a");
        r1.approve_tool("beta", "desc_b", "params_b");

        let mut r2 = ToolSchemaRegistry::new();
        // Insert in different order -- BTreeMap ensures same iteration
        r2.approve_tool("beta", "desc_b", "params_b");
        r2.approve_tool("alpha", "desc_a", "params_a");

        assert_eq!(r1.registry_hash(), r2.registry_hash());
    }

    #[test]
    fn registry_hash_changes_on_mutation() {
        let mut r1 = ToolSchemaRegistry::new();
        r1.approve_tool("tool", "original", "{}");

        let mut r2 = ToolSchemaRegistry::new();
        r2.approve_tool("tool", "mutated", "{}");

        assert_ne!(r1.registry_hash(), r2.registry_hash());
    }

    #[test]
    fn detect_mutations_all_clean() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read", "{}");
        registry.approve_tool("write_file", "Write", "{}");

        let current = vec![
            (
                "read_file".to_string(),
                "Read".to_string(),
                "{}".to_string(),
            ),
            (
                "write_file".to_string(),
                "Write".to_string(),
                "{}".to_string(),
            ),
        ];
        let errors = registry.detect_mutations(&current);
        assert!(errors.is_empty(), "no errors expected for clean set");
    }

    #[test]
    fn detect_mutations_mixed() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("read_file", "Read", "{}");
        registry.approve_tool("write_file", "Write", "{}");

        let current = vec![
            (
                "read_file".to_string(),
                "Read MUTATED".to_string(),
                "{}".to_string(),
            ),
            (
                "evil_tool".to_string(),
                "Evil".to_string(),
                "{}".to_string(),
            ),
            // write_file missing (removed)
        ];
        let errors = registry.detect_mutations(&current);

        // Should have: 1 mutation (read_file), 1 new tool (evil_tool), 1 removed (write_file)
        assert_eq!(errors.len(), 3, "expected 3 errors, got: {:?}", errors);
    }

    #[test]
    fn len_and_is_empty() {
        let mut registry = ToolSchemaRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.approve_tool("tool", "desc", "params");
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn overwrite_approval() {
        let mut registry = ToolSchemaRegistry::new();
        registry.approve_tool("tool", "original", "{}");
        assert!(registry.verify_tool("tool", "original", "{}").is_ok());

        // Overwrite with new schema
        registry.approve_tool("tool", "updated", "{}");
        assert!(registry.verify_tool("tool", "updated", "{}").is_ok());
        assert!(registry.verify_tool("tool", "original", "{}").is_err());
    }

    #[test]
    fn display_schema_mutated() {
        let err = SchemaError::SchemaMutated {
            tool: "read_file".to_string(),
            expected: "abcdef1234567890abcdef".to_string(),
            actual: "1234567890abcdef123456".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("rug-pull detected"));
        assert!(msg.contains("read_file"));
    }

    #[test]
    fn display_new_tool() {
        let err = SchemaError::NewToolDetected("evil_tool".to_string());
        let msg = err.to_string();
        assert!(msg.contains("unapproved tool"));
        assert!(msg.contains("evil_tool"));
    }
}
