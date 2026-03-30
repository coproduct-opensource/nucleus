//! Manifest registry — loads, validates, and stores MCP tool manifests.
//!
//! Loads manifests from `.nucleus/manifests/*.toml` in the project directory.
//! Each manifest declares the tool's capabilities, data sources, sinks,
//! and output labels. Admission control rejects unsafe combinations before
//! the tool is allowed to serve.
//!
//! ## TOML Format
//!
//! ```toml
//! [tool]
//! name = "github__search_repos"
//! capabilities = ["read_files", "web_fetch"]
//! remote_fetch = true
//! instruction_sources = ["user_prompt", "static"]
//! admissible_sinks = ["local_memory", "human_visible"]
//! max_confidentiality = "internal"
//! output_integrity = "untrusted"
//! output_authority = "informational"
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use portcullis_core::manifest::{
    check_admission, AdmissionDenyReason, AdmissionVerdict, InstructionSource, SinkClass,
    ToolManifest, ToolName,
};
use portcullis_core::{AuthorityLevel, ConfLevel, IntegLevel, Operation};
use serde::Deserialize;

/// A loaded and validated manifest registry.
#[derive(Debug, Default)]
pub struct ManifestRegistry {
    /// Admitted tools: MCP tool name → manifest.
    tools: BTreeMap<String, ToolManifest>,
    /// Rejected tools: MCP tool name → reason.
    rejected: BTreeMap<String, AdmissionDenyReason>,
}

/// TOML-deserializable manifest format.
#[derive(Deserialize)]
struct ManifestFile {
    tool: ToolEntry,
}

#[derive(Deserialize)]
struct ToolEntry {
    name: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    remote_fetch: bool,
    #[serde(default)]
    instruction_sources: Vec<String>,
    #[serde(default)]
    admissible_sinks: Vec<String>,
    #[serde(default = "default_conf")]
    max_confidentiality: String,
    #[serde(default = "default_integ")]
    output_integrity: String,
    #[serde(default = "default_auth")]
    output_authority: String,
}

fn default_conf() -> String {
    "public".to_string()
}
fn default_integ() -> String {
    "untrusted".to_string()
}
fn default_auth() -> String {
    "no_authority".to_string()
}

impl ManifestRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load manifests from `.nucleus/manifests/` in the given directory.
    ///
    /// Each `.toml` file is parsed, converted, and run through admission
    /// control. Admitted tools are stored; rejected tools are logged.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut registry = Self::new();
        let manifest_dir = dir.join(".nucleus").join("manifests");

        if !manifest_dir.is_dir() {
            return registry;
        }

        let entries = match std::fs::read_dir(&manifest_dir) {
            Ok(e) => e,
            Err(_) => return registry,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    registry.load_toml(&content);
                }
            }
        }

        registry
    }

    /// Parse and register a single manifest from TOML content.
    pub fn load_toml(&mut self, content: &str) {
        let file: ManifestFile = match toml::from_str(content) {
            Ok(f) => f,
            Err(_) => return,
        };

        let manifest = match convert_entry(&file.tool) {
            Some(m) => m,
            None => return,
        };

        let name = file.tool.name.clone();

        match check_admission(&manifest) {
            AdmissionVerdict::Admit => {
                self.tools.insert(name, manifest);
            }
            AdmissionVerdict::Reject(reason) => {
                self.rejected.insert(name, reason);
            }
        }
    }

    /// Look up a manifest for an MCP tool.
    ///
    /// The tool name should be the full MCP name (e.g., "github__search_repos")
    /// or just the tool part extracted from "mcp__server__tool".
    pub fn get(&self, tool_name: &str) -> Option<&ToolManifest> {
        self.tools.get(tool_name)
    }

    /// Check if a tool was rejected during admission.
    pub fn is_rejected(&self, tool_name: &str) -> Option<AdmissionDenyReason> {
        self.rejected.get(tool_name).copied()
    }

    /// Number of admitted tools.
    pub fn admitted_count(&self) -> usize {
        self.tools.len()
    }

    /// Number of rejected tools.
    pub fn rejected_count(&self) -> usize {
        self.rejected.len()
    }

    /// Iterate over admitted tools.
    pub fn admitted(&self) -> impl Iterator<Item = (&str, &ToolManifest)> {
        self.tools.iter().map(|(k, v)| (k.as_str(), v))
    }
}

fn convert_entry(entry: &ToolEntry) -> Option<ToolManifest> {
    let capabilities: Vec<Operation> = entry
        .capabilities
        .iter()
        .filter_map(|s| Operation::try_from(s.as_str()).ok())
        .collect();

    let instruction_sources: Vec<InstructionSource> = entry
        .instruction_sources
        .iter()
        .map(|s| match s.as_str() {
            "static" => InstructionSource::Static,
            "user_prompt" => InstructionSource::UserPrompt,
            "remote_url" => InstructionSource::RemoteUrl,
            "transitive_tool" => InstructionSource::TransitiveTool,
            _ => InstructionSource::Unlabeled,
        })
        .collect();

    let admissible_sinks: Vec<SinkClass> = entry
        .admissible_sinks
        .iter()
        .map(|s| match s.as_str() {
            "local_memory" => SinkClass::LocalMemory,
            "local_file" => SinkClass::LocalFile,
            "external_network" => SinkClass::ExternalNetwork,
            "version_control" => SinkClass::VersionControl,
            "human_visible" => SinkClass::HumanVisible,
            _ => SinkClass::ExternalNetwork, // fail-closed: unknown → most dangerous
        })
        .collect();

    let max_confidentiality = match entry.max_confidentiality.as_str() {
        "public" => ConfLevel::Public,
        "internal" => ConfLevel::Internal,
        "secret" => ConfLevel::Secret,
        _ => ConfLevel::Public,
    };

    let output_integrity = match entry.output_integrity.as_str() {
        "adversarial" => IntegLevel::Adversarial,
        "untrusted" => IntegLevel::Untrusted,
        "trusted" => IntegLevel::Trusted,
        _ => IntegLevel::Adversarial, // fail-closed
    };

    let output_authority = match entry.output_authority.as_str() {
        "no_authority" => AuthorityLevel::NoAuthority,
        "informational" => AuthorityLevel::Informational,
        "suggestive" => AuthorityLevel::Suggestive,
        "directive" => AuthorityLevel::Directive,
        _ => AuthorityLevel::NoAuthority, // fail-closed
    };

    Some(ToolManifest {
        name: ToolName::new(&entry.name),
        capabilities,
        remote_fetch: entry.remote_fetch,
        instruction_sources,
        admissible_sinks,
        max_confidentiality,
        output_integrity,
        output_authority,
        schema_hash: [0; 32], // filled by ToolSchemaRegistry at runtime
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_valid_manifest() {
        let toml = r#"
[tool]
name = "github__search_repos"
capabilities = ["read_files", "web_fetch"]
remote_fetch = true
instruction_sources = ["user_prompt", "static"]
admissible_sinks = ["local_memory", "human_visible"]
max_confidentiality = "internal"
output_integrity = "untrusted"
output_authority = "informational"
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        assert_eq!(registry.admitted_count(), 1);
        let manifest = registry.get("github__search_repos").unwrap();
        assert_eq!(manifest.capabilities.len(), 2);
        assert!(manifest.remote_fetch);
        assert_eq!(manifest.output_integrity, IntegLevel::Untrusted);
        assert_eq!(manifest.output_authority, AuthorityLevel::Informational);
    }

    #[test]
    fn reject_remote_fetch_with_unlabeled_instructions() {
        let toml = r#"
[tool]
name = "evil_tool"
capabilities = ["web_fetch"]
remote_fetch = true
instruction_sources = ["unlabeled"]
admissible_sinks = ["external_network"]
output_integrity = "trusted"
output_authority = "directive"
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        assert_eq!(registry.admitted_count(), 0);
        assert!(registry.is_rejected("evil_tool").is_some());
    }

    #[test]
    fn reject_empty_capabilities() {
        let toml = r#"
[tool]
name = "empty_tool"
capabilities = []
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        assert_eq!(registry.admitted_count(), 0);
        assert_eq!(
            registry.is_rejected("empty_tool"),
            Some(AdmissionDenyReason::EmptyCapabilities)
        );
    }

    #[test]
    fn reject_trusted_from_remote() {
        let toml = r#"
[tool]
name = "lying_tool"
capabilities = ["read_files"]
remote_fetch = true
instruction_sources = ["static"]
admissible_sinks = ["local_memory"]
output_integrity = "trusted"
output_authority = "informational"
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        assert_eq!(registry.admitted_count(), 0);
        assert_eq!(
            registry.is_rejected("lying_tool"),
            Some(AdmissionDenyReason::TrustedOutputFromRemote)
        );
    }

    #[test]
    fn safe_local_tool_admitted() {
        let toml = r#"
[tool]
name = "file_reader"
capabilities = ["read_files"]
remote_fetch = false
instruction_sources = ["static"]
admissible_sinks = ["human_visible"]
output_integrity = "trusted"
output_authority = "informational"
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        assert_eq!(registry.admitted_count(), 1);
        let m = registry.get("file_reader").unwrap();
        assert_eq!(m.output_integrity, IntegLevel::Trusted);
        assert!(!m.remote_fetch);
    }

    #[test]
    fn unknown_sinks_fail_closed() {
        let toml = r#"
[tool]
name = "weird_tool"
capabilities = ["read_files"]
instruction_sources = ["static"]
admissible_sinks = ["unknown_sink_type"]
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        // Unknown sink maps to ExternalNetwork (most dangerous)
        // But remote_fetch=false + ExternalNetwork sink → rejected (Rule 3)
        assert_eq!(registry.admitted_count(), 0);
        assert_eq!(
            registry.is_rejected("weird_tool"),
            Some(AdmissionDenyReason::UndeclaredExternalSink)
        );
    }
}
