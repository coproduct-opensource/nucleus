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
    /// Rejected tools: MCP tool name → all deny reasons.
    rejected: BTreeMap<String, Vec<AdmissionDenyReason>>,
    /// Tools with invalid or missing signatures (when trust store is present).
    unsigned: Vec<String>,
}

/// Trust store — Ed25519 public keys for manifest signature verification.
///
/// Load keys from `.nucleus/trust/*.pub` (raw 32-byte Ed25519 public keys, hex-encoded).
#[derive(Debug, Default)]
pub struct TrustStore {
    /// Known public keys (raw 32-byte Ed25519 public keys).
    keys: Vec<Vec<u8>>,
}

impl TrustStore {
    /// Load public keys from a trust directory.
    ///
    /// Each `.pub` file should contain a hex-encoded 32-byte Ed25519 public key.
    pub fn load_from_dir(dir: &Path) -> Self {
        let trust_dir = dir.join(".nucleus").join("trust");
        let mut store = Self::default();

        if !trust_dir.is_dir() {
            return store;
        }

        let entries = match std::fs::read_dir(&trust_dir) {
            Ok(e) => e,
            Err(_) => return store,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "pub") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(key_bytes) = hex::decode(content.trim()) {
                        if key_bytes.len() == 32 {
                            store.keys.push(key_bytes);
                        }
                    }
                }
            }
        }

        store
    }

    /// Check if the trust store has any keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verify a signature against any trusted key.
    ///
    /// Returns true if the signature is valid for at least one trusted key.
    #[cfg(feature = "crypto")]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use ring::signature::{self, UnparsedPublicKey};

        for key_bytes in &self.keys {
            let public_key = UnparsedPublicKey::new(&signature::ED25519, key_bytes);
            if public_key.verify(message, signature).is_ok() {
                return true;
            }
        }
        false
    }

    /// Number of trusted keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Verify an Ed25519 signature on a `ToolManifest` against a trust store.
///
/// Returns `Ok(())` if the signature is valid for at least one trusted key,
/// or an `AdmissionDenyReason` if verification fails.
#[cfg(feature = "crypto")]
pub fn verify_manifest_signature(
    manifest: &ToolManifest,
    trust_store: &TrustStore,
) -> Result<(), AdmissionDenyReason> {
    use ring::signature::{self, UnparsedPublicKey};

    let (sig, key) = match (manifest.signature.as_ref(), manifest.signing_key.as_ref()) {
        (Some(s), Some(k)) => (s, k),
        _ => return Err(AdmissionDenyReason::UnsignedManifest),
    };

    // First check: the signing key must be in the trust store
    if !trust_store
        .keys
        .iter()
        .any(|k2| k2.as_slice() == key.as_slice())
    {
        return Err(AdmissionDenyReason::InvalidSignature);
    }

    // Second check: the signature must verify against canonical bytes
    let canonical = manifest.canonical_bytes();
    let public_key = UnparsedPublicKey::new(&signature::ED25519, key.as_slice());
    public_key
        .verify(&canonical, sig.as_slice())
        .map_err(|_| AdmissionDenyReason::InvalidSignature)
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
    /// Ed25519 signature of the manifest content (hex-encoded, 64 bytes, optional).
    #[serde(default)]
    signature: Option<String>,
    /// Ed25519 public key that produced the signature (hex-encoded, 32 bytes, optional).
    #[serde(default)]
    signing_key: Option<String>,
    /// Allowed hosts for remote fetch (optional).
    #[serde(default)]
    allowed_hosts: Option<Vec<String>>,
    /// Whether output carries authority_to_instruct (optional, default false).
    #[serde(default)]
    authority_to_instruct: Option<bool>,
    /// Compartments where this tool is allowed (#462).
    /// Empty = all compartments. When set, tool is only available in listed compartments.
    #[serde(default)]
    allowed_compartments: Option<Vec<String>>,
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
    ///
    /// If a trust store is present (`.nucleus/trust/` has keys), manifests
    /// must be signed. Unsigned or invalidly signed manifests are rejected.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut registry = Self::new();
        let manifest_dir = dir.join(".nucleus").join("manifests");
        let trust_store = TrustStore::load_from_dir(dir);

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
                    registry.load_toml_with_trust(&content, &trust_store);
                }
            }
        }

        registry
    }

    /// Parse and register a single manifest from TOML content (no trust store).
    pub fn load_toml(&mut self, content: &str) {
        self.load_toml_with_trust(content, &TrustStore::default());
    }

    /// Parse and register a single manifest from TOML content with trust verification.
    ///
    /// Signature verification uses `canonical_bytes()` — the same deterministic
    /// struct-based serialization used by `verify_manifest_signature()`. This is
    /// the single source of truth for manifest signing payloads. See #837.
    #[cfg_attr(not(feature = "crypto"), allow(unused_variables))]
    pub fn load_toml_with_trust(&mut self, content: &str, trust_store: &TrustStore) {
        let file: ManifestFile = match toml::from_str(content) {
            Ok(f) => f,
            Err(_) => return,
        };

        let name = file.tool.name.clone();

        let manifest = match convert_entry(&file.tool) {
            Some(m) => m,
            None => return,
        };

        // Signature verification (when trust store has keys).
        // Uses canonical_bytes() for a deterministic, struct-based signing
        // payload — identical to verify_manifest_signature(). (#837)
        #[cfg(feature = "crypto")]
        if !trust_store.is_empty() {
            match verify_manifest_signature(&manifest, trust_store) {
                Ok(()) => {} // valid signature
                Err(AdmissionDenyReason::UnsignedManifest) => {
                    self.unsigned.push(name);
                    return;
                }
                Err(_) => {
                    self.unsigned.push(name);
                    return;
                }
            }
        }

        match check_admission(&manifest) {
            AdmissionVerdict::Admit => {
                self.tools.insert(name, manifest);
            }
            AdmissionVerdict::Reject(reasons) => {
                self.rejected.insert(name, reasons);
            }
        }
    }

    /// Number of unsigned/invalidly signed tools (when trust store is present).
    pub fn unsigned_count(&self) -> usize {
        self.unsigned.len()
    }

    /// Look up a manifest for an MCP tool.
    ///
    /// The tool name should be the full MCP name (e.g., "github__search_repos")
    /// or just the tool part extracted from "mcp__server__tool".
    pub fn get(&self, tool_name: &str) -> Option<&ToolManifest> {
        self.tools.get(tool_name)
    }

    /// Check if a tool was rejected during admission.
    /// Returns the list of all deny reasons (empty vec = not rejected).
    pub fn is_rejected(&self, tool_name: &str) -> Option<&[AdmissionDenyReason]> {
        self.rejected.get(tool_name).map(|v| v.as_slice())
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

    /// Verify Ed25519 signatures on all admitted manifests against a trust store.
    ///
    /// Returns the names of manifests that failed verification (unsigned or
    /// invalid signature). Manifests that pass are left in the registry;
    /// failed manifests are moved to `unsigned`.
    ///
    /// This is separate from `load_from_dir` so callers can load manifests
    /// first, then apply signature verification as a policy gate.
    #[cfg(feature = "crypto")]
    pub fn verify_all(&mut self, trust_store: &TrustStore) -> Vec<(String, AdmissionDenyReason)> {
        let mut failures = Vec::new();
        let mut to_remove = Vec::new();

        for (name, manifest) in &self.tools {
            match verify_manifest_signature(manifest, trust_store) {
                Ok(()) => {} // valid signature
                Err(reason) => {
                    failures.push((name.clone(), reason));
                    to_remove.push(name.clone());
                }
            }
        }

        for name in &to_remove {
            self.tools.remove(name);
            self.unsigned.push(name.clone());
        }

        failures
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

    // Parse signature (hex → [u8; 64])
    let signature = entry.signature.as_ref().and_then(|hex_str| {
        let bytes = hex::decode(hex_str).ok()?;
        <[u8; 64]>::try_from(bytes.as_slice()).ok()
    });

    // Parse signing key (hex → [u8; 32])
    let signing_key = entry.signing_key.as_ref().and_then(|hex_str| {
        let bytes = hex::decode(hex_str).ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    });

    Some(ToolManifest {
        name: ToolName::new(&entry.name),
        capabilities,
        remote_fetch: entry.remote_fetch,
        instruction_sources,
        admissible_sinks,
        max_confidentiality,
        output_integrity,
        output_authority,
        schema_hash: [0; 32],
        allowed_hosts: entry.allowed_hosts.clone().unwrap_or_default(),
        authority_to_instruct: entry.authority_to_instruct.unwrap_or(false),
        memory_behavior: portcullis_core::manifest::MemoryBehavior::None,
        allowed_compartments: entry.allowed_compartments.clone().unwrap_or_default(),
        signature,
        signing_key,
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
        assert!(registry
            .is_rejected("empty_tool")
            .unwrap()
            .contains(&AdmissionDenyReason::EmptyCapabilities));
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
        assert!(registry
            .is_rejected("lying_tool")
            .unwrap()
            .contains(&AdmissionDenyReason::TrustedOutputFromRemote));
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
        assert!(registry
            .is_rejected("weird_tool")
            .unwrap()
            .contains(&AdmissionDenyReason::UndeclaredExternalSink));
    }

    // ── Signed manifest tests (#650) ──────────────────────────────────

    #[test]
    fn load_manifest_with_signature_fields() {
        // Signature fields are parsed from TOML but don't affect admission
        // (crypto verification is separate from content admission)
        let toml = r#"
[tool]
name = "signed_tool"
capabilities = ["read_files"]
instruction_sources = ["static"]
admissible_sinks = ["local_memory"]
output_integrity = "untrusted"
output_authority = "informational"
signature = "aa"
signing_key = "bb"
"#;
        let mut registry = ManifestRegistry::new();
        registry.load_toml(toml);

        // Should be admitted (valid content), but signature is malformed
        // (too short for Ed25519) so sig/key fields will be None
        assert_eq!(registry.admitted_count(), 1);
        let m = registry.get("signed_tool").unwrap();
        assert!(!m.is_signed(), "malformed hex should not parse as signed");
    }

    #[cfg(feature = "crypto")]
    mod crypto_tests {
        use super::*;
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        fn test_keypair() -> Ed25519KeyPair {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
        }

        fn make_trust_store(public_key: &[u8]) -> TrustStore {
            TrustStore {
                keys: vec![public_key.to_vec()],
            }
        }

        fn signed_manifest(key_pair: &Ed25519KeyPair) -> ToolManifest {
            use portcullis_core::manifest::MemoryBehavior;

            let mut manifest = ToolManifest {
                name: ToolName::new("verified_tool"),
                capabilities: vec![portcullis_core::Operation::ReadFiles],
                remote_fetch: false,
                instruction_sources: vec![InstructionSource::Static],
                admissible_sinks: vec![SinkClass::LocalMemory],
                max_confidentiality: ConfLevel::Internal,
                output_integrity: IntegLevel::Untrusted,
                output_authority: AuthorityLevel::Informational,
                schema_hash: [0; 32],
                allowed_hosts: vec![],
                authority_to_instruct: false,
                memory_behavior: MemoryBehavior::None,
                allowed_compartments: vec![],
                signature: None,
                signing_key: None,
            };

            // Sign
            let canonical = manifest.canonical_bytes();
            let sig = key_pair.sign(&canonical);
            let sig_bytes: [u8; 64] = sig.as_ref().try_into().unwrap();
            let pub_bytes: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();

            manifest.signature = Some(sig_bytes);
            manifest.signing_key = Some(pub_bytes);
            manifest
        }

        #[test]
        fn verify_manifest_signature_valid() {
            let kp = test_keypair();
            let manifest = signed_manifest(&kp);
            let trust = make_trust_store(kp.public_key().as_ref());

            assert!(
                verify_manifest_signature(&manifest, &trust).is_ok(),
                "valid signature should verify"
            );
        }

        #[test]
        fn verify_manifest_signature_tampered() {
            let kp = test_keypair();
            let mut manifest = signed_manifest(&kp);
            let trust = make_trust_store(kp.public_key().as_ref());

            // Tamper with the manifest after signing
            manifest.name = ToolName::new("evil_replacement");

            assert_eq!(
                verify_manifest_signature(&manifest, &trust),
                Err(AdmissionDenyReason::InvalidSignature),
                "tampered manifest should fail verification"
            );
        }

        #[test]
        fn verify_manifest_signature_unsigned() {
            let kp = test_keypair();
            let trust = make_trust_store(kp.public_key().as_ref());

            let manifest = ToolManifest {
                name: ToolName::new("unsigned_tool"),
                capabilities: vec![portcullis_core::Operation::ReadFiles],
                remote_fetch: false,
                instruction_sources: vec![InstructionSource::Static],
                admissible_sinks: vec![SinkClass::LocalMemory],
                max_confidentiality: ConfLevel::Internal,
                output_integrity: IntegLevel::Untrusted,
                output_authority: AuthorityLevel::Informational,
                schema_hash: [0; 32],
                allowed_hosts: vec![],
                authority_to_instruct: false,
                memory_behavior: portcullis_core::manifest::MemoryBehavior::None,
                allowed_compartments: vec![],
                signature: None,
                signing_key: None,
            };

            assert_eq!(
                verify_manifest_signature(&manifest, &trust),
                Err(AdmissionDenyReason::UnsignedManifest),
                "unsigned manifest should be rejected"
            );
        }

        #[test]
        fn verify_manifest_signature_wrong_key() {
            let kp1 = test_keypair();
            let kp2 = test_keypair();
            let manifest = signed_manifest(&kp1);
            // Trust store has kp2's key, not kp1's
            let trust = make_trust_store(kp2.public_key().as_ref());

            assert_eq!(
                verify_manifest_signature(&manifest, &trust),
                Err(AdmissionDenyReason::InvalidSignature),
                "signature by untrusted key should fail"
            );
        }

        #[test]
        fn verify_all_removes_invalid() {
            let kp = test_keypair();
            let trust = make_trust_store(kp.public_key().as_ref());

            let mut registry = ManifestRegistry::new();

            // Load a valid unsigned manifest (passes admission, no crypto)
            let toml = r#"
[tool]
name = "unsigned_tool"
capabilities = ["read_files"]
instruction_sources = ["static"]
admissible_sinks = ["local_memory"]
output_integrity = "untrusted"
output_authority = "informational"
"#;
            registry.load_toml(toml);
            assert_eq!(registry.admitted_count(), 1);

            // Now verify_all — the unsigned manifest should be removed
            let failures = registry.verify_all(&trust);
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].0, "unsigned_tool");
            assert_eq!(failures[0].1, AdmissionDenyReason::UnsignedManifest);
            assert_eq!(registry.admitted_count(), 0);
            assert_eq!(registry.unsigned_count(), 1);
        }

        #[test]
        fn verify_all_keeps_valid_signed() {
            let kp = test_keypair();
            let trust = make_trust_store(kp.public_key().as_ref());

            let manifest = signed_manifest(&kp);
            let mut registry = ManifestRegistry::new();
            registry.tools.insert("verified_tool".to_string(), manifest);

            let failures = registry.verify_all(&trust);
            assert!(failures.is_empty(), "valid signed manifest should pass");
            assert_eq!(registry.admitted_count(), 1);
        }

        /// Regression test for #837: load_toml_with_trust uses canonical_bytes()
        /// (same path as verify_manifest_signature), not text-stripping.
        ///
        /// Signs a manifest struct with canonical_bytes(), embeds the signature
        /// into TOML, then loads it through load_toml_with_trust(). Both paths
        /// must agree on the signing payload.
        #[test]
        fn load_toml_with_trust_uses_canonical_bytes() {
            let kp = test_keypair();
            let trust = make_trust_store(kp.public_key().as_ref());

            // Build manifest struct, sign with canonical_bytes()
            let manifest = signed_manifest(&kp);
            let sig_hex = hex::encode(manifest.signature.unwrap());
            let key_hex = hex::encode(manifest.signing_key.unwrap());

            // Embed the signature into TOML — this must verify via canonical_bytes()
            let toml_content = format!(
                r#"
[tool]
name = "verified_tool"
capabilities = ["read_files"]
remote_fetch = false
instruction_sources = ["static"]
admissible_sinks = ["local_memory"]
max_confidentiality = "internal"
output_integrity = "untrusted"
output_authority = "informational"
signature = "{sig_hex}"
signing_key = "{key_hex}"
"#
            );

            let mut registry = ManifestRegistry::new();
            registry.load_toml_with_trust(&toml_content, &trust);

            assert_eq!(
                registry.admitted_count(),
                1,
                "signed manifest should be admitted via load_toml_with_trust"
            );
            assert_eq!(
                registry.unsigned_count(),
                0,
                "should not be marked unsigned"
            );
        }

        /// Regression test for #837: TOML content with "signature"-prefixed
        /// lines in values must not affect verification. The old text-stripping
        /// approach would have incorrectly stripped such lines.
        #[test]
        fn toml_with_signature_in_value_does_not_break_verification() {
            let kp = test_keypair();
            let trust = make_trust_store(kp.public_key().as_ref());

            // The struct-based approach is immune to TOML formatting because
            // it signs the parsed struct, not the raw text.
            let manifest = signed_manifest(&kp);
            assert!(
                verify_manifest_signature(&manifest, &trust).is_ok(),
                "struct-based verification is immune to TOML formatting"
            );
        }
    }
}
