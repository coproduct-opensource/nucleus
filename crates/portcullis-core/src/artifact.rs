//! OCI-like artifact format for compartment images.
//!
//! A compartment artifact bundles policy, compartment definitions, tool manifests,
//! and signatures into a content-addressable unit — analogous to an OCI image
//! manifest. Each artifact has a SHA-256 digest computed from its non-signature
//! layers in canonical order, enabling tamper detection and deduplication.
//!
//! ## Format overview
//!
//! ```text
//! ArtifactManifest
//! ├── schema_version: "1"
//! ├── created_at: <unix timestamp>
//! ├── digest: "sha256:<hex>"        ← computed from layer contents
//! └── layers:
//!     ├── Compartmentfile(toml)     ← compartment definition
//!     ├── Policy(toml)              ← policy.toml
//!     ├── ToolManifests([toml...])  ← per-tool manifests
//!     ├── EgressPolicy(toml)        ← network egress rules
//!     ├── EnterpriseAllowlist(txt)  ← enterprise tool allowlist
//!     └── Signature { key_id, sig } ← Ed25519 over digest
//! ```
//!
//! ## Content addressing
//!
//! The digest is a SHA-256 hash of all non-signature layers serialized in
//! declaration order. Signatures are excluded from the digest so they can be
//! added after the artifact is built (detached signing).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for the artifact format.
pub const SCHEMA_VERSION: &str = "1";

/// Media type for the artifact manifest (OCI-compatible).
pub const MEDIA_TYPE_MANIFEST: &str = "application/vnd.nucleus.compartment.v1+json";

/// An artifact manifest bundling compartment layers with a content-addressable digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactManifest {
    /// Schema version (currently "1").
    pub schema_version: String,
    /// Unix timestamp of artifact creation.
    pub created_at: u64,
    /// SHA-256 digest of canonical layer content: `"sha256:<hex>"`.
    pub digest: String,
    /// Ordered layers comprising the artifact.
    pub layers: Vec<ArtifactLayer>,
}

/// A single layer in a compartment artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum ArtifactLayer {
    /// Compartmentfile TOML content — defines the compartment structure.
    Compartmentfile(String),
    /// Policy TOML content — enforcement rules.
    Policy(String),
    /// Per-tool manifest TOML content.
    ToolManifests(Vec<String>),
    /// Network egress policy TOML.
    EgressPolicy(String),
    /// Enterprise tool allowlist.
    EnterpriseAllowlist(String),
    /// Detached signature over the manifest digest.
    Signature {
        /// Identifier for the signing key.
        key_id: String,
        /// Ed25519 signature bytes.
        signature: Vec<u8>,
    },
}

impl ArtifactLayer {
    /// Returns true if this layer is a signature (excluded from digest computation).
    fn is_signature(&self) -> bool {
        matches!(self, ArtifactLayer::Signature { .. })
    }
}

impl ArtifactManifest {
    /// Compute the SHA-256 digest of all non-signature layers in declaration order.
    ///
    /// Each layer contributes a tag byte followed by its content bytes:
    /// - `Compartmentfile`: `0x01` + UTF-8 bytes
    /// - `Policy`: `0x02` + UTF-8 bytes
    /// - `ToolManifests`: `0x03` + (length as u32 LE) + each manifest's UTF-8 bytes
    /// - `EgressPolicy`: `0x04` + UTF-8 bytes
    /// - `EnterpriseAllowlist`: `0x05` + UTF-8 bytes
    /// - `Signature`: skipped
    pub fn compute_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for layer in &self.layers {
            match layer {
                ArtifactLayer::Compartmentfile(content) => {
                    hasher.update([0x01]);
                    hasher.update(content.as_bytes());
                }
                ArtifactLayer::Policy(content) => {
                    hasher.update([0x02]);
                    hasher.update(content.as_bytes());
                }
                ArtifactLayer::ToolManifests(manifests) => {
                    hasher.update([0x03]);
                    let len = manifests.len() as u32;
                    hasher.update(len.to_le_bytes());
                    for m in manifests {
                        hasher.update(m.as_bytes());
                    }
                }
                ArtifactLayer::EgressPolicy(content) => {
                    hasher.update([0x04]);
                    hasher.update(content.as_bytes());
                }
                ArtifactLayer::EnterpriseAllowlist(content) => {
                    hasher.update([0x05]);
                    hasher.update(content.as_bytes());
                }
                ArtifactLayer::Signature { .. } => {
                    // Signatures are excluded from the digest.
                }
            }
        }
        let result = hasher.finalize();
        format!("sha256:{}", hex_encode(&result))
    }

    /// Verify that the stored digest matches the recomputed digest.
    pub fn verify_digest(&self) -> bool {
        self.digest == self.compute_digest()
    }

    /// Serialize the manifest to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a manifest from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Return all signature layers.
    pub fn signatures(&self) -> Vec<&ArtifactLayer> {
        self.layers.iter().filter(|l| l.is_signature()).collect()
    }

    /// Add a signature layer to the manifest.
    pub fn add_signature(&mut self, key_id: String, signature: Vec<u8>) {
        self.layers
            .push(ArtifactLayer::Signature { key_id, signature });
    }
}

/// Ergonomic builder for constructing artifact manifests.
#[derive(Debug, Default)]
pub struct ArtifactBuilder {
    layers: Vec<ArtifactLayer>,
    created_at: Option<u64>,
}

impl ArtifactBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the creation timestamp (unix seconds).
    pub fn created_at(mut self, ts: u64) -> Self {
        self.created_at = Some(ts);
        self
    }

    /// Add a Compartmentfile layer.
    pub fn compartmentfile(mut self, toml: impl Into<String>) -> Self {
        self.layers
            .push(ArtifactLayer::Compartmentfile(toml.into()));
        self
    }

    /// Add a Policy layer.
    pub fn policy(mut self, toml: impl Into<String>) -> Self {
        self.layers.push(ArtifactLayer::Policy(toml.into()));
        self
    }

    /// Add a single tool manifest.
    pub fn tool_manifest(mut self, toml: impl Into<String>) -> Self {
        // If the last layer is ToolManifests, append to it; otherwise create a new one.
        if let Some(ArtifactLayer::ToolManifests(manifests)) = self.layers.last_mut() {
            manifests.push(toml.into());
        } else {
            self.layers
                .push(ArtifactLayer::ToolManifests(vec![toml.into()]));
        }
        self
    }

    /// Add multiple tool manifests at once.
    pub fn tool_manifests(mut self, tomls: Vec<String>) -> Self {
        self.layers.push(ArtifactLayer::ToolManifests(tomls));
        self
    }

    /// Add an egress policy layer.
    pub fn egress_policy(mut self, toml: impl Into<String>) -> Self {
        self.layers.push(ArtifactLayer::EgressPolicy(toml.into()));
        self
    }

    /// Add an enterprise allowlist layer.
    pub fn enterprise_allowlist(mut self, content: impl Into<String>) -> Self {
        self.layers
            .push(ArtifactLayer::EnterpriseAllowlist(content.into()));
        self
    }

    /// Build the manifest, computing the digest from layer contents.
    pub fn build(self) -> ArtifactManifest {
        let created_at = self.created_at.unwrap_or(0);
        let mut manifest = ArtifactManifest {
            schema_version: SCHEMA_VERSION.to_string(),
            created_at,
            digest: String::new(),
            layers: self.layers,
        };
        manifest.digest = manifest.compute_digest();
        manifest
    }
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_artifact() -> ArtifactManifest {
        ArtifactBuilder::new()
            .created_at(1_700_000_000)
            .compartmentfile("[compartment]\nname = \"test\"")
            .policy("[policy]\nmax_autonomy = \"low\"")
            .tool_manifest("[tool]\nname = \"git\"")
            .tool_manifest("[tool]\nname = \"cargo\"")
            .egress_policy("[egress]\nallow = [\"api.example.com\"]")
            .build()
    }

    #[test]
    fn build_artifact_has_valid_digest() {
        let artifact = sample_artifact();
        assert_eq!(artifact.schema_version, SCHEMA_VERSION);
        assert!(artifact.digest.starts_with("sha256:"));
        assert_eq!(artifact.digest.len(), 7 + 64); // "sha256:" + 64 hex chars
        assert!(artifact.verify_digest());
    }

    #[test]
    fn digest_is_deterministic() {
        let a1 = sample_artifact();
        let a2 = sample_artifact();
        assert_eq!(a1.digest, a2.digest);
    }

    #[test]
    fn tamper_detection_layer_content() {
        let mut artifact = sample_artifact();
        // Tamper with a layer.
        artifact.layers[0] = ArtifactLayer::Compartmentfile("tampered".into());
        assert!(
            !artifact.verify_digest(),
            "tampered artifact should fail verification"
        );
    }

    #[test]
    fn tamper_detection_layer_order() {
        let mut artifact = sample_artifact();
        // Swap first two layers.
        artifact.layers.swap(0, 1);
        assert!(
            !artifact.verify_digest(),
            "reordered layers should fail verification"
        );
    }

    #[test]
    fn tamper_detection_added_layer() {
        let mut artifact = sample_artifact();
        artifact.layers.push(ArtifactLayer::Policy("extra".into()));
        assert!(
            !artifact.verify_digest(),
            "added layer should fail verification"
        );
    }

    #[test]
    fn signature_excluded_from_digest() {
        let mut artifact = sample_artifact();
        let digest_before = artifact.digest.clone();
        artifact.add_signature("key-1".into(), vec![0xAA; 64]);
        // Digest should still verify because signatures are excluded.
        assert!(artifact.verify_digest());
        assert_eq!(artifact.compute_digest(), digest_before);
    }

    #[test]
    fn json_roundtrip() {
        let artifact = sample_artifact();
        let json = artifact.to_json().expect("serialize");
        let restored = ArtifactManifest::from_json(&json).expect("deserialize");
        assert_eq!(artifact, restored);
        assert!(restored.verify_digest());
    }

    #[test]
    fn json_roundtrip_with_signature() {
        let mut artifact = sample_artifact();
        artifact.add_signature("signing-key-1".into(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let json = artifact.to_json().expect("serialize");
        let restored = ArtifactManifest::from_json(&json).expect("deserialize");
        assert_eq!(artifact, restored);
        assert!(restored.verify_digest());
    }

    #[test]
    fn empty_artifact() {
        let artifact = ArtifactBuilder::new().build();
        assert!(artifact.verify_digest());
        assert!(artifact.layers.is_empty());
    }

    #[test]
    fn builder_tool_manifest_coalescing() {
        let artifact = ArtifactBuilder::new()
            .tool_manifest("a")
            .tool_manifest("b")
            .build();
        // Both manifests should be in a single ToolManifests layer.
        assert_eq!(artifact.layers.len(), 1);
        if let ArtifactLayer::ToolManifests(ref ms) = artifact.layers[0] {
            assert_eq!(ms.len(), 2);
        } else {
            panic!("expected ToolManifests layer");
        }
    }

    #[test]
    fn signatures_accessor() {
        let mut artifact = sample_artifact();
        assert!(artifact.signatures().is_empty());
        artifact.add_signature("k1".into(), vec![1]);
        artifact.add_signature("k2".into(), vec![2]);
        assert_eq!(artifact.signatures().len(), 2);
    }

    #[test]
    fn json_contains_media_type_compatible_structure() {
        let artifact = sample_artifact();
        let json = artifact.to_json().expect("serialize");
        // Verify JSON contains expected fields.
        assert!(json.contains("schema_version"));
        assert!(json.contains("digest"));
        assert!(json.contains("layers"));
        assert!(json.contains("Compartmentfile"));
        assert!(json.contains("Policy"));
    }
}
