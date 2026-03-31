//! Governed memory — typed, labeled, time-bounded agent memory.
//!
//! Memory entries carry IFC labels so the flow graph can track
//! information propagation through persistent storage. Entries
//! have TTLs and are garbage-collected when expired.
//!
//! ## Memory governance
//!
//! - Each entry has a `ConfLevel` — reads from high-confidentiality
//!   entries produce high-confidentiality flow labels.
//! - Each entry has a `IntegLevel` — writes from adversarial sources
//!   are stored with adversarial integrity.
//! - TTLs prevent stale data from persisting indefinitely.
//! - Schema types enable validation (string, json, binary).

use crate::{AuthorityLevel, ConfLevel, Freshness, IFCLabel, IntegLevel, ProvenanceSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A governed memory store with typed, labeled entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernedMemory {
    /// Memory entries keyed by name.
    entries: BTreeMap<String, MemoryEntry>,
}

/// A single memory entry with IFC label and TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// The stored value.
    pub value: String,
    /// Schema type for validation.
    pub schema: SchemaType,
    /// IFC label — tracks confidentiality and integrity of the data.
    pub label: MemoryLabel,
    /// Unix timestamp when the entry was created.
    pub created_at: u64,
    /// Time-to-live in seconds (0 = no expiry).
    pub ttl_secs: u64,
}

/// Simplified IFC label for memory entries (serializable as strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLabel {
    /// Confidentiality: "public", "internal", "secret"
    pub confidentiality: String,
    /// Integrity: "adversarial", "untrusted", "trusted"
    pub integrity: String,
}

impl MemoryLabel {
    /// Parse confidentiality level.
    pub fn conf_level(&self) -> ConfLevel {
        match self.confidentiality.as_str() {
            "public" => ConfLevel::Public,
            "internal" => ConfLevel::Internal,
            "secret" => ConfLevel::Secret,
            _ => ConfLevel::Secret, // fail-closed
        }
    }

    /// Parse integrity level.
    pub fn integ_level(&self) -> IntegLevel {
        match self.integrity.as_str() {
            "adversarial" => IntegLevel::Adversarial,
            "untrusted" => IntegLevel::Untrusted,
            "trusted" => IntegLevel::Trusted,
            _ => IntegLevel::Adversarial, // fail-closed
        }
    }

    /// Create from typed levels.
    pub fn from_levels(conf: ConfLevel, integ: IntegLevel) -> Self {
        Self {
            confidentiality: match conf {
                ConfLevel::Public => "public",
                ConfLevel::Internal => "internal",
                ConfLevel::Secret => "secret",
            }
            .to_string(),
            integrity: match integ {
                IntegLevel::Adversarial => "adversarial",
                IntegLevel::Untrusted => "untrusted",
                IntegLevel::Trusted => "trusted",
            }
            .to_string(),
        }
    }
}

/// Schema types for memory entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaType {
    /// Plain text string.
    String,
    /// JSON object.
    Json,
    /// Opaque binary (base64-encoded in the value field).
    Binary,
}

impl GovernedMemory {
    /// Create an empty memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a memory entry with the given label.
    ///
    /// Returns false if max_entries would be exceeded (entry not written).
    pub fn write(
        &mut self,
        key: String,
        value: String,
        schema: SchemaType,
        label: MemoryLabel,
        now: u64,
        ttl_secs: u64,
    ) -> bool {
        self.write_with_limit(key, value, schema, label, now, ttl_secs, 1000)
    }

    /// Write with explicit max_entries limit (#587).
    #[allow(clippy::too_many_arguments)]
    pub fn write_with_limit(
        &mut self,
        key: String,
        value: String,
        schema: SchemaType,
        label: MemoryLabel,
        now: u64,
        ttl_secs: u64,
        max_entries: usize,
    ) -> bool {
        // If key already exists, allow overwrite (doesn't increase count)
        if !self.entries.contains_key(&key) && self.entries.len() >= max_entries {
            return false; // Reject: would exceed limit
        }
        self.entries.insert(
            key,
            MemoryEntry {
                value,
                schema,
                label,
                created_at: now,
                ttl_secs,
            },
        );
        true
    }

    /// Read a memory entry (returns None if not found or expired).
    pub fn read(&self, key: &str, now: u64) -> Option<&MemoryEntry> {
        self.entries.get(key).filter(|e| !e.is_expired(now))
    }

    /// Get the IFC label for a memory read (for flow graph observation).
    pub fn read_label(&self, key: &str, now: u64) -> Option<IFCLabel> {
        self.read(key, now).map(|entry| IFCLabel {
            confidentiality: entry.label.conf_level(),
            integrity: entry.label.integ_level(),
            authority: AuthorityLevel::Informational,
            provenance: ProvenanceSet::MEMORY,
            freshness: Freshness {
                observed_at: entry.created_at,
                ttl_secs: entry.ttl_secs,
            },
        })
    }

    /// Remove expired entries.
    pub fn gc(&mut self, now: u64) {
        self.entries.retain(|_, e| !e.is_expired(now));
    }

    /// Number of entries (including expired).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the store empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List all entry keys.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }
}

impl MemoryEntry {
    /// Is this entry expired?
    pub fn is_expired(&self, now: u64) -> bool {
        self.ttl_secs > 0 && now > self.created_at + self.ttl_secs
    }
}

/// Memory governance configuration (from `.nucleus/memory.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct MemoryConfig {
    /// Default TTL for new entries (seconds). 0 = no expiry.
    #[serde(default)]
    pub default_ttl_secs: u64,
    /// Default confidentiality for new entries: "public", "internal", "secret".
    #[serde(default = "default_conf_str")]
    pub default_confidentiality: String,
    /// Maximum number of entries before oldest are evicted.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

fn default_conf_str() -> String {
    "internal".to_string()
}
fn default_max_entries() -> usize {
    1000
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 0,
            default_confidentiality: default_conf_str(),
            max_entries: default_max_entries(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "key1".to_string(),
            "value1".to_string(),
            SchemaType::String,
            MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted),
            1000,
            0,
        );
        assert_eq!(mem.read("key1", 1000).unwrap().value, "value1");
        assert!(mem.read("nonexistent", 1000).is_none());
    }

    #[test]
    fn ttl_expiry() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "temp".to_string(),
            "data".to_string(),
            SchemaType::String,
            MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Untrusted),
            1000,
            60, // 60 second TTL
        );

        // Not expired yet
        assert!(mem.read("temp", 1059).is_some());
        // Expired
        assert!(mem.read("temp", 1061).is_none());
    }

    #[test]
    fn gc_removes_expired() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "short".to_string(),
            "a".to_string(),
            SchemaType::String,
            MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted),
            1000,
            10,
        );
        mem.write(
            "long".to_string(),
            "b".to_string(),
            SchemaType::String,
            MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted),
            1000,
            3600,
        );

        assert_eq!(mem.len(), 2);
        mem.gc(1020); // short expired, long still valid
        assert_eq!(mem.len(), 1);
        assert!(mem.read("long", 1020).is_some());
    }

    #[test]
    fn read_label_produces_ifc_label() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "secret".to_string(),
            "classified".to_string(),
            SchemaType::String,
            MemoryLabel::from_levels(ConfLevel::Secret, IntegLevel::Trusted),
            1000,
            0,
        );

        let label = mem.read_label("secret", 1000).unwrap();
        assert_eq!(label.confidentiality, ConfLevel::Secret);
        assert_eq!(label.integrity, IntegLevel::Trusted);
        assert!(label.provenance.contains(ProvenanceSet::MEMORY));
    }

    #[test]
    fn zero_ttl_never_expires() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "permanent".to_string(),
            "data".to_string(),
            SchemaType::String,
            MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted),
            1000,
            0, // No expiry
        );
        assert!(mem.read("permanent", u64::MAX - 1).is_some());
    }

    #[test]
    fn parse_memory_config() {
        let toml = r#"
default_ttl_secs = 3600
default_confidentiality = "internal"
max_entries = 500
"#;
        let config: MemoryConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.default_ttl_secs, 3600);
        assert_eq!(config.max_entries, 500);
    }

    #[test]
    fn max_entries_enforced() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);

        // Fill to limit (3 entries)
        for i in 0..3 {
            assert!(mem.write_with_limit(
                format!("key{i}"),
                "value".to_string(),
                SchemaType::String,
                label.clone(),
                1000,
                0,
                3,
            ));
        }
        assert_eq!(mem.len(), 3);

        // 4th entry rejected
        assert!(!mem.write_with_limit(
            "key3".to_string(),
            "value".to_string(),
            SchemaType::String,
            label.clone(),
            1000,
            0,
            3,
        ));
        assert_eq!(mem.len(), 3); // unchanged

        // Overwrite existing key still works
        assert!(mem.write_with_limit(
            "key0".to_string(),
            "updated".to_string(),
            SchemaType::String,
            label,
            1000,
            0,
            3,
        ));
        assert_eq!(mem.read("key0", 1000).unwrap().value, "updated");
    }
}
