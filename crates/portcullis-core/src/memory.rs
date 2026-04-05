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
//! - Each entry has a `MemoryAuthority` — `MayInform` entries can
//!   contribute to reasoning, while `MayNotAuthorize` entries MUST NOT
//!   be used as causal ancestors of privileged actions.
//! - Each entry carries a [`ProvenanceSet`] tracking where the data
//!   originated (USER, WEB, TOOL, etc.). On read, this provenance
//!   flows into the IFC label so the flow graph can track taint.
//! - TTLs prevent stale data from persisting indefinitely.
//! - Schema types enable validation (string, json, binary).
//! - Rebuttal history tracks previous values when entries are
//!   overwritten, capped at [`MAX_REBUTTAL_HISTORY`] per key.
//!
//! ## Poisoned memory detection
//!
//! Entries written from adversarial sources (web scrapes, untrusted
//! delegated agents) should carry `MayNotAuthorize` authority and
//! provenance containing `WEB` or similar tainted sources. The
//! [`GovernedMemory::poisoned_entries`] method returns all entries
//! that cannot authorize privileged actions, and [`GovernedMemory::audit_dump`]
//! produces a full snapshot of every entry's metadata for inspection.

use crate::{AuthorityLevel, ConfLevel, Freshness, IFCLabel, IntegLevel, ProvenanceSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Serde support for [`ProvenanceSet`] (serialized as u8 bitmask).
mod provenance_serde {
    use crate::ProvenanceSet;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &ProvenanceSet, ser: S) -> Result<S::Ok, S::Error> {
        val.bits().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<ProvenanceSet, D::Error> {
        let bits = u8::deserialize(de)?;
        Ok(ProvenanceSet::from_bits(bits))
    }
}

/// Maximum number of rebuttal history entries retained per key.
const MAX_REBUTTAL_HISTORY: usize = 10;

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
    /// Authority class — whether this entry can authorize privileged actions.
    #[serde(default)]
    pub authority: MemoryAuthority,
    /// Provenance — which sources contributed to this entry's data.
    ///
    /// Tracks the origin of the data (USER, WEB, TOOL, MODEL, SYSTEM, MEMORY).
    /// On read, this provenance is unioned with `MEMORY` and flows into the
    /// IFC label for downstream taint tracking.
    #[serde(default, with = "provenance_serde")]
    pub provenance: ProvenanceSet,
    /// Unix timestamp when the entry was created.
    pub created_at: u64,
    /// Time-to-live in seconds (0 = no expiry).
    pub ttl_secs: u64,
    /// History of previous values that were superseded, most recent first.
    /// Capped at [`MAX_REBUTTAL_HISTORY`] entries per key.
    #[serde(default)]
    pub rebuttal_history: Vec<RebuttalEntry>,
}

/// Typed IFC label for memory entries.
///
/// Uses [`ConfLevel`] and [`IntegLevel`] enums directly, eliminating the
/// string-parsing attack surface where unexpected values silently mapped
/// to the most restrictive level (see issue #749).
///
/// The `derivation` field tracks the [`crate::DerivationClass`] of stored data
/// so that AI-derived content is not laundered back to `Deterministic` on read
/// (#1220). Older serialized entries without this field default to `Deterministic`
/// for backward compatibility; new entries should set derivation explicitly via
/// [`MemoryLabel::from_levels_with_derivation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLabel {
    /// Confidentiality level (public, internal, secret).
    pub confidentiality: ConfLevel,
    /// Integrity level (adversarial, untrusted, trusted).
    pub integrity: IntegLevel,
    /// Derivation class — tracks whether data originated from deterministic
    /// computation, AI inference, human promotion, or opaque external sources.
    ///
    /// Defaults to `Deterministic` for backward-compatible deserialization of
    /// entries written before this field was added. Callers writing AI-derived
    /// data MUST use [`MemoryLabel::from_levels_with_derivation`] to ensure the
    /// derivation class is preserved through the memory plane (#1220).
    #[serde(default = "default_derivation")]
    pub derivation: crate::DerivationClass,
}

fn default_derivation() -> crate::DerivationClass {
    crate::DerivationClass::Deterministic
}

impl MemoryLabel {
    /// Return the confidentiality level.
    pub fn conf_level(&self) -> ConfLevel {
        self.confidentiality
    }

    /// Return the integrity level.
    pub fn integ_level(&self) -> IntegLevel {
        self.integrity
    }

    /// Create from typed levels, defaulting to `Deterministic` derivation.
    ///
    /// Use this for entries whose data is known to be deterministic (tool
    /// outputs, configuration, etc.). For AI-generated content, use
    /// [`MemoryLabel::from_levels_with_derivation`] with the appropriate
    /// [`crate::DerivationClass`] to prevent derivation laundering (#1220).
    pub fn from_levels(conf: ConfLevel, integ: IntegLevel) -> Self {
        Self {
            confidentiality: conf,
            integrity: integ,
            derivation: crate::DerivationClass::Deterministic,
        }
    }

    /// Create from typed levels with an explicit derivation class.
    ///
    /// Required when storing AI-derived, human-promoted, or opaque-external
    /// content — the derivation class is preserved through the memory plane
    /// and reflected in the IFC label returned by [`GovernedMemory::read_label`].
    pub fn from_levels_with_derivation(
        conf: ConfLevel,
        integ: IntegLevel,
        derivation: crate::DerivationClass,
    ) -> Self {
        Self {
            confidentiality: conf,
            integrity: integ,
            derivation,
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

/// Authority class for a memory entry — controls whether the entry
/// can influence privileged actions.
///
/// Poisoned memory (written from web-tainted or adversarial sources)
/// should be marked `MayNotAuthorize` so that even if the entry is
/// readable, it cannot become a causal ancestor of privileged operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAuthority {
    /// Entry can inform the model's reasoning (default for trusted sources).
    #[default]
    MayInform,
    /// Entry can be read but MUST NOT be used to authorize actions.
    /// Reads produce `AuthorityLevel::NoAuthority` in the flow label.
    MayNotAuthorize,
}

impl MemoryAuthority {
    /// Derive the appropriate authority from an integrity level.
    ///
    /// This is the fail-safe mapping used by [`GovernedMemory::write()`]:
    /// - `IntegLevel::Trusted` → `MayInform` (trusted data may inform reasoning)
    /// - `IntegLevel::Untrusted` → `MayInform` (but callers should prefer
    ///   [`GovernedMemory::write_governed()`] for explicit control)
    /// - `IntegLevel::Adversarial` → `MayNotAuthorize` (adversarial data is
    ///   automatically prevented from authorizing privileged actions)
    pub fn from_integrity(integ: IntegLevel) -> Self {
        match integ {
            IntegLevel::Adversarial => MemoryAuthority::MayNotAuthorize,
            IntegLevel::Untrusted | IntegLevel::Trusted => MemoryAuthority::MayInform,
        }
    }
}

/// A record of a previous value that was superseded by a write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuttalEntry {
    /// The previous value before it was overwritten.
    pub previous_value: String,
    /// Unix timestamp when this value was replaced.
    pub replaced_at: u64,
    /// Human-readable reason the value was superseded.
    pub reason: String,
    /// The label of the previous entry (#1229) — preserved for forensic
    /// analysis. Without this, taint laundering via overwrite leaves no trace.
    #[serde(default = "default_rebuttal_label")]
    pub previous_label: MemoryLabel,
    /// The authority of the previous entry (#1229).
    #[serde(default = "default_rebuttal_authority")]
    pub previous_authority: MemoryAuthority,
}

fn default_rebuttal_label() -> MemoryLabel {
    MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Untrusted)
}

fn default_rebuttal_authority() -> MemoryAuthority {
    MemoryAuthority::MayNotAuthorize
}

impl GovernedMemory {
    /// Create an empty memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a memory entry with the given label.
    ///
    /// Returns false if max_entries would be exceeded (entry not written).
    ///
    /// **Authority is automatically derived from the label's integrity level**
    /// via [`MemoryAuthority::from_integrity()`]:
    /// - `IntegLevel::Trusted` / `IntegLevel::Untrusted` → `MayInform`
    /// - `IntegLevel::Adversarial` → `MayNotAuthorize` (fail-safe protection
    ///   against memory poisoning — adversarial data can never silently acquire
    ///   informational authority through the convenience API)
    ///
    /// Uses empty provenance by default. Use [`write_governed`] or
    /// [`write_with_provenance`] to specify authority and provenance explicitly.
    pub fn write(
        &mut self,
        key: String,
        value: String,
        schema: SchemaType,
        label: MemoryLabel,
        now: u64,
        ttl_secs: u64,
    ) -> bool {
        let authority = MemoryAuthority::from_integrity(label.integrity);
        self.write_with_limit(
            key,
            value,
            schema,
            label,
            authority,
            ProvenanceSet::EMPTY,
            now,
            ttl_secs,
            1000,
        )
    }

    /// Write a memory entry with explicit authority class.
    ///
    /// Entries from adversarial or web-tainted sources should use
    /// [`MemoryAuthority::MayNotAuthorize`] to prevent poisoned memory
    /// from acquiring operational authority.
    #[allow(clippy::too_many_arguments)]
    pub fn write_governed(
        &mut self,
        key: String,
        value: String,
        schema: SchemaType,
        label: MemoryLabel,
        authority: MemoryAuthority,
        now: u64,
        ttl_secs: u64,
    ) -> bool {
        self.write_with_limit(
            key,
            value,
            schema,
            label,
            authority,
            ProvenanceSet::EMPTY,
            now,
            ttl_secs,
            1000,
        )
    }

    /// Write a memory entry with explicit authority class and provenance.
    ///
    /// This is the most precise write variant (short of `write_with_limit`) —
    /// callers specify exactly where the data originated so downstream flow
    /// analysis can track taint through the memory plane.
    #[allow(clippy::too_many_arguments)]
    pub fn write_with_provenance(
        &mut self,
        key: String,
        value: String,
        schema: SchemaType,
        label: MemoryLabel,
        authority: MemoryAuthority,
        provenance: ProvenanceSet,
        now: u64,
        ttl_secs: u64,
    ) -> bool {
        self.write_with_limit(
            key, value, schema, label, authority, provenance, now, ttl_secs, 1000,
        )
    }

    /// Write with explicit max_entries limit, authority class, and provenance
    /// (#587, #508, #640).
    ///
    /// When overwriting an existing key, the previous value is pushed
    /// onto the rebuttal history (capped at [`MAX_REBUTTAL_HISTORY`]).
    ///
    /// **Invariant enforcement:** If `label.integrity == IntegLevel::Adversarial`,
    /// the caller-supplied `authority` is silently overridden to
    /// `MemoryAuthority::MayNotAuthorize` regardless of what was passed. This
    /// prevents authority escalation on adversarial entries (#1178).
    #[allow(clippy::too_many_arguments)]
    pub fn write_with_limit(
        &mut self,
        key: String,
        value: String,
        schema: SchemaType,
        label: MemoryLabel,
        authority: MemoryAuthority,
        provenance: ProvenanceSet,
        now: u64,
        ttl_secs: u64,
        max_entries: usize,
    ) -> bool {
        // Invariant: adversarial-integrity entries can never hold informational
        // authority, regardless of what the caller passed (#1178).
        let authority = if label.integrity == IntegLevel::Adversarial {
            MemoryAuthority::MayNotAuthorize
        } else {
            authority
        };

        // If key already exists, allow overwrite (doesn't increase count)
        if !self.entries.contains_key(&key) && self.entries.len() >= max_entries {
            return false; // Reject: would exceed limit
        }

        // Monotonic integrity gate (#1229): overwriting an entry must NOT
        // raise the integrity level (lower the restriction). An adversarial
        // entry cannot be silently promoted to trusted — that would be taint
        // laundering. The only way to raise integrity is through an explicit
        // declassification path with human authorization.
        //
        // Biba ordering: Adversarial(0) < Untrusted(1) < Trusted(2).
        // "New label has higher integrity" means it's LESS restrictive.
        if let Some(old) = self.entries.get(&key)
            && label.integrity > old.label.integrity
        {
            return false; // Reject: would lower restriction (launder taint)
        }

        // Preserve rebuttal history from the previous entry (if any).
        let mut rebuttal_history = Vec::new();
        if let Some(old) = self.entries.remove(&key) {
            // Carry forward existing rebuttal history.
            rebuttal_history = old.rebuttal_history;
            // Push the superseded value onto the front, preserving old label + authority.
            rebuttal_history.insert(
                0,
                RebuttalEntry {
                    previous_value: old.value,
                    replaced_at: now,
                    reason: String::new(),
                    previous_label: old.label,
                    previous_authority: old.authority,
                },
            );
            // Cap at MAX_REBUTTAL_HISTORY.
            rebuttal_history.truncate(MAX_REBUTTAL_HISTORY);
        }

        self.entries.insert(
            key,
            MemoryEntry {
                value,
                schema,
                label,
                authority,
                provenance,
                created_at: now,
                ttl_secs,
                rebuttal_history,
            },
        );
        true
    }

    /// Read a memory entry (returns None if not found or expired).
    pub fn read(&self, key: &str, now: u64) -> Option<&MemoryEntry> {
        self.entries.get(key).filter(|e| !e.is_expired(now))
    }

    /// Get the IFC label for a memory read (for flow graph observation).
    ///
    /// The returned label's provenance is the union of the entry's stored
    /// provenance and `MEMORY` (since the data is being read *from* memory).
    /// This ensures downstream flow analysis sees both the original source
    /// and the memory-channel taint.
    ///
    /// `MayNotAuthorize` entries produce `AuthorityLevel::NoAuthority`
    /// so they cannot become causal ancestors of privileged operations.
    pub fn read_label(&self, key: &str, now: u64) -> Option<IFCLabel> {
        self.read(key, now).map(|entry| {
            let authority = match entry.authority {
                MemoryAuthority::MayInform => AuthorityLevel::Informational,
                MemoryAuthority::MayNotAuthorize => AuthorityLevel::NoAuthority,
            };
            IFCLabel {
                confidentiality: entry.label.conf_level(),
                integrity: entry.label.integ_level(),
                authority,
                provenance: entry.provenance.union(ProvenanceSet::MEMORY),
                freshness: Freshness {
                    observed_at: entry.created_at,
                    ttl_secs: entry.ttl_secs,
                },
                // Propagate the stored derivation class (#1220).
                // Previously hardcoded to Deterministic, which laundered AI-derived
                // taint: any content stored via write() appeared Deterministic on
                // read, bypassing DerivationViolation checks for verified sinks.
                derivation: entry.label.derivation,
            }
        })
    }

    /// Get the rebuttal history for a key (empty if key doesn't exist).
    pub fn rebuttal_history(&self, key: &str, now: u64) -> &[RebuttalEntry] {
        self.read(key, now)
            .map(|e| e.rebuttal_history.as_slice())
            .unwrap_or(&[])
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

    /// Return all entries with `MayNotAuthorize` authority (poisoned memory).
    ///
    /// These entries were written from adversarial or web-tainted sources
    /// and MUST NOT be used as causal ancestors of privileged actions.
    /// Expired entries are excluded.
    pub fn poisoned_entries(&self, now: u64) -> Vec<(&str, &MemoryEntry)> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_expired(now) && e.authority == MemoryAuthority::MayNotAuthorize)
            .map(|(k, e)| (k.as_str(), e))
            .collect()
    }

    /// Produce a full audit dump of every live entry's metadata.
    ///
    /// Returns key, provenance, authority, label, created_at, ttl, and
    /// rebuttal count for each non-expired entry — suitable for security
    /// inspection and compliance logging.
    pub fn audit_dump(&self, now: u64) -> Vec<AuditEntry<'_>> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_expired(now))
            .map(|(k, e)| AuditEntry {
                key: k.as_str(),
                provenance: e.provenance,
                authority: e.authority,
                confidentiality: e.label.conf_level(),
                integrity: e.label.integ_level(),
                created_at: e.created_at,
                ttl_secs: e.ttl_secs,
                rebuttal_count: e.rebuttal_history.len(),
            })
            .collect()
    }
}

/// A single row in the memory audit dump.
#[derive(Debug, Clone)]
pub struct AuditEntry<'a> {
    /// Memory key.
    pub key: &'a str,
    /// Provenance bitset tracking data origin.
    pub provenance: ProvenanceSet,
    /// Authority class.
    pub authority: MemoryAuthority,
    /// Confidentiality level.
    pub confidentiality: ConfLevel,
    /// Integrity level.
    pub integrity: IntegLevel,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// TTL in seconds (0 = no expiry).
    pub ttl_secs: u64,
    /// Number of rebuttal history entries.
    pub rebuttal_count: usize,
}

impl MemoryEntry {
    /// Is this entry expired?
    ///
    /// Uses `saturating_add` to prevent overflow: an adversarial `ttl_secs`
    /// that would wrap `created_at + ttl_secs` past `u64::MAX` is clamped to
    /// `u64::MAX`, making the entry appear non-expiring rather than
    /// unexpectedly expired or panicking (#1202).
    pub fn is_expired(&self, now: u64) -> bool {
        self.ttl_secs > 0 && now > self.created_at.saturating_add(self.ttl_secs)
    }
}

/// Memory governance configuration (from `.nucleus/memory.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct MemoryConfig {
    /// Default TTL for new entries (seconds). 0 = no expiry.
    #[serde(default)]
    pub default_ttl_secs: u64,
    /// Default confidentiality for new entries.
    #[serde(default = "default_conf_level")]
    pub default_confidentiality: ConfLevel,
    /// Maximum number of entries before oldest are evicted.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

fn default_conf_level() -> ConfLevel {
    ConfLevel::Internal
}

fn default_max_entries() -> usize {
    1000
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 0,
            default_confidentiality: default_conf_level(),
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
                MemoryAuthority::MayInform,
                ProvenanceSet::EMPTY,
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
            MemoryAuthority::MayInform,
            ProvenanceSet::EMPTY,
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
            MemoryAuthority::MayInform,
            ProvenanceSet::EMPTY,
            1000,
            0,
            3,
        ));
        assert_eq!(mem.read("key0", 1000).unwrap().value, "updated");
    }

    #[test]
    fn rebuttal_history_on_overwrite() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);

        // Initial write — no rebuttal history.
        mem.write(
            "key".into(),
            "v1".into(),
            SchemaType::String,
            label.clone(),
            1000,
            0,
        );
        assert!(mem.rebuttal_history("key", 1000).is_empty());

        // Overwrite — v1 moves to rebuttal history.
        mem.write(
            "key".into(),
            "v2".into(),
            SchemaType::String,
            label.clone(),
            2000,
            0,
        );
        let hist = mem.rebuttal_history("key", 2000);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].previous_value, "v1");
        assert_eq!(hist[0].replaced_at, 2000);

        // Second overwrite — v2 is newest rebuttal, v1 is second.
        mem.write(
            "key".into(),
            "v3".into(),
            SchemaType::String,
            label,
            3000,
            0,
        );
        let hist = mem.rebuttal_history("key", 3000);
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0].previous_value, "v2");
        assert_eq!(hist[1].previous_value, "v1");
    }

    #[test]
    fn rebuttal_history_capped_at_max() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);

        // Write 12 times — only the last 10 rebuttals should be kept.
        for i in 0..12 {
            mem.write(
                "key".into(),
                format!("v{i}"),
                SchemaType::String,
                label.clone(),
                1000 + i as u64,
                0,
            );
        }

        let hist = mem.rebuttal_history("key", 2000);
        assert_eq!(hist.len(), MAX_REBUTTAL_HISTORY);
        // Most recent rebuttal is v10 (the value just before v11).
        assert_eq!(hist[0].previous_value, "v10");
        // Oldest retained is v1 (v0 was evicted).
        assert_eq!(hist[MAX_REBUTTAL_HISTORY - 1].previous_value, "v1");
    }

    #[test]
    fn may_not_authorize_produces_no_authority() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Adversarial);

        // Write with MayNotAuthorize — simulating web-tainted data.
        mem.write_governed(
            "tainted".into(),
            "from-web".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayNotAuthorize,
            1000,
            0,
        );

        let ifc = mem.read_label("tainted", 1000).unwrap();
        assert_eq!(ifc.authority, AuthorityLevel::NoAuthority);
        assert_eq!(ifc.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn may_inform_produces_informational() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);

        mem.write_governed(
            "trusted".into(),
            "safe-data".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayInform,
            1000,
            0,
        );

        let ifc = mem.read_label("trusted", 1000).unwrap();
        assert_eq!(ifc.authority, AuthorityLevel::Informational);
    }

    #[test]
    fn write_trusted_derives_may_inform() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);

        // write() with Trusted integrity derives MayInform.
        mem.write(
            "key".into(),
            "val".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );
        let entry = mem.read("key", 1000).unwrap();
        assert_eq!(entry.authority, MemoryAuthority::MayInform);
    }

    #[test]
    fn write_untrusted_derives_may_inform() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Untrusted);

        // write() with Untrusted integrity still derives MayInform.
        mem.write(
            "key".into(),
            "val".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );
        let entry = mem.read("key", 1000).unwrap();
        assert_eq!(entry.authority, MemoryAuthority::MayInform);
    }

    #[test]
    fn write_adversarial_derives_may_not_authorize() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Adversarial);

        // write() with Adversarial integrity automatically derives MayNotAuthorize —
        // this is the fail-safe protection against memory poisoning (#737).
        mem.write(
            "key".into(),
            "val".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );
        let entry = mem.read("key", 1000).unwrap();
        assert_eq!(entry.authority, MemoryAuthority::MayNotAuthorize);

        // Confirm read_label produces NoAuthority for adversarial write().
        let ifc = mem.read_label("key", 1000).unwrap();
        assert_eq!(ifc.authority, AuthorityLevel::NoAuthority);
    }

    #[test]
    fn from_integrity_mapping() {
        assert_eq!(
            MemoryAuthority::from_integrity(IntegLevel::Trusted),
            MemoryAuthority::MayInform,
        );
        assert_eq!(
            MemoryAuthority::from_integrity(IntegLevel::Untrusted),
            MemoryAuthority::MayInform,
        );
        assert_eq!(
            MemoryAuthority::from_integrity(IntegLevel::Adversarial),
            MemoryAuthority::MayNotAuthorize,
        );
    }

    #[test]
    fn rebuttal_history_preserves_across_authority_change() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);

        // Write trusted entry.
        mem.write_governed(
            "key".into(),
            "trusted-v1".into(),
            SchemaType::String,
            label.clone(),
            MemoryAuthority::MayInform,
            1000,
            0,
        );

        // Overwrite with tainted entry — old value in rebuttal history.
        let tainted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Adversarial);
        mem.write_governed(
            "key".into(),
            "tainted-v2".into(),
            SchemaType::String,
            tainted_label,
            MemoryAuthority::MayNotAuthorize,
            2000,
            0,
        );

        let entry = mem.read("key", 2000).unwrap();
        assert_eq!(entry.authority, MemoryAuthority::MayNotAuthorize);
        assert_eq!(entry.rebuttal_history.len(), 1);
        assert_eq!(entry.rebuttal_history[0].previous_value, "trusted-v1");

        // IFC label reflects the new authority.
        let ifc = mem.read_label("key", 2000).unwrap();
        assert_eq!(ifc.authority, AuthorityLevel::NoAuthority);
    }

    // --- Provenance tracking tests (#640) ---

    #[test]
    fn write_with_provenance_stores_provenance() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Untrusted);

        mem.write_with_provenance(
            "web-data".into(),
            "scraped".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayNotAuthorize,
            ProvenanceSet::WEB,
            1000,
            3600,
        );

        let entry = mem.read("web-data", 1000).unwrap();
        assert!(entry.provenance.contains(ProvenanceSet::WEB));
        assert!(!entry.provenance.contains(ProvenanceSet::USER));
    }

    #[test]
    fn read_label_unions_provenance_with_memory() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);

        // Write with USER provenance.
        mem.write_with_provenance(
            "user-note".into(),
            "hello".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayInform,
            ProvenanceSet::USER,
            1000,
            0,
        );

        // read_label should produce USER | MEMORY.
        let ifc = mem.read_label("user-note", 1000).unwrap();
        assert!(ifc.provenance.contains(ProvenanceSet::USER));
        assert!(ifc.provenance.contains(ProvenanceSet::MEMORY));
    }

    #[test]
    fn default_write_has_empty_provenance() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);

        mem.write(
            "key".into(),
            "val".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );

        let entry = mem.read("key", 1000).unwrap();
        assert_eq!(entry.provenance, ProvenanceSet::EMPTY);

        // read_label still has MEMORY even with empty stored provenance.
        let ifc = mem.read_label("key", 1000).unwrap();
        assert!(ifc.provenance.contains(ProvenanceSet::MEMORY));
    }

    #[test]
    fn multi_source_provenance() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Untrusted);
        let prov = ProvenanceSet::WEB.union(ProvenanceSet::TOOL);

        mem.write_with_provenance(
            "mixed".into(),
            "data".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayNotAuthorize,
            prov,
            1000,
            0,
        );

        let entry = mem.read("mixed", 1000).unwrap();
        assert!(entry.provenance.contains(ProvenanceSet::WEB));
        assert!(entry.provenance.contains(ProvenanceSet::TOOL));
        assert!(!entry.provenance.contains(ProvenanceSet::SYSTEM));
    }

    // --- Poisoned entries tests (#640) ---

    #[test]
    fn poisoned_entries_returns_may_not_authorize() {
        let mut mem = GovernedMemory::new();
        let trusted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);
        let tainted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Adversarial);

        // One trusted entry.
        mem.write_with_provenance(
            "safe".into(),
            "ok".into(),
            SchemaType::String,
            trusted_label,
            MemoryAuthority::MayInform,
            ProvenanceSet::USER,
            1000,
            0,
        );

        // Two poisoned entries.
        mem.write_with_provenance(
            "poison1".into(),
            "bad1".into(),
            SchemaType::String,
            tainted_label.clone(),
            MemoryAuthority::MayNotAuthorize,
            ProvenanceSet::WEB,
            1000,
            0,
        );
        mem.write_with_provenance(
            "poison2".into(),
            "bad2".into(),
            SchemaType::String,
            tainted_label,
            MemoryAuthority::MayNotAuthorize,
            ProvenanceSet::WEB.union(ProvenanceSet::MODEL),
            1000,
            0,
        );

        let poisoned = mem.poisoned_entries(1000);
        assert_eq!(poisoned.len(), 2);
        // All returned entries are MayNotAuthorize.
        for (_, entry) in &poisoned {
            assert_eq!(entry.authority, MemoryAuthority::MayNotAuthorize);
        }
    }

    #[test]
    fn poisoned_entries_excludes_expired() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Adversarial);

        mem.write_with_provenance(
            "expired-poison".into(),
            "old".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayNotAuthorize,
            ProvenanceSet::WEB,
            1000,
            10, // Expires at 1010
        );

        assert_eq!(mem.poisoned_entries(1005).len(), 1); // Still alive
        assert_eq!(mem.poisoned_entries(1011).len(), 0); // Expired
    }

    // --- Audit dump tests (#640) ---

    #[test]
    fn audit_dump_captures_all_metadata() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Secret, IntegLevel::Trusted);

        mem.write_with_provenance(
            "secret-key".into(),
            "v1".into(),
            SchemaType::String,
            label.clone(),
            MemoryAuthority::MayInform,
            ProvenanceSet::SYSTEM,
            1000,
            3600,
        );

        // Overwrite to create rebuttal history.
        mem.write_with_provenance(
            "secret-key".into(),
            "v2".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayInform,
            ProvenanceSet::SYSTEM,
            2000,
            3600,
        );

        let dump = mem.audit_dump(2000);
        assert_eq!(dump.len(), 1);

        let row = &dump[0];
        assert_eq!(row.key, "secret-key");
        assert!(row.provenance.contains(ProvenanceSet::SYSTEM));
        assert_eq!(row.authority, MemoryAuthority::MayInform);
        assert_eq!(row.confidentiality, ConfLevel::Secret);
        assert_eq!(row.integrity, IntegLevel::Trusted);
        assert_eq!(row.created_at, 2000);
        assert_eq!(row.ttl_secs, 3600);
        assert_eq!(row.rebuttal_count, 1);
    }

    #[test]
    fn audit_dump_excludes_expired() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);

        mem.write(
            "live".into(),
            "a".into(),
            SchemaType::String,
            label.clone(),
            1000,
            0,
        );
        mem.write(
            "dead".into(),
            "b".into(),
            SchemaType::String,
            label,
            1000,
            10,
        );

        let dump = mem.audit_dump(1011);
        assert_eq!(dump.len(), 1);
        assert_eq!(dump[0].key, "live");
    }

    #[test]
    fn audit_dump_shows_poisoned_provenance() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Adversarial);

        mem.write_with_provenance(
            "tainted".into(),
            "injected".into(),
            SchemaType::String,
            label,
            MemoryAuthority::MayNotAuthorize,
            ProvenanceSet::WEB.union(ProvenanceSet::MODEL),
            1000,
            0,
        );

        let dump = mem.audit_dump(1000);
        assert_eq!(dump.len(), 1);
        let row = &dump[0];
        assert_eq!(row.authority, MemoryAuthority::MayNotAuthorize);
        assert!(row.provenance.contains(ProvenanceSet::WEB));
        assert!(row.provenance.contains(ProvenanceSet::MODEL));
        assert_eq!(row.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn write_governed_cannot_escalate_adversarial_to_inform() {
        // #1178: write_governed must not let adversarial entries acquire MayInform authority.
        let mut mem = GovernedMemory::new();
        let adversarial_label =
            MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Adversarial);

        // Caller attempts to escalate by supplying MayInform for adversarial data.
        let ok = mem.write_governed(
            "poisoned".into(),
            "injected content".into(),
            SchemaType::String,
            adversarial_label,
            MemoryAuthority::MayInform, // attempted escalation
            0,
            0,
        );
        assert!(ok);

        // The stored entry must have MayNotAuthorize, not the caller-supplied MayInform.
        let entry = mem.read("poisoned", 0).unwrap();
        assert_eq!(
            entry.authority,
            MemoryAuthority::MayNotAuthorize,
            "adversarial entry must not hold MayInform authority"
        );

        // It must appear in poisoned_entries().
        assert_eq!(mem.poisoned_entries(0).len(), 1);
    }

    #[test]
    fn write_with_limit_cannot_escalate_adversarial() {
        // #1178: invariant is enforced at write_with_limit, the lowest write path.
        let mut mem = GovernedMemory::new();
        let adversarial_label =
            MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Adversarial);

        mem.write_with_limit(
            "k".into(),
            "v".into(),
            SchemaType::String,
            adversarial_label,
            MemoryAuthority::MayInform, // attempted escalation
            crate::ProvenanceSet::EMPTY,
            0,
            0,
            1000,
        );

        let entry = mem.read("k", 0).unwrap();
        assert_eq!(entry.authority, MemoryAuthority::MayNotAuthorize);
    }

    // ── is_expired overflow safety (#1202) ──────────────────────────────

    fn make_entry(created_at: u64, ttl_secs: u64) -> MemoryEntry {
        MemoryEntry {
            value: "v".to_string(),
            schema: SchemaType::String,
            label: MemoryLabel::from_levels(crate::ConfLevel::Public, crate::IntegLevel::Trusted),
            authority: MemoryAuthority::MayNotAuthorize,
            provenance: ProvenanceSet::default(),
            created_at,
            ttl_secs,
            rebuttal_history: Vec::new(),
        }
    }

    #[test]
    fn is_expired_does_not_panic_on_max_ttl() {
        // Adversarial: ttl_secs = u64::MAX would overflow in debug without saturating_add.
        let entry = make_entry(1_000_000, u64::MAX);
        // saturating_add clamps to u64::MAX; entry is treated as non-expiring.
        assert!(!entry.is_expired(u64::MAX));
        assert!(!entry.is_expired(1_000_001));
    }

    #[test]
    fn is_expired_overflow_does_not_produce_false_expiry() {
        // Without saturating_add, created_at=1_000_000 + ttl=u64::MAX-999_999 wraps to 0,
        // making now > 0 always true. With saturating_add it clamps to u64::MAX.
        let entry = make_entry(1_000_000, u64::MAX - 999_999);
        // saturating_add → u64::MAX; now=2_000_000 < u64::MAX → not expired.
        assert!(!entry.is_expired(2_000_000));
    }

    // ── Derivation tracking through memory plane (#1220) ─────────────────────

    #[test]
    fn read_label_propagates_ai_derived_derivation() {
        // The laundering bug: AI-derived content stored in memory was read back
        // with DerivationClass::Deterministic, bypassing DerivationViolation checks.
        // After the fix, read_label must return the stored derivation class.
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Internal,
            IntegLevel::Trusted,
            crate::DerivationClass::AIDerived,
        );

        mem.write(
            "ai-content".into(),
            "model output".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );

        let ifc = mem.read_label("ai-content", 1000).unwrap();
        assert_eq!(
            ifc.derivation,
            crate::DerivationClass::AIDerived,
            "AI-derived content must not be laundered to Deterministic on read"
        );
    }

    #[test]
    fn read_label_propagates_mixed_derivation() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Internal,
            IntegLevel::Untrusted,
            crate::DerivationClass::Mixed,
        );
        mem.write(
            "mixed".into(),
            "val".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );
        let ifc = mem.read_label("mixed", 1000).unwrap();
        assert_eq!(ifc.derivation, crate::DerivationClass::Mixed);
    }

    #[test]
    fn read_label_propagates_opaque_external_derivation() {
        let mut mem = GovernedMemory::new();
        let label = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Secret,
            IntegLevel::Adversarial,
            crate::DerivationClass::OpaqueExternal,
        );
        mem.write(
            "opaque".into(),
            "val".into(),
            SchemaType::String,
            label,
            1000,
            0,
        );
        let ifc = mem.read_label("opaque", 1000).unwrap();
        assert_eq!(ifc.derivation, crate::DerivationClass::OpaqueExternal);
    }

    #[test]
    fn from_levels_defaults_to_deterministic() {
        // from_levels is the existing convenience constructor; it must keep
        // defaulting to Deterministic so callers storing known-deterministic
        // data (config, tool outputs) are unaffected.
        let label = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);
        assert_eq!(label.derivation, crate::DerivationClass::Deterministic);
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn serde_roundtrip_preserves_derivation() {
        let label = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Internal,
            IntegLevel::Trusted,
            crate::DerivationClass::HumanPromoted,
        );
        let json = serde_json::to_string(&label).unwrap();
        let restored: MemoryLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.derivation, crate::DerivationClass::HumanPromoted);
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn serde_missing_derivation_defaults_to_deterministic() {
        let json = r#"{"confidentiality":"internal","integrity":"trusted"}"#;
        let label: MemoryLabel = serde_json::from_str(json).unwrap();
        assert_eq!(label.derivation, crate::DerivationClass::Deterministic);
    }

    // ── Integrity monotonicity (#1229) ──────────────────────────────────

    #[test]
    fn overwrite_cannot_raise_integrity() {
        // Write adversarial, then try to overwrite with trusted → rejected
        let mut mem = GovernedMemory::new();
        let adversarial_label =
            MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Adversarial);
        let trusted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);

        mem.write_with_limit(
            "key".into(),
            "adversarial data".into(),
            SchemaType::String,
            adversarial_label,
            MemoryAuthority::MayNotAuthorize,
            crate::ProvenanceSet::WEB,
            1000,
            0,
            100,
        );

        // Overwrite with trusted label → should be rejected
        let ok = mem.write_with_limit(
            "key".into(),
            "laundered data".into(),
            SchemaType::String,
            trusted_label,
            MemoryAuthority::MayInform,
            crate::ProvenanceSet::EMPTY,
            1001,
            0,
            100,
        );
        assert!(!ok, "raising integrity on overwrite should be rejected");

        // Original entry should remain adversarial
        let entry = mem.read("key", 1001).unwrap();
        assert_eq!(entry.label.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn overwrite_can_lower_or_maintain_integrity() {
        // Write trusted, then overwrite with untrusted → allowed (more restrictive)
        let mut mem = GovernedMemory::new();
        let trusted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);
        let untrusted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Untrusted);

        mem.write_with_limit(
            "key".into(),
            "original".into(),
            SchemaType::String,
            trusted_label,
            MemoryAuthority::MayInform,
            crate::ProvenanceSet::EMPTY,
            1000,
            0,
            100,
        );

        let ok = mem.write_with_limit(
            "key".into(),
            "updated".into(),
            SchemaType::String,
            untrusted_label,
            MemoryAuthority::MayInform,
            crate::ProvenanceSet::EMPTY,
            1001,
            0,
            100,
        );
        assert!(ok, "lowering integrity should be allowed");
        assert_eq!(mem.read("key", 1001).unwrap().value, "updated");
    }

    #[test]
    fn rebuttal_entry_preserves_old_label() {
        let mut mem = GovernedMemory::new();
        let trusted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Trusted);
        let untrusted_label = MemoryLabel::from_levels(ConfLevel::Internal, IntegLevel::Untrusted);

        mem.write_with_limit(
            "key".into(),
            "v1".into(),
            SchemaType::String,
            trusted_label,
            MemoryAuthority::MayInform,
            crate::ProvenanceSet::EMPTY,
            1000,
            0,
            100,
        );
        mem.write_with_limit(
            "key".into(),
            "v2".into(),
            SchemaType::String,
            untrusted_label,
            MemoryAuthority::MayInform,
            crate::ProvenanceSet::EMPTY,
            1001,
            0,
            100,
        );

        let entry = mem.read("key", 1001).unwrap();
        assert_eq!(entry.rebuttal_history.len(), 1);
        let rebuttal = &entry.rebuttal_history[0];
        assert_eq!(rebuttal.previous_value, "v1");
        assert_eq!(rebuttal.previous_label.integrity, IntegLevel::Trusted);
        assert_eq!(rebuttal.previous_authority, MemoryAuthority::MayInform);
    }
}
