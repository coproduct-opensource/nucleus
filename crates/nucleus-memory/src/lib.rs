//! # nucleus-memory — Governed Memory for AI Agents
//!
//! The only memory library with IFC labels and integrity tracking.
//! Detect memory poisoning attacks (MINJA, MemoryGraft) at the data level.
//!
//! ## Quick Start
//!
//! ```rust
//! use nucleus_memory::{GovernedMemory, MemoryLabel, MemoryAuthority, SchemaType, ConfLevel, IntegLevel};
//!
//! let mut mem = GovernedMemory::new();
//! let now = 1_000_000u64;
//!
//! // Store a trusted entry
//! let trusted = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted);
//! mem.write("api_key".to_string(), "sk-123".to_string(), SchemaType::String, trusted, now, 0);
//!
//! // Store web-derived data with adversarial label
//! let adversarial = MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Adversarial);
//! mem.write_governed(
//!     "search_result".to_string(),
//!     "some data".to_string(),
//!     SchemaType::String,
//!     adversarial,
//!     MemoryAuthority::MayNotAuthorize,
//!     now,
//!     0,
//! );
//!
//! // Detect poisoned entries
//! let poisoned = mem.poisoned_entries(now);
//! assert_eq!(poisoned.len(), 1);
//! ```
//!
//! ## Why Governed Memory?
//!
//! MINJA (NeurIPS 2025) achieved **95% injection success** against agent memory.
//! MemoryGraft implants fake experiences. OWASP added ASI06 (Memory Poisoning)
//! to the 2026 Agentic Top 10.
//!
//! Every competitor offers heuristic filtering. Nucleus tracks **per-entry IFC
//! labels** — confidentiality, integrity, authority class, and provenance bitflags.
//! Tainted entries can't silently influence privileged operations.

// Re-export the public API from portcullis-core.
pub use portcullis_core::memory::{
    GovernedMemory, MemoryAuthority, MemoryEntry, MemoryLabel, RebuttalEntry, SchemaType,
};
pub use portcullis_core::{ConfLevel, IntegLevel, ProvenanceSet};

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn trusted_label() -> MemoryLabel {
        MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Trusted)
    }

    fn adversarial_label() -> MemoryLabel {
        MemoryLabel::from_levels(ConfLevel::Public, IntegLevel::Adversarial)
    }

    // ── Basic read/write ──────────────────────────────────────────────────────

    #[test]
    fn write_and_read_basic_entry() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "key".to_string(),
            "value".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        let entry = mem.read("key", NOW).expect("entry should exist");
        assert_eq!(entry.value, "value");
    }

    #[test]
    fn missing_key_returns_none() {
        let mem = GovernedMemory::new();
        assert!(mem.read("nonexistent", NOW).is_none());
    }

    #[test]
    fn write_overwrites_existing_key() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "k".to_string(),
            "v1".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        mem.write(
            "k".to_string(),
            "v2".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW + 1,
            0,
        );
        assert_eq!(mem.read("k", NOW + 1).unwrap().value, "v2");
    }

    #[test]
    fn len_counts_live_entries() {
        let mut mem = GovernedMemory::new();
        assert_eq!(mem.len(), 0);
        mem.write(
            "a".to_string(),
            "1".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        mem.write(
            "b".to_string(),
            "2".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        assert_eq!(mem.len(), 2);
    }

    // ── Integrity labels ──────────────────────────────────────────────────────

    #[test]
    fn default_write_preserves_trusted_integrity() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "key".to_string(),
            "val".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        let entry = mem.read("key", NOW).unwrap();
        assert_eq!(entry.label.integrity, IntegLevel::Trusted);
    }

    #[test]
    fn governed_write_preserves_adversarial_label() {
        let mut mem = GovernedMemory::new();
        mem.write_governed(
            "web_result".to_string(),
            "injected data".to_string(),
            SchemaType::String,
            adversarial_label(),
            MemoryAuthority::MayNotAuthorize,
            NOW,
            0,
        );
        let entry = mem.read("web_result", NOW).unwrap();
        assert_eq!(entry.label.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn trusted_entry_has_may_inform_authority() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "safe".to_string(),
            "clean".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        let entry = mem.read("safe", NOW).unwrap();
        assert_eq!(entry.authority, MemoryAuthority::MayInform);
    }

    // ── Poisoning detection ───────────────────────────────────────────────────

    #[test]
    fn adversarial_entry_appears_in_poisoned_entries() {
        let mut mem = GovernedMemory::new();
        mem.write_governed(
            "poison".to_string(),
            "bad".to_string(),
            SchemaType::String,
            adversarial_label(),
            MemoryAuthority::MayNotAuthorize,
            NOW,
            0,
        );
        let poisoned = mem.poisoned_entries(NOW);
        assert_eq!(poisoned.len(), 1);
        assert_eq!(poisoned[0].0, "poison");
    }

    #[test]
    fn mixed_entries_only_adversarial_is_poisoned() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "clean".to_string(),
            "ok".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        mem.write_governed(
            "dirty".to_string(),
            "bad".to_string(),
            SchemaType::String,
            adversarial_label(),
            MemoryAuthority::MayNotAuthorize,
            NOW,
            0,
        );
        let poisoned = mem.poisoned_entries(NOW);
        assert_eq!(poisoned.len(), 1);
        assert_eq!(poisoned[0].0, "dirty");
    }

    #[test]
    fn empty_memory_has_no_poisoned_entries() {
        let mem = GovernedMemory::new();
        assert!(mem.poisoned_entries(NOW).is_empty());
    }

    #[test]
    fn trusted_only_memory_has_no_poisoned_entries() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "a".to_string(),
            "1".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        mem.write(
            "b".to_string(),
            "2".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        assert!(mem.poisoned_entries(NOW).is_empty());
    }

    // ── TTL / expiry ──────────────────────────────────────────────────────────

    #[test]
    fn entry_expires_after_ttl() {
        let mut mem = GovernedMemory::new();
        let ttl = 60u64;
        mem.write(
            "ephemeral".to_string(),
            "gone".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            ttl,
        );
        // Before expiry
        assert!(mem.read("ephemeral", NOW + 30).is_some());
        // After expiry
        assert!(mem.read("ephemeral", NOW + ttl + 1).is_none());
    }

    #[test]
    fn zero_ttl_never_expires() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "permanent".to_string(),
            "here".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        assert!(mem.read("permanent", NOW + 1_000_000).is_some());
    }

    #[test]
    fn gc_removes_expired_entries() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "temp".to_string(),
            "x".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            10,
        );
        assert_eq!(mem.len(), 1);
        mem.gc(NOW + 20);
        assert_eq!(mem.len(), 0);
    }

    #[test]
    fn gc_preserves_non_expired_entries() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "long".to_string(),
            "y".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            1_000,
        );
        mem.write(
            "short".to_string(),
            "z".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            10,
        );
        mem.gc(NOW + 20);
        assert_eq!(mem.len(), 1);
        assert!(mem.read("long", NOW + 20).is_some());
    }

    // ── Keys iteration ────────────────────────────────────────────────────────

    #[test]
    fn keys_returns_all_live_keys() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "alpha".to_string(),
            "1".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        mem.write(
            "beta".to_string(),
            "2".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        let mut keys: Vec<_> = mem.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["alpha", "beta"]);
    }

    // ── Rebuttal history ──────────────────────────────────────────────────────

    #[test]
    fn overwrite_creates_rebuttal_history() {
        let mut mem = GovernedMemory::new();
        mem.write(
            "k".to_string(),
            "v1".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW,
            0,
        );
        mem.write(
            "k".to_string(),
            "v2".to_string(),
            SchemaType::String,
            trusted_label(),
            NOW + 1,
            0,
        );
        let entry = mem.read("k", NOW + 1).unwrap();
        assert_eq!(entry.rebuttal_history.len(), 1);
        assert_eq!(entry.rebuttal_history[0].previous_value, "v1");
    }
}
