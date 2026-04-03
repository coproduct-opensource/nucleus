//! # nucleus-memory — Governed Memory for AI Agents
//!
//! The only memory library with IFC labels and integrity tracking.
//! Detect memory poisoning attacks (MINJA, MemoryGraft) at the data level.
//!
//! ## Quick Start
//!
//! ```rust
//! use nucleus_memory::{GovernedMemory, MemoryLabel, MemoryAuthority};
//!
//! let mut mem = GovernedMemory::new();
//! let now = 1000u64;
//!
//! // Store a secret with appropriate labels
//! mem.write("api_key", "sk-123".to_string(), now, None);
//!
//! // Store web-derived data with adversarial label
//! mem.write_governed(
//!     "search_result",
//!     "some data".to_string(),
//!     MemoryLabel::from_integrity(portcullis_core::IntegLevel::Adversarial),
//!     MemoryAuthority::MayInform,
//!     now,
//!     None,
//! );
//!
//! // Detect poisoned entries
//! let poisoned = mem.poisoned_entries(now);
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
    GovernedMemory, MemoryAuthority, MemoryEntry, MemoryLabel, RebuttalEntry,
};
pub use portcullis_core::{ConfLevel, IntegLevel, ProvenanceSet};
