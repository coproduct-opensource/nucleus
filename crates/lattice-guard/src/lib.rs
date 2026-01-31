//! # Lattice Guard
//!
//! A quotient lattice for AI agent permissions that prevents the "lethal trifecta".
//!
//! ## The Lethal Trifecta
//!
//! The [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) describes
//! three capabilities that, when combined in an AI agent, create critical security vulnerabilities:
//!
//! 1. **Access to private data** - reading files, credentials, secrets
//! 2. **Exposure to untrusted content** - web search, fetching URLs, processing external input
//! 3. **External communication** - git push, PR creation, API calls, command execution
//!
//! When an agent has all three at autonomous levels, prompt injection attacks can exfiltrate
//! private data without human oversight.
//!
//! ## Solution: Quotient Lattice
//!
//! This crate models permissions as a product lattice L with a **nucleus** operator
//! that projects onto the quotient lattice L' of safe configurations:
//!
//! ```text
//! L  = Capabilities × Paths × Budget × Commands × Time
//! L' = { x ∈ L : ν(x) = x }  (safe configurations)
//!
//! The nucleus operator ν:
//! • Is idempotent: ν(ν(x)) = ν(x)
//! • Is deflationary: ν(x) ≤ x
//! • Preserves meets: ν(x ∧ y) = ν(x) ∧ ν(y)
//! ```
//!
//! When the trifecta is detected, exfiltration capabilities are automatically
//! demoted to `AskFirst`, requiring human approval. The quotient L' contains
//! only configurations where this invariant holds.
//!
//! ## Quick Start
//!
//! ```rust
//! use lattice_guard::{PermissionLattice, CapabilityLevel};
//!
//! // Create a permission set with dangerous capabilities
//! let mut perms = PermissionLattice::default();
//! perms.capabilities.read_files = CapabilityLevel::Always;    // Private data
//! perms.capabilities.web_fetch = CapabilityLevel::LowRisk;    // Untrusted content
//! perms.capabilities.git_push = CapabilityLevel::LowRisk;     // Exfiltration
//!
//! // The meet operation detects the trifecta and demotes git_push
//! let safe = perms.meet(&perms);
//! assert_eq!(safe.capabilities.git_push, CapabilityLevel::AskFirst);
//! ```
//!
//! ## Integration with Claude Code / OpenClaw
//!
//! See the `examples/` directory for integration patterns with popular AI agent frameworks.
//!
//! ## Security Model
//!
//! See `THREAT_MODEL.md` for a complete description of what this crate prevents
//! and what it does not prevent.

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod budget;
mod capability;
mod command;
pub mod guard;
mod lattice;
mod path;
mod time;

pub use budget::BudgetLattice;
pub use capability::{CapabilityLattice, CapabilityLevel, IncompatibilityConstraint};
pub use command::CommandLattice;
pub use guard::{CompositeGuard, GuardError, GuardFn, GuardedAction, PermissionGuard};
pub use lattice::{DelegationError, EffectivePermissions, PermissionLattice, PermissionLatticeBuilder};
pub use path::PathLattice;
pub use time::TimeLattice;

/// Check if a glob pattern matches a path.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    path::glob_match(pattern, path)
}
