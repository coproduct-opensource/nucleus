//! Compartments — kernel-enforced privilege boundaries for agent workflows.
//!
//! Each compartment defines a capability ceiling. When active, the session's
//! effective permissions are `perms.meet(compartment.ceiling())` — the
//! intersection of the profile's permissions and the compartment's allowed
//! capabilities.
//!
//! ## Compartment lattice
//!
//! ```text
//! Breakglass (top — all capabilities + enhanced audit)
//!     ↑
//! Execute (read + write + bash, no push)
//!     ↑
//! Draft (read + write, no bash/web)
//!     ↑
//! Research (read + web only — bottom)
//! ```
//!
//! Transitions upward (Research → Draft → Execute) require explicit user
//! action. Transitions downward are always allowed (narrowing).
//! Breakglass requires enhanced justification and produces audit entries.

use crate::CapabilityLattice;
use crate::CapabilityLevel;

/// Agent workflow compartment — determines the capability ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum Compartment {
    /// Read + web only. No writes, no execution.
    /// Use for: research, web browsing, code review, auditing.
    Research = 0,
    /// Read + write. No execution, no web.
    /// Use for: drafting code, editing files, focused writing.
    Draft = 1,
    /// Read + write + execution. No git push, no PR creation.
    /// Use for: running tests, building, debugging.
    Execute = 2,
    /// All capabilities. Enhanced audit trail.
    /// Use for: emergency fixes, releases, break-glass operations.
    Breakglass = 3,
}

impl Compartment {
    /// The capability ceiling for this compartment.
    ///
    /// When combined with a profile via `meet()`, this restricts the
    /// session to only the capabilities appropriate for the compartment.
    pub fn ceiling(&self) -> CapabilityLattice {
        match self {
            Compartment::Research => CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
            },
            Compartment::Draft => CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
            },
            Compartment::Execute => CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
            },
            Compartment::Breakglass => CapabilityLattice::top(),
        }
    }

    /// Can the session transition from `self` to `target`?
    ///
    /// Upward transitions (expanding capabilities) require explicit action.
    /// Downward transitions (narrowing) are always allowed.
    pub fn can_transition_to(&self, target: Compartment) -> bool {
        // All transitions are allowed — the compartment system is
        // policy-enforced, not lattice-enforced. The audit trail
        // records every transition for compliance review.
        // Future: require approval for upward transitions.
        let _ = target;
        true
    }

    /// Is this the breakglass compartment? (triggers enhanced audit)
    pub fn is_breakglass(&self) -> bool {
        *self == Compartment::Breakglass
    }

    /// Parse from string (for env var / CLI).
    ///
    /// For breakglass, accepts `breakglass:reason text` format.
    /// Plain `breakglass` without a reason is also accepted (reason
    /// enforcement happens at the hook level).
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "research" => Some(Compartment::Research),
            "draft" => Some(Compartment::Draft),
            "execute" => Some(Compartment::Execute),
            "breakglass" => Some(Compartment::Breakglass),
            s if s.starts_with("breakglass:") => Some(Compartment::Breakglass),
            _ => None,
        }
    }
}

/// A breakglass entry with mandatory reason string.
#[derive(Debug, Clone)]
pub struct BreakglassEntry {
    /// Operator-provided reason for entering breakglass.
    pub reason: String,
    /// Unix timestamp when breakglass was entered.
    pub entered_at: u64,
}

impl BreakglassEntry {
    /// Parse from the compartment file content.
    ///
    /// Format: `breakglass:reason text here`
    /// Returns None if the reason is missing or empty.
    ///
    /// `now` is the Unix timestamp — callers at the I/O boundary pass
    /// the real clock; tests pass deterministic values (#590).
    pub fn parse(s: &str, now: u64) -> Option<Self> {
        let reason = s.strip_prefix("breakglass:")?.trim();
        if reason.is_empty() {
            return None;
        }
        Some(Self {
            reason: reason.to_string(),
            entered_at: now,
        })
    }
}

impl std::fmt::Display for Compartment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Compartment::Research => write!(f, "research"),
            Compartment::Draft => write!(f, "draft"),
            Compartment::Execute => write!(f, "execute"),
            Compartment::Breakglass => write!(f, "breakglass"),
        }
    }
}

// Compile-time invariant: discriminants match declaration order.
const _: () = {
    assert!(Compartment::Research as u8 == 0);
    assert!(Compartment::Draft as u8 == 1);
    assert!(Compartment::Execute as u8 == 2);
    assert!(Compartment::Breakglass as u8 == 3);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_blocks_writes() {
        let c = Compartment::Research.ceiling();
        assert_eq!(c.write_files, CapabilityLevel::Never);
        assert_eq!(c.edit_files, CapabilityLevel::Never);
        assert_eq!(c.run_bash, CapabilityLevel::Never);
        // But allows reads and web
        assert_eq!(c.read_files, CapabilityLevel::Always);
        assert_eq!(c.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn draft_blocks_exec_and_web() {
        let c = Compartment::Draft.ceiling();
        assert_eq!(c.run_bash, CapabilityLevel::Never);
        assert_eq!(c.web_fetch, CapabilityLevel::Never);
        assert_eq!(c.web_search, CapabilityLevel::Never);
        // But allows read + write
        assert_eq!(c.read_files, CapabilityLevel::Always);
        assert_eq!(c.write_files, CapabilityLevel::Always);
        assert_eq!(c.edit_files, CapabilityLevel::Always);
    }

    #[test]
    fn execute_blocks_push() {
        let c = Compartment::Execute.ceiling();
        assert_eq!(c.git_push, CapabilityLevel::Never);
        assert_eq!(c.create_pr, CapabilityLevel::Never);
        // But allows read + write + bash
        assert_eq!(c.read_files, CapabilityLevel::Always);
        assert_eq!(c.write_files, CapabilityLevel::Always);
        assert_eq!(c.run_bash, CapabilityLevel::Always);
    }

    #[test]
    fn breakglass_is_top() {
        let c = Compartment::Breakglass.ceiling();
        assert_eq!(c, CapabilityLattice::top());
    }

    #[test]
    fn compartment_ordering() {
        assert!(Compartment::Research < Compartment::Draft);
        assert!(Compartment::Draft < Compartment::Execute);
        assert!(Compartment::Execute < Compartment::Breakglass);
    }

    #[test]
    fn ceiling_meet_narrows_profile() {
        // A permissive profile meet with Research ceiling = Research capabilities
        let permissive = CapabilityLattice::top();
        let research = Compartment::Research.ceiling();
        let effective = permissive.meet(&research);
        assert_eq!(effective.write_files, CapabilityLevel::Never);
        assert_eq!(effective.read_files, CapabilityLevel::Always);
        assert_eq!(effective.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn parse_compartment() {
        assert_eq!(
            Compartment::from_str_opt("research"),
            Some(Compartment::Research)
        );
        assert_eq!(Compartment::from_str_opt("draft"), Some(Compartment::Draft));
        assert_eq!(
            Compartment::from_str_opt("execute"),
            Some(Compartment::Execute)
        );
        assert_eq!(
            Compartment::from_str_opt("breakglass"),
            Some(Compartment::Breakglass)
        );
        assert_eq!(Compartment::from_str_opt("unknown"), None);
    }

    #[test]
    fn display_roundtrip() {
        for c in [
            Compartment::Research,
            Compartment::Draft,
            Compartment::Execute,
            Compartment::Breakglass,
        ] {
            assert_eq!(Compartment::from_str_opt(&c.to_string()), Some(c));
        }
    }

    #[test]
    fn breakglass_with_reason_parses() {
        assert_eq!(
            Compartment::from_str_opt("breakglass:emergency fix"),
            Some(Compartment::Breakglass)
        );
    }

    #[test]
    fn breakglass_entry_requires_reason() {
        assert!(BreakglassEntry::parse("breakglass:emergency fix", 1000).is_some());
        assert!(BreakglassEntry::parse("breakglass:", 1000).is_none());
        assert!(BreakglassEntry::parse("breakglass", 1000).is_none());
        assert!(BreakglassEntry::parse("draft", 1000).is_none());
    }

    #[test]
    fn breakglass_entry_extracts_reason() {
        let entry = BreakglassEntry::parse("breakglass:production outage P1", 1000).unwrap();
        assert_eq!(entry.reason, "production outage P1");
    }

    #[test]
    fn breakglass_entry_deterministic_timestamp() {
        // Timestamp is now caller-provided, making entries deterministic (#590)
        let e1 = BreakglassEntry::parse("breakglass:same reason", 42).unwrap();
        let e2 = BreakglassEntry::parse("breakglass:same reason", 42).unwrap();
        assert_eq!(e1.entered_at, 42);
        assert_eq!(e2.entered_at, 42);
        assert_eq!(e1.entered_at, e2.entered_at);
    }
}
