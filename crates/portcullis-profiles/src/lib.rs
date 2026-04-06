//! Application-specific task profiles for the portcullis policy engine.
//!
//! This crate provides pre-built task profiles (CodeReview, BugFix, DocsEdit,
//! Research) that map work categories to operation allowlists. These are
//! **application-specific presets**, not security primitives — they belong in
//! a plugin crate, not in the formal kernel (`portcullis-core`).
//!
//! ## Relationship to portcullis-core
//!
//! `portcullis-core` provides the generic `TaskScopePolicy` that accepts any
//! operation allowlist. This crate provides the named presets that map
//! human-meaningful task categories to those allowlists.
//!
//! ```text
//! portcullis-core:    TaskScopePolicy (generic, formal kernel)
//! portcullis-profiles: TaskKind presets (application-specific, plugin)
//! ```
//!
//! ## Usage
//!
//! ```rust
//! use portcullis_profiles::TaskKind;
//!
//! let kind = TaskKind::CodeReview;
//! let allowed = kind.allowed_operations();
//! let needs_approval = kind.approval_required_operations();
//! ```

pub use portcullis_core::Operation;

/// Application-specific task categories.
///
/// Each variant maps to a set of allowed and approval-required operations.
/// These are presets for common AI agent work patterns — integrators can
/// define their own task kinds by constructing `TaskScopePolicy` directly
/// with custom operation allowlists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskKind {
    /// Reviewing a PR or diff: read + search only; no pushes, no shell exec.
    CodeReview,
    /// Fixing a bug: broad access, but infra/deploy operations need approval.
    BugFix,
    /// Editing documentation: write allowed in docs paths; elsewhere needs approval.
    DocsEdit,
    /// Research / summarization: read and web access only; no mutations.
    Research,
}

impl TaskKind {
    /// Operations that are always allowed for this task kind.
    pub fn allowed_operations(&self) -> &'static [Operation] {
        match self {
            Self::CodeReview => &[
                Operation::ReadFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
            ],
            Self::BugFix => &[
                Operation::ReadFiles,
                Operation::WriteFiles,
                Operation::EditFiles,
                Operation::RunBash,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
                Operation::GitCommit,
            ],
            Self::DocsEdit => &[
                Operation::ReadFiles,
                Operation::WriteFiles,
                Operation::EditFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
            ],
            Self::Research => &[
                Operation::ReadFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
            ],
        }
    }

    /// Operations that require explicit human approval for this task kind.
    pub fn approval_required_operations(&self) -> &'static [Operation] {
        match self {
            Self::CodeReview => &[
                Operation::EditFiles,
                Operation::WriteFiles,
                Operation::RunBash,
                Operation::GitCommit,
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
            Self::BugFix => &[
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
            Self::DocsEdit => &[
                Operation::RunBash,
                Operation::GitCommit,
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
            Self::Research => &[
                Operation::WriteFiles,
                Operation::EditFiles,
                Operation::RunBash,
                Operation::GitCommit,
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_review_allows_read_not_write() {
        let ops = TaskKind::CodeReview.allowed_operations();
        assert!(ops.contains(&Operation::ReadFiles));
        assert!(!ops.contains(&Operation::WriteFiles));
        assert!(!ops.contains(&Operation::RunBash));
    }

    #[test]
    fn bugfix_allows_bash_and_commit() {
        let ops = TaskKind::BugFix.allowed_operations();
        assert!(ops.contains(&Operation::RunBash));
        assert!(ops.contains(&Operation::GitCommit));
        assert!(!ops.contains(&Operation::GitPush));
    }

    #[test]
    fn research_is_read_plus_web_only() {
        let ops = TaskKind::Research.allowed_operations();
        assert!(ops.contains(&Operation::ReadFiles));
        assert!(ops.contains(&Operation::WebFetch));
        assert!(!ops.contains(&Operation::WriteFiles));
        assert!(!ops.contains(&Operation::RunBash));
    }

    #[test]
    fn allowed_and_approval_are_disjoint() {
        for kind in [
            TaskKind::CodeReview,
            TaskKind::BugFix,
            TaskKind::DocsEdit,
            TaskKind::Research,
        ] {
            let allowed = kind.allowed_operations();
            let approval = kind.approval_required_operations();
            for op in allowed {
                assert!(
                    !approval.contains(op),
                    "{kind:?}: {op:?} is in both allowed and approval-required"
                );
            }
        }
    }
}
