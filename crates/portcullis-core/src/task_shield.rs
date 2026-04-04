//! Task Shield — task-alignment enforcement for runtime decisions.
//!
//! Provides two composable building blocks:
//!
//! 1. [`TaskWitness`] — a stable record of what the human asked for, including
//!    a deterministic hash (for audit/cache) and the coarse operation classes
//!    judged relevant to that task. Thread `Option<Arc<TaskWitness>>` through
//!    your [`PolicyRequest`] via [`PolicyRequest::with_task_witness`].
//!
//! 2. [`TaskScopePolicy`] — a [`PolicyCheck`] implementation that enforces
//!    scope based on a [`TaskKind`] enumeration. Ships a built-in operation
//!    allowlist per task kind, plus a path-sensitive rule for `DocsEdit`
//!    (writing outside docs-like paths requires approval).
//!
//! Both pieces are intentionally coarse and deterministic — no embedding
//! models, no planner rewrites. The goal is the smallest kernel surface that
//! future task-alignment work can build on.
//!
//! ## Example
//!
//! ```rust
//! use portcullis_core::task_shield::{TaskKind, TaskScopePolicy, TaskWitness};
//! use portcullis_core::combinators::{PolicyRequest, CheckResult};
//! use portcullis_core::CapabilityLevel;
//! use std::sync::Arc;
//!
//! // Declare what the human asked for.
//! let witness = Arc::new(TaskWitness::from_text("fix the failing unit test"));
//!
//! // Build a request and attach the witness.
//! let req = PolicyRequest::new("git_push", CapabilityLevel::Always)
//!     .with_task_witness(witness.clone());
//!
//! // TaskScopePolicy for BugFix: git_push requires approval (unusual for a test fix).
//! let policy = TaskScopePolicy::new(TaskKind::BugFix);
//! let result = portcullis_core::combinators::PolicyCheck::check(&policy, &req);
//! assert!(matches!(result, CheckResult::RequiresApproval(_)));
//! ```

use crate::Operation;
use crate::combinators::{CheckResult, PolicyCheck, PolicyRequest};

// ═══════════════════════════════════════════════════════════════════════════
// TaskWitness
// ═══════════════════════════════════════════════════════════════════════════

/// A stable record of what the human asked for.
///
/// Carry `Option<Arc<TaskWitness>>` through the runtime decision path
/// (via [`PolicyRequest::with_task_witness`]) so that every policy check
/// has access to the declared task scope without a global side-channel.
///
/// The `task_hash` is deterministic: same `task_text` always yields the same
/// 32-byte value. It is suitable for audit log deduplication and cache keys.
/// It is **not** cryptographically secure — treat it as a stable identifier,
/// not a commitment scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskWitness {
    /// Human-authored task summary or normalized task id.
    pub task_text: String,
    /// Stable 32-byte fingerprint of `task_text` for audit + cache lookup.
    pub task_hash: [u8; 32],
    /// Coarse operation classes judged relevant to the task.
    /// Empty means "no fine-grained scope declared" — checks should abstain.
    pub allowed_ops: Vec<Operation>,
}

impl TaskWitness {
    /// Construct a witness from a task description, computing a deterministic hash.
    ///
    /// `allowed_ops` is empty: the witness records the task text but does not
    /// constrain operations. Use [`TaskWitness::new`] to supply explicit ops.
    pub fn from_text(task_text: impl Into<String>) -> Self {
        let text: String = task_text.into();
        let hash = task_hash_of(&text);
        Self {
            task_text: text,
            task_hash: hash,
            allowed_ops: vec![],
        }
    }

    /// Construct a witness with an explicit operation allowlist.
    pub fn new(task_text: impl Into<String>, allowed_ops: Vec<Operation>) -> Self {
        let text: String = task_text.into();
        let hash = task_hash_of(&text);
        Self {
            task_text: text,
            task_hash: hash,
            allowed_ops,
        }
    }

    /// Returns `true` if `op` is in the declared allowlist,
    /// or if no allowlist was declared (empty `allowed_ops`).
    pub fn permits(&self, op: &Operation) -> bool {
        self.allowed_ops.is_empty() || self.allowed_ops.contains(op)
    }

    /// Hex encoding of `task_hash` for logging/audit entries.
    pub fn hash_hex(&self) -> String {
        self.task_hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Compute a deterministic 32-byte fingerprint of a task text.
///
/// Uses four rounds of FNV-1a with distinct seeds to fill 32 bytes.
/// The result is stable across process restarts and Rust versions
/// (no reliance on `DefaultHasher`).
fn task_hash_of(text: &str) -> [u8; 32] {
    const FNV_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;
    const SEEDS: [u64; 4] = [
        0x0000000000000000,
        0x9e3779b97f4a7c15,
        0x6c62272e07bb0142,
        0x517cc1b727220a95,
    ];

    let bytes = text.as_bytes();
    let mut out = [0u8; 32];

    for (round, &seed) in SEEDS.iter().enumerate() {
        let mut h = FNV_BASIS.wrapping_add(seed);
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        // Also mix in the seed to ensure round independence
        h ^= seed;
        h = h.wrapping_mul(FNV_PRIME);
        for i in 0..8usize {
            out[round * 8 + i] = (h >> (i * 8)) as u8;
        }
    }

    out
}

// ═══════════════════════════════════════════════════════════════════════════
// TaskKind
// ═══════════════════════════════════════════════════════════════════════════

/// Coarse task classification used by [`TaskScopePolicy`].
///
/// Each variant carries a built-in mapping from allowed/discouraged operations
/// that is used to gate or flag requests at enforcement time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskKind {
    /// Reviewing a PR or diff: read + search only; no pushes, no shell exec.
    CodeReview,
    /// Fixing a bug: broad access, but infra/deploy operations need approval.
    BugFix,
    /// Editing documentation: write allowed in docs paths; elsewhere → approval.
    DocsEdit,
    /// Research / summarization: read and web access only; no mutations.
    Research,
}

impl TaskKind {
    /// Returns the set of [`Operation`]s that are always allowed for this kind.
    ///
    /// Operations not listed are either discouraged (require approval) or
    /// fully denied, depending on the kind's policy severity.
    pub fn allowed_operations(&self) -> &'static [Operation] {
        match self {
            TaskKind::CodeReview => &[
                Operation::ReadFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
            ],
            TaskKind::BugFix => &[
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
            TaskKind::DocsEdit => &[
                Operation::ReadFiles,
                Operation::WriteFiles,
                Operation::EditFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
            ],
            TaskKind::Research => &[
                Operation::ReadFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
                Operation::WebFetch,
                Operation::WebSearch,
            ],
        }
    }

    /// Returns the set of [`Operation`]s that require explicit approval for this kind.
    ///
    /// An operation in this list is not fully denied — it is escalated to a human.
    pub fn approval_required_operations(&self) -> &'static [Operation] {
        match self {
            TaskKind::CodeReview => &[
                Operation::EditFiles,
                Operation::WriteFiles,
                Operation::RunBash,
                Operation::GitCommit,
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
            TaskKind::BugFix => &[
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
            TaskKind::DocsEdit => &[
                Operation::RunBash,
                Operation::GitCommit,
                Operation::GitPush,
                Operation::CreatePr,
                Operation::ManagePods,
                Operation::SpawnAgent,
            ],
            TaskKind::Research => &[
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

// ═══════════════════════════════════════════════════════════════════════════
// TaskScopePolicy
// ═══════════════════════════════════════════════════════════════════════════

/// Policy check that enforces scope based on a declared [`TaskKind`].
///
/// Composes with the existing combinator surface. Typical usage:
///
/// ```rust
/// use portcullis_core::task_shield::{TaskKind, TaskScopePolicy};
/// use portcullis_core::combinators::{first_match, PolicyCheck};
/// use portcullis_core::builtin_checks::ReadOnly;
///
/// let pipeline = first_match(vec![
///     Box::new(TaskScopePolicy::new(TaskKind::CodeReview)),
///     Box::new(ReadOnly),
/// ]);
/// ```
///
/// ### DocsEdit path-sensitive rule
///
/// When `kind == DocsEdit` and the operation is `WriteFiles` or `EditFiles`,
/// this check looks at the `path` context key. If the path does not look like
/// a documentation path (`docs/`, `.md`, `.rst`, `.txt` suffix or prefix), the
/// request is escalated to [`CheckResult::RequiresApproval`] regardless of the
/// base operation allowlist.
pub struct TaskScopePolicy {
    pub kind: TaskKind,
}

impl TaskScopePolicy {
    pub fn new(kind: TaskKind) -> Self {
        Self { kind }
    }
}

impl PolicyCheck for TaskScopePolicy {
    fn check(&self, req: &PolicyRequest) -> CheckResult {
        // Resolve the concrete operation from the request string.
        let op = match op_from_str(&req.operation) {
            Some(o) => o,
            // Unknown operation string → abstain; let the next check decide.
            None => return CheckResult::Abstain,
        };

        // DocsEdit path-sensitive rule: writing outside docs paths → approval.
        if self.kind == TaskKind::DocsEdit
            && matches!(op, Operation::WriteFiles | Operation::EditFiles)
        {
            // Only gate when we know the path; no context means allow (conservative).
            if let Some(path) = req.context.get("path").filter(|p| !is_docs_path(p)) {
                return CheckResult::RequiresApproval(format!(
                    "task-shield[DocsEdit]: writing '{}' is outside documentation \
                     paths — requires human approval",
                    path
                ));
            }
        }

        // Check against the TaskWitness allowed_ops if one is attached.
        if let Some(witness) = req
            .task_witness()
            .filter(|w| !w.allowed_ops.is_empty() && !w.allowed_ops.contains(&op))
        {
            return CheckResult::RequiresApproval(format!(
                "task-shield[witness]: '{}' is not in the declared task scope \
                 (task: '{}', hash: {})",
                req.operation,
                &witness.task_text[..witness.task_text.len().min(60)],
                &witness.hash_hex()[..8],
            ));
        }

        // Allowed operations: allow.
        if self.kind.allowed_operations().contains(&op) {
            return CheckResult::Allow;
        }

        // Approval-required operations: escalate.
        if self.kind.approval_required_operations().contains(&op) {
            return CheckResult::RequiresApproval(format!(
                "task-shield[{:?}]: '{}' requires human approval for this task kind",
                self.kind, req.operation
            ));
        }

        // Nothing matched — abstain and let the next check decide.
        CheckResult::Abstain
    }

    fn name(&self) -> &str {
        "TaskScopePolicy"
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Map the operation string used in [`PolicyRequest`] to a typed [`Operation`].
fn op_from_str(s: &str) -> Option<Operation> {
    match s {
        "read_files" => Some(Operation::ReadFiles),
        "write_files" => Some(Operation::WriteFiles),
        "edit_files" => Some(Operation::EditFiles),
        "run_bash" => Some(Operation::RunBash),
        "glob_search" => Some(Operation::GlobSearch),
        "grep_search" => Some(Operation::GrepSearch),
        "web_search" => Some(Operation::WebSearch),
        "web_fetch" => Some(Operation::WebFetch),
        "git_commit" => Some(Operation::GitCommit),
        "git_push" => Some(Operation::GitPush),
        "create_pr" => Some(Operation::CreatePr),
        "manage_pods" => Some(Operation::ManagePods),
        "spawn_agent" => Some(Operation::SpawnAgent),
        _ => None,
    }
}

/// Return `true` if `path` looks like a documentation path.
///
/// Heuristics (intentionally conservative):
/// - Starts with `docs/`, `doc/`, `documentation/`, or `README`
/// - Ends with `.md`, `.rst`, `.txt`, `.adoc`
fn is_docs_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    // Prefix heuristics
    let doc_prefixes = ["docs/", "doc/", "documentation/", "readme", "changelog"];
    if doc_prefixes.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    // Suffix heuristics
    let doc_suffixes = [".md", ".rst", ".txt", ".adoc", ".asciidoc"];
    if doc_suffixes.iter().any(|s| lower.ends_with(s)) {
        return true;
    }
    false
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityLevel;
    use crate::combinators::PolicyRequest;
    use std::sync::Arc;

    // ── TaskWitness ──────────────────────────────────────────────────────

    #[test]
    fn task_hash_is_deterministic() {
        let a = TaskWitness::from_text("fix the failing unit test");
        let b = TaskWitness::from_text("fix the failing unit test");
        assert_eq!(a.task_hash, b.task_hash);
    }

    #[test]
    fn task_hash_differs_for_different_text() {
        let a = TaskWitness::from_text("fix the failing unit test");
        let b = TaskWitness::from_text("review the open pull request");
        assert_ne!(a.task_hash, b.task_hash);
    }

    #[test]
    fn hash_hex_is_64_chars() {
        let w = TaskWitness::from_text("some task");
        assert_eq!(w.hash_hex().len(), 64);
    }

    #[test]
    fn permits_empty_allowlist_allows_anything() {
        let w = TaskWitness::from_text("generic task");
        assert!(w.permits(&Operation::GitPush));
        assert!(w.permits(&Operation::RunBash));
    }

    #[test]
    fn permits_with_allowlist() {
        let w = TaskWitness::new("fix test", vec![Operation::ReadFiles, Operation::EditFiles]);
        assert!(w.permits(&Operation::ReadFiles));
        assert!(w.permits(&Operation::EditFiles));
        assert!(!w.permits(&Operation::GitPush));
    }

    // ── TaskKind ─────────────────────────────────────────────────────────

    #[test]
    fn code_review_allows_read_only_ops() {
        let allowed = TaskKind::CodeReview.allowed_operations();
        assert!(allowed.contains(&Operation::ReadFiles));
        assert!(allowed.contains(&Operation::GrepSearch));
        assert!(!allowed.contains(&Operation::GitPush));
        assert!(!allowed.contains(&Operation::RunBash));
    }

    #[test]
    fn bug_fix_allows_commit_but_not_push() {
        let allowed = TaskKind::BugFix.allowed_operations();
        assert!(allowed.contains(&Operation::GitCommit));
        assert!(!allowed.contains(&Operation::GitPush));
        let approval = TaskKind::BugFix.approval_required_operations();
        assert!(approval.contains(&Operation::GitPush));
    }

    #[test]
    fn research_allows_read_and_web_only() {
        let allowed = TaskKind::Research.allowed_operations();
        assert!(allowed.contains(&Operation::WebSearch));
        assert!(allowed.contains(&Operation::WebFetch));
        assert!(!allowed.contains(&Operation::WriteFiles));
        assert!(!allowed.contains(&Operation::RunBash));
    }

    // ── TaskScopePolicy ──────────────────────────────────────────────────

    fn req(op: &str) -> PolicyRequest {
        PolicyRequest::new(op, CapabilityLevel::LowRisk)
    }

    fn req_always(op: &str) -> PolicyRequest {
        PolicyRequest::new(op, CapabilityLevel::Always)
    }

    #[test]
    fn code_review_allows_read_files() {
        let policy = TaskScopePolicy::new(TaskKind::CodeReview);
        assert!(policy.check(&req("read_files")).is_allow());
    }

    #[test]
    fn code_review_requires_approval_for_edit() {
        let policy = TaskScopePolicy::new(TaskKind::CodeReview);
        let result = policy.check(&req_always("edit_files"));
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn code_review_requires_approval_for_git_push() {
        let policy = TaskScopePolicy::new(TaskKind::CodeReview);
        let result = policy.check(&req_always("git_push"));
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn bug_fix_allows_run_bash() {
        let policy = TaskScopePolicy::new(TaskKind::BugFix);
        assert!(policy.check(&req("run_bash")).is_allow());
    }

    #[test]
    fn bug_fix_requires_approval_for_git_push() {
        let policy = TaskScopePolicy::new(TaskKind::BugFix);
        let result = policy.check(&req_always("git_push"));
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn docs_edit_allows_write_in_docs_path() {
        let policy = TaskScopePolicy::new(TaskKind::DocsEdit);
        let req = PolicyRequest::new("write_files", CapabilityLevel::Always)
            .with_context("path", "docs/getting-started.md");
        assert!(policy.check(&req).is_allow());
    }

    #[test]
    fn docs_edit_requires_approval_outside_docs_path() {
        let policy = TaskScopePolicy::new(TaskKind::DocsEdit);
        let req = PolicyRequest::new("edit_files", CapabilityLevel::Always)
            .with_context("path", "src/main.rs");
        let result = policy.check(&req);
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn docs_edit_allows_write_readme() {
        let policy = TaskScopePolicy::new(TaskKind::DocsEdit);
        let req = PolicyRequest::new("write_files", CapabilityLevel::Always)
            .with_context("path", "README.md");
        assert!(policy.check(&req).is_allow());
    }

    #[test]
    fn docs_edit_requires_approval_for_run_bash() {
        let policy = TaskScopePolicy::new(TaskKind::DocsEdit);
        let result = policy.check(&req("run_bash"));
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn research_allows_web_search() {
        let policy = TaskScopePolicy::new(TaskKind::Research);
        assert!(policy.check(&req("web_search")).is_allow());
    }

    #[test]
    fn research_requires_approval_for_write() {
        let policy = TaskScopePolicy::new(TaskKind::Research);
        let result = policy.check(&req_always("write_files"));
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn unknown_operation_abstains() {
        let policy = TaskScopePolicy::new(TaskKind::BugFix);
        let result = policy.check(&req("unknown_op"));
        assert_eq!(result, CheckResult::Abstain);
    }

    #[test]
    fn task_witness_gates_via_policy_request() {
        let witness = Arc::new(TaskWitness::new(
            "fix the test",
            vec![
                Operation::ReadFiles,
                Operation::EditFiles,
                Operation::RunBash,
            ],
        ));
        let policy = TaskScopePolicy::new(TaskKind::BugFix);

        // EditFiles is in witness.allowed_ops AND BugFix.allowed_operations
        let req_edit = PolicyRequest::new("edit_files", CapabilityLevel::Always)
            .with_task_witness(witness.clone());
        assert!(policy.check(&req_edit).is_allow());

        // GitCommit is in BugFix.allowed_operations but NOT in witness.allowed_ops
        let req_commit = PolicyRequest::new("git_commit", CapabilityLevel::Always)
            .with_task_witness(witness.clone());
        let result = policy.check(&req_commit);
        assert!(matches!(result, CheckResult::RequiresApproval(_)));
    }

    #[test]
    fn no_witness_does_not_gate() {
        let policy = TaskScopePolicy::new(TaskKind::BugFix);
        // No witness attached — git_commit is in BugFix.allowed_operations
        let req = PolicyRequest::new("git_commit", CapabilityLevel::Always);
        assert!(policy.check(&req).is_allow());
    }
}
