//! Operation & sink-class vocabulary of the IFC kernel — the verbs the reference
//! monitor gates and the sink classes it gates them into.
//!
//! Extracted from `lib.rs` (MVK carve M1b, RFC `minimum-viable-ifc-kernel.md`) so
//! the kernel's `Operation`/`SinkClass`/`is_exfil_operation` no longer live in the
//! unfenced crate root. Re-exported at the crate root (`pub use ifc_ops::*`), so
//! `portcullis_core::{Operation, SinkClass, ...}` is unchanged for all consumers,
//! and brought under the kernel-boundary ratchet.

use crate::{AuthorityLevel, IntegLevel};

/// Operations that can be gated by approval.
///
/// These are the 12 core operations that form the dimensions of the
/// capability lattice. Each maps 1:1 to a capability-lattice field.
///
/// `ExtensionOperation` (heap-allocated String) lives in the `portcullis`
/// crate — it cannot be translated by Aeneas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum Operation {
    /// Read files from disk
    ReadFiles = 0,
    /// Write files to disk
    WriteFiles = 1,
    /// Edit files in place
    EditFiles = 2,
    /// Run shell commands
    RunBash = 3,
    /// Glob search
    GlobSearch = 4,
    /// Grep search
    GrepSearch = 5,
    /// Web search
    WebSearch = 6,
    /// Fetch URLs
    WebFetch = 7,
    /// Git commit
    GitCommit = 8,
    /// Git push
    GitPush = 9,
    /// Create PR
    CreatePr = 10,
    /// Manage sub-pods (create, list, monitor, cancel)
    ManagePods = 11,
    /// Spawn a subprocess/agent with its own session.
    /// Classified as ExfilVector because child processes can bypass
    /// the parent session's flow restrictions.
    SpawnAgent = 12,
}

// Compile-time invariant: discriminants match declaration order for Aeneas.
const _: () = {
    assert!(Operation::ReadFiles as u8 == 0);
    assert!(Operation::WriteFiles as u8 == 1);
    assert!(Operation::EditFiles as u8 == 2);
    assert!(Operation::RunBash as u8 == 3);
    assert!(Operation::GlobSearch as u8 == 4);
    assert!(Operation::GrepSearch as u8 == 5);
    assert!(Operation::WebSearch as u8 == 6);
    assert!(Operation::WebFetch as u8 == 7);
    assert!(Operation::GitCommit as u8 == 8);
    assert!(Operation::GitPush as u8 == 9);
    assert!(Operation::CreatePr as u8 == 10);
    assert!(Operation::ManagePods as u8 == 11);
    assert!(Operation::SpawnAgent as u8 == 12);
};

// ═══════════════════════════════════════════════════════════════════════════
// Sealed LatticeOperation trait (#1051)
// ═══════════════════════════════════════════════════════════════════════════

mod private {
    pub trait Sealed {}
}

/// Trait for operations that participate in the verified permission lattice.
///
/// **SEALED**: Cannot be implemented outside this crate. The 13 core
/// operations have Verus verification conditions. Extensions must use
/// string-based `ExtensionOperation` which goes through a separate,
/// runtime-checked code path.
pub trait LatticeOperation: private::Sealed {
    /// Whether this operation can exfiltrate data to external systems.
    fn is_exfiltration_vector(&self) -> bool;

    /// Whether this operation modifies persistent state.
    fn is_mutation(&self) -> bool;
}

impl private::Sealed for Operation {}

impl LatticeOperation for Operation {
    fn is_exfiltration_vector(&self) -> bool {
        matches!(
            self,
            Operation::WebFetch | Operation::GitPush | Operation::CreatePr | Operation::SpawnAgent
        )
    }

    fn is_mutation(&self) -> bool {
        matches!(
            self,
            Operation::WriteFiles
                | Operation::EditFiles
                | Operation::RunBash
                | Operation::GitCommit
                | Operation::GitPush
                | Operation::CreatePr
                | Operation::ManagePods
        )
    }
}

impl Operation {
    /// All 13 core operations.
    pub const ALL: [Operation; 13] = [
        Operation::ReadFiles,
        Operation::WriteFiles,
        Operation::EditFiles,
        Operation::RunBash,
        Operation::GlobSearch,
        Operation::GrepSearch,
        Operation::WebSearch,
        Operation::WebFetch,
        Operation::GitCommit,
        Operation::GitPush,
        Operation::CreatePr,
        Operation::ManagePods,
        Operation::SpawnAgent,
    ];
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Operation::ReadFiles => "read_files",
            Operation::WriteFiles => "write_files",
            Operation::EditFiles => "edit_files",
            Operation::RunBash => "run_bash",
            Operation::GlobSearch => "glob_search",
            Operation::GrepSearch => "grep_search",
            Operation::WebSearch => "web_search",
            Operation::WebFetch => "web_fetch",
            Operation::GitCommit => "git_commit",
            Operation::GitPush => "git_push",
            Operation::CreatePr => "create_pr",
            Operation::ManagePods => "manage_pods",
            Operation::SpawnAgent => "spawn_agent",
        };
        write!(f, "{s}")
    }
}

impl TryFrom<&str> for Operation {
    type Error = OperationParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "read_files" => Ok(Operation::ReadFiles),
            "write_files" => Ok(Operation::WriteFiles),
            "edit_files" => Ok(Operation::EditFiles),
            "run_bash" => Ok(Operation::RunBash),
            "glob_search" => Ok(Operation::GlobSearch),
            "grep_search" => Ok(Operation::GrepSearch),
            "web_search" => Ok(Operation::WebSearch),
            "web_fetch" => Ok(Operation::WebFetch),
            "git_commit" => Ok(Operation::GitCommit),
            "git_push" => Ok(Operation::GitPush),
            "create_pr" => Ok(Operation::CreatePr),
            "manage_pods" => Ok(Operation::ManagePods),
            "spawn_agent" => Ok(Operation::SpawnAgent),
            _ => Err(OperationParseError),
        }
    }
}

/// Error returned when parsing an unknown operation name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationParseError;

impl std::fmt::Display for OperationParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown operation")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sink classes — the security-relevant destination taxonomy
//
// A SinkClass represents WHAT kind of side effect occurs, independent of
// WHICH tool produces it. The Operation enum tracks tool identity; the
// SinkClass tracks the security-relevant destination. This separation
// enables context-dependent classification: RunBash with `curl` → HTTPEgress,
// RunBash without network access → BashExec.
//
// The 13 sink classes cover every externally-observable side effect an agent
// can produce. Each has distinct confidentiality/integrity/authority
// requirements encoded as methods on the enum.
// ═══════════════════════════════════════════════════════════════════════════

/// Security-relevant destination class for agent side effects.
///
/// While [`Operation`] identifies the tool being used, `SinkClass` identifies
/// the type of externally-observable effect. Multiple operations can map to
/// the same sink class (e.g., both `RunBash` with `curl` and `WebFetch` map
/// to `HTTPEgress`), and a single operation can map to different sink classes
/// depending on context (e.g., `RunBash` with `git push` → `GitPush`,
/// `RunBash` with `ls` → `BashExec`).
///
/// Every agent action that passes through the kernel is classified into
/// exactly one sink class. The flow policy enforcement rules use sink
/// classes (not operations) for authority and integrity requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum SinkClass {
    /// Write to the workspace (project files, edits).
    WorkspaceWrite = 0,
    /// Write to system files outside the workspace.
    SystemWrite = 1,
    /// Execute a shell command (no detected network access).
    BashExec = 2,
    /// Outbound HTTP/HTTPS request (data exfiltration vector).
    #[cfg_attr(feature = "serde", serde(rename = "http_egress"))]
    HTTPEgress = 3,
    /// Create a git commit (local mutation).
    GitCommit = 4,
    /// Push to a remote git repository (publish vector).
    GitPush = 5,
    /// Write a PR comment, review, or create a PR (publish vector).
    #[cfg_attr(feature = "serde", serde(rename = "pr_comment_write"))]
    PRCommentWrite = 6,
    /// Send an email (publish vector).
    EmailSend = 7,
    /// Persist data to agent memory (cross-session taint vector).
    MemoryPersist = 8,
    /// Spawn a child agent or subprocess (delegation vector).
    AgentSpawn = 9,
    /// Write via an MCP tool (external system mutation).
    #[cfg_attr(feature = "serde", serde(rename = "mcp_write"))]
    MCPWrite = 10,
    /// Read a secret (API key, credential, env var).
    SecretRead = 11,
    /// Mutate cloud infrastructure (deploy, scale, delete).
    CloudMutation = 12,
    /// Write to the proposed (unverified) storage lane.
    ProposedTableWrite = 13,
    /// Write to the verified storage lane (requires witness / human promotion).
    VerifiedTableWrite = 14,
    /// Mutation of a search index.
    SearchIndexWrite = 15,
    /// Write to a cache layer.
    CacheWrite = 16,
    /// Create or update a ticket / issue.
    TicketWrite = 17,
    /// Append to an audit log (always allowed for integrity data).
    AuditLogAppend = 18,
}

// Compile-time invariant: discriminants match declaration order for Aeneas.
const _: () = {
    assert!(SinkClass::WorkspaceWrite as u8 == 0);
    assert!(SinkClass::SystemWrite as u8 == 1);
    assert!(SinkClass::BashExec as u8 == 2);
    assert!(SinkClass::HTTPEgress as u8 == 3);
    assert!(SinkClass::GitCommit as u8 == 4);
    assert!(SinkClass::GitPush as u8 == 5);
    assert!(SinkClass::PRCommentWrite as u8 == 6);
    assert!(SinkClass::EmailSend as u8 == 7);
    assert!(SinkClass::MemoryPersist as u8 == 8);
    assert!(SinkClass::AgentSpawn as u8 == 9);
    assert!(SinkClass::MCPWrite as u8 == 10);
    assert!(SinkClass::SecretRead as u8 == 11);
    assert!(SinkClass::CloudMutation as u8 == 12);
    assert!(SinkClass::ProposedTableWrite as u8 == 13);
    assert!(SinkClass::VerifiedTableWrite as u8 == 14);
    assert!(SinkClass::SearchIndexWrite as u8 == 15);
    assert!(SinkClass::CacheWrite as u8 == 16);
    assert!(SinkClass::TicketWrite as u8 == 17);
    assert!(SinkClass::AuditLogAppend as u8 == 18);
};

impl SinkClass {
    /// All 19 sink classes.
    pub const ALL: [SinkClass; 19] = [
        SinkClass::WorkspaceWrite,
        SinkClass::SystemWrite,
        SinkClass::BashExec,
        SinkClass::HTTPEgress,
        SinkClass::GitCommit,
        SinkClass::GitPush,
        SinkClass::PRCommentWrite,
        SinkClass::EmailSend,
        SinkClass::MemoryPersist,
        SinkClass::AgentSpawn,
        SinkClass::MCPWrite,
        SinkClass::SecretRead,
        SinkClass::CloudMutation,
        SinkClass::ProposedTableWrite,
        SinkClass::VerifiedTableWrite,
        SinkClass::SearchIndexWrite,
        SinkClass::CacheWrite,
        SinkClass::TicketWrite,
        SinkClass::AuditLogAppend,
    ];

    /// Minimum authority required for this sink class.
    ///
    /// Sinks that can exfiltrate or mutate require at least Suggestive
    /// authority. Read-only sinks require no authority.
    pub fn required_authority(self) -> AuthorityLevel {
        match self {
            // Read-only / append-only — no authority needed
            SinkClass::SecretRead | SinkClass::AuditLogAppend => AuthorityLevel::NoAuthority,
            // Write/exec/publish — require Suggestive
            SinkClass::WorkspaceWrite
            | SinkClass::SystemWrite
            | SinkClass::BashExec
            | SinkClass::HTTPEgress
            | SinkClass::GitCommit
            | SinkClass::GitPush
            | SinkClass::PRCommentWrite
            | SinkClass::EmailSend
            | SinkClass::MemoryPersist
            | SinkClass::AgentSpawn
            | SinkClass::MCPWrite
            | SinkClass::CloudMutation
            | SinkClass::ProposedTableWrite
            | SinkClass::VerifiedTableWrite
            | SinkClass::SearchIndexWrite
            | SinkClass::CacheWrite
            | SinkClass::TicketWrite => AuthorityLevel::Suggestive,
        }
    }

    /// Minimum integrity required for this sink class.
    ///
    /// Publish vectors (git push, PR, email) require trusted integrity —
    /// adversarial data must not reach external audiences. Local mutations
    /// require at least untrusted. Read sinks have no requirement.
    pub fn required_integrity(self) -> IntegLevel {
        match self {
            // Publish vectors — require Trusted
            SinkClass::GitPush
            | SinkClass::PRCommentWrite
            | SinkClass::EmailSend
            | SinkClass::TicketWrite => IntegLevel::Trusted,
            // Verified-lane writes — require Trusted (witness gate)
            SinkClass::VerifiedTableWrite => IntegLevel::Trusted,
            // Local mutations — require at least Untrusted
            SinkClass::WorkspaceWrite
            | SinkClass::SystemWrite
            | SinkClass::BashExec
            | SinkClass::GitCommit
            | SinkClass::CloudMutation
            | SinkClass::MCPWrite
            | SinkClass::ProposedTableWrite
            | SinkClass::SearchIndexWrite
            | SinkClass::CacheWrite => IntegLevel::Untrusted,
            // Delegation — require Untrusted (child inherits taint)
            SinkClass::AgentSpawn => IntegLevel::Untrusted,
            // HTTP egress — require Untrusted (URL can encode data)
            SinkClass::HTTPEgress => IntegLevel::Untrusted,
            // Memory persist — require Untrusted (cross-session taint)
            SinkClass::MemoryPersist => IntegLevel::Untrusted,
            // Read-only / append-only — no integrity requirement
            SinkClass::SecretRead | SinkClass::AuditLogAppend => IntegLevel::Adversarial,
        }
    }

    /// Whether this sink class is an exfiltration vector.
    ///
    /// Exfiltration vectors can transmit data outside the agent's trust
    /// boundary: to remote servers, external audiences, or child processes.
    pub fn is_exfil_vector(self) -> bool {
        matches!(
            self,
            SinkClass::HTTPEgress
                | SinkClass::GitPush
                | SinkClass::PRCommentWrite
                | SinkClass::EmailSend
                | SinkClass::AgentSpawn
                | SinkClass::CloudMutation
                | SinkClass::TicketWrite
        )
    }

    /// Whether this sink class requires verified-lane derivation.
    ///
    /// Verified sinks are publish vectors where AI-derived data must not
    /// land without explicit human promotion. Only `Deterministic` and
    /// `HumanPromoted` derivations pass the [`StorageLane::Verified`] gate.
    ///
    /// This covers sinks that produce externally-visible, hard-to-revoke
    /// artifacts: git pushes, git commits, and PR comments.
    pub fn requires_verified_derivation(self) -> bool {
        matches!(
            self,
            SinkClass::GitPush
                | SinkClass::GitCommit
                | SinkClass::PRCommentWrite
                | SinkClass::VerifiedTableWrite
        )
    }
}

impl std::fmt::Display for SinkClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SinkClass::WorkspaceWrite => "workspace_write",
            SinkClass::SystemWrite => "system_write",
            SinkClass::BashExec => "bash_exec",
            SinkClass::HTTPEgress => "http_egress",
            SinkClass::GitCommit => "git_commit",
            SinkClass::GitPush => "git_push",
            SinkClass::PRCommentWrite => "pr_comment_write",
            SinkClass::EmailSend => "email_send",
            SinkClass::MemoryPersist => "memory_persist",
            SinkClass::AgentSpawn => "agent_spawn",
            SinkClass::MCPWrite => "mcp_write",
            SinkClass::SecretRead => "secret_read",
            SinkClass::CloudMutation => "cloud_mutation",
            SinkClass::ProposedTableWrite => "proposed_table_write",
            SinkClass::VerifiedTableWrite => "verified_table_write",
            SinkClass::SearchIndexWrite => "search_index_write",
            SinkClass::CacheWrite => "cache_write",
            SinkClass::TicketWrite => "ticket_write",
            SinkClass::AuditLogAppend => "audit_log_append",
        };
        write!(f, "{s}")
    }
}

/// Default sink classification from an Operation (without context).
///
/// This is the conservative (fail-closed) mapping. Context-dependent
/// classification (e.g., `RunBash` + command string → `HTTPEgress`)
/// is provided by `classify_sink()` in the `portcullis` crate's
/// `hook_adapter` module.
pub fn default_sink_class(op: Operation) -> SinkClass {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            SinkClass::SecretRead
        }
        Operation::WriteFiles | Operation::EditFiles => SinkClass::WorkspaceWrite,
        // RunBash is conservatively classified as BashExec.
        // Context-dependent reclassification to HTTPEgress happens
        // in the hook adapter when URL patterns are detected.
        Operation::RunBash => SinkClass::BashExec,
        Operation::WebSearch => SinkClass::HTTPEgress,
        Operation::WebFetch => SinkClass::HTTPEgress,
        Operation::GitCommit => SinkClass::GitCommit,
        Operation::GitPush => SinkClass::GitPush,
        Operation::CreatePr => SinkClass::PRCommentWrite,
        Operation::ManagePods => SinkClass::CloudMutation,
        Operation::SpawnAgent => SinkClass::AgentSpawn,
    }
}

/// Whether an operation is an exfiltration vector (can move data to an external
/// sink). A DIRECT match on `Operation` — deliberately NOT routed through the
/// legacy `classify_operation`/`ExposureLabel` machinery, so the kernel does not
/// depend on the exposure code in `lib.rs`. Parity with the classifier-based
/// definition is pinned exhaustively by `is_exfil_operation_matches_classifier`
/// (lib.rs tests).
pub fn is_exfil_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::RunBash
            | Operation::GitPush
            | Operation::CreatePr
            | Operation::SpawnAgent
            | Operation::WriteFiles
            | Operation::EditFiles
            | Operation::GitCommit
            | Operation::ManagePods
    )
}
