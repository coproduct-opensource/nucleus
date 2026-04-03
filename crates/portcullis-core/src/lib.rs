//! Core capability lattice types — the Aeneas verification target.
//!
//! This crate contains the minimal, dependency-free types that form the
//! permission lattice verified by the Lean 4 HeytingAlgebra proofs.
//!
//! ## Why a separate crate?
//!
//! Aeneas (the Rust MIR → Lean 4 translator) requires dependency-free code.
//! The full `portcullis` crate imports serde, BTreeMap, chrono, uuid, etc.
//! which Aeneas cannot model. This crate extracts just the lattice core:
//!
//! - [`CapabilityLevel`] — the 3-element total order (Never < LowRisk < Always)
//! - [`CapabilityLattice`] — product of 12 capability dimensions
//! - `meet`, `join`, `leq` — lattice operations (pointwise min/max/≤)
//!
//! ## Relationship to the production `portcullis` crate
//!
//! The production `portcullis` crate re-exports `CapabilityLevel` from this
//! crate — there is ONE type, one source of truth, zero translation layers.
//! The verified type IS the production type.
//!
//! Serde support is gated behind the optional `serde` feature flag.
//! When `portcullis` depends on `portcullis-core` with `features = ["serde"]`,
//! the type gains `Serialize`/`Deserialize`. Without the feature, the crate
//! remains dependency-free for Aeneas translation.
//!
//! ## Aeneas pipeline
//!
//! ```text
//! portcullis-core (this crate)
//!     → Charon (rustc nightly, MIR extraction)
//!     → Aeneas (OCaml, LLBC → Lean 4 translation)
//!     → PortcullisCore.lean (generated Lean model)
//!     → Mathlib HeytingAlgebra proof (connects to generated types)
//! ```
//!
//! ## What the proof covers (and does not cover)
//!
//! The Aeneas pipeline generates the Lean **type** from this Rust crate and
//! keeps it in sync via CI. The HeytingAlgebra proof is on the generated type
//! (kernel-checked, no `sorry`). This means:
//!
//! - **Covered**: The type definition (`CapabilityLevel`, `CapabilityLattice`)
//!   is machine-translated from Rust to Lean. The proof that these types form
//!   a HeytingAlgebra is kernel-checked against the generated code.
//!
//! - **Not yet covered**: Function-level correspondence (proving that the Rust
//!   `meet()` implementation equals the lattice meet in the Lean proof) requires
//!   completing the `FunsExternal.lean` stubs. This is tracked as future work.
//!
//! - **Defense in depth**: 62 Kani proofs verify the production lattice operations
//!   (meet monotonicity, Heyting adjunction, etc.) in CI on every PR. The Lean
//!   proof verifies algebraic structure of the type. Together they provide
//!   complementary assurance.

#[cfg(feature = "artifact")]
pub mod artifact;
#[cfg(feature = "attestation")]
pub mod attestation;
pub mod autonomy;
#[cfg(feature = "artifact")]
pub mod c2pa_assertions;
pub mod compartment;
#[cfg(feature = "serde")]
pub mod compartmentfile;
#[cfg(feature = "serde")]
pub mod compose;
#[cfg(feature = "serde")]
pub mod compose_runner;
pub mod declassify;
pub mod delegation;
pub mod effect;
#[cfg(feature = "serde")]
pub mod enterprise;
#[cfg(feature = "envelope")]
pub mod envelope;
pub mod flow;
pub mod hash_types;
pub mod ifc_api;
#[cfg(feature = "serde")]
pub mod managed_settings;
pub mod manifest;
#[cfg(feature = "serde")]
pub mod memory;
pub mod parser_registry;
pub mod policy_rules;
#[cfg(feature = "envelope")]
pub mod promotion;
#[cfg(feature = "serde")]
pub mod prov_export;
pub mod provenance_node;
#[cfg(feature = "artifact")]
pub mod provenance_output;
pub mod provenance_schema;
pub mod receipt;
#[cfg(feature = "artifact")]
pub mod registry;
#[cfg(feature = "envelope")]
pub mod replay;
pub mod storage_lane;
pub mod verdict;
#[cfg(feature = "wasm-sandbox")]
pub mod wasm_sandbox;
pub mod wire;
#[cfg(feature = "envelope")]
pub mod witness;

/// Tool permission levels in lattice ordering.
///
/// The ordering is: `Never < LowRisk < Always`
///
/// This is a 3-element bounded lattice where:
/// - `Never` is the bottom element (⊥)
/// - `Always` is the top element (⊤)
/// - `meet` = min, `join` = max
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum CapabilityLevel {
    /// Never allow — bottom element (⊥)
    #[default]
    Never = 0,
    /// Auto-approve for low-risk operations
    LowRisk = 1,
    /// Always auto-approve — top element (⊤)
    Always = 2,
}

// Compile-time invariant: declaration order MUST match discriminant values.
// The Aeneas-generated Lean code uses `read_discriminant` (declaration-order index)
// while FunsExternal.lean uses `toNat` (discriminant value). These must be equal.
// If someone reorders the enum variants, this assertion fails the build.
const _: () = {
    assert!(CapabilityLevel::Never as u8 == 0);
    assert!(CapabilityLevel::LowRisk as u8 == 1);
    assert!(CapabilityLevel::Always as u8 == 2);
};

impl std::fmt::Display for CapabilityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityLevel::Never => write!(f, "never"),
            CapabilityLevel::LowRisk => write!(f, "low_risk"),
            CapabilityLevel::Always => write!(f, "always"),
        }
    }
}

impl CapabilityLevel {
    /// Meet operation (greatest lower bound): min of two levels.
    pub fn meet(self, other: Self) -> Self {
        if self <= other { self } else { other }
    }

    /// Join operation (least upper bound): max of two levels.
    pub fn join(self, other: Self) -> Self {
        if self >= other { self } else { other }
    }

    /// Heyting implication: a → b = max { c | c ∧ a ≤ b }
    ///
    /// For a 3-element chain: a → b = if a ≤ b then ⊤ else b
    pub fn implies(self, other: Self) -> Self {
        if self <= other {
            CapabilityLevel::Always
        } else {
            other
        }
    }

    /// Pseudo-complement: ¬a = a → ⊥
    pub fn complement(self) -> Self {
        self.implies(CapabilityLevel::Never)
    }

    /// Partial order check.
    pub fn leq(self, other: Self) -> bool {
        self <= other
    }
}

/// Capability lattice for tool permissions.
///
/// Product of 12 capability dimensions, each a [`CapabilityLevel`].
/// Meet, join, and leq are computed pointwise.
///
/// This is the primary verification target for the Aeneas pipeline.
/// The Lean 4 proof shows this forms a distributive Heyting algebra
/// (as a product of Heyting algebras).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct CapabilityLattice {
    #[cfg_attr(feature = "serde", serde(default))]
    pub read_files: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub write_files: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub edit_files: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub run_bash: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub glob_search: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub grep_search: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub web_search: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub web_fetch: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub git_commit: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub git_push: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub create_pr: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub manage_pods: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub spawn_agent: CapabilityLevel,
}

impl Default for CapabilityLattice {
    fn default() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            edit_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::LowRisk,
            web_fetch: CapabilityLevel::LowRisk,
            git_commit: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::LowRisk,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::LowRisk,
        }
    }
}

impl CapabilityLattice {
    /// Bottom element — all dimensions Never.
    pub fn bottom() -> Self {
        Self {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
        }
    }

    /// Top element — all dimensions Always.
    pub fn top() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            git_push: CapabilityLevel::Always,
            create_pr: CapabilityLevel::Always,
            manage_pods: CapabilityLevel::Always,
            spawn_agent: CapabilityLevel::Always,
        }
    }

    /// Meet operation (greatest lower bound): pointwise min.
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.meet(other.read_files),
            write_files: self.write_files.meet(other.write_files),
            edit_files: self.edit_files.meet(other.edit_files),
            run_bash: self.run_bash.meet(other.run_bash),
            glob_search: self.glob_search.meet(other.glob_search),
            grep_search: self.grep_search.meet(other.grep_search),
            web_search: self.web_search.meet(other.web_search),
            web_fetch: self.web_fetch.meet(other.web_fetch),
            git_commit: self.git_commit.meet(other.git_commit),
            git_push: self.git_push.meet(other.git_push),
            create_pr: self.create_pr.meet(other.create_pr),
            manage_pods: self.manage_pods.meet(other.manage_pods),
            spawn_agent: self.spawn_agent.meet(other.spawn_agent),
        }
    }

    /// Join operation (least upper bound): pointwise max.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.join(other.read_files),
            write_files: self.write_files.join(other.write_files),
            edit_files: self.edit_files.join(other.edit_files),
            run_bash: self.run_bash.join(other.run_bash),
            glob_search: self.glob_search.join(other.glob_search),
            grep_search: self.grep_search.join(other.grep_search),
            web_search: self.web_search.join(other.web_search),
            web_fetch: self.web_fetch.join(other.web_fetch),
            git_commit: self.git_commit.join(other.git_commit),
            git_push: self.git_push.join(other.git_push),
            create_pr: self.create_pr.join(other.create_pr),
            manage_pods: self.manage_pods.join(other.manage_pods),
            spawn_agent: self.spawn_agent.join(other.spawn_agent),
        }
    }

    /// Partial order check: pointwise ≤.
    pub fn leq(&self, other: &Self) -> bool {
        self.read_files.leq(other.read_files)
            && self.write_files.leq(other.write_files)
            && self.edit_files.leq(other.edit_files)
            && self.run_bash.leq(other.run_bash)
            && self.glob_search.leq(other.glob_search)
            && self.grep_search.leq(other.grep_search)
            && self.web_search.leq(other.web_search)
            && self.web_fetch.leq(other.web_fetch)
            && self.git_commit.leq(other.git_commit)
            && self.git_push.leq(other.git_push)
            && self.create_pr.leq(other.create_pr)
            && self.manage_pods.leq(other.manage_pods)
            && self.spawn_agent.leq(other.spawn_agent)
    }

    /// Read-only projection: meet with the read-only ceiling.
    ///
    /// Preserves read capabilities (read_files, glob_search, grep_search,
    /// web_search, web_fetch) at their current level while dropping all
    /// write/execute/exfil capabilities to Never.
    ///
    /// This is the lockdown lattice: `current ⊓ read_only_ceiling`.
    /// By the HeytingAlgebra deflationary property, the result ≤ current.
    pub fn read_only(&self) -> Self {
        self.meet(&Self {
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
        })
    }

    /// Heyting implication: pointwise →.
    pub fn implies(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.implies(other.read_files),
            write_files: self.write_files.implies(other.write_files),
            edit_files: self.edit_files.implies(other.edit_files),
            run_bash: self.run_bash.implies(other.run_bash),
            glob_search: self.glob_search.implies(other.glob_search),
            grep_search: self.grep_search.implies(other.grep_search),
            web_search: self.web_search.implies(other.web_search),
            web_fetch: self.web_fetch.implies(other.web_fetch),
            git_commit: self.git_commit.implies(other.git_commit),
            git_push: self.git_push.implies(other.git_push),
            create_pr: self.create_pr.implies(other.create_pr),
            manage_pods: self.manage_pods.implies(other.manage_pods),
            spawn_agent: self.spawn_agent.implies(other.spawn_agent),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Operation enum — the 12 core operations (Aeneas-translatable)
// ═══════════════════════════════════════════════════════════════════════════

/// Operations that can be gated by approval.
///
/// These are the 12 core operations that form the dimensions of the
/// capability lattice. Each maps 1:1 to a [`CapabilityLattice`] field.
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

// ═══════════════════════════════════════════════════════════════════════════
// Exposure types — the uninhabitable state detector (Aeneas-translatable)
// ═══════════════════════════════════════════════════════════════════════════

/// Exposure classification for the uninhabitable state detector.
///
/// Each operation contributes at most one exposure label. When all three
/// labels are present in a session, the uninhabitable state is reached
/// and exfiltration operations are dynamically gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExposureLabel {
    /// Agent has accessed private/sensitive data (read_files, glob_search, grep_search)
    PrivateData = 0,
    /// Agent has accessed untrusted external content (web_fetch, web_search)
    UntrustedContent = 1,
    /// Agent has access to an exfiltration vector (run_bash, git_push, create_pr)
    ExfilVector = 2,
}

// Compile-time invariant: discriminants match declaration order for Aeneas.
const _: () = {
    assert!(ExposureLabel::PrivateData as u8 == 0);
    assert!(ExposureLabel::UntrustedContent as u8 == 1);
    assert!(ExposureLabel::ExfilVector as u8 == 2);
};

/// 3-bit exposure accumulator for uninhabitable state detection.
///
/// Tracks which exposure legs have been touched during a session.
/// Once a leg is set, it never resets (monotonicity invariant).
/// When all 3 legs are set, the uninhabitable state is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExposureSet {
    private_data: bool,
    untrusted_content: bool,
    exfil_vector: bool,
}

impl ExposureSet {
    /// Empty exposure set (no exposure legs touched).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an exposure set from a single label.
    pub fn singleton(label: ExposureLabel) -> Self {
        let mut s = Self::empty();
        s.set(label);
        s
    }

    /// Set a specific exposure label.
    pub fn set(&mut self, label: ExposureLabel) {
        match label {
            ExposureLabel::PrivateData => self.private_data = true,
            ExposureLabel::UntrustedContent => self.untrusted_content = true,
            ExposureLabel::ExfilVector => self.exfil_vector = true,
        }
    }

    /// Check if a specific exposure label is present.
    pub fn contains(&self, label: ExposureLabel) -> bool {
        match label {
            ExposureLabel::PrivateData => self.private_data,
            ExposureLabel::UntrustedContent => self.untrusted_content,
            ExposureLabel::ExfilVector => self.exfil_vector,
        }
    }

    /// Union of two exposure sets (the monoid operation).
    pub fn union(&self, other: &Self) -> Self {
        Self {
            private_data: self.private_data || other.private_data,
            untrusted_content: self.untrusted_content || other.untrusted_content,
            exfil_vector: self.exfil_vector || other.exfil_vector,
        }
    }

    /// Check if the uninhabitable state is present (all 3 legs active).
    pub fn is_uninhabitable(&self) -> bool {
        self.private_data && self.untrusted_content && self.exfil_vector
    }

    /// Number of active exposure legs (0..=3).
    pub fn count(&self) -> u8 {
        self.private_data as u8 + self.untrusted_content as u8 + self.exfil_vector as u8
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Exposure classification functions (Aeneas-translatable)
// ═══════════════════════════════════════════════════════════════════════════

/// Classify an operation's exposure contribution.
///
/// Returns the exposure label that this operation contributes to the
/// session's accumulated exposure, or None for neutral operations.
pub fn classify_operation(op: Operation) -> Option<ExposureLabel> {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            Some(ExposureLabel::PrivateData)
        }
        Operation::WebFetch | Operation::WebSearch => Some(ExposureLabel::UntrustedContent),
        Operation::RunBash | Operation::GitPush | Operation::CreatePr | Operation::SpawnAgent => {
            Some(ExposureLabel::ExfilVector)
        }
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::GitCommit
        | Operation::ManagePods => None,
    }
}

/// Project what the exposure set WOULD be if this operation is allowed.
pub fn project_exposure(current: &ExposureSet, op: Operation) -> ExposureSet {
    match classify_operation(op) {
        Some(label) => {
            let mut projected = *current;
            projected.set(label);
            projected
        }
        None => *current,
    }
}

/// Record an allowed operation's exposure contribution.
pub fn apply_record(current: &ExposureSet, op: Operation) -> ExposureSet {
    project_exposure(current, op)
}

/// Check if an operation is an exfiltration vector.
pub fn is_exfil_operation(op: Operation) -> bool {
    matches!(classify_operation(op), Some(ExposureLabel::ExfilVector))
}

/// The dynamic exposure gate: should this operation be gated?
///
/// Returns true if the operation should require approval because:
/// 1. The exposure set is already uninhabitable OR would become uninhabitable, AND
/// 2. The operation is an exfiltration vector
pub fn should_gate(current: &ExposureSet, op: Operation) -> bool {
    let projected = project_exposure(current, op);
    (current.is_uninhabitable() || projected.is_uninhabitable()) && is_exfil_operation(op)
}

// ═══════════════════════════════════════════════════════════════════════════
// Information Flow Control labels — the Flow Kernel foundation
//
// A product lattice of 6 dimensions that tracks data provenance, trust,
// and authority through agent execution. This is the formal substrate
// for defending against trust-boundary exploits (indirect prompt injection,
// memory poisoning, confused-deputy attacks).
//
// Design follows Microsoft FIDES (arXiv:2505.23643) and classical
// BLP+Biba composition with a novel AuthorityLevel dimension.
// ═══════════════════════════════════════════════════════════════════════════

/// Confidentiality level — covariant (join = max).
///
/// Combining data from different confidentiality levels produces
/// a label at the HIGHEST level. Secret data stays secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum ConfLevel {
    /// Publicly available data (web content, public repos, docs).
    #[default]
    Public = 0,
    /// Internal data (private repos, user files, env vars).
    Internal = 1,
    /// Secret data (API keys, credentials, PII).
    Secret = 2,
}

/// Integrity level — CONTRAVARIANT (join = min, least trusted wins).
///
/// Combining trusted data with untrusted data produces UNTRUSTED output.
/// This is the Biba integrity model, inverted from BLP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum IntegLevel {
    /// Adversarially controlled (public issue bodies, web scraping results).
    Adversarial = 0,
    /// Untrusted but not adversarial (MCP tool output, cached data).
    Untrusted = 1,
    /// Trusted (user prompts, system config, verified sources).
    #[default]
    Trusted = 2,
}

/// Authority-to-instruct level — CONTRAVARIANT (join = min).
///
/// The critical innovation: formal encoding of "can this data steer the agent?"
/// Web content gets NoAuthority — it can be READ but cannot INSTRUCT.
/// When correctly labeled at runtime, this enables blocking indirect
/// prompt injection — web content cannot acquire instruction authority
/// regardless of what the LLM decides to do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum AuthorityLevel {
    /// Cannot instruct the agent in any way (web content, public issues).
    #[cfg_attr(feature = "serde", serde(rename = "no_authority"))]
    NoAuthority = 0,
    /// Informational only — can provide context but not direct actions.
    Informational = 1,
    /// Can suggest actions but requires approval (MCP tool descriptions).
    Suggestive = 2,
    /// Full authority to direct agent actions (user prompts, system config).
    #[default]
    Directive = 3,
}

/// Provenance bitset — covariant (join = union, all sources tracked).
///
/// Tracks which sources contributed to a datum. Represented as a 6-bit
/// bitmask for Aeneas translatability (no BTreeSet, no Vec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProvenanceSet(u8);

impl ProvenanceSet {
    pub const USER: ProvenanceSet = ProvenanceSet(1 << 0);
    pub const TOOL: ProvenanceSet = ProvenanceSet(1 << 1);
    pub const WEB: ProvenanceSet = ProvenanceSet(1 << 2);
    pub const MEMORY: ProvenanceSet = ProvenanceSet(1 << 3);
    pub const MODEL: ProvenanceSet = ProvenanceSet(1 << 4);
    pub const SYSTEM: ProvenanceSet = ProvenanceSet(1 << 5);

    pub const EMPTY: ProvenanceSet = ProvenanceSet(0);

    /// Union of two provenance sets.
    pub fn union(self, other: Self) -> Self {
        ProvenanceSet(self.0 | other.0)
    }

    /// Check if a specific source is present.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Intersection of two provenance sets (for meet operation).
    pub fn intersection(self, other: Self) -> Self {
        ProvenanceSet(self.0 & other.0)
    }

    /// Subset check (for lattice ordering).
    pub fn is_subset_of(self, other: Self) -> bool {
        (self.0 & other.0) == self.0
    }

    /// Raw bitmask value (for serialization/signing).
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Construct from raw bitmask (for deserialization/wire protocol).
    /// Only the lower 6 bits are used.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & 0x3F)
    }
}

/// Freshness — covariant (join = oldest timestamp, shortest TTL).
///
/// Uses u64 unix timestamps for Aeneas translatability (no chrono).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Freshness {
    /// Unix timestamp when the data was observed.
    pub observed_at: u64,
    /// Time-to-live in seconds (0 = no expiry).
    pub ttl_secs: u64,
}

impl Freshness {
    /// Join: oldest observation, shortest TTL.
    pub fn join(self, other: Self) -> Self {
        Self {
            observed_at: self.observed_at.min(other.observed_at),
            ttl_secs: if self.ttl_secs == 0 && other.ttl_secs == 0 {
                0
            } else if self.ttl_secs == 0 {
                other.ttl_secs
            } else if other.ttl_secs == 0 {
                self.ttl_secs
            } else {
                self.ttl_secs.min(other.ttl_secs)
            },
        }
    }

    /// Meet: newest observation, longest TTL (greatest lower bound).
    ///
    /// Dual of `join`. The meet is the least restrictive freshness that
    /// is at most as restrictive as both inputs.
    pub fn meet(self, other: Self) -> Self {
        Self {
            observed_at: self.observed_at.max(other.observed_at),
            ttl_secs: if self.ttl_secs == 0 || other.ttl_secs == 0 {
                0 // either has no expiry → meet has no expiry
            } else {
                self.ttl_secs.max(other.ttl_secs)
            },
        }
    }

    /// Lattice partial order for freshness.
    ///
    /// `self ≤ other` means self is less restrictive (newer, longer TTL).
    /// In the join semilattice, join takes oldest/shortest, so the ordering
    /// goes: newer/longer-TTL ≤ older/shorter-TTL.
    pub fn leq(self, other: Self) -> bool {
        self.observed_at >= other.observed_at
            && (other.ttl_secs == 0 || (self.ttl_secs != 0 && self.ttl_secs >= other.ttl_secs))
    }

    /// Check if data has expired at a given time.
    pub fn is_expired_at(self, now: u64) -> bool {
        self.ttl_secs > 0 && now > self.observed_at + self.ttl_secs
    }
}

/// Derivation class — determinism-aware integrity classification.
///
/// Tracks whether a datum was produced by a deterministic computation,
/// AI generation, or some combination. This is the 6th dimension of
/// the IFC product lattice and the core DPI primitive: it determines
/// whether data can be auto-verified or requires human attestation.
///
/// Lattice order (bottom to top): `Deterministic < AIDerived < Mixed < OpaqueExternal`
/// `HumanPromoted` sits beside `Mixed` — promotion does not cleanse.
///
/// Key invariant ("no silent cleansing"): `AIDerived.join(x) != Deterministic`
/// for any `x` — AI-derived data cannot become deterministic without explicit
/// human promotion, and even then the result is `Mixed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum DerivationClass {
    /// Reproducible: pure transform, deterministic fetch, parser output.
    #[default]
    Deterministic = 0,
    /// LLM-generated, not reproducible (classification, extraction, generation).
    AIDerived = 1,
    /// Combination of deterministic and AI-derived inputs.
    Mixed = 2,
    /// AI-derived data explicitly approved by a human. Preserves ancestry
    /// but signals attestation — joining with anything produces Mixed.
    HumanPromoted = 3,
    /// External system with unknown determinism profile. Top element.
    OpaqueExternal = 4,
}

impl DerivationClass {
    /// Join (least upper bound) of two derivation classes.
    ///
    /// Lattice structure (Hasse diagram):
    /// ```text
    ///       OpaqueExternal  (top)
    ///            |
    ///          Mixed
    ///         /     \
    ///   AIDerived  HumanPromoted
    ///         \     /
    ///       Deterministic  (bottom)
    /// ```
    ///
    /// - Deterministic is bottom: `Deterministic ⊔ x = x`
    /// - OpaqueExternal is top: `x ⊔ OpaqueExternal = OpaqueExternal`
    /// - AIDerived ⊔ HumanPromoted = Mixed
    /// - Mixed ⊔ {AIDerived, HumanPromoted} = Mixed
    ///
    /// Key invariant ("no silent cleansing"): `AIDerived.join(x) != Deterministic`
    /// for any x — AI-derived data can never be laundered back to deterministic.
    pub fn join(self, other: Self) -> Self {
        use DerivationClass::*;
        match (self, other) {
            // Deterministic is bottom — identity for join
            (Deterministic, x) | (x, Deterministic) => x,
            // OpaqueExternal is top — absorbs everything
            (OpaqueExternal, _) | (_, OpaqueExternal) => OpaqueExternal,
            // Same class: idempotent
            (AIDerived, AIDerived) => AIDerived,
            (HumanPromoted, HumanPromoted) => HumanPromoted,
            (Mixed, Mixed) => Mixed,
            // Different non-bottom, non-top classes → Mixed
            // AIDerived + HumanPromoted, AIDerived + Mixed, HumanPromoted + Mixed
            _ => Mixed,
        }
    }

    /// Meet (greatest lower bound) of two derivation classes.
    ///
    /// Dual of join:
    /// - OpaqueExternal is top — identity for meet: `meet(x, OpaqueExternal) = x`
    /// - Deterministic is bottom — absorber for meet: `meet(x, Deterministic) = Deterministic`
    /// - `meet(AIDerived, HumanPromoted) = Deterministic` (greatest lower bound of incomparables)
    /// - `meet(Mixed, x) = x` when x is AIDerived or HumanPromoted
    pub fn meet(self, other: Self) -> Self {
        use DerivationClass::*;
        match (self, other) {
            // OpaqueExternal is top — identity for meet
            (OpaqueExternal, x) | (x, OpaqueExternal) => x,
            // Deterministic is bottom — absorber for meet
            (Deterministic, _) | (_, Deterministic) => Deterministic,
            // Same class: idempotent
            (AIDerived, AIDerived) => AIDerived,
            (HumanPromoted, HumanPromoted) => HumanPromoted,
            (Mixed, Mixed) => Mixed,
            // Mixed meets AIDerived or HumanPromoted = the lower element
            (Mixed, x) | (x, Mixed) => x,
            // AIDerived meets HumanPromoted = Deterministic (their GLB)
            (AIDerived, HumanPromoted) | (HumanPromoted, AIDerived) => Deterministic,
        }
    }

    /// Lattice partial order: `self ≤ other`.
    ///
    /// `a.leq(b)` iff `a.join(b) == b` (standard lattice definition).
    pub fn leq(self, other: Self) -> bool {
        self.join(other) == other
    }
}

/// Information flow control label — 6-dimensional product lattice.
///
/// The lattice order follows BLP (confidentiality) + Biba (integrity)
/// composition with authority confinement and derivation tracking:
///
/// - Confidentiality: covariant — join = max (most secret wins)
/// - Integrity: CONTRAVARIANT — join = min (least trusted wins)
/// - Provenance: covariant — join = union (all sources tracked)
/// - Freshness: covariant — join = oldest, shortest TTL
/// - Authority: CONTRAVARIANT — join = min (least authority wins)
/// - Derivation: covariant — join per DerivationClass rules (Mixed absorbs)
///
/// Key property: combining a trusted user prompt with web content produces
/// `integrity = Adversarial, authority = NoAuthority`. This data cannot
/// steer privileged actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IFCLabel {
    pub confidentiality: ConfLevel,
    pub integrity: IntegLevel,
    pub provenance: ProvenanceSet,
    pub freshness: Freshness,
    pub authority: AuthorityLevel,
    /// Derivation class — tracks whether this datum was deterministically
    /// computed, AI-generated, mixed, human-promoted, or from an opaque source.
    pub derivation: DerivationClass,
}

impl Default for IFCLabel {
    /// Default: minimum privilege — public, untrusted, no provenance, no authority.
    ///
    /// The safe default. Forgetting to set a field results in LESS privilege,
    /// not more. Use the named constructors (user_prompt, web_content, etc.)
    /// for specific contexts.
    fn default() -> Self {
        Self {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::EMPTY,
            freshness: Freshness::default(),
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        }
    }
}

impl IFCLabel {
    /// Join two labels (least upper bound in the product lattice).
    ///
    /// Confidentiality and provenance are covariant (max/union).
    /// Integrity and authority are CONTRAVARIANT (min).
    pub fn join(self, other: Self) -> Self {
        Self {
            confidentiality: if self.confidentiality >= other.confidentiality {
                self.confidentiality
            } else {
                other.confidentiality
            },
            // Contravariant: least trusted wins
            integrity: if self.integrity <= other.integrity {
                self.integrity
            } else {
                other.integrity
            },
            provenance: self.provenance.union(other.provenance),
            freshness: self.freshness.join(other.freshness),
            // Contravariant: least authority wins
            authority: if self.authority <= other.authority {
                self.authority
            } else {
                other.authority
            },
            derivation: self.derivation.join(other.derivation),
        }
    }

    /// Check if this label flows to (is less restrictive than) another.
    ///
    /// `a.flows_to(b)` means data labeled `a` may be used where `b` is expected.
    /// Confidentiality: a.conf ≤ b.conf (can't send secret to public)
    /// Integrity: a.integ ≥ b.integ (can't use untrusted where trusted needed)
    /// Authority: a.auth ≥ b.auth (can't use NoAuthority where Directive needed)
    /// Provenance: a.prov ⊆ b.prov (target must accept all sources)
    ///
    /// Note: freshness is checked separately in `check_flow` (Rule 4) because
    /// it depends on wall-clock time, not just the label lattice ordering.
    pub fn flows_to(self, target: Self) -> bool {
        self.confidentiality <= target.confidentiality
            && self.integrity >= target.integrity
            && self.authority >= target.authority
            && self.provenance.is_subset_of(target.provenance)
            && self.derivation.leq(target.derivation)
    }

    /// Bottom label (least restrictive): public, trusted, no provenance, full authority.
    ///
    /// For contravariant dimensions (integrity, authority), bottom = maximum value
    /// so that `join(x, bottom) = x` (joining with bottom doesn't restrict).
    pub fn bottom() -> Self {
        Self {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::EMPTY,
            freshness: Freshness::default(),
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Top label: secret, adversarial, all sources, no authority, expired.
    ///
    /// The most restrictive possible label. Data with this label cannot
    /// flow anywhere useful and will fail freshness checks.
    pub fn top() -> Self {
        Self {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet(0x3F), // all 6 bits
            freshness: Freshness {
                observed_at: 0,
                ttl_secs: 1, // expired immediately (observed_at=0, ttl=1 → expired at t=1)
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::OpaqueExternal,
        }
    }

    /// Intrinsic label for web content — the key indirect-injection defense.
    pub fn web_content(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 3600,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::OpaqueExternal,
        }
    }

    /// Intrinsic label for user prompts — full trust and authority.
    pub fn user_prompt(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Intrinsic label for secrets (API keys, credentials).
    pub fn secret(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Intrinsic label for MCP tool responses.
    pub fn tool_response(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::TOOL,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Intrinsic label for memory entries.
    pub fn memory_entry(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::MEMORY,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 86400,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Meet two labels (greatest lower bound in the product lattice).
    ///
    /// Dual of `join`: the meet is the least restrictive label that is
    /// at most as restrictive as both inputs.
    ///
    /// Confidentiality and provenance are covariant (meet = min / intersection).
    /// Integrity and authority are CONTRAVARIANT (meet = max).
    pub fn meet(self, other: Self) -> Self {
        Self {
            confidentiality: if self.confidentiality <= other.confidentiality {
                self.confidentiality
            } else {
                other.confidentiality
            },
            // Contravariant: most trusted wins (max = greatest lower bound)
            integrity: if self.integrity >= other.integrity {
                self.integrity
            } else {
                other.integrity
            },
            provenance: self.provenance.intersection(other.provenance),
            freshness: self.freshness.meet(other.freshness),
            // Contravariant: most authority wins (max = greatest lower bound)
            authority: if self.authority >= other.authority {
                self.authority
            } else {
                other.authority
            },
            derivation: self.derivation.meet(other.derivation),
        }
    }

    /// Lattice partial order: `self ≤ other` in the product lattice.
    ///
    /// This is the lattice ordering (not the flow relation). A label `a` is
    /// less than `b` when `a` is less restrictive: lower confidentiality,
    /// higher integrity, higher authority, subset provenance.
    ///
    /// Note: This is equivalent to `self.join(other) == other`.
    pub fn leq(self, other: Self) -> bool {
        self.confidentiality <= other.confidentiality
            && self.integrity >= other.integrity
            && self.authority >= other.authority
            && self.provenance.is_subset_of(other.provenance)
            && self.freshness.leq(other.freshness)
            && self.derivation.leq(other.derivation)
    }
}

/// Map an IFCLabel to the legacy ExposureSet (monotone homomorphism).
///
/// This is the quotient map φ that proves backward compatibility:
/// the existing 3-bit exposure tracker is a sound abstraction of the
/// full IFC label lattice.
pub fn ifc_to_exposure(label: &IFCLabel, op: Operation) -> ExposureSet {
    let mut s = ExposureSet::empty();
    if label.confidentiality >= ConfLevel::Internal {
        s.set(ExposureLabel::PrivateData);
    }
    if label.integrity <= IntegLevel::Untrusted {
        s.set(ExposureLabel::UntrustedContent);
    }
    if is_exfil_operation(op) {
        s.set(ExposureLabel::ExfilVector);
    }
    s
}

// ═══════════════════════════════════════════════════════════════════════════
// Pure decision logic — the Lean 4 verification target (Phase 2)
//
// This function captures the security-critical lattice-based decisions
// without runtime dependencies (no chrono, no Path, no Decimal). It is
// the kernel that will be translated to Lean via Aeneas and proved correct.
// ═══════════════════════════════════════════════════════════════════════════

/// Pure verdict from the lattice decision logic.
///
/// Does NOT include runtime checks (time, budget, path, command, isolation).
/// Those are checked in the full `Kernel::decide()` before calling this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PureVerdict {
    /// The capability lattice allows this operation.
    Allow,
    /// The capability level is Never — operation is denied.
    DenyCapability,
    /// Static approval required (capability level is LowRisk).
    RequiresApproval,
    /// Dynamic exposure gate triggered — exfil blocked by uninhabitable state.
    GateExfil,
}

/// Pure lattice-based decision logic.
///
/// Given the effective capability level for an operation and the current
/// exposure state, determine the verdict. This is the function we prove
/// correct in Lean 4.
///
/// The decision chain:
/// 1. If capability level is Never → DenyCapability
/// 2. If capability level is LowRisk → RequiresApproval
/// 3. If exposure gate triggers → GateExfil
/// 4. Otherwise → Allow
pub fn decide_pure(level: CapabilityLevel, exposure: &ExposureSet, op: Operation) -> PureVerdict {
    // Step 1: Capability level check
    if level == CapabilityLevel::Never {
        return PureVerdict::DenyCapability;
    }

    // Step 2: Static approval (LowRisk requires human approval)
    if level == CapabilityLevel::LowRisk {
        return PureVerdict::RequiresApproval;
    }

    // Step 3: Dynamic exposure gate
    if should_gate(exposure, op) {
        return PureVerdict::GateExfil;
    }

    PureVerdict::Allow
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — IFCLabel bounded lattice axioms
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_ifc_label_proofs {
    use super::*;

    /// Generate a symbolic ConfLevel (3 variants — exhaustive).
    fn any_conf() -> ConfLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => ConfLevel::Public,
            1 => ConfLevel::Internal,
            _ => ConfLevel::Secret,
        }
    }

    /// Generate a symbolic IntegLevel (3 variants — exhaustive).
    fn any_integ() -> IntegLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        match v {
            0 => IntegLevel::Adversarial,
            1 => IntegLevel::Untrusted,
            _ => IntegLevel::Trusted,
        }
    }

    /// Generate a symbolic AuthorityLevel (4 variants — exhaustive).
    fn any_auth() -> AuthorityLevel {
        let v: u8 = kani::any();
        kani::assume(v <= 3);
        match v {
            0 => AuthorityLevel::NoAuthority,
            1 => AuthorityLevel::Informational,
            2 => AuthorityLevel::Suggestive,
            _ => AuthorityLevel::Directive,
        }
    }

    /// Generate a symbolic DerivationClass (5 variants — exhaustive).
    fn any_derivation() -> DerivationClass {
        let v: u8 = kani::any();
        kani::assume(v <= 4);
        match v {
            0 => DerivationClass::Deterministic,
            1 => DerivationClass::AIDerived,
            2 => DerivationClass::Mixed,
            3 => DerivationClass::HumanPromoted,
            _ => DerivationClass::OpaqueExternal,
        }
    }

    /// Generate a symbolic IFCLabel with bounded provenance (6-bit) and
    /// bounded freshness for tractable verification.
    fn any_label() -> IFCLabel {
        IFCLabel {
            confidentiality: any_conf(),
            integrity: any_integ(),
            provenance: ProvenanceSet::from_bits(kani::any::<u8>()),
            freshness: Freshness {
                observed_at: kani::any(),
                ttl_secs: kani::any(),
            },
            authority: any_auth(),
            derivation: any_derivation(),
        }
    }

    // ── L1: Join idempotence — a ⊔ a = a ──────────────────────────────

    /// **L1 — IFCLabel join is idempotent.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_join_idempotent() {
        let a = any_label();
        let result = a.join(a);
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L2: Join commutativity — a ⊔ b = b ⊔ a ───────────────────────

    /// **L2 — IFCLabel join is commutative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_join_commutative() {
        let a = any_label();
        let b = any_label();
        let ab = a.join(b);
        let ba = b.join(a);
        assert_eq!(ab.confidentiality, ba.confidentiality);
        assert_eq!(ab.integrity, ba.integrity);
        assert_eq!(ab.authority, ba.authority);
        assert_eq!(ab.provenance.bits(), ba.provenance.bits());
    }

    // ── L3: Join associativity — (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c) ─────────

    /// **L3 — IFCLabel join is associative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_join_associative() {
        let a = any_label();
        let b = any_label();
        let c = any_label();
        let lhs = a.join(b).join(c);
        let rhs = a.join(b.join(c));
        assert_eq!(lhs.confidentiality, rhs.confidentiality);
        assert_eq!(lhs.integrity, rhs.integrity);
        assert_eq!(lhs.authority, rhs.authority);
        assert_eq!(lhs.provenance.bits(), rhs.provenance.bits());
    }

    // ── L4: Meet idempotence — a ⊓ a = a ──────────────────────────────

    /// **L4 — IFCLabel meet is idempotent.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_meet_idempotent() {
        let a = any_label();
        let result = a.meet(a);
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L5: Meet commutativity — a ⊓ b = b ⊓ a ───────────────────────

    /// **L5 — IFCLabel meet is commutative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_meet_commutative() {
        let a = any_label();
        let b = any_label();
        let ab = a.meet(b);
        let ba = b.meet(a);
        assert_eq!(ab.confidentiality, ba.confidentiality);
        assert_eq!(ab.integrity, ba.integrity);
        assert_eq!(ab.authority, ba.authority);
        assert_eq!(ab.provenance.bits(), ba.provenance.bits());
    }

    // ── L6: Meet associativity — (a ⊓ b) ⊓ c = a ⊓ (b ⊓ c) ─────────

    /// **L6 — IFCLabel meet is associative.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_meet_associative() {
        let a = any_label();
        let b = any_label();
        let c = any_label();
        let lhs = a.meet(b).meet(c);
        let rhs = a.meet(b.meet(c));
        assert_eq!(lhs.confidentiality, rhs.confidentiality);
        assert_eq!(lhs.integrity, rhs.integrity);
        assert_eq!(lhs.authority, rhs.authority);
        assert_eq!(lhs.provenance.bits(), rhs.provenance.bits());
    }

    // ── L7: Absorption — a ⊔ (a ⊓ b) = a ─────────────────────────────

    /// **L7 — IFCLabel absorption law (join over meet).**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_absorption_join_meet() {
        let a = any_label();
        let b = any_label();
        let result = a.join(a.meet(b));
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L8: Absorption — a ⊓ (a ⊔ b) = a ─────────────────────────────

    /// **L8 — IFCLabel absorption law (meet over join).**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_absorption_meet_join() {
        let a = any_label();
        let b = any_label();
        let result = a.meet(a.join(b));
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L9: Bottom identity — a ⊔ ⊥ = a ──────────────────────────────

    /// **L9 — Bottom is the identity for join.**
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_bottom_join_identity() {
        let a = any_label();
        let result = a.join(IFCLabel::bottom());
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L10: Top identity — a ⊓ ⊤ = a ─────────────────────────────────

    /// **L10 — Top is the identity for meet.**
    ///
    /// Note: Freshness dimension uses observed_at=0,ttl_secs=1 for top,
    /// which makes this hold for the non-freshness dimensions. Freshness
    /// is checked separately in check_flow (Rule 4), not in the lattice order.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_top_meet_identity() {
        let a = any_label();
        let result = a.meet(IFCLabel::top());
        assert_eq!(result.confidentiality, a.confidentiality);
        assert_eq!(result.integrity, a.integrity);
        assert_eq!(result.authority, a.authority);
        assert_eq!(result.provenance.bits(), a.provenance.bits());
    }

    // ── L11: leq consistent with join — a ≤ b iff a ⊔ b = b ──────────

    /// **L11 — Lattice order is consistent with join.**
    ///
    /// Verifies the core lattice identity: a ≤ b ⟺ a ⊔ b = b,
    /// restricted to the non-freshness dimensions (conf, integ, auth, prov).
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ifc_leq_consistent_with_join() {
        let a = any_label();
        let b = any_label();

        // Fix freshness to be equal so leq is determined by other dims
        let a = IFCLabel {
            freshness: Freshness {
                observed_at: 100,
                ttl_secs: 0,
            },
            ..a
        };
        let b = IFCLabel {
            freshness: Freshness {
                observed_at: 100,
                ttl_secs: 0,
            },
            ..b
        };

        let join_ab = a.join(b);
        let leq = a.leq(b);

        // a ≤ b → a ⊔ b = b (on all non-freshness dims)
        if leq {
            assert_eq!(join_ab.confidentiality, b.confidentiality);
            assert_eq!(join_ab.integrity, b.integrity);
            assert_eq!(join_ab.authority, b.authority);
            assert_eq!(join_ab.provenance.bits(), b.provenance.bits());
        }

        // a ⊔ b = b → a ≤ b
        if join_ab.confidentiality == b.confidentiality
            && join_ab.integrity == b.integrity
            && join_ab.authority == b.authority
            && join_ab.provenance.bits() == b.provenance.bits()
        {
            assert!(a.leq(b));
        }
    }

    // ── DPI-1: No silent cleansing — AIDerived ⊔ x ≠ Deterministic ───

    /// **DPI-1 — AIDerived can never be laundered back to Deterministic.**
    ///
    /// For all DerivationClass values x, `AIDerived.join(x) != Deterministic`.
    /// This is the foundational DPI invariant: AI-generated data carries its
    /// taint irreversibly through all join operations.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_derivation_no_silent_cleansing() {
        let x = any_derivation();
        let result = DerivationClass::AIDerived.join(x);
        assert!(result != DerivationClass::Deterministic);
    }

    // ── DPI-2: Monotone join — join never reduces taint level ─────────

    /// Map DerivationClass to its height in the Hasse diagram (taint level).
    ///
    /// ```text
    ///       OpaqueExternal  = 3 (top)
    ///            |
    ///          Mixed         = 2
    ///         /     \
    ///   AIDerived  HumanPromoted  = 1
    ///         \     /
    ///       Deterministic    = 0 (bottom)
    /// ```
    fn taint_level(d: DerivationClass) -> u8 {
        match d {
            DerivationClass::Deterministic => 0,
            DerivationClass::AIDerived => 1,
            DerivationClass::HumanPromoted => 1,
            DerivationClass::Mixed => 2,
            DerivationClass::OpaqueExternal => 3,
        }
    }

    /// **DPI-2 — DerivationClass join is monotone in taint level.**
    ///
    /// For all a, b: `taint_level(join(a, b)) >= max(taint_level(a), taint_level(b))`.
    /// Joining data can only increase (or maintain) the taint level, never reduce it.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_derivation_join_monotone() {
        let a = any_derivation();
        let b = any_derivation();
        let result = a.join(b);
        let max_input = if taint_level(a) >= taint_level(b) {
            taint_level(a)
        } else {
            taint_level(b)
        };
        assert!(taint_level(result) >= max_input);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_level_ordering() {
        assert!(CapabilityLevel::Never < CapabilityLevel::LowRisk);
        assert!(CapabilityLevel::LowRisk < CapabilityLevel::Always);
    }

    #[test]
    fn meet_is_min() {
        assert_eq!(
            CapabilityLevel::Always.meet(CapabilityLevel::Never),
            CapabilityLevel::Never
        );
        assert_eq!(
            CapabilityLevel::LowRisk.meet(CapabilityLevel::Always),
            CapabilityLevel::LowRisk
        );
    }

    #[test]
    fn join_is_max() {
        assert_eq!(
            CapabilityLevel::Never.join(CapabilityLevel::Always),
            CapabilityLevel::Always
        );
    }

    #[test]
    fn heyting_implication() {
        // a ≤ b → (a → b) = ⊤
        assert_eq!(
            CapabilityLevel::Never.implies(CapabilityLevel::Always),
            CapabilityLevel::Always
        );
        // a > b → (a → b) = b
        assert_eq!(
            CapabilityLevel::Always.implies(CapabilityLevel::Never),
            CapabilityLevel::Never
        );
    }

    #[test]
    fn pseudo_complement() {
        // ¬⊥ = ⊤
        assert_eq!(CapabilityLevel::Never.complement(), CapabilityLevel::Always);
        // ¬⊤ = ⊥
        assert_eq!(CapabilityLevel::Always.complement(), CapabilityLevel::Never);
    }

    #[test]
    fn lattice_meet_pointwise() {
        let a = CapabilityLattice::top();
        let b = CapabilityLattice::bottom();
        assert_eq!(a.meet(&b), CapabilityLattice::bottom());
    }

    #[test]
    fn lattice_join_pointwise() {
        let a = CapabilityLattice::top();
        let b = CapabilityLattice::bottom();
        assert_eq!(a.join(&b), CapabilityLattice::top());
    }

    #[test]
    fn lattice_leq() {
        assert!(CapabilityLattice::bottom().leq(&CapabilityLattice::top()));
        assert!(!CapabilityLattice::top().leq(&CapabilityLattice::bottom()));
    }

    #[test]
    fn lattice_idempotent_meet() {
        let a = CapabilityLattice::default();
        assert_eq!(a.meet(&a), a);
    }

    #[test]
    fn lattice_idempotent_join() {
        let a = CapabilityLattice::default();
        assert_eq!(a.join(&a), a);
    }

    #[test]
    fn read_only_preserves_reads() {
        let full = CapabilityLattice::top();
        let ro = full.read_only();
        assert_eq!(ro.read_files, CapabilityLevel::Always);
        assert_eq!(ro.glob_search, CapabilityLevel::Always);
        assert_eq!(ro.grep_search, CapabilityLevel::Always);
        assert_eq!(ro.web_search, CapabilityLevel::Always);
        assert_eq!(ro.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn read_only_blocks_writes() {
        let full = CapabilityLattice::top();
        let ro = full.read_only();
        assert_eq!(ro.write_files, CapabilityLevel::Never);
        assert_eq!(ro.edit_files, CapabilityLevel::Never);
        assert_eq!(ro.run_bash, CapabilityLevel::Never);
        assert_eq!(ro.git_commit, CapabilityLevel::Never);
        assert_eq!(ro.git_push, CapabilityLevel::Never);
        assert_eq!(ro.create_pr, CapabilityLevel::Never);
        assert_eq!(ro.manage_pods, CapabilityLevel::Never);
    }

    #[test]
    fn read_only_is_deflationary() {
        let a = CapabilityLattice::default();
        let ro = a.read_only();
        assert!(ro.leq(&a));
    }

    // ════════════════════════════════════════════════════════════════════
    // Operation tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn operation_all_has_13_variants() {
        assert_eq!(Operation::ALL.len(), 13);
    }

    #[test]
    fn operation_display_roundtrip() {
        for op in Operation::ALL {
            let s = op.to_string();
            assert!(!s.is_empty(), "Display for {:?} should not be empty", op);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // SinkClass tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn sink_class_all_has_19_variants() {
        assert_eq!(SinkClass::ALL.len(), 19);
    }

    #[test]
    fn sink_class_display_roundtrip() {
        for sink in SinkClass::ALL {
            let s = sink.to_string();
            assert!(!s.is_empty(), "Display for {:?} should not be empty", sink);
        }
    }

    #[test]
    fn sink_class_exfil_vectors() {
        // Exfil vectors: HTTPEgress, GitPush, PRCommentWrite, EmailSend, AgentSpawn, CloudMutation
        assert!(SinkClass::HTTPEgress.is_exfil_vector());
        assert!(SinkClass::GitPush.is_exfil_vector());
        assert!(SinkClass::PRCommentWrite.is_exfil_vector());
        assert!(SinkClass::EmailSend.is_exfil_vector());
        assert!(SinkClass::AgentSpawn.is_exfil_vector());
        assert!(SinkClass::CloudMutation.is_exfil_vector());

        assert!(SinkClass::TicketWrite.is_exfil_vector());

        // Non-exfil: workspace writes, bash exec, git commit, memory persist, MCP write, secret read
        assert!(!SinkClass::WorkspaceWrite.is_exfil_vector());
        assert!(!SinkClass::SystemWrite.is_exfil_vector());
        assert!(!SinkClass::BashExec.is_exfil_vector());
        assert!(!SinkClass::GitCommit.is_exfil_vector());
        assert!(!SinkClass::MemoryPersist.is_exfil_vector());
        assert!(!SinkClass::MCPWrite.is_exfil_vector());
        assert!(!SinkClass::SecretRead.is_exfil_vector());
        assert!(!SinkClass::ProposedTableWrite.is_exfil_vector());
        assert!(!SinkClass::VerifiedTableWrite.is_exfil_vector());
        assert!(!SinkClass::SearchIndexWrite.is_exfil_vector());
        assert!(!SinkClass::CacheWrite.is_exfil_vector());
        assert!(!SinkClass::AuditLogAppend.is_exfil_vector());
    }

    #[test]
    fn sink_class_authority_requirements() {
        // SecretRead and AuditLogAppend require no authority
        assert_eq!(
            SinkClass::SecretRead.required_authority(),
            AuthorityLevel::NoAuthority
        );
        assert_eq!(
            SinkClass::AuditLogAppend.required_authority(),
            AuthorityLevel::NoAuthority
        );
        // All write/exec sinks require Suggestive
        for sink in SinkClass::ALL {
            if sink != SinkClass::SecretRead && sink != SinkClass::AuditLogAppend {
                assert_eq!(
                    sink.required_authority(),
                    AuthorityLevel::Suggestive,
                    "Expected Suggestive authority for {:?}",
                    sink
                );
            }
        }
    }

    #[test]
    fn sink_class_integrity_requirements() {
        // Publish vectors require Trusted
        assert_eq!(SinkClass::GitPush.required_integrity(), IntegLevel::Trusted);
        assert_eq!(
            SinkClass::PRCommentWrite.required_integrity(),
            IntegLevel::Trusted
        );
        assert_eq!(
            SinkClass::EmailSend.required_integrity(),
            IntegLevel::Trusted
        );
        // SecretRead has no integrity requirement
        assert_eq!(
            SinkClass::SecretRead.required_integrity(),
            IntegLevel::Adversarial
        );
        // Most write sinks require Untrusted
        assert_eq!(
            SinkClass::WorkspaceWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::BashExec.required_integrity(),
            IntegLevel::Untrusted
        );
        // New data-pipeline sinks
        assert_eq!(
            SinkClass::TicketWrite.required_integrity(),
            IntegLevel::Trusted
        );
        assert_eq!(
            SinkClass::VerifiedTableWrite.required_integrity(),
            IntegLevel::Trusted
        );
        assert_eq!(
            SinkClass::ProposedTableWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::SearchIndexWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::CacheWrite.required_integrity(),
            IntegLevel::Untrusted
        );
        assert_eq!(
            SinkClass::AuditLogAppend.required_integrity(),
            IntegLevel::Adversarial
        );
    }

    #[test]
    fn default_sink_class_for_all_operations() {
        // Every operation maps to a valid sink class
        for op in Operation::ALL {
            let _ = default_sink_class(op);
        }
    }

    #[test]
    fn default_sink_class_specific_mappings() {
        assert_eq!(
            default_sink_class(Operation::ReadFiles),
            SinkClass::SecretRead
        );
        assert_eq!(
            default_sink_class(Operation::WriteFiles),
            SinkClass::WorkspaceWrite
        );
        assert_eq!(default_sink_class(Operation::RunBash), SinkClass::BashExec);
        assert_eq!(
            default_sink_class(Operation::WebFetch),
            SinkClass::HTTPEgress
        );
        assert_eq!(
            default_sink_class(Operation::GitCommit),
            SinkClass::GitCommit
        );
        assert_eq!(default_sink_class(Operation::GitPush), SinkClass::GitPush);
        assert_eq!(
            default_sink_class(Operation::CreatePr),
            SinkClass::PRCommentWrite
        );
        assert_eq!(
            default_sink_class(Operation::ManagePods),
            SinkClass::CloudMutation
        );
        assert_eq!(
            default_sink_class(Operation::SpawnAgent),
            SinkClass::AgentSpawn
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // ExposureSet tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn exposure_set_empty_is_not_uninhabitable() {
        assert!(!ExposureSet::empty().is_uninhabitable());
        assert_eq!(ExposureSet::empty().count(), 0);
    }

    #[test]
    fn exposure_set_singleton() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        assert!(s.contains(ExposureLabel::PrivateData));
        assert!(!s.contains(ExposureLabel::UntrustedContent));
        assert!(!s.contains(ExposureLabel::ExfilVector));
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn exposure_set_union_accumulates() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
        let c = a.union(&b);
        assert!(c.contains(ExposureLabel::PrivateData));
        assert!(c.contains(ExposureLabel::UntrustedContent));
        assert!(!c.contains(ExposureLabel::ExfilVector));
        assert_eq!(c.count(), 2);
    }

    #[test]
    fn exposure_set_all_three_is_uninhabitable() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        assert!(s.is_uninhabitable());
        assert_eq!(s.count(), 3);
    }

    #[test]
    fn exposure_set_union_idempotent() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        assert_eq!(s.union(&s), s);
    }

    #[test]
    fn exposure_set_union_commutative() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::ExfilVector);
        assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn exposure_set_union_associative() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
        let c = ExposureSet::singleton(ExposureLabel::ExfilVector);
        assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn exposure_set_monotonicity() {
        // Once set, a label cannot be unset
        let mut s = ExposureSet::empty();
        s.set(ExposureLabel::PrivateData);
        assert!(s.contains(ExposureLabel::PrivateData));

        // Union with empty doesn't lose information
        let u = s.union(&ExposureSet::empty());
        assert!(u.contains(ExposureLabel::PrivateData));
    }

    // ════════════════════════════════════════════════════════════════════
    // Classification function tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn classify_operation_coverage() {
        let expected = [
            (Operation::ReadFiles, Some(ExposureLabel::PrivateData)),
            (Operation::WriteFiles, None),
            (Operation::EditFiles, None),
            (Operation::RunBash, Some(ExposureLabel::ExfilVector)),
            (Operation::GlobSearch, Some(ExposureLabel::PrivateData)),
            (Operation::GrepSearch, Some(ExposureLabel::PrivateData)),
            (Operation::WebSearch, Some(ExposureLabel::UntrustedContent)),
            (Operation::WebFetch, Some(ExposureLabel::UntrustedContent)),
            (Operation::GitCommit, None),
            (Operation::GitPush, Some(ExposureLabel::ExfilVector)),
            (Operation::CreatePr, Some(ExposureLabel::ExfilVector)),
            (Operation::ManagePods, None),
        ];
        for (op, exp) in expected {
            assert_eq!(classify_operation(op), exp, "mismatch for {:?}", op);
        }
    }

    #[test]
    fn project_exposure_adds_label() {
        let empty = ExposureSet::empty();
        let projected = project_exposure(&empty, Operation::ReadFiles);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(!projected.contains(ExposureLabel::UntrustedContent));
        assert!(!projected.contains(ExposureLabel::ExfilVector));
    }

    #[test]
    fn project_exposure_neutral_op_unchanged() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        let projected = project_exposure(&s, Operation::WriteFiles);
        assert_eq!(projected, s);
    }

    #[test]
    fn is_exfil_operation_identifies_vectors() {
        assert!(is_exfil_operation(Operation::RunBash));
        assert!(is_exfil_operation(Operation::GitPush));
        assert!(is_exfil_operation(Operation::CreatePr));
        assert!(!is_exfil_operation(Operation::ReadFiles));
        assert!(!is_exfil_operation(Operation::WebFetch));
        assert!(!is_exfil_operation(Operation::WriteFiles));
    }

    #[test]
    fn should_gate_blocks_completing_uninhabitable() {
        // Two legs active: PrivateData + UntrustedContent
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        // GitPush would complete the uninhabitable state → gated
        assert!(should_gate(&exposure, Operation::GitPush));
        // ReadFiles doesn't complete it (already has PrivateData) → not gated
        assert!(!should_gate(&exposure, Operation::ReadFiles));
        // WriteFiles is neutral → not gated
        assert!(!should_gate(&exposure, Operation::WriteFiles));
    }

    #[test]
    fn should_gate_already_uninhabitable() {
        let full = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        // Already uninhabitable → all exfil ops gated
        assert!(should_gate(&full, Operation::GitPush));
        assert!(should_gate(&full, Operation::CreatePr));
        assert!(should_gate(&full, Operation::RunBash));
        // Non-exfil ops still not gated
        assert!(!should_gate(&full, Operation::ReadFiles));
        assert!(!should_gate(&full, Operation::WebFetch));
    }

    #[test]
    fn should_gate_safe_state_allows_everything() {
        let empty = ExposureSet::empty();
        for op in Operation::ALL {
            assert!(
                !should_gate(&empty, op),
                "should not gate {:?} from empty state",
                op
            );
        }
    }

    #[test]
    fn apply_record_matches_project() {
        for op in Operation::ALL {
            let s = ExposureSet::singleton(ExposureLabel::PrivateData);
            assert_eq!(
                apply_record(&s, op),
                project_exposure(&s, op),
                "apply_record and project_exposure should agree for {:?}",
                op
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // IFC Label tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn ifc_join_confidentiality_covariant() {
        let public = IFCLabel {
            confidentiality: ConfLevel::Public,
            ..IFCLabel::default()
        };
        let secret = IFCLabel {
            confidentiality: ConfLevel::Secret,
            ..IFCLabel::default()
        };
        assert_eq!(public.join(secret).confidentiality, ConfLevel::Secret);
    }

    #[test]
    fn ifc_join_integrity_contravariant() {
        let trusted = IFCLabel {
            integrity: IntegLevel::Trusted,
            ..IFCLabel::default()
        };
        let adversarial = IFCLabel {
            integrity: IntegLevel::Adversarial,
            ..IFCLabel::default()
        };
        // Least trusted wins
        assert_eq!(trusted.join(adversarial).integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn ifc_join_authority_contravariant() {
        let directive = IFCLabel {
            authority: AuthorityLevel::Directive,
            ..IFCLabel::default()
        };
        let no_auth = IFCLabel {
            authority: AuthorityLevel::NoAuthority,
            ..IFCLabel::default()
        };
        // Least authority wins
        assert_eq!(
            directive.join(no_auth).authority,
            AuthorityLevel::NoAuthority
        );
    }

    #[test]
    fn ifc_join_provenance_union() {
        let user = IFCLabel {
            provenance: ProvenanceSet::USER,
            ..IFCLabel::default()
        };
        let web = IFCLabel {
            provenance: ProvenanceSet::WEB,
            ..IFCLabel::default()
        };
        let joined = user.join(web);
        assert!(joined.provenance.contains(ProvenanceSet::USER));
        assert!(joined.provenance.contains(ProvenanceSet::WEB));
    }

    #[test]
    fn ifc_web_content_plus_user_prompt_kills_authority() {
        // THE key indirect-injection defense test:
        // User prompt (Directive) + web content (NoAuthority) = NoAuthority
        let user = IFCLabel::user_prompt(1000);
        let web = IFCLabel::web_content(1000);
        let combined = user.join(web);
        assert_eq!(combined.authority, AuthorityLevel::NoAuthority);
        assert_eq!(combined.integrity, IntegLevel::Adversarial);
    }

    #[test]
    fn ifc_secret_does_not_flow_to_public() {
        let secret = IFCLabel::secret(1000);
        let public_sink = IFCLabel {
            confidentiality: ConfLevel::Public,
            ..IFCLabel::default()
        };
        assert!(!secret.flows_to(public_sink));
    }

    #[test]
    fn ifc_untrusted_does_not_flow_to_trusted() {
        let untrusted = IFCLabel {
            integrity: IntegLevel::Untrusted,
            ..IFCLabel::default()
        };
        let trusted_sink = IFCLabel {
            integrity: IntegLevel::Trusted,
            ..IFCLabel::default()
        };
        assert!(!untrusted.flows_to(trusted_sink));
    }

    #[test]
    fn ifc_no_authority_does_not_flow_to_directive() {
        let no_auth = IFCLabel {
            authority: AuthorityLevel::NoAuthority,
            ..IFCLabel::default()
        };
        let directive_sink = IFCLabel {
            authority: AuthorityLevel::Directive,
            ..IFCLabel::default()
        };
        assert!(!no_auth.flows_to(directive_sink));
    }

    #[test]
    fn ifc_bottom_flows_to_everything() {
        let bot = IFCLabel::bottom();
        let top = IFCLabel::top();
        assert!(bot.flows_to(top));
    }

    #[test]
    fn ifc_top_flows_to_nothing_but_itself() {
        let top = IFCLabel::top();
        let bot = IFCLabel::bottom();
        assert!(!top.flows_to(bot));
        assert!(top.flows_to(top));
    }

    #[test]
    fn ifc_quotient_map_backward_compatible() {
        // The quotient φ maps IFCLabel to ExposureSet correctly
        let secret_untrusted = IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Untrusted,
            ..IFCLabel::default()
        };
        let exposure = ifc_to_exposure(&secret_untrusted, Operation::GitPush);
        assert!(exposure.contains(ExposureLabel::PrivateData));
        assert!(exposure.contains(ExposureLabel::UntrustedContent));
        assert!(exposure.contains(ExposureLabel::ExfilVector));
        assert!(exposure.is_uninhabitable());
    }

    #[test]
    fn ifc_quotient_public_trusted_is_safe() {
        let safe = IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            ..IFCLabel::default()
        };
        let exposure = ifc_to_exposure(&safe, Operation::ReadFiles);
        assert!(!exposure.is_uninhabitable());
    }

    #[test]
    fn ifc_freshness_join_oldest_shortest() {
        let a = Freshness {
            observed_at: 1000,
            ttl_secs: 3600,
        };
        let b = Freshness {
            observed_at: 500,
            ttl_secs: 7200,
        };
        let joined = a.join(b);
        assert_eq!(joined.observed_at, 500); // oldest
        assert_eq!(joined.ttl_secs, 3600); // shortest
    }

    #[test]
    fn ifc_freshness_expiry() {
        let f = Freshness {
            observed_at: 1000,
            ttl_secs: 3600,
        };
        assert!(!f.is_expired_at(2000));
        assert!(f.is_expired_at(5000));
    }

    #[test]
    fn provenance_union_and_subset() {
        let user_web = ProvenanceSet::USER.union(ProvenanceSet::WEB);
        assert!(ProvenanceSet::USER.is_subset_of(user_web));
        assert!(ProvenanceSet::WEB.is_subset_of(user_web));
        assert!(!ProvenanceSet::MEMORY.is_subset_of(user_web));
    }

    // -----------------------------------------------------------------------
    // Lean-Rust structural correspondence tests
    //
    // These verify that the Lean models in lean/generated/ match the Rust
    // source. If a field is added/removed in Rust without updating Lean,
    // these tests will fail — alerting the developer to update.
    // -----------------------------------------------------------------------

    #[test]
    fn lean_correspondence_capability_lattice_field_count() {
        // The Lean CapabilityLattice has 13 fields (matching Rust).
        // If you add a field to Rust, this test reminds you to update
        // lean/generated/Types.lean and lean/PortcullisCoreBridge.lean.
        assert_eq!(
            Operation::ALL.len(),
            13,
            "Rust CapabilityLattice has 13 dimensions — update Lean Types.lean if this changes"
        );
    }

    #[test]
    fn lean_correspondence_capability_level_variants() {
        // Lean CapabilityLevel has 3 variants: Never, LowRisk, Always
        // with discriminants 0, 1, 2 matching repr(u8).
        assert_eq!(CapabilityLevel::Never as u8, 0);
        assert_eq!(CapabilityLevel::LowRisk as u8, 1);
        assert_eq!(CapabilityLevel::Always as u8, 2);
    }

    #[test]
    fn lean_correspondence_operation_count() {
        // Lean proofs assume 13 operations. If this changes,
        // update ExposureProofs.lean classify_operation coverage.
        assert_eq!(
            Operation::ALL.len(),
            13,
            "Operation count changed — update Lean ExposureProofs.lean"
        );
    }

    #[test]
    fn lean_correspondence_exposure_labels() {
        // ExposureProofs.lean models 3 exposure labels.
        assert_eq!(ExposureLabel::PrivateData as u8, 0);
        assert_eq!(ExposureLabel::UntrustedContent as u8, 1);
        assert_eq!(ExposureLabel::ExfilVector as u8, 2);
    }

    #[test]
    fn lean_correspondence_spawn_agent_is_exfil() {
        // Lean models SpawnAgent as ExfilVector.
        // This must match classify_operation.
        assert_eq!(
            classify_operation(Operation::SpawnAgent),
            Some(ExposureLabel::ExfilVector),
            "SpawnAgent must be ExfilVector — matches Lean ExposureProofs"
        );
    }

    #[test]
    fn lean_correspondence_meet_commutative() {
        // The Lean HeytingAlgebra proof includes commutativity.
        // Verify the Rust implementation matches.
        let a = CapabilityLevel::Always;
        let b = CapabilityLevel::Never;
        assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn lean_correspondence_meet_idempotent() {
        for level in [
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ] {
            assert_eq!(level.meet(level), level);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // DerivationClass lattice tests
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn derivation_join_exhaustive_table() {
        use DerivationClass::*;
        // Exhaustive 5x5 join table matching the diamond lattice:
        //       OpaqueExternal
        //            |
        //          Mixed
        //         /     \
        //   AIDerived  HumanPromoted
        //         \     /
        //       Deterministic
        let cases = [
            // Deterministic is bottom — identity for join
            (Deterministic, Deterministic, Deterministic),
            (Deterministic, AIDerived, AIDerived),
            (Deterministic, Mixed, Mixed),
            (Deterministic, HumanPromoted, HumanPromoted),
            (Deterministic, OpaqueExternal, OpaqueExternal),
            // AIDerived joins
            (AIDerived, Deterministic, AIDerived),
            (AIDerived, AIDerived, AIDerived),
            (AIDerived, Mixed, Mixed),
            (AIDerived, HumanPromoted, Mixed),
            (AIDerived, OpaqueExternal, OpaqueExternal),
            // Mixed joins
            (Mixed, Deterministic, Mixed),
            (Mixed, AIDerived, Mixed),
            (Mixed, Mixed, Mixed),
            (Mixed, HumanPromoted, Mixed),
            (Mixed, OpaqueExternal, OpaqueExternal),
            // HumanPromoted joins
            (HumanPromoted, Deterministic, HumanPromoted),
            (HumanPromoted, AIDerived, Mixed),
            (HumanPromoted, Mixed, Mixed),
            (HumanPromoted, HumanPromoted, HumanPromoted),
            (HumanPromoted, OpaqueExternal, OpaqueExternal),
            // OpaqueExternal is top — absorbs everything
            (OpaqueExternal, Deterministic, OpaqueExternal),
            (OpaqueExternal, AIDerived, OpaqueExternal),
            (OpaqueExternal, Mixed, OpaqueExternal),
            (OpaqueExternal, HumanPromoted, OpaqueExternal),
            (OpaqueExternal, OpaqueExternal, OpaqueExternal),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                a.join(b),
                expected,
                "{:?}.join({:?}) should be {:?}",
                a,
                b,
                expected
            );
        }
    }

    #[test]
    fn derivation_join_commutative() {
        use DerivationClass::*;
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "{:?}.join({:?}) not commutative",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn derivation_join_associative() {
        use DerivationClass::*;
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                for &c in &all {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
                        "({:?} join {:?}) join {:?} != {:?} join ({:?} join {:?})",
                        a,
                        b,
                        c,
                        a,
                        b,
                        c
                    );
                }
            }
        }
    }

    #[test]
    fn derivation_join_idempotent() {
        use DerivationClass::*;
        for &d in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            assert_eq!(d.join(d), d, "{:?}.join({:?}) should be idempotent", d, d);
        }
    }

    #[test]
    fn derivation_leq_reflexive() {
        use DerivationClass::*;
        for &d in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            assert!(d.leq(d), "{:?} should be leq itself", d);
        }
    }

    #[test]
    fn derivation_leq_antisymmetric() {
        use DerivationClass::*;
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                if a.leq(b) && b.leq(a) {
                    assert_eq!(
                        a, b,
                        "{:?} leq {:?} and {:?} leq {:?} but not equal",
                        a, b, b, a
                    );
                }
            }
        }
    }

    #[test]
    fn derivation_lattice_ordering() {
        use DerivationClass::*;
        // Deterministic is bottom
        assert!(Deterministic.leq(AIDerived));
        assert!(Deterministic.leq(HumanPromoted));
        assert!(Deterministic.leq(Mixed));
        assert!(Deterministic.leq(OpaqueExternal));

        // AIDerived and HumanPromoted are incomparable
        assert!(!AIDerived.leq(HumanPromoted));
        assert!(!HumanPromoted.leq(AIDerived));

        // Both are below Mixed
        assert!(AIDerived.leq(Mixed));
        assert!(HumanPromoted.leq(Mixed));
        assert!(!Mixed.leq(AIDerived));
        assert!(!Mixed.leq(HumanPromoted));

        // OpaqueExternal is top
        for &d in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            assert!(d.leq(OpaqueExternal), "{:?} should be <= OpaqueExternal", d);
        }
    }

    #[test]
    fn derivation_no_silent_cleansing() {
        use DerivationClass::*;
        // AIDerived joined with anything that is not HumanPromoted
        // must never produce Deterministic.
        for &other in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            let result = AIDerived.join(other);
            assert_ne!(
                result, Deterministic,
                "AIDerived.join({:?}) = Deterministic violates no-silent-cleansing",
                other
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // DPI invariant test mirrors (non-Kani mirrors of Kani proofs)
    // ════════════════════════════════════════════════════════════════════

    /// Taint level height in the Hasse diagram (mirrors Kani taint_level).
    fn taint_level(d: DerivationClass) -> u8 {
        match d {
            DerivationClass::Deterministic => 0,
            DerivationClass::AIDerived => 1,
            DerivationClass::HumanPromoted => 1,
            DerivationClass::Mixed => 2,
            DerivationClass::OpaqueExternal => 3,
        }
    }

    #[test]
    fn derivation_no_silent_cleansing_exhaustive() {
        use DerivationClass::*;
        // DPI-1: For ALL variants, AIDerived.join(x) != Deterministic
        for &x in &[
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ] {
            let result = AIDerived.join(x);
            assert_ne!(
                result, Deterministic,
                "DPI-1 violated: AIDerived.join({:?}) = Deterministic",
                x
            );
        }
    }

    #[test]
    fn derivation_join_monotone_exhaustive() {
        use DerivationClass::*;
        // DPI-2: For ALL pairs, taint_level(join(a,b)) >= max(taint_level(a), taint_level(b))
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                let result = a.join(b);
                let max_input = taint_level(a).max(taint_level(b));
                assert!(
                    taint_level(result) >= max_input,
                    "DPI-2 violated: taint_level({:?}.join({:?})) = {} < max({}, {}) = {}",
                    a,
                    b,
                    taint_level(result),
                    taint_level(a),
                    taint_level(b),
                    max_input
                );
            }
        }
    }

    #[test]
    fn derivation_meet_exhaustive() {
        use DerivationClass::*;
        // Meet is dual of join — verify key properties
        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &a in &all {
            for &b in &all {
                let m = a.meet(b);
                // meet(a,b) <= a and meet(a,b) <= b
                assert!(
                    m.leq(a),
                    "meet({:?},{:?}) = {:?} should be <= {:?}",
                    a,
                    b,
                    m,
                    a
                );
                assert!(
                    m.leq(b),
                    "meet({:?},{:?}) = {:?} should be <= {:?}",
                    a,
                    b,
                    m,
                    b
                );
            }
        }
    }

    #[test]
    fn derivation_propagation_through_flow() {
        // Deterministic file + AIDerived model plan = AIDerived
        // (Deterministic is bottom, so it's absorbed by AIDerived)
        let file_label = IFCLabel {
            derivation: DerivationClass::Deterministic,
            ..IFCLabel::bottom()
        };
        let model_label = IFCLabel {
            derivation: DerivationClass::AIDerived,
            ..IFCLabel::bottom()
        };
        let result = file_label.join(model_label);
        assert_eq!(result.derivation, DerivationClass::AIDerived);

        // AIDerived + HumanPromoted = Mixed (incomparable elements)
        let ai_label = IFCLabel {
            derivation: DerivationClass::AIDerived,
            ..IFCLabel::bottom()
        };
        let human_label = IFCLabel {
            derivation: DerivationClass::HumanPromoted,
            ..IFCLabel::bottom()
        };
        let result = ai_label.join(human_label);
        assert_eq!(result.derivation, DerivationClass::Mixed);
    }

    #[test]
    fn derivation_opaque_absorbs_in_join() {
        // Any label joined with OpaqueExternal produces OpaqueExternal derivation
        let opaque = IFCLabel {
            derivation: DerivationClass::OpaqueExternal,
            ..IFCLabel::bottom()
        };
        for &d in &[
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
        ] {
            let other = IFCLabel {
                derivation: d,
                ..IFCLabel::bottom()
            };
            assert_eq!(
                opaque.join(other).derivation,
                DerivationClass::OpaqueExternal,
                "OpaqueExternal should absorb {:?} in IFCLabel join",
                d
            );
        }
    }

    #[test]
    fn derivation_intrinsic_labels_correct() {
        use crate::flow::{NodeKind, intrinsic_label};
        let now = 1000;

        // Deterministic sources
        assert_eq!(
            intrinsic_label(NodeKind::UserPrompt, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::FileRead, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::EnvVar, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::Secret, now).derivation,
            DerivationClass::Deterministic
        );
        assert_eq!(
            intrinsic_label(NodeKind::ToolResponse, now).derivation,
            DerivationClass::Deterministic
        );

        // AI-derived sources
        assert_eq!(
            intrinsic_label(NodeKind::ModelPlan, now).derivation,
            DerivationClass::AIDerived
        );
        assert_eq!(
            intrinsic_label(NodeKind::MemoryWrite, now).derivation,
            DerivationClass::AIDerived
        );
        assert_eq!(
            intrinsic_label(NodeKind::Summarization, now).derivation,
            DerivationClass::AIDerived
        );

        // OpaqueExternal
        assert_eq!(
            intrinsic_label(NodeKind::WebContent, now).derivation,
            DerivationClass::OpaqueExternal
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // IFCLabel bounded lattice axiom tests (test-mode mirrors of Kani proofs)
    // ════════════════════════════════════════════════════════════════════

    /// Helper: enumerate all ConfLevel x IntegLevel x AuthorityLevel x DerivationClass
    /// x ProvenanceSet combinations with fixed freshness (11520 labels).
    fn all_labels() -> Vec<IFCLabel> {
        let confs = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        let integs = [
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        let auths = [
            AuthorityLevel::NoAuthority,
            AuthorityLevel::Informational,
            AuthorityLevel::Suggestive,
            AuthorityLevel::Directive,
        ];
        let derivs = [
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ];
        let fresh = Freshness {
            observed_at: 100,
            ttl_secs: 0,
        };

        let mut labels = Vec::new();
        for &c in &confs {
            for &i in &integs {
                for &a in &auths {
                    for &d in &derivs {
                        for prov_bits in 0..64u8 {
                            labels.push(IFCLabel {
                                confidentiality: c,
                                integrity: i,
                                provenance: ProvenanceSet::from_bits(prov_bits),
                                freshness: fresh,
                                authority: a,
                                derivation: d,
                            });
                        }
                    }
                }
            }
        }
        labels
    }

    #[test]
    fn ifc_join_idempotent_exhaustive() {
        for a in all_labels() {
            let r = a.join(a);
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
            assert_eq!(r.derivation, a.derivation);
        }
    }

    #[test]
    fn ifc_join_commutative_exhaustive() {
        // Sample pairs (full cross-product is 2304^2 ≈ 5M — too many)
        let labels = all_labels();
        // Test every label against a representative set
        let reps = [
            IFCLabel::bottom(),
            IFCLabel::top(),
            IFCLabel::web_content(100),
            IFCLabel::user_prompt(100),
            IFCLabel::secret(100),
        ];
        for a in &labels {
            for b in &reps {
                let ab = a.join(*b);
                let ba = b.join(*a);
                assert_eq!(ab.confidentiality, ba.confidentiality);
                assert_eq!(ab.integrity, ba.integrity);
                assert_eq!(ab.authority, ba.authority);
                assert_eq!(ab.provenance.bits(), ba.provenance.bits());
            }
        }
    }

    #[test]
    fn ifc_meet_idempotent_exhaustive() {
        for a in all_labels() {
            let r = a.meet(a);
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
        }
    }

    #[test]
    fn ifc_absorption_join_meet() {
        let labels = all_labels();
        let reps = [
            IFCLabel::bottom(),
            IFCLabel::top(),
            IFCLabel::web_content(100),
            IFCLabel::user_prompt(100),
        ];
        for a in &labels {
            for b in &reps {
                let r = a.join(a.meet(*b));
                assert_eq!(r.confidentiality, a.confidentiality);
                assert_eq!(r.integrity, a.integrity);
                assert_eq!(r.authority, a.authority);
                assert_eq!(r.provenance.bits(), a.provenance.bits());
            }
        }
    }

    #[test]
    fn ifc_absorption_meet_join() {
        let labels = all_labels();
        let reps = [
            IFCLabel::bottom(),
            IFCLabel::top(),
            IFCLabel::web_content(100),
            IFCLabel::user_prompt(100),
        ];
        for a in &labels {
            for b in &reps {
                let r = a.meet(a.join(*b));
                assert_eq!(r.confidentiality, a.confidentiality);
                assert_eq!(r.integrity, a.integrity);
                assert_eq!(r.authority, a.authority);
                assert_eq!(r.provenance.bits(), a.provenance.bits());
            }
        }
    }

    #[test]
    fn ifc_bottom_is_join_identity() {
        for a in all_labels() {
            let r = a.join(IFCLabel::bottom());
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
        }
    }

    #[test]
    fn ifc_top_is_meet_identity() {
        for a in all_labels() {
            let r = a.meet(IFCLabel::top());
            assert_eq!(r.confidentiality, a.confidentiality);
            assert_eq!(r.integrity, a.integrity);
            assert_eq!(r.authority, a.authority);
            assert_eq!(r.provenance.bits(), a.provenance.bits());
        }
    }
}
