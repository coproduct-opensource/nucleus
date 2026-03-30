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
pub struct CapabilityLattice {
    pub read_files: CapabilityLevel,
    pub write_files: CapabilityLevel,
    pub edit_files: CapabilityLevel,
    pub run_bash: CapabilityLevel,
    pub glob_search: CapabilityLevel,
    pub grep_search: CapabilityLevel,
    pub web_search: CapabilityLevel,
    pub web_fetch: CapabilityLevel,
    pub git_commit: CapabilityLevel,
    pub git_push: CapabilityLevel,
    pub create_pr: CapabilityLevel,
    pub manage_pods: CapabilityLevel,
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
};

impl Operation {
    /// All 12 core operations.
    pub const ALL: [Operation; 12] = [
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
        Operation::RunBash | Operation::GitPush | Operation::CreatePr => {
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
    fn operation_all_has_12_variants() {
        assert_eq!(Operation::ALL.len(), 12);
    }

    #[test]
    fn operation_display_roundtrip() {
        for op in Operation::ALL {
            let s = op.to_string();
            assert!(!s.is_empty(), "Display for {:?} should not be empty", op);
        }
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
        // For the core types (no omnibus RunBash divergence), apply_record == project_exposure
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
}
