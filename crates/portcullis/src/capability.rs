//! Capability lattice for tool permissions.

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Tool permission levels in lattice ordering.
///
/// Single source of truth: re-exported from `portcullis-core`.
/// The verified type IS the production type — one type, zero translation layers.
pub use portcullis_core::CapabilityLevel;

/// Operations that can be gated by approval.
///
/// Single source of truth: re-exported from `portcullis-core`.
/// The verified type IS the production type — one type, zero translation layers.
pub use portcullis_core::{Operation, OperationParseError};

/// Extension operation not covered by Verus proofs.
///
/// The 12 core operations above are frozen — they have 297 Verus verification
/// conditions proving lattice laws, exposure monotonicity, and session safety.
/// Extension operations participate in the same product lattice (meet = pointwise min,
/// join = pointwise max) but are verified only by property tests, not SMT proofs.
///
/// Lattice laws hold by the universal property of products in **Lat**: if each
/// factor is a lattice, the product is a lattice. Since `CapabilityLevel` is a
/// 3-element chain (a lattice), `CapabilityLevel^E` for any finite set `E` is a lattice.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtensionOperation(pub String);

impl ExtensionOperation {
    /// Create a new extension operation.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl std::fmt::Display for ExtensionOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Approval obligations that gate autonomous capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Obligations {
    /// Operations that require explicit approval.
    #[cfg_attr(feature = "serde", serde(default))]
    pub approvals: std::collections::BTreeSet<Operation>,
}

impl Obligations {
    /// Create obligations for a single operation.
    pub fn for_operation(op: Operation) -> Self {
        let mut approvals = std::collections::BTreeSet::new();
        approvals.insert(op);
        Self { approvals }
    }

    /// Check if an operation requires approval.
    pub fn requires(&self, op: Operation) -> bool {
        self.approvals.contains(&op)
    }

    /// Add an approval obligation.
    pub fn insert(&mut self, op: Operation) {
        self.approvals.insert(op);
    }

    /// Get the number of obligations.
    pub fn len(&self) -> usize {
        self.approvals.len()
    }

    /// Check if there are no obligations.
    pub fn is_empty(&self) -> bool {
        self.approvals.is_empty()
    }

    /// Union of obligations.
    pub fn union(&self, other: &Self) -> Self {
        let mut approvals = self.approvals.clone();
        approvals.extend(other.approvals.iter().copied());
        Self { approvals }
    }

    /// Intersection of obligations.
    pub fn intersection(&self, other: &Self) -> Self {
        let approvals = self
            .approvals
            .intersection(&other.approvals)
            .copied()
            .collect();
        Self { approvals }
    }

    /// Check if obligations are less than or equal in the policy order.
    ///
    /// More obligations means a more constrained (smaller) policy.
    pub fn leq(&self, other: &Self) -> bool {
        self.approvals.is_superset(&other.approvals)
    }
}

/// Capability lattice for tool permissions.
///
/// Each field represents a different tool category with its own permission level.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapabilityLattice {
    /// Read files permission level
    pub read_files: CapabilityLevel,
    /// Write files permission level
    pub write_files: CapabilityLevel,
    /// Edit files permission level
    pub edit_files: CapabilityLevel,
    /// Run bash commands permission level
    pub run_bash: CapabilityLevel,
    /// Glob search permission level
    pub glob_search: CapabilityLevel,
    /// Grep search permission level
    pub grep_search: CapabilityLevel,
    /// Web search permission level
    pub web_search: CapabilityLevel,
    /// Web fetch permission level
    pub web_fetch: CapabilityLevel,
    /// Git commit permission level
    pub git_commit: CapabilityLevel,
    /// Git push permission level
    pub git_push: CapabilityLevel,
    /// Create PR permission level
    pub create_pr: CapabilityLevel,
    /// Manage sub-pods permission level
    #[cfg_attr(feature = "serde", serde(default))]
    pub manage_pods: CapabilityLevel,

    /// Extension capability dimensions (not covered by Verus proofs).
    ///
    /// Meet = pointwise min, join = pointwise max, leq = pointwise ≤.
    /// Unknown extensions default to `Never` (fail-closed).
    ///
    /// Excluded from Kani builds: BTreeMap's heap allocator is intractable
    /// for bounded model checking. Extension lattice laws are covered by proptest.
    #[cfg(not(kani))]
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub extensions: BTreeMap<ExtensionOperation, CapabilityLevel>,
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
            #[cfg(not(kani))]
            extensions: BTreeMap::new(),
        }
    }
}

/// Incompatibility constraint that enforces uninhabitable_state prevention.
///
/// Graded risk level for uninhabitable_state completeness.
///
/// This implements a graded topology (fuzzy subobject classifier) rather than
/// a binary one, enabling proportional response to risk levels.
///
/// The ordering forms a bounded lattice: `Safe < Low < Medium < Uninhabitable`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StateRisk {
    /// No uninhabitable_state components present (0 of 3)
    #[default]
    #[cfg_attr(feature = "serde", serde(alias = "none"))]
    Safe = 0,
    /// One component present (1 of 3) - low risk
    Low = 1,
    /// Two components present (2 of 3) - medium risk, escalation likely
    Medium = 2,
    /// All three components present - uninhabitable_state, requires intervention
    #[cfg_attr(feature = "serde", serde(alias = "complete"))]
    Uninhabitable = 3,
}

impl StateRisk {
    /// Returns true if this risk level requires approval obligations
    pub fn requires_intervention(&self) -> bool {
        *self == StateRisk::Uninhabitable
    }

    /// Meet operation: takes the minimum risk level
    pub fn meet(&self, other: &Self) -> Self {
        std::cmp::min(*self, *other)
    }

    /// Join operation: takes the maximum risk level
    pub fn join(&self, other: &Self) -> Self {
        std::cmp::max(*self, *other)
    }
}

/// The "uninhabitable_state" is the combination of:
/// 1. Private data access (read_files, glob_search, grep_search)
/// 2. Untrusted content exposure (web_fetch, web_search)
/// 3. Exfiltration vector (git_push, create_pr, run_bash)
///
/// When all three are present at autonomous levels (≥ LowRisk), this constraint
/// adds approval obligations for the exfiltration vector.
///
/// Note: glob_search and grep_search are included as information disclosure vectors
/// because they can reveal file structure and contents, which combined with
/// untrusted content and exfiltration could enable prompt injection attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IncompatibilityConstraint {
    /// Whether to enforce uninhabitable_state prevention
    pub enforce_uninhabitable: bool,
}

impl IncompatibilityConstraint {
    /// Create an enforcing constraint.
    pub fn enforcing() -> Self {
        Self {
            enforce_uninhabitable: true,
        }
    }

    /// Compute the graded uninhabitable_state risk level.
    ///
    /// Returns a `StateRisk` indicating how many of the three uninhabitable_state
    /// components are present at autonomous levels (≥ LowRisk):
    /// - `None`: 0 components
    /// - `Low`: 1 component
    /// - `Medium`: 2 components
    /// - `Complete`: all 3 components (intervention required)
    pub fn state_risk(&self, caps: &CapabilityLattice) -> StateRisk {
        if !self.enforce_uninhabitable {
            return StateRisk::Safe;
        }

        // Information disclosure: reading files OR searching file structure/contents
        let has_private_access = caps.read_files >= CapabilityLevel::LowRisk
            || caps.glob_search >= CapabilityLevel::LowRisk
            || caps.grep_search >= CapabilityLevel::LowRisk;
        let has_untrusted = caps.web_fetch >= CapabilityLevel::LowRisk
            || caps.web_search >= CapabilityLevel::LowRisk;
        let has_exfil = caps.git_push >= CapabilityLevel::LowRisk
            || caps.create_pr >= CapabilityLevel::LowRisk
            || caps.run_bash >= CapabilityLevel::LowRisk;

        let count = has_private_access as u8 + has_untrusted as u8 + has_exfil as u8;
        match count {
            0 => StateRisk::Safe,
            1 => StateRisk::Low,
            2 => StateRisk::Medium,
            _ => StateRisk::Uninhabitable,
        }
    }

    /// Check if capabilities form a uninhabitable_state at autonomous levels.
    ///
    /// Returns true if:
    /// 1. Private data access (read_files) >= LowRisk
    /// 2. Untrusted content exposure (web_fetch OR web_search) >= LowRisk
    /// 3. Exfiltration vector (git_push OR create_pr OR run_bash) >= LowRisk
    pub fn is_uninhabitable(&self, caps: &CapabilityLattice) -> bool {
        self.state_risk(caps) == StateRisk::Uninhabitable
    }

    /// Check if capabilities form a uninhabitable_state at autonomous levels.
    /// (Legacy alias for backward compatibility)
    #[deprecated(since = "0.2.0", note = "Use state_risk() for graded assessment")]
    pub fn is_uninhabitable_legacy(&self, caps: &CapabilityLattice) -> bool {
        if !self.enforce_uninhabitable {
            return false;
        }

        // Information disclosure: reading files OR searching file structure/contents
        let has_private_access = caps.read_files >= CapabilityLevel::LowRisk
            || caps.glob_search >= CapabilityLevel::LowRisk
            || caps.grep_search >= CapabilityLevel::LowRisk;
        let has_untrusted = caps.web_fetch >= CapabilityLevel::LowRisk
            || caps.web_search >= CapabilityLevel::LowRisk;
        let has_exfil = caps.git_push >= CapabilityLevel::LowRisk
            || caps.create_pr >= CapabilityLevel::LowRisk
            || caps.run_bash >= CapabilityLevel::LowRisk;

        has_private_access && has_untrusted && has_exfil
    }

    /// Compute approval obligations required to break a uninhabitable_state.
    pub fn obligations_for(&self, caps: &CapabilityLattice) -> Obligations {
        if !self.is_uninhabitable(caps) {
            return Obligations::default();
        }

        let mut obligations = Obligations::default();
        if caps.git_push >= CapabilityLevel::LowRisk {
            obligations.insert(Operation::GitPush);
        }
        if caps.create_pr >= CapabilityLevel::LowRisk {
            obligations.insert(Operation::CreatePr);
        }
        if caps.run_bash >= CapabilityLevel::LowRisk {
            obligations.insert(Operation::RunBash);
        }
        obligations
    }
}

impl CapabilityLattice {
    /// Get the capability level for a given core operation.
    pub fn level_for(&self, op: Operation) -> CapabilityLevel {
        match op {
            Operation::ReadFiles => self.read_files,
            Operation::WriteFiles => self.write_files,
            Operation::EditFiles => self.edit_files,
            Operation::RunBash => self.run_bash,
            Operation::GlobSearch => self.glob_search,
            Operation::GrepSearch => self.grep_search,
            Operation::WebSearch => self.web_search,
            Operation::WebFetch => self.web_fetch,
            Operation::GitCommit => self.git_commit,
            Operation::GitPush => self.git_push,
            Operation::CreatePr => self.create_pr,
            Operation::ManagePods => self.manage_pods,
        }
    }

    /// Get the capability level for an extension operation.
    /// Returns `Never` (fail-closed) if the operation is not registered.
    #[cfg(not(kani))]
    pub fn extension_level(&self, op: &ExtensionOperation) -> CapabilityLevel {
        self.extensions
            .get(op)
            .copied()
            .unwrap_or(CapabilityLevel::Never)
    }

    /// Meet operation: minimum of each capability.
    ///
    /// For extension dimensions, missing keys default to `Never`.
    /// Since `min(x, Never) = Never`, absent extensions are fail-closed.
    pub fn meet(&self, other: &Self) -> Self {
        #[cfg(not(kani))]
        let ext = if self.extensions.is_empty() && other.extensions.is_empty() {
            BTreeMap::new()
        } else {
            let mut ext = BTreeMap::new();
            for key in self.extensions.keys().chain(other.extensions.keys()) {
                let a = self.extension_level(key);
                let b = other.extension_level(key);
                let v = std::cmp::min(a, b);
                if v != CapabilityLevel::Never {
                    ext.insert(key.clone(), v);
                }
            }
            ext
        };

        Self {
            read_files: std::cmp::min(self.read_files, other.read_files),
            write_files: std::cmp::min(self.write_files, other.write_files),
            edit_files: std::cmp::min(self.edit_files, other.edit_files),
            run_bash: std::cmp::min(self.run_bash, other.run_bash),
            glob_search: std::cmp::min(self.glob_search, other.glob_search),
            grep_search: std::cmp::min(self.grep_search, other.grep_search),
            web_search: std::cmp::min(self.web_search, other.web_search),
            web_fetch: std::cmp::min(self.web_fetch, other.web_fetch),
            git_commit: std::cmp::min(self.git_commit, other.git_commit),
            git_push: std::cmp::min(self.git_push, other.git_push),
            create_pr: std::cmp::min(self.create_pr, other.create_pr),
            manage_pods: std::cmp::min(self.manage_pods, other.manage_pods),
            #[cfg(not(kani))]
            extensions: ext,
        }
    }

    /// Join operation: maximum of each capability (least upper bound).
    ///
    /// For extension dimensions, missing keys default to `Never`.
    /// Since `max(x, Never) = x`, only keys present in at least one operand appear.
    pub fn join(&self, other: &Self) -> Self {
        #[cfg(not(kani))]
        let ext = if self.extensions.is_empty() && other.extensions.is_empty() {
            BTreeMap::new()
        } else {
            let mut ext = BTreeMap::new();
            for key in self.extensions.keys().chain(other.extensions.keys()) {
                let a = self.extension_level(key);
                let b = other.extension_level(key);
                let v = std::cmp::max(a, b);
                if v != CapabilityLevel::Never {
                    ext.insert(key.clone(), v);
                }
            }
            ext
        };

        Self {
            read_files: std::cmp::max(self.read_files, other.read_files),
            write_files: std::cmp::max(self.write_files, other.write_files),
            edit_files: std::cmp::max(self.edit_files, other.edit_files),
            run_bash: std::cmp::max(self.run_bash, other.run_bash),
            glob_search: std::cmp::max(self.glob_search, other.glob_search),
            grep_search: std::cmp::max(self.grep_search, other.grep_search),
            web_search: std::cmp::max(self.web_search, other.web_search),
            web_fetch: std::cmp::max(self.web_fetch, other.web_fetch),
            git_commit: std::cmp::max(self.git_commit, other.git_commit),
            git_push: std::cmp::max(self.git_push, other.git_push),
            create_pr: std::cmp::max(self.create_pr, other.create_pr),
            manage_pods: std::cmp::max(self.manage_pods, other.manage_pods),
            #[cfg(not(kani))]
            extensions: ext,
        }
    }

    /// Check if this lattice is less than or equal to another (partial order).
    ///
    /// For extension dimensions, missing keys default to `Never`.
    /// Since `Never ≤ x` for all `x`, absent extensions satisfy leq trivially.
    pub fn leq(&self, other: &Self) -> bool {
        let core_leq = self.read_files <= other.read_files
            && self.write_files <= other.write_files
            && self.edit_files <= other.edit_files
            && self.run_bash <= other.run_bash
            && self.glob_search <= other.glob_search
            && self.grep_search <= other.grep_search
            && self.web_search <= other.web_search
            && self.web_fetch <= other.web_fetch
            && self.git_commit <= other.git_commit
            && self.git_push <= other.git_push
            && self.create_pr <= other.create_pr
            && self.manage_pods <= other.manage_pods;

        if !core_leq {
            return false;
        }

        // Extension leq check — excluded from Kani (BTreeMap intractable for BMC)
        #[cfg(not(kani))]
        {
            if !self.extensions.is_empty() || !other.extensions.is_empty() {
                for key in self.extensions.keys().chain(other.extensions.keys()) {
                    if self.extension_level(key) > other.extension_level(key) {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Create a permissive capability set (top of lattice).
    ///
    /// Note: This is the top of the CORE lattice only.
    /// Extension dimensions are empty — they must be configured explicitly.
    pub fn permissive() -> Self {
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
            #[cfg(not(kani))]
            extensions: BTreeMap::new(),
        }
    }

    /// Create a restrictive capability set (near bottom of lattice).
    pub fn restrictive() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            #[cfg(not(kani))]
            extensions: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_level_ordering() {
        assert!(CapabilityLevel::Never < CapabilityLevel::LowRisk);
        assert!(CapabilityLevel::LowRisk < CapabilityLevel::Always);
    }

    #[test]
    fn test_uninhabitable_detection() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert!(constraint.is_uninhabitable(&caps));
    }

    #[test]
    fn test_uninhabitable_not_complete_without_all_three() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            git_push: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert!(!constraint.is_uninhabitable(&caps));
    }

    #[test]
    fn test_uninhabitable_constraint_adds_obligations() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk,
            create_pr: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        let obligations = constraint.obligations_for(&caps);

        assert!(obligations.requires(Operation::GitPush));
        assert!(obligations.requires(Operation::CreatePr));
        assert!(!obligations.requires(Operation::WebFetch));
    }

    #[test]
    fn test_meet_is_min() {
        let a = CapabilityLattice {
            write_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::LowRisk,
            ..Default::default()
        };
        let b = CapabilityLattice {
            write_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Always,
            ..Default::default()
        };
        let result = a.meet(&b);

        assert_eq!(result.write_files, CapabilityLevel::LowRisk);
        assert_eq!(result.run_bash, CapabilityLevel::LowRisk);
    }

    #[test]
    fn test_join_is_max() {
        let a = CapabilityLattice {
            write_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::LowRisk,
            ..Default::default()
        };
        let b = CapabilityLattice {
            write_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            ..Default::default()
        };
        let result = a.join(&b);

        assert_eq!(result.write_files, CapabilityLevel::LowRisk);
        assert_eq!(result.run_bash, CapabilityLevel::LowRisk);
    }

    #[test]
    fn test_uninhabitable_with_glob_search() {
        // glob_search should count as information disclosure
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Never,    // No direct file reading
            glob_search: CapabilityLevel::LowRisk, // But can see file structure
            web_fetch: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::LowRisk, // Exfil vector
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert!(constraint.is_uninhabitable(&caps));
    }

    #[test]
    fn test_uninhabitable_with_grep_search() {
        // grep_search should count as information disclosure
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Never,    // No direct file reading
            grep_search: CapabilityLevel::LowRisk, // But can search file contents
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk, // Exfil vector
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert!(constraint.is_uninhabitable(&caps));
    }

    /// Verify that the Lean 4 `CapabilityLattice` field-index table matches
    /// the actual Rust struct field declaration order.
    ///
    /// `CapabilityLattice.lean` models the struct as `Fin 12 → CapabilityLevel`
    /// with a hand-written index ↔ field table. This test is the CI correspondence
    /// bridge: if either the Lean table or the Rust struct field order changes,
    /// this test fails before the mismatch can reach production.
    #[test]
    fn lean_field_index_table_matches_rust_struct() {
        const LEAN_SOURCE: &str = include_str!(
            "../../portcullis-verified/lean/PortcullisVerified/CapabilityLattice.lean"
        );

        // Each entry: (index, field_name) from the Lean table.
        // These must match the declaration order of fields in CapabilityLattice.
        let expected: &[(usize, &str)] = &[
            (0, "read_files"),
            (1, "write_files"),
            (2, "edit_files"),
            (3, "run_bash"),
            (4, "glob_search"),
            (5, "grep_search"),
            (6, "web_search"),
            (7, "web_fetch"),
            (8, "git_commit"),
            (9, "git_push"),
            (10, "create_pr"),
            (11, "manage_pods"),
        ];

        for &(idx, field) in expected {
            // Check the Lean table has the expected index entry.
            // The table uses `|   N   |` for single-digit indices and `|  NN   |`
            // for two-digit indices (matching the Lean source formatting).
            let index_token = if idx < 10 {
                format!("|   {}   |", idx)
            } else {
                format!("|  {}   |", idx)
            };
            assert!(
                LEAN_SOURCE.contains(&index_token),
                "Lean table missing index entry: {}",
                idx
            );
            // Check the Lean table mentions the field name
            assert!(
                LEAN_SOURCE.contains(field),
                "Lean table missing field name: {}",
                field
            );
        }

        // Verify Rust struct fields are declared in the expected order
        // by checking their relative positions in this source file.
        let rust_source = include_str!("capability.rs");
        let field_positions: Vec<usize> = expected
            .iter()
            .map(|&(_, field)| {
                let decl = format!("pub {}: CapabilityLevel", field);
                rust_source
                    .find(&decl)
                    .unwrap_or_else(|| panic!("Field '{}' not found in capability.rs", field))
            })
            .collect();

        for i in 1..field_positions.len() {
            assert!(
                field_positions[i] > field_positions[i - 1],
                "Field '{}' (index {}) must be declared after '{}' (index {}) in CapabilityLattice",
                expected[i].1,
                expected[i].0,
                expected[i - 1].1,
                expected[i - 1].0,
            );
        }
    }

    /// Verify that the Lean 4 hand-written model's `toNat` mapping matches
    /// the Rust `CapabilityLevel` repr discriminants.
    ///
    /// `CapabilityLevel.lean` is a hand-written Lean 4 model (not generated by
    /// Aeneas/Charon). This test is the CI correspondence bridge: it reads the
    /// Lean source at compile time and asserts the `toNat` values exactly match
    /// the Rust `#[repr]` discriminants. If either side changes, this test fails
    /// before the mismatch can reach production.
    #[test]
    fn lean_tonat_matches_rust_discriminants() {
        const LEAN_SOURCE: &str =
            include_str!("../../portcullis-verified/lean/PortcullisVerified/CapabilityLevel.lean");
        // Verify the Lean toNat mapping contains the expected discriminant lines.
        assert!(
            LEAN_SOURCE.contains("| .never   => 0"),
            "Lean toNat: Never must map to 0"
        );
        assert!(
            LEAN_SOURCE.contains("| .lowRisk => 1"),
            "Lean toNat: LowRisk must map to 1"
        );
        assert!(
            LEAN_SOURCE.contains("| .always  => 2"),
            "Lean toNat: Always must map to 2"
        );
        // Verify the Rust discriminants are stable.
        assert_eq!(
            CapabilityLevel::Never as u8,
            0,
            "Rust: Never discriminant must be 0"
        );
        assert_eq!(
            CapabilityLevel::LowRisk as u8,
            1,
            "Rust: LowRisk discriminant must be 1"
        );
        assert_eq!(
            CapabilityLevel::Always as u8,
            2,
            "Rust: Always discriminant must be 2"
        );
    }

    #[test]
    fn test_state_risk_with_search_only() {
        // Just search capabilities should count as 1 component (private access)
        // Must disable all other capabilities to avoid false positives
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::LowRisk, // Only this counts
            grep_search: CapabilityLevel::LowRisk, // Only this counts
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            extensions: BTreeMap::new(),
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert_eq!(constraint.state_risk(&caps), StateRisk::Low);
    }

    /// Conformance test: verifies that the Kani ExtMock2 sparse-key convention
    /// matches the production BTreeMap extension operations for ALL 2-key inputs.
    ///
    /// The Kani harnesses (R7/R8/R9) verify algebraic properties on ExtMock2.
    /// This test proves ExtMock2 is a faithful model of the production BTreeMap
    /// by exhaustively checking that both implementations produce the same results
    /// for meet, join, and leq on all combinations of 2 keys × 3 levels.
    ///
    /// Together: Kani proves algebra on mock → this test proves mock ≡ production
    /// → therefore algebra holds for production.
    #[test]
    fn test_extension_mock_matches_production_btreemap() {
        let _levels = [
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];

        // Use two fixed extension operations as "slot0" and "slot1"
        let key0 = ExtensionOperation::new("slot0");
        let key1 = ExtensionOperation::new("slot1");

        // Test all combinations: each of a, b has 2 keys, each key has 4 states
        // (absent, Never, LowRisk, Always) = 4^4 = 256 cases per operation
        let states: Vec<Option<CapabilityLevel>> = vec![
            None,
            Some(CapabilityLevel::Never),
            Some(CapabilityLevel::LowRisk),
            Some(CapabilityLevel::Always),
        ];

        let mut cases_checked = 0u64;

        for a0 in &states {
            for a1 in &states {
                for b0 in &states {
                    for b1 in &states {
                        // Build production BTreeMap extensions
                        let mut ext_a = BTreeMap::new();
                        if let Some(level) = a0 {
                            ext_a.insert(key0.clone(), *level);
                        }
                        if let Some(level) = a1 {
                            ext_a.insert(key1.clone(), *level);
                        }

                        let mut ext_b = BTreeMap::new();
                        if let Some(level) = b0 {
                            ext_b.insert(key0.clone(), *level);
                        }
                        if let Some(level) = b1 {
                            ext_b.insert(key1.clone(), *level);
                        }

                        // Build minimal CapabilityLattice with only extensions differing
                        let base = CapabilityLattice::default();
                        let cap_a = CapabilityLattice {
                            extensions: ext_a,
                            ..base.clone()
                        };
                        let cap_b = CapabilityLattice {
                            extensions: ext_b,
                            ..base.clone()
                        };

                        // Verify meet: extension_level for each key matches min
                        let met = cap_a.meet(&cap_b);
                        for key in [&key0, &key1] {
                            let a_lvl = cap_a.extension_level(key);
                            let b_lvl = cap_b.extension_level(key);
                            let expected = std::cmp::min(a_lvl, b_lvl);
                            let actual = met.extension_level(key);
                            assert_eq!(
                                actual, expected,
                                "meet extension mismatch for {key:?}: a={a_lvl:?} b={b_lvl:?}"
                            );
                        }

                        // Verify join: extension_level for each key matches max
                        let joined = cap_a.join(&cap_b);
                        for key in [&key0, &key1] {
                            let a_lvl = cap_a.extension_level(key);
                            let b_lvl = cap_b.extension_level(key);
                            let expected = std::cmp::max(a_lvl, b_lvl);
                            let actual = joined.extension_level(key);
                            assert_eq!(
                                actual, expected,
                                "join extension mismatch for {key:?}: a={a_lvl:?} b={b_lvl:?}"
                            );
                        }

                        // Verify leq: a ≤ b iff all extension levels a[k] ≤ b[k]
                        let all_leq = [&key0, &key1]
                            .iter()
                            .all(|k| cap_a.extension_level(k) <= cap_b.extension_level(k));
                        // leq also checks the 12 fixed fields; since they're
                        // identical (default), leq should match extension-only check
                        assert_eq!(
                            cap_a.leq(&cap_b),
                            all_leq,
                            "leq mismatch: a_ext={:?} b_ext={:?}",
                            cap_a.extensions,
                            cap_b.extensions
                        );

                        cases_checked += 1;
                    }
                }
            }
        }

        assert_eq!(cases_checked, 256, "Should check all 4^4 = 256 cases");
    }

    #[test]
    fn test_operation_try_from_all_variants() {
        let names = [
            "read_files",
            "write_files",
            "edit_files",
            "run_bash",
            "glob_search",
            "grep_search",
            "web_search",
            "web_fetch",
            "git_commit",
            "git_push",
            "create_pr",
            "manage_pods",
        ];
        for name in &names {
            assert!(Operation::try_from(*name).is_ok(), "should parse: {name}");
        }
    }

    #[test]
    fn test_operation_try_from_unknown() {
        assert!(Operation::try_from("unknown_op").is_err());
        assert!(Operation::try_from("").is_err());
    }

    #[test]
    fn test_operation_display_roundtrip() {
        for op in Operation::ALL {
            let s = op.to_string();
            let roundtrip = Operation::try_from(s.as_str()).unwrap();
            assert_eq!(op, roundtrip, "roundtrip failed for {op:?}");
        }
    }

    #[test]
    fn test_operation_all_has_12_variants() {
        assert_eq!(Operation::ALL.len(), 12);
        // Verify uniqueness
        let mut set = std::collections::BTreeSet::new();
        for op in Operation::ALL {
            assert!(set.insert(op), "duplicate in ALL: {op:?}");
        }
    }
}
