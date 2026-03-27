//! Capability lattice for tool permissions.

use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Tool permission levels in lattice ordering.
///
/// The ordering is: `Never < LowRisk < Always`
///
/// - `Never`: Never allow
/// - `LowRisk`: Auto-approve for low-risk operations
/// - `Always`: Always auto-approve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CapabilityLevel {
    /// Never allow
    #[default]
    Never = 0,
    /// Auto-approve for low-risk operations
    LowRisk = 1,
    /// Always auto-approve
    Always = 2,
}

impl CapabilityLevel {
    /// Meet (greatest lower bound) = min.
    ///
    /// Isomorphic to `cap_meet` in the Verus model (`portcullis-verified`):
    ///   `cap_meet(a, b) = if a <= b { a } else { b }` = `std::cmp::min(a, b)`.
    /// The Kani harnesses R1/R2/R3 in `portcullis/src/kani.rs` mechanically
    /// verify this isomorphism for all 9 input pairs.
    pub fn meet(self, other: Self) -> Self {
        std::cmp::min(self, other)
    }

    /// Join (least upper bound) = max.
    ///
    /// Isomorphic to `cap_join` in the Verus model (`portcullis-verified`):
    ///   `cap_join(a, b) = if a >= b { a } else { b }` = `std::cmp::max(a, b)`.
    pub fn join(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }

    /// Partial order: `a ≤ b` in the capability lattice.
    ///
    /// Isomorphic to `cap_leq(a, b) = (a <= b)` in the Verus model.
    pub fn leq(self, other: Self) -> bool {
        self <= other
    }
}

impl std::fmt::Display for CapabilityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityLevel::Never => write!(f, "never"),
            CapabilityLevel::LowRisk => write!(f, "low_risk"),
            CapabilityLevel::Always => write!(f, "always"),
        }
    }
}

/// Operations that can be gated by approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Operation {
    /// Read files from disk
    ReadFiles,
    /// Write files to disk
    WriteFiles,
    /// Edit files in place
    EditFiles,
    /// Run shell commands
    RunBash,
    /// Glob search
    GlobSearch,
    /// Grep search
    GrepSearch,
    /// Web search
    WebSearch,
    /// Fetch URLs
    WebFetch,
    /// Git commit
    GitCommit,
    /// Git push
    GitPush,
    /// Create PR
    CreatePr,
    /// Manage sub-pods (create, list, monitor, cancel)
    ManagePods,
}

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

    /// Refinement test: exhaustively verifies that `CapabilityLevel::meet/join/leq`
    /// match the Verus model functions `cap_meet/cap_join/cap_leq` from
    /// `portcullis-verified` for all 9 input pairs.
    ///
    /// This is the conventional-Rust companion to the Kani harnesses R1/R2/R3
    /// in `portcullis/src/kani.rs`. Both verify the same isomorphism; the Kani
    /// harnesses use bounded model checking, this test uses exhaustive enumeration.
    ///
    /// The Verus model defines:
    ///   cap_meet(a, b) = if a <= b { a } else { b }   (= min)
    ///   cap_join(a, b) = if a >= b { a } else { b }   (= max)
    ///   cap_leq(a, b)  = (a <= b)
    #[test]
    fn test_capability_level_refinement_exhaustive() {
        let all = [
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];

        for &a in &all {
            for &b in &all {
                // R1: meet matches Verus cap_meet = min
                let prod_meet = a.meet(b) as u8;
                let model_meet = std::cmp::min(a as u8, b as u8);
                assert_eq!(
                    prod_meet, model_meet,
                    "R1 violation: meet({a:?},{b:?}) as u8 = {prod_meet} != min = {model_meet}"
                );

                // R2: join matches Verus cap_join = max
                let prod_join = a.join(b) as u8;
                let model_join = std::cmp::max(a as u8, b as u8);
                assert_eq!(
                    prod_join, model_join,
                    "R2 violation: join({a:?},{b:?}) as u8 = {prod_join} != max = {model_join}"
                );

                // R3: leq matches Verus cap_leq = (a as u8 <= b as u8)
                let prod_leq = a.leq(b);
                let model_leq = (a as u8) <= (b as u8);
                assert_eq!(
                    prod_leq, model_leq,
                    "R3 violation: leq({a:?},{b:?}) = {prod_leq} != model = {model_leq}"
                );
            }
        }
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
}
