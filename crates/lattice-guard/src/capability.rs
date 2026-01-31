//! Capability lattice for tool permissions.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Tool permission levels in lattice ordering.
///
/// The ordering is: `Never < AskFirst < LowRisk < Always`
///
/// - `Never`: Never allow, even with approval
/// - `AskFirst`: Always ask for human approval first
/// - `LowRisk`: Auto-approve for low-risk operations
/// - `Always`: Always auto-approve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CapabilityLevel {
    /// Never allow, even with approval
    Never = 0,
    /// Always ask for human approval first
    #[default]
    AskFirst = 1,
    /// Auto-approve for low-risk operations
    LowRisk = 2,
    /// Always auto-approve
    Always = 3,
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
}

impl Default for CapabilityLattice {
    fn default() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::AskFirst,
            edit_files: CapabilityLevel::AskFirst,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::AskFirst,
            web_fetch: CapabilityLevel::AskFirst,
            git_commit: CapabilityLevel::AskFirst,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::AskFirst,
        }
    }
}

/// Incompatibility constraint that enforces trifecta prevention.
///
/// The "lethal trifecta" is the combination of:
/// 1. Private data access (read_files)
/// 2. Untrusted content exposure (web_fetch, web_search)
/// 3. Exfiltration vector (git_push, create_pr, run_bash)
///
/// When all three are present at autonomous levels (≥ LowRisk), this constraint
/// demotes the exfiltration vector to `AskFirst`, requiring human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IncompatibilityConstraint {
    /// Whether to enforce trifecta prevention
    pub enforce_trifecta: bool,
}

impl IncompatibilityConstraint {
    /// Create an enforcing constraint.
    pub fn enforcing() -> Self {
        Self {
            enforce_trifecta: true,
        }
    }

    /// Check if capabilities form a complete trifecta at autonomous levels.
    ///
    /// Returns true if:
    /// 1. Private data access (read_files) >= LowRisk
    /// 2. Untrusted content exposure (web_fetch OR web_search) >= LowRisk
    /// 3. Exfiltration vector (git_push OR create_pr OR run_bash) >= LowRisk
    pub fn is_trifecta_complete(&self, caps: &CapabilityLattice) -> bool {
        if !self.enforce_trifecta {
            return false;
        }

        let has_private_access = caps.read_files >= CapabilityLevel::LowRisk;
        let has_untrusted = caps.web_fetch >= CapabilityLevel::LowRisk
            || caps.web_search >= CapabilityLevel::LowRisk;
        let has_exfil = caps.git_push >= CapabilityLevel::LowRisk
            || caps.create_pr >= CapabilityLevel::LowRisk
            || caps.run_bash >= CapabilityLevel::LowRisk;

        has_private_access && has_untrusted && has_exfil
    }

    /// Apply trifecta constraint by demoting exfiltration to AskFirst.
    ///
    /// This is the minimal intervention that breaks the attack chain while
    /// preserving other capabilities.
    pub fn apply(&self, caps: &CapabilityLattice) -> CapabilityLattice {
        if !self.is_trifecta_complete(caps) {
            return caps.clone();
        }

        let mut result = caps.clone();
        if result.git_push >= CapabilityLevel::LowRisk {
            result.git_push = CapabilityLevel::AskFirst;
        }
        if result.create_pr >= CapabilityLevel::LowRisk {
            result.create_pr = CapabilityLevel::AskFirst;
        }
        if result.run_bash >= CapabilityLevel::LowRisk {
            result.run_bash = CapabilityLevel::AskFirst;
        }
        result
    }
}

impl CapabilityLattice {
    /// Meet operation: minimum of each capability.
    pub fn meet(&self, other: &Self) -> Self {
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
        }
    }

    /// Join operation: maximum of each capability (least upper bound).
    pub fn join(&self, other: &Self) -> Self {
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
        }
    }

    /// Meet operation with trifecta constraint enforcement.
    pub fn meet_constrained(&self, other: &Self, constraint: &IncompatibilityConstraint) -> Self {
        let base = self.meet(other);
        constraint.apply(&base)
    }

    /// Check if this lattice is less than or equal to another (partial order).
    pub fn leq(&self, other: &Self) -> bool {
        self.read_files <= other.read_files
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
    }

    /// Create a permissive capability set (top of lattice).
    pub fn permissive() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::LowRisk,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            git_push: CapabilityLevel::AskFirst,
            create_pr: CapabilityLevel::Always,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_level_ordering() {
        assert!(CapabilityLevel::Never < CapabilityLevel::AskFirst);
        assert!(CapabilityLevel::AskFirst < CapabilityLevel::LowRisk);
        assert!(CapabilityLevel::LowRisk < CapabilityLevel::Always);
    }

    #[test]
    fn test_trifecta_detection() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert!(constraint.is_trifecta_complete(&caps));
    }

    #[test]
    fn test_trifecta_not_complete_without_all_three() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            git_push: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        assert!(!constraint.is_trifecta_complete(&caps));
    }

    #[test]
    fn test_trifecta_constraint_demotes_exfiltration() {
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk,
            create_pr: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let constraint = IncompatibilityConstraint::enforcing();
        let result = constraint.apply(&caps);

        assert_eq!(result.git_push, CapabilityLevel::AskFirst);
        assert_eq!(result.create_pr, CapabilityLevel::AskFirst);
        assert_eq!(result.read_files, CapabilityLevel::Always);
        assert_eq!(result.web_fetch, CapabilityLevel::LowRisk);
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
}
