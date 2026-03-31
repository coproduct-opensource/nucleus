//! Autonomy ceiling — organizational cap on agent permissions.
//!
//! An `AutonomyCeiling` is a meta-permission that caps the maximum
//! `CapabilityLattice` any agent can receive, regardless of what a human
//! approver grants. Set by the organization/deployment, not by individual
//! users.
//!
//! ## Problem it solves
//!
//! - **Boiling frog**: Human approvers gradually grant broader permissions
//!   over many sessions. The ceiling prevents the accumulated grants from
//!   exceeding organizational policy.
//! - **Confused deputy**: The ceiling prevents destructive operations
//!   (delete, destroy) from being auto-approved even if the user trusts
//!   the agent.
//! - **Trust ratchet**: ~40% of Claude Code users reach full auto-approve
//!   by 750 sessions. The ceiling bounds the maximum damage.
//!
//! ## How it works
//!
//! ```text
//! User's granted permissions
//!         ↓
//!    meet(granted, autonomy_ceiling)
//!         ↓
//! Effective permissions (never exceeds ceiling)
//! ```

use crate::CapabilityLattice;
use crate::CapabilityLevel;

/// Organizational ceiling on agent autonomy.
///
/// Applied via `meet()` with any granted permissions to ensure the
/// effective capabilities never exceed the organizational limit.
#[derive(Debug, Clone)]
pub struct AutonomyCeiling {
    /// Maximum capability levels for any agent in this organization.
    pub capabilities: CapabilityLattice,
    /// Human-readable description of the ceiling's purpose.
    pub description: String,
    /// Operations that ALWAYS require human approval, regardless of
    /// capability level. Even if the capability is `Always`, these
    /// operations are gated by `RequiresApproval`.
    pub always_require_approval: Vec<crate::Operation>,
}

impl AutonomyCeiling {
    /// Apply the ceiling to a set of granted capabilities.
    ///
    /// Returns capabilities that are at most as permissive as the ceiling.
    pub fn apply(&self, granted: &CapabilityLattice) -> CapabilityLattice {
        granted.meet(&self.capabilities)
    }

    /// Check if an operation always requires approval under this ceiling.
    pub fn requires_approval(&self, op: crate::Operation) -> bool {
        self.always_require_approval.contains(&op)
    }

    /// Create a conservative ceiling suitable for production deployments.
    ///
    /// - Read/search: Always (unrestricted)
    /// - Write/edit: LowRisk (auto-approved for safe changes)
    /// - Bash: LowRisk (auto-approved for safe commands)
    /// - Git push/PR: RequiresApproval (always human-gated)
    /// - SpawnAgent: LowRisk
    /// - Web: LowRisk
    pub fn production() -> Self {
        Self {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::LowRisk,
                git_commit: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::LowRisk,
            },
            description: "Production ceiling — no git push, no PR creation".to_string(),
            always_require_approval: vec![crate::Operation::GitPush, crate::Operation::CreatePr],
        }
    }

    /// Create a restrictive ceiling for untrusted/sandbox environments.
    ///
    /// Only read operations are allowed. Everything else is Never.
    pub fn sandbox() -> Self {
        Self {
            capabilities: CapabilityLattice {
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
                spawn_agent: CapabilityLevel::Never,
            },
            description: "Sandbox ceiling — read-only, no execution".to_string(),
            always_require_approval: vec![],
        }
    }

    /// Create an unrestricted ceiling (no organizational cap).
    pub fn unrestricted() -> Self {
        Self {
            capabilities: CapabilityLattice::top(),
            description: "Unrestricted — no organizational ceiling".to_string(),
            always_require_approval: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_ceiling_caps_push() {
        let ceiling = AutonomyCeiling::production();
        let full_perms = CapabilityLattice::top();

        let effective = ceiling.apply(&full_perms);

        // Even with full permissions, push is capped
        assert_eq!(effective.git_push, CapabilityLevel::Never);
        assert_eq!(effective.create_pr, CapabilityLevel::Never);

        // Read is unrestricted
        assert_eq!(effective.read_files, CapabilityLevel::Always);
    }

    #[test]
    fn sandbox_ceiling_blocks_writes() {
        let ceiling = AutonomyCeiling::sandbox();
        let permissive = CapabilityLattice {
            write_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::Always,
            ..CapabilityLattice::top()
        };

        let effective = ceiling.apply(&permissive);

        assert_eq!(effective.write_files, CapabilityLevel::Never);
        assert_eq!(effective.run_bash, CapabilityLevel::Never);
        assert_eq!(effective.read_files, CapabilityLevel::Always);
    }

    #[test]
    fn ceiling_is_monotone() {
        let ceiling = AutonomyCeiling::production();
        let small = CapabilityLattice::bottom();
        let large = CapabilityLattice::top();

        let effective_small = ceiling.apply(&small);
        let effective_large = ceiling.apply(&large);

        // Effective(small) ≤ Effective(large) — monotone
        assert!(effective_small.leq(&effective_large));

        // Both ≤ ceiling
        assert!(effective_small.leq(&ceiling.capabilities));
        assert!(effective_large.leq(&ceiling.capabilities));
    }

    #[test]
    fn unrestricted_ceiling_is_identity() {
        let ceiling = AutonomyCeiling::unrestricted();
        let perms = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            ..CapabilityLattice::bottom()
        };

        let effective = ceiling.apply(&perms);
        assert_eq!(effective, perms);
    }

    #[test]
    fn always_require_approval_check() {
        let ceiling = AutonomyCeiling::production();
        assert!(ceiling.requires_approval(crate::Operation::GitPush));
        assert!(ceiling.requires_approval(crate::Operation::CreatePr));
        assert!(!ceiling.requires_approval(crate::Operation::ReadFiles));
    }
}
