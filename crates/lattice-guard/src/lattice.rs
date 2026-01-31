//! The full product lattice combining all permission dimensions.
//!
//! The `PermissionLattice` is the main type exported by this crate.
//! It combines capabilities, paths, budget, commands, and time into
//! a single coherent permission structure.

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    budget::BudgetLattice,
    capability::{CapabilityLattice, CapabilityLevel, IncompatibilityConstraint},
    command::CommandLattice,
    path::PathLattice,
    time::TimeLattice,
};

/// The full product lattice combining all permission dimensions.
///
/// The lattice enforces a key security invariant: the "lethal trifecta"
/// (private data access + untrusted content + exfiltration) cannot exist
/// at fully autonomous levels. When this combination is detected, the
/// exfiltration vector is demoted to require human approval.
///
/// This is modeled as a guarded lattice: L' = { (caps, guard(caps)) | caps ∈ L }
/// where `guard` demotes exfiltration capabilities when trifecta is detected.
///
/// # Security
///
/// The `trifecta_constraint` field is always enforced upon deserialization,
/// regardless of the value in the serialized data. This prevents attacks
/// where a malicious payload sets `trifecta_constraint: false` to bypass
/// the security invariant.
///
/// # Product Lattice Structure
///
/// ```text
/// PermissionLattice = Caps × Paths × Budget × Commands × Time
///
/// Meet Operation (∧):
/// • Caps: min(level_a, level_b) with trifecta constraint
/// • Paths(allowed): intersection
/// • Paths(blocked): union
/// • Budget: min(cap_a, cap_b)
/// • Commands: intersection(allowed), union(blocked)
/// • Time: max(valid_from), min(valid_until)
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PermissionLattice {
    /// Unique identifier for this permission set
    pub id: Uuid,
    /// Human-readable description
    pub description: String,
    /// ID of the parent permission this was derived from (for audit trail)
    pub derived_from: Option<Uuid>,

    /// Tool capabilities
    pub capabilities: CapabilityLattice,
    /// Path access
    pub paths: PathLattice,
    /// Budget constraints
    pub budget: BudgetLattice,
    /// Command restrictions
    pub commands: CommandLattice,
    /// Temporal bounds
    pub time: TimeLattice,

    /// Trifecta constraint - enforces that lethal combinations require human approval
    ///
    /// # Security
    ///
    /// This field is ALWAYS set to `true` upon deserialization, regardless of
    /// the value in the serialized data. Use `with_trifecta_disabled()` in
    /// code if you explicitly need to disable the constraint (e.g., for testing).
    pub trifecta_constraint: bool,

    /// When this permission was created
    pub created_at: DateTime<Utc>,
    /// Who/what created this permission
    pub created_by: String,
}

/// Raw deserialization helper that preserves all fields.
#[cfg(feature = "serde")]
#[derive(Deserialize)]
struct RawPermissionLattice {
    id: Uuid,
    description: String,
    derived_from: Option<Uuid>,
    capabilities: CapabilityLattice,
    paths: PathLattice,
    budget: BudgetLattice,
    commands: CommandLattice,
    time: TimeLattice,
    #[serde(default = "default_trifecta_constraint")]
    #[allow(dead_code)]
    trifecta_constraint: bool, // Ignored during deserialization
    created_at: DateTime<Utc>,
    created_by: String,
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PermissionLattice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPermissionLattice::deserialize(deserializer)?;

        // Security: Always enforce trifecta constraint regardless of input
        Ok(Self {
            id: raw.id,
            description: raw.description,
            derived_from: raw.derived_from,
            capabilities: raw.capabilities,
            paths: raw.paths,
            budget: raw.budget,
            commands: raw.commands,
            time: raw.time,
            trifecta_constraint: true, // ALWAYS true after deserialization
            created_at: raw.created_at,
            created_by: raw.created_by,
        })
    }
}

fn default_trifecta_constraint() -> bool {
    true
}

impl Default for PermissionLattice {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            description: "Default permission set".to_string(),
            derived_from: None,
            capabilities: CapabilityLattice::default(),
            paths: PathLattice::default(),
            budget: BudgetLattice::default(),
            commands: CommandLattice::default(),
            time: TimeLattice::default(),
            trifecta_constraint: true,
            created_at: Utc::now(),
            created_by: "system".to_string(),
        }
    }
}

/// Error type for delegation failures.
#[derive(Debug, Clone, PartialEq)]
pub enum DelegationError {
    /// Requested permissions exceed parent permissions
    ExceedsParent {
        /// The dimension that was exceeded
        dimension: String,
        /// Details about the violation
        details: String,
    },
    /// Parent permission has expired
    ParentExpired,
    /// Requested budget exceeds available
    InsufficientBudget {
        /// The requested budget amount
        requested: Decimal,
        /// The available budget amount
        available: Decimal,
    },
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExceedsParent { dimension, details } => {
                write!(f, "Requested {} exceeds parent: {}", dimension, details)
            }
            Self::ParentExpired => write!(f, "Parent permission has expired"),
            Self::InsufficientBudget {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient budget: requested ${}, available ${}",
                    requested, available
                )
            }
        }
    }
}

impl std::error::Error for DelegationError {}

impl PermissionLattice {
    /// Create a new permission lattice with the given description.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.into(),
            ..Default::default()
        }
    }

    /// Create a permission lattice with a builder pattern.
    pub fn builder() -> PermissionLatticeBuilder {
        PermissionLatticeBuilder::default()
    }

    /// Create a version with trifecta constraint explicitly disabled.
    ///
    /// # Security Warning
    ///
    /// This method disables the core security invariant of this crate.
    /// Only use this for testing or in fully trusted environments where
    /// the trifecta attack is not a concern.
    ///
    /// In production, the trifecta constraint should always be enabled.
    pub fn with_trifecta_disabled(mut self) -> Self {
        self.trifecta_constraint = false;
        self
    }

    /// Meet operation: greatest lower bound of two permission lattices.
    ///
    /// This always returns permissions ≤ both inputs, with an additional
    /// constraint: if the result would form a "lethal trifecta" (private data
    /// access + untrusted content exposure + exfiltration capability all at
    /// autonomous levels), the exfiltration capabilities are demoted to
    /// require human approval.
    ///
    /// This models the guarded lattice L' = { (caps, guard(caps)) | caps ∈ L }
    /// where trifecta-complete configurations are mapped to their
    /// human-gated counterparts.
    pub fn meet(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.meet(&other.capabilities);

        // Apply trifecta constraint if either input enforces it
        let enforce_trifecta = self.trifecta_constraint || other.trifecta_constraint;
        let capabilities = if enforce_trifecta {
            let constraint = IncompatibilityConstraint::enforcing();
            constraint.apply(&base_caps)
        } else {
            base_caps
        };

        Self {
            id: Uuid::new_v4(),
            description: format!("meet({}, {})", self.description, other.description),
            derived_from: Some(self.id),
            capabilities,
            paths: self.paths.meet(&other.paths),
            budget: self.budget.meet(&other.budget),
            commands: self.commands.meet(&other.commands),
            time: self.time.meet(&other.time),
            trifecta_constraint: enforce_trifecta,
            created_at: Utc::now(),
            created_by: "meet_operation".to_string(),
        }
    }

    /// Join operation: least upper bound of two permission lattices.
    ///
    /// This returns the most permissive combination of both inputs.
    /// The trifecta constraint is applied if BOTH inputs enforce it.
    pub fn join(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.join(&other.capabilities);

        // Apply trifecta constraint only if BOTH inputs enforce it
        let enforce_trifecta = self.trifecta_constraint && other.trifecta_constraint;
        let capabilities = if enforce_trifecta {
            let constraint = IncompatibilityConstraint::enforcing();
            constraint.apply(&base_caps)
        } else {
            base_caps
        };

        Self {
            id: Uuid::new_v4(),
            description: format!("join({}, {})", self.description, other.description),
            derived_from: Some(self.id),
            capabilities,
            paths: self.paths.join(&other.paths),
            budget: self.budget.join(&other.budget),
            commands: self.commands.join(&other.commands),
            time: self.time.join(&other.time),
            trifecta_constraint: enforce_trifecta,
            created_at: Utc::now(),
            created_by: "join_operation".to_string(),
        }
    }

    /// Check if current capabilities would form a lethal trifecta.
    pub fn is_trifecta_vulnerable(&self) -> bool {
        let constraint = IncompatibilityConstraint::enforcing();
        constraint.is_trifecta_complete(&self.capabilities)
    }

    /// Delegate permissions to a subagent.
    ///
    /// The resulting permissions are `self ∧ requested`, ensuring:
    /// - Subagent permissions ≤ parent permissions (monotonic)
    /// - Each dimension is the most restrictive of parent and request
    ///
    /// Returns an error if:
    /// - Parent permission has expired
    /// - Budget exceeds remaining
    pub fn delegate_to(&self, requested: &Self, reason: &str) -> Result<Self, DelegationError> {
        // Check if parent is expired
        if self.time.is_expired() {
            return Err(DelegationError::ParentExpired);
        }

        // Compute meet (automatically enforces monotonicity)
        let result = self.meet(requested);

        // Verify budget doesn't exceed remaining
        if requested.budget.max_cost_usd > self.budget.remaining() {
            return Err(DelegationError::InsufficientBudget {
                requested: requested.budget.max_cost_usd,
                available: self.budget.remaining(),
            });
        }

        // Update metadata
        Ok(Self {
            id: Uuid::new_v4(),
            description: reason.to_string(),
            derived_from: Some(self.id),
            created_at: Utc::now(),
            created_by: "delegation".to_string(),
            ..result
        })
    }

    /// Check if this lattice is less than or equal to another (partial order).
    pub fn leq(&self, other: &Self) -> bool {
        self.capabilities.leq(&other.capabilities)
            && self.paths.leq(&other.paths)
            && self.budget.leq(&other.budget)
            && self.commands.leq(&other.commands)
            && self.time.leq(&other.time)
    }

    /// Check if the permission is currently valid.
    pub fn is_valid(&self) -> bool {
        self.time.is_valid() && self.budget.has_remaining()
    }

    /// Check if the permission has expired.
    pub fn is_expired(&self) -> bool {
        self.time.is_expired()
    }

    /// Compute a checksum for integrity verification.
    #[cfg(feature = "serde")]
    pub fn checksum(&self) -> String {
        let data = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Compute a checksum for integrity verification (non-serde version).
    #[cfg(not(feature = "serde"))]
    pub fn checksum(&self) -> String {
        let data = format!("{:?}", self);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Create a permissive permission set (for trusted contexts).
    pub fn permissive() -> Self {
        Self {
            description: "Permissive permissions".to_string(),
            capabilities: CapabilityLattice::permissive(),
            budget: BudgetLattice {
                max_cost_usd: Decimal::from(10),
                max_input_tokens: 500_000,
                max_output_tokens: 50_000,
                ..Default::default()
            },
            time: TimeLattice::with_duration(Duration::hours(4)),
            ..Default::default()
        }
    }

    /// Create a restrictive permission set (for untrusted contexts).
    pub fn restrictive() -> Self {
        Self {
            description: "Restrictive permissions".to_string(),
            capabilities: CapabilityLattice::restrictive(),
            budget: BudgetLattice {
                max_cost_usd: Decimal::from_str_exact("0.5").unwrap_or(Decimal::ONE),
                max_input_tokens: 10_000,
                max_output_tokens: 1_000,
                ..Default::default()
            },
            time: TimeLattice::with_duration(Duration::minutes(10)),
            ..Default::default()
        }
    }

    /// Create a read-only permission set.
    pub fn read_only() -> Self {
        Self {
            description: "Read-only permissions".to_string(),
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
            },
            commands: CommandLattice::restrictive(),
            ..Default::default()
        }
    }

    /// Create a permission set for code review tasks.
    pub fn code_review() -> Self {
        Self {
            description: "Code review permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::AskFirst,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
            },
            budget: BudgetLattice::with_cost_limit(1.0),
            time: TimeLattice::minutes(30),
            ..Default::default()
        }
    }

    /// Create a permission set for fix/implementation tasks.
    pub fn fix_issue() -> Self {
        Self {
            description: "Fix issue permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::AskFirst,
                web_fetch: CapabilityLevel::AskFirst,
                git_commit: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::AskFirst,
                create_pr: CapabilityLevel::AskFirst,
            },
            paths: PathLattice::block_sensitive(),
            budget: BudgetLattice::with_cost_limit(2.0),
            time: TimeLattice::hours(1),
            ..Default::default()
        }
    }
}

/// Builder for constructing `PermissionLattice` instances.
#[derive(Default)]
pub struct PermissionLatticeBuilder {
    description: Option<String>,
    capabilities: Option<CapabilityLattice>,
    paths: Option<PathLattice>,
    budget: Option<BudgetLattice>,
    commands: Option<CommandLattice>,
    time: Option<TimeLattice>,
    trifecta_constraint: Option<bool>,
    created_by: Option<String>,
}

impl PermissionLatticeBuilder {
    /// Set the description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the capabilities.
    pub fn capabilities(mut self, capabilities: CapabilityLattice) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Set the paths.
    pub fn paths(mut self, paths: PathLattice) -> Self {
        self.paths = Some(paths);
        self
    }

    /// Set the budget.
    pub fn budget(mut self, budget: BudgetLattice) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Set the commands.
    pub fn commands(mut self, commands: CommandLattice) -> Self {
        self.commands = Some(commands);
        self
    }

    /// Set the time bounds.
    pub fn time(mut self, time: TimeLattice) -> Self {
        self.time = Some(time);
        self
    }

    /// Set whether to enforce trifecta constraint.
    ///
    /// # Security Warning
    ///
    /// Setting this to `false` disables the core security invariant.
    /// Only use this for testing or in fully trusted environments.
    pub fn trifecta_constraint(mut self, enforce: bool) -> Self {
        self.trifecta_constraint = Some(enforce);
        self
    }

    /// Set who created this permission.
    pub fn created_by(mut self, creator: impl Into<String>) -> Self {
        self.created_by = Some(creator.into());
        self
    }

    /// Build the permission lattice.
    pub fn build(self) -> PermissionLattice {
        PermissionLattice {
            id: Uuid::new_v4(),
            description: self
                .description
                .unwrap_or_else(|| "Custom permissions".to_string()),
            derived_from: None,
            capabilities: self.capabilities.unwrap_or_default(),
            paths: self.paths.unwrap_or_default(),
            budget: self.budget.unwrap_or_default(),
            commands: self.commands.unwrap_or_default(),
            time: self.time.unwrap_or_default(),
            trifecta_constraint: self.trifecta_constraint.unwrap_or(true),
            created_at: Utc::now(),
            created_by: self.created_by.unwrap_or_else(|| "builder".to_string()),
        }
    }
}

/// Effective permissions for a work assignment.
/// This is the fully computed permission set after delegation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EffectivePermissions {
    /// The computed permission lattice
    pub lattice: PermissionLattice,
    /// Budget reservation ID (if budget was reserved)
    pub budget_reservation_id: Option<Uuid>,
    /// Integrity checksum
    pub checksum: String,
}

impl EffectivePermissions {
    /// Create effective permissions from a lattice.
    pub fn new(lattice: PermissionLattice) -> Self {
        let checksum = lattice.checksum();
        Self {
            lattice,
            budget_reservation_id: None,
            checksum,
        }
    }

    /// Create effective permissions with a budget reservation.
    pub fn with_budget_reservation(mut self, reservation_id: Uuid) -> Self {
        self.budget_reservation_id = Some(reservation_id);
        self
    }

    /// Verify the integrity of the permissions.
    pub fn verify_integrity(&self) -> bool {
        self.lattice.checksum() == self.checksum
    }

    /// Check if permissions have expired.
    pub fn is_expired(&self) -> bool {
        self.lattice.is_expired()
    }

    /// Check if permissions are currently valid.
    pub fn is_valid(&self) -> bool {
        self.verify_integrity() && self.lattice.is_valid()
    }
}

impl Default for EffectivePermissions {
    fn default() -> Self {
        Self::new(PermissionLattice::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meet_is_commutative() {
        let a = PermissionLattice::permissive();
        let b = PermissionLattice::restrictive();

        let ab = a.meet(&b);
        let ba = b.meet(&a);

        assert_eq!(ab.capabilities, ba.capabilities);
        assert_eq!(ab.paths, ba.paths);
        assert_eq!(ab.budget.max_cost_usd, ba.budget.max_cost_usd);
    }

    #[test]
    fn test_meet_is_idempotent() {
        let a = PermissionLattice::default();
        let aa = a.meet(&a);

        assert_eq!(a.capabilities, aa.capabilities);
        assert_eq!(a.paths, aa.paths);
        assert_eq!(a.budget.max_cost_usd, aa.budget.max_cost_usd);
    }

    #[test]
    fn test_meet_is_associative() {
        let a = PermissionLattice::permissive();
        let b = PermissionLattice::default();
        let c = PermissionLattice::restrictive();

        let ab_c = a.meet(&b).meet(&c);
        let a_bc = a.meet(&b.meet(&c));

        assert_eq!(ab_c.capabilities, a_bc.capabilities);
        assert_eq!(ab_c.budget.max_cost_usd, a_bc.budget.max_cost_usd);
    }

    #[test]
    fn test_delegation_monotonicity() {
        let parent = PermissionLattice::permissive();
        let requested = PermissionLattice {
            capabilities: CapabilityLattice {
                write_files: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                ..Default::default()
            },
            ..Default::default()
        };

        let result = parent.delegate_to(&requested, "test delegation").unwrap();

        assert!(result.capabilities.leq(&parent.capabilities));
        assert_eq!(result.capabilities.git_push, CapabilityLevel::AskFirst);
    }

    #[test]
    fn test_delegation_fails_when_parent_expired() {
        let mut parent = PermissionLattice::default();
        parent.time.valid_until = Utc::now() - Duration::hours(1);

        let result = parent.delegate_to(&PermissionLattice::default(), "test");
        assert!(matches!(result, Err(DelegationError::ParentExpired)));
    }

    #[test]
    fn test_effective_permissions_integrity() {
        let perms = EffectivePermissions::new(PermissionLattice::default());
        assert!(perms.verify_integrity());
    }

    #[test]
    fn test_builder_pattern() {
        let lattice = PermissionLattice::builder()
            .description("Test permissions")
            .capabilities(CapabilityLattice::restrictive())
            .budget(BudgetLattice::with_cost_limit(1.0))
            .trifecta_constraint(true)
            .created_by("test")
            .build();

        assert_eq!(lattice.description, "Test permissions");
        assert_eq!(lattice.budget.max_cost_usd, Decimal::ONE);
        assert!(lattice.trifecta_constraint);
    }

    #[test]
    fn test_trifecta_is_enforced_in_meet() {
        let dangerous = PermissionLattice {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::LowRisk,
                create_pr: CapabilityLevel::LowRisk,
                ..Default::default()
            },
            trifecta_constraint: true,
            ..Default::default()
        };

        let combined = dangerous.meet(&dangerous);

        // Exfiltration should be demoted
        assert_eq!(combined.capabilities.git_push, CapabilityLevel::AskFirst);
        assert_eq!(combined.capabilities.create_pr, CapabilityLevel::AskFirst);
    }

    #[test]
    fn test_join_operation() {
        let a = PermissionLattice::restrictive();
        let b = PermissionLattice::permissive();

        let result = a.join(&b);

        // Join should take the more permissive values
        assert!(result.budget.max_cost_usd >= a.budget.max_cost_usd);
        assert!(result.budget.max_cost_usd >= b.budget.max_cost_usd);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_trifecta_bypass_via_deserialization_blocked() {
        // Attempt to bypass trifecta constraint via JSON
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "description": "malicious",
            "derived_from": null,
            "capabilities": {
                "read_files": "always",
                "write_files": "ask_first",
                "edit_files": "ask_first",
                "run_bash": "never",
                "glob_search": "always",
                "grep_search": "always",
                "web_search": "ask_first",
                "web_fetch": "ask_first",
                "git_commit": "ask_first",
                "git_push": "never",
                "create_pr": "ask_first"
            },
            "paths": {"allowed": [], "blocked": [], "work_dir": null},
            "budget": {"max_cost_usd": "5", "consumed_usd": "0", "max_input_tokens": 100000, "max_output_tokens": 10000},
            "commands": {"allowed": [], "blocked": []},
            "time": {"valid_from": "2024-01-01T00:00:00Z", "valid_until": "2025-01-01T00:00:00Z"},
            "trifecta_constraint": false,
            "created_at": "2024-01-01T00:00:00Z",
            "created_by": "attacker"
        }"#;

        let perms: PermissionLattice = serde_json::from_str(json).unwrap();

        // Despite the JSON saying false, the constraint should be enforced
        assert!(
            perms.trifecta_constraint,
            "Trifecta constraint should always be true after deserialization"
        );
    }
}
