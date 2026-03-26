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
    capability::{
        CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations, Operation,
    },
    command::{ArgPattern, CommandLattice, CommandPattern},
    frame::Lattice,
    isolation::IsolationLattice,
    path::PathLattice,
    time::TimeLattice,
};

/// The full product lattice combining all permission dimensions.
///
/// The lattice enforces a key security invariant: the "uninhabitable_state"
/// (private data access + untrusted content + exfiltration) cannot exist
/// at fully autonomous levels. When this combination is detected, the
/// exfiltration vector gains approval obligations.
///
/// This is modeled as a guarded lattice: L' = { (caps, obligations(caps)) | caps ∈ L }
/// where `guard` demotes exfiltration capabilities when uninhabitable_state is detected.
///
/// # Security
///
/// The `uninhabitable_constraint` field is always enforced upon deserialization,
/// regardless of the value in the serialized data. This prevents attacks
/// where a malicious payload sets `uninhabitable_constraint: false` to bypass
/// the security invariant.
///
/// # Product Lattice Structure
///
/// ```text
/// PermissionLattice = Caps × Obligations × Paths × Budget × Commands × Time
///
/// Meet Operation (∧):
/// • Caps: min(level_a, level_b)
/// • Obligations: union with uninhabitable_state constraint
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

    /// Tool capabilities (autonomous)
    pub capabilities: CapabilityLattice,
    /// Approval obligations for gated operations
    pub obligations: Obligations,
    /// Path access
    pub paths: PathLattice,
    /// Budget constraints
    pub budget: BudgetLattice,
    /// Command restrictions
    pub commands: CommandLattice,
    /// Temporal bounds
    pub time: TimeLattice,

    ///  UninhabitableState constraint - enforces that lethal combinations require approval
    ///
    /// # Security
    ///
    /// This field is ALWAYS set to `true` upon deserialization, regardless of
    /// the value in the serialized data. Use `with_uninhabitable_disabled()` in
    /// code if you explicitly need to disable the constraint (e.g., for testing).
    ///
    /// Uninhabitable state constraint enforcement.
    ///
    /// **Private in production builds.** Use [`is_uninhabitable_enforced()`]
    /// to read, [`as_ceiling()`] for delegation ceilings.
    ///
    /// With the `testing` feature, the field is `pub` for adversarial tests
    /// that need to verify constraint bypass is detected.
    #[cfg(not(feature = "testing"))]
    pub(crate) uninhabitable_constraint: bool,
    /// See non-testing docs. Public only with `testing` feature for adversarial tests.
    #[cfg(feature = "testing")]
    pub uninhabitable_constraint: bool,

    /// Minimum isolation level required to use this policy.
    ///
    /// When set, the kernel will deny all operations if the runtime isolation
    /// level is weaker than this minimum. This provides defense-in-depth:
    /// security-critical policies can demand strong isolation guarantees.
    ///
    /// `None` means no minimum required (equivalent to localhost).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minimum_isolation: Option<IsolationLattice>,

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
    #[serde(default)]
    obligations: Obligations,
    paths: PathLattice,
    budget: BudgetLattice,
    commands: CommandLattice,
    time: TimeLattice,
    #[serde(
        default = "default_uninhabitable_constraint",
        alias = "trifecta_constraint"
    )]
    #[allow(dead_code)]
    uninhabitable_constraint: bool, // Ignored during deserialization
    #[serde(default)]
    minimum_isolation: Option<IsolationLattice>,
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

        // Security: Always enforce uninhabitable_state constraint regardless of input
        let lattice = Self {
            id: raw.id,
            description: raw.description,
            derived_from: raw.derived_from,
            capabilities: raw.capabilities,
            obligations: raw.obligations,
            paths: raw.paths,
            budget: raw.budget,
            commands: raw.commands,
            time: raw.time,
            uninhabitable_constraint: true, // ALWAYS true after deserialization
            minimum_isolation: raw.minimum_isolation,
            created_at: raw.created_at,
            created_by: raw.created_by,
        };

        Ok(lattice.normalize())
    }
}

fn default_uninhabitable_constraint() -> bool {
    true
}

impl Default for PermissionLattice {
    fn default() -> Self {
        let mut obligations = Obligations::default();
        obligations.insert(Operation::WriteFiles);
        obligations.insert(Operation::EditFiles);
        obligations.insert(Operation::WebSearch);
        obligations.insert(Operation::WebFetch);
        obligations.insert(Operation::GitCommit);
        obligations.insert(Operation::CreatePr);

        let lattice = Self {
            id: Uuid::new_v4(),
            description: "Default permission set".to_string(),
            derived_from: None,
            capabilities: CapabilityLattice::default(),
            obligations,
            paths: PathLattice::default(),
            budget: BudgetLattice::default(),
            commands: CommandLattice::default(),
            time: TimeLattice::default(),
            uninhabitable_constraint: true,
            minimum_isolation: None,
            created_at: Utc::now(),
            created_by: "system".to_string(),
        };

        lattice.normalize()
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
    /// Whether the uninhabitable state constraint is enforced.
    ///
    /// When `true` (the default and strongly recommended), lethal capability
    /// combinations (private data + untrusted content + exfiltration) trigger
    /// mandatory approval obligations.
    pub fn is_uninhabitable_enforced(&self) -> bool {
        self.uninhabitable_constraint
    }

    /// Create a new permission lattice with the given description.
    pub fn new(description: impl Into<String>) -> Self {
        let lattice = Self {
            id: Uuid::new_v4(),
            description: description.into(),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission lattice with a builder pattern.
    pub fn builder() -> PermissionLatticeBuilder {
        PermissionLatticeBuilder::default()
    }

    /// Convert to a delegation ceiling.
    ///
    /// Disables the uninhabitable state constraint on this lattice. Use this
    /// when the lattice represents a **capability ceiling** for delegation,
    /// not a directly enforced policy. The delegated (child) lattice will
    /// have its own constraint enforcement via `normalize()`.
    ///
    /// This is the only production-available way to disable the constraint.
    /// The intent is explicit: "this is a ceiling, not a policy."
    pub fn as_ceiling(mut self) -> Self {
        self.uninhabitable_constraint = false;
        self
    }

    /// Create a version with uninhabitable_state constraint explicitly disabled.
    ///
    /// # Security Warning
    ///
    /// This method disables the core security invariant of this crate.
    /// Only available with the `testing` feature enabled.
    ///
    /// **DO NOT** use in production code. Use `as_ceiling()` if you need
    /// a constraint-free lattice for delegation ceilings.
    #[cfg(feature = "testing")]
    pub fn with_uninhabitable_disabled(mut self) -> Self {
        self.uninhabitable_constraint = false;
        self
    }

    /// Apply the nucleus (ν) to normalize this permission lattice.
    ///
    /// If uninhabitable_state enforcement is enabled, this adds approval obligations to
    /// break any uninhabitable_state configuration.
    pub fn normalize(mut self) -> Self {
        if self.uninhabitable_constraint {
            let constraint = IncompatibilityConstraint::enforcing();
            let required = constraint.obligations_for(&self.capabilities);
            self.obligations = self.obligations.union(&required);
        }
        self
    }

    /// Meet operation: greatest lower bound of two permission lattices.
    ///
    /// This always returns permissions ≤ both inputs, with an additional
    /// constraint: if the result would form a "uninhabitable_state" (private data
    /// access + untrusted content exposure + exfiltration capability all at
    /// autonomous levels), approval obligations are added.
    ///
    /// This models the guarded lattice L' = { (caps, guard(caps)) | caps ∈ L }
    /// where uninhabitable configurations are mapped to their
    /// human-gated counterparts.
    pub fn meet(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.meet(&other.capabilities);

        let base_obligations = self.obligations.union(&other.obligations);

        // Apply uninhabitable_state constraint if either input enforces it
        let enforce_uninhabitable = self.uninhabitable_constraint || other.uninhabitable_constraint;
        let obligations = if enforce_uninhabitable {
            let constraint = IncompatibilityConstraint::enforcing();
            base_obligations.union(&constraint.obligations_for(&base_caps))
        } else {
            base_obligations
        };

        // Minimum isolation: meet takes the join (stronger requirement).
        // If either policy demands stronger isolation, the combined policy demands it.
        let minimum_isolation = match (&self.minimum_isolation, &other.minimum_isolation) {
            (Some(a), Some(b)) => Some(a.join(b)),
            (Some(a), None) => Some(*a),
            (None, Some(b)) => Some(*b),
            (None, None) => None,
        };

        Self {
            id: Uuid::new_v4(),
            description: format!("meet({}, {})", self.description, other.description),
            derived_from: Some(self.id),
            capabilities: base_caps,
            obligations,
            paths: self.paths.meet(&other.paths),
            budget: self.budget.meet(&other.budget),
            commands: self.commands.meet(&other.commands),
            time: self.time.meet(&other.time),
            uninhabitable_constraint: enforce_uninhabitable,
            minimum_isolation,
            created_at: Utc::now(),
            created_by: "meet_operation".to_string(),
        }
    }

    /// Join operation: least upper bound of two permission lattices.
    ///
    /// This returns the most permissive combination of both inputs.
    /// The uninhabitable_state constraint is applied if BOTH inputs enforce it.
    pub fn join(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.join(&other.capabilities);

        let base_obligations = self.obligations.intersection(&other.obligations);

        // Apply uninhabitable_state constraint only if BOTH inputs enforce it
        let enforce_uninhabitable = self.uninhabitable_constraint && other.uninhabitable_constraint;
        let obligations = if enforce_uninhabitable {
            let constraint = IncompatibilityConstraint::enforcing();
            base_obligations.union(&constraint.obligations_for(&base_caps))
        } else {
            base_obligations
        };

        // Minimum isolation: join takes the meet (weaker requirement).
        let minimum_isolation = match (&self.minimum_isolation, &other.minimum_isolation) {
            (Some(a), Some(b)) => {
                let result = a.meet(b);
                if result == IsolationLattice::localhost() {
                    None
                } else {
                    Some(result)
                }
            }
            // Join is least upper bound — if one side has no requirement, result has none
            (_, _) => None,
        };

        Self {
            id: Uuid::new_v4(),
            description: format!("join({}, {})", self.description, other.description),
            derived_from: Some(self.id),
            capabilities: base_caps,
            obligations,
            paths: self.paths.join(&other.paths),
            budget: self.budget.join(&other.budget),
            commands: self.commands.join(&other.commands),
            time: self.time.join(&other.time),
            uninhabitable_constraint: enforce_uninhabitable,
            minimum_isolation,
            created_at: Utc::now(),
            created_by: "join_operation".to_string(),
        }
    }

    /// Check if current capabilities would form a uninhabitable_state.
    pub fn is_uninhabitable_vulnerable(&self) -> bool {
        let constraint = IncompatibilityConstraint::enforcing();
        constraint.is_uninhabitable(&self.capabilities)
    }

    /// Check if an operation requires approval.
    pub fn requires_approval(&self, op: Operation) -> bool {
        self.obligations.requires(op)
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
    ///
    /// `self ≤ other` means self is at most as permissive as other.
    /// For minimum_isolation: a higher minimum means more constrained,
    /// so self ≤ other requires self's minimum ≥ other's minimum.
    pub fn leq(&self, other: &Self) -> bool {
        let isolation_leq = match (&self.minimum_isolation, &other.minimum_isolation) {
            // self has requirement, other doesn't → self is more constrained → ok
            (Some(_), None) => true,
            // self has no requirement, other does → self is less constrained → not leq
            (None, Some(_)) => false,
            // both have requirements → self's minimum must be ≥ other's minimum
            (Some(a), Some(b)) => b.leq(a),
            // neither has requirement → equal
            (None, None) => true,
        };

        isolation_leq
            && self.capabilities.leq(&other.capabilities)
            && self.obligations.leq(&other.obligations)
            && self.paths.leq(&other.paths)
            && self.budget.leq(&other.budget)
            && self.commands.leq(&other.commands)
            && self.time.leq(&other.time)
    }

    /// Get the effective minimum isolation (defaults to localhost if unset).
    pub fn effective_minimum_isolation(&self) -> IsolationLattice {
        self.minimum_isolation
            .unwrap_or_else(IsolationLattice::localhost)
    }

    /// Set the minimum isolation level required to use this policy.
    pub fn with_minimum_isolation(mut self, isolation: IsolationLattice) -> Self {
        self.minimum_isolation = Some(isolation);
        self
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
        let lattice = Self {
            description: "Permissive permissions".to_string(),
            capabilities: CapabilityLattice::permissive(),
            obligations: Obligations::default(),
            budget: BudgetLattice {
                max_cost_usd: Decimal::from(10),
                max_input_tokens: 500_000,
                max_output_tokens: 50_000,
                ..Default::default()
            },
            time: TimeLattice::with_duration(Duration::hours(4)),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a restrictive permission set (for untrusted contexts).
    pub fn restrictive() -> Self {
        let lattice = Self {
            description: "Restrictive permissions".to_string(),
            capabilities: CapabilityLattice::restrictive(),
            obligations: Obligations::default(),
            budget: BudgetLattice {
                max_cost_usd: Decimal::from_str_exact("0.5").unwrap_or(Decimal::ONE),
                max_input_tokens: 10_000,
                max_output_tokens: 1_000,
                ..Default::default()
            },
            time: TimeLattice::with_duration(Duration::minutes(10)),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a read-only permission set.
    pub fn read_only() -> Self {
        let lattice = Self {
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
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            commands: CommandLattice::restrictive(),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a filesystem read-only permission set with sensitive paths blocked.
    pub fn filesystem_readonly() -> Self {
        let mut lattice = Self::read_only();
        lattice.description = "Filesystem read-only permissions".to_string();
        lattice.paths = PathLattice::block_sensitive();
        lattice.normalize()
    }

    /// Create a network-only permission set (no filesystem or execution).
    pub fn network_only() -> Self {
        let lattice = Self {
            description: "Network-only permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Never,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Never,
                grep_search: CapabilityLevel::Never,
                web_search: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::LowRisk,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            budget: BudgetLattice::with_cost_limit(1.0),
            time: TimeLattice::minutes(30),
            commands: CommandLattice::restrictive(),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a web research permission set (read + web, no writes or exec).
    pub fn web_research() -> Self {
        let lattice = Self {
            description: "Web research permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::LowRisk,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::LowRisk,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            budget: BudgetLattice::with_cost_limit(1.5),
            time: TimeLattice::minutes(45),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for code review tasks.
    pub fn code_review() -> Self {
        let mut obligations = Obligations::default();
        obligations.insert(Operation::WebSearch);

        let lattice = Self {
            description: "Code review permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations,
            budget: BudgetLattice::with_cost_limit(1.0),
            time: TimeLattice::minutes(30),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create an edit-only permission set (no exec, no web).
    pub fn edit_only() -> Self {
        let lattice = Self {
            description: "Edit-only permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
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
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            paths: PathLattice::block_sensitive(),
            budget: BudgetLattice::with_cost_limit(1.5),
            time: TimeLattice::minutes(45),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a local dev permission set (shell + edits, no web).
    pub fn local_dev() -> Self {
        let lattice = Self {
            description: "Local dev permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            paths: PathLattice::block_sensitive(),
            commands: CommandLattice::permissive(),
            budget: BudgetLattice::with_cost_limit(3.0),
            time: TimeLattice::hours(2),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for fix/implementation tasks.
    pub fn fix_issue() -> Self {
        let mut obligations = Obligations::default();
        obligations.insert(Operation::WebSearch);
        obligations.insert(Operation::WebFetch);
        obligations.insert(Operation::GitCommit);
        obligations.insert(Operation::GitPush);
        obligations.insert(Operation::CreatePr);

        let lattice = Self {
            description: "Fix issue permissions".to_string(),
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
                git_push: CapabilityLevel::LowRisk,
                create_pr: CapabilityLevel::LowRisk,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations,
            paths: PathLattice::block_sensitive(),
            budget: BudgetLattice::with_cost_limit(2.0),
            time: TimeLattice::hours(1),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for safe PR fixing in CI.
    ///
    /// This is the "killer workflow" profile for GitHub Actions adoption:
    /// - Read all files, write/edit/test with LowRisk
    /// - Commit locally (git_write=LowRisk)
    /// - **Cannot push or create PRs** — the CI script does that
    /// - Web fetch allowed (docs lookup), but no broad web search
    ///
    /// ** UninhabitableState Analysis**: private data (read=Always) + untrusted content
    /// (web_fetch=LowRisk) present, but exfiltration absent (git_push=Never,
    /// create_pr=Never, run_bash=LowRisk but constrained). Two of three
    /// components → no approval escalation needed.
    ///
    /// The key security invariant: the agent can fix code and commit, but
    /// only the trusted CI wrapper script can push the branch and open a PR.
    pub fn safe_pr_fixer() -> Self {
        let lattice = Self {
            description: "Safe PR fixer permissions (no push, no PR creation)".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::LowRisk,
                git_commit: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            paths: PathLattice::block_sensitive(),
            commands: CommandLattice::permissive(),
            budget: BudgetLattice::with_cost_limit(5.0),
            time: TimeLattice::hours(2),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a release/publish permission set (approvals on exfil).
    pub fn release() -> Self {
        let mut obligations = Obligations::default();
        obligations.insert(Operation::GitPush);
        obligations.insert(Operation::CreatePr);

        let lattice = Self {
            description: "Release permissions".to_string(),
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
                git_push: CapabilityLevel::LowRisk,
                create_pr: CapabilityLevel::LowRisk,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations,
            paths: PathLattice::block_sensitive(),
            commands: CommandLattice::permissive(),
            budget: BudgetLattice::with_cost_limit(5.0),
            time: TimeLattice::hours(2),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a database client permission set (CLI access only).
    pub fn database_client() -> Self {
        let mut commands = CommandLattice::permissive();
        for program in ["psql", "mysql", "sqlite3", "redis-cli", "mongosh"] {
            commands.allow_rule(CommandPattern {
                program: program.to_string(),
                args: vec![ArgPattern::AnyRemaining],
            });
        }

        let lattice = Self {
            description: "Database client permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Never,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Never,
                grep_search: CapabilityLevel::Never,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            commands,
            budget: BudgetLattice::with_cost_limit(2.0),
            time: TimeLattice::hours(1),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a demo-friendly permission set for tool-proxy integrations.
    ///
    /// This is permissive enough for live demos but still enforces approvals
    /// on sensitive operations (writes, edits, and uninhabitable_state exfil paths).
    pub fn demo() -> Self {
        let mut obligations = Obligations::default();
        obligations.insert(Operation::WriteFiles);
        obligations.insert(Operation::EditFiles);

        let mut commands = CommandLattice::permissive();
        for program in [
            "bash",
            "sh",
            "zsh",
            "fish",
            "pwsh",
            "powershell",
            "python",
            "python3",
            "node",
            "ruby",
            "perl",
        ] {
            commands.block_rule(CommandPattern {
                program: program.to_string(),
                args: vec![ArgPattern::AnyRemaining],
            });
        }

        let lattice = Self {
            description: "Demo permissions".to_string(),
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
                git_push: CapabilityLevel::LowRisk,
                create_pr: CapabilityLevel::LowRisk,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations,
            commands,
            paths: PathLattice::block_sensitive(),
            budget: BudgetLattice::with_cost_limit(2.0),
            time: TimeLattice::minutes(45),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for PR review tasks.
    ///
    /// This profile is designed for automated PR review agents that:
    /// - Read files to analyze code changes
    /// - Access web (GitHub API) to fetch PR details and post comments
    /// - Cannot write files, execute bash, or push changes
    ///
    /// ** UninhabitableState Analysis**: No exfiltration capability (git_push=Never, create_pr=Never,
    /// run_bash=Never), so uninhabitable_state protection is not triggered.
    ///
    /// Note: run_bash is disabled because it's an exfiltration vector. The agent
    /// can still analyze diffs using file reads and web fetch for GitHub API.
    pub fn pr_review() -> Self {
        let lattice = Self {
            description: "PR review permissions".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::LowRisk,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            paths: PathLattice::block_sensitive(),
            budget: BudgetLattice::with_cost_limit(1.5),
            time: TimeLattice::minutes(30),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for code generation tasks.
    ///
    /// This profile is designed for isolated code generation agents that:
    /// - Read and write files to implement features
    /// - Run bash commands for testing/building
    /// - Commit changes locally
    /// - Have NO network access (fully isolated)
    ///
    /// ** UninhabitableState Analysis**: No untrusted content exposure (web_fetch=Never, web_search=Never),
    /// so uninhabitable_state protection is not triggered despite having write capabilities.
    pub fn codegen() -> Self {
        let lattice = Self {
            description: "Code generation permissions (network-isolated)".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            paths: PathLattice::block_sensitive(),
            commands: CommandLattice::permissive(),
            budget: BudgetLattice::with_cost_limit(5.0),
            time: TimeLattice::hours(1),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for PR approval tasks.
    ///
    /// This profile is designed for automated PR approval agents that:
    /// - Read files to verify implementation
    /// - Access web (GitHub API) to check CI status
    /// - Push/merge approved PRs
    ///
    /// ** UninhabitableState Analysis**: Has all three components (read + web + git_push),
    /// so git_push will require approval. This is intentional - approval should
    /// be gated on CI status verification.
    pub fn pr_approve() -> Self {
        let lattice = Self {
            description: "PR approval permissions (CI-gated)".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::LowRisk,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::LowRisk,
                web_fetch: CapabilityLevel::LowRisk,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::LowRisk,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            paths: PathLattice::block_sensitive(),
            budget: BudgetLattice::with_cost_limit(1.0),
            time: TimeLattice::minutes(15),
            ..Default::default()
        };

        lattice.normalize()
    }

    /// Create a permission set for orchestrator agents (pod management only).
    ///
    /// This profile is designed for meta-agents whose sole capability is
    /// spawning and monitoring other nucleus pods. The orchestrator cannot
    /// write files, run commands, or access the web directly.
    ///
    /// ** UninhabitableState Analysis**: private access (read/glob/grep) present,
    /// untrusted content absent (web_*: Never), exfiltration absent
    /// (git/bash: Never). Only 1/3 components → `StateRisk::Low`.
    /// No approval obligations required.
    ///
    /// **Delegation**: The orchestrator's own permissions are narrow, but it
    /// delegates to sub-pods via a separate delegation ceiling (configured
    /// by the orchestrator's creator). Sub-pod permissions are bounded by
    /// `delegation_ceiling.delegate_to(requested)`.
    pub fn orchestrator() -> Self {
        let lattice = Self {
            description: "Orchestrator permissions (pod management only)".to_string(),
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::LowRisk,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::LowRisk,
                grep_search: CapabilityLevel::LowRisk,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Always,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            budget: BudgetLattice::with_cost_limit(50.0),
            time: TimeLattice::hours(4),
            commands: CommandLattice::restrictive(),
            ..Default::default()
        };

        lattice.normalize()
    }
}

/// Builder for constructing `PermissionLattice` instances.
#[derive(Default)]
pub struct PermissionLatticeBuilder {
    description: Option<String>,
    capabilities: Option<CapabilityLattice>,
    obligations: Option<Obligations>,
    paths: Option<PathLattice>,
    budget: Option<BudgetLattice>,
    commands: Option<CommandLattice>,
    time: Option<TimeLattice>,
    uninhabitable_constraint: Option<bool>,
    minimum_isolation: Option<IsolationLattice>,
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

    /// Set approval obligations.
    pub fn obligations(mut self, obligations: Obligations) -> Self {
        self.obligations = Some(obligations);
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

    /// Set whether to enforce uninhabitable_state constraint.
    ///
    /// # Security Warning
    ///
    /// Setting this to `false` disables the core security invariant.
    /// Only use this for testing or in fully trusted environments.
    pub fn uninhabitable_constraint(mut self, enforce: bool) -> Self {
        self.uninhabitable_constraint = Some(enforce);
        self
    }

    /// Set the minimum isolation required to use this policy.
    pub fn minimum_isolation(mut self, isolation: IsolationLattice) -> Self {
        self.minimum_isolation = Some(isolation);
        self
    }

    /// Set who created this permission.
    pub fn created_by(mut self, creator: impl Into<String>) -> Self {
        self.created_by = Some(creator.into());
        self
    }

    /// Build the permission lattice.
    pub fn build(self) -> PermissionLattice {
        let lattice = PermissionLattice {
            id: Uuid::new_v4(),
            description: self
                .description
                .unwrap_or_else(|| "Custom permissions".to_string()),
            derived_from: None,
            capabilities: self.capabilities.unwrap_or_default(),
            obligations: self.obligations.unwrap_or_default(),
            paths: self.paths.unwrap_or_default(),
            budget: self.budget.unwrap_or_default(),
            commands: self.commands.unwrap_or_default(),
            time: self.time.unwrap_or_default(),
            uninhabitable_constraint: self.uninhabitable_constraint.unwrap_or(true),
            minimum_isolation: self.minimum_isolation,
            created_at: Utc::now(),
            created_by: self.created_by.unwrap_or_else(|| "builder".to_string()),
        };

        lattice.normalize()
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
        let lattice = lattice.normalize();
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
            obligations: Obligations::default(),
            ..Default::default()
        };

        let result = parent.delegate_to(&requested, "test delegation").unwrap();

        assert!(result.capabilities.leq(&parent.capabilities));
        assert!(result.requires_approval(Operation::GitPush));
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
            .uninhabitable_constraint(true)
            .created_by("test")
            .build();

        assert_eq!(lattice.description, "Test permissions");
        assert_eq!(lattice.budget.max_cost_usd, Decimal::ONE);
        assert!(lattice.uninhabitable_constraint);
    }

    #[test]
    fn test_uninhabitable_is_enforced_in_meet() {
        let dangerous = PermissionLattice {
            capabilities: CapabilityLattice {
                read_files: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::LowRisk,
                create_pr: CapabilityLevel::LowRisk,
                ..Default::default()
            },
            obligations: Obligations::default(),
            uninhabitable_constraint: true,
            ..Default::default()
        };

        let combined = dangerous.meet(&dangerous);

        // Exfiltration should require approval
        assert!(combined.requires_approval(Operation::GitPush));
        assert!(combined.requires_approval(Operation::CreatePr));
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
    fn test_uninhabitable_bypass_via_deserialization_blocked() {
        // Attempt to bypass uninhabitable_state constraint via JSON
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "description": "malicious",
            "derived_from": null,
            "capabilities": {
                "read_files": "always",
                "write_files": "low_risk",
                "edit_files": "low_risk",
                "run_bash": "never",
                "glob_search": "always",
                "grep_search": "always",
                "web_search": "low_risk",
                "web_fetch": "low_risk",
                "git_commit": "low_risk",
                "git_push": "never",
                "create_pr": "low_risk"
            },
            "obligations": {"approvals": []},
            "paths": {"allowed": [], "blocked": [], "work_dir": null},
            "budget": {"max_cost_usd": "5", "consumed_usd": "0", "max_input_tokens": 100000, "max_output_tokens": 10000},
            "commands": {"allowed": [], "blocked": []},
            "time": {"valid_from": "2024-01-01T00:00:00Z", "valid_until": "2025-01-01T00:00:00Z"},
            "uninhabitable_constraint": false,
            "created_at": "2024-01-01T00:00:00Z",
            "created_by": "attacker"
        }"#;

        let perms: PermissionLattice = serde_json::from_str(json).unwrap();

        // Despite the JSON saying false, the constraint should be enforced
        assert!(
            perms.uninhabitable_constraint,
            " UninhabitableState constraint should always be true after deserialization"
        );
    }

    // ========================================================================
    // Workflow Profile Tests (pr_review, codegen, pr_approve)
    // ========================================================================

    #[test]
    fn test_pr_review_no_uninhabitable() {
        // pr_review has read + web access, but NO exfiltration capability
        // (git_push=Never, create_pr=Never, run_bash=Never), so uninhabitable_state is not complete
        let perms = PermissionLattice::pr_review();

        // Verify capabilities match expected profile
        assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.web_search, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.edit_files, CapabilityLevel::Never);

        //  UninhabitableState should NOT be detected (no exfil capability)
        assert!(
            !perms.is_uninhabitable_vulnerable(),
            "pr_review should NOT trigger uninhabitable_state (no exfiltration capability)"
        );

        // No approvals should be required
        assert!(
            !perms.requires_approval(Operation::GitPush),
            "git_push is Never, so no approval needed"
        );
    }

    #[test]
    fn test_codegen_no_uninhabitable() {
        // codegen has read + write + bash, but NO untrusted content exposure
        // (web_fetch=Never, web_search=Never), so uninhabitable_state is not complete
        let perms = PermissionLattice::codegen();

        // Verify capabilities match expected profile
        assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(perms.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.edit_files, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.git_commit, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);

        //  UninhabitableState should NOT be detected (no untrusted content)
        assert!(
            !perms.is_uninhabitable_vulnerable(),
            "codegen should NOT trigger uninhabitable_state (no untrusted content exposure)"
        );

        // No approvals should be required for bash since no uninhabitable_state
        assert!(
            !perms.requires_approval(Operation::RunBash),
            "run_bash should not require approval (no uninhabitable_state)"
        );
    }

    #[test]
    fn test_pr_approve_has_uninhabitable() {
        // pr_approve has all three: read + web + git_push
        // This SHOULD trigger uninhabitable_state protection
        let perms = PermissionLattice::pr_approve();

        // Verify capabilities match expected profile
        assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.web_search, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.git_push, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);

        //  UninhabitableState SHOULD be detected
        assert!(
            perms.is_uninhabitable_vulnerable(),
            "pr_approve SHOULD trigger uninhabitable_state (has read + web + git_push)"
        );

        // git_push should require approval due to uninhabitable_state
        assert!(
            perms.requires_approval(Operation::GitPush),
            "git_push should require approval in pr_approve (CI-gated)"
        );

        // run_bash also requires approval since it's an exfil vector
        assert!(
            perms.requires_approval(Operation::RunBash),
            "run_bash should require approval in pr_approve (uninhabitable_state active)"
        );
    }

    #[test]
    fn test_workflow_profiles_block_sensitive_paths() {
        // All workflow profiles should block sensitive paths by default
        let profiles = [
            PermissionLattice::pr_review(),
            PermissionLattice::codegen(),
            PermissionLattice::pr_approve(),
            PermissionLattice::safe_pr_fixer(),
        ];

        for perms in &profiles {
            // Should block common sensitive patterns
            assert!(
                !perms.paths.blocked.is_empty(),
                "Workflow profile '{}' should have blocked paths",
                perms.description
            );
        }
    }

    #[test]
    fn test_codegen_is_fully_network_isolated() {
        let perms = PermissionLattice::codegen();

        // Verify complete network isolation
        assert_eq!(
            perms.capabilities.web_fetch,
            CapabilityLevel::Never,
            "codegen must be network-isolated (web_fetch=Never)"
        );
        assert_eq!(
            perms.capabilities.web_search,
            CapabilityLevel::Never,
            "codegen must be network-isolated (web_search=Never)"
        );
        assert_eq!(
            perms.capabilities.git_push,
            CapabilityLevel::Never,
            "codegen cannot push (git_push=Never)"
        );
        assert_eq!(
            perms.capabilities.create_pr,
            CapabilityLevel::Never,
            "codegen cannot create PRs (create_pr=Never)"
        );
    }

    #[test]
    fn test_safe_pr_fixer_no_push_no_pr() {
        let perms = PermissionLattice::safe_pr_fixer();

        // Key security invariant: cannot push or create PRs
        assert_eq!(
            perms.capabilities.git_push,
            CapabilityLevel::Never,
            "safe_pr_fixer cannot push (CI script does that)"
        );
        assert_eq!(
            perms.capabilities.create_pr,
            CapabilityLevel::Never,
            "safe_pr_fixer cannot create PRs (CI script does that)"
        );

        // Can read, write, edit, commit, run bash
        assert_eq!(perms.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(perms.capabilities.write_files, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.edit_files, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.git_commit, CapabilityLevel::LowRisk);

        // Web fetch allowed (docs lookup) but no broad search
        assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.web_search, CapabilityLevel::Never);

        // No pod management
        assert_eq!(perms.capabilities.manage_pods, CapabilityLevel::Never);

        //  UninhabitableState IS triggered (read + web_fetch + run_bash), and normalize()
        // correctly adds approval obligations on bash. This is the right behavior:
        // bash requires human approval, while git_push/create_pr are fully blocked.
        assert!(
            perms.is_uninhabitable_vulnerable(),
            "safe_pr_fixer has uninhabitable_state (bash is exfil vector), obligations mitigate"
        );
        assert!(
            perms.requires_approval(Operation::RunBash),
            "run_bash should require approval (uninhabitable_state mitigation)"
        );
    }

    #[test]
    fn test_pr_review_cannot_modify_code() {
        let perms = PermissionLattice::pr_review();

        // Verify read-only for code
        assert_eq!(
            perms.capabilities.write_files,
            CapabilityLevel::Never,
            "pr_review cannot write files"
        );
        assert_eq!(
            perms.capabilities.edit_files,
            CapabilityLevel::Never,
            "pr_review cannot edit files"
        );
        assert_eq!(
            perms.capabilities.git_commit,
            CapabilityLevel::Never,
            "pr_review cannot commit"
        );
        assert_eq!(
            perms.capabilities.git_push,
            CapabilityLevel::Never,
            "pr_review cannot push"
        );
        assert_eq!(
            perms.capabilities.run_bash,
            CapabilityLevel::Never,
            "pr_review cannot run bash (exfil vector)"
        );
    }

    #[test]
    fn test_pr_approve_cannot_modify_code() {
        let perms = PermissionLattice::pr_approve();

        // Verify read-only for code (only git_push is allowed for merging)
        assert_eq!(
            perms.capabilities.write_files,
            CapabilityLevel::Never,
            "pr_approve cannot write files"
        );
        assert_eq!(
            perms.capabilities.edit_files,
            CapabilityLevel::Never,
            "pr_approve cannot edit files"
        );
        assert_eq!(
            perms.capabilities.git_commit,
            CapabilityLevel::Never,
            "pr_approve cannot commit"
        );
        // But CAN push (for merging)
        assert_eq!(
            perms.capabilities.git_push,
            CapabilityLevel::LowRisk,
            "pr_approve CAN push (for merging)"
        );
    }

    // ========================================================================
    // Orchestrator Profile Tests
    // ========================================================================

    #[test]
    fn test_orchestrator_no_uninhabitable() {
        let perms = PermissionLattice::orchestrator();

        // Verify core capability: manage_pods is Always
        assert_eq!(
            perms.capabilities.manage_pods,
            CapabilityLevel::Always,
            "orchestrator must have manage_pods: Always"
        );

        // Verify no direct tool access
        assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.git_commit, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(perms.capabilities.create_pr, CapabilityLevel::Never);

        // Read-only access for orchestration configs
        assert_eq!(perms.capabilities.read_files, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.glob_search, CapabilityLevel::LowRisk);
        assert_eq!(perms.capabilities.grep_search, CapabilityLevel::LowRisk);

        // UninhabitableState: only 1/3 components (private access), no untrusted or exfil
        assert!(
            !perms.is_uninhabitable_vulnerable(),
            "orchestrator should NOT trigger uninhabitable_state"
        );

        // No approval obligations required
        assert!(
            !perms.requires_approval(Operation::ManagePods),
            "manage_pods should not require approval"
        );
    }

    #[test]
    fn test_orchestrator_delegation_strips_manage_pods() {
        let orchestrator = PermissionLattice::orchestrator();
        let codegen = PermissionLattice::codegen();

        // Delegate from orchestrator to codegen sub-pod
        let delegated = orchestrator
            .delegate_to(&codegen, "spawn codegen sub-pod")
            .unwrap();

        // Sub-pod should NOT get manage_pods (codegen doesn't request it,
        // and meet of Always with Never = Never)
        assert_eq!(
            delegated.capabilities.manage_pods,
            CapabilityLevel::Never,
            "codegen sub-pod must not get manage_pods"
        );
    }

    #[test]
    fn test_orchestrator_budget() {
        let perms = PermissionLattice::orchestrator();
        assert_eq!(
            perms.budget.max_cost_usd,
            Decimal::from(50),
            "orchestrator should have $50 budget"
        );
    }
}
