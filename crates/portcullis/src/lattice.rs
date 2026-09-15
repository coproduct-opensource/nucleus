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
#[derive(Debug, Clone)]
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

/// Equality is over what the permissions PERMIT, not over how they were made.
///
/// Derived `PartialEq` compared `id`, `description` and `derived_from` — audit
/// provenance that `meet`, `join` and `leq` all deliberately ignore. Since
/// `meet` mints `id: Uuid::new_v4()` on every call and builds an order-dependent
/// `description`, the derived equality made this type satisfy **none** of the
/// fifteen laws its three lattice traits declare: `verify_lattice_laws` over
/// three of its own constructors reported 99 violations, `a.meet(&a) != a` among
/// them, and `a.meet(&b) == a` was never true for any `a` and `b` — which breaks
/// the `a ≤ b ⟺ a ∧ b = a` correspondence by construction.
///
/// It also meant two policy-identical permission sets compared unequal, which is
/// the wrong answer to the only question `==` is ever asked here.
///
/// This is the move [`crate::delegation`]'s neighbour already makes:
/// `portcullis_core::attenuation::LiteralDelegation` hand-writes `PartialEq`
/// because *"deriving `PartialEq` would break join commutativity: `a ∨ b` and
/// `b ∨ a` list elements in different orders"*. Same wall, same answer — make
/// `PartialEq` **be** the law equality rather than adding a second notion of
/// equality beside it.
///
/// `leq` was never affected and is unchanged: it compares only the policy
/// fields, so the one production enforcement site
/// (`certificate.rs`'s `effective_permissions.leq(prev_permissions)`) was sound
/// throughout.
impl PartialEq for PermissionLattice {
    fn eq(&self, other: &Self) -> bool {
        self.capabilities == other.capabilities
            && self.obligations == other.obligations
            && self.paths == other.paths
            && self.budget == other.budget
            && self.commands == other.commands
            && self.time == other.time
            && self.minimum_isolation == other.minimum_isolation
            && self.uninhabitable_constraint == other.uninhabitable_constraint
    }
}

/// Parse a UUID from a string WITHOUT risking a panic on hostile input.
///
/// The `uuid` crate's own `Deserialize`/error path panics (it slices the
/// offending string at a non-char-boundary while formatting its
/// `InvalidUuid` message) when handed a **non-ASCII** string. Because
/// `PermissionLattice` is deserialized from untrusted config — and is a
/// libFuzzer target (`fuzz/fuzz_targets/permission_serde.rs`) — that crash
/// is reachable from arbitrary bytes. A valid UUID is always ASCII, so we
/// reject non-ASCII up front and return a clean error instead of letting it
/// reach uuid's panicking formatter. (No upstream fix as of uuid 1.23.2.)
#[cfg(feature = "serde")]
fn parse_uuid_guarded(s: &str) -> Result<Uuid, String> {
    if !s.is_ascii() {
        return Err("invalid UUID: contains non-ASCII characters".to_string());
    }
    Uuid::try_parse(s).map_err(|e| e.to_string())
}

#[cfg(feature = "serde")]
fn de_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_uuid_guarded(&s).map_err(serde::de::Error::custom)
}

#[cfg(feature = "serde")]
fn de_opt_uuid<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        None => Ok(None),
        Some(s) => parse_uuid_guarded(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

/// Raw deserialization helper that preserves all fields.
#[cfg(feature = "serde")]
#[derive(Deserialize)]
struct RawPermissionLattice {
    #[serde(deserialize_with = "de_uuid")]
    id: Uuid,
    description: String,
    #[serde(default, deserialize_with = "de_opt_uuid")]
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

#[cfg(feature = "serde")]
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
    /// Convert to a delegation ceiling.
    ///
    /// Disables the uninhabitable state constraint on this lattice. Use this
    /// when the lattice represents a **capability ceiling** for delegation,
    /// not a directly enforced policy. The delegated (child) lattice will
    /// have its own constraint enforcement via `normalize()`.
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
    /// The uninhabitable_state constraint is applied if EITHER input enforces it.
    /// This ensures the safety constraint is monotonically preserved upward —
    /// an attacker cannot disable the uninhabitable check by joining with a
    /// permissive lattice that has `uninhabitable_constraint = false`.
    pub fn join(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.join(&other.capabilities);

        let base_obligations = self.obligations.intersection(&other.obligations);

        // Apply uninhabitable_state constraint if EITHER input enforces it (OR-semantics).
        // This prevents an attacker from weakening the safety check via join.
        let enforce_uninhabitable = self.uninhabitable_constraint || other.uninhabitable_constraint;
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

    /// The operations this policy actually permits — every core [`Operation`]
    /// whose capability level is **strictly above** [`CapabilityLevel::Never`].
    ///
    /// This is **the trust choke point** for minting a session capability
    /// token: a [`TokenScope`](crate) built from `granted_operations()` is a
    /// subset of the policy *by construction*, because an operation is present
    /// here **iff** `level_for(op) > Never`. Equivalently, every op excluded
    /// here is exactly one with `level_for(op) == Never` (fully denied), so the
    /// minted scope can never grant an operation the policy denies.
    ///
    /// Enumeration is over [`Operation::ALL`] (the 13 statically-known core
    /// operations), so the ordering is **deterministic** — it follows the
    /// enum's declaration order. `ExtensionOperation`s are intentionally
    /// excluded: they are string-keyed, out of the formally-verified core, and
    /// not part of the token vocabulary.
    pub fn granted_operations(&self) -> Vec<Operation> {
        Operation::ALL
            .into_iter()
            .filter(|&op| self.capabilities.level_for(op) > CapabilityLevel::Never)
            .collect()
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

    /// Compute a checksum over WHAT IS PERMITTED, not over how it was made.
    ///
    /// Coherent with [`PartialEq`], which is the law this previously broke:
    /// two values that compare equal must hash equal, and they did not. The old
    /// implementation serialized the whole struct — `id`, `description` and
    /// `derived_from` included — so a `meet` that produced the same policy under
    /// a new label produced a different checksum, and the audit chain recorded
    /// `pre_permissions_hash != post_permissions_hash`: a permission change that
    /// had not happened.
    ///
    /// The non-serde variant used to hash `format!("{:?}", self)`. Derived
    /// `Debug` is not a stability contract — a field rename or reorder silently
    /// rewrites every hash — which is the defect #747 records for the receipt
    /// chain, here on the permission checksum itself. Both variants now hash the
    /// same projection, so the two builds agree on what a policy hashes to.
    #[must_use]
    pub fn checksum(&self) -> String {
        let mut hasher = Sha256::new();
        // Field-tagged and length-prefixed: without the tags, moving a byte from
        // one field to the next would leave the digest unchanged.
        for (tag, part) in self.digest_parts() {
            hasher.update(tag.as_bytes());
            hasher.update(b"\x00");
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }

    /// The checksum of what a policy COMPUTES, with the validity window left out.
    ///
    /// [`Self::checksum`] answers "is this the same certificate" and a window
    /// belongs there: a grant good until Tuesday is not one good until Friday.
    /// `program_digest` asks "would this compute the same thing", and a window
    /// says WHEN a pod runs, never WHAT it computes. Minted per launch at
    /// nanosecond precision, it made every run a distinct program and a
    /// cross-execution cache could never hit (measured: 7fda8773.../6f095fc2...
    /// for two identical builds; 466842e6... for both with this). Every other
    /// field still enters, so policies differing in what they permit differ.
    #[must_use]
    pub fn program_checksum(&self) -> String {
        let mut hasher = Sha256::new();
        for (tag, part) in self.digest_parts() {
            if tag == "time" {
                continue;
            }
            hasher.update(tag.as_bytes());
            hasher.update(b"\x00");
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }

    /// The policy fields, in a fixed order, each as a stable string.
    ///
    /// Exactly the fields [`PartialEq`] compares — the two must not drift apart,
    /// and `every_policy_field_reaches_the_digest` pins that each one actually
    /// arrives.
    ///
    /// ONE function, with the feature split pushed down into [`Self::encode`].
    /// It was two — a `#[cfg(feature = "serde")]` body and a `#[cfg(not(..))]`
    /// one — and mutation testing reported five survivors against the second.
    /// They survived because `--all-features` does not compile it: mutating code
    /// that is `cfg`-ed out changes nothing, so every mutant passed. A function
    /// no build in CI compiles is a function no test can defend, and splitting
    /// on the feature at the top of a body is how that happens.
    fn digest_parts(&self) -> Vec<(&'static str, String)> {
        vec![
            ("capabilities", Self::encode(&self.capabilities)),
            ("obligations", Self::encode(&self.obligations)),
            ("paths", Self::encode(&self.paths)),
            ("budget", Self::encode(&self.budget)),
            ("commands", Self::encode(&self.commands)),
            ("time", Self::encode(&self.time)),
            ("minimum_isolation", Self::encode(&self.minimum_isolation)),
            ("uninhabitable", self.uninhabitable_constraint.to_string()),
        ]
    }

    /// One field as a stable string.
    ///
    /// The only thing the `serde` feature changes about the digest. `Debug` is
    /// not a stability contract across compiler versions — the defect #747
    /// records for the receipt chain — so the serde build is the one whose
    /// digest is durable, and the fallback exists for the WASM consumers that
    /// build with `default-features = false`.
    #[cfg(feature = "serde")]
    fn encode<T: serde::Serialize>(field: &T) -> String {
        serde_json::to_string(field).unwrap_or_default()
    }

    /// See the serde variant above.
    #[cfg(not(feature = "serde"))]
    fn encode<T: std::fmt::Debug>(field: &T) -> String {
        format!("{field:?}")
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
                spawn_agent: CapabilityLevel::Never,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            },
            obligations: Obligations::default(),
            commands: CommandLattice::restrictive(),
            paths: PathLattice {
                allowed: std::collections::HashSet::new(), // empty = all readable
                blocked: [
                    // Defense-in-depth: block sensitive paths even though write
                    // capabilities are Never. Belt-and-suspenders for lockdown.
                    "**/.env",
                    "**/.env.*",
                    "**/secrets/**",
                    "**/.ssh/**",
                    "**/.gnupg/**",
                    "**/.aws/**",
                    "**/credentials*",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                work_dir: None,
            },
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::LowRisk,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Never,
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
                spawn_agent: CapabilityLevel::Always,
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

    /// Build without normalization — for delegation ceilings that must
    /// remain as pure top elements without obligation injection.
    ///
    /// Use `build()` for normal policies. Use this only when constructing
    /// a ceiling lattice for Galois connection properties.
    pub fn build_unnormalized(self) -> PermissionLattice {
        PermissionLattice {
            id: Uuid::new_v4(),
            description: self
                .description
                .unwrap_or_else(|| "Custom permissions".to_string()),
            derived_from: None,
            capabilities: self.capabilities.unwrap_or_default(),
            obligations: self.obligations.unwrap_or_default(),
            paths: self.paths.unwrap_or_default(),
            budget: self.budget.unwrap_or_default(),
            // Use empty() not default() — default has a pre-populated allowlist
            // which is MORE restrictive. For ceilings we want all-allowed (empty).
            commands: self
                .commands
                .unwrap_or_else(crate::command::CommandLattice::empty),
            time: self.time.unwrap_or_default(),
            uninhabitable_constraint: self.uninhabitable_constraint.unwrap_or(true),
            minimum_isolation: self.minimum_isolation,
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
        let lattice = lattice.normalize();
        let checksum = Self::seal(&lattice);
        Self {
            lattice,
            budget_reservation_id: None,
            checksum,
        }
    }

    /// The tamper seal: a digest over the WHOLE value, provenance included.
    ///
    /// Deliberately not [`PermissionLattice::checksum`], which answers a
    /// different question. That one asks *what is permitted*, and is coherent
    /// with `PartialEq`: two policies that permit the same things hash the same,
    /// so relabelling one does not read as a permission change in the audit
    /// chain.
    ///
    /// This one asks *is this exact value the one I sealed*, and the answer must
    /// be no if `description` or `derived_from` moved — an audit label a
    /// reviewer reads is worth sealing even though it grants nothing.
    /// `effective_permissions_detect_tampering` is the test that says so, and it
    /// is right: a sealed structure seals everything it carries.
    ///
    /// Two questions, two digests. Collapsing them is what made the permission
    /// checksum incoherent with equality in the first place.
    fn seal(lattice: &PermissionLattice) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"portcullis-effective-permissions-seal-v1\x00");
        hasher.update(lattice.checksum().as_bytes());
        hasher.update(b"\x00");
        hasher.update(lattice.id.as_bytes());
        hasher.update(b"\x00");
        hasher.update((lattice.description.len() as u64).to_be_bytes());
        hasher.update(lattice.description.as_bytes());
        hasher.update(b"\x00");
        match lattice.derived_from {
            Some(from) => hasher.update(from.as_bytes()),
            None => hasher.update(b"none"),
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }

    /// Create effective permissions with a budget reservation.
    pub fn with_budget_reservation(mut self, reservation_id: Uuid) -> Self {
        self.budget_reservation_id = Some(reservation_id);
        self
    }

    /// Verify the integrity of the permissions.
    ///
    /// Detects any mutation of the sealed value, including a changed
    /// `description` or `derived_from` — see [`Self::seal`] for why that is a
    /// different question from "what is permitted".
    pub fn verify_integrity(&self) -> bool {
        Self::seal(&self.lattice) == self.checksum
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
#[path = "lattice_tests.rs"]
mod tests;
