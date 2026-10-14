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
/// PermissionLattice = (Caps × Consent) × Paths × Budget × Commands × Time
///
/// Per operation, (Caps × Consent) is `Never`, or a permitted level paired with
/// `Autonomous` / `RequiresApproval` (Autonomous is the more permissive).
///
/// Meet Operation (∧):
/// • Caps: min(level_a, level_b)
/// • Consent: obligated if either side obligates, plus the uninhabitable_state
///   constraint; autonomous only if both sides are
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

    /// Tool capabilities: what each operation is ELIGIBLE for. A level above
    /// `Never` permits the operation within scope; it says nothing about
    /// consent, which [`Self::obligations`] and [`Self::autonomous`] declare.
    pub capabilities: CapabilityLattice,
    /// Approval obligations: the operations declared `RequiresApproval`.
    pub obligations: Obligations,
    /// The operations declared `Autonomous`: permitted without an approval.
    ///
    /// Consent is explicit. Every operation above `Never` must be in exactly
    /// one of `obligations` and `autonomous`; an operation in neither, or in
    /// both, is refused at construction ([`Self::check_consent`]) and by
    /// deserialization, by name. Nothing infers autonomy from omission: an
    /// operation absent from this set is decided `RequiresApproval`
    /// ([`Self::consent_for`]) even on a value whose declaration was broken
    /// after construction through the public fields.
    ///
    /// Private so the only writers are the ones that keep the declaration:
    /// [`Self::declare`], [`Self::grant`], the constructors and the lattice
    /// operations. It is serialized as a plain list of operation names, and
    /// there is no serde default — a lattice without the field is refused.
    #[cfg_attr(feature = "serde", serde(serialize_with = "ser_consent_set"))]
    pub(crate) autonomous: Obligations,
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
///
/// Consent enters through [`PermissionLattice::effective_obligations`]: the
/// operations above `Never` that are decided `RequiresApproval`. Comparing the
/// raw `obligations` set would make an obligation on a forbidden operation — one
/// that changes no decision — distinguish two policies, and the per-operation
/// consent laws (`meet`, `join`) only hold on what is decided.
impl PartialEq for PermissionLattice {
    fn eq(&self, other: &Self) -> bool {
        self.capabilities == other.capabilities
            && self.effective_obligations() == other.effective_obligations()
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
    /// No `#[serde(default)]`: `None` here is a lattice that never declared
    /// consent, and it is refused — never read as an empty set.
    autonomous: Option<std::collections::BTreeSet<Operation>>,
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

/// The `autonomous` set on the wire: a plain list of operation names.
#[cfg(feature = "serde")]
fn ser_consent_set<S>(set: &Obligations, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    set.approvals.serialize(serializer)
}

/// The one way a serialized lattice becomes a value: the consent declaration
/// is checked BEFORE `normalize` (which may move an op from autonomous to
/// obligated, and would otherwise hide a contradiction the author wrote).
#[cfg(feature = "serde")]
impl PermissionLattice {
    fn from_raw(raw: RawPermissionLattice) -> Result<Self, ConsentError> {
        let declared = raw.autonomous.is_some();
        let lattice = Self {
            id: raw.id,
            description: raw.description,
            derived_from: raw.derived_from,
            capabilities: raw.capabilities,
            obligations: raw.obligations,
            autonomous: Obligations {
                approvals: raw.autonomous.unwrap_or_default(),
            },
            paths: raw.paths,
            budget: raw.budget,
            commands: raw.commands,
            time: raw.time,
            // Security: ALWAYS true after deserialization, whatever the input said.
            uninhabitable_constraint: true,
            minimum_isolation: raw.minimum_isolation,
            created_at: raw.created_at,
            created_by: raw.created_by,
        };
        if !declared {
            let mut err = lattice.check_consent().err().unwrap_or_default();
            err.missing_field = true;
            return Err(err);
        }
        lattice.validated()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PermissionLattice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPermissionLattice::deserialize(deserializer)?;
        Self::from_raw(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
fn default_uninhabitable_constraint() -> bool {
    true
}

/// Whether an operation a policy permits needs a human approval.
///
/// The second dimension of a policy, beside eligibility (`CapabilityLevel`):
/// `LowRisk` and `Always` say an operation is permitted within scope, and this
/// says whether it runs without asking. Neither implies the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ConsentMode {
    /// Permitted without an approval (dynamic restrictions still apply).
    Autonomous,
    /// Permitted only with an approval of the action.
    RequiresApproval,
}

/// A consent declaration that was refused, naming every operation at fault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsentError {
    /// Operations above `Never` declared neither autonomous nor obligated.
    pub undeclared: Vec<Operation>,
    /// Operations declared both autonomous and obligated.
    pub contradictory: Vec<Operation>,
    /// The serialized lattice had no `autonomous` field at all.
    pub missing_field: bool,
}

impl ConsentError {
    fn is_empty(&self) -> bool {
        self.undeclared.is_empty() && self.contradictory.is_empty() && !self.missing_field
    }
}

impl std::fmt::Display for ConsentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |ops: &[Operation]| {
            ops.iter()
                .map(|op| op.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut parts = Vec::new();
        if self.missing_field {
            parts.push(
                "the policy has no `autonomous` field (consent is explicit: list the \
                 operations that run without approval, or `autonomous: []`)"
                    .to_string(),
            );
        }
        if !self.undeclared.is_empty() {
            parts.push(format!(
                "consent is not declared for {}: every operation above `never` must be listed \
                 in exactly one of `obligations` (requires approval) or `autonomous`",
                names(&self.undeclared)
            ));
        }
        if !self.contradictory.is_empty() {
            parts.push(format!(
                "{} declared both `autonomous` and requiring approval (in `obligations`)",
                names(&self.contradictory)
            ));
        }
        write!(f, "{}", parts.join("; "))
    }
}

impl std::error::Error for ConsentError {}

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

    /// A lattice from its policy dimensions, every other field fresh.
    ///
    /// Private, and the only struct literal outside deserialization and the
    /// lattice operations: every named constructor goes through here, so each
    /// one states its consent by listing both sets. Not normalized.
    #[allow(clippy::too_many_arguments)]
    fn assemble(
        description: impl Into<String>,
        capabilities: CapabilityLattice,
        obligated: &[Operation],
        autonomous: &[Operation],
        paths: PathLattice,
        budget: BudgetLattice,
        commands: CommandLattice,
        time: TimeLattice,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            description: description.into(),
            derived_from: None,
            capabilities,
            obligations: Obligations {
                approvals: obligated.iter().copied().collect(),
            },
            autonomous: Obligations {
                approvals: autonomous.iter().copied().collect(),
            },
            paths,
            budget,
            commands,
            time,
            uninhabitable_constraint: true,
            minimum_isolation: None,
            created_at: Utc::now(),
            created_by: "system".to_string(),
        }
    }

    /// The supervised permission set: reads and searches run autonomously;
    /// writes, edits, web access, commits and PR creation each need an
    /// approval. Shell, push and pod management are not permitted.
    ///
    /// This is what `PermissionLattice::default()` was. It is no longer a
    /// `Default` (ADR 0007 B-1): a policy is always named by whoever chose it.
    pub fn supervised() -> Self {
        use Operation::*;
        Self::assemble(
            "Supervised permission set",
            // read, glob, grep `always`; write, edit, web, commit, PR `low_risk`;
            // shell, push, pods, sub-agents `never`.
            CapabilityLattice::default(),
            &[
                WriteFiles, EditFiles, WebSearch, WebFetch, GitCommit, CreatePr,
            ],
            &[ReadFiles, GlobSearch, GrepSearch],
            PathLattice::default(),
            BudgetLattice::default(),
            CommandLattice::default(),
            TimeLattice::default(),
        )
        .normalize()
    }

    /// Replace the human-readable description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// The consent this policy states for `op`.
    ///
    /// `Autonomous` only when `op` is declared autonomous and not obligated.
    /// An operation in neither set — possible only on a value whose declaration
    /// was broken after construction, through the public fields — is decided
    /// `RequiresApproval`: nothing infers autonomy from omission.
    pub fn consent_for(&self, op: Operation) -> ConsentMode {
        if self.autonomous.requires(op) && !self.obligations.requires(op) {
            ConsentMode::Autonomous
        } else {
            ConsentMode::RequiresApproval
        }
    }

    /// The operations declared `Autonomous`.
    pub fn autonomous(&self) -> &Obligations {
        &self.autonomous
    }

    /// The decided obligations: every operation above `Never` whose consent is
    /// `RequiresApproval`. What equality, `leq` and the checksum compare — an
    /// obligation on a forbidden operation decides nothing.
    pub fn effective_obligations(&self) -> Obligations {
        Obligations {
            approvals: Operation::ALL
                .into_iter()
                .filter(|&op| self.requires_approval(op))
                .collect(),
        }
    }

    /// Declare the consent for `op`, replacing whatever it was.
    pub fn declare(&mut self, op: Operation, consent: ConsentMode) {
        match consent {
            ConsentMode::Autonomous => {
                self.obligations.remove(op);
                self.autonomous.insert(op);
            }
            ConsentMode::RequiresApproval => {
                self.autonomous.remove(op);
                self.obligations.insert(op);
            }
        }
    }

    /// Keep in `autonomous` only what it can mean: a permitted operation that
    /// is not obligated. An entry for an operation now `Never` is dropped, so
    /// raising that operation later leaves it UNDECLARED (decided
    /// `RequiresApproval`) rather than reviving a consent given for a level it
    /// no longer has. Removes no obligation.
    fn settle_autonomous(&mut self) {
        let obligations = &self.obligations;
        let capabilities = &self.capabilities;
        self.autonomous.approvals.retain(|op| {
            capabilities.level_for(*op) > CapabilityLevel::Never && !obligations.requires(*op)
        });
    }

    /// Declare `consent` for every operation the current levels permit — what
    /// clearing the obligations used to mean, said by name. An operation raised
    /// from `Never` after this call is undeclared again.
    pub fn declare_all(&mut self, consent: ConsentMode) {
        for op in self.capabilities.permitted_operations() {
            self.declare(op, consent);
        }
    }

    /// Obligate every operation in `ops`, moving each from autonomous: the one
    /// way to add obligations that leaves no operation in both sets.
    pub fn add_obligations(&mut self, ops: &Obligations) {
        for &op in &ops.approvals {
            self.declare(op, ConsentMode::RequiresApproval);
        }
    }

    /// Set `op`'s level and its consent together — the one way to raise an
    /// operation from `Never` that leaves it declared. Not normalized: call
    /// [`Self::normalize`] once the edits are done.
    pub fn grant(&mut self, op: Operation, level: CapabilityLevel, consent: ConsentMode) {
        *self.capabilities.level_mut(op) = level;
        self.declare(op, consent);
    }

    /// Replace the capabilities, and declare `consent` for every operation the
    /// new levels permit. The caller names the consent; nothing is inferred.
    /// Not normalized.
    pub fn with_capabilities(
        mut self,
        capabilities: CapabilityLattice,
        consent: ConsentMode,
    ) -> Self {
        self.capabilities = capabilities;
        self.settle_autonomous();
        self.declare_all(consent);
        self
    }

    /// Check the consent declaration: every operation above `Never` in exactly
    /// one of `obligations` and `autonomous`, and none in both. The error names
    /// every operation at fault.
    pub fn check_consent(&self) -> Result<(), ConsentError> {
        let mut err = ConsentError::default();
        for op in Operation::ALL {
            let obligated = self.obligations.requires(op);
            let autonomous = self.autonomous.requires(op);
            if obligated && autonomous {
                err.contradictory.push(op);
            } else if !obligated
                && !autonomous
                && self.capabilities.level_for(op) > CapabilityLevel::Never
            {
                err.undeclared.push(op);
            }
        }
        if err.is_empty() {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// The validated constructor: refuse an undeclared or contradictory
    /// declaration, then normalize.
    pub fn validated(self) -> Result<Self, ConsentError> {
        self.check_consent()?;
        Ok(self.normalize())
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
    ///
    /// It only ever ADDS obligations: an operation it obligates moves from
    /// `autonomous` to `obligations`, and one already in both is settled as
    /// obligated. So it never makes a declared operation undeclared, and it is
    /// idempotent.
    pub fn normalize(mut self) -> Self {
        if self.uninhabitable_constraint {
            let constraint = IncompatibilityConstraint::enforcing();
            let required = constraint.obligations_for(&self.capabilities);
            self.obligations = self.obligations.union(&required);
        }
        self.settle_autonomous();
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
    ///
    /// **Consent.** An operation is obligated if either side obligates it;
    /// otherwise it is autonomous only if it is autonomous on both sides. The
    /// raw `obligations` are the union of both sides' (as before consent was
    /// explicit — a certificate verifier at 2.7.0 checks a child's obligations
    /// contain its parent's), plus any operation above `Never` that is not
    /// autonomous on both, so an undeclared input yields an obligated output and
    /// narrowing never drops consent.
    pub fn meet(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.meet(&other.capabilities);

        let mut base_obligations = self.obligations.union(&other.obligations);
        let mut autonomous = Obligations::default();
        for op in Operation::ALL {
            if base_caps.level_for(op) == CapabilityLevel::Never {
                continue;
            }
            if self.consent_for(op) == ConsentMode::Autonomous
                && other.consent_for(op) == ConsentMode::Autonomous
            {
                autonomous.insert(op);
            } else {
                base_obligations.insert(op);
            }
        }

        // Apply uninhabitable_state constraint if either input enforces it
        let enforce_uninhabitable = self.uninhabitable_constraint || other.uninhabitable_constraint;
        let obligations = if enforce_uninhabitable {
            let constraint = IncompatibilityConstraint::enforcing();
            base_obligations.union(&constraint.obligations_for(&base_caps))
        } else {
            base_obligations
        };
        autonomous.approvals.retain(|op| !obligations.requires(*op));

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
            autonomous,
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
    ///
    /// **Consent** comes from the side or sides where the operation is above
    /// `Never`. If both are, it is obligated only if both obligate it. If only
    /// one is, that side's consent carries over — a side that forbids an
    /// operation says nothing about consenting to it, so it cannot waive the
    /// other side's obligation.
    pub fn join(&self, other: &Self) -> Self {
        let base_caps = self.capabilities.join(&other.capabilities);

        // Operations neither side permits keep the old intersection; they
        // decide nothing either way.
        let mut base_obligations = self.obligations.intersection(&other.obligations);
        let mut autonomous = Obligations::default();
        for op in Operation::ALL {
            let mine = self.capabilities.level_for(op) > CapabilityLevel::Never;
            let theirs = other.capabilities.level_for(op) > CapabilityLevel::Never;
            let consent = match (mine, theirs) {
                (false, false) => continue,
                (true, false) => self.consent_for(op),
                (false, true) => other.consent_for(op),
                (true, true) => {
                    if self.consent_for(op) == ConsentMode::RequiresApproval
                        && other.consent_for(op) == ConsentMode::RequiresApproval
                    {
                        ConsentMode::RequiresApproval
                    } else {
                        ConsentMode::Autonomous
                    }
                }
            };
            match consent {
                ConsentMode::Autonomous => {
                    base_obligations.remove(op);
                    autonomous.insert(op);
                }
                ConsentMode::RequiresApproval => base_obligations.insert(op),
            }
        }

        // Apply uninhabitable_state constraint if EITHER input enforces it (OR-semantics).
        // This prevents an attacker from weakening the safety check via join.
        let enforce_uninhabitable = self.uninhabitable_constraint || other.uninhabitable_constraint;
        let obligations = if enforce_uninhabitable {
            let constraint = IncompatibilityConstraint::enforcing();
            base_obligations.union(&constraint.obligations_for(&base_caps))
        } else {
            base_obligations
        };
        autonomous.approvals.retain(|op| !obligations.requires(*op));

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
            autonomous,
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

    /// Check if an operation requires approval: it is permitted (above
    /// `Never`) and [`Self::consent_for`] is `RequiresApproval` — obligated, or
    /// not declared autonomous. A forbidden operation requires no approval: no
    /// approval would make it run. Exactly membership of
    /// [`Self::effective_obligations`].
    pub fn requires_approval(&self, op: Operation) -> bool {
        self.capabilities.level_for(op) > CapabilityLevel::Never
            && self.consent_for(op) == ConsentMode::RequiresApproval
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
        self.capabilities.permitted_operations()
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
            && self.consent_leq(other)
            && self.paths.leq(&other.paths)
            && self.budget.leq(&other.budget)
            && self.commands.leq(&other.commands)
            && self.time.leq(&other.time)
    }

    /// `self` asks for an approval wherever `other` does, on every operation
    /// `self` permits. An obligation on an operation `self` forbids is no
    /// constraint `self` has to match: it decides nothing.
    ///
    /// This replaced a superset test over the raw `obligations` sets, which
    /// could not agree with the consent `join` — a side that forbids an
    /// operation is below the side that permits it under approval, yet its raw
    /// set lacks that obligation.
    fn consent_leq(&self, other: &Self) -> bool {
        Operation::ALL.into_iter().all(|op| {
            self.capabilities.level_for(op) == CapabilityLevel::Never
                || other.consent_for(op) == ConsentMode::Autonomous
                || self.consent_for(op) == ConsentMode::RequiresApproval
        })
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
    ///
    /// Consent enters as [`Self::effective_obligations`], the projection
    /// equality compares. For a lattice that obligates no forbidden operation
    /// that is byte-for-byte the raw set, so such a checksum is unchanged by
    /// explicit consent; `autonomous` is not hashed, because on every value
    /// that passes [`Self::check_consent`] it is determined by the levels and
    /// the obligations.
    #[must_use]
    pub fn checksum(&self) -> String {
        let mut hasher = Sha256::new();
        // Field-tagged and length-prefixed: without the tags, moving a byte from
        // one field to the next would leave the digest unchanged.
        for (tag, part) in self.digest_parts(&self.effective_obligations()) {
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
    ///
    /// **A cross-version identity.** The node and the pod's guest each compute
    /// `program_digest` over the same received lattice and the node refuses a
    /// workload result whose digests differ (`workload_result.rs`), so this
    /// must hash exactly what a 2.7.0 guest hashes: the RAW `obligations` and
    /// no `autonomous`. Projecting it as [`Self::checksum`] does would change
    /// the digest of every lattice that obligates an operation it forbids —
    /// which `meet` produces whenever a ceiling obligates what the pod's
    /// profile forbids (`permissive ∧ codegen` does; pinned by
    /// `tests/consent_preserved.rs`) — and fail those workloads on a pinned
    /// guest. The cost is conservative: two equal policies whose raw sets
    /// differ on a forbidden operation get different program digests, a cache
    /// miss. And no false hit: on a lattice whose declaration holds,
    /// `autonomous` is determined by the levels and the obligations hashed here.
    #[must_use]
    pub fn program_checksum(&self) -> String {
        let mut hasher = Sha256::new();
        for (tag, part) in self.digest_parts(&self.obligations) {
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

    /// A digest of the value as stored: the raw `obligations` and the raw
    /// `autonomous` set beside every other policy field. Neither coherent with
    /// equality nor a cross-version identity — it answers only "is this the
    /// exact value", for [`EffectivePermissions`]' seal.
    fn raw_checksum(&self) -> String {
        let mut hasher = Sha256::new();
        let mut parts = self.digest_parts(&self.obligations);
        parts.push(("autonomous", Self::encode(&self.autonomous)));
        for (tag, part) in parts {
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
    ///
    /// `obligations` is passed in: the decided projection for [`Self::checksum`],
    /// the raw set for [`Self::program_checksum`] (see there for why).
    fn digest_parts(&self, obligations: &Obligations) -> Vec<(&'static str, String)> {
        vec![
            ("capabilities", Self::encode(&self.capabilities)),
            ("obligations", Self::encode(obligations)),
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
    ///
    /// Consent: every operation autonomous except the uninhabitable-state exfil
    /// channels (`run_bash`, `git_push`, `create_pr`), which `normalize` would
    /// obligate anyway and are declared obligated here.
    pub fn permissive() -> Self {
        use Operation::*;
        Self::assemble(
            "Permissive permissions",
            CapabilityLattice::permissive(),
            &[RunBash, GitPush, CreatePr],
            &[
                ReadFiles, WriteFiles, EditFiles, GlobSearch, GrepSearch, WebSearch, WebFetch,
                GitCommit, ManagePods, SpawnAgent,
            ],
            PathLattice::default(),
            BudgetLattice {
                max_cost_usd: Decimal::from(10),
                max_input_tokens: 500_000,
                max_output_tokens: 50_000,
                ..Default::default()
            },
            CommandLattice::default(),
            TimeLattice::with_duration(Duration::hours(4)),
        )
        .normalize()
    }

    /// Create a restrictive permission set (for untrusted contexts).
    pub fn restrictive() -> Self {
        use Operation::*;
        Self::assemble(
            "Restrictive permissions",
            CapabilityLattice::restrictive(),
            &[],
            &[ReadFiles, GlobSearch, GrepSearch],
            PathLattice::default(),
            BudgetLattice {
                max_cost_usd: Decimal::from_str_exact("0.5").unwrap_or(Decimal::ONE),
                max_input_tokens: 10_000,
                max_output_tokens: 1_000,
                ..Default::default()
            },
            CommandLattice::default(),
            TimeLattice::with_duration(Duration::minutes(10)),
        )
        .normalize()
    }

    /// Create a read-only permission set.
    pub fn read_only() -> Self {
        use Operation::*;
        Self::assemble(
            "Read-only permissions",
            CapabilityLattice {
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
            &[],
            &[ReadFiles, GlobSearch, GrepSearch],
            PathLattice {
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
            BudgetLattice::default(),
            CommandLattice::restrictive(),
            TimeLattice::default(),
        )
        .normalize()
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
        use Operation::*;
        Self::assemble(
            "Network-only permissions",
            CapabilityLattice {
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
            &[],
            &[WebSearch, WebFetch],
            PathLattice::default(),
            BudgetLattice::with_cost_limit(1.0),
            CommandLattice::restrictive(),
            TimeLattice::minutes(30),
        )
        .normalize()
    }

    /// Create a web research permission set (read + web, no writes or exec).
    pub fn web_research() -> Self {
        use Operation::*;
        Self::assemble(
            "Web research permissions",
            CapabilityLattice {
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
            &[],
            &[ReadFiles, GlobSearch, GrepSearch, WebSearch, WebFetch],
            PathLattice::default(),
            BudgetLattice::with_cost_limit(1.5),
            CommandLattice::default(),
            TimeLattice::minutes(45),
        )
        .normalize()
    }

    /// Create a permission set for code review tasks.
    pub fn code_review() -> Self {
        use Operation::*;
        Self::assemble(
            "Code review permissions",
            CapabilityLattice {
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
            &[WebSearch],
            &[ReadFiles, GlobSearch, GrepSearch],
            PathLattice::default(),
            BudgetLattice::with_cost_limit(1.0),
            CommandLattice::default(),
            TimeLattice::minutes(30),
        )
        .normalize()
    }

    /// Create an edit-only permission set (no exec, no web).
    pub fn edit_only() -> Self {
        use Operation::*;
        Self::assemble(
            "Edit-only permissions",
            CapabilityLattice {
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
            &[],
            &[ReadFiles, WriteFiles, EditFiles, GlobSearch, GrepSearch],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(1.5),
            CommandLattice::default(),
            TimeLattice::minutes(45),
        )
        .normalize()
    }

    /// Create a local dev permission set (shell + edits, no web).
    pub fn local_dev() -> Self {
        use Operation::*;
        Self::assemble(
            "Local dev permissions",
            CapabilityLattice {
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
            &[],
            &[
                ReadFiles, WriteFiles, EditFiles, RunBash, GlobSearch, GrepSearch, GitCommit,
            ],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(3.0),
            CommandLattice::permissive(),
            TimeLattice::hours(2),
        )
        .normalize()
    }

    /// Create a permission set for fix/implementation tasks.
    ///
    /// `run_bash` is obligated by the uninhabitable-state rule (private reads,
    /// web content and a shell together), declared here as `normalize` would.
    pub fn fix_issue() -> Self {
        use Operation::*;
        Self::assemble(
            "Fix issue permissions",
            CapabilityLattice {
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
            &[RunBash, WebSearch, WebFetch, GitCommit, GitPush, CreatePr],
            &[
                ReadFiles, WriteFiles, EditFiles, GlobSearch, GrepSearch, SpawnAgent,
            ],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(2.0),
            CommandLattice::default(),
            TimeLattice::hours(1),
        )
        .normalize()
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
    /// (web_fetch=LowRisk) + exfiltration via `run_bash=LowRisk` (shell counts as an
    /// exfil channel; git_push=Never, create_pr=Never). All three components are
    /// present, so `run_bash` (and only `run_bash`) is obligated: shell commands
    /// need approval; writes, edits and commits are declared autonomous.
    ///
    /// The key security invariant: the agent can fix code and commit, but
    /// only the trusted CI wrapper script can push the branch and open a PR.
    pub fn safe_pr_fixer() -> Self {
        use Operation::*;
        Self::assemble(
            "Safe PR fixer permissions (no push, no PR creation)",
            CapabilityLattice {
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
            &[RunBash],
            &[
                ReadFiles, WriteFiles, EditFiles, GlobSearch, GrepSearch, WebFetch, GitCommit,
            ],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(5.0),
            CommandLattice::permissive(),
            TimeLattice::hours(2),
        )
        .normalize()
    }

    /// Create a release/publish permission set (approvals on exfil).
    pub fn release() -> Self {
        use Operation::*;
        Self::assemble(
            "Release permissions",
            CapabilityLattice {
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
            &[RunBash, GitPush, CreatePr],
            &[
                ReadFiles, WriteFiles, EditFiles, GlobSearch, GrepSearch, WebSearch, WebFetch,
                GitCommit,
            ],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(5.0),
            CommandLattice::permissive(),
            TimeLattice::hours(2),
        )
        .normalize()
    }

    /// Create a database client permission set (CLI access only).
    pub fn database_client() -> Self {
        use Operation::*;
        let mut commands = CommandLattice::permissive();
        for program in ["psql", "mysql", "sqlite3", "redis-cli", "mongosh"] {
            commands.allow_rule(CommandPattern {
                program: program.to_string(),
                args: vec![ArgPattern::AnyRemaining],
            });
        }

        Self::assemble(
            "Database client permissions",
            CapabilityLattice {
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
            &[],
            &[RunBash],
            PathLattice::default(),
            BudgetLattice::with_cost_limit(2.0),
            commands,
            TimeLattice::hours(1),
        )
        .normalize()
    }

    /// Create a demo-friendly permission set for tool-proxy integrations.
    ///
    /// This is permissive enough for live demos but still enforces approvals
    /// on sensitive operations (writes, edits, and uninhabitable_state exfil paths).
    pub fn demo() -> Self {
        use Operation::*;
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

        Self::assemble(
            "Demo permissions",
            CapabilityLattice {
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
            &[WriteFiles, EditFiles, RunBash, GitPush, CreatePr],
            &[
                ReadFiles, GlobSearch, GrepSearch, WebSearch, WebFetch, GitCommit,
            ],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(2.0),
            commands,
            TimeLattice::minutes(45),
        )
        .normalize()
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
        use Operation::*;
        Self::assemble(
            "PR review permissions",
            CapabilityLattice {
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
            &[],
            &[ReadFiles, GlobSearch, GrepSearch, WebSearch, WebFetch],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(1.5),
            CommandLattice::default(),
            TimeLattice::minutes(30),
        )
        .normalize()
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
        use Operation::*;
        Self::assemble(
            "Code generation permissions (network-isolated)",
            CapabilityLattice {
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
            &[],
            &[
                ReadFiles, WriteFiles, EditFiles, RunBash, GlobSearch, GrepSearch, GitCommit,
            ],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(5.0),
            CommandLattice::permissive(),
            TimeLattice::hours(1),
        )
        .normalize()
    }

    /// Create a permission set for PR approval tasks.
    ///
    /// This profile is designed for automated PR approval agents that:
    /// - Read files to verify implementation
    /// - Access web (GitHub API) to check CI status
    /// - Push/merge approved PRs
    ///
    /// ** UninhabitableState Analysis**: Has all three components (read + web + git_push),
    /// so git_push (and the shell) require approval. This is intentional - approval should
    /// be gated on CI status verification.
    pub fn pr_approve() -> Self {
        use Operation::*;
        Self::assemble(
            "PR approval permissions (CI-gated)",
            CapabilityLattice {
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
            &[RunBash, GitPush],
            &[ReadFiles, GlobSearch, GrepSearch, WebSearch, WebFetch],
            PathLattice::block_sensitive(),
            BudgetLattice::with_cost_limit(1.0),
            CommandLattice::default(),
            TimeLattice::minutes(15),
        )
        .normalize()
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
    /// No approval obligations required; every permitted op is declared autonomous.
    ///
    /// **Delegation**: The orchestrator's own permissions are narrow, but it
    /// delegates to sub-pods via a separate delegation ceiling (configured
    /// by the orchestrator's creator). Sub-pod permissions are bounded by
    /// `delegation_ceiling.delegate_to(requested)`.
    pub fn orchestrator() -> Self {
        use Operation::*;
        Self::assemble(
            "Orchestrator permissions (pod management only)",
            CapabilityLattice {
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
            &[],
            &[ReadFiles, GlobSearch, GrepSearch, ManagePods, SpawnAgent],
            PathLattice::default(),
            BudgetLattice::with_cost_limit(50.0),
            CommandLattice::restrictive(),
            TimeLattice::hours(4),
        )
        .normalize()
    }
}

/// Builder for constructing `PermissionLattice` instances.
#[derive(Default)]
pub struct PermissionLatticeBuilder {
    description: Option<String>,
    capabilities: Option<CapabilityLattice>,
    obligations: Option<Obligations>,
    autonomous: Obligations,
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

    /// Set approval obligations: the operations declared `RequiresApproval`.
    pub fn obligations(mut self, obligations: Obligations) -> Self {
        self.obligations = Some(obligations);
        self
    }

    /// Set the capabilities and declare `consent` for every operation they
    /// permit. The caller names the consent; [`Self::obligations`] /
    /// [`Self::autonomous`] can still refine it, and an operation then declared
    /// both ways is refused by `build`.
    pub fn capabilities_with(
        mut self,
        capabilities: CapabilityLattice,
        consent: ConsentMode,
    ) -> Self {
        let permitted = capabilities.permitted_operations();
        self.capabilities = Some(capabilities);
        match consent {
            ConsentMode::Autonomous => {
                for op in permitted {
                    self.autonomous.insert(op);
                }
            }
            ConsentMode::RequiresApproval => {
                let obligations = self.obligations.get_or_insert_with(Obligations::default);
                for op in permitted {
                    obligations.insert(op);
                }
            }
        }
        self
    }

    /// Declare operations `Autonomous`. Every operation above `Never` must be
    /// declared here or in [`Self::obligations`], or `build` refuses it.
    pub fn autonomous(mut self, ops: impl IntoIterator<Item = Operation>) -> Self {
        for op in ops {
            self.autonomous.insert(op);
        }
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

    /// Build the permission lattice: refused, naming each operation, when an
    /// operation above `Never` is declared neither autonomous nor obligated, or
    /// both. Normalized.
    pub fn build(self) -> Result<PermissionLattice, ConsentError> {
        let lattice = PermissionLattice {
            id: Uuid::new_v4(),
            description: self
                .description
                .unwrap_or_else(|| "Custom permissions".to_string()),
            derived_from: None,
            capabilities: self.capabilities.unwrap_or_default(),
            obligations: self.obligations.unwrap_or_default(),
            autonomous: self.autonomous,
            paths: self.paths.unwrap_or_default(),
            budget: self.budget.unwrap_or_default(),
            commands: self.commands.unwrap_or_default(),
            time: self.time.unwrap_or_default(),
            uninhabitable_constraint: self.uninhabitable_constraint.unwrap_or(true),
            minimum_isolation: self.minimum_isolation,
            created_at: Utc::now(),
            created_by: self.created_by.unwrap_or_else(|| "builder".to_string()),
        };

        lattice.validated()
    }

    /// Build without normalization — for delegation ceilings that must
    /// remain as pure top elements without obligation injection.
    ///
    /// Use `build()` for normal policies. Use this only when constructing
    /// a ceiling lattice for Galois connection properties. The consent
    /// declaration is checked all the same: a ceiling is met with policies, and
    /// `meet` reads an undeclared operation as obligated.
    pub fn build_unnormalized(self) -> Result<PermissionLattice, ConsentError> {
        let lattice = PermissionLattice {
            id: Uuid::new_v4(),
            description: self
                .description
                .unwrap_or_else(|| "Custom permissions".to_string()),
            derived_from: None,
            capabilities: self.capabilities.unwrap_or_default(),
            obligations: self.obligations.unwrap_or_default(),
            autonomous: self.autonomous,
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
        };
        lattice.check_consent()?;
        Ok(lattice)
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
        // v2: the seal covers the RAW consent sets, not the decided
        // projection `checksum` compares. Removing an obligation in place
        // leaves the operation undeclared — decided the same, fail-closed —
        // but it is still a mutation of the sealed value, and a seal says so.
        hasher.update(b"portcullis-effective-permissions-seal-v2\x00");
        hasher.update(lattice.raw_checksum().as_bytes());
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

#[cfg(test)]
#[path = "lattice_tests.rs"]
mod tests;
