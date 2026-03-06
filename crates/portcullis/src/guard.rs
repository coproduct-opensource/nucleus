//! Type-safe permission enforcement via the PermissionGuard trait.
//!
//! This module provides compile-time guarantees that permission checks cannot
//! be bypassed or ignored by callers.
//!
//! ## Graded Guards
//!
//! The [`GradedGuard`] combines type-safe enforcement with risk tracking via
//! the graded monad. Every guard decision carries a [`TrifectaRisk`] grade
//! that accumulates through monadic composition:
//!
//! ```rust
//! use portcullis::guard::{GradedGuard, PermissionGuard};
//! use portcullis::{PermissionLattice, CapabilityLevel};
//! use portcullis::graded::RiskGrade;
//!
//! let perms = PermissionLattice::read_only();
//! let guard = GradedGuard::new(perms);
//!
//! let result = guard.check_path("/workspace/src/lib.rs");
//! assert!(result.value.is_ok());
//! // Risk grade reflects trifecta exposure of the permission set
//! ```

use std::marker::PhantomData;
use std::sync::RwLock;

use sha2::{Digest, Sha256};

use crate::capability::{IncompatibilityConstraint, Operation, TrifectaRisk};
use crate::graded::Graded;
use crate::heyting::permission_gap;
use crate::PermissionLattice;

/// A proof type that permission was checked and granted.
///
/// This type cannot be constructed externally (the `_private` field
/// prevents it). The only way to obtain a `GuardedAction` is through
/// a successful permission check via [`PermissionGuard::guard`].
///
/// # Example
///
/// ```ignore
/// fn execute_with_permission<A>(action: GuardedAction<A>) {
///     // We know permission was checked because GuardedAction
///     // can only be constructed by the guard system
///     action.execute();
/// }
/// ```
#[derive(Debug)]
pub struct GuardedAction<A> {
    action: A,
    /// Private field prevents external construction
    _private: (),
}

impl<A> GuardedAction<A> {
    /// Create a new guarded action (internal only).
    ///
    /// This is `pub(crate)` to allow the permission system to create
    /// guarded actions, but external code cannot construct them.
    pub(crate) fn new(action: A) -> Self {
        Self {
            action,
            _private: (),
        }
    }

    /// Get a reference to the guarded action.
    pub fn action(&self) -> &A {
        &self.action
    }

    /// Consume the guard and return the action.
    ///
    /// This should only be called when you're ready to execute the action.
    pub fn into_action(self) -> A {
        self.action
    }

    /// Map the action to a new type (functor).
    pub fn map<B, F>(self, f: F) -> GuardedAction<B>
    where
        F: FnOnce(A) -> B,
    {
        GuardedAction::new(f(self.action))
    }

    /// Chain with another fallible guard operation (monad bind).
    ///
    /// This enables composing multiple permission checks:
    /// ```ignore
    /// guard.guard(read_path)?
    ///     .and_then(|path| guard.guard(write_path))?
    ///     .and_then(|path| guard.guard(execute))?
    /// ```
    ///
    /// The monadic structure ensures:
    /// - Each check is performed only if previous checks passed
    /// - The proof chain is preserved (cannot skip intermediate checks)
    /// - Errors propagate correctly through the chain
    pub fn and_then<B, E, F>(self, f: F) -> Result<GuardedAction<B>, GuardError<E>>
    where
        F: FnOnce(A) -> Result<GuardedAction<B>, GuardError<E>>,
    {
        f(self.action)
    }

    /// Chain with another fallible operation that returns a plain result.
    ///
    /// Useful when the next operation isn't a guard check but still needs
    /// the proof that the previous operation was guarded.
    pub fn try_map<B, E, F>(self, f: F) -> Result<GuardedAction<B>, GuardError<E>>
    where
        F: FnOnce(A) -> Result<B, E>,
        E: std::fmt::Display,
    {
        match f(self.action) {
            Ok(b) => Ok(GuardedAction::new(b)),
            Err(e) => Err(GuardError::CheckFailed { error: e }),
        }
    }
}

/// Error type for permission guard failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError<E = String> {
    /// Permission was denied
    Denied {
        /// Reason for denial
        reason: String,
    },
    /// Permission check itself failed
    CheckFailed {
        /// The underlying error
        error: E,
    },
    /// The permission has expired
    Expired,
    /// Budget exhausted
    BudgetExhausted,
    /// Action is blocked by policy
    Blocked {
        /// What blocked it
        blocker: String,
    },
}

impl<E: std::fmt::Display> std::fmt::Display for GuardError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { reason } => write!(f, "Permission denied: {}", reason),
            Self::CheckFailed { error } => write!(f, "Permission check failed: {}", error),
            Self::Expired => write!(f, "Permission has expired"),
            Self::BudgetExhausted => write!(f, "Budget exhausted"),
            Self::Blocked { blocker } => write!(f, "Blocked by policy: {}", blocker),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for GuardError<E> {}

/// Type-safe permission enforcement trait.
///
/// Implementors of this trait provide runtime permission checks that
/// return proof values (`GuardedAction`) rather than just booleans.
///
/// This pattern ensures that callers cannot:
/// - Ignore the permission check result
/// - Construct a "passed" result without actually checking
/// - Accidentally bypass the permission system
///
/// # Example
///
/// ```ignore
/// use trifecta_guard::guard::{PermissionGuard, GuardedAction, GuardError};
///
/// struct FileReadGuard {
///     allowed_paths: Vec<PathBuf>,
/// }
///
/// impl PermissionGuard for FileReadGuard {
///     type Action = PathBuf;
///     type Error = String;
///
///     fn guard(&self, path: PathBuf) -> Result<GuardedAction<PathBuf>, GuardError<String>> {
///         if self.allowed_paths.iter().any(|p| path.starts_with(p)) {
///             Ok(GuardedAction::new(path))
///         } else {
///             Err(GuardError::Denied {
///                 reason: format!("Path {:?} not in allowed list", path),
///             })
///         }
///     }
/// }
///
/// // Using the guard
/// fn read_file(guard: &FileReadGuard, path: PathBuf) -> Result<String, GuardError<String>> {
///     let guarded = guard.guard(path)?; // Must handle error
///     let path = guarded.into_action();
///     std::fs::read_to_string(path).map_err(|e| GuardError::CheckFailed { error: e.to_string() })
/// }
/// ```
pub trait PermissionGuard {
    /// The type of action being guarded.
    type Action;

    /// The error type for permission check failures.
    type Error;

    /// Check if the action is permitted and return a proof if so.
    ///
    /// Returns `Ok(GuardedAction)` if the action is allowed,
    /// or `Err(GuardError)` if denied.
    fn guard(
        &self,
        action: Self::Action,
    ) -> Result<GuardedAction<Self::Action>, GuardError<Self::Error>>;
}

/// Type alias for guard functions to reduce complexity.
pub type GuardFn<A, E> = Box<dyn Fn(&A) -> Result<(), GuardError<E>>>;

/// A composable guard that combines multiple guards.
///
/// All guards must pass for the action to be allowed.
pub struct CompositeGuard<A, E> {
    guards: Vec<GuardFn<A, E>>,
    _phantom: PhantomData<A>,
}

impl<A, E> Default for CompositeGuard<A, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A, E> CompositeGuard<A, E> {
    /// Create a new empty composite guard.
    pub fn new() -> Self {
        Self {
            guards: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Add a guard function to the chain.
    ///
    /// The guard will be checked in order with other guards. All guards must
    /// pass for the action to be allowed.
    pub fn with_guard<F>(mut self, guard: F) -> Self
    where
        F: Fn(&A) -> Result<(), GuardError<E>> + 'static,
    {
        self.guards.push(Box::new(guard));
        self
    }
}

impl<A, E: Clone> PermissionGuard for CompositeGuard<A, E> {
    type Action = A;
    type Error = E;

    fn guard(&self, action: A) -> Result<GuardedAction<A>, GuardError<E>> {
        for guard in &self.guards {
            guard(&action)?;
        }
        Ok(GuardedAction::new(action))
    }
}

/// A permission guard that tracks trifecta risk as a grade.
///
/// Every check returns `Graded<TrifectaRisk, Result<GuardedAction<A>, GuardError>>`,
/// so callers always see both the access decision AND the risk level of the
/// permission set that produced it.
///
/// The risk grade is computed from the underlying `PermissionLattice` via
/// `IncompatibilityConstraint::enforcing()`. This means even allowed actions
/// carry their trifecta risk — enabling downstream systems to add extra
/// oversight for operations that are technically permitted but high-risk.
pub struct GradedGuard {
    perms: PermissionLattice,
    risk: TrifectaRisk,
}

impl GradedGuard {
    /// Create a new graded guard from a permission lattice.
    ///
    /// The trifecta risk is computed once at construction and carried through
    /// all subsequent checks.
    pub fn new(perms: PermissionLattice) -> Self {
        let constraint = IncompatibilityConstraint::enforcing();
        let risk = constraint.trifecta_risk(&perms.capabilities);
        Self { perms, risk }
    }

    /// Get the trifecta risk grade of this guard's permission set.
    pub fn risk(&self) -> TrifectaRisk {
        self.risk
    }

    /// Check if an operation is allowed, returning a graded result.
    ///
    /// The grade carries the trifecta risk regardless of whether the
    /// operation is allowed or denied.
    pub fn check_operation(
        &self,
        operation: Operation,
    ) -> Graded<TrifectaRisk, Result<GuardedAction<Operation>, GuardError>> {
        let requires_approval = self.perms.requires_approval(operation);

        let result = if requires_approval && self.risk == TrifectaRisk::Complete {
            Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: trifecta risk is Complete and operation requires approval",
                    operation
                ),
            })
        } else {
            Ok(GuardedAction::new(operation))
        };

        Graded::new(self.risk, result)
    }

    /// Check if a path is accessible, returning a graded result.
    ///
    /// Uses the permission lattice's path matching against the configured
    /// allowed paths.
    pub fn check_path(
        &self,
        path: &str,
    ) -> Graded<TrifectaRisk, Result<GuardedAction<String>, GuardError>> {
        let allowed = self.perms.paths.can_access(std::path::Path::new(path));

        let result = if allowed {
            Ok(GuardedAction::new(path.to_string()))
        } else {
            Err(GuardError::Denied {
                reason: format!("Path '{}' not in allowed paths", path),
            })
        };

        Graded::new(self.risk, result)
    }

    /// Compute the Heyting permission gap needed to reach a target permission set.
    ///
    /// Returns a graded gap analysis: the grade is the risk of the *target*
    /// (what the requester wants), and the value is the Heyting implication
    /// `current → target` — the logical "what's needed" to bridge.
    pub fn permission_gap_to(
        &self,
        target: &PermissionLattice,
    ) -> Graded<TrifectaRisk, crate::CapabilityLattice> {
        let constraint = IncompatibilityConstraint::enforcing();
        let target_risk = constraint.trifecta_risk(&target.capabilities);
        let gap = permission_gap(&self.perms.capabilities, &target.capabilities);
        Graded::new(target_risk, gap)
    }

    /// Get a reference to the underlying permission lattice.
    pub fn permissions(&self) -> &PermissionLattice {
        &self.perms
    }
}

// ---------------------------------------------------------------------------
// Runtime tool-call interposition
// ---------------------------------------------------------------------------

/// Runtime tool-call interposition guard.
///
/// Called before every tool invocation at execution time (not just delegation
/// time). This closes the gap between static permission checking and runtime
/// enforcement by tracking the *sequence* of operations within a session.
///
/// Unlike [`GradedGuard`] which checks if the *permission set* has trifecta
/// risk, `ToolCallGuard` checks if the *execution sequence* would complete
/// the trifecta — catching read→fetch→exfil attack chains even when
/// individual operations pass their static permission checks.
pub trait ToolCallGuard: Send + Sync {
    /// Check if a tool call is permitted given the current session state.
    ///
    /// Returns `Ok(())` if allowed. The guard may project future risk but
    /// does NOT update accumulated state — call [`record`] after success.
    fn check(&self, operation: Operation) -> Result<(), GuardError>;

    /// Record that an operation was successfully executed.
    ///
    /// Updates accumulated risk. Must be called *after* a tool call succeeds,
    /// not before (to avoid phantom risk from failed operations).
    fn record(&self, operation: Operation);

    /// Get the current accumulated trifecta risk for this session.
    fn accumulated_risk(&self) -> TrifectaRisk;

    /// Verify tool schema integrity (rug-pull detection).
    ///
    /// Compares the current tool schema hash against the pinned hash from
    /// session initialization. Returns `Err` if they differ, indicating
    /// tools were mutated after delegation-time approval.
    fn verify_schema(&self, current_hash: &str) -> Result<(), GuardError>;
}

/// Session-scoped runtime trifecta guard.
///
/// Tracks the sequence of operations executed in an MCP session and blocks
/// operations that would complete the lethal trifecta (private data access +
/// untrusted content + exfiltration).
///
/// Also pins the tool schema at session start for rug-pull detection.
pub struct RuntimeTrifectaGuard {
    /// The underlying permission lattice for static checks.
    perms: PermissionLattice,
    /// Operations executed in this session.
    executed_ops: RwLock<Vec<Operation>>,
    /// Current accumulated risk level.
    accumulated_risk_state: RwLock<TrifectaRisk>,
    /// Pinned SHA-256 of tool list at session init.
    pinned_schema_hash: String,
}

impl RuntimeTrifectaGuard {
    /// Create a new guard for a session.
    ///
    /// `tool_schemas` is a string representation of the tool list, hashed
    /// at session start for rug-pull detection.
    pub fn new(perms: PermissionLattice, tool_schemas: &str) -> Self {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(tool_schemas.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        Self {
            perms,
            executed_ops: RwLock::new(Vec::new()),
            accumulated_risk_state: RwLock::new(TrifectaRisk::None),
            pinned_schema_hash: hash,
        }
    }

    /// Compute the trifecta risk from a set of executed operations.
    ///
    /// This looks at which *categories* of the trifecta have been touched,
    /// not the static capability levels. A session that has only done reads
    /// is Low risk even if the permission set allows web_fetch.
    fn compute_session_risk(ops: &[Operation]) -> TrifectaRisk {
        let has_private = ops.iter().any(|op| {
            matches!(
                op,
                Operation::ReadFiles
                    | Operation::GlobSearch
                    | Operation::GrepSearch
                    | Operation::RunBash // RunBash can read any file
            )
        });
        let has_untrusted = ops
            .iter()
            .any(|op| matches!(op, Operation::WebFetch | Operation::WebSearch));
        let has_exfil = ops.iter().any(|op| {
            matches!(
                op,
                Operation::GitPush | Operation::CreatePr | Operation::RunBash
            )
        });

        match (has_private as u8) + (has_untrusted as u8) + (has_exfil as u8) {
            0 => TrifectaRisk::None,
            1 => TrifectaRisk::Low,
            2 => TrifectaRisk::Medium,
            _ => TrifectaRisk::Complete,
        }
    }
}

impl ToolCallGuard for RuntimeTrifectaGuard {
    fn check(&self, operation: Operation) -> Result<(), GuardError> {
        use crate::CapabilityLevel;

        // 1. Check capability level (is the operation allowed at all?)
        let level = self.perms.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return Err(GuardError::Denied {
                reason: format!("{:?} denied: capability level is Never", operation),
            });
        }

        // 2. Project what the session risk would be if this op executes
        let ops = self.executed_ops.read().expect("lock poisoned");
        let mut projected = ops.clone();
        projected.push(operation);
        let projected_risk = Self::compute_session_risk(&projected);

        // 3. If projected risk would complete trifecta and the operation
        //    has approval obligations, deny it. This is the runtime
        //    interposition gate — blocks the read→fetch→exfil sequence.
        if projected_risk == TrifectaRisk::Complete && self.perms.requires_approval(operation) {
            let current = *self.accumulated_risk_state.read().expect("lock poisoned");
            return Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: would complete trifecta (session risk: {:?} -> Complete)",
                    operation, current,
                ),
            });
        }

        Ok(())
    }

    fn record(&self, operation: Operation) {
        let mut ops = self.executed_ops.write().expect("lock poisoned");
        ops.push(operation);
        let new_risk = Self::compute_session_risk(&ops);
        *self.accumulated_risk_state.write().expect("lock poisoned") = new_risk;
    }

    fn accumulated_risk(&self) -> TrifectaRisk {
        *self.accumulated_risk_state.read().expect("lock poisoned")
    }

    fn verify_schema(&self, current_hash: &str) -> Result<(), GuardError> {
        if current_hash != self.pinned_schema_hash {
            Err(GuardError::Denied {
                reason: format!(
                    "tool schema hash mismatch: expected {}, got {} (possible rug-pull)",
                    self.pinned_schema_hash, current_hash
                ),
            })
        } else {
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GradedTaintGuard — the beautiful version
//
// Rather than tracking Vec<Operation> and rescanning O(n), this uses a
// 3-bit semilattice (TaintSet) as the grade monoid for the Graded monad.
// Taint accumulation is O(1) per operation and compositional by
// construction: the monoid homomorphism λ: Operation → TaintSet
// factors through the graded bind (>>=).
// ═══════════════════════════════════════════════════════════════════════════

/// Taint labels for the three legs of the lethal trifecta.
///
/// These form a free semilattice (join = set union) that the graded monad
/// carries as its grade. When the join reaches `{PrivateData, UntrustedContent,
/// ExfilVector}`, the trifecta is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintLabel {
    /// Private data was accessed (read_files, glob_search, grep_search)
    PrivateData,
    /// Untrusted external content was ingested (web_fetch, web_search)
    UntrustedContent,
    /// An exfiltration-capable operation was performed (run_bash, git_push, create_pr)
    ExfilVector,
}

/// A taint set tracking which trifecta legs have been touched.
///
/// This is the grade monoid for our graded monad:
/// - Identity: empty set (no taint)
/// - Compose: set union (taint only accumulates, never decreases)
///
/// The monoid laws hold trivially: union is associative with {} as identity.
/// This gives us O(1) taint checking vs. O(n) scanning of `Vec<Operation>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct TaintSet {
    private_data: bool,
    untrusted_content: bool,
    exfil_vector: bool,
}

impl TaintSet {
    /// Empty taint set (no trifecta legs touched).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a taint set from a single label.
    pub fn singleton(label: TaintLabel) -> Self {
        let mut s = Self::empty();
        match label {
            TaintLabel::PrivateData => s.private_data = true,
            TaintLabel::UntrustedContent => s.untrusted_content = true,
            TaintLabel::ExfilVector => s.exfil_vector = true,
        }
        s
    }

    /// Union of two taint sets (the monoid operation).
    pub fn union(&self, other: &Self) -> Self {
        Self {
            private_data: self.private_data || other.private_data,
            untrusted_content: self.untrusted_content || other.untrusted_content,
            exfil_vector: self.exfil_vector || other.exfil_vector,
        }
    }

    /// Check if the complete trifecta is present.
    pub fn is_trifecta_complete(&self) -> bool {
        self.private_data && self.untrusted_content && self.exfil_vector
    }

    /// Convert to the corresponding TrifectaRisk level.
    pub fn to_risk(&self) -> TrifectaRisk {
        let count =
            self.private_data as u8 + self.untrusted_content as u8 + self.exfil_vector as u8;
        match count {
            0 => TrifectaRisk::None,
            1 => TrifectaRisk::Low,
            2 => TrifectaRisk::Medium,
            _ => TrifectaRisk::Complete,
        }
    }

    /// Check if a specific taint label is present.
    pub fn contains(&self, label: TaintLabel) -> bool {
        match label {
            TaintLabel::PrivateData => self.private_data,
            TaintLabel::UntrustedContent => self.untrusted_content,
            TaintLabel::ExfilVector => self.exfil_vector,
        }
    }

    /// Number of active taint legs.
    pub fn count(&self) -> u8 {
        self.private_data as u8 + self.untrusted_content as u8 + self.exfil_vector as u8
    }
}

impl std::fmt::Display for TaintSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut labels = Vec::new();
        if self.private_data {
            labels.push("PrivateData");
        }
        if self.untrusted_content {
            labels.push("UntrustedContent");
        }
        if self.exfil_vector {
            labels.push("ExfilVector");
        }
        if labels.is_empty() {
            write!(f, "{{}}")
        } else {
            write!(f, "{{{}}}", labels.join(", "))
        }
    }
}

impl crate::graded::RiskGrade for TaintSet {
    fn identity() -> Self {
        Self::empty()
    }

    fn compose(&self, other: &Self) -> Self {
        self.union(other)
    }

    fn requires_intervention(&self) -> bool {
        self.is_trifecta_complete()
    }
}

/// Classify an operation into its taint label.
///
/// This is the labeling function `λ: Operation → Option<TaintLabel>` that
/// tags each tool call with which trifecta leg it contributes to.
/// Neutral operations (WriteFiles, EditFiles, GitCommit, ManagePods)
/// return `None` — they don't contribute to the trifecta.
///
/// Delegates to [`crate::taint_core::classify_operation`] — the verified
/// shared kernel.
pub fn operation_taint(op: Operation) -> Option<TaintLabel> {
    crate::taint_core::classify_operation(op)
}

/// Session-scoped taint-tracking guard using the graded monad.
///
/// Each tool call is modeled as `Graded<TaintSet, Operation>` — the taint
/// label is the grade, the operation is the value. The session's accumulated
/// state is the monadic composition (>>=) of all recorded tool calls.
///
/// This is the **beautiful** counterpart to [`RuntimeTrifectaGuard`]:
/// - `RuntimeTrifectaGuard`: tracks `Vec<Operation>`, rescans O(n)
/// - `GradedTaintGuard`: tracks `TaintSet` (3 bits), O(1) per check
///
/// Both produce identical decisions. The graded version makes the
/// mathematical structure explicit: taint propagation is a monoid
/// homomorphism from operation sequences to the taint semilattice.
///
/// # Schema Pinning
///
/// At session init, the full tool schema is SHA-256 hashed. Before each
/// tool call, the schema can be verified against this pin. A mismatch
/// indicates an MCP rug-pull attack.
pub struct GradedTaintGuard {
    /// Static permission lattice for this session
    perms: PermissionLattice,
    /// Accumulated taint from all recorded operations (the grade accumulator)
    taint: RwLock<TaintSet>,
    /// Pinned SHA-256 of tool schema at session init
    pinned_schema_hash: String,
}

impl GradedTaintGuard {
    /// Create a new session guard.
    ///
    /// `tool_schemas` is a canonical string representation of the available
    /// tools, hashed at construction for rug-pull detection.
    pub fn new(perms: PermissionLattice, tool_schemas: &str) -> Self {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(tool_schemas.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        Self {
            perms,
            taint: RwLock::new(TaintSet::empty()),
            pinned_schema_hash: hash,
        }
    }

    /// Get the current taint set.
    pub fn taint(&self) -> TaintSet {
        self.taint.read().expect("taint lock poisoned").clone()
    }

    /// Get the underlying permission lattice.
    pub fn permissions(&self) -> &PermissionLattice {
        &self.perms
    }

    /// Get the pinned schema hash.
    pub fn schema_hash(&self) -> &str {
        &self.pinned_schema_hash
    }
}

impl ToolCallGuard for GradedTaintGuard {
    fn check(&self, operation: Operation) -> Result<(), GuardError> {
        use crate::CapabilityLevel;

        // Layer 1: Capability level check (is the operation allowed at all?)
        let level = self.perms.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return Err(GuardError::Denied {
                reason: format!("{:?} denied: capability level is Never", operation),
            });
        }

        // Layer 2: Session taint projection via verified shared kernel
        //
        // Delegates to taint_core::should_deny — the pure decision function
        // whose logic is structurally bisimilar to the Verus exec fn
        // `exec_guard_check`.
        let current = self.taint.read().expect("taint lock poisoned");
        if crate::taint_core::should_deny(
            &current,
            operation,
            self.perms.requires_approval(operation),
            self.perms.trifecta_constraint,
        ) {
            let projected = crate::taint_core::project_taint(&current, operation);
            return Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: would complete trifecta (taint: {} → {})",
                    operation, current, projected,
                ),
            });
        }

        Ok(())
    }

    fn record(&self, operation: Operation) {
        let mut taint = self.taint.write().expect("taint lock poisoned");
        *taint = crate::taint_core::apply_record(&taint, operation);
    }

    fn accumulated_risk(&self) -> TrifectaRisk {
        self.taint.read().expect("taint lock poisoned").to_risk()
    }

    fn verify_schema(&self, current_hash: &str) -> Result<(), GuardError> {
        if current_hash != self.pinned_schema_hash {
            Err(GuardError::Denied {
                reason: format!(
                    "tool schema hash mismatch: pinned={}, current={} (possible rug-pull attack)",
                    self.pinned_schema_hash, current_hash,
                ),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TestPathGuard {
        blocked: Vec<String>,
    }

    impl PermissionGuard for TestPathGuard {
        type Action = PathBuf;
        type Error = String;

        fn guard(&self, path: PathBuf) -> Result<GuardedAction<PathBuf>, GuardError<String>> {
            let path_str = path.to_string_lossy();
            for blocked in &self.blocked {
                if path_str.contains(blocked) {
                    return Err(GuardError::Blocked {
                        blocker: blocked.clone(),
                    });
                }
            }
            Ok(GuardedAction::new(path))
        }
    }

    #[test]
    fn test_guard_allows_valid_path() {
        let guard = TestPathGuard {
            blocked: vec![".env".to_string()],
        };

        let result = guard.guard(PathBuf::from("src/main.rs"));
        assert!(result.is_ok());

        let guarded = result.unwrap();
        assert_eq!(guarded.action(), &PathBuf::from("src/main.rs"));
    }

    #[test]
    fn test_guard_blocks_sensitive_path() {
        let guard = TestPathGuard {
            blocked: vec![".env".to_string()],
        };

        let result = guard.guard(PathBuf::from(".env"));
        assert!(result.is_err());

        match result {
            Err(GuardError::Blocked { blocker }) => {
                assert_eq!(blocker, ".env");
            }
            _ => panic!("Expected Blocked error"),
        }
    }

    #[test]
    fn test_guarded_action_cannot_be_constructed_externally() {
        // This test documents that GuardedAction cannot be constructed
        // outside this module due to the private field.
        //
        // If you uncomment the following line, it will fail to compile:
        // let _action = GuardedAction { action: 42, _private: () };
    }

    #[test]
    fn test_composite_guard() {
        let guard = CompositeGuard::<i32, String>::new()
            .with_guard(|n| {
                if *n < 0 {
                    Err(GuardError::Denied {
                        reason: "negative".to_string(),
                    })
                } else {
                    Ok(())
                }
            })
            .with_guard(|n| {
                if *n > 100 {
                    Err(GuardError::Denied {
                        reason: "too large".to_string(),
                    })
                } else {
                    Ok(())
                }
            });

        // Valid value passes all guards
        assert!(guard.guard(50).is_ok());

        // Negative fails first guard
        assert!(matches!(
            guard.guard(-5),
            Err(GuardError::Denied { reason }) if reason == "negative"
        ));

        // Too large fails second guard
        assert!(matches!(
            guard.guard(150),
            Err(GuardError::Denied { reason }) if reason == "too large"
        ));
    }

    #[test]
    fn test_guarded_action_map() {
        let guard = TestPathGuard { blocked: vec![] };

        let result = guard.guard(PathBuf::from("test.txt"));
        let guarded = result.unwrap();

        // Map to string
        let string_action = guarded.map(|p| p.to_string_lossy().to_string());
        assert_eq!(string_action.into_action(), "test.txt");
    }

    #[test]
    fn test_guarded_action_and_then() {
        let guard = TestPathGuard {
            blocked: vec![".env".to_string()],
        };

        // Successful chain: read src, then read lib
        let result = guard
            .guard(PathBuf::from("src/main.rs"))
            .and_then(|_| guard.guard(PathBuf::from("lib/utils.rs")));
        assert!(result.is_ok());

        // Chain fails on second guard
        let result = guard
            .guard(PathBuf::from("src/main.rs"))
            .and_then(|_| guard.guard(PathBuf::from(".env")));
        assert!(result.is_err());

        // Chain fails on first guard (second never runs)
        let result = guard
            .guard(PathBuf::from(".env"))
            .and_then(|_| guard.guard(PathBuf::from("src/main.rs")));
        assert!(result.is_err());
    }

    #[test]
    fn test_guarded_action_try_map() {
        let guard = TestPathGuard { blocked: vec![] };

        // Successful try_map
        let result: Result<GuardedAction<String>, GuardError<String>> = guard
            .guard(PathBuf::from("test.txt"))
            .unwrap()
            .try_map(|p| Ok::<_, String>(p.to_string_lossy().to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().into_action(), "test.txt");

        // Failed try_map
        let result: Result<GuardedAction<String>, GuardError<String>> = guard
            .guard(PathBuf::from("test.txt"))
            .unwrap()
            .try_map(|_| Err::<String, _>("io error".to_string()));
        assert!(matches!(result, Err(GuardError::CheckFailed { .. })));
    }

    #[test]
    fn test_graded_guard_safe_profile() {
        let perms = PermissionLattice::read_only();
        let guard = GradedGuard::new(perms);

        // read_only has only private data access (read_files: Always)
        // so risk should be Low (1 trifecta component)
        assert_eq!(guard.risk(), TrifectaRisk::Low);

        // ReadFile operation should be allowed
        let result = guard.check_operation(Operation::ReadFiles);
        assert!(result.value.is_ok());
        assert_eq!(result.grade, TrifectaRisk::Low);
    }

    #[test]
    fn test_graded_guard_permissive_denies_trifecta_exfiltration() {
        let perms = PermissionLattice::permissive();
        let guard = GradedGuard::new(perms);

        // Permissive has full trifecta
        assert_eq!(guard.risk(), TrifectaRisk::Complete);

        // Exfiltration operations that require approval should be denied
        let result = guard.check_operation(Operation::GitPush);
        assert_eq!(result.grade, TrifectaRisk::Complete);
        // GitPush requires approval under trifecta, so it should be denied
        assert!(result.value.is_err());
    }

    #[test]
    fn test_graded_guard_path_check() {
        use crate::PathLattice;
        use std::collections::HashSet;

        let perms = PermissionLattice {
            paths: PathLattice {
                allowed: HashSet::from(["**/*.rs".to_string()]),
                blocked: HashSet::from([".env*".to_string()]),
                work_dir: None,
            },
            ..Default::default()
        };
        let guard = GradedGuard::new(perms);

        // .rs files should be allowed
        let result = guard.check_path("src/lib.rs");
        assert!(result.value.is_ok());

        // .env files should be denied
        let result = guard.check_path(".env");
        assert!(result.value.is_err());
    }

    #[test]
    fn test_graded_guard_permission_gap() {
        use crate::CapabilityLevel;

        let floor = PermissionLattice::read_only();
        let mut target = PermissionLattice::read_only();
        target.capabilities.git_push = CapabilityLevel::Always;
        target.capabilities.web_fetch = CapabilityLevel::LowRisk;

        let guard = GradedGuard::new(floor);
        let gap = guard.permission_gap_to(&target);

        // Target has more trifecta components, so risk is higher
        assert!(gap.grade >= TrifectaRisk::Medium);

        // The gap should show what's needed for the capabilities
        // that the floor doesn't have
        assert_eq!(gap.value.git_push, CapabilityLevel::Always);
        assert_eq!(gap.value.web_fetch, CapabilityLevel::Always);
    }

    #[test]
    fn test_graded_guard_compose_checks() {
        let perms = PermissionLattice::read_only();
        let guard = GradedGuard::new(perms);

        // Compose two graded checks using and_then
        let result = guard
            .check_path("/workspace/src/lib.rs")
            .and_then(|first_result| {
                // Only proceed if first check passed
                match first_result {
                    Ok(_) => guard.check_operation(Operation::ReadFiles),
                    Err(e) => Graded::new(guard.risk(), Err(e)),
                }
            });

        // Risk should be composed (max of both checks)
        assert_eq!(result.grade, TrifectaRisk::Low);
        assert!(result.value.is_ok());
    }

    // -----------------------------------------------------------------------
    // RuntimeTrifectaGuard tests
    // -----------------------------------------------------------------------

    fn trifecta_perms() -> PermissionLattice {
        use crate::CapabilityLevel;
        let mut perms = PermissionLattice::default();
        perms.capabilities.read_files = CapabilityLevel::Always;
        perms.capabilities.web_fetch = CapabilityLevel::LowRisk;
        perms.capabilities.run_bash = CapabilityLevel::LowRisk;
        perms.trifecta_constraint = true;
        perms.normalize()
    }

    #[test]
    fn test_session_risk_accumulates() {
        let guard = RuntimeTrifectaGuard::new(trifecta_perms(), "[]");

        // Start at None
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::None);

        // Read (private data leg)
        assert!(guard.check(Operation::ReadFiles).is_ok());
        guard.record(Operation::ReadFiles);
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Low);

        // Fetch (untrusted content leg)
        assert!(guard.check(Operation::WebFetch).is_ok());
        guard.record(Operation::WebFetch);
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Medium);

        // RunBash (exfil leg) — should be BLOCKED because it completes trifecta
        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "RunBash should be blocked when completing trifecta"
        );

        // Risk stays at Medium (RunBash was not recorded)
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Medium);
    }

    #[test]
    fn test_no_phantom_risk() {
        let guard = RuntimeTrifectaGuard::new(trifecta_perms(), "[]");

        // check() alone does NOT increase risk
        assert!(guard.check(Operation::ReadFiles).is_ok());
        assert!(guard.check(Operation::WebFetch).is_ok());
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::None);

        // Only record() increases risk
        guard.record(Operation::ReadFiles);
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Low);
    }

    #[test]
    fn test_benign_sequence_allowed() {
        let guard = RuntimeTrifectaGuard::new(trifecta_perms(), "[]");

        // Read, glob, grep — all private data, only 1 trifecta component
        guard.record(Operation::ReadFiles);
        guard.record(Operation::GlobSearch);
        guard.record(Operation::GrepSearch);
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Low);

        // More reads are always fine
        assert!(guard.check(Operation::ReadFiles).is_ok());
    }

    #[test]
    fn test_schema_pinning_detects_mutation() {
        let guard = RuntimeTrifectaGuard::new(trifecta_perms(), r#"[{"name":"read"}]"#);

        // Same schema: OK
        let mut hasher = Sha256::new();
        hasher.update(r#"[{"name":"read"}]"#.as_bytes());
        let same_hash = format!("{:x}", hasher.finalize());
        assert!(guard.verify_schema(&same_hash).is_ok());

        // Different schema: rug-pull detected
        let mut hasher = Sha256::new();
        hasher.update(r#"[{"name":"read"},{"name":"evil"}]"#.as_bytes());
        let different_hash = format!("{:x}", hasher.finalize());
        assert!(guard.verify_schema(&different_hash).is_err());
    }

    #[test]
    fn test_two_leg_trifecta_allows_exfil() {
        // If only 2 of 3 trifecta legs are present in permissions,
        // exfil should be allowed (no trifecta constraint fires)
        use crate::CapabilityLevel;
        let mut perms = PermissionLattice::default();
        perms.capabilities.read_files = CapabilityLevel::Always;
        perms.capabilities.run_bash = CapabilityLevel::LowRisk;
        // No web_fetch — only 2 legs
        perms.trifecta_constraint = true;
        let perms = perms.normalize();

        let guard = RuntimeTrifectaGuard::new(perms, "[]");

        guard.record(Operation::ReadFiles);
        // RunBash should be allowed — no untrusted content present
        assert!(guard.check(Operation::RunBash).is_ok());
        guard.record(Operation::RunBash);
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Medium);
    }

    // -----------------------------------------------------------------------
    // TaintSet monoid laws
    // -----------------------------------------------------------------------

    #[test]
    fn test_taint_set_identity() {
        let empty = TaintSet::empty();
        let s = TaintSet::singleton(TaintLabel::PrivateData);

        // Left identity: empty ∪ s = s
        assert_eq!(empty.union(&s), s);
        // Right identity: s ∪ empty = s
        assert_eq!(s.union(&empty), s);
    }

    #[test]
    fn test_taint_set_associativity() {
        let a = TaintSet::singleton(TaintLabel::PrivateData);
        let b = TaintSet::singleton(TaintLabel::UntrustedContent);
        let c = TaintSet::singleton(TaintLabel::ExfilVector);

        // (a ∪ b) ∪ c = a ∪ (b ∪ c)
        assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn test_taint_set_idempotent() {
        let s = TaintSet::singleton(TaintLabel::PrivateData);
        // s ∪ s = s (semilattice: join is idempotent)
        assert_eq!(s.union(&s), s);
    }

    #[test]
    fn test_taint_set_commutative() {
        let a = TaintSet::singleton(TaintLabel::PrivateData);
        let b = TaintSet::singleton(TaintLabel::UntrustedContent);
        // a ∪ b = b ∪ a
        assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn test_taint_set_trifecta_detection() {
        let mut taint = TaintSet::empty();
        assert!(!taint.is_trifecta_complete());
        assert_eq!(taint.to_risk(), TrifectaRisk::None);

        taint = taint.union(&TaintSet::singleton(TaintLabel::PrivateData));
        assert!(!taint.is_trifecta_complete());
        assert_eq!(taint.to_risk(), TrifectaRisk::Low);

        taint = taint.union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        assert!(!taint.is_trifecta_complete());
        assert_eq!(taint.to_risk(), TrifectaRisk::Medium);

        taint = taint.union(&TaintSet::singleton(TaintLabel::ExfilVector));
        assert!(taint.is_trifecta_complete());
        assert_eq!(taint.to_risk(), TrifectaRisk::Complete);
    }

    #[test]
    fn test_taint_set_risk_grade_impl() {
        use crate::graded::RiskGrade;

        // Identity
        assert_eq!(TaintSet::identity(), TaintSet::empty());

        // Compose = union
        let a = TaintSet::singleton(TaintLabel::PrivateData);
        let b = TaintSet::singleton(TaintLabel::ExfilVector);
        let composed = a.compose(&b);
        assert!(composed.contains(TaintLabel::PrivateData));
        assert!(composed.contains(TaintLabel::ExfilVector));
        assert!(!composed.contains(TaintLabel::UntrustedContent));

        // requires_intervention only at Complete
        assert!(!a.requires_intervention());
        assert!(!composed.requires_intervention());
        let full = composed.compose(&TaintSet::singleton(TaintLabel::UntrustedContent));
        assert!(full.requires_intervention());
    }

    #[test]
    fn test_taint_set_display() {
        assert_eq!(format!("{}", TaintSet::empty()), "{}");
        assert_eq!(
            format!("{}", TaintSet::singleton(TaintLabel::PrivateData)),
            "{PrivateData}"
        );
        let full = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector));
        assert_eq!(
            format!("{}", full),
            "{PrivateData, UntrustedContent, ExfilVector}"
        );
    }

    #[test]
    fn test_operation_taint_classification() {
        // Private data leg
        assert_eq!(
            operation_taint(Operation::ReadFiles),
            Some(TaintLabel::PrivateData)
        );
        assert_eq!(
            operation_taint(Operation::GlobSearch),
            Some(TaintLabel::PrivateData)
        );
        assert_eq!(
            operation_taint(Operation::GrepSearch),
            Some(TaintLabel::PrivateData)
        );

        // Untrusted content leg
        assert_eq!(
            operation_taint(Operation::WebFetch),
            Some(TaintLabel::UntrustedContent)
        );
        assert_eq!(
            operation_taint(Operation::WebSearch),
            Some(TaintLabel::UntrustedContent)
        );

        // Exfil vector leg
        assert_eq!(
            operation_taint(Operation::RunBash),
            Some(TaintLabel::ExfilVector)
        );
        assert_eq!(
            operation_taint(Operation::GitPush),
            Some(TaintLabel::ExfilVector)
        );
        assert_eq!(
            operation_taint(Operation::CreatePr),
            Some(TaintLabel::ExfilVector)
        );

        // Neutral operations
        assert_eq!(operation_taint(Operation::WriteFiles), None);
        assert_eq!(operation_taint(Operation::EditFiles), None);
        assert_eq!(operation_taint(Operation::GitCommit), None);
        assert_eq!(operation_taint(Operation::ManagePods), None);
    }

    // -----------------------------------------------------------------------
    // GradedTaintGuard tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_graded_taint_guard_risk_accumulates() {
        let guard = GradedTaintGuard::new(trifecta_perms(), "[]");

        // Start at empty taint
        assert_eq!(guard.taint(), TaintSet::empty());
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::None);

        // Read (private data)
        assert!(guard.check(Operation::ReadFiles).is_ok());
        guard.record(Operation::ReadFiles);
        assert!(guard.taint().contains(TaintLabel::PrivateData));
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Low);

        // Fetch (untrusted content)
        assert!(guard.check(Operation::WebFetch).is_ok());
        guard.record(Operation::WebFetch);
        assert!(guard.taint().contains(TaintLabel::UntrustedContent));
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Medium);

        // RunBash (exfil) — BLOCKED: would complete trifecta
        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "RunBash should be blocked when completing trifecta"
        );
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::Medium);
    }

    #[test]
    fn test_graded_taint_guard_no_phantom_taint() {
        let guard = GradedTaintGuard::new(trifecta_perms(), "[]");

        // check() alone does NOT taint the session
        assert!(guard.check(Operation::ReadFiles).is_ok());
        assert!(guard.check(Operation::WebFetch).is_ok());
        assert_eq!(guard.taint(), TaintSet::empty());

        // Only record() taints
        guard.record(Operation::ReadFiles);
        assert!(guard.taint().contains(TaintLabel::PrivateData));
    }

    #[test]
    fn test_graded_taint_guard_neutral_ops_no_taint() {
        let guard = GradedTaintGuard::new(trifecta_perms(), "[]");

        guard.record(Operation::WriteFiles);
        guard.record(Operation::EditFiles);
        guard.record(Operation::GitCommit);

        // Neutral ops don't contribute to taint
        assert_eq!(guard.taint(), TaintSet::empty());
        assert_eq!(guard.accumulated_risk(), TrifectaRisk::None);
    }

    #[test]
    fn test_graded_taint_guard_schema_pinning() {
        let guard = GradedTaintGuard::new(trifecta_perms(), r#"[{"name":"read"}]"#);

        // Same schema: OK
        let same_hash = {
            let mut h = Sha256::new();
            h.update(r#"[{"name":"read"}]"#.as_bytes());
            format!("{:x}", h.finalize())
        };
        assert!(guard.verify_schema(&same_hash).is_ok());

        // Mutated schema: rug-pull detected
        let evil_hash = {
            let mut h = Sha256::new();
            h.update(r#"[{"name":"read"},{"name":"evil_tool"}]"#.as_bytes());
            format!("{:x}", h.finalize())
        };
        let result = guard.verify_schema(&evil_hash);
        assert!(result.is_err());
        if let Err(GuardError::Denied { reason }) = result {
            assert!(
                reason.contains("rug-pull"),
                "error should mention rug-pull: {reason}"
            );
        }
    }

    #[test]
    fn test_graded_taint_guard_agrees_with_runtime_guard() {
        // Both guards should make identical decisions
        let perms = trifecta_perms();
        let runtime = RuntimeTrifectaGuard::new(perms.clone(), "[]");
        let graded = GradedTaintGuard::new(perms, "[]");

        let ops = vec![
            Operation::ReadFiles,
            Operation::GlobSearch,
            Operation::WebFetch,
        ];

        for op in &ops {
            let r1 = runtime.check(*op);
            let r2 = graded.check(*op);
            assert_eq!(r1.is_ok(), r2.is_ok(), "disagreement on {:?}", op);

            if r1.is_ok() {
                runtime.record(*op);
                graded.record(*op);
            }
        }

        // Both should block RunBash now (trifecta complete)
        assert!(runtime.check(Operation::RunBash).is_err());
        assert!(graded.check(Operation::RunBash).is_err());

        // Both report same risk
        assert_eq!(runtime.accumulated_risk(), graded.accumulated_risk());
    }

    #[test]
    fn test_graded_taint_guard_as_graded_monad() {
        // Demonstrate the graded monad composition explicitly
        use crate::graded::{Graded, RiskGrade};

        let guard = GradedTaintGuard::new(trifecta_perms(), "[]");

        // Model each tool call as Graded<TaintSet, Operation>
        let read_call = Graded::new(
            TaintSet::singleton(TaintLabel::PrivateData),
            Operation::ReadFiles,
        );
        let fetch_call = Graded::new(
            TaintSet::singleton(TaintLabel::UntrustedContent),
            Operation::WebFetch,
        );

        // Compose via >>= (and_then): taint accumulates through the monoid
        let composed = read_call.and_then(|_| fetch_call);

        // The composed grade is the union of both taint sets
        assert!(composed.grade.contains(TaintLabel::PrivateData));
        assert!(composed.grade.contains(TaintLabel::UntrustedContent));
        assert!(!composed.grade.contains(TaintLabel::ExfilVector));
        assert_eq!(composed.grade.to_risk(), TrifectaRisk::Medium);

        // Adding an exfil call would complete the trifecta
        let exfil_call = Graded::new(
            TaintSet::singleton(TaintLabel::ExfilVector),
            Operation::RunBash,
        );
        let full = composed.and_then(|_| exfil_call);
        assert!(full.grade.is_trifecta_complete());
        assert!(full.grade.requires_intervention());

        // This is exactly what the guard does internally, but with
        // RwLock state instead of pure functional composition
        guard.record(Operation::ReadFiles);
        guard.record(Operation::WebFetch);
        assert!(guard.check(Operation::RunBash).is_err());
    }

    /// Clinejection attack (Feb 2026): prompt injection in a GitHub issue
    /// triggers `npm install` via an AI coding assistant. The preinstall
    /// hook exfiltrates credentials.
    ///
    /// Portcullis must block this even WITHOUT a prior ReadFiles:
    ///   WebFetch(UntrustedContent) → RunBash(projected: PrivateData+ExfilVector)
    ///   = all 3 trifecta legs → DENIED.
    #[test]
    fn test_clinejection_blocked() {
        let guard = GradedTaintGuard::new(trifecta_perms(), "[]");

        // Step 1: Read untrusted content (GitHub issue via WebFetch)
        assert!(guard.check(Operation::WebFetch).is_ok());
        guard.record(Operation::WebFetch);

        // Step 2: Attempt RunBash (npm install from attacker).
        // RunBash projects PrivateData + ExfilVector (omnibus),
        // completing the trifecta with UntrustedContent.
        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "Clinejection: RunBash after WebFetch must be denied (omnibus projection)"
        );

        // The taint should NOT have changed (check doesn't taint)
        assert!(!guard.taint().contains(TaintLabel::PrivateData));
        assert!(!guard.taint().contains(TaintLabel::ExfilVector));
    }

    /// Verify that RunBash also triggers trifecta in the RuntimeTrifectaGuard.
    #[test]
    fn test_clinejection_runtime_guard() {
        let perms = trifecta_perms();
        let guard = RuntimeTrifectaGuard::new(perms, "[]");

        // WebFetch then RunBash — should complete trifecta
        assert!(guard.check(Operation::WebFetch).is_ok());
        guard.record(Operation::WebFetch);

        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "Clinejection: RuntimeTrifectaGuard must also block WebFetch → RunBash"
        );
    }
}
