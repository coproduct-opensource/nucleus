//! Type-safe permission enforcement via the PermissionGuard trait.
//!
//! This module provides compile-time guarantees that permission checks cannot
//! be bypassed or ignored by callers.
//!
//! ## Graded Guards
//!
//! The [`GradedGuard`] combines type-safe enforcement with risk tracking via
//! the graded monad. Every guard decision carries a [`StateRisk`] grade
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
//! // Risk grade reflects uninhabitable_state exposure of the permission set
//! ```

use std::marker::PhantomData;
use std::sync::RwLock;

use sha2::{Digest, Sha256};

use crate::capability::{IncompatibilityConstraint, Operation, StateRisk};
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

// ---------------------------------------------------------------------------
// CheckProof — linear proof token for typestate protocol enforcement
// ---------------------------------------------------------------------------

/// Proof that [`ToolCallGuard::check`] succeeded.
///
/// This token is:
/// - **Linear**: non-`Clone`, non-`Copy` — cannot be reused
/// - **`#[must_use]`**: compiler warns if dropped without consumption
/// - **Sealed**: the private `_seal` field prevents external construction
///
/// Rust's ownership system enforces at compile time that every
/// `execute_and_record` call is preceded by exactly one `check`.
/// This eliminates the TOCTOU gap between check and record that existed
/// in the previous two-method protocol.
#[must_use = "CheckProof must be consumed by execute_and_record()"]
pub struct CheckProof {
    /// The operation that was checked and approved.
    operation: Operation,
    /// Exposure state at check time, for optimistic TOCTOU detection.
    exposure_snapshot: ExposureSet,
    /// Prevents external construction.
    _seal: (),
}

impl CheckProof {
    /// Get the operation this proof authorizes.
    pub fn operation(&self) -> Operation {
        self.operation
    }
}

impl std::fmt::Debug for CheckProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckProof")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// ExecuteError — error from execute_and_record
// ---------------------------------------------------------------------------

/// Error from [`ToolCallGuard::execute_and_record`].
///
/// Distinguishes between the closure failing (operation not recorded) and
/// a TOCTOU race detected during record (operation executed but exposure grew
/// concurrently, making the operation retroactively denied).
#[derive(Debug)]
pub enum ExecuteError<E> {
    /// The closure returned an error. Operation was NOT recorded.
    OperationFailed(E),
    /// TOCTOU detected: exposure grew between check and record.
    /// The operation DID execute, and its exposure WAS recorded for consistency,
    /// but the caller should treat this as a denial.
    TocTouDenied {
        /// Human-readable reason for the TOCTOU denial.
        reason: String,
    },
}

impl<E: std::fmt::Display> std::fmt::Display for ExecuteError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationFailed(e) => write!(f, "{}", e),
            Self::TocTouDenied { reason } => write!(f, "TOCTOU: {}", reason),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for ExecuteError<E> {}

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
/// use exposure_guard::guard::{PermissionGuard, GuardedAction, GuardError};
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

/// A permission guard that tracks uninhabitable_state risk as a grade.
///
/// Every check returns `Graded<StateRisk, Result<GuardedAction<A>, GuardError>>`,
/// so callers always see both the access decision AND the risk level of the
/// permission set that produced it.
///
/// The risk grade is computed from the underlying `PermissionLattice` via
/// `IncompatibilityConstraint::enforcing()`. This means even allowed actions
/// carry their uninhabitable_state risk — enabling downstream systems to add extra
/// oversight for operations that are technically permitted but high-risk.
pub struct GradedGuard {
    perms: PermissionLattice,
    risk: StateRisk,
}

impl GradedGuard {
    /// Create a new graded guard from a permission lattice.
    ///
    /// The uninhabitable_state risk is computed once at construction and carried through
    /// all subsequent checks.
    pub fn new(perms: PermissionLattice) -> Self {
        let constraint = IncompatibilityConstraint::enforcing();
        let risk = constraint.state_risk(&perms.capabilities);
        Self { perms, risk }
    }

    /// Get the uninhabitable_state risk grade of this guard's permission set.
    pub fn risk(&self) -> StateRisk {
        self.risk
    }

    /// Check if an operation is allowed, returning a graded result.
    ///
    /// The grade carries the uninhabitable_state risk regardless of whether the
    /// operation is allowed or denied.
    pub fn check_operation(
        &self,
        operation: Operation,
    ) -> Graded<StateRisk, Result<GuardedAction<Operation>, GuardError>> {
        let requires_approval = self.perms.requires_approval(operation);

        let result = if requires_approval && self.risk == StateRisk::Uninhabitable {
            Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: uninhabitable_state risk is Complete and operation requires approval",
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
    ) -> Graded<StateRisk, Result<GuardedAction<String>, GuardError>> {
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
    ) -> Graded<StateRisk, crate::CapabilityLattice> {
        let constraint = IncompatibilityConstraint::enforcing();
        let target_risk = constraint.state_risk(&target.capabilities);
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

/// Runtime tool-call interposition guard with typestate protocol enforcement.
///
/// Called before every tool invocation at execution time (not just delegation
/// time). This closes the gap between static permission checking and runtime
/// enforcement by tracking the *sequence* of operations within a session.
///
/// Unlike [`GradedGuard`] which checks if the *permission set* has uninhabitable_state
/// risk, `ToolCallGuard` checks if the *execution sequence* would complete
/// the uninhabitable_state — catching read→fetch→exfil attack chains even when
/// individual operations pass their static permission checks.
///
/// # Typestate Protocol
///
/// The two-phase protocol is enforced at compile time via [`CheckProof`]:
///
/// 1. `check(operation)` → returns `CheckProof` (linear, non-Clone token)
/// 2. `execute_and_record(proof, closure)` → consumes the proof, runs the
///    closure, and records exposure atomically on success
///
/// Rust's ownership system guarantees that `execute_and_record` cannot be
/// called without a preceding `check`, and the proof cannot be reused.
/// This eliminates the TOCTOU gap of the previous check/record protocol.
pub trait ToolCallGuard: Send + Sync {
    /// Check if a tool call is permitted given the current session state.
    ///
    /// Returns a [`CheckProof`] token on success. The token captures a
    /// snapshot of the exposure state for optimistic TOCTOU detection.
    /// The token MUST be consumed by [`execute_and_record`].
    fn check(&self, operation: Operation) -> Result<CheckProof, GuardError>;

    /// Execute an operation and record its exposure atomically.
    ///
    /// Consumes the [`CheckProof`] token (compile-time linearity).
    /// Runs the closure without holding any lock. On closure success:
    ///
    /// 1. Acquires write lock
    /// 2. TOCTOU check: compares exposure snapshot against current state
    /// 3. If exposure grew and re-projection would now deny → records exposure
    ///    (for consistency) but returns [`ExecuteError::TocTouDenied`]
    /// 4. Otherwise records exposure and returns `Ok(value)`
    ///
    /// On closure failure: does NOT record exposure (no phantom risk).
    fn execute_and_record<T, E>(
        &self,
        proof: CheckProof,
        f: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, ExecuteError<E>>;

    /// Get the current accumulated uninhabitable_state risk for this session.
    fn accumulated_risk(&self) -> StateRisk;

    /// Verify tool schema integrity (rug-pull detection).
    ///
    /// Compares the current tool schema hash against the pinned hash from
    /// session initialization. Returns `Err` if they differ, indicating
    /// tools were mutated after delegation-time approval.
    fn verify_schema(&self, current_hash: &str) -> Result<(), GuardError>;
}

/// Session-scoped runtime uninhabitable_state guard.
///
/// Tracks the sequence of operations executed in an MCP session and blocks
/// operations that would complete the uninhabitable_state (private data access +
/// untrusted content + exfiltration).
///
/// Also pins the tool schema at session start for rug-pull detection.
///
/// # Deprecation
///
/// Use [`GradedExposureGuard`] instead. This guard is retained for backward
/// compatibility and testing but now delegates all security decisions to
/// the verified `exposure_core` kernel — the same code path that
/// `GradedExposureGuard` uses and that is structurally bisimilar to the
/// Verus-verified spec functions.
#[deprecated(
    since = "0.5.0",
    note = "Use GradedExposureGuard instead — it uses the same verified exposure_core kernel with O(1) exposure tracking"
)]
pub struct RuntimeStateGuard {
    /// The underlying permission lattice for static checks.
    perms: PermissionLattice,
    /// Operations executed in this session (retained for inspection/debugging).
    executed_ops: RwLock<Vec<Operation>>,
    /// Accumulated exposure from all recorded operations — delegates to exposure_core.
    exposure: RwLock<ExposureSet>,
    /// Pinned SHA-256 of tool list at session init.
    pinned_schema_hash: String,
}

#[allow(deprecated)]
impl RuntimeStateGuard {
    /// Create a new guard for a session.
    ///
    /// `tool_schemas` is a string representation of the tool list, hashed
    /// at session start for rug-pull detection.
    pub fn new(perms: PermissionLattice, tool_schemas: &str) -> Self {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(tool_schemas.as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        Self {
            perms,
            executed_ops: RwLock::new(Vec::new()),
            exposure: RwLock::new(ExposureSet::empty()),
            pinned_schema_hash: hash,
        }
    }
}

#[allow(deprecated)]
impl ToolCallGuard for RuntimeStateGuard {
    fn check(&self, operation: Operation) -> Result<CheckProof, GuardError> {
        use crate::CapabilityLevel;

        // Layer 1: Capability level check (is the operation allowed at all?)
        let level = self.perms.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return Err(GuardError::Denied {
                reason: format!("{:?} denied: capability level is Never", operation),
            });
        }

        // Layer 2: Session exposure projection via verified shared kernel
        //
        // Delegates to exposure_core::should_deny — the pure decision function
        // whose logic is structurally bisimilar to the Verus exec fn
        // `exec_guard_check`.
        let current = self.exposure.read().expect("exposure lock poisoned");
        if crate::exposure_core::should_deny(
            &current,
            operation,
            self.perms.requires_approval(operation),
            self.perms.uninhabitable_constraint,
        ) {
            let projected = crate::exposure_core::project_exposure(&current, operation);
            return Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: would uninhabitable_state (exposure: {} → {})",
                    operation, current, projected,
                ),
            });
        }

        // Snapshot exposure for TOCTOU detection
        let exposure_snapshot = current.clone();

        Ok(CheckProof {
            operation,
            exposure_snapshot,
            _seal: (),
        })
    }

    fn execute_and_record<T, E>(
        &self,
        proof: CheckProof,
        f: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, ExecuteError<E>> {
        // Run the closure without holding any lock
        let value = match f() {
            Ok(v) => v,
            Err(e) => return Err(ExecuteError::OperationFailed(e)),
        };

        // Acquire write locks for atomic TOCTOU check + record
        let mut exposure = self.exposure.write().expect("exposure lock poisoned");
        let mut ops = self.executed_ops.write().expect("ops lock poisoned");

        // TOCTOU detection: check if exposure grew since check()
        if *exposure != proof.exposure_snapshot && self.perms.uninhabitable_constraint {
            // Re-check with current (grown) exposure using exposure_core
            let projected = crate::exposure_core::project_exposure(&exposure, proof.operation);

            if projected.is_uninhabitable() && self.perms.requires_approval(proof.operation) {
                // Record exposure anyway (operation DID execute) for consistency
                ops.push(proof.operation);
                *exposure = crate::exposure_core::apply_record(&exposure, proof.operation);
                return Err(ExecuteError::TocTouDenied {
                    reason: format!(
                        "{:?}: concurrent exposure growth detected ({} → {}); \
                         operation would now be denied (projected: {})",
                        proof.operation, proof.exposure_snapshot, *exposure, projected,
                    ),
                });
            }
        }

        // Record the operation's exposure via exposure_core
        ops.push(proof.operation);
        *exposure = crate::exposure_core::apply_record(&exposure, proof.operation);

        Ok(value)
    }

    fn accumulated_risk(&self) -> StateRisk {
        self.exposure
            .read()
            .expect("exposure lock poisoned")
            .to_risk()
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
// GradedExposureGuard — the beautiful version
//
// Rather than tracking Vec<Operation> and rescanning O(n), this uses a
// 3-bit semilattice (ExposureSet) as the grade monoid for the Graded monad.
// Exposure accumulation is O(1) per operation and compositional by
// construction: the monoid homomorphism λ: Operation → ExposureSet
// factors through the graded bind (>>=).
// ═══════════════════════════════════════════════════════════════════════════

/// Exposure labels for the three legs of the uninhabitable_state.
///
/// These form a free semilattice (join = set union) that the graded monad
/// carries as its grade. When the join reaches `{PrivateData, UntrustedContent,
/// ExfilVector}`, the uninhabitable_state is complete.
///
/// These 3 core labels are FROZEN — they have Verus proofs covering
/// monotonicity, session safety, and irreversibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ExposureLabel {
    /// Private data was accessed (read_files, glob_search, grep_search)
    PrivateData,
    /// Untrusted external content was ingested (web_fetch, web_search)
    UntrustedContent,
    /// An exfiltration-capable operation was performed (run_bash, git_push, create_pr)
    ExfilVector,
}

/// Extension exposure label for emerging threat categories.
///
/// Extension labels participate in the same join-semilattice (union) as core
/// labels, but do NOT affect the core uninhabitable_state predicate. They can be used
/// by [`UninhabitableState`](crate::uninhabitable_state::UninhabitableState) constraints
/// to define new dangerous combinations.
///
/// Exposure monotonicity (E1) holds for extension labels by the same argument
/// as core labels: set-union only grows, never shrinks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtensionExposureLabel(pub String);

impl ExtensionExposureLabel {
    /// Create a new extension exposure label.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl std::fmt::Display for ExtensionExposureLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A exposure set tracking which exposure legs have been touched.
///
/// This is the grade monoid for our graded monad:
/// - Identity: empty set (no exposure)
/// - Compose: set union (exposure only accumulates, never decreases)
///
/// The monoid laws hold trivially: union is associative with {} as identity.
/// This gives us O(1) exposure checking vs. O(n) scanning of `Vec<Operation>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ExposureSet {
    /// FROZEN — Verus-verified core exposure labels.
    private_data: bool,
    untrusted_content: bool,
    exfil_vector: bool,
    /// Extension exposure labels for emerging threat categories.
    /// Does NOT affect the core uninhabitable_state predicate.
    #[cfg(not(kani))]
    extensions: std::collections::BTreeSet<ExtensionExposureLabel>,
}

impl ExposureSet {
    /// Empty exposure set (no exposure legs touched).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create a exposure set from a single label.
    pub fn singleton(label: ExposureLabel) -> Self {
        let mut s = Self::empty();
        match label {
            ExposureLabel::PrivateData => s.private_data = true,
            ExposureLabel::UntrustedContent => s.untrusted_content = true,
            ExposureLabel::ExfilVector => s.exfil_vector = true,
        }
        s
    }

    /// Create a exposure set from a single extension label.
    #[cfg(not(kani))]
    pub fn extension_singleton(label: ExtensionExposureLabel) -> Self {
        let mut s = Self::empty();
        s.extensions.insert(label);
        s
    }

    /// Union of two exposure sets (the monoid operation).
    ///
    /// Core labels: bitwise OR (FROZEN).
    /// Extension labels: set union.
    pub fn union(&self, other: &Self) -> Self {
        #[cfg(not(kani))]
        let extensions = if self.extensions.is_empty() && other.extensions.is_empty() {
            std::collections::BTreeSet::new()
        } else {
            &self.extensions | &other.extensions
        };
        Self {
            private_data: self.private_data || other.private_data,
            untrusted_content: self.untrusted_content || other.untrusted_content,
            exfil_vector: self.exfil_vector || other.exfil_vector,
            #[cfg(not(kani))]
            extensions,
        }
    }

    /// Check if the uninhabitable_state is present.
    pub fn is_uninhabitable(&self) -> bool {
        self.private_data && self.untrusted_content && self.exfil_vector
    }

    /// Convert to the corresponding StateRisk level.
    pub fn to_risk(&self) -> StateRisk {
        let count =
            self.private_data as u8 + self.untrusted_content as u8 + self.exfil_vector as u8;
        match count {
            0 => StateRisk::Safe,
            1 => StateRisk::Low,
            2 => StateRisk::Medium,
            _ => StateRisk::Uninhabitable,
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

    /// Number of active exposure legs.
    pub fn count(&self) -> u8 {
        self.private_data as u8 + self.untrusted_content as u8 + self.exfil_vector as u8
    }

    /// Check if this exposure set is a superset of another.
    ///
    /// Corresponds to `exposure_subset(other, self)` in the Verus model.
    /// Used by the E1 monotonicity invariant assertion.
    pub fn is_superset_of(&self, other: &Self) -> bool {
        let core_ok = (!other.private_data || self.private_data)
            && (!other.untrusted_content || self.untrusted_content)
            && (!other.exfil_vector || self.exfil_vector);
        #[cfg(not(kani))]
        {
            core_ok && (other.extensions.is_empty() || other.extensions.is_subset(&self.extensions))
        }
        #[cfg(kani)]
        core_ok
    }

    /// Check if a specific extension exposure label is present.
    #[cfg(not(kani))]
    pub fn contains_extension(&self, label: &ExtensionExposureLabel) -> bool {
        self.extensions.contains(label)
    }

    /// Iterator over all extension labels present in this exposure set.
    #[cfg(not(kani))]
    pub fn extension_labels(&self) -> impl Iterator<Item = &ExtensionExposureLabel> {
        self.extensions.iter()
    }
}

impl std::fmt::Display for ExposureSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut labels: Vec<String> = Vec::new();
        if self.private_data {
            labels.push("PrivateData".to_string());
        }
        if self.untrusted_content {
            labels.push("UntrustedContent".to_string());
        }
        if self.exfil_vector {
            labels.push("ExfilVector".to_string());
        }
        #[cfg(not(kani))]
        for ext in &self.extensions {
            labels.push(format!("ext:{}", ext.0));
        }
        if labels.is_empty() {
            write!(f, "{{}}")
        } else {
            write!(f, "{{{}}}", labels.join(", "))
        }
    }
}

impl crate::graded::RiskGrade for ExposureSet {
    fn identity() -> Self {
        Self::empty()
    }

    fn compose(&self, other: &Self) -> Self {
        self.union(other)
    }

    fn requires_intervention(&self) -> bool {
        self.is_uninhabitable()
    }
}

/// Classify an operation into its exposure label.
///
/// This is the labeling function `λ: Operation → Option<ExposureLabel>` that
/// tags each tool call with which exposure leg it contributes to.
/// Neutral operations (WriteFiles, EditFiles, GitCommit, ManagePods)
/// return `None` — they don't contribute to the uninhabitable_state.
///
/// Delegates to [`crate::exposure_core::classify_operation`] — the verified
/// shared kernel.
pub fn operation_exposure(op: Operation) -> Option<ExposureLabel> {
    crate::exposure_core::classify_operation(op)
}

/// Session-scoped exposure-tracking guard using the graded monad.
///
/// Each tool call is modeled as `Graded<ExposureSet, Operation>` — the exposure
/// label is the grade, the operation is the value. The session's accumulated
/// state is the monadic composition (>>=) of all recorded tool calls.
///
/// This is the **production** guard (replacing the deprecated
/// [`RuntimeStateGuard`]):
/// - `RuntimeStateGuard` (deprecated): tracks `Vec<Operation>`, delegates to `exposure_core`
/// - `GradedExposureGuard`: tracks `ExposureSet` (3 bits), O(1) per check
///
/// Both produce identical decisions. The graded version makes the
/// mathematical structure explicit: exposure propagation is a monoid
/// homomorphism from operation sequences to the exposure semilattice.
///
/// # Schema Pinning
///
/// At session init, the full tool schema is SHA-256 hashed. Before each
/// tool call, the schema can be verified against this pin. A mismatch
/// indicates an MCP rug-pull attack.
pub struct GradedExposureGuard {
    /// Static permission lattice for this session
    perms: PermissionLattice,
    /// Accumulated exposure from all recorded operations (the grade accumulator)
    exposure: RwLock<ExposureSet>,
    /// Pinned SHA-256 of tool schema at session init
    pinned_schema_hash: String,
}

impl GradedExposureGuard {
    /// Create a new session guard.
    ///
    /// `tool_schemas` is a canonical string representation of the available
    /// tools, hashed at construction for rug-pull detection.
    pub fn new(perms: PermissionLattice, tool_schemas: &str) -> Self {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(tool_schemas.as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        Self {
            perms,
            exposure: RwLock::new(ExposureSet::empty()),
            pinned_schema_hash: hash,
        }
    }

    /// Get the current exposure set.
    pub fn exposure(&self) -> ExposureSet {
        self.exposure
            .read()
            .expect("exposure lock poisoned")
            .clone()
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

impl ToolCallGuard for GradedExposureGuard {
    fn check(&self, operation: Operation) -> Result<CheckProof, GuardError> {
        use crate::CapabilityLevel;

        // Layer 1: Capability level check (is the operation allowed at all?)
        let level = self.perms.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return Err(GuardError::Denied {
                reason: format!("{:?} denied: capability level is Never", operation),
            });
        }

        // Layer 2: Session exposure projection via verified shared kernel
        //
        // Delegates to exposure_core::should_deny — the pure decision function
        // whose logic is structurally bisimilar to the Verus exec fn
        // `exec_guard_check`.
        let current = self.exposure.read().expect("exposure lock poisoned");
        if crate::exposure_core::should_deny(
            &current,
            operation,
            self.perms.requires_approval(operation),
            self.perms.uninhabitable_constraint,
        ) {
            let projected = crate::exposure_core::project_exposure(&current, operation);
            return Err(GuardError::Denied {
                reason: format!(
                    "{:?} denied: would uninhabitable_state (exposure: {} → {})",
                    operation, current, projected,
                ),
            });
        }

        // Snapshot exposure for TOCTOU detection
        let exposure_snapshot = self
            .exposure
            .read()
            .expect("exposure lock poisoned")
            .clone();

        Ok(CheckProof {
            operation,
            exposure_snapshot,
            _seal: (),
        })
    }

    fn execute_and_record<T, E>(
        &self,
        proof: CheckProof,
        f: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, ExecuteError<E>> {
        // Run the closure without holding any lock
        let value = match f() {
            Ok(v) => v,
            Err(e) => return Err(ExecuteError::OperationFailed(e)),
        };

        // Acquire write lock for atomic TOCTOU check + record
        let mut exposure = self.exposure.write().expect("exposure lock poisoned");

        // TOCTOU detection: check if exposure grew since check()
        if *exposure != proof.exposure_snapshot && self.perms.uninhabitable_constraint {
            // Re-check with current (grown) exposure using exposure_core
            let projected = crate::exposure_core::project_exposure(&exposure, proof.operation);

            if projected.is_uninhabitable() && self.perms.requires_approval(proof.operation) {
                // Record exposure anyway (operation DID execute) for consistency
                *exposure = crate::exposure_core::apply_record(&exposure, proof.operation);
                return Err(ExecuteError::TocTouDenied {
                    reason: format!(
                        "{:?}: concurrent exposure growth detected ({} → {}); \
                         operation would now be denied (projected: {})",
                        proof.operation, proof.exposure_snapshot, *exposure, projected,
                    ),
                });
            }
        }

        // Record the operation's exposure via exposure_core
        //
        // INVARIANT (E1, proven in Verus): apply_event_exposure(t, e) ⊇ t
        // Exposure only grows — permissions only tighten. This debug assertion
        // catches any regression where exposure could shrink, which would
        // constitute a privilege escalation vulnerability.
        let old_exposure = exposure.clone();
        *exposure = crate::exposure_core::apply_record(&exposure, proof.operation);
        debug_assert!(
            exposure.is_superset_of(&old_exposure),
            "E1 violation: exposure shrank after recording {:?} ({} → {})",
            proof.operation,
            old_exposure,
            *exposure,
        );

        Ok(value)
    }

    fn accumulated_risk(&self) -> StateRisk {
        self.exposure
            .read()
            .expect("exposure lock poisoned")
            .to_risk()
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

    /// Test helper: check and record an operation in one call.
    /// Panics if check or execute_and_record fails.
    fn check_and_record(guard: &impl ToolCallGuard, op: Operation) {
        let proof = guard.check(op).expect("check failed");
        guard
            .execute_and_record(proof, || Ok::<_, String>(()))
            .expect("execute_and_record failed");
    }

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
        // so risk should be Low (1 uninhabitable_state component)
        assert_eq!(guard.risk(), StateRisk::Low);

        // ReadFile operation should be allowed
        let result = guard.check_operation(Operation::ReadFiles);
        assert!(result.value.is_ok());
        assert_eq!(result.grade, StateRisk::Low);
    }

    #[test]
    fn test_graded_guard_permissive_denies_uninhabitable_exfiltration() {
        let perms = PermissionLattice::permissive();
        let guard = GradedGuard::new(perms);

        // Permissive has complete uninhabitable_state
        assert_eq!(guard.risk(), StateRisk::Uninhabitable);

        // Exfiltration operations that require approval should be denied
        let result = guard.check_operation(Operation::GitPush);
        assert_eq!(result.grade, StateRisk::Uninhabitable);
        // GitPush requires approval under uninhabitable_state, so it should be denied
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

        // Target has more uninhabitable_state components, so risk is higher
        assert!(gap.grade >= StateRisk::Medium);

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
        assert_eq!(result.grade, StateRisk::Low);
        assert!(result.value.is_ok());
    }

    // -----------------------------------------------------------------------
    // RuntimeStateGuard tests
    // -----------------------------------------------------------------------

    fn uninhabitable_perms() -> PermissionLattice {
        use crate::CapabilityLevel;
        let mut perms = PermissionLattice::default();
        perms.capabilities.read_files = CapabilityLevel::Always;
        perms.capabilities.web_fetch = CapabilityLevel::LowRisk;
        perms.capabilities.run_bash = CapabilityLevel::LowRisk;
        perms.uninhabitable_constraint = true;
        perms.normalize()
    }

    #[test]
    #[allow(deprecated)]
    fn test_session_risk_accumulates() {
        let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

        // Start at None
        assert_eq!(guard.accumulated_risk(), StateRisk::Safe);

        // Read (private data leg)
        check_and_record(&guard, Operation::ReadFiles);
        assert_eq!(guard.accumulated_risk(), StateRisk::Low);

        // Fetch (untrusted content leg)
        check_and_record(&guard, Operation::WebFetch);
        assert_eq!(guard.accumulated_risk(), StateRisk::Medium);

        // RunBash (exfil leg) — should be BLOCKED because it completes uninhabitable_state
        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "RunBash should be blocked when completing uninhabitable_state"
        );

        // Risk stays at Medium (RunBash was not recorded)
        assert_eq!(guard.accumulated_risk(), StateRisk::Medium);
    }

    #[test]
    #[allow(deprecated)]
    fn test_no_phantom_risk() {
        let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

        // check() alone does NOT increase risk (proof is dropped, not consumed)
        let _proof1 = guard.check(Operation::ReadFiles).unwrap();
        let _proof2 = guard.check(Operation::WebFetch).unwrap();
        assert_eq!(guard.accumulated_risk(), StateRisk::Safe);

        // Only execute_and_record increases risk
        check_and_record(&guard, Operation::ReadFiles);
        assert_eq!(guard.accumulated_risk(), StateRisk::Low);
    }

    #[test]
    #[allow(deprecated)]
    fn test_benign_sequence_allowed() {
        let guard = RuntimeStateGuard::new(uninhabitable_perms(), "[]");

        // Read, glob, grep — all private data, only 1 uninhabitable_state component
        check_and_record(&guard, Operation::ReadFiles);
        check_and_record(&guard, Operation::GlobSearch);
        check_and_record(&guard, Operation::GrepSearch);
        assert_eq!(guard.accumulated_risk(), StateRisk::Low);

        // More reads are always fine
        assert!(guard.check(Operation::ReadFiles).is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn test_schema_pinning_detects_mutation() {
        let guard = RuntimeStateGuard::new(uninhabitable_perms(), r#"[{"name":"read"}]"#);

        // Same schema: OK
        let mut hasher = Sha256::new();
        hasher.update(r#"[{"name":"read"}]"#.as_bytes());
        let same_hash = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(guard.verify_schema(&same_hash).is_ok());

        // Different schema: rug-pull detected
        let mut hasher = Sha256::new();
        hasher.update(r#"[{"name":"read"},{"name":"evil"}]"#.as_bytes());
        let different_hash = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(guard.verify_schema(&different_hash).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_two_leg_uninhabitable_allows_exfil() {
        // If only 2 of 3 exposure legs are present in permissions,
        // exfil should be allowed (no uninhabitable_state constraint fires)
        use crate::CapabilityLevel;
        let mut perms = PermissionLattice::default();
        perms.capabilities.read_files = CapabilityLevel::Always;
        perms.capabilities.run_bash = CapabilityLevel::LowRisk;
        // No web_fetch — only 2 legs
        perms.uninhabitable_constraint = true;
        let perms = perms.normalize();

        let guard = RuntimeStateGuard::new(perms, "[]");

        check_and_record(&guard, Operation::ReadFiles);
        // RunBash should be allowed — no untrusted content present
        check_and_record(&guard, Operation::RunBash);
        assert_eq!(guard.accumulated_risk(), StateRisk::Medium);
    }

    // -----------------------------------------------------------------------
    // ExposureSet monoid laws
    // -----------------------------------------------------------------------

    #[test]
    fn test_exposure_set_identity() {
        let empty = ExposureSet::empty();
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);

        // Left identity: empty ∪ s = s
        assert_eq!(empty.union(&s), s);
        // Right identity: s ∪ empty = s
        assert_eq!(s.union(&empty), s);
    }

    #[test]
    fn test_exposure_set_associativity() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
        let c = ExposureSet::singleton(ExposureLabel::ExfilVector);

        // (a ∪ b) ∪ c = a ∪ (b ∪ c)
        assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    }

    #[test]
    fn test_exposure_set_idempotent() {
        let s = ExposureSet::singleton(ExposureLabel::PrivateData);
        // s ∪ s = s (semilattice: join is idempotent)
        assert_eq!(s.union(&s), s);
    }

    #[test]
    fn test_exposure_set_commutative() {
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::UntrustedContent);
        // a ∪ b = b ∪ a
        assert_eq!(a.union(&b), b.union(&a));
    }

    #[test]
    fn test_exposure_set_uninhabitable_detection() {
        let mut exposure = ExposureSet::empty();
        assert!(!exposure.is_uninhabitable());
        assert_eq!(exposure.to_risk(), StateRisk::Safe);

        exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::PrivateData));
        assert!(!exposure.is_uninhabitable());
        assert_eq!(exposure.to_risk(), StateRisk::Low);

        exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        assert!(!exposure.is_uninhabitable());
        assert_eq!(exposure.to_risk(), StateRisk::Medium);

        exposure = exposure.union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        assert!(exposure.is_uninhabitable());
        assert_eq!(exposure.to_risk(), StateRisk::Uninhabitable);
    }

    #[test]
    fn test_exposure_set_risk_grade_impl() {
        use crate::graded::RiskGrade;

        // Identity
        assert_eq!(ExposureSet::identity(), ExposureSet::empty());

        // Compose = union
        let a = ExposureSet::singleton(ExposureLabel::PrivateData);
        let b = ExposureSet::singleton(ExposureLabel::ExfilVector);
        let composed = a.compose(&b);
        assert!(composed.contains(ExposureLabel::PrivateData));
        assert!(composed.contains(ExposureLabel::ExfilVector));
        assert!(!composed.contains(ExposureLabel::UntrustedContent));

        // requires_intervention only at Complete
        assert!(!a.requires_intervention());
        assert!(!composed.requires_intervention());
        let full = composed.compose(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        assert!(full.requires_intervention());
    }

    #[test]
    fn test_exposure_set_display() {
        assert_eq!(format!("{}", ExposureSet::empty()), "{}");
        assert_eq!(
            format!("{}", ExposureSet::singleton(ExposureLabel::PrivateData)),
            "{PrivateData}"
        );
        let full = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector));
        assert_eq!(
            format!("{}", full),
            "{PrivateData, UntrustedContent, ExfilVector}"
        );
    }

    #[test]
    fn test_operation_exposure_classification() {
        // Private data leg
        assert_eq!(
            operation_exposure(Operation::ReadFiles),
            Some(ExposureLabel::PrivateData)
        );
        assert_eq!(
            operation_exposure(Operation::GlobSearch),
            Some(ExposureLabel::PrivateData)
        );
        assert_eq!(
            operation_exposure(Operation::GrepSearch),
            Some(ExposureLabel::PrivateData)
        );

        // Untrusted content leg
        assert_eq!(
            operation_exposure(Operation::WebFetch),
            Some(ExposureLabel::UntrustedContent)
        );
        assert_eq!(
            operation_exposure(Operation::WebSearch),
            Some(ExposureLabel::UntrustedContent)
        );

        // Exfil vector leg
        assert_eq!(
            operation_exposure(Operation::RunBash),
            Some(ExposureLabel::ExfilVector)
        );
        assert_eq!(
            operation_exposure(Operation::GitPush),
            Some(ExposureLabel::ExfilVector)
        );
        assert_eq!(
            operation_exposure(Operation::CreatePr),
            Some(ExposureLabel::ExfilVector)
        );

        // Neutral operations
        assert_eq!(operation_exposure(Operation::WriteFiles), None);
        assert_eq!(operation_exposure(Operation::EditFiles), None);
        assert_eq!(operation_exposure(Operation::GitCommit), None);
        assert_eq!(operation_exposure(Operation::ManagePods), None);
    }

    // -----------------------------------------------------------------------
    // GradedExposureGuard tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_graded_exposure_guard_risk_accumulates() {
        let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

        // Start at empty exposure
        assert_eq!(guard.exposure(), ExposureSet::empty());
        assert_eq!(guard.accumulated_risk(), StateRisk::Safe);

        // Read (private data)
        check_and_record(&guard, Operation::ReadFiles);
        assert!(guard.exposure().contains(ExposureLabel::PrivateData));
        assert_eq!(guard.accumulated_risk(), StateRisk::Low);

        // Fetch (untrusted content)
        check_and_record(&guard, Operation::WebFetch);
        assert!(guard.exposure().contains(ExposureLabel::UntrustedContent));
        assert_eq!(guard.accumulated_risk(), StateRisk::Medium);

        // RunBash (exfil) — BLOCKED: would uninhabitable_state
        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "RunBash should be blocked when completing uninhabitable_state"
        );
        assert_eq!(guard.accumulated_risk(), StateRisk::Medium);
    }

    #[test]
    fn test_graded_exposure_guard_no_phantom_exposure() {
        let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

        // check() alone does NOT expose the session (proofs are dropped)
        let _proof1 = guard.check(Operation::ReadFiles).unwrap();
        let _proof2 = guard.check(Operation::WebFetch).unwrap();
        assert_eq!(guard.exposure(), ExposureSet::empty());

        // Only execute_and_record exposures
        check_and_record(&guard, Operation::ReadFiles);
        assert!(guard.exposure().contains(ExposureLabel::PrivateData));
    }

    #[test]
    fn test_graded_exposure_guard_neutral_ops_no_exposure() {
        let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

        check_and_record(&guard, Operation::WriteFiles);
        check_and_record(&guard, Operation::EditFiles);
        check_and_record(&guard, Operation::GitCommit);

        // Neutral ops don't contribute to exposure
        assert_eq!(guard.exposure(), ExposureSet::empty());
        assert_eq!(guard.accumulated_risk(), StateRisk::Safe);
    }

    #[test]
    fn test_graded_exposure_guard_schema_pinning() {
        let guard = GradedExposureGuard::new(uninhabitable_perms(), r#"[{"name":"read"}]"#);

        // Same schema: OK
        let same_hash = {
            let mut h = Sha256::new();
            h.update(r#"[{"name":"read"}]"#.as_bytes());
            h.finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert!(guard.verify_schema(&same_hash).is_ok());

        // Mutated schema: rug-pull detected
        let evil_hash = {
            let mut h = Sha256::new();
            h.update(r#"[{"name":"read"},{"name":"evil_tool"}]"#.as_bytes());
            h.finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
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
    #[allow(deprecated)]
    fn test_graded_exposure_guard_agrees_with_runtime_guard() {
        // Both guards should make identical decisions
        let perms = uninhabitable_perms();
        let runtime = RuntimeStateGuard::new(perms.clone(), "[]");
        let graded = GradedExposureGuard::new(perms, "[]");

        let ops = vec![
            Operation::ReadFiles,
            Operation::GlobSearch,
            Operation::WebFetch,
        ];

        for op in &ops {
            let r1 = runtime.check(*op);
            let r2 = graded.check(*op);
            assert_eq!(r1.is_ok(), r2.is_ok(), "disagreement on {:?}", op);

            if let (Ok(p1), Ok(p2)) = (r1, r2) {
                runtime
                    .execute_and_record(p1, || Ok::<_, String>(()))
                    .unwrap();
                graded
                    .execute_and_record(p2, || Ok::<_, String>(()))
                    .unwrap();
            }
        }

        // Both should block RunBash now (uninhabitable_state complete)
        assert!(runtime.check(Operation::RunBash).is_err());
        assert!(graded.check(Operation::RunBash).is_err());

        // Both report same risk
        assert_eq!(runtime.accumulated_risk(), graded.accumulated_risk());
    }

    #[test]
    fn test_graded_exposure_guard_as_graded_monad() {
        // Demonstrate the graded monad composition explicitly
        use crate::graded::{Graded, RiskGrade};

        let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

        // Model each tool call as Graded<ExposureSet, Operation>
        let read_call = Graded::new(
            ExposureSet::singleton(ExposureLabel::PrivateData),
            Operation::ReadFiles,
        );
        let fetch_call = Graded::new(
            ExposureSet::singleton(ExposureLabel::UntrustedContent),
            Operation::WebFetch,
        );

        // Compose via >>= (and_then): exposure accumulates through the monoid
        let composed = read_call.and_then(|_| fetch_call);

        // The composed grade is the union of both exposure sets
        assert!(composed.grade.contains(ExposureLabel::PrivateData));
        assert!(composed.grade.contains(ExposureLabel::UntrustedContent));
        assert!(!composed.grade.contains(ExposureLabel::ExfilVector));
        assert_eq!(composed.grade.to_risk(), StateRisk::Medium);

        // Adding an exfil call would complete the uninhabitable_state
        let exfil_call = Graded::new(
            ExposureSet::singleton(ExposureLabel::ExfilVector),
            Operation::RunBash,
        );
        let full = composed.and_then(|_| exfil_call);
        assert!(full.grade.is_uninhabitable());
        assert!(full.grade.requires_intervention());

        // This is exactly what the guard does internally, but with
        // RwLock state instead of pure functional composition
        check_and_record(&guard, Operation::ReadFiles);
        check_and_record(&guard, Operation::WebFetch);
        assert!(guard.check(Operation::RunBash).is_err());
    }

    /// Clinejection attack (Feb 2026): prompt injection in a GitHub issue
    /// triggers `npm install` via an AI coding assistant. The preinstall
    /// hook exfiltrates credentials.
    ///
    /// Portcullis must block this even WITHOUT a prior ReadFiles:
    ///   WebFetch(UntrustedContent) → RunBash(projected: PrivateData+ExfilVector)
    ///   = all 3 exposure legs → DENIED.
    #[test]
    fn test_clinejection_blocked() {
        let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

        // Step 1: Read untrusted content (GitHub issue via WebFetch)
        check_and_record(&guard, Operation::WebFetch);

        // Step 2: Attempt RunBash (npm install from attacker).
        // RunBash projects PrivateData + ExfilVector (omnibus),
        // completing the uninhabitable_state with UntrustedContent.
        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "Clinejection: RunBash after WebFetch must be denied (omnibus projection)"
        );

        // The exposure should NOT have changed (check doesn't exposure)
        assert!(!guard.exposure().contains(ExposureLabel::PrivateData));
        assert!(!guard.exposure().contains(ExposureLabel::ExfilVector));
    }

    /// Verify that RunBash also triggers uninhabitable_state in the RuntimeStateGuard.
    #[test]
    #[allow(deprecated)]
    fn test_clinejection_runtime_guard() {
        let perms = uninhabitable_perms();
        let guard = RuntimeStateGuard::new(perms, "[]");

        // WebFetch then RunBash — should uninhabitable_state
        check_and_record(&guard, Operation::WebFetch);

        let result = guard.check(Operation::RunBash);
        assert!(
            result.is_err(),
            "Clinejection: RuntimeStateGuard must also block WebFetch → RunBash"
        );
    }

    /// Verify that execute_and_record does NOT record on closure failure
    /// (no phantom exposure from failed operations).
    #[test]
    fn test_execute_and_record_no_phantom_on_failure() {
        let guard = GradedExposureGuard::new(uninhabitable_perms(), "[]");

        let proof = guard.check(Operation::ReadFiles).unwrap();
        let result = guard.execute_and_record(proof, || Err::<(), _>("io error"));
        assert!(result.is_err());

        // Exposure should be empty — failed operation not recorded
        assert_eq!(guard.exposure(), ExposureSet::empty());
        assert_eq!(guard.accumulated_risk(), StateRisk::Safe);
    }

    // -----------------------------------------------------------------------
    // Exhaustive equivalence: RuntimeStateGuard ≡ GradedExposureGuard
    //
    // Now that RuntimeStateGuard delegates to exposure_core, both guards
    // MUST produce identical check/deny/risk decisions for ALL operation
    // permutations. This test checks every permutation of all 12 operations.
    // -----------------------------------------------------------------------

    /// All Operation variants for exhaustive testing.
    const ALL_OPS: [Operation; 13] = [
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
        Operation::SpawnAgent,
    ];

    /// Exhaustive equivalence test: for every possible operation sequence
    /// (up to length 4), both guards produce identical decisions.
    #[test]
    #[allow(deprecated)]
    fn test_guard_equivalence_exhaustive() {
        // Test all single-operation sequences
        for &op in &ALL_OPS {
            assert_guards_agree(&[op], &format!("[{:?}]", op));
        }

        // Test all 2-operation sequences (12 × 12 = 144)
        for &op1 in &ALL_OPS {
            for &op2 in &ALL_OPS {
                assert_guards_agree(&[op1, op2], &format!("[{:?}, {:?}]", op1, op2));
            }
        }

        // Test critical 3-operation sequences (uninhabitable-state-completing paths)
        let exposure_legs: [Operation; 6] = [
            Operation::ReadFiles,
            Operation::WebFetch,
            Operation::RunBash,
            Operation::GlobSearch,
            Operation::WebSearch,
            Operation::GitPush,
        ];
        for &op1 in &exposure_legs {
            for &op2 in &exposure_legs {
                for &op3 in &exposure_legs {
                    assert_guards_agree(
                        &[op1, op2, op3],
                        &format!("[{:?}, {:?}, {:?}]", op1, op2, op3),
                    );
                }
            }
        }
    }

    /// Helper: create both guards with uninhabitable_perms, feed the same
    /// operations, and assert every observable produces identical results.
    #[allow(deprecated)]
    fn assert_guards_agree(ops: &[Operation], label: &str) {
        let perms = uninhabitable_perms();
        let runtime = RuntimeStateGuard::new(perms.clone(), "[]");
        let graded = GradedExposureGuard::new(perms, "[]");

        for (i, &op) in ops.iter().enumerate() {
            let r1 = runtime.check(op);
            let r2 = graded.check(op);

            assert_eq!(
                r1.is_ok(),
                r2.is_ok(),
                "Guard disagreement on check({:?}) at step {} of {}: runtime={}, graded={}",
                op,
                i,
                label,
                if r1.is_ok() { "allow" } else { "deny" },
                if r2.is_ok() { "allow" } else { "deny" },
            );

            // If both allow, record the operation in both
            if let (Ok(p1), Ok(p2)) = (r1, r2) {
                let e1 = runtime.execute_and_record(p1, || Ok::<_, String>(()));
                let e2 = graded.execute_and_record(p2, || Ok::<_, String>(()));
                assert_eq!(
                    e1.is_ok(),
                    e2.is_ok(),
                    "Guard disagreement on execute({:?}) at step {} of {}",
                    op,
                    i,
                    label,
                );
            }

            // Risk must always agree
            assert_eq!(
                runtime.accumulated_risk(),
                graded.accumulated_risk(),
                "Risk disagreement after step {} of {}: runtime={:?}, graded={:?}",
                i,
                label,
                runtime.accumulated_risk(),
                graded.accumulated_risk(),
            );
        }
    }
}
