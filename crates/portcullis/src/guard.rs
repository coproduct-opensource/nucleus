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
use portcullis_core::act::Act;
#[cfg(test)]
use portcullis_core::act::{Endpoint, FilePath, ReadSink};

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
    /// The act that was checked and approved — verb *and* target.
    ///
    /// Previously this was a bare `Operation`. A proof that says only
    /// "a read was approved" cannot answer "a read of what?", so the target
    /// travelled beside the proof as a separate string and the audit record
    /// was built from that string rather than from the decision. Nothing
    /// connected the two.
    act: Act,
    /// Exposure state at check time, for optimistic TOCTOU detection.
    exposure_snapshot: ExposureSet,
    /// Prevents external construction.
    _seal: (),
}

impl CheckProof {
    /// The act this proof authorizes.
    #[must_use]
    pub fn act(&self) -> &Act {
        &self.act
    }

    /// Get the operation this proof authorizes.
    #[must_use]
    pub fn operation(&self) -> Operation {
        self.act.operation()
    }

    /// The subject this proof authorizes, rendered for the audit record.
    ///
    /// An audit record built from this names what was actually decided on.
    /// One built from a string carried alongside names whatever the caller
    /// happened to pass, which need not be the same thing.
    #[must_use]
    pub fn subject(&self) -> String {
        self.act.subject()
    }
}

impl std::fmt::Debug for CheckProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckProof")
            .field("act", &self.act)
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
    /// snapshot of the exposure state for optimistic TOCTOU detection, and
    /// the [`Act`] it authorizes. The token MUST be consumed by
    /// [`execute_and_record`].
    ///
    /// # Why this takes an `Act` and not an `Operation`
    ///
    /// It used to take the verb alone. Every caller already had the target in
    /// scope — a path, a URL, an argv — and every caller threaded it into the
    /// *audit record* while the *decision* never saw it. A guard cannot refuse
    /// a read of `/etc/shadow` in particular if all it is told is that a read
    /// is happening.
    ///
    /// Taking an `Act` makes naming the target a condition of compiling, and
    /// [`CheckProof::subject`] then gives the audit record a string derived
    /// from the decision rather than one carried beside it.
    ///
    /// # The verb alone no longer type-checks
    ///
    /// ```compile_fail
    /// use portcullis::{
    ///     Act, FilePath, GradedExposureGuard, Operation, PermissionLattice, ReadSink,
    ///     ToolCallGuard,
    /// };
    /// let guard = GradedExposureGuard::new(PermissionLattice::default(), "schema");
    /// let act = Act::Read {
    ///     path: FilePath::new("/workspace/main.rs"),
    ///     sink: ReadSink::AuditLog,
    /// };
    /// let proof = guard.check(&act).expect("a read is allowed by default");
    /// assert_eq!(proof.subject(), "/workspace/main.rs");
    ///
    /// // Everything above this line is proven to compile by the block below.
    /// // This is the only line that can be failing, and it fails because the
    /// // verb is not an act:
    /// let _ = guard.check(Operation::ReadFiles);
    /// ```
    ///
    /// The block below is that one character-for-character, minus the last
    /// statement, and it must pass:
    ///
    /// ```
    /// use portcullis::{
    ///     Act, FilePath, GradedExposureGuard, Operation, PermissionLattice, ReadSink,
    ///     ToolCallGuard,
    /// };
    /// let guard = GradedExposureGuard::new(PermissionLattice::default(), "schema");
    /// let act = Act::Read {
    ///     path: FilePath::new("/workspace/main.rs"),
    ///     sink: ReadSink::AuditLog,
    /// };
    /// let proof = guard.check(&act).expect("a read is allowed by default");
    /// assert_eq!(proof.subject(), "/workspace/main.rs");
    /// # let _ = Operation::ReadFiles;
    /// ```
    ///
    /// The pairing is what makes the first block mean something. A
    /// `compile_fail` doctest that fails for some other reason — a renamed
    /// import, a wrong arity, a typo — asserts nothing, and this repository
    /// already has one of those (`Executor::run_args`, which fails on arity).
    ///
    /// Pinning the error code is the obvious fix and does not work here:
    /// rustdoc accepts `compile_fail,E0308` but does not enforce the code on
    /// stable. Measured, not assumed — breaking an import in the block above
    /// so it fails with `E0432` instead left the doctest passing. So the
    /// shared preamble does the work: break it and the second block reds.
    fn check(&self, act: &Act) -> Result<CheckProof, GuardError>;

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
    fn check(&self, act: &Act) -> Result<CheckProof, GuardError> {
        use crate::CapabilityLevel;

        // The verb still drives every layer below; what is new is that the
        // target arrived with it and survives into the proof.
        let operation = act.operation();

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
        // DECISION LOCK — fail CLOSED on poison. A poisoned exposure lock means
        // the taint/exposure state is unprovable; recovering the torn guard via
        // into_inner() could UNDER-COUNT taint (exposure is monotone-union) and
        // ALLOW an action that must DENY — a fail-open. So we deny instead.
        let current = match self.exposure.read() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(GuardError::Denied {
                    reason: "exposure lock poisoned: session taint/exposure state is \
                             unprovable; failing closed to prevent untracked exposure"
                        .to_string(),
                });
            }
        };
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
            act: act.clone(),
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

        // Acquire write locks for atomic TOCTOU check + record.
        //
        // DECISION LOCK — fail CLOSED on poison. The closure already executed, so
        // the side effect happened, but we cannot prove the resulting exposure is
        // recorded/consistent. Recovering the torn guard via into_inner() risks
        // under-counting taint on a subsequent decision, so we surface a
        // fail-closed denial (TocTouDenied): the operation ran but the caller MUST
        // treat it as denied.
        let mut exposure = match self.exposure.write() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(ExecuteError::TocTouDenied {
                    reason: "exposure lock poisoned: cannot record/verify exposure; \
                             failing closed (operation executed but treated as denied)"
                        .to_string(),
                });
            }
        };
        let mut ops = match self.executed_ops.write() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(ExecuteError::TocTouDenied {
                    reason: "executed_ops lock poisoned: cannot record operation; \
                             failing closed (operation executed but treated as denied)"
                        .to_string(),
                });
            }
        };

        // TOCTOU detection: check if exposure grew since check()
        if *exposure != proof.exposure_snapshot && self.perms.uninhabitable_constraint {
            // Re-check with current (grown) exposure using exposure_core
            let projected = crate::exposure_core::project_exposure(&exposure, proof.operation());

            if projected.is_uninhabitable() && self.perms.requires_approval(proof.operation()) {
                // Record exposure anyway (operation DID execute) for consistency
                ops.push(proof.operation());
                *exposure = crate::exposure_core::apply_record(&exposure, proof.operation());
                return Err(ExecuteError::TocTouDenied {
                    reason: format!(
                        "{:?}: concurrent exposure growth detected ({} → {}); \
                         operation would now be denied (projected: {})",
                        proof.operation(),
                        proof.exposure_snapshot,
                        *exposure,
                        projected,
                    ),
                });
            }
        }

        // Record the operation's exposure via exposure_core
        ops.push(proof.operation());
        *exposure = crate::exposure_core::apply_record(&exposure, proof.operation());

        Ok(value)
    }

    fn accumulated_risk(&self) -> StateRisk {
        // DECISION LOCK — fail CLOSED on poison. This value gates downstream
        // oversight; a poisoned lock makes true risk unprovable, so report the
        // MAXIMUM risk rather than into_inner() (which could under-report).
        match self.exposure.read() {
            Ok(guard) => guard.to_risk(),
            Err(_) => StateRisk::Uninhabitable,
        }
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
/// These 3 core labels are FROZEN — they have Kani + Lean proofs covering
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
        let count = u8::from(self.private_data)
            + u8::from(self.untrusted_content)
            + u8::from(self.exfil_vector);
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
        u8::from(self.private_data) + u8::from(self.untrusted_content) + u8::from(self.exfil_vector)
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
    ///
    /// DECISION LOCK — fail CLOSED on poison. Rather than recover a torn guard
    /// (which could under-report exposure), return the maximal exposure set
    /// (all three legs) so no caller ever under-accounts taint.
    pub fn exposure(&self) -> ExposureSet {
        match self.exposure.read() {
            Ok(guard) => guard.clone(),
            Err(_) => ExposureSet::singleton(ExposureLabel::PrivateData)
                .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent))
                .union(&ExposureSet::singleton(ExposureLabel::ExfilVector)),
        }
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
    fn check(&self, act: &Act) -> Result<CheckProof, GuardError> {
        use crate::CapabilityLevel;

        // The verb still drives every layer below; what is new is that the
        // target arrived with it and survives into the proof.
        let operation = act.operation();

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
        // DECISION LOCK — fail CLOSED on poison (see RuntimeStateGuard::check).
        // into_inner() on a torn exposure guard could under-count taint and turn
        // a required DENY into an ALLOW; deny instead.
        let current = match self.exposure.read() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(GuardError::Denied {
                    reason: "exposure lock poisoned: session taint/exposure state is \
                             unprovable; failing closed to prevent untracked exposure"
                        .to_string(),
                });
            }
        };
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

        // Snapshot exposure for TOCTOU detection — same fail-closed rule.
        let exposure_snapshot = match self.exposure.read() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                return Err(GuardError::Denied {
                    reason: "exposure lock poisoned: session taint/exposure state is \
                             unprovable; failing closed to prevent untracked exposure"
                        .to_string(),
                });
            }
        };

        Ok(CheckProof {
            act: act.clone(),
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

        // Acquire write lock for atomic TOCTOU check + record.
        //
        // DECISION LOCK — fail CLOSED on poison (see RuntimeStateGuard::
        // execute_and_record). The closure already ran, but we cannot prove the
        // exposure is recorded/consistent; surface a fail-closed TocTouDenied
        // rather than recover a torn guard and risk under-counting taint.
        let mut exposure = match self.exposure.write() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(ExecuteError::TocTouDenied {
                    reason: "exposure lock poisoned: cannot record/verify exposure; \
                             failing closed (operation executed but treated as denied)"
                        .to_string(),
                });
            }
        };

        // TOCTOU detection: check if exposure grew since check()
        if *exposure != proof.exposure_snapshot && self.perms.uninhabitable_constraint {
            // Re-check with current (grown) exposure using exposure_core
            let projected = crate::exposure_core::project_exposure(&exposure, proof.operation());

            if projected.is_uninhabitable() && self.perms.requires_approval(proof.operation()) {
                // Record exposure anyway (operation DID execute) for consistency
                *exposure = crate::exposure_core::apply_record(&exposure, proof.operation());
                return Err(ExecuteError::TocTouDenied {
                    reason: format!(
                        "{:?}: concurrent exposure growth detected ({} → {}); \
                         operation would now be denied (projected: {})",
                        proof.operation(),
                        proof.exposure_snapshot,
                        *exposure,
                        projected,
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
        *exposure = crate::exposure_core::apply_record(&exposure, proof.operation());
        debug_assert!(
            exposure.is_superset_of(&old_exposure),
            "E1 violation: exposure shrank after recording {:?} ({} → {})",
            proof.operation(),
            old_exposure,
            *exposure,
        );

        Ok(value)
    }

    fn accumulated_risk(&self) -> StateRisk {
        // DECISION LOCK — fail CLOSED on poison: report MAXIMUM risk rather than
        // into_inner() (which could under-report).
        match self.exposure.read() {
            Ok(guard) => guard.to_risk(),
            Err(_) => StateRisk::Uninhabitable,
        }
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
#[path = "guard_tests.rs"]
mod tests;
